//! Estimate what deduplication would save on a set of files, offline.
//!
//! Each file stands for one object, written in the order given (a
//! directory's files in name order). For every way of uploading it — in
//! one piece, or in multipart parts of a given size — and every chunking
//! the dry-run measures, the files are cut and fingerprinted exactly as the
//! gateway would (`objectio_gateway::dedup`), and every chunk already seen
//! counts as duplicate bytes. One dedup domain covers all the files, as if
//! they were in one bucket with bucket scope.
//!
//! ```text
//! objectio-dedup-estimate checkpoints/        # parts: whole, 5, 8, 64 MiB
//! objectio-dedup-estimate --parts 0,16 a.bin b.bin
//! ```

// Byte counts become MiB and percentages for display only.
#![allow(clippy::cast_precision_loss)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use objectio_gateway::dedup::{CHUNKINGS, Chunking, chunks, fingerprint};

#[derive(Parser)]
#[command(about = "Estimate what deduplication would save on a set of files")]
struct Args {
    /// Multipart part sizes to model, in MiB; 0 is a single PUT.
    #[arg(long, value_delimiter = ',', default_value = "0,5,8,64")]
    parts: Vec<usize>,

    /// Extra average chunk sizes to try, in KiB, beside the dry-run's
    /// (minimum a quarter of it, maximum four times).
    #[arg(long, value_delimiter = ',')]
    avg_kib: Vec<u32>,

    /// Files, or directories of files, in upload order.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
}

/// One way of uploading and chunking, and what it found so far.
struct Run {
    part_mib: usize,
    chunking: Chunking,
    seen: HashSet<[u8; 32]>,
    bytes: u64,
    duplicate: u64,
}

impl Run {
    fn add(&mut self, body: &[u8]) {
        let domain = format!("estimate|{}", self.chunking.name);
        let pieces: Vec<&[u8]> = if self.part_mib == 0 || body.is_empty() {
            vec![body]
        } else {
            body.chunks(self.part_mib << 20).collect()
        };
        for piece in pieces {
            for (off, len) in chunks(piece, &self.chunking) {
                let fp = fingerprint(&domain, &piece[off..off + len]);
                self.bytes += len as u64;
                if !self.seen.insert(fp) {
                    self.duplicate += len as u64;
                }
            }
        }
    }
}

fn files(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for input in inputs {
        if input.is_dir() {
            let mut dir: Vec<PathBuf> = std::fs::read_dir(input)
                .with_context(|| format!("reading {}", input.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_file())
                .collect();
            dir.sort();
            out.extend(dir);
        } else {
            out.push(input.clone());
        }
    }
    Ok(out)
}

fn mib(b: u64) -> f64 {
    b as f64 / f64::from(1 << 20)
}

fn label(part_mib: usize) -> String {
    if part_mib == 0 {
        "single PUT".to_string()
    } else {
        format!("{part_mib} MiB parts")
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let files = files(&args.inputs)?;
    let mut chunkings = CHUNKINGS.to_vec();
    for &avg in &args.avg_kib {
        chunkings.push(Chunking {
            name: Box::leak(format!("{avg}KiB").into_boxed_str()),
            min: (avg / 4).max(1) * 1024,
            avg: avg * 1024,
            max: avg * 4 * 1024,
        });
    }
    let mut runs: Vec<Run> = args
        .parts
        .iter()
        .flat_map(|&part_mib| {
            chunkings.iter().map(move |&chunking| Run {
                part_mib,
                chunking,
                seen: HashSet::new(),
                bytes: 0,
                duplicate: 0,
            })
        })
        .collect();

    for path in &files {
        let body = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        eprintln!("{:>10.1} MiB  {}", mib(body.len() as u64), name(path));
        // Every run reads the same bytes; each keeps its own set.
        std::thread::scope(|s| {
            for run in &mut runs {
                let body = &body;
                s.spawn(move || run.add(body));
            }
        });
    }

    let total: u64 = files
        .iter()
        .map(|p| std::fs::metadata(p).map_or(0, |m| m.len()))
        .sum();
    println!("{} files, {:.1} MiB", files.len(), mib(total));
    println!(
        "{:<16} {:>9} {:>14} {:>9}",
        "upload", "chunking", "duplicate MiB", "share"
    );
    for run in &runs {
        println!(
            "{:<16} {:>9} {:>14.1} {:>8.1}%",
            label(run.part_mib),
            run.chunking.name,
            mib(run.duplicate),
            100.0 * run.duplicate as f64 / run.bytes.max(1) as f64
        );
    }
    Ok(())
}

fn name(p: &Path) -> String {
    p.file_name().map_or_else(
        || p.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}
