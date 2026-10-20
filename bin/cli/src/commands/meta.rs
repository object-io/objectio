//! Meta backups: `obioctl meta export`.

use super::Ctx;
use crate::cli::MetaCmd;
use anyhow::{Context, Result, anyhow};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub async fn meta(cmd: MetaCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        MetaCmd::Export { file } => export(file.as_deref(), ctx).await,
    }
}

/// The bytes of a download, handed to a reader on another thread.
struct Received {
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    chunk: Vec<u8>,
    at: usize,
}

impl Read for Received {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.at == self.chunk.len() {
            match self.rx.recv() {
                Ok(c) => {
                    self.chunk = c;
                    self.at = 0;
                }
                Err(_) => return Ok(0), // the download ended
            }
        }
        let n = buf.len().min(self.chunk.len() - self.at);
        buf[..n].copy_from_slice(&self.chunk[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

fn part_of(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".part");
    PathBuf::from(p)
}

/// Download the backup to `file` (through `file.part`) or standard output,
/// checking it as it passes: a download that isn't a whole backup fails,
/// and never gets `file`'s name.
async fn export(file: Option<&Path>, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    let mut resp = ctx.api.download("/_admin/meta/export", &[]).await?;
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(16);
    let checker = std::thread::spawn(move || {
        objectio_common::meta_backup::verify(Received {
            rx,
            chunk: Vec::new(),
            at: 0,
        })
    });
    let mut part = match file {
        Some(f) => Some((
            part_of(f),
            std::fs::File::create(part_of(f))
                .with_context(|| format!("creating {}", part_of(f).display()))?,
        )),
        None => None,
    };
    let mut total = 0u64;
    let received: Result<()> = async {
        while let Some(chunk) = resp.chunk().await.context("the download was cut short")? {
            match &mut part {
                Some((path, f)) => f
                    .write_all(&chunk)
                    .with_context(|| format!("writing {}", path.display()))?,
                None => ctx.out.w.write_all(&chunk).context("writing the backup")?,
            }
            total += chunk.len() as u64;
            // A checker that stopped has found the file isn't a backup.
            if tx.send(chunk.to_vec()).is_err() {
                break;
            }
        }
        Ok(())
    }
    .await;
    drop(tx);
    let verdict = checker
        .join()
        .map_err(|_| anyhow!("the backup's check stopped"))?;
    let outcome = received.and_then(|()| verdict.map_err(anyhow::Error::from));
    let header = match outcome {
        Ok(h) => h,
        Err(e) => {
            if let Some((path, _)) = &part {
                let _ = std::fs::remove_file(path);
            }
            return Err(e.context("the backup is not whole; nothing was kept"));
        }
    };
    match (part, file) {
        (Some((path, f)), Some(dest)) => {
            f.sync_all()
                .with_context(|| format!("syncing {}", path.display()))?;
            drop(f);
            std::fs::rename(&path, dest)
                .with_context(|| format!("renaming {} to {}", path.display(), dest.display()))?;
            if let Some(dir) = dest.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::File::open(dir).and_then(|d| d.sync_all()).ok();
            }
        }
        _ => ctx.out.w.flush().context("writing the backup")?,
    }
    // What it holds, on standard error: standard output may be the file.
    let h: serde_json::Value = serde_json::from_slice(&header).unwrap_or_default();
    eprintln!(
        "meta backup: {total} bytes, cluster {}, at Raft index {}, format level {}{}",
        h["cluster_id"].as_str().unwrap_or("?"),
        h["last_applied"]["index"],
        h["active_level"],
        file.map(|f| format!(", in {}", f.display()))
            .unwrap_or_default()
    );
    Ok(())
}
