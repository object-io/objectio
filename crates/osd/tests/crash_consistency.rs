//! Crash consistency of the OSD (roadmap B5): every write the OSD
//! acknowledged is there after a power cut at any point.
//!
//! The OSD's shard device and the filesystem holding its state directory
//! (metadata WAL, index) sit on Linux `dm-log-writes` devices, which log
//! every write, flush and FUA in order. Writers store shards and object
//! metadata through an in-process OSD, recording what was acknowledged;
//! every ~100 ms a numbered mark goes into both logs. Afterwards, for a
//! sample of marks, each log is replayed onto the starting image twice:
//!
//! - **to the mark**: everything the devices were given;
//! - **to the last flush**: only what a drive with a volatile write cache
//!   is sure to keep through a power cut at the mark (writes before the
//!   last flush, and FUA writes).
//!
//! The OSD is opened on each replayed image and every write acknowledged
//! before the mark must read back intact.
//!
//! Needs root through `sudo -n` (device mapper, loop devices, mount) and
//! the `dm-log-writes` module:
//!
//! ```text
//! OBJECTIO_CRASH_TEST=1 cargo test -p objectio-osd --test crash_consistency -- --nocapture
//! ```
//!
//! `OBJECTIO_CRASH_SECS` (30) is how long the writers run;
//! `OBJECTIO_CRASH_CUTS` (12) how many marks are replayed.

use objectio_osd::service::OsdService;
use objectio_proto::metadata::{ObjectMeta, ShardLocation, StripeMeta};
use objectio_proto::storage::storage_service_server::StorageService;
use objectio_proto::storage::{
    Checksum, GetObjectMetaRequest, PutObjectMetaRequest, ReadShardRequest, ShardId,
    WriteShardRequest,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tonic::Request;

const DATA_BYTES: u64 = 16 << 30;
const STATE_BYTES: u64 = 1 << 30;
const LOG_BYTES: u64 = 32 << 30;
const BLOCK_SIZE: u32 = 4096;

fn sudo(args: &[&str]) -> String {
    let out = Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .expect("sudo");
    assert!(
        out.status.success(),
        "sudo {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A sparse copy (the images are mostly holes).
fn copy(from: &Path, to: &Path) {
    let out = Command::new("cp")
        .args([
            "--sparse=always",
            from.to_str().unwrap(),
            to.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cp: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn sparse(path: &Path, len: u64) {
    std::fs::File::create(path).unwrap().set_len(len).unwrap();
}

fn losetup(path: &Path) -> String {
    sudo(&["losetup", "--find", "--show", path.to_str().unwrap()])
}

fn me() -> String {
    let uid = Command::new("id").arg("-u").output().unwrap();
    let gid = Command::new("id").arg("-g").output().unwrap();
    format!(
        "{}:{}",
        String::from_utf8_lossy(&uid.stdout).trim(),
        String::from_utf8_lossy(&gid.stdout).trim()
    )
}

/// A device behind dm-log-writes: the target and its log, both on loop
/// devices over files in the run's directory.
struct Logged {
    name: String,
    loops: Vec<String>,
    log_file: PathBuf,
    base: PathBuf,
}

impl Logged {
    fn new(dir: &Path, name: &str, len: u64, prepare: impl Fn(&Path)) -> Self {
        let target = dir.join(format!("{name}.img"));
        sparse(&target, len);
        prepare(&target);
        // The image as the log starts from: replays are applied to a copy.
        let base = dir.join(format!("{name}.base"));
        copy(&target, &base);
        let log_file = dir.join(format!("{name}.log"));
        sparse(&log_file, LOG_BYTES);
        let t = losetup(&target);
        let l = losetup(&log_file);
        let sectors = len / 512;
        let name = format!("objectio-crash-{name}-{}", std::process::id());
        sudo(&[
            "dmsetup",
            "create",
            &name,
            "--table",
            &format!("0 {sectors} log-writes {t} {l}"),
        ]);
        Self {
            name,
            loops: vec![t, l],
            log_file,
            base,
        }
    }

    fn dev(&self) -> String {
        format!("/dev/mapper/{}", self.name)
    }

    fn mark(&self, label: &str) {
        sudo(&["dmsetup", "message", &self.name, "0", "mark", label]);
    }

    fn remove(&self) {
        sudo(&["dmsetup", "remove", &self.name]);
        for l in &self.loops {
            sudo(&["losetup", "-d", l]);
        }
    }
}

// ── dm-log-writes log format (drivers/md/dm-log-writes.c) ─────────────────

const LOG_MAGIC: u64 = 0x006a_7366_7773_6872;
const FLAG_FLUSH: u64 = 1 << 0;
const FLAG_FUA: u64 = 1 << 1;
const FLAG_DISCARD: u64 = 1 << 2;
const FLAG_MARK: u64 = 1 << 3;

struct Entry {
    sector: u64,
    flags: u64,
    /// Data offset in the log file and its length (writes).
    data_at: u64,
    data_len: u64,
    mark: Option<String>,
}

fn read_log(path: &Path) -> (u64, Vec<Entry>) {
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::open(path).unwrap();
    let mut sb = [0u8; 28];
    f.read_exact_at(&mut sb, 0).unwrap();
    let u64_at = |b: &[u8], i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
    assert_eq!(u64_at(&sb, 0), LOG_MAGIC, "not a dm-log-writes log");
    let nr = u64_at(&sb, 16);
    let sectorsize = u64::from(u32::from_le_bytes(sb[24..28].try_into().unwrap()));
    let mut entries = Vec::with_capacity(nr as usize);
    let mut at = sectorsize;
    for _ in 0..nr {
        let mut head = vec![0u8; sectorsize as usize];
        f.read_exact_at(&mut head, at).unwrap();
        let sector = u64_at(&head, 0);
        let nr_sectors = u64_at(&head, 8);
        let flags = u64_at(&head, 16);
        let data_len = u64_at(&head, 24);
        let mut mark = None;
        let mut next = at + sectorsize;
        if flags & FLAG_MARK != 0 {
            let len = data_len as usize;
            mark = Some(String::from_utf8_lossy(&head[32..32 + len]).into_owned());
        } else if flags & FLAG_DISCARD == 0 {
            next += nr_sectors * sectorsize;
        }
        entries.push(Entry {
            sector,
            flags,
            data_at: at + sectorsize,
            data_len: if flags & (FLAG_MARK | FLAG_DISCARD) != 0 {
                0
            } else {
                nr_sectors * sectorsize
            },
            mark,
        });
        at = next;
    }
    (sectorsize, entries)
}

/// Where `label`'s mark is in `dev`'s log.
fn mark_index(dev: &Logged, label: &str) -> usize {
    read_log(&dev.log_file)
        .1
        .iter()
        .position(|e| e.mark.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("mark {label} not in {}", dev.name))
}

/// The base image with the log's first `end` entries applied: all of their
/// writes, or (`flushed_only`) only those a power cut there could not lose:
/// before the last flush, and FUA.
fn replay(dev: &Logged, end: usize, flushed_only: bool, out: &Path) {
    use std::os::unix::fs::FileExt;
    let (sectorsize, entries) = read_log(&dev.log_file);
    let end = end.min(entries.len());
    // A flush makes durable what completed before it.
    let durable = entries[..end]
        .iter()
        .rposition(|e| e.flags & FLAG_FLUSH != 0)
        .unwrap_or(0);
    copy(&dev.base, out);
    let log = std::fs::File::open(&dev.log_file).unwrap();
    let target = std::fs::OpenOptions::new().write(true).open(out).unwrap();
    for (i, e) in entries[..end].iter().enumerate() {
        if e.data_len == 0 {
            continue;
        }
        if flushed_only && i >= durable && e.flags & FLAG_FUA == 0 {
            continue;
        }
        let mut buf = vec![0u8; e.data_len as usize];
        log.read_exact_at(&mut buf, e.data_at).unwrap();
        target.write_all_at(&buf, e.sector * sectorsize).unwrap();
    }
    target.sync_all().unwrap();
}

// ── the workload ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct Acked {
    object_id: Vec<u8>,
    key: String,
    crc: u32,
}

fn object_meta(a: &Acked, len: usize) -> ObjectMeta {
    ObjectMeta {
        bucket: "b".into(),
        key: a.key.clone(),
        object_id: a.object_id.clone(),
        size: len as u64,
        stamp: objectio_common::stamp::CLOCK.now(),
        stripes: vec![StripeMeta {
            stripe_id: 0,
            ec_k: 4,
            ec_m: 2,
            object_id: a.object_id.clone(),
            data_size: len as u64,
            shards: vec![ShardLocation {
                position: 0,
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn shard(object_id: &[u8]) -> ShardId {
    ShardId {
        object_id: object_id.to_vec(),
        stripe_id: 0,
        position: 0,
    }
}

async fn write_one(osd: &OsdService, n: u64) -> Acked {
    let mut object_id = [0u8; 16];
    object_id[..8].copy_from_slice(&n.to_le_bytes());
    let len = 1_000 + (n as usize * 7_919) % 250_000;
    let data: Vec<u8> = (0..len).map(|i| (i as u64 ^ n) as u8).collect();
    let crc = crc32c::crc32c(&data);
    let a = Acked {
        object_id: object_id.to_vec(),
        key: format!("k{n}"),
        crc,
    };
    osd.write_shard(Request::new(WriteShardRequest {
        shard_id: Some(shard(&a.object_id)),
        data: data.into(),
        ec_k: 4,
        ec_m: 2,
        checksum: Some(Checksum {
            crc32c: crc,
            ..Default::default()
        }),
        rdma: None,
        use_reserve: false,
    }))
    .await
    .unwrap();
    osd.put_object_meta(Request::new(PutObjectMetaRequest {
        bucket: "b".into(),
        key: a.key.clone(),
        object: Some(object_meta(&a, len)),
        ..Default::default()
    }))
    .await
    .unwrap();
    a
}

/// What an OSD opened on replayed images is missing of `acked`.
/// The metadata engine under test: `OBJECTIO_META_ENGINE` (native, or
/// rocksdb in a build with that feature), native by default.
fn engine() -> objectio_storage::metadata::MetaEngine {
    std::env::var("OBJECTIO_META_ENGINE")
        .map_or(Ok(objectio_storage::metadata::MetaEngine::Native), |e| {
            e.parse()
        })
        .expect("OBJECTIO_META_ENGINE")
}

async fn check(data: &Path, state: &Path, acked: &[Acked]) -> Vec<String> {
    let osd = match OsdService::new_with_store(
        vec![data.display().to_string()],
        BLOCK_SIZE,
        state.to_path_buf(),
        |c| c.engine = engine(),
    ) {
        Ok(o) => o,
        Err(e) => return vec![format!("the OSD does not open: {e}")],
    };
    let mut wrong = Vec::new();
    for a in acked {
        match osd
            .read_shard(Request::new(ReadShardRequest {
                shard_id: Some(shard(&a.object_id)),
                ..Default::default()
            }))
            .await
        {
            Ok(r) if crc32c::crc32c(&r.get_ref().data) == a.crc => {}
            Ok(_) => wrong.push(format!("{}: shard reads back different bytes", a.key)),
            Err(e) => wrong.push(format!("{}: shard: {}", a.key, e.message())),
        }
        match osd
            .get_object_meta(Request::new(GetObjectMetaRequest {
                bucket: "b".into(),
                key: a.key.clone(),
                version_id: String::new(),
                with_small_shard: false,
            }))
            .await
        {
            Ok(r) if r.get_ref().found => {}
            Ok(_) => wrong.push(format!("{}: object metadata missing", a.key)),
            Err(e) => wrong.push(format!("{}: object metadata: {}", a.key, e.message())),
        }
    }
    wrong
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acknowledged_writes_survive_a_power_cut_anywhere() {
    if std::env::var("OBJECTIO_CRASH_TEST").is_err() {
        eprintln!("skipped: set OBJECTIO_CRASH_TEST=1 (needs sudo -n and dm-log-writes)");
        return;
    }
    let secs: u64 = std::env::var("OBJECTIO_CRASH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let cuts: usize = std::env::var("OBJECTIO_CRASH_CUTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    sudo(&["modprobe", "dm-log-writes"]);
    let run = tempfile::Builder::new()
        .prefix("objectio-crash-")
        .tempdir_in(std::env::var("OBJECTIO_CRASH_DIR").unwrap_or_else(|_| "/tmp".into()))
        .unwrap();
    let dir = run.path();
    let mnt = dir.join("state-mnt");
    std::fs::create_dir_all(&mnt).unwrap();

    let data = Logged::new(dir, "data", DATA_BYTES, |_| {});
    let state = Logged::new(dir, "state", STATE_BYTES, |p| {
        let out = Command::new("mkfs.ext4")
            .args(["-q", "-F", p.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "mkfs: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
    let owner = me();
    sudo(&["chown", &owner, &data.dev()]);
    sudo(&["mount", &state.dev(), mnt.to_str().unwrap()]);
    sudo(&["chown", &owner, mnt.to_str().unwrap()]);

    // The workload, with marks.
    // Checkpoints, and the log truncations after them, every few hundred
    // writes rather than every 64 MiB: power is cut through them too.
    let osd = Arc::new(
        OsdService::new_with_store(vec![data.dev()], BLOCK_SIZE, mnt.join("state"), |c| {
            c.memtable_bytes = 256 << 10;
            c.wal.max_size_bytes = 512 << 10;
            c.engine = engine();
        })
        .expect("OSD on the logged devices"),
    );
    let acked: Arc<Mutex<Vec<Acked>>> = Arc::default();
    let stop = Arc::new(AtomicBool::new(false));
    let next = Arc::new(AtomicUsize::new(0));
    let writers: Vec<_> = (0..8)
        .map(|_| {
            let (osd, acked, stop, next) = (
                Arc::clone(&osd),
                Arc::clone(&acked),
                Arc::clone(&stop),
                Arc::clone(&next),
            );
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let n = next.fetch_add(1, Ordering::Relaxed) as u64;
                    let a = write_one(&osd, n).await;
                    acked.lock().unwrap().push(a);
                }
            })
        })
        .collect();
    // (mark, how many writes had been acknowledged before it was placed)
    let mut marks: Vec<(String, usize)> = Vec::new();
    let started = std::time::Instant::now();
    let mut i = 0;
    while started.elapsed() < Duration::from_secs(secs) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let before = acked.lock().unwrap().len();
        let label = format!("m{i}");
        // A write acknowledged before this point was durable before it,
        // on both devices; the marks go in after.
        data.mark(&label);
        state.mark(&label);
        marks.push((label, before));
        i += 1;
    }
    stop.store(true, Ordering::Relaxed);
    for w in writers {
        w.await.unwrap();
    }
    let acked = acked.lock().unwrap().clone();
    eprintln!("{} writes acknowledged, {} marks", acked.len(), marks.len());
    // The cut: no orderly shutdown reaches the logged images that matter
    // (everything after the last mark is ignored).
    drop(osd);
    sudo(&["umount", mnt.to_str().unwrap()]);
    data.remove();
    state.remove();

    // Replays: at sampled marks, and at a random point (each device its
    // own: a power cut leaves each drive with its own unflushed tail)
    // between a mark and the next, where writes are in flight.
    let step = (marks.len() / cuts).max(1);
    let mut failures = Vec::new();
    let mut rng = 0x9e37_79b9_7f4a_7c15_u64 ^ u64::from(std::process::id());
    let mut random = move |n: usize| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        (rng % n.max(1) as u64) as usize
    };
    let mut cut_points = Vec::new();
    for (m, (label, before)) in marks.iter().enumerate().step_by(step) {
        let (d, s) = (mark_index(&data, label), mark_index(&state, label));
        cut_points.push((label.to_string(), d, s, *before));
        if let Some((next, _)) = marks.get(m + 1) {
            let (dn, sn) = (mark_index(&data, next), mark_index(&state, next));
            cut_points.push((
                format!("{label}+"),
                d + random(dn - d),
                s + random(sn - s),
                *before,
            ));
        }
    }
    // The replay must really cut: at the first cut point, writes
    // acknowledged well after it are missing from the flushed-only image.
    let mut proved_cut = false;
    for (name, d_end, s_end, before) in cut_points {
        for flushed_only in [false, true] {
            let d = dir.join("replay-data.img");
            let s = dir.join("replay-state.img");
            replay(&data, d_end, flushed_only, &d);
            replay(&state, s_end, flushed_only, &s);
            let lo = losetup(&s);
            let out = Command::new("sudo")
                .args(["-n", "mount", &lo, mnt.to_str().unwrap()])
                .output()
                .unwrap();
            if !out.status.success() {
                failures.push(format!(
                    "{name} (flushed_only={flushed_only}): state filesystem does not mount: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
                sudo(&["losetup", "-d", &lo]);
                continue;
            }
            sudo(&["chown", "-R", &owner, mnt.to_str().unwrap()]);
            let wrong = check(&d, &mnt.join("state"), &acked[..before]).await;
            eprintln!(
                "cut at {name} (flushed_only={flushed_only}): {before} acknowledged, {} wrong",
                wrong.len()
            );
            if !wrong.is_empty() {
                failures.push(format!(
                    "{name} (flushed_only={flushed_only}): {} of {before} wrong: {:?}",
                    wrong.len(),
                    &wrong[..wrong.len().min(5)]
                ));
            }
            if !proved_cut && flushed_only {
                let later =
                    &acked[(before + 500).min(acked.len())..(before + 520).min(acked.len())];
                if !later.is_empty() {
                    let missing = check(&d, &mnt.join("state"), later).await.len();
                    assert!(
                        missing > 0,
                        "{name}: writes made after the cut are there: not a cut"
                    );
                    proved_cut = true;
                }
            }
            sudo(&["umount", mnt.to_str().unwrap()]);
            sudo(&["losetup", "-d", &lo]);
        }
    }
    assert!(
        proved_cut,
        "no cut point had later writes to prove the cut with"
    );
    assert!(failures.is_empty(), "{failures:#?}");
}
