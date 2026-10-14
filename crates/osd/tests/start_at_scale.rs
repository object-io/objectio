//! An OSD of many shards back in seconds after a power cut (roadmap B32;
//! objectio-docs `core/osd-start.md`). Grow an OSD to N shards through its
//! own handlers, stop it without a clean shutdown, then start it: it must
//! serve at once, take writes while it counts its PG summaries and bucket
//! usage in the background, and count what a count from scratch gives.
//!
//! Three runs, each its own process, on a directory kept between them:
//!
//! ```text
//! export B32_DIR=/b32
//! B32_SHARDS=10000000 B32_MODE=grow \
//!   cargo test --release -p objectio-osd --test start_at_scale -- --ignored --nocapture
//! # evict the directory from the page cache here, for a cold start
//! B32_MODE=start cargo test …   # serve, write while counting, record the counts
//! B32_MODE=verify cargo test …  # count again from scratch, compare
//! ```
//!
//! `grow` adds shards up to `B32_SHARDS` (a second grow to a larger count
//! adds the rest), one object per shard as an OSD holds them: its metadata
//! copy (one stripe, 4+2, in one of 256 placement groups) and its shard,
//! `B32_SMALL_PCT` (50) percent small (1 KiB, kept in the index), the rest
//! one 4 KiB block each on a sparse disk of `B32_DISK_GIB` (200). Each run
//! exits without dropping the OSD: what the store had not checkpointed is
//! replayed from its log at the next start, as after a power cut.
//!
//! `start` asserts a read and a block write within `B32_SERVE_SECS` (30) of
//! the start, writes (new objects, overwrites, deletes) until both counts
//! are done, reads back everything it wrote by CRC, and records every PG's
//! summary and the bucket usage. `verify` starts again and asserts the
//! counts equal those.

use objectio_osd::service::OsdService;
use objectio_proto::metadata::{ObjectMeta, ShardLocation, StripeMeta};
use objectio_proto::storage::storage_service_server::StorageService;
use objectio_proto::storage::{
    Checksum, DeleteObjectMetaRequest, GetObjectMetaRequest, GetPgInfoRequest, GetStatusRequest,
    PutObjectMetaRequest, ReadShardRequest, ShardId, SmallShard, WriteShardRequest,
};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tonic::Request;

const BLOCK_SIZE: u32 = 4096;
const PGS: u32 = 256;
/// The writers while counting: each owns the keys `n ≡ w (mod WRITERS)`.
const WRITERS: u64 = 64;

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |v| v.parse().expect(name))
}

/// Object `n`'s id at generation `generation` (0: as grown; each
/// overwrite another).
fn object_id(n: u64, generation: u64) -> Vec<u8> {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&n.to_le_bytes());
    id[8..].copy_from_slice(
        &(n.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ generation.wrapping_mul(0x51)).to_le_bytes(),
    );
    id.to_vec()
}

fn key(n: u64) -> String {
    format!("data/{:04}/{:02}/object-{n:010}.parquet", n % 7919, n % 97)
}

fn small(n: u64) -> bool {
    n % 100 < env("B32_SMALL_PCT", 50)
}

fn shard(n: u64, generation: u64) -> ShardId {
    ShardId {
        object_id: object_id(n, generation),
        stripe_id: 0,
        position: (n % 6) as u32,
    }
}

fn data(n: u64, generation: u64, len: u64) -> Vec<u8> {
    (0..len).map(|i| (i ^ n ^ generation) as u8).collect()
}

/// A stamp later than every earlier write of object `n` (`n` below 2^24).
fn stamp(n: u64, generation: u64) -> u64 {
    (generation << 24) + n
}

/// This run's first generation: later than any earlier run's.
fn run_generation() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        << 8
}

/// The metadata copy of object `n`: one 4+2 stripe over six OSDs, its
/// usage counted by `owner` (no one, for the grown objects).
fn object_meta(n: u64, generation: u64, size: u64, owner: &[u8]) -> ObjectMeta {
    let shards = (0..6u32)
        .map(|p| ShardLocation {
            position: p,
            node_id: {
                let mut id = vec![0u8; 16];
                id[0] = p as u8 + 1;
                id
            },
            disk_id: vec![p as u8; 16],
            ..Default::default()
        })
        .collect();
    ObjectMeta {
        bucket: "bench".into(),
        key: key(n),
        object_id: object_id(n, generation),
        size,
        etag: format!("{:032x}", u128::from(n) * 0x1234_5678_9abc_def1),
        content_type: "application/octet-stream".into(),
        created_at: 1_760_000_000 + n,
        modified_at: 1_760_000_000 + n,
        stamp: stamp(n, generation),
        stripes: vec![StripeMeta {
            stripe_id: 0,
            ec_k: 4,
            ec_m: 2,
            data_size: size,
            object_id: object_id(n, generation),
            shards,
            ..Default::default()
        }],
        pg_pool: "default".into(),
        pg_id: (n % u64::from(PGS)) as u32,
        usage_owner: owner.to_vec(),
        ..Default::default()
    }
}

/// Write object `n` at `generation`: its shard (a block, or kept in its
/// record if small), then its metadata.
async fn put(osd: &OsdService, n: u64, generation: u64, owner: &[u8]) {
    if small(n) {
        let data = data(n, generation, 1024);
        osd.put_object_meta(Request::new(PutObjectMetaRequest {
            bucket: "bench".into(),
            key: key(n),
            object: Some(object_meta(n, generation, 4096, owner)),
            shard: Some(SmallShard {
                shard_id: Some(shard(n, generation)),
                crc32c: crc32c::crc32c(&data),
                data,
            }),
            ..Default::default()
        }))
        .await
        .unwrap();
        return;
    }
    let data = data(n, generation, u64::from(BLOCK_SIZE));
    osd.write_shard(Request::new(WriteShardRequest {
        shard_id: Some(shard(n, generation)),
        checksum: Some(Checksum {
            crc32c: crc32c::crc32c(&data),
            ..Default::default()
        }),
        data: data.into(),
        ec_k: 4,
        ec_m: 2,
        ..Default::default()
    }))
    .await
    .unwrap();
    osd.put_object_meta(Request::new(PutObjectMetaRequest {
        bucket: "bench".into(),
        key: key(n),
        object: Some(object_meta(
            n,
            generation,
            16 * u64::from(BLOCK_SIZE),
            owner,
        )),
        ..Default::default()
    }))
    .await
    .unwrap();
}

async fn delete(osd: &OsdService, n: u64, generation: u64) {
    osd.delete_object_meta(Request::new(DeleteObjectMetaRequest {
        bucket: "bench".into(),
        key: key(n),
        stamp: stamp(n, generation),
        ..Default::default()
    }))
    .await
    .unwrap();
}

/// Object `n` reads back as written at `generation` (`None`: deleted):
/// its metadata, and its shard (a block, or kept in its record) by CRC.
async fn check(osd: &OsdService, n: u64, generation: Option<u64>) {
    let got = osd
        .get_object_meta(Request::new(GetObjectMetaRequest {
            bucket: "bench".into(),
            key: key(n),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    let Some(generation) = generation else {
        assert!(!got.found, "object {n} was deleted, yet found");
        return;
    };
    assert!(got.found, "object {n} not found");
    let object = got.object.expect("found");
    assert_eq!(object.object_id, object_id(n, generation), "object {n}");
    let r = osd
        .read_shard(Request::new(ReadShardRequest {
            shard_id: Some(shard(n, generation)),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    let len = if small(n) {
        1024
    } else {
        u64::from(BLOCK_SIZE)
    };
    assert_eq!(
        crc32c::crc32c(&r.data),
        crc32c::crc32c(&data(n, generation, len)),
        "object {n}'s shard"
    );
}

/// The generation object `n` was written at, from its id.
fn generation_of(n: u64, id: &[u8]) -> Option<u64> {
    let high = u64::from_le_bytes(id.get(8..16)?.try_into().ok()?);
    let x = high ^ n.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x.is_multiple_of(0x51).then_some(x / 0x51)
}

/// The first object from `n` on that is there (an earlier run may have
/// deleted some), read back as stored, whatever its generation.
async fn first_found(osd: &OsdService, mut n: u64) -> u64 {
    loop {
        let got = osd
            .get_object_meta(Request::new(GetObjectMetaRequest {
                bucket: "bench".into(),
                key: key(n),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        if let Some(o) = got.object.filter(|_| got.found) {
            let generation = generation_of(n, &o.object_id).expect("one of this test's ids");
            check(osd, n, Some(generation)).await;
            return n;
        }
        n += 1;
    }
}

fn open(dir: &Path) -> OsdService {
    OsdService::new_with_store(
        vec![dir.join("disk.raw").display().to_string()],
        BLOCK_SIZE,
        dir.join("state"),
        |_| {},
    )
    .unwrap()
}

async fn usage_counting(osd: &OsdService) -> bool {
    osd.get_status(Request::new(GetStatusRequest {
        answer_while_counting: true,
        ..Default::default()
    }))
    .await
    .unwrap()
    .into_inner()
    .usage_counting
}

/// Whether the OSD still counts its usage or its PG summaries.
async fn counting(osd: &OsdService) -> bool {
    let pgs = osd
        .get_pg_info(Request::new(GetPgInfoRequest {
            pool: "default".into(),
            pg_id: 0,
        }))
        .await
        .is_err();
    pgs || usage_counting(osd).await
}

/// Every PG's summary and the bucket usage, as text, once counted. A PG's
/// highest stamp is left out: it is the highest ever written, and stays
/// when that entry leaves, where a count from scratch no longer sees it.
async fn counts(osd: &OsdService) -> String {
    let mut out = String::new();
    for pg_id in 0..PGS {
        let s = osd
            .get_pg_info(Request::new(GetPgInfoRequest {
                pool: "default".into(),
                pg_id,
            }))
            .await
            .unwrap()
            .into_inner()
            .summary
            .unwrap_or_default();
        writeln!(
            out,
            "pg {pg_id}: {} objects, {} tombstones, {} stripes, {} short, {} named here, \
             digest {}",
            s.objects,
            s.tombstones,
            s.stripes,
            s.positions_short,
            s.named_here,
            hex::encode(&s.digest)
        )
        .unwrap();
    }
    let status = osd
        .get_status(Request::new(GetStatusRequest::default()))
        .await
        .unwrap()
        .into_inner();
    assert!(!status.usage_counting);
    // Last modified is left out too: deletes leave it where it was.
    for u in status.bucket_usage {
        writeln!(
            out,
            "usage {}: {} objects, {} bytes, {} stored, {} noncurrent, {} noncurrent bytes",
            u.bucket,
            u.objects,
            u.logical_bytes,
            u.stored_bytes,
            u.noncurrent_versions,
            u.noncurrent_bytes
        )
        .unwrap();
    }
    out
}

/// Bytes this process has read from storage (not from the page cache).
fn read_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/io")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| {
                    l.strip_prefix("read_bytes: ")
                        .map(|v| v.trim().parse().ok())
                })
                .flatten()
        })
        .unwrap_or(0)
}

fn peak_rss() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM"))
                .map(str::to_string)
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "at scale; B32_DIR, B32_MODE (grow, start, verify), B32_SHARDS"]
async fn an_osd_of_many_shards_serves_in_seconds_after_a_power_cut() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .try_init();
    let dir = std::path::PathBuf::from(std::env::var("B32_DIR").expect("B32_DIR"));
    let mode = std::env::var("B32_MODE").expect("B32_MODE");
    std::fs::create_dir_all(&dir).unwrap();
    let count = dir.join("count");
    let have: u64 = std::fs::read_to_string(&count).map_or(0, |s| s.trim().parse().unwrap());
    match mode.as_str() {
        "grow" => {
            let want = env("B32_SHARDS", 1_000_000);
            let disk = dir.join("disk.raw");
            if !disk.exists() {
                std::fs::File::create(&disk)
                    .unwrap()
                    .set_len(env("B32_DISK_GIB", 200) << 30)
                    .unwrap();
            }
            let osd = Arc::new(open(&dir));
            let next = Arc::new(AtomicU64::new(have));
            let started = Instant::now();
            let tasks: Vec<_> = (0..env("B32_CONCURRENCY", 256))
                .map(|_| {
                    let (osd, next) = (Arc::clone(&osd), Arc::clone(&next));
                    tokio::spawn(async move {
                        loop {
                            let n = next.fetch_add(1, Ordering::Relaxed);
                            if n >= want {
                                return;
                            }
                            put(&osd, n, 0, &[]).await;
                            if n % 100_000 == 0 && n > have {
                                println!(
                                    "{n} shards, {:.0}/s",
                                    (n - have) as f64 / started.elapsed().as_secs_f64()
                                );
                            }
                        }
                    })
                })
                .collect();
            for t in tasks {
                t.await.unwrap();
            }
            std::fs::write(&count, want.to_string()).unwrap();
            println!(
                "grew to {want} shards in {:.0?}; exiting without a clean shutdown; {}",
                started.elapsed(),
                peak_rss()
            );
            // As a power cut would leave it: no drop, no checkpoint.
            std::process::exit(0);
        }
        "start" => {
            let (read0, started) = (read_bytes(), Instant::now());
            let osd = Arc::new(open(&dir));
            let serving = started.elapsed();
            let owner = osd.node_id().to_vec();
            // A caller from before `usage_counting` is answered once usage
            // is counted, never with a partial count.
            let old_caller = {
                let osd = Arc::clone(&osd);
                tokio::spawn(async move {
                    osd.get_status(Request::new(GetStatusRequest::default()))
                        .await
                        .unwrap();
                    assert!(!usage_counting(&osd).await);
                    started.elapsed()
                })
            };
            first_found(&osd, have / 2).await;
            let first_read = started.elapsed();
            // A block write, of a key below the writers' new ones (a
            // generation no earlier run wrote).
            let first = (have + 1..).find(|&n| !small(n)).unwrap();
            let first_generation = run_generation();
            put(&osd, first, first_generation, &owner).await;
            let first_write = started.elapsed();
            let read = read_bytes() - read0;
            println!(
                "B32 start: {have} shards; serving in {serving:.2?}, first read {first_read:.2?}, \
                 first block write {first_write:.2?}; {:.1} MiB read from storage",
                read as f64 / f64::from(1 << 20)
            );
            assert!(
                first_write < Duration::from_secs(env("B32_SERVE_SECS", 30)),
                "an OSD of {have} shards took {first_write:?} to take a block write"
            );
            assert!(
                counting(&osd).await,
                "the counts were done before it served"
            );

            // While it counts: new objects, overwrites of grown ones (into
            // this OSD's usage), deletes. Each writer owns its keys.
            let written = Arc::new(parking_lot::Mutex::new(HashMap::from([(
                first,
                Some(first_generation),
            )])));
            let ops = Arc::new(AtomicU64::new(0));
            let writers: Vec<_> = (0..WRITERS)
                .map(|w| {
                    let (osd, owner, written, ops) = (
                        Arc::clone(&osd),
                        owner.clone(),
                        Arc::clone(&written),
                        Arc::clone(&ops),
                    );
                    tokio::spawn(async move {
                        let mut r = 0x2545_f491_4f6c_dd1d_u64 ^ (w * 0x9e37);
                        let mut generation = first_generation;
                        while counting(&osd).await {
                            r ^= r << 13;
                            r ^= r >> 7;
                            r ^= r << 17;
                            // A new key past the grown ones, or a grown one.
                            let n = if r.is_multiple_of(3) {
                                have + 1_000 + (r >> 8) % 1_000_000
                            } else {
                                (r >> 8) % have.max(1)
                            };
                            let n = n - n % WRITERS + w;
                            generation += 1;
                            if (r >> 40).is_multiple_of(5) {
                                delete(&osd, n, generation).await;
                                written.lock().insert(n, None);
                            } else {
                                put(&osd, n, generation, &owner).await;
                                written.lock().insert(n, Some(generation));
                            }
                            ops.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                })
                .collect();
            for w in writers {
                w.await.unwrap();
            }
            let counted = started.elapsed();
            let old_caller = old_caller.await.unwrap();
            let written = std::mem::take(&mut *written.lock());
            for (&n, &generation) in &written {
                check(&osd, n, generation).await;
            }
            std::fs::write(dir.join("counted"), counts(&osd).await).unwrap();
            println!(
                "B32 counted by {counted:.2?} (a caller from before answered at \
                 {old_caller:.2?}); {} writes while counting, all read back; {}",
                ops.load(Ordering::Relaxed),
                peak_rss()
            );
            std::process::exit(0);
        }
        "verify" => {
            let osd = open(&dir);
            while counting(&osd).await {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let want = std::fs::read_to_string(dir.join("counted")).expect("run start first");
            let got = counts(&osd).await;
            assert!(
                want == got,
                "the counts after the start differ from a count from scratch:\n{}",
                want.lines()
                    .zip(got.lines())
                    .filter(|(a, b)| a != b)
                    .take(5)
                    .map(|(a, b)| format!("start:  {a}\nverify: {b}\n"))
                    .collect::<String>()
            );
            println!("B32 verify: the counts equal a count from scratch");
            std::process::exit(0);
        }
        other => panic!("B32_MODE {other}: grow, start or verify"),
    }
}
