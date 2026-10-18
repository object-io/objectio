//! Small objects whose shards are kept with their metadata (B21): a GET
//! takes the shards from the metadata answers, with no shard reads.

use std::path::Path;
use std::time::Duration;

use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use serde_json::json;

/// Shard reads the gateway has made so far.
fn shard_reads(c: &Cluster) -> u64 {
    c.request("GET", "/metrics", &[])
        .text()
        .lines()
        .filter(|l| {
            l.starts_with("objectio_gateway_shard_latency_seconds_count")
                && l.contains("direction=\"read\"")
        })
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap() ^ seed)
        .collect()
}

#[test]
fn a_small_get_reads_no_shards() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &[]);
    c.json("POST", "/_admin/buckets", json!({"name": "small"}))
        .expect_ok();
    let body = payload(64 * 1024, 1);
    c.request("PUT", "/small/k", &body).expect(200);

    let before = shard_reads(&c);
    let got = c.request("GET", "/small/k", &[]);
    got.expect(200);
    assert_eq!(got.bytes, body);
    let ranged = c.request_with_headers("GET", "/small/k", &[], &[("Range", "bytes=100-199")]);
    ranged.expect(206);
    assert_eq!(ranged.bytes, body[100..200]);
    assert_eq!(shard_reads(&c), before, "a small GET read shards");

    // Overwritten, the GET decodes the new object's shards, not the old.
    let newer = payload(40 * 1024, 2);
    c.request("PUT", "/small/k", &newer).expect(200);
    let got = c.request("GET", "/small/k", &[]);
    got.expect(200);
    assert_eq!(got.bytes, newer);
    assert_eq!(shard_reads(&c), before, "a small GET read shards");

    // A large object's shards are on disk: its GET reads them (and the
    // count above is a live one).
    let large = payload(1024 * 1024, 3);
    c.request("PUT", "/small/large", &large).expect(200);
    let got = c.request("GET", "/small/large", &[]);
    got.expect(200);
    assert_eq!(got.bytes, large);
    assert!(shard_reads(&c) > before, "a large GET read no shards");
}

/// Two OSDs down (m = 2): the GET still decodes, from the four that answer,
/// parity among them.
#[test]
fn a_small_get_with_two_osds_down_still_decodes() {
    let mut ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/degraded", &[]).status, 200);
    let objects: Vec<(String, Vec<u8>)> = (0..8u8)
        .map(|i| {
            (
                format!("/degraded/k{i}"),
                payload(20_000 + usize::from(i) * 4096, i),
            )
        })
        .collect();
    for (path, body) in &objects {
        c.request("PUT", path, body).expect(200);
    }
    ha.stop_osd(0);
    ha.stop_osd(3);
    let c = &ha.clients[0];
    for (path, body) in &objects {
        let got = c.request("GET", path, &[]);
        got.expect(200);
        assert_eq!(&got.bytes, body, "{path}");
    }
}

/// The size of the first file named `name` under `dir`, at any depth.
fn file_len(dir: &Path, name: &str) -> Option<u64> {
    std::fs::read_dir(dir).ok()?.flatten().find_map(|e| {
        let path = e.path();
        if path.is_dir() {
            file_len(&path, name)
        } else {
            (e.file_name() == name)
                .then(|| e.metadata().ok().map(|m| m.len()))
                .flatten()
        }
    })
}

/// Bytes process `pid` has read so far, page cache included (`rchar`).
fn read_by(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/io"))
        .expect("/proc/<pid>/io")
        .lines()
        .find_map(|l| l.strip_prefix("rchar: ")?.trim().parse().ok())
        .expect("rchar")
}

/// An OSD's restart reads its small shards' locations, not their bytes.
/// The bytes were kept in each location record, and the startup passes
/// over every record (the block store's and the shard index's) read them
/// all: an OSD holding 115,000 small shards took five minutes to start
/// (B2 soak run 24).
///
/// Small objects are written until a checkpoint has taken OSD 0's
/// metadata into its index file (the WAL in front of it is replayed
/// whole on either layout); OSD 0 is then killed and started again, and
/// what it read before listening, less its WAL, must be a small part of
/// its index file. The count is of bytes read, page cache included, not
/// of time.
#[test]
#[cfg(target_os = "linux")]
fn an_osd_restart_does_not_read_its_small_shards_bytes() {
    let mut ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    assert_eq!(ha.clients[0].request("PUT", "/many", &[]).status, 200);

    // 64 KiB objects: 16 KiB shards, kept in the metadata (B21), one on
    // each OSD. The WAL is checkpointed past 64 MiB: some 4,000 objects.
    let index = |ha: &HaCluster| file_len(ha.osd_dir(0), "index.redb").unwrap_or(0);
    let mut written = 0usize;
    while index(&ha) < 48 << 20 {
        assert!(written < 12_000, "no checkpoint after {written} objects");
        let c = &ha.clients[0];
        std::thread::scope(|s| {
            for t in 0..8 {
                s.spawn(move || {
                    for i in (written + t..written + 512).step_by(8) {
                        let body = payload(64 * 1024, u8::try_from(i % 251).unwrap());
                        c.request("PUT", &format!("/many/k{i}"), &body).expect(200);
                    }
                });
            }
        });
        written += 512;
        std::thread::sleep(Duration::from_millis(200));
    }
    let index_len = index(&ha);

    ha.stop_osd(0);
    ha.start_osd(0, None);
    let read = read_by(ha.osd_pid(0).expect("OSD 0 runs"));
    let wal = file_len(ha.osd_dir(0), "metadata.wal").unwrap_or(0);
    let mib = |b: u64| b >> 20;
    println!(
        "{written} objects; index {} MiB, WAL {} MiB; read at start {} MiB",
        mib(index_len),
        mib(wal),
        mib(read)
    );
    assert!(
        read.saturating_sub(wal) < index_len / 4,
        "the restart read {} MiB besides its {} MiB WAL, of an index of {} MiB: \
         the small shards' bytes",
        mib(read.saturating_sub(wal)),
        mib(wal),
        mib(index_len)
    );
    // And it serves them.
    let got = ha.clients[0].request("GET", "/many/k7", &[]);
    got.expect(200);
    assert_eq!(got.bytes, payload(64 * 1024, 7));
}
