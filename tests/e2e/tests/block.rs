//! Block storage through the block gateway that aio runs with
//! `--block-port`: what a VM's disk needs from it — what was written reads
//! back, across restarts, whatever the size and alignment of the writes.

use objectio_e2e::Cluster;
use objectio_proto::block::block_service_client::BlockServiceClient;
use std::time::{Duration, Instant};

use objectio_proto::block::{
    CloneVolumeRequest, CreateSnapshotRequest, CreateVolumeRequest, DeleteSnapshotRequest,
    DeleteVolumeRequest, FlushRequest, ListVolumesRequest, ReadRequest, WriteRequest,
};
use tonic::transport::Channel;

const MIB: u64 = 1024 * 1024;
/// The block layer's chunk: the unit it caches, erasure-codes and stores.
const CHUNK: u64 = 4 * MIB;
const CHUNK_LEN: usize = 4 << 20;

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A cluster with block storage, and a client for it.
struct Block {
    cluster: Cluster,
    port: u16,
    rt: tokio::runtime::Runtime,
}

impl Block {
    fn start() -> Self {
        Self::start_with_args(&[])
    }

    fn start_with_args(extra: &[&str]) -> Self {
        let port = free_port();
        let nbd = free_port();
        let (port_s, nbd_s) = (port.to_string(), nbd.to_string());
        let mut args = vec!["--block-port", &port_s, "--nbd-port", &nbd_s];
        args.extend_from_slice(extra);
        let cluster = Cluster::start_with_ec_and_args(6, 4, 2, &args);
        let rt = tokio::runtime::Runtime::new().unwrap();
        Self { cluster, port, rt }
    }

    fn client(&self) -> BlockServiceClient<Channel> {
        let url = format!("http://127.0.0.1:{}", self.port);
        self.rt.block_on(async {
            for _ in 0..100 {
                if let Ok(c) = BlockServiceClient::connect(url.clone()).await {
                    return c.max_decoding_message_size(64 << 20);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            panic!("block gateway at {url} did not answer");
        })
    }

    fn create(&self, name: &str, size: u64) -> String {
        self.rt
            .block_on(self.client().create_volume(CreateVolumeRequest {
                name: name.into(),
                size_bytes: size,
                ..Default::default()
            }))
            .unwrap()
            .into_inner()
            .volume
            .unwrap()
            .volume_id
    }

    /// The id of the volume called `name`, as the gateway knows it now.
    fn id_of(&self, name: &str) -> String {
        self.rt
            .block_on(self.client().list_volumes(ListVolumesRequest::default()))
            .unwrap()
            .into_inner()
            .volumes
            .into_iter()
            .find(|v| v.name == name)
            .unwrap_or_else(|| panic!("volume {name} is gone"))
            .volume_id
    }

    fn write(&self, vol: &str, offset: u64, data: &[u8]) {
        self.rt
            .block_on(self.client().write(WriteRequest {
                volume_id: vol.into(),
                offset_bytes: offset,
                data: data.to_vec(),
            }))
            .unwrap();
    }

    fn read(&self, vol: &str, offset: u64, len: u64) -> Vec<u8> {
        self.rt
            .block_on(self.client().read(ReadRequest {
                volume_id: vol.into(),
                offset_bytes: offset,
                length_bytes: u32::try_from(len).unwrap(),
            }))
            .unwrap()
            .into_inner()
            .data
    }

    fn flush(&self, vol: &str) {
        self.rt
            .block_on(self.client().flush(FlushRequest {
                volume_id: vol.into(),
            }))
            .unwrap();
    }

    fn restart(&mut self) {
        self.cluster.restart();
    }

    fn snapshot(&self, vol: &str, name: &str) -> String {
        self.rt
            .block_on(self.client().create_snapshot(CreateSnapshotRequest {
                volume_id: vol.into(),
                name: name.into(),
                ..Default::default()
            }))
            .unwrap()
            .into_inner()
            .snapshot
            .unwrap()
            .snapshot_id
    }

    fn clone_of(&self, snapshot: &str, name: &str) -> String {
        self.rt
            .block_on(self.client().clone_volume(CloneVolumeRequest {
                snapshot_id: snapshot.into(),
                name: name.into(),
                ..Default::default()
            }))
            .unwrap()
            .into_inner()
            .volume
            .unwrap()
            .volume_id
    }

    fn delete_volume(&self, vol: &str) {
        self.rt
            .block_on(self.client().delete_volume(DeleteVolumeRequest {
                volume_id: vol.into(),
                force: false,
            }))
            .unwrap();
    }

    fn delete_snapshot(&self, snapshot: &str) {
        self.rt
            .block_on(self.client().delete_snapshot(DeleteSnapshotRequest {
                snapshot_id: snapshot.into(),
            }))
            .unwrap();
    }
}

/// Bytes that do not repeat, so a misplaced or zeroed range shows.
fn pattern(len: u64, seed: u8) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ u64::from(seed);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn flushed_data_reads_back_after_a_restart() {
    let mut b = Block::start();
    let vol = b.create("disk", 64 * MIB);
    let data = pattern(2 * CHUNK, 1);
    b.write(&vol, 0, &data);
    b.flush(&vol);

    b.restart();

    let vol = b.id_of("disk");
    assert!(
        b.read(&vol, 0, 2 * CHUNK) == data,
        "the volume lost its data across a restart"
    );
}

/// A 4 KiB write into a chunk the gateway has not cached must keep the
/// other 4 MiB − 4 KiB of that chunk. The cache used to start such a chunk
/// from zeros, so the next flush wiped everything around the write.
#[test]
fn a_small_write_after_a_restart_keeps_the_rest_of_its_chunk() {
    let mut b = Block::start();
    let vol = b.create("disk", 16 * MIB);
    let mut want = pattern(CHUNK, 2);
    b.write(&vol, 0, &want);
    b.flush(&vol);

    b.restart();

    let vol = b.id_of("disk");
    let small = pattern(4096, 3);
    b.write(&vol, 8192, &small);
    b.flush(&vol);
    want[8192..8192 + 4096].copy_from_slice(&small);
    let got = b.read(&vol, 0, CHUNK);
    let wrong = got.iter().zip(&want).filter(|(a, b)| a != b).count();
    assert_eq!(
        wrong, 0,
        "{wrong} bytes of the chunk changed around a 4 KiB write"
    );
}

/// Writes the gateway acknowledged but had not flushed survive it being
/// killed: they are in its journal, which a restart replays.
#[test]
fn acknowledged_writes_survive_a_crash_before_the_flush() {
    let mut b = Block::start();
    let vol = b.create("disk", 16 * MIB);
    let data = pattern(MIB, 4);
    b.write(&vol, 3 * MIB, &data);

    b.restart(); // kills the process: nothing is flushed on the way down

    let vol = b.id_of("disk");
    assert!(
        b.read(&vol, 3 * MIB, MIB) == data,
        "an acknowledged write was lost in a crash"
    );
}

#[test]
fn io_past_the_end_of_a_volume_is_refused() {
    let b = Block::start();
    let vol = b.create("small", 8 * MIB);
    let past = b.rt.block_on(b.client().write(WriteRequest {
        volume_id: vol.clone(),
        offset_bytes: 8 * MIB - 512,
        data: vec![1; 1024],
    }));
    assert_eq!(past.unwrap_err().code(), tonic::Code::OutOfRange);
    let read = b.rt.block_on(b.client().read(ReadRequest {
        volume_id: vol,
        offset_bytes: 8 * MIB,
        length_bytes: 512,
    }));
    assert_eq!(read.unwrap_err().code(), tonic::Code::OutOfRange);
}

/// What snapshots are for: the volume moves on, the snapshot does not, and
/// a clone starts from the snapshot and then goes its own way — all of it
/// still so after a restart.
#[test]
fn a_snapshot_keeps_its_point_in_time_and_a_clone_starts_from_it() {
    let mut b = Block::start();
    let vol = b.create("base", 4 * CHUNK);
    let before = pattern(2 * CHUNK, 1);
    b.write(&vol, 0, &before);
    // Not flushed: taking the snapshot stores what was written first.
    let snap = b.snapshot(&vol, "s1");

    let after = pattern(CHUNK, 2);
    b.write(&vol, 0, &after);
    b.flush(&vol);
    let clone = b.clone_of(&snap, "copy");
    assert_eq!(
        b.read(&clone, 0, 2 * CHUNK),
        before,
        "the clone is not the snapshot"
    );

    let own = pattern(4096, 3);
    b.write(&clone, CHUNK + 512, &own);
    b.flush(&clone);

    let check = |b: &Block, when: &str| {
        let (vol, clone) = (b.id_of("base"), b.id_of("copy"));
        assert_eq!(
            b.read(&vol, 0, CHUNK),
            after,
            "the volume lost its write {when}"
        );
        assert_eq!(
            b.read(&vol, CHUNK, CHUNK),
            before[CHUNK_LEN..],
            "the volume's untouched chunk changed {when}"
        );
        let mut want = before.clone();
        want[CHUNK_LEN + 512..CHUNK_LEN + 512 + own.len()].copy_from_slice(&own);
        assert_eq!(
            b.read(&clone, 0, 2 * CHUNK),
            want,
            "the clone is wrong {when}"
        );
    };
    check(&b, "");
    b.restart();
    check(&b, "after a restart");
}

/// Deleting gives back exactly what nothing else uses: a snapshot keeps the
/// chunks it shares alive past its volume, and the space comes back when
/// the last holder goes.
#[test]
fn deleting_frees_only_what_nothing_else_uses() {
    let b = Block::start();
    let empty = b.cluster.total_used_bytes();
    let vol = b.create("v", 2 * CHUNK);
    let first = pattern(CHUNK, 4);
    b.write(&vol, 0, &first);
    b.flush(&vol);
    let one_chunk = b
        .cluster
        .await_total_used_bytes(b.cluster.total_used_bytes());
    assert!(one_chunk > empty);

    let snap = b.snapshot(&vol, "keep");
    b.write(&vol, 0, &pattern(CHUNK, 5));
    b.flush(&vol);
    let two_chunks = b.cluster.total_used_bytes();
    assert!(
        two_chunks > one_chunk,
        "the overwrite freed the snapshot's chunk"
    );

    // The volume's own chunk goes; the snapshot's stays readable.
    b.delete_volume(&vol);
    assert_eq!(b.cluster.await_total_used_bytes(one_chunk), one_chunk);
    let clone = b.clone_of(&snap, "from-snapshot");
    assert_eq!(b.read(&clone, 0, CHUNK), first);

    b.delete_snapshot(&snap);
    assert_eq!(
        b.cluster.total_used_bytes(),
        one_chunk,
        "the clone still uses it"
    );
    b.delete_volume(&clone);
    assert_eq!(b.cluster.await_total_used_bytes(empty), empty);
}

/// The gateway keeps nothing a volume depends on: losing its whole
/// directory loses no volume and no flushed data.
#[test]
fn volumes_survive_the_loss_of_the_gateways_own_disk() {
    let mut b = Block::start();
    let vol = b.create("v", 2 * CHUNK);
    let data = pattern(CHUNK + 4096, 6);
    b.write(&vol, 0, &data);
    b.flush(&vol);

    b.cluster.restart_without("block");
    let vol = b.id_of("v");
    assert_eq!(b.read(&vol, 0, CHUNK + 4096), data);
}

/// Sum of every sample of `name` whose labels contain all of `labels`.
fn metric(c: &Cluster, name: &str, labels: &[&str]) -> u64 {
    c.request("GET", "/metrics", &[])
        .text()
        .lines()
        .filter(|l| {
            l.split(['{', ' ']).next() == Some(name) && labels.iter().all(|want| l.contains(want))
        })
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// Block chunks are repaired like objects: after a disk is lost and its
/// shards rebuilt, a volume survives two more lost disks.
#[test]
fn a_lost_disk_is_rebuilt_for_block_chunks_too() {
    let mut b = Block::start_with_args(&["--repair-interval-secs", "1"]);
    let vol = b.create("v", 2 * CHUNK);
    let data = pattern(2 * CHUNK, 7);
    b.write(&vol, 0, &data);
    b.flush(&vol);

    b.cluster.restart_with_lost_disk(0);
    let deadline = Instant::now() + Duration::from_secs(120);
    let rebuilt = |b: &Block| {
        metric(
            &b.cluster,
            "objectio_meta_repair_shards_rebuilt_total",
            &["reason=\"missing\""],
        )
    };
    while rebuilt(&b) < 2 {
        assert!(
            Instant::now() < deadline,
            "the block chunks were not rebuilt"
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    b.cluster.restart_with_lost_disks(&[1, 2]);
    let vol2 = b.id_of("v");
    assert_eq!(vol2, vol);
    assert_eq!(
        b.read(&vol, 0, 2 * CHUNK),
        data,
        "unreadable with two more disks lost"
    );
}
