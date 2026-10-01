//! Block storage through the block gateway that aio runs with
//! `--block-port`: what a VM's disk needs from it — what was written reads
//! back, across restarts, whatever the size and alignment of the writes.

use objectio_e2e::Cluster;
use objectio_proto::block::block_service_client::BlockServiceClient;
use objectio_proto::block::{
    CreateVolumeRequest, FlushRequest, ListVolumesRequest, ReadRequest, WriteRequest,
};
use tonic::transport::Channel;

const MIB: u64 = 1024 * 1024;
/// The block layer's chunk: the unit it caches, erasure-codes and stores.
const CHUNK: u64 = 4 * MIB;

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
        let port = free_port();
        let nbd = free_port();
        let cluster = Cluster::start_with_ec_and_args(
            6,
            4,
            2,
            &[
                "--block-port",
                &port.to_string(),
                "--nbd-port",
                &nbd.to_string(),
            ],
        );
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
