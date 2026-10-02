//! Draining an OSD: everything with a shard on it, of every kind, ends up
//! elsewhere, and the OSD is marked Out only then.
//!
//! The proof is the one an operator relies on: once the console says Out,
//! the drained disk can be pulled and two more lost, and everything still
//! reads back (4+2 on seven OSDs: each stripe has one shard per OSD).

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use objectio_proto::block::block_service_client::BlockServiceClient;
use objectio_proto::block::{CreateVolumeRequest, FlushRequest, ReadRequest, WriteRequest};
use serde_json::json;

const MIB: usize = 1024 * 1024;

fn payload(len: usize, seed: u8) -> Vec<u8> {
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

fn tag(xml: &str, name: &str) -> String {
    xml.split(&format!("<{name}>"))
        .nth(1)
        .and_then(|s| s.split(&format!("</{name}>")).next())
        .unwrap_or_else(|| panic!("no <{name}> in {xml}"))
        .to_string()
}

/// A two-part multipart upload: its stripes are stored under the parts'
/// ids, not the object's.
fn multipart(c: &Cluster, path: &str, body: &[u8]) {
    let r = c.request("POST", &format!("{path}?uploads"), &[]);
    r.expect(200);
    let upload = tag(&r.text(), "UploadId");
    let mut parts = String::new();
    for (n, chunk) in body.chunks(5 * MIB).enumerate() {
        let n = n + 1;
        let r = c.request(
            "PUT",
            &format!("{path}?partNumber={n}&uploadId={upload}"),
            chunk,
        );
        r.expect(200);
        let etag = r.header("etag").unwrap_or_default();
        let _ = write!(
            parts,
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        );
    }
    c.request(
        "POST",
        &format!("{path}?uploadId={upload}"),
        format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>").as_bytes(),
    )
    .expect(200);
}

fn osd_id(c: &Cluster, index: usize) -> String {
    let addr = c.osd_address(index);
    let nodes = c.request("GET", "/_admin/nodes", &[]).json();
    nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["address"].as_str() == Some(addr.as_str()))
        .and_then(|n| n["node_id"].as_str())
        .unwrap_or_else(|| panic!("no OSD at {addr} in {nodes}"))
        .to_string()
}

fn admin_state(c: &Cluster, id: &str) -> String {
    let nodes = c.request("GET", "/_admin/nodes", &[]).json();
    nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["node_id"].as_str() == Some(id))
        .and_then(|n| n["admin_state"].as_str())
        .unwrap_or("?")
        .to_string()
}

async fn block_client(port: u16) -> BlockServiceClient<tonic::transport::Channel> {
    loop {
        if let Ok(c) = BlockServiceClient::connect(format!("http://127.0.0.1:{port}")).await {
            return c.max_decoding_message_size(64 << 20);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A volume holding `data`, stored as chunks (flushed).
async fn write_volume(port: u16, data: &[u8]) -> String {
    let mut client = block_client(port).await;
    let vol = client
        .create_volume(CreateVolumeRequest {
            name: "v".into(),
            size_bytes: 16 * MIB as u64,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .volume
        .unwrap()
        .volume_id;
    client
        .write(WriteRequest {
            volume_id: vol.clone(),
            offset_bytes: 0,
            data: data.to_vec(),
        })
        .await
        .unwrap();
    client
        .flush(FlushRequest {
            volume_id: vol.clone(),
        })
        .await
        .unwrap();
    drop(client);
    vol
}

async fn read_volume(port: u16, vol: String, len: usize) -> Result<Vec<u8>, tonic::Status> {
    block_client(port)
        .await
        .read(ReadRequest {
            volume_id: vol,
            offset_bytes: 0,
            length_bytes: u32::try_from(len).unwrap(),
        })
        .await
        .map(|r| r.into_inner().data)
}

#[test]
fn a_drained_osd_can_be_pulled_with_two_more_lost() {
    let mut c = Cluster::start_with_ec_and_args(
        7,
        4,
        2,
        &[
            "--drain-interval-secs",
            "1",
            "--block-port",
            "{free}",
            "--nbd-port",
            "{free}",
        ],
    );
    let bp: u16 = c.arg("--block-port").unwrap().parse().unwrap();
    c.json("POST", "/_admin/buckets", json!({"name": "d"}))
        .expect_ok();

    // Every kind of stripe: single-part objects, a multipart object, a
    // copy sharing its source's stripe, and block chunks in meta's tables.
    let small: Vec<Vec<u8>> = (0..3).map(|i| payload(300_000, i)).collect();
    for (i, body) in small.iter().enumerate() {
        c.request("PUT", &format!("/d/s{i}"), body).expect(200);
    }
    let big = payload(5 * MIB + 70_000, 9);
    multipart(&c, "/d/big", &big);
    c.request_with_headers("PUT", "/d/copy", &[], &[("x-amz-copy-source", "/d/s0")])
        .expect(200);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let block = payload(2 * 4 * MIB, 11);
    let vol = rt.block_on(write_volume(bp, &block));

    let drained = osd_id(&c, 0);
    c.json(
        "PUT",
        &format!("/_admin/osds/{drained}/admin-state"),
        json!({"state": "draining"}),
    )
    .expect_ok();
    let deadline = Instant::now() + Duration::from_secs(240);
    while admin_state(&c, &drained) != "out" {
        assert!(
            Instant::now() < deadline,
            "OSD 0 never finished draining: {}",
            admin_state(&c, &drained)
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    // Pull the drained disk, and lose two more.
    c.restart_with_lost_disks(&[0, 1, 2]);
    for (i, body) in small.iter().enumerate() {
        let got = c.request("GET", &format!("/d/s{i}"), &[]);
        assert_eq!(got.status, 200, "s{i}: {}", got.text());
        assert_eq!(&got.bytes, body, "s{i} changed");
    }
    let got = c.request("GET", "/d/copy", &[]);
    assert_eq!(got.status, 200, "the copy: {}", got.text());
    assert_eq!(got.bytes, small[0], "the copy changed");
    let got = c.request("GET", "/d/big", &[]);
    assert_eq!(got.status, 200, "the multipart object: {}", got.text());
    assert_eq!(got.bytes, big, "the multipart object changed");
    let read = rt.block_on(read_volume(bp, vol, block.len()));
    assert_eq!(
        read.expect("the block volume is unreadable"),
        block,
        "the block volume changed"
    );
}

/// The shards and metadata copies a drained OSD still holds once nothing
/// refers to them.
async fn osd_shards(address: String) -> u64 {
    use objectio_proto::storage::GetStatusRequest;
    use objectio_proto::storage::storage_service_client::StorageServiceClient;
    let uri = if address.starts_with("http") {
        address
    } else {
        format!("http://{address}")
    };
    let mut client = StorageServiceClient::connect(uri)
        .await
        .expect("connect OSD");
    client
        .get_status(GetStatusRequest::default())
        .await
        .expect("status")
        .into_inner()
        .shard_count
}

/// A drained OSD is wiped once it's Out, and can come back without
/// bringing stale copies with it: an object deleted after the drain stays
/// deleted.
#[test]
fn a_drained_osd_is_purged_and_rejoins_clean() {
    let c = Cluster::start_with_ec_and_args(7, 4, 2, &["--drain-interval-secs", "1"]);
    c.json("POST", "/_admin/buckets", json!({"name": "pur"}))
        .expect_ok();
    let bodies: Vec<Vec<u8>> = (0..6).map(|i| payload(200_000, i)).collect();
    for (i, body) in bodies.iter().enumerate() {
        c.request("PUT", &format!("/pur/o{i}"), body).expect(200);
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    let addr = c.osd_address(0);
    assert!(
        rt.block_on(osd_shards(addr.clone())) > 0,
        "OSD 0 holds nothing to drain"
    );

    let drained = osd_id(&c, 0);
    c.json(
        "PUT",
        &format!("/_admin/osds/{drained}/admin-state"),
        json!({"state": "draining"}),
    )
    .expect_ok();
    let deadline = Instant::now() + Duration::from_secs(240);
    while admin_state(&c, &drained) != "out" {
        assert!(Instant::now() < deadline, "never drained");
        std::thread::sleep(Duration::from_secs(1));
    }
    // Then wiped: its space comes back.
    let deadline = Instant::now() + Duration::from_secs(60);
    while rt.block_on(osd_shards(addr.clone())) > 0 {
        assert!(
            Instant::now() < deadline,
            "the drained OSD was never purged"
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    // Deleted while it's out; then it rejoins.
    c.request("DELETE", "/pur/o1", &[]).expect(204);
    c.json(
        "PUT",
        &format!("/_admin/osds/{drained}/admin-state"),
        json!({"state": "in"}),
    )
    .expect_ok();
    assert_eq!(admin_state(&c, &drained), "in");
    let listing = c.request("GET", "/pur?list-type=2", &[]).text();
    assert!(
        !listing.contains("<Key>o1</Key>"),
        "a deleted object came back: {listing}"
    );
    assert_eq!(c.request("GET", "/pur/o1", &[]).status, 404);
    for (i, body) in bodies.iter().enumerate().filter(|(i, _)| *i != 1) {
        let got = c.request("GET", &format!("/pur/o{i}"), &[]);
        assert_eq!(got.status, 200, "o{i}: {}", got.text());
        assert_eq!(&got.bytes, body, "o{i} changed");
    }
    // And it takes new data again.
    c.request("PUT", "/pur/after", b"new").expect(200);
    assert_eq!(c.request("GET", "/pur/after", &[]).bytes, b"new");
}
