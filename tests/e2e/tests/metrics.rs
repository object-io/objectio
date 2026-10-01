//! `/metrics` as Prometheus reads it: a valid exposition (one declaration
//! per family, every sample declared), carrying what each service records
//! once the cluster has served some traffic.

use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use objectio_proto::block::block_service_client::BlockServiceClient;
use objectio_proto::block::{CreateVolumeRequest, FlushRequest, WriteRequest};
use serde_json::json;

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Object and block traffic of every kind the checks below look for.
fn serve_some_traffic(c: &Cluster, block_port: u16) {
    c.json("POST", "/_admin/buckets", json!({"name": "m"}))
        .expect_ok();
    c.request("PUT", "/m/a", &vec![7u8; 300_000]).expect(200);
    c.request_with_headers("PUT", "/m/b", &[], &[("x-amz-copy-source", "/m/a")])
        .expect(200);
    c.request("GET", "/m/b", &[]).expect(200);
    c.request("GET", "/m?versioning", &[]).expect(200);
    c.request("GET", "/m/missing", &[]).expect(404);
    c.request("PUT", "/m/tiny", b"small enough to be inline")
        .expect(200);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let url = format!("http://127.0.0.1:{block_port}");
        let mut client = loop {
            if let Ok(c) = BlockServiceClient::connect(url.clone()).await {
                break c;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let vol = client
            .create_volume(CreateVolumeRequest {
                name: "v".into(),
                size_bytes: 8 << 20,
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
                data: vec![1; 4096],
            })
            .await
            .unwrap();
        client.flush(FlushRequest { volume_id: vol }).await.unwrap();
        drop(client);
    });
}

/// Families every service must export once it has served traffic.
const EXPECTED: &[(&str, &str)] = &[
    ("objectio_s3_requests_total", "counter"),
    ("objectio_s3_request_duration_seconds", "histogram"),
    ("objectio_gateway_shard_latency_seconds", "histogram"),
    ("objectio_erasure_encode_seconds", "histogram"),
    ("objectio_osd_grpc_requests_total", "counter"),
    ("objectio_osd_grpc_latency_seconds", "histogram"),
    ("objectio_osd_wal_fsync_seconds", "histogram"),
    ("objectio_meta_grpc_requests_total", "counter"),
    ("objectio_meta_grpc_latency_seconds", "histogram"),
    ("objectio_meta_commit_seconds", "histogram"),
    ("objectio_build_info", "gauge"),
    // Block gateway, in this process under aio.
    ("objectio_block_io_seconds", "histogram"),
    ("objectio_block_io_bytes_total", "counter"),
    ("objectio_block_journal_fsync_seconds", "histogram"),
    ("objectio_block_chunks_flushed_total", "counter"),
    ("objectio_block_chunk_flush_seconds", "histogram"),
    ("objectio_block_cache_dirty_bytes", "gauge"),
    // Meta: Raft, the block tables, the stripe registry.
    ("objectio_meta_raft_is_leader", "gauge"),
    ("objectio_meta_raft_term", "gauge"),
    ("objectio_meta_raft_applied_index", "gauge"),
    ("objectio_block_volumes_total", "gauge"),
    ("objectio_block_volume_used_bytes", "gauge"),
    ("objectio_meta_shared_stripes", "gauge"),
    // OSD disks.
    ("objectio_osd_disk_seconds", "histogram"),
    // Gateway.
    ("objectio_gateway_copies_total", "counter"),
    ("objectio_gateway_inline_objects_total", "counter"),
];

/// Families nothing fed, which read as a healthy zero; removed.
const GONE: &[&str] = &[
    "objectio_gateway_active_connections",
    "objectio_gateway_connections_total",
    "objectio_cluster_read_iops",
];

/// `/metrics` once it reflects `serve_some_traffic`: OSD and meta metrics
/// arrive with the gateway's next poll (30 s), so wait for a poll taken
/// after the traffic, not merely any poll.
fn scrape_after_traffic(c: &Cluster) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let text = c.request("GET", "/metrics", &[]).text();
        let has = |family: &str, method: &str| {
            text.lines()
                .any(|l| l.starts_with(family) && l.contains(&format!("method=\"{method}\"")))
        };
        if has("objectio_osd_grpc_requests_total", "WriteShard")
            && has("objectio_meta_grpc_requests_total", "BlockCommitChunks")
        {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "OSD and meta metrics never reached the gateway"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The first sample starting `prefix`, as an integer.
fn value(text: &str, prefix: &str) -> u64 {
    text.lines()
        .find(|l| l.starts_with(prefix))
        .and_then(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("no integer sample starting {prefix}"))
}

#[test]
fn metrics_are_a_valid_exposition_and_cover_every_service() {
    let block_port = free_port();
    let (bp, np) = (block_port.to_string(), free_port().to_string());
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--block-port", &bp, "--nbd-port", &np]);
    serve_some_traffic(&c, block_port);
    let text = scrape_after_traffic(&c);

    let families = objectio_common::exposition::check(&text)
        .unwrap_or_else(|problems| panic!("/metrics is not a valid exposition:\n{problems}"));
    for (family, kind) in EXPECTED {
        let f = families
            .get(*family)
            .unwrap_or_else(|| panic!("{family} is missing"));
        assert_eq!(f.kind, *kind, "{family}");
        assert!(f.samples > 0, "{family} has no samples");
    }
    for dead in GONE {
        assert!(!families.contains_key(*dead), "{dead} is still exported");
    }

    // Requests are named as S3 names them.
    for op in ["CopyObject", "GetBucketConfig", "PutObject", "GetObject"] {
        assert!(
            text.contains(&format!("objectio_s3_requests_total{{operation=\"{op}\"")),
            "no {op} in objectio_s3_requests_total"
        );
    }
    // Every OSD method is counted, with its status code.
    assert!(
        text.lines()
            .any(|l| l.starts_with("objectio_osd_grpc_requests_total")
                && l.contains("method=\"WriteShard\"")
                && l.contains("code=\"OK\"")),
        "WriteShard calls are not counted"
    );
    // The traffic, as each side saw it.
    let v = |prefix: &str| value(&text, prefix);
    assert_eq!(
        v("objectio_block_io_bytes_total{protocol=\"grpc\",op=\"write\"}"),
        4096
    );
    assert!(v("objectio_block_chunks_flushed_total{result=\"stored\"}") >= 1);
    assert_eq!(v("objectio_block_volumes_total{"), 1);
    // One 4 MiB chunk written, as meta records it.
    assert_eq!(v("objectio_block_volume_used_bytes{"), 4 << 20);
    // aio's meta is a single-node Raft cluster: its own leader.
    assert_eq!(v("objectio_meta_raft_is_leader"), 1);
    assert_eq!(v("objectio_gateway_copies_total{mode=\"reference\"}"), 1);
    assert_eq!(v("objectio_gateway_inline_objects_total"), 1);
}
