//! A pool's protection scheme is checked when the pool is made: one the
//! codecs can't keep (no parity, an LRC whose groups aren't one size, no
//! copies, a profile past a stripe's width) is refused by the admin API
//! and not made, and meta refuses one for its default pool at start. An
//! LRC pool takes objects of every length, odd ones too (reed-solomon-simd
//! codes even shard sizes only: an LRC PUT of an odd shard size failed),
//! PUT or multipart, and reads them back, a drive lost too; it
//! acknowledges a write with all but g − 1 shards on disk.

use std::fmt::Write as _;
use std::process::Command;

use objectio_e2e::Cluster;
use serde_json::{Value, json};

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

fn pool_names(c: &Cluster) -> String {
    let pools: Value = c.request("GET", "/_admin/pools", &[]).json();
    pools.to_string()
}

/// Every scheme the codecs can't keep is refused with what is wrong with
/// it, and no pool is made.
#[test]
fn a_scheme_the_codecs_cannot_keep_is_refused() {
    let c = Cluster::start_with_osds(3);
    let refused = [
        // No parity: one lost shard loses the object.
        (
            "mds-1-0",
            json!({"ec_type": 0, "ec_k": 1, "ec_m": 0}),
            "no parity",
        ),
        (
            "mds-4-0",
            json!({"ec_type": 0, "ec_k": 4, "ec_m": 0}),
            "no parity",
        ),
        // 2^32 + 4 data shards: not wrapped into 4 on the way.
        (
            "mds-wrap",
            json!({"ec_type": 0, "ec_k": 4_294_967_300_u64, "ec_m": 2}),
            "not an erasure code",
        ),
        (
            "lrc-uneven",
            json!({"ec_type": 1, "ec_k": 5, "ec_local_parity": 2, "ec_global_parity": 1}),
            "local groups",
        ),
        (
            "lrc-no-global",
            json!({"ec_type": 1, "ec_k": 4, "ec_local_parity": 2, "ec_global_parity": 0}),
            "at least 1",
        ),
        (
            "lrc-no-local",
            json!({"ec_type": 1, "ec_k": 4, "ec_local_parity": 0, "ec_global_parity": 1}),
            "at least 1",
        ),
        (
            "lrc-wide",
            json!({"ec_type": 1, "ec_k": 240, "ec_local_parity": 20, "ec_global_parity": 2}),
            "at most 255",
        ),
        (
            "rep-0",
            json!({"ec_type": 2, "replication_count": 0}),
            "copies",
        ),
        (
            "rep-wide",
            json!({"ec_type": 2, "replication_count": 300}),
            "copies",
        ),
        (
            "no-such-type",
            json!({"ec_type": 7, "ec_k": 4, "ec_m": 2}),
            "ec_type 7",
        ),
    ];
    for (name, mut scheme, why) in refused {
        scheme["name"] = json!(name);
        scheme["enabled"] = json!(true);
        let r = c.json("POST", "/_admin/pools", scheme);
        assert_eq!(r.status, 400, "{name}: {}", r.text());
        assert!(r.text().contains(why), "{name}: {}", r.text());
        assert!(!pool_names(&c).contains(name), "{name} was made");
    }

    // A pool can't be changed into one either.
    let r = c.json(
        "POST",
        "/_admin/pools",
        json!({"name": "rep1", "ec_type": 2, "replication_count": 1, "pg_count": 8,
            "enabled": true}),
    );
    assert!(r.status < 300, "one copy: {}", r.text());
    let r = c.json("PUT", "/_admin/pools/rep1", json!({"replication_count": 0}));
    assert_eq!(r.status, 400, "{}", r.text());
}

/// Meta refuses a default pool it would never make, at start: 1+0 keeps
/// no parity (one copy is `--replication 1`). aio refuses half a scheme.
#[test]
fn a_default_scheme_with_no_parity_is_refused_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(objectio_e2e::binary("objectio-meta"))
        .args([
            "--node-id",
            "1",
            "--listen",
            "127.0.0.1:0",
            "--metrics-port",
            "0",
        ])
        .args([
            "--admin-port",
            "0",
            "--ec-k",
            "1",
            "--ec-m",
            "0",
            "--data-dir",
        ])
        .arg(dir.path())
        .output()
        .expect("run objectio-meta");
    assert!(!out.status.success(), "meta started with 1+0");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("1+0 has no parity"), "{err}");
    assert!(err.contains("--replication 1"), "{err}");

    let out = Command::new(objectio_e2e::binary("objectio-aio"))
        .args(["--osds", "1", "--ec-k", "1", "--ec-m", "0", "--data"])
        .arg(dir.path())
        .output()
        .expect("run objectio-aio");
    assert!(!out.status.success(), "aio started with 1+0");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--ec-k 1 --ec-m 0"), "{err}");
}

/// Lengths across the inline limit, odd and even shard sizes, one shard
/// of 64 bytes and more, and a stripe and a bit.
const LENGTHS: [usize; 16] = [
    1, 2, 3, 255, 4_095, 4_097, 10_001, 16_385, 65_537, 300_001, 300_002, 1_000_003, 1_048_576,
    3_145_735, 4_194_311, 17_000_017,
];

/// An LRC 4+2+1 pool: objects of every length PUT and read back, a
/// multipart upload with an odd last part too, and a range; and all of
/// them again with a drive lost.
#[test]
fn an_lrc_pool_takes_objects_of_every_length() {
    let mut c = Cluster::start_with_osds(7);
    // No ec_m given (the API's default is 2): an LRC pool's is l + g.
    let r = c.json(
        "POST",
        "/_admin/pools",
        json!({"name": "lrc", "ec_type": 1, "ec_k": 4, "ec_local_parity": 2,
            "ec_global_parity": 1, "pg_count": 8, "enabled": true}),
    );
    assert!(r.status < 300, "{}", r.text());
    assert_eq!(r.json()["ec_m"], 3, "{}", r.text());
    c.request_with_headers("PUT", "/lrc", &[], &[("x-objectio-pool", "lrc")])
        .expect(200);

    let mut bodies: Vec<(String, Vec<u8>)> = LENGTHS
        .iter()
        .enumerate()
        .map(|(i, &len)| {
            let key = format!("o-{len}");
            let body = payload(len, u8::try_from(i).unwrap());
            let r = c.request("PUT", &format!("/lrc/{key}"), &body);
            assert_eq!(r.status, 200, "{key}: {}", r.text());
            (key, body)
        })
        .collect();

    // Multipart: a 5 MiB part and an odd one.
    let r = c.request("POST", "/lrc/mpu?uploads", &[]);
    assert!(r.status < 300, "initiate: {}", r.text());
    let text = r.text();
    let upload = text
        .split("<UploadId>")
        .nth(1)
        .and_then(|t| t.split("</UploadId>").next())
        .expect("an upload id")
        .to_string();
    let parts = [payload(5 * 1024 * 1024, 90), payload(777_777, 91)];
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, body) in parts.iter().enumerate() {
        let n = i + 1;
        let r = c.request(
            "PUT",
            &format!("/lrc/mpu?partNumber={n}&uploadId={upload}"),
            body,
        );
        assert_eq!(r.status, 200, "part {n}: {}", r.text());
        let etag = r.header("etag").expect("a part's etag");
        let _ = write!(
            xml,
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        );
    }
    xml.push_str("</CompleteMultipartUpload>");
    let r = c.request(
        "POST",
        &format!("/lrc/mpu?uploadId={upload}"),
        xml.as_bytes(),
    );
    assert_eq!(r.status, 200, "complete: {}", r.text());
    bodies.push(("mpu".to_string(), parts.concat()));

    let all_read = |c: &Cluster, when: &str| {
        for (key, body) in &bodies {
            let got = c.request("GET", &format!("/lrc/{key}"), &[]);
            assert_eq!(got.status, 200, "{key} {when}: {}", got.text());
            assert!(got.bytes == *body, "{key} {when}: other bytes");
        }
        let got = c.request_with_headers(
            "GET",
            "/lrc/o-300001",
            &[],
            &[("Range", "bytes=1001-200002")],
        );
        assert_eq!(got.status, 206, "range {when}: {}", got.text());
        let whole = &bodies.iter().find(|(k, _)| k == "o-300001").unwrap().1;
        assert!(got.bytes == whole[1001..=200_002], "range {when}");
    };
    all_read(&c, "as written");

    // The stripes written are LRC, the multipart's parts too.
    for (key, _) in bodies.iter().filter(|(k, _)| k == "mpu" || k == "o-65537") {
        let stripes = stripes_of(&c, "lrc", key);
        assert!(!stripes.is_empty(), "{key}: no stripes");
        for s in stripes {
            assert_eq!(
                s.ec_type,
                objectio_proto::metadata::ErasureType::ErasureLrc as i32,
                "{key}: stripe {} coded {:?}",
                s.stripe_id,
                s.ec_type
            );
            assert_eq!((s.ec_k, s.ec_local_parity, s.ec_global_parity), (4, 2, 1));
        }
    }

    // A drive lost: every object decodes from the six shards left.
    c.restart_with_lost_disk(0);
    all_read(&c, "with a drive lost");
}

/// `bucket/key`'s stripes, from the first OSD holding its metadata.
fn stripes_of(c: &Cluster, bucket: &str, key: &str) -> Vec<objectio_proto::metadata::StripeMeta> {
    use objectio_proto::storage::GetObjectMetaRequest;
    use objectio_proto::storage::storage_service_client::StorageServiceClient;
    let rt = tokio::runtime::Runtime::new().unwrap();
    for i in 0..7 {
        let address = c.osd_address(i);
        let found = rt.block_on(async {
            let mut client = StorageServiceClient::new(
                objectio_e2e::tls::channel(&address)
                    .await
                    .expect("connect OSD"),
            );
            client
                .get_object_meta(GetObjectMetaRequest {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    version_id: String::new(),
                    with_small_shard: false,
                })
                .await
                .expect("GetObjectMeta")
                .into_inner()
        });
        if found.found {
            return found.object.map(|o| o.stripes).unwrap_or_default();
        }
    }
    panic!("no OSD holds {bucket}/{key}");
}

/// An LRC stripe is acknowledged with all but g − 1 of its shards (9 of
/// LRC 6+2+2), a PUT and a part alike, and 503 short of that. Only a loss
/// of g is sure to decode: acknowledged at k + 1 (7), as it was, a stripe
/// could be missing shards no decode rebuilds.
#[test]
fn an_lrc_write_is_acknowledged_with_all_but_g_minus_one_shards() {
    use objectio_e2e::ha::HaCluster;
    use std::time::Duration;

    // Ten OSDs, all ten the pool's one placement group: none to stand in
    // for one stopped.
    let mut ha = HaCluster::start(1, 10, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    let r = c.json(
        "POST",
        "/_admin/pools",
        json!({"name": "lrc622", "ec_type": 1, "ec_k": 6, "ec_local_parity": 2,
            "ec_global_parity": 2, "pg_count": 1, "failure_domain": "osd", "enabled": true}),
    );
    assert!(r.status < 300, "pool: {}", r.text());
    c.request_with_headers("PUT", "/lrcq", &[], &[("x-objectio-pool", "lrc622")])
        .expect(200);
    let body = payload(5 * 1024 * 1024, 7);
    let r = c.request("POST", "/lrcq/parts?uploads", &[]);
    assert!(r.status < 300, "initiate: {}", r.text());
    let text = r.text();
    let upload = text
        .split("<UploadId>")
        .nth(1)
        .and_then(|t| t.split("</UploadId>").next())
        .expect("an upload id")
        .to_string();
    let part = |c: &Cluster, n: u32| {
        c.request(
            "PUT",
            &format!("/lrcq/parts?partNumber={n}&uploadId={upload}"),
            &body,
        )
    };

    // One shard short: nine, the quorum.
    ha.stop_osd(0);
    let c = &ha.clients[0];
    c.request("PUT", "/lrcq/one-down", &body).expect(200);
    part(c, 1).expect(200);

    // Two short: eight, more than k + 1, less than the quorum.
    ha.stop_osd(1);
    let c = &ha.clients[0];
    let put = c.request("PUT", "/lrcq/two-down", &body);
    assert_eq!(put.status, 503, "PUT with eight shards: {}", put.text());
    let got = part(c, 2);
    assert_eq!(
        got.status,
        503,
        "UploadPart with eight shards: {}",
        got.text()
    );
}
