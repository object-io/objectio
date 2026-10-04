//! A shard stored wrong, with an OSD-side checksum of its own wrong bytes
//! (as a rebuild from a bad source left it, which the B2 soak served with
//! HTTP 200), is caught against the checksum its object records (B23): a
//! GET decodes around it, and never returns the wrong bytes.

use objectio_e2e::Cluster;
use serde_json::json;

fn body(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 31 % 251).unwrap())
        .collect()
}

#[test]
fn a_shard_stored_wrong_is_never_served() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    c.json("POST", "/_admin/buckets", json!({"name": "sums"}))
        .expect_ok();
    let data = body(50_051);
    c.request("PUT", "/sums/k", &data).expect(200);

    let rewrite = |position: u32| {
        c.json(
            "POST",
            "/_admin/test/rewrite-shard",
            json!({"bucket": "sums", "key": "k", "position": position}),
        )
        .expect_ok();
    };

    // Two data shards wrong: 4+2 decodes around them.
    rewrite(1);
    rewrite(3);
    let got = c.request("GET", "/sums/k", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert!(got.bytes == data, "served a shard stored wrong");

    // A third: fewer than k shards are right. An error, not wrong bytes.
    rewrite(0);
    let got = c.request("GET", "/sums/k", &[]);
    assert!(got.status >= 500, "status {}", got.status);
    assert!(got.bytes != data[..got.bytes.len().min(data.len())] || got.bytes.is_empty());
}
