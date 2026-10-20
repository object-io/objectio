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

/// A parity shard stored wrong under a checksum its object records as well
/// (what a stripe coded by another codec is to this gateway: two
/// Reed-Solomon codes agree on data shards, not on parity) passes every
/// read check. A read that rebuilds a data shard through it gets other
/// bytes, and served them with a 200 (#70). It decodes around it when it
/// can, and fails when it can't.
#[test]
fn parity_from_another_codec_is_never_decoded_into_a_read() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    c.json("POST", "/_admin/buckets", json!({"name": "codec"}))
        .expect_ok();
    let data = body(50_051);
    c.request("PUT", "/codec/one", &data).expect(200);
    c.request("PUT", "/codec/both", &data).expect(200);

    let rewrite = |key: &str, position: u32, record: bool| {
        c.json(
            "POST",
            "/_admin/test/rewrite-shard",
            json!({"bucket": "codec", "key": key, "position": position, "record": record}),
        )
        .expect_ok();
    };

    // Parity 4 from "another codec", and data shard 1 unreadable: the read
    // decodes through parity 4 first, then around it through parity 5.
    rewrite("one", 4, true);
    let got = c.request("GET", "/codec/one", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert!(got.bytes == data, "healthy read served wrong bytes");
    rewrite("one", 1, false);
    let got = c.request("GET", "/codec/one", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert!(
        got.bytes == data,
        "served data rebuilt through a wrong parity"
    );

    // All of the parity from the other codec: nothing rebuilds data shard
    // 1 as it was written. An error, not wrong bytes.
    rewrite("both", 4, true);
    rewrite("both", 5, true);
    rewrite("both", 1, false);
    let got = c.request("GET", "/codec/both", &[]);
    assert!(
        got.status >= 500,
        "status {} for a stripe that can't be rebuilt",
        got.status
    );
    assert!(got.bytes != data);
    let range = c.request_with_headers("GET", "/codec/both", &[], &[("range", "bytes=0-99")]);
    assert!(
        range.status >= 500 || (range.status == 206 && range.bytes == data[..100]),
        "range read: status {}",
        range.status
    );
}
