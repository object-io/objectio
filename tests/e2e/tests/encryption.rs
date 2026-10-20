//! SSE-C: an object stored under a customer key is served only to a request
//! carrying that key. A wrong key used to decrypt to garbage served with
//! 200; now 400, as S3 answers, and HEAD answered without any key.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use md5::{Digest, Md5};
use objectio_e2e::Cluster;
use serde_json::json;

fn key_headers(key: &[u8; 32]) -> [(&'static str, String); 3] {
    [
        (
            "x-amz-server-side-encryption-customer-algorithm",
            "AES256".to_string(),
        ),
        ("x-amz-server-side-encryption-customer-key", B64.encode(key)),
        (
            "x-amz-server-side-encryption-customer-key-md5",
            B64.encode(Md5::digest(key)),
        ),
    ]
}

fn with<'a>(headers: &'a [(&'static str, String); 3]) -> Vec<(&'static str, &'a str)> {
    headers.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

#[test]
fn an_sse_c_object_is_served_only_with_its_own_key() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "enc"}))
        .expect_ok();
    let (right, wrong) = (key_headers(&[7; 32]), key_headers(&[9; 32]));
    let body: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    c.request_with_headers("PUT", "/enc/k", &body, &with(&right))
        .expect(200);

    let got = c.request_with_headers("GET", "/enc/k", &[], &with(&right));
    assert_eq!(got.status, 200);
    assert!(got.bytes == body, "the right key read back other bytes");

    for method in ["GET", "HEAD"] {
        let r = c.request_with_headers(method, "/enc/k", &[], &with(&wrong));
        assert_eq!(r.status, 400, "{method} with another key: {}", r.text());
        assert!(r.bytes.is_empty() || !r.bytes.starts_with(&body[..16]));
        let r = c.request(method, "/enc/k", &[]);
        assert_eq!(r.status, 400, "{method} without a key");
    }
    assert_eq!(
        c.request_with_headers("HEAD", "/enc/k", &[], &with(&right))
            .status,
        200
    );
}

#[test]
fn a_multipart_sse_c_object_is_served_only_with_its_own_key() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "enc"}))
        .expect_ok();
    let (right, wrong) = (key_headers(&[3; 32]), key_headers(&[4; 32]));
    let r = c.request_with_headers("POST", "/enc/mp?uploads", &[], &with(&right));
    r.expect(200);
    let text = r.text();
    let upload = text
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .unwrap()
        .to_string();
    let part = vec![5u8; 100_000];
    let etag = c
        .request_with_headers(
            "PUT",
            &format!("/enc/mp?partNumber=1&uploadId={upload}"),
            &part,
            &with(&right),
        )
        .header("etag")
        .unwrap();
    c.request_with_headers(
        "POST",
        &format!("/enc/mp?uploadId={upload}"),
        format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
        )
        .as_bytes(),
        &with(&right),
    )
    .expect(200);

    let got = c.request_with_headers("GET", "/enc/mp", &[], &with(&right));
    assert_eq!(got.status, 200);
    assert!(got.bytes == part);
    assert_eq!(
        c.request_with_headers("GET", "/enc/mp", &[], &with(&wrong))
            .status,
        400
    );
}

/// A copy asked to be SSE-C is encrypted under that key, whatever the
/// source: it used to be made by reference to the source's stripes, so it
/// was stored in the clear and served to anyone, key or not.
#[test]
fn a_copy_to_sse_c_is_encrypted() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "enc"}))
        .expect_ok();
    let body = vec![6u8; 50_000];
    c.request("PUT", "/enc/plain", &body).expect(200);
    let key = key_headers(&[8; 32]);
    let mut headers = with(&key);
    headers.push(("x-amz-copy-source", "/enc/plain"));
    c.request_with_headers("PUT", "/enc/secret", &[], &headers)
        .expect(200);

    assert_eq!(
        c.request("GET", "/enc/secret", &[]).status,
        400,
        "an SSE-C copy was served without its key"
    );
    let got = c.request_with_headers("GET", "/enc/secret", &[], &with(&key));
    assert_eq!(got.status, 200);
    assert!(got.bytes == body);
}

/// A single-PUT object of several stripes is encrypted as one stream,
/// stripe after stripe: each stripe has to be decrypted at its own place in
/// it. A whole-object GET used to decrypt every stripe from the start of
/// the stream, serving all but the first as garbage with 200.
#[test]
fn an_encrypted_object_of_several_stripes_reads_back_whole() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "enc"}))
        .expect_ok();
    let key = key_headers(&[5; 32]);
    // Three stripes of a 4+2 scheme (16 MiB each, less a little).
    let body: Vec<u8> = (0..40u32 << 20)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    c.request_with_headers("PUT", "/enc/big", &body, &with(&key))
        .expect(200);

    let got = c.request_with_headers("GET", "/enc/big", &[], &with(&key));
    assert_eq!(got.status, 200);
    assert_eq!(got.bytes.len(), body.len());
    let first_wrong = got.bytes.iter().zip(&body).position(|(a, b)| a != b);
    assert_eq!(first_wrong, None, "the whole object read back other bytes");

    // A range across the first stripe boundary, and the last bytes.
    for (from, to) in [
        (16_000_000_usize, 17_000_000_usize),
        (body.len() - 100, body.len() - 1),
    ] {
        let range = format!("bytes={from}-{to}");
        let mut headers = with(&key);
        headers.push(("range", &range));
        let got = c.request_with_headers("GET", "/enc/big", &[], &headers);
        assert_eq!(got.status, 206, "{range}");
        assert!(
            got.bytes == body[from..=to],
            "{range} read back other bytes"
        );
    }
}
