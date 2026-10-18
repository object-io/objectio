//! Upload integrity checksums: `Content-MD5` and `x-amz-checksum-*`.
//!
//! The gateway used to ignore both, so a body corrupted on the way in was
//! stored and served as if it were good. A mismatch has to be refused with
//! S3's error and store nothing — a later GET must not find the object.
//!
//! The expected values are hardcoded: base64 of the digest of `payload()`,
//! computed once with Python's hashlib/zlib and a reference CRC32C. "hello
//! world" values stand in as well-formed but wrong checksums.

use objectio_e2e::{Cluster, Response};
use serde_json::json;

/// Larger than the inline limit, so the object goes through erasure coding.
fn payload() -> Vec<u8> {
    (0..100_000)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect()
}

const PAYLOAD_MD5: &str = "KMtZXBWOm3TjSuno2nEP/w==";
const PAYLOAD_MD5_HEX: &str = "28cb595c158e9b74e34ae9e8da710fff";
const PAYLOAD_CRC32: &str = "s1O4+g==";
const PAYLOAD_CRC32C: &str = "ckf2aw==";
const PAYLOAD_SHA256: &str = "zS32lOQkvHlozDf0d1EBnlygzRvfLkeepTfDocMu4ao=";

const WRONG_MD5: &str = "XrY7u+Ae7tCTyyK7j1rNww==";
const WRONG_CRC32C: &str = "yZRlqg==";
const WRONG_SHA256: &str = "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";

fn cluster(bucket: &str) -> Cluster {
    let c = Cluster::start_with_ec(3, 2, 1);
    c.json("POST", "/_admin/buckets", json!({"name": bucket}))
        .expect_ok();
    c
}

#[track_caller]
fn expect_error(r: &Response, code: &str) {
    r.expect(400);
    assert!(
        r.text().contains(&format!("<Code>{code}</Code>")),
        "expected {code}: {}",
        r.text()
    );
}

/// The object must not exist: a refused PUT stored nothing.
#[track_caller]
fn expect_absent(c: &Cluster, path: &str) {
    c.request("GET", path, &[]).expect(404);
}

#[test]
fn content_md5_is_checked() {
    let c = cluster("md5");
    let body = payload();

    let ok = c.request_with_headers("PUT", "/md5/good", &body, &[("Content-MD5", PAYLOAD_MD5)]);
    ok.expect(200);
    assert_eq!(
        ok.header("etag").as_deref(),
        Some(format!("\"{PAYLOAD_MD5_HEX}\"").as_str()),
        "ETag is the MD5 Content-MD5 was checked against"
    );
    assert_eq!(c.request("GET", "/md5/good", &[]).bytes, body);

    let bad = c.request_with_headers("PUT", "/md5/bad", &body, &[("Content-MD5", WRONG_MD5)]);
    expect_error(&bad, "BadDigest");
    expect_absent(&c, "/md5/bad");

    let malformed =
        c.request_with_headers("PUT", "/md5/bad", &body, &[("Content-MD5", "not-an-md5")]);
    expect_error(&malformed, "InvalidDigest");
    expect_absent(&c, "/md5/bad");

    // A mismatch does not replace an object that is already there.
    let over = c.request_with_headers(
        "PUT",
        "/md5/good",
        b"other",
        &[("Content-MD5", PAYLOAD_MD5)],
    );
    expect_error(&over, "BadDigest");
    assert_eq!(c.request("GET", "/md5/good", &[]).bytes, body);
}

#[test]
fn crc32c_is_checked_stored_and_returned() {
    let c = cluster("crc");
    let body = payload();

    let ok = c.request_with_headers(
        "PUT",
        "/crc/good",
        &body,
        &[
            ("x-amz-sdk-checksum-algorithm", "CRC32C"),
            ("x-amz-checksum-crc32c", PAYLOAD_CRC32C),
        ],
    );
    ok.expect(200);
    assert_eq!(
        ok.header("x-amz-checksum-crc32c").as_deref(),
        Some(PAYLOAD_CRC32C)
    );

    // Returned only when asked for.
    let plain = c.request("GET", "/crc/good", &[]);
    plain.expect(200);
    assert_eq!(plain.header("x-amz-checksum-crc32c"), None);

    let mode = [("x-amz-checksum-mode", "ENABLED")];
    let got = c.request_with_headers("GET", "/crc/good", &[], &mode);
    got.expect(200);
    assert_eq!(got.bytes, body);
    assert_eq!(
        got.header("x-amz-checksum-crc32c").as_deref(),
        Some(PAYLOAD_CRC32C)
    );
    let head = c.request_with_headers("HEAD", "/crc/good", &[], &mode);
    head.expect(200);
    assert_eq!(
        head.header("x-amz-checksum-crc32c").as_deref(),
        Some(PAYLOAD_CRC32C)
    );

    let bad = c.request_with_headers(
        "PUT",
        "/crc/bad",
        &body,
        &[("x-amz-checksum-crc32c", WRONG_CRC32C)],
    );
    expect_error(&bad, "BadDigest");
    assert!(
        bad.text()
            .contains("The CRC32C you specified did not match")
    );
    expect_absent(&c, "/crc/bad");

    let malformed = c.request_with_headers(
        "PUT",
        "/crc/bad",
        &body,
        &[("x-amz-checksum-crc32c", "%%%")],
    );
    expect_error(&malformed, "InvalidRequest");
    expect_absent(&c, "/crc/bad");
}

#[test]
fn sha256_is_checked_on_small_and_large_objects() {
    let c = cluster("sha");

    // Large: erasure-coded.
    let body = payload();
    c.request_with_headers(
        "PUT",
        "/sha/large",
        &body,
        &[("x-amz-checksum-sha256", PAYLOAD_SHA256)],
    )
    .expect(200);
    let bad = c.request_with_headers(
        "PUT",
        "/sha/large-bad",
        &body,
        &[("x-amz-checksum-sha256", WRONG_SHA256)],
    );
    expect_error(&bad, "BadDigest");
    expect_absent(&c, "/sha/large-bad");

    // Small: stored inline in its metadata record.
    let small = c.request_with_headers(
        "PUT",
        "/sha/small",
        b"hello world",
        &[("x-amz-checksum-sha256", WRONG_SHA256)],
    );
    small.expect(200);
    let got = c.request_with_headers(
        "GET",
        "/sha/small",
        &[],
        &[("x-amz-checksum-mode", "ENABLED")],
    );
    assert_eq!(
        got.header("x-amz-checksum-sha256").as_deref(),
        Some(WRONG_SHA256)
    );
    let bad = c.request_with_headers(
        "PUT",
        "/sha/small-bad",
        b"hello worle",
        &[("x-amz-checksum-sha256", WRONG_SHA256)],
    );
    expect_error(&bad, "BadDigest");
    expect_absent(&c, "/sha/small-bad");
}

/// What a modern SDK sends: an `aws-chunked` body whose checksum comes after
/// the data, as a trailer.
fn chunked_with_trailer(data: &[u8], checksum: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(65_536) {
        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("0\r\nx-amz-checksum-crc32c:{checksum}\r\n\r\n").as_bytes());
    out
}

#[test]
fn a_trailing_checksum_is_checked() {
    let c = cluster("trailer");
    let body = payload();
    let len = body.len().to_string();
    let headers = [
        ("Content-Encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", len.as_str()),
        ("x-amz-trailer", "x-amz-checksum-crc32c"),
        ("x-amz-sdk-checksum-algorithm", "CRC32C"),
    ];

    let ok = c.request_with_headers(
        "PUT",
        "/trailer/good",
        &chunked_with_trailer(&body, PAYLOAD_CRC32C),
        &headers,
    );
    ok.expect(200);
    assert_eq!(c.request("GET", "/trailer/good", &[]).bytes, body);

    let bad = c.request_with_headers(
        "PUT",
        "/trailer/bad",
        &chunked_with_trailer(&body, WRONG_CRC32C),
        &headers,
    );
    expect_error(&bad, "BadDigest");
    expect_absent(&c, "/trailer/bad");
}

fn tag(xml: &str, name: &str) -> String {
    let start = xml.find(&format!("<{name}>")).expect("open tag") + name.len() + 2;
    let end = xml[start..].find(&format!("</{name}>")).expect("close tag") + start;
    xml[start..end].to_string()
}

#[test]
fn upload_part_is_checked() {
    let c = cluster("mpu");
    let body = payload();
    let r = c.request("POST", "/mpu/obj?uploads", &[]);
    r.expect_ok();
    let upload = tag(&r.text(), "UploadId");
    let part = format!("/mpu/obj?partNumber=1&uploadId={upload}");

    expect_error(
        &c.request_with_headers("PUT", &part, &body, &[("Content-MD5", WRONG_MD5)]),
        "BadDigest",
    );
    expect_error(
        &c.request_with_headers("PUT", &part, &body, &[("x-amz-checksum-crc32", "AAAAAA==")]),
        "BadDigest",
    );
    // Nothing was registered for the refused part.
    let parts = c.request("GET", &format!("/mpu/obj?uploadId={upload}"), &[]);
    parts.expect(200);
    assert!(
        !parts.text().contains("<PartNumber>1</PartNumber>"),
        "{}",
        parts.text()
    );

    let ok = c.request_with_headers(
        "PUT",
        &part,
        &body,
        &[
            ("Content-MD5", PAYLOAD_MD5),
            ("x-amz-checksum-crc32", PAYLOAD_CRC32),
        ],
    );
    ok.expect(200);
    assert_eq!(
        ok.header("etag").as_deref(),
        Some(format!("\"{PAYLOAD_MD5_HEX}\"").as_str())
    );
    assert_eq!(
        ok.header("x-amz-checksum-crc32").as_deref(),
        Some(PAYLOAD_CRC32)
    );

    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>\
         <ETag>\"{PAYLOAD_MD5_HEX}\"</ETag></Part></CompleteMultipartUpload>"
    );
    c.request(
        "POST",
        &format!("/mpu/obj?uploadId={upload}"),
        complete.as_bytes(),
    )
    .expect(200);
    assert_eq!(c.request("GET", "/mpu/obj", &[]).bytes, body);
}
