//! A signed request's body is the body it signed: a hex
//! `x-amz-content-sha256` is checked against the body, and a streaming
//! upload's chunk signatures (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, and its
//! `-TRAILER` form) are checked chunk by chunk. Either way, a body that
//! differs from what was signed stores nothing.

use base64::Engine as _;
use objectio_e2e::{Cluster, SignedRequest};
use serde_json::json;
use sha2::{Digest, Sha256};

fn bucket(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/buckets", json!({ "name": name }))
        .expect_ok();
}

fn code(r: &objectio_e2e::Response) -> String {
    let xml = r.text();
    xml.split("<Code>")
        .nth(1)
        .and_then(|s| s.split("</Code>").next())
        .unwrap_or_default()
        .to_string()
}

fn tag(xml: &str, name: &str) -> String {
    let start = xml.find(&format!("<{name}>")).expect("open tag") + name.len() + 2;
    let end = xml[start..].find(&format!("</{name}>")).expect("close tag") + start;
    xml[start..end].to_string()
}

fn data(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i * 31 % 251).expect("below 251"))
        .collect()
}

fn sha_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// How a streaming body is framed and what is done to it after signing.
#[derive(Clone, Copy)]
struct Streaming {
    /// `-TRAILER`: an `x-amz-checksum-crc32` trailer, signed.
    trailer: bool,
    /// Flip this byte of the payload after its chunk is signed.
    tamper: Option<usize>,
    /// Sign the trailer over a checksum other than the one sent.
    tamper_trailer: bool,
}

const PLAIN: Streaming = Streaming {
    trailer: false,
    tamper: None,
    tamper_trailer: false,
};

/// The body an SDK sends for a signed streaming upload of `payload` in
/// 64 KiB chunks, its chunk signatures chained from `req`'s.
fn frame(req: &SignedRequest, payload: &[u8], how: Streaming) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev = req.signature.clone();
    let mut offset = 0;
    for chunk in payload.chunks(65_536) {
        prev = req.chunk_signature(&prev, chunk);
        let mut sent = chunk.to_vec();
        if let Some(at) = how.tamper
            && (offset..offset + chunk.len()).contains(&at)
        {
            sent[at - offset] ^= 0xff;
        }
        offset += chunk.len();
        out.extend_from_slice(format!("{:x};chunk-signature={prev}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(&sent);
        out.extend_from_slice(b"\r\n");
    }
    prev = req.chunk_signature(&prev, &[]);
    out.extend_from_slice(format!("0;chunk-signature={prev}\r\n").as_bytes());
    if how.trailer {
        let crc = base64::engine::general_purpose::STANDARD
            .encode(crc32fast::hash(payload).to_be_bytes());
        let line = format!("x-amz-checksum-crc32:{crc}");
        let signed_line = if how.tamper_trailer {
            "x-amz-checksum-crc32:AAAAAA==".to_string()
        } else {
            line.clone()
        };
        let sig = req.trailer_signature(&prev, &format!("{signed_line}\n"));
        out.extend_from_slice(format!("{line}\r\nx-amz-trailer-signature:{sig}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// A signed streaming upload of `payload` to `path`, as aws-cli, the Java
/// SDK and minio-go send one.
fn put_streaming(
    c: &Cluster,
    path: &str,
    payload: &[u8],
    how: Streaming,
) -> objectio_e2e::Response {
    let decoded = payload.len().to_string();
    let mut signed = vec![
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", decoded.as_str()),
    ];
    let hash = if how.trailer {
        signed.push(("x-amz-trailer", "x-amz-checksum-crc32"));
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
    } else {
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    };
    let req = c.sign("PUT", path, hash, &signed);
    let body = frame(&req, payload, how);
    req.send(body, &[])
}

#[test]
fn a_body_other_than_the_one_signed_is_refused() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "sha");

    // The signed body is taken.
    let signed = b"the body that was signed".to_vec();
    let req = c.sign("PUT", "/sha/good", &sha_hex(&signed), &[]);
    req.send(signed.clone(), &[]).expect(200);
    assert_eq!(c.request("GET", "/sha/good", &[]).bytes, signed);

    // The same signature over another body: refused, nothing stored. Small
    // (inline) and larger than one stripe, so both write paths are covered.
    for (key, len) in [("small", 100), ("large", 3 * 1024 * 1024 + 7)] {
        let original = data(len);
        let mut other = original.clone();
        other[len / 2] ^= 1;
        let path = format!("/sha/{key}");
        let req = c.sign("PUT", &path, &sha_hex(&original), &[]);
        let r = req.send(other, &[]);
        assert_eq!(
            (r.status, code(&r).as_str()),
            (400, "XAmzContentSHA256Mismatch"),
            "{key}: {}",
            r.text()
        );
        c.request("HEAD", &path, &[]).expect(404);
    }

    // A signed PUT replayed without its body does not store an empty object.
    let req = c.sign("PUT", "/sha/emptied", &sha_hex(b"content"), &[]);
    let r = req.send(Vec::new(), &[]);
    assert_eq!(code(&r), "XAmzContentSHA256Mismatch", "{}", r.text());
    c.request("HEAD", "/sha/emptied", &[]).expect(404);

    // An existing object is not overwritten by the replay either.
    let req = c.sign("PUT", "/sha/good", &sha_hex(b"replacement"), &[]);
    let r = req.send(b"something else".to_vec(), &[]);
    assert_eq!(code(&r), "XAmzContentSHA256Mismatch", "{}", r.text());
    assert_eq!(c.request("GET", "/sha/good", &[]).bytes, signed);
}

#[test]
fn other_signed_bodies_are_held_to_their_hash_too() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "parts");

    // UploadPart.
    let r = c.request("POST", "/parts/obj?uploads", &[]);
    r.expect_ok();
    let upload = tag(&r.text(), "UploadId");
    let part = format!("/parts/obj?partNumber=1&uploadId={upload}");
    let body = data(5 * 1024 * 1024);
    let mut other = body.clone();
    other[17] ^= 1;
    let r = c.sign("PUT", &part, &sha_hex(&body), &[]).send(other, &[]);
    assert_eq!(
        (r.status, code(&r).as_str()),
        (400, "XAmzContentSHA256Mismatch"),
        "{}",
        r.text()
    );
    let parts = c.request("GET", &format!("/parts/obj?uploadId={upload}"), &[]);
    parts.expect_ok();
    assert!(!parts.text().contains("<Part>"), "{}", parts.text());

    // A bucket policy: a replayed PutBucketPolicy can't install another.
    let policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::parts/*"
        }]
    })
    .to_string();
    let r = c
        .sign("PUT", "/parts?policy", &sha_hex(b"{}"), &[])
        .send(policy.into_bytes(), &[]);
    assert_eq!(code(&r), "XAmzContentSHA256Mismatch", "{}", r.text());
    let r = c.request("GET", "/parts?policy", &[]);
    assert_eq!(r.status, 404, "{}", r.text());
}

#[test]
fn a_signed_streaming_upload_is_checked_chunk_by_chunk() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "stream");
    let payload = data(200 * 1024 + 13);

    // What a correct client sends is stored as sent.
    put_streaming(&c, "/stream/good", &payload, PLAIN).expect(200);
    assert_eq!(c.request("GET", "/stream/good", &[]).bytes, payload);

    // One byte of the second chunk changed after it was signed.
    let tampered = Streaming {
        tamper: Some(70_000),
        ..PLAIN
    };
    let r = put_streaming(&c, "/stream/tampered", &payload, tampered);
    assert_eq!(
        (r.status, code(&r).as_str()),
        (403, "SignatureDoesNotMatch"),
        "{}",
        r.text()
    );
    c.request("HEAD", "/stream/tampered", &[]).expect(404);

    // Chunk signatures that chain from another request's signature.
    let decoded = payload.len().to_string();
    let signed = [
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", decoded.as_str()),
    ];
    let other = c.sign(
        "PUT",
        "/stream/other",
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        &signed,
    );
    let req = c.sign(
        "PUT",
        "/stream/spliced",
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        &signed,
    );
    let r = req.send(frame(&other, &payload, PLAIN), &[]);
    assert_eq!(r.status, 403, "{}", r.text());
    c.request("HEAD", "/stream/spliced", &[]).expect(404);

    // With a signed trailer: good, then the checksum changed after signing.
    let trailer = Streaming {
        trailer: true,
        ..PLAIN
    };
    put_streaming(&c, "/stream/trailer", &payload, trailer).expect(200);
    assert_eq!(c.request("GET", "/stream/trailer", &[]).bytes, payload);
    let r = put_streaming(
        &c,
        "/stream/trailer-bad",
        &payload,
        Streaming {
            tamper_trailer: true,
            ..trailer
        },
    );
    assert_eq!(code(&r), "SignatureDoesNotMatch", "{}", r.text());
    c.request("HEAD", "/stream/trailer-bad", &[]).expect(404);
    let r = put_streaming(
        &c,
        "/stream/trailer-chunk",
        &payload,
        Streaming {
            tamper: Some(5),
            ..trailer
        },
    );
    assert_eq!(code(&r), "SignatureDoesNotMatch", "{}", r.text());
    c.request("HEAD", "/stream/trailer-chunk", &[]).expect(404);
}

/// What boto3 and aws-cli send by default since their flexible-checksum
/// change: unsigned chunks, the checksum in a trailer. Taken, and the
/// trailer's checksum still holds the body to it.
#[test]
fn an_unsigned_streaming_upload_is_held_to_its_trailer() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "unsigned");
    let payload = data(150 * 1024);
    let send = |path: &str, body: &[u8], crc: u32, with_trailer: bool| {
        let decoded = payload.len().to_string();
        let req = c.sign(
            "PUT",
            path,
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            &[
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", decoded.as_str()),
                ("x-amz-trailer", "x-amz-checksum-crc32"),
            ],
        );
        let mut framed = Vec::new();
        for chunk in body.chunks(65_536) {
            framed.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            framed.extend_from_slice(chunk);
            framed.extend_from_slice(b"\r\n");
        }
        framed.extend_from_slice(b"0\r\n");
        if with_trailer {
            let crc = base64::engine::general_purpose::STANDARD.encode(crc.to_be_bytes());
            framed.extend_from_slice(format!("x-amz-checksum-crc32:{crc}\r\n").as_bytes());
        }
        framed.extend_from_slice(b"\r\n");
        req.send(framed, &[])
    };
    let crc = crc32fast::hash(&payload);
    send("/unsigned/good", &payload, crc, true).expect(200);
    assert_eq!(c.request("GET", "/unsigned/good", &[]).bytes, payload);

    let mut other = payload.clone();
    other[1000] ^= 1;
    let r = send("/unsigned/bad", &other, crc, true);
    assert_eq!(code(&r), "BadDigest", "{}", r.text());
    c.request("HEAD", "/unsigned/bad", &[]).expect(404);

    // The trailer announced and left off: its checksum can't go unchecked.
    let r = send("/unsigned/none", &other, crc, false);
    assert_eq!(
        (r.status, code(&r).as_str()),
        (400, "MalformedTrailerError"),
        "{}",
        r.text()
    );
    c.request("HEAD", "/unsigned/none", &[]).expect(404);
}

#[test]
fn a_streaming_upload_part_is_checked() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "smpu");
    let r = c.request("POST", "/smpu/obj?uploads", &[]);
    r.expect_ok();
    let upload = tag(&r.text(), "UploadId");
    let part = |n: u32| format!("/smpu/obj?partNumber={n}&uploadId={upload}");
    let first = data(5 * 1024 * 1024);
    let last = data(1000);

    let r = put_streaming(
        &c,
        &part(1),
        &first,
        Streaming {
            tamper: Some(4 * 1024 * 1024),
            ..PLAIN
        },
    );
    assert_eq!(code(&r), "SignatureDoesNotMatch", "{}", r.text());

    let e1 = put_streaming(&c, &part(1), &first, PLAIN);
    e1.expect(200);
    let e2 = put_streaming(
        &c,
        &part(2),
        &last,
        Streaming {
            trailer: true,
            ..PLAIN
        },
    );
    e2.expect(200);
    let etag = |r: &objectio_e2e::Response| r.header("etag").expect("etag");
    let complete = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>\
         </CompleteMultipartUpload>",
        etag(&e1),
        etag(&e2)
    );
    c.request(
        "POST",
        &format!("/smpu/obj?uploadId={upload}"),
        complete.as_bytes(),
    )
    .expect_ok();
    let got = c.request("GET", "/smpu/obj", &[]).bytes;
    assert_eq!(got.len(), first.len() + last.len());
    assert_eq!(&got[..first.len()], &first[..]);
    assert_eq!(&got[first.len()..], &last[..]);
}
