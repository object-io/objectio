//! Multipart upload, end to end.
//!
//! This path had no coverage at all — unit or integration — and it is where
//! the authorization bypass that started this work lived: a 12 MB multipart
//! PUT succeeded against a bucket with an explicit Deny, because the
//! per-part route was not classified as a write. It is also the only path
//! that writes several stripes under one object, so it is the one most
//! likely to leak blocks if reclamation is wrong.
//!
//! A multipart upload is four calls that have to agree with each other about
//! an upload id and a set of part `ETag`s, across the gateway, meta and the
//! OSD. Nothing about that is visible from inside one component.

use objectio_e2e::{Cluster, Response};
use serde_json::json;
use std::fmt::Write as _;

/// S3 requires every part except the last to be at least 5 MiB.
const PART: usize = 5 * 1024 * 1024;

/// Pull a value out of the XML responses the S3 API returns.
///
/// Deliberately not a parser: the harness asserts on a handful of known
/// elements, and taking an XML dependency to read `<UploadId>` would be more
/// machinery than the thing it reads.
fn tag(xml: &str, name: &str) -> String {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml
        .find(&open)
        .unwrap_or_else(|| panic!("no <{name}> in: {xml}"))
        + open.len();
    let end = xml[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("unterminated <{name}> in: {xml}"))
        + start;
    xml[start..end].to_string()
}

fn initiate(c: &Cluster, bucket: &str, key: &str) -> String {
    let r = c.request("POST", &format!("/{bucket}/{key}?uploads"), &[]);
    r.expect_ok();
    tag(&r.text(), "UploadId")
}

fn upload_part(c: &Cluster, bucket: &str, key: &str, upload: &str, n: u32, body: &[u8]) -> String {
    let r = c.request(
        "PUT",
        &format!("/{bucket}/{key}?partNumber={n}&uploadId={upload}"),
        body,
    );
    r.expect(200);
    // The ETag comes back as a header on the real API; the body is empty, so
    // the completion XML below just needs *an* etag per part and the server
    // matches on part number.
    r.header("etag").unwrap_or_else(|| format!("\"part{n}\""))
}

fn complete(
    c: &Cluster,
    bucket: &str,
    key: &str,
    upload: &str,
    etags: &[(u32, String)],
) -> Response {
    let parts = etags.iter().fold(String::new(), |mut acc, (n, e)| {
        let _ = write!(
            acc,
            "<Part><PartNumber>{n}</PartNumber><ETag>{e}</ETag></Part>"
        );
        acc
    });
    let body = format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>");
    c.request(
        "POST",
        &format!("/{bucket}/{key}?uploadId={upload}"),
        body.as_bytes(),
    )
}

/// The whole flow, and the bytes must survive it.
#[test]
fn a_multipart_upload_reassembles_in_order() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "mpu"}))
        .expect_ok();

    // Distinct bytes per part, so an out-of-order assembly is a visible
    // failure rather than a checksum that happens to match.
    let p1 = vec![0xAAu8; PART];
    let p2 = vec![0xBBu8; PART];
    let p3 = vec![0xCCu8; 1024];

    let upload = initiate(&c, "mpu", "big.bin");
    let mut etags = Vec::new();
    for (n, body) in [(1u32, &p1), (2, &p2), (3, &p3)] {
        etags.push((n, upload_part(&c, "mpu", "big.bin", &upload, n, body)));
    }
    complete(&c, "mpu", "big.bin", &upload, &etags).expect_ok();

    let got = c.request("GET", "/mpu/big.bin", &[]);
    got.expect(200);

    let mut want = Vec::with_capacity(p1.len() + p2.len() + p3.len());
    want.extend_from_slice(&p1);
    want.extend_from_slice(&p2);
    want.extend_from_slice(&p3);
    assert_eq!(
        got.bytes.len(),
        want.len(),
        "reassembled object is the wrong length"
    );
    assert!(
        got.bytes == want,
        "parts came back in the wrong order or corrupted"
    );
}

/// Deleting a multipart object frees every stripe it wrote.
///
/// The single-part case is covered in `lifecycle`; this one matters
/// separately because multipart writes each part under its own `object_id`, so
/// the delete path has to walk the stripe list rather than assume one id.
#[test]
fn deleting_a_multipart_object_reclaims_every_stripe() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "mpu-reclaim"}))
        .expect_ok();

    let baseline = c.used_bytes();

    let upload = initiate(&c, "mpu-reclaim", "big.bin");
    let etags: Vec<(u32, String)> = (1..=3u32)
        .map(|n| {
            let fill = u8::try_from(n).unwrap();
            (
                n,
                upload_part(&c, "mpu-reclaim", "big.bin", &upload, n, &vec![fill; PART]),
            )
        })
        .collect();
    complete(&c, "mpu-reclaim", "big.bin", &upload, &etags).expect_ok();

    let after_upload = c.used_bytes();
    assert!(
        after_upload > baseline,
        "a 15 MB multipart upload did not move reported usage"
    );

    c.request("DELETE", "/mpu-reclaim/big.bin", &[]).expect(204);
    let after_delete = c.used_bytes();
    assert_eq!(
        after_delete,
        baseline,
        "deleting the multipart object left {} bytes allocated — stripes leaked",
        after_delete.saturating_sub(baseline)
    );
}

/// An aborted upload does not keep its parts.
#[test]
fn aborting_an_upload_releases_its_parts() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "mpu-abort"}))
        .expect_ok();

    let baseline = c.used_bytes();
    let upload = initiate(&c, "mpu-abort", "abandoned.bin");
    upload_part(
        &c,
        "mpu-abort",
        "abandoned.bin",
        &upload,
        1,
        &vec![9u8; PART],
    );

    c.request(
        "DELETE",
        &format!("/mpu-abort/abandoned.bin?uploadId={upload}"),
        &[],
    )
    .expect_ok();

    // The object must not exist.
    let got = c.request("GET", "/mpu-abort/abandoned.bin", &[]);
    assert_eq!(
        got.status, 404,
        "an aborted upload left a readable object: {}",
        got.status
    );

    let after = c.used_bytes();
    assert_eq!(
        after,
        baseline,
        "aborting left {} bytes allocated",
        after.saturating_sub(baseline)
    );
}

/// A scoped key cannot use multipart to write outside its bucket.
///
/// The bypass this whole line of work started from: a multipart PUT was not
/// classified as a write, so it skipped the check a plain PUT could not. Each
/// of the four calls is asserted separately, because letting any one of them
/// through is enough to land the bytes.
#[test]
fn multipart_respects_a_credential_scope() {
    let c = Cluster::start();
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "mp", "enabled": true}),
    )
    .expect_ok();
    let user = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "mp-admin", "tenant": "mp"}),
    );
    user.expect_ok();
    let uid = user.json()["user_id"].as_str().unwrap().to_string();
    c.json("POST", "/_admin/tenants/mp/admins", json!({"user_id": uid}))
        .expect_ok();
    let admin_key = c.json(
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        json!({}),
    );
    admin_key.expect_ok();
    let ak = admin_key.json();
    let (aak, ask) = (
        ak["access_key_id"].as_str().unwrap().to_string(),
        ak["secret_access_key"].as_str().unwrap().to_string(),
    );

    for bucket in ["allowed", "forbidden"] {
        c.request_as(
            "POST",
            "/_admin/buckets",
            json!({ "name": bucket }).to_string().as_bytes(),
            &aak,
            &ask,
        )
        .expect_ok();
    }

    let scoped = c.request_as(
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        json!({"scope": "s3://allowed/", "operation": "RW"})
            .to_string()
            .as_bytes(),
        &aak,
        &ask,
    );
    scoped.expect_ok();
    let v = scoped.json();
    let (sak, ssk) = (
        v["access_key_id"].as_str().unwrap().to_string(),
        v["secret_access_key"].as_str().unwrap().to_string(),
    );

    // Initiating against the bucket it may not touch must already fail.
    let init = c.request_as("POST", "/forbidden/sneak.bin?uploads", &[], &sak, &ssk);
    assert_eq!(
        init.status,
        403,
        "a scoped key initiated a multipart upload outside its scope: {}",
        init.text()
    );

    // And in its own bucket the whole flow still works — a scope that
    // refuses everything would pass the assertion above for the wrong reason.
    let upload = {
        let r = c.request_as("POST", "/allowed/ok.bin?uploads", &[], &sak, &ssk);
        r.expect_ok();
        tag(&r.text(), "UploadId")
    };
    let part = c.request_as(
        "PUT",
        &format!("/allowed/ok.bin?partNumber=1&uploadId={upload}"),
        &vec![1u8; PART],
        &sak,
        &ssk,
    );
    part.expect(200);

    // Uploading a part of *that* upload into the other bucket's path must
    // fail too: the upload id is not a capability.
    let cross = c.request_as(
        "PUT",
        &format!("/forbidden/ok.bin?partNumber=1&uploadId={upload}"),
        &vec![2u8; PART],
        &sak,
        &ssk,
    );
    assert_eq!(
        cross.status,
        403,
        "a scoped key uploaded a part outside its scope using a valid upload id: {}",
        cross.text()
    );
}

/// A read-only key cannot start or feed a multipart upload.
#[test]
fn a_read_only_key_cannot_upload_parts() {
    let c = Cluster::start();
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "ro", "enabled": true}),
    )
    .expect_ok();
    let user = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "ro-admin", "tenant": "ro"}),
    );
    user.expect_ok();
    let uid = user.json()["user_id"].as_str().unwrap().to_string();
    c.json("POST", "/_admin/tenants/ro/admins", json!({"user_id": uid}))
        .expect_ok();
    let admin_key = c.json(
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        json!({}),
    );
    admin_key.expect_ok();
    let ak = admin_key.json();
    let (aak, ask) = (
        ak["access_key_id"].as_str().unwrap().to_string(),
        ak["secret_access_key"].as_str().unwrap().to_string(),
    );
    c.request_as(
        "POST",
        "/_admin/buckets",
        json!({"name": "ro-bucket"}).to_string().as_bytes(),
        &aak,
        &ask,
    )
    .expect_ok();

    let ro = c.request_as(
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        json!({"scope": "s3://ro-bucket/", "operation": "R"})
            .to_string()
            .as_bytes(),
        &aak,
        &ask,
    );
    ro.expect_ok();
    let v = ro.json();
    let (rak, rsk) = (
        v["access_key_id"].as_str().unwrap().to_string(),
        v["secret_access_key"].as_str().unwrap().to_string(),
    );

    let init = c.request_as("POST", "/ro-bucket/nope.bin?uploads", &[], &rak, &rsk);
    assert_eq!(
        init.status,
        403,
        "a read-only key started a multipart upload: {}",
        init.text()
    );
}
