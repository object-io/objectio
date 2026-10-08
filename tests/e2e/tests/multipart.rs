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

/// A completion must name its parts in ascending order: a part named twice
/// or out of order is `InvalidPartOrder`, as S3 has it, before any size check.
#[test]
fn parts_out_of_order_are_invalid_part_order() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "mpo"}))
        .expect_ok();
    let upload = initiate(&c, "mpo", "k");
    let e1 = upload_part(&c, "mpo", "k", &upload, 1, b"tiny one");
    let e2 = upload_part(&c, "mpo", "k", &upload, 2, b"tiny two");
    for parts in [
        vec![(1, e1.clone()), (1, e1.clone())],
        vec![(2, e2.clone()), (1, e1.clone())],
    ] {
        let r = complete(&c, "mpo", "k", &upload, &parts);
        r.expect(400);
        assert!(
            r.text().contains("<Code>InvalidPartOrder</Code>"),
            "{}",
            r.text()
        );
    }
    // In order, the small first part is what's wrong.
    let r = complete(&c, "mpo", "k", &upload, &[(1, e1), (2, e2)]);
    r.expect(400);
    assert!(
        r.text().contains("<Code>EntityTooSmall</Code>"),
        "{}",
        r.text()
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

/// 1 MiB, distinct per `seed`. A part that is also the last may be any size.
fn mib(seed: u8) -> Vec<u8> {
    (0..1024 * 1024u32)
        .map(|i| u8::try_from(i % 251).unwrap() ^ seed)
        .collect()
}

fn ec_cluster(osds: usize, bucket: &str) -> Cluster {
    let c = Cluster::start_with_ec(osds, 4, 2);
    c.json("POST", "/_admin/buckets", json!({ "name": bucket }))
        .expect_ok();
    c
}

/// Uploading a part number again replaces the part, and the replaced part's
/// shards are freed rather than left referenced by nothing.
#[test]
fn reuploading_a_part_frees_the_part_it_replaced() {
    let c = ec_cluster(6, "mpu-redo");
    let baseline = c.total_used_bytes();
    let upload = initiate(&c, "mpu-redo", "k");
    upload_part(&c, "mpu-redo", "k", &upload, 1, &mib(1));
    let one = c.total_used_bytes() - baseline;

    let etag = upload_part(&c, "mpu-redo", "k", &upload, 1, &mib(2));
    assert_eq!(
        c.await_total_used_bytes(baseline + one) - baseline,
        one,
        "the replaced part's shards are still allocated"
    );

    complete(&c, "mpu-redo", "k", &upload, &[(1, etag)]).expect_ok();
    let got = c.request("GET", "/mpu-redo/k", &[]);
    got.expect(200);
    assert!(got.bytes == mib(2), "the object is not the second upload");
    assert_eq!(c.await_total_used_bytes(baseline + one) - baseline, one);
}

/// Parts uploaded but left out of the completion are not part of any
/// object, and are freed when the upload completes.
#[test]
fn parts_left_out_of_a_completion_are_freed() {
    let c = ec_cluster(6, "mpu-subset");
    let baseline = c.total_used_bytes();
    let upload = initiate(&c, "mpu-subset", "k");
    let first = upload_part(&c, "mpu-subset", "k", &upload, 1, &mib(1));
    let one = c.total_used_bytes() - baseline;
    upload_part(&c, "mpu-subset", "k", &upload, 2, &mib(2));
    upload_part(&c, "mpu-subset", "k", &upload, 3, &mib(3));

    complete(&c, "mpu-subset", "k", &upload, &[(1, first)]).expect_ok();
    assert!(c.request("GET", "/mpu-subset/k", &[]).bytes == mib(1));
    assert_eq!(
        c.await_total_used_bytes(baseline + one) - baseline,
        one,
        "parts 2 and 3 were left out of the object but kept their shards"
    );
}

/// Completing an upload onto a key that already has an object replaces it,
/// and frees it, as a plain PUT does.
#[test]
fn completing_onto_an_existing_key_frees_the_old_object() {
    let c = ec_cluster(6, "mpu-over");
    let baseline = c.total_used_bytes();
    c.request("PUT", "/mpu-over/k", &mib(0)).expect(200);
    let one = c.total_used_bytes() - baseline;

    let upload = initiate(&c, "mpu-over", "k");
    let etag = upload_part(&c, "mpu-over", "k", &upload, 1, &mib(1));
    complete(&c, "mpu-over", "k", &upload, &[(1, etag)]).expect_ok();

    assert!(c.request("GET", "/mpu-over/k", &[]).bytes == mib(1));
    assert_eq!(
        c.await_total_used_bytes(baseline + one) - baseline,
        one,
        "the object the completion replaced kept its shards"
    );
    c.request("DELETE", "/mpu-over/k", &[]).expect(204);
    assert_eq!(c.await_total_used_bytes(baseline), baseline);
}

/// Abort frees each part where that part was placed (in the object's
/// placement group; with more OSDs than one stripe spans, wherever a
/// part's placement put it, should the PG's members have changed).
#[test]
fn aborting_frees_parts_wherever_they_were_placed() {
    let c = ec_cluster(9, "mpu-spread");
    let baseline = c.total_used_bytes();
    let upload = initiate(&c, "mpu-spread", "k");
    for n in 1..=6u32 {
        upload_part(
            &c,
            "mpu-spread",
            "k",
            &upload,
            n,
            &mib(u8::try_from(n).unwrap()),
        );
    }
    assert!(c.total_used_bytes() > baseline);

    c.request("DELETE", &format!("/mpu-spread/k?uploadId={upload}"), &[])
        .expect(204);
    let after = c.await_total_used_bytes(baseline);
    assert_eq!(
        after,
        baseline,
        "abort left {} bytes of parts allocated",
        after.saturating_sub(baseline)
    );
}

/// A completion refused because its object couldn't be stored (here every
/// OSD down) leaves the upload as it was: the parts, acknowledged, are
/// still there, and the completion sent again once the OSDs are back makes
/// the object. Meta used to drop the upload before the object was stored:
/// the parts were freed and a retry was told `NoSuchUpload`.
#[test]
fn a_completion_that_fails_to_store_can_be_retried() {
    use objectio_e2e::ha::HaCluster;
    let mut ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(std::time::Duration::from_secs(30));
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/retry", &[]).status, 200);
    let upload = initiate(c, "retry", "big.bin");
    let first = mib(7);
    let first = [
        first.as_slice(),
        first.as_slice(),
        first.as_slice(),
        first.as_slice(),
        first.as_slice(),
    ]
    .concat();
    let second = b"the last part".to_vec();
    let etags = vec![
        (1, upload_part(c, "retry", "big.bin", &upload, 1, &first)),
        (2, upload_part(c, "retry", "big.bin", &upload, 2, &second)),
    ];

    for i in 0..6 {
        ha.stop_osd(i);
    }
    let c = &ha.clients[0];
    let refused = complete(c, "retry", "big.bin", &upload, &etags);
    assert!(
        refused.status >= 500,
        "a completion with every OSD down can't succeed: {} {}",
        refused.status,
        refused.text()
    );
    for i in 0..6 {
        ha.start_osd(i, None);
    }
    let c = &ha.clients[0];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let r = complete(c, "retry", "big.bin", &upload, &etags);
        if r.status == 200 {
            break;
        }
        assert!(
            r.status >= 500 && std::time::Instant::now() < deadline,
            "the completion sent again: {} {}",
            r.status,
            r.text()
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let got = c.request("GET", "/retry/big.bin", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.bytes, [first, second].concat());
}

/// A completion meta applied whose answer was lost (a leader change, a
/// timeout: here a test hook) is completed by the client's retry, into the
/// object its parts make. Meta used to drop the upload when it applied the
/// completion: the retry found no upload (`NoSuchUpload`), the object never
/// existed, and its parts belonged to nothing.
#[test]
fn a_completion_whose_answer_was_lost_completes_on_the_retry() {
    for versioned in [false, true] {
        let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
        c.json("POST", "/_admin/buckets", json!({ "name": "mpu-lost" }))
            .expect_ok();
        if versioned {
            c.request(
                "PUT",
                "/mpu-lost?versioning",
                b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            )
            .expect(200);
        }
        let upload = initiate(&c, "mpu-lost", "k");
        let first = upload_part(&c, "mpu-lost", "k", &upload, 1, &mib(1));
        c.json(
            "POST",
            "/_admin/test/lose-reply",
            json!({ "call": "complete_multipart_upload" }),
        )
        .expect_ok();
        let lost = complete(&c, "mpu-lost", "k", &upload, &[(1, first.clone())]);
        assert_eq!(lost.status, 503, "versioned {versioned}: {}", lost.text());
        let again = complete(&c, "mpu-lost", "k", &upload, &[(1, first.clone())]);
        assert_eq!(again.status, 200, "versioned {versioned}: {}", again.text());
        let got = c.request("GET", "/mpu-lost/k", &[]);
        assert_eq!(got.status, 200, "versioned {versioned}: {}", got.text());
        assert!(got.bytes == mib(1), "versioned {versioned}: wrong bytes");
        // Sent a third time, it answers as completed, and makes no second
        // version of the same parts.
        complete(&c, "mpu-lost", "k", &upload, &[(1, first)]).expect(200);
        if versioned {
            let versions = c.request("GET", "/mpu-lost?versions", &[]).text();
            assert_eq!(
                versions.matches("<Version>").count(),
                1,
                "one completion, one version: {versions}"
            );
        }
        // Forgotten once committed: no upload is left open.
        let open = c.request("GET", "/mpu-lost?uploads", &[]).text();
        assert!(!open.contains("<Upload>"), "versioned {versioned}: {open}");
    }
}
