//! Object Lock retention, end to end.
//!
//! Retention is a compliance control: under COMPLIANCE mode a lock cannot be
//! lifted by anyone, including the account root. That makes both directions of
//! failure expensive — a lock that silently does not exist is a control the
//! operator believes they have, and a lock that cannot expire is data nobody
//! can ever delete.
//!
//! Every test here is pinned to a way the date conversion used to get this
//! wrong.

use objectio_e2e::Cluster;
use serde_json::json;

/// A bucket with object lock on, holding `locked.txt`.
fn setup(bucket: &str) -> Cluster {
    let c = Cluster::start();
    lock_bucket(&c, bucket);
    c.request("PUT", &format!("/{bucket}/locked.txt"), b"data")
        .expect(200);
    c
}

fn retention_body(mode: &str, date: &str) -> String {
    format!("<Retention><Mode>{mode}</Mode><RetainUntilDate>{date}</RetainUntilDate></Retention>")
}

fn put_retention(c: &Cluster, bucket: &str, mode: &str, date: &str) -> objectio_e2e::Response {
    c.request(
        "PUT",
        &format!("/{bucket}/locked.txt?retention"),
        retention_body(mode, date).as_bytes(),
    )
}

/// The happy path, so the refusals below cannot pass by refusing everything.
#[test]
fn a_future_retention_date_is_stored_and_read_back() {
    let c = setup("lock-ok");
    put_retention(&c, "lock-ok", "GOVERNANCE", "2099-01-01T00:00:00Z").expect_ok();

    let got = c.request("GET", "/lock-ok/locked.txt?retention", &[]);
    got.expect(200);
    let body = got.text();
    assert!(
        body.contains("GOVERNANCE"),
        "mode did not come back: {body}"
    );
    assert!(
        body.contains("2099"),
        "the retain-until date did not come back: {body}"
    );
}

/// A date the server cannot parse must be refused, not quietly dropped.
///
/// It used to fall through `unwrap_or(0)` — "retain until the epoch", which is
/// no retention at all — and answer 200. A client setting a compliance lock
/// got a success and no lock, which is the worst possible direction to fail
/// for a control whose entire purpose is to be relied upon.
#[test]
fn an_unparseable_retention_date_is_refused() {
    let c = setup("lock-bad-date");
    for date in ["not-a-date", "2099-13-45T99:99:99Z", "", "1735689600"] {
        let r = put_retention(&c, "lock-bad-date", "COMPLIANCE", date);
        assert_eq!(
            r.status,
            400,
            "retention date {date:?} was accepted: {}",
            r.text()
        );
    }

    // And nothing was stored by any of them.
    let got = c.request("GET", "/lock-bad-date/locked.txt?retention", &[]);
    assert_ne!(
        got.status,
        200,
        "a refused retention request still left a lock behind: {}",
        got.text()
    );
}

/// A date before 1970 must be refused.
///
/// This is the unrecoverable one. `dt.timestamp()` is negative for a pre-epoch
/// date and `as u64` wrapped it to about 1.8e19 — later than any `now` will
/// ever be. Enforcement compares `retain_until_date > now`, so under
/// COMPLIANCE, which cannot be lifted by anyone, a typo in the year locked the
/// object forever.
#[test]
fn a_retention_date_before_the_epoch_cannot_lock_an_object_forever() {
    let c = setup("lock-prehistoric");
    for date in ["1969-01-01T00:00:00Z", "1900-01-01T00:00:00Z"] {
        let r = put_retention(&c, "lock-prehistoric", "COMPLIANCE", date);
        assert_eq!(
            r.status,
            400,
            "a pre-epoch retention date was accepted: {}",
            r.text()
        );
    }

    // The object must still be deletable — that is the whole point.
    c.request("DELETE", "/lock-prehistoric/locked.txt", &[])
        .expect(204);
}

/// A date already in the past is refused rather than stored pre-expired.
#[test]
fn a_retention_date_in_the_past_is_refused() {
    let c = setup("lock-past");
    let r = put_retention(&c, "lock-past", "GOVERNANCE", "2020-01-01T00:00:00Z");
    assert_eq!(
        r.status,
        400,
        "a retention date in the past was accepted: {}",
        r.text()
    );
}

/// A mode other than the two AWS defines is refused.
#[test]
fn an_unknown_retention_mode_is_refused() {
    let c = setup("lock-mode");
    let r = put_retention(&c, "lock-mode", "SOMETIMES", "2099-01-01T00:00:00Z");
    assert_eq!(r.status, 400, "mode 'SOMETIMES' was accepted: {}", r.text());
}

/// A live compliance lock actually stops a delete.
///
/// The counterpart to every refusal above: if retention did not enforce, all
/// of them would pass for the wrong reason.
#[test]
fn a_compliance_lock_refuses_a_delete() {
    let c = setup("lock-enforced");
    put_retention(&c, "lock-enforced", "COMPLIANCE", "2099-01-01T00:00:00Z").expect_ok();

    // By version: without one a delete only adds a marker, which S3 allows.
    let version = c
        .request("HEAD", "/lock-enforced/locked.txt", &[])
        .header("x-amz-version-id")
        .expect("a version");
    let refused = c.request(
        "DELETE",
        &format!("/lock-enforced/locked.txt?versionId={version}"),
        &[],
    );
    assert_eq!(
        refused.status,
        403,
        "a compliance-locked object was deleted: {}",
        refused.text()
    );
}

// ── WORM buckets: the lock a new object gets, and that it holds ──────────

/// A bucket created with object lock (versioned for good).
fn lock_bucket(c: &Cluster, bucket: &str) {
    c.request_with_headers(
        "PUT",
        &format!("/{bucket}"),
        &[],
        &[("x-amz-bucket-object-lock-enabled", "true")],
    )
    .expect(200);
}

fn put_version(c: &Cluster, path: &str, headers: &[(&str, &str)]) -> String {
    let r = c.request_with_headers("PUT", path, b"worm", headers);
    r.expect(200);
    r.header("x-amz-version-id").expect("a version")
}

/// A bucket's default retention locks every object written into it. It
/// used to lock nothing: the version could be deleted at once.
#[test]
fn a_buckets_default_retention_locks_new_objects() {
    let c = Cluster::start();
    lock_bucket(&c, "worm");
    c.request(
        "PUT",
        "/worm?object-lock",
        b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>\
          <Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days></DefaultRetention></Rule>\
          </ObjectLockConfiguration>",
    )
    .expect(200);
    let v = put_version(&c, "/worm/k", &[]);

    let head = c.request("HEAD", "/worm/k", &[]);
    assert_eq!(
        head.header("x-amz-object-lock-mode").as_deref(),
        Some("COMPLIANCE")
    );
    assert!(head.header("x-amz-object-lock-retain-until-date").is_some());
    let del = c.request("DELETE", &format!("/worm/k?versionId={v}"), &[]);
    assert_eq!(
        del.status,
        403,
        "a default-locked version was deleted: {}",
        del.text()
    );
    // Deleting without a version only adds a marker, which a lock allows.
    c.request("DELETE", "/worm/k", &[]).expect(204);
    c.request("GET", &format!("/worm/k?versionId={v}"), &[])
        .expect(200);
}

/// The lock an upload asks for in its headers is the lock it gets.
#[test]
fn an_upload_carries_the_lock_its_headers_ask_for() {
    let c = Cluster::start();
    lock_bucket(&c, "worm");
    let v = put_version(
        &c,
        "/worm/k",
        &[
            ("x-amz-object-lock-mode", "GOVERNANCE"),
            (
                "x-amz-object-lock-retain-until-date",
                "2099-01-01T00:00:00Z",
            ),
            ("x-amz-object-lock-legal-hold", "ON"),
        ],
    );
    let head = c.request("HEAD", "/worm/k", &[]);
    assert_eq!(
        head.header("x-amz-object-lock-mode").as_deref(),
        Some("GOVERNANCE")
    );
    assert_eq!(
        head.header("x-amz-object-lock-legal-hold").as_deref(),
        Some("ON")
    );
    assert_eq!(
        c.request("DELETE", &format!("/worm/k?versionId={v}"), &[])
            .status,
        403,
        "a version under legal hold was deleted"
    );
}

/// A multipart upload's lock, asked for when it starts, is on the object.
#[test]
fn a_multipart_upload_carries_its_lock() {
    let c = Cluster::start();
    lock_bucket(&c, "worm");
    let r = c.request_with_headers(
        "POST",
        "/worm/mp?uploads",
        &[],
        &[
            ("x-amz-object-lock-mode", "COMPLIANCE"),
            (
                "x-amz-object-lock-retain-until-date",
                "2099-01-01T00:00:00Z",
            ),
        ],
    );
    r.expect(200);
    let text = r.text();
    let upload = text
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .unwrap()
        .to_string();
    let etag = c
        .request(
            "PUT",
            &format!("/worm/mp?partNumber=1&uploadId={upload}"),
            b"part",
        )
        .header("etag")
        .unwrap();
    let done = c.request(
        "POST",
        &format!("/worm/mp?uploadId={upload}"),
        format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
        )
        .as_bytes(),
    );
    done.expect(200);
    let v = done.header("x-amz-version-id").expect("a version");
    assert_eq!(
        c.request("DELETE", &format!("/worm/mp?versionId={v}"), &[])
            .status,
        403,
        "a locked multipart object was deleted"
    );
}

/// COMPLIANCE can be extended, never shortened or weakened; GOVERNANCE only
/// with the bypass header. Any change used to be accepted.
#[test]
fn a_lock_in_force_can_be_tightened_but_not_loosened() {
    let c = Cluster::start();
    lock_bucket(&c, "worm");
    put_version(&c, "/worm/k", &[]);
    let body = |mode: &str, date: &str| {
        format!(
            "<Retention><Mode>{mode}</Mode><RetainUntilDate>{date}</RetainUntilDate></Retention>"
        )
    };
    c.request(
        "PUT",
        "/worm/k?retention",
        body("COMPLIANCE", "2099-01-02T00:00:00Z").as_bytes(),
    )
    .expect(200);
    for (mode, date, what) in [
        ("COMPLIANCE", "2099-01-01T00:00:00Z", "shortened"),
        (
            "GOVERNANCE",
            "2099-06-01T00:00:00Z",
            "weakened to GOVERNANCE",
        ),
    ] {
        let r = c.request("PUT", "/worm/k?retention", body(mode, date).as_bytes());
        assert_eq!(r.status, 403, "a COMPLIANCE lock was {what}: {}", r.text());
    }
    c.request(
        "PUT",
        "/worm/k?retention",
        body("COMPLIANCE", "2099-06-01T00:00:00Z").as_bytes(),
    )
    .expect(200);

    put_version(&c, "/worm/g", &[]);
    c.request(
        "PUT",
        "/worm/g?retention",
        body("GOVERNANCE", "2099-01-02T00:00:00Z").as_bytes(),
    )
    .expect(200);
    let shorter = body("GOVERNANCE", "2099-01-01T00:00:00Z");
    assert_eq!(
        c.request("PUT", "/worm/g?retention", shorter.as_bytes())
            .status,
        403
    );
    c.request_with_headers(
        "PUT",
        "/worm/g?retention",
        shorter.as_bytes(),
        &[("x-amz-bypass-governance-retention", "true")],
    )
    .expect(200);
}

/// Without object lock on the bucket there is nothing to lock with: S3
/// refuses rather than locking objects in a bucket that can be emptied
/// only by deleting them.
#[test]
fn a_bucket_without_object_lock_refuses_locks() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({ "name": "plain" }))
        .expect_ok();
    c.request("PUT", "/plain/locked.txt", b"data").expect(200);
    for (sub, body) in [
        ("legal-hold", "<LegalHold><Status>ON</Status></LegalHold>"),
        (
            "retention",
            "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>",
        ),
    ] {
        let r = c.request("PUT", &format!("/plain/locked.txt?{sub}"), body.as_bytes());
        assert_eq!(r.status, 400, "{sub}: {}", r.text());
        assert!(r.text().contains("InvalidRequest"), "{sub}: {}", r.text());
    }
    let r = c.request_with_headers(
        "PUT",
        "/plain/k",
        b"x",
        &[("x-amz-object-lock-legal-hold", "ON")],
    );
    assert_eq!(r.status, 400, "{}", r.text());
    c.request("DELETE", "/plain/locked.txt", &[]).expect(204);
}
