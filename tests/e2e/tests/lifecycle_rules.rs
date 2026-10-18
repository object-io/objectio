//! Lifecycle rules, carried out: current versions expire (deleted, or under
//! a delete marker when versioned), old versions expire after their days
//! with the newest kept, lone delete markers are cleaned up and ones with
//! versions behind them are not, and locked versions are left alone. A
//! lifecycle "day" is one second here.

use std::time::{Duration, Instant};

use objectio_e2e::{Cluster, Response};

fn cluster(extra: &[&str]) -> Cluster {
    let mut args = vec![
        "--lifecycle-interval-secs",
        "1",
        "--lifecycle-day-secs",
        "1",
    ];
    args.extend_from_slice(extra);
    Cluster::start_with_ec_and_args(6, 4, 2, &args)
}

fn rule(id: &str, filter: &str, actions: &str) -> String {
    format!("<Rule><ID>{id}</ID><Filter>{filter}</Filter><Status>Enabled</Status>{actions}</Rule>")
}

fn lifecycle(c: &Cluster, bucket: &str, rules: &[String]) {
    let doc = format!(
        "<LifecycleConfiguration>{}</LifecycleConfiguration>",
        rules.concat()
    );
    let r = c.request("PUT", &format!("/{bucket}?lifecycle"), doc.as_bytes());
    assert_eq!(r.status, 200, "{}", r.text());
}

fn versioned(c: &Cluster, bucket: &str) {
    c.request("PUT", &format!("/{bucket}"), &[]).expect(200);
    c.request(
        "PUT",
        &format!("/{bucket}?versioning"),
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
}

/// Wait until `check` holds, or fail after `secs`.
fn eventually(secs: u64, what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Every `<VersionId>` in a `ListObjectVersions` answer, and whether each is
/// a delete marker.
fn versions(c: &Cluster, bucket: &str) -> Vec<(String, bool)> {
    let text = c.request("GET", &format!("/{bucket}?versions"), &[]).text();
    let mut out = Vec::new();
    for (tag, marker) in [("<Version>", false), ("<DeleteMarker>", true)] {
        for chunk in text.split(tag).skip(1) {
            let vid = chunk
                .split("<VersionId>")
                .nth(1)
                .and_then(|s| s.split("</VersionId>").next())
                .unwrap_or_default();
            out.push((vid.to_string(), marker));
        }
    }
    out
}

fn put(c: &Cluster, path: &str, body: &[u8]) -> Response {
    let r = c.request("PUT", path, body);
    r.expect(200);
    r
}

#[test]
fn current_versions_expire_after_their_days_and_only_under_the_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let c = cluster(&["--audit-log", log.to_str().unwrap()]);
    c.request("PUT", "/plain", &[]).expect(200);
    put(&c, "/plain/logs/a", b"old");
    put(&c, "/plain/keep/b", b"kept");
    lifecycle(
        &c,
        "plain",
        &[rule(
            "expire-logs",
            "<Prefix>logs/</Prefix>",
            "<Expiration><Days>2</Days></Expiration>",
        )],
    );

    eventually(30, "logs/a expired", || {
        c.request("GET", "/plain/logs/a", &[]).status == 404
    });
    assert_eq!(c.request("GET", "/plain/keep/b", &[]).bytes, b"kept");

    // Lifecycle's own deletes are audit events, by the rule.
    eventually(10, "an audit event for the expiry", || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .any(|l| l.contains("lifecycle:expire-logs") && l.contains("logs/a"))
    });
}

#[test]
fn in_a_versioned_bucket_expiry_adds_a_marker_and_old_versions_go_later() {
    let c = cluster(&[]);
    versioned(&c, "ver");
    let v1 = put(&c, "/ver/k", b"one")
        .header("x-amz-version-id")
        .unwrap();
    let v2 = put(&c, "/ver/k", b"two")
        .header("x-amz-version-id")
        .unwrap();
    let v3 = put(&c, "/ver/k", b"three")
        .header("x-amz-version-id")
        .unwrap();
    lifecycle(
        &c,
        "ver",
        &[rule(
            "old",
            "",
            "<NoncurrentVersionExpiration><NoncurrentDays>3</NoncurrentDays>\
             <NewerNoncurrentVersions>1</NewerNoncurrentVersions></NoncurrentVersionExpiration>",
        )],
    );
    // v1 goes (noncurrent long enough, and not the newest noncurrent); v2
    // stays as the one kept; v3 is current and untouched.
    eventually(30, "v1 expired", || {
        !versions(&c, "ver").iter().any(|(id, _)| *id == v1)
    });
    let left: Vec<String> = versions(&c, "ver").into_iter().map(|(id, _)| id).collect();
    assert!(left.contains(&v2) && left.contains(&v3), "{left:?}");
    assert_eq!(c.request("GET", "/ver/k", &[]).bytes, b"three");
    // An old version deleted by lifecycle is gone for good.
    assert_eq!(
        c.request("GET", &format!("/ver/k?versionId={v1}"), &[])
            .status,
        404
    );

    // Expiring the current version in a versioned bucket hides it under a
    // marker; the data is still there as a version.
    versioned(&c, "ver2");
    let keep = put(&c, "/ver2/k", b"data")
        .header("x-amz-version-id")
        .unwrap();
    lifecycle(
        &c,
        "ver2",
        &[rule(
            "expire",
            "",
            "<Expiration><Days>2</Days></Expiration>",
        )],
    );
    eventually(30, "a delete marker on top", || {
        c.request("GET", "/ver2/k", &[]).status == 404
    });
    assert_eq!(
        c.request("GET", &format!("/ver2/k?versionId={keep}"), &[])
            .bytes,
        b"data"
    );
    assert!(versions(&c, "ver2").iter().any(|(_, marker)| *marker));
}

#[test]
fn a_lone_marker_is_cleaned_up_and_one_with_versions_behind_it_is_not() {
    let c = cluster(&[]);
    versioned(&c, "dmk");
    // "alone": its only version deleted by id, leaving the marker alone.
    let v = put(&c, "/dmk/alone", b"x")
        .header("x-amz-version-id")
        .unwrap();
    c.request("DELETE", "/dmk/alone", &[]).expect(204);
    c.request("DELETE", &format!("/dmk/alone?versionId={v}"), &[])
        .expect(204);
    // "behind": a marker over a version.
    let behind = put(&c, "/dmk/behind", b"y")
        .header("x-amz-version-id")
        .unwrap();
    c.request("DELETE", "/dmk/behind", &[]).expect(204);
    lifecycle(
        &c,
        "dmk",
        &[rule(
            "markers",
            "",
            "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>",
        )],
    );
    eventually(30, "the lone marker removed", || {
        !c.request("GET", "/dmk?versions", &[])
            .text()
            .contains("<Key>alone</Key>")
    });
    // The other marker stays: removing it would bring "behind" back.
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(c.request("GET", "/dmk/behind", &[]).status, 404);
    assert_eq!(
        c.request("GET", &format!("/dmk/behind?versionId={behind}"), &[])
            .bytes,
        b"y"
    );
}

#[test]
fn a_locked_version_outlives_any_rule() {
    let c = cluster(&[]);
    c.request_with_headers(
        "PUT",
        "/worm",
        &[],
        &[("x-amz-bucket-object-lock-enabled", "true")],
    )
    .expect(200);
    c.request(
        "PUT",
        "/worm?object-lock",
        b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>\
          <Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days></DefaultRetention></Rule>\
          </ObjectLockConfiguration>",
    )
    .expect(200);
    let v1 = put(&c, "/worm/k", b"locked")
        .header("x-amz-version-id")
        .unwrap();
    put(&c, "/worm/k", b"newer");
    lifecycle(
        &c,
        "worm",
        &[rule(
            "old",
            "",
            "<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration>",
        )],
    );
    // Several scans pass; the locked version (retained for a real day)
    // is still there.
    std::thread::sleep(Duration::from_secs(8));
    assert_eq!(
        c.request("GET", &format!("/worm/k?versionId={v1}"), &[])
            .bytes,
        b"locked"
    );
}

#[test]
fn configurations_read_back_as_written_and_bad_ones_are_refused() {
    let c = cluster(&[]);
    c.request("PUT", "/cfg", &[]).expect(200);
    assert_eq!(c.request("GET", "/cfg?lifecycle", &[]).status, 404);
    lifecycle(
        &c,
        "cfg",
        &[
            rule(
                "r1",
                "<And><Prefix>a/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And>",
                "<Expiration><Days>7</Days></Expiration>",
            ),
            rule(
                "r2",
                "<Prefix>uploads/</Prefix>",
                "<AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation></AbortIncompleteMultipartUpload>",
            ),
        ],
    );
    let got = c.request("GET", "/cfg?lifecycle", &[]).text();
    for part in [
        "<ID>r1</ID>",
        "<Prefix>a/</Prefix>",
        "<Key>k</Key>",
        "<Days>7</Days>",
        "<DaysAfterInitiation>2</DaysAfterInitiation>",
    ] {
        assert!(got.contains(part), "{part} missing from {got}");
    }
    let bad = c.request(
        "PUT",
        "/cfg?lifecycle",
        b"<LifecycleConfiguration><Rule><ID>x</ID><Filter/><Status>Enabled</Status>\
          <Expiration><Days>0</Days></Expiration></Rule></LifecycleConfiguration>",
    );
    assert_eq!(bad.status, 400, "{}", bad.text());
    c.request("DELETE", "/cfg?lifecycle", &[]).expect(204);
    assert_eq!(c.request("GET", "/cfg?lifecycle", &[]).status, 404);
}
