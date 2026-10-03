//! Bucket replication between two clusters (architecture/design/
//! s3/bucket-replication.md): every version written to the source bucket
//! reaches the target bucket under the same version id, with the same
//! bytes, metadata and tags — whatever happens to the fast path, and after
//! the target was unreachable.

use std::time::{Duration, Instant};

use objectio_e2e::{Cluster, Response};
use serde_json::json;

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

fn versioned_bucket(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/buckets", json!({ "name": name }))
        .expect_ok();
    c.request(
        "PUT",
        &format!("/{name}?versioning"),
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
}

/// `dst`'s bucket `bucket` as target `name` of `src`.
fn add_target(src: &Cluster, dst: &Cluster, name: &str, bucket: &str) {
    src.json(
        "POST",
        "/_admin/replication/targets",
        json!({
            "name": name,
            "endpoint": dst.endpoint,
            "bucket": bucket,
            "access_key": dst.access_key,
            "secret_key": dst.secret_key,
        }),
    )
    .expect_ok();
}

fn rules(src: &Cluster, bucket: &str, target: &str, delete_markers: bool) {
    let markers = if delete_markers {
        "Enabled"
    } else {
        "Disabled"
    };
    src.request(
        "PUT",
        &format!("/{bucket}?replication"),
        format!(
            "<ReplicationConfiguration><Rule><ID>all</ID><Status>Enabled</Status>\
             <Filter><Prefix></Prefix></Filter>\
             <DeleteMarkerReplication><Status>{markers}</Status></DeleteMarkerReplication>\
             <Destination><Bucket>arn:obio:replication:::{target}</Bucket></Destination>\
             </Rule></ReplicationConfiguration>"
        )
        .as_bytes(),
    )
    .expect(200);
}

fn version_of(r: &Response) -> String {
    r.header("x-amz-version-id").expect("a version id")
}

/// Wait until `dst` has `key`'s version `vid` with `body`.
fn await_replica(dst: &Cluster, bucket: &str, key: &str, vid: &str, body: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let r = dst.request("GET", &format!("/{bucket}/{key}?versionId={vid}"), &[]);
        if r.status == 200 {
            assert!(
                r.bytes == body,
                "{key} {vid} replicated with different bytes"
            );
            assert_eq!(
                r.header("x-amz-replication-status").as_deref(),
                Some("REPLICA")
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{key} {vid} never reached the target"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn await_status(src: &Cluster, path: &str, want: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let got = src
            .request("HEAD", path, &[])
            .header("x-amz-replication-status");
        if got.as_deref() == Some(want) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{path}: status stayed {got:?}, wanted {want}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn pair(src_args: &[&str]) -> (Cluster, Cluster) {
    let src = Cluster::start_with_ec_and_args(6, 4, 2, src_args);
    let dst = Cluster::start_with_ec(6, 4, 2);
    versioned_bucket(&src, "src");
    versioned_bucket(&dst, "dst");
    add_target(&src, &dst, "dr", "dst");
    rules(&src, "src", "dr", false);
    (src, dst)
}

/// New versions — small, overwritten, multipart-sized — reach the target
/// with their version ids, bytes, metadata and tags; the source says
/// COMPLETED, the target REPLICA.
#[test]
fn new_versions_reach_the_target() {
    let (src, dst) = pair(&["--replication-scan-secs", "1"]);
    let a1 = payload(10_000, 1);
    let r = src.request_signed(
        "PUT",
        "/src/a",
        &a1,
        &[
            ("x-amz-meta-colour", b"blue".as_slice()),
            ("x-amz-tagging", b"team=ml".as_slice()),
            ("content-type", b"text/plain".as_slice()),
        ],
        false,
    );
    r.expect(200);
    let v1 = version_of(&r);
    let a2 = payload(20_000, 2);
    let v2 = version_of(&src.request("PUT", "/src/a", &a2));
    // Over the single-PUT cut-off: sent as a multipart upload.
    let big = payload(70 << 20, 3);
    let vb = version_of(&src.request("PUT", "/src/big", &big));

    await_replica(&dst, "dst", "a", &v1, &a1);
    await_replica(&dst, "dst", "a", &v2, &a2);
    await_replica(&dst, "dst", "big", &vb, &big);
    // The newer version is current on the target too.
    assert!(dst.request("GET", "/dst/a", &[]).bytes == a2);
    let head = dst.request("HEAD", &format!("/dst/a?versionId={v1}"), &[]);
    assert_eq!(head.header("x-amz-meta-colour").as_deref(), Some("blue"));
    assert_eq!(head.header("content-type").as_deref(), Some("text/plain"));
    assert_eq!(head.header("x-amz-tagging-count").as_deref(), Some("1"));
    // Same ETag on both sides, the multipart one included.
    for (key, vid) in [("a", &v2), ("big", &vb)] {
        let s = src.request("HEAD", &format!("/src/{key}?versionId={vid}"), &[]);
        let d = dst.request("HEAD", &format!("/dst/{key}?versionId={vid}"), &[]);
        assert_eq!(s.header("etag"), d.header("etag"), "{key}");
    }
    await_status(&src, &format!("/src/a?versionId={v1}"), "COMPLETED");
    await_status(&src, "/src/big", "COMPLETED");
}

/// Delete markers stay on the source unless the rule asks for them; a
/// delete of a specific version never replicates.
#[test]
fn deletes_replicate_only_as_asked() {
    let (src, dst) = pair(&["--replication-scan-secs", "1"]);
    let body = payload(5_000, 9);
    let v = version_of(&src.request("PUT", "/src/k", &body));
    await_replica(&dst, "dst", "k", &v, &body);

    // Rule without delete markers: the target still serves the object.
    src.request("DELETE", "/src/k", &[]).expect(204);
    std::thread::sleep(Duration::from_secs(3));
    assert!(dst.request("GET", "/dst/k", &[]).bytes == body);

    // A version delete never replicates.
    src.request("DELETE", &format!("/src/k?versionId={v}"), &[])
        .expect(204);
    std::thread::sleep(Duration::from_secs(3));
    dst.request("GET", &format!("/dst/k?versionId={v}"), &[])
        .expect(200);

    // With markers asked for, a delete marker arrives under its version id.
    rules(&src, "src", "dr", true);
    let body2 = payload(5_000, 10);
    let v2 = version_of(&src.request("PUT", "/src/m", &body2));
    await_replica(&dst, "dst", "m", &v2, &body2);
    let marker = version_of(&src.request("DELETE", "/src/m", &[]));
    let deadline = Instant::now() + Duration::from_secs(60);
    while dst.request("GET", "/dst/m", &[]).status != 404 {
        assert!(Instant::now() < deadline, "the delete marker never arrived");
        std::thread::sleep(Duration::from_millis(250));
    }
    let r = dst.request("HEAD", &format!("/dst/m?versionId={marker}"), &[]);
    assert_eq!(
        r.header("x-amz-delete-marker").as_deref(),
        Some("true"),
        "{:?}",
        r.headers
    );
}

/// A target that can't be reached: versions wait as FAILED, and reach it
/// once it can be.
#[test]
fn an_unreachable_target_is_caught_up() {
    let src = Cluster::start_with_ec_and_args(6, 4, 2, &["--replication-scan-secs", "1"]);
    let dst = Cluster::start_with_ec(6, 4, 2);
    versioned_bucket(&src, "src");
    versioned_bucket(&dst, "dst");
    src.json(
        "POST",
        "/_admin/replication/targets",
        json!({
            "name": "dr",
            "endpoint": "http://127.0.0.1:1",
            "bucket": "dst",
            "access_key": dst.access_key,
            "secret_key": dst.secret_key,
        }),
    )
    .expect_ok();
    rules(&src, "src", "dr", false);
    let mut written = Vec::new();
    for i in 0..5u8 {
        let body = payload(3_000 + usize::from(i) * 1_000, i);
        let v = version_of(&src.request("PUT", &format!("/src/o{i}"), &body));
        written.push((format!("o{i}"), v, body));
    }
    await_status(&src, "/src/o0", "FAILED");

    // Reachable now.
    add_target(&src, &dst, "dr", "dst");
    for (key, v, body) in &written {
        await_replica(&dst, "dst", key, v, body);
    }
    await_status(&src, "/src/o4", "COMPLETED");
}

/// No fast path (as if the gateway that took the writes died before
/// sending them): the scanner finds every version and sends it.
#[test]
fn the_scanner_alone_delivers_every_version() {
    let (src, dst) = pair(&["--replication-scan-secs", "1", "--no-replication-fast-path"]);
    let mut written = Vec::new();
    for i in 0..8u8 {
        let body = payload(2_000 + usize::from(i) * 500, i);
        let v = version_of(&src.request("PUT", &format!("/src/s{}", i % 3), &body));
        written.push((format!("s{}", i % 3), v, body));
    }
    for (key, v, body) in &written {
        await_replica(&dst, "dst", key, v, body);
    }
}

/// The target's side: a replica sent twice is stored once; a different
/// version under the same id is refused; an older replica arriving after
/// a newer one doesn't become current.
#[test]
fn replica_writes_are_idempotent_and_ordered() {
    let dst = Cluster::start_with_ec(6, 4, 2);
    versioned_bucket(&dst, "dst");
    let old_vid = "01a10000-0000-7000-8000-000000000001";
    let new_vid = "01a10000-0000-7000-8000-000000000002";
    let put = |vid: &str, body: &[u8], etag: &str| {
        dst.request_with_headers(
            "PUT",
            "/dst/k",
            body,
            &[
                ("x-objectio-replica-version-id", vid),
                ("x-objectio-replica-etag", etag),
            ],
        )
    };
    put(new_vid, b"newer", "\"e-new\"").expect(200);
    put(new_vid, b"newer", "\"e-new\"").expect(200);
    let conflict = put(new_vid, b"other", "\"e-other\"");
    assert_eq!(conflict.status, 409, "{}", conflict.text());
    // Older, arriving later: kept as a version, not made current.
    put(old_vid, b"older", "\"e-old\"").expect(200);
    assert_eq!(dst.request("GET", "/dst/k", &[]).bytes, b"newer");
    assert_eq!(
        dst.request("GET", &format!("/dst/k?versionId={old_vid}"), &[])
            .bytes,
        b"older"
    );
    let versions = dst.request("GET", "/dst?versions", &[]).text();
    assert_eq!(versions.matches("<Version>").count(), 2, "{versions}");

    // Only into versioned buckets.
    dst.json("POST", "/_admin/buckets", json!({ "name": "plain" }))
        .expect_ok();
    let r = dst.request_with_headers(
        "PUT",
        "/plain/k",
        b"x",
        &[("x-objectio-replica-version-id", new_vid)],
    );
    assert_eq!(r.status, 400, "{}", r.text());
}

/// `(key, version id, is a delete marker)` of every version in a
/// `ListObjectVersions` reply.
fn listed(xml: &str) -> std::collections::BTreeSet<(String, String, bool)> {
    let field = |entry: &str, name: &str| {
        entry
            .split(&format!("<{name}>"))
            .nth(1)
            .and_then(|s| s.split(&format!("</{name}>")).next())
            .unwrap_or_default()
            .to_string()
    };
    let mut out = std::collections::BTreeSet::new();
    for (open, close, marker) in [
        ("<Version>", "</Version>", false),
        ("<DeleteMarker>", "</DeleteMarker>", true),
    ] {
        for part in xml.split(open).skip(1) {
            let entry = part.split(close).next().unwrap_or_default();
            out.insert((field(entry, "Key"), field(entry, "VersionId"), marker));
        }
    }
    out
}

/// Random writes, overwrites and deletes on the source: once replication
/// catches up, the target lists exactly the source's versions and delete
/// markers, and every version reads back the same.
#[test]
fn random_traffic_converges() {
    let (src, dst) = pair(&["--replication-scan-secs", "1"]);
    rules(&src, "src", "dr", true);
    let mut x = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..120 {
        let key = format!("r{}", next() % 12);
        if next() % 4 == 0 {
            src.request("DELETE", &format!("/src/{key}"), &[])
                .expect(204);
        } else {
            let body = payload(1_000 + (next() % 20_000) as usize, (next() % 251) as u8);
            src.request("PUT", &format!("/src/{key}"), &body)
                .expect(200);
        }
    }
    let want = listed(&src.request("GET", "/src?versions", &[]).text());
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let got = listed(&dst.request("GET", "/dst?versions", &[]).text());
        if got == want {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the target never converged: missing {:?}, extra {:?}",
            want.difference(&got).take(5).collect::<Vec<_>>(),
            got.difference(&want).take(5).collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    for (key, vid, marker) in &want {
        if *marker {
            continue;
        }
        let s = src.request("GET", &format!("/src/{key}?versionId={vid}"), &[]);
        let d = dst.request("GET", &format!("/dst/{key}?versionId={vid}"), &[]);
        assert!(s.bytes == d.bytes, "{key} {vid} differs on the target");
    }
    // The same version is current on both sides.
    for k in 0..12 {
        let s = src.request("GET", &format!("/src/r{k}"), &[]);
        let d = dst.request("GET", &format!("/dst/r{k}"), &[]);
        assert_eq!(s.status, d.status, "r{k}");
        if s.status == 200 {
            assert!(s.bytes == d.bytes, "r{k}: a different version is current");
        }
    }
}

/// A tenant and an admin of it; the admin's access key and secret.
fn tenant_admin(c: &Cluster, tenant: &str) -> (String, String) {
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": tenant, "display_name": tenant, "enabled": true}),
    )
    .expect_ok();
    let u = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": format!("{tenant}-admin"), "tenant": tenant}),
    );
    let uid = u.json()["user_id"].as_str().unwrap().to_string();
    c.json(
        "POST",
        &format!("/_admin/tenants/{tenant}/admins"),
        json!({"user_id": uid}),
    )
    .expect_ok();
    let k = c.json(
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        json!({}),
    );
    (
        k.json()["access_key_id"].as_str().unwrap().to_string(),
        k.json()["secret_access_key"].as_str().unwrap().to_string(),
    )
}

fn rule_xml(target: &str) -> Vec<u8> {
    format!(
        "<ReplicationConfiguration><Rule><ID>all</ID><Status>Enabled</Status>\
         <Filter><Prefix></Prefix></Filter>\
         <Destination><Bucket>arn:obio:replication:::{target}</Bucket></Destination>\
         </Rule></ReplicationConfiguration>"
    )
    .into_bytes()
}

/// Targets belong to a tenant: its admin manages them (on hosts the
/// operator allows), sees no other tenant's, and its buckets' rules can
/// name only its own — so no tenant can send data into another's remote
/// bucket with the other's credentials.
#[test]
fn targets_belong_to_a_tenant() {
    let src = Cluster::start_with_ec_and_args(6, 4, 2, &["--replication-scan-secs", "1"]);
    let dst = Cluster::start_with_ec(6, 4, 2);
    versioned_bucket(&dst, "dst");
    let (acme_key, acme_secret) = tenant_admin(&src, "acme");
    let (beta_key, beta_secret) = tenant_admin(&src, "beta");
    let as_acme = |m: &str, p: &str, b: &[u8]| src.request_as(m, p, b, &acme_key, &acme_secret);
    let as_beta = |m: &str, p: &str, b: &[u8]| src.request_as(m, p, b, &beta_key, &beta_secret);
    let target = |endpoint: &str| {
        json!({
            "name": "dr", "endpoint": endpoint, "bucket": "dst",
            "access_key": dst.access_key, "secret_key": dst.secret_key,
        })
        .to_string()
        .into_bytes()
    };

    // A tenant admin: no host is allowed until the operator says so, and
    // then only https to those hosts — never one inside the cluster.
    let post = "/_admin/replication/targets";
    assert_eq!(as_acme("POST", post, &target(&dst.endpoint)).status, 400);
    src.json(
        "PUT",
        "/_admin/replication/settings",
        json!({"allowed_tenant_hosts": ["dr.acme.example"]}),
    )
    .expect_ok();
    assert_eq!(as_acme("POST", post, &target(&dst.endpoint)).status, 400);
    assert_eq!(
        as_acme("POST", post, &target("http://dr.acme.example")).status,
        400
    );
    let r = as_acme("POST", post, &target("https://dr.acme.example"));
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["tenant"], "acme");
    // The operator's settings are the operator's.
    assert_eq!(
        as_acme("GET", "/_admin/replication/settings", &[]).status,
        403
    );

    // The system admin may set a tenant's target anywhere: here, the real
    // one, replacing acme's; and a system target of the same name.
    src.json(
        "POST",
        "/_admin/replication/targets?tenant=acme",
        serde_json::from_slice::<serde_json::Value>(&target(&dst.endpoint)).unwrap(),
    )
    .expect_ok();
    src.json(
        "POST",
        "/_admin/replication/targets",
        json!({
            "name": "sys", "endpoint": dst.endpoint, "bucket": "dst",
            "access_key": dst.access_key, "secret_key": dst.secret_key,
        }),
    )
    .expect_ok();

    // Each tenant sees only its own targets, never a secret.
    let mine = as_acme("GET", post, &[]).json();
    let names: Vec<&str> = mine["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["dr"], "{mine}");
    assert!(mine["targets"][0].get("secret_key").is_none());
    assert_eq!(as_beta("GET", post, &[]).json()["targets"], json!([]));
    assert_eq!(
        as_beta("GET", &format!("{post}?tenant=acme"), &[]).status,
        403
    );
    assert_eq!(
        as_beta("DELETE", &format!("{post}/dr?tenant=acme"), &[]).status,
        403
    );

    // Rules name targets in the bucket's own tenant only.
    for (ak, sk, bucket) in [
        (&acme_key, &acme_secret, "acme-src"),
        (&beta_key, &beta_secret, "beta-src"),
    ] {
        let as_t = |m: &str, p: &str, b: &[u8]| src.request_as(m, p, b, ak, sk);
        as_t("PUT", &format!("/{bucket}"), &[]).expect(200);
        as_t(
            "PUT",
            &format!("/{bucket}?versioning"),
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        )
        .expect(200);
    }
    assert_eq!(
        as_beta("PUT", "/beta-src?replication", &rule_xml("dr")).status,
        400,
        "beta named acme's target"
    );
    assert_eq!(
        as_acme("PUT", "/acme-src?replication", &rule_xml("sys")).status,
        400,
        "acme named the system's target"
    );
    as_acme("PUT", "/acme-src?replication", &rule_xml("dr")).expect(200);

    // And acme's versions go to acme's target.
    let body = payload(5_000, 9);
    let r = as_acme("PUT", "/acme-src/k", &body);
    r.expect(200);
    await_replica(&dst, "dst", "k", &version_of(&r), &body);
}
