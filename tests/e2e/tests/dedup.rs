//! Dedup policy and the phase-1 dry-run (objectio-docs
//! `architecture/design/core/dedup.md`): the policy resolves bucket → tenant →
//! cluster, and dry-run counts how much written data was already stored in
//! its domain, without changing how anything is stored.

use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use serde_json::json;

/// Sum of every sample of `name` whose labels contain all of `labels`.
fn metric(c: &Cluster, name: &str, labels: &[&str]) -> u64 {
    c.request("GET", "/metrics", &[])
        .text()
        .lines()
        .filter(|l| {
            l.split(['{', ' ']).next() == Some(name) && labels.iter().all(|want| l.contains(want))
        })
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// Wait for `name{labels}` to reach at least `want`; dry-run runs after the
/// PUT has answered.
fn await_metric(c: &Cluster, name: &str, labels: &[&str], want: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let got = metric(c, name, labels);
        if got >= want || Instant::now() > deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Bytes that do not repeat, so chunks are not artefacts of a pattern.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

const DUP: &str = "objectio_dedup_dryrun_bytes_total";

fn duplicate_bytes(c: &Cluster, bucket: &str) -> u64 {
    metric(
        c,
        DUP,
        &[
            &format!("bucket=\"{bucket}\""),
            "chunking=\"1MiB\"",
            "result=\"duplicate\"",
        ],
    )
}

fn new_bytes(c: &Cluster, bucket: &str) -> u64 {
    metric(
        c,
        DUP,
        &[
            &format!("bucket=\"{bucket}\""),
            "chunking=\"1MiB\"",
            "result=\"new\"",
        ],
    )
}

fn bucket(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/buckets", json!({"name": name}))
        .expect_ok();
}

#[test]
fn the_policy_resolves_bucket_then_tenant_then_cluster() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "pol");

    let v = c.request("GET", "/_admin/buckets/pol/dedup", &[]).json();
    assert_eq!(v["effective"]["mode"], "off");
    assert_eq!(v["effective"]["mode_from"], "default");

    c.json(
        "PUT",
        "/_admin/dedup",
        json!({"mode": "dry-run", "scope": "cluster"}),
    )
    .expect_ok();
    let v = c.request("GET", "/_admin/buckets/pol/dedup", &[]).json();
    assert_eq!(v["effective"]["mode"], "dry-run");
    assert_eq!(v["effective"]["scope"], "cluster");
    assert_eq!(v["effective"]["mode_from"], "cluster");

    // The bucket overrides only its scope; its mode still comes from the
    // cluster.
    c.json(
        "PUT",
        "/_admin/buckets/pol/dedup",
        json!({"scope": "bucket"}),
    )
    .expect_ok();
    let v = c.request("GET", "/_admin/buckets/pol/dedup", &[]).json();
    assert_eq!(v["effective"]["mode"], "dry-run");
    assert_eq!(v["effective"]["mode_from"], "cluster");
    assert_eq!(v["effective"]["scope"], "bucket");
    assert_eq!(v["effective"]["scope_from"], "bucket");

    c.request("DELETE", "/_admin/buckets/pol/dedup", &[])
        .expect_ok();
    let v = c.request("GET", "/_admin/buckets/pol/dedup", &[]).json();
    assert_eq!(v["effective"]["scope_from"], "cluster");
}

#[test]
fn what_is_not_available_or_not_valid_is_refused() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "ref");
    c.json("PUT", "/_admin/buckets/ref/dedup", json!({"mode": "on"}))
        .expect(400);
    c.json("PUT", "/_admin/dedup", json!({"mode": "on"}))
        .expect(400);
    c.json(
        "PUT",
        "/_admin/buckets/ref/dedup",
        json!({"mode": "sometimes"}),
    )
    .expect(400);
    c.json(
        "PUT",
        "/_admin/buckets/nope/dedup",
        json!({"mode": "dry-run"}),
    )
    .expect(404);
}

/// The second copy of a file in a dry-run bucket is counted as duplicate
/// bytes; nothing about storing or reading it changes.
#[test]
fn dry_run_counts_a_second_copy_as_duplicate() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "dry");
    c.json(
        "PUT",
        "/_admin/buckets/dry/dedup",
        json!({"mode": "dry-run"}),
    )
    .expect_ok();
    let body = noise(6 << 20, 1);

    c.request("PUT", "/dry/first", &body).expect(200);
    assert_eq!(
        await_metric(
            &c,
            DUP,
            &["bucket=\"dry\"", "chunking=\"1MiB\"", "result=\"new\""],
            body.len() as u64
        ),
        body.len() as u64
    );
    assert_eq!(duplicate_bytes(&c, "dry"), 0);

    c.request("PUT", "/dry/second", &body).expect(200);
    assert_eq!(
        await_metric(
            &c,
            DUP,
            &[
                "bucket=\"dry\"",
                "chunking=\"1MiB\"",
                "result=\"duplicate\""
            ],
            body.len() as u64
        ),
        body.len() as u64,
        "the second copy should be all duplicate"
    );
    assert_eq!(c.request("GET", "/dry/second", &[]).bytes, body);
}

/// Bucket scope keeps buckets apart; cluster scope lets them share.
#[test]
fn the_scope_decides_which_copies_match() {
    let c = Cluster::start_with_ec(6, 4, 2);
    for b in ["one", "two", "three"] {
        bucket(&c, b);
    }
    for b in ["one", "two"] {
        c.json(
            "PUT",
            &format!("/_admin/buckets/{b}/dedup"),
            json!({"mode": "dry-run", "scope": "bucket"}),
        )
        .expect_ok();
    }
    let body = noise(3 << 20, 2);
    c.request("PUT", "/one/x", &body).expect(200);
    await_metric(
        &c,
        DUP,
        &["bucket=\"one\"", "chunking=\"1MiB\""],
        body.len() as u64,
    );
    c.request("PUT", "/two/x", &body).expect(200);
    await_metric(
        &c,
        DUP,
        &["bucket=\"two\"", "chunking=\"1MiB\""],
        body.len() as u64,
    );
    assert_eq!(
        duplicate_bytes(&c, "two"),
        0,
        "bucket scope let buckets share"
    );
    assert_eq!(new_bytes(&c, "two"), body.len() as u64);

    // "three" is cluster-scoped, as is a copy now written to "one".
    for b in ["one", "three"] {
        c.json(
            "PUT",
            &format!("/_admin/buckets/{b}/dedup"),
            json!({"mode": "dry-run", "scope": "cluster"}),
        )
        .expect_ok();
    }
    c.request("PUT", "/one/y", &body).expect(200);
    await_metric(
        &c,
        DUP,
        &["bucket=\"one\"", "chunking=\"1MiB\""],
        2 * body.len() as u64,
    );
    c.request("PUT", "/three/x", &body).expect(200);
    assert_eq!(
        await_metric(
            &c,
            DUP,
            &[
                "bucket=\"three\"",
                "chunking=\"1MiB\"",
                "result=\"duplicate\""
            ],
            body.len() as u64
        ),
        body.len() as u64,
        "cluster scope did not share across buckets"
    );
}

#[test]
fn encrypted_writes_are_skipped_and_a_reset_starts_over() {
    // The customer key is 32 bytes of 'A'; its base64 and the base64 of
    // its MD5.
    const SSE_C: [(&str, &str); 3] = [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        (
            "x-amz-server-side-encryption-customer-key",
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
        ),
        (
            "x-amz-server-side-encryption-customer-key-md5",
            "UhbdzFjo2t5SVgded/ZC2g==",
        ),
    ];
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "mix");
    c.json(
        "PUT",
        "/_admin/buckets/mix/dedup",
        json!({"mode": "dry-run"}),
    )
    .expect_ok();

    let body = noise(2 << 20, 3);
    c.request_with_headers("PUT", "/mix/sealed", &body, &SSE_C)
        .expect(200);
    assert!(
        metric(
            &c,
            "objectio_dedup_dryrun_skipped_total",
            &["reason=\"encrypted\""]
        ) >= 1
    );

    c.request("PUT", "/mix/a", &body).expect(200);
    await_metric(
        &c,
        DUP,
        &["bucket=\"mix\"", "chunking=\"1MiB\""],
        body.len() as u64,
    );
    let reset = c.request("POST", "/_admin/dedup/dry-run/reset", &[]);
    reset.expect_ok();
    assert!(reset.json()["forgotten"].as_u64().unwrap() > 0);

    // Forgotten: the same bytes count as new again.
    let before = new_bytes(&c, "mix");
    c.request("PUT", "/mix/b", &body).expect(200);
    assert_eq!(
        await_metric(
            &c,
            DUP,
            &["bucket=\"mix\"", "chunking=\"1MiB\"", "result=\"new\""],
            before + body.len() as u64
        ),
        before + body.len() as u64
    );
}

/// A tenant's policy applies to its buckets, and survives the console's
/// save of the whole tenant record.
#[test]
fn a_tenant_policy_applies_to_its_buckets_and_round_trips() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "acme", "dedup": {"mode": "dry-run", "scope": "tenant"}}),
    )
    .expect(201);
    c.json(
        "POST",
        "/_admin/buckets",
        json!({"name": "acme-data", "tenant": "acme"}),
    )
    .expect_ok();

    let v = c
        .request("GET", "/_admin/buckets/acme-data/dedup", &[])
        .json();
    assert_eq!(v["tenant_name"], "acme");
    assert_eq!(v["effective"]["mode"], "dry-run");
    assert_eq!(v["effective"]["scope"], "tenant");
    assert_eq!(v["effective"]["mode_from"], "tenant");

    // What the console does: read the tenant, change something else, save
    // it whole.
    let mut t = c.request("GET", "/_admin/tenants/acme", &[]).json();
    assert_eq!(t["dedup"]["mode"], "dry-run");
    t["display_name"] = json!("Acme");
    c.json("PUT", "/_admin/tenants/acme", t).expect_ok();
    let v = c
        .request("GET", "/_admin/buckets/acme-data/dedup", &[])
        .json();
    assert_eq!(
        v["effective"]["mode_from"], "tenant",
        "saving the tenant lost its dedup policy"
    );

    c.json(
        "PUT",
        "/_admin/tenants/acme",
        json!({"name": "acme", "dedup": {"mode": "on"}}),
    )
    .expect(400);
}
