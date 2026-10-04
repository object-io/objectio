//! Quotas (A8b): a bucket's and a tenant's byte quotas refuse writes past
//! them with 403 `QuotaExceeded`, under concurrent writers, and deletes make
//! room again once the usage report shows them (objectio-docs
//! `s3/quotas.md`). One gateway: admission is then exact.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use serde_json::json;

const OBJECT: usize = 64 * 1024;

/// Wait until the usage report has `bucket` with a byte quota of `quota`.
fn await_quota_in_report(c: &Cluster, bucket: &str, quota: u64) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let usage = c.request("GET", "/_admin/usage", &[]).json();
        let known = usage["buckets"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|r| r["bucket"] == bucket && r["quota_bytes"].as_u64() == Some(quota))
        });
        let tenant_known = usage["tenants"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|r| r["quota_bytes"].as_u64() == Some(quota))
        });
        if known || tenant_known {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "quota never reached the report: {usage}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Eight writers PUT `OBJECT`-byte objects into `bucket` until each is
/// refused; returns the keys written and checks every refusal is a 403
/// `QuotaExceeded`.
fn fill(c: &Cluster, bucket: &str) -> Vec<String> {
    let written = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for w in 0..8 {
            let written = &written;
            s.spawn(move || {
                let body = vec![u8::try_from(w).unwrap(); OBJECT];
                for i in 0.. {
                    let key = format!("w{w}/o{i}");
                    let r = c.request("PUT", &format!("/{bucket}/{key}"), &body);
                    if r.status == 200 {
                        written.lock().unwrap().push(key);
                        continue;
                    }
                    assert_eq!(r.status, 403, "{}", r.text());
                    assert!(r.text().contains("QuotaExceeded"), "{}", r.text());
                    break;
                }
            });
        }
    });
    written.into_inner().unwrap()
}

#[test]
fn a_bucket_quota_refuses_writes_past_it_and_deletes_make_room() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "q"}))
        .expect_ok();
    let quota: u64 = 1 << 20;
    c.json(
        "PUT",
        "/_admin/buckets/q/quota",
        json!({"quota_bytes": quota}),
    )
    .expect(204);
    await_quota_in_report(&c, "q", quota);

    let written = fill(&c, "q");
    let bytes = written.len() as u64 * OBJECT as u64;
    assert!(
        bytes <= quota,
        "{bytes} bytes written past a {quota}-byte quota"
    );
    assert!(bytes > quota / 2, "refused long before the quota: {bytes}");
    let refused = c.request("PUT", "/q/one-more", &vec![0; OBJECT]);
    assert_eq!(refused.status, 403, "{}", refused.text());

    // Deletes make room once the report shows them.
    for key in &written[..written.len() / 2] {
        c.request("DELETE", &format!("/q/{key}"), &[]).expect(204);
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while c
        .request("PUT", "/q/after-deletes", &vec![0; OBJECT])
        .status
        != 200
    {
        assert!(Instant::now() < deadline, "deletes never made room");
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
fn a_tenant_quota_counts_every_bucket_of_the_tenant() {
    let c = Cluster::start();
    let quota: u64 = 768 * 1024;
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "tq", "display_name": "tq", "enabled": true, "quota_bytes": quota}),
    )
    .expect_ok();
    for b in ["tq-a", "tq-b"] {
        c.json(
            "POST",
            "/_admin/buckets",
            json!({"name": b, "tenant": "tq"}),
        )
        .expect_ok();
    }
    await_quota_in_report(&c, "tq-a", quota);

    let a = fill(&c, "tq-a");
    let b = fill(&c, "tq-b");
    let bytes = (a.len() + b.len()) as u64 * OBJECT as u64;
    assert!(
        bytes <= quota,
        "{bytes} bytes written past a {quota}-byte tenant quota"
    );
    assert!(b.len() < 2, "the second bucket ignored what the first used");
}
