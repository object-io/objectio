//! A bucket is put in a pool when it's created, and stays there: chosen
//! explicitly (`x-objectio-pool`, or `pool` on the admin API), or the
//! tenant's default pool. A tenant may only use the pools it's allowed, and
//! a pool can't be deleted while anything uses it.

use objectio_e2e::{Cluster, Response};
use serde_json::{Value, json};

fn pool(c: &Cluster, name: &str) {
    let r = c.json(
        "POST",
        "/_admin/pools",
        json!({"name": name, "ec_type": 2, "replication_count": 3, "enabled": true}),
    );
    assert!(r.status < 300, "create pool {name}: {}", r.text());
}

fn bucket_pool(c: &Cluster, bucket: &str) -> String {
    let all: Value = c.request("GET", "/_admin/buckets", &[]).json();
    let found = all["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == bucket)
        .cloned();
    let Some(b) = found else {
        panic!("no bucket {bucket}: {all}");
    };
    b["pool"].as_str().unwrap_or_default().to_string()
}

fn create_in(c: &Cluster, keys: Option<(&str, &str)>, bucket: &str, pool: &str) -> Response {
    let headers = [("x-objectio-pool", pool)];
    let headers: &[(&str, &str)] = if pool.is_empty() { &[] } else { &headers };
    match keys {
        None => c.request_with_headers("PUT", &format!("/{bucket}"), &[], headers),
        Some((ak, sk)) => {
            c.request_as_with_headers("PUT", &format!("/{bucket}"), &[], ak, sk, headers)
        }
    }
}

#[test]
fn a_bucket_lives_in_the_pool_it_was_created_in() {
    let c = Cluster::start();
    pool(&c, "rep3");
    create_in(&c, None, "in-pool", "rep3").expect(200);
    create_in(&c, None, "no-pool", "").expect(200);
    assert_eq!(bucket_pool(&c, "in-pool"), "rep3");
    assert_eq!(bucket_pool(&c, "no-pool"), "");

    // Its objects are written and read through the pool's placement.
    let body = vec![7u8; 300_000];
    c.request("PUT", "/in-pool/k", &body).expect(200);
    assert_eq!(c.request("GET", "/in-pool/k", &[]).bytes, body);

    // A pool that doesn't exist is refused, and no bucket is made.
    let r = create_in(&c, None, "nowhere", "missing");
    assert_eq!(r.status, 400, "{}", r.text());
    assert_eq!(c.request("HEAD", "/nowhere", &[]).status, 404);

    // A pool in use can't be deleted.
    let r = c.request("DELETE", "/_admin/pools/rep3", &[]);
    assert_eq!(r.status, 400, "{}", r.text());
    assert!(r.text().contains("in-pool"), "{}", r.text());
    c.request("DELETE", "/in-pool/k", &[]).expect(204);
    c.request("DELETE", "/in-pool", &[]).expect(204);
    let r = c.request("DELETE", "/_admin/pools/rep3", &[]);
    assert!(r.status < 300, "{}", r.text());
}

#[test]
fn a_tenant_uses_its_default_pool_and_only_the_pools_it_is_allowed() {
    let c = Cluster::start();
    pool(&c, "gold");
    pool(&c, "silver");
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "acme", "display_name": "acme", "enabled": true}),
    )
    .expect_ok();
    let u = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "a", "tenant": "acme"}),
    );
    let uid = u.json()["user_id"].as_str().unwrap().to_string();
    c.json(
        "POST",
        "/_admin/tenants/acme/admins",
        json!({"user_id": uid}),
    )
    .expect_ok();
    let k = c.json(
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        json!({}),
    );
    let (ak, sk) = (
        k.json()["access_key_id"].as_str().unwrap().to_string(),
        k.json()["secret_access_key"].as_str().unwrap().to_string(),
    );
    let keys = Some((ak.as_str(), sk.as_str()));

    // Not allowed any pool yet.
    let r = create_in(&c, keys, "acme-gold", "gold");
    assert_eq!(r.status, 403, "{}", r.text());

    // Allowed silver, defaulting to gold.
    c.json(
        "PUT",
        "/_admin/tenants/acme",
        json!({"default_pool": "gold", "allowed_pools": ["silver"]}),
    )
    .expect_ok();
    create_in(&c, keys, "acme-default", "").expect(200);
    assert_eq!(bucket_pool(&c, "acme-default"), "gold");
    create_in(&c, keys, "acme-silver", "silver").expect(200);
    assert_eq!(bucket_pool(&c, "acme-silver"), "silver");
    // A pool it wasn't given: refused even though it exists.
    pool(&c, "platinum");
    assert_eq!(create_in(&c, keys, "acme-plat", "platinum").status, 403);

    // A tenant that refers to a pool keeps it from being deleted.
    c.request("DELETE", "/acme-default", &[]).expect(204);
    let r = c.request("DELETE", "/_admin/pools/gold", &[]);
    assert_eq!(r.status, 400, "{}", r.text());
    assert!(r.text().contains("acme"), "{}", r.text());
}
