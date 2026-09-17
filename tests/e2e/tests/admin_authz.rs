//! Who may call what on `/_admin/*`.
//!
//! This surface drifted three separate times: `GET /_admin/users` and
//! `GET /_admin/buckets` were gated on the root key while their siblings
//! accepted a tenant admin, and credential scope was not applied here at all,
//! so a key confined to one bucket could mint itself an unscoped one.
//!
//! Each of those is a gate disagreeing with the gate next to it, which is
//! exactly what a per-handler unit test cannot see.

use objectio_e2e::Cluster;
use serde_json::json;

/// Create a tenant with an admin user and return
/// `(user_id, access_key, secret_key)` for that user.
fn provision_tenant_admin(c: &Cluster, tenant: &str) -> (String, String, String) {
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": tenant, "display_name": tenant, "enabled": true}),
    )
    .expect_ok();

    let user = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": format!("{tenant}-admin"), "tenant": tenant}),
    );
    user.expect_ok();
    let user_id = user.json()["user_id"]
        .as_str()
        .expect("user_id")
        .to_string();

    c.json(
        "POST",
        &format!("/_admin/tenants/{tenant}/admins"),
        json!({"user_id": user_id}),
    )
    .expect_ok();

    let key = c.json(
        "POST",
        &format!("/_admin/users/{user_id}/access-keys"),
        json!({}),
    );
    key.expect_ok();
    let k = key.json();
    (
        user_id,
        k["access_key_id"].as_str().unwrap().to_string(),
        k["secret_access_key"].as_str().unwrap().to_string(),
    )
}

/// A tenant admin can list the users it creates.
///
/// It could create a user and mint its keys but never list them back: the
/// handler already filtered by tenant, the gate in front admitted only root.
/// A provisioner that cannot list what it made cannot reconcile.
#[test]
fn a_tenant_admin_can_list_its_own_users() {
    let c = Cluster::start();
    let (_, ak, sk) = provision_tenant_admin(&c, "acme");

    let listed = c.request_as("GET", "/_admin/users", &[], &ak, &sk);
    listed.expect(200);

    let v = listed.json();
    let users = v["users"].as_array().expect("users");
    assert!(!users.is_empty(), "tenant admin saw no users at all");
    for u in users {
        assert_eq!(
            u["tenant"], "acme",
            "a tenant admin was shown another tenant's user: {u}"
        );
    }
}

/// Same story for buckets.
#[test]
fn a_tenant_admin_can_list_its_own_buckets() {
    let c = Cluster::start();
    let (_, ak, sk) = provision_tenant_admin(&c, "globex");

    c.request_as(
        "POST",
        "/_admin/buckets",
        json!({"name": "globex-data"}).to_string().as_bytes(),
        &ak,
        &sk,
    )
    .expect_ok();

    let listed = c.request_as("GET", "/_admin/buckets", &[], &ak, &sk);
    listed.expect(200);
    let v = listed.json();
    let names: Vec<&str> = v["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .filter_map(|b| b["name"].as_str())
        .collect();
    assert!(
        names.contains(&"globex-data"),
        "tenant admin could not see the bucket it just created: {names:?}"
    );
}

/// A tenant admin cannot reach into another tenant.
#[test]
fn a_tenant_admin_is_confined_to_its_tenant() {
    let c = Cluster::start();
    let (_, ak, sk) = provision_tenant_admin(&c, "one");
    provision_tenant_admin(&c, "two");

    let cross = c.request_as(
        "POST",
        "/_admin/buckets",
        json!({"name": "stolen", "tenant": "two"})
            .to_string()
            .as_bytes(),
        &ak,
        &sk,
    );
    assert_eq!(
        cross.status,
        403,
        "tenant 'one' created a bucket in tenant 'two': {}",
        cross.text()
    );
}

/// A bucket-scoped key is refused on the management API.
///
/// Scope was only applied to the data path, so a scoped key kept every admin
/// right its user had — and minting an access key is an admin right. A
/// read-only key confined to one bucket could therefore mint itself an
/// unscoped read-write one and walk out of its own scope. Reproduced before
/// the fix; this pins it shut.
#[test]
fn a_scoped_key_cannot_use_the_admin_api() {
    let c = Cluster::start();
    let (user_id, ak, sk) = provision_tenant_admin(&c, "scoped");

    c.request_as(
        "POST",
        "/_admin/buckets",
        json!({"name": "ws-1"}).to_string().as_bytes(),
        &ak,
        &sk,
    )
    .expect_ok();

    let scoped = c.request_as(
        "POST",
        &format!("/_admin/users/{user_id}/access-keys"),
        json!({"scope": "s3://ws-1/", "operation": "R"})
            .to_string()
            .as_bytes(),
        &ak,
        &sk,
    );
    scoped.expect_ok();
    let v = scoped.json();
    let (sak, ssk) = (
        v["access_key_id"].as_str().unwrap().to_string(),
        v["secret_access_key"].as_str().unwrap().to_string(),
    );

    // The escalation: mint yourself a wider key.
    let escalate = c.request_as(
        "POST",
        &format!("/_admin/users/{user_id}/access-keys"),
        json!({}).to_string().as_bytes(),
        &sak,
        &ssk,
    );
    assert_eq!(
        escalate.status,
        403,
        "a scoped key minted itself a new credential: {}",
        escalate.text()
    );

    for path in ["/_admin/users", "/_admin/buckets", "/_admin/nodes"] {
        let r = c.request_as("GET", path, &[], &sak, &ssk);
        assert_eq!(r.status, 403, "a scoped key reached {path}: {}", r.text());
    }
}

/// A scoped key still works on its own bucket, and nowhere else.
///
/// The counterpart to the test above: refusing everything would also pass it.
#[test]
fn a_scoped_key_reaches_only_its_own_bucket() {
    let c = Cluster::start();
    let (user_id, ak, sk) = provision_tenant_admin(&c, "confined");

    for bucket in ["mine", "theirs"] {
        c.request_as(
            "POST",
            "/_admin/buckets",
            json!({ "name": bucket }).to_string().as_bytes(),
            &ak,
            &sk,
        )
        .expect_ok();
    }

    let key = c.request_as(
        "POST",
        &format!("/_admin/users/{user_id}/access-keys"),
        json!({"scope": "s3://mine/", "operation": "RW"})
            .to_string()
            .as_bytes(),
        &ak,
        &sk,
    );
    key.expect_ok();
    let v = key.json();
    let (sak, ssk) = (
        v["access_key_id"].as_str().unwrap().to_string(),
        v["secret_access_key"].as_str().unwrap().to_string(),
    );

    c.request_as("PUT", "/mine/ok.txt", b"hello", &sak, &ssk)
        .expect(200);
    let got = c.request_as("GET", "/mine/ok.txt", &[], &sak, &ssk);
    got.expect(200);
    assert_eq!(got.text(), "hello");

    let blocked = c.request_as("PUT", "/theirs/no.txt", b"nope", &sak, &ssk);
    assert_eq!(
        blocked.status,
        403,
        "a key scoped to s3://mine/ wrote to another bucket: {}",
        blocked.text()
    );
}

/// A username is reusable once deleted.
///
/// `DeleteUser` is a soft delete and the uniqueness check scanned deleted
/// records too, so a name was held forever — invisibly, because listings hide
/// deleted users. A provisioner cycling per-workspace users would have run
/// out of names with no way to see why.
#[test]
fn a_deleted_username_can_be_reused() {
    let c = Cluster::start();
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "recycle", "enabled": true}),
    )
    .expect_ok();

    let first = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "reused", "tenant": "recycle"}),
    );
    first.expect_ok();
    let id = first.json()["user_id"].as_str().unwrap().to_string();

    c.request("DELETE", &format!("/_admin/users/{id}"), &[])
        .expect(204);

    let again = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "reused", "tenant": "recycle"}),
    );
    assert!(
        (200..300).contains(&again.status),
        "the name stayed taken after the user was deleted: {}",
        again.text()
    );
}

/// A duplicate name is a conflict, with a body that does not leak internals.
///
/// It used to be a 500 carrying tonic's Display for Status — which embeds the
/// whole `MetadataMap`, so response headers and internal detail reached the
/// caller.
#[test]
fn a_duplicate_username_is_a_clean_conflict() {
    let c = Cluster::start();
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "dup", "enabled": true}),
    )
    .expect_ok();
    c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "taken", "tenant": "dup"}),
    )
    .expect_ok();

    let again = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "taken", "tenant": "dup"}),
    );
    assert_eq!(again.status, 409, "expected 409, got {}", again.status);
    let body = again.text();
    assert!(
        !body.contains("MetadataMap") && !body.contains("tonic"),
        "the error body leaked gRPC internals: {body}"
    );
}

/// Anonymous callers get nothing.
#[test]
fn the_admin_api_refuses_anonymous_callers() {
    let c = Cluster::start();
    let client = reqwest::blocking::Client::new();
    for path in ["/_admin/users", "/_admin/buckets", "/_admin/nodes"] {
        let r = client
            .get(format!("{}{path}", c.endpoint))
            .send()
            .expect("request");
        assert_eq!(
            r.status().as_u16(),
            401,
            "{path} answered an unauthenticated caller"
        );
    }
}
