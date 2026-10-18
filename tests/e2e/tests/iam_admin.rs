//! Identity administration per tenant: a tenant's admins manage the
//! tenant's policies, groups and roles, attach the operator's shared
//! policies, and can neither see nor touch another tenant's. Suspending a
//! user or deactivating a key cuts it off without deleting anything.

use objectio_e2e::{Cluster, Response};
use serde_json::{Value, json};

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

fn as_admin(c: &Cluster, ak: &str, sk: &str, method: &str, path: &str, body: &Value) -> Response {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    c.request_as(method, path, &bytes, ak, sk)
}

/// A user with a key in `tenant`: `(user_id, access_key, secret_key)`.
fn tenant_user(c: &Cluster, ak: &str, sk: &str, name: &str) -> (String, String, String) {
    let u = as_admin(
        c,
        ak,
        sk,
        "POST",
        "/_admin/users",
        &json!({"display_name": name}),
    );
    u.expect_ok();
    let id = u.json()["user_id"].as_str().unwrap().to_string();
    let k = as_admin(
        c,
        ak,
        sk,
        "POST",
        &format!("/_admin/users/{id}/access-keys"),
        &json!({}),
    );
    k.expect_ok();
    let k = k.json();
    (
        id,
        k["access_key_id"].as_str().unwrap().to_string(),
        k["secret_access_key"].as_str().unwrap().to_string(),
    )
}

const READ_ONLY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
    "Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::*","arn:aws:s3:::*/*"]}]}"#;

#[test]
fn a_tenant_admin_manages_its_tenants_policies() {
    let c = Cluster::start();
    let (_, ak, sk) = provision_tenant_admin(&c, "acme");
    let (_, bk, bs) = provision_tenant_admin(&c, "globex");
    let policy: Value = serde_json::from_str(READ_ONLY).unwrap();

    // The same name in two tenants: two policies.
    for (k, s) in [(&ak, &sk), (&bk, &bs)] {
        let r = as_admin(
            &c,
            k,
            s,
            "POST",
            "/_admin/policies",
            &json!({"name": "auditors", "policy": policy}),
        );
        assert_eq!(r.status, 201, "{}", r.text());
    }
    let listed = as_admin(&c, &ak, &sk, "GET", "/_admin/policies", &Value::Null).json();
    let names: Vec<(String, String)> = listed["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap().into(),
                p["tenant"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(
        names.contains(&("auditors".into(), "acme".into())),
        "{names:?}"
    );
    assert!(
        names.contains(&("readonly".into(), String::new())),
        "the shared catalogue: {names:?}"
    );
    assert!(
        !names.iter().any(|(_, t)| t == "globex"),
        "saw another tenant's: {names:?}"
    );
    assert!(
        !names.iter().any(|(n, _)| n == "consoleAdmin"),
        "an unshared system policy: {names:?}"
    );

    // Edited in place; another tenant's can't be reached.
    let r = as_admin(
        &c,
        &ak,
        &sk,
        "PUT",
        "/_admin/policies/auditors",
        &json!({"policy": policy}),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let r = as_admin(
        &c,
        &ak,
        &sk,
        "GET",
        "/_admin/policies/auditors?tenant=globex",
        &Value::Null,
    );
    assert_eq!(r.status, 403, "{}", r.text());
}

#[test]
fn a_tenant_admin_manages_its_tenants_groups_and_attachments() {
    let c = Cluster::start();
    let (_, ak, sk) = provision_tenant_admin(&c, "acme");
    let (_, bk, bs) = provision_tenant_admin(&c, "globex");
    let policy: Value = serde_json::from_str(READ_ONLY).unwrap();
    as_admin(
        &c,
        &ak,
        &sk,
        "POST",
        "/_admin/policies",
        &json!({"name": "auditors", "policy": policy}),
    )
    .expect(201);
    // Groups and attachment, inside the tenant.
    let (uid, _, _) = tenant_user(&c, &ak, &sk, "carol");
    let g = as_admin(
        &c,
        &ak,
        &sk,
        "POST",
        "/_admin/groups",
        &json!({"group_name": "audit"}),
    );
    assert_eq!(g.status, 201, "{}", g.text());
    let gid = g.json()["group_id"].as_str().unwrap().to_string();
    as_admin(
        &c,
        &ak,
        &sk,
        "POST",
        &format!("/_admin/groups/{gid}/members"),
        &json!({"user_id": uid}),
    )
    .expect(200);
    for name in ["auditors", "readonly"] {
        let r = as_admin(
            &c,
            &ak,
            &sk,
            "POST",
            "/_admin/policies/attach",
            &json!({"policy_name": name, "group_id": gid}),
        );
        assert_eq!(r.status, 200, "attach {name}: {}", r.text());
    }
    let r = as_admin(
        &c,
        &ak,
        &sk,
        "POST",
        "/_admin/policies/attach",
        &json!({"policy_name": "consoleAdmin", "user_id": uid}),
    );
    assert_eq!(
        r.status,
        403,
        "a tenant admin attached consoleAdmin: {}",
        r.text()
    );
    let got = as_admin(
        &c,
        &ak,
        &sk,
        "GET",
        &format!("/_admin/groups/{gid}"),
        &Value::Null,
    );
    assert_eq!(got.json()["member_user_ids"], json!([uid]));

    // Another tenant's admin sees none of it.
    assert_eq!(
        as_admin(
            &c,
            &bk,
            &bs,
            "GET",
            &format!("/_admin/groups/{gid}"),
            &Value::Null
        )
        .status,
        403
    );
    let r = as_admin(
        &c,
        &bk,
        &bs,
        "POST",
        &format!("/_admin/groups/{gid}/members"),
        &json!({"user_id": uid}),
    );
    assert_eq!(r.status, 403);
    let theirs = as_admin(&c, &bk, &bs, "GET", "/_admin/groups", &Value::Null).json();
    assert!(theirs["groups"].as_array().unwrap().is_empty(), "{theirs}");
}

#[test]
fn a_tenant_admin_manages_its_tenants_roles() {
    let c = Cluster::start();
    let (_, ak, sk) = provision_tenant_admin(&c, "acme");
    let (_, bk, bs) = provision_tenant_admin(&c, "globex");
    let policy: Value = serde_json::from_str(READ_ONLY).unwrap();
    as_admin(
        &c,
        &ak,
        &sk,
        "POST",
        "/_admin/policies",
        &json!({"name": "auditors", "policy": policy}),
    )
    .expect(201);
    // Roles.
    let trust = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
        "Action":"sts:AssumeRoleWithWebIdentity","Resource":"*"}]});
    let r = as_admin(
        &c,
        &ak,
        &sk,
        "POST",
        "/_admin/roles",
        &json!({"name": "ci", "trust_policy": trust}),
    );
    assert_eq!(r.status, 201, "{}", r.text());
    assert_eq!(r.json()["arn"], "arn:obio:iam::acme:role/ci");
    as_admin(
        &c,
        &ak,
        &sk,
        "POST",
        "/_admin/policies/attach",
        &json!({"policy_name": "auditors", "role_name": "ci"}),
    )
    .expect(200);
    let role = as_admin(&c, &ak, &sk, "GET", "/_admin/roles/ci", &Value::Null).json();
    assert_eq!(role["attached_policies"], json!(["auditors"]));
    assert_eq!(
        as_admin(&c, &bk, &bs, "GET", "/_admin/roles/ci", &Value::Null).status,
        404
    );
    as_admin(&c, &ak, &sk, "DELETE", "/_admin/roles/ci", &Value::Null).expect(204);
}

#[test]
fn suspending_a_user_or_deactivating_a_key_cuts_it_off() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "b"}))
        .expect_ok();
    let (ak, sk) = (c.access_key.clone(), c.secret_key.clone());
    let (uid, uk, us) = tenant_user(&c, &ak, &sk, "dave");
    c.json(
        "POST",
        "/_admin/policies/attach",
        json!({"policy_name": "readwrite", "user_id": uid}),
    )
    .expect_ok();
    assert_eq!(c.request_as("GET", "/b", &[], &uk, &us).status, 200);

    as_admin(
        &c,
        &ak,
        &sk,
        "PUT",
        &format!("/_admin/users/{uid}"),
        &json!({"status": "suspended"}),
    )
    .expect(200);
    // Within the gateways' credential cache lifetime.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while c.request_as("GET", "/b", &[], &uk, &us).status == 200 {
        assert!(
            std::time::Instant::now() < deadline,
            "a suspended user still works"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    as_admin(
        &c,
        &ak,
        &sk,
        "PUT",
        &format!("/_admin/users/{uid}"),
        &json!({"status": "active"}),
    )
    .expect(200);
    as_admin(
        &c,
        &ak,
        &sk,
        "PUT",
        &format!("/_admin/access-keys/{uk}"),
        &json!({"status": "inactive"}),
    )
    .expect(200);
    std::thread::sleep(std::time::Duration::from_secs(16));
    assert_ne!(
        c.request_as("GET", "/b", &[], &uk, &us).status,
        200,
        "an inactive key still works"
    );
    as_admin(
        &c,
        &ak,
        &sk,
        "PUT",
        &format!("/_admin/access-keys/{uk}"),
        &json!({"status": "active"}),
    )
    .expect(200);
    assert_eq!(
        c.request_as("GET", "/b", &[], &uk, &us).status,
        200,
        "reactivated"
    );
}
