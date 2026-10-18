//! The admin API behaves as a client expects: an update changes what it
//! names and keeps the rest, statuses read the same everywhere, what is
//! read can be written back, and a revocation holds at once on the gateway
//! that made it.

use objectio_e2e::{Cluster, Response};
use serde_json::{Value, json};

fn tenant_admin(c: &Cluster, tenant: &str) -> (String, String, String) {
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": tenant, "display_name": tenant, "enabled": true, "quota_buckets": 7}),
    )
    .expect_ok();
    let user = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": format!("{tenant}-admin"), "tenant": tenant}),
    );
    let id = user.json()["user_id"].as_str().unwrap().to_string();
    c.json(
        "POST",
        &format!("/_admin/tenants/{tenant}/admins"),
        json!({"user_id": id}),
    )
    .expect_ok();
    let k = c.json(
        "POST",
        &format!("/_admin/users/{id}/access-keys"),
        json!({}),
    );
    let k = k.json();
    (
        id,
        k["access_key_id"].as_str().unwrap().to_string(),
        k["secret_access_key"].as_str().unwrap().to_string(),
    )
}

fn as_user(c: &Cluster, ak: &str, sk: &str, method: &str, path: &str, body: &Value) -> Response {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    c.request_as(method, path, &bytes, ak, sk)
}

#[test]
fn an_update_changes_only_what_it_names() {
    let c = Cluster::start();
    let (admin_id, _, _) = tenant_admin(&c, "acme");
    let before = c.request("GET", "/_admin/tenants/acme", &[]).json();
    assert!(before["created_at"].as_u64().unwrap() > 0);

    let r = c.json(
        "PUT",
        "/_admin/tenants/acme",
        json!({"display_name": "Acme Corp"}),
    );
    r.expect_ok();
    let after = c.request("GET", "/_admin/tenants/acme", &[]).json();
    assert_eq!(after["display_name"], "Acme Corp");
    assert_eq!(after["admin_users"], json!([admin_id]), "{after}");
    assert_eq!(after["quota_buckets"], 7);
    assert_eq!(after["created_at"], before["created_at"]);
}

#[test]
fn statuses_read_the_same_in_lists_and_a_tenant_admin_can_reactivate_its_keys() {
    let c = Cluster::start();
    let (_, ak, sk) = tenant_admin(&c, "acme");
    let u = as_user(
        &c,
        &ak,
        &sk,
        "POST",
        "/_admin/users",
        &json!({"display_name": "app"}),
    );
    let uid = u.json()["user_id"].as_str().unwrap().to_string();
    let k = as_user(
        &c,
        &ak,
        &sk,
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        &json!({}),
    );
    let (key, secret) = (
        k.json()["access_key_id"].as_str().unwrap().to_string(),
        k.json()["secret_access_key"].as_str().unwrap().to_string(),
    );
    c.request_as("GET", "/", &[], &key, &secret).expect(200);

    // Deactivated: refused here at once, not after the cache expires.
    as_user(
        &c,
        &ak,
        &sk,
        "PUT",
        &format!("/_admin/access-keys/{key}"),
        &json!({"status": "inactive"}),
    )
    .expect(200);
    assert_eq!(c.request_as("GET", "/", &[], &key, &secret).status, 403);
    let keys = as_user(
        &c,
        &ak,
        &sk,
        "GET",
        &format!("/_admin/users/{uid}/access-keys"),
        &Value::Null,
    )
    .json();
    assert!(keys.to_string().contains("\"inactive\""), "{keys}");

    // The tenant's admin can turn it back on (it used to take the operator).
    let r = as_user(
        &c,
        &ak,
        &sk,
        "PUT",
        &format!("/_admin/access-keys/{key}"),
        &json!({"status": "active"}),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    c.request_as("GET", "/", &[], &key, &secret).expect(200);

    // Suspending the user: also at once.
    as_user(
        &c,
        &ak,
        &sk,
        "PUT",
        &format!("/_admin/users/{uid}"),
        &json!({"status": "suspended"}),
    )
    .expect(200);
    assert_eq!(c.request_as("GET", "/", &[], &key, &secret).status, 403);
    let users = as_user(&c, &ak, &sk, "GET", "/_admin/users", &Value::Null).json();
    assert!(users.to_string().contains("\"suspended\""), "{users}");
    // A suspended user's key is still its tenant's to delete.
    as_user(
        &c,
        &ak,
        &sk,
        "DELETE",
        &format!("/_admin/access-keys/{key}"),
        &Value::Null,
    )
    .expect(204);
}

#[test]
fn an_empty_tenant_means_the_callers_own() {
    let c = Cluster::start();
    let (_, ak, sk) = tenant_admin(&c, "acme");
    let r = as_user(
        &c,
        &ak,
        &sk,
        "GET",
        "/_admin/policies?tenant=",
        &Value::Null,
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let r = as_user(
        &c,
        &ak,
        &sk,
        "POST",
        "/_admin/groups",
        &json!({"group_name": "eng", "tenant": ""}),
    );
    assert_eq!(r.status, 201, "{}", r.text());
}

#[test]
fn a_provider_read_and_written_back_keeps_its_secret() {
    let c = Cluster::start();
    let path = "/_admin/config/identity/openid/corp";
    c.json(
        "PUT",
        path,
        json!({"issuer_url": "https://idp.example", "client_id": "objectio", "client_secret": "s3cret"}),
    )
    .expect_ok();
    let read = c.request("GET", path, &[]).json();
    assert_eq!(read["value"]["client_secret"], "********");
    let mut value = read["value"].clone();
    value["client_id"] = json!("objectio-2");
    c.json("PUT", path, value).expect_ok();
    let stored = c.request("GET", path, &[]).json();
    assert_eq!(stored["value"]["client_id"], "objectio-2");
    assert_eq!(stored["value"]["client_secret"], "********");
}
