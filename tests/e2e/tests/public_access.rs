//! Public access: an unsigned request reaches only what a bucket policy
//! grants to everyone, and Block Public Access — on the bucket, its tenant
//! or the cluster — keeps such grants from being made or from working. New
//! buckets start blocked.

use objectio_e2e::{Cluster, Response};
use serde_json::{Value, json};

const BLOCK_NONE: &[u8] = b"<PublicAccessBlockConfiguration>\
    <BlockPublicAcls>false</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls>\
    <BlockPublicPolicy>false</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets>\
    </PublicAccessBlockConfiguration>";

fn public_read(bucket: &str) -> Vec<u8> {
    json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
        "Resource": format!("arn:aws:s3:::{bucket}/*"),
    }]})
    .to_string()
    .into_bytes()
}

fn anonymous(c: &Cluster, method: &str, path: &str) -> Response {
    c.fetch(method, &format!("{}{path}", c.endpoint), &[])
}

/// A bucket with an object, its block lifted and a public-read policy.
fn public_bucket(c: &Cluster, bucket: &str) {
    c.request("PUT", &format!("/{bucket}"), &[]).expect(200);
    c.request("PUT", &format!("/{bucket}/k"), b"public data")
        .expect(200);
    c.request("PUT", &format!("/{bucket}?publicAccessBlock"), BLOCK_NONE)
        .expect(200);
    c.request("PUT", &format!("/{bucket}?policy"), &public_read(bucket))
        .expect_ok();
}

#[test]
fn a_new_bucket_is_blocked_and_cannot_be_made_public() {
    let c = Cluster::start();
    c.request("PUT", "/blk", &[]).expect(200);
    c.request("PUT", "/blk/k", b"data").expect(200);

    let r = c.request("GET", "/blk?publicAccessBlock", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    for flag in [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    ] {
        assert!(
            r.text().contains(&format!("<{flag}>true</{flag}>")),
            "{}",
            r.text()
        );
    }

    let r = c.request("PUT", "/blk?policy", &public_read("blk"));
    assert_eq!(r.status, 403, "{}", r.text());
    // Nor through the admin API's bucket-policy endpoint.
    let r = c.request("PUT", "/_admin/buckets/blk/policy", &public_read("blk"));
    assert_eq!(r.status, 403, "{}", r.text());
    assert_eq!(anonymous(&c, "GET", "/blk/k").status, 403);

    // A policy pinned to a network isn't public, and is taken.
    let pinned = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::blk/*",
        "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
    }]});
    c.request("PUT", "/blk?policy", pinned.to_string().as_bytes())
        .expect_ok();
    let r = c.request("GET", "/blk?policyStatus", &[]);
    assert!(
        r.text().contains("<IsPublic>false</IsPublic>"),
        "{}",
        r.text()
    );
}

#[test]
fn a_public_policy_lets_anonymous_callers_do_what_it_grants_and_no_more() {
    let c = Cluster::start();
    public_bucket(&c, "pub");
    let r = c.request("GET", "/pub?policyStatus", &[]);
    assert!(
        r.text().contains("<IsPublic>true</IsPublic>"),
        "{}",
        r.text()
    );

    let r = anonymous(&c, "GET", "/pub/k");
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.bytes, b"public data");
    // Granted reading objects: not writing, deleting, listing, configuring.
    assert_eq!(
        c.fetch("PUT", &format!("{}/pub/new", c.endpoint), b"x")
            .status,
        403
    );
    assert_eq!(anonymous(&c, "DELETE", "/pub/k").status, 403);
    assert_eq!(anonymous(&c, "GET", "/pub").status, 403);
    assert_eq!(anonymous(&c, "GET", "/pub?policy").status, 403);
    assert_eq!(
        anonymous(&c, "DELETE", "/pub?publicAccessBlock").status,
        403
    );
    // Nor anything outside the bucket.
    assert_eq!(anonymous(&c, "GET", "/").status, 403);
    c.request("PUT", "/private", &[]).expect(200);
    c.request("PUT", "/private/k", b"secret").expect(200);
    assert_eq!(anonymous(&c, "GET", "/private/k").status, 403);
    assert_eq!(anonymous(&c, "GET", "/_admin/users").status, 401);

    // RestrictPublicBuckets on the bucket shuts the grant off; the owner
    // is unaffected.
    c.request(
        "PUT",
        "/pub?publicAccessBlock",
        b"<PublicAccessBlockConfiguration><RestrictPublicBuckets>true</RestrictPublicBuckets>\
          </PublicAccessBlockConfiguration>",
    )
    .expect(200);
    assert_eq!(anonymous(&c, "GET", "/pub/k").status, 403);
    assert_eq!(c.request("GET", "/pub/k", &[]).bytes, b"public data");

    // Without a block of its own, the bucket answers that it has none.
    c.request("DELETE", "/pub?publicAccessBlock", &[])
        .expect(204);
    let r = c.request("GET", "/pub?publicAccessBlock", &[]);
    assert_eq!(r.status, 404, "{}", r.text());
    assert!(
        r.text().contains("NoSuchPublicAccessBlockConfiguration"),
        "{}",
        r.text()
    );
    assert_eq!(anonymous(&c, "GET", "/pub/k").status, 200);
}

fn tenant_admin(c: &Cluster, tenant: &str) -> (String, String) {
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
    k.expect_ok();
    let k = k.json();
    (
        k["access_key_id"].as_str().unwrap().to_string(),
        k["secret_access_key"].as_str().unwrap().to_string(),
    )
}

fn as_user(
    c: &Cluster,
    (ak, sk): &(String, String),
    method: &str,
    path: &str,
    body: &[u8],
) -> Response {
    c.request_as(method, path, body, ak, sk)
}

/// A tenant admin blocks the tenant, the operator the cluster; a bucket
/// can't opt out of either.
#[test]
fn tenant_and_cluster_blocks_hold_for_every_bucket_beneath() {
    let c = Cluster::start();
    let acme = tenant_admin(&c, "acme");
    let globex = tenant_admin(&c, "globex");

    as_user(&c, &acme, "PUT", "/acme-pub", &[]).expect(200);
    as_user(&c, &acme, "PUT", "/acme-pub/k", b"acme").expect(200);
    as_user(&c, &acme, "PUT", "/acme-pub?publicAccessBlock", BLOCK_NONE).expect(200);
    as_user(
        &c,
        &acme,
        "PUT",
        "/acme-pub?policy",
        &public_read("acme-pub"),
    )
    .expect_ok();
    assert_eq!(anonymous(&c, "GET", "/acme-pub/k").status, 200);

    // The tenant's block.
    let restrict = json!({"RestrictPublicBuckets": true}).to_string();
    as_user(
        &c,
        &acme,
        "PUT",
        "/_admin/public-access-block",
        restrict.as_bytes(),
    )
    .expect(200);
    assert_eq!(anonymous(&c, "GET", "/acme-pub/k").status, 403);
    // Another tenant's admin can neither read nor lift it.
    let other = as_user(
        &c,
        &globex,
        "DELETE",
        "/_admin/public-access-block?tenant=acme",
        &[],
    );
    assert_eq!(other.status, 403, "{}", other.text());
    // Nor may a tenant admin change the cluster's default.
    let r = as_user(
        &c,
        &acme,
        "PUT",
        "/_admin/public-access-block",
        json!({"new_buckets_blocked": false}).to_string().as_bytes(),
    );
    assert_eq!(r.status, 400, "{}", r.text());
    as_user(&c, &acme, "DELETE", "/_admin/public-access-block", &[]).expect(204);
    assert_eq!(anonymous(&c, "GET", "/acme-pub/k").status, 200);

    // The cluster's block, which no tenant can lift.
    c.json(
        "PUT",
        "/_admin/public-access-block",
        json!({"BlockPublicPolicy": true, "RestrictPublicBuckets": true}),
    )
    .expect_ok();
    assert_eq!(anonymous(&c, "GET", "/acme-pub/k").status, 403);
    as_user(&c, &globex, "PUT", "/globex-pub", &[]).expect(200);
    as_user(
        &c,
        &globex,
        "PUT",
        "/globex-pub?publicAccessBlock",
        BLOCK_NONE,
    )
    .expect(200);
    let r = as_user(
        &c,
        &globex,
        "PUT",
        "/globex-pub?policy",
        &public_read("globex-pub"),
    );
    assert_eq!(r.status, 403, "{}", r.text());
    let view: Value = c.request("GET", "/_admin/public-access-block", &[]).json();
    assert_eq!(view["BlockPublicPolicy"], true);
    assert_eq!(view["new_buckets_blocked"], true);

    // The operator can let new buckets start unblocked.
    c.json(
        "PUT",
        "/_admin/public-access-block",
        json!({"new_buckets_blocked": false}),
    )
    .expect_ok();
    c.request("PUT", "/open", &[]).expect(200);
    assert_eq!(c.request("GET", "/open?publicAccessBlock", &[]).status, 404);
}

/// A bucket deleted and created again starts clean: nothing configured on
/// the old one carries over.
#[test]
fn a_recreated_bucket_inherits_nothing() {
    let c = Cluster::start();
    public_bucket(&c, "again");
    c.request(
        "PUT",
        "/again?lifecycle",
        b"<LifecycleConfiguration><Rule><ID>r</ID>\
        <Filter><Prefix></Prefix></Filter><Status>Enabled</Status>\
        <Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
    )
    .expect_ok();
    c.request("DELETE", "/again/k", &[]).expect(204);
    c.request("DELETE", "/again", &[]).expect(204);

    c.request("PUT", "/again", &[]).expect(200);
    assert_eq!(c.request("GET", "/again?policy", &[]).status, 404);
    assert_eq!(c.request("GET", "/again?lifecycle", &[]).status, 404);
    // Blocked, as a new bucket is, not open as the old one was.
    let r = c.request("GET", "/again?publicAccessBlock", &[]);
    assert!(
        r.text().contains("<RestrictPublicBuckets>true"),
        "{}",
        r.text()
    );
    c.request("PUT", "/again/k", b"new").expect(200);
    assert_eq!(anonymous(&c, "GET", "/again/k").status, 403);
}
