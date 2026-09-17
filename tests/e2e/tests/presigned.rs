//! Presigned URLs — `SigV4` credentials in the query string.
//!
//! The gateway could already generate these (Delta Sharing hands them to
//! recipients) but had no path to verify one, so every presigned URL it issued
//! was refused by the server that issued it, with `AccessDenied: missing
//! authorization header`. Any client that is handed a URL rather than making a
//! request — git-lfs, a browser, `curl -O` — has no way to send an
//! `Authorization` header, so without this there is no way for bytes to move
//! except through something that can sign every one of them.
//!
//! The harness signs these itself rather than calling the gateway's own
//! presigning code, so these check the server against an independent reading
//! of the spec rather than against itself.

use objectio_e2e::Cluster;
use serde_json::json;

fn setup(bucket: &str) -> Cluster {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({ "name": bucket }))
        .expect_ok();
    c
}

/// A client holding nothing but the URL can read the object.
#[test]
fn a_presigned_get_serves_the_object_to_an_unauthenticated_client() {
    let c = setup("presign-get");
    c.request("PUT", "/presign-get/weights.bin", b"model-weights")
        .expect(200);

    let url = c.presign("GET", "/presign-get/weights.bin", 3600);
    let got = c.fetch("GET", &url, &[]);
    got.expect(200);
    assert_eq!(got.text(), "model-weights");
}

/// And can write one. This is the half git-lfs needs to upload.
#[test]
fn a_presigned_put_stores_the_body() {
    let c = setup("presign-put");

    let url = c.presign("PUT", "/presign-put/uploaded.bin", 3600);
    c.fetch("PUT", &url, b"pushed-by-url").expect(200);

    // Read it back over the normal signed path — the object is a real object.
    let got = c.request("GET", "/presign-put/uploaded.bin", &[]);
    got.expect(200);
    assert_eq!(got.text(), "pushed-by-url");
}

/// A key that needs percent-encoding survives presigning.
///
/// The URL is signed and routed from the same spelling; sign one and send
/// another and it fails as `SignatureDoesNotMatch`, which reads like bad
/// credentials rather than a key with a space in it.
#[test]
fn a_presigned_url_for_an_awkward_key_still_verifies() {
    let c = setup("presign-keys");
    for key in [
        "a b.bin",
        "nested/deep/f.bin",
        "caf\u{e9}.bin",
        "plus+plus.bin",
    ] {
        let path = format!("/presign-keys/{key}");
        c.request("PUT", &path, key.as_bytes()).expect(200);
        let url = c.presign("GET", &path, 3600);
        let got = c.fetch("GET", &url, &[]);
        assert_eq!(
            got.status,
            200,
            "presigned GET for {key:?} failed: {}",
            got.text()
        );
        assert_eq!(got.text(), key);
    }
}

/// The expiry window is enforced.
#[test]
fn an_expired_presigned_url_is_refused() {
    let c = setup("presign-expiry");
    c.request("PUT", "/presign-expiry/x.bin", b"data")
        .expect(200);

    // Signed two hours ago with a one-hour life.
    let url = c.presign_at("GET", "/presign-expiry/x.bin", 3600, 7200);
    let got = c.fetch("GET", &url, &[]);
    assert_eq!(
        got.status,
        403,
        "an expired presigned URL was honoured: {}",
        got.text()
    );
    assert!(
        got.text().contains("ExpiredToken"),
        "an expired link should say so, so a client knows to ask for a new one \
         rather than to report a permissions problem: {}",
        got.text()
    );
}

/// A link outlives the 15-minute skew window that header-signed requests get.
///
/// The whole point of a presigned URL is to be usable later; applying the
/// header path's clock-skew rule to it would cap every link at 15 minutes.
#[test]
fn a_presigned_url_survives_longer_than_the_header_skew_window() {
    let c = setup("presign-long");
    c.request("PUT", "/presign-long/x.bin", b"data").expect(200);

    // Signed an hour ago, valid for six.
    let url = c.presign_at("GET", "/presign-long/x.bin", 21_600, 3600);
    c.fetch("GET", &url, &[]).expect(200);
}

/// Tampering with any signed part of the URL invalidates it.
#[test]
fn a_tampered_presigned_url_is_refused() {
    let c = setup("presign-tamper");
    c.request("PUT", "/presign-tamper/mine.bin", b"mine")
        .expect(200);
    c.request("PUT", "/presign-tamper/theirs.bin", b"theirs")
        .expect(200);

    let url = c.presign("GET", "/presign-tamper/mine.bin", 3600);

    // A different object, same signature.
    let swapped = url.replace("mine.bin", "theirs.bin");
    let got = c.fetch("GET", &swapped, &[]);
    assert_eq!(
        got.status,
        403,
        "a presigned URL was reused for another object: {}",
        got.text()
    );

    // A flipped signature.
    let sig_start = url.rfind("X-Amz-Signature=").expect("signature") + 16;
    let mut forged = url.clone();
    let c0 = if forged.as_bytes()[sig_start] == b'a' {
        'b'
    } else {
        'a'
    };
    forged.replace_range(sig_start..=sig_start, &c0.to_string());
    assert_eq!(
        c.fetch("GET", &forged, &[]).status,
        403,
        "a forged signature was accepted"
    );

    // A longer life than was signed for.
    let extended = url.replace("X-Amz-Expires=3600", "X-Amz-Expires=604800");
    assert_eq!(
        c.fetch("GET", &extended, &[]).status,
        403,
        "X-Amz-Expires was not covered by the signature"
    );
}

/// A presigned URL cannot escape the scope of the key that signed it.
///
/// It is the same credential either way, so everything downstream — bucket
/// policy, credential scope, tenancy — has to apply exactly as it does to a
/// header-signed request. A presigned URL that skipped scope would be a way to
/// launder a confined key into an unconfined request.
#[test]
fn a_presigned_url_cannot_leave_its_keys_scope() {
    let c = Cluster::start();
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "ps", "enabled": true}),
    )
    .expect_ok();
    let user = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "ps-admin", "tenant": "ps"}),
    );
    user.expect_ok();
    let uid = user.json()["user_id"].as_str().unwrap().to_string();
    c.json("POST", "/_admin/tenants/ps/admins", json!({"user_id": uid}))
        .expect_ok();
    let admin_key = c.json(
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        json!({}),
    );
    admin_key.expect_ok();
    let ak = admin_key.json();
    let (aak, ask) = (
        ak["access_key_id"].as_str().unwrap().to_string(),
        ak["secret_access_key"].as_str().unwrap().to_string(),
    );

    for bucket in ["allowed", "forbidden"] {
        c.request_as(
            "POST",
            "/_admin/buckets",
            json!({ "name": bucket }).to_string().as_bytes(),
            &aak,
            &ask,
        )
        .expect_ok();
    }
    c.request_as("PUT", "/allowed/ok.bin", b"ok", &aak, &ask)
        .expect(200);
    c.request_as("PUT", "/forbidden/no.bin", b"no", &aak, &ask)
        .expect(200);

    let scoped = c.request_as(
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        json!({"scope": "s3://allowed/", "operation": "R"})
            .to_string()
            .as_bytes(),
        &aak,
        &ask,
    );
    scoped.expect_ok();
    let v = scoped.json();
    let (sak, ssk) = (
        v["access_key_id"].as_str().unwrap().to_string(),
        v["secret_access_key"].as_str().unwrap().to_string(),
    );

    // Inside its scope the link works — so the refusal below is not a refusal
    // of everything.
    let ok = c.presign_as("GET", "/allowed/ok.bin", 3600, &sak, &ssk);
    c.fetch("GET", &ok, &[]).expect(200);

    // Outside it, the URL is well-formed and correctly signed and must still
    // be refused.
    let out = c.presign_as("GET", "/forbidden/no.bin", 3600, &sak, &ssk);
    let got = c.fetch("GET", &out, &[]);
    assert_eq!(
        got.status,
        403,
        "a bucket-scoped key presigned its way out of its scope: {}",
        got.text()
    );

    // And a read-only key cannot presign a write.
    let write = c.presign_as("PUT", "/allowed/new.bin", 3600, &sak, &ssk);
    assert_eq!(
        c.fetch("PUT", &write, b"x").status,
        403,
        "a read-only key presigned a PUT"
    );
}

/// An unsigned request is still refused — the presigned path must not become
/// a way past authentication for a request that carries no credentials.
#[test]
fn a_bare_url_with_no_credentials_is_still_refused() {
    let c = setup("presign-none");
    c.request("PUT", "/presign-none/x.bin", b"data").expect(200);

    let bare = format!("{}/presign-none/x.bin", c.endpoint);
    assert_eq!(c.fetch("GET", &bare, &[]).status, 403);

    // A partial set of parameters announces itself as presigned and must be
    // rejected as malformed rather than fall through to unauthenticated.
    let partial = format!("{bare}?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc");
    assert_eq!(c.fetch("GET", &partial, &[]).status, 403);
}
