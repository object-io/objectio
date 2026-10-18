//! Browser form uploads (S3's POST Object): a `multipart/form-data` POST to
//! the bucket, signed by a `SigV4` policy or not signed at all. The policy's
//! conditions bind every field; then the upload is authorized and written
//! as any PUT is.
//!
//! The forms are built and signed here, by hand, so the gateway is checked
//! against an independent reading of the spec rather than against itself.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use objectio_e2e::{Cluster, Response};
use serde_json::{Value, json};
use sha2::Sha256;

/// The signing date. A form's date binds only its credential scope (the
/// policy's expiration is what limits it), so a fixed one is fine.
const DATE: &str = "20261002T120000Z";
const DAY: &str = "20261002";
const LATER: &str = "2099-01-01T00:00:00.000Z";

const BLOCK_NONE: &[u8] = b"<PublicAccessBlockConfiguration>\
    <BlockPublicAcls>false</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls>\
    <BlockPublicPolicy>false</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets>\
    </PublicAccessBlockConfiguration>";

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// A form's fields, signed with `(ak, sk)`: the policy holds `conditions`
/// plus the signing fields themselves, as SDKs write it.
fn signed(
    (ak, sk): (&str, &str),
    expiration: &str,
    conditions: &[Value],
    fields: &[(&str, &str)],
) -> Vec<(String, String)> {
    let credential = format!("{ak}/{DAY}/us-east-1/s3/aws4_request");
    let mut all: Vec<Value> = conditions.to_vec();
    all.extend([
        json!({"x-amz-algorithm": "AWS4-HMAC-SHA256"}),
        json!({"x-amz-credential": credential}),
        json!({"x-amz-date": DATE}),
    ]);
    let policy = B64.encode(json!({"expiration": expiration, "conditions": all}).to_string());
    let mut key = hmac(format!("AWS4{sk}").as_bytes(), DAY);
    key = hmac(&key, "us-east-1");
    key = hmac(&key, "s3");
    key = hmac(&key, "aws4_request");
    let signature = hex::encode(hmac(&key, &policy));

    let mut out: Vec<(String, String)> = fields
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    out.extend([
        ("x-amz-algorithm".into(), "AWS4-HMAC-SHA256".into()),
        ("x-amz-credential".into(), credential),
        ("x-amz-date".into(), DATE.into()),
        ("policy".into(), policy),
        ("x-amz-signature".into(), signature),
    ]);
    out
}

fn unsigned(fields: &[(&str, &str)]) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// POST the form, the file last, without following a redirect.
fn post(
    c: &Cluster,
    bucket: &str,
    fields: &[(String, String)],
    filename: &str,
    file: &[u8],
) -> Response {
    post_with(c, bucket, fields, filename, file, &[])
}

fn post_with(
    c: &Cluster,
    bucket: &str,
    fields: &[(String, String)],
    filename: &str,
    file: &[u8],
    headers: &[(&str, &str)],
) -> Response {
    let boundary = "----objectioFormBoundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
             filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut req = client
        .post(format!("{}/{bucket}", c.endpoint))
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req.send().expect("POST");
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    Response {
        status,
        bytes: resp.bytes().expect("body").to_vec(),
        headers,
    }
}

fn code(r: &Response) -> String {
    r.text()
        .split("<Code>")
        .nth(1)
        .and_then(|t| t.split("</Code>").next())
        .unwrap_or_default()
        .to_string()
}

fn admin(c: &Cluster) -> (&str, &str) {
    (&c.access_key, &c.secret_key)
}

/// The usual policy for `bucket`: anything under `prefix`.
fn under(bucket: &str, prefix: &str) -> Vec<Value> {
    vec![
        json!({"bucket": bucket}),
        json!(["starts-with", "$key", prefix]),
    ]
}

#[test]
fn a_signed_form_uploads_an_object_as_a_put_would() {
    let c = Cluster::start();
    c.request("PUT", "/forms", &[]).expect(200);
    let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();

    // Default: 204, the ETag and where the object is.
    let mut conditions = under("forms", "uploads/");
    conditions.extend([
        json!({"Content-Type": "image/png"}),
        json!(["starts-with", "$x-amz-meta-owner", ""]),
    ]);
    let fields = signed(
        admin(&c),
        LATER,
        &conditions,
        &[
            ("key", "uploads/${filename}"),
            ("Content-Type", "image/png"),
            ("x-amz-meta-owner", "alice"),
        ],
    );
    let r = post(&c, "forms", &fields, "cat.png", &data);
    assert_eq!(r.status, 204, "{}", r.text());
    let etag = r.header("etag").expect("ETag");
    assert!(
        r.header("location")
            .unwrap_or_default()
            .ends_with("/forms/uploads/cat.png"),
        "{:?}",
        r.headers
    );

    let got = c.request("GET", "/forms/uploads/cat.png", &[]);
    got.expect(200);
    assert_eq!(got.bytes, data, "the object differs from what was posted");
    assert_eq!(got.header("etag").as_deref(), Some(etag.as_str()));
    assert_eq!(got.header("content-type").as_deref(), Some("image/png"));
    assert_eq!(got.header("x-amz-meta-owner").as_deref(), Some("alice"));
    // Listed, as a PUT's object is.
    assert!(
        c.request("GET", "/forms?list-type=2", &[])
            .text()
            .contains("uploads/cat.png")
    );

    // 201: a PostResponse document.
    let mut conditions = under("forms", "");
    conditions.push(json!({"success_action_status": "201"}));
    let fields = signed(
        admin(&c),
        LATER,
        &conditions,
        &[("key", "doc.txt"), ("success_action_status", "201")],
    );
    let r = post(&c, "forms", &fields, "doc.txt", b"document");
    assert_eq!(r.status, 201, "{}", r.text());
    let text = r.text();
    for want in [
        "<PostResponse>",
        "<Bucket>forms</Bucket>",
        "<Key>doc.txt</Key>",
        "<ETag>",
        "<Location>",
    ] {
        assert!(text.contains(want), "{want} missing: {text}");
    }

    // 200: empty.
    let mut conditions = under("forms", "");
    conditions.push(json!(["eq", "$success_action_status", "200"]));
    let fields = signed(
        admin(&c),
        LATER,
        &conditions,
        &[("key", "two.txt"), ("success_action_status", "200")],
    );
    let r = post(&c, "forms", &fields, "two.txt", b"two");
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.bytes.is_empty());

    // A redirect: 303 to it, with the bucket, key and ETag.
    let mut conditions = under("forms", "");
    conditions.push(json!([
        "starts-with",
        "$success_action_redirect",
        "https://app.example.com/"
    ]));
    let fields = signed(
        admin(&c),
        LATER,
        &conditions,
        &[
            ("key", "three.txt"),
            (
                "success_action_redirect",
                "https://app.example.com/done?x=1",
            ),
        ],
    );
    let r = post(&c, "forms", &fields, "three.txt", b"three");
    assert_eq!(r.status, 303, "{}", r.text());
    let location = r.header("location").expect("Location");
    assert!(
        location.starts_with("https://app.example.com/done?x=1&bucket=forms&key=three.txt&etag="),
        "{location}"
    );
    assert_eq!(c.request("GET", "/forms/three.txt", &[]).bytes, b"three");
}

#[test]
fn a_form_that_breaks_its_policy_stores_nothing() {
    let c = Cluster::start();
    c.request("PUT", "/strict", &[]).expect(200);
    let ok = |extra: &[Value]| {
        let mut conditions = under("strict", "in/");
        conditions.extend_from_slice(extra);
        conditions
    };

    // A signature by the wrong secret.
    let fields = signed(
        (c.access_key.as_str(), "not-the-secret"),
        LATER,
        &ok(&[]),
        &[("key", "in/a")],
    );
    let r = post(&c, "strict", &fields, "a", b"a");
    assert_eq!(r.status, 403, "{}", r.text());
    assert_eq!(code(&r), "SignatureDoesNotMatch");

    // A signature over another policy.
    let mut fields = signed(admin(&c), LATER, &ok(&[]), &[("key", "in/a")]);
    let other = signed(admin(&c), LATER, &under("strict", ""), &[]);
    let policy = other.iter().find(|(k, _)| k == "policy").unwrap().1.clone();
    fields.iter_mut().find(|(k, _)| k == "policy").unwrap().1 = policy;
    let r = post(&c, "strict", &fields, "a", b"a");
    assert_eq!(code(&r), "SignatureDoesNotMatch", "{}", r.text());

    // Expired.
    let fields = signed(
        admin(&c),
        "2020-01-01T00:00:00.000Z",
        &ok(&[]),
        &[("key", "in/a")],
    );
    let r = post(&c, "strict", &fields, "a", b"a");
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(r.text().contains("Policy expired"), "{}", r.text());

    // A key outside the prefix.
    let fields = signed(admin(&c), LATER, &ok(&[]), &[("key", "out/a")]);
    let r = post(&c, "strict", &fields, "a", b"a");
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(r.text().contains("Policy Condition failed"), "{}", r.text());

    // Another bucket than the policy's.
    c.request("PUT", "/other", &[]).expect(200);
    let fields = signed(admin(&c), LATER, &ok(&[]), &[("key", "in/a")]);
    let r = post(&c, "other", &fields, "a", b"a");
    assert_eq!(r.status, 403, "{}", r.text());

    // A field the policy doesn't speak for.
    let fields = signed(
        admin(&c),
        LATER,
        &ok(&[]),
        &[("key", "in/a"), ("x-amz-meta-sneaky", "1")],
    );
    let r = post(&c, "strict", &fields, "a", b"a");
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(
        r.text().contains("Extra input fields: x-amz-meta-sneaky"),
        "{}",
        r.text()
    );

    // A file outside the content-length-range, either way.
    let ranged = ok(&[json!(["content-length-range", 10, 100])]);
    let fields = signed(admin(&c), LATER, &ranged, &[("key", "in/big")]);
    let r = post(&c, "strict", &fields, "big", &[7u8; 101]);
    assert_eq!(r.status, 400, "{}", r.text());
    assert_eq!(code(&r), "EntityTooLarge");
    let r = post(&c, "strict", &fields, "small", b"tiny");
    assert_eq!(code(&r), "EntityTooSmall", "{}", r.text());
    // Within it.
    let r = post(&c, "strict", &fields, "fits", &[7u8; 100]);
    assert_eq!(r.status, 204, "{}", r.text());
    // Only the one within range was stored.
    assert_eq!(c.request("GET", "/strict/in/big", &[]).bytes, [7u8; 100]);

    // A public ACL: refused, ACLs being owner-enforced.
    let fields = signed(
        admin(&c),
        LATER,
        &ok(&[json!({"acl": "public-read"})]),
        &[("key", "in/acl"), ("acl", "public-read")],
    );
    let r = post(&c, "strict", &fields, "a", b"a");
    assert_eq!(code(&r), "AccessControlListNotSupported", "{}", r.text());

    // SigV2 forms are refused as SigV2 is everywhere.
    let r = post(
        &c,
        "strict",
        &unsigned(&[
            ("key", "in/v2"),
            ("AWSAccessKeyId", &c.access_key),
            ("policy", "e30="),
            ("signature", "abc"),
        ]),
        "a",
        b"a",
    );
    assert_eq!(r.status, 400, "{}", r.text());
    assert_eq!(code(&r), "InvalidRequest");

    for key in ["in/a", "out/a", "in/acl", "in/v2"] {
        assert_eq!(
            c.request("GET", &format!("/strict/{key}"), &[]).status,
            404,
            "{key} was stored"
        );
    }
    assert_eq!(c.request("GET", "/other/in/a", &[]).status, 404);
}

fn tenant_admin(c: &Cluster, tenant: &str) -> (String, String, String) {
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
        id,
        k["access_key_id"].as_str().unwrap().to_string(),
        k["secret_access_key"].as_str().unwrap().to_string(),
    )
}

#[test]
fn a_form_is_authorized_as_its_signer() {
    let c = Cluster::start();
    let (acme_id, acme_key, acme_secret) = tenant_admin(&c, "acme");
    let (_, globex_key, globex_secret) = tenant_admin(&c, "globex");
    c.request_as("PUT", "/acme-up", &[], &acme_key, &acme_secret)
        .expect(200);
    c.request_as("PUT", "/acme-other", &[], &acme_key, &acme_secret)
        .expect(200);
    c.request_as("PUT", "/globex-up", &[], &globex_key, &globex_secret)
        .expect(200);

    // Its own bucket: fine.
    let fields = signed(
        (acme_key.as_str(), acme_secret.as_str()),
        LATER,
        &under("acme-up", ""),
        &[("key", "mine")],
    );
    assert_eq!(post(&c, "acme-up", &fields, "f", b"ok").status, 204);

    // Across the tenant boundary: a valid signature and policy, refused.
    let fields = signed(
        (acme_key.as_str(), acme_secret.as_str()),
        LATER,
        &under("globex-up", ""),
        &[("key", "theirs")],
    );
    let r = post(&c, "globex-up", &fields, "f", b"no");
    assert_eq!(r.status, 403, "{}", r.text());
    assert_eq!(code(&r), "AccessDenied");
    assert_eq!(c.request("GET", "/globex-up/theirs", &[]).status, 404);

    // A key scoped to one bucket signs for that bucket only.
    let scoped = c.request_as(
        "POST",
        &format!("/_admin/users/{acme_id}/access-keys"),
        json!({"scope": "s3://acme-up/", "operation": "RW"})
            .to_string()
            .as_bytes(),
        &acme_key,
        &acme_secret,
    );
    scoped.expect_ok();
    let v = scoped.json();
    let (sak, ssk) = (
        v["access_key_id"].as_str().unwrap().to_string(),
        v["secret_access_key"].as_str().unwrap().to_string(),
    );
    let fields = signed(
        (sak.as_str(), ssk.as_str()),
        LATER,
        &under("acme-other", ""),
        &[("key", "x")],
    );
    let r = post(&c, "acme-other", &fields, "f", b"no");
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(r.text().contains("scoped"), "{}", r.text());
    let fields = signed(
        (sak.as_str(), ssk.as_str()),
        LATER,
        &under("acme-up", ""),
        &[("key", "x")],
    );
    assert_eq!(post(&c, "acme-up", &fields, "f", b"yes").status, 204);

    // A read-only key can't write by form either.
    let ro = c.request_as(
        "POST",
        &format!("/_admin/users/{acme_id}/access-keys"),
        json!({"scope": "s3://acme-up/", "operation": "R"})
            .to_string()
            .as_bytes(),
        &acme_key,
        &acme_secret,
    );
    ro.expect_ok();
    let v = ro.json();
    let fields = signed(
        (
            v["access_key_id"].as_str().unwrap(),
            v["secret_access_key"].as_str().unwrap(),
        ),
        LATER,
        &under("acme-up", ""),
        &[("key", "ro")],
    );
    assert_eq!(post(&c, "acme-up", &fields, "f", b"no").status, 403);
    assert_eq!(c.request("GET", "/acme-up/ro", &[]).status, 404);

    // An unknown key.
    let fields = signed(
        ("AKIDNOSUCHKEY", "x"),
        LATER,
        &under("acme-up", ""),
        &[("key", "u")],
    );
    assert_eq!(post(&c, "acme-up", &fields, "f", b"no").status, 403);
}

#[test]
fn an_anonymous_form_needs_a_public_write_policy_and_no_block() {
    let c = Cluster::start();
    c.request("PUT", "/dropbox", &[]).expect(200);
    let form = unsigned(&[("key", "drop/${filename}")]);

    let r = post(&c, "dropbox", &form, "anon.txt", b"anonymous");
    assert_eq!(r.status, 403, "{}", r.text());
    assert_eq!(code(&r), "AccessDenied");

    let policy = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::dropbox/drop/*",
    }]});
    // Blocked while the bucket's public access block stands.
    assert_eq!(
        c.request("PUT", "/dropbox?policy", policy.to_string().as_bytes())
            .status,
        403
    );
    c.request("PUT", "/dropbox?publicAccessBlock", BLOCK_NONE)
        .expect(200);
    c.request("PUT", "/dropbox?policy", policy.to_string().as_bytes())
        .expect_ok();

    let r = post(&c, "dropbox", &form, "anon.txt", b"anonymous");
    assert_eq!(r.status, 204, "{}", r.text());
    assert_eq!(
        c.request("GET", "/dropbox/drop/anon.txt", &[]).bytes,
        b"anonymous"
    );
    // Only where the policy grants it.
    let r = post(&c, "dropbox", &unsigned(&[("key", "elsewhere")]), "f", b"x");
    assert_eq!(r.status, 403, "{}", r.text());

    // RestrictPublicBuckets shuts the grant off again.
    c.request(
        "PUT",
        "/dropbox?publicAccessBlock",
        b"<PublicAccessBlockConfiguration><RestrictPublicBuckets>true</RestrictPublicBuckets>\
          </PublicAccessBlockConfiguration>",
    )
    .expect(200);
    assert_eq!(post(&c, "dropbox", &form, "again.txt", b"x").status, 403);
}

#[test]
fn a_form_upload_gets_the_buckets_default_encryption_and_cors() {
    let c = Cluster::start();
    c.request("PUT", "/sealed", &[]).expect(200);
    c.request(
        "PUT",
        "/sealed?encryption",
        b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>\
          <SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule>\
          </ServerSideEncryptionConfiguration>",
    )
    .expect_ok();
    c.request(
        "PUT",
        "/sealed?cors",
        b"<CORSConfiguration><CORSRule><AllowedOrigin>https://app.example.com</AllowedOrigin>\
          <AllowedMethod>POST</AllowedMethod><ExposeHeader>ETag</ExposeHeader></CORSRule>\
          </CORSConfiguration>",
    )
    .expect(200);

    let data = b"secret form contents".repeat(500);
    let fields = signed(admin(&c), LATER, &under("sealed", ""), &[("key", "s.bin")]);
    let r = post_with(
        &c,
        "sealed",
        &fields,
        "s.bin",
        &data,
        &[("Origin", "https://app.example.com")],
    );
    assert_eq!(r.status, 204, "{}", r.text());
    assert_eq!(
        r.header("x-amz-server-side-encryption").as_deref(),
        Some("AES256")
    );
    assert_eq!(
        r.header("access-control-allow-origin").as_deref(),
        Some("https://app.example.com")
    );
    assert_eq!(
        r.header("access-control-expose-headers").as_deref(),
        Some("ETag")
    );

    let head = c.request("HEAD", "/sealed/s.bin", &[]);
    head.expect(200);
    assert_eq!(
        head.header("x-amz-server-side-encryption").as_deref(),
        Some("AES256")
    );
    assert_eq!(c.request("GET", "/sealed/s.bin", &[]).bytes, data);

    // A refusal carries the CORS headers too, so the page can read it.
    let fields = signed(
        admin(&c),
        "2020-01-01T00:00:00Z",
        &under("sealed", ""),
        &[("key", "late")],
    );
    let r = post_with(
        &c,
        "sealed",
        &fields,
        "f",
        b"x",
        &[("Origin", "https://app.example.com")],
    );
    assert_eq!(r.status, 403, "{}", r.text());
    assert_eq!(
        r.header("access-control-allow-origin").as_deref(),
        Some("https://app.example.com")
    );
}
