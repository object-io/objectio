//! Where a request came from, in policies: the named endpoint it arrived
//! on (`aws:SourceVpce`) and the client's address (`aws:SourceIp`). A grant
//! confined to either isn't public, so it stands with public access blocked.

use objectio_e2e::{Cluster, Response};
use serde_json::json;

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// The cluster's `--port` is the endpoint "internal"; `external` another.
fn two_endpoints() -> (Cluster, String) {
    let port = free_port();
    let spec = format!("{port}=external");
    let c = Cluster::start_with_ec_and_args(
        6,
        4,
        2,
        &["--endpoint-name", "internal", "--data-port", &spec],
    );
    (c, format!("http://127.0.0.1:{port}"))
}

fn anonymous(base: &str, path: &str) -> Response {
    reqwest::blocking::get(format!("{base}{path}")).map_or_else(
        |e| panic!("{e}"),
        |r| Response {
            status: r.status().as_u16(),
            headers: Vec::new(),
            bytes: r.bytes().unwrap().to_vec(),
        },
    )
}

fn policy(statement: &serde_json::Value) -> Vec<u8> {
    json!({"Version": "2012-10-17", "Statement": [statement]})
        .to_string()
        .into_bytes()
}

#[test]
fn a_grant_to_everyone_inside_holds_inside_only() {
    let (c, external) = two_endpoints();
    c.request("PUT", "/assets", &[]).expect(200);
    c.request("PUT", "/assets/logo", b"logo").expect(200);
    // Readable without keys, from the internal endpoint only: not public,
    // so taken with the new bucket's block in place.
    let inside = json!({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::assets/*",
        "Condition": {"StringEquals": {"aws:SourceVpce": "internal"}}});
    c.request("PUT", "/assets?policy", &policy(&inside))
        .expect_ok();
    let status = c.request("GET", "/assets?policyStatus", &[]);
    assert!(
        status.text().contains("<IsPublic>false</IsPublic>"),
        "{}",
        status.text()
    );

    let r = anonymous(&c.endpoint, "/assets/logo");
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.bytes, b"logo");
    assert_eq!(anonymous(&external, "/assets/logo").status, 403);
    // The external endpoint serves S3 to signed callers all the same.
    let r = reqwest::blocking::get(format!("{external}/health")).unwrap();
    assert_eq!(r.status().as_u16(), 200);
}

#[test]
fn keys_can_be_confined_to_an_endpoint() {
    let (mut c, external) = two_endpoints();
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "acme", "display_name": "acme", "enabled": true}),
    )
    .expect_ok();
    let u = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "app", "tenant": "acme"}),
    );
    let id = u.json()["user_id"].as_str().unwrap().to_string();
    let k = c.json(
        "POST",
        &format!("/_admin/users/{id}/access-keys"),
        json!({}),
    );
    let (ak, sk) = (
        k.json()["access_key_id"].as_str().unwrap().to_string(),
        k.json()["secret_access_key"].as_str().unwrap().to_string(),
    );
    c.request_as("PUT", "/payroll", &[], &ak, &sk).expect(200);
    c.request_as("PUT", "/payroll/k", b"pay", &ak, &sk)
        .expect(200);
    let only_inside = json!({"Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": ["arn:aws:s3:::payroll", "arn:aws:s3:::payroll/*"],
        "Condition": {"StringNotEquals": {"aws:SourceVpce": "internal"}}});
    c.request_as("PUT", "/payroll?policy", &policy(&only_inside), &ak, &sk)
        .expect_ok();

    assert_eq!(
        c.request_as("GET", "/payroll/k", &[], &ak, &sk).bytes,
        b"pay"
    );
    // The same key, from outside: refused.
    let internal = std::mem::replace(&mut c.endpoint, external);
    let r = c.request_as("GET", "/payroll/k", &[], &ak, &sk);
    assert_eq!(r.status, 403, "{}", r.text());
    c.endpoint = internal;
}

#[test]
fn source_ip_is_the_peer_unless_a_trusted_proxy_says_otherwise() {
    let ten_only = |bucket: &str| {
        policy(
            &json!({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": format!("arn:aws:s3:::{bucket}/*"),
            "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}),
        )
    };
    let loopback = policy(
        &json!({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::local/*",
        "Condition": {"IpAddress": {"aws:SourceIp": "127.0.0.0/8"}}}),
    );
    let forwarded = |base: &str, path: &str, xff: &str| {
        reqwest::blocking::Client::new()
            .get(format!("{base}{path}"))
            .header("X-Forwarded-For", xff)
            .send()
            .unwrap()
            .status()
            .as_u16()
    };

    // No trusted proxies: the peer (loopback) is the client, whatever the
    // request claims.
    let c = Cluster::start();
    for b in ["local", "ten"] {
        c.request("PUT", &format!("/{b}"), &[]).expect(200);
        c.request("PUT", &format!("/{b}/k"), b"x").expect(200);
    }
    c.request("PUT", "/local?policy", &loopback).expect_ok();
    c.request("PUT", "/ten?policy", &ten_only("ten"))
        .expect_ok();
    assert_eq!(anonymous(&c.endpoint, "/local/k").status, 200);
    assert_eq!(anonymous(&c.endpoint, "/ten/k").status, 403);
    assert_eq!(forwarded(&c.endpoint, "/ten/k", "10.1.2.3"), 403);
    drop(c);

    // Loopback is a trusted proxy: the forwarded client counts.
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--trusted-proxies", "127.0.0.1"]);
    c.request("PUT", "/ten", &[]).expect(200);
    c.request("PUT", "/ten/k", b"x").expect(200);
    c.request("PUT", "/ten?policy", &ten_only("ten"))
        .expect_ok();
    assert_eq!(forwarded(&c.endpoint, "/ten/k", "10.1.2.3"), 200);
    assert_eq!(forwarded(&c.endpoint, "/ten/k", "203.0.113.5"), 403);
    // A client can't hide behind the proxy: the nearest untrusted hop wins.
    assert_eq!(
        forwarded(&c.endpoint, "/ten/k", "10.1.2.3, 203.0.113.5"),
        403
    );
}

#[test]
fn only_a_trusted_proxy_can_say_the_client_used_tls() {
    let tls_only = policy(
        &json!({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::tls/*",
        "Condition": {"Bool": {"aws:SecureTransport": "true"}}}),
    );
    let open = b"<PublicAccessBlockConfiguration></PublicAccessBlockConfiguration>";
    let via_https = |base: &str| {
        reqwest::blocking::Client::new()
            .get(format!("{base}/tls/k"))
            .header("X-Forwarded-Proto", "https")
            .send()
            .unwrap()
            .status()
            .as_u16()
    };
    let setup = |c: &Cluster| {
        c.request("PUT", "/tls", &[]).expect(200);
        c.request("PUT", "/tls/k", b"x").expect(200);
        c.request("PUT", "/tls?publicAccessBlock", open).expect(200);
        c.request("PUT", "/tls?policy", &tls_only).expect_ok();
    };

    // Plain HTTP from the client itself: the header is its own claim.
    let c = Cluster::start();
    setup(&c);
    assert_eq!(via_https(&c.endpoint), 403);
    drop(c);

    // From a trusted proxy, it says what the proxy saw.
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--trusted-proxies", "127.0.0.1"]);
    setup(&c);
    assert_eq!(via_https(&c.endpoint), 200);
    assert_eq!(anonymous(&c.endpoint, "/tls/k").status, 403);
}
