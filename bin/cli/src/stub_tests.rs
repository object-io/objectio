//! Argument → request mapping, against a local stub HTTP server that
//! records what each command sends.

#![allow(clippy::needless_pass_by_value)] // test helpers take what the call sites build

use crate::cli::Args;
use clap::Parser;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone)]
struct Captured {
    method: String,
    /// The raw (escaped) path, as sent and signed.
    path: String,
    /// Query pairs, percent-decoded.
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Captured {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A canned answer: status, content type, body.
type Canned = (u16, &'static str, String);

struct Stub {
    url: String,
    seen: Arc<Mutex<Vec<Captured>>>,
}

/// Serve `replies` in order (then `200 {}` for anything further).
async fn stub(replies: Vec<Canned>) -> Stub {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let replies = Arc::new(Mutex::new(replies.into_iter()));
    let seen2 = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let head_end = loop {
                let n = sock.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(p);
                }
            };
            let Some(head_end) = head_end else { continue };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or_default();
            let mut parts = request_line.split(' ');
            let method = parts.next().unwrap_or_default().to_string();
            let target = parts.next().unwrap_or_default().to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
                .collect();
            let len: usize = headers
                .iter()
                .find(|(k, _)| k == "content-length")
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            let mut body = buf[head_end + 4..].to_vec();
            while body.len() < len {
                let n = sock.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            let (path, qs) = target.split_once('?').unwrap_or((&target, ""));
            let query = qs
                .split('&')
                .filter(|p| !p.is_empty())
                .map(|p| {
                    let (k, v) = p.split_once('=').unwrap_or((p, ""));
                    (decode(k), decode(v))
                })
                .collect();
            seen2.lock().unwrap().push(Captured {
                method,
                path: path.to_string(),
                query,
                headers,
                body,
            });
            let (status, ct, text) = replies
                .lock()
                .unwrap()
                .next()
                .unwrap_or_else(|| (200, "application/json", "{}".to_string()));
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: {ct}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                text.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    Stub { url, seen }
}

fn ok(body: Value) -> Canned {
    (200, "application/json", body.to_string())
}

const fn empty() -> Canned {
    (204, "application/json", String::new())
}

struct Run {
    seen: Vec<Captured>,
    out: String,
    result: anyhow::Result<()>,
}

async fn cli(argv: &[&str], replies: Vec<Canned>) -> Run {
    cli_env(argv, replies, &[]).await
}

async fn cli_env(argv: &[&str], replies: Vec<Canned>, environment: &[(&str, &str)]) -> Run {
    let s = stub(replies).await;
    let mut full = vec![
        "obioctl",
        "--endpoint",
        &s.url,
        "--access-key",
        "AKTEST",
        "--secret-key",
        "sktest",
    ];
    full.extend_from_slice(argv);
    let parsed = Args::try_parse_from(full).expect("arguments parse");
    let env: Vec<(String, String)> = environment
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    let lookup = move |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let mut buf = Vec::new();
    let result = crate::execute(parsed, &lookup, &mut buf).await;
    let seen = s.seen.lock().unwrap().clone();
    Run {
        seen,
        out: String::from_utf8(buf).unwrap(),
        result,
    }
}

fn file_with(content: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("doc");
    std::fs::write(&p, content).unwrap();
    let s = p.to_str().unwrap().to_string();
    (dir, s)
}

fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

// ── tenants ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn tenant_create_sends_only_what_was_given() {
    let r = cli(
        &[
            "tenant",
            "create",
            "acme",
            "--display-name",
            "Acme",
            "--quota-bytes",
            "1G",
            "--label",
            "env=prod",
            "--allowed-pool",
            "fast",
        ],
        vec![ok(json!({"name": "acme"}))],
    )
    .await;
    r.result.unwrap();
    let c = &r.seen[0];
    assert_eq!(
        (c.method.as_str(), c.path.as_str()),
        ("POST", "/_admin/tenants")
    );
    assert_eq!(
        c.json(),
        json!({"name": "acme", "display_name": "Acme", "quota_bytes": 1u64 << 30,
               "labels": {"env": "prod"}, "allowed_pools": ["fast"], "enabled": true})
    );
    // Signed, with the key it was given.
    let auth = c.header("authorization").unwrap();
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 Credential=AKTEST/"),
        "{auth}"
    );
    assert!(auth.contains("content-type;host;x-amz-content-sha256;x-amz-date"));
}

#[tokio::test]
async fn tenant_update_is_partial() {
    let r = cli(
        &["tenant", "update", "acme", "--enabled", "false"],
        vec![ok(json!({}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].method, "PUT");
    assert_eq!(r.seen[0].path, "/_admin/tenants/acme");
    assert_eq!(r.seen[0].json(), json!({"enabled": false}));
}

#[tokio::test]
async fn a_tenant_admin_arn_stays_one_path_segment() {
    let r = cli(
        &[
            "tenant",
            "admin",
            "remove",
            "acme",
            "arn:obio:iam::acme:user/u1",
        ],
        vec![empty()],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].method, "DELETE");
    assert_eq!(
        r.seen[0].path,
        "/_admin/tenants/acme/admins/arn%3Aobio%3Aiam%3A%3Aacme%3Auser%2Fu1"
    );
    let r = cli(
        &["tenant", "admin", "add", "acme", "arn:x"],
        vec![ok(json!({}))],
    )
    .await;
    assert_eq!(r.seen[0].json(), json!({"user_arn": "arn:x"}));
}

#[tokio::test]
async fn an_api_error_carries_the_servers_message() {
    let r = cli(
        &["tenant", "show", "ghost"],
        vec![(404, "text/plain", "Tenant not found".into())],
    )
    .await;
    let err = r.result.unwrap_err().to_string();
    assert!(
        err.contains("404") && err.contains("Tenant not found"),
        "{err}"
    );
}

#[tokio::test]
async fn json_output_is_the_raw_document() {
    let raw = json!([{"name": "acme", "enabled": true, "admin_users": ["u1"]}]);
    let r = cli(&["-o", "json", "tenant", "list"], vec![ok(raw.clone())]).await;
    r.result.unwrap();
    let back: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(back, raw);
    // And the table is a table.
    let r = cli(&["tenant", "list"], vec![ok(raw)]).await;
    assert!(r.out.starts_with("NAME"), "{}", r.out);
    assert!(r.out.contains("acme"));
}

// ── users / keys ────────────────────────────────────────────────────────

#[tokio::test]
async fn user_list_narrows_to_the_tenant_client_side() {
    let users = json!({"users": [
        {"user_id": "u1", "display_name": "a", "tenant": "acme"},
        {"user_id": "u2", "display_name": "b", "tenant": "globex"}
    ]});
    let r = cli(
        &["-o", "json", "user", "list", "--tenant", "acme"],
        vec![ok(users)],
    )
    .await;
    r.result.unwrap();
    assert!(r.seen[0].query.is_empty(), "the endpoint takes no tenant");
    let back: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(back["users"].as_array().unwrap().len(), 1);
    assert_eq!(back["users"][0]["user_id"], "u1");
}

#[tokio::test]
async fn user_create_without_tenant_sends_no_tenant() {
    let r = cli(
        &["user", "create", "alice"],
        vec![ok(json!({"user_id": "u9"}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].json(), json!({"display_name": "alice"}));
    let r = cli(
        &[
            "user", "create", "bob", "--tenant", "acme", "--email", "b@x",
        ],
        vec![ok(json!({}))],
    )
    .await;
    assert_eq!(
        r.seen[0].json(),
        json!({"display_name": "bob", "tenant": "acme", "email": "b@x"})
    );
}

#[tokio::test]
async fn suspend_and_activate_set_the_status() {
    let r = cli(&["user", "suspend", "u1"], vec![ok(json!({}))]).await;
    r.result.unwrap();
    assert_eq!(r.seen[0].method, "PUT");
    assert_eq!(r.seen[0].path, "/_admin/users/u1");
    assert_eq!(r.seen[0].json(), json!({"status": "suspended"}));
    let r = cli(&["user", "activate", "u1"], vec![ok(json!({}))]).await;
    assert_eq!(r.seen[0].json(), json!({"status": "active"}));
}

#[tokio::test]
async fn key_create_scoped_read_only_and_shows_the_secret_once() {
    let r = cli(
        &["key", "create", "u1", "--scope", "s3://b/p/", "--read-only"],
        vec![ok(
            json!({"access_key_id": "AK1", "secret_access_key": "SECRET1",
                        "scope": "s3://b/p/", "operation": "READ"}),
        )],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].path, "/_admin/users/u1/access-keys");
    assert_eq!(
        r.seen[0].json(),
        json!({"scope": "s3://b/p/", "operation": "R"})
    );
    assert!(r.out.contains("SECRET1"));
    // A malformed scope never reaches the server.
    let r = cli(&["key", "create", "u1", "--scope", "b/p"], vec![]).await;
    assert!(r.result.is_err());
    assert!(r.seen.is_empty());
}

#[tokio::test]
async fn key_list_never_shows_a_secret() {
    let r = cli(
        &["key", "list", "u1"],
        vec![ok(
            json!({"access_keys": [{"access_key_id": "AK1", "status": "active",
                                        "operation": "READ_WRITE", "scope": "", "created_at": 0}]}),
        )],
    )
    .await;
    r.result.unwrap();
    assert!(r.out.contains("AK1") && !r.out.to_lowercase().contains("secret"));
}

#[tokio::test]
async fn key_deactivate_puts_inactive() {
    let r = cli(
        &["key", "deactivate", "AK1"],
        vec![ok(json!({"status": "inactive"}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].method, "PUT");
    assert_eq!(r.seen[0].path, "/_admin/access-keys/AK1");
    assert_eq!(r.seen[0].json(), json!({"status": "inactive"}));
}

// ── policies / groups / roles ───────────────────────────────────────────

#[tokio::test]
async fn policy_create_names_the_tenant_in_the_query() {
    let (_d, f) = file_with(r#"{"Version":"2012-10-17","Statement":[]}"#);
    let r = cli(
        &[
            "policy", "create", "readers", "--file", &f, "--tenant", "acme",
        ],
        vec![ok(json!({}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].path, "/_admin/policies");
    assert_eq!(r.seen[0].query, q(&[("tenant", "acme")]));
    assert_eq!(
        r.seen[0].json(),
        json!({"name": "readers", "policy": {"Version": "2012-10-17", "Statement": []}})
    );
}

#[tokio::test]
async fn policy_attach_puts_the_tenant_in_the_body() {
    let r = cli(
        &[
            "policy", "attach", "readers", "--role", "etl", "--tenant", "acme",
        ],
        vec![empty()],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].path, "/_admin/policies/attach");
    assert!(r.seen[0].query.is_empty());
    assert_eq!(
        r.seen[0].json(),
        json!({"policy_name": "readers", "role_name": "etl", "tenant": "acme"})
    );
}

#[tokio::test]
async fn policy_attached_queries_by_principal() {
    let r = cli(
        &["policy", "attached", "--user", "u1"],
        vec![ok(json!({"policy_names": ["readers"]}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].query, q(&[("user_id", "u1")]));
    assert_eq!(r.out, "readers\n");
}

#[tokio::test]
async fn group_create_and_membership() {
    let r = cli(
        &["group", "create", "devs"],
        vec![ok(json!({"group_id": "g1"}))],
    )
    .await;
    r.result.unwrap();
    assert!(r.seen[0].query.is_empty());
    assert_eq!(r.seen[0].json(), json!({"group_name": "devs"}));
    let r = cli(&["group", "remove-user", "g1", "u1"], vec![empty()]).await;
    assert_eq!(r.seen[0].method, "DELETE");
    assert_eq!(r.seen[0].path, "/_admin/groups/g1/members/u1");
}

#[tokio::test]
async fn role_create_reads_the_trust_file() {
    let (_d, f) = file_with(r#"{"Statement":[]}"#);
    let r = cli(
        &[
            "role",
            "create",
            "etl",
            "--trust-file",
            &f,
            "--max-session-seconds",
            "900",
        ],
        vec![ok(json!({"arn": "arn:obio:iam::acme:role/etl"}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(
        r.seen[0].json(),
        json!({"name": "etl", "trust_policy": {"Statement": []}, "max_session_seconds": 900})
    );
}

// ── oidc / sts / public access / audit ──────────────────────────────────

#[tokio::test]
async fn oidc_put_writes_the_provider_config_key() {
    let (_d, f) = file_with(r#"{"issuer_url":"https://idp","client_id":"c"}"#);
    let r = cli(
        &["oidc", "put", "t-acme", "--file", &f],
        vec![ok(json!({"version": 1}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].method, "PUT");
    assert_eq!(r.seen[0].path, "/_admin/config/identity/openid/t-acme");
    assert_eq!(r.seen[0].json()["issuer_url"], "https://idp");
    let r = cli(&["oidc", "list"], vec![ok(json!([]))]).await;
    assert_eq!(r.seen[0].query, q(&[("prefix", "identity/openid/")]));
}

#[tokio::test]
async fn sts_is_unsigned_and_needs_no_key() {
    let s = stub(vec![(
        200,
        "text/xml",
        "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>\
         <AccessKeyId>ASIA1</AccessKeyId><SecretAccessKey>S</SecretAccessKey>\
         <SessionToken>T</SessionToken><Expiration>2026-01-01T00:00:00Z</Expiration>\
         </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"
            .into(),
    )])
    .await;
    // No --access-key at all.
    let args = Args::try_parse_from([
        "obioctl",
        "--endpoint",
        &s.url,
        "--output",
        "json",
        "sts",
        "assume-role-with-web-identity",
        "--role-arn",
        "arn:obio:iam::acme:role/r",
        "--token",
        "jwt.token",
        "--session-name",
        "s1",
    ])
    .unwrap();
    let mut buf = Vec::new();
    crate::execute(args, &|_| None, &mut buf).await.unwrap();
    let c = s.seen.lock().unwrap()[0].clone();
    assert_eq!((c.method.as_str(), c.path.as_str()), ("POST", "/"));
    assert!(c.header("authorization").is_none());
    assert_eq!(
        c.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    let form = String::from_utf8(c.body).unwrap();
    assert!(form.contains("Action=AssumeRoleWithWebIdentity"), "{form}");
    assert!(form.contains("WebIdentityToken=jwt.token"), "{form}");
    let out: Value = serde_json::from_slice(&buf).unwrap();
    assert_eq!(out["AccessKeyId"], "ASIA1");
}

#[tokio::test]
async fn public_access_block_put_writes_all_four_flags() {
    let r = cli(
        &[
            "public-access-block",
            "put",
            "--block-public-policy",
            "--new-buckets-blocked",
            "false",
        ],
        vec![ok(json!({}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].path, "/_admin/public-access-block");
    assert!(r.seen[0].query.is_empty());
    assert_eq!(
        r.seen[0].json(),
        json!({"BlockPublicAcls": false, "IgnorePublicAcls": false, "BlockPublicPolicy": true,
               "RestrictPublicBuckets": false, "new_buckets_blocked": false})
    );
}

#[tokio::test]
async fn bucket_public_access_block_is_the_s3_subresource() {
    let r = cli(
        &["public-access-block", "bucket", "put", "b1", "--all"],
        vec![ok(json!({}))],
    )
    .await;
    r.result.unwrap();
    let c = &r.seen[0];
    assert_eq!((c.method.as_str(), c.path.as_str()), ("PUT", "/b1"));
    assert_eq!(c.query, q(&[("publicAccessBlock", "")]));
    assert_eq!(c.header("content-type"), Some("application/xml"));
    let xml = String::from_utf8(c.body.clone()).unwrap();
    assert!(
        xml.contains("<BlockPublicPolicy>true</BlockPublicPolicy>"),
        "{xml}"
    );
    let r = cli(
        &[
            "-o",
            "json",
            "public-access-block",
            "bucket",
            "policy-status",
            "b1",
        ],
        vec![(
            200,
            "application/xml",
            "<PolicyStatus><IsPublic>true</IsPublic></PolicyStatus>".into(),
        )],
    )
    .await;
    assert_eq!(r.seen[0].query, q(&[("policyStatus", "")]));
    assert_eq!(
        serde_json::from_str::<Value>(&r.out).unwrap(),
        json!({"IsPublic": true})
    );
}

#[tokio::test]
async fn audit_put_sends_the_file_with_the_tenant() {
    let (_d, f) = file_with(r#"{"targets":[{"type":"stdout","name":"out"}]}"#);
    let r = cli(
        &["audit", "put", "--file", &f, "--tenant", "acme"],
        vec![ok(json!({}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].method, "PUT");
    assert_eq!(r.seen[0].path, "/_admin/audit");
    assert_eq!(r.seen[0].query, q(&[("tenant", "acme")]));
    assert_eq!(r.seen[0].json()["targets"][0]["type"], "stdout");
}

// ── buckets / provisioning ──────────────────────────────────────────────

#[tokio::test]
async fn bucket_create_takes_a_pool_and_a_tenant() {
    let r = cli(
        &[
            "bucket", "create", "b1", "--pool", "fast", "--tenant", "acme",
        ],
        vec![ok(json!({"name": "b1"}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].path, "/_admin/buckets");
    assert_eq!(
        r.seen[0].json(),
        json!({"name": "b1", "pool": "fast", "tenant": "acme"})
    );
}

#[tokio::test]
async fn bucket_list_shows_the_pool() {
    let r = cli(
        &["bucket", "list"],
        vec![ok(
            json!({"buckets": [{"name": "b1", "tenant": "acme", "owner": "u1",
                                     "pool": "fast", "created_at": 0}]}),
        )],
    )
    .await;
    r.result.unwrap();
    assert!(
        r.out.contains("POOL") && r.out.contains("fast"),
        "{}",
        r.out
    );
}

#[tokio::test]
async fn lifecycle_is_xml_on_the_s3_path() {
    let (_d, f) =
        file_with("<LifecycleConfiguration><Rule><ID>r</ID></Rule></LifecycleConfiguration>");
    let r = cli(
        &["bucket", "lifecycle", "put", "b1", "--file", &f],
        vec![ok(json!({}))],
    )
    .await;
    r.result.unwrap();
    let c = &r.seen[0];
    assert_eq!((c.method.as_str(), c.path.as_str()), ("PUT", "/b1"));
    assert_eq!(c.query, q(&[("lifecycle", "")]));
    assert_eq!(c.header("content-type"), Some("application/xml"));
    assert!(String::from_utf8_lossy(&c.body).contains("<ID>r</ID>"));
    let r = cli(&["bucket", "cors", "delete", "b1"], vec![empty()]).await;
    assert_eq!(r.seen[0].method, "DELETE");
    assert_eq!(r.seen[0].query, q(&[("cors", "")]));
}

#[tokio::test]
async fn bucket_dedup_set_sends_what_was_given() {
    let r = cli(
        &["bucket", "dedup", "set", "b1", "--mode", "on"],
        vec![ok(json!({}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].path, "/_admin/buckets/b1/dedup");
    assert_eq!(r.seen[0].json(), json!({"mode": "on"}));
}

#[tokio::test]
async fn provision_creates_then_mints_a_scoped_key() {
    let r = cli_env(
        &["provision", "bucket", "ws-1", "--prefix", "data/", "--read-only"],
        vec![
            ok(json!({"user_id": "prov"})),
            ok(json!({"name": "ws-1"})),
            ok(json!({"access_key_id": "AK2", "secret_access_key": "S2", "scope": "s3://ws-1/data/"})),
        ],
        &[("OBJECTIO_PROVISIONER_USER_ID", "prov")],
    )
    .await;
    r.result.unwrap();
    assert_eq!(
        r.seen[0].path, "/_admin/users/prov",
        "the user is checked first"
    );
    assert_eq!(r.seen[1].path, "/_admin/buckets");
    assert_eq!(r.seen[1].json(), json!({"name": "ws-1"}));
    assert_eq!(r.seen[2].path, "/_admin/users/prov/access-keys");
    assert_eq!(
        r.seen[2].json(),
        json!({"scope": "s3://ws-1/data/", "operation": "R"})
    );
    assert!(r.out.contains("S2"));
}

#[tokio::test]
async fn provision_for_an_unknown_user_creates_nothing() {
    let r = cli(
        &["provision", "bucket", "ws-1", "--user", "ghost"],
        vec![(
            404,
            "application/json",
            r#"{"error":"user not found"}"#.into(),
        )],
    )
    .await;
    assert!(r.result.is_err());
    assert_eq!(r.seen.len(), 1, "no bucket created");
}

#[tokio::test]
async fn deprovision_revokes_only_that_buckets_keys() {
    let r = cli(
        &["provision", "deprovision", "ws-1", "--user", "prov"],
        vec![
            ok(json!({"access_keys": [
                {"access_key_id": "K1", "scope": "s3://ws-1/"},
                {"access_key_id": "K2", "scope": "s3://ws-10/"},
                {"access_key_id": "K3", "scope": ""},
                {"access_key_id": "K4", "scope": "s3://ws-1/sub/"}
            ]})),
            empty(),
            empty(),
            empty(),
        ],
    )
    .await;
    r.result.unwrap();
    let calls: Vec<(String, String)> = r
        .seen
        .iter()
        .map(|c| (c.method.clone(), c.path.clone()))
        .collect();
    assert_eq!(
        calls,
        vec![
            ("GET".into(), "/_admin/users/prov/access-keys".into()),
            ("DELETE".into(), "/_admin/access-keys/K1".into()),
            ("DELETE".into(), "/_admin/access-keys/K4".into()),
            ("DELETE".into(), "/_admin/buckets/ws-1".into()),
        ]
    );
}

// ── cluster / pools / kms / warehouse / config / metrics ────────────────

#[tokio::test]
async fn rebalance_pause_posts() {
    let r = cli(
        &["cluster", "rebalance", "pause"],
        vec![ok(json!({"paused": true}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].method, "POST");
    assert_eq!(r.seen[0].path, "/_admin/rebalance/pause");
}

#[tokio::test]
async fn osd_set_state() {
    let r = cli(
        &[
            "osd",
            "set-state",
            "00112233445566778899aabbccddeeff",
            "out",
        ],
        vec![ok(json!({"found": true, "changed": true, "state": "out"}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(
        r.seen[0].path,
        "/_admin/osds/00112233445566778899aabbccddeeff/admin-state"
    );
    assert_eq!(r.seen[0].json(), json!({"state": "out"}));
    let r = cli(
        &["osd", "set-state", "ff", "in"],
        vec![ok(json!({"found": false, "changed": false}))],
    )
    .await;
    assert!(r.result.is_err(), "an unknown OSD is an error");
}

#[tokio::test]
async fn pool_update_is_partial_and_delete_surfaces_refusals() {
    let r = cli(
        &["pool", "update", "p1", "--ec-k", "6"],
        vec![ok(json!({}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].json(), json!({"ec_k": 6}));
    let r = cli(
        &["pool", "delete", "p1"],
        vec![(400, "text/plain", "pool 'p1' is in use by bucket b1".into())],
    )
    .await;
    let err = r.result.unwrap_err().to_string();
    assert!(err.contains("in use by bucket b1"), "{err}");
}

#[tokio::test]
async fn kms_key_create() {
    let r = cli(
        &["kms", "keys", "create", "--key-id", "k1"],
        vec![ok(json!({"key_id": "k1"}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].path, "/_admin/kms/keys");
    assert_eq!(r.seen[0].json(), json!({"key_id": "k1", "description": ""}));
}

#[tokio::test]
async fn warehouse_create_with_properties() {
    let r = cli(
        &[
            "warehouse",
            "create",
            "lake",
            "--property",
            "format=parquet",
        ],
        vec![ok(json!({"name": "lake"}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(
        r.seen[0].json(),
        json!({"name": "lake", "properties": {"format": "parquet"}})
    );
}

#[tokio::test]
async fn config_set_sends_the_value_as_the_body() {
    let r = cli(
        &["config", "set", "balancer/tuning", "--value", r#"{"a":1}"#],
        vec![ok(json!({"version": 3}))],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].path, "/_admin/config/balancer/tuning");
    assert_eq!(r.seen[0].json(), json!({"a": 1}));
}

#[tokio::test]
async fn metrics_query_passes_promql_through() {
    let r = cli(
        &[
            "metrics",
            "query",
            "sum(rate(x[5m])) by (job)",
            "--time",
            "1700000000",
        ],
        vec![ok(
            json!({"status": "success", "data": {"resultType": "vector", "result": []}}),
        )],
    )
    .await;
    r.result.unwrap();
    assert_eq!(r.seen[0].path, "/_admin/metrics/query");
    assert_eq!(
        r.seen[0].query,
        q(&[
            ("query", "sum(rate(x[5m])) by (job)"),
            ("time", "1700000000")
        ])
    );
}
