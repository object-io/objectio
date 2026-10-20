//! A disabled tenant: every identity of it is refused, on every path that
//! authenticates one, and enabling it again restores them all.
//!
//! A tenant's `enabled` was stored and shown, and read only by console
//! sign-in: its keys, sessions, presigned URLs, console sessions already
//! open and Delta Sharing recipients went on working. Each of these is its
//! own authentication path, so each is driven here from the outside.

use objectio_e2e::{Cluster, Response};
use serde_json::json;

const ALLOW_S3: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;

/// A tenant's admin: its ARN and key.
struct Admin {
    arn: String,
    ak: String,
    sk: String,
}

fn tenant_with_admin(c: &Cluster, tenant: &str) -> Admin {
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
    let u = user.json();
    let user_id = u["user_id"].as_str().unwrap().to_string();
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
    Admin {
        arn: u["arn"].as_str().unwrap().to_string(),
        ak: k["access_key_id"].as_str().unwrap().to_string(),
        sk: k["secret_access_key"].as_str().unwrap().to_string(),
    }
}

/// The text of the first `<tag>…</tag>` in a body.
#[track_caller]
fn one(r: &Response, tag: &str) -> String {
    let text = r.text();
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let start = text
        .find(&open)
        .unwrap_or_else(|| panic!("no <{tag}> in {text}"))
        + open.len();
    let end = text[start..].find(&close).expect("closing tag") + start;
    text[start..end].to_string()
}

/// Temporary credentials from an STS answer.
fn session(r: &Response) -> (String, String, String) {
    r.expect(200);
    (
        one(r, "AccessKeyId"),
        one(r, "SecretAccessKey"),
        one(r, "SessionToken"),
    )
}

/// Console sign-in with a key: the session cookie's value.
fn key_login(c: &Cluster, ak: &str, sk: &str) -> String {
    let r = reqwest::blocking::Client::new()
        .post(format!("{}/_console/api/login", c.endpoint))
        .header("Content-Type", "application/json")
        .body(json!({"accessKey": ak, "secretKey": sk}).to_string())
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "login");
    r.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.split(';').next()?.strip_prefix("objectio-session="))
        .expect("a session")
        .to_string()
}

fn set_enabled(c: &Cluster, tenant: &str, enabled: bool) {
    c.json(
        "PUT",
        &format!("/_admin/tenants/{tenant}"),
        json!({"enabled": enabled}),
    )
    .expect_ok();
}

/// Everything one identity of the tenant can do, each by its own path.
struct Paths<'a> {
    c: &'a Cluster,
    admin: &'a Admin,
    user_session: (String, String, String),
    role_session: (String, String, String),
    presigned: String,
    console: String,
    bearer: String,
}

impl Paths<'_> {
    /// `(path, status)` for each.
    fn statuses(&self) -> Vec<(&'static str, u16)> {
        let c = self.c;
        let (ak, sk) = (self.admin.ak.as_str(), self.admin.sk.as_str());
        let as_session = |s: &(String, String, String)| {
            c.request_as_session("GET", "/acme-data/k", &[], (&s.0, &s.1, &s.2))
                .status
        };
        let cookie = format!("objectio-session={}", self.console);
        let with_cookie = |path: &str| {
            c.fetch_with_headers(
                "GET",
                &format!("{}{path}", c.endpoint),
                &[("Cookie", &cookie)],
            )
            .status
        };
        let bearer = format!("Bearer {}", self.bearer);
        vec![
            (
                "SigV4 S3",
                c.request_as("GET", "/acme-data/k", &[], ak, sk).status,
            ),
            ("presigned GET", c.fetch("GET", &self.presigned, &[]).status),
            ("user session", as_session(&self.user_session)),
            ("role session", as_session(&self.role_session)),
            (
                "IAM API",
                c.query_api("iam", &[("Action", "ListUsers")], (ak, sk, None))
                    .status,
            ),
            (
                "admin API",
                c.request_as("GET", "/_admin/users", &[], ak, sk).status,
            ),
            (
                "Iceberg",
                c.request_as(
                    "GET",
                    "/iceberg/v1/namespaces?warehouse=acme-wh",
                    &[],
                    ak,
                    sk,
                )
                .status,
            ),
            (
                "Unity",
                c.request_as("GET", "/api/2.1/unity-catalog/catalogs", &[], ak, sk)
                    .status,
            ),
            ("console session", with_cookie("/_console/api/session")),
            ("console admin", with_cookie("/_admin/buckets")),
            (
                "Iceberg by session",
                with_cookie("/iceberg/v1/config?warehouse=acme-wh"),
            ),
            (
                "Delta Sharing",
                c.fetch_with_headers(
                    "GET",
                    &format!("{}/delta-sharing/v1/shares/acme-share/schemas", c.endpoint),
                    &[("Authorization", &bearer)],
                )
                .status,
            ),
        ]
    }

    /// The shares the recipient is shown.
    fn shares(&self) -> usize {
        let r = self.c.fetch_with_headers(
            "GET",
            &format!("{}/delta-sharing/v1/shares", self.c.endpoint),
            &[("Authorization", &format!("Bearer {}", self.bearer))],
        );
        r.expect(200);
        r.json()["items"].as_array().map_or(0, Vec::len)
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one identity of each kind, then three passes over them
fn a_disabled_tenants_identities_are_refused_until_it_is_enabled() {
    let c = Cluster::start();
    let admin = tenant_with_admin(&c, "acme");
    let (ak, sk) = (admin.ak.as_str(), admin.sk.as_str());

    c.request_as("PUT", "/acme-data", &[], ak, sk).expect(200);
    c.request_as("PUT", "/acme-data/k", b"v", ak, sk)
        .expect(200);
    c.request_as(
        "POST",
        "/_admin/warehouses",
        json!({"name": "acme-wh"}).to_string().as_bytes(),
        ak,
        sk,
    )
    .expect_ok();

    // A user's own session, and a role's.
    let user_session = session(&c.query_api(
        "sts",
        &[("Action", "GetSessionToken"), ("DurationSeconds", "900")],
        (ak, sk, None),
    ));
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{}"}},"Action":"sts:AssumeRole"}}]}}"#,
        admin.arn
    );
    let iam = |params: &[(&str, &str)]| c.query_api("iam", params, (ak, sk, None));
    let role = iam(&[
        ("Action", "CreateRole"),
        ("RoleName", "reader"),
        ("AssumeRolePolicyDocument", &trust),
    ]);
    role.expect(200);
    let role_arn = one(&role, "Arn");
    iam(&[
        ("Action", "PutRolePolicy"),
        ("RoleName", "reader"),
        ("PolicyName", "s3"),
        ("PolicyDocument", ALLOW_S3),
    ])
    .expect(200);
    let assume = |creds: (&str, &str, Option<&str>)| {
        c.query_api(
            "sts",
            &[
                ("Action", "AssumeRole"),
                ("RoleArn", &role_arn),
                ("RoleSessionName", "r1"),
            ],
            creds,
        )
    };
    let role_session = session(&assume((ak, sk, None)));

    // A share of the tenant's, and a recipient of it.
    c.request_as(
        "POST",
        "/_admin/shares",
        json!({"name": "acme-share"}).to_string().as_bytes(),
        ak,
        sk,
    )
    .expect_ok();
    let recipient = c.request_as(
        "POST",
        "/_admin/recipients",
        json!({"name": "acme-r", "shares": ["acme-share"]})
            .to_string()
            .as_bytes(),
        ak,
        sk,
    );
    recipient.expect_ok();

    let paths = Paths {
        c: &c,
        admin: &admin,
        user_session,
        role_session,
        presigned: c.presign_as("GET", "/acme-data/k", 3600, ak, sk),
        console: key_login(&c, ak, sk),
        bearer: recipient.json()["bearer_token"]
            .as_str()
            .unwrap()
            .to_string(),
    };

    for (path, status) in paths.statuses() {
        assert_eq!(status, 200, "{path} before the tenant is disabled");
    }
    assert_eq!(paths.shares(), 1);

    // Disabled: refused at once on the gateway that disabled it.
    set_enabled(&c, "acme", false);
    for (path, status) in paths.statuses() {
        assert_eq!(status, 403, "{path} while the tenant is disabled");
    }
    let r = c.request_as("GET", "/acme-data/k", &[], ak, sk);
    assert!(r.text().contains("AccessDenied"), "{}", r.text());
    assert_eq!(paths.shares(), 0, "a disabled tenant's share was listed");
    // No new session is made for it either, nor a role of it assumed.
    assume((ak, sk, None)).expect(403);
    let rs = &paths.role_session;
    assume((&rs.0, &rs.1, Some(&rs.2))).expect(403);
    // The system is not the tenant.
    c.request("GET", "/", &[]).expect(200);
    c.request("GET", "/_admin/tenants/acme", &[]).expect(200);
    c.request("GET", "/acme-data/k", &[]).expect(200);

    // Enabled again: everything as it was, sessions and links included.
    set_enabled(&c, "acme", true);
    for (path, status) in paths.statuses() {
        assert_eq!(status, 200, "{path} once the tenant is enabled again");
    }
    assert_eq!(paths.shares(), 1);
}
