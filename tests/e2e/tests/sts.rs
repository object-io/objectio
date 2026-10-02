//! STS `AssumeRoleWithWebIdentity`: an OIDC token for a role's temporary
//! keys. The operator's identity provider vouches only for system roles; a
//! tenant's own provider only for that tenant's roles. The role's trust
//! policy decides who may assume it, and the keys can do what the role's
//! policies allow inside the role's tenant, and nothing else.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use objectio_e2e::{Cluster, Response};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};

/// An OIDC issuer on a local port: discovery, a JWKS with one ES256 key,
/// and tokens signed by it.
struct Idp {
    issuer: String,
    key: EcdsaKeyPair,
}

impl Idp {
    fn start(kid: &'static str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        // Uncompressed point: 0x04 || x || y.
        let point = key.public_key().as_ref().to_vec();
        let jwks = json!({"keys": [{
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
            "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65]),
        }]})
        .to_string();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let discovery = json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
            "token_endpoint": format!("{issuer}/token"),
            "authorization_endpoint": format!("{issuer}/authorize"),
        })
        .to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                let path = head.split_whitespace().nth(1).unwrap_or_default();
                let (status, body) = match path {
                    "/.well-known/openid-configuration" => ("200 OK", discovery.as_str()),
                    "/jwks" => ("200 OK", jwks.as_str()),
                    _ => ("404 Not Found", "{}"),
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Self { issuer, key }
    }

    /// The issuer as policies name it: no scheme.
    fn host(&self) -> &str {
        self.issuer.trim_start_matches("http://")
    }

    /// A signed token for `sub`, valid for `ttl` seconds (negative: expired).
    fn token(&self, kid: &str, sub: &str, ttl: i64) -> String {
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": kid});
        let claims = json!({
            "iss": self.issuer, "aud": "objectio", "sub": sub,
            "iat": now - 10, "exp": now + ttl, "groups": ["eng"],
        });
        let signing_input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = self
            .key
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .unwrap();
        format!("{signing_input}.{}", B64.encode(sig.as_ref()))
    }
}

fn provider(idp: &Idp, system_admin: bool) -> Value {
    json!({"issuer_url": idp.issuer, "client_id": "objectio", "system_admin": system_admin})
}

fn trust(idp: &Idp, sub: &str) -> Value {
    json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": idp.issuer},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {format!("{}:sub", idp.host()): sub}},
    }]})
}

fn allow_bucket(bucket: &str) -> Value {
    json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "s3:*",
        "Resource": [format!("arn:obio:s3:::{bucket}"), format!("arn:obio:s3:::{bucket}/*")],
    }]})
}

/// Create a tenant with an admin key: `(access_key, secret_key)`.
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
    body: &Value,
) -> Response {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    c.request_as(method, path, &bytes, ak, sk)
}

/// `AssumeRoleWithWebIdentity`, unsigned, as an SDK sends it.
fn assume(c: &Cluster, role_arn: &str, token: &str) -> Response {
    let body = format!(
        "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleSessionName=e2e\
         &RoleArn={}&WebIdentityToken={token}",
        role_arn.replace(':', "%3A").replace('/', "%2F")
    );
    c.fetch("POST", &format!("{}/", c.endpoint), body.as_bytes())
}

fn field(xml: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let start = xml
        .find(&open)
        .unwrap_or_else(|| panic!("no {tag} in {xml}"))
        + open.len();
    let end = xml[start..].find(&format!("</{tag}>")).unwrap() + start;
    xml[start..end].to_string()
}

fn creds(r: &Response) -> (String, String, String) {
    assert_eq!(r.status, 200, "{}", r.text());
    let x = r.text();
    (
        field(&x, "AccessKeyId"),
        field(&x, "SecretAccessKey"),
        field(&x, "SessionToken"),
    )
}

fn with(
    c: &Cluster,
    k: &(String, String, String),
    method: &str,
    path: &str,
    body: &[u8],
) -> Response {
    c.request_as_session(method, path, body, (&k.0, &k.1, &k.2))
}

/// acme's role "ci": alice, via acme's identity provider; read-write on
/// acme-data.
fn acme_role(c: &Cluster, acme: &(String, String), acme_idp: &Idp) -> &'static str {
    as_user(
        c,
        acme,
        "POST",
        "/_admin/policies",
        &json!({"name": "data-rw", "policy": allow_bucket("acme-data")}),
    )
    .expect(201);
    as_user(
        c,
        acme,
        "POST",
        "/_admin/roles",
        &json!({"name": "ci", "trust_policy": trust(acme_idp, "alice")}),
    )
    .expect(201);
    as_user(
        c,
        acme,
        "POST",
        "/_admin/policies/attach",
        &json!({"policy_name": "data-rw", "role_name": "ci"}),
    )
    .expect(200);
    "arn:obio:iam::acme:role/ci"
}

/// Each scope trusts only its own identity provider, the trust policy
/// picks who, and the keys stay inside the role's tenant and policies.
#[test]
fn a_tenants_idp_vouches_only_for_its_tenants_roles() {
    let c = Cluster::start();
    let ops_idp = Idp::start("ops-key");
    let acme_idp = Idp::start("acme-key");

    let acme = tenant_admin(&c, "acme");
    let globex = tenant_admin(&c, "globex");
    c.json(
        "PUT",
        "/_admin/config/identity/openid/ops",
        provider(&ops_idp, true),
    )
    .expect_ok();

    // A tenant admin brings the tenant's own IdP, and cannot make it the
    // operator's.
    let r = as_user(
        &c,
        &acme,
        "PUT",
        "/_admin/config/identity/openid/t-acme",
        &provider(&acme_idp, true),
    );
    assert_eq!(r.status, 403, "{}", r.text());
    as_user(
        &c,
        &acme,
        "PUT",
        "/_admin/config/identity/openid/t-acme",
        &provider(&acme_idp, false),
    )
    .expect_ok();
    let r = as_user(
        &c,
        &acme,
        "PUT",
        "/_admin/config/identity/openid/ops",
        &provider(&acme_idp, false),
    );
    assert_eq!(r.status, 403, "{}", r.text());

    // Data: two buckets in acme, one in globex.
    for b in ["/acme-data", "/acme-other"] {
        as_user(&c, &acme, "PUT", b, &Value::Null).expect(200);
    }
    as_user(&c, &globex, "PUT", "/globex-data", &Value::Null).expect(200);
    c.request_as("PUT", "/globex-data/k", b"globex", &globex.0, &globex.1)
        .expect(200);

    let ci = acme_role(&c, &acme, &acme_idp);

    // The operator's IdP cannot vouch for a tenant's role, even for the
    // same subject; nor can a token signed by one IdP naming the other.
    let r = assume(&c, ci, &ops_idp.token("ops-key", "alice", 300));
    assert_eq!(r.status, 400, "{}", r.text());
    assert!(r.text().contains("InvalidIdentityToken"), "{}", r.text());
    // The trust policy picks the subject.
    let r = assume(&c, ci, &acme_idp.token("acme-key", "bob", 300));
    assert_eq!(r.status, 403, "{}", r.text());
    // An expired token is refused as such.
    let r = assume(&c, ci, &acme_idp.token("acme-key", "alice", -600));
    assert!(r.text().contains("ExpiredTokenException"), "{}", r.text());
    // An unknown role answers like a refused token.
    let r = assume(
        &c,
        "arn:obio:iam::acme:role/nope",
        &acme_idp.token("acme-key", "alice", 300),
    );
    assert_eq!(r.status, 403, "{}", r.text());

    let r = assume(&c, ci, &acme_idp.token("acme-key", "alice", 300));
    let k = creds(&r);
    assert!(k.0.starts_with("ASIA"), "{}", k.0);
    assert_eq!(
        field(&r.text(), "Arn"),
        "arn:obio:sts::acme:assumed-role/ci/e2e"
    );

    // What the role's policy allows, in its tenant.
    with(&c, &k, "PUT", "/acme-data/k", b"from ci").expect(200);
    assert_eq!(with(&c, &k, "GET", "/acme-data/k", &[]).bytes, b"from ci");
    // Not the tenant's other bucket: the policy doesn't name it.
    assert_eq!(with(&c, &k, "PUT", "/acme-other/k", b"x").status, 403);
    // Not another tenant's data, whatever a policy says.
    assert_eq!(with(&c, &k, "GET", "/globex-data/k", &[]).status, 403);
    // Not the admin API.
    assert_eq!(with(&c, &k, "GET", "/_admin/users", &[]).status, 403);
    // A tampered session token is worthless.
    let forged = (k.0.clone(), k.1.clone(), format!("{}x", k.2));
    assert_eq!(with(&c, &forged, "GET", "/acme-data/k", &[]).status, 403);

    // Detaching the policy takes effect for live sessions.
    as_user(
        &c,
        &acme,
        "POST",
        "/_admin/policies/detach",
        &json!({"policy_name": "data-rw", "role_name": "ci"}),
    )
    .expect(200);
    assert_eq!(with(&c, &k, "GET", "/acme-data/k", &[]).status, 403);
}

/// A system role trusts only the operator's identity provider.
#[test]
fn the_operators_idp_vouches_only_for_system_roles() {
    let c = Cluster::start();
    let ops_idp = Idp::start("ops-key");
    let acme_idp = Idp::start("acme-key");
    let acme = tenant_admin(&c, "acme");
    c.json(
        "PUT",
        "/_admin/config/identity/openid/ops",
        provider(&ops_idp, true),
    )
    .expect_ok();
    as_user(
        &c,
        &acme,
        "PUT",
        "/_admin/config/identity/openid/t-acme",
        &provider(&acme_idp, false),
    )
    .expect_ok();

    c.request("PUT", "/ops-bucket", &[]).expect(200);
    c.request("PUT", "/ops-bucket/k", b"ops").expect(200);
    c.json(
        "POST",
        "/_admin/policies",
        json!({"name": "ops-read", "policy": allow_bucket("ops-bucket")}),
    )
    .expect(201);
    c.json(
        "POST",
        "/_admin/roles",
        json!({"name": "oncall", "trust_policy": trust(&ops_idp, "carol"), "max_session_seconds": 900}),
    )
    .expect(201);
    c.json(
        "POST",
        "/_admin/policies/attach",
        json!({"policy_name": "ops-read", "role_name": "oncall"}),
    )
    .expect(200);
    let oncall = "arn:obio:iam::objectio:role/oncall";

    // A tenant's IdP cannot vouch for a system role.
    let r = assume(&c, oncall, &acme_idp.token("acme-key", "carol", 300));
    assert_eq!(r.status, 400, "{}", r.text());
    assert!(r.text().contains("InvalidIdentityToken"), "{}", r.text());

    let k = creds(&assume(&c, oncall, &ops_idp.token("ops-key", "carol", 300)));
    assert_eq!(with(&c, &k, "GET", "/ops-bucket/k", &[]).bytes, b"ops");
    // A system role is no system admin.
    assert_eq!(with(&c, &k, "GET", "/_admin/users", &[]).status, 403);

    // Asking for longer than the role allows is refused.
    let body = format!(
        "Action=AssumeRoleWithWebIdentity&RoleSessionName=e2e&DurationSeconds=3600\
         &RoleArn={}&WebIdentityToken={}",
        oncall.replace(':', "%3A").replace('/', "%2F"),
        ops_idp.token("ops-key", "carol", 300)
    );
    let r = c.fetch("POST", &format!("{}/", c.endpoint), body.as_bytes());
    assert_eq!(r.status, 400, "{}", r.text());
    assert!(r.text().contains("ValidationError"), "{}", r.text());
}
