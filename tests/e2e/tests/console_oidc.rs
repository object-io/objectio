//! Console single sign-on: who a sign-in becomes, and in which tenant.
//!
//! A sign-in is the user created for the token's issuer and subject, never
//! a user who happens to have the name the token carries. A tenant's
//! identity provider signs in to that tenant only, whatever the browser
//! asks for, and the flow's `state` is the gateway's own. Only the
//! operator's identity provider, or the system admin's own keys, give a
//! console session that administers the cluster: a system-scope user is
//! not an administrator for being in the system scope.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use objectio_e2e::Cluster;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};

/// An OIDC provider on a local port: discovery, a JWKS with one ES256 key,
/// and a token endpoint. The authorization code is the token's claims,
/// base64url JSON, merged over the defaults (a `null` drops a claim), so a
/// test says in the code who signs in.
struct Idp {
    issuer: String,
}

impl Idp {
    fn start() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        // Uncompressed point: 0x04 || x || y.
        let point = key.public_key().as_ref().to_vec();
        let jwks = json!({"keys": [{
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
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
        let iss = issuer.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (path, body) = read_request(&mut stream);
                let (status, body) = match path.as_str() {
                    "/.well-known/openid-configuration" => ("200 OK", discovery.clone()),
                    "/jwks" => ("200 OK", jwks.clone()),
                    "/token" => code_of(&body).map_or_else(
                        || {
                            (
                                "400 Bad Request",
                                json!({"error": "invalid_grant"}).to_string(),
                            )
                        },
                        |claims| {
                            (
                                "200 OK",
                                json!({
                                    "access_token": "opaque",
                                    "token_type": "Bearer",
                                    "expires_in": 300,
                                    "id_token": sign(&key, &iss, &claims),
                                })
                                .to_string(),
                            )
                        },
                    ),
                    _ => ("404 Not Found", "{}".to_string()),
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Self { issuer }
    }

    /// The provider document the gateway stores for this provider.
    fn provider(&self, extra: &Value) -> Value {
        let mut p = json!({"issuer_url": self.issuer, "client_id": "objectio"});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        p
    }
}

/// A request's path and body.
fn read_request(stream: &mut std::net::TcpStream) -> (String, String) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            return (String::new(), String::new());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let length: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().ok())?
        })
        .unwrap_or(0);
    while buf.len() < head_end + length {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let body = String::from_utf8_lossy(&buf[head_end..]).to_string();
    (path, body)
}

/// The claims an authorization code stands for.
fn code_of(form: &str) -> Option<Value> {
    let code = form.split('&').find_map(|kv| kv.strip_prefix("code="))?;
    serde_json::from_slice(&B64.decode(code).ok()?).ok()
}

/// An ID token from `issuer`: the defaults with `claims` over them.
fn sign(key: &EcdsaKeyPair, issuer: &str, claims: &Value) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut body = json!({
        "iss": issuer, "aud": "objectio", "iat": now - 10, "exp": now + 300,
    });
    for (k, v) in claims.as_object().unwrap() {
        if v.is_null() {
            body.as_object_mut().unwrap().remove(k);
        } else {
            body[k] = v.clone();
        }
    }
    let header = json!({"alg": "ES256", "typ": "JWT", "kid": "k1"});
    let input = format!(
        "{}.{}",
        B64.encode(header.to_string()),
        B64.encode(body.to_string())
    );
    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(sig.as_ref()))
}

/// A client that shows redirects instead of following them.
fn browser() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap()
}

/// The value of the cookie `name` among a response's `Set-Cookie`s.
fn set_cookie(resp: &reqwest::blocking::Response, name: &str) -> Option<String> {
    resp.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            let v = c.split(';').next()?.strip_prefix(&format!("{name}="))?;
            (!v.is_empty()).then(|| v.to_string())
        })
}

/// How a sign-in ended: the session it opened, if any, and where it sent
/// the browser.
struct SignIn {
    session: Option<String>,
    location: String,
}

/// Start a sign-in with `query` (provider, tenant): the `state`, and the
/// cookie that carries it.
fn authorize(c: &Cluster, query: &str) -> (String, String) {
    let r = browser()
        .get(format!(
            "{}/_console/api/oidc/authorize?{query}",
            c.endpoint
        ))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 302, "authorize: {}", r.status());
    let cookie = set_cookie(&r, "oidc-state").expect("an oidc-state cookie");
    let location = reqwest::Url::parse(
        r.headers()
            .get(reqwest::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let state = location
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string())
        .expect("a state in the redirect");
    (state, cookie)
}

/// Come back from the provider with `state` (and `cookie`), signed in as
/// `claims`.
fn callback(c: &Cluster, state: &str, cookie: &str, claims: &Value) -> SignIn {
    let mut url =
        reqwest::Url::parse(&format!("{}/_console/api/oidc/callback", c.endpoint)).unwrap();
    url.query_pairs_mut()
        .append_pair("code", &B64.encode(claims.to_string()))
        .append_pair("state", state);
    let r = browser()
        .get(url)
        .header("Cookie", format!("oidc-state={cookie}"))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 302, "callback: {}", r.status());
    SignIn {
        session: set_cookie(&r, "objectio-session"),
        location: r
            .headers()
            .get(reqwest::header::LOCATION)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default(),
    }
}

fn sign_in(c: &Cluster, query: &str, claims: &Value) -> SignIn {
    let (state, cookie) = authorize(c, query);
    callback(c, &state, &cookie, claims)
}

#[track_caller]
fn refused(s: &SignIn) {
    assert!(
        s.session.is_none(),
        "a session was opened; sent to {}",
        s.location
    );
    assert!(s.location.contains("error="), "{}", s.location);
}

/// A request with a console session.
fn with_session(c: &Cluster, method: &str, path: &str, session: &str) -> objectio_e2e::Response {
    c.fetch_with_headers(
        method,
        &format!("{}{path}", c.endpoint),
        &[("Cookie", &format!("objectio-session={session}"))],
    )
}

/// The status of a JSON request with a console session.
fn post_with_session(c: &Cluster, path: &str, session: &str, body: &Value) -> u16 {
    browser()
        .post(format!("{}{path}", c.endpoint))
        .header("Cookie", format!("objectio-session={session}"))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .unwrap()
        .status()
        .as_u16()
}

fn new_tenant(name: &str) -> Value {
    json!({"name": name, "display_name": name, "enabled": true})
}

fn tenant(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/tenants", new_tenant(name))
        .expect_ok();
}

fn provider(c: &Cluster, name: &str, doc: &Value) {
    c.json(
        "PUT",
        &format!("/_admin/config/identity/openid/{name}"),
        doc.clone(),
    )
    .expect_ok();
}

/// A key minted through the console for the session's own user.
fn my_key(c: &Cluster, session: &str) -> (String, String) {
    let r = with_session(c, "POST", "/_console/api/me/keys", session);
    r.expect_ok();
    let k = r.json();
    (
        k["access_key_id"].as_str().unwrap().to_string(),
        k["secret_access_key"].as_str().unwrap().to_string(),
    )
}

/// Console login with an access key.
fn key_login(c: &Cluster, ak: &str, sk: &str) -> String {
    let r = try_key_login(c, ak, sk);
    assert_eq!(r.status().as_u16(), 200, "login: {}", r.status());
    set_cookie(&r, "objectio-session").expect("a session")
}

fn try_key_login(c: &Cluster, ak: &str, sk: &str) -> reqwest::blocking::Response {
    browser()
        .post(format!("{}/_console/api/login", c.endpoint))
        .header("Content-Type", "application/json")
        .body(json!({"accessKey": ak, "secretKey": sk}).to_string())
        .send()
        .unwrap()
}

/// A user of `tenant` and a key for it, `(user_id, access_key, secret_key)`;
/// one of the tenant's admins when `admin`.
fn tenant_user(c: &Cluster, tenant: &str, name: &str, admin: bool) -> (String, String, String) {
    let user = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": name, "tenant": tenant}),
    );
    user.expect_ok();
    let id = user.json()["user_id"].as_str().unwrap().to_string();
    if admin {
        c.json(
            "POST",
            &format!("/_admin/tenants/{tenant}/admins"),
            json!({"user_id": id}),
        )
        .expect_ok();
    }
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

/// A tenant's provider handing out `preferred_username: admin` signs in as a
/// new user of that tenant: not as the system admin, whose name it is, and
/// the key it mints is no administrator's.
#[test]
fn a_tenant_sign_in_named_admin_is_not_the_system_admin() {
    let c = Cluster::start();
    let idp = Idp::start();
    tenant(&c, "acme");
    provider(&c, "t-acme", &idp.provider(&json!({})));

    let s = sign_in(
        &c,
        "provider=t-acme&tenant=acme",
        &json!({"sub": "mallory", "preferred_username": "admin"}),
    );
    refused(&s);

    // Under a name of its own it signs in, to its tenant, as itself.
    let s = sign_in(
        &c,
        "provider=t-acme&tenant=acme",
        &json!({"sub": "alice-sub", "preferred_username": "alice"}),
    );
    let session = s.session.expect("a session");
    let me = with_session(&c, "GET", "/_console/api/session", &session);
    me.expect_ok();
    let me = me.json();
    assert_eq!(me["tenant"], "acme", "{me}");
    assert_eq!(me["system_admin"], false, "{me}");
    assert_eq!(me["arn"], "arn:objectio:iam::acme:user/alice", "{me}");

    let key = my_key(&c, &session);
    c.request_as("GET", "/_admin/cluster-info", &[], &key.0, &key.1)
        .expect(403);
    with_session(&c, "GET", "/_admin/cluster-info", &session).expect(403);
    assert_eq!(
        post_with_session(&c, "/_admin/tenants", &session, &new_tenant("x")),
        403
    );

    // The same subject again is the same user, whatever name it now sends.
    let again = sign_in(
        &c,
        "provider=t-acme&tenant=acme",
        &json!({"sub": "alice-sub", "preferred_username": "admin"}),
    );
    let again = with_session(&c, "GET", "/_console/api/session", &again.session.unwrap());
    assert_eq!(again.json()["user"], me["user"]);

    // Another subject with alice's name is not alice.
    refused(&sign_in(
        &c,
        "provider=t-acme&tenant=acme",
        &json!({"sub": "not-alice", "preferred_username": "alice"}),
    ));
}

/// A tenant's provider signs in to its own tenant only, and the tenant in
/// the flow is the one the gateway signed.
#[test]
fn a_tenant_provider_cannot_sign_in_to_another_tenant() {
    let c = Cluster::start();
    let idp = Idp::start();
    let theirs = Idp::start();
    tenant(&c, "acme");
    tenant(&c, "other");
    provider(&c, "t-acme", &idp.provider(&json!({})));
    provider(&c, "t-other", &theirs.provider(&json!({})));

    let bob = json!({"sub": "bob-sub", "preferred_username": "bob"});
    refused(&sign_in(&c, "provider=t-acme&tenant=other", &bob));

    // A state the gateway did not sign is refused, even with a cookie to
    // match.
    let forged = "abc:t-acme:other";
    refused(&callback(&c, forged, forged, &bob));
    // A state comes back only to the browser it was handed to.
    let (state, _) = authorize(&c, "provider=t-acme&tenant=acme");
    let (_, other_cookie) = authorize(&c, "provider=t-acme&tenant=acme");
    refused(&callback(&c, &state, &other_cookie, &bob));

    // A token without an issuer is no token.
    refused(&sign_in(
        &c,
        "provider=t-acme&tenant=acme",
        &json!({"sub": "bob-sub", "preferred_username": "bob", "iss": null}),
    ));

    // Its own tenant it signs in to.
    let s = sign_in(&c, "provider=t-acme&tenant=acme", &bob);
    let me = with_session(&c, "GET", "/_console/api/session", &s.session.unwrap());
    assert_eq!(me.json()["tenant"], "acme");
}

/// A system-scope user is not an administrator for being in the system
/// scope; the system admin and the operator's provider are.
#[test]
fn a_system_scope_user_is_refused_what_only_administrators_see() {
    let c = Cluster::start();
    tenant(&c, "acme");
    let user = c.json("POST", "/_admin/users", json!({"display_name": "viewer"}));
    user.expect_ok();
    let id = user.json()["user_id"].as_str().unwrap().to_string();
    let k = c.json(
        "POST",
        &format!("/_admin/users/{id}/access-keys"),
        json!({}),
    );
    k.expect_ok();
    let k = k.json();
    let viewer = key_login(
        &c,
        k["access_key_id"].as_str().unwrap(),
        k["secret_access_key"].as_str().unwrap(),
    );

    let tenants = with_session(&c, "GET", "/_admin/tenants", &viewer);
    tenants.expect_ok();
    assert_eq!(tenants.json(), json!([]), "{}", tenants.text());
    for path in [
        "/_admin/cluster-info",
        "/_admin/topology",
        "/_admin/placement/validate?pool=default",
        "/_admin/warehouses",
        "/_admin/metrics/query?query=up",
    ] {
        with_session(&c, "GET", path, &viewer).expect(403);
    }
    assert_eq!(
        post_with_session(&c, "/_admin/tenants", &viewer, &new_tenant("x")),
        403
    );

    // The system admin's own console session is an administrator's.
    let admin = key_login(&c, &c.access_key, &c.secret_key);
    with_session(&c, "GET", "/_admin/cluster-info", &admin).expect(200);
    let tenants = with_session(&c, "GET", "/_admin/tenants", &admin);
    assert!(tenants.text().contains("acme"), "{}", tenants.text());

    // As is a sign-in through the operator's provider; the key it mints is
    // its user's, which administers nothing.
    let ops = Idp::start();
    provider(&c, "ops", &ops.provider(&json!({"system_admin": true})));
    let s = sign_in(
        &c,
        "provider=ops",
        &json!({"sub": "op-1", "preferred_username": "operator"}),
    );
    let session = s.session.expect("a session");
    with_session(&c, "GET", "/_admin/cluster-info", &session).expect(200);
    let key = my_key(&c, &session);
    c.request_as("GET", "/_admin/cluster-info", &[], &key.0, &key.1)
        .expect(403);

    // A tenant admin's session lists its own tenant's warehouses, and no
    // more; a tenant user's lists none.
    let idp = Idp::start();
    provider(
        &c,
        "t-acme",
        &idp.provider(&json!({"tenant_admin_role": "acme-admins"})),
    );
    let s = sign_in(
        &c,
        "provider=t-acme&tenant=acme",
        &json!({"sub": "carol-sub", "preferred_username": "carol", "groups": ["acme-admins"]}),
    );
    let carol = s.session.expect("a session");
    with_session(&c, "GET", "/_admin/warehouses", &carol).expect(200);
    with_session(&c, "GET", "/_admin/cluster-info", &carol).expect(403);
    let s = sign_in(
        &c,
        "provider=t-acme&tenant=acme",
        &json!({"sub": "dave-sub", "preferred_username": "dave"}),
    );
    let dave = s.session.expect("a session");
    with_session(&c, "GET", "/_admin/warehouses", &dave).expect(403);
}

/// A tenant admin changes only a provider no other tenant uses: one that
/// signs users in to another tenant is the system admin's to change, however
/// it is bound there (that tenant naming it, or its `t-<tenant>` name).
#[test]
fn a_tenant_admin_changes_only_a_provider_no_other_tenant_uses() {
    let c = Cluster::start();
    let idp = Idp::start();
    tenant(&c, "acme");
    tenant(&c, "other");
    let (_, ak, sk) = tenant_user(&c, "acme", "acme-admin", true);
    let doc = idp.provider(&json!({}));
    let body = doc.to_string().into_bytes();
    let disabled = idp
        .provider(&json!({"enabled": false}))
        .to_string()
        .into_bytes();

    // One provider, named by both tenants.
    provider(&c, "shared", &doc);
    for t in ["acme", "other"] {
        c.json(
            "PUT",
            &format!("/_admin/tenants/{t}"),
            json!({"oidc_provider": "shared"}),
        )
        .expect_ok();
    }
    let shared = "/_admin/config/identity/openid/shared";
    c.request_as("PUT", shared, &body, &ak, &sk).expect(403);
    c.request_as("PUT", shared, &disabled, &ak, &sk).expect(403);
    c.request_as("DELETE", shared, &[], &ak, &sk).expect(403);
    // The system admin still can.
    c.request("PUT", shared, &body).expect_ok();

    // Its own provider, which no other tenant uses, it can.
    let own = "/_admin/config/identity/openid/t-acme";
    c.request_as("PUT", own, &body, &ak, &sk).expect_ok();
    // A tenant's user who isn't one of its admins can't.
    let (_, uak, usk) = tenant_user(&c, "acme", "acme-user", false);
    c.request_as("PUT", own, &body, &uak, &usk).expect(403);

    // Once another tenant names it, it is shared too.
    c.json(
        "PUT",
        "/_admin/tenants/other",
        json!({"oidc_provider": "t-acme"}),
    )
    .expect_ok();
    c.request_as("PUT", own, &disabled, &ak, &sk).expect(403);
    c.request_as("DELETE", own, &[], &ak, &sk).expect(403);
}

/// A disabled tenant's users sign in to nothing: not through its provider,
/// not with a key.
#[test]
fn a_disabled_tenant_signs_in_to_nothing() {
    let c = Cluster::start();
    let idp = Idp::start();
    tenant(&c, "acme");
    provider(&c, "t-acme", &idp.provider(&json!({})));
    let (_, ak, sk) = tenant_user(&c, "acme", "acme-user", false);
    let dave = json!({"sub": "dave-sub", "preferred_username": "dave"});
    assert!(
        sign_in(&c, "provider=t-acme&tenant=acme", &dave)
            .session
            .is_some()
    );
    key_login(&c, &ak, &sk);

    c.json("PUT", "/_admin/tenants/acme", json!({"enabled": false}))
        .expect_ok();
    refused(&sign_in(&c, "provider=t-acme&tenant=acme", &dave));
    let r = try_key_login(&c, &ak, &sk);
    assert_eq!(r.status().as_u16(), 403);
    assert!(set_cookie(&r, "objectio-session").is_none());
}
