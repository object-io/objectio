//! The AWS IAM and STS query APIs (`aws iam`, `aws sts`, boto3) over the
//! same users, groups, policies, keys and roles as the admin API: a
//! tenant is an account, its admins its root; keys made through IAM work
//! for S3 at once; one tenant can't see another's; a role assumed through
//! STS acts with the role's policies.

use objectio_e2e::{Cluster, Response};
use serde_json::json;

type Creds = (String, String);

/// A tenant with an admin, through the admin API: the admin's keys.
fn tenant_with_admin(c: &Cluster, tenant: &str) -> Creds {
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
    let user_id = user.json()["user_id"].as_str().unwrap().to_string();
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
        k["access_key_id"].as_str().unwrap().to_string(),
        k["secret_access_key"].as_str().unwrap().to_string(),
    )
}

fn iam(c: &Cluster, who: &Creds, params: &[(&str, &str)]) -> Response {
    c.query_api("iam", params, (&who.0, &who.1, None))
}

fn sts(c: &Cluster, who: (&str, &str, Option<&str>), params: &[(&str, &str)]) -> Response {
    c.query_api("sts", params, who)
}

/// Every `<tag>…</tag>` in a body, in order.
fn all(r: &Response, tag: &str) -> Vec<String> {
    let text = r.text();
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(j) = after.find(&close) else { break };
        out.push(after[..j].to_string());
        rest = &after[j + close.len()..];
    }
    out
}

#[track_caller]
fn one(r: &Response, tag: &str) -> String {
    all(r, tag)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no <{tag}> in {}", r.text()))
}

/// A URL-encoded value (IAM sends policy documents so).
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap();
            out.push(u8::from_str_radix(hex, 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

#[track_caller]
fn error_code(r: &Response) -> String {
    one(r, "Code")
}

/// A user of the caller's account with a key: its keys.
fn user_with_key(c: &Cluster, admin: &Creds, name: &str) -> Creds {
    iam(c, admin, &[("Action", "CreateUser"), ("UserName", name)]).expect(200);
    let k = iam(
        c,
        admin,
        &[("Action", "CreateAccessKey"), ("UserName", name)],
    );
    k.expect(200);
    (one(&k, "AccessKeyId"), one(&k, "SecretAccessKey"))
}

const ALLOW_S3: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;

#[test]
#[allow(clippy::too_many_lines)] // one account's life, start to finish
fn users_groups_and_policies_round_trip() {
    let c = Cluster::start();
    let root = tenant_with_admin(&c, "acme");

    // The account's root, as AWS names it.
    let me = sts(
        &c,
        (&root.0, &root.1, None),
        &[("Action", "GetCallerIdentity")],
    );
    me.expect(200);
    assert_eq!(one(&me, "Arn"), "arn:aws:iam::acme:root");
    assert_eq!(one(&me, "Account"), "acme");

    let u = iam(
        &c,
        &root,
        &[
            ("Action", "CreateUser"),
            ("UserName", "Alice"),
            ("Path", "/team/"),
        ],
    );
    u.expect(200);
    assert_eq!(one(&u, "Arn"), "arn:aws:iam::acme:user/team/Alice");
    assert_eq!(one(&u, "Path"), "/team/");
    // Names are case-insensitive.
    let again = iam(
        &c,
        &root,
        &[("Action", "CreateUser"), ("UserName", "alice")],
    );
    again.expect(409);
    assert_eq!(error_code(&again), "EntityAlreadyExists");
    let got = iam(&c, &root, &[("Action", "GetUser"), ("UserName", "ALICE")]);
    assert_eq!(one(&got, "UserId"), one(&u, "UserId"));
    let listed = iam(
        &c,
        &root,
        &[("Action", "ListUsers"), ("PathPrefix", "/team/")],
    );
    assert_eq!(all(&listed, "UserName"), vec!["Alice"]);

    // The same record the admin API manages.
    let admin_view = c.request("GET", "/_admin/users", &[]).json();
    let user = admin_view["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["display_name"] == "Alice")
        .expect("Alice through the admin API")
        .clone();
    assert_eq!(user["tenant"], "acme");
    assert_eq!(user["user_id"].as_str().unwrap(), one(&u, "UserId"));

    // Groups.
    iam(
        &c,
        &root,
        &[("Action", "CreateGroup"), ("GroupName", "devs")],
    )
    .expect(200);
    iam(
        &c,
        &root,
        &[
            ("Action", "AddUserToGroup"),
            ("GroupName", "devs"),
            ("UserName", "alice"),
        ],
    )
    .expect(200);
    let g = iam(&c, &root, &[("Action", "GetGroup"), ("GroupName", "devs")]);
    assert_eq!(all(&g, "UserName"), vec!["Alice"]);
    let for_user = iam(
        &c,
        &root,
        &[("Action", "ListGroupsForUser"), ("UserName", "Alice")],
    );
    assert_eq!(all(&for_user, "GroupName"), vec!["devs"]);

    // An inline policy, an AWS managed one, and the account's own.
    iam(
        &c,
        &root,
        &[
            ("Action", "PutUserPolicy"),
            ("UserName", "Alice"),
            ("PolicyName", "s3"),
            ("PolicyDocument", ALLOW_S3),
        ],
    )
    .expect(200);
    let doc = iam(
        &c,
        &root,
        &[
            ("Action", "GetUserPolicy"),
            ("UserName", "Alice"),
            ("PolicyName", "s3"),
        ],
    );
    let decoded = url_decode(&one(&doc, "PolicyDocument"));
    assert_eq!(decoded, ALLOW_S3);
    let ro = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess";
    iam(
        &c,
        &root,
        &[
            ("Action", "AttachUserPolicy"),
            ("UserName", "Alice"),
            ("PolicyArn", ro),
        ],
    )
    .expect(200);
    let created = iam(
        &c,
        &root,
        &[
            ("Action", "CreatePolicy"),
            ("PolicyName", "team-s3"),
            ("PolicyDocument", ALLOW_S3),
        ],
    );
    created.expect(200);
    let own_arn = one(&created, "Arn");
    assert_eq!(own_arn, "arn:aws:iam::acme:policy/team-s3");
    iam(
        &c,
        &root,
        &[
            ("Action", "AttachGroupPolicy"),
            ("GroupName", "devs"),
            ("PolicyArn", &own_arn),
        ],
    )
    .expect(200);
    let attached = iam(
        &c,
        &root,
        &[
            ("Action", "ListAttachedUserPolicies"),
            ("UserName", "Alice"),
        ],
    );
    assert_eq!(all(&attached, "PolicyArn"), vec![ro.to_string()]);
    let attached = iam(
        &c,
        &root,
        &[
            ("Action", "ListAttachedGroupPolicies"),
            ("GroupName", "devs"),
        ],
    );
    assert_eq!(all(&attached, "PolicyArn"), vec![own_arn.clone()]);

    // Deleting a user with things hanging off it is a conflict, as in IAM.
    let conflict = iam(
        &c,
        &root,
        &[("Action", "DeleteUser"), ("UserName", "Alice")],
    );
    conflict.expect(409);
    assert_eq!(error_code(&conflict), "DeleteConflict");
    for params in [
        vec![
            ("Action", "DetachUserPolicy"),
            ("UserName", "Alice"),
            ("PolicyArn", ro),
        ],
        vec![
            ("Action", "DeleteUserPolicy"),
            ("UserName", "Alice"),
            ("PolicyName", "s3"),
        ],
        vec![
            ("Action", "RemoveUserFromGroup"),
            ("GroupName", "devs"),
            ("UserName", "Alice"),
        ],
        vec![("Action", "DeleteUser"), ("UserName", "Alice")],
        vec![
            ("Action", "DetachGroupPolicy"),
            ("GroupName", "devs"),
            ("PolicyArn", own_arn.as_str()),
        ],
        vec![("Action", "DeleteGroup"), ("GroupName", "devs")],
        vec![("Action", "DeletePolicy"), ("PolicyArn", own_arn.as_str())],
    ] {
        iam(&c, &root, &params).expect(200);
    }
    let gone = iam(&c, &root, &[("Action", "GetUser"), ("UserName", "Alice")]);
    gone.expect(404);
    assert_eq!(error_code(&gone), "NoSuchEntity");
    // The account's own policy is gone too.
    let r = iam(
        &c,
        &root,
        &[("Action", "GetPolicy"), ("PolicyArn", own_arn.as_str())],
    );
    r.expect(404);
}

#[test]
fn keys_made_through_iam_work_for_s3_and_policies_bind_them() {
    let c = Cluster::start();
    let root = tenant_with_admin(&c, "acme");
    let bob = user_with_key(&c, &root, "bob");

    // A user's own bucket, with its new key.
    c.request_as("PUT", "/bob-bucket", &[], &bob.0, &bob.1)
        .expect(200);
    c.request_as("PUT", "/bob-bucket/a", b"one", &bob.0, &bob.1)
        .expect(200);

    // An inline Deny binds at once (this gateway drops its cache).
    iam(
        &c,
        &root,
        &[
            ("Action", "PutUserPolicy"),
            ("UserName", "bob"),
            ("PolicyName", "no-writes"),
            (
                "PolicyDocument",
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:PutObject","Resource":"*"}]}"#,
            ),
        ],
    )
    .expect(200);
    c.request_as("PUT", "/bob-bucket/b", b"two", &bob.0, &bob.1)
        .expect(403);
    c.request_as("GET", "/bob-bucket/a", &[], &bob.0, &bob.1)
        .expect(200);

    // A key deactivated through IAM stops working; one deleted is gone.
    iam(
        &c,
        &root,
        &[
            ("Action", "UpdateAccessKey"),
            ("UserName", "bob"),
            ("AccessKeyId", &bob.0),
            ("Status", "Inactive"),
        ],
    )
    .expect(200);
    c.request_as("GET", "/bob-bucket/a", &[], &bob.0, &bob.1)
        .expect(403);
    let keys = iam(
        &c,
        &root,
        &[("Action", "ListAccessKeys"), ("UserName", "bob")],
    );
    assert_eq!(all(&keys, "Status"), vec!["Inactive"]);
    iam(
        &c,
        &root,
        &[
            ("Action", "DeleteAccessKey"),
            ("UserName", "bob"),
            ("AccessKeyId", &bob.0),
        ],
    )
    .expect(200);
    let r = iam(
        &c,
        &root,
        &[
            ("Action", "DeleteAccessKey"),
            ("UserName", "bob"),
            ("AccessKeyId", &bob.0),
        ],
    );
    r.expect(404);
}

#[test]
fn an_account_sees_only_itself_and_users_need_policies() {
    let c = Cluster::start();
    let acme = tenant_with_admin(&c, "acme");
    let globex = tenant_with_admin(&c, "globex");
    iam(
        &c,
        &globex,
        &[("Action", "CreateUser"), ("UserName", "gina")],
    )
    .expect(200);

    // Another tenant's user doesn't exist for acme.
    let r = iam(&c, &acme, &[("Action", "GetUser"), ("UserName", "gina")]);
    r.expect(404);
    let r = iam(
        &c,
        &acme,
        &[
            ("Action", "PutUserPolicy"),
            ("UserName", "gina"),
            ("PolicyName", "p"),
            ("PolicyDocument", ALLOW_S3),
        ],
    );
    r.expect(404);
    let listed = iam(&c, &acme, &[("Action", "ListUsers")]);
    assert!(!all(&listed, "UserName").contains(&"gina".to_string()));

    // An ordinary user may make only what its policies allow.
    let dan = user_with_key(&c, &acme, "dan");
    let r = iam(&c, &dan, &[("Action", "ListUsers")]);
    r.expect(403);
    assert_eq!(error_code(&r), "AccessDenied");
    iam(
        &c,
        &acme,
        &[
            ("Action", "AttachUserPolicy"),
            ("UserName", "dan"),
            ("PolicyArn", "arn:aws:iam::aws:policy/IAMReadOnlyAccess"),
        ],
    )
    .expect(200);
    let listed = iam(&c, &dan, &[("Action", "ListUsers")]);
    listed.expect(200);
    assert!(all(&listed, "UserName").contains(&"dan".to_string()));
    // Read-only: no writes, and still nothing of globex's.
    iam(&c, &dan, &[("Action", "CreateUser"), ("UserName", "eve")]).expect(403);
    iam(&c, &dan, &[("Action", "GetUser"), ("UserName", "gina")]).expect(404);
    // An S3 grant is not an IAM one.
    iam(
        &c,
        &acme,
        &[
            ("Action", "AttachUserPolicy"),
            ("UserName", "dan"),
            ("PolicyArn", "arn:aws:iam::aws:policy/AmazonS3FullAccess"),
        ],
    )
    .expect(200);
    iam(&c, &dan, &[("Action", "CreateUser"), ("UserName", "eve")]).expect(403);

    // A key scoped to a bucket makes no IAM calls at all.
    let scoped = c.json(
        "POST",
        &format!(
            "/_admin/users/{}/access-keys",
            one(
                &iam(&c, &acme, &[("Action", "GetUser"), ("UserName", "dan")]),
                "UserId"
            )
        ),
        json!({"scope": "s3://dan-bucket/"}),
    );
    scoped.expect_ok();
    let s = scoped.json();
    let scoped: Creds = (
        s["access_key_id"].as_str().unwrap().into(),
        s["secret_access_key"].as_str().unwrap().into(),
    );
    iam(&c, &scoped, &[("Action", "ListUsers")]).expect(403);

    // Unsigned, an IAM call is refused; S3 at / is untouched.
    let r = c.fetch("POST", &format!("{}/?Action=ListUsers", c.endpoint), &[]);
    r.expect(403);
    c.request("GET", "/", &[]).expect(200);
}

#[test]
#[allow(clippy::too_many_lines)] // a role's life, start to finish
fn assumed_role_and_session_credentials_work_for_s3() {
    let c = Cluster::start();
    let root = tenant_with_admin(&c, "acme");
    let bob = user_with_key(&c, &root, "bob");
    let carol = user_with_key(&c, &root, "carol");
    c.request_as("PUT", "/shared", &[], &root.0, &root.1)
        .expect(200);

    let bob_arn = one(
        &iam(&c, &root, &[("Action", "GetUser"), ("UserName", "bob")]),
        "Arn",
    );
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{bob_arn}"}},"Action":"sts:AssumeRole"}}]}}"#
    );
    let role = iam(
        &c,
        &root,
        &[
            ("Action", "CreateRole"),
            ("RoleName", "writer"),
            ("Path", "/apps/"),
            ("AssumeRolePolicyDocument", &trust),
        ],
    );
    role.expect(200);
    let role_arn = one(&role, "Arn");
    assert_eq!(role_arn, "arn:aws:iam::acme:role/apps/writer");

    // Only who the trust policy names may assume it.
    let r = sts(
        &c,
        (&carol.0, &carol.1, None),
        &[
            ("Action", "AssumeRole"),
            ("RoleArn", &role_arn),
            ("RoleSessionName", "c1"),
        ],
    );
    r.expect(403);
    let assumed = sts(
        &c,
        (&bob.0, &bob.1, None),
        &[
            ("Action", "AssumeRole"),
            ("RoleArn", &role_arn),
            ("RoleSessionName", "b1"),
        ],
    );
    assumed.expect(200);
    let session = (
        one(&assumed, "AccessKeyId"),
        one(&assumed, "SecretAccessKey"),
        one(&assumed, "SessionToken"),
    );
    let creds = (session.0.as_str(), session.1.as_str(), session.2.as_str());
    assert_eq!(
        one(&assumed, "Arn"),
        "arn:aws:sts::acme:assumed-role/writer/b1"
    );
    let who = sts(
        &c,
        (creds.0, creds.1, Some(creds.2)),
        &[("Action", "GetCallerIdentity")],
    );
    assert_eq!(one(&who, "Arn"), "arn:aws:sts::acme:assumed-role/writer/b1");
    assert_eq!(one(&who, "UserId"), format!("{}:b1", one(&role, "RoleId")));

    // The role can do what its policies allow: nothing yet, then writes.
    c.request_as_session("PUT", "/shared/x", b"x", creds)
        .expect(403);
    iam(
        &c,
        &root,
        &[
            ("Action", "PutRolePolicy"),
            ("RoleName", "writer"),
            ("PolicyName", "s3"),
            ("PolicyDocument", ALLOW_S3),
        ],
    )
    .expect(200);
    c.request_as_session("PUT", "/shared/x", b"x", creds)
        .expect(200);

    // A user's own session acts as the user: its own bucket, not root's.
    let st = sts(
        &c,
        (&bob.0, &bob.1, None),
        &[("Action", "GetSessionToken"), ("DurationSeconds", "900")],
    );
    st.expect(200);
    let (key, secret, token) = (
        one(&st, "AccessKeyId"),
        one(&st, "SecretAccessKey"),
        one(&st, "SessionToken"),
    );
    let who = sts(
        &c,
        (&key, &secret, Some(&token)),
        &[("Action", "GetCallerIdentity")],
    );
    assert_eq!(one(&who, "Arn"), bob_arn);
    c.request_as_session("PUT", "/bob-own", &[], (&key, &secret, &token))
        .expect(200);
    c.request_as_session("PUT", "/shared/y", b"y", (&key, &secret, &token))
        .expect(403);

    // A role with policies can't be deleted until they're gone.
    let r = iam(
        &c,
        &root,
        &[("Action", "DeleteRole"), ("RoleName", "writer")],
    );
    r.expect(409);
    iam(
        &c,
        &root,
        &[
            ("Action", "DeleteRolePolicy"),
            ("RoleName", "writer"),
            ("PolicyName", "s3"),
        ],
    )
    .expect(200);
    iam(
        &c,
        &root,
        &[("Action", "DeleteRole"), ("RoleName", "writer")],
    )
    .expect(200);
    // A role recreated under the name starts with nothing.
    iam(
        &c,
        &root,
        &[
            ("Action", "CreateRole"),
            ("RoleName", "writer"),
            ("AssumeRolePolicyDocument", &trust),
        ],
    )
    .expect(200);
    let listed = iam(
        &c,
        &root,
        &[("Action", "ListRolePolicies"), ("RoleName", "writer")],
    );
    assert!(all(&listed, "member").is_empty(), "{}", listed.text());
}
