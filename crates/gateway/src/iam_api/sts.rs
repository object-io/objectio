//! The signed STS calls: `GetCallerIdentity`, `GetSessionToken` and
//! `AssumeRole`. (`AssumeRoleWithWebIdentity` is unsigned: `sts_api`.)
//!
//! Their credentials are the same temporary keys as a web identity's, so
//! they work against S3 at once: an assumed role's session acts as the
//! role (its policies, its tenant), a user's session as the user.

use std::time::Duration;

use axum::http::StatusCode;
use axum::response::Response;
use objectio_auth::policy::{PolicyDecision, RequestContext};
use objectio_auth::{AuthMode, BucketPolicy, Operation};

use super::{
    Actor, Call, IamError, IamResult, STS_NS, Xml, aws_account, aws_arn, iso, max_session, role_id,
};
use crate::auth_middleware::{USER_SESSION_PREFIX, USER_SESSION_SCOPE};

pub(super) async fn dispatch(call: &Call<'_>) -> IamResult<Response> {
    match call.action {
        "GetCallerIdentity" => get_caller_identity(call).await,
        "GetSessionToken" => get_session_token(call).await,
        "AssumeRole" => assume_role(call).await,
        other => Err(IamError::new(
            StatusCode::BAD_REQUEST,
            "InvalidAction",
            format!("{other} is not a supported action"),
        )),
    }
}

/// `(tenant, role key)` of a role session's `user_id` ("role:<key>").
fn session_role(user_id: &str) -> Option<(String, String)> {
    let key = user_id.strip_prefix("role:")?;
    let tenant = key.split_once('/').map_or("", |(t, _)| t);
    Some((tenant.to_string(), key.to_string()))
}

async fn get_caller_identity(call: &Call<'_>) -> IamResult<Response> {
    let auth = call.auth;
    let (user_id, account, arn) = match auth.auth_mode {
        AuthMode::AssumedRole => {
            let (tenant, key) = session_role(&auth.user_id).unwrap_or_default();
            let role = call
                .app
                .meta_client
                .clone()
                .get_role(objectio_proto::metadata::GetRoleRequest { name: key })
                .await
                .ok()
                .and_then(|r| r.into_inner().role);
            let session = auth.user_arn.rsplit('/').next().unwrap_or_default();
            let id = role.map_or_else(|| auth.user_id.clone(), |r| role_id(&r));
            (
                format!("{id}:{session}"),
                aws_account(&tenant),
                aws_arn(&auth.user_arn),
            )
        }
        AuthMode::Permanent | AuthMode::SessionToken => {
            let actor = Actor::of(call.app, auth).await.ok();
            let account = aws_account(&auth.tenant);
            if actor.is_some_and(|a| a.is_root()) {
                let root = format!("arn:aws:iam::{account}:root");
                (account.clone(), account, root)
            } else {
                (auth.user_id.clone(), account, aws_arn(&auth.user_arn))
            }
        }
        _ => (
            auth.user_id.clone(),
            aws_account(&auth.tenant),
            auth.user_arn.clone(),
        ),
    };
    let mut x = Xml::new();
    x.el("Arn", arn)
        .el("UserId", user_id)
        .el("Account", account);
    call.ok(Some(x), STS_NS)
}

/// `DurationSeconds` within `min..=max`, else `default`.
fn duration(call: &Call<'_>, min: u64, max: u64, default: u64) -> IamResult<u64> {
    match call.opt("DurationSeconds").filter(|d| !d.is_empty()) {
        None => Ok(default.min(max)),
        Some(d) => d
            .parse::<u64>()
            .ok()
            .filter(|d| (min..=max).contains(d))
            .ok_or_else(|| {
                IamError::validation(format!("DurationSeconds must be between {min} and {max}"))
            }),
    }
}

fn credentials_xml(x: &mut Xml, c: &objectio_auth::sts::TemporaryCredentials) {
    x.open("Credentials")
        .el("AccessKeyId", &c.access_key_id)
        .el("SecretAccessKey", &c.secret_access_key)
        .el("SessionToken", &c.session_token)
        .el("Expiration", iso(c.expires_at))
        .close("Credentials");
}

/// The caller's own policies on `action` (an `sts:` action) on `resource`.
async fn identity_says(call: &Call<'_>, action: &str, resource: &str) -> PolicyDecision {
    let mut context = RequestContext::new(&call.auth.user_arn, action, resource)
        .with_variable("aws:PrincipalAccount", aws_account(&call.auth.tenant));
    if let Some(ip) = call.auth.source_ip {
        context = context.with_source_ip(ip);
    }
    crate::authz::identity_decision(call.app, call.auth, &context).await
}

async fn get_session_token(call: &Call<'_>) -> IamResult<Response> {
    // A user's own keys only, as in AWS: not a session's.
    if !matches!(call.auth.auth_mode, AuthMode::Permanent) || call.auth.user_id.is_empty() {
        return Err(IamError::access_denied(
            "GetSessionToken takes a user's own access key",
        ));
    }
    if call
        .auth
        .scope
        .as_ref()
        .is_some_and(|s| !s.scope.is_empty())
    {
        return Err(IamError::access_denied(
            "a key scoped to a bucket can't get a session",
        ));
    }
    if identity_says(call, "sts:GetSessionToken", "*").await == PolicyDecision::Deny {
        return Err(IamError::access_denied(
            "not authorized to perform sts:GetSessionToken",
        ));
    }
    let secs = duration(call, 900, 129_600, 43_200)?;
    let creds = call.sts.sts.issue_for(
        &format!("{USER_SESSION_PREFIX}{}", call.auth.user_id),
        USER_SESSION_SCOPE,
        Operation::ReadWrite,
        Duration::from_secs(secs),
    );
    let mut x = Xml::new();
    credentials_xml(&mut x, &creds);
    call.ok(Some(x), STS_NS)
}

/// How a trust policy decides on one caller: Deny, or Allow for the
/// caller named itself, or Allow only through its account.
struct Trust {
    denied: bool,
    direct: bool,
    via_account: bool,
}

fn evaluate_trust(
    call: &Call<'_>,
    trust: &BucketPolicy,
    role_arn: &str,
    external_id: Option<&str>,
) -> Trust {
    let auth = call.auth;
    let evaluator = objectio_auth::PolicyEvaluator::new();
    let decide = |principal: &str| {
        let mut ctx = RequestContext::new(principal, "sts:AssumeRole", role_arn)
            .with_variable("aws:PrincipalArn", principal.to_string())
            .with_variable("aws:PrincipalAccount", aws_account(&auth.tenant));
        if let Some(id) = external_id {
            ctx = ctx.with_variable("sts:ExternalId", id.to_string());
        }
        if let Some(ip) = auth.source_ip {
            ctx = ctx.with_source_ip(ip);
        }
        evaluator.evaluate(trust, &ctx)
    };
    // The caller by its ARN, and a user by its id too (as policies written
    // for RGW name users).
    let account = super::account(&auth.tenant);
    let mut direct = vec![decide(&auth.user_arn)];
    if matches!(auth.auth_mode, AuthMode::Permanent | AuthMode::SessionToken) {
        direct.push(decide(&format!(
            "arn:obio:iam::{account}:user/{}",
            auth.user_id
        )));
    }
    let via_account = decide(&format!("arn:obio:iam::{account}:root"));
    Trust {
        denied: direct.contains(&PolicyDecision::Deny) || via_account == PolicyDecision::Deny,
        direct: direct.contains(&PolicyDecision::Allow),
        via_account: via_account == PolicyDecision::Allow,
    }
}

async fn assume_role(call: &Call<'_>) -> IamResult<Response> {
    let auth = call.auth;
    if matches!(auth.auth_mode, AuthMode::Sts | AuthMode::Anonymous)
        || auth.scope.as_ref().is_some_and(|s| !s.scope.is_empty())
    {
        return Err(IamError::access_denied(
            "these credentials can't assume a role",
        ));
    }
    let role_arn = call.required("RoleArn")?;
    let session = call.required("RoleSessionName")?;
    if session.len() < 2
        || session.len() > 64
        || !session
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_+=,.@-".contains(c))
    {
        return Err(IamError::validation(
            "RoleSessionName must be 2-64 characters of [\\w+=,.@-]",
        ));
    }
    if call.opt("Policy").is_some_and(|p| !p.is_empty())
        || call.params.keys().any(|k| k.starts_with("PolicyArns"))
    {
        return Err(IamError::validation("session policies are not supported"));
    }
    let denied = || {
        IamError::access_denied(format!(
            "User: {} is not authorized to perform: sts:AssumeRole on resource: {role_arn}",
            aws_arn(&auth.user_arn)
        ))
    };
    let (tenant, name) = crate::sts_api::parse_role_arn(role_arn)
        .ok_or_else(|| IamError::validation(format!("{role_arn} is not a role ARN")))?;
    // The role, by name in its tenant, ignoring case. A role that isn't
    // there is refused as one that won't be assumed: no probing for names.
    let role = super::tenant_roles(call.app, &tenant)
        .await?
        .into_iter()
        .find(|r| r.name.eq_ignore_ascii_case(&name))
        .ok_or_else(denied)?;
    let trust = BucketPolicy::from_trust_json(&role.trust_policy_json).map_err(|_| denied())?;

    // Within a tenant the trust policy decides. Across tenants it must name
    // the caller (or the caller's account): a grant to everyone stays in the
    // role's tenant. And outside the account root, a caller that the trust
    // reaches only through its account needs its own policies to allow it,
    // as does any caller from another tenant (IAM's cross-account rule).
    let cross = auth.tenant != role.tenant;
    let trust = if cross {
        trust.without_public_grants()
    } else {
        trust
    };
    let role_resource = objectio_auth::policy::canonical_arn(&role.arn).into_owned();
    let verdict = evaluate_trust(call, &trust, &role_resource, call.opt("ExternalId"));
    if verdict.denied || !(verdict.direct || verdict.via_account) {
        return Err(denied());
    }
    let root = Actor::of(call.app, auth).await.is_ok_and(|a| a.is_root())
        && auth.auth_mode != AuthMode::AssumedRole;
    let needs_identity = !root && (cross || !verdict.direct);
    let identity = identity_says(call, "sts:AssumeRole", &role_resource).await;
    if identity == PolicyDecision::Deny || (needs_identity && identity != PolicyDecision::Allow) {
        return Err(denied());
    }

    // How long: asked for, within the role's limit; a session assuming a
    // role (chaining) gets at most an hour, as in AWS.
    let mut limit = u64::from(max_session(&role));
    if auth.auth_mode == AuthMode::AssumedRole {
        limit = limit.min(3600);
    }
    let secs = duration(call, 900, limit, 3600)?;
    let session_arn = format!(
        "arn:obio:sts::{}:assumed-role/{}/{session}",
        super::account(&role.tenant),
        role.name
    );
    let creds = call.sts.sts.issue_for(
        &session_arn,
        "",
        Operation::ReadWrite,
        Duration::from_secs(secs),
    );
    tracing::info!(
        "sts: {} assumed {} as {session_arn}",
        auth.user_arn,
        role.arn
    );
    let mut x = Xml::new();
    credentials_xml(&mut x, &creds);
    x.open("AssumedRoleUser")
        .el("AssumedRoleId", format!("{}:{session}", role_id(&role)))
        .el("Arn", aws_arn(&session_arn))
        .close("AssumedRoleUser");
    call.ok(Some(x), STS_NS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_role_session_names_its_tenant() {
        assert_eq!(
            session_role("role:acme/ci"),
            Some(("acme".into(), "acme/ci".into()))
        );
        assert_eq!(
            session_role("role:ops"),
            Some((String::new(), "ops".into()))
        );
        assert_eq!(session_role("u-123"), None);
    }
}
