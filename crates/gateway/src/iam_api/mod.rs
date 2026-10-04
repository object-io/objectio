//! The AWS IAM and STS query APIs: what `aws iam`, `aws sts`, boto3 and
//! Terraform's AWS provider speak, over the users, groups, policies, keys
//! and roles the admin API (`/_admin/*`) manages. The same records, the
//! same scoping rules.
//!
//! A call is `POST /` with a form body (or `GET /?Action=…`), SigV4-signed
//! for the service `iam` or `sts`, dispatched on its `Action`, and answered
//! with the XML AWS answers with. It shares the S3 endpoint; S3 has no
//! `POST /`, and the unsigned STS call (`AssumeRoleWithWebIdentity`) goes
//! where it went before.
//!
//! ## Accounts and who may do what
//!
//! A tenant is an IAM account, its id the tenant's name; the system scope
//! is the account with the empty id (`objectio` in stored ARNs). A call
//! acts in the caller's own account, and nothing outside it exists for it.
//!
//! - **The system admin** and **a tenant's admins** are their account's
//!   root: they may make any IAM call in it, and `GetUser` and
//!   `GetCallerIdentity` name them `arn:aws:iam::<account>:root`.
//! - **Anyone else** (a user, a role's session) may make a call when its
//!   own policies allow the action (`iam:CreateUser`, …) on the resource
//!   (`arn:aws:iam::<account>:user/<path><name>`, …).
//! - A key scoped to a bucket, and the vended credentials of the data-lake
//!   APIs, may make none.

mod account;
mod groups;
mod policies;
mod roles;
mod sts;
mod users;
mod xml;

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use objectio_auth::AuthResult;
use objectio_auth::policy::{PolicyDecision, RequestContext, SYSTEM_ACCOUNT, canonical_arn};
use objectio_proto::metadata::{
    ListGroupsRequest, ListRolesRequest, ListUsersRequest, RoleObject, UserMeta, UserStatus,
};
use tracing::debug;

use crate::s3::AppState;
pub(crate) use xml::Xml;

/// What the query API needs: the gateway's state, and the unsigned STS
/// endpoint's (`AssumeRoleWithWebIdentity`).
pub struct QueryApiState {
    pub app: Arc<AppState>,
    pub sts: Arc<crate::sts_api::StsState>,
}

/// The largest form body taken: inline policies are at most 10 KiB, and a
/// form escapes most of a JSON document's characters.
const MAX_BODY: usize = 256 * 1024;

pub(crate) const IAM_NS: &str = "https://iam.amazonaws.com/doc/2010-05-08/";
pub(crate) const STS_NS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";

/// The STS actions a signed call may make.
const STS_ACTIONS: &[&str] = &["AssumeRole", "GetSessionToken", "GetCallerIdentity"];

/// An error document, as IAM and STS answer them.
#[derive(Debug)]
pub(crate) struct IamError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl IamError {
    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
    pub(crate) fn no_such_entity(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NoSuchEntity", message)
    }
    pub(crate) fn already_exists(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "EntityAlreadyExists", message)
    }
    pub(crate) fn delete_conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "DeleteConflict", message)
    }
    pub(crate) fn validation(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "ValidationError", message)
    }
    pub(crate) fn malformed_policy(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "MalformedPolicyDocument", message)
    }
    pub(crate) fn access_denied(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "AccessDenied", message)
    }

    /// A meta error, as IAM would report it.
    pub(crate) fn from_status(e: &tonic::Status) -> Self {
        let message = e.message().to_string();
        match e.code() {
            tonic::Code::NotFound => Self::no_such_entity(message),
            tonic::Code::AlreadyExists => Self::already_exists(message),
            tonic::Code::InvalidArgument => Self::validation(message),
            tonic::Code::FailedPrecondition => {
                Self::new(StatusCode::BAD_REQUEST, "InvalidInput", message)
            }
            tonic::Code::Aborted => Self::new(
                StatusCode::CONFLICT,
                "ConcurrentModification",
                format!("{message}; retry"),
            ),
            tonic::Code::PermissionDenied => Self::access_denied(message),
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, "ServiceFailure", message),
        }
    }

    pub(crate) fn response(&self, ns: &str) -> Response {
        let fault = if self.status.is_server_error() {
            "Receiver"
        } else {
            "Sender"
        };
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ErrorResponse xmlns=\"{ns}\">\
             <Error><Type>{fault}</Type><Code>{}</Code><Message>{}</Message></Error>\
             <RequestId>{}</RequestId></ErrorResponse>",
            self.code,
            xml::escape(&self.message),
            request_id(),
        );
        (self.status, [(header::CONTENT_TYPE, "text/xml")], body).into_response()
    }
}

pub(crate) type IamResult<T> = Result<T, IamError>;

pub(crate) fn request_id() -> String {
    crate::audit::request_id().unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

// ── The layer ──────────────────────────────────────────────────────────

fn has_param(query: &str, name: &str) -> bool {
    query
        .split('&')
        .any(|p| p.split('=').next().is_some_and(|k| k == name))
}

/// Take the IAM and STS query API ahead of S3.
///
/// `POST /` is the query API's (S3 has none): unsigned, it is STS's web
/// identity call as before; signed, any IAM or STS call. `GET /` is S3's
/// ListBuckets unless it names an `Action`. Presigned requests go on to S3.
pub async fn query_api_layer(
    State(q): State<Arc<QueryApiState>>,
    request: Request,
    next: Next,
) -> Response {
    if request.uri().path() != "/" {
        return next.run(request).await;
    }
    let query = request.uri().query().unwrap_or_default().to_string();
    let presigned = crate::auth_middleware::parse_presigned_query(&query).is_some()
        || crate::auth_middleware::is_presigned_v2(&query);
    let signed = request.headers().contains_key(header::AUTHORIZATION);
    let form = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| t.starts_with("application/x-www-form-urlencoded"));
    let take = !presigned
        && match *request.method() {
            Method::POST => !signed || form || has_param(&query, "Action"),
            Method::GET => has_param(&query, "Action"),
            _ => false,
        };
    if !take {
        return next.run(request).await;
    }

    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY).await else {
        return IamError::validation("request too large").response(IAM_NS);
    };
    let params = crate::sts_api::form(&body, parts.uri.query());
    let action = params.get("Action").cloned().unwrap_or_default();
    let is_sts = STS_ACTIONS.contains(&action.as_str()) || action == "AssumeRoleWithWebIdentity";
    let ns = if is_sts { STS_NS } else { IAM_NS };

    // The web identity token is the proof; a signature adds nothing.
    if !signed || action == "AssumeRoleWithWebIdentity" {
        if !signed && (STS_ACTIONS.contains(&action.as_str()) || is_iam_action(&action)) {
            return IamError::new(
                StatusCode::FORBIDDEN,
                "MissingAuthenticationToken",
                "Request is missing Authentication Token",
            )
            .response(ns);
        }
        return crate::sts_api::sts_handler(
            State(Arc::clone(&q.sts)),
            parts.uri,
            parts.headers,
            body,
        )
        .await;
    }

    // Another service's call (SNS's CreateTopic, say): not one of ours,
    // whoever signs it.
    if !is_sts && !is_iam_action(&action) {
        return if action.is_empty() {
            IamError::new(
                StatusCode::BAD_REQUEST,
                "MissingAction",
                "Action is required",
            )
        } else {
            IamError::new(
                StatusCode::BAD_REQUEST,
                "InvalidAction",
                format!("{action} is not a supported action"),
            )
        }
        .response(ns);
    }

    let request = Request::from_parts(parts, ());
    let auth = match crate::auth_middleware::authenticate_query(&q.app.auth_state, &request, &body)
        .await
    {
        Ok(a) => a,
        Err(e) => return auth_error(&e).response(ns),
    };
    let source_ip = request
        .extensions()
        .get::<crate::origin::ClientAddr>()
        .map(|c| q.app.trusted_proxies.client_ip(c.0.ip(), request.headers()));
    let auth = AuthResult { source_ip, ..auth };
    crate::audit::note_identity(&auth);
    crate::audit::note_action(&format!("{}:{action}", if is_sts { "sts" } else { "iam" }));
    debug!("{} calls {action}", auth.user_arn);

    let call = Call {
        app: &q.app,
        sts: &q.sts,
        auth: &auth,
        params: &params,
        action: &action,
    };
    let result = if is_sts {
        sts::dispatch(&call).await
    } else {
        match Actor::of(&q.app, &auth).await {
            Ok(actor) => dispatch(&call, &actor).await,
            Err(e) => Err(e),
        }
    };
    result.unwrap_or_else(|e| e.response(ns))
}

/// A refused signature or credential, as IAM reports it.
fn auth_error(e: &crate::auth_middleware::AuthError) -> IamError {
    use crate::auth_middleware::AuthError;
    match e {
        AuthError::SignatureDoesNotMatch => IamError::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided.",
        ),
        AuthError::RequestTimeTooSkewed => IamError::new(
            StatusCode::FORBIDDEN,
            "RequestExpired",
            "The difference between the request time and the server's time is too large.",
        ),
        AuthError::ExpiredToken(m) => IamError::new(StatusCode::FORBIDDEN, "ExpiredToken", m),
        AuthError::AccessDenied(m) if m.contains("not found") || m.contains("inactive") => {
            IamError::new(
                StatusCode::FORBIDDEN,
                "InvalidClientTokenId",
                "The security token included in the request is invalid.",
            )
        }
        AuthError::AccessDenied(m) => IamError::access_denied(m.clone()),
        AuthError::UnsupportedSigV2 => IamError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Use AWS4-HMAC-SHA256 (Signature Version 4).",
        ),
        AuthError::InternalError => IamError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ServiceFailure",
            "internal error",
        ),
    }
}

/// One call: who makes it, and its parameters.
pub(crate) struct Call<'a> {
    pub app: &'a AppState,
    pub sts: &'a crate::sts_api::StsState,
    pub auth: &'a AuthResult,
    pub params: &'a HashMap<String, String>,
    pub action: &'a str,
}

impl Call<'_> {
    /// A parameter, empty when absent.
    pub(crate) fn param(&self, name: &str) -> &str {
        self.params.get(name).map_or("", String::as_str)
    }

    pub(crate) fn opt(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    /// A required parameter.
    pub(crate) fn required(&self, name: &str) -> IamResult<&str> {
        self.opt(name)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| IamError::validation(format!("{name} is required")))
    }

    /// The answer to this call: `<ActionResponse><ActionResult>…`.
    pub(crate) fn ok(&self, result: Option<Xml>, ns: &str) -> IamResult<Response> {
        Ok(xml::respond(self.action, ns, result))
    }
}

/// Every IAM action this API answers.
const IAM_ACTIONS: &[&str] = &[
    "CreateUser",
    "GetUser",
    "ListUsers",
    "UpdateUser",
    "DeleteUser",
    "CreateAccessKey",
    "ListAccessKeys",
    "UpdateAccessKey",
    "DeleteAccessKey",
    "CreateGroup",
    "GetGroup",
    "ListGroups",
    "UpdateGroup",
    "DeleteGroup",
    "AddUserToGroup",
    "RemoveUserFromGroup",
    "ListGroupsForUser",
    "CreatePolicy",
    "GetPolicy",
    "GetPolicyVersion",
    "ListPolicyVersions",
    "ListPolicies",
    "DeletePolicy",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "ListAttachedUserPolicies",
    "AttachGroupPolicy",
    "DetachGroupPolicy",
    "ListAttachedGroupPolicies",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "ListAttachedRolePolicies",
    "PutUserPolicy",
    "GetUserPolicy",
    "ListUserPolicies",
    "DeleteUserPolicy",
    "PutGroupPolicy",
    "GetGroupPolicy",
    "ListGroupPolicies",
    "DeleteGroupPolicy",
    "PutRolePolicy",
    "GetRolePolicy",
    "ListRolePolicies",
    "DeleteRolePolicy",
    "CreateRole",
    "GetRole",
    "ListRoles",
    "UpdateRole",
    "UpdateAssumeRolePolicy",
    "DeleteRole",
    "GetAccountSummary",
    "ListOpenIDConnectProviders",
];

fn is_iam_action(action: &str) -> bool {
    IAM_ACTIONS.contains(&action)
}

async fn dispatch(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    match call.action {
        "CreateUser" => users::create_user(call, actor).await,
        "GetUser" => users::get_user(call, actor).await,
        "ListUsers" => users::list_users(call, actor).await,
        "UpdateUser" => users::update_user(call, actor).await,
        "DeleteUser" => users::delete_user(call, actor).await,
        "CreateAccessKey" => users::create_access_key(call, actor).await,
        "ListAccessKeys" => users::list_access_keys(call, actor).await,
        "UpdateAccessKey" => users::update_access_key(call, actor).await,
        "DeleteAccessKey" => users::delete_access_key(call, actor).await,
        "CreateGroup" => groups::create_group(call, actor).await,
        "GetGroup" => groups::get_group(call, actor).await,
        "ListGroups" => groups::list_groups(call, actor).await,
        "UpdateGroup" => groups::update_group(call, actor).await,
        "DeleteGroup" => groups::delete_group(call, actor).await,
        "AddUserToGroup" => groups::add_user_to_group(call, actor).await,
        "RemoveUserFromGroup" => groups::remove_user_from_group(call, actor).await,
        "ListGroupsForUser" => groups::list_groups_for_user(call, actor).await,
        "CreatePolicy" => policies::create_policy(call, actor).await,
        "GetPolicy" => policies::get_policy(call, actor).await,
        "GetPolicyVersion" => policies::get_policy_version(call, actor).await,
        "ListPolicyVersions" => policies::list_policy_versions(call, actor).await,
        "ListPolicies" => policies::list_policies(call, actor).await,
        "DeletePolicy" => policies::delete_policy(call, actor).await,
        "AttachUserPolicy" | "AttachGroupPolicy" | "AttachRolePolicy" => {
            policies::attach(call, actor, true).await
        }
        "DetachUserPolicy" | "DetachGroupPolicy" | "DetachRolePolicy" => {
            policies::attach(call, actor, false).await
        }
        "ListAttachedUserPolicies" | "ListAttachedGroupPolicies" | "ListAttachedRolePolicies" => {
            policies::list_attached(call, actor).await
        }
        "PutUserPolicy" | "PutGroupPolicy" | "PutRolePolicy" => {
            policies::put_inline(call, actor).await
        }
        "GetUserPolicy" | "GetGroupPolicy" | "GetRolePolicy" => {
            policies::get_inline(call, actor).await
        }
        "ListUserPolicies" | "ListGroupPolicies" | "ListRolePolicies" => {
            policies::list_inline(call, actor).await
        }
        "DeleteUserPolicy" | "DeleteGroupPolicy" | "DeleteRolePolicy" => {
            policies::delete_inline(call, actor).await
        }
        "CreateRole" => roles::create_role(call, actor).await,
        "GetRole" => roles::get_role(call, actor).await,
        "ListRoles" => roles::list_roles(call, actor).await,
        "UpdateRole" => roles::update_role(call, actor).await,
        "UpdateAssumeRolePolicy" => roles::update_assume_role_policy(call, actor).await,
        "DeleteRole" => roles::delete_role(call, actor).await,
        "GetAccountSummary" => account::get_account_summary(call, actor).await,
        "ListOpenIDConnectProviders" => account::list_open_id_connect_providers(call, actor).await,
        other => Err(IamError::new(
            StatusCode::BAD_REQUEST,
            "InvalidAction",
            format!("{other} is not a supported action"),
        )),
    }
}

// ── Who calls ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActorKind {
    /// The system admin: root of the system account.
    System,
    /// One of a tenant's admins: root of the tenant's account.
    TenantAdmin,
    /// Anyone else: its own policies decide.
    Policy,
}

/// Who makes an IAM call, and the account it acts in.
#[derive(Debug, Clone)]
pub(crate) struct Actor {
    pub kind: ActorKind,
    /// The tenant (empty: the system scope).
    pub tenant: String,
}

impl Actor {
    pub(crate) async fn of(app: &AppState, auth: &AuthResult) -> IamResult<Self> {
        use objectio_auth::AuthMode;
        if auth.scope.as_ref().is_some_and(|s| !s.scope.is_empty()) {
            return Err(IamError::access_denied(
                "a key scoped to a bucket can't make IAM calls",
            ));
        }
        if auth.auth_mode == AuthMode::Sts || auth.auth_mode == AuthMode::Anonymous {
            return Err(IamError::access_denied(
                "these credentials can't make IAM calls",
            ));
        }
        if auth.user_arn == crate::admin::SYSTEM_ADMIN_USER_ARN {
            return Ok(Self {
                kind: ActorKind::System,
                tenant: String::new(),
            });
        }
        let root = matches!(auth.auth_mode, AuthMode::Permanent | AuthMode::SessionToken)
            && !auth.tenant.is_empty()
            && matches!(
                crate::admin::tenant_admin(app, &auth.tenant, &auth.user_id, &auth.user_arn).await,
                Ok(true)
            );
        Ok(Self {
            kind: if root {
                ActorKind::TenantAdmin
            } else {
                ActorKind::Policy
            },
            tenant: auth.tenant.clone(),
        })
    }

    pub(crate) const fn is_root(&self) -> bool {
        !matches!(self.kind, ActorKind::Policy)
    }

    /// Whether the actor may make `action` (without the `iam:` prefix) on
    /// `resource` (a canonical ARN). The account's root may make any call;
    /// anyone else needs an Allow in its own policies, and no Deny.
    pub(crate) async fn allow(
        &self,
        call: &Call<'_>,
        action: &str,
        resource: &str,
    ) -> IamResult<()> {
        self.allow_any(call, action, &[resource.to_string()]).await
    }

    /// As [`Self::allow`], on a user: named by its ARN, or by its id
    /// (`…:user/<user_id>`, as policies written for RGW name users).
    pub(crate) async fn allow_user(
        &self,
        call: &Call<'_>,
        action: &str,
        user: &UserMeta,
    ) -> IamResult<()> {
        self.allow_any(call, action, &user_resources(user)).await
    }

    /// As [`Self::allow`], for a resource with several names: a Deny of
    /// any denies, an Allow of any allows.
    pub(crate) async fn allow_any(
        &self,
        call: &Call<'_>,
        action: &str,
        resources: &[String],
    ) -> IamResult<()> {
        if self.is_root() {
            return Ok(());
        }
        let action = format!("iam:{action}");
        let mut allowed = false;
        for resource in resources {
            let mut context = RequestContext::new(&call.auth.user_arn, &action, resource)
                .with_variable("aws:PrincipalAccount", aws_account(&self.tenant));
            if let Some(ip) = call.auth.source_ip {
                context = context.with_source_ip(ip);
            }
            context = context.with_variable(
                "obio:CredentialType".to_string(),
                call.auth.auth_mode.as_str().to_string(),
            );
            match crate::authz::identity_decision(call.app, call.auth, &context).await {
                PolicyDecision::Allow => allowed = true,
                PolicyDecision::Deny => {
                    allowed = false;
                    break;
                }
                PolicyDecision::ImplicitDeny => {}
            }
        }
        if allowed {
            return Ok(());
        }
        Err(IamError::access_denied(format!(
            "User: {} is not authorized to perform: {action} on resource: {}",
            aws_arn(&call.auth.user_arn),
            resources.first().map(|r| aws_arn(r)).unwrap_or_default()
        )))
    }
}

// ── ARNs, names, paths ─────────────────────────────────────────────────

/// The account segment of a stored ARN: the tenant, or `objectio`.
pub(crate) fn account(tenant: &str) -> &str {
    if tenant.is_empty() {
        SYSTEM_ACCOUNT
    } else {
        tenant
    }
}

/// The account id as the IAM API shows it: the tenant, or empty for the
/// system scope.
pub(crate) fn aws_account(tenant: &str) -> String {
    tenant.to_string()
}

/// An ARN as the IAM API shows it: in the `aws` partition, the system
/// account empty (`arn:aws:iam:::role/ops`).
pub(crate) fn aws_arn(arn: &str) -> String {
    let canonical = canonical_arn(arn);
    let Some(rest) = canonical.strip_prefix("arn:obio:") else {
        return canonical.into_owned();
    };
    let mut parts = rest.splitn(4, ':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(service), Some(region), Some(account), Some(resource)) => {
            let account = if account == SYSTEM_ACCOUNT && matches!(service, "iam" | "sts") {
                ""
            } else {
                account
            };
            format!("arn:aws:{service}:{region}:{account}:{resource}")
        }
        _ => format!("arn:aws:{rest}"),
    }
}

/// The canonical ARN of an IAM entity: `kind` is `user`, `group`, `role`
/// or `policy`.
pub(crate) fn entity_arn(tenant: &str, kind: &str, path: &str, name: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    format!("arn:obio:iam::{}:{kind}{path}{name}", account(tenant))
}

/// An IAM name: 1 to `max` letters, digits and `+=,.@_-`.
pub(crate) fn check_name(what: &str, name: &str, max: usize) -> IamResult<()> {
    let ok = !name.is_empty()
        && name.len() <= max
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c));
    if ok {
        Ok(())
    } else {
        Err(IamError::validation(format!(
            "{what} must be 1 to {max} letters, digits and +=,.@_-"
        )))
    }
}

/// A path parameter: `/` when absent.
pub(crate) fn path_param(call: &Call<'_>, name: &str) -> IamResult<String> {
    let path = call.opt(name).filter(|p| !p.is_empty()).unwrap_or("/");
    let ok = path == "/"
        || (path.len() <= 512
            && path.starts_with('/')
            && path.ends_with('/')
            && !path.contains("//")
            && path.bytes().all(|b| (0x21..=0x7e).contains(&b)));
    if ok {
        Ok(path.to_string())
    } else {
        Err(IamError::validation(format!(
            "{name} must be / or /a/b/: printable ASCII, at most 512 characters"
        )))
    }
}

/// ISO 8601, as IAM writes dates.
pub(crate) fn iso(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// An id derived from what names an entity, for one stored before ids
/// were (`AROA…` for a role, `ANPA…` for a policy).
pub(crate) fn derived_id(prefix: &str, arn: &str, created_at: u64) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{arn}\u{0}{created_at}").as_bytes());
    let tail: String = hex::encode_upper(digest).chars().take(17).collect();
    format!("{prefix}{tail}")
}

// ── Listing ────────────────────────────────────────────────────────────

/// One page of `items`, each with the key it sorts by: those after
/// `Marker`, at most `MaxItems` (default 100). Returns the page and the
/// marker for the next, if any.
pub(crate) fn page<T>(
    call: &Call<'_>,
    mut items: Vec<(String, T)>,
) -> IamResult<(Vec<T>, Option<String>)> {
    let max = match call.opt("MaxItems") {
        None | Some("") => 100,
        Some(m) => m
            .parse::<usize>()
            .ok()
            .filter(|m| (1..=1000).contains(m))
            .ok_or_else(|| IamError::validation("MaxItems must be between 1 and 1000"))?,
    };
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let marker = call.opt("Marker").filter(|m| !m.is_empty());
    let mut rest: Vec<(String, T)> = items
        .into_iter()
        .filter(|(k, _)| marker.is_none_or(|m| k.as_str() > m))
        .collect();
    let next = if rest.len() > max {
        rest.truncate(max);
        rest.last().map(|(k, _)| k.clone())
    } else {
        None
    };
    Ok((rest.into_iter().map(|(_, t)| t).collect(), next))
}

/// `IsTruncated` and `Marker` after a page.
pub(crate) fn page_end(x: &mut Xml, next: Option<&str>) {
    x.el("IsTruncated", if next.is_some() { "true" } else { "false" });
    if let Some(m) = next {
        x.el("Marker", m);
    }
}

/// The sort key of a name: IAM lists ignoring case.
pub(crate) fn sort_key(name: &str) -> String {
    name.to_ascii_lowercase()
}

// ── Lookups ────────────────────────────────────────────────────────────

/// Every live user, all tenants.
pub(crate) async fn all_users(app: &AppState) -> IamResult<Vec<UserMeta>> {
    let mut out = Vec::new();
    let mut marker = String::new();
    loop {
        let r = app
            .meta_client
            .clone()
            .list_users(ListUsersRequest {
                max_results: 1000,
                marker: marker.clone(),
            })
            .await
            .map_err(|e| IamError::from_status(&e))?
            .into_inner();
        out.extend(
            r.users
                .into_iter()
                .filter(|u| u.status != UserStatus::UserDeleted as i32),
        );
        if !r.is_truncated || r.next_marker.is_empty() || r.next_marker == marker {
            break;
        }
        marker = r.next_marker;
    }
    Ok(out)
}

/// The answer for an entity that isn't there: NoSuchEntity for whoever
/// may make the call, AccessDenied for anyone else, who learns nothing of
/// which names exist.
async fn missing(call: &Call<'_>, actor: &Actor, kind: &str, name: &str) -> IamError {
    if let Err(denied) = actor
        .allow(
            call,
            call.action,
            &entity_arn(&actor.tenant, kind, "/", name),
        )
        .await
    {
        return denied;
    }
    IamError::no_such_entity(format!("The {kind} with name {name} cannot be found."))
}

/// The user named `name` in the actor's account. IAM names are
/// case-insensitive; a user's id names it too.
pub(crate) async fn find_user(call: &Call<'_>, actor: &Actor, name: &str) -> IamResult<UserMeta> {
    let users = all_users(call.app).await?;
    let mine = || users.iter().filter(|u| u.tenant == actor.tenant);
    match mine()
        .find(|u| u.display_name.eq_ignore_ascii_case(name))
        .or_else(|| mine().find(|u| u.user_id == name))
    {
        Some(u) => Ok(u.clone()),
        None => Err(missing(call, actor, "user", name).await),
    }
}

/// The caller's own user, for a call that names none.
pub(crate) async fn own_user(call: &Call<'_>) -> IamResult<UserMeta> {
    use objectio_auth::AuthMode;
    if !matches!(
        call.auth.auth_mode,
        AuthMode::Permanent | AuthMode::SessionToken
    ) {
        return Err(IamError::validation(
            "Must specify userName when calling with non-User credentials",
        ));
    }
    call.app
        .meta_client
        .clone()
        .get_user(objectio_proto::metadata::GetUserRequest {
            user_id: call.auth.user_id.clone(),
        })
        .await
        .ok()
        .and_then(|r| r.into_inner().user)
        .ok_or_else(|| IamError::no_such_entity("the caller's user is gone"))
}

/// The user a call names in `UserName`, or the caller's own.
pub(crate) async fn named_or_own_user(call: &Call<'_>, actor: &Actor) -> IamResult<UserMeta> {
    match call.opt("UserName").filter(|n| !n.is_empty()) {
        Some(name) => find_user(call, actor, name).await,
        None => own_user(call).await,
    }
}

/// The ARNs a call on a user is authorized against: its own, and the
/// one naming it by id.
pub(crate) fn user_resources(u: &UserMeta) -> Vec<String> {
    vec![
        canonical_arn(&u.arn).into_owned(),
        format!("arn:obio:iam::{}:user/{}", account(&u.tenant), u.user_id),
    ]
}

/// The group named `name` in the actor's account, ignoring case.
pub(crate) async fn find_group(
    call: &Call<'_>,
    actor: &Actor,
    name: &str,
) -> IamResult<objectio_proto::metadata::GroupMeta> {
    match all_groups(call.app)
        .await?
        .into_iter()
        .find(|g| g.tenant == actor.tenant && g.group_name.eq_ignore_ascii_case(name))
    {
        Some(g) => Ok(g),
        None => Err(missing(call, actor, "group", name).await),
    }
}

/// Every group, all tenants.
pub(crate) async fn all_groups(
    app: &AppState,
) -> IamResult<Vec<objectio_proto::metadata::GroupMeta>> {
    let mut out = Vec::new();
    let mut marker = String::new();
    loop {
        let r = app
            .meta_client
            .clone()
            .list_groups(ListGroupsRequest {
                max_results: 1000,
                marker: marker.clone(),
            })
            .await
            .map_err(|e| IamError::from_status(&e))?
            .into_inner();
        out.extend(r.groups);
        if !r.is_truncated || r.next_marker.is_empty() || r.next_marker == marker {
            break;
        }
        marker = r.next_marker;
    }
    Ok(out)
}

/// The roles of a tenant.
pub(crate) async fn tenant_roles(app: &AppState, tenant: &str) -> IamResult<Vec<RoleObject>> {
    Ok(app
        .meta_client
        .clone()
        .list_roles(ListRolesRequest {
            tenant: tenant.to_string(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .roles
        .into_iter()
        // An empty filter lists every tenant's.
        .filter(|r| r.tenant == tenant)
        .collect())
}

/// The role named `name` in the actor's account, ignoring case.
pub(crate) async fn find_role(call: &Call<'_>, actor: &Actor, name: &str) -> IamResult<RoleObject> {
    match tenant_roles(call.app, &actor.tenant)
        .await?
        .into_iter()
        .find(|r| r.name.eq_ignore_ascii_case(name))
    {
        Some(r) => Ok(r),
        None => Err(missing(call, actor, "role", name).await),
    }
}

/// Where a role is stored, and how its attachments and inline policies
/// name it ("role:<key>").
pub(crate) fn role_key(r: &RoleObject) -> String {
    crate::iam_admin::key(&r.tenant, &r.name)
}

/// A role's id: stored, or derived for one created before ids were.
pub(crate) fn role_id(r: &RoleObject) -> String {
    if r.role_id.is_empty() {
        derived_id("AROA", &r.arn, r.created_at)
    } else {
        r.role_id.clone()
    }
}

/// A role's longest session, in seconds.
pub(crate) fn max_session(r: &RoleObject) -> u32 {
    if r.max_session_seconds == 0 {
        3600
    } else {
        r.max_session_seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arns_show_in_the_aws_partition_with_an_empty_system_account() {
        assert_eq!(
            aws_arn("arn:objectio:iam::acme:user/team/alice"),
            "arn:aws:iam::acme:user/team/alice"
        );
        assert_eq!(
            aws_arn("arn:objectio:iam::user/ops"),
            "arn:aws:iam:::user/ops"
        );
        assert_eq!(
            aws_arn("arn:obio:iam::objectio:role/ci"),
            "arn:aws:iam:::role/ci"
        );
        assert_eq!(
            aws_arn("arn:obio:sts::acme:assumed-role/ci/s1"),
            "arn:aws:sts::acme:assumed-role/ci/s1"
        );
    }

    #[test]
    fn names_are_iam_names() {
        assert!(check_name("UserName", "alice.b+c=d,e@f_g-h", 64).is_ok());
        assert!(check_name("UserName", "", 64).is_err());
        assert!(check_name("UserName", "a/b", 64).is_err());
        assert!(check_name("UserName", &"a".repeat(65), 64).is_err());
    }

    #[test]
    fn derived_ids_differ_for_a_recreated_entity() {
        let a = derived_id("AROA", "arn:obio:iam::t:role/r", 1);
        let b = derived_id("AROA", "arn:obio:iam::t:role/r", 2);
        assert_ne!(a, b);
        assert!(a.starts_with("AROA") && a.len() == 21);
    }
}
