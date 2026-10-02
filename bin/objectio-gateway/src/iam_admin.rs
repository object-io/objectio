//! Named policies, groups and roles, per tenant.
//!
//! Each belongs to a tenant, or to system scope. A tenant's admins manage
//! their tenant's; the system admin manages all. Policies and roles are
//! stored under `<tenant>/<name>` (system: `<name>`), so names are unique
//! per tenant; groups carry their tenant in their ARN.
//!
//! A policy reaches a user, group or role only within its tenant, plus the
//! system policies the operator marks `shared` (a catalogue tenants may
//! attach but not change). The system admin may attach any system policy.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use objectio_auth::AuthResult;
use objectio_proto::metadata::{
    AddUserToGroupRequest, AttachPolicyRequest, CreateGroupRequest, CreatePolicyRequest,
    CreateRoleRequest, DeleteGroupRequest, DeletePolicyRequest, DeleteRoleRequest,
    DetachPolicyRequest, GetPolicyRequest, GetRoleRequest, GroupMeta, ListAttachedPoliciesRequest,
    ListGroupsRequest, ListPoliciesRequest, ListRolesRequest, PolicyObject,
    RemoveUserFromGroupRequest, RoleObject, UpdatePolicyRequest, UpdateRoleRequest,
};
use serde_json::{Value, json};

use crate::admin::{extract_caller, is_system_admin, require_tenant_admin_access};
use crate::s3::AppState;

type Query2 = Query<std::collections::HashMap<String, String>>;

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn grpc_error(e: &tonic::Status) -> Response {
    let status = match e.code() {
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::AlreadyExists | tonic::Code::Aborted => StatusCode::CONFLICT,
        tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition => StatusCode::BAD_REQUEST,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error(status, e.message())
}

/// Where a policy or role is stored.
fn key(tenant: &str, name: &str) -> String {
    if tenant.is_empty() {
        name.to_string()
    } else {
        format!("{tenant}/{name}")
    }
}

/// Who is asking, as far as IAM objects go.
struct Admin {
    system: bool,
    /// The tenant it acts in (empty: system scope).
    tenant: String,
}

/// The tenant an admin request acts in, or the refusal. The system admin
/// acts in `requested` (default: system scope); a tenant admin acts in its
/// own tenant, and may not name another.
async fn admin_in(
    state: &AppState,
    auth: &Option<Extension<AuthResult>>,
    headers: &HeaderMap,
    requested: Option<&str>,
) -> Result<Admin, Response> {
    let caller = extract_caller(auth, headers);
    if !caller.authenticated {
        return Err(error(StatusCode::UNAUTHORIZED, "authentication required"));
    }
    if is_system_admin(&caller) {
        return Ok(Admin {
            system: true,
            tenant: requested.unwrap_or_default().to_string(),
        });
    }
    if caller.tenant.is_empty() || requested.is_some_and(|r| r != caller.tenant) {
        return Err(error(
            StatusCode::FORBIDDEN,
            "not authorized for this tenant scope",
        ));
    }
    if let Some(deny) = require_tenant_admin_access(state, auth, headers, &caller.tenant).await {
        return Err(deny);
    }
    Ok(Admin {
        system: false,
        tenant: caller.tenant,
    })
}

fn requested<'a>(
    params: &'a std::collections::HashMap<String, String>,
    body: &'a Value,
) -> Option<&'a str> {
    body["tenant"]
        .as_str()
        .or_else(|| params.get("tenant").map(String::as_str))
}

/// A policy document from a body's `policy`: a JSON object or its text,
/// checked as the authorization chain will read it.
#[allow(clippy::result_large_err)] // Err is a fully-formed Response built once per request.
fn policy_document(v: &Value, what: &str) -> Result<String, Response> {
    let text = v.as_str().map_or_else(
        || serde_json::to_string(v).unwrap_or_default(),
        str::to_string,
    );
    objectio_auth::BucketPolicy::from_json(&text)
        .map(|_| text)
        .map_err(|e| error(StatusCode::BAD_REQUEST, &format!("invalid {what}: {e}")))
}

fn policy_view(p: &PolicyObject) -> Value {
    json!({
        "name": p.name,
        "tenant": p.tenant,
        "shared": p.shared,
        "policy": serde_json::from_str::<Value>(&p.policy_json).unwrap_or_default(),
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    })
}

fn group_json(g: &GroupMeta) -> Value {
    json!({
        "group_id": g.group_id,
        "group_name": g.group_name,
        "arn": g.arn,
        "tenant": g.tenant,
        "member_user_ids": g.member_user_ids,
        "created_at": g.created_at,
    })
}

fn role_json(r: &RoleObject) -> Value {
    json!({
        "name": r.name,
        "arn": r.arn,
        "tenant": r.tenant,
        "description": r.description,
        "trust_policy": serde_json::from_str::<Value>(&r.trust_policy_json).unwrap_or(Value::Null),
        "max_session_seconds": r.max_session_seconds,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    })
}

async fn get_policy(state: &AppState, key: &str) -> Option<PolicyObject> {
    let r = state
        .meta_client
        .clone()
        .get_policy(GetPolicyRequest {
            name: key.to_string(),
        })
        .await
        .ok()?
        .into_inner();
    r.policy.filter(|_| r.found)
}

async fn find_group(state: &AppState, id: &str) -> Result<GroupMeta, Response> {
    state
        .meta_client
        .clone()
        .list_groups(ListGroupsRequest::default())
        .await
        .map_err(|e| grpc_error(&e))?
        .into_inner()
        .groups
        .into_iter()
        .find(|g| g.group_id == id)
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "group not found"))
}

// ── Policies ────────────────────────────────────────────────────────────

/// `GET /_admin/policies[?tenant=]`: the system admin sees all (or one
/// tenant's); a tenant admin its tenant's and the shared catalogue.
pub async fn list_policies(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query2,
) -> Response {
    let admin = match admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let all = match state
        .meta_client
        .clone()
        .list_policies(ListPoliciesRequest {})
        .await
    {
        Ok(r) => r.into_inner().policies,
        Err(e) => return grpc_error(&e),
    };
    let visible: Vec<Value> = all
        .iter()
        .filter(|p| {
            if admin.system {
                !params.contains_key("tenant") || p.tenant == admin.tenant
            } else {
                p.tenant == admin.tenant || (p.tenant.is_empty() && p.shared)
            }
        })
        .map(policy_view)
        .collect();
    Json(json!({ "policies": visible })).into_response()
}

/// `POST /_admin/policies` `{"name", "policy", "tenant"?, "shared"?}`
pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query2,
    Json(body): Json<Value>,
) -> Response {
    let admin = match admin_in(&state, &auth, &headers, requested(&params, &body)).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let shared = body["shared"].as_bool().unwrap_or(false);
    if shared && !(admin.system && admin.tenant.is_empty()) {
        return error(
            StatusCode::FORBIDDEN,
            "only the system admin shares a system policy",
        );
    }
    let policy_json = match policy_document(&body["policy"], "policy document") {
        Ok(p) => p,
        Err(r) => return r,
    };
    match state
        .meta_client
        .clone()
        .create_policy(CreatePolicyRequest {
            name: body["name"].as_str().unwrap_or_default().to_string(),
            policy_json,
            tenant: admin.tenant,
            shared,
        })
        .await
    {
        Ok(r) => (
            StatusCode::CREATED,
            Json(policy_view(&r.into_inner().policy.unwrap_or_default())),
        )
            .into_response(),
        Err(e) => grpc_error(&e),
    }
}

/// `GET /_admin/policies/{name}[?tenant=]`: a tenant admin may also read a
/// shared system policy.
pub async fn get_policy_handler(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query2,
) -> Response {
    let admin = match admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let found = match get_policy(&state, &key(&admin.tenant, &name)).await {
        Some(p) => Some(p),
        None if !admin.tenant.is_empty() => get_policy(&state, &name).await.filter(|p| p.shared),
        None => None,
    };
    found.map_or_else(
        || error(StatusCode::NOT_FOUND, "policy not found"),
        |p| Json(policy_view(&p)).into_response(),
    )
}

/// `PUT /_admin/policies/{name}[?tenant=]` `{"policy"}`: the document,
/// replaced in place so it never stops applying.
pub async fn update_policy(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query2,
    Json(body): Json<Value>,
) -> Response {
    let admin = match admin_in(&state, &auth, &headers, requested(&params, &body)).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let policy_json = match policy_document(&body["policy"], "policy document") {
        Ok(p) => p,
        Err(r) => return r,
    };
    match state
        .meta_client
        .clone()
        .update_policy(UpdatePolicyRequest {
            name: key(&admin.tenant, &name),
            policy_json,
        })
        .await
    {
        Ok(r) => {
            state.policy_cache.invalidate_all_identities();
            Json(policy_view(&r.into_inner().policy.unwrap_or_default())).into_response()
        }
        Err(e) => grpc_error(&e),
    }
}

/// `DELETE /_admin/policies/{name}[?tenant=]`
pub async fn delete_policy(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query2,
) -> Response {
    let admin = match admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    match state
        .meta_client
        .clone()
        .delete_policy(DeletePolicyRequest {
            name: key(&admin.tenant, &name),
        })
        .await
    {
        Ok(_) => {
            state.policy_cache.invalidate_all_identities();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => grpc_error(&e),
    }
}

// ── Attachments ─────────────────────────────────────────────────────────

/// A principal named in an attach / detach / list request, its tenant, and
/// the key its cached policies are kept under.
struct Principal {
    user_id: String,
    group_id: String,
    role_key: String,
    tenant: String,
    cache_key: String,
}

async fn principal_of(
    state: &AppState,
    body: &Value,
    params: &std::collections::HashMap<String, String>,
    caller_tenant: &str,
) -> Result<Principal, Response> {
    let field = |k: &str| {
        body[k]
            .as_str()
            .map(str::to_string)
            .or_else(|| params.get(k).cloned())
            .unwrap_or_default()
    };
    let (user_id, group_id, role_name) = (field("user_id"), field("group_id"), field("role_name"));
    if !user_id.is_empty() {
        let tenant = crate::s3::lookup_user_tenant(state, &user_id)
            .await
            .ok_or_else(|| error(StatusCode::NOT_FOUND, "user not found"))?;
        return Ok(Principal {
            cache_key: user_id.clone(),
            user_id,
            group_id: String::new(),
            role_key: String::new(),
            tenant,
        });
    }
    if !group_id.is_empty() {
        let g = find_group(state, &group_id).await?;
        return Ok(Principal {
            cache_key: group_id.clone(),
            user_id: String::new(),
            group_id,
            role_key: String::new(),
            tenant: g.tenant,
        });
    }
    if !role_name.is_empty() {
        // A role is named within the tenant the request names, else the
        // caller's own.
        let named = field("tenant");
        let tenant = if named.is_empty() {
            caller_tenant.to_string()
        } else {
            named
        };
        let role_key = key(&tenant, &role_name);
        let found = state
            .meta_client
            .clone()
            .get_role(GetRoleRequest {
                name: role_key.clone(),
            })
            .await
            .map_err(|e| grpc_error(&e))?
            .into_inner();
        if !found.found {
            return Err(error(StatusCode::NOT_FOUND, "role not found"));
        }
        return Ok(Principal {
            cache_key: format!("role:{role_key}"),
            user_id: String::new(),
            group_id: String::new(),
            role_key,
            tenant,
        });
    }
    Err(error(
        StatusCode::BAD_REQUEST,
        "one of user_id, group_id or role_name is required",
    ))
}

/// The stored key of the policy `name` that `admin` may attach to a
/// principal of `tenant`: the tenant's own, else a system policy it may
/// use (shared, or any for the system admin).
async fn attachable(
    state: &AppState,
    admin: &Admin,
    tenant: &str,
    name: &str,
) -> Result<String, Response> {
    if !tenant.is_empty() && get_policy(state, &key(tenant, name)).await.is_some() {
        return Ok(key(tenant, name));
    }
    match get_policy(state, name).await {
        Some(p) if p.tenant.is_empty() && (p.shared || admin.system) => Ok(name.to_string()),
        Some(_) => Err(error(
            StatusCode::FORBIDDEN,
            "that policy isn't shared with tenants",
        )),
        None => Err(error(StatusCode::NOT_FOUND, "policy not found")),
    }
}

/// `POST /_admin/policies/attach` `{"policy_name", "user_id"|"group_id"|"role_name", "tenant"?}`
pub async fn attach_policy(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    change_attachment(state, auth, headers, body, true).await
}

/// `POST /_admin/policies/detach`, as attach.
pub async fn detach_policy(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    change_attachment(state, auth, headers, body, false).await
}

async fn change_attachment(
    state: Arc<AppState>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Value,
    attach: bool,
) -> Response {
    let no_params = std::collections::HashMap::new();
    let caller = extract_caller(&auth, &headers);
    let p = match principal_of(&state, &body, &no_params, &caller.tenant).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    // Admin over the principal's tenant.
    let admin = match admin_in(&state, &auth, &headers, Some(&p.tenant)).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let name = body["policy_name"].as_str().unwrap_or_default();
    let policy_name = if attach {
        match attachable(&state, &admin, &p.tenant, name).await {
            Ok(k) => k,
            Err(r) => return r,
        }
    } else {
        // Detach what is attached: the tenant's policy of that name, else
        // the system one.
        let own = key(&p.tenant, name);
        if !p.tenant.is_empty() && get_policy(&state, &own).await.is_some() {
            own
        } else {
            name.to_string()
        }
    };
    let mut client = state.meta_client.clone();
    let result = if attach {
        client
            .attach_policy(AttachPolicyRequest {
                policy_name,
                user_id: p.user_id,
                group_id: p.group_id,
                role_name: p.role_key,
            })
            .await
            .map(drop)
    } else {
        client
            .detach_policy(DetachPolicyRequest {
                policy_name,
                user_id: p.user_id,
                group_id: p.group_id,
                role_name: p.role_key,
            })
            .await
            .map(drop)
    };
    match result {
        Ok(()) => {
            // The authorization chain caches a principal's policy set.
            state.policy_cache.invalidate_identity(&p.cache_key);
            StatusCode::OK.into_response()
        }
        Err(e) => grpc_error(&e),
    }
}

/// `GET /_admin/policies/attached?user_id=|group_id=|role_name=[&tenant=]`
pub async fn list_attached(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query2,
) -> Response {
    let caller = extract_caller(&auth, &headers);
    let p = match principal_of(&state, &Value::Null, &params, &caller.tenant).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(r) = admin_in(&state, &auth, &headers, Some(&p.tenant)).await {
        return r;
    }
    match state
        .meta_client
        .clone()
        .list_attached_policies(ListAttachedPoliciesRequest {
            user_id: p.user_id,
            group_id: p.group_id,
            role_name: p.role_key,
        })
        .await
    {
        // A tenant's policies are listed by name, not by stored key.
        Ok(r) => {
            let prefix = format!("{}/", p.tenant);
            let names: Vec<String> = r
                .into_inner()
                .policy_names
                .into_iter()
                .map(|n| n.strip_prefix(&prefix).map_or(n.clone(), str::to_string))
                .collect();
            Json(json!({ "policy_names": names })).into_response()
        }
        Err(e) => grpc_error(&e),
    }
}

// ── Groups ──────────────────────────────────────────────────────────────

/// `GET /_admin/groups[?tenant=]`
pub async fn list_groups(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query2,
) -> Response {
    let admin = match admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    match state
        .meta_client
        .clone()
        .list_groups(ListGroupsRequest::default())
        .await
    {
        Ok(r) => {
            let groups: Vec<Value> = r
                .into_inner()
                .groups
                .iter()
                .filter(|g| {
                    (admin.system && !params.contains_key("tenant")) || g.tenant == admin.tenant
                })
                .map(group_json)
                .collect();
            Json(json!({ "groups": groups })).into_response()
        }
        Err(e) => grpc_error(&e),
    }
}

/// `POST /_admin/groups` `{"group_name", "tenant"?}`
pub async fn create_group(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query2,
    Json(body): Json<Value>,
) -> Response {
    let admin = match admin_in(&state, &auth, &headers, requested(&params, &body)).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match state
        .meta_client
        .clone()
        .create_group(CreateGroupRequest {
            group_name: body["group_name"].as_str().unwrap_or_default().to_string(),
            tenant: admin.tenant,
        })
        .await
    {
        Ok(r) => (
            StatusCode::CREATED,
            Json(group_json(&r.into_inner().group.unwrap_or_default())),
        )
            .into_response(),
        Err(e) => grpc_error(&e),
    }
}

/// `GET /_admin/groups/{group_id}`
pub async fn get_group(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
) -> Response {
    let g = match find_group(&state, &group_id).await {
        Ok(g) => g,
        Err(r) => return r,
    };
    if let Err(r) = admin_in(&state, &auth, &headers, Some(&g.tenant)).await {
        return r;
    }
    Json(group_json(&g)).into_response()
}

/// `DELETE /_admin/groups/{group_id}`
pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
) -> Response {
    let g = match find_group(&state, &group_id).await {
        Ok(g) => g,
        Err(r) => return r,
    };
    if let Err(r) = admin_in(&state, &auth, &headers, Some(&g.tenant)).await {
        return r;
    }
    match state
        .meta_client
        .clone()
        .delete_group(DeleteGroupRequest {
            group_id: group_id.clone(),
        })
        .await
    {
        Ok(_) => {
            state.policy_cache.invalidate_identity(&group_id);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => grpc_error(&e),
    }
}

/// `POST /_admin/groups/{group_id}/members` `{"user_id"}`: a user of the
/// group's own tenant.
pub async fn add_group_member(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let user_id = body["user_id"].as_str().unwrap_or_default().to_string();
    change_member(state, auth, headers, group_id, user_id, true).await
}

/// `DELETE /_admin/groups/{group_id}/members/{user_id}`
pub async fn remove_group_member(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path((group_id, user_id)): Path<(String, String)>,
) -> Response {
    change_member(state, auth, headers, group_id, user_id, false).await
}

async fn change_member(
    state: Arc<AppState>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    group_id: String,
    user_id: String,
    add: bool,
) -> Response {
    let g = match find_group(&state, &group_id).await {
        Ok(g) => g,
        Err(r) => return r,
    };
    if let Err(r) = admin_in(&state, &auth, &headers, Some(&g.tenant)).await {
        return r;
    }
    if add {
        match crate::s3::lookup_user_tenant(&state, &user_id).await {
            Some(t) if t == g.tenant => {}
            Some(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "the user is in another tenant than the group",
                );
            }
            None => return error(StatusCode::NOT_FOUND, "user not found"),
        }
    }
    let mut client = state.meta_client.clone();
    let result = if add {
        client
            .add_user_to_group(AddUserToGroupRequest {
                group_id,
                user_id: user_id.clone(),
            })
            .await
            .map(drop)
    } else {
        client
            .remove_user_from_group(RemoveUserFromGroupRequest {
                group_id,
                user_id: user_id.clone(),
            })
            .await
            .map(drop)
    };
    match result {
        Ok(()) => {
            state.policy_cache.invalidate_identity(&user_id);
            StatusCode::OK.into_response()
        }
        Err(e) => grpc_error(&e),
    }
}

// ── Roles ───────────────────────────────────────────────────────────────

/// `GET /_admin/roles[?tenant=]`
pub async fn list_roles(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query2,
) -> Response {
    let admin = match admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let all = admin.system && !params.contains_key("tenant");
    match state
        .meta_client
        .clone()
        .list_roles(ListRolesRequest::default())
        .await
    {
        Ok(r) => {
            let roles: Vec<Value> = r
                .into_inner()
                .roles
                .iter()
                .filter(|role| all || role.tenant == admin.tenant)
                .map(role_json)
                .collect();
            Json(json!({ "roles": roles })).into_response()
        }
        Err(e) => grpc_error(&e),
    }
}

/// `POST /_admin/roles` `{"name", "trust_policy", "description"?,
/// "max_session_seconds"?, "tenant"?}`
pub async fn create_role(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query2,
    Json(body): Json<Value>,
) -> Response {
    let admin = match admin_in(&state, &auth, &headers, requested(&params, &body)).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let trust = match policy_document(&body["trust_policy"], "trust policy") {
        Ok(t) => t,
        Err(r) => return r,
    };
    let role = RoleObject {
        name: body["name"].as_str().unwrap_or_default().to_string(),
        tenant: admin.tenant,
        description: body["description"].as_str().unwrap_or_default().to_string(),
        trust_policy_json: trust,
        max_session_seconds: body["max_session_seconds"]
            .as_u64()
            .and_then(|m| u32::try_from(m).ok())
            .unwrap_or(0),
        ..Default::default()
    };
    match state
        .meta_client
        .clone()
        .create_role(CreateRoleRequest { role: Some(role) })
        .await
    {
        Ok(r) => (
            StatusCode::CREATED,
            Json(role_json(&r.into_inner().role.unwrap_or_default())),
        )
            .into_response(),
        Err(e) => grpc_error(&e),
    }
}

/// `GET /_admin/roles/{name}[?tenant=]`: the role and its attached policies.
pub async fn get_role(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query2,
) -> Response {
    let admin = match admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let role_key = key(&admin.tenant, &name);
    let mut client = state.meta_client.clone();
    let r = match client
        .get_role(GetRoleRequest {
            name: role_key.clone(),
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => return grpc_error(&e),
    };
    let Some(role) = r.role.filter(|_| r.found) else {
        return error(StatusCode::NOT_FOUND, "role not found");
    };
    let attached = client
        .list_attached_policies(ListAttachedPoliciesRequest {
            role_name: role_key,
            ..Default::default()
        })
        .await
        .map(|r| r.into_inner().policy_names)
        .unwrap_or_default();
    let mut j = role_json(&role);
    j["attached_policies"] = json!(attached);
    Json(j).into_response()
}

/// `PUT /_admin/roles/{name}[?tenant=]` `{"trust_policy"?, "description"?,
/// "max_session_seconds"?}`
pub async fn update_role(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query2,
    Json(body): Json<Value>,
) -> Response {
    let admin = match admin_in(&state, &auth, &headers, requested(&params, &body)).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let trust = if body["trust_policy"].is_null() {
        None
    } else {
        match policy_document(&body["trust_policy"], "trust policy") {
            Ok(t) => Some(t),
            Err(r) => return r,
        }
    };
    match state
        .meta_client
        .clone()
        .update_role(UpdateRoleRequest {
            name: key(&admin.tenant, &name),
            description: body["description"].as_str().map(str::to_string),
            trust_policy_json: trust,
            max_session_seconds: body["max_session_seconds"]
                .as_u64()
                .and_then(|m| u32::try_from(m).ok()),
        })
        .await
    {
        Ok(r) => Json(role_json(&r.into_inner().role.unwrap_or_default())).into_response(),
        Err(e) => grpc_error(&e),
    }
}

/// `DELETE /_admin/roles/{name}[?tenant=]`
pub async fn delete_role(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query2,
) -> Response {
    let admin = match admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    match state
        .meta_client
        .clone()
        .delete_role(DeleteRoleRequest {
            name: key(&admin.tenant, &name),
        })
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => grpc_error(&e),
    }
}
