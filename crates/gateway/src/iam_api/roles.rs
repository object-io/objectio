//! Roles: identities assumed through STS, with a trust policy saying who
//! may assume them.

use axum::response::Response;
use objectio_proto::metadata::{
    CreateRoleRequest, DeleteRoleRequest, ListAttachedPoliciesRequest, ListInlinePoliciesRequest,
    RoleObject, UpdateRoleRequest,
};

use super::users::path_prefix;
use super::{
    Actor, Call, IAM_NS, IamError, IamResult, Xml, aws_arn, check_name, entity_arn, find_role, iso,
    max_session, page, page_end, path_param, role_id, role_key, sort_key, tenant_roles,
};

fn path_of(r: &RoleObject) -> &str {
    if r.path.is_empty() { "/" } else { &r.path }
}

fn role_xml(x: &mut Xml, r: &RoleObject) {
    x.el("Path", path_of(r))
        .el("RoleName", &r.name)
        .el("RoleId", role_id(r))
        .el("Arn", aws_arn(&r.arn))
        .el("CreateDate", iso(r.created_at))
        .document("AssumeRolePolicyDocument", &r.trust_policy_json);
    if !r.description.is_empty() {
        x.el("Description", &r.description);
    }
    x.el("MaxSessionDuration", max_session(r).to_string());
}

fn resource(r: &RoleObject) -> String {
    objectio_auth::policy::canonical_arn(&r.arn).into_owned()
}

/// A trust policy, checked as the STS calls will read it.
fn check_trust_policy(doc: &str) -> IamResult<()> {
    if doc.chars().filter(|c| !c.is_whitespace()).count() > 2048 {
        return Err(IamError::new(
            axum::http::StatusCode::CONFLICT,
            "LimitExceeded",
            "Maximum trust policy size of 2048 bytes exceeded.",
        ));
    }
    objectio_auth::BucketPolicy::from_trust_json(doc)
        .map(drop)
        .map_err(|e| IamError::malformed_policy(e.to_string()))
}

/// `MaxSessionDuration`: one to twelve hours.
fn session_param(call: &Call<'_>) -> IamResult<Option<u32>> {
    match call.opt("MaxSessionDuration").filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(v) => v
            .parse::<u32>()
            .ok()
            .filter(|s| (3600..=43200).contains(s))
            .map(Some)
            .ok_or_else(|| {
                IamError::validation("MaxSessionDuration must be between 3600 and 43200 seconds")
            }),
    }
}

pub(super) async fn create_role(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let name = call.required("RoleName")?;
    check_name("RoleName", name, 64)?;
    let path = path_param(call, "Path")?;
    let trust = call.required("AssumeRolePolicyDocument")?;
    check_trust_policy(trust)?;
    let max = session_param(call)?;
    let description = call.param("Description");
    if description.len() > 1000 {
        return Err(IamError::validation(
            "Description is at most 1000 characters",
        ));
    }
    actor
        .allow(
            call,
            "CreateRole",
            &entity_arn(&actor.tenant, "role", &path, name),
        )
        .await?;
    let role = call
        .app
        .meta_client
        .clone()
        .create_role(CreateRoleRequest {
            role: Some(RoleObject {
                name: name.to_string(),
                tenant: actor.tenant.clone(),
                description: description.to_string(),
                trust_policy_json: trust.to_string(),
                max_session_seconds: max.unwrap_or(0),
                path,
                ..Default::default()
            }),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .role
        .unwrap_or_default();
    let mut x = Xml::new();
    x.open("Role");
    role_xml(&mut x, &role);
    x.close("Role");
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn get_role(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let role = find_role(call, actor, call.required("RoleName")?).await?;
    actor.allow(call, "GetRole", &resource(&role)).await?;
    let mut x = Xml::new();
    x.open("Role");
    role_xml(&mut x, &role);
    x.close("Role");
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn list_roles(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let prefix = path_prefix(call);
    actor
        .allow(
            call,
            "ListRoles",
            &entity_arn(&actor.tenant, "role", "/", "*"),
        )
        .await?;
    let roles = tenant_roles(call.app, &actor.tenant)
        .await?
        .into_iter()
        .filter(|r| path_of(r).starts_with(&prefix))
        .map(|r| (sort_key(&r.name), r))
        .collect();
    let (roles, next) = page(call, roles)?;
    let mut x = Xml::new();
    x.open("Roles");
    for r in &roles {
        x.open("member");
        role_xml(&mut x, r);
        x.close("member");
    }
    x.close("Roles");
    page_end(&mut x, next.as_deref());
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn update_role(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let role = find_role(call, actor, call.required("RoleName")?).await?;
    let max = session_param(call)?;
    let description = call.opt("Description");
    if description.is_some_and(|d| d.len() > 1000) {
        return Err(IamError::validation(
            "Description is at most 1000 characters",
        ));
    }
    actor.allow(call, "UpdateRole", &resource(&role)).await?;
    update(call, &role, description.map(str::to_string), None, max).await
}

pub(super) async fn update_assume_role_policy(
    call: &Call<'_>,
    actor: &Actor,
) -> IamResult<Response> {
    let role = find_role(call, actor, call.required("RoleName")?).await?;
    let trust = call.required("PolicyDocument")?;
    check_trust_policy(trust)?;
    actor
        .allow(call, "UpdateAssumeRolePolicy", &resource(&role))
        .await?;
    update(call, &role, None, Some(trust.to_string()), None).await
}

async fn update(
    call: &Call<'_>,
    role: &RoleObject,
    description: Option<String>,
    trust_policy_json: Option<String>,
    max_session_seconds: Option<u32>,
) -> IamResult<Response> {
    call.app
        .meta_client
        .clone()
        .update_role(UpdateRoleRequest {
            name: role_key(role),
            description,
            trust_policy_json,
            max_session_seconds,
        })
        .await
        .map_err(|e| IamError::from_status(&e))?;
    call.ok(None, IAM_NS)
}

pub(super) async fn delete_role(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let role = find_role(call, actor, call.required("RoleName")?).await?;
    actor.allow(call, "DeleteRole", &resource(&role)).await?;
    let key = role_key(&role);
    let mut meta = call.app.meta_client.clone();
    let inline = meta
        .list_inline_policies(ListInlinePoliciesRequest {
            principal: format!("role:{key}"),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .policies;
    let attached = meta
        .list_attached_policies(ListAttachedPoliciesRequest {
            role_name: key.clone(),
            ..Default::default()
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .policy_names;
    if !inline.is_empty() || !attached.is_empty() {
        return Err(IamError::delete_conflict(
            "Cannot delete entity, must remove its policies first.",
        ));
    }
    meta.delete_role(DeleteRoleRequest { name: key.clone() })
        .await
        .map_err(|e| IamError::from_status(&e))?;
    call.app
        .policy_cache
        .invalidate_identity(&format!("role:{key}"));
    call.ok(None, IAM_NS)
}
