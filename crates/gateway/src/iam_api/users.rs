//! Users and their access keys.

use axum::response::Response;
use objectio_proto::metadata::{
    AccessKeyMeta, CreateAccessKeyRequest, CreateUserRequest, DeleteAccessKeyRequest,
    DeleteUserRequest, GetAccessKeyRequest, KeyStatus, ListAccessKeysRequest,
    ListAttachedPoliciesRequest, ListInlinePoliciesRequest, UpdateAccessKeyRequest,
    UpdateUserRequest, UserMeta,
};

use super::{
    Actor, Call, IAM_NS, IamError, IamResult, Xml, all_users, aws_account, aws_arn, check_name,
    entity_arn, find_user, iso, named_or_own_user, page, page_end, path_param, sort_key,
};

/// A user's path as shown.
fn path_of(u: &UserMeta) -> &str {
    if u.path.is_empty() { "/" } else { &u.path }
}

pub(super) fn user_xml(x: &mut Xml, u: &UserMeta) {
    x.el("Path", path_of(u))
        .el("UserName", &u.display_name)
        .el("UserId", &u.user_id)
        .el("Arn", aws_arn(&u.arn))
        .el("CreateDate", iso(u.created_at));
}

/// The system admin is the operator's: only it acts on itself.
fn guard_system_admin(actor: &Actor, u: &UserMeta) -> IamResult<()> {
    if u.arn == crate::admin::SYSTEM_ADMIN_USER_ARN && actor.kind != super::ActorKind::System {
        return Err(IamError::access_denied(
            "only the system admin acts on itself",
        ));
    }
    Ok(())
}

pub(super) async fn create_user(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let name = call.required("UserName")?;
    check_name("UserName", name, 64)?;
    let path = path_param(call, "Path")?;
    actor
        .allow(
            call,
            "CreateUser",
            &entity_arn(&actor.tenant, "user", &path, name),
        )
        .await?;
    let user = call
        .app
        .meta_client
        .clone()
        .create_user(CreateUserRequest {
            display_name: name.to_string(),
            email: String::new(),
            tenant: actor.tenant.clone(),
            path,
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .user
        .unwrap_or_default();
    let mut x = Xml::new();
    x.open("User");
    user_xml(&mut x, &user);
    x.close("User");
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn get_user(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let named = call.opt("UserName").filter(|n| !n.is_empty());
    let user = named_or_own_user(call, actor).await?;
    actor.allow_user(call, "GetUser", &user).await?;
    let mut x = Xml::new();
    x.open("User");
    if named.is_none() && actor.is_root() {
        // The account's root, as AWS shows it.
        let account = aws_account(&actor.tenant);
        x.el("UserId", &account)
            .el("Arn", format!("arn:aws:iam::{account}:root"))
            .el("CreateDate", iso(user.created_at));
    } else {
        user_xml(&mut x, &user);
    }
    x.close("User");
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn list_users(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let prefix = path_prefix(call);
    actor
        .allow(
            call,
            "ListUsers",
            &entity_arn(&actor.tenant, "user", "/", "*"),
        )
        .await?;
    let users: Vec<(String, UserMeta)> = all_users(call.app)
        .await?
        .into_iter()
        .filter(|u| u.tenant == actor.tenant && path_of(u).starts_with(&prefix))
        .map(|u| (sort_key(&u.display_name), u))
        .collect();
    let (users, next) = page(call, users)?;
    let mut x = Xml::new();
    x.open("Users");
    for u in &users {
        x.open("member");
        user_xml(&mut x, u);
        x.close("member");
    }
    x.close("Users");
    page_end(&mut x, next.as_deref());
    call.ok(Some(x), IAM_NS)
}

/// `PathPrefix`, `/` when absent.
pub(super) fn path_prefix(call: &Call<'_>) -> String {
    call.opt("PathPrefix")
        .filter(|p| !p.is_empty())
        .unwrap_or("/")
        .to_string()
}

pub(super) async fn update_user(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let user = find_user(call, actor, call.required("UserName")?).await?;
    let new_name = call.opt("NewUserName").filter(|n| !n.is_empty());
    if let Some(n) = new_name {
        check_name("NewUserName", n, 64)?;
    }
    let new_path = match call.opt("NewPath").filter(|p| !p.is_empty()) {
        Some(_) => Some(path_param(call, "NewPath")?),
        None => None,
    };
    actor.allow_user(call, "UpdateUser", &user).await?;
    guard_system_admin(actor, &user)?;
    call.app.auth_state.forget_user(&user.user_id);
    call.app
        .meta_client
        .clone()
        .update_user(UpdateUserRequest {
            user_id: user.user_id.clone(),
            status: None,
            display_name: new_name.map(str::to_string),
            email: None,
            path: new_path,
        })
        .await
        .map_err(|e| IamError::from_status(&e))?;
    // Again after the commit: a request in between may have cached the
    // old ARN.
    call.app.auth_state.forget_user(&user.user_id);
    call.ok(None, IAM_NS)
}

pub(super) async fn delete_user(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let user = find_user(call, actor, call.required("UserName")?).await?;
    actor.allow_user(call, "DeleteUser", &user).await?;
    guard_system_admin(actor, &user)?;
    if user.user_id == call.auth.user_id {
        return Err(IamError::delete_conflict("you can't delete yourself"));
    }
    // As IAM: keys and policies go first.
    let mut meta = call.app.meta_client.clone();
    let principal = format!("user:{}", user.user_id);
    let keys = meta
        .list_access_keys(ListAccessKeysRequest {
            user_id: user.user_id.clone(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .access_keys;
    let inline = meta
        .list_inline_policies(ListInlinePoliciesRequest {
            principal: principal.clone(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .policies;
    let attached = meta
        .list_attached_policies(ListAttachedPoliciesRequest {
            user_id: user.user_id.clone(),
            ..Default::default()
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .policy_names;
    // Group memberships go with the user (meta drops them in the same
    // commit), which IAM would refuse: tools that clean up delete users
    // before emptying their groups.
    let what = [
        (!keys.is_empty(), "access keys"),
        (!inline.is_empty(), "inline policies"),
        (!attached.is_empty(), "attached policies"),
    ];
    if let Some((_, w)) = what.iter().find(|(has, _)| *has) {
        return Err(IamError::delete_conflict(format!(
            "Cannot delete entity, must remove its {w} first."
        )));
    }
    meta.delete_user(DeleteUserRequest {
        user_id: user.user_id.clone(),
    })
    .await
    .map_err(|e| IamError::from_status(&e))?;
    call.app.auth_state.forget_user(&user.user_id);
    call.app.policy_cache.invalidate_identity(&user.user_id);
    call.ok(None, IAM_NS)
}

// ── Access keys ─────────────────────────────────────────────────────────

fn key_status(k: &AccessKeyMeta) -> &'static str {
    if k.status == KeyStatus::KeyActive as i32 {
        "Active"
    } else {
        "Inactive"
    }
}

pub(super) async fn create_access_key(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let user = named_or_own_user(call, actor).await?;
    actor.allow_user(call, "CreateAccessKey", &user).await?;
    guard_system_admin(actor, &user)?;
    let key = call
        .app
        .meta_client
        .clone()
        .create_access_key(CreateAccessKeyRequest {
            user_id: user.user_id.clone(),
            ..Default::default()
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .access_key
        .unwrap_or_default();
    let mut x = Xml::new();
    x.open("AccessKey")
        .el("UserName", &user.display_name)
        .el("AccessKeyId", &key.access_key_id)
        .el("Status", key_status(&key))
        .el("SecretAccessKey", &key.secret_access_key)
        .el("CreateDate", iso(key.created_at))
        .close("AccessKey");
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn list_access_keys(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let user = named_or_own_user(call, actor).await?;
    actor.allow_user(call, "ListAccessKeys", &user).await?;
    let keys = call
        .app
        .meta_client
        .clone()
        .list_access_keys(ListAccessKeysRequest {
            user_id: user.user_id.clone(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .access_keys
        .into_iter()
        .map(|k| (k.access_key_id.clone(), k))
        .collect();
    let (keys, next) = page(call, keys)?;
    let mut x = Xml::new();
    x.open("AccessKeyMetadata");
    for k in &keys {
        x.open("member")
            .el("UserName", &user.display_name)
            .el("AccessKeyId", &k.access_key_id)
            .el("Status", key_status(k))
            .el("CreateDate", iso(k.created_at))
            .close("member");
    }
    x.close("AccessKeyMetadata");
    page_end(&mut x, next.as_deref());
    call.ok(Some(x), IAM_NS)
}

/// The user a key call names, and its key `AccessKeyId`, which must be
/// that user's.
async fn user_and_key(
    call: &Call<'_>,
    actor: &Actor,
    action: &str,
) -> IamResult<(UserMeta, String)> {
    let user = named_or_own_user(call, actor).await?;
    let key_id = call.required("AccessKeyId")?.to_string();
    actor.allow_user(call, action, &user).await?;
    guard_system_admin(actor, &user)?;
    let owner = call
        .app
        .meta_client
        .clone()
        .get_access_key(GetAccessKeyRequest {
            access_key_id: key_id.clone(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .access_key
        .map(|k| k.user_id);
    if owner.as_deref() != Some(user.user_id.as_str()) {
        return Err(IamError::no_such_entity(format!(
            "The Access Key with id {key_id} cannot be found."
        )));
    }
    Ok((user, key_id))
}

pub(super) async fn update_access_key(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let status = match call.required("Status")? {
        "Active" => KeyStatus::KeyActive,
        "Inactive" => KeyStatus::KeyInactive,
        other => {
            return Err(IamError::validation(format!(
                "Status must be Active or Inactive, not {other}"
            )));
        }
    };
    let (_, key_id) = user_and_key(call, actor, "UpdateAccessKey").await?;
    if status == KeyStatus::KeyInactive && call.auth.access_key_id == key_id {
        return Err(IamError::validation(
            "you can't deactivate the key you are using",
        ));
    }
    call.app
        .meta_client
        .clone()
        .update_access_key(UpdateAccessKeyRequest {
            access_key_id: key_id.clone(),
            status: status as i32,
        })
        .await
        .map_err(|e| IamError::from_status(&e))?;
    call.app.auth_state.forget_key(&key_id);
    call.ok(None, IAM_NS)
}

pub(super) async fn delete_access_key(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let (_, key_id) = user_and_key(call, actor, "DeleteAccessKey").await?;
    call.app
        .meta_client
        .clone()
        .delete_access_key(DeleteAccessKeyRequest {
            access_key_id: key_id.clone(),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?;
    call.app.auth_state.forget_key(&key_id);
    call.ok(None, IAM_NS)
}
