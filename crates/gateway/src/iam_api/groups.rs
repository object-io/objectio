//! Groups and their members.

use axum::response::Response;
use objectio_proto::metadata::{
    AddUserToGroupRequest, CreateGroupRequest, DeleteGroupRequest, GetUserGroupsRequest, GroupMeta,
    ListAttachedPoliciesRequest, ListInlinePoliciesRequest, RemoveUserFromGroupRequest,
    UpdateGroupRequest,
};

use super::users::{path_prefix, user_xml};
use super::{
    Actor, Call, IAM_NS, IamError, IamResult, Xml, all_groups, all_users, aws_arn, check_name,
    entity_arn, find_group, find_user, iso, page, page_end, path_param, sort_key,
};

fn path_of(g: &GroupMeta) -> &str {
    if g.path.is_empty() { "/" } else { &g.path }
}

pub(super) fn group_xml(x: &mut Xml, g: &GroupMeta) {
    x.el("Path", path_of(g))
        .el("GroupName", &g.group_name)
        .el("GroupId", &g.group_id)
        .el("Arn", aws_arn(&g.arn))
        .el("CreateDate", iso(g.created_at));
}

/// The ARN to authorize a call on a group against.
pub(super) fn group_resource(g: &GroupMeta) -> String {
    objectio_auth::policy::canonical_arn(&g.arn).into_owned()
}

pub(super) async fn create_group(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let name = call.required("GroupName")?;
    check_name("GroupName", name, 128)?;
    let path = path_param(call, "Path")?;
    actor
        .allow(
            call,
            "CreateGroup",
            &entity_arn(&actor.tenant, "group", &path, name),
        )
        .await?;
    let group = call
        .app
        .meta_client
        .clone()
        .create_group(CreateGroupRequest {
            group_name: name.to_string(),
            tenant: actor.tenant.clone(),
            path,
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .group
        .unwrap_or_default();
    let mut x = Xml::new();
    x.open("Group");
    group_xml(&mut x, &group);
    x.close("Group");
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn get_group(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let group = find_group(call, actor, call.required("GroupName")?).await?;
    actor
        .allow(call, "GetGroup", &group_resource(&group))
        .await?;
    let members: Vec<(String, _)> = all_users(call.app)
        .await?
        .into_iter()
        .filter(|u| group.member_user_ids.contains(&u.user_id))
        .map(|u| (sort_key(&u.display_name), u))
        .collect();
    let (members, next) = page(call, members)?;
    let mut x = Xml::new();
    x.open("Group");
    group_xml(&mut x, &group);
    x.close("Group").open("Users");
    for u in &members {
        x.open("member");
        user_xml(&mut x, u);
        x.close("member");
    }
    x.close("Users");
    page_end(&mut x, next.as_deref());
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn list_groups(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let prefix = path_prefix(call);
    actor
        .allow(
            call,
            "ListGroups",
            &entity_arn(&actor.tenant, "group", "/", "*"),
        )
        .await?;
    let groups = all_groups(call.app)
        .await?
        .into_iter()
        .filter(|g| g.tenant == actor.tenant && path_of(g).starts_with(&prefix))
        .map(|g| (sort_key(&g.group_name), g))
        .collect();
    list_response(call, groups)
}

fn list_response(call: &Call<'_>, groups: Vec<(String, GroupMeta)>) -> IamResult<Response> {
    let (groups, next) = page(call, groups)?;
    let mut x = Xml::new();
    x.open("Groups");
    for g in &groups {
        x.open("member");
        group_xml(&mut x, g);
        x.close("member");
    }
    x.close("Groups");
    page_end(&mut x, next.as_deref());
    call.ok(Some(x), IAM_NS)
}

pub(super) async fn list_groups_for_user(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let user = find_user(call, actor, call.required("UserName")?).await?;
    actor.allow_user(call, "ListGroupsForUser", &user).await?;
    let groups = call
        .app
        .meta_client
        .clone()
        .get_user_groups(GetUserGroupsRequest {
            user_id: user.user_id,
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .groups
        .into_iter()
        .map(|g| (sort_key(&g.group_name), g))
        .collect();
    list_response(call, groups)
}

pub(super) async fn update_group(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let group = find_group(call, actor, call.required("GroupName")?).await?;
    let new_name = call.opt("NewGroupName").filter(|n| !n.is_empty());
    if let Some(n) = new_name {
        check_name("NewGroupName", n, 128)?;
    }
    let new_path = match call.opt("NewPath").filter(|p| !p.is_empty()) {
        Some(_) => Some(path_param(call, "NewPath")?),
        None => None,
    };
    actor
        .allow(call, "UpdateGroup", &group_resource(&group))
        .await?;
    call.app
        .meta_client
        .clone()
        .update_group(UpdateGroupRequest {
            group_id: group.group_id.clone(),
            group_name: new_name.map(str::to_string),
            path: new_path,
        })
        .await
        .map_err(|e| IamError::from_status(&e))?;
    call.ok(None, IAM_NS)
}

pub(super) async fn delete_group(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    let group = find_group(call, actor, call.required("GroupName")?).await?;
    actor
        .allow(call, "DeleteGroup", &group_resource(&group))
        .await?;
    let mut meta = call.app.meta_client.clone();
    let inline = meta
        .list_inline_policies(ListInlinePoliciesRequest {
            principal: format!("group:{}", group.group_id),
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .policies;
    let attached = meta
        .list_attached_policies(ListAttachedPoliciesRequest {
            group_id: group.group_id.clone(),
            ..Default::default()
        })
        .await
        .map_err(|e| IamError::from_status(&e))?
        .into_inner()
        .policy_names;
    let what = [
        (!group.member_user_ids.is_empty(), "users"),
        (!inline.is_empty(), "inline policies"),
        (!attached.is_empty(), "attached policies"),
    ];
    if let Some((_, w)) = what.iter().find(|(has, _)| *has) {
        return Err(IamError::delete_conflict(format!(
            "Cannot delete entity, must remove its {w} first."
        )));
    }
    meta.delete_group(DeleteGroupRequest {
        group_id: group.group_id.clone(),
    })
    .await
    .map_err(|e| IamError::from_status(&e))?;
    call.app.policy_cache.invalidate_identity(&group.group_id);
    call.ok(None, IAM_NS)
}

pub(super) async fn add_user_to_group(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    change_member(call, actor, true).await
}

pub(super) async fn remove_user_from_group(call: &Call<'_>, actor: &Actor) -> IamResult<Response> {
    change_member(call, actor, false).await
}

async fn change_member(call: &Call<'_>, actor: &Actor, add: bool) -> IamResult<Response> {
    let group = find_group(call, actor, call.required("GroupName")?).await?;
    let user = find_user(call, actor, call.required("UserName")?).await?;
    let action = if add {
        "AddUserToGroup"
    } else {
        "RemoveUserFromGroup"
    };
    actor.allow(call, action, &group_resource(&group)).await?;
    let mut meta = call.app.meta_client.clone();
    let result = if add {
        meta.add_user_to_group(AddUserToGroupRequest {
            group_id: group.group_id.clone(),
            user_id: user.user_id.clone(),
        })
        .await
        .map(drop)
    } else {
        meta.remove_user_from_group(RemoveUserFromGroupRequest {
            group_id: group.group_id.clone(),
            user_id: user.user_id.clone(),
        })
        .await
        .map(drop)
    };
    match result {
        Ok(()) => {}
        // Adding a member twice is no change, as in IAM.
        Err(e) if add && e.code() == tonic::Code::AlreadyExists => {}
        Err(e) => return Err(IamError::from_status(&e)),
    }
    call.app.policy_cache.invalidate_identity(&user.user_id);
    call.ok(None, IAM_NS)
}
