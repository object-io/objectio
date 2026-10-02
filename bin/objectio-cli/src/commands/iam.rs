//! Tenants, users, access keys, policies, groups and roles.

use super::{Ctx, key_values, parse_size, read_json, seg, tenant_query};
use crate::cli::{
    GroupCmd, KeyCmd, PolicyCmd, Principal, RoleCmd, TenantAdminCmd, TenantCmd, TenantFields,
    UserCmd,
};
use crate::output::{field, key_values as kv, rows_of, ts};
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

/// One item per line.
fn lines<S: AsRef<str>>(items: &[S]) -> String {
    items.iter().fold(String::new(), |mut acc, s| {
        acc.push_str(s.as_ref());
        acc.push('\n');
        acc
    })
}

const TENANT_COLUMNS: &[(&str, &str)] = &[
    ("NAME", "name"),
    ("DISPLAY NAME", "display_name"),
    ("ENABLED", "enabled"),
    ("DEFAULT POOL", "default_pool"),
    ("ADMINS", "admin_users"),
    ("OIDC", "oidc_provider"),
];

const USER_COLUMNS: &[(&str, &str)] = &[
    ("USER ID", "user_id"),
    ("NAME", "display_name"),
    ("TENANT", "tenant"),
    ("STATUS", "status"),
    ("ARN", "arn"),
];

const KEY_COLUMNS: &[(&str, &str)] = &[
    ("ACCESS KEY ID", "access_key_id"),
    ("STATUS", "status"),
    ("OPERATION", "operation"),
    ("SCOPE", "scope"),
    ("CREATED", "created"),
];

/// The fields of a tenant body that were given, and nothing else — an
/// update is merged server-side, so absent fields keep their values.
fn tenant_body(f: TenantFields) -> Result<Map<String, Value>> {
    let mut m = Map::new();
    if let Some(v) = f.display_name {
        m.insert("display_name".into(), json!(v));
    }
    if let Some(v) = f.default_pool {
        m.insert("default_pool".into(), json!(v));
    }
    if !f.allowed_pools.is_empty() {
        m.insert("allowed_pools".into(), json!(f.allowed_pools));
    }
    if let Some(v) = f.quota_bytes {
        m.insert("quota_bytes".into(), json!(parse_size(&v)?));
    }
    if let Some(v) = f.quota_buckets {
        m.insert("quota_buckets".into(), json!(v));
    }
    if let Some(v) = f.quota_objects {
        m.insert("quota_objects".into(), json!(v));
    }
    if let Some(v) = f.oidc_provider {
        m.insert("oidc_provider".into(), json!(v));
    }
    if !f.labels.is_empty() {
        m.insert("labels".into(), Value::Object(key_values(&f.labels)?));
    }
    Ok(m)
}

fn show_tenant(v: &Value) -> String {
    kv(v)
}

pub async fn tenant(cmd: TenantCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        TenantCmd::List => {
            let v = ctx.api.get("/_admin/tenants", &[]).await?;
            ctx.out
                .list(&v, &rows_of(&v, "tenants"), TENANT_COLUMNS, "No tenants.")?;
        }
        TenantCmd::Show { name } => {
            let v = ctx
                .api
                .get(&format!("/_admin/tenants/{}", seg(&name)), &[])
                .await?;
            ctx.out.emit(&v, show_tenant)?;
        }
        TenantCmd::Create {
            name,
            fields,
            disabled,
        } => {
            let mut body = tenant_body(fields)?;
            body.insert("name".into(), json!(name));
            body.insert("enabled".into(), json!(!disabled));
            let v = ctx
                .api
                .send_json("POST", "/_admin/tenants", &[], Value::Object(body))
                .await?;
            ctx.out.emit(&v, |v| {
                format!(
                    "Created tenant {}\n",
                    field(v, "name").as_str().unwrap_or(&name)
                )
            })?;
        }
        TenantCmd::Update {
            name,
            fields,
            enabled,
        } => {
            let mut body = tenant_body(fields)?;
            if let Some(e) = enabled {
                body.insert("enabled".into(), json!(e));
            }
            if body.is_empty() {
                bail!("nothing to update: give at least one field");
            }
            let v = ctx
                .api
                .send_json(
                    "PUT",
                    &format!("/_admin/tenants/{}", seg(&name)),
                    &[],
                    Value::Object(body),
                )
                .await?;
            ctx.out.emit(&v, show_tenant)?;
        }
        TenantCmd::Delete { name } => {
            ctx.api
                .delete(&format!("/_admin/tenants/{}", seg(&name)), &[])
                .await?;
            ctx.out.done(&format!("Deleted tenant {name}"))?;
        }
        TenantCmd::Admin { action } => match action {
            TenantAdminCmd::List { tenant } => {
                let v = ctx
                    .api
                    .get(&format!("/_admin/tenants/{}", seg(&tenant)), &[])
                    .await?;
                let admins = v.get("admin_users").cloned().unwrap_or_else(|| json!([]));
                ctx.out.emit(&admins, |a| {
                    let list: Vec<String> = a
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    if list.is_empty() {
                        format!("Tenant {tenant} has no admins.\n")
                    } else {
                        lines(&list)
                    }
                })?;
            }
            TenantAdminCmd::Add { tenant, user } => {
                let field_name = if user.starts_with("arn:") {
                    "user_arn"
                } else {
                    "user_id"
                };
                let v = ctx
                    .api
                    .send_json(
                        "POST",
                        &format!("/_admin/tenants/{}/admins", seg(&tenant)),
                        &[],
                        json!({ field_name: user }),
                    )
                    .await?;
                ctx.out.emit(&v, |_| {
                    format!("{user} is now an admin of tenant {tenant}\n")
                })?;
            }
            TenantAdminCmd::Remove { tenant, user } => {
                ctx.api
                    .delete(
                        &format!("/_admin/tenants/{}/admins/{}", seg(&tenant), seg(&user)),
                        &[],
                    )
                    .await?;
                ctx.out
                    .done(&format!("{user} is no longer an admin of tenant {tenant}"))?;
            }
        },
    }
    Ok(())
}

pub async fn user(cmd: UserCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        UserCmd::List { tenant } => {
            // The endpoint takes no tenant: it answers with every user for
            // the system admin and the caller's tenant's for a tenant admin.
            // --tenant narrows that here.
            let mut v = ctx.api.get("/_admin/users", &[]).await?;
            if let (Some(t), Some(users)) = (
                &tenant.tenant,
                v.get_mut("users").and_then(Value::as_array_mut),
            ) {
                users.retain(|u| u["tenant"].as_str() == Some(t.as_str()));
            }
            ctx.out
                .list(&v, &rows_of(&v, "users"), USER_COLUMNS, "No users.")?;
        }
        UserCmd::Show { user_id } => {
            let v = ctx
                .api
                .get(&format!("/_admin/users/{}", seg(&user_id)), &[])
                .await?;
            ctx.out.emit(&v, kv)?;
        }
        UserCmd::Create {
            display_name,
            email,
            tenant,
        } => {
            let mut body = json!({ "display_name": display_name });
            if let Some(e) = email {
                body["email"] = json!(e);
            }
            if let Some(t) = tenant.tenant {
                body["tenant"] = json!(t);
            }
            let v = ctx
                .api
                .send_json("POST", "/_admin/users", &[], body)
                .await?;
            ctx.out.emit(&v, |v| {
                format!(
                    "Created user {} ({})\n{}",
                    field(v, "user_id").as_str().unwrap_or("?"),
                    display_name,
                    kv(v)
                )
            })?;
        }
        UserCmd::Update {
            user_id,
            display_name,
            email,
        } => {
            let mut body = Map::new();
            if let Some(n) = display_name {
                body.insert("display_name".into(), json!(n));
            }
            if let Some(e) = email {
                body.insert("email".into(), json!(e));
            }
            if body.is_empty() {
                bail!("nothing to update: give --display-name or --email");
            }
            update_user(ctx, &user_id, Value::Object(body)).await?;
        }
        UserCmd::Suspend { user_id } => {
            update_user(ctx, &user_id, json!({"status": "suspended"})).await?;
        }
        UserCmd::Activate { user_id } => {
            update_user(ctx, &user_id, json!({"status": "active"})).await?;
        }
        UserCmd::Delete { user_id } => {
            ctx.api
                .delete(&format!("/_admin/users/{}", seg(&user_id)), &[])
                .await?;
            ctx.out.done(&format!("Deleted user {user_id}"))?;
        }
    }
    Ok(())
}

async fn update_user(ctx: &mut Ctx<'_, '_>, user_id: &str, body: Value) -> Result<()> {
    let v = ctx
        .api
        .send_json("PUT", &format!("/_admin/users/{}", seg(user_id)), &[], body)
        .await?;
    ctx.out.emit(&v, kv)?;
    Ok(())
}

pub async fn key(cmd: KeyCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        KeyCmd::List { user_id } => {
            let v = ctx
                .api
                .get(&format!("/_admin/users/{}/access-keys", seg(&user_id)), &[])
                .await?;
            let rows: Vec<Value> = rows_of(&v, "access_keys")
                .into_iter()
                .map(|mut k| {
                    k["created"] = ts(&k["created_at"]);
                    k
                })
                .collect();
            ctx.out.list(&v, &rows, KEY_COLUMNS, "No access keys.")?;
        }
        KeyCmd::Create {
            user_id,
            scope,
            read_only,
        } => {
            if let Some(s) = &scope
                && let Err(e) = objectio_auth::validate_scope(s)
            {
                bail!("--scope {s}: {e}");
            }
            let mut body = json!({ "operation": if read_only { "R" } else { "RW" } });
            if let Some(s) = scope {
                body["scope"] = json!(s);
            }
            let v = ctx
                .api
                .send_json(
                    "POST",
                    &format!("/_admin/users/{}/access-keys", seg(&user_id)),
                    &[],
                    body,
                )
                .await?;
            ctx.out.emit(&v, |v| {
                format!(
                    "Access key created. The secret is shown only this once — store it now.\n\n\
                     access_key_id:     {}\nsecret_access_key: {}\nscope:             {}\noperation:         {}\n",
                    v["access_key_id"].as_str().unwrap_or("?"),
                    v["secret_access_key"].as_str().unwrap_or("?"),
                    crate::output::cell(&v["scope"]),
                    crate::output::cell(&v["operation"]),
                )
            })?;
        }
        KeyCmd::Activate { access_key_id } => {
            set_key_status(ctx, &access_key_id, "active").await?;
        }
        KeyCmd::Deactivate { access_key_id } => {
            set_key_status(ctx, &access_key_id, "inactive").await?;
        }
        KeyCmd::Delete { access_key_id } => {
            ctx.api
                .delete(&format!("/_admin/access-keys/{}", seg(&access_key_id)), &[])
                .await?;
            ctx.out
                .done(&format!("Deleted access key {access_key_id}"))?;
        }
    }
    Ok(())
}

async fn set_key_status(ctx: &mut Ctx<'_, '_>, id: &str, status: &str) -> Result<()> {
    let v = ctx
        .api
        .send_json(
            "PUT",
            &format!("/_admin/access-keys/{}", seg(id)),
            &[],
            json!({ "status": status }),
        )
        .await?;
    ctx.out.emit(&v, kv)?;
    Ok(())
}

/// The principal fields an attach/detach/attached request names.
fn principal_fields(p: &Principal) -> Vec<(&'static str, String)> {
    [
        ("user_id", &p.user),
        ("group_id", &p.group),
        ("role_name", &p.role),
    ]
    .into_iter()
    .filter_map(|(k, v)| v.clone().map(|v| (k, v)))
    .collect()
}

fn principal_label(p: &Principal) -> String {
    p.user.as_ref().map_or_else(
        || {
            p.group.as_ref().map_or_else(
                || format!("role {}", p.role.as_deref().unwrap_or("?")),
                |g| format!("group {g}"),
            )
        },
        |u| format!("user {u}"),
    )
}

const POLICY_COLUMNS: &[(&str, &str)] = &[
    ("NAME", "name"),
    ("TENANT", "tenant"),
    ("SHARED", "shared"),
    ("STATEMENTS", "statements"),
    ("UPDATED", "updated"),
];

pub async fn policy(cmd: PolicyCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        PolicyCmd::List { tenant } => {
            let v = ctx
                .api
                .get("/_admin/policies", &tenant_query(&tenant))
                .await?;
            let rows: Vec<Value> = rows_of(&v, "policies")
                .into_iter()
                .map(|mut p| {
                    p["statements"] = json!(p["policy"]["Statement"].as_array().map_or_else(
                        || usize::from(p["policy"]["Statement"].is_object()),
                        Vec::len
                    ));
                    p["updated"] = ts(&p["updated_at"]);
                    p
                })
                .collect();
            ctx.out.list(&v, &rows, POLICY_COLUMNS, "No policies.")?;
        }
        PolicyCmd::Show { name, tenant } => {
            let v = ctx
                .api
                .get(
                    &format!("/_admin/policies/{}", seg(&name)),
                    &tenant_query(&tenant),
                )
                .await?;
            if ctx.out.json() {
                ctx.out.raw_json(&v)?;
            } else {
                ctx.out.line(&format!(
                    "Policy {} (tenant: {}, shared: {})",
                    crate::output::cell(&v["name"]),
                    crate::output::cell(&v["tenant"]),
                    v["shared"].as_bool().unwrap_or(false)
                ))?;
                ctx.out.raw_json(&v["policy"])?;
            }
        }
        PolicyCmd::Create {
            name,
            file,
            shared,
            tenant,
        } => {
            let mut body = json!({ "name": name, "policy": read_json(&file)? });
            if shared {
                body["shared"] = json!(true);
            }
            let v = ctx
                .api
                .send_json("POST", "/_admin/policies", &tenant_query(&tenant), body)
                .await?;
            ctx.out.emit(&v, |_| format!("Created policy {name}\n"))?;
        }
        PolicyCmd::Update { name, file, tenant } => {
            let v = ctx
                .api
                .send_json(
                    "PUT",
                    &format!("/_admin/policies/{}", seg(&name)),
                    &tenant_query(&tenant),
                    json!({ "policy": read_json(&file)? }),
                )
                .await?;
            ctx.out.emit(&v, |_| format!("Updated policy {name}\n"))?;
        }
        PolicyCmd::Delete { name, tenant } => {
            ctx.api
                .delete(
                    &format!("/_admin/policies/{}", seg(&name)),
                    &tenant_query(&tenant),
                )
                .await?;
            ctx.out.done(&format!("Deleted policy {name}"))?;
        }
        PolicyCmd::Attach { name, to, tenant } => {
            change_attachment(ctx, "attach", &name, &to, tenant.tenant).await?;
            ctx.out
                .done(&format!("Attached {name} to {}", principal_label(&to)))?;
        }
        PolicyCmd::Detach { name, from, tenant } => {
            change_attachment(ctx, "detach", &name, &from, tenant.tenant).await?;
            ctx.out
                .done(&format!("Detached {name} from {}", principal_label(&from)))?;
        }
        PolicyCmd::Attached { of, tenant } => {
            let mut query: Vec<(String, String)> = principal_fields(&of)
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect();
            query.extend(tenant_query(&tenant));
            let v = ctx.api.get("/_admin/policies/attached", &query).await?;
            ctx.out.emit(&v, |v| {
                let names: Vec<&str> = v["policy_names"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                if names.is_empty() {
                    format!("No policies attached to {}.\n", principal_label(&of))
                } else {
                    lines(&names)
                }
            })?;
        }
    }
    Ok(())
}

async fn change_attachment(
    ctx: &Ctx<'_, '_>,
    verb: &str,
    name: &str,
    p: &Principal,
    tenant: Option<String>,
) -> Result<()> {
    let mut body = json!({ "policy_name": name });
    for (k, v) in principal_fields(p) {
        body[k] = json!(v);
    }
    // The attach endpoint reads the tenant from the body, not the query.
    if let Some(t) = tenant {
        body["tenant"] = json!(t);
    }
    ctx.api
        .send_json("POST", &format!("/_admin/policies/{verb}"), &[], body)
        .await?;
    Ok(())
}

const GROUP_COLUMNS: &[(&str, &str)] = &[
    ("GROUP ID", "group_id"),
    ("NAME", "group_name"),
    ("TENANT", "tenant"),
    ("MEMBERS", "member_user_ids"),
];

pub async fn group(cmd: GroupCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        GroupCmd::List { tenant } => {
            let v = ctx
                .api
                .get("/_admin/groups", &tenant_query(&tenant))
                .await?;
            ctx.out
                .list(&v, &rows_of(&v, "groups"), GROUP_COLUMNS, "No groups.")?;
        }
        GroupCmd::Show { group_id } => {
            let v = ctx
                .api
                .get(&format!("/_admin/groups/{}", seg(&group_id)), &[])
                .await?;
            ctx.out.emit(&v, kv)?;
        }
        GroupCmd::Create { name, tenant } => {
            let v = ctx
                .api
                .send_json(
                    "POST",
                    "/_admin/groups",
                    &tenant_query(&tenant),
                    json!({ "group_name": name }),
                )
                .await?;
            ctx.out.emit(&v, |v| {
                format!(
                    "Created group {name} ({})\n",
                    v["group_id"].as_str().unwrap_or("?")
                )
            })?;
        }
        GroupCmd::Delete { group_id } => {
            ctx.api
                .delete(&format!("/_admin/groups/{}", seg(&group_id)), &[])
                .await?;
            ctx.out.done(&format!("Deleted group {group_id}"))?;
        }
        GroupCmd::AddUser { group_id, user_id } => {
            ctx.api
                .send_json(
                    "POST",
                    &format!("/_admin/groups/{}/members", seg(&group_id)),
                    &[],
                    json!({ "user_id": user_id }),
                )
                .await?;
            ctx.out
                .done(&format!("Added {user_id} to group {group_id}"))?;
        }
        GroupCmd::RemoveUser { group_id, user_id } => {
            ctx.api
                .delete(
                    &format!(
                        "/_admin/groups/{}/members/{}",
                        seg(&group_id),
                        seg(&user_id)
                    ),
                    &[],
                )
                .await?;
            ctx.out
                .done(&format!("Removed {user_id} from group {group_id}"))?;
        }
    }
    Ok(())
}

const ROLE_COLUMNS: &[(&str, &str)] = &[
    ("NAME", "name"),
    ("TENANT", "tenant"),
    ("MAX SESSION", "max_session_seconds"),
    ("ARN", "arn"),
];

pub async fn role(cmd: RoleCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        RoleCmd::List { tenant } => {
            let v = ctx.api.get("/_admin/roles", &tenant_query(&tenant)).await?;
            ctx.out
                .list(&v, &rows_of(&v, "roles"), ROLE_COLUMNS, "No roles.")?;
        }
        RoleCmd::Show { name, tenant } => {
            let v = ctx
                .api
                .get(
                    &format!("/_admin/roles/{}", seg(&name)),
                    &tenant_query(&tenant),
                )
                .await?;
            ctx.out.emit(&v, |v| {
                let mut summary = v.clone();
                let trust = summary
                    .as_object_mut()
                    .and_then(|o| o.remove("trust_policy"))
                    .unwrap_or(Value::Null);
                format!(
                    "{}trust_policy:\n{}\n",
                    kv(&summary),
                    serde_json::to_string_pretty(&trust).unwrap_or_default()
                )
            })?;
        }
        RoleCmd::Create {
            name,
            trust_file,
            description,
            max_session_seconds,
            tenant,
        } => {
            let mut body = json!({ "name": name, "trust_policy": read_json(&trust_file)? });
            if let Some(d) = description {
                body["description"] = json!(d);
            }
            if let Some(s) = max_session_seconds {
                body["max_session_seconds"] = json!(s);
            }
            let v = ctx
                .api
                .send_json("POST", "/_admin/roles", &tenant_query(&tenant), body)
                .await?;
            ctx.out.emit(&v, |v| {
                format!(
                    "Created role {name}\narn: {}\n",
                    v["arn"].as_str().unwrap_or("?")
                )
            })?;
        }
        RoleCmd::Update {
            name,
            trust_file,
            description,
            max_session_seconds,
            tenant,
        } => {
            let mut body = Map::new();
            if let Some(f) = trust_file {
                body.insert("trust_policy".into(), read_json(&f)?);
            }
            if let Some(d) = description {
                body.insert("description".into(), json!(d));
            }
            if let Some(s) = max_session_seconds {
                body.insert("max_session_seconds".into(), json!(s));
            }
            if body.is_empty() {
                bail!(
                    "nothing to update: give --trust-file, --description or --max-session-seconds"
                );
            }
            let v = ctx
                .api
                .send_json(
                    "PUT",
                    &format!("/_admin/roles/{}", seg(&name)),
                    &tenant_query(&tenant),
                    Value::Object(body),
                )
                .await?;
            ctx.out.emit(&v, |_| format!("Updated role {name}\n"))?;
        }
        RoleCmd::Delete { name, tenant } => {
            ctx.api
                .delete(
                    &format!("/_admin/roles/{}", seg(&name)),
                    &tenant_query(&tenant),
                )
                .await?;
            ctx.out.done(&format!("Deleted role {name}"))?;
        }
    }
    Ok(())
}
