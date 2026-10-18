//! Buckets and provisioning.

use super::{Ctx, q, read_input, read_json, seg};
use crate::cli::{BucketCmd, BucketDedupCmd, BucketPolicyCmd, ProvisionCmd, XmlDocCmd};
use crate::http::Body;
use crate::output::{cell, key_values as kv, rows_of, ts};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

const BUCKET_COLUMNS: &[(&str, &str)] = &[
    ("NAME", "name"),
    ("TENANT", "tenant"),
    ("OWNER", "owner"),
    ("POOL", "pool"),
    ("CREATED", "created"),
];

/// The admin bucket listing, narrowed to `tenant` when given. The endpoint
/// itself takes no tenant: it lists the caller's tenant (every bucket, for
/// the system admin).
async fn list_buckets(ctx: &Ctx<'_, '_>, tenant: Option<&str>) -> Result<Value> {
    let mut v = ctx.api.get("/_admin/buckets", &[]).await?;
    if let (Some(t), Some(b)) = (tenant, v.get_mut("buckets").and_then(Value::as_array_mut)) {
        b.retain(|x| x["tenant"].as_str() == Some(t));
    }
    Ok(v)
}

fn with_created(rows: Vec<Value>) -> Vec<Value> {
    rows.into_iter()
        .map(|mut b| {
            b["created"] = ts(&b["created_at"]);
            b
        })
        .collect()
}

pub async fn bucket(cmd: BucketCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        BucketCmd::List { tenant } => {
            let v = list_buckets(ctx, tenant.tenant.as_deref()).await?;
            let rows = with_created(rows_of(&v, "buckets"));
            ctx.out.list(&v, &rows, BUCKET_COLUMNS, "No buckets.")?;
        }
        BucketCmd::Show { name } => {
            // There is no single-bucket GET on the admin API; take it from
            // the listing.
            let v = list_buckets(ctx, None).await?;
            let b = rows_of(&v, "buckets")
                .into_iter()
                .find(|b| b["name"].as_str() == Some(name.as_str()))
                .ok_or_else(|| anyhow!("bucket {name} not found"))?;
            ctx.out.emit(&b, |b| {
                let mut b = b.clone();
                b["created_at"] = ts(&b["created_at"]);
                kv(&b)
            })?;
        }
        BucketCmd::Create { name, pool, tenant } => {
            let v = create_bucket(ctx, &name, pool, tenant.tenant).await?;
            ctx.out.emit(&v, |_| format!("Created bucket {name}\n"))?;
        }
        BucketCmd::Delete { name } => {
            ctx.api
                .delete(&format!("/_admin/buckets/{}", seg(&name)), &[])
                .await?;
            ctx.out.done(&format!("Deleted bucket {name}"))?;
        }
        BucketCmd::SetOwner { name, owner } => {
            ctx.api
                .send_json(
                    "PUT",
                    &format!("/_admin/buckets/{}/owner", seg(&name)),
                    &[],
                    json!({ "owner": owner }),
                )
                .await?;
            ctx.out
                .done(&format!("Bucket {name} is now owned by {owner}"))?;
        }
        BucketCmd::SetQuota {
            name,
            bytes,
            objects,
        } => {
            let bytes = super::parse_size(&bytes)?;
            ctx.api
                .send_json(
                    "PUT",
                    &format!("/_admin/buckets/{}/quota", seg(&name)),
                    &[],
                    json!({ "quota_bytes": bytes, "quota_objects": objects }),
                )
                .await?;
            ctx.out.done(&format!(
                "Bucket {name}: quota {bytes} bytes, {objects} objects (0 = unlimited)"
            ))?;
        }
        BucketCmd::Policy { action } => bucket_policy(action, ctx).await?,
        BucketCmd::Dedup { action } => bucket_dedup(action, ctx).await?,
        BucketCmd::Lifecycle { action } => xml_subresource(ctx, "lifecycle", action).await?,
        BucketCmd::Cors { action } => xml_subresource(ctx, "cors", action).await?,
    }
    Ok(())
}

async fn create_bucket(
    ctx: &Ctx<'_, '_>,
    name: &str,
    pool: Option<String>,
    tenant: Option<String>,
) -> Result<Value> {
    let mut body = json!({ "name": name });
    if let Some(p) = pool {
        body["pool"] = json!(p);
    }
    if let Some(t) = tenant {
        body["tenant"] = json!(t);
    }
    ctx.api
        .send_json("POST", "/_admin/buckets", &[], body)
        .await
}

async fn bucket_policy(cmd: BucketPolicyCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        BucketPolicyCmd::Get { bucket } => {
            let v = ctx
                .api
                .get(&format!("/_admin/buckets/{}/policy", seg(&bucket)), &[])
                .await?;
            if ctx.out.json() {
                ctx.out.raw_json(&v)?;
            } else if v["has_policy"].as_bool() == Some(true) {
                ctx.out.raw_json(&v["policy"])?;
            } else {
                ctx.out.line(&format!(
                    "Bucket {bucket} has no policy (owner-only access)."
                ))?;
            }
        }
        BucketPolicyCmd::Put { bucket, file } => {
            let doc = read_json(&file)?;
            ctx.api
                .send_json(
                    "PUT",
                    &format!("/_admin/buckets/{}/policy", seg(&bucket)),
                    &[],
                    doc,
                )
                .await?;
            ctx.out.done(&format!("Policy set on {bucket}"))?;
        }
        BucketPolicyCmd::Delete { bucket } => {
            ctx.api
                .delete(&format!("/_admin/buckets/{}/policy", seg(&bucket)), &[])
                .await?;
            ctx.out.done(&format!("Policy removed from {bucket}"))?;
        }
    }
    Ok(())
}

fn show_dedup(v: &Value) -> String {
    let level = |x: &Value| -> String {
        if x.is_null() {
            "inherit".into()
        } else {
            format!("mode={} scope={}", cell(&x["mode"]), cell(&x["scope"]))
        }
    };
    format!(
        "bucket:    {}\ntenant:    {}{}\ncluster:   {}\neffective: mode={} (from {}) scope={} (from {})\n",
        level(&v["bucket"]),
        level(&v["tenant"]),
        v["tenant_name"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(|t| format!(" [{t}]"))
            .unwrap_or_default(),
        level(&v["cluster"]),
        cell(&v["effective"]["mode"]),
        cell(&v["effective"]["mode_from"]),
        cell(&v["effective"]["scope"]),
        cell(&v["effective"]["scope_from"]),
    )
}

async fn bucket_dedup(cmd: BucketDedupCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        BucketDedupCmd::Get { bucket } => {
            let v = ctx
                .api
                .get(&format!("/_admin/buckets/{}/dedup", seg(&bucket)), &[])
                .await?;
            ctx.out.emit(&v, show_dedup)?;
        }
        BucketDedupCmd::Set {
            bucket,
            mode,
            scope,
        } => {
            if mode.is_none() && scope.is_none() {
                bail!("give --mode and/or --scope (or use `dedup delete` to inherit)");
            }
            let mut body = json!({});
            if let Some(m) = mode {
                body["mode"] = json!(m);
            }
            if let Some(s) = scope {
                body["scope"] = json!(s);
            }
            let v = ctx
                .api
                .send_json(
                    "PUT",
                    &format!("/_admin/buckets/{}/dedup", seg(&bucket)),
                    &[],
                    body,
                )
                .await?;
            ctx.out.emit(&v, show_dedup)?;
        }
        BucketDedupCmd::Delete { bucket } => {
            let v = ctx
                .api
                .delete(&format!("/_admin/buckets/{}/dedup", seg(&bucket)), &[])
                .await?;
            ctx.out.emit(&v, show_dedup)?;
        }
    }
    Ok(())
}

/// A bucket subresource whose document is S3 XML (`?lifecycle`, `?cors`).
/// The document is passed through as is, in both output modes — it is what
/// `put --file` takes back.
async fn xml_subresource(ctx: &mut Ctx<'_, '_>, sub: &str, cmd: XmlDocCmd) -> Result<()> {
    let query = q(&[(sub, "")]);
    match cmd {
        XmlDocCmd::Get { bucket } => {
            let r = ctx
                .api
                .call("GET", &format!("/{}", seg(&bucket)), &query, Body::Empty)
                .await?;
            let text = r.text();
            ctx.out.print(&text)?;
            if !text.ends_with('\n') {
                ctx.out.line("")?;
            }
        }
        XmlDocCmd::Put { bucket, file } => {
            let bytes = read_input(&file)?;
            ctx.api
                .call(
                    "PUT",
                    &format!("/{}", seg(&bucket)),
                    &query,
                    Body::Raw {
                        bytes,
                        content_type: "application/xml".into(),
                    },
                )
                .await?;
            ctx.out
                .done(&format!("{sub} configuration set on {bucket}"))?;
        }
        XmlDocCmd::Delete { bucket } => {
            ctx.api
                .call("DELETE", &format!("/{}", seg(&bucket)), &query, Body::Empty)
                .await?;
            ctx.out
                .done(&format!("{sub} configuration removed from {bucket}"))?;
        }
    }
    Ok(())
}

fn provisioner(ctx: &Ctx<'_, '_>, user: Option<String>) -> Result<String> {
    user.or_else(|| ctx.provisioner.clone())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| {
            anyhow!("give --user (the provisioner's user_id) or set OBJECTIO_PROVISIONER_USER_ID")
        })
}

async fn mint_scoped_key(
    ctx: &Ctx<'_, '_>,
    user: &str,
    scope: &str,
    read_only: bool,
) -> Result<Value> {
    ctx.api
        .send_json(
            "POST",
            &format!("/_admin/users/{}/access-keys", seg(user)),
            &[],
            json!({ "scope": scope, "operation": if read_only { "R" } else { "RW" } }),
        )
        .await
}

fn show_access(v: &Value) -> String {
    format!(
        "Bucket credential — the secret is shown only this once.\n\n\
         bucket:            {}\naccess_key_id:     {}\nsecret_access_key: {}\nscope:             {}\noperation:         {}\n",
        cell(&v["bucket"]),
        cell(&v["access_key_id"]),
        cell(&v["secret_access_key"]),
        cell(&v["scope"]),
        cell(&v["operation"]),
    )
}

pub async fn provision(cmd: ProvisionCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        ProvisionCmd::Bucket {
            name,
            user,
            prefix,
            read_only,
            pool,
            tenant,
        } => {
            let user = provisioner(ctx, user)?;
            let prefix = prefix.unwrap_or_default();
            if !prefix.is_empty() && !prefix.ends_with('/') {
                bail!("--prefix {prefix:?} must end in /");
            }
            // The key's user must exist, or the bucket would be left with
            // no credential that reaches it.
            ctx.api
                .get(&format!("/_admin/users/{}", seg(&user)), &[])
                .await
                .map_err(|e| anyhow!("provisioner user {user}: {e}"))?;
            create_bucket(ctx, &name, pool, tenant.tenant).await?;
            let scope = format!("s3://{name}/{prefix}");
            let key = mint_scoped_key(ctx, &user, &scope, read_only)
                .await
                .map_err(|e| {
                    // The bucket stays: it may already be taking writes
                    // from an earlier run. Retry with `provision rotate-key`.
                    anyhow!("bucket {name} created but minting its key failed: {e}")
                })?;
            let mut v = key;
            v["bucket"] = json!(name);
            ctx.out.emit(&v, show_access)?;
        }
        ProvisionCmd::RotateKey {
            name,
            user,
            read_only,
        } => {
            let user = provisioner(ctx, user)?;
            let mut v = mint_scoped_key(ctx, &user, &format!("s3://{name}/"), read_only).await?;
            v["bucket"] = json!(name);
            ctx.out.emit(&v, show_access)?;
        }
        ProvisionCmd::Deprovision { name, user } => {
            let user = provisioner(ctx, user)?;
            let keys = ctx
                .api
                .get(&format!("/_admin/users/{}/access-keys", seg(&user)), &[])
                .await?;
            let want = format!("s3://{name}/");
            let mut revoked = Vec::new();
            for k in rows_of(&keys, "access_keys") {
                if k["scope"].as_str().is_some_and(|s| s.starts_with(&want))
                    && let Some(id) = k["access_key_id"].as_str()
                {
                    ctx.api
                        .delete(&format!("/_admin/access-keys/{}", seg(id)), &[])
                        .await
                        .map_err(|e| anyhow!("revoking {id}: {e}"))?;
                    revoked.push(id.to_string());
                }
            }
            ctx.api
                .delete(&format!("/_admin/buckets/{}", seg(&name)), &[])
                .await?;
            let v = json!({ "bucket": name, "revoked_keys": revoked });
            ctx.out.emit(&v, |_| {
                format!(
                    "Revoked {} key(s) and deleted bucket {name}\n",
                    revoked.len()
                )
            })?;
        }
    }
    Ok(())
}
