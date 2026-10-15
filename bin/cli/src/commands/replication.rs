//! `obioctl replication`: targets, and resyncs of existing objects.

use super::{Ctx, parse_size, q, seg, tenant_query};
use crate::cli::{ReplicationCmd, ReplicationTargetCmd, ResyncCmd};
use crate::output::{key_values as kv, rows_of};
use anyhow::Result;
use serde_json::{Value, json};

pub async fn replication(cmd: ReplicationCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        ReplicationCmd::Target { action } => target(action, ctx).await,
        ReplicationCmd::Resync { action } => resync(action, ctx).await,
    }
}

async fn target(cmd: ReplicationTargetCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        ReplicationTargetCmd::List { tenant } => {
            let v = ctx
                .api
                .get("/_admin/replication/targets", &tenant_query(&tenant))
                .await?;
            ctx.out.list(
                &v,
                &rows_of(&v, "targets"),
                &[
                    ("NAME", "name"),
                    ("ENDPOINT", "endpoint"),
                    ("BUCKET", "bucket"),
                    ("ACCESS KEY", "access_key"),
                    ("BANDWIDTH", "bandwidth"),
                ],
                "No targets.",
            )?;
        }
        ReplicationTargetCmd::Set {
            name,
            remote_endpoint: endpoint,
            remote_bucket: bucket,
            remote_access_key: access_key,
            remote_secret_key: secret_key,
            remote_region: region,
            bandwidth,
            tenant,
        } => {
            let mut doc = json!({
                "name": name,
                "endpoint": endpoint,
                "bucket": bucket,
                "access_key": access_key,
                "secret_key": secret_key,
                "bandwidth": bandwidth.as_deref().map(parse_size).transpose()?.unwrap_or(0),
            });
            if let Some(r) = region {
                doc["region"] = json!(r);
            }
            let v = ctx
                .api
                .send_json(
                    "POST",
                    "/_admin/replication/targets",
                    &tenant_query(&tenant),
                    doc,
                )
                .await?;
            ctx.out.emit(&v, |v| format!("Target stored\n{}", kv(v)))?;
        }
        ReplicationTargetCmd::Delete { name, tenant } => {
            ctx.api
                .delete(
                    &format!("/_admin/replication/targets/{}", seg(&name)),
                    &tenant_query(&tenant),
                )
                .await?;
            ctx.out.done(&format!("Target {name} removed"))?;
        }
    }
    Ok(())
}

async fn resync(cmd: ResyncCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        ResyncCmd::Start {
            bucket,
            target,
            again,
        } => {
            let v = ctx
                .api
                .send_json(
                    "POST",
                    "/_admin/replication/resync",
                    &[],
                    json!({ "bucket": bucket, "target": target, "again": again }),
                )
                .await?;
            ctx.out.emit(&v, |v| {
                format!("Resync {}\n{}", v["state"].as_str().unwrap_or(""), kv(v))
            })?;
        }
        ResyncCmd::Status { bucket } => {
            let v = ctx
                .api
                .get("/_admin/replication/resync", &q(&[("bucket", &bucket)]))
                .await?;
            let rows: Vec<Value> = rows_of(&v, "resyncs");
            ctx.out.list(
                &v,
                &rows,
                &[
                    ("TARGET", "target"),
                    ("STATE", "state"),
                    ("AFTER", "after"),
                    ("SCANNED", "scanned"),
                    ("MARKED", "marked"),
                    ("SENT", "sent"),
                    ("FAILED", "failed"),
                    ("BYTES", "bytes"),
                    ("ERROR", "error"),
                ],
                "No resyncs.",
            )?;
        }
        ResyncCmd::Cancel { bucket, target } => {
            let v = ctx
                .api
                .delete(
                    "/_admin/replication/resync",
                    &q(&[("bucket", &bucket), ("target", &target)]),
                )
                .await?;
            ctx.out.emit(&v, |v| {
                format!("Resync {}\n", v["state"].as_str().unwrap_or(""))
            })?;
        }
    }
    Ok(())
}
