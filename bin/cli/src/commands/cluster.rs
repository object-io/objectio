//! Cluster, nodes, OSDs, pools, KMS, warehouses, stored config, metrics.

use super::{Ctx, escape_path, format_size, key_values, parse_size, q, read_json, seg};
use crate::cli::{
    ClusterCmd, ConfigCmd, KmsCmd, KmsKeysCmd, MetricsCmd, NodeCmd, OsdCmd, PoolCmd, PoolFields,
    RebalanceCmd, UpgradeCmd, WarehouseCmd,
};
use crate::output::{cell, key_values as kv, rows_of, table, ts};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};
use std::fmt::Write as _;

fn sized(v: &Value) -> Value {
    v.as_u64().map_or(Value::Null, |b| json!(format_size(b)))
}

/// The topology tree, indented: region → zone → datacenter → rack → host.
pub fn render_topology(v: &Value) -> String {
    const LEVELS: [(&str, &str); 5] = [
        ("region", "zones"),
        ("zone", "datacenters"),
        ("datacenter", "racks"),
        ("rack", "hosts"),
        ("host", "osds"),
    ];
    fn walk(out: &mut String, nodes: &Value, depth: usize) {
        let Some(items) = nodes.as_array() else {
            return;
        };
        let indent = "  ".repeat(depth + 1);
        if depth == LEVELS.len() {
            for osd in items {
                let _ = writeln!(out, "{indent}osd {}", cell(osd));
            }
            return;
        }
        let (name, children) = LEVELS[depth];
        for item in items {
            let _ = writeln!(out, "{indent}{name} {}", cell(&item[name]));
            walk(out, &item[children], depth + 1);
        }
    }
    let mut out = String::new();
    let d = &v["distinct"];
    let _ = writeln!(
        out,
        "{} OSD(s): {} region(s), {} zone(s), {} datacenter(s), {} rack(s), {} host(s)",
        cell(&v["osd_count"]),
        cell(&d["region"]),
        cell(&d["zone"]),
        cell(&d["datacenter"]),
        cell(&d["rack"]),
        cell(&d["host"]),
    );
    walk(&mut out, &v["tree"], 0);
    out
}

/// The upgrade status: the levels, what blocks finalize, every node.
pub fn render_upgrade(v: &Value) -> String {
    let mut out = format!(
        "active format level: {}\nfinalize would raise it to: {}\n",
        cell(&v["active_level"]),
        cell(&v["finalize_to"])
    );
    let blockers = rows_of(&v["blockers"], "blockers");
    if blockers.is_empty() {
        if v["can_finalize"].as_bool() == Some(true) {
            out.push_str("every node runs the new release: ready to finalize\n");
        } else {
            out.push_str("nothing to finalize\n");
        }
    } else {
        out.push_str("not ready to finalize:\n");
        for b in &blockers {
            let _ = writeln!(out, "  - {}", cell(b));
        }
    }
    let nodes = rows_of(&v["nodes"], "nodes");
    let cols = [
        ("KIND", "kind"),
        ("ID", "id"),
        ("RELEASE", "release"),
        ("LEVEL", "format_level"),
        ("ADDRESS", "address"),
        ("SEEN (S AGO)", "seen_secs_ago"),
    ];
    let _ = write!(out, "\n{}", table(&nodes, &cols));
    out
}

pub async fn upgrade(cmd: UpgradeCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        UpgradeCmd::Status => {
            let v = ctx.api.get("/_admin/upgrade", &[]).await?;
            ctx.out.emit(&v, render_upgrade)?;
        }
        UpgradeCmd::Finalize => {
            let v = ctx
                .api
                .call(
                    "POST",
                    "/_admin/upgrade/finalize",
                    &[],
                    crate::http::Body::Empty,
                )
                .await?
                .json()?;
            ctx.out.emit(&v, |v| {
                format!("active format level: {}", cell(&v["active_level"]))
            })?;
        }
    }
    Ok(())
}

pub async fn cluster(cmd: ClusterCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        ClusterCmd::Info => {
            let v = ctx.api.get("/_admin/cluster-info", &[]).await?;
            ctx.out.emit(&v, |v| {
                let me = &v["self_topology"];
                let osds: Vec<Value> = rows_of(&v["osds"], "osds")
                    .into_iter()
                    .map(|mut o| {
                        o["rack"] = o["failure_domain"]["rack"].clone();
                        o["host"] = o["failure_domain"]["host"].clone();
                        o
                    })
                    .collect();
                format!(
                    "gateway topology: region={} zone={} datacenter={} rack={} host={}{}\n\n{}",
                    cell(&me["region"]),
                    cell(&me["zone"]),
                    cell(&me["datacenter"]),
                    cell(&me["rack"]),
                    cell(&me["host"]),
                    if me["configured"].as_bool() == Some(true) {
                        ""
                    } else {
                        " (not configured)"
                    },
                    table(
                        &osds,
                        &[
                            ("NODE ID", "node_id"),
                            ("ADDRESS", "address"),
                            ("RACK", "rack"),
                            ("HOST", "host"),
                            ("DISTANCE", "distance"),
                        ],
                    )
                )
            })?;
        }
        ClusterCmd::Topology => {
            let v = ctx.api.get("/_admin/topology", &[]).await?;
            ctx.out.emit(&v, render_topology)?;
        }
        ClusterCmd::Usage => {
            let v = ctx.api.get("/_admin/usage", &[]).await?;
            ctx.out.emit(&v, render_usage)?;
        }
        ClusterCmd::DrainStatus => {
            let v = ctx.api.get("/_admin/drain-status", &[]).await?;
            ctx.out.list(
                &v,
                &rows_of(&v, "drains"),
                &[
                    ("NODE ID", "node_id"),
                    ("REMAINING", "shards_remaining"),
                    ("MIGRATED", "shards_migrated"),
                    ("INITIAL", "initial_shards"),
                    ("LAST ERROR", "last_error"),
                ],
                "No drains in progress.",
            )?;
        }
        ClusterCmd::ValidatePlacement { pool } => {
            let v = ctx
                .api
                .get("/_admin/placement/validate", &q(&[("pool", &pool)]))
                .await?;
            ctx.out.emit(&v, kv)?;
        }
        ClusterCmd::Rebalance { action } => {
            let v = match action {
                RebalanceCmd::Status => ctx.api.get("/_admin/rebalance-status", &[]).await?,
                RebalanceCmd::Pause => ctx
                    .api
                    .call(
                        "POST",
                        "/_admin/rebalance/pause",
                        &[],
                        crate::http::Body::Empty,
                    )
                    .await?
                    .json()?,
                RebalanceCmd::Resume => ctx
                    .api
                    .call(
                        "POST",
                        "/_admin/rebalance/resume",
                        &[],
                        crate::http::Body::Empty,
                    )
                    .await?
                    .json()?,
            };
            ctx.out.emit(&v, kv)?;
        }
    }
    Ok(())
}

fn render_usage(v: &Value) -> String {
    let mut out = String::new();
    let c = &v["cluster"];
    if c.is_object() {
        let _ = writeln!(
            out,
            "cluster: {} raw, {} used, {} available, {} usable; {} objects in {} buckets, {} logical / {} stored",
            cell(&sized(&c["raw_capacity_bytes"])),
            cell(&sized(&c["raw_used_bytes"])),
            cell(&sized(&c["raw_available_bytes"])),
            cell(&sized(&c["usable_capacity_bytes"])),
            cell(&c["objects"]),
            cell(&c["buckets"]),
            cell(&sized(&c["logical_bytes"])),
            cell(&sized(&c["stored_bytes"])),
        );
        out.push('\n');
    }
    let tenants: Vec<Value> = rows_of(&v["tenants"], "tenants")
        .into_iter()
        .map(|mut t| {
            t["logical"] = sized(&t["logical_bytes"]);
            t["stored"] = sized(&t["stored_bytes"]);
            t["quota"] = sized(&t["quota_bytes"]);
            t
        })
        .collect();
    if !tenants.is_empty() {
        out.push_str(&table(
            &tenants,
            &[
                ("TENANT", "tenant"),
                ("BUCKETS", "buckets"),
                ("OBJECTS", "objects"),
                ("LOGICAL", "logical"),
                ("STORED", "stored"),
                ("QUOTA", "quota"),
            ],
        ));
        out.push('\n');
    }
    let buckets: Vec<Value> = rows_of(&v["buckets"], "buckets")
        .into_iter()
        .map(|mut b| {
            b["logical"] = sized(&b["logical_bytes"]);
            b["stored"] = sized(&b["stored_bytes"]);
            b
        })
        .collect();
    if !buckets.is_empty() {
        out.push_str(&table(
            &buckets,
            &[
                ("BUCKET", "bucket"),
                ("TENANT", "tenant"),
                ("POOL", "pool"),
                ("OBJECTS", "objects"),
                ("LOGICAL", "logical"),
                ("STORED", "stored"),
            ],
        ));
    }
    out
}

const NODE_COLUMNS: &[(&str, &str)] = &[
    ("NODE ID", "node_id"),
    ("NAME", "node_name"),
    ("ADDRESS", "address"),
    ("ONLINE", "online"),
    ("STATE", "admin_state"),
    ("USED", "used"),
    ("CAPACITY", "capacity"),
    ("SHARDS", "shard_count"),
];

fn with_sizes(rows: Vec<Value>) -> Vec<Value> {
    rows.into_iter()
        .map(|mut n| {
            n["used"] = sized(&n["used_capacity"]);
            n["capacity"] = sized(&n["total_capacity"]);
            n
        })
        .collect()
}

pub async fn node(cmd: NodeCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    let v = ctx.api.get("/_admin/nodes", &[]).await?;
    match cmd {
        NodeCmd::List => {
            ctx.out.list(
                &v,
                &with_sizes(rows_of(&v, "nodes")),
                NODE_COLUMNS,
                "No nodes.",
            )?;
        }
        NodeCmd::Show { node } => {
            let n = rows_of(&v, "nodes")
                .into_iter()
                .find(|n| {
                    n["node_id"].as_str() == Some(node.as_str())
                        || n["node_name"].as_str() == Some(node.as_str())
                })
                .ok_or_else(|| anyhow!("node {node} not found"))?;
            ctx.out.emit(&n, |n| {
                let mut summary = n.clone();
                let disks = summary
                    .as_object_mut()
                    .and_then(|o| o.remove("disks"))
                    .unwrap_or_else(|| json!([]));
                let disks = rows_of(&disks, "disks");
                let disk_table = if disks.is_empty() {
                    String::new()
                } else {
                    let cols: Vec<(&str, &str)> = disks[0]
                        .as_object()
                        .map(|o| o.keys().map(|k| (k.as_str(), k.as_str())).collect())
                        .unwrap_or_default();
                    format!("\ndisks:\n{}", table(&disks, &cols))
                };
                format!("{}{disk_table}", kv(&summary))
            })?;
        }
    }
    Ok(())
}

pub async fn osd(cmd: OsdCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    let OsdCmd::SetState { node_id, state } = cmd;
    let v = ctx
        .api
        .send_json(
            "PUT",
            &format!("/_admin/osds/{}/admin-state", seg(&node_id)),
            &[],
            json!({ "state": state }),
        )
        .await?;
    if v["found"].as_bool() == Some(false) {
        bail!("no OSD has node_id {node_id}");
    }
    ctx.out.emit(&v, |v| {
        if v["changed"].as_bool() == Some(true) {
            format!("OSD {node_id} is now {state}\n")
        } else {
            format!("OSD {node_id} was already {state}\n")
        }
    })?;
    Ok(())
}

/// The fields of a pool body that were given. Updates merge server-side.
fn pool_body(f: PoolFields) -> Result<Map<String, Value>> {
    let mut m = Map::new();
    for (k, v) in [
        ("ec_type", f.ec_type),
        ("ec_k", f.ec_k),
        ("ec_m", f.ec_m),
        ("ec_local_parity", f.ec_local_parity),
        ("ec_global_parity", f.ec_global_parity),
        ("replication_count", f.replication_count),
    ] {
        if let Some(v) = v {
            m.insert(k.into(), json!(v));
        }
    }
    if !f.osd_tags.is_empty() {
        m.insert("osd_tags".into(), json!(f.osd_tags));
    }
    if let Some(v) = f.failure_domain {
        m.insert("failure_domain".into(), json!(v));
    }
    if let Some(v) = f.quota_bytes {
        m.insert("quota_bytes".into(), json!(parse_size(&v)?));
    }
    if let Some(v) = f.description {
        m.insert("description".into(), json!(v));
    }
    if let Some(v) = f.tier {
        m.insert("tier".into(), json!(v));
    }
    Ok(m)
}

const POOL_COLUMNS: &[(&str, &str)] = &[
    ("NAME", "name"),
    ("SCHEME", "scheme"),
    ("FAILURE DOMAIN", "failure_domain"),
    ("PGS", "pg_count"),
    ("ENABLED", "enabled"),
    ("TIER", "tier"),
    ("QUOTA", "quota"),
];

/// "EC 4+2", "LRC 6+2+2", "3x".
pub fn scheme(p: &Value) -> String {
    let n = |k: &str| p[k].as_u64().unwrap_or(0);
    match n("ec_type") {
        1 => format!(
            "LRC {}+{}+{}",
            n("ec_k"),
            n("ec_local_parity"),
            n("ec_global_parity")
        ),
        2 => format!("{}x", n("replication_count")),
        _ => format!("EC {}+{}", n("ec_k"), n("ec_m")),
    }
}

fn pool_row(mut p: Value) -> Value {
    p["scheme"] = json!(scheme(&p));
    p["quota"] = if p["quota_bytes"].as_u64() == Some(0) {
        Value::Null
    } else {
        sized(&p["quota_bytes"])
    };
    p
}

pub async fn pool(cmd: PoolCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        PoolCmd::List => {
            let v = ctx.api.get("/_admin/pools", &[]).await?;
            let rows: Vec<Value> = rows_of(&v, "pools").into_iter().map(pool_row).collect();
            ctx.out.list(&v, &rows, POOL_COLUMNS, "No pools.")?;
        }
        PoolCmd::Show { name } => {
            let v = ctx
                .api
                .get(&format!("/_admin/pools/{}", seg(&name)), &[])
                .await?;
            ctx.out.emit(&v, |v| kv(&pool_row(v.clone())))?;
        }
        PoolCmd::Create {
            name,
            fields,
            pg_count,
            disabled,
        } => {
            let mut body = pool_body(fields)?;
            body.insert("name".into(), json!(name));
            body.insert("enabled".into(), json!(!disabled));
            if let Some(pg) = pg_count {
                body.insert("pg_count".into(), json!(pg));
            }
            let v = ctx
                .api
                .send_json("POST", "/_admin/pools", &[], Value::Object(body))
                .await?;
            ctx.out
                .emit(&v, |v| format!("Created pool {name} ({})\n", scheme(v)))?;
        }
        PoolCmd::Update {
            name,
            fields,
            enabled,
        } => {
            let mut body = pool_body(fields)?;
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
                    &format!("/_admin/pools/{}", seg(&name)),
                    &[],
                    Value::Object(body),
                )
                .await?;
            ctx.out.emit(&v, |v| kv(&pool_row(v.clone())))?;
        }
        PoolCmd::Delete { name } => {
            ctx.api
                .delete(&format!("/_admin/pools/{}", seg(&name)), &[])
                .await?;
            ctx.out.done(&format!("Deleted pool {name}"))?;
        }
        PoolCmd::PlacementGroups {
            name,
            start_at,
            max,
        } => {
            let mut query = Vec::new();
            if let Some(s) = start_at {
                query.push(("start_at".to_string(), s.to_string()));
            }
            if let Some(m) = max {
                query.push(("max".to_string(), m.to_string()));
            }
            let v = ctx
                .api
                .get(
                    &format!("/_admin/pools/{}/placement-groups", seg(&name)),
                    &query,
                )
                .await?;
            ctx.out.emit(&v, |v| {
                let rows = rows_of(v, "pgs");
                let mut s = if rows.is_empty() {
                    "No placement groups.\n".to_string()
                } else {
                    table(
                        &rows,
                        &[
                            ("PG", "pg_id"),
                            ("EPOCH", "epoch"),
                            ("ACTING", "acting"),
                            ("UP", "up"),
                        ],
                    )
                };
                if v["next_pg_id"].as_u64().is_some_and(|n| n > 0) {
                    let _ = writeln!(s, "\nmore: --start-at {}", cell(&v["next_pg_id"]));
                }
                s
            })?;
        }
    }
    Ok(())
}

const KMS_KEY_COLUMNS: &[(&str, &str)] = &[
    ("KEY ID", "key_id"),
    ("STATUS", "status"),
    ("DESCRIPTION", "description"),
    ("CREATED BY", "created_by"),
    ("CREATED", "created"),
];

pub async fn kms(cmd: KmsCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        KmsCmd::Status => {
            let v = ctx.api.get("/_admin/kms/status", &[]).await?;
            ctx.out.emit(&v, kv)?;
        }
        KmsCmd::Keys { action } => match action {
            KmsKeysCmd::List => {
                let v = ctx.api.get("/_admin/kms/keys", &[]).await?;
                let rows: Vec<Value> = rows_of(&v, "keys")
                    .into_iter()
                    .map(|mut k| {
                        k["created"] = ts(&k["created_at"]);
                        k
                    })
                    .collect();
                ctx.out.list(&v, &rows, KMS_KEY_COLUMNS, "No KMS keys.")?;
            }
            KmsKeysCmd::Create {
                key_id,
                description,
            } => {
                let v = ctx
                    .api
                    .send_json(
                        "POST",
                        "/_admin/kms/keys",
                        &[],
                        json!({
                            "key_id": key_id.unwrap_or_default(),
                            "description": description.unwrap_or_default(),
                        }),
                    )
                    .await?;
                ctx.out.emit(&v, kv)?;
            }
            KmsKeysCmd::Show { key_id } => {
                let v = ctx
                    .api
                    .get(&format!("/_admin/kms/keys/{}", seg(&key_id)), &[])
                    .await?;
                ctx.out.emit(&v, kv)?;
            }
        },
    }
    Ok(())
}

pub async fn warehouse(cmd: WarehouseCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        WarehouseCmd::List { tenant } => {
            // Lists the caller's tenant's warehouses; the endpoint takes no
            // tenant, so --tenant only narrows what comes back.
            let mut v = ctx.api.get("/_admin/warehouses", &[]).await?;
            if let (Some(t), Some(w)) = (
                &tenant.tenant,
                v.get_mut("warehouses").and_then(Value::as_array_mut),
            ) {
                w.retain(|x| x["tenant"].as_str() == Some(t.as_str()));
            }
            ctx.out.list(
                &v,
                &rows_of(&v, "warehouses"),
                &[
                    ("NAME", "name"),
                    ("TENANT", "tenant"),
                    ("BUCKET", "bucket"),
                    ("LOCATION", "location"),
                ],
                "No warehouses.",
            )?;
        }
        WarehouseCmd::Create {
            name,
            properties,
            tenant,
        } => {
            let mut body = json!({ "name": name });
            if let Some(t) = tenant.tenant {
                body["tenant"] = json!(t);
            }
            if !properties.is_empty() {
                body["properties"] = Value::Object(key_values(&properties)?);
            }
            let v = ctx
                .api
                .send_json("POST", "/_admin/warehouses", &[], body)
                .await?;
            ctx.out.emit(&v, kv)?;
        }
        WarehouseCmd::Delete { name } => {
            ctx.api
                .delete(&format!("/_admin/warehouses/{}", seg(&name)), &[])
                .await?;
            ctx.out.done(&format!("Deleted warehouse {name}"))?;
        }
    }
    Ok(())
}

fn config_path(key: &str) -> String {
    format!(
        "/_admin/config/{}",
        escape_path(key.trim_start_matches('/'))
    )
}

pub async fn config(cmd: ConfigCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        ConfigCmd::List { prefix } => {
            let query = prefix.map_or_else(Vec::new, |p| q(&[("prefix", &p)]));
            let v = ctx.api.get("/_admin/config", &query).await?;
            ctx.out.list(
                &v,
                &rows_of(&v, "entries"),
                &[
                    ("KEY", "key"),
                    ("VERSION", "version"),
                    ("UPDATED BY", "updated_by"),
                    ("VALUE", "value"),
                ],
                "No configuration.",
            )?;
        }
        ConfigCmd::Get { key } => {
            let v = ctx.api.get(&config_path(&key), &[]).await?;
            if ctx.out.json() {
                ctx.out.raw_json(&v)?;
            } else {
                ctx.out.raw_json(&v["value"])?;
            }
        }
        ConfigCmd::Set { key, value, file } => {
            let doc: Value = match (value, file) {
                (Some(text), _) => serde_json::from_str(&text).context("--value is not JSON")?,
                (None, Some(f)) => read_json(&f)?,
                (None, None) => bail!("give --value or --file"),
            };
            let v = ctx
                .api
                .send_json("PUT", &config_path(&key), &[], doc)
                .await?;
            ctx.out.emit(&v, |v| {
                format!("Stored {key} (version {})\n", cell(&v["version"]))
            })?;
        }
        ConfigCmd::Delete { key } => {
            ctx.api.delete(&config_path(&key), &[]).await?;
            ctx.out.done(&format!("Deleted {key}"))?;
        }
    }
    Ok(())
}

/// Prometheus vector/matrix results as rows: the metric's labels, then the
/// value (or the number of points).
fn render_prom(v: &Value) -> String {
    let data = &v["data"];
    let results = data["result"].as_array().cloned().unwrap_or_default();
    if results.is_empty() {
        return format!("{} result(s) ({})\n", 0, cell(&data["resultType"]));
    }
    let mut out = String::new();
    for r in &results {
        let labels = r["metric"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| format!("{k}={}", cell(v)))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let value = r["value"].as_array().map_or_else(
            || {
                let points = r["values"].as_array().map_or(0, Vec::len);
                let last = r["values"]
                    .as_array()
                    .and_then(|a| a.last())
                    .and_then(|p| p.get(1))
                    .map_or_else(|| "-".to_string(), cell);
                format!("{points} points, last {last}")
            },
            |pair| cell(pair.get(1).unwrap_or(&Value::Null)),
        );
        let _ = writeln!(out, "{{{labels}}}  {value}");
    }
    out
}

pub async fn metrics(cmd: MetricsCmd, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    let v = match cmd {
        MetricsCmd::Query { promql, time } => {
            let mut query = q(&[("query", &promql)]);
            if let Some(t) = time {
                query.push(("time".into(), t));
            }
            ctx.api.get("/_admin/metrics/query", &query).await?
        }
        MetricsCmd::QueryRange {
            promql,
            start,
            end,
            step,
        } => {
            ctx.api
                .get(
                    "/_admin/metrics/query_range",
                    &q(&[
                        ("query", &promql),
                        ("start", &start),
                        ("end", &end),
                        ("step", &step),
                    ]),
                )
                .await?
        }
    };
    ctx.out.emit(&v, render_prom)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemes_read_naturally() {
        assert_eq!(
            scheme(&json!({"ec_type": 0, "ec_k": 4, "ec_m": 2})),
            "EC 4+2"
        );
        assert_eq!(
            scheme(&json!({"ec_type": 1, "ec_k": 6, "ec_local_parity": 2, "ec_global_parity": 2})),
            "LRC 6+2+2"
        );
        assert_eq!(scheme(&json!({"ec_type": 2, "replication_count": 3})), "3x");
    }

    #[test]
    fn the_topology_tree_indents_by_level() {
        let v = json!({
            "osd_count": 1,
            "distinct": {"region": 1, "zone": 1, "datacenter": 1, "rack": 1, "host": 1},
            "tree": [{"region": "r", "zones": [{"zone": "z", "datacenters": [{"datacenter": "d",
                "racks": [{"rack": "k", "hosts": [{"host": "h", "osds": ["abcd"]}]}]}]}]}]
        });
        let s = render_topology(&v);
        assert!(s.contains("  region r\n    zone z\n"), "{s}");
        assert!(s.contains("            osd abcd\n"), "{s}");
    }

    #[test]
    fn prometheus_vectors_render_one_line_per_series() {
        let v = json!({"status": "success", "data": {"resultType": "vector", "result": [
            {"metric": {"job": "gw"}, "value": [1, "42"]}
        ]}});
        assert_eq!(render_prom(&v), "{job=gw}  42\n");
    }

    #[test]
    fn a_config_key_keeps_its_slashes() {
        assert_eq!(
            config_path("identity/openid/t-acme"),
            "/_admin/config/identity/openid/t-acme"
        );
    }
}
