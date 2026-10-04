//! Storage consumption per bucket, per tenant and for the cluster.
//!
//! Each OSD reports usage only for the objects it is primary for, so the
//! per-OSD reports are disjoint and are summed here. Bucket → tenant /
//! owner / quota come from meta. The result is served at `/_admin/usage`
//! and exported to Prometheus.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

/// One bucket's usage as reported by one OSD.
#[derive(Debug, Clone, Default)]
pub struct OsdBucketUsage {
    pub bucket: String,
    pub objects: u64,
    pub logical_bytes: u64,
    pub stored_bytes: u64,
    pub noncurrent_versions: u64,
    pub noncurrent_bytes: u64,
    pub last_modified: u64,
}

/// What meta knows about a bucket.
#[derive(Debug, Clone, Default)]
pub struct BucketInfo {
    pub name: String,
    pub tenant: String,
    pub owner: String,
    pub created_at: u64,
    pub pool: String,
    pub quota_bytes: u64,
    pub quota_objects: u64,
}

/// What meta knows about a tenant.
#[derive(Debug, Clone, Default)]
pub struct TenantInfo {
    pub name: String,
    pub quota_bytes: u64,
    pub quota_buckets: u64,
    pub quota_objects: u64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct BucketUsageRow {
    pub bucket: String,
    pub tenant: String,
    pub owner: String,
    pub pool: String,
    pub created_at: u64,
    pub objects: u64,
    pub logical_bytes: u64,
    pub stored_bytes: u64,
    pub noncurrent_versions: u64,
    pub noncurrent_bytes: u64,
    pub last_modified: u64,
    pub quota_bytes: u64,
    pub quota_objects: u64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct TenantUsageRow {
    pub tenant: String,
    pub buckets: u64,
    pub objects: u64,
    pub logical_bytes: u64,
    pub stored_bytes: u64,
    pub last_modified: u64,
    pub quota_bytes: u64,
    pub quota_buckets: u64,
    pub quota_objects: u64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct ClusterUsage {
    pub raw_capacity_bytes: u64,
    pub raw_used_bytes: u64,
    pub raw_available_bytes: u64,
    /// Raw capacity scaled by the default protection scheme's efficiency:
    /// roughly how many bytes of user data fit. 0 when the scheme is not
    /// known yet.
    pub usable_capacity_bytes: u64,
    pub logical_bytes: u64,
    pub stored_bytes: u64,
    pub objects: u64,
    pub buckets: u64,
    pub osds_total: u64,
    pub osds_up: u64,
    /// OSDs whose usage is carried over from an earlier poll because they
    /// did not answer this one.
    pub osds_stale: u64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct UsageReport {
    pub updated_at: u64,
    pub cluster: ClusterUsage,
    pub tenants: Vec<TenantUsageRow>,
    pub buckets: Vec<BucketUsageRow>,
}

/// Merge per-OSD reports and join them with meta's bucket and tenant list.
///
/// Buckets meta no longer knows about (usage left behind on an OSD for a
/// deleted bucket) are dropped: there is no tenant to charge them to, and
/// a bucket that does not exist should not appear in a listing.
#[must_use]
pub fn build_report(
    osd_reports: &[Vec<OsdBucketUsage>],
    buckets: &[BucketInfo],
    tenants: &[TenantInfo],
    mut cluster: ClusterUsage,
    updated_at: u64,
) -> UsageReport {
    let mut summed: HashMap<&str, OsdBucketUsage> = HashMap::new();
    for report in osd_reports {
        for u in report {
            let e = summed.entry(u.bucket.as_str()).or_default();
            e.objects += u.objects;
            e.logical_bytes += u.logical_bytes;
            e.stored_bytes += u.stored_bytes;
            e.noncurrent_versions += u.noncurrent_versions;
            e.noncurrent_bytes += u.noncurrent_bytes;
            // Every shard holder sees a delete marker, so this is a max.
            e.last_modified = e.last_modified.max(u.last_modified);
        }
    }

    let mut rows: Vec<BucketUsageRow> = buckets
        .iter()
        .map(|b| {
            let u = summed.get(b.name.as_str()).cloned().unwrap_or_default();
            BucketUsageRow {
                bucket: b.name.clone(),
                tenant: b.tenant.clone(),
                owner: b.owner.clone(),
                pool: b.pool.clone(),
                created_at: b.created_at,
                objects: u.objects,
                logical_bytes: u.logical_bytes,
                stored_bytes: u.stored_bytes,
                noncurrent_versions: u.noncurrent_versions,
                noncurrent_bytes: u.noncurrent_bytes,
                last_modified: u.last_modified,
                quota_bytes: b.quota_bytes,
                quota_objects: b.quota_objects,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.bucket.cmp(&b.bucket));

    // Every configured tenant appears, even with no buckets, so a new
    // tenant shows as zero rather than missing. The system tenant ("")
    // appears only if it owns something.
    let mut by_tenant: BTreeMap<String, TenantUsageRow> = tenants
        .iter()
        .map(|t| {
            (
                t.name.clone(),
                TenantUsageRow {
                    tenant: t.name.clone(),
                    quota_bytes: t.quota_bytes,
                    quota_buckets: t.quota_buckets,
                    quota_objects: t.quota_objects,
                    ..Default::default()
                },
            )
        })
        .collect();
    for r in &rows {
        let t = by_tenant
            .entry(r.tenant.clone())
            .or_insert_with(|| TenantUsageRow {
                tenant: r.tenant.clone(),
                ..Default::default()
            });
        t.buckets += 1;
        t.objects += r.objects;
        t.logical_bytes += r.logical_bytes;
        t.stored_bytes += r.stored_bytes;
        t.last_modified = t.last_modified.max(r.last_modified);
    }

    cluster.buckets = rows.len() as u64;
    cluster.objects = rows.iter().map(|r| r.objects).sum();
    cluster.logical_bytes = rows.iter().map(|r| r.logical_bytes).sum();
    cluster.stored_bytes = rows.iter().map(|r| r.stored_bytes).sum();

    UsageReport {
        updated_at,
        cluster,
        tenants: by_tenant.into_values().collect(),
        buckets: rows,
    }
}

fn esc(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn family(out: &mut String, name: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}").unwrap();
    writeln!(out, "# TYPE {name} gauge").unwrap();
}

impl UsageReport {
    /// Render as Prometheus gauges. `per_bucket` controls the
    /// `objectio_bucket_*` families, which carry one series per bucket.
    pub fn write_prometheus(&self, out: &mut String, per_bucket: bool) {
        let c = &self.cluster;
        for (name, help, v) in [
            (
                "objectio_cluster_usable_capacity_bytes",
                "Raw capacity scaled by the default protection efficiency",
                c.usable_capacity_bytes,
            ),
            (
                "objectio_cluster_logical_bytes",
                "Bytes of current objects as uploaded, all buckets",
                c.logical_bytes,
            ),
            (
                "objectio_cluster_stored_bytes",
                "Bytes on disk for all object versions incl. parity",
                c.stored_bytes,
            ),
            (
                "objectio_cluster_objects",
                "Current objects across all buckets",
                c.objects,
            ),
            ("objectio_cluster_buckets", "Buckets", c.buckets),
            (
                "objectio_usage_osds_stale",
                "OSDs whose usage is carried over from an earlier poll",
                c.osds_stale,
            ),
            (
                "objectio_usage_last_update_timestamp_seconds",
                "When usage was last refreshed",
                self.updated_at,
            ),
        ] {
            family(out, name, help);
            writeln!(out, "{name} {v}").unwrap();
        }

        type TenantField = fn(&TenantUsageRow) -> u64;
        let tenant_families: [(&str, &str, TenantField); 6] = [
            (
                "objectio_tenant_buckets",
                "Buckets owned by the tenant",
                |t| t.buckets,
            ),
            ("objectio_tenant_objects", "Current objects", |t| t.objects),
            (
                "objectio_tenant_logical_bytes",
                "Bytes of current objects as uploaded",
                |t| t.logical_bytes,
            ),
            (
                "objectio_tenant_stored_bytes",
                "Bytes on disk for all versions incl. parity",
                |t| t.stored_bytes,
            ),
            (
                "objectio_tenant_quota_bytes",
                "Storage quota (0 = unlimited)",
                |t| t.quota_bytes,
            ),
            (
                "objectio_tenant_last_modified_timestamp_seconds",
                "Newest write or delete in any of the tenant's buckets",
                |t| t.last_modified,
            ),
        ];
        for (name, help, f) in tenant_families {
            family(out, name, help);
            for t in &self.tenants {
                writeln!(out, "{name}{{tenant=\"{}\"}} {}", esc(&t.tenant), f(t)).unwrap();
            }
        }

        if !per_bucket {
            return;
        }
        type BucketField = fn(&BucketUsageRow) -> u64;
        let bucket_families: [(&str, &str, BucketField); 7] = [
            ("objectio_bucket_objects", "Current objects", |b| b.objects),
            (
                "objectio_bucket_logical_bytes",
                "Bytes of current objects as uploaded",
                |b| b.logical_bytes,
            ),
            (
                "objectio_bucket_stored_bytes",
                "Bytes on disk for all versions incl. parity",
                |b| b.stored_bytes,
            ),
            (
                "objectio_bucket_noncurrent_versions",
                "Noncurrent object versions",
                |b| b.noncurrent_versions,
            ),
            (
                "objectio_bucket_noncurrent_bytes",
                "Bytes of noncurrent versions as uploaded",
                |b| b.noncurrent_bytes,
            ),
            (
                "objectio_bucket_quota_bytes",
                "Storage quota (0 = unlimited)",
                |b| b.quota_bytes,
            ),
            (
                "objectio_bucket_last_modified_timestamp_seconds",
                "Newest write or delete in the bucket",
                |b| b.last_modified,
            ),
        ];
        for (name, help, f) in bucket_families {
            family(out, name, help);
            for b in &self.buckets {
                writeln!(
                    out,
                    "{name}{{bucket=\"{}\",tenant=\"{}\"}} {}",
                    esc(&b.bucket),
                    esc(&b.tenant),
                    f(b)
                )
                .unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(bucket: &str, objects: u64, bytes: u64, modified: u64) -> OsdBucketUsage {
        OsdBucketUsage {
            bucket: bucket.into(),
            objects,
            logical_bytes: bytes,
            stored_bytes: bytes * 3 / 2,
            last_modified: modified,
            ..Default::default()
        }
    }

    fn bucket(name: &str, tenant: &str) -> BucketInfo {
        BucketInfo {
            name: name.into(),
            tenant: tenant.into(),
            ..Default::default()
        }
    }

    fn report() -> UsageReport {
        build_report(
            &[
                vec![u("a", 2, 100, 5), u("gone", 9, 999, 1)],
                vec![u("a", 1, 50, 9), u("b", 4, 400, 3)],
            ],
            &[bucket("a", "acme"), bucket("b", "acme"), bucket("c", "")],
            &[
                TenantInfo {
                    name: "acme".into(),
                    quota_bytes: 1000,
                    ..Default::default()
                },
                TenantInfo {
                    name: "idle".into(),
                    ..Default::default()
                },
            ],
            ClusterUsage::default(),
            42,
        )
    }

    /// OSD reports are disjoint (primary-only), so they add up; last
    /// activity is the newest any OSD saw.
    #[test]
    fn osd_reports_are_summed_per_bucket() {
        let r = report();
        let a = r.buckets.iter().find(|b| b.bucket == "a").unwrap();
        assert_eq!((a.objects, a.logical_bytes, a.last_modified), (3, 150, 9));
    }

    #[test]
    fn deleted_buckets_are_dropped_and_empty_ones_kept() {
        let r = report();
        let names: Vec<_> = r.buckets.iter().map(|b| b.bucket.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"]);
        assert_eq!(r.cluster.objects, 7);
        assert_eq!(r.cluster.logical_bytes, 550);
        assert_eq!(r.cluster.buckets, 3);
    }

    #[test]
    fn tenants_roll_up_and_idle_tenants_still_appear() {
        let r = report();
        let t: HashMap<_, _> = r.tenants.iter().map(|t| (t.tenant.as_str(), t)).collect();
        assert_eq!(t["acme"].buckets, 2);
        assert_eq!(t["acme"].logical_bytes, 550);
        assert_eq!(t["acme"].quota_bytes, 1000);
        assert_eq!(t["idle"].buckets, 0);
        assert_eq!(t[""].buckets, 1, "system tenant owns bucket c");
    }

    #[test]
    fn prometheus_output_has_bucket_and_tenant_series() {
        let mut out = String::new();
        report().write_prometheus(&mut out, true);
        assert!(
            out.contains(r#"objectio_bucket_logical_bytes{bucket="a",tenant="acme"} 150"#),
            "{out}"
        );
        assert!(
            out.contains(r#"objectio_tenant_stored_bytes{tenant="acme"} 825"#),
            "{out}"
        );
        assert!(out.contains("objectio_cluster_objects 7"), "{out}");

        let mut out = String::new();
        report().write_prometheus(&mut out, false);
        assert!(!out.contains("objectio_bucket_"), "{out}");
        assert!(out.contains("objectio_tenant_objects"), "{out}");
    }
}
