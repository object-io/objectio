//! Byte and object quotas, per bucket and per tenant (A8b; objectio-docs
//! `s3/quotas.md`).
//!
//! A write that adds data is admitted here before any of it is stored:
//! refused when its bucket's or tenant's usage, from the last usage report,
//! plus what this gateway admitted for them since, plus the write, would
//! pass a quota. Usage counts every version (current and noncurrent).
//! Exact in one gateway up to the writes in flight; across gateways, also
//! up to what the others admit within one report interval.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::Instant;

use axum::response::Response;
use http::StatusCode;

use crate::s3::S3Error;
use crate::s3_metrics::usage::UsageReport;

/// Usage and limits of one bucket or tenant; 0 = unlimited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Account {
    bytes: u64,
    objects: u64,
    quota_bytes: u64,
    quota_objects: u64,
}

impl Account {
    const fn limited(&self) -> bool {
        self.quota_bytes > 0 || self.quota_objects > 0
    }
}

/// The last report, reduced to what admission needs.
#[derive(Default)]
struct Limits {
    /// Every bucket: its tenant, and its account when it has a quota.
    buckets: HashMap<String, (String, Option<Account>)>,
    /// Tenants with a quota.
    tenants: HashMap<String, Account>,
}

/// One admitted write, until a report includes it.
struct Admitted {
    at: Instant,
    bucket: String,
    tenant: String,
    bytes: u64,
    objects: u64,
}

static LIMITS: LazyLock<RwLock<Limits>> = LazyLock::new(|| RwLock::new(Limits::default()));
static ADMITTED: LazyLock<Mutex<Vec<Admitted>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Whether any bucket or tenant has a quota: the usage report is then
/// refreshed more often, to keep enforcement close.
#[must_use]
pub fn any_quota() -> bool {
    let l = LIMITS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    !l.tenants.is_empty() || l.buckets.values().any(|(_, a)| a.is_some())
}

/// Take a new usage report, whose usage was gathered from `gathered_at`.
pub fn on_report(report: &UsageReport, gathered_at: Instant) {
    let mut buckets = HashMap::new();
    let mut tenant_use: HashMap<&str, (u64, u64)> = HashMap::new();
    for b in &report.buckets {
        let bytes = b.logical_bytes + b.noncurrent_bytes;
        let objects = b.objects + b.noncurrent_versions;
        let t = tenant_use.entry(b.tenant.as_str()).or_default();
        t.0 += bytes;
        t.1 += objects;
        let account = Account {
            bytes,
            objects,
            quota_bytes: b.quota_bytes,
            quota_objects: b.quota_objects,
        };
        buckets.insert(
            b.bucket.clone(),
            (b.tenant.clone(), account.limited().then_some(account)),
        );
    }
    let tenants = report
        .tenants
        .iter()
        .map(|t| {
            let (bytes, objects) = tenant_use
                .get(t.tenant.as_str())
                .copied()
                .unwrap_or_default();
            (
                t.tenant.clone(),
                Account {
                    bytes,
                    objects,
                    quota_bytes: t.quota_bytes,
                    quota_objects: t.quota_objects,
                },
            )
        })
        .filter(|(_, a)| a.limited())
        .collect();
    *LIMITS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Limits { buckets, tenants };
    ADMITTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|a| a.at >= gathered_at);
}

/// Which quota a write would pass.
#[derive(Debug, PartialEq, Eq)]
pub enum Exceeded {
    BucketBytes,
    BucketObjects,
    TenantBytes,
    TenantObjects,
}

/// Admit a write of `bytes` and `objects` into `bucket`, or say which
/// quota it would pass. Admitted, it counts against the quotas until a
/// report includes it (or, if it fails, until the next report).
///
/// # Errors
/// The quota the write would pass.
pub fn admit(bucket: &str, bytes: u64, objects: u64) -> Result<(), Exceeded> {
    let limits = LIMITS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some((tenant, bucket_account)) = limits.buckets.get(bucket) else {
        return Ok(()); // newer than the report: no quota known for it yet
    };
    let tenant_account = limits.tenants.get(tenant);
    if bucket_account.is_none() && tenant_account.is_none() {
        return Ok(());
    }
    let mut admitted = ADMITTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let since = |pick: &dyn Fn(&Admitted) -> bool| {
        admitted
            .iter()
            .filter(|a| pick(a))
            .fold((0u64, 0u64), |(b, o), a| (b + a.bytes, o + a.objects))
    };
    let over = |account: &Account, (b, o): (u64, u64)| {
        let bytes_over = account.quota_bytes > 0 && account.bytes + b + bytes > account.quota_bytes;
        let objects_over = account.quota_objects > 0
            && objects > 0
            && account.objects + o + objects > account.quota_objects;
        (bytes_over, objects_over)
    };
    if let Some(a) = bucket_account {
        match over(a, since(&|x| x.bucket == bucket)) {
            (true, _) => return Err(Exceeded::BucketBytes),
            (_, true) => return Err(Exceeded::BucketObjects),
            _ => {}
        }
    }
    if let Some(a) = tenant_account {
        match over(a, since(&|x| &x.tenant == tenant)) {
            (true, _) => return Err(Exceeded::TenantBytes),
            (_, true) => return Err(Exceeded::TenantObjects),
            _ => {}
        }
    }
    admitted.push(Admitted {
        at: Instant::now(),
        bucket: bucket.to_string(),
        tenant: tenant.clone(),
        bytes,
        objects,
    });
    Ok(())
}

/// The S3 answer to a refused write: 403 `QuotaExceeded`, as Ceph RGW
/// answers.
#[must_use]
pub fn refusal(bucket: &str, e: &Exceeded) -> Response {
    let what = match e {
        Exceeded::BucketBytes => format!("bucket {bucket}'s storage quota"),
        Exceeded::BucketObjects => format!("bucket {bucket}'s object quota"),
        Exceeded::TenantBytes => "the tenant's storage quota".to_string(),
        Exceeded::TenantObjects => "the tenant's object quota".to_string(),
    };
    crate::gateway_metrics::record_quota_refusal(match e {
        Exceeded::BucketBytes | Exceeded::BucketObjects => "bucket",
        Exceeded::TenantBytes | Exceeded::TenantObjects => "tenant",
    });
    S3Error::xml_response(
        "QuotaExceeded",
        &format!("This write would exceed {what}"),
        StatusCode::FORBIDDEN,
    )
}

/// Admit the write, or the 403 `QuotaExceeded` to answer it with.
#[must_use]
pub fn check(bucket: &str, bytes: u64, objects: u64) -> Option<Response> {
    admit(bucket, bytes, objects)
        .err()
        .map(|e| refusal(bucket, &e))
}

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    *LIMITS.write().unwrap() = Limits::default();
    ADMITTED.lock().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3_metrics::usage::{BucketUsageRow, TenantUsageRow};

    fn report(bucket_used: u64, bucket_quota: u64, tenant_quota: u64) -> UsageReport {
        UsageReport {
            buckets: vec![
                BucketUsageRow {
                    bucket: "b".into(),
                    tenant: "t".into(),
                    objects: 2,
                    logical_bytes: bucket_used,
                    quota_bytes: bucket_quota,
                    quota_objects: 0,
                    ..Default::default()
                },
                BucketUsageRow {
                    bucket: "other".into(),
                    tenant: "t".into(),
                    logical_bytes: 100,
                    noncurrent_bytes: 50,
                    ..Default::default()
                },
            ],
            tenants: vec![TenantUsageRow {
                tenant: "t".into(),
                quota_bytes: tenant_quota,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// One test, in sequence: admission state is process-wide.
    #[test]
    fn quotas_count_the_report_and_what_was_admitted_since() {
        reset_for_tests();
        // No quota anywhere: everything goes, nothing is tracked.
        on_report(&report(0, 0, 0), Instant::now());
        assert!(!any_quota());
        assert_eq!(admit("b", 1 << 40, 1), Ok(()));

        // Bucket quota 1000, 900 used: 100 more fit, then nothing.
        on_report(&report(900, 1000, 0), Instant::now());
        assert!(any_quota());
        assert_eq!(admit("b", 60, 1), Ok(()));
        assert_eq!(admit("b", 40, 1), Ok(()));
        assert_eq!(admit("b", 1, 1), Err(Exceeded::BucketBytes));
        // Another bucket, no quota of its own and the tenant has none.
        assert_eq!(admit("other", 5000, 1), Ok(()));

        // A newer report includes what was admitted: counted once.
        on_report(&report(1000, 1000, 0), Instant::now());
        assert_eq!(admit("b", 1, 1), Err(Exceeded::BucketBytes));
        // Deletes show in the next report and make room.
        on_report(&report(500, 1000, 0), Instant::now());
        assert_eq!(admit("b", 500, 1), Ok(()));

        // Tenant quota: every bucket's versions count (b 500 + other 150).
        on_report(&report(500, 0, 700), Instant::now());
        assert_eq!(admit("other", 50, 1), Ok(()));
        assert_eq!(admit("b", 1, 0), Err(Exceeded::TenantBytes));

        // A bucket newer than the report has no quota known yet.
        assert_eq!(admit("new", 1 << 40, 1), Ok(()));
    }
}
