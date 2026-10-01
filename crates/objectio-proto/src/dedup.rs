//! Deduplication policy: a bucket's effective mode and fingerprint domain.
//!
//! They follow from the policy set at each level. Shared by meta, which
//! resolves it for every placement, and the gateway's admin API, which
//! reads and writes it. Design: objectio-docs
//! `architecture/design/dedup.md`.

use crate::metadata::{DedupMode, DedupPolicy, DedupScope};

/// Config key holding the cluster default, as JSON
/// `{"mode": "...", "scope": "..."}`.
pub const CLUSTER_KEY: &str = "dedup/default";

/// What a bucket's policy resolves to, and which level supplied each part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub mode: DedupMode,
    pub scope: DedupScope,
    /// What a chunk's fingerprint is computed over, besides its bytes:
    /// chunks in different domains never match.
    pub domain: String,
    pub mode_from: &'static str,
    pub scope_from: &'static str,
}

/// Resolve the policy for `bucket` in `tenant`: for mode and scope
/// separately, the most specific level that sets it wins. Nothing set
/// anywhere is mode off, scope bucket.
#[must_use]
pub fn resolve(
    bucket_name: &str,
    tenant_name: &str,
    bucket: Option<&DedupPolicy>,
    tenant: Option<&DedupPolicy>,
    cluster: Option<&DedupPolicy>,
) -> Effective {
    let levels = [("bucket", bucket), ("tenant", tenant), ("cluster", cluster)];
    let (mode, mode_from) = levels
        .iter()
        .find_map(|(from, p)| {
            p.map(DedupPolicy::mode)
                .filter(|m| *m != DedupMode::Unset)
                .map(|m| (m, *from))
        })
        .unwrap_or((DedupMode::Off, "default"));
    let (scope, scope_from) = levels
        .iter()
        .find_map(|(from, p)| {
            p.map(DedupPolicy::scope)
                .filter(|s| *s != DedupScope::Unset)
                .map(|s| (s, *from))
        })
        .unwrap_or((DedupScope::Bucket, "default"));
    Effective {
        mode,
        scope,
        domain: domain(scope, tenant_name, bucket_name),
        mode_from,
        scope_from,
    }
}

/// The fingerprint domain for `scope`. Prefixed so a tenant's domain can
/// never equal a bucket's.
#[must_use]
pub fn domain(scope: DedupScope, tenant: &str, bucket: &str) -> String {
    match scope {
        DedupScope::Cluster => String::new(),
        DedupScope::Tenant => format!("t:{tenant}"),
        DedupScope::Bucket | DedupScope::Unset => format!("b:{tenant}/{bucket}"),
    }
}

/// Refuse what cannot be set yet: mode `on` arrives with phase 2.
///
/// # Errors
/// A message for the caller when `policy` asks for mode `on`.
pub fn validate(policy: &DedupPolicy) -> Result<(), String> {
    if policy.mode() == DedupMode::On {
        return Err("dedup mode \"on\" is not available yet; use \"dry-run\" to measure".into());
    }
    Ok(())
}

#[must_use]
pub const fn mode_name(mode: DedupMode) -> &'static str {
    match mode {
        DedupMode::Unset => "inherit",
        DedupMode::Off => "off",
        DedupMode::DryRun => "dry-run",
        DedupMode::On => "on",
    }
}

#[must_use]
pub const fn scope_name(scope: DedupScope) -> &'static str {
    match scope {
        DedupScope::Unset => "inherit",
        DedupScope::Bucket => "bucket",
        DedupScope::Tenant => "tenant",
        DedupScope::Cluster => "cluster",
    }
}

/// # Errors
/// When `s` names no mode.
pub fn parse_mode(s: &str) -> Result<DedupMode, String> {
    match s {
        "" | "inherit" => Ok(DedupMode::Unset),
        "off" => Ok(DedupMode::Off),
        "dry-run" => Ok(DedupMode::DryRun),
        "on" => Ok(DedupMode::On),
        other => Err(format!(
            "unknown dedup mode {other:?}; expected off, dry-run, on or inherit"
        )),
    }
}

/// # Errors
/// When `s` names no scope.
pub fn parse_scope(s: &str) -> Result<DedupScope, String> {
    match s {
        "" | "inherit" => Ok(DedupScope::Unset),
        "bucket" => Ok(DedupScope::Bucket),
        "tenant" => Ok(DedupScope::Tenant),
        "cluster" => Ok(DedupScope::Cluster),
        other => Err(format!(
            "unknown dedup scope {other:?}; expected bucket, tenant, cluster or inherit"
        )),
    }
}

/// A policy from its JSON form, `{"mode": "...", "scope": "..."}`; absent
/// fields inherit.
///
/// # Errors
/// When the JSON is not an object or names an unknown mode or scope.
pub fn from_json(v: &serde_json::Value) -> Result<DedupPolicy, String> {
    let obj = v.as_object().ok_or("dedup policy must be a JSON object")?;
    let field = |name: &str| {
        obj.get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
    };
    let mut p = DedupPolicy::default();
    p.set_mode(parse_mode(field("mode"))?);
    p.set_scope(parse_scope(field("scope"))?);
    Ok(p)
}

#[must_use]
pub fn to_json(p: &DedupPolicy) -> serde_json::Value {
    serde_json::json!({
        "mode": mode_name(p.mode()),
        "scope": scope_name(p.scope()),
    })
}

/// The cluster default, from its config value. Unreadable JSON counts as
/// unset, so a bad value can only switch dedup off.
#[must_use]
pub fn cluster_from_config(value: &[u8]) -> Option<DedupPolicy> {
    serde_json::from_slice::<serde_json::Value>(value)
        .ok()
        .and_then(|v| from_json(&v).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(mode: DedupMode, scope: DedupScope) -> DedupPolicy {
        let mut p = DedupPolicy::default();
        p.set_mode(mode);
        p.set_scope(scope);
        p
    }

    #[test]
    fn nothing_set_is_off_per_bucket() {
        let e = resolve("b", "t", None, None, None);
        assert_eq!(e.mode, DedupMode::Off);
        assert_eq!(e.scope, DedupScope::Bucket);
        assert_eq!(e.domain, "b:t/b");
        assert_eq!((e.mode_from, e.scope_from), ("default", "default"));
    }

    #[test]
    fn the_most_specific_level_wins() {
        let cluster = policy(DedupMode::DryRun, DedupScope::Cluster);
        let tenant = policy(DedupMode::Off, DedupScope::Tenant);
        let bucket = policy(DedupMode::DryRun, DedupScope::Bucket);
        let e = resolve("b", "t", Some(&bucket), Some(&tenant), Some(&cluster));
        assert_eq!((e.mode, e.scope), (DedupMode::DryRun, DedupScope::Bucket));
        assert_eq!((e.mode_from, e.scope_from), ("bucket", "bucket"));
    }

    /// A bucket can set only its mode and take the tenant's scope.
    #[test]
    fn mode_and_scope_inherit_separately() {
        let tenant = policy(DedupMode::Off, DedupScope::Tenant);
        let bucket = policy(DedupMode::DryRun, DedupScope::Unset);
        let e = resolve("b", "t", Some(&bucket), Some(&tenant), None);
        assert_eq!((e.mode, e.scope), (DedupMode::DryRun, DedupScope::Tenant));
        assert_eq!((e.mode_from, e.scope_from), ("bucket", "tenant"));
        assert_eq!(e.domain, "t:t");
    }

    #[test]
    fn the_cluster_default_applies_when_nothing_else_is_set() {
        let cluster = policy(DedupMode::DryRun, DedupScope::Cluster);
        let e = resolve("b", "t", None, None, Some(&cluster));
        assert_eq!((e.mode, e.scope), (DedupMode::DryRun, DedupScope::Cluster));
        assert_eq!(e.domain, "");
    }

    /// Domains never collide across scopes, so chunks of a bucket-scoped
    /// bucket never match a tenant-scoped one's.
    #[test]
    fn domains_are_distinct_across_scopes() {
        let t = domain(DedupScope::Tenant, "acme", "x");
        let b = domain(DedupScope::Bucket, "acme", "x");
        let c = domain(DedupScope::Cluster, "acme", "x");
        assert!(t != b && b != c && t != c);
        assert_ne!(
            domain(DedupScope::Tenant, "a/b", ""),
            domain(DedupScope::Bucket, "a", "b")
        );
    }

    #[test]
    fn json_round_trips_and_absent_fields_inherit() {
        let p = from_json(&serde_json::json!({"mode": "dry-run"})).unwrap();
        assert_eq!(
            (p.mode(), p.scope()),
            (DedupMode::DryRun, DedupScope::Unset)
        );
        let back = from_json(&to_json(&p)).unwrap();
        assert_eq!(back, p);
        assert!(from_json(&serde_json::json!({"mode": "maybe"})).is_err());
        assert!(from_json(&serde_json::json!("dry-run")).is_err());
    }

    #[test]
    fn on_is_refused_until_phase_two() {
        assert!(validate(&policy(DedupMode::On, DedupScope::Bucket)).is_err());
        assert!(validate(&policy(DedupMode::DryRun, DedupScope::Cluster)).is_ok());
    }

    #[test]
    fn a_bad_cluster_value_counts_as_unset() {
        assert_eq!(cluster_from_config(b"not json"), None);
        assert_eq!(
            cluster_from_config(br#"{"mode":"dry-run","scope":"tenant"}"#)
                .map(|p| (p.mode(), p.scope())),
            Some((DedupMode::DryRun, DedupScope::Tenant))
        );
    }
}
