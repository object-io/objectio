//! Credential scoping — the bucket/prefix restriction a credential carries.
//!
//! Originally only STS-vended sessions were scoped. The same grammar and the
//! same enforcement now back *permanent* access keys, so the primitives live
//! here rather than in [`crate::sts`], which re-exports them for callers that
//! still reach for `sts::scope_allows` and friends.
//!
//! A scope is an `s3://bucket/prefix/` URI. It is a pure *narrowing* filter:
//! it can only subtract from what the identity is already permitted to do, so
//! handing someone a scoped key can never widen their access.

use serde::{Deserialize, Serialize};

/// What the holder of a scoped credential may do against the scoped prefix.
/// Mutating methods (PUT/POST/DELETE/PATCH) are rejected when the operation
/// is `Read`.
///
/// `ReadWrite` is the default so that an unset value — a key created before
/// scoping existed, or a proto field left at zero — imposes no restriction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    #[default]
    ReadWrite,
    Read,
}

impl Operation {
    /// Compact form used inside STS session tokens.
    #[must_use]
    pub fn as_token_str(self) -> &'static str {
        match self {
            Self::Read => "R",
            Self::ReadWrite => "RW",
        }
    }

    /// Parse the compact token form.
    #[must_use]
    pub fn from_token_str(s: &str) -> Option<Self> {
        match s {
            "R" => Some(Self::Read),
            "RW" => Some(Self::ReadWrite),
            _ => None,
        }
    }

    /// Parse an operator-supplied value. Accepts the token forms plus the
    /// spelled-out variants the admin API and CLI take.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "r" | "read" | "readonly" | "read-only" => Some(Self::Read),
            "rw" | "readwrite" | "read-write" => Some(Self::ReadWrite),
            _ => None,
        }
    }
}

/// The restriction carried by one credential.
///
/// `prefix` is empty when the whole bucket is in scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialScope {
    /// `s3://bucket/prefix/` URI. Empty means the credential is unscoped and
    /// only [`CredentialScope::operation`] applies.
    pub scope: String,
    /// Whether this credential may mutate. Applies whether or not `scope` is
    /// set, so a key can be read-only across every bucket.
    pub operation: Operation,
}

impl CredentialScope {
    /// A credential with no bucket restriction and no operation restriction.
    #[must_use]
    pub fn unrestricted() -> Self {
        Self {
            scope: String::new(),
            operation: Operation::ReadWrite,
        }
    }

    /// True when this carries no restriction at all, and so can be skipped.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.scope.is_empty() && self.operation == Operation::ReadWrite
    }

    /// Check one request against this scope.
    ///
    /// `key` is the object key without a leading slash. For bucket-level
    /// requests pass the effective prefix (S3 `?prefix=`), so that a LIST
    /// narrower than the scope is allowed and a broader one is refused.
    #[must_use]
    pub fn allows(&self, bucket: &str, key: &str, method: &str) -> bool {
        if self.operation == Operation::Read && is_mutating_method(method) {
            return false;
        }
        if self.scope.is_empty() {
            return true;
        }
        scope_allows(&self.scope, bucket, key)
    }

    /// Why a request was refused, for the error body. Only meaningful after
    /// [`CredentialScope::allows`] returned false.
    #[must_use]
    pub fn denial_reason(&self, bucket: &str, key: &str, method: &str) -> String {
        if self.operation == Operation::Read && is_mutating_method(method) {
            "this access key is READ-only".to_string()
        } else {
            format!(
                "this access key is scoped to {}, not s3://{}/{}",
                self.scope, bucket, key
            )
        }
    }
}

/// Validate an operator-supplied scope URI.
///
/// Rejects anything that is not `s3://bucket[/prefix]` with a non-empty
/// bucket, so a typo cannot silently produce a scope that matches nothing
/// (or, worse, one that is treated as unscoped).
pub fn validate_scope(scope: &str) -> Result<(), String> {
    let Some(rest) = scope.strip_prefix("s3://") else {
        return Err("scope must start with s3://".to_string());
    };
    let bucket = rest.split('/').next().unwrap_or("");
    if bucket.is_empty() {
        return Err("scope must name a bucket, e.g. s3://bucket/prefix/".to_string());
    }
    if bucket.contains(['?', '#', '\\']) {
        return Err(format!(
            "scope bucket '{bucket}' contains invalid characters"
        ));
    }
    Ok(())
}

/// Returns true if the request `bucket`/`key` falls within `scope`.
///
/// `scope` is an `s3://bucket/prefix/` URI; an empty path component after the
/// bucket means the entire bucket is in scope. `key` is the object key
/// without a leading slash (S3-style).
#[must_use]
pub fn scope_allows(scope: &str, bucket: &str, key: &str) -> bool {
    let Some(rest) = scope.strip_prefix("s3://") else {
        return false;
    };
    let (scope_bucket, scope_prefix) = match rest.split_once('/') {
        Some((b, p)) => (b, p),
        None => (rest, ""),
    };
    if scope_bucket != bucket {
        return false;
    }
    // Empty prefix → whole bucket in scope.
    key.starts_with(scope_prefix)
}

/// Returns true if `method` writes to S3 (would require `ReadWrite`).
#[must_use]
pub fn is_mutating_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "PUT" | "POST" | "DELETE" | "PATCH"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_bucket_scope_admits_any_key() {
        assert!(scope_allows("s3://data", "data", "anything/at/all"));
        assert!(scope_allows("s3://data/", "data", "anything"));
        assert!(!scope_allows("s3://data", "other", "anything"));
    }

    #[test]
    fn prefix_scope_admits_only_that_prefix() {
        assert!(scope_allows("s3://data/logs/", "data", "logs/2026/a.txt"));
        assert!(!scope_allows("s3://data/logs/", "data", "other/a.txt"));
    }

    #[test]
    fn malformed_scope_admits_nothing() {
        assert!(!scope_allows("data/logs", "data", "logs/a"));
        assert!(!scope_allows("", "data", "a"));
    }

    #[test]
    fn read_only_rejects_mutating_methods() {
        let ro = CredentialScope {
            scope: "s3://data/".to_string(),
            operation: Operation::Read,
        };
        assert!(ro.allows("data", "k", "GET"));
        assert!(ro.allows("data", "k", "HEAD"));
        assert!(!ro.allows("data", "k", "PUT"));
        assert!(!ro.allows("data", "k", "POST"));
        assert!(!ro.allows("data", "k", "DELETE"));
    }

    #[test]
    fn operation_applies_without_a_bucket_scope() {
        let ro = CredentialScope {
            scope: String::new(),
            operation: Operation::Read,
        };
        assert!(ro.allows("any", "k", "GET"));
        assert!(!ro.allows("any", "k", "PUT"));
        assert!(!ro.is_unrestricted());
    }

    #[test]
    fn unrestricted_is_skippable() {
        assert!(CredentialScope::unrestricted().is_unrestricted());
        assert!(CredentialScope::unrestricted().allows("b", "k", "DELETE"));
    }

    #[test]
    fn scope_confines_a_key_to_one_bucket() {
        let scoped = CredentialScope {
            scope: "s3://reports/".to_string(),
            operation: Operation::ReadWrite,
        };
        assert!(scoped.allows("reports", "q1.csv", "PUT"));
        assert!(!scoped.allows("payroll", "q1.csv", "GET"));
    }

    #[test]
    fn validate_rejects_typos() {
        assert!(validate_scope("s3://bucket/prefix/").is_ok());
        assert!(validate_scope("s3://bucket").is_ok());
        assert!(validate_scope("bucket/prefix").is_err());
        assert!(validate_scope("s3://").is_err());
        assert!(validate_scope("s3:///prefix").is_err());
    }

    #[test]
    fn operation_parses_operator_spellings() {
        assert_eq!(Operation::parse("R"), Some(Operation::Read));
        assert_eq!(Operation::parse("read-only"), Some(Operation::Read));
        assert_eq!(Operation::parse("RW"), Some(Operation::ReadWrite));
        assert_eq!(Operation::parse("readwrite"), Some(Operation::ReadWrite));
        assert_eq!(Operation::parse("nonsense"), None);
        // Round-trips through the STS token form.
        assert_eq!(
            Operation::from_token_str(Operation::Read.as_token_str()),
            Some(Operation::Read)
        );
    }

    #[test]
    fn default_operation_imposes_no_restriction() {
        assert_eq!(Operation::default(), Operation::ReadWrite);
    }
}
