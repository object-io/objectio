//! ObjectIO Authentication and Authorization
//!
//! This crate provides:
//! - User and access key types
//! - SigV4 signing, and the `Authorization` header's parse (the gateway
//!   verifies signatures)
//! - Bucket and identity policy evaluation
//! - STS temporary credentials
//! - OIDC identity (`oidc` feature)

// Core modules (always available)
pub mod error;
pub mod managed;
pub mod policy;
pub mod presign;
pub mod scope;
pub mod signer;
pub mod sigv4;
pub mod sts;
pub mod user;

// Pluggable identity providers
pub mod provider;
pub mod providers;

// Re-export core types
pub use error::AuthError;
pub use policy::{
    BucketPolicy, Effect, PolicyDecision, PolicyEvaluator, PolicyStatement, Principal,
};
pub use scope::{CredentialScope, Operation, is_mutating_method, scope_allows, validate_scope};
pub use user::{
    AccessKey, AuthMode, AuthResult, KeyStatus, SYSTEM_ADMIN_USER_ARN, User, UserStatus,
};

pub use provider::{AuthProviderError, AuthRequest, AuthenticatedIdentity, IdentityProvider};

// Re-export OIDC types (feature-gated)
#[cfg(feature = "oidc")]
pub use providers::{Claims, OidcConfig, OidcProvider, TokenResponse};
