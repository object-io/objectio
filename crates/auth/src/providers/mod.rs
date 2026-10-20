//! Identity provider implementations of the `IdentityProvider` trait:
//! - `oidc`: OIDC/JWT authentication (optional feature)

#[cfg(feature = "oidc")]
pub mod oidc;

#[cfg(feature = "oidc")]
pub use oidc::{Claims, OidcConfig, OidcProvider, TokenResponse};
