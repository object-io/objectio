//! Delta Sharing bearer token access control.
//!
//! Delta Sharing uses bearer tokens (not `SigV4`). On each request we look up the
//! recipient by hashing the presented token (SHA-256) and checking that the
//! requested share is in the recipient's share list.

use crate::catalog::DeltaCatalog;
use crate::error::DeltaError;
use axum::http::HeaderMap;
use objectio_proto::metadata::DeltaShareEntry;
use sha2::{Digest, Sha256};
use tracing::warn;

/// Extract the raw bearer token from the Authorization header.
#[must_use]
pub fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let header = headers.get("Authorization")?.to_str().ok()?;
    header.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

/// Compute SHA-256 hex digest of the raw bearer token.
/// This mirrors what `delta_create_recipient` stores in the Meta service.
#[must_use]
pub fn hash_token(raw_token: &str) -> String {
    hex::encode(Sha256::digest(raw_token.as_bytes()))
}

/// Access context for a Delta Sharing request — the authenticated recipient.
#[derive(Clone, Debug)]
pub struct RecipientContext {
    pub name: String,
    pub shares: Vec<String>,
}

impl RecipientContext {
    /// Check that this recipient has access to `share`.
    #[must_use]
    pub fn has_share(&self, share: &str) -> bool {
        self.shares.iter().any(|s| s == share)
    }
}

/// Authenticate a Delta Sharing request and return the recipient context.
///
/// # Errors
/// Returns `DeltaError::forbidden` if the Authorization header is missing,
/// the bearer token is invalid, or the recipient does not have access to
/// the requested share.
pub async fn authenticate_request(
    headers: &HeaderMap,
    catalog: &DeltaCatalog,
    required_share: Option<&str>,
) -> Result<RecipientContext, DeltaError> {
    let raw_token = extract_bearer(headers)
        .ok_or_else(|| DeltaError::unauthorized("Missing Authorization: Bearer <token> header"))?;

    let recipient = catalog
        .get_recipient_by_token(&raw_token)
        .await?
        .ok_or_else(|| DeltaError::unauthorized("Invalid bearer token"))?;

    let ctx = RecipientContext {
        name: recipient.name,
        shares: recipient.shares,
    };

    if let Some(share) = required_share {
        if !ctx.has_share(share) {
            return Err(DeltaError::forbidden(format!(
                "Recipient '{}' does not have access to share '{share}'",
                ctx.name
            )));
        }
        // A share of a disabled tenant is shared with no one. One that
        // doesn't exist is the handler's to answer.
        match catalog.get_share(share).await {
            Ok(entry) => {
                if !catalog.tenant_open(&entry.tenant).await? {
                    warn!(
                        "refused recipient '{}' on share '{share}': tenant '{}' is disabled or \
                         does not exist",
                        ctx.name, entry.tenant
                    );
                    return Err(DeltaError::forbidden(format!(
                        "share '{share}' belongs to a disabled tenant"
                    )));
                }
            }
            Err(e) if e.status == axum::http::StatusCode::NOT_FOUND => {}
            Err(e) => return Err(e),
        }
    }

    Ok(ctx)
}

/// `shares` without those of a disabled tenant, which are shared with no
/// one.
///
/// # Errors
/// Returns `DeltaError` if a tenant could not be looked up.
pub async fn open_shares(
    catalog: &DeltaCatalog,
    shares: Vec<DeltaShareEntry>,
) -> Result<Vec<DeltaShareEntry>, DeltaError> {
    let mut open: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    let mut out = Vec::with_capacity(shares.len());
    for share in shares {
        let ok = if let Some(ok) = open.get(&share.tenant) {
            *ok
        } else {
            let ok = catalog.tenant_open(&share.tenant).await?;
            open.insert(share.tenant.clone(), ok);
            ok
        };
        if ok {
            out.push(share);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;

    /// A request without a bearer token is 401, as the protocol has it.
    #[tokio::test]
    async fn no_bearer_token_is_unauthenticated() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let catalog = DeltaCatalog::new(MetadataServiceClient::new(channel));
        let Err(err) = authenticate_request(&HeaderMap::new(), &catalog, None).await else {
            panic!("a request without a token was let in");
        };
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
    }

    /// The system's shares are open without asking; a tenant's is open only
    /// once meta says its tenant is (here meta can't be reached).
    #[tokio::test]
    async fn only_a_tenants_shares_wait_on_its_tenant() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let catalog = DeltaCatalog::new(MetadataServiceClient::new(channel));
        let share = |name: &str, tenant: &str| DeltaShareEntry {
            name: name.into(),
            tenant: tenant.into(),
            ..Default::default()
        };
        let system = open_shares(&catalog, vec![share("s1", ""), share("s2", "")]).await;
        let mixed = open_shares(&catalog, vec![share("s1", ""), share("a1", "acme")]).await;
        drop(catalog);
        assert_eq!(system.unwrap().len(), 2);
        assert!(mixed.is_err());
    }
}
