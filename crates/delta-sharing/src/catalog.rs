//! Delta Sharing catalog — thin gRPC wrapper around the Meta service.

use crate::error::DeltaError;
use objectio_proto::metadata::{
    DeltaGetRecipientByTokenRequest, DeltaGetShareRequest, DeltaListSharesRequest,
    DeltaListTablesRequest, DeltaRecipientEntry, DeltaShareEntry, DeltaShareTableEntry,
    metadata_service_client::MetadataServiceClient,
};
use tonic::transport::Channel;

#[derive(Clone)]
pub struct DeltaCatalog {
    client: MetadataServiceClient<Channel>,
}

impl DeltaCatalog {
    #[must_use]
    pub const fn new(client: MetadataServiceClient<Channel>) -> Self {
        Self { client }
    }

    /// # Errors
    /// Returns `DeltaError` if the gRPC call fails or the share is not found.
    pub async fn get_share(&self, name: &str) -> Result<DeltaShareEntry, DeltaError> {
        let resp = self
            .client
            .clone()
            .delta_get_share(DeltaGetShareRequest {
                name: name.to_string(),
            })
            .await?;
        resp.into_inner()
            .share
            .ok_or_else(|| DeltaError::not_found(format!("share not found: {name}")))
    }

    /// # Errors
    /// Returns `DeltaError` if the gRPC call fails.
    pub async fn list_shares_filtered(
        &self,
        tenant: &str,
    ) -> Result<Vec<DeltaShareEntry>, DeltaError> {
        let resp = self
            .client
            .clone()
            .delta_list_shares(DeltaListSharesRequest {
                max_results: 0,
                page_token: String::new(),
                tenant: tenant.to_string(),
            })
            .await?;
        Ok(resp.into_inner().shares)
    }

    /// # Errors
    /// Returns `DeltaError` if the gRPC call fails.
    pub async fn list_tables(
        &self,
        share: &str,
        schema: &str,
    ) -> Result<Vec<DeltaShareTableEntry>, DeltaError> {
        let resp = self
            .client
            .clone()
            .delta_list_tables(DeltaListTablesRequest {
                share: share.to_string(),
                schema: schema.to_string(),
                max_results: 0,
                page_token: String::new(),
            })
            .await?;
        Ok(resp.into_inner().tables)
    }

    /// List all tables across all schemas in a share.
    ///
    /// # Errors
    /// Returns `DeltaError` if the gRPC call fails.
    pub async fn list_all_tables_in_share(
        &self,
        share: &str,
    ) -> Result<Vec<DeltaShareTableEntry>, DeltaError> {
        self.list_tables(share, "").await
    }

    /// # Errors
    /// Returns `DeltaError` if the gRPC call fails.
    pub async fn get_recipient_by_token(
        &self,
        token: &str,
    ) -> Result<Option<DeltaRecipientEntry>, DeltaError> {
        let resp = self
            .client
            .clone()
            .delta_get_recipient_by_token(DeltaGetRecipientByTokenRequest {
                raw_token: token.to_string(),
            })
            .await?;
        let inner = resp.into_inner();
        if inner.found {
            Ok(inner.recipient)
        } else {
            Ok(None)
        }
    }
}
