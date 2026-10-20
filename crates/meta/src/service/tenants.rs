//! Tenants.

use super::*;

/// Where OIDC providers are kept in config: `identity/openid/<name>`. A
/// tenant's `oidc_provider` names one.
pub(super) const OIDC_PROVIDER_PREFIX: &str = "identity/openid/";

impl MetaService {
    /// The tenants whose `oidc_provider` is `provider`, by name.
    pub(super) fn tenants_using_oidc_provider(&self, provider: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .tenants
            .read()
            .values()
            .filter(|t| t.oidc_provider == provider)
            .map(|t| t.name.clone())
            .collect();
        names.sort();
        names
    }

    /// A tenant may name only an OIDC provider that exists: one it named
    /// that didn't would sign nobody in, and fail only at the first login.
    #[allow(clippy::result_large_err)] // the Status the RPC returns, as is
    fn check_oidc_provider(&self, tenant: &TenantConfig) -> Result<(), Status> {
        let provider = &tenant.oidc_provider;
        if provider.is_empty()
            || self
                .config
                .read()
                .contains_key(&format!("{OIDC_PROVIDER_PREFIX}{provider}"))
        {
            return Ok(());
        }
        Err(Status::invalid_argument(format!(
            "tenant '{}': OIDC provider '{provider}' does not exist; create it first \
             (PUT /_admin/config/{OIDC_PROVIDER_PREFIX}{provider}), or leave oidc_provider empty",
            tenant.name
        )))
    }

    /// Mirror a committed tenant write, so every replica — not only the
    /// leader that served it — sees a tenant's settings (its dedup policy
    /// among them) change.
    pub(super) fn apply_tenant_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut tenants = self.tenants.write();
        match new_value {
            Some(bytes) => match TenantConfig::decode(bytes) {
                Ok(t) => {
                    tenants.insert(key.to_string(), t);
                }
                Err(e) => warn!("apply: decode TenantConfig('{key}') failed: {e}"),
            },
            None => {
                tenants.remove(key);
            }
        }
    }

    pub(crate) async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        let tenant = request
            .into_inner()
            .tenant
            .ok_or_else(|| Status::invalid_argument("missing tenant"))?;
        if tenant.name.is_empty() {
            return Err(Status::invalid_argument("tenant name is required"));
        }
        if self.tenants.read().contains_key(&tenant.name) {
            return Err(Status::already_exists(format!(
                "tenant '{}' already exists",
                tenant.name
            )));
        }
        self.check_oidc_provider(&tenant)?;
        let mut tenant = tenant;
        tenant.created_at = Self::current_timestamp();
        tenant.updated_at = tenant.created_at;
        let bytes = tenant.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Tenants,
                    key: tenant.name.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "create-tenant".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("tenant already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_tenant: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_tenant(&tenant.name, &tenant.encode_to_vec());
        }

        self.tenants
            .write()
            .insert(tenant.name.clone(), tenant.clone());
        info!("Created tenant: {}", tenant.name);
        Ok(Response::new(CreateTenantResponse {
            tenant: Some(tenant),
        }))
    }

    pub(crate) async fn get_tenant(
        &self,
        request: Request<GetTenantRequest>,
    ) -> Result<Response<GetTenantResponse>, Status> {
        let name = request.into_inner().name;
        let tenants = self.tenants.read();
        match tenants.get(&name) {
            Some(t) => Ok(Response::new(GetTenantResponse {
                tenant: Some(t.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetTenantResponse {
                tenant: None,
                found: false,
            })),
        }
    }

    pub(crate) async fn list_tenants(
        &self,
        _request: Request<ListTenantsRequest>,
    ) -> Result<Response<ListTenantsResponse>, Status> {
        let tenants = self.tenants.read();
        Ok(Response::new(ListTenantsResponse {
            tenants: tenants.values().cloned().collect(),
        }))
    }

    pub(crate) async fn update_tenant(
        &self,
        request: Request<UpdateTenantRequest>,
    ) -> Result<Response<UpdateTenantResponse>, Status> {
        let mut tenant = request
            .into_inner()
            .tenant
            .ok_or_else(|| Status::invalid_argument("missing tenant"))?;
        let (expected_bytes, provider_changed) = {
            let tenants = self.tenants.read();
            let current = tenants
                .get(&tenant.name)
                .ok_or_else(|| Status::not_found(format!("tenant '{}' not found", tenant.name)))?;
            (
                current.encode_to_vec(),
                current.oidc_provider != tenant.oidc_provider,
            )
        };
        if provider_changed {
            self.check_oidc_provider(&tenant)?;
        }
        tenant.updated_at = Self::current_timestamp();
        let new_bytes = tenant.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Tenants,
                    key: tenant.name.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "update-tenant".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("tenant changed since read; retry update"));
                    }
                    other => {
                        error!("unexpected raft response for update_tenant: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_tenant(&tenant.name, &tenant.encode_to_vec());
        }

        self.tenants
            .write()
            .insert(tenant.name.clone(), tenant.clone());
        info!("Updated tenant: {}", tenant.name);
        Ok(Response::new(UpdateTenantResponse {
            tenant: Some(tenant),
        }))
    }

    pub(crate) async fn delete_tenant(
        &self,
        request: Request<DeleteTenantRequest>,
    ) -> Result<Response<DeleteTenantResponse>, Status> {
        let name = request.into_inner().name;
        let has_buckets = self.buckets.read().values().any(|b| b.tenant == name);
        if has_buckets {
            return Err(Status::failed_precondition(format!(
                "tenant '{}' still has buckets — delete them first",
                name
            )));
        }
        let expected_bytes = self.tenants.read().get(&name).map(|t| t.encode_to_vec());
        if expected_bytes.is_none() {
            return Ok(Response::new(DeleteTenantResponse { success: false }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Tenants,
                    key: name.clone(),
                    expected: expected_bytes,
                    new_value: None,
                }],
                requested_by: "delete-tenant".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("tenant changed since read; retry delete"));
                    }
                    other => {
                        error!("unexpected raft response for delete_tenant: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_tenant(&name);
        }

        self.tenants.write().remove(&name);
        info!("Deleted tenant: {}", name);
        Ok(Response::new(DeleteTenantResponse { success: true }))
    }
}
