//! Tenants.

use super::*;

impl MetaService {
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
        let expected_bytes = {
            let tenants = self.tenants.read();
            tenants
                .get(&tenant.name)
                .ok_or_else(|| Status::not_found(format!("tenant '{}' not found", tenant.name)))?
                .encode_to_vec()
        };
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
