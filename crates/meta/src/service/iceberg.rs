//! The Iceberg REST catalog: warehouses, namespaces, tables, their policies.

use super::*;

impl MetaService {
    pub(super) fn apply_iceberg_table_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut tables = self.iceberg_tables.write();
        match new_value {
            Some(bytes) => match IcebergTableEntry::decode(bytes) {
                Ok(e) => {
                    tables.insert(key.to_string(), e);
                }
                Err(e) => warn!("apply: decode IcebergTableEntry('{key}') failed: {e}"),
            },
            None => {
                tables.remove(key);
            }
        }
    }

    pub(super) fn apply_iceberg_namespace_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut ns = self.iceberg_namespaces.write();
        match new_value {
            Some(bytes) => match IcebergCreateNamespaceResponse::decode(bytes) {
                Ok(r) => {
                    ns.insert(key.to_string(), r.properties);
                }
                Err(e) => warn!("apply: decode IcebergNamespace('{key}') failed: {e}"),
            },
            None => {
                ns.remove(key);
            }
        }
    }

    pub(super) fn apply_iceberg_warehouse_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut wh = self.iceberg_warehouses.write();
        match new_value {
            Some(bytes) => match IcebergWarehouse::decode(bytes) {
                Ok(w) => {
                    wh.insert(key.to_string(), w);
                }
                Err(e) => warn!("apply: decode IcebergWarehouse('{key}') failed: {e}"),
            },
            None => {
                wh.remove(key);
            }
        }
    }

    /// Encode namespace levels into a store key, scoped by warehouse.
    /// Format: "warehouse\x01ns1\x00ns2" or "ns1\x00ns2" (if warehouse is empty)
    pub(super) fn iceberg_ns_key_wh(warehouse: &str, levels: &[String]) -> String {
        let ns = levels.join("\x00");
        if warehouse.is_empty() {
            ns
        } else {
            format!("{warehouse}\x01{ns}")
        }
    }

    /// Encode namespace + table name into a store key, scoped by warehouse.
    pub(super) fn iceberg_table_key_wh(
        warehouse: &str,
        ns_levels: &[String],
        table_name: &str,
    ) -> String {
        let ns = Self::iceberg_ns_key_wh(warehouse, ns_levels);
        format!("{ns}\x00{table_name}")
    }

    /// Warehouse prefix for scanning all namespaces in a warehouse.
    pub(super) fn iceberg_warehouse_prefix(warehouse: &str) -> String {
        if warehouse.is_empty() {
            String::new()
        } else {
            format!("{warehouse}\x01")
        }
    }

    /// Legacy helpers (no warehouse scope) — kept for backward compat
    pub(super) fn iceberg_ns_key(levels: &[String]) -> String {
        levels.join("\x00")
    }

    pub(super) fn iceberg_table_key(ns_levels: &[String], table_name: &str) -> String {
        let ns = Self::iceberg_ns_key(ns_levels);
        format!("{ns}\x00{table_name}")
    }

    pub(crate) async fn iceberg_create_namespace(
        &self,
        request: Request<IcebergCreateNamespaceRequest>,
    ) -> Result<Response<IcebergCreateNamespaceResponse>, Status> {
        let req = request.into_inner();

        if req.namespace_levels.is_empty() {
            return Err(Status::invalid_argument("namespace levels cannot be empty"));
        }

        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        if self.iceberg_namespaces.read().contains_key(&ns_key) {
            return Err(Status::already_exists("namespace already exists"));
        }

        // If multi-level, verify parent exists
        if req.namespace_levels.len() > 1 {
            let parent_key = Self::iceberg_ns_key_wh(
                &req.warehouse,
                &req.namespace_levels[..req.namespace_levels.len() - 1],
            );
            if !self.iceberg_namespaces.read().contains_key(&parent_key) {
                return Err(Status::not_found("parent namespace does not exist"));
            }
        }

        let properties = req.properties.clone();
        let resp = IcebergCreateNamespaceResponse {
            namespace_levels: req.namespace_levels.clone(),
            properties: properties.clone(),
        };
        let new_bytes = resp.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergNamespaces,
                    key: ns_key.clone(),
                    expected: None,
                    new_value: Some(new_bytes),
                }],
                requested_by: "iceberg-create-namespace".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("namespace already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_namespace: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_iceberg_namespace(&ns_key, &resp.encode_to_vec());
        }

        self.iceberg_namespaces
            .write()
            .insert(ns_key.clone(), properties.clone());

        info!("Created iceberg namespace: {:?}", req.namespace_levels);

        Ok(Response::new(IcebergCreateNamespaceResponse {
            namespace_levels: req.namespace_levels,
            properties,
        }))
    }

    pub(crate) async fn iceberg_load_namespace(
        &self,
        request: Request<IcebergLoadNamespaceRequest>,
    ) -> Result<Response<IcebergLoadNamespaceResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        let properties = self
            .iceberg_namespaces
            .read()
            .get(&ns_key)
            .cloned()
            .ok_or_else(|| Status::not_found("namespace not found"))?;

        Ok(Response::new(IcebergLoadNamespaceResponse {
            namespace_levels: req.namespace_levels,
            properties,
        }))
    }

    pub(crate) async fn iceberg_drop_namespace(
        &self,
        request: Request<IcebergDropNamespaceRequest>,
    ) -> Result<Response<IcebergDropNamespaceResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        // Check namespace exists
        if !self.iceberg_namespaces.read().contains_key(&ns_key) {
            return Err(Status::not_found("namespace not found"));
        }

        // Check for tables in namespace
        let table_prefix = format!("{ns_key}\x00");
        let has_tables = self
            .iceberg_tables
            .read()
            .keys()
            .any(|k| k.starts_with(&table_prefix));
        if has_tables {
            return Err(Status::failed_precondition(
                "namespace is not empty (contains tables)",
            ));
        }

        // Check for child namespaces
        let child_prefix = format!("{ns_key}\x00");
        let has_children = self
            .iceberg_namespaces
            .read()
            .keys()
            .any(|k| k.starts_with(&child_prefix));
        if has_children {
            return Err(Status::failed_precondition(
                "namespace is not empty (contains child namespaces)",
            ));
        }

        // Reconstruct the expected stored bytes from the in-memory
        // properties (prost is deterministic on the same struct shape).
        let expected_bytes = {
            let ns_map = self.iceberg_namespaces.read();
            let properties = ns_map
                .get(&ns_key)
                .cloned()
                .ok_or_else(|| Status::not_found("namespace not found"))?;
            let stored = IcebergCreateNamespaceResponse {
                namespace_levels: req.namespace_levels.clone(),
                properties,
            };
            stored.encode_to_vec()
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergNamespaces,
                    key: ns_key.clone(),
                    expected: Some(expected_bytes),
                    new_value: None,
                }],
                requested_by: "iceberg-drop-namespace".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("namespace changed since read; retry drop"));
                    }
                    other => {
                        error!("unexpected raft response for drop_namespace: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_iceberg_namespace(&ns_key);
        }

        self.iceberg_namespaces.write().remove(&ns_key);

        info!("Dropped iceberg namespace: {:?}", req.namespace_levels);

        Ok(Response::new(IcebergDropNamespaceResponse {
            success: true,
        }))
    }

    pub(crate) async fn iceberg_list_namespaces(
        &self,
        request: Request<IcebergListNamespacesRequest>,
    ) -> Result<Response<IcebergListNamespacesResponse>, Status> {
        let req = request.into_inner();

        let wh_prefix = Self::iceberg_warehouse_prefix(&req.warehouse);

        let parent_key = if req.parent_levels.is_empty() {
            String::new()
        } else {
            Self::iceberg_ns_key_wh(&req.warehouse, &req.parent_levels)
        };

        // If parent specified, verify it exists
        if !parent_key.is_empty() && !self.iceberg_namespaces.read().contains_key(&parent_key) {
            return Err(Status::not_found("parent namespace not found"));
        }

        let prefix = if parent_key.is_empty() {
            wh_prefix.clone()
        } else {
            format!("{parent_key}\x00")
        };

        let page_size = if req.page_size == 0 {
            100
        } else {
            req.page_size.min(1000)
        } as usize;

        let mut keys: Vec<String> = self
            .iceberg_namespaces
            .read()
            .keys()
            .filter(|k| {
                if prefix.is_empty() {
                    // No warehouse, no parent: top-level namespaces without warehouse prefix
                    !k.contains('\x00') && !k.contains('\x01')
                } else if parent_key.is_empty() && !wh_prefix.is_empty() {
                    // Warehouse set but no parent: top-level namespaces in this warehouse
                    k.starts_with(&prefix) && !k[prefix.len()..].contains('\x00')
                } else {
                    k.starts_with(&prefix) && !k[prefix.len()..].contains('\x00')
                }
            })
            .cloned()
            .collect();
        keys.sort();

        // Skip past page_token
        if !req.page_token.is_empty() {
            keys.retain(|k| k.as_str() > req.page_token.as_str());
        }

        let has_more = keys.len() > page_size;
        let keys: Vec<String> = keys.into_iter().take(page_size).collect();

        let next_page_token = if has_more {
            keys.last().cloned().unwrap_or_default()
        } else {
            String::new()
        };

        let namespaces: Vec<IcebergNamespace> = keys
            .iter()
            .map(|k| {
                // Strip warehouse prefix (warehouse\x01) if present
                let ns_part = if let Some(pos) = k.find('\x01') {
                    &k[pos + 1..]
                } else {
                    k.as_str()
                };
                let levels: Vec<String> = ns_part.split('\x00').map(String::from).collect();
                IcebergNamespace { levels }
            })
            .collect();

        Ok(Response::new(IcebergListNamespacesResponse {
            namespaces,
            next_page_token,
        }))
    }

    pub(crate) async fn iceberg_update_namespace_properties(
        &self,
        request: Request<IcebergUpdateNamespacePropertiesRequest>,
    ) -> Result<Response<IcebergUpdateNamespacePropertiesResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        // Compute the before/after snapshot under a read lock so the
        // CAS can roll back cleanly on a concurrent mutation.
        let (expected_bytes, new_bytes, new_properties, updated, removed, missing) = {
            let ns_map = self.iceberg_namespaces.read();
            let current = ns_map
                .get(&ns_key)
                .cloned()
                .ok_or_else(|| Status::not_found("namespace not found"))?;

            let expected = IcebergCreateNamespaceResponse {
                namespace_levels: req.namespace_levels.clone(),
                properties: current.clone(),
            }
            .encode_to_vec();

            let mut new_props = current;
            let mut updated = Vec::new();
            let mut removed = Vec::new();
            let mut missing = Vec::new();
            for key in &req.removals {
                if new_props.remove(key).is_some() {
                    removed.push(key.clone());
                } else {
                    missing.push(key.clone());
                }
            }
            for (key, value) in &req.updates {
                new_props.insert(key.clone(), value.clone());
                updated.push(key.clone());
            }
            let new_bytes = IcebergCreateNamespaceResponse {
                namespace_levels: req.namespace_levels.clone(),
                properties: new_props.clone(),
            }
            .encode_to_vec();
            (expected, new_bytes, new_props, updated, removed, missing)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergNamespaces,
                    key: ns_key.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "iceberg-update-namespace-properties".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted(
                            "namespace properties changed since read; retry",
                        ));
                    }
                    other => {
                        error!(
                            "unexpected raft response for update_namespace_properties: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            let resp = IcebergCreateNamespaceResponse {
                namespace_levels: req.namespace_levels.clone(),
                properties: new_properties.clone(),
            };
            store.put_iceberg_namespace(&ns_key, &resp.encode_to_vec());
        }

        self.iceberg_namespaces
            .write()
            .insert(ns_key.clone(), new_properties);

        Ok(Response::new(IcebergUpdateNamespacePropertiesResponse {
            updated,
            removed,
            missing,
        }))
    }

    pub(crate) async fn iceberg_namespace_exists(
        &self,
        request: Request<IcebergNamespaceExistsRequest>,
    ) -> Result<Response<IcebergNamespaceExistsResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);
        let exists = self.iceberg_namespaces.read().contains_key(&ns_key);
        Ok(Response::new(IcebergNamespaceExistsResponse { exists }))
    }

    pub(crate) async fn iceberg_create_table(
        &self,
        request: Request<IcebergCreateTableRequest>,
    ) -> Result<Response<IcebergCreateTableResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        // Verify namespace exists
        if !self.iceberg_namespaces.read().contains_key(&ns_key) {
            return Err(Status::not_found("namespace not found"));
        }

        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);

        if self.iceberg_tables.read().contains_key(&table_key) {
            return Err(Status::already_exists("table already exists"));
        }

        let now = Self::current_timestamp();
        let entry = IcebergTableEntry {
            metadata_location: req.metadata_location.clone(),
            created_at: now,
            updated_at: now,
            metadata_json: req.metadata_json.clone(),
            policy_json: Vec::new(),
        };
        let new_bytes = entry.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergTables,
                    key: table_key.clone(),
                    expected: None,
                    new_value: Some(new_bytes),
                }],
                requested_by: "iceberg-create-table".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("table already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_table: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_iceberg_table(&table_key, &entry.encode_to_vec());
        }

        self.iceberg_tables
            .write()
            .insert(table_key.clone(), entry.clone());

        info!(
            "Created iceberg table: {:?}.{}",
            req.namespace_levels, req.table_name
        );

        Ok(Response::new(IcebergCreateTableResponse {
            metadata_location: req.metadata_location,
            metadata_json: req.metadata_json,
        }))
    }

    pub(crate) async fn iceberg_load_table(
        &self,
        request: Request<IcebergLoadTableRequest>,
    ) -> Result<Response<IcebergLoadTableResponse>, Status> {
        let req = request.into_inner();
        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);

        let entry = self
            .iceberg_tables
            .read()
            .get(&table_key)
            .cloned()
            .ok_or_else(|| Status::not_found("table not found"))?;

        Ok(Response::new(IcebergLoadTableResponse {
            metadata_location: entry.metadata_location,
            metadata_json: entry.metadata_json,
        }))
    }

    pub(crate) async fn iceberg_commit_table(
        &self,
        request: Request<IcebergCommitTableRequest>,
    ) -> Result<Response<IcebergCommitTableResponse>, Status> {
        let req = request.into_inner();
        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);

        // Stage 1 — read the current entry, validate the expected metadata
        // location, and encode the proposed new entry. Held behind a read
        // lock so concurrent non-conflicting RPCs on other tables aren't
        // serialized against this one.
        let (old_bytes, new_entry, new_bytes) = {
            let tables = self.iceberg_tables.read();
            let entry = tables
                .get(&table_key)
                .ok_or_else(|| Status::not_found("table not found"))?;

            if entry.metadata_location != req.current_metadata_location {
                return Err(Status::failed_precondition(format!(
                    "metadata location mismatch: expected '{}', actual '{}'",
                    req.current_metadata_location, entry.metadata_location
                )));
            }

            let now = Self::current_timestamp();
            let new_entry = IcebergTableEntry {
                metadata_location: req.new_metadata_location.clone(),
                created_at: entry.created_at,
                updated_at: now,
                metadata_json: req.new_metadata_json.clone(),
                policy_json: entry.policy_json.clone(),
            };
            let old_bytes = entry.encode_to_vec();
            let new_bytes = new_entry.encode_to_vec();
            (old_bytes, new_entry, new_bytes)
        };

        // Stage 2 — replicate the CAS through Raft so followers observe
        // the same commit. Non-leader pods return a Forwarding error that
        // `raft_write_to_status` turns into a leader-hint Status; the
        // iceberg REST handler retries against the leader.
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergTables,
                    key: table_key.clone(),
                    expected: Some(old_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "iceberg-commit".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::failed_precondition(
                            "concurrent metadata update detected",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for iceberg commit: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            // Legacy non-Raft path (tests, pre-Raft deployments). Keep the
            // old direct-redb CAS so unit tests without a raft handle
            // still work.
            match store.cas_iceberg_table(&table_key, &old_bytes, &new_bytes) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(Status::failed_precondition(
                        "concurrent metadata update detected",
                    ));
                }
                Err(e) => {
                    error!("Failed to CAS iceberg table '{}': {}", table_key, e);
                    return Err(Status::internal("failed to commit table update"));
                }
            }
        }

        // Stage 3 — mirror into the in-memory cache on this leader so
        // local reads see the update without waiting for a redb hit.
        // Followers' caches are rebuilt from redb on next leader promote
        // (the state machine apply already landed the bytes on disk).
        self.iceberg_tables
            .write()
            .insert(table_key.clone(), new_entry);

        debug!(
            "Committed iceberg table {:?}.{}: {} -> {}",
            req.namespace_levels,
            req.table_name,
            req.current_metadata_location,
            req.new_metadata_location
        );

        Ok(Response::new(IcebergCommitTableResponse {
            metadata_location: req.new_metadata_location,
            metadata_json: req.new_metadata_json,
        }))
    }

    pub(crate) async fn iceberg_commit_transaction(
        &self,
        request: Request<IcebergCommitTransactionRequest>,
    ) -> Result<Response<IcebergCommitTransactionResponse>, Status> {
        let req = request.into_inner();
        if req.table_changes.is_empty() {
            return Err(Status::invalid_argument("table_changes is empty"));
        }
        // One compare-and-set per table, all in one command.
        if req.table_changes.len() > objectio_meta_store::MAX_OPS {
            return Err(Status::invalid_argument(format!(
                "{} table changes in one transaction; at most {}",
                req.table_changes.len(),
                objectio_meta_store::MAX_OPS
            )));
        }

        // Stage 1 — validate every change's expected location and encode the
        // new entries. Held behind a read-lock so concurrent single-table
        // commits on other tables aren't serialized behind this one. A
        // failed expected location aborts the whole transaction before
        // any Raft round-trip.
        struct Prepared {
            table_key: String,
            old_bytes: Vec<u8>,
            new_entry: IcebergTableEntry,
            new_bytes: Vec<u8>,
            resp: IcebergCommitTableResponse,
        }
        let prepared: Vec<Prepared> = {
            let tables = self.iceberg_tables.read();
            let now = Self::current_timestamp();
            let mut prepared = Vec::with_capacity(req.table_changes.len());
            for (i, ch) in req.table_changes.iter().enumerate() {
                let table_key = Self::iceberg_table_key_wh(
                    &req.warehouse,
                    &ch.namespace_levels,
                    &ch.table_name,
                );
                let entry = tables
                    .get(&table_key)
                    .ok_or_else(|| Status::not_found(format!("table_changes[{i}]: not found")))?;
                if entry.metadata_location != ch.current_metadata_location {
                    return Err(Status::failed_precondition(format!(
                        "table_changes[{i}]: metadata location mismatch: expected '{}', actual '{}'",
                        ch.current_metadata_location, entry.metadata_location
                    )));
                }
                let new_entry = IcebergTableEntry {
                    metadata_location: ch.new_metadata_location.clone(),
                    created_at: entry.created_at,
                    updated_at: now,
                    metadata_json: ch.new_metadata_json.clone(),
                    policy_json: entry.policy_json.clone(),
                };
                let old_bytes = entry.encode_to_vec();
                let new_bytes = new_entry.encode_to_vec();
                let resp = IcebergCommitTableResponse {
                    metadata_location: ch.new_metadata_location.clone(),
                    metadata_json: ch.new_metadata_json.clone(),
                };
                prepared.push(Prepared {
                    table_key,
                    old_bytes,
                    new_entry,
                    new_bytes,
                    resp,
                });
            }
            prepared
        };

        // Stage 2 — one Raft MultiCas for the whole batch. All ops land
        // atomically or none do; a stale expected on any row rolls the
        // whole transaction back.
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let ops: Vec<CasOp> = prepared
                .iter()
                .map(|p| CasOp {
                    table: CasTable::IcebergTables,
                    key: p.table_key.clone(),
                    expected: Some(p.old_bytes.clone()),
                    new_value: Some(p.new_bytes.clone()),
                })
                .collect();
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "iceberg-transaction".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::failed_precondition(format!(
                            "concurrent metadata update detected on table_changes {failed_indices:?}"
                        )));
                    }
                    other => {
                        error!(
                            "unexpected raft response for iceberg transaction: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            // Non-Raft test path: emulate atomicity via the store's
            // multi-key CAS helper (one redb write-txn across all ops).
            // Not replicated; production deployments always take the
            // Raft branch above.
            let ops: Vec<(String, Vec<u8>, Vec<u8>)> = prepared
                .iter()
                .map(|p| {
                    (
                        p.table_key.clone(),
                        p.old_bytes.clone(),
                        p.new_bytes.clone(),
                    )
                })
                .collect();
            match store.cas_iceberg_tables_multi(&ops) {
                Ok(failed) if failed.is_empty() => {}
                Ok(failed) => {
                    return Err(Status::failed_precondition(format!(
                        "concurrent metadata update detected on table_changes {failed:?}"
                    )));
                }
                Err(e) => {
                    error!("cas_iceberg_tables_multi failed: {e}");
                    return Err(Status::internal("failed to commit transaction"));
                }
            }
        }

        // Stage 3 — mirror every successful commit into the in-memory
        // cache on this leader. `committed` vector mirrors the request
        // `table_changes` order so the caller can match results 1:1.
        let mut committed = Vec::with_capacity(prepared.len());
        {
            let mut tables = self.iceberg_tables.write();
            for p in prepared {
                tables.insert(p.table_key.clone(), p.new_entry);
                committed.push(p.resp);
            }
        }

        debug!(
            "Committed iceberg transaction: warehouse={} changes={}",
            req.warehouse,
            committed.len()
        );

        Ok(Response::new(IcebergCommitTransactionResponse {
            committed,
        }))
    }

    pub(crate) async fn iceberg_drop_table(
        &self,
        request: Request<IcebergDropTableRequest>,
    ) -> Result<Response<IcebergDropTableResponse>, Status> {
        let req = request.into_inner();
        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);

        let expected_bytes = {
            let tables = self.iceberg_tables.read();
            tables
                .get(&table_key)
                .cloned()
                .ok_or_else(|| Status::not_found("table not found"))?
                .encode_to_vec()
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergTables,
                    key: table_key.clone(),
                    expected: Some(expected_bytes),
                    new_value: None,
                }],
                requested_by: "iceberg-drop-table".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("table changed since read; retry drop"));
                    }
                    other => {
                        error!("unexpected raft response for drop_table: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_iceberg_table(&table_key);
        }

        self.iceberg_tables.write().remove(&table_key);

        info!(
            "Dropped iceberg table: {:?}.{} (purge={})",
            req.namespace_levels, req.table_name, req.purge
        );

        Ok(Response::new(IcebergDropTableResponse { success: true }))
    }

    pub(crate) async fn iceberg_rename_table(
        &self,
        request: Request<IcebergRenameTableRequest>,
    ) -> Result<Response<IcebergRenameTableResponse>, Status> {
        let req = request.into_inner();
        let source = req
            .source
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("source is required"))?;
        let dest = req
            .destination
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("destination is required"))?;

        let src_key = Self::iceberg_table_key(&source.namespace_levels, &source.name);
        let dst_key = Self::iceberg_table_key(&dest.namespace_levels, &dest.name);

        // Verify destination namespace exists
        let dst_ns_key = Self::iceberg_ns_key(&dest.namespace_levels);
        if !self.iceberg_namespaces.read().contains_key(&dst_ns_key) {
            return Err(Status::not_found("destination namespace not found"));
        }

        // Rename is two ops in one atomic MultiCas: delete src + insert
        // dst. If either side conflicts the whole rename aborts.
        let (expected_src_bytes, entry_bytes, entry) = {
            let tables = self.iceberg_tables.read();
            let entry = tables
                .get(&src_key)
                .cloned()
                .ok_or_else(|| Status::not_found("source table not found"))?;
            if tables.contains_key(&dst_key) {
                return Err(Status::already_exists("destination table already exists"));
            }
            let bytes = entry.encode_to_vec();
            (bytes.clone(), bytes, entry)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![
                    CasOp {
                        table: CasTable::IcebergTables,
                        key: src_key.clone(),
                        expected: Some(expected_src_bytes),
                        new_value: None,
                    },
                    CasOp {
                        table: CasTable::IcebergTables,
                        key: dst_key.clone(),
                        expected: None,
                        new_value: Some(entry_bytes),
                    },
                ],
                requested_by: "iceberg-rename-table".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::aborted(format!(
                            "rename conflict at ops {failed_indices:?}; retry"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for rename_table: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_iceberg_table(&src_key);
            store.put_iceberg_table(&dst_key, &entry.encode_to_vec());
        }

        {
            let mut tables = self.iceberg_tables.write();
            tables.remove(&src_key);
            tables.insert(dst_key.clone(), entry);
        }

        info!(
            "Renamed iceberg table: {:?}.{} -> {:?}.{}",
            source.namespace_levels, source.name, dest.namespace_levels, dest.name
        );

        Ok(Response::new(IcebergRenameTableResponse { success: true }))
    }

    pub(crate) async fn iceberg_list_tables(
        &self,
        request: Request<IcebergListTablesRequest>,
    ) -> Result<Response<IcebergListTablesResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        // Verify namespace exists
        if !self.iceberg_namespaces.read().contains_key(&ns_key) {
            return Err(Status::not_found("namespace not found"));
        }

        let prefix = format!("{ns_key}\x00");

        let page_size = if req.page_size == 0 {
            100
        } else {
            req.page_size.min(1000)
        } as usize;

        let mut table_names: Vec<String> = self
            .iceberg_tables
            .read()
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .filter_map(|k| {
                let table_name = &k[prefix.len()..];
                if table_name.contains('\x00') {
                    None
                } else {
                    Some(table_name.to_string())
                }
            })
            .collect();
        table_names.sort();

        // Skip past page_token
        if !req.page_token.is_empty() {
            table_names.retain(|n| n.as_str() > req.page_token.as_str());
        }

        let has_more = table_names.len() > page_size;
        let table_names: Vec<String> = table_names.into_iter().take(page_size).collect();

        let next_page_token = if has_more {
            table_names.last().cloned().unwrap_or_default()
        } else {
            String::new()
        };

        let identifiers: Vec<IcebergTableIdentifier> = table_names
            .iter()
            .map(|name| IcebergTableIdentifier {
                namespace_levels: req.namespace_levels.clone(),
                name: name.clone(),
            })
            .collect();

        Ok(Response::new(IcebergListTablesResponse {
            identifiers,
            next_page_token,
        }))
    }

    pub(crate) async fn iceberg_table_exists(
        &self,
        request: Request<IcebergTableExistsRequest>,
    ) -> Result<Response<IcebergTableExistsResponse>, Status> {
        let req = request.into_inner();
        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);
        let exists = self.iceberg_tables.read().contains_key(&table_key);
        Ok(Response::new(IcebergTableExistsResponse { exists }))
    }

    pub(crate) async fn iceberg_set_table_policy(
        &self,
        request: Request<IcebergSetTablePolicyRequest>,
    ) -> Result<Response<IcebergSetTablePolicyResponse>, Status> {
        let req = request.into_inner();
        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);

        // A CAS against the entry as read, through Raft like every other
        // table write: a policy written only here would be lost to the
        // followers and overwritten by the next commit.
        let (old_bytes, new_entry) = {
            let tables = self.iceberg_tables.read();
            let entry = tables
                .get(&table_key)
                .ok_or_else(|| Status::not_found("table not found"))?;
            let mut new_entry = entry.clone();
            new_entry.policy_json = req.policy_json;
            new_entry.updated_at = Self::current_timestamp();
            (entry.encode_to_vec(), new_entry)
        };
        let new_bytes = new_entry.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergTables,
                    key: table_key.clone(),
                    expected: Some(old_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "iceberg-set-table-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("table changed since read; retry"));
                    }
                    other => {
                        error!("unexpected raft response for set_table_policy: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            match store.cas_iceberg_table(&table_key, &old_bytes, &new_bytes) {
                Ok(true) => {}
                Ok(false) => return Err(Status::aborted("table changed since read; retry")),
                Err(e) => {
                    error!("Failed to CAS iceberg table '{}': {}", table_key, e);
                    return Err(Status::internal("failed to set the table policy"));
                }
            }
        }

        self.iceberg_tables.write().insert(table_key, new_entry);

        info!(
            "Set policy on iceberg table: {:?}.{}",
            req.namespace_levels, req.table_name
        );

        Ok(Response::new(IcebergSetTablePolicyResponse {
            success: true,
        }))
    }

    pub(crate) async fn iceberg_get_table_policy(
        &self,
        request: Request<IcebergGetTablePolicyRequest>,
    ) -> Result<Response<IcebergGetTablePolicyResponse>, Status> {
        let req = request.into_inner();
        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);

        let entry = self
            .iceberg_tables
            .read()
            .get(&table_key)
            .cloned()
            .ok_or_else(|| Status::not_found("table not found"))?;

        Ok(Response::new(IcebergGetTablePolicyResponse {
            policy_json: entry.policy_json,
        }))
    }

    pub(crate) async fn iceberg_create_warehouse(
        &self,
        request: Request<IcebergCreateWarehouseRequest>,
    ) -> Result<Response<IcebergCreateWarehouseResponse>, Status> {
        let req = request.into_inner();

        if req.name.is_empty() {
            return Err(Status::invalid_argument("warehouse name is required"));
        }

        // Check if warehouse already exists
        if self.iceberg_warehouses.read().contains_key(&req.name) {
            return Err(Status::already_exists(format!(
                "warehouse '{}' already exists",
                req.name
            )));
        }

        let bucket_name = format!("iceberg-{}", req.name);
        let location = format!("s3://{}", bucket_name);
        let now = Self::current_timestamp();

        // Create the backing bucket
        if self.buckets.read().contains_key(&bucket_name) {
            return Err(Status::already_exists(format!(
                "bucket '{}' already exists",
                bucket_name
            )));
        }

        let bucket = BucketMeta {
            dedup: None,
            name: bucket_name.clone(),
            owner: "system".to_string(),
            created_at: now,
            storage_class: "STANDARD".to_string(),
            versioning: VersioningState::VersioningDisabled.into(),
            pool: String::new(),
            tenant: req.tenant.clone(),
            quota_bytes: 0,
            quota_objects: 0,
            object_lock: None,
        };
        let bucket_bytes = bucket.encode_to_vec();

        let warehouse = IcebergWarehouse {
            name: req.name.clone(),
            bucket: bucket_name.clone(),
            location,
            tenant: req.tenant.clone(),
            created_at: now,
            properties: req.properties.clone(),
        };
        let warehouse_bytes = warehouse.encode_to_vec();

        // Two-op atomic MultiCas: warehouse row + backing bucket. If
        // either side conflicts the whole creation aborts, avoiding
        // the half-state where a warehouse exists without its bucket
        // (or a lingering orphan bucket from a failed warehouse create).
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![
                    CasOp {
                        table: CasTable::IcebergWarehouses,
                        key: req.name.clone(),
                        expected: None,
                        new_value: Some(warehouse_bytes),
                    },
                    CasOp {
                        table: CasTable::Buckets,
                        key: bucket_name.clone(),
                        expected: None,
                        new_value: Some(bucket_bytes),
                    },
                ],
                requested_by: "iceberg-create-warehouse".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::already_exists(format!(
                            "warehouse or backing bucket already exists (conflicts at {failed_indices:?})"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for create_warehouse: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&bucket_name, &bucket);
            store.put_warehouse(&req.name, &warehouse_bytes);
        }

        self.buckets
            .write()
            .insert(bucket_name.clone(), bucket.clone());
        self.iceberg_warehouses
            .write()
            .insert(req.name.clone(), warehouse.clone());

        info!(
            "Created warehouse: {} (bucket: {})",
            req.name, warehouse.bucket
        );

        Ok(Response::new(IcebergCreateWarehouseResponse {
            warehouse: Some(warehouse),
        }))
    }

    pub(crate) async fn iceberg_list_warehouses(
        &self,
        request: Request<IcebergListWarehousesRequest>,
    ) -> Result<Response<IcebergListWarehousesResponse>, Status> {
        let req = request.into_inner();
        let warehouses: Vec<IcebergWarehouse> = self
            .iceberg_warehouses
            .read()
            .values()
            .filter(|w| req.tenant.is_empty() || w.tenant == req.tenant)
            .cloned()
            .collect();
        Ok(Response::new(IcebergListWarehousesResponse { warehouses }))
    }

    pub(crate) async fn iceberg_delete_warehouse(
        &self,
        request: Request<IcebergDeleteWarehouseRequest>,
    ) -> Result<Response<IcebergDeleteWarehouseResponse>, Status> {
        let name = request.into_inner().name;

        let (wh, wh_bytes, bucket_bytes) = {
            let warehouses = self.iceberg_warehouses.read();
            let wh = warehouses
                .get(&name)
                .cloned()
                .ok_or_else(|| Status::not_found(format!("warehouse '{}' not found", name)))?;
            let wh_bytes = wh.encode_to_vec();
            let bucket_bytes = self
                .buckets
                .read()
                .get(&wh.bucket)
                .map(|b| b.encode_to_vec());
            (wh, wh_bytes, bucket_bytes)
        };

        // Refuse while the bucket holds objects: dropping its record would
        // strand them on disk with no bucket to reach them through. As for
        // DeleteBucket, the listing is the record of current objects; the
        // gateway checks the OSDs for noncurrent versions first.
        if bucket_bytes.is_some()
            && let Some(store) = &self.store
        {
            let (entries, _, _) = store
                .list_object_listings(&wh.bucket, "", "", 1)
                .map_err(|e| Status::unavailable(format!("cannot read the listing: {e}")))?;
            if !entries.is_empty() {
                return Err(Status::failed_precondition(format!(
                    "warehouse '{name}' is not empty: its bucket '{}' holds objects",
                    wh.bucket
                )));
            }
        }
        // The bucket's configuration goes with it, as on DeleteBucket: a
        // bucket created later under the same name must not inherit it.
        let config_rows = if bucket_bytes.is_some() {
            self.bucket_config_rows(&wh.bucket)
        } else {
            Vec::new()
        };

        // Atomic dual delete: warehouse row + backing bucket. If the
        // bucket has already been removed separately, skip its op so
        // we don't spuriously fail on expected=Some but actual=None.
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::IcebergWarehouses,
                key: name.clone(),
                expected: Some(wh_bytes),
                new_value: None,
            }];
            if let Some(bucket_bytes) = bucket_bytes {
                ops.push(CasOp {
                    table: CasTable::Buckets,
                    key: wh.bucket.clone(),
                    expected: Some(bucket_bytes),
                    new_value: None,
                });
            }
            ops.extend(config_rows.iter().map(|(table, key, value)| CasOp {
                table: table.clone(),
                key: key.clone(),
                expected: Some(value.clone()),
                new_value: None,
            }));
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "iceberg-delete-warehouse".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted(
                            "warehouse or bucket changed since read; retry delete",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for delete_warehouse: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_warehouse(&name);
            store.delete_bucket(&wh.bucket);
            for (table, key, _) in &config_rows {
                store.write_named(objectio_meta_store::cas_table_name(table), key, None);
            }
        }

        self.iceberg_warehouses.write().remove(&name);
        self.buckets.write().remove(&wh.bucket);
        self.forget_bucket_config(&wh.bucket);

        info!("Deleted warehouse: {} (bucket: {})", name, wh.bucket);
        Ok(Response::new(IcebergDeleteWarehouseResponse {
            success: true,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> (tempfile::TempDir, MetaService) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MetaStore::open(dir.path().join("meta.redb")).unwrap());
        (dir, MetaService::with_store(EcConfig::default(), store))
    }

    async fn warehouse(svc: &MetaService, name: &str) -> IcebergWarehouse {
        svc.iceberg_create_warehouse(Request::new(IcebergCreateWarehouseRequest {
            name: name.to_string(),
            tenant: "acme".to_string(),
            properties: std::collections::HashMap::default(),
        }))
        .await
        .unwrap()
        .into_inner()
        .warehouse
        .unwrap()
    }

    async fn delete(svc: &MetaService, name: &str) -> Result<(), Status> {
        svc.iceberg_delete_warehouse(Request::new(IcebergDeleteWarehouseRequest {
            name: name.to_string(),
        }))
        .await
        .map(drop)
    }

    /// Deleting a warehouse drops its bucket's record; with objects in it,
    /// they would be stranded on disk.
    #[tokio::test]
    async fn a_warehouse_holding_objects_is_not_deleted() {
        let (_dir, svc) = service();
        let wh = warehouse(&svc, "full").await;
        let store = svc.store.clone().unwrap();
        let listing = format!("{}\0data/part-0.parquet\0", wh.bucket);
        store.put_object_listing(&listing, &ObjectListingEntry::default().encode_to_vec());

        let err = delete(&svc, "full").await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(svc.iceberg_warehouses.read().contains_key("full"));
        assert!(svc.buckets.read().contains_key(&wh.bucket));

        store.delete_object_listing(&listing);
        delete(&svc, "full").await.unwrap();
        assert!(!svc.buckets.read().contains_key(&wh.bucket));
    }

    /// A table's policy is the one of the table in its warehouse, and it is
    /// stored: keyed without the warehouse it named no table at all.
    #[tokio::test]
    async fn a_table_policy_is_stored_on_the_warehouse_table() {
        let (_dir, svc) = service();
        warehouse(&svc, "wh").await;
        let ns = vec!["db".to_string()];
        svc.iceberg_create_namespace(Request::new(IcebergCreateNamespaceRequest {
            namespace_levels: ns.clone(),
            properties: std::collections::HashMap::default(),
            warehouse: "wh".to_string(),
        }))
        .await
        .unwrap();
        svc.iceberg_create_table(Request::new(IcebergCreateTableRequest {
            namespace_levels: ns.clone(),
            table_name: "t".to_string(),
            metadata_location: "s3://iceberg-wh/db/t/metadata/0.json".to_string(),
            metadata_json: b"{}".to_vec(),
            warehouse: "wh".to_string(),
        }))
        .await
        .unwrap();

        svc.iceberg_set_table_policy(Request::new(IcebergSetTablePolicyRequest {
            namespace_levels: ns.clone(),
            table_name: "t".to_string(),
            policy_json: b"{\"p\":1}".to_vec(),
            warehouse: "wh".to_string(),
        }))
        .await
        .unwrap();
        let got = svc
            .iceberg_get_table_policy(Request::new(IcebergGetTablePolicyRequest {
                namespace_levels: ns.clone(),
                table_name: "t".to_string(),
                warehouse: "wh".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got.policy_json, b"{\"p\":1}");

        // Written to the store, not only the cache.
        let key = MetaService::iceberg_table_key_wh("wh", &ns, "t");
        let stored = svc
            .store
            .as_ref()
            .unwrap()
            .get_iceberg_table(&key)
            .unwrap()
            .map(|v| IcebergTableEntry::decode(v.as_slice()).unwrap())
            .expect("table row");
        assert_eq!(stored.policy_json, b"{\"p\":1}");
    }
}
