//! Delta Sharing: shares, their tables, recipients.

use super::*;

impl MetaService {
    pub(crate) async fn delta_create_share(
        &self,
        request: Request<DeltaCreateShareRequest>,
    ) -> Result<Response<DeltaCreateShareResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("share name is required"));
        }
        if self.delta_shares.read().contains_key(&req.name) {
            return Err(Status::already_exists("share already exists"));
        }
        let now = Self::current_timestamp();
        let entry = DeltaShareEntry {
            name: req.name.clone(),
            comment: req.comment,
            created_at: now as i64,
            tenant: req.tenant,
        };
        let bytes = entry.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DeltaShares,
                    key: req.name.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "delta-create-share".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("share already exists"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delta_create_share: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_delta_share(&req.name, &entry.encode_to_vec());
        }

        self.delta_shares
            .write()
            .insert(req.name.clone(), entry.clone());
        info!("Created Delta share: {}", req.name);
        Ok(Response::new(DeltaCreateShareResponse {
            share: Some(entry),
        }))
    }

    pub(crate) async fn delta_get_share(
        &self,
        request: Request<DeltaGetShareRequest>,
    ) -> Result<Response<DeltaGetShareResponse>, Status> {
        let req = request.into_inner();
        let entry = self
            .delta_shares
            .read()
            .get(&req.name)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("share '{}' not found", req.name)))?;
        Ok(Response::new(DeltaGetShareResponse { share: Some(entry) }))
    }

    pub(crate) async fn delta_list_shares(
        &self,
        request: Request<DeltaListSharesRequest>,
    ) -> Result<Response<DeltaListSharesResponse>, Status> {
        let req = request.into_inner();
        let shares: Vec<DeltaShareEntry> = self
            .delta_shares
            .read()
            .values()
            .filter(|s| req.tenant.is_empty() || s.tenant == req.tenant)
            .cloned()
            .collect();
        Ok(Response::new(DeltaListSharesResponse {
            shares,
            next_page_token: String::new(),
        }))
    }

    pub(crate) async fn delta_drop_share(
        &self,
        request: Request<DeltaDropShareRequest>,
    ) -> Result<Response<DeltaDropShareResponse>, Status> {
        let req = request.into_inner();
        // Multi-op MultiCas: the share row + every DeltaShareTableEntry
        // whose key prefix matches. All removed atomically — no orphan
        // table rows pointing at a dropped share.
        let share_prefix = format!("{}\x00", req.name);
        let (expected_share_bytes, table_deletes) = {
            let shares = self.delta_shares.read();
            let Some(share) = shares.get(&req.name) else {
                return Ok(Response::new(DeltaDropShareResponse { success: false }));
            };
            let share_bytes = share.encode_to_vec();
            let tables = self.delta_tables.read();
            let deletes: Vec<(String, Vec<u8>)> = tables
                .iter()
                .filter(|(k, _)| k.starts_with(&share_prefix))
                .map(|(k, v)| (k.clone(), v.encode_to_vec()))
                .collect();
            (share_bytes, deletes)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = Vec::with_capacity(1 + table_deletes.len());
            ops.push(CasOp {
                table: CasTable::DeltaShares,
                key: req.name.clone(),
                expected: Some(expected_share_bytes),
                new_value: None,
            });
            for (tk, tb) in &table_deletes {
                ops.push(CasOp {
                    table: CasTable::DeltaTables,
                    key: tk.clone(),
                    expected: Some(tb.clone()),
                    new_value: None,
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delta-drop-share".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::aborted(format!(
                            "share or table changed mid-drop; retry (conflicts at {failed_indices:?})"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for delta_drop_share: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_delta_share(&req.name);
            for (tk, _) in &table_deletes {
                store.delete_delta_table(tk);
            }
        }

        self.delta_shares.write().remove(&req.name);
        self.delta_tables
            .write()
            .retain(|k, _| !k.starts_with(&share_prefix));
        info!("Dropped Delta share: {}", req.name);
        Ok(Response::new(DeltaDropShareResponse { success: true }))
    }

    pub(crate) async fn delta_add_table(
        &self,
        request: Request<DeltaAddTableRequest>,
    ) -> Result<Response<DeltaAddTableResponse>, Status> {
        let req = request.into_inner();
        if !self.delta_shares.read().contains_key(&req.share) {
            return Err(Status::not_found(format!(
                "share '{}' not found",
                req.share
            )));
        }
        let table_key = format!("{}\x00{}\x00{}", req.share, req.schema, req.table_name);
        let share_id = Uuid::new_v4().to_string();
        let entry = DeltaShareTableEntry {
            share: req.share.clone(),
            schema: req.schema.clone(),
            table_name: req.table_name.clone(),
            share_id: share_id.clone(),
            table_type: req.table_type.clone(),
            bucket: req.bucket.clone(),
            path: req.path.clone(),
            warehouse: req.warehouse.clone(),
            namespace: req.namespace.clone(),
        };
        let bytes = entry.encode_to_vec();
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DeltaTables,
                    key: table_key.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "delta-add-table".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("table already in share"));
                    }
                    other => {
                        error!("unexpected raft response for delta_add_table: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_delta_table(&table_key, &entry.encode_to_vec());
        }

        self.delta_tables
            .write()
            .insert(table_key.clone(), entry.clone());
        info!(
            "Added table {}.{} to Delta share {}",
            req.schema, req.table_name, req.share
        );
        Ok(Response::new(DeltaAddTableResponse { table: Some(entry) }))
    }

    pub(crate) async fn delta_remove_table(
        &self,
        request: Request<DeltaRemoveTableRequest>,
    ) -> Result<Response<DeltaRemoveTableResponse>, Status> {
        let req = request.into_inner();
        let table_key = format!("{}\x00{}\x00{}", req.share, req.schema, req.table_name);
        let expected = self
            .delta_tables
            .read()
            .get(&table_key)
            .map(|v| v.encode_to_vec());
        if expected.is_none() {
            return Ok(Response::new(DeltaRemoveTableResponse { success: false }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DeltaTables,
                    key: table_key.clone(),
                    expected,
                    new_value: None,
                }],
                requested_by: "delta-remove-table".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("table changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delta_remove_table: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_delta_table(&table_key);
        }

        self.delta_tables.write().remove(&table_key);
        Ok(Response::new(DeltaRemoveTableResponse { success: true }))
    }

    pub(crate) async fn delta_list_tables(
        &self,
        request: Request<DeltaListTablesRequest>,
    ) -> Result<Response<DeltaListTablesResponse>, Status> {
        let req = request.into_inner();
        let tables: Vec<DeltaShareTableEntry> = self
            .delta_tables
            .read()
            .iter()
            .filter(|(k, _)| {
                k.starts_with(&format!("{}\x00", req.share))
                    && (req.schema.is_empty()
                        || k.starts_with(&format!("{}\x00{}\x00", req.share, req.schema)))
            })
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(DeltaListTablesResponse {
            tables,
            next_page_token: String::new(),
        }))
    }

    pub(crate) async fn delta_create_recipient(
        &self,
        request: Request<DeltaCreateRecipientRequest>,
    ) -> Result<Response<DeltaCreateRecipientResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("recipient name is required"));
        }
        // Generate a cryptographically random bearer token (32 bytes → 64 hex chars)
        let raw_token = {
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            hex::encode(bytes)
        };
        // Store SHA-256 hash of the token (never store raw)
        let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));

        let now = Self::current_timestamp();
        let entry = DeltaRecipientEntry {
            name: req.name.clone(),
            token_hash: token_hash.clone(),
            shares: req.shares,
            created_at: now as i64,
        };

        if self.delta_recipients.read().contains_key(&req.name) {
            return Err(Status::already_exists("recipient already exists"));
        }
        let bytes = entry.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DeltaRecipients,
                    key: req.name.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "delta-create-recipient".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("recipient already exists"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delta_create_recipient: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_delta_recipient(&req.name, &entry.encode_to_vec());
        }

        self.delta_recipients
            .write()
            .insert(req.name.clone(), entry.clone());
        self.delta_token_index
            .write()
            .insert(token_hash.clone(), req.name.clone());
        info!("Created Delta recipient: {}", req.name);
        Ok(Response::new(DeltaCreateRecipientResponse {
            recipient: Some(entry),
            raw_token,
        }))
    }

    pub(crate) async fn delta_get_recipient_by_token(
        &self,
        request: Request<DeltaGetRecipientByTokenRequest>,
    ) -> Result<Response<DeltaGetRecipientByTokenResponse>, Status> {
        let req = request.into_inner();
        let token_hash = hex::encode(Sha256::digest(req.raw_token.as_bytes()));
        let recipient_name = self.delta_token_index.read().get(&token_hash).cloned();
        match recipient_name {
            Some(name) => {
                let entry = self.delta_recipients.read().get(&name).cloned();
                Ok(Response::new(DeltaGetRecipientByTokenResponse {
                    recipient: entry,
                    found: true,
                }))
            }
            None => Ok(Response::new(DeltaGetRecipientByTokenResponse {
                recipient: None,
                found: false,
            })),
        }
    }

    pub(crate) async fn delta_list_recipients(
        &self,
        _request: Request<DeltaListRecipientsRequest>,
    ) -> Result<Response<DeltaListRecipientsResponse>, Status> {
        let recipients: Vec<DeltaRecipientEntry> =
            self.delta_recipients.read().values().cloned().collect();
        Ok(Response::new(DeltaListRecipientsResponse {
            recipients,
            next_page_token: String::new(),
        }))
    }

    pub(crate) async fn delta_drop_recipient(
        &self,
        request: Request<DeltaDropRecipientRequest>,
    ) -> Result<Response<DeltaDropRecipientResponse>, Status> {
        let req = request.into_inner();
        let (expected, token_hash) = {
            let recipients = self.delta_recipients.read();
            let Some(entry) = recipients.get(&req.name) else {
                return Ok(Response::new(DeltaDropRecipientResponse { success: false }));
            };
            (entry.encode_to_vec(), entry.token_hash.clone())
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DeltaRecipients,
                    key: req.name.clone(),
                    expected: Some(expected),
                    new_value: None,
                }],
                requested_by: "delta-drop-recipient".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("recipient changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delta_drop_recipient: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_delta_recipient(&req.name);
        }

        self.delta_recipients.write().remove(&req.name);
        self.delta_token_index.write().remove(&token_hash);
        info!("Dropped Delta recipient: {}", req.name);
        Ok(Response::new(DeltaDropRecipientResponse { success: true }))
    }
}
