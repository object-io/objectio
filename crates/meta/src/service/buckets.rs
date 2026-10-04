//! Buckets and their settings: policy, versioning, Object Lock, lifecycle, encryption, owner, dedup.

use super::*;

impl MetaService {
    /// The dedup policy `bucket` resolves to: its own, then its tenant's,
    /// then the cluster default. In-memory only, so `GetPlacement` can
    /// return it at no cost.
    pub fn effective_dedup(&self, bucket: &str) -> objectio_proto::dedup::Effective {
        let (bucket_policy, tenant_name) = self
            .buckets
            .read()
            .get(bucket)
            .map(|b| (b.dedup, b.tenant.clone()))
            .unwrap_or_default();
        let tenant_policy = self.tenants.read().get(&tenant_name).and_then(|t| t.dedup);
        let cluster = self
            .config
            .read()
            .get(objectio_proto::dedup::CLUSTER_KEY)
            .and_then(|e| objectio_proto::dedup::cluster_from_config(&e.value));
        objectio_proto::dedup::resolve(
            bucket,
            &tenant_name,
            bucket_policy.as_ref(),
            tenant_policy.as_ref(),
            cluster.as_ref(),
        )
    }

    pub(super) fn with_dedup(
        &self,
        bucket: &str,
        mut resp: GetPlacementResponse,
    ) -> GetPlacementResponse {
        let e = self.effective_dedup(bucket);
        resp.set_dedup_mode(e.mode);
        resp.dedup_domain = e.domain;
        resp
    }

    pub(super) fn apply_bucket_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut buckets = self.buckets.write();
        match new_value {
            Some(bytes) => match BucketMeta::decode(bytes) {
                Ok(b) => {
                    buckets.insert(key.to_string(), b);
                }
                Err(e) => warn!("apply: decode BucketMeta('{key}') failed: {e}"),
            },
            None => {
                buckets.remove(key);
                drop(buckets);
                self.forget_bucket_config(key);
            }
        }
    }

    /// A drained OSD's purge state (`drain_observer::PURGE_*`), if any.
    pub fn purge_state(&self, node_id: [u8; 16]) -> Option<String> {
        self.store
            .as_ref()
            .and_then(|s| s.read_named(OSD_PURGE_TABLE, &hex::encode(node_id)))
            .and_then(|v| String::from_utf8(v).ok())
    }

    /// Drained OSDs whose purge isn't confirmed yet.
    pub fn pending_purges(&self) -> Vec<[u8; 16]> {
        self.store
            .as_ref()
            .map(|s| s.list_named(OSD_PURGE_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, v)| v.as_slice() == crate::drain_observer::PURGE_PENDING.as_bytes())
            .filter_map(|(k, _)| hex::decode(k).ok()?.try_into().ok())
            .collect()
    }

    /// Record (or, with `None`, forget) a drained OSD's purge state.
    pub async fn set_purge_state(
        &self,
        node_id: [u8; 16],
        state: Option<&str>,
    ) -> Result<(), Status> {
        let key = hex::encode(node_id);
        let current = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(OSD_PURGE_TABLE, &key));
        if current.is_none() && state.is_none() {
            return Ok(());
        }
        self.cas_one(
            objectio_meta_store::CasTable::Named(OSD_PURGE_TABLE.into()),
            &key,
            current,
            state.map(|s| s.as_bytes().to_vec()),
            "osd-purge-state",
        )
        .await
    }

    /// The stored rows configuring `bucket` beyond its `BucketMeta`, as
    /// `(table, key, current bytes)`: what deleting the bucket removes.
    pub(super) fn bucket_config_rows(
        &self,
        bucket: &str,
    ) -> Vec<(objectio_meta_store::CasTable, String, Vec<u8>)> {
        use objectio_meta_store::CasTable;
        let Some(store) = &self.store else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        for table in [
            CasTable::BucketPolicies,
            CasTable::Named("object_lock_configs".into()),
            CasTable::Named("lifecycle_configs".into()),
            CasTable::Named("bucket_encryption_configs".into()),
        ] {
            if let Some(v) = store.read_named(objectio_meta_store::cas_table_name(&table), bucket) {
                rows.push((table, bucket.to_string(), v));
            }
        }
        let prefix = format!("{bucket}/");
        rows.extend(
            store
                .list_named(BUCKET_SETTINGS_TABLE)
                .into_iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, v)| (CasTable::Named(BUCKET_SETTINGS_TABLE.into()), k, v)),
        );
        rows
    }

    /// Drop a deleted bucket's configuration from the in-memory caches.
    pub(super) fn forget_bucket_config(&self, bucket: &str) {
        self.bucket_policies.write().remove(bucket);
        self.object_lock_configs.write().remove(bucket);
        self.lifecycle_configs.write().remove(bucket);
        self.bucket_encryption_configs.write().remove(bucket);
    }

    pub(super) fn apply_bucket_policy_event(&self, key: &str, new_value: Option<&[u8]>) {
        let mut m = self.bucket_policies.write();
        match new_value {
            Some(bytes) => match std::str::from_utf8(bytes) {
                Ok(s) => {
                    m.insert(key.to_string(), s.to_string());
                }
                Err(e) => warn!("apply: bucket_policy('{key}') not utf-8: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    pub(crate) async fn create_bucket(
        &self,
        request: Request<CreateBucketRequest>,
    ) -> Result<Response<CreateBucketResponse>, Status> {
        let req = request.into_inner();

        if req.name.is_empty() {
            return Err(Status::invalid_argument("bucket name is required"));
        }

        // Check if bucket already exists
        if self.buckets.read().contains_key(&req.name) {
            return Err(Status::already_exists("bucket already exists"));
        }

        // Validate tenant exists if specified
        let tenant = req.tenant.clone();
        if !tenant.is_empty() && !self.tenants.read().contains_key(&tenant) {
            return Err(Status::not_found(format!("tenant '{}' not found", tenant)));
        }

        // Enforce tenant bucket quota
        if !tenant.is_empty()
            && let Some(tc) = self.tenants.read().get(&tenant)
            && tc.quota_buckets > 0
        {
            let count = self
                .buckets
                .read()
                .values()
                .filter(|b| b.tenant == tenant)
                .count() as u64;
            if count >= tc.quota_buckets {
                return Err(Status::resource_exhausted(format!(
                    "tenant '{}' bucket quota exceeded ({}/{})",
                    tenant, count, tc.quota_buckets
                )));
            }
        }

        let pool = self.resolve_bucket_pool(&tenant, &req.pool)?;

        let bucket = BucketMeta {
            dedup: None,
            name: req.name.clone(),
            owner: req.owner,
            created_at: Self::current_timestamp(),
            storage_class: if req.storage_class.is_empty() {
                "STANDARD".to_string()
            } else {
                req.storage_class
            },
            versioning: VersioningState::VersioningDisabled.into(),
            pool,
            tenant,
            quota_bytes: 0,
            quota_objects: 0,
            object_lock: None,
        };

        // Replicate through Raft so followers see the new bucket at the
        // same log position. Single-op MultiCas with expected=None enforces
        // "must-not-exist" at the state machine — if a concurrent proposal
        // on another pod raced us, the CAS fails and we surface it as
        // AlreadyExists (same error the in-memory precheck above returns).
        let bucket_bytes = bucket.encode_to_vec();
        // Configuration a deleted bucket of this name left behind (from
        // before deletes removed it) is cleared, and the initial settings
        // written, all in the bucket's own commit.
        #[allow(clippy::type_complexity)] // was inside #[async_trait], which clippy did not see
        let mut config_ops: Vec<(
            objectio_meta_store::CasTable,
            String,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        )> = Vec::new();
        let stale = self.bucket_config_rows(&req.name);
        for (name, value) in &req.settings {
            if name.is_empty() || name.contains('/') {
                return Err(Status::invalid_argument("invalid setting name"));
            }
            let key = bucket_setting_key(&req.name, name);
            let current = stale
                .iter()
                .find(|(_, k, _)| *k == key)
                .map(|(_, _, v)| v.clone());
            config_ops.push((
                objectio_meta_store::CasTable::Named(BUCKET_SETTINGS_TABLE.into()),
                key,
                current,
                Some(value.clone()),
            ));
        }
        for (table, key, value) in stale {
            if !config_ops.iter().any(|(_, k, _, _)| *k == key) {
                config_ops.push((table, key, Some(value), None));
            }
        }
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::Buckets,
                key: req.name.clone(),
                expected: None,
                new_value: Some(bucket_bytes),
            }];
            ops.extend(
                config_ops
                    .iter()
                    .map(|(table, key, expected, new_value)| CasOp {
                        table: table.clone(),
                        key: key.clone(),
                        expected: expected.clone(),
                        new_value: new_value.clone(),
                    }),
            );
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "create-bucket".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("bucket already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_bucket: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&req.name, &bucket);
            for (table, key, _, new_value) in &config_ops {
                store.write_named(
                    objectio_meta_store::cas_table_name(table),
                    key,
                    new_value.as_deref(),
                );
            }
        }

        self.forget_bucket_config(&req.name);
        self.buckets
            .write()
            .insert(req.name.clone(), bucket.clone());

        info!("Created bucket: {}", req.name);

        Ok(Response::new(CreateBucketResponse {
            bucket: Some(bucket),
        }))
    }

    pub(crate) async fn delete_bucket(
        &self,
        request: Request<DeleteBucketRequest>,
    ) -> Result<Response<DeleteBucketResponse>, Status> {
        let req = request.into_inner();

        // Read current bucket bytes so the CAS can detect a concurrent
        // mutation between now and commit.
        let current = {
            let b = self.buckets.read();
            b.get(&req.name)
                .cloned()
                .ok_or_else(|| Status::not_found("bucket not found"))?
        };
        let expected_bytes = current.encode_to_vec();

        // Refuse while it holds objects: deleting it orphaned them, their
        // data still on disk with no bucket to reach it through. The
        // listing index is the record of current objects; the gateway
        // checks the OSDs for noncurrent versions before calling this.
        if let Some(store) = &self.store {
            let (entries, _, _) = store
                .list_object_listings(&req.name, "", "", 1)
                .map_err(|e| Status::unavailable(format!("cannot read the listing: {e}")))?;
            if !entries.is_empty() {
                return Err(Status::failed_precondition("bucket is not empty"));
            }
        }

        // Everything configured on the bucket goes with it, in the same
        // commit: a bucket created later under the same name — by anyone —
        // must not inherit this one's policy, lock, lifecycle or settings.
        let config_rows = self.bucket_config_rows(&req.name);

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::Buckets,
                key: req.name.clone(),
                expected: Some(expected_bytes),
                new_value: None, // delete
            }];
            ops.extend(config_rows.iter().map(|(table, key, value)| CasOp {
                table: table.clone(),
                key: key.clone(),
                expected: Some(value.clone()),
                new_value: None,
            }));
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delete-bucket".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket changed since read; retry delete"));
                    }
                    other => {
                        error!("unexpected raft response for delete_bucket: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_bucket(&req.name);
            for (table, key, _) in &config_rows {
                store.write_named(objectio_meta_store::cas_table_name(table), key, None);
            }
        }

        self.buckets.write().remove(&req.name);
        self.forget_bucket_config(&req.name);

        info!("Deleted bucket: {}", req.name);

        Ok(Response::new(DeleteBucketResponse { success: true }))
    }

    pub(crate) async fn get_bucket(
        &self,
        request: Request<GetBucketRequest>,
    ) -> Result<Response<GetBucketResponse>, Status> {
        let req = request.into_inner();

        let bucket = self
            .buckets
            .read()
            .get(&req.name)
            .cloned()
            .ok_or_else(|| Status::not_found("bucket not found"))?;

        Ok(Response::new(GetBucketResponse {
            bucket: Some(bucket),
        }))
    }

    pub(crate) async fn list_buckets(
        &self,
        request: Request<ListBucketsRequest>,
    ) -> Result<Response<ListBucketsResponse>, Status> {
        let req = request.into_inner();

        let buckets: Vec<BucketMeta> = self
            .buckets
            .read()
            .values()
            .filter(|b| req.owner.is_empty() || b.owner == req.owner)
            .filter(|b| req.tenant.is_empty() || b.tenant == req.tenant)
            .cloned()
            .collect();

        Ok(Response::new(ListBucketsResponse { buckets }))
    }

    pub(crate) async fn set_bucket_policy(
        &self,
        request: Request<SetBucketPolicyRequest>,
    ) -> Result<Response<SetBucketPolicyResponse>, Status> {
        let req = request.into_inner();

        // Check if bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }

        // Validate that the policy is valid JSON
        if serde_json::from_str::<serde_json::Value>(&req.policy_json).is_err() {
            return Err(Status::invalid_argument("invalid policy JSON"));
        }

        // CAS against whatever is currently stored so a concurrent update
        // from another pod doesn't silently overwrite. Racing admin
        // operations retry from the handler.
        let expected = self
            .bucket_policies
            .read()
            .get(&req.bucket)
            .map(|v| v.as_bytes().to_vec());
        let new_value = Some(req.policy_json.as_bytes().to_vec());

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::BucketPolicies,
                    key: req.bucket.clone(),
                    expected,
                    new_value,
                }],
                requested_by: "set-bucket-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket policy changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for set_bucket_policy: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket_policy(&req.bucket, &req.policy_json);
        }

        self.bucket_policies
            .write()
            .insert(req.bucket.clone(), req.policy_json.clone());

        info!("Set bucket policy for: {}", req.bucket);

        Ok(Response::new(SetBucketPolicyResponse { success: true }))
    }

    pub(crate) async fn get_bucket_policy(
        &self,
        request: Request<GetBucketPolicyRequest>,
    ) -> Result<Response<GetBucketPolicyResponse>, Status> {
        let req = request.into_inner();

        // Check if bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }

        let policies = self.bucket_policies.read();
        let (policy_json, has_policy) = match policies.get(&req.bucket) {
            Some(policy) => (policy.clone(), true),
            None => (String::new(), false),
        };

        Ok(Response::new(GetBucketPolicyResponse {
            policy_json,
            has_policy,
        }))
    }

    pub(crate) async fn delete_bucket_policy(
        &self,
        request: Request<DeleteBucketPolicyRequest>,
    ) -> Result<Response<DeleteBucketPolicyResponse>, Status> {
        let req = request.into_inner();

        // Check if bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }

        let expected = self
            .bucket_policies
            .read()
            .get(&req.bucket)
            .map(|v| v.as_bytes().to_vec());

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::BucketPolicies,
                    key: req.bucket.clone(),
                    expected,
                    new_value: None, // delete
                }],
                requested_by: "delete-bucket-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket policy changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delete_bucket_policy: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_bucket_policy(&req.bucket);
        }

        self.bucket_policies.write().remove(&req.bucket);

        info!("Deleted bucket policy for: {}", req.bucket);

        Ok(Response::new(DeleteBucketPolicyResponse { success: true }))
    }

    pub(crate) async fn put_bucket_versioning(
        &self,
        request: Request<PutBucketVersioningRequest>,
    ) -> Result<Response<PutBucketVersioningResponse>, Status> {
        let req = request.into_inner();

        // Object-locked buckets cannot have versioning suspended.
        if req.state() == VersioningState::VersioningSuspended {
            let lock_configs = self.object_lock_configs.read();
            if lock_configs.get(&req.bucket).is_some_and(|c| c.enabled) {
                return Err(Status::failed_precondition(
                    "cannot suspend versioning on object-locked bucket",
                ));
            }
        }

        let (expected_bytes, new_bucket, new_bytes) = {
            let buckets = self.buckets.read();
            let current = buckets
                .get(&req.bucket)
                .cloned()
                .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", req.bucket)))?;
            let expected = current.encode_to_vec();
            let mut new_bucket = current;
            new_bucket.versioning = req.state;
            let new_bytes = new_bucket.encode_to_vec();
            (expected, new_bucket, new_bytes)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Buckets,
                    key: req.bucket.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "put-bucket-versioning".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for put_bucket_versioning: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&req.bucket, &new_bucket);
        }

        self.buckets.write().insert(req.bucket.clone(), new_bucket);
        info!(
            "Set versioning for bucket '{}' to {:?}",
            req.bucket,
            req.state()
        );
        Ok(Response::new(PutBucketVersioningResponse { success: true }))
    }

    pub(crate) async fn set_bucket_dedup(
        &self,
        request: Request<objectio_proto::metadata::SetBucketDedupRequest>,
    ) -> Result<Response<objectio_proto::metadata::SetBucketDedupResponse>, Status> {
        use objectio_proto::metadata::{DedupMode, DedupScope};
        let req = request.into_inner();
        // All-unset is no policy at all: the bucket inherits.
        let policy = req
            .policy
            .filter(|p| p.mode() != DedupMode::Unset || p.scope() != DedupScope::Unset);
        if let Some(p) = &policy {
            objectio_proto::dedup::validate(p).map_err(Status::invalid_argument)?;
        }

        let (expected_bytes, new_bucket, new_bytes) = {
            let buckets = self.buckets.read();
            let current = buckets
                .get(&req.bucket)
                .cloned()
                .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", req.bucket)))?;
            let expected = current.encode_to_vec();
            let mut new_bucket = current;
            new_bucket.dedup = policy;
            let new_bytes = new_bucket.encode_to_vec();
            (expected, new_bucket, new_bytes)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Buckets,
                    key: req.bucket.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "set-bucket-dedup".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket changed since read; retry"));
                    }
                    other => {
                        error!("unexpected raft response for set_bucket_dedup: {other:?}");
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&req.bucket, &new_bucket);
        }

        self.buckets.write().insert(req.bucket.clone(), new_bucket);
        info!("Set dedup policy for bucket '{}'", req.bucket);
        Ok(Response::new(
            objectio_proto::metadata::SetBucketDedupResponse {},
        ))
    }

    pub(crate) async fn get_dedup_policy(
        &self,
        request: Request<objectio_proto::metadata::GetDedupPolicyRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetDedupPolicyResponse>, Status> {
        let req = request.into_inner();
        let cluster = self
            .config
            .read()
            .get(objectio_proto::dedup::CLUSTER_KEY)
            .and_then(|e| objectio_proto::dedup::cluster_from_config(&e.value));
        let (bucket, tenant_name) = if req.bucket.is_empty() {
            (None, String::new())
        } else {
            let buckets = self.buckets.read();
            let b = buckets
                .get(&req.bucket)
                .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", req.bucket)))?;
            (b.dedup, b.tenant.clone())
        };
        let tenant = if req.bucket.is_empty() {
            None
        } else {
            self.tenants.read().get(&tenant_name).and_then(|t| t.dedup)
        };
        let e = objectio_proto::dedup::resolve(
            &req.bucket,
            &tenant_name,
            bucket.as_ref(),
            tenant.as_ref(),
            cluster.as_ref(),
        );
        let mut resp = objectio_proto::metadata::GetDedupPolicyResponse {
            bucket,
            tenant,
            cluster,
            tenant_name,
            effective_domain: e.domain,
            mode_from: e.mode_from.into(),
            scope_from: e.scope_from.into(),
            ..Default::default()
        };
        resp.set_effective_mode(e.mode);
        resp.set_effective_scope(e.scope);
        Ok(Response::new(resp))
    }

    pub(crate) async fn set_bucket_owner(
        &self,
        request: Request<SetBucketOwnerRequest>,
    ) -> Result<Response<SetBucketOwnerResponse>, Status> {
        let req = request.into_inner();
        if req.owner.is_empty() {
            return Err(Status::invalid_argument("owner must not be empty"));
        }

        let (expected_bytes, new_bucket, new_bytes) = {
            let buckets = self.buckets.read();
            let current = buckets
                .get(&req.bucket)
                .cloned()
                .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", req.bucket)))?;
            let expected = current.encode_to_vec();
            let mut new_bucket = current;
            new_bucket.owner = req.owner.clone();
            let new_bytes = new_bucket.encode_to_vec();
            (expected, new_bucket, new_bytes)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Buckets,
                    key: req.bucket.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "set-bucket-owner".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket changed since read; retry"));
                    }
                    other => {
                        error!("unexpected raft response for set_bucket_owner: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&req.bucket, &new_bucket);
        }

        self.buckets.write().insert(req.bucket.clone(), new_bucket);
        info!("Set owner for bucket '{}' to '{}'", req.bucket, req.owner);
        Ok(Response::new(SetBucketOwnerResponse { success: true }))
    }

    pub(crate) async fn set_bucket_quota(
        &self,
        request: Request<SetBucketQuotaRequest>,
    ) -> Result<Response<SetBucketQuotaResponse>, Status> {
        let req = request.into_inner();
        let (expected_bytes, new_bucket, new_bytes) = {
            let buckets = self.buckets.read();
            let current = buckets
                .get(&req.bucket)
                .cloned()
                .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", req.bucket)))?;
            let expected = current.encode_to_vec();
            let mut new_bucket = current;
            new_bucket.quota_bytes = req.quota_bytes;
            new_bucket.quota_objects = req.quota_objects;
            let new_bytes = new_bucket.encode_to_vec();
            (expected, new_bucket, new_bytes)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Buckets,
                    key: req.bucket.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "set-bucket-quota".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket changed since read; retry"));
                    }
                    other => {
                        error!("unexpected raft response for set_bucket_quota: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&req.bucket, &new_bucket);
        }

        self.buckets.write().insert(req.bucket.clone(), new_bucket);
        info!(
            "Set quota of bucket '{}': {} bytes, {} objects (0 = unlimited)",
            req.bucket, req.quota_bytes, req.quota_objects
        );
        Ok(Response::new(SetBucketQuotaResponse {}))
    }

    pub(crate) async fn get_bucket_versioning(
        &self,
        request: Request<GetBucketVersioningRequest>,
    ) -> Result<Response<GetBucketVersioningResponse>, Status> {
        let bucket_name = request.into_inner().bucket;
        let buckets = self.buckets.read();
        let bucket = buckets
            .get(&bucket_name)
            .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", bucket_name)))?;
        Ok(Response::new(GetBucketVersioningResponse {
            state: bucket.versioning,
        }))
    }

    pub(crate) async fn put_object_lock_configuration(
        &self,
        request: Request<PutObjectLockConfigRequest>,
    ) -> Result<Response<PutObjectLockConfigResponse>, Status> {
        let req = request.into_inner();
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("missing object lock configuration"))?;

        // Verify bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found(format!(
                "bucket '{}' not found",
                req.bucket
            )));
        }

        let bytes = config.encode_to_vec();
        let expected = self
            .object_lock_configs
            .read()
            .get(&req.bucket)
            .map(|c| c.encode_to_vec());

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("object_lock_configs".into()),
                    key: req.bucket.clone(),
                    expected,
                    new_value: Some(bytes.clone()),
                }],
                requested_by: "put-object-lock-config".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("object lock config changed; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for put_object_lock_config: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_object_lock_config(&req.bucket, &bytes);
        }

        self.object_lock_configs
            .write()
            .insert(req.bucket.clone(), config);
        info!("Set object lock config for bucket '{}'", req.bucket);
        Ok(Response::new(PutObjectLockConfigResponse { success: true }))
    }

    pub(crate) async fn get_object_lock_configuration(
        &self,
        request: Request<GetObjectLockConfigRequest>,
    ) -> Result<Response<GetObjectLockConfigResponse>, Status> {
        let bucket = request.into_inner().bucket;
        let configs = self.object_lock_configs.read();
        match configs.get(&bucket) {
            Some(config) => Ok(Response::new(GetObjectLockConfigResponse {
                config: Some(*config),
                found: true,
            })),
            None => Ok(Response::new(GetObjectLockConfigResponse {
                config: None,
                found: false,
            })),
        }
    }

    pub(crate) async fn put_bucket_lifecycle(
        &self,
        request: Request<PutBucketLifecycleRequest>,
    ) -> Result<Response<PutBucketLifecycleResponse>, Status> {
        let req = request.into_inner();
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("missing lifecycle configuration"))?;

        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found(format!(
                "bucket '{}' not found",
                req.bucket
            )));
        }

        let bytes = config.encode_to_vec();
        let expected = self
            .lifecycle_configs
            .read()
            .get(&req.bucket)
            .map(|c| c.encode_to_vec());

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("lifecycle_configs".into()),
                    key: req.bucket.clone(),
                    expected,
                    new_value: Some(bytes.clone()),
                }],
                requested_by: "put-bucket-lifecycle".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("lifecycle config changed; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for put_bucket_lifecycle: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_lifecycle_config(&req.bucket, &bytes);
        }

        self.lifecycle_configs
            .write()
            .insert(req.bucket.clone(), config);
        info!(
            "Set lifecycle config for bucket '{}' ({} rules)",
            req.bucket,
            bytes.len()
        );
        Ok(Response::new(PutBucketLifecycleResponse { success: true }))
    }

    pub(crate) async fn get_bucket_lifecycle(
        &self,
        request: Request<GetBucketLifecycleRequest>,
    ) -> Result<Response<GetBucketLifecycleResponse>, Status> {
        let bucket = request.into_inner().bucket;
        let configs = self.lifecycle_configs.read();
        match configs.get(&bucket) {
            Some(config) => Ok(Response::new(GetBucketLifecycleResponse {
                config: Some(config.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetBucketLifecycleResponse {
                config: None,
                found: false,
            })),
        }
    }

    pub(crate) async fn delete_bucket_lifecycle(
        &self,
        request: Request<DeleteBucketLifecycleRequest>,
    ) -> Result<Response<DeleteBucketLifecycleResponse>, Status> {
        let bucket = request.into_inner().bucket;
        let expected = self
            .lifecycle_configs
            .read()
            .get(&bucket)
            .map(|c| c.encode_to_vec());
        if expected.is_none() {
            return Ok(Response::new(DeleteBucketLifecycleResponse {
                success: false,
            }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("lifecycle_configs".into()),
                    key: bucket.clone(),
                    expected,
                    new_value: None,
                }],
                requested_by: "delete-bucket-lifecycle".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("lifecycle changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delete_bucket_lifecycle: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_lifecycle_config(&bucket);
        }

        self.lifecycle_configs.write().remove(&bucket);
        info!("Deleted lifecycle config for bucket '{}'", bucket);
        Ok(Response::new(DeleteBucketLifecycleResponse {
            success: true,
        }))
    }

    pub(crate) async fn put_bucket_encryption(
        &self,
        request: Request<PutBucketEncryptionRequest>,
    ) -> Result<Response<PutBucketEncryptionResponse>, Status> {
        let req = request.into_inner();
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("missing bucket encryption configuration"))?;

        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found(format!(
                "bucket '{}' not found",
                req.bucket
            )));
        }

        let bytes = config.encode_to_vec();
        let expected = self
            .bucket_encryption_configs
            .read()
            .get(&req.bucket)
            .map(|c| c.encode_to_vec());

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("bucket_encryption_configs".into()),
                    key: req.bucket.clone(),
                    expected,
                    new_value: Some(bytes.clone()),
                }],
                requested_by: "put-bucket-encryption".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("encryption config changed; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for put_bucket_encryption: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket_encryption_config(&req.bucket, &bytes);
        }

        self.bucket_encryption_configs
            .write()
            .insert(req.bucket.clone(), config);
        info!("Set bucket encryption config for bucket '{}'", req.bucket);
        Ok(Response::new(PutBucketEncryptionResponse { success: true }))
    }

    pub(crate) async fn get_bucket_encryption(
        &self,
        request: Request<GetBucketEncryptionRequest>,
    ) -> Result<Response<GetBucketEncryptionResponse>, Status> {
        let bucket = request.into_inner().bucket;
        let configs = self.bucket_encryption_configs.read();
        match configs.get(&bucket) {
            Some(config) => Ok(Response::new(GetBucketEncryptionResponse {
                config: Some(config.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetBucketEncryptionResponse {
                config: None,
                found: false,
            })),
        }
    }

    pub(crate) async fn get_bucket_setting(
        &self,
        request: Request<objectio_proto::metadata::GetBucketSettingRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetBucketSettingResponse>, Status> {
        let req = request.into_inner();
        let value = self.store.as_ref().and_then(|s| {
            s.read_named(
                BUCKET_SETTINGS_TABLE,
                &bucket_setting_key(&req.bucket, &req.name),
            )
        });
        Ok(Response::new(
            objectio_proto::metadata::GetBucketSettingResponse {
                found: value.is_some(),
                value: value.unwrap_or_default(),
            },
        ))
    }

    pub(crate) async fn put_bucket_setting(
        &self,
        request: Request<objectio_proto::metadata::PutBucketSettingRequest>,
    ) -> Result<Response<objectio_proto::metadata::PutBucketSettingResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() || req.name.contains('/') {
            return Err(Status::invalid_argument("invalid setting name"));
        }
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }
        let key = bucket_setting_key(&req.bucket, &req.name);
        let current = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(BUCKET_SETTINGS_TABLE, &key));
        let existed = current.is_some();
        if req.delete && !existed {
            return Ok(Response::new(
                objectio_proto::metadata::PutBucketSettingResponse { existed },
            ));
        }
        self.cas_one(
            objectio_meta_store::CasTable::Named(BUCKET_SETTINGS_TABLE.into()),
            &key,
            current,
            (!req.delete).then_some(req.value),
            "put-bucket-setting",
        )
        .await?;
        Ok(Response::new(
            objectio_proto::metadata::PutBucketSettingResponse { existed },
        ))
    }

    pub(crate) async fn delete_bucket_encryption(
        &self,
        request: Request<DeleteBucketEncryptionRequest>,
    ) -> Result<Response<DeleteBucketEncryptionResponse>, Status> {
        let bucket = request.into_inner().bucket;
        let expected = self
            .bucket_encryption_configs
            .read()
            .get(&bucket)
            .map(|c| c.encode_to_vec());
        if expected.is_none() {
            return Ok(Response::new(DeleteBucketEncryptionResponse {
                success: false,
            }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("bucket_encryption_configs".into()),
                    key: bucket.clone(),
                    expected,
                    new_value: None,
                }],
                requested_by: "delete-bucket-encryption".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("encryption config changed; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delete_bucket_encryption: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_bucket_encryption_config(&bucket);
        }

        self.bucket_encryption_configs.write().remove(&bucket);
        info!("Deleted bucket encryption config for bucket '{}'", bucket);
        Ok(Response::new(DeleteBucketEncryptionResponse {
            success: true,
        }))
    }
}
