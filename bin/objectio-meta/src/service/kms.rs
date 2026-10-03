//! KMS keys for SSE-KMS.

use super::*;

impl MetaService {
    /// Mirror a replicated KMS key into this node's cache.
    pub(super) fn apply_kms_key_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        match new_value {
            Some(bytes) => match objectio_proto::metadata::KmsKey::decode(bytes) {
                Ok(k) => {
                    self.kms_keys.write().insert(key.to_string(), k);
                }
                Err(e) => warn!("apply: decode KmsKey('{key}') failed: {e}"),
            },
            None => {
                self.kms_keys.write().remove(key);
            }
        }
    }

    /// Generate a short stable id for a new KMS key: `kms-<first 12 hex of UUID>`.
    pub(super) fn generate_kms_key_id() -> String {
        let uuid = Uuid::new_v4().simple().to_string();
        format!("kms-{}", &uuid[..12])
    }

    pub(crate) async fn create_kms_key(
        &self,
        request: Request<CreateKmsKeyRequest>,
    ) -> Result<Response<CreateKmsKeyResponse>, Status> {
        let req = request.into_inner();
        if req.wrapped_key_material.is_empty() {
            return Err(Status::invalid_argument(
                "wrapped_key_material is required — gateway wraps the raw key before sending",
            ));
        }
        let key_id = if req.key_id.trim().is_empty() {
            Self::generate_kms_key_id()
        } else {
            req.key_id.trim().to_string()
        };
        let now = Self::current_timestamp();
        if self.kms_keys.read().contains_key(&key_id) {
            return Err(Status::already_exists(format!(
                "KMS key '{key_id}' already exists"
            )));
        }
        let key = KmsKey {
            key_id: key_id.clone(),
            arn: format!("arn:obio:kms:::{key_id}"),
            description: req.description,
            wrapped_key_material: req.wrapped_key_material,
            status: 0, // KMS_KEY_ENABLED
            created_at: now,
            updated_at: now,
            created_by: req.created_by,
        };
        // Through Raft: a key only the old leader held would leave every
        // object encrypted under it unreadable after a failover. Created
        // only if no key has the id (compare-and-set against nothing).
        if self.raft_handle().is_some() {
            let created = self
                .cas_many(
                    vec![objectio_meta_store::CasOp {
                        table: CasTable::Named(KMS_KEYS_TABLE.into()),
                        key: key_id.clone(),
                        expected: None,
                        new_value: Some(key.encode_to_vec()),
                    }],
                    "create-kms-key",
                )
                .await?;
            if !created {
                return Err(Status::already_exists(format!(
                    "KMS key '{key_id}' already exists"
                )));
            }
        } else if let Some(store) = &self.store {
            store.put_kms_key(&key_id, &key.encode_to_vec());
        }
        self.kms_keys.write().insert(key_id.clone(), key.clone());
        info!("Created KMS key '{key_id}'");
        Ok(Response::new(CreateKmsKeyResponse { key: Some(key) }))
    }

    pub(crate) async fn get_kms_key(
        &self,
        request: Request<GetKmsKeyRequest>,
    ) -> Result<Response<GetKmsKeyResponse>, Status> {
        let key_id = request.into_inner().key_id;
        let map = self.kms_keys.read();
        match map.get(&key_id) {
            Some(k) => Ok(Response::new(GetKmsKeyResponse {
                key: Some(k.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetKmsKeyResponse {
                key: None,
                found: false,
            })),
        }
    }

    pub(crate) async fn list_kms_keys(
        &self,
        request: Request<ListKmsKeysRequest>,
    ) -> Result<Response<ListKmsKeysResponse>, Status> {
        let req = request.into_inner();
        let max = if req.max_results == 0 {
            1000
        } else {
            req.max_results as usize
        };
        let map = self.kms_keys.read();
        let mut keys: Vec<KmsKey> = map.values().cloned().collect();
        keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        // Simple pagination: treat page_token as the last key_id returned.
        if !req.page_token.is_empty() {
            keys.retain(|k| k.key_id > req.page_token);
        }
        let next_token = if keys.len() > max {
            keys[max - 1].key_id.clone()
        } else {
            String::new()
        };
        keys.truncate(max);
        Ok(Response::new(ListKmsKeysResponse {
            keys,
            next_page_token: next_token,
        }))
    }

    pub(crate) async fn delete_kms_key(
        &self,
        request: Request<DeleteKmsKeyRequest>,
    ) -> Result<Response<DeleteKmsKeyResponse>, Status> {
        let key_id = request.into_inner().key_id;
        let removed = self.kms_keys.read().contains_key(&key_id);
        if removed {
            self.replicate(
                vec![(KMS_KEYS_TABLE, key_id.clone(), None)],
                "delete-kms-key",
            )
            .await?;
            self.kms_keys.write().remove(&key_id);
            info!("Deleted KMS key '{key_id}'");
        }
        Ok(Response::new(DeleteKmsKeyResponse { success: removed }))
    }
}
