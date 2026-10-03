//! The Unity Catalog API: catalogs, schemas, tables, functions, volumes, models, their policies.

use super::*;

impl MetaService {
    pub(super) fn apply_unity_catalog_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_catalogs.write();
        match new_value {
            Some(bytes) => match UnityCatalog::decode(bytes) {
                Ok(c) => {
                    m.insert(key.to_string(), c);
                }
                Err(e) => warn!("apply: decode UnityCatalog('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    pub(super) fn apply_unity_schema_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_schemas.write();
        match new_value {
            Some(bytes) => match UnitySchema::decode(bytes) {
                Ok(s) => {
                    m.insert(key.to_string(), s);
                }
                Err(e) => warn!("apply: decode UnitySchema('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    pub(super) fn apply_unity_table_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_tables.write();
        match new_value {
            Some(bytes) => match UnityTable::decode(bytes) {
                Ok(t) => {
                    m.insert(key.to_string(), t);
                }
                Err(e) => warn!("apply: decode UnityTable('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    pub(super) fn apply_unity_function_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_functions.write();
        match new_value {
            Some(bytes) => match UnityFunction::decode(bytes) {
                Ok(f) => {
                    m.insert(key.to_string(), f);
                }
                Err(e) => warn!("apply: decode UnityFunction('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    pub(super) fn apply_unity_volume_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_volumes.write();
        match new_value {
            Some(bytes) => match UnityVolume::decode(bytes) {
                Ok(v) => {
                    m.insert(key.to_string(), v);
                }
                Err(e) => warn!("apply: decode UnityVolume('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    pub(super) fn apply_unity_model_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_models.write();
        match new_value {
            Some(bytes) => match UnityModel::decode(bytes) {
                Ok(m_) => {
                    m.insert(key.to_string(), m_);
                }
                Err(e) => warn!("apply: decode UnityModel('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    pub(super) fn apply_unity_model_version_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_model_versions.write();
        match new_value {
            Some(bytes) => match UnityModelVersion::decode(bytes) {
                Ok(v) => {
                    m.insert(key.to_string(), v);
                }
                Err(e) => warn!("apply: decode UnityModelVersion('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    /// Resolve a Unity function by its three-part dotted name
    /// (`catalog.schema.function`). Used to validate row-filter and
    /// column-mask bindings — we want to reject malformed bindings at
    /// the configuration boundary, not at query time.
    #[allow(clippy::result_large_err)]
    pub(super) fn lookup_unity_function(
        &self,
        full_name: &str,
    ) -> Result<objectio_proto::metadata::UnityFunction, Status> {
        let parts: Vec<&str> = full_name.split('.').collect();
        if parts.len() != 3 {
            return Err(Status::invalid_argument(format!(
                "function name '{full_name}' must be 'catalog.schema.function'"
            )));
        }
        let key = format!("{}\x00{}\x00{}", parts[0], parts[1], parts[2]);
        self.unity_functions
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("function '{full_name}' not found")))
    }

    pub(crate) async fn unity_create_catalog(
        &self,
        request: Request<UnityCreateCatalogRequest>,
    ) -> Result<Response<UnityCreateCatalogResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("catalog name is required"));
        }
        if self.unity_catalogs.read().contains_key(&req.name) {
            return Err(Status::already_exists(format!(
                "unity catalog '{}' already exists",
                req.name
            )));
        }

        let bucket_name = format!("unity-{}", req.name);
        let location = format!("s3://{bucket_name}");
        let now = Self::current_timestamp();

        if self.buckets.read().contains_key(&bucket_name) {
            return Err(Status::already_exists(format!(
                "bucket '{bucket_name}' already exists",
            )));
        }

        let bucket = BucketMeta {
            dedup: None,
            name: bucket_name.clone(),
            owner: if req.owner.is_empty() {
                "system".to_string()
            } else {
                req.owner.clone()
            },
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

        let catalog = UnityCatalog {
            name: req.name.clone(),
            comment: req.comment,
            owner: req.owner,
            bucket: bucket_name.clone(),
            location,
            created_at: now,
            updated_at: now,
            properties: req.properties,
            tenant: req.tenant,
            policy_json: Vec::new(),
        };
        let catalog_bytes = catalog.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![
                    CasOp {
                        table: CasTable::UnityCatalogs,
                        key: req.name.clone(),
                        expected: None,
                        new_value: Some(catalog_bytes),
                    },
                    CasOp {
                        table: CasTable::Buckets,
                        key: bucket_name.clone(),
                        expected: None,
                        new_value: Some(bucket_bytes),
                    },
                ],
                requested_by: "unity-create-catalog".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::already_exists(format!(
                            "unity catalog or backing bucket already exists (conflicts at {failed_indices:?})"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for unity_create_catalog: {other:?}");
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&bucket_name, &bucket);
            store.put_unity_catalog(&req.name, &catalog.encode_to_vec());
        }

        self.buckets
            .write()
            .insert(bucket_name.clone(), bucket.clone());
        self.unity_catalogs
            .write()
            .insert(req.name.clone(), catalog.clone());

        info!(
            "Created unity catalog: {} (bucket: {})",
            req.name, catalog.bucket
        );
        Ok(Response::new(UnityCreateCatalogResponse {
            catalog: Some(catalog),
        }))
    }

    pub(crate) async fn unity_list_catalogs(
        &self,
        request: Request<UnityListCatalogsRequest>,
    ) -> Result<Response<UnityListCatalogsResponse>, Status> {
        let req = request.into_inner();
        let catalogs: Vec<UnityCatalog> = self
            .unity_catalogs
            .read()
            .values()
            .filter(|c| req.tenant.is_empty() || c.tenant == req.tenant)
            .cloned()
            .collect();
        Ok(Response::new(UnityListCatalogsResponse {
            catalogs,
            next_page_token: String::new(),
        }))
    }

    pub(crate) async fn unity_get_catalog(
        &self,
        request: Request<UnityGetCatalogRequest>,
    ) -> Result<Response<UnityGetCatalogResponse>, Status> {
        let name = request.into_inner().name;
        let catalog = self
            .unity_catalogs
            .read()
            .get(&name)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("unity catalog '{name}' not found")))?;
        Ok(Response::new(UnityGetCatalogResponse {
            catalog: Some(catalog),
        }))
    }

    pub(crate) async fn unity_update_catalog(
        &self,
        request: Request<UnityUpdateCatalogRequest>,
    ) -> Result<Response<UnityUpdateCatalogResponse>, Status> {
        let req = request.into_inner();
        let (mut updated, prev_bytes) = {
            let map = self.unity_catalogs.read();
            let prev = map.get(&req.name).cloned().ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.name))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        if !req.new_comment.is_empty() {
            updated.comment = req.new_comment;
        }
        if !req.new_owner.is_empty() {
            updated.owner = req.new_owner;
        }
        if !req.properties.is_empty() {
            updated.properties = req.properties;
        }
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::UnityCatalogs,
                    key: req.name.clone(),
                    expected: Some(prev_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "unity-update-catalog".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("catalog changed since read; retry update"));
                    }
                    other => {
                        error!("unexpected raft response for unity_update_catalog: {other:?}");
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_unity_catalog(&req.name, &updated.encode_to_vec());
        }

        self.unity_catalogs
            .write()
            .insert(req.name.clone(), updated.clone());
        Ok(Response::new(UnityUpdateCatalogResponse {
            catalog: Some(updated),
        }))
    }

    pub(crate) async fn unity_delete_catalog(
        &self,
        request: Request<UnityDeleteCatalogRequest>,
    ) -> Result<Response<UnityDeleteCatalogResponse>, Status> {
        let req = request.into_inner();
        let prefix = format!("{}\x00", req.name);

        let (catalog, catalog_bytes, bucket_bytes) = {
            let map = self.unity_catalogs.read();
            let catalog = map.get(&req.name).cloned().ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.name))
            })?;
            let catalog_bytes = catalog.encode_to_vec();
            let bucket_bytes = self
                .buckets
                .read()
                .get(&catalog.bucket)
                .map(prost::Message::encode_to_vec);
            (catalog, catalog_bytes, bucket_bytes)
        };

        if !req.force {
            // Refuse if any schema or table still references this catalog.
            let has_schema = self
                .unity_schemas
                .read()
                .keys()
                .any(|k| k.starts_with(&prefix));
            if has_schema {
                return Err(Status::failed_precondition(format!(
                    "catalog '{}' is not empty (schemas exist); pass force=true to drop anyway",
                    req.name
                )));
            }
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::UnityCatalogs,
                key: req.name.clone(),
                expected: Some(catalog_bytes),
                new_value: None,
            }];
            if let Some(bucket_bytes) = bucket_bytes {
                ops.push(CasOp {
                    table: CasTable::Buckets,
                    key: catalog.bucket.clone(),
                    expected: Some(bucket_bytes),
                    new_value: None,
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "unity-delete-catalog".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted(
                            "catalog or bucket changed since read; retry delete",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for unity_delete_catalog: {other:?}");
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_unity_catalog(&req.name);
            store.delete_bucket(&catalog.bucket);
        }

        // If forced, also evict any orphaned schema/table cache entries —
        // the redb rows are leaked here, but that's acceptable for a
        // force-drop and matches Iceberg's behavior.
        if req.force {
            let dropped_schemas: Vec<String> = self
                .unity_schemas
                .read()
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            for k in dropped_schemas {
                self.unity_schemas.write().remove(&k);
            }
            let dropped_tables: Vec<String> = self
                .unity_tables
                .read()
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            for k in dropped_tables {
                self.unity_tables.write().remove(&k);
            }
        }

        self.unity_catalogs.write().remove(&req.name);
        self.buckets.write().remove(&catalog.bucket);

        info!(
            "Deleted unity catalog: {} (bucket: {})",
            req.name, catalog.bucket
        );
        Ok(Response::new(UnityDeleteCatalogResponse { success: true }))
    }

    pub(crate) async fn unity_create_schema(
        &self,
        request: Request<UnityCreateSchemaRequest>,
    ) -> Result<Response<UnityCreateSchemaResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name and schema name are required",
            ));
        }
        if !self.unity_catalogs.read().contains_key(&req.catalog_name) {
            return Err(Status::not_found(format!(
                "unity catalog '{}' not found",
                req.catalog_name
            )));
        }
        let key = format!("{}\x00{}", req.catalog_name, req.name);
        if self.unity_schemas.read().contains_key(&key) {
            return Err(Status::already_exists(format!(
                "unity schema '{}.{}' already exists",
                req.catalog_name, req.name
            )));
        }

        let now = Self::current_timestamp();
        let schema = UnitySchema {
            catalog_name: req.catalog_name,
            name: req.name,
            comment: req.comment,
            owner: req.owner,
            created_at: now,
            updated_at: now,
            properties: req.properties,
            policy_json: Vec::new(),
        };
        let bytes = schema.encode_to_vec();

        cas_single_put(
            self,
            CasTable::UnitySchemas,
            &key,
            None,
            bytes.clone(),
            "unity-create-schema",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_schema(&key, &bytes);
        }
        self.unity_schemas.write().insert(key, schema.clone());
        Ok(Response::new(UnityCreateSchemaResponse {
            schema: Some(schema),
        }))
    }

    pub(crate) async fn unity_list_schemas(
        &self,
        request: Request<UnityListSchemasRequest>,
    ) -> Result<Response<UnityListSchemasResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() {
            return Err(Status::invalid_argument("catalog_name is required"));
        }
        let prefix = format!("{}\x00", req.catalog_name);
        let schemas: Vec<UnitySchema> = self
            .unity_schemas
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(UnityListSchemasResponse {
            schemas,
            next_page_token: String::new(),
        }))
    }

    pub(crate) async fn unity_get_schema(
        &self,
        request: Request<UnityGetSchemaRequest>,
    ) -> Result<Response<UnityGetSchemaResponse>, Status> {
        let req = request.into_inner();
        let key = format!("{}\x00{}", req.catalog_name, req.name);
        let schema = self
            .unity_schemas
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity schema '{}.{}' not found",
                    req.catalog_name, req.name
                ))
            })?;
        Ok(Response::new(UnityGetSchemaResponse {
            schema: Some(schema),
        }))
    }

    pub(crate) async fn unity_update_schema(
        &self,
        request: Request<UnityUpdateSchemaRequest>,
    ) -> Result<Response<UnityUpdateSchemaResponse>, Status> {
        let req = request.into_inner();
        let key = format!("{}\x00{}", req.catalog_name, req.name);
        let (mut updated, prev_bytes) = {
            let map = self.unity_schemas.read();
            let prev = map.get(&key).cloned().ok_or_else(|| {
                Status::not_found(format!(
                    "unity schema '{}.{}' not found",
                    req.catalog_name, req.name
                ))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        if !req.new_comment.is_empty() {
            updated.comment = req.new_comment;
        }
        if !req.new_owner.is_empty() {
            updated.owner = req.new_owner;
        }
        if !req.properties.is_empty() {
            updated.properties = req.properties;
        }
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();

        cas_single_put(
            self,
            CasTable::UnitySchemas,
            &key,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-update-schema",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_schema(&key, &new_bytes);
        }
        self.unity_schemas.write().insert(key, updated.clone());
        Ok(Response::new(UnityUpdateSchemaResponse {
            schema: Some(updated),
        }))
    }

    pub(crate) async fn unity_delete_schema(
        &self,
        request: Request<UnityDeleteSchemaRequest>,
    ) -> Result<Response<UnityDeleteSchemaResponse>, Status> {
        let req = request.into_inner();
        let key = format!("{}\x00{}", req.catalog_name, req.name);
        let prev_bytes = {
            let map = self.unity_schemas.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity schema '{}.{}' not found",
                        req.catalog_name, req.name
                    ))
                })?
        };

        if !req.force {
            let table_prefix = format!("{key}\x00");
            let has_table = self
                .unity_tables
                .read()
                .keys()
                .any(|k| k.starts_with(&table_prefix));
            if has_table {
                return Err(Status::failed_precondition(format!(
                    "schema '{}.{}' is not empty (tables exist); pass force=true to drop anyway",
                    req.catalog_name, req.name
                )));
            }
        }

        cas_single_delete(
            self,
            CasTable::UnitySchemas,
            &key,
            prev_bytes,
            "unity-delete-schema",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_schema(&key);
        }
        self.unity_schemas.write().remove(&key);

        if req.force {
            let table_prefix = format!("{key}\x00");
            let dropped_tables: Vec<String> = self
                .unity_tables
                .read()
                .keys()
                .filter(|k| k.starts_with(&table_prefix))
                .cloned()
                .collect();
            for k in dropped_tables {
                self.unity_tables.write().remove(&k);
            }
        }

        Ok(Response::new(UnityDeleteSchemaResponse { success: true }))
    }

    pub(crate) async fn unity_create_table(
        &self,
        request: Request<UnityCreateTableRequest>,
    ) -> Result<Response<UnityCreateTableResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and table name are required",
            ));
        }
        let schema_key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        let catalog = self
            .unity_catalogs
            .read()
            .get(&req.catalog_name)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.catalog_name))
            })?;
        if !self.unity_schemas.read().contains_key(&schema_key) {
            return Err(Status::not_found(format!(
                "unity schema '{}.{}' not found",
                req.catalog_name, req.schema_name
            )));
        }
        let key = format!("{schema_key}\x00{}", req.name);
        if self.unity_tables.read().contains_key(&key) {
            return Err(Status::already_exists(format!(
                "unity table '{}.{}.{}' already exists",
                req.catalog_name, req.schema_name, req.name
            )));
        }

        // Default table_type=MANAGED, data_source_format=DELTA when omitted.
        let table_type = if req.table_type.is_empty() {
            "MANAGED".to_string()
        } else {
            req.table_type
        };
        let data_source_format = if req.data_source_format.is_empty() {
            "DELTA".to_string()
        } else {
            req.data_source_format
        };

        // MANAGED tables auto-derive their location under the catalog's bucket.
        // EXTERNAL tables require the caller to supply a storage_location.
        let storage_location = match table_type.as_str() {
            "MANAGED" => format!(
                "{}/{}/{}/",
                catalog.location.trim_end_matches('/'),
                req.schema_name,
                req.name,
            ),
            "EXTERNAL" => {
                if req.storage_location.is_empty() {
                    return Err(Status::invalid_argument(
                        "EXTERNAL tables require a storage_location",
                    ));
                }
                req.storage_location
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported table_type '{other}' (allowed: MANAGED, EXTERNAL)",
                )));
            }
        };

        let now = Self::current_timestamp();
        let table = UnityTable {
            catalog_name: req.catalog_name,
            schema_name: req.schema_name,
            name: req.name,
            table_id: Uuid::new_v4().to_string(),
            table_type,
            data_source_format,
            storage_location,
            columns_json: req.columns_json,
            owner: req.owner,
            created_at: now,
            updated_at: now,
            properties: req.properties,
            policy_json: Vec::new(),
            row_filter: None,
            column_masks: std::collections::HashMap::new(),
        };
        let bytes = table.encode_to_vec();

        cas_single_put(
            self,
            CasTable::UnityTables,
            &key,
            None,
            bytes.clone(),
            "unity-create-table",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_table(&key, &bytes);
        }
        self.unity_tables.write().insert(key, table.clone());
        Ok(Response::new(UnityCreateTableResponse {
            table: Some(table),
        }))
    }

    pub(crate) async fn unity_list_tables(
        &self,
        request: Request<UnityListTablesRequest>,
    ) -> Result<Response<UnityListTablesResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name and schema_name are required",
            ));
        }
        let prefix = format!("{}\x00{}\x00", req.catalog_name, req.schema_name);
        let tables: Vec<UnityTable> = self
            .unity_tables
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(UnityListTablesResponse {
            tables,
            next_page_token: String::new(),
        }))
    }

    pub(crate) async fn unity_get_table(
        &self,
        request: Request<UnityGetTableRequest>,
    ) -> Result<Response<UnityGetTableResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let table = self.unity_tables.read().get(&key).cloned().ok_or_else(|| {
            Status::not_found(format!(
                "unity table '{}.{}.{}' not found",
                req.catalog_name, req.schema_name, req.name
            ))
        })?;
        Ok(Response::new(UnityGetTableResponse { table: Some(table) }))
    }

    pub(crate) async fn unity_delete_table(
        &self,
        request: Request<UnityDeleteTableRequest>,
    ) -> Result<Response<UnityDeleteTableResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let prev_bytes = {
            let map = self.unity_tables.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity table '{}.{}.{}' not found",
                        req.catalog_name, req.schema_name, req.name
                    ))
                })?
        };
        cas_single_delete(
            self,
            CasTable::UnityTables,
            &key,
            prev_bytes,
            "unity-delete-table",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_table(&key);
        }
        self.unity_tables.write().remove(&key);
        Ok(Response::new(UnityDeleteTableResponse { success: true }))
    }

    pub(crate) async fn unity_create_function(
        &self,
        request: Request<UnityCreateFunctionRequest>,
    ) -> Result<Response<UnityCreateFunctionResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and function name are required",
            ));
        }
        if req.routine_definition.is_empty() {
            return Err(Status::invalid_argument("routine_definition is required"));
        }
        let schema_key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        if !self.unity_catalogs.read().contains_key(&req.catalog_name) {
            return Err(Status::not_found(format!(
                "unity catalog '{}' not found",
                req.catalog_name
            )));
        }
        if !self.unity_schemas.read().contains_key(&schema_key) {
            return Err(Status::not_found(format!(
                "unity schema '{}.{}' not found",
                req.catalog_name, req.schema_name
            )));
        }
        let key = format!("{schema_key}\x00{}", req.name);
        if self.unity_functions.read().contains_key(&key) {
            return Err(Status::already_exists(format!(
                "unity function '{}.{}.{}' already exists",
                req.catalog_name, req.schema_name, req.name
            )));
        }
        // routine_body is the dispatch flag per Databricks spec — default
        // SQL when omitted. EXTERNAL needs an external_language to be
        // executable downstream; we don't enforce that here (callers may
        // legitimately register placeholder functions).
        let routine_body = if req.routine_body.is_empty() {
            "SQL".to_string()
        } else {
            req.routine_body
        };
        let now = Self::current_timestamp();
        let specific_name = if req.specific_name.is_empty() {
            req.name.clone()
        } else {
            req.specific_name
        };
        let function = UnityFunction {
            catalog_name: req.catalog_name,
            schema_name: req.schema_name,
            name: req.name,
            function_id: Uuid::new_v4().to_string(),
            routine_definition: req.routine_definition,
            routine_body,
            external_language: req.external_language,
            data_type: req.data_type,
            full_data_type: req.full_data_type,
            parameter_style: req.parameter_style,
            is_deterministic: req.is_deterministic,
            sql_data_access: req.sql_data_access,
            is_null_call: req.is_null_call,
            security_type: req.security_type,
            specific_name,
            input_params_json: req.input_params_json,
            return_params_json: req.return_params_json,
            comment: req.comment,
            owner: req.owner,
            created_at: now,
            updated_at: now,
            properties: req.properties,
        };
        let bytes = function.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityFunctions,
            &key,
            None,
            bytes.clone(),
            "unity-create-function",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_function(&key, &bytes);
        }
        self.unity_functions.write().insert(key, function.clone());
        Ok(Response::new(UnityCreateFunctionResponse {
            function: Some(function),
        }))
    }

    pub(crate) async fn unity_list_functions(
        &self,
        request: Request<UnityListFunctionsRequest>,
    ) -> Result<Response<UnityListFunctionsResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name and schema_name are required",
            ));
        }
        let prefix = format!("{}\x00{}\x00", req.catalog_name, req.schema_name);
        let functions: Vec<UnityFunction> = self
            .unity_functions
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(UnityListFunctionsResponse {
            functions,
            next_page_token: String::new(),
        }))
    }

    pub(crate) async fn unity_get_function(
        &self,
        request: Request<UnityGetFunctionRequest>,
    ) -> Result<Response<UnityGetFunctionResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let function = self
            .unity_functions
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity function '{}.{}.{}' not found",
                    req.catalog_name, req.schema_name, req.name
                ))
            })?;
        Ok(Response::new(UnityGetFunctionResponse {
            function: Some(function),
        }))
    }

    pub(crate) async fn unity_delete_function(
        &self,
        request: Request<UnityDeleteFunctionRequest>,
    ) -> Result<Response<UnityDeleteFunctionResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let prev_bytes = {
            let map = self.unity_functions.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity function '{}.{}.{}' not found",
                        req.catalog_name, req.schema_name, req.name
                    ))
                })?
        };
        cas_single_delete(
            self,
            CasTable::UnityFunctions,
            &key,
            prev_bytes,
            "unity-delete-function",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_function(&key);
        }
        self.unity_functions.write().remove(&key);
        Ok(Response::new(UnityDeleteFunctionResponse { success: true }))
    }

    pub(crate) async fn unity_create_volume(
        &self,
        request: Request<UnityCreateVolumeRequest>,
    ) -> Result<Response<UnityCreateVolumeResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and volume name are required",
            ));
        }
        let schema_key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        let catalog = self
            .unity_catalogs
            .read()
            .get(&req.catalog_name)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.catalog_name))
            })?;
        if !self.unity_schemas.read().contains_key(&schema_key) {
            return Err(Status::not_found(format!(
                "unity schema '{}.{}' not found",
                req.catalog_name, req.schema_name
            )));
        }
        let key = format!("{schema_key}\x00{}", req.name);
        if self.unity_volumes.read().contains_key(&key) {
            return Err(Status::already_exists(format!(
                "unity volume '{}.{}.{}' already exists",
                req.catalog_name, req.schema_name, req.name
            )));
        }
        let volume_type = if req.volume_type.is_empty() {
            "MANAGED".to_string()
        } else {
            req.volume_type
        };
        let storage_location = match volume_type.as_str() {
            "MANAGED" => format!(
                "{}/{}/__volumes/{}/",
                catalog.location.trim_end_matches('/'),
                req.schema_name,
                req.name,
            ),
            "EXTERNAL" => {
                if req.storage_location.is_empty() {
                    return Err(Status::invalid_argument(
                        "EXTERNAL volumes require a storage_location",
                    ));
                }
                req.storage_location
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported volume_type '{other}' (allowed: MANAGED, EXTERNAL)",
                )));
            }
        };
        let now = Self::current_timestamp();
        let volume = UnityVolume {
            catalog_name: req.catalog_name,
            schema_name: req.schema_name,
            name: req.name,
            volume_id: Uuid::new_v4().to_string(),
            volume_type,
            storage_location,
            comment: req.comment,
            owner: req.owner,
            created_at: now,
            updated_at: now,
            properties: req.properties,
        };
        let bytes = volume.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityVolumes,
            &key,
            None,
            bytes.clone(),
            "unity-create-volume",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_volume(&key, &bytes);
        }
        self.unity_volumes.write().insert(key, volume.clone());
        Ok(Response::new(UnityCreateVolumeResponse {
            volume: Some(volume),
        }))
    }

    pub(crate) async fn unity_list_volumes(
        &self,
        request: Request<UnityListVolumesRequest>,
    ) -> Result<Response<UnityListVolumesResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name and schema_name are required",
            ));
        }
        let prefix = format!("{}\x00{}\x00", req.catalog_name, req.schema_name);
        let volumes: Vec<UnityVolume> = self
            .unity_volumes
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(UnityListVolumesResponse {
            volumes,
            next_page_token: String::new(),
        }))
    }

    pub(crate) async fn unity_get_volume(
        &self,
        request: Request<UnityGetVolumeRequest>,
    ) -> Result<Response<UnityGetVolumeResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let volume = self
            .unity_volumes
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity volume '{}.{}.{}' not found",
                    req.catalog_name, req.schema_name, req.name
                ))
            })?;
        Ok(Response::new(UnityGetVolumeResponse {
            volume: Some(volume),
        }))
    }

    pub(crate) async fn unity_delete_volume(
        &self,
        request: Request<UnityDeleteVolumeRequest>,
    ) -> Result<Response<UnityDeleteVolumeResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let prev_bytes = {
            let map = self.unity_volumes.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity volume '{}.{}.{}' not found",
                        req.catalog_name, req.schema_name, req.name
                    ))
                })?
        };
        cas_single_delete(
            self,
            CasTable::UnityVolumes,
            &key,
            prev_bytes,
            "unity-delete-volume",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_volume(&key);
        }
        self.unity_volumes.write().remove(&key);
        Ok(Response::new(UnityDeleteVolumeResponse { success: true }))
    }

    pub(crate) async fn unity_create_model(
        &self,
        request: Request<UnityCreateModelRequest>,
    ) -> Result<Response<UnityCreateModelResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and model name are required",
            ));
        }
        let schema_key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        let catalog = self
            .unity_catalogs
            .read()
            .get(&req.catalog_name)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.catalog_name))
            })?;
        if !self.unity_schemas.read().contains_key(&schema_key) {
            return Err(Status::not_found(format!(
                "unity schema '{}.{}' not found",
                req.catalog_name, req.schema_name
            )));
        }
        let key = format!("{schema_key}\x00{}", req.name);
        if self.unity_models.read().contains_key(&key) {
            return Err(Status::already_exists(format!(
                "unity model '{}.{}.{}' already exists",
                req.catalog_name, req.schema_name, req.name
            )));
        }
        // Empty storage_location → server-derive a managed location under
        // the catalog bucket. Otherwise honor the caller-supplied URI.
        let storage_location = if req.storage_location.is_empty() {
            format!(
                "{}/{}/__models/{}/",
                catalog.location.trim_end_matches('/'),
                req.schema_name,
                req.name,
            )
        } else {
            req.storage_location
        };
        let now = Self::current_timestamp();
        let model = UnityModel {
            catalog_name: req.catalog_name,
            schema_name: req.schema_name,
            name: req.name,
            model_id: Uuid::new_v4().to_string(),
            storage_location,
            comment: req.comment,
            owner: req.owner,
            created_at: now,
            updated_at: now,
            properties: req.properties,
        };
        let bytes = model.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityModels,
            &key,
            None,
            bytes.clone(),
            "unity-create-model",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_model(&key, &bytes);
        }
        self.unity_models.write().insert(key, model.clone());
        Ok(Response::new(UnityCreateModelResponse {
            model: Some(model),
        }))
    }

    pub(crate) async fn unity_list_models(
        &self,
        request: Request<UnityListModelsRequest>,
    ) -> Result<Response<UnityListModelsResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name and schema_name are required",
            ));
        }
        let prefix = format!("{}\x00{}\x00", req.catalog_name, req.schema_name);
        let models: Vec<UnityModel> = self
            .unity_models
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(UnityListModelsResponse {
            models,
            next_page_token: String::new(),
        }))
    }

    pub(crate) async fn unity_get_model(
        &self,
        request: Request<UnityGetModelRequest>,
    ) -> Result<Response<UnityGetModelResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let model = self.unity_models.read().get(&key).cloned().ok_or_else(|| {
            Status::not_found(format!(
                "unity model '{}.{}.{}' not found",
                req.catalog_name, req.schema_name, req.name
            ))
        })?;
        Ok(Response::new(UnityGetModelResponse { model: Some(model) }))
    }

    pub(crate) async fn unity_delete_model(
        &self,
        request: Request<UnityDeleteModelRequest>,
    ) -> Result<Response<UnityDeleteModelResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let prev_bytes = {
            let map = self.unity_models.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity model '{}.{}.{}' not found",
                        req.catalog_name, req.schema_name, req.name
                    ))
                })?
        };
        // Cascade: drop every version belonging to this model. Versions
        // live under their own table, keyed by `{catalog}\x00{schema}\x00{model}\x00{version_u32_be}`.
        let version_prefix = format!(
            "{}\x00{}\x00{}\x00",
            req.catalog_name, req.schema_name, req.name
        );
        let dropped_versions: Vec<(String, Vec<u8>)> = self
            .unity_model_versions
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&version_prefix))
            .map(|(k, v)| (k.clone(), v.encode_to_vec()))
            .collect();
        for (vkey, vbytes) in &dropped_versions {
            cas_single_delete(
                self,
                CasTable::UnityModelVersions,
                vkey,
                vbytes.clone(),
                "unity-delete-model-cascade",
            )
            .await?;
            if self.raft_handle().is_none()
                && let Some(store) = &self.store
            {
                store.delete_unity_model_version(vkey);
            }
        }
        cas_single_delete(
            self,
            CasTable::UnityModels,
            &key,
            prev_bytes,
            "unity-delete-model",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_model(&key);
        }
        {
            let mut versions = self.unity_model_versions.write();
            for (vkey, _) in &dropped_versions {
                versions.remove(vkey);
            }
        }
        self.unity_models.write().remove(&key);
        Ok(Response::new(UnityDeleteModelResponse { success: true }))
    }

    pub(crate) async fn unity_create_model_version(
        &self,
        request: Request<UnityCreateModelVersionRequest>,
    ) -> Result<Response<UnityCreateModelVersionResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.model_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and model_name are required",
            ));
        }
        let model_key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.model_name
        );
        if !self.unity_models.read().contains_key(&model_key) {
            return Err(Status::not_found(format!(
                "unity model '{}.{}.{}' not found",
                req.catalog_name, req.schema_name, req.model_name
            )));
        }
        // Compute the next version number under this model. Versions
        // are 1-indexed and monotonic; gaps from prior deletes are not
        // reused (mirrors MLflow semantics).
        let prefix = format!(
            "{}\x00{}\x00{}\x00",
            req.catalog_name, req.schema_name, req.model_name
        );
        let next_version: u32 = {
            let map = self.unity_model_versions.read();
            map.iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v.version)
                .max()
                .map_or(1, |m| m + 1)
        };
        let key = format!("{prefix}{next_version:010}");
        let now = Self::current_timestamp();
        let version = UnityModelVersion {
            catalog_name: req.catalog_name,
            schema_name: req.schema_name,
            model_name: req.model_name,
            version: next_version,
            version_id: Uuid::new_v4().to_string(),
            source: req.source,
            run_id: req.run_id,
            status: "PENDING_REGISTRATION".to_string(),
            description: req.description,
            created_at: now,
            updated_at: now,
            properties: req.properties,
        };
        let bytes = version.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityModelVersions,
            &key,
            None,
            bytes.clone(),
            "unity-create-model-version",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_model_version(&key, &bytes);
        }
        self.unity_model_versions
            .write()
            .insert(key, version.clone());
        Ok(Response::new(UnityCreateModelVersionResponse {
            version: Some(version),
        }))
    }

    pub(crate) async fn unity_list_model_versions(
        &self,
        request: Request<UnityListModelVersionsRequest>,
    ) -> Result<Response<UnityListModelVersionsResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.model_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and model_name are required",
            ));
        }
        let prefix = format!(
            "{}\x00{}\x00{}\x00",
            req.catalog_name, req.schema_name, req.model_name
        );
        let mut versions: Vec<UnityModelVersion> = self
            .unity_model_versions
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        versions.sort_by_key(|v| v.version);
        Ok(Response::new(UnityListModelVersionsResponse {
            versions,
            next_page_token: String::new(),
        }))
    }

    pub(crate) async fn unity_get_model_version(
        &self,
        request: Request<UnityGetModelVersionRequest>,
    ) -> Result<Response<UnityGetModelVersionResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}\x00{:010}",
            req.catalog_name, req.schema_name, req.model_name, req.version
        );
        let version = self
            .unity_model_versions
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity model version '{}.{}.{}/v{}' not found",
                    req.catalog_name, req.schema_name, req.model_name, req.version
                ))
            })?;
        Ok(Response::new(UnityGetModelVersionResponse {
            version: Some(version),
        }))
    }

    pub(crate) async fn unity_update_model_version_status(
        &self,
        request: Request<UnityUpdateModelVersionStatusRequest>,
    ) -> Result<Response<UnityUpdateModelVersionStatusResponse>, Status> {
        let req = request.into_inner();
        // Restrict to the documented MLflow lifecycle states; reject
        // arbitrary values to keep callers from inventing new ones that
        // downstream tooling won't recognize.
        match req.new_status.as_str() {
            "PENDING_REGISTRATION" | "READY" | "FAILED_REGISTRATION" => {}
            other => {
                return Err(Status::invalid_argument(format!(
                    "invalid model version status '{other}' (allowed: PENDING_REGISTRATION, READY, FAILED_REGISTRATION)",
                )));
            }
        }
        let key = format!(
            "{}\x00{}\x00{}\x00{:010}",
            req.catalog_name, req.schema_name, req.model_name, req.version
        );
        let (mut updated, prev_bytes) = {
            let map = self.unity_model_versions.read();
            let prev = map.get(&key).cloned().ok_or_else(|| {
                Status::not_found(format!(
                    "unity model version '{}.{}.{}/v{}' not found",
                    req.catalog_name, req.schema_name, req.model_name, req.version
                ))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        updated.status = req.new_status;
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityModelVersions,
            &key,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-update-model-version-status",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_model_version(&key, &new_bytes);
        }
        self.unity_model_versions
            .write()
            .insert(key, updated.clone());
        Ok(Response::new(UnityUpdateModelVersionStatusResponse {
            version: Some(updated),
        }))
    }

    pub(crate) async fn unity_delete_model_version(
        &self,
        request: Request<UnityDeleteModelVersionRequest>,
    ) -> Result<Response<UnityDeleteModelVersionResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}\x00{:010}",
            req.catalog_name, req.schema_name, req.model_name, req.version
        );
        let prev_bytes = {
            let map = self.unity_model_versions.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity model version '{}.{}.{}/v{}' not found",
                        req.catalog_name, req.schema_name, req.model_name, req.version
                    ))
                })?
        };
        cas_single_delete(
            self,
            CasTable::UnityModelVersions,
            &key,
            prev_bytes,
            "unity-delete-model-version",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_model_version(&key);
        }
        self.unity_model_versions.write().remove(&key);
        Ok(Response::new(UnityDeleteModelVersionResponse {
            success: true,
        }))
    }

    pub(crate) async fn unity_set_catalog_policy(
        &self,
        request: Request<UnitySetCatalogPolicyRequest>,
    ) -> Result<Response<UnitySetCatalogPolicyResponse>, Status> {
        let req = request.into_inner();
        let (mut updated, prev_bytes) = {
            let map = self.unity_catalogs.read();
            let prev = map.get(&req.catalog_name).cloned().ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.catalog_name))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        updated.policy_json = req.policy_json;
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityCatalogs,
            &req.catalog_name,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-set-catalog-policy",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_catalog(&req.catalog_name, &new_bytes);
        }
        self.unity_catalogs
            .write()
            .insert(req.catalog_name, updated);
        Ok(Response::new(UnitySetCatalogPolicyResponse {
            success: true,
        }))
    }

    pub(crate) async fn unity_get_catalog_policy(
        &self,
        request: Request<UnityGetCatalogPolicyRequest>,
    ) -> Result<Response<UnityGetCatalogPolicyResponse>, Status> {
        let name = request.into_inner().catalog_name;
        let policy = self
            .unity_catalogs
            .read()
            .get(&name)
            .map(|c| c.policy_json.clone())
            .ok_or_else(|| Status::not_found(format!("unity catalog '{name}' not found")))?;
        Ok(Response::new(UnityGetCatalogPolicyResponse {
            policy_json: policy,
        }))
    }

    pub(crate) async fn unity_set_schema_policy(
        &self,
        request: Request<UnitySetSchemaPolicyRequest>,
    ) -> Result<Response<UnitySetSchemaPolicyResponse>, Status> {
        let req = request.into_inner();
        let key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        let (mut updated, prev_bytes) = {
            let map = self.unity_schemas.read();
            let prev = map.get(&key).cloned().ok_or_else(|| {
                Status::not_found(format!(
                    "unity schema '{}.{}' not found",
                    req.catalog_name, req.schema_name
                ))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        updated.policy_json = req.policy_json;
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnitySchemas,
            &key,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-set-schema-policy",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_schema(&key, &new_bytes);
        }
        self.unity_schemas.write().insert(key, updated);
        Ok(Response::new(UnitySetSchemaPolicyResponse {
            success: true,
        }))
    }

    pub(crate) async fn unity_get_schema_policy(
        &self,
        request: Request<UnityGetSchemaPolicyRequest>,
    ) -> Result<Response<UnityGetSchemaPolicyResponse>, Status> {
        let req = request.into_inner();
        let key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        let policy = self
            .unity_schemas
            .read()
            .get(&key)
            .map(|s| s.policy_json.clone())
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity schema '{}.{}' not found",
                    req.catalog_name, req.schema_name
                ))
            })?;
        Ok(Response::new(UnityGetSchemaPolicyResponse {
            policy_json: policy,
        }))
    }

    pub(crate) async fn unity_set_table_policy(
        &self,
        request: Request<UnitySetTablePolicyRequest>,
    ) -> Result<Response<UnitySetTablePolicyResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.table_name
        );
        let (mut updated, prev_bytes) = {
            let map = self.unity_tables.read();
            let prev = map.get(&key).cloned().ok_or_else(|| {
                Status::not_found(format!(
                    "unity table '{}.{}.{}' not found",
                    req.catalog_name, req.schema_name, req.table_name
                ))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        updated.policy_json = req.policy_json;
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityTables,
            &key,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-set-table-policy",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_table(&key, &new_bytes);
        }
        self.unity_tables.write().insert(key, updated);
        Ok(Response::new(UnitySetTablePolicyResponse { success: true }))
    }

    pub(crate) async fn unity_set_table_security(
        &self,
        request: Request<UnitySetTableSecurityRequest>,
    ) -> Result<Response<UnitySetTableSecurityResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let (mut updated, prev_bytes) = {
            let map = self.unity_tables.read();
            let prev = map.get(&key).cloned().ok_or_else(|| {
                Status::not_found(format!(
                    "unity table '{}.{}.{}' not found",
                    req.catalog_name, req.schema_name, req.name
                ))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };

        // Validate row filter binding (if any) — referenced function must
        // exist and return BOOLEAN. Engines that consume our metadata trust
        // this, so we reject misconfigured bindings here rather than at
        // query time.
        if let Some(rf) = &req.row_filter
            && !rf.function_full_name.is_empty()
        {
            let f = self.lookup_unity_function(&rf.function_full_name)?;
            if !f.data_type.eq_ignore_ascii_case("BOOLEAN")
                && !f.data_type.eq_ignore_ascii_case("BOOL")
            {
                return Err(Status::invalid_argument(format!(
                    "row filter function '{}' returns {} — must return BOOLEAN",
                    rf.function_full_name, f.data_type
                )));
            }
        }
        // Column mask validation: just confirm the function exists. Type
        // matching against the column is more involved (columns_json is a
        // free-form blob); engines reject the mismatch at runtime.
        for (col, mask) in &req.column_masks {
            if mask.function_full_name.is_empty() {
                return Err(Status::invalid_argument(format!(
                    "column mask for '{col}' has empty function_full_name"
                )));
            }
            self.lookup_unity_function(&mask.function_full_name)?;
        }

        updated.row_filter = req.row_filter;
        updated.column_masks = req.column_masks;
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityTables,
            &key,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-set-table-security",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_table(&key, &new_bytes);
        }
        self.unity_tables.write().insert(key, updated.clone());
        Ok(Response::new(UnitySetTableSecurityResponse {
            table: Some(updated),
        }))
    }

    pub(crate) async fn unity_get_table_policy(
        &self,
        request: Request<UnityGetTablePolicyRequest>,
    ) -> Result<Response<UnityGetTablePolicyResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.table_name
        );
        let policy = self
            .unity_tables
            .read()
            .get(&key)
            .map(|t| t.policy_json.clone())
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity table '{}.{}.{}' not found",
                    req.catalog_name, req.schema_name, req.table_name
                ))
            })?;
        Ok(Response::new(UnityGetTablePolicyResponse {
            policy_json: policy,
        }))
    }
}
