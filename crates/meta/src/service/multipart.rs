//! Multipart uploads.

use super::*;

impl MetaService {
    /// Open multipart uploads as Prometheus gauges. An abandoned upload
    /// holds its parts' space until someone aborts it, so this reports how
    /// many there are, how old, and how many bytes they hold.
    pub fn render_multipart_metrics(&self) -> String {
        use std::fmt::Write as _;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let uploads = self.multipart_uploads.read();
        let open = || uploads.values().filter(|u| u.completed.is_none());
        let ages: Vec<u64> = open().map(|u| now.saturating_sub(u.initiated)).collect();
        let bytes: u64 = open().flat_map(|u| u.parts.values()).map(|p| p.size).sum();
        drop(uploads);

        let mut out = String::new();
        let mut gauge = |name: &str, help: &str, samples: &[(&str, u64)]| {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} gauge");
            for (labels, v) in samples {
                if labels.is_empty() {
                    let _ = writeln!(out, "{name} {v}");
                } else {
                    let _ = writeln!(out, "{name}{{{labels}}} {v}");
                }
            }
        };
        gauge(
            "objectio_multipart_uploads_open",
            "Multipart uploads started and neither completed nor aborted",
            &[("", ages.len() as u64)],
        );
        gauge(
            "objectio_multipart_upload_oldest_age_seconds",
            "Age of the oldest open multipart upload",
            &[("", ages.iter().copied().max().unwrap_or(0))],
        );
        let older = |secs: u64| ages.iter().filter(|a| **a > secs).count() as u64;
        gauge(
            "objectio_multipart_uploads_older_than",
            "Open multipart uploads older than the given age",
            &[
                ("age=\"1h\"", older(3600)),
                ("age=\"1d\"", older(86_400)),
                ("age=\"7d\"", older(604_800)),
            ],
        );
        gauge(
            "objectio_multipart_upload_parts_bytes",
            "Bytes held by parts of open multipart uploads",
            &[("", bytes)],
        );
        out
    }

    /// Read, change and write one multipart upload as a unit: through Raft
    /// as a compare-and-set against the record read (retried when it
    /// changed meanwhile), so every meta node has it and a racing
    /// completion, abort or part upload can't be lost; without Raft, under
    /// the in-memory lock. `change` gets the upload as it stands (`None`:
    /// there is none) and returns what it becomes (`None`: removed) and a
    /// result. It may run more than once.
    pub(super) async fn update_multipart<T>(
        &self,
        upload_id: &str,
        what: &str,
        change: impl Fn(
            Option<MultipartUploadState>,
        ) -> Result<(Option<MultipartUploadState>, T), Status>,
    ) -> Result<T, Status> {
        let store = self.store.as_ref().filter(|_| self.raft_handle().is_some());
        let Some(store) = store else {
            let mut uploads = self.multipart_uploads.write();
            let (new, out) = change(uploads.get(upload_id).cloned())?;
            match &new {
                Some(u) => {
                    uploads.insert(upload_id.to_string(), u.clone());
                }
                None => {
                    uploads.remove(upload_id);
                }
            }
            drop(uploads);
            if let Some(store) = &self.store {
                match &new {
                    Some(u) => store.put_multipart_upload(upload_id, u),
                    None => store.delete_multipart_upload(upload_id),
                }
            }
            return Ok(out);
        };
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let stored = store.read_named(MULTIPART_TABLE, upload_id);
            let current = match &stored {
                Some(bytes) => Some(
                    objectio_meta_store::record::deserialize::<MultipartUploadState>(bytes)
                        .map_err(|e| Status::internal(format!("multipart decode: {e}")))?,
                ),
                None => None,
            };
            let (new, out) = change(current)?;
            let new_bytes = match &new {
                Some(u) => Some(
                    objectio_meta_store::record::serialize(u)
                        .map_err(|e| Status::internal(format!("multipart encode: {e}")))?,
                ),
                None => None,
            };
            if new_bytes == stored {
                return Ok(out);
            }
            let ok = self
                .cas_many(
                    vec![objectio_meta_store::CasOp {
                        table: CasTable::Named(MULTIPART_TABLE.into()),
                        key: upload_id.to_string(),
                        expected: stored,
                        new_value: new_bytes,
                    }],
                    what,
                )
                .await?;
            if ok {
                // The apply listener mirrors it too; this makes it visible
                // to the next call on this node at once.
                match new {
                    Some(u) => {
                        self.multipart_uploads
                            .write()
                            .insert(upload_id.to_string(), u);
                    }
                    None => {
                        self.multipart_uploads.write().remove(upload_id);
                    }
                }
                return Ok(out);
            }
        }
        Err(Status::aborted(format!(
            "{what}: the upload kept changing; retry"
        )))
    }

    /// Mirror a replicated multipart upload into this node's cache.
    pub(super) fn apply_multipart_event(&self, key: &str, new_value: Option<&[u8]>) {
        match new_value {
            Some(bytes) => {
                match objectio_meta_store::record::deserialize::<MultipartUploadState>(bytes) {
                    Ok(u) => {
                        self.multipart_uploads.write().insert(key.to_string(), u);
                    }
                    Err(e) => warn!("apply: decode multipart upload('{key}') failed: {e}"),
                }
            }
            None => {
                self.multipart_uploads.write().remove(key);
            }
        }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) async fn create_multipart_upload(
        &self,
        request: Request<CreateMultipartUploadRequest>,
    ) -> Result<Response<CreateMultipartUploadResponse>, Status> {
        let req = request.into_inner();

        // Check if bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }

        let upload_id = Uuid::new_v4().to_string();
        let now = Self::current_timestamp();

        // Store the multipart upload state
        let state = MultipartUploadState {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            upload_id: upload_id.clone(),
            content_type: req.content_type.clone(),
            user_metadata: req.user_metadata.clone(),
            initiated: now,
            parts: HashMap::new(),
            encryption_algorithm: req.encryption_algorithm,
            kms_key_id: req.kms_key_id.clone(),
            encrypted_dek: req.encrypted_dek.clone(),
            customer_key_md5: req.customer_key_md5.clone(),
            encryption_context: req.encryption_context.clone(),
            completed: None,
        };
        self.update_multipart(&upload_id, "create-multipart", |_| {
            Ok((Some(state.clone()), ()))
        })
        .await?;

        info!(
            "Created multipart upload: bucket={}, key={}, upload_id={}, sse_algo={}",
            req.bucket, req.key, upload_id, req.encryption_algorithm
        );

        Ok(Response::new(CreateMultipartUploadResponse {
            upload_id,
            bucket: req.bucket,
            key: req.key,
            encryption_algorithm: req.encryption_algorithm,
            kms_key_id: req.kms_key_id,
        }))
    }

    pub(crate) async fn get_multipart_upload(
        &self,
        request: Request<GetMultipartUploadRequest>,
    ) -> Result<Response<GetMultipartUploadResponse>, Status> {
        let req = request.into_inner();
        let uploads = self.multipart_uploads.read();
        let Some(upload) = uploads.get(&req.upload_id) else {
            return Ok(Response::new(GetMultipartUploadResponse {
                found: false,
                ..Default::default()
            }));
        };
        if upload.bucket != req.bucket || upload.key != req.key {
            return Ok(Response::new(GetMultipartUploadResponse {
                found: false,
                ..Default::default()
            }));
        }
        Ok(Response::new(GetMultipartUploadResponse {
            found: true,
            content_type: upload.content_type.clone(),
            user_metadata: upload.user_metadata.clone(),
            initiated: upload.initiated,
            encryption_algorithm: upload.encryption_algorithm,
            kms_key_id: upload.kms_key_id.clone(),
            encrypted_dek: upload.encrypted_dek.clone(),
            customer_key_md5: upload.customer_key_md5.clone(),
            encryption_context: upload.encryption_context.clone(),
        }))
    }

    #[allow(clippy::result_large_err)]
    pub(crate) async fn register_part(
        &self,
        request: Request<RegisterPartRequest>,
    ) -> Result<Response<RegisterPartResponse>, Status> {
        let req = request.into_inner();

        // Validate part number (S3 allows 1-10,000)
        if req.part_number == 0 || req.part_number > 10000 {
            return Err(Status::invalid_argument(
                "part number must be between 1 and 10000",
            ));
        }

        let now = Self::current_timestamp();

        // Register the part (overwrites if same part_number uploaded again)
        let (checksum_algorithm, checksum) = req
            .checksum
            .clone()
            .map(|c| (c.algorithm, c.value))
            .unwrap_or_default();
        let part_state = PartState {
            part_number: req.part_number,
            etag: req.etag.clone(),
            size: req.size,
            last_modified: now,
            checksum_algorithm,
            checksum,
            stripes: req.stripes.clone(), // Multiple stripes for large parts
        };
        // The part this replaces is referenced by nothing once the insert
        // lands; hand its stripes back so the gateway can free them.
        let replaced = self
            .update_multipart(&req.upload_id, "register-part", |upload| {
                let mut upload = upload.filter(|u| u.completed.is_none()).ok_or_else(|| {
                    Status::not_found(format!("multipart upload not found: {}", req.upload_id))
                })?;
                if upload.bucket != req.bucket || upload.key != req.key {
                    return Err(Status::invalid_argument(
                        "bucket/key mismatch for upload_id",
                    ));
                }
                let replaced = upload.parts.insert(req.part_number, part_state.clone());
                Ok((Some(upload), replaced))
            })
            .await?;

        debug!(
            "Registered part {} for upload {}: size={}, etag={}",
            req.part_number, req.upload_id, req.size, req.etag
        );

        Ok(Response::new(RegisterPartResponse {
            success: true,
            etag: req.etag,
            replaced_stripes: replaced.map(|p| p.stripes).unwrap_or_default(),
        }))
    }

    pub(crate) async fn list_parts(
        &self,
        request: Request<ListPartsRequest>,
    ) -> Result<Response<ListPartsResponse>, Status> {
        let req = request.into_inner();

        let uploads = self.multipart_uploads.read();
        let upload = uploads.get(&req.upload_id).ok_or_else(|| {
            Status::not_found(format!("multipart upload not found: {}", req.upload_id))
        })?;

        // Verify bucket/key match
        if upload.bucket != req.bucket || upload.key != req.key {
            return Err(Status::invalid_argument(
                "bucket/key mismatch for upload_id",
            ));
        }

        // Get parts sorted by part number, starting after marker
        let max_parts = if req.max_parts == 0 {
            1000
        } else {
            req.max_parts.min(1000)
        };
        let marker = req.part_number_marker;

        let mut parts: Vec<PartMeta> = upload
            .parts
            .values()
            .filter(|p| p.part_number > marker)
            .map(|p| PartMeta {
                part_number: p.part_number,
                etag: p.etag.clone(),
                size: p.size,
                last_modified: p.last_modified,
                stripes: p.stripes.clone(), // Multiple stripes for large parts
                checksum: (!p.checksum.is_empty()).then(|| {
                    objectio_proto::metadata::ObjectChecksum {
                        algorithm: p.checksum_algorithm.clone(),
                        value: p.checksum.clone(),
                    }
                }),
            })
            .collect();

        parts.sort_by_key(|p| p.part_number);

        let is_truncated = parts.len() > max_parts as usize;
        let parts: Vec<PartMeta> = parts.into_iter().take(max_parts as usize).collect();
        let next_marker = parts.last().map(|p| p.part_number).unwrap_or(0);

        Ok(Response::new(ListPartsResponse {
            parts,
            is_truncated,
            next_part_number_marker: next_marker,
            bucket: upload.bucket.clone(),
            key: upload.key.clone(),
            upload_id: upload.upload_id.clone(),
        }))
    }

    /// Complete multipart upload
    /// Validates parts and builds final object metadata with all stripes
    #[allow(clippy::result_large_err)]
    pub(crate) async fn complete_multipart_upload(
        &self,
        request: Request<CompleteMultipartUploadRequest>,
    ) -> Result<Response<CompleteMultipartUploadResponse>, Status> {
        let req = request.into_inner();

        // Validate and complete the upload in one step (a compare-and-set
        // through Raft, or under the lock): a read-then-remove let an
        // abort, or a part re-upload, land in between — the abort freed
        // parts this completion went on to use, and a re-uploaded part was
        // dropped with the upload, unreferenced.
        //
        // The upload is kept, marked completed with its object, until the
        // gateway has committed that object and forgets it. Taken out here,
        // a completion whose answer was lost (a leader change, a timeout),
        // or whose commit then failed, left the parts belonging to nothing:
        // the client's retry found no upload, and its object was gone.
        let keep =
            objectio_common::version::allows(objectio_common::version::COMPLETED_UPLOADS_LEVEL);
        let (object, unused_stripes) = self
            .update_multipart(&req.upload_id, "complete-multipart", |upload| {
                let upload = upload.ok_or_else(|| {
                    Status::not_found(format!("multipart upload not found: {}", req.upload_id))
                })?;
                if let Some(done) = &upload.completed {
                    // Sent again: the same object, for the same parts.
                    let (again, _) = complete_upload(&upload, &req)?;
                    if again.etag != done.etag {
                        return Err(Status::not_found(format!(
                            "multipart upload not found: {}",
                            req.upload_id
                        )));
                    }
                    let done = done.clone();
                    return Ok((Some(upload), (done, Vec::new())));
                }
                let (object, unused) = complete_upload(&upload, &req)?;
                if !keep {
                    return Ok((None, (object, unused)));
                }
                let used: std::collections::HashSet<u32> =
                    req.parts.iter().map(|p| p.part_number).collect();
                let mut kept = upload;
                kept.parts.retain(|n, _| used.contains(n));
                kept.completed = Some(object.clone());
                Ok((Some(kept), (object, unused)))
            })
            .await?;

        info!(
            "Completed multipart upload: bucket={}, key={}, upload_id={}, size={}, parts={}",
            req.bucket,
            req.key,
            req.upload_id,
            object.size,
            req.parts.len()
        );

        Ok(Response::new(CompleteMultipartUploadResponse {
            object: Some(object),
            unused_stripes,
        }))
    }

    #[allow(clippy::result_large_err)]
    pub(crate) async fn abort_multipart_upload(
        &self,
        request: Request<AbortMultipartUploadRequest>,
    ) -> Result<Response<AbortMultipartUploadResponse>, Status> {
        let req = request.into_inner();

        // Remove the upload from state. Only the bucket/key it was started
        // for may abort it: the caller frees every part it held.
        let removed = self
            .update_multipart(&req.upload_id, "abort-multipart", |upload| match upload {
                Some(u) if u.bucket != req.bucket || u.key != req.key => Err(Status::not_found(
                    format!("multipart upload not found: {}", req.upload_id),
                )),
                other => Ok((None, other)),
            })
            .await?;

        if removed.as_ref().is_some_and(|u| u.completed.is_some()) {
            // Completed: forgotten once its object is committed (by the
            // gateway that completed it, or a client's abort after). Its
            // parts are the object's: nothing is freed.
            debug!(
                "Forgot completed multipart upload: bucket={}, key={}, upload_id={}",
                req.bucket, req.key, req.upload_id
            );
            return Err(Status::not_found(format!(
                "multipart upload not found: {}",
                req.upload_id
            )));
        } else if removed.is_some() {
            info!(
                "Aborted multipart upload: bucket={}, key={}, upload_id={}",
                req.bucket, req.key, req.upload_id
            );
        } else {
            debug!(
                "Abort for unknown upload_id={} (may already be completed)",
                req.upload_id
            );
            return Err(Status::not_found(format!(
                "multipart upload not found: {}",
                req.upload_id
            )));
        }

        // The parts' shards are freed by the caller, from the stripes taken
        // out here with the upload: nothing else records where they are.
        let stripes = removed
            .map(|u| u.parts.into_values().flat_map(|p| p.stripes).collect())
            .unwrap_or_default();

        Ok(Response::new(AbortMultipartUploadResponse {
            success: true,
            stripes,
        }))
    }

    pub(crate) async fn list_multipart_uploads(
        &self,
        request: Request<ListMultipartUploadsRequest>,
    ) -> Result<Response<ListMultipartUploadsResponse>, Status> {
        let req = request.into_inner();

        // Check if bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }

        let max_uploads = if req.max_uploads == 0 {
            1000
        } else {
            req.max_uploads.min(1000)
        };

        // Filter and collect uploads for this bucket
        let uploads_lock = self.multipart_uploads.read();
        let mut uploads: Vec<MultipartUpload> = uploads_lock
            .values()
            .filter(|u| u.bucket == req.bucket && u.completed.is_none())
            .filter(|u| req.prefix.is_empty() || u.key.starts_with(&req.prefix))
            .filter(|u| {
                if req.key_marker.is_empty() || u.key > req.key_marker {
                    true
                } else if u.key == req.key_marker && !req.upload_id_marker.is_empty() {
                    u.upload_id > req.upload_id_marker
                } else {
                    false
                }
            })
            .map(|u| MultipartUpload {
                key: u.key.clone(),
                upload_id: u.upload_id.clone(),
                initiated: u.initiated,
                storage_class: "STANDARD".to_string(),
            })
            .collect();

        // Sort by key, then upload_id
        uploads.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then_with(|| a.upload_id.cmp(&b.upload_id))
        });

        let is_truncated = uploads.len() > max_uploads as usize;
        let uploads: Vec<MultipartUpload> =
            uploads.into_iter().take(max_uploads as usize).collect();

        let (next_key_marker, next_upload_id_marker) = uploads
            .last()
            .map(|u| (u.key.clone(), u.upload_id.clone()))
            .unwrap_or_default();

        Ok(Response::new(ListMultipartUploadsResponse {
            uploads,
            next_key_marker,
            next_upload_id_marker,
            is_truncated,
        }))
    }
}
