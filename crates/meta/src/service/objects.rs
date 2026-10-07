//! Objects: listing entries, reads, deletes, and where a key is placed.

use super::*;

impl MetaService {
    /// Snapshot of every registered OSD. Cloned so a caller can make network
    /// calls without holding the lock.
    /// Whether `bucket/key` has a current entry in the listing index.
    pub fn object_listed(&self, bucket: &str, key: &str) -> bool {
        self.store
            .as_ref()
            .and_then(|s| s.read_object_listing(&format!("{bucket}\0{key}\0")))
            .is_some()
    }

    /// DEPRECATED: Object metadata is now stored on primary OSD
    /// This RPC is kept for backward compatibility but does nothing
    /// Register a PUT in the Meta-backed OBJECT_LISTINGS index. Every
    /// S3 PUT that succeeds at the data layer calls this to make the
    /// object visible via ListObjects. Routed through Raft MultiCas so
    /// followers see the commit at the same log position.
    pub(crate) async fn create_object(
        &self,
        request: Request<CreateObjectRequest>,
    ) -> Result<Response<CreateObjectResponse>, Status> {
        let req = request.into_inner();
        if req.bucket.is_empty() || req.key.is_empty() {
            return Err(Status::invalid_argument("bucket and key required"));
        }
        // Never list an object into a bucket that isn't there (deleted
        // meanwhile, or never created).
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found(format!(
                "bucket '{}' not found",
                req.bucket
            )));
        }

        // Build the listing entry. primary_osd_id is optional (the
        // first shard in the first stripe, as a routing hint).
        let primary_osd_id = req
            .stripes
            .first()
            .and_then(|s| s.shards.first())
            .map(|s| s.node_id.clone())
            .unwrap_or_default();
        let now = Self::current_timestamp();
        let entry = ObjectListingEntry {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            size: req.size,
            etag: req.etag.clone(),
            content_type: req.content_type.clone(),
            created_at: now,
            modified_at: now,
            version_id: String::new(),
            is_delete_marker: false,
            storage_class: "STANDARD".into(),
            user_metadata: req.user_metadata.clone(),
            primary_osd_id,
            // Gateway carried these from its GetPlacement call. With
            // pg_id set, ListObjects + GET can resolve osd_ids via a
            // single PG lookup; without, we fall back to the legacy
            // per-object CRUSH path.
            pg_id: req.pg_id,
            pool: req.pool.clone(),
        };
        let listing_key = format!("{}\0{}\0", req.bucket, req.key);
        let new_bytes = entry.encode_to_vec();

        // Idempotent overwrite: PUT on an existing key replaces. Read
        // current (if any) so the MultiCas doesn't spuriously fail.
        let expected_bytes = self
            .store
            .as_ref()
            .and_then(|s| s.read_object_listing(&listing_key));

        // A conditional write is decided here, against the entry the
        // MultiCas below expects: a write that changes it meanwhile makes
        // the MultiCas conflict, so two conditional writers can't both win.
        if !req.if_match.is_empty() || !req.if_none_match.is_empty() {
            let current_etag = expected_bytes
                .as_deref()
                .and_then(|b| ObjectListingEntry::decode(b).ok())
                .map(|e| e.etag.trim_matches('"').to_string());
            let matches = |want: &str| {
                current_etag
                    .as_deref()
                    .is_some_and(|e| want == "*" || e == want.trim_matches('"'))
            };
            if !req.if_match.is_empty() && current_etag.is_none() {
                return Err(Status::failed_precondition("NoSuchKey"));
            }
            if (!req.if_match.is_empty() && !matches(&req.if_match))
                || (!req.if_none_match.is_empty() && matches(&req.if_none_match))
            {
                return Err(Status::failed_precondition("PreconditionFailed"));
            }
        }

        // The key's home, recorded with its listing when it moved (or is
        // new): where the gateway just wrote its ObjectMeta.
        let home_key = format!("{}/{}", req.bucket, req.key);
        let current_home = self
            .store
            .as_ref()
            .and_then(|s| s.read_object_home(&home_key));
        let new_home = (!req.home_osd_ids.is_empty())
            .then(|| {
                ObjectHome {
                    osd_ids: req.home_osd_ids.clone(),
                }
                .encode_to_vec()
            })
            .filter(|h| current_home.as_ref() != Some(h));

        // Written short of shards: recorded in the same command (B29), so
        // repair takes it at once and no crash loses it. A write of the key
        // replaces the record of the object it replaces.
        let current_degraded = self.store.as_ref().and_then(|s| s.read_degraded(&home_key));
        let new_degraded = degraded_record(&req, now);

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::ObjectListings,
                key: listing_key.clone(),
                expected: expected_bytes,
                new_value: Some(new_bytes),
            }];
            if current_degraded.is_some() || new_degraded.is_some() {
                ops.push(CasOp {
                    table: CasTable::Named("degraded_objects".into()),
                    key: home_key.clone(),
                    expected: current_degraded,
                    new_value: new_degraded,
                });
            }
            if let Some(home) = new_home {
                ops.push(CasOp {
                    table: CasTable::Named("object_homes".into()),
                    key: home_key,
                    expected: current_home,
                    new_value: Some(home),
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "create-object".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. }
                        if !req.if_match.is_empty() || !req.if_none_match.is_empty() =>
                    {
                        // Another write to the key won: the condition was
                        // decided on a state that is gone.
                        return Err(Status::failed_precondition("PreconditionFailed"));
                    }
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted(
                            "listing changed during PUT; client should retry",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for create_object: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_object_listing(&listing_key, &entry.encode_to_vec());
            if let Some(home) = new_home {
                store.put_object_home(&home_key, &home);
            }
        }

        Ok(Response::new(CreateObjectResponse { object: None }))
    }

    pub(crate) async fn delete_object(
        &self,
        request: Request<DeleteObjectRequest>,
    ) -> Result<Response<DeleteObjectResponse>, Status> {
        let req = request.into_inner();
        let listing_key = format!("{}\0{}\0{}", req.bucket, req.key, req.version_id);
        let expected_bytes = self
            .store
            .as_ref()
            .and_then(|s| s.read_object_listing(&listing_key));
        let home_key = format!("{}/{}", req.bucket, req.key);
        let home = if req.forget_home {
            self.store
                .as_ref()
                .and_then(|s| s.read_object_home(&home_key))
        } else {
            None
        };
        if expected_bytes.is_none() && home.is_none() {
            // Nothing to remove — return success idempotently.
            return Ok(Response::new(DeleteObjectResponse {
                success: true,
                version_id: req.version_id,
            }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = Vec::with_capacity(2);
            if expected_bytes.is_some() {
                ops.push(CasOp {
                    table: CasTable::ObjectListings,
                    key: listing_key,
                    expected: expected_bytes,
                    new_value: None,
                });
            }
            if home.is_some() {
                ops.push(CasOp {
                    table: CasTable::Named("object_homes".into()),
                    key: home_key,
                    expected: home,
                    new_value: None,
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delete-object".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("listing changed during DELETE; retry"));
                    }
                    other => {
                        error!("unexpected raft response for delete_object: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            // Legacy non-raft path: direct redb delete.
            store
                .delete_object_listing(&format!("{}\0{}\0{}", req.bucket, req.key, req.version_id));
            if home.is_some() {
                store.delete_object_home(&home_key);
            }
        }

        Ok(Response::new(DeleteObjectResponse {
            success: true,
            version_id: req.version_id,
        }))
    }

    /// Single-object read — not in the common path (gateway goes to
    /// OSDs for ObjectMeta), kept so admin tools can look up metadata
    /// by (bucket, key).
    pub(crate) async fn get_object(
        &self,
        _request: Request<GetObjectRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        Err(Status::unimplemented(
            "Object metadata lives on OSDs — use GetObjectMeta. ObjectListings only stores the listing hint.",
        ))
    }

    /// Linearizable listing via a B-tree scan of OBJECT_LISTINGS in
    /// Meta's redb. Replaces the old scatter-gather-then-merge path
    /// on the gateway. Continuation token is the bucket-relative
    /// form of the last key returned.
    pub(crate) async fn list_objects(
        &self,
        request: Request<ListObjectsRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let req = request.into_inner();
        if req.bucket.is_empty() {
            return Err(Status::invalid_argument("bucket required"));
        }
        let max_keys = if req.max_keys == 0 {
            1000
        } else {
            req.max_keys.min(1000) as usize
        };
        let start_after = if !req.continuation_token.is_empty() {
            req.continuation_token.clone()
        } else {
            req.start_after.clone()
        };

        let Some(store) = &self.store else {
            // No persistent store = no Raft backend — return empty.
            return Ok(Response::new(ListObjectsResponse::default()));
        };
        let page = page_listing(
            |after, n| {
                let (rows, more, _) = store
                    .list_object_listings(&req.bucket, &req.prefix, after, n)
                    .map_err(|e| e.to_string())?;
                let entries = rows
                    .into_iter()
                    .filter_map(|(_k, bytes)| {
                        <ObjectListingEntry as prost::Message>::decode(bytes.as_slice())
                            .inspect_err(|err| warn!("decode ObjectListingEntry failed: {err}"))
                            .ok()
                    })
                    .collect();
                Ok::<_, String>((entries, more))
            },
            &req.prefix,
            &req.delimiter,
            &start_after,
            max_keys,
        )
        .map_err(|e| {
            error!("list_object_listings failed: {e}");
            Status::internal(format!("list failed: {e}"))
        })?;
        let (entries, common_prefixes, is_truncated, next_token) = (
            page.entries,
            page.common_prefixes,
            page.is_truncated,
            page.next_token,
        );

        let key_count = entries.len() as u32 + common_prefixes.len() as u32;
        Ok(Response::new(ListObjectsResponse {
            common_prefixes,
            next_continuation_token: next_token,
            is_truncated,
            key_count,
            entries,
        }))
    }

    pub(crate) async fn get_placement(
        &self,
        request: Request<GetPlacementRequest>,
    ) -> Result<Response<GetPlacementResponse>, Status> {
        let home = self.object_home(&request.get_ref().bucket, &request.get_ref().key);
        let mut response = self.computed_placement(request).await?;
        if let Some(home) = home {
            self.place_at_home(&mut response.get_mut().nodes, &home);
        }
        Ok(response)
    }

    /// Everything a PUT asks before its data moves, in one call (B21): the
    /// bucket's encryption, versioning and object lock, and the key's
    /// placement, each answered by its own handler, exactly as if called.
    pub(crate) async fn get_write_context(
        &self,
        request: Request<GetWriteContextRequest>,
    ) -> Result<Response<GetWriteContextResponse>, Status> {
        fn packed<T: prost::Message>(r: Result<Response<T>, Status>) -> CallResult {
            match r {
                Ok(resp) => CallResult {
                    code: 0,
                    message: String::new(),
                    response: resp.into_inner().encode_to_vec(),
                },
                Err(s) => CallResult {
                    code: s.code() as i32,
                    message: s.message().to_string(),
                    response: Vec::new(),
                },
            }
        }
        let placement = request
            .into_inner()
            .placement
            .ok_or_else(|| Status::invalid_argument("placement request missing"))?;
        let bucket = placement.bucket.clone();
        let (encryption, versioning, object_lock, placement) = tokio::join!(
            self.get_bucket_encryption(Request::new(GetBucketEncryptionRequest {
                bucket: bucket.clone(),
            })),
            self.get_bucket_versioning(Request::new(GetBucketVersioningRequest {
                bucket: bucket.clone(),
            })),
            self.get_object_lock_configuration(Request::new(GetObjectLockConfigRequest { bucket })),
            self.get_placement(Request::new(placement)),
        );
        Ok(Response::new(GetWriteContextResponse {
            encryption: Some(packed(encryption)),
            versioning: Some(packed(versioning)),
            object_lock: Some(packed(object_lock)),
            placement: Some(packed(placement)),
        }))
    }

    /// Get all active nodes for scatter-gather listing operations
    pub(crate) async fn get_listing_nodes(
        &self,
        request: Request<GetListingNodesRequest>,
    ) -> Result<Response<GetListingNodesResponse>, Status> {
        let req = request.into_inner();
        let topology = self.topology.read();
        let osd_nodes = self.osd_nodes.read();

        // Helper — map internal admin state → proto enum value.
        let admin_state_proto = |s: objectio_common::OsdAdminState| -> i32 {
            match s {
                objectio_common::OsdAdminState::In => {
                    objectio_proto::metadata::OsdAdminState::OsdAdminIn as i32
                }
                objectio_common::OsdAdminState::Out => {
                    objectio_proto::metadata::OsdAdminState::OsdAdminOut as i32
                }
                objectio_common::OsdAdminState::Draining => {
                    objectio_proto::metadata::OsdAdminState::OsdAdminDraining as i32
                }
            }
        };

        // When include_all_states is true, admin UI wants EVERY OSD
        // including Draining / Out / Decommissioning. Scatter-gather
        // callers (the default) only want Active ones.
        let topology_iter: Box<dyn Iterator<Item = &objectio_placement::topology::NodeInfo>> =
            if req.include_all_states {
                Box::new(topology.all_nodes())
            } else {
                Box::new(topology.active_nodes())
            };

        // Build lookups keyed by node_id:
        //   admin_state_by_id — operator intent (In/Out/Draining)
        //   address_by_id    — the real OSD endpoint string. The placement
        //                       topology's `address` field is a SocketAddr
        //                       which can't represent DNS names (e.g.
        //                       "http://objectio-osd-3.objectio-osd-headless:9200")
        //                       and falls back to "0.0.0.0:9200". If we
        //                       used that, every node would collapse to
        //                       the same address and the gateway's
        //                       address-based dedup would reduce the
        //                       whole cluster to a single row.
        let admin_state_by_id: std::collections::HashMap<[u8; 16], objectio_common::OsdAdminState> =
            osd_nodes
                .iter()
                .map(|n| (n.node_id, n.admin_state))
                .collect();
        let address_by_id: std::collections::HashMap<[u8; 16], String> = osd_nodes
            .iter()
            .map(|n| (n.node_id, n.address.clone()))
            .collect();
        let te_segment_by_id: std::collections::HashMap<[u8; 16], String> = osd_nodes
            .iter()
            .map(|n| (n.node_id, n.te_segment.clone()))
            .collect();

        let nodes: Vec<ListingNode> = topology_iter
            .enumerate()
            .map(|(idx, node)| {
                let id_bytes = *node.id.as_bytes();
                let admin_state = admin_state_by_id
                    .get(&id_bytes)
                    .copied()
                    .unwrap_or_default();
                // Prefer the registered DNS form; fall back to the
                // topology's parsed SocketAddr only when the OSD isn't
                // in osd_nodes (shouldn't happen in practice).
                let address = address_by_id
                    .get(&id_bytes)
                    .cloned()
                    .unwrap_or_else(|| format!("http://{}", node.address));
                ListingNode {
                    node_id: id_bytes.to_vec(),
                    address,
                    shard_id: idx as u32, // Assign logical shard IDs in order
                    failure_domain: Some(objectio_proto::metadata::FailureDomainInfo {
                        region: node.failure_domain.region.clone(),
                        datacenter: node.failure_domain.datacenter.clone(),
                        rack: node.failure_domain.rack.clone(),
                        zone: node.failure_domain.zone.clone(),
                        host: node.failure_domain.host.clone(),
                    }),
                    admin_state: admin_state_proto(admin_state),
                    te_segment: te_segment_by_id.get(&id_bytes).cloned().unwrap_or_default(),
                }
            })
            .collect();

        debug!(
            "GetListingNodes: returning {} nodes (topology_version={})",
            nodes.len(),
            topology.version
        );

        Ok(Response::new(GetListingNodesResponse {
            nodes,
            topology_version: topology.version,
        }))
    }
}

/// The degraded-object record (B29) of `req`'s object, if it was written
/// with fewer shards than its stripes have positions: erasure-coded stripes
/// of its own (a slice of a pack is the pack's to repair).
fn degraded_record(req: &CreateObjectRequest, now: u64) -> Option<Vec<u8>> {
    use objectio_proto::metadata::{DegradedObject, DegradedStripe, ErasureType};
    let stripes: Vec<DegradedStripe> = req
        .stripes
        .iter()
        .filter(|s| {
            ErasureType::try_from(s.ec_type).unwrap_or(ErasureType::ErasureMds)
                == ErasureType::ErasureMds
                && s.ec_k > 0
                && s.ec_m > 0
                && s.pack_id.is_empty()
        })
        .filter_map(|s| {
            let total = s.ec_k + s.ec_m;
            let mut present: Vec<u32> = s
                .shards
                .iter()
                .map(|l| l.position)
                .filter(|p| *p < total)
                .collect();
            present.sort_unstable();
            present.dedup();
            let missing: Vec<u32> = (0..total)
                .filter(|p| present.binary_search(p).is_err())
                .collect();
            (!missing.is_empty()).then(|| DegradedStripe {
                stripe_id: s.stripe_id,
                missing,
                present: u32::try_from(present.len()).unwrap_or(u32::MAX),
                needed: s.ec_k,
            })
        })
        .collect();
    (!stripes.is_empty()).then(|| {
        DegradedObject {
            object_id: req.object_id.clone(),
            stripes,
            recorded_at: now,
        }
        .encode_to_vec()
    })
}

impl MetaService {
    /// Objects acknowledged short of shards (B29), not yet repaired:
    /// `("{bucket}/{key}", record, its bytes)`, those with the fewest
    /// shards to spare first.
    pub(crate) fn degraded_objects(
        &self,
    ) -> Vec<(String, objectio_proto::metadata::DegradedObject, Vec<u8>)> {
        let Some(store) = self.store.as_ref() else {
            return Vec::new();
        };
        let mut out: Vec<_> = store
            .degraded_all()
            .into_iter()
            .filter_map(|(k, v)| {
                objectio_proto::metadata::DegradedObject::decode(v.as_slice())
                    .ok()
                    .map(|d| (k, d, v))
            })
            .collect();
        let spare = |d: &objectio_proto::metadata::DegradedObject| {
            d.stripes
                .iter()
                .map(|s| i64::from(s.present) - i64::from(s.needed))
                .min()
                .unwrap_or(i64::MAX)
        };
        out.sort_by_key(|(_, d, _)| (spare(d), d.recorded_at));
        out
    }

    /// Remove a degraded-object record (B29), if it is still `expected`:
    /// a write of the key meanwhile replaced it with its own.
    pub(crate) async fn forget_degraded(&self, key: &str, expected: Vec<u8>) -> Result<(), String> {
        use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
        let Some(raft) = self.raft_handle() else {
            return Ok(());
        };
        let cmd = MetaCommand::MultiCas {
            ops: vec![CasOp {
                table: CasTable::Named("degraded_objects".into()),
                key: key.to_string(),
                expected: Some(expected),
                new_value: None,
            }],
            requested_by: "repair-degraded".into(),
        };
        match raft.client_write(cmd).await {
            Ok(r) => match r.data {
                MetaResponse::MultiCasOk | MetaResponse::MultiCasConflict { .. } => Ok(()),
                other => Err(format!("unexpected raft response: {other:?}")),
            },
            Err(e) => Err(e.to_string()),
        }
    }
}

impl MetaService {
    /// Record `bucket/key`'s object as lost (B29), through Raft.
    pub(crate) async fn record_lost(
        &self,
        key: &str,
        lost: &objectio_proto::metadata::LostObject,
    ) -> Result<(), String> {
        use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
        let Some(raft) = self.raft_handle() else {
            return Ok(());
        };
        let current = self.store.as_ref().and_then(|s| s.read_lost(key));
        let cmd = MetaCommand::MultiCas {
            ops: vec![CasOp {
                table: CasTable::Named("lost_objects".into()),
                key: key.to_string(),
                expected: current,
                new_value: Some(lost.encode_to_vec()),
            }],
            requested_by: "lost-object".into(),
        };
        match raft.client_write(cmd).await {
            Ok(r) => match r.data {
                MetaResponse::MultiCasOk => Ok(()),
                MetaResponse::MultiCasConflict { .. } => Err("recorded meanwhile; again".into()),
                other => Err(format!("unexpected raft response: {other:?}")),
            },
            Err(e) => Err(e.to_string()),
        }
    }

    /// How many objects are recorded as lost (B29).
    pub(crate) fn lost_objects(&self) -> Vec<(String, objectio_proto::metadata::LostObject)> {
        self.store
            .as_ref()
            .map(|s| s.lost_all())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, v)| {
                objectio_proto::metadata::LostObject::decode(v.as_slice())
                    .ok()
                    .map(|l| (k, l))
            })
            .collect()
    }
}
