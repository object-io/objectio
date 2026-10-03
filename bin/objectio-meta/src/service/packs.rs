//! The shared-stripe registry and small-object packs.

use super::*;

impl MetaService {
    /// Mirror a committed change to the shared-stripe registry.
    pub(super) fn apply_stripe_refs_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut map = self.stripe_refs.write();
        match new_value {
            Some(bytes) => match objectio_proto::metadata::StripeRefs::decode(bytes) {
                Ok(r) => {
                    map.insert(key.to_string(), r);
                }
                Err(e) => warn!("apply: decode StripeRefs('{key}') failed: {e}"),
            },
            None => {
                map.remove(key);
            }
        }
    }

    /// Apply registry changes (`None` removes an entry) atomically, each
    /// expected to still hold what it was read as. `Ok(false)` on a
    /// conflict, for the caller to re-read and retry.
    pub(super) async fn write_stripe_refs(
        &self,
        changes: Vec<(String, Option<objectio_proto::metadata::StripeRefs>)>,
        requested_by: &str,
    ) -> Result<bool, Status> {
        use prost::Message;
        if changes.is_empty() {
            return Ok(true);
        }
        let expected: Vec<Option<Vec<u8>>> = {
            let map = self.stripe_refs.read();
            changes
                .iter()
                .map(|(k, _)| map.get(k).map(Message::encode_to_vec))
                .collect()
        };
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let ops = changes
                .iter()
                .zip(expected)
                .map(|((key, new), expected)| CasOp {
                    table: CasTable::Named("stripe_refs".into()),
                    key: key.clone(),
                    expected,
                    new_value: new.as_ref().map(Message::encode_to_vec),
                })
                .collect();
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: requested_by.into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => return Ok(false),
                    other => {
                        error!("unexpected raft response for {requested_by}: {other:?}");
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            for (key, new) in &changes {
                match new {
                    Some(r) => store.put_stripe_refs(key, &r.encode_to_vec()),
                    None => store.delete_stripe_refs(key),
                }
            }
        }
        let mut map = self.stripe_refs.write();
        for (key, new) in changes {
            match new {
                Some(r) => {
                    map.insert(key, r);
                }
                None => {
                    map.remove(&key);
                }
            }
        }
        Ok(true)
    }

    /// A pack's record and its stored bytes (for compare-and-set).
    pub(super) fn pack_record(
        &self,
        pack_id: &[u8],
    ) -> Option<(objectio_proto::metadata::PackRecord, Vec<u8>)> {
        let bytes = self
            .store
            .as_ref()?
            .read_named(PACKS_TABLE, &hex::encode(pack_id))?;
        let record = objectio_proto::metadata::PackRecord::decode(bytes.as_slice()).ok()?;
        Some((record, bytes))
    }

    /// Every pack, sealed or not, for drain and repair (as block chunks).
    pub fn packs(&self) -> Vec<objectio_proto::metadata::PackRecord> {
        self.store
            .as_ref()
            .map(|s| s.list_named(PACKS_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, v)| objectio_proto::metadata::PackRecord::decode(v.as_slice()).ok())
            .filter(|p| p.stripe.is_some())
            .collect()
    }

    /// Record shards of a pack rebuilt where it had none.
    pub async fn pack_add_shard_locations(
        &self,
        pack_id: &[u8],
        added: &[objectio_proto::metadata::ShardLocation],
    ) -> Result<(), Status> {
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let Some((mut record, bytes)) = self.pack_record(pack_id) else {
                return Err(Status::not_found("pack not found"));
            };
            let Some(stripe) = record.stripe.as_mut() else {
                return Err(Status::internal("pack has no stripe"));
            };
            let mut changed = false;
            for loc in added {
                if stripe.shards.iter().all(|l| l.position != loc.position) {
                    stripe.shards.push(loc.clone());
                    changed = true;
                }
            }
            if !changed {
                return Ok(());
            }
            stripe.shards.sort_by_key(|l| l.position);
            record.version += 1;
            let ok = self
                .cas_many(
                    vec![objectio_meta_store::CasOp {
                        table: objectio_meta_store::CasTable::Named(PACKS_TABLE.into()),
                        key: hex::encode(pack_id),
                        expected: Some(bytes),
                        new_value: Some(record.encode_to_vec()),
                    }],
                    "pack-add-shards",
                )
                .await?;
            if ok {
                return Ok(());
            }
        }
        Err(Status::aborted("pack kept changing; retry"))
    }

    /// Record that a pack's shard at `position` moved from `from` to `to`.
    pub async fn move_pack_shard(
        &self,
        pack_id: &[u8],
        position: u32,
        from: [u8; 16],
        to: &objectio_proto::metadata::ShardLocation,
    ) -> Result<(), Status> {
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let Some((mut record, bytes)) = self.pack_record(pack_id) else {
                return Err(Status::not_found("pack not found"));
            };
            let Some(stripe) = record.stripe.as_mut() else {
                return Err(Status::internal("pack has no stripe"));
            };
            let mut moved = false;
            for loc in &mut stripe.shards {
                if loc.position == position && loc.node_id.as_slice() == from.as_slice() {
                    *loc = to.clone();
                    moved = true;
                }
            }
            if !moved {
                // Already moved (a retry), or the record names another node.
                return Ok(());
            }
            record.version += 1;
            let ok = self
                .cas_many(
                    vec![objectio_meta_store::CasOp {
                        table: objectio_meta_store::CasTable::Named(PACKS_TABLE.into()),
                        key: hex::encode(pack_id),
                        expected: Some(bytes),
                        new_value: Some(record.encode_to_vec()),
                    }],
                    "pack-move-shard",
                )
                .await?;
            if ok {
                return Ok(());
            }
        }
        Err(Status::aborted("pack kept changing; retry"))
    }

    pub(crate) async fn share_stripes(
        &self,
        request: Request<objectio_proto::metadata::ShareStripesRequest>,
    ) -> Result<Response<objectio_proto::metadata::ShareStripesResponse>, Status> {
        use objectio_proto::metadata::StripeRefs;
        let req = request.into_inner();
        if req.owner.is_empty() || req.sharer.is_empty() {
            return Err(Status::invalid_argument("owner and sharer are required"));
        }
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let mut changes = Vec::new();
            {
                let map = self.stripe_refs.read();
                for id in &req.stripe_ids {
                    let key = hex::encode(id);
                    let mut refs = match map.get(&key) {
                        // Shared already: the owner must still be a referrer,
                        // or it has let the stripe go and may have freed it.
                        Some(r) if !r.referrers.contains(&req.owner) => {
                            return Err(Status::failed_precondition(format!(
                                "stripe {key} is no longer referenced by the copy's source"
                            )));
                        }
                        Some(r) => r.clone(),
                        // A pack is registered while anything is in it: no
                        // entry means the source's slice is gone already.
                        None if self.pack_record(id).is_some() => {
                            return Err(Status::failed_precondition(format!(
                                "pack {key} is no longer referenced by the copy's source"
                            )));
                        }
                        None => StripeRefs {
                            referrers: vec![req.owner.clone()],
                        },
                    };
                    if !refs.referrers.contains(&req.sharer) {
                        refs.referrers.push(req.sharer.clone());
                        changes.push((key, Some(refs)));
                    }
                }
            }
            if self.write_stripe_refs(changes, "share-stripes").await? {
                return Ok(Response::new(
                    objectio_proto::metadata::ShareStripesResponse {},
                ));
            }
        }
        Err(Status::aborted("stripe references kept changing; retry"))
    }

    pub(crate) async fn release_stripes(
        &self,
        request: Request<objectio_proto::metadata::ReleaseStripesRequest>,
    ) -> Result<Response<objectio_proto::metadata::ReleaseStripesResponse>, Status> {
        use objectio_meta_store::{CasOp, CasTable};
        let req = request.into_inner();
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let mut changes: Vec<(String, Option<objectio_proto::metadata::StripeRefs>)> =
                Vec::new();
            let mut freeable = Vec::new();
            let mut pack_ops = Vec::new();
            let mut freed_packs = Vec::new();
            {
                let map = self.stripe_refs.read();
                for id in &req.stripe_ids {
                    let key = hex::encode(id);
                    let pack = self.pack_record(id);
                    match map.get(&key) {
                        // A pack is always registered while anything is in
                        // it: no entry means nothing here to release, never
                        // "free" — that would delete other objects' bytes.
                        None if pack.is_some() => {}
                        // Never shared: its only referrer is letting it go.
                        None => freeable.push(id.clone()),
                        Some(r) if r.referrers.contains(&req.referrer) => {
                            let mut refs = r.clone();
                            refs.referrers.retain(|x| x != &req.referrer);
                            if refs.referrers.is_empty() {
                                changes.push((key.clone(), None));
                                if let Some((record, bytes)) = pack {
                                    // The last object in the pack: the pack
                                    // goes in the same commit.
                                    pack_ops.push(CasOp {
                                        table: CasTable::Named(PACKS_TABLE.into()),
                                        key,
                                        expected: Some(bytes),
                                        new_value: None,
                                    });
                                    if let Some(stripe) = record.stripe {
                                        freed_packs.push(stripe);
                                    }
                                } else {
                                    freeable.push(id.clone());
                                }
                            } else {
                                changes.push((key, Some(refs)));
                            }
                        }
                        // Shared, and not by this referrer: someone else's.
                        Some(_) => {}
                    }
                }
            }
            let ok = if pack_ops.is_empty() {
                self.write_stripe_refs(changes, "release-stripes").await?
            } else {
                let expected: Vec<Option<Vec<u8>>> = {
                    let map = self.stripe_refs.read();
                    changes
                        .iter()
                        .map(|(k, _)| map.get(k).map(Message::encode_to_vec))
                        .collect()
                };
                let mut ops: Vec<CasOp> = changes
                    .iter()
                    .zip(expected)
                    .map(|((key, new), expected)| CasOp {
                        table: CasTable::Named("stripe_refs".into()),
                        key: key.clone(),
                        expected,
                        new_value: new.as_ref().map(Message::encode_to_vec),
                    })
                    .collect();
                ops.extend(pack_ops);
                let ok = self.cas_many(ops, "release-stripes").await?;
                if ok {
                    let mut map = self.stripe_refs.write();
                    for (key, new) in changes {
                        match new {
                            Some(r) => {
                                map.insert(key, r);
                            }
                            None => {
                                map.remove(&key);
                            }
                        }
                    }
                }
                ok
            };
            if ok {
                return Ok(Response::new(
                    objectio_proto::metadata::ReleaseStripesResponse {
                        freeable,
                        freed_packs,
                    },
                ));
            }
        }
        Err(Status::aborted("stripe references kept changing; retry"))
    }

    pub(crate) async fn intend_pack(
        &self,
        request: Request<objectio_proto::metadata::IntendPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::IntendPackResponse>, Status> {
        let mut pack = request
            .into_inner()
            .pack
            .ok_or_else(|| Status::invalid_argument("pack is required"))?;
        if pack.pack_id.len() != 16 || pack.stripe.is_none() {
            return Err(Status::invalid_argument(
                "a pack needs a 16-byte id and a stripe",
            ));
        }
        pack.sealed = false;
        pack.version = 1;
        pack.created_at = Self::current_timestamp();
        let ok = self
            .cas_many(
                vec![objectio_meta_store::CasOp {
                    table: objectio_meta_store::CasTable::Named(PACKS_TABLE.into()),
                    key: hex::encode(&pack.pack_id),
                    expected: None,
                    new_value: Some(pack.encode_to_vec()),
                }],
                "intend-pack",
            )
            .await?;
        if ok {
            Ok(Response::new(
                objectio_proto::metadata::IntendPackResponse {},
            ))
        } else {
            Err(Status::already_exists("pack id is taken"))
        }
    }

    pub(crate) async fn seal_pack(
        &self,
        request: Request<objectio_proto::metadata::SealPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::SealPackResponse>, Status> {
        use objectio_meta_store::{CasOp, CasTable};
        let req = request.into_inner();
        if req.referrers.is_empty() {
            return Err(Status::invalid_argument("a pack holds at least one object"));
        }
        let Some((mut record, bytes)) = self.pack_record(&req.pack_id) else {
            return Err(Status::failed_precondition("pack is not recorded"));
        };
        if record.sealed {
            return Err(Status::failed_precondition("pack is already sealed"));
        }
        record.sealed = true;
        if let Some(stripe) = req.stripe {
            if stripe.shards.is_empty() {
                return Err(Status::invalid_argument(
                    "a sealed pack needs its shard locations",
                ));
            }
            record.stripe = Some(stripe);
        }
        let key = hex::encode(&req.pack_id);
        if self.stripe_refs.read().contains_key(&key) {
            return Err(Status::failed_precondition("pack id is already registered"));
        }
        let refs = objectio_proto::metadata::StripeRefs {
            referrers: req.referrers,
        };
        let ok = self
            .cas_many(
                vec![
                    CasOp {
                        table: CasTable::Named(PACKS_TABLE.into()),
                        key: key.clone(),
                        expected: Some(bytes),
                        new_value: Some(record.encode_to_vec()),
                    },
                    CasOp {
                        table: CasTable::Named("stripe_refs".into()),
                        key: key.clone(),
                        expected: None,
                        new_value: Some(refs.encode_to_vec()),
                    },
                ],
                "seal-pack",
            )
            .await?;
        if !ok {
            return Err(Status::aborted("pack changed while sealing; retry"));
        }
        self.stripe_refs.write().insert(key, refs);
        Ok(Response::new(objectio_proto::metadata::SealPackResponse {}))
    }

    pub(crate) async fn abort_pack(
        &self,
        request: Request<objectio_proto::metadata::AbortPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::AbortPackResponse>, Status> {
        let id = request.into_inner().pack_id;
        let Some((record, bytes)) = self.pack_record(&id) else {
            return Ok(Response::new(objectio_proto::metadata::AbortPackResponse {
                pack: None,
                found: false,
            }));
        };
        if record.sealed {
            return Err(Status::failed_precondition(
                "a sealed pack is freed by releasing its objects, not aborted",
            ));
        }
        let ok = self
            .cas_many(
                vec![objectio_meta_store::CasOp {
                    table: objectio_meta_store::CasTable::Named(PACKS_TABLE.into()),
                    key: hex::encode(&id),
                    expected: Some(bytes),
                    new_value: None,
                }],
                "abort-pack",
            )
            .await?;
        if !ok {
            return Err(Status::aborted("pack changed; retry"));
        }
        Ok(Response::new(objectio_proto::metadata::AbortPackResponse {
            pack: Some(record),
            found: true,
        }))
    }

    pub(crate) async fn get_pack(
        &self,
        request: Request<objectio_proto::metadata::GetPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetPackResponse>, Status> {
        let pack = self
            .pack_record(&request.into_inner().pack_id)
            .map(|(r, _)| r);
        Ok(Response::new(objectio_proto::metadata::GetPackResponse {
            found: pack.is_some(),
            pack,
        }))
    }

    pub(crate) async fn list_packs(
        &self,
        request: Request<objectio_proto::metadata::ListPacksRequest>,
    ) -> Result<Response<objectio_proto::metadata::ListPacksResponse>, Status> {
        let req = request.into_inner();
        let after = hex::encode(&req.start_after);
        let limit = if req.limit == 0 {
            1000
        } else {
            req.limit as usize
        };
        let mut all: Vec<(String, Vec<u8>)> = self
            .store
            .as_ref()
            .map(|s| s.list_named(PACKS_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter(|(k, _)| req.start_after.is_empty() || *k > after)
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        let truncated = all.len() > limit;
        let packs: Vec<objectio_proto::metadata::PackRecord> = all
            .into_iter()
            .take(limit)
            .filter_map(|(_, v)| objectio_proto::metadata::PackRecord::decode(v.as_slice()).ok())
            .collect();
        let refs = self.stripe_refs.read();
        let referrers = packs
            .iter()
            .map(|p| objectio_proto::metadata::PackReferrers {
                object_ids: refs
                    .get(&hex::encode(&p.pack_id))
                    .map(|r| r.referrers.clone())
                    .unwrap_or_default(),
            })
            .collect();
        Ok(Response::new(objectio_proto::metadata::ListPacksResponse {
            packs,
            truncated,
            referrers,
        }))
    }

    pub(crate) async fn pack_move_shard(
        &self,
        request: Request<objectio_proto::metadata::PackMoveShardRequest>,
    ) -> Result<Response<objectio_proto::metadata::PackMoveShardResponse>, Status> {
        let req = request.into_inner();
        let from: [u8; 16] = req
            .from_node
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("from_node must be 16 bytes"))?;
        let to = req
            .to
            .ok_or_else(|| Status::invalid_argument("to is required"))?;
        MetaService::move_pack_shard(self, &req.pack_id, req.position, from, &to).await?;
        Ok(Response::new(
            objectio_proto::metadata::PackMoveShardResponse {},
        ))
    }

    pub(crate) async fn pack_settle(
        &self,
        request: Request<objectio_proto::metadata::PackSettleRequest>,
    ) -> Result<Response<objectio_proto::metadata::PackSettleResponse>, Status> {
        let req = request.into_inner();
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            // A pack freed meanwhile has nothing left to settle.
            let Some((mut record, bytes)) = self.pack_record(&req.pack_id) else {
                return Ok(Response::new(
                    objectio_proto::metadata::PackSettleResponse {},
                ));
            };
            let mut changed = false;
            for m in &mut record.members {
                if !m.settled && req.object_ids.contains(&m.object_id) {
                    m.settled = true;
                    m.old_stripe = None;
                    changed = true;
                }
            }
            if !changed {
                return Ok(Response::new(
                    objectio_proto::metadata::PackSettleResponse {},
                ));
            }
            let ok = self
                .cas_many(
                    vec![objectio_meta_store::CasOp {
                        table: objectio_meta_store::CasTable::Named(PACKS_TABLE.into()),
                        key: hex::encode(&req.pack_id),
                        expected: Some(bytes),
                        new_value: Some(record.encode_to_vec()),
                    }],
                    "pack-settle",
                )
                .await?;
            if ok {
                return Ok(Response::new(
                    objectio_proto::metadata::PackSettleResponse {},
                ));
            }
        }
        Err(Status::aborted("pack kept changing; retry"))
    }

    pub(crate) async fn locate_chunks(
        &self,
        request: Request<objectio_proto::metadata::LocateChunksRequest>,
    ) -> Result<Response<objectio_proto::metadata::LocateChunksResponse>, Status> {
        let req = request.into_inner();
        let pool = self
            .buckets
            .read()
            .get(&req.bucket)
            .map(|b| b.pool.clone())
            .unwrap_or_default();
        let pg_count = if pool.is_empty() {
            0
        } else {
            self.pools.read().get(&pool).map_or(0, |p| p.pg_count)
        };
        // Without placement groups (today's default buckets), chunks map by
        // jump hash over the OSDs in placement — stable while membership is.
        let mut in_placement: Vec<([u8; 16], String)> = self
            .osd_nodes
            .read()
            .iter()
            .filter(|n| n.admin_state == objectio_common::OsdAdminState::In)
            .map(|n| (n.node_id, n.address.clone()))
            .collect();
        in_placement.sort();

        let (addresses, node_ids) = req
            .fingerprints
            .iter()
            .map(|fp| {
                let h = xxhash_rust::xxh64::xxh64(fp, 0);
                if pg_count > 0 {
                    let pg_id = objectio_placement::jump_consistent_hash(h, pg_count as i32) as u32;
                    return self
                        .placement_group(&pool, pg_id)
                        .and_then(|pg| pg.osd_ids.first().cloned())
                        .and_then(|id| <[u8; 16]>::try_from(id.as_slice()).ok())
                        .and_then(|id| self.osd_address_by_id(&id).map(|a| (a, id.to_vec())))
                        .unwrap_or_default();
                }
                if in_placement.is_empty() {
                    return (String::new(), Vec::new());
                }
                let i = objectio_placement::jump_consistent_hash(h, in_placement.len() as i32);
                let (id, addr) = &in_placement[i as usize];
                (addr.clone(), id.to_vec())
            })
            .unzip();
        Ok(Response::new(
            objectio_proto::metadata::LocateChunksResponse {
                addresses,
                node_ids,
            },
        ))
    }
}
