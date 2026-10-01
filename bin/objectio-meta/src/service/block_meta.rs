//! Block storage metadata, replicated through Raft: volumes, each volume's
//! chunk map, snapshots and clones.
//!
//! The block gateway used to keep this in its own local database — one
//! disk, no copy — so losing it lost every volume while the data sat safe
//! on the OSDs. Here it is in meta's Raft tables, like everything else
//! meta knows.
//!
//! A chunk record holds the erasure-coded stripe with the chunk's bytes,
//! and the referrer it holds that stripe as in the shared-stripe registry:
//! the stripe's own id for a chunk the volume wrote, a snapshot's id, a
//! clone's volume id for chunks it inherited. Snapshots and clones share
//! stripes rather than copying them, and each release goes through the
//! registry, so a stripe is freed only when nothing uses it any more.
//! Chunk-map changes and the registry changes they imply are committed in
//! one Raft write, so a chunk never points at a stripe already freed.

// Every handler here answers with a tonic `Status`, as the service does.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap};

use objectio_proto::block::{Snapshot, SnapshotState, Volume, VolumeState};
use objectio_proto::metadata::{
    BlockChunkRef, BlockCloneVolumeRequest, BlockCommitChunksRequest, BlockCreateSnapshotRequest,
    BlockCreateVolumeRequest, BlockDeleteSnapshotRequest, BlockDeleteVolumeRequest,
    BlockGetChunksRequest, BlockGetChunksResponse, BlockGetSnapshotRequest, BlockGetVolumeRequest,
    BlockListSnapshotsRequest, BlockListSnapshotsResponse, BlockListVolumesResponse,
    BlockReleaseResponse, BlockSnapshotResponse, BlockUpdateVolumeRequest, BlockVolumeResponse,
    ShardLocation, StripeMeta, StripeRefs,
};
use prost::Message;
use tonic::Status;

use super::{MetaService, raft_write_to_status};

pub(super) const VOLUMES: &str = "block_volumes";
pub(super) const NAMES: &str = "block_volume_names";
pub(super) const CHUNKS: &str = "block_chunks";
pub(super) const SNAPSHOTS: &str = "block_snapshots";
pub(super) const SNAP_CHUNKS: &str = "block_snapshot_chunks";
pub(super) const TABLES: [&str; 5] = [VOLUMES, NAMES, CHUNKS, SNAPSHOTS, SNAP_CHUNKS];
const STRIPE_REFS: &str = "stripe_refs";

/// Chunks per Raft write. Each can add a registry op as well as its own,
/// and one write takes at most 256.
const BATCH: usize = 100;

/// Default chunk size: 4 MiB.
const CHUNK_SIZE: u32 = 4 * 1024 * 1024;

/// The block tables as stored: raw bytes, so a compare-and-swap expects
/// exactly what is on disk (a `Volume`'s metadata map has no fixed
/// encoding, so re-encoding a decoded copy could differ).
#[derive(Default)]
pub(super) struct BlockTables {
    rows: HashMap<&'static str, BTreeMap<String, Vec<u8>>>,
}

impl BlockTables {
    fn table(&self, t: &str) -> Option<&BTreeMap<String, Vec<u8>>> {
        self.rows.get(t)
    }

    fn get(&self, t: &str, key: &str) -> Option<Vec<u8>> {
        self.table(t).and_then(|m| m.get(key).cloned())
    }

    /// Rows of `t` keyed `"{id}\0…"`, from `start` (inclusive) to `end`
    /// (exclusive) chunk.
    fn chunks_of(&self, t: &str, id: &str, start: u64, end: u64) -> Vec<(String, Vec<u8>)> {
        let Some(m) = self.table(t) else {
            return Vec::new();
        };
        let lo = chunk_key(id, start);
        let hi = if end == u64::MAX {
            format!("{id}\u{1}")
        } else {
            chunk_key(id, end)
        };
        m.range(lo..hi)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn set(&mut self, t: &str, key: String, value: Option<Vec<u8>>) {
        let Some(name) = TABLES.iter().find(|n| **n == t) else {
            return;
        };
        let m = self.rows.entry(name).or_default();
        match value {
            Some(v) => {
                m.insert(key, v);
            }
            None => {
                m.remove(&key);
            }
        }
    }
}

fn chunk_key(id: &str, chunk: u64) -> String {
    format!("{id}\0{chunk:016x}")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One row to write: `None` deletes it.
struct Op {
    table: &'static str,
    key: String,
    new: Option<Vec<u8>>,
}

fn put(table: &'static str, key: impl Into<String>, msg: &impl Message) -> Op {
    Op {
        table,
        key: key.into(),
        new: Some(msg.encode_to_vec()),
    }
}

fn delete(table: &'static str, key: impl Into<String>) -> Op {
    Op {
        table,
        key: key.into(),
        new: None,
    }
}

fn decode_err(what: &str, e: &prost::DecodeError) -> Status {
    Status::internal(format!("stored {what} does not decode: {e}"))
}

/// Registry changes made within one Raft write, over what is committed.
struct Refs<'a> {
    svc: &'a MetaService,
    changed: HashMap<String, Option<StripeRefs>>,
}

impl<'a> Refs<'a> {
    fn new(svc: &'a MetaService) -> Self {
        Self {
            svc,
            changed: HashMap::new(),
        }
    }

    fn get(&self, key: &str) -> Option<StripeRefs> {
        match self.changed.get(key) {
            Some(v) => v.clone(),
            None => self.svc.stripe_refs.read().get(key).cloned(),
        }
    }

    /// `sharer` references the stripe too, alongside `owner`.
    fn share(&mut self, stripe_id: &[u8], owner: &[u8], sharer: &[u8]) -> Result<(), Status> {
        let key = hex::encode(stripe_id);
        let mut refs = match self.get(&key) {
            Some(r) if !r.referrers.iter().any(|x| x == owner) => {
                return Err(Status::internal(format!(
                    "stripe {key} is not held by the chunk's recorded owner"
                )));
            }
            Some(r) => r,
            None => StripeRefs {
                referrers: vec![owner.to_vec()],
            },
        };
        if !refs.referrers.iter().any(|x| x == sharer) {
            refs.referrers.push(sharer.to_vec());
        }
        self.changed.insert(key, Some(refs));
        Ok(())
    }

    /// `referrer` lets the stripe go. Whether it is now free.
    fn release(&mut self, stripe_id: &[u8], referrer: &[u8]) -> bool {
        let key = hex::encode(stripe_id);
        match self.get(&key) {
            None => true,
            Some(r) if r.referrers.iter().any(|x| x == referrer) => {
                let mut refs = r;
                refs.referrers.retain(|x| x != referrer);
                if refs.referrers.is_empty() {
                    self.changed.insert(key, None);
                    true
                } else {
                    self.changed.insert(key, Some(refs));
                    false
                }
            }
            Some(_) => false,
        }
    }

    fn into_ops(self) -> Vec<Op> {
        self.changed
            .into_iter()
            .map(|(key, v)| Op {
                table: STRIPE_REFS,
                key,
                new: v.map(|r| r.encode_to_vec()),
            })
            .collect()
    }
}

impl MetaService {
    fn block_get(&self, table: &str, key: &str) -> Option<Vec<u8>> {
        self.block.read().get(table, key)
    }

    fn volume(&self, id: &str) -> Result<Volume, Status> {
        let raw = self
            .block_get(VOLUMES, id)
            .ok_or_else(|| Status::not_found(format!("volume {id} not found")))?;
        Volume::decode(raw.as_slice()).map_err(|e| decode_err("volume", &e))
    }

    fn snapshot(&self, id: &str) -> Result<Snapshot, Status> {
        let raw = self
            .block_get(SNAPSHOTS, id)
            .ok_or_else(|| Status::not_found(format!("snapshot {id} not found")))?;
        Snapshot::decode(raw.as_slice()).map_err(|e| decode_err("snapshot", &e))
    }

    /// Mirror a committed row of a block table into the cache.
    pub(super) fn apply_block_event(&self, table: &str, key: &str, new_value: Option<&[u8]>) {
        self.block
            .write()
            .set(table, key.to_string(), new_value.map(<[u8]>::to_vec));
    }

    /// Fill the block-table cache from the store.
    pub(super) fn load_block_tables(&self, store: &objectio_meta_store::MetaStore) {
        let mut tables = BlockTables::default();
        for t in TABLES {
            for (k, v) in store.load_all_raw(t) {
                tables.set(t, k, Some(v));
            }
        }
        *self.block.write() = tables;
    }

    /// Commit `ops` in one Raft write, each expected to still hold what the
    /// cache says. `Ok(false)` on a conflict: re-read and retry.
    async fn block_commit(&self, ops: Vec<Op>, requested_by: &str) -> Result<bool, Status> {
        if ops.is_empty() {
            return Ok(true);
        }
        let expected: Vec<Option<Vec<u8>>> = ops
            .iter()
            .map(|op| {
                if op.table == STRIPE_REFS {
                    self.stripe_refs
                        .read()
                        .get(&op.key)
                        .map(Message::encode_to_vec)
                } else {
                    self.block_get(op.table, &op.key)
                }
            })
            .collect();
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: ops
                    .iter()
                    .zip(expected)
                    .map(|(op, expected)| CasOp {
                        table: CasTable::Named(op.table.to_string()),
                        key: op.key.clone(),
                        expected,
                        new_value: op.new.clone(),
                    })
                    .collect(),
                requested_by: requested_by.into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => return Ok(false),
                    other => {
                        return Err(Status::internal(format!(
                            "unexpected raft response for {requested_by}: {other:?}"
                        )));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            for op in &ops {
                match &op.new {
                    Some(v) => store.put_raw(op.table, &op.key, v),
                    None => store.delete_raw(op.table, &op.key),
                }
            }
        }
        // Mirrored here as well as by the apply listener, so the next
        // request on this node sees it at once.
        for op in ops {
            if op.table == STRIPE_REFS {
                self.apply_stripe_refs_event(&op.key, op.new.as_deref());
            } else {
                self.apply_block_event(op.table, &op.key, op.new.as_deref());
            }
        }
        Ok(true)
    }

    /// Run `build` (which reads the current state and returns the ops) and
    /// commit what it returns, rebuilding after a conflict.
    async fn block_retry<T>(
        &self,
        requested_by: &str,
        mut build: impl FnMut() -> Result<(Vec<Op>, T), Status>,
    ) -> Result<T, Status> {
        for _ in 0..8 {
            let (ops, out) = build()?;
            if self.block_commit(ops, requested_by).await? {
                return Ok(out);
            }
        }
        Err(Status::aborted(format!(
            "{requested_by}: state kept changing; retry"
        )))
    }

    pub(super) async fn block_create_volume_impl(
        &self,
        req: BlockCreateVolumeRequest,
    ) -> Result<BlockVolumeResponse, Status> {
        let _serial = self.block_lock.lock().await;
        if req.name.is_empty() || req.size_bytes == 0 {
            return Err(Status::invalid_argument("a volume needs a name and a size"));
        }
        let volume = self
            .block_retry("block-create-volume", || {
                if self.block_get(NAMES, &req.name).is_some() {
                    return Err(Status::already_exists(format!(
                        "volume {} already exists",
                        req.name
                    )));
                }
                let mut v = Volume {
                    volume_id: uuid::Uuid::new_v4().to_string(),
                    name: req.name.clone(),
                    size_bytes: req.size_bytes,
                    pool: req.pool.clone(),
                    created_at: now(),
                    updated_at: now(),
                    chunk_size_bytes: if req.chunk_size_bytes == 0 {
                        CHUNK_SIZE
                    } else {
                        req.chunk_size_bytes
                    },
                    metadata: req.metadata.clone(),
                    ..Default::default()
                };
                v.set_state(VolumeState::Available);
                let ops = vec![
                    put(VOLUMES, v.volume_id.clone(), &v),
                    Op {
                        table: NAMES,
                        key: v.name.clone(),
                        new: Some(v.volume_id.clone().into_bytes()),
                    },
                ];
                Ok((ops, v))
            })
            .await?;
        Ok(BlockVolumeResponse {
            volume: Some(volume),
        })
    }

    pub(super) fn block_get_volume_impl(
        &self,
        req: &BlockGetVolumeRequest,
    ) -> Result<BlockVolumeResponse, Status> {
        let id = if req.volume_id.is_empty() {
            let raw = self
                .block_get(NAMES, &req.name)
                .ok_or_else(|| Status::not_found(format!("volume {} not found", req.name)))?;
            String::from_utf8(raw).map_err(|e| Status::internal(e.to_string()))?
        } else {
            req.volume_id.clone()
        };
        Ok(BlockVolumeResponse {
            volume: Some(self.volume(&id)?),
        })
    }

    pub(super) fn block_list_volumes_impl(&self) -> BlockListVolumesResponse {
        let mut volumes: Vec<Volume> = self
            .block
            .read()
            .table(VOLUMES)
            .map(|m| {
                m.values()
                    .filter_map(|v| Volume::decode(v.as_slice()).ok())
                    .collect()
            })
            .unwrap_or_default();
        volumes.sort_by(|a, b| a.name.cmp(&b.name));
        BlockListVolumesResponse { volumes }
    }

    pub(super) async fn block_update_volume_impl(
        &self,
        req: BlockUpdateVolumeRequest,
    ) -> Result<BlockVolumeResponse, Status> {
        let _serial = self.block_lock.lock().await;
        let volume = self
            .block_retry("block-update-volume", || {
                let mut v = self.volume(&req.volume_id)?;
                if req.size_bytes != 0 {
                    if req.size_bytes < v.size_bytes {
                        return Err(Status::invalid_argument("a volume can only grow"));
                    }
                    v.size_bytes = req.size_bytes;
                }
                if req.state() != VolumeState::Unknown {
                    v.set_state(req.state());
                }
                v.updated_at = now();
                Ok((vec![put(VOLUMES, v.volume_id.clone(), &v)], v))
            })
            .await?;
        Ok(BlockVolumeResponse {
            volume: Some(volume),
        })
    }

    /// Release every chunk of `owner_id` in `table`, a batch per Raft
    /// write, and return the stripes now free.
    async fn release_chunks(
        &self,
        table: &'static str,
        owner_id: &str,
        referrer_is_owner: bool,
        requested_by: &str,
    ) -> Result<Vec<StripeMeta>, Status> {
        let mut freeable = Vec::new();
        loop {
            let done = self
                .block_retry(requested_by, || {
                    let rows = self.block.read().chunks_of(table, owner_id, 0, u64::MAX);
                    if rows.is_empty() {
                        return Ok((Vec::new(), (true, Vec::new())));
                    }
                    let mut refs = Refs::new(self);
                    let mut ops = Vec::new();
                    let mut free = Vec::new();
                    for (key, raw) in rows.into_iter().take(BATCH) {
                        let r = BlockChunkRef::decode(raw.as_slice())
                            .map_err(|e| decode_err("chunk", &e))?;
                        if let Some(stripe) = r.stripe {
                            let referrer = if referrer_is_owner {
                                owner_id.as_bytes().to_vec()
                            } else {
                                r.owner.clone()
                            };
                            if refs.release(&stripe.object_id, &referrer) {
                                free.push(stripe);
                            }
                        }
                        ops.push(delete(table, key));
                    }
                    ops.extend(refs.into_ops());
                    Ok((ops, (false, free)))
                })
                .await?;
            freeable.extend(done.1);
            if done.0 {
                return Ok(freeable);
            }
        }
    }

    pub(super) async fn block_delete_volume_impl(
        &self,
        req: BlockDeleteVolumeRequest,
    ) -> Result<BlockReleaseResponse, Status> {
        let _serial = self.block_lock.lock().await;
        let mut v = self.volume(&req.volume_id)?;
        if v.state() == VolumeState::Attached {
            return Err(Status::failed_precondition("detach the volume first"));
        }
        // Marked first, so a delete interrupted half way is visibly so and
        // a repeat carries on from where it stopped.
        if v.state() != VolumeState::Deleting {
            v.set_state(VolumeState::Deleting);
            v.updated_at = now();
            let row = put(VOLUMES, v.volume_id.clone(), &v);
            self.block_retry("block-delete-volume", || {
                Ok((
                    vec![Op {
                        table: row.table,
                        key: row.key.clone(),
                        new: row.new.clone(),
                    }],
                    (),
                ))
            })
            .await?;
        }
        let freeable = self
            .release_chunks(CHUNKS, &v.volume_id, false, "block-delete-volume")
            .await?;
        let (id, name) = (v.volume_id.clone(), v.name.clone());
        self.block_retry("block-delete-volume", || {
            Ok((
                vec![delete(VOLUMES, id.clone()), delete(NAMES, name.clone())],
                (),
            ))
        })
        .await?;
        Ok(BlockReleaseResponse { freeable })
    }

    pub(super) fn block_get_chunks_impl(
        &self,
        req: &BlockGetChunksRequest,
    ) -> Result<BlockGetChunksResponse, Status> {
        self.volume(&req.volume_id)?;
        let end = req.start_chunk.saturating_add(req.count.max(1));
        let chunks = self
            .block
            .read()
            .chunks_of(CHUNKS, &req.volume_id, req.start_chunk, end)
            .into_iter()
            .map(|(_, raw)| BlockChunkRef::decode(raw.as_slice()))
            .collect::<Result<_, _>>()
            .map_err(|e| decode_err("chunk", &e))?;
        Ok(BlockGetChunksResponse { chunks })
    }

    pub(super) async fn block_commit_chunks_impl(
        &self,
        req: BlockCommitChunksRequest,
    ) -> Result<BlockReleaseResponse, Status> {
        let _serial = self.block_lock.lock().await;
        if req.updates.len() > BATCH {
            return Err(Status::invalid_argument(format!(
                "at most {BATCH} chunks per commit"
            )));
        }
        let mut ids: Vec<u64> = req.updates.iter().map(|u| u.chunk_id).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(Status::invalid_argument(
                "a chunk appears twice in one commit",
            ));
        }
        let v = self.volume(&req.volume_id)?;
        if matches!(v.state(), VolumeState::Deleting | VolumeState::Creating) {
            return Err(Status::failed_precondition(format!(
                "volume {} is {:?}",
                v.volume_id,
                v.state()
            )));
        }
        let freeable = self
            .block_retry("block-commit-chunks", || {
                let mut refs = Refs::new(self);
                let mut ops = Vec::new();
                let mut free = Vec::new();
                for u in &req.updates {
                    let key = chunk_key(&req.volume_id, u.chunk_id);
                    let current = self
                        .block_get(CHUNKS, &key)
                        .map(|raw| BlockChunkRef::decode(raw.as_slice()))
                        .transpose()
                        .map_err(|e| decode_err("chunk", &e))?;
                    let current_id = current
                        .as_ref()
                        .and_then(|c| c.stripe.as_ref())
                        .map(|s| s.object_id.clone())
                        .unwrap_or_default();
                    // Names what it replaces, so a stale writer cannot
                    // overwrite a newer chunk.
                    if current_id != u.expected_object_id {
                        return Err(Status::aborted(format!(
                            "chunk {} of {} was changed by another writer",
                            u.chunk_id, req.volume_id
                        )));
                    }
                    if let Some(c) = current
                        && let Some(stripe) = c.stripe
                        && refs.release(&stripe.object_id, &c.owner)
                    {
                        free.push(stripe);
                    }
                    match &u.stripe {
                        Some(stripe) if stripe.object_id.is_empty() => {
                            return Err(Status::invalid_argument("a stripe needs its object id"));
                        }
                        Some(stripe) => ops.push(put(
                            CHUNKS,
                            key,
                            &BlockChunkRef {
                                chunk_id: u.chunk_id,
                                stripe: Some(stripe.clone()),
                                owner: stripe.object_id.clone(),
                            },
                        )),
                        None => ops.push(delete(CHUNKS, key)),
                    }
                }
                ops.extend(refs.into_ops());
                Ok((ops, free))
            })
            .await?;
        Ok(BlockReleaseResponse { freeable })
    }

    /// Copy every chunk of `from` (in `from_table`) to `to_id` (in
    /// `to_table`), each held by `to_id` and shared in the registry.
    async fn share_chunks(
        &self,
        from_table: &'static str,
        from_id: &str,
        from_is_owner: bool,
        to_table: &'static str,
        to_id: &str,
        requested_by: &str,
    ) -> Result<(), Status> {
        let rows = self
            .block
            .read()
            .chunks_of(from_table, from_id, 0, u64::MAX);
        for batch in rows.chunks(BATCH) {
            self.block_retry(requested_by, || {
                let mut refs = Refs::new(self);
                let mut ops = Vec::new();
                for (_, raw) in batch {
                    let r = BlockChunkRef::decode(raw.as_slice())
                        .map_err(|e| decode_err("chunk", &e))?;
                    let Some(stripe) = r.stripe.clone() else {
                        continue;
                    };
                    let owner = if from_is_owner {
                        from_id.as_bytes().to_vec()
                    } else {
                        r.owner.clone()
                    };
                    refs.share(&stripe.object_id, &owner, to_id.as_bytes())?;
                    ops.push(put(
                        to_table,
                        chunk_key(to_id, r.chunk_id),
                        &BlockChunkRef {
                            chunk_id: r.chunk_id,
                            stripe: Some(stripe),
                            owner: to_id.as_bytes().to_vec(),
                        },
                    ));
                }
                ops.extend(refs.into_ops());
                Ok((ops, ()))
            })
            .await?;
        }
        Ok(())
    }

    pub(super) async fn block_create_snapshot_impl(
        &self,
        req: BlockCreateSnapshotRequest,
    ) -> Result<BlockSnapshotResponse, Status> {
        let _serial = self.block_lock.lock().await;
        let v = self.volume(&req.volume_id)?;
        if matches!(v.state(), VolumeState::Deleting | VolumeState::Creating) {
            return Err(Status::failed_precondition(format!(
                "volume {} is {:?}",
                v.volume_id,
                v.state()
            )));
        }
        let mut snap = Snapshot {
            snapshot_id: uuid::Uuid::new_v4().to_string(),
            volume_id: v.volume_id.clone(),
            name: req.name.clone(),
            size_bytes: v.size_bytes,
            created_at: now(),
            ..Default::default()
        };
        // Creating while its chunks are recorded, a batch at a time.
        snap.set_state(SnapshotState::Creating);
        let row = snap.clone();
        self.block_retry("block-create-snapshot", || {
            Ok((vec![put(SNAPSHOTS, row.snapshot_id.clone(), &row)], ()))
        })
        .await?;
        self.share_chunks(
            CHUNKS,
            &v.volume_id,
            false,
            SNAP_CHUNKS,
            &snap.snapshot_id,
            "block-create-snapshot",
        )
        .await?;
        snap.set_state(SnapshotState::Available);
        let row = snap.clone();
        self.block_retry("block-create-snapshot", || {
            Ok((vec![put(SNAPSHOTS, row.snapshot_id.clone(), &row)], ()))
        })
        .await?;
        Ok(BlockSnapshotResponse {
            snapshot: Some(snap),
        })
    }

    pub(super) fn block_get_snapshot_impl(
        &self,
        req: &BlockGetSnapshotRequest,
    ) -> Result<BlockSnapshotResponse, Status> {
        Ok(BlockSnapshotResponse {
            snapshot: Some(self.snapshot(&req.snapshot_id)?),
        })
    }

    pub(super) fn block_list_snapshots_impl(
        &self,
        req: &BlockListSnapshotsRequest,
    ) -> BlockListSnapshotsResponse {
        let mut snapshots: Vec<Snapshot> = self
            .block
            .read()
            .table(SNAPSHOTS)
            .map(|m| {
                m.values()
                    .filter_map(|v| Snapshot::decode(v.as_slice()).ok())
                    .filter(|s| req.volume_id.is_empty() || s.volume_id == req.volume_id)
                    .collect()
            })
            .unwrap_or_default();
        snapshots.sort_by_key(|s| s.created_at);
        BlockListSnapshotsResponse { snapshots }
    }

    pub(super) async fn block_delete_snapshot_impl(
        &self,
        req: BlockDeleteSnapshotRequest,
    ) -> Result<BlockReleaseResponse, Status> {
        let _serial = self.block_lock.lock().await;
        let mut snap = self.snapshot(&req.snapshot_id)?;
        if snap.state() != SnapshotState::Deleting {
            snap.set_state(SnapshotState::Deleting);
            let row = snap.clone();
            self.block_retry("block-delete-snapshot", || {
                Ok((vec![put(SNAPSHOTS, row.snapshot_id.clone(), &row)], ()))
            })
            .await?;
        }
        let freeable = self
            .release_chunks(
                SNAP_CHUNKS,
                &snap.snapshot_id,
                true,
                "block-delete-snapshot",
            )
            .await?;
        let id = snap.snapshot_id.clone();
        self.block_retry("block-delete-snapshot", || {
            Ok((vec![delete(SNAPSHOTS, id.clone())], ()))
        })
        .await?;
        Ok(BlockReleaseResponse { freeable })
    }

    pub(super) async fn block_clone_volume_impl(
        &self,
        req: BlockCloneVolumeRequest,
    ) -> Result<BlockVolumeResponse, Status> {
        let _serial = self.block_lock.lock().await;
        let snap = self.snapshot(&req.snapshot_id)?;
        if snap.state() != SnapshotState::Available {
            return Err(Status::failed_precondition(format!(
                "snapshot {} is {:?}",
                snap.snapshot_id,
                snap.state()
            )));
        }
        if req.name.is_empty() {
            return Err(Status::invalid_argument("a clone needs a name"));
        }
        let source = self.volume(&snap.volume_id).ok();
        let mut clone = Volume {
            volume_id: uuid::Uuid::new_v4().to_string(),
            name: req.name.clone(),
            size_bytes: snap.size_bytes,
            pool: source.as_ref().map(|v| v.pool.clone()).unwrap_or_default(),
            created_at: now(),
            updated_at: now(),
            parent_snapshot_id: snap.snapshot_id.clone(),
            chunk_size_bytes: source.as_ref().map_or(CHUNK_SIZE, |v| v.chunk_size_bytes),
            ..Default::default()
        };
        clone.set_state(VolumeState::Creating);
        let row = clone.clone();
        self.block_retry("block-clone-volume", || {
            if self.block_get(NAMES, &row.name).is_some() {
                return Err(Status::already_exists(format!(
                    "volume {} already exists",
                    row.name
                )));
            }
            Ok((
                vec![
                    put(VOLUMES, row.volume_id.clone(), &row),
                    Op {
                        table: NAMES,
                        key: row.name.clone(),
                        new: Some(row.volume_id.clone().into_bytes()),
                    },
                ],
                (),
            ))
        })
        .await?;
        self.share_chunks(
            SNAP_CHUNKS,
            &snap.snapshot_id,
            true,
            CHUNKS,
            &clone.volume_id,
            "block-clone-volume",
        )
        .await?;
        clone.set_state(VolumeState::Available);
        clone.updated_at = now();
        let row = clone.clone();
        self.block_retry("block-clone-volume", || {
            Ok((vec![put(VOLUMES, row.volume_id.clone(), &row)], ()))
        })
        .await?;
        Ok(BlockVolumeResponse {
            volume: Some(clone),
        })
    }
}

impl MetaService {
    /// Every stripe a volume or snapshot refers to, each once. What the
    /// repairer walks for block storage: the chunk records here are the
    /// only record of where a block chunk's shards are.
    pub(crate) fn block_stripes(&self) -> Vec<StripeMeta> {
        let tables = self.block.read();
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for t in [CHUNKS, SNAP_CHUNKS] {
            for raw in tables.table(t).into_iter().flat_map(BTreeMap::values) {
                if let Ok(BlockChunkRef {
                    stripe: Some(s), ..
                }) = BlockChunkRef::decode(raw.as_slice())
                    && seen.insert(s.object_id.clone())
                {
                    out.push(s);
                }
            }
        }
        out
    }

    /// Add rebuilt shards' locations to every chunk record holding the
    /// stripe `object_id`, at positions it has none for. How many records
    /// changed.
    pub(crate) async fn block_add_shard_locations(
        &self,
        object_id: &[u8],
        added: &[ShardLocation],
    ) -> Result<usize, Status> {
        let _serial = self.block_lock.lock().await;
        self.block_retry("repair-block-stripe", || {
            let mut ops = Vec::new();
            let tables = self.block.read();
            for t in [CHUNKS, SNAP_CHUNKS] {
                for (key, raw) in tables.table(t).into_iter().flatten() {
                    let mut r = BlockChunkRef::decode(raw.as_slice())
                        .map_err(|e| decode_err("chunk", &e))?;
                    let Some(stripe) = r.stripe.as_mut() else {
                        continue;
                    };
                    if stripe.object_id != object_id {
                        continue;
                    }
                    let mut changed = false;
                    for loc in added {
                        if stripe.shards.iter().all(|l| l.position != loc.position) {
                            stripe.shards.push(loc.clone());
                            changed = true;
                        }
                    }
                    if changed {
                        stripe.shards.sort_by_key(|l| l.position);
                        ops.push(put(t, key.clone(), &r));
                    }
                }
            }
            let n = ops.len();
            Ok((ops, n))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    //! The rules that keep a volume's, a snapshot's and a clone's data
    //! apart: each sees what it should, and each frees only what nothing
    //! else uses.

    use super::*;
    use objectio_proto::metadata::BlockChunkUpdate;

    fn stripe(id: u8) -> StripeMeta {
        StripeMeta {
            object_id: vec![id; 16],
            data_size: 4096,
            ..Default::default()
        }
    }

    async fn volume(svc: &MetaService, name: &str) -> String {
        svc.block_create_volume_impl(BlockCreateVolumeRequest {
            name: name.into(),
            size_bytes: 64 << 20,
            ..Default::default()
        })
        .await
        .unwrap()
        .volume
        .unwrap()
        .volume_id
    }

    async fn commit(
        svc: &MetaService,
        vol: &str,
        chunk: u64,
        expected: Option<u8>,
        new: Option<u8>,
    ) -> Result<Vec<StripeMeta>, Status> {
        svc.block_commit_chunks_impl(BlockCommitChunksRequest {
            volume_id: vol.into(),
            updates: vec![BlockChunkUpdate {
                chunk_id: chunk,
                expected_object_id: expected.map(|e| vec![e; 16]).unwrap_or_default(),
                stripe: new.map(stripe),
            }],
        })
        .await
        .map(|r| r.freeable)
    }

    fn chunk_of(svc: &MetaService, vol: &str, chunk: u64) -> Option<u8> {
        svc.block_get_chunks_impl(&BlockGetChunksRequest {
            volume_id: vol.into(),
            start_chunk: chunk,
            count: 1,
        })
        .unwrap()
        .chunks
        .first()
        .and_then(|c| c.stripe.as_ref())
        .map(|s| s.object_id[0])
    }

    fn freed(stripes: &[StripeMeta]) -> Vec<u8> {
        let mut ids: Vec<u8> = stripes.iter().map(|s| s.object_id[0]).collect();
        ids.sort_unstable();
        ids
    }

    #[tokio::test]
    async fn an_overwrite_frees_the_stripe_it_replaced() {
        let svc = MetaService::new();
        let vol = volume(&svc, "v").await;
        assert!(
            commit(&svc, &vol, 0, None, Some(1))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            freed(&commit(&svc, &vol, 0, Some(1), Some(2)).await.unwrap()),
            vec![1]
        );
        assert_eq!(chunk_of(&svc, &vol, 0), Some(2));
    }

    /// A writer that does not know the current stripe cannot replace it.
    #[tokio::test]
    async fn a_stale_commit_is_refused() {
        let svc = MetaService::new();
        let vol = volume(&svc, "v").await;
        commit(&svc, &vol, 0, None, Some(1)).await.unwrap();
        let err = commit(&svc, &vol, 0, None, Some(2)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Aborted);
        assert_eq!(chunk_of(&svc, &vol, 0), Some(1));
    }

    /// The point of snapshots: overwriting a snapshotted chunk keeps the
    /// snapshot's stripe, and deleting the snapshot then frees it.
    #[tokio::test]
    async fn a_snapshot_keeps_the_stripes_it_captured() {
        let svc = MetaService::new();
        let vol = volume(&svc, "v").await;
        commit(&svc, &vol, 0, None, Some(1)).await.unwrap();
        let snap = svc
            .block_create_snapshot_impl(BlockCreateSnapshotRequest {
                volume_id: vol.clone(),
                name: "s".into(),
            })
            .await
            .unwrap()
            .snapshot
            .unwrap();
        assert_eq!(snap.state(), SnapshotState::Available);

        assert!(
            commit(&svc, &vol, 0, Some(1), Some(2))
                .await
                .unwrap()
                .is_empty(),
            "the snapshot's stripe was freed by an overwrite"
        );
        let freed_by_delete = svc
            .block_delete_snapshot_impl(BlockDeleteSnapshotRequest {
                snapshot_id: snap.snapshot_id,
            })
            .await
            .unwrap()
            .freeable;
        assert_eq!(freed(&freed_by_delete), vec![1]);
    }

    /// A clone reads its snapshot's chunks, writes its own, and frees only
    /// what is its alone.
    #[tokio::test]
    async fn a_clone_shares_until_it_writes() {
        let svc = MetaService::new();
        let vol = volume(&svc, "v").await;
        commit(&svc, &vol, 0, None, Some(1)).await.unwrap();
        commit(&svc, &vol, 1, None, Some(2)).await.unwrap();
        let snap = svc
            .block_create_snapshot_impl(BlockCreateSnapshotRequest {
                volume_id: vol.clone(),
                name: "s".into(),
            })
            .await
            .unwrap()
            .snapshot
            .unwrap();
        let clone = svc
            .block_clone_volume_impl(BlockCloneVolumeRequest {
                snapshot_id: snap.snapshot_id.clone(),
                name: "c".into(),
            })
            .await
            .unwrap()
            .volume
            .unwrap();
        assert_eq!(chunk_of(&svc, &clone.volume_id, 0), Some(1));
        assert_eq!(chunk_of(&svc, &clone.volume_id, 1), Some(2));

        // The clone's own write frees nothing: the volume and snapshot
        // still hold stripe 1.
        assert!(
            commit(&svc, &clone.volume_id, 0, Some(1), Some(9))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            chunk_of(&svc, &vol, 0),
            Some(1),
            "the clone's write reached its source"
        );

        // Deleting the source volume and the snapshot leaves stripe 2 to
        // the clone and frees stripe 1 (nobody else holds it).
        let mut all = svc
            .block_delete_volume_impl(BlockDeleteVolumeRequest {
                volume_id: vol.clone(),
            })
            .await
            .unwrap()
            .freeable;
        all.extend(
            svc.block_delete_snapshot_impl(BlockDeleteSnapshotRequest {
                snapshot_id: snap.snapshot_id,
            })
            .await
            .unwrap()
            .freeable,
        );
        assert_eq!(freed(&all), vec![1]);
        assert_eq!(chunk_of(&svc, &clone.volume_id, 1), Some(2));

        let last = svc
            .block_delete_volume_impl(BlockDeleteVolumeRequest {
                volume_id: clone.volume_id,
            })
            .await
            .unwrap()
            .freeable;
        assert_eq!(freed(&last), vec![2, 9]);
    }

    #[tokio::test]
    async fn names_are_unique_and_volumes_only_grow() {
        let svc = MetaService::new();
        let vol = volume(&svc, "v").await;
        let dup = svc
            .block_create_volume_impl(BlockCreateVolumeRequest {
                name: "v".into(),
                size_bytes: 1,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(dup.code(), tonic::Code::AlreadyExists);
        let shrink = svc
            .block_update_volume_impl(BlockUpdateVolumeRequest {
                volume_id: vol,
                size_bytes: 1,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(shrink.code(), tonic::Code::InvalidArgument);
    }

    /// A shard the repairer rebuilt where none was recorded is recorded on
    /// the volume's chunk and on the snapshot's alike.
    #[tokio::test]
    async fn rebuilt_shard_locations_reach_every_chunk_holding_the_stripe() {
        let svc = MetaService::new();
        let vol = volume(&svc, "v").await;
        commit(&svc, &vol, 0, None, Some(1)).await.unwrap();
        svc.block_create_snapshot_impl(BlockCreateSnapshotRequest {
            volume_id: vol.clone(),
            name: "s".into(),
        })
        .await
        .unwrap();
        assert_eq!(svc.block_stripes().len(), 1, "one stripe, held twice");

        let loc = ShardLocation {
            position: 5,
            node_id: vec![9; 16],
            ..Default::default()
        };
        let changed = svc
            .block_add_shard_locations(&[1; 16], std::slice::from_ref(&loc))
            .await
            .unwrap();
        assert_eq!(changed, 2);
        let stripe = &svc.block_stripes()[0];
        assert_eq!(stripe.shards, vec![loc.clone()]);
        // Already recorded: nothing to change.
        assert_eq!(
            svc.block_add_shard_locations(&[1; 16], &[loc])
                .await
                .unwrap(),
            0
        );
    }
}
