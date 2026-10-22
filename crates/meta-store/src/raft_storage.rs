// openraft::StorageError<u64> is the canonical error the trait methods
// return — it's intentionally large (wraps a full source chain). Boxing
// it throughout would obscure the call sites without any real payoff.
#![allow(clippy::result_large_err)]

//! Redb-backed [`openraft::RaftStorage`] for the metadata service.
//!
//! We implement the v1 trait and wrap it in [`openraft::storage::Adaptor`]
//! at the consumer side — that produces the v2 [`RaftLogStorage`] and
//! [`RaftStateMachine`] pair the current framework needs.
//!
//! ## Persistence layout (objectio-docs `core/meta-log.md`, B25)
//!
//! | Where                    | What                                                  |
//! |--------------------------|-------------------------------------------------------|
//! | `raft-log/` (files)      | the log: JSON `openraft::Entry<MetaTypeConfig>` records ([`crate::raft_log`]); the purged and committed log ids |
//! | redb `raft_vote`         | `"vote"`: JSON `openraft::Vote<u64>`                  |
//! | redb `raft_state`        | `"state"`: JSON [`RaftPersistentState`] (applied + membership) |
//!
//! A log append returns once it is synced, and a vote once its durable
//! commit is. Applying commits without a flush ([`Commit::Applied`]); a
//! checkpoint ([`MetaRaftStorage::checkpoint`]) makes it durable every
//! `--raft-checkpoint-ms` (200 ms) and before a snapshot is built. A crash
//! rolls the state machine back to the last checkpoint, `last_applied`
//! with it, and the entries
//! after it are applied again from the log. Every durable commit saves
//! redb's allocator state, so the database never needs a full repair.
//!
//! ## Phase R1 scope
//!
//! - Log storage: full (append, truncate, purge, read).
//! - Vote: full.
//! - State machine: applies [`MetaCommand::SetConfig`] /
//!   [`MetaCommand::DeleteConfig`] into the existing `CONFIG` redb table.
//!   All other meta mutations still write directly to redb and are not
//!   quorum-safe yet — they get migrated variant-by-variant in R2+.
//! - Snapshots: the whole state machine, streamed through a file in the
//!   snapshot directory (never held in memory: meta has a listing entry
//!   per object), so the log can be compacted (B18).
//!
//! ## A full filesystem (objectio-docs `core/meta.md`)
//!
//! openraft stops a node for good on any error from these calls, and redb
//! refuses everything after an I/O error until it is opened again. What
//! the filesystem can refuse for want of room without anything being lost
//! waits for room instead of failing: a log append or a purge record
//! (cut off and tried again, [`crate::raft_log`]), a snapshot build (waits
//! until there is room for it above the reserve, and stops before eating
//! into it). A redb commit that fails (apply, checkpoint, vote, install)
//! still fails: the database must be reopened, so the node stops and is
//! restarted, applying again from its log. The reserve
//! ([`crate::disk_space`]) keeps those from meeting a full filesystem.

use std::fmt::Debug;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, Write};
use std::ops::RangeBounds;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use openraft::{
    AnyError, EntryPayload, ErrorSubject, ErrorVerb, LogId, LogState, RaftLogReader,
    RaftSnapshotBuilder, RaftStorage, Snapshot, SnapshotMeta, StorageError, StorageIOError,
    StoredMembership, Vote,
};
use redb::{Database, ReadableTable};
use serde::{Deserialize, Serialize};

use crate::commit_metrics::Commit;
use crate::disk_space::DiskSpace;
use crate::raft::{ApplyEvent, CasOp, CasTable, MetaCommand, MetaResponse, MetaTypeConfig};
use crate::raft_log::{LogError, RaftLog};
use crate::tables;

/// How long a log write the filesystem had no room for waits before it is
/// tried again.
const LOG_ROOM_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

/// How long a snapshot that found no room waits before it is tried again.
const SNAPSHOT_ROOM_RETRY: std::time::Duration = std::time::Duration::from_secs(10);

/// How often a write still waiting for room says so.
const WAITING_TOLD_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

mod backup;
pub use backup::{BackupHeader, Edit, Forced, Voter, rows};

type NodeId = u64;
type Node = openraft::BasicNode;
type Entry = openraft::Entry<MetaTypeConfig>;

/// Single-row payload persisted under `raft_state` so a restart can
/// restore the state machine without replaying the whole log.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RaftPersistentState {
    last_applied: Option<LogId<NodeId>>,
    membership: StoredMembership<NodeId, Node>,
    /// The previous release's config version counter (the current one is
    /// `config_version` in [`tables::COUNTERS`], which snapshots carry).
    /// Still written, and read when it is ahead, so a node can go back to
    /// that release and forward again. Remove in the release after this
    /// one.
    config_version: u64,
}

/// The row of [`tables::COUNTERS`] that numbers config entries.
const CONFIG_VERSION: &str = "config_version";

fn decode_counter(b: &[u8]) -> Result<u64, StorageError<NodeId>> {
    <[u8; 8]>::try_from(b).map(u64::from_be_bytes).map_err(|_| {
        decode_err(
            "counters",
            std::io::Error::other(format!("a counter of {} bytes", b.len())),
        )
    })
}

/// Redb-backed Raft storage for meta.
///
/// Cheap to clone — internally it's an `Arc<Database>`. The openraft
/// Adaptor serializes concurrent access behind its own `RwLock`.
#[derive(Clone)]
pub struct MetaRaftStorage {
    db: Arc<Database>,
    /// Optional broadcast channel to the consumer of apply events.
    /// When set, the state machine emits one [`ApplyEvent`] per op of
    /// each committed `MultiCas` right after the redb commit. Consumers
    /// on both leader and follower use these to refresh their
    /// in-memory caches live — so reads on a just-promoted follower
    /// aren't stuck on the pre-promote snapshot.
    listener: Option<tokio::sync::mpsc::UnboundedSender<ApplyEvent>>,
    /// Where snapshots are written while they are built or received.
    snapshot_dir: PathBuf,
    /// The Raft log, in its own files (B25).
    log: Arc<parking_lot::Mutex<RaftLog>>,
    /// Entries applied since the last checkpoint: set after each apply's
    /// commit, cleared as a checkpoint starts.
    dirty: Arc<AtomicBool>,
    /// The commit index openraft last gave, written at each checkpoint.
    committed: Arc<parking_lot::Mutex<Option<LogId<NodeId>>>>,
    /// Room on the filesystem, and meta's reserve on it.
    space: Arc<DiskSpace>,
}

impl MetaRaftStorage {
    /// The storage over a shared redb database, with the log in `log_dir`
    /// and snapshots through files in `snapshot_dir` (both created if
    /// missing).
    ///
    /// # Errors
    /// The log can't be opened (I/O, or damage it won't skip), or the
    /// database still holds a log of its own ([`log_in_database`]).
    pub fn open(
        db: Arc<Database>,
        snapshot_dir: PathBuf,
        log_dir: &Path,
    ) -> Result<Self, StorageError<NodeId>> {
        log_in_database(&db, log_dir)?;
        clear_partial_snapshots(&snapshot_dir);
        let started = std::time::Instant::now();
        let log = RaftLog::open(log_dir).map_err(read_err)?;
        crate::commit_metrics::log_opened(started.elapsed());
        tracing::info!(
            "Raft log opened in {:.2} s: entries {:?}",
            started.elapsed().as_secs_f64(),
            log.range()
        );
        Ok(Self {
            db,
            listener: None,
            space: Arc::new(DiskSpace::new(log_dir, 0)),
            snapshot_dir,
            log: Arc::new(parking_lot::Mutex::new(log)),
            dirty: Arc::default(),
            committed: Arc::default(),
        })
    }

    /// Check room on the filesystem against `space` (its reserve): a
    /// snapshot is built only with room for it above the reserve. Without
    /// this, no reserve is kept.
    #[must_use]
    pub fn with_disk_space(mut self, space: Arc<DiskSpace>) -> Self {
        self.space = space;
        self
    }

    /// Run `op` on the log until the filesystem has room for it: an append
    /// or a purge record it had none for was cut off, and is tried again
    /// every [`LOG_ROOM_RETRY`]. openraft waits meanwhile (this node falls
    /// behind, or, leading, stops answering and is replaced) rather than
    /// stop for good, as it would on an error. Any other failure is
    /// returned.
    async fn until_room<T>(
        &self,
        what: &str,
        mut op: impl FnMut(&mut RaftLog) -> Result<T, LogError>,
    ) -> Result<T, StorageError<NodeId>> {
        let mut waiting: Option<(std::time::Instant, std::time::Instant)> = None;
        loop {
            let result = op(&mut self.log.lock());
            match result {
                Ok(v) => {
                    if let Some((since, _)) = waiting {
                        tracing::info!(
                            "raft log: {what} written after waiting {:.1} s for room",
                            since.elapsed().as_secs_f64()
                        );
                    }
                    return Ok(v);
                }
                Err(e) if e.is_out_of_space() => {
                    self.space.out_of_space();
                    let now = std::time::Instant::now();
                    match &mut waiting {
                        None => {
                            tracing::error!(
                                "raft log: no room for {what} ({e}); waiting for room, \
                                 retried every {LOG_ROOM_RETRY:?}"
                            );
                            waiting = Some((now, now));
                        }
                        Some((since, told)) if told.elapsed() >= WAITING_TOLD_EVERY => {
                            tracing::error!(
                                "raft log: still no room for {what} after {:.0} s ({e})",
                                since.elapsed().as_secs_f64()
                            );
                            *told = now;
                        }
                        Some(_) => {}
                    }
                    tokio::time::sleep(LOG_ROOM_RETRY).await;
                }
                Err(e) => return Err(write_err(e)),
            }
        }
    }

    /// Attach an apply-event listener. The state machine will send one
    /// event per op of every committed `MultiCas`. Cloning the storage
    /// clones the sender too (unbounded channels are multi-producer).
    #[must_use]
    pub fn with_apply_listener(
        mut self,
        listener: tokio::sync::mpsc::UnboundedSender<ApplyEvent>,
    ) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Make every entry applied so far durable, if any was applied since
    /// the last checkpoint: one durable commit that writes nothing else
    /// (and the commit index, beside the log). Run every
    /// `--raft-checkpoint-ms`, before a snapshot is built and before the log
    /// is purged, and at shutdown.
    /// Returns whether it committed.
    ///
    /// # Errors
    /// The commit fails.
    pub fn checkpoint(&self) -> Result<bool, StorageError<NodeId>> {
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return Ok(false);
        }
        let txn = self.db.begin_write().map_err(write_err)?;
        if let Err(e) = crate::commit_metrics::commit(txn, Commit::Durable) {
            self.dirty.store(true, Ordering::Release);
            return Err(write_err(e));
        }
        let committed = *self.committed.lock();
        if committed.is_some() {
            let bytes = serde_json::to_vec(&committed).map_err(|e| encode_err("committed", e))?;
            // Not synced, and not needed: a lost one (no room for it, say)
            // costs only a later re-apply.
            if let Err(e) = self.log.lock().save_committed(&bytes) {
                tracing::warn!("raft log: commit index not saved: {e}");
            }
        }
        Ok(true)
    }

    // ---------------------------------------------------------------
    // Internal helpers — each is called from a trait method below.
    // These wrap redb transactions + JSON (de)serialization and convert
    // errors to openraft's StorageError.
    // ---------------------------------------------------------------

    fn load_state(&self) -> Result<RaftPersistentState, StorageError<NodeId>> {
        let txn = self.db.begin_read().map_err(read_err)?;
        let table = match txn.open_table(tables::RAFT_STATE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(RaftPersistentState::default());
            }
            Err(e) => return Err(read_err(e)),
        };
        match table.get("state").map_err(read_err)? {
            Some(v) => serde_json::from_slice(v.value()).map_err(|e| decode_err("raft_state", e)),
            None => Ok(RaftPersistentState::default()),
        }
    }

    /// Apply a committed [`MetaCommand`] into `txn`, the apply batch's
    /// transaction, which also moves `last_applied` forward: atomic from
    /// the perspective of a restart. Events for the listener go to
    /// `events`, sent once the batch has committed.
    ///
    /// A command that can't apply because of what it says or what the
    /// store holds is answered [`MetaResponse::Rejected`], having written
    /// nothing, on every node alike: an error here stops the node's Raft,
    /// and every node applies the same entry, so it stopped them all, and
    /// again at each restart. Only the storage failing is an error.
    fn apply_command(
        txn: &redb::WriteTransaction,
        state: &mut RaftPersistentState,
        cmd: &MetaCommand,
        events: &mut Vec<ApplyEvent>,
    ) -> Result<MetaResponse, StorageError<NodeId>> {
        if let Some(reason) = cmd.refusal() {
            return Ok(rejected(reason));
        }
        match cmd {
            MetaCommand::SetConfig {
                key,
                value,
                updated_by,
                updated_at,
            } => {
                // Counted in a state-machine table, not in `raft_state`: a
                // node that joins by snapshot then numbers the next entry
                // as the leader does.
                let version = {
                    let mut t = txn.open_table(tables::COUNTERS).map_err(write_err)?;
                    let stored = t
                        .get(CONFIG_VERSION)
                        .map_err(write_err)?
                        .map(|v| decode_counter(v.value()))
                        .transpose()?
                        .unwrap_or(0);
                    let version = stored.max(state.config_version) + 1;
                    t.insert(CONFIG_VERSION, version.to_be_bytes().as_slice())
                        .map_err(write_err)?;
                    version
                };
                state.config_version = version;
                // Encode as the same protobuf shape meta already consumes,
                // so non-Raft readers (who still read the CONFIG table
                // directly) don't need migration code.
                use prost::Message;
                let entry = objectio_proto::metadata::ConfigEntry {
                    key: key.clone(),
                    value: value.clone(),
                    updated_at: *updated_at,
                    updated_by: updated_by.clone(),
                    version,
                };
                let bytes = entry.encode_to_vec();
                {
                    let mut t = txn.open_table(tables::CONFIG).map_err(write_err)?;
                    t.insert(key.as_str(), bytes.as_slice())
                        .map_err(write_err)?;
                }
                // Followers refresh their config cache from this, as they
                // do for a MultiCas on the config table. Without it a
                // setting changed through the leader stayed stale on every
                // other replica until restart.
                events.push(config_event(key, Some(bytes)));
                Ok(MetaResponse::ConfigSet { version })
            }
            MetaCommand::DeleteConfig { key } => {
                let existed = {
                    let mut t = txn.open_table(tables::CONFIG).map_err(write_err)?;
                    t.remove(key.as_str()).map_err(write_err)?.is_some()
                };
                events.push(config_event(key, None));
                Ok(MetaResponse::ConfigDeleted { existed })
            }
            MetaCommand::SetOsdAdminState {
                node_id,
                state: new_state,
                requested_by: _,
            } => {
                // Same hex encoding the rest of the meta store uses to
                // key OsdNodes in the OSD_NODES table.
                let key = hex_encode_16(node_id);
                let (found, changed) = {
                    let mut t = txn.open_table(tables::OSD_NODES).map_err(write_err)?;
                    // Read current bytes, release the borrow, then write
                    // — otherwise redb's access-guard holds a borrow of
                    // `t` that conflicts with the later insert.
                    let current = t
                        .get(key.as_str())
                        .map_err(read_err)?
                        .map(|v| v.value().to_vec());
                    match current {
                        Some(bytes) => {
                            let mut node = match <crate::types::OsdNode as crate::types::record::Record>::from_bytes(&bytes) {
                                Ok(node) => node,
                                Err(e) => {
                                    return Ok(rejected(format!("OSD record {key} doesn't decode: {e}")));
                                }
                            };
                            let changed = node.admin_state != *new_state;
                            if changed {
                                node.admin_state = *new_state;
                                let new_bytes = Ok::<_, crate::types::record::RecordError>(
                                    crate::types::record::Record::to_bytes(&node),
                                )
                                .map_err(|e| decode_err("OsdNode", e))?;
                                t.insert(key.as_str(), new_bytes.as_slice())
                                    .map_err(write_err)?;
                                // Every node's cache follows, not only the
                                // leader's: a follower that later leads would
                                // otherwise write its stale state back when
                                // the OSD next registers.
                                events.push(ApplyEvent::MultiCasOp {
                                    table: CasTable::Named("osd_nodes".into()),
                                    key: key.clone(),
                                    new_value: Some(new_bytes.clone()),
                                });
                            }
                            (true, changed)
                        }
                        // Unknown node_id — command succeeds (idempotent) but
                        // the caller learns via `found: false`.
                        None => (false, false),
                    }
                };
                Ok(MetaResponse::OsdAdminStateSet { changed, found })
            }
            MetaCommand::MultiCas {
                ops,
                requested_by: _,
            } => apply_multi_cas(txn, ops, events),
            // Each in turn, against what the one before it left, as
            // consecutive entries would be. A conflict or a refusal answers
            // that command alone; an error (storage) fails the whole entry,
            // as it would fail the entry holding the command that met it.
            MetaCommand::Batch(cmds) => cmds
                .iter()
                .map(|cmd| match cmd {
                    MetaCommand::Batch(_) => Ok(rejected("a batch inside a batch".into())),
                    cmd => Self::apply_command(txn, state, cmd, events),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(MetaResponse::Batch),
        }
    }
}

/// A command refused as it applied ([`MetaResponse::Rejected`]): logged, as
/// it is on every node, since a proposer should have refused it first.
fn rejected(reason: String) -> MetaResponse {
    tracing::warn!("a committed command was refused, and wrote nothing: {reason}");
    MetaResponse::Rejected { reason }
}

/// The event a config key's change sends the service, as a MultiCas on the
/// config table would.
fn config_event(key: &str, new_value: Option<Vec<u8>>) -> ApplyEvent {
    ApplyEvent::MultiCasOp {
        table: CasTable::Config,
        key: key.to_string(),
        new_value,
    }
}

/// Refuse a database that still holds a Raft log of its own (`raft_logs`):
/// one from a development build before format level 8, which kept its log
/// there, or from a 0.1.0-rc.2 meta node of a cluster that never finished
/// setting up (no OSD ever registered), which keeps it there until then.
/// Opened with an empty log beside it, the node would lose entries it
/// acknowledged.
fn log_in_database(db: &Database, log_dir: &Path) -> Result<(), StorageError<NodeId>> {
    use redb::TableHandle;
    let txn = db.begin_read().map_err(read_err)?;
    let tables = txn.list_tables().map_err(read_err)?;
    if tables.into_iter().any(|t| t.name() == "raft_logs") {
        return Err(read_err(std::io::Error::other(format!(
            "this meta node's Raft log is in its database, not in {}: it was written by a \
             development build from before 0.1.0, or by 0.1.0-rc.2 in a cluster no OSD has \
             joined yet. Upgrade from 0.1.0-rc.2 once an OSD has registered (that moves the \
             log); a development build's cluster is reinstalled, not upgraded",
            log_dir.display()
        ))));
    }
    Ok(())
}

/// Write `state` (`last_applied`, the config version, membership) into
/// `txn`, so it commits with whatever the entry being applied wrote.
fn write_state(
    txn: &redb::WriteTransaction,
    state: &RaftPersistentState,
) -> Result<(), StorageError<NodeId>> {
    let mut t = txn.open_table(tables::RAFT_STATE).map_err(write_err)?;
    let encoded = serde_json::to_vec(state).map_err(|e| encode_err("raft_state", e))?;
    t.insert("state", encoded.as_slice()).map_err(write_err)?;
    Ok(())
}

/// Apply a [`MetaCommand::MultiCas`] into the apply batch's `txn`.
///
/// Two-pass: (1) read every op's current value and compare against its
/// expected; collect all mismatches. If any mismatch, nothing is written.
/// (2) write/delete every op's new value.
///
/// The read+write happens in the same write-txn so interleaving with
/// other state-machine applies is impossible (openraft serializes
/// applies, and redb's write-txn is exclusive anyway).
fn apply_multi_cas(
    txn: &redb::WriteTransaction,
    ops: &[CasOp],
    events: &mut Vec<ApplyEvent>,
) -> Result<MetaResponse, StorageError<NodeId>> {
    // The operation count and the tables were checked by the caller
    // (`MetaCommand::refusal`): at most `MAX_OPS`, each table named.
    let mut failed_indices: Vec<u32> = Vec::new();

    // Pass 1: verify every expected, writing nothing yet. Redb tables are
    // scoped to the txn, so we re-open per op to keep the lifetimes simple.
    for (idx, op) in ops.iter().enumerate() {
        let name = cas_table_name(&op.table);
        let tdef: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new(name);
        let current: Option<Vec<u8>> = match txn.open_table(tdef) {
            Ok(t) => t
                .get(op.key.as_str())
                .map_err(read_err)?
                .map(|v| v.value().to_vec()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            // A table of other types than `&str -> &[u8]` (a `Named` one):
            // what the store holds, the same on every node, not a failure.
            Err(
                e @ (redb::TableError::TableTypeMismatch { .. }
                | redb::TableError::TableIsMultimap(_)
                | redb::TableError::TableIsNotMultimap(_)
                | redb::TableError::TypeDefinitionChanged { .. }),
            ) => {
                return Ok(rejected(format!("table {name}: {e}")));
            }
            Err(e) => return Err(read_err(e)),
        };
        if current.as_deref() != op.expected.as_deref() {
            failed_indices.push(idx as u32);
        }
    }

    if !failed_indices.is_empty() {
        // Nothing written; `last_applied` still advances with the batch so
        // the entry isn't retried. The failed indices go back to the
        // client so it can refresh and retry.
        return Ok(MetaResponse::MultiCasConflict { failed_indices });
    }

    // Pass 2: apply every write/delete in the same txn.
    for op in ops {
        let name = cas_table_name(&op.table);
        let tdef: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new(name);
        let mut t = txn.open_table(tdef).map_err(write_err)?;
        match &op.new_value {
            Some(bytes) => {
                t.insert(op.key.as_str(), bytes.as_slice())
                    .map_err(write_err)?;
            }
            None => {
                t.remove(op.key.as_str()).map_err(write_err)?;
            }
        }
    }

    events.extend(ops.iter().map(|op| ApplyEvent::MultiCasOp {
        table: op.table.clone(),
        key: op.key.clone(),
        new_value: op.new_value.clone(),
    }));
    Ok(MetaResponse::MultiCasOk)
}

/// Map a [`CasTable`] tag to the redb table name used by the rest of the
/// meta store. Stays in lock-step with `tables.rs` — if you add a new
/// long-lived table, add a `CasTable` variant here too.
pub fn cas_table_name(t: &CasTable) -> &str {
    match t {
        CasTable::Buckets => "buckets",
        CasTable::BucketPolicies => "bucket_policies",
        CasTable::IcebergNamespaces => "iceberg_namespaces",
        CasTable::IcebergTables => "iceberg_tables",
        CasTable::DeltaShares => "delta_shares",
        CasTable::DeltaTables => "delta_tables",
        CasTable::DeltaRecipients => "delta_recipients",
        CasTable::Config => "config",
        CasTable::Pools => "pools",
        CasTable::Tenants => "tenants",
        CasTable::IamPolicies => "iam_policies",
        CasTable::Users => "users",
        CasTable::Groups => "groups",
        CasTable::AccessKeys => "access_keys",
        CasTable::IcebergWarehouses => "iceberg_warehouses",
        CasTable::PolicyAttachments => "policy_attachments",
        CasTable::DataFilters => "data_filters",
        CasTable::MultipartUploads => "multipart_uploads",
        CasTable::ObjectListings => "object_listings",
        CasTable::PlacementGroups => "placement_groups",
        CasTable::UnityCatalogs => "unity_catalogs",
        CasTable::UnitySchemas => "unity_schemas",
        CasTable::UnityTables => "unity_tables",
        CasTable::UnityFunctions => "unity_functions",
        CasTable::UnityVolumes => "unity_volumes",
        CasTable::UnityModels => "unity_models",
        CasTable::UnityModelVersions => "unity_model_versions",
        CasTable::Named(n) => n,
    }
}

/// 16-byte node id → 32-char lowercase hex, matching how MetaStore keys
/// OsdNodes. Tiny local impl so the crate doesn't need a `hex` dep just
/// for this one call site.
fn hex_encode_16(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------
// Error-conversion helpers.
//
// openraft's `StorageError<NodeId>` wants a subject/verb/source triple.
// We slot redb/serde errors into those at the call site so every
// failure mode has a descriptive category.
// ---------------------------------------------------------------

fn write_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<NodeId> {
    StorageError::IO {
        source: StorageIOError::new(ErrorSubject::Logs, ErrorVerb::Write, AnyError::new(&e)),
    }
}

fn read_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<NodeId> {
    StorageError::IO {
        source: StorageIOError::new(ErrorSubject::Logs, ErrorVerb::Read, AnyError::new(&e)),
    }
}

fn decode_err<E: std::error::Error + Send + Sync + 'static>(
    what: &str,
    e: E,
) -> StorageError<NodeId> {
    let tagged = std::io::Error::other(format!("decode {what}: {e}"));
    StorageError::IO {
        source: StorageIOError::new(ErrorSubject::Logs, ErrorVerb::Read, AnyError::new(&tagged)),
    }
}

fn encode_err<E: std::error::Error + Send + Sync + 'static>(
    what: &str,
    e: E,
) -> StorageError<NodeId> {
    let tagged = std::io::Error::other(format!("encode {what}: {e}"));
    StorageError::IO {
        source: StorageIOError::new(ErrorSubject::Logs, ErrorVerb::Write, AnyError::new(&tagged)),
    }
}

// ---------------------------------------------------------------
// RaftLogReader — log reads via try_get_log_entries.
// ---------------------------------------------------------------

impl RaftLogReader<MetaTypeConfig> for MetaRaftStorage {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry>, StorageError<NodeId>> {
        let start = match range.start_bound() {
            std::ops::Bound::Included(&i) => i,
            std::ops::Bound::Excluded(&i) => i.saturating_add(1),
            std::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(&i) => i.saturating_add(1),
            std::ops::Bound::Excluded(&i) => i,
            std::ops::Bound::Unbounded => u64::MAX,
        };

        let records = self.log.lock().read(start, end).map_err(read_err)?;
        records
            .iter()
            .map(|b| serde_json::from_slice(b).map_err(|e| decode_err("raft log entry", e)))
            .collect()
    }
}

// ---------------------------------------------------------------
// Snapshots: every state-machine table, dumped and installed whole.
// ---------------------------------------------------------------

/// Tables Raft keeps for itself. Every other table in the database is
/// state-machine state and goes into a snapshot.
use crate::tables::RAFT_TABLES;

const SNAPSHOT_MAGIC: &[u8] = b"OBIO-META-SNAPSHOT-1\n";

/// A key or value larger than this in a snapshot is damage, not data.
const SNAPSHOT_FIELD_LIMIT: u64 = 1 << 30;

impl MetaRaftStorage {
    /// Write every state-machine table to `out`, and return the Raft state
    /// they correspond to: one read transaction, so the two agree, while
    /// writes go on (redb readers see a fixed version).
    fn write_state_machine(
        db: &Database,
        out: &mut impl Write,
    ) -> Result<RaftPersistentState, StorageError<NodeId>> {
        let txn = db.begin_read().map_err(read_err)?;
        let state = Self::state_in(&txn)?;
        Self::write_tables(&txn, out)?;
        Ok(state)
    }

    /// The Raft state as `txn` sees it.
    fn state_in(txn: &redb::ReadTransaction) -> Result<RaftPersistentState, StorageError<NodeId>> {
        match txn.open_table(tables::RAFT_STATE) {
            Ok(t) => match t.get("state").map_err(read_err)? {
                Some(v) => {
                    serde_json::from_slice(v.value()).map_err(|e| decode_err("raft_state", e))
                }
                None => Ok(RaftPersistentState::default()),
            },
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(RaftPersistentState::default()),
            Err(e) => Err(read_err(e)),
        }
    }

    /// Every state-machine table as `txn` sees it, as a snapshot carries
    /// them.
    fn write_tables(
        txn: &redb::ReadTransaction,
        out: &mut impl Write,
    ) -> Result<(), StorageError<NodeId>> {
        use redb::ReadableTableMetadata as _;
        let io = |e: std::io::Error| encode_err("snapshot", e);
        // Only `&str -> &[u8]` tables are carried; a table of another kind
        // fails the snapshot (and a backup) rather than be left out of it.
        if let Some(t) = txn.list_multimap_tables().map_err(read_err)?.next() {
            return Err(read_err(std::io::Error::other(format!(
                "multimap table {} can't be carried in a snapshot",
                redb::MultimapTableHandle::name(&t)
            ))));
        }
        let mut names: Vec<String> = txn
            .list_tables()
            .map_err(read_err)?
            .map(|h| redb::TableHandle::name(&h).to_string())
            .filter(|n| !RAFT_TABLES.contains(&n.as_str()))
            .collect();
        names.sort();

        out.write_all(SNAPSHOT_MAGIC).map_err(io)?;
        put_u64(out, names.len() as u64).map_err(io)?;
        for name in &names {
            let table = txn
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(name))
                .map_err(read_err)?;
            put_bytes(out, name.as_bytes()).map_err(io)?;
            put_u64(out, table.len().map_err(read_err)?).map_err(io)?;
            for row in table.iter().map_err(read_err)? {
                let (k, v) = row.map_err(read_err)?;
                put_bytes(out, k.value().as_bytes()).map_err(io)?;
                put_bytes(out, v.value()).map_err(io)?;
            }
        }
        out.flush().map_err(io)?;
        Ok(())
    }

    /// Replace every state-machine table with the snapshot read from `src`,
    /// and record the position it was taken at, in one transaction: a crash,
    /// or a snapshot that turns out damaged part way, leaves the old state
    /// whole; nothing is committed until the last row has been read.
    fn install_state_machine(
        db: &Database,
        src: &mut impl BufRead,
        meta: &SnapshotMeta<NodeId, Node>,
    ) -> Result<(), StorageError<NodeId>> {
        let bad = |e: String| decode_err("snapshot", std::io::Error::other(e));
        let txn = db.begin_write().map_err(write_err)?;
        {
            let existing: Vec<String> = txn
                .list_tables()
                .map_err(write_err)?
                .map(|h| redb::TableHandle::name(&h).to_string())
                .filter(|n| !RAFT_TABLES.contains(&n.as_str()))
                .collect();
            for name in &existing {
                txn.delete_table(redb::TableDefinition::<&str, &[u8]>::new(name))
                    .map_err(write_err)?;
            }

            let mut magic = vec![0u8; SNAPSHOT_MAGIC.len()];
            src.read_exact(&mut magic)
                .map_err(|e| bad(format!("snapshot is truncated: {e}")))?;
            if magic != SNAPSHOT_MAGIC {
                return Err(bad("not a meta snapshot".into()));
            }
            for _ in 0..get_u64(src).map_err(bad)? {
                let name = get_string(src).map_err(bad)?;
                if RAFT_TABLES.contains(&name.as_str()) {
                    return Err(bad(format!("snapshot carries Raft's own table {name}")));
                }
                let mut t = txn
                    .open_table(redb::TableDefinition::<&str, &[u8]>::new(&name))
                    .map_err(write_err)?;
                for _ in 0..get_u64(src).map_err(bad)? {
                    let k = get_string(src).map_err(bad)?;
                    let v = get_bytes(src).map_err(bad)?;
                    t.insert(k.as_str(), v.as_slice()).map_err(write_err)?;
                }
            }
            if !src.fill_buf().map_err(|e| bad(e.to_string()))?.is_empty() {
                return Err(bad("trailing bytes after the last table".into()));
            }

            let mut state = match txn.open_table(tables::RAFT_STATE) {
                Ok(t) => match t.get("state").map_err(write_err)? {
                    Some(v) => serde_json::from_slice(v.value())
                        .map_err(|e| decode_err("raft_state", e))?,
                    None => RaftPersistentState::default(),
                },
                Err(e) => return Err(write_err(e)),
            };
            state.last_applied = meta.last_log_id;
            state.membership = meta.last_membership.clone();
            // The leader's count, not this node's own.
            if let Some(v) = txn
                .open_table(tables::COUNTERS)
                .map_err(write_err)?
                .get(CONFIG_VERSION)
                .map_err(write_err)?
            {
                state.config_version = decode_counter(v.value())?;
            }
            let mut t = txn.open_table(tables::RAFT_STATE).map_err(write_err)?;
            let encoded = serde_json::to_vec(&state).map_err(|e| encode_err("raft_state", e))?;
            t.insert("state", encoded.as_slice()).map_err(write_err)?;
        }
        crate::commit_metrics::commit(txn, Commit::Durable).map_err(write_err)
    }

    /// Build a snapshot of the state machine as it is now, and make it the
    /// current one (see [`Self::current_snapshot`]).
    async fn snapshot_of(&self) -> Result<Snapshot<MetaTypeConfig>, StorageError<NodeId>> {
        self.try_snapshot_of().await.map_err(|e| match e {
            Unbuilt::NoRoom(why) => encode_err("snapshot", std::io::Error::other(why)),
            Unbuilt::Failed(e) => e,
        })
    }

    /// [`Self::snapshot_of`], telling a filesystem without room for it
    /// (which a later try may have) from a failure. Whatever it wrote is
    /// removed when it fails.
    async fn try_snapshot_of(&self) -> Result<Snapshot<MetaTypeConfig>, Unbuilt> {
        let (db, dir) = (Arc::clone(&self.db), self.snapshot_dir.clone());
        let space = Arc::clone(&self.space);
        tokio::task::spawn_blocking(move || {
            let started = std::time::Instant::now();
            let (file, path) = snapshot_file(&dir, "build").map_err(Unbuilt::Failed)?;
            let mut guarded = RoomFor::new(&file, &space);
            let mut out = BufWriter::with_capacity(1 << 20, &mut guarded);
            let written = Self::write_state_machine(&db, &mut out);
            drop(out);
            let state = match written {
                Ok(state) => state,
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    return Err(guarded.no_room.map_or(Unbuilt::Failed(e), Unbuilt::NoRoom));
                }
            };
            let len = file.metadata().map_or(0, |m| m.len());
            crate::commit_metrics::snapshot_built(
                usize::try_from(len).unwrap_or(usize::MAX),
                started.elapsed(),
            );
            let snapshot_id = format!(
                "meta-snap-{}-{}",
                state.last_applied.map_or(0, |id| id.leader_id.term),
                state.last_applied.map_or(0, |id| id.index)
            );
            let meta = SnapshotMeta {
                last_log_id: state.last_applied,
                last_membership: state.membership,
                snapshot_id,
            };
            if let Err(e) = keep_snapshot(&dir, &file, &path, &meta) {
                discard_unkept(&dir, &path, &meta.snapshot_id);
                return Err(if objectio_common::error::is_out_of_space(&e) {
                    space.out_of_space();
                    Unbuilt::NoRoom(format!("keeping the snapshot: {e}"))
                } else {
                    Unbuilt::Failed(encode_err("snapshot", e))
                });
            }
            Ok(())
        })
        .await
        .map_err(|e| Unbuilt::Failed(encode_err("snapshot", std::io::Error::other(e))))??;
        self.current_snapshot()
            .await
            .map_err(Unbuilt::Failed)?
            .ok_or_else(|| {
                Unbuilt::Failed(encode_err(
                    "snapshot",
                    std::io::Error::other("just built, now gone"),
                ))
            })
    }

    /// One try at a snapshot for openraft: `Ok(None)`, with why, when it
    /// must wait for room, or (`after_waiting`) for entries past a
    /// snapshot installed meanwhile.
    async fn try_build_snapshot(
        &self,
        after_waiting: bool,
    ) -> Result<Result<Snapshot<MetaTypeConfig>, String>, StorageError<NodeId>> {
        let dir = self.snapshot_dir.clone();
        let kept = tokio::task::spawn_blocking(move || current_snapshot_files(&dir))
            .await
            .map_err(|e| decode_err("snapshot", std::io::Error::other(e)))??;
        // The last one's size: what this one needs, give or take.
        let estimate = kept
            .as_ref()
            .and_then(|(data, _)| std::fs::metadata(data).ok())
            .map_or(0, |m| m.len());
        if let Err(no_room) = self.space.admit_snapshot(estimate) {
            return Ok(Err(no_room.to_string()));
        }
        // openraft takes only a snapshot past the one it knows of; one
        // received from the leader while this one waited may be as far
        // as the state machine is.
        if after_waiting
            && let Some((_, meta)) = &kept
            && meta.last_log_id >= self.load_state()?.last_applied
        {
            return Ok(Err(format!(
                "snapshot {} is as far as the state machine; waiting for entries past it",
                meta.snapshot_id
            )));
        }
        // The state captured is made durable first: the log is purged up to
        // it next, and a crash must not roll `last_applied` back below that.
        self.checkpoint()?;
        match self.try_snapshot_of().await {
            Ok(snapshot) => Ok(Ok(snapshot)),
            Err(Unbuilt::NoRoom(why)) => Ok(Err(why)),
            Err(Unbuilt::Failed(e)) => Err(e),
        }
    }

    /// The current snapshot: the last one built or installed, exactly as it
    /// was. openraft sends a follower the snapshot it last recorded, and
    /// checks the follower's answer against that snapshot's position: one
    /// built afresh at a later position made the leader's check fail (a
    /// panic that stopped its Raft core).
    async fn current_snapshot(
        &self,
    ) -> Result<Option<Snapshot<MetaTypeConfig>>, StorageError<NodeId>> {
        let dir = self.snapshot_dir.clone();
        let found = tokio::task::spawn_blocking(move || current_snapshot_files(&dir))
            .await
            .map_err(|e| decode_err("snapshot", std::io::Error::other(e)))??;
        let Some((data, meta)) = found else {
            return Ok(None);
        };
        let file = tokio::fs::File::open(&data)
            .await
            .map_err(|e| decode_err("snapshot", e))?;
        Ok(Some(Snapshot {
            meta,
            snapshot: Box::new(file),
        }))
    }
}

/// Keep the snapshot written to `file` (at `tmp`) as the current one, as
/// `meta` describes it: `<id>.data`, then `<id>.meta`, whose presence says
/// the pair is whole. Older snapshots are deleted.
fn keep_snapshot(
    dir: &Path,
    file: &std::fs::File,
    tmp: &Path,
    meta: &SnapshotMeta<NodeId, Node>,
) -> std::io::Result<()> {
    file.sync_all()?;
    let data = dir.join(format!("{}.data", meta.snapshot_id));
    std::fs::rename(tmp, &data)?;
    let meta_tmp = dir.join(format!("{}.meta.tmp", meta.snapshot_id));
    {
        let mut f = std::fs::File::create(&meta_tmp)?;
        f.write_all(&serde_json::to_vec(meta).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
    }
    std::fs::rename(&meta_tmp, dir.join(format!("{}.meta", meta.snapshot_id)))?;
    std::fs::File::open(dir).and_then(|d| d.sync_all())?;
    // Everything else: older snapshots, and what a crash left half-written.
    for e in std::fs::read_dir(dir)?.filter_map(Result::ok) {
        let name = e.file_name();
        let name = name.to_string_lossy();
        let ours = name == format!("{}.data", meta.snapshot_id)
            || name == format!("{}.meta", meta.snapshot_id);
        if !ours {
            let _ = std::fs::remove_file(e.path());
        }
    }
    Ok(())
}

/// Remove what a snapshot that failed to be kept as `id` left: its file at
/// `tmp`, and its data and half-written description unless its
/// description was written (it is then whole, and current).
fn discard_unkept(dir: &Path, tmp: &Path, id: &str) {
    let _ = std::fs::remove_file(tmp);
    if !dir.join(format!("{id}.meta")).exists() {
        let _ = std::fs::remove_file(dir.join(format!("{id}.data")));
        let _ = std::fs::remove_file(dir.join(format!("{id}.meta.tmp")));
    }
}

/// Remove what snapshots a crash interrupted left in `dir` (a file being
/// built or copied, a description half-written, data without its
/// description): on a full filesystem it holds room the next snapshot
/// needs. Nothing is being written at open.
fn clear_partial_snapshots(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.filter_map(Result::ok) {
        let path = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        let partial = name.ends_with(".snap")
            || name.ends_with(".tmp")
            || (name.ends_with(".data") && !path.with_extension("meta").exists());
        if partial {
            tracing::info!(
                "removing {}, left by an unfinished snapshot",
                path.display()
            );
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Why a snapshot wasn't built.
enum Unbuilt {
    /// The filesystem had no room for it, or not above the reserve: a
    /// later try may.
    NoRoom(String),
    Failed(StorageError<NodeId>),
}

/// How much a snapshot writes between two looks at the free space.
const SNAPSHOT_ROOM_EVERY: u64 = 16 << 20;

/// A snapshot's file as it is written: the write stops, out of space,
/// before it eats into meta's reserve, and says when the filesystem had no
/// room for it.
struct RoomFor<'a> {
    file: &'a std::fs::File,
    space: &'a DiskSpace,
    /// Written since the free space was last looked at.
    unchecked: u64,
    /// Why the write was stopped for want of room, if it was.
    no_room: Option<String>,
}

impl<'a> RoomFor<'a> {
    fn new(file: &'a std::fs::File, space: &'a DiskSpace) -> Self {
        Self {
            file,
            space,
            unchecked: 0,
            no_room: None,
        }
    }
}

impl Write for RoomFor<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.unchecked >= SNAPSHOT_ROOM_EVERY {
            self.unchecked = 0;
            if let Err(e) = self.space.admit_snapshot(SNAPSHOT_ROOM_EVERY) {
                self.no_room = Some(e.to_string());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    e.to_string(),
                ));
            }
        }
        match (&mut &*self.file).write(buf) {
            Ok(n) => {
                self.unchecked += n as u64;
                Ok(n)
            }
            Err(e) => {
                if objectio_common::error::is_out_of_space(&e) {
                    self.space.out_of_space();
                    self.no_room = Some(e.to_string());
                }
                Err(e)
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&mut &*self.file).flush()
    }
}

/// A kept snapshot: its data file and its description.
type KeptSnapshot = (PathBuf, SnapshotMeta<NodeId, Node>);

/// The current snapshot's data file and description, if there is one.
fn current_snapshot_files(dir: &Path) -> Result<Option<KeptSnapshot>, StorageError<NodeId>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(decode_err("snapshot dir", e)),
    };
    let mut best: Option<KeptSnapshot> = None;
    for e in entries.filter_map(Result::ok) {
        let path = e.path();
        if path.extension().and_then(|x| x.to_str()) != Some("meta") {
            continue;
        }
        let Some(meta) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<SnapshotMeta<NodeId, Node>>(&b).ok())
        else {
            continue;
        };
        let data = path.with_extension("data");
        if !data.exists() {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(_, b)| meta.last_log_id > b.last_log_id)
        {
            best = Some((data, meta));
        }
    }
    Ok(best)
}

/// A new file in `dir` for a snapshot, open for reading and writing, and
/// its path (to unlink once it no longer needs a name).
fn snapshot_file(dir: &Path, what: &str) -> Result<(std::fs::File, PathBuf), StorageError<NodeId>> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::fs::create_dir_all(dir).map_err(|e| encode_err("snapshot dir", e))?;
    let path = dir.join(format!(
        "{what}-{}-{}.snap",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| encode_err("snapshot file", e))?;
    Ok((file, path))
}

fn put_u64(out: &mut impl Write, v: u64) -> std::io::Result<()> {
    out.write_all(&v.to_le_bytes())
}

fn put_bytes(out: &mut impl Write, b: &[u8]) -> std::io::Result<()> {
    put_u64(out, b.len() as u64)?;
    out.write_all(b)
}

fn get_u64(src: &mut impl Read) -> Result<u64, String> {
    let mut b = [0u8; 8];
    src.read_exact(&mut b)
        .map_err(|e| format!("snapshot is truncated: {e}"))?;
    Ok(u64::from_le_bytes(b))
}

fn get_bytes(src: &mut impl Read) -> Result<Vec<u8>, String> {
    let n = get_u64(src)?;
    if n > SNAPSHOT_FIELD_LIMIT {
        return Err(format!("snapshot field of {n} bytes: damaged"));
    }
    let mut b = vec![0u8; usize::try_from(n).map_err(|e| e.to_string())?];
    src.read_exact(&mut b)
        .map_err(|e| format!("snapshot is truncated: {e}"))?;
    Ok(b)
}

fn get_string(src: &mut impl Read) -> Result<String, String> {
    String::from_utf8(get_bytes(src)?).map_err(|e| e.to_string())
}

impl RaftSnapshotBuilder<MetaTypeConfig> for MetaRaftStorage {
    /// A snapshot of the state machine as it is. openraft stops for good on
    /// an error here, so one the filesystem has no room for (above the
    /// reserve) waits, and is tried again every [`SNAPSHOT_ROOM_RETRY`]
    /// until it fits. openraft builds in a task of its own: Raft goes on
    /// meanwhile, without compacting its log.
    async fn build_snapshot(&mut self) -> Result<Snapshot<MetaTypeConfig>, StorageError<NodeId>> {
        let mut waiting: Option<(std::time::Instant, std::time::Instant)> = None;
        loop {
            match self.try_build_snapshot(waiting.is_some()).await? {
                Ok(snapshot) => {
                    if let Some((since, _)) = waiting {
                        tracing::info!(
                            "raft snapshot built after waiting {:.0} s",
                            since.elapsed().as_secs_f64()
                        );
                    }
                    return Ok(snapshot);
                }
                Err(why) => {
                    let now = std::time::Instant::now();
                    match &mut waiting {
                        None => {
                            tracing::warn!(
                                "raft snapshot waits ({why}); the log isn't compacted meanwhile"
                            );
                            waiting = Some((now, now));
                        }
                        Some((since, told)) if told.elapsed() >= WAITING_TOLD_EVERY => {
                            tracing::warn!(
                                "raft snapshot still waiting after {:.0} s ({why})",
                                since.elapsed().as_secs_f64()
                            );
                            *told = now;
                        }
                        Some(_) => {}
                    }
                    tokio::time::sleep(SNAPSHOT_ROOM_RETRY).await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------
// RaftStorage — the big one. Vote, log append/truncate/purge, apply.
// ---------------------------------------------------------------

#[allow(deprecated)] // RaftStorage is deprecated but the Adaptor still consumes it.
impl RaftStorage<MetaTypeConfig> for MetaRaftStorage {
    type LogReader = MetaRaftStorage;
    type SnapshotBuilder = MetaRaftStorage;

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        let txn = self.db.begin_write().map_err(write_err)?;
        {
            let mut t = txn.open_table(tables::RAFT_VOTE).map_err(write_err)?;
            let bytes = serde_json::to_vec(vote).map_err(|e| encode_err("raft_vote", e))?;
            t.insert("vote", bytes.as_slice()).map_err(write_err)?;
        }
        crate::commit_metrics::commit(txn, Commit::Durable).map_err(write_err)?;
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        let txn = self.db.begin_read().map_err(read_err)?;
        let table = match txn.open_table(tables::RAFT_VOTE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(read_err(e)),
        };
        match table.get("vote").map_err(read_err)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).map_err(|e| decode_err("raft_vote", e))?,
            )),
            None => Ok(None),
        }
    }

    async fn get_log_state(&mut self) -> Result<LogState<MetaTypeConfig>, StorageError<NodeId>> {
        let log = self.log.lock();
        let last_purged_log_id: Option<LogId<NodeId>> = log
            .purged()
            .map_err(read_err)?
            .map(|b| serde_json::from_slice(&b).map_err(|e| decode_err("raft log purged", e)))
            .transpose()?
            .flatten();
        let last = match log.range() {
            Some((_, last)) => log.read(last, last + 1).map_err(read_err)?.pop(),
            None => None,
        };
        let last_log_id = match last {
            Some(bytes) => Some(
                serde_json::from_slice::<Entry>(&bytes)
                    .map_err(|e| decode_err("raft log last entry", e))?
                    .log_id,
            ),
            None => last_purged_log_id,
        };
        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        *self.committed.lock() = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        let log = self.log.lock();
        let Some(bytes) = log.committed().map_err(read_err)? else {
            return Ok(None);
        };
        // Written without a sync: unreadable means not saved.
        let Ok(committed) = serde_json::from_slice::<Option<LogId<NodeId>>>(&bytes) else {
            return Ok(None);
        };
        // Never past what the log holds (a log cut back after a crash).
        let last = log.range().map(|(_, l)| l);
        Ok(committed.filter(|c| last.is_some_and(|l| c.index <= l)))
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn append_to_log<I>(&mut self, entries: I) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry> + Send,
    {
        let records = entries
            .into_iter()
            .map(|e| {
                serde_json::to_vec(&e)
                    .map(|b| (e.log_id.index, e.log_id.leader_id.term, b))
                    .map_err(|err| encode_err("raft log entry", err))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Synced before it returns; with no room, cut off and tried again
        // until there is.
        self.until_room("an append", |log| log.append(&records))
            .await
    }

    async fn delete_conflict_logs_since(
        &mut self,
        log_id: LogId<NodeId>,
    ) -> Result<(), StorageError<NodeId>> {
        self.log
            .lock()
            .truncate_from(log_id.index)
            .map_err(write_err)
    }

    async fn purge_logs_upto(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        // Never purge past the durable state machine: a crash would roll
        // `last_applied` back below entries no longer in the log.
        self.checkpoint()?;
        let caller = serde_json::to_vec(&Some(log_id)).map_err(|e| encode_err("purged", e))?;
        // The record is a small file replaced whole; with no room, nothing
        // is purged until there is.
        self.until_room("a purge record", |log| {
            log.record_purge(log_id.index, &caller)
        })
        .await?;
        self.log.lock().purge_upto(log_id.index).map_err(write_err)
    }

    async fn last_applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, Node>), StorageError<NodeId>> {
        let state = self.load_state()?;
        Ok((state.last_applied, state.membership))
    }

    async fn apply_to_state_machine(
        &mut self,
        entries: &[Entry],
    ) -> Result<Vec<MetaResponse>, StorageError<NodeId>> {
        let mut state = self.load_state()?;
        let mut replies = Vec::with_capacity(entries.len());
        let mut events = Vec::new();
        // The whole batch in one transaction, with `last_applied` and
        // membership: one commit for every entry openraft hands over, and a
        // crash leaves either all of them applied or none. It isn't flushed:
        // the next checkpoint makes it durable, and a crash before that
        // rolls it back whole, to be applied again from the log.
        let txn = self.db.begin_write().map_err(write_err)?;
        for entry in entries {
            match &entry.payload {
                EntryPayload::Blank => replies.push(MetaResponse::Ok),
                EntryPayload::Normal(cmd) => {
                    replies.push(Self::apply_command(&txn, &mut state, cmd, &mut events)?);
                }
                EntryPayload::Membership(mem) => {
                    state.membership = StoredMembership::new(Some(entry.log_id), mem.clone());
                    replies.push(MetaResponse::Ok);
                }
            }
            state.last_applied = Some(entry.log_id);
        }
        write_state(&txn, &state)?;
        crate::commit_metrics::commit(txn, Commit::Applied).map_err(write_err)?;
        // After the commit, so a checkpoint that clears it covers it.
        self.dirty.store(true, Ordering::Release);

        // Fan out apply events once the batch is on disk. Send is
        // non-fatal: a dropped receiver (service crash, not yet wired up)
        // means the event is silently discarded. Consumers resync from redb
        // on next load_from_store so the cache can't stay permanently stale.
        if let Some(tx) = self.listener.as_ref() {
            for ev in events {
                let _ = tx.send(ev);
            }
        }
        Ok(replies)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<tokio::fs::File>, StorageError<NodeId>> {
        // A file with no name: it lives as long as the receive does.
        let (file, path) = snapshot_file(&self.snapshot_dir, "recv")?;
        let _ = std::fs::remove_file(&path);
        Ok(Box::new(tokio::fs::File::from_std(file)))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, Node>,
        snapshot: Box<tokio::fs::File>,
    ) -> Result<(), StorageError<NodeId>> {
        // The whole state machine, replaced. (This used to only move
        // last_applied forward with no data, so a replica caught up from a
        // snapshot believed it was current while missing everything.)
        use tokio::io::AsyncSeekExt as _;
        let started = std::time::Instant::now();
        let mut file = *snapshot;
        file.seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(|e| decode_err("snapshot", e))?;
        let file = file.into_std().await;
        let (db, meta_owned, dir) = (
            Arc::clone(&self.db),
            meta.clone(),
            self.snapshot_dir.clone(),
        );
        tokio::task::spawn_blocking(move || {
            let mut src = BufReader::with_capacity(1 << 20, &file);
            Self::install_state_machine(&db, &mut src, &meta_owned)?;
            // And kept as this node's current snapshot, as the leader
            // described it: what it sends on if it leads.
            let mut received = &file;
            received
                .seek(std::io::SeekFrom::Start(0))
                .map_err(|e| decode_err("snapshot", e))?;
            let (copy, tmp) = snapshot_file(&dir, "recv")?;
            std::io::copy(&mut received, &mut &copy)
                .map(drop)
                .and_then(|()| keep_snapshot(&dir, &copy, &tmp, &meta_owned))
                .map_err(|e| {
                    discard_unkept(&dir, &tmp, &meta_owned.snapshot_id);
                    encode_err("snapshot", e)
                })
        })
        .await
        .map_err(|e| decode_err("snapshot", std::io::Error::other(e)))??;
        crate::commit_metrics::snapshot_installed(started.elapsed());
        if let Some(tx) = self.listener.as_ref() {
            let _ = tx.send(ApplyEvent::SnapshotInstalled);
        }
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<MetaTypeConfig>>, StorageError<NodeId>> {
        // The last one built or installed, exactly: openraft checks what a
        // follower answers against it.
        self.current_snapshot().await
    }
}

/// A snapshot directory of its own for each test storage: a node keeps
/// one current snapshot in its directory and clears out the rest.
#[cfg(test)]
fn test_snapshot_dir() -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "objectio-meta-store-test-snapshots/{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::MAX_OPS;
    use openraft::{CommittedLeaderId, EntryPayload, LogId};
    use tempfile::TempDir;

    fn storage() -> (TempDir, MetaRaftStorage) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("meta.db");
        let db = Database::create(&path).unwrap();
        let s = MetaRaftStorage::open(
            Arc::new(db),
            test_snapshot_dir(),
            &dir.path().join("raft-log"),
        )
        .unwrap();
        (dir, s)
    }

    fn log_id(term: u64, index: u64) -> LogId<NodeId> {
        LogId::new(CommittedLeaderId::new(term, 1), index)
    }

    pub(super) fn normal_entry(index: u64, cmd: MetaCommand) -> Entry {
        Entry {
            log_id: log_id(1, index),
            payload: EntryPayload::Normal(cmd),
        }
    }

    /// A config entry applied on two replicas is byte-identical: the
    /// timestamp comes from the command, not from each node's clock.
    #[tokio::test]
    async fn a_config_entry_is_the_same_on_every_replica() {
        let cmd = MetaCommand::SetConfig {
            key: "k".into(),
            value: b"v".to_vec(),
            updated_by: "t".into(),
            updated_at: 1_700_000_000,
        };
        let mut stored = Vec::new();
        for _ in 0..2 {
            let (_d, mut s) = storage();
            s.apply_to_state_machine(&[normal_entry(1, cmd.clone())])
                .await
                .unwrap();
            let txn = s.db.begin_read().unwrap();
            let t = txn.open_table(tables::CONFIG).unwrap();
            stored.push(t.get("k").unwrap().unwrap().value().to_vec());
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }
        assert_eq!(stored[0], stored[1]);
    }

    /// `last_applied` commits with the entry's writes: once an entry is
    /// applied, a restart (which reads the stored state) doesn't apply it
    /// again.
    #[tokio::test]
    async fn an_applied_entry_is_recorded_as_applied_in_the_same_commit() {
        for cmd in [
            MetaCommand::SetConfig {
                key: "k".into(),
                value: b"v".to_vec(),
                updated_by: "t".into(),
                updated_at: 0,
            },
            MetaCommand::DeleteConfig { key: "k".into() },
            MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("t".into()),
                    key: "k".into(),
                    expected: None,
                    new_value: Some(b"x".to_vec()),
                }],
                requested_by: "t".into(),
            },
            // A conflict applies nothing, but is still applied.
            MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("t".into()),
                    key: "k".into(),
                    expected: Some(b"never".to_vec()),
                    new_value: Some(b"y".to_vec()),
                }],
                requested_by: "t".into(),
            },
        ] {
            let (_d, mut s) = storage();
            s.apply_to_state_machine(&[normal_entry(5, cmd.clone())])
                .await
                .unwrap();
            let stored = s.load_state().unwrap();
            assert_eq!(stored.last_applied, Some(log_id(1, 5)), "{cmd:?}");
        }
    }

    /// The config version moves with the entry too, so it can't be counted
    /// twice by an entry applied again after a crash.
    #[tokio::test]
    async fn the_config_version_is_stored_with_the_entry() {
        let (_d, mut s) = storage();
        let cmd = MetaCommand::SetConfig {
            key: "k".into(),
            value: b"v".to_vec(),
            updated_by: "t".into(),
            updated_at: 0,
        };
        s.apply_to_state_machine(&[normal_entry(1, cmd)])
            .await
            .unwrap();
        assert_eq!(s.load_state().unwrap().config_version, 1);
    }

    #[tokio::test]
    async fn vote_round_trip() {
        let (_d, mut s) = storage();
        assert!(s.read_vote().await.unwrap().is_none());
        let v = Vote::new(7, 42);
        s.save_vote(&v).await.unwrap();
        let back = s.read_vote().await.unwrap().unwrap();
        assert_eq!(back.leader_id().get_term(), 7);
    }

    #[tokio::test]
    async fn append_read_truncate_purge() {
        let (_d, mut s) = storage();
        let entries = vec![
            normal_entry(
                1,
                MetaCommand::SetConfig {
                    key: "a".into(),
                    value: b"1".to_vec(),
                    updated_by: "t".into(),
                    updated_at: 0,
                },
            ),
            normal_entry(
                2,
                MetaCommand::SetConfig {
                    key: "b".into(),
                    value: b"2".to_vec(),
                    updated_by: "t".into(),
                    updated_at: 0,
                },
            ),
            normal_entry(
                3,
                MetaCommand::SetConfig {
                    key: "c".into(),
                    value: b"3".to_vec(),
                    updated_by: "t".into(),
                    updated_at: 0,
                },
            ),
        ];
        s.append_to_log(entries).await.unwrap();

        let got = s.try_get_log_entries(1..=3).await.unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].log_id.index, 1);

        // Truncate conflict starting at 2 → only index 1 remains.
        s.delete_conflict_logs_since(log_id(1, 2)).await.unwrap();
        let got = s.try_get_log_entries(0..=10).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].log_id.index, 1);

        // Purge up to 1 → empty + last_purged = 1.
        s.purge_logs_upto(log_id(1, 1)).await.unwrap();
        let got = s.try_get_log_entries(0..=10).await.unwrap();
        assert!(got.is_empty());
        let ls = s.get_log_state().await.unwrap();
        assert_eq!(ls.last_purged_log_id.unwrap().index, 1);
    }

    #[tokio::test]
    async fn apply_set_and_delete_config() {
        let (_d, mut s) = storage();
        let set = normal_entry(
            1,
            MetaCommand::SetConfig {
                key: "license/active".into(),
                value: b"signed-license-bytes".to_vec(),
                updated_by: "console".into(),
                updated_at: 0,
            },
        );
        let del = normal_entry(
            2,
            MetaCommand::DeleteConfig {
                key: "license/active".into(),
            },
        );

        let r = s.apply_to_state_machine(&[set]).await.unwrap();
        assert!(matches!(r[0], MetaResponse::ConfigSet { version: 1 }));

        let (last, _mem) = s.last_applied_state().await.unwrap();
        assert_eq!(last.unwrap().index, 1);

        let r = s.apply_to_state_machine(&[del]).await.unwrap();
        assert!(matches!(
            r[0],
            MetaResponse::ConfigDeleted { existed: true }
        ));
    }

    #[tokio::test]
    async fn multi_cas_all_ok() {
        let (_d, mut s) = storage();
        // Seed: prior iceberg table row.
        let seed = normal_entry(
            1,
            MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergTables,
                    key: "ns/tbl".into(),
                    expected: None,
                    new_value: Some(b"v1".to_vec()),
                }],
                requested_by: "seed".into(),
            },
        );
        let r = s.apply_to_state_machine(&[seed]).await.unwrap();
        assert!(matches!(r[0], MetaResponse::MultiCasOk));

        // Cross-table atomic update: rewrite the iceberg row AND
        // insert a bucket-policy row in one shot.
        let txn = normal_entry(
            2,
            MetaCommand::MultiCas {
                ops: vec![
                    CasOp {
                        table: CasTable::IcebergTables,
                        key: "ns/tbl".into(),
                        expected: Some(b"v1".to_vec()),
                        new_value: Some(b"v2".to_vec()),
                    },
                    CasOp {
                        table: CasTable::BucketPolicies,
                        key: "mybucket".into(),
                        expected: None,
                        new_value: Some(b"policy-json".to_vec()),
                    },
                ],
                requested_by: "txn".into(),
            },
        );
        let r = s.apply_to_state_machine(&[txn]).await.unwrap();
        assert!(matches!(r[0], MetaResponse::MultiCasOk));
    }

    #[tokio::test]
    async fn multi_cas_conflict_aborts_all() {
        let (_d, mut s) = storage();
        // Seed a row at v1.
        let seed = normal_entry(
            1,
            MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergTables,
                    key: "ns/a".into(),
                    expected: None,
                    new_value: Some(b"v1".to_vec()),
                }],
                requested_by: "seed".into(),
            },
        );
        s.apply_to_state_machine(&[seed]).await.unwrap();

        // Attempt cross-table update where op[1]'s expected is wrong.
        // Op[0] would succeed in isolation; with MultiCas, the whole
        // command must abort and no writes land.
        let bad = normal_entry(
            2,
            MetaCommand::MultiCas {
                ops: vec![
                    CasOp {
                        table: CasTable::IcebergTables,
                        key: "ns/a".into(),
                        expected: Some(b"v1".to_vec()),
                        new_value: Some(b"v2".to_vec()),
                    },
                    CasOp {
                        table: CasTable::BucketPolicies,
                        key: "mybucket".into(),
                        expected: Some(b"not-there".to_vec()), // wrong
                        new_value: Some(b"policy-json".to_vec()),
                    },
                ],
                requested_by: "txn".into(),
            },
        );
        let r = s.apply_to_state_machine(&[bad]).await.unwrap();
        match &r[0] {
            MetaResponse::MultiCasConflict { failed_indices } => {
                assert_eq!(failed_indices, &vec![1]);
            }
            other => panic!("expected MultiCasConflict, got {other:?}"),
        }

        // Confirm op[0] was NOT applied — row is still v1, not v2.
        let txn = s.db.begin_read().unwrap();
        let t = txn
            .open_table(redb::TableDefinition::<&str, &[u8]>::new("iceberg_tables"))
            .unwrap();
        let v = t.get("ns/a").unwrap().unwrap().value().to_vec();
        assert_eq!(v, b"v1");

        // And that `last_applied` still advanced — so the conflict entry
        // isn't retried on leader restart.
        let (last, _) = s.last_applied_state().await.unwrap();
        assert_eq!(last.unwrap().index, 2);
    }

    /// A batch (meta's group commit) is applied as its commands would be as
    /// consecutive entries: each answered on its own, a conflict failing
    /// only its command, each seeing what the ones before it wrote.
    #[tokio::test]
    async fn a_batch_is_applied_as_its_commands_one_after_another() {
        let (_d, mut s) = storage();
        let put = |key: &str, expected: Option<&[u8]>, new: &[u8]| MetaCommand::MultiCas {
            ops: vec![CasOp {
                table: CasTable::IcebergTables,
                key: key.into(),
                expected: expected.map(<[u8]>::to_vec),
                new_value: Some(new.to_vec()),
            }],
            requested_by: "batch".into(),
        };
        let batch = MetaCommand::Batch(vec![
            put("ns/a", None, b"a1"),
            // Sees the write before it in the same entry.
            put("ns/a", Some(b"a1"), b"a2"),
            // Conflicts: alone.
            put("ns/b", Some(b"never"), b"b1"),
            put("ns/c", None, b"c1"),
            MetaCommand::SetConfig {
                key: "k".into(),
                value: b"v".to_vec(),
                updated_by: "batch".into(),
                updated_at: 1,
            },
        ]);
        let r = s
            .apply_to_state_machine(&[normal_entry(1, batch)])
            .await
            .unwrap();
        let MetaResponse::Batch(answers) = &r[0] else {
            panic!("expected a batch's answers, got {:?}", r[0]);
        };
        assert_eq!(answers.len(), 5);
        assert!(matches!(answers[0], MetaResponse::MultiCasOk));
        assert!(matches!(answers[1], MetaResponse::MultiCasOk));
        assert!(
            matches!(&answers[2], MetaResponse::MultiCasConflict { failed_indices } if failed_indices == &vec![0])
        );
        assert!(matches!(answers[3], MetaResponse::MultiCasOk));
        assert!(matches!(answers[4], MetaResponse::ConfigSet { version: 1 }));

        let txn = s.db.begin_read().unwrap();
        let t = txn
            .open_table(redb::TableDefinition::<&str, &[u8]>::new("iceberg_tables"))
            .unwrap();
        assert_eq!(t.get("ns/a").unwrap().unwrap().value(), b"a2");
        assert!(t.get("ns/b").unwrap().is_none());
        assert_eq!(t.get("ns/c").unwrap().unwrap().value(), b"c1");
        let (last, _) = s.last_applied_state().await.unwrap();
        assert_eq!(last.unwrap().index, 1);
    }

    /// A batch inside a batch is never written; one in the log is answered
    /// as refused, alone, rather than applied some way or stopping Raft.
    #[tokio::test]
    async fn a_batch_inside_a_batch_is_refused() {
        let (_d, mut s) = storage();
        let nested = MetaCommand::Batch(vec![
            MetaCommand::Batch(vec![]),
            MetaCommand::DeleteConfig { key: "k".into() },
        ]);
        let r = s
            .apply_to_state_machine(&[normal_entry(1, nested)])
            .await
            .unwrap();
        let MetaResponse::Batch(answers) = &r[0] else {
            panic!("expected a batch's answers, got {:?}", r[0]);
        };
        assert!(matches!(answers[0], MetaResponse::Rejected { .. }));
        assert!(matches!(
            answers[1],
            MetaResponse::ConfigDeleted { existed: false }
        ));
        assert_eq!(s.last_applied_state().await.unwrap().0, Some(log_id(1, 1)));
    }

    fn create(table: CasTable, key: &str) -> CasOp {
        CasOp {
            table,
            key: key.into(),
            expected: None,
            new_value: Some(key.as_bytes().to_vec()),
        }
    }

    fn multi_cas(ops: Vec<CasOp>) -> MetaCommand {
        MetaCommand::MultiCas {
            ops,
            requested_by: "test".into(),
        }
    }

    /// A command that can never apply, already in the log: every node
    /// answers it as refused, writes none of it, and counts the entry as
    /// applied, so neither it nor a restart re-applying it stops Raft. The
    /// entries applied with it are applied as ever. (An oversized
    /// compare-and-set used to fail the apply: Raft stopped on every node,
    /// and each restart stopped again at the same entry.)
    #[tokio::test]
    async fn a_command_that_can_never_apply_is_refused_and_the_log_goes_on() {
        let (_d, mut s) = storage();
        // A table of other types, as a `Named` op could meet.
        {
            let txn = s.db.begin_write().unwrap();
            txn.open_table(redb::TableDefinition::<u64, u64>::new("numbers"))
                .unwrap()
                .insert(1, 1)
                .unwrap();
            txn.commit().unwrap();
        }
        let oversized = multi_cas(
            (0..=MAX_OPS)
                .map(|i| create(CasTable::IcebergTables, &format!("big{i}")))
                .collect(),
        );
        let raft_own = multi_cas(vec![
            create(CasTable::IcebergTables, "beside-raft"),
            CasOp {
                table: CasTable::Named("raft_state".into()),
                key: "state".into(),
                expected: None,
                new_value: Some(b"{}".to_vec()),
            },
        ]);
        let unnamed = multi_cas(vec![create(CasTable::Named(String::new()), "x")]);
        let other_types = multi_cas(vec![
            create(CasTable::IcebergTables, "beside-numbers"),
            create(CasTable::Named("numbers".into()), "x"),
        ]);
        let entries = vec![
            normal_entry(
                1,
                multi_cas(vec![create(CasTable::IcebergTables, "before")]),
            ),
            normal_entry(2, oversized),
            normal_entry(3, raft_own),
            normal_entry(4, unnamed),
            normal_entry(5, other_types),
            normal_entry(6, multi_cas(vec![create(CasTable::IcebergTables, "after")])),
        ];
        let r = s.apply_to_state_machine(&entries).await.unwrap();
        assert!(matches!(r[0], MetaResponse::MultiCasOk));
        for (i, answer) in r.iter().enumerate().take(5).skip(1) {
            assert!(
                matches!(answer, MetaResponse::Rejected { .. }),
                "entry {}: {answer:?}",
                i + 1
            );
        }
        assert!(matches!(r[5], MetaResponse::MultiCasOk));
        assert_eq!(s.last_applied_state().await.unwrap().0, Some(log_id(1, 6)));

        let txn = s.db.begin_read().unwrap();
        let t = txn
            .open_table(redb::TableDefinition::<&str, &[u8]>::new("iceberg_tables"))
            .unwrap();
        assert!(t.get("before").unwrap().is_some());
        assert!(t.get("after").unwrap().is_some());
        for refused in ["big0", "beside-raft", "beside-numbers"] {
            assert!(t.get(refused).unwrap().is_none(), "{refused} was written");
        }
        drop(t);
        drop(txn);
        // Raft's own state is its own still.
        assert!(s.load_state().unwrap().last_applied.is_some());

        // Applied again, as after a restart that rolled back to an earlier
        // checkpoint: the same answers.
        let again = s.apply_to_state_machine(&entries[1..5]).await.unwrap();
        assert!(
            again
                .iter()
                .all(|a| matches!(a, MetaResponse::Rejected { .. }))
        );
    }

    /// An OSD record that doesn't decode refuses the admin-state change on
    /// it, the same on every node, rather than stopping Raft.
    #[tokio::test]
    async fn an_admin_state_change_on_a_damaged_osd_record_is_refused() {
        let (_d, mut s) = storage();
        {
            let txn = s.db.begin_write().unwrap();
            txn.open_table(tables::OSD_NODES)
                .unwrap()
                .insert(
                    hex_encode_16(&[3; 16]).as_str(),
                    b"\xffnot a record".as_slice(),
                )
                .unwrap();
            txn.commit().unwrap();
        }
        let r = s
            .apply_to_state_machine(&[normal_entry(
                1,
                MetaCommand::SetOsdAdminState {
                    node_id: [3; 16],
                    state: objectio_common::OsdAdminState::Out,
                    requested_by: "test".into(),
                },
            )])
            .await
            .unwrap();
        assert!(matches!(r[0], MetaResponse::Rejected { .. }), "{:?}", r[0]);
        assert_eq!(s.last_applied_state().await.unwrap().0, Some(log_id(1, 1)));
    }

    /// Setting an OSD's admin state tells every node's listener, not only
    /// the leader: a follower that later leads must not hold the old state.
    #[tokio::test]
    async fn an_osd_admin_state_change_reaches_the_listener() {
        use crate::types::record::Record;
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::create(dir.path().join("meta.db")).unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ApplyEvent>();
        let mut s = MetaRaftStorage::open(db, test_snapshot_dir(), &dir.path().join("raft-log"))
            .unwrap()
            .with_apply_listener(tx);
        let node = crate::types::OsdNode {
            node_id: [7; 16],
            address: "http://osd:9200".into(),
            disk_ids: Vec::new(),
            topology: None,
            disk_capacity_bytes: Vec::new(),
            admin_state: objectio_common::OsdAdminState::In,
            te_segment: String::new(),
        };
        let put = normal_entry(
            1,
            MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("osd_nodes".into()),
                    key: hex_encode_16(&[7; 16]),
                    expected: None,
                    new_value: Some(node.to_bytes()),
                }],
                requested_by: "test".into(),
            },
        );
        let out = normal_entry(
            2,
            MetaCommand::SetOsdAdminState {
                node_id: [7; 16],
                state: objectio_common::OsdAdminState::Out,
                requested_by: "test".into(),
            },
        );
        s.apply_to_state_machine(&[put, out]).await.unwrap();
        let _registered = rx.try_recv().unwrap();
        let ApplyEvent::MultiCasOp { new_value, .. } = rx.try_recv().unwrap() else {
            panic!("no event for the admin state change");
        };
        let seen = crate::types::OsdNode::from_bytes(&new_value.unwrap()).unwrap();
        assert_eq!(seen.admin_state, objectio_common::OsdAdminState::Out);
    }

    #[tokio::test]
    async fn apply_listener_receives_one_event_per_op() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("meta.db");
        let db = Arc::new(Database::create(&path).unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ApplyEvent>();
        let mut s = MetaRaftStorage::open(db, test_snapshot_dir(), &dir.path().join("raft-log"))
            .unwrap()
            .with_apply_listener(tx);

        let e = normal_entry(
            1,
            MetaCommand::MultiCas {
                ops: vec![
                    CasOp {
                        table: CasTable::Buckets,
                        key: "b1".into(),
                        expected: None,
                        new_value: Some(b"v1".to_vec()),
                    },
                    CasOp {
                        table: CasTable::IcebergTables,
                        key: "ns/t".into(),
                        expected: None,
                        new_value: Some(b"v2".to_vec()),
                    },
                    CasOp {
                        table: CasTable::Buckets,
                        key: "b2".into(),
                        expected: None,
                        new_value: None, // delete — none to begin with, still reports as delete event
                    },
                ],
                requested_by: "test".into(),
            },
        );
        s.apply_to_state_machine(&[e]).await.unwrap();

        // Three ops → three events, in declaration order.
        let events: Vec<ApplyEvent> = (0..3).map(|_| rx.try_recv().unwrap()).collect();
        assert!(rx.try_recv().is_err(), "no more events expected");

        match &events[0] {
            ApplyEvent::MultiCasOp {
                table,
                key,
                new_value,
            } => {
                assert_eq!(table, &CasTable::Buckets);
                assert_eq!(key, "b1");
                assert_eq!(new_value.as_deref(), Some(&b"v1"[..]));
            }
            other => panic!("unexpected {other:?}"),
        }
        match &events[1] {
            ApplyEvent::MultiCasOp { table, key, .. } => {
                assert_eq!(table, &CasTable::IcebergTables);
                assert_eq!(key, "ns/t");
            }
            other => panic!("unexpected {other:?}"),
        }
        match &events[2] {
            ApplyEvent::MultiCasOp {
                table,
                key,
                new_value,
            } => {
                assert_eq!(table, &CasTable::Buckets);
                assert_eq!(key, "b2");
                assert!(new_value.is_none(), "delete op");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_listener_not_called_on_conflict() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("meta.db");
        let db = Arc::new(Database::create(&path).unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ApplyEvent>();
        let mut s = MetaRaftStorage::open(db, test_snapshot_dir(), &dir.path().join("raft-log"))
            .unwrap()
            .with_apply_listener(tx);

        // Seed b1=v1.
        let seed = normal_entry(
            1,
            MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Buckets,
                    key: "b1".into(),
                    expected: None,
                    new_value: Some(b"v1".to_vec()),
                }],
                requested_by: "seed".into(),
            },
        );
        s.apply_to_state_machine(&[seed]).await.unwrap();
        // Consume the seed event.
        let _ = rx.try_recv().unwrap();

        // Now try a conflict MultiCas — should NOT emit events because
        // the writes didn't land.
        let bad = normal_entry(
            2,
            MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Buckets,
                    key: "b1".into(),
                    expected: Some(b"wrong".to_vec()),
                    new_value: Some(b"v2".to_vec()),
                }],
                requested_by: "conflict".into(),
            },
        );
        let r = s.apply_to_state_machine(&[bad]).await.unwrap();
        assert!(matches!(r[0], MetaResponse::MultiCasConflict { .. }));

        assert!(
            rx.try_recv().is_err(),
            "conflict should not emit apply events"
        );
    }

    fn set_config(index: u64, value: &str) -> Entry {
        normal_entry(
            index,
            MetaCommand::SetConfig {
                key: "k".into(),
                value: value.as_bytes().to_vec(),
                updated_by: "t".into(),
                updated_at: 0,
            },
        )
    }

    /// Copy a node's files as a crash leaves them: while still open.
    fn crash_copy(from: &Path, to: &Path) {
        std::fs::create_dir_all(to.join("raft-log")).unwrap();
        std::fs::copy(from.join("meta.db"), to.join("meta.db")).unwrap();
        for f in std::fs::read_dir(from.join("raft-log")).unwrap() {
            let f = f.unwrap().path();
            std::fs::copy(&f, to.join("raft-log").join(f.file_name().unwrap())).unwrap();
        }
    }

    #[tokio::test]
    async fn after_a_crash_the_state_is_the_checkpoints_and_the_log_brings_it_back() {
        let dir = TempDir::new().unwrap();
        let db = Database::create(dir.path().join("meta.db")).unwrap();
        let mut s = MetaRaftStorage::open(
            Arc::new(db),
            test_snapshot_dir(),
            &dir.path().join("raft-log"),
        )
        .unwrap();
        let (e1, e2) = (set_config(1, "one"), set_config(2, "two"));
        s.append_to_log([e1.clone(), e2.clone()]).await.unwrap();
        s.apply_to_state_machine(&[e1]).await.unwrap();
        assert!(s.checkpoint().unwrap());
        assert!(!s.checkpoint().unwrap(), "nothing applied since");
        s.apply_to_state_machine(std::slice::from_ref(&e2))
            .await
            .unwrap();

        let crashed = TempDir::new().unwrap();
        crash_copy(dir.path(), crashed.path());
        drop(s);

        let repaired = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&repaired);
        let db = Database::builder()
            .set_repair_callback(move |_| r.store(true, Ordering::Relaxed))
            .create(crashed.path().join("meta.db"))
            .unwrap();
        assert!(!repaired.load(Ordering::Relaxed), "a full repair ran");
        let mut s = MetaRaftStorage::open(
            Arc::new(db),
            test_snapshot_dir(),
            &crashed.path().join("raft-log"),
        )
        .unwrap();
        // Back at the checkpoint, the second entry still in the log.
        let (last, _) = s.last_applied_state().await.unwrap();
        assert_eq!(last.unwrap().index, 1);
        let state = s.get_log_state().await.unwrap();
        assert_eq!(state.last_log_id.unwrap().index, 2);
        let again = s.try_get_log_entries(2..3).await.unwrap();
        assert_eq!(again.len(), 1);
        // Applied again, to the same state as the first time: the same
        // config version.
        let r = s.apply_to_state_machine(&again).await.unwrap();
        assert!(
            matches!(r[0], MetaResponse::ConfigSet { version: 2 }),
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn a_database_holding_its_own_raft_log_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("meta.db");
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let def: redb::TableDefinition<u64, &[u8]> =
                    redb::TableDefinition::new("raft_logs");
                let mut t = txn.open_table(def).unwrap();
                let bytes = serde_json::to_vec(&set_config(1, "x")).unwrap();
                t.insert(1, bytes.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }
        let db = Database::create(&path).unwrap();
        let log_dir = dir.path().join("raft-log");
        let Err(e) = MetaRaftStorage::open(Arc::new(db), test_snapshot_dir(), &log_dir) else {
            panic!("opened a database whose log is in it");
        };
        assert!(e.to_string().contains("Raft log is in its database"), "{e}");
        assert!(!RaftLog::exists(&log_dir), "a log was started beside it");
    }

    #[tokio::test]
    async fn restart_preserves_applied_state() {
        // Write a config, drop the storage, open a new one against the
        // same file, confirm state survived the restart.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("meta.db");
        {
            let db = Database::create(&path).unwrap();
            let mut s = MetaRaftStorage::open(
                Arc::new(db),
                test_snapshot_dir(),
                &dir.path().join("raft-log"),
            )
            .unwrap();
            let e = normal_entry(
                1,
                MetaCommand::SetConfig {
                    key: "k".into(),
                    value: b"v".to_vec(),
                    updated_by: "t".into(),
                    updated_at: 0,
                },
            );
            s.apply_to_state_machine(&[e]).await.unwrap();
        }
        {
            let db = Database::create(&path).unwrap();
            let mut s = MetaRaftStorage::open(
                Arc::new(db),
                test_snapshot_dir(),
                &dir.path().join("raft-log"),
            )
            .unwrap();
            let (last, _) = s.last_applied_state().await.unwrap();
            assert_eq!(last.unwrap().index, 1);
        }
    }
}

#[cfg(test)]
mod snapshot_tests {
    //! A snapshot carries the whole state machine to a replica that needs
    //! it, and replaces what that replica had.

    use super::tests::normal_entry;
    use super::*;
    use openraft::{CommittedLeaderId, LogId};
    use redb::ReadableTable;
    use tempfile::TempDir;

    fn storage() -> (TempDir, MetaRaftStorage) {
        let dir = TempDir::new().unwrap();
        let db = Database::create(dir.path().join("meta.db")).unwrap();
        let s = MetaRaftStorage::open(
            Arc::new(db),
            test_snapshot_dir(),
            &dir.path().join("raft-log"),
        )
        .unwrap();
        (dir, s)
    }

    fn put(s: &MetaRaftStorage, table: &str, key: &str, value: &[u8]) {
        let txn = s.db.begin_write().unwrap();
        {
            let mut t = txn
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(table))
                .unwrap();
            t.insert(key, value).unwrap();
        }
        txn.commit().unwrap();
    }

    fn rows(s: &MetaRaftStorage, table: &str) -> Vec<(String, Vec<u8>)> {
        let txn = s.db.begin_read().unwrap();
        let Ok(t) = txn.open_table(redb::TableDefinition::<&str, &[u8]>::new(table)) else {
            return Vec::new();
        };
        t.iter()
            .unwrap()
            .map(|r| {
                let (k, v) = r.unwrap();
                (k.value().to_string(), v.value().to_vec())
            })
            .collect()
    }

    fn at(index: u64) -> SnapshotMeta<NodeId, Node> {
        SnapshotMeta {
            last_log_id: Some(LogId::new(CommittedLeaderId::new(3, 1), index)),
            last_membership: StoredMembership::default(),
            snapshot_id: format!("t-{index}"),
        }
    }

    /// The leader's tables reach a fresh replica whole — the step that
    /// used to deliver nothing while claiming the replica was current.
    #[tokio::test]
    async fn a_snapshot_carries_every_table_to_a_fresh_replica() {
        let (_a, mut leader) = storage();
        put(&leader, "buckets", "b1", b"bucket one");
        put(&leader, "object_listings", "b1\0k\0", b"listing");
        put(&leader, "stripe_refs", "aa", b"refs");
        let snap = leader.build_snapshot().await.unwrap();

        let (_b, mut replica) = storage();
        replica
            .install_snapshot(&at(42), snap.snapshot)
            .await
            .unwrap();
        for table in ["buckets", "object_listings", "stripe_refs"] {
            assert_eq!(rows(&replica, table), rows(&leader, table), "{table}");
        }
        assert_eq!(
            replica.load_state().unwrap().last_applied.unwrap().index,
            42
        );
    }

    /// A replica that joins by snapshot numbers the next config entry as
    /// the leader does, deleted entries counted too.
    #[tokio::test]
    async fn a_snapshot_carries_the_config_version() {
        let set = |key: &str| MetaCommand::SetConfig {
            key: key.into(),
            value: b"v".to_vec(),
            updated_by: "t".into(),
            updated_at: 0,
        };
        let (_a, mut leader) = storage();
        let entries = [
            normal_entry(1, set("a")),
            normal_entry(2, set("b")),
            normal_entry(3, set("a")),
            normal_entry(4, MetaCommand::DeleteConfig { key: "a".into() }),
        ];
        leader.apply_to_state_machine(&entries).await.unwrap();
        let snap = leader.build_snapshot().await.unwrap();

        let (_b, mut replica) = storage();
        replica
            .apply_to_state_machine(&[normal_entry(1, set("own"))])
            .await
            .unwrap();
        replica
            .install_snapshot(&at(4), snap.snapshot)
            .await
            .unwrap();

        let next = [normal_entry(5, set("c"))];
        let on_leader = leader.apply_to_state_machine(&next).await.unwrap();
        let on_replica = replica.apply_to_state_machine(&next).await.unwrap();
        assert!(matches!(
            on_leader[..],
            [MetaResponse::ConfigSet { version: 4 }]
        ));
        assert!(matches!(
            on_replica[..],
            [MetaResponse::ConfigSet { version: 4 }]
        ));
        assert_eq!(rows(&replica, "config"), rows(&leader, "config"));
    }

    /// What the replica had that the leader no longer has is gone after.
    #[tokio::test]
    async fn installing_replaces_what_the_replica_had() {
        let (_a, mut leader) = storage();
        put(&leader, "buckets", "kept", b"v");
        let snap = leader.build_snapshot().await.unwrap();

        let (_b, mut replica) = storage();
        put(&replica, "buckets", "deleted-since", b"old");
        put(&replica, "tenants", "stale", b"old");
        replica
            .install_snapshot(&at(7), snap.snapshot)
            .await
            .unwrap();
        assert_eq!(
            rows(&replica, "buckets"),
            vec![("kept".into(), b"v".to_vec())]
        );
        assert!(rows(&replica, "tenants").is_empty());
    }

    /// A damaged snapshot is refused before anything is touched.
    #[tokio::test]
    async fn a_truncated_snapshot_changes_nothing() {
        let (_a, mut leader) = storage();
        put(&leader, "buckets", "b", b"v");
        let mut data = Vec::new();
        {
            use tokio::io::AsyncReadExt as _;
            let mut built = *leader.build_snapshot().await.unwrap().snapshot;
            built.read_to_end(&mut data).await.unwrap();
        }
        data.truncate(data.len() - 3);

        let (_b, mut replica) = storage();
        put(&replica, "buckets", "mine", b"x");
        let mut received = replica.begin_receiving_snapshot().await.unwrap();
        {
            use tokio::io::AsyncWriteExt as _;
            received.write_all(&data).await.unwrap();
            received.flush().await.unwrap();
        }
        let err = replica.install_snapshot(&at(9), received).await;
        assert!(err.is_err());
        assert_eq!(
            rows(&replica, "buckets"),
            vec![("mine".into(), b"x".to_vec())]
        );
        assert_ne!(
            replica.load_state().unwrap().last_applied.map(|l| l.index),
            Some(9)
        );
    }

    /// The current snapshot is the one last built or installed, exactly:
    /// none before the first, the installed one (as the leader described
    /// it) after an install, and the same one after a restart. Built afresh
    /// whenever asked, it could be at a later position than the one the
    /// leader recorded sending, and the leader's check of the follower's
    /// answer panicked.
    #[tokio::test]
    async fn the_current_snapshot_is_the_last_built_or_installed() {
        let (_a, mut leader) = storage();
        put(&leader, "buckets", "b", b"v");
        assert!(leader.get_current_snapshot().await.unwrap().is_none());
        let built = leader.build_snapshot().await.unwrap();
        let current = leader.get_current_snapshot().await.unwrap().unwrap();
        assert_eq!(current.meta, built.meta);

        let dir = TempDir::new().unwrap();
        let snaps = dir.path().join("snapshots");
        {
            let db = Database::create(dir.path().join("meta.db")).unwrap();
            let mut replica =
                MetaRaftStorage::open(Arc::new(db), snaps.clone(), &dir.path().join("raft-log"))
                    .unwrap();
            replica
                .install_snapshot(&at(42), built.snapshot)
                .await
                .unwrap();
            let kept = replica.get_current_snapshot().await.unwrap().unwrap();
            assert_eq!(kept.meta, at(42));
        }
        // After a restart, the same one: and it still carries the data.
        let db = Database::open(dir.path().join("meta.db")).unwrap();
        let mut replica =
            MetaRaftStorage::open(Arc::new(db), snaps, &dir.path().join("raft-log")).unwrap();
        let kept = replica.get_current_snapshot().await.unwrap().unwrap();
        assert_eq!(kept.meta, at(42));
        let (_c, mut third) = storage();
        third
            .install_snapshot(&at(42), kept.snapshot)
            .await
            .unwrap();
        assert_eq!(rows(&third, "buckets"), rows(&leader, "buckets"));
    }

    /// The service hears about it, to rebuild its caches.
    #[tokio::test]
    async fn installing_tells_the_service() {
        let (_a, mut leader) = storage();
        let snap = leader.build_snapshot().await.unwrap();
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::create(dir.path().join("meta.db")).unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut replica =
            MetaRaftStorage::open(db, test_snapshot_dir(), &dir.path().join("raft-log"))
                .unwrap()
                .with_apply_listener(tx);
        replica
            .install_snapshot(&at(1), snap.snapshot)
            .await
            .unwrap();
        assert!(matches!(rx.try_recv(), Ok(ApplyEvent::SnapshotInstalled)));
    }
}

#[cfg(test)]
mod room_tests {
    //! A filesystem without room: openraft stops for good on an error, so
    //! what can wait for room waits, and nothing a full filesystem cut
    //! short is left behind or taken for data.

    use super::tests::normal_entry;
    use super::*;
    use tempfile::TempDir;

    /// A storage whose free space is read from `<dir>/free`.
    fn storage(free: u64, reserve: u64) -> (TempDir, MetaRaftStorage) {
        let dir = TempDir::new().unwrap();
        set_free(&dir, free);
        let db = Database::create(dir.path().join("meta.db")).unwrap();
        let space = DiskSpace::with_free_bytes_file(dir.path(), reserve, &dir.path().join("free"));
        let s = MetaRaftStorage::open(
            Arc::new(db),
            dir.path().join("snapshots"),
            &dir.path().join("raft-log"),
        )
        .unwrap()
        .with_disk_space(Arc::new(space));
        (dir, s)
    }

    fn set_free(dir: &TempDir, free: u64) {
        std::fs::write(dir.path().join("free"), free.to_string()).unwrap();
    }

    fn put(s: &MetaRaftStorage, key: &str, len: usize) {
        let txn = s.db.begin_write().unwrap();
        {
            let mut t = txn
                .open_table(redb::TableDefinition::<&str, &[u8]>::new("buckets"))
                .unwrap();
            t.insert(key, vec![7u8; len].as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }

    fn config(index: u64) -> Entry {
        normal_entry(
            index,
            MetaCommand::SetConfig {
                key: format!("k{index}"),
                value: b"v".to_vec(),
                updated_by: "t".into(),
                updated_at: 1,
            },
        )
    }

    fn snapshot_files(dir: &TempDir) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.path().join("snapshots"))
            .map(|d| {
                d.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// A log append that finds the filesystem full waits for room and then
    /// lands, once: openraft never sees the error, which would stop the
    /// node for good. Until then the node counts as having no room.
    #[tokio::test]
    async fn a_log_append_with_no_room_waits_and_lands_once() {
        let (_d, mut s) = storage(u64::MAX / 4, 0);
        s.append_to_log(vec![config(1)]).await.unwrap();
        s.log
            .lock()
            .fail_next_write(10, std::io::ErrorKind::StorageFull);
        let started = std::time::Instant::now();
        s.append_to_log(vec![config(2), config(3)]).await.unwrap();
        assert!(started.elapsed() >= LOG_ROOM_RETRY, "it waited for room");
        assert!(s.space.starved(), "no room, for now");
        assert!(s.space.admit_write().is_err());
        let held: Vec<u64> = s
            .try_get_log_entries(1..10)
            .await
            .unwrap()
            .iter()
            .map(|e| e.log_id.index)
            .collect();
        assert_eq!(held, [1, 2, 3]);
    }

    /// A snapshot with no room above the reserve writes nothing and says
    /// why; once there is room it is built.
    #[tokio::test]
    async fn a_snapshot_without_room_above_the_reserve_waits_and_writes_nothing() {
        let (dir, s) = storage(999, 1000);
        put(&s, "b", 100);
        let why = s.try_build_snapshot(false).await.unwrap().unwrap_err();
        assert!(why.contains("999 bytes free"), "{why}");
        assert!(
            snapshot_files(&dir).is_empty(),
            "{:?}",
            snapshot_files(&dir)
        );

        set_free(&dir, 1 << 40);
        let built = s.try_build_snapshot(true).await.unwrap().unwrap();
        let current = s.current_snapshot().await.unwrap().unwrap();
        assert_eq!(current.meta, built.meta);
    }

    /// A snapshot that would eat into the reserve stops part way: what it
    /// wrote is removed and the one kept before stays current. That is no
    /// full filesystem: new writes are still taken.
    #[tokio::test]
    async fn a_snapshot_that_would_eat_into_the_reserve_stops_and_leaves_nothing() {
        let (dir, s) = storage(1 << 40, 1000);
        put(&s, "small", 10);
        let kept = s.try_build_snapshot(false).await.unwrap().unwrap();
        let before = snapshot_files(&dir);
        assert_eq!(before.len(), 2, "{before:?}");
        for i in 0..20 {
            put(&s, &format!("big{i}"), 1 << 20);
        }
        // Room for one as large as the last, not for 16 MiB more.
        set_free(&dir, 1000 + (1 << 20));
        let why = s.try_build_snapshot(false).await.unwrap().unwrap_err();
        assert!(
            why.contains(&format!("{} needed above 1000", 16 << 20)),
            "stopped part way: {why}"
        );
        assert_eq!(snapshot_files(&dir), before);
        let current = s.current_snapshot().await.unwrap().unwrap();
        assert_eq!(current.meta, kept.meta);
        s.space.admit_write().unwrap();
    }

    /// A snapshot's write the filesystem refuses (ENOSPC, from /dev/full)
    /// is no room, not a failure, and counts as no room for a while.
    #[test]
    fn a_full_device_stops_a_snapshot_as_no_room() {
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("/dev/full");
        let dir = TempDir::new().unwrap();
        let space = DiskSpace::new(dir.path(), 0);
        let mut out = RoomFor::new(&full, &space);
        let e = out.write_all(&[0u8; 4096]).unwrap_err();
        assert!(objectio_common::error::is_out_of_space(&e), "{e}");
        assert!(out.no_room.is_some());
        assert!(space.starved());
    }

    /// What a snapshot interrupted by a crash left (a file being built, a
    /// description half-written, data without one) is removed at open, so
    /// it doesn't hold room the next one needs; the kept one stays.
    #[tokio::test]
    async fn what_an_interrupted_snapshot_left_is_removed_at_open() {
        let (dir, s) = storage(1 << 40, 0);
        put(&s, "b", 10);
        s.try_build_snapshot(false).await.unwrap().unwrap();
        let kept = snapshot_files(&dir);
        drop(s);
        let snaps = dir.path().join("snapshots");
        for junk in [
            "build-1-2.snap",
            "meta-snap-9-9.meta.tmp",
            "meta-snap-9-9.data",
        ] {
            std::fs::write(snaps.join(junk), b"junk").unwrap();
        }
        let db = Database::open(dir.path().join("meta.db")).unwrap();
        let s = MetaRaftStorage::open(Arc::new(db), snaps, &dir.path().join("raft-log")).unwrap();
        assert_eq!(snapshot_files(&dir), kept);
        assert!(s.current_snapshot().await.unwrap().is_some());
    }
}
