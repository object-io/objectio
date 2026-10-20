//! Exporting a backup, and running after a restore to an older point
//! (objectio-docs `core/meta.md`, "Backup, restore and losing a majority").
//!
//! A restored meta is older than its OSDs: copies by reference, packs and
//! completed uploads made after the backup are uses of stripes that the
//! shared-stripe registry no longer knows of, and OSDs it holds as draining
//! or out may have been put back in since. The restore records that in
//! [`RESTORED_KEY`]; here meta acts on it: it frees no stripe that predates
//! the restore, and it leaves those OSDs alone until an operator sets their
//! state again. Every PG is listed once (`pg_relist`, in peering).

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Config key recording that the state machine was restored, and how.
pub const RESTORED_KEY: &str = "cluster/restored";

/// The table of placement groups still to be listed after a restore.
pub(crate) const PG_RELIST_TABLE: &str = "pg_relist";

/// What a restore adds to every placement group's epoch: above any epoch
/// the group it was restored from can have reached.
pub const EPOCH_ERA: u64 = 1 << 32;

/// How far past the restore's own time stripes are held: the old group's
/// clocks against the restoring host's (a gateway's is within 500 ms of
/// meta's).
pub const HOLD_MARGIN_MS: u64 = 5 * 60 * 1000;

/// What [`RESTORED_KEY`] holds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Restored {
    /// `backup` or `forced-membership`.
    pub how: String,
    /// The Raft position the restored state machine was at.
    pub last_applied_index: u64,
    pub last_applied_term: u64,
    /// When the backup was taken, Unix seconds (0 for a forced membership).
    pub backup_created_at: u64,
    /// When it was restored, Unix seconds.
    pub restored_at: u64,
    /// A stripe whose id (a UUIDv7) is older than this, in Unix ms, is
    /// never freed: something meta lost track of may still use it.
    pub hold_frees_before_ms: u64,
    /// OSDs (hex ids) the restored state holds as draining, or out and not
    /// purged: left alone until an operator sets their state again.
    pub osds_to_confirm: Vec<String>,
}

/// Frees a release would have made and didn't, since this node started.
static FREES_HELD: AtomicU64 = AtomicU64::new(0);

/// The term (+ 1) in which this node, leading, last pushed every epoch.
static EPOCHS_PUSHED: AtomicU64 = AtomicU64::new(0);

/// Whether a stripe with id `id` may be freed when stripes made before
/// `before_ms` are held: only one whose id is a UUIDv7 made after it.
#[must_use]
pub fn may_free(id: &[u8], before_ms: u64) -> bool {
    let Ok(id) = <[u8; 16]>::try_from(id) else {
        return false;
    };
    if id[6] >> 4 != 7 {
        return false;
    }
    let mut ms = [0u8; 8];
    ms[2..].copy_from_slice(&id[..6]);
    u64::from_be_bytes(ms) >= before_ms
}

impl MetaService {
    /// What the restore recorded, if this state machine was restored. A
    /// record that doesn't decode holds every free.
    pub(crate) fn restored(&self) -> Option<Restored> {
        let entry = self.config.read().get(RESTORED_KEY).cloned()?;
        match serde_json::from_slice(&entry.value) {
            Ok(r) => Some(r),
            Err(e) => {
                error!("{RESTORED_KEY} doesn't decode ({e}): every stripe's free is held");
                Some(Restored {
                    how: String::new(),
                    last_applied_index: 0,
                    last_applied_term: 0,
                    backup_created_at: 0,
                    restored_at: 0,
                    hold_frees_before_ms: u64::MAX,
                    osds_to_confirm: Vec::new(),
                })
            }
        }
    }

    /// `freeable` and `freed_packs` (a release's answer) less the stripes
    /// a restore holds.
    pub(crate) fn hold_restored_frees(
        &self,
        freeable: Vec<Vec<u8>>,
        freed_packs: Vec<objectio_proto::metadata::StripeMeta>,
    ) -> (Vec<Vec<u8>>, Vec<objectio_proto::metadata::StripeMeta>) {
        let Some(before) = self.restored().map(|r| r.hold_frees_before_ms) else {
            return (freeable, freed_packs);
        };
        let (free, held): (Vec<_>, Vec<_>) =
            freeable.into_iter().partition(|id| may_free(id, before));
        let (packs, held_packs): (Vec<_>, Vec<_>) = freed_packs
            .into_iter()
            .partition(|s| may_free(&s.object_id, before));
        let n = held.len() + held_packs.len();
        if n > 0 {
            FREES_HELD.fetch_add(n as u64, Ordering::Relaxed);
            debug!(
                "restored: {n} stripes made before the restore not freed (a use meta lost track \
                 of may remain)"
            );
        }
        (free, packs)
    }

    /// After a restore, every placement group's epoch is one the OSDs
    /// haven't heard of: told them all at once, by each new leader, rather
    /// than asked for by every OSD at its first write to each PG. (Leader
    /// only; an OSD that misses it asks, as for any epoch it hasn't seen.)
    pub(crate) async fn push_restored_epochs(&self) {
        if self.restored().is_none() {
            return;
        }
        let Some(raft) = self.raft_handle() else {
            return;
        };
        let term = raft.metrics().borrow().current_term;
        if EPOCHS_PUSHED.load(Ordering::Relaxed) == term + 1 {
            return;
        }
        let pgs: Vec<objectio_proto::metadata::PlacementGroup> =
            self.placement_groups.read().values().cloned().collect();
        self.push_pg_epochs(&pgs, &[]).await;
        EPOCHS_PUSHED.store(term + 1, Ordering::Relaxed);
        info!(
            "restored: the epochs of {} placement groups told to every OSD",
            pgs.len()
        );
    }

    /// Whether OSD `node` waits for an operator to set its state, after a
    /// restore.
    pub(crate) fn osd_to_confirm(&self, node: &[u8; 16]) -> bool {
        let hex = hex::encode(node);
        self.restored()
            .is_some_and(|r| r.osds_to_confirm.contains(&hex))
    }

    /// An operator set OSD `node`'s state: it no longer waits.
    pub(crate) async fn confirm_osd(&self, node: &[u8; 16], by: &str) -> Result<(), Status> {
        use objectio_meta_store::CasOp;
        let hex = hex::encode(node);
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let Some(store) = self.store.as_ref() else {
                return Ok(());
            };
            let Some(bytes) = store.read_named("config", RESTORED_KEY) else {
                return Ok(());
            };
            let mut entry = ConfigEntry::decode(bytes.as_slice())
                .map_err(|e| Status::internal(format!("{RESTORED_KEY}: {e}")))?;
            let Ok(mut restored) = serde_json::from_slice::<Restored>(&entry.value) else {
                return Ok(());
            };
            if !restored.osds_to_confirm.contains(&hex) {
                return Ok(());
            }
            restored.osds_to_confirm.retain(|o| *o != hex);
            entry.value = serde_json::to_vec(&restored)
                .map_err(|e| Status::internal(format!("{RESTORED_KEY}: {e}")))?;
            entry.updated_at = Self::current_timestamp();
            entry.updated_by = by.to_string();
            entry.version += 1;
            let op = CasOp {
                table: CasTable::Config,
                key: RESTORED_KEY.to_string(),
                expected: Some(bytes),
                new_value: Some(entry.encode_to_vec()),
            };
            if self.cas_many(vec![op], "restore-confirm-osd").await? {
                info!(
                    "OSD {hex}: its state set after the restore; the drain observer acts on it again"
                );
                return Ok(());
            }
        }
        Err(Status::aborted(format!(
            "{RESTORED_KEY} kept changing; retry"
        )))
    }

    /// The restore's metrics, as Prometheus families.
    pub fn render_restore_metrics(&self, out: &mut String) {
        use std::fmt::Write as _;
        let restored = self.restored();
        let relist = self
            .store
            .as_ref()
            .map_or(0, |s| s.list_named(PG_RELIST_TABLE).len());
        let _ = writeln!(
            out,
            "# HELP objectio_meta_restored 1 if this state machine was restored from a backup or \
             forced to one voter\n# TYPE objectio_meta_restored gauge\nobjectio_meta_restored {}",
            u8::from(restored.is_some())
        );
        let _ = writeln!(
            out,
            "# HELP objectio_meta_pgs_to_relist Placement groups still to be listed after a \
             restore\n# TYPE objectio_meta_pgs_to_relist gauge\nobjectio_meta_pgs_to_relist {relist}"
        );
        let _ = writeln!(
            out,
            "# HELP objectio_meta_restore_osds_unconfirmed OSDs left draining or out by a \
             restore, waiting for an operator to set their state\n# TYPE \
             objectio_meta_restore_osds_unconfirmed gauge\nobjectio_meta_restore_osds_unconfirmed {}",
            restored.map_or(0, |r| r.osds_to_confirm.len())
        );
        let _ = writeln!(
            out,
            "# HELP objectio_meta_restore_frees_held_total Stripes not freed because they predate \
             a restore (space held, never lost)\n# TYPE objectio_meta_restore_frees_held_total \
             counter\nobjectio_meta_restore_frees_held_total {}",
            FREES_HELD.load(Ordering::Relaxed)
        );
    }

    /// `ExportMeta`: a backup of the state machine, streamed.
    pub(crate) async fn export_meta(
        &self,
        request: Request<objectio_proto::metadata::ExportMetaRequest>,
    ) -> Result<Response<ExportStream>, Status> {
        use objectio_proto::metadata::ExportMetaChunk;
        let raft = self
            .raft_handle()
            .ok_or_else(|| Status::unavailable("raft is not running"))?;
        // Everything committed is applied first, by a leader a quorum
        // confirms: the backup holds every write acknowledged before it.
        raft.ensure_linearizable().await.map_err(|e| {
            Status::unavailable(format!("can't confirm this node leads ({e}); retry"))
        })?;
        let db = self
            .store
            .as_ref()
            .ok_or_else(|| Status::unavailable("no store"))?
            .db();
        let who = request.into_inner().requested_by;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<ExportMetaChunk, Status>>(4);
        tokio::task::spawn_blocking(move || {
            let out = ChunkWriter {
                tx: tx.clone(),
                buf: Vec::with_capacity(EXPORT_CHUNK),
            };
            let started = std::time::Instant::now();
            match objectio_meta_store::MetaRaftStorage::export(&db, out) {
                Ok(h) => info!(
                    "meta export for {who}: at {:?}, {:.1} s",
                    h.last_applied,
                    started.elapsed().as_secs_f64()
                ),
                Err(e) => {
                    warn!("meta export for {who} failed: {e}");
                    let _ = tx.blocking_send(Err(Status::internal(format!("export failed: {e}"))));
                }
            }
        });
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        Ok(Response::new(Box::pin(stream)))
    }
}

/// The stream `ExportMeta` answers with.
pub type ExportStream = std::pin::Pin<
    Box<
        dyn futures::Stream<Item = Result<objectio_proto::metadata::ExportMetaChunk, Status>>
            + Send,
    >,
>;

/// Bytes per `ExportMetaChunk`.
const EXPORT_CHUNK: usize = 1 << 20;

/// Writes into the export's channel, a chunk at a time: a slow reader holds
/// the export back. A reader gone ends it.
struct ChunkWriter {
    tx: tokio::sync::mpsc::Sender<Result<objectio_proto::metadata::ExportMetaChunk, Status>>,
    buf: Vec<u8>,
}

impl ChunkWriter {
    fn send(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let data = std::mem::replace(&mut self.buf, Vec::with_capacity(EXPORT_CHUNK));
        self.tx
            .blocking_send(Ok(objectio_proto::metadata::ExportMetaChunk { data }))
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the reader went away")
            })
    }
}

impl std::io::Write for ChunkWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(EXPORT_CHUNK - self.buf.len());
        self.buf.extend_from_slice(&buf[..n]);
        if self.buf.len() == EXPORT_CHUNK {
            self.send()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.send()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_uuid_v7_made_after_the_restore_may_be_freed() {
        let at = |ms: u64| {
            let mut id = *uuid::Uuid::now_v7().as_bytes();
            id[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
            id
        };
        let restore = 1_800_000_000_000;
        assert!(may_free(&at(restore + 1), restore));
        assert!(may_free(&at(restore), restore));
        assert!(!may_free(&at(restore - 1), restore));
        // Not a v7: when it was made can't be told.
        assert!(!may_free(uuid::Uuid::new_v4().as_bytes(), 0));
        assert!(!may_free(b"short", 0));
    }
}
