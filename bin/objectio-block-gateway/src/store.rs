//! Persistent block store using Redb
//!
//! Stores volume/snapshot records and chunk object-key references so state
//! survives gateway restarts.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use objectio_block::VolumeManager;
use objectio_block::volume::{Volume, VolumeState};

// ── Table definitions ─────────────────────────────────────────────────────────

/// Volumes: volume_id (str) → JSON(VolumeRecord)
const VOLUMES: TableDefinition<&str, &str> = TableDefinition::new("volumes");
/// Snapshots: snapshot_id (str) → JSON(SnapshotRecord)
const SNAPSHOTS: TableDefinition<&str, &str> = TableDefinition::new("snapshots");
/// Chunks: "vol_id\x00{chunk_id:016x}" → object_key (str)
const CHUNKS: TableDefinition<&str, &str> = TableDefinition::new("chunks");

// ── Serialisable records ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VolumeRecord {
    volume_id: String,
    name: String,
    size_bytes: u64,
    pool: String,
    state: i32,
    created_at: u64,
    updated_at: u64,
    parent_snapshot_id: Option<String>,
    chunk_size: u64,
}

impl From<&Volume> for VolumeRecord {
    fn from(v: &Volume) -> Self {
        Self {
            volume_id: v.volume_id.clone(),
            name: v.name.clone(),
            size_bytes: v.size_bytes,
            pool: v.pool.clone(),
            state: v.state.into(),
            created_at: v.created_at,
            updated_at: v.updated_at,
            parent_snapshot_id: v.parent_snapshot_id.clone(),
            chunk_size: v.chunk_size,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotRecord {
    snapshot_id: String,
    volume_id: String,
    name: String,
    size_bytes: u64,
    unique_bytes: u64,
    created_at: u64,
}

// ── BlockStore ────────────────────────────────────────────────────────────────

/// Persistent block metadata store backed by Redb.
pub struct BlockStore {
    db: Arc<Database>,
}

impl BlockStore {
    /// Open (or create) the store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).context("open redb database")?;

        // Ensure all tables are created
        let wtx = db.begin_write()?;
        wtx.open_table(VOLUMES)?;
        wtx.open_table(SNAPSHOTS)?;
        wtx.open_table(CHUNKS)?;
        wtx.commit()?;

        Ok(Self { db: Arc::new(db) })
    }

    // ── Volume persistence ────────────────────────────────────────────────────

    /// Persist a volume record. Call after every mutation.
    pub fn save_volume(&self, vol: &Volume) -> Result<()> {
        let rec = VolumeRecord::from(vol);
        let json = serde_json::to_string(&rec)?;
        let wtx = self.db.begin_write()?;
        wtx.open_table(VOLUMES)?
            .insert(rec.volume_id.as_str(), json.as_str())?;
        wtx.commit()?;
        Ok(())
    }

    /// Remove a volume record (and all its chunk refs).
    pub fn delete_volume(&self, volume_id: &str) -> Result<()> {
        let wtx = self.db.begin_write()?;
        wtx.open_table(VOLUMES)?.remove(volume_id)?;
        wtx.commit()?;
        self.delete_volume_chunks(volume_id)?;
        Ok(())
    }

    /// Restore all persisted volumes into `vm`.
    pub fn restore_volumes(&self, vm: &VolumeManager) -> Result<()> {
        let rtx = self.db.begin_read()?;
        let table = rtx.open_table(VOLUMES)?;
        for entry in table.iter()? {
            let (_, value) = entry?;
            let rec: VolumeRecord = serde_json::from_str(value.value())?;

            // Reconstruct via create_volume (sets Available state) then patch state
            let result = vm.create_volume(rec.name.clone(), rec.size_bytes, rec.pool.clone());

            // If name already exists (idempotent restart) just continue
            if let Err(objectio_block::error::BlockError::VolumeExists(_)) = &result {
                continue;
            }
            let vol = result?;

            // Restore non-Available state
            let state = VolumeState::from(rec.state);
            if state != VolumeState::Available {
                vm.set_volume_state(&vol.volume_id, state)?;
            }
        }
        Ok(())
    }

    // ── Snapshot persistence ──────────────────────────────────────────────────

    /// Persist a snapshot record.
    pub fn save_snapshot(&self, snap: &objectio_block::volume::Snapshot) -> Result<()> {
        let rec = SnapshotRecord {
            snapshot_id: snap.snapshot_id.clone(),
            volume_id: snap.volume_id.clone(),
            name: snap.name.clone(),
            size_bytes: snap.size_bytes,
            unique_bytes: snap.unique_bytes,
            created_at: snap.created_at,
        };
        let json = serde_json::to_string(&rec)?;
        let wtx = self.db.begin_write()?;
        wtx.open_table(SNAPSHOTS)?
            .insert(rec.snapshot_id.as_str(), json.as_str())?;
        wtx.commit()?;
        Ok(())
    }

    /// Remove a snapshot record.
    pub fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        let wtx = self.db.begin_write()?;
        wtx.open_table(SNAPSHOTS)?.remove(snapshot_id)?;
        wtx.commit()?;
        Ok(())
    }

    // ── Chunk reference persistence ───────────────────────────────────────────

    /// Store `(volume_id, chunk_id) → object_key` mapping.
    pub fn put_chunk(&self, volume_id: &str, chunk_id: u64, object_key: &str) -> Result<()> {
        let key = chunk_db_key(volume_id, chunk_id);
        let wtx = self.db.begin_write()?;
        wtx.open_table(CHUNKS)?.insert(key.as_str(), object_key)?;
        wtx.commit()?;
        Ok(())
    }

    /// Look up the object key for a chunk. Returns `None` if not yet flushed.
    pub fn get_chunk(&self, volume_id: &str, chunk_id: u64) -> Result<Option<String>> {
        let key = chunk_db_key(volume_id, chunk_id);
        let rtx = self.db.begin_read()?;
        let table = rtx.open_table(CHUNKS)?;
        Ok(table.get(key.as_str())?.map(|v| v.value().to_string()))
    }

    /// Every object key this volume has flushed.
    ///
    /// Volume delete needs this to hand the storage back: the refs are the
    /// only record of which chunks were ever written, and dropping them first
    /// (which is what used to happen) strands every shard behind them.
    pub fn list_volume_chunks(&self, volume_id: &str) -> Result<Vec<String>> {
        let prefix = format!("{volume_id}\x00");
        let rtx = self.db.begin_read()?;
        let table = rtx.open_table(CHUNKS)?;
        let mut keys = Vec::new();
        for entry in table.range(prefix.as_str()..)? {
            let (k, v) = entry?;
            if !k.value().starts_with(prefix.as_str()) {
                break;
            }
            keys.push(v.value().to_string());
        }
        Ok(keys)
    }

    /// Delete all chunk refs for a volume (used on volume delete).
    pub fn delete_volume_chunks(&self, volume_id: &str) -> Result<()> {
        let prefix = format!("{volume_id}\x00");
        let wtx = self.db.begin_write()?;
        let mut table = wtx.open_table(CHUNKS)?;

        let to_delete: Vec<String> = table
            .range(prefix.as_str()..)?
            .map_while(|entry| {
                entry.ok().and_then(|(k, _)| {
                    let key = k.value();
                    if key.starts_with(prefix.as_str()) {
                        Some(key.to_string())
                    } else {
                        None
                    }
                })
            })
            .collect();

        for key in &to_delete {
            table.remove(key.as_str())?;
        }
        drop(table);
        wtx.commit()?;
        Ok(())
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn chunk_db_key(volume_id: &str, chunk_id: u64) -> String {
    format!("{volume_id}\x00{chunk_id:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, BlockStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = BlockStore::open(dir.path().join("block.redb")).expect("open");
        (dir, store)
    }

    #[test]
    fn a_chunk_ref_survives_a_round_trip() {
        let (_dir, s) = store();
        s.put_chunk("vol-a", 7, "vol_vol-a/chunk_00000007").unwrap();
        assert_eq!(
            s.get_chunk("vol-a", 7).unwrap().as_deref(),
            Some("vol_vol-a/chunk_00000007")
        );
    }

    #[test]
    fn an_unflushed_chunk_has_no_ref() {
        let (_dir, s) = store();
        assert!(s.get_chunk("vol-a", 1).unwrap().is_none());
    }

    #[test]
    fn a_rewritten_chunk_keeps_one_ref() {
        // Overwriting a chunk replaces the key rather than accumulating, which
        // is what lets volume delete free exactly what is live.
        let (_dir, s) = store();
        s.put_chunk("vol-a", 3, "first").unwrap();
        s.put_chunk("vol-a", 3, "second").unwrap();
        assert_eq!(s.get_chunk("vol-a", 3).unwrap().as_deref(), Some("second"));
        assert_eq!(s.list_volume_chunks("vol-a").unwrap(), vec!["second"]);
    }

    #[test]
    fn listing_a_volume_returns_every_chunk_it_flushed() {
        let (_dir, s) = store();
        for id in [0u64, 1, 2, 300] {
            s.put_chunk("vol-a", id, &format!("key-{id}")).unwrap();
        }
        let mut got = s.list_volume_chunks("vol-a").unwrap();
        got.sort();
        assert_eq!(got, vec!["key-0", "key-1", "key-2", "key-300"]);
    }

    /// The separator is the whole safety argument for the prefix scan.
    ///
    /// Keys are `"{volume_id}\0{chunk_id:016x}"`, so `vol1`'s range starts at
    /// `"vol1\0"` and every `vol10` key sorts after it — `\0` is below every
    /// printable byte. Without the NUL, `vol1` would sweep up `vol10`'s chunks
    /// and volume delete would free another volume's live data.
    #[test]
    fn one_volume_never_sees_another_whose_id_it_prefixes() {
        let (_dir, s) = store();
        s.put_chunk("vol1", 0, "mine").unwrap();
        s.put_chunk("vol10", 0, "theirs").unwrap();
        s.put_chunk("vol1extra", 0, "also-theirs").unwrap();

        assert_eq!(s.list_volume_chunks("vol1").unwrap(), vec!["mine"]);
        assert_eq!(s.list_volume_chunks("vol10").unwrap(), vec!["theirs"]);

        s.delete_volume_chunks("vol1").unwrap();
        assert!(s.list_volume_chunks("vol1").unwrap().is_empty());
        assert_eq!(
            s.list_volume_chunks("vol10").unwrap(),
            vec!["theirs"],
            "deleting vol1 took vol10's chunk refs with it"
        );
        assert_eq!(
            s.list_volume_chunks("vol1extra").unwrap(),
            vec!["also-theirs"]
        );
    }

    #[test]
    fn deleting_a_volume_clears_its_chunk_refs() {
        let (_dir, s) = store();
        for id in 0..5u64 {
            s.put_chunk("gone", id, &format!("key-{id}")).unwrap();
        }
        s.delete_volume("gone").unwrap();
        assert!(s.list_volume_chunks("gone").unwrap().is_empty());
        assert!(s.get_chunk("gone", 0).unwrap().is_none());
    }

    #[test]
    fn listing_an_unknown_volume_is_empty_rather_than_an_error() {
        let (_dir, s) = store();
        s.put_chunk("real", 0, "key").unwrap();
        assert!(s.list_volume_chunks("missing").unwrap().is_empty());
    }

    /// Chunk ids are fixed-width hex so the range scan stays ordered.
    ///
    /// `{chunk_id:016x}` covers the whole u64; a narrower field would make
    /// chunk 16 sort before chunk 2 and truncate the scan early.
    #[test]
    fn chunk_keys_sort_by_chunk_id() {
        let mut keys: Vec<String> = [0u64, 2, 16, 255, u64::MAX]
            .iter()
            .map(|id| chunk_db_key("v", *id))
            .collect();
        let ordered = keys.clone();
        keys.sort();
        assert_eq!(keys, ordered, "chunk keys do not sort numerically");
    }
}
