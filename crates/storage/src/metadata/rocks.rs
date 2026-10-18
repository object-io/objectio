//! The OSD's metadata index on RocksDB (B27, step 3): an alternative to
//! [`super::MetadataStore`] behind the same [`MetaIndex`] contract, so the
//! two can be compared on the same machines (objectio-docs
//! `core/osd-engines.md`).
//!
//! RocksDB keeps its own write-ahead log, memtable and sorted files, and
//! its own compactions. A write is one `WriteBatch` written with `sync`:
//! durable and all or nothing when it returns, and RocksDB batches
//! concurrent synced writers into one fsync. Keys sort as bytes, as in the
//! native store. Its data lives under `rocksdb/` in the metadata directory.

use std::path::Path;

use objectio_common::{Error, Result};
use rocksdb::{BlockBasedOptions, Cache, DB, Options, WriteBatch, WriteOptions};
use tracing::error;

use super::index::MetaIndex;
use super::store::MetadataStoreConfig;
use super::types::{MetadataKey, MetadataOp};

/// The directory, under the metadata directory, RocksDB's files go in.
pub const DIR: &str = "rocksdb";

/// The metadata index on RocksDB.
pub struct RocksIndex {
    db: DB,
    sync: WriteOptions,
}

/// An index that can't be read is not answered from: as the native store,
/// the OSD stops rather than say a shard or object isn't there.
fn fatal(e: &rocksdb::Error) -> ! {
    error!("metadata index (rocksdb) unreadable, stopping: {e}");
    std::process::abort()
}

impl RocksIndex {
    /// Open the index at `config.data_dir`/rocksdb, creating it if there is
    /// none: a block cache of `cache_bytes` and memtables of
    /// `memtable_bytes`, as the native store's settings.
    ///
    /// # Errors
    /// RocksDB could not open or create it.
    pub fn open(config: &MetadataStoreConfig) -> Result<Self> {
        let path = config.data_dir.join(DIR);
        std::fs::create_dir_all(&path)
            .map_err(|e| Error::Storage(format!("create {}: {e}", path.display())))?;
        let mut table = BlockBasedOptions::default();
        table.set_block_cache(&Cache::new_lru_cache(config.cache_bytes));
        table.set_bloom_filter(10.0, false);
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_block_based_table_factory(&table);
        opts.set_write_buffer_size(config.memtable_bytes);
        opts.set_max_background_jobs(2);
        // Every acknowledged write is on disk: a torn tail of the log is a
        // write that wasn't acknowledged, dropped at open; anything else
        // wrong in it stops the open rather than lose a write silently.
        opts.set_wal_recovery_mode(rocksdb::DBRecoveryMode::PointInTime);
        opts.set_paranoid_checks(true);
        let db = DB::open(&opts, &path)
            .map_err(|e| Error::Storage(format!("open {}: {e}", path.display())))?;
        let mut sync = WriteOptions::default();
        sync.set_sync(true);
        Ok(Self { db, sync })
    }

    fn add(batch: &mut WriteBatch, op: MetadataOp) {
        match op {
            MetadataOp::Put { key, value } => batch.put(key.0, value),
            MetadataOp::Delete { key } => batch.delete(key.0),
            MetadataOp::Batch { ops } => ops.into_iter().for_each(|op| Self::add(batch, op)),
        }
    }

    /// A RocksDB property as a number, or 0.
    fn property(&self, name: &str) -> u64 {
        self.db.property_int_value(name).ok().flatten().unwrap_or(0)
    }
}

impl MetaIndex for RocksIndex {
    fn get(&self, key: &MetadataKey) -> Option<Vec<u8>> {
        self.db.get(&key.0).unwrap_or_else(|e| fatal(&e))
    }

    fn write(&self, ops: Vec<MetadataOp>) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        let mut batch = WriteBatch::default();
        for op in ops {
            Self::add(&mut batch, op);
        }
        self.db
            .write_opt(batch, &self.sync)
            .map_err(|e| Error::Storage(format!("metadata index (rocksdb) write: {e}")))
    }

    fn for_each_prefix(
        &self,
        prefix: &MetadataKey,
        after: Option<&MetadataKey>,
        f: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    ) {
        let mut it = self.db.raw_iterator();
        match after {
            Some(a) if a.0.as_slice() >= prefix.0.as_slice() => it.seek(&a.0),
            _ => it.seek(&prefix.0),
        }
        while it.valid() {
            let (Some(k), Some(v)) = (it.key(), it.value()) else {
                break;
            };
            if !k.starts_with(&prefix.0) {
                break;
            }
            // From after `after`: the key itself is not repeated.
            let skip = after.is_some_and(|a| k == a.0.as_slice());
            if !skip && !f(k, v) {
                return;
            }
            it.next();
        }
        if let Err(e) = it.status() {
            fatal(&e);
        }
    }

    /// Counted by a walk of every key: RocksDB keeps only an estimate. Not
    /// on any request's path.
    fn len(&self) -> u64 {
        let mut n = 0u64;
        let mut it = self.db.raw_iterator();
        it.seek_to_first();
        while it.valid() {
            n += 1;
            it.next();
        }
        n
    }

    fn render_metrics(&self, out: &mut String, labels: &str) {
        use std::fmt::Write;
        for (name, help, prop) in [
            (
                "objectio_osd_rocksdb_keys_estimate",
                "Keys in the metadata index (RocksDB's estimate)",
                "rocksdb.estimate-num-keys",
            ),
            (
                "objectio_osd_rocksdb_sst_bytes",
                "Bytes of the metadata index's sorted files",
                "rocksdb.total-sst-files-size",
            ),
            (
                "objectio_osd_rocksdb_memtable_bytes",
                "Bytes in the metadata index's memtables",
                "rocksdb.cur-size-all-mem-tables",
            ),
            (
                "objectio_osd_rocksdb_pending_compaction_bytes",
                "Bytes RocksDB estimates its compactions still have to rewrite",
                "rocksdb.estimate-pending-compaction-bytes",
            ),
        ] {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} gauge");
            let _ = writeln!(out, "{name}{{{labels}}} {}", self.property(prop));
        }
    }
}

/// Whether a metadata directory holds a RocksDB index.
#[must_use]
pub fn present(dir: &Path) -> bool {
    dir.join(DIR).exists()
}

#[cfg(test)]
mod tests {
    use crate::metadata::MetadataStoreConfig;
    use crate::metadata::index::conformance;

    #[test]
    fn rocksdb_keeps_the_contract() {
        conformance::run(|dir| {
            std::sync::Arc::new(
                super::RocksIndex::open(&MetadataStoreConfig::with_data_dir(dir)).unwrap(),
            )
        });
    }
}

#[cfg(test)]
mod engine_choice {
    use crate::metadata::{MetaEngine, MetadataKey, MetadataStoreConfig, open};

    /// A directory one engine wrote is refused by the other, not opened
    /// empty (which would read as every shard and object gone).
    #[test]
    fn a_directory_is_opened_only_by_the_engine_that_wrote_it() {
        let config = |dir: &std::path::Path, engine| MetadataStoreConfig {
            engine,
            ..MetadataStoreConfig::with_data_dir(dir)
        };
        let native = tempfile::tempdir().unwrap();
        open(config(native.path(), MetaEngine::Native))
            .unwrap()
            .put(MetadataKey::from_bytes(b"k".to_vec()), b"v".to_vec())
            .unwrap();
        let refused = open(config(native.path(), MetaEngine::RocksDb))
            .err()
            .unwrap();
        assert!(refused.to_string().contains("native"), "{refused}");

        let rocks = tempfile::tempdir().unwrap();
        open(config(rocks.path(), MetaEngine::RocksDb))
            .unwrap()
            .put(MetadataKey::from_bytes(b"k".to_vec()), b"v".to_vec())
            .unwrap();
        let refused = open(config(rocks.path(), MetaEngine::Native))
            .err()
            .unwrap();
        assert!(refused.to_string().contains("RocksDB"), "{refused}");
    }
}
