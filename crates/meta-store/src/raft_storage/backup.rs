//! Backups of the state machine, and a node made the only voter: from a
//! backup (a restore) or from its own data (a forced membership, the
//! others lost for good). objectio-docs `core/meta.md`, "Backup, restore
//! and losing a majority".
//!
//! A backup is the state machine as a snapshot carries it, in the
//! container of [`objectio_common::meta_backup`], under a [`BackupHeader`].
//! A restore installs it as a snapshot is installed; both tools then make
//! the same changes and end in the same state: the caller's own
//! state-machine commands applied (what a restore to an older point needs,
//! decided in `objectio-meta`), the membership one voter, a snapshot of the
//! result kept as the current one (what a learner is sent), the log purged
//! up to it and a vote past every entry held.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, BufWriter, Seek, Write};
use std::path::Path;

use objectio_common::meta_backup;
use objectio_common::{Error, Result};
use openraft::{
    LogId, Membership, RaftLogReader, RaftStorage, SnapshotMeta, StoredMembership, Vote,
};
use redb::{Database, ReadableTable};
use serde::{Deserialize, Serialize};

use super::{MetaRaftStorage, Node, NodeId, RaftPersistentState, snapshot_file, write_state};
use crate::commit_metrics::Commit;
use crate::raft::{MetaCommand, MetaResponse};
use crate::tables;

/// What a backup holds, written before its body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupHeader {
    /// The exporting binary's format level.
    pub format_level: u32,
    /// The cluster's active level when it was taken: what a binary must be
    /// able to run at to restore it.
    pub active_level: u32,
    /// The exporting binary's release.
    pub release: String,
    /// The cluster's UUID, in hex (empty if it had none yet): the one on
    /// every OSD's disks.
    pub cluster_id: String,
    /// The Raft position the tables are at.
    pub last_applied: Option<LogId<NodeId>>,
    /// The group's membership when it was taken.
    pub membership: StoredMembership<NodeId, Node>,
    /// When it was taken, Unix seconds.
    pub created_at: u64,
}

/// The one voter a restored or forced node becomes: its id and the address
/// its peers reach it at.
#[derive(Debug, Clone)]
pub struct Voter {
    pub node_id: NodeId,
    pub addr: String,
}

/// The changes to make to the state machine once it is in place at the
/// position given, worked out from it: commands applied as entries are, in
/// one transaction with the new membership.
pub type Edit<'a> =
    Box<dyn FnOnce(&Database, LogId<NodeId>) -> std::result::Result<Vec<MetaCommand>, String> + 'a>;

/// What a forced membership found, and where it left the node.
#[derive(Debug, Clone)]
pub struct Forced {
    /// What the node had applied before.
    pub applied_before: Option<LogId<NodeId>>,
    /// The last entry in its log, all of which it has now applied.
    pub last_log: Option<LogId<NodeId>>,
    /// The commit index it last knew, if it saved one.
    pub committed_known: Option<LogId<NodeId>>,
    /// Where it is now: every entry it held applied.
    pub at: LogId<NodeId>,
    /// The address it is the voter at.
    pub addr: String,
}

fn storage(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Storage(format!("{what}: {e}"))
}

/// The value of config key `key` as `txn` sees it.
fn config_value(txn: &redb::ReadTransaction, key: &str) -> Result<Option<Vec<u8>>> {
    use prost::Message as _;
    let table = match txn.open_table(tables::CONFIG) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(storage("config", e)),
    };
    let Some(v) = table.get(key).map_err(|e| storage("config", e))? else {
        return Ok(None);
    };
    let entry = objectio_proto::metadata::ConfigEntry::decode(v.value())
        .map_err(|e| storage(&format!("config {key}"), e))?;
    Ok(Some(entry.value))
}

fn one_voter(at: LogId<NodeId>, voter: &Voter) -> StoredMembership<NodeId, Node> {
    let voters = BTreeSet::from([voter.node_id]);
    let nodes = BTreeMap::from([(
        voter.node_id,
        Node {
            addr: voter.addr.clone(),
        },
    )]);
    StoredMembership::new(Some(at), Membership::new(vec![voters], nodes))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[allow(deprecated)] // RaftStorage, through which the log is read and applied.
impl MetaRaftStorage {
    /// Write a backup of the state machine in `db` to `out`, from one read
    /// transaction: the header's position and every row agree, while
    /// writes go on.
    ///
    /// # Errors
    /// The database can't be read, or `out` written.
    pub fn export(db: &Database, out: impl Write) -> Result<BackupHeader> {
        let txn = db.begin_read().map_err(|e| storage("backup", e))?;
        let state = Self::state_in(&txn).map_err(|e| storage("backup", e))?;
        let cluster_id = config_value(&txn, "cluster/id")?
            .filter(|v| v.len() == 16)
            .map(|v| v.iter().map(|b| format!("{b:02x}")).collect())
            .unwrap_or_default();
        let active_level = config_value(&txn, objectio_common::version::ACTIVE_LEVEL_KEY)?
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let header = BackupHeader {
            format_level: objectio_common::version::FORMAT_LEVEL,
            active_level,
            release: objectio_common::version::RELEASE.to_string(),
            cluster_id,
            last_applied: state.last_applied,
            membership: state.membership,
            created_at: now_secs(),
        };
        let encoded = serde_json::to_vec(&header).map_err(|e| storage("backup header", e))?;
        let mut w = meta_backup::Writer::new(out, &encoded)?;
        Self::write_tables(&txn, &mut w).map_err(|e| storage("backup", e))?;
        w.finish()?;
        Ok(header)
    }

    /// The header of the backup at `path`, unchecked: a restore checks the
    /// whole file before it uses any of it.
    ///
    /// # Errors
    /// The file can't be read, or doesn't start as a backup does.
    pub fn backup_header(path: &Path) -> Result<BackupHeader> {
        let file = std::fs::File::open(path)?;
        let r = meta_backup::Reader::open(BufReader::new(file))?;
        serde_json::from_slice(r.header()).map_err(|e| {
            Error::Deserialization(format!(
                "not a whole meta backup: its header doesn't decode ({e})"
            ))
        })
    }

    /// Restore the backup at `backup` into this storage, which must be
    /// empty, as the one voter `voter`, with `edit`'s changes. Nothing is
    /// installed unless the whole file checks out and this binary can run
    /// at the level the backup was taken at.
    ///
    /// # Errors
    /// The storage isn't empty, the file isn't a whole backup or is from a
    /// level this binary can't run at, or a write fails.
    pub async fn restore(
        &mut self,
        backup: &Path,
        voter: &Voter,
        edit: Edit<'_>,
    ) -> Result<BackupHeader> {
        let held = self
            .get_log_state()
            .await
            .map_err(|e| storage("raft log", e))?;
        if self
            .load_state()
            .map_err(|e| storage("raft state", e))?
            .last_applied
            .is_some()
            || held.last_log_id.is_some()
        {
            return Err(Error::PreconditionFailed(
                "this storage already holds a state machine or a log: restore into an empty data \
                 directory"
                    .into(),
            ));
        }
        let header = Self::backup_header(backup)?;
        if let Some(why) = objectio_common::version::incompatibility(header.active_level) {
            return Err(Error::PreconditionFailed(format!(
                "the backup was taken at format level {}: {why}",
                header.active_level
            )));
        }
        let at = header.last_applied.ok_or_else(|| {
            Error::InvalidArgument("the backup holds a state machine that applied nothing".into())
        })?;

        // The body, out to a file of its own; the digest is checked as it
        // is copied, so a damaged file installs nothing.
        let (db, dir, backup) = (
            std::sync::Arc::clone(&self.db),
            self.snapshot_dir.clone(),
            backup.to_path_buf(),
        );
        let membership = one_voter(at, voter);
        let meta = SnapshotMeta {
            last_log_id: Some(at),
            last_membership: membership,
            snapshot_id: format!("meta-restore-{}-{}", at.leader_id.term, at.index),
        };
        tokio::task::spawn_blocking(move || -> Result<()> {
            let (body, path) = snapshot_file(&dir, "restore").map_err(|e| storage("restore", e))?;
            let copied = (|| -> Result<()> {
                let src = std::fs::File::open(&backup)?;
                let mut r = meta_backup::Reader::open(BufReader::with_capacity(1 << 20, src))?;
                let mut w = BufWriter::with_capacity(1 << 20, &body);
                std::io::copy(&mut r, &mut w)?;
                w.flush()?;
                drop(w);
                body.sync_all()?;
                let mut src = &body;
                src.seek(std::io::SeekFrom::Start(0))?;
                let mut src = BufReader::with_capacity(1 << 20, src);
                Self::install_state_machine(&db, &mut src, &meta).map_err(|e| storage("install", e))
            })();
            let _ = std::fs::remove_file(&path);
            copied
        })
        .await
        .map_err(|e| storage("restore", e))??;
        self.finish_single_voter(at, voter, edit).await?;
        Ok(header)
    }

    /// Make this node, whose group lost its majority for good, the one
    /// voter `node_id`: every entry in its log applied first (Raft would
    /// commit them if it led), then as a restore. `addr` is where it is
    /// reached; by default the address its membership gives it.
    ///
    /// # Errors
    /// The log or state machine can't be read or written, or no address is
    /// known for `node_id`.
    pub async fn force_single_voter(
        &mut self,
        node_id: NodeId,
        addr: Option<String>,
        edit: Edit<'_>,
    ) -> Result<Forced> {
        let applied_before = self
            .load_state()
            .map_err(|e| storage("raft state", e))?
            .last_applied;
        let held = self
            .get_log_state()
            .await
            .map_err(|e| storage("raft log", e))?;
        let committed_known = self
            .read_committed()
            .await
            .map_err(|e| storage("raft log", e))?;
        let end = held.last_log_id.map_or(0, |l| l.index + 1);
        let mut next = applied_before.map_or(0, |l| l.index + 1);
        while next < end {
            let to = (next + 1000).min(end);
            let entries = self
                .try_get_log_entries(next..to)
                .await
                .map_err(|e| storage("raft log", e))?;
            if entries.len() as u64 != to - next {
                return Err(Error::Storage(format!(
                    "the log holds {} of entries {next}..{to}",
                    entries.len()
                )));
            }
            self.apply_to_state_machine(&entries)
                .await
                .map_err(|e| storage("apply", e))?;
            next = to;
        }
        self.checkpoint().map_err(|e| storage("checkpoint", e))?;
        let state = self.load_state().map_err(|e| storage("raft state", e))?;
        let at = state.last_applied.ok_or_else(|| {
            Error::PreconditionFailed("this node has applied nothing: restore a backup".into())
        })?;
        let addr = addr
            .or_else(|| {
                state
                    .membership
                    .membership()
                    .get_node(&node_id)
                    .map(|n| n.addr.clone())
            })
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "node {node_id} is not in this node's membership: give its address"
                ))
            })?;
        let voter = Voter { node_id, addr };
        self.finish_single_voter(at, &voter, edit).await?;
        Ok(Forced {
            applied_before,
            last_log: held.last_log_id,
            committed_known,
            at,
            addr: voter.addr,
        })
    }

    /// The end of both: `edit`'s commands and the one-voter membership at
    /// `at`, a snapshot of the result kept as the current one, the log
    /// purged up to `at`, and a vote at a term past every entry.
    async fn finish_single_voter(
        &mut self,
        at: LogId<NodeId>,
        voter: &Voter,
        edit: Edit<'_>,
    ) -> Result<()> {
        let commands = edit(&self.db, at).map_err(Error::Storage)?;
        let mut state: RaftPersistentState =
            self.load_state().map_err(|e| storage("raft state", e))?;
        let txn = self.db.begin_write().map_err(|e| storage("restore", e))?;
        let mut events = Vec::new();
        for cmd in &commands {
            // Every change must land: one refused or in conflict would leave
            // the state machine short of what keeps it safe to serve.
            if let Some(why) = cmd.refusal() {
                return Err(Error::Storage(format!(
                    "a restore change is refused: {why}"
                )));
            }
            let answer = Self::apply_command(&txn, &mut state, cmd, &mut events)
                .map_err(|e| storage("restore", e))?;
            if let Some(why) = not_applied(&answer) {
                return Err(Error::Storage(format!("a restore change {why}")));
            }
        }
        state.last_applied = Some(at);
        state.membership = one_voter(at, voter);
        write_state(&txn, &state).map_err(|e| storage("restore", e))?;
        crate::commit_metrics::commit(txn, Commit::Durable).map_err(|e| storage("restore", e))?;

        self.snapshot_of()
            .await
            .map_err(|e| storage("snapshot", e))?;
        self.purge_logs_upto(at)
            .await
            .map_err(|e| storage("raft log", e))?;
        let vote = self
            .read_vote()
            .await
            .map_err(|e| storage("raft vote", e))?
            .unwrap_or_default();
        let term = vote.leader_id().term.max(at.leader_id.term) + 1;
        self.save_vote(&Vote::new(term, voter.node_id))
            .await
            .map_err(|e| storage("raft vote", e))?;
        Ok(())
    }
}

/// Why `answer` says its command didn't apply whole, if it does.
fn not_applied(answer: &MetaResponse) -> Option<String> {
    match answer {
        MetaResponse::MultiCasConflict { failed_indices } => Some(format!(
            "met a value it didn't expect (ops {failed_indices:?})"
        )),
        MetaResponse::Rejected { reason } => Some(format!("was refused: {reason}")),
        MetaResponse::Batch(answers) => answers.iter().find_map(not_applied),
        _ => None,
    }
}

/// The rows of `table` in `db`, for an [`Edit`] to work from.
///
/// # Errors
/// The table can't be read.
pub fn rows(db: &Database, table: &str) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
    let txn = db.begin_read().map_err(|e| e.to_string())?;
    let t = match txn.open_table(redb::TableDefinition::<&str, &[u8]>::new(table)) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    t.iter()
        .map_err(|e| e.to_string())?
        .map(|r| {
            r.map(|(k, v)| (k.value().to_string(), v.value().to_vec()))
                .map_err(|e| e.to_string())
        })
        .collect()
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::raft_storage::test_snapshot_dir;
    use openraft::{CommittedLeaderId, EntryPayload, RaftSnapshotBuilder};
    use std::sync::Arc;
    use tempfile::TempDir;

    type Entry = openraft::Entry<crate::raft::MetaTypeConfig>;

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

    fn log_id(term: u64, index: u64) -> LogId<NodeId> {
        LogId::new(CommittedLeaderId::new(term, 1), index)
    }

    fn set_config(term: u64, index: u64, key: &str, value: &[u8]) -> Entry {
        Entry {
            log_id: log_id(term, index),
            payload: EntryPayload::Normal(MetaCommand::SetConfig {
                key: key.into(),
                value: value.to_vec(),
                updated_by: "t".into(),
                updated_at: 0,
            }),
        }
    }

    /// Three voters, as a group formed by the bootstrap.
    fn three(term: u64, index: u64) -> Entry {
        let voters = BTreeSet::from([1, 2, 3]);
        let nodes: BTreeMap<u64, Node> = (1..=3)
            .map(|i| {
                (
                    i,
                    Node {
                        addr: format!("meta-{i}:9100"),
                    },
                )
            })
            .collect();
        Entry {
            log_id: log_id(term, index),
            payload: EntryPayload::Membership(Membership::new(vec![voters], nodes)),
        }
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

    /// A node of a three-voter group with some state, applied.
    async fn source() -> (TempDir, MetaRaftStorage) {
        let (d, mut s) = storage();
        let entries = vec![
            three(2, 1),
            set_config(2, 2, "cluster/id", &[7u8; 16]),
            set_config(3, 3, "k", b"v"),
        ];
        s.append_to_log(entries.clone()).await.unwrap();
        s.apply_to_state_machine(&entries).await.unwrap();
        put(&s, "buckets", "b1", b"bucket one");
        put(&s, "object_listings", "b1\0k\0", b"listing");
        (d, s)
    }

    fn backup_of(s: &MetaRaftStorage, dir: &Path) -> std::path::PathBuf {
        let path = dir.join("meta.backup");
        let file = std::fs::File::create(&path).unwrap();
        MetaRaftStorage::export(&s.db, BufWriter::new(file)).unwrap();
        path
    }

    fn voter() -> Voter {
        Voter {
            node_id: 1,
            addr: "restored:9100".into(),
        }
    }

    fn no_edit() -> Edit<'static> {
        Box::new(|_, _| Ok(Vec::new()))
    }

    fn config(s: &MetaRaftStorage, key: &str) -> Option<Vec<u8>> {
        use prost::Message as _;
        rows(&s.db, "config")
            .unwrap()
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| {
                objectio_proto::metadata::ConfigEntry::decode(v.as_slice())
                    .unwrap()
                    .value
            })
    }

    /// Where a restore or forced membership leaves a node: at `at`, the one
    /// voter, its log purged to `at`, a vote past every entry, a snapshot at
    /// `at` with the one-voter membership as the current one.
    async fn assert_one_voter(s: &mut MetaRaftStorage, at: LogId<NodeId>, addr: &str) {
        let state = s.load_state().unwrap();
        assert_eq!(state.last_applied, Some(at));
        let m = state.membership.membership();
        assert_eq!(m.voter_ids().collect::<Vec<_>>(), vec![1]);
        assert_eq!(m.get_node(&1).unwrap().addr, addr);
        let log = s.get_log_state().await.unwrap();
        assert_eq!(log.last_purged_log_id, Some(at));
        assert_eq!(log.last_log_id, Some(at));
        let vote = s.read_vote().await.unwrap().unwrap();
        assert!(vote.leader_id().term > at.leader_id.term, "{vote:?}");
        assert_eq!(vote.leader_id().voted_for(), Some(1));
        assert!(!vote.is_committed());
        let snap = s.get_current_snapshot().await.unwrap().unwrap();
        assert_eq!(snap.meta.last_log_id, Some(at));
        assert_eq!(
            snap.meta
                .last_membership
                .membership()
                .voter_ids()
                .collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[tokio::test]
    async fn a_restore_installs_every_table_as_the_one_voter_past_the_backup() {
        let (dir, src) = source().await;
        let path = backup_of(&src, dir.path());
        let header = MetaRaftStorage::backup_header(&path).unwrap();
        assert_eq!(header.cluster_id, "07".repeat(16));
        assert_eq!(header.last_applied, Some(log_id(3, 3)));
        assert_eq!(
            header
                .membership
                .membership()
                .voter_ids()
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        let (_d, mut s) = storage();
        let edit: Edit<'_> = Box::new(|db, at| {
            assert_eq!(at, log_id(3, 3));
            // The edit sees what was installed.
            assert_eq!(rows(db, "buckets").unwrap().len(), 1);
            Ok(vec![MetaCommand::SetConfig {
                key: "cluster/restored".into(),
                value: b"{}".to_vec(),
                updated_by: "restore".into(),
                updated_at: 1,
            }])
        });
        s.restore(&path, &voter(), edit).await.unwrap();
        for table in ["buckets", "object_listings"] {
            assert_eq!(
                rows(&s.db, table).unwrap(),
                rows(&src.db, table).unwrap(),
                "{table}"
            );
        }
        assert_eq!(config(&s, "k").as_deref(), Some(&b"v"[..]));
        assert_eq!(config(&s, "cluster/restored").as_deref(), Some(&b"{}"[..]));
        assert_one_voter(&mut s, log_id(3, 3), "restored:9100").await;

        // What a learner is sent carries the edit too.
        let snap = s.get_current_snapshot().await.unwrap().unwrap();
        let (_e, mut learner) = storage();
        learner
            .install_snapshot(&snap.meta, snap.snapshot)
            .await
            .unwrap();
        assert_eq!(
            rows(&learner.db, "config").unwrap(),
            rows(&s.db, "config").unwrap()
        );
    }

    /// Every state-machine table in `db`, with its rows.
    fn every_table(db: &Database) -> BTreeMap<String, Vec<(String, Vec<u8>)>> {
        let txn = db.begin_read().unwrap();
        txn.list_tables()
            .unwrap()
            .map(|h| redb::TableHandle::name(&h).to_string())
            .filter(|n| !crate::tables::RAFT_TABLES.contains(&n.as_str()))
            .map(|n| {
                let r = rows(db, &n).unwrap();
                (n, r)
            })
            .collect()
    }

    /// A backup that left a table out would lose it on a restore, silently:
    /// whatever tables meta keeps, today's or ones added later, the
    /// restored node holds each, row for row.
    #[tokio::test]
    async fn a_restore_holds_every_table_the_source_did_row_for_row() {
        let (dir, src) = source().await;
        let named = [
            "access_keys",
            "bucket_settings",
            "counters",
            "iam_roles",
            "osd_nodes",
            "packs",
            "pg_relist",
            "placement_groups",
            "tenants",
            "users",
        ];
        for (i, t) in named.iter().enumerate() {
            put(&src, t, &format!("k{i}"), format!("v{i}").as_bytes());
        }
        // One no code names yet.
        put(&src, "a_table_added_later", "k", b"v");
        let before = every_table(&src.db);
        assert!(before.contains_key("counters"), "{:?}", before.keys());
        let path = backup_of(&src, dir.path());

        let (_d, mut s) = storage();
        s.restore(&path, &voter(), no_edit()).await.unwrap();
        assert_eq!(every_table(&s.db), before);
    }

    /// A table the snapshot can't carry fails the export, never goes
    /// missing from it.
    #[tokio::test]
    async fn a_table_a_backup_cant_carry_fails_the_export() {
        let (dir, src) = source().await;
        let txn = src.db.begin_write().unwrap();
        txn.open_multimap_table(redb::MultimapTableDefinition::<&str, &str>::new("multi"))
            .unwrap()
            .insert("k", "v")
            .unwrap();
        txn.commit().unwrap();
        let file = std::fs::File::create(dir.path().join("multi.backup")).unwrap();
        assert!(MetaRaftStorage::export(&src.db, BufWriter::new(file)).is_err());

        let (dir, src) = source().await;
        let txn = src.db.begin_write().unwrap();
        txn.open_table(redb::TableDefinition::<u64, u64>::new("numbers"))
            .unwrap()
            .insert(1, 2)
            .unwrap();
        txn.commit().unwrap();
        let file = std::fs::File::create(dir.path().join("numbers.backup")).unwrap();
        assert!(MetaRaftStorage::export(&src.db, BufWriter::new(file)).is_err());
    }

    /// A restore's change the state machine refuses (one that can never
    /// apply) fails the restore rather than be skipped.
    #[tokio::test]
    async fn a_restore_whose_change_is_refused_fails() {
        let (dir, src) = source().await;
        let path = backup_of(&src, dir.path());
        let (_d, mut s) = storage();
        let edit: Edit<'_> = Box::new(|_, _| {
            Ok(vec![MetaCommand::MultiCas {
                ops: (0..=crate::raft::MAX_OPS)
                    .map(|i| crate::CasOp {
                        table: crate::CasTable::Named("t".into()),
                        key: i.to_string(),
                        expected: None,
                        new_value: Some(b"v".to_vec()),
                    })
                    .collect(),
                requested_by: "t".into(),
            }])
        });
        let e = s.restore(&path, &voter(), edit).await.unwrap_err();
        assert!(e.to_string().contains("refused"), "{e}");
        assert!(rows(&s.db, "t").unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_damaged_or_truncated_backup_installs_nothing() {
        let (dir, src) = source().await;
        let path = backup_of(&src, dir.path());
        let whole = std::fs::read(&path).unwrap();
        let mut changed = whole.clone();
        // In the body, past the header.
        let at = whole.len() - 60;
        changed[at] ^= 0x10;
        for (what, bytes) in [
            ("changed", changed),
            ("truncated", whole[..whole.len() - 40].to_vec()),
        ] {
            std::fs::write(&path, &bytes).unwrap();
            let (_d, mut s) = storage();
            let e = s.restore(&path, &voter(), no_edit()).await.unwrap_err();
            assert!(
                e.to_string().contains("not a whole meta backup"),
                "{what}: {e}"
            );
            assert!(s.load_state().unwrap().last_applied.is_none(), "{what}");
            assert!(rows(&s.db, "buckets").unwrap().is_empty(), "{what}");
        }
    }

    #[tokio::test]
    async fn a_backup_from_a_level_this_binary_cant_run_at_is_refused() {
        let (dir, mut src) = source().await;
        let level = objectio_common::version::FORMAT_LEVEL + 1;
        let entry = set_config(3, 4, "cluster/active_level", level.to_string().as_bytes());
        src.append_to_log(vec![entry.clone()]).await.unwrap();
        src.apply_to_state_machine(&[entry]).await.unwrap();
        let path = backup_of(&src, dir.path());
        assert_eq!(
            MetaRaftStorage::backup_header(&path).unwrap().active_level,
            level
        );

        let (_d, mut s) = storage();
        let e = s.restore(&path, &voter(), no_edit()).await.unwrap_err();
        assert!(
            e.to_string().contains(&format!("format level {level}")),
            "{e}"
        );
        assert!(s.load_state().unwrap().last_applied.is_none());
    }

    #[tokio::test]
    async fn a_restore_into_a_storage_that_holds_state_is_refused() {
        let (dir, src) = source().await;
        let path = backup_of(&src, dir.path());
        let (_d, mut s) = source().await;
        let e = s.restore(&path, &voter(), no_edit()).await.unwrap_err();
        assert!(e.to_string().contains("empty data directory"), "{e}");
    }

    #[tokio::test]
    async fn a_forced_membership_applies_the_log_first_and_leaves_one_voter() {
        let (_d, mut s) = source().await;
        // A snapshot from before, with the old membership: replaced.
        s.build_snapshot().await.unwrap();
        // Two more entries in the log, applied by nobody yet: committed by
        // the old majority or not, they are this node's now.
        let tail = vec![
            set_config(4, 4, "after", b"one"),
            set_config(4, 5, "after", b"two"),
        ];
        s.append_to_log(tail).await.unwrap();

        let forced = s.force_single_voter(1, None, no_edit()).await.unwrap();
        assert_eq!(forced.applied_before, Some(log_id(3, 3)));
        assert_eq!(forced.last_log, Some(log_id(4, 5)));
        assert_eq!(forced.at, log_id(4, 5));
        // The address the old membership gave node 1.
        assert_eq!(forced.addr, "meta-1:9100");
        assert_eq!(config(&s, "after").as_deref(), Some(&b"two"[..]));
        assert_one_voter(&mut s, log_id(4, 5), "meta-1:9100").await;
    }
}
