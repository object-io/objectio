//! The offline tools, run with meta stopped (objectio-docs `core/meta.md`,
//! "Backup, restore and losing a majority"):
//!
//! - `objectio-meta restore`: a data directory made from a backup, holding
//!   a one-voter group;
//! - `objectio-meta force-single-voter`: a surviving node made the only
//!   voter, when the rest of its group is lost for good.
//!
//! Both leave the state machine older than the OSDs (by whatever was
//! written after the backup, or what the survivor missed), and make the
//! changes that keeps that from losing anything: [`edit`].

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use objectio_meta_store::raft_storage::rows;
use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaRaftStorage, MetaStore, Voter};
use openraft::LogId;
use prost::Message as _;

use crate::service::restored::{
    EPOCH_ERA, HOLD_MARGIN_MS, PG_RELIST_TABLE, RESTORED_KEY, Restored,
};

/// Present in a data directory while a restore or a forced membership is
/// writing it: meta refuses to start on it.
pub const INCOMPLETE: &str = "restore-incomplete";

#[derive(clap::Subcommand, Debug, Clone)]
pub enum Tool {
    /// Restore a backup (`obioctl meta export`) into an empty data
    /// directory, as a group of one voter. Start meta on it, then add the
    /// other nodes, empty, as when the group was formed.
    Restore {
        /// The backup file.
        #[arg(long)]
        from: PathBuf,
        /// The data directory to restore into: empty, or holding no meta.
        #[arg(long)]
        data_dir: PathBuf,
        /// This node's Raft id, as meta will be started with.
        #[arg(long)]
        node_id: u64,
        /// The address peers reach this node at (its `--raft-advertise`).
        #[arg(long)]
        raft_advertise: String,
    },
    /// Make this node the only voter of its group, the other voters lost
    /// for good. Every entry in its log is kept; entries the lost majority
    /// committed that this node never received are gone.
    ForceSingleVoter {
        /// The surviving node's data directory.
        #[arg(long)]
        data_dir: PathBuf,
        /// The surviving node's Raft id.
        #[arg(long)]
        node_id: u64,
        /// The address peers reach it at; by default the one its
        /// membership gives it.
        #[arg(long)]
        raft_advertise: Option<String>,
    },
}

/// Refuse to serve a data directory a restore didn't finish writing.
///
/// # Errors
/// It holds [`INCOMPLETE`].
pub fn refuse_incomplete(data_dir: &Path) -> anyhow::Result<()> {
    if data_dir.join(INCOMPLETE).exists() {
        bail!(
            "{} holds {INCOMPLETE}: a restore or forced membership into it did not finish. Run \
             it again (a restore into an emptied directory)",
            data_dir.display()
        );
    }
    Ok(())
}

/// Run `tool`.
///
/// # Errors
/// It refuses, or fails part way (the data directory then holds
/// [`INCOMPLETE`]).
pub async fn run(tool: Tool) -> anyhow::Result<()> {
    match tool {
        Tool::Restore {
            from,
            data_dir,
            node_id,
            raft_advertise,
        } => restore(&from, &data_dir, node_id, raft_advertise).await,
        Tool::ForceSingleVoter {
            data_dir,
            node_id,
            raft_advertise,
        } => force_single_voter(&data_dir, node_id, raft_advertise).await,
    }
}

fn holds_meta(data_dir: &Path) -> bool {
    let non_empty = |p: PathBuf| std::fs::read_dir(p).is_ok_and(|mut d| d.next().is_some());
    data_dir.join("meta.redb").exists()
        || non_empty(data_dir.join("raft-log"))
        || non_empty(data_dir.join("raft-snapshots"))
}

/// Write the marker, durably, before anything else.
fn mark_incomplete(data_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let path = data_dir.join(INCOMPLETE);
    std::fs::File::create(&path)?.sync_all()?;
    std::fs::File::open(data_dir)?.sync_all()?;
    Ok(())
}

fn mark_complete(data_dir: &Path) -> anyhow::Result<()> {
    std::fs::remove_file(data_dir.join(INCOMPLETE))?;
    std::fs::File::open(data_dir)?.sync_all()?;
    Ok(())
}

fn open(data_dir: &Path) -> anyhow::Result<(MetaStore, MetaRaftStorage)> {
    let store = MetaStore::open(data_dir.join("meta.redb"))
        .with_context(|| format!("opening {}", data_dir.join("meta.redb").display()))?;
    let storage = MetaRaftStorage::open(
        store.db(),
        data_dir.join("raft-snapshots"),
        &data_dir.join("raft-log"),
    )
    .map_err(|e| anyhow::anyhow!("opening the Raft log: {e}"))?;
    Ok((store, storage))
}

/// What the operator has to know about the state left in `store`.
fn notes(store: &MetaStore) -> String {
    let mut out = String::new();
    let restored: Option<Restored> = store
        .read_named("config", RESTORED_KEY)
        .and_then(|b| objectio_proto::metadata::ConfigEntry::decode(b.as_slice()).ok())
        .and_then(|e| serde_json::from_slice(&e.value).ok());
    if let Some(r) = restored.filter(|r| !r.osds_to_confirm.is_empty()) {
        out.push_str(&format!(
            "OSDs held as draining or out: {}. They may be back in since, with data meta no \
             longer knows of: nothing drains or purges them until you set each one's state as \
             it really is (obioctl osd set-state ID in|out|draining).\n",
            r.osds_to_confirm.join(", ")
        ));
    }
    let packs = store.list_named("packs").len();
    if packs > 0 {
        out.push_str(&format!(
            "This cluster packs small objects ({packs} packs recorded). Objects packed after this \
             point can't be read: their pack's record is gone.\n"
        ));
    }
    out
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

async fn restore(from: &Path, data_dir: &Path, node_id: u64, addr: String) -> anyhow::Result<()> {
    if holds_meta(data_dir) {
        bail!(
            "{} already holds a meta node's data: restore into an empty directory",
            data_dir.display()
        );
    }
    let header = MetaRaftStorage::backup_header(from)
        .with_context(|| format!("reading {}", from.display()))?;
    println!(
        "Backup of cluster {} taken {} by release {} (format level {}, cluster at level {}), at \
         Raft index {}",
        if header.cluster_id.is_empty() {
            "(no id yet)"
        } else {
            &header.cluster_id
        },
        header.created_at,
        header.release,
        header.format_level,
        header.active_level,
        header.last_applied.map_or(0, |l| l.index),
    );
    // The storage keeps its log where a node at this level does.
    objectio_common::version::set_active_level(header.active_level);
    mark_incomplete(data_dir)?;
    let (store, mut storage) = open(data_dir)?;
    let voter = Voter { node_id, addr };
    let created_at = header.created_at;
    storage
        .restore(
            from,
            &voter,
            Box::new(move |db, at| edit(db, at, "backup", created_at, now_ms())),
        )
        .await
        .with_context(|| format!("restoring {}", from.display()))?;
    drop(storage);
    let notes = notes(&store);
    drop(store);
    mark_complete(data_dir)?;
    println!(
        "Restored into {} as node {node_id}, the only voter, at {}.\n\
         Start meta on it, then add the other nodes with empty data directories \
         (/add-learner, then /change-membership with every voter).\n\
         What was written after the backup: objects are listed again as peering lists every \
         placement group; buckets, users and keys made after it are gone, and ones deleted after \
         it are back. See the failure-recovery guide.\n{notes}",
        data_dir.display(),
        voter.addr,
    );
    Ok(())
}

async fn force_single_voter(
    data_dir: &Path,
    node_id: u64,
    addr: Option<String>,
) -> anyhow::Result<()> {
    if !data_dir.join("meta.redb").exists() {
        bail!("{} holds no meta node's data", data_dir.display());
    }
    mark_incomplete(data_dir)?;
    let (store, storage) = open(data_dir)?;
    // The storage keeps its log where a node at the cluster's level does:
    // decided at its first log call, after this.
    let level = store
        .read_named("config", objectio_common::version::ACTIVE_LEVEL_KEY)
        .and_then(|b| objectio_proto::metadata::ConfigEntry::decode(b.as_slice()).ok())
        .and_then(|e| String::from_utf8(e.value).ok())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    objectio_common::version::set_active_level(level);
    let mut storage = storage;
    let forced = storage
        .force_single_voter(
            node_id,
            addr,
            Box::new(|db, at| edit(db, at, "forced-membership", 0, now_ms())),
        )
        .await
        .context("forcing the membership")?;
    drop(storage);
    let notes = notes(&store);
    drop(store);
    mark_complete(data_dir)?;
    let index =
        |l: Option<LogId<u64>>| l.map_or_else(|| "none".to_string(), |l| l.index.to_string());
    println!(
        "Node {node_id} at {} is now the only voter.\n\
         It had applied up to index {}; its log held up to {} (commit index last known: {}); \
         every entry in it is applied: now at {}.\n\
         Entries the lost nodes committed after index {} never reached this node and are gone. \
         Entries past the commit index it knew may never have been acknowledged; they are kept.\n\
         Start meta on it, then add new nodes with empty data directories.\n{notes}",
        forced.addr,
        index(forced.applied_before),
        index(forced.last_log),
        index(forced.committed_known),
        forced.at.index,
        index(forced.last_log),
    );
    Ok(())
}

/// The changes a restore or a forced membership makes to the state machine
/// it leaves at `at`, older than the OSDs:
///
/// - every placement group's epoch (and each stand-in's) raised by
///   [`EPOCH_ERA`], above anything the old group gave the OSDs and the
///   gateways;
/// - a [`PG_RELIST_TABLE`] row for every placement group, for peering to
///   list it once;
/// - [`RESTORED_KEY`]: frees held for stripes older than the restore, and
///   the OSDs left draining or out, to wait for an operator.
///
/// # Errors
/// A record doesn't decode.
pub fn edit(
    db: &redb::Database,
    at: LogId<u64>,
    how: &str,
    backup_created_at: u64,
    now_ms: u64,
) -> Result<Vec<MetaCommand>, String> {
    use objectio_meta_store::record::Record as _;
    use objectio_proto::metadata::PlacementGroup;

    let relisted: std::collections::HashMap<String, Vec<u8>> =
        rows(db, PG_RELIST_TABLE)?.into_iter().collect();
    let mut ops = Vec::new();
    for (key, bytes) in rows(db, "placement_groups")? {
        let mut pg = PlacementGroup::decode(bytes.as_slice())
            .map_err(|e| format!("placement group {key}: {e}"))?;
        pg.epoch += EPOCH_ERA;
        for f in &mut pg.filling {
            f.epoch += EPOCH_ERA;
        }
        ops.push(CasOp {
            table: CasTable::Named(PG_RELIST_TABLE.into()),
            key: key.clone(),
            expected: relisted.get(&key).cloned(),
            new_value: Some(pg.epoch.to_string().into_bytes()),
        });
        ops.push(CasOp {
            table: CasTable::PlacementGroups,
            key,
            expected: Some(bytes),
            new_value: Some(pg.encode_to_vec()),
        });
    }

    let purges: std::collections::HashMap<String, Vec<u8>> =
        rows(db, "osd_purge")?.into_iter().collect();
    // A backup of a restored cluster: what was still unconfirmed stays so.
    let earlier: Option<Restored> = rows(db, "config")?
        .into_iter()
        .find(|(k, _)| k == RESTORED_KEY)
        .and_then(|(_, b)| objectio_proto::metadata::ConfigEntry::decode(b.as_slice()).ok())
        .and_then(|e| serde_json::from_slice(&e.value).ok());
    let mut osds_to_confirm: Vec<String> = earlier.map(|r| r.osds_to_confirm).unwrap_or_default();
    for (key, bytes) in rows(db, "osd_nodes")? {
        let node = objectio_meta_store::OsdNode::from_bytes(&bytes)
            .map_err(|e| format!("OSD {key}: {e}"))?;
        let purged = purges.get(&key).map(Vec::as_slice)
            == Some(crate::drain_observer::PURGE_DONE.as_bytes());
        let unsettled = match node.admin_state {
            objectio_common::OsdAdminState::Draining => true,
            objectio_common::OsdAdminState::Out => !purged,
            objectio_common::OsdAdminState::In => false,
        };
        let id = hex::encode(node.node_id);
        if unsettled && !osds_to_confirm.contains(&id) {
            osds_to_confirm.push(id);
        }
    }
    let restored = Restored {
        how: how.to_string(),
        last_applied_index: at.index,
        last_applied_term: at.leader_id.term,
        backup_created_at,
        restored_at: now_ms / 1000,
        hold_frees_before_ms: now_ms.saturating_add(HOLD_MARGIN_MS),
        osds_to_confirm,
    };

    // As the service would write them: compare-and-sets of at most 256.
    let mut commands: Vec<MetaCommand> = ops
        .chunks(200)
        .map(|c| MetaCommand::MultiCas {
            ops: c.to_vec(),
            requested_by: format!("restore ({how})"),
        })
        .collect();
    commands.push(MetaCommand::SetConfig {
        key: RESTORED_KEY.to_string(),
        value: serde_json::to_vec(&restored).map_err(|e| e.to_string())?,
        updated_by: format!("restore ({how})"),
        updated_at: now_ms / 1000,
    });
    Ok(commands)
}

#[cfg(test)]
mod tests {
    use super::*;
    use objectio_meta_store::record::Record as _;
    use objectio_proto::metadata::{PgFill, PlacementGroup};
    use openraft::CommittedLeaderId;

    fn put(db: &redb::Database, table: &str, key: &str, value: &[u8]) {
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(table))
                .unwrap();
            t.insert(key, value).unwrap();
        }
        txn.commit().unwrap();
    }

    fn osd(id: u8, state: objectio_common::OsdAdminState) -> (String, Vec<u8>) {
        let node = objectio_meta_store::OsdNode {
            node_id: [id; 16],
            address: format!("osd-{id}:9200"),
            disk_ids: Vec::new(),
            topology: None,
            disk_capacity_bytes: Vec::new(),
            admin_state: state,
            te_segment: String::new(),
        };
        (hex::encode([id; 16]), node.to_bytes())
    }

    #[test]
    fn a_restore_moves_every_pg_to_a_new_era_lists_it_and_holds_unsettled_osds() {
        use objectio_common::OsdAdminState::{Draining, In, Out};
        let dir = tempfile::tempdir().unwrap();
        let store = MetaStore::open(dir.path().join("meta.redb")).unwrap();
        let db = store.db();
        let pg = PlacementGroup {
            pool: "default".into(),
            pg_id: 3,
            acting: vec![vec![1; 16]],
            epoch: 7,
            filling: vec![PgFill {
                position: 0,
                from: vec![2; 16],
                epoch: 6,
            }],
            ..PlacementGroup::default()
        };
        let key = MetaStore::pg_key("default", 3);
        put(&db, "placement_groups", &key, &pg.encode_to_vec());
        for (id, state) in [(1, In), (2, Draining), (3, Out), (4, Out)] {
            let (k, v) = osd(id, state);
            put(&db, "osd_nodes", &k, &v);
        }
        // OSD 4 was drained and purged: settled.
        put(&db, "osd_purge", &hex::encode([4u8; 16]), b"done");

        let at = LogId::new(CommittedLeaderId::new(5, 1), 100);
        let now = 1_800_000_000_000;
        let commands = edit(&db, at, "backup", 1_799_999_000, now).unwrap();
        let MetaCommand::MultiCas { ops, .. } = &commands[0] else {
            panic!("{commands:?}");
        };
        let new_pg = ops
            .iter()
            .find(|o| o.table == CasTable::PlacementGroups)
            .and_then(|o| o.new_value.as_deref())
            .map(|b| PlacementGroup::decode(b).unwrap())
            .unwrap();
        assert_eq!(new_pg.epoch, 7 + EPOCH_ERA);
        assert_eq!(new_pg.filling[0].epoch, 6 + EPOCH_ERA);
        assert_eq!(new_pg.acting, pg.acting, "placement as it was");
        assert!(
            ops.iter()
                .any(|o| o.table == CasTable::Named(PG_RELIST_TABLE.into())
                    && o.key == key
                    && o.expected.is_none())
        );

        let MetaCommand::SetConfig { key, value, .. } = commands.last().unwrap() else {
            panic!("{commands:?}");
        };
        assert_eq!(key, RESTORED_KEY);
        let restored: Restored = serde_json::from_slice(value).unwrap();
        assert_eq!(restored.last_applied_index, 100);
        assert_eq!(restored.last_applied_term, 5);
        assert_eq!(restored.hold_frees_before_ms, now + HOLD_MARGIN_MS);
        assert_eq!(
            restored.osds_to_confirm,
            vec![hex::encode([2u8; 16]), hex::encode([3u8; 16])]
        );
    }
}
