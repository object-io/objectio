//! Meta's group commit (B21; objectio-docs `core/meta-log.md`).
//!
//! openraft 0.9 appends each client write to the log, and waits for the
//! log's sync, before it takes the next: every meta write was a sync of its
//! own, one after another. On a drive without power-loss protection a sync
//! takes milliseconds, so meta took a few hundred writes a second for the
//! whole cluster, and every small PUT waited its turn (B21: 172 ms of a
//! 64 KiB PUT's 175 ms on the lab host).
//!
//! Writes here go through a batcher instead. At most [`IN_FLIGHT`] Raft
//! writes are under way; every write that arrives meanwhile goes, with the
//! others waiting, into the next one, as a single entry
//! ([`MetaCommand::Batch`]) applied command by command as consecutive
//! entries would be. One sync then covers them all. A caller is answered
//! when the entry holding its command is committed and applied, as before:
//! nothing is acknowledged sooner. A write that finds nothing in flight
//! goes at once, alone, as it always did.
//!
//! A command that could never apply ([`MetaCommand::refusal`]: too many
//! operations, a table it may not write) is refused here, before it is
//! proposed, and so never joins a batch: it fails its own caller alone.
//! One the state machine refuses all the same (what the store holds) is
//! answered `MetaResponse::Rejected`, which reaches its caller as
//! [`WriteError::Refused`], and the other commands of its entry apply.

use std::ops::Deref;
use std::sync::Arc;

use objectio_meta_store::{MetaCommand, MetaResponse, MetaTypeConfig};
use openraft::BasicNode;
use openraft::error::{ClientWriteError, Fatal, RaftError};
use openraft::raft::ClientWriteResponse;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::error;

type Raft = openraft::Raft<MetaTypeConfig>;

/// Why a write was not made.
#[derive(Debug, Clone)]
pub enum WriteError {
    /// Raft's own error, for the entry that held the command.
    Raft(RaftError<u64, ClientWriteError<u64, BasicNode>>),
    /// The command can never apply: refused before it was proposed, or
    /// answered `MetaResponse::Rejected` by the state machine. Nothing was
    /// written.
    Refused(String),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raft(e) => e.fmt(f),
            Self::Refused(reason) => write!(f, "refused: {reason}"),
        }
    }
}

impl std::error::Error for WriteError {}

/// What [`MetaRaft::client_write`] answers.
pub type WriteResult = Result<ClientWriteResponse<MetaTypeConfig>, WriteError>;

/// Raft writes under way at once: a second lets the leader's log sync of
/// one overlap the replication of the other.
pub const IN_FLIGHT: usize = 2;

/// Commands in one entry at most.
const MAX_COMMANDS: usize = 256;

/// Encoded bytes in one entry at most (a command larger than this goes
/// alone).
const MAX_BYTES: usize = 4 << 20;

type Pending = (MetaCommand, oneshot::Sender<WriteResult>);

/// The Raft handle meta's service writes through: `client_write` batches,
/// everything else is the Raft's own.
pub struct MetaRaft {
    raft: Arc<Raft>,
    tx: mpsc::UnboundedSender<Pending>,
}

impl Deref for MetaRaft {
    type Target = Raft;

    fn deref(&self) -> &Raft {
        &self.raft
    }
}

impl MetaRaft {
    /// Wrap `raft`, starting its batcher (on the current Tokio runtime).
    #[must_use]
    pub fn new(raft: Arc<Raft>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(batcher(Arc::clone(&raft), rx));
        Self { raft, tx }
    }

    /// The Raft itself.
    #[must_use]
    pub const fn raft(&self) -> &Arc<Raft> {
        &self.raft
    }

    /// Propose `cmd`, answered once it is committed and applied, as
    /// `Raft::client_write`; with others that arrive meanwhile in one entry.
    ///
    /// # Errors
    /// [`WriteError::Refused`] for a command that can never apply (checked
    /// before it is proposed, and by the state machine); otherwise as
    /// `Raft::client_write`, for the entry that held `cmd`.
    pub async fn client_write(&self, cmd: MetaCommand) -> WriteResult {
        if matches!(cmd, MetaCommand::Batch(_)) {
            return Err(WriteError::Refused(
                "a batch is made by the batcher, never proposed".into(),
            ));
        }
        if let Some(reason) = cmd.refusal() {
            return Err(WriteError::Refused(reason));
        }
        let (tx, rx) = oneshot::channel();
        if self.tx.send((cmd, tx)).is_err() {
            return Err(WriteError::Raft(RaftError::Fatal(Fatal::Stopped)));
        }
        let answer = rx
            .await
            .unwrap_or(Err(WriteError::Raft(RaftError::Fatal(Fatal::Stopped))));
        match answer {
            Ok(r) => match r.data {
                MetaResponse::Rejected { reason } => Err(WriteError::Refused(reason)),
                _ => Ok(r),
            },
            Err(e) => Err(e),
        }
    }
}

/// The encoded size of `cmd`, as the log will hold it.
fn encoded_len(cmd: &MetaCommand) -> usize {
    serde_json::to_vec(cmd).map_or(0, |b| b.len())
}

async fn batcher(raft: Arc<Raft>, mut rx: mpsc::UnboundedReceiver<Pending>) {
    let slots = Arc::new(Semaphore::new(IN_FLIGHT));
    let mut carried: Option<Pending> = None;
    loop {
        // A slot first, then the commands: what arrives while every slot
        // is busy waits here, and goes in the next entry together.
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        let first = match carried.take() {
            Some(p) => p,
            None => match rx.recv().await {
                Some(p) => p,
                None => return,
            },
        };
        let mut bytes = encoded_len(&first.0);
        let mut batch = vec![first];
        while batch.len() < MAX_COMMANDS {
            let Ok(next) = rx.try_recv() else { break };
            let len = encoded_len(&next.0);
            if bytes + len > MAX_BYTES {
                carried = Some(next);
                break;
            }
            bytes += len;
            batch.push(next);
        }
        let raft = Arc::clone(&raft);
        tokio::spawn(async move {
            commit(&raft, batch).await;
            drop(slot);
        });
    }
}

/// Propose `batch` as one entry (a lone command as itself) and answer each
/// of its callers.
async fn commit(raft: &Raft, mut batch: Vec<Pending>) {
    if batch.len() == 1 {
        let (cmd, tx) = batch.pop().expect("one");
        let _ = tx.send(raft.client_write(cmd).await.map_err(WriteError::Raft));
        return;
    }
    let (cmds, txs): (Vec<_>, Vec<_>) = batch.into_iter().unzip();
    let count = cmds.len();
    match raft.client_write(MetaCommand::Batch(cmds)).await {
        Ok(resp) => match resp.data {
            MetaResponse::Batch(answers) if answers.len() == count => {
                for (tx, data) in txs.into_iter().zip(answers) {
                    let _ = tx.send(Ok(ClientWriteResponse {
                        log_id: resp.log_id,
                        data,
                        membership: None,
                    }));
                }
            }
            other => {
                // Never: the state machine answers a batch with one answer
                // per command. Fatal for the callers rather than a guess.
                error!("a batch of {count} commands answered {other:?}");
                for tx in txs {
                    let _ = tx.send(Err(WriteError::Raft(RaftError::Fatal(Fatal::Panicked))));
                }
            }
        },
        Err(e) => {
            for tx in txs {
                let _ = tx.send(Err(WriteError::Raft(e.clone())));
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use objectio_meta_store::raft_storage::MetaRaftStorage;
    use objectio_meta_store::{CasOp, CasTable};
    use std::collections::BTreeMap;

    /// A single-voter meta Raft in `dir`, leading.
    pub(crate) async fn single_node(dir: &std::path::Path) -> Arc<Raft> {
        single_node_with(dir, |_| {}).await
    }

    /// As [`single_node`], `prepare` given the database first.
    async fn single_node_with(
        dir: &std::path::Path,
        prepare: impl FnOnce(&redb::Database),
    ) -> Arc<Raft> {
        let db = redb::Database::create(dir.join("meta.db")).unwrap();
        prepare(&db);
        let storage =
            MetaRaftStorage::open(Arc::new(db), dir.join("snapshots"), &dir.join("raft-log"))
                .unwrap();
        let (log, sm) = openraft::storage::Adaptor::new(storage);
        let config = Arc::new(
            crate::raft_config(100_000, 1000, 50, 300)
                .validate()
                .unwrap(),
        );
        let raft = Raft::new(
            1,
            config,
            objectio_meta_store::MetaRaftNetworkFactory::new(1),
            log,
            sm,
        )
        .await
        .unwrap();
        raft.initialize(BTreeMap::from([(1, BasicNode::default())]))
            .await
            .unwrap();
        raft.wait(Some(std::time::Duration::from_secs(10)))
            .current_leader(1, "leads")
            .await
            .unwrap();
        Arc::new(raft)
    }

    fn create(key: &str) -> MetaCommand {
        MetaCommand::MultiCas {
            ops: vec![CasOp {
                table: CasTable::IcebergTables,
                key: key.into(),
                expected: None,
                new_value: Some(key.as_bytes().to_vec()),
            }],
            requested_by: "test".into(),
        }
    }

    /// Writes made together are committed in fewer entries than writes
    /// (group commit), and each caller gets its own command's answer: a
    /// create of a key another caller created first conflicts, alone.
    #[tokio::test]
    async fn concurrent_writes_share_entries_and_keep_their_own_answers() {
        let dir = tempfile::TempDir::new().unwrap();
        let raft = single_node(dir.path()).await;
        let before = raft.metrics().borrow().last_log_index.unwrap_or(0);
        let meta = Arc::new(MetaRaft::new(Arc::clone(&raft)));

        let writes: Vec<_> = (0..400)
            .map(|i| {
                let meta = Arc::clone(&meta);
                // Keys 0..200 twice: one of each pair wins, the other
                // conflicts.
                tokio::spawn(
                    async move { meta.client_write(create(&format!("k{}", i % 200))).await },
                )
            })
            .collect();
        let mut ok = 0;
        let mut conflicts = 0;
        for w in writes {
            match w.await.unwrap().unwrap().data {
                MetaResponse::MultiCasOk => ok += 1,
                MetaResponse::MultiCasConflict { .. } => conflicts += 1,
                other => panic!("unexpected answer {other:?}"),
            }
        }
        assert_eq!((ok, conflicts), (200, 200));
        let entries = raft.metrics().borrow().last_log_index.unwrap_or(0) - before;
        assert!(entries < 100, "{entries} entries for 400 writes");
    }

    /// More operations than one command may carry: refused before it is
    /// proposed, so nothing reaches the log, Raft keeps running, and the
    /// next write commits. (Proposed, it used to stop Raft on every node.)
    #[tokio::test]
    async fn an_oversized_write_is_refused_and_raft_goes_on() {
        let dir = tempfile::TempDir::new().unwrap();
        let raft = single_node(dir.path()).await;
        let meta = MetaRaft::new(Arc::clone(&raft));
        let before = raft.metrics().borrow().last_log_index;
        let ops = (0..=objectio_meta_store::raft::MAX_OPS)
            .map(|i| CasOp {
                table: CasTable::IcebergTables,
                key: format!("k{i}"),
                expected: None,
                new_value: Some(vec![1]),
            })
            .collect();
        let r = meta
            .client_write(MetaCommand::MultiCas {
                ops,
                requested_by: "test".into(),
            })
            .await;
        assert!(matches!(r, Err(WriteError::Refused(_))), "{r:?}");
        assert_eq!(raft.metrics().borrow().last_log_index, before);
        // Nor a table of Raft's own.
        let r = meta
            .client_write(MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("raft_vote".into()),
                    key: "vote".into(),
                    expected: None,
                    new_value: Some(vec![1]),
                }],
                requested_by: "test".into(),
            })
            .await;
        assert!(matches!(r, Err(WriteError::Refused(_))), "{r:?}");

        assert!(raft.metrics().borrow().running_state.is_ok());
        let r = meta.client_write(create("after")).await.unwrap();
        assert!(matches!(r.data, MetaResponse::MultiCasOk));
    }

    /// A command the state machine refuses (here: a table of other types)
    /// that shares an entry with others fails its own caller alone, and
    /// the others commit; a command refused before it is proposed never
    /// joins the batch.
    #[tokio::test]
    async fn a_refused_command_fails_only_its_own_caller() {
        let dir = tempfile::TempDir::new().unwrap();
        let raft = single_node_with(dir.path(), |db| {
            let txn = db.begin_write().unwrap();
            {
                let def: redb::TableDefinition<u64, u64> = redb::TableDefinition::new("numbers");
                txn.open_table(def).unwrap().insert(1, 1).unwrap();
            }
            txn.commit().unwrap();
        })
        .await;
        let meta = Arc::new(MetaRaft::new(Arc::clone(&raft)));
        let before = raft.metrics().borrow().last_log_index.unwrap_or(0);

        let writes: Vec<_> = (0..300)
            .map(|i| {
                let meta = Arc::clone(&meta);
                tokio::spawn(async move {
                    let cmd = match i % 100 {
                        // Refused as it applies.
                        7 => MetaCommand::MultiCas {
                            ops: vec![CasOp {
                                table: CasTable::Named("numbers".into()),
                                key: format!("n{i}"),
                                expected: None,
                                new_value: Some(vec![1]),
                            }],
                            requested_by: "test".into(),
                        },
                        // Refused before it is proposed.
                        9 => MetaCommand::MultiCas {
                            ops: (0..=objectio_meta_store::raft::MAX_OPS)
                                .map(|j| CasOp {
                                    table: CasTable::IcebergTables,
                                    key: format!("big{i}-{j}"),
                                    expected: None,
                                    new_value: Some(vec![1]),
                                })
                                .collect(),
                            requested_by: "test".into(),
                        },
                        _ => create(&format!("k{i}")),
                    };
                    (i, meta.client_write(cmd).await)
                })
            })
            .collect();
        let mut ok = 0;
        for w in writes {
            let (i, r) = w.await.unwrap();
            match i % 100 {
                7 | 9 => assert!(matches!(r, Err(WriteError::Refused(_))), "{i}: {r:?}"),
                _ => {
                    assert!(matches!(r.unwrap().data, MetaResponse::MultiCasOk));
                    ok += 1;
                }
            }
        }
        assert_eq!(ok, 294);
        let entries = raft.metrics().borrow().last_log_index.unwrap_or(0) - before;
        assert!(
            entries < 150,
            "{entries} entries: the writes were not batched"
        );
        assert!(raft.metrics().borrow().running_state.is_ok());
        let r = meta.client_write(create("after")).await.unwrap();
        assert!(matches!(r.data, MetaResponse::MultiCasOk));
    }

    /// A write that finds nothing in flight goes at once, as itself: an
    /// entry of its own, not a batch of one.
    #[tokio::test]
    async fn a_lone_write_is_its_own_entry() {
        let dir = tempfile::TempDir::new().unwrap();
        let raft = single_node(dir.path()).await;
        let meta = MetaRaft::new(Arc::clone(&raft));
        let before = raft.metrics().borrow().last_log_index.unwrap_or(0);
        let r = meta.client_write(create("alone")).await.unwrap();
        assert!(matches!(r.data, MetaResponse::MultiCasOk));
        assert_eq!(r.log_id.index, before + 1);
    }
}
