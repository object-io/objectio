//! An object's metadata, read from its copies, several reads to an OSD in
//! one call (B21; objectio-docs `core/small-object-path.md`).
//!
//! Every GET asks each copy of its key for the object's metadata
//! (`GetObjectMeta`, with a small object's shard): six calls for 4+2. On
//! the lab host that fan-out was most of a GET's CPU, spent on the calls
//! rather than in them (gRPC, HTTP/2, the loopback TCP under it): an OSD
//! answered in 0.13 ms what took the gateway 1.4 ms to collect.
//!
//! So reads to one OSD go through a batcher. At most [`IN_FLIGHT`] calls
//! to it are under way; reads that arrive meanwhile wait, and go together
//! in the next one (`GetObjectMetas`), each answered as `GetObjectMeta`
//! would answer it alone. A read that finds a call free goes at once, by
//! itself, so nothing waits that wouldn't have. The batcher owns the call:
//! a reader that stops waiting (its quorum came) cancels nothing (see
//! [`crate::osd_pool`]'s `closed_by_us`).

#![allow(clippy::result_large_err)] // tonic::Status, as every gRPC call answers

use objectio_proto::storage::storage_service_client::StorageServiceClient;
use objectio_proto::storage::{GetObjectMetaRequest, GetObjectMetaResponse, GetObjectMetasRequest};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tonic::transport::Channel;
use tonic::{Code, Status};

/// Calls to one OSD under way at once.
pub const IN_FLIGHT: usize = 2;

/// Reads in one call at most.
const MAX_READS: usize = 64;

/// How long a call may take, as each read's own did.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

type Answer = Result<GetObjectMetaResponse, Status>;
type Pending = (
    StorageServiceClient<Channel>,
    GetObjectMetaRequest,
    oneshot::Sender<Answer>,
);

/// One batcher per OSD address.
#[derive(Default)]
pub struct MetaReads {
    batchers: Mutex<HashMap<String, mpsc::UnboundedSender<Pending>>>,
}

/// Where reads of one OSD go: its batcher.
#[derive(Clone)]
pub struct MetaReadsTo(mpsc::UnboundedSender<Pending>);

impl MetaReadsTo {
    /// `req`, through `client` (the OSD's channel).
    ///
    /// # Errors
    /// What `GetObjectMeta` would have failed with, or the call's failure.
    pub async fn get(
        self,
        client: StorageServiceClient<Channel>,
        req: GetObjectMetaRequest,
    ) -> Answer {
        // The batcher owns the call: dropping this wait cancels nothing (a
        // copy that answers after the quorum did is let finish: an answer to
        // a cancelled call counts towards h2 closing the connection,
        // `osd_pool::closed_by_us`, and these were thousands a second).
        let (tx, rx) = oneshot::channel();
        self.0
            .send((client, req, tx))
            .map_err(|_| Status::internal("metadata reads stopped"))?;
        rx.await
            .unwrap_or_else(|_| Err(Status::internal("metadata read dropped")))
    }
}

/// The status of a read (or call) that took longer than [`CALL_TIMEOUT`].
fn timed_out() -> Status {
    Status::deadline_exceeded("get_object_meta timed out")
}

/// Whether `e` is a read that timed out here ([`CALL_TIMEOUT`]).
#[must_use]
pub fn is_timeout(e: &Status) -> bool {
    e.code() == Code::DeadlineExceeded && e.message() == timed_out().message()
}

/// `req` alone, in a call of its own.
async fn single(mut client: StorageServiceClient<Channel>, req: GetObjectMetaRequest) -> Answer {
    match tokio::time::timeout(CALL_TIMEOUT, client.get_object_meta(req)).await {
        Ok(r) => r.map(tonic::Response::into_inner),
        Err(_) => Err(timed_out()),
    }
}

impl MetaReads {
    /// Where reads of the OSD at `address` go.
    pub fn to(&self, address: &str) -> MetaReadsTo {
        MetaReadsTo(self.batcher(address))
    }

    fn batcher(&self, address: &str) -> mpsc::UnboundedSender<Pending> {
        let mut batchers = self
            .batchers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(tx) = batchers.get(address).filter(|tx| !tx.is_closed()) {
            return tx.clone();
        }
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(batch(rx));
        batchers.insert(address.to_string(), tx.clone());
        tx
    }
}

async fn batch(mut rx: mpsc::UnboundedReceiver<Pending>) {
    let slots = Arc::new(Semaphore::new(IN_FLIGHT));
    loop {
        // A call first, then the reads: those that arrive while every call
        // is busy wait here, and go in the next one together.
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        let Some(first) = rx.recv().await else {
            return;
        };
        let mut reads = vec![first];
        while reads.len() < MAX_READS {
            let Ok(next) = rx.try_recv() else { break };
            reads.push(next);
        }
        tokio::spawn(async move {
            call(reads).await;
            drop(slot);
        });
    }
}

/// Send `reads` (to one OSD) and answer each.
async fn call(mut reads: Vec<Pending>) {
    if reads.len() == 1 {
        let (client, req, tx) = reads.pop().expect("one");
        let _ = tx.send(single(client, req).await);
        return;
    }
    let mut client = reads[0].0.clone();
    let (requests, txs): (Vec<_>, Vec<_>) = reads.into_iter().map(|(_, r, tx)| (r, tx)).unzip();
    let count = requests.len();
    let sent = tokio::time::timeout(
        CALL_TIMEOUT,
        client.get_object_metas(GetObjectMetasRequest { requests }),
    )
    .await;
    match sent {
        Ok(Ok(resp)) => {
            let answers = resp.into_inner().answers;
            if answers.len() != count {
                let e = Status::internal(format!(
                    "{} answers to {count} metadata reads",
                    answers.len()
                ));
                for tx in txs {
                    let _ = tx.send(Err(e.clone()));
                }
                return;
            }
            for (tx, a) in txs.into_iter().zip(answers) {
                let _ = tx.send(if a.code == 0 {
                    Ok(a.response.unwrap_or_default())
                } else {
                    Err(Status::new(Code::from_i32(a.code), a.message))
                });
            }
        }
        Ok(Err(e)) => {
            for tx in txs {
                let _ = tx.send(Err(e.clone()));
            }
        }
        Err(_) => {
            let e = timed_out();
            for tx in txs {
                let _ = tx.send(Err(e.clone()));
            }
        }
    }
}
