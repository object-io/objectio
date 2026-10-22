//! A meta node answers a client call itself only while it knows it is
//! still the Raft leader.
//!
//! Believing it leads is not enough: openraft 0.9 doesn't step a leader
//! down when it loses its quorum, so a leader cut off from its followers
//! went on answering IAM, bucket, listing and placement reads from its
//! own state for as long as the partition lasted, while the majority
//! elected another leader and changed things (a revoked key stayed valid
//! to a gateway on the old leader's side). Before a call is served here,
//! the gate confirms the leadership with a quorum (openraft's
//! `ensure_linearizable`: a heartbeat round, then waiting until this
//! node has applied everything committed when it started).
//!
//! One confirmation serves every call for a while. Why that is safe, in
//! openraft 0.9's terms: a follower that acked the round's heartbeat
//! (sent after the round started, at `T`) noted the time it did, `u ≥ T`.
//! It refuses to vote for anyone else until its leader lease has passed
//! (`now ≤ u + lease`, the lease being its `election_timeout_max`), and
//! doesn't stand itself before `u + lease + election timeout`. A new
//! leader needs votes from a quorum, which shares a node with the quorum
//! that acked (a follower, or this node, which by voting leaves the term
//! the confirmation is for), so none is elected, and nothing can change
//! elsewhere, before `T + lease`, the smallest lease among the voters.
//! A success is reused while younger than half of this node's
//! `election_timeout_min`, counted from `T`: a quarter of the lease when
//! every node runs the same `--raft-election-ms` (lease = 2 × min), and
//! still inside it while the nodes' values are less than 4× apart (a
//! rolling upgrade that changes the default). Calls arriving while a
//! round is under way wait for it rather than start another, so the
//! cost is at most one heartbeat round per window, however many calls
//! there are.
//!
//! A round that can't reach a quorum is tried again until the gate's
//! timeout (one `election_timeout_min`); then the calls waiting on it are
//! answered UNAVAILABLE, which clients retry, reaching a node that serves
//! (`objectio_proto::transport::meta_channel` leaves a node out while its
//! probe says it isn't serving).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use futures::future::Shared;
use parking_lot::Mutex;
use tokio::time::Instant;

/// Why a confirmation round failed, and whether trying again may help.
#[derive(Debug, Clone)]
pub struct NotConfirmed {
    pub why: String,
    /// No quorum answered in time (followers slow, frozen, cut off), as
    /// opposed to this node having learnt it no longer leads.
    pub retry: bool,
}

type Round = Pin<Box<dyn Future<Output = Result<(), NotConfirmed>> + Send>>;
type Confirm = Box<dyn Fn() -> Round + Send + Sync>;
type Outcome = Shared<Pin<Box<dyn Future<Output = Result<(), String>> + Send>>>;

/// How long a failed round waits before the next, so a failure that is
/// immediate (connections refused) doesn't spin.
const RETRY_PAUSE: Duration = Duration::from_millis(50);

pub struct ReadGate {
    confirm: Confirm,
    /// How long a confirmation is reused, from when its round started.
    window: Duration,
    /// How long the calls waiting on a confirmation wait, at most.
    timeout: Duration,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// When the newest successful round started, and in which term.
    confirmed: Option<(Instant, u64)>,
    /// The confirmation under way, which every call arriving meanwhile
    /// shares: its number and term, and its outcome.
    pending: Option<(u64, u64, Outcome)>,
    rounds: u64,
    /// Whether the last confirmation to finish failed.
    failing: bool,
}

impl ReadGate {
    /// A gate for a Raft group whose election timeout is at least
    /// `election_timeout_min`.
    pub fn for_raft(
        raft: Arc<openraft::Raft<objectio_meta_store::MetaTypeConfig>>,
        election_timeout_min: Duration,
    ) -> Arc<Self> {
        Self::new(
            Box::new(move || {
                let raft = raft.clone();
                Box::pin(async move {
                    raft.ensure_linearizable().await.map(|_| ()).map_err(|e| {
                        let retry = matches!(
                            &e,
                            openraft::error::RaftError::APIError(
                                openraft::error::CheckIsLeaderError::QuorumNotEnough(_)
                            )
                        );
                        NotConfirmed {
                            why: e.to_string(),
                            retry,
                        }
                    })
                })
            }),
            election_timeout_min / 2,
            election_timeout_min,
        )
    }

    fn new(confirm: Confirm, window: Duration, timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            confirm,
            window,
            timeout,
            state: Mutex::default(),
        })
    }

    /// Whether this node, the leader in `term`, may serve a call now:
    /// at once if a confirmation in this term is recent enough, otherwise
    /// once the one under way (or a new one) succeeds.
    ///
    /// # Errors
    /// Why leadership couldn't be confirmed in time.
    pub async fn check(self: &Arc<Self>, term: u64) -> Result<(), String> {
        let outcome = {
            let mut state = self.state.lock();
            if self.fresh(&state, term) {
                return Ok(());
            }
            self.pending_round(&mut state, term)
        };
        outcome.await
    }

    /// For a liveness probe, without waiting: false while the last
    /// confirmation failed and none has succeeded since. A probe that
    /// finds no fresh confirmation starts one, so the answer follows the
    /// node's state even when no call reaches it.
    pub fn serving(self: &Arc<Self>, term: u64) -> bool {
        let mut state = self.state.lock();
        if self.fresh(&state, term) {
            return true;
        }
        let failing = state.failing;
        drop(self.pending_round(&mut state, term));
        !failing
    }

    fn fresh(&self, state: &State, term: u64) -> bool {
        state
            .confirmed
            .is_some_and(|(at, t)| t == term && at.elapsed() < self.window)
    }

    /// The round under way in `term`, or a new one. A round runs as its
    /// own task, so a call that gives up doesn't stall the others.
    fn pending_round(self: &Arc<Self>, state: &mut State, term: u64) -> Outcome {
        if let Some((_, t, outcome)) = &state.pending
            && *t == term
        {
            return outcome.clone();
        }
        state.rounds += 1;
        let round = state.rounds;
        let gate = self.clone();
        let task = tokio::spawn(async move { gate.run(round, term).await });
        let outcome: Outcome = (Box::pin(async move {
            task.await
                .unwrap_or_else(|e| Err(format!("leadership check: {e}")))
        }) as Pin<Box<dyn Future<Output = _> + Send>>)
            .shared();
        state.pending = Some((round, term, outcome.clone()));
        outcome
    }

    async fn run(&self, round: u64, term: u64) -> Result<(), String> {
        let deadline = Instant::now() + self.timeout;
        let outcome = loop {
            let started = Instant::now();
            match tokio::time::timeout_at(deadline, (self.confirm)()).await {
                Ok(Ok(())) => break Ok(started),
                Ok(Err(e)) if e.retry && Instant::now() + RETRY_PAUSE < deadline => {
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
                Ok(Err(e)) => break Err(e.why),
                Err(_) => {
                    break Err(format!("no quorum confirmed it within {:?}", self.timeout));
                }
            }
        };
        let mut state = self.state.lock();
        if state.pending.as_ref().is_some_and(|(r, ..)| *r == round) {
            state.pending = None;
        }
        state.failing = outcome.is_err();
        match outcome {
            Ok(started) => {
                if state
                    .confirmed
                    .is_none_or(|(at, t)| t != term || at < started)
                {
                    state.confirmed = Some((started, term));
                }
                Ok(())
            }
            Err(why) => Err(why),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const WINDOW: Duration = Duration::from_millis(1000);
    const TIMEOUT: Duration = Duration::from_millis(2000);

    /// A gate whose rounds take `takes` and succeed while `ok` says so,
    /// counting them.
    fn gate(
        takes: Duration,
        ok: Arc<std::sync::atomic::AtomicBool>,
    ) -> (Arc<ReadGate>, Arc<AtomicUsize>) {
        let rounds = Arc::new(AtomicUsize::new(0));
        let counted = rounds.clone();
        let g = ReadGate::new(
            Box::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
                let ok = ok.clone();
                Box::pin(async move {
                    tokio::time::sleep(takes).await;
                    if ok.load(Ordering::SeqCst) {
                        Ok(())
                    } else {
                        Err(NotConfirmed {
                            why: "no quorum".into(),
                            retry: true,
                        })
                    }
                })
            }),
            WINDOW,
            TIMEOUT,
        );
        (g, rounds)
    }

    fn ok(v: bool) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::new(std::sync::atomic::AtomicBool::new(v))
    }

    #[tokio::test(start_paused = true)]
    async fn calls_arriving_together_share_one_round() {
        let (g, rounds) = gate(Duration::from_millis(100), ok(true));
        let calls: Vec<_> = (0..50)
            .map(|_| {
                let g = g.clone();
                tokio::spawn(async move { g.check(1).await })
            })
            .collect();
        for c in calls {
            c.await.unwrap().unwrap();
        }
        assert_eq!(rounds.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_confirmation_is_reused_until_the_window_from_its_start_ends() {
        let takes = Duration::from_millis(300);
        let (g, rounds) = gate(takes, ok(true));
        g.check(1).await.unwrap();
        assert_eq!(rounds.load(Ordering::SeqCst), 1);
        // The window counts from the round's start, 300 ms ago.
        tokio::time::advance(WINDOW - takes - Duration::from_millis(10)).await;
        g.check(1).await.unwrap();
        assert_eq!(rounds.load(Ordering::SeqCst), 1, "reused inside the window");
        tokio::time::advance(Duration::from_millis(20)).await;
        g.check(1).await.unwrap();
        assert_eq!(
            rounds.load(Ordering::SeqCst),
            2,
            "a new round once it ended"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_term_needs_its_own_confirmation() {
        let (g, rounds) = gate(Duration::from_millis(10), ok(true));
        g.check(1).await.unwrap();
        g.check(2).await.unwrap();
        assert_eq!(rounds.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_quorum_calls_fail_after_the_timeout_and_recover() {
        let quorum = ok(true);
        let (g, rounds) = gate(Duration::from_millis(500), quorum.clone());
        g.check(1).await.unwrap();
        assert!(g.serving(1));
        quorum.store(false, Ordering::SeqCst);
        // Inside the window, still served from the last confirmation.
        g.check(1).await.unwrap();
        tokio::time::advance(WINDOW).await;
        let started = Instant::now();
        let calls: Vec<_> = (0..10)
            .map(|_| {
                let g = g.clone();
                tokio::spawn(async move { g.check(1).await })
            })
            .collect();
        for c in calls {
            assert!(c.await.unwrap().is_err());
        }
        let waited = started.elapsed();
        assert!(
            waited >= TIMEOUT && waited < TIMEOUT + Duration::from_millis(600),
            "{waited:?}"
        );
        // Retried inside the timeout (500 ms each), all calls sharing them.
        let tried = rounds.load(Ordering::SeqCst);
        assert!((3..=6).contains(&tried), "{tried} rounds");
        assert!(!g.serving(1), "a probe says it isn't serving");

        quorum.store(true, Ordering::SeqCst);
        g.check(1).await.unwrap();
        assert!(g.serving(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_call_that_gives_up_does_not_stall_the_round() {
        let (g, rounds) = gate(Duration::from_millis(200), ok(true));
        let first = {
            let g = g.clone();
            tokio::spawn(async move { g.check(1).await })
        };
        tokio::time::advance(Duration::from_millis(50)).await;
        first.abort();
        tokio::time::advance(Duration::from_millis(300)).await;
        // The round finished on its own: this call is served from it.
        g.check(1).await.unwrap();
        assert_eq!(rounds.load(Ordering::SeqCst), 1);
    }
}
