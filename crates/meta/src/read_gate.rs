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
//! A call that reached the gate at `k` is served from a confirmation
//! whose round started at `T` (this node's monotonic clock, read before
//! the round's heartbeats are sent) only if
//!
//! - `T ≥ k`: the round started after the call arrived. This is
//!   read-index, safe however long the round or the node then takes: a
//!   majority acknowledged this node's term after the call arrived, so
//!   another leader can only be elected, and commit, after that; or
//! - `now − T < window` at the moment the call is let through, and no
//!   vote request was answered since `T` ([`ReadGate::revoke`]). This is
//!   a lease.
//!
//! Why the lease holds, in openraft 0.9's terms: a follower that acked
//! the round (at `u ≥ T`) refuses to vote for anyone else until its
//! leader lease has passed (`now ≤ u + lease`, the lease being its
//! `election_timeout_max`), and doesn't stand itself before
//! `u + lease + election timeout`. A new leader needs votes from a
//! quorum, which shares a node with the quorum that acked. If that node
//! is a follower, nobody is elected before `T + lease`. If it is this
//! node, the lease says nothing: openraft never extends a leader's own
//! lease (it dates from its election), so a leader of more than a lease
//! grants its vote to a candidate of a higher term whose log is as long
//! as its own and steps down, while a round it had under way still
//! succeeds on the followers' acks, and its metrics, which route calls
//! here, change only once openraft has worked through its whole batch of
//! messages, which can hold the new leader's first appends. So answering
//! a vote request revokes the gate (`raft_rpc`), before the answer
//! leaves: a call let through before that arrived before any leader the
//! vote could elect, and a call after it waits for a round started after
//! the revocation, which fails if the vote was granted.
//!
//! The window is a quarter of the lease: 500 ms at the default 2 s. It
//! holds while a voter's clock runs less than 4× as fast as this node's
//! (2× if its `--raft-election-ms` is half this node's, as in a rolling
//! upgrade that changes the default); real clocks differ by parts per
//! million. It is counted to the moment a call is let through, not to
//! when its round finished: a call that waited on a round which took
//! longer, or whose node stalled meanwhile (a paused process, a starved
//! runtime), isn't served from it, but from a round started after it
//! arrived.
//!
//! Calls arriving while a round is under way wait for it rather than
//! start another, so the cost is at most one heartbeat round per window,
//! however many calls there are.
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

type MetaRaft = openraft::Raft<objectio_meta_store::MetaTypeConfig>;

/// How long a failed round waits before the next, so a failure that is
/// immediate (connections refused) doesn't spin.
const RETRY_PAUSE: Duration = Duration::from_millis(50);

pub struct ReadGate {
    confirm: Confirm,
    /// How long after its round started a confirmation still serves a
    /// call that arrived before the round.
    window: Duration,
    /// How long a call waits for a confirmation, at most.
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
    /// Raised by every revocation: a round started before one confirms
    /// nothing.
    revocations: u64,
}

impl ReadGate {
    /// The gate for `raft`: its window is a quarter of the leader lease
    /// (`election_timeout_max`), its timeout `election_timeout_min`.
    pub fn for_raft(raft: Arc<MetaRaft>) -> Arc<Self> {
        let config = raft.config();
        let lease = Duration::from_millis(config.election_timeout_max);
        let timeout = Duration::from_millis(config.election_timeout_min);
        Self::for_raft_with(raft, lease / 4, timeout)
    }

    pub(crate) fn for_raft_with(
        raft: Arc<MetaRaft>,
        window: Duration,
        timeout: Duration,
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
            window,
            timeout,
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

    /// Whether this node, the leader in `term`, may serve a call now: at
    /// once if a confirmation in this term is inside the window, otherwise
    /// once a round started after the call arrived succeeds (or one
    /// started before it, if it ends inside the window).
    ///
    /// # Errors
    /// Why leadership couldn't be confirmed in time.
    pub async fn check(self: &Arc<Self>, term: u64) -> Result<(), String> {
        let arrived = Instant::now();
        let deadline = arrived + self.timeout;
        loop {
            let outcome = {
                let mut state = self.state.lock();
                if self.serves(&state, term, arrived) {
                    return Ok(());
                }
                self.pending_round(&mut state, term)
            };
            match tokio::time::timeout_at(deadline, outcome).await {
                // The round succeeded, but may have started before this
                // call and ended after the window, or been revoked: look
                // again, and start another if so.
                Ok(Ok(())) => {}
                Ok(Err(why)) => return Err(why),
                Err(_) => {
                    return Err(format!("no quorum confirmed it within {:?}", self.timeout));
                }
            }
        }
    }

    /// Close the gate: the last confirmation and the round under way serve
    /// no call, and the next call waits for a round started after this.
    /// For when this node answers a vote request (before the answer
    /// leaves), or hears from another leader: from then on another leader
    /// may be elected without waiting out a follower's lease.
    pub fn revoke(&self) {
        let mut state = self.state.lock();
        state.revocations += 1;
        state.confirmed = None;
        state.pending = None;
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

    /// Whether a call that reached the gate at `arrived` may be let
    /// through now (the module comment says why).
    fn serves(&self, state: &State, term: u64, arrived: Instant) -> bool {
        state
            .confirmed
            .is_some_and(|(at, t)| t == term && at >= arrived)
            || self.fresh(state, term)
    }

    /// Whether the last confirmation in `term` is inside the window.
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
        let revocations = state.revocations;
        let gate = self.clone();
        let task = tokio::spawn(async move { gate.run(round, term, revocations).await });
        let outcome: Outcome = (Box::pin(async move {
            task.await
                .unwrap_or_else(|e| Err(format!("leadership check: {e}")))
        }) as Pin<Box<dyn Future<Output = _> + Send>>)
            .shared();
        state.pending = Some((round, term, outcome.clone()));
        outcome
    }

    async fn run(&self, round: u64, term: u64, revocations: u64) -> Result<(), String> {
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
                // A round revoked while under way confirms nothing: the
                // calls that waited on it look again and start another.
                if state.revocations == revocations
                    && state
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
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    const WINDOW: Duration = Duration::from_millis(1000);
    const TIMEOUT: Duration = Duration::from_millis(2000);

    /// What the fake Raft group does with a round. The tests run on
    /// tokio's paused clock, which the gate reads (`tokio::time::Instant`):
    /// time moves only when a test advances it or every task waits.
    struct Fake {
        /// How long a round takes.
        takes_ms: AtomicU64,
        /// Whether a quorum answers.
        quorum: AtomicBool,
        /// Whether this node still leads when a round starts. As in
        /// openraft, where only the start of a round asks the node's
        /// state and the acks are counted apart from it, a node that
        /// stops leading while a round is under way doesn't fail it.
        leads: AtomicBool,
        rounds: AtomicUsize,
    }

    fn gate(takes: Duration, quorum: bool) -> (Arc<ReadGate>, Arc<Fake>) {
        let fake = Arc::new(Fake {
            takes_ms: AtomicU64::new(u64::try_from(takes.as_millis()).unwrap()),
            quorum: AtomicBool::new(quorum),
            leads: AtomicBool::new(true),
            rounds: AtomicUsize::new(0),
        });
        let f = fake.clone();
        let g = ReadGate::new(
            Box::new(move || {
                f.rounds.fetch_add(1, Ordering::SeqCst);
                let f = f.clone();
                let leads = f.leads.load(Ordering::SeqCst);
                Box::pin(async move {
                    if !leads {
                        return Err(NotConfirmed {
                            why: "not the leader".into(),
                            retry: false,
                        });
                    }
                    let takes = f.takes_ms.load(Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(takes)).await;
                    if f.quorum.load(Ordering::SeqCst) {
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
        (g, fake)
    }

    impl Fake {
        fn rounds(&self) -> usize {
            self.rounds.load(Ordering::SeqCst)
        }
    }

    fn call(g: &Arc<ReadGate>) -> tokio::task::JoinHandle<Result<(), String>> {
        let g = g.clone();
        tokio::spawn(async move { g.check(1).await })
    }

    #[tokio::test(start_paused = true)]
    async fn calls_arriving_together_share_one_round() {
        let (g, fake) = gate(Duration::from_millis(100), true);
        let calls: Vec<_> = (0..50).map(|_| call(&g)).collect();
        for c in calls {
            c.await.unwrap().unwrap();
        }
        assert_eq!(fake.rounds(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_confirmation_is_reused_until_the_window_from_its_start_ends() {
        let takes = Duration::from_millis(300);
        let (g, fake) = gate(takes, true);
        g.check(1).await.unwrap();
        assert_eq!(fake.rounds(), 1);
        // The window counts from the round's start, 300 ms ago.
        tokio::time::advance(WINDOW - takes - Duration::from_millis(10)).await;
        g.check(1).await.unwrap();
        assert_eq!(fake.rounds(), 1, "reused inside the window");
        tokio::time::advance(Duration::from_millis(20)).await;
        g.check(1).await.unwrap();
        assert_eq!(fake.rounds(), 2, "a new round once it ended");
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_term_needs_its_own_confirmation() {
        let (g, fake) = gate(Duration::from_millis(10), true);
        g.check(1).await.unwrap();
        g.check(2).await.unwrap();
        assert_eq!(fake.rounds(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_quorum_calls_fail_after_the_timeout_and_recover() {
        let (g, fake) = gate(Duration::from_millis(500), true);
        g.check(1).await.unwrap();
        assert!(g.serving(1));
        fake.quorum.store(false, Ordering::SeqCst);
        // Inside the window, still served from the last confirmation.
        g.check(1).await.unwrap();
        tokio::time::advance(WINDOW).await;
        let started = Instant::now();
        let calls: Vec<_> = (0..10).map(|_| call(&g)).collect();
        for c in calls {
            assert!(c.await.unwrap().is_err());
        }
        let waited = started.elapsed();
        assert!(
            waited >= TIMEOUT && waited < TIMEOUT + Duration::from_millis(600),
            "{waited:?}"
        );
        // Retried inside the timeout (500 ms each), all calls sharing them.
        let tried = fake.rounds();
        assert!((3..=6).contains(&tried), "{tried} rounds");
        assert!(!g.serving(1), "a probe says it isn't serving");

        fake.quorum.store(true, Ordering::SeqCst);
        g.check(1).await.unwrap();
        assert!(g.serving(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_call_that_gives_up_does_not_stall_the_round() {
        let (g, fake) = gate(Duration::from_millis(200), true);
        let first = call(&g);
        tokio::time::advance(Duration::from_millis(50)).await;
        first.abort();
        tokio::time::advance(Duration::from_millis(300)).await;
        // The round finished on its own: this call is served from it.
        g.check(1).await.unwrap();
        assert_eq!(fake.rounds(), 1);
    }

    /// A call that arrives while a round is under way is served from it if
    /// it ends inside the window; if it ends later (a slow quorum, or this
    /// node stalled with the acks waiting), only from a round started
    /// after the call. Served from the old one, it could miss a write a
    /// leader elected meanwhile committed and acknowledged before it.
    #[tokio::test(start_paused = true)]
    async fn a_call_is_not_served_from_a_round_older_than_itself_after_the_window() {
        let (g, fake) = gate(Duration::from_millis(300), true);
        let first = call(&g);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let joined = call(&g);
        first.await.unwrap().unwrap();
        joined.await.unwrap().unwrap();
        assert_eq!(fake.rounds(), 1, "served from the round it joined");

        // The same, the round ending after the window; meanwhile this
        // node stopped leading, so any later round fails.
        tokio::time::sleep(WINDOW).await;
        fake.takes_ms.store(1500, Ordering::SeqCst);
        let first = call(&g);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let joined = call(&g);
        tokio::time::sleep(Duration::from_millis(100)).await;
        fake.leads.store(false, Ordering::SeqCst);
        // The round started before the first call's arrival, so serves it.
        first.await.unwrap().unwrap();
        let r = joined.await.unwrap();
        assert!(
            r.is_err(),
            "a call arriving 100 ms into a round was served from it 1.4 s later"
        );
        assert_eq!(fake.rounds(), 3);
    }

    /// The node answered a vote request (it may have voted for another
    /// candidate and stepped down): its last confirmation, inside the
    /// window, no longer serves.
    #[tokio::test(start_paused = true)]
    async fn a_revocation_ends_the_confirmation() {
        let (g, fake) = gate(Duration::from_millis(10), true);
        g.check(1).await.unwrap();
        g.revoke();
        fake.leads.store(false, Ordering::SeqCst);
        tokio::time::advance(Duration::from_millis(20)).await;
        assert!(g.check(1).await.is_err(), "served after a vote");
        assert_eq!(fake.rounds(), 2);

        // Revoked while still the leader: the next round confirms again.
        fake.leads.store(true, Ordering::SeqCst);
        g.revoke();
        g.check(1).await.unwrap();
        assert_eq!(fake.rounds(), 3);
    }

    /// A round under way when the node answers a vote request confirms
    /// nothing, though the followers' acks make it succeed: the calls
    /// waiting on it wait for a new round instead.
    #[tokio::test(start_paused = true)]
    async fn a_revocation_voids_the_round_under_way() {
        let (g, fake) = gate(Duration::from_millis(100), true);
        let waiting = call(&g);
        tokio::time::sleep(Duration::from_millis(50)).await;
        g.revoke();
        fake.leads.store(false, Ordering::SeqCst);
        let after = call(&g);
        assert!(
            waiting.await.unwrap().is_err(),
            "served from a voided round"
        );
        assert!(after.await.unwrap().is_err(), "served after a vote");
        // The voided round, then one failed for each call.
        assert_eq!(fake.rounds(), 3);
    }
}
