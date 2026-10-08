//! The epochs of placement groups, as this OSD knows them (B31,
//! objectio-docs `core/pg-recovery.md`).
//!
//! Every change of a placement group's acting set is a Raft commit that
//! raises its epoch, made before any write uses it. A gateway sends the
//! epoch it placed a write under; this OSD refuses one older than it knows
//! (`StaleEpoch`), so a write placed under an acting set that has since
//! changed lands nowhere and is placed again. Meta tells an OSD every
//! epoch when it registers and pushes the PGs it changes; one this OSD has
//! not heard of, or a newer one than it knows, it asks meta for first.
//! Meta's own writes (repair, drain) are directed at an OSD, not placed,
//! and carry no epoch.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use objectio_proto::STALE_EPOCH_HEADER;
use objectio_proto::metadata::GetPlacementGroupRequest;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::storage::PgRef;
use parking_lot::RwLock;
use tonic::Status;

/// How long asking meta for an epoch may take.
const ASK_TIMEOUT: Duration = Duration::from_secs(3);

/// What to do with a request placed under `requested`, given the epoch
/// this OSD knows for its PG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Placed under the current epoch (or not placed at all).
    Accept,
    /// Placed under an older epoch than the one held: refuse, naming it.
    Refuse(u64),
    /// Not known here, or newer than known: ask meta first.
    Ask,
}

/// The rule, apart from asking.
#[must_use]
pub const fn decide(known: Option<u64>, requested: u64) -> Decision {
    if requested == 0 {
        return Decision::Accept; // placed without a placement group
    }
    match known {
        Some(k) if k > requested => Decision::Refuse(k),
        Some(k) if k == requested => Decision::Accept,
        _ => Decision::Ask,
    }
}

/// The refusal: FAILED_PRECONDITION, with the epoch held in
/// [`STALE_EPOCH_HEADER`].
#[must_use]
pub fn stale(pool: &str, pg_id: u32, current: u64) -> Status {
    let mut status = Status::failed_precondition(format!(
        "stale epoch: placement group {pool}/{pg_id} is at epoch {current}; place again"
    ));
    if let Ok(v) = current.to_string().parse() {
        status.metadata_mut().insert(STALE_EPOCH_HEADER, v);
    }
    status
}

#[derive(Default)]
pub struct PgEpochs {
    known: RwLock<HashMap<(String, u32), u64>>,
    meta_endpoint: OnceLock<String>,
}

impl PgEpochs {
    /// Where to ask about an epoch this OSD hasn't heard of.
    pub fn set_meta_endpoint(&self, endpoint: &str) {
        let _ = self.meta_endpoint.set(endpoint.to_string());
    }

    /// Record `epoch` for a PG; an older one than held changes nothing.
    pub fn learn(&self, pool: &str, pg_id: u32, epoch: u64) {
        let mut known = self.known.write();
        let slot = known.entry((pool.to_string(), pg_id)).or_insert(0);
        *slot = (*slot).max(epoch);
    }

    #[must_use]
    pub fn known(&self, pool: &str, pg_id: u32) -> Option<u64> {
        self.known.read().get(&(pool.to_string(), pg_id)).copied()
    }

    /// Whether a request placed as `pg` may be served here.
    ///
    /// # Errors
    /// `StaleEpoch` ([`stale`]) for one placed under an older epoch;
    /// UNAVAILABLE when the epoch has to be asked for and meta can't say.
    pub async fn check(&self, pg: Option<&PgRef>) -> Result<(), Status> {
        let Some(pg) = pg else {
            return Ok(());
        };
        match decide(self.known(&pg.pool, pg.pg_id), pg.epoch) {
            Decision::Accept => Ok(()),
            Decision::Refuse(current) => Err(stale(&pg.pool, pg.pg_id, current)),
            Decision::Ask => {
                let current = self.ask_meta(&pg.pool, pg.pg_id).await.map_err(|e| {
                    Status::unavailable(format!(
                        "epoch of placement group {}/{} unknown here and meta can't say ({e}); retry",
                        pg.pool, pg.pg_id
                    ))
                })?;
                self.learn(&pg.pool, pg.pg_id, current);
                match decide(self.known(&pg.pool, pg.pg_id), pg.epoch) {
                    Decision::Refuse(current) => Err(stale(&pg.pool, pg.pg_id, current)),
                    // Meta has no newer one than the request: it is current.
                    _ => Ok(()),
                }
            }
        }
    }

    async fn ask_meta(&self, pool: &str, pg_id: u32) -> Result<u64, String> {
        let endpoint = self
            .meta_endpoint
            .get()
            .ok_or_else(|| "not registered with meta yet".to_string())?;
        let ask = async {
            let channel = objectio_proto::transport::meta_channel(endpoint).await?;
            MetadataServiceClient::new(channel)
                .get_placement_group(GetPlacementGroupRequest {
                    pool: pool.to_string(),
                    pg_id,
                })
                .await
                .map(|r| r.into_inner().pg.map_or(0, |pg| pg.epoch))
                .map_err(|e| e.message().to_string())
        };
        tokio::time::timeout(ASK_TIMEOUT, ask)
            .await
            .map_err(|_| "timed out".to_string())?
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, PgEpochs, decide};
    use objectio_proto::STALE_EPOCH_HEADER;
    use objectio_proto::storage::PgRef;

    #[test]
    fn a_request_under_an_older_epoch_is_refused_with_the_current_one() {
        assert_eq!(decide(Some(5), 4), Decision::Refuse(5));
        assert_eq!(decide(Some(5), 5), Decision::Accept);
        // Newer than held, or never heard of: meta decides.
        assert_eq!(decide(Some(5), 6), Decision::Ask);
        assert_eq!(decide(None, 1), Decision::Ask);
        // Not placed through a placement group (meta's own writes).
        assert_eq!(decide(Some(5), 0), Decision::Accept);
        assert_eq!(decide(None, 0), Decision::Accept);
    }

    #[test]
    fn an_epoch_learned_never_goes_back() {
        let e = PgEpochs::default();
        e.learn("default", 3, 7);
        e.learn("default", 3, 6);
        assert_eq!(e.known("default", 3), Some(7));
        assert_eq!(e.known("default", 4), None);
        assert_eq!(e.known("other", 3), None);
    }

    #[tokio::test]
    async fn the_refusal_carries_the_epoch_held() {
        let e = PgEpochs::default();
        e.learn("default", 3, 7);
        let pg = |epoch| PgRef {
            pool: "default".into(),
            pg_id: 3,
            epoch,
        };
        let refused = e.check(Some(&pg(6))).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            refused
                .metadata()
                .get(STALE_EPOCH_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
            "7"
        );
        assert!(e.check(Some(&pg(7))).await.is_ok());
        assert!(e.check(None).await.is_ok());
        // Unknown and no meta to ask: not served, but not refused as stale.
        let unknown = e
            .check(Some(&PgRef {
                pool: "default".into(),
                pg_id: 9,
                epoch: 1,
            }))
            .await
            .unwrap_err();
        assert_eq!(unknown.code(), tonic::Code::Unavailable);
    }
}
