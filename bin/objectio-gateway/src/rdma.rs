//! The gateway's side of shard transfers over Mooncake Transfer Engine.
//!
//! The OSD initiates every transfer (objectio-docs
//! `architecture/design/rdma-data-plane.md`), so the gateway never calls
//! Transfer Engine itself. It keeps two remote-accessible pools the OSDs
//! reach into:
//!
//! - **stripe slots**, each holding one encoded stripe (k data then m parity
//!   shards, contiguous), that OSDs read PUT shards out of;
//! - **read slots**, each holding one shard, that OSDs write GET shards into.
//!
//! and decides, shard by shard, whether a transfer goes over Transfer Engine
//! or as gRPC bytes. RDMA is an optimisation, never a dependency: no segment,
//! no free slot, a busy or failing OSD — the shard goes over gRPC.
//!
//! Two rules keep a peer from ever touching memory that has moved on:
//!
//! - A slot whose transfer ended in an error is **quarantined**, not reused,
//!   for longer than any transfer can take — an OSD may still be reading or
//!   writing it after the gateway gave up.
//! - An OSD whose transfer failed is skipped for a **cool-down**, so a broken
//!   path costs one failed attempt, not one per request.
//!
//! Without the `rdma` feature this type cannot be constructed, and every
//! shard goes over gRPC.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use objectio_transport_te::{Slot, SlotPool};

/// How long a slot stays out of use after its transfer failed. Longer than
/// the OSD's gRPC timeouts (30 s write, 10 s read), after which it has
/// stopped touching the slot.
const QUARANTINE: Duration = Duration::from_secs(60);

/// How long an OSD is skipped after a transfer to it failed.
const COOL_DOWN: Duration = Duration::from_secs(30);

/// Each slot shard is at most this: gateways cap a shard just under 4 MiB.
pub const SHARD_SLOT_SIZE: usize = 4 * 1024 * 1024;

/// Why a shard went over gRPC instead of Transfer Engine. Only for shards
/// that could have used it: the OSD advertised a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// Every slot was in use.
    NoSlot,
    /// The OSD had no staging slot free (`RESOURCE_EXHAUSTED`).
    OsdBusy,
    /// The OSD is in its cool-down after an earlier failure.
    Cooling,
    /// The transfer failed or timed out.
    Error,
    /// The bytes that arrived did not match the OSD's checksum.
    Checksum,
}

impl Fallback {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NoSlot => "no_slot",
            Self::OsdBusy => "osd_busy",
            Self::Cooling => "cooling",
            Self::Error => "error",
            Self::Checksum => "checksum",
        }
    }
}

/// The gateway's Transfer Engine segment and the pools OSDs transfer through.
pub struct GatewayRdma {
    segment: String,
    stripe_pool: SlotPool,
    read_pool: SlotPool,
    cooling: Mutex<HashMap<String, Instant>>,
    quarantine: Mutex<VecDeque<(Instant, Bytes)>>,
    // Keeps Transfer Engine running and the pools registered with it.
    #[cfg(feature = "rdma")]
    _engine: std::sync::Arc<objectio_transport_te::Engine>,
    #[cfg(feature = "rdma")]
    _registrations: Vec<objectio_transport_te::Registration>,
}

impl GatewayRdma {
    /// Start Transfer Engine on `host` — an address on the storage network —
    /// and register both pools with it, remote-accessible.
    ///
    /// # Errors
    /// If Transfer Engine cannot start or a pool cannot be allocated or
    /// registered.
    #[cfg(feature = "rdma")]
    pub fn start(
        protocol: objectio_transport_te::Protocol,
        host: &str,
        stripe_slot_size: usize,
        stripe_slots: usize,
        read_slots: usize,
    ) -> Result<Self, String> {
        let engine = objectio_transport_te::Engine::start(&objectio_transport_te::EngineConfig {
            protocol,
            host: host.to_string(),
        })
        .map_err(|e| e.to_string())?;
        let stripe_pool =
            SlotPool::new(stripe_slot_size, stripe_slots).map_err(|e| e.to_string())?;
        let read_pool = SlotPool::new(SHARD_SLOT_SIZE, read_slots).map_err(|e| e.to_string())?;
        let registrations = vec![
            engine
                .register(&stripe_pool, true)
                .map_err(|e| e.to_string())?,
            engine
                .register(&read_pool, true)
                .map_err(|e| e.to_string())?,
        ];
        Ok(Self {
            segment: engine.segment().to_string(),
            stripe_pool,
            read_pool,
            cooling: Mutex::new(HashMap::new()),
            quarantine: Mutex::new(VecDeque::new()),
            _engine: engine,
            _registrations: registrations,
        })
    }

    /// This gateway's segment: where OSDs find the buffers named in requests.
    #[must_use]
    pub fn segment(&self) -> &str {
        &self.segment
    }

    /// Whether a shard for the OSD at `te_segment` should try Transfer
    /// Engine: it has one, and is not cooling down. `Err` says why not, for
    /// an OSD that has a segment.
    pub fn check(&self, te_segment: &str) -> Result<(), Option<Fallback>> {
        if te_segment.is_empty() {
            return Err(None);
        }
        let mut cooling = lock(&self.cooling);
        match cooling.get(te_segment) {
            Some(&until) if Instant::now() < until => Err(Some(Fallback::Cooling)),
            Some(_) => {
                cooling.remove(te_segment);
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Skip the OSD at `te_segment` for a while: a transfer to it failed.
    pub fn cool_down(&self, te_segment: &str) {
        lock(&self.cooling).insert(te_segment.to_string(), Instant::now() + COOL_DOWN);
    }

    /// A slot for one encoded stripe of `len` bytes, if it fits and one is
    /// free.
    #[must_use]
    pub fn stripe_slot(&self, len: usize) -> Option<Slot> {
        self.release_quarantined();
        (len <= self.stripe_pool.slot_size())
            .then(|| self.stripe_pool.acquire())
            .flatten()
    }

    /// A slot one shard can be written into.
    #[must_use]
    pub fn read_slot(&self) -> Option<Slot> {
        self.release_quarantined();
        self.read_pool.acquire()
    }

    /// Hold memory an OSD may still be transferring through — its transfer
    /// failed, but the OSD side may not have stopped — until it is safe to
    /// reuse.
    pub fn quarantine(&self, held: Bytes) {
        lock(&self.quarantine).push_back((Instant::now() + QUARANTINE, held));
    }

    fn release_quarantined(&self) {
        let now = Instant::now();
        let mut q = lock(&self.quarantine);
        while q.front().is_some_and(|(until, _)| *until <= now) {
            q.pop_front();
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `GatewayRdma` without Transfer Engine, for the bookkeeping that does
    /// not need it.
    fn bookkeeping_only(stripe_slots: usize, read_slots: usize) -> GatewayRdma {
        GatewayRdma {
            segment: "10.0.0.1:15000".into(),
            stripe_pool: SlotPool::new(8192, stripe_slots).unwrap(),
            read_pool: SlotPool::new(4096, read_slots).unwrap(),
            cooling: Mutex::new(HashMap::new()),
            quarantine: Mutex::new(VecDeque::new()),
            #[cfg(feature = "rdma")]
            _engine: unreachable_engine(),
            #[cfg(feature = "rdma")]
            _registrations: Vec::new(),
        }
    }

    #[cfg(feature = "rdma")]
    fn unreachable_engine() -> std::sync::Arc<objectio_transport_te::Engine> {
        objectio_transport_te::Engine::start(&objectio_transport_te::EngineConfig {
            protocol: objectio_transport_te::Protocol::Tcp,
            host: "127.0.0.1".into(),
        })
        .unwrap()
    }

    #[test]
    fn only_osds_with_a_segment_that_are_not_cooling_down_are_tried() {
        let r = bookkeeping_only(1, 1);
        assert_eq!(r.check(""), Err(None));
        assert_eq!(r.check("10.0.0.2:15000"), Ok(()));
        r.cool_down("10.0.0.2:15000");
        assert_eq!(r.check("10.0.0.2:15000"), Err(Some(Fallback::Cooling)));
        assert_eq!(r.check("10.0.0.3:15000"), Ok(()), "cooling is per OSD");
    }

    #[test]
    fn a_stripe_that_does_not_fit_a_slot_gets_none() {
        let r = bookkeeping_only(1, 1);
        assert!(r.stripe_slot(8193).is_none());
        assert!(r.stripe_slot(8192).is_some());
    }

    #[test]
    fn a_quarantined_slot_is_not_handed_out_again() {
        let r = bookkeeping_only(1, 1);
        let slot = r.read_slot().unwrap();
        r.quarantine(slot.into_bytes(0));
        assert!(r.read_slot().is_none(), "a quarantined slot was reused");
        // Once its time is up it comes back.
        lock(&r.quarantine).front_mut().unwrap().0 = Instant::now();
        assert!(r.read_slot().is_some());
    }
}
