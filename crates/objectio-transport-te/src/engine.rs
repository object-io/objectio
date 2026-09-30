//! A Transfer Engine instance, the pools registered with it, and transfers.
//!
//! Transfer Engine's hot path is synchronous: submit a batch, then poll its
//! status. That must not happen on a tokio worker, so every [`Engine`] runs one
//! **completion thread**. An async caller hands it a transfer and awaits a
//! oneshot; the thread submits, polls, and answers.
//!
//! A transfer takes **ownership of its slot** and gives it back on success.
//! If the caller's future is dropped mid-transfer, the slot stays with the
//! completion thread until the hardware has finished with it — so a slot is
//! never back in the pool while a NIC may still be writing into it.
//!
//! Peers are addressed with `P2PHANDSHAKE`: a segment is just `ip:port`, and
//! no metadata server (etcd, Redis, HTTP) is involved.

// FFI into Transfer Engine, and raw pointers into registered pools. The
// soundness argument is on each block; the pool's is in `pool.rs`.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use tokio::sync::oneshot;
use tracing::{debug, warn};
use transfer_engine_rust::{
    BatchId, SegmentId, TransferEngine, TransferRequest, TransferStatusCode, WILDCARD_LOCATION,
};

use crate::{Error, Slot, SlotPool};

/// How transfers travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// RDMA verbs: real RNICs, or `SoftRoCE` for development.
    Rdma,
    /// Plain TCP. Same API and code path, no RDMA hardware needed — but see
    /// [`Engine::register`]: TCP cannot keep a registered buffer private.
    Tcp,
}

impl Protocol {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Rdma => "rdma",
            Self::Tcp => "tcp",
        }
    }
}

/// How to start an [`Engine`].
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub protocol: Protocol,
    /// Address peers reach this process on — the storage-network interface,
    /// never a public one. Transfer Engine picks its own RPC port.
    pub host: String,
}

/// Memory in another process, as named in a shard request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBuffer {
    /// The owning process's segment, `ip:port`.
    pub segment: String,
    /// Start address in that process.
    pub addr: u64,
    pub len: u64,
}

/// A running Transfer Engine plus its completion thread.
pub struct Engine {
    te: Arc<TransferEngine>,
    protocol: Protocol,
    segment: String,
    ops: Mutex<Option<mpsc::Sender<Op>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    segments: Mutex<HashMap<String, SegmentId>>,
    registered: Mutex<Vec<SlotPool>>,
}

impl Engine {
    /// Start Transfer Engine and its completion thread.
    ///
    /// # Errors
    /// [`Error::Engine`] if Transfer Engine cannot start or install the
    /// transport.
    pub fn start(config: &EngineConfig) -> Result<Arc<Self>, Error> {
        let te =
            TransferEngine::initialize(&config.host, "P2PHANDSHAKE", config.protocol.as_str(), "")
                .map_err(|e| Error::Engine(format!("start ({:?}): {e}", config.protocol)))?;
        let segment = te
            .local_ip_and_port()
            .map_err(|e| Error::Engine(format!("local segment: {e}")))?;
        let te = Arc::new(te);

        let (tx, rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("te-completion".into())
            .spawn({
                let te = Arc::clone(&te);
                move || completion_loop(&te, &rx)
            })
            .map_err(|e| Error::Engine(format!("spawn completion thread: {e}")))?;
        debug!(%segment, protocol = ?config.protocol, "transfer engine started");

        Ok(Arc::new(Self {
            te,
            protocol: config.protocol,
            segment,
            ops: Mutex::new(Some(tx)),
            thread: Mutex::new(Some(thread)),
            segments: Mutex::new(HashMap::new()),
            registered: Mutex::new(Vec::new()),
        }))
    }

    /// This process's segment, `ip:port`: what peers put in a
    /// [`RemoteBuffer`] to reach memory registered here.
    #[must_use]
    pub fn segment(&self) -> &str {
        &self.segment
    }

    /// Register `pool` for transfers.
    ///
    /// `remote_accessible` decides whether *peers* may read and write it. The
    /// design keeps it `false` on OSDs, which only ever initiate: their memory
    /// is then unreachable from the fabric. Gateways register theirs `true`.
    ///
    /// How that is enforced depends on the transport:
    /// - **RDMA:** Transfer Engine registers the memory region without remote
    ///   access rights, so the NIC refuses peers.
    /// - **TCP:** Transfer Engine ignores the flag — any buffer registered
    ///   with it is readable and writable by any peer that reaches its port.
    ///   So a private pool is *not* registered with Transfer Engine at all:
    ///   an initiator's local buffer needs no registration over TCP, and a
    ///   peer asking for an address outside every registered buffer is
    ///   refused. This engine still tracks the pool, for its own checks.
    ///
    /// # Errors
    /// [`Error::Engine`] if Transfer Engine refuses the registration.
    pub fn register(
        self: &Arc<Self>,
        pool: &SlotPool,
        remote_accessible: bool,
    ) -> Result<Registration, Error> {
        let with_te = remote_accessible || self.protocol == Protocol::Rdma;
        if with_te {
            // SAFETY: the pool's region is valid for `pool.len()` bytes, and
            // the `Registration` returned keeps a clone of the pool — so the
            // region outlives the registration, which is undone before it is
            // dropped.
            unsafe {
                self.te.register_local_memory_ex(
                    pool.base_ptr().cast::<c_void>(),
                    pool.len(),
                    WILDCARD_LOCATION,
                    remote_accessible,
                )
            }
            .map_err(|e| Error::Engine(format!("register {} bytes: {e}", pool.len())))?;
        }
        lock(&self.registered).push(pool.clone());
        Ok(Registration {
            engine: Arc::clone(self),
            pool: pool.clone(),
            with_te,
        })
    }

    /// Read `remote` into `slot[offset..offset + remote.len]`, returning the
    /// slot when the bytes have landed.
    ///
    /// # Errors
    /// [`Error::OutOfRange`], [`Error::NotRegistered`], a failed segment open
    /// or transfer, or [`Error::ShutDown`].
    pub async fn read(
        &self,
        slot: Slot,
        offset: usize,
        remote: RemoteBuffer,
    ) -> Result<Slot, Error> {
        self.transfer(Direction::Read, slot, offset, &remote).await
    }

    /// Write `slot[offset..offset + remote.len]` to `remote`, returning the
    /// slot when the peer has the bytes.
    ///
    /// # Errors
    /// As for [`Self::read`].
    pub async fn write(
        &self,
        slot: Slot,
        offset: usize,
        remote: RemoteBuffer,
    ) -> Result<Slot, Error> {
        self.transfer(Direction::Write, slot, offset, &remote).await
    }

    async fn transfer(
        &self,
        direction: Direction,
        slot: Slot,
        offset: usize,
        remote: &RemoteBuffer,
    ) -> Result<Slot, Error> {
        let len = usize::try_from(remote.len).map_err(|_| Error::OutOfRange {
            offset,
            len: usize::MAX,
            capacity: slot.capacity(),
        })?;
        if offset
            .checked_add(len)
            .is_none_or(|end| end > slot.capacity())
        {
            return Err(Error::OutOfRange {
                offset,
                len,
                capacity: slot.capacity(),
            });
        }
        let local = slot.addr() + offset as u64;
        if !lock(&self.registered)
            .iter()
            .any(|p| p.contains(local, remote.len))
        {
            return Err(Error::NotRegistered);
        }

        let target = self.open_segment(&remote.segment).await?;
        let local = local as *mut c_void;
        let request = match direction {
            Direction::Read => TransferRequest::read(local, target, remote.addr, remote.len),
            Direction::Write => TransferRequest::write(local, target, remote.addr, remote.len),
        };

        let (reply, done) = oneshot::channel();
        lock(&self.ops)
            .as_ref()
            .ok_or(Error::ShutDown)?
            .send(Op {
                request,
                segment: remote.segment.clone(),
                slot,
                reply,
            })
            .map_err(|_| Error::ShutDown)?;
        done.await.map_err(|_| Error::ShutDown)?
    }

    /// The segment id for `name`, opening it on first use. Opening performs
    /// the P2P handshake over the network, so it runs off the async runtime.
    async fn open_segment(&self, name: &str) -> Result<SegmentId, Error> {
        if let Some(&id) = lock(&self.segments).get(name) {
            return Ok(id);
        }
        let te = Arc::clone(&self.te);
        let owned = name.to_string();
        let id = tokio::task::spawn_blocking(move || te.open_segment(&owned))
            .await
            .map_err(|e| Error::Engine(format!("open segment {name}: {e}")))?
            .map_err(|e| Error::Engine(format!("open segment {name}: {e}")))?;
        lock(&self.segments).insert(name.to_string(), id);
        Ok(id)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Closing the channel lets the completion thread finish what is in
        // flight — it holds those slots until then — and exit.
        lock(&self.ops).take();
        if let Some(thread) = lock(&self.thread).take()
            && thread.join().is_err()
        {
            warn!("transfer engine completion thread panicked");
        }
    }
}

/// A pool registered with an [`Engine`]. Unregisters on drop.
pub struct Registration {
    engine: Arc<Engine>,
    pool: SlotPool,
    /// Whether the pool was registered with Transfer Engine itself (see
    /// [`Engine::register`]), and so must be unregistered there.
    with_te: bool,
}

impl Drop for Registration {
    fn drop(&mut self) {
        lock(&self.engine.registered).retain(|p| p.base_ptr() != self.pool.base_ptr());
        if !self.with_te {
            return;
        }
        // SAFETY: `base_ptr` is the address passed to `register_local_memory_ex`
        // in `Engine::register`, and the pool (held here) is still alive.
        if let Err(e) = unsafe {
            self.engine
                .te
                .unregister_local_memory(self.pool.base_ptr().cast::<c_void>())
        } {
            warn!("unregister {} bytes: {e}", self.pool.len());
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Read,
    Write,
}

/// A transfer handed to the completion thread. Owns the slot it moves bytes
/// through until the transfer is terminal.
struct Op {
    request: TransferRequest,
    segment: String,
    slot: Slot,
    reply: oneshot::Sender<Result<Slot, Error>>,
}

// SAFETY: `TransferRequest` holds a raw pointer into `slot`, which the `Op`
// owns — moving the `Op` to the completion thread moves exclusive use of that
// memory with it.
unsafe impl Send for Op {}

struct InFlight {
    batch: BatchId,
    op: Op,
}

fn completion_loop(te: &TransferEngine, ops: &mpsc::Receiver<Op>) {
    let mut in_flight: Vec<InFlight> = Vec::new();
    loop {
        // Idle: block for work. Busy: take whatever else has arrived.
        if in_flight.is_empty() {
            match ops.recv() {
                Ok(op) => submit(te, op, &mut in_flight),
                Err(_) => return,
            }
        }
        while let Ok(op) = ops.try_recv() {
            submit(te, op, &mut in_flight);
        }

        // Answer every transfer that has finished; keep polling the rest.
        let mut i = 0;
        while i < in_flight.len() {
            let status = te.get_transfer_status(in_flight[i].batch, 0);
            if matches!(&status, Ok(s) if !s.status.is_terminal()) {
                i += 1;
                continue;
            }
            let done = in_flight.swap_remove(i);
            if let Err(e) = te.free_batch_id(done.batch) {
                warn!("free transfer batch: {e}");
            }
            let outcome = match status {
                Ok(s) if s.status == TransferStatusCode::Completed => Ok(()),
                Ok(s) => Err(Error::TransferFailed {
                    segment: done.op.segment.clone(),
                    status: format!("{:?}", s.status),
                }),
                Err(e) => Err(Error::Engine(format!("transfer status: {e}"))),
            };
            reply(done.op, outcome);
        }

        // Transfers are in flight: poll again without sleeping, but yield so
        // other threads on this core still run.
        if !in_flight.is_empty() {
            std::thread::yield_now();
        }
    }
}

fn submit(te: &TransferEngine, op: Op, in_flight: &mut Vec<InFlight>) {
    let batch = match te.allocate_batch_id(1) {
        Ok(b) => b,
        Err(e) => return reply(op, Err(Error::Engine(format!("allocate batch: {e}")))),
    };
    // SAFETY: the request's local pointer is inside `op.slot`, a slot of a
    // registered pool (checked in `Engine::transfer`), and `op` — so the slot —
    // stays in `in_flight` until the transfer is terminal.
    match unsafe { te.submit_transfer(batch, std::slice::from_ref(&op.request)) } {
        Ok(()) => in_flight.push(InFlight { batch, op }),
        Err(e) => {
            if let Err(e) = te.free_batch_id(batch) {
                warn!("free transfer batch: {e}");
            }
            let error = Error::Engine(format!("submit to {}: {e}", op.segment));
            reply(op, Err(error));
        }
    }
}

/// Answer a transfer. On success the slot goes back to the caller; on
/// failure — or if the caller has stopped waiting — it drops back into its
/// pool, which is safe because the transfer is terminal.
fn reply(op: Op, outcome: Result<(), Error>) {
    let _ = op.reply.send(outcome.map(|()| op.slot));
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    //! Run in TCP mode, so they need a Mooncake build but no RDMA hardware:
    //! `cargo test -p objectio-transport-te --features te`.

    use super::*;

    const MIB: usize = 1024 * 1024;

    fn tcp_engine() -> Arc<Engine> {
        Engine::start(&EngineConfig {
            protocol: Protocol::Tcp,
            host: "127.0.0.1".into(),
        })
        .expect("start transfer engine")
    }

    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap() ^ seed)
            .collect()
    }

    /// A "gateway" engine with a remote-accessible pool and an "OSD" engine
    /// with a private one, as in the design.
    struct Pair {
        gateway: Arc<Engine>,
        gateway_pool: SlotPool,
        osd: Arc<Engine>,
        osd_pool: SlotPool,
        _registrations: Vec<Registration>,
    }

    fn pair(slots: usize) -> Pair {
        let gateway = tcp_engine();
        let osd = tcp_engine();
        let gateway_pool = SlotPool::new(MIB, slots).unwrap();
        let osd_pool = SlotPool::new(MIB, slots).unwrap();
        let registrations = vec![
            gateway.register(&gateway_pool, true).unwrap(),
            osd.register(&osd_pool, false).unwrap(),
        ];
        Pair {
            gateway,
            gateway_pool,
            osd,
            osd_pool,
            _registrations: registrations,
        }
    }

    fn remote(engine: &Engine, slot: &Slot, len: usize) -> RemoteBuffer {
        RemoteBuffer {
            segment: engine.segment().to_string(),
            addr: slot.addr(),
            len: len as u64,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn osd_pulls_a_shard_and_pushes_one_back() {
        let p = pair(2);

        // PUT shape: the OSD reads a shard out of the gateway's slot.
        let mut shard = p.gateway_pool.acquire().unwrap();
        shard.as_mut_slice().copy_from_slice(&pattern(1, MIB));
        let staging = p.osd_pool.acquire().unwrap();
        let staging = p
            .osd
            .read(staging, 0, remote(&p.gateway, &shard, MIB))
            .await
            .unwrap();
        assert_eq!(staging.as_slice(), &pattern(1, MIB)[..]);

        // GET shape: the OSD writes a shard into the gateway's slot.
        let mut staging = staging;
        staging.as_mut_slice().copy_from_slice(&pattern(2, MIB));
        let dest = p.gateway_pool.acquire().unwrap();
        p.osd
            .write(staging, 0, remote(&p.gateway, &dest, MIB))
            .await
            .unwrap();
        assert_eq!(dest.as_slice(), &pattern(2, MIB)[..]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn partial_ranges_land_at_the_offset() {
        let p = pair(1);
        let mut src = p.gateway_pool.acquire().unwrap();
        src.as_mut_slice()[..4096].copy_from_slice(&pattern(3, 4096));
        let dst = p.osd_pool.acquire().unwrap();
        let dst = p
            .osd
            .read(dst, 8192, remote(&p.gateway, &src, 4096))
            .await
            .unwrap();
        assert_eq!(&dst.as_slice()[8192..12288], &pattern(3, 4096)[..]);
        assert!(dst.as_slice()[..8192].iter().all(|&b| b == 0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refuses_unregistered_memory_and_bad_ranges() {
        let p = pair(1);
        let src = p.gateway_pool.acquire().unwrap();

        let stray = SlotPool::new(MIB, 1).unwrap();
        let err = p
            .osd
            .read(stray.acquire().unwrap(), 0, remote(&p.gateway, &src, 4096))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotRegistered), "{err}");

        let err = p
            .osd
            .read(
                p.osd_pool.acquire().unwrap(),
                MIB - 1,
                remote(&p.gateway, &src, 4096),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::OutOfRange { .. }), "{err}");
        assert_eq!(
            p.osd_pool.available(),
            1,
            "a refused transfer kept its slot"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_rejects_addresses_it_did_not_register() {
        let p = pair(1);
        let bogus = RemoteBuffer {
            segment: p.gateway.segment().to_string(),
            addr: 0x1000,
            len: 4096,
        };
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            p.osd.read(p.osd_pool.acquire().unwrap(), 0, bogus),
        )
        .await
        .expect("a rejected transfer must end, not hang")
        .unwrap_err();
        assert!(matches!(err, Error::TransferFailed { .. }), "{err}");
        assert_eq!(p.osd_pool.available(), 1, "a failed transfer kept its slot");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_private_pool_cannot_be_reached_by_a_peer() {
        // The OSD registers its staging pool with remote_accessible = false.
        // A peer that learns one of its addresses must still be refused.
        let p = pair(1);
        let mut secret = p.osd_pool.acquire().unwrap();
        secret.as_mut_slice().fill(0x5a);
        let target = RemoteBuffer {
            segment: p.osd.segment().to_string(),
            addr: secret.addr(),
            len: 4096,
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            p.gateway.read(p.gateway_pool.acquire().unwrap(), 0, target),
        )
        .await
        .expect("a refused transfer must end, not hang");
        assert!(
            result.is_err(),
            "a peer read {} bytes of a private pool",
            4096
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dropped_transfer_keeps_its_slot_until_it_finishes() {
        let p = pair(1);
        let src = p.gateway_pool.acquire().unwrap();
        let fut = p.osd.read(
            p.osd_pool.acquire().unwrap(),
            0,
            remote(&p.gateway, &src, MIB),
        );
        // Poll once so the transfer is submitted, then abandon it.
        let _ = tokio::time::timeout(std::time::Duration::from_micros(1), fut).await;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while p.osd_pool.available() == 0 {
            assert!(std::time::Instant::now() < deadline, "slot never came back");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sixteen_shards_at_once() {
        let p = pair(16);
        let mut shards = Vec::new();
        for i in 0..16u8 {
            let mut s = p.gateway_pool.acquire().unwrap();
            s.as_mut_slice().copy_from_slice(&pattern(i, MIB));
            shards.push(s);
        }
        let reads = shards.iter().map(|s| {
            let dst = p.osd_pool.acquire().unwrap();
            p.osd.read(dst, 0, remote(&p.gateway, s, MIB))
        });
        let got = futures::future::join_all(reads).await;
        for (i, slot) in got.into_iter().enumerate() {
            assert_eq!(
                slot.unwrap().as_slice(),
                &pattern(u8::try_from(i).unwrap(), MIB)[..]
            );
        }
    }
}
