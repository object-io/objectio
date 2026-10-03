//! Shard transfers over Mooncake Transfer Engine (feature `rdma`).
//!
//! The OSD initiates every transfer: it reads a PUT shard out of the
//! gateway's buffer, and writes a GET shard into one. Its own staging pool is
//! registered private, so peers cannot reach it — see
//! `objectio_transport_te::Engine::register` for how each transport enforces
//! that. The design is objectio-docs
//! `architecture/design/core/rdma-data-plane.md`.

use std::sync::Arc;

use objectio_proto::storage::RdmaBuffer;
use objectio_transport_te::{
    Engine, EngineConfig, Protocol, Registration, RemoteBuffer, Slot, SlotPool,
};
use tonic::Status;

/// A staging slot holds one shard. Gateways cap a shard just under 4 MiB.
pub const SHARD_SLOT_SIZE: usize = 4 * 1024 * 1024;

/// This OSD's Transfer Engine, and the private pool shards land in.
pub struct RdmaStaging {
    engine: Arc<Engine>,
    pool: SlotPool,
    _registration: Registration,
}

impl RdmaStaging {
    /// Start Transfer Engine on `host` — an address on the storage network —
    /// with `slots` staging slots, which bounds concurrent RDMA shard I/O.
    ///
    /// # Errors
    /// If Transfer Engine cannot start or the pool cannot be registered.
    pub fn start(protocol: Protocol, host: &str, slots: usize) -> Result<Self, String> {
        let engine = Engine::start(&EngineConfig {
            protocol,
            host: host.to_string(),
        })
        .map_err(|e| e.to_string())?;
        let pool = SlotPool::new(SHARD_SLOT_SIZE, slots).map_err(|e| e.to_string())?;
        let registration = engine.register(&pool, false).map_err(|e| e.to_string())?;
        Ok(Self {
            engine,
            pool,
            _registration: registration,
        })
    }

    /// The segment gateways address this OSD's transfers to, `ip:port`.
    #[must_use]
    pub fn segment(&self) -> &str {
        self.engine.segment()
    }

    /// Read a PUT shard from `src` into a staging slot and check it against
    /// the CRC32C the gateway computed. Returns the slot and the shard length.
    pub async fn pull(&self, src: &RdmaBuffer, crc32c: u32) -> Result<(Slot, usize), Status> {
        let len = shard_len(src)?;
        let slot = self.slot()?;
        let started = std::time::Instant::now();
        let slot = self
            .engine
            .read(slot, 0, remote(src))
            .await
            .map_err(|e| Status::unavailable(format!("rdma read from {}: {e}", src.segment)))?;
        let read = started.elapsed();
        let got = crc32c::crc32c(&slot.as_slice()[..len]);
        tracing::debug!(
            target: "objectio_osd::rdma",
            read_us = read.as_micros(),
            crc_us = (started.elapsed() - read).as_micros(),
            len,
            "rdma pull"
        );
        if got != crc32c {
            return Err(Status::data_loss(format!(
                "shard read over rdma has crc32c {got:08x}, expected {crc32c:08x}"
            )));
        }
        Ok((slot, len))
    }

    /// Write a GET shard into the gateway's buffer at `dest`.
    pub async fn push(&self, data: &[u8], dest: &RdmaBuffer) -> Result<(), Status> {
        if data.len() as u64 > dest.len {
            return Err(Status::invalid_argument(format!(
                "a {}-byte shard does not fit a {}-byte rdma_dest",
                data.len(),
                dest.len
            )));
        }
        let mut slot = self.slot()?;
        slot.as_mut_slice()[..data.len()].copy_from_slice(data);
        let target = RemoteBuffer {
            segment: dest.segment.clone(),
            addr: dest.addr,
            len: data.len() as u64,
        };
        self.engine
            .write(slot, 0, target)
            .await
            .map_err(|e| Status::unavailable(format!("rdma write to {}: {e}", dest.segment)))?;
        Ok(())
    }

    /// A staging slot, or `RESOURCE_EXHAUSTED` — the gateway then retries the
    /// shard over gRPC rather than waiting here.
    #[allow(clippy::result_large_err)] // Err goes straight back to the gRPC caller.
    fn slot(&self) -> Result<Slot, Status> {
        self.pool
            .acquire()
            .ok_or_else(|| Status::resource_exhausted("no free rdma staging slot"))
    }
}

#[allow(clippy::result_large_err)] // Err goes straight back to the gRPC caller.
fn shard_len(src: &RdmaBuffer) -> Result<usize, Status> {
    usize::try_from(src.len)
        .ok()
        .filter(|&len| len > 0 && len <= SHARD_SLOT_SIZE)
        .ok_or_else(|| {
            Status::invalid_argument(format!(
                "rdma shard of {} bytes: must be 1..={SHARD_SLOT_SIZE}",
                src.len
            ))
        })
}

fn remote(buf: &RdmaBuffer) -> RemoteBuffer {
    RemoteBuffer {
        segment: buf.segment.clone(),
        addr: buf.addr,
        len: buf.len,
    }
}

/// `--rdma` value to a protocol.
///
/// # Errors
/// For anything other than `tcp` or `rdma`.
pub fn parse_protocol(s: &str) -> Result<Protocol, String> {
    match s {
        "rdma" => Ok(Protocol::Rdma),
        "tcp" => Ok(Protocol::Tcp),
        other => Err(format!("--rdma {other}: expected rdma or tcp")),
    }
}
