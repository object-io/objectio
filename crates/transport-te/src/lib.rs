//! Shard transport over Mooncake Transfer Engine.
//!
//! Moves shard bytes between gateways and OSDs over RDMA — or over TCP, which
//! is how it is developed and tested without RDMA hardware — while gRPC keeps
//! carrying control. The design is
//! `objectio-docs/architecture/design/core/rdma-data-plane.md`.
//!
//! Two halves:
//!
//! - [`SlotPool`] — fixed-size, 4 KiB-aligned slots carved from one
//!   allocation, so the whole pool is registered with the NIC once. Always
//!   built, no Mooncake needed.
//! - [`Engine`] (feature `te`) — owns a Transfer Engine instance, registers
//!   pools, and runs transfers. Linux only; needs a Mooncake build.
//!
//! Every `unsafe` block in the transport lives in this crate.
//!
//! The pool's tests run everywhere. The engine's run in TCP mode against a
//! Mooncake build — `test.Dockerfile` in this crate builds one and runs them.

mod error;
mod pool;

#[cfg(feature = "te")]
mod engine;

pub use error::Error;
pub use pool::{ALIGN, Slot, SlotPool};

#[cfg(feature = "te")]
pub use engine::{Engine, EngineConfig, Protocol, Registration, RemoteBuffer};
