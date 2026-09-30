/// Errors from the shard transport.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A pool was asked for zero-sized slots, no slots, or more bytes than
    /// fit in memory.
    #[error("invalid pool: {0}")]
    InvalidPool(&'static str),

    /// The allocator could not supply a pool's memory.
    #[error("could not allocate {0} bytes for a slot pool")]
    OutOfMemory(usize),

    /// A transfer's local range falls outside the slot it was given.
    #[error("range {offset}+{len} does not fit a {capacity}-byte slot")]
    OutOfRange {
        offset: usize,
        len: usize,
        capacity: usize,
    },

    /// A transfer used a slot from a pool this engine never registered.
    #[error("slot is not in memory registered with this engine")]
    NotRegistered,

    /// Transfer Engine rejected a call.
    #[error("transfer engine: {0}")]
    Engine(String),

    /// A transfer reached a terminal state other than completed.
    #[error("transfer to {segment} ended {status}")]
    TransferFailed { segment: String, status: String },

    /// The engine's completion thread has stopped.
    #[error("transfer engine has shut down")]
    ShutDown,
}
