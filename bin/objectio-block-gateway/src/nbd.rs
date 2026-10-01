//! NBD (Network Block Device) newstyle v2 server
//!
//! Implements the NBD newstyle protocol over TCP, multiplexed by export name
//! (= volume_id). One TCP listener on a single port; clients select the volume
//! via the NBD_OPT_GO option during the handshake.

#![allow(clippy::cast_possible_truncation)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use objectio_proto::block::Attachment;
use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::metrics::{Io, Protocol};
use crate::resolve::Resolver;

// ── NBD protocol constants ────────────────────────────────────────────────────

const NBD_MAGIC: u64 = 0x4e42_444d_4147_4943; // "NBDMAGIC"
const NBD_IHAVEOPT: u64 = 0x4948_4156_454f_5054; // "IHAVEOPT"
const NBD_OPTION_REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
const NBD_REPLY_MAGIC: u32 = 0x6744_6698;

// Handshake flags
const NBD_FLAG_FIXED_NEWSTYLE: u16 = 0x0001;
const NBD_FLAG_NO_ZEROES: u16 = 0x0002;

// Option IDs
const NBD_OPT_EXPORT_NAME: u32 = 1;
const NBD_OPT_ABORT: u32 = 2;
const NBD_OPT_LIST: u32 = 3;
const NBD_OPT_GO: u32 = 7;
const NBD_OPT_INFO: u32 = 6;

// Reply types
const NBD_REP_ACK: u32 = 1;
const NBD_REP_SERVER: u32 = 2;
const NBD_REP_INFO: u32 = 3;
const NBD_REP_ERR_UNSUP: u32 = 0x8000_0001;
const NBD_REP_ERR_UNKNOWN: u32 = 0x8000_0006;

// Transmission flags (for export info)
const NBD_FLAG_HAS_FLAGS: u16 = 0x0001;
const NBD_FLAG_SEND_FLUSH: u16 = 0x0004;
const NBD_FLAG_SEND_TRIM: u16 = 0x0008;

// Info types
const NBD_INFO_EXPORT: u16 = 0;

// Commands
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;

/// Requests served at once on one connection. The kernel client queues up
/// to 128; more than this waits to be read.
const MAX_IN_FLIGHT: usize = 64;
const NBD_CMD_FLUSH: u16 = 3;
const NBD_CMD_TRIM: u16 = 4;

// ── Export registry ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct NbdExport {
    size_bytes: u64,
    read_only: bool,
}

pub struct NbdServer {
    exports: RwLock<HashMap<String, NbdExport>>,
    /// Keep a reference to the shared gateway state for I/O
    cache: Arc<objectio_block::WriteCache>,
    resolver: Arc<Resolver>,
}

/// A simple reply's header: magic, error, handle, big-endian.
fn reply_header(handle: u64, error: u32) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[..4].copy_from_slice(&NBD_REPLY_MAGIC.to_be_bytes());
    h[4..8].copy_from_slice(&error.to_be_bytes());
    h[8..].copy_from_slice(&handle.to_be_bytes());
    h
}

impl NbdServer {
    pub fn new(cache: Arc<objectio_block::WriteCache>, resolver: Arc<Resolver>) -> Self {
        Self {
            exports: RwLock::new(HashMap::new()),
            cache,
            resolver,
        }
    }

    /// Register a volume as an NBD export.
    pub fn register(&self, vol_id: &str, size_bytes: u64, read_only: bool) {
        self.exports.write().insert(
            vol_id.to_string(),
            NbdExport {
                size_bytes,
                read_only,
            },
        );
        info!("NBD: registered export '{vol_id}' ({size_bytes}B)");
    }

    /// Unregister a volume export.
    pub fn unregister(&self, vol_id: &str) {
        if self.exports.write().remove(vol_id).is_some() {
            info!("NBD: unregistered export '{vol_id}'");
        }
    }

    /// Return current attachments as proto Attachment records.
    pub fn list_attachments(&self, volume_id_filter: &str) -> Vec<Attachment> {
        self.exports
            .read()
            .iter()
            .filter(|(id, _)| volume_id_filter.is_empty() || id.as_str() == volume_id_filter)
            .map(|(id, export)| Attachment {
                volume_id: id.clone(),
                target_type: 3, // NBD
                target_address: String::new(),
                initiator: String::new(),
                attached_at: 0,
                read_only: export.read_only,
            })
            .collect()
    }

    /// Start the NBD TCP listener.
    pub async fn serve(self: Arc<Self>, addr: SocketAddr) {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("NBD: failed to bind {addr}: {e}");
                return;
            }
        };
        info!("NBD: listening on {addr}");

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    // Every reply is small and answers a request the client
                    // is waiting on. With Nagle on, a reply sent in more
                    // than one segment waited for the client's delayed ACK:
                    // ~40 ms on Linux, on every read, write and flush.
                    if let Err(e) = stream.set_nodelay(true) {
                        warn!("NBD: cannot set TCP_NODELAY for {peer}: {e}");
                    }
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_client(stream, peer).await {
                            warn!("NBD: client {peer} error: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("NBD: accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn handle_client(
        self: Arc<Self>,
        mut stream: TcpStream,
        peer: SocketAddr,
    ) -> anyhow::Result<()> {
        info!("NBD: client {peer} connected");

        // ── Handshake ─────────────────────────────────────────────────────────
        // Server → Client: NBDMAGIC + IHAVEOPT + handshake_flags
        stream.write_u64(NBD_MAGIC).await?;
        stream.write_u64(NBD_IHAVEOPT).await?;
        stream
            .write_u16(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES)
            .await?;

        // Client → Server: client_flags (4 bytes)
        let _client_flags = stream.read_u32().await?;

        // ── Option negotiation ────────────────────────────────────────────────
        let (export_name, export) = self.negotiate_options(&mut stream).await?;

        // ── Data phase ────────────────────────────────────────────────────────
        self.data_phase(stream, &export_name, &export, peer).await?;

        info!("NBD: client {peer} disconnected from '{export_name}'");
        Ok(())
    }

    async fn negotiate_options(
        &self,
        stream: &mut TcpStream,
    ) -> anyhow::Result<(String, NbdExport)> {
        loop {
            // Read option header: IHAVEOPT magic (8) + option (4) + length (4)
            let magic = stream.read_u64().await?;
            if magic != NBD_IHAVEOPT {
                return Err(anyhow::anyhow!("bad option magic: {magic:#x}"));
            }
            let option = stream.read_u32().await?;
            let data_len = stream.read_u32().await?;

            // Read option data
            let mut option_data = vec![0u8; data_len as usize];
            stream.read_exact(&mut option_data).await?;

            match option {
                NBD_OPT_ABORT => {
                    self.send_option_reply(stream, option, NBD_REP_ACK, &[])
                        .await?;
                    return Err(anyhow::anyhow!("client sent NBD_OPT_ABORT"));
                }

                NBD_OPT_LIST => {
                    // Reply with each export name, then ACK
                    let names: Vec<String> = self.exports.read().keys().cloned().collect();
                    for name in &names {
                        let name_bytes = name.as_bytes();
                        let mut reply_data = Vec::with_capacity(4 + name_bytes.len());
                        reply_data.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                        reply_data.extend_from_slice(name_bytes);
                        self.send_option_reply(stream, option, NBD_REP_SERVER, &reply_data)
                            .await?;
                    }
                    self.send_option_reply(stream, option, NBD_REP_ACK, &[])
                        .await?;
                }

                NBD_OPT_INFO | NBD_OPT_GO => {
                    // Parse: u32 name_len + name_bytes + u16 num_info_requests
                    if option_data.len() < 4 {
                        self.send_option_reply(
                            stream,
                            option,
                            NBD_REP_ERR_UNSUP,
                            b"option data too short",
                        )
                        .await?;
                        continue;
                    }
                    let name_len =
                        u32::from_be_bytes(option_data[..4].try_into().unwrap()) as usize;
                    if option_data.len() < 4 + name_len {
                        self.send_option_reply(
                            stream,
                            option,
                            NBD_REP_ERR_UNSUP,
                            b"name truncated",
                        )
                        .await?;
                        continue;
                    }
                    let name = String::from_utf8_lossy(&option_data[4..4 + name_len]).to_string();

                    let export = {
                        let exports = self.exports.read();
                        exports.get(&name).cloned()
                    };

                    let Some(export) = export else {
                        self.send_option_reply(
                            stream,
                            option,
                            NBD_REP_ERR_UNKNOWN,
                            b"export not found",
                        )
                        .await?;
                        continue;
                    };

                    // Reply with NBD_INFO_EXPORT: u16 info_type + u64 size + u16 flags
                    let mut info = Vec::with_capacity(12);
                    info.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
                    info.extend_from_slice(&export.size_bytes.to_be_bytes());
                    let mut flags = NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_TRIM;
                    if export.read_only {
                        flags |= 0x0002; // NBD_FLAG_READ_ONLY
                    }
                    info.extend_from_slice(&flags.to_be_bytes());
                    self.send_option_reply(stream, option, NBD_REP_INFO, &info)
                        .await?;

                    // ACK: done with negotiation
                    self.send_option_reply(stream, option, NBD_REP_ACK, &[])
                        .await?;

                    if option == NBD_OPT_GO {
                        return Ok((name, export));
                    }
                }

                NBD_OPT_EXPORT_NAME => {
                    // Old-style: export name is the option data, no reply, go straight to data phase
                    let name = String::from_utf8_lossy(&option_data).to_string();
                    let export = self
                        .exports
                        .read()
                        .get(&name)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("export '{name}' not found"))?;
                    return Ok((name, export));
                }

                _ => {
                    self.send_option_reply(stream, option, NBD_REP_ERR_UNSUP, b"unsupported")
                        .await?;
                }
            }
        }
    }

    async fn send_option_reply(
        &self,
        stream: &mut TcpStream,
        option: u32,
        reply_type: u32,
        data: &[u8],
    ) -> anyhow::Result<()> {
        stream.write_u64(NBD_OPTION_REPLY_MAGIC).await?;
        stream.write_u32(option).await?;
        stream.write_u32(reply_type).await?;
        stream.write_u32(data.len() as u32).await?;
        if !data.is_empty() {
            stream.write_all(data).await?;
        }
        Ok(())
    }

    /// Serve requests until the client disconnects.
    ///
    /// Requests are read in order and served concurrently, up to
    /// `MAX_IN_FLIGHT` per connection, each reply written whole as soon as
    /// it is ready: NBD replies carry the request's handle, so they may go
    /// out in any order. Served one at a time (as this used to), a client's
    /// queue depth bought nothing: 32 requests in flight were answered one
    /// after another, and writes never shared a journal fsync. Every write
    /// is durable before its reply either way.
    async fn data_phase(
        self: &Arc<Self>,
        stream: TcpStream,
        vol_id: &str,
        export: &NbdExport,
        peer: SocketAddr,
    ) -> anyhow::Result<()> {
        let (mut rd, wr) = stream.into_split();
        let wr = Arc::new(tokio::sync::Mutex::new(wr));
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        let mut in_flight = tokio::task::JoinSet::new();
        let result = loop {
            // Request header: magic(4) + flags(2) + type(2) + handle(8) +
            // offset(8) + length(4) = 28 bytes.
            let header = async {
                let magic = rd.read_u32().await?;
                if magic != NBD_REQUEST_MAGIC {
                    return Err(anyhow::anyhow!("bad request magic: {magic:#x}"));
                }
                let _flags = rd.read_u16().await?;
                let cmd = rd.read_u16().await?;
                let handle = rd.read_u64().await?;
                let offset = rd.read_u64().await?;
                let length = rd.read_u32().await?;
                Ok::<_, anyhow::Error>((cmd, handle, offset, length))
            }
            .await;
            let (cmd, handle, offset, length) = match header {
                Ok(h) => h,
                Err(e) => break Err(e),
            };
            if cmd == NBD_CMD_DISC {
                info!("NBD: client {peer} sent disconnect for '{vol_id}'");
                break Ok(());
            }
            // A write's data follows its header on the socket, so it is read
            // here, in order, before the next request.
            let payload = if cmd == NBD_CMD_WRITE {
                let mut data = vec![0u8; length as usize];
                if let Err(e) = rd.read_exact(&mut data).await {
                    break Err(e.into());
                }
                Some(data)
            } else {
                None
            };
            let slot = Arc::clone(&slots).acquire_owned().await?;
            let server = Arc::clone(self);
            let wr = Arc::clone(&wr);
            let vol = vol_id.to_string();
            let read_only = export.read_only;
            in_flight.spawn(async move {
                let reply = server
                    .serve_request(&vol, peer, read_only, cmd, handle, offset, length, payload)
                    .await;
                if let Err(e) = wr.lock().await.write_all(&reply).await {
                    debug!("NBD: reply to {peer} not sent: {e}");
                }
                drop(slot);
            });
            // Reap what has finished, so the set does not grow with the
            // connection's lifetime.
            while in_flight.try_join_next().is_some() {}
        };
        // Requests already read get their replies before the connection
        // goes.
        while in_flight.join_next().await.is_some() {}
        result
    }

    /// One request's whole reply: header, and for a read its data.
    #[allow(clippy::too_many_arguments)]
    async fn serve_request(
        &self,
        vol_id: &str,
        peer: SocketAddr,
        read_only: bool,
        cmd: u16,
        handle: u64,
        offset: u64,
        length: u32,
        payload: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let status = |error: u32| reply_header(handle, error).to_vec();
        match cmd {
            NBD_CMD_READ => {
                let io = Io::start(Protocol::Nbd, "read");
                // A read that fails is an error to the client, never zeros:
                // zeros it would take for the data. An error reply carries no
                // data.
                let mut data = match self.resolver.read(vol_id, offset, u64::from(length)).await {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("NBD read error for {peer}: {e}");
                        return status(5); // EIO
                    }
                };
                // A simple reply has no length field, so the client reads
                // exactly `length` bytes off the socket no matter what is
                // sent; anything else desynchronises the connection for good.
                if data.len() != length as usize {
                    warn!(
                        "NBD read for {peer} returned {} bytes for a {length}-byte request",
                        data.len()
                    );
                    data.resize(length as usize, 0);
                }
                let mut reply = Vec::with_capacity(16 + data.len());
                reply.extend_from_slice(&reply_header(handle, 0));
                reply.extend_from_slice(&data);
                io.done(u64::from(length));
                reply
            }
            NBD_CMD_WRITE => {
                if read_only {
                    return status(1); // EPERM
                }
                let io = Io::start(Protocol::Nbd, "write");
                let data = payload.unwrap_or_default();
                // Acknowledged once journaled; a chunk the cache did not
                // hold has its stored bytes merged in behind it.
                if let Err(e) = self.cache.write(vol_id, offset, &data) {
                    warn!("NBD write cache error for {peer}: {e}");
                    return status(5); // EIO
                }
                self.resolver.kick(vol_id, offset, u64::from(length));
                io.done(u64::from(length));
                status(0)
            }
            NBD_CMD_FLUSH => {
                // Every write is fsynced to the journal before it is
                // acknowledged; this makes sure, and costs nothing when
                // everything is already synced.
                let io = Io::start(Protocol::Nbd, "flush");
                if let Err(e) = self.cache.sync() {
                    warn!("NBD flush for {peer}: {e}");
                    return status(5);
                }
                io.done(0);
                status(0)
            }
            NBD_CMD_TRIM => {
                if read_only {
                    return status(1);
                }
                // Zero-fill the trimmed range.
                let io = Io::start(Protocol::Nbd, "trim");
                let zeros = vec![0u8; length as usize];
                if self.cache.write(vol_id, offset, &zeros).is_err() {
                    return status(5);
                }
                self.resolver.kick(vol_id, offset, u64::from(length));
                io.done(u64::from(length));
                status(0)
            }
            _ => {
                warn!("NBD: unknown command {cmd} from {peer}");
                status(22) // EINVAL
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NBD_REPLY_MAGIC, reply_header};

    #[test]
    fn a_reply_header_is_magic_error_handle_big_endian() {
        let h = reply_header(0x0102_0304_0506_0708, 5);
        assert_eq!(&h[..4], &NBD_REPLY_MAGIC.to_be_bytes());
        assert_eq!(&h[4..8], &[0, 0, 0, 5]);
        assert_eq!(&h[8..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
