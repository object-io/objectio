//! NBD (Network Block Device) fixed-newstyle server
//!
//! Implements the NBD fixed-newstyle protocol over TCP, multiplexed by
//! export name (= volume_id). One TCP listener on a single port; clients
//! select the volume with `NBD_OPT_GO` (or the older `NBD_OPT_EXPORT_NAME`)
//! during the handshake. See
//! <https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md>.

#![allow(clippy::cast_possible_truncation)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use objectio_proto::block::Attachment;
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::metrics::{Io, Protocol};
use crate::resolve::Resolver;

// ── NBD protocol constants ────────────────────────────────────────────────────

const NBD_MAGIC: u64 = 0x4e42_444d_4147_4943; // "NBDMAGIC"
const NBD_IHAVEOPT: u64 = 0x4948_4156_454f_5054; // "IHAVEOPT"
const NBD_OPTION_REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
const NBD_REPLY_MAGIC: u32 = 0x6744_6698;

// Handshake flags (server)
const NBD_FLAG_FIXED_NEWSTYLE: u16 = 0x0001;
const NBD_FLAG_NO_ZEROES: u16 = 0x0002;

// Client flags
const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 0x0001;
const NBD_FLAG_C_NO_ZEROES: u32 = 0x0002;

// Option IDs
const NBD_OPT_EXPORT_NAME: u32 = 1;
const NBD_OPT_ABORT: u32 = 2;
const NBD_OPT_LIST: u32 = 3;
const NBD_OPT_INFO: u32 = 6;
const NBD_OPT_GO: u32 = 7;

// Reply types
const NBD_REP_ACK: u32 = 1;
const NBD_REP_SERVER: u32 = 2;
const NBD_REP_INFO: u32 = 3;
const NBD_REP_ERR_UNSUP: u32 = 0x8000_0001;
const NBD_REP_ERR_INVALID: u32 = 0x8000_0003;
const NBD_REP_ERR_UNKNOWN: u32 = 0x8000_0006;
const NBD_REP_ERR_TOO_BIG: u32 = 0x8000_0009;

// Transmission flags. Only what is implemented is advertised: no TRIM
// (it zero-fills the range through the write cache, too costly for the
// whole-device discards mkfs sends), no WRITE_ZEROES, no structured
// replies. FUA is honoured by every write: each is journaled and fsynced
// before it is acknowledged.
const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
const NBD_FLAG_READ_ONLY: u16 = 1 << 1;
const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
const NBD_FLAG_SEND_FUA: u16 = 1 << 3;

// Info types
const NBD_INFO_EXPORT: u16 = 0;

// Commands
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_WRITE: u16 = 1;
const NBD_CMD_DISC: u16 = 2;
const NBD_CMD_FLUSH: u16 = 3;
const NBD_CMD_TRIM: u16 = 4;

// Errors (as the protocol numbers them)
const NBD_EPERM: u32 = 1;
const NBD_EIO: u32 = 5;
const NBD_EINVAL: u32 = 22;
const NBD_ENOSPC: u32 = 28;
const NBD_ESHUTDOWN: u32 = 108;

/// Requests served at once on one connection. The kernel client queues up
/// to 128; more than this waits to be read.
const MAX_IN_FLIGHT: usize = 64;
/// Largest read or write served: the size clients assume when the server
/// does not say (32 MiB). Larger requests are refused, not allocated.
const MAX_REQUEST: u32 = 32 * 1024 * 1024;
/// Largest option data taken during the handshake. Export names are at
/// most 4096 bytes; anything far past that is refused, not allocated.
const MAX_OPTION_DATA: u32 = 64 * 1024;

/// Transmission flags for an export.
const fn transmission_flags(read_only: bool) -> u16 {
    let flags = NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA;
    if read_only {
        flags | NBD_FLAG_READ_ONLY
    } else {
        flags
    }
}

// ── Export registry ───────────────────────────────────────────────────────────

/// An export as registered.
struct Registered {
    size_bytes: u64,
    read_only: bool,
    /// Set when the export goes (detach, delete). Every connection to it,
    /// and every request it is serving, holds a receiver: unregistering
    /// waits until they are all gone.
    closed: watch::Sender<bool>,
}

/// An export as a connection holds it.
#[derive(Clone)]
struct NbdExport {
    size_bytes: u64,
    read_only: bool,
    closed: watch::Receiver<bool>,
}

/// Whether the export has gone: unregistered, or replaced.
fn is_closed(closed: &watch::Receiver<bool>) -> bool {
    *closed.borrow() || closed.has_changed().is_err()
}

/// A request header: (flags, command, handle, offset, length).
async fn read_header<R>(rd: &mut R) -> anyhow::Result<(u16, u16, u64, u64, u32)>
where
    R: AsyncRead + Unpin,
{
    // magic(4) + flags(2) + type(2) + handle(8) + offset(8) + length(4).
    let mut h = [0u8; 28];
    rd.read_exact(&mut h).await?;
    let magic = u32::from_be_bytes(h[..4].try_into()?);
    if magic != NBD_REQUEST_MAGIC {
        anyhow::bail!("bad request magic: {magic:#x}");
    }
    Ok((
        u16::from_be_bytes(h[4..6].try_into()?),
        u16::from_be_bytes(h[6..8].try_into()?),
        u64::from_be_bytes(h[8..16].try_into()?),
        u64::from_be_bytes(h[16..24].try_into()?),
        u32::from_be_bytes(h[24..28].try_into()?),
    ))
}

pub struct NbdServer {
    exports: RwLock<HashMap<String, Registered>>,
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

/// The export name of an `NBD_OPT_INFO`/`NBD_OPT_GO` request, if its data
/// is well formed: u32 name length, name, u16 count, then exactly that many
/// u16 information requests.
fn parse_info_request(data: &[u8]) -> Option<String> {
    let name_len = u32::from_be_bytes(data.get(..4)?.try_into().ok()?) as usize;
    let name = data.get(4..4usize.checked_add(name_len)?)?;
    let rest = &data[4 + name_len..];
    let count = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
    if rest.len() != 2 + 2 * count {
        return None;
    }
    Some(String::from_utf8_lossy(name).into_owned())
}

/// One option reply, written whole: magic, option, reply type, length,
/// data.
async fn send_option_reply<S>(
    stream: &mut S,
    option: u32,
    reply_type: u32,
    data: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = Vec::with_capacity(20 + data.len());
    reply.extend_from_slice(&NBD_OPTION_REPLY_MAGIC.to_be_bytes());
    reply.extend_from_slice(&option.to_be_bytes());
    reply.extend_from_slice(&reply_type.to_be_bytes());
    reply.extend_from_slice(&(data.len() as u32).to_be_bytes());
    reply.extend_from_slice(data);
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(())
}

/// Read and drop `len` bytes, to stay in step with a client whose request
/// is refused.
async fn skip<S>(stream: &mut S, len: u64) -> anyhow::Result<()>
where
    S: AsyncRead + Unpin,
{
    let skipped = tokio::io::copy(&mut (&mut *stream).take(len), &mut tokio::io::sink()).await?;
    if skipped != len {
        anyhow::bail!("connection closed after {skipped} of {len} bytes");
    }
    Ok(())
}

/// What a request is checked against.
struct Limits {
    size_bytes: u64,
    read_only: bool,
}

/// The error a request is refused with before it is served, if any: one
/// past the end of the export, larger than `MAX_REQUEST`, a write to a
/// read-only export, or a command not offered.
const fn refusal(cmd: u16, offset: u64, length: u32, export: &Limits) -> Option<u32> {
    let within = in_bounds(offset, length, export.size_bytes);
    match cmd {
        NBD_CMD_READ if length > MAX_REQUEST || !within => Some(NBD_EINVAL),
        NBD_CMD_WRITE | NBD_CMD_TRIM if export.read_only => Some(NBD_EPERM),
        NBD_CMD_WRITE if length > MAX_REQUEST => Some(NBD_EINVAL),
        NBD_CMD_WRITE if !within => Some(NBD_ENOSPC),
        NBD_CMD_TRIM if !within => Some(NBD_EINVAL),
        NBD_CMD_READ | NBD_CMD_WRITE | NBD_CMD_FLUSH | NBD_CMD_TRIM => None,
        _ => Some(NBD_EINVAL),
    }
}

/// Whether `offset + length` lies within an export of `size` bytes.
const fn in_bounds(offset: u64, length: u32, size: u64) -> bool {
    match offset.checked_add(length as u64) {
        Some(end) => end <= size,
        None => false,
    }
}

impl NbdServer {
    pub fn new(cache: Arc<objectio_block::WriteCache>, resolver: Arc<Resolver>) -> Self {
        Self {
            exports: RwLock::new(HashMap::new()),
            cache,
            resolver,
        }
    }

    /// Register a volume as an NBD export. One registered already under
    /// the name is replaced, and its connections closed.
    pub fn register(&self, vol_id: &str, size_bytes: u64, read_only: bool) {
        let (closed, _) = watch::channel(false);
        self.exports.write().insert(
            vol_id.to_string(),
            Registered {
                size_bytes,
                read_only,
                closed,
            },
        );
        info!("NBD: registered export '{vol_id}' ({size_bytes}B)");
    }

    /// Unregister a volume export, and disconnect every client of it.
    ///
    /// Returns once no connection can do I/O on the volume any more: each
    /// stops reading requests, refuses those not yet started with
    /// `ESHUTDOWN`, and finishes those under way, so a write either
    /// completed (journaled, durable) before this returns or never happens.
    /// A detached volume may be attached elsewhere next; a client still
    /// writing to it here would corrupt it.
    pub async fn unregister(&self, vol_id: &str) {
        let removed = self.exports.write().remove(vol_id);
        let Some(export) = removed else {
            return;
        };
        export.closed.send_replace(true);
        let holders = export.closed.receiver_count();
        if holders > 0 {
            info!("NBD: closing export '{vol_id}': waiting for {holders} connections and requests");
        }
        export.closed.closed().await;
        info!("NBD: unregistered export '{vol_id}'");
    }

    /// Whether `vol_id` is exported read-only.
    pub fn is_read_only(&self, vol_id: &str) -> bool {
        self.exports.read().get(vol_id).is_some_and(|e| e.read_only)
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

        let Some((export_name, export)) = self.handshake(&mut stream).await? else {
            info!("NBD: client {peer} aborted the handshake");
            return Ok(());
        };

        self.data_phase(stream, &export_name, export, peer).await?;

        info!("NBD: client {peer} disconnected from '{export_name}'");
        Ok(())
    }

    /// The handshake, up to the transmission phase: the export chosen, or
    /// `None` if the client aborted. An error closes the connection.
    async fn handshake<S>(&self, stream: &mut S) -> anyhow::Result<Option<(String, NbdExport)>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Server → Client: NBDMAGIC + IHAVEOPT + handshake flags.
        let mut hello = Vec::with_capacity(18);
        hello.extend_from_slice(&NBD_MAGIC.to_be_bytes());
        hello.extend_from_slice(&NBD_IHAVEOPT.to_be_bytes());
        hello.extend_from_slice(&(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES).to_be_bytes());
        stream.write_all(&hello).await?;
        stream.flush().await?;

        // Client → Server: client flags. One we did not offer, or do not
        // know, ends the session.
        let client_flags = stream.read_u32().await?;
        if client_flags & !(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES) != 0 {
            anyhow::bail!("unknown client flags {client_flags:#x}");
        }
        let fixed = client_flags & NBD_FLAG_C_FIXED_NEWSTYLE != 0;
        let no_zeroes = client_flags & NBD_FLAG_C_NO_ZEROES != 0;

        loop {
            // Option header: IHAVEOPT (8) + option (4) + length (4).
            let magic = stream.read_u64().await?;
            if magic != NBD_IHAVEOPT {
                anyhow::bail!("bad option magic: {magic:#x}");
            }
            let option = stream.read_u32().await?;
            let data_len = stream.read_u32().await?;

            // A client that is not fixed-newstyle gets no option replies:
            // all it may send is EXPORT_NAME.
            if !fixed && option != NBD_OPT_EXPORT_NAME {
                anyhow::bail!("option {option} from a client without fixed newstyle");
            }
            if data_len > MAX_OPTION_DATA {
                if option == NBD_OPT_EXPORT_NAME {
                    anyhow::bail!("export name of {data_len} bytes");
                }
                // Skip the data to stay in step, then refuse.
                skip(stream, u64::from(data_len)).await?;
                send_option_reply(
                    stream,
                    option,
                    NBD_REP_ERR_TOO_BIG,
                    b"option data too large",
                )
                .await?;
                continue;
            }
            let mut data = vec![0u8; data_len as usize];
            stream.read_exact(&mut data).await?;

            match option {
                NBD_OPT_EXPORT_NAME => {
                    // The data is the name. There is no error reply: an
                    // unknown export ends the session. The reply is the
                    // export's size and transmission flags, then 124 bytes
                    // of zeroes unless the client asked for none — and no
                    // option-reply header.
                    let name = String::from_utf8_lossy(&data).into_owned();
                    let Some(export) = self.export(&name) else {
                        anyhow::bail!("export '{name}' not found");
                    };
                    let mut reply = Vec::with_capacity(8 + 2 + 124);
                    reply.extend_from_slice(&export.size_bytes.to_be_bytes());
                    reply.extend_from_slice(&transmission_flags(export.read_only).to_be_bytes());
                    if !no_zeroes {
                        reply.extend_from_slice(&[0u8; 124]);
                    }
                    stream.write_all(&reply).await?;
                    stream.flush().await?;
                    return Ok(Some((name, export)));
                }

                NBD_OPT_ABORT => {
                    // The server must reply ACK; then the session ends.
                    send_option_reply(stream, option, NBD_REP_ACK, &[]).await?;
                    return Ok(None);
                }

                NBD_OPT_LIST => {
                    if !data.is_empty() {
                        send_option_reply(
                            stream,
                            option,
                            NBD_REP_ERR_INVALID,
                            b"NBD_OPT_LIST takes no data",
                        )
                        .await?;
                        continue;
                    }
                    let mut names: Vec<String> = self.exports.read().keys().cloned().collect();
                    names.sort();
                    for name in &names {
                        let mut reply = Vec::with_capacity(4 + name.len());
                        reply.extend_from_slice(&(name.len() as u32).to_be_bytes());
                        reply.extend_from_slice(name.as_bytes());
                        send_option_reply(stream, option, NBD_REP_SERVER, &reply).await?;
                    }
                    send_option_reply(stream, option, NBD_REP_ACK, &[]).await?;
                }

                NBD_OPT_INFO | NBD_OPT_GO => {
                    let Some(name) = parse_info_request(&data) else {
                        send_option_reply(
                            stream,
                            option,
                            NBD_REP_ERR_INVALID,
                            b"malformed option data",
                        )
                        .await?;
                        continue;
                    };
                    let Some(export) = self.export(&name) else {
                        send_option_reply(stream, option, NBD_REP_ERR_UNKNOWN, b"export not found")
                            .await?;
                        continue;
                    };

                    // NBD_INFO_EXPORT is always sent, whatever was asked
                    // for; the other information types are optional and
                    // not offered. u16 type + u64 size + u16 flags.
                    let mut info = Vec::with_capacity(12);
                    info.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
                    info.extend_from_slice(&export.size_bytes.to_be_bytes());
                    info.extend_from_slice(&transmission_flags(export.read_only).to_be_bytes());
                    send_option_reply(stream, option, NBD_REP_INFO, &info).await?;
                    send_option_reply(stream, option, NBD_REP_ACK, &[]).await?;

                    if option == NBD_OPT_GO {
                        return Ok(Some((name, export)));
                    }
                }

                // STARTTLS, STRUCTURED_REPLY, LIST_META_CONTEXT and the rest
                // are not supported; the client carries on without them.
                _ => {
                    send_option_reply(stream, option, NBD_REP_ERR_UNSUP, b"unsupported option")
                        .await?;
                }
            }
        }
    }

    fn export(&self, name: &str) -> Option<NbdExport> {
        self.exports.read().get(name).map(|e| NbdExport {
            size_bytes: e.size_bytes,
            read_only: e.read_only,
            closed: e.closed.subscribe(),
        })
    }

    /// Serve requests until the client disconnects, or the export goes.
    ///
    /// Requests are read in order and served concurrently, up to
    /// `MAX_IN_FLIGHT` per connection, each reply written whole as soon as
    /// it is ready: NBD replies carry the request's handle, so they may go
    /// out in any order. Served one at a time (as this used to), a client's
    /// queue depth bought nothing: 32 requests in flight were answered one
    /// after another, and writes never shared a journal fsync. Every write
    /// is durable before its reply either way.
    ///
    /// When the export is unregistered the connection stops reading
    /// requests, and closes once those under way are answered; see
    /// [`Self::unregister`].
    async fn data_phase(
        self: &Arc<Self>,
        stream: TcpStream,
        vol_id: &str,
        export: NbdExport,
        peer: SocketAddr,
    ) -> anyhow::Result<()> {
        let NbdExport {
            size_bytes,
            read_only,
            closed,
        } = export;
        let limits = Limits {
            size_bytes,
            read_only,
        };
        let mut watch = closed.clone();
        let (mut rd, wr) = stream.into_split();
        let wr = Arc::new(tokio::sync::Mutex::new(wr));
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        let mut in_flight = tokio::task::JoinSet::new();
        let result = loop {
            // Waiting on the client — for a header, or a write's data —
            // gives way to the export closing.
            let header = tokio::select! {
                biased;
                _ = watch.wait_for(|c| *c) => {
                    info!("NBD: export '{vol_id}' closed; disconnecting {peer}");
                    break Ok(());
                }
                h = read_header(&mut rd) => h,
            };
            let (_flags, cmd, handle, offset, length) = match header {
                Ok(h) => h,
                Err(e) => break Err(e),
            };
            if cmd == NBD_CMD_DISC {
                info!("NBD: client {peer} sent disconnect for '{vol_id}'");
                break Ok(());
            }
            // A request refused outright is answered here, in order. A
            // write's data is still read off the socket (and dropped) to
            // stay in step; it is never allocated.
            if let Some(error) = refusal(cmd, offset, length, &limits) {
                debug!(
                    "NBD: refusing command {cmd} ({length} bytes at {offset}) from {peer}: error {error}"
                );
                if cmd == NBD_CMD_WRITE {
                    let skipped = tokio::select! {
                        biased;
                        _ = watch.wait_for(|c| *c) => break Ok(()),
                        r = skip(&mut rd, u64::from(length)) => r,
                    };
                    if let Err(e) = skipped {
                        break Err(e);
                    }
                }
                if let Err(e) = wr
                    .lock()
                    .await
                    .write_all(&reply_header(handle, error))
                    .await
                {
                    break Err(e.into());
                }
                continue;
            }
            // A write's data follows its header on the socket, so it is read
            // here, in order, before the next request.
            let payload = if cmd == NBD_CMD_WRITE {
                let mut data = vec![0u8; length as usize];
                let read = tokio::select! {
                    biased;
                    _ = watch.wait_for(|c| *c) => break Ok(()),
                    r = rd.read_exact(&mut data) => r,
                };
                if let Err(e) = read {
                    break Err(e.into());
                }
                Some(bytes::Bytes::from(data))
            } else {
                None
            };
            let slot = Arc::clone(&slots).acquire_owned().await?;
            let server = Arc::clone(self);
            let wr = Arc::clone(&wr);
            let vol = vol_id.to_string();
            // Held while the request does its I/O, so unregistering waits
            // for it; dropped before the reply is sent, so a client that
            // stops reading cannot hold up a detach.
            let closed = closed.clone();
            in_flight.spawn(async move {
                let reply = server
                    .serve_request(&vol, peer, &closed, cmd, handle, offset, length, payload)
                    .await;
                drop(closed);
                if let Err(e) = wr.lock().await.write_all(&reply).await {
                    debug!("NBD: reply to {peer} not sent: {e}");
                }
                drop(slot);
            });
            // Reap what has finished, so the set does not grow with the
            // connection's lifetime.
            while in_flight.try_join_next().is_some() {}
        };
        // Nothing more is read; requests under way keep their own hold on
        // the export.
        drop((watch, closed, rd));
        // Requests already read get their replies before the connection
        // goes.
        while in_flight.join_next().await.is_some() {}
        result
    }

    /// One request's whole reply: header, and for a read its data. The
    /// request has passed [`refusal`]. Refused with `ESHUTDOWN` if the
    /// export has closed since it was read.
    #[allow(clippy::too_many_arguments)]
    async fn serve_request(
        &self,
        vol_id: &str,
        peer: SocketAddr,
        closed: &watch::Receiver<bool>,
        cmd: u16,
        handle: u64,
        offset: u64,
        length: u32,
        payload: Option<bytes::Bytes>,
    ) -> Vec<u8> {
        let status = |error: u32| reply_header(handle, error).to_vec();
        if is_closed(closed) {
            return status(NBD_ESHUTDOWN);
        }
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
                        return status(NBD_EIO);
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
                // With or without NBD_CMD_FLAG_FUA: every write is
                // journaled and fsynced before it is acknowledged.
                let io = Io::start(Protocol::Nbd, "write");
                let data = payload.unwrap_or_default();
                // Acknowledged once journaled; a chunk the cache did not
                // hold has its stored bytes merged in behind it.
                if let Err(e) = self.cache.write_durable(vol_id, offset, data).await {
                    warn!("NBD write cache error for {peer}: {e}");
                    return status(NBD_EIO);
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
                if let Err(e) = self.cache.sync_durable().await {
                    warn!("NBD flush for {peer}: {e}");
                    return status(NBD_EIO);
                }
                io.done(0);
                status(0)
            }
            NBD_CMD_TRIM => {
                // Not advertised, but served if sent: the range is
                // zero-filled, a piece at a time so a large trim is never
                // one allocation of its whole length.
                let io = Io::start(Protocol::Nbd, "trim");
                if let Err(e) = self
                    .cache
                    .write_zeroes(vol_id, offset, u64::from(length))
                    .await
                {
                    warn!("NBD trim for {peer}: {e}");
                    return status(NBD_EIO);
                }
                self.resolver.kick(vol_id, offset, u64::from(length));
                io.done(u64::from(length));
                status(0)
            }
            _ => {
                warn!("NBD: unknown command {cmd} from {peer}");
                status(NBD_EINVAL)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The handshake's bytes, exactly as a client sees them, over an
    //! in-memory stream.

    use super::*;
    use objectio_block::WriteCache;
    use objectio_block::chunk::ChunkMapper;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    const SIZE: u64 = 64 << 20;
    /// HAS_FLAGS | SEND_FLUSH | SEND_FUA.
    const FLAGS: u16 = 0x000d;
    const NBD_OPT_STRUCTURED_REPLY: u32 = 8;
    const NBD_INFO_BLOCK_SIZE: u16 = 3;

    fn server() -> Arc<NbdServer> {
        let cache = Arc::new(WriteCache::with_defaults(Arc::new(ChunkMapper::default())));
        cache.init_volume("vol");
        cache.init_volume("ro");
        // Never connected: the handshake does no I/O.
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let meta = Arc::new(crate::meta_blocks::MetaBlocks::new(Arc::new(
            tokio::sync::Mutex::new(
                objectio_proto::metadata::metadata_service_client::MetadataServiceClient::new(
                    channel,
                ),
            ),
        )));
        let resolver = Arc::new(Resolver::new(
            Arc::clone(&cache),
            meta,
            Arc::new(crate::osd_pool::OsdPool::new()),
        ));
        let s = Arc::new(NbdServer::new(cache, resolver));
        s.register("vol", SIZE, false);
        s.register("ro", 4096, true);
        s
    }

    type Outcome = anyhow::Result<Option<(String, NbdExport)>>;

    /// Run the server's handshake on one end of a pipe; the client end,
    /// with the server's greeting read and checked, and `client_flags`
    /// sent.
    async fn start(client_flags: u32) -> (DuplexStream, tokio::task::JoinHandle<Outcome>) {
        let (mut client, mut srv) = tokio::io::duplex(1 << 20);
        let server = server();
        let task = tokio::spawn(async move { server.handshake(&mut srv).await });
        let mut hello = [0u8; 18];
        client.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello[..8], b"NBDMAGIC");
        assert_eq!(&hello[8..16], b"IHAVEOPT");
        // FIXED_NEWSTYLE | NO_ZEROES
        assert_eq!(&hello[16..], &[0, 3]);
        client.write_all(&client_flags.to_be_bytes()).await.unwrap();
        (client, task)
    }

    async fn send_option(client: &mut DuplexStream, option: u32, data: &[u8]) {
        let mut o = Vec::new();
        o.extend_from_slice(b"IHAVEOPT");
        o.extend_from_slice(&option.to_be_bytes());
        o.extend_from_slice(&(data.len() as u32).to_be_bytes());
        o.extend_from_slice(data);
        client.write_all(&o).await.unwrap();
    }

    fn go_data(name: &str, infos: &[u16]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&(name.len() as u32).to_be_bytes());
        d.extend_from_slice(name.as_bytes());
        d.extend_from_slice(&(infos.len() as u16).to_be_bytes());
        for i in infos {
            d.extend_from_slice(&i.to_be_bytes());
        }
        d
    }

    /// One option reply: (option, reply type, data), the magic checked.
    async fn option_reply(client: &mut DuplexStream) -> (u32, u32, Vec<u8>) {
        let mut h = [0u8; 20];
        client.read_exact(&mut h).await.unwrap();
        assert_eq!(&h[..8], &NBD_OPTION_REPLY_MAGIC.to_be_bytes());
        let option = u32::from_be_bytes(h[8..12].try_into().unwrap());
        let kind = u32::from_be_bytes(h[12..16].try_into().unwrap());
        let len = u32::from_be_bytes(h[16..20].try_into().unwrap());
        let mut data = vec![0u8; len as usize];
        client.read_exact(&mut data).await.unwrap();
        (option, kind, data)
    }

    /// Everything the server sends from here until it closes its end.
    async fn rest(
        mut client: DuplexStream,
        task: tokio::task::JoinHandle<Outcome>,
    ) -> (Vec<u8>, Outcome) {
        let outcome = task.await.unwrap(); // its end of the pipe drops here
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        (rest, outcome)
    }

    #[tokio::test]
    async fn export_name_replies_size_flags_and_124_zeroes_with_no_header() {
        let (mut client, task) = start(NBD_FLAG_C_FIXED_NEWSTYLE).await;
        send_option(&mut client, NBD_OPT_EXPORT_NAME, b"vol").await;
        let (reply, outcome) = rest(client, task).await;
        assert_eq!(
            reply.len(),
            8 + 2 + 124,
            "size, flags, padding: nothing else"
        );
        assert_eq!(&reply[..8], &SIZE.to_be_bytes());
        assert_eq!(&reply[8..10], &FLAGS.to_be_bytes());
        assert!(reply[10..].iter().all(|&b| b == 0));
        assert_eq!(outcome.unwrap().unwrap().0, "vol");
    }

    #[tokio::test]
    async fn export_name_with_no_zeroes_replies_size_and_flags_only() {
        let (mut client, task) = start(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES).await;
        send_option(&mut client, NBD_OPT_EXPORT_NAME, b"ro").await;
        let (reply, outcome) = rest(client, task).await;
        assert_eq!(reply.len(), 10);
        assert_eq!(&reply[..8], &4096u64.to_be_bytes());
        assert_eq!(
            &reply[8..],
            &(FLAGS | NBD_FLAG_READ_ONLY).to_be_bytes(),
            "read-only"
        );
        assert!(outcome.unwrap().unwrap().1.read_only);
    }

    /// EXPORT_NAME has no error reply: an unknown name ends the session
    /// with nothing sent.
    #[tokio::test]
    async fn export_name_for_an_unknown_export_closes_the_connection() {
        let (mut client, task) = start(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES).await;
        send_option(&mut client, NBD_OPT_EXPORT_NAME, b"nope").await;
        let (reply, outcome) = rest(client, task).await;
        assert!(reply.is_empty(), "sent {reply:?}");
        assert!(outcome.is_err());
    }

    /// A client that is not fixed-newstyle gets EXPORT_NAME too, without
    /// NO_ZEROES: the padding is sent.
    #[tokio::test]
    async fn export_name_from_a_plain_newstyle_client() {
        let (mut client, task) = start(0).await;
        send_option(&mut client, NBD_OPT_EXPORT_NAME, b"vol").await;
        let (reply, outcome) = rest(client, task).await;
        assert_eq!(reply.len(), 134);
        assert!(outcome.unwrap().is_some());
    }

    #[tokio::test]
    async fn go_replies_info_export_then_ack() {
        let (mut client, task) = start(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES).await;
        // Asks for block sizes too: optional, so only INFO_EXPORT comes.
        send_option(
            &mut client,
            NBD_OPT_GO,
            &go_data("vol", &[NBD_INFO_BLOCK_SIZE]),
        )
        .await;
        let (option, kind, data) = option_reply(&mut client).await;
        assert_eq!((option, kind), (NBD_OPT_GO, NBD_REP_INFO));
        let mut want = Vec::new();
        want.extend_from_slice(&NBD_INFO_EXPORT.to_be_bytes());
        want.extend_from_slice(&SIZE.to_be_bytes());
        want.extend_from_slice(&FLAGS.to_be_bytes());
        assert_eq!(data, want);
        assert_eq!(
            option_reply(&mut client).await,
            (NBD_OPT_GO, NBD_REP_ACK, Vec::new())
        );
        let (rest, outcome) = rest(client, task).await;
        assert!(rest.is_empty(), "no padding after GO");
        assert_eq!(outcome.unwrap().unwrap().0, "vol");
    }

    /// INFO leaves negotiation open; an unknown export is an error reply,
    /// not the end; GO then picks one.
    #[tokio::test]
    async fn info_and_unknown_exports_keep_negotiating() {
        let (mut client, task) = start(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES).await;
        send_option(&mut client, NBD_OPT_INFO, &go_data("ro", &[])).await;
        let (_, kind, data) = option_reply(&mut client).await;
        assert_eq!(kind, NBD_REP_INFO);
        assert_eq!(&data[10..], &(FLAGS | NBD_FLAG_READ_ONLY).to_be_bytes());
        assert_eq!(option_reply(&mut client).await.1, NBD_REP_ACK);

        send_option(&mut client, NBD_OPT_GO, &go_data("nope", &[])).await;
        let (option, kind, _) = option_reply(&mut client).await;
        assert_eq!((option, kind), (NBD_OPT_GO, NBD_REP_ERR_UNKNOWN));

        send_option(&mut client, NBD_OPT_GO, &go_data("vol", &[])).await;
        assert_eq!(option_reply(&mut client).await.1, NBD_REP_INFO);
        assert_eq!(option_reply(&mut client).await.1, NBD_REP_ACK);
        assert_eq!(task.await.unwrap().unwrap().unwrap().0, "vol");
    }

    #[tokio::test]
    async fn malformed_options_are_invalid_and_unknown_ones_unsupported() {
        let (mut client, task) = start(NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES).await;
        // Name length past the data.
        send_option(&mut client, NBD_OPT_GO, &[0, 0, 0, 9, b'v']).await;
        assert_eq!(option_reply(&mut client).await.1, NBD_REP_ERR_INVALID);
        // Trailing bytes after the information requests.
        let mut d = go_data("vol", &[]);
        d.push(0);
        send_option(&mut client, NBD_OPT_GO, &d).await;
        assert_eq!(option_reply(&mut client).await.1, NBD_REP_ERR_INVALID);
        // LIST takes no data.
        send_option(&mut client, NBD_OPT_LIST, b"x").await;
        assert_eq!(option_reply(&mut client).await.1, NBD_REP_ERR_INVALID);
        // Structured replies are not offered.
        send_option(&mut client, NBD_OPT_STRUCTURED_REPLY, &[]).await;
        assert_eq!(
            option_reply(&mut client).await,
            (
                NBD_OPT_STRUCTURED_REPLY,
                NBD_REP_ERR_UNSUP,
                b"unsupported option".to_vec()
            )
        );
        // Oversized data is skipped and refused; the session goes on.
        send_option(&mut client, 99, &vec![0u8; MAX_OPTION_DATA as usize + 1]).await;
        assert_eq!(option_reply(&mut client).await.1, NBD_REP_ERR_TOO_BIG);

        send_option(&mut client, NBD_OPT_LIST, &[]).await;
        let mut names = Vec::new();
        loop {
            let (_, kind, data) = option_reply(&mut client).await;
            if kind == NBD_REP_ACK {
                break;
            }
            assert_eq!(kind, NBD_REP_SERVER);
            let len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
            assert_eq!(data.len(), 4 + len);
            names.push(String::from_utf8(data[4..].to_vec()).unwrap());
        }
        assert_eq!(names, ["ro", "vol"]);

        send_option(&mut client, NBD_OPT_ABORT, &[]).await;
        assert_eq!(
            option_reply(&mut client).await,
            (NBD_OPT_ABORT, NBD_REP_ACK, Vec::new())
        );
        let (rest, outcome) = rest(client, task).await;
        assert!(rest.is_empty());
        assert!(outcome.unwrap().is_none(), "aborted");
    }

    #[tokio::test]
    async fn an_unknown_client_flag_closes_the_connection() {
        let (client, task) = start(0x4).await;
        let (rest, outcome) = rest(client, task).await;
        assert!(rest.is_empty());
        assert!(outcome.is_err());
    }

    /// Options other than EXPORT_NAME need fixed newstyle.
    #[tokio::test]
    async fn go_without_fixed_newstyle_closes_the_connection() {
        let (mut client, task) = start(0).await;
        send_option(&mut client, NBD_OPT_GO, &go_data("vol", &[])).await;
        let (rest, outcome) = rest(client, task).await;
        assert!(rest.is_empty());
        assert!(outcome.is_err());
    }

    #[test]
    fn requests_out_of_bounds_too_large_or_read_only_are_refused() {
        let rw = Limits {
            size_bytes: SIZE,
            read_only: false,
        };
        let ro = Limits {
            size_bytes: SIZE,
            read_only: true,
        };
        assert_eq!(refusal(NBD_CMD_READ, 0, 4096, &rw), None);
        assert_eq!(refusal(NBD_CMD_READ, SIZE - 4096, 4096, &rw), None);
        assert_eq!(
            refusal(NBD_CMD_READ, SIZE - 4096, 4097, &rw),
            Some(NBD_EINVAL)
        );
        assert_eq!(refusal(NBD_CMD_READ, u64::MAX, 1, &rw), Some(NBD_EINVAL));
        assert_eq!(
            refusal(NBD_CMD_READ, 0, MAX_REQUEST + 1, &rw),
            Some(NBD_EINVAL)
        );
        assert_eq!(refusal(NBD_CMD_WRITE, SIZE, 1, &rw), Some(NBD_ENOSPC));
        assert_eq!(
            refusal(NBD_CMD_WRITE, 0, MAX_REQUEST + 1, &rw),
            Some(NBD_EINVAL)
        );
        assert_eq!(refusal(NBD_CMD_WRITE, 0, 4096, &ro), Some(NBD_EPERM));
        assert_eq!(refusal(NBD_CMD_TRIM, 0, 4096, &ro), Some(NBD_EPERM));
        assert_eq!(refusal(NBD_CMD_TRIM, SIZE, 4096, &rw), Some(NBD_EINVAL));
        assert_eq!(refusal(NBD_CMD_READ, 0, 4096, &ro), None);
        assert_eq!(refusal(NBD_CMD_FLUSH, 0, 0, &ro), None);
        assert_eq!(refusal(5, 0, 0, &rw), Some(NBD_EINVAL), "WRITE_ZEROES");
    }

    #[test]
    fn transmission_flags_are_the_protocols_bits() {
        // HAS_FLAGS bit 0, READ_ONLY bit 1, SEND_FLUSH bit 2, SEND_FUA bit
        // 3; SEND_TRIM (bit 5) is not offered.
        assert_eq!(transmission_flags(false), 0b1101);
        assert_eq!(transmission_flags(true), 0b1111);
    }

    /// A client connected over TCP with `NBD_OPT_GO` to `export`.
    async fn connected(
        server: &Arc<NbdServer>,
        export: &str,
    ) -> (tokio::net::TcpStream, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = Arc::clone(server);
        let conn = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let _ = srv.handle_client(stream, peer).await;
        });
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut hello = [0u8; 18];
        c.read_exact(&mut hello).await.unwrap();
        c.write_all(&3u32.to_be_bytes()).await.unwrap();
        let mut o = Vec::new();
        o.extend_from_slice(b"IHAVEOPT");
        o.extend_from_slice(&NBD_OPT_GO.to_be_bytes());
        let data = go_data(export, &[]);
        o.extend_from_slice(&(data.len() as u32).to_be_bytes());
        o.extend_from_slice(&data);
        c.write_all(&o).await.unwrap();
        for want in [NBD_REP_INFO, NBD_REP_ACK] {
            let mut h = [0u8; 20];
            c.read_exact(&mut h).await.unwrap();
            assert_eq!(u32::from_be_bytes(h[12..16].try_into().unwrap()), want);
            let len = u32::from_be_bytes(h[16..20].try_into().unwrap());
            let mut body = vec![0u8; len as usize];
            c.read_exact(&mut body).await.unwrap();
        }
        (c, conn)
    }

    fn request(cmd: u16, handle: u64, offset: u64, length: u32) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&cmd.to_be_bytes());
        r.extend_from_slice(&handle.to_be_bytes());
        r.extend_from_slice(&offset.to_be_bytes());
        r.extend_from_slice(&length.to_be_bytes());
        r
    }

    /// Unregistering (detach, delete) disconnects a client: its write
    /// acknowledged before is kept, the connection is closed, and nothing
    /// it sends afterwards is done.
    #[tokio::test]
    async fn unregister_disconnects_the_exports_clients() {
        let server = server();
        let (mut c, conn) = connected(&server, "vol").await;
        let mut w = request(NBD_CMD_WRITE, 7, 0, 4096);
        w.extend_from_slice(&[0xab; 4096]);
        c.write_all(&w).await.unwrap();
        let mut reply = [0u8; 16];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, reply_header(7, 0));

        tokio::time::timeout(Duration::from_secs(5), server.unregister("vol"))
            .await
            .expect("unregister waited on an idle client");
        conn.await.unwrap();
        // Closed: EOF, and a write sent now goes nowhere.
        let _ = c.write_all(&w).await;
        let mut rest = Vec::new();
        let _ = c.read_to_end(&mut rest).await;
        assert!(
            rest.is_empty(),
            "{} bytes after the export closed",
            rest.len()
        );
        // The acknowledged write is held, its chunk awaiting its stored
        // bytes.
        assert_eq!(server.cache.pending_chunks("vol"), vec![0]);
        assert!(server.export("vol").is_none());
    }

    /// A client that stops halfway through a write's data does not hold
    /// up an unregister, and that write is not done.
    #[tokio::test]
    async fn unregister_does_not_wait_for_a_stalled_client() {
        let server = server();
        let (mut c, conn) = connected(&server, "vol").await;
        let mut w = request(NBD_CMD_WRITE, 1, 8192, 65_536);
        w.extend_from_slice(&[0xcd; 1000]);
        c.write_all(&w).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::time::timeout(Duration::from_secs(5), server.unregister("vol"))
            .await
            .expect("unregister waited on a stalled client");
        conn.await.unwrap();
        assert!(
            server.cache.pending_chunks("vol").is_empty(),
            "the write was done"
        );
        assert!(server.cache.read("vol", 8192, 1).is_none());
    }

    /// A request read before the export closed but not yet started is
    /// refused with ESHUTDOWN, never served.
    #[tokio::test]
    async fn a_request_not_started_when_the_export_closes_is_refused() {
        let server = server();
        let mut closed = server.export("vol").unwrap().closed;
        let handle = tokio::spawn({
            let server = Arc::clone(&server);
            async move { server.unregister("vol").await }
        });
        closed.wait_for(|c| *c).await.unwrap();
        let reply = server
            .serve_request(
                "vol",
                "127.0.0.1:1".parse().unwrap(),
                &closed,
                NBD_CMD_WRITE,
                3,
                0,
                512,
                Some(bytes::Bytes::from_static(&[1; 512])),
            )
            .await;
        assert_eq!(reply, reply_header(3, NBD_ESHUTDOWN));
        assert!(server.cache.pending_chunks("vol").is_empty());
        assert!(
            !handle.is_finished(),
            "unregister returned while a request held the export"
        );
        drop(closed);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn a_reply_header_is_magic_error_handle_big_endian() {
        let h = reply_header(0x0102_0304_0506_0708, 5);
        assert_eq!(&h[..4], &NBD_REPLY_MAGIC.to_be_bytes());
        assert_eq!(&h[4..8], &[0, 0, 0, 5]);
        assert_eq!(&h[8..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
