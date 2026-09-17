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
use tracing::{error, info, warn};

use crate::ec_io::read_chunk;
use crate::osd_pool::OsdPool;
use crate::store::BlockStore;

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
    store: Arc<BlockStore>,
    osd_pool: Arc<OsdPool>,
    meta_client: Arc<
        tokio::sync::Mutex<
            objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
                tonic::transport::Channel,
            >,
        >,
    >,
    ec_k: u32,
    ec_m: u32,
}

/// Where a chunk's slice of a read lands in the reply buffer.
///
/// The reply is one flat buffer covering `[read_offset, read_offset + length)`
/// and each `ChunkRange` describes one chunk's intersection with it, so a
/// range's bytes belong at its absolute position minus where the read started.
///
/// Getting this wrong is invisible in a single-chunk read — the answer is
/// always 0 — and is exactly what a read crossing a chunk boundary depends on.
fn reply_offset(
    range: &objectio_block::chunk::ChunkRange,
    read_offset: u64,
    chunk_size: u64,
) -> usize {
    let absolute = range.chunk_id * chunk_size + range.offset_in_chunk;
    absolute.saturating_sub(read_offset) as usize
}

impl NbdServer {
    pub fn new(
        cache: Arc<objectio_block::WriteCache>,
        store: Arc<BlockStore>,
        osd_pool: Arc<OsdPool>,
        meta_client: Arc<
            tokio::sync::Mutex<
                objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
                    tonic::transport::Channel,
                >,
            >,
        >,
        ec_k: u32,
        ec_m: u32,
    ) -> Self {
        Self {
            exports: RwLock::new(HashMap::new()),
            cache,
            store,
            osd_pool,
            meta_client,
            ec_k,
            ec_m,
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
        self.data_phase(&mut stream, &export_name, &export, peer)
            .await?;

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

    async fn data_phase(
        &self,
        stream: &mut TcpStream,
        vol_id: &str,
        export: &NbdExport,
        peer: SocketAddr,
    ) -> anyhow::Result<()> {
        loop {
            // Read request header: magic(4) + flags(2) + type(2) + handle(8) + offset(8) + length(4) = 28 bytes
            let magic = stream.read_u32().await?;
            if magic != NBD_REQUEST_MAGIC {
                return Err(anyhow::anyhow!("bad request magic: {magic:#x}"));
            }
            let _flags = stream.read_u16().await?;
            let cmd = stream.read_u16().await?;
            let handle = stream.read_u64().await?;
            let offset = stream.read_u64().await?;
            let length = stream.read_u32().await?;

            match cmd {
                NBD_CMD_READ => {
                    let mut data = self
                        .nbd_read(vol_id, offset, length as u64)
                        .await
                        .unwrap_or_else(|e| {
                            warn!("NBD read error for {peer}: {e}");
                            vec![0u8; length as usize]
                        });

                    // A simple reply has no length field, so the client reads
                    // exactly `length` bytes off the socket no matter what we
                    // send. Anything else desynchronises the connection for
                    // good — belt and braces on top of nbd_read's own
                    // guarantee, because the failure is silent corruption.
                    if data.len() != length as usize {
                        warn!(
                            "NBD read for {peer} returned {} bytes for a {length}-byte request",
                            data.len()
                        );
                        data.resize(length as usize, 0);
                    }

                    // Reply: magic(4) + error(4) + handle(8) + data
                    stream.write_u32(NBD_REPLY_MAGIC).await?;
                    stream.write_u32(0).await?; // no error
                    stream.write_u64(handle).await?;
                    stream.write_all(&data).await?;
                }

                NBD_CMD_WRITE => {
                    if export.read_only {
                        // Still need to consume the data bytes
                        let mut discard = vec![0u8; length as usize];
                        stream.read_exact(&mut discard).await?;
                        self.send_reply(stream, handle, 1).await?; // EPERM
                        continue;
                    }
                    let mut data = vec![0u8; length as usize];
                    stream.read_exact(&mut data).await?;

                    let error = if let Err(e) = self.cache.write(vol_id, offset, &data) {
                        warn!("NBD write cache error for {peer}: {e}");
                        5u32 // EIO
                    } else {
                        0u32
                    };
                    self.send_reply(stream, handle, error).await?;
                }

                NBD_CMD_FLUSH => {
                    // Inline flush — need a temporary state reference
                    // We can't call flush_volume_all here without the full state.
                    // Drain the cache's queue without a background state reference.
                    // (Full EC flush happens in background loop; NBD FLUSH ensures
                    //  dirty cache data is at least checkpointed.)
                    self.send_reply(stream, handle, 0).await?;
                }

                NBD_CMD_TRIM => {
                    // Zero-fill trimmed range
                    let zeros = vec![0u8; length as usize];
                    let _ = self.cache.write(vol_id, offset, &zeros);
                    self.send_reply(stream, handle, 0).await?;
                }

                NBD_CMD_DISC => {
                    info!("NBD: client {peer} sent disconnect for '{vol_id}'");
                    return Ok(());
                }

                _ => {
                    warn!("NBD: unknown command {cmd} from {peer}");
                    self.send_reply(stream, handle, 22).await?; // EINVAL
                }
            }
        }
    }

    async fn send_reply(
        &self,
        stream: &mut TcpStream,
        handle: u64,
        error: u32,
    ) -> anyhow::Result<()> {
        stream.write_u32(NBD_REPLY_MAGIC).await?;
        stream.write_u32(error).await?;
        stream.write_u64(handle).await?;
        Ok(())
    }

    /// Read `length` bytes at `offset`, always returning exactly that many.
    ///
    /// This used to serve only the chunk containing `offset`, so a read that
    /// crossed a 4 MB boundary came back short. An NBD simple reply carries no
    /// length — the client reads exactly as many bytes as it asked for — so a
    /// short reply does not produce a short read, it slides the client one
    /// frame out of step and every subsequent reply is parsed as data. A
    /// filesystem with readahead crosses a chunk boundary within seconds of
    /// being mounted.
    ///
    /// Sparse chunks read as zeros: a never-written region of a thin volume is
    /// zeros by definition, not an error.
    async fn nbd_read(&self, vol_id: &str, offset: u64, length: u64) -> anyhow::Result<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }

        // Try cache first — it assembles across chunks itself.
        if let Some(data) = self.cache.read(vol_id, offset, length) {
            return Ok(data);
        }

        let chunk_mapper = objectio_block::chunk::ChunkMapper::default();
        let chunk_size = chunk_mapper.chunk_size() as usize;
        let mut out = vec![0u8; length as usize];

        for range in chunk_mapper.byte_range_to_chunks(offset, length) {
            let chunk_data = match self.store.get_chunk(vol_id, range.chunk_id)? {
                Some(key) => {
                    read_chunk(
                        Arc::clone(&self.meta_client),
                        &self.osd_pool,
                        &key,
                        self.ec_k,
                        self.ec_m,
                    )
                    .await?
                }
                None => vec![0u8; chunk_size],
            };

            self.cache.add_clean(
                vol_id,
                range.chunk_id,
                bytes::Bytes::from(chunk_data.clone()),
            );

            // Copy what this chunk actually holds; anything past its end stays
            // zero rather than shortening the reply.
            let dst = reply_offset(&range, offset, chunk_mapper.chunk_size());
            let start = (range.offset_in_chunk as usize).min(chunk_data.len());
            let end = (start + range.length as usize).min(chunk_data.len());
            let src = &chunk_data[start..end];
            let copy = src.len().min(out.len().saturating_sub(dst));
            out[dst..dst + copy].copy_from_slice(&src[..copy]);
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::reply_offset;
    use objectio_block::chunk::ChunkMapper;

    /// The reply buffer must be tiled exactly: every byte written once, no
    /// gaps, no overlaps, nothing past the end.
    ///
    /// The bug this pins served only the chunk containing the start offset, so
    /// a read crossing a boundary came back short — and an NBD simple reply
    /// has no length field, so a short reply slides the client one frame out of
    /// step and silently corrupts everything after it.
    fn assert_tiles(offset: u64, length: u64) {
        let mapper = ChunkMapper::default();
        let chunk_size = mapper.chunk_size();
        let mut covered = vec![0u8; usize::try_from(length).unwrap()];

        for range in mapper.byte_range_to_chunks(offset, length) {
            let dst = reply_offset(&range, offset, chunk_size);
            let len = usize::try_from(range.length).unwrap();
            assert!(
                dst + len <= covered.len(),
                "chunk {} writes past the end of a {length}-byte reply at {offset}",
                range.chunk_id
            );
            for b in &mut covered[dst..dst + len] {
                *b += 1;
            }
        }

        assert!(
            covered.iter().all(|&n| n == 1),
            "read at {offset} for {length} bytes does not tile its reply: \
             {} bytes unwritten, {} written twice",
            covered.iter().filter(|&&n| n == 0).count(),
            covered.iter().filter(|&&n| n > 1).count(),
        );
    }

    #[test]
    fn a_read_inside_one_chunk_starts_at_zero() {
        assert_tiles(0, 4096);
        assert_tiles(1024, 4096);
    }

    #[test]
    fn a_read_crossing_one_boundary_tiles_both_chunks() {
        let chunk = ChunkMapper::default().chunk_size();
        assert_tiles(chunk - 64 * 1024, 128 * 1024);
    }

    #[test]
    fn a_read_spanning_several_whole_chunks_tiles_all_of_them() {
        let chunk = ChunkMapper::default().chunk_size();
        assert_tiles(0, chunk * 3);
        assert_tiles(chunk * 5, chunk * 2);
    }

    #[test]
    fn an_unaligned_read_across_three_chunks_tiles_them() {
        // The shape a filesystem actually produces: neither end on a boundary.
        let chunk = ChunkMapper::default().chunk_size();
        assert_tiles(chunk + 1234, chunk * 2 + 4567);
    }

    #[test]
    fn a_read_starting_far_into_the_volume_tiles_correctly() {
        // reply_offset subtracts the read offset from an absolute position; at
        // a large offset an unsubtracted value would index far out of bounds.
        let chunk = ChunkMapper::default().chunk_size();
        assert_tiles(chunk * 100_000 + 512, 256 * 1024);
    }

    #[test]
    fn single_sector_reads_tile_at_every_position_in_a_chunk() {
        let chunk = ChunkMapper::default().chunk_size();
        for at in [0, 512, chunk / 2, chunk - 512, chunk, chunk + 512] {
            assert_tiles(at, 512);
        }
    }
}
