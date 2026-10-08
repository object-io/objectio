//! Packed objects: an object whose bytes are a slice of a pack, one stripe
//! shared by many small objects (objectio-docs
//! architecture/design/core/small-object-packing.md).
//!
//! The object's `StripeMeta` names the pack (`pack_id`) and its slice; the
//! pack's shard locations live once, in meta's pack record, so repair and
//! drain move a pack by updating one record. A read resolves the pack into
//! a stripe the ordinary read path understands.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use objectio_auth::AuthResult;
use objectio_common::ErasureConfig;
use objectio_erasure::ErasureCodec;
use objectio_proto::metadata::{
    AbortPackRequest, ErasureType, GetBucketVersioningRequest, GetPackRequest, GetPlacementRequest,
    IntendPackRequest, ListPacksRequest, NodePlacement, ObjectMeta, PackMember, PackRecord,
    PackSettleRequest, SealPackRequest, ShardLocation, SseAlgorithm, StripeMeta, VersioningState,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

use crate::osd_pool::{
    Reclaim, ShardTarget, get_object_meta_from_any, get_object_version_meta_from_osd,
    put_object_meta_to_all, stripe_targets, stripe_targets_of, write_shard_to_osd,
};
use crate::s3::{AppState, spawn_reclaim};

/// How long a pack record is trusted without asking meta again. A pack that
/// moved within it is caught by the read failing and refreshing the record.
const TTL: Duration = Duration::from_secs(60);

/// Records kept at most; past it the cache is cleared, not evicted entry by
/// entry: it refills from meta on demand.
const MAX_ENTRIES: usize = 100_000;

/// Pack records by pack id.
#[derive(Default)]
pub struct PackCache {
    entries: RwLock<HashMap<Vec<u8>, (PackRecord, Instant)>>,
}

impl PackCache {
    fn get(&self, pack_id: &[u8]) -> Option<PackRecord> {
        self.entries
            .read()
            .get(pack_id)
            .filter(|(_, at)| at.elapsed() < TTL)
            .map(|(record, _)| record.clone())
    }

    fn put(&self, record: PackRecord) {
        let mut entries = self.entries.write();
        if entries.len() >= MAX_ENTRIES {
            entries.clear();
        }
        entries.insert(record.pack_id.clone(), (record, Instant::now()));
    }

    /// Drop `pack_ids`, so the next read asks meta where they are now.
    pub fn forget<'a>(&self, pack_ids: impl IntoIterator<Item = &'a [u8]>) {
        let mut entries = self.entries.write();
        for id in pack_ids {
            entries.remove(id);
        }
    }
}

/// The packs `object`'s stripes are slices of.
pub fn packs_of(object: &ObjectMeta) -> Vec<&[u8]> {
    object
        .stripes
        .iter()
        .filter(|s| !s.pack_id.is_empty())
        .map(|s| s.pack_id.as_slice())
        .collect()
}

/// Why a packed object could not be resolved.
#[derive(Debug)]
pub enum ResolveError {
    /// Meta has no record of the pack: the object points at nothing.
    Missing(Vec<u8>),
    Meta(tonic::Status),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(id) => write!(f, "pack {} has no record", hex::encode(id)),
            Self::Meta(e) => write!(f, "pack lookup failed: {e}"),
        }
    }
}

/// Give every packed stripe of `object` its pack's shard locations, so the
/// ordinary read path can read its slice. `fresh` skips the cache. Returns
/// whether any record came from the cache: if the read then fails, the
/// caller refreshes and tries once more, as the pack may have moved.
pub async fn resolve(
    state: &AppState,
    object: &mut ObjectMeta,
    fresh: bool,
) -> Result<bool, ResolveError> {
    let mut from_cache = false;
    let mut meta = state.meta_client.clone();
    for stripe in object.stripes.iter_mut().filter(|s| !s.pack_id.is_empty()) {
        let cached = if fresh {
            None
        } else {
            state.pack_cache.get(&stripe.pack_id)
        };
        let record = if let Some(record) = cached {
            from_cache = true;
            record
        } else {
            let resp = meta
                .get_pack(GetPackRequest {
                    pack_id: stripe.pack_id.clone(),
                })
                .await
                .map_err(ResolveError::Meta)?
                .into_inner();
            let Some(record) = resp.pack.filter(|_| resp.found) else {
                return Err(ResolveError::Missing(stripe.pack_id.clone()));
            };
            state.pack_cache.put(record.clone());
            record
        };
        apply(stripe, &record);
    }
    Ok(from_cache)
}

/// `stripe`, a slice of the pack `record` describes, with the pack's
/// erasure scheme and shard locations; its slice is kept.
fn apply(stripe: &mut StripeMeta, record: &PackRecord) {
    let Some(pack) = record.stripe.as_ref() else {
        return;
    };
    stripe.stripe_id = pack.stripe_id;
    stripe.ec_k = pack.ec_k;
    stripe.ec_m = pack.ec_m;
    stripe.ec_type = pack.ec_type;
    stripe.ec_local_parity = pack.ec_local_parity;
    stripe.ec_global_parity = pack.ec_global_parity;
    stripe.local_group_size = pack.local_group_size;
    stripe.data_size = pack.data_size;
    stripe.shards.clone_from(&pack.shards);
    // The pack's shards are written under the pack id.
    stripe.object_id = if pack.object_id.is_empty() {
        record.pack_id.clone()
    } else {
        pack.object_id.clone()
    };
}

// ── Packing named objects (the test hook; the packer's core) ────────────────

/// Each object's slice starts on a storage block.
const SLICE_ALIGN: usize = 4096;

/// The largest object packed (the design's `pack_max`).
pub const PACK_MAX: u64 = 64 * 1024;

/// Prefix of the key a pack is placed under, in its bucket (meta's
/// repairer places a lost shard by the same key).
pub const PACK_KEY_PREFIX: &str = ".objectio-pack/";

#[derive(Debug, Deserialize)]
pub struct PackRequest {
    pub bucket: String,
    pub keys: Vec<String>,
    /// Stop just after this step, as a crash there would (tests only).
    #[serde(default)]
    pub stop_after: Option<StopAfter>,
    /// Seconds to wait between switching and releasing (see
    /// [`PackOptions::grace`]); 0 by default here.
    #[serde(default)]
    pub grace_secs: u64,
}

/// A point in [`pack_objects`] where a test stops it, standing for a
/// crash there. Reconciliation must then leave every object readable and
/// free only what nothing points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StopAfter {
    /// The pack is recorded, unsealed; nothing written.
    Intend,
    /// Its shards are written; still unsealed.
    Write,
    /// Sealed with its referrers; no object switched.
    Seal,
    /// The first object switched; its old stripe not yet released.
    SwitchOne,
}

/// No object is switched into a pack once this long has passed since it
/// was recorded. Reconciliation leaves packs alone for longer
/// ([`RECONCILE_AFTER`] — and a switch takes at most its RPC timeout, 10 s),
/// so it never decides "never switched" about an object a packer is about
/// to switch: that would release the object's reference to the pack it
/// then names. The packer measures this on its own clock; reconciliation
/// compares the pack's recorded time with its gateway's, so the margin also
/// covers clock skew between gateways and meta.
pub const SWITCH_DEADLINE: Duration = Duration::from_secs(300);

/// A pack this old and still unsettled had a packer die on it, or give up
/// at [`SWITCH_DEADLINE`]: reconciliation may settle it.
pub const RECONCILE_AFTER: Duration = Duration::from_secs(600);

/// How [`pack_objects`] runs.
#[derive(Debug, Clone, Default)]
pub struct PackOptions {
    /// Stop after this step (tests standing for a crash there).
    pub stop_after: Option<StopAfter>,
    /// Repacking this pack: slices of it are packable.
    pub from_pack: Option<Vec<u8>>,
    /// How long after switching to wait before releasing the objects' old
    /// stripes, so a read that fetched an ObjectMeta just before its switch
    /// still finds the shards it names. A packer that dies meanwhile leaves
    /// the members unsettled, and reconciliation releases them. The packer
    /// uses `--pack-grace-secs` (30 s by default).
    pub grace: Duration,
}

#[derive(Debug, Default, Serialize)]
pub struct PackReport {
    /// Hex id of the pack written; empty if nothing was packed.
    pub pack_id: String,
    pub packed: Vec<String>,
    /// `[key, why]` of each key left as it was.
    pub skipped: Vec<(String, String)>,
    /// Hex ids of the OSDs holding the pack's shards.
    pub shard_nodes: Vec<String>,
}

/// `POST /_admin/test/pack {"bucket", "keys"}`: pack those objects now.
/// Mounted only with `--test-hooks`; the system admin only.
pub async fn admin_test_pack(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(req): Json<PackRequest>,
) -> Response {
    let caller = crate::admin::extract_caller(&auth, &headers);
    if !crate::admin::is_system_admin(&caller) {
        return (StatusCode::FORBIDDEN, "system admin only").into_response();
    }
    let opts = PackOptions {
        stop_after: req.stop_after,
        from_pack: None,
        grace: Duration::from_secs(req.grace_secs),
    };
    match pack_objects(&state, &req.bucket, &req.keys, &opts).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// Why `object` can't be packed, if it can't.
pub(crate) fn unpackable(object: &ObjectMeta, versioned_bucket: bool) -> Option<&'static str> {
    unpackable_from(object, versioned_bucket, None)
}

/// As [`unpackable`], when repacking `from_pack`: a slice of that pack is
/// packable too.
fn unpackable_from(
    object: &ObjectMeta,
    versioned_bucket: bool,
    from_pack: Option<&[u8]>,
) -> Option<&'static str> {
    let in_from_pack = |s: &StripeMeta| from_pack.is_some_and(|p| s.pack_id == p);
    let encrypted = SseAlgorithm::try_from(object.encryption_algorithm)
        .is_ok_and(|a| a != SseAlgorithm::SseNone);
    if object.is_delete_marker {
        Some("a delete marker")
    } else if object.size == 0 || object.size > PACK_MAX {
        Some("not a small object")
    } else if !object.inline_data.is_empty() {
        Some("stored inline")
    } else if object.stripes.iter().any(|s| s.shards_in_metadata) {
        // Its shards take no disk blocks to pack (B21).
        Some("kept in metadata")
    } else if encrypted {
        Some("encrypted")
    } else if object.stripes.len() != 1
        || !(object.stripes[0].pack_id.is_empty() || in_from_pack(&object.stripes[0]))
    {
        Some("not one stripe of its own")
    } else if object.version_id.is_empty() && versioned_bucket {
        // A null version can have a version entry of its own that a switch
        // wouldn't update; it would go on naming the stripe released.
        Some("a null version in a versioned bucket")
    } else {
        None
    }
}

/// Whether `bytes` are what `etag` was computed over (a plain MD5 ETag;
/// any other kind can't be checked and doesn't match).
fn etag_matches(etag: &str, bytes: &[u8]) -> bool {
    use md5::Digest as _;
    let etag = etag.trim_matches('"');
    !etag.contains('-') && etag.eq_ignore_ascii_case(&hex::encode(md5::Md5::digest(bytes)))
}

struct Candidate {
    key: String,
    object: ObjectMeta,
    nodes: Vec<NodePlacement>,
    bytes: Bytes,
    offset: u64,
}

/// Pack `keys` of `bucket` into one new pack, in the order the design
/// makes crash-safe: the pack is recorded (unsealed) before a shard is
/// written; sealed, with its locations and its objects as referrers, once
/// written; then each object is switched to its slice, only over the
/// object that was read; and only then is its own stripe released. An
/// object that changed meanwhile keeps its stripe and lets go of the pack.
pub async fn pack_objects(
    state: &Arc<AppState>,
    bucket: &str,
    keys: &[String],
    opts: &PackOptions,
) -> Result<PackReport, String> {
    let stop_after = opts.stop_after;
    let from_pack = opts.from_pack.as_deref();
    let mut report = PackReport::default();
    let mut meta = state.meta_client.clone();
    let versioned = meta
        .get_bucket_versioning(GetBucketVersioningRequest {
            bucket: bucket.to_string(),
        })
        .await
        .map_err(|e| format!("versioning state of {bucket}: {e}"))?
        .into_inner()
        .state()
        != VersioningState::VersioningDisabled;

    let mut candidates = Vec::new();
    for key in keys {
        let mut skip = |why: &str| report.skipped.push((key.clone(), why.to_string()));
        let Ok(nodes) = crate::s3::get_placement_nodes_for_object(state, bucket, key).await else {
            skip("no placement");
            continue;
        };
        let object = match get_object_meta_from_any(&state.osd_pool, &nodes, bucket, key).await {
            Ok(Some(o)) => o,
            Ok(None) => {
                skip("no such object");
                continue;
            }
            Err(e) => {
                skip(&format!("metadata unreadable: {e}"));
                continue;
            }
        };
        if let Some(why) = unpackable_from(&object, versioned, from_pack) {
            skip(why);
            continue;
        }
        // The bytes as a GET returns them, checked against the ETag of the
        // object read: a body from an object written meanwhile won't match.
        let resp = crate::s3::get_object_version(
            state.clone(),
            bucket.to_string(),
            key.clone(),
            None,
            HeaderMap::new(),
        )
        .await;
        if !resp.status().is_success() {
            skip(&format!("read failed: {}", resp.status()));
            continue;
        }
        let Ok(bytes) = axum::body::to_bytes(resp.into_body(), PACK_MAX as usize + 1).await else {
            skip("read failed");
            continue;
        };
        if bytes.len() as u64 != object.size || !etag_matches(&object.etag, &bytes) {
            skip("changed while it was read");
            continue;
        }
        candidates.push(Candidate {
            key: key.clone(),
            object,
            nodes,
            bytes,
            offset: 0,
        });
    }
    if candidates.is_empty() {
        return Ok(report);
    }

    let mut data = Vec::new();
    for c in &mut candidates {
        c.offset = data.len() as u64;
        data.extend_from_slice(&c.bytes);
        data.resize(data.len().next_multiple_of(SLICE_ALIGN), 0);
    }
    let pack_id = Uuid::now_v7().as_bytes().to_vec();
    let placement = meta
        .get_placement(GetPlacementRequest {
            bucket: bucket.to_string(),
            key: format!("{PACK_KEY_PREFIX}{}", hex::encode(&pack_id)),
            size: data.len() as u64,
            storage_class: "STANDARD".to_string(),
        })
        .await
        .map_err(|e| format!("placement: {e}"))?
        .into_inner();
    let (k, m) = (placement.ec_k, placement.ec_m);
    let total = (k + m) as usize;
    if ErasureType::try_from(placement.ec_type) != Ok(ErasureType::ErasureMds) || m == 0 {
        return Err("packs are written with Reed-Solomon (MDS) erasure codes only".into());
    }
    if placement.nodes.len() < total {
        return Err(format!(
            "placement has {} OSDs, the pack needs {total}",
            placement.nodes.len()
        ));
    }
    let nodes: Vec<NodePlacement> = placement.nodes[..total].to_vec();
    let intended = StripeMeta {
        stripe_id: 0,
        ec_k: k,
        ec_m: m,
        ec_type: placement.ec_type,
        data_size: data.len() as u64,
        object_id: pack_id.clone(),
        shards: nodes
            .iter()
            .enumerate()
            .map(|(i, n)| ShardLocation {
                position: u32::try_from(i).unwrap_or(u32::MAX),
                node_id: n.node_id.clone(),
                shard_type: n.shard_type,
                local_group: n.local_group,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };

    // From here, the pack exists: past SWITCH_DEADLINE no object is
    // switched into it, so reconciliation (which waits longer) never races
    // a switch.
    let intended_at = std::time::Instant::now();
    // 1. Intend: recorded before any shard exists, so a crash from here on
    // leaves a record that says where to clean up.
    meta.intend_pack(IntendPackRequest {
        pack: Some(PackRecord {
            pack_id: pack_id.clone(),
            stripe: Some(intended.clone()),
            data_len: data.len() as u64,
            bucket: bucket.to_string(),
            members: candidates.iter().map(member).collect(),
            ..Default::default()
        }),
    })
    .await
    .map_err(|e| format!("intend pack: {e}"))?;
    report.pack_id = hex::encode(&pack_id);
    if stop_after == Some(StopAfter::Intend) {
        return Ok(report);
    }

    // 2. Write.
    let codec = ErasureCodec::new(ErasureConfig::new(
        u8::try_from(k).unwrap_or(u8::MAX),
        u8::try_from(m).unwrap_or(u8::MAX),
    ))
    .map_err(|e| format!("codec: {e}"))?;
    let shards = match codec.encode_bytes(&data) {
        Ok(s) => s,
        Err(e) => {
            abort(state, &pack_id).await;
            return Err(format!("encode: {e}"));
        }
    };
    let writes = shards
        .into_iter()
        .zip(&nodes)
        .enumerate()
        .map(|(i, (shard, node))| {
            let pool = state.osd_pool.clone();
            let id = pack_id.clone();
            async move {
                let position = u32::try_from(i).unwrap_or(u32::MAX);
                let r = write_shard_to_osd(&pool, node, &id, 0, position, shard, k, m, None, None)
                    .await;
                (position, r, node)
            }
        });
    let mut written = Vec::new();
    for (position, result, node) in futures::future::join_all(writes).await {
        match result {
            Ok((loc, crc32c)) => written.push(ShardLocation {
                position,
                node_id: loc.node_id,
                disk_id: loc.disk_id,
                offset: loc.offset,
                shard_type: node.shard_type,
                local_group: node.local_group,
                crc32c: Some(crc32c),
            }),
            Err(e) => warn!("pack {}: shard {position}: {e}", hex::encode(&pack_id)),
        }
    }
    // As a PUT: k + 1 shards on disk, or no pack.
    if written.len() < k as usize + 1 {
        abort(state, &pack_id).await;
        return Err(format!(
            "write quorum not met: {} of {total} shards written",
            written.len()
        ));
    }
    if stop_after == Some(StopAfter::Write) {
        return Ok(report);
    }

    // 3. Seal: the shards as written, and the objects as its referrers.
    let sealed = StripeMeta {
        shards: written,
        ..intended
    };
    if let Err(e) = meta
        .seal_pack(SealPackRequest {
            pack_id: pack_id.clone(),
            referrers: candidates
                .iter()
                .map(|c| c.object.object_id.clone())
                .collect(),
            stripe: Some(sealed.clone()),
        })
        .await
    {
        abort(state, &pack_id).await;
        return Err(format!("seal pack: {e}"));
    }
    report.shard_nodes = sealed
        .shards
        .iter()
        .map(|l| hex::encode(&l.node_id))
        .collect();
    if from_pack.is_some() {
        crate::gateway_metrics::record_pack_compaction(candidates.len() as u64);
    } else {
        crate::gateway_metrics::record_pack(
            candidates.len() as u64,
            candidates
                .iter()
                .map(|c| raw_size(c.object.size, k, m))
                .sum(),
            raw_size(data.len() as u64, k, m),
        );
    }
    if stop_after == Some(StopAfter::Seal) {
        return Ok(report);
    }

    // 4. Switch, and 5. release.
    let mut settled = Vec::new();
    let mut releases = Vec::new();
    for (i, c) in candidates.into_iter().enumerate() {
        let mut packed = c.object.clone();
        packed.stripes = vec![slice_stripe(&pack_id, &sealed, c.offset, c.object.size)];
        let what = format!("{bucket}/{}", c.key);
        if intended_at.elapsed() > SWITCH_DEADLINE {
            // Too late to switch safely: what's left is reconciliation's.
            warn!(
                "pack {}: switch deadline passed; leaving the rest unswitched",
                report.pack_id
            );
            break;
        }
        if i == 1 && stop_after == Some(StopAfter::SwitchOne) {
            return Ok(report);
        }
        if stop_after == Some(StopAfter::SwitchOne) {
            // Switched, and stopped before its old stripe is released.
            let _ = put_object_meta_to_all(
                &state.osd_pool,
                &c.nodes,
                bucket,
                &c.key,
                packed,
                false,
                &c.object.object_id,
            )
            .await;
            report.packed.push(c.key);
            continue;
        }
        match put_object_meta_to_all(
            &state.osd_pool,
            &c.nodes,
            bucket,
            &c.key,
            packed,
            false,
            &c.object.object_id,
        )
        .await
        {
            Ok(displaced)
                if displaced.iter().all(|d| {
                    d.replaced
                        .as_ref()
                        .is_some_and(|r| r.object_id == c.object.object_id)
                }) =>
            {
                // Every copy now names the pack: its own stripe is nobody's,
                // once reads already under way are done with it.
                releases.push((
                    stripe_targets_of(&c.object),
                    what,
                    c.object.object_id.clone(),
                ));
                report.packed.push(c.key);
            }
            Ok(_) => {
                // Switched, but some copy held something else: keep the old
                // stripe rather than guess. A leak, never a loss.
                warn!("pack: {what} switched over an unexpected object; its old stripe is kept");
                report.packed.push(c.key);
            }
            Err(e) if e.unapplied => {
                // Changed meanwhile: it keeps its stripe and lets go of
                // the pack.
                if release(state, pack_reference(&pack_id, &c.object.object_id), &what).await {
                    settled.push(c.object.object_id.clone());
                }
                report
                    .skipped
                    .push((c.key, "changed while it was packed".into()));
            }
            Err(e) => {
                // Some copies may name the pack, others the old stripe:
                // both hold its bytes, so neither is released.
                warn!(
                    "pack: {what} partly switched ({}); both copies kept",
                    e.error
                );
                report.skipped.push((c.key, "partly switched".into()));
            }
        }
    }
    if !releases.is_empty() && !opts.grace.is_zero() {
        tokio::time::sleep(opts.grace).await;
    }
    for (targets, what, object_id) in releases {
        if release(state, targets, &what).await {
            settled.push(object_id);
        }
    }
    // What's done needn't be looked at again; the rest (left partly
    // switched, switched over the unexpected, or not released) is
    // reconciliation's.
    settle(state, &pack_id, settled).await;
    Ok(report)
}

/// A pack's member, as recorded for reconciliation.
fn member(c: &Candidate) -> PackMember {
    let old_stripe = c.object.stripes.first().cloned().unwrap_or_default();
    PackMember {
        object_id: c.object.object_id.clone(),
        key: c.key.clone(),
        version_id: c.object.version_id.clone(),
        slice_offset: c.offset,
        slice_length: c.object.size,
        old_stripe: Some(old_stripe),
        settled: false,
    }
}

/// A packed object's one stripe: its slice of the pack.
fn slice_stripe(pack_id: &[u8], pack: &StripeMeta, offset: u64, length: u64) -> StripeMeta {
    StripeMeta {
        stripe_id: pack.stripe_id,
        ec_k: pack.ec_k,
        ec_m: pack.ec_m,
        ec_type: pack.ec_type,
        data_size: pack.data_size,
        object_id: pack_id.to_vec(),
        pack_id: pack_id.to_vec(),
        slice_offset: offset,
        slice_length: length,
        ..Default::default()
    }
}

/// Raw bytes `size` bytes take as one k+m stripe: each shard rounded up to
/// whole 4 KiB blocks with its 96-byte header and footer.
pub(crate) const fn raw_size(size: u64, k: u32, m: u32) -> u64 {
    let k = if k == 0 { 1 } else { k as u64 };
    let shard = size.div_ceil(k) + 96;
    shard.div_ceil(4096) * 4096 * (k + m as u64)
}

async fn settle(state: &AppState, pack_id: &[u8], object_ids: Vec<Vec<u8>>) {
    if object_ids.is_empty() {
        return;
    }
    if let Err(e) = state
        .meta_client
        .clone()
        .pack_settle(PackSettleRequest {
            pack_id: pack_id.to_vec(),
            object_ids,
        })
        .await
    {
        // Left for reconciliation, which finds them done.
        warn!("pack {}: settling members: {e}", hex::encode(pack_id));
    }
}

// ── Reconciliation ──────────────────────────────────────────────────────────

/// What a reconciliation pass did.
#[derive(Debug, Default, Serialize)]
pub struct ReconcileReport {
    /// Unsealed packs dropped, with their shards.
    pub aborted: usize,
    /// Members never switched (or gone): their pack reference released.
    pub released: usize,
    /// Members whose switch was finished: their old stripe released.
    pub finished: usize,
    /// Members left for a later pass: a copy unreadable, or disagreeing in
    /// a way that isn't safe to settle now.
    pub unknown: usize,
}

/// Bring every pack older than `min_age` to a settled state: an unsealed
/// one (its packer died before sealing) is dropped with its shards; each
/// unsettled member of a sealed one is looked up on every copy of its
/// ObjectMeta and either released from the pack (no copy names it), has its
/// switch finished (some do), or has its old stripe released (all do).
/// Nothing is freed while any copy that could be read points at it, and a
/// member with a copy that can't be read is left for later.
pub async fn reconcile(
    state: &Arc<AppState>,
    min_age: Duration,
) -> Result<ReconcileReport, String> {
    let mut report = ReconcileReport::default();
    let now = crate::lifecycle::now_ms() / 1000;
    let mut after = Vec::new();
    loop {
        let page = state
            .meta_client
            .clone()
            .list_packs(ListPacksRequest {
                start_after: after.clone(),
                limit: 500,
            })
            .await
            .map_err(|e| format!("list packs: {e}"))?
            .into_inner();
        for pack in &page.packs {
            if now.saturating_sub(pack.created_at) < min_age.as_secs() {
                continue;
            }
            if !pack.sealed {
                abort(state, &pack.pack_id).await;
                crate::gateway_metrics::record_pack_reconciled("aborted");
                report.aborted += 1;
                continue;
            }
            let Some(stripe) = pack.stripe.as_ref() else {
                continue;
            };
            let mut settled = Vec::new();
            for m in pack.members.iter().filter(|m| !m.settled) {
                match reconcile_member(state, pack, stripe, m).await {
                    Some(action) => {
                        crate::gateway_metrics::record_pack_reconciled(action);
                        if action == "released" {
                            report.released += 1;
                        } else {
                            report.finished += 1;
                        }
                        settled.push(m.object_id.clone());
                    }
                    None => report.unknown += 1,
                }
            }
            settle(state, &pack.pack_id, settled).await;
        }
        match page.packs.last() {
            Some(last) if page.truncated => after.clone_from(&last.pack_id),
            _ => return Ok(report),
        }
    }
}

/// Settle one member: `Some("released")`, `Some("finished")`, or `None` to
/// leave it for a later pass.
async fn reconcile_member(
    state: &Arc<AppState>,
    pack: &PackRecord,
    stripe: &StripeMeta,
    m: &PackMember,
) -> Option<&'static str> {
    let bucket = pack.bucket.as_str();
    let what = format!("{bucket}/{}", m.key);
    let nodes = crate::s3::get_placement_nodes_for_object(state, bucket, &m.key)
        .await
        .ok()?;
    let mut seen = std::collections::HashSet::new();
    let mut copies = Vec::new();
    for node in nodes.iter().filter(|n| seen.insert(n.node_id.clone())) {
        // A copy that can't be read could name either: decide nothing.
        let copy =
            get_object_version_meta_from_osd(&state.osd_pool, node, bucket, &m.key, &m.version_id)
                .await
                .ok()?;
        copies.push(copy);
    }
    let holders: Vec<&ObjectMeta> = copies
        .iter()
        .flatten()
        .filter(|o| o.object_id == m.object_id && !o.is_delete_marker)
        .collect();
    let names_pack = |o: &ObjectMeta| o.stripes.first().is_some_and(|s| s.pack_id == pack.pack_id);
    let old_stripe = || {
        let mut t = stripe_targets(std::slice::from_ref(m.old_stripe.as_ref()?));
        for x in &mut t {
            x.owner.clone_from(&m.object_id);
        }
        Some(t)
    };

    if holders.is_empty() {
        // Gone from every copy: deleted or overwritten through the S3
        // path, which released what it held. Releasing again is a no-op
        // for what's already gone, and frees what a crash left held.
        let pack_ref = release(state, pack_reference(&pack.pack_id, &m.object_id), &what).await;
        let old = match old_stripe() {
            Some(t) => release(state, t, &what).await,
            None => true,
        };
        return (pack_ref && old).then_some("released");
    }
    if holders.len() != copies.len() {
        // Some copies have it, some don't: repair restores the missing
        // ones first.
        return None;
    }
    let at_pack = holders.iter().filter(|o| names_pack(o)).count();
    if at_pack == 0 {
        // Never switched: it keeps its stripe and lets go of the pack.
        return release(state, pack_reference(&pack.pack_id, &m.object_id), &what)
            .await
            .then_some("released");
    }
    if at_pack < holders.len() {
        // Partly switched: finish it, over the object as it stands.
        let mut packed = holders
            .iter()
            .find(|o| !names_pack(o))
            .map(|o| (*o).clone())?;
        packed.stripes = vec![slice_stripe(
            &pack.pack_id,
            stripe,
            m.slice_offset,
            m.slice_length,
        )];
        let done = put_object_meta_to_all(
            &state.osd_pool,
            &nodes,
            bucket,
            &m.key,
            packed,
            false,
            &m.object_id,
        )
        .await;
        if done.is_err() {
            return None;
        }
    }
    // Every copy names the pack: the old stripe is nobody's.
    let released = match old_stripe() {
        Some(t) => release(state, t, &what).await,
        None => true,
    };
    released.then_some("finished")
}

/// Release `targets` now, and say whether it all went through. A member is
/// settled only after its release did: one that failed (meta busy, an OSD
/// down) stays for a later pass, which releases again — harmless for what
/// already went, since a release drops only this object's own reference.
async fn release(state: &AppState, targets: Vec<ShardTarget>, what: &str) -> bool {
    let failed = crate::osd_pool::reclaim_shards(
        &state.osd_pool,
        &mut state.meta_client.clone(),
        targets,
        Reclaim::Packed,
    )
    .await;
    if failed > 0 {
        warn!("pack: {what}: {failed} releases failed; left for reconciliation");
    }
    failed == 0
}

// ── Compaction ──────────────────────────────────────────────────────────────

/// What a compaction pass did.
#[derive(Debug, Default, Serialize)]
pub struct CompactReport {
    /// Packs whose live objects were moved into a new pack.
    pub compacted: usize,
    /// Objects moved.
    pub moved: usize,
    /// Hex ids of the new packs.
    pub new_packs: Vec<String>,
}

/// A pack is repacked once less than this share of its bytes is live.
const COMPACT_BELOW: f64 = 0.5;

/// The live bytes of `pack`: its members still among its `referrers`.
/// `None` when it can't be told: a member not settled yet (reconciliation
/// first), or a referrer that isn't a member (a copy sharing the pack, whose
/// slice is the source's: moving the source wouldn't free the pack).
fn live_bytes(pack: &PackRecord, referrers: &[Vec<u8>]) -> Option<u64> {
    if pack.members.iter().any(|m| !m.settled)
        || referrers
            .iter()
            .any(|r| !pack.members.iter().any(|m| &m.object_id == r))
    {
        return None;
    }
    Some(
        pack.members
            .iter()
            .filter(|m| referrers.contains(&m.object_id))
            .map(|m| m.slice_length)
            .sum(),
    )
}

/// Repack packs older than `min_age` that are less than half live: their
/// live objects go into a new pack by the same steps as packing (intend,
/// write, seal, switch over the object read, release), and the old pack is
/// freed when its last object lets go. At most `budget` packs.
pub async fn compact(
    state: &Arc<AppState>,
    min_age: Duration,
    budget: usize,
    stop_after: Option<StopAfter>,
    grace: Duration,
) -> Result<CompactReport, String> {
    let mut report = CompactReport::default();
    let now = crate::lifecycle::now_ms() / 1000;
    let mut after = Vec::new();
    loop {
        let page = state
            .meta_client
            .clone()
            .list_packs(ListPacksRequest {
                start_after: after.clone(),
                limit: 500,
            })
            .await
            .map_err(|e| format!("list packs: {e}"))?
            .into_inner();
        for (pack, refs) in page.packs.iter().zip(&page.referrers) {
            if report.compacted >= budget {
                return Ok(report);
            }
            if !pack.sealed || now.saturating_sub(pack.created_at) < min_age.as_secs() {
                continue;
            }
            let Some(live) = live_bytes(pack, &refs.object_ids) else {
                continue;
            };
            #[allow(clippy::cast_precision_loss)]
            let fraction = live as f64 / pack.data_len.max(1) as f64;
            if live == 0 || fraction >= COMPACT_BELOW {
                continue;
            }
            let keys: Vec<String> = pack
                .members
                .iter()
                .filter(|m| refs.object_ids.contains(&m.object_id))
                .map(|m| m.key.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let opts = PackOptions {
                stop_after,
                from_pack: Some(pack.pack_id.clone()),
                grace,
            };
            match pack_objects(state, &pack.bucket, &keys, &opts).await {
                Ok(r) if !r.pack_id.is_empty() => {
                    report.compacted += 1;
                    report.moved += r.packed.len();
                    report.new_packs.push(r.pack_id);
                }
                Ok(_) => {}
                Err(e) => warn!("compacting pack {}: {e}", hex::encode(&pack.pack_id)),
            }
        }
        match page.packs.last() {
            Some(last) if page.truncated => after.clone_from(&last.pack_id),
            _ => return Ok(report),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CompactRequest {
    #[serde(default)]
    pub min_age_secs: u64,
    #[serde(default)]
    pub stop_after: Option<StopAfter>,
    #[serde(default)]
    pub grace_secs: u64,
}

/// `POST /_admin/test/pack-compact {"min_age_secs", "stop_after"}`: run a
/// compaction pass now. Mounted only with `--test-hooks`.
pub async fn admin_test_compact(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(req): Json<CompactRequest>,
) -> Response {
    let caller = crate::admin::extract_caller(&auth, &headers);
    if !crate::admin::is_system_admin(&caller) {
        return (StatusCode::FORBIDDEN, "system admin only").into_response();
    }
    match compact(
        &state,
        Duration::from_secs(req.min_age_secs),
        usize::MAX,
        req.stop_after,
        Duration::from_secs(req.grace_secs),
    )
    .await
    {
        Ok(report) => Json(report).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// `GET /_admin/test/packs`: every pack, its referrers and members, for
/// tests to see what's left. Mounted only with `--test-hooks`.
pub async fn admin_test_list(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    let caller = crate::admin::extract_caller(&auth, &headers);
    if !crate::admin::is_system_admin(&caller) {
        return (StatusCode::FORBIDDEN, "system admin only").into_response();
    }
    let page = match state
        .meta_client
        .clone()
        .list_packs(ListPacksRequest {
            start_after: Vec::new(),
            limit: 10_000,
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => return crate::admin::meta_failure(&e),
    };
    let packs: Vec<serde_json::Value> = page
        .packs
        .iter()
        .zip(&page.referrers)
        .map(|(p, r)| {
            serde_json::json!({
                "pack_id": hex::encode(&p.pack_id),
                "sealed": p.sealed,
                "data_len": p.data_len,
                "referrers": r.object_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                "members": p.members.iter().map(|m| serde_json::json!({
                    "key": m.key,
                    "object_id": hex::encode(&m.object_id),
                    "settled": m.settled,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(serde_json::json!({ "packs": packs })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct ReconcileRequest {
    #[serde(default)]
    pub min_age_secs: u64,
}

/// `POST /_admin/test/pack-reconcile {"min_age_secs"}`: run a
/// reconciliation pass now. Mounted only with `--test-hooks`.
pub async fn admin_test_reconcile(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(req): Json<ReconcileRequest>,
) -> Response {
    let caller = crate::admin::extract_caller(&auth, &headers);
    if !crate::admin::is_system_admin(&caller) {
        return (StatusCode::FORBIDDEN, "system admin only").into_response();
    }
    match reconcile(&state, Duration::from_secs(req.min_age_secs)).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// `object_id`'s reference to the pack, for reclaim to release.
fn pack_reference(pack_id: &[u8], object_id: &[u8]) -> Vec<ShardTarget> {
    let mut targets = stripe_targets(&[StripeMeta {
        object_id: pack_id.to_vec(),
        pack_id: pack_id.to_vec(),
        ..Default::default()
    }]);
    for t in &mut targets {
        t.owner = object_id.to_vec();
    }
    targets
}

/// Drop an unsealed pack and whatever shards of it were written.
async fn abort(state: &Arc<AppState>, pack_id: &[u8]) {
    match state
        .meta_client
        .clone()
        .abort_pack(AbortPackRequest {
            pack_id: pack_id.to_vec(),
        })
        .await
    {
        Ok(r) => {
            if let Some(stripe) = r.into_inner().pack.and_then(|p| p.stripe) {
                spawn_reclaim(
                    state,
                    stripe_targets(&[stripe]),
                    Reclaim::FailedWrite,
                    format!("pack {}", hex::encode(pack_id)),
                );
            }
        }
        // Left unsealed: reconciliation (the packer's) finds and aborts it.
        Err(e) => warn!("pack {}: abort failed: {e}", hex::encode(pack_id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objectio_proto::metadata::ShardLocation;

    fn record(pack_id: &[u8], node: u8) -> PackRecord {
        PackRecord {
            pack_id: pack_id.to_vec(),
            stripe: Some(StripeMeta {
                stripe_id: 0,
                ec_k: 4,
                ec_m: 2,
                data_size: 1 << 20,
                object_id: pack_id.to_vec(),
                shards: (0..6)
                    .map(|position| ShardLocation {
                        position,
                        node_id: vec![node; 16],
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }),
            data_len: 1 << 20,
            version: 1,
            created_at: 0,
            sealed: true,
            bucket: String::new(),
            members: Vec::new(),
        }
    }

    #[test]
    fn a_packed_stripe_takes_the_packs_locations_and_keeps_its_slice() {
        let mut stripe = StripeMeta {
            pack_id: b"pack".to_vec(),
            object_id: b"pack".to_vec(),
            slice_offset: 4096,
            slice_length: 100,
            ..Default::default()
        };
        apply(&mut stripe, &record(b"pack", 7));
        assert_eq!(stripe.shards.len(), 6);
        assert_eq!((stripe.ec_k, stripe.ec_m), (4, 2));
        assert_eq!(stripe.data_size, 1 << 20);
        assert_eq!((stripe.slice_offset, stripe.slice_length), (4096, 100));
        assert_eq!(stripe.object_id, b"pack");
    }

    #[test]
    fn the_cache_forgets_on_request() {
        let cache = PackCache::default();
        cache.put(record(b"p1", 1));
        assert!(cache.get(b"p1").is_some());
        cache.forget([b"p1".as_slice()]);
        assert!(cache.get(b"p1").is_none());
    }
}
