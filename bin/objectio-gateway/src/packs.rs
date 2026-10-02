//! Packed objects: an object whose bytes are a slice of a pack, one stripe
//! shared by many small objects (objectio-docs
//! architecture/design/small-object-packing.md).
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
    IntendPackRequest, NodePlacement, ObjectMeta, PackRecord, SealPackRequest, ShardLocation,
    SseAlgorithm, StripeMeta, VersioningState,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

use crate::osd_pool::{
    Reclaim, ShardTarget, get_object_meta_from_any, put_object_meta_to_all, stripe_targets,
    stripe_targets_of, write_shard_to_osd,
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
    match pack_objects(&state, &req.bucket, &req.keys).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// Why `object` can't be packed, if it can't.
fn unpackable(object: &ObjectMeta, versioned_bucket: bool) -> Option<&'static str> {
    let encrypted = SseAlgorithm::try_from(object.encryption_algorithm)
        .is_ok_and(|a| a != SseAlgorithm::SseNone);
    if object.is_delete_marker {
        Some("a delete marker")
    } else if object.size == 0 || object.size > PACK_MAX {
        Some("not a small object")
    } else if !object.inline_data.is_empty() {
        Some("stored inline")
    } else if encrypted {
        Some("encrypted")
    } else if object.stripes.len() != 1 || !object.stripes[0].pack_id.is_empty() {
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
) -> Result<PackReport, String> {
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
        if let Some(why) = unpackable(&object, versioned) {
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

    // 1. Intend: recorded before any shard exists, so a crash from here on
    // leaves a record that says where to clean up.
    meta.intend_pack(IntendPackRequest {
        pack: Some(PackRecord {
            pack_id: pack_id.clone(),
            stripe: Some(intended.clone()),
            data_len: data.len() as u64,
            bucket: bucket.to_string(),
            ..Default::default()
        }),
    })
    .await
    .map_err(|e| format!("intend pack: {e}"))?;

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
                let r = write_shard_to_osd(&pool, node, &id, 0, position, shard, k, m, None).await;
                (position, r, node)
            }
        });
    let mut written = Vec::new();
    for (position, result, node) in futures::future::join_all(writes).await {
        match result {
            Ok(loc) => written.push(ShardLocation {
                position,
                node_id: loc.node_id,
                disk_id: loc.disk_id,
                offset: loc.offset,
                shard_type: node.shard_type,
                local_group: node.local_group,
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
    report.pack_id = hex::encode(&pack_id);
    report.shard_nodes = sealed
        .shards
        .iter()
        .map(|l| hex::encode(&l.node_id))
        .collect();

    // 4. Switch, and 5. release.
    for c in candidates {
        let mut packed = c.object.clone();
        packed.stripes = vec![StripeMeta {
            stripe_id: sealed.stripe_id,
            ec_k: k,
            ec_m: m,
            ec_type: sealed.ec_type,
            data_size: sealed.data_size,
            object_id: pack_id.clone(),
            pack_id: pack_id.clone(),
            slice_offset: c.offset,
            slice_length: c.object.size,
            ..Default::default()
        }];
        let what = format!("{bucket}/{}", c.key);
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
                // Every copy now names the pack: its own stripe is nobody's.
                spawn_reclaim(state, stripe_targets_of(&c.object), Reclaim::Packed, what);
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
                spawn_reclaim(
                    state,
                    pack_reference(&pack_id, &c.object.object_id),
                    Reclaim::Packed,
                    what,
                );
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
    Ok(report)
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
