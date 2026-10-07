//! S3 API handlers

/// Maximum shard size in bytes (must fit in a storage block)
/// Block size is 4MB with ~96 bytes overhead, so use 4MB - 4KB for safety margin
const MAX_SHARD_SIZE: usize = 4 * 1024 * 1024 - 4096; // ~4MB per shard

use crate::osd_pool::{
    Displaced, MetaWriteError, OsdPool, PendingShards, Reclaim, ShardTarget, delete_meta_from_all,
    get_object_meta_from_any, get_object_version_meta_from_any, put_object_meta_to_all,
    read_shard_from_osd, reclaim_shards, reclaimable_after_overwrite, referenced_object_ids,
    stripe_targets, stripe_targets_of, unreferenced, write_shard_to_osd,
};
use crate::scatter_gather::ScatterGatherEngine;
use axum::{
    Extension,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::Response,
};
use base64::Engine;
use bytes::Bytes;
use objectio_auth::{
    AuthResult,
    policy::{BucketPolicy, PolicyEvaluator},
};
use objectio_common::ErasureConfig;
use objectio_erasure::{
    ErasureCodec,
    backend::{LrcBackend, LrcConfig, RustSimdLrcBackend},
};
use objectio_proto::metadata::{
    AbortMultipartUploadRequest,
    BucketSseConfiguration,
    CompleteMultipartUploadRequest as ProtoCompleteMultipartUploadRequest,
    CreateAccessKeyRequest,
    CreateBucketRequest,
    CreateMultipartUploadRequest,
    // IAM types
    CreateUserRequest,
    DeleteAccessKeyRequest,
    DeleteBucketEncryptionRequest,
    DeleteBucketPolicyRequest,
    DeleteBucketRequest,
    DeleteUserRequest,
    ErasureType,
    GetBucketEncryptionRequest,
    GetBucketPolicyRequest,
    GetBucketRequest,
    GetBucketVersioningRequest,
    GetListingNodesRequest,
    GetMultipartUploadRequest,
    GetObjectLockConfigRequest,
    GetPlacementRequest,
    GetUserRequest,
    KeyOperation as ProtoKeyOperation,
    LegalHold,
    ListAccessKeysRequest,
    ListBucketsRequest,
    ListMultipartUploadsRequest,
    ListPartsRequest,
    ListUsersRequest,
    ObjectChecksum,
    ObjectLockConfiguration as ProtoObjectLockConfig,
    ObjectMeta,
    ObjectRetention,
    PartInfo,
    PutBucketEncryptionRequest,
    PutBucketVersioningRequest,
    PutObjectLockConfigRequest,
    RegisterPartRequest,
    RetentionMode,
    RetentionRule,
    SetBucketPolicyRequest,
    SettleMultipartUploadRequest,
    ShardLocation,
    SseAlgorithm,
    SseRule,
    StripeMeta,
    VersioningState,
    metadata_service_client::MetadataServiceClient,
};
use quick_xml::se::to_string as to_xml;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

mod acl;
mod admin;
mod buckets;
mod copy;
mod delete;
mod get;
mod grep;
mod listing;
mod lock;
mod multipart;
mod put;
mod sse;
mod tagging;
mod types;
mod versions;
pub(crate) use acl::*;
pub use admin::*;
pub use buckets::*;
pub(crate) use copy::*;
pub use delete::*;
pub use get::*;
pub(crate) use grep::*;
pub use listing::*;
pub(crate) use lock::*;
pub(crate) use multipart::*;
pub use put::*;
pub(crate) use sse::*;
pub(crate) use tagging::*;
pub use types::*;
pub(crate) use versions::*;

/// Application state shared across handlers
pub struct AppState {
    pub meta_client: MetadataServiceClient<Channel>,
    pub osd_pool: Arc<OsdPool>,
    pub ec_k: u32,
    pub ec_m: u32,
    pub policy_evaluator: PolicyEvaluator,
    /// TTL cache of bucket policies, bucket owners and attached identity
    /// policies, read by the authorization middleware on every S3 request.
    /// Invalidated locally when this gateway changes any of them.
    pub policy_cache: crate::authz::AuthzCache,
    pub scatter_gather: ScatterGatherEngine,
    /// SSE-S3 master key for wrapping per-object DEKs. `None` when
    /// no master key was configured — PUTs targeting buckets with
    /// default encryption will fail in that case.
    pub master_key: Option<objectio_kms::MasterKey>,
    /// KMS provider used by SSE-KMS PUT/GET paths. Polymorphic so the same
    /// code handles local, Vault, and AWS KMS backends identically.
    ///
    /// Held behind a `RwLock` so `PUT /_admin/kms/config` can hot-swap the
    /// backend without restarting the gateway. Accessors below clone the
    /// inner `Arc` out of the lock before any async call so the lock is
    /// never held across an `await`.
    pub kms: parking_lot::RwLock<Option<Arc<dyn objectio_kms::KmsProvider>>>,
    /// Concrete handle to the local KMS provider (only when backend=local).
    /// Used by `/_admin/kms/*` key-management endpoints. External backends
    /// leave this `None` and those endpoints return `NotImplemented`.
    pub kms_local: parking_lot::RwLock<Option<Arc<crate::kms::LocalKmsProvider>>>,
    /// The gateway's own failure-domain position. Drives locality-aware
    /// read routing (Phase 2): shards on OSDs that share enclosing levels
    /// are tried first. Fully-empty when not configured — routing then
    /// falls back to round-robin and this struct is inert.
    pub self_topology: objectio_placement::FailureDomainInfo,
    /// Platform-specific host lifecycle. `NoopHostProvider` by default;
    /// a k8s / ssh / appliance provider gets wired in via `--host-provider`
    /// at startup. Behind an `Arc<dyn>` so handlers can clone into async
    /// tasks without bound-lifetime issues.
    pub host_provider: Arc<dyn crate::host_provider::HostProvider>,
    /// When set, buckets with no recorded owner stay readable/writable by any
    /// authenticated caller instead of falling through to a deny. Covers the
    /// window between deploying ownership enforcement and backfilling owners
    /// on buckets created before it existed.
    /// Base URL of a Prometheus that scrapes this cluster. Empty = the
    /// console falls back to scraping /metrics live.
    pub prometheus_url: String,
    /// Transfer Engine and the pools OSDs move shards through, when started
    /// with `--rdma` (feature `rdma`). `None`: every shard goes over gRPC.
    pub rdma: Option<Arc<crate::rdma::GatewayRdma>>,
    /// Objects of at most this many bytes are stored inline in their
    /// ObjectMeta rather than in shards (`--inline-max-size`; 0 = never).
    pub inline_max_size: usize,
    /// The largest shard sent with its object's metadata (B21); 0: never.
    pub small_shard_max: usize,
    /// Dedup dry-run queue (objectio-docs `architecture/design/core/dedup.md`).
    pub dedup: crate::dedup::DryRun,
    /// Proxies whose `X-Forwarded-For` names the client (`aws:SourceIp`).
    pub trusted_proxies: crate::origin::TrustedProxies,
    /// The SigV4 layer's state, for the admin API to drop cached
    /// credentials it has just changed.
    pub auth_state: Arc<crate::auth_middleware::AuthState>,
    /// The audit stream, for the admin API to reload after a change.
    pub auditor: Arc<crate::audit::Auditor>,
    /// Pack records of packed objects, for reads.
    pub pack_cache: crate::packs::PackCache,
    /// Bucket replication: caches, the fast-path queue, the backlog.
    pub replication: crate::replication::Replication,
}

impl AppState {
    /// Snapshot of the current KMS provider for polymorphic SSE use.
    /// Returns an owned `Arc` so the caller can `.await` without holding
    /// the internal lock.
    pub fn kms(&self) -> Option<Arc<dyn objectio_kms::KmsProvider>> {
        self.kms.read().clone()
    }

    /// Snapshot of the current local KMS provider (for admin endpoints).
    pub fn kms_local(&self) -> Option<Arc<crate::kms::LocalKmsProvider>> {
        self.kms_local.read().clone()
    }

    /// Atomic swap — used by `PUT /_admin/kms/config` and at startup.
    /// Both fields are updated under the same lock order so external SSE
    /// paths always see a consistent pair.
    pub fn set_kms(
        &self,
        kms: Option<Arc<dyn objectio_kms::KmsProvider>>,
        kms_local: Option<Arc<crate::kms::LocalKmsProvider>>,
    ) {
        *self.kms.write() = kms;
        *self.kms_local.write() = kms_local;
    }
}

/// Buckets whose objects are read by query engines (Iceberg, Delta Sharing),
/// which can't pass SSE-C headers on every read. Hard-block SSE-C writes
/// here rather than letting data land that's later unreadable.
///
/// Iceberg warehouses are auto-provisioned as `iceberg-<name>` by the
/// `iceberg_create_warehouse` path in meta — that prefix is the canonical
/// marker for a warehouse bucket.
fn is_warehouse_bucket(bucket: &str) -> bool {
    bucket.starts_with("iceberg-")
}

/// Extract user metadata from request headers (x-amz-meta-* headers)
/// An admin API error body: `{"error": message}`, escaped properly. These
/// were built with `format!`, which made invalid JSON of a message holding a
/// quote, and carried tonic's whole status rather than its message.
fn admin_error_json(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

/// The standard headers an object keeps and serves back, as S3 does. They
/// ride in `user_metadata` under this prefix (a space can't be in a header
/// name, so no `x-amz-meta-` key can collide) and are served under their own
/// names.
pub(crate) const STORED_HEADER_PREFIX: &str = "objectio header ";
const STORED_HEADERS: [&str; 5] = [
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "expires",
];

fn extract_user_metadata(headers: &HeaderMap) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    for name in STORED_HEADERS {
        if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
            metadata.insert(format!("{STORED_HEADER_PREFIX}{name}"), v.to_string());
        }
    }
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if let Some(key) = name_str.strip_prefix("x-amz-meta-") {
            metadata.insert(key.to_string(), crate::auth_middleware::header_text(value));
        }
    }
    metadata
}

/// Add user metadata headers to response builder
fn add_metadata_headers(
    mut builder: http::response::Builder,
    user_metadata: &HashMap<String, String>,
) -> http::response::Builder {
    for (key, value) in user_metadata {
        if let Some(standard) = key.strip_prefix(STORED_HEADER_PREFIX) {
            if STORED_HEADERS.contains(&standard)
                && let Ok(v) = http::HeaderValue::from_str(value)
            {
                builder = builder.header(standard, v);
            }
            continue;
        }
        // Only what makes a valid header: one that doesn't would fail the
        // whole response (a panic, the connection dropped) for every read
        // of the object.
        let name = format!("x-amz-meta-{key}");
        if http::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
            continue;
        }
        if value.is_ascii() {
            if let Ok(v) = http::HeaderValue::from_str(value) {
                builder = builder.header(name, v);
            }
        } else if !value.chars().any(char::is_control) {
            // Non-ASCII goes out as AWS sends it: RFC 2047, UTF-8, base64.
            let encoded = format!(
                "=?UTF-8?B?{}?=",
                base64::engine::general_purpose::STANDARD.encode(value)
            );
            builder = builder.header(name, encoded);
        }
    }
    builder
}

// ── Object tagging ───────────────────────────────────────────────────────────

/// S3 sub-resources this gateway doesn't implement. Without this a request
/// naming one fell through to the plain request: `GET /b?website` answered
/// with the bucket's listing, `PUT /b?notification` tried to create the bucket.
const UNSUPPORTED_SUBRESOURCES: [&str; 11] = [
    "website",
    "notification",
    "inventory",
    "analytics",
    "metrics",
    "intelligent-tiering",
    "accelerate",
    "requestPayment",
    "restore",
    "select",
    "torrent",
];

/// Refuse a request naming an unimplemented sub-resource: `501
/// NotImplemented`, said plainly, rather than doing something else.
pub async fn unsupported_subresource_layer(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if request.method() == Method::DELETE
        && let Some(refused) = delete_refusal(request.uri().path(), request.uri().query())
    {
        return refused;
    }
    let named = request.uri().query().and_then(|q| {
        q.split('&').find_map(|pair| {
            let name = pair.split('=').next().unwrap_or_default();
            // Logging is a bucket's (`crate::bucket_logging`), not an object's.
            let object_logging = name == "logging"
                && request
                    .uri()
                    .path()
                    .trim_start_matches('/')
                    .split_once('/')
                    .is_some_and(|(_, key)| !key.is_empty());
            (UNSUPPORTED_SUBRESOURCES.contains(&name) || object_logging).then(|| name.to_string())
        })
    });
    match named {
        // `/health`, `/` and the like name no bucket and never get here with
        // a sub-resource; S3 paths do.
        Some(name) if request.uri().path() != "/" => S3Error::xml_response(
            "NotImplemented",
            &format!("The {name} sub-resource is not implemented"),
            StatusCode::NOT_IMPLEMENTED,
        ),
        _ => next.run(request).await,
    }
}

// ── Bucket tagging ───────────────────────────────────────────────────────────

/// The response when a call to meta failed: 503 (retryable: S3 clients try
/// again) when meta couldn't be reached or answer in time — a meta node
/// lost, an election under way — and 500 otherwise.
pub(crate) fn meta_failure(e: &tonic::Status, what: &str) -> Response {
    if S3Error::is_unavailable(e) {
        S3Error::xml_response(
            "ServiceUnavailable",
            &format!("{what}: the metadata service is unavailable; retry"),
            StatusCode::SERVICE_UNAVAILABLE,
        )
    } else {
        S3Error::xml_response(
            "InternalError",
            &format!("{what}: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }
}

pub(crate) fn build_s3_arn(bucket: &str, key: Option<&str>) -> String {
    match key {
        Some(k) => format!("arn:obio:s3:::{}/{}", bucket, k),
        None => format!("arn:obio:s3:::{}", bucket),
    }
}

// XML response types for S3 API

// ============================================================================
// Multipart Upload XML Types
// ============================================================================

// ============================================================================
// DeleteObjects XML Types
// ============================================================================

/// Shards of a k+m stripe that must be on disk before a write is
/// acknowledged: k+1, or all of them when there is no parity.
///
/// k is enough to read the stripe back, but an object acknowledged with
/// exactly k has no redundancy left: one more failure loses it. One spare
/// shard means a write still succeeds with an OSD down, and what it stores
/// survives one further failure until the repairer restores the rest.
const fn write_quorum(ec_k: u32, ec_m: u32) -> usize {
    let k = ec_k as usize;
    if ec_m == 0 { k } else { k + 1 }
}

/// Replicas that must be written before a replicated write is
/// acknowledged: two — the copy and a spare — or one in a pool that keeps
/// only one. Same reasoning as [`write_quorum`].
const fn replica_quorum(replicas: usize) -> usize {
    if replicas < 2 { replicas } else { 2 }
}

// ── ACLs: bucket owner enforced ──────────────────────────────────────────
//
// As AWS has it by default since 2023 (Object Ownership "BucketOwnerEnforced"):
// the bucket's owner owns every object in it with FULL_CONTROL, ACLs are
// read-only in effect, and access is granted by IAM and bucket policies
// only. An ACL that says just that is accepted (it changes nothing); any
// other is refused, so no request can make data public through an ACL.

/// Health check endpoint (GET /health)
pub async fn health_check() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"status":"healthy"}"#))
        .unwrap()
}

// ============================================================================
// Bucket Policy Operations (internal implementations)
// ============================================================================

// ============================================================================
// Multipart Upload Operations
// ============================================================================

/// POST /{bucket}/{key}?uploads - Initiate multipart upload
/// POST /{bucket}/{key}?uploadId=X - Complete multipart upload
/// POST /{bucket}/{key}?grep - Gateway-side regex grep; streams NDJSON
pub async fn post_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<PostObjectParams>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if params.uploads.is_some() {
        // Initiate multipart upload
        initiate_multipart_upload_internal(state, bucket, key, &headers, &auth).await
    } else if let Some(upload_id) = params.upload_id {
        // Complete multipart upload
        complete_multipart_upload_internal(state, bucket, key, upload_id, body, &headers).await
    } else if params.grep.is_some() {
        grep_object_internal(state, bucket, key, auth, headers, body).await
    } else {
        S3Error::xml_response(
            "InvalidRequest",
            "POST request must include ?uploads, ?uploadId, or ?grep parameter",
            StatusCode::BAD_REQUEST,
        )
    }
}

// ============================================================================
// Bucket Versioning
// ============================================================================

// ============================================================================
// Object Lock Configuration
// ============================================================================

// ============================================================================
// Bucket Default Server-Side Encryption
// ============================================================================

// ============================================================================
// Object Retention & Legal Hold
// ============================================================================

// ============================================================================
// List Object Versions
// ============================================================================

/// The OSDs `nodes` (a placement) puts an ObjectMeta on, by position: what
/// meta records as the key's home when the write lands.
fn home_of(nodes: &[objectio_proto::metadata::NodePlacement]) -> Vec<Vec<u8>> {
    nodes.iter().map(|n| n.node_id.clone()).collect()
}

/// Helper to get the primary OSD placement for an object
pub(crate) async fn get_placement_nodes_for_object(
    state: &AppState,
    bucket: &str,
    key: &str,
) -> Result<Vec<objectio_proto::metadata::NodePlacement>, Response> {
    let mut client = state.meta_client.clone();
    match client
        .get_placement(GetPlacementRequest {
            // The key alone: meta places "bucket/key". This passed
            // "bucket/key", so tagging, retention and legal hold went to the
            // OSDs of "bucket/bucket/key" while GET read the object's own.
            key: key.to_string(),
            bucket: bucket.to_string(),
            size: 0,
            storage_class: String::new(),
        })
        .await
    {
        Ok(resp) => {
            let placement = resp.into_inner();
            if placement.nodes.is_empty() {
                Err(S3Error::xml_response(
                    "InternalError",
                    "No OSD nodes available",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            } else {
                Ok(placement.nodes)
            }
        }
        Err(e) => {
            error!("Failed to get placement: {}", e);
            Err(meta_failure(&e, "Failed to get placement"))
        }
    }
}

// ============================================================================
// Admin API - IAM Operations
// ============================================================================

/// Render a `KeyOperation` proto value for API responses.
fn operation_label(operation: i32) -> String {
    if operation == ProtoKeyOperation::KeyOpRead as i32 {
        "READ".to_string()
    } else {
        "READ_WRITE".to_string()
    }
}

#[cfg(test)]
mod s3_tests {
    use super::{
        ByteRange, CompleteMultipartUploadXml, DeleteObjectsRequest, ListBucketResult,
        ObjectContent, Owner, S3Error, StripeMeta, add_metadata_headers, build_s3_arn,
        extract_user_metadata, is_warehouse_bucket, overlapping_stripes, parse_range_header,
        parse_sse_c_headers, sse_condition_vars, timestamp_to_http_date, timestamp_to_iso, to_xml,
    };
    use http::{HeaderMap, HeaderName, HeaderValue};

    /// A null version (or null delete marker) made after a versioned one in
    /// the same second is the newer: it is timed by its UUIDv7 object id,
    /// not by `modified_at`, which only has seconds.
    #[test]
    fn a_null_version_made_later_in_the_same_second_sorts_newer() {
        use objectio_proto::metadata::ObjectMeta;
        let versioned = ObjectMeta {
            version_id: uuid::Uuid::now_v7().to_string(),
            object_id: uuid::Uuid::now_v7().as_bytes().to_vec(),
            modified_at: 1000,
            ..Default::default()
        };
        std::thread::sleep(std::time::Duration::from_millis(3));
        let null_marker = ObjectMeta {
            version_id: String::new(),
            object_id: uuid::Uuid::now_v7().as_bytes().to_vec(),
            is_delete_marker: true,
            modified_at: 1000,
            ..Default::default()
        };
        let mut versions = vec![versioned, null_marker];
        super::sort_versions(&mut versions);
        assert!(
            versions[0].version_id.is_empty(),
            "the null marker is the latest"
        );
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).expect("header name"),
                HeaderValue::from_str(v).expect("header value"),
            );
        }
        h
    }

    fn range(header: &str, size: u64) -> Option<(u64, u64)> {
        parse_range_header(header, size).map(|ByteRange { start, end }| (start, end))
    }

    // ── Range header ──────────────────────────────────────────────────────
    //
    // This decides which bytes a GET returns. `None` becomes a 416.

    #[test]
    fn a_closed_range_is_taken_literally() {
        assert_eq!(range("bytes=0-99", 1000), Some((0, 99)));
        assert_eq!(range("bytes=100-199", 1000), Some((100, 199)));
        assert_eq!(range("bytes=0-0", 1000), Some((0, 0)));
        assert_eq!(range("bytes=999-999", 1000), Some((999, 999)));
    }

    #[test]
    fn an_open_ended_range_runs_to_the_last_byte() {
        assert_eq!(range("bytes=100-", 1000), Some((100, 999)));
        assert_eq!(range("bytes=0-", 1000), Some((0, 999)));
        assert_eq!(range("bytes=999-", 1000), Some((999, 999)));
    }

    #[test]
    fn a_suffix_range_counts_back_from_the_end() {
        assert_eq!(range("bytes=-50", 1000), Some((950, 999)));
        assert_eq!(range("bytes=-1", 1000), Some((999, 999)));
        assert_eq!(range("bytes=-1000", 1000), Some((0, 999)));
    }

    #[test]
    fn a_suffix_longer_than_the_object_is_the_whole_object() {
        assert_eq!(range("bytes=-5000", 1000), Some((0, 999)));
    }

    #[test]
    fn an_end_past_the_object_is_clamped_rather_than_refused() {
        // A client that asks for more than there is gets what there is; S3
        // answers 206 with a short body, not 416.
        assert_eq!(range("bytes=0-99999", 1000), Some((0, 999)));
        assert_eq!(range("bytes=500-99999", 1000), Some((500, 999)));
    }

    /// A range over an empty object must not underflow.
    ///
    /// Every branch computes `total_size - 1`, and the suffix branch reached
    /// that with `total_size == 0`: `Range: bytes=-5` on a zero-byte object
    /// panicked on the subtraction in a debug build and produced a range
    /// ending at `u64::MAX` in a release one. A zero-byte object is something
    /// any client can create, so this was reachable by anyone who could PUT.
    #[test]
    fn no_range_over_an_empty_object_is_satisfiable() {
        for header in [
            "bytes=-5",
            "bytes=0-0",
            "bytes=0-",
            "bytes=-1",
            "bytes=0-10",
        ] {
            assert_eq!(
                range(header, 0),
                None,
                "{header} on a zero-byte object should be unsatisfiable"
            );
        }
    }

    /// `bytes=-0` asks for the last zero bytes, which RFC 7233 calls
    /// unsatisfiable. It used to answer with the entire object.
    #[test]
    fn a_zero_length_suffix_is_unsatisfiable() {
        assert_eq!(range("bytes=-0", 1000), None);
    }

    #[test]
    fn a_range_starting_past_the_end_is_refused() {
        assert_eq!(range("bytes=1000-1099", 1000), None);
        assert_eq!(range("bytes=1000-", 1000), None);
        assert_eq!(range("bytes=5000-6000", 1000), None);
    }

    #[test]
    fn a_backwards_range_is_refused() {
        assert_eq!(range("bytes=99-0", 1000), None);
    }

    #[test]
    fn a_unit_other_than_bytes_is_refused() {
        // Refusing is right: honouring it as bytes would return the wrong
        // region for a client that meant something else.
        for header in ["items=0-99", "0-99", "seconds=0-99", ""] {
            assert_eq!(range(header, 1000), None, "{header:?} was accepted");
        }
    }

    #[test]
    fn malformed_ranges_are_refused_rather_than_guessed_at() {
        for header in [
            "bytes=",
            "bytes=-",
            "bytes=abc-def",
            "bytes=0-99-199",
            "bytes=0-99,200-299",
            "bytes=--5",
        ] {
            assert_eq!(range(header, 1000), None, "{header:?} was accepted");
        }
    }

    #[test]
    fn surrounding_whitespace_in_the_header_is_tolerated() {
        assert_eq!(range("  bytes=0-99  ", 1000), Some((0, 99)));
        assert_eq!(range("bytes= 0 - 99 ", 1000), Some((0, 99)));
    }

    // ── Stripe selection ──────────────────────────────────────────────────

    fn stripes(sizes: &[u64]) -> Vec<StripeMeta> {
        sizes
            .iter()
            .enumerate()
            .map(|(i, &data_size)| StripeMeta {
                stripe_id: i as u64,
                data_size,
                ..Default::default()
            })
            .collect()
    }

    /// A range must fetch every stripe it touches and nothing else.
    ///
    /// Fetching too few truncates the response; fetching too many costs a
    /// round trip to an OSD per extra stripe on every ranged read.
    #[test]
    fn a_range_inside_one_stripe_fetches_only_that_stripe() {
        let s = stripes(&[100, 100, 100]);
        let picked = overlapping_stripes(
            &s,
            &ByteRange {
                start: 120,
                end: 180,
            },
        );
        assert_eq!(picked, vec![(1, 100)]);
    }

    #[test]
    fn a_range_spanning_stripes_fetches_each_of_them_with_its_offset() {
        let s = stripes(&[100, 100, 100]);
        // The second element of each pair is the stripe's absolute start, which
        // is how the caller slices the right bytes out of it.
        assert_eq!(
            overlapping_stripes(
                &s,
                &ByteRange {
                    start: 50,
                    end: 250
                }
            ),
            vec![(0, 0), (1, 100), (2, 200)]
        );
    }

    #[test]
    fn a_boundary_range_does_not_pull_in_the_neighbour() {
        let s = stripes(&[100, 100, 100]);
        // Ends on the last byte of stripe 0.
        assert_eq!(
            overlapping_stripes(&s, &ByteRange { start: 0, end: 99 }),
            vec![(0, 0)]
        );
        // Starts on the first byte of stripe 1.
        assert_eq!(
            overlapping_stripes(
                &s,
                &ByteRange {
                    start: 100,
                    end: 199
                }
            ),
            vec![(1, 100)]
        );
    }

    #[test]
    fn the_whole_object_fetches_every_stripe() {
        let s = stripes(&[100, 100, 100]);
        assert_eq!(
            overlapping_stripes(&s, &ByteRange { start: 0, end: 299 }),
            vec![(0, 0), (1, 100), (2, 200)]
        );
    }

    #[test]
    fn stripes_of_uneven_size_still_report_their_true_offsets() {
        let s = stripes(&[10, 250, 40]);
        assert_eq!(
            overlapping_stripes(&s, &ByteRange { start: 5, end: 265 }),
            vec![(0, 0), (1, 10), (2, 260)]
        );
    }

    // ── User metadata ─────────────────────────────────────────────────────

    #[test]
    fn user_metadata_is_stored_without_its_prefix() {
        let m = extract_user_metadata(&headers(&[
            ("x-amz-meta-author", "yash"),
            ("x-amz-meta-project", "objectio"),
        ]));
        assert_eq!(m.get("author").map(String::as_str), Some("yash"));
        assert_eq!(m.get("project").map(String::as_str), Some("objectio"));
    }

    #[test]
    fn header_names_are_matched_case_insensitively() {
        // HTTP header names are case-insensitive and clients send every
        // variant; a case-sensitive match would silently drop metadata.
        let m = extract_user_metadata(&headers(&[("X-Amz-Meta-Author", "yash")]));
        assert_eq!(m.get("author").map(String::as_str), Some("yash"));
    }

    #[test]
    fn headers_that_are_not_user_metadata_are_left_out() {
        let m = extract_user_metadata(&headers(&[
            ("content-type", "text/plain"),
            ("x-amz-date", "20260917T000000Z"),
            ("x-amz-server-side-encryption", "AES256"),
            ("x-amz-meta-keep", "yes"),
        ]));
        assert_eq!(m.len(), 1);
        assert!(m.contains_key("keep"));
    }

    #[test]
    fn tags_survive_encoding_into_a_header_and_back() {
        let mut t = std::collections::HashMap::new();
        t.insert("team".to_string(), "ml & data".to_string());
        t.insert("a=b".to_string(), "c+d/é".to_string());
        assert_eq!(
            super::parse_tagging(&super::encode_tagging(&t)).ok(),
            Some(t)
        );
    }

    #[test]
    fn a_plus_in_a_tagging_header_is_a_space() {
        let t = super::parse_tagging("k=a+b").ok().unwrap();
        assert_eq!(t["k"], "a b");
    }

    #[test]
    fn metadata_survives_a_round_trip_back_onto_a_response() {
        let m = extract_user_metadata(&headers(&[("x-amz-meta-author", "yash")]));
        let built = add_metadata_headers(http::Response::builder(), &m)
            .body(())
            .expect("response");
        assert_eq!(
            built.headers().get("x-amz-meta-author").unwrap(),
            "yash",
            "metadata did not come back out on the response"
        );
    }

    // ── SSE-C ─────────────────────────────────────────────────────────────

    /// A 32-byte key and the base64 of its MD5, which is the binding the
    /// gateway checks.
    fn sse_c_headers(key: &[u8; 32], md5_of: &[u8]) -> HeaderMap {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        headers(&[
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            (
                "x-amz-server-side-encryption-customer-key",
                &b64.encode(key),
            ),
            (
                "x-amz-server-side-encryption-customer-key-md5",
                &b64.encode(crate::digest::md5(md5_of)),
            ),
        ])
    }

    #[test]
    fn a_request_with_no_sse_c_headers_carries_no_key() {
        assert!(
            parse_sse_c_headers(&HeaderMap::new())
                .expect("no headers is not an error")
                .is_none()
        );
    }

    #[test]
    fn a_complete_and_consistent_sse_c_triple_is_accepted() {
        let key = [7u8; 32];
        let parsed = parse_sse_c_headers(&sse_c_headers(&key, &key))
            .expect("valid triple")
            .expect("a key");
        assert_eq!(parsed.key, key);
    }

    /// Two of the three headers must not be accepted.
    ///
    /// Accepting a key with no MD5 would drop the binding that catches a
    /// corrupted key header; accepting an MD5 with no key would leave the
    /// object unencrypted while the client believed otherwise.
    #[test]
    fn a_partial_sse_c_triple_is_refused() {
        let key = [7u8; 32];
        let full = sse_c_headers(&key, &key);
        for omit in [
            "x-amz-server-side-encryption-customer-algorithm",
            "x-amz-server-side-encryption-customer-key",
            "x-amz-server-side-encryption-customer-key-md5",
        ] {
            let mut h = full.clone();
            h.remove(omit);
            assert!(
                parse_sse_c_headers(&h).is_err(),
                "SSE-C was accepted without {omit}"
            );
        }
    }

    /// The MD5 binds the key to the request.
    ///
    /// Without the check a corrupted key header decrypts to garbage on GET
    /// with no error anywhere — the client gets bytes that are not its data.
    #[test]
    fn an_md5_that_does_not_match_the_key_is_refused() {
        let key = [7u8; 32];
        let wrong = [8u8; 32];
        assert!(
            parse_sse_c_headers(&sse_c_headers(&key, &wrong)).is_err(),
            "a key whose MD5 belongs to a different key was accepted"
        );
    }

    #[test]
    fn an_algorithm_other_than_aes256_is_refused() {
        let key = [7u8; 32];
        let mut h = sse_c_headers(&key, &key);
        h.insert(
            "x-amz-server-side-encryption-customer-algorithm",
            HeaderValue::from_static("AES128"),
        );
        assert!(parse_sse_c_headers(&h).is_err());
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let short = [7u8; 16];
        let mut h = sse_c_headers(&[7u8; 32], &[7u8; 32]);
        h.insert(
            "x-amz-server-side-encryption-customer-key",
            HeaderValue::from_str(&b64.encode(short)).unwrap(),
        );
        h.insert(
            "x-amz-server-side-encryption-customer-key-md5",
            HeaderValue::from_str(&b64.encode(crate::digest::md5(&short[..]))).unwrap(),
        );
        assert!(
            parse_sse_c_headers(&h).is_err(),
            "a 16-byte customer key was accepted for AES-256"
        );
    }

    #[test]
    fn a_key_that_is_not_base64_is_refused() {
        let mut h = sse_c_headers(&[7u8; 32], &[7u8; 32]);
        h.insert(
            "x-amz-server-side-encryption-customer-key",
            HeaderValue::from_static("not base64!!"),
        );
        assert!(parse_sse_c_headers(&h).is_err());
    }

    // ── Policy condition variables ────────────────────────────────────────

    #[test]
    fn sse_headers_become_the_condition_keys_a_bucket_policy_reads() {
        // A policy that denies unsealed PUTs matches on these names exactly.
        let vars = sse_condition_vars(Some(&headers(&[
            ("x-amz-server-side-encryption", "aws:kms"),
            ("x-amz-server-side-encryption-aws-kms-key-id", "key-1"),
        ])));
        assert_eq!(
            vars.get("s3:x-amz-server-side-encryption")
                .map(String::as_str),
            Some("aws:kms")
        );
        assert_eq!(
            vars.get("s3:x-amz-server-side-encryption-aws-kms-key-id")
                .map(String::as_str),
            Some("key-1")
        );
    }

    #[test]
    fn a_request_with_no_sse_headers_sets_no_sse_condition_keys() {
        let vars = sse_condition_vars(Some(&HeaderMap::new()));
        assert!(!vars.contains_key("s3:x-amz-server-side-encryption"));
        // Absent must stay absent: a policy that denies on a value would
        // otherwise match an empty string and refuse every plain PUT.
        // Secure only when the proxy in front says the client used HTTPS.
        assert_eq!(
            vars.get("aws:SecureTransport").map(String::as_str),
            Some("false")
        );
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(
            sse_condition_vars(Some(&h))
                .get("aws:SecureTransport")
                .map(String::as_str),
            Some("true")
        );
    }

    // ── ARNs ──────────────────────────────────────────────────────────────

    #[test]
    fn an_arn_names_a_bucket_or_an_object_within_it() {
        assert_eq!(build_s3_arn("b", None), "arn:obio:s3:::b");
        assert_eq!(build_s3_arn("b", Some("k.txt")), "arn:obio:s3:::b/k.txt");
        assert_eq!(
            build_s3_arn("b", Some("nested/deep/k.txt")),
            "arn:obio:s3:::b/nested/deep/k.txt"
        );
    }

    #[test]
    fn only_the_iceberg_prefix_marks_a_warehouse_bucket() {
        assert!(is_warehouse_bucket("iceberg-analytics"));
        assert!(!is_warehouse_bucket("analytics"));
        assert!(!is_warehouse_bucket("my-iceberg-data"));
    }

    // ── XML the client sends ──────────────────────────────────────────────

    #[test]
    fn a_completion_body_yields_its_parts_in_order() {
        let body = "<CompleteMultipartUpload>\
            <Part><PartNumber>1</PartNumber><ETag>\"a\"</ETag></Part>\
            <Part><PartNumber>2</PartNumber><ETag>\"b\"</ETag></Part>\
            </CompleteMultipartUpload>";
        let parsed: CompleteMultipartUploadXml = quick_xml::de::from_str(body).expect("parse");
        assert_eq!(parsed.parts.len(), 2);
        assert_eq!(parsed.parts[0].part_number, 1);
        assert_eq!(parsed.parts[1].etag, "\"b\"");
    }

    #[test]
    fn a_completion_body_with_no_parts_parses_to_an_empty_list() {
        let parsed: CompleteMultipartUploadXml =
            quick_xml::de::from_str("<CompleteMultipartUpload></CompleteMultipartUpload>")
                .expect("parse");
        assert!(parsed.parts.is_empty());
    }

    #[test]
    fn a_batch_delete_body_yields_its_keys() {
        let body = "<Delete><Quiet>true</Quiet>\
            <Object><Key>a.txt</Key></Object>\
            <Object><Key>b.txt</Key><VersionId>v2</VersionId></Object>\
            </Delete>";
        let parsed = DeleteObjectsRequest::parse(body.as_bytes()).expect("parse");
        assert!(parsed.quiet);
        assert_eq!(parsed.objects.len(), 2);
        assert_eq!(parsed.objects[0].key, "a.txt");
        assert_eq!(parsed.objects[0].version_id, None);
        assert_eq!(parsed.objects[1].version_id.as_deref(), Some("v2"));
    }

    /// A key is exactly what was sent: spaces at either end are part of it.
    #[test]
    fn a_batch_delete_keeps_keys_with_spaces_as_sent() {
        let body = "<Delete><Object><Key> </Key></Object>\
            <Object><Key>_ </Key></Object><Object><Key> a&amp;b </Key></Object></Delete>";
        let parsed = DeleteObjectsRequest::parse(body.as_bytes()).expect("parse");
        let keys: Vec<&str> = parsed.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, [" ", "_ ", " a&b "]);
        assert!(!parsed.quiet);
    }

    // ── XML the gateway sends ─────────────────────────────────────────────

    /// An object key is whatever the client named it, and it ends up inside a
    /// listing's XML. If `<` and `&` are not escaped the listing stops being
    /// parseable — and a key could close a tag and inject elements of its own.
    #[test]
    fn a_key_containing_markup_is_escaped_in_a_listing() {
        let result = ListBucketResult {
            name: "b".to_string(),
            prefix: String::new(),
            delimiter: None,
            marker: None,
            next_marker: None,
            start_after: None,
            continuation_token: None,
            encoding_type: None,
            max_keys: 1000,
            key_count: Some(1),
            is_truncated: false,
            next_continuation_token: None,
            common_prefixes: Vec::new(),
            contents: vec![ObjectContent {
                key: "a<b>&c\"d'e.txt".to_string(),
                last_modified: "1970-01-01T00:00:00.000Z".to_string(),
                etag: "\"x\"".to_string(),
                size: 1,
                storage_class: "STANDARD".to_string(),
                owner: None,
            }],
        };
        let xml = to_xml(&result).expect("serialize");
        assert!(
            !xml.contains("a<b>"),
            "an object key's markup reached the listing unescaped: {xml}"
        );
        assert!(xml.contains("&lt;"), "expected escaped markup in: {xml}");
        assert!(
            xml.contains("&amp;"),
            "the ampersand in a key was not escaped: {xml}"
        );
    }

    /// Error messages interpolate things the caller supplied.
    #[test]
    fn an_error_message_containing_markup_is_escaped() {
        let err = S3Error {
            code: "InvalidArgument".to_string(),
            message: "bad key: </Message><Injected>x</Injected>".to_string(),
            resource: None,
            request_id: "req-1".to_string(),
        };
        let xml = to_xml(&err).expect("serialize");
        assert!(
            !xml.contains("<Injected>"),
            "an error message closed its own tag: {xml}"
        );
    }

    // ── Timestamps ────────────────────────────────────────────────────────

    #[test]
    fn iso_timestamps_are_the_shape_clients_parse() {
        assert_eq!(timestamp_to_iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(timestamp_to_iso(1_700_000_000), "2023-11-14T22:13:20.000Z");
    }

    #[test]
    fn http_dates_are_rfc_7231_shaped() {
        assert_eq!(
            timestamp_to_http_date(784_111_777),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(timestamp_to_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    /// A timestamp chrono cannot represent falls back to the epoch rather than
    /// panicking or emitting something a client cannot parse.
    #[test]
    fn an_impossible_timestamp_degrades_to_the_epoch() {
        assert_eq!(timestamp_to_iso(u64::MAX), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            timestamp_to_http_date(u64::MAX),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
    }

    #[test]
    fn an_owner_renders_inside_a_listing() {
        let xml = to_xml(&Owner {
            id: "u-1".to_string(),
            display_name: "yash".to_string(),
        })
        .expect("serialize");
        assert!(xml.contains("u-1") && xml.contains("yash"), "{xml}");
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    /// A meta leader change reaches the client as 503, which S3 clients
    /// retry, not 500.
    #[test]
    fn an_unavailable_meta_is_service_unavailable() {
        for e in [
            tonic::Status::unavailable("forwarding to the raft leader failed; retry"),
            tonic::Status::deadline_exceeded("slow"),
            tonic::Status::unknown("transport error"),
            tonic::Status::cancelled("Timeout expired"),
        ] {
            assert_eq!(
                S3Error::from_status(&e).status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        for e in [
            tonic::Status::internal("bug"),
            tonic::Status::unknown("something else"),
        ] {
            assert_eq!(
                S3Error::from_status(&e).status(),
                StatusCode::INTERNAL_SERVER_ERROR
            );
        }
    }
}

#[cfg(test)]
mod list_uploads_tests {
    use super::*;

    fn parse_params(query: &str) -> ListObjectsParams {
        let uri: axum::http::Uri = format!("/ws1?{query}").parse().expect("valid uri");
        let Query(params) =
            Query::<ListObjectsParams>::try_from_uri(&uri).expect("query should deserialize");
        params
    }

    #[test]
    fn uploads_flag_is_parsed_from_empty_value() {
        // geesefs sends a bare `?uploads=` at mount; the empty value
        // must still register as "this is ListMultipartUploads".
        let params = parse_params("uploads=");
        assert!(params.uploads.is_some());
    }

    #[test]
    fn uploads_pagination_markers_are_parsed() {
        let params = parse_params(
            "uploads=&prefix=users%2Fys%2F&key-marker=a&upload-id-marker=u1&max-uploads=42",
        );
        assert!(params.uploads.is_some());
        assert_eq!(params.prefix.as_deref(), Some("users/ys/"));
        assert_eq!(params.key_marker.as_deref(), Some("a"));
        assert_eq!(params.upload_id_marker.as_deref(), Some("u1"));
        assert_eq!(params.max_uploads, Some(42));
    }

    #[test]
    fn plain_listing_query_does_not_trigger_uploads() {
        let params = parse_params("prefix=uploads%2F&max-keys=10");
        assert!(params.uploads.is_none());
    }

    #[test]
    fn truncated_result_carries_key_markers_not_continuation_token() {
        // The hang was a truncated ListBucketResult answering ?uploads:
        // its NextContinuationToken is not a key marker, so the client
        // could never advance. A truncated LMU response must expose
        // NextKeyMarker/NextUploadIdMarker instead.
        let result = ListMultipartUploadsResult {
            bucket: "ws1".into(),
            key_marker: String::new(),
            upload_id_marker: String::new(),
            next_key_marker: Some("users/ys/big.bin".into()),
            next_upload_id_marker: Some("upload-7".into()),
            delimiter: None,
            prefix: String::new(),
            max_uploads: 1000,
            is_truncated: true,
            uploads: vec![UploadItem {
                key: "users/ys/big.bin".into(),
                upload_id: "upload-7".into(),
                initiated: "2026-09-09T00:00:00.000Z".into(),
                storage_class: "STANDARD".into(),
            }],
        };

        let xml = to_xml(&result).expect("result should serialize");
        assert!(xml.contains("<ListMultipartUploadsResult>"));
        assert!(xml.contains("<NextKeyMarker>users/ys/big.bin</NextKeyMarker>"));
        assert!(xml.contains("<NextUploadIdMarker>upload-7</NextUploadIdMarker>"));
        assert!(!xml.contains("NextContinuationToken"));
        assert!(!xml.contains("ListBucketResult"));
    }

    fn listing(is_truncated: bool, keys: &[&str]) -> ListBucketResult {
        ListBucketResult {
            name: "ws1".into(),
            prefix: String::new(),
            delimiter: None,
            marker: None,
            next_marker: None,
            start_after: None,
            continuation_token: None,
            encoding_type: None,
            max_keys: 100,
            is_truncated,
            next_continuation_token: Some("opaque-token".into()),
            key_count: Some(keys.len() as u32),
            common_prefixes: vec![],
            contents: keys
                .iter()
                .map(|k| ObjectContent {
                    key: (*k).to_string(),
                    last_modified: "2026-09-09T00:00:00.000Z".into(),
                    etag: "\"e\"".into(),
                    size: 1,
                    storage_class: "STANDARD".into(),
                    owner: None,
                })
                .collect(),
        }
    }

    #[test]
    fn v1_pagination_params_are_parsed() {
        // Both were dropped by serde, so a V1 client re-sent the same
        // request forever while IsTruncated stayed true.
        let params = parse_params("max-keys=100&marker=users%2Fys%2Funtitled.chat");
        assert_eq!(params.marker.as_deref(), Some("users/ys/untitled.chat"));
        let params = parse_params("list-type=2&start-after=users%2Fys%2Funtitled.chat");
        assert_eq!(
            params.start_after.as_deref(),
            Some("users/ys/untitled.chat")
        );
        assert_eq!(params.list_type.as_deref(), Some("2"));
    }

    #[test]
    fn v1_truncated_listing_gives_the_client_a_next_marker() {
        let mut result = listing(true, &["a", "b"]);
        apply_listing_version(&mut result, false, Some("prev".into()), None);

        assert_eq!(result.marker.as_deref(), Some("prev"));
        assert_eq!(result.next_marker.as_deref(), Some("b"));
        // V2-only elements must not appear in a V1 body.
        assert!(result.key_count.is_none());
        assert!(result.next_continuation_token.is_none());
        assert!(result.start_after.is_none());

        let xml = to_xml(&result).expect("serialize");
        assert!(xml.contains("<NextMarker>b</NextMarker>"));
        assert!(!xml.contains("KeyCount"));
        assert!(!xml.contains("NextContinuationToken"));
    }

    #[test]
    fn v1_untruncated_listing_has_no_next_marker() {
        let mut result = listing(false, &["a"]);
        apply_listing_version(&mut result, false, None, None);
        assert!(result.next_marker.is_none());
    }

    #[test]
    fn v2_listing_keeps_key_count_and_echoes_start_after() {
        let mut result = listing(true, &["a"]);
        apply_listing_version(&mut result, true, None, Some("a0".into()));

        assert_eq!(result.start_after.as_deref(), Some("a0"));
        assert_eq!(result.key_count, Some(1));
        assert_eq!(
            result.next_continuation_token.as_deref(),
            Some("opaque-token")
        );
        assert!(result.marker.is_none());
        assert!(result.next_marker.is_none());
    }

    #[test]
    fn untruncated_result_omits_next_markers() {
        let result = ListMultipartUploadsResult {
            bucket: "ws1".into(),
            key_marker: String::new(),
            upload_id_marker: String::new(),
            next_key_marker: None,
            next_upload_id_marker: None,
            delimiter: None,
            prefix: String::new(),
            max_uploads: 1000,
            is_truncated: false,
            uploads: vec![],
        };

        let xml = to_xml(&result).expect("result should serialize");
        assert!(xml.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!xml.contains("NextKeyMarker"));
    }
}

#[cfg(test)]
mod commit_tests {
    use super::{Committed, commit_object};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    async fn after(ms: u64, r: Result<(), &'static str>) -> Result<(), &'static str> {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        r
    }

    #[tokio::test]
    async fn the_two_commits_run_at_the_same_time() {
        let start = std::time::Instant::now();
        let r = commit_object(after(200, Ok(())), after(200, Ok(())), || async {}).await;
        assert_eq!(r, Ok(((), Committed::Both)));
        assert!(
            start.elapsed() < Duration::from_millis(350),
            "the commits ran one after the other: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn a_failed_listing_commit_does_not_fail_the_put() {
        let unlisted = AtomicBool::new(false);
        let r = commit_object(after(0, Ok(())), after(0, Err("raft")), || async {
            unlisted.store(true, Ordering::SeqCst);
        })
        .await;
        assert_eq!(r, Ok(((), Committed::Unlisted("raft"))));
        assert!(
            !unlisted.load(Ordering::SeqCst),
            "took a readable object out of the listing"
        );
    }

    #[tokio::test]
    async fn a_failed_object_meta_commit_takes_the_object_out_of_the_listing() {
        let unlisted = AtomicBool::new(false);
        let r: Result<((), Committed<&str>), _> =
            commit_object(after(0, Err("osd")), after(0, Ok(())), || async {
                unlisted.store(true, Ordering::SeqCst);
            })
            .await;
        assert_eq!(r, Err("osd"));
        assert!(
            unlisted.load(Ordering::SeqCst),
            "the listing shows an object GET cannot read"
        );
    }

    #[tokio::test]
    async fn when_both_fail_there_is_nothing_to_take_out() {
        let unlisted = AtomicBool::new(false);
        let r = commit_object(after(0, Err("osd")), after(0, Err("raft")), || async {
            unlisted.store(true, Ordering::SeqCst);
        })
        .await;
        assert_eq!(r, Err("osd"));
        assert!(!unlisted.load(Ordering::SeqCst));
    }
}

#[cfg(test)]
mod write_quorum_tests {
    use super::write_quorum;

    #[test]
    fn a_write_keeps_one_spare_shard() {
        assert_eq!(write_quorum(4, 2), 5);
        assert_eq!(write_quorum(8, 3), 9);
        assert_eq!(write_quorum(2, 1), 3, "with m = 1 that is every shard");
    }

    #[test]
    fn a_replicated_write_keeps_one_spare_copy() {
        use super::replica_quorum;
        assert_eq!(replica_quorum(3), 2);
        assert_eq!(replica_quorum(2), 2);
        assert_eq!(replica_quorum(1), 1);
    }

    #[test]
    fn without_parity_every_shard_is_needed() {
        assert_eq!(write_quorum(1, 0), 1);
        assert_eq!(write_quorum(4, 0), 4);
    }

    #[test]
    fn a_completion_answer_carries_its_checksum() {
        use super::*;
        let cx = ChecksumXml::of(
            Some(&ObjectChecksum {
                algorithm: "SHA256".into(),
                value: "abc=-2".into(),
            }),
            true,
        );
        let r = CompleteMultipartUploadResult {
            location: "l".into(),
            bucket: "b".into(),
            key: "k".into(),
            etag: "e".into(),
            checksum_crc32: cx.crc32,
            checksum_crc32c: cx.crc32c,
            checksum_crc64nvme: cx.crc64nvme,
            checksum_sha1: cx.sha1,
            checksum_sha256: cx.sha256,
            checksum_type: cx.checksum_type,
        };
        let xml = to_xml(&r).expect("a CompleteMultipartUpload answer serializes");
        assert!(
            xml.contains("<ChecksumSHA256>abc=-2</ChecksumSHA256>"),
            "{xml}"
        );
        assert!(
            xml.contains("<ChecksumType>COMPOSITE</ChecksumType>"),
            "{xml}"
        );
    }
}
