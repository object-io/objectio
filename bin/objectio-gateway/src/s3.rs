//! S3 API handlers

/// Maximum shard size in bytes (must fit in a storage block)
/// Block size is 4MB with ~96 bytes overhead, so use 4MB - 4KB for safety margin
const MAX_SHARD_SIZE: usize = 4 * 1024 * 1024 - 4096; // ~4MB per shard

use crate::osd_pool::{
    Displaced, MetaWriteError, OsdPool, PendingShards, Reclaim, ShardTarget,
    delete_object_meta_from_all, delete_version_from_all, get_object_meta_from_any,
    get_object_version_meta_from_any, put_object_meta_to_all, read_shard_from_osd, reclaim_shards,
    reclaimable_after_overwrite, referenced_object_ids, stripe_targets, stripe_targets_of,
    write_shard_to_osd,
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
    DeleteBucketLifecycleRequest,
    DeleteBucketPolicyRequest,
    DeleteBucketRequest,
    DeleteUserRequest,
    ErasureType,
    GetAccessKeyForAuthRequest,
    GetBucketEncryptionRequest,
    GetBucketLifecycleRequest,
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
    LifecycleConfiguration as ProtoLifecycleConfig,
    LifecycleRule as ProtoLifecycleRule,
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
    PutBucketLifecycleRequest,
    PutBucketVersioningRequest,
    PutObjectLockConfigRequest,
    RegisterPartRequest,
    RetentionMode,
    RetentionRule,
    SetBucketPolicyRequest,
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
    pub legacy_open_buckets: bool,
    /// Base URL of a Prometheus that scrapes this cluster. Empty = the
    /// console falls back to scraping /metrics live.
    pub prometheus_url: String,
    /// Transfer Engine and the pools OSDs move shards through, when started
    /// with `--rdma` (feature `rdma`). `None`: every shard goes over gRPC.
    pub rdma: Option<Arc<crate::rdma::GatewayRdma>>,
    /// Objects of at most this many bytes are stored inline in their
    /// ObjectMeta rather than in shards (`--inline-max-size`; 0 = never).
    pub inline_max_size: usize,
    /// Dedup dry-run queue (objectio-docs `architecture/design/dedup.md`).
    pub dedup: crate::dedup::DryRun,
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

/// Decision produced by [`resolve_sse_decision`].
#[derive(Debug, Clone)]
struct SseDecision {
    algorithm: SseAlgorithm,
    /// KMS key id (or ARN) — populated only for `SseKms`.
    kms_key_id: String,
    /// Optional encryption context for SSE-KMS. Bound to the DEK wrap as AEAD.
    encryption_context: HashMap<String, String>,
}

/// Resolve the effective SSE algorithm for an operation.
///
/// Precedence follows AWS: explicit `x-amz-server-side-encryption*` request
/// headers win, else the bucket default encryption, else plaintext.
#[allow(clippy::result_large_err)]
async fn resolve_sse_decision(
    meta_client: &mut MetadataServiceClient<Channel>,
    bucket: &str,
    headers: Option<&HeaderMap>,
) -> Result<Option<SseDecision>, Response> {
    // 1. Request headers.
    if let Some(h) = headers
        && let Some(algo_hdr) = h
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok())
    {
        match algo_hdr {
            "AES256" => {
                return Ok(Some(SseDecision {
                    algorithm: SseAlgorithm::SseS3,
                    kms_key_id: String::new(),
                    encryption_context: HashMap::new(),
                }));
            }
            "aws:kms" => {
                let kms_key_id = h
                    .get("x-amz-server-side-encryption-aws-kms-key-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let encryption_context = parse_encryption_context_header(h)?;
                if kms_key_id.is_empty() {
                    return Err(S3Error::xml_response(
                        "InvalidArgument",
                        "x-amz-server-side-encryption: aws:kms requires x-amz-server-side-encryption-aws-kms-key-id when no bucket default KMS key is configured",
                        StatusCode::BAD_REQUEST,
                    ));
                }
                return Ok(Some(SseDecision {
                    algorithm: SseAlgorithm::SseKms,
                    kms_key_id,
                    encryption_context,
                }));
            }
            other => {
                return Err(S3Error::xml_response(
                    "InvalidArgument",
                    &format!("x-amz-server-side-encryption value '{other}' is not recognized"),
                    StatusCode::BAD_REQUEST,
                ));
            }
        }
    }

    // 2. Bucket default.
    let bucket_enc = match meta_client
        .get_bucket_encryption(GetBucketEncryptionRequest {
            bucket: bucket.to_string(),
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            error!("Failed to fetch bucket encryption for {bucket}: {e}");
            return Err(S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };
    let Some(rule) = bucket_enc.config.and_then(|c| c.rules.into_iter().next()) else {
        return Ok(None);
    };
    let rule_algo = SseAlgorithm::try_from(rule.algorithm).unwrap_or(SseAlgorithm::SseNone);
    match rule_algo {
        SseAlgorithm::SseNone | SseAlgorithm::SseC => Ok(None),
        SseAlgorithm::SseS3 => Ok(Some(SseDecision {
            algorithm: SseAlgorithm::SseS3,
            kms_key_id: String::new(),
            encryption_context: HashMap::new(),
        })),
        SseAlgorithm::SseKms => {
            if rule.kms_key_id.is_empty() {
                return Err(S3Error::xml_response(
                    "InvalidArgument",
                    "Bucket default encryption is aws:kms but has no KMSMasterKeyID",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
            Ok(Some(SseDecision {
                algorithm: SseAlgorithm::SseKms,
                kms_key_id: rule.kms_key_id,
                encryption_context: HashMap::new(),
            }))
        }
    }
}

/// Customer-supplied SSE-C material, validated.
///
/// The raw `key` never touches persistent storage — it lives in memory
/// only for the duration of the request.
struct SseCKey {
    key: [u8; objectio_kms::DEK_LEN],
    /// Base64-encoded MD5 of the raw key, echoed back in response headers.
    md5_b64: String,
}

/// A write's encryption headers that contradict each other: SSE-C with
/// server-side encryption, or a KMS key without `aws:kms`. 400, as S3.
fn sse_header_conflict(headers: &HeaderMap) -> Option<Response> {
    let has = |name: &str| headers.contains_key(name);
    let customer = has("x-amz-server-side-encryption-customer-algorithm")
        || has("x-amz-server-side-encryption-customer-key")
        || has("x-amz-server-side-encryption-customer-key-md5");
    let algorithm = headers
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok());
    let kms_key = has("x-amz-server-side-encryption-aws-kms-key-id");
    let refuse = |msg: &str| {
        Some(S3Error::xml_response(
            "InvalidArgument",
            msg,
            StatusCode::BAD_REQUEST,
        ))
    };
    if customer && (algorithm.is_some() || kms_key) {
        return refuse(
            "Server Side Encryption with Customer provided key is incompatible with the encryption method specified",
        );
    }
    if kms_key && algorithm != Some("aws:kms") {
        return refuse("Specifying a KMS key id requires x-amz-server-side-encryption: aws:kms");
    }
    None
}

/// A read carrying server-side encryption headers, which belong on writes:
/// S3 refuses it (400) rather than ignore them.
fn sse_headers_on_read(headers: &HeaderMap) -> Option<Response> {
    (headers.contains_key("x-amz-server-side-encryption")
        || headers.contains_key("x-amz-server-side-encryption-aws-kms-key-id"))
    .then(|| {
        S3Error::xml_response(
            "InvalidArgument",
            "x-amz-server-side-encryption headers are not supported for this operation",
            StatusCode::BAD_REQUEST,
        )
    })
}

/// Where an SSE-C object keeps what identifies its customer key: a random
/// salt and SHA-256(salt || key). Never the key, nor anything that reveals
/// it without guessing all 2^256.
const SSE_C_SALT: &str = "objectio-sse-c-salt";
const SSE_C_HASH: &str = "objectio-sse-c-key-sha256";

/// The record of `key` an SSE-C object is stored with.
fn sse_c_verifier(key: &[u8]) -> HashMap<String, String> {
    use rand::RngCore;
    use sha2::Digest;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let hash = sha2::Sha256::new()
        .chain_update(salt)
        .chain_update(key)
        .finalize();
    HashMap::from([
        (SSE_C_SALT.to_string(), hex::encode(salt)),
        (SSE_C_HASH.to_string(), hex::encode(hash)),
    ])
}

/// Whether `key` is the one an SSE-C object was stored with. Objects
/// stored before keys were recorded can't be checked, and pass.
fn sse_c_key_matches(context: &HashMap<String, String>, key: &[u8]) -> bool {
    use sha2::Digest;
    let (Some(salt), Some(want)) = (context.get(SSE_C_SALT), context.get(SSE_C_HASH)) else {
        return true;
    };
    let Ok(salt) = hex::decode(salt) else {
        return false;
    };
    let got = hex::encode(
        sha2::Sha256::new()
            .chain_update(&salt)
            .chain_update(key)
            .finalize(),
    );
    // Constant time: how much matches says nothing about the key.
    got.len() == want.len()
        && got
            .bytes()
            .zip(want.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// The response to a read of an SSE-C object, when its headers don't
/// carry the key it was stored with: 400 without one, 403 with another.
/// A wrong key used to decrypt to garbage served with 200.
fn sse_c_read_refusal(headers: &HeaderMap, object: &ObjectMeta) -> Option<Response> {
    if SseAlgorithm::try_from(object.encryption_algorithm) != Ok(SseAlgorithm::SseC) {
        return None;
    }
    match parse_sse_c_headers(headers) {
        Ok(Some(cust)) if sse_c_key_matches(&object.encryption_context, &cust.key) => None,
        Ok(Some(_)) => Some(S3Error::xml_response(
            "InvalidRequest",
            "The provided customer encryption key is not the one the object was stored with",
            StatusCode::BAD_REQUEST,
        )),
        Ok(None) => Some(S3Error::xml_response(
            "InvalidRequest",
            "The object was stored using a form of SSE-C; the customer key must be provided",
            StatusCode::BAD_REQUEST,
        )),
        Err(resp) => Some(resp),
    }
}

/// Parse + validate SSE-C customer-key headers.
///
/// Returns `Ok(None)` when the headers are absent (i.e. this request isn't
/// SSE-C), `Ok(Some(_))` when all three are present and consistent, and
/// `Err(Response)` for partial/malformed header sets.
#[allow(clippy::result_large_err)]
fn parse_sse_c_headers(headers: &HeaderMap) -> Result<Option<SseCKey>, Response> {
    let algo = headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .and_then(|v| v.to_str().ok());
    let key = headers
        .get("x-amz-server-side-encryption-customer-key")
        .and_then(|v| v.to_str().ok());
    let md5 = headers
        .get("x-amz-server-side-encryption-customer-key-md5")
        .and_then(|v| v.to_str().ok());
    match (algo, key, md5) {
        (None, None, None) => Ok(None),
        (Some(a), Some(k), Some(m)) => {
            if a != "AES256" {
                return Err(S3Error::xml_response(
                    "InvalidArgument",
                    "x-amz-server-side-encryption-customer-algorithm must be AES256",
                    StatusCode::BAD_REQUEST,
                ));
            }
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(k)
                .map_err(|e| {
                    S3Error::xml_response(
                        "InvalidArgument",
                        &format!("customer key must be valid base64: {e}"),
                        StatusCode::BAD_REQUEST,
                    )
                })?;
            if key_bytes.len() != objectio_kms::DEK_LEN {
                return Err(S3Error::xml_response(
                    "InvalidArgument",
                    &format!(
                        "customer key must decode to {} bytes, got {}",
                        objectio_kms::DEK_LEN,
                        key_bytes.len()
                    ),
                    StatusCode::BAD_REQUEST,
                ));
            }
            // MD5 binding — catches key-header corruption and prevents a
            // wrong key from silently producing garbage plaintext on GET.
            let computed = crate::digest::md5(&key_bytes);
            let computed_b64 = base64::engine::general_purpose::STANDARD.encode(computed);
            if computed_b64 != m {
                return Err(S3Error::xml_response(
                    "InvalidArgument",
                    "x-amz-server-side-encryption-customer-key-md5 does not match MD5 of the customer key",
                    StatusCode::BAD_REQUEST,
                ));
            }
            let mut arr = [0u8; objectio_kms::DEK_LEN];
            arr.copy_from_slice(&key_bytes);
            Ok(Some(SseCKey {
                key: arr,
                md5_b64: m.to_string(),
            }))
        }
        _ => Err(S3Error::xml_response(
            "InvalidRequest",
            "SSE-C requires all three x-amz-server-side-encryption-customer-* headers",
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// Parse the optional `x-amz-server-side-encryption-context` header.
///
/// AWS S3 delivers this as a base64-encoded JSON object of string→string.
#[allow(clippy::result_large_err)]
fn parse_encryption_context_header(
    headers: &HeaderMap,
) -> Result<HashMap<String, String>, Response> {
    let Some(raw) = headers
        .get("x-amz-server-side-encryption-context")
        .and_then(|v| v.to_str().ok())
    else {
        return Ok(HashMap::new());
    };
    let bytes = match base64::engine::general_purpose::STANDARD.decode(raw) {
        Ok(b) => b,
        Err(e) => {
            return Err(S3Error::xml_response(
                "InvalidArgument",
                &format!("x-amz-server-side-encryption-context must be valid base64: {e}"),
                StatusCode::BAD_REQUEST,
            ));
        }
    };
    match serde_json::from_slice::<HashMap<String, String>>(&bytes) {
        Ok(m) => Ok(m),
        Err(e) => Err(S3Error::xml_response(
            "InvalidArgument",
            &format!(
                "x-amz-server-side-encryption-context must decode to a JSON object of strings: {e}"
            ),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// Apply SSE to an incoming PUT. Consults the effective SSE decision
/// (request header, else bucket default) and encrypts the body with
/// AES-256-CTR using a per-object DEK.
///
/// For SSE-S3 the DEK is wrapped by the gateway's service master key.
/// For SSE-KMS it's wrapped via the `KmsProvider` (which in turn
/// unwraps a KEK held only on the gateway and binds the wrap to the
/// caller's encryption context).
#[allow(clippy::result_large_err)]
async fn apply_put_sse(
    state: &Arc<AppState>,
    meta_client: &mut MetadataServiceClient<Channel>,
    bucket: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<
    (
        Bytes,
        SseAlgorithm,
        String,
        Vec<u8>,
        Vec<u8>,
        HashMap<String, String>,
        Option<&'static str>,
        String, // sse_c_key_md5 — only populated for SSE-C; empty otherwise
    ),
    Response,
> {
    if let Some(refused) = sse_header_conflict(headers) {
        return Err(refused);
    }
    // SSE-C takes precedence over everything. AWS rejects a PUT that mixes
    // SSE-C customer-* headers with server-side algorithm headers, so the
    // presence of *any* SSE-C header activates this path. Warehouse-bucket
    // guard below.
    if let Some(cust) = parse_sse_c_headers(headers)? {
        // Hard-block SSE-C on warehouse buckets — query engines can't send
        // the customer key on every read, so Iceberg/Delta reads would all
        // fail. Refusing at PUT time is clearer than a silent 403 later.
        if is_warehouse_bucket(bucket) {
            return Err(S3Error::xml_response(
                "InvalidEncryptionAlgorithmError",
                "SSE-C is not supported on warehouse buckets — query engines cannot provide the customer key on every read. Use SSE-S3 or SSE-KMS instead.",
                StatusCode::BAD_REQUEST,
            ));
        }
        let iv = objectio_kms::generate_iv();
        let mut buf = body.to_vec();
        objectio_kms::encrypt_in_place(&cust.key, &iv, &mut buf);
        return Ok((
            Bytes::from(buf),
            SseAlgorithm::SseC,
            String::new(), // no KMS key
            Vec::new(),    // no wrapped DEK — the client holds the key
            iv.to_vec(),
            sse_c_verifier(&cust.key),
            None, // SSE-C uses customer-algorithm headers, not x-amz-server-side-encryption
            cust.md5_b64,
        ));
    }

    let Some(decision) = resolve_sse_decision(meta_client, bucket, Some(headers)).await? else {
        return Ok((
            body,
            SseAlgorithm::SseNone,
            String::new(),
            Vec::new(),
            Vec::new(),
            HashMap::new(),
            None,
            String::new(),
        ));
    };

    match decision.algorithm {
        SseAlgorithm::SseS3 => {
            let Some(mk) = state.master_key.as_ref() else {
                error!("Bucket {bucket} requires SSE-S3 but gateway has no master key configured");
                return Err(S3Error::xml_response(
                    "ServiceUnavailable",
                    "SSE master key not configured on the gateway — contact the administrator",
                    StatusCode::SERVICE_UNAVAILABLE,
                ));
            };
            let dek = objectio_kms::generate_dek();
            let iv = objectio_kms::generate_iv();
            let mut buf = body.to_vec();
            objectio_kms::encrypt_in_place(&dek, &iv, &mut buf);
            Ok((
                Bytes::from(buf),
                SseAlgorithm::SseS3,
                String::new(),
                mk.wrap_dek(&dek),
                iv.to_vec(),
                HashMap::new(),
                Some("AES256"),
                String::new(),
            ))
        }
        SseAlgorithm::SseKms => {
            let Some(kms) = state.kms() else {
                return Err(S3Error::xml_response(
                    "ServiceUnavailable",
                    "SSE-KMS is not configured on this gateway",
                    StatusCode::SERVICE_UNAVAILABLE,
                ));
            };
            let data_key = match kms
                .generate_data_key(&decision.kms_key_id, &decision.encryption_context)
                .await
            {
                Ok(g) => g,
                Err(objectio_kms::KmsError::KeyNotFound(id)) => {
                    return Err(S3Error::xml_response(
                        "KMS.NotFoundException",
                        &format!("KMS key '{id}' does not exist"),
                        StatusCode::BAD_REQUEST,
                    ));
                }
                Err(objectio_kms::KmsError::KeyDisabled(id)) => {
                    return Err(S3Error::xml_response(
                        "KMS.DisabledException",
                        &format!("KMS key '{id}' is disabled"),
                        StatusCode::BAD_REQUEST,
                    ));
                }
                Err(e) => {
                    error!(
                        "KMS generate_data_key for {} failed: {e}",
                        decision.kms_key_id
                    );
                    return Err(S3Error::xml_response(
                        "InternalError",
                        &e.to_string(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ));
                }
            };
            let iv = objectio_kms::generate_iv();
            let mut buf = body.to_vec();
            objectio_kms::encrypt_in_place(&data_key.plaintext_dek, &iv, &mut buf);
            Ok((
                Bytes::from(buf),
                SseAlgorithm::SseKms,
                decision.kms_key_id,
                data_key.wrapped_dek,
                iv.to_vec(),
                decision.encryption_context,
                Some("aws:kms"),
                String::new(),
            ))
        }
        _ => unreachable!("resolve_sse_decision returned unsupported algorithm"),
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
fn extract_user_metadata(headers: &HeaderMap) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str.starts_with("x-amz-meta-")
            && let Ok(value_str) = value.to_str()
        {
            // Strip the x-amz-meta- prefix for storage
            let key = name_str.strip_prefix("x-amz-meta-").unwrap_or(&name_str);
            metadata.insert(key.to_string(), value_str.to_string());
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
        // Only what makes a valid header: one that doesn't would fail the
        // whole response (a panic, the connection dropped) for every read
        // of the object.
        let name = format!("x-amz-meta-{key}");
        if http::header::HeaderName::from_bytes(name.as_bytes()).is_ok()
            && http::HeaderValue::from_str(value).is_ok()
        {
            builder = builder.header(name, value);
        }
    }
    builder
}

// ── Object tagging ───────────────────────────────────────────────────────────

/// Bucket tagging is not implemented. Said plainly: a GET of `?tagging`
/// used to answer with the bucket's listing, and a PUT tried to create
/// the bucket.
fn bucket_tagging_unsupported() -> Response {
    S3Error::xml_response(
        "NotImplemented",
        "Bucket tagging is not supported",
        StatusCode::NOT_IMPLEMENTED,
    )
}

/// Tags an object may carry (S3's limit).
const MAX_TAGS: usize = 10;

/// User-metadata key under which a multipart upload carries the tags its
/// CreateMultipartUpload asked for, until CompleteMultipartUpload puts them
/// on the object. A header name cannot contain a space, so no
/// `x-amz-meta-*` header can collide with it.
const UPLOAD_TAGS_KEY: &str = "objectio tagging";

/// The flexible checksum algorithm a CreateMultipartUpload declares (its
/// `x-amz-checksum-algorithm`), kept in the upload's metadata.
const UPLOAD_CHECKSUM_KEY: &str = "objectio checksum-algorithm";
const UPLOAD_CHECKSUM_TYPE_KEY: &str = "objectio checksum-type";

/// The object-lock headers a CreateMultipartUpload carries, kept in the
/// upload's metadata under this prefix until CompleteMultipartUpload.
const UPLOAD_LOCK_PREFIX: &str = "objectio lock ";
const UPLOAD_LOCK_HEADERS: &[&str] = &[
    "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date",
    "x-amz-object-lock-legal-hold",
];

/// Check tags against S3's rules: at most 10, keys of 1–128 characters and
/// values of at most 256, no key twice, none in the reserved `aws:` space.
#[allow(clippy::result_large_err)]
fn validate_tags(pairs: Vec<(String, String)>) -> Result<HashMap<String, String>, Response> {
    let invalid = |msg: String| {
        Err(S3Error::xml_response(
            "InvalidTag",
            &msg,
            StatusCode::BAD_REQUEST,
        ))
    };
    if pairs.len() > MAX_TAGS {
        return invalid(format!("Object tags cannot be greater than {MAX_TAGS}"));
    }
    let mut tags = HashMap::new();
    for (k, v) in pairs {
        if k.is_empty() || k.chars().count() > 128 {
            return invalid(format!("The TagKey you have provided is invalid: {k:?}"));
        }
        if v.chars().count() > 256 {
            return invalid(format!(
                "The TagValue you have provided is invalid for {k:?}"
            ));
        }
        if k.to_ascii_lowercase().starts_with("aws:") {
            return invalid(format!("Your TagKey cannot be prefixed with aws: ({k:?})"));
        }
        if tags.insert(k.clone(), v).is_some() {
            return invalid(format!(
                "Cannot provide multiple Tags with the same key: {k:?}"
            ));
        }
    }
    Ok(tags)
}

/// Tags from an `x-amz-tagging` value: URL-encoded `k1=v1&k2=v2`.
#[allow(clippy::result_large_err)]
fn parse_tagging(value: &str) -> Result<HashMap<String, String>, Response> {
    let decode = |s: &str| {
        urlencoding::decode(&s.replace('+', " "))
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_else(|_| s.to_string())
    };
    let pairs = value
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect();
    validate_tags(pairs)
}

/// Tags a request sets with `x-amz-tagging`; none when it has no such
/// header.
#[allow(clippy::result_large_err)]
fn tagging_header(headers: &HeaderMap) -> Result<HashMap<String, String>, Response> {
    match headers.get("x-amz-tagging").map(|v| v.to_str()) {
        None => Ok(HashMap::new()),
        Some(Ok(v)) => parse_tagging(v),
        Some(Err(_)) => Err(S3Error::xml_response(
            "InvalidArgument",
            "x-amz-tagging is not valid text",
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// `tags` as an `x-amz-tagging` value.
fn encode_tagging(tags: &HashMap<String, String>) -> String {
    let mut pairs: Vec<_> = tags.iter().collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Whether a copy takes its tags from the request (`x-amz-tagging-directive:
/// REPLACE`) rather than from its source.
fn replaces_tags(copy_headers: &HeaderMap) -> bool {
    copy_headers
        .get("x-amz-tagging-directive")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("REPLACE"))
}

/// `x-amz-tagging-count` on a GET or HEAD of an object that has tags.
fn add_tagging_count(
    builder: http::response::Builder,
    tags: &HashMap<String, String>,
) -> http::response::Builder {
    if tags.is_empty() {
        builder
    } else {
        builder.header("x-amz-tagging-count", tags.len())
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename = "Tagging")]
struct TaggingXml {
    #[serde(rename = "TagSet", default)]
    tag_set: TagSetXml,
}

#[derive(Serialize, Deserialize, Default)]
struct TagSetXml {
    #[serde(rename = "Tag", default)]
    tags: Vec<TagXml>,
}

#[derive(Serialize, Deserialize)]
struct TagXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Value", default)]
    value: String,
}

/// The object's ObjectMeta and the nodes that hold it, or the response to
/// give instead.
async fn object_meta_for_update(
    state: &Arc<AppState>,
    bucket: &str,
    key: &str,
) -> Result<(ObjectMeta, Vec<objectio_proto::metadata::NodePlacement>), Response> {
    let nodes = get_placement_nodes_for_object(state, bucket, key).await?;
    match get_object_meta_from_any(&state.osd_pool, &nodes, bucket, key).await {
        Ok(Some(meta)) if !meta.is_delete_marker => Ok((meta, nodes)),
        Ok(_) => Err(S3Error::xml_response(
            "NoSuchKey",
            "The specified key does not exist.",
            StatusCode::NOT_FOUND,
        )),
        Err(e) => {
            error!("Failed to get object metadata: {e}");
            Err(S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

async fn get_object_tagging_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
) -> Response {
    let (meta, _) = match object_meta_for_update(&state, &bucket, &key).await {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let mut tags: Vec<TagXml> = meta
        .tags
        .into_iter()
        .map(|(key, value)| TagXml { key, value })
        .collect();
    tags.sort_by(|a, b| a.key.cmp(&b.key));
    let body = TaggingXml {
        tag_set: TagSetXml { tags },
    };
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        to_xml(&body).unwrap_or_default()
    );
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml");
    if !meta.version_id.is_empty() {
        builder = builder.header("x-amz-version-id", &meta.version_id);
    }
    builder.body(Body::from(xml)).unwrap()
}

/// Replace the object's tags (`None` removes them all): PutObjectTagging
/// and DeleteObjectTagging.
async fn set_object_tagging(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    tags: HashMap<String, String>,
    status: StatusCode,
) -> Response {
    let (mut meta, nodes) = match object_meta_for_update(&state, &bucket, &key).await {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    meta.tags = tags;
    let version_id = meta.version_id.clone();
    // Only over the object just read: a PUT that replaced it meanwhile must
    // not have this one written back over it.
    let expected = meta.object_id.clone();
    if let Err(e) = put_object_meta_to_all(
        &state.osd_pool,
        &nodes,
        &bucket,
        &key,
        meta,
        false,
        &expected,
    )
    .await
    {
        error!("Failed to update tags of {bucket}/{key}: {e}");
        return S3Error::xml_response(
            "InternalError",
            &e.to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }
    let mut builder = Response::builder().status(status);
    if !version_id.is_empty() {
        builder = builder.header("x-amz-version-id", version_id);
    }
    builder.body(Body::empty()).unwrap()
}

async fn put_object_tagging_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    body: Bytes,
) -> Response {
    let parsed: TaggingXml = match quick_xml::de::from_reader(body.as_ref()) {
        Ok(t) => t,
        Err(e) => {
            return S3Error::xml_response(
                "MalformedXML",
                &format!("Invalid tagging XML: {e}"),
                StatusCode::BAD_REQUEST,
            );
        }
    };
    let pairs = parsed
        .tag_set
        .tags
        .into_iter()
        .map(|t| (t.key, t.value))
        .collect();
    let tags = match validate_tags(pairs) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    set_object_tagging(state, bucket, key, tags, StatusCode::OK).await
}

/// Add the object's stored `x-amz-checksum-<algorithm>` to a GET or HEAD
/// response, when the request asked with `x-amz-checksum-mode: ENABLED`.
/// Only for whole-object responses: the stored value is the checksum of the
/// whole object, which a ranged body would not match.
fn add_checksum_header(
    builder: http::response::Builder,
    request_headers: &HeaderMap,
    object: &ObjectMeta,
) -> http::response::Builder {
    let enabled = request_headers
        .get("x-amz-checksum-mode")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("ENABLED"));
    let stored = object.checksum.as_ref().and_then(|c| {
        crate::checksum::ChecksumAlgorithm::from_aws_name(&c.algorithm)
            .map(|a| (a.header_name(), c.value.as_str()))
    });
    match stored {
        Some((name, value)) if enabled => builder.header(name, value).header(
            "x-amz-checksum-type",
            object
                .checksum
                .as_ref()
                .map_or("FULL_OBJECT", checksum_type_of),
        ),
        _ => builder,
    }
}

/// Parsed Range header
#[derive(Debug, Clone, Copy)]
struct ByteRange {
    start: u64,
    end: u64, // inclusive
}

/// Parse HTTP Range header (e.g., "bytes=0-99" or "bytes=100-" or "bytes=-50")
fn parse_range_header(range_header: &str, total_size: u64) -> Option<ByteRange> {
    // No range over a zero-length object is satisfiable, and every branch
    // below computes `total_size - 1`. The suffix branch reached that with
    // `total_size == 0` — `GET` with `Range: bytes=-5` on an empty object
    // panicked on the underflow in a debug build and produced a range ending
    // at `u64::MAX` in a release one. `None` here becomes the 416 the caller
    // already returns for an unsatisfiable range, which is also what RFC 7233
    // asks for.
    if total_size == 0 {
        return None;
    }

    let range_header = range_header.trim();
    if !range_header.starts_with("bytes=") {
        return None;
    }

    let range_spec = &range_header[6..]; // strip "bytes="
    let parts: Vec<&str> = range_spec.split('-').collect();
    if parts.len() != 2 {
        return None;
    }

    let start_str = parts[0].trim();
    let end_str = parts[1].trim();

    if start_str.is_empty() && end_str.is_empty() {
        return None;
    }

    // Handle suffix range (bytes=-500 means last 500 bytes)
    if start_str.is_empty() {
        let suffix_len: u64 = end_str.parse().ok()?;
        // `bytes=-0` asks for the last zero bytes. RFC 7233 calls that
        // unsatisfiable; this used to answer it with the entire object.
        if suffix_len == 0 {
            return None;
        }
        if suffix_len > total_size {
            return Some(ByteRange {
                start: 0,
                end: total_size - 1,
            });
        }
        return Some(ByteRange {
            start: total_size - suffix_len,
            end: total_size - 1,
        });
    }

    let start: u64 = start_str.parse().ok()?;

    // Handle open-ended range (bytes=100- means from 100 to end)
    if end_str.is_empty() {
        if start >= total_size {
            return None;
        }
        return Some(ByteRange {
            start,
            end: total_size - 1,
        });
    }

    let end: u64 = end_str.parse().ok()?;

    // Validate range
    if start > end || start >= total_size {
        return None;
    }

    // Clamp end to total_size - 1
    let end = std::cmp::min(end, total_size - 1);

    Some(ByteRange { start, end })
}

/// Given a byte range and stripe metadata, return `(stripe_index, stripe_byte_offset)`
/// pairs for only the stripes that overlap the range.
/// A stripe's bytes as its object sees them: a packed stripe's slice, or
/// the whole stripe.
fn object_part(stripe: &StripeMeta, data: Vec<u8>) -> Vec<u8> {
    if stripe.slice_length == 0 {
        return data;
    }
    let start = usize::try_from(stripe.slice_offset)
        .unwrap_or(usize::MAX)
        .min(data.len());
    let end = start
        .saturating_add(usize::try_from(stripe.slice_length).unwrap_or(usize::MAX))
        .min(data.len());
    data[start..end].to_vec()
}

/// Bytes `[from, to)` of a pack stripe's data, read from the data shards
/// they fall in, with no decoding. `None` if any of those reads fails: the
/// caller then decodes the stripe from any k shards.
async fn read_packed_slice(
    state: &Arc<AppState>,
    node_address_map: &mut HashMap<Vec<u8>, String>,
    meta_client: &mut MetadataServiceClient<Channel>,
    stripe: &StripeMeta,
    stripe_data_size: usize,
    from: u64,
    to: u64,
) -> Option<Vec<u8>> {
    let k = stripe.ec_k as usize;
    let shard = objectio_erasure::ErasureCodec::shard_size_for(stripe_data_size, k) as u64;
    if shard == 0 || to <= from {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(usize::try_from(to - from).ok()?);
    let mut pos = from;
    while pos < to {
        let index = pos / shard;
        if index >= k as u64 {
            return None;
        }
        let in_shard = pos % shard;
        let len = (shard - in_shard).min(to - pos);
        let loc = stripe
            .shards
            .iter()
            .find(|l| u64::from(l.position) == index)?;
        let placement = objectio_proto::metadata::NodePlacement {
            te_segment: String::new(),
            position: loc.position,
            node_id: loc.node_id.clone(),
            node_address: resolve_node_address(node_address_map, meta_client, &loc.node_id).await,
            disk_id: loc.disk_id.clone(),
            shard_type: loc.shard_type,
            local_group: loc.local_group,
        };
        let bytes = crate::osd_pool::read_shard_range_from_osd(
            &state.osd_pool,
            &placement,
            &stripe.object_id,
            stripe.stripe_id,
            loc.position,
            in_shard,
            u32::try_from(len).ok()?,
        )
        .await
        .ok()?;
        if bytes.len() as u64 != len {
            return None;
        }
        out.extend_from_slice(&bytes);
        pos += len;
    }
    Some(out)
}

fn overlapping_stripes(
    stripes: &[StripeMeta],
    object_size: u64,
    range: &ByteRange,
) -> Vec<(usize, u64)> {
    let mut offset = 0u64;
    let mut result = Vec::new();
    for (idx, stripe) in stripes.iter().enumerate() {
        let effective_size = if stripe.slice_length > 0 {
            stripe.slice_length
        } else if stripe.data_size > 0 {
            stripe.data_size
        } else if stripes.len() == 1 {
            object_size
        } else {
            // Multi-stripe without data_size: include conservatively
            // (the stripe loop will error out for this case)
            0
        };
        let stripe_end = offset + effective_size;
        // Include stripe if it overlaps the range, or if we can't determine its size
        if effective_size == 0 || (offset <= range.end && stripe_end > range.start) {
            result.push((idx, offset));
        }
        offset = stripe_end;
    }
    result
}

/// Populate policy-engine context variables from incoming S3 request headers.
///
/// These are the AWS IAM/S3 condition keys relevant to object-level SSE
/// enforcement — bucket policies like `Deny unless s3:x-amz-server-side-encryption`
/// read these values from `RequestContext.variables`.
pub(crate) fn sse_condition_vars(headers: Option<&HeaderMap>) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    // Currently the gateway terminates TLS upstream (Cloudflare/ingress), so
    // every request here effectively came in over HTTPS. Mark it so
    // `aws:SecureTransport = "true"` conditions work.
    vars.insert("aws:SecureTransport".to_string(), "true".to_string());
    let Some(h) = headers else { return vars };
    if let Some(v) = h
        .get("x-amz-server-side-encryption")
        .and_then(|v| v.to_str().ok())
    {
        vars.insert("s3:x-amz-server-side-encryption".to_string(), v.to_string());
    }
    if let Some(v) = h
        .get("x-amz-server-side-encryption-aws-kms-key-id")
        .and_then(|v| v.to_str().ok())
    {
        vars.insert(
            "s3:x-amz-server-side-encryption-aws-kms-key-id".to_string(),
            v.to_string(),
        );
    }
    vars
}

/// Build ARN for an S3 resource
/// Shape a listing response for the API version the client asked for.
///
/// V1 (`GET /{bucket}`) paginates on Marker/NextMarker; V2
/// (`?list-type=2`) on ContinuationToken/KeyCount. Answering a V1
/// request with a V2-only body leaves the client nothing to page with.
#[cfg(test)]
fn apply_listing_version(
    result: &mut ListBucketResult,
    is_v2: bool,
    marker: Option<String>,
    start_after: Option<String>,
) {
    apply_listing_echo(result, is_v2, marker, start_after, ListingEcho::default());
}

/// What a listing request asked that its answer echoes or acts on, beyond
/// the markers.
#[derive(Default)]
struct ListingEcho {
    continuation_token: Option<String>,
    /// The bucket's owner, shown on each object for V1, and for V2 with
    /// ?fetch-owner=true (objects record no owner of their own).
    owner: Option<String>,
    fetch_owner: bool,
}

fn apply_listing_echo(
    result: &mut ListBucketResult,
    is_v2: bool,
    marker: Option<String>,
    start_after: Option<String>,
    echo: ListingEcho,
) {
    // max-keys=0 asks for no keys at all.
    if result.max_keys == 0 {
        result.contents.clear();
        result.common_prefixes.clear();
        result.is_truncated = false;
        result.next_continuation_token = None;
        result.key_count = Some(0);
    }
    if let Some(owner) = echo.owner.filter(|_| !is_v2 || echo.fetch_owner) {
        for c in &mut result.contents {
            c.owner = Some(Owner {
                id: owner.clone(),
                display_name: owner.clone(),
            });
        }
    }
    apply_listing_markers(result, is_v2, marker, start_after, echo.continuation_token);
    if result.encoding_type.as_deref() == Some("url") {
        url_encode_listing(result);
    }
}

/// With ?encoding-type=url, S3 percent-encodes every key and prefix in the
/// answer, and clients (boto3 always asks for it) decode them. Echoing the
/// encoding type while sending keys raw made a client decode them anyway:
/// "a+b" listed as "a b", "x%2By" as "x+y".
fn url_encode_listing(result: &mut ListBucketResult) {
    let enc = |s: &mut String| *s = s3_url_encode(s);
    let enc_opt = |s: &mut Option<String>| {
        if let Some(v) = s {
            *v = s3_url_encode(v);
        }
    };
    enc(&mut result.prefix);
    enc_opt(&mut result.delimiter);
    enc_opt(&mut result.marker);
    enc_opt(&mut result.next_marker);
    enc_opt(&mut result.start_after);
    for c in &mut result.contents {
        enc(&mut c.key);
    }
    for p in &mut result.common_prefixes {
        enc(&mut p.prefix);
    }
}

/// Percent-encoding as S3's `encoding-type=url` does it: everything but
/// unreserved characters and "/".
fn s3_url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn apply_listing_markers(
    result: &mut ListBucketResult,
    is_v2: bool,
    marker: Option<String>,
    start_after: Option<String>,
    continuation_token: Option<String>,
) {
    if is_v2 {
        result.start_after = start_after;
        result.continuation_token = continuation_token;
        result.marker = None;
        result.next_marker = None;
        return;
    }
    result.continuation_token = None;
    result.marker = Some(marker.unwrap_or_default());
    result.start_after = None;
    result.key_count = None;
    result.next_continuation_token = None;
    result.next_marker = if result.is_truncated {
        let last_key = result.contents.last().map(|c| c.key.clone());
        let last_prefix = result.common_prefixes.last().map(|p| p.prefix.clone());
        match (last_key, last_prefix) {
            (Some(a), Some(b)) => Some(if a >= b { a } else { b }),
            (a, b) => a.or(b),
        }
    } else {
        None
    };
}

pub(crate) fn build_s3_arn(bucket: &str, key: Option<&str>) -> String {
    match key {
        Some(k) => format!("arn:obio:s3:::{}/{}", bucket, k),
        None => format!("arn:obio:s3:::{}", bucket),
    }
}

/// Query parameters for list objects
#[derive(Debug, Deserialize, Default)]
pub struct ListObjectsParams {
    /// If present, a bucket tagging request: not supported (see
    /// `bucket_tagging_unsupported`).
    tagging: Option<String>,
    prefix: Option<String>,
    delimiter: Option<String>,
    #[serde(rename = "max-keys")]
    max_keys: Option<String>,
    #[serde(rename = "continuation-token")]
    continuation_token: Option<String>,
    /// V1 pagination position (`?marker=`). Was unparsed, so a V1
    /// client could never advance past the first page.
    marker: Option<String>,
    /// V2 pagination position (`?start-after=`). Also unparsed.
    #[serde(rename = "start-after")]
    start_after: Option<String>,
    /// `list-type=2` selects the ListObjectsV2 request/response shape.
    /// Absent means V1, which uses Marker/NextMarker rather than
    /// KeyCount/ContinuationToken.
    #[serde(rename = "list-type")]
    list_type: Option<String>,
    /// Accepted and echoed; only "url" is meaningful to S3 and we do
    /// not currently encode keys, so this is recorded, not honored.
    #[serde(rename = "encoding-type")]
    encoding_type: Option<String>,
    /// ListObjectsV2: put each object's owner in the answer.
    #[serde(rename = "fetch-owner")]
    fetch_owner: Option<String>,
    /// If present, a GetBucketAcl request
    acl: Option<String>,
    /// If present, a GetBucketOwnershipControls request
    #[serde(rename = "ownershipControls")]
    ownership_controls: Option<String>,
    /// If present (even empty), this is a policy request
    policy: Option<String>,
    /// If present, this is a list object versions request
    versions: Option<String>,
    /// If present, this is a get bucket versioning request
    versioning: Option<String>,
    /// If present, this is a get object-lock configuration request
    #[serde(rename = "object-lock")]
    object_lock: Option<String>,
    /// If present, this is a get lifecycle configuration request
    lifecycle: Option<String>,
    /// If present, this is a get bucket encryption request
    encryption: Option<String>,
    /// If present (even empty), this is a ListMultipartUploads request
    uploads: Option<String>,
    /// Key marker for ListMultipartUploads pagination
    #[serde(rename = "key-marker")]
    key_marker: Option<String>,
    /// Version marker for ListObjectVersions pagination
    #[serde(rename = "version-id-marker")]
    version_id_marker: Option<String>,
    /// Upload ID marker for ListMultipartUploads pagination
    #[serde(rename = "upload-id-marker")]
    upload_id_marker: Option<String>,
    /// Max uploads per page for ListMultipartUploads
    #[serde(rename = "max-uploads")]
    max_uploads: Option<u32>,
}

impl ListObjectsParams {
    /// Check if this is a policy operation (has ?policy in query string)
    pub fn is_policy_request(&self) -> bool {
        self.policy.is_some()
    }
}

/// Query parameters for POST bucket operations
#[derive(Debug, Deserialize, Default)]
pub struct PostBucketParams {
    /// If present, this is a delete objects request
    delete: Option<String>,
    /// If present, this is a list multipart uploads request (also handled by GET)
    #[allow(dead_code)]
    uploads: Option<String>,
    /// If present, this is a prefix-scoped grep across multiple keys.
    /// The request body carries a [`grep::PrefixGrepRequest`].
    grep: Option<String>,
}

impl PostBucketParams {
    /// Check if this is a delete objects request (has ?delete in query string)
    pub fn is_delete_request(&self) -> bool {
        self.delete.is_some()
    }
}

/// Query parameters for PUT bucket operations
#[derive(Debug, Deserialize, Default)]
pub struct PutBucketParams {
    /// If present, a bucket tagging request: not supported (see
    /// `bucket_tagging_unsupported`).
    tagging: Option<String>,
    /// If present (even empty), this is a policy request
    policy: Option<String>,
    /// If present, this is a versioning request
    versioning: Option<String>,
    /// If present, this is an object-lock configuration request
    #[serde(rename = "object-lock")]
    object_lock: Option<String>,
    /// If present, this is a lifecycle configuration request
    lifecycle: Option<String>,
    /// If present, this is a put bucket encryption request
    encryption: Option<String>,
    /// If present, a PutBucketAcl request
    acl: Option<String>,
    /// If present, a PutBucketOwnershipControls request
    #[serde(rename = "ownershipControls")]
    ownership_controls: Option<String>,
}

/// Query parameters for DELETE bucket operations
#[derive(Debug, Deserialize, Default)]
pub struct DeleteBucketParams {
    /// If present, a bucket tagging request: not supported (see
    /// `bucket_tagging_unsupported`).
    tagging: Option<String>,
    /// If present (even empty), this is a policy request
    policy: Option<String>,
    /// If present, this is a list multipart uploads request
    #[allow(dead_code)]
    uploads: Option<String>,
    /// If present, this is a lifecycle configuration delete request
    lifecycle: Option<String>,
    /// If present, this is a bucket encryption delete request
    encryption: Option<String>,
}

/// Query parameters for PUT object operations (handles both simple PUT and multipart)
#[derive(Debug, Deserialize, Default)]
pub struct PutObjectParams {
    /// Upload ID for multipart part upload
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    /// Part number for multipart part upload (1-10000)
    #[serde(rename = "partNumber")]
    part_number: Option<u32>,
    /// If present, this is a put object retention request
    retention: Option<String>,
    /// If present, this is a put legal hold request
    #[serde(rename = "legal-hold")]
    legal_hold: Option<String>,
    /// If present, this is a tagging request
    tagging: Option<String>,
    /// The version a retention, legal hold or tagging request is for
    #[serde(rename = "versionId")]
    version_id: Option<String>,
    /// If present, a PutObjectAcl request
    acl: Option<String>,
}

/// Query parameters for GET object operations (handles both GET and list parts)
#[derive(Debug, Deserialize, Default)]
pub struct GetObjectParams {
    /// Upload ID for list parts request
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    /// Max parts to return for list parts
    #[serde(rename = "max-parts")]
    max_parts: Option<u32>,
    /// Part number marker for pagination
    #[serde(rename = "part-number-marker")]
    part_number_marker: Option<u32>,
    /// Version ID for retrieving specific version (used by version-aware GET)
    #[serde(rename = "versionId")]
    version_id: Option<String>,
    /// One part of a multipart object
    #[serde(rename = "partNumber")]
    part_number: Option<u32>,
    /// If present, this is a GetObjectAttributes request
    attributes: Option<String>,
    /// If present, a GetObjectAcl request
    acl: Option<String>,
    /// If present, this is a get object retention request
    retention: Option<String>,
    /// If present, this is a get legal hold request
    #[serde(rename = "legal-hold")]
    legal_hold: Option<String>,
    /// If present, this is a tagging request
    tagging: Option<String>,
}

/// Query parameters for POST object operations (handles multipart initiate/complete)
#[derive(Debug, Deserialize, Default)]
pub struct PostObjectParams {
    /// If present, initiate multipart upload
    uploads: Option<String>,
    /// Upload ID for complete multipart upload
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    /// If present, treat the request as a gateway-side grep. Body is a
    /// JSON [`grep::GrepRequest`]; response is NDJSON with one
    /// [`grep::GrepEvent`] per line. The query-string value is ignored
    /// — presence alone is the signal.
    grep: Option<String>,
}

/// Query parameters for DELETE object operations (handles both delete and abort)
#[derive(Debug, Deserialize, Default)]
pub struct DeleteObjectParams {
    /// Upload ID for abort multipart upload
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    /// Version ID for deleting specific version
    #[serde(rename = "versionId")]
    version_id: Option<String>,
    /// If present, this is a DeleteObjectTagging request
    tagging: Option<String>,
}

// XML response types for S3 API

#[derive(Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
pub struct ListBucketsResult {
    #[serde(rename = "Owner")]
    pub owner: Owner,
    #[serde(rename = "Buckets")]
    pub buckets: Buckets,
    /// Where the next page starts, when there is one.
    #[serde(rename = "ContinuationToken")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
}

/// Query parameters for ListBuckets.
#[derive(Debug, Deserialize, Default)]
pub struct ListBucketsParams {
    #[serde(rename = "max-buckets")]
    max_buckets: Option<u32>,
    #[serde(rename = "continuation-token")]
    continuation_token: Option<String>,
    prefix: Option<String>,
}

#[derive(Serialize)]
pub struct Owner {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
}

#[derive(Serialize)]
pub struct Buckets {
    #[serde(rename = "Bucket")]
    pub bucket: Vec<Bucket>,
}

#[derive(Serialize)]
pub struct Bucket {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "CreationDate")]
    pub creation_date: String,
}

#[derive(Serialize)]
#[serde(rename = "ListBucketResult")]
pub struct ListBucketResult {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "Delimiter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    /// V1 only: echo of the requested ?marker=
    #[serde(rename = "Marker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    /// V1 only: where the client should resume. Emitted whenever the
    /// listing is truncated so a V1 client always has a way forward.
    #[serde(rename = "NextMarker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_marker: Option<String>,
    /// V2 only: echo of the requested ?start-after=
    #[serde(rename = "StartAfter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_after: Option<String>,
    /// V2 only: echo of the requested ?continuation-token=
    #[serde(rename = "ContinuationToken")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
    #[serde(rename = "EncodingType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_type: Option<String>,
    #[serde(rename = "MaxKeys")]
    pub max_keys: u32,
    #[serde(rename = "KeyCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_count: Option<u32>,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "NextContinuationToken")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_continuation_token: Option<String>,
    #[serde(rename = "CommonPrefixes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub common_prefixes: Vec<CommonPrefix>,
    #[serde(rename = "Contents")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contents: Vec<ObjectContent>,
}

#[derive(Serialize)]
pub struct CommonPrefix {
    #[serde(rename = "Prefix")]
    pub prefix: String,
}

#[derive(Serialize)]
pub struct ObjectContent {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
    #[serde(rename = "StorageClass")]
    pub storage_class: String,
    /// V1 always, V2 with ?fetch-owner=true.
    #[serde(rename = "Owner")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
}

#[derive(Serialize)]
#[serde(rename = "Error")]
pub struct S3Error {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "Resource")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(rename = "RequestId")]
    pub request_id: String,
}

impl S3Error {
    pub(crate) fn xml_response(code: &str, message: &str, status: StatusCode) -> Response {
        let error = S3Error {
            code: code.to_string(),
            message: message.to_string(),
            resource: None,
            request_id: Uuid::new_v4().to_string(),
        };

        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
            to_xml(&error).unwrap_or_default()
        );

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/xml")
            .extension(crate::gateway_metrics::S3ErrorCode(code.to_string()))
            .body(Body::from(xml))
            .unwrap()
    }
}

// ============================================================================
// Multipart Upload XML Types
// ============================================================================

/// Response for InitiateMultipartUpload
#[derive(Serialize)]
#[serde(rename = "InitiateMultipartUploadResult")]
pub struct InitiateMultipartUploadResult {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
}

/// Response for CompleteMultipartUpload
#[derive(Serialize)]
#[serde(rename = "CompleteMultipartUploadResult")]
pub struct CompleteMultipartUploadResult {
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    // A checksum as S3 puts it in a body: one Checksum<ALG> element, and
    // its type. (quick-xml can't serialize #[serde(flatten)]: a flattened
    // struct here emptied the whole body.)
    #[serde(rename = "ChecksumCRC32", skip_serializing_if = "Option::is_none")]
    pub checksum_crc32: Option<String>,
    #[serde(rename = "ChecksumCRC32C", skip_serializing_if = "Option::is_none")]
    pub checksum_crc32c: Option<String>,
    #[serde(rename = "ChecksumCRC64NVME", skip_serializing_if = "Option::is_none")]
    pub checksum_crc64nvme: Option<String>,
    #[serde(rename = "ChecksumSHA1", skip_serializing_if = "Option::is_none")]
    pub checksum_sha1: Option<String>,
    #[serde(rename = "ChecksumSHA256", skip_serializing_if = "Option::is_none")]
    pub checksum_sha256: Option<String>,
    #[serde(rename = "ChecksumType", skip_serializing_if = "Option::is_none")]
    pub checksum_type: Option<String>,
}

/// A checksum's values for a response body's `Checksum<ALG>` and
/// `ChecksumType` elements.
#[derive(Default)]
pub struct ChecksumXml {
    crc32: Option<String>,
    crc32c: Option<String>,
    crc64nvme: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
    checksum_type: Option<String>,
}

impl ChecksumXml {
    fn of(checksum: Option<&ObjectChecksum>, with_type: bool) -> Self {
        let mut x = Self::default();
        let Some(c) = checksum else {
            return x;
        };
        let v = Some(c.value.clone());
        match c.algorithm.as_str() {
            "CRC32" => x.crc32 = v,
            "CRC32C" => x.crc32c = v,
            "CRC64NVME" => x.crc64nvme = v,
            "SHA1" => x.sha1 = v,
            "SHA256" => x.sha256 = v,
            _ => {}
        }
        if with_type {
            x.checksum_type = Some(checksum_type_of(c).to_string());
        }
        x
    }
}

/// A multipart object's checksum type: a composite ends in "-<parts>".
fn checksum_type_of(c: &ObjectChecksum) -> &'static str {
    if c.value
        .rsplit_once('-')
        .is_some_and(|(_, n)| n.parse::<u32>().is_ok())
    {
        "COMPOSITE"
    } else {
        "FULL_OBJECT"
    }
}

/// Response for ListParts
#[derive(Serialize)]
#[serde(rename = "ListPartsResult")]
pub struct ListPartsResult {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "PartNumberMarker")]
    pub part_number_marker: u32,
    #[serde(rename = "NextPartNumberMarker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_part_number_marker: Option<u32>,
    #[serde(rename = "MaxParts")]
    pub max_parts: u32,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Part")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<PartItem>,
}

/// Part item in ListParts response
#[derive(Serialize)]
pub struct PartItem {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
    #[serde(rename = "ChecksumCRC32", skip_serializing_if = "Option::is_none")]
    pub checksum_crc32: Option<String>,
    #[serde(rename = "ChecksumCRC32C", skip_serializing_if = "Option::is_none")]
    pub checksum_crc32c: Option<String>,
    #[serde(rename = "ChecksumCRC64NVME", skip_serializing_if = "Option::is_none")]
    pub checksum_crc64nvme: Option<String>,
    #[serde(rename = "ChecksumSHA1", skip_serializing_if = "Option::is_none")]
    pub checksum_sha1: Option<String>,
    #[serde(rename = "ChecksumSHA256", skip_serializing_if = "Option::is_none")]
    pub checksum_sha256: Option<String>,
    #[serde(rename = "ChecksumType", skip_serializing_if = "Option::is_none")]
    pub checksum_type: Option<String>,
}

/// Response for ListMultipartUploads
#[derive(Serialize)]
#[serde(rename = "ListMultipartUploadsResult")]
pub struct ListMultipartUploadsResult {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "KeyMarker")]
    pub key_marker: String,
    #[serde(rename = "UploadIdMarker")]
    pub upload_id_marker: String,
    #[serde(rename = "NextKeyMarker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_key_marker: Option<String>,
    #[serde(rename = "NextUploadIdMarker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_upload_id_marker: Option<String>,
    #[serde(rename = "Delimiter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "MaxUploads")]
    pub max_uploads: u32,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Upload")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uploads: Vec<UploadItem>,
}

/// Upload item in ListMultipartUploads response
#[derive(Serialize)]
pub struct UploadItem {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "Initiated")]
    pub initiated: String,
    #[serde(rename = "StorageClass")]
    pub storage_class: String,
}

/// Request body for CompleteMultipartUpload (XML from client)
#[derive(Debug, Deserialize)]
#[serde(rename = "CompleteMultipartUpload")]
pub struct CompleteMultipartUploadXml {
    #[serde(rename = "Part", default)]
    pub parts: Vec<CompletePart>,
}

/// Part in CompleteMultipartUpload request
#[derive(Debug, Deserialize)]
pub struct CompletePart {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "ETag")]
    pub etag: String,
}

// ============================================================================
// DeleteObjects XML Types
// ============================================================================

/// Request body for DeleteObjects (XML from client)
#[derive(Debug, Default)]
pub struct DeleteObjectsRequest {
    /// Report only the keys that could not be deleted.
    pub quiet: bool,
    pub objects: Vec<DeleteObjectIdentifier>,
}

/// Object identifier in DeleteObjects request
#[derive(Debug, Default)]
pub struct DeleteObjectIdentifier {
    pub key: String,
    pub version_id: Option<String>,
    /// Conditions: delete only if the object has this ETag, last-modified
    /// time (ISO 8601) or size.
    pub etag: Option<String>,
    pub last_modified_time: Option<String>,
    pub size: Option<String>,
}

impl DeleteObjectsRequest {
    /// Parse the body keeping every key exactly as sent. quick-xml's serde
    /// deserializer trims text, so a key with leading or trailing spaces
    /// (" ", "a ") came out as another key: that one was "deleted" and
    /// reported, and the object asked for stayed.
    pub fn parse(body: &[u8]) -> Result<Self, String> {
        use quick_xml::events::Event;
        let mut reader = quick_xml::Reader::from_reader(body);
        let mut buf = Vec::new();
        let mut req = Self::default();
        let mut path: Vec<Vec<u8>> = Vec::new();
        let mut text = String::new();
        let mut current: Option<DeleteObjectIdentifier> = None;
        loop {
            match reader
                .read_event_into(&mut buf)
                .map_err(|e| e.to_string())?
            {
                Event::Start(e) => {
                    let name = e.local_name().as_ref().to_vec();
                    if name == b"Object" {
                        current = Some(DeleteObjectIdentifier::default());
                    }
                    path.push(name);
                    text.clear();
                }
                Event::Text(t) => {
                    text.push_str(&t.unescape().map_err(|e| e.to_string())?);
                }
                Event::CData(t) => {
                    text.push_str(&String::from_utf8_lossy(&t.into_inner()));
                }
                Event::End(_) => {
                    let name = path.pop().unwrap_or_default();
                    match (name.as_slice(), current.as_mut()) {
                        (b"Key", Some(o)) => o.key = std::mem::take(&mut text),
                        (b"VersionId", Some(o)) => {
                            o.version_id = Some(std::mem::take(&mut text));
                        }
                        (b"ETag", Some(o)) => o.etag = Some(std::mem::take(&mut text)),
                        (b"LastModifiedTime", Some(o)) => {
                            o.last_modified_time = Some(std::mem::take(&mut text));
                        }
                        (b"Size", Some(o)) => o.size = Some(std::mem::take(&mut text)),
                        (b"Object", _) => {
                            if let Some(o) = current.take() {
                                req.objects.push(o);
                            }
                        }
                        (b"Quiet", None) => req.quiet = text.trim() == "true",
                        _ => {}
                    }
                    text.clear();
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }
        if !path.is_empty() {
            return Err("unclosed element".into());
        }
        Ok(req)
    }
}

/// Response for DeleteObjects
#[derive(Serialize)]
#[serde(rename = "DeleteResult")]
pub struct DeleteObjectsResult {
    #[serde(rename = "Deleted")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deleted: Vec<DeletedObject>,
    #[serde(rename = "Error")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<DeleteError>,
}

/// Successfully deleted object
#[derive(Serialize)]
pub struct DeletedObject {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "VersionId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// The delete added a marker, or removed one.
    #[serde(rename = "DeleteMarker")]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub delete_marker: bool,
    #[serde(rename = "DeleteMarkerVersionId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_marker_version_id: Option<String>,
}

/// Error deleting object
#[derive(Serialize)]
pub struct DeleteError {
    #[serde(rename = "Key")]
    pub key: String,
    /// The version the delete named, as S3 echoes it.
    #[serde(rename = "VersionId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
}

/// UploadPartCopy response
#[derive(Serialize)]
#[serde(rename = "CopyPartResult")]
struct CopyPartResult {
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "LastModified")]
    last_modified: String,
}

/// Largest part UploadPartCopy takes: it is read into memory, so it is
/// held to the single-PUT limit.
const MAX_COPY_PART: usize = 100 * 1024 * 1024;

/// UploadPartCopy: a part of a multipart upload taken from (a range of) an
/// existing object.
///
/// It used to be an UploadPart of the request's empty body: the copy source
/// was ignored and an empty part stored, so an upload completed from such
/// parts was silently missing their data. The AWS CLI copies any object
/// over its multipart threshold this way.
async fn upload_part_copy_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
    part_number: u32,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    let (source, source_version) = copy_source_of(&headers).unwrap_or_default();
    let Some((source_bucket, source_key)) = source.split_once('/') else {
        return S3Error::xml_response(
            "InvalidArgument",
            "Invalid x-amz-copy-source format",
            StatusCode::BAD_REQUEST,
        );
    };

    // The middleware authorized writing the destination; reading the
    // source is checked here, as CopyObject does.
    if let Some(Extension(auth_result)) = &auth
        && let Some(deny_response) = crate::authz::authorize(
            &state,
            auth_result,
            &crate::authz::AuthzRequest {
                method: &Method::GET,
                action: "s3:GetObject",
                bucket: source_bucket,
                key: Some(source_key),
                scope_key: source_key,
                headers: Some(&headers),
            },
        )
        .await
    {
        return deny_response;
    }
    let mut meta_client = state.meta_client.clone();
    if let Err(resp) = check_copy_sse(
        &state,
        &mut meta_client,
        source_bucket,
        source_key,
        source_version.as_deref(),
        &bucket,
        &headers,
    )
    .await
    {
        return resp;
    }

    // The source range, read the way a ranged GET reads it. Stricter than a
    // GET's Range: "bytes=first-last", both given, first <= last, and within
    // the source (checked once its size is known), as S3 requires.
    let mut get_headers = copy_source_conditions(&headers);
    get_headers.extend(copy_source_customer_headers(&headers));
    let mut copy_last: Option<u64> = None;
    if let Some(range) = headers.get("x-amz-copy-source-range") {
        let bounds = range
            .to_str()
            .ok()
            .and_then(|r| r.strip_prefix("bytes="))
            .and_then(|r| r.split_once('-'))
            .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?)))
            .filter(|(a, b)| a <= b);
        let Some((_, last)) = bounds else {
            return S3Error::xml_response(
                "InvalidArgument",
                "x-amz-copy-source-range must be bytes=first-last",
                StatusCode::BAD_REQUEST,
            );
        };
        copy_last = Some(last);
        get_headers.insert(header::RANGE, range.clone());
    }
    let _ = auth;
    let got = get_object_version(
        Arc::clone(&state),
        source_bucket.to_string(),
        source_key.to_string(),
        source_version.clone(),
        get_headers,
    )
    .await;
    if !got.status().is_success() {
        return copy_condition_failed(got);
    }
    let source_size = got
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit('/').next())
        .and_then(|t| t.parse::<u64>().ok());
    if let (Some(last), Some(size)) = (copy_last, source_size)
        && last >= size
    {
        return S3Error::xml_response(
            "InvalidRange",
            "The requested range is not satisfiable",
            StatusCode::RANGE_NOT_SATISFIABLE,
        );
    }
    let data = match axum::body::to_bytes(got.into_body(), MAX_COPY_PART).await {
        Ok(b) => b,
        Err(_) => {
            return S3Error::xml_response(
                "EntityTooLarge",
                &format!("A copied part may be at most {MAX_COPY_PART} bytes"),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    // The upload's own SSE-C key, as an UploadPart to it carries.
    let mut part_headers = HeaderMap::new();
    for (name, value) in &headers {
        if name
            .as_str()
            .starts_with("x-amz-server-side-encryption-customer-")
        {
            part_headers.insert(name.clone(), value.clone());
        }
    }
    let put = upload_part_internal(
        state,
        bucket,
        key,
        upload_id,
        part_number,
        part_headers,
        data,
    )
    .await;
    if !put.status().is_success() {
        return put;
    }
    let etag = put
        .headers()
        .get("ETag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        to_xml(&CopyPartResult {
            etag,
            last_modified: timestamp_to_iso(now),
        })
        .unwrap_or_default()
    );
    // The part's encryption, as UploadPart reports it.
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml");
    for (name, value) in put.headers() {
        if name.as_str().starts_with("x-amz-server-side-encryption") {
            builder = builder.header(name, value);
        }
    }
    builder.body(Body::from(xml)).unwrap()
}

/// CopyObject response
#[derive(Serialize)]
#[serde(rename = "CopyObjectResult")]
pub struct CopyObjectResult {
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
}

/// Render a Unix timestamp as the ISO 8601 form S3 clients parse.
///
/// `i64::try_from` rather than `as i64`: the cast wrapped the whole upper half
/// of `u64` into negative times, so a timestamp that could not be a real date
/// rendered as one in 1969 instead of reaching the fallback below. A client
/// reading `LastModified` cannot tell a wrong date from a right one.
fn timestamp_to_iso(ts: u64) -> String {
    use chrono::{DateTime, Utc};
    i64::try_from(ts)
        .ok()
        .and_then(|secs| DateTime::<Utc>::from_timestamp(secs, 0))
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string())
}

/// Render a Unix timestamp as an RFC 7231 HTTP date, e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`. Same wrapping caveat as
/// [`timestamp_to_iso`].
fn timestamp_to_http_date(ts: u64) -> String {
    use chrono::{DateTime, Utc};
    i64::try_from(ts)
        .ok()
        .and_then(|secs| DateTime::<Utc>::from_timestamp(secs, 0))
        .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

/// List all buckets (GET /)
pub async fn list_buckets(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListBucketsParams>,
    auth: Option<Extension<AuthResult>>,
) -> Response {
    let tenant = auth
        .as_ref()
        .map(|Extension(a)| a.tenant.clone())
        .unwrap_or_default();

    // A bucket-scoped key must not be able to enumerate the whole namespace.
    // ListAllMyBuckets has no bucket to authorize against, so the layer lets
    // it through and the result is narrowed here instead.
    let scoped_bucket = auth.as_ref().and_then(|Extension(a)| {
        a.scope
            .as_ref()
            .filter(|s| !s.scope.is_empty())
            .map(|s| crate::authz::scope_bucket(&s.scope))
    });

    let mut client = state.meta_client.clone();

    match client
        .list_buckets(ListBucketsRequest {
            owner: String::new(),
            tenant,
        })
        .await
    {
        Ok(response) => {
            let mut buckets = response.into_inner();
            if let Some(only) = &scoped_bucket {
                buckets.buckets.retain(|b| &b.name == only);
            }
            // Pages by name: ?max-buckets=, resumed after ?continuation-token=.
            buckets.buckets.sort_by(|a, b| a.name.cmp(&b.name));
            if let Some(after) = &params.continuation_token {
                buckets.buckets.retain(|b| &b.name > after);
            }
            if let Some(prefix) = &params.prefix {
                buckets
                    .buckets
                    .retain(|b| b.name.starts_with(prefix.as_str()));
            }
            let mut continuation_token = None;
            if let Some(max) = params.max_buckets.filter(|m| *m > 0)
                && buckets.buckets.len() > max as usize
            {
                buckets.buckets.truncate(max as usize);
                continuation_token = buckets.buckets.last().map(|b| b.name.clone());
            }
            let result = ListBucketsResult {
                continuation_token,
                owner: Owner {
                    id: "objectio".to_string(),
                    display_name: "ObjectIO User".to_string(),
                },
                buckets: Buckets {
                    bucket: buckets
                        .buckets
                        .into_iter()
                        .map(|b| Bucket {
                            name: b.name,
                            creation_date: timestamp_to_iso(b.created_at),
                        })
                        .collect(),
                },
            };

            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                to_xml(&result).unwrap_or_default()
            );

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to list buckets: {}", e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

/// Create bucket or set bucket policy/versioning/lock/lifecycle
/// (PUT /{bucket} or PUT /{bucket}?policy|versioning|object-lock|lifecycle)
pub async fn create_bucket(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(params): Query<PutBucketParams>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if params.tagging.is_some() {
        return bucket_tagging_unsupported();
    }
    if params.acl.is_some() {
        return put_acl(&state, &bucket, None, &headers, &body).await;
    }
    if params.ownership_controls.is_some() {
        return put_ownership_controls(&state, &bucket, &body).await;
    }
    if let Some(refused) = acl_header_refusal(&headers) {
        return refused;
    }
    if params.policy.is_some() {
        return put_bucket_policy_internal(state, bucket, body).await;
    }
    if params.versioning.is_some() {
        return put_bucket_versioning_internal(state, bucket, body).await;
    }
    if params.object_lock.is_some() {
        return put_object_lock_config_internal(state, bucket, body).await;
    }
    if params.lifecycle.is_some() {
        return put_bucket_lifecycle_internal(state, bucket, body).await;
    }
    if params.encryption.is_some() {
        return put_bucket_encryption_internal(state, bucket, body).await;
    }

    // S3's naming rules, for a bucket created through S3.
    if let Err(e) = objectio_common::BucketName::new(bucket.clone()) {
        return S3Error::xml_response(
            "InvalidBucketName",
            &format!("The specified bucket is not valid: {e}"),
            StatusCode::BAD_REQUEST,
        );
    }

    // Check for object lock at bucket creation
    let enable_lock = headers
        .get("x-amz-bucket-object-lock-enabled")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));

    let mut client = state.meta_client.clone();

    let tenant = auth
        .as_ref()
        .map(|Extension(a)| a.tenant.clone())
        .unwrap_or_default();

    match client
        .create_bucket(CreateBucketRequest {
            name: bucket.clone(),
            // Recording the creator is what lets authorization fall back to
            // ownership when no policy speaks; the old hardcoded "default"
            // meant no bucket had an owner to fall back to.
            owner: auth
                .as_ref()
                .map(|Extension(a)| a.user_id.clone())
                .unwrap_or_default(),
            storage_class: "STANDARD".to_string(),
            region: "us-east-1".to_string(),
            tenant,
        })
        .await
    {
        Ok(_) => {
            // The authorization chain caches bucket tenant and owner; drop any
            // entry so the next request reads the newly recorded values rather
            // than anything stale.
            state.policy_cache.invalidate(&bucket);
            // Object lock needs versioning, both set before the bucket is
            // used. These errors used to be ignored, which could leave a
            // "lock" bucket unversioned (an overwrite then destroys a locked
            // object) or without the lock; such a bucket is removed again
            // and the create refused.
            if enable_lock {
                let versioned = client
                    .put_bucket_versioning(PutBucketVersioningRequest {
                        bucket: bucket.clone(),
                        state: VersioningState::VersioningEnabled.into(),
                    })
                    .await;
                let locked = match versioned {
                    Ok(_) => client
                        .put_object_lock_configuration(PutObjectLockConfigRequest {
                            bucket: bucket.clone(),
                            config: Some(ProtoObjectLockConfig {
                                enabled: true,
                                default_retention: None,
                            }),
                        })
                        .await
                        .map(drop),
                    Err(e) => Err(e),
                };
                if let Err(e) = locked {
                    error!("{bucket}: cannot set up object lock, removing the bucket: {e}");
                    let _ = client
                        .delete_bucket(DeleteBucketRequest {
                            name: bucket.clone(),
                        })
                        .await;
                    return S3Error::xml_response(
                        "ServiceUnavailable",
                        "Could not enable object lock on the new bucket; retry",
                        StatusCode::SERVICE_UNAVAILABLE,
                    );
                }
            }
            info!(
                "Created bucket: {}{}",
                bucket,
                if enable_lock {
                    " (object-lock enabled)"
                } else {
                    ""
                }
            );
            Response::builder()
                .status(StatusCode::OK)
                .header("Location", format!("/{}", bucket))
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::AlreadyExists {
                // Asked again by its owner: S3 (us-east-1) answers success
                // and leaves the bucket as it is. Anyone else: it's taken.
                let caller = auth
                    .as_ref()
                    .map(|Extension(a)| a.user_id.clone())
                    .unwrap_or_default();
                let owner = client
                    .get_bucket(GetBucketRequest {
                        name: bucket.clone(),
                    })
                    .await
                    .ok()
                    .and_then(|r| r.into_inner().bucket)
                    .map(|b| b.owner);
                if owner.is_some_and(|o| o == caller) {
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header("Location", format!("/{bucket}"))
                        .body(Body::empty())
                        .unwrap();
                }
                S3Error::xml_response(
                    "BucketAlreadyExists",
                    "The requested bucket name is not available",
                    StatusCode::CONFLICT,
                )
            } else {
                error!("Failed to create bucket: {}", e);
                S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
    }
}

/// POST bucket operations (POST /{bucket}?delete - batch delete objects)
pub async fn post_bucket(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(params): Query<PostBucketParams>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Check if this is a delete objects request
    if params.is_delete_request() {
        return delete_objects(State(state), Path(bucket), auth, headers, body).await;
    }
    if params.grep.is_some() {
        return grep_prefix_internal(state, bucket, auth, headers, body).await;
    }

    // Unknown POST operation on bucket
    S3Error::xml_response(
        "InvalidRequest",
        "Invalid POST request on bucket",
        StatusCode::BAD_REQUEST,
    )
}

/// Delete bucket or delete bucket policy (DELETE /{bucket} or DELETE /{bucket}?policy)
pub async fn delete_bucket(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(params): Query<DeleteBucketParams>,
) -> Response {
    if params.tagging.is_some() {
        return bucket_tagging_unsupported();
    }
    if params.policy.is_some() {
        return delete_bucket_policy_internal(state, bucket).await;
    }
    if params.lifecycle.is_some() {
        return delete_bucket_lifecycle_internal(state, bucket).await;
    }
    if params.encryption.is_some() {
        return delete_bucket_encryption_internal(state, bucket).await;
    }

    // Noncurrent versions and delete markers count as contents, as in S3;
    // they live only on the OSDs. Meta checks current objects itself.
    match holds_versions(&state, &bucket).await {
        Ok(false) => {}
        Ok(true) => {
            return S3Error::xml_response(
                "BucketNotEmpty",
                "The bucket you tried to delete is not empty",
                StatusCode::CONFLICT,
            );
        }
        Err(resp) => return resp,
    }

    let mut client = state.meta_client.clone();

    match client
        .delete_bucket(DeleteBucketRequest {
            name: bucket.clone(),
        })
        .await
    {
        Ok(_) => {
            info!("Deleted bucket: {}", bucket);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                S3Error::xml_response("NoSuchBucket", "Bucket not found", StatusCode::NOT_FOUND)
            } else if e.code() == tonic::Code::FailedPrecondition {
                S3Error::xml_response(
                    "BucketNotEmpty",
                    "Bucket is not empty",
                    StatusCode::CONFLICT,
                )
            } else {
                error!("Failed to delete bucket: {}", e);
                S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
    }
}

/// Whether any OSD holds a version or delete marker in `bucket`. Every
/// OSD in the listing must answer: one that can't might hold the only one.
async fn holds_versions(state: &AppState, bucket: &str) -> Result<bool, Response> {
    use objectio_proto::storage::ListObjectVersionsMetaRequest;
    let unavailable = |what: String| {
        warn!("{bucket}: cannot tell whether it is empty: {what}");
        S3Error::xml_response(
            "ServiceUnavailable",
            "Cannot check that the bucket is empty; retry",
            StatusCode::SERVICE_UNAVAILABLE,
        )
    };
    let nodes = state
        .meta_client
        .clone()
        .get_listing_nodes(GetListingNodesRequest {
            bucket: bucket.to_string(),
            include_all_states: false,
        })
        .await
        .map_err(|e| unavailable(e.to_string()))?
        .into_inner()
        .nodes;
    for node in nodes {
        let mut client = state
            .osd_pool
            .get_or_connect(&node.node_id, &node.address)
            .await
            .map_err(|e| unavailable(format!("OSD {}: {e}", node.address)))?;
        let page = client
            .list_object_versions_meta(ListObjectVersionsMetaRequest {
                bucket: bucket.to_string(),
                max_keys: 1,
                ..Default::default()
            })
            .await
            .map_err(|e| unavailable(format!("OSD {}: {e}", node.address)))?
            .into_inner();
        if !page.versions.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Head bucket (HEAD /{bucket})
pub async fn head_bucket(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
) -> Response {
    let mut client = state.meta_client.clone();

    match client.get_bucket(GetBucketRequest { name: bucket }).await {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap(),
    }
}

/// Head bucket with trailing slash (s3fs compatibility)
/// Route: HEAD /{bucket}/
pub async fn head_bucket_trailing(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
) -> Response {
    head_bucket(State(state), Path(bucket)).await
}

/// List objects with trailing slash (s3fs compatibility)
/// Route: GET /{bucket}/
pub async fn list_objects_trailing(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(params): Query<ListObjectsParams>,
    auth: Option<Extension<AuthResult>>,
) -> Response {
    list_objects(State(state), Path(bucket), Query(params), auth).await
}

/// List objects or get bucket policy (GET /{bucket} or GET /{bucket}?policy)
pub async fn list_objects(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(params): Query<ListObjectsParams>,
    // Authorized by `authz::authz_layer` before this handler runs.
    _auth: Option<Extension<AuthResult>>,
) -> Response {
    let mut params = params;
    let max_keys = match params.max_keys.as_deref().map(str::parse::<i64>) {
        None => None,
        Some(Ok(n)) if n >= 0 => Some(u32::try_from(n).unwrap_or(u32::MAX)),
        Some(_) => {
            return S3Error::xml_response(
                "InvalidArgument",
                "max-keys must be a non-negative integer",
                StatusCode::BAD_REQUEST,
            );
        }
    };
    params.max_keys = max_keys.map(|m| m.to_string());
    if params.tagging.is_some() {
        return bucket_tagging_unsupported();
    }
    if params.acl.is_some() {
        return get_acl(&state, &bucket, None, None).await;
    }
    if params.ownership_controls.is_some() {
        return get_ownership_controls(&state, &bucket).await;
    }
    if params.is_policy_request() {
        return get_bucket_policy_internal(state, bucket).await;
    }
    if params.versioning.is_some() {
        return get_bucket_versioning_internal(state, bucket).await;
    }
    if params.object_lock.is_some() {
        return get_object_lock_config_internal(state, bucket).await;
    }
    if params.lifecycle.is_some() {
        return get_bucket_lifecycle_internal(state, bucket).await;
    }
    if params.encryption.is_some() {
        return get_bucket_encryption_internal(state, bucket).await;
    }
    // ?uploads is ListMultipartUploads, NOT an object listing. Falling
    // through to the object listing here hands clients (geesefs aborts
    // stale uploads at mount) a truncated ListBucketResult whose
    // NextContinuationToken they cannot use as a key marker, so they
    // re-issue the same request forever.
    if params.uploads.is_some() {
        return list_multipart_uploads_internal(state, bucket, &params).await;
    }
    if params.versions.is_some() {
        return list_object_versions_internal(
            state,
            bucket,
            VersionListing {
                prefix: params.prefix.clone().unwrap_or_default(),
                delimiter: params.delimiter.clone().filter(|d| !d.is_empty()),
                key_marker: params.key_marker.clone().unwrap_or_default(),
                version_id_marker: params.version_id_marker.clone().unwrap_or_default(),
                max_keys: max_keys.unwrap_or(1000).min(1000),
                url_encoded: params.encoding_type.as_deref() == Some("url"),
            },
        )
        .await;
    }

    let prefix = params.prefix.clone().unwrap_or_default();
    // An empty delimiter is no delimiter, and isn't echoed.
    let delimiter = params.delimiter.clone().filter(|d| !d.is_empty());
    let max_keys = max_keys.unwrap_or(1000);
    let continuation_token = params.continuation_token.as_deref();
    let is_v2 = params.list_type.as_deref() == Some("2");
    // V2 resumes from ?start-after=, V1 from ?marker=. A continuation
    // token, when present, outranks both (Meta applies that precedence).
    let start_after = if is_v2 {
        params.start_after.clone().unwrap_or_default()
    } else {
        params.marker.clone().unwrap_or_default()
    };

    // First verify bucket exists
    let mut client = state.meta_client.clone();
    let bucket_owner = match client
        .get_bucket(GetBucketRequest {
            name: bucket.clone(),
        })
        .await
    {
        Ok(resp) => resp.into_inner().bucket.map(|b| b.owner),
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                return S3Error::xml_response(
                    "NoSuchBucket",
                    "The specified bucket does not exist",
                    StatusCode::NOT_FOUND,
                );
            }
            error!("Failed to get bucket: {}", e);
            return S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };
    let echo = || ListingEcho {
        continuation_token: params.continuation_token.clone(),
        owner: bucket_owner.clone(),
        fetch_owner: params.fetch_owner.as_deref() == Some("true"),
    };

    // Prefer Meta's serializable listing index. Fall back to the
    // scatter-gather path only when Meta has no entries for this
    // bucket — happens during the transition window before the
    // OBJECT_LISTINGS table is populated for pre-migration objects.
    let mut meta_client = state.meta_client.clone();
    {
        use objectio_proto::metadata::ListObjectsRequest as MetaListReq;
        let meta_req = MetaListReq {
            bucket: bucket.clone(),
            prefix: prefix.clone(),
            delimiter: delimiter.clone().unwrap_or_default(),
            start_after: start_after.clone(),
            continuation_token: continuation_token
                .map(ToString::to_string)
                .unwrap_or_default(),
            max_keys,
            include_versions: false,
        };
        if let Ok(resp) = meta_client.list_objects(meta_req).await {
            let r = resp.into_inner();
            if !r.entries.is_empty() || !r.common_prefixes.is_empty() {
                let contents: Vec<ObjectContent> = r
                    .entries
                    .into_iter()
                    .map(|e| ObjectContent {
                        key: e.key,
                        last_modified: timestamp_to_iso(e.modified_at),
                        etag: e.etag,
                        size: e.size,
                        storage_class: if e.storage_class.is_empty() {
                            "STANDARD".into()
                        } else {
                            e.storage_class
                        },
                        owner: None,
                    })
                    .collect();
                let common_prefixes: Vec<CommonPrefix> = r
                    .common_prefixes
                    .into_iter()
                    .map(|p| CommonPrefix { prefix: p })
                    .collect();
                let key_count = contents.len() + common_prefixes.len();
                let mut result = ListBucketResult {
                    name: bucket.clone(),
                    prefix: prefix.clone(),
                    delimiter: delimiter.clone(),
                    marker: None,
                    next_marker: None,
                    start_after: None,
                    continuation_token: None,
                    encoding_type: params.encoding_type.clone(),
                    max_keys,
                    is_truncated: r.is_truncated,
                    next_continuation_token: if r.next_continuation_token.is_empty() {
                        None
                    } else {
                        Some(r.next_continuation_token)
                    },
                    key_count: Some(key_count as u32),
                    common_prefixes,
                    contents,
                };
                apply_listing_echo(
                    &mut result,
                    is_v2,
                    params.marker.clone(),
                    params.start_after.clone(),
                    echo(),
                );
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                    to_xml(&result).unwrap_or_default()
                );
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/xml")
                    .body(Body::from(xml))
                    .unwrap();
            }
        }
    }

    // Fallback: scatter-gather for buckets whose objects predate the
    // ObjectListings migration.
    match state
        .scatter_gather
        .list_objects(
            &mut meta_client,
            &bucket,
            &prefix,
            max_keys,
            continuation_token,
            &start_after,
        )
        .await
    {
        Ok(list_result) => {
            // Process delimiter to extract common prefixes
            let (contents, common_prefixes) = if let Some(ref delim) = delimiter {
                let mut prefixes_set = std::collections::BTreeSet::new();
                let mut filtered_contents = Vec::new();

                for obj in list_result.objects {
                    // Get the part of the key after the prefix
                    let key_after_prefix = if obj.key.starts_with(&prefix) {
                        &obj.key[prefix.len()..]
                    } else {
                        &obj.key[..]
                    };

                    // Check if the key contains the delimiter after the prefix
                    if let Some(delim_pos) = key_after_prefix.find(delim.as_str()) {
                        // Extract the common prefix (prefix + everything up to and including delimiter)
                        let common_prefix =
                            format!("{}{}{}", prefix, &key_after_prefix[..delim_pos], delim);
                        prefixes_set.insert(common_prefix);
                    } else {
                        // No delimiter found - include this object in contents
                        filtered_contents.push(ObjectContent {
                            key: obj.key,
                            last_modified: timestamp_to_iso(obj.modified_at),
                            etag: obj.etag,
                            size: obj.size,
                            storage_class: obj.storage_class,
                            owner: None,
                        });
                    }
                }

                let common_prefixes: Vec<CommonPrefix> = prefixes_set
                    .into_iter()
                    .map(|p| CommonPrefix { prefix: p })
                    .collect();

                (filtered_contents, common_prefixes)
            } else {
                // No delimiter - return all objects
                let contents = list_result
                    .objects
                    .into_iter()
                    .map(|o| ObjectContent {
                        key: o.key,
                        last_modified: timestamp_to_iso(o.modified_at),
                        etag: o.etag,
                        size: o.size,
                        storage_class: o.storage_class,
                        owner: None,
                    })
                    .collect();
                (contents, Vec::new())
            };

            let key_count = contents.len() + common_prefixes.len();
            let mut result = ListBucketResult {
                name: bucket,
                prefix,
                delimiter,
                marker: None,
                next_marker: None,
                start_after: None,
                continuation_token: None,
                encoding_type: params.encoding_type.clone(),
                max_keys,
                is_truncated: list_result.is_truncated,
                next_continuation_token: list_result.next_continuation_token,
                key_count: Some(key_count as u32),
                common_prefixes,
                contents,
            };
            apply_listing_echo(
                &mut result,
                is_v2,
                params.marker.clone(),
                params.start_after.clone(),
                echo(),
            );

            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                to_xml(&result).unwrap_or_default()
            );

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            use crate::scatter_gather::ScatterGatherError;
            match e {
                ScatterGatherError::NoNodesAvailable => {
                    warn!("No OSD nodes available for listing");
                    // Return empty result if no nodes available (cluster might be starting up)
                    let mut result = ListBucketResult {
                        name: bucket,
                        prefix,
                        delimiter,
                        marker: None,
                        next_marker: None,
                        start_after: None,
                        continuation_token: None,
                        encoding_type: params.encoding_type.clone(),
                        max_keys,
                        is_truncated: false,
                        next_continuation_token: None,
                        key_count: Some(0),
                        common_prefixes: vec![],
                        contents: vec![],
                    };
                    apply_listing_echo(
                        &mut result,
                        is_v2,
                        params.marker.clone(),
                        params.start_after.clone(),
                        echo(),
                    );
                    let xml = format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                        to_xml(&result).unwrap_or_default()
                    );
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/xml")
                        .body(Body::from(xml))
                        .unwrap()
                }
                ScatterGatherError::InvalidToken
                | ScatterGatherError::TokenSignatureMismatch
                | ScatterGatherError::TopologyChanged { .. } => S3Error::xml_response(
                    "InvalidArgument",
                    "Invalid continuation token",
                    StatusCode::BAD_REQUEST,
                ),
                _ => {
                    error!("Scatter-gather list failed: {}", e);
                    S3Error::xml_response(
                        "InternalError",
                        &e.to_string(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    )
                }
            }
        }
    }
}

/// Put object (PUT /{bucket}/{key})
/// Refuse a CopyObject whose source or destination uses SSE-C, which needs
/// copy-source customer-key headers not wired through yet; and one whose
/// source is not there. Everything else is copied by `copy_object_data`.
#[allow(clippy::result_large_err)]
async fn check_copy_sse(
    state: &Arc<AppState>,
    meta_client: &mut MetadataServiceClient<Channel>,
    source_bucket: &str,
    source_key: &str,
    source_version: Option<&str>,
    dest_bucket: &str,
    copy_headers: &HeaderMap,
) -> Result<(), Response> {
    // Peek source's SSE state via its ObjectMeta. We need the primary OSD
    // for the source to read the meta; do a cheap GetPlacement.
    let src_placement = meta_client
        .get_placement(GetPlacementRequest {
            bucket: source_bucket.to_string(),
            key: source_key.to_string(),
            size: 0,
            storage_class: "STANDARD".to_string(),
        })
        .await
        .map_err(|e| {
            S3Error::xml_response(
                "NoSuchKey",
                &format!("The specified source does not exist: {e}"),
                StatusCode::NOT_FOUND,
            )
        })?
        .into_inner();
    if src_placement.nodes.is_empty() {
        return Err(S3Error::xml_response(
            "InternalError",
            "No storage nodes available for source",
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    }
    let found = match source_version {
        Some(v) => {
            find_version(
                &state.osd_pool,
                &src_placement.nodes,
                source_bucket,
                source_key,
                v,
            )
            .await
        }
        None => {
            get_object_meta_from_any(
                &state.osd_pool,
                &src_placement.nodes,
                source_bucket,
                source_key,
            )
            .await
        }
    };
    let source_meta = match found {
        Ok(Some(m)) => m,
        Ok(None) => {
            return Err(S3Error::xml_response(
                "NoSuchKey",
                "The specified source does not exist",
                StatusCode::NOT_FOUND,
            ));
        }
        Err(e) => {
            return Err(S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    // An SSE-C source is read with its key, from the copy-source-*
    // customer headers, checked as a GET checks it.
    if let Some(refused) =
        sse_c_read_refusal(&copy_source_customer_headers(copy_headers), &source_meta)
    {
        return Err(refused);
    }
    // The destination's encryption headers must agree with each other.
    if let Some(refused) = sse_header_conflict(copy_headers) {
        return Err(refused);
    }
    resolve_sse_decision(meta_client, dest_bucket, Some(copy_headers)).await?;
    Ok(())
}

/// A copy that references the source's stripes instead of copying their
/// bytes. `None` when it does not apply — either side encrypted, or the
/// source changed or let its stripes go mid-copy — for the caller to copy
/// the bytes instead.
///
/// The order is what makes it safe. The copy is registered as a referrer
/// of the source's stripes first, and the source then read again: if it is
/// still the same object, its delete has not happened yet, and when it
/// does, meta's registry keeps the stripes for the copy. If it is not, the
/// source's stripes may already be freed, so the copy backs out.
async fn copy_by_reference(
    state: &Arc<AppState>,
    dest_bucket: &str,
    dest_key: &str,
    source_bucket: &str,
    source_key: &str,
    copy_headers: &HeaderMap,
) -> Option<Response> {
    use objectio_proto::metadata::ShareStripesRequest;
    let mut meta_client = state.meta_client.clone();

    let src_placement = meta_client
        .get_placement(GetPlacementRequest {
            bucket: source_bucket.to_string(),
            key: source_key.to_string(),
            size: 0,
            storage_class: "STANDARD".to_string(),
        })
        .await
        .ok()?
        .into_inner();
    let source = get_object_meta_from_any(
        &state.osd_pool,
        &src_placement.nodes,
        source_bucket,
        source_key,
    )
    .await
    .ok()??;
    let encrypted = SseAlgorithm::try_from(source.encryption_algorithm)
        .is_ok_and(|a| a != SseAlgorithm::SseNone);
    if source.is_delete_marker
        || encrypted
        || source.object_id.is_empty()
        || asks_sse_c(copy_headers)
    {
        return None;
    }
    if resolve_sse_decision(&mut meta_client, dest_bucket, Some(copy_headers))
        .await
        .ok()?
        .is_some()
    {
        return None;
    }

    let new_id = Uuid::new_v4().as_bytes().to_vec();
    let mut stripes = source.stripes.clone();
    for stripe in &mut stripes {
        if stripe.object_id.is_empty() {
            stripe.object_id.clone_from(&source.object_id);
        }
    }
    let stripe_ids: Vec<Vec<u8>> = stripes
        .iter()
        .map(|s| s.object_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    // On the way out after sharing: the copy lets go again. If the source
    // has gone meanwhile this frees the stripes, as its delete would have.
    let back_out = |state: &Arc<AppState>, what: String| {
        let mut targets = stripe_targets(&stripes);
        for t in &mut targets {
            t.owner.clone_from(&new_id);
        }
        spawn_reclaim(state, targets, Reclaim::FailedWrite, what);
    };

    if !stripe_ids.is_empty() {
        match meta_client
            .share_stripes(ShareStripesRequest {
                stripe_ids: stripe_ids.clone(),
                owner: source.object_id.clone(),
                sharer: new_id.clone(),
            })
            .await
        {
            Ok(_) => {}
            Err(e) if e.code() == tonic::Code::FailedPrecondition => return None,
            Err(e) => {
                return Some(S3Error::xml_response(
                    "ServiceUnavailable",
                    &format!("could not register the copy: {}", e.message()),
                    StatusCode::SERVICE_UNAVAILABLE,
                ));
            }
        }
        let still = get_object_meta_from_any(
            &state.osd_pool,
            &src_placement.nodes,
            source_bucket,
            source_key,
        )
        .await;
        if !matches!(still, Ok(Some(ref m)) if m.object_id == source.object_id) {
            back_out(state, format!("copy of {source_bucket}/{source_key}"));
            return None;
        }
    }

    // The destination, as a PUT of it would be.
    let dest_placement = match meta_client
        .get_placement(GetPlacementRequest {
            bucket: dest_bucket.to_string(),
            key: dest_key.to_string(),
            size: source.size,
            storage_class: "STANDARD".to_string(),
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            back_out(state, format!("copy to {dest_bucket}/{dest_key}"));
            return Some(S3Error::xml_response(
                "InternalError",
                &format!("Failed to get placement: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };
    let versioning_enabled = match bucket_versioning(&mut meta_client, dest_bucket).await {
        Ok(v) => v == VersioningState::VersioningEnabled,
        Err(resp) => {
            back_out(state, format!("copy to {dest_bucket}/{dest_key}"));
            return Some(resp);
        }
    };
    // A copy is a new object: its lock is the request's or the bucket's
    // default, never the source's.
    let (lock_retention, lock_hold) =
        match object_lock_for_write(&mut meta_client, dest_bucket, copy_headers).await {
            Ok(lock) => lock,
            Err(resp) => {
                back_out(state, format!("copy to {dest_bucket}/{dest_key}"));
                return Some(resp);
            }
        };
    let version_id = if versioning_enabled {
        new_version_id()
    } else {
        String::new()
    };
    let replace = copy_headers
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("REPLACE"));
    let (content_type, user_metadata) = if replace {
        (
            copy_headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string(),
            extract_user_metadata(copy_headers),
        )
    } else {
        (source.content_type.clone(), source.user_metadata.clone())
    };
    let tags = if replaces_tags(copy_headers) {
        match tagging_header(copy_headers) {
            Ok(t) => t,
            Err(resp) => return Some(resp),
        }
    } else {
        source.tags.clone()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let object_meta = ObjectMeta {
        bucket: dest_bucket.to_string(),
        key: dest_key.to_string(),
        object_id: new_id.clone(),
        size: source.size,
        content_type: content_type.clone(),
        etag: source.etag.clone(),
        created_at: now,
        modified_at: now,
        stripes: stripes.clone(),
        user_metadata,
        version_id: version_id.clone(),
        storage_class: source.storage_class.clone(),
        inline_data: source.inline_data.clone(),
        checksum: source.checksum.clone(),
        tags,
        retention: lock_retention,
        legal_hold: lock_hold,
        ..Default::default()
    };

    let listing_req = objectio_proto::metadata::CreateObjectRequest {
        bucket: dest_bucket.to_string(),
        key: dest_key.to_string(),
        size: source.size,
        content_type,
        etag: source.etag.clone(),
        user_metadata: object_meta.user_metadata.clone(),
        stripes: stripes.clone(),
        object_id: new_id.clone(),
        pg_id: dest_placement.pg_id,
        pool: dest_placement.pool.clone(),
        home_osd_ids: home_of(&dest_placement.nodes),
        ..Default::default()
    };
    let new_object = referenced_object_ids(&object_meta);
    let mut listing_client = state.meta_client.clone();
    let mut unlist_client = state.meta_client.clone();
    let committed = commit_object(
        put_object_meta_to_all(
            &state.osd_pool,
            &dest_placement.nodes,
            dest_bucket,
            dest_key,
            object_meta,
            versioning_enabled,
            &[],
        ),
        async { listing_client.create_object(listing_req).await.map(drop) },
        || async {
            use objectio_proto::metadata::DeleteObjectRequest as MetaDelReq;
            let _ = unlist_client
                .delete_object(MetaDelReq {
                    bucket: dest_bucket.to_string(),
                    key: dest_key.to_string(),
                    version_id: String::new(),
                    forget_home: false,
                })
                .await;
        },
    )
    .await;

    let what = format!("{dest_bucket}/{dest_key}");
    match &committed {
        Ok((displaced, _)) => {
            settle_commit(
                state,
                Ok(displaced.as_slice()),
                Vec::new(),
                &new_object,
                versioning_enabled,
                &what,
            );
            // A copy onto itself replaced an object that used the same
            // stripes: it lets go of them, though they are not free.
            if !versioning_enabled
                && let Some(old) = displaced.iter().find_map(|d| d.replaced.as_ref())
                && old.object_id != new_id
            {
                let kept: Vec<Vec<u8>> = old
                    .stripes
                    .iter()
                    .map(|s| s.object_id.clone())
                    .filter(|id| new_object.contains(id))
                    .collect();
                let mut meta = state.meta_client.clone();
                crate::osd_pool::release_only(&mut meta, &old.object_id, kept).await;
            }
        }
        Err(e) => {
            error!("CopyObject by reference: failed to store {what}: {e}");
            back_out(state, what);
            return Some(S3Error::xml_response(
                "InternalError",
                &format!("Failed to store object metadata: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    }
    if let Ok((_, Committed::Unlisted(e))) = &committed {
        warn!(
            "create_object on meta failed for {what} ({e}); readable by key, not listed until repair"
        );
    }

    info!(
        "CopyObject: {source_bucket}/{source_key} -> {what} ({} bytes, by reference)",
        source.size
    );
    crate::gateway_metrics::record_copy("reference", source.size);
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        to_xml(&CopyObjectResult {
            etag: source.etag.clone(),
            last_modified: timestamp_to_iso(now),
        })
        .unwrap_or_default()
    );
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .header("ETag", &source.etag);
    if !version_id.is_empty() {
        builder = builder.header("x-amz-version-id", &version_id);
    }
    Some(builder.body(Body::from(xml)).unwrap())
}

/// CopyObject. Where neither side is encrypted, the copy shares the
/// source's stripes ([`copy_by_reference`]): no bytes are read or written,
/// whatever the size. Otherwise, or if sharing is refused, it reads the
/// source through the GET handler (reconstruction and decryption included)
/// and writes it through the PUT handler, so the copy has stripes of its
/// own and the destination's SSE settings apply.
///
/// Sharing is safe because meta now counts who references a shared stripe
/// (`ShareStripes`/`ReleaseStripes`): a copy that shared the source's shards
/// used to lose its data when the source was deleted -- and a rename through
/// an S3 FUSE mount is a copy then a delete. Buffers the object in memory, as the rest of the PUT
/// path does; streaming copies are a separate improvement.
///
/// Metadata follows S3's `x-amz-metadata-directive`: COPY (the default) keeps
/// the source's content type, standard headers and user metadata; REPLACE
/// takes them from the request.
async fn copy_object_data(
    state: Arc<AppState>,
    dest_bucket: String,
    dest_key: String,
    source: CopySource,
    auth: Option<Extension<AuthResult>>,
    copy_headers: HeaderMap,
) -> Response {
    let CopySource {
        bucket: source_bucket,
        key: source_key,
        version: source_version,
    } = source;
    debug!(
        "CopyObject: {}/{} -> {}/{}",
        source_bucket, source_key, dest_bucket, dest_key
    );

    // By reference only from the current version (it re-reads the source's
    // current object to know the stripes are still held), and without
    // conditions on the source, which the read below checks.
    let source_conditions = copy_source_conditions(&copy_headers);
    // Nor when the copy is to be encrypted with a customer key: sharing the
    // source's stripes stored it in the clear, an SSE-C copy unencrypted.
    if source_version.is_none()
        && source_conditions.is_empty()
        && !asks_sse_c(&copy_headers)
        && let Some(resp) = copy_by_reference(
            &state,
            &dest_bucket,
            &dest_key,
            &source_bucket,
            &source_key,
            &copy_headers,
        )
        .await
    {
        return resp;
    }

    // 1. Read the source object as plaintext. The existing GET handler takes
    //    care of reconstruction + decryption.
    let mut source_read = source_conditions;
    source_read.extend(copy_source_customer_headers(&copy_headers));
    let get_resp = get_object_version(
        Arc::clone(&state),
        source_bucket.clone(),
        source_key.clone(),
        source_version.clone(),
        source_read,
    )
    .await;
    if !get_resp.status().is_success() {
        return copy_condition_failed(get_resp);
    }
    let (source_parts, body) = get_resp.into_parts();
    let plaintext = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            error!("CopyObject: failed to buffer source: {e}");
            return S3Error::xml_response(
                "InternalError",
                "Failed to buffer the source object",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    // 2. Build headers for the destination PUT. SSE settings come from the
    //    copy request; the object's own metadata from the source unless the
    //    request says REPLACE. x-amz-copy-source is left out, so the PUT
    //    handler does not recurse back into CopyObject.
    let replace = copy_headers
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("REPLACE"));
    let metadata_from = if replace {
        &copy_headers
    } else {
        &source_parts.headers
    };
    let mut put_headers = HeaderMap::new();
    for (name, value) in copy_headers.iter() {
        if name
            .as_str()
            .to_lowercase()
            .starts_with("x-amz-server-side-encryption")
        {
            put_headers.insert(name.clone(), value.clone());
        }
    }
    for (name, value) in metadata_from.iter() {
        if is_object_metadata_header(name.as_str()) {
            put_headers.insert(name.clone(), value.clone());
        }
    }
    // The copy's own lock, if the request asks for one.
    for (name, value) in copy_headers.iter() {
        if name.as_str().starts_with("x-amz-object-lock-") {
            put_headers.insert(name.clone(), value.clone());
        }
    }
    // Tags: the request's under REPLACE, otherwise the source's, which a
    // GET response only counts (x-amz-tagging-count).
    let tagging = if replaces_tags(&copy_headers) {
        copy_headers.get("x-amz-tagging").cloned()
    } else {
        let source_meta = match &source_version {
            Some(v) => {
                match get_placement_nodes_for_object(&state, &source_bucket, &source_key).await {
                    Ok(nodes) => {
                        match find_version(&state.osd_pool, &nodes, &source_bucket, &source_key, v)
                            .await
                        {
                            Ok(Some(m)) => Ok((m, nodes)),
                            _ => Err(S3Error::xml_response(
                                "NoSuchVersion",
                                "The specified version does not exist.",
                                StatusCode::NOT_FOUND,
                            )),
                        }
                    }
                    Err(resp) => Err(resp),
                }
            }
            None => object_meta_for_update(&state, &source_bucket, &source_key).await,
        };
        match source_meta {
            Ok((src, _)) if !src.tags.is_empty() => {
                http::HeaderValue::from_str(&encode_tagging(&src.tags)).ok()
            }
            Ok(_) => None,
            Err(resp) => return resp,
        }
    };
    if let Some(v) = tagging {
        put_headers.insert("x-amz-tagging", v);
    }

    // 3. Re-PUT through the regular handler. Encryption/erasure-coding/
    //    metadata writing all happen through the same code path single-part
    //    PUTs use, so SSE transitions "just work".
    let copied_bytes = plaintext.len();
    let put_resp = put_object(
        State(Arc::clone(&state)),
        Path((dest_bucket.clone(), dest_key.clone())),
        auth,
        put_headers,
        plaintext,
    )
    .await;
    if !put_resp.status().is_success() {
        return put_resp;
    }
    crate::gateway_metrics::record_copy("bytes", copied_bytes as u64);

    // 4. CopyObject wants a CopyObjectResult XML body, not the PUT's empty
    //    response. ETag comes from the PUT we just issued.
    let etag = put_resp
        .headers()
        .get("ETag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let sse_headers: Vec<(http::HeaderName, http::HeaderValue)> = put_resp
        .headers()
        .iter()
        .filter(|(k, _)| k.as_str().starts_with("x-amz-server-side-encryption"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let now_millis_display = timestamp_to_iso(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        to_xml(&CopyObjectResult {
            etag: etag.clone(),
            last_modified: now_millis_display,
        })
        .unwrap_or_default()
    );
    info!(
        "CopyObject: {}/{} -> {}/{} ({} bytes, copied)",
        source_bucket, source_key, dest_bucket, dest_key, copied_bytes,
    );
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .header("ETag", &etag);
    for (k, v) in sse_headers {
        builder = builder.header(k, v);
    }
    builder.body(Body::from(xml)).unwrap()
}

/// Whether a header is part of what an object carries -- what a copy keeps
/// from its source, or takes from the request under REPLACE.
fn is_object_metadata_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("x-amz-meta-")
        || matches!(
            lower.as_str(),
            "content-type"
                | "content-encoding"
                | "content-disposition"
                | "content-language"
                | "cache-control"
                | "expires"
        )
}

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

/// Hand a body just written to `bucket` to the dedup dry-run, when the
/// bucket's policy asks for one. Encrypted bodies never deduplicate (their
/// ciphertext differs per object by design), and inline-sized ones are not
/// what dedup is for; both are counted as skipped.
fn dedup_dry_run(
    state: &AppState,
    bucket: &str,
    placement: &objectio_proto::metadata::GetPlacementResponse,
    body: &Bytes,
    encrypted: bool,
) {
    use objectio_proto::metadata::DedupMode;
    if !matches!(placement.dedup_mode(), DedupMode::DryRun | DedupMode::On) || body.is_empty() {
        return;
    }
    if encrypted {
        crate::gateway_metrics::record_dedup_skipped("encrypted");
    } else if body.len() <= state.inline_max_size {
        crate::gateway_metrics::record_dedup_skipped("inline");
    } else {
        state
            .dedup
            .submit(bucket, &placement.dedup_domain, body.clone());
    }
}

/// Replicas that must be written before a replicated write is
/// acknowledged: two — the copy and a spare — or one in a pool that keeps
/// only one. Same reasoning as [`write_quorum`].
const fn replica_quorum(replicas: usize) -> usize {
    if replicas < 2 { replicas } else { 2 }
}

/// How a PUT's two commits ended, when the one that decides it succeeded.
#[derive(Debug, PartialEq, Eq)]
enum Committed<E> {
    /// Readable by key and listed.
    Both,
    /// Readable by key, but not in `ListObjects` until repair: the listing
    /// commit failed with this.
    Unlisted(E),
}

/// Run a PUT's two commits at the same time: the object's ObjectMeta on the
/// OSDs (what GET reads) and its entry in Meta's Raft listing index (what
/// `ListObjects` reads). Neither needs the other.
///
/// The ObjectMeta commit decides the outcome. If it fails the PUT fails, and
/// a listing entry that did land is taken out again with `unlist`, so the
/// listing never shows an object GET cannot read. A failed listing commit
/// alone does not fail the PUT: the data landed and is readable by key.
async fn commit_object<T, ME, LE, U>(
    object_meta: impl Future<Output = Result<T, ME>>,
    listing: impl Future<Output = Result<(), LE>>,
    unlist: impl FnOnce() -> U,
) -> Result<(T, Committed<LE>), ME>
where
    U: Future<Output = ()>,
{
    match tokio::join!(object_meta, listing) {
        (Ok(t), Ok(())) => Ok((t, Committed::Both)),
        (Ok(t), Err(e)) => Ok((t, Committed::Unlisted(e))),
        (Err(e), listed) => {
            if listed.is_ok() {
                unlist().await;
            }
            Err(e)
        }
    }
}

/// A GET or HEAD's conditions on `object` (RFC 7232 order): 412 when
/// If-Match fails, or If-Unmodified-Since without an If-Match; 304 (with
/// the ETag) when If-None-Match matches, or If-Modified-Since without an
/// If-None-Match. They used to be ignored: every conditional read was 200.
fn read_preconditions(headers: &HeaderMap, object: &ObjectMeta) -> Option<Response> {
    let get = |name: header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
    let etag = object.etag.trim_matches('"');
    let etag_in = |list: &str| {
        list.split(',')
            .map(|t| t.trim().trim_start_matches("W/").trim_matches('"'))
            .any(|t| t == "*" || t == etag)
    };
    let date = |v: &str| {
        chrono::DateTime::parse_from_rfc2822(v)
            .ok()
            .and_then(|d| u64::try_from(d.timestamp()).ok())
    };
    let failed = || {
        S3Error::xml_response(
            "PreconditionFailed",
            "At least one of the pre-conditions you specified did not hold",
            StatusCode::PRECONDITION_FAILED,
        )
    };
    match get(header::IF_MATCH) {
        Some(m) if !etag_in(m) => return Some(failed()),
        Some(_) => {}
        None => {
            if get(header::IF_UNMODIFIED_SINCE)
                .and_then(date)
                .is_some_and(|since| object.modified_at > since)
            {
                return Some(failed());
            }
        }
    }
    let not_modified = match get(header::IF_NONE_MATCH) {
        Some(m) => etag_in(m),
        None => get(header::IF_MODIFIED_SINCE)
            .and_then(date)
            .is_some_and(|since| object.modified_at <= since),
    };
    not_modified.then(|| {
        Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &object.etag)
            .header(
                header::LAST_MODIFIED,
                timestamp_to_http_date(object.modified_at),
            )
            .body(Body::empty())
            .unwrap()
    })
}

/// The newest version of `bucket/key` that is an object, not a delete
/// marker, from the first of `nodes` that answers.
async fn newest_object(
    pool: &OsdPool,
    nodes: &[objectio_proto::metadata::NodePlacement],
    bucket: &str,
    key: &str,
) -> Option<ObjectMeta> {
    use objectio_proto::storage::ListObjectVersionsMetaRequest;
    for node in nodes {
        let Ok(mut client) = pool.get_client_for_placement(node).await else {
            continue;
        };
        if let Ok(resp) = client
            .list_object_versions_meta(ListObjectVersionsMetaRequest {
                bucket: bucket.to_string(),
                prefix: key.to_string(),
                // The key itself, first: its versions come in one page.
                key_marker: key.to_string(),
                version_id_marker: "-".to_string(),
                max_keys: 1,
            })
            .await
        {
            return resp
                .into_inner()
                .versions
                .into_iter()
                .filter(|v| v.key == key && !v.is_delete_marker)
                .max_by(|a, b| version_age(a).cmp(&version_age(b)));
        }
    }
    None
}

/// A conditional DELETE: the object it acts on must have this ETag ("*":
/// any), last-modified time and size.
struct DeleteCondition {
    etag: Option<String>,
    modified: Option<String>,
    size: Option<String>,
}

impl DeleteCondition {
    fn from_headers(headers: &HeaderMap) -> Self {
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_string())
        };
        Self {
            etag: get("if-match"),
            modified: get("x-amz-if-match-last-modified-time"),
            size: get("x-amz-if-match-size"),
        }
    }

    const fn is_set(&self) -> bool {
        self.etag.is_some() || self.modified.is_some() || self.size.is_some()
    }

    fn holds(&self, target: &ObjectMeta) -> bool {
        let etag_ok = self
            .etag
            .as_deref()
            .is_none_or(|e| e == "*" || e.trim_matches('"') == target.etag.trim_matches('"'));
        // An HTTP date in the header; ISO 8601 in a DeleteObjects body.
        let modified_ok = self.modified.as_deref().is_none_or(|m| {
            chrono::DateTime::parse_from_rfc2822(m)
                .or_else(|_| chrono::DateTime::parse_from_rfc3339(m))
                .ok()
                .and_then(|d| u64::try_from(d.timestamp()).ok())
                .is_some_and(|t| t == target.modified_at)
        });
        let size_ok = self
            .size
            .as_deref()
            .is_none_or(|s| s.parse::<u64>().is_ok_and(|s| s == target.size));
        etag_ok && modified_ok && size_ok
    }
}

/// 416 InvalidRange, with the object's size in `Content-Range` as S3 sends.
fn range_not_satisfiable(size: u64) -> Response {
    let mut resp = S3Error::xml_response(
        "InvalidRange",
        "The requested range is not satisfiable",
        StatusCode::RANGE_NOT_SATISFIABLE,
    );
    if let Ok(v) = header::HeaderValue::from_str(&format!("bytes */{size}")) {
        resp.headers_mut().insert(header::CONTENT_RANGE, v);
    }
    resp
}

// ── ACLs: bucket owner enforced ──────────────────────────────────────────
//
// As AWS has it by default since 2023 (Object Ownership "BucketOwnerEnforced"):
// the bucket's owner owns every object in it with FULL_CONTROL, ACLs are
// read-only in effect, and access is granted by IAM and bucket policies
// only. An ACL that says just that is accepted (it changes nothing); any
// other is refused, so no request can make data public through an ACL.

/// The refusal S3 gives an ACL a bucket owner enforced bucket won't take.
fn acls_not_supported() -> Response {
    S3Error::xml_response(
        "AccessControlListNotSupported",
        "The bucket does not allow ACLs",
        StatusCode::BAD_REQUEST,
    )
}

/// A write's `x-amz-acl` / `x-amz-grant-*` headers asking for more than
/// the owner's FULL_CONTROL.
fn acl_header_refusal(headers: &HeaderMap) -> Option<Response> {
    let canned_ok = headers
        .get("x-amz-acl")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v == "private" || v == "bucket-owner-full-control");
    let grants = headers
        .keys()
        .any(|k| k.as_str().starts_with("x-amz-grant-"));
    (!canned_ok || grants).then(acls_not_supported)
}

/// The owner of `bucket` (who owns everything in it), or the response.
async fn bucket_owner(state: &AppState, bucket: &str) -> Result<String, Response> {
    match state
        .meta_client
        .clone()
        .get_bucket(GetBucketRequest {
            name: bucket.to_string(),
        })
        .await
    {
        Ok(r) => Ok(r.into_inner().bucket.map(|b| b.owner).unwrap_or_default()),
        Err(e) if e.code() == tonic::Code::NotFound => Err(S3Error::xml_response(
            "NoSuchBucket",
            "The specified bucket does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(e) => Err(S3Error::xml_response(
            "InternalError",
            &e.to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

/// GetBucketAcl / GetObjectAcl: the owner, with FULL_CONTROL.
async fn get_acl(
    state: &AppState,
    bucket: &str,
    key: Option<&str>,
    version_id: Option<&str>,
) -> Response {
    let owner = match bucket_owner(state, bucket).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    if let Some(key) = key {
        let nodes = match get_placement_nodes_for_object(state, bucket, key).await {
            Ok(n) => n,
            Err(resp) => return resp,
        };
        if let Err(resp) = object_to_read(state, &nodes, bucket, key, version_id).await {
            return resp;
        }
    }
    let id = quick_xml::escape::escape(&owner);
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Owner><ID>{id}</ID><DisplayName>{id}</DisplayName></Owner>\
         <AccessControlList><Grant>\
         <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
         <ID>{id}</ID><DisplayName>{id}</DisplayName></Grantee>\
         <Permission>FULL_CONTROL</Permission></Grant></AccessControlList>\
         </AccessControlPolicy>"
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(xml))
        .unwrap()
}

/// PutBucketAcl / PutObjectAcl: accepted only if it grants the owner
/// FULL_CONTROL and no one anything. It changes nothing either way. A
/// PutObjectAcl used to be taken as a PutObject: the ACL document became
/// the object's data.
async fn put_acl(
    state: &AppState,
    bucket: &str,
    key: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let owner = match bucket_owner(state, bucket).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    if let Some(key) = key {
        let nodes = match get_placement_nodes_for_object(state, bucket, key).await {
            Ok(n) => n,
            Err(resp) => return resp,
        };
        let version = headers
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok());
        if let Err(resp) = object_to_read(state, &nodes, bucket, key, version).await {
            return resp;
        }
    }
    if let Some(refused) = acl_header_refusal(headers) {
        return refused;
    }
    if !body.is_empty() && !acl_body_is_owner_only(body, &owner) {
        return acls_not_supported();
    }
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

/// Whether an `AccessControlPolicy` body grants FULL_CONTROL to `owner`
/// and nothing to anyone else.
fn acl_body_is_owner_only(body: &[u8], owner: &str) -> bool {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(body);
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut grants = 0;
    let mut grant_id: Option<String> = None;
    let mut grant_other = false;
    let mut permission = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                path.push(String::from_utf8_lossy(e.local_name().as_ref()).into_owned());
                if path.last().is_some_and(|n| n == "Grant") {
                    grant_id = None;
                    grant_other = false;
                    permission.clear();
                }
            }
            Ok(Event::Text(t)) => {
                let text = t
                    .unescape()
                    .map(|c| c.trim().to_string())
                    .unwrap_or_default();
                let n = path.len();
                if n >= 2 && path[n - 2] == "Grantee" {
                    match path[n - 1].as_str() {
                        "ID" => grant_id = Some(text),
                        "URI" | "EmailAddress" => grant_other = true,
                        _ => {}
                    }
                } else if path.last().is_some_and(|p| p == "Permission") {
                    permission = text;
                }
            }
            Ok(Event::End(_)) => {
                if path.pop().is_some_and(|n| n == "Grant") {
                    grants += 1;
                    if grant_other
                        || grant_id.as_deref() != Some(owner)
                        || permission != "FULL_CONTROL"
                    {
                        return false;
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return false,
            _ => {}
        }
        buf.clear();
    }
    grants > 0
}

/// GetBucketOwnershipControls: always bucket owner enforced.
async fn get_ownership_controls(state: &AppState, bucket: &str) -> Response {
    if let Err(resp) = bucket_owner(state, bucket).await {
        return resp;
    }
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
               <OwnershipControls xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
               <Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule>\
               </OwnershipControls>";
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(xml))
        .unwrap()
}

/// PutBucketOwnershipControls: only BucketOwnerEnforced, which is how it is.
async fn put_ownership_controls(state: &AppState, bucket: &str, body: &[u8]) -> Response {
    if let Err(resp) = bucket_owner(state, bucket).await {
        return resp;
    }
    if String::from_utf8_lossy(body)
        .contains("<ObjectOwnership>BucketOwnerEnforced</ObjectOwnership>")
    {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap()
    } else {
        S3Error::xml_response(
            "InvalidRequest",
            "Only BucketOwnerEnforced object ownership is supported: ACLs are disabled",
            StatusCode::BAD_REQUEST,
        )
    }
}

/// What a PUT's `If-Match` / `If-None-Match` ask: "*" or an ETag each.
#[derive(Default)]
struct PutCondition {
    if_match: Option<String>,
    if_none_match: Option<String>,
}

impl PutCondition {
    fn from_headers(headers: &HeaderMap) -> Self {
        let get = |name: header::HeaderName| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_string())
        };
        Self {
            if_match: get(header::IF_MATCH),
            if_none_match: get(header::IF_NONE_MATCH),
        }
    }

    const fn is_set(&self) -> bool {
        self.if_match.is_some() || self.if_none_match.is_some()
    }

    /// The refusal, if `current` (the key's object, if any) fails it.
    fn refuse(&self, current: Option<&ObjectMeta>) -> Option<Response> {
        let matches = |want: &str| {
            current
                .is_some_and(|o| want == "*" || o.etag.trim_matches('"') == want.trim_matches('"'))
        };
        if self.if_match.is_some() && current.is_none() {
            return Some(condition_refused("NoSuchKey"));
        }
        if self.if_match.as_deref().is_some_and(|m| !matches(m))
            || self.if_none_match.as_deref().is_some_and(matches)
        {
            return Some(condition_refused("PreconditionFailed"));
        }
        None
    }
}

fn condition_refused(code: &str) -> Response {
    if code == "NoSuchKey" {
        S3Error::xml_response(
            "NoSuchKey",
            "The specified key does not exist.",
            StatusCode::NOT_FOUND,
        )
    } else {
        S3Error::xml_response(
            "PreconditionFailed",
            "At least one of the pre-conditions you specified did not hold",
            StatusCode::PRECONDITION_FAILED,
        )
    }
}

/// Make `object_meta` the key's current object: its listing entry in meta
/// and its ObjectMeta on every OSD of the placement. `sent` are the shards
/// already written for it, freed if the commit is refused.
///
/// Unconditional, the two commits run together (see `commit_object`). A
/// conditional PUT commits the listing first: meta decides the condition
/// there, in one Raft write, so two racing conditional writers can't both
/// win, or win on different replicas.
async fn commit_put(
    state: &Arc<AppState>,
    placement: &objectio_proto::metadata::GetPlacementResponse,
    object_meta: ObjectMeta,
    versioning_enabled: bool,
    sent: Vec<ShardTarget>,
    condition: &PutCondition,
) -> Result<(), Response> {
    let (bucket, key) = (object_meta.bucket.clone(), object_meta.key.clone());
    let what = format!("{bucket}/{key}");
    let nodes = &placement.nodes;
    let listing_req = objectio_proto::metadata::CreateObjectRequest {
        bucket: bucket.clone(),
        key: key.clone(),
        size: object_meta.size,
        content_type: object_meta.content_type.clone(),
        etag: object_meta.etag.clone(),
        user_metadata: object_meta.user_metadata.clone(),
        stripes: object_meta.stripes.clone(),
        object_id: object_meta.object_id.clone(),
        pg_id: placement.pg_id,
        pool: placement.pool.clone(),
        home_osd_ids: home_of(nodes),
        if_match: condition.if_match.clone().unwrap_or_default(),
        if_none_match: condition.if_none_match.clone().unwrap_or_default(),
    };
    let new_object = referenced_object_ids(&object_meta);
    let failed = |e: &dyn std::fmt::Display| {
        error!("Failed to store object metadata on OSDs: {e}");
        S3Error::xml_response(
            "InternalError",
            &format!("Failed to store object metadata: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    };

    if condition.is_set() {
        if let Err(s) = state.meta_client.clone().create_object(listing_req).await {
            spawn_reclaim(state, sent, Reclaim::FailedWrite, what);
            return Err(match s.code() {
                tonic::Code::FailedPrecondition => condition_refused(s.message()),
                tonic::Code::NotFound => S3Error::xml_response(
                    "NoSuchBucket",
                    "The specified bucket does not exist",
                    StatusCode::NOT_FOUND,
                ),
                _ => S3Error::xml_response(
                    "ServiceUnavailable",
                    &format!("could not commit the object: {}", s.message()),
                    StatusCode::SERVICE_UNAVAILABLE,
                ),
            });
        }
        let outcome = put_object_meta_to_all(
            &state.osd_pool,
            nodes,
            &bucket,
            &key,
            object_meta,
            versioning_enabled,
            &[],
        )
        .await;
        settle_commit(
            state,
            outcome.as_deref(),
            sent,
            &new_object,
            versioning_enabled,
            &what,
        );
        if let Err(e) = outcome {
            sync_listing(state, nodes, &bucket, &key).await;
            return Err(failed(&e));
        }
        return Ok(());
    }

    let mut listing_client = state.meta_client.clone();
    let committed = commit_object(
        put_object_meta_to_all(
            &state.osd_pool,
            nodes,
            &bucket,
            &key,
            object_meta,
            versioning_enabled,
            &[],
        ),
        async { listing_client.create_object(listing_req).await.map(drop) },
        // The listing follows whatever is current on the OSDs: the object
        // this write would have replaced, if any. Unlisting it, as this
        // did, hid an object a failed overwrite left in place.
        || async {
            sync_listing(state, nodes, &bucket, &key).await;
        },
    )
    .await;
    settle_commit(
        state,
        committed.as_ref().map(|(d, _)| d.as_slice()),
        sent,
        &new_object,
        versioning_enabled,
        &what,
    );
    match committed {
        Ok((_, Committed::Both)) => Ok(()),
        Ok((_, Committed::Unlisted(e))) => {
            warn!(
                "create_object on meta failed ({e}); {what} is readable by key \
                 but will not appear in ListObjects until repair",
            );
            Ok(())
        }
        Err(e) => Err(failed(&e)),
    }
}

/// Check an upload's body against the `Content-MD5` and `x-amz-checksum-*`
/// the request carries, refusing it as S3 does on a mismatch or a malformed
/// header.
///
/// Returns the checksums read, and the body's MD5 when `Content-MD5` made us
/// compute it. A request carrying neither costs nothing here.
async fn verify_upload_checksums(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(crate::checksum::RequestChecksums, Option<[u8; 16]>), Response> {
    let refused = |e: &crate::checksum::ChecksumError| {
        S3Error::xml_response(e.code(), &e.message(), StatusCode::BAD_REQUEST)
    };
    let checksums =
        crate::checksum::RequestChecksums::from_headers(headers).map_err(|e| refused(&e))?;
    if checksums.is_empty() {
        return Ok((checksums, None));
    }
    // Hashing a large body is CPU-bound; keep it off the async workers.
    let task = {
        let checksums = checksums.clone();
        let body = body.clone();
        tokio::task::spawn_blocking(move || checksums.verify(&body))
    };
    match task.await {
        Ok(Ok(md5)) => Ok((checksums, md5)),
        Ok(Err(e)) => Err(refused(&e)),
        Err(e) => {
            error!("checksum computation failed: {e}");
            Err(S3Error::xml_response(
                "InternalError",
                "Checksum computation failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

/// Free `targets` off the request's critical path, logging what could not
/// be freed. `what` names the object or upload for the log.
fn spawn_reclaim(state: &Arc<AppState>, targets: Vec<ShardTarget>, reason: Reclaim, what: String) {
    if targets.is_empty() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        warn!(
            "{what}: no runtime to free {} shards ({}); they stay allocated",
            targets.len(),
            reason.label()
        );
        return;
    };
    let state = Arc::clone(state);
    runtime.spawn(async move {
        let total = targets.len();
        let mut meta = state.meta_client.clone();
        let failed = reclaim_shards(&state.osd_pool, &mut meta, targets, reason).await;
        if failed > 0 {
            warn!(
                "{what}: {failed} of {total} shard deletes failed ({}); those blocks stay allocated",
                reason.label()
            );
        } else {
            debug!("{what}: freed {total} shards ({})", reason.label());
        }
    });
}

/// The shards a write is about to send, freed if it is abandoned before
/// its metadata commit.
fn pending_shards(state: &Arc<AppState>, what: String) -> PendingShards {
    let state = Arc::clone(state);
    PendingShards::new(move |targets| spawn_reclaim(&state, targets, Reclaim::FailedWrite, what))
}

/// Free what a metadata commit left unreferenced. On success, the object it
/// replaced — unless versioning keeps that as a version. On a failure no
/// replica applied, `sent`: the shards the new object would have used.
fn settle_commit(
    state: &Arc<AppState>,
    outcome: Result<&[Displaced], &MetaWriteError>,
    sent: Vec<ShardTarget>,
    new_object: &std::collections::HashSet<Vec<u8>>,
    versioning_enabled: bool,
    what: &str,
) {
    match outcome {
        Ok(displaced) if !versioning_enabled => spawn_reclaim(
            state,
            reclaimable_after_overwrite(displaced, new_object),
            Reclaim::Overwrite,
            what.to_string(),
        ),
        Ok(_) => {}
        Err(e) if e.unapplied => {
            spawn_reclaim(state, sent, Reclaim::FailedWrite, what.to_string());
        }
        Err(_) if !sent.is_empty() => warn!(
            "{what}: {} shards stay allocated: a replica may hold the failed write's metadata",
            sent.len()
        ),
        Err(_) => {}
    }
}

pub async fn put_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Refused before anything is stored.
    let tags = match tagging_header(&headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    // Check for copy source header (CopyObject operation)
    let (copy_source, copy_source_version) = copy_source_of(&headers).unzip();
    let copy_source_version = copy_source_version.flatten();

    // CopyObject: the source is read and written again as the destination
    // (copy_object_data). SSE-C on either side is deliberately unsupported
    // (requires a separate set of copy-source-* customer-key headers that we
    // don't wire through yet).
    if let Some(ref source) = copy_source {
        // Parse source bucket/key (format: "bucket/key" or "/bucket/key")
        let parts: Vec<&str> = source.splitn(2, '/').collect();
        if parts.len() != 2 {
            return S3Error::xml_response(
                "InvalidArgument",
                "Invalid x-amz-copy-source format",
                StatusCode::BAD_REQUEST,
            );
        }
        let source_bucket = parts[0];
        let source_key = parts[1];

        // A copy onto itself must change something, or it is refused, as S3
        // refuses it: metadata or tags replaced, encryption or storage class.
        let replaces = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("REPLACE"))
        };
        if source_bucket == bucket
            && source_key == key
            && copy_source_version.is_none()
            && !replaces("x-amz-metadata-directive")
            && !replaces("x-amz-tagging-directive")
            && !headers.contains_key("x-amz-storage-class")
            && !headers
                .keys()
                .any(|k| k.as_str().starts_with("x-amz-server-side-encryption"))
        {
            return S3Error::xml_response(
                "InvalidRequest",
                "This copy request is illegal because it is trying to copy an object to itself \
                 without changing the object's metadata, storage class, website redirect \
                 location or encryption attributes.",
                StatusCode::BAD_REQUEST,
            );
        }

        // CopyObject reads the source as well as writing the destination.
        // The middleware authorized the destination; the source is a
        // different bucket/key and is checked here.
        if let Some(Extension(auth_result)) = &auth
            && let Some(deny_response) = crate::authz::authorize(
                &state,
                auth_result,
                &crate::authz::AuthzRequest {
                    method: &Method::GET,
                    action: "s3:GetObject",
                    bucket: source_bucket,
                    key: Some(source_key),
                    scope_key: source_key,
                    headers: Some(&headers),
                },
            )
            .await
        {
            return deny_response;
        }

        let mut meta_client = state.meta_client.clone();

        // SSE-C on either side is refused; a missing source is NoSuchKey.
        if let Err(resp) = check_copy_sse(
            &state,
            &mut meta_client,
            source_bucket,
            source_key,
            copy_source_version.as_deref(),
            &bucket,
            &headers,
        )
        .await
        {
            return resp;
        }

        // Box-pin to break the `put_object ↔ copy_object_data` async
        // recursion: the copy writes through this handler.
        return Box::pin(copy_object_data(
            state.clone(),
            bucket.clone(),
            key.clone(),
            CopySource {
                bucket: source_bucket.to_string(),
                key: source_key.to_string(),
                version: copy_source_version.clone(),
            },
            auth.clone(),
            headers.clone(),
        ))
        .await;
    }

    debug!(
        "PUT object: {}/{}, size={}, ec={}+{}",
        bucket,
        key,
        body.len(),
        state.ec_k,
        state.ec_m,
    );

    let mut meta_client = state.meta_client.clone();

    // Generate object ID and ETag (MD5 of the *plaintext* body — matches AWS
    // SSE-S3/SSE-KMS ETag semantics; taken before we possibly encrypt).
    //
    // Nothing needs the ETag until the object's metadata is built, so it is
    // computed on a blocking thread while the body is encrypted, erasure-coded
    // and written, instead of in front of all of that. The `etag` phase is the
    // time still spent waiting for it afterwards.
    let mut phases = crate::gateway_metrics::PhaseTimer::start("PutObject");
    let object_id = *Uuid::new_v4().as_bytes();

    // A body that does not match the checksum the client sent is refused
    // here, before any shard is written or metadata committed, so a mismatch
    // stores nothing.
    let (checksums, verified_md5) = match verify_upload_checksums(&headers, &body).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !checksums.is_empty() {
        phases.mark("checksum");
    }

    let etag_task = match verified_md5 {
        // Content-MD5 was checked, so the ETag's MD5 is already known: hand
        // it back through a task that is already done instead of hashing the
        // body a second time.
        Some(md5) => tokio::spawn(async move { format!("\"{}\"", hex::encode(md5)) }),
        None => {
            let body = body.clone();
            tokio::task::spawn_blocking(move || format!("\"{}\"", crate::digest::md5_hex(&body)))
        }
    };
    let stored_checksum = checksums.flexible.as_ref().map(|f| ObjectChecksum {
        algorithm: f.algorithm.aws_name().to_string(),
        value: f.value_b64(),
    });
    let original_size = body.len() as u64;

    // SSE: if the request header or bucket default asks for encryption,
    // encrypt the body before it enters the erasure-coding path. Shards
    // on OSDs see ciphertext; the storage layer is oblivious.
    let (
        body,
        sse_algorithm,
        sse_kms_key_id,
        sse_encrypted_dek,
        sse_iv,
        sse_encryption_context,
        sse_response_header,
        sse_c_key_md5,
    ) = match apply_put_sse(&state, &mut meta_client, &bucket, &headers, body).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    phases.mark("sse");

    // Check bucket versioning state: a missing bucket refuses the PUT.
    let versioning_enabled = match bucket_versioning(&mut meta_client, &bucket).await {
        Ok(v) => v == VersioningState::VersioningEnabled,
        Err(resp) => return resp,
    };
    let (lock_retention, lock_hold) =
        match object_lock_for_write(&mut meta_client, &bucket, &headers).await {
            Ok(lock) => lock,
            Err(resp) => return resp,
        };
    let version_id = if versioning_enabled {
        new_version_id()
    } else {
        String::new()
    };

    // Get placement from metadata service
    let placement = match meta_client
        .get_placement(GetPlacementRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            size: original_size,
            storage_class: "STANDARD".to_string(),
        })
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(e) => {
            error!("Failed to get placement: {}", e);
            return S3Error::xml_response(
                "InternalError",
                &format!("Failed to get placement: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };
    phases.mark("meta_lookup");

    // If-Match / If-None-Match: refused now if the current object already
    // says no, before any data is written. The commit decides for good.
    let condition = PutCondition::from_headers(&headers);
    if condition.is_set() {
        let current = get_object_meta_from_any(&state.osd_pool, &placement.nodes, &bucket, &key)
            .await
            .ok()
            .flatten()
            .filter(|o| !o.is_delete_marker);
        if let Some(refused) = condition.refuse(current.as_ref()) {
            return refused;
        }
    }

    let ec_k = placement.ec_k;
    let ec_m = placement.ec_m;
    let ec_type = ErasureType::try_from(placement.ec_type).unwrap_or(ErasureType::ErasureMds);
    let replication_count = placement.replication_count;

    // A small object goes into its ObjectMeta, whole, on every OSD in the
    // placement: no stripes, no shard writes. It takes the EC path below
    // with zero stripes, whatever the protection scheme — replicating the
    // record is what protects it.
    let inline = !body.is_empty() && body.len() <= state.inline_max_size;

    // Replication mode: no EC, just write raw data to each replica
    // For large files, split into multiple stripes (each stripe <= MAX_SHARD_SIZE)
    if ec_type == ErasureType::ErasureReplication && !inline {
        let total_replicas = replication_count.max(1) as usize;

        // Split data into stripes (each stripe must fit in a block)
        let stripe_size = MAX_SHARD_SIZE;
        let num_stripes = body.len().div_ceil(stripe_size);

        debug!(
            "Replication mode: writing {} replicas x {} stripes for {}/{} (total size={})",
            total_replicas,
            num_stripes,
            bucket,
            key,
            body.len()
        );

        let mut all_stripes = Vec::with_capacity(num_stripes);
        let mut total_success = 0;
        let mut pending = pending_shards(&state, format!("{bucket}/{key}"));

        for stripe_idx in 0..num_stripes {
            let stripe_start = stripe_idx * stripe_size;
            let stripe_end = std::cmp::min(stripe_start + stripe_size, body.len());
            let stripe_data = body.slice(stripe_start..stripe_end);
            let stripe_data_size = stripe_data.len() as u64;

            // Write this stripe to all replicas
            let mut write_futures = Vec::with_capacity(total_replicas);
            for i in 0..total_replicas {
                let placement_node = if i < placement.nodes.len() {
                    placement.nodes[i].clone()
                } else if !placement.nodes.is_empty() {
                    placement.nodes[i % placement.nodes.len()].clone()
                } else {
                    error!("No placement nodes available");
                    return S3Error::xml_response(
                        "InternalError",
                        "No storage nodes available",
                        StatusCode::SERVICE_UNAVAILABLE,
                    );
                };

                let pool = state.osd_pool.clone();
                let obj_id = object_id;
                let shard_data = stripe_data.clone();
                let pos = i as u32;
                let s_idx = stripe_idx as u64;
                pending.sent(&placement_node, &obj_id, s_idx, pos);

                write_futures.push(async move {
                    let result = write_shard_to_osd(
                        &pool,
                        &placement_node,
                        &obj_id,
                        s_idx, // stripe_id
                        pos,
                        shard_data,
                        1,    // ec_k=1 for replication (full data)
                        0,    // ec_m=0 for replication (no parity)
                        None, // Replicated stripes go over gRPC.
                    )
                    .await;
                    (pos, result, placement_node)
                });
            }

            let results = futures::future::join_all(write_futures).await;

            let mut success_count = 0;
            let mut shard_locs = Vec::with_capacity(total_replicas);

            for (pos, result, placement_node) in results {
                match result {
                    Ok(location) => {
                        success_count += 1;
                        shard_locs.push(ShardLocation {
                            position: pos,
                            node_id: location.node_id,
                            disk_id: location.disk_id,
                            offset: location.offset,
                            shard_type: placement_node.shard_type,
                            local_group: placement_node.local_group,
                        });
                        debug!(
                            "Wrote stripe {} replica {} to {}",
                            stripe_idx, pos, placement_node.node_address
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Failed to write stripe {} replica {} to {}: {}",
                            stripe_idx, pos, placement_node.node_address, e
                        );
                        // Do NOT add failed replica locations to metadata —
                        // reading from an unwritten location returns garbage.
                    }
                }
            }

            let quorum = replica_quorum(total_replicas);
            if success_count < quorum {
                error!(
                    "Replication failed for stripe {}: {} successful writes, need {}",
                    stripe_idx, success_count, quorum
                );
                return S3Error::xml_response(
                    "ServiceUnavailable",
                    &format!(
                        "Replication failed for stripe {}: {} successful writes, need {}",
                        stripe_idx, success_count, quorum
                    ),
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            }

            total_success += success_count;
            shard_locs.sort_by_key(|l| l.position);

            all_stripes.push(StripeMeta {
                stripe_id: stripe_idx as u64,
                ec_k: 1,
                ec_m: 0,
                shards: shard_locs,
                ec_type: ErasureType::ErasureReplication.into(),
                ec_local_parity: 0,
                ec_global_parity: 0,
                local_group_size: 0,
                data_size: stripe_data_size,
                object_id: object_id.to_vec(), // Store object_id used for shards
                ..Default::default()
            });
        }
        phases.mark("shards");

        // Store object metadata on primary OSD
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        // The ETag has been computing alongside the stripes; collect it.
        let etag = match etag_task.await {
            Ok(etag) => etag,
            Err(e) => {
                error!("ETag computation failed: {e}");
                return S3Error::xml_response(
                    "InternalError",
                    "ETag computation failed",
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };
        phases.mark("etag");

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let object_meta = ObjectMeta {
            bucket: bucket.clone(),
            key: key.clone(),
            object_id: object_id.to_vec(),
            size: original_size,
            content_type: content_type.clone(),
            etag: etag.clone(),
            created_at: timestamp,
            modified_at: timestamp,
            stripes: all_stripes,
            user_metadata: extract_user_metadata(&headers),
            version_id: version_id.clone(),
            storage_class: "STANDARD".to_string(),
            is_delete_marker: false,
            retention: lock_retention,
            legal_hold: lock_hold,
            encryption_algorithm: sse_algorithm as i32,
            kms_key_id: sse_kms_key_id.clone(),
            encrypted_dek: sse_encrypted_dek.clone(),
            encryption_iv: sse_iv.clone(),
            encryption_context: sse_encryption_context.clone(),
            usage_owner: Vec::new(), // filled in by put_object_meta_to_all
            inline_data: Vec::new(),
            checksum: stored_checksum.clone(),
            tags: tags.clone(),
            part_checksums: Vec::new(),
        };

        // Listed as well: this path used to write only the ObjectMeta, so a
        // replicated object never appeared in ListObjects.
        let sent = pending.disarm();
        if let Err(resp) = commit_put(
            &state,
            &placement,
            object_meta,
            versioning_enabled,
            sent,
            &condition,
        )
        .await
        {
            return resp;
        }
        phases.mark("object_meta");

        dedup_dry_run(
            &state,
            &bucket,
            &placement,
            &body,
            sse_algorithm != SseAlgorithm::SseNone,
        );
        info!(
            "Created object (replication): {}/{}, size={}, stripes={}, replicas_written={}",
            bucket, key, original_size, num_stripes, total_success,
        );

        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .header("ETag", etag);
        if let Some(c) = &checksums.flexible {
            resp = resp.header(c.algorithm.header_name(), c.value_b64());
        }
        if !version_id.is_empty() {
            resp = resp.header("x-amz-version-id", &version_id);
        }
        if let Some(v) = sse_response_header {
            resp = resp.header("x-amz-server-side-encryption", v);
            if v == "aws:kms" && !sse_kms_key_id.is_empty() {
                resp = resp.header(
                    "x-amz-server-side-encryption-aws-kms-key-id",
                    &sse_kms_key_id,
                );
            }
        }
        if sse_algorithm == SseAlgorithm::SseC {
            resp = resp
                .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
                .header(
                    "x-amz-server-side-encryption-customer-key-md5",
                    &sse_c_key_md5,
                );
        }
        return resp.body(Body::empty()).unwrap();
    }

    // EC mode: encode data with erasure coding
    // For large files, split into multiple stripes (each shard <= MAX_SHARD_SIZE)
    let total_shards = (ec_k + ec_m) as usize;

    // Calculate max stripe data size: each encoded shard must fit in MAX_SHARD_SIZE
    // shard_size = stripe_data_size / ec_k (approximately)
    // So max_stripe_data_size = MAX_SHARD_SIZE * ec_k
    let max_stripe_data_size = MAX_SHARD_SIZE * ec_k as usize;
    let num_stripes = if inline {
        0
    } else {
        body.len().div_ceil(max_stripe_data_size)
    };

    debug!(
        "EC mode: encoding {}/{} ({} bytes) into {} stripes with {}+{} shards each",
        bucket,
        key,
        body.len(),
        num_stripes,
        ec_k,
        ec_m
    );

    let mut all_stripes = Vec::with_capacity(num_stripes);
    let mut total_shards_written = 0;
    let mut pending = pending_shards(&state, format!("{bucket}/{key}"));

    for stripe_idx in 0..num_stripes {
        let stripe_start = stripe_idx * max_stripe_data_size;
        let stripe_end = std::cmp::min(stripe_start + max_stripe_data_size, body.len());
        let stripe_data = &body[stripe_start..stripe_end];
        let stripe_data_size = stripe_data.len() as u64;

        // Where the encoded stripe starts in registered memory, when it was
        // encoded into a Transfer Engine stripe slot.
        let mut rdma_base: Option<u64> = None;

        // Encode this stripe with erasure coding - use LRC if specified
        let shards: Vec<Bytes> = match ec_type {
            ErasureType::ErasureLrc => {
                // Use LRC backend with local parity groups
                let lrc_config = LrcConfig::new(
                    ec_k as u8,
                    placement.ec_local_parity as u8,
                    placement.ec_global_parity as u8,
                );
                let backend = match RustSimdLrcBackend::new(lrc_config) {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Failed to create LRC backend: {}", e);
                        return S3Error::xml_response(
                            "InternalError",
                            &format!("LRC codec error: {}", e),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                };

                // Pad data to shard size
                let shard_size = stripe_data.len().div_ceil(ec_k as usize);
                let padded_size = shard_size * ec_k as usize;
                let mut padded_data = stripe_data.to_vec();
                padded_data.resize(padded_size, 0);

                // Split into data shards
                let data_shards: Vec<&[u8]> =
                    padded_data.chunks(shard_size).take(ec_k as usize).collect();

                match backend.encode_lrc(&data_shards, shard_size) {
                    Ok(encoded) => encoded.all_shards().into_iter().map(Bytes::from).collect(),
                    Err(e) => {
                        error!("Failed to encode stripe {} with LRC: {}", stripe_idx, e);
                        return S3Error::xml_response(
                            "InternalError",
                            &format!("LRC encoding failed for stripe {}: {}", stripe_idx, e),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                }
            }
            _ => {
                // Use standard MDS Reed-Solomon
                let codec = match ErasureCodec::new(ErasureConfig::new(ec_k as u8, ec_m as u8)) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Failed to create erasure codec: {}", e);
                        return S3Error::xml_response(
                            "InternalError",
                            &format!("Erasure coding error: {}", e),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                };

                // With Transfer Engine, encode straight into a registered
                // stripe slot: OSDs then read their shards out of it.
                let slot = state
                    .rdma
                    .as_deref()
                    .and_then(|r| r.stripe_slot(codec.stripe_len(stripe_data.len())));
                let encoded = match slot {
                    Some(mut slot) => {
                        let base = slot.addr();
                        codec
                            .encode_into(stripe_data, slot.as_mut_slice())
                            .map(|shard_size| {
                                rdma_base = Some(base);
                                let stripe = slot.into_bytes(shard_size * total_shards);
                                (0..total_shards)
                                    .map(|i| stripe.slice(i * shard_size..(i + 1) * shard_size))
                                    .collect()
                            })
                    }
                    None => codec.encode_bytes(stripe_data),
                };
                match encoded {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to encode stripe {}: {}", stripe_idx, e);
                        return S3Error::xml_response(
                            "InternalError",
                            &format!("Erasure encoding failed for stripe {}: {}", stripe_idx, e),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                }
            }
        };

        debug!(
            "Stripe {}: encoded {} bytes into {} shards of {} bytes each",
            stripe_idx,
            stripe_data.len(),
            shards.len(),
            shards.first().map(|s| s.len()).unwrap_or(0)
        );

        // Write shards to OSDs in parallel
        let mut write_futures = Vec::with_capacity(total_shards);

        // Use placements from metadata service, or fall back to round-robin if not enough
        for (i, shard) in shards.iter().enumerate() {
            let placement_node = if i < placement.nodes.len() {
                placement.nodes[i].clone()
            } else if !placement.nodes.is_empty() {
                // Round-robin if not enough placements
                placement.nodes[i % placement.nodes.len()].clone()
            } else {
                error!("No placement nodes available");
                return S3Error::xml_response(
                    "InternalError",
                    "No storage nodes available",
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            };

            let pool = state.osd_pool.clone();
            let obj_id = object_id;
            let shard_data = shard.clone();
            let pos = i as u32;
            let s_idx = stripe_idx as u64;
            pending.sent(&placement_node, &obj_id, s_idx, pos);
            let rdma = state.rdma.clone();
            let shard_addr = rdma_base.map(|base| base + (i * shard_data.len()) as u64);
            // Transfer Engine was on offer, but no stripe slot was free.
            if rdma.is_some() && shard_addr.is_none() && !placement_node.te_segment.is_empty() {
                crate::gateway_metrics::record_rdma_fallback(
                    "write",
                    crate::rdma::Fallback::NoSlot,
                );
            }

            write_futures.push(async move {
                let source = rdma
                    .as_deref()
                    .zip(shard_addr)
                    .map(|(rdma, addr)| crate::osd_pool::RdmaSource { rdma, addr });
                let result = write_shard_to_osd(
                    &pool,
                    &placement_node,
                    &obj_id,
                    s_idx, // stripe_id
                    pos,
                    shard_data,
                    ec_k,
                    ec_m,
                    source,
                )
                .await;
                (pos, result, placement_node)
            });
        }

        // Wait for all writes and collect results
        let results = futures::future::join_all(write_futures).await;

        let mut success_count = 0;
        let mut shard_locs = Vec::with_capacity(total_shards);

        for (pos, result, placement_node) in results {
            match result {
                Ok(location) => {
                    success_count += 1;
                    shard_locs.push(ShardLocation {
                        position: pos,
                        node_id: location.node_id,
                        disk_id: location.disk_id,
                        offset: location.offset,
                        // Use shard type from placement, or default to data/parity based on position
                        shard_type: placement_node.shard_type,
                        local_group: placement_node.local_group,
                    });
                    debug!(
                        "Wrote stripe {} shard {} to {}",
                        stripe_idx, pos, placement_node.node_address
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to write stripe {} shard {} to {}: {}",
                        stripe_idx, pos, placement_node.node_address, e
                    );
                    // Do NOT add failed shard locations to metadata — the shard
                    // was never written, so reading from this location would
                    // return unrelated data and corrupt EC reconstruction.
                }
            }
        }

        let quorum = write_quorum(ec_k, ec_m);
        if success_count < quorum {
            error!(
                "Write quorum not met for stripe {}: {} successful, need {} (ec_k={}, ec_m={}, total_shards={})",
                stripe_idx, success_count, quorum, ec_k, ec_m, total_shards
            );
            return S3Error::xml_response(
                "ServiceUnavailable",
                &format!(
                    "Write quorum not met for stripe {}: {} successful writes, need {}",
                    stripe_idx, success_count, quorum
                ),
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }

        total_shards_written += success_count;

        // Sort shard locations by position
        shard_locs.sort_by_key(|l| l.position);

        // Add stripe metadata
        all_stripes.push(StripeMeta {
            stripe_id: stripe_idx as u64,
            ec_k,
            ec_m,
            shards: shard_locs,
            // Use the EC type from placement response
            ec_type: placement.ec_type,
            ec_local_parity: placement.ec_local_parity,
            ec_global_parity: placement.ec_global_parity,
            local_group_size: placement.local_group_size,
            data_size: stripe_data_size, // Store this stripe's data size for decoding
            object_id: object_id.to_vec(), // Store object_id used for shards
            ..Default::default()
        });
    }

    // Store object metadata on primary OSD (position 0)
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    phases.mark("shards");

    // The ETag has been computing alongside the stripes; collect it.
    let etag = match etag_task.await {
        Ok(etag) => etag,
        Err(e) => {
            error!("ETag computation failed: {e}");
            return S3Error::xml_response(
                "InternalError",
                "ETag computation failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };
    phases.mark("etag");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build ObjectMeta for OSD storage
    let object_meta = ObjectMeta {
        bucket: bucket.clone(),
        key: key.clone(),
        object_id: object_id.to_vec(),
        size: original_size,
        content_type: content_type.clone(),
        etag: etag.clone(),
        created_at: timestamp,
        modified_at: timestamp,
        stripes: all_stripes,
        user_metadata: extract_user_metadata(&headers),
        version_id: version_id.clone(),
        storage_class: "STANDARD".to_string(),
        is_delete_marker: false,
        retention: lock_retention,
        legal_hold: lock_hold,
        encryption_algorithm: sse_algorithm as i32,
        kms_key_id: sse_kms_key_id.clone(),
        encrypted_dek: sse_encrypted_dek,
        encryption_iv: sse_iv,
        encryption_context: sse_encryption_context,
        usage_owner: Vec::new(), // filled in by put_object_meta_to_all
        inline_data: if inline { body.to_vec() } else { Vec::new() },
        checksum: stored_checksum,
        tags,
        part_checksums: Vec::new(),
    };

    let sent = pending.disarm();
    if let Err(resp) = commit_put(
        &state,
        &placement,
        object_meta,
        versioning_enabled,
        sent,
        &condition,
    )
    .await
    {
        return resp;
    }
    phases.mark("commit");

    dedup_dry_run(
        &state,
        &bucket,
        &placement,
        &body,
        sse_algorithm != SseAlgorithm::SseNone,
    );
    info!(
        "Created object: {}/{}, size={}, stripes={}, shards_written={}, replicas={}",
        bucket,
        key,
        original_size,
        num_stripes,
        total_shards_written,
        placement.nodes.len(),
    );
    if inline {
        crate::gateway_metrics::record_inline(original_size);
    }

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", etag);
    if let Some(c) = &checksums.flexible {
        resp = resp.header(c.algorithm.header_name(), c.value_b64());
    }
    if !version_id.is_empty() {
        resp = resp.header("x-amz-version-id", &version_id);
    }
    if let Some(v) = sse_response_header {
        resp = resp.header("x-amz-server-side-encryption", v);
        if v == "aws:kms" && !sse_kms_key_id.is_empty() {
            resp = resp.header(
                "x-amz-server-side-encryption-aws-kms-key-id",
                &sse_kms_key_id,
            );
        }
    }
    if sse_algorithm == SseAlgorithm::SseC {
        resp = resp
            .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
            .header(
                "x-amz-server-side-encryption-customer-key-md5",
                &sse_c_key_md5,
            );
    }
    resp.body(Body::empty()).unwrap()
}

/// Get object (GET /{bucket}/{key})
pub async fn get_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    // Authorized by `authz::authz_layer` before this handler runs.
    _auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    get_object_version(state, bucket, key, None, headers).await
}

/// GetObjectAttributes (`GET ?attributes`): what `x-amz-object-attributes`
/// names of ETag, Checksum, ObjectParts, StorageClass and ObjectSize,
/// without the data. Parts page with `x-amz-max-parts` and
/// `x-amz-part-number-marker`.
async fn get_object_attributes(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
    headers: &HeaderMap,
) -> Response {
    let nodes = match get_placement_nodes_for_object(&state, &bucket, &key).await {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let object = match object_to_read(&state, &nodes, &bucket, &key, version_id.as_deref()).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    if let Some(refused) = sse_c_read_refusal(headers, &object) {
        return refused;
    }
    let wanted: Vec<String> = headers
        .get("x-amz-object-attributes")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(',')
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .collect();
    if wanted.is_empty() {
        return S3Error::xml_response(
            "InvalidArgument",
            "x-amz-object-attributes must name at least one attribute",
            StatusCode::BAD_REQUEST,
        );
    }
    let wants = |name: &str| wanted.iter().any(|w| w == name);
    let number = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok())
    };

    let mut xml =
        String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<GetObjectAttributesResponse>");
    if wants("ETag") {
        xml.push_str(&format!(
            "<ETag>{}</ETag>",
            quick_xml::escape::escape(object.etag.trim_matches('"'))
        ));
    }
    let checksum_xml = |c: &ObjectChecksum| {
        let tag = format!("Checksum{}", c.algorithm);
        format!("<{tag}>{}</{tag}>", quick_xml::escape::escape(&c.value))
    };
    if wants("Checksum")
        && let Some(c) = &object.checksum
    {
        xml.push_str(&format!(
            "<Checksum>{}<ChecksumType>{}</ChecksumType></Checksum>",
            checksum_xml(c),
            checksum_type_of(c)
        ));
    }
    if wants("ObjectParts") && is_multipart(&object) {
        let count = part_bounds(&object, 1).map_or(0, |(_, _, c)| c);
        let max_parts = number("x-amz-max-parts").unwrap_or(1000).max(1);
        let marker = number("x-amz-part-number-marker").unwrap_or(0);
        let mut parts = String::new();
        let mut last = marker;
        for n in ((marker + 1)..=count).take(max_parts as usize) {
            let Ok((start, end, _)) = part_bounds(&object, n) else {
                break;
            };
            let checksum = object
                .part_checksums
                .get((n - 1) as usize)
                .map(checksum_xml)
                .unwrap_or_default();
            parts.push_str(&format!(
                "<Part><PartNumber>{n}</PartNumber><Size>{}</Size>{checksum}</Part>",
                end + 1 - start
            ));
            last = n;
        }
        let truncated = last < count;
        xml.push_str(&format!(
            "<ObjectParts><PartsCount>{count}</PartsCount>\
             <PartNumberMarker>{marker}</PartNumberMarker>\
             <NextPartNumberMarker>{last}</NextPartNumberMarker>\
             <MaxParts>{max_parts}</MaxParts><IsTruncated>{truncated}</IsTruncated>\
             {parts}</ObjectParts>"
        ));
    }
    if wants("StorageClass") {
        let class = if object.storage_class.is_empty() {
            "STANDARD"
        } else {
            object.storage_class.as_str()
        };
        xml.push_str(&format!(
            "<StorageClass>{}</StorageClass>",
            quick_xml::escape::escape(class)
        ));
    }
    if wants("ObjectSize") {
        xml.push_str(&format!("<ObjectSize>{}</ObjectSize>", object.size));
    }
    xml.push_str("</GetObjectAttributesResponse>");
    with_version_id(Response::builder(), &object)
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .header(
            header::LAST_MODIFIED,
            timestamp_to_http_date(object.modified_at),
        )
        .body(Body::from(xml))
        .unwrap()
}

/// GET of one part of a multipart object (`?partNumber=`): the part's bytes,
/// as a range of the object (206), with `x-amz-mp-parts-count`.
async fn get_object_part(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
    part_number: u32,
    mut headers: HeaderMap,
) -> Response {
    let nodes = match get_placement_nodes_for_object(&state, &bucket, &key).await {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let object = match object_to_read(&state, &nodes, &bucket, &key, version_id.as_deref()).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    let (start, end, count) = match part_bounds(&object, part_number) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    headers.remove(header::RANGE);
    if end >= start
        && let Ok(v) = header::HeaderValue::from_str(&format!("bytes={start}-{end}"))
    {
        headers.insert(header::RANGE, v);
    }
    let mut resp = get_object_version(state, bucket, key, version_id, headers).await;
    // The part's own checksum, not the object's, and always: a client
    // reading parts checks each against what it uploaded.
    if resp.status().is_success()
        && let Some(c) = object
            .part_checksums
            .get((part_number as usize).wrapping_sub(1))
        && let Some(a) = crate::checksum::ChecksumAlgorithm::from_aws_name(&c.algorithm)
        && let Ok(v) = header::HeaderValue::from_str(&c.value)
    {
        let kind = object
            .checksum
            .as_ref()
            .map_or("COMPOSITE", checksum_type_of);
        resp.headers_mut().insert(a.header_name(), v);
        resp.headers_mut().insert(
            "x-amz-checksum-type",
            header::HeaderValue::from_static(kind),
        );
    }
    if resp.status().is_success() && is_multipart(&object) {
        resp.headers_mut()
            .insert("x-amz-mp-parts-count", header::HeaderValue::from(count));
    }
    resp
}

/// Whether `object` was made by CompleteMultipartUpload (its ETag ends in
/// "-<parts>"), so that it has parts to count, even just one.
fn is_multipart(object: &ObjectMeta) -> bool {
    object
        .etag
        .trim_matches('"')
        .rsplit_once('-')
        .is_some_and(|(_, c)| c.parse::<u32>().is_ok())
}

/// Where part `n` (1-based) of `object` lies in it, inclusive, and how many
/// parts it has. A multipart object's parts are its runs of stripes written
/// under one part's id; its ETag ends in "-<parts>". Anything else is one
/// part, the whole object.
#[allow(clippy::result_large_err)] // Err is a fully-formed Response built once per request.
fn part_bounds(object: &ObjectMeta, n: u32) -> Result<(u64, u64, u32), Response> {
    let invalid = || {
        S3Error::xml_response(
            "InvalidPart",
            "The requested partnumber is not satisfiable",
            StatusCode::BAD_REQUEST,
        )
    };
    let multipart = object
        .etag
        .trim_matches('"')
        .rsplit_once('-')
        .and_then(|(_, c)| c.parse::<u32>().ok());
    let Some(count) = multipart else {
        return if n == 1 {
            Ok((0, object.size.saturating_sub(1), 1))
        } else {
            Err(invalid())
        };
    };
    let mut parts: Vec<(u64, u64)> = Vec::new(); // (start, len)
    let mut offset = 0u64;
    let mut last_id: Option<&[u8]> = None;
    for stripe in &object.stripes {
        if last_id == Some(stripe.object_id.as_slice()) {
            if let Some(p) = parts.last_mut() {
                p.1 += stripe.data_size;
            }
        } else {
            parts.push((offset, stripe.data_size));
            last_id = Some(stripe.object_id.as_slice());
        }
        offset += stripe.data_size;
    }
    if parts.len() != count as usize {
        // Parts that can't be told apart (one source copied in twice):
        // say so rather than serve the wrong bytes.
        return Err(S3Error::xml_response(
            "NotImplemented",
            "This object's part boundaries are not recorded",
            StatusCode::NOT_IMPLEMENTED,
        ));
    }
    let (start, len) = *parts
        .get((n as usize).wrapping_sub(1))
        .ok_or_else(invalid)?;
    Ok((start, start + len.saturating_sub(1), count))
}

/// GET one version of an object (`?versionId=`), or the current one.
async fn get_object_version(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
    headers: HeaderMap,
) -> Response {
    debug!("GET object: {}/{}", bucket, key);
    if let Some(refused) = sse_headers_on_read(&headers) {
        return refused;
    }

    // Parse Range header if present
    let range_header = headers.get(header::RANGE).and_then(|v| v.to_str().ok());

    let mut phases = crate::gateway_metrics::PhaseTimer::start("GetObject");
    let mut meta_client = state.meta_client.clone();

    // Get placement to find primary OSD (CRUSH is deterministic)
    let placement = match meta_client
        .get_placement(GetPlacementRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            size: 0, // Size not needed for lookup
            storage_class: "STANDARD".to_string(),
        })
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(e) => {
            error!("Failed to get placement: {}", e);
            return S3Error::xml_response(
                "InternalError",
                &format!("Failed to get placement: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    if placement.nodes.is_empty() {
        return S3Error::xml_response(
            "InternalError",
            "No storage nodes available",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }

    // Build node_id -> address map from placement for shard reads
    let mut node_address_map: HashMap<Vec<u8>, String> = placement
        .nodes
        .iter()
        .map(|n| (n.node_id.clone(), n.node_address.clone()))
        .collect();

    // Build a node_id → failure_domain map for locality-aware EC read
    // ranking (Phase 2). One GetListingNodes call populates both this map
    // and fills any gaps in node_address_map. Empty on older meta servers
    // that don't carry failure_domain in ListingNode — in that case every
    // node ranks as `Unknown` distance and the ranked sort is a no-op.
    let mut node_topo_map: HashMap<Vec<u8>, objectio_placement::FailureDomainInfo> = HashMap::new();
    // node_id → Transfer Engine segment, for shard reads over RDMA. The
    // listing is the more current source, so it wins over the placement.
    let mut node_te_map: HashMap<Vec<u8>, String> = placement
        .nodes
        .iter()
        .map(|n| (n.node_id.clone(), n.te_segment.clone()))
        .collect();
    if let Ok(resp) = meta_client
        .get_listing_nodes(GetListingNodesRequest {
            bucket: String::new(),
            include_all_states: false,
        })
        .await
    {
        for n in resp.into_inner().nodes {
            node_address_map
                .entry(n.node_id.clone())
                .or_insert_with(|| n.address.clone());
            node_te_map.insert(n.node_id.clone(), n.te_segment.clone());
            let fd = n.failure_domain.unwrap_or_default();
            node_topo_map.insert(
                n.node_id,
                objectio_placement::FailureDomainInfo::new_full(
                    &fd.region,
                    &fd.zone,
                    &fd.datacenter,
                    &fd.rack,
                    &fd.host,
                ),
            );
        }
    }

    // If we have stored shard locations pointing to nodes not in placement
    // (e.g. topology changed), fetch all active nodes as fallback
    // This is done lazily below only if a node_id is missing from the map.
    phases.mark("meta_lookup");

    let object = match object_to_read(
        &state,
        &placement.nodes,
        &bucket,
        &key,
        version_id.as_deref(),
    )
    .await
    {
        Ok(obj) => obj,
        Err(resp) => return resp,
    };
    if let Some(resp) = read_preconditions(&headers, &object) {
        return resp;
    }
    phases.mark("object_meta");

    // A zero-byte object legitimately has no stripes — there are no bytes to
    // erasure-code, so nothing was ever written to an OSD. It used to fall
    // into the "no stripe metadata" arm below and answer 500, so an empty file
    // could be stored and then never read back: `touch x && aws s3 cp x
    // s3://b/` succeeded and `aws s3 cp s3://b/x .` returned InternalError.
    // Empty files are ordinary — .gitkeep, an empty __init__.py, a zero-length
    // marker — and this made every one of them a write-only object.
    if object.stripes.is_empty() && object.size == 0 {
        let mut builder = with_version_id(Response::builder(), &object)
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, &object.content_type)
            .header(header::CONTENT_LENGTH, "0")
            .header("ETag", &object.etag)
            .header("Accept-Ranges", "bytes")
            .header(
                header::LAST_MODIFIED,
                timestamp_to_http_date(object.modified_at),
            );
        // Any Range over zero bytes is unsatisfiable, which is what
        // `parse_range_header` already says; answer it the way the ranged path
        // below would rather than returning a body the client did not ask for.
        if headers.contains_key(header::RANGE) {
            return range_not_satisfiable(0);
        }
        builder = add_metadata_headers(builder, &object.user_metadata);
        builder = add_tagging_count(builder, &object.tags);
        builder = add_checksum_header(builder, &headers, &object);
        return builder.body(Body::empty()).unwrap();
    }

    // Check for stripes
    if object.stripes.is_empty() && object.inline_data.is_empty() {
        error!(
            "Object has no stripe metadata: {}/{} (size {})",
            bucket, key, object.size
        );
        return S3Error::xml_response(
            "InternalError",
            "Object has no stripe metadata",
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    // Resolve SSE state up front so per-stripe decryption can be inlined.
    // For SSE-S3 we unwrap the DEK once and decrypt each stripe's contribution
    // to `all_data` below, using that stripe's IV (multipart) or the
    // object-level IV (legacy single-stripe).
    let object_sse_algo =
        SseAlgorithm::try_from(object.encryption_algorithm).unwrap_or(SseAlgorithm::SseNone);
    // `sse_response_header` is the value for `x-amz-server-side-encryption`
    // when the object is SSE-S3/KMS. `sse_c_key_md5` is populated for SSE-C
    // and drives the `x-amz-server-side-encryption-customer-*` headers.
    let (get_sse_dek, sse_response_header, sse_c_key_md5): (
        Option<[u8; objectio_kms::DEK_LEN]>,
        Option<&'static str>,
        String,
    ) = match object_sse_algo {
        SseAlgorithm::SseNone => (None, None, String::new()),
        SseAlgorithm::SseS3 => {
            let Some(mk) = state.master_key.as_ref() else {
                return S3Error::xml_response(
                    "ServiceUnavailable",
                    "SSE master key not configured on the gateway — cannot decrypt object",
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            };
            match mk.unwrap_dek(&object.encrypted_dek) {
                Ok(dek) => (Some(dek), Some("AES256"), String::new()),
                Err(e) => {
                    error!("Failed to unwrap DEK for {}/{}: {}", bucket, key, e);
                    return S3Error::xml_response(
                        "InternalError",
                        "Failed to unwrap object DEK",
                        StatusCode::INTERNAL_SERVER_ERROR,
                    );
                }
            }
        }
        SseAlgorithm::SseKms => {
            let Some(kms) = state.kms() else {
                return S3Error::xml_response(
                    "ServiceUnavailable",
                    "SSE-KMS is not configured on this gateway — cannot decrypt object",
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            };
            match kms
                .decrypt(
                    &object.kms_key_id,
                    &object.encrypted_dek,
                    &object.encryption_context,
                )
                .await
            {
                Ok(dek) => (Some(dek), Some("aws:kms"), String::new()),
                Err(objectio_kms::KmsError::KeyNotFound(_)) => {
                    return S3Error::xml_response(
                        "KMS.NotFoundException",
                        "Object's KMS key no longer exists",
                        StatusCode::NOT_FOUND,
                    );
                }
                Err(e) => {
                    error!(
                        "Failed to unwrap KMS DEK for {}/{} (key {}): {}",
                        bucket, key, object.kms_key_id, e
                    );
                    return S3Error::xml_response(
                        "InternalError",
                        "Failed to unwrap object DEK",
                        StatusCode::INTERNAL_SERVER_ERROR,
                    );
                }
            }
        }
        SseAlgorithm::SseC => {
            if let Some(refused) = sse_c_read_refusal(&headers, &object) {
                return refused;
            }
            let cust = match parse_sse_c_headers(&headers) {
                Ok(Some(c)) => c,
                Ok(None) => {
                    return S3Error::xml_response(
                        "InvalidRequest",
                        "The object was stored using a form of SSE-C; the customer key must be provided on the GET request",
                        StatusCode::BAD_REQUEST,
                    );
                }
                Err(resp) => return resp,
            };
            (Some(cust.key), None, cust.md5_b64)
        }
    };

    // Resolve byte range before fetching any stripe data
    let total_size = object.size;
    let resolved_range = match range_header {
        Some(range_str) => match parse_range_header(range_str, total_size) {
            Some(range) => Some(range),
            None => {
                // Invalid range — return 416 without fetching any stripes
                return range_not_satisfiable(total_size);
            }
        },
        None => None,
    };

    // Log stripe layout for multi-stripe objects (multipart uploads)
    if object.stripes.len() > 1 {
        let stripe_sizes: Vec<u64> = object.stripes.iter().map(|s| s.data_size).collect();
        let stripe_total: u64 = stripe_sizes.iter().sum();
        info!(
            "Multi-stripe object {}/{}: {} stripes, stripe_sizes={:?}, stripe_total={}, object.size={}",
            bucket,
            key,
            object.stripes.len(),
            stripe_sizes,
            stripe_total,
            total_size
        );
        if stripe_total != total_size {
            warn!(
                "Stripe data_size sum ({}) does not match object size ({}) for {}/{}",
                stripe_total, total_size, bucket, key
            );
        }
    }

    // Determine which stripes to fetch (skip non-overlapping stripes for range requests)
    let stripe_plan: Vec<(usize, u64)> = if let Some(ref range) = resolved_range {
        let plan = overlapping_stripes(&object.stripes, total_size, range);
        debug!(
            "Range request bytes={}-{} for {}/{}: fetching {} of {} stripes",
            range.start,
            range.end,
            bucket,
            key,
            plan.len(),
            object.stripes.len()
        );
        plan
    } else {
        // Full object: all stripes, offsets unused since we don't slice
        object
            .stripes
            .iter()
            .enumerate()
            .map(|(i, _)| (i, 0u64))
            .collect()
    };

    // Pre-allocate with appropriate capacity
    let capacity = if let Some(ref range) = resolved_range {
        (range.end - range.start + 1) as usize
    } else {
        object.size as usize
    };
    let mut all_data = Vec::with_capacity(capacity);

    // An inline object is all here already; its stripe plan is empty.
    if !object.inline_data.is_empty() {
        match inline_slice(&object, resolved_range.as_ref(), get_sse_dek.as_ref()) {
            Ok(data) => all_data = data,
            Err(resp) => return resp,
        }
    }

    for &(stripe_idx, stripe_byte_offset) in &stripe_plan {
        let stripe = &object.stripes[stripe_idx];
        let ec_k = stripe.ec_k as usize;
        let ec_m = stripe.ec_m as usize;
        let stripe_ec_type =
            ErasureType::try_from(stripe.ec_type).unwrap_or(ErasureType::ErasureMds);

        // Use stripe's data_size if available, otherwise fall back to object size (for backwards compat)
        let stripe_data_size = if stripe.data_size > 0 {
            stripe.data_size as usize
        } else if object.stripes.len() == 1 {
            object.size as usize
        } else {
            // For multi-stripe without data_size, we can't properly decode
            error!(
                "Multi-stripe object missing data_size on stripe {}",
                stripe_idx
            );
            return S3Error::xml_response(
                "InternalError",
                "Object metadata is incomplete (missing stripe data_size)",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        };

        // Replication mode: just read raw data from any replica
        if stripe_ec_type == ErasureType::ErasureReplication {
            debug!(
                "Reading replicated stripe {} of {}/{}: size={}",
                stripe_idx, bucket, key, stripe_data_size
            );

            // Try each replica until we get the data
            let mut data_read = false;
            for shard_loc in &stripe.shards {
                let node_addr = resolve_node_address(
                    &mut node_address_map,
                    &mut meta_client,
                    &shard_loc.node_id,
                )
                .await;
                let node_placement = objectio_proto::metadata::NodePlacement {
                    te_segment: String::new(),
                    position: shard_loc.position,
                    node_id: shard_loc.node_id.clone(),
                    node_address: node_addr,
                    disk_id: shard_loc.disk_id.clone(),
                    shard_type: shard_loc.shard_type,
                    local_group: shard_loc.local_group,
                };

                // Use stripe's object_id if available (for multipart uploads)
                // Fall back to object.object_id for backwards compat
                let shard_object_id = if !stripe.object_id.is_empty() {
                    &stripe.object_id
                } else {
                    &object.object_id
                };

                match read_shard_from_osd(
                    &state.osd_pool,
                    &node_placement,
                    shard_object_id,
                    stripe.stripe_id,
                    shard_loc.position,
                    None, // Replicated stripes go over gRPC.
                )
                .await
                {
                    Ok(data) => {
                        debug!(
                            "Read replicated data from replica {} ({} bytes)",
                            shard_loc.position,
                            data.len()
                        );
                        // Truncate to actual data size (in case of padding)
                        let actual_data = if data.len() > stripe_data_size {
                            data[..stripe_data_size].to_vec()
                        } else {
                            Vec::from(data)
                        };
                        let actual_data = object_part(stripe, actual_data);
                        let (mut slice, slice_start_in_stripe): (Vec<u8>, u64) =
                            if let Some(ref range) = resolved_range {
                                let stripe_end = stripe_byte_offset + actual_data.len() as u64;
                                let slice_start =
                                    range.start.saturating_sub(stripe_byte_offset) as usize;
                                let slice_end = std::cmp::min(range.end + 1, stripe_end)
                                    .saturating_sub(stripe_byte_offset)
                                    as usize;
                                (
                                    actual_data[slice_start..slice_end].to_vec(),
                                    slice_start as u64,
                                )
                            } else {
                                (actual_data, 0)
                            };
                        if let Some(dek) = get_sse_dek.as_ref()
                            && let Err(resp) = decrypt_stripe_slice(
                                dek,
                                stripe,
                                &object,
                                stripe_byte_offset,
                                slice_start_in_stripe,
                                &mut slice,
                            )
                        {
                            return resp;
                        }
                        all_data.extend(slice);
                        data_read = true;
                        break;
                    }
                    Err(e) => {
                        warn!(
                            "Failed to read replica {} from stripe {}: {}",
                            shard_loc.position, stripe_idx, e
                        );
                    }
                }
            }

            if !data_read {
                error!(
                    "Failed to read any replica for stripe {} of {}/{}",
                    stripe_idx, bucket, key
                );
                return S3Error::xml_response(
                    "InternalError",
                    "Failed to read object: no replicas available",
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }

            continue; // Move to next stripe
        }

        // EC mode: need to read k shards and decode
        let total_shards = ec_k + ec_m;

        debug!(
            "Reading EC stripe {} of {}/{}: size={}, ec={}+{}",
            stripe_idx, bucket, key, stripe_data_size, ec_k, ec_m
        );

        // A packed object's slice: read just its bytes from the data
        // shard(s) they are in. Anything short of that (a shard down, a
        // checksum mismatch) falls through to reading k shards and
        // decoding the pack, below.
        if stripe.slice_length > 0 && stripe_ec_type == ErasureType::ErasureMds {
            let part_len = stripe.slice_length;
            let (from, to) = match resolved_range {
                Some(ref range) => (
                    range.start.saturating_sub(stripe_byte_offset),
                    (range.end + 1 - stripe_byte_offset).min(part_len),
                ),
                None => (0, part_len),
            };
            if let Some(mut slice) = read_packed_slice(
                &state,
                &mut node_address_map,
                &mut meta_client,
                stripe,
                stripe_data_size,
                stripe.slice_offset + from,
                stripe.slice_offset + to,
            )
            .await
            {
                if let Some(dek) = get_sse_dek.as_ref()
                    && let Err(resp) = decrypt_stripe_slice(
                        dek,
                        stripe,
                        &object,
                        stripe_byte_offset,
                        from,
                        &mut slice,
                    )
                {
                    return resp;
                }
                all_data.extend(slice);
                continue;
            }
        }

        // Read shards from OSDs - we need at least k shards
        let mut shards: Vec<Option<Bytes>> = vec![None; total_shards];
        let mut read_count = 0;

        // Create a map of position -> shard location for quick lookup
        let shard_map: HashMap<u32, &ShardLocation> =
            stripe.shards.iter().map(|s| (s.position, s)).collect();

        // Use stripe's object_id if available (for multipart uploads)
        // Fall back to object.object_id for backwards compat
        let ec_shard_object_id = if !stripe.object_id.is_empty() {
            &stripe.object_id
        } else {
            &object.object_id
        };

        // Rank all shard positions by topological distance to this
        // gateway so reads pull from the nearest OSDs first. Any k of the
        // total_shards positions decode correctly, so we no longer need a
        // separate data-first / parity-fallback split — a single ranked
        // pass handles both. Secondary sort key is position, which
        // preserves the legacy "data shards before parity" preference
        // when topology info is absent or ties.
        let me = &state.self_topology;
        let mut ranked_positions: Vec<(u32, objectio_placement::TopologyDistance)> = (0
            ..total_shards as u32)
            .filter_map(|pos| {
                let shard_loc = shard_map.get(&pos)?;
                let dist = node_topo_map
                    .get(&shard_loc.node_id)
                    .map_or(objectio_placement::TopologyDistance::Unknown, |fd| {
                        objectio_placement::distance(me, fd)
                    });
                Some((pos, dist))
            })
            .collect();
        ranked_positions.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

        // Read the nearest k shards at once, not one after another: a stripe
        // then costs one shard round trip instead of k. Each failed read is
        // replaced by the next-nearest position, so a degraded stripe still
        // ends up with k shards if k survive, and no more than k reads are
        // ever in flight.
        let mut candidates = ranked_positions.into_iter();
        let mut in_flight = futures::stream::FuturesUnordered::new();
        loop {
            while read_count + in_flight.len() < ec_k {
                let Some((pos, dist)) = candidates.next() else {
                    break;
                };
                let Some(shard_loc) = shard_map.get(&pos) else {
                    continue;
                };
                let node_addr = resolve_node_address(
                    &mut node_address_map,
                    &mut meta_client,
                    &shard_loc.node_id,
                )
                .await;
                let node_placement = objectio_proto::metadata::NodePlacement {
                    te_segment: node_te_map
                        .get(&shard_loc.node_id)
                        .cloned()
                        .unwrap_or_default(),
                    position: shard_loc.position,
                    node_id: shard_loc.node_id.clone(),
                    node_address: node_addr,
                    disk_id: shard_loc.disk_id.clone(),
                    shard_type: shard_loc.shard_type,
                    local_group: shard_loc.local_group,
                };
                let pool = &state.osd_pool;
                let rdma = state.rdma.as_deref();
                let stripe_id = stripe.stripe_id;
                in_flight.push(async move {
                    let result = read_shard_from_osd(
                        pool,
                        &node_placement,
                        ec_shard_object_id,
                        stripe_id,
                        pos,
                        rdma,
                    )
                    .await;
                    (pos, dist, result)
                });
            }

            // Nothing in flight means k shards are in hand, or every
            // position has been tried.
            let Some((pos, dist, result)) = futures::StreamExt::next(&mut in_flight).await else {
                break;
            };
            match result {
                Ok(data) => {
                    let bytes = data.len();
                    debug!("Read shard {} ({} bytes, {})", pos, bytes, dist.as_str());
                    // Record per-locality read traffic so operators can see
                    // how much cross-zone/cross-dc bandwidth a typical
                    // object read consumes (Phase 2.4).
                    objectio_s3::observe_locality_read_bytes(dist.as_str(), bytes as u64);
                    shards[pos as usize] = Some(data);
                    read_count += 1;
                }
                Err(e) => {
                    warn!("Failed to read shard {}: {}", pos, e);
                }
            }
        }

        // Check if we have enough shards
        if read_count < ec_k {
            error!(
                "Insufficient shards to reconstruct stripe {}: have {}, need {}",
                stripe_idx, read_count, ec_k
            );
            return S3Error::xml_response(
                "InternalError",
                &format!(
                    "Cannot read object: only {} shards available for stripe {}, need {}",
                    read_count, stripe_idx, ec_k
                ),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }

        // Decode using erasure coding. Match the codec to how this stripe
        // was encoded — reading an LRC-written stripe with a plain MDS codec
        // produces wrong bytes (the decoder treats local parity shards as
        // global parity and reconstruction diverges). LRC config pulls the
        // (k, l, g) triple straight off the StripeMeta.
        let codec_config = if stripe_ec_type == ErasureType::ErasureLrc {
            ErasureConfig::lrc(
                ec_k as u8,
                stripe.ec_local_parity as u8,
                stripe.ec_global_parity as u8,
            )
        } else {
            ErasureConfig::new(ec_k as u8, ec_m as u8)
        };
        let codec = match ErasureCodec::new(codec_config) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create erasure codec: {}", e);
                return S3Error::xml_response(
                    "InternalError",
                    &format!("Erasure coding error: {}", e),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };

        let stripe_data = match codec.decode(&mut shards, stripe_data_size) {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to decode stripe {}: {}", stripe_idx, e);
                return S3Error::xml_response(
                    "InternalError",
                    &format!("Erasure decoding failed for stripe {}: {}", stripe_idx, e),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };

        let stripe_data = object_part(stripe, stripe_data);
        let (mut slice, slice_start_in_stripe): (Vec<u8>, u64) =
            if let Some(ref range) = resolved_range {
                let stripe_end = stripe_byte_offset + stripe_data.len() as u64;
                let slice_start = range.start.saturating_sub(stripe_byte_offset) as usize;
                let slice_end = std::cmp::min(range.end + 1, stripe_end)
                    .saturating_sub(stripe_byte_offset) as usize;
                (
                    stripe_data[slice_start..slice_end].to_vec(),
                    slice_start as u64,
                )
            } else {
                (stripe_data, 0)
            };
        if let Some(dek) = get_sse_dek.as_ref()
            && let Err(resp) = decrypt_stripe_slice(
                dek,
                stripe,
                &object,
                stripe_byte_offset,
                slice_start_in_stripe,
                &mut slice,
            )
        {
            return resp;
        }
        all_data.extend(slice);
    }
    phases.mark("shards");

    info!(
        "Read object: {}/{}, size={}, stripes_fetched={}/{}{}",
        bucket,
        key,
        all_data.len(),
        stripe_plan.len(),
        object.stripes.len(),
        if let Some(ref r) = resolved_range {
            format!(", range=bytes {}-{}", r.start, r.end)
        } else {
            String::new()
        }
    );

    // Verify data integrity for full (non-range) reads
    if resolved_range.is_none() && all_data.len() as u64 != total_size {
        error!(
            "Data size mismatch for {}/{}: reassembled {} bytes but object.size={}",
            bucket,
            key,
            all_data.len(),
            total_size
        );
    }

    // Build response — range requests already have sliced data.
    // Decryption (when the object is SSE-encrypted) has already been
    // applied per-stripe inside the fetch loop above.
    if let Some(ref range) = resolved_range {
        let content_range = format!("bytes {}-{}/{total_size}", range.start, range.end);

        let mut builder = with_version_id(Response::builder(), &object)
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, &object.content_type)
            .header(header::CONTENT_LENGTH, all_data.len().to_string())
            .header(header::CONTENT_RANGE, content_range)
            .header("ETag", &object.etag)
            .header("Accept-Ranges", "bytes")
            .header(
                header::LAST_MODIFIED,
                timestamp_to_http_date(object.modified_at),
            );
        if let Some(v) = sse_response_header {
            builder = builder.header("x-amz-server-side-encryption", v);
            if v == "aws:kms" && !object.kms_key_id.is_empty() {
                builder = builder.header(
                    "x-amz-server-side-encryption-aws-kms-key-id",
                    &object.kms_key_id,
                );
            }
        }
        if !sse_c_key_md5.is_empty() {
            builder = builder
                .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
                .header(
                    "x-amz-server-side-encryption-customer-key-md5",
                    &sse_c_key_md5,
                );
        }

        let builder = add_metadata_headers(builder, &object.user_metadata);
        let builder = add_tagging_count(builder, &object.tags);

        builder.body(Body::from(all_data)).unwrap()
    } else {
        let mut builder = with_version_id(Response::builder(), &object)
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, &object.content_type)
            .header(header::CONTENT_LENGTH, all_data.len().to_string())
            .header("ETag", &object.etag)
            .header("Accept-Ranges", "bytes")
            .header(
                header::LAST_MODIFIED,
                timestamp_to_http_date(object.modified_at),
            );
        if let Some(v) = sse_response_header {
            builder = builder.header("x-amz-server-side-encryption", v);
            if v == "aws:kms" && !object.kms_key_id.is_empty() {
                builder = builder.header(
                    "x-amz-server-side-encryption-aws-kms-key-id",
                    &object.kms_key_id,
                );
            }
        }
        if !sse_c_key_md5.is_empty() {
            builder = builder
                .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
                .header(
                    "x-amz-server-side-encryption-customer-key-md5",
                    &sse_c_key_md5,
                );
        }

        let builder = add_metadata_headers(builder, &object.user_metadata);
        let builder = add_tagging_count(builder, &object.tags);
        let builder = add_checksum_header(builder, &headers, &object);

        builder.body(Body::from(all_data)).unwrap()
    }
}

/// The bytes of an inline object a GET asked for: all of them, or `range`,
/// decrypted when the object is encrypted.
#[allow(clippy::result_large_err)]
fn inline_slice(
    object: &ObjectMeta,
    range: Option<&ByteRange>,
    dek: Option<&[u8; objectio_kms::DEK_LEN]>,
) -> Result<Vec<u8>, Response> {
    if object.inline_data.len() as u64 != object.size {
        error!(
            "Inline object {}/{} holds {} bytes but its size is {}",
            object.bucket,
            object.key,
            object.inline_data.len(),
            object.size
        );
        return Err(S3Error::xml_response(
            "InternalError",
            "Object metadata is inconsistent (inline size)",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }
    let (start, end) = range.map_or((0, object.size), |r| (r.start, r.end + 1));
    let mut data = object.inline_data[start as usize..end as usize].to_vec();
    if let Some(dek) = dek {
        // Stored like a single stripe starting at byte 0 of the object.
        decrypt_stripe_slice(dek, &StripeMeta::default(), object, 0, start, &mut data)?;
    }
    Ok(data)
}

/// Decrypt `buf` — one stripe's contribution to the GET response.
///
/// Picks the right IV + counter offset so a single helper works for both
/// the legacy single-stripe whole-body encryption scheme and the new
/// per-stripe IV scheme used by multipart SSE.
#[allow(clippy::result_large_err)]
fn decrypt_stripe_slice(
    dek: &[u8; objectio_kms::DEK_LEN],
    stripe: &StripeMeta,
    object: &ObjectMeta,
    stripe_byte_offset_in_object: u64,
    slice_start_in_stripe: u64,
    buf: &mut [u8],
) -> Result<(), Response> {
    // Per-stripe IV (multipart & new single-part): decrypt from offset within
    // the stripe. Otherwise fall back to the object-level IV (legacy whole-body
    // CTR), using the absolute byte offset within the object.
    let (iv_bytes, effective_offset) = if !stripe.encryption_iv.is_empty() {
        (&stripe.encryption_iv[..], slice_start_in_stripe)
    } else {
        (
            &object.encryption_iv[..],
            stripe_byte_offset_in_object + slice_start_in_stripe,
        )
    };
    if iv_bytes.len() != objectio_kms::IV_LEN {
        error!(
            "Bad IV length on {}/{}: got {}, want {}",
            object.bucket,
            object.key,
            iv_bytes.len(),
            objectio_kms::IV_LEN
        );
        return Err(S3Error::xml_response(
            "InternalError",
            "Object has malformed encryption metadata",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }
    let mut iv = [0u8; objectio_kms::IV_LEN];
    iv.copy_from_slice(iv_bytes);
    objectio_kms::decrypt_in_place(dek, &iv, effective_offset, buf);
    Ok(())
}

/// Resolve the gRPC address for a node.
///
/// First checks the in-memory map (populated from placement response).
/// On cache miss, fetches all active nodes via `GetListingNodes` and
/// populates the map so subsequent lookups are free.
async fn resolve_node_address(
    node_map: &mut HashMap<Vec<u8>, String>,
    meta_client: &mut MetadataServiceClient<Channel>,
    node_id: &[u8],
) -> String {
    // Fast path: already in the map (populated from placement or a prior listing call)
    if let Some(addr) = node_map.get(node_id) {
        return addr.clone();
    }

    // Slow path: node not in placement (topology may have changed).
    // Fetch all active nodes and populate the map.
    if let Ok(resp) = meta_client
        .get_listing_nodes(GetListingNodesRequest {
            bucket: String::new(),
            include_all_states: false,
        })
        .await
    {
        for n in &resp.into_inner().nodes {
            node_map
                .entry(n.node_id.clone())
                .or_insert_with(|| n.address.clone());
        }
    }

    node_map.get(node_id).cloned().unwrap_or_else(|| {
        warn!(
            "Could not resolve address for node {:?}, no listing entry found",
            Uuid::from_slice(node_id).map_or_else(|_| format!("{node_id:?}"), |u| u.to_string()),
        );
        String::from("http://localhost:9002")
    })
}

/// The object a DELETE of `key` — version `vid`, or the current object when
/// empty — leaves referenced by nothing, so its shards may be freed.
///
/// `None` when there is no such object, when it is still referenced, or when
/// that cannot be told: a version that is also the current object loses only
/// its version entry, and a current object that is also a version (written
/// while versioning was on) stays as that version. This used to free the
/// *current* object's shards whatever `vid` named, so deleting an old
/// version destroyed the latest one's data.
async fn unreferenced_after_delete(
    pool: &OsdPool,
    nodes: &[objectio_proto::metadata::NodePlacement],
    bucket: &str,
    key: &str,
    vid: &str,
) -> Option<ObjectMeta> {
    let current = get_object_meta_from_any(pool, nodes, bucket, key)
        .await
        .ok()?;
    if vid.is_empty() {
        let current = current?;
        if current.version_id.is_empty() {
            return Some(current);
        }
        let kept = get_object_version_meta_from_any(pool, nodes, bucket, key, &current.version_id)
            .await
            .ok()?;
        return kept
            .is_none_or(|v| v.object_id != current.object_id)
            .then_some(current);
    }
    let version = get_object_version_meta_from_any(pool, nodes, bucket, key, vid)
        .await
        .ok()??;
    current
        .is_none_or(|c| c.object_id != version.object_id)
        .then_some(version)
}

/// Head object (HEAD /{bucket}/{key})
pub async fn head_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HeadObjectParams>,
    // Authorized by `authz::authz_layer` before this handler runs.
    _auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    // If key is empty (trailing slash on bucket), treat as head_bucket
    if key.is_empty() {
        return head_bucket(State(state), Path(bucket)).await;
    }
    if let Some(mut refused) = sse_headers_on_read(&headers) {
        *refused.body_mut() = Body::empty();
        return refused;
    }

    let mut meta_client = state.meta_client.clone();

    // Get placement to find primary OSD
    let placement = match meta_client
        .get_placement(GetPlacementRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            size: 0,
            storage_class: "STANDARD".to_string(),
        })
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap();
        }
    };

    if placement.nodes.is_empty() {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::empty())
            .unwrap();
    }

    match object_to_read(
        &state,
        &placement.nodes,
        &bucket,
        &key,
        params.version_id.as_deref(),
    )
    .await
    {
        Ok(obj) if sse_c_read_refusal(&headers, &obj).is_some() => {
            let mut resp = sse_c_read_refusal(&headers, &obj).unwrap_or_default();
            *resp.body_mut() = Body::empty();
            resp
        }
        Ok(obj) if read_preconditions(&headers, &obj).is_some() => {
            let mut resp = read_preconditions(&headers, &obj).unwrap_or_default();
            *resp.body_mut() = Body::empty();
            resp
        }
        Ok(obj) => {
            // One part: its length, and how many parts there are.
            let (length, status, parts) = match params.part_number {
                None => (obj.size, StatusCode::OK, None),
                Some(n) => match part_bounds(&obj, n) {
                    Ok((start, end, count)) => (
                        (end + 1).saturating_sub(start),
                        StatusCode::PARTIAL_CONTENT,
                        is_multipart(&obj).then_some(count),
                    ),
                    Err(mut resp) => {
                        *resp.body_mut() = Body::empty();
                        return resp;
                    }
                },
            };
            let mut builder = with_version_id(Response::builder(), &obj)
                .status(status)
                .header(header::CONTENT_TYPE, &obj.content_type)
                .header(header::CONTENT_LENGTH, length.to_string())
                .header("ETag", &obj.etag)
                .header(
                    header::LAST_MODIFIED,
                    timestamp_to_http_date(obj.modified_at),
                );

            // Surface server-side encryption to HEAD responses so clients can
            // see how an object was stored without downloading it.
            let sse_algo =
                SseAlgorithm::try_from(obj.encryption_algorithm).unwrap_or(SseAlgorithm::SseNone);
            match sse_algo {
                SseAlgorithm::SseS3 => {
                    builder = builder.header("x-amz-server-side-encryption", "AES256");
                }
                SseAlgorithm::SseKms => {
                    builder = builder.header("x-amz-server-side-encryption", "aws:kms");
                    if !obj.kms_key_id.is_empty() {
                        builder = builder.header(
                            "x-amz-server-side-encryption-aws-kms-key-id",
                            &obj.kms_key_id,
                        );
                    }
                }
                SseAlgorithm::SseC => {
                    // Advertise the customer-algorithm marker so clients know
                    // this object needs a customer-key on GET. We don't know
                    // the key's md5 server-side; clients already do.
                    builder =
                        builder.header("x-amz-server-side-encryption-customer-algorithm", "AES256");
                }
                SseAlgorithm::SseNone => {}
            }

            // Add user metadata headers
            let builder = add_metadata_headers(builder, &obj.user_metadata);
            let builder = add_tagging_count(builder, &obj.tags);
            let mut builder = add_checksum_header(builder, &headers, &obj);
            if let Some(count) = parts {
                builder = builder.header("x-amz-mp-parts-count", count);
            }

            builder.body(Body::empty()).unwrap()
        }
        // HEAD has no body: keep the status and headers of the refusal.
        Err(mut resp) => {
            *resp.body_mut() = Body::empty();
            resp
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct HeadObjectParams {
    #[serde(rename = "versionId")]
    version_id: Option<String>,
    #[serde(rename = "partNumber")]
    part_number: Option<u32>,
}

/// The headers that describe a stored object beyond its content:
/// `x-amz-version-id` (not for the null version) and its object lock.
fn with_version_id(
    builder: axum::http::response::Builder,
    object: &ObjectMeta,
) -> axum::http::response::Builder {
    let mut builder = if object.version_id.is_empty() {
        builder
    } else {
        builder.header("x-amz-version-id", &object.version_id)
    };
    if let Some(r) = &object.retention
        && let Some(mode) = retention_mode_name(r.mode())
    {
        builder = builder.header("x-amz-object-lock-mode", mode).header(
            "x-amz-object-lock-retain-until-date",
            iso8601(r.retain_until_date),
        );
    }
    if let Some(h) = &object.legal_hold {
        builder = builder.header(
            "x-amz-object-lock-legal-hold",
            if h.status { "ON" } else { "OFF" },
        );
    }
    builder
}

fn retention_mode_name(mode: RetentionMode) -> Option<&'static str> {
    match mode {
        RetentionMode::RetentionGovernance => Some("GOVERNANCE"),
        RetentionMode::RetentionCompliance => Some("COMPLIANCE"),
        RetentionMode::RetentionNone => None,
    }
}

/// A unix time as S3 writes dates in object-lock headers and bodies.
fn iso8601(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The bucket's object-lock configuration, if object lock is on for it.
async fn bucket_lock(
    meta_client: &mut MetadataServiceClient<Channel>,
    bucket: &str,
) -> Result<Option<ProtoObjectLockConfig>, Response> {
    match meta_client
        .get_object_lock_configuration(GetObjectLockConfigRequest {
            bucket: bucket.to_string(),
        })
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            Ok(inner.config.filter(|c| inner.found && c.enabled))
        }
        Err(e) if e.code() == tonic::Code::NotFound => Err(S3Error::xml_response(
            "NoSuchBucket",
            "The specified bucket does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(e) => {
            warn!("{bucket}: cannot read its object lock configuration: {e}");
            Err(S3Error::xml_response(
                "ServiceUnavailable",
                "Cannot read the bucket's object lock configuration; retry",
                StatusCode::SERVICE_UNAVAILABLE,
            ))
        }
    }
}

/// Object lock asked of a bucket without it: S3's answer.
fn lock_not_configured() -> Response {
    S3Error::xml_response(
        "InvalidRequest",
        "Bucket is missing Object Lock Configuration",
        StatusCode::BAD_REQUEST,
    )
}

/// The lock a new object gets: what its `x-amz-object-lock-*` headers ask
/// for, otherwise the bucket's default retention. A WORM bucket used to
/// store objects with no lock at all, whatever it was configured or asked
/// to do: deletable at once.
async fn object_lock_for_write(
    meta_client: &mut MetadataServiceClient<Channel>,
    bucket: &str,
    headers: &HeaderMap,
) -> Result<(Option<ObjectRetention>, Option<LegalHold>), Response> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let mode = header("x-amz-object-lock-mode");
    let until = header("x-amz-object-lock-retain-until-date");
    let hold = header("x-amz-object-lock-legal-hold");
    let invalid =
        |msg: &str| S3Error::xml_response("InvalidArgument", msg, StatusCode::BAD_REQUEST);

    let config = bucket_lock(meta_client, bucket).await?;
    let Some(config) = config else {
        if mode.is_some() || until.is_some() || hold.is_some() {
            return Err(lock_not_configured());
        }
        return Ok((None, None));
    };

    let retention = match (mode, until) {
        (Some(mode), Some(until)) => {
            let mode = match mode.as_str() {
                "GOVERNANCE" => RetentionMode::RetentionGovernance,
                "COMPLIANCE" => RetentionMode::RetentionCompliance,
                _ => return Err(invalid("Unknown wormMode directive")),
            };
            let until = chrono::DateTime::parse_from_rfc3339(&until)
                .ok()
                .and_then(|d| u64::try_from(d.timestamp()).ok())
                .ok_or_else(|| invalid("The retain until date is not a valid date"))?;
            if until <= unix_now() {
                return Err(invalid("The retain until date must be in the future!"));
            }
            Some(ObjectRetention {
                mode: mode.into(),
                retain_until_date: until,
            })
        }
        (None, None) => config.default_retention.and_then(|d| {
            let now = chrono::Utc::now();
            let until = if d.days > 0 {
                now.checked_add_days(chrono::Days::new(u64::from(d.days)))
            } else if d.years > 0 {
                now.checked_add_months(chrono::Months::new(d.years.saturating_mul(12)))
            } else {
                None
            }?;
            Some(ObjectRetention {
                mode: d.mode,
                retain_until_date: u64::try_from(until.timestamp()).ok()?,
            })
        }),
        _ => {
            return Err(invalid(
                "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied",
            ));
        }
    };
    let legal_hold = match hold.as_deref() {
        None => None,
        Some("ON") => Some(LegalHold { status: true }),
        Some("OFF") => Some(LegalHold { status: false }),
        Some(_) => return Err(invalid("Legal Hold must be either of 'ON' or 'OFF'")),
    };
    Ok((retention, legal_hold))
}

/// The ObjectMeta a GET or HEAD reads: `version_id`'s, or the current
/// object's. Otherwise the response S3 gives: 404 NoSuchKey (with
/// `x-amz-delete-marker` when the current version is a delete marker), 404
/// NoSuchVersion, or 405 for a delete marker asked for by version.
async fn object_to_read(
    state: &AppState,
    nodes: &[objectio_proto::metadata::NodePlacement],
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<ObjectMeta, Response> {
    let failed = |e: crate::osd_pool::OsdPoolError| {
        error!("Failed to get object metadata from OSDs: {e}");
        S3Error::xml_response(
            "InternalError",
            &e.to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    };
    let marker_headers = |mut resp: Response, marker: &ObjectMeta| {
        let h = resp.headers_mut();
        h.insert(
            "x-amz-delete-marker",
            header::HeaderValue::from_static("true"),
        );
        if let Ok(v) = header::HeaderValue::from_str(version_label(&marker.version_id)) {
            h.insert("x-amz-version-id", v);
        }
        resp
    };
    let Some(wanted) = version_id else {
        return match get_object_meta_from_any(&state.osd_pool, nodes, bucket, key).await {
            Ok(Some(o)) if o.is_delete_marker => Err(marker_headers(
                S3Error::xml_response(
                    "NoSuchKey",
                    "The specified key does not exist.",
                    StatusCode::NOT_FOUND,
                ),
                &o,
            )),
            Ok(Some(o)) => Ok(o),
            Ok(None) => {
                let mut resp = S3Error::xml_response(
                    "NoSuchKey",
                    "The specified key does not exist.",
                    StatusCode::NOT_FOUND,
                );
                resp.headers_mut().insert(
                    "x-amz-delete-marker",
                    header::HeaderValue::from_static("false"),
                );
                Err(resp)
            }
            Err(e) => Err(failed(e)),
        };
    };
    let found = find_version(&state.osd_pool, nodes, bucket, key, wanted)
        .await
        .map_err(failed)?;
    match found {
        Some(o) if o.is_delete_marker => {
            let mut resp = marker_headers(
                S3Error::xml_response(
                    "MethodNotAllowed",
                    "The specified method is not allowed against this resource.",
                    StatusCode::METHOD_NOT_ALLOWED,
                ),
                &o,
            );
            resp.headers_mut()
                .insert(header::ALLOW, header::HeaderValue::from_static("DELETE"));
            Err(resp)
        }
        Some(o) => Ok(o),
        None => Err(S3Error::xml_response(
            "NoSuchVersion",
            "The specified version does not exist.",
            StatusCode::NOT_FOUND,
        )),
    }
}

/// DELETE `?versionId=`: remove that version for good. Each OSD replica,
/// under the key's lock, also makes the newest remaining version current if
/// this one was; the listing then follows whatever is current.
///
/// The version's shards are freed last, and only once every replica has
/// let go of it: one that hasn't may still have it current.
async fn delete_version(
    state: &Arc<AppState>,
    nodes: &[objectio_proto::metadata::NodePlacement],
    bucket: &str,
    key: &str,
    vid: &str,
) -> Response {
    let done = |marker: bool| {
        let mut b = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("x-amz-version-id", vid);
        if marker {
            b = b.header("x-amz-delete-marker", "true");
        }
        b.body(Body::empty()).unwrap()
    };
    let pool = &state.osd_pool;
    let version = match find_version(pool, nodes, bucket, key, vid).await {
        Ok(Some(v)) => v,
        // Deleting what isn't there succeeds, as S3 has it.
        Ok(None) => return done(false),
        Err(e) => {
            error!("{bucket}/{key} version {vid}: cannot read it: {e}");
            return S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let (ok, of) = delete_version_from_all(pool, nodes, bucket, key, vid).await;
    if ok == 0 {
        return S3Error::xml_response(
            "ServiceUnavailable",
            "No replica of the object's metadata could be reached; retry",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    let current = sync_listing(state, nodes, bucket, key).await;

    let still_current = current
        .as_ref()
        .is_some_and(|c| c.object_id == version.object_id);
    if ok < of || still_current {
        warn!(
            "{bucket}/{key} version {vid}: {ok} of {of} replicas let it go; \
             its blocks stay allocated"
        );
    } else if !version.stripes.is_empty() {
        let failed = reclaim_shards(
            pool,
            &mut state.meta_client.clone(),
            stripe_targets_of(&version),
            Reclaim::Delete,
        )
        .await;
        if failed > 0 {
            warn!(
                "{bucket}/{key} version {vid}: {failed} shard deletes failed; those blocks stay allocated"
            );
        }
    }
    info!("Deleted version {vid} of {bucket}/{key}");
    done(version.is_delete_marker)
}

/// Make meta's listing entry for `bucket/key` match its current object on
/// the OSDs: listed if it is an object, unlisted if a delete marker or
/// nothing. Re-checked after the write, since another request may have
/// changed the current object meanwhile. Returns the current object.
async fn sync_listing(
    state: &Arc<AppState>,
    nodes: &[objectio_proto::metadata::NodePlacement],
    bucket: &str,
    key: &str,
) -> Option<ObjectMeta> {
    use objectio_proto::metadata::DeleteObjectRequest as MetaDelReq;
    let mut meta_client = state.meta_client.clone();
    let mut current = get_object_meta_from_any(&state.osd_pool, nodes, bucket, key)
        .await
        .ok()
        .flatten();
    for _ in 0..3 {
        let written = match &current {
            Some(c) if !c.is_delete_marker => meta_client
                .create_object(objectio_proto::metadata::CreateObjectRequest {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    size: c.size,
                    content_type: c.content_type.clone(),
                    etag: c.etag.clone(),
                    user_metadata: c.user_metadata.clone(),
                    stripes: c.stripes.clone(),
                    object_id: c.object_id.clone(),
                    pg_id: 0,
                    pool: String::new(),
                    home_osd_ids: home_of(nodes),
                    ..Default::default()
                })
                .await
                .map(drop),
            _ => meta_client
                .delete_object(MetaDelReq {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    version_id: String::new(),
                    forget_home: false,
                })
                .await
                .map(drop),
        };
        if let Err(e) = written {
            // Readable by key regardless; the repairer restores listings.
            warn!("{bucket}/{key}: cannot update its listing: {e}");
        }
        let now = get_object_meta_from_any(&state.osd_pool, nodes, bucket, key)
            .await
            .ok()
            .flatten();
        let same = now.as_ref().map(|o| &o.object_id) == current.as_ref().map(|o| &o.object_id);
        current = now;
        if same {
            break;
        }
    }
    current
}

/// The bucket's versioning state, or the response to give: NoSuchBucket,
/// or 503 when it can't be read. Never a guess: taking "unversioned" for
/// a versioned bucket frees the version a write replaces.
async fn bucket_versioning(
    meta_client: &mut MetadataServiceClient<Channel>,
    bucket: &str,
) -> Result<VersioningState, Response> {
    match meta_client
        .get_bucket_versioning(GetBucketVersioningRequest {
            bucket: bucket.to_string(),
        })
        .await
    {
        Ok(resp) => Ok(resp.into_inner().state()),
        Err(e) if e.code() == tonic::Code::NotFound => Err(S3Error::xml_response(
            "NoSuchBucket",
            "The specified bucket does not exist",
            StatusCode::NOT_FOUND,
        )),
        Err(e) => {
            warn!("{bucket}: cannot read its versioning state: {e}");
            Err(S3Error::xml_response(
                "ServiceUnavailable",
                "Cannot read the bucket's versioning state; retry",
                StatusCode::SERVICE_UNAVAILABLE,
            ))
        }
    }
}

/// A copy's `x-amz-copy-source-server-side-encryption-customer-*` headers
/// (the SSE-C source's key) as the headers a GET of the source takes.
fn copy_source_customer_headers(copy_headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for suffix in ["algorithm", "key", "key-md5"] {
        if let Some(v) = copy_headers.get(format!(
            "x-amz-copy-source-server-side-encryption-customer-{suffix}"
        )) && let Ok(name) = header::HeaderName::from_bytes(
            format!("x-amz-server-side-encryption-customer-{suffix}").as_bytes(),
        ) {
            out.insert(name, v.clone());
        }
    }
    out
}

/// Whether a request asks for SSE-C on what it writes.
fn asks_sse_c(headers: &HeaderMap) -> bool {
    headers.keys().any(|k| {
        k.as_str()
            .starts_with("x-amz-server-side-encryption-customer-")
    })
}

/// A copy's `x-amz-copy-source-if-*` conditions as the GET conditions
/// they are on the source. Any that fails refuses the copy with 412.
fn copy_source_conditions(copy_headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (from, to) in [
        ("x-amz-copy-source-if-match", header::IF_MATCH),
        ("x-amz-copy-source-if-none-match", header::IF_NONE_MATCH),
        (
            "x-amz-copy-source-if-modified-since",
            header::IF_MODIFIED_SINCE,
        ),
        (
            "x-amz-copy-source-if-unmodified-since",
            header::IF_UNMODIFIED_SINCE,
        ),
    ] {
        if let Some(v) = copy_headers.get(from) {
            out.insert(to, v.clone());
        }
    }
    out
}

/// A source read refused by its conditions: 304 too is a 412 for a copy.
fn copy_condition_failed(resp: Response) -> Response {
    if resp.status() == StatusCode::NOT_MODIFIED {
        return condition_refused("PreconditionFailed");
    }
    resp
}

/// What a copy reads: an object, at a version or the current one.
struct CopySource {
    bucket: String,
    key: String,
    version: Option<String>,
}

/// `x-amz-copy-source`: "bucket/key", URL-decoded, and the version it
/// names, if any (`?versionId=`).
fn copy_source_of(headers: &HeaderMap) -> Option<(String, Option<String>)> {
    let raw = headers.get("x-amz-copy-source")?.to_str().ok()?;
    let (path, version) = match raw.split_once("?versionId=") {
        Some((p, v)) => (p, Some(v.to_string())),
        None => (raw, None),
    };
    let decoded = urlencoding::decode(path).unwrap_or_else(|_| path.into());
    Some((decoded.trim_start_matches('/').to_string(), version))
}

/// For a sub-resource request (tagging, retention, legal hold) naming a
/// version: those act on the current version only, so refuse one naming
/// another rather than answer for the wrong version.
async fn unless_current(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
) -> Option<Response> {
    let wanted = version_id?;
    let nodes = match get_placement_nodes_for_object(state, bucket, key).await {
        Ok(n) => n,
        Err(resp) => return Some(resp),
    };
    match get_object_meta_from_any(&state.osd_pool, &nodes, bucket, key).await {
        Ok(Some(current)) if version_label(&current.version_id) == wanted => None,
        Ok(_) => match find_version(&state.osd_pool, &nodes, bucket, key, wanted).await {
            Ok(Some(_)) => Some(S3Error::xml_response(
                "NotImplemented",
                "Only the current version's tagging, retention and legal hold can be read or set",
                StatusCode::NOT_IMPLEMENTED,
            )),
            _ => Some(S3Error::xml_response(
                "NoSuchVersion",
                "The specified version does not exist.",
                StatusCode::NOT_FOUND,
            )),
        },
        Err(e) => Some(S3Error::xml_response(
            "InternalError",
            &e.to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

/// Why a lock forbids deleting `meta`, as the response to give.
fn lock_refusal(meta: &ObjectMeta, headers: &HeaderMap) -> Option<Response> {
    // Check legal hold
    if meta.legal_hold.as_ref().is_some_and(|lh| lh.status) {
        return Some(S3Error::xml_response(
            "AccessDenied",
            "Object is under legal hold and cannot be deleted",
            StatusCode::FORBIDDEN,
        ));
    }

    // Check retention
    if let Some(retention) = &meta.retention {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if retention.retain_until_date > now {
            let bypass = headers
                .get("x-amz-bypass-governance-retention")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));

            if retention.mode() == RetentionMode::RetentionCompliance {
                return Some(S3Error::xml_response(
                    "AccessDenied",
                    "Object is under compliance retention and cannot be deleted",
                    StatusCode::FORBIDDEN,
                ));
            }
            if retention.mode() == RetentionMode::RetentionGovernance && !bypass {
                return Some(S3Error::xml_response(
                    "AccessDenied",
                    "Object is under governance retention. Use x-amz-bypass-governance-retention header to override",
                    StatusCode::FORBIDDEN,
                ));
            }
        }
    }
    None
}

/// A new version's id: a UUIDv7, so ids sort by when they were made, and
/// "newest" is the same on every OSD and gateway that lists them.
fn new_version_id() -> String {
    Uuid::now_v7().to_string()
}

/// Where a version sorts among its key's: when it was made, in ms. A
/// UUIDv7 id carries it; the null version and older ids use its
/// modification time.
fn version_age(object: &ObjectMeta) -> (u64, &str) {
    let ms = Uuid::parse_str(&object.version_id)
        .ok()
        .filter(|u| u.get_version_num() == 7)
        .and_then(|u| u.get_timestamp())
        .map_or(object.modified_at.saturating_mul(1000), |t| {
            let (secs, nanos) = t.to_unix();
            secs * 1000 + u64::from(nanos / 1_000_000)
        });
    (ms, object.version_id.as_str())
}

/// A version as S3 names it: the null version is "null".
fn version_label(version_id: &str) -> &str {
    if version_id.is_empty() {
        "null"
    } else {
        version_id
    }
}

/// Version `wanted` of `bucket/key` ("null" is the object stored while
/// versioning was off): the current object if it is that version, else its
/// version entry.
async fn find_version(
    pool: &OsdPool,
    nodes: &[objectio_proto::metadata::NodePlacement],
    bucket: &str,
    key: &str,
    wanted: &str,
) -> Result<Option<ObjectMeta>, crate::osd_pool::OsdPoolError> {
    if wanted == "null"
        && let Some(current) = get_object_meta_from_any(pool, nodes, bucket, key).await?
        && current.version_id.is_empty()
    {
        return Ok(Some(current));
    }
    get_object_version_meta_from_any(pool, nodes, bucket, key, wanted).await
}

/// Delete object (DELETE /{bucket}/{key})
pub async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    // Authorized by `authz::authz_layer` before this handler runs.
    _auth: Option<Extension<AuthResult>>,
    version_id: Option<String>,
    headers: HeaderMap,
) -> Response {
    let mut meta_client = state.meta_client.clone();

    // Get placement to find primary OSD
    let placement = match meta_client
        .get_placement(GetPlacementRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            size: 0,
            storage_class: "STANDARD".to_string(),
        })
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap();
        }
    };

    if placement.nodes.is_empty() {
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap();
    }

    // Check versioning state
    let versioning = match bucket_versioning(&mut meta_client, &bucket).await {
        Ok(v) => Some(v),
        Err(resp) => return resp,
    };
    let versioning_enabled = versioning == Some(VersioningState::VersioningEnabled);
    // Known never to have had versions, so nothing of the key outlives
    // this delete and its home can go. Not when the state is unknown.
    let never_versioned = versioning == Some(VersioningState::VersioningDisabled);

    // Conditional delete (If-Match, x-amz-if-match-last-modified-time,
    // x-amz-if-match-size): on the version named, or else the key's object:
    // the current one, or behind a delete marker the newest version that
    // is an object. No object at all: the delete succeeds, as S3 has it.
    if DeleteCondition::from_headers(&headers).is_set() {
        let pool = &state.osd_pool;
        let nodes = &placement.nodes;
        let target = match &version_id {
            Some(vid) => find_version(pool, nodes, &bucket, &key, vid)
                .await
                .ok()
                .flatten(),
            None => match get_object_meta_from_any(pool, nodes, &bucket, &key).await {
                Ok(Some(c)) if c.is_delete_marker => {
                    newest_object(pool, nodes, &bucket, &key).await
                }
                Ok(current) => current,
                Err(_) => None,
            },
        };
        if target.is_some_and(|t| !DeleteCondition::from_headers(&headers).holds(&t)) {
            return condition_refused("PreconditionFailed");
        }
    }

    // Lock enforcement: retention and legal hold protect the version a
    // delete would destroy. A versioned delete without a version destroys
    // nothing (it adds a marker), so S3 allows it.
    let protected = if let Some(vid) = &version_id {
        find_version(&state.osd_pool, &placement.nodes, &bucket, &key, vid)
            .await
            .ok()
            .flatten()
    } else if versioning_enabled {
        None
    } else {
        get_object_meta_from_any(&state.osd_pool, &placement.nodes, &bucket, &key)
            .await
            .ok()
            .flatten()
    };
    if let Some(meta) = protected
        && let Some(refusal) = lock_refusal(&meta, &headers)
    {
        return refusal;
    }

    if versioning_enabled && version_id.is_none() {
        // Versioned delete without version_id: create a delete marker
        let marker_version_id = new_version_id();
        let delete_marker = ObjectMeta {
            bucket: bucket.clone(),
            key: key.clone(),
            object_id: Uuid::new_v4().as_bytes().to_vec(),
            size: 0,
            etag: String::new(),
            content_type: String::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            modified_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            storage_class: String::new(),
            user_metadata: HashMap::new(),
            version_id: marker_version_id.clone(),
            is_delete_marker: true,
            stripes: Vec::new(),
            retention: None,
            legal_hold: None,
            ..Default::default()
        };

        if let Err(e) = put_object_meta_to_all(
            &state.osd_pool,
            &placement.nodes,
            &bucket,
            &key,
            delete_marker,
            true,
            &[],
        )
        .await
        {
            error!("Failed to create delete marker: {}", e);
            return S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }

        // The key no longer has a current version, so drop it from Meta's
        // listing index; it stays reachable through ListObjectVersions.
        {
            use objectio_proto::metadata::DeleteObjectRequest as MetaDelReq;
            let _ = state
                .meta_client
                .clone()
                .delete_object(MetaDelReq {
                    bucket: bucket.clone(),
                    key: key.clone(),
                    version_id: String::new(),
                    forget_home: false,
                })
                .await;
        }

        info!(
            "Created delete marker: {}/{} (version={})",
            bucket, key, marker_version_id
        );
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("x-amz-version-id", &marker_version_id)
            .header("x-amz-delete-marker", "true")
            .body(Body::empty())
            .unwrap();
    }

    if let Some(vid) = version_id {
        return delete_version(&state, &placement.nodes, &bucket, &key, &vid).await;
    }

    // Without a version: the current object goes. (With versioning on, a
    // marker was added above instead.)

    // Reclaim the shards *before* dropping the metadata: the stripe layout is
    // the only record of where they live, so destroying it first would leak
    // every block the object occupied with no way left to find them. That is
    // what used to happen — the shards were never deleted at all — so a
    // cluster could show an empty bucket and a disk with no free blocks.
    if let Some(meta) =
        unreferenced_after_delete(&state.osd_pool, &placement.nodes, &bucket, &key, "").await
        && !meta.stripes.is_empty()
    {
        let failed = reclaim_shards(
            &state.osd_pool,
            &mut meta_client,
            stripe_targets_of(&meta),
            Reclaim::Delete,
        )
        .await;
        if failed > 0 {
            // Leaked blocks, not lost data — the object is gone either way.
            warn!(
                "{}/{}: {} shard deletes failed; those blocks stay allocated",
                bucket, key, failed
            );
        }
    }

    if let Err(e) =
        delete_object_meta_from_all(&state.osd_pool, &placement.nodes, &bucket, &key, "").await
    {
        warn!("Failed to delete object metadata from OSD: {}", e);
    }

    // Unregister from Meta's listing index. Non-fatal if it fails —
    // the next ListObjects sweep will re-check the OSDs and prune.
    {
        use objectio_proto::metadata::DeleteObjectRequest as MetaDelReq;
        let mut meta_client = state.meta_client.clone();
        let _ = meta_client
            .delete_object(MetaDelReq {
                bucket: bucket.clone(),
                key: key.clone(),
                version_id: String::new(),
                forget_home: never_versioned,
            })
            .await;
    }

    info!("Deleted object: {}/{}", bucket, key);
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap()
}

/// Delete multiple objects (POST /{bucket}?delete)
pub async fn delete_objects(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    debug!("DELETE objects: {} (batch)", bucket);

    // Parse XML request body
    let delete_request = match DeleteObjectsRequest::parse(body.as_ref()) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to parse DeleteObjects request: {}", e);
            return S3Error::xml_response(
                "MalformedXML",
                &format!("Invalid XML: {}", e),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    if delete_request.objects.is_empty() {
        return S3Error::xml_response(
            "MalformedXML",
            "No objects specified for deletion",
            StatusCode::BAD_REQUEST,
        );
    }

    // Limit number of objects per request (S3 limit is 1000)
    if delete_request.objects.len() > 1000 {
        return S3Error::xml_response(
            "MalformedXML",
            "Too many objects specified (max 1000)",
            StatusCode::BAD_REQUEST,
        );
    }

    let mut deleted = Vec::new();
    let mut errors = Vec::new();

    // Delete each object
    let quiet = delete_request.quiet;
    for obj in delete_request.objects {
        // Batch delete reports per-key outcomes inside a 200 response, so
        // each key is evaluated here instead of by the middleware, which
        // classifies this route as `DeferToHandler`.
        if let Some(Extension(auth_result)) = &auth
            && crate::authz::authorize(
                &state,
                auth_result,
                &crate::authz::AuthzRequest {
                    method: &Method::DELETE,
                    action: "s3:DeleteObject",
                    bucket: &bucket,
                    key: Some(&obj.key),
                    scope_key: &obj.key,
                    headers: None,
                },
            )
            .await
            .is_some()
        {
            errors.push(DeleteError {
                key: obj.key,
                version_id: obj.version_id,
                code: "AccessDenied".to_string(),
                message: "Access Denied".to_string(),
            });
            continue;
        }

        // Each key goes through the single-object DELETE, so a batch gets
        // the same versioning, object-lock and listing handling, and frees
        // the shards. Deleting only the ObjectMeta here, as this did, left
        // every object's shards allocated and its listing entry behind.
        let mut object_headers = headers.clone();
        for (name, value) in [
            ("if-match", &obj.etag),
            ("x-amz-if-match-last-modified-time", &obj.last_modified_time),
            ("x-amz-if-match-size", &obj.size),
        ] {
            if let Some(v) = value
                && let Ok(v) = header::HeaderValue::from_str(v)
            {
                object_headers.insert(name, v);
            }
        }
        let resp = delete_object(
            State(Arc::clone(&state)),
            Path((bucket.clone(), obj.key.clone())),
            None,
            obj.version_id.clone(),
            object_headers,
        )
        .await;
        if resp.status().is_success() {
            let header_version = resp
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let delete_marker = resp.headers().contains_key("x-amz-delete-marker");
            deleted.push(DeletedObject {
                key: obj.key,
                // A version deleted by id is named; a marker just added is
                // named as the marker.
                version_id: obj.version_id.clone(),
                delete_marker,
                delete_marker_version_id: if delete_marker { header_version } else { None },
            });
        } else {
            let code = resp
                .extensions()
                .get::<crate::gateway_metrics::S3ErrorCode>()
                .map_or_else(|| "InternalError".to_string(), |c| c.0.clone());
            errors.push(DeleteError {
                key: obj.key,
                version_id: obj.version_id,
                message: code.clone(),
                code,
            });
        }
    }

    info!(
        "Batch delete: bucket={}, deleted={}, errors={}",
        bucket,
        deleted.len(),
        errors.len()
    );

    // Build response: in quiet mode, only what could not be deleted.
    if quiet {
        deleted.clear();
    }
    let result = DeleteObjectsResult { deleted, errors };

    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        to_xml(&result).unwrap_or_default()
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(xml))
        .unwrap()
}

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

/// Get bucket policy (GET /{bucket}?policy) - internal implementation
async fn get_bucket_policy_internal(state: Arc<AppState>, bucket: String) -> Response {
    let mut client = state.meta_client.clone();

    match client
        .get_bucket_policy(GetBucketPolicyRequest {
            bucket: bucket.clone(),
        })
        .await
    {
        Ok(response) => {
            let policy_resp = response.into_inner();
            if policy_resp.has_policy {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(policy_resp.policy_json))
                    .unwrap()
            } else {
                S3Error::xml_response(
                    "NoSuchBucketPolicy",
                    "The bucket policy does not exist",
                    StatusCode::NOT_FOUND,
                )
            }
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                S3Error::xml_response(
                    "NoSuchBucket",
                    "The specified bucket does not exist",
                    StatusCode::NOT_FOUND,
                )
            } else {
                error!("Failed to get bucket policy: {}", e);
                S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
    }
}

/// Set bucket policy (PUT /{bucket}?policy) - internal implementation
async fn put_bucket_policy_internal(state: Arc<AppState>, bucket: String, body: Bytes) -> Response {
    let mut client = state.meta_client.clone();

    // Parse the policy JSON to validate it
    let policy_json = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(_) => {
            return S3Error::xml_response(
                "MalformedPolicy",
                "The policy is not valid UTF-8",
                StatusCode::BAD_REQUEST,
            );
        }
    };

    // Validate JSON format
    if serde_json::from_str::<serde_json::Value>(&policy_json).is_err() {
        return S3Error::xml_response(
            "MalformedPolicy",
            "The policy is not valid JSON",
            StatusCode::BAD_REQUEST,
        );
    }

    // Valid JSON is not enough: a document that is not a valid *policy* parses
    // as nothing at authorization time, and the bucket then behaves as though
    // no policy were set — a grant that silently does nothing, visible only as
    // a log line. Reject it here instead.
    if let Err(e) = BucketPolicy::from_json(&policy_json) {
        return S3Error::xml_response(
            "MalformedPolicy",
            &format!("The policy is not a valid bucket policy: {e}"),
            StatusCode::BAD_REQUEST,
        );
    }

    match client
        .set_bucket_policy(SetBucketPolicyRequest {
            bucket: bucket.clone(),
            policy_json,
        })
        .await
    {
        Ok(_) => {
            info!("Set bucket policy for: {}", bucket);
            // Drop the cached copy so this gateway enforces the new policy on
            // the next request instead of after the TTL.
            state.policy_cache.invalidate(&bucket);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                S3Error::xml_response(
                    "NoSuchBucket",
                    "The specified bucket does not exist",
                    StatusCode::NOT_FOUND,
                )
            } else if e.code() == tonic::Code::InvalidArgument {
                S3Error::xml_response("MalformedPolicy", e.message(), StatusCode::BAD_REQUEST)
            } else {
                error!("Failed to set bucket policy: {}", e);
                S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
    }
}

/// Delete bucket policy (DELETE /{bucket}?policy) - internal implementation
async fn delete_bucket_policy_internal(state: Arc<AppState>, bucket: String) -> Response {
    let mut client = state.meta_client.clone();

    match client
        .delete_bucket_policy(DeleteBucketPolicyRequest {
            bucket: bucket.clone(),
        })
        .await
    {
        Ok(_) => {
            info!("Deleted bucket policy for: {}", bucket);
            state.policy_cache.invalidate(&bucket);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                S3Error::xml_response(
                    "NoSuchBucket",
                    "The specified bucket does not exist",
                    StatusCode::NOT_FOUND,
                )
            } else {
                error!("Failed to delete bucket policy: {}", e);
                S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
    }
}

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
        initiate_multipart_upload_internal(state, bucket, key, &headers).await
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

/// `POST /{bucket}/{key}?grep` — gateway-side regex/grep over the
/// object's contents. Reuses the normal authenticated GetObject path
/// to fetch the body, then streams match events (NDJSON) back with
/// full byte-offset metadata for agent follow-up fetches. See
/// `grep.rs` for the wire format.
///
/// v1 collects the object body into memory before scanning — fine for
/// the .md / .txt / .jsonl agent use case up to a few GiB. Streaming
/// directly off the EC read path is a follow-up.
async fn grep_object_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    use crate::grep;
    // Parse the grep request body first — fast fail on bad JSON.
    let req = match grep::parse_body(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Re-use the existing get_object pipeline so we inherit SigV4
    // policy, bucket policy, SSE-C decryption, versioning.
    // No Range header — we need the full object for scanning.
    let mut get_headers = HeaderMap::new();
    for (k, v) in headers.iter() {
        // Carry auth + SSE-C headers; strip Content-Type (not needed
        // for GetObject).
        if k == header::CONTENT_TYPE {
            continue;
        }
        get_headers.insert(k, v.clone());
    }
    let resp = get_object(State(state.clone()), Path((bucket, key)), auth, get_headers).await;
    if !resp.status().is_success() {
        return resp; // NotFound, AccessDenied, etc. — pass through
    }

    let size: u64 = resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let etag = resp
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Wrap the GetObject body stream as an AsyncRead so the scanner
    // walks line-by-line through a 64 KiB BufReader — memory bounded
    // regardless of object size. No collect-to-bytes; no 16 GiB cap.
    use futures::TryStreamExt;
    use tokio_util::io::StreamReader;
    let body_stream = resp
        .into_body()
        .into_data_stream()
        .map_err(std::io::Error::other);
    let reader = StreamReader::new(body_stream);
    grep::respond(req, reader, size, etag)
}

/// `POST /{bucket}?grep` — prefix-scoped regex grep across many keys.
/// Lists keys under the requested prefix, runs the same scan as the
/// single-object path on each, and streams match events tagged by
/// `bucket` + `key`. Emits `Object` / `ObjectEnd` frames bracketing
/// each key's matches so agents know when one file is done.
///
/// Global `max_matches` caps the total match stream; per-object cap
/// protects against a single noisy file exhausting the budget.
///
/// Same memory caveat as single-object grep — each object is
/// collected in full before scanning. Follow-up for streaming.
async fn grep_prefix_internal(
    state: Arc<AppState>,
    bucket: String,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    use crate::grep;
    let req = match grep::parse_prefix_body(&headers, &body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let (per_object_req_template, caps) = req.to_per_object();

    // List keys up-front so we know the cap. Agents asking for a
    // scan over 10k keys should use pagination; v1 caps at
    // `max_keys`. Pagination: callers pass the previous response's
    // `next_continuation_token` back in `caps.continuation_token` to
    // resume where the last scan stopped.
    let mut meta_client = state.meta_client.clone();
    let list_resp = match meta_client
        .list_objects(objectio_proto::metadata::ListObjectsRequest {
            bucket: bucket.clone(),
            prefix: caps.prefix.clone(),
            delimiter: String::new(),
            start_after: String::new(),
            continuation_token: caps.continuation_token.clone(),
            max_keys: caps.max_keys,
            include_versions: false,
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return S3Error::xml_response(
                "InternalError",
                &format!("list_objects failed: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let mut keys: Vec<(String, u64)> = list_resp
        .entries
        .into_iter()
        .map(|e| (e.key, e.size))
        .collect();

    // Capture the pagination cursor — emitted in the End frame so the
    // client can continue on the next request.
    let mut next_token: Option<String> =
        if list_resp.is_truncated && !list_resp.next_continuation_token.is_empty() {
            Some(list_resp.next_continuation_token.clone())
        } else {
            None
        };

    // Meta's OBJECT_LISTINGS table may be empty for pre-migration
    // objects. Fall back to the scatter-gather path (same as
    // list_objects handler) so freshly-uploaded aio-backed buckets
    // work out of the box. scatter_gather returns its own
    // is_truncated + next_continuation_token; carry those through.
    if keys.is_empty() {
        let ct_opt = if caps.continuation_token.is_empty() {
            None
        } else {
            Some(caps.continuation_token.as_str())
        };
        if let Ok(list_result) = state
            .scatter_gather
            .list_objects(
                &mut meta_client,
                &bucket,
                &caps.prefix,
                caps.max_keys,
                ct_opt,
                "",
            )
            .await
        {
            keys = list_result
                .objects
                .into_iter()
                .map(|o| (o.key, o.size))
                .collect();
            if list_result.is_truncated {
                next_token = list_result.next_continuation_token;
            }
        }
    }

    tracing::info!(
        "grep-prefix: bucket={} prefix={:?} listed {} keys",
        bucket,
        caps.prefix,
        keys.len()
    );

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(256);
    let state = Arc::clone(&state);
    let bucket_for_task = bucket.clone();
    let pattern_echo = per_object_req_template.pattern.clone();

    tokio::spawn(async move {
        use std::time::Instant;
        let start_time = Instant::now();
        // Emit a Start frame up-front (reusing the single-object
        // Start event shape) so clients see a pattern echo + per-scan
        // correlation ID. file_size/etag are zeroed — multi-object
        // scans have neither at this level.
        let _ = crate::grep::emit_prefix_start(&pattern_echo, &tx).await;

        let mut matches_global: u64 = 0;
        let mut bytes_scanned: u64 = 0;
        let mut objects_scanned: u64 = 0;
        let mut truncated = false;

        for (key, size_hint) in keys {
            if matches_global >= caps.max_matches_global as u64 {
                truncated = true;
                break;
            }
            // Fetch the object by re-entering the authenticated GET
            // path. Keeps SigV4 + bucket-policy + SSE-C consistent
            // with single-object grep.
            let get_headers = HeaderMap::new();
            let resp = get_object(
                State(Arc::clone(&state)),
                Path((bucket_for_task.clone(), key.clone())),
                auth.clone(),
                get_headers,
            )
            .await;
            if !resp.status().is_success() {
                // Non-fatal: skip this key but note it.
                let _ = tx
                    .send(Ok(Bytes::from(
                        serde_json::json!({
                            "type": "error",
                            "message": format!(
                                "skip {}/{}: status {}", bucket_for_task, key, resp.status()
                            ),
                        })
                        .to_string()
                            + "\n",
                    )))
                    .await;
                continue;
            }
            let file_size: u64 = resp
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(size_hint);
            let etag = resp
                .headers()
                .get(header::ETAG)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let _ =
                crate::grep::emit_object_start(&bucket_for_task, &key, file_size, &etag, &tx).await;

            // Stream the body directly into the scanner — no
            // collect-to-bytes, no memory cap, per-line processing.
            use futures::TryStreamExt;
            use tokio_util::io::StreamReader;
            let body_stream = resp
                .into_body()
                .into_data_stream()
                .map_err(std::io::Error::other);
            let reader = StreamReader::new(body_stream);

            let remaining = caps.max_matches_global as u64 - matches_global;
            let per_req = crate::grep::GrepRequest {
                pattern: per_object_req_template.pattern.clone(),
                literal: per_object_req_template.literal,
                case_insensitive: per_object_req_template.case_insensitive,
                max_matches: per_object_req_template.max_matches,
                content_max_bytes: per_object_req_template.content_max_bytes,
                invert: per_object_req_template.invert,
                engine: per_object_req_template.engine.clone(),
            };
            let (matches_here, per_truncated, obj_bytes) = crate::grep::scan_object_into_channel(
                bucket_for_task.clone(),
                key.clone(),
                reader,
                per_req,
                remaining,
                tx.clone(),
            )
            .await;
            bytes_scanned += obj_bytes;
            matches_global += matches_here;
            objects_scanned += 1;
            let _ = crate::grep::emit_object_end(
                &bucket_for_task,
                &key,
                matches_here,
                per_truncated,
                &tx,
            )
            .await;
        }

        let _ = crate::grep::emit_prefix_end(
            matches_global,
            bytes_scanned,
            truncated,
            start_time.elapsed().as_millis() as u64,
            objects_scanned,
            next_token.clone(),
            &tx,
        )
        .await;
    });

    crate::grep::respond_from_channel(rx, None)
}

/// Initiate multipart upload - internal implementation
async fn initiate_multipart_upload_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    headers: &HeaderMap,
) -> Response {
    if let Some(refused) = sse_header_conflict(headers) {
        return refused;
    }
    if let Some(refused) = acl_header_refusal(headers) {
        return refused;
    }
    let mut client = state.meta_client.clone();

    // What the object will carry, fixed now as AWS fixes it: content type,
    // x-amz-meta-*, and tags (held in the upload's metadata until
    // CompleteMultipartUpload puts them on the object). All three used to
    // be dropped: a multipart object came back with none of them.
    let tags = match tagging_header(headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let mut user_metadata = extract_user_metadata(headers);
    if !tags.is_empty() {
        user_metadata.insert(UPLOAD_TAGS_KEY.to_string(), encode_tagging(&tags));
    }
    // Object lock asked for now, checked now, applied at completion (with
    // the bucket's default retention when none is asked for).
    if let Err(resp) = object_lock_for_write(&mut client, &bucket, headers).await {
        return resp;
    }
    for name in UPLOAD_LOCK_HEADERS {
        if let Some(v) = headers.get(*name).and_then(|v| v.to_str().ok()) {
            user_metadata.insert(format!("{UPLOAD_LOCK_PREFIX}{name}"), v.to_string());
        }
    }
    // The checksum algorithm its parts are checked with, and its composite
    // checksum made from.
    let checksum_algorithm = match headers
        .get("x-amz-checksum-algorithm")
        .and_then(|v| v.to_str().ok())
    {
        None => None,
        Some(name) => match crate::checksum::ChecksumAlgorithm::from_aws_name(name) {
            Some(a) => Some(a),
            None => {
                return S3Error::xml_response(
                    "InvalidRequest",
                    &format!("Checksum algorithm {name} is not supported"),
                    StatusCode::BAD_REQUEST,
                );
            }
        },
    };
    // COMPOSITE (a checksum of the parts' checksums) or FULL_OBJECT (the
    // whole object's CRC, combined from the parts'): S3's default by
    // algorithm, CRC64NVME being FULL_OBJECT only.
    let checksum_type = match headers
        .get("x-amz-checksum-type")
        .and_then(|v| v.to_str().ok())
    {
        Some(t) if t.eq_ignore_ascii_case("COMPOSITE") || t.eq_ignore_ascii_case("FULL_OBJECT") => {
            Some(t.to_ascii_uppercase())
        }
        Some(t) => {
            return S3Error::xml_response(
                "InvalidRequest",
                &format!("Checksum type {t} is not supported"),
                StatusCode::BAD_REQUEST,
            );
        }
        None => checksum_algorithm.map(|a| {
            if a == crate::checksum::ChecksumAlgorithm::Crc64Nvme {
                "FULL_OBJECT".to_string()
            } else {
                "COMPOSITE".to_string()
            }
        }),
    };
    if let (Some(a), Some(t)) = (checksum_algorithm, &checksum_type) {
        if t == "FULL_OBJECT" && !a.can_combine() {
            return S3Error::xml_response(
                "InvalidRequest",
                &format!(
                    "The FULL_OBJECT checksum type is not supported for {}",
                    a.aws_name()
                ),
                StatusCode::BAD_REQUEST,
            );
        }
        user_metadata.insert(UPLOAD_CHECKSUM_KEY.to_string(), a.aws_name().to_string());
        user_metadata.insert(UPLOAD_CHECKSUM_TYPE_KEY.to_string(), t.clone());
    }

    // SSE-C multipart: validate the customer key at CreateMultipartUpload
    // and stash its MD5 on meta. UploadPart requests must resupply the same
    // key; we never store the raw bytes. Warehouse-bucket guard matches the
    // single-part path.
    if headers
        .get("x-amz-server-side-encryption-customer-algorithm")
        .is_some()
    {
        let cust = match parse_sse_c_headers(headers) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return S3Error::xml_response(
                    "InvalidRequest",
                    "partial SSE-C headers",
                    StatusCode::BAD_REQUEST,
                );
            }
            Err(resp) => return resp,
        };
        if is_warehouse_bucket(&bucket) {
            return S3Error::xml_response(
                "InvalidEncryptionAlgorithmError",
                "SSE-C is not supported on warehouse buckets — query engines cannot provide the customer key on every read",
                StatusCode::BAD_REQUEST,
            );
        }
        // The key itself never leaves the gateway address space — we only
        // persist its MD5 so UploadPart can validate callers. The raw key
        // material in `cust.key` gets dropped when `cust` goes out of scope.
        let md5 = cust.md5_b64;

        match client
            .create_multipart_upload(CreateMultipartUploadRequest {
                bucket: bucket.clone(),
                key: key.clone(),
                content_type: content_type.clone(),
                user_metadata: user_metadata.clone(),
                encryption_algorithm: SseAlgorithm::SseC as i32,
                kms_key_id: String::new(),
                encrypted_dek: Vec::new(),
                customer_key_md5: md5.clone(),
                // No KMS context for SSE-C: what identifies the customer's
                // key, for reads of the object to check.
                encryption_context: sse_c_verifier(&cust.key),
            })
            .await
        {
            Ok(response) => {
                let resp = response.into_inner();
                let result = InitiateMultipartUploadResult {
                    bucket: resp.bucket,
                    key: resp.key,
                    upload_id: resp.upload_id,
                };
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                    to_xml(&result).unwrap_or_default()
                );
                info!("Initiated multipart upload (SSE-C): {}/{}", bucket, key);
                let mut builder = Response::builder();
                if let Some(a) = checksum_algorithm {
                    builder = builder.header("x-amz-checksum-algorithm", a.aws_name());
                }
                if let Some(t) = &checksum_type {
                    builder = builder.header("x-amz-checksum-type", t);
                }
                return builder
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/xml")
                    .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
                    .header("x-amz-server-side-encryption-customer-key-md5", &md5)
                    .body(Body::from(xml))
                    .unwrap();
            }
            Err(e) => {
                if e.code() == tonic::Code::NotFound {
                    return S3Error::xml_response(
                        "NoSuchBucket",
                        "The specified bucket does not exist",
                        StatusCode::NOT_FOUND,
                    );
                }
                error!("Failed to initiate SSE-C multipart upload: {}", e);
                return S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        }
    }

    // Resolve SSE up front. AWS fixes the MPU's SSE config at creation time;
    // per-UploadPart SSE headers are ignored. We generate + wrap the DEK
    // once here and stash it on meta alongside the MPU state.
    let sse_decision = match resolve_sse_decision(&mut client, &bucket, Some(headers)).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let (algo, kms_key_id, wrapped_dek, sse_response_header, encryption_context) =
        match sse_decision {
            None => (
                SseAlgorithm::SseNone as i32,
                String::new(),
                Vec::new(),
                None,
                HashMap::new(),
            ),
            Some(d) if d.algorithm == SseAlgorithm::SseS3 => {
                let Some(mk) = state.master_key.as_ref() else {
                    error!(
                        "Multipart upload {bucket}/{key} requires SSE-S3 but gateway has no master key"
                    );
                    return S3Error::xml_response(
                        "ServiceUnavailable",
                        "SSE master key not configured on the gateway",
                        StatusCode::SERVICE_UNAVAILABLE,
                    );
                };
                let dek = objectio_kms::generate_dek();
                (
                    SseAlgorithm::SseS3 as i32,
                    String::new(),
                    mk.wrap_dek(&dek),
                    Some("AES256"),
                    HashMap::new(),
                )
            }
            Some(d) if d.algorithm == SseAlgorithm::SseKms => {
                let Some(kms) = state.kms() else {
                    return S3Error::xml_response(
                        "ServiceUnavailable",
                        "SSE-KMS is not configured on this gateway",
                        StatusCode::SERVICE_UNAVAILABLE,
                    );
                };
                let data_key = match kms
                    .generate_data_key(&d.kms_key_id, &d.encryption_context)
                    .await
                {
                    Ok(g) => g,
                    Err(objectio_kms::KmsError::KeyNotFound(id)) => {
                        return S3Error::xml_response(
                            "KMS.NotFoundException",
                            &format!("KMS key '{id}' does not exist"),
                            StatusCode::BAD_REQUEST,
                        );
                    }
                    Err(e) => {
                        error!("KMS generate_data_key for MPU failed: {e}");
                        return S3Error::xml_response(
                            "InternalError",
                            &e.to_string(),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                };
                (
                    SseAlgorithm::SseKms as i32,
                    d.kms_key_id,
                    data_key.wrapped_dek,
                    Some("aws:kms"),
                    d.encryption_context,
                )
            }
            Some(d) => {
                error!(
                    "resolve_sse_decision returned unexpected algorithm for MPU: {:?}",
                    d.algorithm
                );
                return S3Error::xml_response(
                    "InternalError",
                    "unexpected SSE resolution",
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };

    let response_kms_key_id = kms_key_id.clone();
    match client
        .create_multipart_upload(CreateMultipartUploadRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            content_type,
            user_metadata,
            encryption_algorithm: algo,
            kms_key_id,
            encrypted_dek: wrapped_dek,
            customer_key_md5: String::new(),
            encryption_context,
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            let result = InitiateMultipartUploadResult {
                bucket: resp.bucket,
                key: resp.key,
                upload_id: resp.upload_id,
            };

            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                to_xml(&result).unwrap_or_default()
            );

            info!("Initiated multipart upload: {}/{}", bucket, key);

            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml");
            if let Some(a) = checksum_algorithm {
                builder = builder.header("x-amz-checksum-algorithm", a.aws_name());
            }
            if let Some(t) = &checksum_type {
                builder = builder.header("x-amz-checksum-type", t);
            }
            if let Some(v) = sse_response_header {
                builder = builder.header("x-amz-server-side-encryption", v);
                if v == "aws:kms" && !response_kms_key_id.is_empty() {
                    builder = builder.header(
                        "x-amz-server-side-encryption-aws-kms-key-id",
                        &response_kms_key_id,
                    );
                }
            }
            builder.body(Body::from(xml)).unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                S3Error::xml_response(
                    "NoSuchBucket",
                    "The specified bucket does not exist",
                    StatusCode::NOT_FOUND,
                )
            } else {
                error!("Failed to initiate multipart upload: {}", e);
                S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
    }
}

/// PUT /{bucket}/{key}?uploadId=X&partNumber=N - Upload part
pub async fn put_object_with_params(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<PutObjectParams>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // If uploadId and partNumber are present, this is a multipart part upload
    if let (Some(upload_id), Some(part_number)) = (params.upload_id, params.part_number) {
        if headers.contains_key("x-amz-copy-source") {
            return upload_part_copy_internal(
                state,
                bucket,
                key,
                upload_id,
                part_number,
                auth,
                headers,
            )
            .await;
        }
        return upload_part_internal(state, bucket, key, upload_id, part_number, headers, body)
            .await;
    }
    if params.acl.is_some() {
        return put_acl(&state, &bucket, Some(&key), &headers, &body).await;
    }
    if let Some(refused) = acl_header_refusal(&headers) {
        return refused;
    }
    if params.retention.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        return put_object_retention_internal(state, bucket, key, body, &headers).await;
    }
    if params.legal_hold.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        return put_object_legal_hold_internal(state, bucket, key, body).await;
    }
    if params.tagging.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        return put_object_tagging_internal(state, bucket, key, body).await;
    }

    // Otherwise, it's a regular PUT object
    put_object(State(state), Path((bucket, key)), auth, headers, body).await
}

/// Upload part - internal implementation
async fn upload_part_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
    part_number: u32,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    debug!(
        "Upload part: bucket={}, key={}, uploadId={}, partNumber={}, size={}",
        bucket,
        key,
        upload_id,
        part_number,
        body.len()
    );

    // Validate part number
    if part_number == 0 || part_number > 10000 {
        return S3Error::xml_response(
            "InvalidArgument",
            "Part number must be between 1 and 10000",
            StatusCode::BAD_REQUEST,
        );
    }

    // Refuse a part that does not match its checksum before any of it is
    // written, as PutObject does.
    let (checksums, verified_md5) = match verify_upload_checksums(&headers, &body).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Calculate ETag for this part — AWS semantics for SSE-S3/SSE-KMS:
    // part ETag is the MD5 of the *plaintext*. Compute before we possibly
    // encrypt below; Content-MD5 already did when it was sent.
    let etag = format!(
        "\"{}\"",
        verified_md5.map_or_else(|| crate::digest::md5_hex(&body), hex::encode)
    );
    let part_size = body.len() as u64;

    let mut meta_client = state.meta_client.clone();

    // Fetch the MPU's SSE state. The decision was made at CreateMultipartUpload
    // time — per-UploadPart SSE headers are ignored for SSE-S3/SSE-KMS. For
    // SSE-C the client must resupply their customer key on every part and we
    // validate against the stored MD5. If encryption is on, we unwrap the DEK
    // once and generate a fresh IV per stripe below.
    let declared_checksum: Option<String>;
    let (mpu_dek, sse_response_header, sse_kms_key_id, sse_c_key_md5_for_resp) = match meta_client
        .get_multipart_upload(GetMultipartUploadRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            upload_id: upload_id.clone(),
        })
        .await
    {
        Ok(resp) => {
            let mpu = resp.into_inner();
            if !mpu.found {
                return S3Error::xml_response(
                    "NoSuchUpload",
                    "The specified multipart upload does not exist",
                    StatusCode::NOT_FOUND,
                );
            }
            declared_checksum = mpu.user_metadata.get(UPLOAD_CHECKSUM_KEY).cloned();
            let algo =
                SseAlgorithm::try_from(mpu.encryption_algorithm).unwrap_or(SseAlgorithm::SseNone);
            match algo {
                SseAlgorithm::SseS3 => {
                    let Some(mk) = state.master_key.as_ref() else {
                        return S3Error::xml_response(
                            "ServiceUnavailable",
                            "SSE master key not configured on the gateway",
                            StatusCode::SERVICE_UNAVAILABLE,
                        );
                    };
                    match mk.unwrap_dek(&mpu.encrypted_dek) {
                        Ok(dek) => (Some(dek), Some("AES256"), String::new(), String::new()),
                        Err(e) => {
                            error!("Failed to unwrap DEK for MPU {upload_id}: {e}");
                            return S3Error::xml_response(
                                "InternalError",
                                "Failed to unwrap MPU DEK",
                                StatusCode::INTERNAL_SERVER_ERROR,
                            );
                        }
                    }
                }
                SseAlgorithm::SseKms => {
                    let Some(kms) = state.kms() else {
                        return S3Error::xml_response(
                            "ServiceUnavailable",
                            "SSE-KMS is not configured on this gateway",
                            StatusCode::SERVICE_UNAVAILABLE,
                        );
                    };
                    // The encryption context was supplied at CreateMultipartUpload
                    // and stored on the MPU state so every UploadPart uses the
                    // same AEAD binding as the wrapped DEK.
                    match kms
                        .decrypt(&mpu.kms_key_id, &mpu.encrypted_dek, &mpu.encryption_context)
                        .await
                    {
                        Ok(dek) => (Some(dek), Some("aws:kms"), mpu.kms_key_id, String::new()),
                        Err(e) => {
                            error!("Failed to unwrap KMS DEK for MPU {upload_id}: {e}");
                            return S3Error::xml_response(
                                "InternalError",
                                "Failed to unwrap MPU DEK via KMS",
                                StatusCode::INTERNAL_SERVER_ERROR,
                            );
                        }
                    }
                }
                SseAlgorithm::SseC => {
                    // UploadPart must resupply the customer key headers. Compare
                    // the provided MD5 against what was stored at CreateMPU; if
                    // they differ we reject without ever reading the key bytes.
                    let cust = match parse_sse_c_headers(&headers) {
                        Ok(Some(c)) => c,
                        Ok(None) => {
                            return S3Error::xml_response(
                                "InvalidRequest",
                                "UploadPart on an SSE-C multipart upload must include the customer-key headers",
                                StatusCode::BAD_REQUEST,
                            );
                        }
                        Err(resp) => return resp,
                    };
                    if cust.md5_b64 != mpu.customer_key_md5 {
                        return S3Error::xml_response(
                            "InvalidArgument",
                            "Customer key MD5 does not match the MD5 provided at CreateMultipartUpload",
                            StatusCode::BAD_REQUEST,
                        );
                    }
                    (Some(cust.key), None, String::new(), cust.md5_b64)
                }
                _ => (None, None, String::new(), String::new()),
            }
        }
        Err(e) => {
            error!("Failed to fetch MPU state for {upload_id}: {e}");
            return S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    // The part's checksum, kept for the object's composite: the one the
    // request sent (verified above), else computed with the algorithm the
    // upload declared. Over the plaintext, as the client sees the part.
    let part_checksum = match (&checksums.flexible, declared_checksum.as_deref()) {
        (Some(c), _) => Some(ObjectChecksum {
            algorithm: c.algorithm.aws_name().to_string(),
            value: c.value_b64(),
        }),
        (None, Some(name)) => crate::checksum::ChecksumAlgorithm::from_aws_name(name).map(|a| {
            use base64::Engine;
            ObjectChecksum {
                algorithm: a.aws_name().to_string(),
                value: base64::engine::general_purpose::STANDARD.encode(a.compute(&body)),
            }
        }),
        (None, None) => None,
    };

    // Get placement for this part (using a unique key for the part)
    let part_key = format!("__mpu/{}/part{:05}", upload_id, part_number);
    let placement = match meta_client
        .get_placement(GetPlacementRequest {
            bucket: bucket.clone(),
            key: part_key.clone(),
            size: part_size,
            storage_class: "STANDARD".to_string(),
        })
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(e) => {
            error!("Failed to get placement for part: {}", e);
            return S3Error::xml_response(
                "InternalError",
                &format!("Failed to get placement: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let ec_k = placement.ec_k;
    let ec_m = placement.ec_m;
    let ec_type = ErasureType::try_from(placement.ec_type).unwrap_or(ErasureType::ErasureMds);
    let replication_count = placement.replication_count;

    // Generate a unique object ID for this part
    let part_object_id = *Uuid::new_v4().as_bytes();
    let mut pending = pending_shards(
        &state,
        format!("{bucket}/{key} upload {upload_id} part {part_number}"),
    );

    // Replication mode: no EC, just write raw data to each replica
    // For large parts, split into multiple stripes (each stripe <= MAX_SHARD_SIZE)
    let (all_stripes, total_success, used_ec_type) = if ec_type == ErasureType::ErasureReplication {
        let total_replicas = replication_count.max(1) as usize;

        // Split data into stripes (each stripe must fit in a block)
        let stripe_size = MAX_SHARD_SIZE;
        let num_stripes = body.len().div_ceil(stripe_size);

        debug!(
            "Replication mode for part {}: writing {} replicas x {} stripes (size={})",
            part_number,
            total_replicas,
            num_stripes,
            body.len()
        );

        let mut all_stripes = Vec::with_capacity(num_stripes);
        let mut total_success = 0;

        for stripe_idx in 0..num_stripes {
            let stripe_start = stripe_idx * stripe_size;
            let stripe_end = std::cmp::min(stripe_start + stripe_size, body.len());
            // Copy this stripe's bytes out; encrypt in place if the MPU is
            // SSE-S3. A fresh IV per stripe means on GET each stripe can
            // decrypt independently starting from its own offset zero.
            let mut stripe_bytes = body[stripe_start..stripe_end].to_vec();
            let stripe_iv: Vec<u8> = if let Some(dek) = mpu_dek.as_ref() {
                let iv = objectio_kms::generate_iv();
                objectio_kms::encrypt_in_place(dek, &iv, &mut stripe_bytes);
                iv.to_vec()
            } else {
                Vec::new()
            };
            let stripe_bytes = Bytes::from(stripe_bytes);
            let stripe_data_size = stripe_bytes.len() as u64;

            let mut write_futures = Vec::with_capacity(total_replicas);

            for i in 0..total_replicas {
                let placement_node = if i < placement.nodes.len() {
                    placement.nodes[i].clone()
                } else if !placement.nodes.is_empty() {
                    placement.nodes[i % placement.nodes.len()].clone()
                } else {
                    error!("No placement nodes available");
                    return S3Error::xml_response(
                        "InternalError",
                        "No storage nodes available",
                        StatusCode::SERVICE_UNAVAILABLE,
                    );
                };

                let pool = state.osd_pool.clone();
                let obj_id = part_object_id;
                let shard_data = stripe_bytes.clone();
                let pos = i as u32;
                let s_idx = stripe_idx as u64;
                pending.sent(&placement_node, &obj_id, s_idx, pos);

                write_futures.push(async move {
                    let result = write_shard_to_osd(
                        &pool,
                        &placement_node,
                        &obj_id,
                        s_idx, // stripe_id
                        pos,
                        shard_data,
                        1,    // ec_k=1 for replication
                        0,    // ec_m=0 for replication
                        None, // Replicated stripes go over gRPC.
                    )
                    .await;
                    (pos, result, placement_node)
                });
            }

            let results = futures::future::join_all(write_futures).await;

            let mut success = 0;
            let mut locs = Vec::with_capacity(total_replicas);

            for (pos, result, placement_node) in results {
                match result {
                    Ok(location) => {
                        success += 1;
                        locs.push(ShardLocation {
                            position: pos,
                            node_id: location.node_id,
                            disk_id: location.disk_id,
                            offset: location.offset,
                            shard_type: placement_node.shard_type,
                            local_group: placement_node.local_group,
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Failed to write stripe {} replica {} for part: {}",
                            stripe_idx, pos, e
                        );
                    }
                }
            }

            if success < 1 {
                error!(
                    "Replication failed for part stripe {}: no successful writes",
                    stripe_idx
                );
                return S3Error::xml_response(
                    "InternalError",
                    &format!(
                        "Replication failed for stripe {}: no successful writes",
                        stripe_idx
                    ),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }

            total_success += success;
            locs.sort_by_key(|l| l.position);

            all_stripes.push(StripeMeta {
                stripe_id: stripe_idx as u64,
                ec_k: 1,
                ec_m: 0,
                shards: locs,
                ec_type: ErasureType::ErasureReplication.into(),
                ec_local_parity: 0,
                ec_global_parity: 0,
                local_group_size: 0,
                data_size: stripe_data_size,
                object_id: part_object_id.to_vec(), // Store object_id used for shards
                encryption_iv: stripe_iv.clone(),
                ..Default::default()
            });
        }

        (all_stripes, total_success, ErasureType::ErasureReplication)
    } else {
        // EC mode: encode data with erasure coding
        // For large parts, split into multiple stripes (each stripe's shards must fit in a block)
        let total_shards_per_stripe = (ec_k + ec_m) as usize;

        // Calculate max raw data per stripe: each shard is data_size/k bytes
        // To keep each shard <= MAX_SHARD_SIZE, raw data must be <= MAX_SHARD_SIZE * k
        let max_stripe_data_size = MAX_SHARD_SIZE * ec_k as usize;
        let num_stripes = body.len().div_ceil(max_stripe_data_size);

        debug!(
            "EC mode for part {}: {} stripes, {} shards/stripe (ec_k={}, ec_m={}), part_size={}",
            part_number,
            num_stripes,
            total_shards_per_stripe,
            ec_k,
            ec_m,
            body.len()
        );

        let codec = match ErasureCodec::new(ErasureConfig::new(ec_k as u8, ec_m as u8)) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create erasure codec: {}", e);
                return S3Error::xml_response(
                    "InternalError",
                    &format!("Erasure coding error: {}", e),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };

        let mut all_stripes = Vec::with_capacity(num_stripes);
        let mut total_success = 0;

        for stripe_idx in 0..num_stripes {
            let stripe_start = stripe_idx * max_stripe_data_size;
            let stripe_end = std::cmp::min(stripe_start + max_stripe_data_size, body.len());
            // Copy this stripe's bytes out; encrypt in place if the MPU is
            // SSE-S3. A fresh IV per stripe means on GET each stripe can
            // decrypt independently starting from its own offset zero.
            let mut stripe_bytes = body[stripe_start..stripe_end].to_vec();
            let stripe_iv: Vec<u8> = if let Some(dek) = mpu_dek.as_ref() {
                let iv = objectio_kms::generate_iv();
                objectio_kms::encrypt_in_place(dek, &iv, &mut stripe_bytes);
                iv.to_vec()
            } else {
                Vec::new()
            };
            let stripe_data_size = stripe_bytes.len() as u64;

            let shards: Vec<Bytes> = match codec.encode_bytes(&stripe_bytes) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to encode stripe {} data: {}", stripe_idx, e);
                    return S3Error::xml_response(
                        "InternalError",
                        &format!("Erasure encoding failed for stripe {}: {}", stripe_idx, e),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    );
                }
            };

            let mut write_futures = Vec::with_capacity(total_shards_per_stripe);
            for (i, shard) in shards.iter().enumerate() {
                let placement_node = if i < placement.nodes.len() {
                    placement.nodes[i].clone()
                } else if !placement.nodes.is_empty() {
                    placement.nodes[i % placement.nodes.len()].clone()
                } else {
                    error!("No placement nodes available");
                    return S3Error::xml_response(
                        "InternalError",
                        "No storage nodes available",
                        StatusCode::SERVICE_UNAVAILABLE,
                    );
                };

                let pool = state.osd_pool.clone();
                let obj_id = part_object_id;
                let shard_data = shard.clone();
                let pos = i as u32;
                let s_idx = stripe_idx as u64;
                pending.sent(&placement_node, &obj_id, s_idx, pos);

                write_futures.push(async move {
                    let result = write_shard_to_osd(
                        &pool,
                        &placement_node,
                        &obj_id,
                        s_idx, // stripe_id
                        pos,
                        shard_data,
                        ec_k,
                        ec_m,
                        None, // Multipart parts go over gRPC (for now).
                    )
                    .await;
                    (pos, result, placement_node)
                });
            }

            let results = futures::future::join_all(write_futures).await;

            let mut success = 0;
            let mut locs = Vec::with_capacity(total_shards_per_stripe);

            for (pos, result, placement_node) in results {
                match result {
                    Ok(location) => {
                        success += 1;
                        locs.push(ShardLocation {
                            position: pos,
                            node_id: location.node_id,
                            disk_id: location.disk_id,
                            offset: location.offset,
                            shard_type: placement_node.shard_type,
                            local_group: placement_node.local_group,
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Failed to write shard {} for part stripe {}: {}",
                            pos, stripe_idx, e
                        );
                    }
                }
            }

            let quorum = write_quorum(ec_k, ec_m);
            if success < quorum {
                error!(
                    "Write quorum not met for part stripe {}: {} successful, need {} (ec_k={}, ec_m={})",
                    stripe_idx, success, quorum, ec_k, ec_m
                );
                return S3Error::xml_response(
                    "ServiceUnavailable",
                    &format!(
                        "Write quorum not met for stripe {}: {} successful writes, need {}",
                        stripe_idx, success, quorum
                    ),
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            }

            total_success += success;
            locs.sort_by_key(|l| l.position);

            // Multipart uses an MDS encoder regardless of placement.ec_type
            // — LRC multipart encoding isn't wired yet. Persist the stripe
            // as MDS so the read path decodes correctly; LRC-encoded
            // multipart is tracked as a separate roadmap item.
            all_stripes.push(StripeMeta {
                stripe_id: stripe_idx as u64,
                ec_k,
                ec_m,
                shards: locs,
                ec_type: ErasureType::ErasureMds.into(),
                ec_local_parity: 0,
                ec_global_parity: 0,
                local_group_size: 0,
                data_size: stripe_data_size,
                object_id: part_object_id.to_vec(),
                encryption_iv: stripe_iv.clone(),
                ..Default::default()
            });
        }

        (all_stripes, total_success, ErasureType::ErasureMds)
    };

    debug!(
        "Part {} uploaded: {} stripes, {} shards written, mode={:?}",
        part_number,
        all_stripes.len(),
        total_success,
        used_ec_type
    );

    // Register the part with metadata service (using all stripes)
    // Registered or not, the part's shards are settled below: kept if meta
    // recorded the part, freed if it refused it (the upload was aborted or
    // completed meanwhile). An error that is not a refusal may have landed.
    let sent = pending.disarm();
    let registered = meta_client
        .register_part(RegisterPartRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            upload_id: upload_id.clone(),
            part_number,
            etag: etag.clone(),
            size: part_size,
            stripes: all_stripes, // Multiple stripes for large parts
            checksum: part_checksum.clone(),
        })
        .await;
    let what = format!("{bucket}/{key} upload {upload_id} part {part_number}");
    match registered {
        Ok(resp) => {
            info!(
                "Uploaded part {}: bucket={}, key={}, uploadId={}, size={}",
                part_number, bucket, key, upload_id, part_size
            );
            // The part this one replaced is referenced by nothing now.
            spawn_reclaim(
                &state,
                stripe_targets(&resp.into_inner().replaced_stripes),
                Reclaim::ReplacedPart,
                what,
            );
            dedup_dry_run(&state, &bucket, &placement, &body, mpu_dek.is_some());

            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header("ETag", &etag);
            if let Some(c) = &part_checksum
                && let Some(a) = crate::checksum::ChecksumAlgorithm::from_aws_name(&c.algorithm)
            {
                builder = builder.header(a.header_name(), &c.value);
            }
            if let Some(v) = sse_response_header {
                builder = builder.header("x-amz-server-side-encryption", v);
                if v == "aws:kms" && !sse_kms_key_id.is_empty() {
                    builder = builder.header(
                        "x-amz-server-side-encryption-aws-kms-key-id",
                        &sse_kms_key_id,
                    );
                }
            }
            if !sse_c_key_md5_for_resp.is_empty() {
                builder = builder
                    .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
                    .header(
                        "x-amz-server-side-encryption-customer-key-md5",
                        &sse_c_key_md5_for_resp,
                    );
            }
            builder.body(Body::empty()).unwrap()
        }
        Err(e) => {
            error!("Failed to register part: {}", e);
            if matches!(
                e.code(),
                tonic::Code::NotFound | tonic::Code::InvalidArgument
            ) {
                spawn_reclaim(&state, sent, Reclaim::FailedWrite, what);
            } else if !sent.is_empty() {
                warn!(
                    "{what}: {} shards stay allocated: meta may have recorded the part",
                    sent.len()
                );
            }
            if e.code() == tonic::Code::NotFound {
                S3Error::xml_response(
                    "NoSuchUpload",
                    "The specified multipart upload does not exist",
                    StatusCode::NOT_FOUND,
                )
            } else {
                S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
    }
}

/// Complete multipart upload - internal implementation
async fn complete_multipart_upload_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
    body: Bytes,
    headers: &HeaderMap,
) -> Response {
    // An SSE-C upload completes only with its key, as each part was sent:
    // checked against the key the upload was started with.
    if let Ok(resp) = state
        .meta_client
        .clone()
        .get_multipart_upload(GetMultipartUploadRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            upload_id: upload_id.clone(),
        })
        .await
    {
        let mpu = resp.into_inner();
        if mpu.found && mpu.encryption_algorithm == SseAlgorithm::SseC as i32 {
            let refused = match parse_sse_c_headers(headers) {
                Ok(Some(cust)) if cust.md5_b64 == mpu.customer_key_md5 => None,
                Ok(Some(_)) => Some("The customer key is not the one the upload was started with"),
                Ok(None) => Some("This upload is SSE-C: the customer key must be provided"),
                Err(resp) => return resp,
            };
            if let Some(msg) = refused {
                return S3Error::xml_response("InvalidRequest", msg, StatusCode::BAD_REQUEST);
            }
        }
    }

    // If-Match / If-None-Match: refused now, while the upload still exists
    // for the client to retry. The commit decides for good.
    let condition = PutCondition::from_headers(headers);
    if condition.is_set() {
        let current = match get_placement_nodes_for_object(&state, &bucket, &key).await {
            Ok(nodes) => get_object_meta_from_any(&state.osd_pool, &nodes, &bucket, &key)
                .await
                .ok()
                .flatten()
                .filter(|o| !o.is_delete_marker),
            Err(resp) => return resp,
        };
        if let Some(refused) = condition.refuse(current.as_ref()) {
            return refused;
        }
    }
    // Parse the CompleteMultipartUpload XML request
    let xml_str = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(_) => {
            return S3Error::xml_response(
                "MalformedXML",
                "The XML provided was not well-formed",
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let complete_req: CompleteMultipartUploadXml = match quick_xml::de::from_str(&xml_str) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to parse CompleteMultipartUpload XML: {}", e);
            return S3Error::xml_response(
                "MalformedXML",
                &format!("Failed to parse XML: {}", e),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let mut meta_client = state.meta_client.clone();

    // Convert to proto PartInfo
    let parts: Vec<PartInfo> = complete_req
        .parts
        .into_iter()
        .map(|p| PartInfo {
            part_number: p.part_number,
            etag: p.etag,
            size: 0, // Will be filled by meta service from stored state
        })
        .collect();

    let part_etags: Vec<String> = parts.iter().map(|p| p.etag.clone()).collect();

    // The composite checksum (each part's checksum, checksummed, "-N"),
    // and the request's own, checked now while the upload still exists.
    let numbers: Vec<u32> = parts.iter().map(|p| p.part_number).collect();
    let (composite, part_checksums) =
        match composite_checksum(&state, &bucket, &key, &upload_id, &numbers).await {
            Some((c, parts)) => (Some(c), parts),
            None => (None, Vec::new()),
        };
    if let Some(asked) = crate::checksum::ChecksumAlgorithm::all()
        .into_iter()
        .find_map(|a| {
            headers
                .get(a.header_name())
                .and_then(|v| v.to_str().ok())
                .map(|v| (a, v.to_string()))
        })
    {
        // The upload already completed (a retry): nothing to compute from;
        // the completed object answers below.
        let gone = composite.is_none()
            && state
                .meta_client
                .clone()
                .get_multipart_upload(GetMultipartUploadRequest {
                    bucket: bucket.clone(),
                    key: key.clone(),
                    upload_id: upload_id.clone(),
                })
                .await
                .is_ok_and(|r| !r.into_inner().found);
        let matches = gone
            || composite.as_ref().is_some_and(|c| {
                c.algorithm == asked.0.aws_name()
                    && (asked.1 == c.value
                        || c.value.split_once('-').is_some_and(|(b, _)| b == asked.1))
            });
        if !matches {
            return S3Error::xml_response(
                "BadDigest",
                &format!(
                    "The {} you specified did not match the calculated checksum.",
                    asked.0.aws_name()
                ),
                StatusCode::BAD_REQUEST,
            );
        }
    }

    // Complete the multipart upload via metadata service
    match meta_client
        .complete_multipart_upload(ProtoCompleteMultipartUploadRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            upload_id: upload_id.clone(),
            parts,
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            // Parts left out of the object went with the upload.
            spawn_reclaim(
                &state,
                stripe_targets(&resp.unused_stripes),
                Reclaim::UnusedPart,
                format!("{bucket}/{key} upload {upload_id}"),
            );
            if let Some(mut object) = resp.object {
                // Tags asked for at CreateMultipartUpload; validated then.
                if let Some(t) = object.user_metadata.remove(UPLOAD_TAGS_KEY) {
                    object.tags = parse_tagging(&t).unwrap_or_default();
                }
                // What the upload kept for its parts' checksums, not the
                // object's metadata.
                object.user_metadata.remove(UPLOAD_CHECKSUM_KEY);
                object.user_metadata.remove(UPLOAD_CHECKSUM_TYPE_KEY);
                // Log multipart assembly details
                let stripe_sizes: Vec<u64> = object.stripes.iter().map(|s| s.data_size).collect();
                let stripe_total: u64 = stripe_sizes.iter().sum();
                info!(
                    "Completed multipart {}/{}: size={}, stripes={}, stripe_sizes={:?}, stripe_total={}",
                    bucket,
                    key,
                    object.size,
                    object.stripes.len(),
                    stripe_sizes,
                    stripe_total
                );
                if stripe_total != object.size {
                    error!(
                        "Multipart stripe data_size sum ({}) != object.size ({}) for {}/{}",
                        stripe_total, object.size, bucket, key
                    );
                }

                // Store the final object metadata on primary OSD
                let placement = match meta_client
                    .get_placement(GetPlacementRequest {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        size: object.size,
                        storage_class: "STANDARD".to_string(),
                    })
                    .await
                {
                    Ok(resp) => resp.into_inner(),
                    Err(e) => {
                        error!("Failed to get placement for completed object: {}", e);
                        return S3Error::xml_response(
                            "InternalError",
                            &e.to_string(),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                };

                // With versioning on, an object this replaces is kept (the
                // OSDs also say so per replica); otherwise it is freed.
                // Not knowing, keep what this replaces: a leak at worst,
                // where guessing "unversioned" would free a version. The
                // upload is already gone from meta, so it is not refused.
                let versioning_enabled = bucket_versioning(&mut meta_client, &bucket)
                    .await
                    .map_or(true, |v| v == VersioningState::VersioningEnabled);
                // A new version, as a single-part PUT makes.
                if versioning_enabled {
                    object.version_id = new_version_id();
                }
                // The lock asked for at CreateMultipartUpload, or the
                // bucket's default retention. Past refusing (the upload is
                // gone), a lock that can't be had now (a date passed
                // meanwhile) gives way to the default rather than to none.
                let mut asked = HeaderMap::new();
                for name in UPLOAD_LOCK_HEADERS {
                    if let Some(v) = object
                        .user_metadata
                        .remove(&format!("{UPLOAD_LOCK_PREFIX}{name}"))
                        && let Ok(v) = header::HeaderValue::from_str(&v)
                    {
                        asked.insert(*name, v);
                    }
                }
                let lock = match object_lock_for_write(&mut meta_client, &bucket, &asked).await {
                    Ok(lock) => Ok(lock),
                    Err(_) => {
                        object_lock_for_write(&mut meta_client, &bucket, &HeaderMap::new()).await
                    }
                };
                if let Ok((retention, legal_hold)) = lock {
                    object.retention = retention;
                    object.legal_hold = legal_hold;
                } else {
                    warn!(
                        "{bucket}/{key}: cannot read the bucket's object lock; stored without one"
                    );
                }
                if let Some(c) = &composite {
                    object.checksum = Some(c.clone());
                    object.part_checksums = part_checksums;
                }
                // Listed with its ObjectMeta, as a single-part PUT is. On
                // failure the parts belong to nothing: meta has already
                // dropped the upload, and commit_put frees them.
                if let Err(resp) = commit_put(
                    &state,
                    &placement,
                    object.clone(),
                    versioning_enabled,
                    stripe_targets(&object.stripes),
                    &condition,
                )
                .await
                {
                    return resp;
                }

                let cx = ChecksumXml::of(object.checksum.as_ref(), true);
                let result = CompleteMultipartUploadResult {
                    location: format!("/{}/{}", bucket, key),
                    bucket: bucket.clone(),
                    key: key.clone(),
                    etag: object.etag.clone(),
                    checksum_crc32: cx.crc32,
                    checksum_crc32c: cx.crc32c,
                    checksum_crc64nvme: cx.crc64nvme,
                    checksum_sha1: cx.sha1,
                    checksum_sha256: cx.sha256,
                    checksum_type: cx.checksum_type,
                };

                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                    to_xml(&result).unwrap_or_default()
                );

                info!(
                    "Completed multipart upload: bucket={}, key={}, uploadId={}, size={}",
                    bucket, key, upload_id, object.size
                );

                let mut builder = with_version_id(Response::builder(), &object)
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/xml")
                    .header("ETag", &object.etag);
                if let Some(c) = &composite
                    && let Some(a) = crate::checksum::ChecksumAlgorithm::from_aws_name(&c.algorithm)
                {
                    builder = builder
                        .header(a.header_name(), &c.value)
                        .header("x-amz-checksum-type", checksum_type_of(c));
                }
                let sse_algo = SseAlgorithm::try_from(object.encryption_algorithm)
                    .unwrap_or(SseAlgorithm::SseNone);
                match sse_algo {
                    SseAlgorithm::SseS3 => {
                        builder = builder.header("x-amz-server-side-encryption", "AES256");
                    }
                    SseAlgorithm::SseKms => {
                        builder = builder.header("x-amz-server-side-encryption", "aws:kms");
                        if !object.kms_key_id.is_empty() {
                            builder = builder.header(
                                "x-amz-server-side-encryption-aws-kms-key-id",
                                &object.kms_key_id,
                            );
                        }
                    }
                    // SSE-C: the key it was completed with (checked above).
                    SseAlgorithm::SseC => {
                        if let Some(md5) = headers
                            .get("x-amz-server-side-encryption-customer-key-md5")
                            .and_then(|v| v.to_str().ok())
                        {
                            builder = builder
                                .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
                                .header("x-amz-server-side-encryption-customer-key-md5", md5);
                        }
                    }
                    SseAlgorithm::SseNone => {}
                }
                builder.body(Body::from(xml)).unwrap()
            } else {
                S3Error::xml_response(
                    "InternalError",
                    "No object returned from complete multipart",
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
        Err(e) => {
            error!("Failed to complete multipart upload: {}", e);
            if e.code() == tonic::Code::NotFound {
                // Completed already, by this request sent again (a client
                // retrying after a lost response): the object these parts
                // make is the current one. Answer as the first time.
                if let Some(resp) = already_completed(&state, &bucket, &key, &part_etags).await {
                    return resp;
                }
                S3Error::xml_response(
                    "NoSuchUpload",
                    "The specified multipart upload does not exist",
                    StatusCode::NOT_FOUND,
                )
            } else if e.code() == tonic::Code::InvalidArgument
                && e.message().starts_with("EntityTooSmall")
            {
                S3Error::xml_response("EntityTooSmall", e.message(), StatusCode::BAD_REQUEST)
            } else if e.code() == tonic::Code::InvalidArgument {
                S3Error::xml_response("InvalidPart", e.message(), StatusCode::BAD_REQUEST)
            } else {
                S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
    }
}

/// The composite checksum of an object made of `numbers`' parts, when they
/// all have one, of one algorithm: that algorithm over their checksums
/// end to end, base64, then "-" and how many.
async fn composite_checksum(
    state: &AppState,
    bucket: &str,
    key: &str,
    upload_id: &str,
    numbers: &[u32],
) -> Option<(ObjectChecksum, Vec<ObjectChecksum>)> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let listed = state
        .meta_client
        .clone()
        .list_parts(ListPartsRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id: upload_id.to_string(),
            part_number_marker: 0,
            max_parts: 10_000,
        })
        .await
        .ok()?
        .into_inner()
        .parts;
    let by_number: HashMap<u32, (&ObjectChecksum, u64)> = listed
        .iter()
        .filter_map(|p| p.checksum.as_ref().map(|c| (p.part_number, (c, p.size))))
        .collect();
    let full_object = state
        .meta_client
        .clone()
        .get_multipart_upload(GetMultipartUploadRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id: upload_id.to_string(),
        })
        .await
        .ok()
        .and_then(|r| {
            r.into_inner()
                .user_metadata
                .get(UPLOAD_CHECKSUM_TYPE_KEY)
                .cloned()
        })
        .is_some_and(|t| t == "FULL_OBJECT");
    let mut algorithm: Option<&str> = None;
    let mut joined = Vec::new();
    let mut raw = Vec::with_capacity(numbers.len());
    let mut each = Vec::with_capacity(numbers.len());
    for n in numbers {
        let (c, size) = by_number.get(n)?;
        if *algorithm.get_or_insert(&c.algorithm) != c.algorithm {
            return None;
        }
        let value = b64.decode(&c.value).ok()?;
        joined.extend(&value);
        raw.push((value, *size));
        each.push((*c).clone());
    }
    let algorithm = crate::checksum::ChecksumAlgorithm::from_aws_name(algorithm?)?;
    let value = if full_object {
        b64.encode(algorithm.combine(&raw)?)
    } else {
        format!(
            "{}-{}",
            b64.encode(algorithm.compute(&joined)),
            numbers.len()
        )
    };
    Some((
        ObjectChecksum {
            algorithm: algorithm.aws_name().to_string(),
            value,
        },
        each,
    ))
}

/// The ETag S3 gives an object made of parts with these ETags: the MD5 of
/// their MD5s, then "-" and how many.
fn multipart_etag(part_etags: &[String]) -> Option<String> {
    let mut md5s = Vec::with_capacity(part_etags.len() * 16);
    for etag in part_etags {
        md5s.extend(hex::decode(etag.trim_matches('"')).ok()?);
    }
    Some(format!(
        "\"{}-{}\"",
        crate::digest::md5_hex(&md5s),
        part_etags.len()
    ))
}

/// The CompleteMultipartUpload answer for an upload completed before with
/// these parts, if the key's current object is what they made.
async fn already_completed(
    state: &Arc<AppState>,
    bucket: &str,
    key: &str,
    part_etags: &[String],
) -> Option<Response> {
    let want = multipart_etag(part_etags)?;
    let nodes = get_placement_nodes_for_object(state, bucket, key)
        .await
        .ok()?;
    let current = get_object_meta_from_any(&state.osd_pool, &nodes, bucket, key)
        .await
        .ok()??;
    if current.is_delete_marker || current.etag.trim_matches('"') != want.trim_matches('"') {
        return None;
    }
    let cx = ChecksumXml::of(current.checksum.as_ref(), true);
    let result = CompleteMultipartUploadResult {
        location: format!("/{bucket}/{key}"),
        bucket: bucket.to_string(),
        key: key.to_string(),
        etag: current.etag.clone(),
        checksum_crc32: cx.crc32,
        checksum_crc32c: cx.crc32c,
        checksum_crc64nvme: cx.crc64nvme,
        checksum_sha1: cx.sha1,
        checksum_sha256: cx.sha256,
        checksum_type: cx.checksum_type,
    };
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        to_xml(&result).unwrap_or_default()
    );
    Some(
        with_version_id(Response::builder(), &current)
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/xml")
            .header("ETag", &current.etag)
            .body(Body::from(xml))
            .unwrap(),
    )
}

/// GET /{bucket}/{key}?uploadId=X - List parts
pub async fn get_object_with_params(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<GetObjectParams>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    // If key is empty (trailing slash on bucket), treat as list_objects
    if key.is_empty() {
        let list_params = ListObjectsParams {
            max_keys: params.max_parts.map(|m| m.to_string()),
            ..Default::default()
        };
        return list_objects(State(state), Path(bucket), Query(list_params), auth).await;
    }

    // If uploadId is present, this is a list parts request
    if let Some(upload_id) = params.upload_id {
        return list_parts_internal(
            state,
            bucket,
            key,
            upload_id,
            params.max_parts.unwrap_or(1000),
            params.part_number_marker.unwrap_or(0),
        )
        .await;
    }
    if params.retention.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        return get_object_retention_internal(state, bucket, key).await;
    }
    if params.legal_hold.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        return get_object_legal_hold_internal(state, bucket, key).await;
    }
    if params.tagging.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        return get_object_tagging_internal(state, bucket, key).await;
    }

    // Otherwise, it's a regular GET object
    let _ = auth;
    if params.attributes.is_some() {
        return get_object_attributes(state, bucket, key, params.version_id, &headers).await;
    }
    if params.acl.is_some() {
        return get_acl(&state, &bucket, Some(&key), params.version_id.as_deref()).await;
    }
    if let Some(n) = params.part_number {
        return get_object_part(state, bucket, key, params.version_id, n, headers).await;
    }
    get_object_version(state, bucket, key, params.version_id, headers).await
}

/// List parts - internal implementation
async fn list_parts_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
    max_parts: u32,
    part_number_marker: u32,
) -> Response {
    let mut client = state.meta_client.clone();

    match client
        .list_parts(ListPartsRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            upload_id: upload_id.clone(),
            part_number_marker,
            max_parts,
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();

            let result = ListPartsResult {
                bucket: resp.bucket,
                key: resp.key,
                upload_id: resp.upload_id,
                part_number_marker,
                next_part_number_marker: if resp.is_truncated {
                    Some(resp.next_part_number_marker)
                } else {
                    None
                },
                max_parts,
                is_truncated: resp.is_truncated,
                parts: resp
                    .parts
                    .into_iter()
                    .map(|p| {
                        let cx = ChecksumXml::of(p.checksum.as_ref(), false);
                        PartItem {
                            part_number: p.part_number,
                            last_modified: timestamp_to_iso(p.last_modified),
                            etag: p.etag,
                            size: p.size,
                            checksum_crc32: cx.crc32,
                            checksum_crc32c: cx.crc32c,
                            checksum_crc64nvme: cx.crc64nvme,
                            checksum_sha1: cx.sha1,
                            checksum_sha256: cx.sha256,
                            checksum_type: cx.checksum_type,
                        }
                    })
                    .collect(),
            };

            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                to_xml(&result).unwrap_or_default()
            );

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                S3Error::xml_response(
                    "NoSuchUpload",
                    "The specified multipart upload does not exist",
                    StatusCode::NOT_FOUND,
                )
            } else {
                error!("Failed to list parts: {}", e);
                S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
    }
}

/// DELETE /{bucket}/{key}?uploadId=X - Abort multipart upload
pub async fn delete_object_with_params(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<DeleteObjectParams>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    // If uploadId is present, this is an abort multipart upload request
    if let Some(upload_id) = params.upload_id {
        return abort_multipart_upload_internal(state, bucket, key, upload_id).await;
    }
    if params.tagging.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        return set_object_tagging(state, bucket, key, HashMap::new(), StatusCode::NO_CONTENT)
            .await;
    }

    // Otherwise, it's a regular DELETE object (possibly version-specific)
    delete_object(
        State(state),
        Path((bucket, key)),
        auth,
        params.version_id,
        headers,
    )
    .await
}

/// Abort multipart upload - internal implementation
async fn abort_multipart_upload_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    upload_id: String,
) -> Response {
    let mut client = state.meta_client.clone();

    // Meta drops the upload and hands back every part's stripes in one step;
    // then the parts are freed, each where its own location says it is.
    //
    // This used to list the parts, free them, then abort — so an abort racing
    // a completion could free parts the completed object was made of. And it
    // sent the deletes to the *object key's* placement, but parts are placed
    // by their own keys: with more OSDs than a stripe spans, part shards on
    // OSDs outside the key's placement were never deleted.
    match client
        .abort_multipart_upload(AbortMultipartUploadRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            upload_id: upload_id.clone(),
        })
        .await
    {
        Ok(resp) => {
            // Best effort, like the object path: a shard that cannot be
            // deleted is a leaked block, not a failed abort. Awaited, as a
            // DELETE is, so the space is free when the client hears back.
            let failed = reclaim_shards(
                &state.osd_pool,
                &mut client,
                stripe_targets(&resp.into_inner().stripes),
                Reclaim::Abort,
            )
            .await;
            if failed > 0 {
                warn!("{bucket}/{key} upload {upload_id}: {failed} shard deletes failed");
            }
            info!(
                "Aborted multipart upload: bucket={}, key={}, uploadId={}",
                bucket, key, upload_id
            );
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) if e.code() == tonic::Code::NotFound => S3Error::xml_response(
            "NoSuchUpload",
            "The specified multipart upload does not exist",
            StatusCode::NOT_FOUND,
        ),
        Err(e) => {
            error!("Failed to abort multipart upload: {}", e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

/// GET /{bucket}?uploads - List multipart uploads.
///
/// Dispatched from [`list_objects`] when `?uploads` is present. Honors
/// `prefix`, `key-marker`, `upload-id-marker` and `max-uploads` so a
/// truncated response can actually be paged to completion — Meta
/// resumes strictly after (key-marker, upload-id-marker).
///
/// `delimiter` is accepted and echoed for wire fidelity but uploads are
/// never rolled up into `CommonPrefixes`; Meta has no grouping support.
async fn list_multipart_uploads_internal(
    state: Arc<AppState>,
    bucket: String,
    params: &ListObjectsParams,
) -> Response {
    // Authorization (s3:ListBucketMultipartUploads) is enforced by
    // authz_layer before the handler runs.
    let prefix = params.prefix.clone().unwrap_or_default();
    let key_marker = params.key_marker.clone().unwrap_or_default();
    let upload_id_marker = params.upload_id_marker.clone().unwrap_or_default();
    let max_uploads = params.max_uploads.unwrap_or(1000).clamp(1, 1000);

    let mut client = state.meta_client.clone();

    match client
        .list_multipart_uploads(ListMultipartUploadsRequest {
            bucket: bucket.clone(),
            prefix: prefix.clone(),
            key_marker: key_marker.clone(),
            upload_id_marker: upload_id_marker.clone(),
            max_uploads,
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();

            let result = ListMultipartUploadsResult {
                bucket: bucket.clone(),
                key_marker,
                upload_id_marker,
                next_key_marker: if resp.is_truncated {
                    Some(resp.next_key_marker)
                } else {
                    None
                },
                next_upload_id_marker: if resp.is_truncated {
                    Some(resp.next_upload_id_marker)
                } else {
                    None
                },
                delimiter: params.delimiter.clone(),
                prefix,
                max_uploads,
                is_truncated: resp.is_truncated,
                uploads: resp
                    .uploads
                    .into_iter()
                    .map(|u| UploadItem {
                        key: u.key,
                        upload_id: u.upload_id,
                        initiated: timestamp_to_iso(u.initiated),
                        storage_class: u.storage_class,
                    })
                    .collect(),
            };

            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                to_xml(&result).unwrap_or_default()
            );

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                S3Error::xml_response(
                    "NoSuchBucket",
                    "The specified bucket does not exist",
                    StatusCode::NOT_FOUND,
                )
            } else {
                error!("Failed to list multipart uploads: {}", e);
                S3Error::xml_response(
                    "InternalError",
                    &e.to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
        }
    }
}

// ============================================================================
// Bucket Versioning
// ============================================================================

/// XML request for PUT bucket versioning
#[derive(Deserialize)]
#[serde(rename = "VersioningConfiguration")]
struct VersioningConfigurationRequest {
    #[serde(rename = "Status")]
    status: String,
}

/// XML response for GET bucket versioning
#[derive(Serialize)]
#[serde(rename = "VersioningConfiguration")]
struct VersioningConfigurationResponse {
    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
}

async fn put_bucket_versioning_internal(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let config: VersioningConfigurationRequest = match quick_xml::de::from_reader(body.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            return S3Error::xml_response(
                "MalformedXML",
                &format!("Invalid versioning XML: {}", e),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let versioning_state = match config.status.as_str() {
        "Enabled" => VersioningState::VersioningEnabled,
        "Suspended" => VersioningState::VersioningSuspended,
        _ => {
            return S3Error::xml_response(
                "MalformedXML",
                "Status must be 'Enabled' or 'Suspended'",
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let mut client = state.meta_client.clone();
    match client
        .put_bucket_versioning(PutBucketVersioningRequest {
            bucket: bucket.clone(),
            state: versioning_state.into(),
        })
        .await
    {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        // Meta refuses to suspend versioning on a bucket with object lock.
        Err(e) if e.code() == tonic::Code::FailedPrecondition => {
            S3Error::xml_response("InvalidBucketState", e.message(), StatusCode::CONFLICT)
        }
        Err(e) if e.code() == tonic::Code::NotFound => S3Error::xml_response(
            "NoSuchBucket",
            "The specified bucket does not exist",
            StatusCode::NOT_FOUND,
        ),
        Err(e) => {
            error!("Failed to set versioning for {}: {}", bucket, e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

async fn get_bucket_versioning_internal(state: Arc<AppState>, bucket: String) -> Response {
    let mut client = state.meta_client.clone();
    match client
        .get_bucket_versioning(GetBucketVersioningRequest {
            bucket: bucket.clone(),
        })
        .await
    {
        Ok(resp) => {
            let state = resp.into_inner().state();
            let status = match state {
                VersioningState::VersioningEnabled => Some("Enabled".to_string()),
                VersioningState::VersioningSuspended => Some("Suspended".to_string()),
                VersioningState::VersioningDisabled => None,
            };
            let result = VersioningConfigurationResponse { status };
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                to_xml(&result).unwrap_or_default()
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to get versioning for {}: {}", bucket, e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

// ============================================================================
// Object Lock Configuration
// ============================================================================

#[derive(Deserialize)]
#[serde(rename = "ObjectLockConfiguration")]
struct ObjectLockConfigRequest {
    #[serde(rename = "ObjectLockEnabled")]
    #[serde(default)]
    object_lock_enabled: Option<String>,
    #[serde(rename = "Rule")]
    #[serde(default)]
    rule: Option<ObjectLockRuleXml>,
}

#[derive(Deserialize)]
struct ObjectLockRuleXml {
    #[serde(rename = "DefaultRetention")]
    #[serde(default)]
    default_retention: Option<DefaultRetentionXml>,
}

#[derive(Deserialize, Serialize)]
struct DefaultRetentionXml {
    #[serde(rename = "Mode")]
    mode: String,
    #[serde(rename = "Days")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    days: Option<i64>,
    #[serde(rename = "Years")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    years: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename = "ObjectLockConfiguration")]
struct ObjectLockConfigResponse {
    #[serde(rename = "ObjectLockEnabled")]
    object_lock_enabled: String,
    #[serde(rename = "Rule")]
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<ObjectLockRuleResponseXml>,
}

#[derive(Serialize)]
struct ObjectLockRuleResponseXml {
    #[serde(rename = "DefaultRetention")]
    default_retention: DefaultRetentionXml,
}

async fn put_object_lock_config_internal(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let config: ObjectLockConfigRequest = match quick_xml::de::from_reader(body.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            return S3Error::xml_response(
                "MalformedXML",
                &format!("Invalid object lock XML: {}", e),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let malformed = |msg: &str| S3Error::xml_response("MalformedXML", msg, StatusCode::BAD_REQUEST);
    if config.object_lock_enabled.as_deref() != Some("Enabled") {
        return malformed("ObjectLockEnabled must be Enabled");
    }
    let mut client = state.meta_client.clone();
    // Object lock needs versioning on, for good (meta then refuses to
    // suspend it): that is what keeps a locked version from being
    // overwritten. A bucket created with lock has it; an existing one may
    // turn lock on once versioning is enabled, as S3 allows.
    match bucket_lock(&mut client, &bucket).await {
        Ok(Some(_)) => {}
        Ok(None) => match bucket_versioning(&mut client, &bucket).await {
            Ok(VersioningState::VersioningEnabled) => {}
            Ok(_) => {
                return S3Error::xml_response(
                    "InvalidBucketState",
                    "Versioning must be enabled on the bucket to enable Object Lock",
                    StatusCode::CONFLICT,
                );
            }
            Err(resp) => return resp,
        },
        Err(resp) => return resp,
    }
    let default_retention = match config.rule.and_then(|r| r.default_retention) {
        None => None,
        Some(dr) => {
            let mode = match dr.mode.as_str() {
                "GOVERNANCE" => RetentionMode::RetentionGovernance,
                "COMPLIANCE" => RetentionMode::RetentionCompliance,
                _ => return malformed("Mode must be GOVERNANCE or COMPLIANCE"),
            };
            let period = |v: i64| u32::try_from(v).ok().filter(|v| *v > 0);
            let bad_period = || {
                S3Error::xml_response(
                    "InvalidRetentionPeriod",
                    "Default retention period must be a positive integer value",
                    StatusCode::BAD_REQUEST,
                )
            };
            let (days, years) = match (dr.days, dr.years) {
                (Some(d), None) => match period(d) {
                    Some(d) => (d, 0),
                    None => return bad_period(),
                },
                (None, Some(y)) => match period(y) {
                    Some(y) => (0, y),
                    None => return bad_period(),
                },
                _ => return malformed("Exactly one of Days and Years is required"),
            };
            Some(RetentionRule {
                mode: mode.into(),
                days,
                years,
            })
        }
    };

    match client
        .put_object_lock_configuration(PutObjectLockConfigRequest {
            bucket: bucket.clone(),
            config: Some(ProtoObjectLockConfig {
                enabled: config
                    .object_lock_enabled
                    .as_deref()
                    .is_some_and(|v| v == "Enabled"),
                default_retention,
            }),
        })
        .await
    {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            error!("Failed to set object lock config for {}: {}", bucket, e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

async fn get_object_lock_config_internal(state: Arc<AppState>, bucket: String) -> Response {
    let mut client = state.meta_client.clone();
    match client
        .get_object_lock_configuration(GetObjectLockConfigRequest {
            bucket: bucket.clone(),
        })
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            if !inner.found {
                return S3Error::xml_response(
                    "ObjectLockConfigurationNotFoundError",
                    "Object Lock configuration does not exist for this bucket",
                    StatusCode::NOT_FOUND,
                );
            }
            let config = inner.config.unwrap_or_default();
            let rule = config.default_retention.map(|dr| {
                let mode = match dr.mode() {
                    RetentionMode::RetentionGovernance => "GOVERNANCE",
                    RetentionMode::RetentionCompliance => "COMPLIANCE",
                    RetentionMode::RetentionNone => "COMPLIANCE",
                };
                ObjectLockRuleResponseXml {
                    default_retention: DefaultRetentionXml {
                        mode: mode.to_string(),
                        days: (dr.days > 0).then_some(i64::from(dr.days)),
                        years: (dr.years > 0).then_some(i64::from(dr.years)),
                    },
                }
            });
            let result = ObjectLockConfigResponse {
                object_lock_enabled: if config.enabled {
                    "Enabled".to_string()
                } else {
                    "Disabled".to_string()
                },
                rule,
            };
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                to_xml(&result).unwrap_or_default()
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to get object lock config for {}: {}", bucket, e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

// ============================================================================
// Lifecycle Configuration
// ============================================================================

#[derive(Deserialize)]
#[serde(rename = "LifecycleConfiguration")]
struct LifecycleConfigRequest {
    #[serde(rename = "Rule")]
    #[serde(default)]
    rules: Vec<LifecycleRuleXml>,
}

#[derive(Deserialize, Serialize, Clone)]
struct LifecycleRuleXml {
    #[serde(rename = "ID")]
    #[serde(default)]
    id: String,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Filter")]
    #[serde(default)]
    filter: Option<LifecycleFilterXml>,
    #[serde(rename = "Expiration")]
    #[serde(default)]
    expiration: Option<LifecycleExpirationXml>,
    #[serde(rename = "NoncurrentVersionExpiration")]
    #[serde(default)]
    noncurrent_version_expiration: Option<NoncurrentVersionExpirationXml>,
    #[serde(rename = "AbortIncompleteMultipartUpload")]
    #[serde(default)]
    abort_incomplete_multipart_upload: Option<AbortIncompleteMultipartUploadXml>,
}

#[derive(Deserialize, Serialize, Clone, Default)]
struct LifecycleFilterXml {
    #[serde(rename = "Prefix")]
    #[serde(default)]
    prefix: String,
}

#[derive(Deserialize, Serialize, Clone)]
struct LifecycleExpirationXml {
    #[serde(rename = "Days")]
    #[serde(default)]
    days: Option<u32>,
    #[serde(rename = "ExpiredObjectDeleteMarker")]
    #[serde(default)]
    expired_object_delete_marker: Option<bool>,
}

#[derive(Deserialize, Serialize, Clone)]
struct NoncurrentVersionExpirationXml {
    #[serde(rename = "NoncurrentDays")]
    #[serde(default)]
    noncurrent_days: Option<u32>,
}

#[derive(Deserialize, Serialize, Clone)]
struct AbortIncompleteMultipartUploadXml {
    #[serde(rename = "DaysAfterInitiation")]
    #[serde(default)]
    days_after_initiation: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename = "LifecycleConfiguration")]
struct LifecycleConfigResponse {
    #[serde(rename = "Rule")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<LifecycleRuleXml>,
}

async fn put_bucket_lifecycle_internal(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let config: LifecycleConfigRequest = match quick_xml::de::from_reader(body.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            return S3Error::xml_response(
                "MalformedXML",
                &format!("Invalid lifecycle XML: {}", e),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let proto_rules: Vec<ProtoLifecycleRule> = config
        .rules
        .iter()
        .map(|r| ProtoLifecycleRule {
            id: r.id.clone(),
            enabled: r.status == "Enabled",
            prefix: r
                .filter
                .as_ref()
                .map(|f| f.prefix.clone())
                .unwrap_or_default(),
            expiration_days: r.expiration.as_ref().and_then(|e| e.days).unwrap_or(0),
            expiration_date: 0,
            noncurrent_version_expiration_days: r
                .noncurrent_version_expiration
                .as_ref()
                .and_then(|n| n.noncurrent_days)
                .unwrap_or(0),
            expired_object_delete_marker: r
                .expiration
                .as_ref()
                .and_then(|e| e.expired_object_delete_marker)
                .unwrap_or(false),
            abort_incomplete_multipart_upload_days: r
                .abort_incomplete_multipart_upload
                .as_ref()
                .and_then(|a| a.days_after_initiation)
                .unwrap_or(0),
        })
        .collect();

    let mut client = state.meta_client.clone();
    match client
        .put_bucket_lifecycle(PutBucketLifecycleRequest {
            bucket: bucket.clone(),
            config: Some(ProtoLifecycleConfig { rules: proto_rules }),
        })
        .await
    {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            error!("Failed to set lifecycle config for {}: {}", bucket, e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

async fn get_bucket_lifecycle_internal(state: Arc<AppState>, bucket: String) -> Response {
    let mut client = state.meta_client.clone();
    match client
        .get_bucket_lifecycle(GetBucketLifecycleRequest {
            bucket: bucket.clone(),
        })
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            if !inner.found {
                return S3Error::xml_response(
                    "NoSuchLifecycleConfiguration",
                    "The lifecycle configuration does not exist",
                    StatusCode::NOT_FOUND,
                );
            }
            let config = inner.config.unwrap_or_default();
            let rules: Vec<LifecycleRuleXml> = config
                .rules
                .iter()
                .map(|r| LifecycleRuleXml {
                    id: r.id.clone(),
                    status: if r.enabled {
                        "Enabled".to_string()
                    } else {
                        "Disabled".to_string()
                    },
                    filter: Some(LifecycleFilterXml {
                        prefix: r.prefix.clone(),
                    }),
                    expiration: if r.expiration_days > 0 || r.expired_object_delete_marker {
                        Some(LifecycleExpirationXml {
                            days: if r.expiration_days > 0 {
                                Some(r.expiration_days)
                            } else {
                                None
                            },
                            expired_object_delete_marker: if r.expired_object_delete_marker {
                                Some(true)
                            } else {
                                None
                            },
                        })
                    } else {
                        None
                    },
                    noncurrent_version_expiration: if r.noncurrent_version_expiration_days > 0 {
                        Some(NoncurrentVersionExpirationXml {
                            noncurrent_days: Some(r.noncurrent_version_expiration_days),
                        })
                    } else {
                        None
                    },
                    abort_incomplete_multipart_upload: if r.abort_incomplete_multipart_upload_days
                        > 0
                    {
                        Some(AbortIncompleteMultipartUploadXml {
                            days_after_initiation: Some(r.abort_incomplete_multipart_upload_days),
                        })
                    } else {
                        None
                    },
                })
                .collect();

            let result = LifecycleConfigResponse { rules };
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                to_xml(&result).unwrap_or_default()
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to get lifecycle config for {}: {}", bucket, e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

async fn delete_bucket_lifecycle_internal(state: Arc<AppState>, bucket: String) -> Response {
    let mut client = state.meta_client.clone();
    match client
        .delete_bucket_lifecycle(DeleteBucketLifecycleRequest {
            bucket: bucket.clone(),
        })
        .await
    {
        Ok(_) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            error!("Failed to delete lifecycle config for {}: {}", bucket, e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

// ============================================================================
// Bucket Default Server-Side Encryption
// ============================================================================

#[derive(Deserialize)]
#[serde(rename = "ServerSideEncryptionConfiguration")]
struct SseConfigRequest {
    #[serde(rename = "Rule")]
    #[serde(default)]
    rules: Vec<SseRuleXml>,
}

#[derive(Deserialize, Serialize, Clone)]
struct SseRuleXml {
    #[serde(rename = "ApplyServerSideEncryptionByDefault")]
    apply_default: Option<SseByDefaultXml>,
    #[serde(rename = "BucketKeyEnabled")]
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_key_enabled: Option<bool>,
}

#[derive(Deserialize, Serialize, Clone)]
struct SseByDefaultXml {
    #[serde(rename = "SSEAlgorithm")]
    sse_algorithm: String,
    #[serde(rename = "KMSMasterKeyID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    kms_master_key_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename = "ServerSideEncryptionConfiguration")]
struct SseConfigResponse {
    #[serde(rename = "Rule")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<SseRuleXml>,
}

fn parse_sse_algorithm(s: &str) -> Option<SseAlgorithm> {
    match s {
        "AES256" => Some(SseAlgorithm::SseS3),
        "aws:kms" => Some(SseAlgorithm::SseKms),
        _ => None,
    }
}

fn sse_algorithm_to_aws(alg: SseAlgorithm) -> Option<&'static str> {
    match alg {
        SseAlgorithm::SseS3 => Some("AES256"),
        SseAlgorithm::SseKms => Some("aws:kms"),
        SseAlgorithm::SseNone | SseAlgorithm::SseC => None,
    }
}

async fn put_bucket_encryption_internal(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
    let config: SseConfigRequest = match quick_xml::de::from_reader(body.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            return S3Error::xml_response(
                "MalformedXML",
                &format!("Invalid encryption XML: {}", e),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let mut proto_rules: Vec<SseRule> = Vec::with_capacity(config.rules.len());
    for rule in &config.rules {
        let apply = rule.apply_default.as_ref().ok_or(());
        let Ok(apply) = apply else {
            return S3Error::xml_response(
                "MalformedXML",
                "Missing ApplyServerSideEncryptionByDefault",
                StatusCode::BAD_REQUEST,
            );
        };
        let algorithm = match parse_sse_algorithm(&apply.sse_algorithm) {
            Some(a) => a,
            None => {
                return S3Error::xml_response(
                    "InvalidEncryptionAlgorithmError",
                    &format!(
                        "The encryption algorithm '{}' is not supported as a bucket default",
                        apply.sse_algorithm
                    ),
                    StatusCode::BAD_REQUEST,
                );
            }
        };
        if algorithm == SseAlgorithm::SseKms
            && apply.kms_master_key_id.as_deref().unwrap_or("").is_empty()
        {
            return S3Error::xml_response(
                "InvalidArgument",
                "KMSMasterKeyID is required when SSEAlgorithm is aws:kms",
                StatusCode::BAD_REQUEST,
            );
        }
        proto_rules.push(SseRule {
            algorithm: algorithm as i32,
            kms_key_id: apply.kms_master_key_id.clone().unwrap_or_default(),
            bucket_key_enabled: rule.bucket_key_enabled.unwrap_or(false),
        });
    }

    let mut client = state.meta_client.clone();
    match client
        .put_bucket_encryption(PutBucketEncryptionRequest {
            bucket: bucket.clone(),
            config: Some(BucketSseConfiguration { rules: proto_rules }),
        })
        .await
    {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            error!("Failed to set encryption config for {}: {}", bucket, e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

async fn get_bucket_encryption_internal(state: Arc<AppState>, bucket: String) -> Response {
    let mut client = state.meta_client.clone();
    match client
        .get_bucket_encryption(GetBucketEncryptionRequest {
            bucket: bucket.clone(),
        })
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            if !inner.found {
                return S3Error::xml_response(
                    "ServerSideEncryptionConfigurationNotFoundError",
                    "The server side encryption configuration was not found",
                    StatusCode::NOT_FOUND,
                );
            }
            let config = inner.config.unwrap_or_default();
            let rules: Vec<SseRuleXml> = config
                .rules
                .iter()
                .filter_map(|r| {
                    let algorithm = SseAlgorithm::try_from(r.algorithm).ok()?;
                    let aws_name = sse_algorithm_to_aws(algorithm)?;
                    Some(SseRuleXml {
                        apply_default: Some(SseByDefaultXml {
                            sse_algorithm: aws_name.to_string(),
                            kms_master_key_id: if r.kms_key_id.is_empty() {
                                None
                            } else {
                                Some(r.kms_key_id.clone())
                            },
                        }),
                        bucket_key_enabled: if r.bucket_key_enabled {
                            Some(true)
                        } else {
                            None
                        },
                    })
                })
                .collect();

            let result = SseConfigResponse { rules };
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                to_xml(&result).unwrap_or_default()
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to get encryption config for {}: {}", bucket, e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

async fn delete_bucket_encryption_internal(state: Arc<AppState>, bucket: String) -> Response {
    let mut client = state.meta_client.clone();
    match client
        .delete_bucket_encryption(DeleteBucketEncryptionRequest {
            bucket: bucket.clone(),
        })
        .await
    {
        Ok(_) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap(),
        Err(e) => {
            error!("Failed to delete encryption config for {}: {}", bucket, e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

// ============================================================================
// Object Retention & Legal Hold
// ============================================================================

#[derive(Deserialize)]
#[serde(rename = "Retention")]
struct RetentionRequest {
    #[serde(rename = "Mode")]
    mode: String,
    #[serde(rename = "RetainUntilDate")]
    retain_until_date: String,
}

#[derive(Serialize)]
#[serde(rename = "Retention")]
struct RetentionResponse {
    #[serde(rename = "Mode")]
    mode: String,
    #[serde(rename = "RetainUntilDate")]
    retain_until_date: String,
}

#[derive(Deserialize)]
#[serde(rename = "LegalHold")]
struct LegalHoldRequest {
    #[serde(rename = "Status")]
    status: String,
}

#[derive(Serialize)]
#[serde(rename = "LegalHold")]
struct LegalHoldResponse {
    #[serde(rename = "Status")]
    status: String,
}

async fn put_object_retention_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    body: Bytes,
    headers: &HeaderMap,
) -> Response {
    match bucket_lock(&mut state.meta_client.clone(), &bucket).await {
        Ok(Some(_)) => {}
        Ok(None) => return lock_not_configured(),
        Err(resp) => return resp,
    }
    let req: RetentionRequest = match quick_xml::de::from_reader(body.as_ref()) {
        Ok(r) => r,
        Err(e) => {
            return S3Error::xml_response(
                "MalformedXML",
                &format!("Invalid retention XML: {}", e),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let mode = match req.mode.as_str() {
        "GOVERNANCE" => RetentionMode::RetentionGovernance,
        "COMPLIANCE" => RetentionMode::RetentionCompliance,
        _ => {
            return S3Error::xml_response(
                "MalformedXML",
                "Mode must be GOVERNANCE or COMPLIANCE",
                StatusCode::BAD_REQUEST,
            );
        }
    };

    // Parse ISO 8601 date to unix timestamp.
    //
    // Three separate ways this went wrong, all from converting without
    // checking:
    //
    //   - An unparseable date became `0` — "retain until the epoch", which is
    //     no retention at all — and the request still answered 200. A client
    //     setting a compliance lock got a success and no lock.
    //   - A date before 1970 has a negative timestamp, and `as u64` wrapped it
    //     to about 1.8e19, later than any `now` will ever be. Under
    //     COMPLIANCE, which by definition cannot be lifted, that is an object
    //     locked forever by a typo.
    //   - A date merely in the past stored a retention that was already
    //     expired, again reporting success for a control doing nothing.
    //
    // Silently succeeding is the wrong direction to fail for a compliance
    // control, so all three are now `InvalidArgument`, which is what AWS
    // answers.
    let retain_until = match chrono::DateTime::parse_from_rfc3339(&req.retain_until_date) {
        Ok(dt) => match u64::try_from(dt.timestamp()) {
            Ok(secs) => secs,
            Err(_) => {
                return S3Error::xml_response(
                    "InvalidArgument",
                    "RetainUntilDate must not be before 1970-01-01T00:00:00Z",
                    StatusCode::BAD_REQUEST,
                );
            }
        },
        Err(e) => {
            return S3Error::xml_response(
                "InvalidArgument",
                &format!("RetainUntilDate is not a valid RFC 3339 date: {e}"),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if retain_until <= now_secs {
        return S3Error::xml_response(
            "InvalidArgument",
            "RetainUntilDate must be in the future",
            StatusCode::BAD_REQUEST,
        );
    }

    let nodes = match get_placement_nodes_for_object(&state, &bucket, &key).await {
        Ok(n) => n,
        Err(resp) => return resp,
    };

    let mut object_meta = match get_object_meta_from_any(&state.osd_pool, &nodes, &bucket, &key)
        .await
    {
        Ok(Some(meta)) => meta,
        Ok(None) => {
            return S3Error::xml_response("NoSuchKey", "Object not found", StatusCode::NOT_FOUND);
        }
        Err(e) => {
            error!("Failed to get object metadata: {}", e);
            return S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    // A lock in force can be tightened, never loosened: COMPLIANCE can only
    // be extended; GOVERNANCE can be shortened or changed in mode only with
    // x-amz-bypass-governance-retention. Any change used to be accepted, so
    // a COMPLIANCE lock could be shortened to tomorrow and the object
    // deleted then.
    if let Some(old) = object_meta.retention.as_ref()
        && old.retain_until_date > now_secs
        && retention_mode_name(old.mode()).is_some()
    {
        let loosens = mode != old.mode() || retain_until < old.retain_until_date;
        let bypass = headers
            .get("x-amz-bypass-governance-retention")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let allowed = match old.mode() {
            RetentionMode::RetentionCompliance => !loosens,
            _ => !loosens || bypass,
        };
        if !allowed {
            return S3Error::xml_response(
                "AccessDenied",
                "The object is locked: its retention can be extended but not shortened or changed",
                StatusCode::FORBIDDEN,
            );
        }
    }

    object_meta.retention = Some(ObjectRetention {
        mode: mode.into(),
        retain_until_date: retain_until,
    });

    // Only over the object just read: a PUT that replaced it meanwhile has
    // freed its shards, and must not have it written back over its own.
    let expected = object_meta.object_id.clone();
    if let Err(e) = put_object_meta_to_all(
        &state.osd_pool,
        &nodes,
        &bucket,
        &key,
        object_meta,
        false,
        &expected,
    )
    .await
    {
        error!("Failed to update object retention: {}", e);
        return S3Error::xml_response(
            "InternalError",
            &e.to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

async fn get_object_retention_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
) -> Response {
    match bucket_lock(&mut state.meta_client.clone(), &bucket).await {
        Ok(Some(_)) => {}
        Ok(None) => return lock_not_configured(),
        Err(resp) => return resp,
    }
    let nodes = match get_placement_nodes_for_object(&state, &bucket, &key).await {
        Ok(n) => n,
        Err(resp) => return resp,
    };

    match get_object_meta_from_any(&state.osd_pool, &nodes, &bucket, &key).await {
        Ok(Some(meta)) => match meta.retention {
            Some(retention) => {
                let mode = match retention.mode() {
                    RetentionMode::RetentionGovernance => "GOVERNANCE",
                    RetentionMode::RetentionCompliance => "COMPLIANCE",
                    RetentionMode::RetentionNone => "COMPLIANCE",
                };
                // `as i64` mapped the upper half of u64 onto negative times,
                // so a stored value that cannot be a real date rendered as one
                // in 1969 — an expired lock — rather than as nothing.
                let date = i64::try_from(retention.retain_until_date)
                    .ok()
                    .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default();
                let result = RetentionResponse {
                    mode: mode.to_string(),
                    retain_until_date: date,
                };
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                    to_xml(&result).unwrap_or_default()
                );
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/xml")
                    .body(Body::from(xml))
                    .unwrap()
            }
            None => S3Error::xml_response(
                "NoSuchObjectLockConfiguration",
                "No retention set on this object",
                StatusCode::NOT_FOUND,
            ),
        },
        Ok(None) => S3Error::xml_response("NoSuchKey", "Object not found", StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get object metadata: {}", e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

async fn put_object_legal_hold_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    body: Bytes,
) -> Response {
    let req: LegalHoldRequest = match quick_xml::de::from_reader(body.as_ref()) {
        Ok(r) => r,
        Err(e) => {
            return S3Error::xml_response(
                "MalformedXML",
                &format!("Invalid legal hold XML: {}", e),
                StatusCode::BAD_REQUEST,
            );
        }
    };

    let status = match req.status.as_str() {
        "ON" => true,
        "OFF" => false,
        _ => {
            return S3Error::xml_response(
                "MalformedXML",
                "Legal hold status must be ON or OFF",
                StatusCode::BAD_REQUEST,
            );
        }
    };
    match bucket_lock(&mut state.meta_client.clone(), &bucket).await {
        Ok(Some(_)) => {}
        Ok(None) => return lock_not_configured(),
        Err(resp) => return resp,
    }

    let nodes = match get_placement_nodes_for_object(&state, &bucket, &key).await {
        Ok(n) => n,
        Err(resp) => return resp,
    };

    let mut object_meta = match get_object_meta_from_any(&state.osd_pool, &nodes, &bucket, &key)
        .await
    {
        Ok(Some(meta)) => meta,
        Ok(None) => {
            return S3Error::xml_response("NoSuchKey", "Object not found", StatusCode::NOT_FOUND);
        }
        Err(e) => {
            error!("Failed to get object metadata: {}", e);
            return S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    object_meta.legal_hold = Some(LegalHold { status });

    // Only over the object just read: a PUT that replaced it meanwhile has
    // freed its shards, and must not have it written back over its own.
    let expected = object_meta.object_id.clone();
    if let Err(e) = put_object_meta_to_all(
        &state.osd_pool,
        &nodes,
        &bucket,
        &key,
        object_meta,
        false,
        &expected,
    )
    .await
    {
        error!("Failed to update legal hold: {}", e);
        return S3Error::xml_response(
            "InternalError",
            &e.to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

async fn get_object_legal_hold_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
) -> Response {
    match bucket_lock(&mut state.meta_client.clone(), &bucket).await {
        Ok(Some(_)) => {}
        Ok(None) => return lock_not_configured(),
        Err(resp) => return resp,
    }
    let nodes = match get_placement_nodes_for_object(&state, &bucket, &key).await {
        Ok(n) => n,
        Err(resp) => return resp,
    };

    match get_object_meta_from_any(&state.osd_pool, &nodes, &bucket, &key).await {
        Ok(Some(meta)) => {
            let status = meta.legal_hold.as_ref().is_some_and(|lh| lh.status);
            let result = LegalHoldResponse {
                status: if status {
                    "ON".to_string()
                } else {
                    "OFF".to_string()
                },
            };
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
                to_xml(&result).unwrap_or_default()
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Ok(None) => S3Error::xml_response("NoSuchKey", "Object not found", StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get object metadata: {}", e);
            S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

// ============================================================================
// List Object Versions
// ============================================================================

#[derive(Serialize)]
#[serde(rename = "ListVersionsResult")]
struct ListVersionsResult {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Prefix")]
    prefix: String,
    #[serde(rename = "KeyMarker")]
    key_marker: String,
    #[serde(rename = "VersionIdMarker")]
    version_id_marker: String,
    #[serde(rename = "NextKeyMarker", skip_serializing_if = "Option::is_none")]
    next_key_marker: Option<String>,
    #[serde(
        rename = "NextVersionIdMarker",
        skip_serializing_if = "Option::is_none"
    )]
    next_version_id_marker: Option<String>,
    #[serde(rename = "MaxKeys")]
    max_keys: u32,
    #[serde(rename = "Delimiter", skip_serializing_if = "Option::is_none")]
    delimiter: Option<String>,
    #[serde(rename = "EncodingType", skip_serializing_if = "Option::is_none")]
    encoding_type: Option<String>,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    /// Versions and delete markers in listing order, as S3 interleaves
    /// them.
    #[serde(rename = "$value")]
    entries: Vec<VersionEntryXml>,
    #[serde(rename = "CommonPrefixes", skip_serializing_if = "Vec::is_empty")]
    common_prefixes: Vec<CommonPrefix>,
}

#[derive(Serialize)]
enum VersionEntryXml {
    Version(ObjectVersionXml),
    DeleteMarker(DeleteMarkerXml),
}

#[derive(Serialize)]
struct ObjectVersionXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "VersionId")]
    version_id: String,
    #[serde(rename = "IsLatest")]
    is_latest: bool,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "Size")]
    size: u64,
    #[serde(rename = "StorageClass")]
    storage_class: String,
}

#[derive(Serialize)]
struct DeleteMarkerXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "VersionId")]
    version_id: String,
    #[serde(rename = "IsLatest")]
    is_latest: bool,
    #[serde(rename = "LastModified")]
    last_modified: String,
}

/// What a ListObjectVersions request asks for.
struct VersionListing {
    prefix: String,
    delimiter: Option<String>,
    key_marker: String,
    version_id_marker: String,
    max_keys: u32,
    /// ?encoding-type=url: keys and prefixes percent-encoded in the answer.
    url_encoded: bool,
}

/// One OSD's version listing, read a page of whole keys at a time.
struct VersionSource {
    node: objectio_proto::metadata::ListingNode,
    /// Where its next page starts; `None` once it has no more.
    next: Option<String>,
    /// The last key it returned: everything up to here is in.
    reached: Option<String>,
}

/// ListObjectVersions. Every version lives on the OSDs of its key's home,
/// so each OSD's listing holds whole keys: read them all in key order, a
/// page at a time, and use only the keys every OSD still being read has
/// got past (an OSD further back may yet return more versions of a key).
/// Then dedupe the replicas, order each key's versions newest first, and
/// page.
async fn list_object_versions_internal(
    state: Arc<AppState>,
    bucket: String,
    req: VersionListing,
) -> Response {
    use objectio_proto::storage::ListObjectVersionsMetaRequest;

    let nodes = match state
        .meta_client
        .clone()
        .get_listing_nodes(GetListingNodesRequest {
            bucket: bucket.clone(),
            include_all_states: false,
        })
        .await
    {
        Ok(resp) => resp.into_inner().nodes,
        Err(e) => {
            error!("Failed to get listing nodes: {}", e);
            return S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    // Enough keys to fill a page whatever each holds, and one more to say
    // whether there is a next page.
    let want = req.max_keys as usize + 1;
    let page = req.max_keys.max(100);
    let mut sources: Vec<VersionSource> = nodes
        .into_iter()
        .map(|node| VersionSource {
            node,
            next: Some(req.key_marker.clone()),
            reached: None,
        })
        .collect();
    let mut found: std::collections::BTreeMap<String, Vec<ObjectMeta>> =
        std::collections::BTreeMap::new();
    let complete_to = |sources: &[VersionSource]| -> Option<Option<String>> {
        // None: nothing is complete yet. Some(None): everything is.
        let mut horizon: Option<&String> = None;
        for s in sources.iter().filter(|s| s.next.is_some()) {
            let r = s.reached.as_ref()?;
            horizon = Some(horizon.map_or(r, |h| h.min(r)));
        }
        Some(horizon.cloned())
    };
    loop {
        let complete = match complete_to(&sources) {
            Some(None) => found.len(),
            Some(Some(h)) => found.range(..=h).count(),
            None => 0,
        };
        if complete >= want {
            break;
        }
        // Read on from the OSD furthest behind.
        let Some(behind) = sources
            .iter_mut()
            .filter(|s| s.next.is_some())
            .min_by(|a, b| a.reached.cmp(&b.reached))
        else {
            break;
        };
        let from = behind.next.take().unwrap_or_default();
        let first = behind.reached.is_none();
        let mut client = match state
            .osd_pool
            .get_or_connect(&behind.node.node_id, &behind.node.address)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                // Its keys are on the other OSDs of their homes.
                warn!(
                    "version listing: OSD {} unreachable: {e}",
                    behind.node.address
                );
                continue;
            }
        };
        match client
            .list_object_versions_meta(ListObjectVersionsMetaRequest {
                bucket: bucket.clone(),
                prefix: req.prefix.clone(),
                key_marker: from,
                // The marker key's own versions, on the first page only:
                // its later versions come after the version marker.
                version_id_marker: if first && !req.version_id_marker.is_empty() {
                    req.version_id_marker.clone()
                } else {
                    String::new()
                },
                max_keys: page,
            })
            .await
        {
            Ok(resp) => {
                let page = resp.into_inner();
                for v in page.versions {
                    behind.reached = Some(v.key.clone());
                    found.entry(v.key.clone()).or_default().push(v);
                }
                behind.next = page.is_truncated.then_some(page.next_key_marker);
                if behind.reached.is_none() {
                    behind.reached = Some(String::new());
                }
            }
            Err(e) => {
                warn!("version listing: OSD {} failed: {e}", behind.node.address);
            }
        }
    }
    let horizon = complete_to(&sources).flatten();
    let more_beyond = horizon.is_some();
    if let Some(h) = &horizon {
        found.retain(|k, _| k <= h);
    }

    // Each key's versions once, newest first; the newest is the latest.
    let mut ordered: Vec<(ObjectMeta, bool)> = Vec::new();
    for (_, mut versions) in found {
        versions.sort_by(|a, b| version_age(b).cmp(&version_age(a)));
        versions.dedup_by(|a, b| a.version_id == b.version_id);
        for (i, v) in versions.into_iter().enumerate() {
            ordered.push((v, i == 0));
        }
    }
    // After the markers: past key_marker, or past version_id_marker within it.
    if !req.key_marker.is_empty() {
        let mut past = req.version_id_marker.is_empty();
        // A marker that is a rolled-up prefix: past every key under it.
        let rolled_marker = req
            .delimiter
            .as_ref()
            .is_some_and(|d| req.key_marker.ends_with(d.as_str()));
        ordered.retain(|(v, _)| {
            if rolled_marker && v.key.starts_with(&req.key_marker) {
                return false;
            }
            if v.key != req.key_marker {
                return v.key > req.key_marker;
            }
            if past {
                return !req.version_id_marker.is_empty();
            }
            if version_label(&v.version_id) == req.version_id_marker {
                past = true;
            }
            false
        });
    }

    let mut entries = Vec::new();
    let mut common_prefixes: Vec<CommonPrefix> = Vec::new();
    let mut last: Option<(String, String)> = None;
    let mut is_truncated = false;
    for (v, is_latest) in ordered {
        let rolled = req.delimiter.as_ref().and_then(|d| {
            v.key[req.prefix.len()..]
                .find(d.as_str())
                .map(|i| v.key[..req.prefix.len() + i + d.len()].to_string())
        });
        if let Some(p) = rolled {
            if common_prefixes.last().is_some_and(|c| c.prefix == p) {
                continue;
            }
            if entries.len() + common_prefixes.len() >= req.max_keys as usize {
                is_truncated = true;
                break;
            }
            // The next page starts after the whole prefix.
            last = Some((p.clone(), String::new()));
            common_prefixes.push(CommonPrefix { prefix: p });
            continue;
        }
        if entries.len() + common_prefixes.len() >= req.max_keys as usize {
            is_truncated = true;
            break;
        }
        last = Some((v.key.clone(), version_label(&v.version_id).to_string()));
        let last_modified = timestamp_to_iso(v.modified_at);
        let version_id = version_label(&v.version_id).to_string();
        entries.push(if v.is_delete_marker {
            VersionEntryXml::DeleteMarker(DeleteMarkerXml {
                key: v.key,
                version_id,
                is_latest,
                last_modified,
            })
        } else {
            VersionEntryXml::Version(ObjectVersionXml {
                key: v.key,
                version_id,
                is_latest,
                last_modified,
                etag: v.etag,
                size: v.size,
                storage_class: if v.storage_class.is_empty() {
                    "STANDARD".to_string()
                } else {
                    v.storage_class
                },
            })
        });
    }
    let is_truncated = is_truncated || (more_beyond && last.is_some());
    let (next_key_marker, next_version_id_marker) = match (is_truncated, last) {
        (true, Some((k, v))) => (Some(k), Some(v).filter(|v| !v.is_empty())),
        _ => (None, None),
    };

    let mut result = ListVersionsResult {
        name: bucket,
        prefix: req.prefix,
        key_marker: req.key_marker,
        version_id_marker: req.version_id_marker,
        next_key_marker,
        next_version_id_marker,
        max_keys: req.max_keys,
        delimiter: req.delimiter,
        encoding_type: req.url_encoded.then(|| "url".to_string()),
        is_truncated,
        entries,
        common_prefixes,
    };
    if req.url_encoded {
        let enc = |s: &mut String| *s = s3_url_encode(s);
        enc(&mut result.prefix);
        enc(&mut result.key_marker);
        if let Some(d) = &mut result.delimiter {
            enc(d);
        }
        if let Some(k) = &mut result.next_key_marker {
            enc(k);
        }
        for e in &mut result.entries {
            match e {
                VersionEntryXml::Version(v) => enc(&mut v.key),
                VersionEntryXml::DeleteMarker(m) => enc(&mut m.key),
            }
        }
        for p in &mut result.common_prefixes {
            enc(&mut p.prefix);
        }
    }
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        to_xml(&result).unwrap_or_default()
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(xml))
        .unwrap()
}

/// The OSDs `nodes` (a placement) puts an ObjectMeta on, by position: what
/// meta records as the key's home when the write lands.
fn home_of(nodes: &[objectio_proto::metadata::NodePlacement]) -> Vec<Vec<u8>> {
    nodes.iter().map(|n| n.node_id.clone()).collect()
}

/// Helper to get the primary OSD placement for an object
async fn get_placement_nodes_for_object(
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
            Err(S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

// ============================================================================
// Admin API - IAM Operations
// ============================================================================

/// Admin API response types
#[derive(Serialize)]
pub struct AdminUserResponse {
    pub user_id: String,
    pub display_name: String,
    pub arn: String,
    pub status: String,
    pub created_at: u64,
    pub email: String,
    pub tenant: String,
}

#[derive(Serialize)]
pub struct AdminAccessKeyResponse {
    pub access_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
    pub user_id: String,
    pub status: String,
    pub created_at: u64,
    /// `s3://bucket/prefix/` the key is confined to. Empty = unscoped.
    pub scope: String,
    /// `"READ"` or `"READ_WRITE"`.
    pub operation: String,
}

/// Optional JSON body for `POST /_admin/users/{user_id}/keys`.
///
/// An absent or empty body yields an unscoped read-write key, which is what
/// every pre-scoping caller sends.
#[derive(Debug, Deserialize, Default)]
pub struct CreateAccessKeyBody {
    /// `s3://bucket/prefix/` restriction. Omitted or empty = unscoped.
    #[serde(default)]
    pub scope: String,
    /// `"R"`/`"read-only"` or `"RW"`/`"read-write"`. Omitted = read-write.
    #[serde(default)]
    pub operation: Option<String>,
}

/// Render a `KeyOperation` proto value for API responses.
fn operation_label(operation: i32) -> String {
    if operation == ProtoKeyOperation::KeyOpRead as i32 {
        "READ".to_string()
    } else {
        "READ_WRITE".to_string()
    }
}

#[derive(Serialize)]
pub struct AdminListUsersResponse {
    pub users: Vec<AdminUserResponse>,
    pub is_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_marker: Option<String>,
}

#[derive(Serialize)]
pub struct AdminListAccessKeysResponse {
    pub access_keys: Vec<AdminAccessKeyResponse>,
}

#[derive(Deserialize)]
pub struct CreateUserParams {
    pub display_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub tenant: String,
}

/// List users (GET /_admin/users)
pub async fn admin_list_users(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    // Extract tenant before auth check consumes auth
    let tenant = auth
        .as_ref()
        .map(|Extension(a)| a.tenant.clone())
        .or_else(|| crate::console_auth::validate_session_from_headers(&headers).map(|s| s.tenant))
        .unwrap_or_default();

    // This handler already filters its result to the caller's tenant — it was
    // written for tenant admins. The gate in front of it was not: over SigV4
    // `check_admin_access` admits only the root key, so a tenant admin could
    // create a user and mint its keys but never list them back. Every sibling
    // route (list/create/delete access keys, delete user) uses the
    // tenant-aware gate; this one was the outlier.
    if tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &tenant).await
    {
        return deny;
    }

    let mut client = state.meta_client.clone();

    match client
        .list_users(ListUsersRequest {
            max_results: 1000,
            marker: String::new(),
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            let result = AdminListUsersResponse {
                users: resp
                    .users
                    .into_iter()
                    .filter(|u| tenant.is_empty() || u.tenant == tenant)
                    .map(|u| AdminUserResponse {
                        user_id: u.user_id,
                        display_name: u.display_name,
                        arn: u.arn,
                        status: format!("{:?}", u.status),
                        created_at: u.created_at,
                        email: u.email,
                        tenant: u.tenant,
                    })
                    .collect(),
                is_truncated: resp.is_truncated,
                next_marker: if resp.next_marker.is_empty() {
                    None
                } else {
                    Some(resp.next_marker)
                },
            };

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&result).unwrap()))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to list users: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"error":"{}"}}"#, e)))
                .unwrap()
        }
    }
}

/// Create user (POST /_admin/users)
pub async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = crate::admin::extract_caller(&auth, &headers);

    let params: CreateUserParams = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"error":"Invalid JSON: {}"}}"#, e)))
                .unwrap();
        }
    };

    // Default to the caller's tenant if the body leaves it empty.
    let tenant = if params.tenant.is_empty() {
        caller.tenant.clone()
    } else {
        params.tenant
    };

    // System admin can create users in any tenant (including system scope).
    // Tenant admins can only create users inside their own tenant.
    if tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &tenant).await
    {
        return deny;
    }

    let mut client = state.meta_client.clone();

    match client
        .create_user(CreateUserRequest {
            display_name: params.display_name,
            email: params.email,
            tenant,
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            let user = resp.user.unwrap();
            let result = AdminUserResponse {
                user_id: user.user_id,
                display_name: user.display_name,
                arn: user.arn,
                status: format!("{:?}", user.status),
                created_at: user.created_at,
                email: user.email,
                tenant: user.tenant,
            };

            info!("Created user: {}", result.user_id);
            Response::builder()
                .status(StatusCode::CREATED)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&result).unwrap()))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to create user: {}", e);
            // Map the gRPC code rather than calling everything a 500, and
            // send `e.message()` rather than `e` — the Display impl embeds the
            // whole tonic Status including its MetadataMap, which put response
            // headers and internal detail into the client's error body.
            let status = match e.code() {
                tonic::Code::AlreadyExists => StatusCode::CONFLICT,
                tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
                tonic::Code::NotFound => StatusCode::NOT_FOUND,
                tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "error": e.message() }).to_string(),
                ))
                .unwrap()
        }
    }
}

/// Resolve a user_id to its tenant via meta. Returns `None` if the user
/// does not exist, letting callers respond 404 appropriately.
async fn lookup_user_tenant(state: &AppState, user_id: &str) -> Option<String> {
    let mut client = state.meta_client.clone();
    let resp = client
        .get_user(GetUserRequest {
            user_id: user_id.to_string(),
        })
        .await
        .ok()?
        .into_inner();
    resp.user.map(|u| u.tenant)
}

/// Resolve an access_key_id to its tenant via meta.
async fn lookup_access_key_tenant(state: &AppState, access_key_id: &str) -> Option<String> {
    let mut client = state.meta_client.clone();
    let resp = client
        .get_access_key_for_auth(GetAccessKeyForAuthRequest {
            access_key_id: access_key_id.to_string(),
        })
        .await
        .ok()?
        .into_inner();
    resp.user.map(|u| u.tenant)
}

/// Delete user (DELETE /_admin/users/{user_id})
pub async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    // Look up target user's tenant so tenant admins cannot delete users
    // outside their own tenant.
    let target_tenant = match lookup_user_tenant(&state, &user_id).await {
        Some(t) => t,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"User not found"}"#))
                .unwrap();
        }
    };
    if target_tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &target_tenant).await
    {
        return deny;
    }

    let mut client = state.meta_client.clone();

    match client
        .delete_user(DeleteUserRequest {
            user_id: user_id.clone(),
        })
        .await
    {
        Ok(_) => {
            info!("Deleted user: {}", user_id);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"User not found"}"#))
                    .unwrap()
            } else {
                error!("Failed to delete user: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"error":"{}"}}"#, e)))
                    .unwrap()
            }
        }
    }
}

/// List access keys for user (GET /_admin/users/{user_id}/access-keys)
pub async fn admin_list_access_keys(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let target_tenant = match lookup_user_tenant(&state, &user_id).await {
        Some(t) => t,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"User not found"}"#))
                .unwrap();
        }
    };
    if target_tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &target_tenant).await
    {
        return deny;
    }

    let mut client = state.meta_client.clone();

    match client
        .list_access_keys(ListAccessKeysRequest {
            user_id: user_id.clone(),
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            let result = AdminListAccessKeysResponse {
                access_keys: resp
                    .access_keys
                    .into_iter()
                    .map(|k| AdminAccessKeyResponse {
                        access_key_id: k.access_key_id,
                        secret_access_key: None, // Don't return secret on list
                        user_id: k.user_id,
                        status: format!("{:?}", k.status),
                        created_at: k.created_at,
                        scope: k.scope,
                        operation: operation_label(k.operation),
                    })
                    .collect(),
            };

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&result).unwrap()))
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"User not found"}"#))
                    .unwrap()
            } else {
                error!("Failed to list access keys: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"error":"{}"}}"#, e)))
                    .unwrap()
            }
        }
    }
}
/// 400 with a JSON error body, for bad scope/operation input.
fn admin_key_error(message: &str) -> Response {
    let body = serde_json::json!({ "error": message }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// Create access key for user (POST /_admin/users/{user_id}/access-keys)
pub async fn admin_create_access_key(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    body: Bytes,
) -> Response {
    let target_tenant = match lookup_user_tenant(&state, &user_id).await {
        Some(t) => t,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"User not found"}"#))
                .unwrap();
        }
    };
    if target_tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &target_tenant).await
    {
        return deny;
    }

    // Body is optional: callers that predate scoped keys send none.
    let params: CreateAccessKeyBody = if body.is_empty() {
        CreateAccessKeyBody::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(e) => return admin_key_error(&format!("invalid request body: {e}")),
        }
    };

    // Reject a malformed scope rather than storing one that matches nothing.
    if !params.scope.is_empty()
        && let Err(msg) = objectio_auth::validate_scope(&params.scope)
    {
        return admin_key_error(&msg);
    }

    let operation = match params.operation.as_deref() {
        None => ProtoKeyOperation::KeyOpReadWrite,
        Some(raw) => match objectio_auth::Operation::parse(raw) {
            Some(objectio_auth::Operation::Read) => ProtoKeyOperation::KeyOpRead,
            Some(objectio_auth::Operation::ReadWrite) => ProtoKeyOperation::KeyOpReadWrite,
            None => {
                return admin_key_error(&format!(
                    "invalid operation '{raw}': expected 'R'/'read-only' or 'RW'/'read-write'"
                ));
            }
        },
    };

    let mut client = state.meta_client.clone();

    match client
        .create_access_key(CreateAccessKeyRequest {
            user_id: user_id.clone(),
            scope: params.scope.clone(),
            operation: operation as i32,
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            let key = resp.access_key.unwrap();
            let result = AdminAccessKeyResponse {
                access_key_id: key.access_key_id,
                secret_access_key: Some(key.secret_access_key), // Include secret on create
                user_id: key.user_id,
                status: format!("{:?}", key.status),
                created_at: key.created_at,
                scope: key.scope,
                operation: operation_label(key.operation),
            };

            info!(
                "Created access key {} for user {}",
                result.access_key_id, user_id
            );
            Response::builder()
                .status(StatusCode::CREATED)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&result).unwrap()))
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"User not found"}"#))
                    .unwrap()
            } else {
                error!("Failed to create access key: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"error":"{}"}}"#, e)))
                    .unwrap()
            }
        }
    }
}

/// Delete access key (DELETE /_admin/access-keys/{access_key_id})
pub async fn admin_delete_access_key(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(access_key_id): Path<String>,
) -> Response {
    let target_tenant = match lookup_access_key_tenant(&state, &access_key_id).await {
        Some(t) => t,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"Access key not found"}"#))
                .unwrap();
        }
    };
    if target_tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &target_tenant).await
    {
        return deny;
    }

    let mut client = state.meta_client.clone();

    match client
        .delete_access_key(DeleteAccessKeyRequest {
            access_key_id: access_key_id.clone(),
        })
        .await
    {
        Ok(_) => {
            info!("Deleted access key: {}", access_key_id);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"Access key not found"}"#))
                    .unwrap()
            } else {
                error!("Failed to delete access key: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"error":"{}"}}"#, e)))
                    .unwrap()
            }
        }
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
            300,
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
                300,
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
            overlapping_stripes(&s, 300, &ByteRange { start: 0, end: 99 }),
            vec![(0, 0)]
        );
        // Starts on the first byte of stripe 1.
        assert_eq!(
            overlapping_stripes(
                &s,
                300,
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
            overlapping_stripes(&s, 300, &ByteRange { start: 0, end: 299 }),
            vec![(0, 0), (1, 100), (2, 200)]
        );
    }

    #[test]
    fn a_single_stripe_without_a_recorded_size_falls_back_to_the_object_size() {
        // Objects written before data_size was recorded per stripe.
        let s = stripes(&[0]);
        assert_eq!(
            overlapping_stripes(&s, 500, &ByteRange { start: 10, end: 20 }),
            vec![(0, 0)]
        );
    }

    #[test]
    fn stripes_of_uneven_size_still_report_their_true_offsets() {
        let s = stripes(&[10, 250, 40]);
        assert_eq!(
            overlapping_stripes(&s, 300, &ByteRange { start: 5, end: 265 }),
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
        assert_eq!(
            vars.get("aws:SecureTransport").map(String::as_str),
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
