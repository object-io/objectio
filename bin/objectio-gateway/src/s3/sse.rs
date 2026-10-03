//! Server-side encryption: deciding it for a write, SSE-C keys, decrypting reads, bucket default encryption.

use super::*;

/// Decision produced by [`resolve_sse_decision`].
#[derive(Debug, Clone)]
pub(crate) struct SseDecision {
    pub(crate) algorithm: SseAlgorithm,
    /// KMS key id (or ARN) — populated only for `SseKms`.
    pub(crate) kms_key_id: String,
    /// Optional encryption context for SSE-KMS. Bound to the DEK wrap as AEAD.
    pub(crate) encryption_context: HashMap<String, String>,
}

/// Resolve the effective SSE algorithm for an operation.
///
/// Precedence follows AWS: explicit `x-amz-server-side-encryption*` request
/// headers win, else the bucket default encryption, else plaintext.
#[allow(clippy::result_large_err)]
pub(crate) async fn resolve_sse_decision(
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
            return Err(S3Error::from_status(&e));
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
pub(crate) struct SseCKey {
    pub(crate) key: [u8; objectio_kms::DEK_LEN],
    /// Base64-encoded MD5 of the raw key, echoed back in response headers.
    pub(crate) md5_b64: String,
}

/// A write's encryption headers that contradict each other: SSE-C with
/// server-side encryption, or a KMS key without `aws:kms`. 400, as S3.
pub(crate) fn sse_header_conflict(headers: &HeaderMap) -> Option<Response> {
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
pub(crate) fn sse_headers_on_read(headers: &HeaderMap) -> Option<Response> {
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
pub(crate) const SSE_C_SALT: &str = "objectio-sse-c-salt";

pub(crate) const SSE_C_HASH: &str = "objectio-sse-c-key-sha256";

/// The record of `key` an SSE-C object is stored with.
pub(crate) fn sse_c_verifier(key: &[u8]) -> HashMap<String, String> {
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
pub(crate) fn sse_c_key_matches(context: &HashMap<String, String>, key: &[u8]) -> bool {
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
pub(crate) fn sse_c_read_refusal(headers: &HeaderMap, object: &ObjectMeta) -> Option<Response> {
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
pub(crate) fn parse_sse_c_headers(headers: &HeaderMap) -> Result<Option<SseCKey>, Response> {
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
pub(crate) fn parse_encryption_context_header(
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
pub(crate) async fn apply_put_sse(
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

/// Populate policy-engine context variables from incoming S3 request headers.
///
/// These are the AWS IAM/S3 condition keys relevant to object-level SSE
/// enforcement — bucket policies like `Deny unless s3:x-amz-server-side-encryption`
/// read these values from `RequestContext.variables`.
pub(crate) fn sse_condition_vars(headers: Option<&HeaderMap>) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    let Some(h) = headers else {
        vars.insert("aws:SecureTransport".to_string(), "false".to_string());
        return vars;
    };
    let header = |name: &str| h.get(name).and_then(|v| v.to_str().ok());
    // TLS ends at the proxy in front of the gateway, which says so in
    // X-Forwarded-Proto. This was "true" for every request, so a policy
    // denying plain HTTP denied nothing on a gateway reached over HTTP.
    let secure = header("x-forwarded-proto").is_some_and(|p| p.eq_ignore_ascii_case("https"));
    vars.insert("aws:SecureTransport".to_string(), secure.to_string());
    // Request headers S3 exposes as condition keys.
    for name in [
        "x-amz-server-side-encryption",
        "x-amz-server-side-encryption-aws-kms-key-id",
        "x-amz-server-side-encryption-customer-algorithm",
        "x-amz-acl",
        "x-amz-copy-source",
        "x-amz-metadata-directive",
        "x-amz-storage-class",
        "x-amz-content-sha256",
        "x-amz-object-lock-mode",
        "x-amz-object-lock-legal-hold",
    ] {
        if let Some(v) = header(name) {
            vars.insert(format!("s3:{name}"), v.to_string());
        }
    }
    // Tags the request puts on the object.
    if let Some(tagging) = header("x-amz-tagging")
        && let Ok(tags) = parse_tagging(tagging)
    {
        let mut keys: Vec<&String> = tags.keys().collect();
        keys.sort();
        vars.insert(
            "s3:RequestObjectTagKeys".to_string(),
            keys.iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(","),
        );
        for (k, v) in &tags {
            vars.insert(format!("s3:RequestObjectTag/{k}"), v.clone());
        }
    }
    vars
}

/// Put object (PUT /{bucket}/{key})
/// Refuse a CopyObject whose source or destination uses SSE-C, which needs
/// copy-source customer-key headers not wired through yet; and one whose
/// source is not there. Everything else is copied by `copy_object_data`.
#[allow(clippy::result_large_err)]
pub(crate) async fn check_copy_sse(
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

/// Decrypt `buf` — one stripe's contribution to the GET response.
///
/// Picks the right IV + counter offset so a single helper works for both
/// single-part objects (one IV for the whole body) and multipart ones (an
/// IV per stripe).
#[allow(clippy::result_large_err)]
pub(crate) fn decrypt_stripe_slice(
    dek: &[u8; objectio_kms::DEK_LEN],
    stripe: &StripeMeta,
    object: &ObjectMeta,
    stripe_byte_offset_in_object: u64,
    slice_start_in_stripe: u64,
    buf: &mut [u8],
) -> Result<(), Response> {
    // Per-stripe IV (multipart): decrypt from the offset within the
    // stripe. Otherwise the object-level IV (single-part, whole-body CTR),
    // with the absolute byte offset within the object.
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

/// A copy's `x-amz-copy-source-server-side-encryption-customer-*` headers
/// (the SSE-C source's key) as the headers a GET of the source takes.
pub(crate) fn copy_source_customer_headers(copy_headers: &HeaderMap) -> HeaderMap {
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
pub(crate) fn asks_sse_c(headers: &HeaderMap) -> bool {
    headers.keys().any(|k| {
        k.as_str()
            .starts_with("x-amz-server-side-encryption-customer-")
    })
}

#[derive(Deserialize)]
#[serde(rename = "ServerSideEncryptionConfiguration")]
pub(crate) struct SseConfigRequest {
    #[serde(rename = "Rule")]
    #[serde(default)]
    pub(crate) rules: Vec<SseRuleXml>,
}

#[derive(Deserialize, Serialize, Clone)]
pub(crate) struct SseRuleXml {
    #[serde(rename = "ApplyServerSideEncryptionByDefault")]
    pub(crate) apply_default: Option<SseByDefaultXml>,
    #[serde(rename = "BucketKeyEnabled")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) bucket_key_enabled: Option<bool>,
}

#[derive(Deserialize, Serialize, Clone)]
pub(crate) struct SseByDefaultXml {
    #[serde(rename = "SSEAlgorithm")]
    pub(crate) sse_algorithm: String,
    #[serde(rename = "KMSMasterKeyID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kms_master_key_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename = "ServerSideEncryptionConfiguration")]
pub(crate) struct SseConfigResponse {
    #[serde(rename = "Rule")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) rules: Vec<SseRuleXml>,
}

pub(crate) fn parse_sse_algorithm(s: &str) -> Option<SseAlgorithm> {
    match s {
        "AES256" => Some(SseAlgorithm::SseS3),
        "aws:kms" => Some(SseAlgorithm::SseKms),
        _ => None,
    }
}

pub(crate) fn sse_algorithm_to_aws(alg: SseAlgorithm) -> Option<&'static str> {
    match alg {
        SseAlgorithm::SseS3 => Some("AES256"),
        SseAlgorithm::SseKms => Some("aws:kms"),
        SseAlgorithm::SseNone | SseAlgorithm::SseC => None,
    }
}

pub(crate) async fn put_bucket_encryption_internal(
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
            S3Error::from_status(&e)
        }
    }
}

pub(crate) async fn get_bucket_encryption_internal(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
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
            S3Error::from_status(&e)
        }
    }
}

pub(crate) async fn delete_bucket_encryption_internal(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
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
            S3Error::from_status(&e)
        }
    }
}
