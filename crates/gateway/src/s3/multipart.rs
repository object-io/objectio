//! Multipart uploads.

use super::*;

/// User-metadata key under which a multipart upload carries the tags its
/// CreateMultipartUpload asked for, until CompleteMultipartUpload puts them
/// on the object. A header name cannot contain a space, so no
/// `x-amz-meta-*` header can collide with it.
pub(crate) const UPLOAD_TAGS_KEY: &str = "objectio tagging";

/// The flexible checksum algorithm a CreateMultipartUpload declares (its
/// `x-amz-checksum-algorithm`), kept in the upload's metadata.
pub(crate) const UPLOAD_CHECKSUM_KEY: &str = "objectio checksum-algorithm";

pub(crate) const UPLOAD_CHECKSUM_TYPE_KEY: &str = "objectio checksum-type";

/// The object-lock headers a CreateMultipartUpload carries, kept in the
/// upload's metadata under this prefix until CompleteMultipartUpload.
pub(crate) const UPLOAD_LOCK_PREFIX: &str = "objectio lock ";

pub(crate) const UPLOAD_LOCK_HEADERS: &[&str] = &[
    "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date",
    "x-amz-object-lock-legal-hold",
];

/// Initiate multipart upload - internal implementation
pub(crate) async fn initiate_multipart_upload_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    headers: &HeaderMap,
    auth: &Option<Extension<AuthResult>>,
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
    // A replica sent as a multipart upload keeps its source's version id
    // and ETag: carried with the upload to its completion.
    let versioned = bucket_versioning(&mut client, &bucket)
        .await
        .is_ok_and(|v| v == VersioningState::VersioningEnabled);
    match crate::replication::replica_request(&state, auth, &bucket, &key, headers, versioned).await
    {
        Ok(Some(r)) => {
            user_metadata.insert(
                crate::replication::UPLOAD_REPLICA_VERSION.into(),
                r.version_id,
            );
            user_metadata.insert(crate::replication::UPLOAD_REPLICA_ETAG.into(), r.etag);
            user_metadata.insert(crate::replication::UPLOAD_REPLICA_OF.into(), r.of);
        }
        Ok(None) => {}
        Err(resp) => return resp,
    }
    // Object lock asked for now, checked now, applied at completion (with
    // the bucket's default retention when none is asked for).
    if let Err(resp) = object_lock_for_write(&mut client, &bucket, headers, None).await {
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
                return S3Error::from_status(&e);
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
                S3Error::from_status(&e)
            }
        }
    }
}

/// Upload part - internal implementation
pub(crate) async fn upload_part_internal(
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
    // Quotas (A8b): a part's bytes count when it is uploaded; the object,
    // when the upload completes.
    if let Some(refused) = crate::quota::check(&bucket, part_size, 0) {
        return refused;
    }

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
            return S3Error::from_status(&e);
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
            return meta_failure(&e, "Failed to get placement");
        }
    };

    let ec_k = placement.ec_k;
    let ec_m = placement.ec_m;
    let ec_type = ErasureType::try_from(placement.ec_type).unwrap_or(ErasureType::ErasureMds);
    let replication_count = placement.replication_count;

    // Generate a unique object ID for this part
    let part_object_id = *Uuid::now_v7().as_bytes();
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

            let mut full = false;
            for (pos, result, placement_node) in results {
                match result {
                    Ok((location, crc32c)) => {
                        success += 1;
                        locs.push(ShardLocation {
                            position: pos,
                            node_id: location.node_id,
                            disk_id: location.disk_id,
                            offset: location.offset,
                            shard_type: placement_node.shard_type,
                            local_group: placement_node.local_group,
                            crc32c: Some(crc32c),
                        });
                    }
                    Err(e) => {
                        full |= e.is_full();
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
                if full {
                    return S3Error::storage_full();
                }
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

            let mut full = false;
            for (pos, result, placement_node) in results {
                match result {
                    Ok((location, crc32c)) => {
                        success += 1;
                        locs.push(ShardLocation {
                            position: pos,
                            node_id: location.node_id,
                            disk_id: location.disk_id,
                            offset: location.offset,
                            shard_type: placement_node.shard_type,
                            local_group: placement_node.local_group,
                            crc32c: Some(crc32c),
                        });
                    }
                    Err(e) => {
                        full |= e.is_full();
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
                if full {
                    return S3Error::storage_full();
                }
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
                S3Error::from_status(&e)
            }
        }
    }
}

/// Complete multipart upload - internal implementation
pub(crate) async fn complete_multipart_upload_internal(
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

    // Quotas (A8b): the object (its parts' bytes were counted as they came).
    if let Some(refused) = crate::quota::check(&bucket, 0, 1) {
        return refused;
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

    // Where the object goes, and whether it is a version: read before the
    // completion, while failing leaves the upload as it was. (Read after
    // it, a failure here left the client no upload to complete again.)
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
        Err(e) => {
            error!("Failed to get placement for {bucket}/{key}: {e}");
            return meta_failure(&e, "Failed to get placement");
        }
    };
    // With versioning on, an object this replaces is kept (the OSDs also
    // say so per replica); otherwise it is freed. Not knowing, keep what
    // this replaces: a leak at worst, where guessing "unversioned" would
    // free a version.
    let versioning_enabled = bucket_versioning(&mut meta_client, &bucket)
        .await
        .map_or(true, |v| v == VersioningState::VersioningEnabled);
    let version_id = if versioning_enabled {
        new_version_id()
    } else {
        String::new()
    };

    // Complete the multipart upload via metadata service: two-phase, so
    // the upload stays (being completed) until the object is stored, and
    // a completion that fails to store it can be sent again.
    let completed = meta_client
        .complete_multipart_upload(ProtoCompleteMultipartUploadRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            upload_id: upload_id.clone(),
            parts,
            version_id: version_id.clone(),
            // Two-phase once every node reads the mark (format level 6);
            // before that, as the release before: the upload goes at once.
            settle_after_commit: objectio_common::version::allows(
                objectio_common::version::COMPLETED_UPLOADS_LEVEL,
            ),
        })
        .await;
    // A lost answer, for --test-hooks (as a leader change or timeout loses
    // one): the completion stays, being completed, for the retry.
    match crate::test_hooks::maybe_lost("complete_multipart_upload", completed) {
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

                // A new version, as a single-part PUT makes: meta keeps the
                // one asked for with the completion, so one sent again
                // makes the same version (a meta of the release before
                // returns none). Or a replica's, which keeps its source's
                // version id and ETag.
                if object.version_id.is_empty() {
                    object.version_id.clone_from(&version_id);
                }
                if let Some(v) = object
                    .user_metadata
                    .remove(crate::replication::UPLOAD_REPLICA_VERSION)
                {
                    object.version_id = v;
                    if let Some(etag) = object
                        .user_metadata
                        .remove(crate::replication::UPLOAD_REPLICA_ETAG)
                        .filter(|e| !e.is_empty())
                    {
                        object.etag = etag;
                    }
                    object.replica_of = object
                        .user_metadata
                        .remove(crate::replication::UPLOAD_REPLICA_OF)
                        .unwrap_or_else(|| "replica".to_string());
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
                let lock = match object_lock_for_write(&mut meta_client, &bucket, &asked, None)
                    .await
                {
                    Ok(lock) => Ok(lock),
                    Err(_) => {
                        object_lock_for_write(&mut meta_client, &bucket, &HeaderMap::new(), None)
                            .await
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
                // Listed with its ObjectMeta, as a single-part PUT is. The
                // parts are never freed here: stored, they are the object;
                // certainly not stored, the upload is open again and they
                // are its parts; maybe stored, it stays being completed and
                // the completion sent again stores the same object.
                //
                // Not settling (meta dropped the upload at once, below the
                // level): the parts belong to nothing on a failure that
                // stored nothing, and commit_put frees them, as before.
                let sent = if resp.settling {
                    Vec::new()
                } else {
                    stripe_targets(&object.stripes)
                };
                let committed = commit_put_outcome(
                    &state,
                    &placement,
                    object.clone(),
                    versioning_enabled,
                    sent,
                    &condition,
                    None,
                )
                .await;
                match committed {
                    Ok(()) if resp.settling => {
                        settle_upload(&state, &bucket, &key, &upload_id, &object.object_id, true)
                            .await;
                    }
                    Ok(()) => {}
                    Err(refused) if !resp.settling => return refused.response,
                    Err(refused) => {
                        if refused.not_stored {
                            settle_upload(
                                &state,
                                &bucket,
                                &key,
                                &upload_id,
                                &object.object_id,
                                false,
                            )
                            .await;
                        } else {
                            warn!(
                                "{bucket}/{key} upload {upload_id}: the object may have been \
                                 stored; the upload stays being completed for a retry"
                            );
                        }
                        return refused.response;
                    }
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
                && let Some(code) = ["EntityTooSmall", "InvalidPartOrder"]
                    .into_iter()
                    .find(|c| e.message().starts_with(c))
            {
                S3Error::xml_response(code, e.message(), StatusCode::BAD_REQUEST)
            } else if e.code() == tonic::Code::InvalidArgument {
                S3Error::xml_response("InvalidPart", e.message(), StatusCode::BAD_REQUEST)
            } else {
                S3Error::from_status(&e)
            }
        }
    }
}

/// Settle a two-phase completion in meta: its object `stored`, or certainly
/// not. Retried for a while in the background when meta can't take it now;
/// until then the upload stays being completed, which a completion sent
/// again or an abort resolves.
pub(crate) async fn settle_upload(
    state: &Arc<AppState>,
    bucket: &str,
    key: &str,
    upload_id: &str,
    object_id: &[u8],
    stored: bool,
) {
    let req = SettleMultipartUploadRequest {
        bucket: bucket.to_string(),
        key: key.to_string(),
        upload_id: upload_id.to_string(),
        object_id: object_id.to_vec(),
        committed: stored,
    };
    let first = state
        .meta_client
        .clone()
        .settle_multipart_upload(req.clone())
        .await;
    match first {
        Ok(_) => return,
        // A meta of the release before: it dropped the upload already.
        Err(e) if e.code() == tonic::Code::Unimplemented => return,
        Err(e) => warn!("{bucket}/{key} upload {upload_id}: not settled yet ({e}); retrying"),
    }
    let state = Arc::clone(state);
    tokio::spawn(async move {
        let mut wait = std::time::Duration::from_millis(500);
        for _ in 0..8 {
            tokio::time::sleep(wait).await;
            if state
                .meta_client
                .clone()
                .settle_multipart_upload(req.clone())
                .await
                .is_ok()
            {
                return;
            }
            wait = (wait * 2).min(std::time::Duration::from_secs(30));
        }
        warn!(
            "{}/{} upload {}: still not settled; left being completed",
            req.bucket, req.key, req.upload_id
        );
    });
}

/// How long a completion is left to finish before an abort decides it: by
/// then its gateway has stored the object and settled, or is gone, and a
/// copy the commit reached has been healed (a maybe-stored object is
/// either current by now or never will be).
const COMPLETING_GRACE_SECS: u64 = 600;

/// Abort `upload_id`: dropped in meta, its parts' stripes returned for the
/// caller to free. One being completed is decided first: if its object was
/// stored the upload is gone (NotFound, as for any completed upload); if
/// not, it is opened again and aborted; if too recent to tell, Unavailable.
pub(crate) async fn abort_upload(
    state: &Arc<AppState>,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<Vec<objectio_proto::metadata::StripeMeta>, tonic::Status> {
    let mut client = state.meta_client.clone();
    let abort = || AbortMultipartUploadRequest {
        bucket: bucket.to_string(),
        key: key.to_string(),
        upload_id: upload_id.to_string(),
    };
    match client.abort_multipart_upload(abort()).await {
        Ok(resp) => return Ok(resp.into_inner().stripes),
        Err(e) if e.code() != tonic::Code::FailedPrecondition => return Err(e),
        Err(_) => {}
    }
    let upload = client
        .get_multipart_upload(GetMultipartUploadRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id: upload_id.to_string(),
        })
        .await?
        .into_inner();
    if !upload.found {
        return Err(tonic::Status::not_found("multipart upload not found"));
    }
    if !upload.completing_object_id.is_empty() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if now.saturating_sub(upload.completing_since) < COMPLETING_GRACE_SECS {
            return Err(tonic::Status::unavailable(
                "the upload is being completed; retry later",
            ));
        }
        let Ok(nodes) = get_placement_nodes_for_object(state, bucket, key).await else {
            return Err(tonic::Status::unavailable("no placement for the key"));
        };
        let pool = &state.osd_pool;
        let read = if upload.completing_version_id.is_empty() {
            get_object_meta_from_any(pool, &nodes, bucket, key).await
        } else {
            find_version(pool, &nodes, bucket, key, &upload.completing_version_id).await
        };
        let stored = match read {
            Ok(found) => found.is_some_and(|o| o.object_id == upload.completing_object_id),
            Err(e) => return Err(tonic::Status::unavailable(format!("reading the key: {e}"))),
        };
        settle_upload(
            state,
            bucket,
            key,
            upload_id,
            &upload.completing_object_id,
            stored,
        )
        .await;
        if stored {
            return Err(tonic::Status::not_found("the upload was completed"));
        }
    }
    client
        .abort_multipart_upload(abort())
        .await
        .map(|resp| resp.into_inner().stripes)
}

/// The composite checksum of an object made of `numbers`' parts, when they
/// all have one, of one algorithm: that algorithm over their checksums
/// end to end, base64, then "-" and how many.
pub(crate) async fn composite_checksum(
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
pub(crate) fn multipart_etag(part_etags: &[String]) -> Option<String> {
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
pub(crate) async fn already_completed(
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

/// List parts - internal implementation
pub(crate) async fn list_parts_internal(
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
                S3Error::from_status(&e)
            }
        }
    }
}

/// Abort multipart upload - internal implementation
pub(crate) async fn abort_multipart_upload_internal(
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
    match abort_upload(&state, &bucket, &key, &upload_id).await {
        Ok(stripes) => {
            // Best effort, like the object path: a shard that cannot be
            // deleted is a leaked block, not a failed abort. Awaited, as a
            // DELETE is, so the space is free when the client hears back.
            let failed = reclaim_shards(
                &state.osd_pool,
                &mut client,
                stripe_targets(&stripes),
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
            S3Error::from_status(&e)
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
pub(crate) async fn list_multipart_uploads_internal(
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
                S3Error::from_status(&e)
            }
        }
    }
}
