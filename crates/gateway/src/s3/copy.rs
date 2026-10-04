//! CopyObject and UploadPartCopy.

use super::*;

/// Largest part UploadPartCopy takes: it is read into memory, so it is
/// held to the single-PUT limit.
pub(crate) const MAX_COPY_PART: usize = 100 * 1024 * 1024;

/// UploadPartCopy: a part of a multipart upload taken from (a range of) an
/// existing object.
///
/// It used to be an UploadPart of the request's empty body: the copy source
/// was ignored and an empty part stored, so an upload completed from such
/// parts was silently missing their data. The AWS CLI copies any object
/// over its multipart threshold this way.
pub(crate) async fn upload_part_copy_internal(
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
pub(crate) async fn copy_by_reference(
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

    // Quotas (A8b): a copy by reference stores no new shards, but the
    // destination object counts as the source's size, as usage does.
    if let Some(refused) = crate::quota::check(dest_bucket, source.size, 1) {
        return Some(refused);
    }

    let new_id = Uuid::now_v7().as_bytes().to_vec();
    let stripes = source.stripes.clone();
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
            return Some(meta_failure(&e, "Failed to get placement"));
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
    let mut object_meta = object_meta;
    crate::replication::mark(state, &mut object_meta).await;
    let marked = (!object_meta.replication.is_empty()).then(|| object_meta.clone());

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

    if let Some(object) = marked {
        crate::replication::enqueue(state, &object);
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
pub(crate) async fn copy_object_data(
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

/// A copy's `x-amz-copy-source-if-*` conditions as the GET conditions
/// they are on the source. Any that fails refuses the copy with 412.
pub(crate) fn copy_source_conditions(copy_headers: &HeaderMap) -> HeaderMap {
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
pub(crate) fn copy_condition_failed(resp: Response) -> Response {
    if resp.status() == StatusCode::NOT_MODIFIED {
        return condition_refused("PreconditionFailed");
    }
    resp
}

/// What a copy reads: an object, at a version or the current one.
pub(crate) struct CopySource {
    pub(crate) bucket: String,
    pub(crate) key: String,
    pub(crate) version: Option<String>,
}

/// `x-amz-copy-source`: "bucket/key", URL-decoded, and the version it
/// names, if any (`?versionId=`).
pub(crate) fn copy_source_of(headers: &HeaderMap) -> Option<(String, Option<String>)> {
    let raw = headers.get("x-amz-copy-source")?.to_str().ok()?;
    let (path, version) = match raw.split_once("?versionId=") {
        Some((p, v)) => (p, Some(v.to_string())),
        None => (raw, None),
    };
    let decoded = urlencoding::decode(path).unwrap_or_else(|_| path.into());
    Some((decoded.trim_start_matches('/').to_string(), version))
}
