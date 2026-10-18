//! Grep over an object or a prefix.

use super::*;

/// `POST /{bucket}/{key}?grep` — gateway-side regex/grep over the
/// object's contents. Reuses the normal authenticated GetObject path
/// to fetch the body, then streams match events (NDJSON) back with
/// full byte-offset metadata for agent follow-up fetches. See
/// `grep.rs` for the wire format.
///
/// v1 collects the object body into memory before scanning — fine for
/// the .md / .txt / .jsonl agent use case up to a few GiB. Streaming
/// directly off the EC read path is a follow-up.
pub(crate) async fn grep_object_internal(
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
pub(crate) async fn grep_prefix_internal(
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

    let keys: Vec<(String, u64)> = list_resp
        .entries
        .into_iter()
        .map(|e| (e.key, e.size))
        .collect();

    // Capture the pagination cursor — emitted in the End frame so the
    // client can continue on the next request.
    let next_token: Option<String> =
        if list_resp.is_truncated && !list_resp.next_continuation_token.is_empty() {
            Some(list_resp.next_continuation_token.clone())
        } else {
            None
        };

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
