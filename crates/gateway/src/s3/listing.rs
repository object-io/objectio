//! ListObjects (v1, v2) and ListObjectVersions.

use super::*;

/// Build ARN for an S3 resource
/// Shape a listing response for the API version the client asked for.
///
/// V1 (`GET /{bucket}`) paginates on Marker/NextMarker; V2
/// (`?list-type=2`) on ContinuationToken/KeyCount. Answering a V1
/// request with a V2-only body leaves the client nothing to page with.
#[cfg(test)]
pub(crate) fn apply_listing_version(
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
pub(crate) struct ListingEcho {
    pub(crate) continuation_token: Option<String>,
    /// The bucket's owner, shown on each object for V1, and for V2 with
    /// ?fetch-owner=true (objects record no owner of their own).
    pub(crate) owner: Option<String>,
    pub(crate) fetch_owner: bool,
}

pub(crate) fn apply_listing_echo(
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
pub(crate) fn url_encode_listing(result: &mut ListBucketResult) {
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
pub(crate) fn s3_url_encode(s: &str) -> String {
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

pub(crate) fn apply_listing_markers(
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
        return get_bucket_tagging(&state, &bucket).await;
    }
    if params.acl.is_some() {
        return get_acl(&state, &bucket, None, None).await;
    }
    if params.ownership_controls.is_some() {
        return get_ownership_controls(&state, &bucket).await;
    }
    if params.public_access_block.is_some() {
        return crate::public_access::get_bucket(&state, &bucket).await;
    }
    if params.policy_status.is_some() {
        return crate::public_access::get_policy_status(&state, &bucket).await;
    }
    if params.cors.is_some() {
        return crate::cors::get_bucket(&state, &bucket).await;
    }
    if params.replication.is_some() {
        return crate::replication::get_config(&state, &bucket).await;
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
        return crate::lifecycle::get_config(&state, &bucket).await;
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
            return S3Error::from_status(&e);
        }
    };
    let echo = || ListingEcho {
        continuation_token: params.continuation_token.clone(),
        owner: bucket_owner.clone(),
        fetch_owner: params.fetch_owner.as_deref() == Some("true"),
    };

    // Meta's listing index is the listing.
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
        let r = match meta_client.list_objects(meta_req).await {
            Ok(resp) => resp.into_inner(),
            Err(e) => return meta_failure(&e, "listing"),
        };
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
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/xml")
            .body(Body::from(xml))
            .unwrap()
    }
}

#[derive(Serialize)]
#[serde(rename = "ListVersionsResult")]
pub(crate) struct ListVersionsResult {
    #[serde(rename = "Name")]
    pub(crate) name: String,
    #[serde(rename = "Prefix")]
    pub(crate) prefix: String,
    #[serde(rename = "KeyMarker")]
    pub(crate) key_marker: String,
    #[serde(rename = "VersionIdMarker")]
    pub(crate) version_id_marker: String,
    #[serde(rename = "NextKeyMarker", skip_serializing_if = "Option::is_none")]
    pub(crate) next_key_marker: Option<String>,
    #[serde(
        rename = "NextVersionIdMarker",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) next_version_id_marker: Option<String>,
    #[serde(rename = "MaxKeys")]
    pub(crate) max_keys: u32,
    #[serde(rename = "Delimiter", skip_serializing_if = "Option::is_none")]
    pub(crate) delimiter: Option<String>,
    #[serde(rename = "EncodingType", skip_serializing_if = "Option::is_none")]
    pub(crate) encoding_type: Option<String>,
    #[serde(rename = "IsTruncated")]
    pub(crate) is_truncated: bool,
    /// Versions and delete markers in listing order, as S3 interleaves
    /// them.
    #[serde(rename = "$value")]
    pub(crate) entries: Vec<VersionEntryXml>,
    #[serde(rename = "CommonPrefixes", skip_serializing_if = "Vec::is_empty")]
    pub(crate) common_prefixes: Vec<CommonPrefix>,
}

#[derive(Serialize)]
pub(crate) enum VersionEntryXml {
    Version(ObjectVersionXml),
    DeleteMarker(DeleteMarkerXml),
}

#[derive(Serialize)]
pub(crate) struct ObjectVersionXml {
    #[serde(rename = "Key")]
    pub(crate) key: String,
    #[serde(rename = "VersionId")]
    pub(crate) version_id: String,
    #[serde(rename = "IsLatest")]
    pub(crate) is_latest: bool,
    #[serde(rename = "LastModified")]
    pub(crate) last_modified: String,
    #[serde(rename = "ETag")]
    pub(crate) etag: String,
    #[serde(rename = "Size")]
    pub(crate) size: u64,
    #[serde(rename = "StorageClass")]
    pub(crate) storage_class: String,
    #[serde(rename = "Owner", skip_serializing_if = "Option::is_none")]
    pub(crate) owner: Option<Owner>,
}

#[derive(Serialize)]
pub(crate) struct DeleteMarkerXml {
    #[serde(rename = "Key")]
    pub(crate) key: String,
    #[serde(rename = "VersionId")]
    pub(crate) version_id: String,
    #[serde(rename = "IsLatest")]
    pub(crate) is_latest: bool,
    #[serde(rename = "LastModified")]
    pub(crate) last_modified: String,
    #[serde(rename = "Owner", skip_serializing_if = "Option::is_none")]
    pub(crate) owner: Option<Owner>,
}

/// What a ListObjectVersions request asks for.
pub(crate) struct VersionListing {
    pub(crate) prefix: String,
    pub(crate) delimiter: Option<String>,
    pub(crate) key_marker: String,
    pub(crate) version_id_marker: String,
    pub(crate) max_keys: u32,
    /// ?encoding-type=url: keys and prefixes percent-encoded in the answer.
    pub(crate) url_encoded: bool,
}

/// One OSD's version listing, read a page of whole keys at a time.
pub(crate) struct VersionSource {
    pub(crate) node: objectio_proto::metadata::ListingNode,
    /// Where its next page starts; `None` once it has no more.
    pub(crate) next: Option<String>,
    /// The last key it returned: everything up to here is in.
    pub(crate) reached: Option<String>,
}

/// ListObjectVersions. Every version lives on the OSDs of its key's home,
/// so each OSD's listing holds whole keys: read them all in key order, a
/// page at a time, and use only the keys every OSD still being read has
/// got past (an OSD further back may yet return more versions of a key).
/// Then dedupe the replicas, order each key's versions newest first, and
/// page.
/// Every version of the keys from `key_marker` on, gathered from the OSDs
/// of their homes: at least `max_keys` whole keys (each with all its
/// versions, unsorted, possibly repeated across OSDs) unless the bucket
/// runs out first, and whether any keys lie beyond. Keys at or before
/// `key_marker` may be included; callers skip them.
pub(crate) async fn gather_versions(
    state: &AppState,
    bucket: &str,
    prefix: &str,
    key_marker: &str,
    version_id_marker: &str,
    max_keys: u32,
) -> Result<(std::collections::BTreeMap<String, Vec<ObjectMeta>>, bool), Response> {
    use objectio_proto::storage::ListObjectVersionsMetaRequest;
    let bucket = bucket.to_string();
    let req = VersionListing {
        prefix: prefix.to_string(),
        delimiter: None,
        key_marker: key_marker.to_string(),
        version_id_marker: version_id_marker.to_string(),
        max_keys,
        url_encoded: false,
    };
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
            return Err(S3Error::from_status(&e));
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

    Ok((found, more_beyond))
}

pub(crate) async fn list_object_versions_internal(
    state: Arc<AppState>,
    bucket: String,
    req: VersionListing,
) -> Response {
    let (found, more_beyond) = match gather_versions(
        &state,
        &bucket,
        &req.prefix,
        &req.key_marker,
        &req.version_id_marker,
        req.max_keys,
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Every version is the bucket owner's (BucketOwnerEnforced), and S3
    // names it on each entry.
    let owner = state
        .meta_client
        .clone()
        .get_bucket(GetBucketRequest {
            name: bucket.clone(),
        })
        .await
        .ok()
        .and_then(|r| r.into_inner().bucket)
        .map(|b| Owner {
            id: b.owner.clone(),
            display_name: b.owner,
        })
        .filter(|o| !o.id.is_empty());

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
                owner: owner.clone(),
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
                owner: owner.clone(),
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
