//! GET and HEAD: ranges, parts, preconditions, reading stripes.

use super::*;

/// Add the object's stored `x-amz-checksum-<algorithm>` to a GET or HEAD
/// response, when the request asked with `x-amz-checksum-mode: ENABLED`.
/// Only for whole-object responses: the stored value is the checksum of the
/// whole object, which a ranged body would not match.
pub(crate) fn add_checksum_header(
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
pub(crate) struct ByteRange {
    pub(crate) start: u64,
    pub(crate) end: u64, // inclusive
}

/// Parse HTTP Range header (e.g., "bytes=0-99" or "bytes=100-" or "bytes=-50")
pub(crate) fn parse_range_header(range_header: &str, total_size: u64) -> Option<ByteRange> {
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
pub(crate) fn object_part(stripe: &StripeMeta, data: Vec<u8>) -> Vec<u8> {
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
pub(crate) async fn read_packed_slice(
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

pub(crate) fn overlapping_stripes(stripes: &[StripeMeta], range: &ByteRange) -> Vec<(usize, u64)> {
    let mut offset = 0u64;
    let mut result = Vec::new();
    for (idx, stripe) in stripes.iter().enumerate() {
        // A pack member's bytes are a slice of the pack's stripe.
        let effective_size = if stripe.slice_length > 0 {
            stripe.slice_length
        } else {
            stripe.data_size
        };
        let stripe_end = offset + effective_size;
        if offset <= range.end && stripe_end > range.start {
            result.push((idx, offset));
        }
        offset = stripe_end;
    }
    result
}

/// A GET or HEAD's conditions on `object` (RFC 7232 order): 412 when
/// If-Match fails, or If-Unmodified-Since without an If-Match; 304 (with
/// the ETag) when If-None-Match matches, or If-Modified-Since without an
/// If-None-Match. They used to be ignored: every conditional read was 200.
pub(crate) fn read_preconditions(headers: &HeaderMap, object: &ObjectMeta) -> Option<Response> {
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

/// 416 InvalidRange, with the object's size in `Content-Range` as S3 sends.
pub(crate) fn range_not_satisfiable(size: u64) -> Response {
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
pub(crate) async fn get_object_attributes(
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
pub(crate) async fn get_object_part(
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
pub(crate) fn is_multipart(object: &ObjectMeta) -> bool {
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
pub(crate) fn part_bounds(object: &ObjectMeta, n: u32) -> Result<(u64, u64, u32), Response> {
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
pub(crate) async fn get_object_version(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
    headers: HeaderMap,
) -> Response {
    let mut notes = ReadNotes::default();
    let mut resp = get_object_version_once(
        state.clone(),
        bucket.clone(),
        key.clone(),
        version_id.clone(),
        headers.clone(),
        false,
        &mut notes,
    )
    .await;
    // A packed object read through a cached pack record that failed: the
    // pack may have moved (repair, drain). Once more, asking meta.
    if resp.status().is_server_error() && !notes.cached_packs.is_empty() {
        state
            .pack_cache
            .forget(notes.cached_packs.iter().map(Vec::as_slice));
        resp = get_object_version_once(state, bucket, key, version_id, headers, true, &mut notes)
            .await;
    }
    if resp.status().is_success()
        && let Some(v) = notes.expiration
    {
        resp.headers_mut().insert("x-amz-expiration", v);
    }
    if resp.status().is_success()
        && let Some(v) = notes.replication
    {
        resp.headers_mut().insert(
            "x-amz-replication-status",
            header::HeaderValue::from_static(v),
        );
    }
    resp
}

/// What one attempt at a read learned, for [`get_object_version`].
#[derive(Default)]
pub(crate) struct ReadNotes {
    /// Packs resolved from the cache.
    pub(crate) cached_packs: Vec<Vec<u8>>,
    /// `x-amz-expiration` for the object read.
    pub(crate) expiration: Option<header::HeaderValue>,
    /// `x-amz-replication-status` for the object read.
    pub(crate) replication: Option<&'static str>,
}

/// One attempt at [`get_object_version`]. `fresh_packs` resolves packs
/// from meta, not the cache; `notes` gets what the caller needs to know.
pub(crate) async fn get_object_version_once(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    version_id: Option<String>,
    headers: HeaderMap,
    fresh_packs: bool,
    notes: &mut ReadNotes,
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
            return meta_failure(&e, "Failed to get placement");
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

    let mut object = match object_to_read(
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
    // A packed object's stripe is a slice of its pack: where the pack's
    // shards are comes from the pack's record.
    match crate::packs::resolve(&state, &mut object, fresh_packs).await {
        Ok(true) => {
            notes.cached_packs.extend(
                crate::packs::packs_of(&object)
                    .into_iter()
                    .map(<[u8]>::to_vec),
            );
        }
        Ok(false) => {}
        Err(e) => {
            error!("GET {bucket}/{key}: {e}");
            return S3Error::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    }
    if let Some(resp) = read_preconditions(&headers, &object) {
        return resp;
    }
    notes.replication = crate::replication::status_header(&object);
    // The current version: when lifecycle will expire it.
    if version_id.is_none() {
        notes.expiration =
            crate::lifecycle::expiration_header(&state, &bucket, &object, version_time_ms(&object))
                .await;
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
    // object-level IV (single-part).
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
        let plan = overlapping_stripes(&object.stripes, range);
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

        let stripe_data_size = stripe.data_size as usize;
        if stripe_data_size == 0 && object.size > 0 {
            error!("Object stripe {stripe_idx} has no data_size");
            return S3Error::xml_response(
                "InternalError",
                "Object metadata is incomplete (missing stripe data_size)",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }

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

                let shard_object_id = &stripe.object_id;

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

        let ec_shard_object_id = &stripe.object_id;

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
pub(crate) fn inline_slice(
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

/// Resolve the gRPC address for a node.
///
/// First checks the in-memory map (populated from placement response).
/// On cache miss, fetches all active nodes via `GetListingNodes` and
/// populates the map so subsequent lookups are free.
pub(crate) async fn resolve_node_address(
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
            if let Some(v) = crate::replication::status_header(&obj) {
                builder = builder.header("x-amz-replication-status", v);
            }
            if params.version_id.is_none()
                && let Some(v) = crate::lifecycle::expiration_header(
                    &state,
                    &bucket,
                    &obj,
                    version_time_ms(&obj),
                )
                .await
            {
                builder = builder.header("x-amz-expiration", v);
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

/// The headers that describe a stored object beyond its content:
/// `x-amz-version-id` (not for the null version) and its object lock.
pub(crate) fn with_version_id(
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
    // `response-*`: the headers this one answer should carry instead of the
    // object's own (a presigned link forcing a download name, say). S3
    // refuses them to anonymous callers.
    let overrides = params.response_overrides();
    if !overrides.is_empty() {
        let anonymous = auth
            .as_ref()
            .is_some_and(|Extension(a)| a.auth_mode == objectio_auth::AuthMode::Anonymous);
        if anonymous {
            return S3Error::xml_response(
                "InvalidRequest",
                "Request specific response headers cannot be used for anonymous GET requests.",
                StatusCode::BAD_REQUEST,
            );
        }
        let mut values = Vec::with_capacity(overrides.len());
        for (name, v) in overrides {
            match header::HeaderValue::from_str(v) {
                Ok(v) => values.push((name, v)),
                Err(_) => {
                    return S3Error::xml_response(
                        "InvalidArgument",
                        &format!("Invalid value for {name}"),
                        StatusCode::BAD_REQUEST,
                    );
                }
            }
        }
        let mut resp = if let Some(n) = params.part_number {
            get_object_part(state, bucket, key, params.version_id, n, headers).await
        } else {
            get_object_version(state, bucket, key, params.version_id, headers).await
        };
        if resp.status().is_success() {
            for (name, v) in values {
                resp.headers_mut().insert(name, v);
            }
        }
        return resp;
    }
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
