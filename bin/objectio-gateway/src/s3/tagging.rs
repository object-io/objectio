//! Object and bucket tagging.

use super::*;

/// Bucket setting that holds the bucket's tags: a JSON array of
/// `[key, value]` pairs, sorted by key.
pub(crate) const BUCKET_TAGS_SETTING: &str = "tagging";

/// Tags a bucket may carry (S3's limit).
pub(crate) const MAX_BUCKET_TAGS: usize = 50;

pub(crate) fn bucket_setting_error(e: &tonic::Status) -> Response {
    if e.code() == tonic::Code::NotFound {
        S3Error::xml_response(
            "NoSuchBucket",
            "The specified bucket does not exist",
            StatusCode::NOT_FOUND,
        )
    } else {
        error!("bucket setting: {e}");
        S3Error::xml_response(
            "InternalError",
            e.message(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }
}

/// `GET /{bucket}?tagging`
pub(crate) async fn get_bucket_tagging(state: &AppState, bucket: &str) -> Response {
    if let Err(resp) = bucket_owner(state, bucket).await {
        return resp;
    }
    let setting = match state
        .meta_client
        .clone()
        .get_bucket_setting(objectio_proto::metadata::GetBucketSettingRequest {
            bucket: bucket.to_string(),
            name: BUCKET_TAGS_SETTING.to_string(),
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => return bucket_setting_error(&e),
    };
    let stored: Option<Vec<(String, String)>> = setting
        .found
        .then(|| serde_json::from_slice(&setting.value).ok())
        .flatten();
    let Some(pairs) = stored else {
        return S3Error::xml_response(
            "NoSuchTagSet",
            "The TagSet does not exist",
            StatusCode::NOT_FOUND,
        );
    };
    let body = TaggingXml {
        tag_set: TagSetXml {
            tags: pairs
                .into_iter()
                .map(|(key, value)| TagXml { key, value })
                .collect(),
        },
    };
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        to_xml(&body).unwrap_or_default()
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(xml))
        .unwrap()
}

/// `PUT /{bucket}?tagging` (a whole new tag set) and `DELETE
/// /{bucket}?tagging` (`None`).
pub(crate) async fn set_bucket_tagging(
    state: &AppState,
    bucket: &str,
    body: Option<&[u8]>,
) -> Response {
    let value = match body {
        None => Vec::new(),
        Some(body) => {
            let parsed: TaggingXml = match quick_xml::de::from_reader(body) {
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
            let tags = match validate_tags(pairs, MAX_BUCKET_TAGS) {
                Ok(t) => t,
                Err(resp) => return resp,
            };
            let mut sorted: Vec<(String, String)> = tags.into_iter().collect();
            sorted.sort();
            serde_json::to_vec(&sorted).unwrap_or_default()
        }
    };
    match state
        .meta_client
        .clone()
        .put_bucket_setting(objectio_proto::metadata::PutBucketSettingRequest {
            bucket: bucket.to_string(),
            name: BUCKET_TAGS_SETTING.to_string(),
            delete: body.is_none(),
            value,
        })
        .await
    {
        Ok(_) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap(),
        Err(e) => bucket_setting_error(&e),
    }
}

/// Tags an object may carry (S3's limit).
pub(crate) const MAX_TAGS: usize = 10;

/// Check tags against S3's rules: at most 10, keys of 1–128 characters and
/// values of at most 256, no key twice, none in the reserved `aws:` space.
#[allow(clippy::result_large_err)]
pub(crate) fn validate_tags(
    pairs: Vec<(String, String)>,
    max: usize,
) -> Result<HashMap<String, String>, Response> {
    let invalid = |msg: String| {
        Err(S3Error::xml_response(
            "InvalidTag",
            &msg,
            StatusCode::BAD_REQUEST,
        ))
    };
    if pairs.len() > max {
        return invalid(format!("Tags cannot be more than {max}"));
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
pub(crate) fn parse_tagging(value: &str) -> Result<HashMap<String, String>, Response> {
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
    validate_tags(pairs, MAX_TAGS)
}

/// Tags a request sets with `x-amz-tagging`; none when it has no such
/// header.
#[allow(clippy::result_large_err)]
pub(crate) fn tagging_header(headers: &HeaderMap) -> Result<HashMap<String, String>, Response> {
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
pub(crate) fn encode_tagging(tags: &HashMap<String, String>) -> String {
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
pub(crate) fn replaces_tags(copy_headers: &HeaderMap) -> bool {
    copy_headers
        .get("x-amz-tagging-directive")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("REPLACE"))
}

/// `x-amz-tagging-count` on a GET or HEAD of an object that has tags.
pub(crate) fn add_tagging_count(
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
pub(crate) struct TaggingXml {
    #[serde(rename = "TagSet", default)]
    pub(crate) tag_set: TagSetXml,
}

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct TagSetXml {
    #[serde(rename = "Tag", default)]
    pub(crate) tags: Vec<TagXml>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct TagXml {
    #[serde(rename = "Key")]
    pub(crate) key: String,
    #[serde(rename = "Value", default)]
    pub(crate) value: String,
}

/// The object's ObjectMeta and the nodes that hold it, or the response to
/// give instead.
pub(crate) async fn object_meta_for_update(
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

pub(crate) async fn get_object_tagging_internal(
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
pub(crate) async fn set_object_tagging(
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

pub(crate) async fn put_object_tagging_internal(
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
    let tags = match validate_tags(pairs, MAX_TAGS) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    set_object_tagging(state, bucket, key, tags, StatusCode::OK).await
}
