//! Object Lock on objects: retention, legal hold, what they refuse.

use super::*;

pub(crate) fn retention_mode_name(mode: RetentionMode) -> Option<&'static str> {
    match mode {
        RetentionMode::RetentionGovernance => Some("GOVERNANCE"),
        RetentionMode::RetentionCompliance => Some("COMPLIANCE"),
        RetentionMode::RetentionNone => None,
    }
}

/// A unix time as S3 writes dates in object-lock headers and bodies.
pub(crate) fn iso8601(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The bucket's object-lock configuration, if object lock is on for it.
pub(crate) async fn bucket_lock(
    meta_client: &mut MetadataServiceClient<Channel>,
    bucket: &str,
) -> Result<Option<ProtoObjectLockConfig>, Response> {
    bucket_lock_with(meta_client, bucket, None).await
}

/// [`bucket_lock`], with meta's answer already fetched (`pre`, from
/// `GetWriteContext`, B21) when given.
pub(crate) async fn bucket_lock_with(
    meta_client: &mut MetadataServiceClient<Channel>,
    bucket: &str,
    pre: Option<Result<objectio_proto::metadata::GetObjectLockConfigResponse, tonic::Status>>,
) -> Result<Option<ProtoObjectLockConfig>, Response> {
    let answer = match pre {
        Some(answer) => answer,
        None => meta_client
            .get_object_lock_configuration(GetObjectLockConfigRequest {
                bucket: bucket.to_string(),
            })
            .await
            .map(tonic::Response::into_inner),
    };
    match answer {
        Ok(inner) => Ok(inner.config.filter(|c| inner.found && c.enabled)),
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
pub(crate) fn lock_not_configured() -> Response {
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
pub(crate) async fn object_lock_for_write(
    meta_client: &mut MetadataServiceClient<Channel>,
    bucket: &str,
    headers: &HeaderMap,
    pre: Option<Result<objectio_proto::metadata::GetObjectLockConfigResponse, tonic::Status>>,
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

    let config = bucket_lock_with(meta_client, bucket, pre).await?;
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
pub(crate) async fn object_to_read(
    state: &AppState,
    nodes: &[objectio_proto::metadata::NodePlacement],
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    every_copy: bool,
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
        let read = if every_copy {
            crate::osd_pool::get_object_meta_every_copy(&state.osd_pool, nodes, bucket, key).await
        } else {
            get_object_meta_from_any(&state.osd_pool, nodes, bucket, key).await
        };
        return match read {
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

/// Why a lock forbids deleting `meta`, as the response to give.
pub(crate) fn lock_refusal(meta: &ObjectMeta, headers: &HeaderMap) -> Option<Response> {
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

#[derive(Deserialize)]
#[serde(rename = "Retention")]
pub(crate) struct RetentionRequest {
    #[serde(rename = "Mode")]
    pub(crate) mode: String,
    #[serde(rename = "RetainUntilDate")]
    pub(crate) retain_until_date: String,
}

#[derive(Serialize)]
#[serde(rename = "Retention")]
pub(crate) struct RetentionResponse {
    #[serde(rename = "Mode")]
    pub(crate) mode: String,
    #[serde(rename = "RetainUntilDate")]
    pub(crate) retain_until_date: String,
}

#[derive(Deserialize)]
#[serde(rename = "LegalHold")]
pub(crate) struct LegalHoldRequest {
    #[serde(rename = "Status")]
    pub(crate) status: String,
}

#[derive(Serialize)]
#[serde(rename = "LegalHold")]
pub(crate) struct LegalHoldResponse {
    #[serde(rename = "Status")]
    pub(crate) status: String,
}

pub(crate) async fn put_object_retention_internal(
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
            return S3Error::for_osd_error(&e, "Failed to read object metadata");
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
        return S3Error::for_osd_error(&e.error, "Failed to store object metadata");
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

pub(crate) async fn get_object_retention_internal(
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

pub(crate) async fn put_object_legal_hold_internal(
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
            return S3Error::for_osd_error(&e, "Failed to read object metadata");
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
        return S3Error::for_osd_error(&e.error, "Failed to store object metadata");
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

pub(crate) async fn get_object_legal_hold_internal(
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
