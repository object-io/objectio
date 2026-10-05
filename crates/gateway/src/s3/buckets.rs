//! Buckets: create, delete, list, head, policy, versioning, Object Lock configuration.

use super::*;

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

    // Least privilege: a user lists the buckets it owns; a tenant's admins
    // list the tenant's; the system admin lists all. Every user used to
    // see every bucket of its tenant (and, in system scope, of all
    // tenants), whether or not it could touch them.
    let owner = match auth.as_ref() {
        Some(Extension(a)) if a.user_arn != crate::admin::SYSTEM_ADMIN_USER_ARN => {
            let tenant_admin = !a.tenant.is_empty()
                && client
                    .get_tenant(objectio_proto::metadata::GetTenantRequest {
                        name: a.tenant.clone(),
                    })
                    .await
                    .ok()
                    .and_then(|r| r.into_inner().tenant)
                    .is_some_and(|t| {
                        t.admin_users
                            .iter()
                            .any(|u| u == &a.user_id || u == &a.user_arn)
                    });
            if tenant_admin {
                String::new()
            } else {
                a.user_id.clone()
            }
        }
        _ => String::new(),
    };
    match client
        .list_buckets(ListBucketsRequest { owner, tenant })
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
            S3Error::from_status(&e)
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
        return set_bucket_tagging(&state, &bucket, Some(&body)).await;
    }
    if params.acl.is_some() {
        return put_acl(&state, &bucket, None, &headers, &body).await;
    }
    if params.ownership_controls.is_some() {
        return put_ownership_controls(&state, &bucket, &body).await;
    }
    if params.public_access_block.is_some() {
        return crate::public_access::put_bucket(&state, &bucket, &body).await;
    }
    if params.cors.is_some() {
        return crate::cors::put_bucket(&state, &bucket, &headers, &body).await;
    }
    if params.replication.is_some() {
        return crate::replication::put_config(&state, &bucket, &body).await;
    }
    if params.logging.is_some() {
        return crate::bucket_logging::put_config(
            &state,
            &bucket,
            auth.as_ref().map(|Extension(a)| a),
            &body,
        )
        .await;
    }
    // Ownership other than BucketOwnerEnforced can't be honoured (ACLs are
    // off): refused, as PutBucketOwnershipControls refuses it, rather than
    // a bucket created that quietly behaves otherwise.
    if headers
        .get("x-amz-object-ownership")
        .is_some_and(|v| v.as_bytes() != b"BucketOwnerEnforced")
    {
        return S3Error::xml_response(
            "InvalidRequest",
            "Only BucketOwnerEnforced object ownership is supported: ACLs are disabled",
            StatusCode::BAD_REQUEST,
        );
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
        return crate::lifecycle::put_config(&state, &bucket, &body).await;
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
            settings: crate::public_access::initial_settings(&state).await,
            // The pool its data goes to; meta checks the tenant may use it.
            pool: headers
                .get("x-objectio-pool")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string(),
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
            } else if e.code() == tonic::Code::PermissionDenied {
                S3Error::xml_response("AccessDenied", e.message(), StatusCode::FORBIDDEN)
            } else if matches!(
                e.code(),
                tonic::Code::NotFound | tonic::Code::FailedPrecondition
            ) {
                // A pool that doesn't exist or is disabled.
                S3Error::xml_response("InvalidArgument", e.message(), StatusCode::BAD_REQUEST)
            } else if e.code() == tonic::Code::ResourceExhausted {
                S3Error::xml_response("TooManyBuckets", e.message(), StatusCode::BAD_REQUEST)
            } else {
                error!("Failed to create bucket: {}", e);
                S3Error::from_status(&e)
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
        return set_bucket_tagging(&state, &bucket, None).await;
    }
    if params.policy.is_some() {
        return delete_bucket_policy_internal(state, bucket).await;
    }
    if params.lifecycle.is_some() {
        return crate::lifecycle::delete_config(&state, &bucket).await;
    }
    if params.encryption.is_some() {
        return delete_bucket_encryption_internal(state, bucket).await;
    }
    if params.public_access_block.is_some() {
        return crate::public_access::delete_bucket(&state, &bucket).await;
    }
    if params.cors.is_some() {
        return crate::cors::delete_bucket(&state, &bucket).await;
    }
    if params.replication.is_some() {
        return crate::replication::delete_config(&state, &bucket).await;
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
                S3Error::from_status(&e)
            }
        }
    }
}

/// Whether any OSD holds a version or delete marker in `bucket`. Every
/// OSD in the listing must answer: one that can't might hold the only one.
pub(crate) async fn holds_versions(state: &AppState, bucket: &str) -> Result<bool, Response> {
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

/// The bucket's versioning state, or the response to give: NoSuchBucket,
/// or 503 when it can't be read. Never a guess: taking "unversioned" for
/// a versioned bucket frees the version a write replaces.
pub(crate) async fn bucket_versioning(
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

/// Get bucket policy (GET /{bucket}?policy) - internal implementation
pub(crate) async fn get_bucket_policy_internal(state: Arc<AppState>, bucket: String) -> Response {
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
                S3Error::from_status(&e)
            }
        }
    }
}

/// Set bucket policy (PUT /{bucket}?policy) - internal implementation
pub(crate) async fn put_bucket_policy_internal(
    state: Arc<AppState>,
    bucket: String,
    body: Bytes,
) -> Response {
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
    let parsed = match BucketPolicy::from_json(&policy_json) {
        Ok(p) => p,
        Err(e) => {
            return S3Error::xml_response(
                "MalformedPolicy",
                &format!("The policy is not a valid bucket policy: {e}"),
                StatusCode::BAD_REQUEST,
            );
        }
    };
    if crate::public_access::refuses_policy(&state, &bucket, &parsed).await {
        return S3Error::xml_response(
            "AccessDenied",
            "The bucket policy would make the bucket public, and public access is blocked",
            StatusCode::FORBIDDEN,
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
                S3Error::from_status(&e)
            }
        }
    }
}

/// Delete bucket policy (DELETE /{bucket}?policy) - internal implementation
pub(crate) async fn delete_bucket_policy_internal(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
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
                S3Error::from_status(&e)
            }
        }
    }
}

/// XML request for PUT bucket versioning
#[derive(Deserialize)]
#[serde(rename = "VersioningConfiguration")]
pub(crate) struct VersioningConfigurationRequest {
    #[serde(rename = "Status")]
    pub(crate) status: String,
}

/// XML response for GET bucket versioning
#[derive(Serialize)]
#[serde(rename = "VersioningConfiguration")]
pub(crate) struct VersioningConfigurationResponse {
    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<String>,
}

pub(crate) async fn put_bucket_versioning_internal(
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
            S3Error::from_status(&e)
        }
    }
}

pub(crate) async fn get_bucket_versioning_internal(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
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
            S3Error::from_status(&e)
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "ObjectLockConfiguration")]
pub(crate) struct ObjectLockConfigRequest {
    #[serde(rename = "ObjectLockEnabled")]
    #[serde(default)]
    pub(crate) object_lock_enabled: Option<String>,
    #[serde(rename = "Rule")]
    #[serde(default)]
    pub(crate) rule: Option<ObjectLockRuleXml>,
}

#[derive(Deserialize)]
pub(crate) struct ObjectLockRuleXml {
    #[serde(rename = "DefaultRetention")]
    #[serde(default)]
    pub(crate) default_retention: Option<DefaultRetentionXml>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct DefaultRetentionXml {
    #[serde(rename = "Mode")]
    pub(crate) mode: String,
    #[serde(rename = "Days")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub(crate) days: Option<i64>,
    #[serde(rename = "Years")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub(crate) years: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename = "ObjectLockConfiguration")]
pub(crate) struct ObjectLockConfigResponse {
    #[serde(rename = "ObjectLockEnabled")]
    pub(crate) object_lock_enabled: String,
    #[serde(rename = "Rule")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rule: Option<ObjectLockRuleResponseXml>,
}

#[derive(Serialize)]
pub(crate) struct ObjectLockRuleResponseXml {
    #[serde(rename = "DefaultRetention")]
    pub(crate) default_retention: DefaultRetentionXml,
}

pub(crate) async fn put_object_lock_config_internal(
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
            S3Error::from_status(&e)
        }
    }
}

pub(crate) async fn get_object_lock_config_internal(
    state: Arc<AppState>,
    bucket: String,
) -> Response {
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
            S3Error::from_status(&e)
        }
    }
}
