//! DELETE and DeleteObjects.

use super::*;

/// The query parameters each DELETE takes. Anything else named a
/// sub-resource the handlers don't delete, and fell through to deleting
/// the bucket or object itself: `DELETE /b?acl`, `?versioning`,
/// `?ownershipControls` deleted an empty bucket; `DELETE /b/k?retention`,
/// `?legal-hold` the object.
pub(crate) const BUCKET_DELETE_PARAMS: [&str; 8] = [
    "tagging",
    "replication",
    "policy",
    "lifecycle",
    "encryption",
    "publicAccessBlock",
    "cors",
    "x-id",
];

pub(crate) const OBJECT_DELETE_PARAMS: [&str; 4] = ["versionId", "uploadId", "tagging", "x-id"];

/// A DELETE naming something other than what a delete acts on: refused,
/// never read as "delete the bucket/object".
pub(crate) fn delete_refusal(path: &str, query: Option<&str>) -> Option<Response> {
    let query = query?;
    let trimmed = path.trim_start_matches('/');
    let object = trimmed
        .split_once('/')
        .is_some_and(|(_, key)| !key.is_empty());
    let allowed: &[&str] = if object {
        &OBJECT_DELETE_PARAMS
    } else {
        &BUCKET_DELETE_PARAMS
    };
    let other = query
        .split('&')
        .filter(|p| !p.is_empty())
        .find_map(|pair| {
            let name = pair.split('=').next().unwrap_or_default();
            // A presigned DELETE carries its signature in the query.
            let presign = name.len() > 6 && name[..6].eq_ignore_ascii_case("x-amz-");
            (!presign && !allowed.contains(&name)).then(|| name.to_string())
        })?;
    if !object && other == "ownershipControls" {
        return Some(S3Error::xml_response(
            "InvalidRequest",
            "Object ownership is BucketOwnerEnforced and can't be removed",
            StatusCode::BAD_REQUEST,
        ));
    }
    Some(S3Error::xml_response(
        "MethodNotAllowed",
        &format!("DELETE is not allowed on the {other} sub-resource"),
        StatusCode::METHOD_NOT_ALLOWED,
    ))
}

/// The newest version of `bucket/key` that is an object, not a delete
/// marker, from the first of `nodes` that answers.
pub(crate) async fn newest_object(
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
pub(crate) struct DeleteCondition {
    pub(crate) etag: Option<String>,
    pub(crate) modified: Option<String>,
    pub(crate) size: Option<String>,
}

impl DeleteCondition {
    pub(crate) fn from_headers(headers: &HeaderMap) -> Self {
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

    pub(crate) const fn is_set(&self) -> bool {
        self.etag.is_some() || self.modified.is_some() || self.size.is_some()
    }

    pub(crate) fn holds(&self, target: &ObjectMeta) -> bool {
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

/// DELETE `?versionId=`: remove that version for good. Each OSD replica,
/// under the key's lock, also makes the newest remaining version current if
/// this one was; the listing then follows whatever is current.
///
/// The version's shards are freed last, and only once every replica has
/// let go of it: one that hasn't may still have it current.
pub(crate) async fn delete_version(
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
            return S3Error::for_osd_error(&e, "Failed to read object metadata");
        }
    };

    let deleted = delete_meta_from_all(pool, nodes, bucket, key, vid).await;
    let (ok, of) = (deleted.ok, deleted.of);
    if ok < deleted.quorum {
        return S3Error::xml_response(
            "ServiceUnavailable",
            &format!("The delete reached {ok} of {of} metadata copies, not a quorum; retry"),
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
    } else {
        // What the replicas removed (a packing switch may have rewritten
        // the version since it was read), and only what none still has.
        for gone in unreferenced(pool, nodes, bucket, key, deleted.removed).await {
            let failed = reclaim_shards(
                pool,
                &mut state.meta_client.clone(),
                stripe_targets_of(&gone),
                Reclaim::Delete,
            )
            .await;
            if failed > 0 {
                warn!(
                    "{bucket}/{key} version {vid}: {failed} shard deletes failed; those blocks stay allocated"
                );
            }
        }
    }
    info!("Deleted version {vid} of {bucket}/{key}");
    done(version.is_delete_marker)
}

/// Bring Meta's listing of `bucket/key` in line with what its copies hold,
/// and return the current object as read (`None`: none, or unreadable).
///
/// A read that fails changes nothing: "unreadable" is not "deleted" (taken
/// as deleted, it dropped existing objects from listings). An update that
/// fails, as while meta elects a leader, is retried in the background and
/// then left to the heal queue, whose healing ends with this: a delete
/// that reached its quorum while meta was down left the key listed for
/// good (the B2 soak).
pub(crate) async fn sync_listing(
    state: &Arc<AppState>,
    nodes: &[objectio_proto::metadata::NodePlacement],
    bucket: &str,
    key: &str,
) -> Option<ObjectMeta> {
    match try_sync_listing(state, nodes, bucket, key).await {
        Ok(current) => current,
        Err(e) => {
            warn!("{bucket}/{key}: listing not updated yet ({e}); retrying in the background");
            let (state, nodes) = (Arc::clone(state), nodes.to_vec());
            let (bucket, key) = (bucket.to_string(), key.to_string());
            tokio::spawn(async move {
                let mut wait = std::time::Duration::from_millis(500);
                for _ in 0..7 {
                    tokio::time::sleep(wait).await;
                    if try_sync_listing(&state, &nodes, &bucket, &key)
                        .await
                        .is_ok()
                    {
                        return;
                    }
                    wait = (wait * 2).min(std::time::Duration::from_secs(16));
                }
                warn!("{bucket}/{key}: listing still not updated; left to the heal queue");
                state.osd_pool.queue_heal(&bucket, &key, "").await;
            });
            None
        }
    }
}

/// One attempt of [`sync_listing`]: the current object, once the listing
/// says the same (re-read after the update, in case a write raced it).
async fn try_sync_listing(
    state: &Arc<AppState>,
    nodes: &[objectio_proto::metadata::NodePlacement],
    bucket: &str,
    key: &str,
) -> Result<Option<ObjectMeta>, String> {
    use objectio_proto::metadata::DeleteObjectRequest as MetaDelReq;
    let mut meta_client = state.meta_client.clone();
    let read = |state: &Arc<AppState>| {
        let state = Arc::clone(state);
        async move {
            get_object_meta_from_any(&state.osd_pool, nodes, bucket, key)
                .await
                .map_err(|e| format!("reading its copies: {e}"))
        }
    };
    let mut current = read(state).await?;
    for _ in 0..3 {
        match &current {
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
        }
        .map_err(|e| format!("updating the listing: {e}"))?;
        let now = read(state).await?;
        let same = now.as_ref().map(|o| &o.object_id) == current.as_ref().map(|o| &o.object_id);
        current = now;
        if same {
            break;
        }
    }
    Ok(current)
}

/// For a sub-resource request (tagging, retention, legal hold) naming a
/// version: those act on the current version only, so refuse one naming
/// another rather than answer for the wrong version.
pub(crate) async fn unless_current(
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

/// Delete object (DELETE /{bucket}/{key})
///
/// Runs to the end even if the client hangs up. A delete is several steps —
/// the OSDs' metadata, the listing in meta, the shards — and a request
/// future dropped between them (a client timeout) left a key listed that
/// no longer existed, and a bucket that then couldn't be deleted.
pub async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    // Authorized by `authz::authz_layer` before this handler runs.
    auth: Option<Extension<AuthResult>>,
    version_id: Option<String>,
    headers: HeaderMap,
) -> Response {
    let task = tokio::spawn(delete_object_to_the_end(
        state, bucket, key, auth, version_id, headers,
    ));
    task.await.unwrap_or_else(|e| {
        error!("delete task failed: {e}");
        S3Error::xml_response(
            "InternalError",
            "the delete did not complete",
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    })
}

pub(crate) async fn delete_object_to_the_end(
    state: Arc<AppState>,
    bucket: String,
    key: String,
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
        // Not "deleted": nothing was. (A 204 here told clients the object
        // was gone while meta elected a leader; the B2 soak found it.)
        Err(e) => return S3Error::from_status(&e),
    };

    if placement.nodes.is_empty() {
        return S3Error::for_osd_error(
            &crate::osd_pool::OsdPoolError::NoNodesAvailable,
            "No OSDs to delete from",
        );
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
        // A condition that can't be checked is not met.
        let target = match &version_id {
            Some(vid) => match find_version(pool, nodes, &bucket, &key, vid).await {
                Ok(v) => v,
                Err(e) => return S3Error::for_osd_error(&e, "Failed to read object metadata"),
            },
            None => match get_object_meta_from_any(pool, nodes, &bucket, &key).await {
                Ok(Some(c)) if c.is_delete_marker => {
                    newest_object(pool, nodes, &bucket, &key).await
                }
                Ok(current) => current,
                Err(e) => return S3Error::for_osd_error(&e, "Failed to read object metadata"),
            },
        };
        if target.is_some_and(|t| !DeleteCondition::from_headers(&headers).holds(&t)) {
            return condition_refused("PreconditionFailed");
        }
    }

    // Lock enforcement: retention and legal hold protect the version a
    // delete would destroy. A versioned delete without a version destroys
    // nothing (it adds a marker), so S3 allows it.
    // A lock that can't be read protects what it may cover: no delete.
    let read = if let Some(vid) = &version_id {
        find_version(&state.osd_pool, &placement.nodes, &bucket, &key, vid).await
    } else if versioning_enabled {
        Ok(None)
    } else {
        get_object_meta_from_any(&state.osd_pool, &placement.nodes, &bucket, &key).await
    };
    let protected = match read {
        Ok(p) => p,
        Err(e) => return S3Error::for_osd_error(&e, "Failed to read object metadata"),
    };
    if let Some(meta) = protected
        && let Some(refusal) = lock_refusal(&meta, &headers)
    {
        return refusal;
    }

    // A delete marker another cluster replicates here, under its own
    // version id.
    if version_id.is_none()
        && let Some(resp) = crate::replication::replica_delete(
            &state,
            &_auth,
            &bucket,
            &key,
            &headers,
            versioning_enabled,
        )
        .await
    {
        return resp;
    }

    if versioning_enabled && version_id.is_none() {
        // Versioned delete without version_id: create a delete marker
        let marker_version_id = new_version_id();
        let mut delete_marker = ObjectMeta {
            bucket: bucket.clone(),
            key: key.clone(),
            object_id: Uuid::now_v7().as_bytes().to_vec(),
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
        // Replicated if a rule asks for delete markers: marked as it's
        // committed.
        crate::replication::mark(&state, &mut delete_marker).await;
        let marked = (!delete_marker.replication.is_empty()).then(|| delete_marker.clone());

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
            return S3Error::for_osd_error(&e.error, "Failed to store object metadata");
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

        if let Some(marker) = marked {
            crate::replication::enqueue(&state, &marker);
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

    // Suspended versioning, no version named: S3 puts a delete marker
    // whose version is "null" on top. It replaces the null version, if
    // that's what is current (its data then goes), and leaves older real
    // versions as they are. Removing the current entry instead hid the
    // object with no marker, and the version under it still listed as
    // latest.
    if versioning == Some(VersioningState::VersioningSuspended) && version_id.is_none() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let marker = ObjectMeta {
            bucket: bucket.clone(),
            key: key.clone(),
            object_id: Uuid::now_v7().as_bytes().to_vec(),
            created_at: now,
            modified_at: now,
            version_id: String::new(),
            is_delete_marker: true,
            ..Default::default()
        };
        let displaced = match put_object_meta_to_all(
            &state.osd_pool,
            &placement.nodes,
            &bucket,
            &key,
            marker,
            false,
            &[],
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to put the null delete marker: {}", e.error);
                return S3Error::for_osd_error(&e.error, "Failed to store object metadata");
            }
        };
        // A null version it replaced: its shards, once every replica agrees.
        spawn_reclaim(
            &state,
            crate::osd_pool::reclaimable_after_overwrite(
                &displaced,
                &std::collections::HashSet::new(),
            ),
            Reclaim::Overwrite,
            format!("{bucket}/{key} null version under a delete marker"),
        );
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
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("x-amz-version-id", "null")
            .header("x-amz-delete-marker", "true")
            .body(Body::empty())
            .unwrap();
    }

    if let Some(vid) = version_id {
        return delete_version(&state, &placement.nodes, &bucket, &key, &vid).await;
    }

    // Without a version: the current object goes. (With versioning on, a
    // marker was added above instead.)

    // Free what the delete actually removed, not what was read before it:
    // the object can change in between (a PUT replacing it, a packing
    // switch or a tagging update rewriting it), and freeing the stripes of
    // the version read would leak the ones the removed copy named. Only
    // once every replica has let it go, and only what no replica still has
    // as current: a racing write can leave it on some.
    let deleted = delete_meta_from_all(&state.osd_pool, &placement.nodes, &bucket, &key, "").await;
    if deleted.ok < deleted.quorum {
        sync_listing(&state, &placement.nodes, &bucket, &key).await;
        return S3Error::xml_response(
            "ServiceUnavailable",
            &format!(
                "The delete reached {} of {} metadata copies, not a quorum; retry",
                deleted.ok, deleted.of
            ),
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    if deleted.ok < deleted.of {
        warn!(
            "{bucket}/{key}: {} of {} replicas deleted it; its blocks stay allocated",
            deleted.ok, deleted.of
        );
    } else {
        for gone in unreferenced(
            &state.osd_pool,
            &placement.nodes,
            &bucket,
            &key,
            deleted.removed,
        )
        .await
        {
            let failed = reclaim_shards(
                &state.osd_pool,
                &mut meta_client,
                stripe_targets_of(&gone),
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

/// How many keys of one DeleteObjects request are deleted at once.
pub(crate) const DELETE_OBJECTS_CONCURRENCY: usize = 16;

/// One key of a DeleteObjects request: authorized, then deleted through the
/// single-object DELETE.
pub(crate) async fn delete_one(
    state: &Arc<AppState>,
    auth: Option<&Extension<AuthResult>>,
    bucket: &str,
    headers: &HeaderMap,
    obj: DeleteObjectIdentifier,
) -> Result<DeletedObject, DeleteError> {
    // Batch delete reports per-key outcomes inside a 200 response, so
    // each key is evaluated here instead of by the middleware, which
    // classifies this route as `DeferToHandler`.
    if let Some(Extension(auth_result)) = auth
        && crate::authz::authorize(
            state,
            auth_result,
            &crate::authz::AuthzRequest {
                method: &Method::DELETE,
                action: "s3:DeleteObject",
                bucket,
                key: Some(&obj.key),
                scope_key: &obj.key,
                headers: None,
            },
        )
        .await
        .is_some()
    {
        return Err(DeleteError {
            key: obj.key,
            version_id: obj.version_id,
            code: "AccessDenied".to_string(),
            message: "Access Denied".to_string(),
        });
    }

    // Each key goes through the single-object DELETE, so a batch gets
    // the same versioning, object-lock and listing handling, and frees
    // the shards.
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
        State(Arc::clone(state)),
        Path((bucket.to_string(), obj.key.clone())),
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
        Ok(DeletedObject {
            key: obj.key,
            // A version deleted by id is named; a marker just added is
            // named as the marker.
            version_id: obj.version_id,
            delete_marker,
            delete_marker_version_id: if delete_marker { header_version } else { None },
        })
    } else {
        let code = resp
            .extensions()
            .get::<crate::gateway_metrics::S3ErrorCode>()
            .map_or_else(|| "InternalError".to_string(), |c| c.0.clone());
        Err(DeleteError {
            key: obj.key,
            version_id: obj.version_id,
            message: code.clone(),
            code,
        })
    }
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

    // Keys are deleted concurrently, a bounded number at a time; one key
    // named more than once is deleted in request order (its entries run in
    // one task). Outcomes are reported in request order.
    use futures::StreamExt;
    let quiet = delete_request.quiet;
    let mut by_key: Vec<Vec<(usize, DeleteObjectIdentifier)>> = Vec::new();
    let mut slot: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, obj) in delete_request.objects.into_iter().enumerate() {
        let g = *slot.entry(obj.key.clone()).or_insert_with(|| {
            by_key.push(Vec::new());
            by_key.len() - 1
        });
        by_key[g].push((i, obj));
    }
    let mut outcomes: Vec<(usize, Result<DeletedObject, DeleteError>)> =
        futures::stream::iter(by_key.into_iter().map(|entries| {
            let (state, auth, bucket, headers) = (&state, &auth, &bucket, &headers);
            async move {
                let mut out = Vec::with_capacity(entries.len());
                for (i, obj) in entries {
                    out.push((
                        i,
                        delete_one(state, auth.as_ref(), bucket, headers, obj).await,
                    ));
                }
                out
            }
        }))
        .buffer_unordered(DELETE_OBJECTS_CONCURRENCY)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .flatten()
        .collect();
    outcomes.sort_unstable_by_key(|(i, _)| *i);
    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for (_, outcome) in outcomes {
        match outcome {
            Ok(d) => deleted.push(d),
            Err(e) => errors.push(e),
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
