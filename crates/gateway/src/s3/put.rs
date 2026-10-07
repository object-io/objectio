//! PUT: writing an object and committing it.

use super::*;

/// Whether a header is part of what an object carries -- what a copy keeps
/// from its source, or takes from the request under REPLACE.
pub(crate) fn is_object_metadata_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("x-amz-meta-")
        || matches!(
            lower.as_str(),
            "content-type"
                | "content-encoding"
                | "content-disposition"
                | "content-language"
                | "cache-control"
                | "expires"
        )
}

/// Hand a body just written to `bucket` to the dedup dry-run, when the
/// bucket's policy asks for one. Encrypted bodies never deduplicate (their
/// ciphertext differs per object by design), and inline-sized ones are not
/// what dedup is for; both are counted as skipped.
pub(crate) fn dedup_dry_run(
    state: &AppState,
    bucket: &str,
    placement: &objectio_proto::metadata::GetPlacementResponse,
    body: &Bytes,
    encrypted: bool,
) {
    use objectio_proto::metadata::DedupMode;
    if !matches!(placement.dedup_mode(), DedupMode::DryRun | DedupMode::On) || body.is_empty() {
        return;
    }
    if encrypted {
        crate::gateway_metrics::record_dedup_skipped("encrypted");
    } else if body.len() <= state.inline_max_size {
        crate::gateway_metrics::record_dedup_skipped("inline");
    } else {
        state
            .dedup
            .submit(bucket, &placement.dedup_domain, body.clone());
    }
}

/// How a PUT's two commits ended, when the one that decides it succeeded.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Committed<E> {
    /// Readable by key and listed.
    Both,
    /// Readable by key, but not in `ListObjects` until repair: the listing
    /// commit failed with this.
    Unlisted(E),
}

/// Run a PUT's two commits at the same time: the object's ObjectMeta on the
/// OSDs (what GET reads) and its entry in Meta's Raft listing index (what
/// `ListObjects` reads). Neither needs the other.
///
/// The ObjectMeta commit decides the outcome. If it fails the PUT fails, and
/// a listing entry that did land is taken out again with `unlist`, so the
/// listing never shows an object GET cannot read. A failed listing commit
/// alone does not fail the PUT: the data landed and is readable by key.
pub(crate) async fn commit_object<T, ME, LE, U>(
    object_meta: impl Future<Output = Result<T, ME>>,
    listing: impl Future<Output = Result<(), LE>>,
    unlist: impl FnOnce() -> U,
) -> Result<(T, Committed<LE>), ME>
where
    U: Future<Output = ()>,
{
    match tokio::join!(object_meta, listing) {
        (Ok(t), Ok(())) => Ok((t, Committed::Both)),
        (Ok(t), Err(e)) => Ok((t, Committed::Unlisted(e))),
        (Err(e), listed) => {
            if listed.is_ok() {
                unlist().await;
            }
            Err(e)
        }
    }
}

/// What a PUT's `If-Match` / `If-None-Match` ask: "*" or an ETag each.
#[derive(Default)]
pub(crate) struct PutCondition {
    pub(crate) if_match: Option<String>,
    pub(crate) if_none_match: Option<String>,
}

impl PutCondition {
    pub(crate) fn from_headers(headers: &HeaderMap) -> Self {
        let get = |name: header::HeaderName| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_string())
        };
        Self {
            if_match: get(header::IF_MATCH),
            if_none_match: get(header::IF_NONE_MATCH),
        }
    }

    pub(crate) const fn is_set(&self) -> bool {
        self.if_match.is_some() || self.if_none_match.is_some()
    }

    /// The refusal, if `current` (the key's object, if any) fails it.
    pub(crate) fn refuse(&self, current: Option<&ObjectMeta>) -> Option<Response> {
        let matches = |want: &str| {
            current
                .is_some_and(|o| want == "*" || o.etag.trim_matches('"') == want.trim_matches('"'))
        };
        if self.if_match.is_some() && current.is_none() {
            return Some(condition_refused("NoSuchKey"));
        }
        if self.if_match.as_deref().is_some_and(|m| !matches(m))
            || self.if_none_match.as_deref().is_some_and(matches)
        {
            return Some(condition_refused("PreconditionFailed"));
        }
        None
    }
}

pub(crate) fn condition_refused(code: &str) -> Response {
    if code == "NoSuchKey" {
        S3Error::xml_response(
            "NoSuchKey",
            "The specified key does not exist.",
            StatusCode::NOT_FOUND,
        )
    } else {
        S3Error::xml_response(
            "PreconditionFailed",
            "At least one of the pre-conditions you specified did not hold",
            StatusCode::PRECONDITION_FAILED,
        )
    }
}

/// Make `object_meta` the key's current object: its listing entry in meta
/// and its ObjectMeta on every OSD of the placement. `sent` are the shards
/// already written for it, freed if the commit is refused.
///
/// Unconditional, the two commits run together (see `commit_object`). A
/// conditional PUT commits the listing first: meta decides the condition
/// there, in one Raft write, so two racing conditional writers can't both
/// win, or win on different replicas.
pub(crate) async fn commit_put(
    state: &Arc<AppState>,
    placement: &objectio_proto::metadata::GetPlacementResponse,
    object_meta: ObjectMeta,
    versioning_enabled: bool,
    sent: Vec<ShardTarget>,
    condition: &PutCondition,
    small: Option<&SmallShards>,
) -> Result<(), Response> {
    commit_put_outcome(
        state,
        placement,
        object_meta,
        versioning_enabled,
        sent,
        condition,
        small,
    )
    .await
    .map_err(|refused| refused.response)
}

/// A commit that didn't succeed: the answer for the client, and whether the
/// object is certainly not stored (no copy took it) rather than maybe.
pub(crate) struct CommitRefused {
    pub(crate) response: Response,
    pub(crate) not_stored: bool,
}

/// [`commit_put`], saying on a failure whether the object may still have
/// been stored: a multipart completion keeps its upload for a retry then.
pub(crate) async fn commit_put_outcome(
    state: &Arc<AppState>,
    placement: &objectio_proto::metadata::GetPlacementResponse,
    mut object_meta: ObjectMeta,
    versioning_enabled: bool,
    sent: Vec<ShardTarget>,
    condition: &PutCondition,
    small: Option<&SmallShards>,
) -> Result<(), CommitRefused> {
    if !object_meta.replica_of.is_empty() {
        return commit_replica(state, placement, object_meta, sent, small).await;
    }
    // Marked for replication in the same write that commits it: a version
    // is never committed and then forgotten.
    crate::replication::mark(state, &mut object_meta).await;
    let marked = (!object_meta.replication.is_empty()).then(|| object_meta.clone());
    commit_new(
        state,
        placement,
        object_meta,
        versioning_enabled,
        sent,
        condition,
        small,
    )
    .await?;
    if let Some(object) = marked {
        crate::replication::enqueue(state, &object);
    }
    Ok(())
}

/// Commit a replica another cluster sent: under its source's version id,
/// made current only if no newer version is (versions can arrive in any
/// order), and listed as whatever is current then. A replica displaces
/// nothing: the bucket is versioned, so what was current stays a version.
pub(crate) async fn commit_replica(
    state: &Arc<AppState>,
    placement: &objectio_proto::metadata::GetPlacementResponse,
    object_meta: ObjectMeta,
    sent: Vec<ShardTarget>,
    small: Option<&SmallShards>,
) -> Result<(), CommitRefused> {
    let (bucket, key) = (object_meta.bucket.clone(), object_meta.key.clone());
    let written = crate::osd_pool::put_object_meta_with(
        &state.osd_pool,
        &placement.nodes,
        &bucket,
        &key,
        object_meta,
        crate::osd_pool::MetaWrite {
            versioning_enabled: true,
            keep_newer_current: true,
            // A small replica's shards go with its metadata too (B21).
            small_shards: small.map(|s| &s.shards),
            min_copies: small.map_or(0, |s| s.quorum),
            ..Default::default()
        },
    )
    .await;
    sync_listing(state, &placement.nodes, &bucket, &key).await;
    match written {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.unapplied {
                spawn_reclaim(state, sent, Reclaim::FailedWrite, format!("{bucket}/{key}"));
            }
            Err(CommitRefused {
                response: S3Error::xml_response(
                    "ServiceUnavailable",
                    &format!("storing the replica: {}", e.error),
                    StatusCode::SERVICE_UNAVAILABLE,
                ),
                not_stored: e.unapplied,
            })
        }
    }
}

/// How long a conditional commit whose answer is lost is sent again.
const CONDITIONAL_SETTLE: std::time::Duration = std::time::Duration::from_secs(20);

/// Whether a failed call to meta may have been applied: its answer lost to
/// a leader change, a timeout or a dropped connection, not a refusal.
const fn is_ambiguous(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::Unavailable
            | tonic::Code::DeadlineExceeded
            | tonic::Code::Unknown
            | tonic::Code::Cancelled
            | tonic::Code::Internal
    )
}

/// Commit a conditional PUT's listing entry: meta decides the condition.
/// An answer lost (the write applied or not) is sent again until meta
/// decides. Meta takes the same write sent twice as applied once (it knows
/// its entry by object id); refused by its own entry, the PUT failed, freed
/// its shards and left the listing naming an object no GET finds, refusing
/// every If-None-Match after.
async fn create_conditional(
    state: &Arc<AppState>,
    req: objectio_proto::metadata::CreateObjectRequest,
) -> Result<(), tonic::Status> {
    let deadline = std::time::Instant::now() + CONDITIONAL_SETTLE;
    let mut wait = std::time::Duration::from_millis(250);
    let mut answer = crate::test_hooks::maybe_lost(
        "create_object",
        state.meta_client.clone().create_object(req.clone()).await,
    );
    loop {
        match answer {
            Ok(_) => return Ok(()),
            Err(s) if is_ambiguous(s.code()) && std::time::Instant::now() < deadline => {
                debug!(
                    "{}/{}: conditional commit undecided ({s}); sending it again",
                    req.bucket, req.key
                );
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(std::time::Duration::from_secs(4));
            }
            Err(s) => return Err(s),
        }
        answer = state.meta_client.clone().create_object(req.clone()).await;
    }
}

/// [`commit_put`] for a version written here.
pub(crate) async fn commit_new(
    state: &Arc<AppState>,
    placement: &objectio_proto::metadata::GetPlacementResponse,
    object_meta: ObjectMeta,
    versioning_enabled: bool,
    sent: Vec<ShardTarget>,
    condition: &PutCondition,
    small: Option<&SmallShards>,
) -> Result<(), CommitRefused> {
    // Small shards travel with the metadata (B21): each copy is a shard
    // too, so the write needs the shard quorum (k + 1) as well.
    let write = crate::osd_pool::MetaWrite {
        versioning_enabled,
        small_shards: small.map(|s| &s.shards),
        min_copies: small.map_or(0, |s| s.quorum),
        ..Default::default()
    };
    let (bucket, key) = (object_meta.bucket.clone(), object_meta.key.clone());
    let what = format!("{bucket}/{key}");
    let nodes = &placement.nodes;
    let listing_req = objectio_proto::metadata::CreateObjectRequest {
        bucket: bucket.clone(),
        key: key.clone(),
        size: object_meta.size,
        content_type: object_meta.content_type.clone(),
        etag: object_meta.etag.clone(),
        user_metadata: object_meta.user_metadata.clone(),
        stripes: object_meta.stripes.clone(),
        object_id: object_meta.object_id.clone(),
        pg_id: placement.pg_id,
        pool: placement.pool.clone(),
        home_osd_ids: home_of(nodes),
        if_match: condition.if_match.clone().unwrap_or_default(),
        if_none_match: condition.if_none_match.clone().unwrap_or_default(),
    };
    let new_object = referenced_object_ids(&object_meta);
    let failed = |e: &crate::osd_pool::MetaWriteError| {
        error!("Failed to store object metadata on OSDs: {e}");
        CommitRefused {
            response: S3Error::for_osd_error(&e.error, "Failed to store object metadata"),
            not_stored: e.unapplied,
        }
    };

    if condition.is_set() {
        if let Err(s) = create_conditional(state, listing_req).await {
            if is_ambiguous(s.code()) {
                // Meta may have taken it, its answer lost every time: the
                // listing may name an object no copy holds. Healing puts
                // the listing back to what the copies hold; the shards stay
                // (a leak) rather than be freed under a listed object.
                warn!(
                    "{what}: conditional commit undecided ({s}); keeping its shards, healing the key"
                );
                state.osd_pool.queue_heal(&bucket, &key, "").await;
                // Maybe stored: meta may hold the entry. A multipart
                // completion stays being completed, and sent again commits
                // the same object, which meta then takes as applied.
                return Err(CommitRefused {
                    response: S3Error::xml_response(
                        "ServiceUnavailable",
                        &format!("could not commit the object: {}", s.message()),
                        StatusCode::SERVICE_UNAVAILABLE,
                    ),
                    not_stored: false,
                });
            }
            spawn_reclaim(state, sent, Reclaim::FailedWrite, what);
            // Refused before any copy was written: certainly not stored.
            return Err(CommitRefused {
                response: match s.code() {
                    tonic::Code::FailedPrecondition => condition_refused(s.message()),
                    tonic::Code::NotFound => S3Error::xml_response(
                        "NoSuchBucket",
                        "The specified bucket does not exist",
                        StatusCode::NOT_FOUND,
                    ),
                    _ => S3Error::xml_response(
                        "ServiceUnavailable",
                        &format!("could not commit the object: {}", s.message()),
                        StatusCode::SERVICE_UNAVAILABLE,
                    ),
                },
                not_stored: true,
            });
        }
        let outcome = crate::osd_pool::put_object_meta_with(
            &state.osd_pool,
            nodes,
            &bucket,
            &key,
            object_meta,
            write,
        )
        .await;
        settle_commit(
            state,
            outcome.as_deref(),
            sent,
            &new_object,
            versioning_enabled,
            &what,
        );
        if let Err(e) = outcome {
            sync_listing(state, nodes, &bucket, &key).await;
            return Err(failed(&e));
        }
        return Ok(());
    }

    let mut listing_client = state.meta_client.clone();
    let committed = commit_object(
        crate::osd_pool::put_object_meta_with(
            &state.osd_pool,
            nodes,
            &bucket,
            &key,
            object_meta,
            write,
        ),
        async { listing_client.create_object(listing_req).await.map(drop) },
        // The listing follows whatever is current on the OSDs: the object
        // this write would have replaced, if any. Unlisting it, as this
        // did, hid an object a failed overwrite left in place.
        || async {
            sync_listing(state, nodes, &bucket, &key).await;
        },
    )
    .await;
    settle_commit(
        state,
        committed.as_ref().map(|(d, _)| d.as_slice()),
        sent,
        &new_object,
        versioning_enabled,
        &what,
    );
    match committed {
        Ok((_, Committed::Both)) => Ok(()),
        Ok((_, Committed::Unlisted(e))) => {
            // Stored and acknowledged; the listing follows (retried, then
            // healed), not left to an hourly repair pass.
            warn!("create_object on meta failed ({e}); listing {what} again");
            sync_listing(state, nodes, &bucket, &key).await;
            Ok(())
        }
        Err(e) => Err(failed(&e)),
    }
}

/// Check an upload's body against the `Content-MD5` and `x-amz-checksum-*`
/// the request carries, refusing it as S3 does on a mismatch or a malformed
/// header.
///
/// Returns the checksums read, and the body's MD5 when `Content-MD5` made us
/// compute it. A request carrying neither costs nothing here.
pub(crate) async fn verify_upload_checksums(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(crate::checksum::RequestChecksums, Option<[u8; 16]>), Response> {
    let refused = |e: &crate::checksum::ChecksumError| {
        S3Error::xml_response(e.code(), &e.message(), StatusCode::BAD_REQUEST)
    };
    let checksums =
        crate::checksum::RequestChecksums::from_headers(headers).map_err(|e| refused(&e))?;
    if checksums.is_empty() {
        return Ok((checksums, None));
    }
    // Hashing a large body is CPU-bound; keep it off the async workers.
    let task = {
        let checksums = checksums.clone();
        let body = body.clone();
        tokio::task::spawn_blocking(move || checksums.verify(&body))
    };
    match task.await {
        Ok(Ok(md5)) => Ok((checksums, md5)),
        Ok(Err(e)) => Err(refused(&e)),
        Err(e) => {
            error!("checksum computation failed: {e}");
            Err(S3Error::xml_response(
                "InternalError",
                "Checksum computation failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

/// Free `targets` off the request's critical path, logging what could not
/// be freed. `what` names the object or upload for the log.
pub(crate) fn spawn_reclaim(
    state: &Arc<AppState>,
    targets: Vec<ShardTarget>,
    reason: Reclaim,
    what: String,
) {
    if targets.is_empty() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        warn!(
            "{what}: no runtime to free {} shards ({}); they stay allocated",
            targets.len(),
            reason.label()
        );
        return;
    };
    let state = Arc::clone(state);
    runtime.spawn(async move {
        let total = targets.len();
        let mut meta = state.meta_client.clone();
        let failed = reclaim_shards(&state.osd_pool, &mut meta, targets, reason).await;
        if failed > 0 {
            warn!(
                "{what}: {failed} of {total} shard deletes failed ({}); those blocks stay allocated",
                reason.label()
            );
        } else {
            debug!("{what}: freed {total} shards ({})", reason.label());
        }
    });
}

/// The shards a write is about to send, freed if it is abandoned before
/// its metadata commit.
pub(crate) fn pending_shards(state: &Arc<AppState>, what: String) -> PendingShards {
    let state = Arc::clone(state);
    PendingShards::new(move |targets| spawn_reclaim(&state, targets, Reclaim::FailedWrite, what))
}

/// Free what a metadata commit left unreferenced. On success, the object it
/// replaced — unless versioning keeps that as a version. On a failure no
/// replica applied, `sent`: the shards the new object would have used.
pub(crate) fn settle_commit(
    state: &Arc<AppState>,
    outcome: Result<&[Displaced], &MetaWriteError>,
    sent: Vec<ShardTarget>,
    new_object: &std::collections::HashSet<Vec<u8>>,
    versioning_enabled: bool,
    what: &str,
) {
    match outcome {
        // Every copy already held a newer write of the key (last writer
        // wins): nothing references this one's shards.
        Ok(displaced) if !displaced.is_empty() && displaced.iter().all(|d| d.superseded) => {
            spawn_reclaim(state, sent, Reclaim::FailedWrite, what.to_string());
        }
        Ok(displaced) if !versioning_enabled => spawn_reclaim(
            state,
            reclaimable_after_overwrite(displaced, new_object),
            Reclaim::Overwrite,
            what.to_string(),
        ),
        Ok(_) => {}
        Err(e) if e.unapplied => {
            spawn_reclaim(state, sent, Reclaim::FailedWrite, what.to_string());
        }
        // A refused small write some copies didn't answer the withdrawal
        // of: its shards go once they have.
        Err(MetaWriteError {
            withdrawing: Some(w),
            ..
        }) => {
            let (state, w, what) = (Arc::clone(state), w.clone(), what.to_string());
            tokio::spawn(async move {
                if crate::osd_pool::withdraw_later(&state.osd_pool, w).await {
                    spawn_reclaim(&state, sent, Reclaim::FailedWrite, what);
                }
            });
        }
        Err(_) if !sent.is_empty() => warn!(
            "{what}: {} shards stay allocated: a replica may hold the failed write's metadata",
            sent.len()
        ),
        Err(_) => {}
    }
}

pub async fn put_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Refused before anything is stored.
    let tags = match tagging_header(&headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    // Check for copy source header (CopyObject operation)
    let (copy_source, copy_source_version) = copy_source_of(&headers).unzip();
    let copy_source_version = copy_source_version.flatten();

    // CopyObject: the source is read and written again as the destination
    // (copy_object_data). SSE-C on either side is deliberately unsupported
    // (requires a separate set of copy-source-* customer-key headers that we
    // don't wire through yet).
    if let Some(ref source) = copy_source {
        // Parse source bucket/key (format: "bucket/key" or "/bucket/key")
        let parts: Vec<&str> = source.splitn(2, '/').collect();
        if parts.len() != 2 {
            return S3Error::xml_response(
                "InvalidArgument",
                "Invalid x-amz-copy-source format",
                StatusCode::BAD_REQUEST,
            );
        }
        let source_bucket = parts[0];
        let source_key = parts[1];

        // A copy onto itself must change something, or it is refused, as S3
        // refuses it: metadata or tags replaced, encryption or storage class.
        let replaces = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("REPLACE"))
        };
        if source_bucket == bucket
            && source_key == key
            && copy_source_version.is_none()
            && !replaces("x-amz-metadata-directive")
            && !replaces("x-amz-tagging-directive")
            && !headers.contains_key("x-amz-storage-class")
            && !headers
                .keys()
                .any(|k| k.as_str().starts_with("x-amz-server-side-encryption"))
        {
            return S3Error::xml_response(
                "InvalidRequest",
                "This copy request is illegal because it is trying to copy an object to itself \
                 without changing the object's metadata, storage class, website redirect \
                 location or encryption attributes.",
                StatusCode::BAD_REQUEST,
            );
        }

        // CopyObject reads the source as well as writing the destination.
        // The middleware authorized the destination; the source is a
        // different bucket/key and is checked here.
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

        // SSE-C on either side is refused; a missing source is NoSuchKey.
        if let Err(resp) = check_copy_sse(
            &state,
            &mut meta_client,
            source_bucket,
            source_key,
            copy_source_version.as_deref(),
            &bucket,
            &headers,
        )
        .await
        {
            return resp;
        }

        // Box-pin to break the `put_object ↔ copy_object_data` async
        // recursion: the copy writes through this handler.
        return Box::pin(copy_object_data(
            state.clone(),
            bucket.clone(),
            key.clone(),
            CopySource {
                bucket: source_bucket.to_string(),
                key: source_key.to_string(),
                version: copy_source_version.clone(),
            },
            auth.clone(),
            headers.clone(),
        ))
        .await;
    }

    debug!(
        "PUT object: {}/{}, size={}, ec={}+{}",
        bucket,
        key,
        body.len(),
        state.ec_k,
        state.ec_m,
    );

    let mut meta_client = state.meta_client.clone();

    // Generate object ID and ETag (MD5 of the *plaintext* body — matches AWS
    // SSE-S3/SSE-KMS ETag semantics; taken before we possibly encrypt).
    //
    // Nothing needs the ETag until the object's metadata is built, so it is
    // computed on a blocking thread while the body is encrypted, erasure-coded
    // and written, instead of in front of all of that. The `etag` phase is the
    // time still spent waiting for it afterwards.
    let mut phases = crate::gateway_metrics::PhaseTimer::start("PutObject");
    let object_id = *Uuid::now_v7().as_bytes();

    // A body that does not match the checksum the client sent is refused
    // here, before any shard is written or metadata committed, so a mismatch
    // stores nothing.
    let (checksums, verified_md5) = match verify_upload_checksums(&headers, &body).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if !checksums.is_empty() {
        phases.mark("checksum");
    }

    let etag_task = match verified_md5 {
        // Content-MD5 was checked, so the ETag's MD5 is already known: hand
        // it back through a task that is already done instead of hashing the
        // body a second time.
        Some(md5) => tokio::spawn(async move { format!("\"{}\"", hex::encode(md5)) }),
        None => {
            let body = body.clone();
            tokio::task::spawn_blocking(move || format!("\"{}\"", crate::digest::md5_hex(&body)))
        }
    };
    let stored_checksum = checksums.flexible.as_ref().map(|f| ObjectChecksum {
        algorithm: f.algorithm.aws_name().to_string(),
        value: f.value_b64(),
    });
    let original_size = body.len() as u64;
    // Quotas (A8b): admitted before any of it is stored.
    if let Some(refused) = crate::quota::check(&bucket, original_size, 1) {
        return refused;
    }

    // SSE: if the request header or bucket default asks for encryption,
    // encrypt the body before it enters the erasure-coding path. Shards
    // on OSDs see ciphertext; the storage layer is oblivious.
    // What meta must answer before the data moves, in one call (B21). An
    // older meta, without it, is asked call by call, as before.
    let (pre_encryption, pre_versioning, pre_lock, pre_placement) =
        match write_context(&mut meta_client, &bucket, &key, original_size).await {
            Some(c) => (
                Some(c.encryption),
                Some(c.versioning),
                Some(c.object_lock),
                Some(c.placement),
            ),
            None => (None, None, None, None),
        };
    let (
        body,
        sse_algorithm,
        sse_kms_key_id,
        sse_encrypted_dek,
        sse_iv,
        sse_encryption_context,
        sse_response_header,
        sse_c_key_md5,
    ) = match apply_put_sse(
        &state,
        &mut meta_client,
        &bucket,
        &headers,
        body,
        pre_encryption,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    phases.mark("sse");

    // Check bucket versioning state: a missing bucket refuses the PUT.
    let versioning_enabled =
        match bucket_versioning_with(&mut meta_client, &bucket, pre_versioning).await {
            Ok(v) => v == VersioningState::VersioningEnabled,
            Err(resp) => return resp,
        };
    let (lock_retention, lock_hold) =
        match object_lock_for_write(&mut meta_client, &bucket, &headers, pre_lock).await {
            Ok(lock) => lock,
            Err(resp) => return resp,
        };
    let version_id = if versioning_enabled {
        new_version_id()
    } else {
        String::new()
    };
    // A replica another cluster sends keeps its version id (and ETag); one
    // this bucket holds already is a repeat, answered without storing it
    // again.
    let replica = match crate::replication::replica_request(
        &state,
        &auth,
        &bucket,
        &key,
        &headers,
        versioning_enabled,
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let version_id = replica
        .as_ref()
        .map_or(version_id, |r| r.version_id.clone());

    // Get placement from metadata service
    let answer = match pre_placement {
        Some(answer) => answer,
        None => meta_client
            .get_placement(GetPlacementRequest {
                bucket: bucket.clone(),
                key: key.clone(),
                size: original_size,
                storage_class: "STANDARD".to_string(),
            })
            .await
            .map(tonic::Response::into_inner),
    };
    let placement = match answer {
        Ok(p) => {
            // Where a read of the key, soon after, finds it (B21).
            crate::placement_cache::put(&bucket, &key, &p);
            p
        }
        Err(e) => {
            error!("Failed to get placement: {}", e);
            return meta_failure(&e, "Failed to get placement");
        }
    };
    phases.mark("meta_lookup");

    // If-Match / If-None-Match: refused now if the current object already
    // says no, before any data is written. The commit decides for good.
    let condition = PutCondition::from_headers(&headers);
    if condition.is_set() {
        let current = get_object_meta_from_any(&state.osd_pool, &placement.nodes, &bucket, &key)
            .await
            .ok()
            .flatten()
            .filter(|o| !o.is_delete_marker);
        if let Some(refused) = condition.refuse(current.as_ref()) {
            return refused;
        }
    }

    let ec_k = placement.ec_k;
    let ec_m = placement.ec_m;
    let ec_type = ErasureType::try_from(placement.ec_type).unwrap_or(ErasureType::ErasureMds);
    let replication_count = placement.replication_count;

    // A small object goes into its ObjectMeta, whole, on every OSD in the
    // placement: no stripes, no shard writes. It takes the EC path below
    // with zero stripes, whatever the protection scheme — replicating the
    // record is what protects it.
    let inline = !body.is_empty() && body.len() <= state.inline_max_size;

    // Replication mode: no EC, just write raw data to each replica
    // For large files, split into multiple stripes (each stripe <= MAX_SHARD_SIZE)
    if ec_type == ErasureType::ErasureReplication && !inline {
        let total_replicas = replication_count.max(1) as usize;

        // Split data into stripes (each stripe must fit in a block)
        let stripe_size = MAX_SHARD_SIZE;
        let num_stripes = body.len().div_ceil(stripe_size);

        debug!(
            "Replication mode: writing {} replicas x {} stripes for {}/{} (total size={})",
            total_replicas,
            num_stripes,
            bucket,
            key,
            body.len()
        );

        let mut all_stripes = Vec::with_capacity(num_stripes);
        let mut total_success = 0;
        let mut pending = pending_shards(&state, format!("{bucket}/{key}"));

        for stripe_idx in 0..num_stripes {
            let stripe_start = stripe_idx * stripe_size;
            let stripe_end = std::cmp::min(stripe_start + stripe_size, body.len());
            let stripe_data = body.slice(stripe_start..stripe_end);
            let stripe_data_size = stripe_data.len() as u64;

            // Write this stripe to all replicas
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
                let obj_id = object_id;
                let shard_data = stripe_data.clone();
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
                        1,    // ec_k=1 for replication (full data)
                        0,    // ec_m=0 for replication (no parity)
                        None, // Replicated stripes go over gRPC.
                    )
                    .await;
                    (pos, result, placement_node)
                });
            }

            let results = futures::future::join_all(write_futures).await;

            let mut success_count = 0;
            let mut shard_locs = Vec::with_capacity(total_replicas);

            let mut full = false;
            for (pos, result, placement_node) in results {
                match result {
                    Ok((location, crc32c)) => {
                        success_count += 1;
                        shard_locs.push(ShardLocation {
                            position: pos,
                            node_id: location.node_id,
                            disk_id: location.disk_id,
                            offset: location.offset,
                            shard_type: placement_node.shard_type,
                            local_group: placement_node.local_group,
                            crc32c: Some(crc32c),
                        });
                        debug!(
                            "Wrote stripe {} replica {} to {}",
                            stripe_idx, pos, placement_node.node_address
                        );
                    }
                    Err(e) => {
                        full |= e.is_full();
                        warn!(
                            "Failed to write stripe {} replica {} to {}: {}",
                            stripe_idx, pos, placement_node.node_address, e
                        );
                        // Do NOT add failed replica locations to metadata —
                        // reading from an unwritten location returns garbage.
                    }
                }
            }

            let quorum = replica_quorum(total_replicas);
            if success_count < quorum {
                error!(
                    "Replication failed for stripe {}: {} successful writes, need {}",
                    stripe_idx, success_count, quorum
                );
                if full {
                    return S3Error::storage_full();
                }
                return S3Error::xml_response(
                    "ServiceUnavailable",
                    &format!(
                        "Replication failed for stripe {}: {} successful writes, need {}",
                        stripe_idx, success_count, quorum
                    ),
                    StatusCode::SERVICE_UNAVAILABLE,
                );
            }

            total_success += success_count;
            shard_locs.sort_by_key(|l| l.position);

            all_stripes.push(StripeMeta {
                stripe_id: stripe_idx as u64,
                ec_k: 1,
                ec_m: 0,
                shards: shard_locs,
                ec_type: ErasureType::ErasureReplication.into(),
                ec_local_parity: 0,
                ec_global_parity: 0,
                local_group_size: 0,
                data_size: stripe_data_size,
                object_id: object_id.to_vec(), // Store object_id used for shards
                ..Default::default()
            });
        }
        phases.mark("shards");

        // Store object metadata on primary OSD
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        // The ETag has been computing alongside the stripes; collect it.
        let etag = match etag_task.await {
            Ok(etag) => etag,
            Err(e) => {
                error!("ETag computation failed: {e}");
                return S3Error::xml_response(
                    "InternalError",
                    "ETag computation failed",
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };
        phases.mark("etag");

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let etag = replica.as_ref().map_or(etag, |r| r.etag.clone());
        let object_meta = ObjectMeta {
            bucket: bucket.clone(),
            key: key.clone(),
            object_id: object_id.to_vec(),
            size: original_size,
            content_type: content_type.clone(),
            etag: etag.clone(),
            created_at: timestamp,
            modified_at: timestamp,
            stripes: all_stripes,
            user_metadata: extract_user_metadata(&headers),
            version_id: version_id.clone(),
            storage_class: "STANDARD".to_string(),
            is_delete_marker: false,
            retention: lock_retention,
            legal_hold: lock_hold,
            encryption_algorithm: sse_algorithm as i32,
            kms_key_id: sse_kms_key_id.clone(),
            encrypted_dek: sse_encrypted_dek.clone(),
            encryption_iv: sse_iv.clone(),
            encryption_context: sse_encryption_context.clone(),
            usage_owner: Vec::new(), // filled in by put_object_meta_to_all
            inline_data: Vec::new(),
            checksum: stored_checksum.clone(),
            tags: tags.clone(),
            part_checksums: Vec::new(),
            replication: HashMap::new(),
            replica_of: replica.as_ref().map(|r| r.of.clone()).unwrap_or_default(),
            required_level: 0,
            stamp: 0, // stamped when stored
            update_stamp: 0,
        };

        // Listed as well: this path used to write only the ObjectMeta, so a
        // replicated object never appeared in ListObjects.
        // What lifecycle filters on, for x-amz-expiration once it's stored.
        let expiration_of = ObjectMeta {
            key: object_meta.key.clone(),
            size: object_meta.size,
            tags: object_meta.tags.clone(),
            ..ObjectMeta::default()
        };
        let sent = pending.disarm();
        if let Err(resp) = commit_put(
            &state,
            &placement,
            object_meta,
            versioning_enabled,
            sent,
            &condition,
            None,
        )
        .await
        {
            return resp;
        }
        phases.mark("object_meta");

        dedup_dry_run(
            &state,
            &bucket,
            &placement,
            &body,
            sse_algorithm != SseAlgorithm::SseNone,
        );
        info!(
            "Created object (replication): {}/{}, size={}, stripes={}, replicas_written={}",
            bucket, key, original_size, num_stripes, total_success,
        );

        let expiration = crate::lifecycle::expiration_header(
            &state,
            &bucket,
            &expiration_of,
            crate::lifecycle::now_ms(),
        )
        .await;
        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .header("ETag", etag);
        if let Some(c) = &checksums.flexible {
            resp = resp.header(c.algorithm.header_name(), c.value_b64());
        }
        if !version_id.is_empty() {
            resp = resp.header("x-amz-version-id", &version_id);
        }
        if let Some(v) = expiration {
            resp = resp.header("x-amz-expiration", v);
        }
        if let Some(v) = sse_response_header {
            resp = resp.header("x-amz-server-side-encryption", v);
            if v == "aws:kms" && !sse_kms_key_id.is_empty() {
                resp = resp.header(
                    "x-amz-server-side-encryption-aws-kms-key-id",
                    &sse_kms_key_id,
                );
            }
        }
        if sse_algorithm == SseAlgorithm::SseC {
            resp = resp
                .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
                .header(
                    "x-amz-server-side-encryption-customer-key-md5",
                    &sse_c_key_md5,
                );
        }
        return resp.body(Body::empty()).unwrap();
    }

    // EC mode: encode data with erasure coding
    // For large files, split into multiple stripes (each shard <= MAX_SHARD_SIZE)
    let total_shards = (ec_k + ec_m) as usize;

    // Calculate max stripe data size: each encoded shard must fit in MAX_SHARD_SIZE
    // shard_size = stripe_data_size / ec_k (approximately)
    // So max_stripe_data_size = MAX_SHARD_SIZE * ec_k
    let max_stripe_data_size = MAX_SHARD_SIZE * ec_k as usize;
    let num_stripes = if inline {
        0
    } else {
        body.len().div_ceil(max_stripe_data_size)
    };

    debug!(
        "EC mode: encoding {}/{} ({} bytes) into {} stripes with {}+{} shards each",
        bucket,
        key,
        body.len(),
        num_stripes,
        ec_k,
        ec_m
    );

    let mut all_stripes = Vec::with_capacity(num_stripes);
    let mut total_shards_written = 0;
    let mut pending = pending_shards(&state, format!("{bucket}/{key}"));
    // A small object (B21): one stripe whose shards each fit in an OSD's
    // metadata record, on as many OSDs as shards, once the cluster allows
    // it. Its shards go with its metadata, in the commit: one call and one
    // flush per OSD.
    let mut small: Option<SmallShards> = None;
    let small_object = num_stripes == 1
        && ec_type == ErasureType::ErasureMds
        && state.rdma.is_none()
        && body.len().div_ceil(ec_k as usize) <= state.small_shard_max
        && objectio_common::version::allows(objectio_common::version::SMALL_SHARDS_LEVEL)
        && placement.nodes.len() == total_shards
        && placement
            .nodes
            .iter()
            .map(|n| n.node_id.as_slice())
            .collect::<std::collections::HashSet<_>>()
            .len()
            == total_shards;

    for stripe_idx in 0..num_stripes {
        let stripe_start = stripe_idx * max_stripe_data_size;
        let stripe_end = std::cmp::min(stripe_start + max_stripe_data_size, body.len());
        let stripe_data = &body[stripe_start..stripe_end];
        let stripe_data_size = stripe_data.len() as u64;

        // Where the encoded stripe starts in registered memory, when it was
        // encoded into a Transfer Engine stripe slot.
        let mut rdma_base: Option<u64> = None;

        // Encode this stripe with erasure coding - use LRC if specified
        let shards: Vec<Bytes> = match ec_type {
            ErasureType::ErasureLrc => {
                // Use LRC backend with local parity groups
                let lrc_config = LrcConfig::new(
                    ec_k as u8,
                    placement.ec_local_parity as u8,
                    placement.ec_global_parity as u8,
                );
                let backend = match RustSimdLrcBackend::new(lrc_config) {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Failed to create LRC backend: {}", e);
                        return S3Error::xml_response(
                            "InternalError",
                            &format!("LRC codec error: {}", e),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                };

                // Pad data to shard size
                let shard_size = stripe_data.len().div_ceil(ec_k as usize);
                let padded_size = shard_size * ec_k as usize;
                let mut padded_data = stripe_data.to_vec();
                padded_data.resize(padded_size, 0);

                // Split into data shards
                let data_shards: Vec<&[u8]> =
                    padded_data.chunks(shard_size).take(ec_k as usize).collect();

                match backend.encode_lrc(&data_shards, shard_size) {
                    Ok(encoded) => encoded.all_shards().into_iter().map(Bytes::from).collect(),
                    Err(e) => {
                        error!("Failed to encode stripe {} with LRC: {}", stripe_idx, e);
                        return S3Error::xml_response(
                            "InternalError",
                            &format!("LRC encoding failed for stripe {}: {}", stripe_idx, e),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                }
            }
            _ => {
                // Use standard MDS Reed-Solomon
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

                // With Transfer Engine, encode straight into a registered
                // stripe slot: OSDs then read their shards out of it.
                let slot = state
                    .rdma
                    .as_deref()
                    .and_then(|r| r.stripe_slot(codec.stripe_len(stripe_data.len())));
                let encoded = match slot {
                    Some(mut slot) => {
                        let base = slot.addr();
                        codec
                            .encode_into(stripe_data, slot.as_mut_slice())
                            .map(|shard_size| {
                                rdma_base = Some(base);
                                let stripe = slot.into_bytes(shard_size * total_shards);
                                (0..total_shards)
                                    .map(|i| stripe.slice(i * shard_size..(i + 1) * shard_size))
                                    .collect()
                            })
                    }
                    None => codec.encode_bytes(stripe_data),
                };
                match encoded {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to encode stripe {}: {}", stripe_idx, e);
                        return S3Error::xml_response(
                            "InternalError",
                            &format!("Erasure encoding failed for stripe {}: {}", stripe_idx, e),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        );
                    }
                }
            }
        };

        debug!(
            "Stripe {}: encoded {} bytes into {} shards of {} bytes each",
            stripe_idx,
            stripe_data.len(),
            shards.len(),
            shards.first().map(|s| s.len()).unwrap_or(0)
        );

        if small_object {
            let mut shards_by_node = std::collections::HashMap::with_capacity(total_shards);
            let mut shard_locs = Vec::with_capacity(total_shards);
            for (i, (shard, node)) in shards.iter().zip(&placement.nodes).enumerate() {
                let pos = i as u32;
                pending.sent(node, &object_id, stripe_idx as u64, pos);
                let crc = crc32c::crc32c(shard);
                shard_locs.push(ShardLocation {
                    position: pos,
                    node_id: node.node_id.clone(),
                    disk_id: vec![0u8; 16],
                    offset: 0,
                    shard_type: node.shard_type,
                    local_group: node.local_group,
                    crc32c: Some(crc),
                });
                shards_by_node.insert(
                    node.node_id.clone(),
                    objectio_proto::storage::SmallShard {
                        shard_id: Some(objectio_proto::storage::ShardId {
                            object_id: object_id.to_vec(),
                            stripe_id: stripe_idx as u64,
                            position: pos,
                        }),
                        data: shard.to_vec(),
                        crc32c: crc,
                    },
                );
            }
            total_shards_written += total_shards;
            small = Some(SmallShards {
                shards: shards_by_node,
                quorum: write_quorum(ec_k, ec_m),
            });
            all_stripes.push(StripeMeta {
                stripe_id: stripe_idx as u64,
                ec_k,
                ec_m,
                shards: shard_locs,
                ec_type: placement.ec_type,
                ec_local_parity: placement.ec_local_parity,
                ec_global_parity: placement.ec_global_parity,
                local_group_size: placement.local_group_size,
                data_size: stripe_data_size,
                object_id: object_id.to_vec(),
                shards_in_metadata: true,
                ..Default::default()
            });
            continue;
        }

        // Write shards to OSDs in parallel
        let mut write_futures = Vec::with_capacity(total_shards);

        // Use placements from metadata service, or fall back to round-robin if not enough
        for (i, shard) in shards.iter().enumerate() {
            let placement_node = if i < placement.nodes.len() {
                placement.nodes[i].clone()
            } else if !placement.nodes.is_empty() {
                // Round-robin if not enough placements
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
            let obj_id = object_id;
            let shard_data = shard.clone();
            let pos = i as u32;
            let s_idx = stripe_idx as u64;
            pending.sent(&placement_node, &obj_id, s_idx, pos);
            let rdma = state.rdma.clone();
            let shard_addr = rdma_base.map(|base| base + (i * shard_data.len()) as u64);
            // Transfer Engine was on offer, but no stripe slot was free.
            if rdma.is_some() && shard_addr.is_none() && !placement_node.te_segment.is_empty() {
                crate::gateway_metrics::record_rdma_fallback(
                    "write",
                    crate::rdma::Fallback::NoSlot,
                );
            }

            write_futures.push(async move {
                let source = rdma
                    .as_deref()
                    .zip(shard_addr)
                    .map(|(rdma, addr)| crate::osd_pool::RdmaSource { rdma, addr });
                let result = write_shard_to_osd(
                    &pool,
                    &placement_node,
                    &obj_id,
                    s_idx, // stripe_id
                    pos,
                    shard_data,
                    ec_k,
                    ec_m,
                    source,
                )
                .await;
                (pos, result, placement_node)
            });
        }

        // Wait for all writes and collect results
        let results = futures::future::join_all(write_futures).await;

        let mut success_count = 0;
        let mut shard_locs = Vec::with_capacity(total_shards);

        let mut full = false;
        for (pos, result, placement_node) in results {
            match result {
                Ok((location, crc32c)) => {
                    success_count += 1;
                    shard_locs.push(ShardLocation {
                        position: pos,
                        node_id: location.node_id,
                        disk_id: location.disk_id,
                        offset: location.offset,
                        // Use shard type from placement, or default to data/parity based on position
                        shard_type: placement_node.shard_type,
                        local_group: placement_node.local_group,
                        crc32c: Some(crc32c),
                    });
                    debug!(
                        "Wrote stripe {} shard {} to {}",
                        stripe_idx, pos, placement_node.node_address
                    );
                }
                Err(e) => {
                    full |= e.is_full();
                    warn!(
                        "Failed to write stripe {} shard {} to {}: {}",
                        stripe_idx, pos, placement_node.node_address, e
                    );
                    // Do NOT add failed shard locations to metadata — the shard
                    // was never written, so reading from this location would
                    // return unrelated data and corrupt EC reconstruction.
                }
            }
        }

        let quorum = write_quorum(ec_k, ec_m);
        if success_count < quorum {
            error!(
                "Write quorum not met for stripe {}: {} successful, need {} (ec_k={}, ec_m={}, total_shards={})",
                stripe_idx, success_count, quorum, ec_k, ec_m, total_shards
            );
            if full {
                return S3Error::storage_full();
            }
            return S3Error::xml_response(
                "ServiceUnavailable",
                &format!(
                    "Write quorum not met for stripe {}: {} successful writes, need {}",
                    stripe_idx, success_count, quorum
                ),
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }

        total_shards_written += success_count;

        // Sort shard locations by position
        shard_locs.sort_by_key(|l| l.position);

        // Add stripe metadata
        all_stripes.push(StripeMeta {
            stripe_id: stripe_idx as u64,
            ec_k,
            ec_m,
            shards: shard_locs,
            // Use the EC type from placement response
            ec_type: placement.ec_type,
            ec_local_parity: placement.ec_local_parity,
            ec_global_parity: placement.ec_global_parity,
            local_group_size: placement.local_group_size,
            data_size: stripe_data_size, // Store this stripe's data size for decoding
            object_id: object_id.to_vec(), // Store object_id used for shards
            ..Default::default()
        });
    }

    // Store object metadata on primary OSD (position 0)
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    phases.mark("shards");

    // The ETag has been computing alongside the stripes; collect it.
    let etag = match etag_task.await {
        Ok(etag) => etag,
        Err(e) => {
            error!("ETag computation failed: {e}");
            return S3Error::xml_response(
                "InternalError",
                "ETag computation failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };
    phases.mark("etag");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build ObjectMeta for OSD storage
    let etag = replica.as_ref().map_or(etag, |r| r.etag.clone());
    let object_meta = ObjectMeta {
        bucket: bucket.clone(),
        key: key.clone(),
        object_id: object_id.to_vec(),
        size: original_size,
        content_type: content_type.clone(),
        etag: etag.clone(),
        created_at: timestamp,
        modified_at: timestamp,
        stripes: all_stripes,
        user_metadata: extract_user_metadata(&headers),
        version_id: version_id.clone(),
        storage_class: "STANDARD".to_string(),
        is_delete_marker: false,
        retention: lock_retention,
        legal_hold: lock_hold,
        encryption_algorithm: sse_algorithm as i32,
        kms_key_id: sse_kms_key_id.clone(),
        encrypted_dek: sse_encrypted_dek,
        encryption_iv: sse_iv,
        encryption_context: sse_encryption_context,
        usage_owner: Vec::new(), // filled in by put_object_meta_to_all
        inline_data: if inline { body.to_vec() } else { Vec::new() },
        checksum: stored_checksum,
        tags,
        part_checksums: Vec::new(),
        replication: HashMap::new(),
        replica_of: replica.as_ref().map(|r| r.of.clone()).unwrap_or_default(),
        required_level: 0,
        stamp: 0, // stamped when stored
        update_stamp: 0,
    };

    // What lifecycle filters on, for x-amz-expiration once it's stored.
    let expiration_of = ObjectMeta {
        key: object_meta.key.clone(),
        size: object_meta.size,
        tags: object_meta.tags.clone(),
        ..ObjectMeta::default()
    };
    let sent = pending.disarm();
    if let Err(resp) = commit_put(
        &state,
        &placement,
        object_meta,
        versioning_enabled,
        sent,
        &condition,
        small.as_ref(),
    )
    .await
    {
        return resp;
    }
    phases.mark("commit");

    dedup_dry_run(
        &state,
        &bucket,
        &placement,
        &body,
        sse_algorithm != SseAlgorithm::SseNone,
    );
    info!(
        "Created object: {}/{}, size={}, stripes={}, shards_written={}, replicas={}",
        bucket,
        key,
        original_size,
        num_stripes,
        total_shards_written,
        placement.nodes.len(),
    );
    if inline {
        crate::gateway_metrics::record_inline(original_size);
    }

    let expiration = crate::lifecycle::expiration_header(
        &state,
        &bucket,
        &expiration_of,
        crate::lifecycle::now_ms(),
    )
    .await;
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", etag);
    if let Some(c) = &checksums.flexible {
        resp = resp.header(c.algorithm.header_name(), c.value_b64());
    }
    if !version_id.is_empty() {
        resp = resp.header("x-amz-version-id", &version_id);
    }
    if let Some(v) = expiration {
        resp = resp.header("x-amz-expiration", v);
    }
    if let Some(v) = sse_response_header {
        resp = resp.header("x-amz-server-side-encryption", v);
        if v == "aws:kms" && !sse_kms_key_id.is_empty() {
            resp = resp.header(
                "x-amz-server-side-encryption-aws-kms-key-id",
                &sse_kms_key_id,
            );
        }
    }
    if sse_algorithm == SseAlgorithm::SseC {
        resp = resp
            .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
            .header(
                "x-amz-server-side-encryption-customer-key-md5",
                &sse_c_key_md5,
            );
    }
    resp.body(Body::empty()).unwrap()
}

/// PUT /{bucket}/{key}?uploadId=X&partNumber=N - Upload part
pub async fn put_object_with_params(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<PutObjectParams>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // If uploadId and partNumber are present, this is a multipart part upload
    if let (Some(upload_id), Some(part_number)) = (params.upload_id, params.part_number) {
        if headers.contains_key("x-amz-copy-source") {
            return upload_part_copy_internal(
                state,
                bucket,
                key,
                upload_id,
                part_number,
                auth,
                headers,
            )
            .await;
        }
        return upload_part_internal(state, bucket, key, upload_id, part_number, headers, body)
            .await;
    }
    if params.acl.is_some() {
        return put_acl(&state, &bucket, Some(&key), &headers, &body).await;
    }
    if let Some(refused) = acl_header_refusal(&headers) {
        return refused;
    }
    if params.retention.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        return put_object_retention_internal(state, bucket, key, body, &headers).await;
    }
    if params.legal_hold.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        return put_object_legal_hold_internal(state, bucket, key, body).await;
    }
    if params.tagging.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        return put_object_tagging_internal(state, bucket, key, body).await;
    }

    // Otherwise, it's a regular PUT object
    put_object(State(state), Path((bucket, key)), auth, headers, body).await
}

/// What [`write_context`] fetched: each answer as its own call gives it.
struct WriteContext {
    encryption: Result<objectio_proto::metadata::GetBucketEncryptionResponse, tonic::Status>,
    versioning: Result<objectio_proto::metadata::GetBucketVersioningResponse, tonic::Status>,
    object_lock: Result<objectio_proto::metadata::GetObjectLockConfigResponse, tonic::Status>,
    placement: Result<objectio_proto::metadata::GetPlacementResponse, tonic::Status>,
}

/// The bucket's encryption, versioning and object lock and the key's
/// placement, in one meta call (`GetWriteContext`, B21). `None` if meta
/// can't answer it (an older release): then each is asked on its own.
async fn write_context(
    meta_client: &mut MetadataServiceClient<Channel>,
    bucket: &str,
    key: &str,
    size: u64,
) -> Option<WriteContext> {
    #[allow(clippy::result_large_err)] // tonic::Status, as every call returns
    fn unpack<T: prost::Message + Default>(
        c: Option<objectio_proto::metadata::CallResult>,
    ) -> Result<T, tonic::Status> {
        let c = c.ok_or_else(|| tonic::Status::internal("meta left out an answer"))?;
        if c.code == 0 {
            T::decode(c.response.as_slice()).map_err(|e| tonic::Status::internal(e.to_string()))
        } else {
            Err(tonic::Status::new(tonic::Code::from(c.code), c.message))
        }
    }
    let r = meta_client
        .get_write_context(objectio_proto::metadata::GetWriteContextRequest {
            placement: Some(GetPlacementRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                size,
                storage_class: "STANDARD".to_string(),
            }),
        })
        .await
        .ok()?
        .into_inner();
    Some(WriteContext {
        encryption: unpack(r.encryption),
        versioning: unpack(r.versioning),
        object_lock: unpack(r.object_lock),
        placement: unpack(r.placement),
    })
}

/// A small object's shards, sent with its metadata (B21): each OSD's by
/// node id, and how many copies the write needs.
pub(crate) struct SmallShards {
    pub(crate) shards: std::collections::HashMap<Vec<u8>, objectio_proto::storage::SmallShard>,
    pub(crate) quorum: usize,
}
