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

/// Whether the bucket's dedup policy asks for bodies written to it to be
/// noted.
pub(crate) fn dedup_wanted(placement: &objectio_proto::metadata::GetPlacementResponse) -> bool {
    use objectio_proto::metadata::DedupMode;
    matches!(placement.dedup_mode(), DedupMode::DryRun | DedupMode::On)
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
    if !dedup_wanted(placement) || body.is_empty() {
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
    let pg = objectio_proto::stripe::fence(placement);
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
            pg: pg.as_ref(),
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
    let pg = objectio_proto::stripe::fence(placement);
    let write = crate::osd_pool::MetaWrite {
        versioning_enabled,
        small_shards: small.map(|s| &s.shards),
        min_copies: small.map_or(0, |s| s.quorum),
        pg: pg.as_ref(),
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
            Copies {
                nodes,
                bucket: &bucket,
                key: &key,
            },
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
        Copies {
            nodes,
            bucket: &bucket,
            key: &key,
        },
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
                "{what}: {failed} of {total} shard deletes failed ({}); retried in the background",
                reason.label()
            );
        } else {
            debug!("{what}: freed {total} shards ({})", reason.label());
        }
    });
}

/// Where a key's copies are: what an overwrite's freeing reads again when
/// its copies disagreed.
#[derive(Clone, Copy)]
pub(crate) struct Copies<'a> {
    pub nodes: &'a [objectio_proto::metadata::NodePlacement],
    pub bucket: &'a str,
    pub key: &'a str,
}

/// Free what an overwrite displaced: at once when its copies agree, else
/// what no copy holds once a racing write has settled
/// ([`reclaimable_after_overwrite`]).
pub(crate) fn spawn_overwrite_reclaim(
    state: &Arc<AppState>,
    displaced: &[Displaced],
    keep: &std::collections::HashSet<Vec<u8>>,
    at: Copies<'_>,
    what: String,
) {
    let freed = reclaimable_after_overwrite(displaced, keep);
    spawn_reclaim(state, freed.now, Reclaim::Overwrite, what.clone());
    if freed.unsettled.is_empty() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let state = Arc::clone(state);
    let (nodes, bucket, key) = (at.nodes.to_vec(), at.bucket.to_string(), at.key.to_string());
    let keep = keep.clone();
    runtime.spawn(async move {
        tokio::time::sleep(crate::osd_pool::RESTAMP_SETTLE).await;
        let mut meta = state.meta_client.clone();
        let failed = crate::osd_pool::reclaim_unsettled(
            &state.osd_pool,
            &mut meta,
            &nodes,
            &bucket,
            &key,
            freed.unsettled,
            &keep,
        )
        .await;
        if failed > 0 {
            warn!("{what}: {failed} shard deletes failed (overwrite); retried in the background");
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
    at: Copies<'_>,
    what: &str,
) {
    match outcome {
        // Every copy already held a newer write of the key (last writer
        // wins): nothing references this one's shards.
        Ok(displaced) if !displaced.is_empty() && displaced.iter().all(|d| d.superseded) => {
            spawn_reclaim(state, sent, Reclaim::FailedWrite, what.to_string());
        }
        Ok(displaced) if !versioning_enabled => {
            spawn_overwrite_reclaim(state, displaced, new_object, at, what.to_string());
        }
        Ok(_) => {}
        Err(e) if e.unapplied => {
            spawn_reclaim(state, sent, Reclaim::FailedWrite, what.to_string());
        }
        // A refused small write not yet withdrawn from every copy that may
        // hold it (or not yet known to be held by k): its shards go once
        // it is withdrawn.
        Err(MetaWriteError {
            withdrawing: Some(w),
            ..
        }) => {
            let (state, w, what) = (Arc::clone(state), w.clone(), what.to_string());
            tokio::spawn(async move {
                let (targets, bucket, key) = (w.targets.clone(), w.bucket.clone(), w.key.clone());
                let withdrawn = crate::osd_pool::withdraw_later(&state.osd_pool, w).await;
                // Decided after the PUT's own listing update, which found
                // it still on some copies: the listing follows what they
                // hold now. (Peering keeps an entry no copy backs, as
                // unfound.)
                sync_listing(&state, &targets, &bucket, &key).await;
                if withdrawn {
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

/// PUT, placed again once when an OSD refused it as placed under an older
/// epoch of its placement group than it knows (B31;
/// [`crate::stripe::placed_again`]).
pub async fn put_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    crate::stripe::placed_again(&bucket, &key, || {
        put_object_placed(
            Arc::clone(&state),
            bucket.clone(),
            key.clone(),
            auth.clone(),
            headers.clone(),
            body.clone(),
        )
    })
    .await
}

/// What a PUT decided before any of its body is stored: how it is
/// encrypted, versioned, locked and placed, and on what condition.
pub(crate) struct PutPlan {
    tags: HashMap<String, String>,
    sse: PutSse,
    versioning_enabled: bool,
    retention: Option<ObjectRetention>,
    legal_hold: Option<LegalHold>,
    version_id: String,
    replica: Option<crate::replication::Replica>,
    placement: objectio_proto::metadata::GetPlacementResponse,
    condition: PutCondition,
}

/// Everything a PUT of `size` bytes (its declared length) asks meta, and
/// decides, before its body moves; refused here, nothing is stored.
async fn plan_put(
    state: &Arc<AppState>,
    bucket: &str,
    key: &str,
    auth: &Option<Extension<AuthResult>>,
    headers: &HeaderMap,
    tags: HashMap<String, String>,
    size: u64,
) -> Result<PutPlan, Response> {
    // Quotas (A8b): admitted before any of it is stored.
    if let Some(refused) = crate::quota::check(bucket, size, 1) {
        return Err(refused);
    }
    let mut meta_client = state.meta_client.clone();
    // What meta must answer before the data moves, in one call (B21).
    let (pre_encryption, pre_versioning, pre_lock, pre_placement) =
        match write_context(&mut meta_client, bucket, key, size).await {
            Ok(c) => (
                Some(c.encryption),
                Some(c.versioning),
                Some(c.object_lock),
                c.placement,
            ),
            Err(e) => {
                error!("Failed to get the write context: {e}");
                return Err(meta_failure(&e, "Failed to get the write context"));
            }
        };
    // SSE: if the request header or bucket default asks for encryption,
    // the body is encrypted before it enters the erasure-coding path.
    // Shards on OSDs see ciphertext; the storage layer is oblivious.
    let sse = put_sse(state, &mut meta_client, bucket, headers, pre_encryption).await?;

    // Check bucket versioning state: a missing bucket refuses the PUT.
    let versioning_enabled = bucket_versioning_with(&mut meta_client, bucket, pre_versioning)
        .await?
        == VersioningState::VersioningEnabled;
    let (retention, legal_hold) =
        object_lock_for_write(&mut meta_client, bucket, headers, pre_lock).await?;
    let version_id = if versioning_enabled {
        new_version_id()
    } else {
        String::new()
    };
    // A replica another cluster sends keeps its version id (and ETag); one
    // this bucket holds already is a repeat, answered without storing it
    // again.
    let replica =
        crate::replication::replica_request(state, auth, bucket, key, headers, versioning_enabled)
            .await?;
    let version_id = replica
        .as_ref()
        .map_or(version_id, |r| r.version_id.clone());

    // Get placement from metadata service
    let placement = match pre_placement {
        Ok(p) => {
            // Where a read of the key, soon after, finds it (B21).
            crate::placement_cache::put(bucket, key, &p);
            p
        }
        Err(e) => {
            error!("Failed to get placement: {}", e);
            return Err(meta_failure(&e, "Failed to get placement"));
        }
    };
    crate::test_hooks::held_after_placement(bucket, key).await;

    // If-Match / If-None-Match: refused now if the current object already
    // says no, before any data is written. The commit decides for good.
    let condition = PutCondition::from_headers(headers);
    if condition.is_set() {
        let current = get_object_meta_from_any(&state.osd_pool, &placement.nodes, bucket, key)
            .await
            .ok()
            .flatten()
            .filter(|o| !o.is_delete_marker);
        if let Some(refused) = condition.refuse(current.as_ref()) {
            return Err(refused);
        }
    }
    Ok(PutPlan {
        tags,
        sse,
        versioning_enabled,
        retention,
        legal_hold,
        version_id,
        replica,
        placement,
        condition,
    })
}

/// A PUT's body, stored and not yet committed.
pub(crate) struct Written {
    object_id: [u8; 16],
    size: u64,
    stripes: Vec<StripeMeta>,
    /// The quoted MD5 of the plaintext.
    etag: String,
    /// The flexible checksum the client sent, kept with the object.
    checksum: Option<(crate::checksum::ChecksumAlgorithm, String)>,
    /// The object itself, when it is small enough to live in its metadata.
    inline_data: Vec<u8>,
    sent: Vec<ShardTarget>,
    small: Option<SmallShards>,
    /// The body as stored, for the dedup dry-run (a body read whole; a
    /// streamed one is noted stripe by stripe).
    dedup: Option<Bytes>,
}

/// Commit a PUT whose body is stored, and answer it.
async fn finish_put(
    state: &Arc<AppState>,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    plan: PutPlan,
    written: Written,
    phases: &mut crate::gateway_metrics::PhaseTimer,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let inline = !written.inline_data.is_empty();
    let stripes = written.stripes.len();
    let etag = plan
        .replica
        .as_ref()
        .map_or(written.etag, |r| r.etag.clone());
    let sse = &plan.sse;
    let object_meta = ObjectMeta {
        bucket: bucket.to_string(),
        key: key.to_string(),
        object_id: written.object_id.to_vec(),
        size: written.size,
        content_type,
        etag: etag.clone(),
        created_at: timestamp,
        modified_at: timestamp,
        stripes: written.stripes,
        user_metadata: extract_user_metadata(headers),
        version_id: plan.version_id.clone(),
        storage_class: "STANDARD".to_string(),
        is_delete_marker: false,
        retention: plan.retention,
        legal_hold: plan.legal_hold,
        encryption_algorithm: sse.algorithm as i32,
        kms_key_id: sse.kms_key_id.clone(),
        encrypted_dek: sse.encrypted_dek.clone(),
        encryption_iv: sse.iv.clone(),
        encryption_context: sse.encryption_context.clone(),
        usage_owner: Vec::new(), // filled in by put_object_meta_to_all
        inline_data: written.inline_data,
        checksum: written.checksum.as_ref().map(|(a, v)| ObjectChecksum {
            algorithm: a.aws_name().to_string(),
            value: v.clone(),
        }),
        tags: plan.tags,
        part_checksums: Vec::new(),
        replication: HashMap::new(),
        replica_of: plan
            .replica
            .as_ref()
            .map(|r| r.of.clone())
            .unwrap_or_default(),
        required_level: 0,
        stamp: 0, // stamped when stored
        update_stamp: 0,
        pg_pool: plan.placement.pool.clone(),
        pg_id: plan.placement.pg_id,
    };

    // What lifecycle filters on, for x-amz-expiration once it's stored.
    let expiration_of = ObjectMeta {
        key: object_meta.key.clone(),
        size: object_meta.size,
        tags: object_meta.tags.clone(),
        ..ObjectMeta::default()
    };
    if let Err(resp) = commit_put(
        state,
        &plan.placement,
        object_meta,
        plan.versioning_enabled,
        written.sent,
        &plan.condition,
        written.small.as_ref(),
    )
    .await
    {
        return resp;
    }
    phases.mark("commit");

    if let Some(body) = &written.dedup {
        dedup_dry_run(state, bucket, &plan.placement, body, sse.encrypts());
    }
    debug!(
        "Created object: {bucket}/{key}, size={}, stripes={stripes}, replicas={}",
        written.size,
        plan.placement.nodes.len(),
    );
    if inline {
        crate::gateway_metrics::record_inline(written.size);
    }

    let expiration = crate::lifecycle::expiration_header(
        state,
        bucket,
        &expiration_of,
        crate::lifecycle::now_ms(),
    )
    .await;
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", etag);
    if let Some((algorithm, value)) = &written.checksum {
        resp = resp.header(algorithm.header_name(), value);
    }
    if !plan.version_id.is_empty() {
        resp = resp.header("x-amz-version-id", &plan.version_id);
    }
    if let Some(v) = expiration {
        resp = resp.header("x-amz-expiration", v);
    }
    if let Some(v) = sse.response_header {
        resp = resp.header("x-amz-server-side-encryption", v);
        if v == "aws:kms" && !sse.kms_key_id.is_empty() {
            resp = resp.header(
                "x-amz-server-side-encryption-aws-kms-key-id",
                &sse.kms_key_id,
            );
        }
    }
    if sse.algorithm == SseAlgorithm::SseC {
        resp = resp
            .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
            .header(
                "x-amz-server-side-encryption-customer-key-md5",
                &sse.sse_c_key_md5,
            );
    }
    resp.body(Body::empty()).unwrap()
}

async fn put_object_placed(
    state: Arc<AppState>,
    bucket: String,
    key: String,
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
    let original_size = body.len() as u64;
    let plan = match plan_put(&state, &bucket, &key, &auth, &headers, tags, original_size).await {
        Ok(plan) => plan,
        Err(resp) => return resp,
    };
    let body = if plan.sse.encrypts() {
        let mut buf = body.to_vec();
        plan.sse.cipher().apply(0, &mut buf);
        Bytes::from(buf)
    } else {
        body
    };
    phases.mark("meta_lookup");

    // Where and how the stripes go, and the placement group epoch every
    // shard is written under (B31): an OSD that knows a newer one refuses
    // it, and the PUT is placed again.
    let placement = &plan.placement;
    let placed = crate::stripe::Placed::new(placement);
    let scheme = placed.scheme;
    let total_shards = scheme.width();

    // A small object goes into its ObjectMeta, whole, on every OSD in the
    // placement: no stripes, no shard writes. It takes the path below with
    // zero stripes, whatever the protection scheme — replicating the
    // record is what protects it.
    let inline = !body.is_empty() && body.len() <= state.inline_max_size;

    // Split into stripes whose shards each fit in an OSD block.
    let max_stripe_data_size = MAX_SHARD_SIZE * scheme.data_shards();
    let num_stripes = if inline {
        0
    } else {
        body.len().div_ceil(max_stripe_data_size)
    };

    debug!(
        "{}/{} ({} bytes): {} stripes of {:?}",
        bucket,
        key,
        body.len(),
        num_stripes,
        scheme
    );

    let coder = match crate::stripe::Coder::new(scheme) {
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
    let mut pending = pending_shards(&state, format!("{bucket}/{key}"));
    // A small object (B21): one stripe whose shards each fit in an OSD's
    // metadata record, each on an OSD of its own. Its shards go with its
    // metadata, in the commit: one call and one flush per OSD.
    let mut small: Option<SmallShards> = None;
    let small_object = num_stripes == 1
        && matches!(scheme, crate::stripe::Scheme::Mds { .. })
        && state.rdma.is_none()
        && body.len().div_ceil(scheme.data_shards()) <= state.small_shard_max
        && placement.nodes.len() == total_shards
        && objectio_proto::stripe::targets(&placement.nodes, total_shards)
            .iter()
            .all(Option::is_some);

    for stripe_idx in 0..num_stripes {
        let stripe_start = stripe_idx * max_stripe_data_size;
        let stripe_end = std::cmp::min(stripe_start + max_stripe_data_size, body.len());
        let stripe_data = body.slice(stripe_start..stripe_end);
        let stripe_data_size = stripe_data.len() as u64;

        // With Transfer Engine, an MDS stripe is encoded straight into a
        // registered stripe slot: OSDs then read their shards out of it.
        // Copies and LRC stripes go over gRPC.
        let rdma = state
            .rdma
            .as_deref()
            .filter(|_| matches!(scheme, crate::stripe::Scheme::Mds { .. }));
        let (shards, rdma_base) = match crate::stripe::encode(&coder, rdma, stripe_data) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to encode stripe {}: {}", stripe_idx, e);
                return S3Error::xml_response(
                    "InternalError",
                    &format!("Erasure encoding failed for stripe {}: {}", stripe_idx, e),
                    StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        };

        debug!(
            "Stripe {}: {} bytes into {} shards of {} bytes each",
            stripe_idx,
            stripe_data_size,
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
            small = Some(SmallShards {
                shards: shards_by_node,
                quorum: scheme.quorum(),
            });
            all_stripes.push(StripeMeta {
                shards_in_metadata: true,
                ..scheme.stripe(
                    stripe_idx as u64,
                    stripe_data_size,
                    object_id.to_vec(),
                    shard_locs,
                )
            });
            continue;
        }

        let shard_locs = match crate::stripe::write_stripe(
            &state.osd_pool,
            &placed,
            &object_id,
            stripe_idx as u64,
            shards,
            rdma.map(|rdma| crate::stripe::RdmaStripe {
                rdma,
                base: rdma_base,
            }),
            Some(&mut pending),
        )
        .await
        {
            Ok(locs) => locs,
            Err(short) => {
                error!("{bucket}/{key}: stripe {stripe_idx}: {short}");
                return crate::stripe::refused(&short, stripe_idx as u64);
            }
        };
        all_stripes.push(scheme.stripe(
            stripe_idx as u64,
            stripe_data_size,
            object_id.to_vec(),
            shard_locs,
        ));
    }
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

    let written = Written {
        object_id,
        size: original_size,
        stripes: all_stripes,
        etag,
        checksum: checksums
            .flexible
            .as_ref()
            .map(|f| (f.algorithm, f.value_b64())),
        inline_data: if inline { body.to_vec() } else { Vec::new() },
        sent: pending.disarm(),
        small,
        dedup: Some(body),
    };
    finish_put(&state, &bucket, &key, &headers, plan, written, &mut phases).await
}

/// The length a streamed upload's request declares for its payload
/// (`Content-Length`, which the chunked decoder sets to the decoded
/// length), if it does.
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
}

/// A body read up to its first stripe that ended there: the bytes, with
/// its checksum trailers as headers, for the path a body read whole takes.
pub(crate) enum FirstStripe {
    /// The whole body; the request's headers with its trailers.
    Whole(Bytes, HeaderMap),
    /// More follows: the reader has it all, the first stripe put back.
    More,
}

/// Read a streamed body's first stripe, and whether that was all of it: a
/// body that small is stored as any of its size is (inline, small shards,
/// one stripe), on the path that reads bodies whole.
pub(crate) async fn first_stripe(
    reader: &mut super::stream::BodyReader,
    size: usize,
    headers: &HeaderMap,
) -> Result<FirstStripe, Response> {
    let refused = |e: axum::Error| crate::admission::body_refused(&e);
    let first = reader.next(size).await.map_err(refused)?;
    if reader.at_end().await.map_err(refused)? {
        let mut headers = headers.clone();
        if let Some(t) = reader.trailers.take() {
            headers.extend(t);
        }
        return Ok(FirstStripe::Whole(
            first.map(bytes::BytesMut::freeze).unwrap_or_default(),
            headers,
        ));
    }
    if let Some(first) = first {
        reader.unread(first.freeze());
    }
    Ok(FirstStripe::More)
}

/// A PUT whose body is streamed ([`crate::admission::Streamed`]): written
/// to the shards stripe by stripe as it arrives, never held whole, and
/// committed once all of it has arrived and passed its checks.
pub(crate) async fn put_object_streamed(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let tags = match tagging_header(&headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let checksums = match crate::checksum::RequestChecksums::from_headers(&headers) {
        Ok(c) => c,
        Err(e) => return S3Error::xml_response(e.code(), &e.message(), StatusCode::BAD_REQUEST),
    };
    let declared = declared_length(&headers);
    let mut phases = crate::gateway_metrics::PhaseTimer::start("PutObject");
    let plan = match plan_put(
        &state,
        &bucket,
        &key,
        &auth,
        &headers,
        tags,
        declared.unwrap_or(0),
    )
    .await
    {
        Ok(plan) => plan,
        Err(resp) => return resp,
    };
    phases.mark("meta_lookup");
    let scheme = crate::stripe::Scheme::of(&plan.placement);
    // What it holds of its body, reserved before a byte of it is read.
    let Some(window) = state
        .admission
        .budget
        .try_reserve(super::stream::window(scheme, declared))
    else {
        return crate::admission::slow_down("memory");
    };
    let mut reader = super::stream::BodyReader::new(body);
    match first_stripe(&mut reader, super::stream::stripe_size(scheme), &headers).await {
        Err(resp) => return resp,
        Ok(FirstStripe::Whole(body, headers)) => {
            drop(plan);
            return put_object(State(state), Path((bucket, key)), auth, headers, body).await;
        }
        Ok(FirstStripe::More) => {}
    }

    let object_id = *Uuid::now_v7().as_bytes();
    let dedup_on = dedup_wanted(&plan.placement);
    let to = super::stream::StreamTo {
        state: &state,
        placement: &plan.placement,
        object_id,
        cipher: plan.sse.cipher(),
        rdma: true,
        dedup: (dedup_on && !plan.sse.encrypts())
            .then_some((bucket.as_str(), plan.placement.dedup_domain.as_str())),
        what: format!("{bucket}/{key}"),
    };
    let streamed = match super::stream::stream_stripes(
        to,
        &mut reader,
        crate::checksum::StreamingChecksums::new(checksums, None),
        window,
    )
    .await
    {
        Ok(s) => s,
        Err(resp) => {
            crate::stripe::stale_streamed(&bucket, &key, &resp);
            return resp;
        }
    };
    phases.mark("shards");
    // A length not known up front is held to the quota now, before it is
    // committed.
    if declared.is_none()
        && let Some(refused) = crate::quota::check(&bucket, streamed.size, 1)
    {
        return refused;
    }
    if dedup_on && plan.sse.encrypts() {
        crate::gateway_metrics::record_dedup_skipped("encrypted");
    }
    debug!(
        "PUT object: {bucket}/{key}, {} bytes streamed in {} stripes",
        streamed.size,
        streamed.stripes.len()
    );
    let written = Written {
        object_id,
        size: streamed.size,
        stripes: streamed.stripes,
        etag: format!("\"{}\"", hex::encode(streamed.checksums.md5)),
        checksum: streamed.checksums.sent(),
        inline_data: Vec::new(),
        sent: streamed.sent.disarm(),
        small: None,
        dedup: None,
    };
    finish_put(&state, &bucket, &key, &headers, plan, written, &mut phases).await
}

/// A request body that the admission layer has already read whole, as
/// one buffer.
async fn whole(body: Body) -> Result<Bytes, Response> {
    axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| crate::admission::body_refused(&e))
}

/// PUT /{bucket}/{key}?uploadId=X&partNumber=N - Upload part
pub async fn put_object_with_params(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<PutObjectParams>,
    auth: Option<Extension<AuthResult>>,
    streamed: Option<Extension<crate::admission::Streamed>>,
    headers: HeaderMap,
    body: Body,
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
        if streamed.is_some() {
            return upload_part_streamed(state, bucket, key, upload_id, part_number, headers, body)
                .await;
        }
        let body = match whole(body).await {
            Ok(b) => b,
            Err(resp) => return resp,
        };
        return upload_part_internal(state, bucket, key, upload_id, part_number, headers, body)
            .await;
    }
    if params.acl.is_some() {
        let body = match whole(body).await {
            Ok(b) => b,
            Err(resp) => return resp,
        };
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
        let body = match whole(body).await {
            Ok(b) => b,
            Err(resp) => return resp,
        };
        return put_object_retention_internal(state, bucket, key, body, &headers).await;
    }
    if params.legal_hold.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        let body = match whole(body).await {
            Ok(b) => b,
            Err(resp) => return resp,
        };
        return put_object_legal_hold_internal(state, bucket, key, body).await;
    }
    if params.tagging.is_some() {
        if let Some(refused) =
            unless_current(&state, &bucket, &key, params.version_id.as_deref()).await
        {
            return refused;
        }
        let body = match whole(body).await {
            Ok(b) => b,
            Err(resp) => return resp,
        };
        return put_object_tagging_internal(state, bucket, key, body).await;
    }

    // Otherwise, it's a regular PUT object
    if streamed.is_some() {
        return put_object_streamed(state, bucket, key, auth, headers, body).await;
    }
    let body = match whole(body).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
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
/// placement, in one meta call (`GetWriteContext`, B21).
async fn write_context(
    meta_client: &mut MetadataServiceClient<Channel>,
    bucket: &str,
    key: &str,
    size: u64,
) -> Result<WriteContext, tonic::Status> {
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
        .await?
        .into_inner();
    Ok(WriteContext {
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
