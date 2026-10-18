//! Version ids: minting, ordering, finding a version.

use super::*;

/// A new version's id: a UUIDv7, so ids sort by when they were made, and
/// "newest" is the same on every OSD and gateway that lists them.
pub(crate) fn new_version_id() -> String {
    Uuid::now_v7().to_string()
}

/// Where a version sorts among its key's: when it was made, in ms. A
/// UUIDv7 id carries it; the null version and older ids use its
/// modification time.
/// When a version was written, in unix milliseconds.
pub(crate) fn version_time_ms(object: &ObjectMeta) -> u64 {
    version_age(object).0
}

/// A key's versions newest first, each once (it may be read from several
/// OSDs of its home).
pub(crate) fn sort_versions(versions: &mut Vec<ObjectMeta>) {
    versions.sort_by(|a, b| version_age(b).cmp(&version_age(a)));
    versions.dedup_by(|a, b| a.version_id == b.version_id);
}

/// Where a version sorts among its key's: when it was made, in ms. A
/// UUIDv7 version id carries it; the null version has no id, so its object
/// id (a UUIDv7 too) does. `modified_at`, in seconds, is the last resort:
/// a null version timed by it can sort behind a version made later in the
/// same second. The OSDs order versions the same way.
pub(crate) fn version_age(object: &ObjectMeta) -> (u64, &str) {
    let ms_of = |u: Uuid| {
        (u.get_version_num() == 7)
            .then(|| u.get_timestamp())
            .flatten()
            .map(|t| {
                let (secs, nanos) = t.to_unix();
                secs * 1000 + u64::from(nanos / 1_000_000)
            })
    };
    let ms = Uuid::parse_str(&object.version_id)
        .ok()
        .and_then(ms_of)
        .or_else(|| {
            Uuid::from_slice(&object.object_id)
                .ok()
                .and_then(ms_of)
                .filter(|_| object.version_id.is_empty())
        })
        .unwrap_or_else(|| object.modified_at.saturating_mul(1000));
    (ms, object.version_id.as_str())
}

/// A version as S3 names it: the null version is "null".
pub(crate) fn version_label(version_id: &str) -> &str {
    if version_id.is_empty() {
        "null"
    } else {
        version_id
    }
}

/// Version `wanted` of `bucket/key` ("null" is the object stored while
/// versioning was off): the current object if it is that version, else its
/// version entry.
pub(crate) async fn find_version(
    pool: &OsdPool,
    nodes: &[objectio_proto::metadata::NodePlacement],
    bucket: &str,
    key: &str,
    wanted: &str,
) -> Result<Option<ObjectMeta>, crate::osd_pool::OsdPoolError> {
    if wanted == "null"
        && let Some(current) = get_object_meta_from_any(pool, nodes, bucket, key).await?
        && current.version_id.is_empty()
    {
        return Ok(Some(current));
    }
    get_object_version_meta_from_any(pool, nodes, bucket, key, wanted).await
}
