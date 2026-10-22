//! `/_admin/test/*` endpoints for faults no client can cause, mounted only
//! with `--test-hooks`.

use crate::AppState;
use crate::osd_pool::{get_object_meta_from_any, read_shard_from_osd, write_shard_to_osd};
use axum::Json;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use objectio_auth::AuthResult;
use objectio_proto::metadata::{GetPlacementRequest, NodePlacement};
use std::sync::Arc;

#[derive(serde::Deserialize)]
pub struct RewriteShard {
    bucket: String,
    key: String,
    position: u32,
    /// Record the wrong bytes' checksum in the object as well, as their
    /// writer would have: what a parity shard written by another codec is
    /// to this gateway, which every read check then passes.
    #[serde(default)]
    record: bool,
    /// Which of the object's stripes (by index; the first by default).
    #[serde(default)]
    stripe: usize,
}

/// `POST /_admin/test/rewrite-shard`: store wrong bytes for one shard of
/// one of an object's stripes, on the OSD that holds it, as a bad rebuild
/// would: the OSD takes them with a checksum of their own, so its checks
/// pass (B23). With `record`, the object's checksum of the shard is theirs
/// too.
pub async fn rewrite_shard(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(req): Json<RewriteShard>,
) -> Response {
    let caller = crate::admin::extract_caller(&auth, &headers);
    if !crate::admin::is_system_admin(&caller) {
        return (StatusCode::FORBIDDEN, "system admin only").into_response();
    }
    let fail = |e: String| (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    let placement = match state
        .meta_client
        .clone()
        .get_placement(GetPlacementRequest {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            size: 0,
            storage_class: String::new(),
        })
        .await
    {
        Ok(p) => p.into_inner(),
        Err(e) => return fail(e.to_string()),
    };
    let object =
        match get_object_meta_from_any(&state.osd_pool, &placement.nodes, &req.bucket, &req.key)
            .await
        {
            Ok(Some(o)) => o,
            Ok(None) => return (StatusCode::NOT_FOUND, "no such object").into_response(),
            Err(e) => return fail(e.to_string()),
        };
    let Some(stripe) = object.stripes.get(req.stripe) else {
        return fail(format!("no stripe {} (inline?)", req.stripe));
    };
    let Some(loc) = stripe.shards.iter().find(|l| l.position == req.position) else {
        return fail(format!("no shard at position {}", req.position));
    };
    let Some(node) = placement.nodes.iter().find(|n| n.node_id == loc.node_id) else {
        return fail("the shard's OSD is not in the placement".into());
    };
    let target = NodePlacement {
        te_segment: String::new(),
        ..node.clone()
    };
    let shard = match read_shard_from_osd(
        &state.osd_pool,
        &target,
        &stripe.object_id,
        stripe.stripe_id,
        loc.position,
        None,
        None,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return fail(e.to_string()),
    };
    // Every byte wrong, and wrong differently at each position: two parity
    // shards off by one same pattern cancel out in some decodes, which
    // another codec's parity does not.
    let mut x = 0x9E37_79B9_u32 ^ loc.position;
    let wrong: bytes::Bytes = shard
        .iter()
        .map(|b| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            b ^ (u8::try_from(x >> 24).unwrap_or(0) | 1)
        })
        .collect::<Vec<u8>>()
        .into();
    let crc = match write_shard_to_osd(
        &state.osd_pool,
        &target,
        &stripe.object_id,
        stripe.stripe_id,
        loc.position,
        wrong,
        stripe.ec_k,
        stripe.ec_m,
        None,
        None,
    )
    .await
    {
        Ok((_, crc)) => crc,
        Err(e) => return fail(e.to_string()),
    };
    if !req.record {
        return StatusCode::NO_CONTENT.into_response();
    }
    let position = loc.position;
    let expected = object.object_id.clone();
    let mut object = object;
    if let Some(l) = object.stripes[req.stripe]
        .shards
        .iter_mut()
        .find(|l| l.position == position)
    {
        l.crc32c = Some(crc);
    }
    match crate::osd_pool::put_object_meta_to_all(
        &state.osd_pool,
        &placement.nodes,
        &req.bucket,
        &req.key,
        object,
        false,
        &expected,
    )
    .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => fail(e.error.to_string()),
    }
}

/// Calls to meta (or, for `put_object_meta`, to an OSD) whose next answer
/// is lost on purpose, by name.
static LOSE_REPLY: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

#[derive(serde::Deserialize)]
pub struct LoseReply {
    call: String,
}

/// `POST /_admin/test/lose-reply`: the next answer meta gives to `call`
/// (applied there) is taken as lost, as a leader change or a timeout loses
/// one: the gateway sees UNAVAILABLE for a call meta did apply. For
/// `put_object_meta`, the next answer of one OSD copy; asked n times, n
/// copies'.
pub async fn lose_reply(
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(req): Json<LoseReply>,
) -> Response {
    let caller = crate::admin::extract_caller(&auth, &headers);
    if !crate::admin::is_system_admin(&caller) {
        return (StatusCode::FORBIDDEN, "system admin only").into_response();
    }
    LOSE_REPLY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(req.call);
    StatusCode::NO_CONTENT.into_response()
}

/// `answer`, unless a test asked for the next answer to `call` to be lost
/// (only ever with `--test-hooks`).
#[allow(clippy::result_large_err)] // tonic's own error type, passed through
pub fn maybe_lost<T>(call: &str, answer: Result<T, tonic::Status>) -> Result<T, tonic::Status> {
    let mut lose = LOSE_REPLY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match lose.iter().position(|c| c == call) {
        Some(i) if answer.is_ok() => {
            lose.remove(i);
            Err(tonic::Status::unavailable(format!(
                "{call}: answer lost (test hook)"
            )))
        }
        _ => answer,
    }
}

/// PUTs and UploadParts to hold, by "bucket/key", after they are placed:
/// how long.
static HOLD_PLACED: std::sync::Mutex<Vec<(String, u64)>> = std::sync::Mutex::new(Vec::new());

#[derive(serde::Deserialize)]
pub struct HoldPlaced {
    bucket: String,
    key: String,
    millis: u64,
}

/// `POST /_admin/test/hold-placed`: the next PUT or UploadPart of
/// `bucket/key` waits `millis` between being placed and writing anything,
/// so a test can change the placement group's acting set meanwhile (B31):
/// the write is then placed under an epoch that is no longer current.
pub async fn hold_placed(
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(req): Json<HoldPlaced>,
) -> Response {
    let caller = crate::admin::extract_caller(&auth, &headers);
    if !crate::admin::is_system_admin(&caller) {
        return (StatusCode::FORBIDDEN, "system admin only").into_response();
    }
    HOLD_PLACED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((format!("{}/{}", req.bucket, req.key), req.millis));
    StatusCode::NO_CONTENT.into_response()
}

/// Wait, if a test asked the next PUT or UploadPart of `bucket/key` to
/// (only ever with `--test-hooks`).
pub async fn held_after_placement(bucket: &str, key: &str) {
    let millis = {
        let mut held = HOLD_PLACED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let name = format!("{bucket}/{key}");
        let Some(i) = held.iter().position(|(k, _)| *k == name) else {
            return;
        };
        held.remove(i).1
    };
    tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
}
