//! Rolling upgrades, for the operator (objectio-docs core/upgrade-path.md):
//!
//! - `GET /_admin/upgrade`: every node's release and format level, the
//!   cluster's active level, and what finalize would do (or why not);
//! - `POST /_admin/upgrade/finalize`: raise the active level once every
//!   node runs the new release.
//!
//! System admin only.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use objectio_auth::AuthResult;
use objectio_proto::metadata::{FinalizeUpgradeRequest, GetUpgradeStatusRequest};
use serde_json::json;

use crate::s3::AppState;

#[allow(clippy::result_large_err)]
fn system_admin(
    auth: &Option<Extension<AuthResult>>,
    headers: &HeaderMap,
) -> Result<String, Response> {
    let caller = crate::admin::extract_caller(auth, headers);
    if crate::admin::is_system_admin(&caller) {
        Ok(caller.user_id)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "system admin only"})),
        )
            .into_response())
    }
}

fn meta_error(e: &tonic::Status) -> Response {
    let status = match e.code() {
        tonic::Code::FailedPrecondition => StatusCode::CONFLICT,
        tonic::Code::Aborted => StatusCode::CONFLICT,
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({"error": e.message()}))).into_response()
}

/// `GET /_admin/upgrade`
pub async fn status(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = system_admin(&auth, &headers) {
        return r;
    }
    match state
        .meta_client
        .clone()
        .get_upgrade_status(GetUpgradeStatusRequest {})
        .await
    {
        Ok(r) => {
            let r = r.into_inner();
            let nodes: Vec<_> = r
                .nodes
                .iter()
                .map(|n| {
                    json!({
                        "kind": n.kind,
                        "id": n.id,
                        "release": n.release,
                        "format_level": n.format_level,
                        "min_level": n.min_level,
                        "address": n.address,
                        "seen_secs_ago": n.seen_secs_ago,
                    })
                })
                .collect();
            Json(json!({
                "active_level": r.active_level,
                "finalize_to": r.finalize_to,
                "can_finalize": r.blockers.is_empty() && r.finalize_to > r.active_level,
                "blockers": r.blockers,
                "nodes": nodes,
            }))
            .into_response()
        }
        Err(e) => meta_error(&e),
    }
}

/// `POST /_admin/upgrade/finalize`
pub async fn finalize(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    let who = match system_admin(&auth, &headers) {
        Ok(w) => w,
        Err(r) => return r,
    };
    match state
        .meta_client
        .clone()
        .finalize_upgrade(FinalizeUpgradeRequest { requested_by: who })
        .await
    {
        Ok(r) => Json(json!({"active_level": r.into_inner().active_level})).into_response(),
        Err(e) => meta_error(&e),
    }
}
