//! `GET /_admin/meta/export`: a backup of meta's whole state machine, as
//! the leader streams it (objectio-docs core/meta.md, "Backup, restore and
//! losing a majority"). System admin only. The body is the backup file;
//! `obioctl meta export` checks it as it arrives.

use std::sync::Arc;

use axum::Extension;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::StreamExt as _;
use objectio_auth::AuthResult;
use objectio_proto::metadata::ExportMetaRequest;
use serde_json::json;

use crate::s3::AppState;

/// `GET /_admin/meta/export`
pub async fn export(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    let who = match crate::upgrade::system_admin(&auth, &headers) {
        Ok(w) => w,
        Err(r) => return r,
    };
    let chunks = match state
        .meta_client
        .clone()
        .export_meta(ExportMetaRequest { requested_by: who })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) if e.code() == tonic::Code::Unimplemented => {
            return (
                StatusCode::NOT_IMPLEMENTED,
                axum::Json(json!({
                    "error": "this cluster's meta leader runs a release without backups: \
                              upgrade every meta node first"
                })),
            )
                .into_response();
        }
        Err(e) => return crate::upgrade::meta_error(&e),
    };
    // A failure part way ends the body short, as an error: the client sees
    // a transfer that didn't finish, never a file that looks whole.
    let body = chunks.map(|r| {
        r.map(|c| bytes::Bytes::from(c.data))
            .map_err(|e| std::io::Error::other(format!("meta export: {}", e.message())))
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"objectio-meta.backup\"",
        )
        .body(Body::from_stream(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
