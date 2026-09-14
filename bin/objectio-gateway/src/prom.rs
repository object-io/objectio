//! Prometheus query proxy for the console.
//!
//! The console needs history the gateway cannot provide. `/metrics` is a
//! point-in-time scrape, so a browser polling it can only ever know what has
//! happened since the page opened — about five minutes at the console's
//! interval. Anything the design asks for beyond that (1h, 24h, 30d) and
//! anything labelled per node or per gateway lives in Prometheus, which
//! already scrapes the gateway, every meta node and every OSD.
//!
//! The browser cannot query Prometheus itself: it is usually on a private
//! network, has no CORS headers, and no notion of who the caller is. So the
//! gateway forwards, and in doing so puts the query behind the same admin
//! check as the rest of the console.
//!
//! When `--prometheus-url` is unset the endpoints report that they are not
//! configured and the console falls back to scraping `/metrics` live. That
//! keeps Prometheus optional rather than a new hard dependency.

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

use crate::s3::AppState;

/// Upper bound on a single range query's point count.
///
/// Prometheus itself caps at 11 000; asking for more is always a mistake in
/// the caller's step calculation, and the error it returns is unhelpful.
const MAX_POINTS: f64 = 11_000.0;

#[derive(Debug, Deserialize)]
pub struct InstantQuery {
    pub query: String,
    /// RFC3339 or a unix timestamp. Omitted means now.
    #[serde(default)]
    pub time: String,
}

#[derive(Debug, Deserialize)]
pub struct RangeQuery {
    pub query: String,
    pub start: String,
    pub end: String,
    /// Step in seconds.
    pub step: String,
}

fn not_configured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "prometheus_not_configured",
            "message": "This gateway has no --prometheus-url. Historical ranges and \
                        per-node series need Prometheus; the console falls back to a \
                        live scrape of /metrics without it.",
        })),
    )
        .into_response()
}

/// `GET /_console/api/metrics/capabilities`
///
/// Lets the console decide which view to render before it asks for data,
/// rather than discovering the gap through a failed query.
pub async fn capabilities(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "prometheus": !state.prometheus_url.is_empty(),
        // What the live-scrape fallback can offer, so the console does not have
        // to hardcode its own limits.
        "live_scrape": {
            "interval_seconds": 5,
            "max_points": 60,
        },
    }))
}

/// `GET /_console/api/metrics/query` — instant query.
pub async fn query(
    State(state): State<Arc<AppState>>,
    auth: Option<axum::Extension<objectio_auth::AuthResult>>,
    headers: HeaderMap,
    Query(q): Query<InstantQuery>,
) -> Response {
    if let Some(deny) = crate::admin::require_admin_or_session(&auth, &headers) {
        return deny;
    }
    if state.prometheus_url.is_empty() {
        return not_configured();
    }
    let mut params = vec![("query", q.query)];
    if !q.time.is_empty() {
        params.push(("time", q.time));
    }
    forward(&state.prometheus_url, "/api/v1/query", &params).await
}

/// `GET /_console/api/metrics/query_range` — range query.
pub async fn query_range(
    State(state): State<Arc<AppState>>,
    auth: Option<axum::Extension<objectio_auth::AuthResult>>,
    headers: HeaderMap,
    Query(q): Query<RangeQuery>,
) -> Response {
    if let Some(deny) = crate::admin::require_admin_or_session(&auth, &headers) {
        return deny;
    }
    if state.prometheus_url.is_empty() {
        return not_configured();
    }

    // Reject an over-wide range here rather than letting Prometheus answer
    // with its own generic exceeded-maximum error.
    if let (Ok(start), Ok(end), Ok(step)) = (
        q.start.parse::<f64>(),
        q.end.parse::<f64>(),
        q.step.parse::<f64>(),
    ) && step > 0.0
        && (end - start) / step > MAX_POINTS
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "range_too_wide",
                "message": format!(
                    "{} points requested; widen the step or narrow the range \
                     (max {MAX_POINTS})",
                    ((end - start) / step) as i64
                ),
            })),
        )
            .into_response();
    }

    let params = vec![
        ("query", q.query),
        ("start", q.start),
        ("end", q.end),
        ("step", q.step),
    ];
    forward(&state.prometheus_url, "/api/v1/query_range", &params).await
}

/// Pass a query to Prometheus and hand back its answer verbatim.
///
/// The body is returned unchanged so the console can use the standard
/// Prometheus response shape, and a failure names the upstream rather than
/// reporting a generic gateway error for something that went wrong elsewhere.
async fn forward(base: &str, path: &str, params: &[(&str, String)]) -> Response {
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let client = reqwest::Client::new();
    match client.get(&url).query(params).send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let body = resp.text().await.unwrap_or_default();
            (
                status,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }
        Err(e) => {
            warn!("Prometheus query to {url} failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "prometheus_unreachable",
                    "message": format!("Could not reach Prometheus at {base}: {e}"),
                })),
            )
                .into_response()
        }
    }
}

/// Unused today but kept alongside the proxy: the label set the console asks
/// for when building filter dropdowns.
#[allow(dead_code)]
pub fn label_values_path(label: &str) -> String {
    format!("/api/v1/label/{label}/values")
}

#[allow(dead_code)]
type Params = HashMap<String, String>;
