//! Metrics middleware for automatic S3 operation tracking
//!
//! Intercepts all requests and records metrics based on HTTP method and path patterns.

use crate::s3_metrics::{IcebergOperation, S3Operation, UnityOperation, s3_metrics};
use axum::{body::Body, extract::Request, http::Method, middleware::Next, response::Response};
use std::time::Instant;

/// Extract S3 operation type from HTTP method and path
fn extract_operation(method: &Method, path: &str) -> Option<S3Operation> {
    // Remove query string
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_start_matches('/');

    // Split path into segments
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match (method, segments.as_slice()) {
        // Service level (GET /)
        (m, []) if m == Method::GET => Some(S3Operation::ListBuckets),

        // Bucket operations (GET/PUT/DELETE/HEAD /{bucket})
        (m, [_bucket]) if m == Method::GET => Some(S3Operation::ListObjects),
        (m, [_bucket]) if m == Method::PUT => Some(S3Operation::CreateBucket),
        (m, [_bucket]) if m == Method::DELETE => Some(S3Operation::DeleteBucket),
        (m, [_bucket]) if m == Method::HEAD => Some(S3Operation::HeadBucket),
        (m, [_bucket]) if m == Method::POST => {
            // POST /{bucket}?delete is batch delete - treat as DeleteObjects
            Some(S3Operation::DeleteObjects)
        }

        // Object operations (GET/PUT/DELETE/HEAD/POST /{bucket}/{key...})
        (m, [_bucket, ..]) if m == Method::GET => Some(S3Operation::GetObject),
        (m, [_bucket, ..]) if m == Method::PUT => Some(S3Operation::PutObject),
        (m, [_bucket, ..]) if m == Method::DELETE => Some(S3Operation::DeleteObject),
        (m, [_bucket, ..]) if m == Method::HEAD => Some(S3Operation::HeadObject),
        (m, [_bucket, ..]) if m == Method::POST => {
            // POST on object path could be multipart initiate/complete
            Some(S3Operation::InitiateMultipartUpload)
        }

        // Skip admin and metrics endpoints
        _ => None,
    }
}

/// Check whether `query` carries `name` as a parameter key in its own
/// right. Substring matching would misread `?prefix=uploads/` as a
/// ListMultipartUploads request.
fn has_query_flag(query: &str, name: &str) -> bool {
    query
        .split('&')
        .any(|pair| pair.split('=').next() == Some(name))
}

/// S3's sub-resources: a request naming one reads or sets that part of
/// a bucket or object (`?policy`, `?tagging`…) rather than its data or
/// listing. Anything else in a query (list parameters, `versionId`,
/// presigned-URL signatures, `response-*` overrides) leaves the operation
/// as it is.
const SUBRESOURCES: &[&str] = &[
    "accelerate",
    "acl",
    "analytics",
    "attributes",
    "cors",
    "encryption",
    "intelligent-tiering",
    "inventory",
    "legal-hold",
    "lifecycle",
    "location",
    "logging",
    "metrics",
    "notification",
    "object-lock",
    "ownershipControls",
    "policy",
    "policyStatus",
    "publicAccessBlock",
    "replication",
    "requestPayment",
    "restore",
    "retention",
    "tagging",
    "versioning",
    "website",
];

/// Whether `query` names a sub-resource.
fn names_subresource(query: &str) -> bool {
    SUBRESOURCES.iter().any(|r| has_query_flag(query, r))
}

/// Refine operation type from the query, and from whether the request
/// names a copy source (`x-amz-copy-source`).
fn refine_operation(op: S3Operation, query: Option<&str>, copy: bool) -> S3Operation {
    let query = query.unwrap_or_default();
    let multipart = has_query_flag(query, "uploadId");
    match op {
        S3Operation::PutObject if multipart && copy => S3Operation::UploadPartCopy,
        S3Operation::PutObject if multipart => S3Operation::UploadPart,
        S3Operation::PutObject if names_subresource(query) => S3Operation::PutObjectConfig,
        S3Operation::PutObject if copy => S3Operation::CopyObject,
        S3Operation::GetObject if multipart => S3Operation::ListParts,
        S3Operation::GetObject if names_subresource(query) => S3Operation::GetObjectConfig,
        S3Operation::HeadObject if names_subresource(query) => S3Operation::GetObjectConfig,
        S3Operation::DeleteObject if multipart => S3Operation::AbortMultipartUpload,
        S3Operation::DeleteObject if names_subresource(query) => S3Operation::DeleteObjectConfig,
        S3Operation::InitiateMultipartUpload if multipart => S3Operation::CompleteMultipartUpload,
        S3Operation::ListObjects if has_query_flag(query, "uploads") => {
            S3Operation::ListMultipartUploads
        }
        S3Operation::ListObjects if has_query_flag(query, "versions") => {
            S3Operation::ListObjectVersions
        }
        S3Operation::ListObjects if names_subresource(query) => S3Operation::GetBucketConfig,
        S3Operation::CreateBucket if names_subresource(query) => S3Operation::PutBucketConfig,
        S3Operation::DeleteBucket if names_subresource(query) => S3Operation::DeleteBucketConfig,
        S3Operation::DeleteObjects if !has_query_flag(query, "delete") => S3Operation::PostObject,
        _ => op,
    }
}

/// Extract Iceberg operation type from HTTP method and path (without /iceberg prefix).
fn extract_iceberg_operation(method: &Method, path: &str) -> Option<IcebergOperation> {
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match (method, segments.as_slice()) {
        // GET /v1/config
        (m, ["v1", "config"]) if m == Method::GET => Some(IcebergOperation::GetConfig),
        // GET /v1/namespaces
        (m, ["v1", "namespaces"]) if m == Method::GET => Some(IcebergOperation::ListNamespaces),
        // POST /v1/namespaces
        (m, ["v1", "namespaces"]) if m == Method::POST => Some(IcebergOperation::CreateNamespace),
        // POST /v1/tables/rename
        (m, ["v1", "tables", "rename"]) if m == Method::POST => Some(IcebergOperation::RenameTable),
        // POST /v1/namespaces/{ns}/properties
        (m, ["v1", "namespaces", _ns, "properties"]) if m == Method::POST => {
            Some(IcebergOperation::UpdateNamespaceProperties)
        }
        // GET /v1/namespaces/{ns}/tables
        (m, ["v1", "namespaces", _ns, "tables"]) if m == Method::GET => {
            Some(IcebergOperation::ListTables)
        }
        // POST /v1/namespaces/{ns}/tables
        (m, ["v1", "namespaces", _ns, "tables"]) if m == Method::POST => {
            Some(IcebergOperation::CreateTable)
        }
        // GET /v1/namespaces/{ns}/tables/{table}
        (m, ["v1", "namespaces", _ns, "tables", _table]) if m == Method::GET => {
            Some(IcebergOperation::LoadTable)
        }
        // POST /v1/namespaces/{ns}/tables/{table}
        (m, ["v1", "namespaces", _ns, "tables", _table]) if m == Method::POST => {
            Some(IcebergOperation::UpdateTable)
        }
        // HEAD /v1/namespaces/{ns}/tables/{table}
        (m, ["v1", "namespaces", _ns, "tables", _table]) if m == Method::HEAD => {
            Some(IcebergOperation::TableExists)
        }
        // DELETE /v1/namespaces/{ns}/tables/{table}
        (m, ["v1", "namespaces", _ns, "tables", _table]) if m == Method::DELETE => {
            Some(IcebergOperation::DropTable)
        }
        // GET /v1/namespaces/{ns}
        (m, ["v1", "namespaces", _ns]) if m == Method::GET => Some(IcebergOperation::LoadNamespace),
        // HEAD /v1/namespaces/{ns}
        (m, ["v1", "namespaces", _ns]) if m == Method::HEAD => {
            Some(IcebergOperation::NamespaceExists)
        }
        // DELETE /v1/namespaces/{ns}
        (m, ["v1", "namespaces", _ns]) if m == Method::DELETE => {
            Some(IcebergOperation::DropNamespace)
        }
        _ => None,
    }
}

/// Extract Unity Catalog operation type from HTTP method and path
/// (full path including the `/api/2.1/unity-catalog` prefix). The
/// router uses absolute paths under that prefix, so we match against
/// segments after the prefix.
fn extract_unity_operation(method: &Method, path: &str) -> Option<UnityOperation> {
    let path = path.split('?').next().unwrap_or(path);
    let rest = path.strip_prefix("/api/2.1/unity-catalog")?;
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();

    match (method, segments.as_slice()) {
        // Catalogs
        (m, ["catalogs"]) if m == Method::GET => Some(UnityOperation::ListCatalogs),
        (m, ["catalogs"]) if m == Method::POST => Some(UnityOperation::CreateCatalog),
        (m, ["catalogs", _name]) if m == Method::GET => Some(UnityOperation::GetCatalog),
        (m, ["catalogs", _name]) if m == Method::PATCH => Some(UnityOperation::UpdateCatalog),
        (m, ["catalogs", _name]) if m == Method::DELETE => Some(UnityOperation::DeleteCatalog),
        // Schemas
        (m, ["schemas"]) if m == Method::GET => Some(UnityOperation::ListSchemas),
        (m, ["schemas"]) if m == Method::POST => Some(UnityOperation::CreateSchema),
        (m, ["schemas", _full]) if m == Method::GET => Some(UnityOperation::GetSchema),
        (m, ["schemas", _full]) if m == Method::PATCH => Some(UnityOperation::UpdateSchema),
        (m, ["schemas", _full]) if m == Method::DELETE => Some(UnityOperation::DeleteSchema),
        // Tables
        (m, ["tables"]) if m == Method::GET => Some(UnityOperation::ListTables),
        (m, ["tables"]) if m == Method::POST => Some(UnityOperation::CreateTable),
        (m, ["tables", _full]) if m == Method::GET => Some(UnityOperation::GetTable),
        (m, ["tables", _full]) if m == Method::DELETE => Some(UnityOperation::DeleteTable),
        // Vended credentials
        (m, ["temporary-table-credentials"]) if m == Method::POST => {
            Some(UnityOperation::TemporaryTableCredentials)
        }
        // Policy management endpoints share the catalog/schema/table
        // counter — they're rare admin actions, not worth a separate
        // operation label.
        _ => None,
    }
}

/// Metrics middleware that records S3 operation metrics
pub async fn metrics_layer(request: Request<Body>, next: Next) -> Response {
    let start = Instant::now();

    // Extract operation type from request
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path();
    let query = uri.query();

    // Skip metrics and health endpoints
    if path == "/metrics" || path == "/health" || path == "/_ready" || path.starts_with("/_admin") {
        return next.run(request).await;
    }

    // Catalog and console paths look like S3 buckets to the segment matcher
    // (e.g. `/iceberg/v1/...` parses as bucket=`iceberg`). Dispatch them
    // first so they're recorded under the right metric family instead of
    // bleeding into S3 GetObject/PutObject counters.
    let iceberg_operation = path
        .strip_prefix("/iceberg")
        .and_then(|iceberg_path| extract_iceberg_operation(&method, iceberg_path));
    let unity_operation = if iceberg_operation.is_none() {
        extract_unity_operation(&method, path)
    } else {
        None
    };
    let is_catalog = iceberg_operation.is_some()
        || unity_operation.is_some()
        || path.starts_with("/iceberg")
        || path.starts_with("/api/2.1/unity-catalog")
        || path.starts_with("/delta-sharing")
        || path.starts_with("/_console");

    // Determine S3 operation type — only if the path isn't claimed by a
    // non-S3 surface above.
    let s3_operation = if is_catalog {
        None
    } else {
        let copy = request.headers().contains_key("x-amz-copy-source");
        extract_operation(&method, path).map(|op| refine_operation(op, query, copy))
    };

    // Get request body size from Content-Length header
    let request_bytes = request
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let _in_flight = s3_operation.map(|op| {
        if request_bytes > 0 {
            crate::gateway_metrics::record_request_size(op.as_str(), request_bytes);
        }
        crate::gateway_metrics::InFlight::start(op.as_str())
    });

    // Run the handler
    let response = next.run(request).await;

    let status_code = response.status().as_u16();
    if let Some(op) = s3_operation
        && status_code >= 400
    {
        let error = response
            .extensions()
            .get::<crate::gateway_metrics::S3ErrorCode>()
            .map(|e| e.0.as_str());
        crate::gateway_metrics::record_error(op.as_str(), status_code, error);
    }
    let latency_us = start.elapsed().as_micros() as u64;

    // Record metrics for S3 or Iceberg operation
    if let Some(op) = s3_operation {
        let response_bytes = response
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        s3_metrics().record_operation(op, status_code, request_bytes, response_bytes, latency_us);
    } else if let Some(op) = iceberg_operation {
        s3_metrics().record_iceberg_operation(op, status_code, latency_us);
    } else if let Some(op) = unity_operation {
        s3_metrics().record_unity_operation(op, status_code, latency_us);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(method: &Method, uri: &str, copy: bool) -> &'static str {
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        refine_operation(extract_operation(method, path).unwrap(), Some(query), copy).as_str()
    }

    #[test]
    fn requests_are_named_as_s3_names_them() {
        let (get, put, post, del) = (&Method::GET, &Method::PUT, &Method::POST, &Method::DELETE);
        assert_eq!(op(put, "/b/k", false), "PutObject");
        assert_eq!(op(put, "/b/k", true), "CopyObject");
        assert_eq!(op(put, "/b/k?partNumber=1&uploadId=u", false), "UploadPart");
        assert_eq!(
            op(put, "/b/k?partNumber=1&uploadId=u", true),
            "UploadPartCopy"
        );
        assert_eq!(op(put, "/b/k?tagging", false), "PutObjectConfig");
        assert_eq!(op(get, "/b/k?uploadId=u", false), "ListParts");
        assert_eq!(op(get, "/b/k?versionId=v", false), "GetObject");
        assert_eq!(
            op(get, "/b/k?X-Amz-Signature=s&response-content-type=t", false),
            "GetObject"
        );
        assert_eq!(op(get, "/b/k?tagging", false), "GetObjectConfig");
        assert_eq!(op(del, "/b/k?uploadId=u", false), "AbortMultipartUpload");
        assert_eq!(op(post, "/b/k?uploads", false), "InitiateMultipartUpload");
        assert_eq!(
            op(post, "/b/k?uploadId=u", false),
            "CompleteMultipartUpload"
        );
        assert_eq!(op(post, "/b?delete", false), "DeleteObjects");
        assert_eq!(op(post, "/b", false), "PostObject");
        assert_eq!(
            op(get, "/b?list-type=2&prefix=uploads/", false),
            "ListObjects"
        );
        assert_eq!(op(get, "/b?uploads", false), "ListMultipartUploads");
        assert_eq!(op(get, "/b?versions", false), "ListObjectVersions");
        assert_eq!(op(get, "/b?policy", false), "GetBucketConfig");
        assert_eq!(op(put, "/b?versioning", false), "PutBucketConfig");
        assert_eq!(op(put, "/b", false), "CreateBucket");
        assert_eq!(op(del, "/b?lifecycle", false), "DeleteBucketConfig");
    }
}
