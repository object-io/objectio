//! Block Public Access, as S3 has it, at three levels: the bucket, its
//! tenant (S3's account level) and the whole cluster. A flag set at any
//! level holds for the bucket.
//!
//! - `BlockPublicPolicy`: a bucket policy that would make the bucket public
//!   is refused.
//! - `RestrictPublicBuckets`: a public policy already in place grants
//!   nothing to anonymous callers, or to callers outside the bucket's
//!   tenant.
//! - `BlockPublicAcls` / `IgnorePublicAcls`: kept and reported. ACLs are
//!   owner-enforced here, so no ACL can grant public access in the first
//!   place; both hold by construction.
//!
//! New buckets start with every flag set, as S3's have since 2023, unless
//! the operator turns that default off (`new_buckets_blocked: false`).

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use objectio_auth::AuthResult;
use objectio_proto::metadata::{
    DeleteConfigRequest, GetBucketSettingRequest, GetConfigRequest, PutBucketSettingRequest,
    SetConfigRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::s3::{AppState, S3Error};

/// The bucket setting holding a bucket's own block.
pub const SETTING: &str = "public-access-block";

const CLUSTER_KEY: &str = "public-access-block/cluster";

fn tenant_key(tenant: &str) -> String {
    format!("public-access-block/tenant/{tenant}")
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
#[allow(clippy::struct_excessive_bools)] // S3's four flags, as S3 names them.
pub struct PublicAccessBlock {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

impl PublicAccessBlock {
    pub const ALL: Self = Self {
        block_public_acls: true,
        ignore_public_acls: true,
        block_public_policy: true,
        restrict_public_buckets: true,
    };

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            block_public_acls: self.block_public_acls || other.block_public_acls,
            ignore_public_acls: self.ignore_public_acls || other.ignore_public_acls,
            block_public_policy: self.block_public_policy || other.block_public_policy,
            restrict_public_buckets: self.restrict_public_buckets || other.restrict_public_buckets,
        }
    }

    /// A stored setting; anything unreadable blocks everything, the safe
    /// reading of a setting that exists but can't be understood.
    #[must_use]
    pub fn from_stored(bytes: &[u8]) -> Self {
        serde_json::from_slice(bytes).unwrap_or(Self::ALL)
    }

    fn to_stored(self) -> Vec<u8> {
        serde_json::to_vec(&self).unwrap_or_default()
    }

    /// A `PublicAccessBlockConfiguration` document. Absent flags are false.
    fn from_xml(body: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(body).ok()?;
        if !text.contains("PublicAccessBlockConfiguration") {
            return None;
        }
        let flag = |name: &str| -> Option<bool> {
            let open = format!("<{name}>");
            let Some(start) = text.find(&open) else {
                return Some(false);
            };
            let rest = &text[start + open.len()..];
            let end = rest.find(&format!("</{name}>"))?;
            match rest[..end].trim().to_ascii_lowercase().as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            }
        };
        Some(Self {
            block_public_acls: flag("BlockPublicAcls")?,
            ignore_public_acls: flag("IgnorePublicAcls")?,
            block_public_policy: flag("BlockPublicPolicy")?,
            restrict_public_buckets: flag("RestrictPublicBuckets")?,
        })
    }

    fn to_xml(self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <PublicAccessBlockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <BlockPublicAcls>{}</BlockPublicAcls><IgnorePublicAcls>{}</IgnorePublicAcls>\
             <BlockPublicPolicy>{}</BlockPublicPolicy>\
             <RestrictPublicBuckets>{}</RestrictPublicBuckets>\
             </PublicAccessBlockConfiguration>",
            self.block_public_acls,
            self.ignore_public_acls,
            self.block_public_policy,
            self.restrict_public_buckets
        )
    }
}

/// A tenant's or the cluster's stored document, via the cache.
async fn account_doc(state: &AppState, key: &str) -> Option<serde_json::Value> {
    if let Some(doc) = state.policy_cache.account(key) {
        return doc;
    }
    let doc = match state
        .meta_client
        .clone()
        .get_config(GetConfigRequest {
            key: key.to_string(),
        })
        .await
    {
        Ok(r) => r
            .into_inner()
            .entry
            .map(|e| serde_json::from_slice(&e.value).unwrap_or_else(|_| json!({}))),
        // Unknown: don't cache it, and block everything meanwhile.
        Err(_) => return serde_json::to_value(PublicAccessBlock::ALL).ok(),
    };
    state.policy_cache.put_account(key, doc.clone());
    doc
}

fn doc_block(doc: Option<&serde_json::Value>) -> PublicAccessBlock {
    doc.and_then(|d| serde_json::from_value(d.clone()).ok())
        .unwrap_or_default()
}

/// What holds for a bucket in `bucket_tenant` whose own block is `own`.
pub async fn effective(
    state: &AppState,
    bucket_tenant: &str,
    own: PublicAccessBlock,
) -> PublicAccessBlock {
    let cluster = doc_block(account_doc(state, CLUSTER_KEY).await.as_ref());
    let tenant = if bucket_tenant.is_empty() {
        PublicAccessBlock::default()
    } else {
        doc_block(
            account_doc(state, &tenant_key(bucket_tenant))
                .await
                .as_ref(),
        )
    };
    own.union(tenant).union(cluster)
}

/// A bucket's own block, if it has one. Unreadable: everything blocked.
pub async fn bucket_block(state: &AppState, bucket: &str) -> Option<PublicAccessBlock> {
    match state
        .meta_client
        .clone()
        .get_bucket_setting(GetBucketSettingRequest {
            bucket: bucket.to_string(),
            name: SETTING.to_string(),
        })
        .await
    {
        Ok(r) => {
            let r = r.into_inner();
            r.found.then(|| PublicAccessBlock::from_stored(&r.value))
        }
        Err(_) => Some(PublicAccessBlock::ALL),
    }
}

/// The settings a new bucket starts with.
pub async fn initial_settings(state: &AppState) -> HashMap<String, Vec<u8>> {
    let blocked = account_doc(state, CLUSTER_KEY)
        .await
        .and_then(|d| {
            d.get("new_buckets_blocked")
                .and_then(serde_json::Value::as_bool)
        })
        .unwrap_or(true);
    let mut settings = HashMap::new();
    if blocked {
        settings.insert(SETTING.to_string(), PublicAccessBlock::ALL.to_stored());
    }
    settings
}

fn xml_ok(body: String) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(body))
        .unwrap()
}

fn meta_error(e: &tonic::Status) -> Response {
    if e.code() == tonic::Code::NotFound {
        S3Error::xml_response(
            "NoSuchBucket",
            "The specified bucket does not exist",
            StatusCode::NOT_FOUND,
        )
    } else {
        S3Error::xml_response(
            "InternalError",
            e.message(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }
}

/// `GET /{bucket}?publicAccessBlock`
pub async fn get_bucket(state: &AppState, bucket: &str) -> Response {
    if let Err(resp) = crate::s3::bucket_owner(state, bucket).await {
        return resp;
    }
    match bucket_block(state, bucket).await {
        Some(block) => xml_ok(block.to_xml()),
        None => S3Error::xml_response(
            "NoSuchPublicAccessBlockConfiguration",
            "The public access block configuration was not found",
            StatusCode::NOT_FOUND,
        ),
    }
}

/// `PUT /{bucket}?publicAccessBlock`
pub async fn put_bucket(state: &AppState, bucket: &str, body: &[u8]) -> Response {
    let Some(block) = PublicAccessBlock::from_xml(body) else {
        return S3Error::xml_response(
            "MalformedXML",
            "The XML you provided was not well-formed or did not validate",
            StatusCode::BAD_REQUEST,
        );
    };
    write_bucket(state, bucket, Some(block)).await
}

/// `DELETE /{bucket}?publicAccessBlock`
pub async fn delete_bucket(state: &AppState, bucket: &str) -> Response {
    write_bucket(state, bucket, None).await
}

async fn write_bucket(
    state: &AppState,
    bucket: &str,
    block: Option<PublicAccessBlock>,
) -> Response {
    let result = state
        .meta_client
        .clone()
        .put_bucket_setting(PutBucketSettingRequest {
            bucket: bucket.to_string(),
            name: SETTING.to_string(),
            value: block.map(PublicAccessBlock::to_stored).unwrap_or_default(),
            delete: block.is_none(),
        })
        .await;
    state.policy_cache.invalidate(bucket);
    match result {
        Ok(_) if block.is_some() => StatusCode::OK.into_response(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => meta_error(&e),
    }
}

/// Whether the bucket's own block, its tenant's or the cluster's refuses
/// `policy` (a public one) on `bucket`.
pub async fn refuses_policy(
    state: &AppState,
    bucket: &str,
    policy: &objectio_auth::BucketPolicy,
) -> bool {
    if !policy.is_public() {
        return false;
    }
    let tenant = state
        .meta_client
        .clone()
        .get_bucket(objectio_proto::metadata::GetBucketRequest {
            name: bucket.to_string(),
        })
        .await
        .ok()
        .and_then(|r| r.into_inner().bucket)
        .map(|b| b.tenant)
        .unwrap_or_default();
    let own = bucket_block(state, bucket).await.unwrap_or_default();
    effective(state, &tenant, own).await.block_public_policy
}

/// `GET /{bucket}?policyStatus`: whether the bucket's policy makes it public.
pub async fn get_policy_status(state: &AppState, bucket: &str) -> Response {
    if let Err(resp) = crate::s3::bucket_owner(state, bucket).await {
        return resp;
    }
    let policy = state
        .meta_client
        .clone()
        .get_bucket_policy(objectio_proto::metadata::GetBucketPolicyRequest {
            bucket: bucket.to_string(),
        })
        .await
        .ok()
        .map(tonic::Response::into_inner)
        .filter(|r| r.has_policy);
    let Some(policy) = policy else {
        return S3Error::xml_response(
            "NoSuchBucketPolicy",
            "The bucket policy does not exist",
            StatusCode::NOT_FOUND,
        );
    };
    let public =
        objectio_auth::BucketPolicy::from_json(&policy.policy_json).is_ok_and(|p| p.is_public());
    xml_ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <PolicyStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <IsPublic>{public}</IsPublic></PolicyStatus>"
    ))
}

// ── Admin API: the tenant's and the cluster's block ─────────────────────

fn admin_key(tenant: &str) -> String {
    if tenant.is_empty() {
        CLUSTER_KEY.to_string()
    } else {
        tenant_key(tenant)
    }
}

fn admin_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

/// `GET /_admin/public-access-block[?tenant=]`: the cluster's block (system
/// admin, no tenant) or a tenant's.
pub async fn admin_get(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let admin = match crate::iam_admin::admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let key = admin_key(&admin.tenant);
    state.policy_cache.forget_account(&key);
    let doc = account_doc(&state, &key).await;
    let mut out = serde_json::to_value(doc_block(doc.as_ref())).unwrap_or_default();
    out["tenant"] = json!(admin.tenant);
    if admin.tenant.is_empty() {
        out["new_buckets_blocked"] = json!(
            doc.as_ref()
                .and_then(|d| d
                    .get("new_buckets_blocked")
                    .and_then(serde_json::Value::as_bool))
                .unwrap_or(true)
        );
    }
    Json(out).into_response()
}

/// `PUT /_admin/public-access-block[?tenant=]` `{"BlockPublicAcls": true, ...,
/// "new_buckets_blocked"?: bool}` (the last for the cluster only).
pub async fn admin_put(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let admin = match crate::iam_admin::admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return admin_error(StatusCode::BAD_REQUEST, "invalid JSON");
    };
    let Ok(block) = serde_json::from_value::<PublicAccessBlock>(body.clone()) else {
        return admin_error(StatusCode::BAD_REQUEST, "flags must be booleans");
    };
    let mut doc = serde_json::to_value(block).unwrap_or_default();
    if let Some(v) = body.get("new_buckets_blocked") {
        if !admin.tenant.is_empty() {
            return admin_error(
                StatusCode::BAD_REQUEST,
                "new_buckets_blocked is a cluster setting",
            );
        }
        let Some(v) = v.as_bool() else {
            return admin_error(
                StatusCode::BAD_REQUEST,
                "new_buckets_blocked must be a boolean",
            );
        };
        doc["new_buckets_blocked"] = json!(v);
    }
    let key = admin_key(&admin.tenant);
    let updated_by = auth
        .as_ref()
        .map(|Extension(a)| a.user_id.clone())
        .unwrap_or_default();
    let result = state
        .meta_client
        .clone()
        .set_config(SetConfigRequest {
            key: key.clone(),
            value: doc.to_string().into_bytes(),
            updated_by,
        })
        .await;
    state.policy_cache.forget_account(&key);
    match result {
        Ok(_) => Json(doc).into_response(),
        Err(e) => admin_error(StatusCode::INTERNAL_SERVER_ERROR, e.message()),
    }
}

/// `DELETE /_admin/public-access-block[?tenant=]`
pub async fn admin_delete(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let admin = match crate::iam_admin::admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let key = admin_key(&admin.tenant);
    let result = state
        .meta_client
        .clone()
        .delete_config(DeleteConfigRequest { key: key.clone() })
        .await;
    state.policy_cache.forget_account(&key);
    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => admin_error(StatusCode::INTERNAL_SERVER_ERROR, e.message()),
    }
}

#[cfg(test)]
mod tests {
    use super::PublicAccessBlock;

    #[test]
    fn the_xml_document_round_trips_and_absent_flags_are_false() {
        let all = PublicAccessBlock::ALL;
        assert_eq!(
            PublicAccessBlock::from_xml(all.to_xml().as_bytes()),
            Some(all)
        );
        let one = br"<PublicAccessBlockConfiguration>
            <BlockPublicPolicy>true</BlockPublicPolicy></PublicAccessBlockConfiguration>";
        let parsed = PublicAccessBlock::from_xml(one).unwrap();
        assert!(parsed.block_public_policy && !parsed.restrict_public_buckets);
        let bad = br"<PublicAccessBlockConfiguration><BlockPublicPolicy>yes</BlockPublicPolicy>
            </PublicAccessBlockConfiguration>";
        assert_eq!(PublicAccessBlock::from_xml(bad), None);
    }

    #[test]
    fn a_flag_at_any_level_holds_and_unreadable_blocks_all() {
        let policy = PublicAccessBlock {
            block_public_policy: true,
            ..PublicAccessBlock::default()
        };
        let restrict = PublicAccessBlock {
            restrict_public_buckets: true,
            ..PublicAccessBlock::default()
        };
        let both = policy.union(restrict);
        assert!(both.block_public_policy && both.restrict_public_buckets);
        assert_eq!(
            PublicAccessBlock::from_stored(b"garbage"),
            PublicAccessBlock::ALL
        );
    }
}
