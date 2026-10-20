//! Axum route handlers for the Iceberg REST API endpoints.
#![allow(clippy::significant_drop_tightening)]

use crate::access::{
    CATALOG_POLICY_NAMESPACE, HierarchicalPolicyCheck, IcebergPolicyCheck, TAG_PREFIX, and_then,
    build_iceberg_arn, check_hierarchical_policies, check_iceberg_policy, extract_tags, grant,
    validate_iceberg_policy,
};
use crate::catalog::{IcebergCatalog, NewDataFilter};
use crate::error::IcebergError;
use crate::filters;
use crate::metadata;
use crate::roles::IcebergRole;
use crate::types::{
    CatalogConfig, CommitTableRequest, CommitTableResponse, CommitTransactionRequest,
    CreateDataFilterRequest as CreateDataFilterRestRequest, CreateNamespaceRequest,
    CreateNamespaceResponse, CreateTableRequest, DataFilterResponse, EffectivePolicyEntry,
    EffectivePolicyParams, EffectivePolicyResponse, GetEncryptionPolicyResponse, GetQuotaResponse,
    GetTagsResponse, ListDataFiltersResponse as ListDataFiltersRestResponse, ListNamespacesParams,
    ListNamespacesResponse, ListTablesParams, ListTablesResponse, LoadNamespaceResponse,
    LoadTableResponse, PurgeParams, RenameTableRequest, SetEncryptionPolicyRequest,
    SetPolicyRequest, SetQuotaRequest, SetRoleBindingRequest, SetTagsRequest,
    SimulateMatchedStatement, SimulatePolicyRequest, SimulatePolicyResponse,
    UpdateNamespacePropertiesRequest, UpdateNamespacePropertiesResponse,
};
use axum::Extension;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use objectio_auth::AuthResult;
use objectio_auth::policy::{BucketPolicy, PolicyDecision, PolicyEvaluator, RequestContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

type Result<T> = std::result::Result<T, IcebergError>;

/// Common query params — all Iceberg endpoints accept `?warehouse=`
#[derive(Debug, serde::Deserialize, Default)]
pub struct WarehouseParam {
    #[serde(default)]
    pub warehouse: String,
}

/// Warehouse from path prefix (/v1/ws/{warehouse}/...)
#[derive(Debug, serde::Deserialize)]
pub struct WarehousePathParam {
    pub warehouse: String,
}

impl From<WarehousePathParam> for WarehouseParam {
    fn from(p: WarehousePathParam) -> Self {
        Self {
            warehouse: p.warehouse,
        }
    }
}

/// Shared state for Iceberg handlers — wraps the catalog.
pub struct IcebergState {
    pub catalog: IcebergCatalog,
    pub policy_evaluator: PolicyEvaluator,
    /// ARN patterns that grant admin access (e.g., OIDC groups/roles).
    /// Matched against both `user_arn` and `group_arns` in `AuthResult`.
    /// The builtin `user/admin` check is always active in addition to these.
    pub admin_principals: Vec<String>,
    /// STS provider for vended credentials in `LoadTable` responses.
    pub sts_provider: Option<objectio_auth::sts::StsProvider>,
    /// S3 endpoint URL for vended credential config.
    pub s3_endpoint: String,
    /// Authentication is on (the gateway runs without `--no-auth`): a
    /// request with no identity is refused, never run as if unchecked.
    pub auth_required: bool,
}

/// Who is asking.
#[derive(Clone, Copy)]
enum Caller<'a> {
    /// `--no-auth`: there is no identity, and nothing is checked.
    Unchecked,
    Identity(&'a AuthResult),
}

/// The caller of a request. No identity is refused when authentication is
/// on: it means the auth layer didn't run, not that the caller may do
/// anything.
fn caller<'a>(state: &IcebergState, auth: Option<&'a Extension<AuthResult>>) -> Result<Caller<'a>> {
    match auth {
        Some(Extension(a)) if a.auth_mode != objectio_auth::AuthMode::Anonymous => {
            Ok(Caller::Identity(a))
        }
        _ if state.auth_required => Err(IcebergError::unauthorized("Authentication required")),
        _ => Ok(Caller::Unchecked),
    }
}

/// Whether `auth` is a catalog administrator: the system admin, or a
/// principal (user or group) named by `--oidc-admin-roles`.
fn is_catalog_admin(auth: &AuthResult, admin_principals: &[String]) -> bool {
    auth.is_system_admin()
        || std::iter::once(auth.user_arn.as_str())
            .chain(auth.group_arns.iter().map(String::as_str))
            .any(|arn| admin_principals.iter().any(|p| p == arn))
}

/// Whether `auth` is listed among `tenant`'s admins.
async fn is_tenant_admin(state: &IcebergState, tenant: &str, auth: &AuthResult) -> Result<bool> {
    if tenant.is_empty() || auth.tenant != tenant {
        return Ok(false);
    }
    let resp = state
        .catalog
        .meta_client()
        .get_tenant(objectio_proto::metadata::GetTenantRequest {
            name: tenant.to_string(),
        })
        .await
        .map_err(|e| IcebergError::unavailable(format!("cannot read tenant '{tenant}': {e}")))?
        .into_inner();
    Ok(resp.tenant.filter(|_| resp.found).is_some_and(|t| {
        t.admin_users
            .iter()
            .any(|u| *u == auth.user_id || *u == auth.user_arn)
    }))
}

/// A request's warehouse, resolved for its caller.
struct Scope<'a> {
    caller: Caller<'a>,
    warehouse: objectio_proto::metadata::IcebergWarehouse,
    /// The catalog, scoped to this warehouse.
    catalog: IcebergCatalog,
    /// The caller administers this warehouse: a catalog admin, or an admin
    /// of the warehouse's tenant. With no policy granting a request, only
    /// they go ahead, as only a bucket's owner does on S3.
    administers: bool,
}

/// Resolve the warehouse a request names, as its caller sees it: a
/// warehouse of another tenant is "unknown", exactly as one that doesn't
/// exist. Every operation names a warehouse; real clients pass
/// `?warehouse=X` on `/v1/config` and use the `ws/{warehouse}` prefix it
/// returns from then on.
///
/// # Errors
/// 401 with no identity (auth on), 400 for an empty or unknown warehouse,
/// 503 if meta can't be read.
async fn scope<'a>(
    state: &IcebergState,
    auth: Option<&'a Extension<AuthResult>>,
    warehouse: &str,
) -> Result<Scope<'a>> {
    let caller = caller(state, auth)?;
    if warehouse.is_empty() {
        return Err(IcebergError::bad_request(
            "warehouse query parameter is required",
        ));
    }
    let resp = state
        .catalog
        .meta_client()
        .iceberg_list_warehouses(objectio_proto::metadata::IcebergListWarehousesRequest {
            tenant: String::new(),
        })
        .await
        .map_err(|e| IcebergError::unavailable(format!("meta unavailable: {e}")))?;
    let found = resp
        .into_inner()
        .warehouses
        .into_iter()
        .find(|w| w.name == warehouse);
    let (visible, administers) = match (caller, &found) {
        (_, None) => (false, false),
        (Caller::Unchecked, Some(_)) => (true, true),
        (Caller::Identity(a), Some(_)) if is_catalog_admin(a, &state.admin_principals) => {
            (true, true)
        }
        (Caller::Identity(a), Some(w)) => {
            let visible = a.tenant == w.tenant;
            (
                visible,
                visible && is_tenant_admin(state, &w.tenant, a).await?,
            )
        }
    };
    match found {
        Some(w) if visible => Ok(Scope {
            caller,
            catalog: state.catalog.with_warehouse(&w.name),
            warehouse: w,
            administers,
        }),
        _ => Err(IcebergError::bad_request(format!(
            "unknown warehouse '{warehouse}'"
        ))),
    }
}

/// A namespace's properties, `None` if there is no such namespace.
async fn namespace_properties(
    catalog: &IcebergCatalog,
    levels: Vec<String>,
) -> Result<Option<HashMap<String, String>>> {
    match catalog.load_namespace(levels).await {
        Ok(resp) => Ok(Some(resp.properties)),
        Err(e) if e.code == StatusCode::NOT_FOUND => Ok(None),
        Err(e) => Err(IcebergError::unavailable(format!(
            "cannot read namespace policy: {}",
            e.message
        ))),
    }
}

/// Load the warehouse's catalog-level default policy (the `__catalog`
/// namespace's `__policy` property).
async fn load_catalog_policy(catalog: &IcebergCatalog) -> Result<Option<String>> {
    Ok(
        namespace_properties(catalog, vec![CATALOG_POLICY_NAMESPACE.to_string()])
            .await?
            .and_then(|p| p.get("__policy").cloned()),
    )
}

/// Collected namespace policies and merged resource tags from the hierarchy.
struct NamespaceHierarchy {
    policies: Vec<(String, Option<String>)>,
    tags: HashMap<String, String>,
}

/// Collect namespace policies and resource tags for the full hierarchy.
///
/// For namespace `["a", "b", "c"]`, loads properties for `a`, `a.b`, `a.b.c`,
/// extracting `__policy` entries and merging `__tag:*` entries (child tags
/// override parent tags with the same key). A level that doesn't exist has
/// no policy; a level meta can't read fails the request.
async fn collect_namespace_hierarchy(
    catalog: &IcebergCatalog,
    ns_levels: &[String],
) -> Result<NamespaceHierarchy> {
    let mut policies = Vec::with_capacity(ns_levels.len());
    let mut tags = HashMap::new();
    for i in 1..=ns_levels.len() {
        let prefix = &ns_levels[..i];
        let label = format!("namespace:{}", prefix.join("."));
        let properties = namespace_properties(catalog, prefix.to_vec())
            .await?
            .unwrap_or_default();
        // Merge tags from this level (child overrides parent)
        for (k, v) in &properties {
            if let Some(tag_key) = k.strip_prefix(TAG_PREFIX) {
                tags.insert(tag_key.to_string(), v.clone());
            }
        }
        policies.push((label, properties.get("__policy").cloned()));
    }
    Ok(NamespaceHierarchy { policies, tags })
}

impl Scope<'_> {
    /// What the catalog and namespace policies say of `action` on
    /// `resource_arn`, for an identified caller.
    async fn namespace_decision(
        &self,
        state: &IcebergState,
        auth: &AuthResult,
        ns_levels: &[String],
        action: &str,
        resource_arn: &str,
    ) -> Result<PolicyDecision> {
        // Extract table name from resource ARN if present (after last /)
        let table_name = resource_arn
            .strip_prefix("arn:obio:iceberg:::")
            .and_then(|rest| rest.split_once('/').map(|(_, t)| t));

        let catalog_policy = load_catalog_policy(&self.catalog).await?;
        let hierarchy = collect_namespace_hierarchy(&self.catalog, ns_levels).await?;

        check_hierarchical_policies(&HierarchicalPolicyCheck {
            evaluator: &state.policy_evaluator,
            catalog_policy_json: catalog_policy.as_deref(),
            ancestor_policies: &hierarchy.policies,
            user_arn: &auth.user_arn,
            action,
            resource_arn,
            ns_levels,
            table_name,
            resource_tags: &hierarchy.tags,
        })
    }

    /// Authorize `action` on a namespace (or on a table to be created in
    /// it): the catalog policy and each namespace level's. A Deny anywhere
    /// refuses; an Allow anywhere grants; with neither, only the
    /// warehouse's administrators go ahead. The system admin is not
    /// subject to the chain, so no policy can lock the operator out.
    async fn authorize_namespace(
        &self,
        state: &IcebergState,
        ns_levels: &[String],
        action: &str,
        resource_arn: &str,
    ) -> Result<()> {
        let Caller::Identity(auth) = self.caller else {
            return Ok(());
        };
        if auth.is_system_admin() {
            return Ok(());
        }
        let decision = self
            .namespace_decision(state, auth, ns_levels, action, resource_arn)
            .await?;
        grant(decision, self.administers, action, resource_arn)
    }

    /// What the whole chain, the table's own policy included, says of
    /// `action` on a table.
    async fn table_decision(
        &self,
        state: &IcebergState,
        auth: &AuthResult,
        ns_levels: &[String],
        table_name: &str,
        action: &str,
        resource_arn: &str,
    ) -> Result<PolicyDecision> {
        let decision = self
            .namespace_decision(state, auth, ns_levels, action, resource_arn)
            .await?;
        // A table that doesn't exist has no policy; the handler answers 404.
        let policy = match self
            .catalog
            .get_table_policy(ns_levels.to_vec(), table_name)
            .await
        {
            Ok(bytes) => bytes.and_then(|b| String::from_utf8(b).ok()),
            Err(e) if e.code == StatusCode::NOT_FOUND => None,
            Err(e) => {
                return Err(IcebergError::unavailable(format!(
                    "cannot read table policy: {}",
                    e.message
                )));
            }
        };
        and_then(
            decision,
            check_iceberg_policy(&IcebergPolicyCheck {
                evaluator: &state.policy_evaluator,
                policy_json: policy.as_deref(),
                user_arn: &auth.user_arn,
                action,
                resource_arn,
                ns_levels,
                table_name: Some(table_name),
                policy_source: "table",
                resource_tags: &HashMap::new(),
            }),
        )
    }

    /// Authorize `action` on a table: the namespace chain, then the
    /// table's own policy, decided as [`Self::authorize_namespace`].
    async fn authorize_table(
        &self,
        state: &IcebergState,
        ns_levels: &[String],
        table_name: &str,
        action: &str,
        resource_arn: &str,
    ) -> Result<()> {
        let Caller::Identity(auth) = self.caller else {
            return Ok(());
        };
        if auth.is_system_admin() {
            return Ok(());
        }
        let decision = self
            .table_decision(state, auth, ns_levels, table_name, action, resource_arn)
            .await?;
        grant(decision, self.administers, action, resource_arn)
    }

    /// Whether the caller may do `action` on a table, without refusing:
    /// `false` for a refusal, an error only when it can't be decided.
    async fn may_on_table(
        &self,
        state: &IcebergState,
        ns_levels: &[String],
        table_name: &str,
        action: &str,
        resource_arn: &str,
    ) -> Result<bool> {
        match self
            .authorize_table(state, ns_levels, table_name, action, resource_arn)
            .await
        {
            Ok(()) => Ok(true),
            Err(e) if e.code == StatusCode::FORBIDDEN => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Policy, tags, quotas, encryption and role bindings are the
    /// warehouse administrators'.
    fn require_admin(&self) -> Result<()> {
        if self.administers {
            Ok(())
        } else {
            Err(IcebergError::forbidden(
                "Admin access required: a catalog admin, or an admin of the warehouse's tenant.",
            ))
        }
    }

    /// The warehouse's location, without a trailing slash.
    fn location(&self) -> &str {
        self.warehouse.location.trim_end_matches('/')
    }

    /// Refuse a table location outside the warehouse: its vended
    /// credentials are scoped to it, so a table pointed at another bucket
    /// would hand out credentials for that bucket.
    fn confine(&self, location: &str) -> Result<()> {
        if location_within(location, self.location()) {
            Ok(())
        } else {
            Err(IcebergError::bad_request(format!(
                "table location \"{location}\" is outside warehouse '{}' ({})",
                self.warehouse.name,
                self.location()
            )))
        }
    }
}

/// Whether `location` is `root` itself or a path under it. `..` segments
/// are refused: they would let a path that starts under the warehouse
/// leave it.
fn location_within(location: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    if root.is_empty() || location.split('/').any(|seg| seg == ".." || seg == ".") {
        return false;
    }
    let location = location.trim_end_matches('/');
    location == root
        || location
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

// ---- Config ----

/// `GET /v1/config` — return catalog configuration.
///
/// # Errors
/// Returns `IcebergError::bad_request` if the `warehouse` query parameter
/// is empty or names a warehouse the caller doesn't know.
pub async fn get_config(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
) -> Result<Json<CatalogConfig>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let warehouse_loc = scope.warehouse.location;

    let mut overrides = HashMap::new();
    // Set prefix so PyIceberg prepends warehouse name to all URL paths
    overrides.insert("prefix".to_string(), format!("ws/{}", wh.warehouse));

    let config = CatalogConfig {
        defaults: HashMap::from([("warehouse".to_string(), warehouse_loc)]),
        overrides,
    };
    Ok(Json(config))
}

// ---- Namespace handlers ----

/// Parse a namespace path segment like "ns1%1Fns2" into levels.
/// The Iceberg REST spec uses U+001F (unit separator) to encode multi-level namespaces in URLs.
fn parse_namespace(encoded: &str) -> Vec<String> {
    encoded.split('\x1F').map(String::from).collect()
}

/// Namespace properties the catalog itself reads: the policy, tags (policy
/// conditions), quota and encryption requirement. Only the warehouse's
/// administrators set them, through their own endpoints or here.
fn is_reserved_property(key: &str) -> bool {
    key.starts_with("__")
}

/// `GET /v1/namespaces` — list namespaces, optionally under a parent.
///
/// # Errors
/// Returns `IcebergError` if the parent namespace is not found.
pub async fn list_namespaces(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Query(params): Query<ListNamespacesParams>,
) -> Result<Json<ListNamespacesResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let parent = params.parent.as_ref().map(|p| parse_namespace(p));
    let parent_levels = parent.clone().unwrap_or_default();
    let arn = build_iceberg_arn(&parent_levels, None);
    scope
        .authorize_namespace(&state, &parent_levels, "iceberg:ListNamespaces", &arn)
        .await?;
    let (namespaces, next_page_token) = scope
        .catalog
        .list_namespaces(parent, params.page_token, params.page_size)
        .await?;
    Ok(Json(ListNamespacesResponse {
        namespaces,
        next_page_token,
    }))
}

/// `POST /v1/namespaces` — create a new namespace.
///
/// # Errors
/// Returns `IcebergError` if the namespace already exists or parent is missing.
pub async fn create_namespace(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Json(req): Json<CreateNamespaceRequest>,
) -> Result<(StatusCode, Json<CreateNamespaceResponse>)> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    if req.namespace.is_empty() {
        return Err(IcebergError::bad_request("namespace is required"));
    }
    // Decided by the catalog policy and the parent levels' policies.
    let parent = &req.namespace[..req.namespace.len() - 1];
    let arn = build_iceberg_arn(&req.namespace, None);
    scope
        .authorize_namespace(&state, parent, "iceberg:CreateNamespace", &arn)
        .await?;
    if req.properties.keys().any(|k| is_reserved_property(k)) {
        scope.require_admin()?;
    }
    let resp = scope
        .catalog
        .create_namespace(req.namespace, req.properties)
        .await?;
    Ok((StatusCode::OK, Json(resp)))
}

/// `GET /v1/namespaces/{namespace}` — load namespace properties.
///
/// # Errors
/// Returns `IcebergError` if the namespace is not found.
pub async fn load_namespace(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
) -> Result<Json<LoadNamespaceResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, None);
    scope
        .authorize_namespace(&state, &levels, "iceberg:LoadNamespace", &arn)
        .await?;
    let resp = scope.catalog.load_namespace(levels).await?;
    Ok(Json(resp))
}

/// `HEAD /v1/namespaces/{namespace}` — check if namespace exists.
///
/// # Errors
/// Returns `IcebergError` on gRPC communication failure.
pub async fn namespace_exists(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, None);
    scope
        .authorize_namespace(&state, &levels, "iceberg:NamespaceExists", &arn)
        .await?;
    let exists = scope.catalog.namespace_exists(levels).await?;
    if exists {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

/// `DELETE /v1/namespaces/{namespace}` — drop a namespace.
///
/// # Errors
/// Returns `IcebergError` if the namespace is not found or not empty.
pub async fn drop_namespace(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    // The chain covers every ancestor's policy as well as this level's.
    let arn = build_iceberg_arn(&levels, None);
    scope
        .authorize_namespace(&state, &levels, "iceberg:DropNamespace", &arn)
        .await?;
    scope.catalog.drop_namespace(levels).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/namespaces/{namespace}/properties` — update namespace properties.
///
/// # Errors
/// Returns `IcebergError` if the namespace is not found.
pub async fn update_namespace_properties(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
    Json(req): Json<UpdateNamespacePropertiesRequest>,
) -> Result<Json<UpdateNamespacePropertiesResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, None);
    scope
        .authorize_namespace(&state, &levels, "iceberg:UpdateNamespaceProperties", &arn)
        .await?;

    // The policy, tags, quota and encryption requirement are the admins'.
    let touches_reserved = req.updates.keys().any(|k| is_reserved_property(k))
        || req.removals.iter().any(|k| is_reserved_property(k));
    if touches_reserved {
        scope.require_admin()?;
    }

    let resp = scope
        .catalog
        .update_namespace_properties(levels, req.removals, req.updates)
        .await?;
    Ok(Json(resp))
}

// ---- Table handlers ----

/// `GET /v1/namespaces/{namespace}/tables` — list tables in namespace.
///
/// # Errors
/// Returns `IcebergError` if the namespace is not found.
pub async fn list_tables(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
    Query(params): Query<ListTablesParams>,
) -> Result<Json<ListTablesResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, None);
    scope
        .authorize_namespace(&state, &levels, "iceberg:ListTables", &arn)
        .await?;
    let (identifiers, next_page_token) = scope
        .catalog
        .list_tables(levels, params.page_token, params.page_size)
        .await?;
    Ok(Json(ListTablesResponse {
        identifiers,
        next_page_token,
    }))
}

/// `POST /v1/namespaces/{namespace}/tables` — create a new table.
///
/// # Errors
/// Returns `IcebergError` if the namespace is not found or table already exists.
#[allow(clippy::cast_possible_truncation)]
pub async fn create_table(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
    Json(req): Json<CreateTableRequest>,
) -> Result<(StatusCode, Json<LoadTableResponse>)> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let catalog = &scope.catalog;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, Some(&req.name));
    scope
        .authorize_namespace(&state, &levels, "iceberg:CreateTable", &arn)
        .await?;

    // Check namespace quota
    let ns_props = catalog.load_namespace(levels.clone()).await?;
    if let Some(max_str) = ns_props.properties.get(QUOTA_MAX_TABLES_KEY)
        && let Ok(max_tables) = max_str.parse::<u32>()
    {
        let (existing_tables, _) = catalog.list_tables(levels.clone(), None, None).await?;
        #[allow(clippy::cast_possible_truncation)]
        let count = existing_tables.len() as u32;
        if count >= max_tables {
            return Err(IcebergError::bad_request(format!(
                "Namespace table quota exceeded: {count}/{max_tables} tables"
            )));
        }
    }

    // Build initial table metadata (Iceberg v2 format)
    let table_uuid = uuid::Uuid::new_v4().to_string();

    let location = req.location.unwrap_or_else(|| {
        let ns_path = levels.join("/");
        format!("{}/{ns_path}/{}", scope.location(), req.name)
    });
    scope.confine(&location)?;

    // Check encryption policy — location must start with required prefix
    if let Some(required_prefix) = ns_props.properties.get(ENCRYPTION_PREFIX_KEY)
        && !location.starts_with(required_prefix.as_str())
    {
        return Err(IcebergError::bad_request(format!(
            "Table location \"{location}\" does not match required encryption prefix \"{required_prefix}\""
        )));
    }

    let schema = if req.schema.is_null() {
        json!({
            "type": "struct",
            "schema-id": 0,
            "fields": []
        })
    } else if req.schema.get("schema-id").is_none() {
        let mut s = req.schema.clone();
        if let Some(obj) = s.as_object_mut() {
            obj.insert("schema-id".to_string(), json!(0));
        }
        s
    } else {
        req.schema
    };

    let partition_spec = if req.partition_spec.is_null() {
        json!({"spec-id": 0, "fields": []})
    } else {
        req.partition_spec
    };

    let sort_order = if req.write_order.is_null() {
        json!({"order-id": 0, "fields": []})
    } else {
        req.write_order
    };

    let metadata = json!({
        "format-version": 2,
        "table-uuid": table_uuid,
        "location": location,
        "last-sequence-number": 0,
        "last-updated-ms": chrono_now_ms(),
        "last-column-id": last_column_id(&schema),
        "current-schema-id": 0,
        "schemas": [schema],
        "default-spec-id": 0,
        "partition-specs": [partition_spec],
        "last-partition-id": 0,
        "default-sort-order-id": 0,
        "sort-orders": [sort_order],
        "properties": req.properties,
        "current-snapshot-id": -1,
        "snapshots": [],
        "snapshot-log": [],
        "metadata-log": [],
        "refs": {}
    });

    let metadata_location = format!("{location}/metadata/00000-{table_uuid}.metadata.json");

    let metadata_bytes = serde_json::to_vec(&metadata)
        .map_err(|e| IcebergError::internal(format!("failed to serialize metadata: {e}")))?;

    let _stored = catalog
        .create_table(levels, &req.name, &metadata_location, metadata_bytes)
        .await?;

    Ok((
        StatusCode::OK,
        Json(LoadTableResponse {
            metadata_location,
            metadata,
            config: None,
        }),
    ))
}

/// `GET /v1/namespaces/{namespace}/tables/{table}` — load a table.
///
/// When data filters are configured for the calling principal, the response
/// metadata is modified: schema fields are filtered (column security) and a
/// `obio.row-filter` property is injected (row security).
///
/// # Errors
/// Returns `IcebergError` if the table is not found.
pub async fn load_table(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path((namespace, table)): Path<(String, String)>,
) -> Result<Json<LoadTableResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let catalog = &scope.catalog;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, Some(&table));
    scope
        .authorize_table(&state, &levels, &table, "iceberg:LoadTable", &arn)
        .await?;
    let (metadata_location, metadata_bytes) = catalog.load_table(levels.clone(), &table).await?;

    if metadata_bytes.is_empty() {
        return Err(IcebergError::internal("table metadata is empty"));
    }

    let mut metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| IcebergError::internal(format!("failed to deserialize metadata: {e}")))?;

    // Apply data filters if the caller is authenticated and not admin.
    // Filters that can't be read fail the request: without them the
    // caller would see the columns and rows they hide.
    if let Caller::Identity(auth_result) = scope.caller
        && !auth_result.is_system_admin()
    {
        let applicable_filters = catalog
            .get_data_filters_for_principal(
                levels.clone(),
                &table,
                &auth_result.user_arn,
                auth_result.group_arns.clone(),
            )
            .await
            .map_err(|e| {
                IcebergError::unavailable(format!("cannot read data filters: {}", e.message))
            })?;

        for filter in &applicable_filters {
            filters::apply_column_filter(
                &mut metadata,
                &filter.allowed_columns,
                &filter.excluded_columns,
            );
            filters::apply_row_filter(&mut metadata, &filter.row_filter_expression);
        }
    }

    // Vended S3 credentials for the table's data: read-write only for a
    // caller who may also commit to the table, read-only otherwise.
    let config = if let Some(sts) = state.sts_provider.as_ref() {
        // Scope to the table base directory, not the metadata file. The
        // metadata location is `s3://warehouse/db/table/metadata/00001-…json`
        // — Spark/PyIceberg need to read/write `data/` under the same table
        // dir, so strip the trailing `metadata/...` to recover the base.
        let table_base = iceberg_table_base_from_metadata_location(&metadata_location);
        scope.confine(&table_base)?;
        let operation = if scope
            .may_on_table(&state, &levels, &table, "iceberg:UpdateTable", &arn)
            .await?
        {
            objectio_auth::sts::Operation::ReadWrite
        } else {
            objectio_auth::sts::Operation::Read
        };
        let user_arn = match scope.caller {
            Caller::Identity(a) => a.user_arn.as_str(),
            Caller::Unchecked => "anonymous",
        };
        // The session is held to the warehouse's tenant: should its scope
        // ever name another tenant's bucket, it gets nothing there.
        let creds = sts.issue(user_arn, &scope.warehouse.tenant, &table_base, operation);
        let mut cfg = std::collections::HashMap::new();
        cfg.insert("s3.access-key-id".to_string(), creds.access_key_id);
        cfg.insert("s3.secret-access-key".to_string(), creds.secret_access_key);
        cfg.insert("s3.session-token".to_string(), creds.session_token);
        if !state.s3_endpoint.is_empty() {
            cfg.insert("s3.endpoint".to_string(), state.s3_endpoint.clone());
        }
        cfg.insert("s3.path-style-access".to_string(), "true".to_string());
        Some(cfg)
    } else {
        None
    };

    Ok(Json(LoadTableResponse {
        metadata_location,
        metadata,
        config,
    }))
}

/// `POST /v1/namespaces/{namespace}/tables/{table}` — commit table update (CAS).
///
/// # Errors
/// Returns `IcebergError` if the table is not found or the commit conflicts.
pub async fn update_table(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path((namespace, table)): Path<(String, String)>,
    Json(req): Json<CommitTableRequest>,
) -> Result<Json<CommitTableResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let catalog = &scope.catalog;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, Some(&table));
    scope
        .authorize_table(&state, &levels, &table, "iceberg:UpdateTable", &arn)
        .await?;

    // 1. Load current metadata
    let (current_location, metadata_bytes) = catalog.load_table(levels.clone(), &table).await?;

    if metadata_bytes.is_empty() {
        return Err(IcebergError::internal("table metadata is empty"));
    }

    let mut md: serde_json::Value = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| IcebergError::internal(format!("failed to deserialize metadata: {e}")))?;

    // 2. Validate requirements against current metadata
    metadata::validate_requirements(&md, &req.requirements)?;

    // 3. Apply updates; the table stays inside its warehouse.
    metadata::apply_updates(&mut md, &req.updates)?;
    scope.confine(
        md.get("location")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
    )?;

    // 4. Increment sequence number and update timestamp
    let seq = md
        .get("last-sequence-number")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
        + 1;
    md["last-sequence-number"] = json!(seq);
    md["last-updated-ms"] = json!(chrono_now_ms());

    // 5. Append current location to metadata-log
    if let Some(log) = md
        .get_mut("metadata-log")
        .and_then(serde_json::Value::as_array_mut)
    {
        log.push(json!({
            "metadata-file": current_location,
            "timestamp-ms": chrono_now_ms()
        }));
    }

    // 6. Generate new metadata location with sequence number
    let new_location = format!(
        "{}/metadata/{:05}-{}.metadata.json",
        md.get("location")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        seq,
        uuid::Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("0")
    );

    // 7. Serialize and commit
    let new_bytes = serde_json::to_vec(&md)
        .map_err(|e| IcebergError::internal(format!("failed to serialize metadata: {e}")))?;

    let (committed_location, _) = catalog
        .commit_table(levels, &table, &current_location, &new_location, new_bytes)
        .await?;

    Ok(Json(CommitTableResponse {
        metadata_location: committed_location,
        metadata: md,
    }))
}

/// Per-table commit pre-prepared from a `CommitTransactionRequest` entry —
/// validated, requirements checked, ready to be proposed as a single CAS op.
struct PreparedCommit {
    levels: Vec<String>,
    table: String,
    current_location: String,
    new_location: String,
    new_bytes: Vec<u8>,
    new_metadata: serde_json::Value,
}

/// `POST /v1/transactions/commit` — atomic multi-table commit.
///
/// Iceberg REST spec endpoint. Every entry in `table-changes` goes
/// through the same requirements-then-updates path as `update_table`,
/// but all per-table CAS ops land as a single Raft `MultiCas` at the meta
/// layer — if any requirement fails, or any current metadata location
/// is stale, every change in the batch aborts with no writes. The
/// response mirrors the request order.
///
/// # Errors
/// Returns `IcebergError::FailedPrecondition` on requirements mismatch
/// or stale current location; the client retries after a re-load.
#[allow(clippy::too_many_lines)] // linear prepare → propose → respond pipeline; splitting hurts readability
pub async fn commit_transaction(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Json(req): Json<CommitTransactionRequest>,
) -> Result<Json<Vec<CommitTableResponse>>> {
    if req.table_changes.is_empty() {
        return Err(IcebergError::bad_request("table-changes is empty"));
    }
    // Meta commits a transaction as one command, of one write per table.
    if req.table_changes.len() > objectio_common::META_MAX_OPS {
        return Err(IcebergError::bad_request(format!(
            "{} table changes in one transaction; at most {}",
            req.table_changes.len(),
            objectio_common::META_MAX_OPS
        )));
    }

    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let catalog = &scope.catalog;

    let mut prepared: Vec<PreparedCommit> = Vec::with_capacity(req.table_changes.len());

    for (idx, change) in req.table_changes.iter().enumerate() {
        let identifier = change.identifier.as_ref().ok_or_else(|| {
            IcebergError::bad_request(format!("table-changes[{idx}]: identifier is required"))
        })?;
        let table = identifier.name.clone();
        let levels: Vec<String> = identifier.namespace.clone();
        let namespace_joined = levels.join(".");
        let arn = build_iceberg_arn(&levels, Some(&table));
        scope
            .authorize_table(&state, &levels, &table, "iceberg:UpdateTable", &arn)
            .await?;

        // Per-table: same load → validate requirements → apply updates →
        // assemble new metadata blob pipeline as the single-table
        // update_table handler. Done before any CAS proposal so the
        // whole batch either prepares or aborts cleanly.
        let (current_location, metadata_bytes) = catalog.load_table(levels.clone(), &table).await?;
        if metadata_bytes.is_empty() {
            return Err(IcebergError::internal(format!(
                "table-changes[{idx}] ({namespace_joined}.{table}): metadata is empty"
            )));
        }
        let mut md: serde_json::Value = serde_json::from_slice(&metadata_bytes).map_err(|e| {
            IcebergError::internal(format!(
                "table-changes[{idx}]: failed to deserialize metadata: {e}"
            ))
        })?;

        metadata::validate_requirements(&md, &change.requirements)?;
        metadata::apply_updates(&mut md, &change.updates)?;
        scope.confine(
            md.get("location")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        )?;

        let seq = md
            .get("last-sequence-number")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0)
            + 1;
        md["last-sequence-number"] = json!(seq);
        md["last-updated-ms"] = json!(chrono_now_ms());
        if let Some(log) = md
            .get_mut("metadata-log")
            .and_then(serde_json::Value::as_array_mut)
        {
            log.push(json!({
                "metadata-file": current_location,
                "timestamp-ms": chrono_now_ms()
            }));
        }

        let new_location = format!(
            "{}/metadata/{:05}-{}.metadata.json",
            md.get("location")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            seq,
            uuid::Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("0")
        );
        let new_bytes = serde_json::to_vec(&md).map_err(|e| {
            IcebergError::internal(format!(
                "table-changes[{idx}]: failed to serialize metadata: {e}"
            ))
        })?;

        prepared.push(PreparedCommit {
            levels,
            table,
            current_location,
            new_location,
            new_bytes,
            new_metadata: md,
        });
    }

    // Atomic commit at the meta layer.
    let committed = catalog
        .commit_transaction(
            prepared
                .iter()
                .map(|p| {
                    (
                        p.levels.clone(),
                        p.table.clone(),
                        p.current_location.clone(),
                        p.new_location.clone(),
                        p.new_bytes.clone(),
                    )
                })
                .collect(),
        )
        .await?;

    // Zip the meta-side response (authoritative committed location +
    // stored bytes) with the client-side metadata JSON we just built.
    let mut out = Vec::with_capacity(prepared.len());
    for (p, (committed_location, _)) in prepared.into_iter().zip(committed.into_iter()) {
        out.push(CommitTableResponse {
            metadata_location: committed_location,
            metadata: p.new_metadata,
        });
    }
    Ok(Json(out))
}

/// `HEAD /v1/namespaces/{namespace}/tables/{table}` — check if table exists.
///
/// # Errors
/// Returns `IcebergError` on gRPC communication failure.
pub async fn table_exists(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path((namespace, table)): Path<(String, String)>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, Some(&table));
    scope
        .authorize_table(&state, &levels, &table, "iceberg:TableExists", &arn)
        .await?;
    let exists = scope.catalog.table_exists(levels, &table).await?;
    if exists {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

/// `DELETE /v1/namespaces/{namespace}/tables/{table}` — drop a table.
///
/// # Errors
/// Returns `IcebergError` if the table is not found.
pub async fn drop_table(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path((namespace, table)): Path<(String, String)>,
    Query(params): Query<PurgeParams>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, Some(&table));
    scope
        .authorize_table(&state, &levels, &table, "iceberg:DropTable", &arn)
        .await?;
    scope
        .catalog
        .drop_table(levels, &table, params.purge_requested)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/tables/rename` — rename a table across namespaces.
///
/// # Errors
/// Returns `IcebergError` if the source or destination namespace/table has issues.
pub async fn rename_table(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Json(req): Json<RenameTableRequest>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    // Check policy on source table (need DropTable equivalent)
    let src_arn = build_iceberg_arn(&req.source.namespace, Some(&req.source.name));
    scope
        .authorize_table(
            &state,
            &req.source.namespace,
            &req.source.name,
            "iceberg:RenameTable",
            &src_arn,
        )
        .await?;
    // Check policy on destination namespace (rename creates a table in the destination)
    let dst_arn = build_iceberg_arn(&req.destination.namespace, Some(&req.destination.name));
    scope
        .authorize_namespace(
            &state,
            &req.destination.namespace,
            "iceberg:CreateTable",
            &dst_arn,
        )
        .await?;
    scope
        .catalog
        .rename_table(
            req.source.namespace,
            &req.source.name,
            req.destination.namespace,
            &req.destination.name,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- Policy management endpoints ----

/// `PUT /v1/namespaces/{namespace}/policy` — set namespace-level access policy.
///
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if namespace not found or user is not admin.
pub async fn set_namespace_policy(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
    Json(req): Json<SetPolicyRequest>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    scope.require_admin()?;
    let levels = parse_namespace(&namespace);

    // Validate policy before persisting
    if let Err(e) = validate_iceberg_policy(&req.policy) {
        return Err(IcebergError::bad_request(format!(
            "Invalid iceberg policy: {e}"
        )));
    }

    // Store policy as __policy property on the namespace
    let mut updates = HashMap::new();
    updates.insert("__policy".to_string(), req.policy);
    scope
        .catalog
        .update_namespace_properties(levels, Vec::new(), updates)
        .await?;
    Ok(StatusCode::OK)
}

/// `PUT /v1/namespaces/{namespace}/tables/{table}/policy` — set table-level access policy.
///
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if table not found or user is not admin.
pub async fn set_table_policy(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path((namespace, table)): Path<(String, String)>,
    Json(req): Json<SetPolicyRequest>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    scope.require_admin()?;
    let levels = parse_namespace(&namespace);

    // Validate policy before persisting
    if let Err(e) = validate_iceberg_policy(&req.policy) {
        return Err(IcebergError::bad_request(format!(
            "Invalid iceberg policy: {e}"
        )));
    }

    scope
        .catalog
        .set_table_policy(levels, &table, req.policy.into_bytes())
        .await?;
    Ok(StatusCode::OK)
}

/// `PUT /v1/catalog/policy` — set catalog-level default policy.
///
/// Stores the policy as `__policy` property on the reserved `__catalog` namespace.
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if user is not admin or policy is invalid.
pub async fn set_catalog_policy(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Json(req): Json<SetPolicyRequest>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    scope.require_admin()?;

    // Validate policy before persisting
    if let Err(e) = validate_iceberg_policy(&req.policy) {
        return Err(IcebergError::bad_request(format!(
            "Invalid iceberg policy: {e}"
        )));
    }

    // Ensure __catalog namespace exists
    let catalog_ns = vec![CATALOG_POLICY_NAMESPACE.to_string()];
    if !scope.catalog.namespace_exists(catalog_ns.clone()).await? {
        match scope
            .catalog
            .create_namespace(catalog_ns.clone(), HashMap::new())
            .await
        {
            Ok(_) => {}
            // Created meanwhile by another request: as good.
            Err(e) if e.code == StatusCode::CONFLICT => {}
            Err(e) => return Err(e),
        }
    }

    // Store policy as __policy property on __catalog namespace
    let mut updates = HashMap::new();
    updates.insert("__policy".to_string(), req.policy);
    scope
        .catalog
        .update_namespace_properties(catalog_ns, Vec::new(), updates)
        .await?;
    Ok(StatusCode::OK)
}

/// `GET /v1/namespaces/{namespace}/effective-policy` — show effective merged policy.
///
/// Returns the catalog-level policy plus each namespace policy in the hierarchy.
/// Read-only, admin-only.
///
/// # Errors
/// Returns `IcebergError` if user is not admin.
pub async fn get_effective_policy(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
    Query(_params): Query<EffectivePolicyParams>,
) -> Result<Json<EffectivePolicyResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    scope.require_admin()?;

    let levels = parse_namespace(&namespace);

    // Load catalog-level policy
    let catalog_policy_str = load_catalog_policy(&scope.catalog).await?;
    let catalog_policy = catalog_policy_str
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());

    // Load each namespace policy in the hierarchy
    let mut namespace_policies = Vec::new();
    for i in 1..=levels.len() {
        let prefix = &levels[..i];
        let ns_name = prefix.join(".");
        let policy_json = namespace_properties(&scope.catalog, prefix.to_vec())
            .await?
            .and_then(|p| p.get("__policy").cloned());
        let policy = policy_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        namespace_policies.push(EffectivePolicyEntry {
            namespace: ns_name,
            policy,
        });
    }

    Ok(Json(EffectivePolicyResponse {
        namespace: levels.join("."),
        catalog_policy,
        namespace_policies,
    }))
}

/// `POST /v1/simulate-policy` — simulate a policy decision without executing.
///
/// Returns the decision and which policy statement caused it.
/// Admin-only.
///
/// # Errors
/// Returns `IcebergError` if user is not admin or input is invalid.
pub async fn simulate_policy(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Json(req): Json<SimulatePolicyRequest>,
) -> Result<Json<SimulatePolicyResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    scope.require_admin()?;

    // Parse the resource ARN to extract namespace/table
    let resource_path = req
        .resource
        .strip_prefix("arn:obio:iceberg:::")
        .unwrap_or(&req.resource);

    let parts: Vec<&str> = resource_path.split('/').collect();
    if parts.is_empty() {
        return Err(IcebergError::bad_request(
            "resource must be a valid Iceberg ARN (arn:obio:iceberg:::ns/table)",
        ));
    }

    let ns_levels: Vec<String> = if parts.len() > 1 {
        parts[..parts.len() - 1]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        parts.iter().map(|s| (*s).to_string()).collect()
    };
    let table_name = if parts.len() > 1 {
        Some(parts[parts.len() - 1])
    } else {
        None
    };

    // Build context
    let mut context = RequestContext::new(&req.user_arn, &req.action, &req.resource);
    context
        .variables
        .insert("iceberg:namespace".to_string(), ns_levels.join("."));
    if let Some(t) = table_name {
        context
            .variables
            .insert("iceberg:tableName".to_string(), t.to_string());
    }
    context
        .variables
        .insert("iceberg:operation".to_string(), req.action.clone());

    // Check catalog policy
    let catalog_policy_str = load_catalog_policy(&scope.catalog).await?;
    if let Some(ref json) = catalog_policy_str
        && let Ok(policy) = BucketPolicy::from_json(json)
    {
        let explanation = state
            .policy_evaluator
            .evaluate_with_explanation(&policy, &context, "catalog");
        if explanation.decision == objectio_auth::policy::PolicyDecision::Deny {
            return Ok(Json(explanation_to_response(explanation)));
        }
    }

    // Check namespace hierarchy
    for i in 1..=ns_levels.len() {
        let prefix = &ns_levels[..i];
        let ns_label = format!("namespace:{}", prefix.join("."));
        let policy_json = namespace_properties(&scope.catalog, prefix.to_vec())
            .await?
            .and_then(|p| p.get("__policy").cloned());
        if let Some(ref json) = policy_json
            && let Ok(policy) = BucketPolicy::from_json(json)
        {
            let explanation = state
                .policy_evaluator
                .evaluate_with_explanation(&policy, &context, &ns_label);
            if explanation.decision == objectio_auth::policy::PolicyDecision::Deny
                || explanation.decision == objectio_auth::policy::PolicyDecision::Allow
            {
                return Ok(Json(explanation_to_response(explanation)));
            }
        }
    }

    // Check table policy if applicable
    if let Some(t) = table_name {
        let policy_bytes = match scope.catalog.get_table_policy(ns_levels.clone(), t).await {
            Ok(bytes) => bytes,
            Err(e) if e.code == StatusCode::NOT_FOUND => None,
            Err(e) => return Err(e),
        };

        if let Some(bytes) = policy_bytes
            && let Ok(json_str) = String::from_utf8(bytes)
            && let Ok(policy) = BucketPolicy::from_json(&json_str)
        {
            let source = format!("table:{}", ns_levels.join(".") + "/" + t);
            let explanation = state
                .policy_evaluator
                .evaluate_with_explanation(&policy, &context, &source);
            if explanation.decision != objectio_auth::policy::PolicyDecision::ImplicitDeny {
                return Ok(Json(explanation_to_response(explanation)));
            }
        }
    }

    // No matching policy
    Ok(Json(SimulatePolicyResponse {
        decision: "implicit_deny".to_string(),
        matched_statement: None,
    }))
}

fn explanation_to_response(
    explanation: objectio_auth::policy::PolicyExplanation,
) -> SimulatePolicyResponse {
    let decision = match explanation.decision {
        objectio_auth::policy::PolicyDecision::Allow => "allow",
        objectio_auth::policy::PolicyDecision::Deny => "deny",
        objectio_auth::policy::PolicyDecision::ImplicitDeny => "implicit_deny",
    };
    SimulatePolicyResponse {
        decision: decision.to_string(),
        matched_statement: explanation
            .matched_statement
            .map(|ms| SimulateMatchedStatement {
                sid: ms.sid,
                effect: match ms.effect {
                    objectio_auth::policy::Effect::Allow => "Allow".to_string(),
                    objectio_auth::policy::Effect::Deny => "Deny".to_string(),
                },
                source: ms.source,
            }),
    }
}

// ---- Role binding ----

/// `PUT /v1/namespaces/{namespace}/role-binding` — bind a built-in role to principals.
///
/// Generates the equivalent policy document and stores it as the namespace policy.
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if the role is unknown or the user is not admin.
pub async fn set_role_binding(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
    Json(req): Json<SetRoleBindingRequest>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    scope.require_admin()?;

    let role = IcebergRole::from_name(&req.role).ok_or_else(|| {
        IcebergError::bad_request(format!(
            "Unknown role \"{}\". Valid roles: CatalogAdmin, NamespaceOwner, TableWriter, TableReader",
            req.role
        ))
    })?;

    if req.principals.is_empty() {
        return Err(IcebergError::bad_request("principals list cannot be empty"));
    }

    let levels = parse_namespace(&namespace);
    let ns_name = levels.join(".");
    let policy_json = role.to_policy_json(&req.principals, &ns_name);

    // Store as namespace policy
    let mut updates = HashMap::new();
    updates.insert("__policy".to_string(), policy_json);
    scope
        .catalog
        .update_namespace_properties(levels, Vec::new(), updates)
        .await?;

    tracing::info!(
        namespace = %ns_name,
        role = %role.name(),
        principals = ?req.principals,
        "iceberg.role_binding.set"
    );

    Ok(StatusCode::OK)
}

// ---- Tag management endpoints ----

/// `PUT /v1/namespaces/{namespace}/tags` — set namespace tags.
///
/// Tags are stored as `__tag:{key}` properties on the namespace.
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if namespace not found or user is not admin.
pub async fn set_namespace_tags(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
    Json(req): Json<SetTagsRequest>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    scope.require_admin()?;
    let levels = parse_namespace(&namespace);

    let updates: HashMap<String, String> = req
        .tags
        .into_iter()
        .map(|(k, v)| (format!("{TAG_PREFIX}{k}"), v))
        .collect();

    scope
        .catalog
        .update_namespace_properties(levels, Vec::new(), updates)
        .await?;
    Ok(StatusCode::OK)
}

/// `GET /v1/namespaces/{namespace}/tags` — get namespace tags.
///
/// # Errors
/// Returns `IcebergError` if namespace not found.
pub async fn get_namespace_tags(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
) -> Result<Json<GetTagsResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, None);
    scope
        .authorize_namespace(&state, &levels, "iceberg:LoadNamespace", &arn)
        .await?;

    let resp = scope.catalog.load_namespace(levels).await?;
    let tags = extract_tags(&resp.properties);
    Ok(Json(GetTagsResponse { tags }))
}

/// `PUT /v1/namespaces/{namespace}/tables/{table}/tags` — set table tags.
///
/// Table tags are stored as `__tag:{key}` entries in the table's Iceberg
/// metadata `properties` map.
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if table not found or user is not admin.
pub async fn set_table_tags(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path((namespace, table)): Path<(String, String)>,
    Json(req): Json<SetTagsRequest>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    scope.require_admin()?;
    let levels = parse_namespace(&namespace);

    // Load current metadata, inject tags, commit
    let (current_location, metadata_bytes) =
        scope.catalog.load_table(levels.clone(), &table).await?;

    if metadata_bytes.is_empty() {
        return Err(IcebergError::internal("table metadata is empty"));
    }

    let mut md: serde_json::Value = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| IcebergError::internal(format!("failed to deserialize metadata: {e}")))?;

    // Ensure properties object exists
    if md.get("properties").is_none() {
        md["properties"] = json!({});
    }
    if let Some(props) = md
        .get_mut("properties")
        .and_then(serde_json::Value::as_object_mut)
    {
        for (k, v) in &req.tags {
            props.insert(
                format!("{TAG_PREFIX}{k}"),
                serde_json::Value::String(v.clone()),
            );
        }
    }

    let new_bytes = serde_json::to_vec(&md)
        .map_err(|e| IcebergError::internal(format!("failed to serialize metadata: {e}")))?;

    let new_location = format!(
        "{}/metadata/tags-{}.metadata.json",
        md.get("location")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        uuid::Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("0")
    );

    scope
        .catalog
        .commit_table(levels, &table, &current_location, &new_location, new_bytes)
        .await?;

    Ok(StatusCode::OK)
}

/// `GET /v1/namespaces/{namespace}/tables/{table}/tags` — get table tags.
///
/// # Errors
/// Returns `IcebergError` if table not found.
pub async fn get_table_tags(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path((namespace, table)): Path<(String, String)>,
) -> Result<Json<GetTagsResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, Some(&table));
    scope
        .authorize_table(&state, &levels, &table, "iceberg:LoadTable", &arn)
        .await?;

    let (_location, metadata_bytes) = scope.catalog.load_table(levels, &table).await?;
    if metadata_bytes.is_empty() {
        return Ok(Json(GetTagsResponse {
            tags: HashMap::new(),
        }));
    }

    let md: serde_json::Value = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| IcebergError::internal(format!("failed to deserialize metadata: {e}")))?;

    let tags = md
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .map(|props| {
            props
                .iter()
                .filter_map(|(k, v)| {
                    k.strip_prefix(TAG_PREFIX).map(|tag_key| {
                        (
                            tag_key.to_string(),
                            v.as_str().unwrap_or_default().to_string(),
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(GetTagsResponse { tags }))
}

// ---- Quota management endpoints ----

/// Property key for maximum tables quota.
const QUOTA_MAX_TABLES_KEY: &str = "__quota_max_tables";

/// `PUT /v1/namespaces/{namespace}/quota` — set namespace quota.
///
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if namespace not found or user is not admin.
pub async fn set_namespace_quota(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
    Json(req): Json<SetQuotaRequest>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    scope.require_admin()?;
    let levels = parse_namespace(&namespace);

    let mut updates = HashMap::new();
    let mut removals = Vec::new();

    if let Some(max) = req.max_tables {
        updates.insert(QUOTA_MAX_TABLES_KEY.to_string(), max.to_string());
    } else {
        removals.push(QUOTA_MAX_TABLES_KEY.to_string());
    }

    scope
        .catalog
        .update_namespace_properties(levels, removals, updates)
        .await?;
    Ok(StatusCode::OK)
}

/// `GET /v1/namespaces/{namespace}/quota` — get namespace quota and current usage.
///
/// # Errors
/// Returns `IcebergError` if namespace not found.
#[allow(clippy::cast_possible_truncation)]
pub async fn get_namespace_quota(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
) -> Result<Json<GetQuotaResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, None);
    scope
        .authorize_namespace(&state, &levels, "iceberg:LoadNamespace", &arn)
        .await?;

    let resp = scope.catalog.load_namespace(levels.clone()).await?;
    let max_tables = resp
        .properties
        .get(QUOTA_MAX_TABLES_KEY)
        .and_then(|v| v.parse::<u32>().ok());

    // Count current tables
    let (tables, _) = scope.catalog.list_tables(levels, None, None).await?;
    let current_tables = tables.len() as u32;

    Ok(Json(GetQuotaResponse {
        max_tables,
        current_tables,
    }))
}

// ---- Encryption policy endpoints ----

/// Property key for required encryption location prefix.
const ENCRYPTION_PREFIX_KEY: &str = "__encryption_required_prefix";

/// `PUT /v1/namespaces/{namespace}/encryption-policy` — set encryption requirement.
///
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if namespace not found or user is not admin.
pub async fn set_encryption_policy(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
    Json(req): Json<SetEncryptionPolicyRequest>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    scope.require_admin()?;
    let levels = parse_namespace(&namespace);

    let mut updates = HashMap::new();
    updates.insert(
        ENCRYPTION_PREFIX_KEY.to_string(),
        req.required_location_prefix,
    );

    scope
        .catalog
        .update_namespace_properties(levels, Vec::new(), updates)
        .await?;
    Ok(StatusCode::OK)
}

/// `GET /v1/namespaces/{namespace}/encryption-policy` — get encryption requirement.
///
/// # Errors
/// Returns `IcebergError` if namespace not found.
pub async fn get_encryption_policy(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path(namespace): Path<String>,
) -> Result<Json<GetEncryptionPolicyResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    let levels = parse_namespace(&namespace);
    let arn = build_iceberg_arn(&levels, None);
    scope
        .authorize_namespace(&state, &levels, "iceberg:LoadNamespace", &arn)
        .await?;

    let resp = scope.catalog.load_namespace(levels).await?;
    let required_location_prefix = resp.properties.get(ENCRYPTION_PREFIX_KEY).cloned();

    Ok(Json(GetEncryptionPolicyResponse {
        required_location_prefix,
    }))
}

// ---- Data filter endpoints ----

/// Data filters are recorded by namespace and table name, not by
/// warehouse, so one filter can bear on a same-named table in every
/// warehouse: managing them is for catalog admins only.
fn require_catalog_admin(scope: &Scope<'_>, state: &IcebergState) -> Result<()> {
    match scope.caller {
        Caller::Unchecked => Ok(()),
        Caller::Identity(a) if is_catalog_admin(a, &state.admin_principals) => Ok(()),
        Caller::Identity(_) => Err(IcebergError::forbidden(
            "Data filters are managed by catalog admins",
        )),
    }
}

/// `PUT /v1/namespaces/{namespace}/tables/{table}/data-filters` — create a data filter.
///
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if user is not admin or table is not found.
pub async fn create_data_filter(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path((namespace, table)): Path<(String, String)>,
    Json(req): Json<CreateDataFilterRestRequest>,
) -> Result<(StatusCode, Json<DataFilterResponse>)> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    require_catalog_admin(&scope, &state)?;
    let levels = parse_namespace(&namespace);

    let filter = scope
        .catalog
        .create_data_filter(NewDataFilter {
            ns_levels: levels,
            table_name: &table,
            filter_name: &req.filter_name,
            principal_arns: req.principal_arns,
            allowed_columns: req.allowed_columns,
            excluded_columns: req.excluded_columns,
            row_filter_expression: &req.row_filter_expression,
        })
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(DataFilterResponse {
            filter_id: filter.filter_id,
            filter_name: filter.filter_name,
            namespace: filter.namespace_levels,
            table_name: filter.table_name,
            principal_arns: filter.principal_arns,
            allowed_columns: filter.allowed_columns,
            excluded_columns: filter.excluded_columns,
            row_filter_expression: filter.row_filter_expression,
            created_at: filter.created_at,
            updated_at: filter.updated_at,
        }),
    ))
}

/// `GET /v1/namespaces/{namespace}/tables/{table}/data-filters` — list data filters.
///
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if user is not admin.
pub async fn list_data_filters(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path((namespace, table)): Path<(String, String)>,
) -> Result<Json<ListDataFiltersRestResponse>> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    require_catalog_admin(&scope, &state)?;
    let levels = parse_namespace(&namespace);

    let proto_filters = scope.catalog.list_data_filters(levels, &table).await?;

    let filters = proto_filters
        .into_iter()
        .map(|f| DataFilterResponse {
            filter_id: f.filter_id,
            filter_name: f.filter_name,
            namespace: f.namespace_levels,
            table_name: f.table_name,
            principal_arns: f.principal_arns,
            allowed_columns: f.allowed_columns,
            excluded_columns: f.excluded_columns,
            row_filter_expression: f.row_filter_expression,
            created_at: f.created_at,
            updated_at: f.updated_at,
        })
        .collect();

    Ok(Json(ListDataFiltersRestResponse { filters }))
}

/// `DELETE /v1/namespaces/{namespace}/tables/{table}/data-filters/{filter_id}` — delete a filter.
///
/// Requires admin user.
///
/// # Errors
/// Returns `IcebergError` if user is not admin or filter not found.
pub async fn delete_data_filter(
    State(state): State<Arc<IcebergState>>,
    auth: Option<Extension<AuthResult>>,
    Query(wh): Query<WarehouseParam>,
    Path((_namespace, _table, filter_id)): Path<(String, String, String)>,
) -> Result<StatusCode> {
    let scope = scope(&state, auth.as_ref(), &wh.warehouse).await?;
    require_catalog_admin(&scope, &state)?;

    let deleted = scope.catalog.delete_data_filter(&filter_id).await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(IcebergError::not_found(format!(
            "Data filter {filter_id} not found"
        )))
    }
}

// ---- Helpers ----

#[allow(clippy::cast_possible_truncation)]
fn chrono_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Recover the table base directory from an Iceberg `metadata_location`.
///
/// `metadata_location` is a file URL like
/// `s3://warehouse/db/table/metadata/00001-abc.json`. The vended STS scope
/// must cover the whole table directory (including `data/`, `metadata/`,
/// `snapshots/`), so we strip everything from `/metadata/` onward and
/// re-append a trailing slash.
///
/// Returns the input unchanged if the path doesn't contain `/metadata/`,
/// which keeps the behavior safe for non-standard layouts.
fn iceberg_table_base_from_metadata_location(metadata_location: &str) -> String {
    metadata_location.rfind("/metadata/").map_or_else(
        || metadata_location.to_string(),
        |idx| {
            let mut base = metadata_location[..idx].to_string();
            base.push('/');
            base
        },
    )
}

fn last_column_id(schema: &serde_json::Value) -> i64 {
    schema
        .get("fields")
        .and_then(|f| f.as_array())
        .and_then(|fields| fields.iter().filter_map(|f| f.get("id")?.as_i64()).max())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_location_stays_inside_its_warehouse() {
        let root = "s3://iceberg-wh";
        assert!(location_within("s3://iceberg-wh", root));
        assert!(location_within("s3://iceberg-wh/", root));
        assert!(location_within("s3://iceberg-wh/db/t", root));
        assert!(location_within("s3://iceberg-wh/db/t/", "s3://iceberg-wh/"));
        // Another bucket, including one whose name starts the same.
        assert!(!location_within("s3://other/db/t", root));
        assert!(!location_within("s3://iceberg-wh2/db/t", root));
        assert!(!location_within("s3://iceberg-wh-other/t", root));
        // Climbing out.
        assert!(!location_within("s3://iceberg-wh/../other/t", root));
        assert!(!location_within("s3://iceberg-wh/db/./t", root));
        // No root, no location.
        assert!(!location_within("s3://iceberg-wh/db", ""));
        assert!(!location_within("", root));
    }

    fn auth(user_arn: &str, groups: &[&str]) -> AuthResult {
        AuthResult {
            user_arn: user_arn.to_string(),
            group_arns: groups.iter().map(ToString::to_string).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn catalog_admins_are_the_operator_and_the_configured_principals() {
        let principals = vec!["arn:obio:iam::oidc:group/lake-admins".to_string()];
        assert!(is_catalog_admin(
            &auth(objectio_auth::SYSTEM_ADMIN_USER_ARN, &[]),
            &principals
        ));
        assert!(is_catalog_admin(
            &auth("arn:x:user/bob", &["arn:obio:iam::oidc:group/lake-admins"]),
            &principals
        ));
        assert!(!is_catalog_admin(&auth("arn:x:user/bob", &[]), &principals));
        // A tenant user named "admin" is not the operator.
        assert!(!is_catalog_admin(
            &auth("arn:objectio:iam::tenant/acme:user/admin", &[]),
            &principals
        ));
    }
}
