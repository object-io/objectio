//! Metadata gRPC service implementation

mod block;
mod block_meta;
mod buckets;
mod cluster;
mod delta;
mod grpc;
mod iam;
mod iceberg;
mod kms;
mod multipart;
mod objects;
mod packs;
mod tenants;
mod unity;
mod upgrade;

use objectio_common::{NodeId, NodeStatus};
use objectio_meta_store::{
    CasTable, EcConfig, MetaStore, MultipartUploadState, OsdNode, PartState, StoredAccessKey,
    StoredDataFilter, StoredGroup, StoredUser,
};
use objectio_placement::{
    Crush2, PlacementTemplate, ShardRole,
    topology::{ClusterTopology, DiskInfo, FailureDomainInfo, NodeInfo},
};
use sha2::{Digest, Sha256};

use objectio_proto::metadata::{
    AbortMultipartUploadRequest,
    AbortMultipartUploadResponse,
    // IAM types
    AccessKeyMeta,
    AddUserToGroupRequest,
    AddUserToGroupResponse,
    // Named IAM policy types
    AttachPolicyRequest,
    AttachPolicyResponse,
    BucketMeta,
    // Bucket SSE types
    BucketSseConfiguration,
    CallResult,
    CompleteMultipartUploadRequest,
    CompleteMultipartUploadResponse,
    // Config types
    ConfigEntry,
    CreateAccessKeyRequest,
    CreateAccessKeyResponse,
    CreateBucketRequest,
    CreateBucketResponse,
    CreateDataFilterRequest,
    CreateDataFilterResponse,
    CreateGroupRequest,
    CreateGroupResponse,
    CreateKmsKeyRequest,
    CreateKmsKeyResponse,
    CreateMultipartUploadRequest,
    CreateMultipartUploadResponse,
    CreateObjectRequest,
    CreateObjectResponse,
    CreatePolicyRequest,
    CreatePolicyResponse,
    // Pool types
    CreatePoolRequest,
    CreatePoolResponse,
    CreateRoleRequest,
    CreateRoleResponse,
    // Tenant types
    CreateTenantRequest,
    CreateTenantResponse,
    CreateUserRequest,
    CreateUserResponse,
    DeleteAccessKeyRequest,
    DeleteAccessKeyResponse,
    DeleteBucketEncryptionRequest,
    DeleteBucketEncryptionResponse,
    // Lifecycle types
    DeleteBucketLifecycleRequest,
    DeleteBucketLifecycleResponse,
    DeleteBucketPolicyRequest,
    DeleteBucketPolicyResponse,
    DeleteBucketRequest,
    DeleteBucketResponse,
    DeleteConfigRequest,
    DeleteConfigResponse,
    DeleteDataFilterRequest,
    DeleteDataFilterResponse,
    DeleteGroupRequest,
    DeleteGroupResponse,
    DeleteInlinePolicyRequest,
    DeleteInlinePolicyResponse,
    DeleteKmsKeyRequest,
    DeleteKmsKeyResponse,
    DeleteObjectRequest,
    DeleteObjectResponse,
    DeletePolicyRequest,
    DeletePolicyResponse,
    DeletePoolRequest,
    DeletePoolResponse,
    DeleteRoleRequest,
    DeleteRoleResponse,
    DeleteTenantRequest,
    DeleteTenantResponse,
    DeleteUserRequest,
    DeleteUserResponse,
    // Delta Sharing types
    DeltaAddTableRequest,
    DeltaAddTableResponse,
    DeltaCreateRecipientRequest,
    DeltaCreateRecipientResponse,
    DeltaCreateShareRequest,
    DeltaCreateShareResponse,
    DeltaDropRecipientRequest,
    DeltaDropRecipientResponse,
    DeltaDropShareRequest,
    DeltaDropShareResponse,
    DeltaGetRecipientByTokenRequest,
    DeltaGetRecipientByTokenResponse,
    DeltaGetShareRequest,
    DeltaGetShareResponse,
    DeltaListRecipientsRequest,
    DeltaListRecipientsResponse,
    DeltaListSharesRequest,
    DeltaListSharesResponse,
    DeltaListTablesRequest,
    DeltaListTablesResponse,
    DeltaRecipientEntry,
    DeltaRemoveTableRequest,
    DeltaRemoveTableResponse,
    DeltaShareEntry,
    DeltaShareTableEntry,
    DetachPolicyRequest,
    DetachPolicyResponse,
    DrainStatus as ProtoDrainStatus,
    ErasureType,
    GetAccessKeyForAuthRequest,
    GetAccessKeyForAuthResponse,
    GetBucketEncryptionRequest,
    GetBucketEncryptionResponse,
    GetBucketLifecycleRequest,
    GetBucketLifecycleResponse,
    GetBucketPolicyRequest,
    GetBucketPolicyResponse,
    GetBucketRequest,
    GetBucketResponse,
    // Versioning types
    GetBucketVersioningRequest,
    GetBucketVersioningResponse,
    GetConfigRequest,
    GetConfigResponse,
    GetDataFiltersForPrincipalRequest,
    GetDrainStatusRequest,
    GetDrainStatusResponse,
    GetInlinePolicyRequest,
    GetInlinePolicyResponse,
    GetKmsKeyRequest,
    GetKmsKeyResponse,
    GetListingNodesRequest,
    GetListingNodesResponse,
    GetMultipartUploadRequest,
    GetMultipartUploadResponse,
    // Object lock types
    GetObjectLockConfigRequest,
    GetObjectLockConfigResponse,
    GetObjectRequest,
    GetObjectResponse,
    GetPlacementGroupRequest,
    GetPlacementGroupResponse,
    GetPlacementRequest,
    GetPlacementResponse,
    GetPolicyRequest,
    GetPolicyResponse,
    GetPoolRequest,
    GetPoolResponse,
    GetRebalanceStatusRequest,
    GetRebalanceStatusResponse,
    GetRoleRequest,
    GetRoleResponse,
    GetTenantRequest,
    GetTenantResponse,
    GetUserGroupsRequest,
    GetUserGroupsResponse,
    GetUserRequest,
    GetUserResponse,
    GetWriteContextRequest,
    GetWriteContextResponse,
    GroupMeta,
    // Iceberg types
    IcebergCommitTableRequest,
    IcebergCommitTableResponse,
    IcebergCommitTransactionRequest,
    IcebergCommitTransactionResponse,
    IcebergCreateNamespaceRequest,
    IcebergCreateNamespaceResponse,
    IcebergCreateTableRequest,
    IcebergCreateTableResponse,
    IcebergCreateWarehouseRequest,
    IcebergCreateWarehouseResponse,
    IcebergDataFilter,
    IcebergDeleteWarehouseRequest,
    IcebergDeleteWarehouseResponse,
    IcebergDropNamespaceRequest,
    IcebergDropNamespaceResponse,
    IcebergDropTableRequest,
    IcebergDropTableResponse,
    IcebergGetTablePolicyRequest,
    IcebergGetTablePolicyResponse,
    IcebergListNamespacesRequest,
    IcebergListNamespacesResponse,
    IcebergListTablesRequest,
    IcebergListTablesResponse,
    IcebergListWarehousesRequest,
    IcebergListWarehousesResponse,
    IcebergLoadNamespaceRequest,
    IcebergLoadNamespaceResponse,
    IcebergLoadTableRequest,
    IcebergLoadTableResponse,
    IcebergNamespace,
    IcebergNamespaceExistsRequest,
    IcebergNamespaceExistsResponse,
    IcebergRenameTableRequest,
    IcebergRenameTableResponse,
    IcebergSetTablePolicyRequest,
    IcebergSetTablePolicyResponse,
    IcebergTableEntry,
    IcebergTableExistsRequest,
    IcebergTableExistsResponse,
    IcebergTableIdentifier,
    IcebergUpdateNamespacePropertiesRequest,
    IcebergUpdateNamespacePropertiesResponse,
    IcebergWarehouse,
    InlinePolicy,
    KeyStatus,
    KmsKey,
    LifecycleConfiguration,
    ListAccessKeysRequest,
    ListAccessKeysResponse,
    ListAttachedPoliciesRequest,
    ListAttachedPoliciesResponse,
    ListBucketsRequest,
    ListBucketsResponse,
    ListConfigRequest,
    ListConfigResponse,
    ListDataFiltersRequest,
    ListDataFiltersResponse,
    ListGroupsRequest,
    ListGroupsResponse,
    ListInlinePoliciesRequest,
    ListInlinePoliciesResponse,
    ListKmsKeysRequest,
    ListKmsKeysResponse,
    ListMultipartUploadsRequest,
    ListMultipartUploadsResponse,
    ListObjectsRequest,
    ListObjectsResponse,
    ListPartsRequest,
    ListPartsResponse,
    ListPlacementGroupsRequest,
    ListPlacementGroupsResponse,
    ListPoliciesRequest,
    ListPoliciesResponse,
    ListPoolsRequest,
    ListPoolsResponse,
    ListRolesRequest,
    ListRolesResponse,
    ListTenantsRequest,
    ListTenantsResponse,
    ListUsersRequest,
    ListUsersResponse,
    ListingNode,
    MultipartUpload,
    NodePlacement,
    ObjectHome,
    ObjectListingEntry,
    ObjectLockConfiguration,
    ObjectMeta,
    PartMeta,
    PlacementGroup,
    PolicyObject,
    PoolConfig,
    PutBucketEncryptionRequest,
    PutBucketEncryptionResponse,
    PutBucketLifecycleRequest,
    PutBucketLifecycleResponse,
    PutBucketVersioningRequest,
    PutBucketVersioningResponse,
    PutInlinePolicyRequest,
    PutInlinePolicyResponse,
    PutObjectLockConfigRequest,
    PutObjectLockConfigResponse,
    RegisterOsdRequest,
    RegisterOsdResponse,
    RegisterPartRequest,
    RegisterPartResponse,
    RemoveUserFromGroupRequest,
    RemoveUserFromGroupResponse,
    RoleObject,
    SetBucketOwnerRequest,
    SetBucketOwnerResponse,
    SetBucketPolicyRequest,
    SetBucketPolicyResponse,
    SetBucketQuotaRequest,
    SetBucketQuotaResponse,
    SetConfigRequest,
    SetConfigResponse,
    SetOsdAdminStateRequest,
    SetOsdAdminStateResponse,
    SettleMultipartUploadRequest,
    SettleMultipartUploadResponse,
    ShardType,
    TenantConfig,
    // Unity Catalog types
    UnityCatalog,
    UnityCreateCatalogRequest,
    UnityCreateCatalogResponse,
    UnityCreateFunctionRequest,
    UnityCreateFunctionResponse,
    UnityCreateModelRequest,
    UnityCreateModelResponse,
    UnityCreateModelVersionRequest,
    UnityCreateModelVersionResponse,
    UnityCreateSchemaRequest,
    UnityCreateSchemaResponse,
    UnityCreateTableRequest,
    UnityCreateTableResponse,
    UnityCreateVolumeRequest,
    UnityCreateVolumeResponse,
    UnityDeleteCatalogRequest,
    UnityDeleteCatalogResponse,
    UnityDeleteFunctionRequest,
    UnityDeleteFunctionResponse,
    UnityDeleteModelRequest,
    UnityDeleteModelResponse,
    UnityDeleteModelVersionRequest,
    UnityDeleteModelVersionResponse,
    UnityDeleteSchemaRequest,
    UnityDeleteSchemaResponse,
    UnityDeleteTableRequest,
    UnityDeleteTableResponse,
    UnityDeleteVolumeRequest,
    UnityDeleteVolumeResponse,
    // Functions
    UnityFunction,
    UnityGetCatalogPolicyRequest,
    UnityGetCatalogPolicyResponse,
    UnityGetCatalogRequest,
    UnityGetCatalogResponse,
    UnityGetFunctionRequest,
    UnityGetFunctionResponse,
    UnityGetModelRequest,
    UnityGetModelResponse,
    UnityGetModelVersionRequest,
    UnityGetModelVersionResponse,
    UnityGetSchemaPolicyRequest,
    UnityGetSchemaPolicyResponse,
    UnityGetSchemaRequest,
    UnityGetSchemaResponse,
    UnityGetTablePolicyRequest,
    UnityGetTablePolicyResponse,
    UnityGetTableRequest,
    UnityGetTableResponse,
    UnityGetVolumeRequest,
    UnityGetVolumeResponse,
    UnityListCatalogsRequest,
    UnityListCatalogsResponse,
    UnityListFunctionsRequest,
    UnityListFunctionsResponse,
    UnityListModelVersionsRequest,
    UnityListModelVersionsResponse,
    UnityListModelsRequest,
    UnityListModelsResponse,
    UnityListSchemasRequest,
    UnityListSchemasResponse,
    UnityListTablesRequest,
    UnityListTablesResponse,
    UnityListVolumesRequest,
    UnityListVolumesResponse,
    // Models + Versions
    UnityModel,
    UnityModelVersion,
    UnitySchema,
    UnitySetCatalogPolicyRequest,
    UnitySetCatalogPolicyResponse,
    UnitySetSchemaPolicyRequest,
    UnitySetSchemaPolicyResponse,
    UnitySetTablePolicyRequest,
    UnitySetTablePolicyResponse,
    UnitySetTableSecurityRequest,
    UnitySetTableSecurityResponse,
    UnityTable,
    UnityUpdateCatalogRequest,
    UnityUpdateCatalogResponse,
    UnityUpdateModelVersionStatusRequest,
    UnityUpdateModelVersionStatusResponse,
    UnityUpdateSchemaRequest,
    UnityUpdateSchemaResponse,
    // Volumes
    UnityVolume,
    UpdateAccessKeyRequest,
    UpdateAccessKeyResponse,
    UpdateGroupRequest,
    UpdateGroupResponse,
    UpdatePolicyRequest,
    UpdatePolicyResponse,
    UpdatePoolRequest,
    UpdatePoolResponse,
    UpdateRoleRequest,
    UpdateRoleResponse,
    UpdateTenantRequest,
    UpdateTenantResponse,
    UpdateUserRequest,
    UpdateUserResponse,
    UserMeta,
    UserStatus,
    VersioningState,
    metadata_service_server::MetadataService,
};
use parking_lot::RwLock;
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Map an openraft `client_write` error to a tonic status the gateway /
/// CLI can interpret. ForwardToLeader becomes `FailedPrecondition` with
/// a message the caller can parse for the leader id; all other errors
/// become `Internal`. Concrete to the types used by `MetaTypeConfig`.
fn raft_write_to_status(
    err: &openraft::error::RaftError<
        u64,
        openraft::error::ClientWriteError<u64, openraft::BasicNode>,
    >,
) -> tonic::Status {
    use openraft::error::{ClientWriteError, RaftError};
    match err {
        RaftError::APIError(ClientWriteError::ForwardToLeader(f)) => {
            let leader = f
                .leader_id
                .map_or_else(|| "unknown".to_string(), |id| id.to_string());
            let addr = f
                .leader_node
                .as_ref()
                .map_or_else(String::new, |n| format!(" at {}", n.addr));
            tonic::Status::failed_precondition(format!(
                "not the raft leader — forward to node {leader}{addr}"
            ))
        }
        other => tonic::Status::internal(format!("raft client_write: {other}")),
    }
}

/// Run a single-op `MultiCas` put through Raft. Centralizes the
/// boilerplate that every Unity Catalog mutation shares: build a
/// `MultiCas` with one `CasOp`, dispatch the matching `MetaResponse`
/// variants, and convert errors to `tonic::Status`. When Raft isn't
/// wired (in-memory tests or single-node store mode) this returns
/// `Ok(())` and the caller is expected to mirror the write into the
/// underlying store directly.
async fn cas_single_put(
    svc: &MetaService,
    table: objectio_meta_store::CasTable,
    key: &str,
    expected: Option<Vec<u8>>,
    new_value: Vec<u8>,
    requested_by: &str,
) -> Result<(), tonic::Status> {
    let Some(raft) = svc.raft_handle() else {
        return Ok(());
    };
    use objectio_meta_store::{CasOp, MetaCommand, MetaResponse};
    let cmd = MetaCommand::MultiCas {
        ops: vec![CasOp {
            table,
            key: key.to_string(),
            expected,
            new_value: Some(new_value),
        }],
        requested_by: requested_by.to_string(),
    };
    match raft.client_write(cmd).await {
        Ok(r) => match r.data {
            MetaResponse::MultiCasOk => Ok(()),
            MetaResponse::MultiCasConflict { .. } => Err(tonic::Status::aborted(format!(
                "{requested_by}: row changed since read; retry",
            ))),
            other => {
                tracing::error!("unexpected raft response for {requested_by}: {other:?}");
                Err(tonic::Status::internal("raft commit wrong variant"))
            }
        },
        Err(e) => Err(raft_write_to_status(&e)),
    }
}

/// Mirror of `cas_single_put` for deletes: tombstones a single row with
/// optimistic concurrency on its previous bytes.
async fn cas_single_delete(
    svc: &MetaService,
    table: objectio_meta_store::CasTable,
    key: &str,
    expected: Vec<u8>,
    requested_by: &str,
) -> Result<(), tonic::Status> {
    let Some(raft) = svc.raft_handle() else {
        return Ok(());
    };
    use objectio_meta_store::{CasOp, MetaCommand, MetaResponse};
    let cmd = MetaCommand::MultiCas {
        ops: vec![CasOp {
            table,
            key: key.to_string(),
            expected: Some(expected),
            new_value: None,
        }],
        requested_by: requested_by.to_string(),
    };
    match raft.client_write(cmd).await {
        Ok(r) => match r.data {
            MetaResponse::MultiCasOk => Ok(()),
            MetaResponse::MultiCasConflict { .. } => Err(tonic::Status::aborted(format!(
                "{requested_by}: row changed since read; retry",
            ))),
            other => {
                tracing::error!("unexpected raft response for {requested_by}: {other:?}");
                Err(tonic::Status::internal("raft commit wrong variant"))
            }
        },
        Err(e) => Err(raft_write_to_status(&e)),
    }
}

/// Classify a shard slot's role under MDS/LRC/Replication layouts the
/// PG-allocation path uses. For MDS and Replication the layout is
/// [data... parity...]; for LRC it is [data... local_parities...
/// global_parities...] ordered by `template.lrc(k, l, g)` in the
/// placement crate.
fn pg_position_shard_type(
    ec_type: ErasureType,
    position: usize,
    ec_k: usize,
    ec_local_parity: usize,
    _local_group_size: usize,
) -> ShardType {
    match ec_type {
        ErasureType::ErasureLrc => {
            if position < ec_k {
                ShardType::ShardData
            } else if position < ec_k + ec_local_parity {
                ShardType::ShardLocalParity
            } else {
                ShardType::ShardGlobalParity
            }
        }
        ErasureType::ErasureReplication => ShardType::ShardData,
        _ => {
            if position < ec_k {
                ShardType::ShardData
            } else {
                ShardType::ShardGlobalParity
            }
        }
    }
}

/// For LRC, shard positions within a local-parity group share a
/// `local_group` id. MDS and Replication return 0.
fn pg_position_local_group(
    ec_type: ErasureType,
    position: usize,
    ec_k: usize,
    ec_local_parity: usize,
    local_group_size: usize,
) -> u32 {
    if ec_type != ErasureType::ErasureLrc || local_group_size == 0 {
        return 0;
    }
    if position < ec_k {
        (position / local_group_size) as u32
    } else if position < ec_k + ec_local_parity {
        ((position - ec_k).min(ec_local_parity.saturating_sub(1))) as u32
    } else {
        0
    }
}

/// Metadata service state
///
/// Note: Object metadata is stored on OSDs (primary OSD for each object).
/// The meta service only stores cluster configuration (buckets, topology, policies).
/// ListObjects uses scatter-gather to query OSDs directly.
/// What status a node should carry in the placement topology.
///
/// Operator intent wins outright: Draining and Out are decisions, and
/// `active_nodes()` skips both however the node is behaving. `In` only means
/// the operator does not object, which is not the same as the node being
/// there — so whether it counts as Active depends on whether anything has
/// actually seen it.
///
/// `known` is the status it already carries, if it is already in the topology.
fn topology_status(
    admin: objectio_common::OsdAdminState,
    evidence: NodeEvidence,
    known: Option<NodeStatus>,
) -> NodeStatus {
    match admin {
        objectio_common::OsdAdminState::Draining => NodeStatus::Draining,
        objectio_common::OsdAdminState::Out => NodeStatus::Decommissioning,
        objectio_common::OsdAdminState::In => match evidence {
            NodeEvidence::Observed => NodeStatus::Active,
            // Keep a node the prober has confirmed; otherwise make it earn its
            // place. `Down` costs a live OSD one probe — the prober sweeps
            // immediately at startup and restores on first success — and costs
            // a dead one everything, which is the point.
            NodeEvidence::FromStore => match known {
                Some(NodeStatus::Active) => NodeStatus::Active,
                _ => NodeStatus::Down,
            },
        },
    }
}

/// Whether a topology update is backed by evidence that the node is reachable
/// right now, or is only a record being replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeEvidence {
    /// The node just registered — it opened a connection and identified itself.
    Observed,
    /// Loaded from the store, or swept up in a rebuild of every node. Says
    /// nothing about whether the node is there.
    FromStore,
}

pub struct MetaService {
    /// Renders this node's Prometheus exposition for `GetMetrics`. Set by
    /// the binary once its metrics state exists.
    metrics_renderer: std::sync::OnceLock<Box<dyn Fn() -> String + Send + Sync>>,
    /// Bucket metadata: name -> BucketMeta
    buckets: RwLock<HashMap<String, BucketMeta>>,
    /// Bucket policies: bucket_name -> policy_json
    bucket_policies: RwLock<HashMap<String, String>>,
    /// In-progress multipart uploads: upload_id -> MultipartUploadState
    multipart_uploads: RwLock<HashMap<String, MultipartUploadState>>,
    /// Registered OSD nodes
    osd_nodes: RwLock<Vec<OsdNode>>,
    /// Cluster topology for CRUSH 2.0
    topology: RwLock<ClusterTopology>,
    /// CRUSH 2.0 placement engine
    crush: RwLock<Crush2>,
    /// Default erasure coding configuration
    default_ec: EcConfig,
    /// Default erasure coding parameters (for backward compat)
    default_ec_k: u32,
    default_ec_m: u32,
    /// IAM: Users indexed by user_id
    users: RwLock<HashMap<String, StoredUser>>,
    /// IAM: Access keys indexed by access_key_id
    access_keys: RwLock<HashMap<String, StoredAccessKey>>,
    /// IAM: Map from user_id to their access_key_ids
    user_keys: RwLock<HashMap<String, Vec<String>>>,
    /// IAM: Groups indexed by group_id
    groups: RwLock<HashMap<String, StoredGroup>>,
    /// Iceberg: data filters indexed by filter_id
    data_filters: RwLock<HashMap<String, StoredDataFilter>>,
    /// Iceberg: namespace key -> properties (prost-encoded bytes in store, HashMap in memory)
    iceberg_namespaces: RwLock<HashMap<String, HashMap<String, String>>>,
    /// Iceberg: table key ("ns\0table") -> IcebergTableEntry
    iceberg_tables: RwLock<HashMap<String, IcebergTableEntry>>,
    /// Delta Sharing: share name -> DeltaShareEntry
    delta_shares: RwLock<HashMap<String, DeltaShareEntry>>,
    /// Delta Sharing: "{share}\x00{schema}\x00{table}" -> DeltaShareTableEntry
    delta_tables: RwLock<HashMap<String, DeltaShareTableEntry>>,
    /// Delta Sharing: recipient name -> DeltaRecipientEntry
    delta_recipients: RwLock<HashMap<String, DeltaRecipientEntry>>,
    /// Delta Sharing: token_hash -> recipient name (reverse index for auth lookups)
    delta_token_index: RwLock<HashMap<String, String>>,
    /// Cluster configuration: key -> ConfigEntry (prost-encoded)
    config: RwLock<HashMap<String, ConfigEntry>>,
    /// Config version counter (monotonically increasing)
    config_version: std::sync::atomic::AtomicU64,
    /// Every node's last version report, kept by the leader (rolling
    /// upgrades; see `upgrade.rs`). Keyed by (kind, id).
    versions: RwLock<HashMap<(String, String), upgrade::Report>>,
    /// Server pools: name -> PoolConfig
    pools: RwLock<HashMap<String, PoolConfig>>,
    /// Tenants: name -> TenantConfig
    tenants: RwLock<HashMap<String, TenantConfig>>,
    /// IAM policies: name -> PolicyObject
    iam_policies: RwLock<HashMap<String, PolicyObject>>,
    /// Policy attachments: "user:{id}" or "group:{id}" -> Vec<policy_name>
    policy_attachments: RwLock<HashMap<String, Vec<String>>>,
    /// Iceberg warehouses: warehouse_name -> IcebergWarehouse
    iceberg_warehouses: RwLock<HashMap<String, IcebergWarehouse>>,
    /// Unity Catalog: catalog_name -> UnityCatalog (top-level container,
    /// auto-provisions a backing "unity-{name}" bucket for MANAGED tables).
    unity_catalogs: RwLock<HashMap<String, UnityCatalog>>,
    /// Unity Catalog: "{catalog}\x00{schema}" -> UnitySchema
    unity_schemas: RwLock<HashMap<String, UnitySchema>>,
    /// Unity Catalog: "{catalog}\x00{schema}\x00{table}" -> UnityTable
    unity_tables: RwLock<HashMap<String, UnityTable>>,
    /// Unity Catalog: "{catalog}\x00{schema}\x00{function}" -> UnityFunction
    unity_functions: RwLock<HashMap<String, UnityFunction>>,
    /// Unity Catalog: "{catalog}\x00{schema}\x00{volume}" -> UnityVolume
    unity_volumes: RwLock<HashMap<String, UnityVolume>>,
    /// Unity Catalog: "{catalog}\x00{schema}\x00{model}" -> UnityModel
    unity_models: RwLock<HashMap<String, UnityModel>>,
    /// Unity Catalog: "{catalog}\x00{schema}\x00{model}\x00{version:010}"
    /// -> UnityModelVersion. Versions are zero-padded to 10 digits so
    /// range scans land in numeric order (1 < 2 < … < 10 < 11).
    unity_model_versions: RwLock<HashMap<String, UnityModelVersion>>,
    /// Placement groups: (pool, pg_id) -> PlacementGroup. Refreshed by
    /// the apply-listener so every replica has an up-to-date cache and
    /// GetPlacement on the leader is a sub-millisecond in-memory lookup.
    placement_groups: RwLock<HashMap<(String, u32), PlacementGroup>>,
    /// Object lock configurations: bucket_name -> ObjectLockConfiguration
    object_lock_configs: RwLock<HashMap<String, ObjectLockConfiguration>>,
    /// Shared stripes and who references them, by stripe id in hex. See
    /// `share_stripes`.
    stripe_refs: RwLock<HashMap<String, objectio_proto::metadata::StripeRefs>>,
    /// Block volumes, chunk maps and snapshots, as stored. See `block_meta`.
    block: RwLock<block_meta::BlockTables>,
    /// Serializes block metadata changes on this node, so a multi-step
    /// change (a snapshot copying a chunk map) is not raced by another.
    block_lock: tokio::sync::Mutex<()>,
    /// Lifecycle configurations: bucket_name -> LifecycleConfiguration
    lifecycle_configs: RwLock<HashMap<String, LifecycleConfiguration>>,
    /// Bucket default SSE configurations: bucket_name -> BucketSseConfiguration
    bucket_encryption_configs: RwLock<HashMap<String, BucketSseConfiguration>>,
    /// KMS keys (material already wrapped by gateway's service master key):
    /// key_id -> KmsKey
    kms_keys: RwLock<HashMap<String, KmsKey>>,
    /// Persistent store (None = in-memory only)
    store: Option<Arc<MetaStore>>,
    /// Raft handle — set by main.rs after `Raft::new()` succeeds. Config
    /// mutations route through `client_write`; other mutations still
    /// write to redb directly pending their R2+ migration. Behind a
    /// `RwLock` so the service can be constructed before Raft (the
    /// existing startup order needs meta_service to register OSDs first).
    raft: RwLock<Option<Arc<openraft::Raft<objectio_meta_store::MetaTypeConfig>>>>,
    /// Per-OSD drain progress — populated by the Phase 3b migrator
    /// while an OSD is Draining, cleared when the OSD flips to Out or
    /// back to In. Keyed by 16-byte node_id.
    ///
    /// Exposed to the admin layer via `drain_statuses()` and consumed
    /// by `GET /_admin/drain-status`. Lives in memory only — losing
    /// progress across leader failover is OK, the next sweep
    /// reconstructs it from current shard counts.
    drain_statuses: RwLock<HashMap<[u8; 16], DrainProgress>>,
    /// Cluster-wide rebalance progress (one instance, not per-OSD).
    rebalance_progress: RwLock<RebalanceProgress>,
}

/// Cluster-wide rebalance progress — exposed to the admin UI.
///
/// The rebalancer scans every primary-held ObjectMeta in the cluster
/// once per scan cycle and migrates misplaced shards at the same rate
/// as the drain migrator. One instance lives in `MetaService`;
/// populated on the Raft leader, read by anyone.
#[derive(Clone, Debug, Default)]
pub struct RebalanceProgress {
    /// True iff the reconciler sweep touched at least one OSD since
    /// process start. Lets the console distinguish "not yet started"
    /// from "finished clean".
    pub started: bool,
    /// Admin-toggled: when true, reconciler skips its sweep. Stored
    /// in the `rebalance/paused` config key; mirrored here for fast
    /// reads without a config lookup.
    pub paused: bool,
    /// Last time a sweep completed (unix seconds). 0 before first.
    pub last_sweep_at: u64,
    /// Number of ObjectMetas scanned so far in the current pass.
    /// Resets each time we complete a full loop through the cluster.
    pub scanned_this_pass: u64,
    /// Number of drifted shards observed in the current pass.
    pub drifts_seen_this_pass: u64,
    /// Cumulative count of shards successfully migrated since process
    /// start. Monotonic — doesn't reset per pass.
    pub shards_rebalanced_total: u64,
    /// Last non-empty error (transient OSD outage, etc.). Empty when
    /// the last sweep succeeded. Surfaces real failures to operators.
    pub last_error: String,
    /// Cumulative PG moves committed by the balancer since process
    /// start. Non-decreasing.
    pub pgs_moved_total: u64,
    /// PG candidates (overloaded/underloaded) found in the most
    /// recent balancer tick. Reset per tick.
    pub pg_candidates_last_tick: u64,
    /// PGs scanned in the most recent balancer tick.
    pub pgs_scanned_last_tick: u64,
}

/// Live progress for one Draining OSD.
#[derive(Clone, Debug, Default)]
pub struct DrainProgress {
    /// shard_count reported by the OSD at the last sweep.
    pub shards_remaining: u64,
    /// Initial shard_count observed when the OSD first entered
    /// Draining in this leader's lifetime. Used for "X of Y migrated"
    /// display — `shards_migrated = initial - remaining`.
    pub initial_shards: u64,
    /// Unix seconds of the last sweep update.
    pub updated_at: u64,
    /// Last non-transient error observed by the migrator for this
    /// OSD. Empty when the last sweep succeeded. Surfaced to the
    /// admin UI so operators see real failures instead of silent
    /// stalls.
    pub last_error: String,
    /// Number of shards the migrator successfully moved so far (distinct
    /// from the derived `initial - remaining` because OSD shard_count
    /// is eventually consistent and may lag slightly).
    pub shards_migrated: u64,
}

/// Statistics for the metadata service
#[derive(Debug, Clone, Default)]
pub struct MetaStats {
    pub bucket_count: u64,
    pub osd_count: u64,
    pub user_count: u64,
}

impl Default for MetaService {
    fn default() -> Self {
        Self::new()
    }
}

/// Tries a compare-and-set loop makes before answering "kept changing":
/// many releases of one pack at once (an object's delete, the packer's
/// release, compaction) all write its one registry entry.
const CAS_ATTEMPTS: u32 = 64;

/// A short, growing, randomised pause between compare-and-set attempts, so
/// writers contending for one entry spread out instead of colliding again.
async fn contention_backoff(attempt: u32) {
    use rand::Rng;
    let cap_ms = 1u64 << attempt.min(5);
    let ms = rand::thread_rng().gen_range(0..=cap_ms);
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
}

impl MetaService {
    /// Create a new metadata service with default MDS 4+2 configuration
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::with_ec_config(EcConfig::default())
    }

    /// Install the function `GetMetrics` serves. Later calls are ignored.
    pub fn set_metrics_renderer(&self, f: Box<dyn Fn() -> String + Send + Sync>) {
        let _ = self.metrics_renderer.set(f);
    }

    /// Get statistics for metrics
    pub fn stats(&self) -> MetaStats {
        let bucket_count = self.buckets.read().len() as u64;
        let osd_count = self.topology.read().all_nodes().count() as u64;
        let user_count = self.users.read().len() as u64;

        MetaStats {
            bucket_count,
            osd_count,
            user_count,
        }
    }

    /// Create a new metadata service with custom EC configuration
    pub fn with_ec_config(ec_config: EcConfig) -> Self {
        let topology = ClusterTopology::new();
        let crush = Crush2::new(topology.clone(), 64); // 64 stripe groups

        // For replication mode: k=1 (full data), m=0 (no parity)
        // The gateway will skip EC encoding entirely
        let (default_ec_k, default_ec_m) = match &ec_config {
            EcConfig::Mds { k, m } => (*k as u32, *m as u32),
            EcConfig::Lrc { k, l, g } => (*k as u32, (*l + *g) as u32),
            EcConfig::Replication { count: _ } => (1, 0), // No EC, just raw data
        };

        Self {
            metrics_renderer: std::sync::OnceLock::new(),
            buckets: RwLock::new(HashMap::new()),
            bucket_policies: RwLock::new(HashMap::new()),
            multipart_uploads: RwLock::new(HashMap::new()),
            osd_nodes: RwLock::new(Vec::new()),
            topology: RwLock::new(topology),
            crush: RwLock::new(crush),
            default_ec: ec_config,
            default_ec_k,
            default_ec_m,
            users: RwLock::new(HashMap::new()),
            access_keys: RwLock::new(HashMap::new()),
            user_keys: RwLock::new(HashMap::new()),
            groups: RwLock::new(HashMap::new()),
            data_filters: RwLock::new(HashMap::new()),
            iceberg_namespaces: RwLock::new(HashMap::new()),
            iceberg_tables: RwLock::new(HashMap::new()),
            delta_shares: RwLock::new(HashMap::new()),
            delta_tables: RwLock::new(HashMap::new()),
            delta_recipients: RwLock::new(HashMap::new()),
            delta_token_index: RwLock::new(HashMap::new()),
            config: RwLock::new(HashMap::new()),
            config_version: std::sync::atomic::AtomicU64::new(0),
            versions: RwLock::new(HashMap::new()),
            pools: RwLock::new(HashMap::new()),
            tenants: RwLock::new(HashMap::new()),
            iam_policies: RwLock::new(HashMap::new()),
            policy_attachments: RwLock::new(HashMap::new()),
            iceberg_warehouses: RwLock::new(HashMap::new()),
            unity_catalogs: RwLock::new(HashMap::new()),
            unity_schemas: RwLock::new(HashMap::new()),
            unity_tables: RwLock::new(HashMap::new()),
            unity_functions: RwLock::new(HashMap::new()),
            unity_volumes: RwLock::new(HashMap::new()),
            unity_models: RwLock::new(HashMap::new()),
            unity_model_versions: RwLock::new(HashMap::new()),
            placement_groups: RwLock::new(HashMap::new()),
            object_lock_configs: RwLock::new(HashMap::new()),
            stripe_refs: RwLock::new(HashMap::new()),
            block: RwLock::new(block_meta::BlockTables::default()),
            block_lock: tokio::sync::Mutex::new(()),
            lifecycle_configs: RwLock::new(HashMap::new()),
            bucket_encryption_configs: RwLock::new(HashMap::new()),
            kms_keys: RwLock::new(HashMap::new()),
            drain_statuses: RwLock::new(HashMap::new()),
            rebalance_progress: RwLock::new(RebalanceProgress::default()),
            store: None,
            raft: RwLock::new(None),
        }
    }

    /// Create a metadata service backed by persistent storage.
    /// Loads all existing data from the store on startup.
    pub fn with_store(ec_config: EcConfig, store: Arc<MetaStore>) -> Self {
        let mut svc = Self::with_ec_config(ec_config);
        svc.store = Some(store);
        svc.load_from_store();
        svc
    }

    /// Borrow the underlying persistent store, if the service is
    /// persistence-backed. Raft wiring needs this so `MetaRaftStorage`
    /// can share the same redb database handle.
    #[must_use]
    pub fn store(&self) -> Option<Arc<MetaStore>> {
        self.store.clone()
    }

    /// Install the Raft handle. Called from `main.rs` once the cluster
    /// scaffolding is live, before the service is wrapped in `Arc`.
    /// Config mutations routed through Raft become linearizable; without
    /// a handle set, they fall back to the legacy direct-redb path
    /// (useful for in-memory tests).
    pub fn set_raft(&self, raft: Arc<openraft::Raft<objectio_meta_store::MetaTypeConfig>>) {
        *self.raft.write() = Some(raft);
    }

    /// Current Raft handle, if any.
    pub fn raft_handle(&self) -> Option<Arc<openraft::Raft<objectio_meta_store::MetaTypeConfig>>> {
        self.raft.read().clone()
    }

    /// Spawn the apply-listener task. Consumes `ApplyEvent`s emitted by
    /// the Raft state machine after every committed MultiCas and
    /// refreshes the matching in-memory cache. Runs on every replica —
    /// not just the leader — so on failover a freshly-promoted pod
    /// serves reads against a cache that was kept live all along,
    /// instead of the pre-Raft snapshot plus whatever's been applied
    /// since startup.
    pub fn spawn_apply_listener(
        self: &Arc<Self>,
        mut rx: tokio::sync::mpsc::UnboundedReceiver<objectio_meta_store::ApplyEvent>,
    ) {
        let svc = Arc::clone(self);
        tokio::spawn(async move {
            use objectio_meta_store::{ApplyEvent, CasTable};
            while let Some(ev) = rx.recv().await {
                match ev {
                    // Every table was replaced: rebuild every cache.
                    ApplyEvent::SnapshotInstalled => {
                        info!("Raft snapshot installed; reloading meta state from the store");
                        svc.load_from_store();
                    }
                    ApplyEvent::MultiCasOp {
                        table,
                        key,
                        new_value,
                    } => match table {
                        CasTable::Buckets => svc.apply_bucket_event(&key, new_value.as_deref()),
                        CasTable::BucketPolicies => {
                            svc.apply_bucket_policy_event(&key, new_value.as_deref());
                        }
                        CasTable::Users => svc.apply_user_event(&key, new_value.as_deref()),
                        CasTable::AccessKeys => {
                            svc.apply_access_key_event(&key, new_value.as_deref());
                        }
                        CasTable::IcebergTables => {
                            svc.apply_iceberg_table_event(&key, new_value.as_deref());
                        }
                        CasTable::IcebergNamespaces => {
                            svc.apply_iceberg_namespace_event(&key, new_value.as_deref());
                        }
                        CasTable::IcebergWarehouses => {
                            svc.apply_iceberg_warehouse_event(&key, new_value.as_deref());
                        }
                        CasTable::UnityCatalogs => {
                            svc.apply_unity_catalog_event(&key, new_value.as_deref());
                        }
                        CasTable::UnitySchemas => {
                            svc.apply_unity_schema_event(&key, new_value.as_deref());
                        }
                        CasTable::UnityTables => {
                            svc.apply_unity_table_event(&key, new_value.as_deref());
                        }
                        CasTable::UnityFunctions => {
                            svc.apply_unity_function_event(&key, new_value.as_deref());
                        }
                        CasTable::UnityVolumes => {
                            svc.apply_unity_volume_event(&key, new_value.as_deref());
                        }
                        CasTable::UnityModels => {
                            svc.apply_unity_model_event(&key, new_value.as_deref());
                        }
                        CasTable::UnityModelVersions => {
                            svc.apply_unity_model_version_event(&key, new_value.as_deref());
                        }
                        CasTable::PlacementGroups => {
                            svc.apply_placement_group_event(&key, new_value.as_deref());
                        }
                        CasTable::Config => {
                            svc.apply_config_event(&key, new_value.as_deref());
                        }
                        CasTable::Tenants => svc.apply_tenant_event(&key, new_value.as_deref()),
                        CasTable::Named(ref t) if t == "stripe_refs" => {
                            svc.apply_stripe_refs_event(&key, new_value.as_deref());
                        }
                        CasTable::Named(ref t) if t == OSD_NODES_TABLE => {
                            svc.apply_osd_node_event(&key, new_value.as_deref());
                        }
                        CasTable::Named(ref t) if t == KMS_KEYS_TABLE => {
                            svc.apply_kms_key_event(&key, new_value.as_deref());
                        }
                        CasTable::Named(ref t) if t == MULTIPART_TABLE => {
                            svc.apply_multipart_event(&key, new_value.as_deref());
                        }
                        CasTable::Named(ref t) if block_meta::TABLES.contains(&t.as_str()) => {
                            svc.apply_block_event(t, &key, new_value.as_deref());
                        }
                        // Tables not yet covered by a cache refresh:
                        // writers are responsible for mirroring their
                        // own writes on the leader, and followers still
                        // rebuild from redb on promote (load_from_store).
                        _ => {}
                    },
                }
            }
        });
    }

    /// Apply several compare-and-set writes in one commit. `Ok(false)` on
    /// a conflict, for the caller to re-read and retry.
    async fn cas_many(
        &self,
        ops: Vec<objectio_meta_store::CasOp>,
        what: &str,
    ) -> Result<bool, Status> {
        use objectio_meta_store::{MetaCommand, MetaResponse};
        if ops.is_empty() {
            return Ok(true);
        }
        if let Some(raft) = self.raft_handle() {
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: what.into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => Ok(true),
                    MetaResponse::MultiCasConflict { .. } => Ok(false),
                    other => {
                        error!("unexpected raft response for {what}: {other:?}");
                        Err(Status::internal("raft commit wrong variant"))
                    }
                },
                Err(e) => Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            for op in ops {
                store.write_named(
                    objectio_meta_store::cas_table_name(&op.table),
                    &op.key,
                    op.new_value.as_deref(),
                );
            }
            Ok(true)
        } else {
            Err(Status::unavailable("no store"))
        }
    }

    /// Write `writes` — `(table, key, value)`, `None` to delete — through
    /// Raft, so every meta node holds them, not just this one. Each is
    /// set over whatever the store holds now (last writer wins), as one
    /// compare-and-set retried on conflict. Without Raft (in-memory tests,
    /// store-only mode) they go to the store directly.
    pub(crate) async fn replicate(
        &self,
        writes: Vec<(&'static str, String, Option<Vec<u8>>)>,
        what: &str,
    ) -> Result<(), Status> {
        let Some(store) = self.store.as_ref() else {
            return Ok(());
        };
        if self.raft_handle().is_none() {
            for (table, key, value) in &writes {
                store.write_named(table, key, value.as_deref());
            }
            return Ok(());
        }
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let ops = writes
                .iter()
                .map(|(table, key, value)| objectio_meta_store::CasOp {
                    table: CasTable::Named((*table).into()),
                    key: key.clone(),
                    expected: store.read_named(table, key),
                    new_value: value.clone(),
                })
                .collect();
            if self.cas_many(ops, what).await? {
                return Ok(());
            }
        }
        Err(Status::aborted(format!("{what}: kept changing; retry")))
    }

    /// True iff this replica is the current Raft leader. Used by
    /// leader-only background tasks (drain observer, future migrator)
    /// so every replica can run the task definition while only one
    /// actually mutates state.
    ///
    /// Returns `false` when Raft isn't wired (in-memory tests), which
    /// is the correct answer — there's no leader to issue writes to.
    #[must_use]
    pub fn is_raft_leader(&self) -> bool {
        self.raft_handle()
            .map(|r| {
                let m = r.metrics().borrow().clone();
                m.current_leader == Some(m.id)
            })
            .unwrap_or(false)
    }

    /// Fetch a config value as a string, falling back to `default` if
    /// the key is absent, un-UTF-8, or the stored bytes are empty.
    /// Used by background tasks (balancer, drain observer) to hot-read
    /// tuning knobs without restarting the process.
    pub fn config_str(&self, key: &str, default: &str) -> String {
        let cfg = self.config.read();
        cfg.get(key)
            .and_then(|e| std::str::from_utf8(&e.value).ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map_or_else(|| default.to_string(), str::to_string)
    }

    /// Typed config read — `FromStr` into the target type, falling
    /// back to `default` on any error (missing key, parse failure).
    pub fn config_parsed<T: std::str::FromStr>(&self, key: &str, default: T) -> T {
        self.config_str(key, "").parse::<T>().unwrap_or(default)
    }

    /// Stable cluster UUID — lazily generated on first request and
    /// persisted via Raft (config key `cluster/uuid`). Handed back to
    /// every OSD on RegisterOsd so they can stamp their disk
    /// superblocks with it; a disk whose on-disk cluster_uuid differs
    /// from this value is refused by `DiskManager::set_identity`,
    /// preventing an operator from accidentally mounting a disk from a
    /// different cluster.
    pub async fn cluster_uuid(&self) -> Vec<u8> {
        // Deliberately "cluster/id" rather than "cluster/uuid" — an
        // earlier patch of this function wrote raw 16-byte UUIDs to
        // `cluster/uuid` (missing the ConfigEntry wrap), which left
        // some clusters with a decode-failing entry at that key and a
        // permanent MultiCasConflict on re-write with expected=None.
        // Using a fresh key sidesteps the recovery dance.
        const KEY: &str = "cluster/id";
        // Fast path — in-memory config cache.
        {
            let cfg = self.config.read();
            if let Some(entry) = cfg.get(KEY)
                && entry.value.len() == 16
            {
                return entry.value.clone();
            }
        }

        // Slow path — not yet set. Generate a fresh UUID and persist
        // via Raft so every replica agrees. Only the leader actually
        // writes; followers return empty so the OSD skips stamping
        // and tries again on the next register retry.
        let Some(raft) = self.raft_handle() else {
            warn!(
                "cluster_uuid requested before Raft handle is set — returning non-persistent value"
            );
            return Uuid::new_v4().as_bytes().to_vec();
        };
        if !self.is_raft_leader() {
            return Vec::new();
        }

        let fresh = Uuid::new_v4();
        let uuid_bytes = fresh.as_bytes().to_vec();

        // Config entries are stored as prost-encoded ConfigEntry
        // values. Writing raw UUID bytes makes the apply-listener
        // drop the entry (decode failure) and the cache never
        // observes the write — which is exactly what used to happen.
        let version = self
            .config_version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let entry = ConfigEntry {
            key: KEY.to_string(),
            value: uuid_bytes.clone(),
            updated_at: Self::current_timestamp(),
            updated_by: "cluster-uuid-init".into(),
            version,
        };

        use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
        // A cluster gets its id when its first OSD registers: it is new,
        // so nothing older than this binary is in it, and it starts at
        // this binary's format level.
        let level = ConfigEntry {
            key: objectio_common::version::ACTIVE_LEVEL_KEY.to_string(),
            value: objectio_common::version::FORMAT_LEVEL
                .to_string()
                .into_bytes(),
            updated_at: Self::current_timestamp(),
            updated_by: "cluster-uuid-init".into(),
            version,
        };
        let cmd = MetaCommand::MultiCas {
            ops: vec![
                CasOp {
                    table: CasTable::Config,
                    key: KEY.to_string(),
                    expected: None,
                    new_value: Some(entry.encode_to_vec()),
                },
                CasOp {
                    table: CasTable::Config,
                    key: objectio_common::version::ACTIVE_LEVEL_KEY.to_string(),
                    expected: None,
                    new_value: Some(level.encode_to_vec()),
                },
            ],
            requested_by: "cluster-uuid-init".into(),
        };
        match raft.client_write(cmd).await {
            Ok(r) => match r.data {
                MetaResponse::MultiCasOk => {
                    info!("Generated and persisted cluster/id: {fresh}");
                    uuid_bytes
                }
                MetaResponse::MultiCasConflict { .. } => {
                    // Another caller won the race (or a pre-existing
                    // corrupt entry sits at this key). Poll the config
                    // cache briefly — the apply listener populates it
                    // shortly after the raft commit.
                    for _ in 0..20 {
                        if let Some(entry) = self.config.read().get(KEY)
                            && entry.value.len() == 16
                        {
                            return entry.value.clone();
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    warn!(
                        "cluster_uuid conflict but cache never populated — giving up for this call"
                    );
                    Vec::new()
                }
                other => {
                    warn!("cluster_uuid generation got unexpected raft response: {other:?}");
                    Vec::new()
                }
            },
            Err(e) => {
                warn!("Failed to persist cluster_uuid: {e}");
                Vec::new()
            }
        }
    }

    /// Load all data from the persistent store into in-memory maps.
    /// Fill every cache from the store, clearing it first: run at startup,
    /// and again after a Raft snapshot replaced the store's tables, when an
    /// entry the snapshot no longer has must not linger.
    fn load_from_store(&self) {
        let Some(store) = &self.store else { return };

        // Buckets
        match store.load_buckets() {
            Ok(buckets) => {
                let mut map = self.buckets.write();
                map.clear();
                for (name, bucket) in buckets {
                    map.insert(name, bucket);
                }
                info!("Loaded {} buckets from store", map.len());
            }
            Err(e) => error!("Failed to load buckets: {}", e),
        }

        // Bucket policies
        match store.load_bucket_policies() {
            Ok(policies) => {
                let mut map = self.bucket_policies.write();
                map.clear();
                for (name, policy) in policies {
                    map.insert(name, policy);
                }
                info!("Loaded {} bucket policies from store", map.len());
            }
            Err(e) => error!("Failed to load bucket policies: {}", e),
        }

        // Multipart uploads
        match store.load_multipart_uploads() {
            Ok(uploads) => {
                let mut map = self.multipart_uploads.write();
                map.clear();
                for (id, state) in uploads {
                    map.insert(id, state);
                }
                info!("Loaded {} multipart uploads from store", map.len());
            }
            Err(e) => error!("Failed to load multipart uploads: {}", e),
        }

        // OSD nodes, then the topology rebuilt from them
        match store.load_osd_nodes() {
            Ok(nodes) => {
                let mut osd_nodes = self.osd_nodes.write();
                *osd_nodes = nodes.into_iter().map(|(_, node)| node).collect();
                info!("Loaded {} OSD nodes from store", osd_nodes.len());
            }
            Err(e) => error!("Failed to load OSD nodes: {}", e),
        }

        // Topology — rebuilt from the OSD list, the only source.
        {
            let nodes = self.osd_nodes.read().clone();
            *self.topology.write() = Default::default();
            for node in &nodes {
                self.refresh_topology_node(node);
            }
            info!(
                "Rebuilt topology from {} stored OSD nodes (pending liveness probe)",
                nodes.len()
            );
        }

        // Users
        match store.load_users() {
            Ok(users) => {
                let mut user_map = self.users.write();
                user_map.clear();
                let mut user_keys = self.user_keys.write();
                user_keys.clear();
                for (id, user) in users {
                    user_keys.entry(id.clone()).or_default();
                    user_map.insert(id, user);
                }
                info!("Loaded {} users from store", user_map.len());
            }
            Err(e) => error!("Failed to load users: {}", e),
        }

        // Access keys (rebuild user_keys index)
        match store.load_access_keys() {
            Ok(keys) => {
                let mut key_map = self.access_keys.write();
                key_map.clear();
                let mut user_keys = self.user_keys.write();
                for (id, key) in keys {
                    user_keys
                        .entry(key.user_id.clone())
                        .or_default()
                        .push(id.clone());
                    key_map.insert(id, key);
                }
                info!("Loaded {} access keys from store", key_map.len());
            }
            Err(e) => error!("Failed to load access keys: {}", e),
        }

        // Groups
        match store.load_groups() {
            Ok(groups) => {
                let mut group_map = self.groups.write();
                group_map.clear();
                for (id, group) in groups {
                    group_map.insert(id, group);
                }
                info!("Loaded {} groups from store", group_map.len());
            }
            Err(e) => error!("Failed to load groups: {}", e),
        }

        // Data filters
        match store.load_data_filters() {
            Ok(filters) => {
                let mut filter_map = self.data_filters.write();
                filter_map.clear();
                for (id, filter) in filters {
                    filter_map.insert(id, filter);
                }
                info!("Loaded {} data filters from store", filter_map.len());
            }
            Err(e) => error!("Failed to load data filters: {}", e),
        }

        // Iceberg namespaces
        match store.list_iceberg_namespaces("") {
            Ok(entries) => {
                let mut ns_map = self.iceberg_namespaces.write();
                ns_map.clear();
                for (key, bytes) in entries {
                    match IcebergCreateNamespaceResponse::decode(bytes.as_slice()) {
                        Ok(resp) => {
                            ns_map.insert(key, resp.properties);
                        }
                        Err(e) => error!("Failed to decode iceberg namespace '{}': {}", key, e),
                    }
                }
                info!("Loaded {} iceberg namespaces from store", ns_map.len());
            }
            Err(e) => error!("Failed to load iceberg namespaces: {}", e),
        }

        // Iceberg tables
        match store.list_iceberg_tables("") {
            Ok(entries) => {
                let mut tbl_map = self.iceberg_tables.write();
                tbl_map.clear();
                for (key, bytes) in entries {
                    match IcebergTableEntry::decode(bytes.as_slice()) {
                        Ok(entry) => {
                            tbl_map.insert(key, entry);
                        }
                        Err(e) => error!("Failed to decode iceberg table '{}': {}", key, e),
                    }
                }
                info!("Loaded {} iceberg tables from store", tbl_map.len());
            }
            Err(e) => error!("Failed to load iceberg tables: {}", e),
        }

        // Delta Sharing: shares
        match store.load_delta_shares() {
            Ok(entries) => {
                let mut map = self.delta_shares.write();
                map.clear();
                for (key, bytes) in entries {
                    match DeltaShareEntry::decode(bytes.as_slice()) {
                        Ok(entry) => {
                            map.insert(key, entry);
                        }
                        Err(e) => error!("Failed to decode delta share '{}': {}", key, e),
                    }
                }
                info!("Loaded {} delta shares from store", map.len());
            }
            Err(e) => error!("Failed to load delta shares: {}", e),
        }

        // Delta Sharing: tables
        match store.load_delta_tables() {
            Ok(entries) => {
                let mut map = self.delta_tables.write();
                map.clear();
                for (key, bytes) in entries {
                    match DeltaShareTableEntry::decode(bytes.as_slice()) {
                        Ok(entry) => {
                            map.insert(key, entry);
                        }
                        Err(e) => error!("Failed to decode delta table '{}': {}", key, e),
                    }
                }
                info!("Loaded {} delta tables from store", map.len());
            }
            Err(e) => error!("Failed to load delta tables: {}", e),
        }

        // Delta Sharing: recipients (rebuild token index)
        match store.load_delta_recipients() {
            Ok(entries) => {
                let mut map = self.delta_recipients.write();
                map.clear();
                let mut token_index = self.delta_token_index.write();
                token_index.clear();
                for (key, bytes) in entries {
                    match DeltaRecipientEntry::decode(bytes.as_slice()) {
                        Ok(entry) => {
                            token_index.insert(entry.token_hash.clone(), key.clone());
                            map.insert(key, entry);
                        }
                        Err(e) => error!("Failed to decode delta recipient '{}': {}", key, e),
                    }
                }
                info!("Loaded {} delta recipients from store", map.len());
            }
            Err(e) => error!("Failed to load delta recipients: {}", e),
        }

        // Cluster config
        {
            let entries = store.load_all_config();
            let mut map = self.config.write();
            map.clear();
            let mut max_version = 0u64;
            for (key, bytes) in entries {
                match ConfigEntry::decode(bytes.as_slice()) {
                    Ok(entry) => {
                        max_version = max_version.max(entry.version);
                        map.insert(key, entry);
                    }
                    Err(e) => error!("Failed to decode config entry: {}", e),
                }
            }
            self.config_version
                .store(max_version, std::sync::atomic::Ordering::SeqCst);
            info!("Loaded {} config entries from store", map.len());
        }

        // Server pools
        {
            let entries = store.load_all_pools();
            let mut map = self.pools.write();
            map.clear();
            for (key, bytes) in entries {
                match PoolConfig::decode(bytes.as_slice()) {
                    Ok(pool) => {
                        map.insert(key, pool);
                    }
                    Err(e) => error!("Failed to decode pool: {}", e),
                }
            }
            info!("Loaded {} server pools from store", map.len());
        }

        // Tenants
        {
            let entries = store.load_all_tenants();
            let mut map = self.tenants.write();
            map.clear();
            for (key, bytes) in entries {
                match TenantConfig::decode(bytes.as_slice()) {
                    Ok(tenant) => {
                        map.insert(key, tenant);
                    }
                    Err(e) => error!("Failed to decode tenant: {}", e),
                }
            }
            info!("Loaded {} tenants from store", map.len());
        }

        // Iceberg warehouses
        {
            let entries = store.load_all_warehouses();
            let mut map = self.iceberg_warehouses.write();
            map.clear();
            for (key, bytes) in entries {
                match IcebergWarehouse::decode(bytes.as_slice()) {
                    Ok(wh) => {
                        map.insert(key, wh);
                    }
                    Err(e) => error!("Failed to decode warehouse: {}", e),
                }
            }
            info!("Loaded {} iceberg warehouses from store", map.len());
        }

        // Unity catalogs
        {
            let entries = store.load_all_unity_catalogs();
            let mut map = self.unity_catalogs.write();
            map.clear();
            for (key, bytes) in entries {
                match UnityCatalog::decode(bytes.as_slice()) {
                    Ok(c) => {
                        map.insert(key, c);
                    }
                    Err(e) => error!("Failed to decode unity catalog: {}", e),
                }
            }
            info!("Loaded {} unity catalogs from store", map.len());
        }
        {
            let entries = store.load_all_unity_schemas();
            let mut map = self.unity_schemas.write();
            map.clear();
            for (key, bytes) in entries {
                match UnitySchema::decode(bytes.as_slice()) {
                    Ok(s) => {
                        map.insert(key, s);
                    }
                    Err(e) => error!("Failed to decode unity schema: {}", e),
                }
            }
            info!("Loaded {} unity schemas from store", map.len());
        }
        {
            let entries = store.load_all_unity_tables();
            let mut map = self.unity_tables.write();
            map.clear();
            for (key, bytes) in entries {
                match UnityTable::decode(bytes.as_slice()) {
                    Ok(t) => {
                        map.insert(key, t);
                    }
                    Err(e) => error!("Failed to decode unity table: {}", e),
                }
            }
            info!("Loaded {} unity tables from store", map.len());
        }
        {
            let entries = store.load_all_unity_functions();
            let mut map = self.unity_functions.write();
            map.clear();
            for (key, bytes) in entries {
                match UnityFunction::decode(bytes.as_slice()) {
                    Ok(f) => {
                        map.insert(key, f);
                    }
                    Err(e) => error!("Failed to decode unity function: {}", e),
                }
            }
            info!("Loaded {} unity functions from store", map.len());
        }
        {
            let entries = store.load_all_unity_volumes();
            let mut map = self.unity_volumes.write();
            map.clear();
            for (key, bytes) in entries {
                match UnityVolume::decode(bytes.as_slice()) {
                    Ok(v) => {
                        map.insert(key, v);
                    }
                    Err(e) => error!("Failed to decode unity volume: {}", e),
                }
            }
            info!("Loaded {} unity volumes from store", map.len());
        }
        {
            let entries = store.load_all_unity_models();
            let mut map = self.unity_models.write();
            map.clear();
            for (key, bytes) in entries {
                match UnityModel::decode(bytes.as_slice()) {
                    Ok(m) => {
                        map.insert(key, m);
                    }
                    Err(e) => error!("Failed to decode unity model: {}", e),
                }
            }
            info!("Loaded {} unity models from store", map.len());
        }
        {
            let entries = store.load_all_unity_model_versions();
            let mut map = self.unity_model_versions.write();
            map.clear();
            for (key, bytes) in entries {
                match UnityModelVersion::decode(bytes.as_slice()) {
                    Ok(v) => {
                        map.insert(key, v);
                    }
                    Err(e) => error!("Failed to decode unity model version: {}", e),
                }
            }
            info!("Loaded {} unity model versions from store", map.len());
        }

        // Placement groups. Re-hydrate every PG across every pool so
        // the first GetPlacement doesn't do a redb read. The store API
        // is per-pool, so scan pools first; pools load above.
        {
            let pool_names: Vec<String> = self.pools.read().keys().cloned().collect();
            let mut map = self.placement_groups.write();
            map.clear();
            let mut loaded = 0usize;
            for pool in &pool_names {
                let mut next_pg: u32 = 0;
                loop {
                    let rows = match store.list_placement_groups(pool, next_pg, 1000) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("list placement_groups({pool}) failed: {e}");
                            break;
                        }
                    };
                    if rows.is_empty() {
                        break;
                    }
                    let mut highest = next_pg;
                    for bytes in rows {
                        match PlacementGroup::decode(bytes.as_slice()) {
                            Ok(pg) => {
                                highest = highest.max(pg.pg_id);
                                map.insert((pg.pool.clone(), pg.pg_id), pg);
                                loaded += 1;
                            }
                            Err(e) => error!("decode PlacementGroup: {e}"),
                        }
                    }
                    // list_placement_groups already advances past
                    // start_after_pg_id; step one past the highest we
                    // saw to paginate forward.
                    next_pg = highest.saturating_add(1);
                }
            }
            info!("Loaded {} placement groups from store", loaded);
        }

        // Shared stripes
        {
            let mut map = self.stripe_refs.write();
            map.clear();
            for (key, bytes) in store.load_all_stripe_refs() {
                match objectio_proto::metadata::StripeRefs::decode(bytes.as_slice()) {
                    Ok(refs) => {
                        map.insert(key, refs);
                    }
                    Err(e) => error!("Failed to decode stripe refs '{key}': {e}"),
                }
            }
            info!("Loaded {} shared stripes from store", map.len());
        }
        {
            self.load_block_tables(store);
        }

        // Object lock configs
        {
            let entries = store.load_all_object_lock_configs();
            let mut map = self.object_lock_configs.write();
            map.clear();
            for (key, bytes) in entries {
                match ObjectLockConfiguration::decode(bytes.as_slice()) {
                    Ok(config) => {
                        map.insert(key, config);
                    }
                    Err(e) => error!("Failed to decode object lock config: {}", e),
                }
            }
            info!("Loaded {} object lock configs from store", map.len());
        }

        // Lifecycle configs
        {
            let entries = store.load_all_lifecycle_configs();
            let mut map = self.lifecycle_configs.write();
            map.clear();
            for (key, bytes) in entries {
                match LifecycleConfiguration::decode(bytes.as_slice()) {
                    Ok(config) => {
                        map.insert(key, config);
                    }
                    Err(e) => error!("Failed to decode lifecycle config: {}", e),
                }
            }
            info!("Loaded {} lifecycle configs from store", map.len());
        }

        // Bucket default SSE configs
        {
            let entries = store.load_all_bucket_encryption_configs();
            let mut map = self.bucket_encryption_configs.write();
            map.clear();
            for (key, bytes) in entries {
                match BucketSseConfiguration::decode(bytes.as_slice()) {
                    Ok(config) => {
                        map.insert(key, config);
                    }
                    Err(e) => error!("Failed to decode bucket encryption config: {}", e),
                }
            }
            info!("Loaded {} bucket encryption configs from store", map.len());
        }

        // KMS keys
        {
            let entries = store.load_all_kms_keys();
            let mut map = self.kms_keys.write();
            map.clear();
            for (key_id, bytes) in entries {
                match KmsKey::decode(bytes.as_slice()) {
                    Ok(k) => {
                        map.insert(key_id, k);
                    }
                    Err(e) => error!("Failed to decode KMS key: {}", e),
                }
            }
            info!("Loaded {} KMS keys from store", map.len());
        }

        // IAM policies
        {
            let entries = store.load_all_iam_policies();
            let mut map = self.iam_policies.write();
            map.clear();
            for (name, bytes) in entries {
                match PolicyObject::decode(bytes.as_slice()) {
                    Ok(policy) => {
                        map.insert(name, policy);
                    }
                    Err(e) => error!("Failed to decode IAM policy: {}", e),
                }
            }
            info!("Loaded {} IAM policies from store", map.len());

            // Insert built-in policies if they don't already exist
            let builtins = [
                (
                    "readonly",
                    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:GetBucketLocation"],"Resource":["arn:obio:s3:::*/*"]}]}"#,
                ),
                (
                    "readwrite",
                    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:obio:s3:::*","arn:obio:s3:::*/*"]}]}"#,
                ),
                (
                    "writeonly",
                    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:obio:s3:::*/*"]}]}"#,
                ),
                (
                    "consoleAdmin",
                    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","admin:*"],"Resource":["*"]}]}"#,
                ),
            ];
            let now = Self::current_timestamp();
            for (name, json) in builtins {
                // Tenant admins may attach these to their own users; the
                // tenant boundary keeps them to the tenant's buckets.
                // consoleAdmin (admin:*) is the operator's alone.
                let shared = name != "consoleAdmin";
                if let Some(existing) = map.get_mut(name) {
                    // Stored before policies had a scope.
                    existing.shared = existing.tenant.is_empty() && shared;
                } else {
                    let policy = PolicyObject {
                        name: name.to_string(),
                        policy_json: json.to_string(),
                        created_at: now,
                        updated_at: now,
                        tenant: String::new(),
                        shared,
                        ..Default::default()
                    };
                    store.put_iam_policy(name, &policy.encode_to_vec());
                    map.insert(name.to_string(), policy);
                }
            }
        }

        // Policy attachments
        {
            let entries = store.load_all_policy_attachments();
            let mut map = self.policy_attachments.write();
            map.clear();
            for (key, csv) in entries {
                let policies: Vec<String> = csv
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect();
                map.insert(key, policies);
            }
            info!("Loaded {} policy attachments from store", map.len());
        }

        // A binary too old (or too new) for the cluster's active format
        // level stops here rather than serve.
        self.note_active_level();
    }

    /// Generate object key for internal storage
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// One page of a bucket listing, as the client sees it.
struct ListingPage {
    entries: Vec<ObjectListingEntry>,
    common_prefixes: Vec<String>,
    is_truncated: bool,
    /// Where the next page starts (exclusive). Empty when not truncated.
    next_token: String,
}

/// Sorts after every key that starts with the string it is appended to.
const PAST_PREFIX: char = char::MAX;

/// Page a listing in terms of what the client sees: `max_keys` counts
/// keys *and* common prefixes, a common prefix appears once however many
/// keys roll up into it, and a page never starts inside a prefix the
/// previous page already returned.
///
/// `fetch(after, n)` returns up to `n` entries with keys strictly after
/// `after` (and under the request prefix), and whether more exist.
fn page_listing<F, E>(
    mut fetch: F,
    prefix: &str,
    delimiter: &str,
    start_after: &str,
    max_keys: usize,
) -> Result<ListingPage, E>
where
    F: FnMut(&str, usize) -> Result<(Vec<ObjectListingEntry>, bool), E>,
{
    let rolls_up = |key: &str| -> Option<String> {
        if delimiter.is_empty() {
            return None;
        }
        let tail = key.strip_prefix(prefix)?;
        let idx = tail.find(delimiter)?;
        Some(key[..prefix.len() + idx + delimiter.len()].to_string())
    };

    // Resuming from a common prefix (a V1 NextMarker, or our own token):
    // skip everything under it, or the prefix comes back on every page.
    let mut cursor = match rolls_up(start_after) {
        Some(cp) if cp == start_after => format!("{cp}{PAST_PREFIX}"),
        _ => start_after.to_string(),
    };
    let mut page = ListingPage {
        entries: Vec::new(),
        common_prefixes: Vec::new(),
        is_truncated: false,
        next_token: String::new(),
    };
    let emitted = |p: &ListingPage| p.entries.len() + p.common_prefixes.len();

    'scan: loop {
        let (batch, more) = fetch(&cursor, max_keys + 1)?;
        let exhausted = batch.is_empty();
        for e in batch {
            let cp = rolls_up(&e.key);
            if emitted(&page) >= max_keys {
                page.is_truncated = true;
                break 'scan;
            }
            if let Some(cp) = cp {
                // Jump past the whole prefix: its other keys add nothing.
                cursor = format!("{cp}{PAST_PREFIX}");
                page.next_token.clone_from(&cp);
                page.common_prefixes.push(cp);
                continue 'scan;
            }
            cursor.clone_from(&e.key);
            page.next_token.clone_from(&e.key);
            page.entries.push(e);
        }
        if exhausted || !more {
            break;
        }
    }
    if !page.is_truncated {
        page.next_token.clear();
    }
    Ok(page)
}

/// The tenant in an IAM ARN's account segment ("objectio" = system scope).
fn group_tenant(arn: &str) -> String {
    arn.split(':')
        .nth(4)
        .filter(|a| *a != "objectio")
        .unwrap_or_default()
        .to_string()
}

/// Where a policy or role is stored: "<name>" in system scope,
/// "<tenant>/<name>" in a tenant's.
fn iam_key(tenant: &str, name: &str) -> String {
    if tenant.is_empty() {
        name.to_string()
    } else {
        format!("{tenant}/{name}")
    }
}

/// Roles, prost-encoded `RoleObject` by name. Written through
/// `CasTable::Named(ROLES_TABLE)`.
const ROLES_TABLE: &str = "iam_roles";

/// Inline policies, prost-encoded `InlinePolicy`, keyed by
/// [`inline_policy_key`]. Written through `CasTable::Named`.
const INLINE_POLICIES_TABLE: &str = "iam_inline_policies";

/// Format level that adds IAM paths, role and policy ids, group renames
/// and inline policies (the IAM API).
const LEVEL_IAM_API: u32 = 3;

/// Where an inline policy is stored: its principal ("user:<id>",
/// "group:<id>", "role:<key>"), NUL, its name.
fn inline_policy_key(principal: &str, name: &str) -> String {
    format!("{principal}\u{0}{name}")
}

/// The account segment of an IAM ARN: the tenant, or `objectio` for the
/// system scope.
fn iam_account(tenant: &str) -> &str {
    if tenant.is_empty() {
        "objectio"
    } else {
        tenant
    }
}

/// An IAM path as given (empty is `/`), checked: `/` or `/a/b/`, printable
/// ASCII, at most 512 characters.
#[allow(clippy::result_large_err)] // the Status the RPC returns, as is
fn iam_path(path: &str) -> Result<String, Status> {
    if path.is_empty() || path == "/" {
        return Ok("/".to_string());
    }
    let ok = path.len() <= 512
        && path.starts_with('/')
        && path.ends_with('/')
        && !path.contains("//")
        && path.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if ok {
        Ok(path.to_string())
    } else {
        Err(Status::invalid_argument(
            "path must be / or /a/b/: printable ASCII, at most 512 characters",
        ))
    }
}

/// A path as stored: empty for `/`, so a record in the root path is the
/// same bytes it was before paths existed.
fn stored_path(path: &str) -> String {
    if path == "/" {
        String::new()
    } else {
        path.to_string()
    }
}

/// A stored path as shown: `/` for empty.
fn shown_path(stored: &str) -> &str {
    if stored.is_empty() { "/" } else { stored }
}

/// A user's ARN. System users keep their account-less form
/// (`arn:objectio:iam::user/admin`).
fn user_arn(tenant: &str, path: &str, name: &str) -> String {
    let path = shown_path(path);
    if tenant.is_empty() {
        format!("arn:objectio:iam::user{path}{name}")
    } else {
        format!("arn:objectio:iam::{tenant}:user{path}{name}")
    }
}

fn group_arn(tenant: &str, path: &str, name: &str) -> String {
    format!(
        "arn:obio:iam::{}:group{}{name}",
        iam_account(tenant),
        shown_path(path)
    )
}

fn role_arn(tenant: &str, path: &str, name: &str) -> String {
    format!(
        "arn:obio:iam::{}:role{}{name}",
        iam_account(tenant),
        shown_path(path)
    )
}

/// An IAM name (policy, inline policy): letters, digits and `+=,.@_-`,
/// 1 to `max` characters.
fn iam_name_ok(name: &str, max: usize) -> bool {
    !name.is_empty()
        && name.len() <= max
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c))
}

/// A fresh IAM id: AWS's four-letter kind prefix and 17 random uppercase
/// letters and digits (`AIDA…` user, `AGPA…` group, `AROA…` role, `ANPA…`
/// policy).
fn iam_id(prefix: &str) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut rng = rand::thread_rng();
    let tail: String = (0..17)
        .map(|_| char::from(CHARS[rng.gen_range(0..CHARS.len())]))
        .collect();
    format!("{prefix}{tail}")
}

/// Keys whose ObjectMeta copies may disagree, for gateways to heal
/// (objectio-docs core/object-metadata-quorum.md): `CasTable::Named`,
/// keyed by [`heal_key`], each a `HealEntry`.
const HEAL_TABLE: &str = "heal_queue";

fn heal_key(bucket: &str, key: &str, version_id: &str) -> String {
    format!("{bucket}\u{0}{key}\u{0}{version_id}")
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Small-object packs, by pack id (hex): prost `PackRecord`.
/// Tables written through Raft by name ([`MetaService::replicate`]); the
/// same tables the store loads them from.
const OSD_NODES_TABLE: &str = "osd_nodes";
const KMS_KEYS_TABLE: &str = "kms_keys";
const MULTIPART_TABLE: &str = "multipart_uploads";
const PACKS_TABLE: &str = "packs";

/// Drained OSDs' purge state, by node id (hex): "pending" until the OSD
/// confirms it was wiped, then "done".
const OSD_PURGE_TABLE: &str = "osd_purge";

/// Named leases (`AcquireLease`), JSON `{holder, expires_at}`.
const LEASES_TABLE: &str = "leases";

/// Per-bucket settings, keyed `<bucket>/<name>`.
const BUCKET_SETTINGS_TABLE: &str = "bucket_settings";

fn bucket_setting_key(bucket: &str, name: &str) -> String {
    format!("{bucket}/{name}")
}

impl MetaService {
    /// Commit one compare-and-set write through Raft (or straight to the
    /// store without Raft). `expected` is the row as read; a change since
    /// is ABORTED, for the caller to retry.
    async fn cas_one(
        &self,
        table: objectio_meta_store::CasTable,
        key: &str,
        expected: Option<Vec<u8>>,
        new_value: Option<Vec<u8>>,
        what: &str,
    ) -> Result<(), Status> {
        use objectio_meta_store::{CasOp, MetaCommand, MetaResponse};
        if let Some(raft) = self.raft_handle() {
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table,
                    key: key.to_string(),
                    expected,
                    new_value,
                }],
                requested_by: what.into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => Ok(()),
                    MetaResponse::MultiCasConflict { .. } => {
                        Err(Status::aborted(format!("{what}: changed meanwhile; retry")))
                    }
                    other => {
                        error!("unexpected raft response for {what}: {other:?}");
                        Err(Status::internal("raft commit wrong variant"))
                    }
                },
                Err(e) => Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.write_named(
                objectio_meta_store::cas_table_name(&table),
                key,
                new_value.as_deref(),
            );
            Ok(())
        } else {
            Err(Status::unavailable("no store"))
        }
    }
}

/// Check a completion against `upload` and build the object it makes:
/// every part named exists with its ETag, all but the last at least 5 MiB.
/// Returns the object and the stripes of parts left out of it.
#[allow(clippy::result_large_err)]
fn complete_upload(
    upload: &MultipartUploadState,
    req: &CompleteMultipartUploadRequest,
) -> Result<(ObjectMeta, Vec<objectio_proto::metadata::StripeMeta>), Status> {
    // Verify bucket/key match
    if upload.bucket != req.bucket || upload.key != req.key {
        return Err(Status::invalid_argument(
            "bucket/key mismatch for upload_id",
        ));
    }

    // Parts are named in strictly ascending order, as S3 requires: a part
    // named twice or out of order is refused before anything else.
    if req
        .parts
        .windows(2)
        .any(|w| w[1].part_number <= w[0].part_number)
    {
        return Err(Status::invalid_argument(
            "InvalidPartOrder: the list of parts was not in ascending order; \
             parts must be ordered by part number",
        ));
    }

    // Validate that all requested parts exist and ETags match
    let mut stripes = Vec::new();
    let mut total_size = 0u64;

    for (i, part_info) in req.parts.iter().enumerate() {
        let stored_part = upload.parts.get(&part_info.part_number).ok_or_else(|| {
            Status::invalid_argument(format!("part {} not found", part_info.part_number))
        })?;
        // Every part but the last is at least 5 MiB, as S3 requires.
        if i + 1 < req.parts.len() && stored_part.size < 5 * 1024 * 1024 {
            return Err(Status::invalid_argument(format!(
                "EntityTooSmall: part {} is {} bytes; all parts but the last must be at least 5 MiB",
                part_info.part_number, stored_part.size
            )));
        }

        // Verify ETag matches (normalize by removing quotes)
        let req_etag = part_info.etag.trim_matches('"');
        let stored_etag = stored_part.etag.trim_matches('"');
        if req_etag != stored_etag {
            return Err(Status::invalid_argument(format!(
                "ETag mismatch for part {}: expected {}, got {}",
                part_info.part_number, stored_etag, req_etag
            )));
        }

        total_size += stored_part.size;

        // Add all stripes for this part (large parts may have multiple stripes)
        stripes.extend(stored_part.stripes.clone());
    }

    // Calculate multipart ETag: MD5 of concatenated part MD5s + "-" + part count
    let final_etag = {
        let mut concatenated_hashes = Vec::new();
        for part_info in &req.parts {
            if let Some(stored_part) = upload.parts.get(&part_info.part_number) {
                // Decode hex ETag and add to concatenated bytes
                let etag_clean = stored_part.etag.trim_matches('"');
                if let Ok(bytes) = hex::decode(etag_clean) {
                    concatenated_hashes.extend(bytes);
                }
            }
        }
        let hash = md5::compute(&concatenated_hashes);
        format!("\"{:x}-{}\"", hash, req.parts.len())
    };

    let object_id = *Uuid::now_v7().as_bytes();
    let now = MetaService::current_timestamp();

    let object = ObjectMeta {
        bucket: req.bucket.clone(),
        key: req.key.clone(),
        object_id: object_id.to_vec(),
        size: total_size,
        etag: final_etag,
        content_type: upload.content_type.clone(),
        created_at: upload.initiated,
        modified_at: now,
        storage_class: "STANDARD".to_string(),
        user_metadata: upload.user_metadata.clone(),
        version_id: String::new(),
        is_delete_marker: false,
        stripes,
        retention: None,
        legal_hold: None,
        // Multipart SSE: each stripe carries its own IV; the object-level
        // fields just record the algorithm + wrapped DEK so GET knows
        // how to unwrap and which algorithm to advertise on responses.
        encryption_algorithm: upload.encryption_algorithm,
        kms_key_id: upload.kms_key_id.clone(),
        encrypted_dek: upload.encrypted_dek.clone(),
        encryption_iv: Vec::new(),
        // SSE-KMS: the context the DEK was wrapped under, needed to
        // unwrap it. SSE-C: what identifies the customer's key. Both
        // used to be dropped here, so a multipart object's DEK
        // couldn't be unwrapped under a context, and any key read it.
        encryption_context: upload.encryption_context.clone(),
        ..Default::default()
    };

    // Parts uploaded but not named in the completion belong to nothing
    // once the upload is gone.
    let used: std::collections::HashSet<u32> = req.parts.iter().map(|p| p.part_number).collect();
    let unused_stripes: Vec<_> = upload
        .parts
        .values()
        .filter(|p| !used.contains(&p.part_number))
        .flat_map(|p| p.stripes.iter().cloned())
        .collect();

    Ok((object, unused_stripes))
}

#[cfg(test)]
mod topology_status_tests {
    use super::{NodeEvidence, topology_status};
    use objectio_common::{NodeStatus, OsdAdminState};

    /// A node that just registered is there — it opened a connection to say so.
    #[test]
    fn a_node_that_just_registered_is_active() {
        assert_eq!(
            topology_status(OsdAdminState::In, NodeEvidence::Observed, None),
            NodeStatus::Active
        );
        // Even one previously written off: it is answering now.
        assert_eq!(
            topology_status(
                OsdAdminState::In,
                NodeEvidence::Observed,
                Some(NodeStatus::Down)
            ),
            NodeStatus::Active
        );
    }

    /// A record read from the store is not evidence of anything.
    ///
    /// This is the bug that made every restart serve 500s: a node the prober
    /// had marked Down came back Active because status was derived from
    /// `admin_state` alone, and placement handed out an address that had been
    /// dead for days.
    #[test]
    fn a_node_only_read_from_the_store_must_earn_its_place() {
        assert_eq!(
            topology_status(OsdAdminState::In, NodeEvidence::FromStore, None),
            NodeStatus::Down
        );
    }

    #[test]
    fn a_rebuild_does_not_resurrect_a_node_the_prober_wrote_off() {
        // Changing any node's admin state rebuilds every node's topology
        // entry. That pass used to reset liveness for all of them.
        assert_eq!(
            topology_status(
                OsdAdminState::In,
                NodeEvidence::FromStore,
                Some(NodeStatus::Down)
            ),
            NodeStatus::Down
        );
    }

    #[test]
    fn a_rebuild_does_not_evict_a_node_the_prober_confirmed() {
        // The counterpart: a healthy cluster must not lose every node to an
        // unrelated admin-state change.
        assert_eq!(
            topology_status(
                OsdAdminState::In,
                NodeEvidence::FromStore,
                Some(NodeStatus::Active)
            ),
            NodeStatus::Active
        );
    }

    /// Operator intent wins over anything observed, in both directions.
    #[test]
    fn draining_and_out_are_decisions_not_observations() {
        for evidence in [NodeEvidence::Observed, NodeEvidence::FromStore] {
            assert_eq!(
                topology_status(OsdAdminState::Draining, evidence, Some(NodeStatus::Active)),
                NodeStatus::Draining
            );
            assert_eq!(
                topology_status(OsdAdminState::Out, evidence, Some(NodeStatus::Active)),
                NodeStatus::Decommissioning
            );
        }
    }

    /// Bringing a node back In does not make it Active on the strength of a
    /// stale Decommissioning entry — the prober has to see it.
    #[test]
    fn a_node_marked_back_in_is_still_probed_first() {
        assert_eq!(
            topology_status(
                OsdAdminState::In,
                NodeEvidence::FromStore,
                Some(NodeStatus::Decommissioning)
            ),
            NodeStatus::Down
        );
    }
}

#[cfg(test)]
mod listing_page_tests {
    use super::{ObjectListingEntry, page_listing};

    /// An in-memory index: sorted keys, `fetch` returns keys strictly after
    /// `after`, as the store does.
    fn run(
        keys: &[&str],
        delimiter: &str,
        start_after: &str,
        max: usize,
    ) -> (Vec<String>, bool, String) {
        let mut keys: Vec<String> = keys.iter().map(ToString::to_string).collect();
        keys.sort();
        let page = page_listing(
            |after, n| {
                let rest: Vec<_> = keys.iter().filter(|k| k.as_str() > after).collect();
                let more = rest.len() > n;
                Ok::<_, std::convert::Infallible>((
                    rest.into_iter()
                        .take(n)
                        .map(|k| ObjectListingEntry {
                            key: k.clone(),
                            ..Default::default()
                        })
                        .collect(),
                    more,
                ))
            },
            "",
            delimiter,
            start_after,
            max,
        )
        .unwrap();
        let mut out: Vec<String> = page.entries.into_iter().map(|e| e.key).collect();
        out.extend(page.common_prefixes);
        out.sort();
        (out, page.is_truncated, page.next_token)
    }

    /// Page through to the end the way a V2 client does.
    fn all_pages(keys: &[&str], delimiter: &str, max: usize) -> Vec<Vec<String>> {
        let mut pages = Vec::new();
        let mut token = String::new();
        loop {
            let (items, truncated, next) = run(keys, delimiter, &token, max);
            pages.push(items);
            if !truncated {
                return pages;
            }
            token = next;
        }
    }

    const KEYS: &[&str] = &["a", "b", "c", "dir/x", "dir/y", "e"];

    #[test]
    fn start_is_exclusive() {
        let (items, _, _) = run(KEYS, "", "c", 100);
        assert_eq!(items, ["dir/x", "dir/y", "e"]);
    }

    #[test]
    fn pages_cover_every_key_once_and_the_last_is_not_truncated() {
        let pages = all_pages(KEYS, "", 2);
        assert_eq!(pages.concat(), ["a", "b", "c", "dir/x", "dir/y", "e"]);
        assert_eq!(pages.len(), 3);
        let (_, truncated, token) = run(KEYS, "", "", 100);
        assert!(!truncated && token.is_empty());
    }

    /// max-keys counts common prefixes, and a prefix is returned once even
    /// when its keys straddle a page boundary.
    #[test]
    fn a_common_prefix_appears_once_across_pages() {
        let pages = all_pages(KEYS, "/", 2);
        assert_eq!(pages.concat(), ["a", "b", "c", "dir/", "e"]);
        assert!(pages.iter().all(|p| p.len() <= 2), "{pages:?}");
    }

    /// A V1 client resumes from NextMarker, which may be a common prefix.
    #[test]
    fn resuming_from_a_prefix_skips_its_keys() {
        let (items, _, _) = run(KEYS, "/", "dir/", 100);
        assert_eq!(items, ["e"]);
    }
}

#[cfg(test)]
mod te_segment_tests {
    //! An OSD's Transfer Engine segment travels from its registration to the
    //! gateways that will move shards to it.

    use super::MetaService;
    use objectio_proto::metadata::metadata_service_server::MetadataService;
    use objectio_proto::metadata::{GetListingNodesRequest, RegisterOsdRequest};
    use tonic::Request;

    fn registration(id: u8, te_segment: &str) -> RegisterOsdRequest {
        RegisterOsdRequest {
            node_id: vec![id; 16],
            address: format!("http://10.0.0.{id}:9200"),
            disk_ids: vec![vec![id; 16]],
            disk_capacity_bytes: vec![1 << 30],
            te_segment: te_segment.to_string(),
            ..Default::default()
        }
    }

    /// The gRPC handler — `MetaService` also has an inherent `register_osd`
    /// that takes an `OsdNode`, which would shadow it.
    async fn register(svc: &MetaService, req: RegisterOsdRequest) {
        MetadataService::register_osd(svc, Request::new(req))
            .await
            .unwrap();
    }

    async fn listed_segments(svc: &MetaService) -> Vec<(u8, String)> {
        let mut out: Vec<(u8, String)> = svc
            .get_listing_nodes(Request::new(GetListingNodesRequest {
                bucket: String::new(),
                include_all_states: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .nodes
            .into_iter()
            .map(|n| (n.node_id[0], n.te_segment))
            .collect();
        out.sort();
        out
    }

    #[tokio::test]
    async fn listing_carries_each_osds_segment_and_follows_re_registration() {
        let svc = MetaService::new();
        register(&svc, registration(1, "10.0.0.1:15001")).await;
        register(&svc, registration(2, "")).await;
        assert_eq!(
            listed_segments(&svc).await,
            [(1, "10.0.0.1:15001".to_string()), (2, String::new())]
        );

        // Restarting with RDMA turned on — or off — must be picked up, not
        // leave gateways sending transfers to a segment that is gone.
        register(&svc, registration(1, "")).await;
        register(&svc, registration(2, "10.0.0.2:15002")).await;
        assert_eq!(
            listed_segments(&svc).await,
            [(1, String::new()), (2, "10.0.0.2:15002".to_string())]
        );
    }
}

#[cfg(test)]
mod stripe_refs_tests {
    //! The shared-stripe registry: a stripe's shards may be freed only
    //! when the last object referencing it lets go.

    use super::MetaService;
    use objectio_proto::metadata::{ReleaseStripesRequest, ShareStripesRequest};
    use tonic::Request;

    const X: [u8; 16] = [7; 16];
    const SOURCE: [u8; 16] = [1; 16];
    const COPY: [u8; 16] = [2; 16];
    const COPY2: [u8; 16] = [3; 16];

    async fn share(
        svc: &MetaService,
        owner: [u8; 16],
        sharer: [u8; 16],
    ) -> Result<(), tonic::Status> {
        svc.share_stripes(Request::new(ShareStripesRequest {
            stripe_ids: vec![X.to_vec()],
            owner: owner.to_vec(),
            sharer: sharer.to_vec(),
        }))
        .await
        .map(drop)
    }

    async fn release(svc: &MetaService, referrer: [u8; 16]) -> bool {
        let freeable = svc
            .release_stripes(Request::new(ReleaseStripesRequest {
                stripe_ids: vec![X.to_vec()],
                referrer: referrer.to_vec(),
            }))
            .await
            .unwrap()
            .into_inner()
            .freeable;
        freeable == vec![X.to_vec()]
    }

    #[tokio::test]
    async fn an_unshared_stripe_is_freed_by_its_only_referrer() {
        let svc = MetaService::new();
        assert!(release(&svc, SOURCE).await);
    }

    /// Either side of a copy may go first; the shards go with the last.
    #[tokio::test]
    async fn a_shared_stripe_is_freed_only_by_its_last_referrer() {
        let svc = MetaService::new();
        share(&svc, SOURCE, COPY).await.unwrap();
        assert!(!release(&svc, SOURCE).await, "freed while the copy used it");
        assert!(release(&svc, COPY).await);

        let svc = MetaService::new();
        share(&svc, SOURCE, COPY).await.unwrap();
        assert!(!release(&svc, COPY).await, "freed while the source used it");
        assert!(release(&svc, SOURCE).await);
    }

    #[tokio::test]
    async fn a_copy_of_a_copy_shares_too() {
        let svc = MetaService::new();
        share(&svc, SOURCE, COPY).await.unwrap();
        share(&svc, COPY, COPY2).await.unwrap();
        assert!(!release(&svc, SOURCE).await);
        assert!(!release(&svc, COPY).await);
        assert!(release(&svc, COPY2).await);
    }

    /// Releasing twice must not free a stripe someone else still uses.
    #[tokio::test]
    async fn a_repeated_release_is_harmless() {
        let svc = MetaService::new();
        share(&svc, SOURCE, COPY).await.unwrap();
        assert!(!release(&svc, SOURCE).await);
        assert!(
            !release(&svc, SOURCE).await,
            "a retried release freed the copy's data"
        );
    }

    /// A source that has already let go of a shared stripe cannot share it
    /// again: its shards may be gone with it.
    #[tokio::test]
    async fn sharing_from_a_source_that_let_go_is_refused() {
        let svc = MetaService::new();
        share(&svc, SOURCE, COPY).await.unwrap();
        release(&svc, SOURCE).await;
        let err = share(&svc, SOURCE, COPY2).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }
}

#[cfg(test)]
mod multipart_reclaim_tests {
    //! The stripes meta hands back when a part, or a whole upload, stops
    //! being referenced — the gateway frees exactly these.

    use super::MetaService;
    use objectio_proto::metadata::{
        AbortMultipartUploadRequest, CompleteMultipartUploadRequest, CreateBucketRequest,
        CreateMultipartUploadRequest, PartInfo, RegisterPartRequest, SettleMultipartUploadRequest,
        StripeMeta,
    };
    use tonic::Request;

    fn stripe(id: u8) -> StripeMeta {
        StripeMeta {
            object_id: vec![id; 16],
            ..Default::default()
        }
    }

    async fn upload(svc: &MetaService) -> String {
        svc.create_bucket(Request::new(CreateBucketRequest {
            name: "b".into(),
            ..Default::default()
        }))
        .await
        .unwrap();
        svc.create_multipart_upload(Request::new(CreateMultipartUploadRequest {
            bucket: "b".into(),
            key: "k".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .upload_id
    }

    async fn register(svc: &MetaService, upload_id: &str, part: u32, id: u8) -> Vec<StripeMeta> {
        svc.register_part(Request::new(RegisterPartRequest {
            bucket: "b".into(),
            key: "k".into(),
            upload_id: upload_id.into(),
            part_number: part,
            etag: format!("\"{id:032x}\""),
            // At S3's minimum, so any part may come before another.
            size: 5 * 1024 * 1024,
            stripes: vec![stripe(id)],
            checksum: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .replaced_stripes
    }

    fn ids(stripes: &[StripeMeta]) -> Vec<u8> {
        let mut v: Vec<u8> = stripes.iter().map(|s| s.object_id[0]).collect();
        v.sort_unstable();
        v
    }

    #[tokio::test]
    async fn re_registering_a_part_returns_the_one_it_replaced() {
        let svc = MetaService::new();
        let id = upload(&svc).await;
        assert!(register(&svc, &id, 1, 1).await.is_empty());
        assert_eq!(ids(&register(&svc, &id, 1, 2).await), [1]);
        assert!(register(&svc, &id, 2, 3).await.is_empty());
    }

    #[tokio::test]
    async fn completion_returns_the_parts_it_left_out() {
        let svc = MetaService::new();
        let id = upload(&svc).await;
        for (part, sid) in [(1, 1), (2, 2), (3, 3)] {
            register(&svc, &id, part, sid).await;
        }
        let resp = svc
            .complete_multipart_upload(Request::new(CompleteMultipartUploadRequest {
                bucket: "b".into(),
                key: "k".into(),
                upload_id: id.clone(),
                parts: vec![PartInfo {
                    part_number: 2,
                    etag: format!("\"{:032x}\"", 2),
                    size: 0,
                }],
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ids(&resp.object.unwrap().stripes), [2]);
        assert_eq!(ids(&resp.unused_stripes), [1, 3]);

        // The upload is gone: an abort now finds nothing, and frees nothing.
        let abort = svc
            .abort_multipart_upload(Request::new(AbortMultipartUploadRequest {
                bucket: "b".into(),
                key: "k".into(),
                upload_id: id,
            }))
            .await;
        assert_eq!(
            abort
                .map(|r| r.into_inner().stripes.len())
                .map_err(|e| e.code()),
            Err(tonic::Code::NotFound),
            "abort of a completed upload"
        );
    }

    fn two_phase(id: &str, parts: &[u32]) -> CompleteMultipartUploadRequest {
        CompleteMultipartUploadRequest {
            bucket: "b".into(),
            key: "k".into(),
            upload_id: id.into(),
            parts: parts
                .iter()
                .map(|n| PartInfo {
                    part_number: *n,
                    etag: format!("\"{n:032x}\""),
                    size: 0,
                })
                .collect(),
            version_id: "v1".into(),
            settle_after_commit: true,
        }
    }

    async fn settle(svc: &MetaService, id: &str, object_id: Vec<u8>, committed: bool) -> bool {
        svc.settle_multipart_upload(Request::new(SettleMultipartUploadRequest {
            bucket: "b".into(),
            key: "k".into(),
            upload_id: id.into(),
            object_id,
            committed,
        }))
        .await
        .unwrap()
        .into_inner()
        .settled
    }

    async fn abort(svc: &MetaService, id: &str) -> Result<Vec<u8>, tonic::Code> {
        svc.abort_multipart_upload(Request::new(AbortMultipartUploadRequest {
            bucket: "b".into(),
            key: "k".into(),
            upload_id: id.into(),
        }))
        .await
        .map(|r| ids(&r.into_inner().stripes))
        .map_err(|e| e.code())
    }

    /// A two-phase completion keeps the upload until it is settled: sent
    /// again it makes the same object, nothing can abort it or change its
    /// parts meanwhile, and "not stored" gives the upload back as it was.
    #[tokio::test]
    async fn a_completion_not_stored_gives_the_upload_back() {
        let svc = MetaService::new();
        let id = upload(&svc).await;
        for part in [1, 2, 3] {
            register(&svc, &id, part, u8::try_from(part).unwrap()).await;
        }
        let first = svc
            .complete_multipart_upload(Request::new(two_phase(&id, &[1, 2])))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ids(&first.unused_stripes), [3]);
        let object = first.object.unwrap();
        assert_eq!(object.version_id, "v1");
        assert_eq!(ids(&object.stripes), [1, 2]);

        let again = svc
            .complete_multipart_upload(Request::new(two_phase(&id, &[1, 2])))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(again.object.unwrap().object_id, object.object_id);
        assert!(again.unused_stripes.is_empty());

        assert_eq!(abort(&svc, &id).await, Err(tonic::Code::FailedPrecondition));
        let reupload = svc
            .register_part(Request::new(RegisterPartRequest {
                bucket: "b".into(),
                key: "k".into(),
                upload_id: id.clone(),
                part_number: 1,
                etag: format!("\"{:032x}\"", 9),
                size: 5 * 1024 * 1024,
                stripes: vec![stripe(9)],
                checksum: None,
            }))
            .await;
        assert_eq!(
            reupload.map(drop).map_err(|e| e.code()),
            Err(tonic::Code::FailedPrecondition)
        );

        // Another completion's settle changes nothing.
        assert!(!settle(&svc, &id, vec![0; 16], false).await);
        assert!(settle(&svc, &id, object.object_id.clone(), false).await);
        // Open again: its parts (the ones the completion used) are there.
        assert_eq!(abort(&svc, &id).await, Ok(vec![1, 2]));
    }

    #[tokio::test]
    async fn a_completion_stored_takes_the_upload() {
        let svc = MetaService::new();
        let id = upload(&svc).await;
        register(&svc, &id, 1, 1).await;
        let object = svc
            .complete_multipart_upload(Request::new(two_phase(&id, &[1])))
            .await
            .unwrap()
            .into_inner()
            .object
            .unwrap();
        assert!(settle(&svc, &id, object.object_id, true).await);
        assert_eq!(abort(&svc, &id).await, Err(tonic::Code::NotFound));
    }

    #[tokio::test]
    async fn abort_returns_every_part_and_only_for_its_own_key() {
        let svc = MetaService::new();
        let id = upload(&svc).await;
        register(&svc, &id, 1, 1).await;
        register(&svc, &id, 2, 2).await;

        let err = svc
            .abort_multipart_upload(Request::new(AbortMultipartUploadRequest {
                bucket: "b".into(),
                key: "other".into(),
                upload_id: id.clone(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        let abort = svc
            .abort_multipart_upload(Request::new(AbortMultipartUploadRequest {
                bucket: "b".into(),
                key: "k".into(),
                upload_id: id,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ids(&abort.stripes), [1, 2]);
    }
}

#[cfg(test)]
mod pack_tests {
    //! A pack's record from intent to the last object letting go: nothing
    //! frees a pack anything is still in, and the last release takes the
    //! record with it.

    use super::*;
    use objectio_proto::metadata::{
        AbortPackRequest, IntendPackRequest, PackRecord, ReleaseStripesRequest, SealPackRequest,
        ShardLocation, ShareStripesRequest, StripeMeta,
    };

    fn service() -> (tempfile::TempDir, MetaService) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MetaStore::open(dir.path().join("meta.redb")).unwrap());
        (dir, MetaService::with_store(EcConfig::default(), store))
    }

    fn stripe(pack: &[u8], node: u8) -> StripeMeta {
        StripeMeta {
            ec_k: 4,
            ec_m: 2,
            object_id: pack.to_vec(),
            shards: (0..6)
                .map(|position| ShardLocation {
                    position,
                    node_id: vec![node + u8::try_from(position).unwrap(); 16],
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    async fn intend(svc: &MetaService, pack: &[u8]) {
        svc.intend_pack(Request::new(IntendPackRequest {
            pack: Some(PackRecord {
                pack_id: pack.to_vec(),
                stripe: Some(stripe(pack, 0)),
                ..Default::default()
            }),
        }))
        .await
        .unwrap();
    }

    async fn release(svc: &MetaService, pack: &[u8], who: u8) -> (Vec<Vec<u8>>, usize) {
        let r = svc
            .release_stripes(Request::new(ReleaseStripesRequest {
                stripe_ids: vec![pack.to_vec()],
                referrer: vec![who; 16],
            }))
            .await
            .unwrap()
            .into_inner();
        (r.freeable, r.freed_packs.len())
    }

    #[tokio::test]
    async fn a_pack_goes_with_its_last_object_and_not_before() {
        let (_dir, svc) = service();
        let pack = [7u8; 16];
        intend(&svc, &pack).await;
        assert!(svc.packs().iter().all(|p| !p.sealed));
        svc.seal_pack(Request::new(SealPackRequest {
            pack_id: pack.to_vec(),
            referrers: vec![vec![1; 16], vec![2; 16]],
            // Where the shards landed, not where they were meant to.
            stripe: Some(stripe(&pack, 100)),
        }))
        .await
        .unwrap();
        let sealed = svc.packs();
        assert_eq!(sealed.len(), 1);
        assert!(sealed[0].sealed);
        assert_eq!(
            sealed[0].stripe.as_ref().unwrap().shards[0].node_id,
            vec![100; 16]
        );

        // Not a referrer: nothing changes. The first object: nothing freed.
        assert_eq!(release(&svc, &pack, 9).await, (vec![], 0));
        assert_eq!(release(&svc, &pack, 1).await, (vec![], 0));
        assert_eq!(svc.packs().len(), 1);
        // The last: the pack's shards are handed back, and its record goes.
        assert_eq!(release(&svc, &pack, 2).await, (vec![], 1));
        assert!(svc.packs().is_empty());
        // Released again (a retry): never "free" — the pack is gone.
        assert_eq!(release(&svc, &pack, 2).await, (vec![pack.to_vec()], 0));
    }

    #[tokio::test]
    async fn a_copy_shares_a_pack_only_while_its_source_is_in_it() {
        let (_dir, svc) = service();
        let pack = [8u8; 16];
        intend(&svc, &pack).await;
        svc.seal_pack(Request::new(SealPackRequest {
            pack_id: pack.to_vec(),
            referrers: vec![vec![1; 16]],
            stripe: None,
        }))
        .await
        .unwrap();
        svc.share_stripes(Request::new(ShareStripesRequest {
            stripe_ids: vec![pack.to_vec()],
            owner: vec![1; 16],
            sharer: vec![3; 16],
        }))
        .await
        .unwrap();
        assert_eq!(release(&svc, &pack, 1).await, (vec![], 0));
        // The source has let go: a second copy from it is refused.
        let refused = svc
            .share_stripes(Request::new(ShareStripesRequest {
                stripe_ids: vec![pack.to_vec()],
                owner: vec![1; 16],
                sharer: vec![4; 16],
            }))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert_eq!(release(&svc, &pack, 3).await, (vec![], 1));
    }

    #[tokio::test]
    async fn only_an_unsealed_pack_is_aborted() {
        let (_dir, svc) = service();
        let pack = [9u8; 16];
        intend(&svc, &pack).await;
        // An unsealed pack has no referrers: a release frees nothing.
        assert_eq!(release(&svc, &pack, 1).await, (vec![], 0));
        let aborted = svc
            .abort_pack(Request::new(AbortPackRequest {
                pack_id: pack.to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(aborted.found && aborted.pack.is_some());
        assert!(svc.packs().is_empty());

        intend(&svc, &pack).await;
        svc.seal_pack(Request::new(SealPackRequest {
            pack_id: pack.to_vec(),
            referrers: vec![vec![1; 16]],
            stripe: None,
        }))
        .await
        .unwrap();
        let refused = svc
            .abort_pack(Request::new(AbortPackRequest {
                pack_id: pack.to_vec(),
            }))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn settled_members_leave_the_record_and_others_stay() {
        use objectio_proto::metadata::{PackMember, PackSettleRequest};
        let (_dir, svc) = service();
        let pack = [11u8; 16];
        svc.intend_pack(Request::new(IntendPackRequest {
            pack: Some(PackRecord {
                pack_id: pack.to_vec(),
                stripe: Some(stripe(&pack, 0)),
                members: (1..=3u8)
                    .map(|i| PackMember {
                        object_id: vec![i; 16],
                        key: format!("k{i}"),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }),
        }))
        .await
        .unwrap();
        svc.seal_pack(Request::new(SealPackRequest {
            pack_id: pack.to_vec(),
            referrers: vec![vec![1; 16], vec![2; 16], vec![3; 16]],
            stripe: None,
        }))
        .await
        .unwrap();
        assert_eq!(svc.packs()[0].members.len(), 3, "sealing keeps the members");
        svc.pack_settle(Request::new(PackSettleRequest {
            pack_id: pack.to_vec(),
            object_ids: vec![vec![1; 16], vec![3; 16], vec![9; 16]],
        }))
        .await
        .unwrap();
        let left: Vec<String> = svc.packs()[0]
            .members
            .iter()
            .filter(|m| !m.settled)
            .map(|m| m.key.clone())
            .collect();
        assert_eq!(left, ["k2"]);
        assert_eq!(
            svc.packs()[0].members.len(),
            3,
            "settled members stay, marked"
        );
        let listed = svc
            .list_packs(Request::new(
                objectio_proto::metadata::ListPacksRequest::default(),
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.referrers.len(), 1);
        assert_eq!(
            listed.referrers[0].object_ids.len(),
            3,
            "the pack's referrers"
        );
        // A pack that's gone has nothing to settle.
        svc.pack_settle(Request::new(PackSettleRequest {
            pack_id: vec![99; 16],
            object_ids: vec![vec![2; 16]],
        }))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn moved_and_rebuilt_shards_are_recorded_once_in_the_pack() {
        let (_dir, svc) = service();
        let pack = [10u8; 16];
        intend(&svc, &pack).await;
        let mut partial = stripe(&pack, 0);
        partial.shards.retain(|l| l.position != 5);
        svc.seal_pack(Request::new(SealPackRequest {
            pack_id: pack.to_vec(),
            referrers: vec![vec![1; 16]],
            stripe: Some(partial),
        }))
        .await
        .unwrap();
        let to = ShardLocation {
            position: 2,
            node_id: vec![50; 16],
            ..Default::default()
        };
        svc.move_pack_shard(&pack, 2, [2; 16], &to).await.unwrap();
        // A retry finds it moved already.
        svc.move_pack_shard(&pack, 2, [2; 16], &to).await.unwrap();
        let rebuilt = ShardLocation {
            position: 5,
            node_id: vec![60; 16],
            ..Default::default()
        };
        svc.pack_add_shard_locations(&pack, &[rebuilt])
            .await
            .unwrap();
        let record = &svc.packs()[0];
        let shards = &record.stripe.as_ref().unwrap().shards;
        assert_eq!(shards.len(), 6);
        assert_eq!(shards[2].node_id, vec![50; 16]);
        assert_eq!(shards[5].node_id, vec![60; 16]);
        assert_eq!(record.version, 3, "intended at 1, bumped by each change");
    }
}
