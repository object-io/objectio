//! Metadata gRPC service implementation

mod block_meta;
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
    SetConfigRequest,
    SetConfigResponse,
    SetOsdAdminStateRequest,
    SetOsdAdminStateResponse,
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

    /// Open multipart uploads as Prometheus gauges. An abandoned upload
    /// holds its parts' space until someone aborts it, so this reports how
    /// many there are, how old, and how many bytes they hold.
    pub fn render_multipart_metrics(&self) -> String {
        use std::fmt::Write as _;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let uploads = self.multipart_uploads.read();
        let ages: Vec<u64> = uploads
            .values()
            .map(|u| now.saturating_sub(u.initiated))
            .collect();
        let bytes: u64 = uploads
            .values()
            .flat_map(|u| u.parts.values())
            .map(|p| p.size)
            .sum();
        drop(uploads);

        let mut out = String::new();
        let mut gauge = |name: &str, help: &str, samples: &[(&str, u64)]| {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} gauge");
            for (labels, v) in samples {
                if labels.is_empty() {
                    let _ = writeln!(out, "{name} {v}");
                } else {
                    let _ = writeln!(out, "{name}{{{labels}}} {v}");
                }
            }
        };
        gauge(
            "objectio_multipart_uploads_open",
            "Multipart uploads started and neither completed nor aborted",
            &[("", ages.len() as u64)],
        );
        gauge(
            "objectio_multipart_upload_oldest_age_seconds",
            "Age of the oldest open multipart upload",
            &[("", ages.iter().copied().max().unwrap_or(0))],
        );
        let older = |secs: u64| ages.iter().filter(|a| **a > secs).count() as u64;
        gauge(
            "objectio_multipart_uploads_older_than",
            "Open multipart uploads older than the given age",
            &[
                ("age=\"1h\"", older(3600)),
                ("age=\"1d\"", older(86_400)),
                ("age=\"7d\"", older(604_800)),
            ],
        );
        gauge(
            "objectio_multipart_upload_parts_bytes",
            "Bytes held by parts of open multipart uploads",
            &[("", bytes)],
        );
        out
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

    /// Mirror a Raft-committed Config write into the in-memory cache.
    /// Writes made via direct handlers (set_config, rebalance/pause,
    /// balancer knobs) update the cache themselves and then the
    /// Raft commit re-applies this same event — idempotent, harmless.
    /// Writes made via cluster_uuid()'s direct Raft path rely entirely
    /// on this handler to populate the cache.
    fn apply_config_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        {
            let mut map = self.config.write();
            match new_value {
                Some(bytes) => match ConfigEntry::decode(bytes) {
                    Ok(entry) => {
                        map.insert(key.to_string(), entry);
                    }
                    Err(e) => {
                        warn!("apply: decode ConfigEntry('{key}') failed: {e}");
                    }
                },
                None => {
                    map.remove(key);
                }
            }
        }
        if key == objectio_common::version::ACTIVE_LEVEL_KEY {
            self.note_active_level();
        }
    }

    /// Mirror a committed change to the shared-stripe registry.
    fn apply_stripe_refs_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut map = self.stripe_refs.write();
        match new_value {
            Some(bytes) => match objectio_proto::metadata::StripeRefs::decode(bytes) {
                Ok(r) => {
                    map.insert(key.to_string(), r);
                }
                Err(e) => warn!("apply: decode StripeRefs('{key}') failed: {e}"),
            },
            None => {
                map.remove(key);
            }
        }
    }

    /// Apply registry changes (`None` removes an entry) atomically, each
    /// expected to still hold what it was read as. `Ok(false)` on a
    /// conflict, for the caller to re-read and retry.
    async fn write_stripe_refs(
        &self,
        changes: Vec<(String, Option<objectio_proto::metadata::StripeRefs>)>,
        requested_by: &str,
    ) -> Result<bool, Status> {
        use prost::Message;
        if changes.is_empty() {
            return Ok(true);
        }
        let expected: Vec<Option<Vec<u8>>> = {
            let map = self.stripe_refs.read();
            changes
                .iter()
                .map(|(k, _)| map.get(k).map(Message::encode_to_vec))
                .collect()
        };
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let ops = changes
                .iter()
                .zip(expected)
                .map(|((key, new), expected)| CasOp {
                    table: CasTable::Named("stripe_refs".into()),
                    key: key.clone(),
                    expected,
                    new_value: new.as_ref().map(Message::encode_to_vec),
                })
                .collect();
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: requested_by.into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => return Ok(false),
                    other => {
                        error!("unexpected raft response for {requested_by}: {other:?}");
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            for (key, new) in &changes {
                match new {
                    Some(r) => store.put_stripe_refs(key, &r.encode_to_vec()),
                    None => store.delete_stripe_refs(key),
                }
            }
        }
        let mut map = self.stripe_refs.write();
        for (key, new) in changes {
            match new {
                Some(r) => {
                    map.insert(key, r);
                }
                None => {
                    map.remove(&key);
                }
            }
        }
        Ok(true)
    }

    /// Mirror a committed tenant write, so every replica — not only the
    /// leader that served it — sees a tenant's settings (its dedup policy
    /// among them) change.
    fn apply_tenant_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut tenants = self.tenants.write();
        match new_value {
            Some(bytes) => match TenantConfig::decode(bytes) {
                Ok(t) => {
                    tenants.insert(key.to_string(), t);
                }
                Err(e) => warn!("apply: decode TenantConfig('{key}') failed: {e}"),
            },
            None => {
                tenants.remove(key);
            }
        }
    }

    /// The dedup policy `bucket` resolves to: its own, then its tenant's,
    /// then the cluster default. In-memory only, so `GetPlacement` can
    /// return it at no cost.
    pub fn effective_dedup(&self, bucket: &str) -> objectio_proto::dedup::Effective {
        let (bucket_policy, tenant_name) = self
            .buckets
            .read()
            .get(bucket)
            .map(|b| (b.dedup, b.tenant.clone()))
            .unwrap_or_default();
        let tenant_policy = self.tenants.read().get(&tenant_name).and_then(|t| t.dedup);
        let cluster = self
            .config
            .read()
            .get(objectio_proto::dedup::CLUSTER_KEY)
            .and_then(|e| objectio_proto::dedup::cluster_from_config(&e.value));
        objectio_proto::dedup::resolve(
            bucket,
            &tenant_name,
            bucket_policy.as_ref(),
            tenant_policy.as_ref(),
            cluster.as_ref(),
        )
    }

    fn with_dedup(&self, bucket: &str, mut resp: GetPlacementResponse) -> GetPlacementResponse {
        let e = self.effective_dedup(bucket);
        resp.set_dedup_mode(e.mode);
        resp.dedup_domain = e.domain;
        resp
    }

    fn apply_bucket_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut buckets = self.buckets.write();
        match new_value {
            Some(bytes) => match BucketMeta::decode(bytes) {
                Ok(b) => {
                    buckets.insert(key.to_string(), b);
                }
                Err(e) => warn!("apply: decode BucketMeta('{key}') failed: {e}"),
            },
            None => {
                buckets.remove(key);
                drop(buckets);
                self.forget_bucket_config(key);
            }
        }
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

    /// Read, change and write one multipart upload as a unit: through Raft
    /// as a compare-and-set against the record read (retried when it
    /// changed meanwhile), so every meta node has it and a racing
    /// completion, abort or part upload can't be lost; without Raft, under
    /// the in-memory lock. `change` gets the upload as it stands (`None`:
    /// there is none) and returns what it becomes (`None`: removed) and a
    /// result. It may run more than once.
    async fn update_multipart<T>(
        &self,
        upload_id: &str,
        what: &str,
        change: impl Fn(
            Option<MultipartUploadState>,
        ) -> Result<(Option<MultipartUploadState>, T), Status>,
    ) -> Result<T, Status> {
        let store = self.store.as_ref().filter(|_| self.raft_handle().is_some());
        let Some(store) = store else {
            let mut uploads = self.multipart_uploads.write();
            let (new, out) = change(uploads.get(upload_id).cloned())?;
            match &new {
                Some(u) => {
                    uploads.insert(upload_id.to_string(), u.clone());
                }
                None => {
                    uploads.remove(upload_id);
                }
            }
            drop(uploads);
            if let Some(store) = &self.store {
                match &new {
                    Some(u) => store.put_multipart_upload(upload_id, u),
                    None => store.delete_multipart_upload(upload_id),
                }
            }
            return Ok(out);
        };
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let stored = store.read_named(MULTIPART_TABLE, upload_id);
            let current = match &stored {
                Some(bytes) => Some(
                    bincode::deserialize::<MultipartUploadState>(bytes)
                        .map_err(|e| Status::internal(format!("multipart decode: {e}")))?,
                ),
                None => None,
            };
            let (new, out) = change(current)?;
            let new_bytes = match &new {
                Some(u) => Some(
                    bincode::serialize(u)
                        .map_err(|e| Status::internal(format!("multipart encode: {e}")))?,
                ),
                None => None,
            };
            if new_bytes == stored {
                return Ok(out);
            }
            let ok = self
                .cas_many(
                    vec![objectio_meta_store::CasOp {
                        table: CasTable::Named(MULTIPART_TABLE.into()),
                        key: upload_id.to_string(),
                        expected: stored,
                        new_value: new_bytes,
                    }],
                    what,
                )
                .await?;
            if ok {
                // The apply listener mirrors it too; this makes it visible
                // to the next call on this node at once.
                match new {
                    Some(u) => {
                        self.multipart_uploads
                            .write()
                            .insert(upload_id.to_string(), u);
                    }
                    None => {
                        self.multipart_uploads.write().remove(upload_id);
                    }
                }
                return Ok(out);
            }
        }
        Err(Status::aborted(format!(
            "{what}: the upload kept changing; retry"
        )))
    }

    /// Mirror a replicated OSD record into this node's caches.
    fn apply_osd_node_event(&self, key: &str, new_value: Option<&[u8]>) {
        match new_value {
            Some(bytes) => match bincode::deserialize::<OsdNode>(bytes) {
                Ok(node) => {
                    {
                        let mut nodes = self.osd_nodes.write();
                        // A replacement at the same address (lost state, new
                        // id) supersedes the old entry, as registration does.
                        nodes.retain(|n| n.node_id == node.node_id || n.address != node.address);
                        match nodes.iter_mut().find(|n| n.node_id == node.node_id) {
                            Some(existing) => *existing = node.clone(),
                            None => nodes.push(node.clone()),
                        }
                    }
                    self.refresh_topology_node(&node);
                }
                Err(e) => warn!("apply: decode OsdNode('{key}') failed: {e}"),
            },
            None => {
                let Ok(id) = hex::decode(key) else { return };
                self.osd_nodes
                    .write()
                    .retain(|n| n.node_id.as_slice() != id.as_slice());
                if let Ok(id) = <[u8; 16]>::try_from(id.as_slice()) {
                    self.topology.write().remove_node(NodeId::from_bytes(id));
                }
            }
        }
    }

    /// Mirror a replicated KMS key into this node's cache.
    fn apply_kms_key_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        match new_value {
            Some(bytes) => match objectio_proto::metadata::KmsKey::decode(bytes) {
                Ok(k) => {
                    self.kms_keys.write().insert(key.to_string(), k);
                }
                Err(e) => warn!("apply: decode KmsKey('{key}') failed: {e}"),
            },
            None => {
                self.kms_keys.write().remove(key);
            }
        }
    }

    /// Mirror a replicated multipart upload into this node's cache.
    fn apply_multipart_event(&self, key: &str, new_value: Option<&[u8]>) {
        match new_value {
            Some(bytes) => match bincode::deserialize::<MultipartUploadState>(bytes) {
                Ok(u) => {
                    self.multipart_uploads.write().insert(key.to_string(), u);
                }
                Err(e) => warn!("apply: decode multipart upload('{key}') failed: {e}"),
            },
            None => {
                self.multipart_uploads.write().remove(key);
            }
        }
    }

    /// A pack's record and its stored bytes (for compare-and-set).
    fn pack_record(
        &self,
        pack_id: &[u8],
    ) -> Option<(objectio_proto::metadata::PackRecord, Vec<u8>)> {
        let bytes = self
            .store
            .as_ref()?
            .read_named(PACKS_TABLE, &hex::encode(pack_id))?;
        let record = objectio_proto::metadata::PackRecord::decode(bytes.as_slice()).ok()?;
        Some((record, bytes))
    }

    /// Every pack, sealed or not, for drain and repair (as block chunks).
    pub fn packs(&self) -> Vec<objectio_proto::metadata::PackRecord> {
        self.store
            .as_ref()
            .map(|s| s.list_named(PACKS_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, v)| objectio_proto::metadata::PackRecord::decode(v.as_slice()).ok())
            .filter(|p| p.stripe.is_some())
            .collect()
    }

    /// Record shards of a pack rebuilt where it had none.
    pub async fn pack_add_shard_locations(
        &self,
        pack_id: &[u8],
        added: &[objectio_proto::metadata::ShardLocation],
    ) -> Result<(), Status> {
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let Some((mut record, bytes)) = self.pack_record(pack_id) else {
                return Err(Status::not_found("pack not found"));
            };
            let Some(stripe) = record.stripe.as_mut() else {
                return Err(Status::internal("pack has no stripe"));
            };
            let mut changed = false;
            for loc in added {
                if stripe.shards.iter().all(|l| l.position != loc.position) {
                    stripe.shards.push(loc.clone());
                    changed = true;
                }
            }
            if !changed {
                return Ok(());
            }
            stripe.shards.sort_by_key(|l| l.position);
            record.version += 1;
            let ok = self
                .cas_many(
                    vec![objectio_meta_store::CasOp {
                        table: objectio_meta_store::CasTable::Named(PACKS_TABLE.into()),
                        key: hex::encode(pack_id),
                        expected: Some(bytes),
                        new_value: Some(record.encode_to_vec()),
                    }],
                    "pack-add-shards",
                )
                .await?;
            if ok {
                return Ok(());
            }
        }
        Err(Status::aborted("pack kept changing; retry"))
    }

    /// Record that a pack's shard at `position` moved from `from` to `to`.
    pub async fn pack_move_shard(
        &self,
        pack_id: &[u8],
        position: u32,
        from: [u8; 16],
        to: &objectio_proto::metadata::ShardLocation,
    ) -> Result<(), Status> {
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let Some((mut record, bytes)) = self.pack_record(pack_id) else {
                return Err(Status::not_found("pack not found"));
            };
            let Some(stripe) = record.stripe.as_mut() else {
                return Err(Status::internal("pack has no stripe"));
            };
            let mut moved = false;
            for loc in &mut stripe.shards {
                if loc.position == position && loc.node_id.as_slice() == from.as_slice() {
                    *loc = to.clone();
                    moved = true;
                }
            }
            if !moved {
                // Already moved (a retry), or the record names another node.
                return Ok(());
            }
            record.version += 1;
            let ok = self
                .cas_many(
                    vec![objectio_meta_store::CasOp {
                        table: objectio_meta_store::CasTable::Named(PACKS_TABLE.into()),
                        key: hex::encode(pack_id),
                        expected: Some(bytes),
                        new_value: Some(record.encode_to_vec()),
                    }],
                    "pack-move-shard",
                )
                .await?;
            if ok {
                return Ok(());
            }
        }
        Err(Status::aborted("pack kept changing; retry"))
    }

    /// A drained OSD's purge state (`drain_observer::PURGE_*`), if any.
    pub fn purge_state(&self, node_id: [u8; 16]) -> Option<String> {
        self.store
            .as_ref()
            .and_then(|s| s.read_named(OSD_PURGE_TABLE, &hex::encode(node_id)))
            .and_then(|v| String::from_utf8(v).ok())
    }

    /// Drained OSDs whose purge isn't confirmed yet.
    pub fn pending_purges(&self) -> Vec<[u8; 16]> {
        self.store
            .as_ref()
            .map(|s| s.list_named(OSD_PURGE_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, v)| v.as_slice() == crate::drain_observer::PURGE_PENDING.as_bytes())
            .filter_map(|(k, _)| hex::decode(k).ok()?.try_into().ok())
            .collect()
    }

    /// Record (or, with `None`, forget) a drained OSD's purge state.
    pub async fn set_purge_state(
        &self,
        node_id: [u8; 16],
        state: Option<&str>,
    ) -> Result<(), Status> {
        let key = hex::encode(node_id);
        let current = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(OSD_PURGE_TABLE, &key));
        if current.is_none() && state.is_none() {
            return Ok(());
        }
        self.cas_one(
            objectio_meta_store::CasTable::Named(OSD_PURGE_TABLE.into()),
            &key,
            current,
            state.map(|s| s.as_bytes().to_vec()),
            "osd-purge-state",
        )
        .await
    }

    /// The pool a new bucket in `tenant` goes to, `requested` or not.
    ///
    /// A system bucket may go to any enabled pool. A tenant's bucket goes to
    /// the pool it asks for only if the tenant may use it (its default, or
    /// one of its allowed pools), otherwise to the tenant's default pool;
    /// empty means the cluster's default placement.
    #[allow(clippy::result_large_err)]
    fn resolve_bucket_pool(&self, tenant: &str, requested: &str) -> Result<String, Status> {
        let (default_pool, allowed) = if tenant.is_empty() {
            (String::new(), None)
        } else {
            let tenants = self.tenants.read();
            let t = tenants.get(tenant);
            (
                t.map(|t| t.default_pool.clone()).unwrap_or_default(),
                Some(t.map(|t| t.allowed_pools.clone()).unwrap_or_default()),
            )
        };
        let pool = if requested.is_empty() {
            default_pool.clone()
        } else {
            requested.to_string()
        };
        if pool.is_empty() {
            return Ok(pool);
        }
        if let Some(allowed) = &allowed
            && pool != default_pool
            && !allowed.contains(&pool)
        {
            return Err(Status::permission_denied(format!(
                "tenant '{tenant}' may not use pool '{pool}'"
            )));
        }
        match self.pools.read().get(&pool) {
            Some(p) if p.enabled => Ok(pool),
            Some(_) => Err(Status::failed_precondition(format!(
                "pool '{pool}' is disabled"
            ))),
            None => Err(Status::not_found(format!("pool '{pool}' does not exist"))),
        }
    }

    /// The stored rows configuring `bucket` beyond its `BucketMeta`, as
    /// `(table, key, current bytes)`: what deleting the bucket removes.
    fn bucket_config_rows(
        &self,
        bucket: &str,
    ) -> Vec<(objectio_meta_store::CasTable, String, Vec<u8>)> {
        use objectio_meta_store::CasTable;
        let Some(store) = &self.store else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        for table in [
            CasTable::BucketPolicies,
            CasTable::Named("object_lock_configs".into()),
            CasTable::Named("lifecycle_configs".into()),
            CasTable::Named("bucket_encryption_configs".into()),
        ] {
            if let Some(v) = store.read_named(objectio_meta_store::cas_table_name(&table), bucket) {
                rows.push((table, bucket.to_string(), v));
            }
        }
        let prefix = format!("{bucket}/");
        rows.extend(
            store
                .list_named(BUCKET_SETTINGS_TABLE)
                .into_iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, v)| (CasTable::Named(BUCKET_SETTINGS_TABLE.into()), k, v)),
        );
        rows
    }

    /// Drop a deleted bucket's configuration from the in-memory caches.
    fn forget_bucket_config(&self, bucket: &str) {
        self.bucket_policies.write().remove(bucket);
        self.object_lock_configs.write().remove(bucket);
        self.lifecycle_configs.write().remove(bucket);
        self.bucket_encryption_configs.write().remove(bucket);
    }

    fn apply_bucket_policy_event(&self, key: &str, new_value: Option<&[u8]>) {
        let mut m = self.bucket_policies.write();
        match new_value {
            Some(bytes) => match std::str::from_utf8(bytes) {
                Ok(s) => {
                    m.insert(key.to_string(), s.to_string());
                }
                Err(e) => warn!("apply: bucket_policy('{key}') not utf-8: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    fn apply_user_event(&self, key: &str, new_value: Option<&[u8]>) {
        let mut m = self.users.write();
        match new_value {
            Some(bytes) => match bincode::deserialize::<StoredUser>(bytes) {
                Ok(u) => {
                    m.insert(key.to_string(), u);
                }
                Err(e) => warn!("apply: decode StoredUser('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    fn apply_access_key_event(&self, key: &str, new_value: Option<&[u8]>) {
        let mut m = self.access_keys.write();
        match new_value {
            Some(bytes) => {
                match bincode::deserialize::<objectio_meta_store::StoredAccessKey>(bytes) {
                    Ok(k) => {
                        // Keep user_keys index consistent: insert the
                        // access_key_id under the owning user if absent.
                        let user_id = k.user_id.clone();
                        m.insert(key.to_string(), k);
                        drop(m);
                        let mut idx = self.user_keys.write();
                        let ids = idx.entry(user_id).or_default();
                        if !ids.iter().any(|k2| k2 == key) {
                            ids.push(key.to_string());
                        }
                    }
                    Err(e) => warn!("apply: decode StoredAccessKey('{key}') failed: {e}"),
                }
            }
            None => {
                let removed = m.remove(key);
                drop(m);
                if let Some(k) = removed {
                    let mut idx = self.user_keys.write();
                    if let Some(ids) = idx.get_mut(&k.user_id) {
                        ids.retain(|k2| k2 != key);
                    }
                }
            }
        }
    }

    fn apply_iceberg_table_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut tables = self.iceberg_tables.write();
        match new_value {
            Some(bytes) => match IcebergTableEntry::decode(bytes) {
                Ok(e) => {
                    tables.insert(key.to_string(), e);
                }
                Err(e) => warn!("apply: decode IcebergTableEntry('{key}') failed: {e}"),
            },
            None => {
                tables.remove(key);
            }
        }
    }

    fn apply_iceberg_namespace_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut ns = self.iceberg_namespaces.write();
        match new_value {
            Some(bytes) => match IcebergCreateNamespaceResponse::decode(bytes) {
                Ok(r) => {
                    ns.insert(key.to_string(), r.properties);
                }
                Err(e) => warn!("apply: decode IcebergNamespace('{key}') failed: {e}"),
            },
            None => {
                ns.remove(key);
            }
        }
    }

    /// Apply a committed PlacementGroup mutation to the in-memory
    /// cache. Key format is "{pool}\0{pg_id:010}" — same as the redb
    /// key produced by `objectio_meta_store::MetaStore::pg_key`. A
    /// delete (`new_value = None`) removes the entry; a put decodes
    /// the prost bytes and upserts.
    fn apply_placement_group_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let Some((pool, pg_id)) = Self::parse_pg_key(key) else {
            warn!("apply: malformed placement_group key '{key}'");
            return;
        };
        let mut map = self.placement_groups.write();
        match new_value {
            Some(bytes) => match PlacementGroup::decode(bytes) {
                Ok(pg) => {
                    map.insert((pool, pg_id), pg);
                }
                Err(e) => warn!("apply: decode PlacementGroup('{key}') failed: {e}"),
            },
            None => {
                map.remove(&(pool, pg_id));
            }
        }
    }

    /// Inverse of `objectio_meta_store::MetaStore::pg_key`. Returns
    /// (pool, pg_id) from "{pool}\0{pg_id:010}".
    fn parse_pg_key(key: &str) -> Option<(String, u32)> {
        let (pool, tail) = key.split_once('\0')?;
        let pg_id: u32 = tail.parse().ok()?;
        Some((pool.to_string(), pg_id))
    }

    /// Look up a placement group from the in-memory cache.
    pub fn placement_group(&self, pool: &str, pg_id: u32) -> Option<PlacementGroup> {
        self.placement_groups
            .read()
            .get(&(pool.to_string(), pg_id))
            .cloned()
    }

    /// Pre-allocate `pool.pg_count` placement groups using the
    /// copyset allocator. Called from `create_pool` once the pool
    /// row has been committed. Returns Ok(()) when every PG is
    /// written (or on the non-Raft fallback path). Commits in
    /// MultiCas batches of ≤128 ops to stay under the storage
    /// limit (see `raft_storage::MAX_OPS = 256`).
    async fn preallocate_placement_groups(&self, pool: &PoolConfig) -> Result<(), Status> {
        use objectio_common::FailureDomain;
        use objectio_placement::CopysetPool;

        let copy_count = match pool.ec_type() {
            ErasureType::ErasureMds => (pool.ec_k + pool.ec_m) as usize,
            ErasureType::ErasureLrc => {
                (pool.ec_k + pool.ec_local_parity + pool.ec_global_parity) as usize
            }
            ErasureType::ErasureReplication => pool.replication_count as usize,
        };
        if copy_count == 0 {
            return Err(Status::invalid_argument(
                "pool has zero shards per PG — check ec_k / ec_m / replication_count",
            ));
        }

        let fd_level = match pool.failure_domain.as_str() {
            "host" | "" => FailureDomain::Host,
            "node" => FailureDomain::Node,
            "rack" => FailureDomain::Rack,
            "datacenter" => FailureDomain::Datacenter,
            "zone" => FailureDomain::Zone,
            "region" => FailureDomain::Region,
            "disk" => FailureDomain::Disk,
            other => {
                return Err(Status::invalid_argument(format!(
                    "pool.failure_domain '{other}' not recognised"
                )));
            }
        };

        let topology = self.topology.read().clone();
        // Seed = topology.version × pg_count so concurrent pool creates
        // with the same topology get distinct pools.
        let seed = topology
            .version
            .wrapping_mul(1_000_003)
            .wrapping_add(u64::from(pool.pg_count));
        // scatter_width matches the balancer's knob so pre-alloc and
        // later rebalance see copyset pools of equivalent shape.
        let scatter_width = self
            .config_parsed::<usize>("balancer/scatter_width", 10)
            .max(1);
        let cs_pool = CopysetPool::build(&topology, fd_level, copy_count, scatter_width, seed)
            .map_err(|e| Status::failed_precondition(format!("copyset pool build failed: {e}")))?;
        if cs_pool.sets.is_empty() {
            return Err(Status::failed_precondition(
                "no feasible copysets for current topology",
            ));
        }

        let now = Self::current_timestamp();
        let mut pgs: Vec<PlacementGroup> = Vec::with_capacity(pool.pg_count as usize);
        for pg_id in 0..pool.pg_count {
            let cs = &cs_pool.sets[pg_id as usize % cs_pool.sets.len()];
            pgs.push(PlacementGroup {
                pool: pool.name.clone(),
                pg_id,
                osd_ids: cs.osds.iter().map(|n| n.as_bytes().to_vec()).collect(),
                version: 1,
                updated_at: now,
                migrating_to_osd_ids: Vec::new(),
                migration_started_at: 0,
                pending_moves_count: 0,
            });
        }

        // Commit in batches. MAX_OPS in raft_storage is 256 — stay
        // well under to leave headroom for other MultiCas calls that
        // land in the same raft entry.
        const CHUNK: usize = 128;
        let raft = self.raft_handle();
        for chunk in pgs.chunks(CHUNK) {
            if let Some(raft) = raft.clone() {
                use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
                let ops: Vec<CasOp> = chunk
                    .iter()
                    .map(|pg| CasOp {
                        table: CasTable::PlacementGroups,
                        key: MetaStore::pg_key(&pg.pool, pg.pg_id),
                        expected: None,
                        new_value: Some(pg.encode_to_vec()),
                    })
                    .collect();
                let cmd = MetaCommand::MultiCas {
                    ops,
                    requested_by: "create-pool:init-pgs".into(),
                };
                match raft.client_write(cmd).await {
                    Ok(r) => match r.data {
                        MetaResponse::MultiCasOk => {}
                        MetaResponse::MultiCasConflict { .. } => {
                            return Err(Status::aborted("PG conflict during pre-allocation"));
                        }
                        other => {
                            error!("unexpected raft response during PG pre-alloc: {other:?}");
                            return Err(Status::internal("raft commit wrong variant"));
                        }
                    },
                    Err(e) => return Err(raft_write_to_status(&e)),
                }
            } else if let Some(store) = &self.store {
                for pg in chunk {
                    store.put_placement_group(&pg.pool, pg.pg_id, &pg.encode_to_vec());
                }
            }
        }

        info!(
            "pool '{}' pre-allocated {} PGs (copy_count={}, fd={}, pool.size={})",
            pool.name,
            pool.pg_count,
            copy_count,
            fd_level,
            cs_pool.sets.len(),
        );
        Ok(())
    }

    fn apply_iceberg_warehouse_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut wh = self.iceberg_warehouses.write();
        match new_value {
            Some(bytes) => match IcebergWarehouse::decode(bytes) {
                Ok(w) => {
                    wh.insert(key.to_string(), w);
                }
                Err(e) => warn!("apply: decode IcebergWarehouse('{key}') failed: {e}"),
            },
            None => {
                wh.remove(key);
            }
        }
    }

    fn apply_unity_catalog_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_catalogs.write();
        match new_value {
            Some(bytes) => match UnityCatalog::decode(bytes) {
                Ok(c) => {
                    m.insert(key.to_string(), c);
                }
                Err(e) => warn!("apply: decode UnityCatalog('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    fn apply_unity_schema_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_schemas.write();
        match new_value {
            Some(bytes) => match UnitySchema::decode(bytes) {
                Ok(s) => {
                    m.insert(key.to_string(), s);
                }
                Err(e) => warn!("apply: decode UnitySchema('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    fn apply_unity_table_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_tables.write();
        match new_value {
            Some(bytes) => match UnityTable::decode(bytes) {
                Ok(t) => {
                    m.insert(key.to_string(), t);
                }
                Err(e) => warn!("apply: decode UnityTable('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    fn apply_unity_function_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_functions.write();
        match new_value {
            Some(bytes) => match UnityFunction::decode(bytes) {
                Ok(f) => {
                    m.insert(key.to_string(), f);
                }
                Err(e) => warn!("apply: decode UnityFunction('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    fn apply_unity_volume_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_volumes.write();
        match new_value {
            Some(bytes) => match UnityVolume::decode(bytes) {
                Ok(v) => {
                    m.insert(key.to_string(), v);
                }
                Err(e) => warn!("apply: decode UnityVolume('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    fn apply_unity_model_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_models.write();
        match new_value {
            Some(bytes) => match UnityModel::decode(bytes) {
                Ok(m_) => {
                    m.insert(key.to_string(), m_);
                }
                Err(e) => warn!("apply: decode UnityModel('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
    }

    fn apply_unity_model_version_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut m = self.unity_model_versions.write();
        match new_value {
            Some(bytes) => match UnityModelVersion::decode(bytes) {
                Ok(v) => {
                    m.insert(key.to_string(), v);
                }
                Err(e) => warn!("apply: decode UnityModelVersion('{key}') failed: {e}"),
            },
            None => {
                m.remove(key);
            }
        }
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

    /// Read-only snapshot of the registered OSD list. Exposed for
    /// internal background tasks (drain observer) that need to
    /// iterate without acquiring the lock for an async scope.
    pub fn osd_nodes_read(&self) -> parking_lot::RwLockReadGuard<'_, Vec<OsdNode>> {
        self.osd_nodes.read()
    }

    /// Clone-snapshot of all pools. Background tasks use this instead
    /// of holding the lock across awaits.
    pub fn pools_snapshot(&self) -> Vec<PoolConfig> {
        self.pools.read().values().cloned().collect()
    }

    /// Clone-snapshot of all placement groups for a given pool.
    pub fn placement_groups_for_pool(&self, pool: &str) -> Vec<PlacementGroup> {
        let map = self.placement_groups.read();
        let mut pgs: Vec<PlacementGroup> = map
            .iter()
            .filter(|((p, _), _)| p == pool)
            .map(|(_, pg)| pg.clone())
            .collect();
        pgs.sort_by_key(|p| p.pg_id);
        pgs
    }

    /// Clone-snapshot of the cluster topology.
    pub fn topology_snapshot(&self) -> ClusterTopology {
        self.topology.read().clone()
    }

    /// Snapshot of all OSD drain progresses — node_id → progress.
    /// Consumed by the gateway's `/_admin/drain-status` endpoint.
    pub fn drain_statuses_snapshot(&self) -> HashMap<[u8; 16], DrainProgress> {
        self.drain_statuses.read().clone()
    }

    /// Mutate a single OSD's drain progress. Creates a default entry
    /// if absent. Background-task entrypoint — not exposed over gRPC.
    pub fn update_drain_progress<F: FnOnce(&mut DrainProgress)>(&self, node_id: [u8; 16], f: F) {
        let mut statuses = self.drain_statuses.write();
        let entry = statuses.entry(node_id).or_default();
        f(entry);
    }

    /// Remove a node from the drain-progress map — called once an OSD
    /// leaves the Draining state (either finalised to Out or rolled
    /// back to In).
    pub fn clear_drain_progress(&self, node_id: &[u8; 16]) {
        self.drain_statuses.write().remove(node_id);
    }

    /// Snapshot of the cluster-wide rebalance progress — consumed by
    /// `/_admin/rebalance-status`.
    pub fn rebalance_progress_snapshot(&self) -> RebalanceProgress {
        self.rebalance_progress.read().clone()
    }

    /// Mutate rebalance progress. Used by the reconciler sweep.
    pub fn update_rebalance_progress<F: FnOnce(&mut RebalanceProgress)>(&self, f: F) {
        let mut p = self.rebalance_progress.write();
        f(&mut p);
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

    /// Is the rebalancer currently paused via the `rebalance/paused`
    /// config key? Checked on every reconciler sweep so paused state
    /// stays hot-swappable without restarting the process.
    pub fn is_rebalance_paused(&self) -> bool {
        // The config map mirrors what `set_config` has committed via
        // Raft; a bool cast from the stored "true"/"false" byte
        // string. Any parse error is treated as not-paused so a
        // garbled config can't lock the cluster into a no-rebalance
        // state.
        let cfg = self.config.read();
        cfg.get("rebalance/paused")
            .and_then(|e| std::str::from_utf8(&e.value).ok())
            .map(|s| s.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    /// Look up the address of an OSD by its node_id. Used by the drain
    /// migrator to open client channels.
    pub fn osd_address_by_id(&self, node_id: &[u8; 16]) -> Option<String> {
        self.osd_nodes
            .read()
            .iter()
            .find(|n| &n.node_id == node_id)
            .map(|n| n.address.clone())
    }

    /// Snapshot of every registered OSD. Cloned so a caller can make network
    /// calls without holding the lock.
    /// Whether `bucket/key` has a current entry in the listing index.
    pub fn object_listed(&self, bucket: &str, key: &str) -> bool {
        self.store
            .as_ref()
            .and_then(|s| s.read_object_listing(&format!("{bucket}\0{key}\0")))
            .is_some()
    }

    pub fn osd_nodes_snapshot(&self) -> Vec<OsdNode> {
        self.osd_nodes.read().clone()
    }

    /// Set one node's observed status in the topology and rebuild CRUSH.
    ///
    /// Nothing outside registration used to touch node status, which is why a
    /// dead OSD stayed in the placement set: `NodeStatus::Down` existed and
    /// `active_nodes()` already skipped it, but there was no path that ever
    /// set it.
    pub fn set_topology_node_status(&self, node_id: NodeId, status: NodeStatus) {
        {
            let mut topology = self.topology.write();
            let Some(current) = topology.get_node(node_id) else {
                return;
            };
            if current.status == status {
                return;
            }
            let mut updated = current.clone();
            updated.status = status;
            topology.upsert_node(updated);
        }
        // Same rebuild the registration path does — replacing the engine
        // wholesale would drop its stripe-group configuration.
        let topology = self.topology.read().clone();
        self.crush.write().update_topology(topology);
    }

    /// List addresses of every registered OSD (any admin_state).
    /// Drain migrator uses this to fan out the
    /// `FindObjectsReferencingNode` scan.
    pub fn all_osd_addresses(&self) -> Vec<(String, [u8; 16])> {
        self.osd_nodes
            .read()
            .iter()
            .map(|n| (n.address.clone(), n.node_id))
            .collect()
    }

    /// Compute a CRUSH replacement for a single shard at `position` in
    /// the placement set for `object_id`, excluding the `exclude` node
    /// (typically the draining / current-owner OSD). Only returns
    /// candidates that are currently **registered** on this meta —
    /// a stale topology entry for an unregistered node is skipped
    /// rather than returned, so the caller can rely on
    /// `osd_address_by_id(target)` succeeding.
    ///
    /// Returns `None` if CRUSH can't find a valid alternative (too few
    /// eligible OSDs, or every CRUSH-picked node is unregistered /
    /// the excluded one). Caller logs and retries next sweep.
    pub fn pick_migration_target(
        &self,
        object_id: &[u8; 16],
        position: u32,
        exclude: &[u8; 16],
    ) -> Option<[u8; 16]> {
        use objectio_placement::crush2::PlacementTemplate;

        let template = PlacementTemplate::mds(self.default_ec_k as u8, self.default_ec_m as u8);

        let crush = self.crush.read();
        let obj_id = objectio_common::ObjectId::from_uuid(uuid::Uuid::from_bytes(*object_id));
        let placements = crush.select_placement(&obj_id, &template);
        drop(crush);

        let registered: std::collections::HashSet<[u8; 16]> =
            self.osd_nodes.read().iter().map(|n| n.node_id).collect();

        let eligible = |cand: &[u8; 16]| cand != exclude && registered.contains(cand);

        // Prefer the CRUSH pick for the exact stripe position. This
        // preserves the intended role (Data vs Parity) and keeps
        // placement deterministic for the other shards in the stripe.
        for p in &placements {
            if p.position as u32 == position {
                let cand = *p.node_id.as_bytes();
                if eligible(&cand) {
                    return Some(cand);
                }
            }
        }
        // Fallback: any CRUSH-eligible node in the returned set that
        // isn't excluded. Role becomes a soft hint — better than
        // failing the migration outright.
        placements
            .iter()
            .map(|p| *p.node_id.as_bytes())
            .find(eligible)
    }

    /// Where a drain moves shard `position` of a stripe: an OSD in
    /// service (not Draining or Out) that holds no other shard of the
    /// stripe (`holders`), so the stripe keeps one shard per OSD and still
    /// survives the failures it was written to survive. The CRUSH choice
    /// for `object_id` if it qualifies; otherwise the first in-service OSD
    /// that does, in a fixed order per stripe.
    pub fn pick_drain_target(
        &self,
        object_id: &[u8; 16],
        position: u32,
        holders: &[[u8; 16]],
    ) -> Option<[u8; 16]> {
        let in_service: Vec<[u8; 16]> = self
            .osd_nodes
            .read()
            .iter()
            .filter(|n| n.admin_state == objectio_common::OsdAdminState::In)
            .map(|n| n.node_id)
            .collect();
        let ok = |c: &[u8; 16]| in_service.contains(c) && !holders.contains(c);
        if let Some(c) = self.pick_migration_target(object_id, position, &[0u8; 16])
            && ok(&c)
        {
            return Some(c);
        }
        // Spread the fallback by stripe rather than always the same OSD.
        let mut candidates: Vec<[u8; 16]> = in_service.iter().copied().filter(|c| ok(c)).collect();
        candidates.sort_by_key(|c| {
            let mut h = [0u8; 16];
            for (i, b) in c.iter().enumerate() {
                h[i] = b ^ object_id[i] ^ (position as u8);
            }
            h
        });
        candidates.first().copied()
    }

    /// Invoke `SetOsdAdminState` from internal code (background tasks,
    /// not from an incoming RPC). Same Raft-routed path as the public
    /// gRPC handler; just skips the request-parsing / authz layer and
    /// always supplies `requested_by` so the audit log shows which
    /// subsystem triggered the change.
    ///
    /// # Errors
    /// Propagates any Raft `client_write` error (leader loss, timeout,
    /// shutdown).
    pub async fn internal_set_osd_admin_state(
        &self,
        node_id: [u8; 16],
        state: objectio_common::OsdAdminState,
        requested_by: String,
    ) -> anyhow::Result<()> {
        let raft = self
            .raft_handle()
            .ok_or_else(|| anyhow::anyhow!("raft handle unavailable"))?;
        raft.client_write(objectio_meta_store::MetaCommand::SetOsdAdminState {
            node_id,
            state,
            requested_by,
        })
        .await
        .map_err(|e| anyhow::anyhow!("client_write: {e}"))?;

        // Mirror into in-memory osd_nodes so the next get_listing_nodes
        // response reflects the new state immediately on this leader.
        let mut nodes = self.osd_nodes.write();
        if let Some(n) = nodes.iter_mut().find(|n| n.node_id == node_id) {
            n.admin_state = state;
        }
        // Rebuild placement topology to apply the change to CRUSH
        // without waiting for the next registration.
        let snapshot = nodes.clone();
        drop(nodes);
        for osd in &snapshot {
            self.refresh_topology_node(osd);
        }
        Ok(())
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

        // OSD nodes + topology rebuild
        match store.load_osd_nodes() {
            Ok(nodes) => {
                let count = nodes.len();
                // Dedupe by address on load: if the persistent store still
                // holds pre-cleanup duplicates from older binaries, keep
                // only the newest entry per address (last-wins). Also drop
                // known-bad placeholder addresses (e.g. http://0.0.0.0:9200)
                // that come from OSDs that never heartbeated a real
                // address — they pollute CRUSH and cause empty-address
                // write failures.
                let mut by_address: std::collections::HashMap<String, OsdNode> =
                    std::collections::HashMap::new();
                let mut bad_placeholder = 0usize;
                for (_hex_id, node) in nodes {
                    if node.address.is_empty()
                        || node.address.contains("://0.0.0.0")
                        || node.address.contains("://[::]")
                    {
                        bad_placeholder += 1;
                        continue;
                    }
                    by_address.insert(node.address.clone(), node);
                }
                let deduped: Vec<OsdNode> = by_address.into_values().collect();
                let evicted = count - deduped.len() - bad_placeholder;
                if evicted > 0 {
                    warn!(
                        "Deduped {} stale OSD entries on startup (same address, stale node_id)",
                        evicted
                    );
                }
                if bad_placeholder > 0 {
                    warn!(
                        "Dropped {} OSD entries with placeholder addresses on startup",
                        bad_placeholder
                    );
                }
                let mut osd_nodes = self.osd_nodes.write();
                osd_nodes.clear();
                for node in deduped {
                    osd_nodes.push(node);
                }
                info!("Loaded {} OSD nodes from store", osd_nodes.len());
            }
            Err(e) => error!("Failed to load OSD nodes: {}", e),
        }

        // Topology — rebuild from the post-dedup OSD list so any ghost
        // node_ids that lingered in the stored topology (from pre-cleanup
        // binaries) don't come back into CRUSH. The stored topology is
        // an optimization; the authoritative source is the live OSD list.
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
                            if entry.metadata_json.is_empty() {
                                warn!(
                                    "Iceberg table '{}' has no inline metadata \
                                     (created by older catalog version); \
                                     load-table will fail until it is dropped and re-created",
                                    key
                                );
                            }
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

    /// Create admin user if no users exist
    /// The admin's first key, once the admin exists with one.
    pub fn admin_credentials(&self, admin_name: &str) -> Option<(String, String)> {
        let admin = self
            .users
            .read()
            .values()
            .find(|u| u.display_name == admin_name && u.tenant.is_empty())
            .cloned()?;
        let keys = self.user_keys.read();
        let first = keys.get(&admin.user_id)?.first()?;
        self.access_keys
            .read()
            .get(first)
            .map(|k| (k.access_key_id.clone(), k.secret_access_key.clone()))
    }

    /// Create the bootstrap admin and its key through the ordinary,
    /// replicated user and key calls — on the leader, when there are no
    /// users yet (or the admin lost the race to get its key: a leader that
    /// died between the two).
    pub async fn create_admin(&self, admin_name: &str) -> Result<(), Status> {
        use objectio_proto::metadata::metadata_service_server::MetadataService as _;
        let existing = self
            .users
            .read()
            .values()
            .find(|u| u.display_name == admin_name && u.tenant.is_empty())
            .map(|u| u.user_id.clone());
        let user_id = match existing {
            Some(id) => id,
            None if self.users.read().is_empty() => self
                .create_user(Request::new(CreateUserRequest {
                    display_name: admin_name.to_string(),
                    email: String::new(),
                    tenant: String::new(),
                }))
                .await?
                .into_inner()
                .user
                .map(|u| u.user_id)
                .ok_or_else(|| Status::internal("created the admin, but got no user back"))?,
            // Users exist and none is the admin: an operator's choice.
            None => return Ok(()),
        };
        if self
            .user_keys
            .read()
            .get(&user_id)
            .is_none_or(Vec::is_empty)
        {
            self.create_access_key(Request::new(CreateAccessKeyRequest {
                user_id,
                ..Default::default()
            }))
            .await?;
        }
        Ok(())
    }

    pub fn ensure_admin(&self, admin_name: &str) -> Option<(String, String)> {
        let users = self.users.read();
        if !users.is_empty() {
            // Users exist, check if admin already has keys
            drop(users);
            let user = self
                .users
                .read()
                .values()
                .find(|u| u.display_name == admin_name)
                .cloned();
            if let Some(admin_user) = user {
                let keys = self.user_keys.read();
                if let Some(key_ids) = keys.get(&admin_user.user_id)
                    && let Some(first_key_id) = key_ids.first()
                    && let Some(key) = self.access_keys.read().get(first_key_id)
                {
                    return Some((key.access_key_id.clone(), key.secret_access_key.clone()));
                }
            }
            return None;
        }
        drop(users);

        // Create admin user
        let user_id = Uuid::new_v4().to_string();
        let now = Self::current_timestamp();
        let user = StoredUser {
            user_id: user_id.clone(),
            display_name: admin_name.to_string(),
            arn: format!("arn:objectio:iam::user/{}", admin_name),
            status: UserStatus::UserActive as i32,
            created_at: now,
            email: String::new(),
            tenant: String::new(), // system admin has no tenant
        };

        self.users.write().insert(user_id.clone(), user.clone());
        self.user_keys.write().insert(user_id.clone(), Vec::new());

        // Create access key
        let access_key_id = Self::generate_access_key_id();
        let secret_access_key = Self::generate_secret_access_key();

        let key = StoredAccessKey {
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
            user_id: user_id.clone(),
            status: KeyStatus::KeyActive as i32,
            created_at: now,
            tenant: String::new(),
            // The bootstrap admin key is deliberately unscoped.
            scope: String::new(),
            operation: 0,
        };

        self.access_keys
            .write()
            .insert(access_key_id.clone(), key.clone());
        self.user_keys
            .write()
            .entry(user_id)
            .or_default()
            .push(access_key_id.clone());

        // Persist admin user + key atomically
        if let Some(store) = &self.store {
            store.put_user_and_key(&user, &key);
        }

        info!(
            "Created admin user '{}' with access key {}",
            admin_name, access_key_id
        );

        Some((access_key_id, secret_access_key))
    }

    /// Generate AWS-style access key ID (20 chars, starts with AKIA)
    fn generate_access_key_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
        let suffix: String = (0..16)
            .map(|_| chars[rng.gen_range(0..chars.len())])
            .collect();
        format!("AKIA{}", suffix)
    }

    /// Generate AWS-style secret access key (40 chars, base64-like)
    fn generate_secret_access_key() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .chars()
            .collect();
        (0..40)
            .map(|_| chars[rng.gen_range(0..chars.len())])
            .collect()
    }

    /// Update CRUSH topology with a new OSD node
    /// Whether a topology update is backed by evidence the node is reachable
    /// *now*.
    ///
    /// An OSD that has just registered is: it opened a connection and said so.
    /// A record read from the store at startup, or re-read during a
    /// rebuild-everything pass, is not — it describes the cluster as it was
    /// when meta last wrote it down.
    ///
    /// The distinction existed nowhere, so status was derived from
    /// `admin_state` alone in every case. That is the exact defect the liveness
    /// prober was written to fix, still present on these paths: a node the
    /// prober had marked `Down` came back `Active` on the next restart or the
    /// next admin-state change, and placement handed it out again. On the live
    /// deployment that meant every restart served 500s for thirty seconds from
    /// an address that had been dead for days.
    fn update_topology_with_node(&self, osd_node: &OsdNode) {
        self.upsert_topology_node(osd_node, NodeEvidence::Observed);
    }

    /// As [`Self::update_topology_with_node`], for a node we have not heard
    /// from — loaded from the store, or swept up in a rebuild of every node.
    fn refresh_topology_node(&self, osd_node: &OsdNode) {
        self.upsert_topology_node(osd_node, NodeEvidence::FromStore);
    }

    fn upsert_topology_node(&self, osd_node: &OsdNode, evidence: NodeEvidence) {
        // Prefer the 5-level `topology` when present; fall back to the
        // legacy 3-tuple for OsdNodes persisted before zone/host existed.
        let (region, zone, dc, rack, host) = osd_node
            .topology
            .clone()
            .or_else(|| {
                osd_node
                    .failure_domain
                    .clone()
                    .map(|(r, dc, rack)| (r, String::new(), dc, rack, String::new()))
            })
            .unwrap_or_else(|| {
                (
                    "default".to_string(),
                    String::new(),
                    "dc1".to_string(),
                    "rack1".to_string(),
                    String::new(),
                )
            });

        let node_id = NodeId::from_bytes(osd_node.node_id);

        let disks: Vec<DiskInfo> = osd_node
            .disk_ids
            .iter()
            .map(|disk_id| {
                DiskInfo {
                    id: objectio_common::DiskId::from_bytes(*disk_id),
                    path: String::new(),
                    total_capacity: 1_000_000_000_000, // 1TB default
                    used_capacity: 0,
                    status: objectio_common::DiskStatus::Healthy,
                    weight: 1.0,
                }
            })
            .collect();

        // Merge operator intent (admin_state) with observed status. Draining
        // and Out are intent and win outright, so placement's `active_nodes()`
        // filter skips them either way. `In` means the operator does not
        // object — which is not the same as the node being there.
        let known = self.topology.read().get_node(node_id).map(|n| n.status);
        let status = topology_status(osd_node.admin_state, evidence, known);

        let node_info = NodeInfo {
            id: node_id,
            name: hex::encode(&osd_node.node_id[..4]),
            address: osd_node
                .address
                .parse()
                .unwrap_or_else(|_| "0.0.0.0:9200".parse().unwrap()),
            failure_domain: FailureDomainInfo::new_full(&region, &zone, &dc, &rack, &host),
            status,
            disks,
            weight: 1.0,
            last_heartbeat: Self::current_timestamp(),
        };

        // Update topology and rebuild CRUSH
        {
            let mut topology = self.topology.write();
            topology.upsert_node(node_info);
        }

        // Rebuild CRUSH with updated topology
        {
            let topology = self.topology.read().clone();
            let mut crush = self.crush.write();
            crush.update_topology(topology);
        }

        debug!(
            "Updated CRUSH topology with node {}",
            hex::encode(osd_node.node_id)
        );
    }

    /// Encode namespace levels into a store key, scoped by warehouse.
    /// Format: "warehouse\x01ns1\x00ns2" or "ns1\x00ns2" (if warehouse is empty)
    fn iceberg_ns_key_wh(warehouse: &str, levels: &[String]) -> String {
        let ns = levels.join("\x00");
        if warehouse.is_empty() {
            ns
        } else {
            format!("{warehouse}\x01{ns}")
        }
    }

    /// Encode namespace + table name into a store key, scoped by warehouse.
    fn iceberg_table_key_wh(warehouse: &str, ns_levels: &[String], table_name: &str) -> String {
        let ns = Self::iceberg_ns_key_wh(warehouse, ns_levels);
        format!("{ns}\x00{table_name}")
    }

    /// Warehouse prefix for scanning all namespaces in a warehouse.
    fn iceberg_warehouse_prefix(warehouse: &str) -> String {
        if warehouse.is_empty() {
            String::new()
        } else {
            format!("{warehouse}\x01")
        }
    }

    /// Legacy helpers (no warehouse scope) — kept for backward compat
    fn iceberg_ns_key(levels: &[String]) -> String {
        levels.join("\x00")
    }

    fn iceberg_table_key(ns_levels: &[String], table_name: &str) -> String {
        let ns = Self::iceberg_ns_key(ns_levels);
        format!("{ns}\x00{table_name}")
    }

    /// Generate object key for internal storage
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Resolve a Unity function by its three-part dotted name
    /// (`catalog.schema.function`). Used to validate row-filter and
    /// column-mask bindings — we want to reject malformed bindings at
    /// the configuration boundary, not at query time.
    #[allow(clippy::result_large_err)]
    fn lookup_unity_function(
        &self,
        full_name: &str,
    ) -> Result<objectio_proto::metadata::UnityFunction, Status> {
        let parts: Vec<&str> = full_name.split('.').collect();
        if parts.len() != 3 {
            return Err(Status::invalid_argument(format!(
                "function name '{full_name}' must be 'catalog.schema.function'"
            )));
        }
        let key = format!("{}\x00{}\x00{}", parts[0], parts[1], parts[2]);
        self.unity_functions
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("function '{full_name}' not found")))
    }

    /// Generate a short stable id for a new KMS key: `kms-<first 12 hex of UUID>`.
    fn generate_kms_key_id() -> String {
        let uuid = Uuid::new_v4().simple().to_string();
        format!("kms-{}", &uuid[..12])
    }

    /// Legacy placement algorithm (fallback when no CRUSH topology)
    async fn get_placement_legacy(
        &self,
        req: &GetPlacementRequest,
    ) -> Result<Response<GetPlacementResponse>, Status> {
        let nodes = self.osd_nodes.read();

        // Determine number of shards and EC type based on config
        let (total_shards, ec_type, replication_count) = match &self.default_ec {
            EcConfig::Mds { k, m } => ((*k + *m) as usize, ErasureType::ErasureMds, 0u32),
            EcConfig::Lrc { k, l, g } => ((*k + *l + *g) as usize, ErasureType::ErasureLrc, 0u32),
            EcConfig::Replication { count } => (
                *count as usize,
                ErasureType::ErasureReplication,
                *count as u32,
            ),
        };

        if nodes.is_empty() {
            return Err(Status::unavailable("no storage nodes available"));
        }

        let mut all_disks = eligible_disks(&nodes);

        if all_disks.is_empty() {
            return Err(Status::unavailable(
                "no storage nodes are accepting writes (all are draining or out)",
            ));
        }

        // Use object key hash for deterministic placement
        let hash_seed = {
            let key_bytes = format!("{}/{}", req.bucket, req.key);
            key_bytes
                .bytes()
                .fold(0u64, |acc, b| acc.wrapping_add(b as u64))
        };

        // Rotate the disk list based on hash for distribution
        if !all_disks.is_empty() {
            let rotation = (hash_seed as usize) % all_disks.len();
            all_disks.rotate_left(rotation);
        }

        // Select disks for each shard position, spreading across nodes
        let mut placements: Vec<NodePlacement> = Vec::with_capacity(total_shards);
        let mut used_nodes: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();

        // First pass: try to use different nodes for each shard
        for pos in 0..total_shards {
            if placements.len() >= total_shards {
                break;
            }

            let disk_opt = all_disks
                .iter()
                .find(|(node, _)| !used_nodes.contains(&node.node_id));

            if let Some((node, disk_id)) = disk_opt {
                let pos_u32 = pos as u32;
                placements.push(NodePlacement {
                    position: pos_u32,
                    node_id: node.node_id.to_vec(),
                    node_address: node.address.clone(),
                    te_segment: node.te_segment.clone(),
                    disk_id: disk_id.to_vec(),
                    shard_type: if pos_u32 < self.default_ec_k {
                        ShardType::ShardData.into()
                    } else {
                        ShardType::ShardGlobalParity.into()
                    },
                    local_group: 0,
                });
                used_nodes.insert(node.node_id);
            }
        }

        // Second pass: reuse nodes with different disks if needed
        if placements.len() < total_shards {
            for (node, disk_id) in all_disks.iter() {
                if placements.len() >= total_shards {
                    break;
                }
                let disk_used = placements.iter().any(|p| p.disk_id == disk_id.to_vec());
                if !disk_used {
                    let pos = placements.len() as u32;
                    placements.push(NodePlacement {
                        position: pos,
                        node_id: node.node_id.to_vec(),
                        node_address: node.address.clone(),
                        te_segment: node.te_segment.clone(),
                        disk_id: disk_id.to_vec(),
                        shard_type: if pos < self.default_ec_k {
                            ShardType::ShardData.into()
                        } else {
                            ShardType::ShardGlobalParity.into()
                        },
                        local_group: 0,
                    });
                }
            }
        }

        // Third pass: allow disk reuse for single disk mode
        while placements.len() < total_shards {
            let idx = placements.len() % all_disks.len().max(1);
            if let Some((node, disk_id)) = all_disks.get(idx) {
                let pos = placements.len() as u32;
                placements.push(NodePlacement {
                    position: pos,
                    node_id: node.node_id.to_vec(),
                    node_address: node.address.clone(),
                    te_segment: node.te_segment.clone(),
                    disk_id: disk_id.to_vec(),
                    shard_type: if pos < self.default_ec_k {
                        ShardType::ShardData.into()
                    } else {
                        ShardType::ShardGlobalParity.into()
                    },
                    local_group: 0,
                });
            } else {
                break;
            }
        }

        debug!(
            "Legacy placement for {}/{}: {} shards across {} nodes",
            req.bucket,
            req.key,
            placements.len(),
            used_nodes.len()
        );

        Ok(Response::new(self.with_dedup(
            &req.bucket,
            GetPlacementResponse {
                storage_class: "STANDARD".to_string(),
                ec_k: self.default_ec_k,
                ec_m: self.default_ec_m,
                nodes: placements,
                ec_type: ec_type.into(),
                ec_local_parity: 0,
                ec_global_parity: self.default_ec_m,
                local_group_size: 0,
                replication_count,
                // Legacy path: no PG, pool blank. Phase 3 fills these.
                pg_id: 0,
                pg_version: 0,
                pool: String::new(),
                dedup_mode: 0,
                dedup_domain: String::new(),
            },
        )))
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

    fn role(&self, name: &str) -> Option<RoleObject> {
        let bytes = self.store.as_ref()?.read_named(ROLES_TABLE, name)?;
        RoleObject::decode(bytes.as_slice()).ok()
    }

    /// The OSDs `bucket/key`'s ObjectMeta was written to, by position, if
    /// it has been written.
    fn object_home(&self, bucket: &str, key: &str) -> Option<ObjectHome> {
        let bytes = self
            .store
            .as_ref()?
            .read_object_home(&format!("{bucket}/{key}"))?;
        ObjectHome::decode(bytes.as_slice())
            .inspect_err(|e| warn!("decode ObjectHome({bucket}/{key}) failed: {e}"))
            .ok()
    }

    /// Put `nodes` (a computed placement) at the key's home: each position
    /// on the OSD the key's ObjectMeta was written to, so it is read where
    /// it is, whatever joined or left the cluster since. A home OSD that
    /// is no longer active gives its position to the first computed OSD
    /// not already in the set, as the computed placement would have.
    fn place_at_home(&self, nodes: &mut [NodePlacement], home: &ObjectHome) {
        if home.osd_ids.len() != nodes.len() {
            // The pool's protection changed since, so positions no longer
            // line up.
            warn!(
                "object home has {} OSDs, placement {}: using the computed placement",
                home.osd_ids.len(),
                nodes.len()
            );
            return;
        }
        let topology = self.topology.read();
        let osd_nodes = self.osd_nodes.read();
        let usable: Vec<Option<&OsdNode>> = home
            .osd_ids
            .iter()
            .map(|id| {
                let id = <[u8; 16]>::try_from(id.as_slice()).ok()?;
                topology
                    .active_nodes()
                    .any(|n| *n.id.as_bytes() == id)
                    .then(|| osd_nodes.iter().find(|n| n.node_id == id))
                    .flatten()
            })
            .collect();
        let mut spares: std::collections::VecDeque<NodePlacement> = nodes
            .iter()
            .filter(|n| {
                !usable
                    .iter()
                    .flatten()
                    .any(|h| h.node_id.as_slice() == n.node_id.as_slice())
            })
            .cloned()
            .collect();
        for (slot, home_node) in nodes.iter_mut().zip(usable) {
            let (node_id, node_address, disk_id, te_segment) = match home_node {
                Some(n) => (
                    n.node_id.to_vec(),
                    n.address.clone(),
                    n.disk_ids
                        .first()
                        .map_or_else(|| vec![0u8; 16], |d| d.to_vec()),
                    n.te_segment.clone(),
                ),
                None => match spares.pop_front() {
                    Some(s) => (s.node_id, s.node_address, s.disk_id, s.te_segment),
                    None => continue,
                },
            };
            slot.node_id = node_id;
            slot.node_address = node_address;
            slot.disk_id = disk_id;
            slot.te_segment = te_segment;
        }
    }

    /// Placement computed from the topology (or the bucket's pool's
    /// placement groups), whatever the key's home.
    async fn computed_placement(
        &self,
        request: Request<GetPlacementRequest>,
    ) -> Result<Response<GetPlacementResponse>, Status> {
        let req = request.into_inner();

        // Check if we have any nodes in the topology
        let active_node_count = {
            let topology = self.topology.read();
            topology.active_nodes().count()
        };

        if active_node_count == 0 {
            // Fall back to legacy placement if no CRUSH topology
            return self.get_placement_legacy(&req).await;
        }

        // Create object ID from bucket/key for deterministic placement
        let object_id = {
            let key_str = format!("{}/{}", req.bucket, req.key);
            let hash = xxhash_rust::xxh64::xxh64(key_str.as_bytes(), 0);
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&hash.to_le_bytes());
            bytes[8..16].copy_from_slice(&hash.to_be_bytes());
            objectio_common::ObjectId::from_uuid(Uuid::from_bytes(bytes))
        };

        // Resolve pool for this bucket — use pool-specific EC config if available
        let pool_name = {
            let buckets = self.buckets.read();
            buckets
                .get(&req.bucket)
                .map(|b| b.pool.clone())
                .unwrap_or_default()
        };
        let (pool_ec, pool_pg_count) = if !pool_name.is_empty() {
            self.pools
                .read()
                .get(&pool_name)
                .map(|p| {
                    (
                        Some((
                            p.ec_type(),
                            p.ec_k,
                            p.ec_m,
                            p.ec_local_parity,
                            p.ec_global_parity,
                            p.replication_count,
                        )),
                        p.pg_count,
                    )
                })
                .unwrap_or((None, 0))
        } else {
            (None, 0)
        };

        // Select placement template based on pool EC config or global default
        let (
            template,
            ec_type,
            ec_k,
            ec_local_parity,
            ec_global_parity,
            local_group_size,
            replication_count,
        ) = if let Some((p_ec_type, p_k, p_m, p_lp, p_gp, p_rep)) = pool_ec {
            match p_ec_type {
                ErasureType::ErasureLrc => (
                    PlacementTemplate::lrc(p_k as u8, p_lp as u8, p_gp as u8),
                    ErasureType::ErasureLrc,
                    p_k,
                    p_lp,
                    p_gp,
                    if p_lp > 0 { p_k / p_lp } else { 0 },
                    0u32,
                ),
                ErasureType::ErasureReplication => (
                    PlacementTemplate::mds(p_rep as u8, 0),
                    ErasureType::ErasureReplication,
                    1u32,
                    0u32,
                    0u32,
                    0u32,
                    p_rep,
                ),
                _ => (
                    PlacementTemplate::mds(p_k as u8, p_m as u8),
                    ErasureType::ErasureMds,
                    p_k,
                    0u32,
                    p_m,
                    0u32,
                    0u32,
                ),
            }
        } else {
            // Fall back to global default EC config
            match &self.default_ec {
                EcConfig::Mds { k, m } => (
                    PlacementTemplate::mds(*k, *m),
                    ErasureType::ErasureMds,
                    *k as u32,
                    0u32,
                    *m as u32,
                    0u32,
                    0u32,
                ),
                EcConfig::Lrc { k, l, g } => (
                    PlacementTemplate::lrc(*k, *l, *g),
                    ErasureType::ErasureLrc,
                    *k as u32,
                    *l as u32,
                    *g as u32,
                    (*k / *l) as u32,
                    0u32,
                ),
                EcConfig::Replication { count } => (
                    PlacementTemplate::mds(*count, 0),
                    ErasureType::ErasureReplication,
                    1u32,
                    0u32,
                    0u32,
                    0u32,
                    *count as u32,
                ),
            }
        };

        // Placement-group fast path. When the bucket's pool has a
        // non-zero pg_count we route object_id -> pg_id via jump
        // consistent hash and read the PG's committed osd_ids in one
        // in-memory lookup. Falls through to CRUSH2 if the PG row is
        // missing (pre-allocation still in progress on a fresh pool)
        // or if the PG's shard count disagrees with the current EC
        // config (topology mid-reconfigure).
        if pool_pg_count > 0 && !pool_name.is_empty() {
            let key_str = format!("{}/{}", req.bucket, req.key);
            let key_hash = xxhash_rust::xxh64::xxh64(key_str.as_bytes(), 0);
            let pg_id =
                objectio_placement::jump_consistent_hash(key_hash, pool_pg_count as i32) as u32;
            if let Some(pg) = self.placement_group(&pool_name, pg_id) {
                let expected_shards = match ec_type {
                    ErasureType::ErasureMds => ec_k as usize + ec_global_parity as usize,
                    ErasureType::ErasureLrc => {
                        ec_k as usize + ec_local_parity as usize + ec_global_parity as usize
                    }
                    ErasureType::ErasureReplication => replication_count as usize,
                };
                if pg.osd_ids.len() == expected_shards && expected_shards > 0 {
                    let nodes_snap = self.osd_nodes.read();
                    let placements: Vec<NodePlacement> = pg
                        .osd_ids
                        .iter()
                        .enumerate()
                        .map(|(pos, osd_bytes)| {
                            let node = nodes_snap
                                .iter()
                                .find(|n| n.node_id.as_slice() == osd_bytes.as_slice());
                            let (node_address, disk_id) = match node {
                                Some(n) => (
                                    n.address.clone(),
                                    n.disk_ids
                                        .first()
                                        .map(|d| d.to_vec())
                                        .unwrap_or_else(|| vec![0u8; 16]),
                                ),
                                None => (String::new(), vec![0u8; 16]),
                            };
                            let te_segment = node.map(|n| n.te_segment.clone()).unwrap_or_default();
                            let shard_type = pg_position_shard_type(
                                ec_type,
                                pos,
                                ec_k as usize,
                                ec_local_parity as usize,
                                local_group_size as usize,
                            );
                            let local_group = pg_position_local_group(
                                ec_type,
                                pos,
                                ec_k as usize,
                                ec_local_parity as usize,
                                local_group_size as usize,
                            );
                            NodePlacement {
                                position: pos as u32,
                                node_id: osd_bytes.clone(),
                                node_address,
                                disk_id,
                                shard_type: shard_type.into(),
                                local_group,
                                te_segment,
                            }
                        })
                        .collect();
                    debug!(
                        "PG placement for {}/{}: pool={}, pg_id={}, {} shards",
                        req.bucket,
                        req.key,
                        pool_name,
                        pg_id,
                        placements.len()
                    );
                    return Ok(Response::new(self.with_dedup(
                        &req.bucket,
                        GetPlacementResponse {
                            storage_class: req.storage_class.clone(),
                            ec_k,
                            ec_m: ec_local_parity + ec_global_parity,
                            nodes: placements,
                            ec_type: ec_type.into(),
                            ec_local_parity,
                            ec_global_parity,
                            local_group_size,
                            replication_count,
                            pg_id,
                            pg_version: pg.version,
                            pool: pool_name.clone(),
                            dedup_mode: 0,
                            dedup_domain: String::new(),
                        },
                    )));
                }
                warn!(
                    "PG {}/{}: osd_ids={} doesn't match expected shards={}; falling back to CRUSH",
                    pool_name,
                    pg_id,
                    pg.osd_ids.len(),
                    expected_shards
                );
            }
        }

        // Use CRUSH 2.0 for placement
        let crush = self.crush.read();
        let hrw_placements = crush.select_placement(&object_id, &template);
        drop(crush);

        // Convert HRW placements to NodePlacement responses
        let nodes = self.osd_nodes.read();
        let placements: Vec<NodePlacement> = hrw_placements
            .iter()
            .map(|hrw| {
                // Find the OSD node by NodeId
                let node = nodes
                    .iter()
                    .find(|n| NodeId::from_bytes(n.node_id) == hrw.node_id);

                let (node_address, disk_id) = match node {
                    Some(n) => {
                        let disk = n
                            .disk_ids
                            .first()
                            .map(|d| d.to_vec())
                            .unwrap_or_else(|| vec![0u8; 16]);
                        (n.address.clone(), disk)
                    }
                    None => {
                        // Node not found in legacy list, use placeholder
                        warn!("Node {} not found in OSD list", hrw.node_id);
                        (String::new(), hrw.node_id.as_bytes().to_vec())
                    }
                };

                let te_segment = node.map(|n| n.te_segment.clone()).unwrap_or_default();

                let shard_type = match hrw.role {
                    ShardRole::Data => ShardType::ShardData.into(),
                    ShardRole::LocalParity => ShardType::ShardLocalParity.into(),
                    ShardRole::GlobalParity => ShardType::ShardGlobalParity.into(),
                };

                NodePlacement {
                    position: hrw.position as u32,
                    node_id: hrw.node_id.as_bytes().to_vec(),
                    node_address,
                    disk_id,
                    shard_type,
                    local_group: hrw.local_group.unwrap_or(0) as u32,
                    te_segment,
                }
            })
            .collect();

        debug!(
            "CRUSH 2.0 placement for {}/{}: {} shards using {:?}",
            req.bucket,
            req.key,
            placements.len(),
            ec_type
        );

        Ok(Response::new(self.with_dedup(
            &req.bucket,
            GetPlacementResponse {
                storage_class: req.storage_class.clone(),
                ec_k,
                ec_m: ec_local_parity + ec_global_parity,
                nodes: placements,
                ec_type: ec_type.into(),
                ec_local_parity,
                ec_global_parity,
                local_group_size,
                replication_count,
                // Filled by Phase 3 once the PG lookup replaces
                // per-object CRUSH. Leaving zeros keeps pre-migration
                // clients safe (gateway treats 0 as legacy).
                pg_id: 0,
                pg_version: 0,
                pool: String::new(),
                dedup_mode: 0,
                dedup_domain: String::new(),
            },
        )))
    }
}

#[tonic::async_trait]
impl MetadataService for MetaService {
    async fn get_metrics(
        &self,
        _request: Request<objectio_proto::metadata::GetMetricsRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetMetricsResponse>, Status> {
        Ok(Response::new(
            objectio_proto::metadata::GetMetricsResponse {
                text: self.metrics_renderer.get().map(|f| f()).unwrap_or_default(),
                process_instance: objectio_common::process_metrics::instance_id().to_string(),
            },
        ))
    }

    async fn create_bucket(
        &self,
        request: Request<CreateBucketRequest>,
    ) -> Result<Response<CreateBucketResponse>, Status> {
        let req = request.into_inner();

        if req.name.is_empty() {
            return Err(Status::invalid_argument("bucket name is required"));
        }

        // Check if bucket already exists
        if self.buckets.read().contains_key(&req.name) {
            return Err(Status::already_exists("bucket already exists"));
        }

        // Validate tenant exists if specified
        let tenant = req.tenant.clone();
        if !tenant.is_empty() && !self.tenants.read().contains_key(&tenant) {
            return Err(Status::not_found(format!("tenant '{}' not found", tenant)));
        }

        // Enforce tenant bucket quota
        if !tenant.is_empty()
            && let Some(tc) = self.tenants.read().get(&tenant)
            && tc.quota_buckets > 0
        {
            let count = self
                .buckets
                .read()
                .values()
                .filter(|b| b.tenant == tenant)
                .count() as u64;
            if count >= tc.quota_buckets {
                return Err(Status::resource_exhausted(format!(
                    "tenant '{}' bucket quota exceeded ({}/{})",
                    tenant, count, tc.quota_buckets
                )));
            }
        }

        let pool = self.resolve_bucket_pool(&tenant, &req.pool)?;

        let bucket = BucketMeta {
            dedup: None,
            name: req.name.clone(),
            owner: req.owner,
            created_at: Self::current_timestamp(),
            storage_class: if req.storage_class.is_empty() {
                "STANDARD".to_string()
            } else {
                req.storage_class
            },
            versioning: VersioningState::VersioningDisabled.into(),
            pool,
            tenant,
            quota_bytes: 0,
            quota_objects: 0,
            object_lock: None,
        };

        // Replicate through Raft so followers see the new bucket at the
        // same log position. Single-op MultiCas with expected=None enforces
        // "must-not-exist" at the state machine — if a concurrent proposal
        // on another pod raced us, the CAS fails and we surface it as
        // AlreadyExists (same error the in-memory precheck above returns).
        let bucket_bytes = bucket.encode_to_vec();
        // Configuration a deleted bucket of this name left behind (from
        // before deletes removed it) is cleared, and the initial settings
        // written, all in the bucket's own commit.
        let mut config_ops: Vec<(
            objectio_meta_store::CasTable,
            String,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        )> = Vec::new();
        let stale = self.bucket_config_rows(&req.name);
        for (name, value) in &req.settings {
            if name.is_empty() || name.contains('/') {
                return Err(Status::invalid_argument("invalid setting name"));
            }
            let key = bucket_setting_key(&req.name, name);
            let current = stale
                .iter()
                .find(|(_, k, _)| *k == key)
                .map(|(_, _, v)| v.clone());
            config_ops.push((
                objectio_meta_store::CasTable::Named(BUCKET_SETTINGS_TABLE.into()),
                key,
                current,
                Some(value.clone()),
            ));
        }
        for (table, key, value) in stale {
            if !config_ops.iter().any(|(_, k, _, _)| *k == key) {
                config_ops.push((table, key, Some(value), None));
            }
        }
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::Buckets,
                key: req.name.clone(),
                expected: None,
                new_value: Some(bucket_bytes),
            }];
            ops.extend(
                config_ops
                    .iter()
                    .map(|(table, key, expected, new_value)| CasOp {
                        table: table.clone(),
                        key: key.clone(),
                        expected: expected.clone(),
                        new_value: new_value.clone(),
                    }),
            );
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "create-bucket".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("bucket already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_bucket: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&req.name, &bucket);
            for (table, key, _, new_value) in &config_ops {
                store.write_named(
                    objectio_meta_store::cas_table_name(table),
                    key,
                    new_value.as_deref(),
                );
            }
        }

        self.forget_bucket_config(&req.name);
        self.buckets
            .write()
            .insert(req.name.clone(), bucket.clone());

        info!("Created bucket: {}", req.name);

        Ok(Response::new(CreateBucketResponse {
            bucket: Some(bucket),
        }))
    }

    async fn delete_bucket(
        &self,
        request: Request<DeleteBucketRequest>,
    ) -> Result<Response<DeleteBucketResponse>, Status> {
        let req = request.into_inner();

        // Read current bucket bytes so the CAS can detect a concurrent
        // mutation between now and commit.
        let current = {
            let b = self.buckets.read();
            b.get(&req.name)
                .cloned()
                .ok_or_else(|| Status::not_found("bucket not found"))?
        };
        let expected_bytes = current.encode_to_vec();

        // Refuse while it holds objects: deleting it orphaned them, their
        // data still on disk with no bucket to reach it through. The
        // listing index is the record of current objects; the gateway
        // checks the OSDs for noncurrent versions before calling this.
        if let Some(store) = &self.store {
            let (entries, _, _) = store
                .list_object_listings(&req.name, "", "", 1)
                .map_err(|e| Status::unavailable(format!("cannot read the listing: {e}")))?;
            if !entries.is_empty() {
                return Err(Status::failed_precondition("bucket is not empty"));
            }
        }

        // Everything configured on the bucket goes with it, in the same
        // commit: a bucket created later under the same name — by anyone —
        // must not inherit this one's policy, lock, lifecycle or settings.
        let config_rows = self.bucket_config_rows(&req.name);

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::Buckets,
                key: req.name.clone(),
                expected: Some(expected_bytes),
                new_value: None, // delete
            }];
            ops.extend(config_rows.iter().map(|(table, key, value)| CasOp {
                table: table.clone(),
                key: key.clone(),
                expected: Some(value.clone()),
                new_value: None,
            }));
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delete-bucket".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket changed since read; retry delete"));
                    }
                    other => {
                        error!("unexpected raft response for delete_bucket: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_bucket(&req.name);
            for (table, key, _) in &config_rows {
                store.write_named(objectio_meta_store::cas_table_name(table), key, None);
            }
        }

        self.buckets.write().remove(&req.name);
        self.forget_bucket_config(&req.name);

        info!("Deleted bucket: {}", req.name);

        Ok(Response::new(DeleteBucketResponse { success: true }))
    }

    async fn get_bucket(
        &self,
        request: Request<GetBucketRequest>,
    ) -> Result<Response<GetBucketResponse>, Status> {
        let req = request.into_inner();

        let bucket = self
            .buckets
            .read()
            .get(&req.name)
            .cloned()
            .ok_or_else(|| Status::not_found("bucket not found"))?;

        Ok(Response::new(GetBucketResponse {
            bucket: Some(bucket),
        }))
    }

    async fn list_buckets(
        &self,
        request: Request<ListBucketsRequest>,
    ) -> Result<Response<ListBucketsResponse>, Status> {
        let req = request.into_inner();

        let buckets: Vec<BucketMeta> = self
            .buckets
            .read()
            .values()
            .filter(|b| req.owner.is_empty() || b.owner == req.owner)
            .filter(|b| req.tenant.is_empty() || b.tenant == req.tenant)
            .cloned()
            .collect();

        Ok(Response::new(ListBucketsResponse { buckets }))
    }

    /// DEPRECATED: Object metadata is now stored on primary OSD
    /// This RPC is kept for backward compatibility but does nothing
    /// Register a PUT in the Meta-backed OBJECT_LISTINGS index. Every
    /// S3 PUT that succeeds at the data layer calls this to make the
    /// object visible via ListObjects. Routed through Raft MultiCas so
    /// followers see the commit at the same log position.
    async fn create_object(
        &self,
        request: Request<CreateObjectRequest>,
    ) -> Result<Response<CreateObjectResponse>, Status> {
        let req = request.into_inner();
        if req.bucket.is_empty() || req.key.is_empty() {
            return Err(Status::invalid_argument("bucket and key required"));
        }
        // Never list an object into a bucket that isn't there (deleted
        // meanwhile, or never created).
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found(format!(
                "bucket '{}' not found",
                req.bucket
            )));
        }

        // Build the listing entry. primary_osd_id is optional (the
        // first shard in the first stripe, as a routing hint).
        let primary_osd_id = req
            .stripes
            .first()
            .and_then(|s| s.shards.first())
            .map(|s| s.node_id.clone())
            .unwrap_or_default();
        let now = Self::current_timestamp();
        let entry = ObjectListingEntry {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            size: req.size,
            etag: req.etag.clone(),
            content_type: req.content_type.clone(),
            created_at: now,
            modified_at: now,
            version_id: String::new(),
            is_delete_marker: false,
            storage_class: "STANDARD".into(),
            user_metadata: req.user_metadata.clone(),
            primary_osd_id,
            // Gateway carried these from its GetPlacement call. With
            // pg_id set, ListObjects + GET can resolve osd_ids via a
            // single PG lookup; without, we fall back to the legacy
            // per-object CRUSH path.
            pg_id: req.pg_id,
            pool: req.pool.clone(),
        };
        let listing_key = format!("{}\0{}\0", req.bucket, req.key);
        let new_bytes = entry.encode_to_vec();

        // Idempotent overwrite: PUT on an existing key replaces. Read
        // current (if any) so the MultiCas doesn't spuriously fail.
        let expected_bytes = self
            .store
            .as_ref()
            .and_then(|s| s.read_object_listing(&listing_key));

        // A conditional write is decided here, against the entry the
        // MultiCas below expects: a write that changes it meanwhile makes
        // the MultiCas conflict, so two conditional writers can't both win.
        if !req.if_match.is_empty() || !req.if_none_match.is_empty() {
            let current_etag = expected_bytes
                .as_deref()
                .and_then(|b| ObjectListingEntry::decode(b).ok())
                .map(|e| e.etag.trim_matches('"').to_string());
            let matches = |want: &str| {
                current_etag
                    .as_deref()
                    .is_some_and(|e| want == "*" || e == want.trim_matches('"'))
            };
            if !req.if_match.is_empty() && current_etag.is_none() {
                return Err(Status::failed_precondition("NoSuchKey"));
            }
            if (!req.if_match.is_empty() && !matches(&req.if_match))
                || (!req.if_none_match.is_empty() && matches(&req.if_none_match))
            {
                return Err(Status::failed_precondition("PreconditionFailed"));
            }
        }

        // The key's home, recorded with its listing when it moved (or is
        // new): where the gateway just wrote its ObjectMeta.
        let home_key = format!("{}/{}", req.bucket, req.key);
        let current_home = self
            .store
            .as_ref()
            .and_then(|s| s.read_object_home(&home_key));
        let new_home = (!req.home_osd_ids.is_empty())
            .then(|| {
                ObjectHome {
                    osd_ids: req.home_osd_ids.clone(),
                }
                .encode_to_vec()
            })
            .filter(|h| current_home.as_ref() != Some(h));

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::ObjectListings,
                key: listing_key.clone(),
                expected: expected_bytes,
                new_value: Some(new_bytes),
            }];
            if let Some(home) = new_home {
                ops.push(CasOp {
                    table: CasTable::Named("object_homes".into()),
                    key: home_key,
                    expected: current_home,
                    new_value: Some(home),
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "create-object".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. }
                        if !req.if_match.is_empty() || !req.if_none_match.is_empty() =>
                    {
                        // Another write to the key won: the condition was
                        // decided on a state that is gone.
                        return Err(Status::failed_precondition("PreconditionFailed"));
                    }
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted(
                            "listing changed during PUT; client should retry",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for create_object: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_object_listing(&listing_key, &entry.encode_to_vec());
            if let Some(home) = new_home {
                store.put_object_home(&home_key, &home);
            }
        }

        Ok(Response::new(CreateObjectResponse { object: None }))
    }

    async fn delete_object(
        &self,
        request: Request<DeleteObjectRequest>,
    ) -> Result<Response<DeleteObjectResponse>, Status> {
        let req = request.into_inner();
        let listing_key = format!("{}\0{}\0{}", req.bucket, req.key, req.version_id);
        let expected_bytes = self
            .store
            .as_ref()
            .and_then(|s| s.read_object_listing(&listing_key));
        let home_key = format!("{}/{}", req.bucket, req.key);
        let home = if req.forget_home {
            self.store
                .as_ref()
                .and_then(|s| s.read_object_home(&home_key))
        } else {
            None
        };
        if expected_bytes.is_none() && home.is_none() {
            // Nothing to remove — return success idempotently.
            return Ok(Response::new(DeleteObjectResponse {
                success: true,
                version_id: req.version_id,
            }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = Vec::with_capacity(2);
            if expected_bytes.is_some() {
                ops.push(CasOp {
                    table: CasTable::ObjectListings,
                    key: listing_key,
                    expected: expected_bytes,
                    new_value: None,
                });
            }
            if home.is_some() {
                ops.push(CasOp {
                    table: CasTable::Named("object_homes".into()),
                    key: home_key,
                    expected: home,
                    new_value: None,
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delete-object".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("listing changed during DELETE; retry"));
                    }
                    other => {
                        error!("unexpected raft response for delete_object: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            // Legacy non-raft path: direct redb delete.
            store
                .delete_object_listing(&format!("{}\0{}\0{}", req.bucket, req.key, req.version_id));
            if home.is_some() {
                store.delete_object_home(&home_key);
            }
        }

        Ok(Response::new(DeleteObjectResponse {
            success: true,
            version_id: req.version_id,
        }))
    }

    /// Single-object read — not in the common path (gateway goes to
    /// OSDs for ObjectMeta), kept so admin tools can look up metadata
    /// by (bucket, key).
    async fn get_object(
        &self,
        _request: Request<GetObjectRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        Err(Status::unimplemented(
            "Object metadata lives on OSDs — use GetObjectMeta. ObjectListings only stores the listing hint.",
        ))
    }

    /// Linearizable listing via a B-tree scan of OBJECT_LISTINGS in
    /// Meta's redb. Replaces the old scatter-gather-then-merge path
    /// on the gateway. Continuation token is the bucket-relative
    /// form of the last key returned.
    async fn list_objects(
        &self,
        request: Request<ListObjectsRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let req = request.into_inner();
        if req.bucket.is_empty() {
            return Err(Status::invalid_argument("bucket required"));
        }
        let max_keys = if req.max_keys == 0 {
            1000
        } else {
            req.max_keys.min(1000) as usize
        };
        let start_after = if !req.continuation_token.is_empty() {
            req.continuation_token.clone()
        } else {
            req.start_after.clone()
        };

        let Some(store) = &self.store else {
            // No persistent store = no Raft backend — return empty.
            return Ok(Response::new(ListObjectsResponse::default()));
        };
        let page = page_listing(
            |after, n| {
                let (rows, more, _) = store
                    .list_object_listings(&req.bucket, &req.prefix, after, n)
                    .map_err(|e| e.to_string())?;
                let entries = rows
                    .into_iter()
                    .filter_map(|(_k, bytes)| {
                        <ObjectListingEntry as prost::Message>::decode(bytes.as_slice())
                            .inspect_err(|err| warn!("decode ObjectListingEntry failed: {err}"))
                            .ok()
                    })
                    .collect();
                Ok::<_, String>((entries, more))
            },
            &req.prefix,
            &req.delimiter,
            &start_after,
            max_keys,
        )
        .map_err(|e| {
            error!("list_object_listings failed: {e}");
            Status::internal(format!("list failed: {e}"))
        })?;
        let (entries, common_prefixes, is_truncated, next_token) = (
            page.entries,
            page.common_prefixes,
            page.is_truncated,
            page.next_token,
        );

        let key_count = entries.len() as u32 + common_prefixes.len() as u32;
        Ok(Response::new(ListObjectsResponse {
            common_prefixes,
            next_continuation_token: next_token,
            is_truncated,
            key_count,
            entries,
        }))
    }

    async fn get_placement(
        &self,
        request: Request<GetPlacementRequest>,
    ) -> Result<Response<GetPlacementResponse>, Status> {
        let home = self.object_home(&request.get_ref().bucket, &request.get_ref().key);
        let mut response = self.computed_placement(request).await?;
        if let Some(home) = home {
            self.place_at_home(&mut response.get_mut().nodes, &home);
        }
        Ok(response)
    }

    #[allow(clippy::result_large_err)]
    async fn create_multipart_upload(
        &self,
        request: Request<CreateMultipartUploadRequest>,
    ) -> Result<Response<CreateMultipartUploadResponse>, Status> {
        let req = request.into_inner();

        // Check if bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }

        let upload_id = Uuid::new_v4().to_string();
        let now = Self::current_timestamp();

        // Store the multipart upload state
        let state = MultipartUploadState {
            bucket: req.bucket.clone(),
            key: req.key.clone(),
            upload_id: upload_id.clone(),
            content_type: req.content_type.clone(),
            user_metadata: req.user_metadata.clone(),
            initiated: now,
            parts: HashMap::new(),
            encryption_algorithm: req.encryption_algorithm,
            kms_key_id: req.kms_key_id.clone(),
            encrypted_dek: req.encrypted_dek.clone(),
            customer_key_md5: req.customer_key_md5.clone(),
            encryption_context: req.encryption_context.clone(),
        };
        self.update_multipart(&upload_id, "create-multipart", |_| {
            Ok((Some(state.clone()), ()))
        })
        .await?;

        info!(
            "Created multipart upload: bucket={}, key={}, upload_id={}, sse_algo={}",
            req.bucket, req.key, upload_id, req.encryption_algorithm
        );

        Ok(Response::new(CreateMultipartUploadResponse {
            upload_id,
            bucket: req.bucket,
            key: req.key,
            encryption_algorithm: req.encryption_algorithm,
            kms_key_id: req.kms_key_id,
        }))
    }

    async fn get_multipart_upload(
        &self,
        request: Request<GetMultipartUploadRequest>,
    ) -> Result<Response<GetMultipartUploadResponse>, Status> {
        let req = request.into_inner();
        let uploads = self.multipart_uploads.read();
        let Some(upload) = uploads.get(&req.upload_id) else {
            return Ok(Response::new(GetMultipartUploadResponse {
                found: false,
                ..Default::default()
            }));
        };
        if upload.bucket != req.bucket || upload.key != req.key {
            return Ok(Response::new(GetMultipartUploadResponse {
                found: false,
                ..Default::default()
            }));
        }
        Ok(Response::new(GetMultipartUploadResponse {
            found: true,
            content_type: upload.content_type.clone(),
            user_metadata: upload.user_metadata.clone(),
            initiated: upload.initiated,
            encryption_algorithm: upload.encryption_algorithm,
            kms_key_id: upload.kms_key_id.clone(),
            encrypted_dek: upload.encrypted_dek.clone(),
            customer_key_md5: upload.customer_key_md5.clone(),
            encryption_context: upload.encryption_context.clone(),
        }))
    }

    #[allow(clippy::result_large_err)]
    async fn register_part(
        &self,
        request: Request<RegisterPartRequest>,
    ) -> Result<Response<RegisterPartResponse>, Status> {
        let req = request.into_inner();

        // Validate part number (S3 allows 1-10,000)
        if req.part_number == 0 || req.part_number > 10000 {
            return Err(Status::invalid_argument(
                "part number must be between 1 and 10000",
            ));
        }

        let now = Self::current_timestamp();

        // Register the part (overwrites if same part_number uploaded again)
        let (checksum_algorithm, checksum) = req
            .checksum
            .clone()
            .map(|c| (c.algorithm, c.value))
            .unwrap_or_default();
        let part_state = PartState {
            part_number: req.part_number,
            etag: req.etag.clone(),
            size: req.size,
            last_modified: now,
            checksum_algorithm,
            checksum,
            stripes: req.stripes.clone(), // Multiple stripes for large parts
        };
        // The part this replaces is referenced by nothing once the insert
        // lands; hand its stripes back so the gateway can free them.
        let replaced = self
            .update_multipart(&req.upload_id, "register-part", |upload| {
                let mut upload = upload.ok_or_else(|| {
                    Status::not_found(format!("multipart upload not found: {}", req.upload_id))
                })?;
                if upload.bucket != req.bucket || upload.key != req.key {
                    return Err(Status::invalid_argument(
                        "bucket/key mismatch for upload_id",
                    ));
                }
                let replaced = upload.parts.insert(req.part_number, part_state.clone());
                Ok((Some(upload), replaced))
            })
            .await?;

        debug!(
            "Registered part {} for upload {}: size={}, etag={}",
            req.part_number, req.upload_id, req.size, req.etag
        );

        Ok(Response::new(RegisterPartResponse {
            success: true,
            etag: req.etag,
            replaced_stripes: replaced.map(|p| p.stripes).unwrap_or_default(),
        }))
    }

    async fn list_parts(
        &self,
        request: Request<ListPartsRequest>,
    ) -> Result<Response<ListPartsResponse>, Status> {
        let req = request.into_inner();

        let uploads = self.multipart_uploads.read();
        let upload = uploads.get(&req.upload_id).ok_or_else(|| {
            Status::not_found(format!("multipart upload not found: {}", req.upload_id))
        })?;

        // Verify bucket/key match
        if upload.bucket != req.bucket || upload.key != req.key {
            return Err(Status::invalid_argument(
                "bucket/key mismatch for upload_id",
            ));
        }

        // Get parts sorted by part number, starting after marker
        let max_parts = if req.max_parts == 0 {
            1000
        } else {
            req.max_parts.min(1000)
        };
        let marker = req.part_number_marker;

        let mut parts: Vec<PartMeta> = upload
            .parts
            .values()
            .filter(|p| p.part_number > marker)
            .map(|p| PartMeta {
                part_number: p.part_number,
                etag: p.etag.clone(),
                size: p.size,
                last_modified: p.last_modified,
                stripes: p.stripes.clone(), // Multiple stripes for large parts
                checksum: (!p.checksum.is_empty()).then(|| {
                    objectio_proto::metadata::ObjectChecksum {
                        algorithm: p.checksum_algorithm.clone(),
                        value: p.checksum.clone(),
                    }
                }),
            })
            .collect();

        parts.sort_by_key(|p| p.part_number);

        let is_truncated = parts.len() > max_parts as usize;
        let parts: Vec<PartMeta> = parts.into_iter().take(max_parts as usize).collect();
        let next_marker = parts.last().map(|p| p.part_number).unwrap_or(0);

        Ok(Response::new(ListPartsResponse {
            parts,
            is_truncated,
            next_part_number_marker: next_marker,
            bucket: upload.bucket.clone(),
            key: upload.key.clone(),
            upload_id: upload.upload_id.clone(),
        }))
    }

    /// Complete multipart upload
    /// Validates parts and builds final object metadata with all stripes
    #[allow(clippy::result_large_err)]
    async fn complete_multipart_upload(
        &self,
        request: Request<CompleteMultipartUploadRequest>,
    ) -> Result<Response<CompleteMultipartUploadResponse>, Status> {
        let req = request.into_inner();

        // Validate and take the upload in one step (a compare-and-set
        // through Raft, or under the lock): a read-then-remove let an
        // abort, or a part re-upload, land in between — the abort freed
        // parts this completion went on to use, and a re-uploaded part was
        // dropped with the upload, unreferenced.
        let (object, unused_stripes) = self
            .update_multipart(&req.upload_id, "complete-multipart", |upload| {
                let upload = upload.ok_or_else(|| {
                    Status::not_found(format!("multipart upload not found: {}", req.upload_id))
                })?;
                Ok((None, complete_upload(&upload, &req)?))
            })
            .await?;

        info!(
            "Completed multipart upload: bucket={}, key={}, upload_id={}, size={}, parts={}",
            req.bucket,
            req.key,
            req.upload_id,
            object.size,
            req.parts.len()
        );

        Ok(Response::new(CompleteMultipartUploadResponse {
            object: Some(object),
            unused_stripes,
        }))
    }

    #[allow(clippy::result_large_err)]
    async fn abort_multipart_upload(
        &self,
        request: Request<AbortMultipartUploadRequest>,
    ) -> Result<Response<AbortMultipartUploadResponse>, Status> {
        let req = request.into_inner();

        // Remove the upload from state. Only the bucket/key it was started
        // for may abort it: the caller frees every part it held.
        let removed = self
            .update_multipart(&req.upload_id, "abort-multipart", |upload| match upload {
                Some(u) if u.bucket != req.bucket || u.key != req.key => Err(Status::not_found(
                    format!("multipart upload not found: {}", req.upload_id),
                )),
                other => Ok((None, other)),
            })
            .await?;

        if removed.is_some() {
            info!(
                "Aborted multipart upload: bucket={}, key={}, upload_id={}",
                req.bucket, req.key, req.upload_id
            );
        } else {
            debug!(
                "Abort for unknown upload_id={} (may already be completed)",
                req.upload_id
            );
            return Err(Status::not_found(format!(
                "multipart upload not found: {}",
                req.upload_id
            )));
        }

        // The parts' shards are freed by the caller, from the stripes taken
        // out here with the upload: nothing else records where they are.
        let stripes = removed
            .map(|u| u.parts.into_values().flat_map(|p| p.stripes).collect())
            .unwrap_or_default();

        Ok(Response::new(AbortMultipartUploadResponse {
            success: true,
            stripes,
        }))
    }

    async fn list_multipart_uploads(
        &self,
        request: Request<ListMultipartUploadsRequest>,
    ) -> Result<Response<ListMultipartUploadsResponse>, Status> {
        let req = request.into_inner();

        // Check if bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }

        let max_uploads = if req.max_uploads == 0 {
            1000
        } else {
            req.max_uploads.min(1000)
        };

        // Filter and collect uploads for this bucket
        let uploads_lock = self.multipart_uploads.read();
        let mut uploads: Vec<MultipartUpload> = uploads_lock
            .values()
            .filter(|u| u.bucket == req.bucket)
            .filter(|u| req.prefix.is_empty() || u.key.starts_with(&req.prefix))
            .filter(|u| {
                if req.key_marker.is_empty() || u.key > req.key_marker {
                    true
                } else if u.key == req.key_marker && !req.upload_id_marker.is_empty() {
                    u.upload_id > req.upload_id_marker
                } else {
                    false
                }
            })
            .map(|u| MultipartUpload {
                key: u.key.clone(),
                upload_id: u.upload_id.clone(),
                initiated: u.initiated,
                storage_class: "STANDARD".to_string(),
            })
            .collect();

        // Sort by key, then upload_id
        uploads.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then_with(|| a.upload_id.cmp(&b.upload_id))
        });

        let is_truncated = uploads.len() > max_uploads as usize;
        let uploads: Vec<MultipartUpload> =
            uploads.into_iter().take(max_uploads as usize).collect();

        let (next_key_marker, next_upload_id_marker) = uploads
            .last()
            .map(|u| (u.key.clone(), u.upload_id.clone()))
            .unwrap_or_default();

        Ok(Response::new(ListMultipartUploadsResponse {
            uploads,
            next_key_marker,
            next_upload_id_marker,
            is_truncated,
        }))
    }

    async fn set_bucket_policy(
        &self,
        request: Request<SetBucketPolicyRequest>,
    ) -> Result<Response<SetBucketPolicyResponse>, Status> {
        let req = request.into_inner();

        // Check if bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }

        // Validate that the policy is valid JSON
        if serde_json::from_str::<serde_json::Value>(&req.policy_json).is_err() {
            return Err(Status::invalid_argument("invalid policy JSON"));
        }

        // CAS against whatever is currently stored so a concurrent update
        // from another pod doesn't silently overwrite. Racing admin
        // operations retry from the handler.
        let expected = self
            .bucket_policies
            .read()
            .get(&req.bucket)
            .map(|v| v.as_bytes().to_vec());
        let new_value = Some(req.policy_json.as_bytes().to_vec());

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::BucketPolicies,
                    key: req.bucket.clone(),
                    expected,
                    new_value,
                }],
                requested_by: "set-bucket-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket policy changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for set_bucket_policy: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket_policy(&req.bucket, &req.policy_json);
        }

        self.bucket_policies
            .write()
            .insert(req.bucket.clone(), req.policy_json.clone());

        info!("Set bucket policy for: {}", req.bucket);

        Ok(Response::new(SetBucketPolicyResponse { success: true }))
    }

    async fn get_bucket_policy(
        &self,
        request: Request<GetBucketPolicyRequest>,
    ) -> Result<Response<GetBucketPolicyResponse>, Status> {
        let req = request.into_inner();

        // Check if bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }

        let policies = self.bucket_policies.read();
        let (policy_json, has_policy) = match policies.get(&req.bucket) {
            Some(policy) => (policy.clone(), true),
            None => (String::new(), false),
        };

        Ok(Response::new(GetBucketPolicyResponse {
            policy_json,
            has_policy,
        }))
    }

    async fn delete_bucket_policy(
        &self,
        request: Request<DeleteBucketPolicyRequest>,
    ) -> Result<Response<DeleteBucketPolicyResponse>, Status> {
        let req = request.into_inner();

        // Check if bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }

        let expected = self
            .bucket_policies
            .read()
            .get(&req.bucket)
            .map(|v| v.as_bytes().to_vec());

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::BucketPolicies,
                    key: req.bucket.clone(),
                    expected,
                    new_value: None, // delete
                }],
                requested_by: "delete-bucket-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket policy changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delete_bucket_policy: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_bucket_policy(&req.bucket);
        }

        self.bucket_policies.write().remove(&req.bucket);

        info!("Deleted bucket policy for: {}", req.bucket);

        Ok(Response::new(DeleteBucketPolicyResponse { success: true }))
    }

    async fn register_osd(
        &self,
        request: Request<RegisterOsdRequest>,
    ) -> Result<Response<RegisterOsdResponse>, Status> {
        let req = request.into_inner();

        // Validate node_id is 16 bytes
        if req.node_id.len() != 16 {
            return Err(Status::invalid_argument("node_id must be 16 bytes"));
        }

        // Resolve cluster_uuid upfront — any resolution that goes to
        // Raft needs to finish before we grab the osd_nodes write lock,
        // otherwise the parking_lot guard would be held across an
        // await and poison the future's Send bound.
        let cluster_uuid = self.cluster_uuid().await;

        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&req.node_id);

        // Parse disk IDs
        let mut disk_ids = Vec::new();
        for disk_id in &req.disk_ids {
            if disk_id.len() != 16 {
                return Err(Status::invalid_argument("disk_id must be 16 bytes"));
            }
            let mut id = [0u8; 16];
            id.copy_from_slice(disk_id);
            disk_ids.push(id);
        }

        // Capacity hint must be index-aligned with disk_ids. Tolerate the
        // older single-field protocol (empty capacities) by treating the
        // caller as reporting 0 bytes — under-reports, never blocks
        // re-registration of already-known hardware.
        let disk_capacity_bytes: Vec<u64> = if req.disk_capacity_bytes.is_empty() {
            vec![0; disk_ids.len()]
        } else if req.disk_capacity_bytes.len() == disk_ids.len() {
            req.disk_capacity_bytes.clone()
        } else {
            return Err(Status::invalid_argument(
                "disk_capacity_bytes length must match disk_ids",
            ));
        };

        // Register the OSD. Pull failure-domain fields from the request
        // and persist both the legacy 3-tuple (back-compat) and the full
        // 5-level `topology`, so newer meta readers see zone/host and
        // older code paths still find region/dc/rack.
        let topology_tuple = req.failure_domain.as_ref().map(|fd| {
            (
                fd.region.clone(),
                fd.zone.clone(),
                fd.datacenter.clone(),
                fd.rack.clone(),
                fd.host.clone(),
            )
        });
        let legacy_fd = req
            .failure_domain
            .as_ref()
            .map(|fd| (fd.region.clone(), fd.datacenter.clone(), fd.rack.clone()));
        let num_disks = disk_ids.len();
        // Preserve operator intent across re-registrations: if the OSD
        // was marked Out or Draining and the same node_id (or address)
        // re-registers, keep it out of placement until an admin
        // explicitly flips it back to In.
        let prev_admin_state = {
            let nodes = self.osd_nodes.read();
            nodes
                .iter()
                .find(|n| n.node_id == node_id || n.address == req.address)
                .map(|n| n.admin_state)
                .unwrap_or_default()
        };
        let node = OsdNode {
            node_id,
            address: req.address.clone(),
            disk_ids,
            failure_domain: legacy_fd,
            topology: topology_tuple,
            disk_capacity_bytes,
            admin_state: prev_admin_state,
            te_segment: req.te_segment.clone(),
        };

        // Check if node already exists and update, or add new. We dedupe
        // on node_id AND on address — an OSD that loses its persistent
        // state gets a new node_id on restart, but still advertises the
        // same hostname. Treat "same address, different node_id" as a
        // replacement so the topology doesn't accumulate ghosts.
        let evicted_ids = {
            let mut nodes = self.osd_nodes.write();
            let mut evicted_ids: Vec<[u8; 16]> = Vec::new();
            if let Some(existing) = nodes.iter_mut().find(|n| n.node_id == node_id) {
                existing.address = node.address.clone();
                existing.disk_ids = node.disk_ids.clone();
                existing.disk_capacity_bytes = node.disk_capacity_bytes.clone();
                existing.failure_domain = node.failure_domain.clone();
                existing.topology = node.topology.clone();
                existing.te_segment = node.te_segment.clone();
                info!(
                    "Updated OSD registration: {} at {}",
                    hex::encode(node_id),
                    req.address
                );
            } else {
                // Evict any existing entry at the same address (stale node_id
                // from a prior OSD process) so the tree shows live nodes only.
                nodes.retain(|n| {
                    if n.address == req.address && n.node_id != node_id {
                        evicted_ids.push(n.node_id);
                        false
                    } else {
                        true
                    }
                });
                if !evicted_ids.is_empty() {
                    info!(
                        "Evicted {} stale OSD entry/entries at address {} (node_id changed)",
                        evicted_ids.len(),
                        req.address
                    );
                }
                info!(
                    "Registered new OSD: {} at {} with {} disks",
                    hex::encode(node_id),
                    req.address,
                    num_disks
                );
                nodes.push(node.clone());
            }
            evicted_ids
        };

        // Also drop the stale node_ids from the CRUSH topology so listings
        // and placement see a clean view.
        if !evicted_ids.is_empty() {
            let mut topology = self.topology.write();
            for id in &evicted_ids {
                let stale = NodeId::from_bytes(*id);
                topology.remove_node(stale);
            }
        }

        // Add (or refresh) THIS OSD in the topology. Without this, a
        // freshly-registered OSD whose state PVC was wiped — so it comes
        // back with a new node_id — never joins the CRUSH placement set,
        // because the old node_id was evicted but the new one was never
        // inserted. Symptom on the cluster: writes and rebalance both
        // skip the OSD forever, its shard count stays at 0. Update the
        // topology now so `active_nodes()` sees the new node_id right
        // away; the CRUSH engine gets rebuilt inside
        // `update_topology_with_node`.
        self.update_topology_with_node(&node);

        // Persist through Raft, so a new leader knows every OSD (it used to
        // know only those that registered with it: none, after failover).
        // The topology is rebuilt from the OSD records on load.
        let mut writes = vec![(
            OSD_NODES_TABLE,
            hex::encode(node_id),
            Some(
                bincode::serialize(&node)
                    .map_err(|e| Status::internal(format!("OSD encode: {e}")))?,
            ),
        )];
        writes.extend(
            evicted_ids
                .iter()
                .map(|id| (OSD_NODES_TABLE, hex::encode(id), None)),
        );
        self.replicate(writes, "register-osd").await?;

        // Get current topology version
        let topology_version = self.topology.read().version;

        Ok(Response::new(RegisterOsdResponse {
            success: true,
            topology_version,
            cluster_uuid,
        }))
    }

    /// Get all active nodes for scatter-gather listing operations
    async fn get_listing_nodes(
        &self,
        request: Request<GetListingNodesRequest>,
    ) -> Result<Response<GetListingNodesResponse>, Status> {
        let req = request.into_inner();
        let topology = self.topology.read();
        let osd_nodes = self.osd_nodes.read();

        // Helper — map internal admin state → proto enum value.
        let admin_state_proto = |s: objectio_common::OsdAdminState| -> i32 {
            match s {
                objectio_common::OsdAdminState::In => {
                    objectio_proto::metadata::OsdAdminState::OsdAdminIn as i32
                }
                objectio_common::OsdAdminState::Out => {
                    objectio_proto::metadata::OsdAdminState::OsdAdminOut as i32
                }
                objectio_common::OsdAdminState::Draining => {
                    objectio_proto::metadata::OsdAdminState::OsdAdminDraining as i32
                }
            }
        };

        // When include_all_states is true, admin UI wants EVERY OSD
        // including Draining / Out / Decommissioning. Scatter-gather
        // callers (the default) only want Active ones.
        let topology_iter: Box<dyn Iterator<Item = &objectio_placement::topology::NodeInfo>> =
            if req.include_all_states {
                Box::new(topology.all_nodes())
            } else {
                Box::new(topology.active_nodes())
            };

        // Build lookups keyed by node_id:
        //   admin_state_by_id — operator intent (In/Out/Draining)
        //   address_by_id    — the real OSD endpoint string. The placement
        //                       topology's `address` field is a SocketAddr
        //                       which can't represent DNS names (e.g.
        //                       "http://objectio-osd-3.objectio-osd-headless:9200")
        //                       and falls back to "0.0.0.0:9200". If we
        //                       used that, every node would collapse to
        //                       the same address and the gateway's
        //                       address-based dedup would reduce the
        //                       whole cluster to a single row.
        let admin_state_by_id: std::collections::HashMap<[u8; 16], objectio_common::OsdAdminState> =
            osd_nodes
                .iter()
                .map(|n| (n.node_id, n.admin_state))
                .collect();
        let address_by_id: std::collections::HashMap<[u8; 16], String> = osd_nodes
            .iter()
            .map(|n| (n.node_id, n.address.clone()))
            .collect();
        let te_segment_by_id: std::collections::HashMap<[u8; 16], String> = osd_nodes
            .iter()
            .map(|n| (n.node_id, n.te_segment.clone()))
            .collect();

        let mut nodes: Vec<ListingNode> = topology_iter
            .enumerate()
            .map(|(idx, node)| {
                let id_bytes = *node.id.as_bytes();
                let admin_state = admin_state_by_id
                    .get(&id_bytes)
                    .copied()
                    .unwrap_or_default();
                // Prefer the registered DNS form; fall back to the
                // topology's parsed SocketAddr only when the OSD isn't
                // in osd_nodes (shouldn't happen in practice).
                let address = address_by_id
                    .get(&id_bytes)
                    .cloned()
                    .unwrap_or_else(|| format!("http://{}", node.address));
                ListingNode {
                    node_id: id_bytes.to_vec(),
                    address,
                    shard_id: idx as u32, // Assign logical shard IDs in order
                    failure_domain: Some(objectio_proto::metadata::FailureDomainInfo {
                        region: node.failure_domain.region.clone(),
                        datacenter: node.failure_domain.datacenter.clone(),
                        rack: node.failure_domain.rack.clone(),
                        zone: node.failure_domain.zone.clone(),
                        host: node.failure_domain.host.clone(),
                    }),
                    admin_state: admin_state_proto(admin_state),
                    te_segment: te_segment_by_id.get(&id_bytes).cloned().unwrap_or_default(),
                }
            })
            .collect();

        // Also include legacy OSD nodes if no topology nodes exist
        if nodes.is_empty() {
            nodes = osd_nodes
                .iter()
                .enumerate()
                .map(|(idx, node)| {
                    let fd = node.topology.as_ref().map(|t| {
                        objectio_proto::metadata::FailureDomainInfo {
                            region: t.0.clone(),
                            zone: t.1.clone(),
                            datacenter: t.2.clone(),
                            rack: t.3.clone(),
                            host: t.4.clone(),
                        }
                    });
                    ListingNode {
                        node_id: node.node_id.to_vec(),
                        address: node.address.clone(),
                        shard_id: idx as u32,
                        failure_domain: fd,
                        admin_state: admin_state_proto(node.admin_state),
                        te_segment: node.te_segment.clone(),
                    }
                })
                .collect();
        }

        debug!(
            "GetListingNodes: returning {} nodes (topology_version={})",
            nodes.len(),
            topology.version
        );

        Ok(Response::new(GetListingNodesResponse {
            nodes,
            topology_version: topology.version,
        }))
    }

    // =========== IAM Operations ===========

    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let req = request.into_inner();

        if req.display_name.is_empty() {
            return Err(Status::invalid_argument("display_name is required"));
        }

        // Check if a *live* user with this name exists. DeleteUser is a soft
        // delete — it flips status to Deleted and leaves the record in place —
        // so scanning every value meant a deleted name was taken forever.
        // Listing already hides those users, which made it look like the name
        // was free right up until the create failed.
        if self.users.read().values().any(|u| {
            u.display_name == req.display_name && u.status != UserStatus::UserDeleted as i32
        }) {
            return Err(Status::already_exists("user with this name already exists"));
        }

        let user_id = Uuid::new_v4().to_string();
        let now = Self::current_timestamp();

        // Validate tenant if specified
        let tenant = req.tenant.clone();
        if !tenant.is_empty() && !self.tenants.read().contains_key(&tenant) {
            return Err(Status::not_found(format!("tenant '{}' not found", tenant)));
        }

        // Include tenant in ARN if tenant-scoped
        let arn = if tenant.is_empty() {
            format!("arn:objectio:iam::user/{}", req.display_name)
        } else {
            format!("arn:objectio:iam::{}:user/{}", tenant, req.display_name)
        };

        let user = StoredUser {
            user_id: user_id.clone(),
            display_name: req.display_name.clone(),
            arn,
            status: UserStatus::UserActive as i32,
            created_at: now,
            email: req.email.clone(),
            tenant: tenant.clone(),
        };

        // Replicate through Raft. expected=None ensures the user_id
        // hasn't collided with a concurrent create (cryptographically
        // unlikely for UUIDs, but tested correctly by the state machine).
        let user_bytes =
            bincode::serialize(&user).map_err(|e| Status::internal(format!("user encode: {e}")))?;
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Users,
                    key: user_id.clone(),
                    expected: None,
                    new_value: Some(user_bytes),
                }],
                requested_by: "create-user".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists(
                            "user_id collision (retry with fresh id)",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for create_user: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_user(&user_id, &user);
        }

        self.users.write().insert(user_id.clone(), user.clone());
        self.user_keys.write().insert(user_id.clone(), Vec::new());

        info!(
            "Created user: {} (tenant={})",
            req.display_name,
            if tenant.is_empty() { "system" } else { &tenant }
        );

        Ok(Response::new(CreateUserResponse {
            user: Some(UserMeta {
                user_id: user.user_id,
                display_name: user.display_name,
                arn: user.arn,
                status: user.status,
                created_at: user.created_at,
                email: user.email,
                tenant,
            }),
        }))
    }

    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let req = request.into_inner();

        let user = self
            .users
            .read()
            .get(&req.user_id)
            .cloned()
            .ok_or_else(|| Status::not_found("user not found"))?;

        Ok(Response::new(GetUserResponse {
            user: Some(UserMeta {
                user_id: user.user_id.clone(),
                display_name: user.display_name.clone(),
                arn: user.arn.clone(),
                status: user.status,
                created_at: user.created_at,
                email: user.email.clone(),
                tenant: user.tenant.clone(),
            }),
        }))
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let req = request.into_inner();
        let max_results = if req.max_results == 0 {
            100
        } else {
            req.max_results.min(1000)
        };

        let users: Vec<UserMeta> = self
            .users
            .read()
            .values()
            .filter(|u| req.marker.is_empty() || u.user_id > req.marker)
            .filter(|u| u.status != UserStatus::UserDeleted as i32)
            .take(max_results as usize + 1)
            .map(|u| UserMeta {
                user_id: u.user_id.clone(),
                display_name: u.display_name.clone(),
                arn: u.arn.clone(),
                status: u.status,
                created_at: u.created_at,
                email: u.email.clone(),
                tenant: u.tenant.clone(),
            })
            .collect();

        let is_truncated = users.len() > max_results as usize;
        let users: Vec<UserMeta> = users.into_iter().take(max_results as usize).collect();
        let next_marker = users.last().map(|u| u.user_id.clone()).unwrap_or_default();

        Ok(Response::new(ListUsersResponse {
            users,
            next_marker: if is_truncated {
                next_marker
            } else {
                String::new()
            },
            is_truncated,
        }))
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let req = request.into_inner();

        // Snapshot current user + access-key state under read locks so we
        // can build the CAS batch atomically. The user's status flips to
        // Deleted; every owned access key flips to Inactive — all in one
        // MultiCas so followers see the compound change at the same log
        // position (can't observe "user deleted but keys still active").
        let (old_user_bytes, new_user_bytes, user_snapshot) = {
            let users = self.users.read();
            let user = users
                .get(&req.user_id)
                .ok_or_else(|| Status::not_found("user not found"))?;
            let mut new_user = user.clone();
            new_user.status = UserStatus::UserDeleted as i32;
            let old_bytes = bincode::serialize(user)
                .map_err(|e| Status::internal(format!("user encode: {e}")))?;
            let new_bytes = bincode::serialize(&new_user)
                .map_err(|e| Status::internal(format!("user encode: {e}")))?;
            (old_bytes, new_bytes, new_user)
        };

        let key_ids: Vec<String> = self
            .user_keys
            .read()
            .get(&req.user_id)
            .cloned()
            .unwrap_or_default();

        // Build per-key (old_bytes, new_bytes) transitions. Keys that
        // aren't found in the access_keys map are silently skipped (stale
        // entry in user_keys index).
        let mut key_transitions: Vec<(String, Vec<u8>, Vec<u8>, StoredAccessKey)> =
            Vec::with_capacity(key_ids.len());
        {
            let keys = self.access_keys.read();
            for key_id in &key_ids {
                if let Some(key) = keys.get(key_id) {
                    let mut new_key = key.clone();
                    new_key.status = KeyStatus::KeyInactive as i32;
                    let old_b = bincode::serialize(key)
                        .map_err(|e| Status::internal(format!("key encode: {e}")))?;
                    let new_b = bincode::serialize(&new_key)
                        .map_err(|e| Status::internal(format!("key encode: {e}")))?;
                    key_transitions.push((key_id.clone(), old_b, new_b, new_key));
                }
            }
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = Vec::with_capacity(1 + key_transitions.len());
            ops.push(CasOp {
                table: CasTable::Users,
                key: req.user_id.clone(),
                expected: Some(old_user_bytes),
                new_value: Some(new_user_bytes),
            });
            for (kid, old_b, new_b, _) in &key_transitions {
                ops.push(CasOp {
                    table: CasTable::AccessKeys,
                    key: kid.clone(),
                    expected: Some(old_b.clone()),
                    new_value: Some(new_b.clone()),
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delete-user".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::aborted(format!(
                            "user or access-key changed mid-delete; retry (conflicts at ops {failed_indices:?})"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for delete_user: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_user(&req.user_id, &user_snapshot);
            for (kid, _, _, new_key) in &key_transitions {
                store.put_access_key(kid, new_key);
            }
        }

        // Mirror into in-memory caches after the quorum commit.
        self.users
            .write()
            .insert(req.user_id.clone(), user_snapshot);
        {
            let mut keys = self.access_keys.write();
            for (kid, _, _, new_key) in key_transitions {
                keys.insert(kid, new_key);
            }
        }

        info!("Deleted user: {}", req.user_id);

        Ok(Response::new(DeleteUserResponse { success: true }))
    }

    async fn create_access_key(
        &self,
        request: Request<CreateAccessKeyRequest>,
    ) -> Result<Response<CreateAccessKeyResponse>, Status> {
        let req = request.into_inner();

        // Verify user exists and is active
        let user = self
            .users
            .read()
            .get(&req.user_id)
            .cloned()
            .ok_or_else(|| Status::not_found("user not found"))?;

        if user.status != UserStatus::UserActive as i32 {
            return Err(Status::failed_precondition("user is not active"));
        }

        let now = Self::current_timestamp();
        let access_key_id = Self::generate_access_key_id();
        let secret_access_key = Self::generate_secret_access_key();

        let key = StoredAccessKey {
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
            user_id: req.user_id.clone(),
            status: KeyStatus::KeyActive as i32,
            created_at: now,
            tenant: user.tenant.clone(),
            scope: req.scope.clone(),
            operation: req.operation,
        };

        let key_bytes = bincode::serialize(&key)
            .map_err(|e| Status::internal(format!("access key encode: {e}")))?;
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    // No enum variant yet for access_keys — use Named
                    // escape hatch. Switching to a dedicated CasTable
                    // variant later is additive.
                    table: CasTable::AccessKeys,
                    key: access_key_id.clone(),
                    expected: None,
                    new_value: Some(key_bytes),
                }],
                requested_by: "create-access-key".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists(
                            "access key id collision (retry with fresh id)",
                        ));
                    }
                    other => {
                        error!(
                            "unexpected raft response for create_access_key: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_access_key(&access_key_id, &key);
        }

        self.access_keys
            .write()
            .insert(access_key_id.clone(), key.clone());
        // `apply_access_key_event` maintains this index too, and the raft
        // write above already ran it — without a guard every key lands twice
        // and `key list` shows duplicates.
        {
            let mut idx = self.user_keys.write();
            let ids = idx.entry(req.user_id.clone()).or_default();
            if !ids.contains(&access_key_id) {
                ids.push(access_key_id.clone());
            }
        }

        info!(
            "Created access key {} for user {}",
            access_key_id, req.user_id
        );

        Ok(Response::new(CreateAccessKeyResponse {
            access_key: Some(AccessKeyMeta {
                access_key_id: key.access_key_id,
                secret_access_key: key.secret_access_key, // Only returned on creation
                user_id: key.user_id,
                status: key.status,
                created_at: key.created_at,
                tenant: key.tenant,
                scope: key.scope,
                operation: key.operation,
            }),
        }))
    }

    async fn list_access_keys(
        &self,
        request: Request<ListAccessKeysRequest>,
    ) -> Result<Response<ListAccessKeysResponse>, Status> {
        let req = request.into_inner();

        let key_ids = self
            .user_keys
            .read()
            .get(&req.user_id)
            .cloned()
            .unwrap_or_default();

        let keys = self.access_keys.read();
        let access_keys: Vec<AccessKeyMeta> = key_ids
            .iter()
            .filter_map(|id| keys.get(id))
            .map(|k| AccessKeyMeta {
                access_key_id: k.access_key_id.clone(),
                secret_access_key: String::new(), // Don't return secret in list
                user_id: k.user_id.clone(),
                status: k.status,
                created_at: k.created_at,
                tenant: k.tenant.clone(),
                scope: k.scope.clone(),
                operation: k.operation,
            })
            .collect();

        Ok(Response::new(ListAccessKeysResponse { access_keys }))
    }

    async fn delete_access_key(
        &self,
        request: Request<DeleteAccessKeyRequest>,
    ) -> Result<Response<DeleteAccessKeyResponse>, Status> {
        let req = request.into_inner();

        let current = self
            .access_keys
            .read()
            .get(&req.access_key_id)
            .cloned()
            .ok_or_else(|| Status::not_found("access key not found"))?;
        let expected_bytes = bincode::serialize(&current)
            .map_err(|e| Status::internal(format!("access key encode: {e}")))?;

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::AccessKeys,
                    key: req.access_key_id.clone(),
                    expected: Some(expected_bytes),
                    new_value: None, // delete
                }],
                requested_by: "delete-access-key".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted(
                            "access key changed since read; retry delete",
                        ));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delete_access_key: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_access_key(&req.access_key_id);
        }

        self.access_keys.write().remove(&req.access_key_id);
        if let Some(keys) = self.user_keys.write().get_mut(&current.user_id) {
            keys.retain(|id| id != &req.access_key_id);
        }

        info!("Deleted access key: {}", req.access_key_id);
        Ok(Response::new(DeleteAccessKeyResponse { success: true }))
    }

    async fn get_access_key(
        &self,
        request: Request<objectio_proto::metadata::GetAccessKeyRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetAccessKeyResponse>, Status> {
        let id = request.into_inner().access_key_id;
        let key = self.access_keys.read().get(&id).cloned();
        Ok(Response::new(
            objectio_proto::metadata::GetAccessKeyResponse {
                found: key.is_some(),
                access_key: key.map(|k| AccessKeyMeta {
                    access_key_id: k.access_key_id,
                    secret_access_key: String::new(),
                    user_id: k.user_id,
                    status: k.status,
                    created_at: k.created_at,
                    tenant: k.tenant,
                    scope: k.scope,
                    operation: k.operation,
                }),
            },
        ))
    }

    async fn get_access_key_for_auth(
        &self,
        request: Request<GetAccessKeyForAuthRequest>,
    ) -> Result<Response<GetAccessKeyForAuthResponse>, Status> {
        let req = request.into_inner();

        let key = self
            .access_keys
            .read()
            .get(&req.access_key_id)
            .cloned()
            .ok_or_else(|| Status::not_found("access key not found"))?;

        if key.status != KeyStatus::KeyActive as i32 {
            return Err(Status::permission_denied("access key is inactive"));
        }

        let user = self
            .users
            .read()
            .get(&key.user_id)
            .cloned()
            .ok_or_else(|| Status::not_found("user not found"))?;

        if user.status != UserStatus::UserActive as i32 {
            return Err(Status::permission_denied("user is not active"));
        }

        Ok(Response::new(GetAccessKeyForAuthResponse {
            access_key: Some(AccessKeyMeta {
                access_key_id: key.access_key_id,
                secret_access_key: key.secret_access_key, // Include for auth verification
                user_id: key.user_id,
                status: key.status,
                created_at: key.created_at,
                tenant: key.tenant,
                scope: key.scope,
                operation: key.operation,
            }),
            user: Some(UserMeta {
                user_id: user.user_id,
                display_name: user.display_name,
                arn: user.arn,
                status: user.status,
                created_at: user.created_at,
                email: user.email,
                tenant: user.tenant,
            }),
        }))
    }

    // =========== Iceberg Catalog Operations ===========

    async fn iceberg_create_namespace(
        &self,
        request: Request<IcebergCreateNamespaceRequest>,
    ) -> Result<Response<IcebergCreateNamespaceResponse>, Status> {
        let req = request.into_inner();

        if req.namespace_levels.is_empty() {
            return Err(Status::invalid_argument("namespace levels cannot be empty"));
        }

        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        if self.iceberg_namespaces.read().contains_key(&ns_key) {
            return Err(Status::already_exists("namespace already exists"));
        }

        // If multi-level, verify parent exists
        if req.namespace_levels.len() > 1 {
            let parent_key = Self::iceberg_ns_key_wh(
                &req.warehouse,
                &req.namespace_levels[..req.namespace_levels.len() - 1],
            );
            if !self.iceberg_namespaces.read().contains_key(&parent_key) {
                return Err(Status::not_found("parent namespace does not exist"));
            }
        }

        let properties = req.properties.clone();
        let resp = IcebergCreateNamespaceResponse {
            namespace_levels: req.namespace_levels.clone(),
            properties: properties.clone(),
        };
        let new_bytes = resp.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergNamespaces,
                    key: ns_key.clone(),
                    expected: None,
                    new_value: Some(new_bytes),
                }],
                requested_by: "iceberg-create-namespace".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("namespace already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_namespace: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_iceberg_namespace(&ns_key, &resp.encode_to_vec());
        }

        self.iceberg_namespaces
            .write()
            .insert(ns_key.clone(), properties.clone());

        info!("Created iceberg namespace: {:?}", req.namespace_levels);

        Ok(Response::new(IcebergCreateNamespaceResponse {
            namespace_levels: req.namespace_levels,
            properties,
        }))
    }

    async fn iceberg_load_namespace(
        &self,
        request: Request<IcebergLoadNamespaceRequest>,
    ) -> Result<Response<IcebergLoadNamespaceResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        let properties = self
            .iceberg_namespaces
            .read()
            .get(&ns_key)
            .cloned()
            .ok_or_else(|| Status::not_found("namespace not found"))?;

        Ok(Response::new(IcebergLoadNamespaceResponse {
            namespace_levels: req.namespace_levels,
            properties,
        }))
    }

    async fn iceberg_drop_namespace(
        &self,
        request: Request<IcebergDropNamespaceRequest>,
    ) -> Result<Response<IcebergDropNamespaceResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        // Check namespace exists
        if !self.iceberg_namespaces.read().contains_key(&ns_key) {
            return Err(Status::not_found("namespace not found"));
        }

        // Check for tables in namespace
        let table_prefix = format!("{ns_key}\x00");
        let has_tables = self
            .iceberg_tables
            .read()
            .keys()
            .any(|k| k.starts_with(&table_prefix));
        if has_tables {
            return Err(Status::failed_precondition(
                "namespace is not empty (contains tables)",
            ));
        }

        // Check for child namespaces
        let child_prefix = format!("{ns_key}\x00");
        let has_children = self
            .iceberg_namespaces
            .read()
            .keys()
            .any(|k| k.starts_with(&child_prefix));
        if has_children {
            return Err(Status::failed_precondition(
                "namespace is not empty (contains child namespaces)",
            ));
        }

        // Reconstruct the expected stored bytes from the in-memory
        // properties (prost is deterministic on the same struct shape).
        let expected_bytes = {
            let ns_map = self.iceberg_namespaces.read();
            let properties = ns_map
                .get(&ns_key)
                .cloned()
                .ok_or_else(|| Status::not_found("namespace not found"))?;
            let stored = IcebergCreateNamespaceResponse {
                namespace_levels: req.namespace_levels.clone(),
                properties,
            };
            stored.encode_to_vec()
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergNamespaces,
                    key: ns_key.clone(),
                    expected: Some(expected_bytes),
                    new_value: None,
                }],
                requested_by: "iceberg-drop-namespace".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("namespace changed since read; retry drop"));
                    }
                    other => {
                        error!("unexpected raft response for drop_namespace: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_iceberg_namespace(&ns_key);
        }

        self.iceberg_namespaces.write().remove(&ns_key);

        info!("Dropped iceberg namespace: {:?}", req.namespace_levels);

        Ok(Response::new(IcebergDropNamespaceResponse {
            success: true,
        }))
    }

    async fn iceberg_list_namespaces(
        &self,
        request: Request<IcebergListNamespacesRequest>,
    ) -> Result<Response<IcebergListNamespacesResponse>, Status> {
        let req = request.into_inner();

        let wh_prefix = Self::iceberg_warehouse_prefix(&req.warehouse);

        let parent_key = if req.parent_levels.is_empty() {
            String::new()
        } else {
            Self::iceberg_ns_key_wh(&req.warehouse, &req.parent_levels)
        };

        // If parent specified, verify it exists
        if !parent_key.is_empty() && !self.iceberg_namespaces.read().contains_key(&parent_key) {
            return Err(Status::not_found("parent namespace not found"));
        }

        let prefix = if parent_key.is_empty() {
            wh_prefix.clone()
        } else {
            format!("{parent_key}\x00")
        };

        let page_size = if req.page_size == 0 {
            100
        } else {
            req.page_size.min(1000)
        } as usize;

        let mut keys: Vec<String> = self
            .iceberg_namespaces
            .read()
            .keys()
            .filter(|k| {
                if prefix.is_empty() {
                    // No warehouse, no parent: top-level namespaces without warehouse prefix
                    !k.contains('\x00') && !k.contains('\x01')
                } else if parent_key.is_empty() && !wh_prefix.is_empty() {
                    // Warehouse set but no parent: top-level namespaces in this warehouse
                    k.starts_with(&prefix) && !k[prefix.len()..].contains('\x00')
                } else {
                    k.starts_with(&prefix) && !k[prefix.len()..].contains('\x00')
                }
            })
            .cloned()
            .collect();
        keys.sort();

        // Skip past page_token
        if !req.page_token.is_empty() {
            keys.retain(|k| k.as_str() > req.page_token.as_str());
        }

        let has_more = keys.len() > page_size;
        let keys: Vec<String> = keys.into_iter().take(page_size).collect();

        let next_page_token = if has_more {
            keys.last().cloned().unwrap_or_default()
        } else {
            String::new()
        };

        let namespaces: Vec<IcebergNamespace> = keys
            .iter()
            .map(|k| {
                // Strip warehouse prefix (warehouse\x01) if present
                let ns_part = if let Some(pos) = k.find('\x01') {
                    &k[pos + 1..]
                } else {
                    k.as_str()
                };
                let levels: Vec<String> = ns_part.split('\x00').map(String::from).collect();
                IcebergNamespace { levels }
            })
            .collect();

        Ok(Response::new(IcebergListNamespacesResponse {
            namespaces,
            next_page_token,
        }))
    }

    async fn iceberg_update_namespace_properties(
        &self,
        request: Request<IcebergUpdateNamespacePropertiesRequest>,
    ) -> Result<Response<IcebergUpdateNamespacePropertiesResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        // Compute the before/after snapshot under a read lock so the
        // CAS can roll back cleanly on a concurrent mutation.
        let (expected_bytes, new_bytes, new_properties, updated, removed, missing) = {
            let ns_map = self.iceberg_namespaces.read();
            let current = ns_map
                .get(&ns_key)
                .cloned()
                .ok_or_else(|| Status::not_found("namespace not found"))?;

            let expected = IcebergCreateNamespaceResponse {
                namespace_levels: req.namespace_levels.clone(),
                properties: current.clone(),
            }
            .encode_to_vec();

            let mut new_props = current;
            let mut updated = Vec::new();
            let mut removed = Vec::new();
            let mut missing = Vec::new();
            for key in &req.removals {
                if new_props.remove(key).is_some() {
                    removed.push(key.clone());
                } else {
                    missing.push(key.clone());
                }
            }
            for (key, value) in &req.updates {
                new_props.insert(key.clone(), value.clone());
                updated.push(key.clone());
            }
            let new_bytes = IcebergCreateNamespaceResponse {
                namespace_levels: req.namespace_levels.clone(),
                properties: new_props.clone(),
            }
            .encode_to_vec();
            (expected, new_bytes, new_props, updated, removed, missing)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergNamespaces,
                    key: ns_key.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "iceberg-update-namespace-properties".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted(
                            "namespace properties changed since read; retry",
                        ));
                    }
                    other => {
                        error!(
                            "unexpected raft response for update_namespace_properties: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            let resp = IcebergCreateNamespaceResponse {
                namespace_levels: req.namespace_levels.clone(),
                properties: new_properties.clone(),
            };
            store.put_iceberg_namespace(&ns_key, &resp.encode_to_vec());
        }

        self.iceberg_namespaces
            .write()
            .insert(ns_key.clone(), new_properties);

        Ok(Response::new(IcebergUpdateNamespacePropertiesResponse {
            updated,
            removed,
            missing,
        }))
    }

    async fn iceberg_namespace_exists(
        &self,
        request: Request<IcebergNamespaceExistsRequest>,
    ) -> Result<Response<IcebergNamespaceExistsResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);
        let exists = self.iceberg_namespaces.read().contains_key(&ns_key);
        Ok(Response::new(IcebergNamespaceExistsResponse { exists }))
    }

    async fn iceberg_create_table(
        &self,
        request: Request<IcebergCreateTableRequest>,
    ) -> Result<Response<IcebergCreateTableResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        // Verify namespace exists
        if !self.iceberg_namespaces.read().contains_key(&ns_key) {
            return Err(Status::not_found("namespace not found"));
        }

        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);

        if self.iceberg_tables.read().contains_key(&table_key) {
            return Err(Status::already_exists("table already exists"));
        }

        let now = Self::current_timestamp();
        let entry = IcebergTableEntry {
            metadata_location: req.metadata_location.clone(),
            created_at: now,
            updated_at: now,
            metadata_json: req.metadata_json.clone(),
            policy_json: Vec::new(),
        };
        let new_bytes = entry.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergTables,
                    key: table_key.clone(),
                    expected: None,
                    new_value: Some(new_bytes),
                }],
                requested_by: "iceberg-create-table".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("table already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_table: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_iceberg_table(&table_key, &entry.encode_to_vec());
        }

        self.iceberg_tables
            .write()
            .insert(table_key.clone(), entry.clone());

        info!(
            "Created iceberg table: {:?}.{}",
            req.namespace_levels, req.table_name
        );

        Ok(Response::new(IcebergCreateTableResponse {
            metadata_location: req.metadata_location,
            metadata_json: req.metadata_json,
        }))
    }

    async fn iceberg_load_table(
        &self,
        request: Request<IcebergLoadTableRequest>,
    ) -> Result<Response<IcebergLoadTableResponse>, Status> {
        let req = request.into_inner();
        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);

        let entry = self
            .iceberg_tables
            .read()
            .get(&table_key)
            .cloned()
            .ok_or_else(|| Status::not_found("table not found"))?;

        Ok(Response::new(IcebergLoadTableResponse {
            metadata_location: entry.metadata_location,
            metadata_json: entry.metadata_json,
        }))
    }

    async fn iceberg_commit_table(
        &self,
        request: Request<IcebergCommitTableRequest>,
    ) -> Result<Response<IcebergCommitTableResponse>, Status> {
        let req = request.into_inner();
        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);

        // Stage 1 — read the current entry, validate the expected metadata
        // location, and encode the proposed new entry. Held behind a read
        // lock so concurrent non-conflicting RPCs on other tables aren't
        // serialized against this one.
        let (old_bytes, new_entry, new_bytes) = {
            let tables = self.iceberg_tables.read();
            let entry = tables
                .get(&table_key)
                .ok_or_else(|| Status::not_found("table not found"))?;

            if entry.metadata_location != req.current_metadata_location {
                return Err(Status::failed_precondition(format!(
                    "metadata location mismatch: expected '{}', actual '{}'",
                    req.current_metadata_location, entry.metadata_location
                )));
            }

            let now = Self::current_timestamp();
            let new_entry = IcebergTableEntry {
                metadata_location: req.new_metadata_location.clone(),
                created_at: entry.created_at,
                updated_at: now,
                metadata_json: req.new_metadata_json.clone(),
                policy_json: entry.policy_json.clone(),
            };
            let old_bytes = entry.encode_to_vec();
            let new_bytes = new_entry.encode_to_vec();
            (old_bytes, new_entry, new_bytes)
        };

        // Stage 2 — replicate the CAS through Raft so followers observe
        // the same commit. Non-leader pods return a Forwarding error that
        // `raft_write_to_status` turns into a leader-hint Status; the
        // iceberg REST handler retries against the leader.
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergTables,
                    key: table_key.clone(),
                    expected: Some(old_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "iceberg-commit".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::failed_precondition(
                            "concurrent metadata update detected",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for iceberg commit: {:?}", other);
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            // Legacy non-Raft path (tests, pre-Raft deployments). Keep the
            // old direct-redb CAS so unit tests without a raft handle
            // still work.
            match store.cas_iceberg_table(&table_key, &old_bytes, &new_bytes) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(Status::failed_precondition(
                        "concurrent metadata update detected",
                    ));
                }
                Err(e) => {
                    error!("Failed to CAS iceberg table '{}': {}", table_key, e);
                    return Err(Status::internal("failed to commit table update"));
                }
            }
        }

        // Stage 3 — mirror into the in-memory cache on this leader so
        // local reads see the update without waiting for a redb hit.
        // Followers' caches are rebuilt from redb on next leader promote
        // (the state machine apply already landed the bytes on disk).
        self.iceberg_tables
            .write()
            .insert(table_key.clone(), new_entry);

        debug!(
            "Committed iceberg table {:?}.{}: {} -> {}",
            req.namespace_levels,
            req.table_name,
            req.current_metadata_location,
            req.new_metadata_location
        );

        Ok(Response::new(IcebergCommitTableResponse {
            metadata_location: req.new_metadata_location,
            metadata_json: req.new_metadata_json,
        }))
    }

    async fn iceberg_commit_transaction(
        &self,
        request: Request<IcebergCommitTransactionRequest>,
    ) -> Result<Response<IcebergCommitTransactionResponse>, Status> {
        let req = request.into_inner();
        if req.table_changes.is_empty() {
            return Err(Status::invalid_argument("table_changes is empty"));
        }

        // Stage 1 — validate every change's expected location and encode the
        // new entries. Held behind a read-lock so concurrent single-table
        // commits on other tables aren't serialized behind this one. A
        // failed expected location aborts the whole transaction before
        // any Raft round-trip.
        struct Prepared {
            table_key: String,
            old_bytes: Vec<u8>,
            new_entry: IcebergTableEntry,
            new_bytes: Vec<u8>,
            resp: IcebergCommitTableResponse,
        }
        let prepared: Vec<Prepared> = {
            let tables = self.iceberg_tables.read();
            let now = Self::current_timestamp();
            let mut prepared = Vec::with_capacity(req.table_changes.len());
            for (i, ch) in req.table_changes.iter().enumerate() {
                let table_key = Self::iceberg_table_key_wh(
                    &req.warehouse,
                    &ch.namespace_levels,
                    &ch.table_name,
                );
                let entry = tables
                    .get(&table_key)
                    .ok_or_else(|| Status::not_found(format!("table_changes[{i}]: not found")))?;
                if entry.metadata_location != ch.current_metadata_location {
                    return Err(Status::failed_precondition(format!(
                        "table_changes[{i}]: metadata location mismatch: expected '{}', actual '{}'",
                        ch.current_metadata_location, entry.metadata_location
                    )));
                }
                let new_entry = IcebergTableEntry {
                    metadata_location: ch.new_metadata_location.clone(),
                    created_at: entry.created_at,
                    updated_at: now,
                    metadata_json: ch.new_metadata_json.clone(),
                    policy_json: entry.policy_json.clone(),
                };
                let old_bytes = entry.encode_to_vec();
                let new_bytes = new_entry.encode_to_vec();
                let resp = IcebergCommitTableResponse {
                    metadata_location: ch.new_metadata_location.clone(),
                    metadata_json: ch.new_metadata_json.clone(),
                };
                prepared.push(Prepared {
                    table_key,
                    old_bytes,
                    new_entry,
                    new_bytes,
                    resp,
                });
            }
            prepared
        };

        // Stage 2 — one Raft MultiCas for the whole batch. All ops land
        // atomically or none do; a stale expected on any row rolls the
        // whole transaction back.
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let ops: Vec<CasOp> = prepared
                .iter()
                .map(|p| CasOp {
                    table: CasTable::IcebergTables,
                    key: p.table_key.clone(),
                    expected: Some(p.old_bytes.clone()),
                    new_value: Some(p.new_bytes.clone()),
                })
                .collect();
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "iceberg-transaction".into(),
            };
            match raft.client_write(cmd).await {
                Ok(resp) => match resp.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::failed_precondition(format!(
                            "concurrent metadata update detected on table_changes {failed_indices:?}"
                        )));
                    }
                    other => {
                        error!(
                            "unexpected raft response for iceberg transaction: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit returned wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            // Non-Raft test path: emulate atomicity via the store's
            // multi-key CAS helper (one redb write-txn across all ops).
            // Not replicated; production deployments always take the
            // Raft branch above.
            let ops: Vec<(String, Vec<u8>, Vec<u8>)> = prepared
                .iter()
                .map(|p| {
                    (
                        p.table_key.clone(),
                        p.old_bytes.clone(),
                        p.new_bytes.clone(),
                    )
                })
                .collect();
            match store.cas_iceberg_tables_multi(&ops) {
                Ok(failed) if failed.is_empty() => {}
                Ok(failed) => {
                    return Err(Status::failed_precondition(format!(
                        "concurrent metadata update detected on table_changes {failed:?}"
                    )));
                }
                Err(e) => {
                    error!("cas_iceberg_tables_multi failed: {e}");
                    return Err(Status::internal("failed to commit transaction"));
                }
            }
        }

        // Stage 3 — mirror every successful commit into the in-memory
        // cache on this leader. `committed` vector mirrors the request
        // `table_changes` order so the caller can match results 1:1.
        let mut committed = Vec::with_capacity(prepared.len());
        {
            let mut tables = self.iceberg_tables.write();
            for p in prepared {
                tables.insert(p.table_key.clone(), p.new_entry);
                committed.push(p.resp);
            }
        }

        debug!(
            "Committed iceberg transaction: warehouse={} changes={}",
            req.warehouse,
            committed.len()
        );

        Ok(Response::new(IcebergCommitTransactionResponse {
            committed,
        }))
    }

    async fn iceberg_drop_table(
        &self,
        request: Request<IcebergDropTableRequest>,
    ) -> Result<Response<IcebergDropTableResponse>, Status> {
        let req = request.into_inner();
        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);

        let expected_bytes = {
            let tables = self.iceberg_tables.read();
            tables
                .get(&table_key)
                .cloned()
                .ok_or_else(|| Status::not_found("table not found"))?
                .encode_to_vec()
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IcebergTables,
                    key: table_key.clone(),
                    expected: Some(expected_bytes),
                    new_value: None,
                }],
                requested_by: "iceberg-drop-table".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("table changed since read; retry drop"));
                    }
                    other => {
                        error!("unexpected raft response for drop_table: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_iceberg_table(&table_key);
        }

        self.iceberg_tables.write().remove(&table_key);

        info!(
            "Dropped iceberg table: {:?}.{} (purge={})",
            req.namespace_levels, req.table_name, req.purge
        );

        Ok(Response::new(IcebergDropTableResponse { success: true }))
    }

    async fn iceberg_rename_table(
        &self,
        request: Request<IcebergRenameTableRequest>,
    ) -> Result<Response<IcebergRenameTableResponse>, Status> {
        let req = request.into_inner();
        let source = req
            .source
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("source is required"))?;
        let dest = req
            .destination
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("destination is required"))?;

        let src_key = Self::iceberg_table_key(&source.namespace_levels, &source.name);
        let dst_key = Self::iceberg_table_key(&dest.namespace_levels, &dest.name);

        // Verify destination namespace exists
        let dst_ns_key = Self::iceberg_ns_key(&dest.namespace_levels);
        if !self.iceberg_namespaces.read().contains_key(&dst_ns_key) {
            return Err(Status::not_found("destination namespace not found"));
        }

        // Rename is two ops in one atomic MultiCas: delete src + insert
        // dst. If either side conflicts the whole rename aborts.
        let (expected_src_bytes, entry_bytes, entry) = {
            let tables = self.iceberg_tables.read();
            let entry = tables
                .get(&src_key)
                .cloned()
                .ok_or_else(|| Status::not_found("source table not found"))?;
            if tables.contains_key(&dst_key) {
                return Err(Status::already_exists("destination table already exists"));
            }
            let bytes = entry.encode_to_vec();
            (bytes.clone(), bytes, entry)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![
                    CasOp {
                        table: CasTable::IcebergTables,
                        key: src_key.clone(),
                        expected: Some(expected_src_bytes),
                        new_value: None,
                    },
                    CasOp {
                        table: CasTable::IcebergTables,
                        key: dst_key.clone(),
                        expected: None,
                        new_value: Some(entry_bytes),
                    },
                ],
                requested_by: "iceberg-rename-table".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::aborted(format!(
                            "rename conflict at ops {failed_indices:?}; retry"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for rename_table: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_iceberg_table(&src_key);
            store.put_iceberg_table(&dst_key, &entry.encode_to_vec());
        }

        {
            let mut tables = self.iceberg_tables.write();
            tables.remove(&src_key);
            tables.insert(dst_key.clone(), entry);
        }

        info!(
            "Renamed iceberg table: {:?}.{} -> {:?}.{}",
            source.namespace_levels, source.name, dest.namespace_levels, dest.name
        );

        Ok(Response::new(IcebergRenameTableResponse { success: true }))
    }

    async fn iceberg_list_tables(
        &self,
        request: Request<IcebergListTablesRequest>,
    ) -> Result<Response<IcebergListTablesResponse>, Status> {
        let req = request.into_inner();
        let ns_key = Self::iceberg_ns_key_wh(&req.warehouse, &req.namespace_levels);

        // Verify namespace exists
        if !self.iceberg_namespaces.read().contains_key(&ns_key) {
            return Err(Status::not_found("namespace not found"));
        }

        let prefix = format!("{ns_key}\x00");

        let page_size = if req.page_size == 0 {
            100
        } else {
            req.page_size.min(1000)
        } as usize;

        let mut table_names: Vec<String> = self
            .iceberg_tables
            .read()
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .filter_map(|k| {
                let table_name = &k[prefix.len()..];
                if table_name.contains('\x00') {
                    None
                } else {
                    Some(table_name.to_string())
                }
            })
            .collect();
        table_names.sort();

        // Skip past page_token
        if !req.page_token.is_empty() {
            table_names.retain(|n| n.as_str() > req.page_token.as_str());
        }

        let has_more = table_names.len() > page_size;
        let table_names: Vec<String> = table_names.into_iter().take(page_size).collect();

        let next_page_token = if has_more {
            table_names.last().cloned().unwrap_or_default()
        } else {
            String::new()
        };

        let identifiers: Vec<IcebergTableIdentifier> = table_names
            .iter()
            .map(|name| IcebergTableIdentifier {
                namespace_levels: req.namespace_levels.clone(),
                name: name.clone(),
            })
            .collect();

        Ok(Response::new(IcebergListTablesResponse {
            identifiers,
            next_page_token,
        }))
    }

    async fn iceberg_table_exists(
        &self,
        request: Request<IcebergTableExistsRequest>,
    ) -> Result<Response<IcebergTableExistsResponse>, Status> {
        let req = request.into_inner();
        let table_key =
            Self::iceberg_table_key_wh(&req.warehouse, &req.namespace_levels, &req.table_name);
        let exists = self.iceberg_tables.read().contains_key(&table_key);
        Ok(Response::new(IcebergTableExistsResponse { exists }))
    }

    async fn iceberg_set_table_policy(
        &self,
        request: Request<IcebergSetTablePolicyRequest>,
    ) -> Result<Response<IcebergSetTablePolicyResponse>, Status> {
        let req = request.into_inner();
        let table_key = Self::iceberg_table_key(&req.namespace_levels, &req.table_name);

        let mut tables = self.iceberg_tables.write();
        let entry = tables
            .get_mut(&table_key)
            .ok_or_else(|| Status::not_found("table not found"))?;

        entry.policy_json = req.policy_json;

        if let Some(store) = &self.store {
            store.put_iceberg_table(&table_key, &entry.encode_to_vec());
        }

        info!(
            "Set policy on iceberg table: {:?}.{}",
            req.namespace_levels, req.table_name
        );

        Ok(Response::new(IcebergSetTablePolicyResponse {
            success: true,
        }))
    }

    async fn iceberg_get_table_policy(
        &self,
        request: Request<IcebergGetTablePolicyRequest>,
    ) -> Result<Response<IcebergGetTablePolicyResponse>, Status> {
        let req = request.into_inner();
        let table_key = Self::iceberg_table_key(&req.namespace_levels, &req.table_name);

        let entry = self
            .iceberg_tables
            .read()
            .get(&table_key)
            .cloned()
            .ok_or_else(|| Status::not_found("table not found"))?;

        Ok(Response::new(IcebergGetTablePolicyResponse {
            policy_json: entry.policy_json,
        }))
    }

    // ---- Group management ----

    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        let req = request.into_inner();

        if req.group_name.is_empty() {
            return Err(Status::invalid_argument("group_name is required"));
        }

        // Unique within its tenant (the ARN names both).
        let arn = format!(
            "arn:obio:iam::{}:group/{}",
            if req.tenant.is_empty() {
                "objectio"
            } else {
                &req.tenant
            },
            req.group_name
        );
        if self.groups.read().values().any(|g| g.arn == arn) {
            return Err(Status::already_exists(
                "group with this name already exists",
            ));
        }

        let group_id = Uuid::new_v4().to_string();
        let now = Self::current_timestamp();

        let group = StoredGroup {
            group_id: group_id.clone(),
            group_name: req.group_name.clone(),
            arn,
            member_user_ids: Vec::new(),
            created_at: now,
        };
        let group_bytes = bincode::serialize(&group)
            .map_err(|e| Status::internal(format!("group encode: {e}")))?;

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Groups,
                    key: group_id.clone(),
                    expected: None,
                    new_value: Some(group_bytes),
                }],
                requested_by: "create-group".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists(
                            "group_id collision (retry with fresh id)",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for create_group: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_group(&group_id, &group);
        }

        self.groups.write().insert(group_id.clone(), group.clone());
        info!("Created group: {}", req.group_name);

        Ok(Response::new(CreateGroupResponse {
            group: Some(GroupMeta {
                group_id: group.group_id,
                group_name: group.group_name,
                tenant: group_tenant(&group.arn),
                arn: group.arn,
                member_user_ids: group.member_user_ids,
                created_at: group.created_at,
            }),
        }))
    }

    async fn delete_group(
        &self,
        request: Request<DeleteGroupRequest>,
    ) -> Result<Response<DeleteGroupResponse>, Status> {
        let req = request.into_inner();
        let expected_bytes = {
            let groups = self.groups.read();
            let g = groups
                .get(&req.group_id)
                .ok_or_else(|| Status::not_found("group not found"))?;
            bincode::serialize(g).map_err(|e| Status::internal(format!("group encode: {e}")))?
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Groups,
                    key: req.group_id.clone(),
                    expected: Some(expected_bytes),
                    new_value: None,
                }],
                requested_by: "delete-group".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("group changed since read; retry delete"));
                    }
                    other => {
                        error!("unexpected raft response for delete_group: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_group(&req.group_id);
        }

        self.groups.write().remove(&req.group_id);
        info!("Deleted group: {}", req.group_id);

        Ok(Response::new(DeleteGroupResponse { success: true }))
    }

    async fn list_groups(
        &self,
        request: Request<ListGroupsRequest>,
    ) -> Result<Response<ListGroupsResponse>, Status> {
        let req = request.into_inner();
        let max_results = if req.max_results == 0 {
            100
        } else {
            req.max_results.min(1000)
        };

        let groups: Vec<GroupMeta> = self
            .groups
            .read()
            .values()
            .filter(|g| req.marker.is_empty() || g.group_id > req.marker)
            .take(max_results as usize + 1)
            .map(|g| GroupMeta {
                group_id: g.group_id.clone(),
                group_name: g.group_name.clone(),
                arn: g.arn.clone(),
                tenant: group_tenant(&g.arn),
                member_user_ids: g.member_user_ids.clone(),
                created_at: g.created_at,
            })
            .collect();

        let is_truncated = groups.len() > max_results as usize;
        let groups: Vec<GroupMeta> = groups.into_iter().take(max_results as usize).collect();
        let next_marker = groups
            .last()
            .map(|g| g.group_id.clone())
            .unwrap_or_default();

        Ok(Response::new(ListGroupsResponse {
            groups,
            next_marker: if is_truncated {
                next_marker
            } else {
                String::new()
            },
            is_truncated,
        }))
    }

    async fn add_user_to_group(
        &self,
        request: Request<AddUserToGroupRequest>,
    ) -> Result<Response<AddUserToGroupResponse>, Status> {
        let req = request.into_inner();

        if !self.users.read().contains_key(&req.user_id) {
            return Err(Status::not_found("user not found"));
        }

        let (expected_bytes, new_group) = {
            let groups = self.groups.read();
            let current = groups
                .get(&req.group_id)
                .cloned()
                .ok_or_else(|| Status::not_found("group not found"))?;
            if current.member_user_ids.contains(&req.user_id) {
                return Err(Status::already_exists("user already in group"));
            }
            let expected = bincode::serialize(&current)
                .map_err(|e| Status::internal(format!("group encode: {e}")))?;
            let mut new_group = current;
            new_group.member_user_ids.push(req.user_id.clone());
            (expected, new_group)
        };
        let new_bytes = bincode::serialize(&new_group)
            .map_err(|e| Status::internal(format!("group encode: {e}")))?;

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Groups,
                    key: req.group_id.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "add-user-to-group".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("group changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for add_user_to_group: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_group(&req.group_id, &new_group);
        }

        self.groups.write().insert(req.group_id.clone(), new_group);
        info!("Added user {} to group {}", req.user_id, req.group_id);
        Ok(Response::new(AddUserToGroupResponse { success: true }))
    }

    async fn remove_user_from_group(
        &self,
        request: Request<RemoveUserFromGroupRequest>,
    ) -> Result<Response<RemoveUserFromGroupResponse>, Status> {
        let req = request.into_inner();

        let (expected_bytes, new_group) = {
            let groups = self.groups.read();
            let current = groups
                .get(&req.group_id)
                .cloned()
                .ok_or_else(|| Status::not_found("group not found"))?;
            if !current.member_user_ids.contains(&req.user_id) {
                return Err(Status::not_found("user not in group"));
            }
            let expected = bincode::serialize(&current)
                .map_err(|e| Status::internal(format!("group encode: {e}")))?;
            let mut new_group = current;
            new_group.member_user_ids.retain(|id| id != &req.user_id);
            (expected, new_group)
        };
        let new_bytes = bincode::serialize(&new_group)
            .map_err(|e| Status::internal(format!("group encode: {e}")))?;

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Groups,
                    key: req.group_id.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "remove-user-from-group".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("group changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for remove_user_from_group: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_group(&req.group_id, &new_group);
        }

        self.groups.write().insert(req.group_id.clone(), new_group);
        info!("Removed user {} from group {}", req.user_id, req.group_id);
        Ok(Response::new(RemoveUserFromGroupResponse { success: true }))
    }

    async fn get_user_groups(
        &self,
        request: Request<GetUserGroupsRequest>,
    ) -> Result<Response<GetUserGroupsResponse>, Status> {
        let req = request.into_inner();

        // Validate user exists
        if !self.users.read().contains_key(&req.user_id) {
            return Err(Status::not_found("user not found"));
        }

        let groups: Vec<GroupMeta> = self
            .groups
            .read()
            .values()
            .filter(|g| g.member_user_ids.contains(&req.user_id))
            .map(|g| GroupMeta {
                group_id: g.group_id.clone(),
                group_name: g.group_name.clone(),
                arn: g.arn.clone(),
                tenant: group_tenant(&g.arn),
                member_user_ids: g.member_user_ids.clone(),
                created_at: g.created_at,
            })
            .collect();

        Ok(Response::new(GetUserGroupsResponse { groups }))
    }

    // ---- Data filter RPCs ----

    async fn create_data_filter(
        &self,
        request: Request<CreateDataFilterRequest>,
    ) -> Result<Response<CreateDataFilterResponse>, Status> {
        let req = request.into_inner();
        let filter_id = Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let filter = StoredDataFilter {
            filter_id: filter_id.clone(),
            filter_name: req.filter_name.clone(),
            namespace_levels: req.namespace_levels.clone(),
            table_name: req.table_name.clone(),
            principal_arns: req.principal_arns.clone(),
            allowed_columns: req.allowed_columns.clone(),
            excluded_columns: req.excluded_columns.clone(),
            row_filter_expression: req.row_filter_expression.clone(),
            created_at: now,
            updated_at: now,
        };

        let bytes = bincode::serialize(&filter)
            .map_err(|e| Status::internal(format!("data_filter encode: {e}")))?;
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DataFilters,
                    key: filter_id.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "create-data-filter".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("filter_id collision"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for create_data_filter: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_data_filter(&filter_id, &filter);
        }
        self.data_filters
            .write()
            .insert(filter_id.clone(), filter.clone());

        info!(
            filter_id = %filter.filter_id,
            filter_name = %filter.filter_name,
            table = %filter.table_name,
            "data_filter.created"
        );

        Ok(Response::new(CreateDataFilterResponse {
            filter: Some(IcebergDataFilter {
                filter_id: filter.filter_id,
                filter_name: filter.filter_name,
                namespace_levels: filter.namespace_levels,
                table_name: filter.table_name,
                principal_arns: filter.principal_arns,
                allowed_columns: filter.allowed_columns,
                excluded_columns: filter.excluded_columns,
                row_filter_expression: filter.row_filter_expression,
                created_at: filter.created_at,
                updated_at: filter.updated_at,
            }),
        }))
    }

    async fn list_data_filters(
        &self,
        request: Request<ListDataFiltersRequest>,
    ) -> Result<Response<ListDataFiltersResponse>, Status> {
        let req = request.into_inner();
        let ns_key = req.namespace_levels.join("\x00");

        let filters: Vec<IcebergDataFilter> = self
            .data_filters
            .read()
            .values()
            .filter(|f| f.namespace_levels.join("\x00") == ns_key && f.table_name == req.table_name)
            .map(|f| IcebergDataFilter {
                filter_id: f.filter_id.clone(),
                filter_name: f.filter_name.clone(),
                namespace_levels: f.namespace_levels.clone(),
                table_name: f.table_name.clone(),
                principal_arns: f.principal_arns.clone(),
                allowed_columns: f.allowed_columns.clone(),
                excluded_columns: f.excluded_columns.clone(),
                row_filter_expression: f.row_filter_expression.clone(),
                created_at: f.created_at,
                updated_at: f.updated_at,
            })
            .collect();

        Ok(Response::new(ListDataFiltersResponse { filters }))
    }

    async fn delete_data_filter(
        &self,
        request: Request<DeleteDataFilterRequest>,
    ) -> Result<Response<DeleteDataFilterResponse>, Status> {
        let req = request.into_inner();
        let expected = {
            let filters = self.data_filters.read();
            let Some(f) = filters.get(&req.filter_id) else {
                return Ok(Response::new(DeleteDataFilterResponse { success: false }));
            };
            bincode::serialize(f)
                .map_err(|e| Status::internal(format!("data_filter encode: {e}")))?
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DataFilters,
                    key: req.filter_id.clone(),
                    expected: Some(expected),
                    new_value: None,
                }],
                requested_by: "delete-data-filter".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("filter changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delete_data_filter: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_data_filter(&req.filter_id);
        }

        self.data_filters.write().remove(&req.filter_id);
        Ok(Response::new(DeleteDataFilterResponse { success: true }))
    }

    async fn get_data_filters_for_principal(
        &self,
        request: Request<GetDataFiltersForPrincipalRequest>,
    ) -> Result<Response<ListDataFiltersResponse>, Status> {
        let req = request.into_inner();
        let ns_key = req.namespace_levels.join("\x00");

        let all_arns: Vec<&str> = std::iter::once(req.principal_arn.as_str())
            .chain(req.group_arns.iter().map(String::as_str))
            .collect();

        let filters: Vec<IcebergDataFilter> = self
            .data_filters
            .read()
            .values()
            .filter(|f| {
                f.namespace_levels.join("\x00") == ns_key
                    && f.table_name == req.table_name
                    && f.principal_arns
                        .iter()
                        .any(|p| p == "*" || all_arns.iter().any(|a| a == p))
            })
            .map(|f| IcebergDataFilter {
                filter_id: f.filter_id.clone(),
                filter_name: f.filter_name.clone(),
                namespace_levels: f.namespace_levels.clone(),
                table_name: f.table_name.clone(),
                principal_arns: f.principal_arns.clone(),
                allowed_columns: f.allowed_columns.clone(),
                excluded_columns: f.excluded_columns.clone(),
                row_filter_expression: f.row_filter_expression.clone(),
                created_at: f.created_at,
                updated_at: f.updated_at,
            })
            .collect();

        Ok(Response::new(ListDataFiltersResponse { filters }))
    }

    // ============================================================
    // Delta Sharing Protocol
    // ============================================================

    async fn delta_create_share(
        &self,
        request: Request<DeltaCreateShareRequest>,
    ) -> Result<Response<DeltaCreateShareResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("share name is required"));
        }
        if self.delta_shares.read().contains_key(&req.name) {
            return Err(Status::already_exists("share already exists"));
        }
        let now = Self::current_timestamp();
        let entry = DeltaShareEntry {
            name: req.name.clone(),
            comment: req.comment,
            created_at: now as i64,
            tenant: req.tenant,
        };
        let bytes = entry.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DeltaShares,
                    key: req.name.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "delta-create-share".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("share already exists"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delta_create_share: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_delta_share(&req.name, &entry.encode_to_vec());
        }

        self.delta_shares
            .write()
            .insert(req.name.clone(), entry.clone());
        info!("Created Delta share: {}", req.name);
        Ok(Response::new(DeltaCreateShareResponse {
            share: Some(entry),
        }))
    }

    async fn delta_get_share(
        &self,
        request: Request<DeltaGetShareRequest>,
    ) -> Result<Response<DeltaGetShareResponse>, Status> {
        let req = request.into_inner();
        let entry = self
            .delta_shares
            .read()
            .get(&req.name)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("share '{}' not found", req.name)))?;
        Ok(Response::new(DeltaGetShareResponse { share: Some(entry) }))
    }

    async fn delta_list_shares(
        &self,
        request: Request<DeltaListSharesRequest>,
    ) -> Result<Response<DeltaListSharesResponse>, Status> {
        let req = request.into_inner();
        let shares: Vec<DeltaShareEntry> = self
            .delta_shares
            .read()
            .values()
            .filter(|s| req.tenant.is_empty() || s.tenant == req.tenant)
            .cloned()
            .collect();
        Ok(Response::new(DeltaListSharesResponse {
            shares,
            next_page_token: String::new(),
        }))
    }

    async fn delta_drop_share(
        &self,
        request: Request<DeltaDropShareRequest>,
    ) -> Result<Response<DeltaDropShareResponse>, Status> {
        let req = request.into_inner();
        // Multi-op MultiCas: the share row + every DeltaShareTableEntry
        // whose key prefix matches. All removed atomically — no orphan
        // table rows pointing at a dropped share.
        let share_prefix = format!("{}\x00", req.name);
        let (expected_share_bytes, table_deletes) = {
            let shares = self.delta_shares.read();
            let Some(share) = shares.get(&req.name) else {
                return Ok(Response::new(DeltaDropShareResponse { success: false }));
            };
            let share_bytes = share.encode_to_vec();
            let tables = self.delta_tables.read();
            let deletes: Vec<(String, Vec<u8>)> = tables
                .iter()
                .filter(|(k, _)| k.starts_with(&share_prefix))
                .map(|(k, v)| (k.clone(), v.encode_to_vec()))
                .collect();
            (share_bytes, deletes)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = Vec::with_capacity(1 + table_deletes.len());
            ops.push(CasOp {
                table: CasTable::DeltaShares,
                key: req.name.clone(),
                expected: Some(expected_share_bytes),
                new_value: None,
            });
            for (tk, tb) in &table_deletes {
                ops.push(CasOp {
                    table: CasTable::DeltaTables,
                    key: tk.clone(),
                    expected: Some(tb.clone()),
                    new_value: None,
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delta-drop-share".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::aborted(format!(
                            "share or table changed mid-drop; retry (conflicts at {failed_indices:?})"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for delta_drop_share: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_delta_share(&req.name);
            for (tk, _) in &table_deletes {
                store.delete_delta_table(tk);
            }
        }

        self.delta_shares.write().remove(&req.name);
        self.delta_tables
            .write()
            .retain(|k, _| !k.starts_with(&share_prefix));
        info!("Dropped Delta share: {}", req.name);
        Ok(Response::new(DeltaDropShareResponse { success: true }))
    }

    async fn delta_add_table(
        &self,
        request: Request<DeltaAddTableRequest>,
    ) -> Result<Response<DeltaAddTableResponse>, Status> {
        let req = request.into_inner();
        if !self.delta_shares.read().contains_key(&req.share) {
            return Err(Status::not_found(format!(
                "share '{}' not found",
                req.share
            )));
        }
        let table_key = format!("{}\x00{}\x00{}", req.share, req.schema, req.table_name);
        let share_id = Uuid::new_v4().to_string();
        let entry = DeltaShareTableEntry {
            share: req.share.clone(),
            schema: req.schema.clone(),
            table_name: req.table_name.clone(),
            share_id: share_id.clone(),
            table_type: req.table_type.clone(),
            bucket: req.bucket.clone(),
            path: req.path.clone(),
            warehouse: req.warehouse.clone(),
            namespace: req.namespace.clone(),
        };
        let bytes = entry.encode_to_vec();
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DeltaTables,
                    key: table_key.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "delta-add-table".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("table already in share"));
                    }
                    other => {
                        error!("unexpected raft response for delta_add_table: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_delta_table(&table_key, &entry.encode_to_vec());
        }

        self.delta_tables
            .write()
            .insert(table_key.clone(), entry.clone());
        info!(
            "Added table {}.{} to Delta share {}",
            req.schema, req.table_name, req.share
        );
        Ok(Response::new(DeltaAddTableResponse { table: Some(entry) }))
    }

    async fn delta_remove_table(
        &self,
        request: Request<DeltaRemoveTableRequest>,
    ) -> Result<Response<DeltaRemoveTableResponse>, Status> {
        let req = request.into_inner();
        let table_key = format!("{}\x00{}\x00{}", req.share, req.schema, req.table_name);
        let expected = self
            .delta_tables
            .read()
            .get(&table_key)
            .map(|v| v.encode_to_vec());
        if expected.is_none() {
            return Ok(Response::new(DeltaRemoveTableResponse { success: false }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DeltaTables,
                    key: table_key.clone(),
                    expected,
                    new_value: None,
                }],
                requested_by: "delta-remove-table".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("table changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delta_remove_table: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_delta_table(&table_key);
        }

        self.delta_tables.write().remove(&table_key);
        Ok(Response::new(DeltaRemoveTableResponse { success: true }))
    }

    async fn delta_list_tables(
        &self,
        request: Request<DeltaListTablesRequest>,
    ) -> Result<Response<DeltaListTablesResponse>, Status> {
        let req = request.into_inner();
        let tables: Vec<DeltaShareTableEntry> = self
            .delta_tables
            .read()
            .iter()
            .filter(|(k, _)| {
                k.starts_with(&format!("{}\x00", req.share))
                    && (req.schema.is_empty()
                        || k.starts_with(&format!("{}\x00{}\x00", req.share, req.schema)))
            })
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(DeltaListTablesResponse {
            tables,
            next_page_token: String::new(),
        }))
    }

    async fn delta_create_recipient(
        &self,
        request: Request<DeltaCreateRecipientRequest>,
    ) -> Result<Response<DeltaCreateRecipientResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("recipient name is required"));
        }
        // Generate a cryptographically random bearer token (32 bytes → 64 hex chars)
        let raw_token = {
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            hex::encode(bytes)
        };
        // Store SHA-256 hash of the token (never store raw)
        let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));

        let now = Self::current_timestamp();
        let entry = DeltaRecipientEntry {
            name: req.name.clone(),
            token_hash: token_hash.clone(),
            shares: req.shares,
            created_at: now as i64,
        };

        if self.delta_recipients.read().contains_key(&req.name) {
            return Err(Status::already_exists("recipient already exists"));
        }
        let bytes = entry.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DeltaRecipients,
                    key: req.name.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "delta-create-recipient".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("recipient already exists"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delta_create_recipient: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_delta_recipient(&req.name, &entry.encode_to_vec());
        }

        self.delta_recipients
            .write()
            .insert(req.name.clone(), entry.clone());
        self.delta_token_index
            .write()
            .insert(token_hash.clone(), req.name.clone());
        info!("Created Delta recipient: {}", req.name);
        Ok(Response::new(DeltaCreateRecipientResponse {
            recipient: Some(entry),
            raw_token,
        }))
    }

    async fn delta_get_recipient_by_token(
        &self,
        request: Request<DeltaGetRecipientByTokenRequest>,
    ) -> Result<Response<DeltaGetRecipientByTokenResponse>, Status> {
        let req = request.into_inner();
        let token_hash = hex::encode(Sha256::digest(req.raw_token.as_bytes()));
        let recipient_name = self.delta_token_index.read().get(&token_hash).cloned();
        match recipient_name {
            Some(name) => {
                let entry = self.delta_recipients.read().get(&name).cloned();
                Ok(Response::new(DeltaGetRecipientByTokenResponse {
                    recipient: entry,
                    found: true,
                }))
            }
            None => Ok(Response::new(DeltaGetRecipientByTokenResponse {
                recipient: None,
                found: false,
            })),
        }
    }

    async fn delta_list_recipients(
        &self,
        _request: Request<DeltaListRecipientsRequest>,
    ) -> Result<Response<DeltaListRecipientsResponse>, Status> {
        let recipients: Vec<DeltaRecipientEntry> =
            self.delta_recipients.read().values().cloned().collect();
        Ok(Response::new(DeltaListRecipientsResponse {
            recipients,
            next_page_token: String::new(),
        }))
    }

    async fn delta_drop_recipient(
        &self,
        request: Request<DeltaDropRecipientRequest>,
    ) -> Result<Response<DeltaDropRecipientResponse>, Status> {
        let req = request.into_inner();
        let (expected, token_hash) = {
            let recipients = self.delta_recipients.read();
            let Some(entry) = recipients.get(&req.name) else {
                return Ok(Response::new(DeltaDropRecipientResponse { success: false }));
            };
            (entry.encode_to_vec(), entry.token_hash.clone())
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::DeltaRecipients,
                    key: req.name.clone(),
                    expected: Some(expected),
                    new_value: None,
                }],
                requested_by: "delta-drop-recipient".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("recipient changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delta_drop_recipient: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_delta_recipient(&req.name);
        }

        self.delta_recipients.write().remove(&req.name);
        self.delta_token_index.write().remove(&token_hash);
        info!("Dropped Delta recipient: {}", req.name);
        Ok(Response::new(DeltaDropRecipientResponse { success: true }))
    }

    // ============ Cluster Configuration ============

    async fn get_config(
        &self,
        request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        let req = request.into_inner();
        let config = self.config.read();
        match config.get(&req.key) {
            Some(entry) => Ok(Response::new(GetConfigResponse {
                entry: Some(entry.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetConfigResponse {
                entry: None,
                found: false,
            })),
        }
    }

    async fn set_config(
        &self,
        request: Request<SetConfigRequest>,
    ) -> Result<Response<SetConfigResponse>, Status> {
        let req = request.into_inner();

        if req.key.is_empty() {
            return Err(Status::invalid_argument("config key is required"));
        }
        if req.key == objectio_common::version::ACTIVE_LEVEL_KEY {
            return Err(Status::permission_denied(
                "the active format level is raised only by finalizing an upgrade",
            ));
        }

        // Consensus path: if Raft is wired, every config write has to
        // commit through the log. Non-leader nodes reject with a leader
        // hint so the client (gateway) can retry against the right pod.
        if let Some(raft) = self.raft_handle() {
            match raft
                .client_write(objectio_meta_store::MetaCommand::SetConfig {
                    key: req.key.clone(),
                    value: req.value.clone(),
                    updated_by: req.updated_by.clone(),
                })
                .await
            {
                Ok(resp) => {
                    // The state machine wrote to the CONFIG redb table
                    // with a monotonic version inside apply. Mirror that
                    // entry into the in-memory map on the leader so
                    // local reads see the new value without a redb hit.
                    // Followers pick it up via apply on their own copy,
                    // but their in-memory map is not updated until R1's
                    // follow-up adds an apply listener.
                    let version = match resp.data {
                        objectio_meta_store::MetaResponse::ConfigSet { version } => version,
                        _ => 0,
                    };
                    let now = Self::current_timestamp();
                    let entry = ConfigEntry {
                        key: req.key.clone(),
                        value: req.value.clone(),
                        updated_at: now,
                        updated_by: req.updated_by.clone(),
                        version,
                    };
                    self.config.write().insert(req.key.clone(), entry.clone());
                    self.config_version
                        .store(version, std::sync::atomic::Ordering::SeqCst);

                    info!(
                        "Config set via Raft: key={} version={} log_id={:?}",
                        req.key, version, resp.log_id
                    );
                    return Ok(Response::new(SetConfigResponse { entry: Some(entry) }));
                }
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        }

        // Legacy direct-redb path — tests without a Raft handle fall
        // through here; production deployments always have Raft set.
        let version = self
            .config_version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let now = Self::current_timestamp();

        let entry = ConfigEntry {
            key: req.key.clone(),
            value: req.value,
            updated_at: now,
            updated_by: req.updated_by,
            version,
        };

        if let Some(store) = &self.store {
            store.put_config(&req.key, &entry.encode_to_vec());
        }
        self.config.write().insert(req.key.clone(), entry.clone());

        info!(
            "Config set (legacy path): key={}, version={}",
            req.key, version
        );
        Ok(Response::new(SetConfigResponse { entry: Some(entry) }))
    }

    async fn delete_config(
        &self,
        request: Request<DeleteConfigRequest>,
    ) -> Result<Response<DeleteConfigResponse>, Status> {
        let req = request.into_inner();
        if req.key == objectio_common::version::ACTIVE_LEVEL_KEY {
            return Err(Status::permission_denied(
                "the active format level is raised only by finalizing an upgrade",
            ));
        }

        if let Some(raft) = self.raft_handle() {
            match raft
                .client_write(objectio_meta_store::MetaCommand::DeleteConfig {
                    key: req.key.clone(),
                })
                .await
            {
                Ok(resp) => {
                    let existed = matches!(
                        resp.data,
                        objectio_meta_store::MetaResponse::ConfigDeleted { existed: true }
                    );
                    if existed {
                        self.config.write().remove(&req.key);
                        info!(
                            "Config deleted via Raft: key={} log_id={:?}",
                            req.key, resp.log_id
                        );
                    }
                    return Ok(Response::new(DeleteConfigResponse { success: existed }));
                }
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        }

        // Legacy direct path.
        let removed = self.config.write().remove(&req.key).is_some();
        if removed {
            if let Some(store) = &self.store {
                store.delete_config(&req.key);
            }
            info!("Config deleted (legacy path): key={}", req.key);
        }

        Ok(Response::new(DeleteConfigResponse { success: removed }))
    }

    async fn set_osd_admin_state(
        &self,
        request: Request<SetOsdAdminStateRequest>,
    ) -> Result<Response<SetOsdAdminStateResponse>, Status> {
        let req = request.into_inner();

        // node_id must be 16 bytes (UUID).
        let node_id: [u8; 16] = req
            .node_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("node_id must be 16 bytes"))?;

        // Map wire enum → internal enum. Proto's numeric `i32` reaches us
        // here; rely on the generated accessor to handle unknown values.
        // prost prefixes the proto enum variants with the enum name; map
        // them back to our internal OsdAdminState.
        let state = match objectio_proto::metadata::OsdAdminState::try_from(req.state) {
            Ok(objectio_proto::metadata::OsdAdminState::OsdAdminIn) => {
                objectio_common::OsdAdminState::In
            }
            Ok(objectio_proto::metadata::OsdAdminState::OsdAdminOut) => {
                objectio_common::OsdAdminState::Out
            }
            Ok(objectio_proto::metadata::OsdAdminState::OsdAdminDraining) => {
                objectio_common::OsdAdminState::Draining
            }
            Err(_) => {
                return Err(Status::invalid_argument(format!(
                    "unknown OsdAdminState: {}",
                    req.state
                )));
            }
        };

        let requested_by = if req.requested_by.is_empty() {
            "meta".to_string()
        } else {
            req.requested_by.clone()
        };

        // A drained OSD comes back only once it's been wiped: until then it
        // holds stale copies of metadata (objects deleted since would
        // reappear) and shards nothing refers to.
        let purge = self.purge_state(node_id);
        if state != objectio_common::OsdAdminState::Out
            && purge.as_deref() == Some(crate::drain_observer::PURGE_PENDING)
        {
            return Err(Status::failed_precondition(
                "this OSD was drained and is still being purged; it can rejoin once that's done",
            ));
        }

        // Raft is the only write path. set_osd_admin_state persists to
        // OSD_NODES inside apply, which every follower also observes.
        let raft = self.raft_handle().ok_or_else(|| {
            Status::failed_precondition(
                "raft is not initialized — run POST /init on meta admin port",
            )
        })?;

        let resp = raft
            .client_write(objectio_meta_store::MetaCommand::SetOsdAdminState {
                node_id,
                state,
                requested_by,
            })
            .await
            .map_err(|e| raft_write_to_status(&e))?;

        let (found, changed) = match resp.data {
            objectio_meta_store::MetaResponse::OsdAdminStateSet { found, changed } => {
                (found, changed)
            }
            _ => (false, false),
        };

        // Mirror the change into the in-memory OsdNode list so this
        // process's topology rebuild sees the new state without a redb
        // re-read. (Followers do this via their own apply — deferred
        // until the apply-listener lands in a later phase.)
        if found && changed {
            let mut nodes = self.osd_nodes.write();
            if let Some(n) = nodes.iter_mut().find(|n| n.node_id == node_id) {
                n.admin_state = state;
            }
        }

        // Rebuild the placement topology so the next `place_object`
        // call respects the new state immediately.
        if found && changed {
            let snapshot = self.osd_nodes.read().clone();
            for osd in &snapshot {
                self.refresh_topology_node(osd);
            }
            info!(
                "OSD {} admin_state → {} (via Raft, log_id={:?})",
                hex::encode(node_id),
                state.as_str(),
                resp.log_id
            );
        } else if !found {
            warn!(
                "set_osd_admin_state: no OSD with node_id={}",
                hex::encode(node_id)
            );
        }

        // Back in service after a purge: it starts clean, and a later
        // drain starts a new record.
        if found
            && state != objectio_common::OsdAdminState::Out
            && purge.as_deref() == Some(crate::drain_observer::PURGE_DONE)
            && let Err(e) = self.set_purge_state(node_id, None).await
        {
            warn!("clearing purge state for {}: {e}", hex::encode(node_id));
        }

        Ok(Response::new(SetOsdAdminStateResponse {
            found,
            changed,
            effective: req.state,
        }))
    }

    async fn get_drain_status(
        &self,
        _request: Request<GetDrainStatusRequest>,
    ) -> Result<Response<GetDrainStatusResponse>, Status> {
        let snapshot = self.drain_statuses_snapshot();
        let drains: Vec<ProtoDrainStatus> = snapshot
            .into_iter()
            .map(|(node_id, p)| ProtoDrainStatus {
                node_id: node_id.to_vec(),
                shards_remaining: p.shards_remaining,
                initial_shards: p.initial_shards,
                shards_migrated: p.shards_migrated,
                updated_at: p.updated_at,
                last_error: p.last_error,
            })
            .collect();
        Ok(Response::new(GetDrainStatusResponse { drains }))
    }

    async fn get_rebalance_status(
        &self,
        _request: Request<GetRebalanceStatusRequest>,
    ) -> Result<Response<GetRebalanceStatusResponse>, Status> {
        let p = self.rebalance_progress_snapshot();
        // `paused` is sourced from the live config each request; the
        // cached field is kept for the reconciler's fast path.
        let paused = self.is_rebalance_paused();
        // `paused` merges two sources: the live `rebalance/paused`
        // config (legacy gate) and `balancer/paused` (PG engine). The
        // balancer itself mirrors its flag into `p.paused`, so OR'ing
        // with `is_rebalance_paused()` gives a single "anything
        // paused" signal to the UI.
        let paused = paused || p.paused;
        Ok(Response::new(GetRebalanceStatusResponse {
            started: p.started,
            paused,
            last_sweep_at: p.last_sweep_at,
            scanned_this_pass: p.scanned_this_pass,
            drifts_seen_this_pass: p.drifts_seen_this_pass,
            shards_rebalanced_total: p.shards_rebalanced_total,
            last_error: p.last_error,
            pgs_moved_total: p.pgs_moved_total,
            pg_candidates_last_tick: p.pg_candidates_last_tick,
            pgs_scanned_last_tick: p.pgs_scanned_last_tick,
        }))
    }

    async fn list_config(
        &self,
        request: Request<ListConfigRequest>,
    ) -> Result<Response<ListConfigResponse>, Status> {
        let req = request.into_inner();
        let config = self.config.read();

        let entries: Vec<ConfigEntry> = if req.prefix.is_empty() {
            config.values().cloned().collect()
        } else {
            config
                .iter()
                .filter(|(k, _)| k.starts_with(&req.prefix))
                .map(|(_, v)| v.clone())
                .collect()
        };

        Ok(Response::new(ListConfigResponse { entries }))
    }

    // ============ Server Pools ============

    async fn create_pool(
        &self,
        request: Request<CreatePoolRequest>,
    ) -> Result<Response<CreatePoolResponse>, Status> {
        let pool = request
            .into_inner()
            .pool
            .ok_or_else(|| Status::invalid_argument("missing pool"))?;
        if pool.name.is_empty() {
            return Err(Status::invalid_argument("pool name is required"));
        }
        if self.pools.read().contains_key(&pool.name) {
            return Err(Status::already_exists(format!(
                "pool '{}' already exists",
                pool.name
            )));
        }
        let mut pool = pool;
        pool.created_at = Self::current_timestamp();
        pool.updated_at = pool.created_at;
        let bytes = pool.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Pools,
                    key: pool.name.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "create-pool".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("pool already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_pool: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_pool(&pool.name, &pool.encode_to_vec());
        }

        self.pools.write().insert(pool.name.clone(), pool.clone());
        info!("Created pool: {}", pool.name);

        // Pre-allocate placement groups if the pool opted in. Done
        // after the pool row is committed so a partial failure here
        // leaves a pool with pg_count>0 but no PGs — the balancer
        // (Phase 4) will detect that and regenerate. Fatal errors
        // from allocation surface as status; gateway retries.
        if pool.pg_count > 0
            && let Err(e) = self.preallocate_placement_groups(&pool).await
        {
            warn!(
                "pool '{}' created but PG pre-allocation failed: {}",
                pool.name, e
            );
        }

        Ok(Response::new(CreatePoolResponse { pool: Some(pool) }))
    }

    async fn get_pool(
        &self,
        request: Request<GetPoolRequest>,
    ) -> Result<Response<GetPoolResponse>, Status> {
        let name = request.into_inner().name;
        let pools = self.pools.read();
        match pools.get(&name) {
            Some(pool) => Ok(Response::new(GetPoolResponse {
                pool: Some(pool.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetPoolResponse {
                pool: None,
                found: false,
            })),
        }
    }

    async fn list_pools(
        &self,
        _request: Request<ListPoolsRequest>,
    ) -> Result<Response<ListPoolsResponse>, Status> {
        let pools = self.pools.read();
        Ok(Response::new(ListPoolsResponse {
            pools: pools.values().cloned().collect(),
        }))
    }

    async fn update_pool(
        &self,
        request: Request<UpdatePoolRequest>,
    ) -> Result<Response<UpdatePoolResponse>, Status> {
        let mut pool = request
            .into_inner()
            .pool
            .ok_or_else(|| Status::invalid_argument("missing pool"))?;
        let expected_bytes = {
            let pools = self.pools.read();
            pools
                .get(&pool.name)
                .ok_or_else(|| Status::not_found(format!("pool '{}' not found", pool.name)))?
                .encode_to_vec()
        };
        pool.updated_at = Self::current_timestamp();
        let new_bytes = pool.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Pools,
                    key: pool.name.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "update-pool".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("pool changed since read; retry update"));
                    }
                    other => {
                        error!("unexpected raft response for update_pool: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_pool(&pool.name, &pool.encode_to_vec());
        }

        self.pools.write().insert(pool.name.clone(), pool.clone());
        info!("Updated pool: {}", pool.name);
        Ok(Response::new(UpdatePoolResponse { pool: Some(pool) }))
    }

    async fn delete_pool(
        &self,
        request: Request<DeletePoolRequest>,
    ) -> Result<Response<DeletePoolResponse>, Status> {
        let name = request.into_inner().name;
        if name == "default" {
            return Err(Status::invalid_argument("cannot delete the default pool"));
        }
        // Its buckets' objects were placed by it: without it they'd be
        // looked for where the default placement puts them.
        let users: Vec<String> = self
            .buckets
            .read()
            .values()
            .filter(|b| b.pool == name)
            .map(|b| b.name.clone())
            .take(5)
            .collect();
        if !users.is_empty() {
            return Err(Status::failed_precondition(format!(
                "pool '{name}' holds buckets ({}{}); delete them first",
                users.join(", "),
                if users.len() == 5 { ", ..." } else { "" }
            )));
        }
        // Tenants that default to it, or may choose it, are reconfigured
        // first.
        if let Some(t) = self
            .tenants
            .read()
            .values()
            .find(|t| t.default_pool == name || t.allowed_pools.contains(&name))
        {
            return Err(Status::failed_precondition(format!(
                "tenant '{}' refers to pool '{name}'; change its pools first",
                t.name
            )));
        }
        let expected_bytes = self.pools.read().get(&name).map(|p| p.encode_to_vec());
        if expected_bytes.is_none() {
            return Ok(Response::new(DeletePoolResponse { success: false }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Pools,
                    key: name.clone(),
                    expected: expected_bytes,
                    new_value: None,
                }],
                requested_by: "delete-pool".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("pool changed since read; retry delete"));
                    }
                    other => {
                        error!("unexpected raft response for delete_pool: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_pool(&name);
        }

        self.pools.write().remove(&name);
        info!("Deleted pool: {}", name);
        Ok(Response::new(DeletePoolResponse { success: true }))
    }

    // ============ Placement groups ============
    //
    // Balancer owns writes (via CasTable::PlacementGroups MultiCas).
    // Gateway only reads, so only Get + List are exposed for now.

    async fn get_placement_group(
        &self,
        request: Request<GetPlacementGroupRequest>,
    ) -> Result<Response<GetPlacementGroupResponse>, Status> {
        let req = request.into_inner();
        let pg = self.placement_group(&req.pool, req.pg_id);
        let found = pg.is_some();
        Ok(Response::new(GetPlacementGroupResponse { pg, found }))
    }

    async fn list_placement_groups(
        &self,
        request: Request<ListPlacementGroupsRequest>,
    ) -> Result<Response<ListPlacementGroupsResponse>, Status> {
        let req = request.into_inner();
        let max = if req.max_results == 0 {
            1000usize
        } else {
            (req.max_results as usize).min(10_000)
        };
        let map = self.placement_groups.read();
        let mut pgs: Vec<PlacementGroup> = map
            .iter()
            .filter(|((p, id), _)| p == &req.pool && *id > req.start_after_pg_id)
            .map(|(_, v)| v.clone())
            .collect();
        pgs.sort_by_key(|p| p.pg_id);
        let truncated = pgs.len() > max;
        pgs.truncate(max);
        let next_pg_id = if truncated {
            pgs.last().map(|p| p.pg_id).unwrap_or(0)
        } else {
            0
        };
        Ok(Response::new(ListPlacementGroupsResponse {
            pgs,
            next_pg_id,
        }))
    }

    // ============ Tenants ============

    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<CreateTenantResponse>, Status> {
        let tenant = request
            .into_inner()
            .tenant
            .ok_or_else(|| Status::invalid_argument("missing tenant"))?;
        if tenant.name.is_empty() {
            return Err(Status::invalid_argument("tenant name is required"));
        }
        if self.tenants.read().contains_key(&tenant.name) {
            return Err(Status::already_exists(format!(
                "tenant '{}' already exists",
                tenant.name
            )));
        }
        let mut tenant = tenant;
        tenant.created_at = Self::current_timestamp();
        tenant.updated_at = tenant.created_at;
        let bytes = tenant.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Tenants,
                    key: tenant.name.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "create-tenant".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("tenant already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_tenant: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_tenant(&tenant.name, &tenant.encode_to_vec());
        }

        self.tenants
            .write()
            .insert(tenant.name.clone(), tenant.clone());
        info!("Created tenant: {}", tenant.name);
        Ok(Response::new(CreateTenantResponse {
            tenant: Some(tenant),
        }))
    }

    async fn get_tenant(
        &self,
        request: Request<GetTenantRequest>,
    ) -> Result<Response<GetTenantResponse>, Status> {
        let name = request.into_inner().name;
        let tenants = self.tenants.read();
        match tenants.get(&name) {
            Some(t) => Ok(Response::new(GetTenantResponse {
                tenant: Some(t.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetTenantResponse {
                tenant: None,
                found: false,
            })),
        }
    }

    async fn list_tenants(
        &self,
        _request: Request<ListTenantsRequest>,
    ) -> Result<Response<ListTenantsResponse>, Status> {
        let tenants = self.tenants.read();
        Ok(Response::new(ListTenantsResponse {
            tenants: tenants.values().cloned().collect(),
        }))
    }

    async fn update_tenant(
        &self,
        request: Request<UpdateTenantRequest>,
    ) -> Result<Response<UpdateTenantResponse>, Status> {
        let mut tenant = request
            .into_inner()
            .tenant
            .ok_or_else(|| Status::invalid_argument("missing tenant"))?;
        let expected_bytes = {
            let tenants = self.tenants.read();
            tenants
                .get(&tenant.name)
                .ok_or_else(|| Status::not_found(format!("tenant '{}' not found", tenant.name)))?
                .encode_to_vec()
        };
        tenant.updated_at = Self::current_timestamp();
        let new_bytes = tenant.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Tenants,
                    key: tenant.name.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "update-tenant".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("tenant changed since read; retry update"));
                    }
                    other => {
                        error!("unexpected raft response for update_tenant: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_tenant(&tenant.name, &tenant.encode_to_vec());
        }

        self.tenants
            .write()
            .insert(tenant.name.clone(), tenant.clone());
        info!("Updated tenant: {}", tenant.name);
        Ok(Response::new(UpdateTenantResponse {
            tenant: Some(tenant),
        }))
    }

    async fn delete_tenant(
        &self,
        request: Request<DeleteTenantRequest>,
    ) -> Result<Response<DeleteTenantResponse>, Status> {
        let name = request.into_inner().name;
        let has_buckets = self.buckets.read().values().any(|b| b.tenant == name);
        if has_buckets {
            return Err(Status::failed_precondition(format!(
                "tenant '{}' still has buckets — delete them first",
                name
            )));
        }
        let expected_bytes = self.tenants.read().get(&name).map(|t| t.encode_to_vec());
        if expected_bytes.is_none() {
            return Ok(Response::new(DeleteTenantResponse { success: false }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Tenants,
                    key: name.clone(),
                    expected: expected_bytes,
                    new_value: None,
                }],
                requested_by: "delete-tenant".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("tenant changed since read; retry delete"));
                    }
                    other => {
                        error!("unexpected raft response for delete_tenant: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_tenant(&name);
        }

        self.tenants.write().remove(&name);
        info!("Deleted tenant: {}", name);
        Ok(Response::new(DeleteTenantResponse { success: true }))
    }

    // ============================================================
    // ============================================================
    // Iceberg Warehouse Management
    // ============================================================

    async fn iceberg_create_warehouse(
        &self,
        request: Request<IcebergCreateWarehouseRequest>,
    ) -> Result<Response<IcebergCreateWarehouseResponse>, Status> {
        let req = request.into_inner();

        if req.name.is_empty() {
            return Err(Status::invalid_argument("warehouse name is required"));
        }

        // Check if warehouse already exists
        if self.iceberg_warehouses.read().contains_key(&req.name) {
            return Err(Status::already_exists(format!(
                "warehouse '{}' already exists",
                req.name
            )));
        }

        let bucket_name = format!("iceberg-{}", req.name);
        let location = format!("s3://{}", bucket_name);
        let now = Self::current_timestamp();

        // Create the backing bucket
        if self.buckets.read().contains_key(&bucket_name) {
            return Err(Status::already_exists(format!(
                "bucket '{}' already exists",
                bucket_name
            )));
        }

        let bucket = BucketMeta {
            dedup: None,
            name: bucket_name.clone(),
            owner: "system".to_string(),
            created_at: now,
            storage_class: "STANDARD".to_string(),
            versioning: VersioningState::VersioningDisabled.into(),
            pool: String::new(),
            tenant: req.tenant.clone(),
            quota_bytes: 0,
            quota_objects: 0,
            object_lock: None,
        };
        let bucket_bytes = bucket.encode_to_vec();

        let warehouse = IcebergWarehouse {
            name: req.name.clone(),
            bucket: bucket_name.clone(),
            location,
            tenant: req.tenant.clone(),
            created_at: now,
            properties: req.properties.clone(),
        };
        let warehouse_bytes = warehouse.encode_to_vec();

        // Two-op atomic MultiCas: warehouse row + backing bucket. If
        // either side conflicts the whole creation aborts, avoiding
        // the half-state where a warehouse exists without its bucket
        // (or a lingering orphan bucket from a failed warehouse create).
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![
                    CasOp {
                        table: CasTable::IcebergWarehouses,
                        key: req.name.clone(),
                        expected: None,
                        new_value: Some(warehouse_bytes),
                    },
                    CasOp {
                        table: CasTable::Buckets,
                        key: bucket_name.clone(),
                        expected: None,
                        new_value: Some(bucket_bytes),
                    },
                ],
                requested_by: "iceberg-create-warehouse".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::already_exists(format!(
                            "warehouse or backing bucket already exists (conflicts at {failed_indices:?})"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for create_warehouse: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&bucket_name, &bucket);
            store.put_warehouse(&req.name, &warehouse_bytes);
        }

        self.buckets
            .write()
            .insert(bucket_name.clone(), bucket.clone());
        self.iceberg_warehouses
            .write()
            .insert(req.name.clone(), warehouse.clone());

        info!(
            "Created warehouse: {} (bucket: {})",
            req.name, warehouse.bucket
        );

        Ok(Response::new(IcebergCreateWarehouseResponse {
            warehouse: Some(warehouse),
        }))
    }

    async fn iceberg_list_warehouses(
        &self,
        request: Request<IcebergListWarehousesRequest>,
    ) -> Result<Response<IcebergListWarehousesResponse>, Status> {
        let req = request.into_inner();
        let warehouses: Vec<IcebergWarehouse> = self
            .iceberg_warehouses
            .read()
            .values()
            .filter(|w| req.tenant.is_empty() || w.tenant == req.tenant)
            .cloned()
            .collect();
        Ok(Response::new(IcebergListWarehousesResponse { warehouses }))
    }

    async fn iceberg_delete_warehouse(
        &self,
        request: Request<IcebergDeleteWarehouseRequest>,
    ) -> Result<Response<IcebergDeleteWarehouseResponse>, Status> {
        let name = request.into_inner().name;

        let (wh, wh_bytes, bucket_bytes) = {
            let warehouses = self.iceberg_warehouses.read();
            let wh = warehouses
                .get(&name)
                .cloned()
                .ok_or_else(|| Status::not_found(format!("warehouse '{}' not found", name)))?;
            let wh_bytes = wh.encode_to_vec();
            let bucket_bytes = self
                .buckets
                .read()
                .get(&wh.bucket)
                .map(|b| b.encode_to_vec());
            (wh, wh_bytes, bucket_bytes)
        };

        // Atomic dual delete: warehouse row + backing bucket. If the
        // bucket has already been removed separately, skip its op so
        // we don't spuriously fail on expected=Some but actual=None.
        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::IcebergWarehouses,
                key: name.clone(),
                expected: Some(wh_bytes),
                new_value: None,
            }];
            if let Some(bucket_bytes) = bucket_bytes {
                ops.push(CasOp {
                    table: CasTable::Buckets,
                    key: wh.bucket.clone(),
                    expected: Some(bucket_bytes),
                    new_value: None,
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "iceberg-delete-warehouse".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted(
                            "warehouse or bucket changed since read; retry delete",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for delete_warehouse: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_warehouse(&name);
            store.delete_bucket(&wh.bucket);
        }

        self.iceberg_warehouses.write().remove(&name);
        self.buckets.write().remove(&wh.bucket);

        info!("Deleted warehouse: {} (bucket: {})", name, wh.bucket);
        Ok(Response::new(IcebergDeleteWarehouseResponse {
            success: true,
        }))
    }

    // ============================================================
    // Unity Catalog (catalog.schema.table)
    // ============================================================

    async fn unity_create_catalog(
        &self,
        request: Request<UnityCreateCatalogRequest>,
    ) -> Result<Response<UnityCreateCatalogResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("catalog name is required"));
        }
        if self.unity_catalogs.read().contains_key(&req.name) {
            return Err(Status::already_exists(format!(
                "unity catalog '{}' already exists",
                req.name
            )));
        }

        let bucket_name = format!("unity-{}", req.name);
        let location = format!("s3://{bucket_name}");
        let now = Self::current_timestamp();

        if self.buckets.read().contains_key(&bucket_name) {
            return Err(Status::already_exists(format!(
                "bucket '{bucket_name}' already exists",
            )));
        }

        let bucket = BucketMeta {
            dedup: None,
            name: bucket_name.clone(),
            owner: if req.owner.is_empty() {
                "system".to_string()
            } else {
                req.owner.clone()
            },
            created_at: now,
            storage_class: "STANDARD".to_string(),
            versioning: VersioningState::VersioningDisabled.into(),
            pool: String::new(),
            tenant: req.tenant.clone(),
            quota_bytes: 0,
            quota_objects: 0,
            object_lock: None,
        };
        let bucket_bytes = bucket.encode_to_vec();

        let catalog = UnityCatalog {
            name: req.name.clone(),
            comment: req.comment,
            owner: req.owner,
            bucket: bucket_name.clone(),
            location,
            created_at: now,
            updated_at: now,
            properties: req.properties,
            tenant: req.tenant,
            policy_json: Vec::new(),
        };
        let catalog_bytes = catalog.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![
                    CasOp {
                        table: CasTable::UnityCatalogs,
                        key: req.name.clone(),
                        expected: None,
                        new_value: Some(catalog_bytes),
                    },
                    CasOp {
                        table: CasTable::Buckets,
                        key: bucket_name.clone(),
                        expected: None,
                        new_value: Some(bucket_bytes),
                    },
                ],
                requested_by: "unity-create-catalog".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::already_exists(format!(
                            "unity catalog or backing bucket already exists (conflicts at {failed_indices:?})"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for unity_create_catalog: {other:?}");
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&bucket_name, &bucket);
            store.put_unity_catalog(&req.name, &catalog.encode_to_vec());
        }

        self.buckets
            .write()
            .insert(bucket_name.clone(), bucket.clone());
        self.unity_catalogs
            .write()
            .insert(req.name.clone(), catalog.clone());

        info!(
            "Created unity catalog: {} (bucket: {})",
            req.name, catalog.bucket
        );
        Ok(Response::new(UnityCreateCatalogResponse {
            catalog: Some(catalog),
        }))
    }

    async fn unity_list_catalogs(
        &self,
        request: Request<UnityListCatalogsRequest>,
    ) -> Result<Response<UnityListCatalogsResponse>, Status> {
        let req = request.into_inner();
        let catalogs: Vec<UnityCatalog> = self
            .unity_catalogs
            .read()
            .values()
            .filter(|c| req.tenant.is_empty() || c.tenant == req.tenant)
            .cloned()
            .collect();
        Ok(Response::new(UnityListCatalogsResponse {
            catalogs,
            next_page_token: String::new(),
        }))
    }

    async fn unity_get_catalog(
        &self,
        request: Request<UnityGetCatalogRequest>,
    ) -> Result<Response<UnityGetCatalogResponse>, Status> {
        let name = request.into_inner().name;
        let catalog = self
            .unity_catalogs
            .read()
            .get(&name)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("unity catalog '{name}' not found")))?;
        Ok(Response::new(UnityGetCatalogResponse {
            catalog: Some(catalog),
        }))
    }

    async fn unity_update_catalog(
        &self,
        request: Request<UnityUpdateCatalogRequest>,
    ) -> Result<Response<UnityUpdateCatalogResponse>, Status> {
        let req = request.into_inner();
        let (mut updated, prev_bytes) = {
            let map = self.unity_catalogs.read();
            let prev = map.get(&req.name).cloned().ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.name))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        if !req.new_comment.is_empty() {
            updated.comment = req.new_comment;
        }
        if !req.new_owner.is_empty() {
            updated.owner = req.new_owner;
        }
        if !req.properties.is_empty() {
            updated.properties = req.properties;
        }
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::UnityCatalogs,
                    key: req.name.clone(),
                    expected: Some(prev_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "unity-update-catalog".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("catalog changed since read; retry update"));
                    }
                    other => {
                        error!("unexpected raft response for unity_update_catalog: {other:?}");
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_unity_catalog(&req.name, &updated.encode_to_vec());
        }

        self.unity_catalogs
            .write()
            .insert(req.name.clone(), updated.clone());
        Ok(Response::new(UnityUpdateCatalogResponse {
            catalog: Some(updated),
        }))
    }

    async fn unity_delete_catalog(
        &self,
        request: Request<UnityDeleteCatalogRequest>,
    ) -> Result<Response<UnityDeleteCatalogResponse>, Status> {
        let req = request.into_inner();
        let prefix = format!("{}\x00", req.name);

        let (catalog, catalog_bytes, bucket_bytes) = {
            let map = self.unity_catalogs.read();
            let catalog = map.get(&req.name).cloned().ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.name))
            })?;
            let catalog_bytes = catalog.encode_to_vec();
            let bucket_bytes = self
                .buckets
                .read()
                .get(&catalog.bucket)
                .map(prost::Message::encode_to_vec);
            (catalog, catalog_bytes, bucket_bytes)
        };

        if !req.force {
            // Refuse if any schema or table still references this catalog.
            let has_schema = self
                .unity_schemas
                .read()
                .keys()
                .any(|k| k.starts_with(&prefix));
            if has_schema {
                return Err(Status::failed_precondition(format!(
                    "catalog '{}' is not empty (schemas exist); pass force=true to drop anyway",
                    req.name
                )));
            }
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = vec![CasOp {
                table: CasTable::UnityCatalogs,
                key: req.name.clone(),
                expected: Some(catalog_bytes),
                new_value: None,
            }];
            if let Some(bucket_bytes) = bucket_bytes {
                ops.push(CasOp {
                    table: CasTable::Buckets,
                    key: catalog.bucket.clone(),
                    expected: Some(bucket_bytes),
                    new_value: None,
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "unity-delete-catalog".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted(
                            "catalog or bucket changed since read; retry delete",
                        ));
                    }
                    other => {
                        error!("unexpected raft response for unity_delete_catalog: {other:?}");
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_unity_catalog(&req.name);
            store.delete_bucket(&catalog.bucket);
        }

        // If forced, also evict any orphaned schema/table cache entries —
        // the redb rows are leaked here, but that's acceptable for a
        // force-drop and matches Iceberg's behavior.
        if req.force {
            let dropped_schemas: Vec<String> = self
                .unity_schemas
                .read()
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            for k in dropped_schemas {
                self.unity_schemas.write().remove(&k);
            }
            let dropped_tables: Vec<String> = self
                .unity_tables
                .read()
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            for k in dropped_tables {
                self.unity_tables.write().remove(&k);
            }
        }

        self.unity_catalogs.write().remove(&req.name);
        self.buckets.write().remove(&catalog.bucket);

        info!(
            "Deleted unity catalog: {} (bucket: {})",
            req.name, catalog.bucket
        );
        Ok(Response::new(UnityDeleteCatalogResponse { success: true }))
    }

    async fn unity_create_schema(
        &self,
        request: Request<UnityCreateSchemaRequest>,
    ) -> Result<Response<UnityCreateSchemaResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name and schema name are required",
            ));
        }
        if !self.unity_catalogs.read().contains_key(&req.catalog_name) {
            return Err(Status::not_found(format!(
                "unity catalog '{}' not found",
                req.catalog_name
            )));
        }
        let key = format!("{}\x00{}", req.catalog_name, req.name);
        if self.unity_schemas.read().contains_key(&key) {
            return Err(Status::already_exists(format!(
                "unity schema '{}.{}' already exists",
                req.catalog_name, req.name
            )));
        }

        let now = Self::current_timestamp();
        let schema = UnitySchema {
            catalog_name: req.catalog_name,
            name: req.name,
            comment: req.comment,
            owner: req.owner,
            created_at: now,
            updated_at: now,
            properties: req.properties,
            policy_json: Vec::new(),
        };
        let bytes = schema.encode_to_vec();

        cas_single_put(
            self,
            CasTable::UnitySchemas,
            &key,
            None,
            bytes.clone(),
            "unity-create-schema",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_schema(&key, &bytes);
        }
        self.unity_schemas.write().insert(key, schema.clone());
        Ok(Response::new(UnityCreateSchemaResponse {
            schema: Some(schema),
        }))
    }

    async fn unity_list_schemas(
        &self,
        request: Request<UnityListSchemasRequest>,
    ) -> Result<Response<UnityListSchemasResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() {
            return Err(Status::invalid_argument("catalog_name is required"));
        }
        let prefix = format!("{}\x00", req.catalog_name);
        let schemas: Vec<UnitySchema> = self
            .unity_schemas
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(UnityListSchemasResponse {
            schemas,
            next_page_token: String::new(),
        }))
    }

    async fn unity_get_schema(
        &self,
        request: Request<UnityGetSchemaRequest>,
    ) -> Result<Response<UnityGetSchemaResponse>, Status> {
        let req = request.into_inner();
        let key = format!("{}\x00{}", req.catalog_name, req.name);
        let schema = self
            .unity_schemas
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity schema '{}.{}' not found",
                    req.catalog_name, req.name
                ))
            })?;
        Ok(Response::new(UnityGetSchemaResponse {
            schema: Some(schema),
        }))
    }

    async fn unity_update_schema(
        &self,
        request: Request<UnityUpdateSchemaRequest>,
    ) -> Result<Response<UnityUpdateSchemaResponse>, Status> {
        let req = request.into_inner();
        let key = format!("{}\x00{}", req.catalog_name, req.name);
        let (mut updated, prev_bytes) = {
            let map = self.unity_schemas.read();
            let prev = map.get(&key).cloned().ok_or_else(|| {
                Status::not_found(format!(
                    "unity schema '{}.{}' not found",
                    req.catalog_name, req.name
                ))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        if !req.new_comment.is_empty() {
            updated.comment = req.new_comment;
        }
        if !req.new_owner.is_empty() {
            updated.owner = req.new_owner;
        }
        if !req.properties.is_empty() {
            updated.properties = req.properties;
        }
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();

        cas_single_put(
            self,
            CasTable::UnitySchemas,
            &key,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-update-schema",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_schema(&key, &new_bytes);
        }
        self.unity_schemas.write().insert(key, updated.clone());
        Ok(Response::new(UnityUpdateSchemaResponse {
            schema: Some(updated),
        }))
    }

    async fn unity_delete_schema(
        &self,
        request: Request<UnityDeleteSchemaRequest>,
    ) -> Result<Response<UnityDeleteSchemaResponse>, Status> {
        let req = request.into_inner();
        let key = format!("{}\x00{}", req.catalog_name, req.name);
        let prev_bytes = {
            let map = self.unity_schemas.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity schema '{}.{}' not found",
                        req.catalog_name, req.name
                    ))
                })?
        };

        if !req.force {
            let table_prefix = format!("{key}\x00");
            let has_table = self
                .unity_tables
                .read()
                .keys()
                .any(|k| k.starts_with(&table_prefix));
            if has_table {
                return Err(Status::failed_precondition(format!(
                    "schema '{}.{}' is not empty (tables exist); pass force=true to drop anyway",
                    req.catalog_name, req.name
                )));
            }
        }

        cas_single_delete(
            self,
            CasTable::UnitySchemas,
            &key,
            prev_bytes,
            "unity-delete-schema",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_schema(&key);
        }
        self.unity_schemas.write().remove(&key);

        if req.force {
            let table_prefix = format!("{key}\x00");
            let dropped_tables: Vec<String> = self
                .unity_tables
                .read()
                .keys()
                .filter(|k| k.starts_with(&table_prefix))
                .cloned()
                .collect();
            for k in dropped_tables {
                self.unity_tables.write().remove(&k);
            }
        }

        Ok(Response::new(UnityDeleteSchemaResponse { success: true }))
    }

    async fn unity_create_table(
        &self,
        request: Request<UnityCreateTableRequest>,
    ) -> Result<Response<UnityCreateTableResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and table name are required",
            ));
        }
        let schema_key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        let catalog = self
            .unity_catalogs
            .read()
            .get(&req.catalog_name)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.catalog_name))
            })?;
        if !self.unity_schemas.read().contains_key(&schema_key) {
            return Err(Status::not_found(format!(
                "unity schema '{}.{}' not found",
                req.catalog_name, req.schema_name
            )));
        }
        let key = format!("{schema_key}\x00{}", req.name);
        if self.unity_tables.read().contains_key(&key) {
            return Err(Status::already_exists(format!(
                "unity table '{}.{}.{}' already exists",
                req.catalog_name, req.schema_name, req.name
            )));
        }

        // Default table_type=MANAGED, data_source_format=DELTA when omitted.
        let table_type = if req.table_type.is_empty() {
            "MANAGED".to_string()
        } else {
            req.table_type
        };
        let data_source_format = if req.data_source_format.is_empty() {
            "DELTA".to_string()
        } else {
            req.data_source_format
        };

        // MANAGED tables auto-derive their location under the catalog's bucket.
        // EXTERNAL tables require the caller to supply a storage_location.
        let storage_location = match table_type.as_str() {
            "MANAGED" => format!(
                "{}/{}/{}/",
                catalog.location.trim_end_matches('/'),
                req.schema_name,
                req.name,
            ),
            "EXTERNAL" => {
                if req.storage_location.is_empty() {
                    return Err(Status::invalid_argument(
                        "EXTERNAL tables require a storage_location",
                    ));
                }
                req.storage_location
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported table_type '{other}' (allowed: MANAGED, EXTERNAL)",
                )));
            }
        };

        let now = Self::current_timestamp();
        let table = UnityTable {
            catalog_name: req.catalog_name,
            schema_name: req.schema_name,
            name: req.name,
            table_id: Uuid::new_v4().to_string(),
            table_type,
            data_source_format,
            storage_location,
            columns_json: req.columns_json,
            owner: req.owner,
            created_at: now,
            updated_at: now,
            properties: req.properties,
            policy_json: Vec::new(),
            row_filter: None,
            column_masks: std::collections::HashMap::new(),
        };
        let bytes = table.encode_to_vec();

        cas_single_put(
            self,
            CasTable::UnityTables,
            &key,
            None,
            bytes.clone(),
            "unity-create-table",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_table(&key, &bytes);
        }
        self.unity_tables.write().insert(key, table.clone());
        Ok(Response::new(UnityCreateTableResponse {
            table: Some(table),
        }))
    }

    async fn unity_list_tables(
        &self,
        request: Request<UnityListTablesRequest>,
    ) -> Result<Response<UnityListTablesResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name and schema_name are required",
            ));
        }
        let prefix = format!("{}\x00{}\x00", req.catalog_name, req.schema_name);
        let tables: Vec<UnityTable> = self
            .unity_tables
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(UnityListTablesResponse {
            tables,
            next_page_token: String::new(),
        }))
    }

    async fn unity_get_table(
        &self,
        request: Request<UnityGetTableRequest>,
    ) -> Result<Response<UnityGetTableResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let table = self.unity_tables.read().get(&key).cloned().ok_or_else(|| {
            Status::not_found(format!(
                "unity table '{}.{}.{}' not found",
                req.catalog_name, req.schema_name, req.name
            ))
        })?;
        Ok(Response::new(UnityGetTableResponse { table: Some(table) }))
    }

    async fn unity_delete_table(
        &self,
        request: Request<UnityDeleteTableRequest>,
    ) -> Result<Response<UnityDeleteTableResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let prev_bytes = {
            let map = self.unity_tables.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity table '{}.{}.{}' not found",
                        req.catalog_name, req.schema_name, req.name
                    ))
                })?
        };
        cas_single_delete(
            self,
            CasTable::UnityTables,
            &key,
            prev_bytes,
            "unity-delete-table",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_table(&key);
        }
        self.unity_tables.write().remove(&key);
        Ok(Response::new(UnityDeleteTableResponse { success: true }))
    }

    // ---- Unity Functions ----

    async fn unity_create_function(
        &self,
        request: Request<UnityCreateFunctionRequest>,
    ) -> Result<Response<UnityCreateFunctionResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and function name are required",
            ));
        }
        if req.routine_definition.is_empty() {
            return Err(Status::invalid_argument("routine_definition is required"));
        }
        let schema_key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        if !self.unity_catalogs.read().contains_key(&req.catalog_name) {
            return Err(Status::not_found(format!(
                "unity catalog '{}' not found",
                req.catalog_name
            )));
        }
        if !self.unity_schemas.read().contains_key(&schema_key) {
            return Err(Status::not_found(format!(
                "unity schema '{}.{}' not found",
                req.catalog_name, req.schema_name
            )));
        }
        let key = format!("{schema_key}\x00{}", req.name);
        if self.unity_functions.read().contains_key(&key) {
            return Err(Status::already_exists(format!(
                "unity function '{}.{}.{}' already exists",
                req.catalog_name, req.schema_name, req.name
            )));
        }
        // routine_body is the dispatch flag per Databricks spec — default
        // SQL when omitted. EXTERNAL needs an external_language to be
        // executable downstream; we don't enforce that here (callers may
        // legitimately register placeholder functions).
        let routine_body = if req.routine_body.is_empty() {
            "SQL".to_string()
        } else {
            req.routine_body
        };
        let now = Self::current_timestamp();
        let specific_name = if req.specific_name.is_empty() {
            req.name.clone()
        } else {
            req.specific_name
        };
        let function = UnityFunction {
            catalog_name: req.catalog_name,
            schema_name: req.schema_name,
            name: req.name,
            function_id: Uuid::new_v4().to_string(),
            routine_definition: req.routine_definition,
            routine_body,
            external_language: req.external_language,
            data_type: req.data_type,
            full_data_type: req.full_data_type,
            parameter_style: req.parameter_style,
            is_deterministic: req.is_deterministic,
            sql_data_access: req.sql_data_access,
            is_null_call: req.is_null_call,
            security_type: req.security_type,
            specific_name,
            input_params_json: req.input_params_json,
            return_params_json: req.return_params_json,
            comment: req.comment,
            owner: req.owner,
            created_at: now,
            updated_at: now,
            properties: req.properties,
        };
        let bytes = function.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityFunctions,
            &key,
            None,
            bytes.clone(),
            "unity-create-function",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_function(&key, &bytes);
        }
        self.unity_functions.write().insert(key, function.clone());
        Ok(Response::new(UnityCreateFunctionResponse {
            function: Some(function),
        }))
    }

    async fn unity_list_functions(
        &self,
        request: Request<UnityListFunctionsRequest>,
    ) -> Result<Response<UnityListFunctionsResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name and schema_name are required",
            ));
        }
        let prefix = format!("{}\x00{}\x00", req.catalog_name, req.schema_name);
        let functions: Vec<UnityFunction> = self
            .unity_functions
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(UnityListFunctionsResponse {
            functions,
            next_page_token: String::new(),
        }))
    }

    async fn unity_get_function(
        &self,
        request: Request<UnityGetFunctionRequest>,
    ) -> Result<Response<UnityGetFunctionResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let function = self
            .unity_functions
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity function '{}.{}.{}' not found",
                    req.catalog_name, req.schema_name, req.name
                ))
            })?;
        Ok(Response::new(UnityGetFunctionResponse {
            function: Some(function),
        }))
    }

    async fn unity_delete_function(
        &self,
        request: Request<UnityDeleteFunctionRequest>,
    ) -> Result<Response<UnityDeleteFunctionResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let prev_bytes = {
            let map = self.unity_functions.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity function '{}.{}.{}' not found",
                        req.catalog_name, req.schema_name, req.name
                    ))
                })?
        };
        cas_single_delete(
            self,
            CasTable::UnityFunctions,
            &key,
            prev_bytes,
            "unity-delete-function",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_function(&key);
        }
        self.unity_functions.write().remove(&key);
        Ok(Response::new(UnityDeleteFunctionResponse { success: true }))
    }

    // ---- Unity Volumes ----

    async fn unity_create_volume(
        &self,
        request: Request<UnityCreateVolumeRequest>,
    ) -> Result<Response<UnityCreateVolumeResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and volume name are required",
            ));
        }
        let schema_key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        let catalog = self
            .unity_catalogs
            .read()
            .get(&req.catalog_name)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.catalog_name))
            })?;
        if !self.unity_schemas.read().contains_key(&schema_key) {
            return Err(Status::not_found(format!(
                "unity schema '{}.{}' not found",
                req.catalog_name, req.schema_name
            )));
        }
        let key = format!("{schema_key}\x00{}", req.name);
        if self.unity_volumes.read().contains_key(&key) {
            return Err(Status::already_exists(format!(
                "unity volume '{}.{}.{}' already exists",
                req.catalog_name, req.schema_name, req.name
            )));
        }
        let volume_type = if req.volume_type.is_empty() {
            "MANAGED".to_string()
        } else {
            req.volume_type
        };
        let storage_location = match volume_type.as_str() {
            "MANAGED" => format!(
                "{}/{}/__volumes/{}/",
                catalog.location.trim_end_matches('/'),
                req.schema_name,
                req.name,
            ),
            "EXTERNAL" => {
                if req.storage_location.is_empty() {
                    return Err(Status::invalid_argument(
                        "EXTERNAL volumes require a storage_location",
                    ));
                }
                req.storage_location
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported volume_type '{other}' (allowed: MANAGED, EXTERNAL)",
                )));
            }
        };
        let now = Self::current_timestamp();
        let volume = UnityVolume {
            catalog_name: req.catalog_name,
            schema_name: req.schema_name,
            name: req.name,
            volume_id: Uuid::new_v4().to_string(),
            volume_type,
            storage_location,
            comment: req.comment,
            owner: req.owner,
            created_at: now,
            updated_at: now,
            properties: req.properties,
        };
        let bytes = volume.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityVolumes,
            &key,
            None,
            bytes.clone(),
            "unity-create-volume",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_volume(&key, &bytes);
        }
        self.unity_volumes.write().insert(key, volume.clone());
        Ok(Response::new(UnityCreateVolumeResponse {
            volume: Some(volume),
        }))
    }

    async fn unity_list_volumes(
        &self,
        request: Request<UnityListVolumesRequest>,
    ) -> Result<Response<UnityListVolumesResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name and schema_name are required",
            ));
        }
        let prefix = format!("{}\x00{}\x00", req.catalog_name, req.schema_name);
        let volumes: Vec<UnityVolume> = self
            .unity_volumes
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(UnityListVolumesResponse {
            volumes,
            next_page_token: String::new(),
        }))
    }

    async fn unity_get_volume(
        &self,
        request: Request<UnityGetVolumeRequest>,
    ) -> Result<Response<UnityGetVolumeResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let volume = self
            .unity_volumes
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity volume '{}.{}.{}' not found",
                    req.catalog_name, req.schema_name, req.name
                ))
            })?;
        Ok(Response::new(UnityGetVolumeResponse {
            volume: Some(volume),
        }))
    }

    async fn unity_delete_volume(
        &self,
        request: Request<UnityDeleteVolumeRequest>,
    ) -> Result<Response<UnityDeleteVolumeResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let prev_bytes = {
            let map = self.unity_volumes.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity volume '{}.{}.{}' not found",
                        req.catalog_name, req.schema_name, req.name
                    ))
                })?
        };
        cas_single_delete(
            self,
            CasTable::UnityVolumes,
            &key,
            prev_bytes,
            "unity-delete-volume",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_volume(&key);
        }
        self.unity_volumes.write().remove(&key);
        Ok(Response::new(UnityDeleteVolumeResponse { success: true }))
    }

    // ---- Unity Models ----

    async fn unity_create_model(
        &self,
        request: Request<UnityCreateModelRequest>,
    ) -> Result<Response<UnityCreateModelResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and model name are required",
            ));
        }
        let schema_key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        let catalog = self
            .unity_catalogs
            .read()
            .get(&req.catalog_name)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.catalog_name))
            })?;
        if !self.unity_schemas.read().contains_key(&schema_key) {
            return Err(Status::not_found(format!(
                "unity schema '{}.{}' not found",
                req.catalog_name, req.schema_name
            )));
        }
        let key = format!("{schema_key}\x00{}", req.name);
        if self.unity_models.read().contains_key(&key) {
            return Err(Status::already_exists(format!(
                "unity model '{}.{}.{}' already exists",
                req.catalog_name, req.schema_name, req.name
            )));
        }
        // Empty storage_location → server-derive a managed location under
        // the catalog bucket. Otherwise honor the caller-supplied URI.
        let storage_location = if req.storage_location.is_empty() {
            format!(
                "{}/{}/__models/{}/",
                catalog.location.trim_end_matches('/'),
                req.schema_name,
                req.name,
            )
        } else {
            req.storage_location
        };
        let now = Self::current_timestamp();
        let model = UnityModel {
            catalog_name: req.catalog_name,
            schema_name: req.schema_name,
            name: req.name,
            model_id: Uuid::new_v4().to_string(),
            storage_location,
            comment: req.comment,
            owner: req.owner,
            created_at: now,
            updated_at: now,
            properties: req.properties,
        };
        let bytes = model.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityModels,
            &key,
            None,
            bytes.clone(),
            "unity-create-model",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_model(&key, &bytes);
        }
        self.unity_models.write().insert(key, model.clone());
        Ok(Response::new(UnityCreateModelResponse {
            model: Some(model),
        }))
    }

    async fn unity_list_models(
        &self,
        request: Request<UnityListModelsRequest>,
    ) -> Result<Response<UnityListModelsResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name and schema_name are required",
            ));
        }
        let prefix = format!("{}\x00{}\x00", req.catalog_name, req.schema_name);
        let models: Vec<UnityModel> = self
            .unity_models
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        Ok(Response::new(UnityListModelsResponse {
            models,
            next_page_token: String::new(),
        }))
    }

    async fn unity_get_model(
        &self,
        request: Request<UnityGetModelRequest>,
    ) -> Result<Response<UnityGetModelResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let model = self.unity_models.read().get(&key).cloned().ok_or_else(|| {
            Status::not_found(format!(
                "unity model '{}.{}.{}' not found",
                req.catalog_name, req.schema_name, req.name
            ))
        })?;
        Ok(Response::new(UnityGetModelResponse { model: Some(model) }))
    }

    async fn unity_delete_model(
        &self,
        request: Request<UnityDeleteModelRequest>,
    ) -> Result<Response<UnityDeleteModelResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let prev_bytes = {
            let map = self.unity_models.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity model '{}.{}.{}' not found",
                        req.catalog_name, req.schema_name, req.name
                    ))
                })?
        };
        // Cascade: drop every version belonging to this model. Versions
        // live under their own table, keyed by `{catalog}\x00{schema}\x00{model}\x00{version_u32_be}`.
        let version_prefix = format!(
            "{}\x00{}\x00{}\x00",
            req.catalog_name, req.schema_name, req.name
        );
        let dropped_versions: Vec<(String, Vec<u8>)> = self
            .unity_model_versions
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&version_prefix))
            .map(|(k, v)| (k.clone(), v.encode_to_vec()))
            .collect();
        for (vkey, vbytes) in &dropped_versions {
            cas_single_delete(
                self,
                CasTable::UnityModelVersions,
                vkey,
                vbytes.clone(),
                "unity-delete-model-cascade",
            )
            .await?;
            if self.raft_handle().is_none()
                && let Some(store) = &self.store
            {
                store.delete_unity_model_version(vkey);
            }
        }
        cas_single_delete(
            self,
            CasTable::UnityModels,
            &key,
            prev_bytes,
            "unity-delete-model",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_model(&key);
        }
        {
            let mut versions = self.unity_model_versions.write();
            for (vkey, _) in &dropped_versions {
                versions.remove(vkey);
            }
        }
        self.unity_models.write().remove(&key);
        Ok(Response::new(UnityDeleteModelResponse { success: true }))
    }

    // ---- Unity Model Versions ----

    async fn unity_create_model_version(
        &self,
        request: Request<UnityCreateModelVersionRequest>,
    ) -> Result<Response<UnityCreateModelVersionResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.model_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and model_name are required",
            ));
        }
        let model_key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.model_name
        );
        if !self.unity_models.read().contains_key(&model_key) {
            return Err(Status::not_found(format!(
                "unity model '{}.{}.{}' not found",
                req.catalog_name, req.schema_name, req.model_name
            )));
        }
        // Compute the next version number under this model. Versions
        // are 1-indexed and monotonic; gaps from prior deletes are not
        // reused (mirrors MLflow semantics).
        let prefix = format!(
            "{}\x00{}\x00{}\x00",
            req.catalog_name, req.schema_name, req.model_name
        );
        let next_version: u32 = {
            let map = self.unity_model_versions.read();
            map.iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v.version)
                .max()
                .map_or(1, |m| m + 1)
        };
        let key = format!("{prefix}{next_version:010}");
        let now = Self::current_timestamp();
        let version = UnityModelVersion {
            catalog_name: req.catalog_name,
            schema_name: req.schema_name,
            model_name: req.model_name,
            version: next_version,
            version_id: Uuid::new_v4().to_string(),
            source: req.source,
            run_id: req.run_id,
            status: "PENDING_REGISTRATION".to_string(),
            description: req.description,
            created_at: now,
            updated_at: now,
            properties: req.properties,
        };
        let bytes = version.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityModelVersions,
            &key,
            None,
            bytes.clone(),
            "unity-create-model-version",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_model_version(&key, &bytes);
        }
        self.unity_model_versions
            .write()
            .insert(key, version.clone());
        Ok(Response::new(UnityCreateModelVersionResponse {
            version: Some(version),
        }))
    }

    async fn unity_list_model_versions(
        &self,
        request: Request<UnityListModelVersionsRequest>,
    ) -> Result<Response<UnityListModelVersionsResponse>, Status> {
        let req = request.into_inner();
        if req.catalog_name.is_empty() || req.schema_name.is_empty() || req.model_name.is_empty() {
            return Err(Status::invalid_argument(
                "catalog_name, schema_name and model_name are required",
            ));
        }
        let prefix = format!(
            "{}\x00{}\x00{}\x00",
            req.catalog_name, req.schema_name, req.model_name
        );
        let mut versions: Vec<UnityModelVersion> = self
            .unity_model_versions
            .read()
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect();
        versions.sort_by_key(|v| v.version);
        Ok(Response::new(UnityListModelVersionsResponse {
            versions,
            next_page_token: String::new(),
        }))
    }

    async fn unity_get_model_version(
        &self,
        request: Request<UnityGetModelVersionRequest>,
    ) -> Result<Response<UnityGetModelVersionResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}\x00{:010}",
            req.catalog_name, req.schema_name, req.model_name, req.version
        );
        let version = self
            .unity_model_versions
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity model version '{}.{}.{}/v{}' not found",
                    req.catalog_name, req.schema_name, req.model_name, req.version
                ))
            })?;
        Ok(Response::new(UnityGetModelVersionResponse {
            version: Some(version),
        }))
    }

    async fn unity_update_model_version_status(
        &self,
        request: Request<UnityUpdateModelVersionStatusRequest>,
    ) -> Result<Response<UnityUpdateModelVersionStatusResponse>, Status> {
        let req = request.into_inner();
        // Restrict to the documented MLflow lifecycle states; reject
        // arbitrary values to keep callers from inventing new ones that
        // downstream tooling won't recognize.
        match req.new_status.as_str() {
            "PENDING_REGISTRATION" | "READY" | "FAILED_REGISTRATION" => {}
            other => {
                return Err(Status::invalid_argument(format!(
                    "invalid model version status '{other}' (allowed: PENDING_REGISTRATION, READY, FAILED_REGISTRATION)",
                )));
            }
        }
        let key = format!(
            "{}\x00{}\x00{}\x00{:010}",
            req.catalog_name, req.schema_name, req.model_name, req.version
        );
        let (mut updated, prev_bytes) = {
            let map = self.unity_model_versions.read();
            let prev = map.get(&key).cloned().ok_or_else(|| {
                Status::not_found(format!(
                    "unity model version '{}.{}.{}/v{}' not found",
                    req.catalog_name, req.schema_name, req.model_name, req.version
                ))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        updated.status = req.new_status;
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityModelVersions,
            &key,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-update-model-version-status",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_model_version(&key, &new_bytes);
        }
        self.unity_model_versions
            .write()
            .insert(key, updated.clone());
        Ok(Response::new(UnityUpdateModelVersionStatusResponse {
            version: Some(updated),
        }))
    }

    async fn unity_delete_model_version(
        &self,
        request: Request<UnityDeleteModelVersionRequest>,
    ) -> Result<Response<UnityDeleteModelVersionResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}\x00{:010}",
            req.catalog_name, req.schema_name, req.model_name, req.version
        );
        let prev_bytes = {
            let map = self.unity_model_versions.read();
            map.get(&key)
                .map(prost::Message::encode_to_vec)
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "unity model version '{}.{}.{}/v{}' not found",
                        req.catalog_name, req.schema_name, req.model_name, req.version
                    ))
                })?
        };
        cas_single_delete(
            self,
            CasTable::UnityModelVersions,
            &key,
            prev_bytes,
            "unity-delete-model-version",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.delete_unity_model_version(&key);
        }
        self.unity_model_versions.write().remove(&key);
        Ok(Response::new(UnityDeleteModelVersionResponse {
            success: true,
        }))
    }

    async fn unity_set_catalog_policy(
        &self,
        request: Request<UnitySetCatalogPolicyRequest>,
    ) -> Result<Response<UnitySetCatalogPolicyResponse>, Status> {
        let req = request.into_inner();
        let (mut updated, prev_bytes) = {
            let map = self.unity_catalogs.read();
            let prev = map.get(&req.catalog_name).cloned().ok_or_else(|| {
                Status::not_found(format!("unity catalog '{}' not found", req.catalog_name))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        updated.policy_json = req.policy_json;
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityCatalogs,
            &req.catalog_name,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-set-catalog-policy",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_catalog(&req.catalog_name, &new_bytes);
        }
        self.unity_catalogs
            .write()
            .insert(req.catalog_name, updated);
        Ok(Response::new(UnitySetCatalogPolicyResponse {
            success: true,
        }))
    }

    async fn unity_get_catalog_policy(
        &self,
        request: Request<UnityGetCatalogPolicyRequest>,
    ) -> Result<Response<UnityGetCatalogPolicyResponse>, Status> {
        let name = request.into_inner().catalog_name;
        let policy = self
            .unity_catalogs
            .read()
            .get(&name)
            .map(|c| c.policy_json.clone())
            .ok_or_else(|| Status::not_found(format!("unity catalog '{name}' not found")))?;
        Ok(Response::new(UnityGetCatalogPolicyResponse {
            policy_json: policy,
        }))
    }

    async fn unity_set_schema_policy(
        &self,
        request: Request<UnitySetSchemaPolicyRequest>,
    ) -> Result<Response<UnitySetSchemaPolicyResponse>, Status> {
        let req = request.into_inner();
        let key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        let (mut updated, prev_bytes) = {
            let map = self.unity_schemas.read();
            let prev = map.get(&key).cloned().ok_or_else(|| {
                Status::not_found(format!(
                    "unity schema '{}.{}' not found",
                    req.catalog_name, req.schema_name
                ))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        updated.policy_json = req.policy_json;
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnitySchemas,
            &key,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-set-schema-policy",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_schema(&key, &new_bytes);
        }
        self.unity_schemas.write().insert(key, updated);
        Ok(Response::new(UnitySetSchemaPolicyResponse {
            success: true,
        }))
    }

    async fn unity_get_schema_policy(
        &self,
        request: Request<UnityGetSchemaPolicyRequest>,
    ) -> Result<Response<UnityGetSchemaPolicyResponse>, Status> {
        let req = request.into_inner();
        let key = format!("{}\x00{}", req.catalog_name, req.schema_name);
        let policy = self
            .unity_schemas
            .read()
            .get(&key)
            .map(|s| s.policy_json.clone())
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity schema '{}.{}' not found",
                    req.catalog_name, req.schema_name
                ))
            })?;
        Ok(Response::new(UnityGetSchemaPolicyResponse {
            policy_json: policy,
        }))
    }

    async fn unity_set_table_policy(
        &self,
        request: Request<UnitySetTablePolicyRequest>,
    ) -> Result<Response<UnitySetTablePolicyResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.table_name
        );
        let (mut updated, prev_bytes) = {
            let map = self.unity_tables.read();
            let prev = map.get(&key).cloned().ok_or_else(|| {
                Status::not_found(format!(
                    "unity table '{}.{}.{}' not found",
                    req.catalog_name, req.schema_name, req.table_name
                ))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };
        updated.policy_json = req.policy_json;
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityTables,
            &key,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-set-table-policy",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_table(&key, &new_bytes);
        }
        self.unity_tables.write().insert(key, updated);
        Ok(Response::new(UnitySetTablePolicyResponse { success: true }))
    }

    async fn unity_set_table_security(
        &self,
        request: Request<UnitySetTableSecurityRequest>,
    ) -> Result<Response<UnitySetTableSecurityResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.name
        );
        let (mut updated, prev_bytes) = {
            let map = self.unity_tables.read();
            let prev = map.get(&key).cloned().ok_or_else(|| {
                Status::not_found(format!(
                    "unity table '{}.{}.{}' not found",
                    req.catalog_name, req.schema_name, req.name
                ))
            })?;
            let prev_bytes = prev.encode_to_vec();
            (prev, prev_bytes)
        };

        // Validate row filter binding (if any) — referenced function must
        // exist and return BOOLEAN. Engines that consume our metadata trust
        // this, so we reject misconfigured bindings here rather than at
        // query time.
        if let Some(rf) = &req.row_filter
            && !rf.function_full_name.is_empty()
        {
            let f = self.lookup_unity_function(&rf.function_full_name)?;
            if !f.data_type.eq_ignore_ascii_case("BOOLEAN")
                && !f.data_type.eq_ignore_ascii_case("BOOL")
            {
                return Err(Status::invalid_argument(format!(
                    "row filter function '{}' returns {} — must return BOOLEAN",
                    rf.function_full_name, f.data_type
                )));
            }
        }
        // Column mask validation: just confirm the function exists. Type
        // matching against the column is more involved (columns_json is a
        // free-form blob); engines reject the mismatch at runtime.
        for (col, mask) in &req.column_masks {
            if mask.function_full_name.is_empty() {
                return Err(Status::invalid_argument(format!(
                    "column mask for '{col}' has empty function_full_name"
                )));
            }
            self.lookup_unity_function(&mask.function_full_name)?;
        }

        updated.row_filter = req.row_filter;
        updated.column_masks = req.column_masks;
        updated.updated_at = Self::current_timestamp();
        let new_bytes = updated.encode_to_vec();
        cas_single_put(
            self,
            CasTable::UnityTables,
            &key,
            Some(prev_bytes),
            new_bytes.clone(),
            "unity-set-table-security",
        )
        .await?;
        if self.raft_handle().is_none()
            && let Some(store) = &self.store
        {
            store.put_unity_table(&key, &new_bytes);
        }
        self.unity_tables.write().insert(key, updated.clone());
        Ok(Response::new(UnitySetTableSecurityResponse {
            table: Some(updated),
        }))
    }

    async fn unity_get_table_policy(
        &self,
        request: Request<UnityGetTablePolicyRequest>,
    ) -> Result<Response<UnityGetTablePolicyResponse>, Status> {
        let req = request.into_inner();
        let key = format!(
            "{}\x00{}\x00{}",
            req.catalog_name, req.schema_name, req.table_name
        );
        let policy = self
            .unity_tables
            .read()
            .get(&key)
            .map(|t| t.policy_json.clone())
            .ok_or_else(|| {
                Status::not_found(format!(
                    "unity table '{}.{}.{}' not found",
                    req.catalog_name, req.schema_name, req.table_name
                ))
            })?;
        Ok(Response::new(UnityGetTablePolicyResponse {
            policy_json: policy,
        }))
    }

    // Bucket Versioning
    // ============================================================

    async fn put_bucket_versioning(
        &self,
        request: Request<PutBucketVersioningRequest>,
    ) -> Result<Response<PutBucketVersioningResponse>, Status> {
        let req = request.into_inner();

        // Object-locked buckets cannot have versioning suspended.
        if req.state() == VersioningState::VersioningSuspended {
            let lock_configs = self.object_lock_configs.read();
            if lock_configs.get(&req.bucket).is_some_and(|c| c.enabled) {
                return Err(Status::failed_precondition(
                    "cannot suspend versioning on object-locked bucket",
                ));
            }
        }

        let (expected_bytes, new_bucket, new_bytes) = {
            let buckets = self.buckets.read();
            let current = buckets
                .get(&req.bucket)
                .cloned()
                .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", req.bucket)))?;
            let expected = current.encode_to_vec();
            let mut new_bucket = current;
            new_bucket.versioning = req.state;
            let new_bytes = new_bucket.encode_to_vec();
            (expected, new_bucket, new_bytes)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Buckets,
                    key: req.bucket.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "put-bucket-versioning".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for put_bucket_versioning: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&req.bucket, &new_bucket);
        }

        self.buckets.write().insert(req.bucket.clone(), new_bucket);
        info!(
            "Set versioning for bucket '{}' to {:?}",
            req.bucket,
            req.state()
        );
        Ok(Response::new(PutBucketVersioningResponse { success: true }))
    }

    async fn share_stripes(
        &self,
        request: Request<objectio_proto::metadata::ShareStripesRequest>,
    ) -> Result<Response<objectio_proto::metadata::ShareStripesResponse>, Status> {
        use objectio_proto::metadata::StripeRefs;
        let req = request.into_inner();
        if req.owner.is_empty() || req.sharer.is_empty() {
            return Err(Status::invalid_argument("owner and sharer are required"));
        }
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let mut changes = Vec::new();
            {
                let map = self.stripe_refs.read();
                for id in &req.stripe_ids {
                    let key = hex::encode(id);
                    let mut refs = match map.get(&key) {
                        // Shared already: the owner must still be a referrer,
                        // or it has let the stripe go and may have freed it.
                        Some(r) if !r.referrers.contains(&req.owner) => {
                            return Err(Status::failed_precondition(format!(
                                "stripe {key} is no longer referenced by the copy's source"
                            )));
                        }
                        Some(r) => r.clone(),
                        // A pack is registered while anything is in it: no
                        // entry means the source's slice is gone already.
                        None if self.pack_record(id).is_some() => {
                            return Err(Status::failed_precondition(format!(
                                "pack {key} is no longer referenced by the copy's source"
                            )));
                        }
                        None => StripeRefs {
                            referrers: vec![req.owner.clone()],
                        },
                    };
                    if !refs.referrers.contains(&req.sharer) {
                        refs.referrers.push(req.sharer.clone());
                        changes.push((key, Some(refs)));
                    }
                }
            }
            if self.write_stripe_refs(changes, "share-stripes").await? {
                return Ok(Response::new(
                    objectio_proto::metadata::ShareStripesResponse {},
                ));
            }
        }
        Err(Status::aborted("stripe references kept changing; retry"))
    }

    async fn release_stripes(
        &self,
        request: Request<objectio_proto::metadata::ReleaseStripesRequest>,
    ) -> Result<Response<objectio_proto::metadata::ReleaseStripesResponse>, Status> {
        use objectio_meta_store::{CasOp, CasTable};
        let req = request.into_inner();
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            let mut changes: Vec<(String, Option<objectio_proto::metadata::StripeRefs>)> =
                Vec::new();
            let mut freeable = Vec::new();
            let mut pack_ops = Vec::new();
            let mut freed_packs = Vec::new();
            {
                let map = self.stripe_refs.read();
                for id in &req.stripe_ids {
                    let key = hex::encode(id);
                    let pack = self.pack_record(id);
                    match map.get(&key) {
                        // A pack is always registered while anything is in
                        // it: no entry means nothing here to release, never
                        // "free" — that would delete other objects' bytes.
                        None if pack.is_some() => {}
                        // Never shared: its only referrer is letting it go.
                        None => freeable.push(id.clone()),
                        Some(r) if r.referrers.contains(&req.referrer) => {
                            let mut refs = r.clone();
                            refs.referrers.retain(|x| x != &req.referrer);
                            if refs.referrers.is_empty() {
                                changes.push((key.clone(), None));
                                if let Some((record, bytes)) = pack {
                                    // The last object in the pack: the pack
                                    // goes in the same commit.
                                    pack_ops.push(CasOp {
                                        table: CasTable::Named(PACKS_TABLE.into()),
                                        key,
                                        expected: Some(bytes),
                                        new_value: None,
                                    });
                                    if let Some(stripe) = record.stripe {
                                        freed_packs.push(stripe);
                                    }
                                } else {
                                    freeable.push(id.clone());
                                }
                            } else {
                                changes.push((key, Some(refs)));
                            }
                        }
                        // Shared, and not by this referrer: someone else's.
                        Some(_) => {}
                    }
                }
            }
            let ok = if pack_ops.is_empty() {
                self.write_stripe_refs(changes, "release-stripes").await?
            } else {
                let expected: Vec<Option<Vec<u8>>> = {
                    let map = self.stripe_refs.read();
                    changes
                        .iter()
                        .map(|(k, _)| map.get(k).map(Message::encode_to_vec))
                        .collect()
                };
                let mut ops: Vec<CasOp> = changes
                    .iter()
                    .zip(expected)
                    .map(|((key, new), expected)| CasOp {
                        table: CasTable::Named("stripe_refs".into()),
                        key: key.clone(),
                        expected,
                        new_value: new.as_ref().map(Message::encode_to_vec),
                    })
                    .collect();
                ops.extend(pack_ops);
                let ok = self.cas_many(ops, "release-stripes").await?;
                if ok {
                    let mut map = self.stripe_refs.write();
                    for (key, new) in changes {
                        match new {
                            Some(r) => {
                                map.insert(key, r);
                            }
                            None => {
                                map.remove(&key);
                            }
                        }
                    }
                }
                ok
            };
            if ok {
                return Ok(Response::new(
                    objectio_proto::metadata::ReleaseStripesResponse {
                        freeable,
                        freed_packs,
                    },
                ));
            }
        }
        Err(Status::aborted("stripe references kept changing; retry"))
    }

    async fn intend_pack(
        &self,
        request: Request<objectio_proto::metadata::IntendPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::IntendPackResponse>, Status> {
        let mut pack = request
            .into_inner()
            .pack
            .ok_or_else(|| Status::invalid_argument("pack is required"))?;
        if pack.pack_id.len() != 16 || pack.stripe.is_none() {
            return Err(Status::invalid_argument(
                "a pack needs a 16-byte id and a stripe",
            ));
        }
        pack.sealed = false;
        pack.version = 1;
        pack.created_at = Self::current_timestamp();
        let ok = self
            .cas_many(
                vec![objectio_meta_store::CasOp {
                    table: objectio_meta_store::CasTable::Named(PACKS_TABLE.into()),
                    key: hex::encode(&pack.pack_id),
                    expected: None,
                    new_value: Some(pack.encode_to_vec()),
                }],
                "intend-pack",
            )
            .await?;
        if ok {
            Ok(Response::new(
                objectio_proto::metadata::IntendPackResponse {},
            ))
        } else {
            Err(Status::already_exists("pack id is taken"))
        }
    }

    async fn seal_pack(
        &self,
        request: Request<objectio_proto::metadata::SealPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::SealPackResponse>, Status> {
        use objectio_meta_store::{CasOp, CasTable};
        let req = request.into_inner();
        if req.referrers.is_empty() {
            return Err(Status::invalid_argument("a pack holds at least one object"));
        }
        let Some((mut record, bytes)) = self.pack_record(&req.pack_id) else {
            return Err(Status::failed_precondition("pack is not recorded"));
        };
        if record.sealed {
            return Err(Status::failed_precondition("pack is already sealed"));
        }
        record.sealed = true;
        if let Some(stripe) = req.stripe {
            if stripe.shards.is_empty() {
                return Err(Status::invalid_argument(
                    "a sealed pack needs its shard locations",
                ));
            }
            record.stripe = Some(stripe);
        }
        let key = hex::encode(&req.pack_id);
        if self.stripe_refs.read().contains_key(&key) {
            return Err(Status::failed_precondition("pack id is already registered"));
        }
        let refs = objectio_proto::metadata::StripeRefs {
            referrers: req.referrers,
        };
        let ok = self
            .cas_many(
                vec![
                    CasOp {
                        table: CasTable::Named(PACKS_TABLE.into()),
                        key: key.clone(),
                        expected: Some(bytes),
                        new_value: Some(record.encode_to_vec()),
                    },
                    CasOp {
                        table: CasTable::Named("stripe_refs".into()),
                        key: key.clone(),
                        expected: None,
                        new_value: Some(refs.encode_to_vec()),
                    },
                ],
                "seal-pack",
            )
            .await?;
        if !ok {
            return Err(Status::aborted("pack changed while sealing; retry"));
        }
        self.stripe_refs.write().insert(key, refs);
        Ok(Response::new(objectio_proto::metadata::SealPackResponse {}))
    }

    async fn abort_pack(
        &self,
        request: Request<objectio_proto::metadata::AbortPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::AbortPackResponse>, Status> {
        let id = request.into_inner().pack_id;
        let Some((record, bytes)) = self.pack_record(&id) else {
            return Ok(Response::new(objectio_proto::metadata::AbortPackResponse {
                pack: None,
                found: false,
            }));
        };
        if record.sealed {
            return Err(Status::failed_precondition(
                "a sealed pack is freed by releasing its objects, not aborted",
            ));
        }
        let ok = self
            .cas_many(
                vec![objectio_meta_store::CasOp {
                    table: objectio_meta_store::CasTable::Named(PACKS_TABLE.into()),
                    key: hex::encode(&id),
                    expected: Some(bytes),
                    new_value: None,
                }],
                "abort-pack",
            )
            .await?;
        if !ok {
            return Err(Status::aborted("pack changed; retry"));
        }
        Ok(Response::new(objectio_proto::metadata::AbortPackResponse {
            pack: Some(record),
            found: true,
        }))
    }

    async fn get_pack(
        &self,
        request: Request<objectio_proto::metadata::GetPackRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetPackResponse>, Status> {
        let pack = self
            .pack_record(&request.into_inner().pack_id)
            .map(|(r, _)| r);
        Ok(Response::new(objectio_proto::metadata::GetPackResponse {
            found: pack.is_some(),
            pack,
        }))
    }

    async fn list_packs(
        &self,
        request: Request<objectio_proto::metadata::ListPacksRequest>,
    ) -> Result<Response<objectio_proto::metadata::ListPacksResponse>, Status> {
        let req = request.into_inner();
        let after = hex::encode(&req.start_after);
        let limit = if req.limit == 0 {
            1000
        } else {
            req.limit as usize
        };
        let mut all: Vec<(String, Vec<u8>)> = self
            .store
            .as_ref()
            .map(|s| s.list_named(PACKS_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter(|(k, _)| req.start_after.is_empty() || *k > after)
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        let truncated = all.len() > limit;
        let packs: Vec<objectio_proto::metadata::PackRecord> = all
            .into_iter()
            .take(limit)
            .filter_map(|(_, v)| objectio_proto::metadata::PackRecord::decode(v.as_slice()).ok())
            .collect();
        let refs = self.stripe_refs.read();
        let referrers = packs
            .iter()
            .map(|p| objectio_proto::metadata::PackReferrers {
                object_ids: refs
                    .get(&hex::encode(&p.pack_id))
                    .map(|r| r.referrers.clone())
                    .unwrap_or_default(),
            })
            .collect();
        Ok(Response::new(objectio_proto::metadata::ListPacksResponse {
            packs,
            truncated,
            referrers,
        }))
    }

    async fn pack_move_shard(
        &self,
        request: Request<objectio_proto::metadata::PackMoveShardRequest>,
    ) -> Result<Response<objectio_proto::metadata::PackMoveShardResponse>, Status> {
        let req = request.into_inner();
        let from: [u8; 16] = req
            .from_node
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("from_node must be 16 bytes"))?;
        let to = req
            .to
            .ok_or_else(|| Status::invalid_argument("to is required"))?;
        MetaService::pack_move_shard(self, &req.pack_id, req.position, from, &to).await?;
        Ok(Response::new(
            objectio_proto::metadata::PackMoveShardResponse {},
        ))
    }

    async fn pack_settle(
        &self,
        request: Request<objectio_proto::metadata::PackSettleRequest>,
    ) -> Result<Response<objectio_proto::metadata::PackSettleResponse>, Status> {
        let req = request.into_inner();
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                contention_backoff(attempt).await;
            }
            // A pack freed meanwhile has nothing left to settle.
            let Some((mut record, bytes)) = self.pack_record(&req.pack_id) else {
                return Ok(Response::new(
                    objectio_proto::metadata::PackSettleResponse {},
                ));
            };
            let mut changed = false;
            for m in &mut record.members {
                if !m.settled && req.object_ids.contains(&m.object_id) {
                    m.settled = true;
                    m.old_stripe = None;
                    changed = true;
                }
            }
            if !changed {
                return Ok(Response::new(
                    objectio_proto::metadata::PackSettleResponse {},
                ));
            }
            let ok = self
                .cas_many(
                    vec![objectio_meta_store::CasOp {
                        table: objectio_meta_store::CasTable::Named(PACKS_TABLE.into()),
                        key: hex::encode(&req.pack_id),
                        expected: Some(bytes),
                        new_value: Some(record.encode_to_vec()),
                    }],
                    "pack-settle",
                )
                .await?;
            if ok {
                return Ok(Response::new(
                    objectio_proto::metadata::PackSettleResponse {},
                ));
            }
        }
        Err(Status::aborted("pack kept changing; retry"))
    }

    async fn block_create_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockCreateVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Ok(Response::new(
            self.block_create_volume_impl(request.into_inner()).await?,
        ))
    }

    async fn block_get_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockGetVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Ok(Response::new(
            self.block_get_volume_impl(request.get_ref())?,
        ))
    }

    async fn block_list_volumes(
        &self,
        _request: Request<objectio_proto::metadata::BlockListVolumesRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockListVolumesResponse>, Status> {
        Ok(Response::new(self.block_list_volumes_impl()))
    }

    async fn block_update_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockUpdateVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Ok(Response::new(
            self.block_update_volume_impl(request.into_inner()).await?,
        ))
    }

    async fn block_delete_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockDeleteVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockReleaseResponse>, Status> {
        Ok(Response::new(
            self.block_delete_volume_impl(request.into_inner()).await?,
        ))
    }

    async fn block_get_chunks(
        &self,
        request: Request<objectio_proto::metadata::BlockGetChunksRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockGetChunksResponse>, Status> {
        Ok(Response::new(
            self.block_get_chunks_impl(request.get_ref())?,
        ))
    }

    async fn block_commit_chunks(
        &self,
        request: Request<objectio_proto::metadata::BlockCommitChunksRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockReleaseResponse>, Status> {
        Ok(Response::new(
            self.block_commit_chunks_impl(request.into_inner()).await?,
        ))
    }

    async fn block_create_snapshot(
        &self,
        request: Request<objectio_proto::metadata::BlockCreateSnapshotRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockSnapshotResponse>, Status> {
        Ok(Response::new(
            self.block_create_snapshot_impl(request.into_inner())
                .await?,
        ))
    }

    async fn block_get_snapshot(
        &self,
        request: Request<objectio_proto::metadata::BlockGetSnapshotRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockSnapshotResponse>, Status> {
        Ok(Response::new(
            self.block_get_snapshot_impl(request.get_ref())?,
        ))
    }

    async fn block_list_snapshots(
        &self,
        request: Request<objectio_proto::metadata::BlockListSnapshotsRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockListSnapshotsResponse>, Status> {
        Ok(Response::new(
            self.block_list_snapshots_impl(request.get_ref()),
        ))
    }

    async fn block_delete_snapshot(
        &self,
        request: Request<objectio_proto::metadata::BlockDeleteSnapshotRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockReleaseResponse>, Status> {
        Ok(Response::new(
            self.block_delete_snapshot_impl(request.into_inner())
                .await?,
        ))
    }

    async fn block_clone_volume(
        &self,
        request: Request<objectio_proto::metadata::BlockCloneVolumeRequest>,
    ) -> Result<Response<objectio_proto::metadata::BlockVolumeResponse>, Status> {
        Ok(Response::new(
            self.block_clone_volume_impl(request.into_inner()).await?,
        ))
    }

    async fn set_bucket_dedup(
        &self,
        request: Request<objectio_proto::metadata::SetBucketDedupRequest>,
    ) -> Result<Response<objectio_proto::metadata::SetBucketDedupResponse>, Status> {
        use objectio_proto::metadata::{DedupMode, DedupScope};
        let req = request.into_inner();
        // All-unset is no policy at all: the bucket inherits.
        let policy = req
            .policy
            .filter(|p| p.mode() != DedupMode::Unset || p.scope() != DedupScope::Unset);
        if let Some(p) = &policy {
            objectio_proto::dedup::validate(p).map_err(Status::invalid_argument)?;
        }

        let (expected_bytes, new_bucket, new_bytes) = {
            let buckets = self.buckets.read();
            let current = buckets
                .get(&req.bucket)
                .cloned()
                .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", req.bucket)))?;
            let expected = current.encode_to_vec();
            let mut new_bucket = current;
            new_bucket.dedup = policy;
            let new_bytes = new_bucket.encode_to_vec();
            (expected, new_bucket, new_bytes)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Buckets,
                    key: req.bucket.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "set-bucket-dedup".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket changed since read; retry"));
                    }
                    other => {
                        error!("unexpected raft response for set_bucket_dedup: {other:?}");
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&req.bucket, &new_bucket);
        }

        self.buckets.write().insert(req.bucket.clone(), new_bucket);
        info!("Set dedup policy for bucket '{}'", req.bucket);
        Ok(Response::new(
            objectio_proto::metadata::SetBucketDedupResponse {},
        ))
    }

    async fn get_dedup_policy(
        &self,
        request: Request<objectio_proto::metadata::GetDedupPolicyRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetDedupPolicyResponse>, Status> {
        let req = request.into_inner();
        let cluster = self
            .config
            .read()
            .get(objectio_proto::dedup::CLUSTER_KEY)
            .and_then(|e| objectio_proto::dedup::cluster_from_config(&e.value));
        let (bucket, tenant_name) = if req.bucket.is_empty() {
            (None, String::new())
        } else {
            let buckets = self.buckets.read();
            let b = buckets
                .get(&req.bucket)
                .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", req.bucket)))?;
            (b.dedup, b.tenant.clone())
        };
        let tenant = if req.bucket.is_empty() {
            None
        } else {
            self.tenants.read().get(&tenant_name).and_then(|t| t.dedup)
        };
        let e = objectio_proto::dedup::resolve(
            &req.bucket,
            &tenant_name,
            bucket.as_ref(),
            tenant.as_ref(),
            cluster.as_ref(),
        );
        let mut resp = objectio_proto::metadata::GetDedupPolicyResponse {
            bucket,
            tenant,
            cluster,
            tenant_name,
            effective_domain: e.domain,
            mode_from: e.mode_from.into(),
            scope_from: e.scope_from.into(),
            ..Default::default()
        };
        resp.set_effective_mode(e.mode);
        resp.set_effective_scope(e.scope);
        Ok(Response::new(resp))
    }

    async fn locate_chunks(
        &self,
        request: Request<objectio_proto::metadata::LocateChunksRequest>,
    ) -> Result<Response<objectio_proto::metadata::LocateChunksResponse>, Status> {
        let req = request.into_inner();
        let pool = self
            .buckets
            .read()
            .get(&req.bucket)
            .map(|b| b.pool.clone())
            .unwrap_or_default();
        let pg_count = if pool.is_empty() {
            0
        } else {
            self.pools.read().get(&pool).map_or(0, |p| p.pg_count)
        };
        // Without placement groups (today's default buckets), chunks map by
        // jump hash over the OSDs in placement — stable while membership is.
        let mut in_placement: Vec<([u8; 16], String)> = self
            .osd_nodes
            .read()
            .iter()
            .filter(|n| n.admin_state == objectio_common::OsdAdminState::In)
            .map(|n| (n.node_id, n.address.clone()))
            .collect();
        in_placement.sort();

        let (addresses, node_ids) = req
            .fingerprints
            .iter()
            .map(|fp| {
                let h = xxhash_rust::xxh64::xxh64(fp, 0);
                if pg_count > 0 {
                    let pg_id = objectio_placement::jump_consistent_hash(h, pg_count as i32) as u32;
                    return self
                        .placement_group(&pool, pg_id)
                        .and_then(|pg| pg.osd_ids.first().cloned())
                        .and_then(|id| <[u8; 16]>::try_from(id.as_slice()).ok())
                        .and_then(|id| self.osd_address_by_id(&id).map(|a| (a, id.to_vec())))
                        .unwrap_or_default();
                }
                if in_placement.is_empty() {
                    return (String::new(), Vec::new());
                }
                let i = objectio_placement::jump_consistent_hash(h, in_placement.len() as i32);
                let (id, addr) = &in_placement[i as usize];
                (addr.clone(), id.to_vec())
            })
            .unzip();
        Ok(Response::new(
            objectio_proto::metadata::LocateChunksResponse {
                addresses,
                node_ids,
            },
        ))
    }

    async fn set_bucket_owner(
        &self,
        request: Request<SetBucketOwnerRequest>,
    ) -> Result<Response<SetBucketOwnerResponse>, Status> {
        let req = request.into_inner();
        if req.owner.is_empty() {
            return Err(Status::invalid_argument("owner must not be empty"));
        }

        let (expected_bytes, new_bucket, new_bytes) = {
            let buckets = self.buckets.read();
            let current = buckets
                .get(&req.bucket)
                .cloned()
                .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", req.bucket)))?;
            let expected = current.encode_to_vec();
            let mut new_bucket = current;
            new_bucket.owner = req.owner.clone();
            let new_bytes = new_bucket.encode_to_vec();
            (expected, new_bucket, new_bytes)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Buckets,
                    key: req.bucket.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "set-bucket-owner".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("bucket changed since read; retry"));
                    }
                    other => {
                        error!("unexpected raft response for set_bucket_owner: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket(&req.bucket, &new_bucket);
        }

        self.buckets.write().insert(req.bucket.clone(), new_bucket);
        info!("Set owner for bucket '{}' to '{}'", req.bucket, req.owner);
        Ok(Response::new(SetBucketOwnerResponse { success: true }))
    }

    async fn get_bucket_versioning(
        &self,
        request: Request<GetBucketVersioningRequest>,
    ) -> Result<Response<GetBucketVersioningResponse>, Status> {
        let bucket_name = request.into_inner().bucket;
        let buckets = self.buckets.read();
        let bucket = buckets
            .get(&bucket_name)
            .ok_or_else(|| Status::not_found(format!("bucket '{}' not found", bucket_name)))?;
        Ok(Response::new(GetBucketVersioningResponse {
            state: bucket.versioning,
        }))
    }

    // ============================================================
    // Object Lock Configuration
    // ============================================================

    async fn put_object_lock_configuration(
        &self,
        request: Request<PutObjectLockConfigRequest>,
    ) -> Result<Response<PutObjectLockConfigResponse>, Status> {
        let req = request.into_inner();
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("missing object lock configuration"))?;

        // Verify bucket exists
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found(format!(
                "bucket '{}' not found",
                req.bucket
            )));
        }

        let bytes = config.encode_to_vec();
        let expected = self
            .object_lock_configs
            .read()
            .get(&req.bucket)
            .map(|c| c.encode_to_vec());

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("object_lock_configs".into()),
                    key: req.bucket.clone(),
                    expected,
                    new_value: Some(bytes.clone()),
                }],
                requested_by: "put-object-lock-config".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("object lock config changed; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for put_object_lock_config: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_object_lock_config(&req.bucket, &bytes);
        }

        self.object_lock_configs
            .write()
            .insert(req.bucket.clone(), config);
        info!("Set object lock config for bucket '{}'", req.bucket);
        Ok(Response::new(PutObjectLockConfigResponse { success: true }))
    }

    async fn get_object_lock_configuration(
        &self,
        request: Request<GetObjectLockConfigRequest>,
    ) -> Result<Response<GetObjectLockConfigResponse>, Status> {
        let bucket = request.into_inner().bucket;
        let configs = self.object_lock_configs.read();
        match configs.get(&bucket) {
            Some(config) => Ok(Response::new(GetObjectLockConfigResponse {
                config: Some(*config),
                found: true,
            })),
            None => Ok(Response::new(GetObjectLockConfigResponse {
                config: None,
                found: false,
            })),
        }
    }

    // ============================================================
    // Lifecycle Configuration
    // ============================================================

    async fn put_bucket_lifecycle(
        &self,
        request: Request<PutBucketLifecycleRequest>,
    ) -> Result<Response<PutBucketLifecycleResponse>, Status> {
        let req = request.into_inner();
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("missing lifecycle configuration"))?;

        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found(format!(
                "bucket '{}' not found",
                req.bucket
            )));
        }

        let bytes = config.encode_to_vec();
        let expected = self
            .lifecycle_configs
            .read()
            .get(&req.bucket)
            .map(|c| c.encode_to_vec());

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("lifecycle_configs".into()),
                    key: req.bucket.clone(),
                    expected,
                    new_value: Some(bytes.clone()),
                }],
                requested_by: "put-bucket-lifecycle".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("lifecycle config changed; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for put_bucket_lifecycle: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_lifecycle_config(&req.bucket, &bytes);
        }

        self.lifecycle_configs
            .write()
            .insert(req.bucket.clone(), config);
        info!(
            "Set lifecycle config for bucket '{}' ({} rules)",
            req.bucket,
            bytes.len()
        );
        Ok(Response::new(PutBucketLifecycleResponse { success: true }))
    }

    async fn get_bucket_lifecycle(
        &self,
        request: Request<GetBucketLifecycleRequest>,
    ) -> Result<Response<GetBucketLifecycleResponse>, Status> {
        let bucket = request.into_inner().bucket;
        let configs = self.lifecycle_configs.read();
        match configs.get(&bucket) {
            Some(config) => Ok(Response::new(GetBucketLifecycleResponse {
                config: Some(config.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetBucketLifecycleResponse {
                config: None,
                found: false,
            })),
        }
    }

    async fn delete_bucket_lifecycle(
        &self,
        request: Request<DeleteBucketLifecycleRequest>,
    ) -> Result<Response<DeleteBucketLifecycleResponse>, Status> {
        let bucket = request.into_inner().bucket;
        let expected = self
            .lifecycle_configs
            .read()
            .get(&bucket)
            .map(|c| c.encode_to_vec());
        if expected.is_none() {
            return Ok(Response::new(DeleteBucketLifecycleResponse {
                success: false,
            }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("lifecycle_configs".into()),
                    key: bucket.clone(),
                    expected,
                    new_value: None,
                }],
                requested_by: "delete-bucket-lifecycle".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("lifecycle changed since read; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delete_bucket_lifecycle: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_lifecycle_config(&bucket);
        }

        self.lifecycle_configs.write().remove(&bucket);
        info!("Deleted lifecycle config for bucket '{}'", bucket);
        Ok(Response::new(DeleteBucketLifecycleResponse {
            success: true,
        }))
    }

    // ============================================================
    // Bucket Default SSE Configuration
    // ============================================================

    async fn put_bucket_encryption(
        &self,
        request: Request<PutBucketEncryptionRequest>,
    ) -> Result<Response<PutBucketEncryptionResponse>, Status> {
        let req = request.into_inner();
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("missing bucket encryption configuration"))?;

        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found(format!(
                "bucket '{}' not found",
                req.bucket
            )));
        }

        let bytes = config.encode_to_vec();
        let expected = self
            .bucket_encryption_configs
            .read()
            .get(&req.bucket)
            .map(|c| c.encode_to_vec());

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("bucket_encryption_configs".into()),
                    key: req.bucket.clone(),
                    expected,
                    new_value: Some(bytes.clone()),
                }],
                requested_by: "put-bucket-encryption".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("encryption config changed; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for put_bucket_encryption: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_bucket_encryption_config(&req.bucket, &bytes);
        }

        self.bucket_encryption_configs
            .write()
            .insert(req.bucket.clone(), config);
        info!("Set bucket encryption config for bucket '{}'", req.bucket);
        Ok(Response::new(PutBucketEncryptionResponse { success: true }))
    }

    async fn get_bucket_encryption(
        &self,
        request: Request<GetBucketEncryptionRequest>,
    ) -> Result<Response<GetBucketEncryptionResponse>, Status> {
        let bucket = request.into_inner().bucket;
        let configs = self.bucket_encryption_configs.read();
        match configs.get(&bucket) {
            Some(config) => Ok(Response::new(GetBucketEncryptionResponse {
                config: Some(config.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetBucketEncryptionResponse {
                config: None,
                found: false,
            })),
        }
    }

    async fn report_version(
        &self,
        request: Request<objectio_proto::metadata::ReportVersionRequest>,
    ) -> Result<Response<objectio_proto::metadata::ReportVersionResponse>, Status> {
        let active_level = self.record_version(request.into_inner());
        Ok(Response::new(
            objectio_proto::metadata::ReportVersionResponse { active_level },
        ))
    }

    async fn get_upgrade_status(
        &self,
        _request: Request<objectio_proto::metadata::GetUpgradeStatusRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetUpgradeStatusResponse>, Status> {
        let plan = self.upgrade_plan();
        Ok(Response::new(
            objectio_proto::metadata::GetUpgradeStatusResponse {
                active_level: plan.active,
                nodes: plan.nodes,
                finalize_to: plan.target,
                blockers: plan.blockers,
            },
        ))
    }

    async fn finalize_upgrade(
        &self,
        request: Request<objectio_proto::metadata::FinalizeUpgradeRequest>,
    ) -> Result<Response<objectio_proto::metadata::FinalizeUpgradeResponse>, Status> {
        let active_level = self.finalize(&request.into_inner().requested_by).await?;
        Ok(Response::new(
            objectio_proto::metadata::FinalizeUpgradeResponse { active_level },
        ))
    }

    async fn acquire_lease(
        &self,
        request: Request<objectio_proto::metadata::AcquireLeaseRequest>,
    ) -> Result<Response<objectio_proto::metadata::AcquireLeaseResponse>, Status> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Lease {
            holder: String,
            expires_at: u64,
        }
        let req = request.into_inner();
        if req.name.is_empty() || req.holder.is_empty() {
            return Err(Status::invalid_argument("name and holder are required"));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let current_bytes = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(LEASES_TABLE, &req.name));
        let current = current_bytes
            .as_deref()
            .and_then(|b| serde_json::from_slice::<Lease>(b).ok());
        let held_by_other = current
            .as_ref()
            .is_some_and(|l| l.holder != req.holder && l.expires_at > now);
        if held_by_other {
            let l = current.unwrap_or(Lease {
                holder: String::new(),
                expires_at: 0,
            });
            return Ok(Response::new(
                objectio_proto::metadata::AcquireLeaseResponse {
                    acquired: false,
                    holder: l.holder,
                    expires_at: l.expires_at,
                },
            ));
        }
        let (new_value, lease) = if req.release {
            (
                None,
                Lease {
                    holder: String::new(),
                    expires_at: 0,
                },
            )
        } else {
            let lease = Lease {
                holder: req.holder.clone(),
                expires_at: now + req.ttl_secs.max(1),
            };
            (serde_json::to_vec(&lease).ok(), lease)
        };
        if req.release && current.is_none() {
            return Ok(Response::new(
                objectio_proto::metadata::AcquireLeaseResponse::default(),
            ));
        }
        // Compare-and-swap on what was read: of two callers racing for a
        // free lease, one commit wins and the other is refused.
        match self
            .cas_one(
                objectio_meta_store::CasTable::Named(LEASES_TABLE.into()),
                &req.name,
                current_bytes,
                new_value,
                "acquire-lease",
            )
            .await
        {
            Ok(()) => Ok(Response::new(
                objectio_proto::metadata::AcquireLeaseResponse {
                    acquired: !req.release,
                    holder: lease.holder,
                    expires_at: lease.expires_at,
                },
            )),
            Err(e) if e.code() == tonic::Code::Aborted => Ok(Response::new(
                objectio_proto::metadata::AcquireLeaseResponse::default(),
            )),
            Err(e) => Err(e),
        }
    }

    async fn get_bucket_setting(
        &self,
        request: Request<objectio_proto::metadata::GetBucketSettingRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetBucketSettingResponse>, Status> {
        let req = request.into_inner();
        let value = self.store.as_ref().and_then(|s| {
            s.read_named(
                BUCKET_SETTINGS_TABLE,
                &bucket_setting_key(&req.bucket, &req.name),
            )
        });
        Ok(Response::new(
            objectio_proto::metadata::GetBucketSettingResponse {
                found: value.is_some(),
                value: value.unwrap_or_default(),
            },
        ))
    }

    async fn put_bucket_setting(
        &self,
        request: Request<objectio_proto::metadata::PutBucketSettingRequest>,
    ) -> Result<Response<objectio_proto::metadata::PutBucketSettingResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() || req.name.contains('/') {
            return Err(Status::invalid_argument("invalid setting name"));
        }
        if !self.buckets.read().contains_key(&req.bucket) {
            return Err(Status::not_found("bucket not found"));
        }
        let key = bucket_setting_key(&req.bucket, &req.name);
        let current = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(BUCKET_SETTINGS_TABLE, &key));
        let existed = current.is_some();
        if req.delete && !existed {
            return Ok(Response::new(
                objectio_proto::metadata::PutBucketSettingResponse { existed },
            ));
        }
        self.cas_one(
            objectio_meta_store::CasTable::Named(BUCKET_SETTINGS_TABLE.into()),
            &key,
            current,
            (!req.delete).then_some(req.value),
            "put-bucket-setting",
        )
        .await?;
        Ok(Response::new(
            objectio_proto::metadata::PutBucketSettingResponse { existed },
        ))
    }

    async fn delete_bucket_encryption(
        &self,
        request: Request<DeleteBucketEncryptionRequest>,
    ) -> Result<Response<DeleteBucketEncryptionResponse>, Status> {
        let bucket = request.into_inner().bucket;
        let expected = self
            .bucket_encryption_configs
            .read()
            .get(&bucket)
            .map(|c| c.encode_to_vec());
        if expected.is_none() {
            return Ok(Response::new(DeleteBucketEncryptionResponse {
                success: false,
            }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named("bucket_encryption_configs".into()),
                    key: bucket.clone(),
                    expected,
                    new_value: None,
                }],
                requested_by: "delete-bucket-encryption".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("encryption config changed; retry"));
                    }
                    other => {
                        error!(
                            "unexpected raft response for delete_bucket_encryption: {:?}",
                            other
                        );
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_bucket_encryption_config(&bucket);
        }

        self.bucket_encryption_configs.write().remove(&bucket);
        info!("Deleted bucket encryption config for bucket '{}'", bucket);
        Ok(Response::new(DeleteBucketEncryptionResponse {
            success: true,
        }))
    }

    // ============================================================
    // KMS keys
    // ============================================================

    async fn create_kms_key(
        &self,
        request: Request<CreateKmsKeyRequest>,
    ) -> Result<Response<CreateKmsKeyResponse>, Status> {
        let req = request.into_inner();
        if req.wrapped_key_material.is_empty() {
            return Err(Status::invalid_argument(
                "wrapped_key_material is required — gateway wraps the raw key before sending",
            ));
        }
        let key_id = if req.key_id.trim().is_empty() {
            Self::generate_kms_key_id()
        } else {
            req.key_id.trim().to_string()
        };
        let now = Self::current_timestamp();
        if self.kms_keys.read().contains_key(&key_id) {
            return Err(Status::already_exists(format!(
                "KMS key '{key_id}' already exists"
            )));
        }
        let key = KmsKey {
            key_id: key_id.clone(),
            arn: format!("arn:obio:kms:::{key_id}"),
            description: req.description,
            wrapped_key_material: req.wrapped_key_material,
            status: 0, // KMS_KEY_ENABLED
            created_at: now,
            updated_at: now,
            created_by: req.created_by,
        };
        // Through Raft: a key only the old leader held would leave every
        // object encrypted under it unreadable after a failover. Created
        // only if no key has the id (compare-and-set against nothing).
        if self.raft_handle().is_some() {
            let created = self
                .cas_many(
                    vec![objectio_meta_store::CasOp {
                        table: CasTable::Named(KMS_KEYS_TABLE.into()),
                        key: key_id.clone(),
                        expected: None,
                        new_value: Some(key.encode_to_vec()),
                    }],
                    "create-kms-key",
                )
                .await?;
            if !created {
                return Err(Status::already_exists(format!(
                    "KMS key '{key_id}' already exists"
                )));
            }
        } else if let Some(store) = &self.store {
            store.put_kms_key(&key_id, &key.encode_to_vec());
        }
        self.kms_keys.write().insert(key_id.clone(), key.clone());
        info!("Created KMS key '{key_id}'");
        Ok(Response::new(CreateKmsKeyResponse { key: Some(key) }))
    }

    async fn get_kms_key(
        &self,
        request: Request<GetKmsKeyRequest>,
    ) -> Result<Response<GetKmsKeyResponse>, Status> {
        let key_id = request.into_inner().key_id;
        let map = self.kms_keys.read();
        match map.get(&key_id) {
            Some(k) => Ok(Response::new(GetKmsKeyResponse {
                key: Some(k.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetKmsKeyResponse {
                key: None,
                found: false,
            })),
        }
    }

    async fn list_kms_keys(
        &self,
        request: Request<ListKmsKeysRequest>,
    ) -> Result<Response<ListKmsKeysResponse>, Status> {
        let req = request.into_inner();
        let max = if req.max_results == 0 {
            1000
        } else {
            req.max_results as usize
        };
        let map = self.kms_keys.read();
        let mut keys: Vec<KmsKey> = map.values().cloned().collect();
        keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        // Simple pagination: treat page_token as the last key_id returned.
        if !req.page_token.is_empty() {
            keys.retain(|k| k.key_id > req.page_token);
        }
        let next_token = if keys.len() > max {
            keys[max - 1].key_id.clone()
        } else {
            String::new()
        };
        keys.truncate(max);
        Ok(Response::new(ListKmsKeysResponse {
            keys,
            next_page_token: next_token,
        }))
    }

    async fn delete_kms_key(
        &self,
        request: Request<DeleteKmsKeyRequest>,
    ) -> Result<Response<DeleteKmsKeyResponse>, Status> {
        let key_id = request.into_inner().key_id;
        let removed = self.kms_keys.read().contains_key(&key_id);
        if removed {
            self.replicate(
                vec![(KMS_KEYS_TABLE, key_id.clone(), None)],
                "delete-kms-key",
            )
            .await?;
            self.kms_keys.write().remove(&key_id);
            info!("Deleted KMS key '{key_id}'");
        }
        Ok(Response::new(DeleteKmsKeyResponse { success: removed }))
    }

    // ---- Named IAM Policies (PBAC) ----

    async fn create_policy(
        &self,
        request: Request<CreatePolicyRequest>,
    ) -> Result<Response<CreatePolicyResponse>, Status> {
        let req = request.into_inner();
        let plain = req.name.trim().to_string();
        if plain.is_empty() || plain.contains('/') {
            return Err(Status::invalid_argument(
                "Policy name is required, without \"/\"",
            ));
        }
        if req.shared && !req.tenant.is_empty() {
            return Err(Status::invalid_argument(
                "only system policies can be shared",
            ));
        }
        let name = iam_key(&req.tenant, &plain);
        if req.policy_json.trim().is_empty() {
            return Err(Status::invalid_argument("Policy JSON is required"));
        }
        // Validate that policy_json is valid JSON
        if serde_json::from_str::<serde_json::Value>(&req.policy_json).is_err() {
            return Err(Status::invalid_argument("Invalid JSON in policy document"));
        }

        if self.iam_policies.read().contains_key(&name) {
            return Err(Status::already_exists(format!(
                "Policy '{}' already exists",
                name
            )));
        }
        let now = Self::current_timestamp();
        let policy = PolicyObject {
            name: plain,
            policy_json: req.policy_json,
            created_at: now,
            updated_at: now,
            tenant: req.tenant,
            shared: req.shared,
        };
        let bytes = policy.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::IamPolicies,
                    key: name.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "create-iam-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("policy already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_policy: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_iam_policy(&name, &policy.encode_to_vec());
        }

        self.iam_policies
            .write()
            .insert(name.clone(), policy.clone());
        info!("Created IAM policy '{}'", name);
        Ok(Response::new(CreatePolicyResponse {
            policy: Some(policy),
        }))
    }

    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let name = request.into_inner().name;
        let map = self.iam_policies.read();
        match map.get(&name) {
            Some(policy) => Ok(Response::new(GetPolicyResponse {
                policy: Some(policy.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetPolicyResponse {
                policy: None,
                found: false,
            })),
        }
    }

    async fn list_policies(
        &self,
        _request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let map = self.iam_policies.read();
        let policies: Vec<PolicyObject> = map.values().cloned().collect();
        Ok(Response::new(ListPoliciesResponse { policies }))
    }

    async fn delete_policy(
        &self,
        request: Request<DeletePolicyRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        let name = request.into_inner().name;
        // Snapshot current state: policy row + every attachment row that
        // references this policy. The whole mutation lands as one atomic
        // MultiCas — a crash mid-delete can't leave orphan attachments.
        let (expected_policy_bytes, attachment_transitions) = {
            let policies = self.iam_policies.read();
            let Some(current) = policies.get(&name) else {
                return Ok(Response::new(DeletePolicyResponse { success: false }));
            };
            let expected = current.encode_to_vec();
            let mut transitions: Vec<(String, Vec<u8>, Option<Vec<u8>>, Vec<String>)> = Vec::new();
            let atts = self.policy_attachments.read();
            for (key, policy_names) in atts.iter() {
                if policy_names.contains(&name) {
                    let before = policy_names.clone();
                    let after: Vec<String> = policy_names
                        .iter()
                        .filter(|p| *p != &name)
                        .cloned()
                        .collect();
                    let old_bytes = before.join(",").into_bytes();
                    let new_bytes = if after.is_empty() {
                        None
                    } else {
                        Some(after.join(",").into_bytes())
                    };
                    transitions.push((key.clone(), old_bytes, new_bytes, after));
                }
            }
            (expected, transitions)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let mut ops = Vec::with_capacity(1 + attachment_transitions.len());
            ops.push(CasOp {
                table: CasTable::IamPolicies,
                key: name.clone(),
                expected: Some(expected_policy_bytes),
                new_value: None,
            });
            for (key, old, new, _) in &attachment_transitions {
                ops.push(CasOp {
                    table: CasTable::PolicyAttachments,
                    key: key.clone(),
                    expected: Some(old.clone()),
                    new_value: new.clone(),
                });
            }
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: "delete-iam-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { failed_indices } => {
                        return Err(Status::aborted(format!(
                            "policy or attachment changed mid-delete; retry (conflicts at ops {failed_indices:?})"
                        )));
                    }
                    other => {
                        error!("unexpected raft response for delete_policy: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_iam_policy(&name);
            for (key, _, new, after) in &attachment_transitions {
                if new.is_some() {
                    store.put_policy_attachment(key, &after.join(","));
                } else {
                    store.delete_policy_attachment(key);
                }
            }
        }

        // Mirror into in-memory caches.
        self.iam_policies.write().remove(&name);
        {
            let mut atts = self.policy_attachments.write();
            for (key, _, _, after) in attachment_transitions {
                if after.is_empty() {
                    atts.remove(&key);
                } else {
                    atts.insert(key, after);
                }
            }
        }
        info!("Deleted IAM policy '{}'", name);
        Ok(Response::new(DeletePolicyResponse { success: true }))
    }

    async fn attach_policy(
        &self,
        request: Request<AttachPolicyRequest>,
    ) -> Result<Response<AttachPolicyResponse>, Status> {
        let req = request.into_inner();
        let policy_name = req.policy_name;

        // Validate the policy exists
        if !self.iam_policies.read().contains_key(&policy_name) {
            return Err(Status::not_found(format!(
                "Policy '{}' not found",
                policy_name
            )));
        }

        let key = if !req.user_id.is_empty() {
            format!("user:{}", req.user_id)
        } else if !req.group_id.is_empty() {
            format!("group:{}", req.group_id)
        } else if !req.role_name.is_empty() {
            format!("role:{}", req.role_name)
        } else {
            return Err(Status::invalid_argument(
                "One of user_id, group_id or role_name is required",
            ));
        };

        // Snapshot current attachments under a read lock, compute the
        // transition, then CAS. Idempotent: if the policy is already
        // attached, no-op returns success without a Raft round-trip.
        let (expected_bytes, new_policies_vec) = {
            let atts = self.policy_attachments.read();
            let current: Vec<String> = atts.get(&key).cloned().unwrap_or_default();
            if current.contains(&policy_name) {
                return Ok(Response::new(AttachPolicyResponse { success: true }));
            }
            let old_bytes = if current.is_empty() {
                None
            } else {
                Some(current.join(",").into_bytes())
            };
            let mut after = current;
            after.push(policy_name.clone());
            (old_bytes, after)
        };
        let new_bytes = new_policies_vec.join(",").into_bytes();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::PolicyAttachments,
                    key: key.clone(),
                    expected: expected_bytes,
                    new_value: Some(new_bytes),
                }],
                requested_by: "attach-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("attachment changed since read; retry"));
                    }
                    other => {
                        error!("unexpected raft response for attach_policy: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_policy_attachment(&key, &new_policies_vec.join(","));
        }

        self.policy_attachments
            .write()
            .insert(key.clone(), new_policies_vec);
        info!("Attached policy '{}' to '{}'", policy_name, key);
        Ok(Response::new(AttachPolicyResponse { success: true }))
    }

    async fn detach_policy(
        &self,
        request: Request<DetachPolicyRequest>,
    ) -> Result<Response<DetachPolicyResponse>, Status> {
        let req = request.into_inner();
        let policy_name = req.policy_name;

        let key = if !req.user_id.is_empty() {
            format!("user:{}", req.user_id)
        } else if !req.group_id.is_empty() {
            format!("group:{}", req.group_id)
        } else if !req.role_name.is_empty() {
            format!("role:{}", req.role_name)
        } else {
            return Err(Status::invalid_argument(
                "One of user_id, group_id or role_name is required",
            ));
        };

        // Compute the transition under a read lock.
        let (expected_bytes, new_after) = {
            let atts = self.policy_attachments.read();
            let Some(current) = atts.get(&key).cloned() else {
                return Ok(Response::new(DetachPolicyResponse { success: false }));
            };
            if !current.contains(&policy_name) {
                return Ok(Response::new(DetachPolicyResponse { success: false }));
            }
            let old_bytes = current.join(",").into_bytes();
            let after: Vec<String> = current.into_iter().filter(|p| p != &policy_name).collect();
            (old_bytes, after)
        };

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let new_value = if new_after.is_empty() {
                None
            } else {
                Some(new_after.join(",").into_bytes())
            };
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::PolicyAttachments,
                    key: key.clone(),
                    expected: Some(expected_bytes),
                    new_value,
                }],
                requested_by: "detach-policy".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("attachment changed since read; retry"));
                    }
                    other => {
                        error!("unexpected raft response for detach_policy: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            if new_after.is_empty() {
                store.delete_policy_attachment(&key);
            } else {
                store.put_policy_attachment(&key, &new_after.join(","));
            }
        }

        let mut attachments = self.policy_attachments.write();
        if new_after.is_empty() {
            attachments.remove(&key);
        } else {
            attachments.insert(key.clone(), new_after);
        }
        info!("Detached policy '{}' from '{}'", policy_name, key);
        let removed = true;
        Ok(Response::new(DetachPolicyResponse { success: removed }))
    }

    async fn update_policy(
        &self,
        request: Request<UpdatePolicyRequest>,
    ) -> Result<Response<UpdatePolicyResponse>, Status> {
        let req = request.into_inner();
        if serde_json::from_str::<serde_json::Value>(&req.policy_json).is_err() {
            return Err(Status::invalid_argument("Invalid JSON in policy document"));
        }
        let old = self
            .iam_policies
            .read()
            .get(&req.name)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("Policy '{}' not found", req.name)))?;
        let mut new = old.clone();
        new.policy_json = req.policy_json;
        new.updated_at = Self::current_timestamp();
        self.cas_one(
            objectio_meta_store::CasTable::IamPolicies,
            &req.name,
            Some(old.encode_to_vec()),
            Some(new.encode_to_vec()),
            "update-iam-policy",
        )
        .await?;
        self.iam_policies
            .write()
            .insert(req.name.clone(), new.clone());
        info!("Updated IAM policy '{}'", req.name);
        Ok(Response::new(UpdatePolicyResponse { policy: Some(new) }))
    }

    async fn update_user(
        &self,
        request: Request<UpdateUserRequest>,
    ) -> Result<Response<UpdateUserResponse>, Status> {
        let req = request.into_inner();
        let old = self
            .users
            .read()
            .get(&req.user_id)
            .cloned()
            .filter(|u| u.status != UserStatus::UserDeleted as i32)
            .ok_or_else(|| Status::not_found("user not found"))?;
        let mut new = old.clone();
        if let Some(status) = req.status {
            if status != UserStatus::UserActive as i32 && status != UserStatus::UserSuspended as i32
            {
                return Err(Status::invalid_argument(
                    "status must be ACTIVE or SUSPENDED",
                ));
            }
            new.status = status;
        }
        if let Some(name) = req.display_name {
            new.display_name = name;
        }
        if let Some(email) = req.email {
            new.email = email;
        }
        let enc = |u: &StoredUser| -> Result<Vec<u8>, Box<Status>> {
            bincode::serialize(u)
                .map_err(|e| Box::new(Status::internal(format!("user encode: {e}"))))
        };
        self.cas_one(
            objectio_meta_store::CasTable::Users,
            &req.user_id,
            Some(enc(&old).map_err(|e| *e)?),
            Some(enc(&new).map_err(|e| *e)?),
            "update-user",
        )
        .await?;
        self.users.write().insert(req.user_id.clone(), new.clone());
        info!("Updated user {} (status {})", req.user_id, new.status);
        Ok(Response::new(UpdateUserResponse {
            user: Some(UserMeta {
                user_id: new.user_id,
                display_name: new.display_name,
                arn: new.arn,
                status: new.status,
                created_at: new.created_at,
                email: new.email,
                tenant: new.tenant,
            }),
        }))
    }

    async fn update_access_key(
        &self,
        request: Request<UpdateAccessKeyRequest>,
    ) -> Result<Response<UpdateAccessKeyResponse>, Status> {
        let req = request.into_inner();
        if req.status != KeyStatus::KeyActive as i32 && req.status != KeyStatus::KeyInactive as i32
        {
            return Err(Status::invalid_argument(
                "status must be ACTIVE or INACTIVE",
            ));
        }
        let old = self
            .access_keys
            .read()
            .get(&req.access_key_id)
            .cloned()
            .ok_or_else(|| Status::not_found("access key not found"))?;
        // A deleted user's keys stay off.
        if req.status == KeyStatus::KeyActive as i32
            && self
                .users
                .read()
                .get(&old.user_id)
                .is_none_or(|u| u.status == UserStatus::UserDeleted as i32)
        {
            return Err(Status::failed_precondition("the key's user is deleted"));
        }
        let mut new = old.clone();
        new.status = req.status;
        let enc = |k: &StoredAccessKey| -> Result<Vec<u8>, Box<Status>> {
            bincode::serialize(k)
                .map_err(|e| Box::new(Status::internal(format!("key encode: {e}"))))
        };
        self.cas_one(
            objectio_meta_store::CasTable::AccessKeys,
            &req.access_key_id,
            Some(enc(&old).map_err(|e| *e)?),
            Some(enc(&new).map_err(|e| *e)?),
            "update-access-key",
        )
        .await?;
        self.access_keys
            .write()
            .insert(req.access_key_id.clone(), new.clone());
        info!("Access key {} status {}", req.access_key_id, new.status);
        Ok(Response::new(UpdateAccessKeyResponse {
            key: Some(AccessKeyMeta {
                access_key_id: new.access_key_id,
                secret_access_key: String::new(),
                user_id: new.user_id,
                status: new.status,
                created_at: new.created_at,
                tenant: new.tenant,
                scope: new.scope,
                operation: new.operation,
            }),
        }))
    }

    async fn get_sts_signing_key(
        &self,
        _request: Request<objectio_proto::metadata::GetStsSigningKeyRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetStsSigningKeyResponse>, Status> {
        const TABLE: &str = "cluster_secrets";
        const KEY: &str = "sts-signing-key";
        let read = || {
            self.store
                .as_ref()
                .and_then(|s| s.read_named(TABLE, KEY))
                .filter(|k| k.len() >= 32)
        };
        if let Some(key) = read() {
            return Ok(Response::new(
                objectio_proto::metadata::GetStsSigningKeyResponse { key },
            ));
        }
        // First use: one random key, created only if none exists, so two
        // racing creators end up with the same one.
        let mut fresh = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut fresh);
        match self
            .cas_one(
                objectio_meta_store::CasTable::Named(TABLE.into()),
                KEY,
                None,
                Some(fresh),
                "create-sts-signing-key",
            )
            .await
        {
            Ok(()) => info!("Created the cluster's STS signing key"),
            Err(e) if e.code() == tonic::Code::Aborted => {}
            Err(e) => return Err(e),
        }
        read()
            .map(|key| Response::new(objectio_proto::metadata::GetStsSigningKeyResponse { key }))
            .ok_or_else(|| Status::unavailable("STS signing key not readable yet; retry"))
    }

    async fn create_role(
        &self,
        request: Request<CreateRoleRequest>,
    ) -> Result<Response<CreateRoleResponse>, Status> {
        let mut role = request
            .into_inner()
            .role
            .ok_or_else(|| Status::invalid_argument("role is required"))?;
        role.name = role.name.trim().to_string();
        if role.name.is_empty()
            || !role
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c))
        {
            return Err(Status::invalid_argument(
                "role name: letters, digits and +=,.@_- only",
            ));
        }
        if serde_json::from_str::<serde_json::Value>(&role.trust_policy_json).is_err() {
            return Err(Status::invalid_argument(
                "trust policy must be a JSON document",
            ));
        }
        let now = Self::current_timestamp();
        role.arn = format!(
            "arn:obio:iam::{}:role/{}",
            if role.tenant.is_empty() {
                "objectio"
            } else {
                &role.tenant
            },
            role.name
        );
        role.created_at = now;
        role.updated_at = now;
        self.cas_one(
            objectio_meta_store::CasTable::Named(ROLES_TABLE.into()),
            &iam_key(&role.tenant, &role.name),
            None,
            Some(role.encode_to_vec()),
            "create-role",
        )
        .await
        .map_err(|e| {
            if e.code() == tonic::Code::Aborted {
                Status::already_exists(format!("role '{}' already exists", role.name))
            } else {
                e
            }
        })?;
        info!("Created role {}", role.arn);
        Ok(Response::new(CreateRoleResponse { role: Some(role) }))
    }

    async fn get_role(
        &self,
        request: Request<GetRoleRequest>,
    ) -> Result<Response<GetRoleResponse>, Status> {
        let role = self.role(&request.into_inner().name);
        Ok(Response::new(GetRoleResponse {
            found: role.is_some(),
            role,
        }))
    }

    async fn list_roles(
        &self,
        request: Request<ListRolesRequest>,
    ) -> Result<Response<ListRolesResponse>, Status> {
        let tenant = request.into_inner().tenant;
        let roles = self
            .store
            .as_ref()
            .map(|s| s.list_named(ROLES_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, b)| RoleObject::decode(b.as_slice()).ok())
            .filter(|r| tenant.is_empty() || r.tenant == tenant)
            .collect();
        Ok(Response::new(ListRolesResponse { roles }))
    }

    async fn update_role(
        &self,
        request: Request<UpdateRoleRequest>,
    ) -> Result<Response<UpdateRoleResponse>, Status> {
        let req = request.into_inner();
        let old = self
            .role(&req.name)
            .ok_or_else(|| Status::not_found(format!("role '{}' not found", req.name)))?;
        let mut new = old.clone();
        if let Some(d) = req.description {
            new.description = d;
        }
        if let Some(t) = req.trust_policy_json {
            if serde_json::from_str::<serde_json::Value>(&t).is_err() {
                return Err(Status::invalid_argument(
                    "trust policy must be a JSON document",
                ));
            }
            new.trust_policy_json = t;
        }
        if let Some(m) = req.max_session_seconds {
            new.max_session_seconds = m;
        }
        new.updated_at = Self::current_timestamp();
        self.cas_one(
            objectio_meta_store::CasTable::Named(ROLES_TABLE.into()),
            &req.name,
            Some(old.encode_to_vec()),
            Some(new.encode_to_vec()),
            "update-role",
        )
        .await?;
        Ok(Response::new(UpdateRoleResponse { role: Some(new) }))
    }

    async fn delete_role(
        &self,
        request: Request<DeleteRoleRequest>,
    ) -> Result<Response<DeleteRoleResponse>, Status> {
        let name = request.into_inner().name;
        let old = self
            .role(&name)
            .ok_or_else(|| Status::not_found(format!("role '{name}' not found")))?;
        self.cas_one(
            objectio_meta_store::CasTable::Named(ROLES_TABLE.into()),
            &name,
            Some(old.encode_to_vec()),
            None,
            "delete-role",
        )
        .await?;
        info!("Deleted role {}", old.arn);
        Ok(Response::new(DeleteRoleResponse { success: true }))
    }

    async fn list_attached_policies(
        &self,
        request: Request<ListAttachedPoliciesRequest>,
    ) -> Result<Response<ListAttachedPoliciesResponse>, Status> {
        let req = request.into_inner();
        let key = if !req.user_id.is_empty() {
            format!("user:{}", req.user_id)
        } else if !req.group_id.is_empty() {
            format!("group:{}", req.group_id)
        } else if !req.role_name.is_empty() {
            format!("role:{}", req.role_name)
        } else {
            return Err(Status::invalid_argument(
                "One of user_id, group_id or role_name is required",
            ));
        };

        let attachments = self.policy_attachments.read();
        let policy_names = attachments.get(&key).cloned().unwrap_or_default();
        Ok(Response::new(ListAttachedPoliciesResponse { policy_names }))
    }
}

/// The (node, disk) pairs the legacy placement engine may choose from.
///
/// Extracted from `get_placement_legacy` so it can be tested without standing
/// up a whole `MetaService`. The filter is the point: this path used to
/// collect every registered node with no filter at all, so marking an OSD Out
/// removed it from the CRUSH engine — which honours intent through
/// `active_nodes()` — and not from this one. Which engine answered then
/// decided whether the operator's instruction meant anything.
fn eligible_disks(nodes: &[OsdNode]) -> Vec<(&OsdNode, &[u8; 16])> {
    nodes
        .iter()
        .filter(|node| node.admin_state == objectio_common::OsdAdminState::In)
        .flat_map(|node| node.disk_ids.iter().map(move |disk_id| (node, disk_id)))
        .collect()
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
mod placement_tests {
    use super::*;
    use objectio_common::OsdAdminState;

    fn node(id: u8, disks: usize, admin_state: OsdAdminState) -> OsdNode {
        OsdNode {
            node_id: [id; 16],
            address: format!("http://127.0.0.1:{}", 9200 + u16::from(id)),
            disk_ids: (0..disks).map(|d| [id * 10 + d as u8; 16]).collect(),
            failure_domain: None,
            topology: None,
            disk_capacity_bytes: vec![1_000_000_000; disks],
            admin_state,
            te_segment: String::new(),
        }
    }

    #[test]
    fn every_disk_of_an_in_node_is_selectable() {
        let nodes = vec![node(1, 2, OsdAdminState::In), node(2, 3, OsdAdminState::In)];
        assert_eq!(eligible_disks(&nodes).len(), 5);
    }

    #[test]
    fn an_out_node_is_not_handed_writes() {
        // The operator said no. Before this filter existed, the legacy engine
        // ignored that entirely and kept placing on it.
        let nodes = vec![
            node(1, 2, OsdAdminState::In),
            node(2, 2, OsdAdminState::Out),
        ];
        let picked = eligible_disks(&nodes);
        assert_eq!(picked.len(), 2);
        assert!(
            picked.iter().all(|(n, _)| n.node_id == [1; 16]),
            "a node marked Out was selected"
        );
    }

    #[test]
    fn a_draining_node_is_not_handed_writes() {
        // Draining means "no new data, keep serving reads" — placing on it
        // would fight the drain that is trying to empty it.
        let nodes = vec![
            node(1, 1, OsdAdminState::In),
            node(2, 4, OsdAdminState::Draining),
        ];
        let picked = eligible_disks(&nodes);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].0.node_id, [1; 16]);
    }

    #[test]
    fn no_eligible_nodes_yields_nothing_rather_than_a_default() {
        // The caller turns this into "no storage nodes are accepting writes",
        // which is actionable. Falling back to any node would place data on a
        // disk the operator is trying to remove.
        let nodes = vec![
            node(1, 2, OsdAdminState::Out),
            node(2, 2, OsdAdminState::Draining),
        ];
        assert!(eligible_disks(&nodes).is_empty());
    }

    #[test]
    fn a_node_with_no_disks_contributes_nothing() {
        // The stale registration that broke writes on the live cluster looked
        // exactly like this: still listed, zero disks.
        let nodes = vec![node(1, 0, OsdAdminState::In), node(2, 2, OsdAdminState::In)];
        let picked = eligible_disks(&nodes);
        assert_eq!(picked.len(), 2);
        assert!(picked.iter().all(|(n, _)| n.node_id == [2; 16]));
    }

    #[test]
    fn an_empty_cluster_is_empty() {
        assert!(eligible_disks(&[]).is_empty());
    }
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
    use objectio_proto::metadata::metadata_service_server::MetadataService;
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
    use objectio_proto::metadata::metadata_service_server::MetadataService;
    use objectio_proto::metadata::{
        AbortMultipartUploadRequest, CompleteMultipartUploadRequest, CreateBucketRequest,
        CreateMultipartUploadRequest, PartInfo, RegisterPartRequest, StripeMeta,
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
        svc.pack_move_shard(&pack, 2, [2; 16], &to).await.unwrap();
        // A retry finds it moved already.
        svc.pack_move_shard(&pack, 2, [2; 16], &to).await.unwrap();
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
