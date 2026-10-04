//! The command tree. Every command maps to one gateway admin-API route (or
//! an S3 subresource on the bucket), named in its doc comment.
//!
//! Doc comments here are `--help` text, so they are written for a terminal,
//! not for rustdoc.
#![allow(clippy::doc_markdown)]

use crate::output::Format;
use clap::{Args as ClapArgs, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "obioctl", version, about = "ObjectIO management CLI")]
#[command(
    after_help = "Credentials: --access-key/--secret-key, OBJECTIO_ACCESS_KEY(_FILE)/\
OBJECTIO_SECRET_KEY(_FILE) (AWS_* accepted), or a profile in ~/.objectio/config \
written by `obioctl configure`."
)]
pub struct Args {
    /// Gateway URL, e.g. https://s3.example.com [env: OBJECTIO_ENDPOINT, OBJECTIO_URL]
    #[arg(long, global = true)]
    pub endpoint: Option<String>,

    /// Access key ID [env: OBJECTIO_ACCESS_KEY, AWS_ACCESS_KEY_ID]
    #[arg(long, global = true)]
    pub access_key: Option<String>,

    /// Secret key. Prefer OBJECTIO_SECRET_KEY_FILE or a profile: a flag is
    /// visible in the process list.
    #[arg(long, global = true)]
    pub secret_key: Option<String>,

    /// SigV4 region [env: OBJECTIO_REGION, AWS_REGION] [default: us-east-1]
    #[arg(long, global = true)]
    pub region: Option<String>,

    /// Profile in ~/.objectio/config [env: OBJECTIO_PROFILE] [default: default]
    #[arg(long, global = true)]
    pub profile: Option<String>,

    /// Output format: human tables, or the API's JSON for scripts
    #[arg(short, long, global = true, value_enum, default_value = "table")]
    pub output: Format,

    /// Block gateway gRPC endpoint, for `volume` and `snapshot`
    #[arg(
        long,
        global = true,
        env = "OBJECTIO_BLOCK_ENDPOINT",
        default_value = "http://localhost:9300"
    )]
    pub block_endpoint: String,

    /// Log level
    #[arg(long, global = true, default_value = "warn")]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Save an endpoint and credentials as a profile in ~/.objectio/config
    Configure(ConfigureArgs),
    /// Tenants and their admins (system admin)
    Tenant {
        #[command(subcommand)]
        action: TenantCmd,
    },
    /// IAM users
    User {
        #[command(subcommand)]
        action: UserCmd,
    },
    /// Access keys
    Key {
        #[command(subcommand)]
        action: KeyCmd,
    },
    /// Named IAM policies and their attachments
    Policy {
        #[command(subcommand)]
        action: PolicyCmd,
    },
    /// IAM groups
    Group {
        #[command(subcommand)]
        action: GroupCmd,
    },
    /// IAM roles (assumed through STS)
    Role {
        #[command(subcommand)]
        action: RoleCmd,
    },
    /// OIDC identity providers
    Oidc {
        #[command(subcommand)]
        action: OidcCmd,
    },
    /// Temporary credentials from an OIDC token (keyless)
    Sts {
        #[command(subcommand)]
        action: StsCmd,
    },
    /// Block Public Access: cluster, tenant and bucket level
    PublicAccessBlock {
        #[command(subcommand)]
        action: PabCmd,
    },
    /// The audit event stream configuration
    Audit {
        #[command(subcommand)]
        action: AuditCmd,
    },
    /// Buckets: create, owner, policy, dedup, lifecycle, CORS
    Bucket {
        #[command(subcommand)]
        action: BucketCmd,
    },
    /// A bucket and the one scoped credential that reaches it
    Provision {
        #[command(subcommand)]
        action: ProvisionCmd,
    },
    /// Cluster state (system admin)
    Cluster {
        #[command(subcommand)]
        action: ClusterCmd,
    },
    /// Rolling upgrades: every node's release, and finalize (system admin)
    Upgrade {
        #[command(subcommand)]
        action: UpgradeCmd,
    },
    /// Storage nodes (OSDs)
    Node {
        #[command(subcommand)]
        action: NodeCmd,
    },
    /// OSD administrative state
    Osd {
        #[command(subcommand)]
        action: OsdCmd,
    },
    /// Storage pools (system admin)
    Pool {
        #[command(subcommand)]
        action: PoolCmd,
    },
    /// Key management (SSE-KMS)
    Kms {
        #[command(subcommand)]
        action: KmsCmd,
    },
    /// Iceberg warehouses
    Warehouse {
        #[command(subcommand)]
        action: WarehouseCmd,
    },
    /// Stored cluster configuration (system admin)
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// PromQL through the gateway's Prometheus proxy
    Metrics {
        #[command(subcommand)]
        action: MetricsCmd,
    },
    /// Block volumes (gRPC to the block gateway)
    Volume {
        #[command(subcommand)]
        action: VolumeCmd,
    },
    /// Block snapshots (gRPC to the block gateway)
    Snapshot {
        #[command(subcommand)]
        action: SnapshotCmd,
    },
}

// ── configure ───────────────────────────────────────────────────────────

#[derive(ClapArgs, Debug)]
pub struct ConfigureArgs {
    /// List the profiles (secrets masked) instead of writing one
    #[arg(long)]
    pub list: bool,
    /// Do not prompt; take only --endpoint/--access-key/--secret-key/--region
    #[arg(long)]
    pub non_interactive: bool,
}

/// `--tenant`: omitted means the caller's own tenant; it is never sent empty.
#[derive(ClapArgs, Debug, Clone, Default)]
pub struct TenantOpt {
    /// Tenant to act in (default: your own; the system admin's is system scope)
    #[arg(long, value_parser = non_empty)]
    pub tenant: Option<String>,
}

fn non_empty(s: &str) -> Result<String, String> {
    if s.trim().is_empty() {
        Err("must not be empty (omit the flag for your own tenant)".into())
    } else {
        Ok(s.trim().to_string())
    }
}

// ── tenant ──────────────────────────────────────────────────────────────

#[derive(ClapArgs, Debug, Default)]
pub struct TenantFields {
    /// Human-readable name
    #[arg(long)]
    pub display_name: Option<String>,
    /// Pool new buckets land in
    #[arg(long)]
    pub default_pool: Option<String>,
    /// Pools the tenant may use (repeatable)
    #[arg(long = "allowed-pool")]
    pub allowed_pools: Vec<String>,
    /// Byte quota, e.g. 500G or 2T (0 = unlimited)
    #[arg(long)]
    pub quota_bytes: Option<String>,
    /// Bucket count quota (0 = unlimited)
    #[arg(long)]
    pub quota_buckets: Option<u64>,
    /// Object count quota (0 = unlimited)
    #[arg(long)]
    pub quota_objects: Option<u64>,
    /// OIDC provider the tenant's users sign in with
    #[arg(long)]
    pub oidc_provider: Option<String>,
    /// Label key=value (repeatable)
    #[arg(long = "label")]
    pub labels: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum TenantCmd {
    /// GET /_admin/tenants
    List,
    /// GET /_admin/tenants/{name}
    Show { name: String },
    /// POST /_admin/tenants
    Create {
        name: String,
        #[command(flatten)]
        fields: TenantFields,
        /// Create it disabled
        #[arg(long)]
        disabled: bool,
    },
    /// PUT /_admin/tenants/{name} — only the fields given change
    Update {
        name: String,
        #[command(flatten)]
        fields: TenantFields,
        /// Enable or disable the tenant
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// DELETE /_admin/tenants/{name} (its buckets must be gone)
    Delete { name: String },
    /// Tenant admins
    Admin {
        #[command(subcommand)]
        action: TenantAdminCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum TenantAdminCmd {
    /// GET /_admin/tenants/{name} → admin_users
    List { tenant: String },
    /// POST /_admin/tenants/{name}/admins
    Add {
        tenant: String,
        /// user_id, or a user ARN (arn:...)
        user: String,
    },
    /// DELETE /_admin/tenants/{name}/admins/{user}
    Remove {
        tenant: String,
        /// As it was added: user_id or ARN
        user: String,
    },
}

// ── user / key ──────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum UserCmd {
    /// GET /_admin/users (filtered to --tenant when given)
    List {
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// GET /_admin/users/{id}
    Show { user_id: String },
    /// POST /_admin/users
    Create {
        display_name: String,
        #[arg(long)]
        email: Option<String>,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// PUT /_admin/users/{id}
    Update {
        user_id: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        email: Option<String>,
    },
    /// PUT /_admin/users/{id} {"status":"suspended"} — every key refused, nothing deleted
    Suspend { user_id: String },
    /// PUT /_admin/users/{id} {"status":"active"}
    Activate { user_id: String },
    /// DELETE /_admin/users/{id} (and its keys)
    Delete { user_id: String },
}

#[derive(Subcommand, Debug)]
pub enum KeyCmd {
    /// GET /_admin/users/{id}/access-keys
    List { user_id: String },
    /// POST /_admin/users/{id}/access-keys — the secret is shown once
    Create {
        user_id: String,
        /// Confine the key, e.g. s3://bucket/ or s3://bucket/prefix/
        #[arg(long)]
        scope: Option<String>,
        /// A key that refuses PUT, POST and DELETE
        #[arg(long)]
        read_only: bool,
    },
    /// PUT /_admin/access-keys/{id} {"status":"active"}
    Activate { access_key_id: String },
    /// PUT /_admin/access-keys/{id} {"status":"inactive"}
    Deactivate { access_key_id: String },
    /// DELETE /_admin/access-keys/{id}
    Delete { access_key_id: String },
}

// ── policy / group / role ───────────────────────────────────────────────

/// Exactly one principal.
#[derive(ClapArgs, Debug)]
#[group(required = true, multiple = false)]
pub struct Principal {
    /// A user_id
    #[arg(long)]
    pub user: Option<String>,
    /// A group_id
    #[arg(long)]
    pub group: Option<String>,
    /// A role name (in --tenant, or your own)
    #[arg(long)]
    pub role: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// GET /_admin/policies[?tenant=]
    List {
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// GET /_admin/policies/{name}[?tenant=]
    Show {
        name: String,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// POST /_admin/policies[?tenant=]
    Create {
        name: String,
        /// Policy JSON, or - for stdin
        #[arg(long)]
        file: PathBuf,
        /// Publish a system policy for tenants to attach (system admin)
        #[arg(long)]
        shared: bool,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// PUT /_admin/policies/{name}[?tenant=] — replaced in place, stays attached
    Update {
        name: String,
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// DELETE /_admin/policies/{name}[?tenant=]
    Delete {
        name: String,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// POST /_admin/policies/attach
    Attach {
        name: String,
        #[command(flatten)]
        to: Principal,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// POST /_admin/policies/detach
    Detach {
        name: String,
        #[command(flatten)]
        from: Principal,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// GET /_admin/policies/attached
    Attached {
        #[command(flatten)]
        of: Principal,
        #[command(flatten)]
        tenant: TenantOpt,
    },
}

#[derive(Subcommand, Debug)]
pub enum GroupCmd {
    /// GET /_admin/groups[?tenant=]
    List {
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// GET /_admin/groups/{id}
    Show { group_id: String },
    /// POST /_admin/groups[?tenant=]
    Create {
        name: String,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// DELETE /_admin/groups/{id}
    Delete { group_id: String },
    /// POST /_admin/groups/{id}/members
    AddUser { group_id: String, user_id: String },
    /// DELETE /_admin/groups/{id}/members/{user_id}
    RemoveUser { group_id: String, user_id: String },
}

#[derive(Subcommand, Debug)]
pub enum RoleCmd {
    /// GET /_admin/roles[?tenant=]
    List {
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// GET /_admin/roles/{name}[?tenant=]
    Show {
        name: String,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// POST /_admin/roles[?tenant=]
    Create {
        name: String,
        /// Trust policy JSON, or - for stdin
        #[arg(long)]
        trust_file: PathBuf,
        #[arg(long)]
        description: Option<String>,
        /// Cap on assumed sessions (default: one hour)
        #[arg(long)]
        max_session_seconds: Option<u32>,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// PUT /_admin/roles/{name}[?tenant=] — only what is given changes
    Update {
        name: String,
        #[arg(long)]
        trust_file: Option<PathBuf>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        max_session_seconds: Option<u32>,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// DELETE /_admin/roles/{name}[?tenant=]
    Delete {
        name: String,
        #[command(flatten)]
        tenant: TenantOpt,
    },
}

// ── oidc / sts ──────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum OidcCmd {
    /// GET /_admin/config?prefix=identity/openid/
    List,
    /// GET /_admin/config/identity/openid/{name}
    Show { name: String },
    /// PUT /_admin/config/identity/openid/{name} — replaces the provider
    Put {
        name: String,
        /// Provider JSON (issuer_url, client_id, client_secret, ...), or - for stdin
        #[arg(long)]
        file: PathBuf,
    },
    /// DELETE /_admin/config/identity/openid/{name}
    Delete { name: String },
    /// Print a tenant's own provider name, t-<tenant> (no request)
    TenantName { tenant: String },
}

#[derive(Subcommand, Debug)]
pub enum StsCmd {
    /// POST / Action=AssumeRoleWithWebIdentity (unsigned: the token is the proof)
    AssumeRoleWithWebIdentity {
        /// arn:obio:iam::<tenant>:role/<name>
        #[arg(long)]
        role_arn: String,
        /// The OIDC ID token
        #[arg(
            long,
            conflicts_with = "token_file",
            required_unless_present = "token_file"
        )]
        token: Option<String>,
        /// A file holding the token (e.g. a projected service-account token)
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long, default_value = "obioctl")]
        session_name: String,
        #[arg(long)]
        duration_seconds: Option<u32>,
        /// Print `export AWS_...=` lines for a shell
        #[arg(long)]
        env: bool,
    },
}

// ── public access block / audit ─────────────────────────────────────────

#[derive(ClapArgs, Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // S3's four flags, as S3 names them
pub struct PabFlags {
    /// Set all four flags
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub block_public_acls: bool,
    #[arg(long)]
    pub ignore_public_acls: bool,
    #[arg(long)]
    pub block_public_policy: bool,
    #[arg(long)]
    pub restrict_public_buckets: bool,
}

#[derive(Subcommand, Debug)]
pub enum PabCmd {
    /// GET /_admin/public-access-block[?tenant=] (no tenant as system admin: the cluster)
    Get {
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// PUT /_admin/public-access-block[?tenant=] — replaces: flags not given are cleared
    Put {
        #[command(flatten)]
        flags: PabFlags,
        /// Cluster only: whether new buckets start fully blocked
        #[arg(long)]
        new_buckets_blocked: Option<bool>,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// DELETE /_admin/public-access-block[?tenant=]
    Delete {
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// A bucket's own block (S3 ?publicAccessBlock)
    Bucket {
        #[command(subcommand)]
        action: PabBucketCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum PabBucketCmd {
    /// GET /{bucket}?publicAccessBlock
    Get { bucket: String },
    /// PUT /{bucket}?publicAccessBlock — flags not given are cleared
    Put {
        bucket: String,
        #[command(flatten)]
        flags: PabFlags,
    },
    /// DELETE /{bucket}?publicAccessBlock
    Delete { bucket: String },
    /// GET /{bucket}?policyStatus — is the bucket policy public?
    PolicyStatus { bucket: String },
}

#[derive(Subcommand, Debug)]
pub enum AuditCmd {
    /// GET /_admin/audit[?tenant=]
    Get {
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// PUT /_admin/audit[?tenant=] — replaces the configuration
    Put {
        /// Configuration JSON ({"targets": [...]}), or - for stdin
        #[arg(long)]
        file: PathBuf,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// DELETE /_admin/audit[?tenant=]
    Delete {
        #[command(flatten)]
        tenant: TenantOpt,
    },
}

// ── bucket / provision ──────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum BucketCmd {
    /// GET /_admin/buckets (filtered to --tenant when given)
    List {
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// GET /_admin/buckets, the one named
    Show { name: String },
    /// POST /_admin/buckets
    Create {
        name: String,
        /// Storage pool (the tenant's default or one of its allowed pools)
        #[arg(long)]
        pool: Option<String>,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// DELETE /_admin/buckets/{name} (must be empty)
    Delete { name: String },
    /// PUT /_admin/buckets/{name}/owner
    SetOwner { name: String, owner: String },
    /// PUT /_admin/buckets/{name}/quota: byte and object quotas; a write
    /// that would pass one is refused (403 QuotaExceeded)
    SetQuota {
        name: String,
        /// Byte quota, e.g. 500G or 2T (0 = unlimited)
        #[arg(long, default_value = "0")]
        bytes: String,
        /// Object count quota (0 = unlimited)
        #[arg(long, default_value_t = 0)]
        objects: u64,
    },
    /// Bucket policy
    Policy {
        #[command(subcommand)]
        action: BucketPolicyCmd,
    },
    /// Deduplication policy
    Dedup {
        #[command(subcommand)]
        action: BucketDedupCmd,
    },
    /// Lifecycle configuration (S3 ?lifecycle, XML)
    Lifecycle {
        #[command(subcommand)]
        action: XmlDocCmd,
    },
    /// CORS configuration (S3 ?cors, XML)
    Cors {
        #[command(subcommand)]
        action: XmlDocCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum BucketPolicyCmd {
    /// GET /_admin/buckets/{name}/policy
    Get { bucket: String },
    /// PUT /_admin/buckets/{name}/policy
    Put {
        bucket: String,
        /// Policy JSON, or - for stdin
        #[arg(long)]
        file: PathBuf,
    },
    /// DELETE /_admin/buckets/{name}/policy
    Delete { bucket: String },
}

#[derive(Subcommand, Debug)]
pub enum BucketDedupCmd {
    /// GET /_admin/buckets/{name}/dedup
    Get { bucket: String },
    /// PUT /_admin/buckets/{name}/dedup
    Set {
        bucket: String,
        /// off | dry-run | on (omit to inherit)
        #[arg(long)]
        mode: Option<String>,
        /// bucket | tenant | cluster (omit to inherit)
        #[arg(long)]
        scope: Option<String>,
    },
    /// DELETE /_admin/buckets/{name}/dedup — inherit everything
    Delete { bucket: String },
}

#[derive(Subcommand, Debug)]
pub enum XmlDocCmd {
    /// GET /{bucket}?<subresource>
    Get { bucket: String },
    /// PUT /{bucket}?<subresource>
    Put {
        bucket: String,
        /// The XML document, or - for stdin
        #[arg(long)]
        file: PathBuf,
    },
    /// DELETE /{bucket}?<subresource>
    Delete { bucket: String },
}

#[derive(Subcommand, Debug)]
pub enum ProvisionCmd {
    /// Create a bucket and mint a key scoped to it (two calls, no policy)
    Bucket {
        name: String,
        /// User the key is minted on (normally the provisioner's own) [env: OBJECTIO_PROVISIONER_USER_ID]
        #[arg(long)]
        user: Option<String>,
        /// Confine further to s3://<bucket>/<prefix> (must end in /)
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long)]
        read_only: bool,
        /// Storage pool for the bucket
        #[arg(long)]
        pool: Option<String>,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// Mint a fresh key scoped to a provisioned bucket (the old one keeps working)
    RotateKey {
        name: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        read_only: bool,
    },
    /// Revoke every key scoped to the bucket, then delete it (must be empty)
    Deprovision {
        name: String,
        #[arg(long)]
        user: Option<String>,
    },
}

// ── cluster / node / osd / pool ─────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum ClusterCmd {
    /// GET /_admin/cluster-info
    Info,
    /// GET /_admin/topology
    Topology,
    /// GET /_admin/usage
    Usage,
    /// GET /_admin/drain-status
    DrainStatus,
    /// GET /_admin/placement/validate?pool=
    ValidatePlacement { pool: String },
    /// The rebalancer
    Rebalance {
        #[command(subcommand)]
        action: RebalanceCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum UpgradeCmd {
    /// GET /_admin/upgrade: every node's release and format level, and
    /// whether the upgrade can be finalized
    Status,
    /// POST /_admin/upgrade/finalize: once every node runs the new release,
    /// let the cluster write its new formats. There is no going back to
    /// the previous release afterwards; back up meta first.
    Finalize,
}

#[derive(Subcommand, Debug)]
pub enum RebalanceCmd {
    /// GET /_admin/rebalance-status
    Status,
    /// POST /_admin/rebalance/pause
    Pause,
    /// POST /_admin/rebalance/resume
    Resume,
}

#[derive(Subcommand, Debug)]
pub enum NodeCmd {
    /// GET /_admin/nodes
    List,
    /// GET /_admin/nodes, the one whose node_id or name matches
    Show { node: String },
}

#[derive(Subcommand, Debug)]
pub enum OsdCmd {
    /// PUT /_admin/osds/{node_id}/admin-state
    SetState {
        /// The 32-hex-character node_id from `node list`
        node_id: String,
        #[arg(value_parser = ["in", "out", "draining"])]
        state: String,
    },
}

#[derive(ClapArgs, Debug, Default)]
pub struct PoolFields {
    /// 0 = Reed-Solomon, 1 = LRC, 2 = replication
    #[arg(long)]
    pub ec_type: Option<u32>,
    #[arg(long)]
    pub ec_k: Option<u32>,
    #[arg(long)]
    pub ec_m: Option<u32>,
    #[arg(long)]
    pub ec_local_parity: Option<u32>,
    #[arg(long)]
    pub ec_global_parity: Option<u32>,
    #[arg(long)]
    pub replication_count: Option<u32>,
    /// OSD tag the pool is confined to (repeatable)
    #[arg(long = "osd-tag")]
    pub osd_tags: Vec<String>,
    /// node | rack | datacenter | ...
    #[arg(long)]
    pub failure_domain: Option<String>,
    /// Byte quota, e.g. 10T (0 = unlimited)
    #[arg(long)]
    pub quota_bytes: Option<String>,
    #[arg(long)]
    pub description: Option<String>,
    #[arg(long)]
    pub tier: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum PoolCmd {
    /// GET /_admin/pools
    List,
    /// GET /_admin/pools/{name}
    Show { name: String },
    /// POST /_admin/pools
    Create {
        name: String,
        #[command(flatten)]
        fields: PoolFields,
        /// Placement groups (fixed at creation; 0 = per-object placement)
        #[arg(long)]
        pg_count: Option<u32>,
        #[arg(long)]
        disabled: bool,
    },
    /// PUT /_admin/pools/{name} — only the fields given change
    Update {
        name: String,
        #[command(flatten)]
        fields: PoolFields,
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// DELETE /_admin/pools/{name}
    Delete { name: String },
    /// GET /_admin/pools/{name}/placement-groups
    PlacementGroups {
        name: String,
        #[arg(long)]
        start_after: Option<u32>,
        #[arg(long)]
        max: Option<u32>,
    },
}

// ── kms / warehouse / config / metrics ──────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum KmsCmd {
    /// GET /_admin/kms/status
    Status,
    /// KMS keys (built-in KMS)
    Keys {
        #[command(subcommand)]
        action: KmsKeysCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum KmsKeysCmd {
    /// GET /_admin/kms/keys
    List,
    /// POST /_admin/kms/keys
    Create {
        /// Key ID (default: server-chosen)
        #[arg(long)]
        key_id: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    /// GET /_admin/kms/keys/{id}
    Show { key_id: String },
}

#[derive(Subcommand, Debug)]
pub enum WarehouseCmd {
    /// GET /_admin/warehouses (filtered to --tenant when given)
    List {
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// POST /_admin/warehouses — also creates bucket iceberg-<name>
    Create {
        name: String,
        /// Property key=value (repeatable)
        #[arg(long = "property")]
        properties: Vec<String>,
        #[command(flatten)]
        tenant: TenantOpt,
    },
    /// DELETE /_admin/warehouses/{name}
    Delete { name: String },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// GET /_admin/config[?prefix=]
    List {
        #[arg(long)]
        prefix: Option<String>,
    },
    /// GET /_admin/config/{key}
    Get { key: String },
    /// PUT /_admin/config/{key}
    Set {
        key: String,
        /// The JSON value inline
        #[arg(long, conflicts_with = "file", required_unless_present = "file")]
        value: Option<String>,
        /// A file holding the JSON value, or - for stdin
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// DELETE /_admin/config/{key}
    Delete { key: String },
}

#[derive(Subcommand, Debug)]
pub enum MetricsCmd {
    /// GET /_admin/metrics/query
    Query {
        promql: String,
        /// RFC 3339 or unix seconds (default: now)
        #[arg(long)]
        time: Option<String>,
    },
    /// GET /_admin/metrics/query_range
    QueryRange {
        promql: String,
        #[arg(long)]
        start: String,
        #[arg(long)]
        end: String,
        /// Seconds
        #[arg(long)]
        step: String,
    },
}

// ── block (gRPC) ────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
pub enum VolumeCmd {
    /// List volumes
    List {
        #[arg(short, long, default_value = "")]
        pool: String,
    },
    /// Create a volume
    Create {
        name: String,
        /// Size, e.g. 10G, 1T, 500M
        #[arg(short, long)]
        size: String,
        #[arg(short, long, default_value = "")]
        pool: String,
    },
    /// Show a volume
    Show { volume_id: String },
    /// Grow a volume
    Resize {
        volume_id: String,
        #[arg(short, long)]
        size: String,
    },
    /// Delete a volume
    Delete {
        volume_id: String,
        /// Even if attached
        #[arg(short, long)]
        force: bool,
    },
    /// Export a volume over NBD (the export name is the volume id)
    Attach {
        volume_id: String,
        /// Export it read-only
        #[arg(long)]
        read_only: bool,
    },
    /// Stop exporting a volume; its NBD clients are disconnected first
    Detach {
        volume_id: String,
        /// Even if the volume is busy
        #[arg(short, long)]
        force: bool,
    },
    /// List attachments (exports)
    Attachments {
        /// Only this volume's
        #[arg(long, default_value = "")]
        volume_id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum SnapshotCmd {
    /// List a volume's snapshots
    List { volume_id: String },
    /// Snapshot a volume
    Create {
        volume_id: String,
        #[arg(short, long)]
        name: String,
    },
    /// Show a snapshot
    Show { snapshot_id: String },
    /// Delete a snapshot
    Delete { snapshot_id: String },
    /// Clone a new volume from a snapshot
    Clone {
        snapshot_id: String,
        #[arg(short, long)]
        name: String,
    },
}
