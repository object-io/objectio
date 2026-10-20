//! Who may call what between the services, under mTLS.
//!
//! mTLS proves a peer holds a certificate the cluster's CA signed; this
//! says which calls each kind of peer may make. Every service certificate
//! names its role in a SAN URI, `spiffe://objectio/<role>` (several URIs
//! for a process that is several components, the all-in-one). Each gRPC
//! call on meta, an OSD or a block gateway is checked against [`RULES`],
//! the one table of which roles may call each method: an OSD can't read a
//! user's secret key from meta, a gateway can't purge an OSD, and nothing
//! that is not in the table is served.
//!
//! Without mTLS there is nothing to check: the internal network is then
//! trusted, and the servers say so when they start.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{Context, Poll};

use tonic::body::BoxBody;
use tonic::codegen::http;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};

/// The SAN URI prefix a role is named under.
pub const ROLE_URI_PREFIX: &str = "spiffe://objectio/";

/// A set of roles.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Roles(u8);

impl Roles {
    pub const NONE: Self = Self(0);
    /// A meta node.
    pub const META: Self = Self(1);
    /// An OSD.
    pub const OSD: Self = Self(1 << 1);
    /// An S3 gateway.
    pub const GATEWAY: Self = Self(1 << 2);
    /// A block gateway.
    pub const BLOCK_GATEWAY: Self = Self(1 << 3);
    /// An operator's tool: `obioctl`'s block commands, the Raft bootstrap.
    pub const ADMIN: Self = Self(1 << 4);
    /// Every role.
    pub const ALL: Self = Self(0b1_1111);

    const NAMES: [(Self, &'static str); 5] = [
        (Self::META, "meta"),
        (Self::OSD, "osd"),
        (Self::GATEWAY, "gateway"),
        (Self::BLOCK_GATEWAY, "block-gateway"),
        (Self::ADMIN, "admin"),
    ];

    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether the two sets share a role.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The role a name (`meta`, `osd`, …) stands for.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::NAMES
            .iter()
            .find(|(_, n)| *n == name)
            .map(|(r, _)| *r)
    }

    /// The role a SAN URI names, if it names one.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        uri.strip_prefix(ROLE_URI_PREFIX).and_then(Self::from_name)
    }
}

impl fmt::Debug for Roles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Roles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = Self::NAMES
            .iter()
            .filter(|(r, _)| self.intersects(*r))
            .map(|(_, n)| *n)
            .collect();
        if names.is_empty() {
            f.write_str("no role")
        } else {
            f.write_str(&names.join(","))
        }
    }
}

const META: Roles = Roles::META;
const OSD: Roles = Roles::OSD;
const GATEWAY: Roles = Roles::GATEWAY;
const BLOCK: Roles = Roles::BLOCK_GATEWAY;
const ADMIN: Roles = Roles::ADMIN;
/// Meta and the gateways. Meta is allowed every meta call: a follower
/// forwards each call it gets to the leader under its own certificate
/// (`objectio-meta`'s `forward`), after checking the caller's here.
const GW: Roles = GATEWAY.or(META);
/// Every service.
const NODES: Roles = META.or(OSD).or(GATEWAY).or(BLOCK);

/// The gRPC services the cluster serves.
pub const METADATA_SERVICE: &str = "objectio.metadata.MetadataService";
pub const RAFT_SERVICE: &str = "objectio.raft.RaftRpc";
pub const STORAGE_SERVICE: &str = "objectio.storage.StorageService";
pub const BLOCK_SERVICE: &str = "objectio.block.BlockService";

/// Which roles may call each method, by service.
///
/// The callers are the code's: a method no component calls is given to
/// the one that owns the data. A method missing here is refused (a unit
/// test checks every method of every served service has an entry).
pub const RULES: &[(&str, &[(&str, Roles)])] = &[
    (
        METADATA_SERVICE,
        &[
            ("CreateBucket", GW),
            ("SetBucketOwner", GW),
            ("SetBucketQuota", GW),
            ("DeleteBucket", GW),
            ("GetBucket", GW),
            ("ListBuckets", GW),
            ("CreateObject", GW),
            ("ReportDegraded", GW),
            ("DeleteObject", GW),
            ("GetObject", GW),
            ("ListObjects", GW),
            // Where a block gateway's chunks go, too.
            ("GetPlacement", GW.or(BLOCK)),
            ("GetWriteContext", GW),
            ("CreateMultipartUpload", GW),
            ("GetMultipartUpload", GW),
            ("RegisterPart", GW),
            ("ListParts", GW),
            ("CompleteMultipartUpload", GW),
            ("AbortMultipartUpload", GW),
            ("SettleMultipartUpload", GW),
            ("ListMultipartUploads", GW),
            ("SetBucketPolicy", GW),
            ("GetBucketPolicy", GW),
            ("DeleteBucketPolicy", GW),
            ("RegisterOsd", OSD.or(META)),
            ("GetListingNodes", GW.or(BLOCK)),
            ("SetOsdAdminState", GW),
            ("GetDrainStatus", GW),
            ("GetRebalanceStatus", GW),
            ("CreateUser", GW),
            ("GetUser", GW),
            ("ListUsers", GW),
            ("DeleteUser", GW),
            ("CreateAccessKey", GW),
            ("ListAccessKeys", GW),
            ("DeleteAccessKey", GW),
            // A user's secret key: what the gateway checks signatures with.
            ("GetAccessKeyForAuth", GW),
            ("GetAccessKey", GW),
            ("IcebergCreateNamespace", GW),
            ("IcebergLoadNamespace", GW),
            ("IcebergDropNamespace", GW),
            ("IcebergListNamespaces", GW),
            ("IcebergUpdateNamespaceProperties", GW),
            ("IcebergNamespaceExists", GW),
            ("IcebergCreateTable", GW),
            ("IcebergLoadTable", GW),
            ("IcebergCommitTable", GW),
            ("IcebergCommitTransaction", GW),
            ("IcebergDropTable", GW),
            ("IcebergRenameTable", GW),
            ("IcebergListTables", GW),
            ("IcebergTableExists", GW),
            ("IcebergCreateWarehouse", GW),
            ("IcebergListWarehouses", GW),
            ("IcebergDeleteWarehouse", GW),
            ("IcebergSetTablePolicy", GW),
            ("IcebergGetTablePolicy", GW),
            ("CreateGroup", GW),
            ("DeleteGroup", GW),
            ("ListGroups", GW),
            ("AddUserToGroup", GW),
            ("RemoveUserFromGroup", GW),
            ("GetUserGroups", GW),
            ("CreateDataFilter", GW),
            ("ListDataFilters", GW),
            ("DeleteDataFilter", GW),
            ("GetDataFiltersForPrincipal", GW),
            ("UnityCreateCatalog", GW),
            ("UnityListCatalogs", GW),
            ("UnityGetCatalog", GW),
            ("UnityUpdateCatalog", GW),
            ("UnityDeleteCatalog", GW),
            ("UnityCreateSchema", GW),
            ("UnityListSchemas", GW),
            ("UnityGetSchema", GW),
            ("UnityUpdateSchema", GW),
            ("UnityDeleteSchema", GW),
            ("UnityCreateTable", GW),
            ("UnityListTables", GW),
            ("UnityGetTable", GW),
            ("UnityDeleteTable", GW),
            ("UnitySetTableSecurity", GW),
            ("UnitySetCatalogPolicy", GW),
            ("UnityGetCatalogPolicy", GW),
            ("UnitySetSchemaPolicy", GW),
            ("UnityGetSchemaPolicy", GW),
            ("UnitySetTablePolicy", GW),
            ("UnityGetTablePolicy", GW),
            ("UnityCreateFunction", GW),
            ("UnityListFunctions", GW),
            ("UnityGetFunction", GW),
            ("UnityDeleteFunction", GW),
            ("UnityCreateVolume", GW),
            ("UnityListVolumes", GW),
            ("UnityGetVolume", GW),
            ("UnityDeleteVolume", GW),
            ("UnityCreateModel", GW),
            ("UnityListModels", GW),
            ("UnityGetModel", GW),
            ("UnityDeleteModel", GW),
            ("UnityCreateModelVersion", GW),
            ("UnityListModelVersions", GW),
            ("UnityGetModelVersion", GW),
            ("UnityUpdateModelVersionStatus", GW),
            ("UnityDeleteModelVersion", GW),
            ("DeltaCreateShare", GW),
            ("DeltaGetShare", GW),
            ("DeltaListShares", GW),
            ("DeltaDropShare", GW),
            ("DeltaAddTable", GW),
            ("DeltaRemoveTable", GW),
            ("DeltaListTables", GW),
            ("DeltaCreateRecipient", GW),
            ("DeltaGetRecipientByToken", GW),
            ("DeltaListRecipients", GW),
            ("DeltaDropRecipient", GW),
            ("GetConfig", GW),
            ("SetConfig", GW),
            ("DeleteConfig", GW),
            ("ListConfig", GW),
            ("CreatePool", GW),
            ("GetPool", GW),
            ("ListPools", GW),
            ("UpdatePool", GW),
            ("DeletePool", GW),
            // An OSD learns its placement groups' epochs.
            ("GetPlacementGroup", GW.or(OSD)),
            ("ListPlacementGroups", GW),
            ("RequestPgScrub", GW),
            ("CreateTenant", GW),
            ("GetTenant", GW),
            ("ListTenants", GW),
            ("UpdateTenant", GW),
            ("DeleteTenant", GW),
            ("PutBucketVersioning", GW),
            ("GetBucketVersioning", GW),
            ("SetBucketDedup", GW),
            ("GetDedupPolicy", GW),
            ("LocateChunks", GW),
            ("ShareStripes", GW),
            ("ReleaseStripes", GW),
            ("IntendPack", GW),
            ("SealPack", GW),
            ("AbortPack", GW),
            ("GetPack", GW),
            ("ListPacks", GW),
            ("PackMoveShard", GW),
            ("PackSettle", GW),
            // Volumes, snapshots and chunk maps: the block gateway's.
            ("BlockCreateVolume", BLOCK.or(META)),
            ("BlockGetVolume", BLOCK.or(META)),
            ("BlockListVolumes", BLOCK.or(META)),
            ("BlockUpdateVolume", BLOCK.or(META)),
            ("BlockDeleteVolume", BLOCK.or(META)),
            ("BlockGetChunks", BLOCK.or(META)),
            ("BlockCommitChunks", BLOCK.or(META)),
            ("BlockCreateSnapshot", BLOCK.or(META)),
            ("BlockGetSnapshot", BLOCK.or(META)),
            ("BlockListSnapshots", BLOCK.or(META)),
            ("BlockDeleteSnapshot", BLOCK.or(META)),
            ("BlockCloneVolume", BLOCK.or(META)),
            ("PutObjectLockConfiguration", GW),
            ("GetObjectLockConfiguration", GW),
            ("PutBucketLifecycle", GW),
            ("GetBucketLifecycle", GW),
            ("DeleteBucketLifecycle", GW),
            ("PutBucketEncryption", GW),
            ("GetBucketEncryption", GW),
            ("DeleteBucketEncryption", GW),
            ("GetBucketSetting", GW),
            ("AcquireLease", GW),
            // Every process reports its release and format level.
            ("ReportVersion", NODES),
            ("GetUpgradeStatus", GW),
            ("FinalizeUpgrade", GW),
            ("PutBucketSetting", GW),
            ("CreateKmsKey", GW),
            ("GetKmsKey", GW),
            ("ListKmsKeys", GW),
            ("DeleteKmsKey", GW),
            ("CreatePolicy", GW),
            ("GetPolicy", GW),
            ("ListPolicies", GW),
            ("DeletePolicy", GW),
            ("AttachPolicy", GW),
            ("DetachPolicy", GW),
            ("ListAttachedPolicies", GW),
            ("UpdatePolicy", GW),
            ("UpdateUser", GW),
            ("UpdateAccessKey", GW),
            // The cluster's secret, that STS and console sessions are
            // signed with.
            ("GetStsSigningKey", GW),
            ("CreateRole", GW),
            ("GetRole", GW),
            ("ListRoles", GW),
            ("UpdateRole", GW),
            ("DeleteRole", GW),
            ("UpdateGroup", GW),
            ("PutInlinePolicy", GW),
            ("GetInlinePolicy", GW),
            ("ListInlinePolicies", GW),
            ("DeleteInlinePolicy", GW),
            ("HealEnqueue", GW),
            ("HealList", GW),
            ("HealClaim", GW),
            ("HealDone", GW),
            // Also every meta client's liveness probe.
            ("GetMetrics", NODES),
            ("GetTime", GW),
        ],
    ),
    (
        RAFT_SERVICE,
        &[
            ("AppendEntries", META),
            ("Vote", META),
            ("InstallSnapshot", META),
        ],
    ),
    (
        STORAGE_SERVICE,
        &[
            // Gateways write and read objects' shards and delete them on
            // overwrite and delete; meta repairs, recovers and drains;
            // block gateways write their chunks.
            ("WriteShard", GW.or(BLOCK)),
            ("ReadShard", GW.or(BLOCK)),
            ("DeleteShard", GW.or(BLOCK)),
            ("GetShardMeta", GW),
            ("ListShards", META),
            ("HealthCheck", NODES),
            ("GetStatus", GW),
            ("FindObjectsReferencingNode", META),
            ("PutObjectMeta", GW),
            ("GetObjectMeta", GW),
            ("GetObjectMetas", GW),
            ("DeleteObjectMeta", GW),
            ("ListObjectsMeta", GW),
            ("StreamListObjectsMeta", GW),
            ("ListObjectVersionsMeta", GW),
            ("GetMetrics", GW),
            // Placement groups, repair and drain: meta's alone.
            ("CheckShards", META),
            ("SetPgEpochs", META),
            ("GetPgInfo", META),
            ("ListPg", META),
            ("ScrubPg", META),
            ("NoteChunks", GW),
            ("ResetChunkNotes", GW),
            ("Purge", META),
        ],
    ),
    (
        BLOCK_SERVICE,
        &[
            // An operator's: `obioctl volume|snapshot`.
            ("CreateVolume", ADMIN),
            ("DeleteVolume", ADMIN),
            ("GetVolume", ADMIN),
            ("ListVolumes", ADMIN),
            ("ResizeVolume", ADMIN),
            ("UpdateVolumeQos", ADMIN),
            ("GetVolumeStats", ADMIN),
            ("CreateSnapshot", ADMIN),
            ("DeleteSnapshot", ADMIN),
            ("GetSnapshot", ADMIN),
            ("ListSnapshots", ADMIN),
            ("CloneVolume", ADMIN),
            ("AttachVolume", ADMIN),
            ("DetachVolume", ADMIN),
            ("ListAttachments", ADMIN),
            ("Read", ADMIN),
            ("Write", ADMIN),
            ("Flush", ADMIN),
            ("Trim", ADMIN),
            ("GetOsdMetrics", ADMIN),
            ("ListOsdMetrics", ADMIN),
            ("GetClusterMetrics", ADMIN),
            ("GetIoTrace", ADMIN),
        ],
    ),
];

/// [`RULES`] by gRPC path (`/package.Service/Method`).
static BY_PATH: LazyLock<HashMap<String, (&'static str, Roles)>> = LazyLock::new(|| {
    RULES
        .iter()
        .flat_map(|(service, methods)| {
            methods
                .iter()
                .map(move |(m, roles)| (format!("/{service}/{m}"), (*service, *roles)))
        })
        .collect()
});

/// The roles that may make the call at gRPC `path`, on a server serving
/// `services`; none for a path not in [`RULES`] or not served there.
#[must_use]
pub fn allowed(path: &str, services: &[&str]) -> Roles {
    match BY_PATH.get(path) {
        Some((service, roles)) if services.contains(service) => *roles,
        _ => Roles::NONE,
    }
}

/// The roles a certificate (DER) names in its SAN URIs.
#[must_use]
pub fn roles_of_cert(der: &[u8]) -> Roles {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return Roles::NONE;
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Roles::NONE;
    };
    san.value
        .general_names
        .iter()
        .filter_map(|n| match n {
            x509_parser::extensions::GeneralName::URI(uri) => Roles::from_uri(uri),
            _ => None,
        })
        .fold(Roles::NONE, Roles::or)
}

/// Peers' certificates seen, and their roles: a connection's certificate
/// comes with each of its calls, and an OSD takes thousands a second.
static SEEN: LazyLock<parking_lot::RwLock<HashMap<Vec<u8>, Roles>>> =
    LazyLock::new(Default::default);

fn cached_roles(der: &[u8]) -> Roles {
    if let Some(r) = SEEN.read().get(der) {
        return *r;
    }
    let roles = roles_of_cert(der);
    let mut seen = SEEN.write();
    // Certificates are few (one per node and role); a bound in case of
    // churn.
    if seen.len() >= 4096 {
        seen.clear();
    }
    seen.insert(der.to_vec(), roles);
    roles
}

/// The roles of the peer of a call that arrived over mTLS.
///
/// Those its certificate names. A certificate naming none comes from a
/// release before roles: in a cluster still running one (its active level
/// below [`objectio_common::version::PEER_ROLES_LEVEL`]) it is taken for
/// any role, so the upgrade can roll; once the upgrade is finalized, it
/// has none.
#[must_use]
pub fn peer_roles(certs: Option<&[impl AsRef<[u8]>]>) -> Roles {
    let Some(leaf) = certs.and_then(<[_]>::first) else {
        return Roles::NONE;
    };
    let roles = cached_roles(leaf.as_ref());
    if roles.is_empty() && before_roles() {
        Roles::ALL
    } else {
        roles
    }
}

/// Whether the cluster still runs a release from before roles.
fn before_roles() -> bool {
    let active = objectio_common::version::active_level();
    active != 0 && active < objectio_common::version::PEER_ROLES_LEVEL
}

/// Refuses each gRPC call its peer's roles don't allow, when mTLS is on
/// (see the module's documentation). `services` are the services the
/// server serves: a call to any other is refused too.
#[derive(Clone, Copy)]
pub struct PeerAuthLayer {
    services: &'static [&'static str],
}

impl PeerAuthLayer {
    #[must_use]
    pub const fn new(services: &'static [&'static str]) -> Self {
        Self { services }
    }
}

impl<S> tower::Layer<S> for PeerAuthLayer {
    type Service = PeerAuth<S>;
    fn layer(&self, inner: S) -> Self::Service {
        PeerAuth {
            inner,
            services: self.services,
        }
    }
}

#[derive(Clone)]
pub struct PeerAuth<S> {
    inner: S,
    services: &'static [&'static str],
}

/// Why a call is refused, if it is.
fn refusal<B>(req: &http::Request<B>, services: &[&str]) -> Option<tonic::Status> {
    if !crate::transport::tls_enabled() {
        return None;
    }
    let path = req.uri().path();
    let allowed = allowed(path, services);
    if allowed.is_empty() {
        return Some(tonic::Status::permission_denied(format!(
            "{path}: not a call this server takes"
        )));
    }
    let certs = req
        .extensions()
        .get::<TlsConnectInfo<TcpConnectInfo>>()
        .and_then(TlsConnectInfo::peer_certs);
    let roles = peer_roles(certs.as_deref().map(Vec::as_slice));
    if roles.intersects(allowed) {
        return None;
    }
    tracing::warn!("refused {path} from a peer with role {roles} (allowed: {allowed})");
    Some(tonic::Status::permission_denied(format!(
        "{path}: a peer with role {roles} may not make this call"
    )))
}

impl<S> tower::Service<http::Request<BoxBody>> for PeerAuth<S>
where
    S: tower::Service<http::Request<BoxBody>, Response = http::Response<BoxBody>>,
    S::Future: Send + 'static,
{
    type Response = http::Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<BoxBody>) -> Self::Future {
        if let Some(status) = refusal(&req, self.services) {
            return Box::pin(async move { Ok(status.into_http()) });
        }
        Box::pin(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The methods a `.proto` file declares for `service`.
    fn declared(proto: &str, service: &str) -> Vec<String> {
        let start = proto
            .find(&format!("service {service} {{"))
            .unwrap_or_else(|| panic!("service {service}"));
        let body = &proto[start..];
        let body = &body[..body.find("\n}").expect("end of service")];
        body.lines()
            .filter_map(|l| l.trim().strip_prefix("rpc "))
            .map(|l| l.split(['(', ' ']).next().unwrap().to_string())
            .collect()
    }

    const SERVED: [(&str, &str, &str); 4] = [
        (
            include_str!("../proto/metadata.proto"),
            METADATA_SERVICE,
            "MetadataService",
        ),
        (include_str!("../proto/raft.proto"), RAFT_SERVICE, "RaftRpc"),
        (
            include_str!("../proto/storage.proto"),
            STORAGE_SERVICE,
            "StorageService",
        ),
        (
            include_str!("../proto/block.proto"),
            BLOCK_SERVICE,
            "BlockService",
        ),
    ];

    #[test]
    fn every_method_of_every_served_service_has_a_rule_and_no_rule_is_stale() {
        for (proto, full, short) in SERVED {
            let methods = declared(proto, short);
            assert!(methods.len() > 2, "{short}: {methods:?}");
            let rules = RULES
                .iter()
                .find(|(s, _)| *s == full)
                .unwrap_or_else(|| panic!("no rules for {full}"))
                .1;
            for m in &methods {
                let who = allowed(&format!("/{full}/{m}"), &[full]);
                assert!(!who.is_empty(), "{full}/{m} has no rule");
            }
            for (m, _) in rules {
                assert!(
                    methods.iter().any(|d| d == m),
                    "{full}/{m} is in the rules but not the service"
                );
            }
            assert_eq!(rules.len(), methods.len(), "{full}: a method twice");
        }
    }

    #[test]
    fn an_unknown_or_unserved_call_is_allowed_to_no_one() {
        let meta = [METADATA_SERVICE, RAFT_SERVICE];
        assert!(allowed("/objectio.metadata.MetadataService/Nope", &meta).is_empty());
        assert!(allowed("/grpc.health.v1.Health/Check", &meta).is_empty());
        assert!(allowed("", &meta).is_empty());
        // A real method, but of a service this server doesn't serve.
        assert!(allowed("/objectio.storage.StorageService/Purge", &meta).is_empty());
        assert!(!allowed("/objectio.storage.StorageService/Purge", &[STORAGE_SERVICE]).is_empty());
    }

    #[test]
    fn secrets_go_to_gateways_and_purges_come_from_meta() {
        let meta = [METADATA_SERVICE];
        for m in ["GetAccessKeyForAuth", "GetStsSigningKey"] {
            let r = allowed(&format!("/{METADATA_SERVICE}/{m}"), &meta);
            assert!(r.intersects(Roles::GATEWAY), "{m}");
            for no in [Roles::OSD, Roles::BLOCK_GATEWAY, Roles::ADMIN] {
                assert!(!r.intersects(no), "{m} allowed to {no}");
            }
        }
        let osd = [STORAGE_SERVICE];
        for m in ["Purge", "SetPgEpochs", "ScrubPg", "CheckShards"] {
            assert_eq!(
                allowed(&format!("/{STORAGE_SERVICE}/{m}"), &osd),
                Roles::META
            );
        }
        // Gateways delete shards on overwrite and delete.
        assert!(
            allowed(&format!("/{STORAGE_SERVICE}/DeleteShard"), &osd).intersects(Roles::GATEWAY)
        );
        assert_eq!(
            allowed(&format!("/{RAFT_SERVICE}/AppendEntries"), &[RAFT_SERVICE]),
            Roles::META
        );
    }

    fn cert_with_uris(uris: &[&str]) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        for u in uris {
            params
                .subject_alt_names
                .push(rcgen::SanType::URI((*u).try_into().unwrap()));
        }
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn a_certificate_names_its_roles_in_san_uris() {
        assert_eq!(
            roles_of_cert(&cert_with_uris(&["spiffe://objectio/osd"])),
            Roles::OSD
        );
        assert_eq!(
            roles_of_cert(&cert_with_uris(&[
                "spiffe://objectio/meta",
                "spiffe://objectio/gateway",
                "https://example.com/x",
            ])),
            Roles::META.or(Roles::GATEWAY)
        );
        assert!(roles_of_cert(&cert_with_uris(&[])).is_empty());
        assert!(roles_of_cert(&cert_with_uris(&["spiffe://other/meta"])).is_empty());
        assert!(roles_of_cert(&cert_with_uris(&["spiffe://objectio/root"])).is_empty());
        assert!(roles_of_cert(b"not a certificate").is_empty());
    }

    #[test]
    fn a_certificate_without_roles_is_any_role_only_before_the_upgrade_is_finalized() {
        let certs = [cert_with_uris(&[])];
        // A process that hasn't heard the cluster's level yet: none.
        assert_eq!(objectio_common::version::active_level(), 0);
        assert!(peer_roles(Some(&certs[..])).is_empty());
        objectio_common::version::set_active_level(objectio_common::version::PEER_ROLES_LEVEL - 1);
        assert_eq!(peer_roles(Some(&certs[..])), Roles::ALL);
        let osd = [cert_with_uris(&["spiffe://objectio/osd"])];
        assert_eq!(peer_roles(Some(&osd[..])), Roles::OSD, "roles are roles");
        objectio_common::version::set_active_level(objectio_common::version::PEER_ROLES_LEVEL);
        assert!(peer_roles(Some(&certs[..])).is_empty());
        assert!(peer_roles(None::<&[Vec<u8>]>).is_empty());
    }
}
