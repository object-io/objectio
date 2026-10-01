//! Stored types for metadata persistence.
//!
//! These types are serialized to redb via bincode. Proto types embedded
//! in these structs use dedicated serde wrapper modules for encoding.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Serde wrapper for `Vec<StripeMeta>` (prost type in bincode)
mod stripe_meta_vec {
    use prost::Message;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(
        items: &[objectio_proto::metadata::StripeMeta],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<Vec<u8>> = items.iter().map(Message::encode_to_vec).collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Vec<objectio_proto::metadata::StripeMeta>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: Vec<Vec<u8>> = Vec::<Vec<u8>>::deserialize(deserializer)?;
        encoded
            .into_iter()
            .map(|bytes| {
                objectio_proto::metadata::StripeMeta::decode(bytes.as_slice())
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

/// Serde wrapper for `Option<VolumeQos>` (prost type in bincode)
mod volume_qos_option {
    use prost::Message;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(
        value: &Option<objectio_proto::block::VolumeQos>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Option<Vec<u8>> = value.as_ref().map(Message::encode_to_vec);
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<objectio_proto::block::VolumeQos>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: Option<Vec<u8>> = Option::<Vec<u8>>::deserialize(deserializer)?;
        encoded
            .map(|bytes| {
                objectio_proto::block::VolumeQos::decode(bytes.as_slice())
                    .map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

// ---- S3 / Cluster types ----

/// OSD node information for placement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OsdNode {
    pub node_id: [u8; 16],
    pub address: String,
    pub disk_ids: Vec<[u8; 16]>,
    /// Legacy 3-tuple `(region, datacenter, rack)`. Kept for on-disk
    /// back-compat; populated from `topology` below when present.
    pub failure_domain: Option<(String, String, String)>,
    /// Full 5-level topology `(region, zone, datacenter, rack, host)`.
    /// Populated by modern OSDs at registration; `None` on data serialized
    /// before this field existed — in that case the service falls back to
    /// `failure_domain` plus empty zone/host.
    #[serde(default)]
    pub topology: Option<(String, String, String, String, String)>,
    /// Raw capacity per disk in bytes, index-aligned with `disk_ids`. Empty
    /// when the registering OSD predates the field; license capacity checks
    /// treat missing entries as 0 bytes (conservative — under-reports).
    #[serde(default)]
    pub disk_capacity_bytes: Vec<u64>,
    /// Operator-set intent — `In` (default, participating), `Out`
    /// (forced out of placement), or `Draining`. Independent of
    /// heartbeat-derived `NodeStatus` used by the topology; the service
    /// merges the two when rebuilding CRUSH.
    ///
    /// `#[serde(default)]` so existing serialized OSDs load as `In`.
    #[serde(default)]
    pub admin_state: objectio_common::OsdAdminState,
    /// Transfer Engine segment (`ip:port`) the OSD accepts shard transfers
    /// on, from its registration. Empty when it has none — gateways then
    /// move its shards as gRPC bytes.
    #[serde(default)]
    pub te_segment: String,
}

impl OsdNode {
    /// Decode an `OsdNode` from the `OSD_NODES` table, whichever release
    /// wrote it.
    ///
    /// bincode records carry no field names or lengths, so
    /// `#[serde(default)]` does nothing for it: a record written before a
    /// field existed is just short, and decoding it as the current struct
    /// fails with "unexpected end of file". v0.3.0 met exactly that on
    /// records v0.2.2 wrote and started with no OSDs until each one
    /// registered again — forgetting any Draining or Out state. Each
    /// earlier layout is tried in turn, newest first; **adding a field to
    /// `OsdNode` means adding the old layout to [`legacy_osd_node`].**
    ///
    /// # Errors
    /// The current layout's error, when no layout decodes `bytes`.
    pub fn decode(bytes: &[u8]) -> bincode::Result<Self> {
        bincode::deserialize::<Self>(bytes).or_else(|current| {
            bincode::deserialize::<legacy_osd_node::V2>(bytes)
                .map(Self::from)
                .or_else(|_| bincode::deserialize::<legacy_osd_node::V1>(bytes).map(Self::from))
                .map_err(|_| current)
        })
    }
}

/// Earlier on-disk layouts of [`OsdNode`], for [`OsdNode::decode`].
pub mod legacy_osd_node {
    use serde::{Deserialize, Serialize};

    /// v0.2.x: before `te_segment`.
    #[derive(Serialize, Deserialize)]
    pub struct V2 {
        pub node_id: [u8; 16],
        pub address: String,
        pub disk_ids: Vec<[u8; 16]>,
        pub failure_domain: Option<(String, String, String)>,
        pub topology: Option<(String, String, String, String, String)>,
        pub disk_capacity_bytes: Vec<u64>,
        pub admin_state: objectio_common::OsdAdminState,
    }

    /// The first release: before `admin_state`.
    #[derive(Serialize, Deserialize)]
    pub struct V1 {
        pub node_id: [u8; 16],
        pub address: String,
        pub disk_ids: Vec<[u8; 16]>,
        pub failure_domain: Option<(String, String, String)>,
        pub topology: Option<(String, String, String, String, String)>,
        pub disk_capacity_bytes: Vec<u64>,
    }
}

impl From<legacy_osd_node::V2> for OsdNode {
    fn from(v: legacy_osd_node::V2) -> Self {
        Self {
            node_id: v.node_id,
            address: v.address,
            disk_ids: v.disk_ids,
            failure_domain: v.failure_domain,
            topology: v.topology,
            disk_capacity_bytes: v.disk_capacity_bytes,
            admin_state: v.admin_state,
            te_segment: String::new(),
        }
    }
}

impl From<legacy_osd_node::V1> for OsdNode {
    fn from(v: legacy_osd_node::V1) -> Self {
        Self::from(legacy_osd_node::V2 {
            node_id: v.node_id,
            address: v.address,
            disk_ids: v.disk_ids,
            failure_domain: v.failure_domain,
            topology: v.topology,
            disk_capacity_bytes: v.disk_capacity_bytes,
            admin_state: objectio_common::OsdAdminState::default(),
        })
    }
}

/// EC configuration for a storage class
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EcConfig {
    Mds { k: u8, m: u8 },
    Lrc { k: u8, l: u8, g: u8 },
    Replication { count: u8 },
}

impl Default for EcConfig {
    fn default() -> Self {
        Self::Mds { k: 4, m: 2 }
    }
}

/// State for an in-progress multipart upload
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MultipartUploadState {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub content_type: String,
    pub user_metadata: HashMap<String, String>,
    pub initiated: u64,
    pub parts: HashMap<u32, PartState>,
    /// Server-side encryption for this upload. Fixed at CreateMultipartUpload
    /// time; per-UploadPart SSE headers are ignored (AWS semantics). Values
    /// map to `SseAlgorithm` in the proto (0 = none, 1 = AES256, 2 = aws:kms,
    /// 3 = sse-c).
    #[serde(default)]
    pub encryption_algorithm: i32,
    #[serde(default)]
    pub kms_key_id: String,
    #[serde(default)]
    pub encrypted_dek: Vec<u8>,
    /// SSE-C only: base64-encoded MD5 of the customer key provided at
    /// CreateMultipartUpload. Every UploadPart must resupply a matching key;
    /// we never store the raw key bytes.
    #[serde(default)]
    pub customer_key_md5: String,
    /// SSE-KMS only: encryption context supplied at CreateMultipartUpload.
    /// Round-tripped to UploadPart's KmsProvider::decrypt call so the AEAD
    /// binding on the wrapped DEK still validates.
    #[serde(default)]
    pub encryption_context: HashMap<String, String>,
}

/// State for a completed part within a multipart upload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartState {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
    pub last_modified: u64,
    #[serde(with = "stripe_meta_vec")]
    pub stripes: Vec<objectio_proto::metadata::StripeMeta>,
}

// ---- IAM types ----

/// Internal user storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredUser {
    pub user_id: String,
    pub display_name: String,
    pub arn: String,
    pub status: i32,
    pub created_at: u64,
    pub email: String,
    #[serde(default)]
    pub tenant: String,
}

/// Internal access key storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredAccessKey {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub user_id: String,
    pub status: i32,
    pub created_at: u64,
    #[serde(default)]
    pub tenant: String,
    /// `s3://bucket/prefix/` restriction. Empty = unscoped.
    #[serde(default)]
    pub scope: String,
    /// `KeyOperation` proto value: 0 = READ_WRITE, 1 = READ. Zero is the
    /// permissive default so an unset value imposes no restriction.
    #[serde(default)]
    pub operation: i32,
}

/// Layout of [`StoredAccessKey`] before scoping existed.
///
/// bincode is not self-describing, so `#[serde(default)]` cannot rescue a
/// record that simply ends early — the decoder runs off the end and errors.
/// Keeping the old shape lets [`decode_access_key`] fall back and upgrade in
/// place, so adding scope fields does not invalidate keys already issued.
#[derive(Deserialize)]
struct StoredAccessKeyV1 {
    access_key_id: String,
    secret_access_key: String,
    user_id: String,
    status: i32,
    created_at: u64,
    #[serde(default)]
    tenant: String,
}

impl From<StoredAccessKeyV1> for StoredAccessKey {
    fn from(v1: StoredAccessKeyV1) -> Self {
        Self {
            access_key_id: v1.access_key_id,
            secret_access_key: v1.secret_access_key,
            user_id: v1.user_id,
            status: v1.status,
            created_at: v1.created_at,
            tenant: v1.tenant,
            scope: String::new(),
            operation: 0,
        }
    }
}

/// Decode a stored access key, accepting records written before the `scope`
/// and `operation` fields existed.
///
/// # Errors
/// Returns the current-layout error when the bytes match neither layout.
pub fn decode_access_key(bytes: &[u8]) -> Result<StoredAccessKey, bincode::Error> {
    match bincode::deserialize::<StoredAccessKey>(bytes) {
        Ok(k) => Ok(k),
        Err(current) => bincode::deserialize::<StoredAccessKeyV1>(bytes)
            .map(Into::into)
            .map_err(|_| current),
    }
}

/// Internal group storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredGroup {
    pub group_id: String,
    pub group_name: String,
    pub arn: String,
    pub member_user_ids: Vec<String>,
    pub created_at: u64,
}

// ---- Iceberg data filter types ----

/// Stored data filter for column/row-level security
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredDataFilter {
    pub filter_id: String,
    pub filter_name: String,
    pub namespace_levels: Vec<String>,
    pub table_name: String,
    pub principal_arns: Vec<String>,
    pub allowed_columns: Vec<String>,
    pub excluded_columns: Vec<String>,
    pub row_filter_expression: String,
    pub created_at: u64,
    pub updated_at: u64,
}

// ---- Block storage types ----

/// Stored volume metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredVolume {
    pub volume_id: String,
    pub name: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub pool: String,
    pub state: i32,
    pub created_at: u64,
    pub updated_at: u64,
    pub parent_snapshot_id: String,
    pub chunk_size_bytes: u32,
    pub metadata: HashMap<String, String>,
    #[serde(with = "volume_qos_option")]
    pub qos: Option<objectio_proto::block::VolumeQos>,
}

/// Stored snapshot metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSnapshot {
    pub snapshot_id: String,
    pub volume_id: String,
    pub name: String,
    pub size_bytes: u64,
    pub unique_bytes: u64,
    pub state: i32,
    pub created_at: u64,
    pub metadata: HashMap<String, String>,
    pub chunk_refs: HashMap<u64, StoredChunkRef>,
}

/// Stored chunk reference
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredChunkRef {
    pub chunk_id: u64,
    pub object_key: String,
    pub etag: String,
    pub size_bytes: u64,
}

/// Stored attachment information (ephemeral, not persisted)
#[derive(Clone, Debug)]
pub struct StoredAttachment {
    pub volume_id: String,
    pub target_type: i32,
    pub target_address: String,
    pub initiator: String,
    pub attached_at: u64,
    pub read_only: bool,
}

#[cfg(test)]
mod access_key_compat_tests {
    use super::*;

    #[test]
    fn current_layout_round_trips() {
        let key = StoredAccessKey {
            access_key_id: "AKIA1".into(),
            secret_access_key: "s".into(),
            user_id: "u".into(),
            status: 0,
            created_at: 1,
            tenant: "t".into(),
            scope: "s3://data/logs/".into(),
            operation: 1,
        };
        let bytes = bincode::serialize(&key).unwrap();
        let back = decode_access_key(&bytes).unwrap();
        assert_eq!(back.scope, "s3://data/logs/");
        assert_eq!(back.operation, 1);
    }

    /// A key issued before scoping existed must still authenticate, not vanish
    /// from the store with a decode warning.
    #[test]
    fn pre_scope_records_still_decode() {
        #[derive(Serialize)]
        struct V1 {
            access_key_id: String,
            secret_access_key: String,
            user_id: String,
            status: i32,
            created_at: u64,
            tenant: String,
        }
        let bytes = bincode::serialize(&V1 {
            access_key_id: "AKIAOLD".into(),
            secret_access_key: "old-secret".into(),
            user_id: "u1".into(),
            status: 0,
            created_at: 42,
            tenant: "acme".into(),
        })
        .unwrap();

        // Proves the fallback is load-bearing: the current layout cannot read it.
        assert!(bincode::deserialize::<StoredAccessKey>(&bytes).is_err());

        let upgraded = decode_access_key(&bytes).unwrap();
        assert_eq!(upgraded.access_key_id, "AKIAOLD");
        assert_eq!(upgraded.secret_access_key, "old-secret");
        assert_eq!(upgraded.tenant, "acme");
        // Upgraded records are unscoped, so existing keys keep working as-is.
        assert!(upgraded.scope.is_empty());
        assert_eq!(upgraded.operation, 0);
    }

    #[test]
    fn garbage_is_still_an_error() {
        assert!(decode_access_key(&[0xff, 0x00, 0x01]).is_err());
    }
}

#[cfg(test)]
mod osd_node_compat_tests {
    use super::*;
    use objectio_common::OsdAdminState;

    fn v2() -> legacy_osd_node::V2 {
        legacy_osd_node::V2 {
            node_id: [7; 16],
            address: "http://10.0.0.7:9200".into(),
            disk_ids: vec![[1; 16], [2; 16]],
            failure_domain: Some(("r".into(), "dc".into(), "rack".into())),
            topology: Some((
                "r".into(),
                "z".into(),
                "dc".into(),
                "rack".into(),
                "h".into(),
            )),
            disk_capacity_bytes: vec![10, 20],
            admin_state: OsdAdminState::Draining,
        }
    }

    #[test]
    fn the_current_layout_round_trips() {
        let mut node = OsdNode::from(v2());
        node.te_segment = "10.0.0.7:15000".into();
        let back = OsdNode::decode(&bincode::serialize(&node).unwrap()).unwrap();
        assert_eq!(back.te_segment, "10.0.0.7:15000");
        assert_eq!(back.admin_state, OsdAdminState::Draining);
    }

    /// What v0.3.0 could not read: a record v0.2.x wrote, without
    /// `te_segment`. Its Draining state must survive the upgrade.
    #[test]
    fn a_v0_2_record_decodes_with_its_admin_state() {
        let bytes = bincode::serialize(&v2()).unwrap();
        assert!(
            bincode::deserialize::<OsdNode>(&bytes).is_err(),
            "the current layout reads this by itself now; is the legacy path still needed?"
        );
        let node = OsdNode::decode(&bytes).unwrap();
        assert_eq!(node.node_id, [7; 16]);
        assert_eq!(node.address, "http://10.0.0.7:9200");
        assert_eq!(node.disk_ids, vec![[1; 16], [2; 16]]);
        assert_eq!(node.disk_capacity_bytes, vec![10, 20]);
        assert_eq!(node.admin_state, OsdAdminState::Draining);
        assert!(node.te_segment.is_empty());
    }

    #[test]
    fn a_first_release_record_decodes_as_in() {
        let v = v2();
        let v1 = legacy_osd_node::V1 {
            node_id: v.node_id,
            address: v.address,
            disk_ids: v.disk_ids,
            failure_domain: v.failure_domain,
            topology: v.topology,
            disk_capacity_bytes: v.disk_capacity_bytes,
        };
        let node = OsdNode::decode(&bincode::serialize(&v1).unwrap()).unwrap();
        assert_eq!(node.address, "http://10.0.0.7:9200");
        assert_eq!(node.admin_state, OsdAdminState::In);
    }

    #[test]
    fn garbage_is_still_an_error() {
        assert!(OsdNode::decode(&[1, 2, 3]).is_err());
    }
}
