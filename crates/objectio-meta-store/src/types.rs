//! Stored types for metadata persistence.
//!
//! Every record is protobuf (field-tagged, so a field can be added without
//! breaking what is stored): the structs derive `prost::Message`, except
//! [`OsdNode`], which keeps its Rust types and is stored as
//! [`OsdNodeRecord`]. [`record::serialize`] and [`record::deserialize`]
//! read and write them all.

use std::collections::HashMap;

/// Reading and writing stored records.
pub mod record {
    /// A record that can be stored.
    pub trait Record: Sized {
        fn to_bytes(&self) -> Vec<u8>;
        /// # Errors
        /// The bytes are not this record.
        fn from_bytes(bytes: &[u8]) -> Result<Self, RecordError>;
    }

    /// A stored record that doesn't decode.
    #[derive(Debug)]
    pub struct RecordError(pub String);

    impl std::fmt::Display for RecordError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for RecordError {}

    impl<T: prost::Message + Default> Record for T {
        fn to_bytes(&self) -> Vec<u8> {
            self.encode_to_vec()
        }
        fn from_bytes(bytes: &[u8]) -> Result<Self, RecordError> {
            T::decode(bytes).map_err(|e| RecordError(e.to_string()))
        }
    }

    /// `record`'s bytes.
    ///
    /// # Errors
    /// Never; the `Result` keeps call sites uniform with [`deserialize`].
    #[allow(clippy::unnecessary_wraps)]
    pub fn serialize<T: Record>(record: &T) -> Result<Vec<u8>, RecordError> {
        Ok(record.to_bytes())
    }

    /// The record in `bytes`.
    ///
    /// # Errors
    /// The bytes are not a `T`.
    pub fn deserialize<T: Record>(bytes: &[u8]) -> Result<T, RecordError> {
        T::from_bytes(bytes)
    }
}

// ---- S3 / Cluster types ----

/// OSD node information for placement. Stored as [`OsdNodeRecord`].
#[derive(Clone, Debug)]
pub struct OsdNode {
    pub node_id: [u8; 16],
    pub address: String,
    pub disk_ids: Vec<[u8; 16]>,
    /// Full 5-level topology `(region, zone, datacenter, rack, host)`.
    pub topology: Option<(String, String, String, String, String)>,
    /// Raw capacity per disk in bytes, index-aligned with `disk_ids`.
    pub disk_capacity_bytes: Vec<u64>,
    /// Operator-set intent — `In` (default, participating), `Out`
    /// (forced out of placement), or `Draining`. Independent of
    /// heartbeat-derived `NodeStatus` used by the topology; the service
    /// merges the two when rebuilding CRUSH.
    pub admin_state: objectio_common::OsdAdminState,
    /// Transfer Engine segment (`ip:port`) the OSD accepts shard transfers
    /// on, from its registration. Empty when it has none — gateways then
    /// move its shards as gRPC bytes.
    pub te_segment: String,
}

/// How an [`OsdNode`] is stored.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OsdNodeRecord {
    #[prost(bytes = "vec", tag = "1")]
    pub node_id: Vec<u8>,
    #[prost(string, tag = "2")]
    pub address: String,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub disk_ids: Vec<Vec<u8>>,
    /// `region, zone, datacenter, rack, host`; empty when it has none.
    #[prost(string, repeated, tag = "4")]
    pub topology: Vec<String>,
    #[prost(uint64, repeated, tag = "5")]
    pub disk_capacity_bytes: Vec<u64>,
    /// "in", "out" or "draining".
    #[prost(string, tag = "6")]
    pub admin_state: String,
    #[prost(string, tag = "7")]
    pub te_segment: String,
}

fn id16(bytes: &[u8]) -> Result<[u8; 16], record::RecordError> {
    bytes
        .try_into()
        .map_err(|_| record::RecordError(format!("an id of {} bytes, not 16", bytes.len())))
}

impl record::Record for OsdNode {
    fn to_bytes(&self) -> Vec<u8> {
        use prost::Message;
        OsdNodeRecord {
            node_id: self.node_id.to_vec(),
            address: self.address.clone(),
            disk_ids: self.disk_ids.iter().map(|d| d.to_vec()).collect(),
            topology: self
                .topology
                .clone()
                .map(|(r, z, d, k, h)| vec![r, z, d, k, h])
                .unwrap_or_default(),
            disk_capacity_bytes: self.disk_capacity_bytes.clone(),
            admin_state: self.admin_state.as_str().to_string(),
            te_segment: self.te_segment.clone(),
        }
        .encode_to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, record::RecordError> {
        let r = <OsdNodeRecord as record::Record>::from_bytes(bytes)?;
        let topology = match <[String; 5]>::try_from(r.topology) {
            Ok([region, zone, dc, rack, host]) => Some((region, zone, dc, rack, host)),
            Err(t) if t.is_empty() => None,
            Err(t) => {
                return Err(record::RecordError(format!(
                    "a topology of {} levels, not 5",
                    t.len()
                )));
            }
        };
        Ok(Self {
            node_id: id16(&r.node_id)?,
            address: r.address,
            disk_ids: r
                .disk_ids
                .iter()
                .map(|d| id16(d))
                .collect::<Result<_, _>>()?,
            topology,
            disk_capacity_bytes: r.disk_capacity_bytes,
            admin_state: r
                .admin_state
                .parse()
                .map_err(|e: &str| record::RecordError(e.to_string()))?,
            te_segment: r.te_segment,
        })
    }
}

/// EC configuration for a storage class
#[derive(Clone, Debug)]
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
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MultipartUploadState {
    #[prost(string, tag = "1")]
    pub bucket: String,
    #[prost(string, tag = "2")]
    pub key: String,
    #[prost(string, tag = "3")]
    pub upload_id: String,
    #[prost(string, tag = "4")]
    pub content_type: String,
    #[prost(map = "string, string", tag = "5")]
    pub user_metadata: HashMap<String, String>,
    #[prost(uint64, tag = "6")]
    pub initiated: u64,
    #[prost(map = "uint32, message", tag = "7")]
    pub parts: HashMap<u32, PartState>,
    /// Server-side encryption for this upload. Fixed at CreateMultipartUpload
    /// time; per-UploadPart SSE headers are ignored (AWS semantics). Values
    /// map to `SseAlgorithm` in the proto (0 = none, 1 = AES256, 2 = aws:kms,
    /// 3 = sse-c).
    #[prost(int32, tag = "8")]
    pub encryption_algorithm: i32,
    #[prost(string, tag = "9")]
    pub kms_key_id: String,
    #[prost(bytes = "vec", tag = "10")]
    pub encrypted_dek: Vec<u8>,
    /// SSE-C only: base64-encoded MD5 of the customer key provided at
    /// CreateMultipartUpload. Every UploadPart must resupply a matching key;
    /// we never store the raw key bytes.
    #[prost(string, tag = "11")]
    pub customer_key_md5: String,
    /// SSE-KMS only: encryption context supplied at CreateMultipartUpload.
    /// Round-tripped to UploadPart's KmsProvider::decrypt call so the AEAD
    /// binding on the wrapped DEK still validates.
    #[prost(map = "string, string", tag = "12")]
    pub encryption_context: HashMap<String, String>,
}

/// State for a completed part within a multipart upload
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PartState {
    #[prost(uint32, tag = "1")]
    pub part_number: u32,
    #[prost(string, tag = "2")]
    pub etag: String,
    #[prost(uint64, tag = "3")]
    pub size: u64,
    #[prost(uint64, tag = "4")]
    pub last_modified: u64,
    /// The part's flexible checksum: S3 algorithm name and base64 value.
    #[prost(string, tag = "5")]
    pub checksum_algorithm: String,
    #[prost(string, tag = "6")]
    pub checksum: String,
    #[prost(message, repeated, tag = "7")]
    pub stripes: Vec<objectio_proto::metadata::StripeMeta>,
}

// ---- IAM types ----

/// Internal user storage
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StoredUser {
    #[prost(string, tag = "1")]
    pub user_id: String,
    #[prost(string, tag = "2")]
    pub display_name: String,
    #[prost(string, tag = "3")]
    pub arn: String,
    #[prost(int32, tag = "4")]
    pub status: i32,
    #[prost(uint64, tag = "5")]
    pub created_at: u64,
    #[prost(string, tag = "6")]
    pub email: String,
    #[prost(string, tag = "7")]
    pub tenant: String,
}

/// Internal access key storage
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StoredAccessKey {
    #[prost(string, tag = "1")]
    pub access_key_id: String,
    #[prost(string, tag = "2")]
    pub secret_access_key: String,
    #[prost(string, tag = "3")]
    pub user_id: String,
    #[prost(int32, tag = "4")]
    pub status: i32,
    #[prost(uint64, tag = "5")]
    pub created_at: u64,
    #[prost(string, tag = "6")]
    pub tenant: String,
    /// `s3://bucket/prefix/` restriction. Empty = unscoped.
    #[prost(string, tag = "7")]
    pub scope: String,
    /// `KeyOperation` proto value: 0 = READ_WRITE, 1 = READ. Zero is the
    /// permissive default so an unset value imposes no restriction.
    #[prost(int32, tag = "8")]
    pub operation: i32,
}

/// Internal group storage
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StoredGroup {
    #[prost(string, tag = "1")]
    pub group_id: String,
    #[prost(string, tag = "2")]
    pub group_name: String,
    #[prost(string, tag = "3")]
    pub arn: String,
    #[prost(string, repeated, tag = "4")]
    pub member_user_ids: Vec<String>,
    #[prost(uint64, tag = "5")]
    pub created_at: u64,
}

// ---- Iceberg data filter types ----

/// Stored data filter for column/row-level security
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StoredDataFilter {
    #[prost(string, tag = "1")]
    pub filter_id: String,
    #[prost(string, tag = "2")]
    pub filter_name: String,
    #[prost(string, repeated, tag = "3")]
    pub namespace_levels: Vec<String>,
    #[prost(string, tag = "4")]
    pub table_name: String,
    #[prost(string, repeated, tag = "5")]
    pub principal_arns: Vec<String>,
    #[prost(string, repeated, tag = "6")]
    pub allowed_columns: Vec<String>,
    #[prost(string, repeated, tag = "7")]
    pub excluded_columns: Vec<String>,
    #[prost(string, tag = "8")]
    pub row_filter_expression: String,
    #[prost(uint64, tag = "9")]
    pub created_at: u64,
    #[prost(uint64, tag = "10")]
    pub updated_at: u64,
}

#[cfg(test)]
mod tests {
    use super::record::{Record, deserialize, serialize};
    use super::*;

    fn node(topology: Option<(String, String, String, String, String)>) -> OsdNode {
        OsdNode {
            node_id: [7; 16],
            address: "http://10.0.0.7:9200".into(),
            disk_ids: vec![[1; 16], [2; 16]],
            topology,
            disk_capacity_bytes: vec![1 << 40, 2 << 40],
            admin_state: objectio_common::OsdAdminState::Draining,
            te_segment: "10.0.0.7:12345".into(),
        }
    }

    #[test]
    fn an_osd_node_round_trips_with_and_without_a_topology() {
        for topology in [
            None,
            Some(("r".into(), "z".into(), "d".into(), "k".into(), "h".into())),
        ] {
            let n = node(topology);
            let back: OsdNode = deserialize(&serialize(&n).unwrap()).unwrap();
            assert_eq!(back.node_id, n.node_id);
            assert_eq!(back.disk_ids, n.disk_ids);
            assert_eq!(back.topology, n.topology);
            assert_eq!(back.disk_capacity_bytes, n.disk_capacity_bytes);
            assert_eq!(back.admin_state, n.admin_state);
            assert_eq!(back.te_segment, n.te_segment);
        }
    }

    #[test]
    fn a_malformed_osd_node_is_refused_not_guessed() {
        use prost::Message;
        let bad_id = OsdNodeRecord {
            node_id: vec![1; 15],
            admin_state: "in".into(),
            ..Default::default()
        };
        assert!(OsdNode::from_bytes(&bad_id.encode_to_vec()).is_err());
        let bad_topology = OsdNodeRecord {
            node_id: vec![1; 16],
            topology: vec!["r".into(), "z".into()],
            admin_state: "in".into(),
            ..Default::default()
        };
        assert!(OsdNode::from_bytes(&bad_topology.encode_to_vec()).is_err());
    }

    /// Why records are protobuf: a release that adds a field writes records
    /// the release before it still reads (it skips the field it doesn't
    /// know), so the two can run side by side during a rolling upgrade.
    #[test]
    fn a_record_with_a_field_from_a_newer_release_still_decodes() {
        use prost::Message;
        #[derive(Clone, PartialEq, ::prost::Message)]
        struct NewerUser {
            #[prost(string, tag = "1")]
            user_id: String,
            #[prost(string, tag = "7")]
            tenant: String,
            #[prost(string, tag = "99")]
            added_later: String,
        }
        let bytes = NewerUser {
            user_id: "u1".into(),
            tenant: "acme".into(),
            added_later: "x".into(),
        }
        .encode_to_vec();
        let user: StoredUser = deserialize(&bytes).unwrap();
        assert_eq!(
            (user.user_id.as_str(), user.tenant.as_str()),
            ("u1", "acme")
        );
    }
}
