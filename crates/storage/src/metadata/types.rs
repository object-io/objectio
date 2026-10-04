//! Metadata types for OSD storage

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Key for metadata entries
///
/// Keys are designed for efficient prefix scanning: `m` (an object's
/// current version), `v` (its versions), and the OSD's own prefixes
/// (`osd_loc:` for shard locations, `dedup_note:`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MetadataKey(pub Vec<u8>);

impl MetadataKey {
    /// Create a block metadata key
    pub fn block(block_num: u64) -> Self {
        let mut key = Vec::with_capacity(9);
        key.push(b'b');
        key.extend_from_slice(&block_num.to_be_bytes()); // Big-endian for sorting
        Self(key)
    }

    /// Create an object metadata key by bucket/key (for primary OSD storage)
    /// Format: `m:{bucket}\0{key}`
    pub fn object_meta(bucket: &str, key: &str) -> Self {
        let mut data = Vec::with_capacity(2 + bucket.len() + key.len());
        data.push(b'm');
        data.extend_from_slice(bucket.as_bytes());
        data.push(0); // null separator
        data.extend_from_slice(key.as_bytes());
        Self(data)
    }

    /// Create a prefix for scanning object metadata by bucket
    /// Format: `m:{bucket}\0`
    pub fn object_meta_prefix(bucket: &str) -> Self {
        let mut data = Vec::with_capacity(2 + bucket.len());
        data.push(b'm');
        data.extend_from_slice(bucket.as_bytes());
        data.push(0);
        Self(data)
    }

    /// Global scan prefix: every object metadata entry across every
    /// bucket on this OSD. Single-byte `m` prefix.
    ///
    /// Used by the drain migrator (FindObjectsReferencingNode) which
    /// needs to enumerate all primary-held ObjectMetas to discover
    /// which ones reference a draining OSD's node_id.
    #[must_use]
    pub fn all_object_meta_prefix() -> Self {
        Self(vec![b'm'])
    }

    /// Parse bucket and key from object metadata key
    pub fn parse_object_meta(&self) -> Option<(String, String)> {
        if self.0.first() != Some(&b'm') {
            return None;
        }
        let rest = &self.0[1..];
        let null_pos = rest.iter().position(|&b| b == 0)?;
        let bucket = std::str::from_utf8(&rest[..null_pos]).ok()?;
        let key = std::str::from_utf8(&rest[null_pos + 1..]).ok()?;
        Some((bucket.to_string(), key.to_string()))
    }

    /// Create a versioned object metadata key
    /// Format: `v:{bucket}\0{key}\0{version_id}`
    pub fn object_version(bucket: &str, key: &str, version_id: &str) -> Self {
        let mut data = Vec::with_capacity(3 + bucket.len() + key.len() + version_id.len());
        data.push(b'v');
        data.extend_from_slice(bucket.as_bytes());
        data.push(0);
        data.extend_from_slice(key.as_bytes());
        data.push(0);
        data.extend_from_slice(version_id.as_bytes());
        Self(data)
    }

    /// Create a prefix for scanning all versions of objects in a bucket
    /// Format: `v:{bucket}\0`
    pub fn object_version_bucket_prefix(bucket: &str) -> Self {
        let mut data = Vec::with_capacity(2 + bucket.len());
        data.push(b'v');
        data.extend_from_slice(bucket.as_bytes());
        data.push(0);
        Self(data)
    }

    /// Create a prefix for scanning all versions of a specific object
    /// Format: `v:{bucket}\0{key}\0`
    pub fn object_version_prefix(bucket: &str, key: &str) -> Self {
        let mut data = Vec::with_capacity(3 + bucket.len() + key.len());
        data.push(b'v');
        data.extend_from_slice(bucket.as_bytes());
        data.push(0);
        data.extend_from_slice(key.as_bytes());
        data.push(0);
        Self(data)
    }

    /// Parse bucket, key, and version_id from versioned object metadata key
    pub fn parse_object_version(&self) -> Option<(String, String, String)> {
        if self.0.first() != Some(&b'v') {
            return None;
        }
        let rest = &self.0[1..];
        let first_null = rest.iter().position(|&b| b == 0)?;
        let bucket = std::str::from_utf8(&rest[..first_null]).ok()?;
        let after_bucket = &rest[first_null + 1..];
        let second_null = after_bucket.iter().position(|&b| b == 0)?;
        let key = std::str::from_utf8(&after_bucket[..second_null]).ok()?;
        let version_id = std::str::from_utf8(&after_bucket[second_null + 1..]).ok()?;
        Some((bucket.to_string(), key.to_string(), version_id.to_string()))
    }

    /// The tombstone of a delete of `bucket/key` (`version_id` empty: the
    /// current object), holding the delete's stamp
    /// (objectio-docs core/object-metadata-quorum.md).
    /// Format: `t{bucket}\0{key}\0{version_id}`
    pub fn tombstone(bucket: &str, key: &str, version_id: &str) -> Self {
        let mut data = Vec::with_capacity(3 + bucket.len() + key.len() + version_id.len());
        data.push(b't');
        data.extend_from_slice(bucket.as_bytes());
        data.push(0);
        data.extend_from_slice(key.as_bytes());
        data.push(0);
        data.extend_from_slice(version_id.as_bytes());
        Self(data)
    }

    /// Get the key type prefix
    pub fn key_type(&self) -> Option<char> {
        self.0.first().map(|&b| b as char)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Ord for MetadataKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for MetadataKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for MetadataKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Generic metadata entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetadataEntry {
    /// Entry key
    pub key: MetadataKey,
    /// Entry value (serialized)
    pub value: Vec<u8>,
    /// Log Sequence Number (for ordering)
    pub lsn: u64,
    /// Tombstone flag (true = deleted)
    pub deleted: bool,
}

impl MetadataEntry {
    /// Create a new entry
    pub fn new(key: MetadataKey, value: Vec<u8>, lsn: u64) -> Self {
        Self {
            key,
            value,
            lsn,
            deleted: false,
        }
    }

    /// Create a tombstone (deletion marker)
    pub fn tombstone(key: MetadataKey, lsn: u64) -> Self {
        Self {
            key,
            value: vec![],
            lsn,
            deleted: true,
        }
    }
}

/// Metadata operation type for WAL
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MetadataOp {
    /// Insert or update an entry
    Put { key: MetadataKey, value: Vec<u8> },
    /// Delete an entry
    Delete { key: MetadataKey },
    /// Batch of operations (atomic)
    Batch { ops: Vec<MetadataOp> },
}

/// How a [`MetadataOp`] is written to the metadata log: protobuf, so a
/// later release can add fields that this one skips.
#[derive(Clone, PartialEq, ::prost::Message)]
struct OpRecord {
    /// 1 = put, 2 = delete, 3 = batch.
    #[prost(uint32, tag = "1")]
    kind: u32,
    #[prost(bytes = "vec", tag = "2")]
    key: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    value: Vec<u8>,
    #[prost(message, repeated, tag = "4")]
    ops: Vec<OpRecord>,
}

impl OpRecord {
    fn of(op: &MetadataOp) -> Self {
        match op {
            MetadataOp::Put { key, value } => Self {
                kind: 1,
                key: key.0.clone(),
                value: value.clone(),
                ops: Vec::new(),
            },
            MetadataOp::Delete { key } => Self {
                kind: 2,
                key: key.0.clone(),
                ..Self::default()
            },
            MetadataOp::Batch { ops } => Self {
                kind: 3,
                ops: ops.iter().map(Self::of).collect(),
                ..Self::default()
            },
        }
    }

    fn into_op(self) -> Option<MetadataOp> {
        Some(match self.kind {
            1 => MetadataOp::Put {
                key: MetadataKey(self.key),
                value: self.value,
            },
            2 => MetadataOp::Delete {
                key: MetadataKey(self.key),
            },
            3 => MetadataOp::Batch {
                ops: self
                    .ops
                    .into_iter()
                    .map(Self::into_op)
                    .collect::<Option<_>>()?,
            },
            _ => return None,
        })
    }
}

impl MetadataOp {
    /// The operation as the metadata log stores it.
    pub fn to_bytes(&self) -> Vec<u8> {
        use prost::Message;
        OpRecord::of(self).encode_to_vec()
    }

    /// The operation in `data`; `None` if it isn't one this release knows.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        use prost::Message;
        OpRecord::decode(data).ok()?.into_op()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_key_ordering() {
        let k1 = MetadataKey::block(1);
        let k2 = MetadataKey::block(2);
        let k3 = MetadataKey::block(100);

        assert!(k1 < k2);
        assert!(k2 < k3);
    }
}
