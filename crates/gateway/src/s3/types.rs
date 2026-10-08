//! S3 request parameters and XML bodies, and the S3 error response.

use super::*;

/// Query parameters for list objects
#[derive(Debug, Deserialize, Default)]
pub struct ListObjectsParams {
    /// If present, a bucket tagging request.
    pub(crate) tagging: Option<String>,
    pub(crate) prefix: Option<String>,
    pub(crate) delimiter: Option<String>,
    #[serde(rename = "max-keys")]
    pub(crate) max_keys: Option<String>,
    #[serde(rename = "continuation-token")]
    pub(crate) continuation_token: Option<String>,
    /// V1 pagination position (`?marker=`). Was unparsed, so a V1
    /// client could never advance past the first page.
    pub(crate) marker: Option<String>,
    /// V2 pagination position (`?start-after=`). Also unparsed.
    #[serde(rename = "start-after")]
    pub(crate) start_after: Option<String>,
    /// `list-type=2` selects the ListObjectsV2 request/response shape.
    /// Absent means V1, which uses Marker/NextMarker rather than
    /// KeyCount/ContinuationToken.
    #[serde(rename = "list-type")]
    pub(crate) list_type: Option<String>,
    /// Accepted and echoed; only "url" is meaningful to S3 and we do
    /// not currently encode keys, so this is recorded, not honored.
    #[serde(rename = "encoding-type")]
    pub(crate) encoding_type: Option<String>,
    /// ListObjectsV2: put each object's owner in the answer.
    #[serde(rename = "fetch-owner")]
    pub(crate) fetch_owner: Option<String>,
    /// If present, a GetBucketAcl request
    pub(crate) acl: Option<String>,
    /// If present, a GetBucketOwnershipControls request
    #[serde(rename = "ownershipControls")]
    pub(crate) ownership_controls: Option<String>,
    /// If present, a GetPublicAccessBlock request
    #[serde(rename = "publicAccessBlock")]
    pub(crate) public_access_block: Option<String>,
    /// If present, a GetBucketPolicyStatus request
    #[serde(rename = "policyStatus")]
    pub(crate) policy_status: Option<String>,
    /// If present, a GetBucketCors request (see `crate::cors`)
    pub(crate) cors: Option<String>,
    /// If present, a bucket replication configuration request.
    pub(crate) replication: Option<String>,
    /// If present, a GetBucketLogging request (see `crate::bucket_logging`).
    pub(crate) logging: Option<String>,
    /// If present (even empty), this is a policy request
    pub(crate) policy: Option<String>,
    /// If present, this is a list object versions request
    pub(crate) versions: Option<String>,
    /// If present, this is a get bucket versioning request
    pub(crate) versioning: Option<String>,
    /// If present, this is a get object-lock configuration request
    #[serde(rename = "object-lock")]
    pub(crate) object_lock: Option<String>,
    /// If present, this is a get lifecycle configuration request
    pub(crate) lifecycle: Option<String>,
    /// If present, this is a get bucket encryption request
    pub(crate) encryption: Option<String>,
    /// If present (even empty), this is a ListMultipartUploads request
    pub(crate) uploads: Option<String>,
    /// Key marker for ListMultipartUploads pagination
    #[serde(rename = "key-marker")]
    pub(crate) key_marker: Option<String>,
    /// Version marker for ListObjectVersions pagination
    #[serde(rename = "version-id-marker")]
    pub(crate) version_id_marker: Option<String>,
    /// Upload ID marker for ListMultipartUploads pagination
    #[serde(rename = "upload-id-marker")]
    pub(crate) upload_id_marker: Option<String>,
    /// Max uploads per page for ListMultipartUploads
    #[serde(rename = "max-uploads")]
    pub(crate) max_uploads: Option<u32>,
}

impl ListObjectsParams {
    /// Check if this is a policy operation (has ?policy in query string)
    pub fn is_policy_request(&self) -> bool {
        self.policy.is_some()
    }
}

/// Query parameters for POST bucket operations
#[derive(Debug, Deserialize, Default)]
pub struct PostBucketParams {
    /// If present, this is a delete objects request
    pub(crate) delete: Option<String>,
    /// If present, this is a list multipart uploads request (also handled by GET)
    #[allow(dead_code)]
    pub(crate) uploads: Option<String>,
    /// If present, this is a prefix-scoped grep across multiple keys.
    /// The request body carries a [`grep::PrefixGrepRequest`].
    pub(crate) grep: Option<String>,
}

impl PostBucketParams {
    /// Check if this is a delete objects request (has ?delete in query string)
    pub fn is_delete_request(&self) -> bool {
        self.delete.is_some()
    }
}

/// Query parameters for PUT bucket operations
#[derive(Debug, Deserialize, Default)]
pub struct PutBucketParams {
    /// If present, a bucket tagging request.
    pub(crate) tagging: Option<String>,
    /// If present (even empty), this is a policy request
    pub(crate) policy: Option<String>,
    /// If present, this is a versioning request
    pub(crate) versioning: Option<String>,
    /// If present, this is an object-lock configuration request
    #[serde(rename = "object-lock")]
    pub(crate) object_lock: Option<String>,
    /// If present, this is a lifecycle configuration request
    pub(crate) lifecycle: Option<String>,
    /// If present, this is a put bucket encryption request
    pub(crate) encryption: Option<String>,
    /// If present, a PutBucketAcl request
    pub(crate) acl: Option<String>,
    /// If present, a PutBucketOwnershipControls request
    #[serde(rename = "ownershipControls")]
    pub(crate) ownership_controls: Option<String>,
    /// If present, a PutPublicAccessBlock request
    #[serde(rename = "publicAccessBlock")]
    pub(crate) public_access_block: Option<String>,
    /// If present, a PutBucketCors request (see `crate::cors`)
    pub(crate) cors: Option<String>,
    /// If present, a bucket replication configuration request.
    pub(crate) replication: Option<String>,
    /// If present, a PutBucketLogging request (see `crate::bucket_logging`).
    pub(crate) logging: Option<String>,
}

/// Query parameters for DELETE bucket operations
#[derive(Debug, Deserialize, Default)]
pub struct DeleteBucketParams {
    /// If present, a bucket tagging request.
    pub(crate) tagging: Option<String>,
    /// If present (even empty), this is a policy request
    pub(crate) policy: Option<String>,
    /// If present, this is a list multipart uploads request
    #[allow(dead_code)]
    pub(crate) uploads: Option<String>,
    /// If present, this is a lifecycle configuration delete request
    pub(crate) lifecycle: Option<String>,
    /// If present, this is a bucket encryption delete request
    pub(crate) encryption: Option<String>,
    /// If present, a DeletePublicAccessBlock request
    #[serde(rename = "publicAccessBlock")]
    pub(crate) public_access_block: Option<String>,
    /// If present, a DeleteBucketCors request (see `crate::cors`)
    pub(crate) cors: Option<String>,
    /// If present, a bucket replication configuration request.
    pub(crate) replication: Option<String>,
}

/// Query parameters for PUT object operations (handles both simple PUT and multipart)
#[derive(Debug, Deserialize, Default)]
pub struct PutObjectParams {
    /// Upload ID for multipart part upload
    #[serde(rename = "uploadId")]
    pub(crate) upload_id: Option<String>,
    /// Part number for multipart part upload (1-10000)
    #[serde(rename = "partNumber")]
    pub(crate) part_number: Option<u32>,
    /// If present, this is a put object retention request
    pub(crate) retention: Option<String>,
    /// If present, this is a put legal hold request
    #[serde(rename = "legal-hold")]
    pub(crate) legal_hold: Option<String>,
    /// If present, this is a tagging request
    pub(crate) tagging: Option<String>,
    /// The version a retention, legal hold or tagging request is for
    #[serde(rename = "versionId")]
    pub(crate) version_id: Option<String>,
    /// If present, a PutObjectAcl request
    pub(crate) acl: Option<String>,
}

/// Query parameters for GET object operations (handles both GET and list parts)
#[derive(Debug, Deserialize, Default)]
pub struct GetObjectParams {
    /// Upload ID for list parts request
    #[serde(rename = "uploadId")]
    pub(crate) upload_id: Option<String>,
    /// Max parts to return for list parts
    #[serde(rename = "max-parts")]
    pub(crate) max_parts: Option<u32>,
    /// Part number marker for pagination
    #[serde(rename = "part-number-marker")]
    pub(crate) part_number_marker: Option<u32>,
    /// Version ID for retrieving specific version (used by version-aware GET)
    #[serde(rename = "versionId")]
    pub(crate) version_id: Option<String>,
    /// One part of a multipart object
    #[serde(rename = "partNumber")]
    pub(crate) part_number: Option<u32>,
    /// If present, this is a GetObjectAttributes request
    pub(crate) attributes: Option<String>,
    /// If present, a GetObjectAcl request
    pub(crate) acl: Option<String>,
    /// If present, this is a get object retention request
    pub(crate) retention: Option<String>,
    /// If present, this is a get legal hold request
    #[serde(rename = "legal-hold")]
    pub(crate) legal_hold: Option<String>,
    /// If present, this is a tagging request
    pub(crate) tagging: Option<String>,
    #[serde(rename = "response-content-type")]
    pub(crate) response_content_type: Option<String>,
    #[serde(rename = "response-content-language")]
    pub(crate) response_content_language: Option<String>,
    #[serde(rename = "response-expires")]
    pub(crate) response_expires: Option<String>,
    #[serde(rename = "response-cache-control")]
    pub(crate) response_cache_control: Option<String>,
    #[serde(rename = "response-content-disposition")]
    pub(crate) response_content_disposition: Option<String>,
    #[serde(rename = "response-content-encoding")]
    pub(crate) response_content_encoding: Option<String>,
}

impl GetObjectParams {
    /// The `response-*` overrides asked for: header name and value.
    pub(crate) fn response_overrides(&self) -> Vec<(header::HeaderName, &str)> {
        [
            (header::CONTENT_TYPE, &self.response_content_type),
            (header::CONTENT_LANGUAGE, &self.response_content_language),
            (header::EXPIRES, &self.response_expires),
            (header::CACHE_CONTROL, &self.response_cache_control),
            (
                header::CONTENT_DISPOSITION,
                &self.response_content_disposition,
            ),
            (header::CONTENT_ENCODING, &self.response_content_encoding),
        ]
        .into_iter()
        .filter_map(|(name, v)| v.as_deref().map(|v| (name, v)))
        .collect()
    }
}

/// Query parameters for POST object operations (handles multipart initiate/complete)
#[derive(Debug, Deserialize, Default)]
pub struct PostObjectParams {
    /// If present, initiate multipart upload
    pub(crate) uploads: Option<String>,
    /// Upload ID for complete multipart upload
    #[serde(rename = "uploadId")]
    pub(crate) upload_id: Option<String>,
    /// If present, treat the request as a gateway-side grep. Body is a
    /// JSON [`grep::GrepRequest`]; response is NDJSON with one
    /// [`grep::GrepEvent`] per line. The query-string value is ignored
    /// — presence alone is the signal.
    pub(crate) grep: Option<String>,
}

/// Query parameters for DELETE object operations (handles both delete and abort)
#[derive(Debug, Deserialize, Default)]
pub struct DeleteObjectParams {
    /// Upload ID for abort multipart upload
    #[serde(rename = "uploadId")]
    pub(crate) upload_id: Option<String>,
    /// Version ID for deleting specific version
    #[serde(rename = "versionId")]
    pub(crate) version_id: Option<String>,
    /// If present, this is a DeleteObjectTagging request
    pub(crate) tagging: Option<String>,
}

#[derive(Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
pub struct ListBucketsResult {
    #[serde(rename = "Owner")]
    pub owner: Owner,
    #[serde(rename = "Buckets")]
    pub buckets: Buckets,
    /// Where the next page starts, when there is one.
    #[serde(rename = "ContinuationToken")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
}

/// Query parameters for ListBuckets.
#[derive(Debug, Deserialize, Default)]
pub struct ListBucketsParams {
    #[serde(rename = "max-buckets")]
    pub(crate) max_buckets: Option<u32>,
    #[serde(rename = "continuation-token")]
    pub(crate) continuation_token: Option<String>,
    pub(crate) prefix: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct Owner {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
}

#[derive(Serialize)]
pub struct Buckets {
    #[serde(rename = "Bucket")]
    pub bucket: Vec<Bucket>,
}

#[derive(Serialize)]
pub struct Bucket {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "CreationDate")]
    pub creation_date: String,
}

#[derive(Serialize)]
#[serde(rename = "ListBucketResult")]
pub struct ListBucketResult {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "Delimiter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    /// V1 only: echo of the requested ?marker=
    #[serde(rename = "Marker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    /// V1 only: where the client should resume. Emitted whenever the
    /// listing is truncated so a V1 client always has a way forward.
    #[serde(rename = "NextMarker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_marker: Option<String>,
    /// V2 only: echo of the requested ?start-after=
    #[serde(rename = "StartAfter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_after: Option<String>,
    /// V2 only: echo of the requested ?continuation-token=
    #[serde(rename = "ContinuationToken")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
    #[serde(rename = "EncodingType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_type: Option<String>,
    #[serde(rename = "MaxKeys")]
    pub max_keys: u32,
    #[serde(rename = "KeyCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_count: Option<u32>,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "NextContinuationToken")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_continuation_token: Option<String>,
    #[serde(rename = "CommonPrefixes")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub common_prefixes: Vec<CommonPrefix>,
    #[serde(rename = "Contents")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contents: Vec<ObjectContent>,
}

#[derive(Serialize)]
pub struct CommonPrefix {
    #[serde(rename = "Prefix")]
    pub prefix: String,
}

#[derive(Serialize)]
pub struct ObjectContent {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
    #[serde(rename = "StorageClass")]
    pub storage_class: String,
    /// V1 always, V2 with ?fetch-owner=true.
    #[serde(rename = "Owner")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Owner>,
}

#[derive(Serialize)]
#[serde(rename = "Error")]
pub struct S3Error {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "Resource")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(rename = "RequestId")]
    pub request_id: String,
}

impl S3Error {
    /// A failed meta or OSD call, as S3 answers it. Unavailable (a meta
    /// leader change, a node restarting) is 503 ServiceUnavailable, which
    /// S3 clients retry; anything else is 500 InternalError. tonic reports
    /// a connection that dropped (the node it went to was killed) as
    /// Unknown "transport error", and a call that ran out of time as
    /// Cancelled "Timeout expired": those are unavailable too.
    /// Whether a failed meta or OSD call means "unavailable, retry": the
    /// service said so, ran out of time, or the connection dropped (tonic's
    /// Unknown "transport error", Cancelled "Timeout expired").
    pub fn is_unavailable(e: &tonic::Status) -> bool {
        matches!(
            e.code(),
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled
        ) || crate::osd_pool::connection_broke(e)
    }

    /// A write refused because the OSDs it needs are full (B3): 507, which
    /// clients don't retry blindly, as MinIO answers (`XMinioStorageFull`).
    pub fn storage_full() -> Response {
        Self::xml_response(
            "StorageFull",
            "The cluster has no room for this write: its disks are full",
            StatusCode::INSUFFICIENT_STORAGE,
        )
    }

    /// A failed ObjectMeta read or write, as S3 answers it: 507 when the
    /// OSDs are full, 503 (retry) when copies were unreachable or this
    /// gateway's clock may not stamp writes, otherwise 500. `what`
    /// prefixes the message.
    pub fn for_osd_error(e: &crate::osd_pool::OsdPoolError, what: &str) -> Response {
        use crate::osd_pool::OsdPoolError as E;
        match e {
            E::StaleEpoch(_) => {
                let mut resp = Self::xml_response(
                    "ServiceUnavailable",
                    &format!("{what}: {e}"),
                    StatusCode::SERVICE_UNAVAILABLE,
                );
                resp.extensions_mut()
                    .insert(crate::osd_pool::StalePlacement);
                resp
            }
            E::Full(_) => Self::storage_full(),
            E::ConnectionFailed(_) | E::NoNodesAvailable | E::NodeNotFound(_) | E::ClockSkew(_) => {
                Self::xml_response(
                    "ServiceUnavailable",
                    &format!("{what}: {e}"),
                    StatusCode::SERVICE_UNAVAILABLE,
                )
            }
            E::ChecksumMismatch(_) | E::TooOld(_) => Self::xml_response(
                "InternalError",
                &format!("{what}: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        }
    }

    pub fn from_status(e: &tonic::Status) -> Response {
        if Self::is_unavailable(e) {
            Self::xml_response(
                "ServiceUnavailable",
                e.message(),
                StatusCode::SERVICE_UNAVAILABLE,
            )
        } else {
            Self::xml_response(
                "InternalError",
                &e.to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }

    pub(crate) fn xml_response(code: &str, message: &str, status: StatusCode) -> Response {
        let error = S3Error {
            code: code.to_string(),
            message: message.to_string(),
            resource: None,
            request_id: crate::audit::request_id().unwrap_or_else(|| Uuid::new_v4().to_string()),
        };

        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
            to_xml(&error).unwrap_or_default()
        );

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/xml")
            .extension(crate::gateway_metrics::S3ErrorCode(code.to_string()))
            .body(Body::from(xml))
            .unwrap()
    }
}

/// Response for InitiateMultipartUpload
#[derive(Serialize)]
#[serde(rename = "InitiateMultipartUploadResult")]
pub struct InitiateMultipartUploadResult {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
}

/// Response for CompleteMultipartUpload
#[derive(Serialize)]
#[serde(rename = "CompleteMultipartUploadResult")]
pub struct CompleteMultipartUploadResult {
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    // A checksum as S3 puts it in a body: one Checksum<ALG> element, and
    // its type. (quick-xml can't serialize #[serde(flatten)]: a flattened
    // struct here emptied the whole body.)
    #[serde(rename = "ChecksumCRC32", skip_serializing_if = "Option::is_none")]
    pub checksum_crc32: Option<String>,
    #[serde(rename = "ChecksumCRC32C", skip_serializing_if = "Option::is_none")]
    pub checksum_crc32c: Option<String>,
    #[serde(rename = "ChecksumCRC64NVME", skip_serializing_if = "Option::is_none")]
    pub checksum_crc64nvme: Option<String>,
    #[serde(rename = "ChecksumSHA1", skip_serializing_if = "Option::is_none")]
    pub checksum_sha1: Option<String>,
    #[serde(rename = "ChecksumSHA256", skip_serializing_if = "Option::is_none")]
    pub checksum_sha256: Option<String>,
    #[serde(rename = "ChecksumType", skip_serializing_if = "Option::is_none")]
    pub checksum_type: Option<String>,
}

/// A checksum's values for a response body's `Checksum<ALG>` and
/// `ChecksumType` elements.
#[derive(Default)]
pub struct ChecksumXml {
    pub(crate) crc32: Option<String>,
    pub(crate) crc32c: Option<String>,
    pub(crate) crc64nvme: Option<String>,
    pub(crate) sha1: Option<String>,
    pub(crate) sha256: Option<String>,
    pub(crate) checksum_type: Option<String>,
}

impl ChecksumXml {
    pub(crate) fn of(checksum: Option<&ObjectChecksum>, with_type: bool) -> Self {
        let mut x = Self::default();
        let Some(c) = checksum else {
            return x;
        };
        let v = Some(c.value.clone());
        match c.algorithm.as_str() {
            "CRC32" => x.crc32 = v,
            "CRC32C" => x.crc32c = v,
            "CRC64NVME" => x.crc64nvme = v,
            "SHA1" => x.sha1 = v,
            "SHA256" => x.sha256 = v,
            _ => {}
        }
        if with_type {
            x.checksum_type = Some(checksum_type_of(c).to_string());
        }
        x
    }
}

/// A multipart object's checksum type: a composite ends in "-<parts>".
pub(crate) fn checksum_type_of(c: &ObjectChecksum) -> &'static str {
    if c.value
        .rsplit_once('-')
        .is_some_and(|(_, n)| n.parse::<u32>().is_ok())
    {
        "COMPOSITE"
    } else {
        "FULL_OBJECT"
    }
}

/// Response for ListParts
#[derive(Serialize)]
#[serde(rename = "ListPartsResult")]
pub struct ListPartsResult {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "PartNumberMarker")]
    pub part_number_marker: u32,
    #[serde(rename = "NextPartNumberMarker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_part_number_marker: Option<u32>,
    #[serde(rename = "MaxParts")]
    pub max_parts: u32,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Part")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<PartItem>,
}

/// Part item in ListParts response
#[derive(Serialize)]
pub struct PartItem {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: u64,
    #[serde(rename = "ChecksumCRC32", skip_serializing_if = "Option::is_none")]
    pub checksum_crc32: Option<String>,
    #[serde(rename = "ChecksumCRC32C", skip_serializing_if = "Option::is_none")]
    pub checksum_crc32c: Option<String>,
    #[serde(rename = "ChecksumCRC64NVME", skip_serializing_if = "Option::is_none")]
    pub checksum_crc64nvme: Option<String>,
    #[serde(rename = "ChecksumSHA1", skip_serializing_if = "Option::is_none")]
    pub checksum_sha1: Option<String>,
    #[serde(rename = "ChecksumSHA256", skip_serializing_if = "Option::is_none")]
    pub checksum_sha256: Option<String>,
    #[serde(rename = "ChecksumType", skip_serializing_if = "Option::is_none")]
    pub checksum_type: Option<String>,
}

/// Response for ListMultipartUploads
#[derive(Serialize)]
#[serde(rename = "ListMultipartUploadsResult")]
pub struct ListMultipartUploadsResult {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "KeyMarker")]
    pub key_marker: String,
    #[serde(rename = "UploadIdMarker")]
    pub upload_id_marker: String,
    #[serde(rename = "NextKeyMarker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_key_marker: Option<String>,
    #[serde(rename = "NextUploadIdMarker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_upload_id_marker: Option<String>,
    #[serde(rename = "Delimiter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "MaxUploads")]
    pub max_uploads: u32,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Upload")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uploads: Vec<UploadItem>,
}

/// Upload item in ListMultipartUploads response
#[derive(Serialize)]
pub struct UploadItem {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "Initiated")]
    pub initiated: String,
    #[serde(rename = "StorageClass")]
    pub storage_class: String,
}

/// Request body for CompleteMultipartUpload (XML from client)
#[derive(Debug, Deserialize)]
#[serde(rename = "CompleteMultipartUpload")]
pub struct CompleteMultipartUploadXml {
    #[serde(rename = "Part", default)]
    pub parts: Vec<CompletePart>,
}

/// Part in CompleteMultipartUpload request
#[derive(Debug, Deserialize)]
pub struct CompletePart {
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    #[serde(rename = "ETag")]
    pub etag: String,
}

/// Request body for DeleteObjects (XML from client)
#[derive(Debug, Default)]
pub struct DeleteObjectsRequest {
    /// Report only the keys that could not be deleted.
    pub quiet: bool,
    pub objects: Vec<DeleteObjectIdentifier>,
}

/// Object identifier in DeleteObjects request
#[derive(Debug, Default)]
pub struct DeleteObjectIdentifier {
    pub key: String,
    pub version_id: Option<String>,
    /// Conditions: delete only if the object has this ETag, last-modified
    /// time (ISO 8601) or size.
    pub etag: Option<String>,
    pub last_modified_time: Option<String>,
    pub size: Option<String>,
}

impl DeleteObjectsRequest {
    /// Parse the body keeping every key exactly as sent. quick-xml's serde
    /// deserializer trims text, so a key with leading or trailing spaces
    /// (" ", "a ") came out as another key: that one was "deleted" and
    /// reported, and the object asked for stayed.
    pub fn parse(body: &[u8]) -> Result<Self, String> {
        use quick_xml::events::Event;
        let mut reader = quick_xml::Reader::from_reader(body);
        let mut buf = Vec::new();
        let mut req = Self::default();
        let mut path: Vec<Vec<u8>> = Vec::new();
        let mut text = String::new();
        let mut current: Option<DeleteObjectIdentifier> = None;
        loop {
            match reader
                .read_event_into(&mut buf)
                .map_err(|e| e.to_string())?
            {
                Event::Start(e) => {
                    let name = e.local_name().as_ref().to_vec();
                    if name == b"Object" {
                        current = Some(DeleteObjectIdentifier::default());
                    }
                    path.push(name);
                    text.clear();
                }
                Event::Text(t) => {
                    text.push_str(&t.unescape().map_err(|e| e.to_string())?);
                }
                Event::CData(t) => {
                    text.push_str(&String::from_utf8_lossy(&t.into_inner()));
                }
                Event::End(_) => {
                    let name = path.pop().unwrap_or_default();
                    match (name.as_slice(), current.as_mut()) {
                        (b"Key", Some(o)) => o.key = std::mem::take(&mut text),
                        (b"VersionId", Some(o)) => {
                            o.version_id = Some(std::mem::take(&mut text));
                        }
                        (b"ETag", Some(o)) => o.etag = Some(std::mem::take(&mut text)),
                        (b"LastModifiedTime", Some(o)) => {
                            o.last_modified_time = Some(std::mem::take(&mut text));
                        }
                        (b"Size", Some(o)) => o.size = Some(std::mem::take(&mut text)),
                        (b"Object", _) => {
                            if let Some(o) = current.take() {
                                req.objects.push(o);
                            }
                        }
                        (b"Quiet", None) => req.quiet = text.trim() == "true",
                        _ => {}
                    }
                    text.clear();
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }
        if !path.is_empty() {
            return Err("unclosed element".into());
        }
        Ok(req)
    }
}

/// Response for DeleteObjects
#[derive(Serialize)]
#[serde(rename = "DeleteResult")]
pub struct DeleteObjectsResult {
    #[serde(rename = "Deleted")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deleted: Vec<DeletedObject>,
    #[serde(rename = "Error")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<DeleteError>,
}

/// Successfully deleted object
#[derive(Serialize)]
pub struct DeletedObject {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "VersionId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// The delete added a marker, or removed one.
    #[serde(rename = "DeleteMarker")]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub delete_marker: bool,
    #[serde(rename = "DeleteMarkerVersionId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_marker_version_id: Option<String>,
}

/// Error deleting object
#[derive(Serialize)]
pub struct DeleteError {
    #[serde(rename = "Key")]
    pub key: String,
    /// The version the delete named, as S3 echoes it.
    #[serde(rename = "VersionId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
}

/// UploadPartCopy response
#[derive(Serialize)]
#[serde(rename = "CopyPartResult")]
pub(crate) struct CopyPartResult {
    #[serde(rename = "ETag")]
    pub(crate) etag: String,
    #[serde(rename = "LastModified")]
    pub(crate) last_modified: String,
}

/// CopyObject response
#[derive(Serialize)]
#[serde(rename = "CopyObjectResult")]
pub struct CopyObjectResult {
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
}

/// Render a Unix timestamp as the ISO 8601 form S3 clients parse.
///
/// `i64::try_from` rather than `as i64`: the cast wrapped the whole upper half
/// of `u64` into negative times, so a timestamp that could not be a real date
/// rendered as one in 1969 instead of reaching the fallback below. A client
/// reading `LastModified` cannot tell a wrong date from a right one.
pub(crate) fn timestamp_to_iso(ts: u64) -> String {
    use chrono::{DateTime, Utc};
    i64::try_from(ts)
        .ok()
        .and_then(|secs| DateTime::<Utc>::from_timestamp(secs, 0))
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string())
}

/// Render a Unix timestamp as an RFC 7231 HTTP date, e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`. Same wrapping caveat as
/// [`timestamp_to_iso`].
pub(crate) fn timestamp_to_http_date(ts: u64) -> String {
    use chrono::{DateTime, Utc};
    i64::try_from(ts)
        .ok()
        .and_then(|secs| DateTime::<Utc>::from_timestamp(secs, 0))
        .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
}

#[derive(Debug, Deserialize, Default)]
pub struct HeadObjectParams {
    #[serde(rename = "versionId")]
    pub(crate) version_id: Option<String>,
    #[serde(rename = "partNumber")]
    pub(crate) part_number: Option<u32>,
}
