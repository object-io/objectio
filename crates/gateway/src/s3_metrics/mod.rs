//! S3 metrics and usage accounting: per-operation request metrics, merging
//! the OSDs' and meta's metrics into the gateway's, and the usage report.

pub mod metrics;
pub mod metrics_merge;
pub mod usage;

pub use metrics::{
    IcebergOperation, OperationTimer, ProtectionConfig, S3Metrics, S3Operation, UnityOperation,
    observe_locality_read_bytes, s3_metrics,
};
