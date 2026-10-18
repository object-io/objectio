//! The cluster's OSDs, as meta lists them (`GetListingNodes`): addresses,
//! Transfer Engine segments and failure domains, which a GET needs for
//! every shard holder. They change when an OSD joins, leaves or moves, not
//! per request, so a GET reads them from here instead of asking meta each
//! time (B21). The background poll (`cluster_poll`) refreshes the list;
//! a GET refreshes it itself only when it is missing or older than
//! [`MAX_AGE`].

use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{GetListingNodesRequest, ListingNode};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tonic::transport::Channel;

/// The oldest list a GET uses: two background polls.
pub const MAX_AGE: Duration = Duration::from_secs(60);

static NODES: RwLock<Option<(Instant, Arc<Vec<ListingNode>>)>> = RwLock::new(None);

/// Record the list the background poll fetched.
pub fn record(nodes: Vec<ListingNode>) {
    *NODES
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some((Instant::now(), Arc::new(nodes)));
}

/// The OSDs, from the last list if fresh enough, else from meta (and
/// kept). `None` if meta can't be asked and nothing is known.
pub async fn nodes(meta: &MetadataServiceClient<Channel>) -> Option<Arc<Vec<ListingNode>>> {
    if let Some((at, nodes)) = NODES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        && at.elapsed() < MAX_AGE
    {
        return Some(Arc::clone(nodes));
    }
    refresh(meta).await
}

/// Ask meta now: for a shard holder the last list doesn't know.
pub async fn refresh(meta: &MetadataServiceClient<Channel>) -> Option<Arc<Vec<ListingNode>>> {
    let mut client = meta.clone();
    match client
        .get_listing_nodes(GetListingNodesRequest {
            bucket: String::new(),
            include_all_states: true,
        })
        .await
    {
        Ok(resp) => {
            let nodes = resp.into_inner().nodes;
            record(nodes.clone());
            Some(Arc::new(nodes))
        }
        Err(_) => NODES
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(_, n)| Arc::clone(n)),
    }
}
