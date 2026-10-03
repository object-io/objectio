//! HTTP/2 settings for gRPC servers that receive shards.
//!
//! hyper's server defaults give each connection a 1 MiB receive window, for
//! each stream and for the connection as a whole. A shard is up to 4 MiB, so
//! a lone PUT's shard stalls on window updates several times on its way to
//! the OSD. On datacore (NVMe, loopback), opening the windows took a single
//! 4 MiB PUT from ~80 to ~175 MiB/s — its shard writes' transport time from
//! ~9 ms to ~2 ms — and left 16-way concurrent PUT and GET unchanged.
//!
//! Only servers are tuned. Enlarging the gateway's client windows as well
//! (hyper's client defaults are already 2 MiB per stream, 5 MiB per
//! connection) cost a single GET ~30% of its throughput in the same test.
//!
//! The windows are credit the receiver extends, not memory it allocates up
//! front: a connection only buffers what is actually in flight.

use tonic::transport::Server;

/// Per-stream window: one whole shard (at most 4 MiB) arrives without the
/// sender waiting for a window update.
pub const STREAM_WINDOW: u32 = 8 * 1024 * 1024;

/// Per-connection window: room for many shards in flight from one gateway.
pub const CONNECTION_WINDOW: u32 = 64 * 1024 * 1024;

/// A server builder whose connections accept shards at full window.
#[must_use]
pub fn server() -> Server {
    Server::builder()
        .initial_stream_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
}

/// Header marking a meta liveness probe (see [`meta_channel`]).
pub const META_PROBE_HEADER: &str = "x-objectio-probe";

/// The longest a call to meta may take before the client gives up on it:
/// a meta node that stopped answering (frozen, cut off) would otherwise
/// hold the call, and the request behind it, forever. Meta answers in
/// milliseconds and elects a new leader in one or two seconds, so 5 s is
/// ample; a call cut off by it fails as retryable (503 to S3 clients).
pub const META_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How often each meta address is probed, and how long a probe may take.
const PROBE_EVERY: std::time::Duration = std::time::Duration::from_secs(1);
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// A channel to the meta service. `endpoints` is one address, or several
/// separated by commas (every meta node, say). Any meta node serves any
/// call — a follower forwards it to the Raft leader — so with several, the
/// channel spreads calls over those that answer: each is probed every
/// second (a gRPC call it answers itself, with a one-second timeout — a
/// frozen node still accepts connections), and one that doesn't answer is
/// left out until it does. With one, the connection is made now, as
/// before, so a wrong address fails at startup. Every call times out after
/// [`META_CALL_TIMEOUT`].
///
/// # Errors
/// An address that doesn't parse, or (with one address) can't be reached.
pub async fn meta_channel(endpoints: &str) -> Result<tonic::transport::Channel, String> {
    let parsed: Vec<tonic::transport::Endpoint> = endpoints
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|e| {
            let uri = if e.contains("://") {
                e.to_string()
            } else {
                format!("http://{e}")
            };
            tonic::transport::Endpoint::from_shared(uri)
                .and_then(|ep| {
                    // The user-agent carries this binary's format level:
                    // meta refuses a client too old for the cluster.
                    ep.connect_timeout(std::time::Duration::from_secs(3))
                        .timeout(META_CALL_TIMEOUT)
                        .user_agent(objectio_common::version::user_agent())
                })
                .map_err(|err| format!("meta endpoint {e}: {err}"))
        })
        .collect::<Result<_, _>>()?;
    match parsed.as_slice() {
        [] => Err("no meta endpoint given".to_string()),
        [one] => one
            .connect()
            .await
            .map_err(|e| format!("connect to meta at {}: {e}", one.uri())),
        _ => {
            let (channel, changes) = tonic::transport::Channel::balance_channel::<usize>(16);
            for (i, ep) in parsed.iter().enumerate() {
                let _ = changes
                    .send(tower04::discover::Change::Insert(i, ep.clone()))
                    .await;
            }
            tokio::spawn(keep_healthy(parsed, changes));
            Ok(channel)
        }
    }
}

/// Probe every meta address and keep the balanced channel's set to those
/// that answer — or, if none does, to all of them, so calls fail rather
/// than wait. Ends when the channel is dropped.
async fn keep_healthy(
    endpoints: Vec<tonic::transport::Endpoint>,
    changes: tokio::sync::mpsc::Sender<
        tower04::discover::Change<usize, tonic::transport::Endpoint>,
    >,
) {
    let mut in_set = vec![true; endpoints.len()];
    loop {
        tokio::time::sleep(PROBE_EVERY).await;
        let mut alive = Vec::with_capacity(endpoints.len());
        for ep in &endpoints {
            alive.push(probe(ep).await);
        }
        let none_alive = !alive.iter().any(|a| *a);
        for (i, ep) in endpoints.iter().enumerate() {
            let want = alive[i] || none_alive;
            if want == in_set[i] {
                continue;
            }
            let change = if want {
                tower04::discover::Change::Insert(i, ep.clone())
            } else {
                tower04::discover::Change::Remove(i)
            };
            if changes.send(change).await.is_err() {
                return; // the channel is gone
            }
            in_set[i] = want;
        }
    }
}

/// Whether the meta node at `ep` answers a probe: any gRPC answer means
/// it's up; a connection failure or a timeout means it isn't.
async fn probe(ep: &tonic::transport::Endpoint) -> bool {
    let attempt = async {
        let channel = ep.connect().await.ok()?;
        let mut client =
            crate::metadata::metadata_service_client::MetadataServiceClient::new(channel);
        let mut req = tonic::Request::new(crate::metadata::GetMetricsRequest::default());
        req.metadata_mut().insert(
            META_PROBE_HEADER,
            tonic::metadata::MetadataValue::from_static("1"),
        );
        match client.get_metrics(req).await {
            Ok(_) => Some(()),
            // An answer, whatever it says: the node is up.
            Err(status) if !status.message().contains("transport error") => Some(()),
            Err(_) => None,
        }
    };
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, attempt).await,
        Ok(Some(()))
    )
}

/// How often each process reports its version to meta.
pub const VERSION_REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// Report this process's release and format level to meta now and every
/// [`VERSION_REPORT_EVERY`], and learn the cluster's active level from the
/// answer (`objectio_common::version::set_active_level`). A process too old
/// or too new for the cluster stops here with a message that says which,
/// rather than run and misread what the others write.
///
/// `endpoints` is the meta address list (as for [`meta_channel`]),
/// connected to with retries; `kind` is "meta", "osd", "gateway" or
/// "block-gateway"; `id` names the node within its kind.
pub fn spawn_version_reporter(endpoints: String, kind: &'static str, id: String, address: String) {
    use objectio_common::version;
    tokio::spawn(async move {
        let channel = loop {
            match meta_channel(&endpoints).await {
                Ok(c) => break c,
                Err(e) => {
                    tracing::debug!("{kind} {id}: version reporter can't reach meta yet: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        };
        let mut client =
            crate::metadata::metadata_service_client::MetadataServiceClient::new(channel);
        loop {
            let req = crate::metadata::ReportVersionRequest {
                kind: kind.to_string(),
                id: id.clone(),
                release: version::RELEASE.to_string(),
                format_level: version::FORMAT_LEVEL,
                min_level: version::MIN_LEVEL,
                address: address.clone(),
            };
            match client.report_version(req).await {
                Ok(resp) => {
                    let active = resp.into_inner().active_level;
                    if let Some(why) = version::incompatibility(active) {
                        tracing::error!("{kind} {id}: {why}; stopping");
                        std::process::exit(78);
                    }
                    version::set_active_level(active);
                }
                Err(status) if status.code() == tonic::Code::FailedPrecondition => {
                    tracing::error!(
                        "{kind} {id}: meta refused this binary: {}; stopping",
                        status.message()
                    );
                    std::process::exit(78);
                }
                Err(status) => {
                    tracing::debug!("{kind} {id}: version report failed ({status}); will retry");
                }
            }
            tokio::time::sleep(VERSION_REPORT_EVERY).await;
        }
    });
}
