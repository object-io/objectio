//! Rolling upgrades: every node's reported version, the cluster's active
//! format level, and finalize (objectio-docs core/upgrade-path.md).
//!
//! Each process reports its release and format level every 30 s
//! (`objectio_proto::transport::spawn_version_reporter`); the leader keeps
//! the reports in memory (a new leader hears from everyone again within
//! 30 s). The active level lives in config, through Raft. Finalize raises
//! it to the lowest level among the nodes that must take part, and refuses
//! while any of them hasn't reported or runs an older release.

use std::time::{Duration, Instant};

use objectio_common::version;
use objectio_proto::metadata::{ConfigEntry, NodeVersion, ReportVersionRequest};
use prost::Message;
use tonic::Status;
use tracing::{error, info};

use super::MetaService;

/// A report older than this no longer counts: the node may be gone.
const FRESH: Duration = Duration::from_secs(90);

/// One node's last report.
pub(super) struct Report {
    pub(super) version: NodeVersion,
    pub(super) at: Instant,
}

/// What finalize would do now.
pub(super) struct Plan {
    pub(super) active: u32,
    pub(super) target: u32,
    pub(super) blockers: Vec<String>,
    pub(super) nodes: Vec<NodeVersion>,
}

impl MetaService {
    /// The cluster's active format level, from config (0 while a new
    /// cluster is being set up, before its first OSD registers).
    pub(super) fn active_level(&self) -> u32 {
        self.config
            .read()
            .get(version::ACTIVE_LEVEL_KEY)
            .and_then(|e| std::str::from_utf8(&e.value).ok()?.trim().parse().ok())
            .unwrap_or(0)
    }

    /// The active level changed (committed through Raft, or loaded): tell
    /// this process, and stop if this binary can no longer run in it.
    pub(super) fn note_active_level(&self) {
        let active = self.active_level();
        if let Some(why) = version::incompatibility(active) {
            error!("meta: {why}; stopping");
            std::process::exit(78);
        }
        version::set_active_level(active);
    }

    pub(super) fn record_version(&self, req: ReportVersionRequest) -> u32 {
        let key = (req.kind.clone(), req.id.clone());
        let report = Report {
            version: NodeVersion {
                kind: req.kind,
                id: req.id,
                release: req.release,
                format_level: req.format_level,
                min_level: req.min_level,
                address: req.address,
                seen_secs_ago: 0,
            },
            at: Instant::now(),
        };
        self.versions.write().insert(key, report);
        self.active_level()
    }

    /// Who must have reported, and what finalize would raise the level to.
    pub(super) fn upgrade_plan(&self) -> Plan {
        let active = self.active_level();
        let now = Instant::now();
        let reports = self.versions.read();
        let fresh = |kind: &str, id: &str| {
            reports
                .get(&(kind.to_string(), id.to_string()))
                .filter(|r| now.duration_since(r.at) < FRESH)
        };

        // Must take part: every meta voter, and every OSD not marked out.
        let mut required: Vec<(&str, String)> = Vec::new();
        if let Some(raft) = self.raft_handle() {
            let m = raft.metrics().borrow().clone();
            for id in m.membership_config.membership().voter_ids() {
                required.push(("meta", id.to_string()));
            }
        }
        for osd in self.osd_nodes.read().iter() {
            if osd.admin_state != objectio_common::OsdAdminState::Out {
                required.push(("osd", hex::encode(osd.node_id)));
            }
        }

        let mut blockers = Vec::new();
        let mut target = version::FORMAT_LEVEL;
        for (kind, id) in &required {
            match fresh(kind, id) {
                None => blockers.push(format!(
                    "{kind} {id} has not reported in the last {}s: it is down; start it, \
                     or remove it",
                    FRESH.as_secs()
                )),
                Some(r) => target = target.min(r.version.format_level),
            }
        }
        // Gateways can't be listed in advance (they're stateless); the
        // ones heard from count, and the operator checks the list.
        let mut nodes: Vec<NodeVersion> = reports
            .values()
            .filter(|r| now.duration_since(r.at) < FRESH)
            .map(|r| NodeVersion {
                seen_secs_ago: now.duration_since(r.at).as_secs(),
                ..r.version.clone()
            })
            .collect();
        nodes.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
        for n in &nodes {
            target = target.min(n.format_level);
        }
        // An upgrade under way: some nodes run a newer release than others.
        let newest = nodes.iter().map(|n| n.format_level).max().unwrap_or(0);
        for n in nodes.iter().filter(|n| n.format_level < newest) {
            blockers.push(format!(
                "{} {} still runs release {} (format level {}); others are at {newest}",
                n.kind, n.id, n.release, n.format_level
            ));
        }
        Plan {
            active,
            target: target.max(active),
            blockers,
            nodes,
        }
    }

    /// Raise the active level to the plan's target, through Raft.
    pub(super) async fn finalize(&self, requested_by: &str) -> Result<u32, Status> {
        let plan = self.upgrade_plan();
        if !plan.blockers.is_empty() {
            return Err(Status::failed_precondition(format!(
                "not every node runs the new release: {}",
                plan.blockers.join("; ")
            )));
        }
        if plan.target <= plan.active {
            return Ok(plan.active);
        }
        let Some(raft) = self.raft_handle() else {
            return Err(Status::unavailable(
                "no Raft; finalize needs a meta cluster",
            ));
        };
        let expected = self
            .config
            .read()
            .get(version::ACTIVE_LEVEL_KEY)
            .map(Message::encode_to_vec);
        let entry = ConfigEntry {
            key: version::ACTIVE_LEVEL_KEY.to_string(),
            value: plan.target.to_string().into_bytes(),
            updated_at: Self::current_timestamp(),
            updated_by: requested_by.to_string(),
            version: 0,
        };
        use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
        let cmd = MetaCommand::MultiCas {
            ops: vec![CasOp {
                table: CasTable::Config,
                key: version::ACTIVE_LEVEL_KEY.to_string(),
                expected,
                new_value: Some(entry.encode_to_vec()),
            }],
            requested_by: "upgrade-finalize".into(),
        };
        match raft.client_write(cmd).await {
            Ok(r) => match r.data {
                MetaResponse::MultiCasOk => {
                    info!(
                        "upgrade finalized by {requested_by}: active format level {} -> {}",
                        plan.active, plan.target
                    );
                    Ok(plan.target)
                }
                MetaResponse::MultiCasConflict { .. } => Err(Status::aborted(
                    "the active level changed meanwhile; check the status and retry",
                )),
                other => Err(Status::internal(format!(
                    "unexpected raft response to finalize: {other:?}"
                ))),
            },
            Err(e) => Err(super::raft_write_to_status(&e)),
        }
    }
}
