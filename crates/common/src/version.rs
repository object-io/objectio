//! Format levels: what lets a cluster run two releases side by side during a
//! rolling upgrade (objectio-docs `architecture/design/core/upgrade-path.md`).
//!
//! A binary's **format level** rises whenever a release adds something an
//! older binary would misread: a stored or exchanged format, a Raft command,
//! a meaning. Meta keeps the cluster's **active level**, the highest level
//! any node may *write*; it rises only when the operator finalizes an
//! upgrade, after every node runs the new release. Until then a newer node
//! reads the new formats but writes the old ones, so any node can go back.
//!
//! Code that writes something new asks [`allows`] first.

use std::sync::atomic::{AtomicU32, Ordering};

/// This binary's format level. Releases before levels existed (v0.4.0 and
/// earlier) are not supported at all: a cluster on one is reinstalled, not
/// upgraded, and a client that declares no level is refused.
///
/// | Level | Adds |
/// |---|---|
/// | 1 | format levels (v0.5.0) |
/// | 2 | object metadata at quorum: an ObjectMeta write succeeds at the write quorum, so a copy may lag (objectio-docs `core/object-metadata-quorum.md`); readers must take the newest copy |
/// | 3 | the IAM API: paths on users, groups, roles and policies; role and policy ids; group renames; inline policies (meta table `iam_inline_policies`) |
/// | 4 | meta's Raft log in files of its own, not in its database (objectio-docs `core/meta-log.md`): a meta node of the previous release would find its log empty |
/// | 5 | small shards kept in the OSD's metadata records, not disk blocks (objectio-docs `core/small-object-path.md`): an OSD of the previous release can't read them |
/// | 6 | a completed multipart upload kept, marked completed, until its object is committed: a meta node of the previous release would take it for an open upload, list it and let an abort free the object's parts |
pub const FORMAT_LEVEL: u32 = 6;

/// The level from which meta keeps a completed multipart upload (marked
/// with its object) until the gateway has committed that object, so a
/// completion sent again gets the same object.
pub const COMPLETED_UPLOADS_LEVEL: u32 = 6;

/// The level from which small shards are kept in the OSDs' metadata
/// records and sent with their object's metadata (B21).
pub const SMALL_SHARDS_LEVEL: u32 = 5;

/// The largest shard kept in an OSD's metadata record rather than a disk
/// block (B21): a 64 KiB object's shards with 4+2.
pub const SMALL_SHARD_MAX: usize = 16 * 1024;

/// The lowest active level this binary can run in: it reads every format
/// from this level up.
pub const MIN_LEVEL: u32 = 1;

/// The release, as tagged (`v` + the workspace version).
pub const RELEASE: &str = env!("CARGO_PKG_VERSION");

/// Meta config key holding the cluster's active level (decimal text).
/// Absent (0) only while a new cluster is being set up, before its first
/// OSD registers; then it is this release's level.
pub const ACTIVE_LEVEL_KEY: &str = "cluster/active_level";

/// The token in a meta client's `user-agent` that carries its level.
const LEVEL_TOKEN: &str = "objectio-level/";

static ACTIVE: AtomicU32 = AtomicU32::new(0);

/// The cluster's active level as this process last learned it (0 until it
/// has heard from meta).
#[must_use]
pub fn active_level() -> u32 {
    ACTIVE.load(Ordering::Acquire)
}

/// Record the cluster's active level. It only ever rises.
pub fn set_active_level(level: u32) {
    ACTIVE.fetch_max(level, Ordering::AcqRel);
}

/// Whether the cluster lets this process write formats introduced at
/// `level`.
#[must_use]
pub fn allows(level: u32) -> bool {
    active_level() >= level
}

/// Why this binary can't run in a cluster at `active`, if it can't. An
/// `active` of 0 is a cluster still being set up: anything may join.
#[must_use]
pub fn incompatibility(active: u32) -> Option<String> {
    if active == 0 {
        None
    } else if FORMAT_LEVEL < active {
        Some(format!(
            "this binary (release {RELEASE}, format level {FORMAT_LEVEL}) is older than the \
             cluster, whose active level is {active}: run a release at level {active} or above"
        ))
    } else if MIN_LEVEL > active {
        Some(format!(
            "this binary (release {RELEASE}) needs the cluster at format level {MIN_LEVEL} or \
             above, and it is at {active}: upgrade through the releases in between first"
        ))
    } else {
        None
    }
}

/// The `user-agent` a meta client sends, carrying its release and level.
#[must_use]
pub fn user_agent() -> String {
    format!("objectio/{RELEASE} {LEVEL_TOKEN}{FORMAT_LEVEL}")
}

/// The format level a caller's `user-agent` declares; 0 when it declares
/// none, which no supported release does.
#[must_use]
pub fn level_of_user_agent(user_agent: &str) -> u32 {
    user_agent
        .split_whitespace()
        .find_map(|t| t.strip_prefix(LEVEL_TOKEN))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_agent_round_trips_its_level() {
        let ua = format!("{} tonic/0.12.3", user_agent());
        assert_eq!(level_of_user_agent(&ua), FORMAT_LEVEL);
    }

    #[test]
    fn a_client_that_declares_no_level_is_level_0() {
        assert_eq!(level_of_user_agent("tonic/0.12.3"), 0);
        assert_eq!(level_of_user_agent(""), 0);
        assert_eq!(level_of_user_agent("objectio-level/x"), 0);
    }

    #[test]
    fn compatibility_follows_the_levels() {
        assert!(incompatibility(0).is_none(), "a cluster being set up");
        assert!(incompatibility(FORMAT_LEVEL).is_none());
        assert!(incompatibility(MIN_LEVEL).is_none());
        assert!(incompatibility(FORMAT_LEVEL + 1).is_some());
    }
}
