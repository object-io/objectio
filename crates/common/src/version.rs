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

/// This binary's format level.
///
/// Level 8 is the **baseline**: 0.1.0-rc.1, the first release, ran at it,
/// and no binary runs below it ([`MIN_LEVEL`]). What levels 1 to 8 added
/// (development builds before 0.1.0 ran at those) is how every supported
/// release works: format levels and version reports; object metadata at
/// quorum; the IAM API's paths and ids; meta's Raft log in files of its
/// own; small shards in the OSDs' metadata records; multipart completions
/// kept until their object is stored; every key placed through a placement
/// group; meta's group commit, metadata reads of an OSD several to a call,
/// and index values split to fit the index file's pages. A cluster on a
/// development build is reinstalled, not upgraded, and a client that
/// declares no level is refused.
///
/// | Level | Release | Adds |
/// |---|---|---|
/// | 8 | 0.1.0-rc.1 | the baseline |
/// | 9 | 0.1.0-rc.2 | users bound to the OIDC issuer and subject of the single sign-on that created them: a meta node of the previous release would drop the binding, and the user could no longer sign on |
/// | 10 | 0.1.0-rc.2 | roles on the services' certificates (objectio-docs `operations-guide/administration/mtls.md`): under mTLS each call between the services is checked against its peer's role, and a certificate of the previous release names none |
pub const FORMAT_LEVEL: u32 = 10;

/// The level from which a single sign-on creates a user bound to the
/// token's issuer and subject, and is mapped only to that user. Before it,
/// console single sign-on is refused.
pub const FEDERATED_USERS_LEVEL: u32 = 9;

/// The level from which a peer's certificate must name its role (a SAN
/// URI `spiffe://objectio/<role>`): below it, while the cluster still runs
/// a release whose certificates name none, one without a role is taken
/// for any.
pub const PEER_ROLES_LEVEL: u32 = 10;

/// The largest shard kept in an OSD's metadata record rather than a disk
/// block (B21): a 64 KiB object's shards with 4+2.
pub const SMALL_SHARD_MAX: usize = 16 * 1024;

/// The lowest active level this binary can run in, the baseline: it reads
/// every format from this level up, and refuses to start in, or join, a
/// cluster below it.
pub const MIN_LEVEL: u32 = 8;

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
            "this binary (release {RELEASE}) runs in a cluster at format level {MIN_LEVEL} \
             (0.1.0-rc.1) or above, and this one is at {active}: a development build from \
             before 0.1.0, which can't be upgraded. Install this release fresh and copy the \
             data across"
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

    #[test]
    fn a_cluster_below_the_baseline_is_refused_saying_why() {
        assert_eq!(MIN_LEVEL, 8, "the baseline: 0.1.0-rc.1's level");
        assert!(incompatibility(8).is_none(), "0.1.0-rc.1's level");
        for below in 1..MIN_LEVEL {
            let why = incompatibility(below).expect("a level below the baseline");
            assert!(why.contains("development build"), "{why}");
            assert!(why.contains(&format!("at {below}")), "{why}");
        }
    }
}
