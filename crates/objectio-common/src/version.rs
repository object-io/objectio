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

/// This binary's format level. Level 0 is every release before levels
/// existed (v0.4.0 and earlier); level 1 is the first that reports one.
pub const FORMAT_LEVEL: u32 = 1;

/// The lowest active level this binary can run in: it reads every format
/// from this level up.
pub const MIN_LEVEL: u32 = 0;

/// The release, as tagged (`v` + the workspace version).
pub const RELEASE: &str = env!("CARGO_PKG_VERSION");

/// Meta config key holding the cluster's active level (decimal text).
/// Absent means 0: a cluster from before levels existed.
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

/// Why this binary can't run in a cluster at `active`, if it can't.
// `MIN_LEVEL` is 0 today, so its check can't fire yet; it rises when a
// release drops the readers for a level's formats.
#[allow(clippy::absurd_extreme_comparisons)]
#[must_use]
pub fn incompatibility(active: u32) -> Option<String> {
    if FORMAT_LEVEL < active {
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
/// none (every release before levels existed).
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
    fn a_client_from_before_levels_is_level_0() {
        assert_eq!(level_of_user_agent("tonic/0.12.3"), 0);
        assert_eq!(level_of_user_agent(""), 0);
        assert_eq!(level_of_user_agent("objectio-level/x"), 0);
    }

    #[test]
    fn compatibility_follows_the_levels() {
        assert!(incompatibility(FORMAT_LEVEL).is_none());
        assert!(incompatibility(MIN_LEVEL).is_none());
        assert!(incompatibility(FORMAT_LEVEL + 1).is_some());
    }
}
