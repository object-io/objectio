#!/usr/bin/env bash
# Build a previous release's service binaries, for the rolling-upgrade test.
#
#   scripts/upgrade-test/previous-release.sh [tag]     # default: the latest tag before HEAD
#
# The tag must be a release with format levels (the upgrade-ready release
# or later).
#
# Prints the directory holding the binaries; point the test at it:
#
#   OBJECTIO_PREVIOUS_RELEASE_BIN=$(scripts/upgrade-test/previous-release.sh) \
#     cargo test -p objectio-e2e --test rolling_upgrade
#
# The release is checked out in a git worktree and built with its own target
# directory under target/previous/<tag>, so it never touches the current
# build. A second run reuses both.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
tag=${1:-$(git -C "$root" describe --tags --abbrev=0 HEAD)}
base="$root/target/previous/$tag"
src="$base/src"
bins="$base/target/debug"

# Only releases with format levels can be rolled from: nothing carries
# over from the ones before (objectio-docs core/upgrade-path.md).
# (crates/common since the layout change; crates/objectio-common before.)
if ! git -C "$root" cat-file -e "$tag:crates/common/src/version.rs" 2>/dev/null &&
   ! git -C "$root" cat-file -e "$tag:crates/objectio-common/src/version.rs" 2>/dev/null; then
    echo "$tag has no format levels; the first release with them is the earliest" \
         "a rolling upgrade starts from" >&2
    exit 1
fi

# Reuse the checkout only if it really is the tag: a directory left behind
# (a CI cache restores parts of target/) would otherwise build whatever
# Cargo.toml it finds above it, i.e. the current tree.
want=$(git -C "$root" rev-parse "$tag^{commit}")
if [ "$(git -C "$src" rev-parse HEAD 2>/dev/null)" != "$want" ] ||
   [ "$(git -C "$src" rev-parse --show-toplevel 2>/dev/null)" != "$(cd "$src" 2>/dev/null && pwd -P)" ]; then
    rm -rf "$src"
    git -C "$root" worktree prune
    mkdir -p "$base"
    git -C "$root" worktree add --detach "$src" "$tag" >&2
fi
(
    cd "$src"
    cargo build -q --target-dir "$base/target" \
        --bin objectio-meta --bin objectio-osd --bin objectio-gateway >&2
)
for b in objectio-meta objectio-osd objectio-gateway; do
    [ -x "$bins/$b" ] || { echo "missing $bins/$b" >&2; exit 1; }
    got=$("$bins/$b" --version)
    [ "$got" = "$b ${tag#v}" ] || { echo "$bins/$b is '$got', not $tag" >&2; exit 1; }
done
echo "$bins"
