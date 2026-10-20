#!/usr/bin/env bash
# Run a soak (roadmap B2) on the lab host: build a commit, bring the chaos
# cluster up on it, run soak.py, and record the run.
#
#   deploy/chaos/run-soak.sh [--quick] [--harness-ref REF] <ref> [<run>]
#
# <ref>          a commit, tag or branch of origin: built and soaked
# <run>          the run's number (default: one more than the last recorded)
# --quick        the quick profile: 3 h, a fault every 5 min, on little data
#                (README); what a soak fix goes through before 48 h
# --harness-ref  cluster.sh, soak.py and chaos.py from REF, not from <ref>:
#                an older commit soaked with today's harness
#
# Any variable soak.py reads (SOAK_HOURS, FAULT_EVERY, SOAK_POOL, ...) is
# passed through; --quick only sets the ones not set. A soak already
# running is stopped first. Run it detached, it lasts as long as the soak:
#
#   nohup deploy/chaos/run-soak.sh --quick origin/main > /dev/null 2>&1 &
#
# $SOAK_HOME (/data/soak) holds:
#   repo/              a clone of origin of its own, checked out detached at
#                      each run's commit. Not a worktree of a development
#                      checkout: a branch moved under a worktree leaves its
#                      files as they were, and a run builds the old tree.
#   bin/               the binaries the cluster was last brought up with
#   runs/<n>/          build.log, cluster-up.log, soak.log, ops.log,
#                      summary.json, and harness/ when --harness-ref
#   runs.tsv           a line per run: what was soaked and how it ended
set -euo pipefail

home=${SOAK_HOME:-/data/soak}
repo=$home/repo

# This file is in the checkout it is about to move to another commit, and
# bash reads a script as it goes: run from a copy.
if [ -z "${RUN_SOAK_COPY:-}" ]; then
    copy=$(mktemp "$home/.run-soak.XXXXXX")
    cp "$0" "$copy"
    RUN_SOAK_COPY=$copy exec bash "$copy" "$@"
fi
trap 'rm -f "$RUN_SOAK_COPY"' EXIT

quick=0
harness_ref=
while [ $# -gt 0 ]; do
    case $1 in
        --quick) quick=1; shift ;;
        --harness-ref) harness_ref=$2; shift 2 ;;
        -*) echo "unknown option $1" >&2; exit 2 ;;
        *) break ;;
    esac
done
[ $# -ge 1 ] || { sed -n '5,13p' "$RUN_SOAK_COPY" >&2; exit 2; }
ref=$1
if [ "$(git -C "$repo" rev-parse --absolute-git-dir 2>/dev/null)" != "$repo/.git" ]; then
    echo "$repo is not a clone of its own (a worktree, or missing):" >&2
    echo "  git clone $(git remote get-url origin 2>/dev/null || echo '<origin>') $repo" >&2
    exit 1
fi

mkdir -p "$home/runs" "$home/bin"
last=$( { ls "$home/runs"; tail -n +2 "$home/runs.tsv" 2>/dev/null | cut -f1; } |
    grep -E '^[0-9]+$' | sort -n | tail -1 || true)
run=${2:-$(( ${last:-0} + 1 ))}
dir=$home/runs/$run
[ ! -e "$dir" ] || { echo "run $run already recorded in $dir" >&2; exit 1; }
mkdir -p "$dir"

for p in $(pgrep -f 'python3 .*soak\.py$' || true); do
    echo "stopping the soak running as pid $p"
    kill "$p"
done

commit_of() {
    git -C "$repo" rev-parse --verify -q "origin/$1^{commit}" ||
        git -C "$repo" rev-parse --verify -q "$1^{commit}" ||
        { echo "no commit $1 at origin" >&2; exit 1; }
}
git -C "$repo" fetch -q --tags --prune origin
commit=$(commit_of "$ref")
git -C "$repo" checkout -q --force --detach "$commit"
git -C "$repo" reset -q --hard "$commit"
# What is built must be what was asked for, untracked files aside.
if [ -n "$(git -C "$repo" status --porcelain --untracked-files=no)" ] ||
   [ "$(git -C "$repo" rev-parse HEAD)" != "$commit" ]; then
    echo "$repo is not at $commit after checkout:" >&2
    git -C "$repo" status -s | head >&2
    exit 1
fi
subject=$(git -C "$repo" log -1 --format=%s "$commit")

harness=$repo/deploy/chaos
harness_commit=$commit
if [ -n "$harness_ref" ]; then
    harness_commit=$(commit_of "$harness_ref")
    git -C "$repo" archive "$harness_commit" deploy/chaos | tar -x -C "$dir"
    mv "$dir/deploy/chaos" "$dir/harness" && rmdir "$dir/deploy"
    harness=$dir/harness
fi

if [ $quick = 1 ]; then
    profile=quick
    export SOAK_HOURS=${SOAK_HOURS:-3} FAULT_EVERY=${FAULT_EVERY:-5} \
        FULL_HIGH=${FULL_HIGH:-0.3} FULL_LOW=${FULL_LOW:-0.1} \
        STALL_MAX_SECS=${STALL_MAX_SECS:-900} NOT_CLEAN_MAX_SECS=${NOT_CLEAN_MAX_SECS:-3600}
else
    profile=full
fi
# Meta back in step after a fault: soak.py logs any that takes over 30 s,
# and fails a run only past this.
export META_RECOVERY_SECS=${META_RECOVERY_SECS:-1800}
export OPLOG=$dir/ops.log

started=$(date -u +%FT%TZ)
echo "$(date +%T) run $run: $profile soak of ${commit:0:8} $subject"

cd "$repo"
cargo build --release --features io-uring \
    --bin objectio-meta --bin objectio-osd --bin objectio-gateway > "$dir/build.log" 2>&1 ||
    { echo "run $run: the build failed, $dir/build.log" >&2; exit 1; }
cp target/release/objectio-meta target/release/objectio-osd target/release/objectio-gateway "$home/bin/"
"$harness/cluster.sh" down > "$dir/cluster-down.log" 2>&1
"$harness/cluster.sh" up "$home/bin" > "$dir/cluster-up.log" 2>&1

set +e
python3 "$harness/soak.py" > "$dir/soak.log" 2>&1
status=$?
set -e
ended=$(date -u +%FT%TZ)

RUN=$run REF=$ref COMMIT=$commit SUBJECT=$subject HARNESS=$harness_commit PROFILE=$profile \
STARTED=$started ENDED=$ended STATUS=$status LOG=$dir/soak.log python3 - > "$dir/summary.json" <<'EOF'
import json, os, re
lines = open(os.environ["LOG"], errors="replace").read().splitlines()
verdict = next((l for l in reversed(lines) if l[:1] in "✓✗"), "")
faults = [m.group(1) for l in lines
          if (m := re.match(r"▶ \S+ after ([a-z-]+) \(\d+\): \d+ keys read as expected", l))]
leak = next((m.group(0) for l in reversed(lines) if (m := re.search(r"\b(no )?leak: .*", l))), "")
# Each service's highest resident memory over the run, in MB (B33).
rss = {}
for l in lines:
    if l.startswith("{") and '"rss_mb"' in l:
        for svc, mbs in (json.loads(l).get("rss_mb") or {}).items():
            rss[svc] = max([rss.get(svc, 0)] + [m for m in mbs if m is not None])
e = os.environ
print(json.dumps({
    "run": int(e["RUN"]), "ref": e["REF"], "commit": e["COMMIT"], "subject": e["SUBJECT"],
    "harness": e["HARNESS"], "profile": e["PROFILE"],
    "started": e["STARTED"], "ended": e["ENDED"], "exit": int(e["STATUS"]),
    "passed": verdict.startswith("✓") and e["STATUS"] == "0",
    "faults": len(faults), "by_fault": {f: faults.count(f) for f in sorted(set(faults))},
    "leak": leak, "rss_peak_mb": rss, "verdict": verdict,
}, ensure_ascii=False, indent=1))
EOF
[ -s "$home/runs.tsv" ] ||
    printf 'run\tstarted\tended\tprofile\tcommit\tfaults\tpassed\tverdict\n' > "$home/runs.tsv"
python3 -c '
import json, sys
s = json.load(open(sys.argv[1]))
print("\t".join(str(s[k]) for k in ("run", "started", "ended", "profile")),
      s["commit"][:8], s["faults"], "yes" if s["passed"] else "no",
      s["verdict"].replace("\t", " ")[:300], sep="\t")' "$dir/summary.json" >> "$home/runs.tsv"
echo "$(date +%T) run $run: soak exited $status; $(tail -1 "$home/runs.tsv" | cut -f8)"
