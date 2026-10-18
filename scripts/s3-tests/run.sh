#!/usr/bin/env bash
# Run ceph's s3-tests against a fresh objectio-aio, and write a report.
#
#   scripts/s3-tests/run.sh [options] [-- extra pytest args]
#
#   --work DIR       where s3-tests, its venv, the cluster and the results go
#                    (default: target/s3-tests)
#   --port N         S3 port for the aio (default: 19900)
#   --jobs N         pytest workers (default: 4)
#   --s3tests REF    s3-tests commit to test against (default: the pinned one)
#   --acl-shim       turn canned bucket ACLs into equivalent bucket policies
#                    (ObjectIO is BucketOwnerEnforced); off by default so runs
#                    compare
#   --no-build       use target/debug/objectio-aio as it is
#   --previous CSV   an earlier results.csv: the summary lists what changed
#
# Any arguments after `--` go to pytest, e.g. `-- -k test_object_` for a subset.
#
# Results land in <work>/report/: results.csv (one row per test), summary.md,
# junit.xml. To publish a run, copy that folder to objectio-docs under
# developer-guide/s3-compatibility/<date>/<platform>/. Failures are labelled from
# known-failures.csv next to this script; add new ones there.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$REPO/scripts/s3-tests"
WORK="$REPO/target/s3-tests"
PORT=19900
JOBS=4
S3TESTS_REF=5522d1c   # ceph/s3-tests main, 2026-10-02
ACL_SHIM=0
BUILD=1
PREVIOUS=""
PYTEST_EXTRA=()

while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --s3tests) S3TESTS_REF="$2"; shift 2 ;;
    --acl-shim) ACL_SHIM=1; shift ;;
    --no-build) BUILD=0; shift ;;
    --previous) PREVIOUS="$2"; shift 2 ;;
    --) shift; PYTEST_EXTRA=("$@"); break ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
DATA="$WORK/data"
REPORT="$WORK/report"

# s3-tests, pinned, and its own venv (never the system Python).
if [ ! -d "$WORK/s3-tests/.git" ]; then
  git clone -q https://github.com/ceph/s3-tests "$WORK/s3-tests"
fi
git -C "$WORK/s3-tests" fetch -q origin
git -C "$WORK/s3-tests" checkout -q "$S3TESTS_REF"
if [ ! -x "$WORK/venv/bin/python" ]; then
  python3 -m venv "$WORK/venv"
fi
PY="$WORK/venv/bin/python"
"$PY" -m pip install -q --upgrade pip
"$PY" -m pip install -q -r "$WORK/s3-tests/requirements.txt" pytest-xdist pytest-timeout
"$PY" -m pip install -q -e "$WORK/s3-tests"

if [ "$BUILD" = 1 ]; then
  (cd "$REPO" && cargo build --bin objectio-aio)
fi

# A fresh cluster every run: leftovers from an earlier run change results.
rm -rf "$DATA"
"$REPO/target/debug/objectio-aio" \
  --data "$DATA" --port "$PORT" --listen-addr 127.0.0.1 \
  --osds 6 --ec-k 4 --ec-m 2 --auth \
  --lifecycle-interval-secs 2 --lifecycle-day-secs 10 \
  --bucket-log-roll-secs 3 \
  > "$WORK/aio.log" 2>&1 &
AIO=$!
trap 'kill $AIO 2>/dev/null || true; wait $AIO 2>/dev/null || true' EXIT

echo "waiting for the cluster on :$PORT ..."
for _ in $(seq 1 120); do
  if [ -f "$DATA/meta/admin-creds.env" ] &&
     curl -s -o /dev/null "http://127.0.0.1:$PORT/"; then
    break
  fi
  kill -0 "$AIO" 2>/dev/null || { echo "aio exited; see $WORK/aio.log" >&2; exit 1; }
  sleep 1
done
[ -f "$DATA/meta/admin-creds.env" ] || { echo "cluster never came up; see $WORK/aio.log" >&2; exit 1; }

"$PY" "$HERE/setup_users.py" "http://127.0.0.1:$PORT" "$DATA/meta/admin-creds.env" "$WORK/users.json"
"$PY" "$HERE/make_conf.py" "$WORK/users.json" 127.0.0.1 "$PORT" "$WORK/s3tests.conf"

PLUGIN=()
if [ "$ACL_SHIM" = 1 ]; then
  export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"
  PLUGIN=(-p acl_shim)
fi

mkdir -p "$REPORT"
echo "running s3-tests (this takes about an hour) ..."
set +e
# TZ=UTC: the logging tests compare a log object's name (UTC, as in S3) with
# the local clock.
(cd "$WORK/s3-tests" && TZ=UTC S3TEST_CONF="$WORK/s3tests.conf" "$PY" -m pytest s3tests/functional \
  -n "$JOBS" --timeout 120 -p no:cacheprovider -q -rN \
  ${PLUGIN[@]+"${PLUGIN[@]}"} --junitxml="$REPORT/junit.xml" \
  ${PYTEST_EXTRA[@]+"${PYTEST_EXTRA[@]}"}) > "$WORK/pytest.log" 2>&1
set -e
tail -1 "$WORK/pytest.log"

"$PY" "$HERE/report.py" "$REPORT/junit.xml" "$REPORT" \
  --date "$(date -u +%Y-%m-%d)" \
  --commit "$(git -C "$REPO" rev-parse --short HEAD)" \
  --s3tests-commit "$(git -C "$WORK/s3-tests" rev-parse --short HEAD)" \
  --platform "$(uname -s) $(uname -m)" \
  ${PREVIOUS:+--previous "$PREVIOUS"}
echo "report: $REPORT/summary.md"
