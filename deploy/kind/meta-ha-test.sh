#!/usr/bin/env bash
# Meta HA on Kubernetes (roadmap A5): with S3 traffic running, kill the
# meta leader's pod, then a follower's, then roll the whole StatefulSet;
# every write the gateway acknowledged must read back intact, writes must
# resume within MAX_GAP seconds of each kill, and a write that fails
# meanwhile must fail with 503 (retry), never 500.
#
#   make kind-up                      # the chart, 3 metas, on kind
#   deploy/kind/meta-ha-test.sh
#
# The traffic runs in a pod (deploy/kind/meta_ha_load.py), so nothing
# depends on a port-forward surviving the kills.
#
#   NAMESPACE  where the chart is installed (default: objectio)
#   MAX_GAP    longest allowed stretch without a successful write (default: 60)
set -euo pipefail

NS=${NAMESPACE:-objectio}
MAX_GAP=${MAX_GAP:-60}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POD=meta-ha-load
k() { kubectl -n "$NS" "$@"; }
say() { echo "▶ $(date +%T) $*"; }
die() { echo "✗ $*" >&2; exit 1; }

STS=$(k get sts -l app.kubernetes.io/component=meta -o jsonpath='{.items[0].metadata.name}')
HEADLESS=$(k get sts "$STS" -o jsonpath='{.spec.serviceName}')
REPLICAS=$(k get sts "$STS" -o jsonpath='{.spec.replicas}')
GW_SVC=$(k get svc -l app.kubernetes.io/component=gateway -o jsonpath='{.items[0].metadata.name}')
GW_PORT=$(k get svc "$GW_SVC" -o jsonpath='{.spec.ports[0].port}')
[ "$REPLICAS" -ge 3 ] || die "meta has $REPLICAS replicas; the test needs 3 or more"
say "meta: $STS ($REPLICAS replicas), gateway: $GW_SVC:$GW_PORT"

# The traffic pod.
k delete pod "$POD" --ignore-not-found --wait >/dev/null
k create configmap "$POD" --from-file="$HERE/meta_ha_load.py" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
k run "$POD" --image=python:3.12-slim --restart=Never --overrides='{
  "spec": {
    "containers": [{
      "name": "load",
      "image": "python:3.12-slim",
      "command": ["python3", "/load/meta_ha_load.py", "http://'"$GW_SVC:$GW_PORT"'"],
      "volumeMounts": [{"name": "load", "mountPath": "/load"}]
    }],
    "volumes": [{"name": "load", "configMap": {"name": "'"$POD"'"}}]
  }
}' >/dev/null
k wait --for=condition=Ready "pod/$POD" --timeout=300s >/dev/null

# Each meta's Raft status, as "index self_id leader_id last_applied voters"
# (unreachable ones left out), asked from inside the cluster.
statuses() {
    k exec "$POD" -- python3 -c '
import json, sys, urllib.request
sts, headless, ns, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
for i in range(n):
    try:
        url = f"http://{sts}-{i}.{headless}.{ns}.svc.cluster.local:9102/status"
        s = json.load(urllib.request.urlopen(url, timeout=3))
        print(i, s["self_id"], s["leader_id"], s["last_applied"] or 0, len(s["voters"]), s["current_term"])
    except Exception:
        pass
' "$STS" "$HEADLESS" "$NS" "$REPLICAS" 2>/dev/null || true
}

# The pod index of the leader every reachable meta agrees on, or nothing.
leader_index() {
    statuses | awk -v n="$REPLICAS" '
        { id[$1] = $2; lead[$1] = $3; seen++ }
        END {
            l = ""; for (i in lead) { if (l == "") l = lead[i]; else if (lead[i] != l) exit }
            if (l == "" || l == "None") exit
            for (i in id) if (id[i] == l) print i
        }'
}

# Every meta reachable, one leader, all voters, caught up to within 100.
await_healthy() {
    local what=$1 deadline=$((SECONDS + 300))
    while [ $SECONDS -lt $deadline ]; do
        if statuses | awk -v n="$REPLICAS" '
            { seen++; lead[$3]++; if ($4 > max) max = $4; if (min == "" || $4 < min) min = $4; if ($5 != n) bad = 1 }
            END { if (seen != n || length(lead) != 1 || bad || max - min > 100) exit 1 }'
        then
            say "healthy: $what"
            return
        fi
        sleep 2
    done
    statuses >&2
    die "meta never became healthy: $what"
}

acked() { k logs "$POD" --tail=1 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("acked", 0))' 2>/dev/null || echo 0; }

await_healthy "before"
while [ "$(acked)" -lt 200 ]; do sleep 2; done
say "traffic running: $(acked) objects acknowledged"

# The term every reachable meta is in, if they agree on a leader.
leader_term() {
    [ -n "$(leader_index)" ] && statuses | awk '{print $6}' | sort -n | tail -1
}

kill_meta() {
    local i=$1 what=$2 old_leader old_term
    old_leader=$(leader_index)
    old_term=$(leader_term)
    say "killing $STS-$i ($what)"
    local t0=$SECONDS
    k delete pod "$STS-$i" --grace-period=0 --force >/dev/null 2>&1
    if [ "$i" = "$old_leader" ]; then
        # A new leader is a higher term, whichever pod wins it: the killed
        # one, back on a new IP within seconds, may.
        local deadline=$((SECONDS + 60)) l="" t=""
        while [ $SECONDS -lt $deadline ]; do
            l=$(leader_index)
            t=$(leader_term)
            [ -n "$l" ] && [ -n "$t" ] && [ "$t" -gt "$old_term" ] && break
            sleep 1
        done
        [ -n "$l" ] && [ -n "$t" ] && [ "$t" -gt "$old_term" ] ||
            die "no new leader within 60s of killing the leader"
        say "new leader $STS-$l (term $t) after $((SECONDS - t0))s"
    fi
    await_healthy "$STS-$i back after $what"
    sleep 15
}

L=$(leader_index); [ -n "$L" ] || die "no leader"
kill_meta "$L" "the leader"
L=$(leader_index)
F=$(( (L + 1) % REPLICAS ))
kill_meta "$F" "a follower"

say "rolling restart of $STS"
k rollout restart "sts/$STS" >/dev/null
k rollout status "sts/$STS" --timeout=600s >/dev/null
await_healthy "after the rolling restart"
sleep 15

say "stopping traffic; reading every acknowledged object back"
k exec "$POD" -- touch /tmp/stop
k wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$POD" --timeout=900s >/dev/null 2>&1 || true
summary=$(k logs "$POD" | grep '"summary"' | tail -1)
echo "$summary"
code=$(k get pod "$POD" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}')
gap=$(echo "$summary" | python3 -c 'import json,sys; print(json.load(sys.stdin)["longest_gap_s"])')
[ "$code" = 0 ] || die "acknowledged objects missing or different"
# A failed write during a failover must say "retry" (503), never 500.
bad=$(echo "$summary" | python3 -c 'import json,sys; e=json.load(sys.stdin)["write_errors"]; print(" ".join(f"{k}:{v}" for k,v in e.items() if k not in ("503", "None")))')
[ -z "$bad" ] || die "writes failed with other than 503: $bad"
python3 -c "import sys; sys.exit(0 if $gap <= $MAX_GAP else 1)" ||
    die "writes stopped for ${gap}s (allowed: ${MAX_GAP}s)"
k delete pod "$POD" --wait=false >/dev/null
echo "✓ meta HA: every acknowledged write intact; longest gap ${gap}s"
