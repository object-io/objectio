#!/usr/bin/env bash
# A multi-host cluster of Incus VMs on one lab host, for the chaos test
# (roadmap A6; deploy/chaos/README.md).
#
#   deploy/chaos/cluster.sh up <bin-dir>   # create the VMs, install, start
#   deploy/chaos/cluster.sh status
#   deploy/chaos/cluster.sh down           # delete the VMs and their disks
#
# <bin-dir> holds Linux x86_64 objectio-meta, objectio-osd and
# objectio-gateway. Six VMs, chaos-1 .. chaos-6: each runs one OSD on its
# own block device (an Incus volume, so it can be pulled), chaos-1..3 run
# meta (one Raft group), chaos-1..2 run a gateway. Needs incus (through
# sudo -n) and an Ubuntu 24.04 VM image (IMAGE).
set -euo pipefail

N=${CHAOS_VMS:-6}
METAS=3
GATEWAYS=2
IMAGE=${IMAGE:-images:ubuntu/24.04}
POOL=${POOL:-default}
DISK_SIZE=${DISK_SIZE:-16GiB}
MASTER_KEY=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
incus() { sudo -n incus "$@"; }
say() { echo "▶ $(date +%T) $*" >&2; }

ip_of() {
    incus list "$1" --format json | python3 -c '
import json, sys
for i in json.load(sys.stdin):
    for n in (i.get("state") or {}).get("network", {}).values():
        for a in n.get("addresses", []):
            if a["family"] == "inet" and a["scope"] == "global":
                print(a["address"]); sys.exit()'
}

await_agent() {
    for _ in $(seq 1 120); do
        incus exec "$1" -- true 2>/dev/null && [ -n "$(ip_of "$1")" ] && return
        sleep 2
    done
    echo "$1 never came up" >&2; exit 1
}

# The OSD's disk inside VM $1: the Incus volume, by its stable id.
osd_disk() {
    incus exec "$1" -- sh -c 'ls /dev/disk/by-id/ | grep -m1 "incus_osd$" | sed "s|^|/dev/disk/by-id/|"'
}

unit() { # vm name exec-line
    incus exec "$1" -- sh -c "cat > /etc/systemd/system/$2.service" <<EOF
[Unit]
Description=$2
After=network-online.target
[Service]
Environment=OBJECTIO_MASTER_KEY=$MASTER_KEY
ExecStart=$3
Restart=always
RestartSec=2
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
    incus exec "$1" -- sh -c "systemctl daemon-reload && systemctl enable --now $2" >/dev/null 2>&1
}

admin() { # ip path json
    curl -sf -m 10 -X POST -H 'content-type: application/json' -d "$3" "http://$1:9102$2"
}

up() {
    local bins=$1
    for b in objectio-meta objectio-osd objectio-gateway; do
        [ -x "$bins/$b" ] || { echo "missing $bins/$b" >&2; exit 1; }
    done
    for i in $(seq 1 "$N"); do
        local vm=chaos-$i
        if ! incus info "$vm" >/dev/null 2>&1; then
            say "creating $vm"
            incus init "$IMAGE" "$vm" --vm -c limits.cpu=2 -c limits.memory=3GiB \
                -d root,size=12GiB >/dev/null
            incus storage volume create "$POOL" "$vm-osd" --type=block size="$DISK_SIZE" >/dev/null
            incus config device add "$vm" osd disk pool="$POOL" source="$vm-osd" >/dev/null
            incus start "$vm"
        fi
    done
    for i in $(seq 1 "$N"); do await_agent "chaos-$i"; done
    # A gateway refuses writes while its clock is more than 500 ms from
    # meta's: start only once every VM's clock is synchronised.
    for i in $(seq 1 "$N"); do
        local tries=0
        until [ "$(incus exec "chaos-$i" -- timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ]; do
            tries=$((tries + 1))
            [ "$tries" -gt 60 ] && { say "chaos-$i: clock not synchronised after 120 s; going on"; break; }
            sleep 2
        done
    done

    # Logs for a whole soak: the default journal keeps about five hours of
    # a busy node, and soak run 9 needed ones from before that.
    for i in $(seq 1 "$N"); do
        incus exec "chaos-$i" -- sh -c 'mkdir -p /etc/systemd/journald.conf.d && printf "[Journal]\nSystemMaxUse=3G\n" > /etc/systemd/journald.conf.d/objectio.conf && systemctl restart systemd-journald'
    done

    declare -A IP
    for i in $(seq 1 "$N"); do IP[$i]=$(ip_of "chaos-$i"); done
    local metas="" i
    for i in $(seq 1 "$METAS"); do metas+="${metas:+,}http://${IP[$i]}:9100"; done

    for i in $(seq 1 "$N"); do
        local vm=chaos-$i
        say "installing $vm (${IP[$i]})"
        for b in objectio-meta objectio-osd objectio-gateway; do
            incus file push "$bins/$b" "$vm/usr/local/bin/$b" --mode 0755
        done
        incus exec "$vm" -- mkdir -p /var/lib/objectio/meta /var/lib/objectio/osd
    done

    for i in $(seq 1 "$METAS"); do
        unit "chaos-$i" objectio-meta "/usr/local/bin/objectio-meta --node-id $i \
--listen 0.0.0.0:9100 --raft-advertise ${IP[$i]}:9100 --data-dir /var/lib/objectio/meta \
--metrics-port 9101 --admin-port 9102 --ec-k 4 --ec-m 2 --repair-interval-secs 60"
    done
    for _ in $(seq 1 60); do curl -sf -m 2 "http://${IP[1]}:9102/status" >/dev/null && break; sleep 1; done
    if ! curl -sf "http://${IP[1]}:9102/status" | grep -q '"voters":\[1,2,3\]'; then
        say "forming the Raft group"
        admin "${IP[1]}" /init '{}' >/dev/null || true
        for _ in $(seq 1 30); do
            curl -sf "http://${IP[1]}:9102/status" | grep -q '"state":"Leader"' && break; sleep 1
        done
        for i in $(seq 2 "$METAS"); do
            admin "${IP[1]}" /add-learner "{\"node_id\":$i,\"addr\":\"${IP[$i]}:9100\"}" >/dev/null
        done
        admin "${IP[1]}" /change-membership '{"voters":[1,2,3]}' >/dev/null
    fi

    for i in $(seq 1 "$N"); do
        local disk; disk=$(osd_disk "chaos-$i")
        unit "chaos-$i" objectio-osd "/usr/local/bin/objectio-osd --listen 0.0.0.0:9200 \
--advertise-addr http://${IP[$i]}:9200 --meta-endpoint $metas \
--data-dir /var/lib/objectio/osd --disks $disk --init-blank-disks --metrics-port 9201"
    done
    for i in $(seq 1 "$GATEWAYS"); do
        unit "chaos-$i" objectio-gateway "/usr/local/bin/objectio-gateway --listen 0.0.0.0:9000 \
--meta-endpoint $metas --external-endpoint http://${IP[$i]}:9000 --no-auth"
    done
    for i in $(seq 1 "$GATEWAYS"); do
        for _ in $(seq 1 60); do curl -sf -m 2 "http://${IP[$i]}:9000/health" >/dev/null && break; sleep 1; done
    done
    status
}

status() {
    for i in $(seq 1 "$N"); do
        local vm=chaos-$i ip; ip=$(ip_of "$vm" || true)
        printf '%s %s ' "$vm" "${ip:--}"
        incus exec "$vm" -- sh -c 'for s in objectio-meta objectio-osd objectio-gateway; do
            [ -f /etc/systemd/system/$s.service ] && printf "%s=%s " "${s#objectio-}" "$(systemctl is-active $s)"; done; echo' 2>/dev/null || echo "(down)"
    done
}

down() {
    for i in $(seq 1 "$N") 7 8; do
        incus delete --force "chaos-$i" >/dev/null 2>&1 || true
        for v in $(incus storage volume list "$POOL" --format csv -c n 2>/dev/null | grep "^chaos-$i-"); do
            incus storage volume delete "$POOL" "$v" >/dev/null 2>&1 || true
        done
    done
    say "deleted"
}

case "${1:-}" in
    up) up "${2:?bin dir}" ;;
    status) status ;;
    down) down ;;
    *) sed -n '2,15p' "$0"; exit 1 ;;
esac
