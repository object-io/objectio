"""Chaos test for a multi-host cluster (roadmap A6; deploy/chaos/README.md).

    python3 deploy/chaos/chaos.py            # on the lab host, after cluster.sh up

S3 traffic runs through both gateways for the whole test while faults
are injected one at a time, each held, healed and left to settle:

  meta-kill       SIGKILL the meta leader's process (systemd restarts it)
  power-off       an OSD-only VM switched off for a minute, then on
  meta-power-off  a meta VM switched off for a minute, then on
  partition       the meta leader's VM cut off the network for a minute
                  (its interface taken down)
  disk-pull       an OSD's disk unplugged; the OSD set out; a new disk
                  plugged in; the OSD back on it and set in (repair
                  rebuilds what the old disk held)

Invariants, checked after every fault and at the end:
  - every write a gateway acknowledged reads back byte for byte;
  - writes resume: no stretch longer than MAX_GAP without one succeeding;
  - a write that fails says retry (503) or never reached a gateway:
    never 500;
  - redundancy is restored: with the cluster healed and repair run, any
    two OSDs can be stopped and every object still reads back.

Standard library only; the gateways run with --no-auth. Exits 1 on the
first broken invariant, with what broke.
"""

import datetime
import hashlib
import hmac
import json
import os
import random
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VMS = [f"chaos-{i}" for i in range(1, 7)]
METAS = VMS[:3]
GATEWAYS = VMS[:2]
BUCKET = "chaos"
WRITERS = 6
MAX_GAP = float(os.environ.get("MAX_GAP", "60"))
HOLD = int(os.environ.get("HOLD", "60"))
REPAIR_WAIT = int(os.environ.get("REPAIR_WAIT", "900"))
DISK_SIZE = os.environ.get("DISK_SIZE", "16GiB")  # as cluster.sh


def say(msg):
    print(f"▶ {time.strftime('%T')} {msg}", flush=True)


def fail(msg):
    print(f"✗ {msg}", flush=True)
    sys.exit(1)


def incus(*args, check=True):
    r = subprocess.run(["sudo", "-n", "incus", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        fail(f"incus {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def vm_exec(vm, cmd, check=True):
    return incus("exec", vm, "--", "sh", "-c", cmd, check=check)


def ips():
    out = {}
    for i in json.loads(incus("list", "chaos-", "--format", "json")):
        for n in (i.get("state") or {}).get("network", {}).values():
            for a in n.get("addresses", []):
                if a["family"] == "inet" and a["scope"] == "global":
                    out[i["name"]] = a["address"]
    return out


IP = ips()
GW = [f"http://{IP[g]}:9000" for g in GATEWAYS]


def http(method, url, body=None, timeout=5, headers=None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # refused, reset, timed out: never reached a gateway
        return None, str(e).encode()


def admin_creds():
    env = vm_exec(METAS[0], "cat /var/lib/objectio/meta/admin-creds.env")
    kv = dict(line.split("=", 1) for line in env.replace("export ", "").split("\n") if "=" in line)
    return kv["AWS_ACCESS_KEY_ID"], kv["AWS_SECRET_ACCESS_KEY"]


AK, SK = admin_creds()


def sigv4(method, url, body):
    """Headers signing a request as the system admin (the admin API wants
    SigV4 even with --no-auth)."""
    u = urllib.parse.urlsplit(url)
    now = datetime.datetime.now(datetime.timezone.utc)
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    payload = hashlib.sha256(body or b"").hexdigest()
    headers = {"host": u.netloc, "x-amz-content-sha256": payload, "x-amz-date": amz}
    signed = ";".join(sorted(headers))
    query = "&".join(sorted(u.query.split("&"))) if u.query else ""
    canonical = "\n".join([method, urllib.parse.quote(u.path), query,
                           "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)),
                           signed, payload])
    scope = f"{day}/us-east-1/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope,
                         hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + SK).encode()
    for part in (day, "us-east-1", "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (f"AWS4-HMAC-SHA256 Credential={AK}/{scope}, "
                                f"SignedHeaders={signed}, Signature={sig}")
    del headers["host"]
    return headers


def admin(method, path, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    for url in GW:
        headers = sigv4(method, url + path, body)
        if body is not None:
            headers["content-type"] = "application/json"
        status, data = http(method, url + path, body, 10, headers)
        if status is not None:
            return status, data
    return None, b"no gateway answered"


# --- traffic ---------------------------------------------------------------

acked = {}  # key -> sha256
lock = threading.Lock()
stop = threading.Event()
last_ok = [time.monotonic()]
gap = [0.0]  # longest gap in the current phase
errors = {}  # status -> count, current phase
samples = {}


def body_for(key):
    seed = hashlib.sha256(key.encode()).digest()
    size = 2_000 + int.from_bytes(seed[:2], "big") * 4  # 2 KB .. ~260 KB
    return (seed * (size // 32 + 1))[:size]


def writer(n):
    i = 0
    while not stop.is_set():
        key = f"w{n}/k{i}"
        body = body_for(key)
        status, reply = http("PUT", f"{GW[i % len(GW)]}/{BUCKET}/{key}", body)
        now = time.monotonic()
        with lock:
            if status == 200:
                acked[key] = hashlib.sha256(body).hexdigest()
                gap[0] = max(gap[0], now - last_ok[0])
                last_ok[0] = now
            else:
                errors[str(status)] = errors.get(str(status), 0) + 1
                s = samples.setdefault(str(status), [])
                if len(s) < 2:
                    s.append(reply[:200].decode(errors="replace"))
        if status != 200:
            time.sleep(0.2)
        i += 1


def phase_report(name):
    with lock:
        g = max(gap[0], time.monotonic() - last_ok[0])
        report = {"phase": name, "acked": len(acked), "longest_gap_s": round(g, 1),
                  "errors": dict(errors), "samples": dict(samples)}
        gap[0] = 0.0
        errors.clear()
        samples.clear()
    print(json.dumps(report), flush=True)
    bad = {k: v for k, v in report["errors"].items() if k not in ("503", "None")}
    if bad:
        fail(f"{name}: writes failed with other than 503: {bad} {report['samples']}")
    if g > MAX_GAP:
        fail(f"{name}: writes stopped for {g:.0f}s (allowed {MAX_GAP:.0f}s)")


def read_one(n, key, digest, attempts=20):
    """One acknowledged object, read back through either gateway: None if
    intact, else what went wrong."""
    for a in range(attempts):
        status, data = http("GET", f"{GW[(n + a) % len(GW)]}/{BUCKET}/{key}", timeout=10)
        if status == 200 or status not in (None, 503):
            break
        time.sleep(1)
    if status != 200:
        return (key, status)
    if hashlib.sha256(data).hexdigest() != digest:
        return (key, "different")
    return None


checked = set()  # keys read back by an earlier check


def read_all(what, everything=False):
    """Acknowledged objects read back intact, through either gateway (32 at
    a time): every one written since the last check and a random 2,000 of
    the older ones, or with `everything`, all of them."""
    from concurrent.futures import ThreadPoolExecutor
    with lock:
        items = list(acked.items())
    if not everything:
        new = [i for i in items if i[0] not in checked]
        old = [i for i in items if i[0] in checked]
        items = new + random.sample(old, min(len(old), 2000))
    with ThreadPoolExecutor(max_workers=32) as pool:
        bad = [r for r in pool.map(lambda a: read_one(a[0], *a[1]), enumerate(items)) if r]
    if bad:
        fail(f"{what}: {len(bad)} of {len(items)} acknowledged objects unreadable: {bad[:10]}")
    checked.update(k for k, _ in items)
    say(f"{what}: {len(items)} acknowledged objects read back" + (" (all)" if everything else ""))


# --- cluster state -------------------------------------------------------

def meta_status(vm):
    status, data = http("GET", f"http://{IP[vm]}:9102/status", timeout=3)
    return json.loads(data) if status == 200 else None


def leader_vm(timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        seen = {vm: meta_status(vm) for vm in METAS}
        leaders = {s["leader_id"] for s in seen.values() if s}
        if len(leaders) == 1 and None not in leaders:
            lid = leaders.pop()
            for vm, s in seen.items():
                if s and s["self_id"] == lid:
                    return vm
        time.sleep(1)
    fail("no leader every meta agrees on")


# How long every meta may take to be back in step after a fault. A meta
# node reopening its database after a power cut walks all of it (roadmap
# B25), minutes on these VMs: the soak sets this higher and logs the time.
META_RECOVERY = float(os.environ.get("META_RECOVERY_SECS", "300"))


def await_metas_healthy(timeout=None):
    started = time.monotonic()
    deadline = started + (timeout or META_RECOVERY)
    while time.monotonic() < deadline:
        seen = [meta_status(vm) for vm in METAS]
        if all(seen) and len({s["leader_id"] for s in seen}) == 1 and all(
                len(s["voters"]) == 3 for s in seen):
            applied = [s["last_applied"] or 0 for s in seen]
            if max(applied) - min(applied) < 100:
                took = time.monotonic() - started
                if took > 30:
                    say(f"meta back in step after {took:.0f} s")
                return
        time.sleep(2)
    fail(f"meta never became healthy (waited {timeout or META_RECOVERY:.0f} s)")


def nodes():
    status, data = admin("GET", "/_admin/nodes")
    if status != 200:
        fail(f"/_admin/nodes: {status} {data[:200]}")
    v = json.loads(data)
    return v["nodes"] if isinstance(v, dict) else v


def osd_of(vm):
    for n in nodes():
        if f"//{IP[vm]}:" in n.get("address", ""):
            return n
    return None


def await_osds_online(count, timeout=300):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        up = [n for n in nodes() if n.get("online") and n.get("admin_state", "in") == "in"]
        if len(up) >= count:
            return
        time.sleep(3)
    fail(f"fewer than {count} OSDs online and in")


def settle(name):
    await_metas_healthy()
    await_osds_online(6)
    time.sleep(15)
    phase_report(name)


# --- faults ----------------------------------------------------------------

def meta_kill():
    vm = leader_vm()
    say(f"meta-kill: SIGKILL objectio-meta on {vm} (the leader)")
    vm_exec(vm, "kill -9 $(systemctl show -p MainPID --value objectio-meta)")
    new = leader_vm()
    say(f"meta-kill: leader now {new}")
    settle("meta-kill")


def power_off(vm, name):
    say(f"{name}: switching {vm} off for {HOLD}s")
    incus("stop", "--force", vm)
    time.sleep(HOLD)
    incus("start", vm)
    deadline = time.monotonic() + 300
    while subprocess.run(["sudo", "-n", "incus", "exec", vm, "--", "true"],
                         capture_output=True).returncode != 0:
        if time.monotonic() > deadline:
            fail(f"{vm} never came back")
        time.sleep(2)
    settle(name)


def partition():
    vm = leader_vm()
    say(f"partition: cutting {vm} (the leader) off the network for {HOLD}s")
    # The VM's interface down: no packets either way. (The image has no
    # iptables; incus exec goes over vsock, not the network, so we can
    # still bring it back.)
    vm_exec(vm, "ip link set enp5s0 down")
    time.sleep(HOLD)
    vm_exec(vm, "ip link set enp5s0 up")
    say("partition: healed")
    settle("partition")


def disk_pull(vm="chaos-5", new=None):
    """`new`: the Incus volume to plug in (default `<vm>-osd2`)."""
    new = new or f"{vm}-osd2"
    old = osd_of(vm)
    if not old:
        fail(f"no OSD found on {vm}")
    say(f"disk-pull: unplugging {vm}'s disk (OSD {old['node_id']})")
    incus("config", "device", "remove", vm, "osd")
    time.sleep(HOLD)
    say(f"disk-pull: setting OSD {old['node_id']} out; plugging in a new disk")
    status, data = admin("PUT", f"/_admin/osds/{old['node_id']}/admin-state", {"state": "out"})
    if status != 200:
        fail(f"set out: {status} {data[:200]}")
    incus("storage", "volume", "create", "default", new, "--type=block", f"size={DISK_SIZE}")
    incus("config", "device", "add", vm, "osd", "disk", "pool=default", f"source={new}")
    vm_exec(vm, "sleep 3; systemctl restart objectio-osd")
    # The documented replacement: the OSD comes back on the new disk under
    # its identity (its metadata lives in its state directory; the shards
    # the old disk held are dropped), still out until the operator sets it
    # in; then repair rebuilds what it held, in place.
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        back = osd_of(vm)
        if back and back["node_id"] == old["node_id"] and back.get("online"):
            break
        time.sleep(3)
    else:
        fail(f"{vm}'s OSD never came back on the new disk")
    status, data = admin("PUT", f"/_admin/osds/{old['node_id']}/admin-state", {"state": "in"})
    if status != 200:
        fail(f"set in: {status} {data[:200]}")
    say(f"disk-pull: OSD {old['node_id']} back on the new disk, set in")
    settle("disk-pull")


def repair_counters():
    """Meta's repair counters, as a gateway exports them: passes, and
    shards rebuilt or moved."""
    status, body = http("GET", f"{GW[0]}/metrics", timeout=10)
    if status != 200:
        return None
    passes = work = 0
    for line in body.decode(errors="replace").splitlines():
        name = line.split("{")[0].split(" ")[0]
        if name == "objectio_meta_repair_passes_total":
            passes += int(float(line.rsplit(" ", 1)[1]))
        elif name in ("objectio_meta_repair_shards_rebuilt_total",
                      "objectio_meta_repair_shards_moved_total"):
            work += int(float(line.rsplit(" ", 1)[1]))
    return passes, work


def await_repair_quiet(deadline):
    """Wait for a whole repair pass that rebuilt and moved nothing. Stopping
    OSDs while repair still works would only slow it: a shard can't be
    rebuilt from stopped OSDs."""
    start = None
    while time.monotonic() < deadline:
        now = repair_counters()
        if now is None:
            time.sleep(10)
            continue
        if start is None or now[1] != start[1]:
            start = now  # still working: count passes from here
        elif now[0] >= start[0] + 2:
            return True  # a whole pass began and ended with nothing to do
        time.sleep(10)
    return False


def redundancy_restored(keys=None, intact=None):
    """With every node up, wait for repair (meta runs it every minute
    here) to have nothing left to do, then any two OSDs may go. `keys`
    (default: the acknowledged ones) are sampled; `intact(key, data)`
    (default: its acknowledged digest) says whether a read is right."""
    if keys is None:
        with lock:
            keys = list(acked)
    if intact is None:
        def intact(key, data):
            return hashlib.sha256(data).hexdigest() == acked[key]
    say("redundancy: running repair until two OSDs can be stopped")
    pairs = [("chaos-1", "chaos-2"), ("chaos-3", "chaos-4"), ("chaos-5", "chaos-6")]
    deadline = time.monotonic() + REPAIR_WAIT
    while True:
        if await_repair_quiet(deadline):
            say("redundancy: repair is quiet; stopping OSDs in pairs")
        else:
            say(f"redundancy: repair still working after {REPAIR_WAIT}s; stopping OSDs in pairs anyway")
        ok = True
        for a, b in pairs:
            for vm in (a, b):
                vm_exec(vm, "systemctl stop objectio-osd")
            try:
                unreadable = 0
                for key in random.sample(keys, min(len(keys), 400)):
                    status, data = http("GET", f"{GW[0]}/{BUCKET}/{key}", timeout=10)
                    if status != 200 or not intact(key, data):
                        unreadable += 1
            finally:
                for vm in (a, b):
                    vm_exec(vm, "systemctl start objectio-osd")
            await_osds_online(6)
            if unreadable:
                say(f"redundancy: {unreadable} of 400 unreadable with {a},{b} stopped")
                ok = False
                break
        if ok:
            say("redundancy: restored (any listed pair of OSDs can be stopped)")
            return
        if time.monotonic() > deadline:
            fail("redundancy never restored")
        time.sleep(60)


def main():
    say(f"cluster: {IP}")
    while http("PUT", f"{GW[0]}/{BUCKET}")[0] not in (200, 409):
        time.sleep(2)
    await_metas_healthy()
    await_osds_online(6)
    threads = [threading.Thread(target=writer, args=(n,), daemon=True) for n in range(WRITERS)]
    for t in threads:
        t.start()
    time.sleep(30)
    phase_report("warm-up")

    faults = os.environ.get("FAULTS", "meta-kill,power-off,meta-power-off,partition,disk-pull")
    for f in faults.split(","):
        if f == "meta-kill":
            meta_kill()
        elif f == "power-off":
            power_off("chaos-6", "power-off")
        elif f == "meta-power-off":
            power_off("chaos-3", "meta-power-off")
        elif f == "partition":
            partition()
        elif f == "disk-pull":
            disk_pull()
        else:
            fail(f"unknown fault {f}")
        read_all(f"after {f}")

    stop.set()
    for t in threads:
        t.join()
    phase_report("end")
    read_all("at the end", everything=True)
    redundancy_restored()
    read_all("after the redundancy check")
    print(f"✓ chaos: {len(acked)} acknowledged writes intact through every fault", flush=True)


if __name__ == "__main__":
    main()
