"""Soak for a multi-host cluster (roadmap B2; deploy/chaos/README.md).

    python3 deploy/chaos/soak.py             # on the lab host, after cluster.sh up

Runs for SOAK_HOURS (48) on the chaos cluster: writers PUT, overwrite
and delete objects (1 KB to 8 MB) through both gateways, filling the
cluster past the OSDs' full ratio and deleting it back down, over and
over, while the chaos faults (chaos.py) are injected in turn, one every
FAULT_EVERY minutes (20).

Invariants:
  - every key holds what its last acknowledged write left: the object,
    byte for byte, or nothing after a delete (a write or delete that
    failed may or may not have taken effect: either is accepted);
    checked after each fault on a sample, and on every key at the end;
  - writes never fail with other than 503 (retry), 507 (full) or no
    answer; something is acknowledged at least every MAX_GAP seconds;
  - the bucket lists exactly the keys that exist;
  - redundancy is restored after the last fault (as chaos.py);
  - nothing leaks: once every key is deleted, the space the cluster uses
    falls back to what it used before the run, within LEAK_SLACK bytes.

Standard library only. Exits 1 on the first broken invariant. Prints a
JSON progress line every 5 minutes.
"""

import hashlib
import json
import os
import random
import subprocess
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import chaos
from chaos import GW, fail, http, incus, say

HOURS = float(os.environ.get("SOAK_HOURS", "48"))
FAULT_EVERY = float(os.environ.get("FAULT_EVERY", "20")) * 60
WRITERS = int(os.environ.get("WRITERS", "12"))
FULL_HIGH = float(os.environ.get("FULL_HIGH", "0.97"))  # past the OSDs' 0.95
FULL_LOW = float(os.environ.get("FULL_LOW", "0.5"))
LEAK_SLACK = int(os.environ.get("LEAK_SLACK", str(1 << 30)))
SAMPLE = int(os.environ.get("SAMPLE", "20000"))
GONE = "-"  # the outcome "no object"
# A bucket of its own: keys left by an earlier run would read as wrong.
BUCKET = os.environ.get("SOAK_BUCKET", f"soak-{int(time.time())}")
POOL = os.environ.get("SOAK_POOL", "")
chaos.BUCKET = BUCKET  # for chaos's redundancy check
OPLOG = open(os.environ.get("OPLOG", "soak-ops.log"), "a", buffering=1)  # noqa: SIM115


def oplog(*fields):
    OPLOG.write(" ".join([f"{time.time():.3f}", *map(str, fields)]) + "\n")

# key -> the outcomes a read may show: a digest, or GONE. One writer owns
# each key, so its operations on it never race.
expect = {}
touched = set()  # keys changed since the last check
lock = threading.Lock()
stop = threading.Event()
draining = threading.Event()
stats = {"put": 0, "overwrite": 0, "delete": 0, "failed": 0, "full": 0, "bytes": 0}
errors = {}
samples = {}
last_ok = [time.monotonic()]
gap = [0.0]


def body_for(key, gen):
    seed = hashlib.sha256(f"{key}#{gen}".encode()).digest()
    r = seed[0]
    if r < 179:  # 70%: 1-64 KB (inline, packed)
        size = 1_000 + int.from_bytes(seed[1:3], "big")
    elif r < 243:  # 25%: 64 KB-1 MB
        size = 64_000 + int.from_bytes(seed[1:4], "big") % 960_000
    else:  # 5%: 1-8 MB
        size = 1_000_000 + int.from_bytes(seed[1:4], "big") % 7_000_000
    return (seed * (size // 32 + 1))[:size]


def digest(data):
    return hashlib.sha256(data).hexdigest()[:32]


def record(status, reply, ok_statuses):
    now = time.monotonic()
    with lock:
        if status in ok_statuses:
            gap[0] = max(gap[0], now - last_ok[0])
            last_ok[0] = now
            return True
        stats["failed"] += 1
        stats["full"] += status == 507
        errors[str(status)] = errors.get(str(status), 0) + 1
        s = samples.setdefault(str(status), [])
        if len(s) < 2:
            s.append(reply[:200].decode(errors="replace"))
        return False


def writer(n):
    rng = random.Random(n)
    mine = []  # keys this writer made and has not seen deleted
    gen = {}
    i = 0
    while not stop.is_set():
        url = GW[i % len(GW)]
        i += 1
        r = rng.random()
        delete_share = 0.65 if draining.is_set() else 0.10
        if mine and r < delete_share:
            key = mine.pop(rng.randrange(len(mine)))
            with lock:  # a read from now on may see it gone
                expect[key] = expect[key] | {GONE}
            t0 = time.time()
            status, reply = http("DELETE", f"{url}/{BUCKET}/{key}", timeout=30)
            oplog(key, "DELETE", url.split("//")[1], f"{t0:.3f}", status)
            ok = record(status, reply, (204, 200))
            with lock:
                if ok:
                    expect[key] = {GONE}
                touched.add(key)
                stats["delete"] += ok
            if not ok:
                mine.append(key)  # may still be there: delete again later
        else:
            overwrite = mine and r < delete_share + 0.15
            key = rng.choice(mine) if overwrite else f"w{n}/k{i}"
            gen[key] = gen.get(key, 0) + 1
            body = body_for(key, gen[key])
            d = digest(body)
            with lock:  # a read from now on may see it
                expect[key] = expect.get(key, {GONE}) | {d}
            t0 = time.time()
            status, reply = http("PUT", f"{url}/{BUCKET}/{key}", body, timeout=60)
            oplog(key, "PUT", url.split("//")[1], f"{t0:.3f}", status, f"gen={gen[key]}", d)
            ok = record(status, reply, (200,))
            with lock:
                if ok:
                    expect[key] = {d}
                touched.add(key)
                if ok:
                    stats["overwrite" if overwrite else "put"] += 1
                    stats["bytes"] += len(body)
            if not overwrite:
                mine.append(key)
        if status not in (200, 204):
            time.sleep(0.2)


def phase_report(name):
    """Replaces chaos.phase_report, which chaos's faults call when settled."""
    with lock:
        g = max(gap[0], time.monotonic() - last_ok[0])
        report = {"phase": name, "keys": len(expect), "longest_gap_s": round(g, 1),
                  "errors": dict(errors), "samples": dict(samples)}
        gap[0] = 0.0
        errors.clear()
        samples.clear()
    print(json.dumps(report), flush=True)
    bad = {k: v for k, v in report["errors"].items() if k not in ("503", "507", "None")}
    if bad:
        fail(f"{name}: operations failed with other than 503/507: {bad} {report['samples']}")
    if g > chaos.MAX_GAP:
        fail(f"{name}: nothing acknowledged for {g:.0f}s (allowed {chaos.MAX_GAP:.0f}s)")


chaos.phase_report = phase_report


def usage():
    """(used, capacity) bytes across the OSDs, from a gateway's metrics."""
    for url in GW:
        status, body = http("GET", f"{url}/metrics", timeout=10)
        if status != 200:
            continue
        got = {}
        for line in body.decode(errors="replace").splitlines():
            name = line.split(" ")[0]
            if name in ("objectio_cluster_used_bytes", "objectio_cluster_capacity_bytes"):
                got[name] = float(line.rsplit(" ", 1)[1])
        if len(got) == 2:
            return got["objectio_cluster_used_bytes"], got["objectio_cluster_capacity_bytes"]
    return None


def fullest():
    """The used share of the fullest OSD: while one rebuilds, the others are
    fuller than the average and refuse writes first."""
    status, data = chaos.admin("GET", "/_admin/nodes")
    if status != 200:
        return None
    shares = [n["used_capacity"] / n["total_capacity"]
              for n in json.loads(data).get("nodes", []) if n.get("total_capacity")]
    return max(shares, default=None)


def fill_control():
    """Fill past the full ratio, then delete down to FULL_LOW, repeatedly
    (on the fullest OSD)."""
    while not stop.is_set():
        ratio = fullest()
        if ratio is not None:
            if ratio >= FULL_HIGH or (ratio >= FULL_HIGH - 0.03 and stats_full_refusals()):
                if not draining.is_set():
                    say(f"fill: {ratio:.0%} used, deleting down to {FULL_LOW:.0%}")
                draining.set()
            elif ratio <= FULL_LOW and draining.is_set():
                say(f"fill: {ratio:.0%} used, filling again")
                draining.clear()
        stop.wait(30)


full_seen = [0]


def stats_full_refusals():
    """Whether PUTs were refused as full since the last look: OSDs fill
    unevenly, so the cluster may refuse before the average reaches FULL_HIGH."""
    with lock:
        n = stats["full"]
    seen, full_seen[0] = full_seen[0], n
    return n > seen


def incusd_mb():
    """incusd's resident memory, in MB (None if not found)."""
    r = subprocess.run(["ps", "-o", "rss=", "-C", "incusd"], capture_output=True, text=True)
    sizes = [int(x) for x in r.stdout.split() if x.isdigit()]
    return max(sizes) // 1024 if sizes else None


PG_GAUGES = {
    "objectio_meta_pgs_not_clean": "not_clean",
    "objectio_meta_pg_not_clean_oldest_seconds": "oldest",
    "objectio_meta_osds_down": "osds_down",
    "objectio_meta_pg_objects_unfound": "unfound",
    "objectio_meta_lost_objects": "lost",
}


def pg_health():
    """Placement groups not Clean, how long the one longest so has been,
    OSDs down, objects unfound and lost (B31), from a gateway's metrics
    (meta's, polled by the gateway); None if no gateway answers with them."""
    for url in GW:
        status, body = http("GET", f"{url}/metrics", timeout=10)
        if status != 200:
            continue
        got = {}
        for line in body.decode(errors="replace").splitlines():
            name = line.split("{")[0].split(" ")[0]
            if name in PG_GAUGES:
                got[PG_GAUGES[name]] = max(got.get(PG_GAUGES[name], 0), int(float(line.rsplit(" ", 1)[1])))
        if len(got) == len(PG_GAUGES):
            return got
    return None


# The run fails on recovery that is stuck, not on recovery that is slow:
# the pool's placement groups out of Clean while, for STALL_MAX_SECS with
# every OSD up, neither their objects degraded fell below their lowest nor
# any object was recovered (B31, objectio-docs core/pg-recovery.md). Per
# pool, not per PG: a lost drive's replacement is in every PG of the lab's
# 6 hosts, so its PGs backfill a few at a time and the rest queue (run
# 19). How fast it gets back to Clean is B24's to measure on real disks;
# here it is logged, and only a ceiling (NOT_CLEAN_MAX_SECS) fails the
# run. Run 18's drive-lost took 61 minutes on the VMs' shared disks.
STALL_MAX_SECS = int(os.environ.get("STALL_MAX_SECS", "1800"))
NOT_CLEAN_MAX_SECS = int(os.environ.get("NOT_CLEAN_MAX_SECS", "10800"))
last_osd_down = [time.monotonic()]
# (lowest objects degraded, most recovered, when either last moved), since
# the pool last was all Clean
pool_mark = [None]
all_clean_since = [None]  # when the pool last left all Clean: None = all Clean


def pg_watch():
    """Every minute: the pool's recovery progress, and the run failed when
    it is stuck (above). Logs how long the pool took to get back to all
    Clean."""
    while not stop.wait(60):
        if not POOL:
            continue
        try:
            status, body = chaos.admin("GET", f"/_admin/pools/{POOL}/placement-groups", retry_for=30)
            pgs = json.loads(body)["pgs"] if status == 200 else None
        except Exception:  # noqa: BLE001 — a poll that fails is retried next minute
            pgs = None
        if not pgs:
            continue
        now = time.monotonic()
        states = [p.get("state") or {} for p in pgs]
        out = [s for s in states if s.get("state") != "Clean"]
        if not out:
            if all_clean_since[0] is not None:
                say(f"pgs: all {len(pgs)} Clean again after {int(now - all_clean_since[0])} s")
            all_clean_since[0] = None
            pool_mark[0] = None
            continue
        if all_clean_since[0] is None:
            all_clean_since[0] = now
        degraded = sum(s.get("objects_degraded", 0) for s in out)
        recovered = sum((s.get("recovery") or {}).get("recovered", 0) for s in states)
        mark = pool_mark[0]
        if mark is None or degraded < mark[0] or recovered > mark[1]:
            low = degraded if mark is None else min(degraded, mark[0])
            most = recovered if mark is None else max(recovered, mark[1])
            pool_mark[0] = (low, most, now)
            continue
        stalled = now - mark[2]
        all_up_for = now - last_osd_down[0]
        if stalled > STALL_MAX_SECS and all_up_for > STALL_MAX_SECS:
            worst = max(out, key=lambda s: s.get("objects_degraded", 0))
            say(f"pool {POOL}: {len(out)} PGs out of Clean, {degraded} objects degraded; e.g. "
                f"{json.dumps({k: v for k, v in worst.items() if k != 'members'})[:600]}")
            print(f"✗ pool {POOL}'s recovery made no progress for {int(stalled)} s "
                  f"with every OSD up for {int(all_up_for)} s", flush=True)
            OPLOG.flush()
            os._exit(1)


def progress():
    while not stop.wait(300):
        u = usage()
        with lock:
            line = {"t": time.strftime("%F %T"), **stats, "keys": len(expect),
                    "draining": draining.is_set(),
                    "used": None if not u else round(u[0] / max(u[1], 1), 3),
                    # The harness drives everything through incusd, which
                    # leaked to 16 GB and locked up once (2026-10-06).
                    "incusd_mb": incusd_mb(),
                    "pgs": pg_health()}
        print(json.dumps(line), flush=True)
        h = line["pgs"]
        if h is None:
            continue
        if h["osds_down"] > 0:
            last_osd_down[0] = time.monotonic()
        all_up_for = time.monotonic() - last_osd_down[0]
        if h["oldest"] > NOT_CLEAN_MAX_SECS and all_up_for > NOT_CLEAN_MAX_SECS:
            print(f"✗ a placement group has been out of Clean for {h['oldest']} s with every OSD up "
                  f"for {int(all_up_for)} s ({h['not_clean']} not Clean)", flush=True)
            OPLOG.flush()
            os._exit(1)
        if h["lost"] > 0:
            print(f"✗ {h['lost']} objects recorded lost", flush=True)
            OPLOG.flush()
            os._exit(1)


def read_outcome(key, attempts=20):
    """What a read of `key` shows: a digest, GONE, or the failing status."""
    for a in range(attempts):
        status, data = http("GET", f"{GW[a % len(GW)]}/{BUCKET}/{key}", timeout=30)
        if status == 200:
            return digest(data)
        if status == 404:
            return GONE
        if status not in (None, 503):
            return status
        time.sleep(1)
    return status


def check_one(item):
    """None if a read of the key shows an outcome it allows. Writers go on
    meanwhile, so a read that doesn't match is retried against what is
    allowed by then; a wrong read three times running is wrong."""
    key, allowed = item
    for _ in range(3):
        got = read_outcome(key)
        with lock:
            now = expect[key]
        if got in allowed or got in now:
            return None
        allowed = now
        time.sleep(2)
    return (key, "deleted" if got == GONE else got if not isinstance(got, str) else "different")


def check(what, everything=False):
    with lock:
        if everything:
            items = list(expect.items())
        else:
            recent = random.sample(list(touched), min(len(touched), SAMPLE))
            items = [(k, expect[k]) for k in recent]
            items += random.sample(list(expect.items()), min(len(expect), 2000))
        touched.clear()
    with ThreadPoolExecutor(max_workers=32) as pool:
        bad = [r for r in pool.map(check_one, items) if r]
    if bad:
        OPLOG.flush()
        for key, _ in bad[:5]:
            say(f"history of {key}:")
            with open(OPLOG.name) as f:
                for line in f:
                    if line.split(" ", 2)[1] == key:
                        print("   ", line.rstrip(), flush=True)
            say(f"  reads now: {read_outcome(key)}; allowed: {expect[key]}")
        fail(f"{what}: {len(bad)} of {len(items)} keys read wrong: {bad[:10]}")
    say(f"{what}: {len(items)} keys read as expected" + (" (all)" if everything else ""))


VERIFY_RATE = float(os.environ.get("VERIFY_RATE", "200"))  # keys read a second


def verifier():
    """Read every key, over and over, at VERIFY_RATE a second, faults or
    not: an acknowledged object unreadable (a 5xx that persists) fails the
    run within one cycle. The checks after each fault sample; this sees
    every key, and keeps going through a fault that lasts hours (soak run
    9 lost an object during a four-hour evacuation, and overwrote it before
    any check read it)."""
    cycle = 0
    while not stop.is_set():
        cycle += 1
        with lock:
            keys = list(expect)
        random.shuffle(keys)
        started = time.monotonic()
        for i, key in enumerate(keys):
            if stop.is_set():
                return
            status, _ = http("GET", f"{GW[i % len(GW)]}/{BUCKET}/{key}", timeout=30)
            if status is not None and status >= 500 and status != 503:
                # Not "retry later": read it again, as check_one would.
                with lock:
                    allowed = set(expect.get(key, ()))
                bad = check_one((key, allowed))
                if bad:
                    # fail() exits only this thread: end the run.
                    print(f"✗ verifier: {key} reads {status}; {bad}", flush=True)
                    OPLOG.flush()
                    os._exit(1)
            pause = (i + 1) / VERIFY_RATE - (time.monotonic() - started)
            if pause > 0:
                stop.wait(pause)
        say(f"verifier: cycle {cycle}: {len(keys)} keys read in {time.monotonic() - started:.0f} s")


def listed():
    """Every key the bucket lists."""
    keys, token = set(), None
    while True:
        q = "list-type=2&max-keys=1000" + (
            f"&continuation-token={urllib.parse.quote(token, safe='')}" if token else "")
        for attempt in range(20):
            status, body = http("GET", f"{GW[attempt % len(GW)]}/{BUCKET}?{q}", timeout=60)
            if status == 200:
                break
            time.sleep(2)
        else:
            fail(f"listing failed: {status} {body[:200]}")
        text = body.decode()
        keys.update(part.split("</Key>")[0] for part in text.split("<Key>")[1:])
        if "<IsTruncated>true</IsTruncated>" not in text:
            return keys
        token = text.split("<NextContinuationToken>")[1].split("</NextContinuationToken>")[0]


def check_listing():
    keys = listed()
    with lock:
        must = {k for k, a in expect.items() if GONE not in a}
        may = {k for k, a in expect.items() if a - {GONE}}
    missing, extra = must - keys, keys - may
    if missing or extra:
        fail(f"listing: {len(missing)} keys missing {sorted(missing)[:5]}, "
             f"{len(extra)} listed that should be gone {sorted(extra)[:5]}")
    say(f"listing: {len(keys)} keys, as expected")


def delete_everything():
    with lock:
        keys = [k for k, a in expect.items() if a != {GONE}]

    def gone(key):
        for a in range(20):
            status, reply = http("DELETE", f"{GW[a % len(GW)]}/{BUCKET}/{key}", timeout=30)
            if status in (200, 204):
                with lock:
                    expect[key] = {GONE}
                return None
            time.sleep(1)
        return (key, status)

    with ThreadPoolExecutor(max_workers=32) as pool:
        bad = [r for r in pool.map(gone, keys) if r]
    if bad:
        fail(f"deleting everything: {len(bad)} deletes failed: {bad[:5]}")
    say(f"deleted all {len(keys)} remaining keys")


def await_no_leak(baseline):
    """Space comes back: within LEAK_SLACK of the baseline, given time for
    the deletes' tombstones and packs to be cleaned up."""
    deadline = time.monotonic() + float(os.environ.get("LEAK_WAIT", "3600"))
    while True:
        u = usage()
        if u and u[0] <= baseline + LEAK_SLACK:
            say(f"no leak: {u[0] / 1e9:.2f} GB used, {baseline / 1e9:.2f} GB before the run")
            return
        if time.monotonic() > deadline:
            fail(f"leak: {u and u[0] / 1e9:.2f} GB still used with every key deleted "
                 f"({baseline / 1e9:.2f} GB before the run)")
        time.sleep(60)


def main():
    say(f"soak: {HOURS} h, a fault every {FAULT_EVERY / 60:.0f} min, {WRITERS} writers; "
        f"cluster {chaos.IP}")
    # SOAK_POOL: the bucket goes in a pool of its own that places through
    # placement groups (4+2, 32 PGs, one shard per host), the layout the
    # docs recommend; without it, the default pool (CRUSH, no PGs). The
    # PG path went untested here, and a lost OSD stayed in its PGs.
    headers = {}
    if POOL:
        status, reply = chaos.admin("POST", "/_admin/pools", {
            "name": POOL, "ec_type": 0, "ec_k": 4, "ec_m": 2,
            "pg_count": 32, "failure_domain": "host", "enabled": True})
        if status not in (200, 201, 409):
            fail(f"pool {POOL}: {status} {reply[:300]!r}")
        headers = {"x-objectio-pool": POOL}
        say(f"bucket {BUCKET} in pool {POOL} (placement groups)")
    while http("PUT", f"{GW[0]}/{BUCKET}", headers=headers)[0] not in (200, 409):
        time.sleep(2)
    chaos.await_metas_healthy()
    chaos.await_osds_online(6)
    baseline = usage()[0]
    threads = [threading.Thread(target=writer, args=(n,), daemon=True) for n in range(WRITERS)]
    threads += [threading.Thread(target=fill_control, daemon=True),
                threading.Thread(target=progress, daemon=True),
                threading.Thread(target=pg_watch, daemon=True),
                threading.Thread(target=verifier, daemon=True)]
    for t in threads:
        t.start()
    time.sleep(60)
    phase_report("warm-up")

    faults = os.environ.get(
        "FAULTS", "meta-kill,power-off,meta-power-off,partition,disk-pull,drive-lost")
    faults = faults.split(",")
    volume = {}  # the VM pulled from -> its OSD's current volume
    end = time.monotonic() + HOURS * 3600
    n = 0
    while time.monotonic() < end:
        stop.wait(FAULT_EVERY)
        f = faults[n % len(faults)]
        n += 1
        if f == "meta-kill":
            chaos.meta_kill()
        elif f == "power-off":
            chaos.power_off("chaos-6", "power-off")
        elif f == "meta-power-off":
            chaos.power_off("chaos-3", "meta-power-off")
        elif f == "partition":
            chaos.partition()
        elif f == "disk-pull":
            vm = "chaos-5"
            old = volume.get(vm, f"{vm}-osd")
            chaos.disk_pull(vm, new=f"{vm}-osd-{n}")
            volume[vm] = f"{vm}-osd-{n}"
            incus("storage", "volume", "delete", "default", old, check=False)
        elif f == "drive-lost":
            vm = "chaos-4"
            old = volume.get(vm, f"{vm}-osd")
            chaos.drive_lost(vm, new=f"{vm}-osd-{n}")
            volume[vm] = f"{vm}-osd-{n}"
            incus("storage", "volume", "delete", "default", old, check=False)
        else:
            fail(f"unknown fault {f}")
        check(f"after {f} ({n})")

    stop.set()
    for t in threads[:WRITERS]:
        t.join()
    phase_report("end")
    check("at the end", everything=True)
    check_listing()
    with lock:
        want = {k: next(iter(a)) for k, a in expect.items() if GONE not in a and len(a) == 1}
    chaos.redundancy_restored(list(want), lambda key, data: digest(data) == want[key])
    delete_everything()
    check("after deleting everything", everything=True)
    await_no_leak(baseline)
    print(f"✓ soak: {sum(stats[k] for k in ('put', 'overwrite', 'delete'))} acknowledged "
          f"operations over {HOURS} h, {stats['bytes'] / 1e12:.2f} TB written; nothing lost, "
          f"nothing leaked", flush=True)


if __name__ == "__main__":
    main()
