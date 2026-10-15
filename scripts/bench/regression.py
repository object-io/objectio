#!/usr/bin/env python3
"""Performance regression check (B4): one build against another, same host.

    scripts/bench/regression.py --base <dir> --head <dir> [--rounds 5]

Each directory holds an `objectio-aio` (the head's also `objectio-s3-bench`,
the one client both are measured with). Each run starts a fresh aio (six
OSDs, 4+2) and puts, then gets, 64 KiB and 4 MiB objects through it.

Shared CI runners differ from each other by more than most regressions, so
nothing here is an absolute number: both builds run on the same runner, in
the same job, interleaved (base, head, head, base, ...) so a runner that
slows down part way through slows both. CI gives the aio a tmpfs for its
data (--workdir): a runner's disk swung one build's 64 KiB PUTs from
208 to 372 a second between runs, which no threshold can see through, so
the check measures the software (CPU, copies, RPCs, locks) and not the
drive. A change that adds disk work (another fsync) is not seen here; the
lab and cloud baselines measure the drives. A cell's result is the head's median
over the base's; the check fails when a cell's throughput falls below
`--threshold` of the base's. p99 latency is shown, not judged: on a shared
runner's disk it moves too much from run to run.

Writes a Markdown table to stdout and, under GitHub Actions, to the job
summary. Exit status 1 is a regression, 2 a run that could not be measured.
"""

import argparse
import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

# (name, size, objects, GETs of each, concurrency): one small-object cell,
# bound by the OSDs' fsyncs and the RPCs per request, and one large, bound
# by erasure coding and the data path's copies. A few seconds a phase.
CELLS = [
    ("64KiB", "64KiB", 6000, 4, 32),
    ("4MiB", "4MiB", 150, 4, 8),
]

PHASE = re.compile(r"^(PUT|GET): (\d+) ok, (\d+) failed in ([\d.]+) s", re.M)
THROUGHPUT = re.compile(r"throughput ([\d.]+) MiB/s, ([\d.]+) ops/s")
P99 = re.compile(r"p99 ([\d.]+) (µs|ms|s)\b")
UNIT = {"µs": 1e-3, "ms": 1.0, "s": 1e3}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ready(endpoint, osds):
    """The gateway's own readiness, with every OSD reachable."""
    try:
        with urllib.request.urlopen(f"{endpoint}/_ready", timeout=2) as r:
            body = json.load(r)
    except (OSError, ValueError):
        return False
    return body.get("status") == "ready" and body.get("osds_reachable", 0) >= osds


class Aio:
    """One aio on a fresh data directory, stopped (and its data removed)
    when the block ends."""

    def __init__(self, binary, workdir, logs, osds=6):
        self.binary, self.osds = binary, osds
        self.data = Path(tempfile.mkdtemp(prefix="aio-", dir=workdir))
        self.endpoint = f"http://127.0.0.1:{free_port()}"
        self.log = open(logs / f"{self.data.name}.log", "w")

    def __enter__(self):
        port = self.endpoint.rsplit(":", 1)[1]
        self.proc = subprocess.Popen(
            [self.binary, "--data", str(self.data), "--port", port,
             "--listen-addr", "127.0.0.1", "--strict-port", "--log-level", "warn",
             "--osds", str(self.osds), "--ec-k", "4", "--ec-m", "2"],
            stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.binary} exited with {self.proc.returncode}"
                                   f" (log: {self.log.name})")
            if ready(self.endpoint, self.osds):
                return self
            time.sleep(0.25)
        raise RuntimeError(f"{self.binary}: not ready with {self.osds} OSDs within 120 s")

    def __exit__(self, *_):
        self.proc.terminate()
        try:
            self.proc.wait(30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()
        shutil.rmtree(self.data, ignore_errors=True)


def bench(client, endpoint, size, objects, passes, concurrency):
    """PUT then GET; {op: (ops/s, MiB/s, p99 ms)}."""
    out = subprocess.run(
        [client, "--endpoint", endpoint, "--bucket", "regression", "--size", size,
         "--objects", str(objects), "--get-passes", str(passes),
         "--concurrency", str(concurrency),
         "--op", "both", "--metrics-wait", "0"],
        capture_output=True, text=True, timeout=900)
    if out.returncode != 0:
        raise RuntimeError(f"s3-bench failed: {out.stderr.strip()[-2000:]}")
    text, result = out.stdout, {}
    for m in PHASE.finditer(text):
        op, ok, failed = m.group(1), int(m.group(2)), int(m.group(3))
        if failed:
            raise RuntimeError(f"{op} {size}: {failed} of {ok + failed} failed")
        block = text[m.end():]
        mib, ops = map(float, THROUGHPUT.search(block).groups())
        v, unit = P99.search(block).groups()
        result[op] = (ops, mib, float(v) * UNIT[unit])
    if set(result) != {"PUT", "GET"}:
        raise RuntimeError(f"s3-bench output not understood:\n{text}")
    return result


def run(binary, client, workdir, logs):
    with Aio(binary, workdir, logs) as aio:
        # Unmeasured: the first requests pay for connections and the
        # pool's first placement; a pool still being made refuses them.
        deadline = time.monotonic() + 60
        while True:
            try:
                bench(client, aio.endpoint, "64KiB", 200, 1, 16)
                break
            except RuntimeError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(1)
        return {name: bench(client, aio.endpoint, size, n, p, c)
                for name, size, n, p, c in CELLS}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, type=Path, help="the build to compare against")
    ap.add_argument("--head", required=True, type=Path, help="the build under test")
    ap.add_argument("--rounds", type=int, default=5,
                    help="runs of each build (default 5)")
    ap.add_argument("--threshold", type=float, default=0.85,
                    help="fail when the head's throughput is below this share "
                         "of the base's (default 0.85)")
    ap.add_argument("--workdir", type=Path, default=Path(tempfile.gettempdir()),
                    help="where each run's aio keeps its data: a tmpfs, see above "
                         "(not under /dev, which an OSD takes for a device)")
    ap.add_argument("--logs", type=Path, default=Path(tempfile.gettempdir()),
                    help="where each run's aio log is kept")
    ap.add_argument("--json", type=Path, help="also write every run's numbers here")
    args = ap.parse_args()

    builds = {"base": args.base / "objectio-aio", "head": args.head / "objectio-aio"}
    client = args.head / "objectio-s3-bench"
    for b in [*builds.values(), client]:
        if not os.access(b, os.X_OK):
            sys.exit(f"not an executable: {b}")

    runs = {"base": [], "head": []}
    for r in range(args.rounds):
        # base, head, head, base, ...: a drift over the job hits both alike.
        for build in (("base", "head") if r % 2 == 0 else ("head", "base")):
            started = time.monotonic()
            try:
                runs[build].append(run(builds[build], client, args.workdir, args.logs))
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                print(f"round {r + 1}, {build}: {e}", file=sys.stderr)
                sys.exit(2)
            print(f"round {r + 1}, {build}: {time.monotonic() - started:.0f} s, "
                  + ", ".join(f"{c} {op} {v[0]:.0f} ops/s"
                              for c, ops in runs[build][-1].items()
                              for op, v in ops.items()),
                  file=sys.stderr)

    if args.json:
        args.json.write_text(json.dumps(runs, indent=1))

    rows, failed = [], []
    for name, *_ in CELLS:
        for op in ("PUT", "GET"):
            series = {b: [run_[name][op] for run_ in runs[b]] for b in runs}
            med = {b: statistics.median(v[0] for v in s) for b, s in series.items()}
            p99 = {b: statistics.median(v[2] for v in s) for b, s in series.items()}
            spread = {b: (max(v[0] for v in s) - min(v[0] for v in s)) / med[b]
                      for b, s in series.items()}
            ratio = med["head"] / med["base"]
            ok = ratio >= args.threshold
            if not ok:
                failed.append(f"{op} {name}")
            mib = name != "64KiB"
            unit = "MiB/s" if mib else "ops/s"
            fmt = (lambda b: statistics.median(v[1] for v in series[b])) if mib else med.get
            rows.append(
                f"| {op} {name} | {fmt('base'):,.0f} {unit} (±{spread['base'] / 2:.0%}) "
                f"| {fmt('head'):,.0f} {unit} (±{spread['head'] / 2:.0%}) "
                f"| **{ratio:.2f}** {'✅' if ok else '❌'} "
                f"| {p99['base']:.0f} → {p99['head']:.0f} ms |")

    report = "\n".join([
        "## Performance against the base",
        "",
        f"Median of {args.rounds} runs of each build on this runner, interleaved; "
        f"± is half the range. A cell fails below {args.threshold:.2f} of the base.",
        "",
        "| Cell | Base | Head | Head ÷ base | p99 (not judged) |",
        "|---|---|---|---|---|",
        *rows,
        "",
        (f"**Slower than the base:** {', '.join(failed)}." if failed
         else "No cell slower than the threshold."),
        "",
    ])
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(report)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
