#!/usr/bin/env python3
"""Small S3 throughput/latency benchmark for ObjectIO.

Standard library only — no boto3, no warp. The point is to be droppable onto
any host that can reach the gateway, and to keep the client cheap enough that
it is measuring the server rather than itself.

    ./s3bench.py --endpoint http://10.0.0.5:9000 --bucket bench

What it reports, per (size, concurrency) cell:

    throughput   aggregate MB/s over the phase's wall clock — the number you
                 compare between systems
    ops/s        same, in operations
    p50/p90/p99  per-operation latency, which is what a caller feels
    TTFB         GET only: time to the first byte of the body, which separates
                 "the server was slow to start" from "the transfer was slow"

Comparing against RustFS / MinIO / Ceph: run this against both with identical
flags, from the same client host, on the same network path. Published numbers
from those projects normally come from `warp` (github.com/minio/warp), which
is the apples-to-apples tool if you need results others will trust — this
script is for iterating quickly and for the things warp does not separate,
like proxy cost versus storage cost.

Exit status is non-zero if any operation failed, so it can gate CI.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import ssl
import statistics
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# SigV4 — same algorithm as sdk/python/objectio/_sigv4.py, inlined so this
# file stays a single droppable script.
# --------------------------------------------------------------------------

_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _escape(value: str) -> str:
    out = []
    for byte in value.encode("utf-8"):
        ch = chr(byte)
        out.append(ch if ch in _UNRESERVED else f"%{byte:02X}")
    return "".join(out)


def _escape_path(path: str) -> str:
    return "/".join(_escape(seg) for seg in path.split("/"))


def _hmac(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def sign(method: str, host: str, path: str, query: str, payload_hash: str,
         access_key: str, secret_key: str, region: str) -> dict[str, str]:
    """Headers authenticating one request.

    `payload_hash` is passed in rather than computed: for a repeated PUT of the
    same body, hashing once and reusing it keeps the client's CPU out of the
    measurement.
    """
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    names = sorted(headers)
    canonical_headers = "".join(f"{h}:{headers[h]}\n" for h in names)
    signed_headers = ";".join(names)

    canonical_request = "\n".join(
        [method, _escape_path(path) or "/", query, canonical_headers,
         signed_headers, payload_hash]
    )
    scope = f"{date_stamp}/{region}/s3/aws4_request"
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope,
         hashlib.sha256(canonical_request.encode()).hexdigest()]
    )
    key = _hmac(f"AWS4{secret_key}".encode(), date_stamp)
    for part in (region, "s3", "aws4_request"):
        key = _hmac(key, part)
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()

    return {
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Content-Sha256": payload_hash,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass
class Sample:
    latency: float
    ttfb: float | None = None
    ok: bool = True
    status: int = 0


@dataclass
class PhaseResult:
    op: str
    size: int
    concurrency: int
    wall: float
    samples: list[Sample] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(1 for s in self.samples if not s.ok)

    @property
    def count(self) -> int:
        return len(self.samples)

    @property
    def succeeded(self) -> int:
        """Operations that actually moved data.

        Throughput counts only these. Counting attempts meant a cell where
        every request 500'd still reported 216 MB/s, which is worse than no
        number at all — it is a number that will be believed.
        """
        return sum(1 for s in self.samples if s.ok)

    @property
    def ops_per_sec(self) -> float:
        return self.succeeded / self.wall if self.wall else 0.0

    @property
    def mb_per_sec(self) -> float:
        # Aggregate over the phase's wall clock, not the mean of per-op rates.
        # The latter flatters a run whose workers did not overlap.
        return (self.succeeded * self.size) / self.wall / 1e6 if self.wall else 0.0

    @property
    def status_breakdown(self) -> dict[int, int]:
        out: dict[int, int] = {}
        for s in self.samples:
            if not s.ok:
                out[s.status] = out.get(s.status, 0) + 1
        return out

    def pct(self, p: float, ttfb: bool = False) -> float:
        vals = [
            (s.ttfb if ttfb else s.latency)
            for s in self.samples
            if s.ok and (s.ttfb is not None or not ttfb)
        ]
        if not vals:
            return 0.0
        vals.sort()
        # Nearest-rank: with a few hundred samples, interpolation invents
        # precision the sample size does not support.
        k = max(0, min(len(vals) - 1, int(round(p / 100 * len(vals) + 0.5)) - 1))
        return vals[k]

    def row(self) -> dict:
        return {
            "op": self.op,
            "object_size": self.size,
            "concurrency": self.concurrency,
            "operations": self.count,
            "succeeded": self.succeeded,
            "errors": self.errors,
            "error_status": {str(k): v for k, v in self.status_breakdown.items()},
            "wall_seconds": round(self.wall, 4),
            "ops_per_sec": round(self.ops_per_sec, 1),
            "mb_per_sec": round(self.mb_per_sec, 1),
            "p50_ms": round(self.pct(50) * 1000, 2),
            "p90_ms": round(self.pct(90) * 1000, 2),
            "p99_ms": round(self.pct(99) * 1000, 2),
            "max_ms": round(max((s.latency for s in self.samples if s.ok), default=0) * 1000, 2),
            "ttfb_p50_ms": round(self.pct(50, ttfb=True) * 1000, 2) or None,
        }


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


class Conn(threading.local):
    """One keep-alive connection per worker thread.

    Reconnecting per request would measure TCP and TLS setup, which is a real
    cost but not the one being asked about — and it is the cost that differs
    most between a direct hit and one through a reverse proxy.
    """

    conn = None


class Bench:
    def __init__(self, endpoint: str, access_key: str, secret_key: str,
                 region: str, insecure: bool):
        u = urlparse(endpoint)
        self.scheme = u.scheme
        self.host = u.netloc
        self.hostname = u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.insecure = insecure
        self._local = Conn()

    def _connection(self):
        if self._local.conn is None:
            if self.scheme == "https":
                ctx = ssl.create_default_context()
                if self.insecure:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                self._local.conn = HTTPSConnection(
                    self.hostname, self.port, timeout=120, context=ctx
                )
            else:
                self._local.conn = HTTPConnection(self.hostname, self.port, timeout=120)
        return self._local.conn

    def _reset(self):
        try:
            if self._local.conn:
                self._local.conn.close()
        except Exception:
            pass
        self._local.conn = None

    def request(self, method: str, path: str, body: bytes | None,
                payload_hash: str, read_body: bool) -> Sample:
        headers = sign(method, self.host, path, "", payload_hash,
                       self.access_key, self.secret_key, self.region)
        if body is not None:
            headers["Content-Length"] = str(len(body))

        start = time.perf_counter()
        try:
            conn = self._connection()
            conn.request(method, _escape_path(path), body=body, headers=headers)
            resp = conn.getresponse()
            ttfb = time.perf_counter() - start
            if read_body:
                # Must drain it: the transfer is the thing being measured, and
                # an undrained response also poisons the keep-alive.
                data = resp.read()
                n = len(data)
            else:
                resp.read()
                n = 0
            latency = time.perf_counter() - start
            ok = 200 <= resp.status < 300
            if not ok:
                self._reset()
            return Sample(latency=latency, ttfb=ttfb, ok=ok, status=resp.status)
        except Exception:
            self._reset()
            return Sample(latency=time.perf_counter() - start, ok=False, status=0)


# --------------------------------------------------------------------------
# Phases
# --------------------------------------------------------------------------


def run_phase(bench: Bench, op: str, bucket: str, keys: list[str],
              payload: bytes | None, payload_hash: str, concurrency: int,
              size: int) -> PhaseResult:
    read_body = op == "GET"
    method = {"PUT": "PUT", "GET": "GET", "DELETE": "DELETE"}[op]

    def one(key: str) -> Sample:
        return bench.request(
            method, f"/{bucket}/{key}",
            payload if op == "PUT" else None,
            payload_hash if op == "PUT" else EMPTY_SHA256,
            read_body,
        )

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        samples = list(pool.map(one, keys))
    wall = time.perf_counter() - start
    return PhaseResult(op=op, size=size, concurrency=concurrency, wall=wall,
                       samples=samples)


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:g}{unit}" if n < 1024 else f"{n/1024:g}GB"
        n /= 1024
    return str(n)


def parse_size(s: str) -> int:
    s = s.strip().upper()
    mult = 1
    for suffix, m in (("KB", 1024), ("MB", 1024**2), ("GB", 1024**3),
                      ("K", 1024), ("M", 1024**2), ("G", 1024**3)):
        if s.endswith(suffix):
            return int(float(s[: -len(suffix)]) * m)
    return int(s) * mult


def main() -> int:
    p = argparse.ArgumentParser(
        description="Throughput and latency benchmark for an S3 endpoint.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Exit status")[0].split("What it reports")[1],
    )
    p.add_argument("--endpoint", default=os.environ.get("OBJECTIO_URL")
                   or os.environ.get("OBJECTIO_ENDPOINT"),
                   help="gateway base URL (env: OBJECTIO_URL)")
    p.add_argument("--access-key", default=os.environ.get("OBJECTIO_ACCESS_KEY")
                   or os.environ.get("AWS_ACCESS_KEY_ID"))
    p.add_argument("--secret-key", default=os.environ.get("OBJECTIO_SECRET_KEY")
                   or os.environ.get("AWS_SECRET_ACCESS_KEY"))
    p.add_argument("--region", default=os.environ.get("OBJECTIO_REGION", "us-east-1"))
    p.add_argument("--bucket", default="objectio-bench",
                   help="bucket to use; must already exist")
    p.add_argument("--sizes", default="4KB,64KB,1MB,8MB",
                   help="comma-separated object sizes (default: 4KB,64KB,1MB,8MB)")
    p.add_argument("--concurrency", default="1,8,32",
                   help="comma-separated worker counts (default: 1,8,32)")
    p.add_argument("--objects", type=int, default=64,
                   help="objects per cell (default: 64)")
    p.add_argument("--warmup", type=int, default=4,
                   help="unmeasured operations before each phase (default: 4)")
    p.add_argument("--keep", action="store_true",
                   help="leave objects behind instead of deleting them")
    p.add_argument("--json", metavar="FILE", help="also write results as JSON")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--label", default="", help="tag for the JSON output, e.g. 'direct' or 'via-proxy'")
    args = p.parse_args()

    missing = [n for n, v in (("--endpoint", args.endpoint),
                              ("--access-key", args.access_key),
                              ("--secret-key", args.secret_key)) if not v]
    if missing:
        p.error(f"missing {', '.join(missing)}")

    sizes = [parse_size(s) for s in args.sizes.split(",")]
    concurrencies = [int(c) for c in args.concurrency.split(",")]
    bench = Bench(args.endpoint, args.access_key, args.secret_key,
                  args.region, args.insecure)

    run_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    print(f"endpoint   {args.endpoint}")
    print(f"bucket     {args.bucket}   run {run_id}")
    print(f"sizes      {', '.join(human(s) for s in sizes)}")
    print(f"workers    {', '.join(str(c) for c in concurrencies)}   "
          f"{args.objects} objects per cell")
    print()
    header = (f"{'op':<7}{'size':>7}{'conc':>6}{'ops/s':>10}{'MB/s':>10}"
              f"{'p50 ms':>9}{'p90 ms':>9}{'p99 ms':>9}{'ttfb p50':>10}{'err':>5}")
    print(header)
    print("-" * len(header))

    results: list[PhaseResult] = []
    failures = 0

    for size in sizes:
        # One payload per size, hashed once. Regenerating or rehashing inside
        # the loop would put the client's CPU into the measurement.
        payload = os.urandom(size)
        payload_hash = hashlib.sha256(payload).hexdigest()

        for conc in concurrencies:
            keys = [f"{run_id}/{human(size)}/c{conc}/{i:05d}" for i in range(args.objects)]

            if args.warmup:
                run_phase(bench, "PUT", args.bucket, keys[:args.warmup],
                          payload, payload_hash, min(conc, args.warmup), size)

            for op in ("PUT", "GET"):
                r = run_phase(bench, op, args.bucket, keys, payload, payload_hash,
                              conc, size)
                results.append(r)
                failures += r.errors
                row = r.row()
                print(f"{r.op:<7}{human(size):>7}{conc:>6}"
                      f"{row['ops_per_sec']:>10.1f}{row['mb_per_sec']:>10.1f}"
                      f"{row['p50_ms']:>9.2f}{row['p90_ms']:>9.2f}{row['p99_ms']:>9.2f}"
                      f"{(row['ttfb_p50_ms'] or 0):>10.2f}{r.errors:>5}")
                if r.errors:
                    # A count alone sends you to tcpdump. The status does not.
                    detail = ", ".join(
                        f"{n}x HTTP {code}" if code else f"{n}x transport"
                        for code, n in sorted(r.status_breakdown.items())
                    )
                    print(f"{'':>7}{'':>7}{'':>6}  -> {detail}")

            if not args.keep:
                run_phase(bench, "DELETE", args.bucket, keys, None,
                          EMPTY_SHA256, conc, size)

    print()
    if failures:
        print(f"!! {failures} operations failed", file=sys.stderr)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(
                {
                    "label": args.label,
                    "endpoint": args.endpoint,
                    "run": run_id,
                    "at": datetime.now(timezone.utc).isoformat(),
                    "objects_per_cell": args.objects,
                    "results": [r.row() for r in results],
                },
                fh,
                indent=2,
            )
        print(f"wrote {args.json}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
