"""S3 traffic for the meta HA test on kind, run inside the cluster.

    python3 meta_ha_load.py <gateway-url>

Writes objects from several threads until /tmp/stop exists, keeping each
one the gateway acknowledged (200), then reads every acknowledged object
back and compares it byte for byte. Prints one JSON line per second while
running and a JSON summary at the end; exits 1 if anything acknowledged
is missing or different.

Standard library only (the gateway runs with --no-auth on kind), so the
pod needs nothing but python.
"""

import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

URL = sys.argv[1].rstrip("/")
BUCKET = "meta-ha"
WRITERS = 4
STOP = "/tmp/stop"

acked = {}  # key -> sha256 of the body
lock = threading.Lock()
last_ok = [time.monotonic()]
longest_gap = [0.0]
errors = {}  # status (or exception) -> count
samples = {}  # status -> the first few response bodies


def request(method, path, body=None, timeout=10):
    req = urllib.request.Request(URL + path, data=body, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # connection refused, reset, timeout
        return None, str(e).encode()


def body_for(key):
    seed = hashlib.sha256(key.encode()).digest()
    size = 1_000 + int.from_bytes(seed[:2], "big") * 3  # 1 KB .. ~200 KB
    return (seed * (size // len(seed) + 1))[:size]


def writer(n):
    i = 0
    while not os.path.exists(STOP):
        key = f"w{n}/k{i}"
        body = body_for(key)
        status, reply = request("PUT", f"/{BUCKET}/{key}", body)
        now = time.monotonic()
        with lock:
            if status == 200:
                acked[key] = hashlib.sha256(body).hexdigest()
                longest_gap[0] = max(longest_gap[0], now - last_ok[0])
                last_ok[0] = now
            else:
                errors[status] = errors.get(status, 0) + 1
                seen = samples.setdefault(str(status), [])
                if len(seen) < 3:
                    seen.append(reply[:300].decode(errors="replace"))
        if status != 200:
            time.sleep(0.2)  # as a client backs off; keeps the count meaningful
        i += 1


def main():
    deadline = time.monotonic() + 300
    while request("PUT", f"/{BUCKET}")[0] not in (200, 409):
        if time.monotonic() > deadline:
            sys.exit("the bucket could not be created")
        time.sleep(2)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(WRITERS)]
    for t in threads:
        t.start()
    while not os.path.exists(STOP):
        with lock:
            print(json.dumps({
                "acked": len(acked),
                "errors": sum(errors.values()),
                "since_last_ok_s": round(time.monotonic() - last_ok[0], 1),
                "longest_gap_s": round(longest_gap[0], 1),
            }), flush=True)
        time.sleep(1)
    for t in threads:
        t.join()
    # A stretch of failures that lasts to the end counts too.
    longest_gap[0] = max(longest_gap[0], time.monotonic() - last_ok[0])

    missing, different = [], []
    for key, digest in sorted(acked.items()):
        for _ in range(30):
            status, data = request("GET", f"/{BUCKET}/{key}")
            if status is not None:
                break
            time.sleep(1)
        if status != 200:
            missing.append([key, status])
        elif hashlib.sha256(data).hexdigest() != digest:
            different.append(key)
    summary = {
        "summary": True,
        "acked": len(acked),
        "write_errors": {str(k): v for k, v in errors.items()},
        "error_samples": samples,
        "longest_gap_s": round(longest_gap[0], 1),
        "missing": missing[:20],
        "missing_count": len(missing),
        "different": different[:20],
        "different_count": len(different),
    }
    print(json.dumps(summary), flush=True)
    sys.exit(1 if missing or different else 0)


if __name__ == "__main__":
    main()
