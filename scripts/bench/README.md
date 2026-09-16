# s3bench

A small throughput/latency benchmark for an S3 endpoint. Standard library
only — droppable onto any host that can reach the gateway.

```bash
./s3bench.py --endpoint https://s3.example.com --bucket objectio-bench
```

Credentials come from flags or the same environment variables the SDKs use
(`OBJECTIO_URL`, `OBJECTIO_ACCESS_KEY`, `OBJECTIO_SECRET_KEY`, or the
`AWS_*` equivalents). The bucket must already exist.

## What it measures

Per (object size × concurrency) cell:

| | |
|---|---|
| `MB/s` | aggregate over the phase's wall clock — the comparison number |
| `ops/s` | same, in operations; what matters for small objects |
| `p50/p90/p99` | per-operation latency, what a caller feels |
| `ttfb` | GET only — separates "slow to start" from "slow to transfer" |

Throughput counts **only successful operations**. A cell where everything
failed reports 0 MB/s, not a number someone will quote.

## Separating the network from the store

Most of a benchmark against a public endpoint measures TLS and the reverse
proxy in front of it. Run it twice and diff:

```bash
./s3bench.py --endpoint https://s3.example.com   --label via-proxy --json proxy.json
./s3bench.py --endpoint http://10.0.0.5:9000     --label direct    --json direct.json
```

## Comparing against RustFS / MinIO / Ceph

Run this against both with identical flags, from the same client host, on the
same network path. Anything else is not a comparison.

For numbers others will trust, use [`warp`](https://github.com/minio/warp) —
it is what those projects publish from, so it is the apples-to-apples tool.
This script is for iterating quickly, and for the things warp does not
separate.

## Caveats worth stating in any result

- **Python is the client.** With enough concurrency it will bottleneck before
  a fast server does. If `ops/s` stops scaling with `--concurrency`, suspect
  the client before the server.
- **One object size per cell** — real workloads are mixed.
- **No multipart.** Objects are single PUTs, so this does not exercise the
  multipart path at all.
