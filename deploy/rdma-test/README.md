# RDMA tests on the HGX cluster

Measures ObjectIO's Transfer Engine data path on real RNICs
(objectio-docs `architecture/design/rdma-data-plane.md`), in the
`obio-rdma-test` namespace of the `prod-k8s` cluster. That cluster is shared
with production:

- **Only `obio-rdma-test` is ours.** Never apply to, or delete from, any other
  namespace.
- **No priority class and no CPU or memory requests** on any pod — only the
  `rdma/hca_gpu0` device slot the RDMA containers need. At priority 0 and
  best-effort, these pods can never preempt anything; if a node is full they
  wait in Pending, and they are the first evicted under pressure.
  (A first attempt used `build-preemptible`, priority 75. Production pods here
  mostly have no priority class — 0 — so the 12-CPU OSD pod, not fitting on a
  node whose CPU was 90% requested, preempted a vLLM deployment. Never again.)
- The API gateway rejects shell text (`bash -c`, redirections, `/proc`). Nothing
  here uses a shell: manifests pass arguments directly, `$(VAR)` is expanded by
  Kubernetes, and every `kubectl exec` below runs a binary with plain arguments.
- The fabric is rail-optimised. Everything uses rail **mlx5_0**
  (`rdma/hca_gpu0`, `MC_TE_FILTERS=mlx5_0`); mismatched rails fail with
  "transport retry counter exceeded".

Nodes: `gpu-compute-05` (gateways, `obio-te-a`) and `gpu-compute-07`
(meta, OSDs, `obio-te-b`).

```bash
export KUBECONFIG=<path>/kubeconfig      # context prod-k8s
K="kubectl --context prod-k8s -n obio-rdma-test"
```

## 0. Namespace

`00-namespace.yaml` — privileged pod security, like the `mooncake` namespace
(hostNetwork and IPC_LOCK need it). Deleting it removes everything below.

## 1. Image and pull secret

The manifests use `ghcr.io/infinia-technology/objectio-rdma-test:<commit>`
and the pull secret `ghcr-kvbench`, copied into `obio-rdma-test` from
`dynamo-poc`. To rebuild after a change:

```bash
docker build -f deploy/rdma-test/Dockerfile.rdma-test \
  -t ghcr.io/infinia-technology/objectio-rdma-test:$(git rev-parse --short HEAD) .
docker push ghcr.io/infinia-technology/objectio-rdma-test:$(git rev-parse --short HEAD)
```

and update the tag in `10-*.yaml` and `20-*.yaml`.

## 2. The fabric, raw

```bash
kubectl --context prod-k8s apply -f deploy/rdma-test/10-rdma-probe.yaml
$K wait --for=condition=Ready pod/obio-te-a pod/obio-te-b --timeout=10m
A=$($K get pod obio-te-a -o jsonpath='{.status.hostIP}')
B=$($K get pod obio-te-b -o jsonpath='{.status.hostIP}')
```

**Rail check** (expect ~390 Gb/s on a 400G CX-7). In one terminal:

```bash
$K exec obio-te-b -- ib_write_bw -d mlx5_0 --report_gbits -D 10
```

In another, pointing at B's address **on mlx5_0's interface** (find it with
`$K exec obio-te-b -- ip -br addr`):

```bash
$K exec obio-te-a -- ib_write_bw -d mlx5_0 --report_gbits -D 10 <B-address-on-mlx5_0>
```

**Transfer Engine, RDMA.** Serve on B (leave running; note the printed line):

```bash
$K exec obio-te-b -- te-bench serve rdma $B 16 1048576
# SEGMENT <ip:port> ADDR <addr>
```

Pull from A:

```bash
$K exec obio-te-a -- te-bench pull rdma $A <ip:port> <addr> 16 1048576 200
```

Then the same with `tcp` in both commands for the TCP baseline. Compare with
datacore: TE over TCP between containers did 5.2 GB/s batched, p50 228 µs for
one 1 MiB shard.

## 3. ObjectIO across the nodes

```bash
kubectl --context prod-k8s apply -f deploy/rdma-test/20-objectio.yaml
$K wait --for=condition=Ready pod/obio-meta pod/obio-osds pod/obio-gw-rdma pod/obio-gw-grpc --timeout=10m
$K logs job/obio-meta-init          # "HTTP 200" (or 409: already initialised)
```

Same OSDs, two gateways: `obio-gw-rdma` moves shards over RDMA, `obio-gw-grpc`
as gRPC bytes. Each listens on 127.0.0.1 only; the benchmark runs inside it.

```bash
$K exec obio-gw-rdma -- objectio-s3-bench --endpoint http://127.0.0.1:19000 --size 4MiB --objects 200 --concurrency 1
$K exec obio-gw-grpc -- objectio-s3-bench --endpoint http://127.0.0.1:19010 --size 4MiB --objects 200 --concurrency 1
# then --concurrency 16 --objects 500, and --size 64KiB --objects 2000 --concurrency 32
```

Alternate the two, and repeat a few rounds, before calling a difference.
Check the RDMA gateway really used RDMA:

```bash
$K exec obio-gw-rdma -- curl -s http://127.0.0.1:19000/metrics   # look for:
#   objectio_gateway_shard_transfers_total{direction=…,transport="rdma"}  > 0
#   objectio_gateway_rdma_fallbacks_total                                 absent or 0
```

**NVMe.** `osd-data` is a hostPath, `/mnt/kvcache/obio-rdma-test`, on
compute-07's Mooncake spill drive (a PM1733a; the node's other seven are
Longhorn's). Use it only while `mooncake-store-gpu-compute-07` is scaled to
zero, and remove the directory before the store comes back (see below). The
store's check refuses to start unless the drive has 12 TiB free.

## 4. Tear down

```bash
kubectl --context prod-k8s delete ns obio-rdma-test
```

Deleting the namespace leaves the OSD disk files in
`/mnt/kvcache/obio-rdma-test` on compute-07; clear that directory too.
