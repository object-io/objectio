# RDMA tests on the HGX cluster

Measures ObjectIO's Transfer Engine data path on real RNICs
(objectio-docs `architecture/design/rdma-data-plane.md`), in the
`obio-rdma-test` namespace of the `prod-k8s` cluster. That cluster is shared
with production:

- **Only `obio-rdma-test` is ours.** Never apply to, or delete from, any other
  namespace.
- Every pod is `build-preemptible`, so production workloads always win.
- The API gateway rejects shell text (`bash -c`, redirections, `/proc`). Nothing
  here uses a shell: manifests pass arguments directly, `$(VAR)` is expanded by
  Kubernetes, and every `kubectl exec` below runs a binary with plain arguments.
- The fabric is rail-optimised. Everything uses rail **mlx5_0**
  (`rdma/hca_gpu0`, `MC_TE_FILTERS=mlx5_0`); mismatched rails fail with
  "transport retry counter exceeded".

Nodes: `ihc-gpu-compute-05` (gateways, `obio-te-a`) and `ihc-gpu-compute-07`
(meta, OSDs, `obio-te-b`).

```bash
export KUBECONFIG=<path>/kubeconfig      # context prod-k8s
K="kubectl --context prod-k8s -n obio-rdma-test"
```

## 0. Namespace

`00-namespace.yaml` — privileged pod security, like the `mooncake` namespace
(hostNetwork and IPC_LOCK need it). Deleting it removes everything below.

## 1. Image and pull secret

```bash
docker build -f deploy/rdma-test/Dockerfile.rdma-test -t <registry>/objectio-rdma-test:<tag> .
docker push <registry>/objectio-rdma-test:<tag>
```

Create a pull secret for that registry in `obio-rdma-test`, then set the
image and secret name in `10-*.yaml` and `20-*.yaml` (the `REPLACE-…` values).

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

**NVMe.** `osd-data` is an `emptyDir` on the node's ephemeral disk. For
numbers comparable to datacore's, replace it in `20-objectio.yaml` with a
`hostPath` on compute-07's NVMe — a directory of its own, agreed with whoever
owns that disk (the Mooncake stores spill to NVMe on these nodes too).

## 4. Tear down

```bash
kubectl --context prod-k8s delete ns obio-rdma-test
```
