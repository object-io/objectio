---
name: objectio-deploy
description: Install, size, upgrade, monitor, back up and troubleshoot an ObjectIO deployment (the S3-compatible storage system in Rust -- meta Raft nodes, OSDs, gateways, block gateway) as the all-in-one objectio-aio, as binaries under systemd, or with the Helm chart on Kubernetes, including the choices that are hard to change later -- erasure code, failure domains, drives, mTLS, the SSE master key, auth and OIDC. Use when asked to deploy or stand up ObjectIO, pick an erasure code or hardware, write a values.yaml, roll a cluster to the next release and finalize it, set up Prometheus scraping, alerts and dashboards, back up meta and the encryption key, or work out why pods, writes or nodes are failing. Day-to-day administration with obioctl (tenants, users, keys, pools, buckets, repair) is the objectio-admin skill.
---

# Deploying and running ObjectIO

This is the person who installs and keeps the cluster up: hosts, disks,
`helm`, `kubectl`, systemd, Prometheus. What happens inside the cluster
afterwards -- tenants, users, keys, pools, buckets, replication, repair --
is the `objectio-admin` skill.

The full guides are at https://object-io.github.io/latest/ (list at the
end). This skill is the shape of the job and the things that go wrong.
0.x releases still change flags: check `<binary> --help` before using one.

## What gets deployed

| Component | Binary | Ports (cluster convention) | State |
|---|---|---|---|
| Gateway | `objectio-gateway` | 9000: S3, Iceberg REST, Delta Sharing, `/_admin/*`, `/_console/`, `/metrics` | Stateless (audit spool on local disk) |
| Meta | `objectio-meta` | 9100 gRPC + Raft, 9101 `/metrics`, 9102 Raft admin HTTP | Raft group on redb, 3 or 5 nodes |
| OSD | `objectio-osd` | 9200 gRPC, 9201 `/metrics` | One per drive: shards on it, index + WAL in `--data-dir` |
| Block gateway (optional) | `objectio-block-gateway` | 9300 gRPC, 10809 NBD, 9301 `/metrics` | Write journal in `--data-dir` |
| Admin CLI | `obioctl` | a client of `/_admin/*` on the gateway | -- |

Three ways to run it: **`objectio-aio`**, everything in one process (a
laptop, a demo, CI; no HA, not for production); **binaries under systemd**
on Linux (amd64 and arm64, both coding with ISA-L; they mix in one cluster); the
**Helm chart** `oci://ghcr.io/object-io/charts/objectio`, one image
`ghcr.io/object-io/objectio:<tag>` for every service. A release's
downloads are `objectio-aio-<tag>-{linux-amd64,linux-arm64,darwin-arm64}`;
every other binary is in the image. macOS runs aio only.

## Before installing: decide these, they are hard to change later

1. **Erasure code.** Meta's `--ec-k`/`--ec-m` (chart `ec.k`/`ec.m`; the
   same on every gateway) is the default pool's protection. **The chart
   defaults to `k: 1, m: 0`, no redundancy**; aio to replication 1. Use 4+2
   for 7-12 hosts, 8+4 from 13. A pool's protection, failure domain and PG
   count never change: another scheme later is a new pool (`objectio-admin`).
2. **Failure domains.** Meta makes the default pool once k+m OSDs are up
   and every registered one is (or 30 s have passed): over **hosts** if
   there are k+m of them, else over **single OSDs**, its PG count sized
   from the OSDs up then. So start the whole first set of OSD hosts
   together. The leader logs `default pool made: <n> PGs over hosts` (or
   `over nodes`); `obioctl cluster validate-placement default` shows
   `required_level`. An OSD's host is `[osd.failure_domain] host` (default
   the hostname; in the chart, the node). Plan k+m hosts plus one spare.
3. **Drives.** NVMe with power-loss protection, or a UPS per host: an ack
   means fsynced, and a volatile cache can still lose it in a power cut.
   One OSD per drive, its `--data-dir` on a small partition (about 2%) of
   the same drive, not the boot disk. Meta on a drive of its own. Leave
   the block size at the OSD's 4 KiB.
4. **mTLS between services.** `--tls-cert/--tls-key/--tls-ca` (env
   `OBJECTIO_TLS_CERT/KEY/CA`) everywhere, chart `tls.enabled`. Each
   certificate names its role in a SAN URI `spiffe://objectio/<role>`
   (`meta`, `osd`, `gateway`, `block-gateway`, `admin` for obioctl's block
   commands and meta's admin port; aio's names all five), and each call is
   checked against it. Without mTLS nothing internal is authenticated:
   meta 9100-9102, OSD 9200-9201 and block 9300/10809 must be reachable by
   ObjectIO alone (the chart's `networkPolicy`, on by default). A cluster
   can't run half on TLS: turning it on later restarts everything at once.
   Client TLS ends at the ingress or load balancer.
5. **The SSE master key.** `OBJECTIO_MASTER_KEY`, base64 of 32 bytes, on
   the gateways. It encrypts SSE-S3 objects and wraps local KMS keys: lose
   or change it and they are unreadable. `gateway.sse.enabled: true`
   generates it once into Secret `<fullname>-gateway-sse` (key
   `master-key`) and keeps it on upgrades; copy it out at once. `helm
   template` and GitOps tools can't see that Secret and render a new key
   each time: pin `gateway.sse.masterKey` there. `gateway.kms.backend:
   vault` keeps KMS keys in Vault Transit.
6. **Auth and addresses.** `gateway.noAuth` defaults to `true`: set
   `false`. `gateway.externalUrl` is the address handed out in Iceberg
   vended credentials, Delta Sharing URLs and the OIDC callback;
   `gateway.region` the SigV4 region clients sign with. OIDC:
   `gateway.oidc.issuerUrl`, `clientId`, `clientSecret` (a plain value:
   keep the values file private), `adminRoles`. `gateway.trustedProxies`:
   the ingress network, for `aws:SourceIp`/`aws:SecureTransport` policies.
7. **Meta size.** 3 nodes (5 to survive two at once), each on its own
   host. Never an even number.

## Installing

### aio

```bash
objectio-aio --data /var/lib/objectio-aio --osds 6 --ec-k 4 --ec-m 2 --auth --strict-port
```

`--auth` turns SigV4 on (off by default in aio) and prints the admin key
pair, kept in `<data>/meta/admin-creds.env`. `--strict-port` fails if the
port is taken; without it aio quietly binds another. Without `--data` all
is in a tempdir wiped on exit. `--block-port` adds the block gateway.
Container: `ghcr.io/object-io/objectio:<tag>` with command `objectio-aio`.

### Kubernetes (Helm)

Kubernetes 1.26+, a local-disk `ReadWriteOnce` StorageClass with
`WaitForFirstConsumer` (not NFS or local-path), cert-manager for the mTLS
certificate. A minimal production `values.yaml`:

```yaml
ec: {k: 4, m: 2}
meta:
  replicas: 3
  persistence: {size: 50Gi, storageClass: local-nvme}
osd:
  replicas: 7                       # k + m + 1, on at least 7 nodes
  persistence:
    data:  {size: 4Ti,   storageClass: local-nvme}
    state: {size: 100Gi, storageClass: local-nvme}   # index + WAL: see sizing
  failureDomain: {region: eu-west-1, datacenter: dc1, rack: rack1}
gateway:
  replicas: 3
  noAuth: false
  externalUrl: https://s3.example.com
  trustedProxies: "10.244.0.0/16"   # the ingress controller's pod network
  sse: {enabled: true}
  ingress:
    enabled: true
    className: nginx
    hosts: [{host: s3.example.com}]
    tls: [{hosts: [s3.example.com], secretName: s3-tls}]
tls:
  enabled: true
  certManager: {issuerRef: {name: objectio-ca, kind: Issuer}}   # a CA issuer; a certificate per role
networkPolicy:
  metricsFrom: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: monitoring}}}]
monitoring:
  prometheusRule: {enabled: true}   # for a prometheus-operator
```

```bash
helm show values oci://ghcr.io/object-io/charts/objectio --version <version>   # every key
helm install objectio oci://ghcr.io/object-io/charts/objectio --version <version> \
  -n objectio --create-namespace -f values.yaml
kubectl -n objectio rollout status statefulset/objectio-meta
kubectl -n objectio rollout status statefulset/objectio-osd
kubectl -n objectio rollout status deployment/objectio-gateway
kubectl -n objectio exec objectio-meta-0 -- cat /var/lib/objectio/meta/admin-creds.env
```

- Leave `--wait` off the first install (the kind script does): gateways
  turn Ready only once meta's Raft group exists, and the Job that forms
  it (`objectio-meta-raft-bootstrap`) is a post-install hook, which Helm
  runs after the wait.
- With release `objectio` the objects are `objectio-meta`, `-osd`,
  `-gateway`; with another release name, `<release>-objectio-*`.
- The chart version is the release version and pins the image. Offline:
  mirror `ghcr.io/object-io/objectio`, `curlimages/curl:8.10.1` (the
  bootstrap Job) and, for `monitoring.enabled`, `prom/prometheus` and
  `grafana/grafana`; set `global.imageRegistry`.
- Every OSD pod gets the same `osd.failureDomain`; its host is its node.
  The chart sets no affinity, so the StorageClass decides where pods land.
- On a laptop: `make kind-up` in a checkout (`PF_PORT=19000` if 9000 is
  taken; `make kind-down`). Auth off, local-path storage: never promote it.

### Linux binaries under systemd

`objectio-install` sets a host up: units carrying the flags the chart
passes, one OSD per disk (each with its TOML), and `cluster init` forms
meta's Raft group over the admin ports. As root, binaries in
`/usr/local/bin`:

```bash
# each host: its meta node id (1, 2, 3), the address the others reach it at,
# every meta node, its disks (blank: each OSD formats its own on first start)
objectio-install init --role all --node-id 1 --advertise node1 \
  --meta-endpoint http://node1:9100,http://node2:9100,http://node3:9100 \
  --disks /dev/disk/by-id/nvme-a,/dev/disk/by-id/nvme-b --ec-profile 4+2 --systemd
systemctl enable --now objectio-meta
# once, from any host (a lone meta needs it too); safe to repeat. Under mTLS
# add --tls-cert admin.pem --tls-key admin.key --tls-ca ca.pem (role admin),
# and give each unit its certificate with a drop-in (OBJECTIO_TLS_CERT/KEY/CA)
objectio-install cluster init node1 node2 node3
systemctl enable --now objectio-osd-0 objectio-osd-1 objectio-gateway
```

By hand, the same: meta and the gateway take flags only, the OSD its TOML
(and flags, which win). Run as a non-root user; OSDs need raw-disk access.

```bash
# each meta node (node-id 1, 2, 3)
objectio-meta --node-id 1 --listen 0.0.0.0:9100 --raft-advertise meta1:9100 \
  --data-dir /var/lib/objectio/meta --ec-k 4 --ec-m 2
# once, on meta1's admin port, form the group (a lone meta needs /init too).
# With mTLS it is HTTPS and takes a role-admin certificate:
#   curl --cacert ca.pem --cert admin.pem --key admin.key https://meta1:9102/...
curl -X POST http://meta1:9102/init
curl -X POST http://meta1:9102/add-learner -H 'content-type: application/json' -d '{"node_id": 2, "addr": "meta2:9100"}'
curl -X POST http://meta1:9102/add-learner -H 'content-type: application/json' -d '{"node_id": 3, "addr": "meta3:9100"}'
curl -X POST http://meta1:9102/change-membership -H 'content-type: application/json' -d '{"voters": [1, 2, 3]}'
curl http://meta1:9102/status
# one OSD per drive; a blank drive named in --disks is formatted by the OSD
objectio-osd --config /etc/objectio/osd-nvme1.toml --listen 0.0.0.0:9200 --advertise-addr http://osd1:9200 \
  --meta-endpoint http://meta1:9100,http://meta2:9100,http://meta3:9100 \
  --disks /dev/nvme1n1p2 --data-dir /var/lib/objectio/osd-nvme1 --metrics-port 9201
# gateways behind an L4 load balancer, OBJECTIO_MASTER_KEY in the unit's environment
objectio-gateway --listen 0.0.0.0:9000 --meta-endpoint http://meta1:9100,http://meta2:9100,http://meta3:9100 \
  --ec-k 4 --ec-m 2 --external-endpoint https://s3.example.com --no-reexport-metrics
```

- Give every client of meta **every** meta address. The OSD's failure
  domain is in its TOML: `[osd.failure_domain]` `region`, `datacenter`,
  `rack`, `zone`, `host`.
- Without `--advertise-addr` an OSD on `0.0.0.0` advertises `127.0.0.1`. A
  second OSD on a host needs its own `--listen` port and `--metrics-port`.
- A new master key: `openssl rand -base64 32`, kept outside the cluster.
- `objectio-install disk list` / `disk check <dev>` show drives. The
  gateway's unit reads `/etc/objectio/gateway.env` if present: put
  `OBJECTIO_MASTER_KEY` there, the same on every gateway.

Smoke test: `aws --endpoint-url <gateway> s3 mb s3://demo`, put and get an
object, then `obioctl node list` and `obioctl cluster validate-placement default`.

## Sizing

From the [sizing guide and calculator](https://object-io.github.io/latest/operations-guide/installation/hardware-sizing/).
Most figures are 0.x estimates: measure on your hardware before buying at scale.

| | Plan |
|---|---|
| Hosts | k+m+1: 7 for 4+2, 13 for 8+4, 15 for 10+4 |
| Usable capacity | raw x k/(k+m) x 0.95, less one host's worth for rebuilds; alert at 85% |
| OSD | 1.5 GB RAM per drive (`--meta-cache-mib`, 1 GiB by default, is most of it), one core per NVMe drive; 8 GB per host for the OS |
| Gateway | 4 GB plus 2 GB per GB/s; about 3 cores per GB/s of writes without NIC offload (the MD5 of every PUT sets the floor) |
| Meta | 16 GB RAM (32 GB past 500 million objects); disk 2.2 x its database, about 750 bytes per object |
| OSD index (`--data-dir`) | objects x (k+m) / drives x 1.5 KB per drive, more for small objects whose shards live there |
| Network | two ports per host, 25 GbE or faster, with room for rebuild traffic |

## Upgrading

One release to the next; to skip, go through each. A build from before
0.1.0 can't be upgraded: install fresh and copy the data across.

1. **Back up meta** (below) and read the release notes.
2. **Meta**: followers one at a time, the leader last (`state` in
   `curl <meta>:9102/status`). After each, wait until its `last_applied`
   is level with the others'.
3. **OSDs**, one failure domain at a time, each online in `obioctl node
   list` before the next. No drain: reads tolerate m missing shards.
4. **Gateways and block gateways**, in any order.
5. `obioctl upgrade status`: every node on the new release, no blockers.
   Nodes report every 30 s; one silent for 90 s blocks. Gateways can't be
   listed in advance: check that every one appears.
6. `obioctl upgrade finalize`, refused (409) while anything blocks.
   **There is no going back after it.** Before it, going back is the same
   steps in reverse order with the previous release.

On Kubernetes, `helm upgrade ... --version <next> -f values.yaml` (the
file, not `--reuse-values`) rolls meta, OSDs and gateways at once, and the
meta and OSD readiness probes only check the TCP port. To keep the order,
hold both StatefulSets first (`kubectl -n objectio patch statefulset
objectio-meta -p '{"spec":{"updateStrategy":{"rollingUpdate":{"partition":3}}}}'`,
its replica count), then lower `partition` by one per checked pod.

## Monitoring

| Process | Metrics | Health |
|---|---|---|
| Gateway | `:9000/metrics` (`--admin-listen` if set) | `/health` (liveness); `/_ready` (503 until meta and enough OSDs answer; a start-up gate that doesn't drop later) |
| Meta | `:9101/metrics` (`--metrics-port`, 0 off) | `:9101/health`; Raft state at `:9102/status` |
| OSD | `:9201/metrics` | `:9201/health` |
| Block gateway | `:9301/metrics` (`--metrics-listen`) | -- |

- A gateway re-exports meta's and the OSDs' metrics by default, so one
  target covers aio or a single gateway. With several, run them with
  `--no-reexport-metrics` (the chart does) and scrape every gateway, meta
  and OSD, or sums multiply.
- `monitoring.enabled` deploys a Prometheus and Grafana that scrape them
  and load the alert rules (change `monitoring.grafana.adminPassword`,
  default `objectio`). For your own, `monitoring.prometheusRule.enabled`
  publishes the rules; there are no ServiceMonitors, so add scrape jobs.
  Rules and dashboards: `deploy/helm/objectio/alerts/`, `deploy/monitoring/grafana/dashboards/`.
- `--prometheus-url` on the gateway (the chart doesn't set it) gives the
  console long ranges and makes `obioctl metrics query` work (503 without).
- Page someone on `objectio_objects_unreadable > 0` and
  `objectio_meta_raft_has_leader == 0`; then objects at risk, OSDs down,
  disks near full, clock skew. Nothing alerts on certificate expiry: use
  cert-manager's `certmanager_certificate_expiration_timestamp_seconds`.
- NTP everywhere: a gateway over 500 ms from meta's clock refuses writes
  (503) until back in step (`objectio_gateway_clock_skewed`). Logs go to
  stderr (`--log-level` or `RUST_LOG`); no tracing yet.

## Backups, and what is lost if

| Lost | What goes with it | Keep instead |
|---|---|---|
| The SSE master key | Every SSE-S3 and locally wrapped SSE-KMS object, for good | `kubectl -n objectio get secret objectio-gateway-sse -o jsonpath='{.data.master-key}' \| base64 -d` (aio: `<data>/master_key`), stored off the cluster |
| A meta majority, disks and all | Everything since the last meta backup: buckets, users and keys made since, block volumes' writes, objects packed since (objects written since read, and are listed again) | `obioctl meta export --file F` on a schedule and before every upgrade, stored off the cluster; restore with `objectio-meta restore` ([failure recovery](https://object-io.github.io/latest/operations-guide/operations/failure-recovery/)). Two of three metas lost with one intact: `objectio-meta force-single-voter` on the survivor, no backup needed |
| More than m shards of a stripe | Those objects | Enough hosts; a dead host set `out` within hours |
| A whole site | Whatever had not replicated | Bucket replication to a second ObjectIO cluster (`objectio-admin`) |
| The block gateway's journal disk | Block writes not yet flushed (a known gap) | -- |
| A gateway pod killed without a clean stop | Its undelivered audit events | Size the spool (`gateway.audit.spool.*`) |

`helm uninstall` keeps the PVCs; deleting them deletes the data.

## When something is wrong

| Symptom | Look at |
|---|---|
| OSD pods `Pending` | The PVC can't bind: `kubectl -n objectio describe pvc` |
| Meta crash-loops, or every write 503 after install | The Raft group wasn't formed: `kubectl -n objectio logs job/objectio-meta-raft-bootstrap` (gone once it succeeds), each meta's `:9102/status`. Re-run: `kubectl -n objectio delete job objectio-meta-raft-bootstrap`, then `helm upgrade` |
| Gateway never Ready | `curl <gateway>/_ready`: `meta_reachable`, `osds_reachable` against `osds_required` |
| Writes 503 | No meta leader (a majority must be up), a gateway's clock skewed, or no default pool yet (fewer than k+m OSDs up; meta logs `default pool not made yet`). Seconds of 503 in a failover are normal: clients retry |
| Writes 507 | An OSD past `--full-ratio` (95%): add capacity or delete data |
| A remote OSD registered at `127.0.0.1`, or `Metrics server error: Address already in use` | `--advertise-addr` missing; two OSDs on a host sharing `--metrics-port` |
| No redundancy | `ec.k: 1, m: 0` (the chart default) or aio without `--ec-k`; `obioctl cluster validate-placement default` |
| Spread over OSDs, not hosts | Fewer than k+m hosts were up when the pool was made. It can't change: a new pool, or reinstall before data goes in |
| `obioctl upgrade finalize` answers 409 | `obioctl upgrade status` names the blockers; a node just restarted may not have reported yet |
| Internal calls fail after a certificate renewal or expiry | Certificates are read at start: `kubectl -n objectio rollout restart statefulset/objectio-meta statefulset/objectio-osd deployment/objectio-gateway` |
| `Failed to connect to initial OSD` at gateway start | Harmless: it connects on demand |

Runbooks per alert (OSD down, disk swap, disks full, meta, repair) are in
[production](https://object-io.github.io/latest/operations-guide/operations/production/); their commands are `objectio-admin`'s.

## Do not

- Do not run production with `ec.m: 0`, `noAuth: true`, or fewer than k+m
  hosts. Placement doesn't refuse it; one failure then loses data.
- Do not trade durability for speed: no drives with a volatile cache and no
  power-loss protection, no OSDs on NFS or object-backed volumes, no
  raising `--full-ratio` to get writes going (it spends the room repair
  needs), no turning repair or scrub off (`--repair-interval-secs 0`,
  `--scrub-interval-secs 0`).
- Do not skip releases, or finalize before every node runs the new release
  and meta is backed up. Do not change, regenerate or lose the SSE key.
- Do not wipe disks (`objectio-install disk prepare --force`) or set OSDs
  `out` while objects are unreadable: bring every intact OSD back first.
- Do not run an even number of meta nodes, or scale meta down by lowering
  `meta.replicas`: change the membership first (`/change-membership`).
- Do not assume port 9000, or that a gateway on it is this cluster's: pass
  every address.
- Do not delete PVCs or `--data-dir`s, or edit `meta.redb`, unless the
  cluster is meant to be gone.
- Do not restart a gateway for clock skew; fix the clock.

## The full guides

Under https://object-io.github.io/latest/operations-guide/:

- `installation/` (paths, ports, requirements), `installation/quickstart/`
  (aio, containers), `installation/kubernetes/` (Helm, kind),
  `installation/linux/`, `installation/hardware-sizing/` (calculator),
  `installation/configuration/` (flags)
- `operations/production/` (checklist, alerts, runbooks),
  `operations/upgrades/`, `operations/monitoring/`, `operations/metrics/`,
  `operations/failure-recovery/`, `operations/meta-ha/`
- `administration/mtls/`, `administration/authentication/` (SigV4, OIDC, STS)
