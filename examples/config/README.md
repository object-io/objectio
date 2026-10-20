# ObjectIO OSD Configuration Examples

Example `osd.toml` files for different deployment topologies. Only the OSD
reads a config file; meta and the gateway are configured by flags (see the
operations guide's configuration reference). `objectio-install init` writes
these files for a host, one OSD per disk.

## Topology Overview

Each OSD reports its **failure domain** on registration, and placement
spreads each object's shards (or copies) across different failure domains.

### Failure Domain Hierarchy

```
region (us-east)
└── datacenter (dc1)
    └── rack (rack-01)
        └── host (osd-node1)
            └── OSD
```

An OSD is the smallest failure domain: it holds at most one shard of a
stripe, however many disks it has. A k+m erasure code needs k+m OSDs.

### How Placement Works

1. OSD starts and reads its `[osd.failure_domain]` from config
2. OSD registers with metadata service, reporting its failure domain
3. Metadata service builds the cluster topology
4. The default pool spreads each placement group's shards over hosts when
   there are k+m of them, else over OSDs; a pool made with
   `failure_domain = "rack"` puts no two shards of an object in one rack.

## Directory Structure

```
config/
├── single-node/          # One server, one OSD with several disks
│   └── osd.toml
│
├── three-nodes/          # Three servers in different racks
│   ├── node1-osd.toml
│   ├── node2-osd.toml
│   └── node3-osd.toml
│
└── multi-rack-lrc/       # Servers across racks, for LRC codes
    └── osd-rack1-node1.toml
```

## Deployment Scenarios

### Single Node (Development / Small Scale)

**Hardware:** 1 server with several NVMe drives

**Config:** `single-node/osd.toml`

```toml
[osd.failure_domain]
region = "default"
datacenter = "dc1"
rack = "rack1"
```

One OSD with all the drives holds one copy of each object: run meta with
`--replication 1`. To erasure-code on one server (`4+2` survives two drive
failures, not the server's), run one OSD per drive, each with its own
config, port and data directory, as `objectio-install init` sets up.

### Three Nodes (Production Small)

**Hardware:** 3 servers, in different racks

**Config:** `three-nodes/node{1,2,3}-osd.toml`

```toml
# node1-osd.toml
[osd.failure_domain]
region = "us-east"
datacenter = "dc1"
rack = "rack-01"   # Different rack per node!

# node2-osd.toml
[osd.failure_domain]
region = "us-east"
datacenter = "dc1"
rack = "rack-02"

# node3-osd.toml
[osd.failure_domain]
region = "us-east"
datacenter = "dc1"
rack = "rack-03"
```

With one OSD per node: `2+1`, which survives one node or rack. Wider codes
need more OSDs (one per drive): a code of k+m shards across three hosts
puts several shards on a host.

### Multi-Rack LRC (Large Scale)

**Hardware:** servers across multiple racks

**Config:** `multi-rack-lrc/osd-*.toml`

**LRC** `6+2+2`: 6 data shards, 2 local parity, 2 global parity, on at
least 10 OSDs. A single lost shard is rebuilt from 3 others rather than 6.

## Key Configuration Fields

### `[osd.failure_domain]`

| Field        | Description                          | Example        |
|--------------|--------------------------------------|----------------|
| `region`     | Geographic region                    | `us-east`      |
| `zone`       | Availability zone                    | `us-east-1a`   |
| `datacenter` | Data center                          | `dc1`          |
| `rack`       | Physical rack or network segment     | `rack-01`      |
| `host`       | The machine; its hostname when unset | `osd-node1`    |

### `weight`

Read, but placement doesn't use it yet: every OSD weighs the same.

## Quick Start

1. Copy the appropriate example to `/etc/objectio/osd.toml`
2. Edit the failure domain to match your topology
3. Update the disk paths
4. Start the OSD: `objectio-osd --config /etc/objectio/osd.toml`

```bash
# Example: Node 2 in a three-node deployment
cp examples/config/three-nodes/node2-osd.toml /etc/objectio/osd.toml

# Edit failure domain and disks
vim /etc/objectio/osd.toml

# Start
objectio-osd --config /etc/objectio/osd.toml
```

## Verification

After starting OSDs, verify the topology:

```bash
# Check registered OSDs and their failure domains. obioctl talks to
# the gateway's admin API, signed with the admin key:
export OBJECTIO_ENDPOINT=http://gateway:9000
export OBJECTIO_ACCESS_KEY=... OBJECTIO_SECRET_KEY=...
obioctl cluster topology
obioctl node list

# Example output (cluster topology):
# 3 OSD(s): 1 region(s), 1 zone(s), 1 datacenter(s), 3 rack(s), 3 host(s)
#   region us-east
#     zone (none)
#       datacenter dc1
#         rack rack-01
#           host osd-node1
#             osd 3e3cbac67af045cd988f9bb353941aed
#         ...
```
