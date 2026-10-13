# Multi-host chaos test

Roadmap A6. Six Incus VMs on one Linux lab host stand in for six
machines, each with its own kernel, network stack and block device:

| VM | meta | OSD | gateway |
|---|---|---|---|
| chaos-1, chaos-2 | ✓ | ✓ (its own disk) | ✓ |
| chaos-3 | ✓ | ✓ | |
| chaos-4 .. chaos-6 | | ✓ | |

4+2 erasure coding; meta runs repair every minute.

```bash
# Linux x86_64 objectio-meta, objectio-osd, objectio-gateway in <bin-dir>
deploy/chaos/cluster.sh up <bin-dir>
python3 deploy/chaos/chaos.py        # about 15 minutes
deploy/chaos/cluster.sh down
```

`chaos.py` runs S3 traffic through both gateways for the whole test and
injects, one at a time:

| Fault | How |
|---|---|
| meta-kill | SIGKILL the meta leader's process (systemd restarts it) |
| power-off | an OSD-only VM switched off for a minute |
| meta-power-off | a meta VM switched off for a minute |
| partition | the meta leader's VM cut off the network for a minute (its interface taken down) |
| disk-pull | an OSD's disk unplugged (the Incus device removed), the OSD set `out`, a new disk plugged in, the OSD back on it and set `in`; repair rebuilds what the old disk held |

and checks, after each:

- every write a gateway acknowledged reads back byte for byte;
- writes resume: no stretch longer than `MAX_GAP` (60 s) without one;
- a write that fails gets 503 (retry) or never reached a gateway: no 500;

and at the end, that repair restored full redundancy: pairs of OSDs are
stopped and every object sampled still reads back.

`FAULTS=meta-kill,partition` runs a subset; `HOLD` (60) sets how long a
fault lasts. Needs `sudo -n incus` and an Ubuntu 24.04 VM image (`IMAGE`,
default `images:ubuntu/24.04`).

## Soak

`soak.py` (roadmap B2) runs the same faults in turn, plus drive-lost (an
OSD's drive and its metadata gone for good, the OSD back on a new one
and the old one evacuated), for `SOAK_HOURS` (48), one every
`FAULT_EVERY` minutes (20). Twelve writers fill the cluster past the
OSDs' full ratio and delete it back down, over and over. Its docstring
lists the invariants. `SOAK_POOL=<name>` puts the bucket in a pool that
places through placement groups.

A fix to something a soak found goes through the quick soak first. It
runs the same faults, closer together and on less data, so a
drive-lost evacuation takes minutes, not an hour. That shows in two or
three hours what a 48 h soak would show in six to twenty:

```bash
SOAK_HOURS=3 FAULT_EVERY=5 FULL_HIGH=0.3 FULL_LOW=0.1 \
  STALL_MAX_SECS=900 NOT_CLEAN_MAX_SECS=3600 python3 deploy/chaos/soak.py
```

It never reaches the full ratio, so it doesn't test running full, and
restarts are fast on so little data. Only the 48 h soak passes B2.
