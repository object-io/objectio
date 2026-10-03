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
