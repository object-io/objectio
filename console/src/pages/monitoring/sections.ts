/// What the System views on the Monitoring page show: per section, the
/// tiles (readings right now) and charts, each chart as PromQL for a window
/// and as the same series computed from two live scrapes.

import {
  groupSum,
  quantile,
  rate,
  total,
  type Scrape,
} from "../../api/exposition";

// ── Formatting ───────────────────────────────────────────────────────────────

export type Unit = "ms" | "bytes" | "bytes/s" | "per_s" | "count";

function formatBytes(b: number): string {
  if (!Number.isFinite(b) || b <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const i = Math.min(
    units.length - 1,
    Math.floor(Math.log(b) / Math.log(1024)),
  );
  const v = b / 1024 ** i;
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function format(v: number, unit: Unit): string {
  if (!Number.isFinite(v)) return "—";
  switch (unit) {
    case "ms":
      return v >= 100
        ? `${v.toFixed(0)} ms`
        : `${v.toFixed(v >= 10 ? 1 : 2)} ms`;
    case "bytes":
      return formatBytes(v);
    case "bytes/s":
      return `${formatBytes(v)}/s`;
    case "per_s":
      return v >= 100 ? v.toFixed(0) : v.toFixed(v >= 10 ? 1 : 2);
    case "count":
      return Math.round(v).toLocaleString();
  }
}

function ago(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 90) return `${Math.round(seconds)}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

// ── Section definitions ──────────────────────────────────────────────────────

export interface Tile {
  label: string;
  sub: string;
  /// The reading, from the latest scrape (and the one before it, for
  /// readings that need a difference). `undefined`: not exported here.
  value: (cur: Scrape, prev?: Scrape) => string | undefined;
}

export interface Chart {
  title: string;
  subtitle: string;
  unit: Unit;
  /// PromQL, `$RATE` replaced by the window; one entry per named series,
  /// or a single query whose series are named by `legend`.
  prom: string | { name: string; query: string }[];
  legend?: (labels: Record<string, string>) => string;
  /// The same series from two consecutive live scrapes.
  live: (cur: Scrape, prev: Scrape) => Record<string, number>;
  /// Multiply values by this before display (seconds → ms).
  scale?: number;
}

export interface Section {
  key: string;
  label: string;
  intro: string;
  tiles: Tile[];
  charts: Chart[];
}

const ms = 1000;
const short = (id: string) => id.slice(0, 8);
const notOk = { code: (c: string) => c !== "OK" };

/// `name`'s value now, formatted, or undefined when not exported.
function gauge(name: string, unit: Unit) {
  return (cur: Scrape) => {
    const v = total(cur.samples, name);
    return v === undefined ? undefined : format(v, unit);
  };
}

/// A histogram's percentile over the last scrape interval.
function livePercentile(
  histogram: string,
  q: number,
  match?: Record<string, string>,
) {
  return (cur: Scrape, prev?: Scrape) => {
    if (!prev) return undefined;
    const v = quantile(cur, prev, histogram, q, undefined, match).value;
    return v === undefined ? "idle" : format(v * ms, "ms");
  };
}

export const SECTIONS: Section[] = [
  {
    key: "block",
    label: "Block storage",
    intro:
      "Block volumes served over NBD and gRPC. Every acknowledged write is journaled and fsynced; the flush loop then stores 4 MiB chunks as erasure-coded stripes.",
    tiles: [
      {
        label: "Unflushed data",
        sub: "journaled, not yet stored as stripes",
        value: gauge("objectio_block_cache_dirty_bytes", "bytes"),
      },
      {
        label: "Volumes",
        sub: "objectio_block_volumes_total",
        value: gauge("objectio_block_volumes_total", "count"),
      },
      {
        label: "Journal fsync p99",
        sub: "every write waits for one",
        value: livePercentile("objectio_block_journal_fsync_seconds", 0.99),
      },
      {
        label: "Flush failures",
        sub: "since start · retried",
        value: (cur) => {
          const g = groupSum(
            cur.samples,
            "objectio_block_chunks_flushed_total",
            "result",
          );
          return Object.keys(g).length === 0
            ? undefined
            : format(g.failed ?? 0, "count");
        },
      },
    ],
    charts: [
      {
        title: "Block operations",
        subtitle: "per second, by operation",
        unit: "per_s",
        prom: "sum by (op) (rate(objectio_block_io_seconds_count[$RATE]))",
        legend: (l) => l.op,
        live: (c, p) => rate(c, p, "objectio_block_io_seconds_count", "op"),
      },
      {
        title: "Block latency p99",
        subtitle: "milliseconds · read, write, trim (a flush waits for chunks to be stored)",
        unit: "ms",
        scale: ms,
        prom: 'histogram_quantile(0.99, sum by (op, le) (rate(objectio_block_io_seconds_bucket{op!="flush"}[$RATE])))',
        legend: (l) => l.op,
        live: (c, p) =>
          quantile(c, p, "objectio_block_io_seconds", 0.99, "op", { op: (o) => o !== "flush" }),
      },
      {
        title: "Block throughput",
        subtitle: "bytes per second, by operation",
        unit: "bytes/s",
        prom: "sum by (op) (rate(objectio_block_io_bytes_total[$RATE]))",
        legend: (l) => l.op,
        live: (c, p) => rate(c, p, "objectio_block_io_bytes_total", "op"),
      },
      {
        title: "Unflushed data",
        subtitle: "bytes journaled, not yet stored as stripes",
        unit: "bytes",
        prom: [
          { name: "dirty", query: "sum(objectio_block_cache_dirty_bytes)" },
        ],
        live: (c) => ({
          dirty: total(c.samples, "objectio_block_cache_dirty_bytes") ?? 0,
        }),
      },
      {
        title: "Chunk flushes",
        subtitle: "per second, by result",
        unit: "per_s",
        prom: "sum by (result) (rate(objectio_block_chunks_flushed_total[$RATE]))",
        legend: (l) => l.result,
        live: (c, p) =>
          rate(c, p, "objectio_block_chunks_flushed_total", "result"),
      },
      {
        title: "Journal fsync",
        subtitle: "milliseconds · p50 and p99",
        unit: "ms",
        scale: ms,
        prom: [
          {
            name: "p50",
            query:
              "histogram_quantile(0.5, sum by (le) (rate(objectio_block_journal_fsync_seconds_bucket[$RATE])))",
          },
          {
            name: "p99",
            query:
              "histogram_quantile(0.99, sum by (le) (rate(objectio_block_journal_fsync_seconds_bucket[$RATE])))",
          },
        ],
        live: (c, p) => ({
          ...rename(
            quantile(c, p, "objectio_block_journal_fsync_seconds", 0.5),
            "p50",
          ),
          ...rename(
            quantile(c, p, "objectio_block_journal_fsync_seconds", 0.99),
            "p99",
          ),
        }),
      },
      {
        title: "Block errors",
        subtitle: "per second, by operation",
        unit: "per_s",
        prom: "sum by (op) (rate(objectio_block_io_errors_total[$RATE]))",
        legend: (l) => l.op,
        live: (c, p) => rate(c, p, "objectio_block_io_errors_total", "op"),
      },
    ],
  },
  {
    key: "meta",
    label: "Metadata",
    intro:
      "The meta service: a Raft cluster that holds buckets, block volumes and placement. A write commits once a majority of meta nodes has it.",
    tiles: [
      {
        label: "Raft leader",
        sub: "a cluster without one accepts no writes",
        value: (cur) => {
          const v = total(cur.samples, "objectio_meta_raft_has_leader");
          if (v === undefined) return undefined;
          return v > 0 ? "elected" : "NONE";
        },
      },
      {
        label: "Term",
        sub: "rises with each election",
        value: gauge("objectio_meta_raft_term", "count"),
      },
      {
        label: "Applied index",
        sub: "Raft entries applied",
        value: gauge("objectio_meta_raft_applied_index", "count"),
      },
      {
        label: "Voters",
        sub: "meta nodes in the cluster",
        value: gauge("objectio_meta_raft_voters", "count"),
      },
    ],
    charts: [
      {
        title: "Meta calls",
        subtitle: "per second, busiest methods",
        unit: "per_s",
        prom: "topk(4, sum by (method) (rate(objectio_meta_grpc_requests_total[$RATE])))",
        legend: (l) => l.method,
        live: (c, p) =>
          top(rate(c, p, "objectio_meta_grpc_requests_total", "method"), 4),
      },
      {
        title: "Meta call latency",
        subtitle: "milliseconds · p50 and p99, all methods",
        unit: "ms",
        scale: ms,
        prom: [
          {
            name: "p50",
            query:
              "histogram_quantile(0.5, sum by (le) (rate(objectio_meta_grpc_latency_seconds_bucket[$RATE])))",
          },
          {
            name: "p99",
            query:
              "histogram_quantile(0.99, sum by (le) (rate(objectio_meta_grpc_latency_seconds_bucket[$RATE])))",
          },
        ],
        live: (c, p) => ({
          ...rename(
            quantile(c, p, "objectio_meta_grpc_latency_seconds", 0.5),
            "p50",
          ),
          ...rename(
            quantile(c, p, "objectio_meta_grpc_latency_seconds", 0.99),
            "p99",
          ),
        }),
      },
      {
        title: "Durable commits",
        subtitle: "milliseconds · p99 of a redb commit (fsync)",
        unit: "ms",
        scale: ms,
        prom: [
          {
            name: "p99",
            query:
              "histogram_quantile(0.99, sum by (le) (rate(objectio_meta_commit_seconds_bucket[$RATE])))",
          },
        ],
        live: (c, p) =>
          rename(quantile(c, p, "objectio_meta_commit_seconds", 0.99), "p99"),
      },
      {
        title: "Raft entries applied",
        subtitle: "per second",
        unit: "per_s",
        prom: [
          {
            name: "applied",
            query: "max(rate(objectio_meta_raft_applied_index[$RATE]))",
          },
        ],
        live: (c, p) =>
          rename(rate(c, p, "objectio_meta_raft_applied_index"), "applied"),
      },
      {
        title: "Replication lag",
        subtitle: "entries each follower is behind (leader's view)",
        unit: "count",
        prom: "max by (peer) (objectio_meta_raft_replication_lag_entries)",
        legend: (l) => `node ${l.peer}`,
        live: (c) =>
          prefix(
            groupSum(
              c.samples,
              "objectio_meta_raft_replication_lag_entries",
              "peer",
            ),
            "node ",
          ),
      },
      {
        title: "Meta call errors",
        subtitle: "per second, by method",
        unit: "per_s",
        prom: 'sum by (method) (rate(objectio_meta_grpc_requests_total{code!="OK"}[$RATE]))',
        legend: (l) => l.method,
        live: (c, p) =>
          rate(c, p, "objectio_meta_grpc_requests_total", "method", notOk),
      },
    ],
  },
  {
    key: "protection",
    label: "Data protection",
    intro:
      "Whether every stripe still has its redundancy. OSD scrubbers read every shard and check it; the meta repairer rebuilds what is missing or corrupt.",
    tiles: [
      {
        label: "Degraded objects",
        sub: "missing a shard, still readable",
        value: gauge("objectio_objects_degraded", "count"),
      },
      {
        label: "At-risk objects",
        sub: "one more loss from unreadable",
        value: gauge("objectio_objects_at_risk", "count"),
      },
      {
        label: "Last repair pass",
        sub: "the meta leader's repairer",
        value: (cur) => {
          const g = groupSum(
            cur.samples,
            "objectio_meta_repair_last_pass_timestamp_seconds",
          );
          if (!("value" in g)) return undefined;
          return g.value > 0 ? ago(cur.t / 1000 - g.value) : "not yet";
        },
      },
      {
        label: "Oldest scrub",
        sub: "least recently scrubbed OSD",
        value: (cur) => {
          const g = groupSum(
            cur.samples,
            "objectio_osd_scrub_last_pass_timestamp_seconds",
            "osd_id",
          );
          const ts = Object.values(g);
          if (ts.length === 0) return undefined;
          const oldest = Math.min(...ts);
          return oldest > 0 ? ago(cur.t / 1000 - oldest) : "not yet";
        },
      },
    ],
    charts: [
      {
        title: "Objects short of redundancy",
        subtitle: "degraded, at risk, unreadable",
        unit: "count",
        prom: [
          { name: "degraded", query: "max(objectio_objects_degraded)" },
          { name: "at risk", query: "max(objectio_objects_at_risk)" },
          { name: "unreadable", query: "max(objectio_objects_unreadable)" },
        ],
        live: (c) => ({
          degraded: total(c.samples, "objectio_objects_degraded") ?? 0,
          "at risk": total(c.samples, "objectio_objects_at_risk") ?? 0,
          unreadable: total(c.samples, "objectio_objects_unreadable") ?? 0,
        }),
      },
      {
        title: "Shards rebuilt",
        subtitle: "per second, by reason",
        unit: "per_s",
        prom: "sum by (reason) (rate(objectio_meta_repair_shards_rebuilt_total[$RATE]))",
        legend: (l) => l.reason,
        live: (c, p) =>
          rate(c, p, "objectio_meta_repair_shards_rebuilt_total", "reason"),
      },
      {
        title: "Corrupt shards",
        subtitle: "on OSDs, not yet rebuilt",
        unit: "count",
        prom: [{ name: "corrupt", query: "sum(objectio_osd_corrupt_shards)" }],
        live: (c) => ({
          corrupt: total(c.samples, "objectio_osd_corrupt_shards") ?? 0,
        }),
      },
      {
        title: "Scrub throughput",
        subtitle: "bytes read and checked per second",
        unit: "bytes/s",
        prom: [
          {
            name: "scrubbed",
            query: "sum(rate(objectio_osd_scrub_bytes_total[$RATE]))",
          },
        ],
        live: (c, p) =>
          rename(rate(c, p, "objectio_osd_scrub_bytes_total"), "scrubbed"),
      },
    ],
  },
  {
    key: "disks",
    label: "Disks & OSDs",
    intro:
      "Each shard write is written and synced to disk before it is acknowledged; the OSD's metadata goes through its own write-ahead log.",
    tiles: [
      {
        label: "OSDs up",
        sub: "answered the gateway's last poll",
        value: (cur) => {
          const up = total(cur.samples, "objectio_cluster_osds_up");
          const all = total(cur.samples, "objectio_cluster_osds_total");
          return up === undefined || all === undefined
            ? undefined
            : `${up} / ${all}`;
        },
      },
      {
        label: "Raw capacity used",
        sub: "across OSDs that answered",
        value: (cur) => {
          const used = total(cur.samples, "objectio_cluster_used_bytes");
          const cap = total(cur.samples, "objectio_cluster_capacity_bytes");
          return used === undefined || !cap
            ? undefined
            : `${((100 * used) / cap).toFixed(1)}%`;
        },
      },
      {
        label: "Shard sync p99",
        sub: "making a write durable",
        value: livePercentile("objectio_osd_disk_seconds", 0.99, {
          op: "sync",
        }),
      },
      {
        label: "Disk errors",
        sub: "since start · read, write, checksum",
        value: gauge("objectio_disk_errors_total", "count"),
      },
    ],
    charts: [
      {
        title: "Disk operation latency",
        subtitle: "milliseconds · p99, by operation",
        unit: "ms",
        scale: ms,
        prom: "histogram_quantile(0.99, sum by (op, le) (rate(objectio_osd_disk_seconds_bucket[$RATE])))",
        legend: (l) => l.op,
        live: (c, p) => quantile(c, p, "objectio_osd_disk_seconds", 0.99, "op"),
      },
      {
        title: "Shard write latency per OSD",
        subtitle: "milliseconds · p99 of WriteShard",
        unit: "ms",
        scale: ms,
        prom: 'histogram_quantile(0.99, sum by (osd_id, le) (rate(objectio_osd_grpc_latency_seconds_bucket{method="WriteShard"}[$RATE])))',
        legend: (l) => short(l.osd_id ?? "osd"),
        live: (c, p) =>
          shortKeys(
            quantile(
              c,
              p,
              "objectio_osd_grpc_latency_seconds",
              0.99,
              "osd_id",
              { method: "WriteShard" },
            ),
          ),
      },
      {
        title: "OSD metadata WAL fsync",
        subtitle: "milliseconds · p99",
        unit: "ms",
        scale: ms,
        prom: [
          {
            name: "p99",
            query:
              "histogram_quantile(0.99, sum by (le) (rate(objectio_osd_wal_fsync_seconds_bucket[$RATE])))",
          },
        ],
        live: (c, p) =>
          rename(quantile(c, p, "objectio_osd_wal_fsync_seconds", 0.99), "p99"),
      },
      {
        title: "Disk throughput",
        subtitle: "bytes per second, all OSDs",
        unit: "bytes/s",
        prom: [
          {
            name: "written",
            query: "sum(rate(objectio_disk_written_bytes_total[$RATE]))",
          },
          {
            name: "read",
            query: "sum(rate(objectio_disk_read_bytes_total[$RATE]))",
          },
        ],
        live: (c, p) => ({
          ...rename(rate(c, p, "objectio_disk_written_bytes_total"), "written"),
          ...rename(rate(c, p, "objectio_disk_read_bytes_total"), "read"),
        }),
      },
      {
        title: "OSD call errors",
        subtitle: "per second, by method",
        unit: "per_s",
        prom: 'sum by (method) (rate(objectio_osd_grpc_requests_total{code!="OK"}[$RATE]))',
        legend: (l) => l.method,
        live: (c, p) =>
          rate(c, p, "objectio_osd_grpc_requests_total", "method", notOk),
      },
    ],
  },
];

function rename(
  g: Record<string, number>,
  name: string,
): Record<string, number> {
  return "value" in g ? { [name]: g.value } : {};
}

function prefix(g: Record<string, number>, p: string): Record<string, number> {
  return Object.fromEntries(Object.entries(g).map(([k, v]) => [`${p}${k}`, v]));
}

function shortKeys(g: Record<string, number>): Record<string, number> {
  return Object.fromEntries(Object.entries(g).map(([k, v]) => [short(k), v]));
}

function top(g: Record<string, number>, n: number): Record<string, number> {
  return Object.fromEntries(
    Object.entries(g)
      .sort((a, b) => b[1] - a[1])
      .slice(0, n),
  );
}
