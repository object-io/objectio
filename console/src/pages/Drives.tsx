import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell as BarCell,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  ChevronDown,
  ChevronRight,
  Container,
  HardDrive,
  Layers3,
  MoreHorizontal,
  Plus,
  Search,
  Server,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import {
  Badge,
  Banner,
  Button,
  CapacityBar,
  ChartCard,
  Chip,
  Input,
  LegendDot,
  Table,
  Row,
  Cell,
  seriesColor,
} from "../components/ui";
import {
  nodes as nodesApi,
  hostProvider as hostProviderApi,
  type NodeInfo,
  type HostProviderInfo,
} from "../api/client";
import { capabilities, queryRange, type Series } from "../api/metrics";

function formatBytes(b: number): string {
  if (!b) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(b) / Math.log(1024)));
  const v = b / 1024 ** i;
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

function formatUptime(seconds: number): string {
  if (!seconds) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

interface TopoPath {
  region: string;
  zone: string;
  datacenter: string;
  rack: string;
}

interface Host {
  name: string;
  osds: NodeInfo[];
  total: number;
  used: number;
  shards: number;
  allOnline: boolean;
  path: TopoPath | null;
  labels: string[];
}

const AXIS = { fontSize: 10, fontFamily: "var(--oio-font-mono)", fill: "var(--oio-faint)" };
const TOOLTIP = {
  background: "var(--oio-surface)",
  border: "1px solid var(--oio-border-strong)",
  borderRadius: 8,
  fontSize: 11,
};

/// The balancer aims to keep every OSD within this band of the cluster mean;
/// the chart draws the band so a skewed OSD is visible as out-of-band rather
/// than merely "taller".
const BALANCER_BAND = 10;

interface Props {
  embedded?: boolean;
}

export default function Drives({ embedded = false }: Props = {}) {
  const [nodeList, setNodeList] = useState<NodeInfo[]>([]);
  const [paths, setPaths] = useState<Map<string, TopoPath>>(new Map());
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "issues">("all");
  const [groupByRack, setGroupByRack] = useState(true);
  const [provider, setProvider] = useState<HostProviderInfo | null>(null);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [latency, setLatency] = useState<Series[] | null>(null);
  const [promReady, setPromReady] = useState(false);

  const load = useCallback(() => {
    nodesApi
      .list()
      .then((data) => {
        const list = data.nodes || [];
        setNodeList(list);
        setExpanded(new Set(list.map((n) => n.kubernetes_node || n.hostname || n.node_name)));
      })
      .catch(() => setNodeList([]))
      .finally(() => setLoading(false));

    // The topology column is the failure domain the placement engine
    // actually uses, so read it from /_admin/topology rather than guessing
    // from the k8s node name.
    fetch("/_admin/topology")
      .then((r) => r.json())
      .then((t) => {
        const m = new Map<string, TopoPath>();
        for (const r of t.tree ?? [])
          for (const z of r.zones)
            for (const d of z.datacenters)
              for (const rk of d.racks)
                for (const h of rk.hosts)
                  m.set(h.host, {
                    region: r.region,
                    zone: z.zone,
                    datacenter: d.datacenter,
                    rack: rk.rack,
                  });
        setPaths(m);
      })
      .catch(() => setPaths(new Map()));
  }, []);

  useEffect(load, [load]);

  useEffect(() => {
    hostProviderApi
      .info()
      .then(setProvider)
      .catch(() =>
        setProvider({ provider: "noop", supports_add_host: false, supports_reboot: false })
      );
  }, []);

  useEffect(() => {
    let cancelled = false;
    capabilities()
      .then(async (c) => {
        if (cancelled || !c.prometheus) return;
        setPromReady(true);
        const s = await queryRange(
          "histogram_quantile(0.99, sum by (instance) (rate(objectio_osd_grpc_latency_seconds_bucket[5m])))",
          3600
        ).catch(() => [] as Series[]);
        if (!cancelled) setLatency(s);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const addHost = async () => {
    setError(null);
    setAdding(true);
    try {
      await hostProviderApi.addHosts(1);
      // A new OSD pod takes 5–15s to register; poll once so the host
      // appears without a manual refresh.
      setTimeout(load, 8000);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setAdding(false);
    }
  };

  const hosts: Host[] = useMemo(() => {
    const grouped = new Map<string, NodeInfo[]>();
    for (const osd of nodeList) {
      const key = osd.kubernetes_node || osd.hostname || osd.node_name;
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key)!.push(osd);
    }
    return [...grouped].map(([name, osds]) => {
      const first = osds[0];
      // There is no OSD tag field yet, so the labels are what the node
      // actually reports about itself. Naming them for what they are beats
      // an empty column.
      const labels = [
        first?.os_info ? first.os_info.split(" ")[0].toLowerCase() : "",
        first?.cpu_cores ? `${first.cpu_cores}c` : "",
        first?.memory_bytes ? formatBytes(first.memory_bytes) : "",
      ].filter(Boolean);
      return {
        name,
        osds,
        total: osds.reduce((s, n) => s + n.total_capacity, 0),
        used: osds.reduce((s, n) => s + n.used_capacity, 0),
        shards: osds.reduce((s, n) => s + n.shard_count, 0),
        allOnline: osds.every((n) => n.online),
        path: paths.get(name) ?? null,
        labels,
      };
    });
  }, [nodeList, paths]);

  // Fill distribution across every OSD, which is the thing the balancer
  // equalises. Sorted by name so the bars keep their position between
  // refreshes rather than reshuffling as fill changes.
  const fill = useMemo(() => {
    const rows = nodeList
      .map((n) => ({
        name: n.pod_name || n.node_name,
        pct: n.total_capacity > 0 ? (n.used_capacity / n.total_capacity) * 100 : 0,
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
    const mean = rows.length ? rows.reduce((s, r) => s + r.pct, 0) / rows.length : 0;
    const outliers = rows.filter((r) => Math.abs(r.pct - mean) > BALANCER_BAND).length;
    return { rows, mean, outliers };
  }, [nodeList]);

  const issues = hosts.filter((h) => !h.allOnline).length;

  const visible = hosts
    .filter((h) =>
      query
        ? h.name.toLowerCase().includes(query.toLowerCase()) ||
          h.osds.some((o) =>
            (o.pod_name || o.node_name).toLowerCase().includes(query.toLowerCase())
          )
        : true
    )
    .filter((h) => (filter === "issues" ? !h.allOnline : true));

  // Rack grouping reads off the real failure domain. Hosts with no topology
  // configured fall into one bucket rather than each becoming its own rack.
  const racks = useMemo(() => {
    if (!groupByRack) return null;
    const m = new Map<string, Host[]>();
    for (const h of visible) {
      const key = h.path?.rack || "(no rack)";
      if (!m.has(key)) m.set(key, []);
      m.get(key)!.push(h);
    }
    return [...m].sort((a, b) => a[0].localeCompare(b[0]));
  }, [groupByRack, visible]);

  const toggle = (name: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  const columns = [
    { key: "name", label: "Host / OSD" },
    { key: "status", label: "Status", className: "w-36" },
    { key: "topology", label: "Topology · reg / zone / dc / rack", className: "w-72" },
    { key: "capacity", label: "Capacity", className: "w-64" },
    { key: "labels", label: "Labels", className: "w-44" },
    { key: "actions", label: "", className: "w-12" },
  ];

  const latencyNames = (latency ?? []).map((s) => s.labels.instance ?? "osd");
  const latencyRows = useMemo(() => {
    const byTime = new Map<number, Record<string, number | string>>();
    (latency ?? []).forEach((s, i) => {
      for (const p of s.points) {
        const row = byTime.get(p.t) ?? {
          t: p.t,
          time: new Date(p.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        };
        row[latencyNames[i]] = p.v * 1000;
        byTime.set(p.t, row);
      }
    });
    return [...byTime.values()].sort((a, b) => Number(a.t) - Number(b.t));
  }, [latency, latencyNames]);

  return (
    <div className={embedded ? "" : "p-6"}>
      {!embedded && (
        <PageHeader
          title="Nodes & drives"
          description="Hosts, OSDs and the disks under them"
          action={
            <Button
              variant="primary"
              icon={<Plus size={13} />}
              disabled={adding || !provider?.supports_add_host}
              onClick={() => void addHost()}
              title={
                provider?.supports_add_host
                  ? "Scale the OSD StatefulSet by +1"
                  : "Requires a host provider — set --host-provider on the gateway"
              }
            >
              {adding ? "Adding…" : "Add host"}
            </Button>
          }
        />
      )}

      {error && (
        <Banner kind="err" className="mb-4">
          {error}
        </Banner>
      )}

      <div className="grid lg:grid-cols-2 gap-4 mb-4">
        <ChartCard
          title="OSD fill distribution"
          subtitle={
            fill.rows.length
              ? `percent used per OSD · balancer target ±${BALANCER_BAND}% of mean (${fill.mean.toFixed(
                  0
                )}%)${fill.outliers ? ` · ${fill.outliers} outside the band` : ""}`
              : "percent used per OSD"
          }
        >
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={fill.rows} margin={{ top: 4, right: 4, left: -8, bottom: 0 }}>
              <CartesianGrid stroke="var(--oio-border)" vertical={false} />
              <XAxis dataKey="name" tick={AXIS} tickLine={false} axisLine={false} minTickGap={24} />
              <YAxis
                tick={AXIS}
                tickLine={false}
                axisLine={false}
                width={40}
                domain={[0, 100]}
                tickFormatter={(v: number) => `${v}%`}
              />
              <Tooltip
                contentStyle={TOOLTIP}
                formatter={(v) => [`${Number(v).toFixed(1)}%`, "used"]}
                cursor={{ fill: "var(--oio-surface-2)" }}
              />
              <ReferenceLine
                y={fill.mean}
                stroke="var(--oio-muted)"
                strokeDasharray="3 3"
                label={{ value: "mean", position: "right", fontSize: 10, fill: "var(--oio-faint)" }}
              />
              <Bar dataKey="pct" isAnimationActive={false} radius={[2, 2, 0, 0]}>
                {fill.rows.map((r) => (
                  <BarCell
                    key={r.name}
                    // Out-of-band bars carry the warning colour so the skew
                    // the balancer is working on is visible without reading
                    // the axis.
                    fill={
                      Math.abs(r.pct - fill.mean) > BALANCER_BAND
                        ? "var(--oio-warn-dot)"
                        : seriesColor(0)
                    }
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard
          title="OSD write latency p99"
          subtitle="ms · last hour"
          legend={
            latencyNames.length > 1 ? (
              <div className="flex gap-3 flex-wrap">
                {latencyNames.slice(0, 4).map((n, i) => (
                  <LegendDot key={n} index={i} label={n} />
                ))}
              </div>
            ) : undefined
          }
        >
          {latencyRows.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={latencyRows} margin={{ top: 4, right: 4, left: -8, bottom: 0 }}>
                <CartesianGrid stroke="var(--oio-border)" vertical={false} />
                <XAxis dataKey="time" tick={AXIS} tickLine={false} axisLine={false} minTickGap={40} />
                <YAxis tick={AXIS} tickLine={false} axisLine={false} width={40} />
                <Tooltip contentStyle={TOOLTIP} />
                {latencyNames.slice(0, 4).map((n, i) => (
                  <Line
                    key={n}
                    type="monotone"
                    dataKey={n}
                    stroke={seriesColor(i)}
                    strokeWidth={2}
                    dot={false}
                    isAnimationActive={false}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[200px] flex flex-col items-center justify-center text-center px-6 gap-1.5">
              <code className="font-mono text-[11px] text-text-2 bg-surface-2 px-1.5 py-px rounded-[5px]">
                objectio_osd_grpc_latency_seconds
              </code>
              <p className="text-[11px] text-muted max-w-xs">
                {promReady
                  ? "Prometheus is configured but has no series for this — each OSD exports on its own :9201, and a single-process deployment only publishes the gateway's own metrics."
                  : "This needs Prometheus. Per-OSD latency is a histogram on each OSD's :9201 endpoint, which a browser cannot reach."}
              </p>
            </div>
          )}
        </ChartCard>
      </div>

      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <div className="w-full sm:w-64">
          <Input
            icon={<Search size={13} />}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search hosts or OSDs…"
          />
        </div>
        <div className="inline-flex rounded-control border border-border-strong overflow-hidden">
          {(
            [
              ["all", "All nodes"],
              ["issues", `Has issues ${issues}`],
            ] as const
          ).map(([k, label]) => (
            <button
              key={k}
              onClick={() => setFilter(k)}
              className={`h-8 px-3 text-[12px] font-medium ${
                filter === k ? "bg-surface-2 text-text" : "bg-surface text-muted hover:text-text"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="flex-1" />
        <button
          onClick={() => setGroupByRack((v) => !v)}
          className="inline-flex items-center gap-2 text-[12px] text-text-2"
        >
          <span
            className={`w-8 h-[18px] rounded-full transition-colors relative ${
              groupByRack ? "bg-accent" : "bg-border-strong"
            }`}
          >
            <span
              className={`absolute top-[2px] w-[14px] h-[14px] rounded-full bg-surface transition-all ${
                groupByRack ? "left-[16px]" : "left-[2px]"
              }`}
            />
          </span>
          Group by rack
        </button>
      </div>

      <Table
        columns={columns}
        loading={loading}
        empty={hosts.length === 0 ? "No hosts registered" : "No matches"}
      >
        {visible.length
          ? racks
            ? racks.flatMap(([rack, list]) => [
                <tr key={`rack:${rack}`} className="border-t border-border bg-surface-2/60">
                  <Cell colSpan={columns.length}>
                    <span className="flex items-center gap-2">
                      <Layers3 size={13} className="text-muted" />
                      <span className="font-mono text-[12px] text-text">{rack}</span>
                      <span className="text-[11px] text-muted">
                        · {list.reduce((n, h) => n + h.osds.length, 0)} OSDs
                      </span>
                    </span>
                  </Cell>
                </tr>,
                ...list.flatMap((h) => hostRows(h, expanded, toggle)),
              ])
            : visible.flatMap((h) => hostRows(h, expanded, toggle))
          : undefined}
      </Table>
    </div>
  );
}

/// One host row plus, when open, its OSD rows and each OSD's disks. Returned
/// as a flat array because a `<tbody>` cannot hold a fragment wrapper without
/// breaking the table's row striping.
function hostRows(
  host: Host,
  expanded: Set<string>,
  toggle: (n: string) => void
): React.ReactElement[] {
  const open = expanded.has(host.name);
  const down = host.osds.filter((o) => !o.online).length;
  const rows: React.ReactElement[] = [
    <Row key={host.name}>
      <Cell>
        <span className="flex items-center gap-2">
          <button
            onClick={() => toggle(host.name)}
            className="text-faint hover:text-text"
            aria-label={open ? "Collapse" : "Expand"}
          >
            {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </button>
          <Server size={14} className="text-muted shrink-0" />
          <span className="flex flex-col min-w-0">
            <span className="text-[13px] font-medium text-text truncate">{host.name}</span>
            <span className="text-[11px] text-muted truncate">
              {host.osds.length} OSD{host.osds.length === 1 ? "" : "s"}
              {host.shards ? ` · ${host.shards.toLocaleString()} shards` : ""}
            </span>
          </span>
        </span>
      </Cell>
      <Cell>
        <Badge kind={host.allOnline ? "ok" : down === host.osds.length ? "err" : "warn"}>
          {host.allOnline ? "Healthy" : `${down} down`}
        </Badge>
      </Cell>
      <Cell className="font-mono text-[11px]">
        {host.path
          ? `${host.path.region} / ${host.path.zone} / ${host.path.datacenter} / ${host.path.rack}`
          : "—"}
      </Cell>
      <Cell>
        <span className="flex items-center gap-2.5">
          <CapacityBar used={host.used} total={host.total} className="flex-1 min-w-20" />
          <span className="font-mono text-[11px] text-muted tabular-nums whitespace-nowrap">
            {formatBytes(host.used)} / {formatBytes(host.total)}
          </span>
        </span>
      </Cell>
      <Cell>
        <span className="flex items-center gap-1 flex-wrap">
          {host.labels.map((l) => (
            <Chip key={l} mono>
              {l}
            </Chip>
          ))}
        </span>
      </Cell>
      <Cell align="right">
        <span className="opacity-0 group-hover:opacity-100 transition-opacity">
          <MoreHorizontal size={13} className="text-muted inline" />
        </span>
      </Cell>
    </Row>,
  ];

  if (!open) return rows;

  for (const osd of host.osds) {
    const state = osd.admin_state ?? "in";
    rows.push(
      <Row key={osd.node_id}>
        <Cell>
          <span className="flex items-center gap-2 pl-7">
            <Container size={13} className="text-muted shrink-0" />
            <span className="font-mono text-[12px] text-text">
              {osd.pod_name || osd.node_name}
            </span>
            <span className="font-mono text-[11px] text-faint truncate">
              {osd.disks[0]?.path ?? osd.address.replace("http://", "")}
            </span>
          </span>
        </Cell>
        <Cell>
          <Badge kind={osd.online && state === "in" ? "ok" : osd.online ? "warn" : "err"}>
            {osd.online ? "up" : "down"} / {state}
          </Badge>
        </Cell>
        <Cell className="font-mono text-[11px] text-muted">
          {osd.address.replace("http://", "")} · up {formatUptime(osd.uptime_seconds)}
        </Cell>
        <Cell>
          <span className="flex items-center gap-2.5">
            <CapacityBar used={osd.used_capacity} total={osd.total_capacity} className="flex-1 min-w-20" />
            <span className="font-mono text-[11px] text-muted tabular-nums whitespace-nowrap">
              {formatBytes(osd.used_capacity)} / {formatBytes(osd.total_capacity)}
            </span>
          </span>
        </Cell>
        <Cell className="font-mono text-[11px] text-muted">
          {osd.shard_count.toLocaleString()} shards
        </Cell>
        <Cell />
      </Row>
    );

    for (const disk of osd.disks) {
      rows.push(
        <Row key={disk.disk_id}>
          <Cell>
            <span className="flex items-center gap-2 pl-14">
              <HardDrive
                size={12}
                className={disk.status === "healthy" ? "text-ok shrink-0" : "text-err shrink-0"}
              />
              <span className="font-mono text-[11px] text-muted truncate">
                {disk.path || disk.disk_id.slice(0, 8)}
              </span>
            </span>
          </Cell>
          <Cell>
            <Badge kind={disk.status === "healthy" ? "ok" : "err"}>{disk.status}</Badge>
          </Cell>
          <Cell />
          <Cell>
            <span className="flex items-center gap-2.5">
              <CapacityBar
                used={disk.used_capacity}
                total={disk.total_capacity}
                className="flex-1 min-w-20"
              />
              <span className="font-mono text-[11px] text-muted tabular-nums whitespace-nowrap">
                {formatBytes(disk.used_capacity)} / {formatBytes(disk.total_capacity)}
              </span>
            </span>
          </Cell>
          <Cell className="font-mono text-[11px] text-muted">
            {disk.shard_count.toLocaleString()} shards
          </Cell>
          <Cell />
        </Row>
      );
    }
  }

  return rows;
}
