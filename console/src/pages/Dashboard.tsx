import { useCallback, useEffect, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity, RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";
import PageHeader from "../components/PageHeader";
import {
  Badge,
  Banner,
  Button,
  CapacityBar,
  Card,
  ChartCard,
  Chip,
  LegendDot,
  StatTile,
} from "../components/ui";
import { seriesColor } from "../components/ui/chart-series";
import { cluster, nodes as nodesApi, type NodeInfo } from "../api/client";
import {
  LIVE_INTERVAL_MS,
  QUERIES,
  capabilities,
  queryInstant,
  queryRange,
  withRate,
  type MetricsCapabilities,
  type Series,
} from "../api/metrics";

const DAY = 86_400;
const AXIS = { fontSize: 10, fontFamily: "var(--oio-font-mono)", fill: "var(--oio-faint)" };
const TOOLTIP = {
  background: "var(--oio-surface)",
  border: "1px solid var(--oio-border-strong)",
  borderRadius: 8,
  fontSize: 11,
};

/// Join Prometheus series into the row-per-timestamp shape Recharts wants,
/// keyed by a label so each series keeps its identity across the join.
function rows(series: Series[], key: string) {
  const names = series.map((s, i) => s.labels[key] ?? `series ${i + 1}`);
  const byTime = new Map<number, Record<string, number | string>>();
  series.forEach((s, i) => {
    for (const pt of s.points) {
      const row = byTime.get(pt.t) ?? {
        t: pt.t,
        time: new Date(pt.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      row[names[i]] = pt.v;
      byTime.set(pt.t, row);
    }
  });
  return { names, data: [...byTime.values()].sort((a, b) => Number(a.t) - Number(b.t)) };
}

/// Read one counter from the Prometheus text exposition.
function counter(text: string, name: string, label?: [string, string]): number {
  const sel = label ? `\\{[^}]*${label[0]}="${label[1]}"[^}]*\\}` : "(?:\\{[^}]*\\})?";
  const m = text.match(new RegExp(`^${name}${sel}\\s+(\\S+)`, "m"));
  return m ? Number.parseFloat(m[1]) : 0;
}

/// Sum every sample of a counter family, whatever its labels — the total
/// across operations rather than any one of them.
function counterSum(text: string, name: string): number {
  let total = 0;
  for (const line of text.split("\n")) {
    if (line.startsWith(name) && !line.startsWith("#")) {
      const v = Number.parseFloat(line.slice(line.lastIndexOf(" ") + 1));
      if (Number.isFinite(v)) total += v;
    }
  }
  return total;
}

function bytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

interface Spark {
  v: number;
}

export default function Dashboard() {
  const [caps, setCaps] = useState<MetricsCapabilities | null>(null);
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [nodeList, setNodeList] = useState<NodeInfo[]>([]);
  const [pools, setPools] = useState<{ name: string; scheme?: string; used?: number; total?: number }[]>([]);
  const [license, setLicense] = useState<{ tier?: string; licensee?: string } | null>(null);
  const [rebalance, setRebalance] = useState<string>("");
  const [rates, setRates] = useState<{ req: number; err: number; bytes: number }>({ req: 0, err: 0, bytes: 0 });
  const [spark, setSpark] = useState<Record<string, Spark[]>>({ req: [], err: [], bytes: [] });
  const [protection, setProtection] = useState({ data: 0, parity: 0 });
  const [p99, setP99] = useState<number | null>(null);
  const [p50, setP50] = useState<number | null>(null);
  const [reqSeries, setReqSeries] = useState<Series[]>([]);
  const [latSeries, setLatSeries] = useState<Series[]>([]);
  // Previous counter reading, held only to difference against the next one.
  const [, setPrev] = useState<Record<string, number> | null>(null);

  const load = useCallback(async () => {
    cluster.health().then(setHealthy).catch(() => setHealthy(false));
    nodesApi.list().then((d) => setNodeList(d.nodes ?? [])).catch(() => setNodeList([]));
    fetch("/_admin/pools")
      .then((r) => r.json())
      .then((d) => setPools(Array.isArray(d) ? d : (d.pools ?? [])))
      .catch(() => setPools([]));
    fetch("/_admin/license").then((r) => r.json()).then(setLicense).catch(() => setLicense(null));
    fetch("/_admin/rebalance-status")
      .then((r) => r.json())
      .then((d) => setRebalance(d.running ? "rebalancing" : "idle"))
      .catch(() => setRebalance(""));
  }, []);

  const sampleMetrics = useCallback(async () => {
    try {
      const text = await cluster.metrics();
      setProtection({
        data: counter(text, "objectio_gateway_protection_data_shards"),
        parity: counter(text, "objectio_gateway_protection_parity_shards"),
      });
      const now = {
        req: counterSum(text, "objectio_s3_requests_total"),
        err: counter(text, "objectio_s3_requests_total", ["status", "server_error"]),
        bytes:
          counterSum(text, "objectio_s3_response_bytes_total") +
          counterSum(text, "objectio_s3_request_bytes_total"),
      };
      setPrev((p) => {
        if (p) {
          const per = LIVE_INTERVAL_MS / 1000;
          // A counter that went backwards means the process restarted; report
          // zero rather than a large negative rate.
          const d = (k: keyof typeof now) => (now[k] < p[k] ? 0 : (now[k] - p[k]) / per);
          const next = { req: d("req"), err: d("err"), bytes: d("bytes") };
          setRates(next);
          setSpark((s) => ({
            req: [...s.req, { v: next.req }].slice(-24),
            err: [...s.err, { v: next.err }].slice(-24),
            bytes: [...s.bytes, { v: next.bytes }].slice(-24),
          }));
        }
        return now;
      });
    } catch {
      // A missed sample is a gap, not a failure of the page.
    }
  }, []);

  // The 24h panels and the latency percentiles are the parts of this screen
  // that cannot come from a browser polling /metrics: a quantile is computed
  // from the histogram by Prometheus, and a day of history is history.
  const loadHistory = useCallback(async () => {
    const [ops, lat50, lat99, now99, now50] = await Promise.all([
      queryRange(withRate(QUERIES.requestsByOperation, DAY), DAY).catch(() => [] as Series[]),
      queryRange(withRate(QUERIES.latencyQuantile(0.5), DAY), DAY).catch(() => [] as Series[]),
      queryRange(withRate(QUERIES.latencyQuantile(0.99), DAY), DAY).catch(() => [] as Series[]),
      queryInstant(withRate(QUERIES.latencyQuantile(0.99), 300)).catch(() => [] as Series[]),
      queryInstant(withRate(QUERIES.latencyQuantile(0.5), 300)).catch(() => [] as Series[]),
    ]);
    setReqSeries(ops);
    setLatSeries([
      ...lat50.map((x) => ({ ...x, labels: { q: "p50" } })),
      ...lat99.map((x) => ({ ...x, labels: { q: "p99" } })),
    ]);
    const first = (s: Series[]) => s[0]?.points.at(-1)?.v;
    setP99(first(now99) ?? null);
    setP50(first(now50) ?? null);
  }, []);

  useEffect(() => {
    capabilities()
      .then((c) => {
        setCaps(c);
        if (c.prometheus) void loadHistory();
      })
      .catch(() => setCaps(null));
    void load();
    // Both are async and set state only after their awaits; the rule flags the
    // call because it cannot see past the function boundary.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void sampleMetrics();
    const t = setInterval(() => void sampleMetrics(), LIVE_INTERVAL_MS);
    return () => clearInterval(t);
  }, [load, sampleMetrics, loadHistory]);

  const disks = nodeList.flatMap((n) => n.disks ?? []);
  const totalCap = disks.reduce((a, d) => a + (d.total_capacity ?? 0), 0);
  const usedCap = disks.reduce((a, d) => a + (d.used_capacity ?? 0), 0);
  const online = nodeList.filter((n) => n.online).length;
  const shards = protection.data + protection.parity;
  const dataShare = shards > 0 ? protection.data / shards : 0;

  const req = rows(reqSeries, "operation");
  const lat = rows(latSeries, "q");

  const tiles = [
    { label: "S3 requests / s", value: rates.req.toFixed(1), sub: "all operations", key: "req" },
    {
      label: "p99 latency",
      // A percentile has no meaning without the histogram, and the browser
      // only sees running totals — so this is blank rather than wrong when
      // Prometheus is not wired.
      value: p99 == null ? "—" : `${(p99 * 1000).toFixed(0)} ms`,
      sub: p50 == null ? "needs Prometheus" : `p50 ${(p50 * 1000).toFixed(0)} ms`,
      key: "",
    },
    { label: "Throughput", value: `${bytes(rates.bytes)}/s`, sub: "request + response", key: "bytes" },
    { label: "Errors (5xx) / s", value: rates.err.toFixed(2), sub: "server_error", key: "err" },
    { label: "OSDs up", value: `${online} / ${nodeList.length}`, sub: `${disks.length} disks`, key: "" },
  ];

  return (
    <div className="p-6">
      <PageHeader
        title="Dashboard"
        description={
          nodeList.length
            ? `${nodeList.length} host${nodeList.length === 1 ? "" : "s"} · ${disks.length} disk${disks.length === 1 ? "" : "s"} · ${bytes(totalCap)} raw`
            : "Cluster overview"
        }
        action={
          <div className="flex gap-2">
            <Button variant="secondary" icon={<RefreshCw size={13} />} onClick={() => void load()}>
              Refresh
            </Button>
            <Link to="/monitoring">
              <Button variant="primary" icon={<Activity size={13} />}>
                Open monitoring
              </Button>
            </Link>
          </div>
        }
      />

      <Banner
        kind={healthy === false ? "err" : "ok"}
        className="mb-4"
        title={healthy === false ? "Gateway is not answering health checks" : "All systems operational"}
      >
        {[
          license?.tier ? `license ${license.tier}` : null,
          rebalance ? `balancer ${rebalance}` : null,
          `${online}/${nodeList.length || 0} OSDs online`,
        ]
          .filter(Boolean)
          .join(" · ")}
      </Banner>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 mb-4">
        {tiles.map((t) => (
          <StatTile
            key={t.label}
            label={t.label}
            value={t.value}
            sub={t.sub}
            spark={
              t.key && spark[t.key]?.length > 1 ? (
                <div className="w-[120px] h-[26px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={spark[t.key]}>
                      <YAxis hide domain={["dataMin", "dataMax"]} />
                      <Line
                        type="monotone"
                        dataKey="v"
                        stroke={seriesColor(0)}
                        strokeWidth={1.5}
                        dot={false}
                        isAnimationActive={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              ) : undefined
            }
          />
        ))}
      </div>

      <div className="grid lg:grid-cols-2 gap-4 mb-4">
        <ChartCard
          title="S3 request rate"
          subtitle="requests per second · 24h"
          legend={
            req.names.length ? (
              <div className="flex gap-3 flex-wrap">
                {req.names.slice(0, 4).map((n, i) => (
                  <LegendDot key={n} index={i} label={n} />
                ))}
              </div>
            ) : undefined
          }
        >
          {req.data.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={req.data} margin={{ top: 4, right: 4, left: -8, bottom: 0 }}>
                <CartesianGrid stroke="var(--oio-border)" vertical={false} />
                <XAxis dataKey="time" tick={AXIS} tickLine={false} axisLine={false} minTickGap={40} />
                <YAxis tick={AXIS} tickLine={false} axisLine={false} width={44} />
                <Tooltip contentStyle={TOOLTIP} />
                {req.names.slice(0, 4).map((n, i) => (
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
            <NeedsHistory promReady={caps?.prometheus === true} />
          )}
        </ChartCard>

        <ChartCard
          title="Request latency"
          subtitle="milliseconds · 24h"
          legend={
            <div className="flex gap-3">
              {["p50", "p99"].map((n, i) => (
                <LegendDot key={n} index={i} label={n} />
              ))}
            </div>
          }
        >
          {lat.data.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={lat.data} margin={{ top: 4, right: 4, left: -8, bottom: 0 }}>
                <CartesianGrid stroke="var(--oio-border)" vertical={false} />
                <XAxis dataKey="time" tick={AXIS} tickLine={false} axisLine={false} minTickGap={40} />
                <YAxis
                  tick={AXIS}
                  tickLine={false}
                  axisLine={false}
                  width={44}
                  tickFormatter={(v) => `${(Number(v) * 1000).toFixed(0)}`}
                />
                <Tooltip
                  contentStyle={TOOLTIP}
                  formatter={(v) => [`${(Number(v) * 1000).toFixed(1)} ms`, ""]}
                />
                {["p50", "p99"].map((n, i) => (
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
            <NeedsHistory promReady={caps?.prometheus === true} />
          )}
        </ChartCard>
      </div>

      <div className="grid lg:grid-cols-4 gap-4">
        <Card title="Capacity">
          <p className="font-display text-[26px] leading-none font-semibold text-text tabular-nums">
            {bytes(usedCap)}
          </p>
          <p className="text-[11px] text-muted mt-1 mb-3">
            of {bytes(totalCap)} raw
            {totalCap > 0 && ` · ${((usedCap / totalCap) * 100).toFixed(1)}%`}
          </p>
          <CapacityBar used={usedCap} total={totalCap} />
          {shards > 0 && (
            <div className="flex items-center gap-3 mt-3 text-[11px] text-muted">
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ background: seriesColor(0) }} />
                Data {protection.data}
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-warn-dot" />
                Parity {protection.parity}
              </span>
              <span className="ml-auto">{(dataShare * 100).toFixed(0)}% usable</span>
            </div>
          )}
          {!caps?.prometheus && (
            <p className="mt-3 text-[11px] text-faint">
              A capacity trend needs Prometheus; this is the current reading.
            </p>
          )}
        </Card>

        <Card title="Pools · PG fill">
          {pools.length === 0 ? (
            <p className="text-[12px] text-muted">
              No pools defined.{" "}
              <Link to="/pools" className="text-accent">
                Create one
              </Link>
            </p>
          ) : (
            <div className="space-y-2.5">
              {pools.map((p) => (
                <div key={p.name} className="flex items-center gap-2">
                  <span className="font-mono text-[11px] text-text-2 w-20 truncate">{p.name}</span>
                  {p.scheme && <Chip mono>{p.scheme}</Chip>}
                  <CapacityBar used={p.used ?? 0} total={p.total ?? 0} className="flex-1" />
                  <span className="text-[11px] text-muted tabular-nums w-10 text-right">
                    {p.total ? `${Math.round(((p.used ?? 0) / p.total) * 100)}%` : "—"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Hosts">
          {nodeList.length === 0 ? (
            <p className="text-[12px] text-muted">No OSDs registered</p>
          ) : (
            <div className="space-y-2.5">
              {nodeList.slice(0, 6).map((n) => {
                const t = (n.disks ?? []).reduce((a, d) => a + d.total_capacity, 0);
                const u = (n.disks ?? []).reduce((a, d) => a + d.used_capacity, 0);
                return (
                  <div key={n.node_id} className="flex items-center gap-2">
                    <span className="font-mono text-[11px] text-text-2 flex-1 truncate">
                      {n.hostname || n.node_name}
                    </span>
                    <CapacityBar used={u} total={t} className="w-16" />
                    <span className="text-[11px] text-muted tabular-nums w-9 text-right">
                      {t ? `${Math.round((u / t) * 100)}%` : "—"}
                    </span>
                    <Badge kind={n.online ? "ok" : "err"}>{n.online ? "up" : "down"}</Badge>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        {/* The artboard shows a recent-events feed. Nothing records one: there
            is no event log endpoint, and inventing entries from whatever the
            page happens to know would be worse than saying so. */}
        <Card title="Recent events">
          <p className="text-[11px] text-muted">
            No event log yet. Balancer moves, licence changes and bucket
            lifecycle are not recorded anywhere the console can read, so this
            panel has no source.
          </p>
        </Card>
      </div>
    </div>
  );
}

/// Shown where a 24h panel has no data. A browser polling /metrics knows
/// nothing older than the moment the page opened, so an empty chart here
/// would read as "no traffic" rather than "no history".
function NeedsHistory({ promReady }: { promReady: boolean }) {
  return (
    <div className="h-[200px] flex flex-col items-center justify-center text-center px-6 gap-1.5">
      <code className="font-mono text-[11px] text-text-2 bg-surface-2 px-1.5 py-px rounded-[5px]">
        {promReady ? "no samples in the last 24h" : "--prometheus-url"}
      </code>
      <p className="text-[11px] text-muted max-w-xs">
        {promReady
          ? "Prometheus is wired but has not been scraping this long yet. The panel fills in as history accumulates."
          : "A day of history comes from Prometheus. Without it this screen can only show the live scrape, which starts when the page opens."}
      </p>
    </div>
  );
}
