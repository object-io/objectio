import { useCallback, useEffect, useRef, useState } from "react";
import {
  Line,
  LineChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ExternalLink, Pause, Play } from "lucide-react";
import PageHeader from "../components/PageHeader";
import { Banner, ChartCard, StatTile, Tabs } from "../components/ui";
import { LegendDot } from "../components/ui/ChartCard";
import { seriesColor } from "../components/ui/chart-series";
import { cluster } from "../api/client";
import {
  LIVE_INTERVAL_MS,
  MAX_LIVE_POINTS,
  PrometheusError,
  QUERIES,
  RANGES,
  capabilities,
  queryRange,
  withRate,
  type MetricsCapabilities,
  type Series,
} from "../api/metrics";

interface Point {
  t: number;
  time: string;
  [k: string]: string | number;
}

/// Read one counter out of the Prometheus text exposition, optionally matching
/// a label. Used only by the live view; the Prometheus path gets structured
/// data back and needs none of this.
function readCounter(text: string, name: string, label?: [string, string]): number {
  const sel = label ? `\\{[^}]*${label[0]}="${label[1]}"[^}]*\\}` : "(?:\\{[^}]*\\})?";
  const m = text.match(new RegExp(`^${name}${sel}\\s+(\\S+)`, "m"));
  return m ? Number.parseFloat(m[1]) : 0;
}

/// Turn Prometheus series into the row-per-timestamp shape Recharts wants,
/// keyed by a label so each series keeps its identity across the join.
function toRows(series: Series[], key: string): { rows: Point[]; names: string[] } {
  const names = series.map((s) => s.labels[key] ?? "value");
  const byTime = new Map<number, Point>();
  series.forEach((s, i) => {
    for (const p of s.points) {
      const row =
        byTime.get(p.t) ??
        ({ t: p.t, time: new Date(p.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) } as Point);
      row[names[i]] = p.v;
      byTime.set(p.t, row);
    }
  });
  return { rows: [...byTime.values()].sort((a, b) => a.t - b.t), names };
}

const AXIS = { fontSize: 10, fontFamily: "var(--oio-font-mono)", fill: "var(--oio-faint)" };

function chartAxes() {
  return (
    <>
      <CartesianGrid stroke="var(--oio-border)" vertical={false} />
      <XAxis dataKey="time" tick={AXIS} tickLine={false} axisLine={false} minTickGap={40} />
      <YAxis tick={AXIS} tickLine={false} axisLine={false} width={44} />
      <Tooltip
        contentStyle={{
          background: "var(--oio-surface)",
          border: "1px solid var(--oio-border-strong)",
          borderRadius: 8,
          fontSize: 11,
        }}
        cursor={{ stroke: "var(--oio-muted)", strokeDasharray: "3 3" }}
      />
    </>
  );
}

export default function Monitoring() {
  const [caps, setCaps] = useState<MetricsCapabilities | null>(null);
  const [range, setRange] = useState("5m");
  const [paused, setPaused] = useState(false);
  const [live, setLive] = useState<Point[]>([]);
  const [promData, setPromData] = useState<Record<string, Series[]>>({});
  const [promError, setPromError] = useState<PrometheusError | null>(null);
  const prev = useRef<Record<string, number>>({});
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const selected = RANGES.find((r) => r.key === range) ?? RANGES[0];
  const usingPrometheus = selected.needsPrometheus;

  // --- live scrape -------------------------------------------------------
  const scrape = useCallback(async () => {
    try {
      const text = await cluster.metrics();
      const now = Date.now();
      const current: Record<string, number> = {
        GetObject: readCounter(text, "objectio_s3_requests_total", ["operation", "GetObject"]),
        PutObject: readCounter(text, "objectio_s3_requests_total", ["operation", "PutObject"]),
        DeleteObject: readCounter(text, "objectio_s3_requests_total", ["operation", "DeleteObject"]),
        ListObjects: readCounter(text, "objectio_s3_requests_total", ["operation", "ListObjects"]),
        // The previous build read objectio_http_responses_total, which this
        // server does not export — the error chart was flat zero. Errors are a
        // status on the S3 counter.
        client_error: readCounter(text, "objectio_s3_requests_total", ["status", "client_error"]),
        server_error: readCounter(text, "objectio_s3_requests_total", ["status", "server_error"]),
        iceberg: readCounter(text, "objectio_iceberg_requests_total"),
      };
      const point: Point = {
        t: now,
        time: new Date(now).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" }),
      };
      for (const [k, v] of Object.entries(current)) {
        // Counters only go up; a drop means the process restarted, and
        // reporting the difference then would invent a huge negative spike.
        const p = prev.current[k];
        point[k] = p === undefined || v < p ? 0 : (v - p) / (LIVE_INTERVAL_MS / 1000);
      }
      prev.current = current;
      setLive((h) => [...h, point].slice(-MAX_LIVE_POINTS));
    } catch {
      // A failed scrape is a gap, not a reason to tear the page down.
    }
  }, []);

  // --- prometheus --------------------------------------------------------
  const loadRange = useCallback(async (seconds: number) => {
    const q = (s: string) => withRate(s, seconds);
    try {
      const [ops, p50, p95, p99, errs, iceberg, thru, osd] = await Promise.all([
        queryRange(q(QUERIES.requestsByOperation), seconds),
        queryRange(q(QUERIES.latencyQuantile(0.5)), seconds),
        queryRange(q(QUERIES.latencyQuantile(0.95)), seconds),
        queryRange(q(QUERIES.latencyQuantile(0.99)), seconds),
        queryRange(q(QUERIES.errorsByClass), seconds),
        queryRange(q(QUERIES.icebergOps), seconds),
        queryRange(q(QUERIES.throughputByInstance), seconds),
        queryRange(q(QUERIES.osdLatencyByInstance), seconds),
      ]);
      setPromData({ ops, p50, p95, p99, errs, iceberg, thru, osd });
      // Cleared on success rather than up front: a previous failure should stay
      // on screen while the retry is in flight, and clearing it synchronously
      // would be a setState inside the mount effect.
      setPromError(null);
    } catch (e) {
      setPromError(
        e instanceof PrometheusError ? e : new PrometheusError(String(e), "query_failed")
      );
    }
  }, []);

  useEffect(() => {
    capabilities().then(setCaps).catch(() => setCaps(null));
  }, []);

  useEffect(() => {
    if (usingPrometheus) {
      if (timer.current) clearInterval(timer.current);
      // `loadRange` is async and sets state only after its awaits, so nothing
      // here runs synchronously — the rule flags the call because it cannot
      // see past the function boundary.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      void loadRange(selected.seconds);
      return;
    }
    void scrape();
    timer.current = setInterval(() => {
      if (!paused) void scrape();
    }, LIVE_INTERVAL_MS);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [usingPrometheus, selected.seconds, paused, scrape, loadRange]);

  const promReady = caps?.prometheus === true;
  const latest = live.at(-1);

  // Tiles come from the live scrape in both modes: they are a "right now"
  // reading, and a range query would answer a different question.
  const tiles = [
    { label: "GET / s", value: latest ? latest.GetObject : 0, sub: "objectio_s3_requests_total" },
    { label: "PUT / s", value: latest ? latest.PutObject : 0, sub: "objectio_s3_requests_total" },
    { label: "Iceberg ops / s", value: latest ? latest.iceberg : 0, sub: "objectio_iceberg_requests_total" },
    { label: "Errors / s", value: latest ? Number(latest.client_error) + Number(latest.server_error) : 0, sub: "4xx + 5xx" },
  ];

  const opsRows = usingPrometheus ? toRows(promData.ops ?? [], "operation") : null;
  const errRows = usingPrometheus ? toRows(promData.errs ?? [], "status") : null;
  const thruRows = usingPrometheus ? toRows(promData.thru ?? [], "instance") : null;
  const osdRows = usingPrometheus ? toRows(promData.osd ?? [], "instance") : null;

  const latencyRows = usingPrometheus
    ? (() => {
        const merged = new Map<number, Point>();
        (["p50", "p95", "p99"] as const).forEach((k) => {
          for (const s of promData[k] ?? []) {
            for (const p of s.points) {
              const row =
                merged.get(p.t) ??
                ({ t: p.t, time: new Date(p.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) } as Point);
              row[k] = p.v * 1000; // seconds → ms
              merged.set(p.t, row);
            }
          }
        });
        return [...merged.values()].sort((a, b) => a.t - b.t);
      })()
    : null;

  return (
    <div className="p-6">
      <PageHeader
        title="Monitoring"
        description={
          usingPrometheus
            ? `From Prometheus · ${selected.label} window`
            : `Live scrape · ${LIVE_INTERVAL_MS / 1000}s · ${live.length}/${MAX_LIVE_POINTS} points`
        }
        action={
          <a
            href="/metrics"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 h-8 px-3 rounded-control border border-border-strong bg-surface text-[12px] font-medium text-text hover:bg-surface-2"
          >
            <ExternalLink size={13} /> Raw /metrics
          </a>
        }
      />

      <div className="flex items-center justify-between gap-3 mb-4 flex-wrap">
        <Tabs
          items={RANGES.map((r) => ({
            key: r.key,
            label: r.needsPrometheus && !promReady ? `${r.label} ·` : r.label,
          }))}
          value={range}
          onChange={(k) => {
            const opt = RANGES.find((r) => r.key === k);
            // Longer windows are not a richer version of the live view — they
            // are a different source. Without it, say so rather than showing an
            // empty chart.
            if (opt?.needsPrometheus && !promReady) return;
            setRange(k);
          }}
        />
        {!usingPrometheus && (
          <button
            onClick={() => setPaused((p) => !p)}
            className="inline-flex items-center gap-1.5 h-8 px-3 rounded-control border border-border-strong bg-surface text-[12px] font-medium text-text hover:bg-surface-2"
          >
            {paused ? <Play size={13} /> : <Pause size={13} />}
            {paused ? "Resume" : "Pause"}
          </button>
        )}
      </div>

      {!promReady && (
        <Banner kind="warn" className="mb-4" title="Showing the last five minutes">
          This gateway has no Prometheus configured, so history beyond the live
          scrape, and any series grouped by node or gateway, are unavailable.
          Set <code>--prometheus-url</code> to enable the longer ranges.
        </Banner>
      )}

      {promError && (
        <Banner kind="err" className="mb-4" title="Prometheus query failed">
          {promError.message}
        </Banner>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
        {tiles.map((t) => (
          <StatTile
            key={t.label}
            label={t.label}
            value={Number(t.value).toLocaleString(undefined, { maximumFractionDigits: 1 })}
            sub={t.sub}
          />
        ))}
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <ChartCard
          title="S3 requests by operation"
          subtitle="requests per second"
          legend={
            <div className="flex gap-3">
              {(usingPrometheus ? (opsRows?.names ?? []) : ["GetObject", "PutObject", "DeleteObject", "ListObjects"])
                .slice(0, 4)
                .map((n, i) => (
                  <LegendDot key={n} index={i} label={n} />
                ))}
            </div>
          }
        >
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={usingPrometheus ? (opsRows?.rows ?? []) : live}>
              {chartAxes()}
              {(usingPrometheus
                ? (opsRows?.names ?? [])
                : ["GetObject", "PutObject", "DeleteObject", "ListObjects"]
              )
                .slice(0, 4)
                .map((n, i) => (
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
        </ChartCard>

        <ChartCard
          title="S3 request latency"
          subtitle="milliseconds · from the duration histogram"
          legend={
            <div className="flex gap-3">
              {["p50", "p95", "p99"].map((n, i) => (
                <LegendDot key={n} index={i} label={n} />
              ))}
            </div>
          }
        >
          {usingPrometheus ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={latencyRows ?? []}>
                {chartAxes()}
                {["p50", "p95", "p99"].map((n, i) => (
                  <Line key={n} type="monotone" dataKey={n} stroke={seriesColor(i)} strokeWidth={2} dot={false} isAnimationActive={false} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <Unavailable reason="Percentiles are computed from the histogram by Prometheus; the live scrape reads only the running totals." />
          )}
        </ChartCard>

        <ChartCard title="Error responses" subtitle="per second · 4xx and 5xx">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={usingPrometheus ? (errRows?.rows ?? []) : live}>
              {chartAxes()}
              {(usingPrometheus ? (errRows?.names ?? []) : ["client_error", "server_error"]).map((n, i) => (
                <Bar key={n} dataKey={n} fill={seriesColor(i)} isAnimationActive={false} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Iceberg catalog operations" subtitle="objectio_iceberg_requests_total">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={usingPrometheus ? (toRows(promData.iceberg ?? [], "__name__").rows) : live}>
              {chartAxes()}
              <Bar dataKey={usingPrometheus ? "value" : "iceberg"} fill={seriesColor(0)} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Throughput per gateway" subtitle="response bytes per second, by instance">
          {usingPrometheus ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={thruRows?.rows ?? []}>
                {chartAxes()}
                {(thruRows?.names ?? []).slice(0, 4).map((n, i) => (
                  <Line key={n} type="monotone" dataKey={n} stroke={seriesColor(i)} strokeWidth={2} dot={false} isAnimationActive={false} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <Unavailable reason="Grouping by gateway needs the instance label, which Prometheus adds when it scrapes. The raw /metrics text has no such label." />
          )}
        </ChartCard>

        <ChartCard title="OSD request latency" subtitle="objectio_osd_grpc_latency_seconds, by instance">
          {usingPrometheus ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={osdRows?.rows ?? []}>
                {chartAxes()}
                {(osdRows?.names ?? []).slice(0, 4).map((n, i) => (
                  <Line key={n} type="monotone" dataKey={n} stroke={seriesColor(i)} strokeWidth={2} dot={false} isAnimationActive={false} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <Unavailable reason="OSD metrics live on each OSD's own :9201 endpoint, which the browser cannot reach. Prometheus already scrapes them." />
          )}
        </ChartCard>
      </div>
    </div>
  );
}

/// Shown where a panel has no data source in the current mode. Says which
/// source is missing rather than rendering an empty chart, which would read as
/// "nothing is happening".
function Unavailable({ reason }: { reason: string }) {
  return (
    <div className="h-[200px] flex items-center justify-center text-center px-6">
      <p className="text-[11px] text-muted max-w-xs">{reason}</p>
    </div>
  );
}
