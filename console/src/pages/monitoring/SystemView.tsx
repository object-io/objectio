/// System views on the Monitoring page: block storage, metadata (Raft),
/// data protection, disks and OSDs.
///
/// Each section is tiles (a reading right now, always from the live scrape)
/// and charts. A chart is drawn from Prometheus over the chosen window when
/// the window needs it, and otherwise from the live scrape: rates and
/// percentiles computed from what changed between scrapes, as PromQL would.
///
/// The live scrape is the gateway's `/metrics`, which carries the OSDs' and
/// meta's metrics as well unless the gateway runs with
/// `--no-reexport-metrics` (the helm chart does; Prometheus then scrapes
/// them directly).

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartCard, StatTile } from "../../components/ui";
import { LegendDot } from "../../components/ui/ChartCard";
import { seriesColor } from "../../components/ui/chart-series";
import { cluster } from "../../api/client";
import {
  LIVE_INTERVAL_MS,
  MAX_LIVE_POINTS,
  queryRange,
  withRate,
  type Series,
} from "../../api/metrics";
import { parse, type Scrape } from "../../api/exposition";
import { format, type Section } from "./sections";

// ── Rendering ────────────────────────────────────────────────────────────────

interface Row {
  t: number;
  time: string;
  [series: string]: number | string;
}

const AXIS = {
  fontSize: 10,
  fontFamily: "var(--oio-font-mono)",
  fill: "var(--oio-faint)",
};
const MAX_SERIES = 4;

/// Live rates and percentiles are taken over at least this much time, as
/// `rate(…[1m])` would be, not between adjacent scrapes. The gateway
/// refreshes the OSDs' and meta's metrics every 30 s: over 5 s they read
/// zero, then jump.
const LOOKBACK_MS = 35_000;

/// For scrape `i`, the latest earlier scrape at least `LOOKBACK_MS` older,
/// if any.
function base(scrapes: Scrape[], i: number): Scrape | undefined {
  for (let j = i - 1; j >= 0; j--) {
    if (scrapes[i].t - scrapes[j].t >= LOOKBACK_MS) return scrapes[j];
  }
  return undefined;
}

function timeLabel(t: number, long: boolean): string {
  return new Date(t).toLocaleTimeString(
    [],
    long
      ? { hour: "2-digit", minute: "2-digit" }
      : { minute: "2-digit", second: "2-digit" },
  );
}

/// Rows from Prometheus series, one per timestamp.
function promRows(
  named: { name: string; series: Series }[],
  scale: number,
): Row[] {
  const byTime = new Map<number, Row>();
  for (const { name, series } of named) {
    for (const p of series.points) {
      if (!Number.isFinite(p.v)) continue;
      const row = byTime.get(p.t) ?? { t: p.t, time: timeLabel(p.t, true) };
      row[name] = p.v * scale;
      byTime.set(p.t, row);
    }
  }
  return [...byTime.values()].sort((a, b) => a.t - b.t);
}

function seriesNames(rows: Row[]): string[] {
  const names = new Set<string>();
  for (const r of rows)
    for (const k of Object.keys(r)) if (k !== "t" && k !== "time") names.add(k);
  return [...names].slice(0, MAX_SERIES);
}

export default function SystemView({
  section,
  rangeSeconds,
  usingPrometheus,
  paused,
}: {
  section: Section;
  rangeSeconds: number;
  usingPrometheus: boolean;
  paused: boolean;
}) {
  const [scrapes, setScrapes] = useState<Scrape[]>([]);
  const [promRowsByChart, setPromRowsByChart] = useState<Row[][]>([]);
  const [promFailed, setPromFailed] = useState(false);
  const pausedRef = useRef(paused);
  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  // Live scrape: always, since the tiles read it in either mode.
  const scrape = useCallback(async () => {
    try {
      const samples = parse(await cluster.metrics());
      setScrapes((s) =>
        [...s, { t: Date.now(), samples }].slice(-(MAX_LIVE_POINTS + 1)),
      );
    } catch {
      // A failed scrape is a gap, not a reason to tear the page down.
    }
  }, []);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- async: sets state after its await
    void scrape();
    const id = setInterval(() => {
      if (!pausedRef.current) void scrape();
    }, LIVE_INTERVAL_MS);
    return () => clearInterval(id);
  }, [scrape]);

  // Prometheus: the section's charts over the window.
  useEffect(() => {
    if (!usingPrometheus) return;
    let cancelled = false;
    Promise.all(
      section.charts.map(async (c) => {
        const scale = c.scale ?? 1;
        if (typeof c.prom === "string") {
          const series = await queryRange(
            withRate(c.prom, rangeSeconds),
            rangeSeconds,
          );
          return promRows(
            series.map((s) => ({
              name: c.legend ? c.legend(s.labels) : "value",
              series: s,
            })),
            scale,
          );
        }
        const each = await Promise.all(
          c.prom.map(async (q) => {
            const series = await queryRange(
              withRate(q.query, rangeSeconds),
              rangeSeconds,
            );
            return series.map((s) => ({ name: q.name, series: s }));
          }),
        );
        return promRows(each.flat(), scale);
      }),
    )
      .then((rows) => {
        if (cancelled) return;
        setPromRowsByChart(rows);
        setPromFailed(false);
      })
      .catch(() => {
        if (!cancelled) setPromFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [section, rangeSeconds, usingPrometheus]);

  // Live rows: each chart's series at each scrape, over the lookback.
  const liveRowsByChart = useMemo(
    () =>
      section.charts.map((c) => {
        const scale = c.scale ?? 1;
        const rows: Row[] = [];
        for (let i = 1; i < scrapes.length; i++) {
          const from = base(scrapes, i);
          if (!from) continue;
          const row: Row = {
            t: scrapes[i].t,
            time: timeLabel(scrapes[i].t, false),
          };
          for (const [k, v] of Object.entries(c.live(scrapes[i], from))) {
            if (Number.isFinite(v)) row[k] = v * scale;
          }
          rows.push(row);
        }
        return rows;
      }),
    [section, scrapes],
  );

  const cur = scrapes.at(-1);
  const prev = scrapes.length > 0 ? base(scrapes, scrapes.length - 1) : undefined;

  return (
    <div>
      <p className="text-[12px] text-muted mb-3 max-w-3xl">{section.intro}</p>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
        {section.tiles.map((t) => (
          <StatTile
            key={t.label}
            label={t.label}
            value={(cur && t.value(cur, prev)) ?? "—"}
            sub={
              cur && t.value(cur, prev) === undefined
                ? "not exported here"
                : t.sub
            }
          />
        ))}
      </div>
      {usingPrometheus && promFailed && (
        <p className="text-[12px] text-err mb-3">
          Prometheus queries for this section failed.
        </p>
      )}
      <div className="grid lg:grid-cols-2 gap-4">
        {section.charts.map((c, i) => {
          const rows = usingPrometheus
            ? (promRowsByChart[i] ?? [])
            : liveRowsByChart[i];
          const names = seriesNames(rows);
          return (
            <ChartCard
              key={c.title}
              title={c.title}
              subtitle={c.subtitle}
              legend={
                names.length > 1 ? (
                  <div className="flex gap-3 flex-wrap">
                    {names.map((n, j) => (
                      <LegendDot key={n} index={j} label={n} />
                    ))}
                  </div>
                ) : undefined
              }
            >
              {names.length === 0 ? (
                <div className="h-[200px] flex items-center justify-center text-center px-6">
                  <p className="text-[11px] text-muted max-w-xs">
                    {usingPrometheus
                      ? "No data in this window."
                      : !prev
                        ? "Collecting: rates are taken over 35 seconds."
                        : "Nothing recorded yet, or this gateway does not re-export these metrics (it runs with --no-reexport-metrics; Prometheus has them)."}
                  </p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart
                    data={rows}
                    margin={{ top: 4, right: 4, left: 4, bottom: 0 }}
                  >
                    <CartesianGrid
                      stroke="var(--oio-border)"
                      vertical={false}
                    />
                    <XAxis
                      dataKey="time"
                      tick={AXIS}
                      tickLine={false}
                      axisLine={false}
                      minTickGap={40}
                    />
                    <YAxis
                      tick={AXIS}
                      tickLine={false}
                      axisLine={false}
                      width={60}
                      tickFormatter={(v: number) => format(v, c.unit)}
                    />
                    <Tooltip
                      formatter={(v) => format(Number(v), c.unit)}
                      contentStyle={{
                        background: "var(--oio-surface)",
                        border: "1px solid var(--oio-border-strong)",
                        borderRadius: 8,
                        fontSize: 11,
                      }}
                    />
                    {names.map((n, j) => (
                      <Line
                        key={n}
                        type="monotone"
                        dataKey={n}
                        stroke={seriesColor(j)}
                        strokeWidth={2}
                        dot={false}
                        isAnimationActive={false}
                      />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
              )}
            </ChartCard>
          );
        })}
      </div>
    </div>
  );
}
