/// Metrics client.
///
/// Two sources, deliberately distinct rather than one degraded version of the
/// other:
///
///  * **Live scrape** — poll `/metrics` and difference the counters. Always
///    available, but a browser only knows what happened since the page opened,
///    so the window is `MAX_LIVE_POINTS * LIVE_INTERVAL_MS` — five minutes.
///  * **Prometheus** — range queries proxied by the gateway. Needed for any
///    window past that, and for anything grouped by instance, because the raw
///    `/metrics` text carries no instance label at all.
///
/// `capabilities()` says which exist, so a screen can choose its shape before
/// asking for data instead of finding out through a failed query.

export const LIVE_INTERVAL_MS = 5000;
export const MAX_LIVE_POINTS = 60;

export interface MetricsCapabilities {
  prometheus: boolean;
  live_scrape: { interval_seconds: number; max_points: number };
}

/// A Prometheus matrix result: one series and its points.
export interface Series {
  /// Label set, e.g. `{ operation: "GetObject", instance: "gw-0:9000" }`.
  labels: Record<string, string>;
  points: { t: number; v: number }[];
}

export async function capabilities(): Promise<MetricsCapabilities> {
  const r = await fetch("/_admin/metrics/capabilities");
  if (!r.ok) {
    // Treat an unreachable capability endpoint as "no Prometheus" rather than
    // failing the page — the live view still works.
    return {
      prometheus: false,
      live_scrape: {
        interval_seconds: LIVE_INTERVAL_MS / 1000,
        max_points: MAX_LIVE_POINTS,
      },
    };
  }
  return r.json();
}

export class PrometheusError extends Error {
  /// `prometheus_not_configured`, `prometheus_unreachable`, `range_too_wide`,
  /// or whatever Prometheus itself returned. Lets a caller distinguish "not
  /// set up" from "broken", which need different things said to the user.
  code: string;

  constructor(message: string, code: string) {
    super(message);
    this.code = code;
  }
}

async function unwrap(r: Response): Promise<{ result: RawSeries[] }> {
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    throw new PrometheusError(
      body.message || body.error || `Query failed (${r.status})`,
      body.error || "query_failed"
    );
  }
  if (body.status !== "success") {
    throw new PrometheusError(body.error || "Query failed", body.errorType || "query_failed");
  }
  return body.data;
}

interface RawSeries {
  metric: Record<string, string>;
  values?: [number, string][];
  value?: [number, string];
}

function toSeries(raw: RawSeries[]): Series[] {
  return raw.map((s) => ({
    labels: s.metric ?? {},
    points: (s.values ?? (s.value ? [s.value] : [])).map(([t, v]) => ({
      t: t * 1000,
      v: Number.parseFloat(v),
    })),
  }));
}

/// Range query. `rangeSeconds` back from now, with `points` samples.
///
/// The step is derived from the window rather than fixed, so a 30-day range
/// does not ask for a sample every 5s — the gateway refuses over 11 000 points
/// and Prometheus would struggle well before that.
export async function queryRange(
  query: string,
  rangeSeconds: number,
  points = 120
): Promise<Series[]> {
  const end = Math.floor(Date.now() / 1000);
  const start = end - rangeSeconds;
  const step = Math.max(1, Math.floor(rangeSeconds / points));
  const qs = new URLSearchParams({
    query,
    start: String(start),
    end: String(end),
    step: String(step),
  });
  return toSeries((await unwrap(await fetch(`/_admin/metrics/query_range?${qs}`))).result);
}

export async function queryInstant(query: string): Promise<Series[]> {
  const qs = new URLSearchParams({ query });
  return toSeries((await unwrap(await fetch(`/_admin/metrics/query?${qs}`))).result);
}

/// Windows the Monitoring screen offers.
///
/// `5m` is the live scrape; everything longer needs Prometheus, which is why
/// each carries the flag rather than the screen guessing from the duration.
export interface RangeOption {
  key: string;
  label: string;
  seconds: number;
  needsPrometheus: boolean;
}

export const RANGES: RangeOption[] = [
  { key: "5m", label: "5m", seconds: 300, needsPrometheus: false },
  { key: "1h", label: "1h", seconds: 3600, needsPrometheus: true },
  { key: "6h", label: "6h", seconds: 21600, needsPrometheus: true },
  { key: "24h", label: "24h", seconds: 86400, needsPrometheus: true },
  { key: "7d", label: "7d", seconds: 604800, needsPrometheus: true },
];

/// PromQL for each panel, kept together so the queries are reviewable in one
/// place rather than scattered through JSX.
///
/// `$RATE` is substituted with a rate window suited to the range — too short
/// and a long query returns holes wherever scrapes were sparse.
export const QUERIES = {
  requestsByOperation:
    'sum by (operation) (rate(objectio_s3_requests_total{status="success"}[$RATE]))',
  latencyQuantile: (q: number) =>
    `histogram_quantile(${q}, sum by (le) (rate(objectio_s3_request_duration_seconds_bucket[$RATE])))`,
  errorsByClass:
    'sum by (status) (rate(objectio_s3_requests_total{status=~"client_error|server_error"}[$RATE]))',
  icebergOps: "sum(rate(objectio_iceberg_requests_total[$RATE]))",
  // Possible only through Prometheus: `instance` is added by the scraper, and
  // is absent from the /metrics text the live view reads.
  throughputByInstance:
    "sum by (instance) (rate(objectio_s3_response_bytes_total[$RATE]))",
  osdLatencyByInstance:
    "sum by (instance) (rate(objectio_osd_grpc_latency_seconds_sum[$RATE]))",
};

/// Rate window for a given range. A 5s scrape needs at least a few intervals
/// to produce a rate at all.
export function rateWindow(rangeSeconds: number): string {
  if (rangeSeconds <= 300) return "1m";
  if (rangeSeconds <= 3600) return "5m";
  if (rangeSeconds <= 86400) return "15m";
  return "1h";
}

export function withRate(query: string, rangeSeconds: number): string {
  return query.replace(/\$RATE/g, rateWindow(rangeSeconds));
}
