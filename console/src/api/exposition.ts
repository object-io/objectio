/// Reading the Prometheus text the gateway serves at `/metrics`, for views
/// that run without Prometheus.
///
/// Counters and histograms only mean something as differences, so the live
/// views keep the previous scrape and compute rates and percentiles from
/// what changed in between — the same arithmetic as PromQL's `rate()` and
/// `histogram_quantile()`, over one scrape interval.

export interface Sample {
  name: string;
  labels: Record<string, string>;
  value: number;
}

export interface Scrape {
  /// Milliseconds since the epoch.
  t: number;
  samples: Sample[];
}

/// Every sample in `text`. Comments and malformed lines are skipped.
export function parse(text: string): Sample[] {
  const out: Sample[] = [];
  for (const line of text.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const brace = line.indexOf("{");
    const space = line.lastIndexOf(" ");
    if (space < 0) continue;
    const value = Number.parseFloat(line.slice(space + 1));
    if (Number.isNaN(value)) continue;
    if (brace < 0 || brace > space) {
      out.push({ name: line.slice(0, space), labels: {}, value });
      continue;
    }
    const close = line.lastIndexOf("}", space);
    const labels: Record<string, string> = {};
    const re = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g;
    for (const m of line.slice(brace + 1, close).matchAll(re)) {
      labels[m[1]] = m[2].replace(/\\"/g, '"').replace(/\\\\/g, "\\");
    }
    out.push({ name: line.slice(0, brace), labels, value });
  }
  return out;
}

/// A label matcher: exact value, or a predicate.
export type Match = Record<string, string | ((v: string) => boolean)>;

function matches(s: Sample, name: string, match?: Match): boolean {
  if (s.name !== name) return false;
  if (!match) return true;
  return Object.entries(match).every(([k, want]) => {
    const v = s.labels[k] ?? "";
    return typeof want === "string" ? v === want : want(v);
  });
}

/// Sum of `name`'s samples matching `match`, grouped by the value of label
/// `by` (one group, `value`, when `by` is omitted).
export function groupSum(
  samples: Sample[],
  name: string,
  by?: string,
  match?: Match,
): Record<string, number> {
  const out: Record<string, number> = {};
  for (const s of samples) {
    if (!matches(s, name, match)) continue;
    const k = by ? (s.labels[by] ?? "") : "value";
    out[k] = (out[k] ?? 0) + s.value;
  }
  return out;
}

/// One number: the sum of every matching sample, or `undefined` when there
/// is none (absent is not zero).
export function total(
  samples: Sample[],
  name: string,
  match?: Match,
): number | undefined {
  const g = groupSum(samples, name, undefined, match);
  return "value" in g ? g.value : undefined;
}

/// Per-second increase of a counter between two scrapes, by group. A
/// counter that went down was reset (a restart): its group is left out
/// rather than shown as a huge negative rate.
export function rate(
  cur: Scrape,
  prev: Scrape,
  name: string,
  by?: string,
  match?: Match,
): Record<string, number> {
  const dt = (cur.t - prev.t) / 1000;
  if (dt <= 0) return {};
  const a = groupSum(cur.samples, name, by, match);
  const b = groupSum(prev.samples, name, by, match);
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(a)) {
    const before = b[k] ?? 0;
    if (v >= before) out[k] = (v - before) / dt;
  }
  return out;
}

/// The `q` quantile of what a histogram observed between two scrapes, by
/// group, in the histogram's unit — as `histogram_quantile(q, rate(…))`.
/// Groups with no observations in between are left out.
export function quantile(
  cur: Scrape,
  prev: Scrape,
  histogram: string,
  q: number,
  by?: string,
  match?: Match,
): Record<string, number> {
  const bucket = `${histogram}_bucket`;
  // group → le → increase
  const inc = new Map<string, Map<number, number>>();
  const add = (samples: Sample[], sign: number) => {
    for (const s of samples) {
      if (!matches(s, bucket, match)) continue;
      const le =
        s.labels.le === "+Inf" ? Infinity : Number.parseFloat(s.labels.le);
      if (Number.isNaN(le)) continue;
      const g = by ? (s.labels[by] ?? "") : "value";
      const m = inc.get(g) ?? new Map<number, number>();
      m.set(le, (m.get(le) ?? 0) + sign * s.value);
      inc.set(g, m);
    }
  };
  add(cur.samples, 1);
  add(prev.samples, -1);

  const out: Record<string, number> = {};
  for (const [g, m] of inc) {
    const buckets = [...m.entries()].sort((x, y) => x[0] - y[0]);
    const count = buckets.at(-1)?.[1] ?? 0;
    if (count <= 0) continue;
    const rank = q * count;
    let lower = 0;
    let below = 0;
    for (const [le, cum] of buckets) {
      if (cum >= rank) {
        if (le === Infinity) {
          // Past the last bound: the best that can be said is "at least".
          out[g] = lower;
        } else {
          const inBucket = cum - below;
          out[g] =
            inBucket > 0
              ? lower + ((le - lower) * (rank - below)) / inBucket
              : le;
        }
        break;
      }
      lower = le;
      below = cum;
    }
  }
  return out;
}
