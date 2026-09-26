//! Lock-free Prometheus histograms, rendered in the text format by hand
//! like the rest of ObjectIO's metrics.
//!
//! [`Histogram`] is one series; [`HistogramVec`] keys series by a
//! pre-rendered label string (`op="CreateBucket"`). Keep label values
//! bounded — every distinct string is a series forever.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Upper bounds for latencies, in seconds: 100µs to 30s.
pub const LATENCY_BUCKETS: &[f64] = &[
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
    5.0, 10.0, 30.0,
];

/// Upper bounds for sizes, in bytes: 1 KiB to 5 GiB in powers of four.
pub const SIZE_BUCKETS: &[f64] = &[
    1024.0,
    4096.0,
    16384.0,
    65536.0,
    262_144.0,
    1_048_576.0,
    4_194_304.0,
    16_777_216.0,
    67_108_864.0,
    268_435_456.0,
    1_073_741_824.0,
    5_368_709_120.0,
];

/// Upper bounds for ages, in seconds: 1 minute to 30 days.
pub const AGE_BUCKETS: &[f64] = &[
    60.0,
    300.0,
    900.0,
    3600.0,
    21600.0,
    86400.0,
    259_200.0,
    604_800.0,
    2_592_000.0,
];

/// Sum is kept in millionths so it fits an atomic integer.
const SUM_SCALE: f64 = 1e6;

pub struct Histogram {
    bounds: &'static [f64],
    /// Non-cumulative count per bucket, plus one for +Inf.
    counts: Vec<AtomicU64>,
    sum_micros: AtomicU64,
}

impl Histogram {
    #[must_use]
    pub fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            counts: (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            sum_micros: AtomicU64::new(0),
        }
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn observe(&self, v: f64) {
        let idx = self
            .bounds
            .iter()
            .position(|b| v <= *b)
            .unwrap_or(self.bounds.len());
        self.counts[idx].fetch_add(1, Ordering::Relaxed);
        self.sum_micros
            .fetch_add((v.max(0.0) * SUM_SCALE) as u64, Ordering::Relaxed);
    }

    pub fn observe_duration(&self, d: Duration) {
        self.observe(d.as_secs_f64());
    }

    /// Write `name_bucket` / `_sum` / `_count` samples (no HELP/TYPE).
    #[allow(clippy::cast_precision_loss)]
    pub fn write_samples(&self, out: &mut String, name: &str, labels: &str) {
        let sep = if labels.is_empty() { "" } else { "," };
        let mut cumulative = 0;
        for (i, c) in self.counts.iter().enumerate() {
            cumulative += c.load(Ordering::Relaxed);
            let le = self
                .bounds
                .get(i)
                .map_or_else(|| "+Inf".to_string(), ToString::to_string);
            writeln!(
                out,
                "{name}_bucket{{{labels}{sep}le=\"{le}\"}} {cumulative}"
            )
            .unwrap();
        }
        let braces = if labels.is_empty() {
            String::new()
        } else {
            format!("{{{labels}}}")
        };
        let sum = self.sum_micros.load(Ordering::Relaxed) as f64 / SUM_SCALE;
        writeln!(out, "{name}_sum{braces} {sum}").unwrap();
        writeln!(out, "{name}_count{braces} {cumulative}").unwrap();
    }

    /// Render as a complete family with HELP and TYPE.
    pub fn render(&self, out: &mut String, name: &str, help: &str, labels: &str) {
        header(out, name, help);
        self.write_samples(out, name, labels);
    }
}

fn header(out: &mut String, name: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}").unwrap();
    writeln!(out, "# TYPE {name} histogram").unwrap();
}

/// Histograms keyed by a rendered label set.
pub struct HistogramVec {
    bounds: &'static [f64],
    series: RwLock<HashMap<String, Histogram>>,
}

impl HistogramVec {
    #[must_use]
    pub fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            series: RwLock::new(HashMap::new()),
        }
    }

    /// Record `v` under `labels`, e.g. `op="CreateBucket"`.
    pub fn observe(&self, labels: &str, v: f64) {
        if let Ok(g) = self.series.read()
            && let Some(h) = g.get(labels)
        {
            h.observe(v);
            return;
        }
        if let Ok(mut g) = self.series.write() {
            g.entry(labels.to_string())
                .or_insert_with(|| Histogram::new(self.bounds))
                .observe(v);
        }
    }

    pub fn observe_duration(&self, labels: &str, d: Duration) {
        self.observe(labels, d.as_secs_f64());
    }

    /// Render every series as one family. `extra` (e.g. `osd_id="…"`) is
    /// prepended to each series' labels. Nothing is written when there are
    /// no series yet.
    pub fn render(&self, out: &mut String, name: &str, help: &str, extra: &str) {
        let Ok(g) = self.series.read() else { return };
        if g.is_empty() {
            return;
        }
        header(out, name, help);
        let mut keys: Vec<&String> = g.keys().collect();
        keys.sort();
        for k in keys {
            let labels = match (extra.is_empty(), k.is_empty()) {
                (true, _) => k.clone(),
                (false, true) => extra.to_string(),
                (false, false) => format!("{extra},{k}"),
            };
            g[k].write_samples(out, name, &labels);
        }
    }
}

/// Escape a label value.
#[must_use]
pub fn label_value(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_cumulative() {
        let h = Histogram::new(&[1.0, 2.0]);
        for v in [0.5, 1.5, 1.5, 9.0] {
            h.observe(v);
        }
        let mut out = String::new();
        h.render(&mut out, "x", "help", "");
        assert!(out.contains("x_bucket{le=\"1\"} 1"), "{out}");
        assert!(out.contains("x_bucket{le=\"2\"} 3"), "{out}");
        assert!(out.contains("x_bucket{le=\"+Inf\"} 4"), "{out}");
        assert!(out.contains("x_count 4"), "{out}");
        assert!(out.contains("x_sum 12.5"), "{out}");
    }

    #[test]
    fn vec_renders_one_family_with_labels() {
        let v = HistogramVec::new(&[1.0]);
        v.observe("op=\"a\"", 0.5);
        v.observe("op=\"b\"", 5.0);
        let mut out = String::new();
        v.render(&mut out, "y", "help", "osd_id=\"n\"");
        assert_eq!(out.matches("# TYPE y histogram").count(), 1, "{out}");
        assert!(
            out.contains("y_bucket{osd_id=\"n\",op=\"a\",le=\"1\"} 1"),
            "{out}"
        );
        assert!(out.contains("y_count{osd_id=\"n\",op=\"b\"} 1"), "{out}");
    }

    #[test]
    fn empty_vec_renders_nothing() {
        let mut out = String::new();
        HistogramVec::new(LATENCY_BUCKETS).render(&mut out, "z", "h", "");
        assert!(out.is_empty());
    }
}

/// Monotonic counters keyed by a rendered label set.
#[derive(Default)]
pub struct CounterVec {
    series: RwLock<HashMap<String, AtomicU64>>,
}

impl CounterVec {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc(&self, labels: &str) {
        self.add(labels, 1);
    }

    pub fn add(&self, labels: &str, v: u64) {
        if let Ok(g) = self.series.read()
            && let Some(c) = g.get(labels)
        {
            c.fetch_add(v, Ordering::Relaxed);
            return;
        }
        if let Ok(mut g) = self.series.write() {
            g.entry(labels.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(v, Ordering::Relaxed);
        }
    }

    /// Render as one counter family; nothing when empty.
    pub fn render(&self, out: &mut String, name: &str, help: &str) {
        render_scalar(out, name, help, "counter", &self.series, |c| {
            c.load(Ordering::Relaxed).to_string()
        });
    }
}

/// Up/down gauges keyed by a rendered label set.
#[derive(Default)]
pub struct GaugeVec {
    series: RwLock<HashMap<String, std::sync::atomic::AtomicI64>>,
}

impl GaugeVec {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, labels: &str, v: i64) {
        if let Ok(g) = self.series.read()
            && let Some(c) = g.get(labels)
        {
            c.fetch_add(v, Ordering::Relaxed);
            return;
        }
        if let Ok(mut g) = self.series.write() {
            g.entry(labels.to_string())
                .or_insert_with(|| std::sync::atomic::AtomicI64::new(0))
                .fetch_add(v, Ordering::Relaxed);
        }
    }

    /// Render as one gauge family; nothing when empty.
    pub fn render(&self, out: &mut String, name: &str, help: &str) {
        render_scalar(out, name, help, "gauge", &self.series, |c| {
            c.load(Ordering::Relaxed).to_string()
        });
    }
}

fn render_scalar<T>(
    out: &mut String,
    name: &str,
    help: &str,
    kind: &str,
    series: &RwLock<HashMap<String, T>>,
    value: impl Fn(&T) -> String,
) {
    let Ok(g) = series.read() else { return };
    if g.is_empty() {
        return;
    }
    writeln!(out, "# HELP {name} {help}").unwrap();
    writeln!(out, "# TYPE {name} {kind}").unwrap();
    let mut keys: Vec<&String> = g.keys().collect();
    keys.sort();
    for k in keys {
        if k.is_empty() {
            writeln!(out, "{name} {}", value(&g[k])).unwrap();
        } else {
            writeln!(out, "{name}{{{k}}} {}", value(&g[k])).unwrap();
        }
    }
}

#[cfg(test)]
mod vec_tests {
    use super::*;

    #[test]
    fn counters_and_gauges_render() {
        let c = CounterVec::new();
        c.inc("reason=\"signature\"");
        c.add("reason=\"signature\"", 2);
        let g = GaugeVec::new();
        g.add("operation=\"PutObject\"", 1);
        g.add("operation=\"PutObject\"", -1);
        let mut out = String::new();
        c.render(&mut out, "a_total", "h");
        g.render(&mut out, "b", "h");
        assert!(out.contains("a_total{reason=\"signature\"} 3"), "{out}");
        assert!(
            out.contains("# TYPE b gauge\nb{operation=\"PutObject\"} 0"),
            "{out}"
        );
    }
}
