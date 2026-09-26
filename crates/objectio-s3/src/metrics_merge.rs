//! Merge other services' Prometheus expositions into the gateway's.
//!
//! The gateway's `/metrics` is the one scrape target: OSDs and meta hand it
//! their exposition over gRPC. Concatenating the texts would not be a valid
//! scrape — six OSDs each open the same families, and a family may only
//! appear once — so samples are regrouped under one HELP/TYPE per family.
//!
//! Rules, in order:
//! - a family the gateway already exports is the gateway's; the same name
//!   from another source is dropped rather than mixed with a different
//!   label set — except [`is_shared`] families (`process_*`,
//!   `objectio_build_info`), which every service exports with the same
//!   labels and which are appended;
//! - families matched by `skip` are dropped;
//! - `inject` (e.g. `osd_id="…"`) is added to every sample that does not
//!   already carry that label, so series from different OSDs stay distinct;
//! - an exact duplicate series keeps its first value.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

/// One exposition to merge in.
pub struct Source<'a> {
    pub text: &'a str,
    /// Label to add where missing, as `(name, value)`.
    pub inject: Option<(&'a str, &'a str)>,
    /// Drop `process_*` families (they describe the gateway's own process
    /// when the source runs in the same one).
    pub drop_process: bool,
}

#[derive(Default)]
struct Family {
    help: Option<String>,
    kind: Option<String>,
    samples: Vec<String>,
}

/// Family a sample line belongs to: its own name, or the name with a
/// histogram/summary suffix stripped when that is a declared family.
fn family_of<'a>(sample_name: &'a str, declared: &HashSet<String>) -> &'a str {
    if declared.contains(sample_name) {
        return sample_name;
    }
    for suffix in ["_bucket", "_sum", "_count"] {
        if let Some(base) = sample_name.strip_suffix(suffix)
            && declared.contains(base)
        {
            return base;
        }
    }
    sample_name
}

fn sample_name(line: &str) -> &str {
    let end = line.find(['{', ' ']).unwrap_or(line.len());
    &line[..end]
}

/// Series identity: everything before the value.
fn series_key(line: &str) -> &str {
    line.rfind(' ').map_or(line, |i| &line[..i])
}

fn inject_label(line: &str, name: &str, value: &str) -> String {
    let n = sample_name(line);
    let rest = &line[n.len()..];
    if let Some(body) = rest.strip_prefix('{') {
        let close = body.find('}').unwrap_or(body.len());
        let labels = &body[..close];
        if labels
            .split(',')
            .any(|l| l.trim_start().starts_with(&format!("{name}=")))
        {
            return line.to_string();
        }
        let sep = if labels.is_empty() { "" } else { "," };
        format!("{n}{{{name}=\"{value}\"{sep}{body}")
    } else {
        format!("{n}{{{name}=\"{value}\"}}{rest}")
    }
}

fn parse_into(
    text: &str,
    families: &mut Vec<(String, Family)>,
    index: &mut HashMap<String, usize>,
    keep: &dyn Fn(&str) -> bool,
    inject: Option<(&str, &str)>,
) {
    let declared: HashSet<String> = text
        .lines()
        .filter_map(|l| {
            l.strip_prefix("# TYPE ")
                .or_else(|| l.strip_prefix("# HELP "))
                .and_then(|r| r.split_whitespace().next())
                .map(str::to_string)
        })
        .collect();

    let mut slot = |name: &str, families: &mut Vec<(String, Family)>| -> usize {
        *index.entry(name.to_string()).or_insert_with(|| {
            families.push((name.to_string(), Family::default()));
            families.len() - 1
        })
    };

    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (name, help) = rest.split_once(' ').unwrap_or((rest, ""));
            if keep(name) {
                let i = slot(name, families);
                families[i].1.help.get_or_insert_with(|| help.to_string());
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').unwrap_or((rest, "untyped"));
            if keep(name) {
                let i = slot(name, families);
                families[i].1.kind.get_or_insert_with(|| kind.to_string());
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let fam = family_of(sample_name(line), &declared).to_string();
        if !keep(&fam) {
            continue;
        }
        let i = slot(&fam, families);
        let sample = match inject {
            Some((n, v)) => inject_label(line, n, v),
            None => line.to_string(),
        };
        families[i].1.samples.push(sample);
    }
}

/// Families every service exports in the same shape; samples from each
/// source are kept side by side, told apart by the injected label.
#[must_use]
pub fn is_shared(name: &str) -> bool {
    name.starts_with("process_") || name == "objectio_build_info"
}

/// Merge `sources` into `base` (the gateway's own exposition).
#[must_use]
pub fn merge(base: &str, sources: &[Source<'_>], skip: &dyn Fn(&str) -> bool) -> String {
    let mut families: Vec<(String, Family)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    parse_into(base, &mut families, &mut index, &|_| true, None);
    let owned: HashSet<String> = index.keys().cloned().collect();

    for src in sources {
        let keep = |name: &str| {
            if skip(name) {
                return false;
            }
            if is_shared(name) {
                return !src.drop_process;
            }
            !owned.contains(name)
        };
        parse_into(src.text, &mut families, &mut index, &keep, src.inject);
    }

    let mut out = String::with_capacity(base.len() * 2);
    for (name, fam) in &families {
        if fam.samples.is_empty() {
            continue;
        }
        if let Some(h) = &fam.help {
            writeln!(out, "# HELP {name} {h}").unwrap();
        }
        if let Some(k) = &fam.kind {
            writeln!(out, "# TYPE {name} {k}").unwrap();
        }
        let mut seen = HashSet::new();
        for s in &fam.samples {
            if seen.insert(series_key(s)) {
                out.push_str(s);
                out.push('\n');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const OSD: &str = "# HELP objectio_disk_reads_total Shard reads\n\
        # TYPE objectio_disk_reads_total counter\n\
        objectio_disk_reads_total{osd_id=\"X\",disk=\"/d\"} 5\n\
        # HELP objectio_block_volumes_total Volumes\n\
        # TYPE objectio_block_volumes_total gauge\n\
        objectio_block_volumes_total 0\n\
        # HELP objectio_osd_capacity_bytes Cap\n\
        # TYPE objectio_osd_capacity_bytes gauge\n\
        objectio_osd_capacity_bytes{osd_id=\"X\"} 9\n\
        # TYPE objectio_osd_wal_fsync_seconds histogram\n\
        objectio_osd_wal_fsync_seconds_bucket{le=\"+Inf\"} 3\n\
        objectio_osd_wal_fsync_seconds_sum 0.1\n\
        objectio_osd_wal_fsync_seconds_count 3\n\
        # TYPE process_cpu_seconds_total counter\n\
        process_cpu_seconds_total 1.5\n";

    const GATEWAY: &str = "# HELP objectio_osd_capacity_bytes Raw capacity of one OSD\n\
        # TYPE objectio_osd_capacity_bytes gauge\n\
        objectio_osd_capacity_bytes{node_id=\"a\",address=\"x\"} 100\n";

    fn two_osds(drop_process: bool) -> String {
        merge(
            GATEWAY,
            &[
                Source {
                    text: OSD,
                    inject: Some(("osd_id", "A")),
                    drop_process,
                },
                Source {
                    text: OSD,
                    inject: Some(("osd_id", "B")),
                    drop_process,
                },
            ],
            &|_| false,
        )
    }

    /// Two OSDs must not produce two HELP/TYPE blocks for one family —
    /// Prometheus rejects the whole scrape if they do.
    #[test]
    fn each_family_is_declared_once() {
        let out = two_osds(false);
        assert_eq!(
            out.matches("# TYPE objectio_disk_reads_total").count(),
            1,
            "{out}"
        );
        assert_eq!(
            out.matches("# TYPE objectio_osd_wal_fsync_seconds").count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn samples_without_the_label_get_it_and_existing_ones_are_kept() {
        let out = two_osds(false);
        assert!(
            out.contains("objectio_block_volumes_total{osd_id=\"A\"} 0"),
            "{out}"
        );
        assert!(
            out.contains("objectio_block_volumes_total{osd_id=\"B\"} 0"),
            "{out}"
        );
        assert!(
            out.contains("objectio_osd_wal_fsync_seconds_bucket{osd_id=\"B\",le=\"+Inf\"} 3"),
            "{out}"
        );
        // Already had osd_id="X": left alone, and the second copy is a
        // duplicate series.
        assert_eq!(
            out.matches("objectio_disk_reads_total{osd_id=\"X\"")
                .count(),
            1,
            "{out}"
        );
    }

    /// The gateway's own family wins; the OSD's differently-labelled one
    /// with the same name is dropped.
    #[test]
    fn gateway_families_are_not_mixed_with_remote_ones() {
        let out = two_osds(false);
        assert!(out.contains("address=\"x\"} 100"), "{out}");
        assert!(!out.contains("objectio_osd_capacity_bytes{osd_id"), "{out}");
    }

    #[test]
    fn process_families_can_be_dropped() {
        assert!(two_osds(false).contains("process_cpu_seconds_total{osd_id=\"A\"} 1.5"));
        assert!(!two_osds(true).contains("process_cpu_seconds_total"));
    }

    /// Process stats from other processes sit next to the gateway's.
    #[test]
    fn shared_families_are_appended() {
        let out = merge(
            "# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 9\n",
            &[Source {
                text: OSD,
                inject: Some(("osd_id", "A")),
                drop_process: false,
            }],
            &|_| false,
        );
        assert!(out.contains("process_cpu_seconds_total 9"), "{out}");
        assert!(
            out.contains("process_cpu_seconds_total{osd_id=\"A\"} 1.5"),
            "{out}"
        );
        assert_eq!(
            out.matches("# TYPE process_cpu_seconds_total").count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn skip_drops_families() {
        let out = merge(
            "",
            &[Source {
                text: OSD,
                inject: None,
                drop_process: false,
            }],
            &|n| n.starts_with("objectio_block_"),
        );
        assert!(!out.contains("objectio_block_volumes_total"), "{out}");
        assert!(out.contains("objectio_disk_reads_total"), "{out}");
    }
}
