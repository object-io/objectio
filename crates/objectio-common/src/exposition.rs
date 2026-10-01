//! Checks on Prometheus text exposition, for tests.
//!
//! Every metric here is hand-rendered, so nothing stops two modules from
//! declaring the same family (Prometheus then rejects the whole scrape) or
//! a sample from appearing under no declaration. These are the checks a
//! scraper would fail on.

use std::collections::{HashMap, HashSet};

/// One declared family: its type and every sample name seen for it.
#[derive(Debug, Default)]
pub struct Family {
    pub kind: String,
    pub help: bool,
    pub samples: usize,
}

/// Parse `text`, returning its families by name, or every problem found:
/// a family declared twice, a sample under no declaration, or a malformed
/// name or line.
///
/// # Errors
/// A list of the problems, one per line.
pub fn check(text: &str) -> Result<HashMap<String, Family>, String> {
    let mut families: HashMap<String, Family> = HashMap::new();
    let mut problems = Vec::new();
    let mut typed: HashSet<String> = HashSet::new();
    let mut helped: HashSet<String> = HashSet::new();

    for (n, line) in text.lines().enumerate() {
        let n = n + 1;
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let name = rest.split(' ').next().unwrap_or_default();
            if !helped.insert(name.to_string()) {
                problems.push(format!("line {n}: HELP for {name} again"));
            }
            families.entry(name.to_string()).or_default().help = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split(' ');
            let name = parts.next().unwrap_or_default();
            let kind = parts.next().unwrap_or_default();
            if !typed.insert(name.to_string()) {
                problems.push(format!("line {n}: TYPE for {name} again"));
            }
            if !matches!(
                kind,
                "counter" | "gauge" | "histogram" | "summary" | "untyped"
            ) {
                problems.push(format!("line {n}: {name} has type {kind:?}"));
            }
            families.entry(name.to_string()).or_default().kind = kind.to_string();
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let name_end = line.find(['{', ' ']).unwrap_or(line.len());
        let sample = &line[..name_end];
        if !valid_name(sample) {
            problems.push(format!("line {n}: bad metric name {sample:?}"));
            continue;
        }
        let value = line.rsplit(' ').next().unwrap_or_default();
        if value.parse::<f64>().is_err() && !matches!(value, "NaN" | "+Inf" | "-Inf") {
            problems.push(format!("line {n}: {sample} has value {value:?}"));
        }
        match family_of(sample, &families) {
            Some(f) => families.get_mut(&f).expect("found").samples += 1,
            None => problems.push(format!("line {n}: {sample} has no TYPE")),
        }
    }
    for (name, f) in &families {
        if f.kind.is_empty() {
            problems.push(format!("{name} has HELP but no TYPE"));
        }
    }
    if problems.is_empty() {
        Ok(families)
    } else {
        Err(problems.join("\n"))
    }
}

/// The declared family a sample belongs to: itself, or a histogram's or
/// summary's for its `_bucket` / `_sum` / `_count` series.
fn family_of(sample: &str, families: &HashMap<String, Family>) -> Option<String> {
    if families.get(sample).is_some_and(|f| !f.kind.is_empty()) {
        return Some(sample.to_string());
    }
    for suffix in ["_bucket", "_sum", "_count"] {
        if let Some(base) = sample.strip_suffix(suffix)
            && families
                .get(base)
                .is_some_and(|f| matches!(f.kind.as_str(), "histogram" | "summary"))
        {
            return Some(base.to_string());
        }
    }
    None
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == ':')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_exposition_passes() {
        let text = "# HELP a_total x\n# TYPE a_total counter\na_total{k=\"v\"} 3\n\
                    # HELP h x\n# TYPE h histogram\nh_bucket{le=\"+Inf\"} 1\nh_sum 0.5\nh_count 1\n";
        let f = check(text).unwrap();
        assert_eq!(f["a_total"].samples, 1);
        assert_eq!(f["h"].samples, 3);
    }

    #[test]
    fn a_family_declared_twice_fails() {
        let text = "# HELP d x\n# TYPE d gauge\nd 1\n# HELP d x\n# TYPE d gauge\nd{x=\"y\"} 1\n";
        let e = check(text).unwrap_err();
        assert!(e.contains("TYPE for d again"), "{e}");
    }

    #[test]
    fn an_undeclared_sample_fails() {
        let e = check("orphan 1\n").unwrap_err();
        assert!(e.contains("orphan has no TYPE"), "{e}");
    }
}
