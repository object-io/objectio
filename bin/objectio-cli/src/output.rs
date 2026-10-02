//! Human tables and `--output json`.
//!
//! JSON mode prints the API's own answer, pretty-printed, so a script reads
//! the same document the SDKs do. Table mode is for people: a fixed set of
//! columns per object kind, and `key: value` lines for a single object.

use serde_json::Value;
use std::fmt::Write as _;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Table,
    Json,
}

/// A cell as a person reads it: strings bare, null/empty as `-`, arrays
/// comma-joined, objects as compact JSON.
pub fn cell(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::String(s) if s.is_empty() => "-".into(),
        Value::String(s) => s.clone(),
        Value::Array(a) if a.is_empty() => "-".into(),
        Value::Array(a) if a.iter().all(|x| !x.is_object() && !x.is_array()) => {
            a.iter().map(cell).collect::<Vec<_>>().join(",")
        }
        other => other.to_string(),
    }
}

/// `columns` are `(header, json field)`. A field may be a dotted path.
pub fn table(rows: &[Value], columns: &[(&str, &str)]) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| columns.iter().map(|(_, f)| cell(field(r, f))).collect())
        .collect();
    let mut widths: Vec<usize> = columns.iter().map(|(h, _)| h.chars().count()).collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    let line = |vals: Vec<&str>| -> String {
        let last = vals.len().saturating_sub(1);
        vals.iter()
            .enumerate()
            .map(|(i, v)| {
                if i == last {
                    (*v).to_string()
                } else {
                    format!("{v:<w$}", w = widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut out = line(columns.iter().map(|(h, _)| *h).collect());
    out.push('\n');
    for row in &cells {
        out.push_str(&line(row.iter().map(String::as_str).collect()));
        out.push('\n');
    }
    out
}

/// `a.b.c` into a JSON value; missing is `null`.
pub fn field<'a>(v: &'a Value, path: &str) -> &'a Value {
    path.split('.')
        .fold(v, |acc, k| acc.get(k).unwrap_or(&Value::Null))
}

/// One object as aligned `key: value` lines.
pub fn key_values(v: &Value) -> String {
    let Some(obj) = v.as_object() else {
        return format!("{}\n", cell(v));
    };
    let width = obj.keys().map(|k| k.chars().count()).max().unwrap_or(0) + 1;
    let mut out = String::new();
    for (k, val) in obj {
        let label = format!("{k}:");
        // The API's timestamps are unix seconds; a person reads a date.
        let shown = if k.ends_with("_at") && val.as_u64().is_some_and(|s| s > 0) {
            cell(&ts(val))
        } else {
            cell(val)
        };
        let _ = writeln!(out, "{label:<width$} {shown}");
    }
    out
}

/// Render a timestamp column: the API's unix seconds as UTC.
pub fn ts(v: &Value) -> Value {
    v.as_u64()
        .filter(|s| *s > 0)
        .and_then(|s| chrono::DateTime::from_timestamp(i64::try_from(s).ok()?, 0))
        .map_or(Value::Null, |d| {
            Value::String(d.format("%Y-%m-%d %H:%M:%SZ").to_string())
        })
}

/// Where a command writes.
pub struct Out<'a> {
    pub format: Format,
    pub w: &'a mut dyn Write,
}

impl Out<'_> {
    pub const fn json(&self) -> bool {
        matches!(self.format, Format::Json)
    }

    pub fn print(&mut self, s: &str) -> std::io::Result<()> {
        self.w.write_all(s.as_bytes())
    }

    pub fn line(&mut self, s: &str) -> std::io::Result<()> {
        writeln!(self.w, "{s}")
    }

    /// The raw document in JSON mode, `human` otherwise.
    pub fn emit(
        &mut self,
        raw: &Value,
        human: impl FnOnce(&Value) -> String,
    ) -> std::io::Result<()> {
        if self.json() {
            self.raw_json(raw)
        } else {
            let s = human(raw);
            self.print(&s)
        }
    }

    /// Pretty JSON, whatever the format — for documents a person reads as
    /// JSON anyway (a policy, a trust policy).
    pub fn raw_json(&mut self, raw: &Value) -> std::io::Result<()> {
        if raw.is_null() {
            return Ok(());
        }
        let s = serde_json::to_string_pretty(raw).unwrap_or_else(|_| raw.to_string());
        writeln!(self.w, "{s}")
    }

    /// A list: the raw document in JSON mode; a table of `rows` otherwise,
    /// or `empty` when there are none.
    pub fn list(
        &mut self,
        raw: &Value,
        rows: &[Value],
        columns: &[(&str, &str)],
        empty: &str,
    ) -> std::io::Result<()> {
        if self.json() {
            return self.raw_json(raw);
        }
        if rows.is_empty() {
            return self.line(empty);
        }
        let t = table(rows, columns);
        self.print(&t)
    }

    /// A confirmation for a call that answers with nothing (204). JSON mode
    /// prints nothing: there is no document to print.
    pub fn done(&mut self, msg: &str) -> std::io::Result<()> {
        if self.json() { Ok(()) } else { self.line(msg) }
    }
}

/// The array under `key`, or the document itself when it is a bare array.
pub fn rows_of(v: &Value, key: &str) -> Vec<Value> {
    v.as_array()
        .or_else(|| v.get(key).and_then(Value::as_array))
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_table_aligns_columns_and_marks_empties() {
        let rows = vec![
            json!({"name": "acme", "quota": 10, "admins": ["u1", "u2"]}),
            json!({"name": "globex-long", "quota": null, "admins": []}),
        ];
        let t = table(
            &rows,
            &[("NAME", "name"), ("QUOTA", "quota"), ("ADMINS", "admins")],
        );
        assert_eq!(
            t,
            "NAME         QUOTA  ADMINS\n\
             acme         10     u1,u2\n\
             globex-long  -      -\n"
        );
    }

    #[test]
    fn dotted_fields_reach_into_objects() {
        let v = json!({"effective": {"mode": "on"}});
        assert_eq!(cell(field(&v, "effective.mode")), "on");
        assert_eq!(cell(field(&v, "effective.missing")), "-");
    }

    #[test]
    fn key_values_align() {
        let s = key_values(&json!({"name": "acme", "enabled": true, "labels": {"a": "b"}}));
        // Key order is whatever serde_json keeps (sorted, unless a crate in
        // the build enables preserve_order); the alignment is the point.
        let mut lines: Vec<&str> = s.lines().collect();
        lines.sort_unstable();
        assert_eq!(
            lines,
            vec!["enabled: true", "labels:  {\"a\":\"b\"}", "name:    acme"]
        );
    }

    #[test]
    fn key_values_show_timestamps_as_dates() {
        let s = key_values(&json!({"created_at": 1_789_387_200u64, "updated_at": 0}));
        assert!(s.contains("created_at: 2026-09-14 12:00:00Z"), "{s}");
        assert!(s.contains("updated_at: 0"), "{s}");
    }

    #[test]
    fn json_mode_prints_the_raw_document() {
        let mut buf = Vec::new();
        let mut out = Out {
            format: Format::Json,
            w: &mut buf,
        };
        let raw = json!({"users": [{"user_id": "u1"}]});
        out.list(&raw, &rows_of(&raw, "users"), &[("ID", "user_id")], "none")
            .unwrap();
        let back: Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn table_mode_says_when_a_list_is_empty() {
        let mut buf = Vec::new();
        let mut out = Out {
            format: Format::Table,
            w: &mut buf,
        };
        out.list(
            &json!({"users": []}),
            &[],
            &[("ID", "user_id")],
            "No users.",
        )
        .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "No users.\n");
    }

    #[test]
    fn rows_come_from_a_bare_array_or_a_wrapper() {
        assert_eq!(rows_of(&json!([1, 2]), "x").len(), 2);
        assert_eq!(rows_of(&json!({"x": [1]}), "x").len(), 1);
        assert!(rows_of(&json!({"y": [1]}), "x").is_empty());
    }

    #[test]
    fn timestamps_render_as_utc() {
        assert_eq!(ts(&json!(0)), Value::Null);
        assert_eq!(ts(&json!(1_789_387_200)), json!("2026-09-14 12:00:00Z"));
    }
}
