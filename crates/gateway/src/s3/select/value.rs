//! Values of the SQL evaluator: what a column, a literal or an expression
//! holds, with the coercions S3 Select makes.
//!
//! CSV fields are strings. A string meets a number in a comparison or in
//! arithmetic by being read as a number, so `_1 > 100` works on CSV the way
//! people write it; a string that isn't a number is unequal to any number
//! and unordered with it (the comparison is unknown, like NULL).

use super::datetime::{Ts, format_timestamp, parse_timestamp};
use super::error::{SelectError, SelectResult};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// No such field (PartiQL's MISSING): left out of JSON output.
    Missing,
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Timestamp(Ts),
    List(Vec<Value>),
    /// Fields in their order.
    Struct(Vec<(String, Value)>),
}

/// The target of `CAST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CastType {
    Int,
    Float,
    String,
    Bool,
    Timestamp,
}

impl CastType {
    pub fn parse(word: &str) -> Option<Self> {
        Some(match word.to_ascii_lowercase().as_str() {
            "int" | "integer" | "bigint" | "smallint" => Self::Int,
            "float" | "double" | "real" | "decimal" | "numeric" => Self::Float,
            "string" | "varchar" | "char" | "text" => Self::String,
            "bool" | "boolean" => Self::Bool,
            "timestamp" => Self::Timestamp,
            _ => return None,
        })
    }
}

/// A number read from text: an integer when it is one.
pub fn parse_number(s: &str) -> Option<Value> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(i) = t.parse::<i64>() {
        return Some(Value::Int(i));
    }
    // Rust accepts "inf" and "nan"; SQL text doesn't.
    if t.bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+' | b'e' | b'E'))
        && let Ok(f) = t.parse::<f64>()
    {
        return Some(Value::Float(f));
    }
    None
}

fn cast_failed(v: &Value, to: &str) -> SelectError {
    SelectError::new(
        "CastFailed",
        format!("cannot cast {} to {to}", v.describe()),
    )
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null | Self::Missing)
    }

    /// A short description for error messages.
    pub fn describe(&self) -> String {
        match self {
            Self::Missing => "MISSING".into(),
            Self::Null => "NULL".into(),
            Self::Str(s) => {
                let short: String = s.chars().take(40).collect();
                format!("'{short}'")
            }
            Self::List(_) => "a list".into(),
            Self::Struct(_) => "a struct".into(),
            other => other.to_text(),
        }
    }

    /// The value as a number, reading strings; `None` when it isn't one.
    pub fn as_number(&self) -> Option<Value> {
        match self {
            Self::Int(_) | Self::Float(_) => Some(self.clone()),
            Self::Str(s) => parse_number(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self.as_number()? {
            Self::Int(i) => Some(i as f64),
            Self::Float(f) => Some(f),
            _ => None,
        }
    }

    /// The value as SQL truth: `Some(bool)`, `None` for NULL/MISSING (unknown).
    pub fn truth(&self) -> SelectResult<Option<bool>> {
        match self {
            Self::Bool(b) => Ok(Some(*b)),
            Self::Null | Self::Missing => Ok(None),
            Self::Str(s) if s.eq_ignore_ascii_case("true") => Ok(Some(true)),
            Self::Str(s) if s.eq_ignore_ascii_case("false") => Ok(Some(false)),
            other => Err(SelectError::new(
                "IncorrectSqlFunctionArgumentType",
                format!("{} is not a boolean", other.describe()),
            )),
        }
    }

    /// Text of the value, as CSV output and string functions see it. NULL and
    /// MISSING are empty.
    pub fn to_text(&self) -> String {
        match self {
            Self::Missing | Self::Null => String::new(),
            Self::Bool(b) => b.to_string(),
            Self::Int(i) => i.to_string(),
            Self::Float(f) => format_float(*f),
            Self::Str(s) => s.clone(),
            Self::Timestamp(t) => format_timestamp(t),
            Self::List(_) | Self::Struct(_) => {
                let mut out = String::new();
                write_json(self, &mut out);
                out
            }
        }
    }

    pub fn cast(&self, to: CastType) -> SelectResult<Value> {
        if self.is_null() {
            return Ok(Value::Null);
        }
        Ok(match to {
            CastType::Int => match self {
                Self::Int(i) => Self::Int(*i),
                Self::Float(f) => {
                    if !f.is_finite() || f.abs() >= 9.2e18 {
                        return Err(cast_failed(self, "INT"));
                    }
                    Self::Int(f.trunc() as i64)
                }
                Self::Bool(b) => Self::Int(i64::from(*b)),
                Self::Str(s) => match parse_number(s) {
                    Some(Self::Int(i)) => Self::Int(i),
                    Some(Self::Float(f)) => return Self::Float(f).cast(CastType::Int),
                    _ => return Err(cast_failed(self, "INT")),
                },
                _ => return Err(cast_failed(self, "INT")),
            },
            CastType::Float => match self {
                Self::Int(i) => Self::Float(*i as f64),
                Self::Float(f) => Self::Float(*f),
                Self::Bool(b) => Self::Float(if *b { 1.0 } else { 0.0 }),
                Self::Str(_) => match self.as_f64() {
                    Some(f) => Self::Float(f),
                    None => return Err(cast_failed(self, "FLOAT")),
                },
                _ => return Err(cast_failed(self, "FLOAT")),
            },
            CastType::String => Self::Str(self.to_text()),
            CastType::Bool => match self {
                Self::Bool(b) => Self::Bool(*b),
                Self::Int(i) => Self::Bool(*i != 0),
                Self::Float(f) => Self::Bool(*f != 0.0),
                Self::Str(s) if s.trim().eq_ignore_ascii_case("true") => Self::Bool(true),
                Self::Str(s) if s.trim().eq_ignore_ascii_case("false") => Self::Bool(false),
                Self::Str(s) => match parse_number(s) {
                    Some(n) => return n.cast(CastType::Bool),
                    None => return Err(cast_failed(self, "BOOL")),
                },
                _ => return Err(cast_failed(self, "BOOL")),
            },
            CastType::Timestamp => match self {
                Self::Timestamp(t) => Self::Timestamp(*t),
                Self::Str(s) => Self::Timestamp(parse_timestamp(s)?),
                _ => return Err(cast_failed(self, "TIMESTAMP")),
            },
        })
    }
}

/// Floats print with a decimal point (`3.0`, `0.1`, `1e300`).
pub fn format_float(f: f64) -> String {
    format!("{f:?}")
}

/// Order two values, coercing as the module doc says. `None`: unordered
/// (a NULL on either side, or types that don't compare).
pub fn compare(a: &Value, b: &Value) -> Option<Ordering> {
    use Value::{Bool, Float, Int, List, Str, Struct, Timestamp};
    match (a, b) {
        _ if a.is_null() || b.is_null() => None,
        (Int(x), Int(y)) => Some(x.cmp(y)),
        (Int(_) | Float(_), Int(_) | Float(_)) => a.as_f64()?.partial_cmp(&b.as_f64()?),
        (Str(x), Str(y)) => Some(x.as_bytes().cmp(y.as_bytes())),
        (Str(_), Int(_) | Float(_)) => compare(&a.as_number()?, b),
        (Int(_) | Float(_), Str(_)) => compare(a, &b.as_number()?),
        (Bool(x), Bool(y)) => Some(x.cmp(y)),
        (Str(s), Bool(_)) => compare(&Value::Str(s.clone()).truth().ok()?.map(Bool)?, b),
        (Bool(_), Str(_)) => compare(b, a).map(Ordering::reverse),
        (Timestamp(x), Timestamp(y)) => Some(x.dt.cmp(&y.dt)),
        (Str(s), Timestamp(_)) => compare(&Timestamp(parse_timestamp(s).ok()?), b),
        (Timestamp(_), Str(_)) => compare(b, a).map(Ordering::reverse),
        (List(x), List(y)) => (x == y).then_some(Ordering::Equal),
        (Struct(x), Struct(y)) => (x == y).then_some(Ordering::Equal),
        _ => None,
    }
}

/// SQL `=`: `None` when either side is NULL; values that don't compare are
/// unequal.
pub fn equals(a: &Value, b: &Value) -> Option<bool> {
    if a.is_null() || b.is_null() {
        return None;
    }
    Some(compare(a, b) == Some(Ordering::Equal))
}

fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// JSON text of a value (MISSING inside a struct is left out; elsewhere it
/// is `null`).
pub fn write_json(v: &Value, out: &mut String) {
    match v {
        Value::Missing | Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Float(f) if f.is_finite() => out.push_str(&format_float(*f)),
        Value::Float(f) => json_string(&format_float(*f), out),
        Value::Str(s) => json_string(s, out),
        Value::Timestamp(t) => json_string(&format_timestamp(t), out),
        Value::List(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        Value::Struct(fields) => {
            write_json_object(fields.iter().map(|(k, v)| (k.as_str(), v)), out)
        }
    }
}

/// A JSON object of `fields`, MISSING ones left out.
pub fn write_json_object<'a>(fields: impl Iterator<Item = (&'a str, &'a Value)>, out: &mut String) {
    out.push('{');
    let mut first = true;
    for (k, v) in fields {
        if matches!(v, Value::Missing) {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        json_string(k, out);
        out.push(':');
        write_json(v, out);
    }
    out.push('}');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> Value {
        Value::Str(x.to_string())
    }

    #[test]
    fn strings_meet_numbers_as_numbers() {
        assert_eq!(compare(&s("10"), &Value::Int(9)), Some(Ordering::Greater));
        assert_eq!(
            compare(&s(" 2.5 "), &Value::Float(2.5)),
            Some(Ordering::Equal)
        );
        assert_eq!(compare(&s("abc"), &Value::Int(1)), None);
        assert_eq!(equals(&s("abc"), &Value::Int(1)), Some(false));
        // Two strings compare as text, not numbers.
        assert_eq!(compare(&s("10"), &s("9")), Some(Ordering::Less));
    }

    #[test]
    fn null_compares_to_nothing() {
        assert_eq!(equals(&Value::Null, &Value::Null), None);
        assert_eq!(equals(&Value::Missing, &Value::Int(1)), None);
        assert_eq!(compare(&Value::Int(1), &Value::Null), None);
    }

    #[test]
    fn casts_follow_the_value() {
        assert_eq!(s("+00").cast(CastType::Int).unwrap(), Value::Int(0));
        assert_eq!(s("7.9").cast(CastType::Int).unwrap(), Value::Int(7));
        assert_eq!(s("x").cast(CastType::Int).unwrap_err().code, "CastFailed");
        assert_eq!(s("").cast(CastType::Int).unwrap_err().code, "CastFailed");
        assert_eq!(
            Value::Int(3).cast(CastType::Bool).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(s("TRUE").cast(CastType::Bool).unwrap(), Value::Bool(true));
        assert_eq!(
            Value::Int(3).cast(CastType::Float).unwrap(),
            Value::Float(3.0)
        );
        assert_eq!(Value::Float(3.0).cast(CastType::String).unwrap(), s("3.0"));
        assert_eq!(Value::Null.cast(CastType::Int).unwrap(), Value::Null);
        assert!(matches!(
            s("2001-01-01T00:00Z").cast(CastType::Timestamp).unwrap(),
            Value::Timestamp(_)
        ));
    }

    #[test]
    fn json_text_escapes_and_drops_missing_fields() {
        let v = Value::Struct(vec![
            ("a".into(), s("x\"y\n")),
            ("gone".into(), Value::Missing),
            (
                "n".into(),
                Value::List(vec![Value::Int(1), Value::Null, Value::Float(0.5)]),
            ),
        ]);
        let mut out = String::new();
        write_json(&v, &mut out);
        assert_eq!(out, r#"{"a":"x\"y\n","n":[1,null,0.5]}"#);
    }
}
