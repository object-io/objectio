//! JSON records, streamed.
//!
//! The input is a sequence of JSON values (DOCUMENT: as large as they are;
//! LINES: one per line, which reads the same). Each top-level value is
//! walked along the FROM path as it is read: what the path skips is
//! scanned without being kept, and only the records it reaches are built,
//! each at most 1 MB of input. So `FROM S3Object[*].rows[*]` over a
//! document of millions of rows holds one row at a time.
//!
//! As in AWS, a FROM path ending on an array gives the array as one record
//! (`S3Object[*].rows`); `[*]` reads its elements (`S3Object[*].rows[*]`).
//! RGW reads the elements in both cases.

use super::csv::{MAX_RECORD, too_long};
use super::error::{SelectError, SelectResult, from_io};
use super::sql::Step;
use super::value::Value;
use std::io::BufRead;

/// Deepest nesting read.
const MAX_DEPTH: usize = 512;

pub struct JsonReader<R> {
    r: R,
    offset: u64,
    /// No top-level value starting after this offset is read (a scan
    /// range's end).
    last: Option<u64>,
}

fn syntax(at: u64, what: &str) -> SelectError {
    SelectError::new(
        "JSONParsingError",
        format!("the object is not valid JSON at byte {at}: {what}"),
    )
}

/// What a callback says after a record: go on (true), or stop (LIMIT
/// reached).
type Flow = bool;

impl<R: BufRead> JsonReader<R> {
    pub fn new(r: R, last: Option<u64>) -> Self {
        Self { r, offset: 0, last }
    }

    fn peek(&mut self) -> SelectResult<Option<u8>> {
        let buf = self
            .r
            .fill_buf()
            .map_err(|e| from_io(e, "JSONParsingError"))?;
        Ok(buf.first().copied())
    }

    fn bump(&mut self) {
        self.r.consume(1);
        self.offset += 1;
    }

    /// The next byte that isn't whitespace, not consumed.
    fn skip_ws(&mut self) -> SelectResult<Option<u8>> {
        loop {
            let (n, found) = {
                let buf = self
                    .r
                    .fill_buf()
                    .map_err(|e| from_io(e, "JSONParsingError"))?;
                if buf.is_empty() {
                    return Ok(None);
                }
                match buf.iter().position(|b| !b.is_ascii_whitespace()) {
                    Some(p) => (p, Some(buf[p])),
                    None => (buf.len(), None),
                }
            };
            self.r.consume(n);
            self.offset += n as u64;
            if found.is_some() {
                return Ok(found);
            }
        }
    }

    fn expect(&mut self, want: u8) -> SelectResult<()> {
        match self.skip_ws()? {
            Some(c) if c == want => {
                self.bump();
                Ok(())
            }
            Some(c) => Err(syntax(
                self.offset,
                &format!("expected '{}', found '{}'", want as char, c as char),
            )),
            None => Err(syntax(self.offset, "the input ends inside a value")),
        }
    }

    /// Every record of the input along `path`, to `f` until it says stop.
    pub fn for_each(
        &mut self,
        path: &[Step],
        f: &mut dyn FnMut(Value) -> SelectResult<Flow>,
    ) -> SelectResult<()> {
        while self.skip_ws()?.is_some() {
            if self.last.is_some_and(|l| self.offset > l) {
                return Ok(());
            }
            if !self.walk(path, 0, f)? {
                return Ok(());
            }
        }
        Ok(())
    }

    fn walk(
        &mut self,
        steps: &[Step],
        depth: usize,
        f: &mut dyn FnMut(Value) -> SelectResult<Flow>,
    ) -> SelectResult<Flow> {
        if depth > MAX_DEPTH {
            return Err(syntax(self.offset, "nested too deeply"));
        }
        let Some(c) = self.skip_ws()? else {
            return Err(syntax(
                self.offset,
                "the input ends where a value was expected",
            ));
        };
        let Some(step) = steps.first() else {
            let start = self.offset;
            let v = self.value(start, depth)?;
            return f(v);
        };
        let rest = &steps[1..];
        match (step, c) {
            (Step::Key { .. } | Step::AllValues, b'{') => {
                self.bump();
                if self.skip_ws()? == Some(b'}') {
                    self.bump();
                    return Ok(true);
                }
                loop {
                    if self.skip_ws()? != Some(b'"') {
                        return Err(syntax(self.offset, "expected a key"));
                    }
                    self.bump();
                    let mut key = Vec::new();
                    self.string(Some(&mut key), self.offset)?;
                    let key = String::from_utf8(key).map_err(|_| not_utf8())?;
                    self.expect(b':')?;
                    if matches!(step, Step::AllValues) || step.matches(&key) {
                        if !self.walk(rest, depth + 1, f)? {
                            return Ok(false);
                        }
                    } else {
                        self.skip()?;
                    }
                    if !self.after_element(b'}')? {
                        return Ok(true);
                    }
                }
            }
            (Step::Index(_) | Step::AllElements, b'[') => {
                self.bump();
                if self.skip_ws()? == Some(b']') {
                    self.bump();
                    return Ok(true);
                }
                let mut i = 0i64;
                loop {
                    let hit = match step {
                        Step::Index(n) => *n == i,
                        _ => true,
                    };
                    if hit {
                        if !self.walk(rest, depth + 1, f)? {
                            return Ok(false);
                        }
                    } else {
                        self.skip()?;
                    }
                    i += 1;
                    if !self.after_element(b']')? {
                        return Ok(true);
                    }
                }
            }
            // The path leads nowhere in this value: no record.
            _ => {
                self.skip()?;
                Ok(true)
            }
        }
    }

    /// After a container's element: true at `,` (more follow), false at
    /// `close`.
    fn after_element(&mut self, close: u8) -> SelectResult<bool> {
        match self.skip_ws()? {
            Some(b',') => {
                self.bump();
                Ok(true)
            }
            Some(c) if c == close => {
                self.bump();
                Ok(false)
            }
            Some(c) => Err(syntax(
                self.offset,
                &format!("expected ',' or '{}', found '{}'", close as char, c as char),
            )),
            None => Err(syntax(self.offset, "the input ends inside a value")),
        }
    }

    /// A string's bytes after its opening quote, unescaped into `out` (or
    /// dropped).
    fn string(&mut self, mut out: Option<&mut Vec<u8>>, start: u64) -> SelectResult<()> {
        loop {
            let (n, stop) = {
                let buf = self
                    .r
                    .fill_buf()
                    .map_err(|e| from_io(e, "JSONParsingError"))?;
                if buf.is_empty() {
                    return Err(syntax(self.offset, "an unterminated string"));
                }
                match buf.iter().position(|&b| b == b'"' || b == b'\\') {
                    Some(p) => {
                        if let Some(o) = out.as_deref_mut() {
                            o.extend_from_slice(&buf[..p]);
                        }
                        (p + 1, Some(buf[p]))
                    }
                    None => {
                        if let Some(o) = out.as_deref_mut() {
                            o.extend_from_slice(buf);
                        }
                        (buf.len(), None)
                    }
                }
            };
            self.r.consume(n);
            self.offset += n as u64;
            if out.is_some() && self.offset - start > MAX_RECORD as u64 {
                return Err(too_long());
            }
            match stop {
                Some(b'"') => return Ok(()),
                Some(_) => self.escape(out.as_deref_mut())?,
                None => {}
            }
        }
    }

    fn escape(&mut self, out: Option<&mut Vec<u8>>) -> SelectResult<()> {
        let Some(c) = self.peek()? else {
            return Err(syntax(self.offset, "an unterminated string"));
        };
        self.bump();
        let ch = match c {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let hi = self.hex4()?;
                let code = if (0xd800..0xdc00).contains(&hi) {
                    // A surrogate pair: `😀`.
                    if self.peek()? == Some(b'\\') {
                        self.bump();
                        if self.peek()? != Some(b'u') {
                            return Err(syntax(self.offset, "a lone surrogate"));
                        }
                        self.bump();
                        let lo = self.hex4()?;
                        if !(0xdc00..0xe000).contains(&lo) {
                            return Err(syntax(self.offset, "a lone surrogate"));
                        }
                        0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                    } else {
                        0xfffd
                    }
                } else {
                    hi
                };
                char::from_u32(code).unwrap_or('\u{fffd}')
            }
            other => {
                return Err(syntax(
                    self.offset,
                    &format!("'\\{}' is not an escape", other as char),
                ));
            }
        };
        if let Some(o) = out {
            let mut b = [0; 4];
            o.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
        }
        Ok(())
    }

    fn hex4(&mut self) -> SelectResult<u32> {
        let mut v = 0;
        for _ in 0..4 {
            let Some(c) = self.peek()? else {
                return Err(syntax(self.offset, "a short \\u escape"));
            };
            let d = (c as char)
                .to_digit(16)
                .ok_or_else(|| syntax(self.offset, "a bad \\u escape"))?;
            self.bump();
            v = v * 16 + d;
        }
        Ok(v)
    }

    /// A bare token: a number, `true`, `false`, `null`.
    fn word(&mut self) -> SelectResult<Vec<u8>> {
        let mut w = Vec::new();
        while let Some(c) = self.peek()? {
            if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'+' | b'.') {
                w.push(c);
                self.bump();
                if w.len() > 1024 {
                    return Err(syntax(self.offset, "a token too long"));
                }
            } else {
                break;
            }
        }
        Ok(w)
    }

    fn scalar(&mut self) -> SelectResult<Value> {
        let at = self.offset;
        let w = self.word()?;
        Ok(match w.as_slice() {
            b"true" => Value::Bool(true),
            b"false" => Value::Bool(false),
            b"null" => Value::Null,
            [] => return Err(syntax(at, "expected a value")),
            num => {
                let s = std::str::from_utf8(num).unwrap_or_default();
                let valid = s
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.' | b'e' | b'E'));
                if !valid {
                    return Err(syntax(at, &format!("'{s}' is not a value")));
                }
                if let Ok(i) = s.parse::<i64>() {
                    Value::Int(i)
                } else {
                    Value::Float(
                        s.parse::<f64>()
                            .map_err(|_| syntax(at, &format!("'{s}' is not a number")))?,
                    )
                }
            }
        })
    }

    /// Build the next value; `start` is where its record began.
    fn value(&mut self, start: u64, depth: usize) -> SelectResult<Value> {
        if depth > MAX_DEPTH {
            return Err(syntax(self.offset, "nested too deeply"));
        }
        if self.offset - start > MAX_RECORD as u64 {
            return Err(too_long());
        }
        let Some(c) = self.skip_ws()? else {
            return Err(syntax(
                self.offset,
                "the input ends where a value was expected",
            ));
        };
        match c {
            b'{' => {
                self.bump();
                let mut fields = Vec::new();
                if self.skip_ws()? == Some(b'}') {
                    self.bump();
                    return Ok(Value::Struct(fields));
                }
                loop {
                    if self.skip_ws()? != Some(b'"') {
                        return Err(syntax(self.offset, "expected a key"));
                    }
                    self.bump();
                    let mut key = Vec::new();
                    self.string(Some(&mut key), start)?;
                    let key = String::from_utf8(key).map_err(|_| not_utf8())?;
                    self.expect(b':')?;
                    fields.push((key, self.value(start, depth + 1)?));
                    if !self.after_element(b'}')? {
                        return Ok(Value::Struct(fields));
                    }
                }
            }
            b'[' => {
                self.bump();
                let mut items = Vec::new();
                if self.skip_ws()? == Some(b']') {
                    self.bump();
                    return Ok(Value::List(items));
                }
                loop {
                    items.push(self.value(start, depth + 1)?);
                    if !self.after_element(b']')? {
                        return Ok(Value::List(items));
                    }
                }
            }
            b'"' => {
                self.bump();
                let mut s = Vec::new();
                self.string(Some(&mut s), start)?;
                Ok(Value::Str(String::from_utf8(s).map_err(|_| not_utf8())?))
            }
            _ => self.scalar(),
        }
    }

    /// Pass over the next value without keeping it.
    fn skip(&mut self) -> SelectResult<()> {
        let mut depth = 0usize;
        loop {
            let Some(c) = self.skip_ws()? else {
                return Err(syntax(self.offset, "the input ends inside a value"));
            };
            match c {
                b'{' | b'[' => {
                    self.bump();
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(syntax(self.offset, "nested too deeply"));
                    }
                    continue;
                }
                b'}' | b']' => {
                    if depth == 0 {
                        return Err(syntax(self.offset, &format!("unexpected '{}'", c as char)));
                    }
                    self.bump();
                    depth -= 1;
                }
                b',' | b':' if depth > 0 => {
                    self.bump();
                    continue;
                }
                b'"' => {
                    self.bump();
                    self.string(None, self.offset)?;
                }
                _ => {
                    self.scalar()?;
                }
            }
            if depth == 0 {
                return Ok(());
            }
        }
    }
}

fn not_utf8() -> SelectError {
    SelectError::new(
        "InvalidTextEncoding",
        "the object is not UTF-8 text, the only encoding S3 Select reads",
    )
}

#[cfg(test)]
mod tests {
    use super::super::sql::parse;
    use super::*;
    use crate::s3::select::value::write_json;

    fn records(data: &str, from: &str) -> SelectResult<Vec<String>> {
        let q = parse(&format!("select * from {from}")).unwrap();
        let mut r = JsonReader::new(data.as_bytes(), None);
        let mut out = Vec::new();
        r.for_each(&q.from_path, &mut |v| {
            let mut s = String::new();
            write_json(&v, &mut s);
            out.push(s);
            Ok(true)
        })?;
        Ok(out)
    }

    #[test]
    fn documents_and_lines() {
        let data = "{\"a\": 1, \"b\": [true, null, 2.5, \"x\\u00e9\\n\"]}\n{\"a\":-2}\n  7 \"s\"";
        assert_eq!(
            records(data, "s3object[*]").unwrap(),
            [
                r#"{"a":1,"b":[true,null,2.5,"xé\n"]}"#,
                r#"{"a":-2}"#,
                "7",
                r#""s""#
            ]
        );
    }

    #[test]
    fn a_path_reads_only_what_it_reaches() {
        let data =
            r#"{"skip": {"deep": [1, {"x": "}"}]}, "root": [{"c1": 1}, {"c1": 2}], "after": 1}"#;
        // As in AWS: the array is one record; `[*]` reads its elements.
        assert_eq!(
            records(data, "s3object[*].root").unwrap(),
            [r#"[{"c1":1},{"c1":2}]"#]
        );
        assert_eq!(
            records(data, "s3object[*].root[*]").unwrap(),
            [r#"{"c1":1}"#, r#"{"c1":2}"#]
        );
        assert_eq!(records(data, "s3object[*].root[*].c1").unwrap(), ["1", "2"]);
        assert_eq!(
            records(data, "s3object[*].root[1]").unwrap(),
            [r#"{"c1":2}"#]
        );
        assert_eq!(
            records(data, "s3object[*].ROOT[0]").unwrap(),
            [r#"{"c1":1}"#]
        );
        assert!(records(data, "s3object[*].\"ROOT\"").unwrap().is_empty());
        assert!(records(data, "s3object[*].nothing").unwrap().is_empty());
        assert_eq!(
            records(data, "s3object[*].skip.*").unwrap(),
            [r#"[1,{"x":"}"}]"#]
        );
    }

    #[test]
    fn a_stop_ends_the_scan() {
        let mut r = JsonReader::new("[1,2,3] [4]".as_bytes(), None);
        let mut seen = Vec::new();
        let q = parse("select * from s3object[*][*]").unwrap();
        r.for_each(&q.from_path, &mut |v| {
            seen.push(v);
            Ok(seen.len() < 2)
        })
        .unwrap();
        assert_eq!(seen, [Value::Int(1), Value::Int(2)]);
    }

    #[test]
    fn bad_json_is_a_parsing_error() {
        for bad in [
            "{\"a\" 1}",
            "[1 2]",
            "{\"a\": tru}",
            "\"open",
            "{\"a\": 1",
            "]",
        ] {
            assert_eq!(
                records(bad, "s3object").unwrap_err().code,
                "JSONParsingError",
                "{bad}"
            );
        }
    }

    #[test]
    fn big_records_are_refused_but_can_be_skipped() {
        let big = "x".repeat(MAX_RECORD + 1);
        let data = format!(r#"{{"big": "{big}", "small": [1]}}"#);
        assert_eq!(
            records(&data, "s3object").unwrap_err().code,
            "OverMaxRecordSize"
        );
        assert_eq!(records(&data, "s3object[*].small").unwrap(), ["[1]"]);
    }
}
