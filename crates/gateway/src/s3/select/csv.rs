//! CSV records in and out.
//!
//! In: a record ends at the record delimiter. Inside it, a field that starts
//! with the quote character runs to the closing quote, delimiters included;
//! in it the escape character (the quote itself by default, `""`) makes the
//! next quote data. A quote anywhere else is data. A record delimiter inside
//! quotes is data only with `AllowQuotedRecordDelimiter`; otherwise it ends
//! the record, as in AWS. Blank lines and lines starting with the comment
//! character are skipped; with `\n` as the delimiter a `\r` before it goes
//! too, so CRLF files read as they look.

use super::error::{SelectError, SelectResult};
use super::request::{CsvInput, CsvOutput, QuoteFields};
use super::value::Value;
use std::borrow::Cow;
use std::io::{BufRead, Read};

/// Longest record read or written, as AWS (1 MB).
pub const MAX_RECORD: usize = 1024 * 1024;

pub fn too_long() -> SelectError {
    SelectError::new(
        "OverMaxRecordSize",
        "a record is longer than 1 MB, the most S3 Select reads",
    )
}

/// How fields are written: their delimiter, the quote, its escape.
struct Syntax {
    field_delimiter: Vec<u8>,
    quote: Option<Vec<u8>>,
    escape: Option<Vec<u8>>,
}

pub struct CsvReader<R> {
    r: R,
    record_delimiter: Vec<u8>,
    syntax: Syntax,
    comments: Option<Vec<u8>>,
    quoted_delimiters: bool,
    /// Bytes consumed so far.
    offset: u64,
    line: Vec<u8>,
    /// How far the record being read is scanned for quotes.
    quotes: SplitState,
    first: bool,
}

fn utf8(c: char) -> Vec<u8> {
    c.to_string().into_bytes()
}

impl<R: BufRead> CsvReader<R> {
    pub fn new(r: R, opts: &CsvInput) -> Self {
        Self {
            r,
            record_delimiter: opts.record_delimiter.as_bytes().to_vec(),
            syntax: Syntax {
                field_delimiter: opts.field_delimiter.as_bytes().to_vec(),
                quote: opts.quote.map(utf8),
                escape: opts.quote_escape.map(utf8),
            },
            comments: opts.comments.as_ref().map(|c| c.as_bytes().to_vec()),
            quoted_delimiters: opts.allow_quoted_record_delimiter,
            offset: 0,
            line: Vec::new(),
            quotes: SplitState::new(),
            first: true,
        }
    }

    /// Bytes consumed so far.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Skip to just past the next record delimiter (a scan range that
    /// starts inside a record). False at the end of the input.
    pub fn skip_partial(&mut self) -> SelectResult<bool> {
        self.first = false;
        let delim = self.record_delimiter.clone();
        let last = *delim.last().unwrap_or(&b'\n');
        let mut tail: Vec<u8> = Vec::new();
        let mut chunk = Vec::new();
        loop {
            chunk.clear();
            let n = (&mut self.r)
                .take(64 * 1024)
                .read_until(last, &mut chunk)
                .map_err(|e| super::error::from_io(e, "CSVParsingError"))?;
            self.offset += n as u64;
            if n == 0 {
                return Ok(false);
            }
            tail.extend_from_slice(&chunk);
            if tail.len() > delim.len() {
                tail.drain(..tail.len() - delim.len());
            }
            if chunk.last() == Some(&last) && tail.ends_with(&delim) {
                return Ok(true);
            }
        }
    }

    /// Read one raw record into `self.line` (without its delimiter).
    /// `None` at the end of the input.
    fn raw_record(&mut self) -> SelectResult<Option<()>> {
        self.line.clear();
        self.quotes = SplitState::new();
        let last = *self.record_delimiter.last().unwrap_or(&b'\n');
        let most = MAX_RECORD + self.record_delimiter.len();
        loop {
            // Never more than a record's worth in memory.
            let room = (most + 1).saturating_sub(self.line.len()) as u64;
            let n = (&mut self.r)
                .take(room)
                .read_until(last, &mut self.line)
                .map_err(|e| super::error::from_io(e, "CSVParsingError"))?;
            self.offset += n as u64;
            if self.line.len() > most {
                return Err(too_long());
            }
            if n == 0 {
                return Ok((!self.line.is_empty()).then_some(()));
            }
            if !self.line.ends_with(&self.record_delimiter) {
                if self.line.last() == Some(&last) {
                    continue; // the delimiter's last byte alone, not the whole
                }
                return Ok(Some(())); // the end of the input
            }
            if self.quoted_delimiters
                && self.ends_in_quotes(self.line.len() - self.record_delimiter.len())
            {
                continue;
            }
            self.line
                .truncate(self.line.len() - self.record_delimiter.len());
            if self.record_delimiter == b"\n" && self.line.last() == Some(&b'\r') {
                self.line.pop();
            }
            return Ok(Some(()));
        }
    }

    /// Whether `self.line[..end]` ends inside a quoted field, scanning on
    /// from where the last call stopped.
    fn ends_in_quotes(&mut self, end: usize) -> bool {
        split_into(
            &self.line,
            end,
            &self.syntax,
            &mut self.quotes,
            None,
            &mut Vec::new(),
        );
        self.quotes.quoted
    }

    /// The next record's fields, into `fields`. False at the end.
    pub fn next_record(&mut self, fields: &mut Vec<String>) -> SelectResult<bool> {
        loop {
            if self.raw_record()?.is_none() {
                return Ok(false);
            }
            if self.first {
                self.first = false;
                if self.line.starts_with(b"\xef\xbb\xbf") {
                    self.line.drain(..3);
                }
            }
            if self.line.is_empty() {
                continue;
            }
            if let Some(c) = &self.comments
                && self.line.starts_with(c)
            {
                continue;
            }
            let mut raw = Vec::new();
            split(&self.line, &self.syntax, &mut raw);
            fields.clear();
            for f in raw {
                fields.push(String::from_utf8(f).map_err(|_| {
                    SelectError::new(
                        "InvalidTextEncoding",
                        "the object is not UTF-8 text, the only encoding S3 Select reads",
                    )
                })?);
            }
            return Ok(true);
        }
    }
}

/// Where splitting a record stopped: a record read in pieces (record
/// delimiters inside quotes) is scanned once, piece by piece.
#[derive(Debug, Clone, Copy)]
struct SplitState {
    pos: usize,
    quoted: bool,
    at_start: bool,
}

impl SplitState {
    const fn new() -> Self {
        Self {
            pos: 0,
            quoted: false,
            at_start: true,
        }
    }
}

/// Scan `line[st.pos..end]` (looking past `end` where a quote's meaning
/// depends on what follows); with `out`, gather the fields, the one in
/// progress in `field`.
fn split_into(
    line: &[u8],
    end: usize,
    syntax: &Syntax,
    st: &mut SplitState,
    mut out: Option<&mut Vec<Vec<u8>>>,
    field: &mut Vec<u8>,
) {
    let (delim, quote, escape) = (
        syntax.field_delimiter.as_slice(),
        syntax.quote.as_deref(),
        syntax.escape.as_deref(),
    );
    let keep = out.is_some();
    let starts = |i: usize, pat: &[u8]| !pat.is_empty() && line[i..].starts_with(pat);
    let take = |field: &mut Vec<u8>, bytes: &[u8]| {
        if keep {
            field.extend_from_slice(bytes);
        }
    };
    let mut i = st.pos;
    while i < end {
        if st.at_start {
            st.at_start = false;
            if let Some(q) = quote
                && starts(i, q)
            {
                st.quoted = true;
                i += q.len();
                continue;
            }
        }
        if st.quoted {
            let q = quote.unwrap_or_default();
            if let Some(e) = escape
                && e != q
                && starts(i, e)
            {
                let j = i + e.len();
                if starts(j, q) {
                    take(field, q);
                    i = j + q.len();
                } else if starts(j, e) {
                    take(field, e);
                    i = j + e.len();
                } else {
                    take(field, e);
                    i = j;
                }
                continue;
            }
            if starts(i, q) {
                let j = i + q.len();
                if escape == Some(q) && starts(j, q) {
                    take(field, q);
                    i = j + q.len();
                } else {
                    st.quoted = false;
                    i = j;
                }
                continue;
            }
            take(field, &line[i..=i]);
            i += 1;
            continue;
        }
        if starts(i, delim) {
            if let Some(out) = out.as_deref_mut() {
                out.push(std::mem::take(field));
            }
            i += delim.len();
            st.at_start = true;
            continue;
        }
        take(field, &line[i..=i]);
        i += 1;
    }
    st.pos = i;
}

/// Split a record into fields.
fn split(line: &[u8], syntax: &Syntax, out: &mut Vec<Vec<u8>>) {
    let mut st = SplitState::new();
    let mut field = Vec::new();
    split_into(line, line.len(), syntax, &mut st, Some(out), &mut field);
    out.push(field);
}

/// Writes records as CSV.
pub struct CsvWriter {
    field_delimiter: String,
    record_delimiter: String,
    quote: char,
    escape: char,
    always: bool,
}

impl CsvWriter {
    pub fn new(opts: &CsvOutput) -> Self {
        Self {
            field_delimiter: opts.field_delimiter.clone(),
            record_delimiter: opts.record_delimiter.clone(),
            quote: opts.quote,
            escape: opts.quote_escape,
            always: opts.quote_fields == QuoteFields::Always,
        }
    }

    fn needs_quotes(&self, s: &str) -> bool {
        self.always
            || s.contains(self.field_delimiter.as_str())
            || s.contains(self.record_delimiter.as_str())
            || s.contains(['\n', '\r', self.quote])
    }

    /// Append one record of values.
    pub fn write<'a>(&self, values: impl IntoIterator<Item = &'a Value>, out: &mut Vec<u8>) {
        self.write_texts(values.into_iter().map(|v| Cow::Owned(v.to_text())), out);
    }

    /// Append one record of texts.
    pub fn write_texts<'a>(
        &self,
        texts: impl IntoIterator<Item = Cow<'a, str>>,
        out: &mut Vec<u8>,
    ) {
        let mut s = String::new();
        for (i, text) in texts.into_iter().enumerate() {
            if i > 0 {
                s.push_str(&self.field_delimiter);
            }
            if self.needs_quotes(&text) {
                s.push(self.quote);
                for c in text.chars() {
                    if c == self.quote {
                        s.push(self.escape);
                    }
                    s.push(c);
                }
                s.push(self.quote);
            } else {
                s.push_str(&text);
            }
        }
        s.push_str(&self.record_delimiter);
        out.extend_from_slice(s.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::super::request::FileHeaderInfo;
    use super::*;

    fn opts() -> CsvInput {
        CsvInput {
            header: FileHeaderInfo::None,
            comments: Some("#".into()),
            field_delimiter: ",".into(),
            record_delimiter: "\n".into(),
            quote: Some('"'),
            quote_escape: Some('"'),
            allow_quoted_record_delimiter: false,
        }
    }

    fn read(data: &str, o: &CsvInput) -> Vec<Vec<String>> {
        let mut r = CsvReader::new(data.as_bytes(), o);
        let mut out = Vec::new();
        let mut f = Vec::new();
        while r.next_record(&mut f).unwrap() {
            out.push(f.clone());
        }
        out
    }

    #[test]
    fn quotes_delimiters_and_comments() {
        let rows = read(
            "\u{feff}a,\"b,c\",\"say \"\"hi\"\"\"\r\n# a comment\n\nx\"y,,\nlast",
            &opts(),
        );
        assert_eq!(
            rows,
            [
                vec!["a", "b,c", "say \"hi\""],
                vec!["x\"y", "", ""],
                vec!["last"],
            ]
        );
    }

    #[test]
    fn a_custom_escape_and_delimiters() {
        let mut o = opts();
        o.field_delimiter = "|".into();
        o.record_delimiter = "\t".into();
        o.quote_escape = Some('\\');
        let rows = read("1|\"a\\\"b|c\"|3\t4|5|\t", &o);
        assert_eq!(rows, [vec!["1", "a\"b|c", "3"], vec!["4", "5", ""]]);
        o.record_delimiter = "\r\n".into();
        o.field_delimiter = ",".into();
        assert_eq!(
            read("a,b\r\nc\rd,e\r\n", &o),
            [vec!["a", "b"], vec!["c\rd", "e"]]
        );
    }

    #[test]
    fn quoted_record_delimiters() {
        let data = "1,\"two\nlines\",3\n4,5,6\n";
        assert_eq!(
            read(data, &opts()),
            [vec!["1", "two"], vec!["lines\"", "3"], vec!["4", "5", "6"]]
        );
        let mut o = opts();
        o.allow_quoted_record_delimiter = true;
        assert_eq!(
            read(data, &o),
            [vec!["1", "two\nlines", "3"], vec!["4", "5", "6"]]
        );
        // A field over several lines, its quotes escaped another way.
        o.quote_escape = Some('\\');
        assert_eq!(
            read("a,\"x\ny \\\" \nz\",b\nc\n", &o),
            [vec!["a", "x\ny \" \nz", "b"], vec!["c"]]
        );
    }

    #[test]
    fn a_partial_record_is_skipped() {
        let data = "aaa,1\nbbb,2\n";
        let mut r = CsvReader::new(&data.as_bytes()[2..], &opts());
        assert!(r.skip_partial().unwrap());
        assert_eq!(r.offset(), 4);
        let mut f = Vec::new();
        assert!(r.next_record(&mut f).unwrap());
        assert_eq!(f, ["bbb", "2"]);
    }

    #[test]
    fn records_over_the_limit_are_refused() {
        let mut f = Vec::new();
        for data in [
            "x".repeat(MAX_RECORD + 10),
            format!("{}\n", "x".repeat(MAX_RECORD + 10)),
        ] {
            let mut r = CsvReader::new(data.as_bytes(), &opts());
            assert_eq!(r.next_record(&mut f).unwrap_err().code, "OverMaxRecordSize");
        }
        let fits = format!("{}\nok\n", "x".repeat(MAX_RECORD));
        let mut r = CsvReader::new(fits.as_bytes(), &opts());
        assert!(r.next_record(&mut f).unwrap());
        assert!(r.next_record(&mut f).unwrap());
        assert_eq!(f, ["ok"]);
    }

    #[test]
    fn output_quotes_as_needed_or_always() {
        let mut o = CsvOutput {
            field_delimiter: ",".into(),
            record_delimiter: "\n".into(),
            quote: '"',
            quote_escape: '"',
            quote_fields: QuoteFields::AsNeeded,
        };
        let vals = [
            Value::Str("a,b".into()),
            Value::Int(1),
            Value::Null,
            Value::Str("q\"x".into()),
            Value::Float(0.5),
        ];
        let mut out = Vec::new();
        CsvWriter::new(&o).write(&vals, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\"a,b\",1,,\"q\"\"x\",0.5\n"
        );
        o.quote_fields = QuoteFields::Always;
        o.field_delimiter = "$".into();
        o.record_delimiter = "#".into();
        o.quote_escape = '\\';
        let mut out = Vec::new();
        CsvWriter::new(&o).write(&vals[..2], &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "\"a,b\"$\"1\"#");
    }
}
