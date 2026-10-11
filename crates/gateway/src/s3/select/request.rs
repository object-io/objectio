//! The `SelectObjectContentRequest` body.
//!
//! Parsed by hand rather than through serde: delimiters are whitespace
//! (`<RecordDelimiter>\n</RecordDelimiter>`, a tab) and must be kept as
//! sent, where a deserializer would trim them away.

use super::error::{SelectError, SelectResult};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Bzip2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileHeaderInfo {
    /// The first line is data.
    None,
    /// The first line is a header, skipped.
    Ignore,
    /// The first line is a header naming the columns.
    Use,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvInput {
    pub header: FileHeaderInfo,
    /// Lines starting with this are skipped.
    pub comments: Option<String>,
    pub field_delimiter: String,
    pub record_delimiter: String,
    pub quote: Option<char>,
    /// Escapes the quote (or itself) inside a quoted field; the quote
    /// itself by default (`""`).
    pub quote_escape: Option<char>,
    /// A record delimiter inside quotes is data rather than the record's
    /// end.
    pub allow_quoted_record_delimiter: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonType {
    /// One or more JSON values, each as large as it is.
    Document,
    /// One JSON value per line.
    Lines,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputFormat {
    Csv(CsvInput),
    Json(JsonType),
    Parquet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteFields {
    Always,
    AsNeeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvOutput {
    pub field_delimiter: String,
    pub record_delimiter: String,
    pub quote: char,
    pub quote_escape: char,
    pub quote_fields: QuoteFields,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    Csv(CsvOutput),
    Json { record_delimiter: String },
}

/// `ScanRange`: the records that start within `[start, end]` (inclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanRange {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

impl ScanRange {
    /// The absolute `[first, last]` byte range in an object of `size`
    /// bytes; `None` when it holds no byte. `End` alone is the last `End`
    /// bytes, as in a `Range: bytes=-N`.
    pub fn resolve(&self, size: u64) -> Option<(u64, u64)> {
        let last_byte = size.checked_sub(1)?;
        let (first, last) = match (self.start, self.end) {
            (None, Some(n)) => (size.saturating_sub(n), last_byte),
            (Some(s), Some(e)) => (s, e.min(last_byte)),
            (Some(s), None) => (s, last_byte),
            (None, None) => (0, last_byte),
        };
        (first <= last).then_some((first, last))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectRequest {
    pub expression: String,
    pub progress: bool,
    pub compression: Compression,
    pub input: InputFormat,
    pub output: OutputFormat,
    pub scan_range: Option<ScanRange>,
}

fn malformed(why: impl Into<String>) -> SelectError {
    SelectError::new("MalformedXML", why)
}

fn missing(what: &str) -> SelectError {
    SelectError::new(
        "MissingRequiredParameter",
        format!("the request has no {what}"),
    )
}

/// One character, or `None` for an empty value.
fn one_char(v: &str, what: &str) -> SelectResult<Option<char>> {
    let mut it = v.chars();
    match (it.next(), it.next()) {
        (None, _) => Ok(None),
        (Some(c), None) => Ok(Some(c)),
        _ => Err(SelectError::new(
            "InvalidRequestParameter",
            format!("{what} must be a single character"),
        )),
    }
}

/// A delimiter: one character, or two for a record delimiter (`\r\n`).
fn delimiter(
    v: Option<&String>,
    default: &str,
    max_chars: usize,
    what: &str,
) -> SelectResult<String> {
    match v {
        None => Ok(default.to_string()),
        Some(s) if s.is_empty() => Ok(default.to_string()),
        Some(s) if s.chars().count() <= max_chars => Ok(s.clone()),
        Some(_) => Err(SelectError::new(
            "InvalidRequestParameter",
            format!(
                "{what} must be {}",
                if max_chars == 1 {
                    "a single character"
                } else {
                    "one or two characters"
                }
            ),
        )),
    }
}

fn boolean(v: Option<&String>, what: &str) -> SelectResult<bool> {
    match v.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(SelectError::new(
            "InvalidRequestParameter",
            format!("{what} must be TRUE or FALSE"),
        )),
    }
}

fn number(v: Option<&String>, what: &str) -> SelectResult<Option<u64>> {
    match v.map(|s| s.trim()) {
        None => Ok(None),
        Some(s) => s.parse().map(Some).map_err(|_| {
            SelectError::new(
                "InvalidScanRange",
                format!("{what} must be a non-negative number"),
            )
        }),
    }
}

/// Parse a request body.
pub fn parse(body: &[u8]) -> SelectResult<SelectRequest> {
    use quick_xml::events::Event;
    if body.iter().all(u8::is_ascii_whitespace) {
        return Err(SelectError::new(
            "EmptyRequestBody",
            "the request body is empty",
        ));
    }
    let mut reader = quick_xml::Reader::from_reader(body);
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();
    // Elements present (as `A/B`), and the text of each leaf.
    let mut seen: HashSet<String> = HashSet::new();
    let mut text: HashMap<String, String> = HashMap::new();
    let mut cur = String::new();
    let mut root = false;
    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| malformed(format!("the request is not well-formed XML: {e}")))?;
        match event {
            Event::Start(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if path.is_empty() {
                    if root {
                        return Err(malformed("the request has more than one root element"));
                    }
                    if name != "SelectObjectContentRequest" {
                        return Err(malformed(format!(
                            "the root element must be SelectObjectContentRequest, not {name}"
                        )));
                    }
                    root = true;
                }
                path.push(name);
                if path.len() > 1 {
                    seen.insert(path[1..].join("/"));
                }
                cur.clear();
            }
            Event::Empty(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if path.is_empty() {
                    return Err(malformed("the request has no SelectObjectContentRequest"));
                }
                let mut p = path[1..].to_vec();
                p.push(name);
                let key = p.join("/");
                seen.insert(key.clone());
                text.insert(key, String::new());
            }
            Event::Text(t) => cur.push_str(
                &t.unescape()
                    .map_err(|e| malformed(format!("bad text in the request: {e}")))?,
            ),
            Event::CData(t) => cur.push_str(
                std::str::from_utf8(&t.into_inner())
                    .map_err(|_| malformed("the request is not UTF-8"))?,
            ),
            Event::End(_) => {
                if path.len() > 1 {
                    text.insert(path[1..].join("/"), std::mem::take(&mut cur));
                }
                cur.clear();
                path.pop();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !root {
        return Err(malformed("the request has no SelectObjectContentRequest"));
    }
    if !path.is_empty() {
        return Err(malformed("the request ends inside an element"));
    }
    let get = |k: &str| text.get(k);
    let upper = |k: &str| get(k).map(|s| s.trim().to_ascii_uppercase());

    let expression = get("Expression")
        .cloned()
        .ok_or_else(|| missing("Expression"))?;
    match upper("ExpressionType").as_deref() {
        Some("SQL") => {}
        Some(other) => {
            return Err(SelectError::new(
                "InvalidExpressionType",
                format!("ExpressionType must be SQL, not {other}"),
            ));
        }
        None => return Err(missing("ExpressionType")),
    }
    let progress = boolean(get("RequestProgress/Enabled"), "RequestProgress Enabled")?;

    if !seen.contains("InputSerialization") {
        return Err(missing("InputSerialization"));
    }
    let compression = match upper("InputSerialization/CompressionType").as_deref() {
        None | Some("") | Some("NONE") => Compression::None,
        Some("GZIP") => Compression::Gzip,
        Some("BZIP2") => Compression::Bzip2,
        Some(other) => {
            return Err(SelectError::new(
                "InvalidCompressionFormat",
                format!("CompressionType must be NONE, GZIP or BZIP2, not {other}"),
            ));
        }
    };
    let formats = ["CSV", "JSON", "Parquet"]
        .iter()
        .filter(|f| seen.contains(&format!("InputSerialization/{f}")))
        .count();
    if formats > 1 {
        return Err(SelectError::new(
            "MultipleDataSourcesUnsupported",
            "InputSerialization must name one format: CSV, JSON or Parquet",
        ));
    }
    let input = if seen.contains("InputSerialization/CSV") {
        let c = |k: &str| get(&format!("InputSerialization/CSV/{k}"));
        let header = match c("FileHeaderInfo")
            .map(|s| s.trim().to_ascii_uppercase())
            .as_deref()
        {
            None | Some("") | Some("NONE") => FileHeaderInfo::None,
            Some("IGNORE") => FileHeaderInfo::Ignore,
            Some("USE") => FileHeaderInfo::Use,
            Some(other) => {
                return Err(SelectError::new(
                    "InvalidFileHeaderInfo",
                    format!("FileHeaderInfo must be NONE, IGNORE or USE, not {other}"),
                ));
            }
        };
        let quote = match c("QuoteCharacter") {
            None => Some('"'),
            Some(q) => one_char(q, "QuoteCharacter")?,
        };
        let quote_escape = match c("QuoteEscapeCharacter") {
            None => quote,
            Some(q) => one_char(q, "QuoteEscapeCharacter")?.or(quote),
        };
        let comments = match c("Comments") {
            None => Some("#".to_string()),
            Some(s) if s.is_empty() => None,
            Some(s) => one_char(s, "Comments")?.map(String::from),
        };
        InputFormat::Csv(CsvInput {
            header,
            comments,
            field_delimiter: delimiter(c("FieldDelimiter"), ",", 1, "FieldDelimiter")?,
            record_delimiter: delimiter(c("RecordDelimiter"), "\n", 2, "RecordDelimiter")?,
            quote,
            quote_escape,
            allow_quoted_record_delimiter: boolean(
                c("AllowQuotedRecordDelimiter"),
                "AllowQuotedRecordDelimiter",
            )?,
        })
    } else if seen.contains("InputSerialization/JSON") {
        match upper("InputSerialization/JSON/Type").as_deref() {
            Some("DOCUMENT") => InputFormat::Json(JsonType::Document),
            Some("LINES") => InputFormat::Json(JsonType::Lines),
            None | Some("") => {
                return Err(SelectError::new(
                    "InvalidJsonType",
                    "JSON input needs a Type: DOCUMENT or LINES",
                ));
            }
            Some(other) => {
                return Err(SelectError::new(
                    "InvalidJsonType",
                    format!("the JSON Type must be DOCUMENT or LINES, not {other}"),
                ));
            }
        }
    } else if seen.contains("InputSerialization/Parquet") {
        if compression != Compression::None {
            return Err(SelectError::new(
                "InvalidCompressionFormat",
                "Parquet input takes CompressionType NONE: Parquet compresses its own columns",
            ));
        }
        InputFormat::Parquet
    } else {
        return Err(missing(
            "input format (CSV, JSON or Parquet) in InputSerialization",
        ));
    };

    if !seen.contains("OutputSerialization") {
        return Err(missing("OutputSerialization"));
    }
    let (csv_out, json_out) = (
        seen.contains("OutputSerialization/CSV"),
        seen.contains("OutputSerialization/JSON"),
    );
    let output = match (csv_out, json_out) {
        (true, true) => {
            return Err(SelectError::new(
                "ObjectSerializationConflict",
                "OutputSerialization must name one format: CSV or JSON",
            ));
        }
        (true, false) => {
            let c = |k: &str| get(&format!("OutputSerialization/CSV/{k}"));
            let quote = match c("QuoteCharacter") {
                None => '"',
                Some(q) => one_char(q, "QuoteCharacter")?.unwrap_or('"'),
            };
            let quote_escape = match c("QuoteEscapeCharacter") {
                None => quote,
                Some(q) => one_char(q, "QuoteEscapeCharacter")?.unwrap_or(quote),
            };
            let quote_fields = match c("QuoteFields")
                .map(|s| s.trim().to_ascii_uppercase())
                .as_deref()
            {
                None | Some("") | Some("ASNEEDED") => QuoteFields::AsNeeded,
                Some("ALWAYS") => QuoteFields::Always,
                Some(other) => {
                    return Err(SelectError::new(
                        "InvalidQuoteFields",
                        format!("QuoteFields must be ALWAYS or ASNEEDED, not {other}"),
                    ));
                }
            };
            OutputFormat::Csv(CsvOutput {
                field_delimiter: delimiter(c("FieldDelimiter"), ",", 1, "FieldDelimiter")?,
                record_delimiter: delimiter(c("RecordDelimiter"), "\n", 2, "RecordDelimiter")?,
                quote,
                quote_escape,
                quote_fields,
            })
        }
        (false, true) => OutputFormat::Json {
            record_delimiter: delimiter(
                get("OutputSerialization/JSON/RecordDelimiter"),
                "\n",
                2,
                "RecordDelimiter",
            )?,
        },
        (false, false) => {
            return Err(missing(
                "output format (CSV or JSON) in OutputSerialization",
            ));
        }
    };

    let scan_range = if seen.contains("ScanRange") {
        let range = ScanRange {
            start: number(get("ScanRange/Start"), "ScanRange Start")?,
            end: number(get("ScanRange/End"), "ScanRange End")?,
        };
        if let (Some(s), Some(e)) = (range.start, range.end)
            && s > e
        {
            return Err(SelectError::new(
                "InvalidScanRange",
                "ScanRange Start must not be after its End",
            ));
        }
        Some(range)
    } else {
        None
    };

    Ok(SelectRequest {
        expression,
        progress,
        compression,
        input,
        output,
        scan_range,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(input: &str, output: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <SelectObjectContentRequest xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Expression>select * from s3object</Expression><ExpressionType>SQL</ExpressionType>\
             <InputSerialization>{input}</InputSerialization>\
             <OutputSerialization>{output}</OutputSerialization>\
             </SelectObjectContentRequest>"
        )
    }

    #[test]
    fn whitespace_delimiters_are_kept() {
        let body = req(
            "<CSV><RecordDelimiter>\t</RecordDelimiter><FieldDelimiter>|</FieldDelimiter>\
             <QuoteEscapeCharacter>\\</QuoteEscapeCharacter><FileHeaderInfo>use</FileHeaderInfo></CSV>\
             <CompressionType>GZIP</CompressionType>",
            "<CSV><RecordDelimiter>&#13;&#10;</RecordDelimiter><QuoteFields>ALWAYS</QuoteFields></CSV>",
        );
        let r = parse(body.as_bytes()).unwrap();
        let InputFormat::Csv(c) = &r.input else {
            panic!()
        };
        assert_eq!(c.record_delimiter, "\t");
        assert_eq!(c.field_delimiter, "|");
        assert_eq!(c.quote_escape, Some('\\'));
        assert_eq!(c.header, FileHeaderInfo::Use);
        assert_eq!(c.comments.as_deref(), Some("#"));
        assert_eq!(r.compression, Compression::Gzip);
        let OutputFormat::Csv(o) = &r.output else {
            panic!()
        };
        assert_eq!(o.record_delimiter, "\r\n");
        assert_eq!(o.quote_fields, QuoteFields::Always);
        assert!(!r.progress);
    }

    #[test]
    fn defaults_and_other_formats() {
        let r = parse(req("<JSON><Type>LINES</Type></JSON>", "<JSON/>").as_bytes()).unwrap();
        assert_eq!(r.input, InputFormat::Json(JsonType::Lines));
        assert_eq!(
            r.output,
            OutputFormat::Json {
                record_delimiter: "\n".into()
            }
        );
        let r = parse(req("<Parquet/>", "<CSV/>").as_bytes()).unwrap();
        assert_eq!(r.input, InputFormat::Parquet);
        let OutputFormat::Csv(o) = r.output else {
            panic!()
        };
        assert_eq!(
            (o.quote, o.quote_escape, o.field_delimiter.as_str()),
            ('"', '"', ",")
        );
    }

    #[test]
    fn bad_requests_get_their_codes() {
        let code = |b: &str| parse(b.as_bytes()).unwrap_err().code;
        assert_eq!(code(""), "EmptyRequestBody");
        assert_eq!(code("<Select"), "MalformedXML");
        assert_eq!(code("<Other/>"), "MalformedXML");
        assert_eq!(code("<SelectObjectContentRequest>"), "MalformedXML");
        assert_eq!(
            code(&req("<JSON><Type>X</Type></JSON>", "<CSV/>")),
            "InvalidJsonType"
        );
        assert_eq!(
            code(&req("<CSV/><JSON/>", "<CSV/>")),
            "MultipleDataSourcesUnsupported"
        );
        assert_eq!(
            code(&req("<CSV/>", "<CSV/><JSON/>")),
            "ObjectSerializationConflict"
        );
        assert_eq!(
            code(&req(
                "<CSV/><CompressionType>ZIP</CompressionType>",
                "<CSV/>"
            )),
            "InvalidCompressionFormat"
        );
        assert_eq!(
            code(&req(
                "<Parquet/><CompressionType>GZIP</CompressionType>",
                "<CSV/>"
            )),
            "InvalidCompressionFormat"
        );
        assert_eq!(
            code(&req(
                "<CSV><FileHeaderInfo>maybe</FileHeaderInfo></CSV>",
                "<CSV/>"
            )),
            "InvalidFileHeaderInfo"
        );
        assert_eq!(
            code(&req(
                "<CSV/>",
                "<CSV><QuoteFields>NEVER</QuoteFields></CSV>"
            )),
            "InvalidQuoteFields"
        );
        assert_eq!(
            code(&req(
                "<CSV><FieldDelimiter>ab</FieldDelimiter></CSV>",
                "<CSV/>"
            )),
            "InvalidRequestParameter"
        );
        assert_eq!(code(&req("", "<CSV/>")), "MissingRequiredParameter");
        let sql = req("<CSV/>", "<CSV/>").replace("<ExpressionType>SQL", "<ExpressionType>XPATH");
        assert_eq!(code(&sql), "InvalidExpressionType");
    }

    #[test]
    fn scan_ranges() {
        let body = req("<CSV/>", "<CSV/>").replace(
            "</SelectObjectContentRequest>",
            "<ScanRange><Start>5</Start><End>9</End></ScanRange></SelectObjectContentRequest>",
        );
        let r = parse(body.as_bytes()).unwrap().scan_range.unwrap();
        assert_eq!(r.resolve(100), Some((5, 9)));
        assert_eq!(r.resolve(7), Some((5, 6)));
        assert_eq!(r.resolve(3), None);
        let tail = ScanRange {
            start: None,
            end: Some(10),
        };
        assert_eq!(tail.resolve(100), Some((90, 99)));
        let bad = req("<CSV/>", "<CSV/>").replace(
            "</SelectObjectContentRequest>",
            "<ScanRange><Start>9</Start><End>5</End></ScanRange></SelectObjectContentRequest>",
        );
        assert_eq!(parse(bad.as_bytes()).unwrap_err().code, "InvalidScanRange");
    }
}
