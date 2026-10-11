//! S3 Select (`SelectObjectContent`) against a running cluster: CSV, JSON
//! and Parquet objects, compressed ones, aggregates, scan ranges, and the
//! answer's event stream, each message's CRCs checked; errors before the
//! stream (S3 XML) and in it (an error event).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::Arc;

use objectio_e2e::{Cluster, Response};
use serde_json::json;

fn bucket(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/buckets", json!({ "name": name }))
        .expect_ok();
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A `SelectObjectContentRequest`; `input` and `output` are the inside of
/// `InputSerialization` and `OutputSerialization`; `extra` goes at the end.
fn request(sql: &str, input: &str, output: &str, extra: &str) -> String {
    format!(
        "<SelectObjectContentRequest xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Expression>{}</Expression><ExpressionType>SQL</ExpressionType>\
         <InputSerialization>{input}</InputSerialization>\
         <OutputSerialization>{output}</OutputSerialization>{extra}\
         </SelectObjectContentRequest>",
        xml_escape(sql)
    )
}

fn select(c: &Cluster, path: &str, body: &str) -> Response {
    c.request(
        "POST",
        &format!("{path}?select&select-type=2"),
        body.as_bytes(),
    )
}

/// One event-stream message.
#[derive(Debug)]
struct Msg {
    headers: HashMap<String, String>,
    payload: Vec<u8>,
}

impl Msg {
    fn kind(&self) -> &str {
        self.headers
            .get(":event-type")
            .or_else(|| self.headers.get(":message-type"))
            .map_or("", String::as_str)
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

/// Split a response body into its messages, checking each one's prelude
/// and message CRCs.
fn messages(body: &[u8]) -> Vec<Msg> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let total = be32(rest) as usize;
        let hlen = be32(&rest[4..]) as usize;
        let m = &rest[..total];
        assert_eq!(be32(&m[8..]), crc32fast::hash(&m[..8]), "prelude CRC");
        assert_eq!(
            be32(&m[total - 4..]),
            crc32fast::hash(&m[..total - 4]),
            "message CRC"
        );
        let mut headers = HashMap::new();
        let mut i = 12;
        while i < 12 + hlen {
            let n = m[i] as usize;
            let name = String::from_utf8(m[i + 1..=i + n].to_vec()).unwrap();
            i += 1 + n;
            assert_eq!(m[i], 7, "string header");
            let vl = u16::from_be_bytes([m[i + 1], m[i + 2]]) as usize;
            let value = String::from_utf8(m[i + 3..i + 3 + vl].to_vec()).unwrap();
            i += 3 + vl;
            headers.insert(name, value);
        }
        out.push(Msg {
            headers,
            payload: m[12 + hlen..total - 4].to_vec(),
        });
        rest = &rest[total..];
    }
    out
}

/// The records of a successful answer, after checking it ends with
/// `Stats` then `End`.
fn records(r: &Response) -> String {
    r.expect(200);
    let msgs = messages(&r.bytes);
    let kinds: Vec<&str> = msgs.iter().map(Msg::kind).collect();
    assert!(
        kinds.ends_with(&["Stats", "End"]),
        "the stream must end with Stats, End: {kinds:?}"
    );
    msgs.iter()
        .filter(|m| m.kind() == "Records")
        .map(|m| String::from_utf8(m.payload.clone()).unwrap())
        .collect()
}

/// `(scanned, processed, returned)` from the `Stats` event.
fn stats(r: &Response) -> (u64, u64, u64) {
    let msgs = messages(&r.bytes);
    let s = msgs.iter().find(|m| m.kind() == "Stats").expect("Stats");
    let xml = String::from_utf8(s.payload.clone()).unwrap();
    let field = |name: &str| -> u64 {
        xml.split(&format!("<{name}>"))
            .nth(1)
            .and_then(|x| x.split('<').next())
            .and_then(|x| x.parse().ok())
            .unwrap_or_else(|| panic!("{name} in {xml}"))
    };
    (
        field("BytesScanned"),
        field("BytesProcessed"),
        field("BytesReturned"),
    )
}

fn xml_code(r: &Response) -> String {
    r.text()
        .split("<Code>")
        .nth(1)
        .and_then(|s| s.split("</Code>").next())
        .unwrap_or_default()
        .to_string()
}

const CSV_IN: &str = "<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>";
const CSV_OUT: &str = "<CSV/>";
const JSON_OUT: &str = "<JSON/>";

const PEOPLE: &str = "name,age,city\n\
                      alice,30,\"Paris, FR\"\n\
                      bob,25,Berlin\n\
                      # a comment line\n\
                      carol,41,\"say \"\"hi\"\"\"\n";

#[test]
fn csv_rows_stream_with_stats_and_end() {
    let c = Cluster::start();
    bucket(&c, "sel");
    c.request("PUT", "/sel/people.csv", PEOPLE.as_bytes())
        .expect(200);

    let r = select(
        &c,
        "/sel/people.csv",
        &request(
            "SELECT s.name, s.city FROM S3Object s WHERE CAST(s.age AS INT) > 26",
            CSV_IN,
            CSV_OUT,
            "",
        ),
    );
    let out = records(&r);
    assert_eq!(out, "alice,\"Paris, FR\"\ncarol,\"say \"\"hi\"\"\"\n");
    let (scanned, processed, returned) = stats(&r);
    assert_eq!(scanned, PEOPLE.len() as u64);
    assert_eq!(processed, PEOPLE.len() as u64);
    assert_eq!(returned, out.len() as u64);

    // JSON out, names from the header; LIMIT.
    let r = select(
        &c,
        "/sel/people.csv",
        &request("select * from s3object limit 2", CSV_IN, JSON_OUT, ""),
    );
    assert_eq!(
        records(&r),
        "{\"name\":\"alice\",\"age\":\"30\",\"city\":\"Paris, FR\"}\n\
         {\"name\":\"bob\",\"age\":\"25\",\"city\":\"Berlin\"}\n"
    );

    // Positional columns, custom output delimiters, quoting always.
    let r = select(
        &c,
        "/sel/people.csv",
        &request(
            "select _1, upper(_3) from s3object where _2 = '25'",
            "<CSV><FileHeaderInfo>IGNORE</FileHeaderInfo></CSV>",
            "<CSV><FieldDelimiter>|</FieldDelimiter><RecordDelimiter>&#13;&#10;</RecordDelimiter>\
             <QuoteFields>ALWAYS</QuoteFields></CSV>",
            "",
        ),
    );
    assert_eq!(records(&r), "\"bob\"|\"BERLIN\"\r\n");
}

#[test]
fn json_documents_and_lines() {
    let c = Cluster::start();
    bucket(&c, "sel");
    let doc = json!({
        "meta": {"skip": [1, 2, {"deep": true}]},
        "rows": [
            {"id": 1, "tags": ["a", "b"], "who": {"name": "x"}},
            {"id": 2, "tags": [], "who": {"name": "y"}},
            {"id": 3, "who": null},
        ]
    });
    c.request("PUT", "/sel/doc.json", doc.to_string().as_bytes())
        .expect(200);
    let doc_in = "<JSON><Type>DOCUMENT</Type></JSON>";

    let r = select(
        &c,
        "/sel/doc.json",
        &request(
            "SELECT r.id, r.who.name AS n, r.tags[0] FROM S3Object[*].rows[*] r WHERE r.id < 3",
            doc_in,
            JSON_OUT,
            "",
        ),
    );
    assert_eq!(
        records(&r),
        "{\"id\":1,\"n\":\"x\",\"_3\":\"a\"}\n{\"id\":2,\"n\":\"y\"}\n"
    );

    // As in AWS, a path ending on the array gives it as one record; `[*]`
    // reads its elements. `_1` is the record (RGW's name for it).
    let r = select(
        &c,
        "/sel/doc.json",
        &request("select count(*) from s3object[*].rows", doc_in, CSV_OUT, ""),
    );
    assert_eq!(records(&r), "1\n");
    let r = select(
        &c,
        "/sel/doc.json",
        &request(
            "select count(*), sum(_1.id), max(_1.id) from s3object[*].rows[*]",
            doc_in,
            CSV_OUT,
            "",
        ),
    );
    assert_eq!(records(&r), "3,6,3\n");
    // In LIKE, brackets are themselves.
    let r = select(
        &c,
        "/sel/doc.json",
        &request(
            "select count(*) from s3object[*].rows[*] r where r.who.name like '[x-y]'",
            doc_in,
            CSV_OUT,
            "",
        ),
    );
    assert_eq!(records(&r), "0\n");

    let lines = "{\"a\": 1, \"b\": \"x\"}\n{\"a\": 2}\n\n{\"a\": 3, \"b\": \"z\"}\n";
    c.request("PUT", "/sel/lines.json", lines.as_bytes())
        .expect(200);
    let r = select(
        &c,
        "/sel/lines.json",
        &request(
            "select s.a, s.b from s3object s where s.b is not missing",
            "<JSON><Type>LINES</Type></JSON>",
            "<JSON><RecordDelimiter>;</RecordDelimiter></JSON>",
            "",
        ),
    );
    assert_eq!(records(&r), "{\"a\":1,\"b\":\"x\"};{\"a\":3,\"b\":\"z\"};");
}

/// A CSV of `n` rows `i,i*2,name-i`.
fn numbers(n: u64) -> String {
    let mut s = String::from("a,b,name\n");
    for i in 0..n {
        writeln!(s, "{i},{},name-{i}", i * 2).unwrap();
    }
    s
}

#[test]
fn aggregates_over_a_multi_range_object() {
    let c = Cluster::start();
    bucket(&c, "sel");
    // A few MB: read in several ranges.
    let n = 200_000u64;
    let data = numbers(n);
    c.request("PUT", "/sel/n.csv", data.as_bytes()).expect(200);
    let r = select(
        &c,
        "/sel/n.csv",
        &request(
            "select count(*), sum(cast(a as int)), min(cast(b as int)), max(cast(b as int)), \
             avg(cast(a as int)), count(name) from s3object where cast(a as int) % 2 = 0",
            CSV_IN,
            CSV_OUT,
            "",
        ),
    );
    let half = n / 2;
    let sum: u64 = (0..n).step_by(2).sum();
    assert_eq!(
        records(&r),
        format!("{half},{sum},0,{},{}.0,{half}\n", (n - 2) * 2, n / 2 - 1)
    );
    let (scanned, processed, _) = stats(&r);
    assert_eq!(scanned, data.len() as u64);
    assert_eq!(processed, data.len() as u64);

    // An aggregate over no rows: COUNT 0, the others NULL.
    let r = select(
        &c,
        "/sel/n.csv",
        &request(
            "select count(*), sum(a), min(a) from s3object where a = 'none'",
            CSV_IN,
            JSON_OUT,
            "",
        ),
    );
    assert_eq!(records(&r), "{\"_1\":0,\"_2\":null,\"_3\":null}\n");
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn bzip2(data: &[u8]) -> Vec<u8> {
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn gzip_and_bzip2_objects() {
    let c = Cluster::start();
    bucket(&c, "sel");
    let data = numbers(20_000);
    let sql = "select name from s3object where cast(a as int) between 100 and 102";
    let want = "name-100\nname-101\nname-102\n";
    for (key, body, kind) in [
        ("n.csv.gz", gzip(data.as_bytes()), "GZIP"),
        ("n.csv.bz2", bzip2(data.as_bytes()), "BZIP2"),
    ] {
        c.request("PUT", &format!("/sel/{key}"), &body).expect(200);
        let input = format!(
            "<CompressionType>{kind}</CompressionType><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>"
        );
        let r = select(
            &c,
            &format!("/sel/{key}"),
            &request(sql, &input, CSV_OUT, ""),
        );
        assert_eq!(records(&r), want, "{kind}");
        let (scanned, processed, _) = stats(&r);
        assert_eq!(
            scanned,
            body.len() as u64,
            "{kind}: scanned is the stored size"
        );
        assert_eq!(
            processed,
            data.len() as u64,
            "{kind}: processed is decompressed"
        );
    }
    // Plain text named GZIP is refused in the stream's place.
    c.request("PUT", "/sel/plain", data.as_bytes()).expect(200);
    let r = select(
        &c,
        "/sel/plain",
        &request(
            sql,
            "<CompressionType>GZIP</CompressionType><CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>",
            CSV_OUT,
            "",
        ),
    );
    assert_eq!(r.status, 400, "{}", r.text());
    assert_eq!(xml_code(&r), "InvalidCompressionFormat");
}

/// A Parquet file: `id` (int64), `name` (string), `score` (double, null on
/// every third row), in row groups of 1000.
fn parquet_file(rows: i64) -> Vec<u8> {
    use parquet::data_type::{ByteArray, ByteArrayType, DoubleType, Int64Type};
    use parquet::file::properties::WriterProperties;
    use parquet::file::writer::SerializedFileWriter;
    use parquet::schema::parser::parse_message_type;

    let schema = Arc::new(
        parse_message_type(
            "message s { REQUIRED INT64 id; REQUIRED BYTE_ARRAY name (UTF8); OPTIONAL DOUBLE score; }",
        )
        .unwrap(),
    );
    let mut out = Vec::new();
    let mut w = SerializedFileWriter::new(
        &mut out,
        schema,
        Arc::new(WriterProperties::builder().build()),
    )
    .unwrap();
    for start in (0..rows).step_by(1000) {
        let ids: Vec<i64> = (start..(start + 1000).min(rows)).collect();
        let names: Vec<ByteArray> = ids
            .iter()
            .map(|i| ByteArray::from(format!("n{i}").as_str()))
            .collect();
        let scores: Vec<f64> = ids
            .iter()
            .filter(|i| *i % 3 != 0)
            .map(|i| f64::from(i32::try_from(*i).unwrap()) / 2.0)
            .collect();
        let defs: Vec<i16> = ids.iter().map(|i| i16::from(*i % 3 != 0)).collect();
        let mut rg = w.next_row_group().unwrap();
        let mut col = rg.next_column().unwrap().unwrap();
        col.typed::<Int64Type>()
            .write_batch(&ids, None, None)
            .unwrap();
        col.close().unwrap();
        let mut col = rg.next_column().unwrap().unwrap();
        col.typed::<ByteArrayType>()
            .write_batch(&names, None, None)
            .unwrap();
        col.close().unwrap();
        let mut col = rg.next_column().unwrap().unwrap();
        col.typed::<DoubleType>()
            .write_batch(&scores, Some(&defs), None)
            .unwrap();
        col.close().unwrap();
        rg.close().unwrap();
    }
    w.close().unwrap();
    out
}

#[test]
fn parquet_objects() {
    let c = Cluster::start();
    bucket(&c, "sel");
    let file = parquet_file(5000);
    c.request("PUT", "/sel/t.parquet", &file).expect(200);
    let r = select(
        &c,
        "/sel/t.parquet",
        &request(
            "select name, score from s3object where id between 3 and 5",
            "<Parquet/>",
            JSON_OUT,
            "",
        ),
    );
    assert_eq!(
        records(&r),
        "{\"name\":\"n3\",\"score\":null}\n{\"name\":\"n4\",\"score\":2.0}\n{\"name\":\"n5\",\"score\":2.5}\n"
    );
    let r = select(
        &c,
        "/sel/t.parquet",
        &request(
            "select count(*), count(score), max(id), min(name) from s3object",
            "<Parquet/>",
            CSV_OUT,
            "",
        ),
    );
    assert_eq!(records(&r), "5000,3333,4999,n0\n");
    let r = select(
        &c,
        "/sel/t.parquet",
        &request(
            "select * from s3object s where s.id = 4997",
            "<Parquet/>",
            CSV_OUT,
            "",
        ),
    );
    assert_eq!(records(&r), "4997,n4997,2498.5\n");
    let (scanned, _, _) = stats(&r);
    assert!(scanned > 0 && scanned <= file.len() as u64 * 2, "{scanned}");

    // Not Parquet at all.
    c.request("PUT", "/sel/fake.parquet", b"a,b\n1,2\n")
        .expect(200);
    let r = select(
        &c,
        "/sel/fake.parquet",
        &request("select * from s3object", "<Parquet/>", CSV_OUT, ""),
    );
    assert_eq!(r.status, 400, "{}", r.text());
    assert_eq!(xml_code(&r), "ParquetParsingError");
}

#[test]
fn errors_before_and_during_the_stream() {
    let c = Cluster::start();
    bucket(&c, "sel");
    c.request("PUT", "/sel/people.csv", PEOPLE.as_bytes())
        .expect(200);

    for (sql, code) in [
        ("select from s3object", "ParseEmptySelect"),
        ("select * from table", "InvalidDataSource"),
        ("select nosuch(_1) from s3object", "UnsupportedFunction"),
        ("select nosuch from s3object", "MissingHeaders"),
        (
            "select _1 from s3object where count(*) > 1",
            "ParseUnsupportedSyntax",
        ),
    ] {
        let r = select(&c, "/sel/people.csv", &request(sql, CSV_IN, CSV_OUT, ""));
        assert_eq!(r.status, 400, "{sql}: {}", r.text());
        assert_eq!(xml_code(&r), code, "{sql}");
    }
    let r = select(&c, "/sel/people.csv", "<SelectObjectContentRequest>");
    assert_eq!(xml_code(&r), "MalformedXML");
    let r = select(
        &c,
        "/sel/missing.csv",
        &request("select * from s3object", CSV_IN, CSV_OUT, ""),
    );
    assert_eq!(r.status, 404, "{}", r.text());
    assert_eq!(xml_code(&r), "NoSuchKey");

    // Enough good rows to start the stream, then one that can't be cast:
    // an error event ends it, with no Stats or End.
    let mut data = numbers(20_000);
    data.push_str("oops,1,x\n");
    c.request("PUT", "/sel/bad.csv", data.as_bytes())
        .expect(200);
    let r = select(
        &c,
        "/sel/bad.csv",
        &request("select cast(a as int) from s3object", CSV_IN, CSV_OUT, ""),
    );
    r.expect(200);
    let msgs = messages(&r.bytes);
    let last = msgs.last().unwrap();
    assert_eq!(last.kind(), "error", "{msgs:?}");
    assert_eq!(last.headers[":error-code"], "CastFailed");
    assert!(msgs.iter().any(|m| m.kind() == "Records"));
    assert!(!msgs.iter().any(|m| m.kind() == "End"));
}

#[test]
fn progress_and_scan_ranges() {
    let c = Cluster::start();
    bucket(&c, "sel");
    let data = "1,a\n22,bb\n333,ccc\n4444,dddd\n";
    c.request("PUT", "/sel/r.csv", data.as_bytes()).expect(200);
    let r = select(
        &c,
        "/sel/r.csv",
        &request(
            "select _2 from s3object",
            "<CSV/>",
            CSV_OUT,
            "<RequestProgress><Enabled>true</Enabled></RequestProgress>",
        ),
    );
    assert_eq!(records(&r), "a\nbb\nccc\ndddd\n");
    let msgs = messages(&r.bytes);
    let kinds: Vec<&str> = msgs.iter().map(Msg::kind).collect();
    assert!(kinds.ends_with(&["Progress", "Stats", "End"]), "{kinds:?}");

    // Records that start in [5, 12]: "22,bb" starts at 4, outside;
    // "333,ccc" starts at 10, inside, and is read to its end.
    let range = |start: u64, end: u64| {
        format!("<ScanRange><Start>{start}</Start><End>{end}</End></ScanRange>")
    };
    let r = select(
        &c,
        "/sel/r.csv",
        &request("select _2 from s3object", "<CSV/>", CSV_OUT, &range(5, 12)),
    );
    assert_eq!(records(&r), "ccc\n");
    let r = select(
        &c,
        "/sel/r.csv",
        &request("select _2 from s3object", "<CSV/>", CSV_OUT, &range(4, 10)),
    );
    assert_eq!(records(&r), "bb\nccc\n");
    let r = select(
        &c,
        "/sel/r.csv",
        &request("select _2 from s3object", "<CSV/>", CSV_OUT, &range(0, 0)),
    );
    assert_eq!(records(&r), "a\n");

    // With a header, read apart when the range starts past it.
    let with_header = "x,y\n1,a\n22,bb\n333,ccc\n";
    c.request("PUT", "/sel/h.csv", with_header.as_bytes())
        .expect(200);
    for ((start, end), want) in [((1, 9), "a\nbb\n"), ((5, 20), "bb\nccc\n")] {
        let r = select(
            &c,
            "/sel/h.csv",
            &request(
                "select y from s3object",
                CSV_IN,
                CSV_OUT,
                &range(start, end),
            ),
        );
        assert_eq!(records(&r), want, "[{start}, {end}]");
    }

    let lines = "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n";
    c.request("PUT", "/sel/r.json", lines.as_bytes())
        .expect(200);
    let r = select(
        &c,
        "/sel/r.json",
        &request(
            "select s.n from s3object s",
            "<JSON><Type>LINES</Type></JSON>",
            CSV_OUT,
            &range(1, 8),
        ),
    );
    assert_eq!(records(&r), "2\n");

    // A range over a compressed object is refused.
    let r = select(
        &c,
        "/sel/r.csv",
        &request(
            "select * from s3object",
            "<CompressionType>GZIP</CompressionType><CSV/>",
            CSV_OUT,
            &range(0, 1),
        ),
    );
    assert_eq!(xml_code(&r), "UnsupportedScanRangeInput");
}
