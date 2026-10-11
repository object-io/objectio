//! S3 Select: `SelectObjectContent` (`POST /{bucket}/{key}?select&select-type=2`).
//!
//! The request names an SQL statement, the object's format (CSV, JSON or
//! Parquet; CSV and JSON may be GZIP or BZIP2) and the output's (CSV or
//! JSON). The gateway reads the object through its own GET path (so SSE,
//! packs and degraded reads are GET's), in ranges, each with `If-Match` on
//! the ETag the first read saw: a concurrent overwrite stops the query
//! rather than mixing two objects. CSV and JSON are read front to back,
//! decompressed and parsed as they arrive; Parquet by its footer and the
//! chunks of the columns the statement names. Memory is a few ranges and
//! one record, not the object.
//!
//! The scan runs on a blocking thread and answers in AWS's event stream
//! (`events`): `Records` in batches of 64 KiB, `Cont` or `Progress` once a
//! second, then `Stats` and `End`. A failure before the first event is an
//! S3 XML error; after it, an error event.

mod csv;
mod datetime;
mod error;
mod eval;
mod events;
mod json;
mod parquet;
mod request;
mod sql;
mod value;

use super::*;
use error::{SelectError, SelectResult};
use eval::{Aggregator, Plan, Rec, Schema};
use request::{Compression, FileHeaderInfo, InputFormat, OutputFormat, SelectRequest};
use std::borrow::Cow;
use std::io::{BufRead, BufReader, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use value::Value;

/// The first read of an object; each next one doubles, up to `MAX_CHUNK`.
const FIRST_CHUNK: u64 = 256 * 1024;
const MAX_CHUNK: u64 = 8 * 1024 * 1024;
/// The tail read first from a Parquet object: its footer, usually whole.
const PARQUET_TAIL: u64 = 64 * 1024;
/// Records are sent once this much output has gathered.
const FLUSH_AT: usize = 64 * 1024;
/// With nothing else sent for this long, a `Cont` (or `Progress`) goes out.
const TICK: Duration = Duration::from_secs(1);

/// `SelectObjectContent`.
pub(crate) async fn select_object_content_internal(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let req = match request::parse(&body) {
        Ok(r) => r,
        Err(e) => return xml_error(&e),
    };
    let query = match sql::parse(&req.expression) {
        Ok(q) => q,
        Err(e) => return xml_error(&e),
    };
    if let Some(e) = scan_range_refusal(&req) {
        return xml_error(&e);
    }
    let first_range = match req.input {
        InputFormat::Parquet => format!("bytes=-{PARQUET_TAIL}"),
        _ => format!("bytes=0-{}", FIRST_CHUNK - 1),
    };
    let source = Source {
        state,
        bucket,
        key,
        headers: read_headers(&headers),
        etag: String::new(),
        size: 0,
        handle: tokio::runtime::Handle::current(),
    };
    let (source, first) = match source.open(&first_range).await {
        Ok((source, first)) => (Arc::new(source), first),
        Err(resp) => return resp,
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Msg>(4);
    tokio::task::spawn_blocking(move || {
        let mut em = Emitter::new(tx.clone(), req.progress);
        let first = if matches!(req.input, InputFormat::Parquet) {
            // Read for the size only: the Parquet reader reads it again.
            em.scanned.fetch_add(first.len() as u64, Ordering::Relaxed);
            None
        } else {
            Some(first)
        };
        if let Err(e) = run(&req, &query, &source, first, &mut em)
            && !e.is_cancelled()
        {
            if e.is_internal() {
                warn!("S3 Select on {}/{}: {e}", source.bucket, source.key);
            }
            let _ = tx.blocking_send(Msg::Fail(e));
        }
    });
    let first = match rx.recv().await {
        Some(Msg::Frame(f)) => f,
        Some(Msg::Fail(e)) => return xml_error(&e),
        None => {
            return xml_error(&SelectError::internal(
                "the query stopped without an answer",
            ));
        }
    };
    let rest = futures::stream::unfold(rx, |mut rx| async move {
        match rx.recv().await? {
            Msg::Frame(f) => Some((f, rx)),
            // The last message: the query failed after the response began.
            Msg::Fail(e) => {
                rx.close();
                Some((Bytes::from(events::error(e.code, &e.message)), rx))
            }
        }
    });
    let stream = futures::StreamExt::map(
        futures::StreamExt::chain(futures::stream::once(async move { first }), rest),
        Ok::<_, std::io::Error>,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from_stream(stream))
        .unwrap()
}

fn xml_error(e: &SelectError) -> Response {
    let status = if e.is_internal() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    S3Error::xml_response(e.code, &e.message, status)
}

/// AWS reads a scan range of uncompressed CSV, JSON Lines and Parquet only.
fn scan_range_refusal(req: &SelectRequest) -> Option<SelectError> {
    req.scan_range?;
    let why = match &req.input {
        _ if req.compression != Compression::None => "a compressed object",
        InputFormat::Json(request::JsonType::Document) => "a JSON DOCUMENT (use LINES)",
        InputFormat::Csv(c) if c.allow_quoted_record_delimiter => {
            "CSV with AllowQuotedRecordDelimiter, whose records can't be found from the middle"
        }
        _ => return None,
    };
    Some(SelectError::new(
        "UnsupportedScanRangeInput",
        format!("ScanRange can't be used on {why}"),
    ))
}

/// The request's headers that a read of the object needs: SSE-C keys
/// (the request itself was authorized already, as a read of the object).
fn read_headers(h: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in h {
        let name = k.as_str();
        let keep = name.starts_with("x-amz-server-side-encryption-customer-")
            || name == "x-amz-expected-bucket-owner";
        if keep {
            out.append(k.clone(), v.clone());
        }
    }
    out
}

fn header_text(resp: &Response, name: header::HeaderName) -> String {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// The object being read.
struct Source {
    state: Arc<AppState>,
    bucket: String,
    key: String,
    headers: HeaderMap,
    /// The ETag of the first read; later reads must see the same.
    etag: String,
    size: u64,
    handle: tokio::runtime::Handle,
}

impl Source {
    /// The first read (`range`, a `Range` value): the object's size, its
    /// ETag, and the bytes read. A failure is the GET's own answer.
    async fn open(mut self, range: &str) -> Result<(Self, Bytes), Response> {
        let mut h = self.headers.clone();
        h.insert(header::RANGE, header::HeaderValue::from_str(range).unwrap());
        let resp = super::get::get_object_version(
            self.state.clone(),
            self.bucket.clone(),
            self.key.clone(),
            None,
            h,
        )
        .await;
        let status = resp.status();
        // `bytes a-b/total`, or `bytes */0` for an empty object.
        let total = header_text(&resp, header::CONTENT_RANGE)
            .rsplit('/')
            .next()
            .and_then(|t| t.parse::<u64>().ok());
        let etag = header_text(&resp, header::ETAG);
        let len = header_text(&resp, header::CONTENT_LENGTH)
            .parse::<u64>()
            .ok();
        match status {
            StatusCode::PARTIAL_CONTENT | StatusCode::OK => {
                self.etag = etag;
                self.size = match (status, total, len) {
                    (StatusCode::PARTIAL_CONTENT, Some(t), _) => t,
                    (_, _, Some(l)) => l,
                    _ => {
                        return Err(xml_error(&SelectError::internal(
                            "the object's size is unknown",
                        )));
                    }
                };
                let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .map_err(|e| xml_error(&SelectError::internal(format!("read failed: {e}"))))?;
                Ok((self, body))
            }
            StatusCode::RANGE_NOT_SATISFIABLE if total == Some(0) => Ok((self, Bytes::new())),
            _ => Err(resp),
        }
    }

    /// `len` bytes at `start`, from a blocking thread.
    fn read(&self, start: u64, len: u64) -> SelectResult<Bytes> {
        if len == 0 {
            return Ok(Bytes::new());
        }
        let mut h = self.headers.clone();
        let range = format!("bytes={start}-{}", start + len - 1);
        h.insert(
            header::RANGE,
            header::HeaderValue::from_str(&range).unwrap(),
        );
        if let Ok(v) = header::HeaderValue::from_str(&self.etag)
            && !self.etag.is_empty()
        {
            h.insert(header::IF_MATCH, v);
        }
        self.handle.block_on(async {
            let resp = super::get::get_object_version(
                self.state.clone(),
                self.bucket.clone(),
                self.key.clone(),
                None,
                h,
            )
            .await;
            match resp.status() {
                StatusCode::OK | StatusCode::PARTIAL_CONTENT => {
                    axum::body::to_bytes(resp.into_body(), usize::MAX)
                        .await
                        .map_err(|e| SelectError::internal(format!("an object read failed: {e}")))
                }
                StatusCode::PRECONDITION_FAILED | StatusCode::NOT_FOUND => {
                    Err(SelectError::internal(
                        "the object was overwritten or deleted while it was being read",
                    ))
                }
                s => Err(SelectError::internal(format!("an object read failed: {s}"))),
            }
        })
    }
}

/// The object from `from` to its end, in growing ranges. `first`: bytes
/// already read at `from`.
struct ObjectReader<'a> {
    source: &'a Source,
    pos: u64,
    chunk: Bytes,
    next_len: u64,
    scanned: Arc<AtomicU64>,
}

impl Read for ObjectReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.chunk.is_empty() {
            let left = self.source.size.saturating_sub(self.pos);
            if left == 0 {
                return Ok(0);
            }
            let n = self.next_len.min(left);
            self.chunk = self.source.read(self.pos, n).map_err(error::to_io)?;
            if self.chunk.is_empty() {
                return Err(error::to_io(SelectError::internal(
                    "the object ended before its size",
                )));
            }
            self.pos += self.chunk.len() as u64;
            self.next_len = (self.next_len * 2).min(MAX_CHUNK);
        }
        let n = buf.len().min(self.chunk.len());
        buf[..n].copy_from_slice(&self.chunk[..n]);
        bytes::Buf::advance(&mut self.chunk, n);
        // Counted as handed on, not as fetched: Progress then tracks the scan.
        self.scanned.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Counts bytes read through it.
struct Counting<R> {
    inner: R,
    n: Arc<AtomicU64>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.n.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// A decompressor's errors as `InvalidCompressionFormat` (a failed read
/// under it keeps its own).
struct Decompressing<R> {
    inner: R,
    kind: &'static str,
}

impl<R: Read> Read for Decompressing<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf).map_err(|e| {
            if e.get_ref().is_some_and(|i| i.is::<SelectError>()) {
                e
            } else {
                error::to_io(SelectError::new(
                    "InvalidCompressionFormat",
                    format!("the object is not valid {}: {e}", self.kind),
                ))
            }
        })
    }
}

/// The object's bytes from `from`, decompressed, counted.
fn input<'a>(
    source: &'a Source,
    from: u64,
    first: Option<Bytes>,
    compression: Compression,
    em: &Emitter,
) -> Box<dyn BufRead + 'a> {
    let (pos, chunk) = match first {
        Some(b) if from == 0 => (b.len() as u64, b),
        _ => (from, Bytes::new()),
    };
    let raw = ObjectReader {
        source,
        pos,
        chunk,
        next_len: FIRST_CHUNK,
        scanned: em.scanned.clone(),
    };
    let plain: Box<dyn Read + 'a> = match compression {
        Compression::None => Box::new(raw),
        Compression::Gzip => Box::new(Decompressing {
            inner: flate2::read::MultiGzDecoder::new(raw),
            kind: "GZIP",
        }),
        Compression::Bzip2 => Box::new(Decompressing {
            inner: bzip2::read::MultiBzDecoder::new(raw),
            kind: "BZIP2",
        }),
    };
    Box::new(BufReader::with_capacity(
        64 * 1024,
        Counting {
            inner: plain,
            n: em.processed.clone(),
        },
    ))
}

enum Msg {
    Frame(Bytes),
    Fail(SelectError),
}

/// Sends the response's events from the scan.
struct Emitter {
    tx: tokio::sync::mpsc::Sender<Msg>,
    progress: bool,
    /// Records gathered for the next `Records` event.
    pending: Vec<u8>,
    returned: u64,
    scanned: Arc<AtomicU64>,
    processed: Arc<AtomicU64>,
    last_sent: Instant,
    last_progress: Instant,
    ticks: u32,
}

impl Emitter {
    fn new(tx: tokio::sync::mpsc::Sender<Msg>, progress: bool) -> Self {
        Self {
            tx,
            progress,
            pending: Vec::new(),
            returned: 0,
            scanned: Arc::new(AtomicU64::new(0)),
            processed: Arc::new(AtomicU64::new(0)),
            last_sent: Instant::now(),
            last_progress: Instant::now(),
            ticks: 0,
        }
    }

    fn send(&mut self, frame: Vec<u8>) -> SelectResult<()> {
        self.tx
            .blocking_send(Msg::Frame(Bytes::from(frame)))
            .map_err(|_| SelectError::cancelled())?;
        self.last_sent = Instant::now();
        Ok(())
    }

    fn counts(&self) -> events::Counts {
        events::Counts {
            scanned: self.scanned.load(Ordering::Relaxed),
            processed: self.processed.load(Ordering::Relaxed),
            returned: self.returned,
        }
    }

    fn flush(&mut self) -> SelectResult<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.returned += self.pending.len() as u64;
        let frame = events::records(&self.pending);
        self.pending.clear();
        self.send(frame)
    }

    /// After each record read: send a full batch; once a second, what's
    /// gathered, progress if asked, or a `Cont` to keep the connection.
    fn tick(&mut self) -> SelectResult<()> {
        if self.pending.len() >= FLUSH_AT {
            self.flush()?;
        }
        self.ticks = self.ticks.wrapping_add(1);
        if !self.ticks.is_multiple_of(64) {
            return Ok(());
        }
        if self.progress && self.last_progress.elapsed() >= TICK {
            self.flush()?;
            self.send(events::progress(self.counts()))?;
            self.last_progress = Instant::now();
        }
        if self.last_sent.elapsed() >= TICK {
            if self.pending.is_empty() {
                self.send(events::cont())?;
            } else {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> SelectResult<()> {
        self.flush()?;
        if self.progress {
            self.send(events::progress(self.counts()))?;
        }
        self.send(events::stats(self.counts()))?;
        self.send(events::end())
    }
}

enum Writer {
    Csv(csv::CsvWriter),
    Json { record_delimiter: String },
}

impl Writer {
    fn new(out: &OutputFormat) -> Self {
        match out {
            OutputFormat::Csv(c) => Self::Csv(csv::CsvWriter::new(c)),
            OutputFormat::Json { record_delimiter } => Self::Json {
                record_delimiter: record_delimiter.clone(),
            },
        }
    }

    /// One row of named values.
    fn row(&self, cols: &[(&str, Value)], out: &mut Vec<u8>) {
        match self {
            Self::Csv(w) => w.write(cols.iter().map(|(_, v)| v), out),
            Self::Json { record_delimiter } => {
                let mut s = String::new();
                value::write_json_object(cols.iter().map(|(k, v)| (*k, v)), &mut s);
                s.push_str(record_delimiter);
                out.extend_from_slice(s.as_bytes());
            }
        }
    }

    /// `SELECT *` of a record.
    fn star(&self, rec: Rec<'_>, header: Option<&[String]>, out: &mut Vec<u8>) {
        match (self, rec) {
            (Self::Csv(w), Rec::Fields(f)) => {
                w.write_texts(f.iter().map(|s| Cow::Borrowed(s.as_str())), out);
            }
            (Self::Csv(w), Rec::Value(Value::Struct(cols))) => {
                w.write(cols.iter().map(|(_, v)| v), out)
            }
            (Self::Csv(w), Rec::Value(v)) => w.write([v], out),
            (Self::Json { record_delimiter }, rec) => {
                let mut s = String::new();
                match rec {
                    Rec::Fields(f) => {
                        let names: Vec<Cow<'_, str>> = (0..f.len())
                            .map(|i| match header.and_then(|h| h.get(i)) {
                                Some(n) => Cow::Borrowed(n.as_str()),
                                None => Cow::Owned(format!("_{}", i + 1)),
                            })
                            .collect();
                        let vals: Vec<Value> = f.iter().map(|x| Value::Str(x.clone())).collect();
                        value::write_json_object(
                            names.iter().map(|n| n.as_ref()).zip(vals.iter()),
                            &mut s,
                        );
                    }
                    Rec::Value(v @ Value::Struct(_)) => value::write_json(v, &mut s),
                    Rec::Value(v) => value::write_json_object(std::iter::once(("_1", v)), &mut s),
                }
                s.push_str(record_delimiter);
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
}

/// One query over one input's records.
struct Scan<'a> {
    plan: Plan,
    writer: Writer,
    em: &'a mut Emitter,
    agg: Option<Aggregator>,
    emitted: u64,
    /// CSV header names, for `SELECT *` as JSON.
    header: Option<Vec<String>>,
}

impl<'a> Scan<'a> {
    fn new(
        plan: Plan,
        out: &OutputFormat,
        em: &'a mut Emitter,
        header: Option<Vec<String>>,
    ) -> Self {
        let agg = plan.aggregates().then(|| Aggregator::new(&plan));
        Self {
            plan,
            writer: Writer::new(out),
            em,
            agg,
            emitted: 0,
            header,
        }
    }

    /// Whether the scan is done before it starts (`LIMIT 0`).
    fn done(&self) -> bool {
        self.agg.is_none() && self.plan.limit == Some(0)
    }

    /// Take one record; false once LIMIT is reached.
    fn record(&mut self, rec: Rec<'_>) -> SelectResult<bool> {
        let pass = self.plan.passes(rec)?;
        if pass {
            if let Some(agg) = &mut self.agg {
                agg.add(&self.plan, rec)?;
            } else {
                let before = self.em.pending.len();
                match &self.plan.items {
                    None => self
                        .writer
                        .star(rec, self.header.as_deref(), &mut self.em.pending),
                    Some(items) => {
                        let mut cols = Vec::with_capacity(items.len());
                        for (e, name) in items {
                            cols.push((name.as_str(), self.plan.eval(e, rec, &[])?));
                        }
                        self.writer.row(&cols, &mut self.em.pending);
                    }
                }
                if self.em.pending.len() - before > csv::MAX_RECORD {
                    return Err(csv::too_long());
                }
                self.emitted += 1;
            }
        }
        self.em.tick()?;
        Ok(self.plan.limit.is_none_or(|l| self.emitted < l))
    }

    fn finish(mut self) -> SelectResult<()> {
        if let Some(agg) = self.agg.take()
            && self.plan.limit != Some(0)
        {
            let results = agg.results();
            let items = self.plan.items.as_deref().unwrap_or_default();
            let empty = Value::Null;
            let mut cols = Vec::with_capacity(items.len());
            for (e, name) in items {
                cols.push((
                    name.as_str(),
                    self.plan.eval(e, Rec::Value(&empty), &results)?,
                ));
            }
            self.writer.row(&cols, &mut self.em.pending);
        }
        self.em.finish()
    }
}

fn run(
    req: &SelectRequest,
    query: &sql::Query,
    source: &Arc<Source>,
    first: Option<Bytes>,
    em: &mut Emitter,
) -> SelectResult<()> {
    let range = req.scan_range.map(|r| r.resolve(source.size));
    // A scan range holding no byte of the object: no records.
    if range == Some(None) {
        let plan = eval::bind(query, Schema::Json)?;
        return Scan::new(plan, &req.output, em, None).finish();
    }
    let range = range.flatten();
    match &req.input {
        InputFormat::Csv(opts) => run_csv(req, opts, query, source, first, range, em),
        InputFormat::Json(_) => run_json(req, query, source, first, range, em),
        InputFormat::Parquet => run_parquet(req, query, source, range, em),
    }
}

fn run_csv(
    req: &SelectRequest,
    opts: &request::CsvInput,
    query: &sql::Query,
    source: &Source,
    first: Option<Bytes>,
    range: Option<(u64, u64)>,
    em: &mut Emitter,
) -> SelectResult<()> {
    let mut fields = Vec::new();
    let delim = opts.record_delimiter.len() as u64;
    // Records that start in `[lo, hi]`: read from just before `lo`, where
    // the delimiter ending the record before would be.
    let from = range.map_or(0, |(lo, _)| lo.saturating_sub(delim));
    let mut reader = csv::CsvReader::new(
        input(source, from, first.clone(), req.compression, em),
        opts,
    );
    let mut header = None;
    if opts.header != FileHeaderInfo::None {
        if from == 0 {
            if reader.next_record(&mut fields)? {
                header = Some(std::mem::take(&mut fields));
            }
        } else {
            // The header is the object's first record, outside the range.
            let mut head = csv::CsvReader::new(input(source, 0, first, req.compression, em), opts);
            if head.next_record(&mut fields)? {
                header = Some(std::mem::take(&mut fields));
            }
        }
    }
    let names = (opts.header == FileHeaderInfo::Use)
        .then_some(header)
        .flatten();
    let plan = eval::bind(query, Schema::Csv(names.as_deref()))?;
    let mut scan = Scan::new(plan, &req.output, em, names);
    if scan.done() {
        return scan.finish();
    }
    // Read from inside the object: first to the end of the record there.
    // (From its start, records are aligned, and those before `lo` are
    // read and dropped.)
    if from > 0 && !reader.skip_partial()? {
        return scan.finish();
    }
    loop {
        let start = from + reader.offset();
        if let Some((_, hi)) = range
            && start > hi
        {
            break;
        }
        if !reader.next_record(&mut fields)? {
            break;
        }
        if range.is_some_and(|(lo, _)| start < lo) {
            continue;
        }
        if !scan.record(Rec::Fields(&fields))? {
            break;
        }
    }
    scan.finish()
}

fn run_json(
    req: &SelectRequest,
    query: &sql::Query,
    source: &Source,
    first: Option<Bytes>,
    range: Option<(u64, u64)>,
    em: &mut Emitter,
) -> SelectResult<()> {
    let plan = eval::bind(query, Schema::Json)?;
    let (from, lo) = match range {
        Some((lo, _)) => (lo.saturating_sub(1), lo),
        None => (0, 0),
    };
    let mut r = input(source, from, first, req.compression, em);
    let mut skipped = 0u64;
    if lo > 0 {
        // Past the line the range starts inside.
        let mut line = Vec::new();
        loop {
            line.clear();
            let n = (&mut r)
                .take(64 * 1024)
                .read_until(b'\n', &mut line)
                .map_err(|e| error::from_io(e, "JSONParsingError"))?;
            skipped += n as u64;
            if n == 0 || line.last() == Some(&b'\n') {
                break;
            }
        }
    }
    let last = range.map(|(_, hi)| hi.saturating_sub(from + skipped));
    if range.is_some_and(|(_, hi)| from + skipped > hi) {
        return Scan::new(plan, &req.output, em, None).finish();
    }
    let mut scan = Scan::new(plan, &req.output, em, None);
    if scan.done() {
        return scan.finish();
    }
    let mut reader = json::JsonReader::new(r, last);
    reader.for_each(&query.from_path, &mut |v| scan.record(Rec::Value(&v)))?;
    scan.finish()
}

fn run_parquet(
    req: &SelectRequest,
    query: &sql::Query,
    source: &Arc<Source>,
    range: Option<(u64, u64)>,
    em: &mut Emitter,
) -> SelectResult<()> {
    let scanned = em.scanned.clone();
    let from = Arc::clone(source);
    let file = parquet::RemoteFile::new(
        source.size,
        Box::new(move |start, len| {
            let b = from.read(start, len)?;
            scanned.fetch_add(b.len() as u64, Ordering::Relaxed);
            Ok(b)
        }),
    );
    let input = parquet::ParquetInput::open(file)?;
    let columns = input.columns();
    let mut plan = eval::bind(query, Schema::Parquet(&columns))?;
    // Read only the columns the statement names.
    let wanted = if plan.items.is_none() {
        None
    } else {
        let mut used = std::collections::BTreeSet::new();
        let mut note = |e: &sql::Expr| {
            eval::visit(e, &mut |x| {
                if let sql::Expr::Field(i, _) = x {
                    used.insert(*i);
                }
                true
            });
        };
        plan.items.iter().flatten().for_each(|(e, _)| note(e));
        plan.condition.iter().for_each(&mut note);
        plan.aggs
            .iter()
            .filter_map(|(_, a)| a.as_ref())
            .for_each(&mut note);
        if used.is_empty() && !columns.is_empty() {
            used.insert(0);
        }
        let wanted: Vec<usize> = used.into_iter().collect();
        let pos = |i: usize| wanted.iter().position(|&w| w == i).unwrap_or(i);
        for (e, _) in plan.items.iter_mut().flatten() {
            eval::remap_fields(e, &pos);
        }
        if let Some(c) = plan.condition.as_mut() {
            eval::remap_fields(c, &pos);
        }
        for a in plan.aggs.iter_mut().filter_map(|(_, a)| a.as_mut()) {
            eval::remap_fields(a, &pos);
        }
        Some(wanted)
    };
    let processed = em.processed.clone();
    let mut scan = Scan::new(plan, &req.output, em, None);
    if scan.done() {
        return scan.finish();
    }
    input.scan(wanted.as_deref(), range, &processed, &mut |v| {
        scan.record(Rec::Value(&v))
    })?;
    scan.finish()
}
