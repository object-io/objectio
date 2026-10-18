//! Delivery: records from the spool, batched by where they go, written as
//! log objects.
//!
//! One task per gateway reads the spool in order and keeps a batch per
//! destination (target bucket, prefix, key format; with a partitioned
//! format also the source bucket and owner, which the key names). A batch
//! is written once its first record has waited [`Timing::roll`], or it
//! holds [`Timing::max_records`] records or [`MAX_OBJECT_BYTES`]. The
//! spool's cursor moves only past records whose batch is written (or
//! refused), so a gateway killed with batches open delivers them when it
//! is back: at least once — a batch written just before a crash can be
//! written again, under another name.
//!
//! Before a batch is written, the target's consent is checked again for
//! each source in it (`super::check_target`): records for a target that
//! is gone, in another tenant, or whose policy no longer lets them in are
//! dropped and counted. A write that fails otherwise (meta or OSDs
//! unavailable) is retried with backoff; that batch then holds the cursor,
//! and the spool keeps everything after it.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use chrono::{DateTime, Utc};
use tracing::{debug, warn};

use super::{
    CURSOR, DELIVERED, DROPPED, FAILURES, KeyFormat, Logger, Record, Refusal, check_target, reason,
};
use crate::audit_spool::{Pos, Spool};
use crate::s3::AppState;

/// A log object is written once its batch is this big.
const MAX_OBJECT_BYTES: usize = 16 << 20;
/// Records read from the spool at a time.
const READ_BATCH: usize = 2_000;
/// Past this much held in open batches (targets failing), the spool is not
/// read further until some are written.
const HOLD_MAX: usize = 256 << 20;
/// How often batches are looked at when nothing new arrives.
const TICK: Duration = Duration::from_millis(250);

/// Where a batch goes: target, prefix, key format, and for a partitioned
/// format the source bucket and owner.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Dest {
    target: String,
    prefix: String,
    format: KeyFormat,
    source: String,
    owner: String,
}

impl Dest {
    fn of(r: &Record) -> Self {
        let partitioned = matches!(r.kf, KeyFormat::Partitioned { .. });
        Self {
            target: r.tb.clone(),
            prefix: r.tp.clone(),
            format: r.kf.clone(),
            source: if partitioned {
                r.sb.clone()
            } else {
                String::new()
            },
            owner: if partitioned {
                r.so.clone()
            } else {
                String::new()
            },
        }
    }
}

struct Batch {
    /// The spool position its first record starts at.
    start: Pos,
    opened: Instant,
    records: Vec<Record>,
    bytes: usize,
    attempts: u32,
    next_try: Instant,
}

enum Outcome {
    /// Written, or refused for good: the batch is done.
    Done,
    /// Try again later.
    Retry,
}

/// The name of a log object.
fn object_key(
    dest: &Dest,
    region: &str,
    delivered: DateTime<Utc>,
    first_event: i64,
    unique: &str,
) -> String {
    let stamp = delivered.format("%Y-%m-%d-%H-%M-%S");
    match dest.format {
        KeyFormat::Simple => format!("{}{stamp}-{unique}", dest.prefix),
        KeyFormat::Partitioned { event_time } => {
            let day = if event_time {
                DateTime::from_timestamp(first_event, 0).unwrap_or(delivered)
            } else {
                delivered
            };
            format!(
                "{}{}/{region}/{}/{}/{stamp}-{unique}",
                dest.prefix,
                dest.owner,
                dest.source,
                day.format("%Y/%m/%d"),
            )
        }
    }
}

/// A batch's unique string: from this gateway's spool id and where the
/// batch starts in it, so writing the same batch again (a retry) replaces
/// the object rather than adding one.
fn unique(spool_id: &str, dest: &Dest, start: Pos) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    spool_id.hash(&mut h);
    dest.hash(&mut h);
    start.seg.hash(&mut h);
    start.off.hash(&mut h);
    format!("{:016X}", h.finish())
}

/// Start delivering what `logger` spools.
pub fn spawn(state: Arc<AppState>, logger: Arc<Logger>) {
    let Some(spool) = logger.spool.clone() else {
        return;
    };
    tokio::spawn(run(state, logger, spool));
}

async fn run(state: Arc<AppState>, logger: Arc<Logger>, spool: Arc<Spool>) {
    let mut read_at = spool.cursor(CURSOR);
    let mut saved = read_at;
    let mut batches: HashMap<Dest, Batch> = HashMap::new();
    let mut durable = spool.durable();
    loop {
        let held: usize = batches.values().map(|b| b.bytes).sum();
        let lines = if held < HOLD_MAX {
            let s = Arc::clone(&spool);
            match tokio::task::spawn_blocking(move || s.read(read_at, READ_BATCH)).await {
                Ok(Ok(l)) => l,
                Ok(Err(e)) => {
                    warn!("bucket logging: reading the spool: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                Err(e) => {
                    warn!("bucket logging: reading the spool: {e}");
                    continue;
                }
            }
        } else {
            Vec::new()
        };
        let full_read = lines.len() == READ_BATCH;
        for (pos, line) in lines {
            match serde_json::from_slice::<Record>(&line) {
                Ok(r) => {
                    let dest = Dest::of(&r);
                    let b = batches.entry(dest).or_insert_with(|| Batch {
                        start: read_at,
                        opened: Instant::now(),
                        records: Vec::new(),
                        bytes: 0,
                        attempts: 0,
                        next_try: Instant::now(),
                    });
                    b.bytes += r.line.len() + 1;
                    b.records.push(r);
                }
                Err(e) => {
                    warn!("bucket logging: a spool record that doesn't parse: {e}");
                    DROPPED.inc(&reason("unreadable"));
                }
            }
            read_at = pos;
        }

        let draining = logger.draining.load(Ordering::Relaxed);
        let now = Instant::now();
        let due: Vec<Dest> = batches
            .iter()
            .filter(|(_, b)| {
                now >= b.next_try
                    && (draining
                        || b.opened.elapsed() >= logger.timing.roll
                        || b.records.len() >= logger.timing.max_records
                        || b.bytes >= MAX_OBJECT_BYTES)
            })
            .map(|(d, _)| d.clone())
            .collect();
        for dest in due {
            let Some(batch) = batches.get_mut(&dest) else {
                continue;
            };
            match deliver(&state, &logger, &spool.id, &dest, batch).await {
                Outcome::Done => {
                    batches.remove(&dest);
                }
                Outcome::Retry => {
                    FAILURES.inc("");
                    batch.attempts += 1;
                    let backoff = Duration::from_secs(1 << batch.attempts.min(5));
                    batch.next_try = Instant::now() + backoff;
                }
            }
        }

        // Everything before the oldest open batch is delivered.
        let cursor = batches.values().map(|b| b.start).min().unwrap_or(read_at);
        if cursor != saved {
            match spool.advance(CURSOR, cursor) {
                Ok(()) => saved = cursor,
                Err(e) => warn!("bucket logging: cannot save the spool cursor: {e}"),
            }
        }
        if !full_read {
            tokio::select! {
                _ = durable.changed() => {}
                () = tokio::time::sleep(TICK) => {}
            }
        }
    }
}

/// Write one batch.
async fn deliver(
    state: &Arc<AppState>,
    logger: &Logger,
    spool_id: &str,
    dest: &Dest,
    batch: &Batch,
) -> Outcome {
    // The target's consent, for each source in the batch.
    let mut allowed: HashMap<(&str, &str, &str), bool> = HashMap::new();
    for r in &batch.records {
        let source = (r.sb.as_str(), r.so.as_str(), r.st.as_str());
        if allowed.contains_key(&source) {
            continue;
        }
        let ok = match check_target(
            &logger.meta,
            &dest.target,
            &dest.prefix,
            &r.sb,
            &r.so,
            &r.st,
        )
        .await
        {
            Ok(()) => true,
            Err(Refusal::Unavailable(e)) => {
                warn!("bucket logging: checking {}: {e}; will retry", dest.target);
                return Outcome::Retry;
            }
            Err(why) => {
                warn!(
                    "bucket logging: {} doesn't take logs from {} ({why:?}); dropped",
                    dest.target, r.sb
                );
                false
            }
        };
        allowed.insert(source, ok);
    }
    let mut body = String::with_capacity(batch.bytes);
    let mut kept = 0u64;
    let mut refused = 0u64;
    for r in &batch.records {
        if allowed
            .get(&(r.sb.as_str(), r.so.as_str(), r.st.as_str()))
            .copied()
            .unwrap_or(false)
        {
            body.push_str(&r.line);
            body.push('\n');
            kept += 1;
        } else {
            refused += 1;
        }
    }
    if refused > 0 {
        DROPPED.add(&reason("refused"), refused);
    }
    if kept == 0 {
        return Outcome::Done;
    }
    let first_event = batch.records.first().map_or(0, |r| r.at);
    let key = object_key(
        dest,
        &logger.region,
        Utc::now(),
        first_event,
        &unique(spool_id, dest, batch.start),
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain"),
    );
    let put = crate::s3::put_object(
        State(Arc::clone(state)),
        Path((dest.target.clone(), key.clone())),
        None,
        headers,
        Bytes::from(body),
    )
    .await;
    let status = put.status();
    if status == StatusCode::OK {
        debug!("bucket logging: {kept} records to {}/{key}", dest.target);
        DELIVERED.add("", kept);
        Outcome::Done
    } else if status.is_client_error() {
        // The target refuses it (gone since the check, over its quota):
        // retrying won't change that.
        warn!(
            "bucket logging: {}/{key}: {status}; {kept} records dropped",
            dest.target
        );
        DROPPED.add(&reason("target-refused"), kept);
        Outcome::Done
    } else {
        warn!(
            "bucket logging: {}/{key}: {status}; will retry",
            dest.target
        );
        Outcome::Retry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(format: KeyFormat, prefix: &str) -> Dest {
        Dest {
            target: "logs".into(),
            prefix: prefix.into(),
            format,
            source: "src".into(),
            owner: "owner".into(),
        }
    }

    #[test]
    fn log_objects_are_named_as_s3_names_them() {
        let at = DateTime::parse_from_rfc3339("2026-10-05T07:08:09Z")
            .unwrap()
            .with_timezone(&Utc);
        let event = DateTime::parse_from_rfc3339("2026-10-04T23:59:00Z")
            .unwrap()
            .timestamp();
        assert_eq!(
            object_key(
                &dest(KeyFormat::Simple, "log/"),
                "us-east-1",
                at,
                event,
                "ABC"
            ),
            "log/2026-10-05-07-08-09-ABC"
        );
        assert_eq!(
            object_key(&dest(KeyFormat::Simple, ""), "us-east-1", at, event, "ABC"),
            "2026-10-05-07-08-09-ABC"
        );
        assert_eq!(
            object_key(
                &dest(KeyFormat::Partitioned { event_time: false }, "log/"),
                "us-east-1",
                at,
                event,
                "ABC"
            ),
            "log/owner/us-east-1/src/2026/10/05/2026-10-05-07-08-09-ABC"
        );
        assert_eq!(
            object_key(
                &dest(KeyFormat::Partitioned { event_time: true }, ""),
                "us-east-1",
                at,
                event,
                "ABC"
            ),
            "owner/us-east-1/src/2026/10/04/2026-10-05-07-08-09-ABC"
        );
    }

    #[test]
    fn a_batch_written_again_keeps_its_name() {
        let d = dest(KeyFormat::Simple, "log/");
        let p = Pos { seg: 1, off: 10 };
        assert_eq!(unique("g", &d, p), unique("g", &d, p));
        assert_ne!(unique("g", &d, p), unique("h", &d, p));
        assert_ne!(unique("g", &d, p), unique("g", &d, Pos { seg: 1, off: 11 }));
        assert_eq!(unique("g", &d, p).len(), 16);
    }

    /// Simple-prefix records from different sources share a batch (one
    /// object holds them all, as in S3); partitioned ones don't.
    #[test]
    fn records_are_batched_by_where_they_go() {
        let rec = |sb: &str, kf: KeyFormat| Record {
            tb: "logs".into(),
            tp: "log/".into(),
            kf,
            sb: sb.into(),
            so: "o".into(),
            st: "t".into(),
            at: 0,
            line: String::new(),
        };
        assert_eq!(
            Dest::of(&rec("a", KeyFormat::Simple)),
            Dest::of(&rec("b", KeyFormat::Simple))
        );
        let p = KeyFormat::Partitioned { event_time: false };
        assert_ne!(Dest::of(&rec("a", p.clone())), Dest::of(&rec("b", p)));
    }
}
