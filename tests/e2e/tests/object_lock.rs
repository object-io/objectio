//! Object Lock retention, end to end.
//!
//! Retention is a compliance control: under COMPLIANCE mode a lock cannot be
//! lifted by anyone, including the account root. That makes both directions of
//! failure expensive — a lock that silently does not exist is a control the
//! operator believes they have, and a lock that cannot expire is data nobody
//! can ever delete.
//!
//! Every test here is pinned to a way the date conversion used to get this
//! wrong.

use objectio_e2e::Cluster;
use serde_json::json;

fn setup(bucket: &str) -> Cluster {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({ "name": bucket }))
        .expect_ok();
    c.request("PUT", &format!("/{bucket}/locked.txt"), b"data")
        .expect(200);
    c
}

fn retention_body(mode: &str, date: &str) -> String {
    format!("<Retention><Mode>{mode}</Mode><RetainUntilDate>{date}</RetainUntilDate></Retention>")
}

fn put_retention(c: &Cluster, bucket: &str, mode: &str, date: &str) -> objectio_e2e::Response {
    c.request(
        "PUT",
        &format!("/{bucket}/locked.txt?retention"),
        retention_body(mode, date).as_bytes(),
    )
}

/// The happy path, so the refusals below cannot pass by refusing everything.
#[test]
fn a_future_retention_date_is_stored_and_read_back() {
    let c = setup("lock-ok");
    put_retention(&c, "lock-ok", "GOVERNANCE", "2099-01-01T00:00:00Z").expect_ok();

    let got = c.request("GET", "/lock-ok/locked.txt?retention", &[]);
    got.expect(200);
    let body = got.text();
    assert!(
        body.contains("GOVERNANCE"),
        "mode did not come back: {body}"
    );
    assert!(
        body.contains("2099"),
        "the retain-until date did not come back: {body}"
    );
}

/// A date the server cannot parse must be refused, not quietly dropped.
///
/// It used to fall through `unwrap_or(0)` — "retain until the epoch", which is
/// no retention at all — and answer 200. A client setting a compliance lock
/// got a success and no lock, which is the worst possible direction to fail
/// for a control whose entire purpose is to be relied upon.
#[test]
fn an_unparseable_retention_date_is_refused() {
    let c = setup("lock-bad-date");
    for date in ["not-a-date", "2099-13-45T99:99:99Z", "", "1735689600"] {
        let r = put_retention(&c, "lock-bad-date", "COMPLIANCE", date);
        assert_eq!(
            r.status,
            400,
            "retention date {date:?} was accepted: {}",
            r.text()
        );
    }

    // And nothing was stored by any of them.
    let got = c.request("GET", "/lock-bad-date/locked.txt?retention", &[]);
    assert_ne!(
        got.status,
        200,
        "a refused retention request still left a lock behind: {}",
        got.text()
    );
}

/// A date before 1970 must be refused.
///
/// This is the unrecoverable one. `dt.timestamp()` is negative for a pre-epoch
/// date and `as u64` wrapped it to about 1.8e19 — later than any `now` will
/// ever be. Enforcement compares `retain_until_date > now`, so under
/// COMPLIANCE, which cannot be lifted by anyone, a typo in the year locked the
/// object forever.
#[test]
fn a_retention_date_before_the_epoch_cannot_lock_an_object_forever() {
    let c = setup("lock-prehistoric");
    for date in ["1969-01-01T00:00:00Z", "1900-01-01T00:00:00Z"] {
        let r = put_retention(&c, "lock-prehistoric", "COMPLIANCE", date);
        assert_eq!(
            r.status,
            400,
            "a pre-epoch retention date was accepted: {}",
            r.text()
        );
    }

    // The object must still be deletable — that is the whole point.
    c.request("DELETE", "/lock-prehistoric/locked.txt", &[])
        .expect(204);
}

/// A date already in the past is refused rather than stored pre-expired.
#[test]
fn a_retention_date_in_the_past_is_refused() {
    let c = setup("lock-past");
    let r = put_retention(&c, "lock-past", "GOVERNANCE", "2020-01-01T00:00:00Z");
    assert_eq!(
        r.status,
        400,
        "a retention date in the past was accepted: {}",
        r.text()
    );
}

/// A mode other than the two AWS defines is refused.
#[test]
fn an_unknown_retention_mode_is_refused() {
    let c = setup("lock-mode");
    let r = put_retention(&c, "lock-mode", "SOMETIMES", "2099-01-01T00:00:00Z");
    assert_eq!(r.status, 400, "mode 'SOMETIMES' was accepted: {}", r.text());
}

/// A live compliance lock actually stops a delete.
///
/// The counterpart to every refusal above: if retention did not enforce, all
/// of them would pass for the wrong reason.
#[test]
fn a_compliance_lock_refuses_a_delete() {
    let c = setup("lock-enforced");
    put_retention(&c, "lock-enforced", "COMPLIANCE", "2099-01-01T00:00:00Z").expect_ok();

    let refused = c.request("DELETE", "/lock-enforced/locked.txt", &[]);
    assert_eq!(
        refused.status,
        403,
        "a compliance-locked object was deleted: {}",
        refused.text()
    );
}
