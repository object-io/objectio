//! Conditional requests: a write with If-None-Match / If-Match happens only
//! if the key is in the state it names, decided once for all replicas.

use objectio_e2e::Cluster;
use serde_json::json;

fn bucket(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/buckets", json!({ "name": name }))
        .expect_ok();
}

/// Many writers racing to create the same key with If-None-Match: * —
/// exactly one wins, and the key holds what that one wrote. The condition
/// used to be ignored: every writer "won", the last one silently.
#[test]
fn racing_create_if_absent_writers_have_exactly_one_winner() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "c");
    for round in 0..5 {
        let key = format!("/c/k{round}");
        let statuses: Vec<(usize, u16)> = std::thread::scope(|s| {
            // Collected first so every writer is running before any is joined.
            #[allow(clippy::needless_collect)]
            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let (c, key) = (&c, &key);
                    s.spawn(move || {
                        let body = vec![u8::try_from(i).unwrap(); 50_000];
                        (
                            i,
                            c.request_with_headers("PUT", key, &body, &[("if-none-match", "*")])
                                .status,
                        )
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let winners: Vec<usize> = statuses
            .iter()
            .filter(|(_, st)| *st == 200)
            .map(|(i, _)| *i)
            .collect();
        assert_eq!(winners.len(), 1, "round {round}: {statuses:?}");
        assert!(
            statuses.iter().all(|(_, st)| *st == 200 || *st == 412),
            "round {round}: {statuses:?}"
        );
        let got = c.request("GET", &key, &[]);
        assert_eq!(
            got.bytes,
            vec![u8::try_from(winners[0]).unwrap(); 50_000],
            "round {round}: the key doesn't hold the winner's write"
        );
    }
}

#[test]
fn if_match_writes_only_over_the_object_named() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "c");
    assert_eq!(
        c.request_with_headers("PUT", "/c/k", b"x", &[("if-match", "*")])
            .status,
        404,
        "If-Match on a key with no object"
    );
    let etag = c.request("PUT", "/c/k", b"one").header("etag").unwrap();
    assert_eq!(
        c.request_with_headers("PUT", "/c/k", b"two", &[("if-match", "\"nope\"")])
            .status,
        412
    );
    assert_eq!(
        c.request("GET", "/c/k", &[]).bytes,
        b"one",
        "a refused write changed the key"
    );
    c.request_with_headers("PUT", "/c/k", b"two", &[("if-match", &etag)])
        .expect(200);
    assert_eq!(c.request("GET", "/c/k", &[]).bytes, b"two");
    // The refused writes left the key listed (a failed overwrite used to
    // unlist the object it left in place).
    assert!(c.request("GET", "/c", &[]).text().contains("<Key>k</Key>"));
}

#[test]
fn conditional_reads_answer_304_and_412() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "c");
    let etag = c.request("PUT", "/c/k", b"data").header("etag").unwrap();
    let get = |h: &[(&str, &str)]| c.request_with_headers("GET", "/c/k", &[], h).status;
    assert_eq!(get(&[("if-none-match", &etag)]), 304);
    assert_eq!(get(&[("if-match", "\"nope\"")]), 412);
    assert_eq!(get(&[("if-match", &etag)]), 200);
    assert_eq!(
        get(&[("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT")]),
        304
    );
    assert_eq!(
        get(&[("if-unmodified-since", "Sat, 29 Oct 1994 19:43:31 GMT")]),
        412
    );
}

/// Objects in a replicated pool (one OSD here) are listed: that write path
/// used to store the `ObjectMeta` and never list the object.
#[test]
fn replicated_objects_are_listed() {
    let c = Cluster::start();
    bucket(&c, "r");
    c.request("PUT", "/r/large", &vec![7u8; 200_000])
        .expect(200);
    c.request("PUT", "/r/small", b"x").expect(200);
    let listing = c.request("GET", "/r", &[]).text();
    assert!(listing.contains("<Key>large</Key>"), "{listing}");
    assert!(listing.contains("<Key>small</Key>"), "{listing}");
}

/// A conditional PUT whose commit meta applied but whose answer was lost
/// (a leader change, a timeout: here a test hook) still succeeds: the
/// gateway sends it again and meta knows its own entry. It used to fail
/// with 503 and free its shards while the listing named it: the object
/// was listed, unreadable, and every If-None-Match after it was refused.
#[test]
fn a_conditional_put_whose_answer_was_lost_is_committed_once() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    bucket(&c, "lost");
    c.json(
        "POST",
        "/_admin/test/lose-reply",
        json!({ "call": "create_object" }),
    )
    .expect_ok();
    let body = vec![7u8; 50_000];
    let first = c.request_with_headers("PUT", "/lost/k", &body, &[("if-none-match", "*")]);
    // What a client does with a 503: send it again.
    if first.status != 200 {
        let again = c.request_with_headers("PUT", "/lost/k", &body, &[("if-none-match", "*")]);
        assert_eq!(
            again.status,
            200,
            "first {}: {}; again: {}",
            first.status,
            first.text(),
            again.text()
        );
    }
    let got = c.request("GET", "/lost/k", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.bytes, body);
    // And it is the key's one object: a second create is refused.
    let second = c.request_with_headers("PUT", "/lost/k", b"other", &[("if-none-match", "*")]);
    assert_eq!(second.status, 412, "{}", second.text());
}
