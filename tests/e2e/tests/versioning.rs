//! Versioned buckets: every version stays readable by its id, a delete
//! leaves a marker, deleting a version by id brings the previous one back,
//! and `ListObjectVersions` lists what is there, newest first.

use objectio_e2e::{Cluster, Response};
use serde_json::json;

fn body(i: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|j| u8::try_from((i * 31 + j) % 251).unwrap())
        .collect()
}

fn versioned(c: &Cluster, bucket: &str) {
    c.json("POST", "/_admin/buckets", json!({ "name": bucket }))
        .expect_ok();
    c.request(
        "PUT",
        &format!("/{bucket}?versioning"),
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
}

fn put(c: &Cluster, path: &str, data: &[u8]) -> String {
    let r = c.request("PUT", path, data);
    r.expect(200);
    r.header("x-amz-version-id").expect("a version id")
}

/// `(key, version id, is latest, is a delete marker)`, in listing order.
fn listed(xml: &str) -> Vec<(String, String, bool, bool)> {
    let field = |entry: &str, name: &str| {
        entry
            .split(&format!("<{name}>"))
            .nth(1)
            .and_then(|s| s.split(&format!("</{name}>")).next())
            .unwrap_or_default()
            .to_string()
    };
    let mut out = Vec::new();
    let mut rest = xml;
    loop {
        let v = rest.find("<Version>");
        let m = rest.find("<DeleteMarker>");
        let (start, marker) = match (v, m) {
            (Some(v), Some(m)) if m < v => (m, true),
            (Some(v), _) => (v, false),
            (None, Some(m)) => (m, true),
            (None, None) => break,
        };
        let close = if marker {
            "</DeleteMarker>"
        } else {
            "</Version>"
        };
        let end = rest[start..].find(close).unwrap() + start;
        let entry = &rest[start..end];
        out.push((
            field(entry, "Key"),
            field(entry, "VersionId"),
            field(entry, "IsLatest") == "true",
            marker,
        ));
        rest = &rest[end..];
    }
    out
}

fn tag(xml: &str, name: &str) -> Option<String> {
    xml.split(&format!("<{name}>"))
        .nth(1)
        .and_then(|s| s.split(&format!("</{name}>")).next())
        .map(ToString::to_string)
}

fn expect_bytes(r: &Response, want: &[u8], what: &str) {
    assert_eq!(r.status, 200, "{what}: {}", r.text());
    assert!(
        r.bytes == want,
        "{what}: wrong bytes ({} long)",
        r.bytes.len()
    );
}

#[test]
fn every_version_reads_back_by_its_id() {
    let c = Cluster::start_with_ec(6, 4, 2);
    versioned(&c, "v");
    let (a, b) = (body(1, 20_000), body(2, 300));
    let va = put(&c, "/v/k", &a);
    let vb = put(&c, "/v/k", &b);
    assert_ne!(va, vb);

    let cur = c.request("GET", "/v/k", &[]);
    expect_bytes(&cur, &b, "the current version");
    assert_eq!(cur.header("x-amz-version-id"), Some(vb.clone()));
    expect_bytes(
        &c.request("GET", &format!("/v/k?versionId={va}"), &[]),
        &a,
        "the first version",
    );
    let head = c.request("HEAD", &format!("/v/k?versionId={va}"), &[]);
    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-length"), Some(a.len().to_string()));
    assert_eq!(head.header("x-amz-version-id"), Some(va.clone()));
    let ranged = c.request_with_headers(
        "GET",
        &format!("/v/k?versionId={va}"),
        &[],
        &[("range", "bytes=10-19")],
    );
    assert_eq!(ranged.status, 206);
    assert_eq!(ranged.bytes, a[10..20]);
    assert_eq!(
        c.request("GET", "/v/k?versionId=nope", &[]).status,
        404,
        "an unknown version"
    );

    let list = listed(&c.request("GET", "/v?versions", &[]).text());
    assert_eq!(
        list,
        vec![
            ("k".into(), vb, true, false),
            ("k".into(), va, false, false)
        ],
        "both versions, newest first, once each"
    );
}

#[test]
fn a_delete_leaves_a_marker_and_deleting_the_marker_brings_the_object_back() {
    let c = Cluster::start_with_ec(6, 4, 2);
    versioned(&c, "v");
    let a = body(3, 9_000);
    let va = put(&c, "/v/k", &a);

    let del = c.request("DELETE", "/v/k", &[]);
    assert_eq!(del.status, 204);
    assert_eq!(del.header("x-amz-delete-marker").as_deref(), Some("true"));
    let marker = del
        .header("x-amz-version-id")
        .expect("the marker's version");

    let gone = c.request("GET", "/v/k", &[]);
    assert_eq!(gone.status, 404, "behind a delete marker");
    assert_eq!(gone.header("x-amz-delete-marker").as_deref(), Some("true"));
    assert_eq!(c.request("HEAD", "/v/k", &[]).status, 404);
    assert!(!c.request("GET", "/v", &[]).text().contains("<Key>k</Key>"));
    expect_bytes(
        &c.request("GET", &format!("/v/k?versionId={va}"), &[]),
        &a,
        "the version behind the marker",
    );
    assert_eq!(
        c.request("GET", &format!("/v/k?versionId={marker}"), &[])
            .status,
        405,
        "a delete marker by version"
    );
    let list = listed(&c.request("GET", "/v?versions", &[]).text());
    assert_eq!(
        list,
        vec![
            ("k".into(), marker.clone(), true, true),
            ("k".into(), va, false, false)
        ]
    );

    let undelete = c.request("DELETE", &format!("/v/k?versionId={marker}"), &[]);
    assert_eq!(undelete.status, 204);
    assert_eq!(
        undelete.header("x-amz-delete-marker").as_deref(),
        Some("true")
    );
    expect_bytes(&c.request("GET", "/v/k", &[]), &a, "after the marker went");
    assert!(
        c.request("GET", "/v", &[]).text().contains("<Key>k</Key>"),
        "listed again"
    );
}

#[test]
fn deleting_the_current_version_makes_the_previous_one_current() {
    let c = Cluster::start_with_ec(6, 4, 2);
    versioned(&c, "v");
    // One erasure-coded, one small enough to be stored inline: promotion
    // must carry an inline object's bytes.
    let (a, b) = (body(4, 900), body(5, 70_000));
    let empty = c.total_used_bytes();
    let va = put(&c, "/v/k", &a);
    let vb = put(&c, "/v/k", &b);

    let del = c.request("DELETE", &format!("/v/k?versionId={vb}"), &[]);
    assert_eq!(del.status, 204);
    assert_eq!(del.header("x-amz-version-id"), Some(vb.clone()));
    let cur = c.request("GET", "/v/k", &[]);
    expect_bytes(&cur, &a, "the previous version, now current");
    assert_eq!(cur.header("x-amz-version-id"), Some(va.clone()));
    assert_eq!(
        c.request("GET", &format!("/v/k?versionId={vb}"), &[])
            .status,
        404
    );
    let listing = c.request("GET", "/v", &[]).text();
    assert_eq!(
        tag(&listing, "Size"),
        Some(a.len().to_string()),
        "listed at its size"
    );

    c.request("DELETE", &format!("/v/k?versionId={va}"), &[])
        .expect(204);
    assert_eq!(c.request("GET", "/v/k", &[]).status, 404);
    assert!(!c.request("GET", "/v", &[]).text().contains("<Key>k</Key>"));
    assert!(listed(&c.request("GET", "/v?versions", &[]).text()).is_empty());
    assert_eq!(
        c.await_total_used_bytes(empty),
        empty,
        "both versions' blocks are freed"
    );
}

#[test]
fn an_object_from_before_versioning_is_kept_as_the_null_version() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "v"}))
        .expect_ok();
    let n = body(6, 40_000);
    c.request("PUT", "/v/k", &n).expect(200);
    c.request(
        "PUT",
        "/v?versioning",
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
    let a = body(7, 1_000);
    let va = put(&c, "/v/k", &a);

    expect_bytes(&c.request("GET", "/v/k", &[]), &a, "the new version");
    expect_bytes(
        &c.request("GET", "/v/k?versionId=null", &[]),
        &n,
        "the object from before versioning",
    );
    let list = listed(&c.request("GET", "/v?versions", &[]).text());
    assert_eq!(
        list,
        vec![
            ("k".into(), va, true, false),
            ("k".into(), "null".into(), false, false)
        ]
    );
}

#[test]
fn version_listing_pages_and_rolls_up_prefixes() {
    let c = Cluster::start_with_ec(6, 4, 2);
    versioned(&c, "v");
    let mut want = Vec::new();
    for k in ["a", "b", "d/1", "d/2", "e"] {
        let mut ids: Vec<String> = (0..3)
            .map(|i| put(&c, &format!("/v/{k}"), &body(i, 100)))
            .collect();
        ids.reverse();
        for (i, id) in ids.into_iter().enumerate() {
            want.push((k.to_string(), id, i == 0, false));
        }
    }

    let mut got = Vec::new();
    let mut marker = String::new();
    loop {
        let xml = c
            .request("GET", &format!("/v?versions&max-keys=4{marker}"), &[])
            .text();
        let page = listed(&xml);
        assert!(page.len() <= 4, "a page of {}", page.len());
        got.extend(page);
        if tag(&xml, "IsTruncated").as_deref() != Some("true") {
            break;
        }
        marker = format!(
            "&key-marker={}&version-id-marker={}",
            tag(&xml, "NextKeyMarker").expect("NextKeyMarker"),
            tag(&xml, "NextVersionIdMarker").expect("NextVersionIdMarker")
        );
    }
    assert_eq!(got, want, "every version once, in order, across pages");

    let xml = c.request("GET", "/v?versions&delimiter=/", &[]).text();
    assert!(
        xml.contains("<CommonPrefixes><Prefix>d/</Prefix></CommonPrefixes>"),
        "{xml}"
    );
    assert!(!listed(&xml).iter().any(|(k, ..)| k.starts_with("d/")));
    let xml = c.request("GET", "/v?versions&prefix=d/", &[]).text();
    assert_eq!(listed(&xml).len(), 6);
}

/// Older versions live with the key's metadata after its current version
/// is deleted (no listing entry any more): the cluster growing must not
/// lose them.
#[test]
fn older_versions_stay_readable_after_a_delete_and_osds_joining() {
    const N: usize = 30;
    let mut c = Cluster::start_with_ec(6, 4, 2);
    versioned(&c, "v");
    let versions: Vec<String> = (0..N)
        .map(|i| {
            let v = put(&c, &format!("/v/o{i}"), &body(i, 20_000));
            c.request("DELETE", &format!("/v/o{i}"), &[]).expect(204);
            v
        })
        .collect();
    c.restart_with_osds(18);
    let missing: Vec<String> = versions
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            let r = c.request("GET", &format!("/v/o{i}?versionId={v}"), &[]);
            (r.status != 200 || r.bytes != body(i, 20_000))
                .then(|| format!("o{i}: {} {} bytes", r.status, r.bytes.len()))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "after 12 OSDs joined, {} of {N} older versions are unreadable: {missing:?}",
        missing.len()
    );
}

#[test]
fn a_multipart_upload_is_a_new_version() {
    let c = Cluster::start_with_ec(6, 4, 2);
    versioned(&c, "v");
    let a = body(8, 3_000);
    let va = put(&c, "/v/k", &a);
    let r = c.request("POST", "/v/k?uploads", &[]);
    r.expect(200);
    let upload = tag(&r.text(), "UploadId").unwrap();
    let part = body(9, 6 * 1024 * 1024);
    let etag = c
        .request(
            "PUT",
            &format!("/v/k?partNumber=1&uploadId={upload}"),
            &part,
        )
        .header("etag")
        .unwrap();
    let done = c.request(
        "POST",
        &format!("/v/k?uploadId={upload}"),
        format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
        )
        .as_bytes(),
    );
    done.expect(200);
    let vm = done.header("x-amz-version-id").expect("a version id");
    assert_ne!(vm, va);
    expect_bytes(
        &c.request("GET", "/v/k", &[]),
        &part,
        "the uploaded version",
    );
    expect_bytes(
        &c.request("GET", &format!("/v/k?versionId={va}"), &[]),
        &a,
        "the version it replaced",
    );
}

#[test]
fn version_sub_resources_and_copies_use_the_version_named() {
    let c = Cluster::start_with_ec(6, 4, 2);
    versioned(&c, "v");
    let a = body(10, 2_000);
    let va = put(&c, "/v/k", &a);
    let vb = put(&c, "/v/k", &body(11, 2_000));

    // The current version by id is the current version.
    let tagging = b"<Tagging><TagSet><Tag><Key>t</Key><Value>1</Value></Tag></TagSet></Tagging>";
    c.request("PUT", &format!("/v/k?tagging&versionId={vb}"), tagging)
        .expect(200);
    // An older one is refused, not answered for the current one.
    assert_eq!(
        c.request("GET", &format!("/v/k?tagging&versionId={va}"), &[])
            .status,
        501
    );
    assert_eq!(
        c.request("GET", "/v/k?tagging&versionId=nope", &[]).status,
        404
    );

    // A copy reads the version named, the current one or an older one.
    for (version, want) in [(&vb, body(11, 2_000)), (&va, a)] {
        c.request_with_headers(
            "PUT",
            "/v/copy",
            &[],
            &[("x-amz-copy-source", &format!("/v/k?versionId={version}"))],
        )
        .expect(200);
        expect_bytes(&c.request("GET", "/v/copy", &[]), &want, "the copy");
    }
}

/// A lock protects the version it is on: deleting that version by id is
/// refused even once a newer version is current, and a plain delete (which
/// only adds a marker) is allowed.
#[test]
fn a_locked_older_version_cannot_be_deleted_by_its_id() {
    let c = Cluster::start_with_ec(6, 4, 2);
    versioned(&c, "v");
    let a = body(12, 2_000);
    let va = put(&c, "/v/k", &a);
    c.request(
        "PUT",
        "/v/k?retention",
        b"<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>",
    )
    .expect(200);
    put(&c, "/v/k", &body(13, 2_000));

    assert_eq!(
        c.request("DELETE", &format!("/v/k?versionId={va}"), &[])
            .status,
        403,
        "the locked version was deleted"
    );
    assert_eq!(c.request("DELETE", "/v/k", &[]).status, 204, "a marker");
    expect_bytes(
        &c.request("GET", &format!("/v/k?versionId={va}"), &[]),
        &a,
        "the locked version",
    );
}

/// Deleting every version of a key at once, from many clients: none may be
/// left current. Promotion used to happen in the gateway across separate
/// calls, so one delete could make current a version another was deleting,
/// leaving the key "current" with no data behind it.
#[test]
fn concurrent_deletes_of_every_version_leave_nothing_current() {
    let c = Cluster::start_with_ec(6, 4, 2);
    versioned(&c, "v");
    for round in 0..5 {
        let ids: Vec<String> = (0..6)
            .map(|i| put(&c, "/v/k", &body(round * 10 + i, 3_000)))
            .collect();
        std::thread::scope(|s| {
            for id in &ids {
                let c = &c;
                s.spawn(move || {
                    let r = c.request("DELETE", &format!("/v/k?versionId={id}"), &[]);
                    assert_eq!(r.status, 204, "{}", r.text());
                });
            }
        });
        assert!(
            listed(&c.request("GET", "/v?versions", &[]).text()).is_empty(),
            "round {round}: versions left"
        );
        let head = c.request("HEAD", "/v/k", &[]);
        assert_eq!(
            head.status,
            404,
            "round {round}: a key with no versions is still current ({:?})",
            head.header("x-amz-version-id")
        );
        assert!(
            !c.request("GET", "/v", &[]).text().contains("<Key>k</Key>"),
            "round {round}: still listed"
        );
    }
    assert_eq!(
        c.request("DELETE", "/v", &[]).status,
        204,
        "the bucket is empty"
    );
}
