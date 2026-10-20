//! Buckets hold what is in them: one with objects (or versions) can't be
//! deleted, nothing is written into one that doesn't exist, and a listing
//! paged any way returns each key once.

use objectio_e2e::Cluster;
use serde_json::json;

#[test]
fn a_bucket_with_objects_cannot_be_deleted() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "full"}))
        .expect_ok();
    c.request("PUT", "/full/k", b"data").expect(200);

    let r = c.request("DELETE", "/full", &[]);
    assert_eq!(
        r.status,
        409,
        "deleted a bucket with an object: {}",
        r.text()
    );
    assert!(r.text().contains("BucketNotEmpty"), "{}", r.text());
    assert_eq!(c.request("GET", "/full/k", &[]).bytes, b"data");

    c.request("DELETE", "/full/k", &[]).expect(204);
    assert_eq!(c.request("DELETE", "/full", &[]).status, 204);
}

/// A versioned bucket whose only contents are an old version behind a
/// delete marker is not empty either.
#[test]
fn a_bucket_with_only_versions_left_cannot_be_deleted() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "v"}))
        .expect_ok();
    c.request(
        "PUT",
        "/v?versioning",
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
    c.request("PUT", "/v/k", b"data").expect(200);
    c.request("DELETE", "/v/k", &[]).expect(204);

    let r = c.request("DELETE", "/v", &[]);
    assert_eq!(
        r.status,
        409,
        "deleted a bucket holding versions: {}",
        r.text()
    );
}

#[test]
fn nothing_is_written_into_a_bucket_that_does_not_exist() {
    let c = Cluster::start_with_ec(6, 4, 2);
    let r = c.request("PUT", "/nowhere/k", b"data");
    assert_eq!(r.status, 404, "{}", r.text());
    assert!(r.text().contains("NoSuchBucket"), "{}", r.text());
    assert_eq!(c.request("GET", "/nowhere/k", &[]).status, 404);
}

/// `/{bucket}/` is the bucket, for every verb: minio-go (warp, mc) creates
/// buckets with `PUT /b/`, s3fs probes with `HEAD /b/`.
#[test]
fn a_trailing_slash_names_the_bucket() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.request("PUT", "/slash/", &[]).expect(200);
    assert_eq!(c.request("HEAD", "/slash/", &[]).status, 200);
    c.request("PUT", "/slash/k", b"data").expect(200);
    let list = c.request("GET", "/slash/", &[]);
    assert_eq!(list.status, 200, "{}", list.text());
    assert!(list.text().contains("<Key>k</Key>"), "{}", list.text());

    let batch = b"<Delete><Object><Key>k</Key></Object></Delete>";
    let r = c.request("POST", "/slash/?delete", batch);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(c.request("GET", "/slash/k", &[]).status, 404);

    assert_eq!(c.request("DELETE", "/slash/", &[]).status, 204);
    assert_eq!(c.request("HEAD", "/slash", &[]).status, 404);
}

/// Every `<{tag}>…</{tag}>` in `xml`, in order.
fn all(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    xml.split(&open)
        .skip(1)
        .filter_map(|s| s.split(&close).next())
        .map(ToString::to_string)
        .collect()
}

fn one(xml: &str, tag: &str) -> Option<String> {
    all(xml, tag).into_iter().next()
}

/// A page's keys and common prefixes, sorted together.
fn items(xml: &str) -> Vec<String> {
    let mut out = all(xml, "Key");
    out.extend(
        all(xml, "CommonPrefixes")
            .iter()
            .filter_map(|p| one(p, "Prefix")),
    );
    out.sort();
    out
}

/// Every page of a V2 listing (`params` besides the paging), and V1's,
/// paged on `NextMarker`. Values go in the query as they are: the client
/// encodes them when it signs.
fn paged(c: &Cluster, bucket: &str, params: &str, max: usize) -> (Vec<String>, Vec<String>) {
    let mut v2 = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let cont = token
            .as_deref()
            .map(|t| format!("&continuation-token={t}"))
            .unwrap_or_default();
        let r = c.request(
            "GET",
            &format!("/{bucket}?list-type=2&max-keys={max}{params}{cont}"),
            &[],
        );
        assert_eq!(r.status, 200, "{}", r.text());
        let xml = r.text();
        let page = items(&xml);
        assert!(page.len() <= max, "{params} max {max}: {xml}");
        v2.extend(page);
        assert!(v2.len() < 1000, "V2 {params} max {max} never ends: {xml}");
        if one(&xml, "IsTruncated").as_deref() != Some("true") {
            break;
        }
        token = Some(one(&xml, "NextContinuationToken").expect("a token"));
    }
    let mut v1 = Vec::new();
    let mut marker = String::new();
    loop {
        let r = c.request(
            "GET",
            &format!("/{bucket}?max-keys={max}{params}&marker={marker}"),
            &[],
        );
        assert_eq!(r.status, 200, "{}", r.text());
        let xml = r.text();
        let page = items(&xml);
        v1.extend(page.iter().cloned());
        assert!(v1.len() < 1000, "V1 {params} max {max} never ends: {xml}");
        if one(&xml, "IsTruncated").as_deref() != Some("true") {
            break;
        }
        marker = one(&xml, "NextMarker")
            .or_else(|| page.last().cloned())
            .expect("a marker");
    }
    (v2, v1)
}

/// A listing resumes after its marker: keys that are prefixes of each
/// other, common prefixes over many keys, a marker inside a common prefix
/// and a request prefix, at every page size, through V1 and V2.
#[test]
fn listings_page_through_every_key_once() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "ls"}))
        .expect_ok();
    let mut keys: Vec<String> = (0..6)
        .flat_map(|d| (0..6).map(move |k| format!("dir{d}/{k}")))
        .collect();
    keys.extend(
        ["a", "a/1", "a/b/2", "ab", "dir0", "dir3/3/x", "z"]
            .iter()
            .map(ToString::to_string),
    );
    for k in &keys {
        c.request("PUT", &format!("/ls/{k}"), k.as_bytes())
            .expect(200);
    }
    keys.sort();

    let rolled = [
        "a", "a/", "ab", "dir0", "dir0/", "dir1/", "dir2/", "dir3/", "dir4/", "dir5/", "z",
    ];
    for max in [1, 2, 3, 5, 1000] {
        let (v2, v1) = paged(&c, "ls", "", max);
        assert_eq!(v2, keys, "V2, max-keys {max}");
        assert_eq!(v1, keys, "V1, max-keys {max}");
        let (v2, v1) = paged(&c, "ls", "&delimiter=/", max);
        assert_eq!(v2, rolled, "V2 with a delimiter, max-keys {max}");
        assert_eq!(v1, rolled, "V1 with a delimiter, max-keys {max}");
        let (v2, v1) = paged(&c, "ls", "&prefix=dir3/&delimiter=/", max);
        let under = [
            "dir3/0", "dir3/1", "dir3/2", "dir3/3", "dir3/3/", "dir3/4", "dir3/5",
        ];
        assert_eq!(v2, under, "V2 under a prefix, max-keys {max}");
        assert_eq!(v1, under, "V1 under a prefix, max-keys {max}");
    }

    // Starting inside a common prefix, and from a marker that is no key.
    let start = |after: &str, params: &str| {
        let r = c.request(
            "GET",
            &format!("/ls?list-type=2&start-after={after}{params}"),
            &[],
        );
        assert_eq!(r.status, 200, "{}", r.text());
        items(&r.text())
    };
    assert_eq!(
        start("dir2/3", "&delimiter=/"),
        ["dir2/", "dir3/", "dir4/", "dir5/", "z"]
    );
    assert_eq!(
        start("dir2/", "&delimiter=/"),
        ["dir3/", "dir4/", "dir5/", "z"]
    );
    assert_eq!(start("dir5/5", ""), ["z"]);
    assert_eq!(start("a", "&prefix=a"), ["a/1", "a/b/2", "ab"]);
    assert_eq!(start("dir", "&prefix=dir0"), {
        let mut v = vec!["dir0".to_string()];
        v.extend((0..6).map(|k| format!("dir0/{k}")));
        v
    });
}
