//! Virtual-hosted-style addressing: with the gateway's S3 domain set
//! (`--s3-domain`), a request to `bucket.<domain>` addresses that bucket, as
//! S3 reads it — the path is the key, the signature covers the path and host
//! as sent, and policies see the bucket in the host. Path-style keeps
//! working beside it.
//!
//! What can't be resolved is refused rather than misread: a client that
//! puts the bucket in the host of a gateway without a domain used to have
//! `GET /?list-type=2` answered with the caller's buckets (an empty or wrong
//! listing, no error) and `PUT /` taken for nothing in particular.

use objectio_e2e::Cluster;
use serde_json::json;

const DOMAIN: &str = "s3.test";

const BLOCK_NONE: &[u8] = b"<PublicAccessBlockConfiguration>\
    <BlockPublicAcls>false</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls>\
    <BlockPublicPolicy>false</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets>\
    </PublicAccessBlockConfiguration>";

/// A client of `c` that sends `Host: <bucket>.s3.test:<port>`.
fn at_bucket(c: &Cluster, bucket: &str) -> Cluster {
    c.at_host(&format!("{bucket}.{DOMAIN}:{}", c.endpoint_port()))
}

#[test]
fn with_a_domain_the_bucket_in_the_host_is_the_one_addressed() {
    let c = Cluster::start_with_args(1, &["--s3-domain", DOMAIN]);
    let photos = at_bucket(&c, "photos");

    // CreateBucket and HeadBucket on the bucket's own host.
    photos.request("PUT", "/", &[]).expect(200);
    photos.request("HEAD", "/", &[]).expect(200);
    at_bucket(&c, "nosuch")
        .request("HEAD", "/", &[])
        .expect(404);
    c.request("HEAD", "/photos", &[]).expect(200);

    // Objects: the path is the key. Nothing reads its first segment as a
    // bucket.
    photos.request("PUT", "/a/b.txt", b"hello").expect(200);
    let r = photos.request("GET", "/a/b.txt", &[]);
    r.expect(200);
    assert_eq!(r.text(), "hello");
    photos.request("HEAD", "/a/b.txt", &[]).expect(200);
    let r = c.request("GET", "/photos/a/b.txt", &[]);
    r.expect(200);
    assert_eq!(r.text(), "hello");
    c.request("HEAD", "/a", &[]).expect(404);

    // Listings: bucket operations on `/`.
    for list in ["/?list-type=2", "/?encoding-type=url", "/"] {
        let r = photos.request("GET", list, &[]);
        r.expect(200);
        assert!(
            r.text().contains("<Name>photos</Name>") && r.text().contains("<Key>a/b.txt</Key>"),
            "{list}: {}",
            r.text()
        );
    }

    // GetBucketLocation on the bucket's host is the region (us-east-1: the
    // empty constraint), not a listing; a sub-resource the gateway lacks is
    // 501 there too.
    let r = photos.request("GET", "/?location", &[]);
    r.expect(200);
    assert!(
        r.text()
            .ends_with("<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>"),
        "{}",
        r.text()
    );
    let r = photos.request("GET", "/?website", &[]);
    assert_eq!(r.status, 501, "{}", r.text());

    // A presigned URL signed for the bucket's host works there, and only
    // there: on the domain itself the same path is another object.
    let url = photos.presign("GET", "/a/b.txt", 300);
    let r = photos.fetch("GET", &url, &[]);
    r.expect(200);
    assert_eq!(r.text(), "hello");
    let apex = c.at_host(&format!("{DOMAIN}:{}", c.endpoint_port()));
    assert_eq!(apex.fetch("GET", &url, &[]).status, 403);

    // The domain itself is path-style: ListBuckets, objects, the admin API.
    let r = apex.request("GET", "/", &[]);
    r.expect(200);
    assert!(r.text().contains("<Name>photos</Name>"), "{}", r.text());
    assert_eq!(apex.request("GET", "/photos/a/b.txt", &[]).text(), "hello");
    apex.request("GET", "/_admin/nodes", &[]).expect(200);

    // DeleteObjects.
    photos.request("PUT", "/c", b"x").expect(200);
    let batch =
        b"<Delete><Object><Key>a/b.txt</Key></Object><Object><Key>c</Key></Object></Delete>";
    let r = photos.request("POST", "/?delete", batch);
    r.expect(200);
    assert_eq!(r.text().matches("<Deleted>").count(), 2, "{}", r.text());
    c.request("GET", "/photos/c", &[]).expect(404);
    c.request("GET", "/photos/a/b.txt", &[]).expect(404);

    // A bucket name with dots is a name, not more of the host.
    let dotted = at_bucket(&c, "my.photos");
    dotted.request("PUT", "/", &[]).expect(200);
    dotted.request("PUT", "/k", b"dots").expect(200);
    assert_eq!(c.request("GET", "/my.photos/k", &[]).text(), "dots");
    dotted.request("DELETE", "/k", &[]).expect(204);
    dotted.request("DELETE", "/", &[]).expect(204);
    c.request("HEAD", "/my.photos", &[]).expect(404);

    // A host under the domain that names no valid bucket is refused.
    let r = at_bucket(&c, "Bad_Name").request("GET", "/", &[]);
    assert_eq!(r.status, 400, "{}", r.text());
    assert!(
        r.text().contains("<Code>InvalidBucketName</Code>"),
        "{}",
        r.text()
    );

    // A host under no domain is path-style, and a bucket operation on `/`
    // from it names no bucket: refused, the domain named.
    let elsewhere = c.at_host(&format!("photos.other.test:{}", c.endpoint_port()));
    let r = elsewhere.request("GET", "/?list-type=2", &[]);
    assert_eq!(r.status, 400, "{}", r.text());
    assert!(
        r.text().contains("<Code>InvalidRequest</Code>") && r.text().contains(DOMAIN),
        "{}",
        r.text()
    );
}

#[test]
fn a_bucket_policy_sees_the_bucket_in_the_host() {
    let c = Cluster::start_with_args(1, &["--s3-domain", DOMAIN]);
    let site = at_bucket(&c, "site");
    site.request("PUT", "/", &[]).expect(200);
    site.request("PUT", "/pub/index.html", b"public")
        .expect(200);
    site.request("PUT", "/private/notes", b"secret").expect(200);
    site.request("PUT", "/?publicAccessBlock", BLOCK_NONE)
        .expect(200);
    let policy = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::site/pub/*",
    }]});
    site.request("PUT", "/?policy", policy.to_string().as_bytes())
        .expect_ok();

    // Unsigned, on the bucket's host: the grant covers site/pub/* only.
    let anonymous = |path: &str| site.fetch("GET", &format!("{}{path}", c.endpoint), &[]);
    let r = anonymous("/pub/index.html");
    r.expect(200);
    assert_eq!(r.text(), "public");
    assert_eq!(anonymous("/private/notes").status, 403);
}

#[test]
fn without_a_domain_a_bucket_operation_from_a_bucket_host_is_refused() {
    let c = Cluster::start();
    let photos = at_bucket(&c, "photos");
    let batch: &[u8] = b"<Delete><Object><Key>k</Key></Object></Delete>";
    for (method, path, body) in [
        ("PUT", "/", &[][..]),
        ("GET", "/?list-type=2", &[]),
        ("GET", "/?encoding-type=url", &[]),
        ("GET", "/?location", &[]),
        ("HEAD", "/", &[]),
        ("DELETE", "/", &[]),
        ("POST", "/?delete", batch),
    ] {
        let r = photos.request(method, path, body);
        assert_eq!(r.status, 400, "{method} {path}: {}", r.text());
        if method != "HEAD" {
            assert!(
                r.text().contains("<Code>InvalidRequest</Code>")
                    && r.text().contains("--s3-domain"),
                "{method} {path}: {}",
                r.text()
            );
        }
    }

    // Path-style is as it was: ListBuckets with its parameters, the IAM
    // query API on `/`, buckets and objects.
    c.request("GET", "/?max-buckets=10", &[]).expect(200);
    c.query_api(
        "sts",
        &[("Action", "GetCallerIdentity"), ("Version", "2011-06-15")],
        (&c.access_key, &c.secret_key, None),
    )
    .expect(200);
    c.request("PUT", "/photos", &[]).expect(200);
    c.request("PUT", "/photos/k", b"v").expect(200);
    assert_eq!(c.request("GET", "/photos/k", &[]).text(), "v");
}
