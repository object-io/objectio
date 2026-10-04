//! Bucket logging (A12): requests on a logged bucket arrive in its target
//! bucket as S3 server-access-log lines, batched into objects; the target
//! must consent (its policy) and be in the source's tenant; turning logging
//! off stops delivery; a gateway killed with records not yet delivered
//! delivers them when it is back.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use objectio_e2e::{Cluster, Response};
use serde_json::json;

/// Roll time the clusters here run with: a log object every few seconds.
const ROLL: &str = "2";

fn cluster() -> Cluster {
    Cluster::start_with_ec_and_args(1, 1, 0, &["--bucket-log-roll-secs", ROLL])
}

fn target_policy(target: &str, prefix: &str, source: &str, account: &str) -> Vec<u8> {
    json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "S3ServerAccessLogsPolicy",
            "Effect": "Allow",
            "Principal": {"Service": "logging.s3.amazonaws.com"},
            "Action": ["s3:PutObject"],
            "Resource": format!("arn:aws:s3:::{target}/{prefix}*"),
            "Condition": {
                "ArnLike": {"aws:SourceArn": format!("arn:aws:s3:::{source}")},
                "StringEquals": {"aws:SourceAccount": account}
            }
        }]
    })
    .to_string()
    .into_bytes()
}

fn logging_xml(target: &str, prefix: &str, format: &str) -> Vec<u8> {
    format!(
        "<BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LoggingEnabled>\
         <TargetBucket>{target}</TargetBucket><TargetPrefix>{prefix}</TargetPrefix>{format}\
         </LoggingEnabled></BucketLoggingStatus>"
    )
    .into_bytes()
}

const OFF: &[u8] = b"<BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";

/// The owner recorded for buckets the system admin creates: its user id,
/// as `?acl` reports it.
fn owner_of(c: &Cluster, bucket: &str) -> String {
    let acl = c.request("GET", &format!("/{bucket}?acl"), &[]).text();
    acl.split("<ID>")
        .nth(1)
        .and_then(|s| s.split("</ID>").next())
        .expect("owner id")
        .to_string()
}

fn keys(c: &Cluster, bucket: &str, prefix: &str) -> Vec<String> {
    let list = c
        .request(
            "GET",
            &format!("/{bucket}?list-type=2&prefix={prefix}"),
            &[],
        )
        .text();
    list.split("<Key>")
        .skip(1)
        .filter_map(|s| s.split("</Key>").next())
        .map(str::to_string)
        .collect()
}

/// A log line split as ceph's s3-tests (and most parsers) split it:
/// brackets read as quotes, then shell-style words.
fn fields(line: &str) -> Vec<String> {
    let line = line.replace(['[', ']'], "\"");
    let mut out = Vec::new();
    let (mut cur, mut quoted, mut any) = (String::new(), false, false);
    for ch in line.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            ' ' if !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            ch => {
                cur.push(ch);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// Every log line under `prefix` in `bucket`, waiting up to `secs` until
/// `done` holds of them.
fn await_lines(
    c: &Cluster,
    bucket: &str,
    prefix: &str,
    secs: u64,
    done: impl Fn(&[Vec<String>]) -> bool,
) -> Vec<Vec<String>> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let lines: Vec<Vec<String>> = keys(c, bucket, prefix)
            .iter()
            .flat_map(|k| {
                c.request("GET", &format!("/{bucket}/{k}"), &[])
                    .text()
                    .lines()
                    .map(fields)
                    .collect::<Vec<_>>()
            })
            .collect();
        if done(&lines) || Instant::now() > deadline {
            return lines;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn find<'a>(lines: &'a [Vec<String>], op: &str, key: &str) -> Option<&'a Vec<String>> {
    lines.iter().find(|f| f[6] == op && f[7] == key)
}

fn enable(c: &Cluster, source: &str, target: &str, prefix: &str, format: &str) -> Response {
    c.request(
        "PUT",
        &format!("/{source}?logging"),
        &logging_xml(target, prefix, format),
    )
}

#[test]
fn requests_on_a_logged_bucket_arrive_as_access_log_lines() {
    let c = cluster();
    for b in ["src", "logs"] {
        c.request("PUT", &format!("/{b}"), &[]).expect(200);
    }
    let owner = owner_of(&c, "src");
    c.request(
        "PUT",
        "/logs?policy",
        &target_policy("logs", "log/", "src", &owner),
    )
    .expect(204);
    enable(&c, "src", "logs", "log/", "").expect(200);
    let conf = c.request("GET", "/src?logging", &[]);
    conf.expect(200);
    let xml = conf.text();
    assert!(xml.contains("<TargetBucket>logs</TargetBucket>"), "{xml}");
    assert!(xml.contains("<TargetPrefix>log/</TargetPrefix>"), "{xml}");
    assert!(xml.contains("<SimplePrefix>"), "{xml}");
    assert!(conf.header("last-modified").is_some());

    let put = c.request("PUT", "/src/dir/k 1", b"hello");
    put.expect(200);
    let put_id = put.header("x-amz-request-id").unwrap();
    c.request("GET", "/src/dir/k 1", &[]).expect(200);
    c.request("HEAD", "/src/dir/k 1", &[]).expect(200);
    c.request("GET", "/src/missing", &[]).expect(404);
    c.request("GET", "/src?list-type=2", &[]).expect(200);
    c.request("DELETE", "/src/dir/k 1", &[]).expect(204);

    let lines = await_lines(&c, "logs", "log/", 30, |l| {
        find(l, "REST.DELETE.OBJECT", "dir/k%201").is_some()
    });
    for f in &lines {
        assert_eq!(f.len(), 26, "{f:?}");
        assert_eq!(f[0], owner, "the bucket owner");
        assert_eq!(f[1], "src");
        assert_eq!(f[19], "SigV4");
        assert_eq!(f[21], "AuthHeader");
    }
    let put = find(&lines, "REST.PUT.OBJECT", "dir/k%201").expect("PUT logged");
    assert_eq!(put[5], put_id, "the request id the client got");
    assert_eq!(put[9], "200");
    assert_eq!(put[12], "5", "object size");
    assert!(put[8].starts_with("PUT /src/dir/k%201 HTTP/1.1"), "{put:?}");
    let get = find(&lines, "REST.GET.OBJECT", "dir/k%201").expect("GET logged");
    assert_eq!(get[9], "200");
    assert_eq!(get[11], "5", "bytes sent");
    assert_eq!(get[12], "5");
    assert!(find(&lines, "REST.HEAD.OBJECT", "dir/k%201").is_some());
    let missing = find(&lines, "REST.GET.OBJECT", "missing").expect("a 404 is logged");
    assert_eq!(missing[9], "404");
    assert_eq!(missing[10], "NoSuchKey");
    assert!(find(&lines, "REST.GET.BUCKET", "-").is_some());
    assert!(find(&lines, "REST.PUT.LOGGING_STATUS", "-").is_some());
    assert_eq!(
        find(&lines, "REST.DELETE.OBJECT", "dir/k%201").unwrap()[9],
        "204"
    );

    // Named <prefix>YYYY-mm-DD-HH-MM-SS-<16 hex>.
    for k in keys(&c, "logs", "log/") {
        let rest = k.strip_prefix("log/").unwrap();
        let (stamp, unique) = rest.split_at(19);
        let shape: String = stamp
            .chars()
            .map(|c| if c.is_ascii_digit() { 'd' } else { c })
            .collect();
        assert_eq!(shape, "dddd-dd-dd-dd-dd-dd", "{k}");
        assert_eq!(unique.len(), 17, "{k}");
        assert!(unique[1..].chars().all(|c| c.is_ascii_hexdigit()), "{k}");
    }

    // A batch delete: one record for the request, one per key deleted. A
    // copy: REST.COPY.OBJECT for the destination, REST.COPY.OBJECT_GET for
    // the source.
    for k in ["a", "b"] {
        c.request("PUT", &format!("/src/{k}"), b"x").expect(200);
    }
    c.request_with_headers(
        "PUT",
        "/src/a-copy",
        &[],
        &[("x-amz-copy-source", "/src/a")],
    )
    .expect(200);
    let body = b"<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object></Delete>";
    c.request("POST", "/src?delete", body).expect(200);
    let lines = await_lines(&c, "logs", "log/", 30, |l| {
        find(l, "BATCH.DELETE.OBJECT", "b").is_some()
    });
    assert!(find(&lines, "REST.POST.MULTI_OBJECT_DELETE", "-").is_some());
    assert!(find(&lines, "BATCH.DELETE.OBJECT", "a").is_some());
    assert!(find(&lines, "REST.COPY.OBJECT", "a-copy").is_some());
    assert!(find(&lines, "REST.COPY.OBJECT_GET", "a").is_some());
}

/// Partitioned: `<prefix><owner>/<region>/<bucket>/YYYY/MM/DD/...`.
#[test]
fn a_partitioned_prefix_names_owner_region_and_bucket() {
    let c = cluster();
    for b in ["src2", "logs"] {
        c.request("PUT", &format!("/{b}"), &[]).expect(200);
    }
    let owner = owner_of(&c, "src2");
    c.request(
        "PUT",
        "/logs?policy",
        &target_policy("logs", "", "*", &owner),
    )
    .expect(204);
    enable(
        &c,
        "src2",
        "logs",
        "p/",
        "<TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>EventTime\
         </PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat>",
    )
    .expect(200);
    c.request("PUT", "/src2/x", b"x").expect(200);
    let lines = await_lines(&c, "logs", "p/", 30, |l| {
        find(l, "REST.PUT.OBJECT", "x").is_some()
    });
    assert!(find(&lines, "REST.PUT.OBJECT", "x").is_some());
    let k = keys(&c, "logs", "p/").pop().unwrap();
    let parts: Vec<&str> = k.split('/').collect();
    assert_eq!(
        parts[..4],
        ["p", owner.as_str(), "us-east-1", "src2"],
        "{k}"
    );
    assert_eq!(parts.len(), 8, "{k}");
}

/// A provisioned tenant admin: `(user_id, access_key, secret_key)`.
fn tenant_admin(c: &Cluster, tenant: &str) -> (String, String, String) {
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": tenant, "display_name": tenant, "enabled": true}),
    )
    .expect_ok();
    user(c, tenant, true)
}

fn user(c: &Cluster, tenant: &str, admin: bool) -> (String, String, String) {
    let u = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": format!("{tenant}-{admin}"), "tenant": tenant}),
    );
    u.expect_ok();
    let id = u.json()["user_id"].as_str().unwrap().to_string();
    if admin {
        c.json(
            "POST",
            &format!("/_admin/tenants/{tenant}/admins"),
            json!({"user_id": id}),
        )
        .expect_ok();
    }
    let k = c.json(
        "POST",
        &format!("/_admin/users/{id}/access-keys"),
        json!({}),
    );
    k.expect_ok();
    let k = k.json();
    (
        id,
        k["access_key_id"].as_str().unwrap().to_string(),
        k["secret_access_key"].as_str().unwrap().to_string(),
    )
}

fn code(r: &Response) -> String {
    let t = r.text();
    t.split("<Code>")
        .nth(1)
        .and_then(|s| s.split("</Code>").next())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn logging_needs_the_targets_consent_its_tenant_and_the_owner() {
    let c = cluster();
    for b in ["src", "logs"] {
        c.request("PUT", &format!("/{b}"), &[]).expect(200);
    }
    let owner = owner_of(&c, "src");

    // No policy on the target: no consent.
    let r = enable(&c, "src", "logs", "log/", "");
    assert_eq!((r.status, code(&r).as_str()), (403, "AccessDenied"));
    // A policy for another prefix, another source or another account.
    for p in [
        target_policy("logs", "other/", "src", &owner),
        target_policy("logs", "log/", "kaboom", &owner),
        target_policy("logs", "log/", "src", "kaboom"),
    ] {
        c.request("PUT", "/logs?policy", &p).expect(204);
        let r = enable(&c, "src", "logs", "log/", "");
        assert_eq!((r.status, code(&r).as_str()), (403, "AccessDenied"));
    }
    // Everyone allowed (with the source pinned, so not public) is not the
    // service named.
    let mut everyone: serde_json::Value =
        serde_json::from_slice(&target_policy("logs", "log/", "src", &owner)).unwrap();
    everyone["Statement"][0]["Principal"] = json!({"AWS": "*"});
    c.request("PUT", "/logs?policy", everyone.to_string().as_bytes())
        .expect(204);
    let r = enable(&c, "src", "logs", "log/", "");
    assert_eq!((r.status, code(&r).as_str()), (403, "AccessDenied"));

    c.request(
        "PUT",
        "/logs?policy",
        &target_policy("logs", "log/", "src", &owner),
    )
    .expect(204);
    // No such target; the source itself; a bad key format.
    let r = enable(&c, "src", "nosuch", "log/", "");
    assert_eq!(
        (r.status, code(&r).as_str()),
        (400, "InvalidTargetBucketForLogging")
    );
    let r = enable(&c, "src", "src", "log/", "");
    assert_eq!((r.status, code(&r).as_str()), (400, "InvalidArgument"));
    let r = enable(
        &c,
        "src",
        "logs",
        "log/",
        "<TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>kaboom\
         </PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat>",
    );
    assert_eq!((r.status, code(&r).as_str()), (400, "MalformedXML"));
    enable(&c, "src", "logs", "log/", "").expect(200);

    // A target in another tenant, whatever its policy says.
    let (_, ak, sk) = tenant_admin(&c, "acme");
    c.request_as("PUT", "/acme-logs", &[], &ak, &sk).expect(200);
    c.request_as(
        "PUT",
        "/acme-logs?policy",
        &target_policy("acme-logs", "log/", "src", &owner),
        &ak,
        &sk,
    )
    .expect(204);
    let r = enable(&c, "src", "acme-logs", "log/", "");
    assert_eq!(
        (r.status, code(&r).as_str()),
        (400, "InvalidTargetBucketForLogging")
    );

    // Only the bucket's owner configures it, whatever its policy grants.
    let acme_owner = owner_of(&c, "acme-logs");
    let (_, ok, os) = user(&c, "acme", false);
    c.request_as("PUT", "/acme-src", &[], &ak, &sk).expect(200);
    let grant = json!({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": ["arn:objectio:iam::acme:user/acme-false"]},
        "Action": ["s3:PutBucketLogging", "s3:GetBucketLogging"],
        "Resource": "arn:aws:s3:::acme-src"}]});
    c.request_as(
        "PUT",
        "/acme-src?policy",
        grant.to_string().as_bytes(),
        &ak,
        &sk,
    )
    .expect(204);
    c.request_as(
        "PUT",
        "/acme-logs?policy",
        &target_policy("acme-logs", "log/", "acme-src", &acme_owner),
        &ak,
        &sk,
    )
    .expect(204);
    let xml = logging_xml("acme-logs", "log/", "");
    let r = c.request_as("PUT", "/acme-src?logging", &xml, &ok, &os);
    assert_eq!((r.status, code(&r).as_str()), (403, "AccessDenied"));
    assert!(r.text().contains("bucket owner"), "{}", r.text());
    // Reading it is what the policy grants.
    c.request_as("GET", "/acme-src?logging", &[], &ok, &os)
        .expect(200);
    c.request_as("PUT", "/acme-src?logging", &xml, &ak, &sk)
        .expect(200);
}

#[test]
fn turning_logging_off_stops_delivery() {
    let c = cluster();
    for b in ["src", "logs"] {
        c.request("PUT", &format!("/{b}"), &[]).expect(200);
    }
    let owner = owner_of(&c, "src");
    c.request(
        "PUT",
        "/logs?policy",
        &target_policy("logs", "log/", "src", &owner),
    )
    .expect(204);
    enable(&c, "src", "logs", "log/", "").expect(200);
    c.request("PUT", "/src/before", b"x").expect(200);
    let lines = await_lines(&c, "logs", "log/", 30, |l| {
        find(l, "REST.PUT.OBJECT", "before").is_some()
    });
    assert!(find(&lines, "REST.PUT.OBJECT", "before").is_some());

    c.request("PUT", "/src?logging", OFF).expect(200);
    let conf = c.request("GET", "/src?logging", &[]).text();
    assert!(!conf.contains("LoggingEnabled"), "{conf}");
    c.request("PUT", "/src/after", b"x").expect(200);
    // Three roll times: anything recorded would be delivered by now.
    std::thread::sleep(Duration::from_secs(3 * ROLL.parse::<u64>().unwrap() + 2));
    let lines = await_lines(&c, "logs", "log/", 0, |_| true);
    assert!(
        find(&lines, "REST.PUT.OBJECT", "after").is_none(),
        "a request after logging was turned off was logged"
    );
}

/// Records are on the gateway's disk before they are delivered: a gateway
/// killed (no drain) with batches open delivers every one when it is back.
#[test]
fn records_spooled_before_a_kill_are_delivered_after_the_restart() {
    let mut c = Cluster::start_with_ec_and_args(1, 1, 0, &["--bucket-log-roll-secs", "8"]);
    for b in ["src", "logs"] {
        c.request("PUT", &format!("/{b}"), &[]).expect(200);
    }
    let owner = owner_of(&c, "src");
    c.request(
        "PUT",
        "/logs?policy",
        &target_policy("logs", "log/", "src", &owner),
    )
    .expect(204);
    enable(&c, "src", "logs", "log/", "").expect(200);
    let mut ids = BTreeMap::new();
    for i in 0..30 {
        let r = c.request("PUT", &format!("/src/k{i}"), b"x");
        r.expect(200);
        ids.insert(format!("k{i}"), r.header("x-amz-request-id").unwrap());
    }
    // Well inside the roll time: nothing delivered yet.
    std::thread::sleep(Duration::from_millis(300));
    assert!(keys(&c, "logs", "log/").is_empty());
    c.restart();

    let lines = await_lines(&c, "logs", "log/", 60, |l| {
        ids.keys().all(|k| find(l, "REST.PUT.OBJECT", k).is_some())
    });
    for (k, id) in &ids {
        let f = find(&lines, "REST.PUT.OBJECT", k)
            .unwrap_or_else(|| panic!("{k}'s record was lost across the restart"));
        assert_eq!(&f[5], id);
    }
}
