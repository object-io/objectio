# ceph s3-tests

Runs [ceph/s3-tests](https://github.com/ceph/s3-tests), the S3 compatibility
suite, against a fresh single-process cluster (`objectio-aio`) and writes a
report.

```bash
scripts/s3-tests/run.sh                          # the whole suite, about an hour
scripts/s3-tests/run.sh -- -k test_bucket_list   # a subset (pytest -k)
scripts/s3-tests/run.sh --previous <old>/results.csv   # list what changed
```

Needs Python 3, git, curl and a Rust toolchain (it builds `objectio-aio`).
Everything goes in `target/s3-tests/` (`--work` to change it): the s3-tests
checkout, pinned to a commit so runs compare, with its own venv; the
cluster's data; and the results.

## What it sets up

- A 6-OSD, 4+2 aio with SigV4 auth on, and lifecycle "days" of 10 seconds,
  so the lifecycle tests finish (`lc_debug_interval = 10` in the config).
- Bucket-logging objects rolled every 3 seconds (`--bucket-log-roll-secs`):
  the logging tests wait 5.5 seconds for one. pytest runs with `TZ=UTC`, as
  they compare a log object's name (UTC) with the local clock.
- Users through the admin API (`setup_users.py`):
  - `main` and `alt` in tenant `s3t`;
  - `tenant` in tenant `testx`;
  - IAM-test users.

  None of them is the system admin, which bypasses bucket policies.
- The cluster default that blocks public access on new buckets turned off,
  as s3-tests makes buckets public with policies.
- KMS keys `testkey-1` and `testkey-2` for the SSE-KMS tests.
- `--acl-shim` (off by default) turns canned bucket ACLs into the
  equivalent bucket policies, since ObjectIO is BucketOwnerEnforced.

## The report

`<work>/report/` holds:
- `junit.xml`: pytest's raw output.
- `results.csv`: one row per test, with columns
  `test_id, file, outcome, category, note, message`.
- `summary.md`: totals; a table by file; failures by reason; every bug,
  gap and uncategorized failure listed; and, with `--previous`, the tests
  whose outcome changed.

Each failure's category and note come from `known-failures.csv`:

| Category | Meaning |
|---|---|
| `not-implemented-by-design` | left out on purpose: ACL grants, SigV2, the IAM API, S3 Select, torrents, RGW extensions |
| `aws-compatible-already` | ObjectIO does what AWS does; the test expects RGW's behaviour |
| `test-environment` | can't pass on this setup |
| `gap` | a feature we lack and could add |
| `bug` | wrong behaviour, to fix |

A failure missing from that file shows up as `uncategorized`. Look at it,
fix it or add it to the file with a reason. When a bug is fixed, delete its
row.

## Publishing a run

Run it on Linux, x86_64 and arm64 (on a Mac, in a Linux VM or container:
native macOS syncs are far slower, and some tests time out there). Copy
each `report/` to objectio-docs under
`developer-guide/s3-compatibility/<date>/<platform>/` (`linux-amd64`,
`linux-arm64`), and update the latest numbers in
`developer-guide/s3-compatibility/README.md`.
