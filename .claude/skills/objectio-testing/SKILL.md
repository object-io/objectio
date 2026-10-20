---
name: objectio-testing
description: Running and writing ObjectIO's tests -- unit tests per crate, end-to-end tests against real processes in tests/e2e (single-process Cluster and multi-process HaCluster), ceph s3-tests, the rolling-upgrade test -- and telling a flaky test from a timing bug. Use when asked to test a change, write a test, run the e2e suite or a file of it, reproduce a CI or merge-queue failure, or check S3 compatibility.
---

# Testing ObjectIO

Test where the behaviour shows. A bug fix comes with the test that fails
without it.

| What changed | Test | Where |
|---|---|---|
| Logic inside one crate | Unit test, same file, `#[cfg(test)] mod tests` (`#[tokio::test]` for async) | the crate |
| What a client sees: the S3 API, the admin API, `obioctl` | End-to-end, one process (`Cluster`) | `tests/e2e/tests/<area>.rs` |
| Failover, quorum, repair, placement across nodes | End-to-end, many processes (`HaCluster`) | `tests/e2e/tests/<area>.rs`, helpers in `tests/e2e/src/ha.rs` |
| S3 compatibility | ceph s3-tests | `scripts/s3-tests/` |
| A rolling upgrade from the last release | `tests/e2e/tests/rolling_upgrade.rs` | `scripts/upgrade-test/` |

## Unit tests and lints

```bash
cargo test -p objectio-meta                          # one crate
cargo test -p objectio-meta --lib -- keep_progress   # tests whose name matches
cargo test -p objectio-erasure                       # ISA-L on x86_64 and arm64
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Every build erasure-codes with ISA-L, built from source: it needs
autoconf, automake, libtool and libclang-dev (NASM too on x86_64).

## End-to-end tests

They start real binaries from `target/debug`, so build those first, after
every change to the code under test:

```bash
cargo build --bin objectio-aio --bin obioctl --bin objectio-meta \
  --bin objectio-osd --bin objectio-gateway --bin objectio-block-gateway --bin objectio-install
cargo test -p objectio-e2e --test presigned                  # one file
cargo test -p objectio-e2e --test pg_recovery -- <test_name>  # one test
```

A test run against stale binaries tests the old code: if a result makes no
sense, check the binary is newer than your edit.

**Never rebuild while an end-to-end run is going in the same checkout**
(`cargo build`, `clippy` and `test` all relink): the binaries change under
the running suite. Use another `git worktree` with its own `--target-dir`.

CI runs the suite with nextest in eight shards, one test at a time per
shard, and the data-path files again on binaries built with the release's
features (`end-to-end (release features)`: io_uring). Tests marked
`#[ignore]` are left out there: measurements, and the tests below that
need something a plain machine lacks.

## Tests that need something

A test that needs root, a kernel feature or another build is
`#[ignore = "needs …; CI: <job>"]`, and run with `-- --ignored` it
**fails** when what it needs is missing. It never passes having tested
nothing. Each has a CI job that provides what it needs:

| Test | Needs | Run it with | CI job |
|---|---|---|---|
| `crates/osd/tests/crash_consistency.rs` | root through `sudo -n`, loop devices, `dm-log-writes` | `cargo test -p objectio-osd --test crash_consistency -- --ignored --nocapture` | `crash consistency` |
| `tests/e2e/tests/rolling_upgrade.rs` | the previous release's binaries | below | `rolling upgrade` |
| `tests/e2e/tests/rdma.rs` | an aio built with `--features rdma` (a Mooncake build), `OBJECTIO_E2E_RDMA=tcp` | `crates/transport-te/ci-test.sh`, in `crates/transport-te/test.Dockerfile`'s image | `rdma (transfer engine, tcp)` |
| `io_backend::tests::uring_roundtrip` (`objectio-storage`) | a host that allows io_uring (docker's default seccomp denies it) | `cargo test -p objectio-storage --features io-uring` (not ignored: the feature is the opt-in) | `unit tests`, `end-to-end (release features)` |
| `tests/e2e/tests/mtls.rs` | the suite on mTLS, its default (fails under `OBJECTIO_E2E_PLAIN`) | with the suite | the shards |

CI passes `--include-ignored`, so that dropping an `#[ignore]` can't make
its job run nothing. Writing such a test: check the prerequisite first and
`panic!`/`expect` with what is missing, never `eprintln!("skipped"); return`.

### Writing one

One process (meta, OSDs and gateway in an aio), signed requests through
the harness:

```rust
use objectio_e2e::Cluster;
use serde_json::json;

#[test]
fn a_presigned_get_serves_the_object_to_an_unauthenticated_client() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({ "name": "b" })).expect_ok();
    c.request("PUT", "/b/k", b"data").expect(200);
    // ...
}
```

`Cluster::start_with_ec(osds, k, m)` and `start_with_ec_and_args` pick the
scheme and flags; `restart`, `restart_with_lost_disk` and friends simulate
crashes and lost drives. Many processes: `objectio_e2e::ha::HaCluster::start(metas,
osds, gateways)`, then `await_leader`, and kill or restart members.

- **Name the test for the behaviour**, as a sentence:
  `a_full_member_holds_the_backfill_until_it_has_room`.
- **Wait for a condition with a deadline, never a fixed sleep.** Poll the
  state, `assert!(Instant::now() < deadline, "<what never happened>: {state}")`,
  and print the state you saw in the message.
- **Assert what a user would notice**, not internal counters that happen
  to move.
- The module comment says what the file covers and why it matters.

## ceph s3-tests

```bash
scripts/s3-tests/run.sh                          # the suite, about ten minutes
scripts/s3-tests/run.sh -- -k test_bucket_list   # a subset
scripts/s3-tests/run.sh --previous <old>/results.csv   # what changed
scripts/s3-tests/run.sh --jobs 1 -- -k "test_iam or test_sts"   # IAM/STS alone
```

It starts its own aio (port 19900), and writes `target/s3-tests/report/`.
A new failure shows as `uncategorized`: fix it, or give it a category and
a reason in `scripts/s3-tests/known-failures.csv`. Run on Linux; on a Mac,
in a Linux VM.

## The rolling upgrade

```bash
OBJECTIO_PREVIOUS_RELEASE_BIN=$(scripts/upgrade-test/previous-release.sh) \
  cargo test -p objectio-e2e --test rolling_upgrade -- --ignored --nocapture
```

It builds the last tag in a worktree under `target/previous/`, starts a
cluster on it, and upgrades one node at a time under traffic. It fails if
`main` carries a version that is already tagged, and without
`OBJECTIO_PREVIOUS_RELEASE_BIN`. The CI job finds the tag itself; before
the first release it says, as a warning, that there is nothing to upgrade
from, and fails if tags exist but none is behind the commit.

## A failure that comes and goes

Before calling it flaky:

1. Read the failing assertion and the state it printed.
2. Run that one test alone, several times:
   `for i in 1 2 3 4 5; do cargo test -p objectio-e2e --test <file> -- <name> | grep "test result"; done`
3. Passes alone, fails in the suite: something else running at the same
   time (another test, a background loop) changed the state. That is often
   a real race in the product: find which loop, and fix the product, not
   the test's timing.
4. Fails alone too: it's a bug, or the test asserts the wrong thing.

Don't add retries or longer sleeps to make a test pass; don't mark it
`#[ignore]` to get CI green.
