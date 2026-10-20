# Contributing to ObjectIO

Thank you for helping. ObjectIO is storage: people trust it with data they
can't get back. Most of what follows comes from that.

- [Ways to help](#ways-to-help)
- [Before you write code](#before-you-write-code)
- [Setting up](#setting-up)
- [Making a change](#making-a-change)
- [Testing](#testing)
- [Pull requests](#pull-requests)
- [Documentation](#documentation)
- [Licensing](#licensing)

Security problems are not reported here: see [SECURITY.md](SECURITY.md).
Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Ways to help

- **Report a bug.** Use the bug form under
  [Issues](https://github.com/object-io/objectio/issues/new/choose). The
  most useful report says what you ran (the release, how it is deployed,
  the client and the request), what you expected, what happened, and the
  logs around it. A failing test case is better still.
- **Try it and tell us.** Run `objectio-aio` or the Helm chart against
  your own clients and workloads. What breaks or confuses you is exactly
  what we can't see from inside.
- **Improve the documentation.** The guides at
  [object-io.github.io](https://object-io.github.io): a wrong command, a
  missing step or an unclear page is worth an issue.
- **Pick up an issue.** Issues labelled
  [`good first issue`](https://github.com/object-io/objectio/labels/good%20first%20issue)
  are small and self-contained; [`help wanted`](https://github.com/object-io/objectio/labels/help%20wanted)
  ones are larger. Say in the issue that you're taking it, so two people
  don't do the same work.

## Before you write code

**Every change starts from an issue.** For a bug, the issue is the
report. For anything else, open (or find) an issue that says what will be
true when it's done and how that is tested, and wait for a maintainer to
agree on the approach before writing much code. A pull request with no
issue behind it may be a good change we still can't take, because it
doesn't fit the plan.

What's planned is on the [roadmap](https://object-io.github.io/latest/ROADMAP/),
by release; each item links its issue, and the
[project board](https://github.com/orgs/object-io/projects/1) shows what's
in progress. Issues carry an `area:` label for their domain (`s3`, `core`,
`datalake`, `security`, `block`, `file`, `platform`, `ci`, `docs`) and a
milestone for their release.

Some things we won't take, however well done:

- **Trading durability for speed.** An acknowledgement means the data is on
  stable storage. A change that acknowledges first and persists later, or
  skips an fsync to win a benchmark, is a bug.
- **Code for old releases, formats or clients**: fallbacks for data
  "written before X", decoders for old layouts, defaults that exist only so
  old records parse. The one exception is compatibility between two
  adjacent releases, which a rolling upgrade needs.
- **Features S3 deprecated or ObjectIO left out on purpose**: ACL grants
  (buckets are BucketOwnerEnforced; use bucket policies), SigV2, access
  across tenants. The S3 compatibility page lists them, with reasons.
- **Licence tiers, feature flags that gate paid features, or telemetry.**
  Everything is Apache-2.0.

## Setting up

ObjectIO targets Linux, on x86_64 and arm64. On a Mac, build and test
inside a Linux VM or container: macOS is fine for editing, but its fsync
behaviour and timings make test results misleading.

You need:

- Rust, at the version pinned in [rust-toolchain.toml](rust-toolchain.toml)
  (rustup installs it on first use);
- `protoc` (`protobuf-compiler`);
- for ISA-L, which every build erasure-codes with (built from source):
  `autoconf`, `automake`, `libtool`, `libclang-dev`, and `nasm` on x86_64.

```sh
sudo apt-get install build-essential protobuf-compiler \
  nasm autoconf automake libtool libclang-dev       # Ubuntu / Debian
git clone https://github.com/object-io/objectio && cd objectio
make build        # debug build
make test
```

No Rust installed? `docker compose run --rm build` (and `test`, `lint`,
`fmt`) runs the same in a container.

To run what you built: `target/debug/objectio-aio` runs meta, the OSDs and
the gateway in one process (the [README](README.md#quickstart) has a
quickstart). The repo's layout and every crate's job are in
[CLAUDE.md](CLAUDE.md#map): it was written for coding agents, and it's as
good a map for people.

## Making a change

- **One change per pull request.** A fix, a feature or a refactor, each on
  its own. A refactor that a fix needs goes in a commit of its own, before
  the fix.
- **Rust 2024; `cargo fmt`; `cargo clippy -- -D warnings`.** CI runs both
  on every pull request. Locally: `make lint`, and `make fmt` (check) or
  `make fmt-fix`.
- **Errors**: `objectio_common::Error` everywhere except `objectio-block`,
  which has its own; don't mix them. No `unwrap()` on anything a client,
  a disk or the network can make fail.
- **Meta writes go through Raft** (`replicate`, `cas_many`); a handler
  never writes the store directly.
- **Comments say why, not what.** Name things for what they are; a
  comment that repeats the code goes stale.
- **No new dependency without saying why** in the pull request. Prefer what
  the workspace already uses.
- **Commits**: a subject saying what is now true, prefixed by the part it
  touches, e.g. `meta: a raft log append a crash left partly zeros is cut
  off at open`, or `gateway: ...`. The body says why, and how it was
  tested. Each commit builds and passes its tests.

## Testing

Every change is tested, at the level where its behaviour shows:

| Change | Test | Run it with |
|---|---|---|
| Logic inside one crate | A unit test in the same file (`#[cfg(test)] mod tests`; `#[tokio::test]` for async) | `cargo test -p <crate>` |
| Behaviour across processes: the S3 API, failover, repair, upgrades | An end-to-end test in `tests/e2e`, against real processes | `cargo test -p objectio-e2e --test <file>` (build the binaries first, below) |
| S3 compatibility | ceph s3-tests | `scripts/s3-tests/run.sh` ([README](scripts/s3-tests/README.md)) |
| A rolling upgrade | The upgrade test, from the last release | `scripts/upgrade-test/previous-release.sh` (see its header) |

End-to-end tests run the binaries in `target/debug`, so build them first:

```sh
cargo build --bin objectio-aio --bin obioctl --bin objectio-meta \
  --bin objectio-osd --bin objectio-gateway --bin objectio-block-gateway
```

Don't rebuild while an end-to-end run is going in the same checkout: the
binaries change under it. Use a second checkout or `git worktree` with its
own `--target-dir`.

A bug fix comes with the test that fails without it. A test that sleeps
for a fixed time and hopes is a flaky test: wait for the condition, with a
deadline.

Maintainers also run fault-injection (chaos) and long soak runs on real
machines before a release; you don't need to, but if your change touches
recovery, placement or durability, say so in the pull request and we will.

## Pull requests

1. Fork, branch from `main`, and make your change.
2. Open a pull request that says **what** changes, **why** (link the issue:
   `Closes #123`), and **how you tested it**. Fill in the template.
3. CI runs formatting, clippy, unit tests, the console and the Helm chart
   on every pull request; a maintainer approves the first run from a fork.
4. A maintainer reviews. We look first at correctness and durability, then
   at tests, then at whether the code reads like the code around it.
   Expect questions; answer in the thread, push fixes as new commits, and
   don't force-push during review unless asked.
5. Once approved, a maintainer adds it to the merge queue. The queue runs
   the heavy jobs (the eight end-to-end shards, the rolling upgrade, the
   images, a performance check against the base) on your change merged
   with the latest `main`, and merges it, squashed, if they pass. If the
   queue fails, we'll tell you why.

A pull request that has had no reply from its author for a month may be
closed; reopening it is always fine.

## Documentation

A change to how a part works updates its design; a change to what users
see updates the guides. Both live in a separate documentation repository
that isn't public yet, so for now:

- in your pull request, say what changes for users or operators (a flag, a
  default, an error, a limit), and a maintainer updates the guides and the
  design with it;
- `README.md` files in this repo (`bin/cli/README.md`, `sdk/*/README.md`,
  `scripts/*/README.md`, …) are updated in your pull request itself.

## Licensing

ObjectIO is licensed under the [Apache License 2.0](LICENSE). By opening a
pull request, you agree that your contribution is licensed under it too
(section 5 of the licence: inbound = outbound), and that you have the right
to contribute it. Don't submit code you didn't write unless its licence is
compatible and you say where it came from.
