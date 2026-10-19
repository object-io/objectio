---
name: objectio-contribute
description: The workflow for changing ObjectIO's code in this repository -- finding or opening the issue first, branching, keeping to the project's rules (durability, no legacy code, one change per PR), choosing the test level, writing the commit and the pull request, and what CI and the merge queue run. Use when asked to fix a bug, add a feature, refactor, or open a pull request in the objectio repo.
---

# Contributing a change to ObjectIO

The rules are in `CONTRIBUTING.md` and the map of the code in `CLAUDE.md`;
read both before the first change in a session. This skill is the order
of the work and the things that get a pull request sent back.

## 1. The issue comes first

No feature work starts without an issue, even when the person asks for the
feature directly. Look for it before opening one:

```bash
gh issue list -R object-io/objectio --search "<words>" --state all
```

- **Found:** say which issue covers the request, and work against what it
  says "done" means.
- **Not found, a feature:** open one with what will be true when it's done
  and how that is tested, an `area:` label (`s3`, `core`, `datalake`,
  `security`, `block`, `file`, `platform`, `ci`, `docs`) and, if a
  maintainer has decided the release, its milestone:

  ```bash
  gh issue create -R object-io/objectio --title "..." --label area:core --body "..."
  ```

  For anything sizeable, stop here and let the person (or a maintainer)
  agree the approach in the issue before writing code.
- **A bug fix:** the bug report is the issue. A fix needs no feature issue
  unless it changes what a feature can do.

## 2. Before writing code: what will be refused

- **Anything that acknowledges before the data is on stable storage**, or
  skips an fsync, a quorum or a checksum for speed. Durability is not
  traded, whatever the benchmark says.
- **Code for old releases or formats**: fallbacks for data "written before
  X", old-layout decoders, `serde(default)` just so old records parse. Only
  compatibility between two adjacent releases (a rolling upgrade) is kept.
  Ask the person before adding any.
- **What S3 or the project left out on purpose**: ACL grants, SigV2,
  access across tenants.
- **Meta writes outside Raft.** A handler goes through `replicate` or
  `cas_many`, never the store directly.

## 3. Make the change

```bash
git switch -c <area>/<short-name> origin/main
```

- One coherent change per branch. A refactor the fix needs is its own
  commit, first.
- Match the code around it: naming, comment density (comments say why),
  error types (`objectio_common::Error`; `BlockError` only inside
  `objectio-block`).
- Handlers that must work under `--no-auth` take
  `Option<Extension<AuthResult>>`; public routes are mounted outside the
  SigV4 middleware.
- New dependencies need a reason in the PR.

## 4. Test it at the right level

The `objectio-testing` skill has the commands and the pitfalls. In short:
logic in one crate gets a unit test in the same file; anything a client or
another process sees gets an end-to-end test in `tests/e2e`; a bug fix
includes the test that fails without it. Run, at least:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p <crate>
```

and the end-to-end files the change touches.

## 5. Commit

- Subject: what is now true, prefixed by the part, e.g.
  `meta: a raft log append a crash left partly zeros is cut off at open`.
  Not "fix bug" or "update code".
- Body: why, and how it was tested.
- Each commit builds and passes its tests.
- Use the person's own git identity. Don't add trailers or footers the
  project doesn't use unless the person asks.

## 6. The pull request

```bash
git push -u origin HEAD
gh pr create -R object-io/objectio --fill-first   # then edit the body to the template
```

Fill in `.github/pull_request_template.md`: what and why with
`Closes #<issue>`, how it was tested, and what changes for users and
operators (flags, defaults, errors, metrics, limits).

Documentation: `README.md` files in this repo (`bin/cli/README.md`,
`sdk/*/README.md`, `scripts/*/README.md`) change in the same PR. The guides
and the designs live in the separate docs repository; if it's checked out
next to this one (`../objectio-docs`) and the person maintains it, the
design and guide change go in a docs PR alongside. Otherwise say in the PR
what the guides need, and a maintainer carries it.

## 7. CI and the merge queue

- Every PR runs rustfmt, clippy, unit tests, the console build and the Helm
  chart. Fix a red check before asking for review; don't re-run a failure
  hoping it passes without reading its log first.
- After approval a maintainer queues it. The queue runs the eight
  end-to-end shards, the rolling upgrade, the images and a performance
  check on the PR merged with the latest `main`. A failure there that
  isn't in the change's own tests is often a real timing bug the change
  exposed: read the failing test, run it alone a few times, and report
  what you find instead of calling it flaky.

## Don't

- Don't push to `main`, force-push a branch under review, or merge your own
  PR unless the person says that is how their repo works.
- Don't build or run tests in a checkout where an end-to-end run is going:
  the binaries change under it.
- Don't put hostnames, IPs, keys or customers' names in code, tests or
  docs.
