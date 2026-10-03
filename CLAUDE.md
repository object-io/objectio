# CLAUDE.md

How to work in this repository: the rules, the commands, the map, and
where to look. It holds no design: how each part works is in the docs repo
(`../objectio-docs/`, below), which is the one place it is written down.

## Rules

- **Roadmap first.** `../objectio-docs/ROADMAP.md` is the plan of record.
  Before any work on a new feature, even one asked for directly, find its
  row there; add one (🔨, plus a milestone with an exit test if it's
  sizeable) or mark the existing one 🔨, then start. Mark it ✅ in the docs
  PR that documents it. Bug fixes need no row unless they change a
  feature's status.
- **No legacy support.** No code for old releases, old formats or old
  clients (old-layout decoders, fallbacks for data "written before X",
  `serde(default)` only so old records parse). Ask before adding any.
  Compatibility between two adjacent releases, for a rolling upgrade, is
  the only exception (`core/upgrade-path.md`).
- **Reliability first.** An acknowledgement means the data is on stable
  storage. Never trade durability for speed.
- **Docs move with the code.** A change to how a part works updates its
  design in the same PR (docs repo); a change to what users see updates
  the guide.
- **Don't rebuild during an e2e run.** The suite runs `target/debug/`
  binaries; a `cargo build`/`clippy`/`test` in the same checkout swaps them
  mid-run. Edit only, or use a worktree with its own `--target-dir`.

## Where to look

In `../objectio-docs/` (clone it next to this repo):

| For | Read |
|---|---|
| What exists, what's planned, its status | `ROADMAP.md` |
| The system in an hour | `architecture/README.md`, then its short phase docs (`vision`, `data`, `services`, `decisions`, …) |
| How a part works | `architecture/design/README.md` (index by area: `core/`, `s3/`, `datalake/`, `security/`, `block/`, `file/`, `platform/`), then the design |
| Why a decision was made | `architecture/decisions.md`, `architecture/adr/` |
| What users and operators see | `developer-guide/` (features, API, S3 compatibility runs), `operations-guide/` |

Where a part has no design yet (the S3 gateway, the Iceberg catalog,
auth), the code is the reference. Check the docs before inventing an
explanation; if they're wrong, fix them in the same PR.

## Commands

```bash
make build | build-release | test | lint | fmt | fmt-fix | ci | coverage
cargo test -p objectio-erasure --features isal          # one crate
cargo test -p objectio-e2e --test <file>                # e2e: spawns target/debug binaries; build them first
cargo build --bin objectio-aio --bin objectio-cli --bin objectio-meta --bin objectio-osd --bin objectio-gateway --bin objectio-block-gateway
```

- Needs `protoc`. `isal` (x86_64 only) needs NASM, autoconf, automake,
  libtool, libclang-dev. It is declared on `objectio-erasure` and forwarded
  by gateway, osd and aio: use `--workspace --features isal` or
  `--bin objectio-aio --features isal`, not on other crates.
- Clippy runs with `-D warnings`. The `pedantic` and `nursery` groups apply
  only where a crate opts into `[lints] workspace = true` (today 6 of the
  15 library crates and 3 of the 10 binaries).
- Without local Rust: `docker compose run --rm build|test|lint|fmt|dev`.
- Local cluster: `objectio-aio` (meta + OSD + gateway in one process; see
  the README quickstart), or kind: `make kind-up | kind-up-registry |
  kind-load | kind-down` (`deploy/kind/`, chart in `deploy/helm/objectio/`).
- Console: `cd console && npm install && npm run build | dev | lint`
  (see `console/README.md`).
- Docs repo: `python3 scripts/docs.py index` then `check` before a docs PR.

## Map

Binaries live in `bin/`, libraries in `crates/`.

| | Port | What |
|---|---|---|
| `bin/objectio-gateway` | 9000 | S3 API (`s3.rs`), admin API, Iceberg REST, Unity Catalog, Delta Sharing, console; SigV4/OIDC/STS auth (`authz.rs`) |
| `bin/objectio-meta` | 9100 (metrics 9101, admin 9102) | Metadata on Raft (openraft + redb); placement, IAM, tenants, listings |
| `bin/objectio-osd` | 9200 (metrics 9201) | Shards on raw disks |
| `bin/objectio-block-gateway` | 9300 gRPC, 10809 NBD | Block volumes |
| `bin/objectio-aio` | | All of the above in one process |
| `bin/objectio-cli` | | Admin CLI: a SigV4 client of the gateway only (`bin/objectio-cli/README.md`) |
| `bin/objectio-{install,io-bench,s3-bench,dedup-estimate}` | | Tools |
| `crates/objectio-common` | | `Error`/`Result`, shared types, metrics, format levels (`version`) |
| `crates/objectio-proto` | | gRPC definitions (`proto/*.proto`, the only `build.rs`); meta channel (`transport`) |
| `crates/objectio-storage` | | The OSD's disk engine and metadata store |
| `crates/objectio-erasure` | | Erasure coding (rust-simd, ISA-L) |
| `crates/objectio-placement` | | CRUSH placement, topology |
| `crates/objectio-meta-store` | | Meta's redb tables, Raft storage and network |
| `crates/objectio-block` | | Block engine: volumes, write cache, journal |
| `crates/objectio-auth` | | SigV4 (signer too), policies, STS |
| `crates/objectio-kms` | | SSE key handling |
| `crates/objectio-iceberg`, `-unity-catalog`, `-delta-sharing` | | Data lake APIs |
| `crates/objectio-s3` | | S3 metrics and usage accounting |
| `crates/objectio-transport-te` | | RDMA shard transport (Mooncake TE) |
| `tests/e2e` | | End-to-end tests against real processes (`src/ha.rs`: multi-process clusters) |

## Code conventions

- Rust 2024, rustc ≥ 1.93; Tokio, Axum 0.8, Tonic 0.12 / Prost 0.13.
- Errors: `objectio_common::Error` everywhere except `objectio-block`,
  which has its own `BlockError`/`BlockResult`; don't mix them.
- Unit tests sit in their source file (`#[cfg(test)] mod tests`);
  `#[tokio::test]` for async. Behaviour across processes goes in
  `tests/e2e`.
- Handlers take `Option<Extension<AuthResult>>` when they must work under
  `--no-auth` (no extension then). A route that must be public (health, or
  bearer-token APIs like Delta Sharing) is mounted outside the SigV4
  middleware.
- Meta writes go through Raft (`replicate`, `cas_many`); never write redb
  directly in a handler.
- Commits: author `yash <ys@imys.in>`; no `Co-Authored-By` lines.
