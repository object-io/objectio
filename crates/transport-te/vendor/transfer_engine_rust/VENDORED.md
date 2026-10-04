# Vendored: Mooncake Transfer Engine Rust bindings

- **Upstream:** https://github.com/kvcache-ai/Mooncake, directory
  `mooncake-transfer-engine/rust`
- **Commit:** `c3fa13ecaf1038df933dcb784ff8ffe026381100`
- **License:** Apache-2.0 (`LICENSE-APACHE`, copied from the upstream root)
- **Changes from upstream** (everything else is byte-for-byte):
  - `build.rs` is upstream's, renamed `build_upstream.rs`. A new `build.rs`
    runs it only with the `link` feature, and then sets `cfg(te_linked)`.
  - `src/lib.rs` gains one line, `#![cfg(te_linked)]`: without `link` the
    crate is empty.
  - `Cargo.toml`: adds the `link` feature (which pulls in the now-optional
    `bindgen` build dependency) and `publish = false`, drops `[[example]]`
    and `[dev-dependencies]`, and allows clippy's lints so `clippy -D
    warnings` over our code does not fail on upstream style.

Vendored because the crate is not published on crates.io, and a git
dependency would make every workspace build fetch the whole Mooncake
repository to resolve the lockfile — even builds that never enable RDMA.

Being an in-tree path dependency, it is a member of ObjectIO's workspace
(Cargo makes it one; `exclude` does not apply to path dependencies of
members), so every `--workspace` command builds it. Hence the `link` gate:
plain builds get an empty crate and need no Mooncake; `objectio-transport-te`'s
`te` feature turns `link` on. Its `build.rs`
needs a Mooncake CMake build: set `MOONCAKE_BUILD_DIR` and
`MOONCAKE_TE_INCLUDE_DIR` (see its README upstream), and have libclang
available for bindgen.

To update: copy upstream's `build.rs` over `build_upstream.rs`, and `src/`
and `LICENSE-APACHE`, from the new commit; reapply the `lib.rs` line and the
`Cargo.toml` changes above; update the commit here and in
`../../test.Dockerfile`; and rerun the TE tests (`test.Dockerfile`).
