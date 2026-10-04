//! Make sure `console/dist` exists before `include_dir!` looks at it.
//!
//! aio embeds the built console with
//! `include_dir!("$CARGO_MANIFEST_DIR/../../console/dist")`, and that
//! directory is a build artefact — it is gitignored. So a fresh clone could
//! not build the project's main binary at all: the proc macro panicked with
//! "…/console/dist is not a directory", which reads like a corrupt checkout
//! rather than "run npm run build first".
//!
//! Creating an empty directory is enough for the macro; the binary then
//! serves an empty console, which is the right outcome for someone who has
//! not built the frontend. Anyone who wants the real thing runs
//! `npm ci && npm run build` in `console/` and rebuilds.

use std::path::Path;

fn main() {
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../console/dist");
    if !dist.is_dir() {
        if let Err(e) = std::fs::create_dir_all(&dist) {
            println!("cargo:warning=could not create {}: {e}", dist.display());
        } else {
            println!(
                "cargo:warning=console/dist was missing, created it empty — \
                 run `npm ci && npm run build` in console/ for the real UI"
            );
        }
    }
    println!("cargo:rerun-if-changed=../../console/dist");
}
