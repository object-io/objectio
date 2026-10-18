// ObjectIO wrapper around upstream's build script (build_upstream.rs,
// unchanged). Upstream always binds and links Mooncake; here that happens only
// with the `link` feature, so that the crate — a member of ObjectIO's
// workspace, like every in-tree path dependency — builds as an empty library
// everywhere else. See VENDORED.md.

#[cfg(feature = "link")]
mod upstream {
    include!("build_upstream.rs");

    pub fn run() {
        main();
    }
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(te_linked)");
    #[cfg(feature = "link")]
    {
        upstream::run();
        println!("cargo:rustc-cfg=te_linked");
    }
}
