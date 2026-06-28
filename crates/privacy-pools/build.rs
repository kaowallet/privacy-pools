//! When the `bundled` feature is on, fail early with a friendly message if the
//! circuit artifacts haven't been generated yet (rather than a raw
//! `include_bytes!` "file not found").

use std::path::Path;

fn main() {
    if std::env::var_os("CARGO_FEATURE_BUNDLED").is_none() {
        return;
    }

    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let artifacts = Path::new(&manifest).join("artifacts");

    let required = [
        "withdraw.graph.bin",
        "withdraw.zkey",
        "withdraw.vkey.json",
        "commitment.graph.bin",
        "commitment.zkey",
        "commitment.vkey.json",
    ];

    for name in required {
        let path = artifacts.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        if !path.exists() {
            panic!(
                "\n\nMissing bundled circuit artifact:\n    {}\n\n\
                 Generate the artifacts with:\n    cargo xtask pull-circuits\n\n\
                 …or build with `--no-default-features` to load them from a \
                 directory at runtime instead.\n",
                path.display()
            );
        }
    }
}
