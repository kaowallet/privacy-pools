//! When the `bundled` / `partial-bundled-v2` features are on, fail early with a
//! friendly message if the circuit artifacts haven't been generated yet (rather
//! than a raw `include_bytes!` "file not found").

use std::path::Path;

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let artifacts = Path::new(&manifest).join("artifacts");

    if std::env::var_os("CARGO_FEATURE_BUNDLED").is_some() {
        require(
            &artifacts,
            &[
                "withdraw.graph.bin",
                "withdraw.zkey",
                "withdraw.vkey.json",
                "commitment.graph.bin",
                "commitment.zkey",
                "commitment.vkey.json",
            ],
            "cargo xtask pull-circuits",
            Some("bundled"),
        );
    }

    // The v2 catalog (pinned hashes / sizes / URLs) is embedded in every build.
    require(
        &artifacts.join("v2"),
        &["manifest.json"],
        "cargo xtask pull-circuits-v2",
        None,
    );

    if std::env::var_os("CARGO_FEATURE_PARTIAL_BUNDLED_V2").is_some() {
        let mut files: Vec<String> = ["deposit", "ragequit"]
            .into_iter()
            .map(String::from)
            .chain((1..=5).flat_map(|n| (1..=5).map(move |m| format!("transact_{n}x{m}"))))
            .flat_map(|c| [format!("{c}.graph.bin"), format!("{c}.vkey.json")])
            .collect();
        files.extend(["deposit", "ragequit", "transact_1x1"].map(|c| format!("{c}.zkey")));
        let files: Vec<&str> = files.iter().map(String::as_str).collect();
        require(
            &artifacts.join("v2"),
            &files,
            "cargo xtask pull-circuits-v2",
            Some("partial-bundled-v2"),
        );
    }
}

fn require(dir: &Path, files: &[&str], generate: &str, feature: Option<&str>) {
    for name in files {
        let path = dir.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        if !path.exists() {
            let alternative = feature
                .map(|f| {
                    format!(
                        "…or build without the `{f}` feature to load them from a \
                         directory at runtime instead.\n"
                    )
                })
                .unwrap_or_default();
            panic!(
                "\n\nMissing circuit artifact:\n    {}\n\n\
                 Generate the artifacts with:\n    {generate}\n\n{alternative}",
                path.display()
            );
        }
    }
}
