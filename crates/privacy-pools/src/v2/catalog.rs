//! The v2 artifact catalog: `artifacts/v2/manifest.json`, written by
//! `cargo xtask pull-circuits-v2` and embedded in every build, so the pinned
//! sha256 / size / download URL of all 27 circuits is known whether or not
//! their bytes are bundled.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use super::Circuit;
use crate::error::{Error, Result};

const MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/v2/manifest.json"
));

#[derive(Deserialize)]
pub(crate) struct Catalog {
    pub source: Source,
    /// The monorepo commit the zkey URLs (and vkey URLs) pin.
    pub source_commit: String,
    pub circuits: BTreeMap<String, Entry>,
}

#[derive(Deserialize)]
pub(crate) struct Source {
    pub repo: String,
}

#[derive(Deserialize)]
pub(crate) struct Entry {
    pub graph: FileEntry,
    pub vkey: FileEntry,
    pub zkey: ZkeyEntry,
}

#[derive(Deserialize)]
pub(crate) struct FileEntry {
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Deserialize)]
pub(crate) struct ZkeyEntry {
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
    pub url: String,
}

pub(crate) fn catalog() -> Result<&'static Catalog> {
    static CATALOG: OnceLock<std::result::Result<Catalog, String>> = OnceLock::new();
    CATALOG
        .get_or_init(|| serde_json::from_str(MANIFEST).map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| Error::Artifact(format!("embedded v2 manifest.json: {e}")))
}

pub(crate) fn entry(circuit: Circuit) -> Result<&'static Entry> {
    let name = circuit.checked_name()?;
    catalog()?
        .circuits
        .get(&name)
        .ok_or_else(|| Error::Artifact(format!("{name} is missing from the v2 manifest")))
}

/// `https://raw.githubusercontent.com/<owner>/<repo>/<commit>/<path>` for a
/// plain-git file of the pinned monorepo commit.
pub(crate) fn raw_github_url(path: &str) -> Result<String> {
    let catalog = catalog()?;
    let slug = catalog
        .source
        .repo
        .strip_prefix("https://github.com/")
        .map(|s| s.trim_end_matches(".git"))
        .ok_or_else(|| Error::Artifact("v2 manifest source is not a GitHub repo".into()))?;
    Ok(format!(
        "https://raw.githubusercontent.com/{slug}/{}/{path}",
        catalog.source_commit
    ))
}
