//! `cargo xtask pull-circuits-v2`
//!
//! The Privacy Pools **v2** counterpart of `pull-circuits`: compile the v2
//! circom circuits into circom-witnesscalc graphs and stage them, the ceremony
//! verification keys and a subset of the ceremony proving keys under
//! `crates/privacy-pools/artifacts/v2/`.
//!
//! v2 ships 27 circuits (deposit, ragequit and 25 `transact_NxM` variants) with
//! ~1 GB of zkeys, so the split is:
//!
//! - **graphs + vkeys for all 27** are staged (they are small, and the graphs
//!   are our own build output that nobody else hosts);
//! - **zkeys only for [`BUNDLED`]**, which the crate's `partial-bundled-v2`
//!   feature embeds;
//! - every other zkey is recorded in the manifest catalog (sha256, size and a
//!   GitHub URL at the pinned commit) for the crate to download on request.
//!
//! Pipeline:
//!   1. Clone `0xbow-io/privacy-pools-v2-monorepo` at a pinned tag (sparse: the
//!      circom sources + every `build/<circuit>/`). The zkeys are git-lfs
//!      objects; the clone keeps them as LFS *pointers*.
//!   2. Clone `iden3/circomlib` and the zk-kit `binary-merkle-root.circom`
//!      package into the clone's `node_modules/`, mirroring the circomkit
//!      include paths (`./node_modules`, `./node_modules/circomlib/circuits`).
//!   3. For each circuit, check the committed circomkit `main` component
//!      against our spec, then run `build-circuit --O1` on it.
//!   4. Check each zkey's LFS pointer oid against the sha256 pinned from
//!      `CEREMONY.md`; download the bundled ones through the GitHub LFS batch
//!      API (plain `curl`, so git-lfs need not be installed).
//!   5. Write `artifacts/v2/manifest.json`, the catalog the crate embeds.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::pull_circuits::{
    artifact_file, clone_circomlib, compile_graph, copy_file, ensure_build_circuit, ensure_git, sh,
    workspace_root, ArtifactFile, SourcePin, CIRCOMLIB_REF, CIRCOMLIB_REPO, WITNESSCALC_VERSION,
};

// ---------------------------------------------------------------------------
// Pinned upstream sources.
// ---------------------------------------------------------------------------

const V2_GITHUB: &str = "0xbow-io/privacy-pools-v2-monorepo";
const V2_REPO: &str = "https://github.com/0xbow-io/privacy-pools-v2-monorepo.git";
/// v1.0.2 -> commit 1ee57b03a7a6a26a4bb70e9b3b49a4ca7fe2f6da. The ceremony keys
/// landed in v1.0.1; v1.0.2 is an SDK-only fix with identical circuits/keys.
const V2_REF: &str = "v1.0.2";

const ZK_KIT_REPO: &str = "https://github.com/privacy-scaling-explorations/zk-kit.circom.git";
/// `@zk-kit/binary-merkle-root.circom@2.0.0`, as resolved by the monorepo's
/// `pnpm-lock.yaml` (it depends on the same circomlib 2.0.5).
const ZK_KIT_REF: &str = "binary-merkle-root.circom-v2.0.0";

/// `Transact` / `Ragequit` tree-depth parameters (`circuits.json`).
const STATE_MAX_DEPTH: u32 = 22;
const KEYSTORE_MAX_DEPTH: u32 = 18;
const ASP_MAX_DEPTH: u32 = 18;

/// Circuits whose zkeys are staged for the crate's `partial-bundled-v2`
/// feature (~24 MB). Keep in sync with `crates/privacy-pools/src/v2`.
///
/// `deposit` is needed for every deposit, `ragequit` is the exit that must work
/// even when GitHub is unreachable, and `transact_1x1` is withdrawing from one
/// note (the official SDK proves with `transact_{n}x{m}`, `n` = notes spent,
/// `m` = one change note per label plus one recipient note per label for a
/// transfer).
const BUNDLED: &[&str] = &["deposit", "ragequit", "transact_1x1"];

/// sha256 of every `build/<circuit>/groth16_pkey.zkey`, copied from
/// `packages/circuits/CEREMONY.md` (ppv2-ceremony: 500 contributions per circuit
/// plus an Ethereum RANDAO beacon). This is the integrity anchor: a zkey whose LFS
/// oid or downloaded bytes differ from it is rejected, so a moved tag or a
/// tampered LFS object cannot slip in a different key.
const CEREMONY_ZKEY_SHA256: &[(&str, &str)] = &[
    (
        "deposit",
        "e6fb5283c7b7511b0422a773d9f054925969e47e8ddf55a6b38b590c951a73a4",
    ),
    (
        "ragequit",
        "044abe871b1b79fecb6b4ca6128d08a142d7ce8665f439032953bae92f6ab076",
    ),
    (
        "transact_1x1",
        "e92ad88f417c034f073580658839b64fdd1ad3c89a86a9faa926728f80351121",
    ),
    (
        "transact_1x2",
        "996b738388d50b8e85fa1c84b0733ac70ad3c2f320e226037d91ad8c8bf1335f",
    ),
    (
        "transact_1x3",
        "6e6e697f672a35770d2d9f49588bc841b943ff7c10a6afed07b6627d5f62fd3f",
    ),
    (
        "transact_1x4",
        "5ddee0a56c6ffc09c3f1f4ac4be78fe54b5c2b626a922eaec14e848558f91542",
    ),
    (
        "transact_1x5",
        "eeb45b1fd355d87a4975341b70982f993215370efec45c8b13bb065c6d9145c1",
    ),
    (
        "transact_2x1",
        "3afe537fd4762cb6957f1c8532049879a4f29ed7c54ef893a8299dabf68d9ea5",
    ),
    (
        "transact_2x2",
        "2083cba8cbeba5eb56756331fc01ce1849ebbec7bc64aaeb7a58a7417264f391",
    ),
    (
        "transact_2x3",
        "b22cc9171ce8c86b00aa95d095c4ed9eb9d5a97df1e2c2d5ee3257b37946b28f",
    ),
    (
        "transact_2x4",
        "b816f6391e06595e714840d66f59a8757541f7eb3160fc92e78275ffad544ccd",
    ),
    (
        "transact_2x5",
        "259a99de8620a1020680a3eb501b9f2c489cd2a6a0abff0d68967eb76ce937f0",
    ),
    (
        "transact_3x1",
        "cb03d64333509767bf1a7cff131e2d790f15afe9dfd74e942398e451d24f754e",
    ),
    (
        "transact_3x2",
        "e342328a03523b693462d75e96de5da6ddf8094940007a09ab38ca394540e707",
    ),
    (
        "transact_3x3",
        "e1d7ce07915fad1d8d6562ef166a2fce981bdf211827a81f2ba3e029f7b01268",
    ),
    (
        "transact_3x4",
        "83475261ec0e8125651e3672491d27318cec1db42cadce4cb2db7ab6b907fdc3",
    ),
    (
        "transact_3x5",
        "f1816f47842fa384592241e962a46f3938ff8fb931c42b6c5a1021d4ff1481ab",
    ),
    (
        "transact_4x1",
        "6c9a5eaea3f44de8a16de1436839721c3c1a3f92c5746719a6e1d0bf27b7fed8",
    ),
    (
        "transact_4x2",
        "211675e1dd535fd03e4ae923a13b186c28c2ba60fb1a1b502203979fc863e1cd",
    ),
    (
        "transact_4x3",
        "a9427d68a67b55a9d81c071fea3ffc52bafe4d2eadda0250c20708ab9db405d2",
    ),
    (
        "transact_4x4",
        "3a8cdb10ede535c64303b198e2db9a4c8c9c5a49bb340c487a220dd64ee47c95",
    ),
    (
        "transact_4x5",
        "239041de4d4d28356afd61cffbd2b2e8909c7e843b923aed8d79c7364bda5345",
    ),
    (
        "transact_5x1",
        "895add3547d0d33eaae16287148a1596fc9ca6d61a7a5cdfc3461c1633e8736f",
    ),
    (
        "transact_5x2",
        "e2f5f69e7365e63329fc840974b4a6b0c13553b9829dc4c95f45fd71fbc86baa",
    ),
    (
        "transact_5x3",
        "c9b2d185fea95ad798a6f8be531d7d4454aa5c4a6285a8c5ec1d9d4709487020",
    ),
    (
        "transact_5x4",
        "3f974b64a084bfa5bcf2b1f700e643ea6b7bc37e35f30e588ef6b80e21d0ef5b",
    ),
    (
        "transact_5x5",
        "7c70692fc7e41e7dec43159d18ca8aef73891f945e09019e4ebe5d7ea0673ed5",
    ),
];

// ---------------------------------------------------------------------------
// Circuit specs
// ---------------------------------------------------------------------------

/// One v2 circuit, as instantiated by circomkit from `circuits.json`.
struct V2Circuit {
    /// `deposit`, `ragequit` or `transact_<n>x<m>` (also the `build/` dir name).
    name: String,
    /// The committed circomkit `main` file, relative to `packages/circuits/circuits`.
    main: String,
    template: &'static str,
    params: Vec<u32>,
    /// Output signal names in declaration order (arrays expanded).
    outputs: Vec<String>,
    /// Declared public input signal names in declaration order.
    pubs: &'static [&'static str],
}

impl V2Circuit {
    fn parse(name: &str) -> Result<Self> {
        let circuit = match name {
            "deposit" => Self {
                name: name.into(),
                main: "main/deposit.circom".into(),
                template: "Deposit",
                params: vec![],
                outputs: vec!["outputCommitment".into()],
                pubs: &["tokenId", "value", "context"],
            },
            "ragequit" => Self {
                name: name.into(),
                main: "main/ragequit.circom".into(),
                template: "Ragequit",
                params: vec![KEYSTORE_MAX_DEPTH],
                outputs: vec!["nullifierHash".into(), "commitment".into()],
                pubs: &["keystoreRoot", "ownerAddress", "value", "tokenId", "label"],
            },
            _ => {
                let (n, m) = parse_transact(name).with_context(|| {
                    format!(
                        "unknown v2 circuit `{name}` (expected deposit, ragequit or \
                         transact_<n>x<m> with n, m in 1..=5)"
                    )
                })?;
                let outputs = (0..n)
                    .map(|i| format!("nullifierHashes[{i}]"))
                    .chain((0..m).map(|j| format!("outputCommitments[{j}]")))
                    .collect();
                Self {
                    name: name.into(),
                    main: format!("main/transact/{name}.circom"),
                    template: "Transact",
                    params: vec![n, m, STATE_MAX_DEPTH, KEYSTORE_MAX_DEPTH, ASP_MAX_DEPTH],
                    outputs,
                    pubs: &[
                        "stateRoot",
                        "keystoreRoot",
                        "associationSetRoot",
                        "amountOut",
                        "tokenIdOut",
                        "context",
                    ],
                }
            }
        };
        Ok(circuit)
    }

    /// The `component main` line circomkit generates for this spec.
    fn main_component(&self) -> String {
        let params = self
            .params
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "component main {{public[{}]}} = {}({});",
            self.pubs.join(", "),
            self.template,
            params
        )
    }

    /// Full public-signal ordering the verifier expects: outputs then pubs.
    fn public_signals(&self) -> Vec<String> {
        self.outputs
            .iter()
            .cloned()
            .chain(self.pubs.iter().map(|s| s.to_string()))
            .collect()
    }

    fn ceremony_sha256(&self) -> Result<&'static str> {
        CEREMONY_ZKEY_SHA256
            .iter()
            .find(|(n, _)| *n == self.name)
            .map(|(_, h)| *h)
            .with_context(|| format!("no ceremony zkey hash pinned for `{}`", self.name))
    }
}

/// `transact_<n>x<m>` -> `(n, m)`, both in `1..=5`.
fn parse_transact(name: &str) -> Option<(u32, u32)> {
    let (n, m) = name.strip_prefix("transact_")?.split_once('x')?;
    let (n, m) = (n.parse().ok()?, m.parse().ok()?);
    ((1..=5).contains(&n) && (1..=5).contains(&m)).then_some((n, m))
}

/// All 27 circuits, in `CEREMONY.md` order.
fn all_circuits() -> Result<Vec<V2Circuit>> {
    CEREMONY_ZKEY_SHA256
        .iter()
        .map(|(n, _)| V2Circuit::parse(n))
        .collect()
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
pub struct Args {
    /// Re-download and rebuild even when the staged artifacts already match.
    #[arg(long)]
    force: bool,

    /// privacy-pools-v2-monorepo git ref (tag or branch) to pull from.
    #[arg(long, default_value = V2_REF)]
    v2_ref: String,

    /// Keep the temporary clone/work directory after a successful run.
    #[arg(long)]
    keep_work: bool,
}

// ---------------------------------------------------------------------------
// Manifest written alongside the artifacts.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Manifest {
    generator: String,
    source: SourcePin,
    /// The commit `source.git_ref` resolved to; the zkey URLs pin it.
    source_commit: String,
    circomlib: SourcePin,
    zk_kit: SourcePin,
    witnesscalc_version: String,
    circuits: BTreeMap<String, V2CircuitManifest>,
}

#[derive(Serialize, Deserialize)]
struct V2CircuitManifest {
    template: String,
    params: Vec<u32>,
    /// Public-signal names in verifier order (outputs ++ public inputs).
    public_signals: Vec<String>,
    graph: ArtifactFile,
    vkey: ArtifactFile,
    zkey: ZkeyFile,
}

#[derive(Serialize, Deserialize)]
struct ZkeyFile {
    file: String,
    /// The ceremony sha256 (`CEREMONY.md`), also the git-lfs oid.
    sha256: String,
    bytes: u64,
    /// GitHub-served copy at the pinned commit, for on-request download.
    url: String,
    /// Staged next to the manifest (embedded by `partial-bundled-v2`).
    bundled: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(args: Args) -> Result<()> {
    let root = workspace_root()?;
    let artifacts_dir = root.join("crates/privacy-pools/artifacts/v2");
    let manifest_path = artifacts_dir.join("manifest.json");
    let specs = all_circuits()?;

    if !args.force && manifest_is_current(&manifest_path, &args.v2_ref, &artifacts_dir)? {
        println!(
            "✔ v2 artifacts already up to date for {} (use --force to rebuild)",
            args.v2_ref
        );
        return Ok(());
    }

    ensure_git()?;
    Command::new("curl")
        .arg("--version")
        .output()
        .context("`curl` is required (git-lfs zkey download) but was not found on PATH")?;

    let work = root.join("target/pull-circuits");
    fs::create_dir_all(&work).context("creating work dir")?;
    fs::create_dir_all(&artifacts_dir).context("creating artifacts dir")?;

    let build_circuit = ensure_build_circuit(&work)?;

    let v2_dir = work.join("privacy-pools-v2");
    if v2_dir.exists() {
        fs::remove_dir_all(&v2_dir).context("clearing previous clone")?;
    }
    clone_v2(&v2_dir, &args.v2_ref, &specs)?;
    let commit = git_head(&v2_dir)?;

    let pkg = v2_dir.join("packages/circuits");
    let node_modules = pkg.join("node_modules");
    clone_circomlib(&node_modules.join("circomlib"))?;
    clone_zk_kit(&node_modules)?;

    // circomkit.json: "include": ["./node_modules", "./node_modules/circomlib/circuits"]
    let lib_search = [
        node_modules.clone(),
        node_modules.join("circomlib/circuits"),
    ];
    let lfs_cache = work.join("lfs-cache");
    fs::create_dir_all(&lfs_cache).context("creating lfs cache dir")?;

    let mut manifest_circuits = BTreeMap::new();

    for spec in &specs {
        println!("── building v2 circuit `{}` ──", spec.name);

        // 1. Compile the committed circomkit main file, after checking it still
        //    instantiates the template/params/public set we expect.
        let main = pkg.join("circuits").join(&spec.main);
        let src =
            fs::read_to_string(&main).with_context(|| format!("reading {}", main.display()))?;
        let normalized = src.split_whitespace().collect::<Vec<_>>().join(" ");
        let expected = spec.main_component();
        if !normalized.contains(&expected) {
            bail!(
                "{} no longer contains `{expected}` — upstream changed the circuit \
                 instantiation; update the v2 spec",
                main.display()
            );
        }

        let graph_out = artifacts_dir.join(format!("{}.graph.bin", spec.name));
        compile_graph(&build_circuit, &main, &graph_out, &lib_search, &work)?;

        // 2. The plain-git vkey, and the ceremony proving key (an LFS object):
        //    staged when bundled, otherwise only catalogued.
        let build = pkg.join("build").join(&spec.name);
        let vkey_out = artifacts_dir.join(format!("{}.vkey.json", spec.name));
        copy_file(&build.join("groth16_vkey.json"), &vkey_out)?;

        let pointer = build.join("groth16_pkey.zkey");
        let sha256 = spec.ceremony_sha256()?;
        let bundled = BUNDLED.contains(&spec.name.as_str());
        let zkey_file = format!("{}.zkey", spec.name);
        let bytes = if bundled {
            let zkey_out = artifacts_dir.join(&zkey_file);
            fetch_lfs_object(&pointer, sha256, &lfs_cache, &zkey_out)?;
            artifact_file(&zkey_out)?.bytes
        } else {
            lfs_pointer_size(&pointer, sha256)?
        };

        manifest_circuits.insert(
            spec.name.clone(),
            V2CircuitManifest {
                template: spec.template.to_string(),
                params: spec.params.clone(),
                public_signals: spec.public_signals(),
                graph: artifact_file(&graph_out)?,
                vkey: artifact_file(&vkey_out)?,
                zkey: ZkeyFile {
                    file: zkey_file,
                    sha256: sha256.to_string(),
                    bytes,
                    url: format!(
                        "https://media.githubusercontent.com/media/{V2_GITHUB}/{commit}/\
                         packages/circuits/build/{}/groth16_pkey.zkey",
                        spec.name
                    ),
                    bundled,
                },
            },
        );
    }

    // Drop zkeys a previous run staged that are no longer bundled.
    for entry in fs::read_dir(&artifacts_dir).context("listing artifacts dir")? {
        let path = entry?.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if let Some(circuit) = name.strip_suffix(".zkey") {
            if !BUNDLED.contains(&circuit) {
                fs::remove_file(&path)
                    .with_context(|| format!("removing stale {}", path.display()))?;
            }
        }
    }

    let manifest = Manifest {
        generator: format!(
            "xtask pull-circuits-v2 ({} build)",
            env!("CARGO_PKG_VERSION")
        ),
        source: SourcePin {
            repo: V2_REPO.to_string(),
            git_ref: args.v2_ref.clone(),
        },
        source_commit: commit,
        circomlib: SourcePin {
            repo: CIRCOMLIB_REPO.to_string(),
            git_ref: CIRCOMLIB_REF.to_string(),
        },
        zk_kit: SourcePin {
            repo: ZK_KIT_REPO.to_string(),
            git_ref: ZK_KIT_REF.to_string(),
        },
        witnesscalc_version: WITNESSCALC_VERSION.to_string(),
        circuits: manifest_circuits,
    };
    let json = serde_json::to_string_pretty(&manifest)? + "\n";
    fs::write(&manifest_path, json).context("writing manifest.json")?;

    if !args.keep_work {
        let _ = fs::remove_dir_all(&v2_dir);
    }

    println!(
        "\n✔ staged graphs + vkeys for {} v2 circuits and the zkeys of {} in {}",
        specs.len(),
        BUNDLED.join(", "),
        artifacts_dir.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

fn clone_v2(dest: &Path, git_ref: &str, specs: &[V2Circuit]) -> Result<()> {
    println!("→ cloning {V2_REPO} @ {git_ref} (sparse)");
    // Keep LFS objects as pointers even where git-lfs is installed: a full
    // smudge of `packages/circuits/build` would pull every zkey (~1 GB).
    sh(
        Command::new("git")
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .args([
                "-c",
                "advice.detachedHead=false",
                "clone",
                "--quiet",
                "--filter=blob:none",
                "--sparse",
                "--depth",
                "1",
                "--branch",
                git_ref,
                V2_REPO,
            ])
            .arg(dest),
        "git clone privacy-pools-v2-monorepo",
    )?;
    let mut sparse = Command::new("git");
    sparse
        .current_dir(dest)
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .args(["sparse-checkout", "set", "packages/circuits/circuits"]);
    for spec in specs {
        sparse.arg(format!("packages/circuits/build/{}", spec.name));
    }
    sh(&mut sparse, "git sparse-checkout")
}

/// Fetch `packages/binary-merkle-root` and place it where the circuits'
/// `include "@zk-kit/binary-merkle-root.circom/src/..."` resolves.
fn clone_zk_kit(node_modules: &Path) -> Result<()> {
    println!("→ cloning {ZK_KIT_REPO} @ {ZK_KIT_REF} (sparse)");
    let clone = node_modules.join(".zk-kit.circom");
    sh(
        Command::new("git")
            .args([
                "-c",
                "advice.detachedHead=false",
                "clone",
                "--quiet",
                "--filter=blob:none",
                "--sparse",
                "--depth",
                "1",
                "--branch",
                ZK_KIT_REF,
                ZK_KIT_REPO,
            ])
            .arg(&clone),
        "git clone zk-kit.circom",
    )?;
    sh(
        Command::new("git").current_dir(&clone).args([
            "sparse-checkout",
            "set",
            "packages/binary-merkle-root",
        ]),
        "git sparse-checkout",
    )?;
    let dest = node_modules.join("@zk-kit/binary-merkle-root.circom");
    fs::create_dir_all(dest.parent().unwrap()).context("creating node_modules/@zk-kit")?;
    fs::rename(clone.join("packages/binary-merkle-root"), &dest)
        .context("staging @zk-kit/binary-merkle-root.circom")?;
    fs::remove_dir_all(&clone).ok();
    Ok(())
}

fn git_head(repo: &Path) -> Result<String> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .context("git rev-parse HEAD")?;
    ensure!(out.status.success(), "git rev-parse HEAD failed");
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

/// Size of the (not downloaded) LFS object behind `pointer`, after checking
/// its oid against the pinned ceremony sha256.
fn lfs_pointer_size(pointer: &Path, expected: &str) -> Result<u64> {
    let raw = fs::read(pointer).with_context(|| format!("reading {}", pointer.display()))?;
    let (oid, size) = match parse_lfs_pointer(&raw) {
        Some(p) => p,
        // git-lfs smudged the real file in despite GIT_LFS_SKIP_SMUDGE.
        None => (sha256_hex(&raw), raw.len() as u64),
    };
    ensure!(
        oid == expected,
        "{}: LFS oid {oid} != pinned ceremony sha256 {expected} — upstream keys changed",
        pointer.display()
    );
    Ok(size)
}

/// Materialize the git-lfs object behind `pointer` into `dest`, requiring its
/// sha256 to equal `expected`. Downloads are cached in `cache/<oid>`.
fn fetch_lfs_object(pointer: &Path, expected: &str, cache: &Path, dest: &Path) -> Result<()> {
    let raw = fs::read(pointer).with_context(|| format!("reading {}", pointer.display()))?;
    let Some((oid, size)) = parse_lfs_pointer(&raw) else {
        // git-lfs smudged the real file in despite GIT_LFS_SKIP_SMUDGE.
        ensure!(
            sha256_hex(&raw) == expected,
            "{} does not match the pinned ceremony sha256 {expected}",
            pointer.display()
        );
        return copy_file(pointer, dest);
    };
    ensure!(
        oid == expected,
        "{}: LFS oid {oid} != pinned ceremony sha256 {expected} — upstream keys changed",
        pointer.display()
    );

    let cached = cache.join(&oid);
    let is_cached = fs::read(&cached).is_ok_and(|b| sha256_hex(&b) == oid);
    if !is_cached {
        let (href, headers) = lfs_download_action(&oid, size)?;
        println!("→ downloading LFS object {oid} ({size} bytes)");
        let part = cache.join(format!("{oid}.part"));
        let mut curl = Command::new("curl");
        curl.args(["-fsSL", "--retry", "3", "-o"]).arg(&part);
        for (k, v) in &headers {
            curl.arg("-H").arg(format!("{k}: {v}"));
        }
        curl.arg(&href);
        sh(&mut curl, "curl (LFS download)")?;

        let bytes = fs::read(&part).context("reading downloaded LFS object")?;
        ensure!(
            bytes.len() as u64 == size && sha256_hex(&bytes) == oid,
            "downloaded LFS object {oid} failed its size/sha256 check"
        );
        fs::rename(&part, &cached).context("caching LFS object")?;
    }
    copy_file(&cached, dest)
}

/// Parse a git-lfs v1 pointer file into `(sha256 oid, size)`.
fn parse_lfs_pointer(raw: &[u8]) -> Option<(String, u64)> {
    let text = std::str::from_utf8(raw).ok()?;
    if !text.starts_with("version https://git-lfs.github.com/spec/v1") {
        return None;
    }
    let mut oid = None;
    let mut size = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("oid sha256:") {
            oid = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("size ") {
            size = v.trim().parse().ok();
        }
    }
    Some((oid?, size?))
}

/// Ask the GitHub LFS batch API where to download `oid` from.
fn lfs_download_action(oid: &str, size: u64) -> Result<(String, Vec<(String, String)>)> {
    let endpoint = format!("{V2_REPO}/info/lfs/objects/batch");
    let body = serde_json::json!({
        "operation": "download",
        "transfers": ["basic"],
        "objects": [{ "oid": oid, "size": size }],
    });
    let out = Command::new("curl")
        .args([
            "-fsS",
            "--retry",
            "3",
            "-X",
            "POST",
            "-H",
            "Accept: application/vnd.git-lfs+json",
            "-H",
            "Content-Type: application/vnd.git-lfs+json",
            "--data",
        ])
        .arg(body.to_string())
        .arg(&endpoint)
        .output()
        .context("running curl (LFS batch API)")?;
    if !out.status.success() {
        bail!(
            "LFS batch request failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let resp: Value = serde_json::from_slice(&out.stdout).context("parsing LFS batch response")?;
    let object = &resp["objects"][0];
    if let Some(err) = object.get("error") {
        bail!("LFS batch API refused {oid}: {err}");
    }
    let download = &object["actions"]["download"];
    let href = download["href"]
        .as_str()
        .context("LFS batch response has no download href")?
        .to_string();
    let headers = download["header"]
        .as_object()
        .map(|h| {
            h.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();
    Ok((href, headers))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// True iff a manifest exists for `git_ref`, catalogs all 27 circuits with the
/// pinned ceremony hashes and the current [`BUNDLED`] set, and every staged
/// file is present with a matching sha256.
fn manifest_is_current(manifest_path: &Path, git_ref: &str, dir: &Path) -> Result<bool> {
    let Ok(raw) = fs::read(manifest_path) else {
        return Ok(false);
    };
    let Ok(manifest) = serde_json::from_slice::<Manifest>(&raw) else {
        return Ok(false);
    };
    if manifest.source.git_ref != git_ref || manifest.circuits.len() != CEREMONY_ZKEY_SHA256.len() {
        return Ok(false);
    }
    let staged_ok = |file: &str, sha256: &str| {
        fs::read(dir.join(file)).is_ok_and(|bytes| sha256_hex(&bytes) == sha256)
    };
    for (name, pinned) in CEREMONY_ZKEY_SHA256 {
        let Some(c) = manifest.circuits.get(*name) else {
            return Ok(false);
        };
        let bundled = BUNDLED.contains(name);
        if c.zkey.sha256 != *pinned
            || c.zkey.bundled != bundled
            || !staged_ok(&c.graph.file, &c.graph.sha256)
            || !staged_ok(&c.vkey.file, &c.vkey.sha256)
            || (bundled && !staged_ok(&c.zkey.file, &c.zkey.sha256))
        {
            return Ok(false);
        }
    }
    Ok(true)
}
