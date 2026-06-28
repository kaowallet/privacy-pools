//! `cargo xtask pull-circuits`
//!
//! Mirrors what `packages/circuits/scripts/present.sh` does upstream (stage the
//! `commitment` + `withdraw` trusted-setup keys), but additionally compiles each
//! circom circuit into a [circom-witnesscalc] *graph* file so witnesses can be
//! generated from pure Rust with no wasm/node runtime.
//!
//! Pipeline:
//!   1. Clone `0xbow-io/privacy-pools-core` at a pinned tag (sparse: just the
//!      circuits package, which carries the circom sources AND the `.zkey`/`.vkey`
//!      trusted-setup keys committed in `trusted-setup/final-keys/`).
//!   2. Clone `iden3/circomlib` at a pinned tag into the clone's `node_modules/`
//!      so the circuits' relative `include "../../../node_modules/circomlib/..."`
//!      lines resolve.
//!   3. For each circuit, synthesize the `main` component wrapper exactly as
//!      upstream's `src/index.ts` does (template + params + public-signal list),
//!      then run `build-circuit` to emit `<name>.graph.bin`.
//!   4. Copy `<name>.zkey` / `<name>.vkey` into the crate's `artifacts/` dir.
//!   5. Write `artifacts/manifest.json` (provenance + sha256 + public-signal order).
//!
//! [circom-witnesscalc]: https://github.com/iden3/circom-witnesscalc

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Pinned upstream sources.  Bump these (and re-run the task) to track a new
// privacy-pools-core release.  The keys MUST match the on-chain Groth16 verifier
// you intend to prove against, so we pin to a tagged release by default.
// ---------------------------------------------------------------------------

const PP_CORE_REPO: &str = "https://github.com/0xbow-io/privacy-pools-core.git";
/// privacy-pools-core v1.2.1 -> commit a80836a47451e662f127af17e11430ffa976c234
const PP_CORE_REF: &str = "v1.2.1";

const CIRCOMLIB_REPO: &str = "https://github.com/iden3/circomlib.git";
/// Matches `packages/circuits/package.json`'s `circomlib: 2.0.5`.
const CIRCOMLIB_REF: &str = "v2.0.5";

/// The circom-witnesscalc release whose `calc_witness` consumes the graphs we
/// build, recorded in the manifest. The runtime crate depends on the matching
/// crates.io `circom-witnesscalc = "0.3.0"`.
const WITNESSCALC_VERSION: &str = "0.3.0";

/// `build-circuit` is NOT in the published crate — it's an unpublished
/// workspace member (`extensions/build-circuit`). We build it from the SAME
/// git tag as the published 0.3.0 lib so the emitted graph format
/// (`wtns.graph.002`) is byte-compatible with the lib's `calc_witness`.
const WITNESSCALC_REPO: &str = "https://github.com/iden3/circom-witnesscalc.git";
/// Tag `v0.3.0` == commit d48eb7c97857d46b8a75c94ab96f769207263245.
const WITNESSCALC_TAG: &str = "v0.3.0";

/// Circuits staged by upstream `present.sh`, with the `main`-component
/// parameters taken verbatim from `packages/circuits/src/index.ts`.
const CIRCUITS: &[CircuitSpec] = &[
    CircuitSpec {
        name: "commitment",
        src_file: "commitment",
        template: "CommitmentHasher",
        params: &[],
        // circom orders the public-signal vector as: outputs (decl order) then
        // declared public inputs (decl order).
        outputs: &["commitment", "nullifierHash"],
        pubs: &["value", "label"],
    },
    CircuitSpec {
        name: "withdraw",
        src_file: "withdraw",
        template: "Withdraw",
        params: &[32],
        outputs: &["newCommitmentHash", "existingNullifierHash"],
        pubs: &[
            "withdrawnValue",
            "stateRoot",
            "stateTreeDepth",
            "ASPRoot",
            "ASPTreeDepth",
            "context",
        ],
    },
];

struct CircuitSpec {
    /// Output artifact basename and upstream key basename.
    name: &'static str,
    /// `<src_file>.circom` in the circuits dir.
    src_file: &'static str,
    /// circom template to instantiate as `main`.
    template: &'static str,
    /// Template parameters (e.g. `maxTreeDepth = 32`).
    params: &'static [u32],
    /// Output signal names in declaration order.
    outputs: &'static [&'static str],
    /// Declared public input signal names in declaration order.
    pubs: &'static [&'static str],
}

impl CircuitSpec {
    /// The `main` component wrapper, equivalent to what circomkit generates from
    /// `src/index.ts`. The witness/constraint layout depends only on the
    /// template instantiation + public-signal set, so reproducing this exactly
    /// keeps our graph compatible with the committed `.zkey`.
    fn main_wrapper(&self) -> String {
        let params = self
            .params
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "pragma circom 2.2.0;\n\n\
             // GENERATED by `cargo xtask pull-circuits` — do not edit.\n\
             include \"./{src}.circom\";\n\n\
             component main {{public [{pubs}]}} = {template}({params});\n",
            src = self.src_file,
            pubs = self.pubs.join(", "),
            template = self.template,
            params = params,
        )
    }

    /// Full public-signal ordering the verifier expects: outputs then pubs.
    fn public_signals(&self) -> Vec<String> {
        self.outputs
            .iter()
            .chain(self.pubs.iter())
            .map(|s| s.to_string())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(clap::Args)]
pub struct Args {
    /// Re-download and rebuild even when the staged artifacts already match the
    /// requested ref.
    #[arg(long)]
    force: bool,

    /// privacy-pools-core git ref (tag or branch) to pull from.
    #[arg(long, default_value = PP_CORE_REF)]
    core_ref: String,

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
    circomlib: SourcePin,
    witnesscalc_version: String,
    circuits: BTreeMap<String, CircuitManifest>,
}

#[derive(Serialize, Deserialize)]
struct SourcePin {
    repo: String,
    git_ref: String,
}

#[derive(Serialize, Deserialize)]
struct CircuitManifest {
    template: String,
    params: Vec<u32>,
    /// Public-signal names in verifier order (outputs ++ public inputs).
    public_signals: Vec<String>,
    graph: ArtifactFile,
    zkey: ArtifactFile,
    vkey: ArtifactFile,
}

#[derive(Serialize, Deserialize)]
struct ArtifactFile {
    file: String,
    sha256: String,
    bytes: u64,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(args: Args) -> Result<()> {
    let root = workspace_root()?;
    let artifacts_dir = root.join("crates/privacy-pools/artifacts");
    let manifest_path = artifacts_dir.join("manifest.json");

    if !args.force && manifest_is_current(&manifest_path, &args.core_ref, &artifacts_dir)? {
        println!(
            "✔ artifacts already up to date for {} (use --force to rebuild)",
            args.core_ref
        );
        return Ok(());
    }

    ensure_git()?;

    let work = root.join("target/pull-circuits");
    fs::create_dir_all(&work).context("creating work dir")?;
    fs::create_dir_all(&artifacts_dir).context("creating artifacts dir")?;

    // build-circuit is reused across runs (it's slow to install).
    let build_circuit = ensure_build_circuit(&work)?;

    // A fresh clone each rebuild keeps things deterministic.
    let core_dir = work.join("privacy-pools-core");
    if core_dir.exists() {
        fs::remove_dir_all(&core_dir).context("clearing previous clone")?;
    }
    clone_core(&core_dir, &args.core_ref)?;

    let node_modules = core_dir.join("node_modules");
    let circomlib_dir = node_modules.join("circomlib");
    clone_circomlib(&circomlib_dir)?;

    let circuits_src = core_dir.join("packages/circuits/circuits");
    let final_keys = core_dir.join("packages/circuits/trusted-setup/final-keys");

    let lib_search = [
        node_modules.clone(),
        circomlib_dir.join("circuits"),
        circuits_src.clone(),
    ];

    let mut manifest_circuits = BTreeMap::new();

    for spec in CIRCUITS {
        println!("── building circuit `{}` ──", spec.name);

        // 1. Synthesize the `main` wrapper next to the source so relative
        //    includes resolve, then compile it into a witnesscalc graph.
        let wrapper = circuits_src.join(format!("__main_{}.circom", spec.name));
        fs::write(&wrapper, spec.main_wrapper())
            .with_context(|| format!("writing wrapper {}", wrapper.display()))?;

        let graph_out = artifacts_dir.join(format!("{}.graph.bin", spec.name));
        compile_graph(&build_circuit, &wrapper, &graph_out, &lib_search, &work)?;

        // 2. Stage the committed trusted-setup keys (cf. present.sh).
        let zkey_out = artifacts_dir.join(format!("{}.zkey", spec.name));
        copy_file(&final_keys.join(format!("{}.zkey", spec.name)), &zkey_out)?;

        let vkey_out = artifacts_dir.join(format!("{}.vkey.json", spec.name));
        copy_file(&final_keys.join(format!("{}.vkey", spec.name)), &vkey_out)?;

        manifest_circuits.insert(
            spec.name.to_string(),
            CircuitManifest {
                template: spec.template.to_string(),
                params: spec.params.to_vec(),
                public_signals: spec.public_signals(),
                graph: artifact_file(&graph_out)?,
                zkey: artifact_file(&zkey_out)?,
                vkey: artifact_file(&vkey_out)?,
            },
        );
    }

    let manifest = Manifest {
        generator: format!("xtask pull-circuits ({} build)", env!("CARGO_PKG_VERSION")),
        source: SourcePin {
            repo: PP_CORE_REPO.to_string(),
            git_ref: args.core_ref.clone(),
        },
        circomlib: SourcePin {
            repo: CIRCOMLIB_REPO.to_string(),
            git_ref: CIRCOMLIB_REF.to_string(),
        },
        witnesscalc_version: WITNESSCALC_VERSION.to_string(),
        circuits: manifest_circuits,
    };
    let json = serde_json::to_string_pretty(&manifest)? + "\n";
    fs::write(&manifest_path, json).context("writing manifest.json")?;

    if !args.keep_work {
        let _ = fs::remove_dir_all(&core_dir);
    }

    println!("\n✔ staged artifacts in {}", artifacts_dir.display());
    for spec in CIRCUITS {
        println!("    {0}.graph.bin  {0}.zkey  {0}.vkey.json", spec.name);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

fn clone_core(dest: &Path, git_ref: &str) -> Result<()> {
    println!("→ cloning {PP_CORE_REPO} @ {git_ref} (sparse)");
    sh(
        Command::new("git").args([
            "clone",
            "--quiet",
            "--filter=blob:none",
            "--sparse",
            "--depth",
            "1",
            "--branch",
            git_ref,
            PP_CORE_REPO,
            &dest.to_string_lossy(),
        ]),
        "git clone privacy-pools-core",
    )?;
    sh(
        Command::new("git")
            .current_dir(dest)
            .args(["sparse-checkout", "set", "packages/circuits"]),
        "git sparse-checkout",
    )?;
    Ok(())
}

fn clone_circomlib(dest: &Path) -> Result<()> {
    println!("→ cloning {CIRCOMLIB_REPO} @ {CIRCOMLIB_REF}");
    fs::create_dir_all(dest.parent().unwrap()).ok();
    sh(
        Command::new("git").args([
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--branch",
            CIRCOMLIB_REF,
            CIRCOMLIB_REPO,
            &dest.to_string_lossy(),
        ]),
        "git clone circomlib",
    )?;
    Ok(())
}

fn compile_graph(
    build_circuit: &Path,
    circuit: &Path,
    out: &Path,
    lib_search: &[PathBuf],
    cwd: &Path,
) -> Result<()> {
    println!("→ build-circuit {} -> {}", circuit.display(), out.display());
    let mut cmd = Command::new(build_circuit);
    // build-circuit hardcodes `produce_input_log: true`, dumping
    // `log_input_signals*.txt` into the CWD — keep that out of the repo root.
    cmd.current_dir(cwd);
    cmd.arg(circuit).arg(out);
    for lib in lib_search {
        cmd.arg("-l").arg(lib);
    }
    // CRITICAL: the witness layout must match the committed zkey, which 0xbow
    // built via circomkit at circom's `--O1`. build-circuit defaults to `--O2`,
    // which fuses signals (e.g. withdraw 36901 -> 17513 wires) and yields a
    // witness incompatible with the zkey. Pin `--O1`.
    cmd.arg("--O1");
    sh(&mut cmd, "build-circuit")?;
    if !out.exists() {
        bail!("build-circuit reported success but {} is missing", out.display());
    }
    Ok(())
}

/// Locate or build the `build-circuit` binary.
///
/// Resolution order:
///   1. `$BUILD_CIRCUIT` — an explicit path to a binary you trust.
///   2. A pinned copy under the work dir's `tools/` (built once, then cached).
///
/// We deliberately do NOT pick up a random `build-circuit` from `$PATH`: a
/// version-mismatched binary could emit a graph the runtime crate's pinned
/// `calc_witness` can't read.
fn ensure_build_circuit(work: &Path) -> Result<PathBuf> {
    if let Some(custom) = std::env::var_os("BUILD_CIRCUIT") {
        let p = PathBuf::from(custom);
        if !p.exists() {
            bail!("$BUILD_CIRCUIT points at {} which does not exist", p.display());
        }
        println!("→ using build-circuit from $BUILD_CIRCUIT: {}", p.display());
        return Ok(p);
    }

    let tools = work.join("tools");
    let bin = tools.join("bin").join("build-circuit");
    if bin.exists() {
        return Ok(bin);
    }

    println!(
        "→ building build-circuit from {WITNESSCALC_REPO} @ {WITNESSCALC_TAG}\n  \
         (one-time; this compiles the iden3 circom frontend and may take a few minutes)…"
    );
    // `--locked` reuses the repo's Cargo.lock so the iden3/circom `branch = master`
    // deps resolve to the exact commits that the 0.3.0 release was built against.
    // Some environments lack a committed lock, so fall back to an unlocked build.
    let install = |locked: bool| -> bool {
        let mut cmd = Command::new("cargo");
        cmd.arg("install");
        if locked {
            cmd.arg("--locked");
        }
        cmd.args([
            "--git",
            WITNESSCALC_REPO,
            "--tag",
            WITNESSCALC_TAG,
            "--root",
            &tools.to_string_lossy(),
            "build-circuit",
        ]);
        cmd.status().map(|s| s.success()).unwrap_or(false)
    };

    if !install(true) {
        println!("  (locked install failed; retrying unlocked)");
        install(false);
    }
    if !bin.exists() {
        bail!(
            "failed to build `build-circuit` into {}. \
             Build it manually and set $BUILD_CIRCUIT to the binary path.",
            bin.display()
        );
    }
    Ok(bin)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> Result<PathBuf> {
    // xtask's CARGO_MANIFEST_DIR is `<root>/xtask`.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(Path::to_path_buf)
        .context("locating workspace root")
}

fn ensure_git() -> Result<()> {
    Command::new("git")
        .arg("--version")
        .output()
        .context("`git` is required but was not found on PATH")?;
    Ok(())
}

fn sh(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn `{what}`"))?;
    if !status.success() {
        bail!("`{what}` failed with {status}");
    }
    Ok(())
}

fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    fs::copy(src, dst)
        .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    Ok(())
}

fn artifact_file(path: &Path) -> Result<ArtifactFile> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    Ok(ArtifactFile {
        file: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        sha256: hex::encode(digest),
        bytes: bytes.len() as u64,
    })
}

/// True iff a manifest exists, targets `git_ref`, and every referenced file is
/// present with a matching sha256.
fn manifest_is_current(manifest_path: &Path, git_ref: &str, dir: &Path) -> Result<bool> {
    let Ok(raw) = fs::read(manifest_path) else {
        return Ok(false);
    };
    let Ok(manifest) = serde_json::from_slice::<Manifest>(&raw) else {
        return Ok(false);
    };
    if manifest.source.git_ref != git_ref {
        return Ok(false);
    }
    for circuit in manifest.circuits.values() {
        for f in [&circuit.graph, &circuit.zkey, &circuit.vkey] {
            let path = dir.join(&f.file);
            let Ok(bytes) = fs::read(&path) else {
                return Ok(false);
            };
            if hex::encode(Sha256::digest(&bytes)) != f.sha256 {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
