//! [`CircuitStore`]: embedded v2 artifacts plus a directory of downloaded ones.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{catalog, Circuit};
use crate::error::{Error, Result};
use crate::prover::Prover;
use crate::verifier::Verifier;

/// Which artifact of a circuit a file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    /// circom-witnesscalc graph (our `build-circuit --O1` output).
    Graph,
    /// snarkjs verification key (`groth16_vkey.json`).
    Vkey,
    /// Ceremony proving key (`groth16_pkey.zkey`).
    Zkey,
}

/// A file a circuit needs, with its pinned sha256 and where to get it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactSource {
    pub circuit: Circuit,
    pub kind: ArtifactKind,
    /// File name inside the store directory.
    pub file: String,
    /// Expected sha256 (lowercase hex). Zkeys carry the ceremony hash.
    pub sha256: String,
    /// Expected size in bytes.
    pub bytes: u64,
    /// GitHub URL at the pinned monorepo commit, or `None` for graphs (our own
    /// build output, which only `partial-bundled-v2` or the xtask provides).
    pub url: Option<String>,
}

impl ArtifactSource {
    /// Every file `circuit` needs, embedded or not.
    pub fn all_for(circuit: Circuit) -> Result<[ArtifactSource; 3]> {
        let entry = catalog::entry(circuit)?;
        let name = circuit.name();
        let source = |kind, file: &str, sha256: &str, bytes, url| ArtifactSource {
            circuit,
            kind,
            file: file.to_string(),
            sha256: sha256.to_string(),
            bytes,
            url,
        };
        Ok([
            source(
                ArtifactKind::Graph,
                &entry.graph.file,
                &entry.graph.sha256,
                entry.graph.bytes,
                None,
            ),
            source(
                ArtifactKind::Vkey,
                &entry.vkey.file,
                &entry.vkey.sha256,
                entry.vkey.bytes,
                Some(catalog::raw_github_url(&format!(
                    "packages/circuits/build/{name}/groth16_vkey.json"
                ))?),
            ),
            source(
                ArtifactKind::Zkey,
                &entry.zkey.file,
                &entry.zkey.sha256,
                entry.zkey.bytes,
                Some(entry.zkey.url.clone()),
            ),
        ])
    }
}

/// Where v2 provers/verifiers come from: the artifacts embedded by
/// `partial-bundled-v2`, then files previously installed into `dir`.
///
/// Typical wallet flow: before a transaction, check
/// [`missing`](Self::missing) for the circuit(s) it needs; if non-empty, ask
/// the user to download `sum(bytes)` (with the `download` feature,
/// [`download`](Self::download)), then call [`prover`](Self::prover).
///
/// **Privacy:** the transact shape a transaction uses is public on-chain, so
/// fetching a single `transact_NxM` right before using it lets the server (or
/// anyone watching the connection) link your IP to that transaction. Prefer
/// downloading every missing circuit at once, well ahead of use.
#[derive(Clone, Debug)]
pub struct CircuitStore {
    dir: PathBuf,
}

impl CircuitStore {
    /// A store backed by `dir` (created on the first install). Without
    /// `partial-bundled-v2`, `dir` must hold the `pull-circuits-v2` graphs and
    /// vkeys too.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory installed files live in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether `circuit` can be proven and verified right now.
    pub fn is_available(&self, circuit: Circuit) -> Result<bool> {
        Ok(self.missing([circuit])?.is_empty())
    }

    /// The files `circuits` still need, in order and without duplicates; empty
    /// when all of them are ready. Sum `bytes` for the download size.
    ///
    /// Only checks presence and size (no hashing). [`prover`](Self::prover)
    /// verifies the sha256 on load and deletes a corrupt file, so it shows up
    /// here again.
    pub fn missing(
        &self,
        circuits: impl IntoIterator<Item = Circuit>,
    ) -> Result<Vec<ArtifactSource>> {
        let mut missing: Vec<ArtifactSource> = Vec::new();
        for circuit in circuits {
            for source in ArtifactSource::all_for(circuit)? {
                if embedded(&source).is_some()
                    || missing.contains(&source)
                    || self.installed_size(&source) == Some(source.bytes)
                {
                    continue;
                }
                missing.push(source);
            }
        }
        Ok(missing)
    }

    /// Store `bytes` as `source` after checking its size and sha256.
    pub fn install(&self, source: &ArtifactSource, bytes: &[u8]) -> Result<()> {
        self.install_from_reader(source, bytes, |_| ControlFlow::Continue(()))
    }

    /// Stream `reader` into the store as `source`, hashing as it goes. Nothing
    /// lands at the final path unless the size and sha256 match. `on_bytes`
    /// gets the bytes written so far; returning `Break` cancels with
    /// [`Error::Cancelled`].
    ///
    /// This is the seam for wallets that bring their own HTTP client.
    pub fn install_from_reader(
        &self,
        source: &ArtifactSource,
        mut reader: impl Read,
        mut on_bytes: impl FnMut(u64) -> ControlFlow<()>,
    ) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        let part = self.dir.join(format!("{}.part", source.file));
        let result = (|| {
            let mut out = fs::File::create(&part)?;
            let mut hasher = Sha256::new();
            let mut written = 0u64;
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => return Err(Error::Io(e)),
                };
                written += n as u64;
                if written > source.bytes {
                    return Err(Error::Artifact(format!(
                        "{} is larger than the pinned {} bytes",
                        source.file, source.bytes
                    )));
                }
                hasher.update(&buf[..n]);
                out.write_all(&buf[..n])?;
                if on_bytes(written).is_break() {
                    return Err(Error::Cancelled);
                }
            }
            check_digest(source, written, &hasher.finalize())?;
            out.sync_all()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(fs::rename(&part, self.dir.join(&source.file))?),
            Err(e) => {
                let _ = fs::remove_file(&part);
                Err(e)
            }
        }
    }

    /// A prover for `circuit`, from embedded or installed artifacts.
    ///
    /// Returns [`Error::CircuitNotDownloaded`] if a file is missing.
    pub fn prover(&self, circuit: Circuit) -> Result<Prover> {
        let [graph, _, zkey] = ArtifactSource::all_for(circuit)?;
        let graph = self.load(&graph)?;
        let zkey = self.load(&zkey)?;
        Prover::new(&graph, &zkey)
    }

    /// A verifier for `circuit` (vkey only — no zkey needed).
    pub fn verifier(&self, circuit: Circuit) -> Result<Verifier> {
        let [_, vkey, _] = ArtifactSource::all_for(circuit)?;
        Verifier::from_vkey_json(&self.load(&vkey)?)
    }

    fn installed_size(&self, source: &ArtifactSource) -> Option<u64> {
        fs::metadata(self.dir.join(&source.file))
            .ok()
            .map(|m| m.len())
    }

    /// Embedded bytes, or the installed file after a size + sha256 check. A
    /// corrupt file is deleted so [`missing`](Self::missing) reports it again.
    fn load(&self, source: &ArtifactSource) -> Result<std::borrow::Cow<'static, [u8]>> {
        if let Some(bytes) = embedded(source) {
            return Ok(bytes.into());
        }
        let path = self.dir.join(&source.file);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(Error::CircuitNotDownloaded(source.circuit.name()))
            }
            Err(e) => return Err(Error::Io(e)),
        };
        if let Err(e) = check_digest(source, bytes.len() as u64, &Sha256::digest(&bytes)) {
            let _ = fs::remove_file(&path);
            return Err(e);
        }
        Ok(bytes.into())
    }
}

fn check_digest(source: &ArtifactSource, len: u64, digest: &[u8]) -> Result<()> {
    if len != source.bytes || hex::encode(digest) != source.sha256 {
        return Err(Error::Artifact(format!(
            "{}: got {len} bytes with sha256 {}, expected {} bytes with sha256 {}",
            source.file,
            hex::encode(digest),
            source.bytes,
            source.sha256
        )));
    }
    Ok(())
}

#[cfg(feature = "partial-bundled-v2")]
fn embedded(source: &ArtifactSource) -> Option<&'static [u8]> {
    let name = source.circuit.name();
    match source.kind {
        ArtifactKind::Graph => super::bundled::graph(&name),
        ArtifactKind::Vkey => super::bundled::vkey(&name),
        ArtifactKind::Zkey => super::bundled::zkey(&name),
    }
}

#[cfg(not(feature = "partial-bundled-v2"))]
fn embedded(_: &ArtifactSource) -> Option<&'static [u8]> {
    None
}
