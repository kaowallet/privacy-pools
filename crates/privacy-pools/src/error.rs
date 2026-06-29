//! Error type for the crate.

use std::fmt;

/// Errors produced while building witnesses, proving, or verifying.
#[derive(Debug)]
pub enum Error {
    /// A circuit input was malformed (e.g. not a valid field element, or a
    /// fixed-length array had the wrong length).
    Input(String),
    /// Witness generation via circom-witnesscalc failed.
    Witness(String),
    /// Parsing a bundled/loaded artifact (graph, zkey, or vkey) failed.
    Artifact(String),
    /// Groth16 proof generation failed.
    Prove(String),
    /// Groth16 verification ran but the proof did not satisfy the circuit.
    VerificationFailed,
    /// An I/O error while loading artifacts from a runtime directory.
    Io(std::io::Error),
    /// A chain interaction failed (RPC error, log decode, etc.) — only produced
    /// by the `onchain` sync layer.
    Chain(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Input(m) => write!(f, "invalid circuit input: {m}"),
            Error::Witness(m) => write!(f, "witness generation failed: {m}"),
            Error::Artifact(m) => write!(f, "artifact error: {m}"),
            Error::Prove(m) => write!(f, "proof generation failed: {m}"),
            Error::VerificationFailed => write!(f, "groth16 verification failed"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Chain(m) => write!(f, "chain error: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
