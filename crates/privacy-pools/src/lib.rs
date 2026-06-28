//! Generate and verify [Privacy Pools] (0xbow) Groth16 proofs in pure Rust.
//!
//! Witnesses are computed with [circom-witnesscalc] from a bundled circuit
//! *graph* (no wasm / node runtime), and proofs are produced with `ark-groth16`
//! against the bundled snarkjs trusted-setup keys. The output proof is
//! snarkjs / Solidity-verifier compatible.
//!
//! # Quick start
//!
//! ```no_run
//! use privacy_pools::{WithdrawProver, WithdrawInputs, Field, siblings};
//!
//! let prover = WithdrawProver::bundled()?;
//! let inputs = WithdrawInputs {
//!     withdrawn_value: Field::from(1_000_000_000_000_000_000u64),
//!     // ... remaining signals ...
//! #   state_root: Field::ZERO, state_tree_depth: Field::from(2u32),
//! #   asp_root: Field::ZERO, asp_tree_depth: Field::from(2u32), context: Field::ZERO,
//! #   label: Field::ZERO, existing_value: Field::from(5u64),
//! #   existing_nullifier: Field::from(1u64), existing_secret: Field::from(2u64),
//! #   new_nullifier: Field::from(3u64), new_secret: Field::from(4u64),
//! #   state_index: Field::ZERO, asp_index: Field::ZERO,
//!     state_siblings: siblings(&[])?,
//!     asp_siblings: siblings(&[])?,
//! };
//! let proof = prover.prove(&inputs)?;
//! assert!(prover.verify(&proof)?);
//! let calldata = proof.to_solidity_calldata();
//! # Ok::<(), privacy_pools::Error>(())
//! ```
//!
//! # Layering
//!
//! The modules split into a protocol-agnostic *engine* ([`Prover`], [`Verifier`],
//! [`Groth16Proof`], [`Field`], [`WitnessGenerator`], and the vendored zkey
//! reader / QAP) and a thin *protocol* layer ([`Circuit`], [`WithdrawInputs`],
//! the bundled artifacts, and the typed wrappers below). The engine is written
//! to be extracted into a shared crate once a second circom/Groth16 protocol
//! needs it.
//!
//! [Privacy Pools]: https://github.com/0xbow-io/privacy-pools-core
//! [circom-witnesscalc]: https://github.com/iden3/circom-witnesscalc

use std::fs;
use std::path::Path;

mod error;
mod field;
mod proof;
mod prover;
mod verifier;
mod vendor;
mod witness;

mod circuit;
mod inputs;

pub use circuit::{Circuit, MAX_TREE_DEPTH};
pub use error::{Error, Result};
pub use field::Field;
pub use inputs::{siblings, CircuitInputs, CommitmentInputs, WithdrawInputs};
pub use proof::{Groth16Proof, SolidityCalldata};
pub use prover::Prover;
pub use verifier::Verifier;
pub use witness::{parse_wtns, GraphWitness, WitnessGenerator};

// --- bundled artifact bytes -------------------------------------------------

#[cfg(feature = "bundled")]
macro_rules! artifact {
    ($name:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/artifacts/", $name))
    };
}

#[cfg(feature = "bundled")]
mod bundled {
    pub const WITHDRAW_GRAPH: &[u8] = artifact!("withdraw.graph.bin");
    pub const WITHDRAW_ZKEY: &[u8] = artifact!("withdraw.zkey");
    pub const WITHDRAW_VKEY: &[u8] = artifact!("withdraw.vkey.json");
    pub const COMMITMENT_GRAPH: &[u8] = artifact!("commitment.graph.bin");
    pub const COMMITMENT_ZKEY: &[u8] = artifact!("commitment.zkey");
    pub const COMMITMENT_VKEY: &[u8] = artifact!("commitment.vkey.json");
}

fn read_dir_file(dir: &Path, file: &str) -> Result<Vec<u8>> {
    fs::read(dir.join(file)).map_err(Error::Io)
}

/// Label a proof's public signals with their circuit signal names.
pub fn named_public_signals(circuit: Circuit, proof: &Groth16Proof) -> Vec<(&'static str, String)> {
    circuit
        .public_signal_names()
        .iter()
        .copied()
        .zip(proof.public_signals_decimal())
        .collect()
}

// --- typed protocol wrappers ------------------------------------------------

macro_rules! typed_prover {
    ($prover:ident, $inputs:ty, $circuit:expr, $graph:literal, $zkey:literal,
     $graph_const:path, $zkey_const:path) => {
        #[doc = concat!("Prover for the `", $graph, "` circuit.")]
        pub struct $prover(Prover);

        impl $prover {
            /// Build from the artifacts embedded in the binary.
            #[cfg(feature = "bundled")]
            pub fn bundled() -> Result<Self> {
                Ok(Self(Prover::new($graph_const, $zkey_const)?))
            }

            /// Build from raw `graph` + `zkey` bytes.
            pub fn from_bytes(graph: &[u8], zkey: &[u8]) -> Result<Self> {
                Ok(Self(Prover::new(graph, zkey)?))
            }

            /// Build from a directory containing the `pull-circuits` artifacts.
            pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self> {
                let dir = dir.as_ref();
                Self::from_bytes(&read_dir_file(dir, $graph)?, &read_dir_file(dir, $zkey)?)
            }

            /// Generate a proof for the given typed inputs.
            pub fn prove(&self, inputs: &$inputs) -> Result<Groth16Proof> {
                self.0.prove(&inputs.to_input_json()?)
            }

            /// Verify a proof with this circuit's verifying key.
            pub fn verify(&self, proof: &Groth16Proof) -> Result<bool> {
                self.0.verify(proof)
            }

            /// The circuit this prover targets.
            pub const fn circuit(&self) -> Circuit {
                $circuit
            }

            /// Access the underlying engine [`Prover`].
            pub fn engine(&self) -> &Prover {
                &self.0
            }
        }
    };
}

macro_rules! typed_verifier {
    ($verifier:ident, $vkey:literal, $vkey_const:path) => {
        #[doc = concat!("Verify-only handle for the `", $vkey, "` circuit (no zkey needed).")]
        pub struct $verifier(Verifier);

        impl $verifier {
            /// Build from the vkey embedded in the binary.
            #[cfg(feature = "bundled")]
            pub fn bundled() -> Result<Self> {
                Ok(Self(Verifier::from_vkey_json($vkey_const)?))
            }

            /// Build from raw `vkey.json` bytes.
            pub fn from_vkey_json(vkey: &[u8]) -> Result<Self> {
                Ok(Self(Verifier::from_vkey_json(vkey)?))
            }

            /// Build from a directory containing the `pull-circuits` artifacts.
            pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self> {
                Self::from_vkey_json(&read_dir_file(dir.as_ref(), $vkey)?)
            }

            /// Verify a proof.
            pub fn verify(&self, proof: &Groth16Proof) -> Result<bool> {
                self.0.verify(proof)
            }

            /// Access the underlying engine [`Verifier`].
            pub fn engine(&self) -> &Verifier {
                &self.0
            }
        }
    };
}

// The `bundled()` constructors reference these via the macro; they are gated on
// the same feature, so name resolution only happens when the consts exist.
#[cfg(feature = "bundled")]
use bundled::*;

typed_prover!(
    WithdrawProver,
    WithdrawInputs,
    Circuit::Withdraw,
    "withdraw.graph.bin",
    "withdraw.zkey",
    WITHDRAW_GRAPH,
    WITHDRAW_ZKEY
);
typed_prover!(
    CommitmentProver,
    CommitmentInputs,
    Circuit::Commitment,
    "commitment.graph.bin",
    "commitment.zkey",
    COMMITMENT_GRAPH,
    COMMITMENT_ZKEY
);

typed_verifier!(WithdrawVerifier, "withdraw.vkey.json", WITHDRAW_VKEY);
typed_verifier!(CommitmentVerifier, "commitment.vkey.json", COMMITMENT_VKEY);
