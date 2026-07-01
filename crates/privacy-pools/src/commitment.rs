//! Privacy Pools commitment + nullifier hashing (matches `commitment.circom`).
//!
//! ```text
//! nullifierHash  = Poseidon([nullifier])
//! precommitment  = Poseidon([nullifier, secret])
//! commitment     = Poseidon([value, label, precommitment])
//! ```

use crate::error::Result;
use crate::field::Field;
use crate::poseidon::poseidon;

/// `Poseidon([nullifier])` — the public nullifier hash that prevents double-spends.
pub fn nullifier_hash(nullifier: Field) -> Result<Field> {
    poseidon(&[nullifier])
}

/// `Poseidon([nullifier, secret])`.
pub fn precommitment(nullifier: Field, secret: Field) -> Result<Field> {
    poseidon(&[nullifier, secret])
}

/// `Poseidon([value, label, Poseidon([nullifier, secret])])`.
pub fn commitment_hash(
    value: Field,
    label: Field,
    nullifier: Field,
    secret: Field,
) -> Result<Field> {
    let pre = precommitment(nullifier, secret)?;
    poseidon(&[value, label, pre])
}

/// A Privacy Pools commitment (a "note"): the spendable record of `value` held
/// in a pool under `label`, locked by `(nullifier, secret)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub value: Field,
    pub label: Field,
    pub nullifier: Field,
    pub secret: Field,
}

impl Commitment {
    pub fn new(value: Field, label: Field, nullifier: Field, secret: Field) -> Self {
        Self {
            value,
            label,
            nullifier,
            secret,
        }
    }

    /// The commitment hash (the leaf inserted into the state tree).
    pub fn hash(&self) -> Result<Field> {
        commitment_hash(self.value, self.label, self.nullifier, self.secret)
    }

    /// The nullifier hash revealed when spending.
    pub fn nullifier_hash(&self) -> Result<Field> {
        nullifier_hash(self.nullifier)
    }

    /// The precommitment `Poseidon([nullifier, secret])`.
    pub fn precommitment(&self) -> Result<Field> {
        precommitment(self.nullifier, self.secret)
    }
}
