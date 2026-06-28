//! Typed circuit inputs that serialize to the exact JSON circom expects.

use serde::Serialize;

use crate::circuit::{Circuit, MAX_TREE_DEPTH};
use crate::error::{Error, Result};
use crate::field::Field;

/// Inputs that can be turned into a witness for a specific [`Circuit`].
pub trait CircuitInputs: Serialize {
    /// Which circuit these inputs are for.
    const CIRCUIT: Circuit;

    /// Serialize to the circom input JSON (decimal strings / arrays).
    fn to_input_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| Error::Input(format!("serializing circuit inputs: {e}")))
    }
}

/// Build a fixed `[Field; MAX_TREE_DEPTH]` sibling array from a slice of the
/// actual proof siblings, zero-padding the remainder. Errors if more than
/// [`MAX_TREE_DEPTH`] siblings are supplied.
pub fn siblings(actual: &[Field]) -> Result<[Field; MAX_TREE_DEPTH]> {
    if actual.len() > MAX_TREE_DEPTH {
        return Err(Error::Input(format!(
            "too many siblings: {} > MAX_TREE_DEPTH ({MAX_TREE_DEPTH})",
            actual.len()
        )));
    }
    let mut out = [Field::ZERO; MAX_TREE_DEPTH];
    out[..actual.len()].copy_from_slice(actual);
    Ok(out)
}

/// Inputs to the `withdraw` circuit (`Withdraw(32)`).
///
/// Field names mirror the circom signals. `state_siblings` / `asp_siblings`
/// are fixed length [`MAX_TREE_DEPTH`]; use [`siblings`] to build them from a
/// shorter proof path.
#[derive(Clone, Debug, Serialize)]
pub struct WithdrawInputs {
    // ---- public ----
    #[serde(rename = "withdrawnValue")]
    pub withdrawn_value: Field,
    #[serde(rename = "stateRoot")]
    pub state_root: Field,
    #[serde(rename = "stateTreeDepth")]
    pub state_tree_depth: Field,
    #[serde(rename = "ASPRoot")]
    pub asp_root: Field,
    #[serde(rename = "ASPTreeDepth")]
    pub asp_tree_depth: Field,
    #[serde(rename = "context")]
    pub context: Field,
    // ---- private ----
    #[serde(rename = "label")]
    pub label: Field,
    #[serde(rename = "existingValue")]
    pub existing_value: Field,
    #[serde(rename = "existingNullifier")]
    pub existing_nullifier: Field,
    #[serde(rename = "existingSecret")]
    pub existing_secret: Field,
    #[serde(rename = "newNullifier")]
    pub new_nullifier: Field,
    #[serde(rename = "newSecret")]
    pub new_secret: Field,
    #[serde(rename = "stateSiblings")]
    pub state_siblings: [Field; MAX_TREE_DEPTH],
    #[serde(rename = "stateIndex")]
    pub state_index: Field,
    #[serde(rename = "ASPSiblings")]
    pub asp_siblings: [Field; MAX_TREE_DEPTH],
    #[serde(rename = "ASPIndex")]
    pub asp_index: Field,
}

impl CircuitInputs for WithdrawInputs {
    const CIRCUIT: Circuit = Circuit::Withdraw;
}

/// Inputs to the `commitment` circuit (`CommitmentHasher`).
#[derive(Clone, Debug, Serialize)]
pub struct CommitmentInputs {
    pub value: Field,
    pub label: Field,
    pub nullifier: Field,
    pub secret: Field,
}

impl CircuitInputs for CommitmentInputs {
    const CIRCUIT: Circuit = Circuit::Commitment;
}
