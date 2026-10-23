//! Typed inputs for the v2 circuits, serializing to the exact witness JSON the
//! SDK's `WitnessPreparationService` builds (decimal strings, circuit-reduced).
//!
//! Each type can be filled in field by field, or built from notes and the
//! three LeanIMT trees (`from_trees`), which looks up the leaves and makes the
//! Merkle proofs. `to_input_json` validates first — the same range, Merkle and
//! value-conservation rules the circuit enforces — so a bad request fails here
//! with a reason instead of as an unprovable witness. `public_signals` gives
//! the values a proof of these inputs exposes, in verifier order.
//!
//! Merkle proofs feed zk-kit's `BinaryMerkleRoot`: the LeanIMT path-compressed
//! `index`, `depth = siblings.len()`, siblings zero-padded to the circuit's
//! maximum depth.

use serde_json::{json, Value};

use super::note::{self, Note, OutputNote};
use super::{Circuit, ASP_MAX_DEPTH, KEYSTORE_MAX_DEPTH, MAX_TRANSACT_NOTES, STATE_MAX_DEPTH};
use crate::context::Address;
use crate::error::{Error, Result};
use crate::field::Field;
use crate::poseidon::poseidon2;
use crate::tree::{LeanImt, MerkleProof};

/// Inputs to one of the v2 circuits.
pub trait CircuitInputs {
    /// The circuit (and, for transact, the `NxM` shape) these inputs prove.
    fn circuit(&self) -> Circuit;

    /// Check everything the circuit will constrain.
    fn validate(&self) -> Result<()>;

    /// The proof's public signals, in verifier order.
    fn public_signals(&self) -> Result<Vec<Field>>;

    /// The circuit inputs as a JSON object.
    fn to_input_value(&self) -> Result<Value>;

    /// Validate, then serialize to the circom input JSON.
    fn to_input_json(&self) -> Result<String> {
        self.validate()?;
        Ok(self.to_input_value()?.to_string())
    }
}

/// The root `zk-kit` `BinaryMerkleRoot` computes for a LeanIMT proof: every
/// sibling is hashed in, ordered by the bits of `index`.
pub fn binary_merkle_root(leaf: Field, index: u64, siblings: &[Field]) -> Result<Field> {
    let mut node = leaf;
    for (level, &sibling) in siblings.iter().enumerate() {
        node = if (index >> level) & 1 == 0 {
            poseidon2(node, sibling)?
        } else {
            poseidon2(sibling, node)?
        };
    }
    Ok(node)
}

// --- deposit -------------------------------------------------------------------

/// Inputs to the `deposit` circuit: proves the commitment of a new note
/// without revealing its owner or label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositInputs {
    pub token: Address,
    pub value: u128,
    /// [`deposit_context`](super::deposit_context) of the note data sent with it.
    pub context: Field,
    pub note_address_hash: Field,
    pub deposit_secret: Field,
}

impl DepositInputs {
    /// The inputs depositing `note` (made by [`Note::deposit`] with `deposit_secret`).
    pub fn new(note: &Note, deposit_secret: Field, context: Field) -> Result<Self> {
        let inputs = Self {
            token: note.token,
            value: note.value,
            context,
            note_address_hash: note.note_address_hash()?,
            deposit_secret,
        };
        if inputs.label()? != note.label {
            return Err(Error::Input(
                "note label is not P(precommitment, deposit_secret)".into(),
            ));
        }
        Ok(inputs)
    }

    /// The label the deposit gives the note.
    pub fn label(&self) -> Result<Field> {
        note::deposit_label(self.precommitment()?, self.deposit_secret)
    }

    /// The commitment the deposit inserts (the proof's only output).
    pub fn commitment(&self) -> Result<Field> {
        note::commitment(self.precommitment()?, self.label()?)
    }

    fn precommitment(&self) -> Result<Field> {
        note::precommitment(self.note_address_hash, self.token, self.value)
    }
}

impl CircuitInputs for DepositInputs {
    fn circuit(&self) -> Circuit {
        Circuit::Deposit
    }

    fn validate(&self) -> Result<()> {
        Ok(())
    }

    /// `[outputCommitment, tokenId, value, context]`.
    fn public_signals(&self) -> Result<Vec<Field>> {
        Ok(vec![
            self.commitment()?,
            self.token.to_field(),
            self.value.into(),
            self.context,
        ])
    }

    fn to_input_value(&self) -> Result<Value> {
        Ok(json!({
            "tokenId": self.token.to_field(),
            "value": Field::from(self.value),
            "context": self.context,
            "noteAddressHash": self.note_address_hash,
            "depositSecret": self.deposit_secret,
        }))
    }
}

// --- ragequit ------------------------------------------------------------------

/// Inputs to the `ragequit` circuit: exits a whole note to its owner without
/// ASP approval, authorized by the owner's keystore leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RagequitInputs {
    pub keystore_root: Field,
    pub owner: Address,
    pub value: u128,
    pub token: Address,
    pub label: Field,
    pub note_secret: Field,
    /// Note metadata; 0 for every v2.0 note.
    pub metadata: Field,
    pub nullifying_key: Field,
    pub revocable_key: Field,
    /// Membership of the owner's keystore leaf.
    pub keystore_proof: MerkleProof,
}

impl RagequitInputs {
    /// Ragequit `note`, proving its owner's leaf is in `keystore_tree`.
    pub fn from_trees(
        note: &Note,
        nullifying_key: Field,
        revocable_key: Field,
        keystore_tree: &LeanImt,
    ) -> Result<Self> {
        let leaf = note::keystore_leaf(
            note.owner,
            note::nullifying_key_hash(nullifying_key)?,
            note::auth_digest(revocable_key)?,
        )?;
        let keystore_proof = prove_leaf(keystore_tree, leaf, "keystore")?;
        Ok(Self {
            keystore_root: keystore_proof.root,
            owner: note.owner,
            value: note.value,
            token: note.token,
            label: note.label,
            note_secret: note.secret,
            metadata: Field::ZERO,
            nullifying_key,
            revocable_key,
            keystore_proof,
        })
    }

    /// The commitment of the note being exited.
    pub fn commitment(&self) -> Result<Field> {
        let nah = note::note_address_hash(self.owner, self.note_secret)?;
        let pre = poseidon_precommitment(nah, self.token, self.value, self.metadata)?;
        note::commitment(pre, self.label)
    }
}

impl CircuitInputs for RagequitInputs {
    fn circuit(&self) -> Circuit {
        Circuit::Ragequit
    }

    fn validate(&self) -> Result<()> {
        let leaf = note::keystore_leaf(
            self.owner,
            note::nullifying_key_hash(self.nullifying_key)?,
            note::auth_digest(self.revocable_key)?,
        )?;
        check_proof(
            &self.keystore_proof,
            leaf,
            self.keystore_root,
            KEYSTORE_MAX_DEPTH,
            "keystore",
        )
    }

    /// `[nullifierHash, commitment, keystoreRoot, ownerAddress, value, tokenId, label]`.
    fn public_signals(&self) -> Result<Vec<Field>> {
        let commitment = self.commitment()?;
        Ok(vec![
            note::nullifier_hash(self.nullifying_key, commitment)?,
            commitment,
            self.keystore_root,
            self.owner.to_field(),
            self.value.into(),
            self.token.to_field(),
            self.label,
        ])
    }

    fn to_input_value(&self) -> Result<Value> {
        Ok(json!({
            "keystoreRoot": self.keystore_root,
            "ownerAddress": self.owner.to_field(),
            "value": Field::from(self.value),
            "tokenId": self.token.to_field(),
            "label": self.label,
            "noteSecret": self.note_secret,
            "metadata": self.metadata,
            "privateNullifyingKey": self.nullifying_key,
            "privateRevocableKey": self.revocable_key,
            "keystoreLeafIndex": Field::from(self.keystore_proof.index),
            "keystoreSiblings": padded::<KEYSTORE_MAX_DEPTH>(&self.keystore_proof)?,
            "keystoreTreeDepth": depth(&self.keystore_proof),
        }))
    }
}

// --- transact ------------------------------------------------------------------

/// One spent note of a transact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactInput {
    pub note_secret: Field,
    pub value: u128,
    pub label: Field,
    /// `block.timestamp` of the note's insertion (part of its state leaf).
    pub timestamp: u64,
    /// Membership of the note's commitment leaf in the state tree.
    pub state_proof: MerkleProof,
    /// Membership of `P(label)` in the association set.
    pub asp_proof: MerkleProof,
}

/// A spendable note and when it was inserted, for [`TransactInputs::from_trees`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendNote {
    pub note: Note,
    /// `block.timestamp` the note's commitment leaf was inserted with.
    pub timestamp: u64,
}

/// Inputs to `transact_NxM` (`N = inputs.len()`, `M = outputs.len()`, both
/// 1..=5): spend `N` notes of one token into `M` new notes, withdrawing
/// `amount_out` publicly (0 for a private transfer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactInputs {
    pub state_root: Field,
    pub keystore_root: Field,
    pub asp_root: Field,
    pub amount_out: u128,
    /// `token` when `amount_out > 0`, the zero address otherwise.
    pub token_out: Address,
    /// [`transact_context`](super::transact_context) of the params and note data.
    pub context: Field,
    pub owner: Address,
    pub nullifying_key: Field,
    pub revocable_key: Field,
    pub keystore_proof: MerkleProof,
    pub token: Address,
    pub inputs: Vec<TransactInput>,
    /// Change notes first, then recipient notes (the SDK's order, which the
    /// note data and on-chain leaves follow).
    pub outputs: Vec<OutputNote>,
}

impl TransactInputs {
    /// Spend `notes` (one owner, one token) into `outputs`, proving membership
    /// in the given trees and withdrawing `amount_out` (0 = private transfer).
    #[allow(clippy::too_many_arguments)]
    pub fn from_trees(
        notes: &[SpendNote],
        outputs: Vec<OutputNote>,
        amount_out: u128,
        context: Field,
        nullifying_key: Field,
        revocable_key: Field,
        state_tree: &LeanImt,
        keystore_tree: &LeanImt,
        asp_tree: &LeanImt,
    ) -> Result<Self> {
        let first = notes
            .first()
            .ok_or_else(|| Error::Input("transact needs at least one input note".into()))?
            .note;
        if notes
            .iter()
            .any(|s| s.note.owner != first.owner || s.note.token != first.token)
        {
            return Err(Error::Input(
                "all input notes must share one owner and one token".into(),
            ));
        }
        let keystore_leaf = note::keystore_leaf(
            first.owner,
            note::nullifying_key_hash(nullifying_key)?,
            note::auth_digest(revocable_key)?,
        )?;
        let keystore_proof = prove_leaf(keystore_tree, keystore_leaf, "keystore")?;
        let inputs = notes
            .iter()
            .map(|s| {
                Ok(TransactInput {
                    note_secret: s.note.secret,
                    value: s.note.value,
                    label: s.note.label,
                    timestamp: s.timestamp,
                    state_proof: prove_leaf(
                        state_tree,
                        s.note.commitment_leaf(s.timestamp)?,
                        "state",
                    )?,
                    asp_proof: prove_leaf(asp_tree, s.note.asp_leaf()?, "association set")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            state_root: tree_root(state_tree)?,
            keystore_root: keystore_proof.root,
            asp_root: tree_root(asp_tree)?,
            amount_out,
            token_out: if amount_out == 0 {
                Address([0; 20])
            } else {
                first.token
            },
            context,
            owner: first.owner,
            nullifying_key,
            revocable_key,
            keystore_proof,
            token: first.token,
            inputs,
            outputs,
        })
    }

    fn input_commitment(&self, input: &TransactInput) -> Result<Field> {
        let nah = note::note_address_hash(self.owner, input.note_secret)?;
        note::commitment(
            note::precommitment(nah, self.token, input.value)?,
            input.label,
        )
    }

    /// The circuit's `ValueConservation`: totals balance, every output label
    /// is a spent label, and no label's outputs exceed its inputs.
    fn check_values(&self) -> Result<()> {
        let total_in = checked_sum(self.inputs.iter().map(|i| i.value))?;
        let total_out = checked_sum(
            self.outputs
                .iter()
                .map(|o| o.value)
                .chain([self.amount_out]),
        )?;
        if total_in != total_out {
            return Err(Error::Input(format!(
                "value not conserved: inputs {total_in} != outputs + amount_out {total_out}"
            )));
        }
        for out in &self.outputs {
            if !self.inputs.iter().any(|i| i.label == out.label) {
                return Err(Error::Input(
                    "every output label must be the label of a spent note".into(),
                ));
            }
            let label_in = checked_sum(
                self.inputs
                    .iter()
                    .filter(|i| i.label == out.label)
                    .map(|i| i.value),
            )?;
            let label_out = checked_sum(
                self.outputs
                    .iter()
                    .filter(|o| o.label == out.label)
                    .map(|o| o.value),
            )?;
            if label_out > label_in {
                return Err(Error::Input(format!(
                    "outputs take {label_out} from a label whose inputs hold {label_in}"
                )));
            }
        }
        Ok(())
    }
}

impl CircuitInputs for TransactInputs {
    fn circuit(&self) -> Circuit {
        Circuit::Transact {
            inputs: self.inputs.len().min(u8::MAX as usize) as u8,
            outputs: self.outputs.len().min(u8::MAX as usize) as u8,
        }
    }

    fn validate(&self) -> Result<()> {
        let range = 1..=MAX_TRANSACT_NOTES as usize;
        if !range.contains(&self.inputs.len()) || !range.contains(&self.outputs.len()) {
            return Err(Error::Input(format!(
                "transact needs 1..={MAX_TRANSACT_NOTES} inputs and outputs, got {}x{}",
                self.inputs.len(),
                self.outputs.len()
            )));
        }
        let expected_out = if self.amount_out == 0 {
            Address([0; 20])
        } else {
            self.token
        };
        if self.token_out != expected_out {
            return Err(Error::Input(
                "token_out must be the token when withdrawing and zero otherwise".into(),
            ));
        }
        let keystore_leaf = note::keystore_leaf(
            self.owner,
            note::nullifying_key_hash(self.nullifying_key)?,
            note::auth_digest(self.revocable_key)?,
        )?;
        check_proof(
            &self.keystore_proof,
            keystore_leaf,
            self.keystore_root,
            KEYSTORE_MAX_DEPTH,
            "keystore",
        )?;
        for input in &self.inputs {
            let leaf = note::commitment_leaf(self.input_commitment(input)?, input.timestamp)?;
            check_proof(
                &input.state_proof,
                leaf,
                self.state_root,
                STATE_MAX_DEPTH,
                "state",
            )?;
            let asp = note::asp_leaf(input.label)?;
            check_proof(
                &input.asp_proof,
                asp,
                self.asp_root,
                ASP_MAX_DEPTH,
                "association set",
            )?;
        }
        self.check_values()
    }

    /// `[nullifierHashes(N), outputCommitments(M), stateRoot, keystoreRoot,
    /// associationSetRoot, amountOut, tokenIdOut, context]`.
    fn public_signals(&self) -> Result<Vec<Field>> {
        let mut signals = Vec::with_capacity(self.inputs.len() + self.outputs.len() + 6);
        for input in &self.inputs {
            signals.push(note::nullifier_hash(
                self.nullifying_key,
                self.input_commitment(input)?,
            )?);
        }
        for out in &self.outputs {
            signals.push(out.commitment(self.token)?);
        }
        signals.extend([
            self.state_root,
            self.keystore_root,
            self.asp_root,
            self.amount_out.into(),
            self.token_out.to_field(),
            self.context,
        ]);
        Ok(signals)
    }

    fn to_input_value(&self) -> Result<Value> {
        let each = |f: &dyn Fn(&TransactInput) -> Result<Value>| {
            self.inputs.iter().map(f).collect::<Result<Vec<_>>>()
        };
        Ok(json!({
            "stateRoot": self.state_root,
            "keystoreRoot": self.keystore_root,
            "associationSetRoot": self.asp_root,
            "amountOut": Field::from(self.amount_out),
            "tokenIdOut": self.token_out.to_field(),
            "context": self.context,
            "ownerAddress": self.owner.to_field(),
            "privateNullifyingKey": self.nullifying_key,
            "privateRevocableKey": self.revocable_key,
            "keystoreLeafIndex": Field::from(self.keystore_proof.index),
            "keystoreSiblings": padded::<KEYSTORE_MAX_DEPTH>(&self.keystore_proof)?,
            "keystoreTreeDepth": depth(&self.keystore_proof),
            "noteSecret": each(&|i| Ok(json!(i.note_secret)))?,
            "value": each(&|i| Ok(json!(Field::from(i.value))))?,
            "tokenId": self.token.to_field(),
            "label": each(&|i| Ok(json!(i.label)))?,
            "stateLeafIndex": each(&|i| Ok(json!(Field::from(i.state_proof.index))))?,
            "stateSiblings": each(&|i| Ok(json!(padded::<STATE_MAX_DEPTH>(&i.state_proof)?)))?,
            "stateTreeDepth": each(&|i| Ok(json!(depth(&i.state_proof))))?,
            "associationSetLeafIndex": each(&|i| Ok(json!(Field::from(i.asp_proof.index))))?,
            "associationSetSiblings": each(&|i| Ok(json!(padded::<ASP_MAX_DEPTH>(&i.asp_proof)?)))?,
            "associationSetTreeDepth": each(&|i| Ok(json!(depth(&i.asp_proof))))?,
            "timestamp": each(&|i| Ok(json!(Field::from(i.timestamp))))?,
            "outputNoteAddressHash": self.outputs.iter().map(|o| o.note_address_hash).collect::<Vec<_>>(),
            "outputValue": self.outputs.iter().map(|o| Field::from(o.value)).collect::<Vec<_>>(),
            "outputLabel": self.outputs.iter().map(|o| o.label).collect::<Vec<_>>(),
        }))
    }
}

// --- helpers -------------------------------------------------------------------

fn checked_sum(mut values: impl Iterator<Item = u128>) -> Result<u128> {
    values
        .try_fold(0u128, u128::checked_add)
        .ok_or_else(|| Error::Input("note values overflow 2^128".into()))
}

/// `P(noteAddressHash, tokenId, value, metadata)` with explicit metadata
/// (ragequit takes it as an input).
fn poseidon_precommitment(
    nah: Field,
    token: Address,
    value: u128,
    metadata: Field,
) -> Result<Field> {
    crate::poseidon::poseidon(&[nah, token.to_field(), value.into(), metadata])
}

/// A proof for the first occurrence of `leaf` in `tree` (the SDK's `indexOf`).
fn prove_leaf(tree: &LeanImt, leaf: Field, what: &str) -> Result<MerkleProof> {
    let position = tree
        .leaves()
        .iter()
        .position(|&l| l == leaf)
        .ok_or_else(|| Error::Input(format!("leaf not found in the {what} tree")))?;
    tree.generate_proof(position)
}

fn tree_root(tree: &LeanImt) -> Result<Field> {
    tree.root()
        .ok_or_else(|| Error::Input("empty tree has no root".into()))
}

/// `proof` proves `leaf` under `root` within the circuit's `max_depth`.
fn check_proof(
    proof: &MerkleProof,
    leaf: Field,
    root: Field,
    max_depth: usize,
    what: &str,
) -> Result<()> {
    if proof.siblings.len() > max_depth || proof.index >> max_depth != 0 {
        return Err(Error::Input(format!(
            "{what} proof exceeds the circuit's depth {max_depth}"
        )));
    }
    if proof.leaf != leaf || binary_merkle_root(leaf, proof.index, &proof.siblings)? != root {
        return Err(Error::Input(format!(
            "{what} proof does not prove the expected leaf"
        )));
    }
    Ok(())
}

/// The siblings zero-padded to `D` (the circuit's fixed array length).
fn padded<const D: usize>(proof: &MerkleProof) -> Result<Vec<Field>> {
    if proof.siblings.len() > D {
        return Err(Error::Input(format!(
            "{} siblings exceed the circuit's depth {D}",
            proof.siblings.len()
        )));
    }
    let mut siblings = proof.siblings.clone();
    siblings.resize(D, Field::ZERO);
    Ok(siblings)
}

fn depth(proof: &MerkleProof) -> Field {
    Field::from(proof.siblings.len() as u64)
}
