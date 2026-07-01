//! High-level wallet flows — the plug-and-play layer that ties the account,
//! state tree, ASP proof, and proving inputs together.
//!
//! These are pure (no chain I/O): the wallet fetches/syncs with its provider
//! (see [`crate::sync`]), then calls these to assemble a deposit's calldata or a
//! withdrawal's [`WithdrawInputs`] + [`Withdrawal`] struct, proves with the
//! bundled prover (off the UI thread), and submits the resulting calldata.

use alloy::primitives::{Address, Bytes, U256};

use crate::account::Account;
use crate::commitment::Commitment;
use crate::context::context;
use crate::error::{Error, Result};
use crate::field::Field;
use crate::inputs::{siblings, CommitmentInputs, WithdrawInputs};
use crate::onchain::{
    deposit_erc20_calldata, deposit_native_calldata, direct_withdrawal, field_to_u256,
    from_alloy_address, relayed_withdrawal, u256_to_field, Withdrawal,
};
use crate::tree::MerkleProof;

// --- deposits -------------------------------------------------------------

/// Precommitment + calldata for a native (ETH) deposit at `index` in `scope`.
/// The wallet sends the tx with `value` set to the deposit amount.
pub fn native_deposit(account: &Account, scope: Field, index: u64) -> Result<(Field, Bytes)> {
    let pre = account.deposit_precommitment(scope, index)?;
    Ok((pre, deposit_native_calldata(pre)))
}

/// Precommitment + calldata for an ERC20 deposit (after a prior `approve`).
pub fn erc20_deposit(
    account: &Account,
    scope: Field,
    index: u64,
    asset: Address,
    value: U256,
) -> Result<(Field, Bytes)> {
    let pre = account.deposit_precommitment(scope, index)?;
    Ok((pre, deposit_erc20_calldata(asset, value, pre)))
}

// --- withdrawals ----------------------------------------------------------

/// Where a withdrawal's funds go.
#[derive(Clone, Copy, Debug)]
pub enum Destination {
    /// Relayed through the Entrypoint: `recipient` gets the funds net of the
    /// relay fee, `fee_recipient` gets the fee (`relay_fee_bps` basis points).
    Relayed {
        entrypoint: Address,
        recipient: Address,
        fee_recipient: Address,
        relay_fee_bps: U256,
    },
    /// Direct: `processooor` calls the pool itself and receives the funds.
    Direct { processooor: Address },
}

impl Destination {
    fn withdrawal(&self) -> Withdrawal {
        match *self {
            Destination::Relayed {
                entrypoint,
                recipient,
                fee_recipient,
                relay_fee_bps,
            } => relayed_withdrawal(entrypoint, recipient, fee_recipient, relay_fee_bps),
            Destination::Direct { processooor } => direct_withdrawal(processooor),
        }
    }
}

/// Everything needed to prove + submit a withdrawal.
#[derive(Clone, Debug)]
pub struct WithdrawalPlan {
    /// Circuit inputs — feed to `WithdrawProver::prove`.
    pub inputs: WithdrawInputs,
    /// The withdrawal context bound into the proof.
    pub context: Field,
    /// The `Withdrawal` struct for the `withdraw`/`relay` calldata.
    pub withdrawal: Withdrawal,
    /// The change note to persist (the new commitment the proof creates).
    pub new_note: Commitment,
}

/// Assemble a [`WithdrawalPlan`] from a spendable `note`, its state-tree
/// membership proof, and an ASP membership proof for its label.
///
/// `state_proof` proves `note.hash()` is in the state tree; `asp_proof` proves
/// `note.label` is in the ASP tree (the wallet fetches the ASP leaves and
/// builds this — see [`crate::LeanImt`]). `child_index` is the next change index
/// for this account (e.g. `pool_account.children.len()`).
#[allow(clippy::too_many_arguments)]
pub fn build_withdrawal(
    account: &Account,
    scope: Field,
    note: &Commitment,
    child_index: u64,
    withdrawn_value: U256,
    state_proof: &MerkleProof,
    asp_proof: &MerkleProof,
    dest: &Destination,
) -> Result<WithdrawalPlan> {
    // The proofs must be for this note.
    if state_proof.leaf != note.hash()? {
        return Err(Error::Input(
            "state_proof is not for this note's commitment".into(),
        ));
    }
    if asp_proof.leaf != note.label {
        return Err(Error::Input(
            "asp_proof is not for this note's label".into(),
        ));
    }

    let remaining = field_to_u256(note.value)
        .checked_sub(withdrawn_value)
        .ok_or_else(|| Error::Input("withdrawn value exceeds the note value".into()))?;

    let (new_nullifier, new_secret) = account.withdrawal_secrets(note.label, child_index)?;
    let new_note = Commitment::new(
        u256_to_field(remaining),
        note.label,
        new_nullifier,
        new_secret,
    );

    // Bind the withdrawal (processooor + data) and scope into the context.
    let withdrawal = dest.withdrawal();
    let context = context(
        from_alloy_address(withdrawal.processooor),
        &withdrawal.data,
        scope,
    );

    let inputs = WithdrawInputs {
        withdrawn_value: u256_to_field(withdrawn_value),
        state_root: state_proof.root,
        state_tree_depth: Field::from(state_proof.depth() as u64),
        asp_root: asp_proof.root,
        asp_tree_depth: Field::from(asp_proof.depth() as u64),
        context,
        label: note.label,
        existing_value: note.value,
        existing_nullifier: note.nullifier,
        existing_secret: note.secret,
        new_nullifier,
        new_secret,
        state_siblings: siblings(&state_proof.siblings)?,
        state_index: Field::from(state_proof.index),
        asp_siblings: siblings(&asp_proof.siblings)?,
        asp_index: Field::from(asp_proof.index),
    };

    Ok(WithdrawalPlan {
        inputs,
        context,
        withdrawal,
        new_note,
    })
}

// --- ragequit -------------------------------------------------------------

/// Commitment-circuit inputs to ragequit (exit) a `note` — prove with
/// `CommitmentProver`, then `ragequit_calldata(&proof)`.
pub fn ragequit_inputs(note: &Commitment) -> CommitmentInputs {
    CommitmentInputs {
        value: note.value,
        label: note.label,
        nullifier: note.nullifier,
        secret: note.secret,
    }
}
