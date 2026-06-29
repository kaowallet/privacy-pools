//! End-to-end wallet flow: assemble a withdrawal from an account + note + state
//! proof + ASP proof via the `flow` API, then prove it with the bundled prover
//! and verify. No chain needed (synthetic state/ASP trees).
#![cfg(all(feature = "wallet", feature = "bundled"))]

use privacy_pools::alloy::primitives::{address, U256};
use privacy_pools::{
    build_withdrawal, native_deposit, ragequit_inputs, relay_calldata, Account, Commitment,
    CommitmentProver, CommitmentVerifier, Destination, Field, LeanImt, WithdrawProver,
    WithdrawVerifier,
};

const MNEMONIC: &str = "test test test test test test test test test test test junk";

/// A tree holding `leaf` at a chosen position among filler leaves, with the
/// membership proof for it.
fn tree_with(leaf: Field, others: usize, pos: usize, offset: u64) -> privacy_pools::MerkleProof {
    let mut leaves: Vec<Field> = (0..others as u64).map(|i| Field::from(1000 + offset + i)).collect();
    let pos = pos.min(leaves.len());
    leaves.insert(pos, leaf);
    LeanImt::from_leaves(&leaves).unwrap().generate_proof(pos).unwrap()
}

#[test]
fn relayed_withdrawal_flow_proves_and_verifies() {
    let account = Account::from_mnemonic(MNEMONIC).unwrap();
    let scope = Field::from(12345u64);
    let label = Field::from(0xabcu64);
    let value = 1_000_000u64;

    // The spendable deposit note.
    let (nullifier, secret) = account.deposit_secrets(scope, 0).unwrap();
    let note = Commitment::new(Field::from(value), label, nullifier, secret);

    // State proof (commitment in the state tree) + ASP proof (label in the ASP tree).
    let state_proof = tree_with(note.hash().unwrap(), 6, 3, 0);
    let asp_proof = tree_with(label, 4, 1, 5000);

    let dest = Destination::Relayed {
        entrypoint: address!("1111111111111111111111111111111111111111"),
        recipient: address!("2222222222222222222222222222222222222222"),
        fee_recipient: address!("3333333333333333333333333333333333333333"),
        relay_fee_bps: U256::from(250),
    };

    let plan = build_withdrawal(
        &account,
        scope,
        &note,
        0,
        U256::from(400_000),
        &state_proof,
        &asp_proof,
        &dest,
    )
    .unwrap();

    // The change note holds the remainder.
    assert_eq!(plan.new_note.value, Field::from(600_000u64));

    // The assembled inputs prove + verify against the real circuit.
    let prover = WithdrawProver::bundled().unwrap();
    let proof = prover.prove(&plan.inputs).unwrap();
    assert!(WithdrawVerifier::bundled().unwrap().verify(&proof).unwrap());

    // The context bound into the proof matches the plan's context (signal 7).
    let sigs = proof.public_signals_decimal();
    assert_eq!(sigs[7], plan.context.to_decimal());
    // ...and the new commitment (signal 0) is the change note.
    assert_eq!(sigs[0], plan.new_note.hash().unwrap().to_decimal());

    // Relay calldata is built from the same Withdrawal struct.
    let calldata = relay_calldata(&plan.withdrawal, &proof, scope).unwrap();
    assert_eq!(&calldata[..4], &[0x8a, 0x44, 0x12, 0x1e]); // relay(...) selector
}

#[test]
fn deposit_helper_matches_account_precommitment() {
    let account = Account::from_mnemonic(MNEMONIC).unwrap();
    let scope = Field::from(99u64);
    let (pre, calldata) = native_deposit(&account, scope, 3).unwrap();
    assert_eq!(pre, account.deposit_precommitment(scope, 3).unwrap());
    assert_eq!(&calldata[..4], &[0xb6, 0xb5, 0x5f, 0x25]); // deposit(uint256)
}

#[test]
fn ragequit_flow_proves_with_commitment_circuit() {
    let account = Account::from_mnemonic(MNEMONIC).unwrap();
    let scope = Field::from(77u64);
    let (nullifier, secret) = account.deposit_secrets(scope, 0).unwrap();
    let note = Commitment::new(Field::from(42u64), Field::from(7u64), nullifier, secret);

    let inputs = ragequit_inputs(&note);
    let proof = CommitmentProver::bundled().unwrap().prove(&inputs).unwrap();
    assert!(CommitmentVerifier::bundled().unwrap().verify(&proof).unwrap());

    // Public signal 0 is the commitment hash being exited.
    assert_eq!(
        proof.public_signals_decimal()[0],
        note.hash().unwrap().to_decimal()
    );
}
