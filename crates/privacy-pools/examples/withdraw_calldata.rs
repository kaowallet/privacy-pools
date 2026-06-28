//! Build a valid withdrawal proof from scratch and print its Solidity
//! `verifyProof` calldata as JSON — for the anvil on-chain verification check.
//!
//!   cargo run --release --example withdraw_calldata

use privacy_pools::{
    label, scope, Address, Commitment, Field, LeanImt, WithdrawInputs, WithdrawProver, Withdrawal,
};

fn main() -> Result<(), privacy_pools::Error> {
    let pool = Address::from_bytes([0xab; 20]);
    let asset = Address::from_bytes([0xcd; 20]);
    let scope = scope(pool, 1, asset);
    let label = label(scope, 1);

    let existing = Commitment::new(
        Field::from(100u64),
        label,
        Field::from(12_345u64),
        Field::from(67_890u64),
    );
    let state = LeanImt::from_leaves(&[
        Field::from(1u64),
        Field::from(2u64),
        existing.hash()?,
        Field::from(4u64),
        Field::from(5u64),
    ])?;
    let state_proof = state.generate_proof(2)?;
    let asp = LeanImt::from_leaves(&[Field::from(7u64), label, Field::from(9u64)])?;
    let asp_proof = asp.generate_proof(1)?;
    let context = Withdrawal::new(pool, vec![0xde, 0xad, 0xbe, 0xef]).context(scope);

    let inputs = WithdrawInputs {
        withdrawn_value: Field::from(30u64),
        state_root: state.root().unwrap(),
        state_tree_depth: Field::from(state.depth() as u64),
        asp_root: asp.root().unwrap(),
        asp_tree_depth: Field::from(asp.depth() as u64),
        context,
        label,
        existing_value: Field::from(100u64),
        existing_nullifier: Field::from(12_345u64),
        existing_secret: Field::from(67_890u64),
        new_nullifier: Field::from(11_111u64),
        new_secret: Field::from(22_222u64),
        state_siblings: state_proof.padded_siblings()?,
        state_index: Field::from(state_proof.index),
        asp_siblings: asp_proof.padded_siblings()?,
        asp_index: Field::from(asp_proof.index),
    };

    let proof = WithdrawProver::bundled()?.prove(&inputs)?;
    // self-check before we hand it to the chain
    assert!(WithdrawProver::bundled()?.verify(&proof)?);

    let cd = proof.to_solidity_calldata();
    println!(
        "{}",
        serde_json::json!({
            "a": cd.a,
            "b": cd.b,
            "c": cd.c,
            "pub": cd.public_signals,
        })
    );
    Ok(())
}
