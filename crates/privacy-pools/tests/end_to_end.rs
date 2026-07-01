//! The full integration loop a wallet performs: derive everything with the
//! helper layer, then prove + verify with the bundled artifacts. Nothing here
//! touches a fixture — it's all built from raw user/protocol data.

use privacy_pools::{
    label, scope, Address, Commitment, Field, LeanImt, WithdrawInputs, WithdrawProver,
    WithdrawVerifier, Withdrawal,
};

#[test]
fn build_inputs_from_scratch_then_prove_and_verify() {
    // --- protocol params the wallet knows ---
    let pool = Address::from_bytes([0xab; 20]);
    let asset = Address::from_bytes([0xcd; 20]);
    let chain_id = 1u64;
    let scope = scope(pool, chain_id, asset);
    let deposit_nonce = 1u64;
    let label = label(scope, deposit_nonce);

    // --- the user's existing note (from a prior deposit) ---
    let existing = Commitment::new(
        Field::from(100u64), // existingValue
        label,
        Field::from(12_345u64), // existingNullifier
        Field::from(67_890u64), // existingSecret
    );
    let existing_leaf = existing.hash().unwrap();

    // --- state tree: other pool commitments + ours ---
    let state = LeanImt::from_leaves(&[
        Field::from(1u64),
        Field::from(2u64),
        existing_leaf, // our note at index 2
        Field::from(4u64),
        Field::from(5u64),
    ])
    .unwrap();
    let state_proof = state.generate_proof(2).unwrap();

    // --- ASP tree: approved labels, including ours ---
    let asp = LeanImt::from_leaves(&[Field::from(7u64), label, Field::from(9u64)]).unwrap();
    let asp_proof = asp.generate_proof(1).unwrap();

    // --- the withdrawal ---
    let withdrawal = Withdrawal::new(pool, vec![0xde, 0xad, 0xbe, 0xef]);
    let context = withdrawal.context(scope);

    let inputs = WithdrawInputs {
        withdrawn_value: Field::from(30u64), // <= existingValue (remaining 70)
        state_root: state.root().unwrap(),
        state_tree_depth: Field::from(state.depth() as u64),
        asp_root: asp.root().unwrap(),
        asp_tree_depth: Field::from(asp.depth() as u64),
        context,
        label,
        existing_value: Field::from(100u64),
        existing_nullifier: Field::from(12_345u64),
        existing_secret: Field::from(67_890u64),
        new_nullifier: Field::from(11_111u64), // != existing nullifier
        new_secret: Field::from(22_222u64),
        state_siblings: state_proof.padded_siblings().unwrap(),
        state_index: Field::from(state_proof.index),
        asp_siblings: asp_proof.padded_siblings().unwrap(),
        asp_index: Field::from(asp_proof.index),
    };

    let prover = WithdrawProver::bundled().unwrap();
    let proof = prover
        .prove(&inputs)
        .expect("circuit accepts the derived inputs");

    assert!(prover.verify(&proof).unwrap());
    assert!(WithdrawVerifier::bundled().unwrap().verify(&proof).unwrap());

    // The circuit's public outputs are derivable independently:
    //   public[1] = existingNullifierHash = Poseidon([existingNullifier])
    assert_eq!(
        proof.public_signals_decimal()[1],
        existing.nullifier_hash().unwrap().to_decimal()
    );
    //   public[3] = stateRoot we supplied
    assert_eq!(
        proof.public_signals_decimal()[3],
        state.root().unwrap().to_decimal()
    );
}
