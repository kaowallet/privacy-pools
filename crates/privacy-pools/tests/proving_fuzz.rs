//! Proving-path fuzz: generate *valid* random withdrawals end-to-end, prove
//! them, and assert (a) the proof verifies, (b) the public signals equal the
//! values our derivation helpers compute independently, and (c) flipping any
//! public signal fails verification.
//!
//! This cross-checks the whole witness + Groth16 pipeline against the
//! derivation helpers across many random inputs — the other proving tests only
//! pin a single upstream fixture, so a regression in witness generation that
//! still produced *a* valid proof (wrong signal order, off-by-one wire, …)
//! could slip past them. Here the helpers are the oracle for what the circuit
//! must output.
//!
//! Constraints a valid `Withdraw(32)` witness must satisfy (see
//! `withdraw.circom`): `withdrawnValue < 2^128`, `remainingValue =
//! existingValue - withdrawnValue ∈ [0, 2^128)` (so `withdrawnValue ≤
//! existingValue`), `existingNullifier ≠ newNullifier`, `existingCommitment` in
//! the state tree, and `label` in the ASP tree.
//!
//! Default is a handful of cases so it stays in `cargo test`. Run a deeper
//! campaign with e.g. `PROPTEST_CASES=512 cargo test --release --test
//! proving_fuzz` (proptest honours `$PROPTEST_CASES`).

use std::sync::OnceLock;

use privacy_pools::{
    commitment_hash, nullifier_hash, siblings, Field, LeanImt, WithdrawInputs, WithdrawProver,
    WithdrawVerifier,
};
use proptest::prelude::*;

// The 17 MB zkey / vkey are parsed once and shared across every case.
fn prover() -> &'static WithdrawProver {
    static P: OnceLock<WithdrawProver> = OnceLock::new();
    P.get_or_init(|| WithdrawProver::bundled().expect("load withdraw prover"))
}
fn verifier() -> &'static WithdrawVerifier {
    static V: OnceLock<WithdrawVerifier> = OnceLock::new();
    V.get_or_init(|| WithdrawVerifier::bundled().expect("load withdraw verifier"))
}

/// The eight public signals the circuit must output, in order.
type Expected = [String; 8];

/// Build a valid `WithdrawInputs` and the public signals it must produce, from
/// concrete values. Requires `withdrawn_value <= existing_value`.
#[allow(clippy::too_many_arguments)]
fn build_valid_withdraw(
    existing_value: u128,
    withdrawn_value: u128,
    label: Field,
    e_null: Field,
    e_sec: Field,
    n_null: Field,
    n_sec: Field,
    context: Field,
    state_others: &[Field],
    state_pos: usize,
    asp_others: &[Field],
    asp_pos: usize,
) -> (WithdrawInputs, Expected) {
    assert!(withdrawn_value <= existing_value);
    let remaining = existing_value - withdrawn_value;

    // State tree: the existing commitment sits at `state_idx` among fillers.
    let existing_commitment =
        commitment_hash(Field::from(existing_value), label, e_null, e_sec).unwrap();
    let state_idx = state_pos % (state_others.len() + 1);
    let mut state_leaves = state_others.to_vec();
    state_leaves.insert(state_idx, existing_commitment);
    let state_tree = LeanImt::from_leaves(&state_leaves).unwrap();
    let state_proof = state_tree.generate_proof(state_idx).unwrap();

    // ASP tree: the label sits at `asp_idx` among fillers.
    let asp_idx = asp_pos % (asp_others.len() + 1);
    let mut asp_leaves = asp_others.to_vec();
    asp_leaves.insert(asp_idx, label);
    let asp_tree = LeanImt::from_leaves(&asp_leaves).unwrap();
    let asp_proof = asp_tree.generate_proof(asp_idx).unwrap();

    let state_root = state_tree.root().unwrap();
    let asp_root = asp_tree.root().unwrap();
    let state_depth = Field::from(state_proof.depth() as u64);
    let asp_depth = Field::from(asp_proof.depth() as u64);

    let inputs = WithdrawInputs {
        withdrawn_value: Field::from(withdrawn_value),
        state_root,
        state_tree_depth: state_depth,
        asp_root,
        asp_tree_depth: asp_depth,
        context,
        label,
        existing_value: Field::from(existing_value),
        existing_nullifier: e_null,
        existing_secret: e_sec,
        new_nullifier: n_null,
        new_secret: n_sec,
        state_siblings: siblings(&state_proof.siblings).unwrap(),
        state_index: Field::from(state_proof.index),
        asp_siblings: siblings(&asp_proof.siblings).unwrap(),
        asp_index: Field::from(asp_proof.index),
    };

    let new_commitment = commitment_hash(Field::from(remaining), label, n_null, n_sec).unwrap();
    let expected: Expected = [
        new_commitment.to_decimal(),               // newCommitmentHash
        nullifier_hash(e_null).unwrap().to_decimal(), // existingNullifierHash
        Field::from(withdrawn_value).to_decimal(), // withdrawnValue
        state_root.to_decimal(),                   // stateRoot
        state_depth.to_decimal(),                  // stateTreeDepth
        asp_root.to_decimal(),                     // ASPRoot
        asp_depth.to_decimal(),                    // ASPTreeDepth
        context.to_decimal(),                      // context
    ];
    (inputs, expected)
}

/// Prove the inputs, verify, check the public signals, and confirm a tampered
/// signal is rejected.
fn prove_and_check(inputs: &WithdrawInputs, expected: &Expected) {
    let proof = prover().prove(inputs).expect("prove valid withdrawal");
    assert!(verifier().verify(&proof).expect("verify"), "valid proof rejected");
    assert_eq!(
        proof.public_signals_decimal().as_slice(),
        expected.as_slice(),
        "public signals disagree with the derivation helpers"
    );

    let mut tampered = proof.clone();
    tampered.public_signals[0] += Field::from(1u64).into_fr();
    assert!(
        !verifier().verify(&tampered).unwrap(),
        "tampered proof verified"
    );
}

/// `n` distinct nonzero filler leaves (offset keeps state/ASP fillers disjoint).
fn fillers(n: usize, offset: u64) -> Vec<Field> {
    (0..n as u64).map(|i| Field::from(1 + offset + i)).collect()
}

fn field_strat() -> impl Strategy<Value = Field> {
    prop::array::uniform32(any::<u8>()).prop_map(|b| Field::from_bytes_be(&b))
}

proptest! {
    // Few cases by default (each is a full Groth16 proof); override with
    // $PROPTEST_CASES for a real campaign. Shrinking a proving failure would
    // re-prove repeatedly for little benefit, so it's disabled.
    #![proptest_config(ProptestConfig { cases: 12, max_shrink_iters: 0, ..ProptestConfig::default() })]

    #[test]
    fn random_valid_withdrawals_prove_and_verify(
        existing_value in any::<u128>(),
        w_pick in any::<u128>(),
        label in field_strat(),
        e_null in field_strat(),
        e_sec in field_strat(),
        n_null in field_strat(),
        n_sec in field_strat(),
        context in field_strat(),
        state_others in prop::collection::vec(field_strat(), 0..20),
        state_pos in any::<usize>(),
        asp_others in prop::collection::vec(field_strat(), 0..20),
        asp_pos in any::<usize>(),
    ) {
        prop_assume!(n_null != e_null); // circuit forbids reusing the nullifier
        // withdrawn_value uniform in [0, existing_value] (no field underflow).
        let withdrawn_value = match existing_value.checked_add(1) {
            Some(m) => w_pick % m,
            None => w_pick, // existing_value == u128::MAX: any u128 is <= it
        };
        let (inputs, expected) = build_valid_withdraw(
            existing_value, withdrawn_value, label, e_null, e_sec, n_null, n_sec,
            context, &state_others, state_pos, &asp_others, asp_pos,
        );
        prove_and_check(&inputs, &expected);
    }
}

/// Boundary values the random run is unlikely to hit: zero / full withdrawal,
/// `2^128 - 1` values, and the exact tree shapes that drive LeanIMT's
/// single-child promotion and depth growth.
#[test]
fn withdraw_value_and_tree_edge_cases() {
    let label = Field::from(0x1234_5678u64);
    let (e_null, e_sec, n_null, n_sec, ctx) = (
        Field::from(111u64),
        Field::from(222u64),
        Field::from(333u64),
        Field::from(444u64),
        Field::from(555u64),
    );
    let max = u128::MAX;

    // (existingValue, withdrawnValue): zero, full, and 128-bit extremes.
    let value_cases: [(u128, u128); 6] = [
        (1_000, 0),     // withdraw nothing  -> remaining == existing
        (1_000, 1_000), // withdraw all      -> remaining == 0
        (max, max),     // max value, full withdraw
        (max, 1),       // max value, tiny withdraw
        (max, max - 1), // max value, remaining == 1
        (0, 0),         // zero-value commitment
    ];
    for (ev, wv) in value_cases {
        let (inputs, expected) = build_valid_withdraw(
            ev, wv, label, e_null, e_sec, n_null, n_sec, ctx,
            &fillers(3, 0), 1, &fillers(3, 100), 1,
        );
        prove_and_check(&inputs, &expected);
    }

    // Tree shapes — (#state fillers, state pos, #asp fillers, asp pos). `pos ==
    // len` puts the target leaf last; with an even `len` that makes it the
    // promoted single child. Covers size 1, the 3-leaf promotion, and the
    // 16/17/32-leaf depth boundaries on both sides of the path.
    let shape_cases: [(usize, usize, usize, usize); 6] = [
        (0, 0, 0, 0),     // single-leaf trees (depth 0)
        (2, 2, 2, 2),     // size 3, target is the promoted leaf
        (15, 15, 7, 0),   // size 16 (full depth 4), target last vs target first
        (16, 16, 16, 16), // size 17 (depth 5), target is the lone promoted top leaf
        (31, 0, 31, 31),  // size 32, target first vs target last
        (40, 13, 5, 5),   // odd interior position in a deeper tree
    ];
    for (sn, sp, an, ap) in shape_cases {
        let (inputs, expected) = build_valid_withdraw(
            7_000_000, 3_000_000, label, e_null, e_sec, n_null, n_sec, ctx,
            &fillers(sn, 0), sp, &fillers(an, 100), ap,
        );
        prove_and_check(&inputs, &expected);
    }
}
