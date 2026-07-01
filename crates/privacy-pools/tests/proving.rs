//! End-to-end: bundled artifacts → witness → Groth16 proof → verify.
//!
//! Uses the upstream example inputs (privacy-pools-core
//! `packages/circuits/inputs/{withdraw,commitment}/default.json`).

use privacy_pools::{
    siblings, CommitmentInputs, CommitmentProver, CommitmentVerifier, Field, WithdrawInputs,
    WithdrawProver, WithdrawVerifier,
};
use serde_json::Value;

const WITHDRAW_JSON: &str = include_str!("fixtures/withdraw_default.json");
const COMMITMENT_JSON: &str = include_str!("fixtures/commitment_default.json");

fn fdec(v: &Value, key: &str) -> Field {
    Field::from_decimal(v[key].as_str().expect("string field")).expect("valid field")
}

fn fsiblings(v: &Value, key: &str) -> [Field; privacy_pools::MAX_TREE_DEPTH] {
    let arr: Vec<Field> = v[key]
        .as_array()
        .expect("array")
        .iter()
        .map(|x| Field::from_decimal(x.as_str().unwrap()).unwrap())
        .collect();
    siblings(&arr).expect("<= MAX_TREE_DEPTH siblings")
}

/// Build the typed `WithdrawInputs` from the fixture — this also exercises that
/// every `#[serde(rename)]` matches a real circuit signal (a wrong name would
/// make witness generation fail).
fn withdraw_inputs() -> WithdrawInputs {
    let v: Value = serde_json::from_str(WITHDRAW_JSON).unwrap();
    WithdrawInputs {
        withdrawn_value: fdec(&v, "withdrawnValue"),
        state_root: fdec(&v, "stateRoot"),
        state_tree_depth: fdec(&v, "stateTreeDepth"),
        asp_root: fdec(&v, "ASPRoot"),
        asp_tree_depth: fdec(&v, "ASPTreeDepth"),
        context: fdec(&v, "context"),
        label: fdec(&v, "label"),
        existing_value: fdec(&v, "existingValue"),
        existing_nullifier: fdec(&v, "existingNullifier"),
        existing_secret: fdec(&v, "existingSecret"),
        new_nullifier: fdec(&v, "newNullifier"),
        new_secret: fdec(&v, "newSecret"),
        state_siblings: fsiblings(&v, "stateSiblings"),
        state_index: fdec(&v, "stateIndex"),
        asp_siblings: fsiblings(&v, "ASPSiblings"),
        asp_index: fdec(&v, "ASPIndex"),
    }
}

#[test]
fn withdraw_prove_and_verify() {
    let prover = WithdrawProver::bundled().expect("load withdraw prover");
    assert_eq!(prover.engine().num_public(), 8);

    let proof = prover.prove(&withdraw_inputs()).expect("prove withdraw");
    assert_eq!(proof.public_signals.len(), 8);

    // prover-side verification (vk from zkey)
    assert!(prover.verify(&proof).expect("verify via prover"));

    // standalone verifier (vk from the few-KB vkey.json, no zkey)
    let verifier = WithdrawVerifier::bundled().expect("load withdraw verifier");
    assert!(verifier.verify(&proof).expect("verify via vkey"));
}

#[test]
fn withdraw_engine_matches_typed_and_serialization_is_sane() {
    let prover = WithdrawProver::bundled().unwrap();

    // Engine path with the raw upstream JSON must agree on public signals with
    // the typed path.
    let raw = prover.engine().prove(WITHDRAW_JSON).unwrap();
    let typed = prover.prove(&withdraw_inputs()).unwrap();
    assert_eq!(raw.public_signals, typed.public_signals);

    // snarkjs / Solidity serialization shape.
    let json = typed.to_snarkjs_json();
    assert_eq!(json["protocol"], "groth16");
    assert_eq!(json["curve"], "bn128");
    assert_eq!(json["pi_b"].as_array().unwrap().len(), 3);

    let calldata = typed.to_solidity_calldata();
    assert_eq!(calldata.public_signals.len(), 8);
    // G2 limbs are swapped relative to the JSON form.
    assert_eq!(calldata.b[0][0], json["pi_b"][0][1].as_str().unwrap());
    assert_eq!(calldata.b[0][1], json["pi_b"][0][0].as_str().unwrap());
}

#[test]
fn tampered_public_signal_fails_verification() {
    let prover = WithdrawProver::bundled().unwrap();
    let mut proof = prover.prove(&withdraw_inputs()).unwrap();

    proof.public_signals[0] += Field::from(1u64).into_fr();
    assert!(!prover.verify(&proof).unwrap());
}

#[test]
fn withdraw_public_signals_are_stable() {
    // The proof is randomized (r, s) but the public signals are a deterministic
    // function of the inputs. Pinning the computed outputs catches any change in
    // the witness pipeline (graph, optimization level, signal ordering).
    let prover = WithdrawProver::bundled().unwrap();
    let sig = prover
        .prove(&withdraw_inputs())
        .unwrap()
        .public_signals_decimal();
    assert_eq!(
        sig[0], // newCommitmentHash
        "20221811712987028781701257863323289551825415376350293487493338619948341744706"
    );
    assert_eq!(
        sig[1], // existingNullifierHash
        "18039167616040266842480420918192602605750291173853081205310130137735640368215"
    );
    assert_eq!(sig[2], "1000000000000000000"); // withdrawnValue
    assert_eq!(sig[7], "7682233326816519"); // context
}

#[test]
fn withdraw_from_dir_roundtrip() {
    // The runtime-load path (used when the `bundled` feature is off).
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts");
    let prover = WithdrawProver::from_dir(&dir).expect("load prover from dir");
    let proof = prover.prove(&withdraw_inputs()).unwrap();
    assert!(prover.verify(&proof).unwrap());

    let verifier = WithdrawVerifier::from_dir(&dir).expect("load verifier from dir");
    assert!(verifier.verify(&proof).unwrap());
}

#[test]
fn commitment_prove_and_verify() {
    let v: Value = serde_json::from_str(COMMITMENT_JSON).unwrap();
    let inputs = CommitmentInputs {
        value: fdec(&v, "value"),
        label: fdec(&v, "label"),
        nullifier: fdec(&v, "nullifier"),
        secret: fdec(&v, "secret"),
    };

    let prover = CommitmentProver::bundled().expect("load commitment prover");
    assert_eq!(prover.engine().num_public(), 4);

    let proof = prover.prove(&inputs).expect("prove commitment");
    assert_eq!(proof.public_signals.len(), 4);
    assert!(prover.verify(&proof).unwrap());

    // deterministic computed outputs (commitment hash, nullifier hash)
    let sig = proof.public_signals_decimal();
    assert_eq!(
        sig[0],
        "14908830324296103267270395035016969945175328767936610816837620276441541757060"
    );
    assert_eq!(
        sig[1],
        "6275082065951062693025191952844771393149331252390508022719638233339590493096"
    );

    let verifier = CommitmentVerifier::bundled().unwrap();
    assert!(verifier.verify(&proof).unwrap());
}
