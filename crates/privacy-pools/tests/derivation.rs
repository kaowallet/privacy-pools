//! Validate the input-derivation helpers against the real circuits:
//!   * Poseidon/commitment outputs vs the values the `commitment` circuit emits.
//!   * LeanIMT root recomputation vs the `withdraw` circuit's state/ASP roots.

use privacy_pools::{
    commitment_hash, compute_root, nullifier_hash, verify_inclusion, Commitment, Field,
};
use serde_json::Value;

fn fdec(s: &str) -> Field {
    Field::from_decimal(s).unwrap()
}

#[test]
fn commitment_and_nullifier_match_circuit_outputs() {
    // From the `commitment` circuit run on value=12, label=2^256-1, nullifier=56,
    // secret=78 (see examples/prove.rs output, which is the circuit's own result).
    let label =
        fdec("115792089237316195423570985008687907853269984665640564039457584007913129639935");

    let nh = nullifier_hash(Field::from(56u64)).unwrap();
    assert_eq!(
        nh.to_decimal(),
        "6275082065951062693025191952844771393149331252390508022719638233339590493096"
    );

    let c = commitment_hash(
        Field::from(12u64),
        label,
        Field::from(56u64),
        Field::from(78u64),
    )
    .unwrap();
    assert_eq!(
        c.to_decimal(),
        "14908830324296103267270395035016969945175328767936610816837620276441541757060"
    );

    // Same via the Commitment struct.
    let note = Commitment::new(
        Field::from(12u64),
        label,
        Field::from(56u64),
        Field::from(78u64),
    );
    assert_eq!(note.hash().unwrap(), c);
    assert_eq!(note.nullifier_hash().unwrap(), nh);
}

const WITHDRAW: &str = include_str!("fixtures/withdraw_default.json");

fn siblings_of(v: &Value, key: &str) -> Vec<Field> {
    v[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| fdec(x.as_str().unwrap()))
        .collect()
}

#[test]
fn leanimt_root_matches_withdraw_state_and_asp_roots() {
    let v: Value = serde_json::from_str(WITHDRAW).unwrap();

    // State tree: the leaf is the existing commitment.
    let existing = Commitment::new(
        fdec(v["existingValue"].as_str().unwrap()),
        fdec(v["label"].as_str().unwrap()),
        fdec(v["existingNullifier"].as_str().unwrap()),
        fdec(v["existingSecret"].as_str().unwrap()),
    )
    .hash()
    .unwrap();
    let state_index: u64 = v["stateIndex"].as_str().unwrap().parse().unwrap();
    let state_root = fdec(v["stateRoot"].as_str().unwrap());
    assert_eq!(
        compute_root(existing, state_index, &siblings_of(&v, "stateSiblings")).unwrap(),
        state_root
    );
    assert!(verify_inclusion(
        state_root,
        existing,
        state_index,
        &siblings_of(&v, "stateSiblings")
    )
    .unwrap());

    // ASP tree: the leaf is the label itself.
    let label = fdec(v["label"].as_str().unwrap());
    let asp_index: u64 = v["ASPIndex"].as_str().unwrap().parse().unwrap();
    let asp_root = fdec(v["ASPRoot"].as_str().unwrap());
    assert_eq!(
        compute_root(label, asp_index, &siblings_of(&v, "ASPSiblings")).unwrap(),
        asp_root
    );
}
