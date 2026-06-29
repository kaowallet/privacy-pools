//! On-chain ABI layer: proof->struct conversions, calldata selectors (which pin
//! the deposit-overload mapping), and `Withdrawal.data` encoding.
#![cfg(all(feature = "onchain", feature = "bundled"))]

use privacy_pools::alloy::primitives::{address, U256};
use privacy_pools::alloy::sol_types::{SolCall, SolValue};
use privacy_pools::{
    deposit_erc20_calldata, deposit_native_calldata, field_to_u256, ragequit_proof, relay_data,
    u256_to_field, withdraw_calldata, withdraw_proof, CommitmentInputs, CommitmentProver, Field,
    IEntrypoint, IPrivacyPool, RelayData, WithdrawInputs, WithdrawProver,
};
use serde_json::Value;

const WITHDRAW_JSON: &str = include_str!("fixtures/withdraw_default.json");
const COMMITMENT_JSON: &str = include_str!("fixtures/commitment_default.json");

fn fdec(v: &Value, k: &str) -> Field {
    Field::from_decimal(v[k].as_str().unwrap()).unwrap()
}

fn withdraw_inputs() -> WithdrawInputs {
    let v: Value = serde_json::from_str(WITHDRAW_JSON).unwrap();
    let sibs = |k: &str| {
        let a: Vec<Field> = v[k]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| Field::from_decimal(x.as_str().unwrap()).unwrap())
            .collect();
        privacy_pools::siblings(&a).unwrap()
    };
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
        state_siblings: sibs("stateSiblings"),
        state_index: fdec(&v, "stateIndex"),
        asp_siblings: sibs("ASPSiblings"),
        asp_index: fdec(&v, "ASPIndex"),
    }
}

#[test]
fn field_u256_roundtrip() {
    for s in ["0", "1", "1000000000000000000", "7682233326816519"] {
        let f = Field::from_decimal(s).unwrap();
        assert_eq!(u256_to_field(field_to_u256(f)), f);
    }
}

#[test]
fn withdraw_proof_struct_matches_calldata() {
    let prover = WithdrawProver::bundled().unwrap();
    let proof = prover.prove(&withdraw_inputs()).unwrap();
    let cd = proof.to_solidity_calldata();
    let wp = withdraw_proof(&proof).unwrap();

    // pubSignals are the 8 public signals, in order.
    assert_eq!(wp.pubSignals.len(), 8);
    for (got, want) in wp.pubSignals.iter().zip(cd.public_signals.iter()) {
        assert_eq!(*got, want.parse::<U256>().unwrap());
    }
    // pA/pC and the (swapped) pB limbs match the Solidity calldata form.
    assert_eq!(wp.pA[0], cd.a[0].parse::<U256>().unwrap());
    assert_eq!(wp.pB[0][0], cd.b[0][0].parse::<U256>().unwrap());
    assert_eq!(wp.pB[1][1], cd.b[1][1].parse::<U256>().unwrap());
    assert_eq!(wp.pC[1], cd.c[1].parse::<U256>().unwrap());
}

#[test]
fn ragequit_proof_uses_commitment_circuit_signals() {
    // The commitment circuit's 4 public signals == RagequitProof.pubSignals.
    let v: Value = serde_json::from_str(COMMITMENT_JSON).unwrap();
    let inputs = CommitmentInputs {
        value: fdec(&v, "value"),
        label: fdec(&v, "label"),
        nullifier: fdec(&v, "nullifier"),
        secret: fdec(&v, "secret"),
    };
    let proof = CommitmentProver::bundled().unwrap().prove(&inputs).unwrap();
    let rp = ragequit_proof(&proof).unwrap();
    assert_eq!(rp.pubSignals.len(), 4);
    let sig = proof.public_signals_decimal();
    assert_eq!(rp.pubSignals[0], sig[0].parse::<U256>().unwrap()); // commitmentHash
    assert_eq!(rp.pubSignals[1], sig[1].parse::<U256>().unwrap()); // nullifierHash
}

#[test]
fn deposit_overload_mapping_is_correct() {
    // deposit_0 must be native deposit(uint256); deposit_1 the ERC20 overload.
    assert_eq!(IEntrypoint::deposit_0Call::SELECTOR, [0xb6, 0xb5, 0x5f, 0x25]);
    assert_eq!(IEntrypoint::deposit_1Call::SELECTOR, [0x0e, 0xfe, 0x6a, 0x8b]);

    let native = deposit_native_calldata(Field::from(42u64));
    assert_eq!(&native[..4], &[0xb6, 0xb5, 0x5f, 0x25]);

    let erc20 = deposit_erc20_calldata(address!("00000000000000000000000000000000000000aa"), U256::from(5), Field::from(42u64));
    assert_eq!(&erc20[..4], &[0x0e, 0xfe, 0x6a, 0x8b]);
}

#[test]
fn withdraw_calldata_has_expected_selector() {
    let prover = WithdrawProver::bundled().unwrap();
    let proof = prover.prove(&withdraw_inputs()).unwrap();
    let w = privacy_pools::direct_withdrawal(address!("00000000000000000000000000000000000000bb"));
    let data = withdraw_calldata(&w, &proof).unwrap();
    assert_eq!(&data[..4], &[0x30, 0xc0, 0x76, 0x6d]); // withdraw(...) selector
    assert_eq!(IPrivacyPool::withdrawCall::SELECTOR, [0x30, 0xc0, 0x76, 0x6d]);
}

#[test]
fn relay_data_roundtrips() {
    let recipient = address!("1111111111111111111111111111111111111111");
    let fee_recipient = address!("2222222222222222222222222222222222222222");
    let data = relay_data(recipient, fee_recipient, U256::from(250));

    // abi.encode of a static 3-field tuple = 96 bytes.
    assert_eq!(data.len(), 96);
    let decoded = RelayData::abi_decode(&data).unwrap();
    assert_eq!(decoded.recipient, recipient);
    assert_eq!(decoded.feeRecipient, fee_recipient);
    assert_eq!(decoded.relayFeeBPS, U256::from(250));
}
