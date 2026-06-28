//! Minimal end-to-end example: build inputs, prove, verify, serialize.
//!
//! Run with: `cargo run --release --example prove`

use privacy_pools::{
    CommitmentInputs, CommitmentProver, Field, WithdrawProver, WithdrawVerifier,
};

fn main() -> Result<(), privacy_pools::Error> {
    // ---- commitment: the typed-input path (4 fields) ----
    let inputs = CommitmentInputs {
        value: Field::from(12u64),
        label: Field::from_decimal(
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        )?,
        nullifier: Field::from(56u64),
        secret: Field::from(78u64),
    };
    let prover = CommitmentProver::bundled()?;
    let proof = prover.prove(&inputs)?;
    println!("commitment proof public signals:");
    for (name, val) in privacy_pools::named_public_signals(prover.circuit(), &proof) {
        println!("  {name:>16} = {val}");
    }
    println!("  verified: {}\n", prover.verify(&proof)?);

    // ---- withdraw: prove from raw circuit-input JSON ----
    let withdraw_json = include_str!("../tests/fixtures/withdraw_default.json");
    let prover = WithdrawProver::bundled()?;
    let proof = prover.engine().prove(withdraw_json)?;
    println!("withdraw proof public signals:");
    for (name, val) in privacy_pools::named_public_signals(privacy_pools::Circuit::Withdraw, &proof)
    {
        println!("  {name:>22} = {val}");
    }

    // verify-only path (needs just the small vkey, not the 17 MB zkey)
    let verifier = WithdrawVerifier::bundled()?;
    println!("  verified (vkey only): {}", verifier.verify(&proof)?);

    // Solidity calldata, ready for the on-chain verifier.
    let calldata = proof.to_solidity_calldata();
    println!("\nsolidity calldata a = {:?}", calldata.a);

    Ok(())
}
