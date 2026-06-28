//! Groth16 proof + snarkjs / Solidity serialization.
//!
//! [Engine layer — no protocol knowledge.]

use ark_bn254::{Bn254, Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;
use num_bigint::BigUint;
use serde::Serialize;

/// A Groth16 proof together with its public signals (`witness[1..=nPublic]`,
/// i.e. circuit outputs followed by declared public inputs).
#[derive(Clone, Debug)]
pub struct Groth16Proof {
    pub proof: Proof<Bn254>,
    pub public_signals: Vec<Fr>,
}

/// Solidity `verifyProof` calldata, matching `snarkjs exportSolidityCallData`.
///
/// Note the G2 coordinate swap (`c1` before `c0`) that the on-chain pairing
/// precompile expects — applied here, *not* in [`Groth16Proof::to_snarkjs_json`].
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SolidityCalldata {
    pub a: [String; 2],
    pub b: [[String; 2]; 2],
    pub c: [String; 2],
    pub public_signals: Vec<String>,
}

impl Groth16Proof {
    /// Public signals as decimal strings (snarkjs `public.json` order).
    pub fn public_signals_decimal(&self) -> Vec<String> {
        self.public_signals.iter().map(fr_to_dec).collect()
    }

    /// snarkjs `proof.json` form. G2 is stored `[c0, c1]` (NO swap), each point
    /// carries its trailing affine marker (`"1"` / `["1","0"]`).
    pub fn to_snarkjs_json(&self) -> serde_json::Value {
        let p = &self.proof;
        serde_json::json!({
            "protocol": "groth16",
            "curve": "bn128",
            "pi_a": [fq_to_dec(&p.a.x), fq_to_dec(&p.a.y), "1"],
            "pi_b": [
                [fq_to_dec(&p.b.x.c0), fq_to_dec(&p.b.x.c1)],
                [fq_to_dec(&p.b.y.c0), fq_to_dec(&p.b.y.c1)],
                ["1", "0"]
            ],
            "pi_c": [fq_to_dec(&p.c.x), fq_to_dec(&p.c.y), "1"],
        })
    }

    /// Solidity calldata. G2 limbs are swapped (`c1` first); no negation.
    pub fn to_solidity_calldata(&self) -> SolidityCalldata {
        let p = &self.proof;
        SolidityCalldata {
            a: [fq_to_dec(&p.a.x), fq_to_dec(&p.a.y)],
            b: [
                [fq_to_dec(&p.b.x.c1), fq_to_dec(&p.b.x.c0)],
                [fq_to_dec(&p.b.y.c1), fq_to_dec(&p.b.y.c0)],
            ],
            c: [fq_to_dec(&p.c.x), fq_to_dec(&p.c.y)],
            public_signals: self.public_signals_decimal(),
        }
    }
}

fn fr_to_dec(f: &Fr) -> String {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_str_radix(10)
}

fn fq_to_dec(f: &Fq) -> String {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_str_radix(10)
}
