//! Groth16 verifier.
//!
//! [Engine layer — no protocol knowledge.]
//!
//! A [`Verifier`] needs only a snarkjs `vkey.json` — a few KB — so a
//! verify-only consumer can avoid shipping the multi-MB proving key.

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, VerifyingKey};
use num_bigint::BigUint;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::proof::Groth16Proof;

/// A Groth16 verifier built from a snarkjs `vkey.json`.
pub struct Verifier {
    pvk: PreparedVerifyingKey<Bn254>,
    n_public: usize,
}

impl Verifier {
    /// Parse a snarkjs groth16 `vkey.json`.
    pub fn from_vkey_json(bytes: &[u8]) -> Result<Self> {
        let v: Value = serde_json::from_slice(bytes)
            .map_err(|e| Error::Artifact(format!("parsing vkey.json: {e}")))?;
        let vk = vkey_from_json(&v)?;
        let n_public = vk
            .gamma_abc_g1
            .len()
            .checked_sub(1)
            .ok_or_else(|| Error::Artifact("vkey IC must have at least one point".into()))?;
        Ok(Self {
            pvk: prepare_verifying_key(&vk),
            n_public,
        })
    }

    /// Number of public signals the verifying key expects.
    pub fn num_public(&self) -> usize {
        self.n_public
    }

    /// Verify a proof against this key.
    pub fn verify(&self, proof: &Groth16Proof) -> Result<bool> {
        if proof.public_signals.len() != self.n_public {
            return Err(Error::Input(format!(
                "proof has {} public signals but vkey expects {}",
                proof.public_signals.len(),
                self.n_public
            )));
        }
        verify_with_pvk(&self.pvk, proof)
    }
}

pub(crate) fn verify_with_pvk(
    pvk: &PreparedVerifyingKey<Bn254>,
    proof: &Groth16Proof,
) -> Result<bool> {
    Groth16::<Bn254>::verify_proof(pvk, &proof.proof, &proof.public_signals)
        .map_err(|e| Error::Prove(format!("verification error: {e}")))
}

// --- snarkjs vkey.json -> arkworks VerifyingKey -----------------------------
// JSON stores G2 as [[c0, c1], ...] (NO swap), so it maps straight to
// Fq2::new(c0, c1). Points are from a trusted, pinned artifact.

fn vkey_from_json(j: &Value) -> Result<VerifyingKey<Bn254>> {
    let protocol = j.get("protocol").and_then(Value::as_str);
    if protocol != Some("groth16") {
        return Err(Error::Artifact(format!(
            "expected groth16 vkey, got protocol {protocol:?}"
        )));
    }
    let ic = j
        .get("IC")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Artifact("vkey missing IC".into()))?
        .iter()
        .map(parse_g1)
        .collect::<Result<Vec<_>>>()?;

    Ok(VerifyingKey::<Bn254> {
        alpha_g1: parse_g1(field(j, "vk_alpha_1")?)?,
        beta_g2: parse_g2(field(j, "vk_beta_2")?)?,
        gamma_g2: parse_g2(field(j, "vk_gamma_2")?)?,
        delta_g2: parse_g2(field(j, "vk_delta_2")?)?,
        gamma_abc_g1: ic,
    })
}

fn field<'a>(j: &'a Value, key: &str) -> Result<&'a Value> {
    j.get(key)
        .ok_or_else(|| Error::Artifact(format!("vkey missing {key}")))
}

fn parse_fq(v: &Value) -> Result<Fq> {
    let s = v
        .as_str()
        .ok_or_else(|| Error::Artifact("expected decimal-string coordinate".into()))?;
    let n = s
        .parse::<BigUint>()
        .map_err(|e| Error::Artifact(format!("invalid Fq {s:?}: {e}")))?;
    Ok(Fq::from_be_bytes_mod_order(&n.to_bytes_be()))
}

fn parse_g1(v: &Value) -> Result<G1Affine> {
    let a = v
        .as_array()
        .filter(|a| a.len() >= 2)
        .ok_or_else(|| Error::Artifact("G1 point must be [x, y, ..]".into()))?;
    Ok(G1Affine::new_unchecked(parse_fq(&a[0])?, parse_fq(&a[1])?))
}

fn parse_g2(v: &Value) -> Result<G2Affine> {
    let a = v
        .as_array()
        .filter(|a| a.len() >= 2)
        .ok_or_else(|| Error::Artifact("G2 point must be [[..],[..], ..]".into()))?;
    let x = a[0]
        .as_array()
        .filter(|c| c.len() >= 2)
        .ok_or_else(|| Error::Artifact("G2 x must be [c0, c1]".into()))?;
    let y = a[1]
        .as_array()
        .filter(|c| c.len() >= 2)
        .ok_or_else(|| Error::Artifact("G2 y must be [c0, c1]".into()))?;
    Ok(G2Affine::new_unchecked(
        Fq2::new(parse_fq(&x[0])?, parse_fq(&x[1])?),
        Fq2::new(parse_fq(&y[0])?, parse_fq(&y[1])?),
    ))
}
