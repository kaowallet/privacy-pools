//! circomlib-compatible Poseidon hashing over BN254.
//!
//! Thin wrapper over [`light_poseidon`], which matches iden3 circomlib's
//! Poseidon (the parameterization circom/snarkjs use). Width is `inputs + 1`.

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};

use crate::error::{Error, Result};
use crate::field::Field;

/// Poseidon hash of 1–N field elements (circomlib `Poseidon(N)`).
///
/// Errors if `inputs` is empty or wider than light-poseidon supports.
pub fn poseidon(inputs: &[Field]) -> Result<Field> {
    if inputs.is_empty() {
        return Err(Error::Input("poseidon requires at least one input".into()));
    }
    let frs: Vec<Fr> = inputs.iter().map(|f| f.into_fr()).collect();
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .map_err(|e| Error::Input(format!("poseidon init ({} inputs): {e}", inputs.len())))?;
    let out = hasher
        .hash(&frs)
        .map_err(|e| Error::Input(format!("poseidon hash: {e}")))?;
    Ok(Field::new(out))
}

/// Poseidon of two elements — the LeanIMT node hash.
pub fn poseidon2(left: Field, right: Field) -> Result<Field> {
    poseidon(&[left, right])
}
