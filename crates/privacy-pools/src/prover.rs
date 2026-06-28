//! Groth16 prover.
//!
//! [Engine layer — no protocol knowledge.]

use std::io::Cursor;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;

use crate::error::{Error, Result};
use crate::proof::Groth16Proof;
use crate::vendor::qap::CircomReduction;
use crate::vendor::zkey::read_zkey;
use crate::witness::{GraphWitness, WitnessGenerator};

/// A reusable prover: a parsed snarkjs proving key + a witness backend.
///
/// Construct once (parsing a 17 MB zkey is not free) and call [`Prover::prove`]
/// repeatedly.
pub struct Prover {
    witness: Box<dyn WitnessGenerator>,
    pk: ProvingKey<Bn254>,
    matrices: ConstraintMatrices<Fr>,
    pvk: PreparedVerifyingKey<Bn254>,
}

impl Prover {
    /// Build from a witnesscalc `graph` and a snarkjs `zkey` (raw bytes).
    pub fn new(graph: &[u8], zkey: &[u8]) -> Result<Self> {
        Self::with_backend(Box::new(GraphWitness::new(graph.to_vec())), zkey)
    }

    /// Build with a custom witness backend.
    pub fn with_backend(witness: Box<dyn WitnessGenerator>, zkey: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(zkey);
        let (pk, matrices) =
            read_zkey(&mut cursor).map_err(|e| Error::Artifact(format!("reading zkey: {e}")))?;
        let pvk = prepare_verifying_key(&pk.vk);
        Ok(Self {
            witness,
            matrices,
            pk,
            pvk,
        })
    }

    /// Number of public signals (`nPublic`).
    pub fn num_public(&self) -> usize {
        self.matrices.num_instance_variables - 1
    }

    /// Generate a witness from circuit input JSON and produce a proof.
    pub fn prove(&self, inputs_json: &str) -> Result<Groth16Proof> {
        let assignment = self.witness.generate(inputs_json)?;
        self.prove_with_witness(&assignment)
    }

    /// Produce a proof from an already-computed full witness assignment.
    pub fn prove_with_witness(&self, full_assignment: &[Fr]) -> Result<Groth16Proof> {
        let num_inputs = self.matrices.num_instance_variables;
        let num_constraints = self.matrices.num_constraints;
        // The zkey reader sets num_witness_variables = nVars - nPublic (it does
        // not subtract the constant-1 instance), so the full witness length is
        // num_instance + num_witness - 1 = nVars.
        let n_vars = num_inputs + self.matrices.num_witness_variables - 1;
        if full_assignment.len() != n_vars {
            return Err(Error::Witness(format!(
                "witness length {} != circuit variable count {n_vars}",
                full_assignment.len(),
            )));
        }

        let mut rng = thread_rng();
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);

        let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &self.pk,
            r,
            s,
            &self.matrices,
            num_inputs,
            num_constraints,
            full_assignment,
        )
        .map_err(|e| Error::Prove(e.to_string()))?;

        let public_signals = full_assignment[1..num_inputs].to_vec();
        Ok(Groth16Proof { proof, public_signals })
    }

    /// Verify a proof with this circuit's verifying key (from the zkey).
    pub fn verify(&self, proof: &Groth16Proof) -> Result<bool> {
        crate::verifier::verify_with_pvk(&self.pvk, proof)
    }
}
