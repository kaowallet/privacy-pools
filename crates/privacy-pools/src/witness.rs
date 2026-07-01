//! Witness generation.
//!
//! [Engine layer — no protocol knowledge.]
//!
//! The default [`GraphWitness`] backend runs circom-witnesscalc against a
//! compiled circuit *graph* (`.graph.bin`) — no wasm/node runtime. The
//! [`WitnessGenerator`] trait keeps the proving stack agnostic to *how* the
//! witness was produced, so an alternative backend (e.g. a `wasmi` interpreter
//! over a circom `.wasm`) can be slotted in without touching the prover.

use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::error::{Error, Result};

/// Produces a full witness assignment `[1, outputs.., public.., private.., …]`
/// (the snarkjs `.wtns` ordering, starting with the constant `1`).
pub trait WitnessGenerator: Send + Sync {
    fn generate(&self, inputs_json: &str) -> Result<Vec<Fr>>;
}

/// circom-witnesscalc graph-based witness generation.
pub struct GraphWitness {
    graph: Vec<u8>,
}

impl GraphWitness {
    /// `graph` is a `wtns.graph.00x` blob produced by `build-circuit`.
    pub fn new(graph: impl Into<Vec<u8>>) -> Self {
        Self {
            graph: graph.into(),
        }
    }
}

impl WitnessGenerator for GraphWitness {
    fn generate(&self, inputs_json: &str) -> Result<Vec<Fr>> {
        let wtns = circom_witnesscalc::calc_witness(inputs_json, &self.graph)
            .map_err(|e| Error::Witness(e.to_string()))?;
        parse_wtns(&wtns)
    }
}

/// Parse a snarkjs binary `.wtns` (magic `wtns`, v2) into field elements.
///
/// Layout: `magic[4] | version:u32 | nSections:u32`, then sections
/// `id:u32 | len:u64 | body`. Section 1 (header) = `n8:u32 | prime[n8] |
/// nWitness:u32`; section 2 = `nWitness × field[n8]`, little-endian.
pub fn parse_wtns(bytes: &[u8]) -> Result<Vec<Fr>> {
    let err = |m: &str| Error::Witness(format!("malformed .wtns: {m}"));

    if bytes.len() < 12 || &bytes[0..4] != b"wtns" {
        return Err(err("bad magic"));
    }
    let n_sections = u32::from_le_bytes(bytes[8..12].try_into().unwrap());

    let mut off = 12usize;
    let mut n8: Option<usize> = None;
    let mut section2: Option<(usize, usize)> = None; // (start, len)

    for _ in 0..n_sections {
        if off + 12 > bytes.len() {
            return Err(err("truncated section header"));
        }
        let stype = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let slen = u64::from_le_bytes(bytes[off + 4..off + 12].try_into().unwrap()) as usize;
        let body = off + 12;
        if body + slen > bytes.len() {
            return Err(err("section overruns buffer"));
        }
        match stype {
            1 => {
                if slen < 4 {
                    return Err(err("header section too small"));
                }
                n8 = Some(u32::from_le_bytes(bytes[body..body + 4].try_into().unwrap()) as usize);
            }
            2 => section2 = Some((body, slen)),
            _ => {}
        }
        off = body + slen;
    }

    let n8 = n8.ok_or_else(|| err("missing header section"))?;
    let (start, len) = section2.ok_or_else(|| err("missing witness section"))?;
    if n8 == 0 || len % n8 != 0 {
        return Err(err("witness length not a multiple of field size"));
    }

    Ok(bytes[start..start + len]
        .chunks_exact(n8)
        .map(Fr::from_le_bytes_mod_order)
        .collect())
}
