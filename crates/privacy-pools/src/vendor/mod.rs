//! Code vendored from [`ark-circom`] (arkworks-rs/circom-compat) v0.5.0, which
//! is dual-licensed MIT OR Apache-2.0.
//!
//! Only the two wasmer-free pieces we actually need are vendored:
//!   * [`zkey::read_zkey`] — parse a snarkjs `.zkey` into an arkworks
//!     `ProvingKey<Bn254>` + `ConstraintMatrices<Fr>`.
//!   * [`qap::CircomReduction`] — the snarkjs-compatible Groth16 QAP witness map.
//!
//! We do not depend on the `ark-circom` crate directly because it forces
//! `wasmer` + `wasmer-wasix` into the build for its WASM witness calculator —
//! the very dependency that using circom-witnesscalc for witness generation is
//! meant to eliminate.
//!
//! [`ark-circom`]: https://github.com/arkworks-rs/circom-compat

pub mod qap;
pub mod zkey;
