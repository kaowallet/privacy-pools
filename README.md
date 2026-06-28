# privacy-pools

Generate and verify [Privacy Pools](https://github.com/0xbow-io/privacy-pools-core)
(0xbow) Groth16 proofs in **pure Rust**, with the circuit artifacts bundled —
**no wasmer, no node, no `circom` binary at runtime**.

- **Witnesses** are computed by [circom-witnesscalc](https://github.com/iden3/circom-witnesscalc)
  from a compiled circuit *graph* (`.graph.bin`).
- **Proofs** are produced by `ark-groth16` against the upstream snarkjs
  trusted-setup keys, using a snarkjs-compatible QAP — so the output verifies
  with snarkjs / the on-chain Solidity verifier.

## Layout

```
xtask/                         cargo xtask pull-circuits  (artifact pipeline)
crates/privacy-pools/
  artifacts/                   generated: <c>.graph.bin / <c>.zkey / <c>.vkey.json + manifest.json
  src/
    field, witness, proof,     ── engine (protocol-agnostic; extract later)
    prover, verifier, vendor/
    circuit, inputs, lib       ── protocol layer (Privacy Pools specifics)
```

The `vendor/` module is the only non-arkworks proving glue: `read_zkey` and
`CircomReduction`, copied from [`ark-circom`](https://github.com/arkworks-rs/circom-compat)
v0.5.0 (MIT/Apache-2.0). We vendor them rather than depend on `ark-circom`
because that crate forces `wasmer` into the build for its WASM witness
calculator — the exact dependency circom-witnesscalc lets us avoid.

## Usage

```rust
use privacy_pools::{WithdrawProver, WithdrawInputs, WithdrawVerifier, Field, siblings};

let prover = WithdrawProver::bundled()?;          // artifacts embedded in the binary
let proof  = prover.prove(&inputs)?;              // WithdrawInputs -> Groth16 proof
assert!(prover.verify(&proof)?);

// verify-only consumers need just the few-KB vkey, not the 17 MB zkey:
assert!(WithdrawVerifier::bundled()?.verify(&proof)?);

// on-chain / snarkjs interop:
let calldata = proof.to_solidity_calldata();      // matches snarkjs exportSolidityCallData
let json     = proof.to_snarkjs_json();           // proof.json form
```

`CommitmentProver` / `CommitmentVerifier` work the same way.

### Features

- `bundled` *(default)* — embed artifacts via `include_bytes!`. With it off,
  load them at runtime: `WithdrawProver::from_dir("…/artifacts")`.
- `parallel` *(default)* — multi-threaded proving (rayon).

## Regenerating artifacts

```
cargo xtask pull-circuits          # pulls pinned sources, builds graphs, stages keys
cargo xtask pull-circuits --force  # ignore the cached manifest and rebuild
```

The task pins **privacy-pools-core `v1.2.1`** and **circomlib `v2.0.5`**, builds
the witnesscalc graphs with `build-circuit` (from circom-witnesscalc `v0.3.0`)
at **`--O1`** to match the optimization level the committed zkeys were compiled
with, and writes `artifacts/manifest.json` (provenance + sha256 + public-signal
order). First run builds `build-circuit` from git (compiles the iden3 circom
frontend; needs `protoc`); set `$BUILD_CIRCUIT` to reuse an existing binary.

To track a new upstream release, bump `PP_CORE_REF` in
[`xtask/src/pull_circuits.rs`](xtask/src/pull_circuits.rs) and re-run. The zkeys
must match whatever on-chain Groth16 verifier you target.

## Reuse across protocols

The engine modules carry no Privacy Pools knowledge — they prove/verify any
circom Groth16/BN254 circuit given `(graph, zkey, vkey)` bytes. When a second
protocol (Railgun, Tornado, …) needs them, lift `field/witness/proof/prover/
verifier/vendor` into a shared `circom-groth16` crate and the `xtask` pipeline
into a config-driven library; each protocol crate then contributes only its
typed inputs, circuit metadata, and bundled artifacts. The witness step is a
`WitnessGenerator` trait, so a legacy circom-1 protocol can swap in a `.wasm`
backend (e.g. `wasmi`) without touching proving.
