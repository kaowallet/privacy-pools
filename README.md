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
    circuit, inputs, lib       ── protocol layer (Privacy Pools proving)
    commitment, tree, context  ── input derivation (Poseidon, LeanIMT, scope/label/context)
    account                    ── HD keys           (feature: account)
    onchain, sync, flow        ── wallet SDK        (feature: onchain / wallet)
```

The `vendor/` module is the only non-arkworks proving glue: `read_zkey` and
`CircomReduction`, copied from [`ark-circom`](https://github.com/arkworks-rs/circom-compat)
v0.5.0 (MIT/Apache-2.0). We vendor them rather than depend on `ark-circom`
because that crate forces `wasmer` into the build for its WASM witness
calculator — the exact dependency circom-witnesscalc lets us avoid.

## Usage

```rust
use privacy_pools::{WithdrawProver, WithdrawVerifier};

// `inputs` is a `WithdrawInputs`, built from your note + Merkle proofs — see
// "Deriving circuit inputs" below, or `build_withdrawal` in the wallet SDK.
let prover = WithdrawProver::bundled()?;          // artifacts embedded in the binary
let proof  = prover.prove(&inputs)?;              // WithdrawInputs -> Groth16 proof
assert!(prover.verify(&proof)?);

// Verify-only needs just the few-KB vkey to *operate*. Note: the `bundled`
// feature still embeds every artifact — to drop the 17 MB zkey from a
// verify-only binary, build without `bundled` and use
// `WithdrawVerifier::from_vkey_json` / `from_dir`.
assert!(WithdrawVerifier::bundled()?.verify(&proof)?);

// on-chain / snarkjs interop:
let calldata = proof.to_solidity_calldata();      // matches snarkjs exportSolidityCallData
let json     = proof.to_snarkjs_json();           // proof.json form
```

`CommitmentProver` / `CommitmentVerifier` work the same way.

### Deriving circuit inputs

The crate also derives the inputs the circuits expect — so you can go from raw
protocol data to a proof without a separate SDK:

```rust
use privacy_pools::{scope, label, Address, Commitment, LeanImt, Withdrawal, Field};

// commitments / nullifier hashes (circomlib-compatible Poseidon)
let lbl  = label(scope(pool, chain_id, asset), nonce);
let note = Commitment::new(value, lbl, nullifier, secret);
let leaf = note.hash()?;

// LeanIMT membership proofs in the exact shape WithdrawInputs wants
let state = LeanImt::from_leaves(&all_commitments)?;
let proof = state.generate_proof(my_index)?;   // -> { index, siblings, .. }
let siblings = proof.padded_siblings()?;        // padded to MAX_TREE_DEPTH

// withdrawal context (keccak256(abi.encode(Withdrawal, scope)) % p)
let context = Withdrawal::new(processooor, data).context(scope(pool, chain_id, asset));
```

`tests/end_to_end.rs` builds a complete `WithdrawInputs` from scratch with these
helpers and proves+verifies it against the circuit. All helpers are validated
against upstream vectors: Poseidon/commitments vs the `commitment` circuit's
outputs, LeanIMT roots vs the `withdraw` circuit's state/ASP roots, and
`context` vs the SDK's `calculateContext` test vector.

### Features

- `bundled` *(default)* — embed artifacts via `include_bytes!`. With it off,
  load them at runtime: `WithdrawProver::from_dir("…/artifacts")`.
- `parallel` *(default)* — multi-threaded proving (rayon).
- `account` — HD key derivation (`Account`), byte-compatible with the 0xbow SDK.
- `onchain` — alloy ABI bindings, calldata builders, and the async `Syncer`
  (pulls `alloy`, pinned to 2.0.1).
- `wallet` — the full wallet SDK = `account` + `onchain`.

**Bundle size:** with `bundled` on, the embedded artifacts add **~18.7 MB** to
your binary — almost all of it `withdraw.zkey` (17 MB, the withdraw proving key);
the commitment circuit adds ~0.9 MB and the vkeys are a few KB each. Local
*proving* needs the zkeys; verify-only or size-sensitive builds can turn
`bundled` off and load artifacts at runtime with `from_dir` / `from_vkey_json`.

## Wallet SDK (`wallet` feature)

The crate is a plug-and-play wallet SDK: HD accounts, chain sync over **your**
alloy provider, note recovery, and one-call withdrawal assembly. It does **no
network I/O on its own** — you drive the provider (so every 3rd-party request is
user-triggered), proving stays synchronous (wrap it in your async runtime / an
`iced::Task`), and there is no wasmer. `alloy` is re-exported as
`privacy_pools::alloy` so your wallet and the SDK share one alloy instance.

```rust
use privacy_pools::{Account, Syncer, recover_accounts, build_withdrawal, Destination,
                    WithdrawProver, relay_calldata, native_deposit};
use privacy_pools::alloy::primitives::U256;

// 1. HD account — same derivation as 0xbow's client, so notes are interoperable.
let account = Account::from_mnemonic(seed_phrase)?;

// 2. Deposit: precommitment + calldata (send the tx with value = amount).
let (precommitment, calldata) = native_deposit(&account, scope, next_index)?;

// 3. Sync + recover — the SDK drives YOUR (helios-backed) provider on demand.
let syncer = Syncer::new(pool, entrypoint);
let logs = syncer.scan_pool(&provider, deploy_block, None).await?;   // chunked eth_getLogs
let accounts = recover_accounts(&account, scope, &logs, 10)?;        // gap-limit recovery
let acct = &accounts[0];
let note = acct.spendable().expect("a spendable note");

// 4. Trust anchor: rebuild the trees from (untrusted) logs, then verify the
//    roots against helios-verified eth_call. A forged log set can't pass.
let state_tree = logs.state_tree()?;
let state_proof = state_tree.generate_proof(logs.leaf_index(note.hash()?).unwrap())?;
assert!(syncer.verify_state_root(&provider, state_proof.root).await?);
// asp_proof: a LeanImt membership proof of `note.label` in the ASP leaf set you
// fetched (e.g. via IPFS from the latest RootUpdated CID — a manual trigger):
assert!(syncer.verify_asp_root(&provider, asp_proof.root).await?);

// 5. Assemble → prove (off the UI thread) → submit.
let dest = Destination::Relayed { entrypoint, recipient, fee_recipient,
                                  relay_fee_bps: U256::from(250) };
let plan = build_withdrawal(&account, scope, note, acct.children.len() as u64,
                            U256::from(amount), &state_proof, &asp_proof, &dest)?;
let proof = WithdrawProver::bundled()?.prove(&plan.inputs)?;
let calldata = relay_calldata(&plan.withdrawal, &proof, scope)?;     // submit via your provider
// persist `plan.new_note` as the change note.
```

(Pseudo-code: the chain calls are `async`, and `pool` / `entrypoint` / `provider`
/ `asp_proof` etc. come from your wallet — see `validation/anvil-lifecycle/` for a
runnable end-to-end version.)

**Why the SDK drives the scan over your provider** (rather than taking pre-fetched
logs): it mirrors both the 0xbow SDK and the EF Kohaku wallet, which own the
chunked-`getLogs` loop behind a provider seam. Helios cannot serve trustless logs
at scale (`eth_getLogs` is capped to ~8k recent blocks), so the model — also
Kohaku's — is to rebuild the trees from cheap untrusted logs and then verify the
*roots* against helios-verifiable `eth_call`s (`verify_state_root` walks the
pool's 64-slot root ring buffer; `verify_asp_root` checks `Entrypoint.latestRoot()`).

Building blocks if you want more control: `Account::{deposit_secrets,
withdrawal_secrets, deposit_precommitment}`; `Syncer::{scan_pool,
current_state_root, current_tree_depth, latest_asp_root}`; `PoolLogs::{state_tree,
leaf_index}`; `PoolAccount::spendable`; `erc20_deposit`; `Destination::Direct`;
`ragequit_inputs` (+ `CommitmentProver` → `ragequit_calldata`). The raw ABI lives
in `privacy_pools::{IPrivacyPool, IEntrypoint}` and the calldata/struct helpers
(`withdraw_calldata`, `withdraw_proof`, `relay_data`, …).

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

## Validation

Beyond the in-crate tests, `validation/` cross-checks against the canonical
reference implementations:

- **`validation/differential/`** — random inputs through both the Rust helpers
  and the real `@0xbow/privacy-pools-core-sdk` (+ `@zk-kit/lean-imt`,
  `maci-crypto`, `viem`); HD key derivation (master keys + deposit/change
  secrets), Poseidon, commitments, `scope`/`label`/`context`, and LeanIMT
  roots/proofs all match (0 mismatches over thousands of cases).
- **`validation/anvil/`** — a Rust-generated proof is verified by the actual
  snarkjs `WithdrawalVerifier.sol` on a local anvil node: valid → `true`,
  tampered → `false`. So the proof + Solidity calldata are on-chain compatible.
- **`validation/anvil-lifecycle/`** — the **full wallet flow** against the whole
  deployed suite (Poseidon libs + verifiers + `Entrypoint` proxy + native pool):
  deposit → async `Syncer` recovery → on-chain root verification → relayed
  withdrawal (`Entrypoint.relay`) → ragequit (`Pool.ragequit`), all accepted by
  the real contracts (`just lifecycle`).

See [validation/README.md](validation/README.md).

## Reuse across protocols

The engine modules carry no Privacy Pools knowledge — they prove/verify any
circom Groth16/BN254 circuit given `(graph, zkey, vkey)` bytes. When a second
protocol (Railgun, Tornado, …) needs them, lift `field/witness/proof/prover/
verifier/vendor` into a shared `circom-groth16` crate and the `xtask` pipeline
into a config-driven library; each protocol crate then contributes only its
typed inputs, circuit metadata, and bundled artifacts. The witness step is a
`WitnessGenerator` trait, so a legacy circom-1 protocol can swap in a `.wasm`
backend (e.g. `wasmi`) without touching proving.
