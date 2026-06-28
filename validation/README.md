# validation

Cross-checks of the `privacy-pools` crate against the canonical reference
implementations. Both are optional (need extra tooling) and not part of
`cargo test`.

## differential/ — fuzz vs the 0xbow TypeScript SDK

Runs random inputs through both the Rust helpers and the actual
`@0xbow/privacy-pools-core-sdk` (+ `@zk-kit/lean-imt`, `maci-crypto`, `viem`)
and asserts the outputs match — Poseidon, commitment/nullifier hashing,
`scope`/`label`/`context`, and LeanIMT roots + membership proofs.

The input distribution is adversarial, not just uniform-random: ~¼ of field /
address inputs are boundary values (`0`, `1`, `p-1`, zero / all-`FF` address);
`context` `data` lengths are usually **not** multiples of 32 (exercises the
`abi.encode` right-padding branch); tree sizes straddle the LeanIMT depth
boundaries (16/17, 31/32/33, 63/64/65); the root is checked after **every**
insert (`leanRootSeq`), not just the final tree; and every leaf of small trees
gets a membership proof (`leanProofs`).

```bash
cd validation/differential
bun install
bun run differential.ts 200      # 200 iterations
```

Requires [bun](https://bun.sh). Expect `mismatches: 0`.

## anvil/ — on-chain Solidity verifier check

Generates a withdrawal proof in Rust, deploys the snarkjs-generated
`WithdrawalVerifier.sol` (vendored from privacy-pools-core v1.2.1, matching the
bundled `withdraw.zkey`) to a local anvil node, and calls `verifyProof` with the
Rust-produced Solidity calldata.

```bash
cd validation/anvil
./verify.sh
```

Requires [foundry](https://getfoundry.sh) (`anvil`/`forge`/`cast`). Expect
`valid proof => true` and `tampered proof => false`.
