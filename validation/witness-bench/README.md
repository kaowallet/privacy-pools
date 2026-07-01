# witness-bench — wasmer vs. our wasmer-free witness generation

Benchmarks the two ways to turn circuit inputs into a Groth16 witness for the
real privacy-pools `commitment` and `withdraw` circuits:

- **graph (our solution)** — `circom-witnesscalc`'s `calc_witness` over the
  committed `*.graph.bin`. No wasm, no node, no wasmer.
- **wasm + wasmer** — the classic path: a circom `.wasm` driven by `ark-circom`'s
  `WitnessCalculator` on top of **wasmer**.

Proving (`ark-groth16`) is identical for both, so witness generation is the only
step that differs — that is all this measures. The harness also asserts that
both backends produce the **same** witness before timing.

This crate is workspace-excluded (it pulls arkworks 0.6 + wasmer 6, whereas the
main crate is pinned to arkworks 0.5). The two arkworks versions never meet:
witnesses are compared as decimal strings at the boundary.

## Run

```
cargo run --release --manifest-path validation/witness-bench/Cargo.toml
```

## Results (Apple M-series, 10 logical CPUs)

| circuit    | signals | graph (median) | wasm (median) | speedup | wasm one-time compile |
|------------|--------:|---------------:|--------------:|--------:|----------------------:|
| commitment |   1 542 |        ~0.23 ms |       ~2.05 ms |  ~9x    |               ~160 ms |
| withdraw   |  36 901 |        ~3.99 ms |      ~56.5 ms  | ~14x    |               ~120 ms |

The graph backend is ~9–14x faster per witness **and** has no module-compile
cold start. Its per-witness figure is if anything conservative: it re-parses the
graph on every call, while the wasm figure excludes the one-time compile.

## Regenerating the wasm assets

The `.graph.bin` files come from `cargo xtask pull-circuits`. The `.wasm` files in
`assets/` are the classic-path counterpart, compiled from the **same** `main`
wrapper at the **same** `--O1` optimization level (so witness layouts match):

```
# 1. install circom (iden3)
cargo install --git https://github.com/iden3/circom.git --tag v2.2.0 circom

# 2. stage the circuit sources + wrappers (keeps the clone under target/)
cargo xtask pull-circuits --keep-work --force

# 3. compile each wrapper to wasm at --O1
CORE=target/pull-circuits/privacy-pools-core
SRC=$CORE/packages/circuits/circuits
NM=$CORE/node_modules
for c in commitment withdraw; do
  circom "$SRC/__main_${c}.circom" --wasm --O1 \
    -l "$NM" -l "$NM/circomlib/circuits" -l "$SRC" -o target/wasm-bench
  cp target/wasm-bench/__main_${c}_js/__main_${c}.wasm \
     validation/witness-bench/assets/${c}.wasm
done
```

Note: circom 2.2 emits a `runtime.printDebug` wasm import that ark-circom 0.6's
built-in import set lacks, so the bench builds the wasmer instance with its own
import object (no-op stubs) — see `build_calculator` in `src/main.rs`.
