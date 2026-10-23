# privacy-pools task runner — https://just.systems
# Run `just` (or `just --list`) to see all recipes.

# List available recipes.
default:
    @just --list

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

# Run the full Rust test suite (release).
test:
    cargo test --workspace --release --features privacy-pools/download

# Lint with clippy (warnings as errors).
lint:
    cargo clippy --workspace --all-targets --features privacy-pools/download -- -D warnings

# Generate / refresh the bundled circuit artifacts (pass --force to rebuild).
pull-circuits *args:
    cargo xtask pull-circuits {{args}}

# Generate the Privacy Pools v2 artifacts (pass --force to rebuild).
pull-circuits-v2 *args:
    cargo xtask pull-circuits-v2 {{args}}

# Download the 24 non-bundled v2 zkeys (~984 MB) from GitHub and prove every transact shape.
test-v2-download:
    cargo test --release -p privacy-pools --features download --test v2_proving -- --ignored --nocapture

# ---------------------------------------------------------------------------
# Validation (see validation/README.md)
# ---------------------------------------------------------------------------

# Differential fuzz vs the 0xbow TypeScript SDK (needs bun). n = iterations.
differential n="200":
    cd validation/differential && bun install --silent && bun run differential.ts {{n}}

# Verify a Rust proof against the on-chain Solidity verifier on anvil (needs foundry).
verify-onchain:
    cd validation/anvil && ./verify.sh

# Full on-chain wallet lifecycle vs the deployed contract suite (needs foundry + git + bun).
lifecycle:
    cd validation/anvil-lifecycle && ./lifecycle.sh

# Deep-fuzz a parser with cargo-fuzz (needs nightly + cargo-fuzz). target=parse_wtns|vkey, secs=time.
fuzz target="parse_wtns" secs="60":
    cd crates/privacy-pools && cargo +nightly fuzz run {{target}} -- -max_total_time={{secs}}

# Proving-path fuzz: prove/verify N random *valid* withdrawals vs the helpers.
fuzz-proving cases="256":
    PROPTEST_CASES={{cases}} cargo test --release --test proving_fuzz

# Everything: Rust tests, differential fuzz, and on-chain verification.
validate: test differential verify-onchain

# Remove validation build artifacts (node_modules, foundry out, scratch files).
clean-validation:
    rm -rf validation/differential/node_modules validation/differential/cases.json validation/differential/bun.lock
    rm -rf validation/anvil/out validation/anvil/cache validation/anvil/calldata.json validation/anvil/broadcast
