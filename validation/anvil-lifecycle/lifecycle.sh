#!/usr/bin/env bash
# End-to-end: start anvil, deploy the full Privacy Pools suite, and run the
# Rust lifecycle (deposit -> sync -> verify -> relay -> ragequit).
#   ./lifecycle.sh           (needs: anvil, cast, forge, git, bun)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RPC="${RPC_URL:-http://localhost:8545}"

echo "[lifecycle] starting anvil…"
anvil >/tmp/anvil-lifecycle.log 2>&1 &
ANVIL=$!
trap 'kill $ANVIL 2>/dev/null || true' EXIT
for _ in $(seq 1 40); do
  cast block-number --rpc-url "$RPC" >/dev/null 2>&1 && break
  sleep 0.25
done

RPC_URL="$RPC" "$HERE/deploy.sh"

echo "[lifecycle] running Rust lifecycle…"
RPC_URL="$RPC" cargo run --quiet --release --manifest-path "$HERE/Cargo.toml"
