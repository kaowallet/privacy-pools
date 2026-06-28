#!/usr/bin/env bash
# Verify a Rust-generated withdrawal proof against the real snarkjs-generated
# WithdrawalVerifier.sol (v1.2.1, matches the bundled withdraw.zkey) on anvil.
#
# Requires: foundry (anvil/forge/cast), cargo. Run: ./verify.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RPC="http://127.0.0.1:8545"
# anvil's deterministic account #0
KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

cleanup() { [[ -n "${ANVIL_PID:-}" ]] && kill "$ANVIL_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "→ starting anvil"
anvil --silent & ANVIL_PID=$!
for _ in $(seq 1 30); do cast block-number --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.3; done

echo "→ deploying WithdrawalVerifier.sol"
cd "$HERE"
OUT="$(forge create WithdrawalVerifier.sol:WithdrawalVerifier --rpc-url "$RPC" --private-key "$KEY" --broadcast 2>&1)"
ADDR="$(echo "$OUT" | grep -i 'Deployed to' | grep -oE '0x[0-9a-fA-F]{40}')"
echo "  verifier at $ADDR"

echo "→ generating a fresh proof from Rust"
cd "$REPO"
cargo run -q --release --example withdraw_calldata 2>/dev/null | grep '^{' > "$HERE/calldata.json"

ADDR="$ADDR" RPC="$RPC" CD="$HERE/calldata.json" python3 - <<'PY'
import json, os, subprocess, sys
d = json.load(open(os.environ['CD']))
a = f"[{d['a'][0]},{d['a'][1]}]"
b = f"[[{d['b'][0][0]},{d['b'][0][1]}],[{d['b'][1][0]},{d['b'][1][1]}]]"
c = f"[{d['c'][0]},{d['c'][1]}]"
sig = "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[8])(bool)"
def call(pub):
    r = subprocess.run(["cast","call",os.environ['ADDR'],sig,a,b,c,
                        "["+",".join(pub)+"]","--rpc-url",os.environ['RPC']],
                       capture_output=True, text=True)
    return (r.stdout.strip() or r.stderr.strip())
ok = call(d['pub'])
tampered = d['pub'][:]; tampered[0] = str(int(tampered[0]) + 1)
bad = call(tampered)
print(f"  valid proof    => {ok}")
print(f"  tampered proof => {bad}")
sys.exit(0 if (ok == "true" and bad == "false") else 1)
PY
echo "✔ on-chain verification OK"
