#!/usr/bin/env bash
# Deploy the full Privacy Pools suite (Poseidon libs + verifiers + Entrypoint
# proxy + native pool) to a running anvil, register the pool, and write the
# addresses to deployed.json. Idempotent: the contract clone + npm deps are
# cached under .work/ and reused.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RPC="${RPC_URL:-http://localhost:8545}"
PK="${DEPLOYER_PK:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
OWNER="$(cast wallet address --private-key "$PK")"

WORK="$HERE/.work"
DEPS="$WORK/deps"
REPO="$WORK/ppc"
NM="$DEPS/node_modules"
CON="$REPO/packages/contracts"

NATIVE=0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE
PROXY=0x4e59b44847b379578588920ca78fbf26c0b4956c
T3ADDR=0x3333333C0A88F9BE4fd23ed0536F9B6c427e3B93
T4ADDR=0x4443338EF595F44e0121df4C21102677B142ECF0

# --- 1. isolated Solidity deps (OZ, lean-imt.sol, poseidon-solidity) ---------
if [ ! -d "$NM/poseidon-solidity" ]; then
  echo "[deploy] installing Solidity deps…"
  mkdir -p "$DEPS"
  ( cd "$DEPS" && bun init -y >/dev/null 2>&1 \
    && bun add --silent @openzeppelin/contracts@5.1.0 \
        @openzeppelin/contracts-upgradeable@5.0.2 \
        @zk-kit/lean-imt.sol@2.0.0 poseidon-solidity@0.0.5 )
fi

# --- 2. sparse clone of the contracts (no large circuit/ptau blobs) ----------
if [ ! -d "$CON/src" ]; then
  echo "[deploy] cloning privacy-pools-core@v1.2.1 contracts…"
  rm -rf "$REPO"
  git clone --depth 1 --branch v1.2.1 --filter=blob:none --sparse \
    https://github.com/0xbow-io/privacy-pools-core "$REPO" >/dev/null 2>&1
  ( cd "$REPO" && git sparse-checkout set packages/contracts >/dev/null 2>&1 )
  rm -rf "$CON/test" "$CON/script"   # only src/ is needed; tests pull forge-std/halmos
fi

# --- 3. remappings + foundry libraries (Poseidon linked at fixed addrs) ------
cat > "$CON/remappings.txt" <<EOF
@oz/=$NM/@openzeppelin/contracts/
@oz-upgradeable/=$NM/@openzeppelin/contracts-upgradeable/
lean-imt/=$NM/@zk-kit/lean-imt.sol/
poseidon/=$NM/poseidon-solidity/
@openzeppelin/contracts-upgradeable/=$NM/@openzeppelin/contracts-upgradeable/
@openzeppelin/contracts/=$NM/@openzeppelin/contracts/
poseidon-solidity/=$NM/poseidon-solidity/
contracts/=src/contracts/
interfaces/=src/interfaces/
EOF
cat > "$CON/foundry.toml" <<EOF
[profile.default]
solc_version = '0.8.28'
optimizer_runs = 10000
bytecode_hash = "none"
cbor_metadata = false
libraries = [
  "$NM/poseidon-solidity/PoseidonT3.sol:PoseidonT3:$T3ADDR",
  "$NM/poseidon-solidity/PoseidonT4.sol:PoseidonT4:$T4ADDR",
]
EOF

# --- 4. deterministic Poseidon deploy (det-proxy is preloaded on anvil) ------
echo "[deploy] deploying Poseidon libraries…"
for t in PoseidonT2 PoseidonT3 PoseidonT4; do
  DATA="$( cd "$DEPS" && bun -e "process.stdout.write(require('poseidon-solidity').$t.data)" )"
  cast send "$PROXY" "$DATA" --private-key "$PK" --rpc-url "$RPC" >/dev/null
done

# --- 5. build + deploy contracts ---------------------------------------------
echo "[deploy] forge build…"
( cd "$CON" && forge build >/dev/null )

dc() { ( cd "$CON" && forge create "$1" --rpc-url "$RPC" --private-key "$PK" --broadcast "${@:2}" ) \
  2>/dev/null | grep -oE 'Deployed to: 0x[0-9a-fA-F]{40}' | grep -oE '0x[0-9a-fA-F]{40}'; }

echo "[deploy] deploying contracts…"
WV="$(dc src/contracts/verifiers/WithdrawalVerifier.sol:WithdrawalVerifier)"
RV="$(dc src/contracts/verifiers/CommitmentVerifier.sol:CommitmentVerifier)"
IMPL="$(dc src/contracts/Entrypoint.sol:Entrypoint)"
INIT="$(cast calldata 'initialize(address,address)' "$OWNER" "$OWNER")"
EP="$(dc "$NM/@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy" --constructor-args "$IMPL" "$INIT")"
POOL="$(dc src/contracts/implementations/PrivacyPoolSimple.sol:PrivacyPoolSimple --constructor-args "$EP" "$WV" "$RV")"
[ -n "$POOL" ] || { echo "[deploy] pool deploy failed" >&2; exit 1; }

cast send "$EP" 'registerPool(address,address,uint256,uint256,uint256)' \
  "$NATIVE" "$POOL" 1000000000000000 100 100 --private-key "$PK" --rpc-url "$RPC" >/dev/null

SCOPE="$(cast call "$POOL" 'SCOPE()(uint256)' --rpc-url "$RPC" | awk '{print $1}')"

cat > "$HERE/deployed.json" <<EOF
{ "entrypoint": "$EP", "pool": "$POOL", "scope": "$SCOPE" }
EOF
echo "[deploy] pool=$POOL entrypoint=$EP scope=$SCOPE"
echo "[deploy] wrote $HERE/deployed.json"
