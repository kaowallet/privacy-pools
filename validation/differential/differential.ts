// Differential fuzz: Rust privacy-pools helpers vs the 0xbow TS SDK / zk-kit / viem.
//   bun install && bun run differential.ts [opsPerKind]
import { writeFileSync } from "fs";
import { join, resolve } from "path";
import { poseidon } from "maci-crypto/build/ts/hashing.js";
import { LeanIMT } from "@zk-kit/lean-imt";
import { calculateContext } from "@0xbow/privacy-pools-core-sdk";
import { keccak256, encodePacked } from "viem";

const REPO = resolve(import.meta.dir, "../..");
const CASES = join(import.meta.dir, "cases.json");
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const N = Number(process.argv[2] ?? 150);
const mod = (x: bigint) => ((x % P) + P) % P;

const rnd = (n: number) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
const toHex = (b: Uint8Array) => "0x" + Buffer.from(b).toString("hex");
const randField = () => (BigInt(toHex(rnd(32))) % P).toString();
const randAddr = () => toHex(rnd(20));
const randInt = (max: number) => Math.floor(Math.random() * max);

type Op = Record<string, any>;
const ops: Op[] = [];
const ref: string[] = [];
const push = (op: Op, out: string) => { ops.push(op); ref.push(out); };

for (let i = 0; i < N; i++) {
  for (const k of [1, 2, 3]) {
    const inp = Array.from({ length: k }, randField);
    push({ op: "poseidon", in: inp }, poseidon(inp.map(BigInt)).toString());
  }
  const [v, l, n, s] = [randField(), randField(), randField(), randField()];
  push({ op: "nullifierHash", in: [n] }, poseidon([BigInt(n)]).toString());
  push({ op: "precommitment", in: [n, s] }, poseidon([BigInt(n), BigInt(s)]).toString());
  push({ op: "commitment", in: [v, l, n, s] },
    poseidon([BigInt(v), BigInt(l), poseidon([BigInt(n), BigInt(s)])]).toString());

  const pool = randAddr(), asset = randAddr(), chainId = String(randInt(1_000_000) + 1);
  const scope = mod(BigInt(keccak256(encodePacked(["address", "uint256", "address"], [pool as any, BigInt(chainId), asset as any]))));
  push({ op: "scope", pool, asset, chainId }, scope.toString());
  const nonce = String(randInt(1_000_000) + 1);
  const lbl = mod(BigInt(keccak256(encodePacked(["uint256", "uint256"], [scope, BigInt(nonce)]))));
  push({ op: "label", scope: scope.toString(), nonce }, lbl.toString());

  const proc = randAddr();
  const data = toHex(rnd(randInt(4) * 32));
  const ctx = BigInt(calculateContext({ processooor: proc as any, data: data as any }, BigInt(scope) as any)).toString();
  push({ op: "context", processooor: proc, data, scope: scope.toString() }, ctx);

  const m = randInt(20) + 1;
  const leaves = Array.from({ length: m }, randField);
  const t = new LeanIMT<bigint>((a, b) => poseidon([a, b]));
  t.insertMany(leaves.map(BigInt));
  push({ op: "leanRoot", leaves }, t.root.toString());
  const idx = randInt(m);
  const pr = t.generateProof(idx);
  push({ op: "leanProof", leaves, index: idx }, `${pr.index}:${pr.siblings.map((x) => x.toString()).join(",")}`);
}

writeFileSync(CASES, JSON.stringify({ ops }));

const proc = Bun.spawnSync(["cargo", "run", "-q", "--release", "--example", "differential", "--", CASES], { cwd: REPO });
if (proc.exitCode !== 0) { console.error("rust example failed:\n", proc.stderr.toString()); process.exit(1); }
const rust: string[] = JSON.parse(proc.stdout.toString()).out;

let mismatches = 0;
for (let i = 0; i < ops.length; i++) {
  if (rust[i] !== ref[i]) {
    if (++mismatches <= 10) {
      console.error(`MISMATCH [${ops[i].op}]`, JSON.stringify(ops[i]).slice(0, 160));
      console.error("  rust:", rust[i], "\n  ts:  ", ref[i]);
    }
  }
}
const byKind = ops.reduce((m, o) => ((m[o.op] = (m[o.op] || 0) + 1), m), {} as Record<string, number>);
console.log("ops by kind:", byKind);
console.log(`total ops: ${ops.length}, mismatches: ${mismatches}`);
process.exit(mismatches === 0 ? 0 : 1);
