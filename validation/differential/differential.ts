// Differential fuzz: Rust privacy-pools helpers vs the 0xbow TS SDK / zk-kit / viem.
//   bun install && bun run differential.ts [iterations]
//
// Each iteration emits a batch of ops covering Poseidon, commitments,
// scope/label/context and LeanIMT. The input distribution is deliberately
// adversarial: ~1/4 of field/address inputs are boundary values (0, 1, p-1,
// zero/all-FF address), context `data` lengths are frequently NOT multiples of
// 32 (exercises the abi.encode right-padding branch), tree sizes straddle the
// 16/17/32/33/63/64/65 depth boundaries, every leaf of small trees gets a
// membership proof, and roots are checked after *every* insert — not just the
// final tree.
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
const randInt = (max: number) => Math.floor(Math.random() * max);
const pick = <T>(xs: T[]): T => xs[randInt(xs.length)];
const chance = (p: number) => Math.random() < p;

// Boundary field values that uniform-random-mod-p essentially never produces.
const EDGE_FIELDS = ["0", "1", "2", "3", (P - 1n).toString(), (P - 2n).toString(), "1000000"];
const uniformField = () => (BigInt(toHex(rnd(32))) % P).toString();
const randField = () => (chance(0.25) ? pick(EDGE_FIELDS) : uniformField());

// Boundary addresses alongside random ones.
const EDGE_ADDRS = ["0x" + "00".repeat(20), "0x" + "ff".repeat(20)];
const randAddr = () => (chance(0.2) ? pick(EDGE_ADDRS) : toHex(rnd(20)));

// Tree sizes that straddle LeanIMT depth boundaries (promotion / depth growth).
const SIZE_BOUNDARIES = [1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65];
const randSize = () => (chance(0.7) ? pick(SIZE_BOUNDARIES) : randInt(80) + 1);

// `data` lengths, heavily weighted toward NON-multiples of 32.
const DATA_LENS = [0, 1, 2, 31, 32, 33, 63, 64, 65, 95, 96, 97];
const randDataLen = () => (chance(0.8) ? pick(DATA_LENS) : randInt(200));

// Up to `max` distinct indices in [0, size); always includes first and last.
const sampleIndices = (size: number, max: number): number[] => {
  if (size <= max) return Array.from({ length: size }, (_, i) => i);
  const s = new Set<number>([0, size - 1]);
  while (s.size < max) s.add(randInt(size));
  return [...s];
};

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
  const data = toHex(rnd(randDataLen()));
  const ctx = BigInt(calculateContext({ processooor: proc as any, data: data as any }, BigInt(scope) as any)).toString();
  push({ op: "context", processooor: proc, data, scope: scope.toString() }, ctx);

  // LeanIMT: insert leaves one at a time and record the root after each insert,
  // then prove membership for a sample of leaves of the final tree.
  const m = randSize();
  const leaves = Array.from({ length: m }, randField);
  const t = new LeanIMT<bigint>((a, b) => poseidon([a, b]));
  const roots: string[] = [];
  for (const leaf of leaves) { t.insert(BigInt(leaf)); roots.push(t.root.toString()); }
  push({ op: "leanRootSeq", leaves }, roots.join(";"));

  const indices = sampleIndices(m, 12);
  const proofs = indices.map((idx) => {
    const pr = t.generateProof(idx);
    return `${pr.index}:${pr.siblings.map((x) => x.toString()).join(",")}`;
  });
  push({ op: "leanProofs", leaves, indices }, proofs.join(";"));
}

writeFileSync(CASES, JSON.stringify({ ops }));

const proc = Bun.spawnSync(["cargo", "run", "-q", "--release", "--example", "differential", "--", CASES], { cwd: REPO });
if (proc.exitCode !== 0) { console.error("rust example failed:\n", proc.stderr.toString()); process.exit(1); }
const rust: string[] = JSON.parse(proc.stdout.toString()).out;

let mismatches = 0;
for (let i = 0; i < ops.length; i++) {
  if (rust[i] !== ref[i]) {
    if (++mismatches <= 10) {
      console.error(`MISMATCH [${ops[i].op}]`, JSON.stringify(ops[i]).slice(0, 200));
      console.error("  rust:", String(rust[i]).slice(0, 120), "\n  ts:  ", String(ref[i]).slice(0, 120));
    }
  }
}
const byKind = ops.reduce((m, o) => ((m[o.op] = (m[o.op] || 0) + 1), m), {} as Record<string, number>);
console.log("ops by kind:", byKind);
console.log(`total ops: ${ops.length}, mismatches: ${mismatches}`);
process.exit(mismatches === 0 ? 0 : 1);
