// THROWAWAY: generates pinned vectors for crates/privacy-pools/tests/v2_*.rs. Do not commit.
import {
  CryptoService, PoseidonHashService, NoteComputationService, MerkleService, WitnessPreparationService,
  EvmContextHashService, EvmPayoutRoutingCodec, APP_IDENTIFIER, COMMITMENT_LEAF_TAG, NoteStatus,
  EMPTY_NOTE_DATA, EMPTY_ADDRESS, bigintToHex, BN254_SCALAR_MODULUS, NATIVE_ASSET_ADDRESS,
  buildSetAuthPolicyTypedData,
} from "@0xbow/privacy-pools-v2-sdk";
import { keccak256, toBytes, toHex, hashTypedData, hashDomain, hashStruct } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const P = BN254_SCALAR_MODULUS as bigint;
const red = (h: string) => (BigInt(h) % P).toString();
const hx = (h: string) => "0x" + (BigInt(h) % P).toString(16).padStart(64, "0");
const rep = (b: string, n: number) => "0x" + b.repeat(n);

const cs = new CryptoService();
const hash = await PoseidonHashService.create();
const nc = new NoteComputationService({ hashService: hash, cryptoService: cs });
const merkle = new MerkleService({ hashService: hash });
const wps = new WitnessPreparationService({ noteComputationService: nc, hashService: hash, merkleService: merkle });
const ctxs = new EvmContextHashService();
const codec = new EvmPayoutRoutingCodec();
const NULLIFIER_LEAF_TAG = "0x0345f8523330820ba63c70407f3bfd09321587cae07bd4f7d37d5049f9c51b17";

const out: any = {};

// --- tags
const strInt = (s: string) => "0x" + Buffer.from(s, "utf8").toString("hex");
out.tags = {
  noteInt: BigInt(strInt("privacy_pools_note")).toString(),
  nullInt: BigInt(strInt("privacy_pools_nullifier")).toString(),
  commitmentTag: hash.hash([strInt("privacy_pools_note")]),
  nullifierTag: hash.hash([strInt("privacy_pools_nullifier")]),
  sdkCommitmentTag: COMMITMENT_LEAF_TAG,
  nativeAsset: NATIVE_ASSET_ADDRESS,
};

// --- note chains
function chain(c: any) {
  const nah = nc.computeNoteAddressHash(c.owner, c.secret);
  const pre = nc.computePrecommitment(nah, c.token, c.value);
  const label = nc.computeLabel(pre, c.depositSecret);
  const commitment = nc.computeFullCommitment({ noteAddressHash: nah, tokenId: c.token, value: c.value, label });
  const nullifier = nc.computeNullifier(c.nk, commitment);
  const authDigest = nc.computeAuthDigest(c.rk);
  const nkHash = hash.hash([c.nk]);
  const keystoreLeaf = (wps as any).computeKeystoreLeaf(c.owner, c.nk, authDigest);
  const tsHex = bigintToHex(BigInt(c.ts));
  const commitmentLeaf = (wps as any).computeTimestampedLeaf(commitment, tsHex);
  const nullifierLeaf = hash.hash([NULLIFIER_LEAF_TAG, nullifier, tsHex]);
  const labelHash = nc.computeLabelHash(label);
  return { ...c, nah, pre, label, commitment, nullifier, authDigest, nkHash, keystoreLeaf, commitmentLeaf, nullifierLeaf, labelHash };
}
out.chains = [
  { name: "eth", owner: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", secret: rep("11", 32), depositSecret: rep("22", 32),
    token: NATIVE_ASSET_ADDRESS, value: "0xde0b6b3a7640000", nk: "0x0" + "3".repeat(63), rk: "0x0" + "4".repeat(63), ts: "1750000000" },
  { name: "usdc", owner: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", secret: rep("11", 32), depositSecret: rep("22", 32),
    token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", value: "0x3b9aca00", nk: "0x01", rk: "0x02", ts: "1" },
  { name: "sdkapi", owner: rep("11", 20), secret: rep("22", 32), depositSecret: rep("33", 32),
    token: rep("aa", 20), value: "0x64", nk: "0x0f22e94df31b8aec2307d0cdbd63420864ead3910473bd50d19466604d244b4c",
    rk: "0x28b5c9202aa1a12bcd2a90d068b92a65d5ea279fdf8cb4b0c08606902a4239f0", ts: "0x1234" },
  { name: "zeros", owner: EMPTY_ADDRESS, secret: "0x0", depositSecret: "0x0", token: EMPTY_ADDRESS, value: "0x0",
    nk: "0x0", rk: "0x0", ts: "0" },
  { name: "max", owner: rep("ff", 20), secret: "0x" + (P - 1n).toString(16), depositSecret: "0x" + (P - 2n).toString(16),
    token: rep("ff", 20), value: "0x" + ((1n << 128n) - 1n).toString(16), nk: "0x" + (P - 1n).toString(16),
    rk: "0x" + (P - 3n).toString(16), ts: "18446744073709551615" },
].map(chain);

// --- secret_from_entropy via the real generateSecret with stubbed randomness
const entropies = [
  "00".repeat(48),
  "ff".repeat(48),
  P.toString(16).padStart(96, "0"),
  (P + 1n).toString(16).padStart(96, "0"),
  Array.from({ length: 48 }, (_, i) => (i + 1).toString(16).padStart(2, "0")).join(""),
  "80" + "00".repeat(47),
];
const realGRV = crypto.getRandomValues.bind(crypto);
out.secrets = entropies.map((e) => {
  const bytes = Buffer.from(e, "hex");
  (crypto as any).getRandomValues = (arr: Uint8Array) => { arr.set(bytes.subarray(0, arr.length)); return arr; };
  const s = cs.generateSecret();
  (crypto as any).getRandomValues = realGRV;
  return { entropy: e, secret: s };
});

// --- contexts
const dctxCases = [
  EMPTY_NOTE_DATA,
  { hint: "0x" + "00".repeat(31) + "01", data: "0xdeadbeef" },
  { hint: rep("ab", 32), data: rep("aa", 31) },
  { hint: rep("ab", 32), data: rep("bb", 32) },
  { hint: rep("ab", 32), data: rep("cc", 33) },
  { hint: rep("ff", 32), data: "0x" + Array.from({ length: 145 }, (_, i) => (i & 0xff).toString(16).padStart(2, "0")).join("") },
];
out.depositContexts = dctxCases.map((nd) => { const raw = ctxs.computeDepositContext(nd as any); return { ...nd, raw, reduced: red(raw) }; });

const routings = [
  { recipient: rep("44", 20), feeRecipient: rep("55", 20), feeAmount: 10n, nativeGas: 0n },
  { recipient: EMPTY_ADDRESS, feeRecipient: EMPTY_ADDRESS, feeAmount: 0n, nativeGas: 0n },
  { recipient: rep("ff", 20), feeRecipient: rep("ff", 20), feeAmount: (1n << 128n) - 1n, nativeGas: (1n << 128n) - 1n },
  { recipient: "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853", feeRecipient: "0x8ba1f109551bD432803012645Ac136ddd64DBA72", feeAmount: 2500000000000000n, nativeGas: 1000000000000000n },
];
out.routings = routings.map((r) => ({ ...r, feeAmount: r.feeAmount.toString(), nativeGas: r.nativeGas.toString(), encoded: codec.encode(r as any) }));

const nd = (h: string, d: string) => ({ hint: h, data: d });
const hint = (i: number) => "0x" + i.toString(16).padStart(64, "0");
const tctxCases = [
  { processor: EMPTY_ADDRESS, data: "0x", notes: [] },
  { processor: rep("88", 20), data: out.routings[0].encoded, notes: [] },
  { processor: rep("88", 20), data: out.routings[0].encoded, notes: [nd(hint(1), "0x"), nd(hint(2), "0xdeadbeef")] },
  { processor: rep("88", 20), data: "0x", notes: [nd(rep("ab", 32), "0x")] },
  { processor: "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853", data: rep("11", 31),
    notes: [nd(hint(3), rep("aa", 31)), nd(hint(4), rep("bb", 32)), nd(hint(5), rep("cc", 33))] },
  { processor: rep("ff", 20), data: rep("22", 33),
    notes: [nd(rep("01", 32), rep("aa", 72)), nd(rep("02", 32), "0x"), nd(rep("03", 32), rep("bb", 1)),
            nd(rep("04", 32), rep("cc", 64)), nd(rep("05", 32), rep("dd", 65))] },
  { processor: "0x8ba1f109551bD432803012645Ac136ddd64DBA72", data: out.routings[3].encoded,
    notes: [nd(rep("0e", 32), rep("e1", 133)), nd(rep("0f", 32), rep("f1", 129))] },
];
out.transactContexts = tctxCases.map((c) => {
  const raw = ctxs.computeTransactContext({ processor: c.processor as any, data: c.data as any }, c.notes as any);
  return { ...c, raw, reduced: red(raw) };
});

// --- SecretDerivation (sample-app payload, apps/sample-web/src/secretDerivationPayload.ts)
const SECRET_DERIVATION_PURPOSE =
  "This signature is used to deterministically derive application-specific secrets from your master seed. It is not a transaction and will not cost any gas.";
function buildSecretDerivationPayload(signerAddress: string) {
  const addressHash = keccak256(toBytes(signerAddress));
  const salt = keccak256(toHex(APP_IDENTIFIER));
  return {
    domain: { name: "Standardized Secret Derivation", version: "1", verifyingContract: "0x0000000000000000000000000000000000000000", salt },
    message: { purpose: SECRET_DERIVATION_PURPOSE, addressHash },
    primaryType: "SecretDerivation",
    types: {
      EIP712Domain: [
        { name: "name", type: "string" }, { name: "version", type: "string" },
        { name: "verifyingContract", type: "address" }, { name: "salt", type: "bytes32" },
      ],
      SecretDerivation: [{ name: "purpose", type: "string" }, { name: "addressHash", type: "bytes32" }],
    },
  } as const;
}
const signers = [
  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", EMPTY_ADDRESS, rep("ff", 20),
  "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF", "0x8ba1f109551bD432803012645Ac136ddd64DBA72",
];
out.appIdentifier = APP_IDENTIFIER;
out.secretDerivation = signers.map((s) => {
  const p = buildSecretDerivationPayload(s);
  return {
    signer: s, addressHash: p.message.addressHash,
    domainSeparator: hashDomain({ domain: p.domain as any, types: p.types as any }),
    structHash: hashStruct({ data: p.message as any, primaryType: "SecretDerivation", types: p.types as any }),
    digest: hashTypedData(p as any), json: JSON.stringify(p),
  };
});

// --- SetAuthPolicy
function sap(a: any) {
  const td = buildSetAuthPolicyTypedData(a);
  const types = { EIP712Domain: [
    { name: "name", type: "string" }, { name: "version", type: "string" },
    { name: "chainId", type: "uint256" }, { name: "verifyingContract", type: "address" }], ...td.types } as any;
  return { ...a, domainSeparator: hashDomain({ domain: td.domain as any, types }),
    structHash: hashStruct({ data: td.message as any, primaryType: td.primaryType, types }), digest: hashTypedData(td as any) };
}
// --- end-to-end keys: anvil keys sign the sample-app payload
const anvil = [
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
];
out.e2e = [];
for (const pk of anvil) {
  const acct = privateKeyToAccount(pk as any);
  const payload = buildSecretDerivationPayload(acct.address);
  const signature = await acct.signTypedData(payload as any);
  const signature2 = await acct.signTypedData(payload as any);
  const cfg = (n: string) => ({ signature, signerAddress: acct.address, revocableKeyIndex: n, addressHash: payload.message.addressHash });
  const k0 = cs.deriveKeysFromSignature(cfg("0x0") as any) as any;
  const rk = (n: string) => (cs.deriveKeysFromSignature(cfg(n) as any) as any).privateRevocableKey;
  const nkHash = hash.hash([k0.privateNullifyingKey]);
  const authDigest = nc.computeAuthDigest(k0.privateRevocableKey);
  const keystoreLeaf = (wps as any).computeKeystoreLeaf(acct.address, k0.privateNullifyingKey, authDigest);
  out.e2e.push({ pk, address: acct.address, digest: hashTypedData(payload as any), signature, deterministic: signature === signature2,
    keys: k0, rk1: rk("0x1"), rk2: rk("0x2"), rkMax: rk("0xffffffffffffffff"), nkHash, authDigest, keystoreLeaf,
    setAuthPolicy: sap({ keystoreAddress: "0x6d264aCb9C3A7A3105c29470AfE2F5F1EC203C73", chainId: 11155111, account: acct.address,
      authDigest, nullifyingKeyHash: nkHash, deadline: "0xffffffffffffffff" }) });
}
out.setAuthPolicy = [
  sap({ keystoreAddress: rep("11", 20), chainId: 8453, account: rep("22", 20), authDigest: "0x" + "0".repeat(61) + "abc",
    nullifyingKeyHash: "0x" + "0".repeat(61) + "def", deadline: "0x1234" }),
  sap({ keystoreAddress: "0x6d264aCb9C3A7A3105c29470AfE2F5F1EC203C73", chainId: 11155111, account: rep("11", 20),
    authDigest: "0x065e2c6cc08a36c4a943286bc91c216054a1981eb4f7570f67394ef8937a21b8",
    nullifyingKeyHash: "0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133", deadline: bigintToHex(1700000000n) }),
  sap({ keystoreAddress: rep("ff", 20), chainId: 1, account: EMPTY_ADDRESS, authDigest: "0x" + (P - 1n).toString(16),
    nullifyingKeyHash: "0x01", deadline: "0x0" }),
];

// --- witnesses (decimal, reduced) for the Rust typed inputs
const decWitness = (w: any): any => Array.isArray(w) ? w.map(decWitness) : typeof w === "object" ? Object.fromEntries(Object.entries(w).map(([k, v]) => [k, decWitness(v)])) : red(w as string);
const E = out.e2e[0];
const owner = E.address;
const nk = E.keys.privateNullifyingKey, rkey = E.keys.privateRevocableKey;
const token = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
function mkNote(secret: string, depSecret: string, value: bigint, ts: bigint, tok = token) {
  const v = bigintToHex(value);
  const nah = nc.computeNoteAddressHash(owner, secret);
  const label = nc.computeLabel(nc.computePrecommitment(nah, tok, v), depSecret);
  const commitment = nc.computeFullCommitment({ noteAddressHash: nah, tokenId: tok, value: v, label });
  return { noteAddressHash: nah, commitment, value: v, tokenId: tok, label, status: NoteStatus.ACTIVE, ownerAddress: owner,
    noteSecret: secret, isOwned: true, depositSecret: depSecret, createdAtBlock: bigintToHex(ts), spentAtBlock: null, txHash: rep("00", 32) };
}
function mkOut(o: string, secret: string, value: bigint, label: string) {
  const v = bigintToHex(value);
  const nah = nc.computeNoteAddressHash(o, secret);
  return { noteAddressHash: nah, commitment: nc.computeFullCommitment({ noteAddressHash: nah, tokenId: token, value: v, label }),
    value: v, tokenId: token, label, status: NoteStatus.PENDING, ownerAddress: o, noteSecret: secret, isOwned: true };
}
const n1 = mkNote(rep("a1", 32).slice(0, 4) + "1".repeat(62), rep("0b", 32), 3_000_000_000_000_000_000n, 1760000000n);
const n2 = mkNote(rep("0c", 32), rep("0d", 32), 2_000_000_000_000_000_000n, 1760000600n);
const ksLeaf = E.keystoreLeaf;
const stLeaf = (n: any) => (wps as any).computeTimestampedLeaf(n.commitment, n.createdAtBlock);
const nulLeaf = (h: string, ts: bigint) => hash.hash([NULLIFIER_LEAF_TAG, h, bigintToHex(ts)]);
const stateLeaves = [hint(5), stLeaf(n1), nulLeaf(hint(9), 1759999000n), hint(7), stLeaf(n2), hint(8)];
const keystoreLeaves = [hint(1), hint(2), ksLeaf, hint(3), hint(4)];
const aspLeaves = [nc.computeLabelHash(n2.label), hint(11), hint(12), hint(13), nc.computeLabelHash(n1.label)];

const depCtx = ctxs.computeDepositContext({ hint: rep("ab", 32), data: "0xdeadbeef" } as any);
out.witness = { owner, nk, rk: rkey, token, n1, n2, stateLeaves, keystoreLeaves, aspLeaves };
out.witness.deposit = decWitness(await wps.buildDepositWitness({ noteAddressHash: n1.noteAddressHash, tokenId: token,
  value: n1.value, context: depCtx, depositSecret: n1.depositSecret } as any));
out.witness.depositContext = depCtx;
const rq = await wps.buildRagequitWitness({ note: n1, ownerAddress: owner, privateNullifyingKey: nk, privateRevocableKey: rkey,
  tokenId: token, label: n1.label, keystoreLeaves } as any);
out.witness.ragequit = { witness: decWitness(rq.witness), nullifierHash: rq.nullifierHash, commitment: rq.commitment };

// 2x2: withdraw 1 ETH; change A = 2.5? -> recipient A 2.5 ETH(label n1) change B 1.5 ETH(label n2), amountOut 1 ETH
const recipient = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853";
const ch = mkOut(owner, rep("0e", 32), 1_500_000_000_000_000_000n, n2.label);
const rc = mkOut(recipient, rep("0f", 32), 2_500_000_000_000_000_000n, n1.label);
const txCtx = ctxs.computeTransactContext({ processor: rep("88", 20) as any, data: out.routings[3].encoded },
  [{ hint: rep("01", 32), data: rep("aa", 100) }, { hint: rep("02", 32), data: rep("bb", 100) }] as any);
const tw = await wps.buildTransactWitness({ inputNotes: [n1, n2], changeNotes: [ch], recipientNotes: [rc], ownerAddress: owner,
  privateNullifyingKey: nk, privateRevocableKey: rkey, tokenId: token, amountOut: bigintToHex(1_000_000_000_000_000_000n),
  tokenIdOut: token, context: txCtx, stateLeaves, keystoreLeaves, aspLeaves } as any);
out.witness.transact2x2 = { witness: decWitness(tw), context: txCtx, ch, rc,
  nullifiers: [n1, n2].map((n) => nc.computeNullifier(nk, n.commitment)) };

// 1x1 private transfer of all of n2 to recipient (amountOut 0, tokenIdOut 0) + zero change
const ch0 = mkOut(owner, rep("1e", 32), 0n, n2.label);
const rc0 = mkOut(recipient, rep("1f", 32), 2_000_000_000_000_000_000n, n2.label);
const tw2 = await wps.buildTransactWitness({ inputNotes: [n2], changeNotes: [ch0], recipientNotes: [rc0], ownerAddress: owner,
  privateNullifyingKey: nk, privateRevocableKey: rkey, tokenId: token, amountOut: "0x0",
  tokenIdOut: EMPTY_ADDRESS, context: txCtx, stateLeaves, keystoreLeaves, aspLeaves } as any);
out.witness.transfer1x2 = { witness: decWitness(tw2), ch0, rc0 };

console.log(JSON.stringify(out, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
