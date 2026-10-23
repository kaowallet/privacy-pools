//! Differential-testing helper for Privacy Pools v2: read a list of ops (JSON),
//! compute each with the Rust `v2` module, print the results (JSON). Paired
//! with `validation/differential-v2/differential.ts`, which runs the same ops
//! through `@0xbow/privacy-pools-v2-sdk@1.0.2` / viem and compares line by line.
//!
//!   cargo run -q --release --features keys-v2 --example differential_v2 -- cases.json
//!
//! Conventions (shared with the TS side):
//! - inputs: field elements and integers are decimal strings, addresses and
//!   byte strings are `0x` hex;
//! - outputs: field elements are decimal unless the op says hex (keys and
//!   digests are `0x` + 64 lowercase hex), multi-value results are joined by
//!   `,`, witness results are canonical JSON (sorted keys);
//! - a library `Err` prints `ERR: <message>`, a panic `PANIC: <message>`.

use std::panic::{catch_unwind, AssertUnwindSafe};

use privacy_pools::v2::{
    self, note, CircuitInputs, DepositInputs, Note, NoteData, OutputNote, RagequitInputs,
    SetAuthPolicy, SpendNote, TransactInputs, TransactParams,
};
use privacy_pools::{Address, Field, LeanImt, Result};
use serde_json::{json, Value};

fn s(v: &Value) -> &str {
    v.as_str()
        .unwrap_or_else(|| panic!("expected a string, got {v}"))
}

fn f(v: &Value) -> Field {
    Field::from_decimal(s(v)).unwrap()
}

fn fields(v: &Value) -> Vec<Field> {
    v.as_array().unwrap().iter().map(f).collect()
}

fn addr(v: &Value) -> Address {
    Address::from_hex(s(v)).unwrap()
}

fn u64v(v: &Value) -> u64 {
    s(v).parse().unwrap()
}

fn u128v(v: &Value) -> u128 {
    s(v).parse().unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(s(v).trim_start_matches("0x")).unwrap()
}

fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

fn hex32(b: [u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn hexf(x: Field) -> String {
    hex32(x.to_bytes_be())
}

fn dec(x: Field) -> String {
    x.to_decimal()
}

fn decs(xs: &[Field]) -> Vec<String> {
    xs.iter().map(|x| x.to_decimal()).collect()
}

/// Canonical JSON: object keys sorted (recursively), no whitespace.
fn canon(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let body: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), canon(&m[k])))
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(canon).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

fn note_data(v: &Value) -> NoteData {
    NoteData {
        hint: b32(&v["hint"]),
        data: bytes(&v["data"]),
    }
}

fn note_datas(v: &Value) -> Vec<NoteData> {
    v.as_array().unwrap().iter().map(note_data).collect()
}

fn tree(v: &Value) -> LeanImt {
    LeanImt::from_leaves(&fields(v)).unwrap()
}

/// `{input, publicSignals, validate}` for a set of circuit inputs.
fn witness_result(inputs: &dyn CircuitInputs) -> Result<String> {
    let validate = match inputs.validate() {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("err: {e}"),
    };
    Ok(canon(&json!({
        "input": inputs.to_input_value()?,
        "publicSignals": decs(&inputs.public_signals()?),
        "validate": validate,
    })))
}

/// Key-derivation ops, only available with the `keys-v2` feature.
#[cfg(feature = "keys-v2")]
fn keys_op(op: &Value) -> Result<String> {
    let signer = addr(&op["signer"]);
    let k = v2::Keys::from_signature(&bytes(&op["sig"]), signer, u64v(&op["index"]))?;
    let k2 = k.with_revocable_key_index(u64v(&op["index2"]));
    Ok([
        hexf(k.nullifying_key()),
        hexf(k.revocable_key()),
        hex32(k.viewing_private_key()),
        hex32(k.viewing_public_key()),
        hexf(k.nullifying_key_hash()?),
        hexf(k.auth_digest()?),
        hexf(k.keystore_leaf(signer)?),
        hexf(k2.revocable_key()),
        hexf(k2.auth_digest()?),
        hexf(k2.keystore_leaf(signer)?),
        k2.revocable_key_index().to_string(),
    ]
    .join(","))
}

#[cfg(not(feature = "keys-v2"))]
fn keys_op(_: &Value) -> Result<String> {
    panic!("the keys op needs --features keys-v2")
}

fn run(op: &Value) -> Result<String> {
    Ok(match s(&op["op"]) {
        // --- constants -----------------------------------------------------------
        "constants" => [
            format!("0x{}", hex::encode(v2::NATIVE_ASSET.0)),
            v2::APP_IDENTIFIER.to_string(),
            v2::STATE_MAX_DEPTH.to_string(),
            v2::KEYSTORE_MAX_DEPTH.to_string(),
            v2::ASP_MAX_DEPTH.to_string(),
            v2::MAX_TRANSACT_NOTES.to_string(),
            dec(note::commitment_leaf_tag()),
            dec(note::nullifier_leaf_tag()),
            note::AUTH_TYPE_DIRECT_KEY.to_string(),
        ]
        .join(","),

        // --- keys / EIP-712 ------------------------------------------------------
        "keys" => keys_op(op)?,
        "addressHash" => hex32(v2::address_hash(addr(&op["signer"]))),
        "sdDigest" => hex32(v2::secret_derivation_digest(addr(&op["signer"]))),
        "sdTypedData" => canon(&v2::secret_derivation_typed_data(addr(&op["signer"]))),
        "setAuthPolicy" => hex32(
            SetAuthPolicy {
                keystore: addr(&op["keystore"]),
                chain_id: u64v(&op["chainId"]),
                account: addr(&op["account"]),
                auth_digest: f(&op["authDigest"]),
                nullifying_key_hash: f(&op["nullifyingKeyHash"]),
                deadline: u64v(&op["deadline"]),
            }
            .digest(),
        ),

        // --- note math -----------------------------------------------------------
        "secretFromEntropy" => {
            let e: [u8; 48] = bytes(&op["entropy"]).try_into().unwrap();
            hexf(v2::secret_from_entropy(&e))
        }
        "noteAddressHash" => dec(note::note_address_hash(addr(&op["owner"]), f(&op["secret"]))?),
        "precommitment" => dec(note::precommitment(
            f(&op["nah"]),
            addr(&op["token"]),
            u128v(&op["value"]),
        )?),
        "depositLabel" => dec(note::deposit_label(f(&op["pre"]), f(&op["depositSecret"]))?),
        "commitment" => dec(note::commitment(f(&op["pre"]), f(&op["label"]))?),
        "nullifierHash" => dec(note::nullifier_hash(f(&op["nk"]), f(&op["commitment"]))?),
        "nullifyingKeyHash" => dec(note::nullifying_key_hash(f(&op["nk"]))?),
        "authDigest" => dec(note::auth_digest(f(&op["rk"]))?),
        "keystoreLeaf" => dec(note::keystore_leaf(
            addr(&op["owner"]),
            note::nullifying_key_hash(f(&op["nk"]))?,
            note::auth_digest(f(&op["rk"]))?,
        )?),
        "commitmentLeaf" => dec(note::commitment_leaf(f(&op["commitment"]), u64v(&op["ts"]))?),
        "nullifierLeaf" => dec(note::nullifier_leaf(f(&op["nullifierHash"]), u64v(&op["ts"]))?),
        "aspLeaf" => dec(note::asp_leaf(f(&op["label"]))?),
        "outputCommitment" => dec(OutputNote {
            note_address_hash: f(&op["nah"]),
            value: u128v(&op["value"]),
            label: f(&op["label"]),
        }
        .commitment(addr(&op["token"]))?),
        // A deposit note end to end: every derived value plus its spend.
        "noteDeposit" => {
            let token = addr(&op["token"]);
            let n = Note::deposit(
                addr(&op["owner"]),
                token,
                u128v(&op["value"]),
                f(&op["secret"]),
                f(&op["depositSecret"]),
            )?;
            let nk = f(&op["nk"]);
            let ts = u64v(&op["ts"]);
            let commitment = n.commitment()?;
            [
                dec(n.note_address_hash()?),
                dec(n.precommitment()?),
                dec(n.label),
                dec(commitment),
                dec(n.nullifier_hash(nk)?),
                dec(n.commitment_leaf(ts)?),
                dec(note::nullifier_leaf(n.nullifier_hash(nk)?, ts)?),
                dec(n.asp_leaf()?),
                dec(n.as_output()?.commitment(token)?),
            ]
            .join(",")
        }

        // --- context -------------------------------------------------------------
        "emptyDepositContext" => dec(v2::deposit_context(&NoteData::EMPTY)),
        "depositContext" => dec(v2::deposit_context(&note_data(&op["noteData"]))),
        "transactContext" => dec(v2::transact_context(
            &TransactParams {
                processor: addr(&op["processor"]),
                data: bytes(&op["data"]),
            },
            &note_datas(&op["noteData"]),
        )),
        "payoutRouting" => format!(
            "0x{}",
            hex::encode(v2::payout_routing_data(
                addr(&op["recipient"]),
                addr(&op["feeRecipient"]),
                u128v(&op["feeAmount"]),
                u128v(&op["nativeGas"]),
            ))
        ),

        // --- Merkle --------------------------------------------------------------
        "binaryMerkleRoot" => dec(v2::binary_merkle_root(
            f(&op["leaf"]),
            u64v(&op["index"]),
            &fields(&op["siblings"]),
        )?),

        // --- witnesses -----------------------------------------------------------
        "depositWitness" => {
            let deposit_secret = f(&op["depositSecret"]);
            let n = Note::deposit(
                addr(&op["owner"]),
                addr(&op["token"]),
                u128v(&op["value"]),
                f(&op["secret"]),
                deposit_secret,
            )?;
            let context = v2::deposit_context(&note_data(&op["noteData"]));
            witness_result(&DepositInputs::new(&n, deposit_secret, context)?)?
        }
        "ragequitWitness" => {
            let n = Note {
                owner: addr(&op["owner"]),
                secret: f(&op["secret"]),
                token: addr(&op["token"]),
                value: u128v(&op["value"]),
                label: f(&op["label"]),
            };
            witness_result(&RagequitInputs::from_trees(
                &n,
                f(&op["nk"]),
                f(&op["rk"]),
                &tree(&op["keystoreLeaves"]),
            )?)?
        }
        "transactWitness" => {
            let (owner, token) = (addr(&op["owner"]), addr(&op["token"]));
            let notes: Vec<SpendNote> = op["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| SpendNote {
                    note: Note {
                        owner,
                        secret: f(&i["secret"]),
                        token,
                        value: u128v(&i["value"]),
                        label: f(&i["label"]),
                    },
                    timestamp: u64v(&i["ts"]),
                })
                .collect();
            let outputs: Vec<OutputNote> = op["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| OutputNote {
                    note_address_hash: f(&o["nah"]),
                    value: u128v(&o["value"]),
                    label: f(&o["label"]),
                })
                .collect();
            let context = v2::transact_context(
                &TransactParams {
                    processor: addr(&op["processor"]),
                    data: bytes(&op["data"]),
                },
                &note_datas(&op["noteData"]),
            );
            witness_result(&TransactInputs::from_trees(
                &notes,
                outputs,
                u128v(&op["amountOut"]),
                context,
                f(&op["nk"]),
                f(&op["rk"]),
                &tree(&op["stateLeaves"]),
                &tree(&op["keystoreLeaves"]),
                &tree(&op["aspLeaves"]),
            )?)?
        }
        other => panic!("unknown op {other}"),
    })
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: differential_v2 <cases.json>");
    let j: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let out: Vec<String> = j["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|op| match catch_unwind(AssertUnwindSafe(|| run(op))) {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => format!("ERR: {e}"),
            Err(p) => {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                format!("PANIC: {msg}")
            }
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string(&json!({ "out": out })).unwrap()
    );
}
