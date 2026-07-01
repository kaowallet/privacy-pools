//! Differential-testing helper: read a list of ops (JSON), compute each with the
//! Rust helpers, print the results (JSON). Paired with a bun harness that runs
//! the same ops through the 0xbow TypeScript SDK / @zk-kit/lean-imt.
//!
//!   cargo run --release --example differential -- ops.json

use privacy_pools::{
    commitment_hash, context, label, nullifier_hash, poseidon, precommitment, scope, Address,
    Field, LeanImt,
};
use serde_json::Value;

fn f(v: &Value) -> Field {
    Field::from_decimal(v.as_str().unwrap()).unwrap()
}

fn fields(v: &Value) -> Vec<Field> {
    v.as_array().unwrap().iter().map(f).collect()
}

fn addr(v: &Value) -> Address {
    Address::from_hex(v.as_str().unwrap()).unwrap()
}

fn u64v(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}

/// Account-derivation ops, only available with the `account` feature. Returns
/// `None` for non-account ops so the main `match` handles them.
#[cfg(feature = "account")]
fn account_op(op: &Value) -> Option<String> {
    use privacy_pools::Account;
    let pair = |(n, s): (Field, Field)| format!("{},{}", n.to_decimal(), s.to_decimal());
    let mnemonic = || op["mnemonic"].as_str().unwrap();
    let index = || op["index"].as_str().unwrap().parse::<u64>().unwrap();
    Some(match op["op"].as_str().unwrap() {
        "masterKeys" => {
            let k = Account::from_mnemonic(mnemonic()).unwrap().master_keys();
            format!("{},{}", k.nullifier.to_decimal(), k.secret.to_decimal())
        }
        "depositSecret" => pair(
            Account::from_mnemonic(mnemonic())
                .unwrap()
                .deposit_secrets(f(&op["scope"]), index())
                .unwrap(),
        ),
        "withdrawalSecret" => pair(
            Account::from_mnemonic(mnemonic())
                .unwrap()
                .withdrawal_secrets(f(&op["label"]), index())
                .unwrap(),
        ),
        _ => return None,
    })
}

#[cfg(not(feature = "account"))]
fn account_op(_: &Value) -> Option<String> {
    None
}

fn run(op: &Value) -> String {
    if let Some(s) = account_op(op) {
        return s;
    }
    match op["op"].as_str().unwrap() {
        "poseidon" => poseidon(&fields(&op["in"])).unwrap().to_decimal(),
        "nullifierHash" => nullifier_hash(f(&op["in"][0])).unwrap().to_decimal(),
        "precommitment" => precommitment(f(&op["in"][0]), f(&op["in"][1]))
            .unwrap()
            .to_decimal(),
        "commitment" => {
            let a = fields(&op["in"]);
            commitment_hash(a[0], a[1], a[2], a[3])
                .unwrap()
                .to_decimal()
        }
        "scope" => scope(addr(&op["pool"]), u64v(&op["chainId"]), addr(&op["asset"])).to_decimal(),
        "label" => label(f(&op["scope"]), u64v(&op["nonce"])).to_decimal(),
        "context" => {
            let data = hex::decode(op["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
            context(addr(&op["processooor"]), &data, f(&op["scope"])).to_decimal()
        }
        "leanRoot" => LeanImt::from_leaves(&fields(&op["leaves"]))
            .unwrap()
            .root()
            .unwrap()
            .to_decimal(),
        "leanProof" => {
            let tree = LeanImt::from_leaves(&fields(&op["leaves"])).unwrap();
            let p = tree
                .generate_proof(op["index"].as_u64().unwrap() as usize)
                .unwrap();
            let sibs: Vec<String> = p.siblings.iter().map(Field::to_decimal).collect();
            format!("{}:{}", p.index, sibs.join(","))
        }
        // Root after each successive insert (exercises depth growth / promotion
        // at every size, not just the final tree).
        "leanRootSeq" => {
            let leaves = fields(&op["leaves"]);
            let mut tree = LeanImt::new();
            let mut roots = Vec::with_capacity(leaves.len());
            for leaf in leaves {
                tree.insert(leaf).unwrap();
                roots.push(tree.root().unwrap().to_decimal());
            }
            roots.join(";")
        }
        // Membership proofs for many leaves of one tree (dedups the leaf array).
        "leanProofs" => {
            let tree = LeanImt::from_leaves(&fields(&op["leaves"])).unwrap();
            let proofs: Vec<String> = op["indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|idx| {
                    let p = tree.generate_proof(idx.as_u64().unwrap() as usize).unwrap();
                    let sibs: Vec<String> = p.siblings.iter().map(Field::to_decimal).collect();
                    format!("{}:{}", p.index, sibs.join(","))
                })
                .collect();
            proofs.join(";")
        }
        other => panic!("unknown op {other}"),
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: differential <ops.json>");
    let j: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let out: Vec<String> = j["ops"].as_array().unwrap().iter().map(run).collect();
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({ "out": out })).unwrap()
    );
}
