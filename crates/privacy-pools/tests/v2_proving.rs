//! Privacy Pools v2, stage 1: our wasmer-free proving pipeline against the v2
//! **ceremony** keys.
//!
//! `cargo xtask pull-circuits-v2` compiles the committed circomkit `main` files
//! with `build-circuit --O1` and stages the ppv2-ceremony zkeys/vkeys (sha256
//! pinned from upstream `CEREMONY.md`) under `artifacts/v2/`. Upstream warns
//! that recompiling a circuit can renumber its wires, after which proofs stop
//! verifying. These tests are what shows our graphs line up with the ceremony
//! keys. Each one builds a *valid* witness from first principles (the v2 note
//! math below plus LeanIMT trees), proves it, and asserts:
//!
//! - every public signal equals the value computed independently here;
//! - the proof verifies under the zkey's vk AND the standalone ceremony
//!   `groth16_vkey.json`;
//! - bumping any single public signal makes verification fail.
//!
//! v2 protocol math (`packages/circuits/circuits/templates`, monorepo v1.0.2):
//!
//! - `noteAddressHash = P(ownerAddress, noteSecret)`
//! - `precommitment   = P(noteAddressHash, tokenId, value, metadata = 0)`
//! - `label           = P(precommitment, depositSecret)` (fixed at deposit)
//! - `commitment      = P(precommitment, label)`
//! - `nullifierHash   = P(privateNullifyingKey, commitment)`
//! - state leaf       = `P(COMMITMENT_LEAF_TAG, commitment, timestamp)`
//! - ASP leaf         = `P(label)`
//! - keystore leaf    = `P(ownerAddress, P(privateNullifyingKey), P(0, privateRevocableKey))`
//!
//! The Merkle proofs feed zk-kit's `BinaryMerkleRoot`, which takes a LeanIMT
//! proof as is: real siblings only, path-derived index, `depth = #siblings`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use privacy_pools::v2::{self, CircuitStore, ASP_MAX_DEPTH, KEYSTORE_MAX_DEPTH, STATE_MAX_DEPTH};
use privacy_pools::{poseidon, Field, Groth16Proof, LeanImt, MerkleProof, Prover, Verifier};
use serde_json::{json, Value};

/// `COMMITMENT_LEAF_TAG` (`Transact.circom`, mirrored in `Constants.sol`).
const COMMITMENT_LEAF_TAG: &str =
    "3791694183000795315792098099581407680958131641292811872617553086713867485913";

const OWNER: &str = "0x8ba1f109551bD432803012645Ac136ddd64DBA72";
const RECIPIENT: &str = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853";
/// Sepolia USDC; any 160-bit address works as a `tokenId`.
const TOKEN: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";

const ETHER: u128 = 1_000_000_000_000_000_000;

// --- artifacts ---------------------------------------------------------------

struct V2Circuit {
    prover: Prover,
    verifier: Verifier,
}

/// The staged `pull-circuits-v2` output. With `partial-bundled-v2` the store
/// serves the embedded artifacts first, so that path is what gets exercised.
fn store() -> CircuitStore {
    CircuitStore::new(Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/v2"))
}

fn load_from(store: &CircuitStore, circuit: v2::Circuit) -> V2Circuit {
    let name = circuit.name();
    let hint = "run `cargo xtask pull-circuits-v2`";
    let prover = store
        .prover(circuit)
        .unwrap_or_else(|e| panic!("loading {name} prover: {e}; {hint}"));
    let verifier = store
        .verifier(circuit)
        .unwrap_or_else(|e| panic!("loading {name} vkey: {e}; {hint}"));
    assert_eq!(
        prover.num_public(),
        circuit.num_public(),
        "{name}: zkey nPublic"
    );
    assert_eq!(
        verifier.num_public(),
        circuit.num_public(),
        "{name}: vkey nPublic"
    );
    V2Circuit { prover, verifier }
}

/// Parsed once per circuit per test binary.
fn circuit(c: v2::Circuit) -> &'static V2Circuit {
    static CACHE: OnceLock<Mutex<HashMap<v2::Circuit, &'static V2Circuit>>> = OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap();
    if let Some(&loaded) = cache.get(&c) {
        return loaded;
    }
    let loaded: &'static V2Circuit = Box::leak(Box::new(load_from(&store(), c)));
    cache.insert(c, loaded);
    loaded
}

fn transact(inputs: u8, outputs: u8) -> v2::Circuit {
    v2::Circuit::Transact { inputs, outputs }
}

impl V2Circuit {
    /// Prove `inputs`, then check signals, both verifiers and tamper rejection.
    fn prove_and_check(&self, inputs: &Value, expected: &[Field]) -> Groth16Proof {
        let proof = self.prover.prove(&inputs.to_string()).expect("prove");
        let signals: Vec<Field> = proof
            .public_signals
            .iter()
            .copied()
            .map(Field::from)
            .collect();
        assert_eq!(signals, expected, "public signals");

        assert!(
            self.prover.verify(&proof).unwrap(),
            "zkey vk rejected the proof"
        );
        assert!(
            self.verifier.verify(&proof).unwrap(),
            "ceremony vkey rejected the proof"
        );

        for i in 0..proof.public_signals.len() {
            let mut tampered = proof.clone();
            tampered.public_signals[i] += Field::from(1u8).into_fr();
            assert!(
                !self.verifier.verify(&tampered).unwrap(),
                "tampered public signal {i} still verified"
            );
        }
        proof
    }
}

// --- v2 note math ----------------------------------------------------------------

fn h(inputs: &[Field]) -> Field {
    poseidon(inputs).expect("poseidon")
}

/// Deterministic full-width field elements for secrets/keys/fillers.
fn rnd(i: u64) -> Field {
    h(&[Field::from(0x5eed_u64), Field::from(i)])
}

fn addr(hex: &str) -> Field {
    Field::from_hex(hex).expect("address")
}

fn precommitment(note_address_hash: Field, token: Field, value: Field) -> Field {
    h(&[note_address_hash, token, value, Field::ZERO])
}

fn deposit_label(
    note_address_hash: Field,
    token: Field,
    value: Field,
    deposit_secret: Field,
) -> Field {
    h(&[
        precommitment(note_address_hash, token, value),
        deposit_secret,
    ])
}

fn note_commitment(note_address_hash: Field, token: Field, value: Field, label: Field) -> Field {
    h(&[precommitment(note_address_hash, token, value), label])
}

fn keystore_leaf(owner: Field, nullifying_key: Field, revocable_key: Field) -> Field {
    h(&[
        owner,
        h(&[nullifying_key]),
        h(&[Field::ZERO, revocable_key]),
    ])
}

fn state_leaf(commitment: Field, timestamp: u64) -> Field {
    let tag = Field::from_decimal(COMMITMENT_LEAF_TAG).unwrap();
    h(&[tag, commitment, Field::from(timestamp)])
}

/// A LeanIMT holding `leaf` at position `pos` among `n - 1` filler leaves.
fn tree_with(leaf: Field, n: usize, pos: usize, seed: u64) -> MerkleProof {
    let leaves: Vec<Field> = (0..n)
        .map(|i| if i == pos { leaf } else { rnd(seed + i as u64) })
        .collect();
    LeanImt::from_leaves(&leaves)
        .unwrap()
        .generate_proof(pos)
        .unwrap()
}

// --- circuit input JSON -------------------------------------------------------

fn dec(x: Field) -> Value {
    Value::String(x.to_decimal())
}

fn padded(proof: &MerkleProof, max_depth: usize) -> Value {
    assert!(
        proof.siblings.len() <= max_depth,
        "proof deeper than circuit"
    );
    let mut siblings: Vec<Value> = proof.siblings.iter().copied().map(dec).collect();
    siblings.resize(max_depth, dec(Field::ZERO));
    Value::Array(siblings)
}

fn depth(proof: &MerkleProof) -> Value {
    dec(Field::from(proof.siblings.len() as u64))
}

// --- deposit -----------------------------------------------------------------

#[test]
fn v2_deposit_prove_and_verify() {
    let token = addr(TOKEN);
    let value = Field::from(ETHER);
    let (note_secret, deposit_secret, context) = (rnd(1), rnd(2), rnd(3));

    let note_address_hash = h(&[addr(OWNER), note_secret]);
    let label = deposit_label(note_address_hash, token, value, deposit_secret);
    let commitment = note_commitment(note_address_hash, token, value, label);

    let inputs = json!({
        "tokenId": dec(token),
        "value": dec(value),
        "context": dec(context),
        "noteAddressHash": dec(note_address_hash),
        "depositSecret": dec(deposit_secret),
    });
    circuit(v2::Circuit::Deposit).prove_and_check(&inputs, &[commitment, token, value, context]);
}

// --- ragequit ----------------------------------------------------------------

#[test]
fn v2_ragequit_prove_and_verify() {
    let owner = addr(OWNER);
    let token = addr(TOKEN);
    let value = Field::from(7 * ETHER / 4);
    let (nullifying_key, revocable_key) = (rnd(10), rnd(11));
    let (note_secret, deposit_secret) = (rnd(12), rnd(13));

    let note_address_hash = h(&[owner, note_secret]);
    let label = deposit_label(note_address_hash, token, value, deposit_secret);
    let commitment = note_commitment(note_address_hash, token, value, label);
    let nullifier = h(&[nullifying_key, commitment]);
    let leaf = keystore_leaf(owner, nullifying_key, revocable_key);

    // (5, 4): last leaf of a 5-leaf tree, promoted twice (1 real sibling).
    // (7, 2): interior leaf with a full path. (1, 0): single-leaf tree, depth 0.
    for (n, pos) in [(5, 4), (7, 2), (1, 0)] {
        let keystore = tree_with(leaf, n, pos, 1000);
        let inputs = json!({
            "keystoreRoot": dec(keystore.root),
            "ownerAddress": dec(owner),
            "value": dec(value),
            "tokenId": dec(token),
            "label": dec(label),
            "noteSecret": dec(note_secret),
            "metadata": "0",
            "privateNullifyingKey": dec(nullifying_key),
            "privateRevocableKey": dec(revocable_key),
            "keystoreLeafIndex": dec(Field::from(keystore.index)),
            "keystoreSiblings": padded(&keystore, KEYSTORE_MAX_DEPTH),
            "keystoreTreeDepth": depth(&keystore),
        });
        circuit(v2::Circuit::Ragequit).prove_and_check(
            &inputs,
            &[
                nullifier,
                commitment,
                keystore.root,
                owner,
                value,
                token,
                label,
            ],
        );
    }
}

// --- transact -----------------------------------------------------------------

/// A note owned by `OWNER`, as created by a deposit and inserted at `timestamp`.
struct InputNote {
    secret: Field,
    value: Field,
    label: Field,
    commitment: Field,
    timestamp: u64,
}

fn input_note(value: u128, secret: Field, deposit_secret: Field, timestamp: u64) -> InputNote {
    let token = addr(TOKEN);
    let value = Field::from(value);
    let note_address_hash = h(&[addr(OWNER), secret]);
    let label = deposit_label(note_address_hash, token, value, deposit_secret);
    InputNote {
        secret,
        value,
        label,
        commitment: note_commitment(note_address_hash, token, value, label),
        timestamp,
    }
}

struct OutputNote {
    note_address_hash: Field,
    value: Field,
    label: Field,
}

fn output(owner: &str, secret: Field, value: u128, label: Field) -> OutputNote {
    OutputNote {
        note_address_hash: h(&[addr(owner), secret]),
        value: Field::from(value),
        label,
    }
}

/// Valid `Transact(n, m, 22, 18, 18)` inputs spending `notes` into `outputs`
/// (`n = notes.len()`, `m = outputs.len()`), plus the public signals they must
/// produce.
fn transact_inputs(
    notes: &[InputNote],
    outputs: &[OutputNote],
    amount_out: Field,
    token_id_out: Field,
) -> (Value, Vec<Field>) {
    let owner = addr(OWNER);
    let token = addr(TOKEN);
    let context = rnd(20);
    let (nullifying_key, revocable_key) = (rnd(21), rnd(22));

    let keystore = tree_with(
        keystore_leaf(owner, nullifying_key, revocable_key),
        6,
        3,
        2000,
    );

    // State tree: each note's timestamped leaf at an odd position among fillers
    // (stand-ins for other commitment and nullifier leaves); ASP tree: each
    // label's `P(label)` every third position.
    let state_pos: Vec<usize> = (0..notes.len()).map(|i| 2 * i + 1).collect();
    let mut state_leaves: Vec<Field> = (0..2 * notes.len() + 3)
        .map(|i| rnd(3000 + i as u64))
        .collect();
    for (note, &pos) in notes.iter().zip(&state_pos) {
        state_leaves[pos] = state_leaf(note.commitment, note.timestamp);
    }
    let state = LeanImt::from_leaves(&state_leaves).unwrap();
    let state_proofs: Vec<MerkleProof> = state_pos
        .iter()
        .map(|&pos| state.generate_proof(pos).unwrap())
        .collect();

    let asp_pos: Vec<usize> = (0..notes.len()).map(|i| 3 * i).collect();
    let mut asp_leaves: Vec<Field> = (0..3 * notes.len() + 1)
        .map(|i| rnd(4000 + i as u64))
        .collect();
    for (note, &pos) in notes.iter().zip(&asp_pos) {
        asp_leaves[pos] = h(&[note.label]);
    }
    let asp = LeanImt::from_leaves(&asp_leaves).unwrap();
    let asp_proofs: Vec<MerkleProof> = asp_pos
        .iter()
        .map(|&pos| asp.generate_proof(pos).unwrap())
        .collect();

    let state_root = state.root().unwrap();
    let asp_root = asp.root().unwrap();

    let inputs = json!({
        "stateRoot": dec(state_root),
        "keystoreRoot": dec(keystore.root),
        "associationSetRoot": dec(asp_root),
        "amountOut": dec(amount_out),
        "tokenIdOut": dec(token_id_out),
        "context": dec(context),

        "ownerAddress": dec(owner),
        "privateNullifyingKey": dec(nullifying_key),
        "privateRevocableKey": dec(revocable_key),
        "keystoreLeafIndex": dec(Field::from(keystore.index)),
        "keystoreSiblings": padded(&keystore, KEYSTORE_MAX_DEPTH),
        "keystoreTreeDepth": depth(&keystore),

        "noteSecret": notes.iter().map(|n| dec(n.secret)).collect::<Vec<_>>(),
        "value": notes.iter().map(|n| dec(n.value)).collect::<Vec<_>>(),
        "label": notes.iter().map(|n| dec(n.label)).collect::<Vec<_>>(),
        "tokenId": dec(token),
        "stateLeafIndex": state_proofs.iter().map(|p| dec(Field::from(p.index))).collect::<Vec<_>>(),
        "stateSiblings": state_proofs.iter().map(|p| padded(p, STATE_MAX_DEPTH)).collect::<Vec<_>>(),
        "stateTreeDepth": state_proofs.iter().map(depth).collect::<Vec<_>>(),
        "associationSetLeafIndex": asp_proofs.iter().map(|p| dec(Field::from(p.index))).collect::<Vec<_>>(),
        "associationSetSiblings": asp_proofs.iter().map(|p| padded(p, ASP_MAX_DEPTH)).collect::<Vec<_>>(),
        "associationSetTreeDepth": asp_proofs.iter().map(depth).collect::<Vec<_>>(),
        "timestamp": notes.iter().map(|n| dec(Field::from(n.timestamp))).collect::<Vec<_>>(),

        "outputNoteAddressHash": outputs.iter().map(|o| dec(o.note_address_hash)).collect::<Vec<_>>(),
        "outputValue": outputs.iter().map(|o| dec(o.value)).collect::<Vec<_>>(),
        "outputLabel": outputs.iter().map(|o| dec(o.label)).collect::<Vec<_>>(),
    });

    let mut expected: Vec<Field> = notes
        .iter()
        .map(|n| h(&[nullifying_key, n.commitment]))
        .collect();
    expected.extend(
        outputs
            .iter()
            .map(|o| note_commitment(o.note_address_hash, token, o.value, o.label)),
    );
    expected.extend([
        state_root,
        keystore.root,
        asp_root,
        amount_out,
        token_id_out,
        context,
    ]);
    (inputs, expected)
}

/// A valid withdrawal for any `n x m` shape: `n` notes worth `i + 1` ETH, each
/// with its own label; output `j` takes label `j mod n` and an equal share of
/// that label's value (keeping a share back); everything left is withdrawn.
fn withdrawal(n: u8, m: u8) -> (Value, Vec<Field>) {
    let notes: Vec<InputNote> = (0..n as u64)
        .map(|i| {
            input_note(
                (i as u128 + 1) * ETHER,
                rnd(100 + i),
                rnd(200 + i),
                1_760_000_000 + 60 * i,
            )
        })
        .collect();
    let per_label = |i: usize| (0..m as usize).filter(|j| j % n as usize == i).count() as u128;
    let share = |i: usize| (i as u128 + 1) * ETHER / (per_label(i) + 1);
    let outputs: Vec<OutputNote> = (0..m as usize)
        .map(|j| {
            let i = j % n as usize;
            output(RECIPIENT, rnd(300 + j as u64), share(i), notes[i].label)
        })
        .collect();
    let total_in: u128 = (1..=n as u128).map(|v| v * ETHER).sum();
    let total_out: u128 = (0..m as usize).map(|j| share(j % n as usize)).sum();
    transact_inputs(
        &notes,
        &outputs,
        Field::from(total_in - total_out),
        addr(TOKEN),
    )
}

/// The bundled transact shape, end to end against the ceremony keys.
#[test]
fn v2_transact_1x1_withdrawals_prove_and_verify() {
    assert!(transact(1, 1).is_bundled());
    let circuit = circuit(transact(1, 1));

    // Partial: a 1 ETH note -> 0.5 ETH change note + 0.5 ETH withdrawn.
    let (inputs, expected) = withdrawal(1, 1);
    circuit.prove_and_check(&inputs, &expected);

    // Full: the whole note withdrawn plus the zero-value change note the
    // official SDK always emits.
    let notes = [input_note(2 * ETHER, rnd(70), rnd(71), 1_760_000_000)];
    let outputs = [output(OWNER, rnd(72), 0, notes[0].label)];
    let (inputs, expected) = transact_inputs(&notes, &outputs, Field::from(2 * ETHER), addr(TOKEN));
    circuit.prove_and_check(&inputs, &expected);
}

/// The pipeline must not turn an unsatisfiable witness into a verifying proof:
/// creating value (out > in) has to fail either at witness time or at verify.
#[test]
fn v2_transact_rejects_value_creation() {
    let notes = [input_note(3 * ETHER, rnd(60), rnd(61), 1_760_000_000)];
    let outputs = [output(RECIPIENT, rnd(62), 3 * ETHER + 1, notes[0].label)];
    let (inputs, _) = transact_inputs(&notes, &outputs, Field::ZERO, Field::ZERO);
    let circuit = circuit(transact(1, 1));
    if let Ok(proof) = circuit.prover.prove(&inputs.to_string()) {
        assert!(
            !circuit.verifier.verify(&proof).unwrap(),
            "value creation verified"
        );
    }
}

// --- every circuit, downloaded from GitHub ------------------------------------

/// Downloads the 24 non-bundled zkeys (~984 MB, kept in `target/tmp` across
/// runs) from GitHub and proves + verifies every `transact_NxM` against the
/// ceremony keys — the check that all 27 embedded graphs match — plus a
/// two-label withdrawal and a private transfer on `transact_2x2`.
///
/// `just test-v2-download`, i.e.
/// `cargo test --release --features download --test v2_proving -- --ignored`
#[cfg(feature = "download")]
#[test]
#[ignore = "downloads ~984 MB from GitHub"]
fn v2_all_circuits_download_prove_verify() {
    use std::ops::ControlFlow;

    let store = CircuitStore::new(Path::new(env!("CARGO_TARGET_TMPDIR")).join("v2-store"));
    let mut last = 0;
    store
        .download(v2::Circuit::all(), |p| {
            if p.done - last >= 50 << 20 || p.done == p.total {
                eprintln!("downloaded {} / {} MB", p.done >> 20, p.total >> 20);
                last = p.done;
            }
            ControlFlow::Continue(())
        })
        .expect("download");
    assert!(store.missing(v2::Circuit::all()).unwrap().is_empty());

    for n in 1..=v2::MAX_TRANSACT_NOTES {
        for m in 1..=v2::MAX_TRANSACT_NOTES {
            let (inputs, expected) = withdrawal(n, m);
            load_from(&store, transact(n, m)).prove_and_check(&inputs, &expected);
            eprintln!("transact_{n}x{m} ✔");
        }
    }

    let transact_2x2 = load_from(&store, transact(2, 2));
    let notes = [
        input_note(3 * ETHER, rnd(30), rnd(31), 1_760_000_000),
        input_note(2 * ETHER, rnd(32), rnd(33), 1_760_000_600),
    ];

    // 5 ETH in = 2.5 (to RECIPIENT, label A) + 1.5 (change, label B) + 1 withdrawn.
    let outputs = [
        output(RECIPIENT, rnd(40), 5 * ETHER / 2, notes[0].label),
        output(OWNER, rnd(41), 3 * ETHER / 2, notes[1].label),
    ];
    let (inputs, expected) = transact_inputs(&notes, &outputs, Field::from(ETHER), addr(TOKEN));
    transact_2x2.prove_and_check(&inputs, &expected);

    // Pure transfer: amountOut = 0 and tokenIdOut = 0, values move label-for-label.
    let outputs = [
        output(RECIPIENT, rnd(50), 3 * ETHER, notes[0].label),
        output(OWNER, rnd(51), 2 * ETHER, notes[1].label),
    ];
    let (inputs, expected) = transact_inputs(&notes, &outputs, Field::ZERO, Field::ZERO);
    transact_2x2.prove_and_check(&inputs, &expected);
    eprintln!("transact_2x2 withdrawal + private transfer ✔");
}
