//! The v2 proof `context`: what a deposit or transact proof is bound to.
//!
//! Mirrors `PoolVault.sol` (monorepo v1.0.2):
//! ```solidity
//! deposit:  context == uint256(keccak256(abi.encode(noteData)))                 % p;
//! transact: context == uint256(keccak256(abi.encode(transactParams, noteData))) % p;
//! ```
//! with `NoteData { bytes32 hint; bytes data; }` and
//! `TransactParams { address processor; bytes data; }`. The SDK hands the
//! unreduced keccak to snarkjs, which reduces it; we reduce here because the
//! witness generator rejects inputs ≥ 2^254.
//!
//! The `NoteData` and `TransactParams` passed here must be exactly the ones sent
//! on-chain (same count, order and bytes), or the proof is rejected.

use crate::context::{keccak256, word, Address};
use crate::field::Field;

/// An encrypted note announcement emitted with a deposit or transact output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoteData {
    /// Discovery hint (random, or a recipient-chosen tag).
    pub hint: [u8; 32],
    /// `ephemeralPub(32) ‖ nonce(24) ‖ XChaCha20-Poly1305 ciphertext ‖ tag(16)`.
    pub data: Vec<u8>,
}

impl NoteData {
    /// `{hint: 0x00…, data: 0x}` — the SDK's `EMPTY_NOTE_DATA`, used by a
    /// deposit with no recipient viewing key.
    pub const EMPTY: NoteData = NoteData {
        hint: [0; 32],
        data: Vec::new(),
    };
}

/// Who may submit a transact proof and how a withdrawal is paid out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactParams {
    /// The only address allowed to submit the proof.
    pub processor: Address,
    /// Processor-specific data, e.g. [`payout_routing_data`] for the relay.
    pub data: Vec<u8>,
}

/// `keccak256(abi.encode(noteData)) % p` — a deposit's context.
pub fn deposit_context(note_data: &NoteData) -> Field {
    let mut buf = word(0x20).to_vec(); // offset of the (dynamic) tuple
    encode_note_data(&mut buf, note_data);
    Field::from_bytes_be(&keccak256(&buf))
}

/// `keccak256(abi.encode(transactParams, noteData)) % p` — a transact's context.
///
/// `note_data` holds one entry per announced output, in output order.
pub fn transact_context(params: &TransactParams, note_data: &[NoteData]) -> Field {
    // head: offsets of the two dynamic parameters
    let params_len = 3 * 32 + padded_len(params.data.len());
    let mut buf = word(0x40).to_vec();
    buf.extend_from_slice(&word((0x40 + params_len) as u64));
    // TransactParams tuple
    buf.extend_from_slice(&address_word(params.processor));
    buf.extend_from_slice(&word(0x40)); // offset of `data`, relative to the tuple
    encode_bytes(&mut buf, &params.data);
    // NoteData[]: length, element offsets (relative to after the length), elements
    buf.extend_from_slice(&word(note_data.len() as u64));
    let mut offset = 32 * note_data.len();
    for nd in note_data {
        buf.extend_from_slice(&word(offset as u64));
        offset += 3 * 32 + padded_len(nd.data.len());
    }
    for nd in note_data {
        encode_note_data(&mut buf, nd);
    }
    Field::from_bytes_be(&keccak256(&buf))
}

/// `abi.encode((address recipient, address feeRecipient, uint256 feeAmount,
/// uint256 nativeGas))` — the `TransactParams.data` the relay decodes to pay a
/// withdrawal (`EvmPayoutRoutingCodec`).
pub fn payout_routing_data(
    recipient: Address,
    fee_recipient: Address,
    fee_amount: u128,
    native_gas: u128,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 * 32);
    buf.extend_from_slice(&address_word(recipient));
    buf.extend_from_slice(&address_word(fee_recipient));
    buf.extend_from_slice(&u128_word(fee_amount));
    buf.extend_from_slice(&u128_word(native_gas));
    buf
}

/// `hint | 0x40 | len | data (right-padded)` — one `NoteData` tuple.
fn encode_note_data(buf: &mut Vec<u8>, nd: &NoteData) {
    buf.extend_from_slice(&nd.hint);
    buf.extend_from_slice(&word(0x40));
    encode_bytes(buf, &nd.data);
}

/// `len | data (right-padded to 32)` — an ABI `bytes` tail.
fn encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&word(data.len() as u64));
    buf.extend_from_slice(data);
    buf.resize(buf.len() + padded_len(data.len()) - data.len(), 0);
}

fn padded_len(n: usize) -> usize {
    n.div_ceil(32) * 32
}

/// An address left-padded to an ABI word.
pub(crate) fn address_word(a: Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a.0);
    w
}

fn u128_word(x: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&x.to_be_bytes());
    w
}
