//! Privacy Pools v2 note math — matches `NoteCommitment.circom`,
//! `KeystoreLeaf.circom`, `Transact.circom`, `PoolVault.sol` and the SDK's
//! `NoteComputationService` (monorepo v1.0.2).
//!
//! ```text
//! noteAddressHash   = P(owner, noteSecret)
//! precommitment     = P(noteAddressHash, tokenId, value, metadata = 0)
//! label             = P(precommitment, depositSecret)   // fixed at deposit, inherited after
//! commitment        = P(precommitment, label)
//! nullifierHash     = P(privateNullifyingKey, commitment)
//! commitment leaf   = P(COMMITMENT_LEAF_TAG, commitment, block.timestamp)    ┐ one state
//! nullifier leaf    = P(NULLIFIER_LEAF_TAG, nullifierHash, block.timestamp)  ┘ LeanIMT
//! ASP leaf          = P(label)
//! keystore leaf     = P(owner, P(privateNullifyingKey), P(0, privateRevocableKey))
//! ```
//!
//! `P` is circomlib Poseidon; addresses and token ids enter as their uint160
//! value ([`Address::to_field`]). Native ETH is [`NATIVE_ASSET`].

use crate::context::Address;
use crate::error::Result;
use crate::field::Field;
use crate::poseidon::poseidon;

/// The native-ETH token id, `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` (`Constants.sol`).
pub const NATIVE_ASSET: Address = Address([0xee; 20]);

/// `authType` of the only implemented authorizer (direct revocable key).
pub const AUTH_TYPE_DIRECT_KEY: u64 = 0;

/// `Poseidon(uint("privacy_pools_note"))` — domain tag of commitment leaves.
const COMMITMENT_LEAF_TAG_BE: [u8; 32] = [
    0x08, 0x62, 0x05, 0xd9, 0xd9, 0xe3, 0x2c, 0xe5, 0x3f, 0xc3, 0x09, 0x58, 0x56, 0x85, 0xdd, 0xb6,
    0x29, 0xe8, 0x78, 0xdd, 0xd2, 0xdd, 0x04, 0xf5, 0x75, 0x08, 0x9c, 0x3a, 0x42, 0x13, 0x42, 0xd9,
];

/// `Poseidon(uint("privacy_pools_nullifier"))` — domain tag of nullifier leaves.
const NULLIFIER_LEAF_TAG_BE: [u8; 32] = [
    0x03, 0x45, 0xf8, 0x52, 0x33, 0x30, 0x82, 0x0b, 0xa6, 0x3c, 0x70, 0x40, 0x7f, 0x3b, 0xfd, 0x09,
    0x32, 0x15, 0x87, 0xca, 0xe0, 0x7b, 0xd4, 0xf7, 0xd3, 0x7d, 0x50, 0x49, 0xf9, 0xc5, 0x1b, 0x17,
];

/// The commitment-leaf domain tag
/// (3791694183000795315792098099581407680958131641292811872617553086713867485913).
pub fn commitment_leaf_tag() -> Field {
    Field::from_bytes_be(&COMMITMENT_LEAF_TAG_BE)
}

/// The nullifier-leaf domain tag
/// (1480564842420020354887207755615370381236762558448265256256653429412951563031).
pub fn nullifier_leaf_tag() -> Field {
    Field::from_bytes_be(&NULLIFIER_LEAF_TAG_BE)
}

/// A uniform note / deposit secret from 48 bytes of entropy (big-endian,
/// reduced mod p) — the SDK's `generateSecret`. v2 secrets are random, not
/// derived from the account keys, so the caller supplies the entropy (e.g.
/// from an OS RNG).
pub fn secret_from_entropy(entropy: &[u8; 48]) -> Field {
    Field::from_bytes_be(entropy)
}

/// `P(owner, noteSecret)` — binds a note to its owner.
pub fn note_address_hash(owner: Address, note_secret: Field) -> Result<Field> {
    poseidon(&[owner.to_field(), note_secret])
}

/// `P(noteAddressHash, tokenId, value, 0)` (standard notes carry metadata 0).
pub fn precommitment(note_address_hash: Field, token: Address, value: u128) -> Result<Field> {
    poseidon(&[
        note_address_hash,
        token.to_field(),
        value.into(),
        Field::ZERO,
    ])
}

/// `P(precommitment, depositSecret)` — a deposit's lineage label.
pub fn deposit_label(precommitment: Field, deposit_secret: Field) -> Result<Field> {
    poseidon(&[precommitment, deposit_secret])
}

/// `P(precommitment, label)` — the note commitment.
pub fn commitment(precommitment: Field, label: Field) -> Result<Field> {
    poseidon(&[precommitment, label])
}

/// `P(privateNullifyingKey, commitment)` — revealed when the note is spent.
pub fn nullifier_hash(nullifying_key: Field, commitment: Field) -> Result<Field> {
    poseidon(&[nullifying_key, commitment])
}

/// `P(privateNullifyingKey)` — registered in the keystore.
pub fn nullifying_key_hash(nullifying_key: Field) -> Result<Field> {
    poseidon(&[nullifying_key])
}

/// `P(0, privateRevocableKey)` — the direct-key authorizer digest.
pub fn auth_digest(revocable_key: Field) -> Result<Field> {
    poseidon(&[AUTH_TYPE_DIRECT_KEY.into(), revocable_key])
}

/// `P(owner, nullifyingKeyHash, authDigest)` — a keystore tree leaf, from the
/// public values the `Keystore` contract stores.
pub fn keystore_leaf(
    owner: Address,
    nullifying_key_hash: Field,
    auth_digest: Field,
) -> Result<Field> {
    poseidon(&[owner.to_field(), nullifying_key_hash, auth_digest])
}

/// `P(COMMITMENT_LEAF_TAG, commitment, timestamp)` — the state-tree leaf of a
/// note inserted at `timestamp` (`block.timestamp`, unix seconds).
pub fn commitment_leaf(commitment: Field, timestamp: u64) -> Result<Field> {
    poseidon(&[commitment_leaf_tag(), commitment, timestamp.into()])
}

/// `P(NULLIFIER_LEAF_TAG, nullifierHash, timestamp)` — the state-tree leaf
/// recording a spend at `timestamp`.
pub fn nullifier_leaf(nullifier_hash: Field, timestamp: u64) -> Result<Field> {
    poseidon(&[nullifier_leaf_tag(), nullifier_hash, timestamp.into()])
}

/// `P(label)` — an association-set (ASP) tree leaf.
pub fn asp_leaf(label: Field) -> Result<Field> {
    poseidon(&[label])
}

/// A v2 note: `value` of `token` owned by `owner`, spendable with the owner's
/// keystore keys and `secret`, carrying the lineage `label` of its deposit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub owner: Address,
    pub secret: Field,
    pub token: Address,
    pub value: u128,
    pub label: Field,
}

impl Note {
    /// The note a deposit creates; its label is `P(precommitment, depositSecret)`.
    pub fn deposit(
        owner: Address,
        token: Address,
        value: u128,
        secret: Field,
        deposit_secret: Field,
    ) -> Result<Self> {
        let pre = precommitment(note_address_hash(owner, secret)?, token, value)?;
        Ok(Self {
            owner,
            secret,
            token,
            value,
            label: deposit_label(pre, deposit_secret)?,
        })
    }

    pub fn note_address_hash(&self) -> Result<Field> {
        note_address_hash(self.owner, self.secret)
    }

    pub fn precommitment(&self) -> Result<Field> {
        precommitment(self.note_address_hash()?, self.token, self.value)
    }

    pub fn commitment(&self) -> Result<Field> {
        commitment(self.precommitment()?, self.label)
    }

    /// The nullifier hash revealed when the owner (with `nullifying_key`) spends it.
    pub fn nullifier_hash(&self, nullifying_key: Field) -> Result<Field> {
        nullifier_hash(nullifying_key, self.commitment()?)
    }

    /// The state-tree leaf of this note, inserted at `timestamp`.
    pub fn commitment_leaf(&self, timestamp: u64) -> Result<Field> {
        commitment_leaf(self.commitment()?, timestamp)
    }

    /// The ASP leaf that must be in the association set for it to be spent.
    pub fn asp_leaf(&self) -> Result<Field> {
        asp_leaf(self.label)
    }

    /// This note as a transact output (the circuit only sees its address hash).
    pub fn as_output(&self) -> Result<OutputNote> {
        Ok(OutputNote {
            note_address_hash: self.note_address_hash()?,
            value: self.value,
            label: self.label,
        })
    }
}

/// A transact output note, as the circuit sees it. A recipient's note is
/// known to the sender only by its `noteAddressHash`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputNote {
    pub note_address_hash: Field,
    pub value: u128,
    /// Must be the label of one of the spent notes.
    pub label: Field,
}

impl OutputNote {
    /// The output commitment for `token`.
    pub fn commitment(&self, token: Address) -> Result<Field> {
        commitment(
            precommitment(self.note_address_hash, token, self.value)?,
            self.label,
        )
    }
}
