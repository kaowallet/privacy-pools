//! v2 account keys from one wallet signature, byte-compatible with
//! `@0xbow/privacy-pools-v2-sdk` `CryptoService.deriveKeysFromSignature`.
//!
//! ```text
//! r           = signature[0..32]                       (ECDSA r of the SecretDerivation sig)
//! rootSecret  = HKDF(ikm=r,          salt=signer[20],          info="Standardized-Secret-Derivation-v1-Root")
//! appSecret   = HKDF(ikm=rootSecret, salt=APP_IDENTIFIER,      info="Standardized-Secret-Derivation-v1-App")
//! masterPRK   = HKDF-Extract(salt="PP_V2", ikm=appSecret)
//! identityPRK = Expand(masterPRK, "IDENTITY", 32)       viewingPRK = Expand(masterPRK, "VIEWING", 32)
//! nullifying  = Expand(identityPRK, "NULLIFYING", 48)                      mod p
//! revocable_n = Expand(identityPRK, "AUTH0:REVOCABLE" ‖ u64be(n), 48)      mod p
//! viewing     = clamp(Expand(viewingPRK, "VIEWING_KEY", 32))  → X25519 public key
//! ```
//! All HKDFs are SHA-256; strings are their ASCII bytes. Keys depend on `r`
//! alone, so the signature must come from a deterministic (RFC 6979) signer
//! over [`secret_derivation_digest`](super::secret_derivation_digest) — or the
//! derived keys must be persisted. Whoever holds `r` holds every key.

use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use sha2::Sha256;

use super::eip712::APP_IDENTIFIER;
use super::note;
use crate::context::Address;
use crate::error::{Error, Result};
use crate::field::Field;

const ROOT_DERIVATION_INFO: &[u8] = b"Standardized-Secret-Derivation-v1-Root";
const APP_DERIVATION_INFO: &[u8] = b"Standardized-Secret-Derivation-v1-App";
const PROTOCOL_SALT: &[u8] = b"PP_V2";
const IDENTITY_DOMAIN: &[u8] = b"IDENTITY";
const VIEWING_DOMAIN: &[u8] = b"VIEWING";
const NULLIFYING_INFO: &[u8] = b"NULLIFYING";
const AUTH0_REVOCABLE_PREFIX: &[u8] = b"AUTH0:REVOCABLE";
const VIEWING_KEY_INFO: &[u8] = b"VIEWING_KEY";

/// secp256k1 group order `n`, big-endian.
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// An account's v2 protocol keys.
///
/// - `nullifying_key` — immutable identity; derives every nullifier.
/// - `revocable_key` — spending authorization at rotation index `n`; rotate
///   with [`Keys::with_revocable_key_index`] (same signature, next `n`).
/// - viewing key — X25519, for encrypted note discovery.
#[derive(Clone, PartialEq, Eq)]
pub struct Keys {
    identity_prk: [u8; 32],
    nullifying_key: Field,
    revocable_key: Field,
    revocable_key_index: u64,
    viewing_private_key: [u8; 32],
    viewing_public_key: [u8; 32],
}

impl Keys {
    /// Derive the keys from the 65-byte `r ‖ s ‖ v` SecretDerivation signature
    /// made by `signer`, at revocable-key rotation index `revocable_key_index`
    /// (0 for a fresh account).
    ///
    /// Rejects what the SDK rejects: a wrong length, `r` or `s` outside
    /// `[1, n)`, or `v ∉ {0, 1, 27, 28}`. High-`s` is accepted, and `s`/`v` do
    /// not affect the keys. The signature is not checked against `signer`.
    pub fn from_signature(
        signature: &[u8],
        signer: Address,
        revocable_key_index: u64,
    ) -> Result<Self> {
        let sig: &[u8; 65] = signature.try_into().map_err(|_| {
            Error::Input(format!(
                "signature must be 65 bytes (r ‖ s ‖ v), got {}",
                signature.len()
            ))
        })?;
        let (r, s, v) = (&sig[0..32], &sig[32..64], sig[64]);
        for (name, x) in [("r", r), ("s", s)] {
            if x.iter().all(|&b| b == 0) || x >= &SECP256K1_ORDER[..] {
                return Err(Error::Input(format!(
                    "signature {name} must be in [1, secp256k1 order)"
                )));
            }
        }
        if !matches!(v, 0 | 1 | 27 | 28) {
            return Err(Error::Input(format!("invalid signature v byte {v:#04x}")));
        }

        let root = hkdf_32(Some(&signer.0), r, ROOT_DERIVATION_INFO);
        let app = hkdf_32(Some(APP_IDENTIFIER.as_bytes()), &root, APP_DERIVATION_INFO);
        let (master_prk, _) = Hkdf::<Sha256>::extract(Some(PROTOCOL_SALT), &app);
        let identity_prk = expand(&master_prk, IDENTITY_DOMAIN);
        let viewing_prk = expand(&master_prk, VIEWING_DOMAIN);

        let mut nullifying = [0u8; 48];
        expand_into(&identity_prk, NULLIFYING_INFO, &mut nullifying);
        let mut viewing_private_key = expand(&viewing_prk, VIEWING_KEY_INFO);
        clamp(&mut viewing_private_key);

        Ok(Self {
            identity_prk,
            nullifying_key: Field::from_bytes_be(&nullifying),
            revocable_key: revocable_key(&identity_prk, revocable_key_index),
            revocable_key_index,
            viewing_private_key,
            viewing_public_key: MontgomeryPoint::mul_base_clamped(viewing_private_key).to_bytes(),
        })
    }

    /// The same account with its revocable key rotated to index `n`.
    pub fn with_revocable_key_index(&self, n: u64) -> Self {
        Self {
            revocable_key: revocable_key(&self.identity_prk, n),
            revocable_key_index: n,
            ..self.clone()
        }
    }

    /// The private nullifying key (a field element).
    pub fn nullifying_key(&self) -> Field {
        self.nullifying_key
    }

    /// The private revocable key at [`revocable_key_index`](Self::revocable_key_index).
    pub fn revocable_key(&self) -> Field {
        self.revocable_key
    }

    pub fn revocable_key_index(&self) -> u64 {
        self.revocable_key_index
    }

    /// The clamped X25519 viewing private key.
    pub fn viewing_private_key(&self) -> [u8; 32] {
        self.viewing_private_key
    }

    /// The X25519 viewing public key (little-endian u-coordinate), registered
    /// so others can encrypt notes to this account.
    pub fn viewing_public_key(&self) -> [u8; 32] {
        self.viewing_public_key
    }

    /// `P(nullifyingKey)`, as registered in the keystore.
    pub fn nullifying_key_hash(&self) -> Result<Field> {
        note::nullifying_key_hash(self.nullifying_key)
    }

    /// `P(0, revocableKey)` — the current authorizer digest.
    pub fn auth_digest(&self) -> Result<Field> {
        note::auth_digest(self.revocable_key)
    }

    /// This account's keystore tree leaf, for `owner` (the signer).
    pub fn keystore_leaf(&self, owner: Address) -> Result<Field> {
        note::keystore_leaf(owner, self.nullifying_key_hash()?, self.auth_digest()?)
    }
}

impl std::fmt::Debug for Keys {
    /// Only the public parts — the private keys never reach logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("revocable_key_index", &self.revocable_key_index)
            .field("viewing_public_key", &hex::encode(self.viewing_public_key))
            .finish_non_exhaustive()
    }
}

fn revocable_key(identity_prk: &[u8; 32], n: u64) -> Field {
    let info = [AUTH0_REVOCABLE_PREFIX, &n.to_be_bytes()].concat();
    let mut okm = [0u8; 48];
    expand_into(identity_prk, &info, &mut okm);
    Field::from_bytes_be(&okm)
}

/// HKDF-SHA256 (extract + expand) to 32 bytes.
fn hkdf_32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    okm
}

/// HKDF-Expand of a 32-byte PRK to 32 bytes.
fn expand(prk: &[u8], info: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    expand_into(prk, info, &mut okm);
    okm
}

fn expand_into(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    Hkdf::<Sha256>::from_prk(prk)
        .expect("a SHA-256 PRK is 32 bytes")
        .expand(info, okm)
        .expect("≤ 48 bytes is a valid HKDF-SHA256 length");
}

/// RFC 7748 clamping, in place (the stored viewing key is pre-clamped).
fn clamp(k: &mut [u8; 32]) {
    k[0] &= 0xf8;
    k[31] &= 0x7f;
    k[31] |= 0x40;
}
