//! HD account key derivation, byte-compatible with the 0xbow TypeScript SDK
//! (`@0xbow/privacy-pools-core-sdk`, `crypto.ts`). Deriving keys the same way
//! makes wallets interoperable: deposits created by the official client are
//! recoverable here and vice-versa.
//!
//! ```text
//! priv_i           = secp256k1 private key at BIP-44 m/44'/60'/i'/0/0   (i = 0, 1)
//! masterNullifier  = Poseidon([priv_0])      // priv reduced mod the BN254 field
//! masterSecret     = Poseidon([priv_1])
//!
//! deposit  at scope, index i:   nullifier = Poseidon([masterNullifier, scope, i])
//!                               secret    = Poseidon([masterSecret,    scope, i])
//! change   at label, index i:   nullifier = Poseidon([masterNullifier, label, i])
//!                               secret    = Poseidon([masterSecret,    label, i])
//! ```
//!
//! `priv_i` is the full 32-byte big-endian secp256k1 scalar, which can exceed
//! the BN254 scalar field modulus; Poseidon reduces it mod `p` (exactly as
//! maci-crypto's `poseidon` does in the SDK). The BIP-44 path mirrors viem's
//! `mnemonicToAccount(mnemonic, { accountIndex: i })`, which the SDK uses.

use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic};

use crate::commitment::precommitment;
use crate::error::{Error, Result};
use crate::field::Field;
use crate::poseidon::poseidon;

/// The two master field elements every per-deposit secret is derived from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MasterKeys {
    pub nullifier: Field,
    pub secret: Field,
}

/// A Privacy Pools account — master keys plus the protocol's per-deposit and
/// per-change `(nullifier, secret)` derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    keys: MasterKeys,
}

impl Account {
    /// Derive an account from a BIP-39 mnemonic (empty passphrase).
    pub fn from_mnemonic(phrase: &str) -> Result<Self> {
        Self::from_mnemonic_with_passphrase(phrase, "")
    }

    /// Derive an account from a BIP-39 mnemonic with a passphrase.
    pub fn from_mnemonic_with_passphrase(phrase: &str, passphrase: &str) -> Result<Self> {
        let priv0 = eth_private_key(phrase, passphrase, 0)?;
        let priv1 = eth_private_key(phrase, passphrase, 1)?;
        let nullifier = poseidon(&[Field::from_bytes_be(&priv0)])?;
        let secret = poseidon(&[Field::from_bytes_be(&priv1)])?;
        Ok(Self { keys: MasterKeys { nullifier, secret } })
    }

    /// Build directly from master keys (e.g. supplied by a host keystore that
    /// owns the mnemonic itself).
    pub fn from_master_keys(keys: MasterKeys) -> Self {
        Self { keys }
    }

    /// The account's master keys.
    pub fn master_keys(&self) -> MasterKeys {
        self.keys
    }

    /// `(nullifier, secret)` for the deposit at `index` in pool `scope`.
    pub fn deposit_secrets(&self, scope: Field, index: u64) -> Result<(Field, Field)> {
        let i = Field::from(index);
        Ok((
            poseidon(&[self.keys.nullifier, scope, i])?,
            poseidon(&[self.keys.secret, scope, i])?,
        ))
    }

    /// `(nullifier, secret)` for the change commitment at child `index` of the
    /// account whose deposit has `label` (each partial withdrawal mints a new
    /// change note with a fresh pair).
    pub fn withdrawal_secrets(&self, label: Field, index: u64) -> Result<(Field, Field)> {
        let i = Field::from(index);
        Ok((
            poseidon(&[self.keys.nullifier, label, i])?,
            poseidon(&[self.keys.secret, label, i])?,
        ))
    }

    /// The precommitment `Poseidon([nullifier, secret])` to submit on-chain for
    /// the deposit at `index` in pool `scope`. This is the only secret-derived
    /// value a deposit transaction needs; `label` and the full `commitment`
    /// come back in the pool's `Deposited` event.
    pub fn deposit_precommitment(&self, scope: Field, index: u64) -> Result<Field> {
        let (nullifier, secret) = self.deposit_secrets(scope, index)?;
        precommitment(nullifier, secret)
    }
}

/// secp256k1 private key at BIP-44 `m/44'/60'/{account_index}'/0/0`, as 32
/// big-endian bytes — matching viem's `mnemonicToAccount(mnemonic, { accountIndex })`.
fn eth_private_key(phrase: &str, passphrase: &str, account_index: u32) -> Result<[u8; 32]> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|e| Error::Input(format!("invalid mnemonic: {e}")))?;
    let seed = mnemonic.to_seed(passphrase);
    let path: DerivationPath = format!("m/44'/60'/{account_index}'/0/0")
        .parse()
        .map_err(|e| Error::Input(format!("bad derivation path: {e}")))?;
    let xprv = XPrv::derive_from_path(seed, &path)
        .map_err(|e| Error::Input(format!("key derivation failed: {e}")))?;
    Ok(xprv.to_bytes())
}
