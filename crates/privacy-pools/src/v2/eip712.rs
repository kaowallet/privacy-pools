//! EIP-712 payloads a v2 wallet signs.
//!
//! - **SecretDerivation** — the one-time signature every v2 key is derived from
//!   (see `Keys::from_signature`). The SDK deliberately ships no builder; this
//!   is the reference payload of the monorepo's sample apps
//!   (`apps/sample{,-web}/…/secretDerivationPayload.ts`). Signing anything else
//!   yields a different, non-interoperable key family.
//! - **SetAuthPolicy** — authorizes a relayer to register the account's
//!   keystore leaf (`Keystore.sol`, `keystoreEip712.ts`).
//!
//! The digests here are what an RFC 6979 signer (e.g. k256 `sign_prehash`)
//! signs; [`secret_derivation_typed_data`] is the `eth_signTypedData_v4`
//! payload for an injected wallet. Hashing is hand-rolled over keccak so it
//! needs no alloy.

use serde_json::{json, Value};

use super::context::address_word;
use crate::context::{keccak256, word, Address};
use crate::field::Field;

/// Salt input of the second derivation stage and of the SecretDerivation
/// domain. Upstream declares it final: changing it changes every key.
pub const APP_IDENTIFIER: &str = "TODO-privacy-pools-v2";

/// The `purpose` the wallet shows when asked to sign the SecretDerivation
/// payload. Part of the signed hash, so it must stay byte-for-byte stable.
pub const SECRET_DERIVATION_PURPOSE: &str = "This signature is used to deterministically derive \
    application-specific secrets from your master seed. It is not a transaction and will not \
    cost any gas.";

const SECRET_DERIVATION_DOMAIN_NAME: &str = "Standardized Secret Derivation";
const SECRET_DERIVATION_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)";
const SECRET_DERIVATION_TYPE: &str = "SecretDerivation(string purpose,bytes32 addressHash)";

const KEYSTORE_DOMAIN_NAME: &str = "PrivacyPoolsKeystore";
const KEYSTORE_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const SET_AUTH_POLICY_TYPE: &str =
    "SetAuthPolicy(address account,uint256 authDigest,uint256 nullifyingKeyHash,uint256 deadline)";

/// `keccak256(signer)` over the raw 20 address bytes — the SecretDerivation
/// message's `addressHash`, binding the signature to its signer.
pub fn address_hash(signer: Address) -> [u8; 32] {
    keccak256(&signer.0)
}

/// The EIP-712 digest of the SecretDerivation payload for `signer`.
pub fn secret_derivation_digest(signer: Address) -> [u8; 32] {
    let domain = keccak256(
        &[
            keccak256(SECRET_DERIVATION_DOMAIN_TYPE.as_bytes()),
            keccak256(SECRET_DERIVATION_DOMAIN_NAME.as_bytes()),
            keccak256(b"1"),
            address_word(Address([0; 20])),
            keccak256(APP_IDENTIFIER.as_bytes()),
        ]
        .concat(),
    );
    let message = keccak256(
        &[
            keccak256(SECRET_DERIVATION_TYPE.as_bytes()),
            keccak256(SECRET_DERIVATION_PURPOSE.as_bytes()),
            address_hash(signer),
        ]
        .concat(),
    );
    typed_data_digest(domain, message)
}

/// The SecretDerivation payload for `signer` as `eth_signTypedData_v4` JSON.
pub fn secret_derivation_typed_data(signer: Address) -> Value {
    json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "verifyingContract", "type": "address" },
                { "name": "salt", "type": "bytes32" },
            ],
            "SecretDerivation": [
                { "name": "purpose", "type": "string" },
                { "name": "addressHash", "type": "bytes32" },
            ],
        },
        "primaryType": "SecretDerivation",
        "domain": {
            "name": SECRET_DERIVATION_DOMAIN_NAME,
            "version": "1",
            "verifyingContract": format!("0x{}", hex::encode([0u8; 20])),
            "salt": format!("0x{}", hex::encode(keccak256(APP_IDENTIFIER.as_bytes()))),
        },
        "message": {
            "purpose": SECRET_DERIVATION_PURPOSE,
            "addressHash": format!("0x{}", hex::encode(address_hash(signer))),
        },
    })
}

/// A relayed keystore registration, signed by the account owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetAuthPolicy {
    /// The `Keystore` contract (EIP-712 verifying contract).
    pub keystore: Address,
    pub chain_id: u64,
    /// The account being registered (the signer).
    pub account: Address,
    pub auth_digest: Field,
    pub nullifying_key_hash: Field,
    /// Unix timestamp after which the authorization expires.
    pub deadline: u64,
}

impl SetAuthPolicy {
    /// The EIP-712 digest the `Keystore` verifies against `account`.
    pub fn digest(&self) -> [u8; 32] {
        let domain = keccak256(
            &[
                keccak256(KEYSTORE_DOMAIN_TYPE.as_bytes()),
                keccak256(KEYSTORE_DOMAIN_NAME.as_bytes()),
                keccak256(b"1"),
                word(self.chain_id),
                address_word(self.keystore),
            ]
            .concat(),
        );
        let message = keccak256(
            &[
                keccak256(SET_AUTH_POLICY_TYPE.as_bytes()),
                address_word(self.account),
                self.auth_digest.to_bytes_be(),
                self.nullifying_key_hash.to_bytes_be(),
                word(self.deadline),
            ]
            .concat(),
        );
        typed_data_digest(domain, message)
    }
}

/// `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)`.
fn typed_data_digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    keccak256(&[&[0x19, 0x01][..], &domain_separator, &struct_hash].concat())
}
