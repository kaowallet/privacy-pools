//! keccak-based derivations: `scope`, `label`, `context`.
//!
//! Mirrors the privacy-pools-core contracts (v1.2.1):
//! ```solidity
//! SCOPE   = uint256(keccak256(abi.encodePacked(address(this), block.chainid, asset))) % p;
//! label   = uint256(keccak256(abi.encodePacked(SCOPE, nonce)))                        % p;
//! context = uint256(keccak256(abi.encode(Withdrawal{processooor, data}, SCOPE)))      % p;
//! ```
//! `% p` reduction is handled by [`Field::from_bytes_be`].

use sha3::{Digest, Keccak256};

use crate::error::{Error, Result};
use crate::field::Field;

/// A 20-byte Ethereum address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn from_bytes(b: [u8; 20]) -> Self {
        Address(b)
    }

    /// Parse `0x…`-prefixed (or bare) 20-byte hex.
    pub fn from_hex(s: &str) -> Result<Self> {
        let h = s.strip_prefix("0x").unwrap_or(s);
        let bytes =
            hex::decode(h).map_err(|e| Error::Input(format!("invalid address hex: {e}")))?;
        let arr: [u8; 20] = bytes.try_into().map_err(|v: Vec<u8>| {
            Error::Input(format!("address must be 20 bytes, got {}", v.len()))
        })?;
        Ok(Address(arr))
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// Big-endian 32-byte (uint256) encoding of a u64.
fn word(x: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&x.to_be_bytes());
    b
}

/// `keccak256(abi.encodePacked(pool, chainId, asset)) % p` — a pool's scope.
pub fn scope(pool: Address, chain_id: u64, asset: Address) -> Field {
    let mut buf = Vec::with_capacity(72);
    buf.extend_from_slice(&pool.0); // address: 20 bytes (packed, not padded)
    buf.extend_from_slice(&word(chain_id)); // uint256: 32 bytes
    buf.extend_from_slice(&asset.0); // address: 20 bytes
    Field::from_bytes_be(&keccak256(&buf))
}

/// `keccak256(abi.encodePacked(scope, nonce)) % p` — a deposit's label.
///
/// In the contract `nonce` is pre-incremented (the first deposit uses nonce 1).
pub fn label(scope: Field, nonce: u64) -> Field {
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(&scope.to_bytes_be()); // uint256
    buf[32..64].copy_from_slice(&word(nonce)); // uint256
    Field::from_bytes_be(&keccak256(&buf))
}

/// A withdrawal request, as ABI-encoded into the `context`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Withdrawal {
    /// The address authorized to process the withdrawal.
    pub processooor: Address,
    /// Opaque processooor-specific data (e.g. relayer/fee parameters).
    pub data: Vec<u8>,
}

impl Withdrawal {
    pub fn new(processooor: Address, data: Vec<u8>) -> Self {
        Self { processooor, data }
    }

    /// `keccak256(abi.encode(self, scope)) % p` — the withdrawal context.
    pub fn context(&self, scope: Field) -> Field {
        context(self.processooor, &self.data, scope)
    }
}

/// `keccak256(abi.encode(Withdrawal{processooor, data}, scope)) % p`.
///
/// `abi.encode` (not packed) of a `(tuple(address, bytes), uint256)`. Because
/// the tuple contains a dynamic `bytes`, it is itself dynamic:
/// ```text
/// 0x00  offset to withdrawal tuple = 0x40
/// 0x20  scope
/// 0x40  processooor (left-padded address)        ┐ tuple
/// 0x60  offset to data = 0x40 (relative to 0x40) │
/// 0x80  data length                              │
/// 0xa0  data bytes (right-padded to 32)          ┘
/// ```
pub fn context(processooor: Address, data: &[u8], scope: Field) -> Field {
    let mut buf = Vec::new();
    // outer head: offset to the (dynamic) withdrawal tuple, then scope
    buf.extend_from_slice(&word(0x40));
    buf.extend_from_slice(&scope.to_bytes_be());
    // withdrawal tuple
    buf.extend_from_slice(&[0u8; 12]); // address left-pad
    buf.extend_from_slice(&processooor.0);
    buf.extend_from_slice(&word(0x40)); // offset to data, relative to tuple start
    buf.extend_from_slice(&word(data.len() as u64));
    buf.extend_from_slice(data);
    let rem = data.len() % 32;
    if rem != 0 {
        buf.extend(std::iter::repeat(0u8).take(32 - rem));
    }
    Field::from_bytes_be(&keccak256(&buf))
}
