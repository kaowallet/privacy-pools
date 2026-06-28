//! A BN254 scalar-field element with ergonomic constructors.
//!
//! [Engine layer — no protocol knowledge.]
//!
//! Circuit inputs are field elements. [`Field`] wraps [`ark_bn254::Fr`] and
//! serializes to the decimal-string form circom/snarkjs expects in input JSON.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use num_bigint::BigUint;
use serde::{Serialize, Serializer};

use crate::error::{Error, Result};

/// A BN254 scalar field element (`Fr`).
///
/// Construct from integers, decimal/hex strings, or raw bytes. Values are
/// reduced modulo the field order, matching circom semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Field(pub Fr);

impl Field {
    /// The additive identity (`0`).
    pub const ZERO: Field = Field(Fr::ZERO);

    /// Wrap a raw [`Fr`].
    pub fn new(fr: Fr) -> Self {
        Field(fr)
    }

    /// The inner [`Fr`].
    pub fn into_fr(self) -> Fr {
        self.0
    }

    /// Parse a base-10 integer string (e.g. `"21888242871839275222246..."`).
    pub fn from_decimal(s: &str) -> Result<Self> {
        let n = s
            .trim()
            .parse::<BigUint>()
            .map_err(|e| Error::Input(format!("invalid decimal field element {s:?}: {e}")))?;
        Ok(Field::from_bytes_be(&n.to_bytes_be()))
    }

    /// Parse a hex integer string, with or without a `0x` prefix.
    pub fn from_hex(s: &str) -> Result<Self> {
        let h = s.trim().strip_prefix("0x").unwrap_or_else(|| s.trim());
        let n = BigUint::parse_bytes(h.as_bytes(), 16)
            .ok_or_else(|| Error::Input(format!("invalid hex field element {s:?}")))?;
        Ok(Field::from_bytes_be(&n.to_bytes_be()))
    }

    /// Interpret big-endian bytes as an integer (reduced mod the field order).
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Field(Fr::from_be_bytes_mod_order(bytes))
    }

    /// Interpret little-endian bytes as an integer (reduced mod the field order).
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        Field(Fr::from_le_bytes_mod_order(bytes))
    }

    /// The canonical big-endian 32-byte encoding.
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let be = self.0.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        // `to_bytes_be` yields exactly 32 bytes for BN254 Fr.
        out[32 - be.len()..].copy_from_slice(&be);
        out
    }

    /// The canonical base-10 string (what circom input JSON uses).
    pub fn to_decimal(&self) -> String {
        BigUint::from_bytes_be(&self.0.into_bigint().to_bytes_be()).to_str_radix(10)
    }
}

impl From<Fr> for Field {
    fn from(fr: Fr) -> Self {
        Field(fr)
    }
}

macro_rules! from_uint {
    ($($t:ty),*) => {$(
        impl From<$t> for Field {
            fn from(v: $t) -> Self { Field(Fr::from(v)) }
        }
    )*};
}
from_uint!(u8, u16, u32, u64, u128, bool);

impl Serialize for Field {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        // circom/snarkjs inputs are decimal strings.
        s.serialize_str(&self.to_decimal())
    }
}

/// Allow `Field::try_from("123")` for decimal strings.
impl TryFrom<&str> for Field {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        Field::from_decimal(s)
    }
}
