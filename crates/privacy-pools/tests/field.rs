//! Unit + property tests for the `Field` type.

use privacy_pools::Field;
use proptest::prelude::*;

const FIELD_ORDER: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[test]
fn zero_and_one_edges() {
    assert_eq!(Field::ZERO.to_decimal(), "0");
    assert_eq!(Field::from(0u64), Field::ZERO);
    assert_eq!(Field::from(1u64).to_decimal(), "1");
    assert_eq!(Field::from(true).to_decimal(), "1");
    assert_eq!(Field::from(false), Field::ZERO);
}

#[test]
fn reduces_modulo_field_order() {
    // p ≡ 0
    assert_eq!(Field::from_decimal(FIELD_ORDER).unwrap(), Field::ZERO);
    // p + 5 ≡ 5
    let p_plus_5 = "21888242871839275222246405745257275088548364400416034343698204186575808495622";
    assert_eq!(Field::from_decimal(p_plus_5).unwrap(), Field::from(5u64));
}

#[test]
fn hex_matches_decimal() {
    assert_eq!(Field::from_hex("0xff").unwrap(), Field::from(255u64));
    assert_eq!(Field::from_hex("FF").unwrap(), Field::from(255u64));
    assert_eq!(Field::from_hex("0x0").unwrap(), Field::ZERO);
}

#[test]
fn to_bytes_be_is_32_and_big_endian() {
    let b = Field::from(1u64).to_bytes_be();
    assert_eq!(b.len(), 32);
    assert_eq!(b[31], 1);
    assert_eq!(b[..31], [0u8; 31]);
    assert_eq!(Field::from(256u64).to_bytes_be()[30], 1);
}

#[test]
fn rejects_garbage_decimal_and_hex() {
    assert!(Field::from_decimal("not a number").is_err());
    assert!(Field::from_decimal("12x3").is_err());
    assert!(Field::from_hex("0xZZ").is_err());
}

proptest! {
    /// decimal → Field → decimal round-trips for arbitrary field elements.
    #[test]
    fn decimal_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
        let f = Field::from_bytes_be(&bytes);
        prop_assert_eq!(f, Field::from_decimal(&f.to_decimal()).unwrap());
    }

    /// big-endian byte round-trip.
    #[test]
    fn be_bytes_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
        let f = Field::from_bytes_be(&bytes);
        prop_assert_eq!(f, Field::from_bytes_be(&f.to_bytes_be()));
    }

    /// little/big-endian agree when byte order is reversed.
    #[test]
    fn le_be_consistency(bytes in prop::array::uniform32(any::<u8>())) {
        let mut rev = bytes;
        rev.reverse();
        prop_assert_eq!(Field::from_bytes_be(&bytes), Field::from_bytes_le(&rev));
    }

    /// small ints serialize to their plain decimal form.
    #[test]
    fn u64_decimal(x in any::<u64>()) {
        prop_assert_eq!(Field::from(x).to_decimal(), x.to_string());
    }

    /// arbitrary strings as decimal input never panic.
    #[test]
    fn arbitrary_decimal_never_panics(s in ".*") {
        let _ = Field::from_decimal(&s);
    }
}
