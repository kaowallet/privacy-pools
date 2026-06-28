//! Property/fuzz tests for the parsers that consume external bytes. These must
//! return `Err` on bad input, never panic.
//!
//! For deep fuzzing campaigns see `fuzz/` (cargo-fuzz / libFuzzer).

use privacy_pools::{parse_wtns, WithdrawVerifier};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    /// `parse_wtns` on arbitrary bytes must not panic.
    #[test]
    fn parse_wtns_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = parse_wtns(&bytes);
    }

    /// Valid magic + arbitrary tail exercises the section-walking code paths
    /// (lengths, offsets) without panicking.
    #[test]
    fn parse_wtns_valid_magic(tail in prop::collection::vec(any::<u8>(), 0..1024)) {
        let mut b = b"wtns".to_vec();
        b.extend_from_slice(&tail);
        let _ = parse_wtns(&b);
    }

    /// Bytes shaped like a header with attacker-controlled section
    /// lengths/counts must not panic (overflow / OOB guarded).
    #[test]
    fn parse_wtns_adversarial_header(
        version in any::<u32>(),
        n_sections in any::<u32>(),
        stype in any::<u32>(),
        slen in any::<u64>(),
        body in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut b = b"wtns".to_vec();
        b.extend_from_slice(&version.to_le_bytes());
        b.extend_from_slice(&n_sections.to_le_bytes());
        b.extend_from_slice(&stype.to_le_bytes());
        b.extend_from_slice(&slen.to_le_bytes());
        b.extend_from_slice(&body);
        let _ = parse_wtns(&b);
    }

    /// vkey parser on arbitrary bytes must not panic.
    #[test]
    fn vkey_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = WithdrawVerifier::from_vkey_json(&bytes);
    }

    /// Arbitrary strings (often valid-ish JSON) as vkey must not panic.
    #[test]
    fn vkey_arbitrary_text_never_panics(s in ".{0,512}") {
        let _ = WithdrawVerifier::from_vkey_json(s.as_bytes());
    }
}

/// Hand-picked malformed vkeys hit specific error branches.
#[test]
fn vkey_specific_malformations_error() {
    let cases = [
        "",
        "{}",
        "null",
        "[]",
        "123",
        r#"{"protocol":"plonk","IC":[]}"#,
        r#"{"protocol":"groth16"}"#,
        r#"{"protocol":"groth16","IC":[]}"#,
        r#"{"protocol":"groth16","vk_alpha_1":["x","y"],"IC":[["1","2"]]}"#,
    ];
    for c in cases {
        assert!(
            WithdrawVerifier::from_vkey_json(c.as_bytes()).is_err(),
            "expected error for vkey {c:?}"
        );
    }
}
