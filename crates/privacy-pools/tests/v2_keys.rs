//! v2 key derivation vs vectors from the official SDK (`@0xbow/privacy-pools-v2-sdk`
//! 1.0.2, `CryptoService.deriveKeysFromSignature`; inputs from upstream
//! `packages/evm-sdk/test/services/CryptoService.derivation.test.ts`).
#![cfg(feature = "keys-v2")]

use privacy_pools::v2::Keys;
use privacy_pools::{Address, Field};

fn signer() -> Address {
    Address::from_hex("0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF").unwrap()
}

fn sig(hex_sig: &str) -> Vec<u8> {
    hex::decode(hex_sig.trim_start_matches("0x")).unwrap()
}

fn f(hex: &str) -> Field {
    Field::from_hex(hex).unwrap()
}

/// `0x` + `ab`×64 + `1b` (r = s = 0xabab…, high-s, v = 27).
fn fixture_sig() -> Vec<u8> {
    sig(&format!("{}1b", "ab".repeat(64)))
}

#[test]
fn derivation_matches_sdk_fixture() {
    let keys = Keys::from_signature(&fixture_sig(), signer(), 0).unwrap();
    assert_eq!(
        keys.nullifying_key(),
        f("0x0f22e94df31b8aec2307d0cdbd63420864ead3910473bd50d19466604d244b4c")
    );
    assert_eq!(
        keys.revocable_key(),
        f("0x28b5c9202aa1a12bcd2a90d068b92a65d5ea279fdf8cb4b0c08606902a4239f0")
    );
    assert_eq!(
        hex::encode(keys.viewing_private_key()),
        "48d658ea285c22de3b72ddf39db4fac84af799f193b2e9c5cbfc4a4cd612ca68"
    );
    assert_eq!(
        hex::encode(keys.viewing_public_key()),
        "561d14ec99193812f74cf728aff2bcffdc2c762548ef2ba96f9d3fc684d5403b"
    );
}

#[test]
fn revocable_key_rotation_matches_sdk() {
    let keys = Keys::from_signature(&fixture_sig(), signer(), 0).unwrap();
    for (n, rk) in [
        (1, "0x00266a7c2b66da29b4d2bc58b34bd4f4f9dd06567db4da2bfe2e1435cbe295dd"),
        (5, "0x095e31d4a5c4eb33f31105727f604966b4fee9f24c8c046b11bf3c8ded278662"),
        (10, "0x1f46a65f65b24a0e1fe6d6d33d9de1188221fa8a4ec3e603df82caa99fbbd2cb"),
        (
            u64::MAX,
            "0x05cc8f3a7c519deba8d9e5436b439d45da29ca1da7a34681c718d3e789c28b62",
        ),
    ] {
        let rotated = keys.with_revocable_key_index(n);
        assert_eq!(rotated.revocable_key(), f(rk), "n = {n}");
        assert_eq!(rotated.revocable_key_index(), n);
        assert_eq!(rotated.nullifying_key(), keys.nullifying_key());
        assert_eq!(rotated.viewing_public_key(), keys.viewing_public_key());
        assert_eq!(
            Keys::from_signature(&fixture_sig(), signer(), n).unwrap(),
            rotated
        );
    }
}

/// r with a leading zero byte must stay a 32-byte IKM.
#[test]
fn leading_zero_r_is_kept() {
    let s = sig(&format!("00{}{}1b", "ab".repeat(31), "ab".repeat(32)));
    let keys = Keys::from_signature(&s, signer(), 0).unwrap();
    assert_eq!(
        keys.nullifying_key(),
        f("0x2431374186a6cb7cee62d59e00899f0ab938f3320a328653ade86bee255b6b76")
    );
    assert_eq!(
        keys.revocable_key(),
        f("0x112f290af3b7279a67da244589eaac9c546ffa678d68dd2174dddee7c5fb700f")
    );
    assert_eq!(
        hex::encode(keys.viewing_public_key()),
        "ba6a04617f1b64fe4a29658851d3f94ba02cb771bd5d4139336d5af5763ba106"
    );
}

#[test]
fn s_and_v_do_not_affect_keys_and_bad_signatures_are_rejected() {
    let base = Keys::from_signature(&fixture_sig(), signer(), 0).unwrap();
    for v in ["00", "01", "1b", "1c"] {
        let mut s = fixture_sig();
        s[64] = u8::from_str_radix(v, 16).unwrap();
        s[40] ^= 0x01; // a different (still valid) s
        assert_eq!(Keys::from_signature(&s, signer(), 0).unwrap(), base);
    }
    let n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    for bad in [
        format!("{}{}1b", "00".repeat(32), "ab".repeat(32)), // r = 0
        format!("{}{}1b", "ab".repeat(32), "00".repeat(32)), // s = 0
        format!("{n}{}1b", "ab".repeat(32)),                 // r = n
        format!("{}{n}1b", "ab".repeat(32)),                 // s = n
        format!("{}02", "ab".repeat(64)),                    // v = 2
        format!("{}25", "ab".repeat(64)),                    // v = 37 (EIP-155)
        "ab".repeat(64),                                     // 64 bytes
        format!("{}1b00", "ab".repeat(64)),                  // 66 bytes
    ] {
        assert!(Keys::from_signature(&sig(&bad), signer(), 0).is_err(), "{bad}");
    }
}

#[test]
fn debug_does_not_print_private_keys() {
    let keys = Keys::from_signature(&fixture_sig(), signer(), 0).unwrap();
    let dbg = format!("{keys:?}");
    assert!(!dbg.contains("48d658ea285c22de"));
    assert!(dbg.contains("561d14ec99193812"));
}
