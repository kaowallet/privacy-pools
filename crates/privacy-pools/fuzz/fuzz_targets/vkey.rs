#![no_main]
//! Fuzz the snarkjs vkey.json parser: must never panic on arbitrary bytes.
//!
//! Run: `cargo +nightly fuzz run vkey`

use libfuzzer_sys::fuzz_target;
use privacy_pools::WithdrawVerifier;

fuzz_target!(|data: &[u8]| {
    let _ = WithdrawVerifier::from_vkey_json(data);
});
