#![no_main]
//! Fuzz the .wtns parser: must never panic on arbitrary bytes.
//!
//! Run: `cargo +nightly fuzz run parse_wtns`

use libfuzzer_sys::fuzz_target;
use privacy_pools::parse_wtns;

fuzz_target!(|data: &[u8]| {
    let _ = parse_wtns(data);
});
