//! Artifacts embedded by `partial-bundled-v2`: the graph + vkey of all 27
//! circuits (~52 MB) and the zkeys of the [`Circuit::is_bundled`] three (~24 MB).
//!
//! [`Circuit::is_bundled`]: super::Circuit::is_bundled

macro_rules! embedded {
    ($fn:ident, $ext:literal, [$($name:literal),* $(,)?]) => {
        pub(super) fn $fn(name: &str) -> Option<&'static [u8]> {
            match name {
                $($name => Some(include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/artifacts/v2/",
                    $name,
                    $ext
                )).as_slice()),)*
                _ => None,
            }
        }
    };
}

macro_rules! all_circuits {
    ($($fn:ident => $ext:literal),*) => {$(
        embedded!($fn, $ext, [
            "deposit", "ragequit",
            "transact_1x1", "transact_1x2", "transact_1x3", "transact_1x4", "transact_1x5",
            "transact_2x1", "transact_2x2", "transact_2x3", "transact_2x4", "transact_2x5",
            "transact_3x1", "transact_3x2", "transact_3x3", "transact_3x4", "transact_3x5",
            "transact_4x1", "transact_4x2", "transact_4x3", "transact_4x4", "transact_4x5",
            "transact_5x1", "transact_5x2", "transact_5x3", "transact_5x4", "transact_5x5",
        ]);
    )*};
}

all_circuits!(graph => ".graph.bin", vkey => ".vkey.json");

embedded!(zkey, ".zkey", ["deposit", "ragequit", "transact_1x1"]);
