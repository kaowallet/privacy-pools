//! keccak derivation tests, anchored on the upstream SDK's `calculateContext`
//! vector (privacy-pools-core packages/sdk crypto.spec.ts).

use privacy_pools::{context, label, scope, Address, Field, Withdrawal};

#[test]
fn context_matches_sdk_vector() {
    let processooor = Address::from_hex("0xa513E6E4b8f2a923D98304ec87F64353C4D5C853").unwrap();
    // 3 ABI words: relayer addr, fee-recipient addr, amount (0xc350 = 50000)
    let data = hex::decode(
        "00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8\
000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266\
000000000000000000000000000000000000000000000000000000000000c350",
    )
    .unwrap();
    let scope =
        Field::from_hex("0x0555c5fdc167f1f1519c1b21a690de24d9be5ff0bde19447a5f28958d9256e50")
            .unwrap();
    let expected =
        Field::from_hex("0x266f59df0823b7efe6821eba38eb5de1177c6366a214b59f12154cd16079965a")
            .unwrap();

    assert_eq!(context(processooor, &data, scope), expected);
    assert_eq!(Withdrawal::new(processooor, data).context(scope), expected);
}

#[test]
fn context_handles_unaligned_data() {
    // 5 bytes of data (not a multiple of 32) must encode without panicking and
    // be deterministic.
    let p = Address::from_bytes([0x11; 20]);
    let s = Field::from(42u64);
    let c1 = context(p, &[1, 2, 3, 4, 5], s);
    let c2 = context(p, &[1, 2, 3, 4, 5], s);
    assert_eq!(c1, c2);
    assert_ne!(c1, context(p, &[1, 2, 3, 4, 6], s)); // different data → different context
}

#[test]
fn scope_and_label_are_deterministic_and_distinct() {
    let pool = Address::from_bytes([0xaa; 20]);
    let asset = Address::from_bytes([0xbb; 20]);
    let s = scope(pool, 1, asset);
    assert_eq!(s, scope(pool, 1, asset));
    assert_ne!(s, scope(pool, 10, asset)); // chain id matters
    assert_ne!(s, scope(asset, 1, pool)); // arg order matters

    let l1 = label(s, 1);
    let l2 = label(s, 2);
    assert_eq!(l1, label(s, 1));
    assert_ne!(l1, l2); // nonce matters
}
