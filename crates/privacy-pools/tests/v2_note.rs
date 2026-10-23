//! v2 note math vs the official SDK (`@0xbow/privacy-pools-v2-sdk@1.0.2`):
//! `NoteComputationService` (note address hash, precommitment, label,
//! commitment, nullifier, auth digest, label hash), `WitnessPreparationService`
//! (`computeKeystoreLeaf`, `computeTimestampedLeaf`) and
//! `CryptoService.generateSecret`. Every hex output below was computed by the
//! published SDK; the ETH, USDC and "sdkapi" chains and the canonical-key and
//! keystore samples also appear in the extracted upstream specs.

use privacy_pools::v2::{note, secret_from_entropy, Note, OutputNote, NATIVE_ASSET};
use privacy_pools::{poseidon, Address, Field};

fn f(hex: &str) -> Field {
    Field::from_hex(hex).unwrap()
}

fn fdec(dec: &str) -> Field {
    Field::from_decimal(dec).unwrap()
}

fn addr(hex: &str) -> Address {
    Address::from_hex(hex).unwrap()
}

// --- domain tags -----------------------------------------------------------------

/// `Constants.sol`: each tag is `Poseidon1` of the UTF-8 string read as a
/// big-endian integer.
#[test]
fn leaf_tags_derive_from_their_utf8_strings() {
    let note_int = Field::from_bytes_be(b"privacy_pools_note");
    let nullifier_int = Field::from_bytes_be(b"privacy_pools_nullifier");
    assert_eq!(
        note_int.to_decimal(),
        "9795508397791996215241242626151178971346021"
    );
    assert_eq!(
        nullifier_int.to_decimal(),
        "10770275383349755482884329940408439817076266725135705458"
    );

    let commitment_tag = poseidon(&[note_int]).unwrap();
    let nullifier_tag = poseidon(&[nullifier_int]).unwrap();
    assert_eq!(note::commitment_leaf_tag(), commitment_tag);
    assert_eq!(note::nullifier_leaf_tag(), nullifier_tag);

    // Constants.sol / Transact.circom decimals and the SDK's COMMITMENT_LEAF_TAG.
    assert_eq!(
        note::commitment_leaf_tag(),
        fdec("3791694183000795315792098099581407680958131641292811872617553086713867485913")
    );
    assert_eq!(
        note::commitment_leaf_tag(),
        f("0x086205d9d9e32ce53fc309585685ddb629e878ddd2dd04f575089c3a421342d9")
    );
    assert_eq!(
        note::nullifier_leaf_tag(),
        fdec("1480564842420020354887207755615370381236762558448265256256653429412951563031")
    );
    assert_eq!(
        note::nullifier_leaf_tag(),
        f("0x0345f8523330820ba63c70407f3bfd09321587cae07bd4f7d37d5049f9c51b17")
    );
    assert_ne!(note::commitment_leaf_tag(), note::nullifier_leaf_tag());
}

#[test]
fn native_asset_is_the_eth_sentinel() {
    assert_eq!(
        NATIVE_ASSET,
        addr("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE")
    );
    assert_eq!(
        NATIVE_ASSET.to_field().to_decimal(),
        "1364068194842176056990105843868530818345537040110"
    );
    // Addresses enter circuits as their uint160 value; case is irrelevant.
    assert_eq!(
        addr("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").to_field(),
        addr("0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266").to_field()
    );
    assert_eq!(
        Address([0xff; 20]).to_field(),
        fdec("1461501637330902918203684832716283019655932542975") // 2^160 - 1
    );
}

// --- the note hash chain -----------------------------------------------------------

struct Chain {
    name: &'static str,
    owner: &'static str,
    secret: &'static str,
    deposit_secret: &'static str,
    token: &'static str,
    value: u128,
    nk: &'static str,
    rk: &'static str,
    ts: u64,
    // SDK outputs
    nah: &'static str,
    precommitment: &'static str,
    label: &'static str,
    commitment: &'static str,
    nullifier_hash: &'static str,
    nullifying_key_hash: &'static str,
    auth_digest: &'static str,
    keystore_leaf: &'static str,
    commitment_leaf: &'static str,
    nullifier_leaf: &'static str,
    asp_leaf: &'static str,
}

const CHAINS: [Chain; 5] = [
    // ETH deposit by anvil #0 (also the notes/witness spec chain).
    Chain {
        name: "eth",
        owner: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        secret: "0x1111111111111111111111111111111111111111111111111111111111111111",
        deposit_secret: "0x2222222222222222222222222222222222222222222222222222222222222222",
        token: "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
        value: 1_000_000_000_000_000_000,
        nk: "0x0333333333333333333333333333333333333333333333333333333333333333",
        rk: "0x0444444444444444444444444444444444444444444444444444444444444444",
        ts: 1_750_000_000,
        nah: "0x08d18fbcc65e35f13dd27e15c2a2eb26ed98e9bc6f1c20e5dbee6d320f4d179f",
        precommitment: "0x225e4589fa8686ce8dd98d77fa4d93e01f403c6013516384c46cccf4892ad15a",
        label: "0x2b5d4bae92af98735fb5afc2abc12a679eeb23d4c2e1d4af7fc855bd55f69181",
        commitment: "0x0bf35753879b34b9e61f8b0b08509c9b3d4d0af9ca0602c9dadcbbde815c369b",
        nullifier_hash: "0x0fb46cff291a90988e9ded92e0367c6b3cd52c5c8b3b6086a7eba6b2dea7d987",
        nullifying_key_hash: "0x1aa90e6c68d0562dda94d57ebc7dbd2fa38e41b54e9d4fd0a4f0a17d6d9454f8",
        auth_digest: "0x00e9e4ee5365b15b761e4e44d9cc5000da5cee4550044b2358eb402b0d023927",
        keystore_leaf: "0x2a2ef39bbbe6df742df9e445d3f574d924059526551f498f9b75541f1bec1ae4",
        commitment_leaf: "0x2b0ba4784882af2de14322bfa8e00cea655916d6244ab7c5113494a15a5f89ab",
        nullifier_leaf: "0x2fdc115e30ee19a48563f506371c0bab83d4d535ec4d4bfb76af5e85b49c78f3",
        asp_leaf: "0x1edaa304c230e13fabb0342d93935d682c66914dd6c9172b83b11bd04d02d2b6",
    },
    // Same owner and secrets, mainnet USDC (spec USDC vector), nk = 1, rk = 2.
    Chain {
        name: "usdc",
        owner: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        secret: "0x1111111111111111111111111111111111111111111111111111111111111111",
        deposit_secret: "0x2222222222222222222222222222222222222222222222222222222222222222",
        token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        value: 1_000_000_000,
        nk: "0x01",
        rk: "0x02",
        ts: 1,
        nah: "0x08d18fbcc65e35f13dd27e15c2a2eb26ed98e9bc6f1c20e5dbee6d320f4d179f",
        precommitment: "0x25f5369320a5d6948d5df1bf00aa8a0a327b30dd6caf9227e34fd4c7024caf63",
        label: "0x0ca84c7b9a6d94a732c92df5d7ae428d16284dd52a17c27c5c6b9d968e8cff33",
        commitment: "0x102535aa73c7e5f2cdd93fd1ddf5c8292d3a734adeb76446dd569f6463e95737",
        nullifier_hash: "0x025b52c495a4afa835bcb5b14bee9f46da62b676388e085d82e56e33b4310cdc",
        nullifying_key_hash: "0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133",
        auth_digest: "0x065e2c6cc08a36c4a943286bc91c216054a1981eb4f7570f67394ef8937a21b8",
        keystore_leaf: "0x102a563de669cc99e949ceec38545346c41dfea8550167b639f4684b9a8e3e50",
        commitment_leaf: "0x1ba17815a562a0c876b9167ad2a8260eeff0b8646218da0a75a8c89ae7109f8f",
        nullifier_leaf: "0x2fd627a6e592613245714cbc49c2f550f7d97ab666f0569439661fab83551c22",
        asp_leaf: "0x283dc38bf64294cf1dbad399ec29f38dd227061971d4ab10fb54448375706c2c",
    },
    // The SDK-API spec vector (keys from the upstream derivation fixture).
    Chain {
        name: "sdkapi",
        owner: "0x1111111111111111111111111111111111111111",
        secret: "0x2222222222222222222222222222222222222222222222222222222222222222",
        deposit_secret: "0x3333333333333333333333333333333333333333333333333333333333333333",
        token: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        value: 100,
        nk: "0x0f22e94df31b8aec2307d0cdbd63420864ead3910473bd50d19466604d244b4c",
        rk: "0x28b5c9202aa1a12bcd2a90d068b92a65d5ea279fdf8cb4b0c08606902a4239f0",
        ts: 0x1234,
        nah: "0x004265b87ec9ed306cd93c682a7598c46422c7d7cfd526eca816386cc3b5b103",
        precommitment: "0x3058262ebfcda81539d63103babdb62b96f46edc73dcd5eee8e0535fc8dbc04e",
        label: "0x25c638b750e73d7f7f3649ffea79aa48487c1c240a0ad54d85fd5906cf17a687",
        commitment: "0x21eb1db69e734f7ba56d196546774d9e673998ca3c3033f0a8f7b065a9b726cf",
        nullifier_hash: "0x0ce87907bd057c8466337e0a61b320fbbe1f40ab3777aa09b60ec3a2e0d91384",
        nullifying_key_hash: "0x2cd3bb5417816f4b42efbd9b9b23ecb2f951da07aed51ea1187b0df8a0dda0f2",
        auth_digest: "0x2374c564e2bb8c757af8cb8357ff260f67155bee1c40b4947aa781f8b286882a",
        keystore_leaf: "0x0893b275f900cc3efcd6d3a05e63fce939745b90566a8ff4fe1a74c978010cb3",
        commitment_leaf: "0x1d52a72a4af95d753b5215d6e76b11ab20bdbcdbd22b0e0f8801108ef17e8586",
        nullifier_leaf: "0x0228e0136232c7d2d22523e8abc2b4ead2ad273fcace2ea406e310c228542b7e",
        asp_leaf: "0x1dc7bc66363fd3b7e3febfec75288d9df5f8bf2aa5df3cdd16d807335bd396a0",
    },
    // Everything zero: zero owner and token, zero secrets, keys and value.
    Chain {
        name: "zeros",
        owner: "0x0000000000000000000000000000000000000000",
        secret: "0x0",
        deposit_secret: "0x0",
        token: "0x0000000000000000000000000000000000000000",
        value: 0,
        nk: "0x0",
        rk: "0x0",
        ts: 0,
        nah: "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
        precommitment: "0x27a5e9f55608cf8972b22142d1c977413ad5305de9286e840d14ddc297c36191",
        label: "0x12f8585791c611eda44d590a5e87df8b4055e28ad515f1068b5ed797cc12d785",
        commitment: "0x136e3f8b749c7a5246a173f374bb3f133494b96a7dbb0c4bab63eb13dce800bf",
        nullifier_hash: "0x11459ed45c45d4eeee246df8fb6c81a660877ebe18638db2c83e94861833813d",
        nullifying_key_hash: "0x2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c",
        auth_digest: "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
        keystore_leaf: "0x229e0d6319fb43339adee508cd03203bcfb19775c4693bcafffc4985f008f40c",
        commitment_leaf: "0x0a0cd4b2b773396e819b65d2ab433ce9c7a1ffbcad24975c3a44d195543c346c",
        nullifier_leaf: "0x12f530b95b4d57a801153f9056c464434163c2c4b783bcf58011be4911c7d612",
        asp_leaf: "0x117f0330a2ffbfbddf27363db4d383f3c64e21f050c08bce55fa2d0395fdca75",
    },
    // Upper bounds: 0xff..ff owner/token, value 2^128 - 1, secrets/keys near
    // p (p - 1, p - 2, p - 3), timestamp u64::MAX.
    Chain {
        name: "max",
        owner: "0xffffffffffffffffffffffffffffffffffffffff",
        secret: "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
        deposit_secret: "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff",
        token: "0xffffffffffffffffffffffffffffffffffffffff",
        value: u128::MAX,
        nk: "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
        rk: "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffffe",
        ts: u64::MAX,
        nah: "0x2a2d6e27bedae33e01ebafa85709b552b6b4452664cc294b3c1f7617587d34a6",
        precommitment: "0x08cd6ceeeee4146e609e4b715fdd9945f4e715154802a63e6d4682325204a6ea",
        label: "0x2ebb35694a16b22b4045429d48531da973454a9a877d3dcb3cc073d82759ddeb",
        commitment: "0x0d5acc6a80322dd51fd8956fba82b42843121f4547d23b116b84ac719d0306b9",
        nullifier_hash: "0x1c7e1a3e462f77bd6a2703111f855e488aecdc5b099033e8fbf291bc1fb02e13",
        nullifying_key_hash: "0x0771743e7ade0f56f51d16544f60059ba3029ba556d63697612900fe5f020b16",
        auth_digest: "0x2531ebd5a2e709b9f9d3220d1ba866c3873ac0bf3a2329b3bc1bf3da578d5872",
        keystore_leaf: "0x26296dd51c61dec066220686edab84c5f81cdd84dd21e74c345bd64b929c6bb1",
        commitment_leaf: "0x01c164bf326198a02cc0bf5b6320462e2bdb25baffbdc11c7562944bd9e8ef6d",
        nullifier_leaf: "0x0a840c81030265a5c537a1797461e716224212bbc4ba4b3c6a1b29bb038f1d85",
        asp_leaf: "0x26a89914a4eb17a03e6683ac14da2389b6e54cd355a5df022cd69a90c2fa797b",
    },
];

/// The free functions, step by step, against the SDK's services.
#[test]
fn note_functions_match_sdk() {
    for c in &CHAINS {
        let (owner, token) = (addr(c.owner), addr(c.token));
        let name = c.name;

        let nah = note::note_address_hash(owner, f(c.secret)).unwrap();
        assert_eq!(nah, f(c.nah), "{name}: noteAddressHash");
        let pre = note::precommitment(nah, token, c.value).unwrap();
        assert_eq!(pre, f(c.precommitment), "{name}: precommitment");
        let label = note::deposit_label(pre, f(c.deposit_secret)).unwrap();
        assert_eq!(label, f(c.label), "{name}: label");
        let commitment = note::commitment(pre, label).unwrap();
        assert_eq!(commitment, f(c.commitment), "{name}: commitment");

        let nullifier = note::nullifier_hash(f(c.nk), commitment).unwrap();
        assert_eq!(nullifier, f(c.nullifier_hash), "{name}: nullifierHash");
        let nkh = note::nullifying_key_hash(f(c.nk)).unwrap();
        assert_eq!(nkh, f(c.nullifying_key_hash), "{name}: P(nk)");
        let digest = note::auth_digest(f(c.rk)).unwrap();
        assert_eq!(digest, f(c.auth_digest), "{name}: authDigest");
        assert_eq!(
            note::keystore_leaf(owner, nkh, digest).unwrap(),
            f(c.keystore_leaf),
            "{name}: keystore leaf"
        );

        assert_eq!(
            note::commitment_leaf(commitment, c.ts).unwrap(),
            f(c.commitment_leaf),
            "{name}: commitment leaf"
        );
        assert_eq!(
            note::nullifier_leaf(nullifier, c.ts).unwrap(),
            f(c.nullifier_leaf),
            "{name}: nullifier leaf"
        );
        assert_eq!(
            note::asp_leaf(label).unwrap(),
            f(c.asp_leaf),
            "{name}: ASP leaf"
        );
    }
}

/// [`Note`] composes the same chain.
#[test]
fn note_struct_matches_sdk() {
    for c in &CHAINS {
        let name = c.name;
        let note = Note::deposit(
            addr(c.owner),
            addr(c.token),
            c.value,
            f(c.secret),
            f(c.deposit_secret),
        )
        .unwrap();
        assert_eq!(note.label, f(c.label), "{name}: label");
        assert_eq!(note.secret, f(c.secret));
        assert_eq!(note.note_address_hash().unwrap(), f(c.nah), "{name}");
        assert_eq!(note.precommitment().unwrap(), f(c.precommitment), "{name}");
        assert_eq!(note.commitment().unwrap(), f(c.commitment), "{name}");
        assert_eq!(
            note.nullifier_hash(f(c.nk)).unwrap(),
            f(c.nullifier_hash),
            "{name}"
        );
        assert_eq!(
            note.commitment_leaf(c.ts).unwrap(),
            f(c.commitment_leaf),
            "{name}"
        );
        assert_eq!(note.asp_leaf().unwrap(), f(c.asp_leaf), "{name}");

        // As a transact output it commits to the same value under the same label.
        let out = note.as_output().unwrap();
        assert_eq!(
            out,
            OutputNote {
                note_address_hash: f(c.nah),
                value: c.value,
                label: f(c.label),
            }
        );
        assert_eq!(out.commitment(addr(c.token)).unwrap(), f(c.commitment));
    }
}

/// Field inputs are taken mod p, as circomlibjs does: a secret of `p + x`
/// hashes like `x`.
#[test]
fn unreduced_hex_inputs_hash_like_their_residue() {
    let p_plus_5 = f("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000006");
    assert_eq!(p_plus_5, Field::from(5u8));
    let owner = addr(CHAINS[0].owner);
    assert_eq!(
        note::note_address_hash(owner, p_plus_5).unwrap(),
        note::note_address_hash(owner, Field::from(5u8)).unwrap()
    );
}

// --- outputs and inherited labels --------------------------------------------------

/// Change / recipient notes inherit a spent note's label; their commitment is
/// `P(P(nah, token, value, 0), label)` (`TransactOrchestrator`).
#[test]
fn inherited_label_output_commitments_match_sdk() {
    let eth_label = f(CHAINS[0].label);
    // Notes spec: change note (secret 0x55×32, value 4e17) of the ETH chain.
    let change = Note {
        owner: addr("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
        secret: f("0x5555555555555555555555555555555555555555555555555555555555555555"),
        token: NATIVE_ASSET,
        value: 400_000_000_000_000_000,
        label: eth_label,
    };
    assert_eq!(
        change.note_address_hash().unwrap(),
        f("0x0e07a554628552f3d59a0d5c296b1dce2752bc5a7c9a9f999d9564303255d98c")
    );
    assert_eq!(
        change.commitment().unwrap(),
        f("0x20ade7fc38571dfe57e2e8c1998fe664953787f9e6250800310dd11b0012a24c")
    );
    assert_eq!(
        change.as_output().unwrap().commitment(NATIVE_ASSET).unwrap(),
        change.commitment().unwrap()
    );

    // SDK `TransactOrchestrator` outputs of the 2x2 witness vector (Sepolia
    // USDC): a change note to the owner and a recipient note known to the
    // sender only by its noteAddressHash.
    let usdc = addr("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
    let owner = addr("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    let recipient = addr("0xa513E6E4b8f2a923D98304ec87F64353C4D5C853");
    let label_a = f("0x180ee981ea0d79b47684a59fa808b0390c40520b70d428fa5c4ba074c071463d");
    let label_b = f("0x0cf4f3546b80e719121642b3ed61b374645f47bf99a19bea38ddbcd452894742");
    for (owner, secret, value, label, nah, commitment) in [
        (
            owner,
            "0x0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
            1_500_000_000_000_000_000,
            label_b,
            "0x23dcbcb0f3aae08b773a934164b37fb3388685a83c2bf6aa31bbd2ead88e411e",
            "0x270fdb5496d31dcce6dd2a46f3a91dea45f8402a7fa5527f0d22838c4b5c9160",
        ),
        (
            recipient,
            "0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            2_500_000_000_000_000_000,
            label_a,
            "0x2eb3cafa00b26098ace93f015afa22844472cb0881804f1f20ea4bcf6bbd6d65",
            "0x2495e5038b4e2a7383520dd324dd33ccecd6c2e0e838b80ae88fbd0bf34cdd80",
        ),
        // The zero-value change note the SDK always emits.
        (
            owner,
            "0x1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e",
            0,
            label_b,
            "0x0949f13c3470a9eff125a52632a6dc2bbfea7045b159cbec1577ec60301dde22",
            "0x26433501158edb8ee139fd50d7d99abe6ca52c3c9766023f86cd79bf98211b46",
        ),
    ] {
        let out = OutputNote {
            note_address_hash: note::note_address_hash(owner, f(secret)).unwrap(),
            value,
            label,
        };
        assert_eq!(out.note_address_hash, f(nah));
        assert_eq!(out.commitment(usdc).unwrap(), f(commitment));
        let as_note = Note {
            owner,
            secret: f(secret),
            token: usdc,
            value,
            label,
        };
        assert_eq!(as_note.as_output().unwrap(), out);
        // The same output under another token is a different commitment.
        assert_ne!(out.commitment(NATIVE_ASSET).unwrap(), f(commitment));
    }
}

// --- keystore -----------------------------------------------------------------------

/// Keystore samples from the specs: the canonical zero-appSecret keys
/// (`CanonicalVectors.test.ts`, reduced) for anvil #0, and `nk = 1, rk = 2`
/// for `0x1111…11` (also the `setAuthPolicy` calldata vector).
#[test]
fn keystore_leaf_spec_vectors() {
    let nk = f("0x1aac3c3616b343de7c61b4987190eed46980a6a274493690a87943388c1945a7");
    let rk = f("0x152df42551c2ab363b162d7c64b069f23b08fddca850a96dc32a05e8d03b1495");
    let nkh = note::nullifying_key_hash(nk).unwrap();
    let digest = note::auth_digest(rk).unwrap();
    assert_eq!(
        nkh,
        f("0x0ddc01d1b82a7b3845199640dfb31ce42a44662aee5d704f4812b571ada457a5")
    );
    assert_eq!(
        digest,
        f("0x279ddbe31eb5f20ea7843ec7d4dadf84992421a32b8e23b3e322b57451dcc213")
    );
    assert_eq!(
        note::keystore_leaf(
            addr("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            nkh,
            digest
        )
        .unwrap(),
        f("0x057ab8e1d433d0f0373542dc76f38485fbe3b13176f466b399f1d385f13295d3")
    );

    let nkh = note::nullifying_key_hash(Field::from(1u8)).unwrap();
    let digest = note::auth_digest(Field::from(2u8)).unwrap();
    assert_eq!(
        nkh,
        f("0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133")
    );
    assert_eq!(
        digest,
        f("0x065e2c6cc08a36c4a943286bc91c216054a1981eb4f7570f67394ef8937a21b8")
    );
    assert_eq!(
        note::keystore_leaf(Address([0x11; 20]), nkh, digest).unwrap(),
        f("0x0a0d72635e27d6a557015e90480c7d359fec73e23cebc06d2e5736e218233b4c")
    );
    assert_eq!(note::AUTH_TYPE_DIRECT_KEY, 0);
}

/// Context spec vector 10: raw timestamped leaves over small values.
#[test]
fn timestamped_leaf_spec_vectors() {
    assert_eq!(
        note::commitment_leaf(Field::from(5u8), 1_700_000_000).unwrap(),
        f("0x1ff3918fbf04e9e27d1a24ff86107f2e5a749dfd4257813f9c2639bb961d55f4")
    );
    assert_eq!(
        note::nullifier_leaf(Field::from(7u8), 1_700_000_000).unwrap(),
        f("0x121fbab1111a7470b2d91d15e4abdb09c590a148c10db4c208f4fa302369a2ee")
    );
    // The two leaf kinds of one value never collide.
    assert_ne!(
        note::commitment_leaf(Field::from(5u8), 1).unwrap(),
        note::nullifier_leaf(Field::from(5u8), 1).unwrap()
    );
}

// --- secrets ------------------------------------------------------------------------

/// `CryptoService.generateSecret` (48 random bytes, big-endian, mod p) with
/// its randomness stubbed to these bytes.
#[test]
fn secret_from_entropy_matches_sdk_generate_secret() {
    for (entropy, secret) in [
        (
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0x03d581d748ffa25e32c475047957bf7ba7f12acca5b6cd8cb075da81ef8cfeb8",
        ),
        // BE(p) and BE(p + 1).
        (
            "0000000000000000000000000000000030644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "0000000000000000000000000000000030644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000002",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        ),
        (
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
            "0x1bee1f106da4075eb532b675cd011b0dde06c6559ce55de7c30f378f535686b6",
        ),
        (
            "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0x1a1ce8251518a143f58a5d5d7d6c8bec6812898a8fb81f0efa2be80aefc67f5d",
        ),
    ] {
        let entropy: [u8; 48] = hex::decode(entropy).unwrap().try_into().unwrap();
        let got = secret_from_entropy(&entropy);
        assert_eq!(got, f(secret), "{}", hex::encode(entropy));
        assert_eq!(format!("0x{}", hex::encode(got.to_bytes_be())), secret);
    }
}
