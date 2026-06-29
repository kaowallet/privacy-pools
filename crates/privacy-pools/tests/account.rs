//! HD account key derivation — pinned against the 0xbow TypeScript SDK
//! (`@0xbow/privacy-pools-core-sdk`, `crypto.ts`) for the well-known test
//! mnemonic. The live cross-check over random mnemonics lives in
//! `validation/differential/` (0 mismatches); these vectors keep the
//! derivation regression-locked without bun.
#![cfg(feature = "account")]

use privacy_pools::{Account, Field};

const MNEMONIC: &str = "test test test test test test test test test test test junk";

fn fdec(s: &str) -> Field {
    Field::from_decimal(s).unwrap()
}

#[test]
fn master_keys_match_sdk() {
    let keys = Account::from_mnemonic(MNEMONIC).unwrap().master_keys();
    assert_eq!(
        keys.nullifier,
        fdec("20068762160393292801596226195912281868434195939362930533775271887246872084568")
    );
    assert_eq!(
        keys.secret,
        fdec("4263194520628581151689140073493505946870598678660509318310629023735624352890")
    );
}

#[test]
fn deposit_and_withdrawal_secrets_match_sdk() {
    let acct = Account::from_mnemonic(MNEMONIC).unwrap();
    let (scope, label, index) = (fdec("123456789"), fdec("987654321"), 7u64);

    let (d_null, d_sec) = acct.deposit_secrets(scope, index).unwrap();
    assert_eq!(
        d_null,
        fdec("19475315022216625291354534090789221757761393634784815774281714396099624011873")
    );
    assert_eq!(
        d_sec,
        fdec("7864384861538466662339237220644335684388023288306110893365145360637677422784")
    );

    let (w_null, w_sec) = acct.withdrawal_secrets(label, index).unwrap();
    assert_eq!(
        w_null,
        fdec("621109981963405117718393326853850136662392967041753360851776587572007669196")
    );
    assert_eq!(
        w_sec,
        fdec("10246753788852305082950425429093043304721579825493070650281677297828300207763")
    );
}

#[test]
fn precommitment_chains_through_deposit_secrets() {
    let acct = Account::from_mnemonic(MNEMONIC).unwrap();
    let scope = fdec("123456789");
    let (null, sec) = acct.deposit_secrets(scope, 7).unwrap();
    assert_eq!(
        acct.deposit_precommitment(scope, 7).unwrap(),
        privacy_pools::precommitment(null, sec).unwrap()
    );
}

#[test]
fn from_master_keys_roundtrips() {
    let acct = Account::from_mnemonic(MNEMONIC).unwrap();
    let rebuilt = Account::from_master_keys(acct.master_keys());
    assert_eq!(
        acct.deposit_secrets(fdec("1"), 0).unwrap(),
        rebuilt.deposit_secrets(fdec("1"), 0).unwrap()
    );
}
