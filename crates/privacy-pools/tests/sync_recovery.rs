//! Note-recovery logic (gap-limit deposit scan + change-chain walking), driven
//! by synthetic logs so it needs no chain. The async scan/verify paths are
//! exercised against anvil in the validation stage.
#![cfg(all(feature = "account", feature = "onchain"))]

use privacy_pools::alloy::primitives::{Address, U256};
use privacy_pools::{
    commitment_hash, nullifier_hash, precommitment, recover_accounts, Account, DepositLog, Field,
    PoolLogs, RagequitLog, WithdrawLog,
};

const MNEMONIC: &str = "test test test test test test test test test test test junk";

fn acct() -> Account {
    Account::from_mnemonic(MNEMONIC).unwrap()
}

/// A `Deposited` log for deposit `i` with the given value + (arbitrary) label.
fn deposit(a: &Account, scope: Field, i: u64, value: u128, label: Field) -> DepositLog {
    let (n, s) = a.deposit_secrets(scope, i).unwrap();
    DepositLog {
        depositor: Address::ZERO,
        commitment: commitment_hash(Field::from(value), label, n, s).unwrap(),
        label,
        value: U256::from(value),
        precommitment: precommitment(n, s).unwrap(),
        block: 1,
    }
}

/// A `Withdrawn` log spending `parent_nullifier`, minting the change note for
/// `child_index` of the account with `label`.
fn withdraw(
    a: &Account,
    label: Field,
    parent_nullifier: Field,
    parent_value: u128,
    withdrawn: u128,
    child_index: u64,
) -> WithdrawLog {
    let (n2, s2) = a.withdrawal_secrets(label, child_index).unwrap();
    WithdrawLog {
        processooor: Address::ZERO,
        value: U256::from(withdrawn),
        spent_nullifier: nullifier_hash(parent_nullifier).unwrap(),
        new_commitment: commitment_hash(Field::from(parent_value - withdrawn), label, n2, s2)
            .unwrap(),
        block: 2,
    }
}

#[test]
fn recovers_deposits_changes_and_ragequit() {
    let a = acct();
    let scope = Field::from(999u64);
    let (l0, l1, l2) = (
        Field::from(1000u64),
        Field::from(1001u64),
        Field::from(1002u64),
    );

    // Deposit 0 is partially withdrawn (100 -> 70); deposit 1 is untouched;
    // deposit 2 is ragequit.
    let (n0, _) = a.deposit_secrets(scope, 0).unwrap();
    let logs = PoolLogs {
        deposits: vec![
            deposit(&a, scope, 0, 100, l0),
            deposit(&a, scope, 1, 50, l1),
            deposit(&a, scope, 2, 70, l2),
        ],
        withdrawals: vec![withdraw(&a, l0, n0, 100, 30, 0)],
        ragequits: vec![RagequitLog {
            ragequitter: Address::ZERO,
            commitment: Field::ZERO,
            label: l2,
            value: U256::from(70),
            block: 3,
        }],
        ..Default::default()
    };

    let accounts = recover_accounts(&a, scope, &logs, 10).unwrap();
    assert_eq!(accounts.len(), 3);

    // Account 0: a change note of value 70 is the spendable commitment.
    assert_eq!(accounts[0].deposit_index, 0);
    assert_eq!(accounts[0].children.len(), 1);
    assert_eq!(accounts[0].spendable().unwrap().value, Field::from(70u64));

    // Account 1: untouched deposit of 50.
    assert!(accounts[1].children.is_empty());
    assert_eq!(accounts[1].spendable().unwrap().value, Field::from(50u64));

    // Account 2: ragequit -> not spendable.
    assert!(accounts[2].ragequit);
    assert!(accounts[2].spendable().is_none());
}

#[test]
fn walks_a_multi_step_change_chain() {
    let a = acct();
    let scope = Field::from(7u64);
    let label = Field::from(42u64);

    // 200 -> withdraw 50 -> 150 -> withdraw 25 -> 125.
    let (n0, _) = a.deposit_secrets(scope, 0).unwrap();
    let (n1, _) = a.withdrawal_secrets(label, 0).unwrap(); // first change note's nullifier
    let logs = PoolLogs {
        deposits: vec![deposit(&a, scope, 0, 200, label)],
        withdrawals: vec![
            withdraw(&a, label, n0, 200, 50, 0),
            withdraw(&a, label, n1, 150, 25, 1),
        ],
        ..Default::default()
    };

    let accounts = recover_accounts(&a, scope, &logs, 10).unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].children.len(), 2);
    assert_eq!(accounts[0].spendable().unwrap().value, Field::from(125u64));
}

#[test]
fn gap_limit_stops_the_scan() {
    let a = acct();
    let scope = Field::from(3u64);
    // Deposits at indices 0 and 5, gap of 4 empty indices between them.
    let logs = PoolLogs {
        deposits: vec![
            deposit(&a, scope, 0, 10, Field::from(1u64)),
            deposit(&a, scope, 5, 10, Field::from(2u64)),
        ],
        ..Default::default()
    };

    // gap_limit 3 < 4 -> stops before index 5, finding only the first deposit.
    assert_eq!(recover_accounts(&a, scope, &logs, 3).unwrap().len(), 1);
    // gap_limit 10 > 4 -> finds both.
    assert_eq!(recover_accounts(&a, scope, &logs, 10).unwrap().len(), 2);
}

#[test]
fn rejects_change_note_inconsistent_with_chain() {
    let a = acct();
    let scope = Field::from(1u64);
    let label = Field::from(9u64);
    let (n0, _) = a.deposit_secrets(scope, 0).unwrap();

    let mut bad = withdraw(&a, label, n0, 100, 40, 0);
    bad.new_commitment = Field::from(123_456u64); // doesn't match the derived note
    let logs = PoolLogs {
        deposits: vec![deposit(&a, scope, 0, 100, label)],
        withdrawals: vec![bad],
        ..Default::default()
    };

    assert!(recover_accounts(&a, scope, &logs, 10).is_err());
}
