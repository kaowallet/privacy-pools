//! Async chain sync over an alloy provider — the SDK drives the scan; the wallet
//! supplies its own (helios-backed) provider.
//!
//! This mirrors how the 0xbow SDK and Kohaku source data: chunked `eth_getLogs`
//! to replay the pool's events, a locally-rebuilt LeanIMT state tree, gap-limit
//! note recovery, and — crucially for a light-client wallet — **root
//! verification against `eth_call`** (which helios *can* verify, unlike logs):
//! the rebuilt state root is checked against the pool's 64-slot root ring
//! buffer, and the ASP root against `Entrypoint.latestRoot()`. So untrusted
//! logs are safe: a tampered log set can't forge a root that the on-chain
//! contract agrees with.

use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;

use crate::commitment::{nullifier_hash, Commitment};
use crate::error::{Error, Result};
use crate::field::Field;
use crate::onchain::{field_to_u256, u256_to_field, IPrivacyPool};
use crate::tree::LeanImt;

/// Size of the pool's recent-root ring buffer (`ROOT_HISTORY_SIZE`).
pub const ROOT_HISTORY_SIZE: u64 = 64;

/// A `LeafInserted(index, leaf, root)` event (one per state-tree insertion).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafInsert {
    /// 1-based post-insert tree size (0-based array position is `index - 1`).
    pub index: u64,
    pub leaf: Field,
    pub root: Field,
}

/// A pool `Deposited` event (carries the leaf commitment, label, value and
/// precommitment used for note recovery).
#[derive(Clone, Copy, Debug)]
pub struct DepositLog {
    pub depositor: Address,
    pub commitment: Field,
    pub label: Field,
    pub value: U256,
    pub precommitment: Field,
    pub block: u64,
}

/// A pool `Withdrawn` event.
#[derive(Clone, Copy, Debug)]
pub struct WithdrawLog {
    pub processooor: Address,
    pub value: U256,
    pub spent_nullifier: Field,
    pub new_commitment: Field,
    pub block: u64,
}

/// A pool `Ragequit` event.
#[derive(Clone, Copy, Debug)]
pub struct RagequitLog {
    pub ragequitter: Address,
    pub commitment: Field,
    pub label: Field,
    pub value: U256,
    pub block: u64,
}

/// All decoded pool logs from a scan, plus the block scanned to (a cursor for
/// incremental re-sync).
#[derive(Clone, Debug, Default)]
pub struct PoolLogs {
    /// `LeafInserted` events, sorted by tree index (insertion order).
    pub leaves: Vec<LeafInsert>,
    pub deposits: Vec<DepositLog>,
    pub withdrawals: Vec<WithdrawLog>,
    pub ragequits: Vec<RagequitLog>,
    pub to_block: u64,
}

impl PoolLogs {
    /// The state-tree leaves in insertion order.
    pub fn state_leaves(&self) -> Vec<Field> {
        self.leaves.iter().map(|l| l.leaf).collect()
    }

    /// Rebuild the LeanIMT state tree from the scanned leaves.
    pub fn state_tree(&self) -> Result<LeanImt> {
        LeanImt::from_leaves(&self.state_leaves())
    }

    /// The array position of a commitment among the state leaves (for building
    /// its membership proof).
    pub fn leaf_index(&self, commitment: Field) -> Option<usize> {
        self.leaves.iter().position(|l| l.leaf == commitment)
    }
}

/// A recovered account for one deposit: the deposit note, any change notes from
/// partial withdrawals, and whether it was ragequit.
#[derive(Clone, Debug)]
pub struct PoolAccount {
    pub label: Field,
    pub deposit_index: u64,
    pub deposit: Commitment,
    pub children: Vec<Commitment>,
    pub ragequit: bool,
}

impl PoolAccount {
    /// The current spendable commitment (last change note, else the deposit),
    /// or `None` if fully withdrawn or ragequit.
    pub fn spendable(&self) -> Option<&Commitment> {
        if self.ragequit {
            return None;
        }
        let c = self.children.last().unwrap_or(&self.deposit);
        if c.value == Field::ZERO {
            None
        } else {
            Some(c)
        }
    }
}

/// Drives the chain scan + verification over a caller-supplied alloy provider.
#[derive(Clone, Copy, Debug)]
pub struct Syncer {
    pub pool: Address,
    pub entrypoint: Address,
    /// Blocks per `eth_getLogs` request.
    pub chunk_size: u64,
    /// Consecutive empty deposit indices before recovery stops.
    pub gap_limit: usize,
}

impl Syncer {
    /// A syncer for a pool + entrypoint, with sensible defaults (5k-block
    /// chunks, gap limit 10 — matching the reference SDKs).
    pub fn new(pool: Address, entrypoint: Address) -> Self {
        Self {
            pool,
            entrypoint,
            chunk_size: 5000,
            gap_limit: 10,
        }
    }

    /// Scan the pool's events from `from_block` to `to_block` (or chain head),
    /// chunked into `chunk_size`-block windows.
    pub async fn scan_pool<P: Provider>(
        &self,
        provider: &P,
        from_block: u64,
        to_block: Option<u64>,
    ) -> Result<PoolLogs> {
        let head = match to_block {
            Some(b) => b,
            None => provider
                .get_block_number()
                .await
                .map_err(|e| Error::Chain(format!("get_block_number: {e}")))?,
        };

        let dec = |e: alloy::sol_types::Error| Error::Chain(format!("log decode: {e}"));
        let mut logs = PoolLogs {
            to_block: head,
            ..Default::default()
        };

        let mut start = from_block;
        while start <= head {
            let end = (start + self.chunk_size - 1).min(head);
            let filter = Filter::new()
                .address(self.pool)
                .from_block(start)
                .to_block(end);
            let chunk = provider
                .get_logs(&filter)
                .await
                .map_err(|e| Error::Chain(format!("get_logs {start}-{end}: {e}")))?;

            for log in &chunk {
                let block = log.block_number.unwrap_or_default();
                match log.topics().first() {
                    Some(t) if *t == IPrivacyPool::LeafInserted::SIGNATURE_HASH => {
                        let d = log
                            .log_decode::<IPrivacyPool::LeafInserted>()
                            .map_err(dec)?
                            .inner
                            .data;
                        logs.leaves.push(LeafInsert {
                            index: d._index.to::<u64>(),
                            leaf: u256_to_field(d._leaf),
                            root: u256_to_field(d._root),
                        });
                    }
                    Some(t) if *t == IPrivacyPool::Deposited::SIGNATURE_HASH => {
                        let d = log
                            .log_decode::<IPrivacyPool::Deposited>()
                            .map_err(dec)?
                            .inner
                            .data;
                        logs.deposits.push(DepositLog {
                            depositor: d._depositor,
                            commitment: u256_to_field(d._commitment),
                            label: u256_to_field(d._label),
                            value: d._value,
                            precommitment: u256_to_field(d._precommitmentHash),
                            block,
                        });
                    }
                    Some(t) if *t == IPrivacyPool::Withdrawn::SIGNATURE_HASH => {
                        let d = log
                            .log_decode::<IPrivacyPool::Withdrawn>()
                            .map_err(dec)?
                            .inner
                            .data;
                        logs.withdrawals.push(WithdrawLog {
                            processooor: d._processooor,
                            value: d._value,
                            spent_nullifier: u256_to_field(d._spentNullifier),
                            new_commitment: u256_to_field(d._newCommitment),
                            block,
                        });
                    }
                    Some(t) if *t == IPrivacyPool::Ragequit::SIGNATURE_HASH => {
                        let d = log
                            .log_decode::<IPrivacyPool::Ragequit>()
                            .map_err(dec)?
                            .inner
                            .data;
                        logs.ragequits.push(RagequitLog {
                            ragequitter: d._ragequitter,
                            commitment: u256_to_field(d._commitment),
                            label: u256_to_field(d._label),
                            value: d._value,
                            block,
                        });
                    }
                    _ => {}
                }
            }
            start = end + 1;
        }

        logs.leaves.sort_by_key(|l| l.index);
        Ok(logs)
    }

    /// `Pool.currentRoot()` — the latest state-tree root (via `eth_call`).
    pub async fn current_state_root<P: Provider>(&self, provider: &P) -> Result<Field> {
        let r = IPrivacyPool::new(self.pool, provider)
            .currentRoot()
            .call()
            .await
            .map_err(|e| Error::Chain(format!("currentRoot: {e}")))?;
        Ok(u256_to_field(r))
    }

    /// `Pool.currentTreeDepth()`.
    pub async fn current_tree_depth<P: Provider>(&self, provider: &P) -> Result<u64> {
        let d = IPrivacyPool::new(self.pool, provider)
            .currentTreeDepth()
            .call()
            .await
            .map_err(|e| Error::Chain(format!("currentTreeDepth: {e}")))?;
        Ok(d.to::<u64>())
    }

    /// `Entrypoint.latestRoot()` — the current ASP root a withdrawal must use.
    pub async fn latest_asp_root<P: Provider>(&self, provider: &P) -> Result<Field> {
        let r = crate::onchain::IEntrypoint::new(self.entrypoint, provider)
            .latestRoot()
            .call()
            .await
            .map_err(|e| Error::Chain(format!("latestRoot: {e}")))?;
        Ok(u256_to_field(r))
    }

    /// Trust anchor: is `root` one of the pool's recent on-chain state roots?
    /// Checks `currentRoot()` then walks the 64-slot `roots` ring buffer — all
    /// helios-verifiable `eth_call`s, so a forged log set can't pass.
    pub async fn verify_state_root<P: Provider>(&self, provider: &P, root: Field) -> Result<bool> {
        let pool = IPrivacyPool::new(self.pool, provider);
        let target = field_to_u256(root);
        let current = pool
            .currentRoot()
            .call()
            .await
            .map_err(|e| Error::Chain(format!("currentRoot: {e}")))?;
        if current == target {
            return Ok(true);
        }
        for i in 0..ROOT_HISTORY_SIZE {
            let r = pool
                .roots(U256::from(i))
                .call()
                .await
                .map_err(|e| Error::Chain(format!("roots({i}): {e}")))?;
            if r == target {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Trust anchor: does `root` equal the entrypoint's current ASP root?
    pub async fn verify_asp_root<P: Provider>(&self, provider: &P, root: Field) -> Result<bool> {
        Ok(self.latest_asp_root(provider).await? == root)
    }
}

/// Recover this account's notes from scanned pool logs, using the gap-limit
/// scan the protocol defines: for deposit index `0, 1, 2, …` derive the
/// precommitment and look for a matching `Deposited` event, stopping after
/// `gap_limit` consecutive misses; then walk each account's change chain via
/// `Withdrawn` events keyed by the spent nullifier hash.
#[cfg(feature = "account")]
pub fn recover_accounts(
    account: &crate::account::Account,
    scope: Field,
    logs: &PoolLogs,
    gap_limit: usize,
) -> Result<Vec<PoolAccount>> {
    use std::collections::{HashMap, HashSet};

    let deposits: HashMap<[u8; 32], &DepositLog> = logs
        .deposits
        .iter()
        .map(|d| (d.precommitment.to_bytes_be(), d))
        .collect();
    let withdrawals: HashMap<[u8; 32], &WithdrawLog> = logs
        .withdrawals
        .iter()
        .map(|w| (w.spent_nullifier.to_bytes_be(), w))
        .collect();
    let ragequit_labels: HashSet<[u8; 32]> = logs
        .ragequits
        .iter()
        .map(|r| r.label.to_bytes_be())
        .collect();

    let mut accounts = Vec::new();
    let mut misses = 0;
    let mut index = 0u64;
    while misses < gap_limit {
        let pre = account.deposit_precommitment(scope, index)?;
        let Some(dep) = deposits.get(&pre.to_bytes_be()) else {
            misses += 1;
            index += 1;
            continue;
        };
        misses = 0;
        let label = dep.label;
        let (nullifier, secret) = account.deposit_secrets(scope, index)?;
        let deposit = Commitment::new(u256_to_field(dep.value), label, nullifier, secret);

        // Walk the change chain: each Withdrawn(spentNullifier) mints a child.
        let mut children = Vec::new();
        let mut current = deposit;
        let mut current_value = dep.value;
        let mut child_index = 0u64;
        while let Some(w) = withdrawals.get(&nullifier_hash(current.nullifier)?.to_bytes_be()) {
            let new_value = current_value
                .checked_sub(w.value)
                .ok_or_else(|| Error::Chain("withdrawal exceeds note value".into()))?;
            let (n2, s2) = account.withdrawal_secrets(label, child_index)?;
            let change = Commitment::new(u256_to_field(new_value), label, n2, s2);
            // Sanity-check the derived change note against the on-chain event.
            if change.hash()? != w.new_commitment {
                return Err(Error::Chain(format!(
                    "recovered change commitment != on-chain new commitment at label {}, child {child_index}",
                    label.to_decimal()
                )));
            }
            children.push(change);
            current = change;
            current_value = new_value;
            child_index += 1;
        }

        let ragequit = ragequit_labels.contains(&label.to_bytes_be());
        accounts.push(PoolAccount {
            label,
            deposit_index: index,
            deposit,
            children,
            ragequit,
        });
        index += 1;
    }
    Ok(accounts)
}
