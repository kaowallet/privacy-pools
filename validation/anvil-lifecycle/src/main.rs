//! Full on-chain lifecycle against contracts deployed on anvil (see deploy.sh):
//! deposit -> sync/recover -> verify roots -> withdraw (relayed) -> ragequit,
//! exercising the async `Syncer` over a real alloy HTTP provider and proving
//! that the SDK's calldata is accepted by the actual Entrypoint + Pool.
//!
//!   RPC_URL=http://localhost:8545 cargo run   (after deploy.sh)

use std::fs;

use alloy::network::EthereumWallet;
use alloy::primitives::{address, Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use privacy_pools::{
    build_withdrawal, field_to_u256, ragequit_inputs, ragequit_proof, recover_accounts,
    withdraw_proof, Account, CommitmentProver, Destination, Field, IEntrypoint, IPrivacyPool,
    LeanImt, Syncer, WithdrawProver,
};

// updateRoot is an ASP-postman (admin) call, not a wallet operation, so it
// isn't in the wallet SDK — bind it locally for the test harness.
sol! {
    #[sol(rpc)]
    interface IAspAdmin {
        function updateRoot(uint256 _root, string _ipfsCID) external returns (uint256);
    }
}

const MNEMONIC: &str = "test test test test test test test test test test test junk";
// anvil default accounts.
const ACC0_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ONE_ETH: u128 = 1_000_000_000_000_000_000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rpc = std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".into());
    let dep: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/deployed.json"))?)?;
    let entrypoint: Address = dep["entrypoint"].as_str().unwrap().parse()?;
    let pool: Address = dep["pool"].as_str().unwrap().parse()?;
    let scope = Field::from_decimal(dep["scope"].as_str().unwrap())?;

    let signer: PrivateKeySigner = ACC0_PK.parse()?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(rpc.parse()?);

    let account = Account::from_mnemonic(MNEMONIC)?;
    let syncer = Syncer::new(pool, entrypoint);
    let ep = IEntrypoint::new(entrypoint, &provider);
    let pl = IPrivacyPool::new(pool, &provider);

    // === 1. deposit (index 0), 1 ETH ========================================
    let pre0 = account.deposit_precommitment(scope, 0)?;
    let r = ep.deposit_0(field_to_u256(pre0)).value(U256::from(ONE_ETH)).send().await?.get_receipt().await?;
    anyhow::ensure!(r.status(), "deposit A reverted");
    println!("✓ deposit A");

    // === 2. sync + recover ==================================================
    let logs = syncer.scan_pool(&provider, 0, None).await?;
    let accounts = recover_accounts(&account, scope, &logs, 10)?;
    let acct = accounts.iter().find(|a| a.deposit_index == 0).expect("recovered deposit 0");
    let note = *acct.spendable().expect("a spendable note");
    println!("✓ recovered note: value={} label={}", note.value.to_decimal(), note.label.to_decimal());

    // === 3. state proof + on-chain root verification ========================
    let state_tree = logs.state_tree()?;
    let idx = logs.leaf_index(note.hash()?).expect("note commitment is a state leaf");
    let state_proof = state_tree.generate_proof(idx)?;
    anyhow::ensure!(syncer.verify_state_root(&provider, state_proof.root).await?, "state root not on-chain");
    println!("✓ state root verified on-chain");

    // === 4. ASP: build a tree with our label, post the root, verify =========
    let asp_tree = LeanImt::from_leaves(&[note.label])?;
    let asp_proof = asp_tree.generate_proof(0)?;
    let asp_root = asp_tree.root().unwrap();
    let cid = "ipfs_cid_ipfs_cid_ipfs_cid_ipfs_cid_ipfs_cid_".to_string(); // 45 chars (32..64)
    let r = IAspAdmin::new(entrypoint, &provider)
        .updateRoot(field_to_u256(asp_root), cid)
        .send().await?.get_receipt().await?;
    anyhow::ensure!(r.status(), "updateRoot reverted");
    anyhow::ensure!(syncer.verify_asp_root(&provider, asp_root).await?, "asp root mismatch");
    println!("✓ ASP root posted + verified");

    // === 5. build + prove + relay a withdrawal ==============================
    let recipient = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"); // anvil acc1
    let fee_recipient = address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"); // anvil acc2
    let withdrawn = U256::from(400_000_000_000_000_000u64); // 0.4 ETH
    let dest = Destination::Relayed {
        entrypoint,
        recipient,
        fee_recipient,
        relay_fee_bps: U256::from(100),
    };
    let plan = build_withdrawal(
        &account, scope, &note, acct.children.len() as u64, withdrawn, &state_proof, &asp_proof, &dest,
    )?;
    let proof = WithdrawProver::bundled()?.prove(&plan.inputs)?;

    let before = provider.get_balance(recipient).await?;
    let r = ep
        .relay(plan.withdrawal.clone(), withdraw_proof(&proof)?, field_to_u256(scope))
        .send().await?.get_receipt().await?;
    anyhow::ensure!(r.status(), "relay reverted");
    let after = provider.get_balance(recipient).await?;
    anyhow::ensure!(after > before, "recipient was not paid");
    println!("✓ relay accepted on-chain; recipient +{} wei", after - before);

    // === 6. deposit B (index 1) + ragequit ==================================
    let pre1 = account.deposit_precommitment(scope, 1)?;
    let r = ep.deposit_0(field_to_u256(pre1)).value(U256::from(ONE_ETH)).send().await?.get_receipt().await?;
    anyhow::ensure!(r.status(), "deposit B reverted");

    let logs2 = syncer.scan_pool(&provider, 0, None).await?;
    let accts2 = recover_accounts(&account, scope, &logs2, 10)?;
    let acct_b = accts2.iter().find(|a| a.deposit_index == 1).expect("recovered deposit 1");
    let note_b = *acct_b.spendable().expect("spendable B");
    let rq_proof = CommitmentProver::bundled()?.prove(&ragequit_inputs(&note_b))?;
    let r = pl.ragequit(ragequit_proof(&rq_proof)?).send().await?.get_receipt().await?;
    anyhow::ensure!(r.status(), "ragequit reverted");
    println!("✓ ragequit accepted on-chain");

    println!("\nLIFECYCLE OK — deposit, sync, recover, verify, relay, ragequit all succeeded against live contracts.");
    Ok(())
}
