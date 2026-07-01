//! On-chain ABI layer (alloy) for the Privacy Pools contracts.
//!
//! `sol!` bindings (events, view functions, structs), calldata builders for
//! deposit / withdraw / relay / ragequit, and conversions from our
//! [`Groth16Proof`] to the Solidity proof structs. Pinned to the wallet's alloy
//! 2.0.1 so the boundary types (`Address`, `U256`, `Provider`, `Log`) unify.
//!
//! This module is pure ABI + types; the async chain scanner that drives a
//! provider lives in [`crate::sync`] (built on the `#[sol(rpc)]` bindings here).

use alloy::primitives::{address, Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};

use crate::error::{Error, Result};
use crate::field::Field;
use crate::proof::Groth16Proof;

/// Sentinel address for the native asset (ETH) used by the Entrypoint /
/// pool config — note this is NOT `address(0)`.
pub const NATIVE_ASSET: Address = address!("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE");

sol! {
    // ---- shared structs (match IPrivacyPool / IEntrypoint / ProofLib) ----
    #[derive(Debug)]
    struct Withdrawal {
        address processooor;
        bytes data;
    }
    #[derive(Debug)]
    struct WithdrawProof {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        uint256[8] pubSignals;
    }
    #[derive(Debug)]
    struct RagequitProof {
        uint256[2] pA;
        uint256[2][2] pB;
        uint256[2] pC;
        uint256[4] pubSignals;
    }
    /// `Withdrawal.data` for a relayed withdrawal (the Entrypoint's `RelayData`).
    #[derive(Debug)]
    struct RelayData {
        address recipient;
        address feeRecipient;
        uint256 relayFeeBPS;
    }

    #[sol(rpc)]
    interface IPrivacyPool {
        function SCOPE() external view returns (uint256);
        function ASSET() external view returns (address);
        function currentRoot() external view returns (uint256);
        function currentRootIndex() external view returns (uint32);
        function currentTreeDepth() external view returns (uint256);
        function currentTreeSize() external view returns (uint256);
        function roots(uint256 _index) external view returns (uint256);
        function nonce() external view returns (uint256);
        function nullifierHashes(uint256 _nullifierHash) external view returns (bool);
        function depositors(uint256 _label) external view returns (address);
        function deposit(address _depositor, uint256 _value, uint256 _precommitment) external payable returns (uint256);
        function withdraw(Withdrawal _w, WithdrawProof _p) external;
        function ragequit(RagequitProof _p) external;

        event LeafInserted(uint256 _index, uint256 _leaf, uint256 _root);
        event Deposited(address indexed _depositor, uint256 _commitment, uint256 _label, uint256 _value, uint256 _precommitmentHash);
        event Withdrawn(address indexed _processooor, uint256 _value, uint256 _spentNullifier, uint256 _newCommitment);
        event Ragequit(address indexed _ragequitter, uint256 _commitment, uint256 _label, uint256 _value);
    }

    #[sol(rpc)]
    interface IEntrypoint {
        function latestRoot() external view returns (uint256);
        function rootByIndex(uint256 _index) external view returns (uint256);
        function scopeToPool(uint256 _scope) external view returns (address);
        function assetConfig(address _asset) external view returns (address pool, uint256 minimumDepositAmount, uint256 vettingFeeBPS, uint256 maxRelayFeeBPS);
        function deposit(uint256 _precommitment) external payable returns (uint256);
        function deposit(address _asset, uint256 _value, uint256 _precommitment) external returns (uint256);
        function relay(Withdrawal _withdrawal, WithdrawProof _proof, uint256 _scope) external;

        event Deposited(address indexed _depositor, address indexed _pool, uint256 _commitment, uint256 _amount);
        event WithdrawalRelayed(address indexed _relayer, address indexed _recipient, address indexed _asset, uint256 _amount, uint256 _feeAmount);
        event RootUpdated(uint256 _root, string _ipfsCID, uint256 _timestamp);
        event PoolRegistered(address _pool, address _asset, uint256 _scope);
    }
}

// --- field <-> U256 -------------------------------------------------------

/// A field element as a `uint256` (big-endian).
pub fn field_to_u256(f: Field) -> U256 {
    U256::from_be_slice(&f.to_bytes_be())
}

/// A `uint256` reduced into the field (mod the BN254 scalar field).
pub fn u256_to_field(x: U256) -> Field {
    Field::from_bytes_be(&x.to_be_bytes::<32>())
}

/// This crate's [`crate::Address`] as an alloy `Address`.
pub fn to_alloy_address(a: crate::context::Address) -> Address {
    Address::from(a.0)
}

/// An alloy `Address` as this crate's [`crate::Address`].
pub fn from_alloy_address(a: Address) -> crate::context::Address {
    crate::context::Address(a.into_array())
}

// --- proof -> Solidity struct ---------------------------------------------

fn parse_u256(s: &str) -> Result<U256> {
    s.parse::<U256>()
        .map_err(|e| Error::Input(format!("invalid U256 '{s}': {e}")))
}

/// `(pA, pB, pC, pubSignals)` in the Solidity proof-struct shape.
type ProofParts = ([U256; 2], [[U256; 2]; 2], [U256; 2], Vec<U256>);

/// Parse a proof's `(pA, pB, pC, pubSignals)` from its Solidity calldata form
/// (which already applies the G2 `c1`/`c0` swap).
fn proof_parts(proof: &Groth16Proof) -> Result<ProofParts> {
    let cd = proof.to_solidity_calldata();
    let pa = [parse_u256(&cd.a[0])?, parse_u256(&cd.a[1])?];
    let pb = [
        [parse_u256(&cd.b[0][0])?, parse_u256(&cd.b[0][1])?],
        [parse_u256(&cd.b[1][0])?, parse_u256(&cd.b[1][1])?],
    ];
    let pc = [parse_u256(&cd.c[0])?, parse_u256(&cd.c[1])?];
    let sig = cd
        .public_signals
        .iter()
        .map(|s| parse_u256(s))
        .collect::<Result<Vec<_>>>()?;
    Ok((pa, pb, pc, sig))
}

/// Build the on-chain `WithdrawProof` (8 public signals) from a withdraw proof.
pub fn withdraw_proof(proof: &Groth16Proof) -> Result<WithdrawProof> {
    let (pa, pb, pc, sig) = proof_parts(proof)?;
    let pub_signals: [U256; 8] = sig.try_into().map_err(|v: Vec<U256>| {
        Error::Input(format!(
            "withdraw proof needs 8 public signals, got {}",
            v.len()
        ))
    })?;
    Ok(WithdrawProof {
        pA: pa,
        pB: pb,
        pC: pc,
        pubSignals: pub_signals,
    })
}

/// Build the on-chain `RagequitProof` (4 public signals) from a commitment
/// proof. The `commitment` circuit's public signals are exactly the ragequit
/// signals `[commitmentHash, nullifierHash, value, label]`.
pub fn ragequit_proof(proof: &Groth16Proof) -> Result<RagequitProof> {
    let (pa, pb, pc, sig) = proof_parts(proof)?;
    let pub_signals: [U256; 4] = sig.try_into().map_err(|v: Vec<U256>| {
        Error::Input(format!(
            "ragequit proof needs 4 public signals, got {}",
            v.len()
        ))
    })?;
    Ok(RagequitProof {
        pA: pa,
        pB: pb,
        pC: pc,
        pubSignals: pub_signals,
    })
}

// --- Withdrawal builders --------------------------------------------------

/// `abi.encode((recipient, feeRecipient, relayFeeBPS))` — the `Withdrawal.data`
/// for an Entrypoint-relayed withdrawal.
pub fn relay_data(recipient: Address, fee_recipient: Address, relay_fee_bps: U256) -> Bytes {
    SolValue::abi_encode(&RelayData {
        recipient,
        feeRecipient: fee_recipient,
        relayFeeBPS: relay_fee_bps,
    })
    .into()
}

/// A direct (non-relayed) withdrawal: `processooor` calls the pool itself and
/// `data` is empty.
pub fn direct_withdrawal(processooor: Address) -> Withdrawal {
    Withdrawal {
        processooor,
        data: Bytes::new(),
    }
}

/// An Entrypoint-relayed withdrawal: `processooor` is the Entrypoint and `data`
/// carries the recipient / fee-recipient / relay fee.
pub fn relayed_withdrawal(
    entrypoint: Address,
    recipient: Address,
    fee_recipient: Address,
    relay_fee_bps: U256,
) -> Withdrawal {
    Withdrawal {
        processooor: entrypoint,
        data: relay_data(recipient, fee_recipient, relay_fee_bps),
    }
}

// --- calldata builders (selector + args; the wallet sets to/value/gas) -----

/// `Entrypoint.deposit(uint256 _precommitment)` — native-asset deposit. The
/// wallet must set `value` to the deposit amount.
pub fn deposit_native_calldata(precommitment: Field) -> Bytes {
    SolCall::abi_encode(&IEntrypoint::deposit_0Call {
        _precommitment: field_to_u256(precommitment),
    })
    .into()
}

/// `Entrypoint.deposit(IERC20 _asset, uint256 _value, uint256 _precommitment)`
/// — ERC20 deposit (requires a prior `approve`).
pub fn deposit_erc20_calldata(asset: Address, value: U256, precommitment: Field) -> Bytes {
    SolCall::abi_encode(&IEntrypoint::deposit_1Call {
        _asset: asset,
        _value: value,
        _precommitment: field_to_u256(precommitment),
    })
    .into()
}

/// `Pool.withdraw(Withdrawal, WithdrawProof)` — direct withdrawal.
pub fn withdraw_calldata(w: &Withdrawal, proof: &Groth16Proof) -> Result<Bytes> {
    Ok(SolCall::abi_encode(&IPrivacyPool::withdrawCall {
        _w: w.clone(),
        _p: withdraw_proof(proof)?,
    })
    .into())
}

/// `Entrypoint.relay(Withdrawal, WithdrawProof, uint256 scope)` — relayed
/// withdrawal (`Withdrawal.processooor` must be the Entrypoint).
pub fn relay_calldata(w: &Withdrawal, proof: &Groth16Proof, scope: Field) -> Result<Bytes> {
    Ok(SolCall::abi_encode(&IEntrypoint::relayCall {
        _withdrawal: w.clone(),
        _proof: withdraw_proof(proof)?,
        _scope: field_to_u256(scope),
    })
    .into())
}

/// `Pool.ragequit(RagequitProof)` — original-depositor exit (no ASP approval).
pub fn ragequit_calldata(proof: &Groth16Proof) -> Result<Bytes> {
    Ok(SolCall::abi_encode(&IPrivacyPool::ragequitCall {
        _p: ragequit_proof(proof)?,
    })
    .into())
}
