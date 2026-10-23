//! Privacy Pools **v2** (0xbow `privacy-pools-v2-monorepo` v1.0.2,
//! ppv2-ceremony keys): keys, note math, typed circuit inputs and circuit
//! artifacts. Byte-compatible with `@0xbow/privacy-pools-v2-sdk@1.0.2`.
//!
//! - **Keys** (`keys-v2` feature): `Keys::from_signature` derives the
//!   nullifying, revocable and X25519 viewing keys from one EIP-712 signature
//!   over [`secret_derivation_digest`] — no mnemonic or passphrase.
//! - **Notes**: [`Note`], [`OutputNote`] and the leaf hashes of the state,
//!   keystore and association-set trees ([`note`] functions).
//! - **Binding**: [`deposit_context`] / [`transact_context`] over the
//!   [`NoteData`] and [`TransactParams`] sent on-chain.
//! - **Inputs**: [`DepositInputs`], [`RagequitInputs`], [`TransactInputs`]
//!   ([`CircuitInputs`]) — validated witness JSON plus the expected public
//!   signals; prove them with [`CircuitStore::prove`].
//!
//! v2 ships 27 circuits: `deposit`, `ragequit` and `transact_NxM` for
//! `N, M ∈ 1..=5`, with ~1 GB of proving keys (zkeys). Artifacts are served by a
//! [`CircuitStore`]:
//!
//! - `partial-bundled-v2` embeds the graph + vkey of **all 27** circuits and the
//!   zkeys of deposit, ragequit and transact_1x1 ([`Circuit::is_bundled`],
//!   ~24 MB), so those prove offline and any v2 proof verifies offline.
//! - The other 24 zkeys are downloaded on request into the store's directory,
//!   from 0xbow's GitHub at the pinned commit, and checked against the pinned
//!   ceremony sha256 ([`CircuitStore::missing`], [`CircuitStore::install`],
//!   and `CircuitStore::download` with the `download` feature).
//!
//! Every pinned hash, size and URL comes from `artifacts/v2/manifest.json`
//! (written by `cargo xtask pull-circuits-v2`), which is embedded in every build.

#[cfg(feature = "partial-bundled-v2")]
mod bundled;
mod catalog;
mod context;
#[cfg(feature = "download")]
mod download;
mod eip712;
mod inputs;
#[cfg(feature = "keys-v2")]
mod keys;
pub mod note;
mod store;

pub use context::{
    deposit_context, payout_routing_data, transact_context, NoteData, TransactParams,
};
#[cfg(feature = "download")]
pub use download::DownloadProgress;
pub use eip712::{
    address_hash, secret_derivation_digest, secret_derivation_typed_data, SetAuthPolicy,
    APP_IDENTIFIER, SECRET_DERIVATION_PURPOSE,
};
pub use inputs::{
    binary_merkle_root, CircuitInputs, DepositInputs, RagequitInputs, SpendNote, TransactInput,
    TransactInputs,
};
#[cfg(feature = "keys-v2")]
pub use keys::Keys;
pub use note::{secret_from_entropy, Note, OutputNote, NATIVE_ASSET};
pub use store::{ArtifactKind, ArtifactSource, CircuitStore};

/// `Transact` / `Ragequit` maximum state-tree depth (sibling array length).
pub const STATE_MAX_DEPTH: usize = 22;
/// Maximum keystore-tree depth.
pub const KEYSTORE_MAX_DEPTH: usize = 18;
/// Maximum association-set (ASP) tree depth.
pub const ASP_MAX_DEPTH: usize = 18;
/// Largest `N` / `M` a `transact_NxM` circuit is published for.
pub const MAX_TRANSACT_NOTES: u8 = 5;

/// A Privacy Pools v2 circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Circuit {
    /// Create a deposit commitment (`public [tokenId, value, context]`).
    Deposit,
    /// Exit a note to its owner without ASP approval.
    Ragequit,
    /// Spend `inputs` notes into `outputs` notes, optionally withdrawing
    /// `amountOut` publicly. Both counts must be in `1..=5`.
    Transact { inputs: u8, outputs: u8 },
}

impl Circuit {
    /// All 27 published circuits.
    pub fn all() -> impl Iterator<Item = Circuit> {
        let transacts = (1..=MAX_TRANSACT_NOTES).flat_map(|inputs| {
            (1..=MAX_TRANSACT_NOTES).map(move |outputs| Circuit::Transact { inputs, outputs })
        });
        [Circuit::Deposit, Circuit::Ragequit]
            .into_iter()
            .chain(transacts)
    }

    /// Parse an artifact basename (`deposit`, `ragequit`, `transact_<n>x<m>`).
    pub fn from_name(name: &str) -> Option<Circuit> {
        Circuit::all().find(|c| c.name() == name)
    }

    /// The artifact basename: `deposit`, `ragequit` or `transact_<n>x<m>`.
    pub fn name(self) -> String {
        match self {
            Circuit::Deposit => "deposit".into(),
            Circuit::Ragequit => "ragequit".into(),
            Circuit::Transact { inputs, outputs } => format!("transact_{inputs}x{outputs}"),
        }
    }

    /// Public-signal names in verifier order: outputs (declaration order) then
    /// declared public inputs. This equals `witness[1..=nPublic]`.
    pub fn public_signal_names(self) -> Vec<String> {
        let (outputs, pubs): (Vec<String>, &[&str]) = match self {
            Circuit::Deposit => (
                vec!["outputCommitment".into()],
                &["tokenId", "value", "context"],
            ),
            Circuit::Ragequit => (
                vec!["nullifierHash".into(), "commitment".into()],
                &["keystoreRoot", "ownerAddress", "value", "tokenId", "label"],
            ),
            Circuit::Transact { inputs, outputs } => (
                (0..inputs)
                    .map(|i| format!("nullifierHashes[{i}]"))
                    .chain((0..outputs).map(|j| format!("outputCommitments[{j}]")))
                    .collect(),
                &[
                    "stateRoot",
                    "keystoreRoot",
                    "associationSetRoot",
                    "amountOut",
                    "tokenIdOut",
                    "context",
                ],
            ),
        };
        outputs
            .into_iter()
            .chain(pubs.iter().map(|s| s.to_string()))
            .collect()
    }

    /// Number of public signals (`nPublic`).
    pub fn num_public(self) -> usize {
        match self {
            Circuit::Deposit => 4,
            Circuit::Ragequit => 7,
            Circuit::Transact { inputs, outputs } => inputs as usize + outputs as usize + 6,
        }
    }

    /// Whether `partial-bundled-v2` embeds this circuit's zkey: `deposit`,
    /// `ragequit` and `transact_1x1`.
    ///
    /// Deposit is needed for every deposit and ragequit is the exit that must
    /// work offline. The official SDK proves with `transact_{n}x{m}` where `n` =
    /// notes spent and `m` = one change note per label (plus one recipient note
    /// per label for a transfer), so 1x1 is withdrawing from one note.
    pub const fn is_bundled(self) -> bool {
        matches!(
            self,
            Circuit::Deposit
                | Circuit::Ragequit
                | Circuit::Transact {
                    inputs: 1,
                    outputs: 1
                }
        )
    }

    /// The name, or an error for a `Transact` shape upstream does not publish.
    pub(crate) fn checked_name(self) -> crate::Result<String> {
        if let Circuit::Transact { inputs, outputs } = self {
            let range = 1..=MAX_TRANSACT_NOTES;
            if !range.contains(&inputs) || !range.contains(&outputs) {
                return Err(crate::Error::Input(format!(
                    "transact_{inputs}x{outputs} does not exist (inputs and outputs \
                     must be in 1..={MAX_TRANSACT_NOTES})"
                )));
            }
        }
        Ok(self.name())
    }
}
