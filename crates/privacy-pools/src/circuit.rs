//! The Privacy Pools circuits we bundle.

/// Maximum Merkle tree depth the `withdraw` circuit was compiled with
/// (`Withdraw(32)`), and hence the fixed length of the sibling arrays.
pub const MAX_TREE_DEPTH: usize = 32;

/// A bundled Privacy Pools circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Circuit {
    /// Prove a valid withdrawal: membership in the state + ASP trees, value
    /// bounds, and the new/existing commitment relationship.
    Withdraw,
    /// Compute a commitment hash + nullifier hash from `(value, label,
    /// nullifier, secret)`.
    Commitment,
}

impl Circuit {
    /// The artifact basename (`withdraw` / `commitment`).
    pub const fn name(self) -> &'static str {
        match self {
            Circuit::Withdraw => "withdraw",
            Circuit::Commitment => "commitment",
        }
    }

    /// Public-signal names in the order the on-chain verifier expects them:
    /// circuit outputs (declaration order) followed by declared public inputs
    /// (declaration order). This equals `witness[1..=nPublic]`.
    pub const fn public_signal_names(self) -> &'static [&'static str] {
        match self {
            Circuit::Withdraw => &[
                "newCommitmentHash",
                "existingNullifierHash",
                "withdrawnValue",
                "stateRoot",
                "stateTreeDepth",
                "ASPRoot",
                "ASPTreeDepth",
                "context",
            ],
            Circuit::Commitment => &["commitment", "nullifierHash", "value", "label"],
        }
    }

    /// Number of public signals (`nPublic`).
    pub const fn num_public(self) -> usize {
        self.public_signal_names().len()
    }
}
