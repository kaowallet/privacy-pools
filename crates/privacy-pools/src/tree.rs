//! LeanIMT (Lean Incremental Merkle Tree) — matches `@zk-kit/lean-imt` and the
//! `LeanIMTInclusionProof` circuit.
//!
//! A LeanIMT is a Merkle tree whose hash is `Poseidon([left, right])` and where
//! **a node with a single (left) child takes that child's value directly** — no
//! hashing against a zero sibling. The depth grows as leaves are added.
//!
//! The builder ([`LeanImt`]) is filled in once the exact zk-kit insertion order
//! is confirmed; [`compute_root`] (the inclusion-proof root recomputation) is
//! the circuit's own logic and is validated against the upstream withdraw
//! vectors.

use crate::circuit::MAX_TREE_DEPTH;
use crate::error::{Error, Result};
use crate::field::Field;
use crate::poseidon::poseidon2;

/// Recompute a LeanIMT root from an inclusion proof, exactly as the circuit's
/// `LeanIMTInclusionProof` does.
///
/// At each level `i`, an empty sibling (`Field::ZERO` — i.e. a single-child node
/// or a level beyond the tree depth) passes the node through unchanged;
/// otherwise the node is hashed with the sibling, ordered by bit `i` of `index`
/// (bit 0 → node is the left input, bit 1 → node is the right input).
pub fn compute_root(leaf: Field, index: u64, siblings: &[Field]) -> Result<Field> {
    if siblings.len() > MAX_TREE_DEPTH {
        return Err(Error::Input(format!(
            "too many siblings: {} > {MAX_TREE_DEPTH}",
            siblings.len()
        )));
    }
    let mut node = leaf;
    for (i, &sib) in siblings.iter().enumerate() {
        if sib == Field::ZERO {
            // single-child node / padding beyond the actual depth: passthrough
            continue;
        }
        node = if (index >> i) & 1 == 0 {
            poseidon2(node, sib)?
        } else {
            poseidon2(sib, node)?
        };
    }
    Ok(node)
}

/// Verify that `leaf` sits at `index` under `root` given `siblings`.
pub fn verify_inclusion(root: Field, leaf: Field, index: u64, siblings: &[Field]) -> Result<bool> {
    Ok(compute_root(leaf, index, siblings)? == root)
}

/// A membership proof, in the exact shape the circuit consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub root: Field,
    pub leaf: Field,
    /// Path-derived index — this is the `leafIndex` the circuit wants (NOT the
    /// leaf's array position).
    pub index: u64,
    /// Real siblings, in level order (no zero padding).
    pub siblings: Vec<Field>,
}

impl MerkleProof {
    /// `siblings` zero-padded to [`MAX_TREE_DEPTH`], as the circuit expects.
    pub fn padded_siblings(&self) -> Result<[Field; MAX_TREE_DEPTH]> {
        crate::inputs::siblings(&self.siblings)
    }

    /// The tree depth (= number of real siblings is ≤ this).
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

/// A Lean Incremental Merkle Tree (matches `@zk-kit/lean-imt`).
///
/// Insert commitments (or labels, for the ASP tree) in order, then
/// [`generate_proof`](LeanImt::generate_proof) to get circuit inputs. The hash
/// is `Poseidon([left, right])`; a node with a single child takes that child's
/// value directly.
#[derive(Clone, Debug, Default)]
pub struct LeanImt {
    /// `nodes[0]` = leaves; `nodes[level]` = that level's nodes; last = `[root]`.
    nodes: Vec<Vec<Field>>,
}

impl LeanImt {
    pub fn new() -> Self {
        Self { nodes: vec![vec![]] }
    }

    /// Build directly from a list of leaves (insertion order preserved).
    pub fn from_leaves(leaves: &[Field]) -> Result<Self> {
        let mut t = Self::new();
        t.insert_many(leaves)?;
        Ok(t)
    }

    /// Number of leaves.
    pub fn size(&self) -> usize {
        self.nodes[0].len()
    }

    /// Tree depth (0 for an empty or single-leaf tree).
    pub fn depth(&self) -> usize {
        self.nodes.len() - 1
    }

    /// The current root (`None` if empty).
    pub fn root(&self) -> Option<Field> {
        self.nodes.last().and_then(|level| level.first().copied())
    }

    /// The inserted leaves.
    pub fn leaves(&self) -> &[Field] {
        &self.nodes[0]
    }

    /// Append a leaf.
    pub fn insert(&mut self, leaf: Field) -> Result<()> {
        if self.depth() < ceil_log2(self.size() + 1) {
            self.nodes.push(Vec::new());
        }
        let mut node = leaf;
        let mut index = self.size();
        for level in 0..self.depth() {
            set(&mut self.nodes[level], index, node);
            if index & 1 == 1 {
                let sibling = self.nodes[level][index - 1];
                node = poseidon2(sibling, node)?;
            }
            index >>= 1;
        }
        let depth = self.depth();
        self.nodes[depth] = vec![node];
        Ok(())
    }

    /// Append many leaves.
    pub fn insert_many(&mut self, leaves: &[Field]) -> Result<()> {
        for &leaf in leaves {
            self.insert(leaf)?;
        }
        Ok(())
    }

    /// Generate a membership proof for the leaf at array position `index`.
    pub fn generate_proof(&self, mut index: usize) -> Result<MerkleProof> {
        if index >= self.size() {
            return Err(Error::Input(format!(
                "leaf index {index} out of range (size {})",
                self.size()
            )));
        }
        let leaf = self.nodes[0][index];
        let root = self.root().ok_or_else(|| Error::Input("empty tree".into()))?;
        let mut siblings = Vec::new();
        let mut path = Vec::new();
        for level in 0..self.depth() {
            let is_right = index & 1;
            let sibling_index = if is_right == 1 { index - 1 } else { index + 1 };
            if let Some(&sibling) = self.nodes[level].get(sibling_index) {
                path.push(is_right as u64);
                siblings.push(sibling);
            }
            index >>= 1;
        }
        // Proof index = path bits, level-0 bit is the least significant.
        let mut proof_index = 0u64;
        for (k, &bit) in path.iter().enumerate() {
            proof_index |= bit << k;
        }
        Ok(MerkleProof { root, leaf, index: proof_index, siblings })
    }
}

/// `ceil(log2(n))`, with `ceil_log2(0) = ceil_log2(1) = 0`.
fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as usize
    }
}

/// Assign `v[i] = val`, growing with zeros if needed (mirrors JS sparse assign).
fn set(v: &mut Vec<Field>, i: usize, val: Field) {
    while v.len() <= i {
        v.push(Field::ZERO);
    }
    v[i] = val;
}
