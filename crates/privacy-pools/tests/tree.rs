//! LeanIMT builder tests — cross-checked against `compute_root` (which is itself
//! validated against the withdraw circuit in tests/derivation.rs).

use privacy_pools::{compute_root, poseidon2, verify_inclusion, Field, LeanImt};

fn leaves(n: u64) -> Vec<Field> {
    (1..=n).map(|i| Field::from(1000 + i)).collect()
}

#[test]
fn small_trees_have_expected_roots() {
    // 1 leaf: root is the leaf.
    let t = LeanImt::from_leaves(&[Field::from(7u64)]).unwrap();
    assert_eq!(t.root().unwrap(), Field::from(7u64));
    assert_eq!(t.depth(), 0);

    // 2 leaves: root = H(a, b).
    let (a, b, c) = (Field::from(11u64), Field::from(22u64), Field::from(33u64));
    let t = LeanImt::from_leaves(&[a, b]).unwrap();
    assert_eq!(t.root().unwrap(), poseidon2(a, b).unwrap());
    assert_eq!(t.depth(), 1);

    // 3 leaves: root = H(H(a, b), c) — c is promoted as a single child.
    let t = LeanImt::from_leaves(&[a, b, c]).unwrap();
    assert_eq!(
        t.root().unwrap(),
        poseidon2(poseidon2(a, b).unwrap(), c).unwrap()
    );
    assert_eq!(t.depth(), 2);
}

#[test]
fn proofs_verify_for_every_leaf() {
    for n in [1u64, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31] {
        let ls = leaves(n);
        let tree = LeanImt::from_leaves(&ls).unwrap();
        let root = tree.root().unwrap();

        for (i, &leaf) in ls.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert_eq!(proof.leaf, leaf);
            assert_eq!(proof.root, root);

            // The proof reproduces the root via the circuit's own logic.
            assert_eq!(
                compute_root(proof.leaf, proof.index, &proof.siblings).unwrap(),
                root,
                "n={n} i={i}"
            );
            // And with circuit-style zero padding to MAX_TREE_DEPTH.
            let padded = proof.padded_siblings().unwrap();
            assert!(verify_inclusion(root, proof.leaf, proof.index, &padded).unwrap());
        }
    }
}

#[test]
fn incremental_insert_matches_batch() {
    let ls = leaves(13);
    let batch = LeanImt::from_leaves(&ls).unwrap();
    let mut incremental = LeanImt::new();
    for &l in &ls {
        incremental.insert(l).unwrap();
    }
    assert_eq!(batch.root(), incremental.root());
    assert_eq!(batch.depth(), incremental.depth());
}

#[test]
fn wrong_leaf_or_index_fails() {
    let ls = leaves(8);
    let tree = LeanImt::from_leaves(&ls).unwrap();
    let root = tree.root().unwrap();
    let proof = tree.generate_proof(3).unwrap();

    assert!(!verify_inclusion(root, Field::from(999_999u64), proof.index, &proof.siblings).unwrap());
    assert!(!verify_inclusion(root, proof.leaf, proof.index ^ 1, &proof.siblings).unwrap());

    assert!(tree.generate_proof(8).is_err()); // out of range
}
