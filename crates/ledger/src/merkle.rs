//! RFC 6962 Merkle trees over ledger entries and account state.
//!
//! The tree is built from already-leaf-hashed values using the domain-separated
//! primitives in [`crate::hash`]:
//!
//! - `MTH({})` = [`empty_tree_root`](crate::hash::empty_tree_root),
//! - `MTH({d0})` = the leaf value itself (already [`leaf_hash`](crate::hash::leaf_hash)`ed`),
//! - `MTH(D[n])` = `node_hash(MTH(D[0..k]), MTH(D[k..n]))` where `k` is the
//!   largest power of two strictly less than `n`.
//!
//! Because [`leaf_hash`](crate::hash::leaf_hash) and
//! [`node_hash`](crate::hash::node_hash) use distinct BLAKE3 derive-key
//! contexts, RFC 6962's `0x00`/`0x01` prefixes are covered: leaves and
//! internal nodes can never be confused.

use crate::account::{AccountRef, Balances};
use crate::entry::SignedEntry;
use crate::error::LedgerError;
use crate::hash::{Hash, empty_tree_root, entry_hash, leaf_hash, node_hash, state_leaf_hash};

/// Largest power of two strictly less than `n` (for `n >= 2`).
fn largest_power_of_two_less_than(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// The canonical audit-path length for `index` in a tree of `tree_size`.
///
/// Must only be called with `tree_size > 0` and `index < tree_size`.
fn proof_len(index: usize, tree_size: usize) -> usize {
    let mut lo = 0usize;
    let mut hi = tree_size;
    let mut idx = index;
    let mut depth = 0usize;
    while hi - lo > 1 {
        let k = largest_power_of_two_less_than(hi - lo);
        if idx < k {
            hi = lo + k;
        } else {
            lo += k;
            idx -= k;
        }
        depth += 1;
    }
    depth
}

/// The Merkle Tree Hash (RFC 6962) of an already-leaf-hashed list.
///
/// `leaves` must already have been passed through
/// [`leaf_hash`](crate::hash::leaf_hash) (as [`entry_root`] and [`state_root`]
/// do); [`root`] does not re-hash them. An empty list returns
/// [`empty_tree_root`](crate::hash::empty_tree_root).
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_tree_root(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_less_than(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// The RFC 6962 audit path for `index`, ordered from the leaf toward the root.
///
/// Returns [`LedgerError::IndexOutOfRange`] when `index >= leaves.len()`.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Result<Vec<Hash>, LedgerError> {
    if index >= leaves.len() {
        return Err(LedgerError::IndexOutOfRange);
    }

    let mut proof = Vec::new();
    let mut lo = 0usize;
    let mut hi = leaves.len();
    let mut idx = index;
    while hi - lo > 1 {
        let k = largest_power_of_two_less_than(hi - lo);
        if idx < k {
            proof.push(root(&leaves[lo + k..hi]));
            hi = lo + k;
        } else {
            proof.push(root(&leaves[lo..lo + k]));
            lo += k;
            idx -= k;
        }
    }
    // The loop records siblings root-first; the audit path is leaf-first.
    proof.reverse();
    Ok(proof)
}

/// Verify an RFC 6962 inclusion proof.
///
/// `leaf` is the already-leaf-hashed value (an element of the list passed to
/// [`root`]); `tree_size` is the number of leaves. Returns `false` for an empty
/// tree, an out-of-range index, a wrong-length proof, or any mismatch.
///
/// `tree_size` and `root` must both come from the same authenticated source
/// (e.g. a signed [`crate::commit::Commitment`]): as in RFC 6962, the tree size
/// is external context and is not itself bound into the hash path.
pub fn verify_inclusion(
    leaf: &Hash,
    index: usize,
    tree_size: usize,
    proof: &[Hash],
    root: &Hash,
) -> bool {
    if tree_size == 0 || index >= tree_size {
        return false;
    }
    if proof.len() != proof_len(index, tree_size) {
        return false;
    }

    let mut node = *leaf;
    let mut fn_ = index;
    let mut sn = tree_size - 1;
    for sibling in proof {
        if sn == 0 {
            return false; // proof too long
        }
        if fn_ & 1 == 1 || fn_ == sn {
            node = node_hash(sibling, &node);
            if fn_ & 1 == 0 {
                // Right-shift both until the LSB of `fn_` is set or `fn_` is 0.
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            node = node_hash(&node, sibling);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    sn == 0 && node == *root
}

/// The Merkle root over a ledger prefix.
///
/// Leaves are `leaf_hash(entry_hash(entry)?)` for each entry, in order.
pub fn entry_root(entries: &[SignedEntry]) -> Result<Hash, LedgerError> {
    let mut leaves = Vec::with_capacity(entries.len());
    for entry in entries {
        leaves.push(leaf_hash(&entry_hash(&entry.entry)?));
    }
    Ok(root(&leaves))
}

/// The Merkle root over a node's current account state.
///
/// Leaf order is defined by [`Balances::accounts`]: `Parent` (when present),
/// then `Child` accounts in `NodeId` (BTreeMap) order — including zero
/// balances — then `Equity`. The root is therefore deterministic and
/// independent of the history that produced the balances.
pub fn state_root(balances: &Balances) -> Hash {
    let leaves: Vec<Hash> = balances
        .accounts()
        .map(|(account, balance)| state_leaf_hash(&account, balance))
        .collect();
    root(&leaves)
}

/// The audit path for one account in a balances state tree.
///
/// Returns `(index, proof)` where `index` is the account's position in
/// [`Balances::accounts`] order. Returns [`LedgerError::IndexOutOfRange`] when
/// the account is not present (an unopened child, or `Parent` at the root).
pub fn state_inclusion_proof(
    balances: &Balances,
    account: &AccountRef,
) -> Result<(usize, Vec<Hash>), LedgerError> {
    let mut leaves = Vec::with_capacity(balances.accounts().count());
    let mut found = None;
    for (index, (candidate, balance)) in balances.accounts().enumerate() {
        if found.is_none() && &candidate == account {
            found = Some(index);
        }
        leaves.push(state_leaf_hash(&candidate, balance));
    }
    let index = found.ok_or(LedgerError::IndexOutOfRange)?;
    let proof = inclusion_proof(&leaves, index)?;
    Ok((index, proof))
}

/// Verify a state leaf (`account`, `balance`) against a state root.
pub fn verify_state_inclusion(
    account: &AccountRef,
    balance: i128,
    index: usize,
    tree_size: usize,
    proof: &[Hash],
    root: &Hash,
) -> bool {
    let leaf = state_leaf_hash(account, balance);
    verify_inclusion(&leaf, index, tree_size, proof, root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountRef, NodeId, Posting};
    use crate::amount::SignedAmount;
    use crate::entry::{Entry, EntryBody};
    use crate::keys::LedgerSecretKey;
    use proptest::prelude::*;

    fn child(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn posting(account: AccountRef, delta: i64) -> Posting {
        Posting {
            account,
            delta: SignedAmount::new(delta),
        }
    }

    /// Deterministic leaf hashes for a tree of `n` leaves.
    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|index| leaf_hash(&Hash::from_bytes([index as u8; 32])))
            .collect()
    }

    fn signed_open(seq: u64, prev: Hash, id: &str, key: &LedgerSecretKey) -> SignedEntry {
        let entry = Entry {
            ledger_id: key.public(),
            seq,
            height: seq,
            prev_hash: prev,
            issued_at: seq,
            body: EntryBody::OpenAccount {
                child: child(id),
                kind: cawala_topology::ChildKind::Node,
            },
            postings: vec![],
            auth: None,
        };
        SignedEntry::sign(entry, key).unwrap()
    }

    #[test]
    fn empty_and_single_leaf() {
        assert_eq!(root(&[]), empty_tree_root());
        let one = leaves(1);
        assert_eq!(root(&one), one[0]);
    }

    #[test]
    fn root_matches_manual_split() {
        let three = leaves(3);
        assert_eq!(
            root(&three),
            node_hash(&node_hash(&three[0], &three[1]), &three[2])
        );

        let four = leaves(4);
        assert_eq!(
            root(&four),
            node_hash(
                &node_hash(&four[0], &four[1]),
                &node_hash(&four[2], &four[3])
            )
        );

        let five = leaves(5);
        assert_eq!(root(&five), node_hash(&root(&five[..4]), &five[4]));
    }

    #[test]
    fn inclusion_proofs_verify_for_all_sizes_and_indices() {
        for n in 0..=33 {
            let list = leaves(n);
            let r = root(&list);
            for index in 0..n {
                let proof = inclusion_proof(&list, index).unwrap();
                assert!(
                    verify_inclusion(&list[index], index, n, &proof, &r),
                    "proof failed for n={n} index={index}"
                );
            }
            assert_eq!(inclusion_proof(&list, n), Err(LedgerError::IndexOutOfRange));
        }
    }

    #[test]
    fn tampering_is_rejected() {
        let list = leaves(7);
        let r = root(&list);
        let index = 3;
        let proof = inclusion_proof(&list, index).unwrap();

        // Tampered leaf.
        let other_leaf = leaf_hash(&Hash::from_bytes([0xff; 32]));
        assert!(!verify_inclusion(&other_leaf, index, 7, &proof, &r));
        // Wrong index.
        assert!(!verify_inclusion(&list[index], index + 1, 7, &proof, &r));
        // Out-of-range tree size.
        assert!(!verify_inclusion(&list[index], index, index, &proof, &r));
        // A larger tree size that changes the required path depth.
        let last = list.len() - 1;
        let last_proof = inclusion_proof(&list, last).unwrap();
        assert!(!verify_inclusion(
            &list[last],
            last,
            list.len() + 1,
            &last_proof,
            &r
        ));
        // Tampered proof element.
        let mut bad = proof.clone();
        bad[0] = Hash::ZERO;
        assert!(!verify_inclusion(&list[index], index, 7, &bad, &r));
        // Truncated proof.
        assert!(!verify_inclusion(
            &list[index],
            index,
            7,
            &proof[..proof.len() - 1],
            &r
        ));
        // Over-long proof.
        let mut long = proof.clone();
        long.push(Hash::ZERO);
        assert!(!verify_inclusion(&list[index], index, 7, &long, &r));
        // Empty tree / out-of-range index.
        assert!(!verify_inclusion(&list[index], index, 0, &proof, &r));
        assert!(!verify_inclusion(&list[index], 99, 7, &proof, &r));
    }

    #[test]
    fn entry_root_is_deterministic() {
        let key = LedgerSecretKey::from_bytes([1u8; 32]);
        let first = signed_open(0, Hash::ZERO, "a", &key);
        let prev = entry_hash(&first.entry).unwrap();
        let second = signed_open(1, prev, "b", &key);
        let entries = vec![first, second];

        let expected_leaf_0 = leaf_hash(&entry_hash(&entries[0].entry).unwrap());
        let expected_leaf_1 = leaf_hash(&entry_hash(&entries[1].entry).unwrap());
        let expected = root(&[expected_leaf_0, expected_leaf_1]);

        assert_eq!(entry_root(&entries).unwrap(), expected);
        assert_eq!(entry_root(&entries.clone()).unwrap(), expected);
    }

    #[test]
    fn state_root_is_order_and_history_independent() {
        // Two histories that open the same accounts produce the same root,
        // regardless of open order or which posting materialized each balance.
        let mut a = Balances::new_non_root();
        a.open_account(&child("b")).unwrap();
        a.open_account(&child("a")).unwrap();
        a.apply(&[
            posting(AccountRef::Child(child("a")), 5),
            posting(AccountRef::Equity, -5),
        ])
        .unwrap();

        let mut b = Balances::new_non_root();
        b.open_account(&child("a")).unwrap();
        b.open_account(&child("b")).unwrap();
        b.apply(&[
            posting(AccountRef::Child(child("a")), 5),
            posting(AccountRef::Equity, -5),
        ])
        .unwrap();

        assert_eq!(state_root(&a), state_root(&b));
        assert_eq!(state_root(&a), state_root(&a.clone()));

        // A different balance changes the root.
        let mut c = a.clone();
        c.apply(&[
            posting(AccountRef::Child(child("a")), 1),
            posting(AccountRef::Equity, -1),
        ])
        .unwrap();
        assert_ne!(state_root(&a), state_root(&c));
    }

    #[test]
    fn state_inclusion_proofs_verify_for_every_account() {
        let mut balances = Balances::new_non_root();
        balances.open_account(&child("b")).unwrap();
        balances.open_account(&child("a")).unwrap();
        balances
            .apply(&[
                posting(AccountRef::Child(child("a")), 5),
                posting(AccountRef::Equity, -5),
            ])
            .unwrap();

        let root_hash = state_root(&balances);
        let tree_size = balances.accounts().count();
        for (account, balance) in balances.accounts() {
            let (index, proof) = state_inclusion_proof(&balances, &account).unwrap();
            assert!(
                verify_state_inclusion(&account, balance, index, tree_size, &proof, &root_hash),
                "state proof failed for {account:?}"
            );
        }

        // An account that was never opened has no leaf.
        assert_eq!(
            state_inclusion_proof(&balances, &AccountRef::Child(child("z"))),
            Err(LedgerError::IndexOutOfRange)
        );
        // The root has no parent account.
        let root = Balances::new_root();
        assert_eq!(
            state_inclusion_proof(&root, &AccountRef::Parent),
            Err(LedgerError::IndexOutOfRange)
        );
    }

    proptest! {
        #[test]
        fn proofs_verify_for_random_trees(hashes in prop::collection::vec(any::<u64>(), 0..64)) {
            let list: Vec<Hash> = hashes
                .iter()
                .map(|value| {
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&value.to_le_bytes());
                    leaf_hash(&Hash::from_bytes(bytes))
                })
                .collect();
            let r = root(&list);
            for (index, leaf) in list.iter().enumerate() {
                let proof = inclusion_proof(&list, index).unwrap();
                prop_assert!(verify_inclusion(leaf, index, list.len(), &proof, &r));
            }
        }
    }
}
