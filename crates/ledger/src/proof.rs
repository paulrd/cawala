//! Proofs that a terminal settlement entry was actually applied.
//!
//! Two independent, pure checks:
//!
//! - [`EntryInclusionProof`] binds a signed entry to a committed `entry_root`
//!   using the RFC 6962 audit path built by [`crate::merkle`]. The leaf
//!   convention is exactly the one [`crate::merkle::entry_root`] and
//!   [`crate::commit::build_commitment`] use: `leaf_hash(entry_hash(entry))`.
//! - [`verify_applied_entry`] structurally proves that a terminal `Transfer`
//!   entry credits the order's payee (and, for a leaf payer, debits the payer).
//!
//! Both are pure: no clock, no RNG, no I/O.

use serde::{Deserialize, Serialize};

use crate::account::{AccountRef, aggregate_deltas};
use crate::auth::PaymentOrder;
use crate::entry::{EntryBody, HopRole, SignedEntry};
use crate::error::LedgerError;
use crate::hash::{Hash, entry_hash, leaf_hash};
use crate::log::{Ledger, LedgerLog};
use crate::merkle;

/// Maximum accepted RFC 6962 audit-path length in an [`EntryInclusionProof`].
///
/// Even a tree of `2^64` leaves has depth 64, so any honest proof is at most
/// this long; the cap bounds work and allocation before the path is verified.
pub const MAX_ENTRY_PROOF: usize = 64;

/// An RFC 6962 inclusion proof for one signed ledger entry.
///
/// `index`/`tree_size` are the compact `u32` wire form; both must be taken from
/// (or checked against) the authenticated [`crate::commit::Commitment`] the
/// `entry_root` came from. As in RFC 6962, the tree size is external context
/// and is not itself bound into the hash path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInclusionProof {
    /// Leaf position of the entry in the tree (`seq`, since the log is dense).
    pub index: u32,
    /// Number of leaves in the tree at proof time
    /// (`== Commitment::entry_count`).
    pub tree_size: u32,
    /// RFC 6962 audit path, ordered from the leaf toward the root.
    pub proof: Vec<Hash>,
}

/// Build the inclusion proof for the entry at ledger `seq`.
///
/// Leaves are `leaf_hash(entry_hash(entry)?)`, matching
/// [`crate::merkle::entry_root`] and [`crate::commit::build_commitment`]; the
/// audit path comes from [`crate::merkle::inclusion_proof`].
///
/// Returns [`LedgerError::IndexOutOfRange`] when `seq` is not a leaf of this
/// ledger (including when `seq != entry.seq`, so a caller cannot ask for a
/// position the log does not dense-address). The log is dense from 0, so `seq`
/// is both the ledger sequence number and the leaf index.
pub fn entry_inclusion_proof<L: LedgerLog>(
    ledger: &Ledger<L>,
    seq: u64,
) -> Result<EntryInclusionProof, LedgerError> {
    let index = usize::try_from(seq).map_err(|_| LedgerError::IndexOutOfRange)?;
    let tree_size = ledger.len();
    if index >= tree_size {
        return Err(LedgerError::IndexOutOfRange);
    }
    // Convert early so an unaddressable tree fails before allocating leaves.
    let index_u32 = u32::try_from(index).map_err(|_| LedgerError::IndexOutOfRange)?;
    let tree_size_u32 = u32::try_from(tree_size).map_err(|_| LedgerError::IndexOutOfRange)?;

    // Confirm the dense invariant rather than assume it.
    let entry = ledger
        .get(index)?
        .ok_or(LedgerError::MissingEntry { index })?;
    if entry.entry.seq != seq {
        return Err(LedgerError::IndexOutOfRange);
    }

    let mut leaves = Vec::with_capacity(tree_size);
    for position in 0..tree_size {
        let signed = ledger
            .get(position)?
            .ok_or(LedgerError::MissingEntry { index: position })?;
        leaves.push(leaf_hash(&entry_hash(&signed.entry)?));
    }
    let proof = merkle::inclusion_proof(&leaves, index)?;

    Ok(EntryInclusionProof {
        index: index_u32,
        tree_size: tree_size_u32,
        proof,
    })
}

/// Verify `entry` is included at `proof.index` in a tree of `proof.tree_size`
/// leaves with `entry_root`.
///
/// Returns `false` (never an error and never a panic) for an over-long proof
/// (`> MAX_ENTRY_PROOF`), `index >= tree_size`, an entry that cannot be hashed,
/// a wrong-length audit path, or any cryptographic mismatch. The leaf is
/// recomputed from `entry` with the same convention used to build the tree:
/// `leaf_hash(entry_hash(entry))`.
///
/// `entry_root` and `proof.tree_size` must both come from the same
/// authenticated [`crate::commit::Commitment`]; this function does not verify
/// the commitment itself.
pub fn verify_entry_inclusion(
    entry: &SignedEntry,
    proof: &EntryInclusionProof,
    entry_root: &Hash,
) -> bool {
    if proof.proof.len() > MAX_ENTRY_PROOF {
        return false;
    }
    if proof.index >= proof.tree_size {
        return false;
    }
    let leaf = match entry_hash(&entry.entry) {
        Ok(hash) => leaf_hash(&hash),
        Err(_) => return false,
    };
    merkle::verify_inclusion(
        &leaf,
        proof.index as usize,
        proof.tree_size as usize,
        &proof.proof,
        entry_root,
    )
}

/// Verify the terminal `Transfer` entry actually credits the order's payee.
///
/// Structural and pure: no signature, registry, or clock checks. All of the
/// following must hold, else [`LedgerError::InvalidEntryShape`]:
///
/// - the body is `Transfer` with `payment_id == order.hash()` and
///   `amount == order.amount`;
/// - the **net** posting for `Child(order.to)` is `+order.amount`;
/// - the role is [`HopRole::Direct`] when `payer_leaf`, and that hop's net
///   posting for `Child(order.from)` is `-order.amount` (the payer and payee
///   share a parent, so value moves child-to-child);
/// - otherwise the role is [`HopRole::Descend`] (the payer is not a leaf here;
///   the terminal credit lands in the payee's parent-side `Descend` hop).
///
/// Postings are aggregated first, so only the net posting for an account is
/// considered (an account cannot be credited more than `order.amount`).
pub fn verify_applied_entry(
    entry: &SignedEntry,
    order: &PaymentOrder,
    payer_leaf: bool,
) -> Result<(), LedgerError> {
    let EntryBody::Transfer {
        payment_id,
        amount,
        role,
    } = &entry.entry.body
    else {
        return Err(LedgerError::InvalidEntryShape);
    };
    if *payment_id != order.hash() || *amount != order.amount {
        return Err(LedgerError::InvalidEntryShape);
    }

    let amount = amount.get() as i128;
    let deltas = aggregate_deltas(&entry.entry.postings)?;

    // The payee's child account must receive the full order amount.
    let payee = AccountRef::Child(order.to.clone());
    if deltas.get(&payee).copied().unwrap_or(0) != amount {
        return Err(LedgerError::InvalidEntryShape);
    }

    if payer_leaf {
        // Same-parent move: the payer child is debited and the hop is `Direct`.
        if *role != HopRole::Direct {
            return Err(LedgerError::InvalidEntryShape);
        }
        let payer = AccountRef::Child(order.from.clone());
        if deltas.get(&payer).copied().unwrap_or(0) != -amount {
            return Err(LedgerError::InvalidEntryShape);
        }
    } else if *role != HopRole::Descend {
        return Err(LedgerError::InvalidEntryShape);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{NodeId, Posting};
    use crate::amount::{Amount, SignedAmount};
    use crate::commit::build_commitment;
    use crate::entry::Entry;
    use crate::keys::LedgerSecretKey;

    fn key() -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([1u8; 32])
    }

    fn child(id: &str) -> NodeId {
        NodeId::from(id)
    }

    /// A root ledger whose first `n` entries each open a distinct account.
    fn ledger_with(n: usize) -> Ledger {
        let key = key();
        let mut ledger = Ledger::new_root(key.public());
        let mut prev = Hash::ZERO;
        for seq in 0..n {
            let entry = Entry {
                ledger_id: key.public(),
                seq: seq as u64,
                height: seq as u64,
                prev_hash: prev,
                issued_at: seq as u64,
                body: EntryBody::OpenAccount {
                    child: child(&format!("n{seq}")),
                    kind: cawala_topology::ChildKind::Node,
                },
                postings: vec![],
                auth: None,
            };
            let signed = SignedEntry::sign(entry, &key).unwrap();
            prev = entry_hash(&signed.entry).unwrap();
            ledger.append(signed).unwrap();
        }
        ledger
    }

    fn entries_of(ledger: &Ledger) -> Vec<SignedEntry> {
        (0..ledger.len())
            .map(|index| ledger.get(index).unwrap().unwrap())
            .collect()
    }

    #[test]
    fn proofs_verify_at_every_index() {
        for n in 1..=9usize {
            let ledger = ledger_with(n);
            let entries = entries_of(&ledger);
            let root = crate::merkle::entry_root(&entries).unwrap();
            // The proof's tree is the same one a commitment commits to.
            assert_eq!(
                root,
                build_commitment(&ledger, Hash::ZERO, 0).unwrap().entry_root
            );

            for seq in 0..n as u64 {
                let proof = entry_inclusion_proof(&ledger, seq).unwrap();
                assert_eq!(proof.index, seq as u32, "n={n}");
                assert_eq!(proof.tree_size, n as u32, "n={n}");
                assert!(
                    verify_entry_inclusion(&entries[seq as usize], &proof, &root),
                    "proof failed for n={n} seq={seq}"
                );
            }

            // One past the last leaf, and unchecked positions, are out of range.
            assert_eq!(
                entry_inclusion_proof(&ledger, n as u64),
                Err(LedgerError::IndexOutOfRange)
            );
            assert_eq!(
                entry_inclusion_proof(&ledger, u64::MAX),
                Err(LedgerError::IndexOutOfRange)
            );
        }
    }

    #[test]
    fn single_entry_tree_has_empty_proof() {
        let ledger = ledger_with(1);
        let entries = entries_of(&ledger);
        let root = crate::merkle::entry_root(&entries).unwrap();
        let proof = entry_inclusion_proof(&ledger, 0).unwrap();
        assert_eq!(proof.index, 0);
        assert_eq!(proof.tree_size, 1);
        assert!(proof.proof.is_empty());
        assert!(verify_entry_inclusion(&entries[0], &proof, &root));
    }

    #[test]
    fn tampering_and_wrong_entry_are_rejected() {
        let ledger = ledger_with(7);
        let entries = entries_of(&ledger);
        let root = crate::merkle::entry_root(&entries).unwrap();
        let proof = entry_inclusion_proof(&ledger, 3).unwrap();
        let entry = entries[3].clone();
        assert!(verify_entry_inclusion(&entry, &proof, &root));

        // Tampered entry: the recomputed leaf no longer matches.
        let mut tampered = entry.clone();
        tampered.entry.seq = 99;
        assert!(!verify_entry_inclusion(&tampered, &proof, &root));

        // Tampered index.
        let mut bad_index = proof.clone();
        bad_index.index = 4;
        assert!(!verify_entry_inclusion(&entry, &bad_index, &root));

        // Index no longer strictly inside the (shrunken) tree.
        let mut degenerate = proof.clone();
        degenerate.tree_size = degenerate.index;
        assert!(!verify_entry_inclusion(&entry, &degenerate, &root));

        // A larger tree size that changes the required path depth/root: use the
        // last leaf, where +1 leaf changes the final sibling (mirroring the
        // merkle module's tamper test).
        let last = ledger.len() - 1;
        let last_entry = entries[last].clone();
        let last_proof = entry_inclusion_proof(&ledger, last as u64).unwrap();
        assert!(verify_entry_inclusion(&last_entry, &last_proof, &root));
        let mut bad_size = last_proof.clone();
        bad_size.tree_size += 1;
        assert!(!verify_entry_inclusion(&last_entry, &bad_size, &root));

        // Tampered root.
        assert!(!verify_entry_inclusion(
            &entry,
            &proof,
            &Hash::from_bytes([9u8; 32])
        ));

        // A valid proof for a different leaf must not verify this entry.
        let other_proof = entry_inclusion_proof(&ledger, 5).unwrap();
        assert!(!verify_entry_inclusion(&entry, &other_proof, &root));

        // Tampered / truncated / empty audit paths.
        let mut bad_path = proof.clone();
        bad_path.proof[0] = Hash::ZERO;
        assert!(!verify_entry_inclusion(&entry, &bad_path, &root));
        let mut short = proof.clone();
        short.proof.pop();
        assert!(!verify_entry_inclusion(&entry, &short, &root));
        let mut empty = proof.clone();
        empty.proof.clear();
        assert!(!verify_entry_inclusion(&entry, &empty, &root));
    }

    #[test]
    fn over_long_proof_is_rejected() {
        let ledger = ledger_with(4);
        let entries = entries_of(&ledger);
        let root = crate::merkle::entry_root(&entries).unwrap();
        let mut proof = entry_inclusion_proof(&ledger, 1).unwrap();

        // One extra sibling.
        proof.proof.push(Hash::ZERO);
        assert!(!verify_entry_inclusion(&entries[1], &proof, &root));

        // Beyond the explicit cap (and far beyond any honest path).
        proof.proof = vec![Hash::ZERO; MAX_ENTRY_PROOF + 1];
        assert!(!verify_entry_inclusion(&entries[1], &proof, &root));
    }

    #[test]
    fn proof_round_trips_through_serde() {
        let ledger = ledger_with(3);
        let proof = entry_inclusion_proof(&ledger, 2).unwrap();
        let bytes = postcard::to_allocvec(&proof).unwrap();
        let back: EntryInclusionProof = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, proof);
    }

    // --- verify_applied_entry ------------------------------------------------

    fn posting(account: AccountRef, delta: i64) -> Posting {
        Posting {
            account,
            delta: SignedAmount::new(delta),
        }
    }

    fn child_posting(id: &str, delta: i64) -> Posting {
        posting(AccountRef::Child(child(id)), delta)
    }

    fn order() -> PaymentOrder {
        PaymentOrder {
            from: child("alice"),
            to: child("bob"),
            amount: Amount::new(10),
            nonce: 1,
            expiry: 100,
        }
    }

    fn transfer(
        payment_id: Hash,
        amount: Amount,
        role: HopRole,
        postings: Vec<Posting>,
    ) -> SignedEntry {
        let entry = Entry {
            ledger_id: key().public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::Transfer {
                payment_id,
                amount,
                role,
            },
            postings,
            // `verify_applied_entry` is structural and does not consult auth.
            auth: None,
        };
        SignedEntry::sign(entry, &key()).unwrap()
    }

    #[test]
    fn applied_entry_accepts_direct_and_descend() {
        let order = order();

        // Leaf payer: Direct child-to-child move.
        let direct = transfer(
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("bob", 10)],
        );
        assert_eq!(verify_applied_entry(&direct, &order, true), Ok(()));

        // Non-leaf payer: the terminal credit is a Descend hop.
        let descend = transfer(
            order.hash(),
            order.amount,
            HopRole::Descend,
            vec![posting(AccountRef::Parent, 10), child_posting("bob", 10)],
        );
        assert_eq!(verify_applied_entry(&descend, &order, false), Ok(()));
    }

    #[test]
    fn applied_entry_rejects_wrong_amount() {
        let order = order();
        let entry = transfer(
            order.hash(),
            Amount::new(11),
            HopRole::Direct,
            vec![child_posting("alice", -11), child_posting("bob", 11)],
        );
        assert_eq!(
            verify_applied_entry(&entry, &order, true),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn applied_entry_rejects_wrong_payment_id() {
        let order = order();
        let entry = transfer(
            Hash::ZERO,
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("bob", 10)],
        );
        assert_eq!(
            verify_applied_entry(&entry, &order, true),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn applied_entry_rejects_wrong_payee() {
        let order = order();
        let entry = transfer(
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("carol", 10)],
        );
        assert_eq!(
            verify_applied_entry(&entry, &order, true),
            Err(LedgerError::InvalidEntryShape)
        );

        // Descend that credits the wrong child.
        let entry = transfer(
            order.hash(),
            order.amount,
            HopRole::Descend,
            vec![posting(AccountRef::Parent, 10), child_posting("carol", 10)],
        );
        assert_eq!(
            verify_applied_entry(&entry, &order, false),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn applied_entry_rejects_wrong_payer_debit() {
        let order = order();
        // Correct payee credit, but the debit is some other child.
        let entry = transfer(
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("carol", -10), child_posting("bob", 10)],
        );
        assert_eq!(
            verify_applied_entry(&entry, &order, true),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn applied_entry_rejects_wrong_role() {
        let order = order();

        // `payer_leaf == true` requires Direct.
        let descend_shape = transfer(
            order.hash(),
            order.amount,
            HopRole::Descend,
            vec![posting(AccountRef::Parent, 10), child_posting("bob", 10)],
        );
        assert_eq!(
            verify_applied_entry(&descend_shape, &order, true),
            Err(LedgerError::InvalidEntryShape)
        );

        // `payer_leaf == false` requires Descend.
        let direct_shape = transfer(
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("bob", 10)],
        );
        assert_eq!(
            verify_applied_entry(&direct_shape, &order, false),
            Err(LedgerError::InvalidEntryShape)
        );

        // Ascend/Lca are never a terminal applied credit.
        for role in [HopRole::Ascend, HopRole::Lca] {
            let entry = transfer(
                order.hash(),
                order.amount,
                role,
                vec![child_posting("alice", -10), child_posting("bob", 10)],
            );
            assert_eq!(
                verify_applied_entry(&entry, &order, true),
                Err(LedgerError::InvalidEntryShape),
                "role {role:?}"
            );
        }
    }

    #[test]
    fn applied_entry_rejects_duplicate_credit_legs() {
        let order = order();
        // Two +10 legs to the payee net to +20, so the payee is over-credited:
        // aggregation means only the net posting counts.
        let entry = transfer(
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![
                child_posting("alice", -10),
                child_posting("bob", 10),
                child_posting("bob", 10),
            ],
        );
        assert_eq!(
            verify_applied_entry(&entry, &order, true),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn applied_entry_rejects_non_transfer_body() {
        let order = order();
        let entry = Entry {
            ledger_id: key().public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::Issue {
                child: child("bob"),
                amount: order.amount,
            },
            postings: vec![child_posting("bob", 10)],
            auth: None,
        };
        let signed = SignedEntry::sign(entry, &key()).unwrap();
        assert_eq!(
            verify_applied_entry(&signed, &order, false),
            Err(LedgerError::InvalidEntryShape)
        );
    }
}
