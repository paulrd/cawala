//! Signed state commitments over a prefix of the ledger.
//!
//! A [`Commitment`] binds a ledger identity to the Merkle roots of its entry
//! history and account state at a point in time. Commitments are chained by
//! [`Commitment::prev_commitment_hash`] and signed by the ledger key.
//!
//! The commitment has no independent height yet: `height == entry_count ==
//! ledger.len()`.

use serde::{Deserialize, Serialize};

use crate::account::{AccountRef, NodeId};
use crate::amount::Amount;
use crate::error::LedgerError;
use crate::hash::Hash;
use crate::keys::{LedgerId, LedgerPubKey, LedgerSecretKey, Signature};
use crate::log::{Ledger, LedgerLog};
use crate::merkle;

/// BLAKE3 derive-key context for [`commitment_hash`].
pub const COMMITMENT_CONTEXT: &str = "cawala-ledger/commitment/v1";

/// A parent/child edge that a [`BalanceAttestation`] covers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EdgeAccount {
    /// The parent node.
    pub parent: NodeId,
    /// The child node.
    pub child: NodeId,
}

/// A point-in-time commitment to a ledger's entries and state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// The ledger's public identity.
    pub ledger_id: LedgerId,
    /// The ledger's public key (must equal `ledger_id`).
    pub ledger_pubkey: LedgerPubKey,
    /// Height of the committed prefix (`== entry_count` for now).
    pub height: u64,
    /// Number of entries committed.
    pub entry_count: u64,
    /// Merkle root over the committed entries.
    pub entry_root: Hash,
    /// Merkle root over the committed account state.
    pub state_root: Hash,
    /// Hash of the previous commitment ([`Hash::ZERO`] at genesis).
    pub prev_commitment_hash: Hash,
    /// Coarse issuance timestamp.
    pub issued_at: u64,
}

impl Commitment {
    /// The fixed-width canonical encoding of this commitment.
    ///
    /// All fields have a fixed size, so this encoding cannot fail. It is the
    /// message signed by [`SignedCommitment::sign`] and hashed by
    /// [`commitment_hash`].
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 * 32 + 3 * 8);
        out.extend_from_slice(&self.ledger_id.to_bytes());
        out.extend_from_slice(&self.ledger_pubkey.to_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.entry_count.to_le_bytes());
        out.extend_from_slice(self.entry_root.as_bytes());
        out.extend_from_slice(self.state_root.as_bytes());
        out.extend_from_slice(self.prev_commitment_hash.as_bytes());
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out
    }
}

/// A [`Commitment`] together with its ledger signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCommitment {
    /// The signed commitment.
    pub commitment: Commitment,
    /// Signature over `commitment.canonical_bytes()`.
    pub signature: Signature,
}

impl SignedCommitment {
    /// Sign a commitment with the ledger key.
    ///
    /// Fails with [`LedgerError::LedgerMismatch`] unless the commitment is
    /// internally consistent (`ledger_id == ledger_pubkey`) and
    /// `ledger_pubkey` is the public key of `key`.
    pub fn sign(commitment: Commitment, key: &LedgerSecretKey) -> Result<Self, LedgerError> {
        if commitment.ledger_id != commitment.ledger_pubkey
            || commitment.ledger_pubkey != key.public()
        {
            return Err(LedgerError::LedgerMismatch);
        }
        let signature = key.sign(&commitment.canonical_bytes());
        Ok(SignedCommitment {
            commitment,
            signature,
        })
    }

    /// Verify this commitment against the expected ledger key.
    ///
    /// Checks internal consistency (`ledger_id == ledger_pubkey`), that
    /// `ledger_pubkey == *expected`, and the signature.
    pub fn verify(&self, expected: &LedgerPubKey) -> Result<(), LedgerError> {
        let commitment = &self.commitment;
        if commitment.ledger_id != commitment.ledger_pubkey || commitment.ledger_pubkey != *expected
        {
            return Err(LedgerError::LedgerMismatch);
        }
        commitment
            .ledger_pubkey
            .verify(&commitment.canonical_bytes(), &self.signature)
    }
}

/// Verify a chain of commitments for one ledger.
///
/// Every element must verify under `expected` and satisfy `height ==
/// entry_count`; every element after the first must have a strictly greater
/// `height`, and its `prev_commitment_hash` must equal [`commitment_hash`] of
/// its predecessor. The first element's `prev_commitment_hash` must be
/// [`Hash::ZERO`] (the chain anchor).
///
/// An empty chain verifies vacuously.
///
/// # Equivocation
///
/// Two commitments with the same height but different roots (a fork) cannot be
/// detected from a single chain. They are detectable only by comparing heads
/// across peers, which is Phase C netting's job.
pub fn verify_chain(
    chain: &[SignedCommitment],
    expected: &LedgerPubKey,
) -> Result<(), LedgerError> {
    let mut iter = chain.iter();
    let Some(first) = iter.next() else {
        return Ok(());
    };

    first.verify(expected)?;
    check_consistent_height(&first.commitment)?;
    if first.commitment.prev_commitment_hash != Hash::ZERO {
        return Err(LedgerError::PrevHashMismatch {
            expected: Hash::ZERO,
            found: first.commitment.prev_commitment_hash,
        });
    }

    let mut prev = first;
    for current in iter {
        current.verify(expected)?;
        check_consistent_height(&current.commitment)?;

        if current.commitment.height <= prev.commitment.height {
            return Err(LedgerError::InvalidHeight {
                expected: prev.commitment.height.saturating_add(1),
                found: current.commitment.height,
            });
        }

        let expected_prev = commitment_hash(&prev.commitment);
        if current.commitment.prev_commitment_hash != expected_prev {
            return Err(LedgerError::PrevHashMismatch {
                expected: expected_prev,
                found: current.commitment.prev_commitment_hash,
            });
        }

        prev = current;
    }
    Ok(())
}

/// Until commitments have an independent height, `height` must equal
/// `entry_count`.
fn check_consistent_height(commitment: &Commitment) -> Result<(), LedgerError> {
    if commitment.height != commitment.entry_count {
        return Err(LedgerError::InvalidHeight {
            expected: commitment.entry_count,
            found: commitment.height,
        });
    }
    Ok(())
}

/// The domain-separated hash of a commitment (used for chaining).
pub fn commitment_hash(commitment: &Commitment) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key(COMMITMENT_CONTEXT);
    hasher.update(&commitment.canonical_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// A verifiable attestation of one child account's balance at a height.
///
/// The inclusion proof binds the `Child(edge.child)` leaf (with `balance`) to
/// `state_root`, which in turn is bound to a signed [`Commitment`]. The
/// `ledger_pubkey` names the attesting ledger; `edge` carries the real
/// topology node ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceAttestation {
    /// The real topology parent/child edge the balance belongs to.
    pub edge: EdgeAccount,
    /// The attesting ledger's public key.
    pub ledger_pubkey: LedgerPubKey,
    /// The attested balance of the child account.
    pub balance: Amount,
    /// Height of the committed prefix (`== entry_count`).
    pub height: u64,
    /// The state root the proof is against.
    pub state_root: Hash,
    /// Leaf index in [`crate::merkle::state_root`] order.
    pub index: usize,
    /// Number of state leaves the proof is for.
    pub tree_size: usize,
    /// Merkle audit path for the child leaf.
    pub proof: Vec<Hash>,
}

/// Produce a verifiable balance attestation for `child` under `parent` from a
/// ledger's current state.
///
/// `parent` and `child` are real topology [`NodeId`]s; `ledger_pubkey` is
/// taken from the ledger itself.
pub fn attest_balance(
    ledger: &Ledger<impl LedgerLog>,
    parent: &NodeId,
    child: &NodeId,
) -> Result<BalanceAttestation, LedgerError> {
    let balances = ledger.balances();
    let account = AccountRef::Child(child.clone());
    let (index, proof) = merkle::state_inclusion_proof(balances, &account)?;
    let tree_size = balances.accounts().count();

    Ok(BalanceAttestation {
        edge: EdgeAccount {
            parent: parent.clone(),
            child: child.clone(),
        },
        ledger_pubkey: *ledger.ledger_pubkey(),
        balance: balances.child_balance(child),
        height: ledger.len() as u64,
        state_root: merkle::state_root(balances),
        index,
        tree_size,
        proof,
    })
}

/// Verify a balance attestation against a signed commitment and an expected
/// ledger key.
///
/// Checks that the commitment verifies under `expected`, that the commitment's
/// `ledger_pubkey` and the attestation's `ledger_pubkey` both equal `expected`,
/// that the attestation height and `state_root` match the commitment, and that
/// the inclusion proof binds `Child(edge.child)` with `balance` to that root.
///
/// Associating `edge.parent` with the expected ledger key requires a
/// [`crate::registry::PeerRegistry`]; that cross-check is Phase C's job.
pub fn verify_balance_attestation(
    attestation: &BalanceAttestation,
    commitment: &SignedCommitment,
    expected: &LedgerPubKey,
) -> Result<(), LedgerError> {
    // The commitment and attestation must belong to the expected ledger.
    commitment.verify(expected)?;
    let committed = &commitment.commitment;
    if committed.ledger_pubkey != *expected {
        return Err(LedgerError::LedgerMismatch);
    }
    if attestation.ledger_pubkey != *expected {
        return Err(LedgerError::LedgerMismatch);
    }
    if attestation.height != committed.height {
        return Err(LedgerError::InvalidHeight {
            expected: committed.height,
            found: attestation.height,
        });
    }
    if attestation.state_root != committed.state_root {
        return Err(LedgerError::StateRootMismatch);
    }

    let account = AccountRef::Child(attestation.edge.child.clone());
    let balance = attestation.balance.get() as i128;
    if !merkle::verify_state_inclusion(
        &account,
        balance,
        attestation.index,
        attestation.tree_size,
        &attestation.proof,
        &committed.state_root,
    ) {
        return Err(LedgerError::InvalidProof);
    }
    Ok(())
}

/// Build the commitment for a ledger's current prefix.
///
/// `height == entry_count == ledger.len()`; `prev_commitment_hash` and
/// `issued_at` are caller-supplied.
pub fn build_commitment(
    ledger: &Ledger<impl LedgerLog>,
    prev_commitment_hash: Hash,
    issued_at: u64,
) -> Result<Commitment, LedgerError> {
    let entry_count = ledger.len() as u64;
    let mut entries = Vec::with_capacity(ledger.len());
    for index in 0..ledger.len() {
        match ledger.get(index)? {
            Some(entry) => entries.push(entry),
            None => return Err(LedgerError::MissingEntry { index }),
        }
    }

    Ok(Commitment {
        ledger_id: *ledger.ledger_id(),
        ledger_pubkey: *ledger.ledger_pubkey(),
        height: entry_count,
        entry_count,
        entry_root: merkle::entry_root(&entries)?,
        state_root: merkle::state_root(ledger.balances()),
        prev_commitment_hash,
        issued_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Entry, EntryBody, SignedEntry};
    use crate::hash::entry_hash;
    use crate::keys::LedgerSecretKey;

    fn ledger_key() -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([1u8; 32])
    }

    /// Build a root ledger whose first `n` entries each open an account.
    fn ledger_with(n: usize, key: &LedgerSecretKey) -> Ledger {
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
                    child: NodeId::from(format!("n{seq}")),
                    kind: cawala_topology::ChildKind::Node,
                },
                postings: vec![],
                auth: None,
            };
            let signed = SignedEntry::sign(entry, key).unwrap();
            prev = entry_hash(&signed.entry).unwrap();
            ledger.append(signed).unwrap();
        }
        ledger
    }

    /// Build a commitment with arbitrary roots for chain tests.
    fn commitment(
        key: &LedgerSecretKey,
        height: u64,
        entry_root_byte: u8,
        state_root_byte: u8,
        prev_commitment_hash: Hash,
        issued_at: u64,
    ) -> Commitment {
        Commitment {
            ledger_id: key.public(),
            ledger_pubkey: key.public(),
            height,
            entry_count: height,
            entry_root: Hash::from_bytes([entry_root_byte; 32]),
            state_root: Hash::from_bytes([state_root_byte; 32]),
            prev_commitment_hash,
            issued_at,
        }
    }

    #[test]
    fn build_commitment_matches_ledger() {
        let key = ledger_key();
        let ledger = ledger_with(3, &key);
        let built = build_commitment(&ledger, Hash::ZERO, 42).unwrap();

        assert_eq!(built.height, 3);
        assert_eq!(built.entry_count, 3);
        assert_eq!(built.height, ledger.len() as u64);
        assert_eq!(built.ledger_id, *ledger.ledger_id());
        assert_eq!(built.ledger_pubkey, *ledger.ledger_pubkey());

        let entries: Vec<SignedEntry> = (0..ledger.len())
            .map(|index| ledger.get(index).unwrap().unwrap())
            .collect();
        assert_eq!(built.entry_root, merkle::entry_root(&entries).unwrap());
        assert_eq!(built.state_root, merkle::state_root(ledger.balances()));
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = ledger_key();
        let ledger = ledger_with(2, &key);
        let built = build_commitment(&ledger, Hash::ZERO, 1).unwrap();
        let signed = SignedCommitment::sign(built, &key).unwrap();
        assert_eq!(signed.verify(&key.public()), Ok(()));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = ledger_key();
        let ledger = ledger_with(1, &key);
        let built = build_commitment(&ledger, Hash::ZERO, 1).unwrap();
        let signed = SignedCommitment::sign(built, &key).unwrap();

        let other = LedgerSecretKey::from_bytes([2u8; 32]);
        assert_eq!(
            signed.verify(&other.public()),
            Err(LedgerError::LedgerMismatch)
        );
    }

    #[test]
    fn tampered_field_is_rejected() {
        let key = ledger_key();
        let ledger = ledger_with(1, &key);
        let built = build_commitment(&ledger, Hash::ZERO, 1).unwrap();
        let mut signed = SignedCommitment::sign(built, &key).unwrap();
        signed.commitment.issued_at += 1;
        assert_eq!(
            signed.verify(&key.public()),
            Err(LedgerError::InvalidSignature)
        );
    }

    #[test]
    fn sign_rejects_inconsistent_identity() {
        let key = ledger_key();
        let other = LedgerSecretKey::from_bytes([2u8; 32]);

        // ledger_id != ledger_pubkey
        let mut mismatched_id = commitment(&key, 1, 1, 2, Hash::ZERO, 0);
        mismatched_id.ledger_id = other.public();
        assert_eq!(
            SignedCommitment::sign(mismatched_id, &key),
            Err(LedgerError::LedgerMismatch)
        );

        // signing key does not match ledger_pubkey
        let foreign = commitment(&key, 1, 1, 2, Hash::ZERO, 0);
        assert_eq!(
            SignedCommitment::sign(foreign, &other),
            Err(LedgerError::LedgerMismatch)
        );
    }

    #[test]
    fn verify_chain_accepts_linked_chain() {
        let key = ledger_key();
        let first =
            SignedCommitment::sign(commitment(&key, 1, 1, 2, Hash::ZERO, 10), &key).unwrap();
        let second = SignedCommitment::sign(
            commitment(&key, 2, 3, 4, commitment_hash(&first.commitment), 20),
            &key,
        )
        .unwrap();

        assert_eq!(verify_chain(&[first, second], &key.public()), Ok(()));
        assert_eq!(verify_chain(&[], &key.public()), Ok(()));
    }

    #[test]
    fn verify_chain_rejects_height_rollback() {
        let key = ledger_key();
        let first =
            SignedCommitment::sign(commitment(&key, 5, 1, 2, Hash::ZERO, 10), &key).unwrap();
        let rollback = SignedCommitment::sign(
            commitment(&key, 4, 3, 4, commitment_hash(&first.commitment), 20),
            &key,
        )
        .unwrap();

        assert!(matches!(
            verify_chain(&[first, rollback], &key.public()),
            Err(LedgerError::InvalidHeight { .. })
        ));
    }

    #[test]
    fn verify_chain_rejects_broken_prev_hash() {
        let key = ledger_key();
        let first =
            SignedCommitment::sign(commitment(&key, 1, 1, 2, Hash::ZERO, 10), &key).unwrap();
        let broken =
            SignedCommitment::sign(commitment(&key, 2, 3, 4, Hash::ZERO, 20), &key).unwrap();

        assert!(matches!(
            verify_chain(&[first, broken], &key.public()),
            Err(LedgerError::PrevHashMismatch { expected, found })
                if expected != Hash::ZERO && found == Hash::ZERO
        ));
    }

    #[test]
    fn verify_chain_rejects_non_genesis_anchor() {
        let key = ledger_key();
        let first = SignedCommitment::sign(
            commitment(&key, 1, 1, 2, Hash::from_bytes([9u8; 32]), 10),
            &key,
        )
        .unwrap();

        assert!(matches!(
            verify_chain(&[first], &key.public()),
            Err(LedgerError::PrevHashMismatch { expected, found: _ })
                if expected == Hash::ZERO
        ));
    }

    #[test]
    fn verify_chain_rejects_wrong_key() {
        let key = ledger_key();
        let first =
            SignedCommitment::sign(commitment(&key, 1, 1, 2, Hash::ZERO, 10), &key).unwrap();
        let other = LedgerSecretKey::from_bytes([2u8; 32]);
        assert_eq!(
            verify_chain(&[first], &other.public()),
            Err(LedgerError::LedgerMismatch)
        );
    }

    #[test]
    fn verify_chain_rejects_mixed_ledger() {
        let key = ledger_key();
        let other = LedgerSecretKey::from_bytes([2u8; 32]);
        let first =
            SignedCommitment::sign(commitment(&key, 1, 1, 2, Hash::ZERO, 10), &key).unwrap();
        let second = SignedCommitment::sign(
            commitment(&other, 2, 3, 4, commitment_hash(&first.commitment), 20),
            &other,
        )
        .unwrap();

        assert_eq!(
            verify_chain(&[first, second], &key.public()),
            Err(LedgerError::LedgerMismatch)
        );
    }

    #[test]
    fn balance_attestation_round_trips_through_serde() {
        let attestation = BalanceAttestation {
            edge: EdgeAccount {
                parent: NodeId::from("root"),
                child: NodeId::from("a"),
            },
            ledger_pubkey: ledger_key().public(),
            balance: Amount::new(7),
            height: 3,
            state_root: Hash::from_bytes([1u8; 32]),
            index: 2,
            tree_size: 5,
            proof: vec![Hash::from_bytes([2u8; 32])],
        };
        let bytes = postcard::to_allocvec(&attestation).unwrap();
        let back: BalanceAttestation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, attestation);
    }

    #[test]
    fn balance_attestation_verifies_and_rejects_tampering() {
        let key = ledger_key();
        let parent = NodeId::from("parent");
        let child = NodeId::from("n1");
        let ledger = ledger_with(3, &key);
        let commitment =
            SignedCommitment::sign(build_commitment(&ledger, Hash::ZERO, 1).unwrap(), &key)
                .unwrap();

        let attestation = attest_balance(&ledger, &parent, &child).unwrap();
        assert_eq!(attestation.edge.parent, parent);
        assert_eq!(attestation.edge.child, child);
        assert_eq!(attestation.ledger_pubkey, key.public());
        assert_eq!(
            verify_balance_attestation(&attestation, &commitment, &key.public()),
            Ok(())
        );

        // Tampered balance.
        let mut bad = attestation.clone();
        bad.balance = Amount::new(bad.balance.get() + 1);
        assert_eq!(
            verify_balance_attestation(&bad, &commitment, &key.public()),
            Err(LedgerError::InvalidProof)
        );

        // Tampered state root.
        let mut bad = attestation.clone();
        bad.state_root = Hash::from_bytes([9u8; 32]);
        assert_eq!(
            verify_balance_attestation(&bad, &commitment, &key.public()),
            Err(LedgerError::StateRootMismatch)
        );

        // Tampered attesting ledger key.
        let mut bad = attestation.clone();
        bad.ledger_pubkey = LedgerSecretKey::from_bytes([2u8; 32]).public();
        assert_eq!(
            verify_balance_attestation(&bad, &commitment, &key.public()),
            Err(LedgerError::LedgerMismatch)
        );

        // Height mismatch.
        let mut bad = attestation.clone();
        bad.height += 1;
        assert_eq!(
            verify_balance_attestation(&bad, &commitment, &key.public()),
            Err(LedgerError::InvalidHeight {
                expected: 3,
                found: 4
            })
        );

        // Wrong expected ledger key.
        let other = LedgerSecretKey::from_bytes([2u8; 32]);
        assert_eq!(
            verify_balance_attestation(&attestation, &commitment, &other.public()),
            Err(LedgerError::LedgerMismatch)
        );
    }

    #[test]
    fn forged_attestation_under_a_different_key_is_rejected() {
        // A fully self-consistent forgery: forged ledger, forged commitment and
        // forged attestation, all under the forger's key.
        let expected = ledger_key();
        let forger = LedgerSecretKey::from_bytes([7u8; 32]);
        let parent = NodeId::from("parent");

        let forged_ledger = ledger_with(1, &forger);
        let forged_commitment = SignedCommitment::sign(
            build_commitment(&forged_ledger, Hash::ZERO, 1).unwrap(),
            &forger,
        )
        .unwrap();
        let forged_attestation =
            attest_balance(&forged_ledger, &parent, &NodeId::from("n0")).unwrap();

        // Self-consistent under the forger's key...
        assert_eq!(
            verify_balance_attestation(&forged_attestation, &forged_commitment, &forger.public()),
            Ok(())
        );
        // ...but rejected against the expected ledger key.
        assert_eq!(
            verify_balance_attestation(&forged_attestation, &forged_commitment, &expected.public()),
            Err(LedgerError::LedgerMismatch)
        );
    }

    #[test]
    fn attest_balance_rejects_unopened_child() {
        let key = ledger_key();
        let ledger = ledger_with(1, &key);
        assert_eq!(
            attest_balance(&ledger, &NodeId::from("parent"), &NodeId::from("missing")),
            Err(LedgerError::IndexOutOfRange)
        );
    }

    #[test]
    fn verify_chain_rejects_inconsistent_height() {
        let key = ledger_key();
        let mut inconsistent = commitment(&key, 3, 1, 2, Hash::ZERO, 10);
        inconsistent.entry_count = 2; // height != entry_count
        let signed = SignedCommitment::sign(inconsistent, &key).unwrap();

        assert!(matches!(
            verify_chain(&[signed], &key.public()),
            Err(LedgerError::InvalidHeight {
                expected: 2,
                found: 3
            })
        ));
    }
}
