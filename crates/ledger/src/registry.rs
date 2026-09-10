//! Peer registry: public identity and key material for known nodes.
//!
//! The registry holds **public data only**. Secrets live with the node (later,
//! in `crates/node`). It answers "which operator authorises this node's
//! orders?" and "which ledger key signs this node's entries?" and verifies
//! signed entries/commitments against the registered keys.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::account::NodeId;
use crate::commit::SignedCommitment;
use crate::entry::SignedEntry;
use crate::error::LedgerError;
use crate::keys::{LedgerPubKey, OperatorPubKey};

/// Whether a peer is an internal node or a leaf user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PeerRole {
    /// An internal network node.
    Node,
    /// A leaf user.
    User,
}

/// A peer's public identity and keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerKeys {
    /// The node identifier.
    pub node_id: NodeId,
    /// The operator key that authorises this node's control actions.
    pub operator: OperatorPubKey,
    /// The ledger key that signs this node's entries and commitments.
    ///
    /// `None` for users, who hold no ledger.
    pub ledger: Option<LedgerPubKey>,
    /// Whether the peer is a node or a user.
    pub role: PeerRole,
}

/// A registry of known peers, keyed by [`NodeId`] (BTreeMap order).
///
/// Deserialization re-runs [`PeerRegistry::insert`] for every peer, so a
/// decoded registry can never contain duplicate operator or ledger keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerRegistry {
    peers: BTreeMap<NodeId, PeerKeys>,
}

// Serialized as a sequence of `PeerKeys` (not a map) so that the custom
// `Deserialize` below can validate each entry through `insert`.
impl Serialize for PeerRegistry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.peers.len()))?;
        for peer in self.peers.values() {
            seq.serialize_element(peer)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for PeerRegistry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let peers = Vec::<PeerKeys>::deserialize(deserializer)?;
        let mut registry = PeerRegistry::new();
        for peer in peers {
            registry.insert(peer).map_err(serde::de::Error::custom)?;
        }
        Ok(registry)
    }
}

impl PeerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        PeerRegistry {
            peers: BTreeMap::new(),
        }
    }

    /// Register a peer.
    ///
    /// Returns [`LedgerError::InvalidPeerKeys`] if the role/ledger invariant is
    /// violated (a `User` must have no ledger key; a `Node` must have one),
    /// [`LedgerError::DuplicatePeer`] if the node id is already present, and
    /// [`LedgerError::DuplicateKey`] if another peer already uses this
    /// operator, or this (non-`None`) ledger key. Keys are unique so
    /// `verify_entry` / `verify_commitment` can never mis-attribute a
    /// signature.
    pub fn insert(&mut self, keys: PeerKeys) -> Result<(), LedgerError> {
        let role_ledger_ok = match (keys.role, keys.ledger.is_some()) {
            (PeerRole::Node, true) | (PeerRole::User, false) => true,
            (PeerRole::Node, false) | (PeerRole::User, true) => false,
        };
        if !role_ledger_ok {
            return Err(LedgerError::InvalidPeerKeys);
        }
        if self
            .peers
            .values()
            .any(|peer| peer.operator == keys.operator)
        {
            return Err(LedgerError::DuplicateKey);
        }
        let ledger_conflict = keys.ledger.is_some()
            && self
                .peers
                .values()
                .any(|peer| peer.ledger.is_some() && peer.ledger == keys.ledger);
        if ledger_conflict {
            return Err(LedgerError::DuplicateKey);
        }
        match self.peers.entry(keys.node_id.clone()) {
            std::collections::btree_map::Entry::Occupied(_) => Err(LedgerError::DuplicatePeer),
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(keys);
                Ok(())
            }
        }
    }

    /// Look up a peer by node id.
    pub fn get(&self, node_id: &NodeId) -> Option<&PeerKeys> {
        self.peers.get(node_id)
    }

    /// The registered operator key for a node, if known.
    pub fn operator_of(&self, node_id: &NodeId) -> Option<&OperatorPubKey> {
        self.peers.get(node_id).map(|peer| &peer.operator)
    }

    /// The registered ledger key for a node, if any.
    ///
    /// `None` when the node is unknown or is a user (users hold no ledger).
    pub fn ledger_of(&self, node_id: &NodeId) -> Option<&LedgerPubKey> {
        self.peers
            .get(node_id)
            .and_then(|peer| peer.ledger.as_ref())
    }

    /// Look up the peer registered under a ledger key, if any.
    pub fn peer_by_ledger(&self, ledger: &LedgerPubKey) -> Option<&PeerKeys> {
        self.peers
            .values()
            .find(|peer| peer.ledger.as_ref() == Some(ledger))
    }

    /// Number of registered peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Verify a signed entry under the ledger key registered for its
    /// `ledger_id`.
    ///
    /// Returns [`LedgerError::Unauthorized`] when no peer is registered with
    /// that ledger key, and propagates signature/identity failures from
    /// [`SignedEntry::verify`].
    pub fn verify_entry(&self, entry: &SignedEntry) -> Result<&PeerKeys, LedgerError> {
        let peer = self
            .peer_by_ledger(&entry.entry.ledger_id)
            .ok_or(LedgerError::Unauthorized)?;
        let ledger = peer.ledger.as_ref().ok_or(LedgerError::Unauthorized)?;
        entry.verify(ledger)?;
        Ok(peer)
    }

    /// Verify a signed commitment under the ledger key registered for its
    /// `ledger_pubkey`.
    ///
    /// Returns [`LedgerError::Unauthorized`] when no peer is registered with
    /// that ledger key.
    pub fn verify_commitment(
        &self,
        commitment: &SignedCommitment,
    ) -> Result<&PeerKeys, LedgerError> {
        let peer = self
            .peer_by_ledger(&commitment.commitment.ledger_pubkey)
            .ok_or(LedgerError::Unauthorized)?;
        let ledger = peer.ledger.as_ref().ok_or(LedgerError::Unauthorized)?;
        commitment.verify(ledger)?;
        Ok(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::{Commitment, SignedCommitment};
    use crate::entry::{Entry, EntryBody};
    use crate::hash::Hash;
    use crate::keys::LedgerSecretKey;

    fn child(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorPubKey {
        crate::keys::OperatorSecretKey::from_bytes([seed; 32]).public()
    }

    fn ledger_key(seed: u8) -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([seed; 32])
    }

    fn peer(id: &str, operator_seed: u8, ledger_seed: u8) -> PeerKeys {
        PeerKeys {
            node_id: child(id),
            operator: operator(operator_seed),
            ledger: Some(ledger_key(ledger_seed).public()),
            role: PeerRole::Node,
        }
    }

    fn user(id: &str, operator_seed: u8) -> PeerKeys {
        PeerKeys {
            node_id: child(id),
            operator: operator(operator_seed),
            ledger: None,
            role: PeerRole::User,
        }
    }

    fn open_entry(key: &LedgerSecretKey, id: &str) -> SignedEntry {
        let entry = Entry {
            ledger_id: key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::OpenAccount {
                child: child(id),
                kind: cawala_topology::ChildKind::Node,
            },
            postings: vec![],
            auth: None,
        };
        SignedEntry::sign(entry, key).unwrap()
    }

    fn signed_commitment(key: &LedgerSecretKey) -> SignedCommitment {
        let commitment = Commitment {
            ledger_id: key.public(),
            ledger_pubkey: key.public(),
            height: 1,
            entry_count: 1,
            entry_root: Hash::from_bytes([1u8; 32]),
            state_root: Hash::from_bytes([2u8; 32]),
            prev_commitment_hash: Hash::ZERO,
            issued_at: 0,
        };
        SignedCommitment::sign(commitment, key).unwrap()
    }

    #[test]
    fn insert_get_and_duplicate() {
        let mut registry = PeerRegistry::new();
        assert!(registry.is_empty());

        registry.insert(peer("alice", 1, 11)).unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get(&child("alice")), Some(&peer("alice", 1, 11)));
        assert_eq!(registry.operator_of(&child("alice")), Some(&operator(1)));
        assert_eq!(
            registry.ledger_of(&child("alice")),
            Some(&ledger_key(11).public())
        );

        assert_eq!(registry.get(&child("bob")), None);
        assert_eq!(registry.operator_of(&child("bob")), None);
        assert_eq!(registry.ledger_of(&child("bob")), None);

        assert_eq!(
            registry.insert(peer("alice", 2, 22)),
            Err(LedgerError::DuplicatePeer)
        );
    }

    #[test]
    fn insert_rejects_duplicate_operator_and_ledger() {
        let mut registry = PeerRegistry::new();
        registry.insert(peer("alice", 1, 11)).unwrap();

        // Same operator key under a different node id.
        assert_eq!(
            registry.insert(peer("bob", 1, 22)),
            Err(LedgerError::DuplicateKey)
        );
        // Same ledger key under a different node id.
        assert_eq!(
            registry.insert(peer("bob", 2, 11)),
            Err(LedgerError::DuplicateKey)
        );

        // Neither rejected insertion took effect.
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get(&child("bob")), None);
    }

    #[test]
    fn user_peers_have_no_ledger() {
        let mut registry = PeerRegistry::new();
        registry.insert(peer("alice", 1, 11)).unwrap();
        registry.insert(user("u1", 2)).unwrap();
        // Multiple users (no ledger) may be registered.
        registry.insert(user("u2", 3)).unwrap();

        assert_eq!(registry.ledger_of(&child("u1")), None);
        assert_eq!(
            registry.get(&child("u1")).map(|peer| peer.role),
            Some(PeerRole::User)
        );
        assert_eq!(
            registry
                .peer_by_ledger(&ledger_key(11).public())
                .map(|peer| peer.node_id.clone()),
            Some(child("alice"))
        );
        assert!(registry.peer_by_ledger(&ledger_key(77).public()).is_none());
    }

    #[test]
    fn insert_rejects_operator_collision_with_a_user() {
        let mut registry = PeerRegistry::new();
        registry.insert(user("u1", 5)).unwrap();
        assert_eq!(
            registry.insert(peer("alice", 5, 11)),
            Err(LedgerError::DuplicateKey)
        );
    }

    #[test]
    fn insert_rejects_role_ledger_mismatch() {
        let mut registry = PeerRegistry::new();
        // A user must not carry a ledger key.
        let bad_user = PeerKeys {
            node_id: child("u1"),
            operator: operator(1),
            ledger: Some(ledger_key(11).public()),
            role: PeerRole::User,
        };
        assert_eq!(registry.insert(bad_user), Err(LedgerError::InvalidPeerKeys));
        // A node must carry a ledger key.
        let bad_node = PeerKeys {
            node_id: child("n1"),
            operator: operator(2),
            ledger: None,
            role: PeerRole::Node,
        };
        assert_eq!(registry.insert(bad_node), Err(LedgerError::InvalidPeerKeys));
        assert!(registry.is_empty());
    }

    #[test]
    fn deserialize_revalidates_keys() {
        // Duplicate operator.
        let peers = vec![peer("alice", 1, 11), peer("bob", 1, 22)];
        let bytes = postcard::to_allocvec(&peers).unwrap();
        assert!(postcard::from_bytes::<PeerRegistry>(&bytes).is_err());

        // Duplicate ledger.
        let peers = vec![peer("alice", 1, 11), peer("bob", 2, 11)];
        let bytes = postcard::to_allocvec(&peers).unwrap();
        assert!(postcard::from_bytes::<PeerRegistry>(&bytes).is_err());

        // Role/ledger mismatch.
        let peers = vec![PeerKeys {
            node_id: child("u1"),
            operator: operator(3),
            ledger: Some(ledger_key(33).public()),
            role: PeerRole::User,
        }];
        let bytes = postcard::to_allocvec(&peers).unwrap();
        assert!(postcard::from_bytes::<PeerRegistry>(&bytes).is_err());
    }

    #[test]
    fn verify_entry_accepts_registered_ledger() {
        let mut registry = PeerRegistry::new();
        registry.insert(peer("alice", 1, 11)).unwrap();

        let entry = open_entry(&ledger_key(11), "x");
        let verified = registry.verify_entry(&entry).unwrap();
        assert_eq!(verified.node_id, child("alice"));
    }

    #[test]
    fn verify_entry_rejects_unregistered_ledger() {
        let registry = PeerRegistry::new();
        let entry = open_entry(&ledger_key(11), "x");
        assert_eq!(
            registry.verify_entry(&entry),
            Err(LedgerError::Unauthorized)
        );
    }

    #[test]
    fn verify_entry_rejects_mismatched_ledger_key() {
        let mut registry = PeerRegistry::new();
        registry.insert(peer("alice", 1, 11)).unwrap();

        // Claims the registered ledger id but is signed by a different key.
        let signer = ledger_key(99);
        let entry = Entry {
            ledger_id: ledger_key(11).public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::OpenAccount {
                child: child("x"),
                kind: cawala_topology::ChildKind::Node,
            },
            postings: vec![],
            auth: None,
        };
        let signed = SignedEntry::sign(entry, &signer).unwrap();
        assert_eq!(
            registry.verify_entry(&signed),
            Err(LedgerError::InvalidSignature)
        );
    }

    #[test]
    fn verify_commitment_accepts_registered_ledger() {
        let mut registry = PeerRegistry::new();
        registry.insert(peer("alice", 1, 11)).unwrap();

        let commitment = signed_commitment(&ledger_key(11));
        let verified = registry.verify_commitment(&commitment).unwrap();
        assert_eq!(verified.node_id, child("alice"));
    }

    #[test]
    fn verify_commitment_rejects_unregistered_and_mismatched() {
        // Unregistered.
        let registry = PeerRegistry::new();
        let commitment = signed_commitment(&ledger_key(11));
        assert_eq!(
            registry.verify_commitment(&commitment),
            Err(LedgerError::Unauthorized)
        );

        // Registered ledger id, but the signature is from a different key.
        let mut registry = PeerRegistry::new();
        registry.insert(peer("alice", 1, 11)).unwrap();
        let mut tampered = signed_commitment(&ledger_key(11));
        tampered.signature = ledger_key(99).sign(b"wrong commitment");
        assert_eq!(
            registry.verify_commitment(&tampered),
            Err(LedgerError::InvalidSignature)
        );
    }

    #[test]
    fn registry_round_trips_through_serde() {
        let mut registry = PeerRegistry::new();
        registry.insert(peer("alice", 1, 11)).unwrap();
        registry.insert(user("u1", 2)).unwrap();
        let bytes = postcard::to_allocvec(&registry).unwrap();
        let back: PeerRegistry = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, registry);
    }
}
