//! Hash type and domain-separated BLAKE3 derivations.
//!
//! Every hash derived here uses a distinct BLAKE3 derive-key context string,
//! so an entry hash can never collide with a Merkle leaf/node hash or a state
//! leaf at the type level.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::account::AccountRef;
use crate::entry::Entry;
use crate::error::LedgerError;

/// A 32-byte BLAKE3 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    /// The all-zero hash. Used as the `prev_hash` of a genesis entry and as
    /// the head hash of an empty log.
    pub const ZERO: Hash = Hash([0u8; 32]);

    /// The raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrap 32 raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Lowercase hex encoding.
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

/// BLAKE3 derive-key context for canonical entry hashing.
pub const ENTRY_CONTEXT: &str = "cawala-ledger/entry/v1";
/// BLAKE3 derive-key context for Merkle leaf hashing.
pub const LEAF_CONTEXT: &str = "cawala-ledger/leaf/v1";
/// BLAKE3 derive-key context for Merkle internal-node hashing.
pub const NODE_CONTEXT: &str = "cawala-ledger/node/v1";
/// BLAKE3 derive-key context for state (account balance) leaf hashing.
pub const STATE_CONTEXT: &str = "cawala-ledger/state/v1";
/// BLAKE3 derive-key context for the empty-tree root.
pub const EMPTY_CONTEXT: &str = "cawala-ledger/empty/v1";

fn derive(context: &str, parts: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in parts {
        hasher.update(part);
    }
    Hash(*hasher.finalize().as_bytes())
}

/// The canonical hash of an entry, over its canonical (versioned, postcard)
/// bytes.
///
/// This is the value chained into the next entry's `prev_hash` and committed
/// as a Merkle leaf. Fallible only if canonical encoding fails.
pub fn entry_hash(entry: &Entry) -> Result<Hash, LedgerError> {
    let bytes = entry.canonical_bytes()?;
    Ok(derive(ENTRY_CONTEXT, &[&bytes]))
}

/// Domain-separated Merkle leaf hash over an entry hash.
pub fn leaf_hash(leaf: &Hash) -> Hash {
    derive(LEAF_CONTEXT, &[leaf.as_bytes()])
}

/// Domain-separated Merkle internal-node hash over two child hashes.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    derive(NODE_CONTEXT, &[left.as_bytes(), right.as_bytes()])
}

/// Domain-separated state leaf hash for an account and its balance.
///
/// `AccountRef` is encoded with an explicit tag and a length-prefixed child
/// id; the balance is encoded as 16 little-endian bytes (i128), negative
/// equity included.
pub fn state_leaf_hash(account: &AccountRef, balance: i128) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key(STATE_CONTEXT);
    match account {
        AccountRef::Parent => {
            hasher.update(&[0x00]);
        }
        AccountRef::Child(id) => {
            hasher.update(&[0x01]);
            let id_bytes = id.as_str().as_bytes();
            hasher.update(&(id_bytes.len() as u32).to_le_bytes());
            hasher.update(id_bytes);
        }
        AccountRef::Equity => {
            hasher.update(&[0x02]);
        }
    }
    hasher.update(&balance.to_le_bytes());
    Hash(*hasher.finalize().as_bytes())
}

/// The root hash of an empty tree. Distinct from [`Hash::ZERO`].
pub fn empty_tree_root() -> Hash {
    derive(EMPTY_CONTEXT, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::NodeId;

    fn sample_entry() -> Entry {
        use crate::entry::EntryBody;
        use crate::keys::LedgerPubKey;

        Entry {
            ledger_id: LedgerPubKey::from_bytes(
                &crate::keys::LedgerSecretKey::from_bytes([9u8; 32])
                    .public()
                    .to_bytes(),
            )
            .unwrap(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 1,
            body: EntryBody::OpenAccount {
                child: NodeId::from("a"),
                kind: cawala_topology::ChildKind::Node,
            },
            postings: vec![],
            auth: None,
        }
    }

    #[test]
    fn zero_and_bytes() {
        assert_eq!(Hash::ZERO.as_bytes(), &[0u8; 32]);
        assert_eq!(Hash::from_bytes([7u8; 32]).as_bytes(), &[7u8; 32]);
        assert_eq!(Hash::from_bytes([0xabu8; 32]).to_string(), "ab".repeat(32));
    }

    #[test]
    fn domains_are_separated() {
        let h = Hash::from_bytes([5u8; 32]);
        let leaf = leaf_hash(&h);
        assert_ne!(leaf, h);
        assert_ne!(node_hash(&h, &h), leaf);
        assert_ne!(empty_tree_root(), Hash::ZERO);
        // Same input, different domains -> different outputs.
        assert_ne!(
            state_leaf_hash(&AccountRef::Equity, 0),
            entry_hash(&sample_entry()).unwrap()
        );
    }

    #[test]
    fn entry_hash_is_deterministic_and_sensitive() {
        let entry = sample_entry();
        let h = entry_hash(&entry).unwrap();
        assert_eq!(h, entry_hash(&entry.clone()).unwrap());

        let mut tampered = entry;
        tampered.seq = 1;
        assert_ne!(h, entry_hash(&tampered).unwrap());
    }

    #[test]
    fn state_leaves_distinguish_accounts() {
        let a = state_leaf_hash(&AccountRef::Parent, 0);
        let b = state_leaf_hash(&AccountRef::Child(NodeId::from("a")), 0);
        let c = state_leaf_hash(&AccountRef::Child(NodeId::from("b")), 0);
        let d = state_leaf_hash(&AccountRef::Equity, 0);
        assert_eq!(a, state_leaf_hash(&AccountRef::Parent, 0));
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(b, d);
        assert_ne!(
            state_leaf_hash(&AccountRef::Equity, 0),
            state_leaf_hash(&AccountRef::Equity, 1)
        );
    }

    #[test]
    fn node_hash_is_order_sensitive() {
        let l = leaf_hash(&Hash::from_bytes([1u8; 32]));
        let r = leaf_hash(&Hash::from_bytes([2u8; 32]));
        assert_eq!(node_hash(&l, &r), node_hash(&l, &r));
        assert_ne!(node_hash(&l, &r), node_hash(&r, &l));
    }

    #[test]
    fn empty_tree_root_is_stable() {
        assert_eq!(empty_tree_root(), empty_tree_root());
        assert_ne!(empty_tree_root(), leaf_hash(&Hash::ZERO));
    }

    #[test]
    fn serde_round_trip() {
        let h = Hash::from_bytes([3u8; 32]);
        let back: Hash = postcard::from_bytes(&postcard::to_allocvec(&h).unwrap()).unwrap();
        assert_eq!(h, back);
    }
}
