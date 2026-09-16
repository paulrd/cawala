//! Node record persistence: the node's *links* — one optional parent link and
//! up to 8 child links — plus its asserted octal [`OctAddr`], persisted as JSON
//! at `<data-dir>/node.json`.
//!
//! Links are never accompanied by a locally *derived* address: a lone node
//! cannot derive its own full address without its parent chain, and addresses
//! are recomputed from links where the full tree view exists (see the topology
//! crate). The one stored address is admin-asserted (CLI: `topo set-address`),
//! not derived, and tells routing where this node sits in the tree.
//!
//! Validation is applied on load and on every mutation: at most 8 children,
//! child slots unique and in `0..=MAX_SLOT`, parent slot in `0..=MAX_SLOT`,
//! a non-root address requires a parent and must match that parent's slot (only
//! the root address `"0"` may stand alone), and the kind is restricted to
//! `node`/`user` at (de)serialization time.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use cawala_topology::{ChildKind, MAX_SLOT, OctAddr};

/// Name of the node record file inside the data dir.
pub const NODE_RECORD_FILE: &str = "node.json";

/// Maximum number of children a node may have.
pub const MAX_CHILDREN: usize = MAX_SLOT as usize + 1;

/// The node's persisted record: identity, optional parent link, and child
/// links.
///
/// JSON shape:
/// ```json
/// {
///   "node_id": "<id>",
///   "address": "0.1.2",
///   "parent": { "parent_id": "<id>", "slot": 0 },
///   "children": [ { "child_id": "<id>", "kind": "node", "slot": 0, "date_joined": 1700000000 } ]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: String,
    /// This node's asserted octal address. Never derived locally; an admin sets
    /// it (CLI: `topo set-address`). `None` means routing is unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<OctAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ParentLink>,
    #[serde(default)]
    pub children: Vec<ChildEntry>,
    /// This node's own monotonic address epoch.
    ///
    /// Bumped whenever the stored asserted address value changes (join,
    /// re-base apply, exit-to-root, detach-notice). It is carried as the
    /// `generation` of every outgoing [`cawala_control::RebaseNotice`] so a
    /// child can order notices from this parent. Local bookkeeping only: it is
    /// never asserted or derived from peers, and `#[serde(default)]` lets an
    /// older `node.json` (written before this field existed) load unchanged.
    #[serde(default)]
    pub address_epoch: u64,
}

/// A link to this node's parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentLink {
    pub parent_id: String,
    pub slot: u8,
    /// High-water mark of [`cawala_control::RebaseNotice::generation`] applied
    /// from this parent. `0` on a fresh link (nothing applied yet); it only
    /// ever increases for a given link and resets when the link is replaced.
    #[serde(default)]
    pub generation: u64,
}

/// A link to one of this node's children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildEntry {
    pub child_id: String,
    /// Serialized as `"node"` or `"user"` (see [`kind_serde`]).
    #[serde(with = "kind_serde")]
    pub kind: ChildKind,
    pub slot: u8,
    /// Unix seconds when the child first joined this parent. Kept when a child
    /// is re-parented (moved) so seniority ("earliest `date_joined`") survives
    /// address reassignment; slot/address is geography, not seniority.
    pub date_joined: u64,
}

/// Errors raised by record validation, mutations, and (de)serialization.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("node '{0}' cannot reference itself")]
    SelfReference(String),
    #[error("slot {0} out of range (must be 0..=7)")]
    SlotOutOfRange(u8),
    #[error("slot {0} is already taken")]
    SlotTaken(u8),
    #[error("address '{0}' set without a parent (only the root address \"0\" may have no parent)")]
    AddressWithoutParent(String),
    #[error("address slot {address_slot:?} does not match parent slot {parent_slot}")]
    AddressSlotMismatch {
        address_slot: Option<u8>,
        parent_slot: u8,
    },
    #[error("node already has {MAX_CHILDREN} children (cap reached)")]
    CapExceeded,
    #[error("child '{0}' already present")]
    DuplicateChild(String),
    #[error("child '{0}' not found")]
    ChildNotFound(String),
    #[error("record node_id '{found}' does not match this node's endpoint id '{expected}'")]
    IdMismatch { found: String, expected: String },
    #[error("could not read {path}: {detail}")]
    ReadFailed { path: String, detail: String },
    #[error("could not write {path}: {detail}")]
    WriteFailed { path: String, detail: String },
    #[error("record file {path} is corrupt: {detail}")]
    Corrupt { path: String, detail: String },
}

impl NodeRecord {
    /// A fresh, unattached record for the given node id.
    pub fn new(node_id: impl Into<String>) -> Self {
        NodeRecord {
            node_id: node_id.into(),
            address: None,
            parent: None,
            children: Vec::new(),
            address_epoch: 0,
        }
    }

    /// This node's own monotonic address epoch (see the field docs).
    pub fn address_epoch(&self) -> u64 {
        self.address_epoch
    }

    /// High-water mark of `RebaseNotice.generation` applied from the current
    /// parent (`0` when unattached).
    pub fn parent_generation(&self) -> u64 {
        self.parent.as_ref().map_or(0, |parent| parent.generation)
    }

    /// Validate structural invariants. Must hold on load and after every
    /// mutation.
    pub fn validate(&self) -> Result<(), RecordError> {
        if let Some(parent) = &self.parent {
            if parent.parent_id == self.node_id {
                return Err(RecordError::SelfReference(self.node_id.clone()));
            }
            if parent.slot > MAX_SLOT {
                return Err(RecordError::SlotOutOfRange(parent.slot));
            }
        }
        if let Some(address) = &self.address {
            match &self.parent {
                Some(parent) => {
                    if address.depth() < 2 || address.slot() != Some(parent.slot) {
                        return Err(RecordError::AddressSlotMismatch {
                            address_slot: address.slot(),
                            parent_slot: parent.slot,
                        });
                    }
                }
                None => {
                    if !address.is_root() {
                        return Err(RecordError::AddressWithoutParent(address.to_string()));
                    }
                }
            }
        }
        if self.children.len() > MAX_CHILDREN {
            return Err(RecordError::CapExceeded);
        }
        let mut slots: Vec<u8> = Vec::with_capacity(self.children.len());
        for child in &self.children {
            if child.child_id == self.node_id {
                return Err(RecordError::SelfReference(child.child_id.clone()));
            }
            if child.slot > MAX_SLOT {
                return Err(RecordError::SlotOutOfRange(child.slot));
            }
            if slots.contains(&child.slot) {
                return Err(RecordError::SlotTaken(child.slot));
            }
            slots.push(child.slot);
        }
        Ok(())
    }
}

/// In-memory handle to the persisted node record, with mutation helpers that
/// validate before applying. Call [`RecordStore::save`] to persist.
#[derive(Debug, Clone)]
pub struct RecordStore {
    data_dir: PathBuf,
    record: NodeRecord,
}

impl RecordStore {
    /// Load the record from `<data_dir>/node.json`, or create a fresh
    /// unattached record for `node_id` if absent. Validates on load and
    /// rejects a record whose `node_id` does not match the node's endpoint id.
    pub fn open(data_dir: impl Into<PathBuf>, node_id: &str) -> Result<Self, RecordError> {
        let data_dir = data_dir.into();
        let path = data_dir.join(NODE_RECORD_FILE);
        let record = if path.exists() {
            let bytes = std::fs::read(&path).map_err(|err| RecordError::ReadFailed {
                path: path.display().to_string(),
                detail: err.to_string(),
            })?;
            serde_json::from_slice::<NodeRecord>(&bytes).map_err(|err| RecordError::Corrupt {
                path: path.display().to_string(),
                detail: err.to_string(),
            })?
        } else {
            NodeRecord::new(node_id.to_string())
        };
        record.validate()?;
        if record.node_id != node_id {
            return Err(RecordError::IdMismatch {
                found: record.node_id,
                expected: node_id.to_string(),
            });
        }
        Ok(RecordStore { data_dir, record })
    }

    /// The current record.
    pub fn record(&self) -> &NodeRecord {
        &self.record
    }

    /// This node's id.
    pub fn node_id(&self) -> &str {
        &self.record.node_id
    }

    /// This node's own monotonic address epoch (see [`NodeRecord::address_epoch`]).
    pub fn address_epoch(&self) -> u64 {
        self.record.address_epoch
    }

    /// The high-water mark of [`cawala_control::RebaseNotice::generation`]
    /// applied from the current parent (`0` when unattached).
    pub fn parent_generation(&self) -> u64 {
        self.record.parent_generation()
    }

    /// Advance the current parent link's applied-generation high-water mark.
    ///
    /// Monotonic: never lowers the stored mark. A no-op when there is no parent
    /// link (a rebase cannot be applied without one anyway).
    pub fn set_parent_generation(&mut self, generation: u64) {
        if let Some(parent) = self.record.parent.as_mut() {
            parent.generation = parent.generation.max(generation);
        }
    }

    /// Set the stored asserted address, bumping
    /// [`NodeRecord::address_epoch`] exactly when the value actually changes.
    ///
    /// This is the single site the epoch advances: every address mutation
    /// (`set_address`, `unset_address`, `unset_parent`, `rebase_to_root`) goes
    /// through it, so each stored-value change bumps the epoch exactly once.
    fn set_address_value(&mut self, address: Option<OctAddr>) {
        if self.record.address != address {
            self.record.address = address;
            self.record.address_epoch = self.record.address_epoch.saturating_add(1);
        }
    }

    /// Persist the record to `<data_dir>/node.json` (pretty JSON), after
    /// re-validating.
    ///
    /// The write is atomic (temp file + fsync + rename), so a concurrent reader
    /// observes either the previous complete document or the new one, never a
    /// torn `node.json`.
    pub fn save(&self) -> Result<(), RecordError> {
        self.record.validate()?;
        std::fs::create_dir_all(&self.data_dir).map_err(|err| RecordError::WriteFailed {
            path: self.data_dir.display().to_string(),
            detail: err.to_string(),
        })?;
        let path = self.data_dir.join(NODE_RECORD_FILE);
        let json =
            serde_json::to_string_pretty(&self.record).map_err(|err| RecordError::WriteFailed {
                path: path.display().to_string(),
                detail: err.to_string(),
            })?;
        write_json_atomic(&path, &json)
    }

    /// Add a child link. `slot: None` picks the lowest free slot.
    ///
    /// `date_joined` records when the child first joined this parent (unix
    /// seconds). It is taken explicitly — the store never reads the clock — so
    /// callers can preserve a moved child's original `date_joined` or reset it.
    pub fn attach_child(
        &mut self,
        child_id: impl Into<String>,
        kind: ChildKind,
        slot: Option<u8>,
        date_joined: u64,
    ) -> Result<(), RecordError> {
        let child_id = child_id.into();
        if child_id == self.record.node_id {
            return Err(RecordError::SelfReference(child_id));
        }
        if self.record.children.iter().any(|c| c.child_id == child_id) {
            return Err(RecordError::DuplicateChild(child_id));
        }
        let slot = match slot {
            Some(s) => {
                if s > MAX_SLOT {
                    return Err(RecordError::SlotOutOfRange(s));
                }
                if self.record.children.iter().any(|c| c.slot == s) {
                    return Err(RecordError::SlotTaken(s));
                }
                s
            }
            None => (0..=MAX_SLOT)
                .find(|s| !self.record.children.iter().any(|c| c.slot == *s))
                .ok_or(RecordError::CapExceeded)?,
        };
        if self.record.children.len() >= MAX_CHILDREN {
            return Err(RecordError::CapExceeded);
        }
        self.record.children.push(ChildEntry {
            child_id,
            kind,
            slot,
            date_joined,
        });
        self.record.validate()?;
        Ok(())
    }

    /// Remove a child link.
    pub fn detach_child(&mut self, child_id: &str) -> Result<(), RecordError> {
        let idx = self
            .record
            .children
            .iter()
            .position(|c| c.child_id == child_id)
            .ok_or_else(|| RecordError::ChildNotFound(child_id.to_string()))?;
        self.record.children.remove(idx);
        self.record.validate()?;
        Ok(())
    }

    /// Set this node's parent link.
    pub fn set_parent(
        &mut self,
        parent_id: impl Into<String>,
        slot: u8,
    ) -> Result<(), RecordError> {
        let parent_id = parent_id.into();
        if parent_id == self.record.node_id {
            return Err(RecordError::SelfReference(parent_id));
        }
        if slot > MAX_SLOT {
            return Err(RecordError::SlotOutOfRange(slot));
        }
        self.record.parent = Some(ParentLink {
            parent_id,
            slot,
            generation: 0,
        });
        self.record.validate()?;
        Ok(())
    }

    /// Clear this node's parent link.
    ///
    /// A retained non-root address would no longer be legal without a parent,
    /// so it is cleared too; a root `"0"` address survives.
    pub fn unset_parent(&mut self) -> Result<(), RecordError> {
        self.record.parent = None;
        if self.record.address.as_ref().is_some_and(|a| !a.is_root()) {
            self.set_address_value(None);
        }
        self.record.validate()?;
        Ok(())
    }

    /// Detach to an independent root network in a single validated mutation.
    ///
    /// Clears the parent link **and** sets the asserted address to the root `0`
    /// together, so the record is never observably in the illegal
    /// `parent = Some` + `address = 0` state. This is the exit/rebase primitive:
    /// the independent subtree is re-rooted at `0`, and its descendants are
    /// re-based by their own parents.
    ///
    /// A no-op re-application is legal and idempotent: clearing an absent parent
    /// and re-asserting `0` both validate.
    pub fn rebase_to_root(&mut self) -> Result<(), RecordError> {
        self.record.parent = None;
        self.set_address_value(Some(
            OctAddr::from_digits(vec![0]).expect("the root address \"0\" is always valid"),
        ));
        self.record.validate()?;
        Ok(())
    }

    /// Assert this node's octal address (admin-set, never derived).
    pub fn set_address(&mut self, address: OctAddr) -> Result<(), RecordError> {
        self.set_address_value(Some(address));
        self.record.validate()?;
        Ok(())
    }

    /// Clear this node's asserted address. Always legal.
    pub fn unset_address(&mut self) -> Result<(), RecordError> {
        self.set_address_value(None);
        self.record.validate()?;
        Ok(())
    }
}

/// Write `json` to `path` atomically: create a sibling temp file, fsync it,
/// then rename it over `path` (same directory, so the rename cannot cross a
/// filesystem boundary). A reader therefore sees either the old complete
/// document or the new one, never a partially written file.
fn write_json_atomic(path: &Path, json: &str) -> Result<(), RecordError> {
    let tmp = path.with_extension("tmp");
    let write_failed = |target: &Path, err: std::io::Error| RecordError::WriteFailed {
        path: target.display().to_string(),
        detail: err.to_string(),
    };
    {
        let mut file = File::create(&tmp).map_err(|err| write_failed(&tmp, err))?;
        file.write_all(json.as_bytes())
            .map_err(|err| write_failed(&tmp, err))?;
        file.sync_all().map_err(|err| write_failed(&tmp, err))?;
    }
    // Preserve any existing file permissions across the rename (best effort).
    if let Ok(metadata) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, metadata.permissions());
    }
    std::fs::rename(&tmp, path).map_err(|err| write_failed(path, err))?;
    Ok(())
}

/// Serialize [`ChildKind`] as `"node"`/`"user"` (the topology crate's default
/// serde output is `"Node"`/`"User"`).
mod kind_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::ChildKind;

    pub fn serialize<S>(kind: &ChildKind, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match kind {
            ChildKind::Node => serializer.serialize_str("node"),
            ChildKind::User => serializer.serialize_str("user"),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ChildKind, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "node" => Ok(ChildKind::Node),
            "user" => Ok(ChildKind::User),
            other => Err(serde::de::Error::custom(format!(
                "invalid child kind '{other}' (expected 'node' or 'user')"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn store(dir: &Path) -> RecordStore {
        RecordStore::open(dir, "node-a").unwrap()
    }

    const JOINED: u64 = 1700000000;

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store.set_parent("parent-x", 3).unwrap();
        store
            .attach_child("child-1", ChildKind::Node, Some(0), JOINED)
            .unwrap();
        store
            .attach_child("child-2", ChildKind::User, Some(5), JOINED)
            .unwrap();
        store.save().unwrap();

        let loaded = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(loaded.record(), store.record());
        assert_eq!(
            loaded.record().parent.as_ref().unwrap().parent_id,
            "parent-x"
        );
        assert_eq!(loaded.record().children.len(), 2);
    }

    #[test]
    fn save_replaces_existing_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store.set_parent("parent-x", 1).unwrap();
        store.save().unwrap();

        store.set_parent("parent-y", 2).unwrap();
        store
            .attach_child("c1", ChildKind::Node, Some(0), JOINED)
            .unwrap();
        store.save().unwrap();

        let loaded = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(loaded.record(), store.record());
        assert_eq!(
            loaded.record().parent.as_ref().unwrap().parent_id,
            "parent-y"
        );
        assert_eq!(loaded.record().children.len(), 1);
        // A successful atomic save leaves no temp file behind.
        assert!(!dir.path().join("node.tmp").exists());
    }

    #[test]
    fn failed_save_leaves_previous_file_intact() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store.set_parent("parent-x", 1).unwrap();
        store.save().unwrap();
        let before = std::fs::read(dir.path().join(NODE_RECORD_FILE)).unwrap();

        // Occupy the temp path with a directory so the write fails before any
        // rename; the destination must be left exactly as it was.
        std::fs::create_dir(dir.path().join("node.tmp")).unwrap();

        store.set_parent("parent-y", 2).unwrap();
        let err = store.save().unwrap_err();
        assert!(
            matches!(err, RecordError::WriteFailed { .. }),
            "unexpected error: {err}"
        );

        let after = std::fs::read(dir.path().join(NODE_RECORD_FILE)).unwrap();
        assert_eq!(before, after);
        let loaded = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(
            loaded.record().parent.as_ref().unwrap().parent_id,
            "parent-x"
        );
    }

    #[test]
    fn attach_auto_slot_picks_lowest_free() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store
            .attach_child("c1", ChildKind::Node, Some(2), JOINED)
            .unwrap();
        store
            .attach_child("c2", ChildKind::Node, None, JOINED)
            .unwrap();
        let c2 = store
            .record()
            .children
            .iter()
            .find(|c| c.child_id == "c2")
            .unwrap();
        assert_eq!(c2.slot, 0); // lowest free (0 is free, 2 is taken)
    }

    #[test]
    fn date_joined_recorded_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        // The store records the provided date_joined verbatim.
        store
            .attach_child("c1", ChildKind::Node, Some(0), 1700000000)
            .unwrap();
        let c1 = store
            .record()
            .children
            .iter()
            .find(|c| c.child_id == "c1")
            .unwrap();
        assert_eq!(c1.date_joined, 1700000000);
        // It survives a save + load round-trip, in node.json and in memory.
        store.save().unwrap();
        let json = std::fs::read_to_string(dir.path().join(NODE_RECORD_FILE)).unwrap();
        assert!(json.contains("\"date_joined\": 1700000000"));
        let loaded = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(loaded.record(), store.record());
        let loaded_c1 = loaded
            .record()
            .children
            .iter()
            .find(|c| c.child_id == "c1")
            .unwrap();
        assert_eq!(loaded_c1.date_joined, 1700000000);
    }

    #[test]
    fn ninth_child_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        for i in 0..8 {
            store
                .attach_child(format!("c{i}"), ChildKind::Node, None, JOINED)
                .unwrap();
        }
        // Auto slot: all 8 slots taken.
        assert_eq!(
            store.attach_child("c8", ChildKind::Node, None, JOINED),
            Err(RecordError::CapExceeded)
        );
        // Explicit slot on the (full) parent is reported as taken.
        assert_eq!(
            store.attach_child("c8", ChildKind::Node, Some(4), JOINED),
            Err(RecordError::SlotTaken(4))
        );
        assert_eq!(store.record().children.len(), 8);
    }

    #[test]
    fn duplicate_slot_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store
            .attach_child("c1", ChildKind::Node, Some(3), JOINED)
            .unwrap();
        assert_eq!(
            store.attach_child("c2", ChildKind::Node, Some(3), JOINED),
            Err(RecordError::SlotTaken(3))
        );
    }

    #[test]
    fn duplicate_child_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store
            .attach_child("c1", ChildKind::Node, None, JOINED)
            .unwrap();
        assert_eq!(
            store.attach_child("c1", ChildKind::User, Some(1), JOINED),
            Err(RecordError::DuplicateChild("c1".into()))
        );
    }

    #[test]
    fn slot_out_of_range_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        assert_eq!(
            store.attach_child("c1", ChildKind::Node, Some(8), JOINED),
            Err(RecordError::SlotOutOfRange(8))
        );
        assert_eq!(
            store.set_parent("parent-x", 9),
            Err(RecordError::SlotOutOfRange(9))
        );
        assert!(store.record().parent.is_none());
    }

    #[test]
    fn self_reference_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        assert_eq!(
            store.set_parent("node-a", 1),
            Err(RecordError::SelfReference("node-a".into()))
        );
        assert_eq!(
            store.attach_child("node-a", ChildKind::Node, None, JOINED),
            Err(RecordError::SelfReference("node-a".into()))
        );
    }

    #[test]
    fn detach_child() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store
            .attach_child("c1", ChildKind::Node, None, JOINED)
            .unwrap();
        store.detach_child("c1").unwrap();
        assert!(store.record().children.is_empty());
        assert_eq!(
            store.detach_child("c1"),
            Err(RecordError::ChildNotFound("c1".into()))
        );
    }

    #[test]
    fn parent_link_roundtrip_via_json() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store.set_parent("parent-x", 5).unwrap();
        store
            .attach_child("c1", ChildKind::User, Some(0), JOINED)
            .unwrap();
        store.save().unwrap();
        let json = std::fs::read_to_string(dir.path().join(NODE_RECORD_FILE)).unwrap();
        // kind is lowercase in JSON
        assert!(json.contains("\"kind\": \"user\""));
        assert!(json.contains("\"parent_id\": \"parent-x\""));
        // round-trips
        let loaded = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(loaded.record(), store.record());
    }

    #[test]
    fn bad_kind_rejected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let json = r#"{"node_id":"node-a","parent":null,"children":[{"child_id":"c1","kind":"bogus","slot":0,"date_joined":0}]}"#;
        std::fs::write(dir.path().join(NODE_RECORD_FILE), json).unwrap();
        let err = RecordStore::open(dir.path(), "node-a").unwrap_err();
        assert!(matches!(err, RecordError::Corrupt { .. }));
    }

    #[test]
    fn id_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store
            .attach_child("c1", ChildKind::Node, None, JOINED)
            .unwrap();
        store.save().unwrap();
        assert_eq!(
            RecordStore::open(dir.path(), "some-other-id").unwrap_err(),
            RecordError::IdMismatch {
                found: "node-a".into(),
                expected: "some-other-id".into()
            }
        );
    }

    #[test]
    fn validate_rejects_tampered_file() {
        let dir = tempfile::tempdir().unwrap();
        // duplicate slot
        let json = r#"{"node_id":"node-a","parent":null,"children":[{"child_id":"c1","kind":"node","slot":1,"date_joined":0},{"child_id":"c2","kind":"node","slot":1,"date_joined":0}]}"#;
        std::fs::write(dir.path().join(NODE_RECORD_FILE), json).unwrap();
        assert_eq!(
            RecordStore::open(dir.path(), "node-a").unwrap_err(),
            RecordError::SlotTaken(1)
        );
        // slot > 7
        let json = r#"{"node_id":"node-a","parent":{"parent_id":"p","slot":8},"children":[]}"#;
        std::fs::write(dir.path().join(NODE_RECORD_FILE), json).unwrap();
        assert_eq!(
            RecordStore::open(dir.path(), "node-a").unwrap_err(),
            RecordError::SlotOutOfRange(8)
        );
    }

    #[test]
    fn record_address_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store.set_parent("parent-x", 2).unwrap();
        store.set_address("0.1.2".parse().unwrap()).unwrap();
        store.save().unwrap();

        let json = std::fs::read_to_string(dir.path().join(NODE_RECORD_FILE)).unwrap();
        assert!(json.contains("\"address\": \"0.1.2\""));

        let loaded = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(loaded.record(), store.record());
        assert_eq!(
            loaded.record().address,
            Some("0.1.2".parse::<OctAddr>().unwrap())
        );
    }

    #[test]
    fn record_rejects_address_without_parent() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        assert_eq!(
            store.set_address("0.1.2".parse().unwrap()),
            Err(RecordError::AddressWithoutParent("0.1.2".into()))
        );
        // The root address is legal without a parent.
        store.set_address("0".parse().unwrap()).unwrap();
        assert_eq!(store.record().address, Some("0".parse().unwrap()));
    }

    #[test]
    fn record_rejects_address_slot_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store.set_parent("parent-x", 2).unwrap();
        assert_eq!(
            store.set_address("0.1.5".parse().unwrap()),
            Err(RecordError::AddressSlotMismatch {
                address_slot: Some(5),
                parent_slot: 2,
            })
        );
    }

    #[test]
    fn address_epoch_bumps_once_per_address_change() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        assert_eq!(store.address_epoch(), 0);

        store.set_parent("parent-x", 2).unwrap();
        // None -> Some: one bump.
        store.set_address("0.1.2".parse().unwrap()).unwrap();
        assert_eq!(store.address_epoch(), 1);
        // Re-asserting the same value is a no-op.
        store.set_address("0.1.2".parse().unwrap()).unwrap();
        assert_eq!(store.address_epoch(), 1);

        // A different value (exit-to-root): one bump.
        store.rebase_to_root().unwrap();
        assert_eq!(store.address_epoch(), 2);
        // Applying the same root again is a no-op.
        store.rebase_to_root().unwrap();
        assert_eq!(store.address_epoch(), 2);

        // Some -> None (detach/user unset): one bump.
        store.unset_address().unwrap();
        assert_eq!(store.address_epoch(), 3);
        // An unattached unset is a no-op.
        store.unset_address().unwrap();
        assert_eq!(store.address_epoch(), 3);

        // None -> root `0` (legal without a parent): one bump.
        store.set_address("0".parse().unwrap()).unwrap();
        assert_eq!(store.address_epoch(), 4);
        // unset_parent keeps a root address and does not bump.
        store.unset_parent().unwrap();
        assert_eq!(store.address_epoch(), 4);
    }

    #[test]
    fn parent_generation_is_monotonic_and_resets_with_the_link() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        assert_eq!(store.parent_generation(), 0, "unattached");

        store.set_parent("parent-x", 2).unwrap();
        assert_eq!(store.parent_generation(), 0, "a fresh link is unknown");

        store.set_parent_generation(3);
        assert_eq!(store.parent_generation(), 3);
        // Monotonic: a lower value never lowers the mark.
        store.set_parent_generation(1);
        assert_eq!(store.parent_generation(), 3);

        // Replacing the link resets the mark.
        store.set_parent("parent-y", 2).unwrap();
        assert_eq!(store.parent_generation(), 0);
    }

    #[test]
    fn old_node_json_without_new_fields_loads_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        // A pre-epoch `node.json` with neither `address_epoch` nor a parent
        // `generation`.
        let json = r#"{"node_id":"node-a","address":null,"parent":null,"children":[]}"#;
        std::fs::write(dir.path().join(NODE_RECORD_FILE), json).unwrap();
        let store = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(store.address_epoch(), 0);
        assert_eq!(store.parent_generation(), 0);

        // Same, but with a parent link (validated address).
        let json = r#"{"node_id":"node-a","address":"0.3","parent":{"parent_id":"parent-x","slot":3},"children":[]}"#;
        std::fs::write(dir.path().join(NODE_RECORD_FILE), json).unwrap();
        let mut store = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(store.record().address_epoch(), 0);
        assert_eq!(store.parent_generation(), 0);
        // The old document's links still work: unset bumps the epoch once.
        store.unset_address().unwrap();
        assert_eq!(store.address_epoch(), 1);
    }

    #[test]
    fn rebase_to_root_clears_parent_and_sets_root_in_one_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store.set_parent("parent-x", 2).unwrap();
        store.set_address("0.1.2".parse().unwrap()).unwrap();
        store
            .attach_child("c1", ChildKind::Node, Some(0), JOINED)
            .unwrap();

        store.rebase_to_root().unwrap();
        assert!(store.record().parent.is_none());
        assert_eq!(store.record().address, Some("0".parse().unwrap()));
        // Children are untouched (they are re-based by their own parent).
        assert_eq!(store.record().children.len(), 1);
        store.record().validate().unwrap();

        // Idempotent: re-applying on an already-root record is a legal no-op.
        store.rebase_to_root().unwrap();
        assert!(store.record().parent.is_none());
        assert_eq!(store.record().address, Some("0".parse().unwrap()));

        // The root-0 record round-trips through disk.
        store.save().unwrap();
        let loaded = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(loaded.record(), store.record());
    }

    #[test]
    fn unset_parent_clears_nonroot_address() {
        let dir = tempfile::tempdir().unwrap();
        let mut attached = store(dir.path());
        attached.set_parent("parent-x", 2).unwrap();
        attached.set_address("0.1.2".parse().unwrap()).unwrap();
        attached.unset_parent().unwrap();
        assert!(attached.record().parent.is_none());
        assert!(attached.record().address.is_none());
        attached.record().validate().unwrap();

        // A root address needs no parent and survives unset_parent.
        let dir2 = tempfile::tempdir().unwrap();
        let mut root = store(dir2.path());
        root.set_address("0".parse().unwrap()).unwrap();
        root.unset_parent().unwrap();
        assert_eq!(root.record().address, Some("0".parse().unwrap()));
        root.record().validate().unwrap();
    }
}
