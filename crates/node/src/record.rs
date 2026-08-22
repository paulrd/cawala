//! Node record persistence: the node's *links* — one optional parent link and
//! up to 8 child links — persisted as JSON at `<data-dir>/node.json`.
//!
//! Only links are persisted, never derived octal addresses: a lone node cannot
//! derive its own full address without its parent chain, and addresses are
//! recomputed from links where the full tree view exists (see the topology
//! crate).
//!
//! Validation is applied on load and on every mutation: at most 8 children,
//! child slots unique and in `0..=MAX_SLOT`, parent slot in `0..=MAX_SLOT`,
//! and the kind is restricted to `node`/`user` at (de)serialization time.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use cawala_topology::{ChildKind, MAX_SLOT};

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
///   "parent": { "parent_id": "<id>", "slot": 0 },
///   "children": [ { "child_id": "<id>", "kind": "node", "slot": 0, "date_joined": 1700000000 } ]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ParentLink>,
    #[serde(default)]
    pub children: Vec<ChildEntry>,
}

/// A link to this node's parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentLink {
    pub parent_id: String,
    pub slot: u8,
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
            parent: None,
            children: Vec::new(),
        }
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

    /// Persist the record to `<data_dir>/node.json` (pretty JSON), after
    /// re-validating.
    pub fn save(&self) -> Result<(), RecordError> {
        self.record.validate()?;
        std::fs::create_dir_all(&self.data_dir).map_err(|err| RecordError::WriteFailed {
            path: self.data_dir.display().to_string(),
            detail: err.to_string(),
        })?;
        let path = self.data_dir.join(NODE_RECORD_FILE);
        let json = serde_json::to_string_pretty(&self.record)
            .map_err(|err| RecordError::WriteFailed {
                path: path.display().to_string(),
                detail: err.to_string(),
            })?;
        std::fs::write(&path, json).map_err(|err| RecordError::WriteFailed {
            path: path.display().to_string(),
            detail: err.to_string(),
        })
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
            None => {
                let free = (0..=MAX_SLOT)
                    .find(|s| !self.record.children.iter().any(|c| c.slot == *s))
                    .ok_or(RecordError::CapExceeded)?;
                free
            }
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
    pub fn set_parent(&mut self, parent_id: impl Into<String>, slot: u8) -> Result<(), RecordError> {
        let parent_id = parent_id.into();
        if parent_id == self.record.node_id {
            return Err(RecordError::SelfReference(parent_id));
        }
        if slot > MAX_SLOT {
            return Err(RecordError::SlotOutOfRange(slot));
        }
        self.record.parent = Some(ParentLink { parent_id, slot });
        self.record.validate()?;
        Ok(())
    }

    /// Clear this node's parent link.
    pub fn unset_parent(&mut self) -> Result<(), RecordError> {
        self.record.parent = None;
        self.record.validate()?;
        Ok(())
    }
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
        store.attach_child("child-1", ChildKind::Node, Some(0), JOINED).unwrap();
        store.attach_child("child-2", ChildKind::User, Some(5), JOINED).unwrap();
        store.save().unwrap();

        let loaded = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(loaded.record(), store.record());
        assert_eq!(loaded.record().parent.as_ref().unwrap().parent_id, "parent-x");
        assert_eq!(loaded.record().children.len(), 2);
    }

    #[test]
    fn attach_auto_slot_picks_lowest_free() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store.attach_child("c1", ChildKind::Node, Some(2), JOINED).unwrap();
        store.attach_child("c2", ChildKind::Node, None, JOINED).unwrap();
        let c2 = store.record().children.iter().find(|c| c.child_id == "c2").unwrap();
        assert_eq!(c2.slot, 0); // lowest free (0 is free, 2 is taken)
    }

    #[test]
    fn date_joined_recorded_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        // The store records the provided date_joined verbatim.
        store.attach_child("c1", ChildKind::Node, Some(0), 1700000000).unwrap();
        let c1 = store.record().children.iter().find(|c| c.child_id == "c1").unwrap();
        assert_eq!(c1.date_joined, 1700000000);
        // It survives a save + load round-trip, in node.json and in memory.
        store.save().unwrap();
        let json = std::fs::read_to_string(dir.path().join(NODE_RECORD_FILE)).unwrap();
        assert!(json.contains("\"date_joined\": 1700000000"));
        let loaded = RecordStore::open(dir.path(), "node-a").unwrap();
        assert_eq!(loaded.record(), store.record());
        let loaded_c1 = loaded.record().children.iter().find(|c| c.child_id == "c1").unwrap();
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
        store.attach_child("c1", ChildKind::Node, Some(3), JOINED).unwrap();
        assert_eq!(
            store.attach_child("c2", ChildKind::Node, Some(3), JOINED),
            Err(RecordError::SlotTaken(3))
        );
    }

    #[test]
    fn duplicate_child_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store(dir.path());
        store.attach_child("c1", ChildKind::Node, None, JOINED).unwrap();
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
        store.attach_child("c1", ChildKind::Node, None, JOINED).unwrap();
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
        store.attach_child("c1", ChildKind::User, Some(0), JOINED).unwrap();
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
        store.attach_child("c1", ChildKind::Node, None, JOINED).unwrap();
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
}
