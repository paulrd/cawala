//! Persistence for in-flight join handshakes.
//!
//! Two independent JSON documents live in the data dir:
//!
//! - `<data_dir>/pending_joins.json`: a `Vec<JoinRequest>` of applicants this
//!   node has queued for admin approval (it is their prospective parent);
//! - `<data_dir>/outbound_join.json`: the single `JoinRequest` this node has
//!   sent to a prospective parent, plus that parent's node id (or `null` when
//!   there is no pending outbound join).
//!
//! Both are written with the same temp-file + rename convention as
//! [`crate::ledger_peers`], and both are validated on load: a present but
//! malformed or structurally invalid document is an error, never silently
//! ignored.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use cawala_control::{JoinRequest, NodeId, OperatorPubKey};

/// Name of the pending-joins file inside the data dir.
pub const PENDING_JOINS_FILE: &str = "pending_joins.json";

/// Name of the outbound-join file inside the data dir.
pub const OUTBOUND_JOIN_FILE: &str = "outbound_join.json";

/// An outbound join: the request this node sent, and the prospective parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundJoin {
    /// The self-signed request that was sent.
    pub request: JoinRequest,
    /// The node the request was sent to.
    pub parent: NodeId,
    /// The parent's operator key pinned out-of-band by an invite, if this join
    /// was started from one. A `JoinApproved` is only accepted when its
    /// controller matches this key. `None` for a legacy/direct `--parent`
    /// join, preserving the old trust-on-first-use behavior.
    #[serde(default)]
    pub pinned_operator: Option<OperatorPubKey>,
}

/// In-memory handle to the persisted pending/outbound join state.
///
/// Every mutating method updates memory only; call [`ControlStore::save`] to
/// persist. Validation happens on load.
#[derive(Debug, Clone, Default)]
pub struct ControlStore {
    data_dir: PathBuf,
    pending: Vec<JoinRequest>,
    outbound: Option<OutboundJoin>,
}

impl ControlStore {
    /// Load both documents from `data_dir`.
    ///
    /// Missing files yield empty state; a present but malformed/invalid file is
    /// an error.
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let data_dir = data_dir.into();
        let pending = load_pending(&data_dir)?;
        let outbound = load_outbound(&data_dir)?;
        Ok(ControlStore {
            data_dir,
            pending,
            outbound,
        })
    }

    /// The queued join requests (application order).
    pub fn pending(&self) -> &[JoinRequest] {
        &self.pending
    }

    /// The queued request for `node`, if any.
    pub fn pending_for(&self, node: &NodeId) -> Option<&JoinRequest> {
        self.pending.iter().find(|req| &req.node == node)
    }

    /// Queue `request`. A request for a node that is already queued is
    /// ignored (idempotent); the caller decides whether that is reported as
    /// [`crate::control::ControlReply::Pending`].
    pub fn add_pending(&mut self, request: JoinRequest) {
        if self.pending_for(&request.node).is_none() {
            self.pending.push(request);
        }
    }

    /// Remove and return the queued request for `node`.
    pub fn remove_pending(&mut self, node: &NodeId) -> Option<JoinRequest> {
        let idx = self.pending.iter().position(|req| &req.node == node)?;
        Some(self.pending.remove(idx))
    }

    /// The pending outbound join, if any.
    pub fn outbound(&self) -> Option<&OutboundJoin> {
        self.outbound.as_ref()
    }

    /// Record (replacing any existing) outbound join for `parent`.
    ///
    /// `pinned_operator` is the parent's operator key when the join came from
    /// an invite (`Some`), or `None` for a direct `--parent` join.
    pub fn set_outbound(
        &mut self,
        request: JoinRequest,
        parent: NodeId,
        pinned_operator: Option<OperatorPubKey>,
    ) {
        self.outbound = Some(OutboundJoin {
            request,
            parent,
            pinned_operator,
        });
    }

    /// Clear the outbound join (approved or rejected).
    pub fn clear_outbound(&mut self) {
        self.outbound = None;
    }

    /// Persist both documents atomically.
    pub fn save(&self) -> Result<()> {
        write_json_atomic(&self.data_dir.join(PENDING_JOINS_FILE), &self.pending)?;
        write_json_atomic(&self.data_dir.join(OUTBOUND_JOIN_FILE), &self.outbound)?;
        Ok(())
    }
}

/// Load and validate `pending_joins.json`.
fn load_pending(data_dir: &Path) -> Result<Vec<JoinRequest>> {
    let path = data_dir.join(PENDING_JOINS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes =
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let pending: Vec<JoinRequest> = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid pending-joins document", path.display()))?;
    for request in &pending {
        request.validate().map_err(|err| {
            anyhow::anyhow!("{} is corrupt: invalid join request: {err}", path.display())
        })?;
    }
    for (i, request) in pending.iter().enumerate() {
        if pending[i + 1..]
            .iter()
            .any(|other| other.node == request.node)
        {
            anyhow::bail!(
                "{} is corrupt: duplicate pending node '{}'",
                path.display(),
                request.node
            );
        }
    }
    Ok(pending)
}

/// Load and validate `outbound_join.json`.
fn load_outbound(data_dir: &Path) -> Result<Option<OutboundJoin>> {
    let path = data_dir.join(OUTBOUND_JOIN_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let outbound: Option<OutboundJoin> = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid outbound-join document", path.display()))?;
    if let Some(out) = &outbound {
        out.request.validate().map_err(|err| {
            anyhow::anyhow!(
                "{} is corrupt: invalid outbound join request: {err}",
                path.display()
            )
        })?;
    }
    Ok(outbound)
}

/// Write `value` as pretty JSON to `path` via a temp file + rename.
fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create data dir {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(value)
        .with_context(|| format!("failed to encode {}", path.display()))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json).with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_control::{ChildKind, OperatorSecretKey};
    use cawala_ledger::LedgerSecretKey;

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn join(node_id: &str, slot: Option<u8>) -> JoinRequest {
        JoinRequest {
            node: node(node_id),
            kind: ChildKind::Node,
            operator: OperatorSecretKey::from_bytes([1u8; 32]).public(),
            ledger: Some(LedgerSecretKey::from_bytes([2u8; 32]).public()),
            desired_slot: slot,
            location_hint: None,
            nonce: 7,
            expiry: 1000,
        }
    }

    #[test]
    fn absent_files_are_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = ControlStore::open(dir.path()).unwrap();
        assert!(store.pending().is_empty());
        assert!(store.outbound().is_none());
    }

    #[test]
    fn round_trip_pending_and_outbound() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ControlStore::open(dir.path()).unwrap();
        store.add_pending(join("applicant-a", Some(3)));
        store.add_pending(join("applicant-b", None));
        store.set_outbound(join("me", Some(1)), node("parent"), None);
        store.save().unwrap();

        let loaded = ControlStore::open(dir.path()).unwrap();
        assert_eq!(loaded.pending().len(), 2);
        assert_eq!(
            loaded
                .pending_for(&node("applicant-a"))
                .unwrap()
                .desired_slot,
            Some(3)
        );
        let out = loaded.outbound().expect("outbound present");
        assert_eq!(out.parent, node("parent"));
        assert_eq!(out.request.node, node("me"));
    }

    #[test]
    fn pinned_operator_round_trips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ControlStore::open(dir.path()).unwrap();
        let pinned = OperatorSecretKey::from_bytes([9u8; 32]).public();
        store.set_outbound(join("me", Some(1)), node("parent"), Some(pinned));
        store.save().unwrap();

        let loaded = ControlStore::open(dir.path()).unwrap();
        assert_eq!(loaded.outbound().unwrap().pinned_operator, Some(pinned));

        // A document without the field (legacy/direct join) loads as `None`.
        let legacy = serde_json::json!({
            "request": join("me", Some(1)),
            "parent": "parent",
        });
        std::fs::write(
            dir.path().join(OUTBOUND_JOIN_FILE),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let loaded = ControlStore::open(dir.path()).unwrap();
        assert_eq!(loaded.outbound().unwrap().pinned_operator, None);
    }

    #[test]
    fn add_pending_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ControlStore::open(dir.path()).unwrap();
        store.add_pending(join("applicant-a", Some(3)));
        store.add_pending(join("applicant-a", Some(5)));
        assert_eq!(store.pending().len(), 1);
        assert_eq!(
            store
                .pending_for(&node("applicant-a"))
                .unwrap()
                .desired_slot,
            Some(3)
        );
    }

    #[test]
    fn remove_pending_returns_request() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ControlStore::open(dir.path()).unwrap();
        store.add_pending(join("applicant-a", Some(3)));
        let removed = store.remove_pending(&node("applicant-a")).unwrap();
        assert_eq!(removed.node, node("applicant-a"));
        assert!(store.pending().is_empty());
        assert!(store.remove_pending(&node("applicant-a")).is_none());
    }

    #[test]
    fn clear_outbound() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ControlStore::open(dir.path()).unwrap();
        store.set_outbound(join("me", None), node("parent"), None);
        assert!(store.outbound().is_some());
        store.clear_outbound();
        assert!(store.outbound().is_none());
    }

    #[test]
    fn malformed_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PENDING_JOINS_FILE), b"{ not json").unwrap();
        assert!(ControlStore::open(dir.path()).is_err());

        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(dir2.path().join(OUTBOUND_JOIN_FILE), b"42").unwrap();
        assert!(ControlStore::open(dir2.path()).is_err());
    }

    #[test]
    fn structurally_invalid_pending_rejected() {
        let dir = tempfile::tempdir().unwrap();
        // A node-kind join without a ledger key violates `JoinRequest::validate`.
        let bad = serde_json::json!([{
            "node": "x",
            "kind": "Node",
            "operator": vec![0u8; 32],
            "ledger": null,
            "desired_slot": null,
            "location_hint": null,
            "nonce": 1,
            "expiry": 1,
        }]);
        std::fs::write(
            dir.path().join(PENDING_JOINS_FILE),
            serde_json::to_vec(&bad).unwrap(),
        )
        .unwrap();
        assert!(ControlStore::open(dir.path()).is_err());
    }

    #[test]
    fn duplicate_pending_node_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let req = join("applicant-a", Some(3));
        let doc = vec![req.clone(), req];
        std::fs::write(
            dir.path().join(PENDING_JOINS_FILE),
            serde_json::to_vec(&doc).unwrap(),
        )
        .unwrap();
        assert!(ControlStore::open(dir.path()).is_err());
    }
}
