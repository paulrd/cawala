//! Cawala topology: a hierarchy of nodes and users with octal addressing.
//!
//! Model:
//! - one root node; every node has at most 8 children occupying octal slots
//!   `0..=7`;
//! - a child's address = parent's address + its slot digit (see [`OctAddr`]);
//!   geographic containment follows by construction;
//! - topology changes are *downward-only*: a node may only be re-parented
//!   within its current parent's subtree (no cross-region renumbering), while
//!   attaching an unattached node under any existing node is unrestricted;
//! - `User`-kind nodes can never be parents (users are leaves).
//!
//! Pure `std` + `serde`: no iroh, no tokio. All mutating operations return
//! [`Result`]; on error the topology is left unchanged.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

pub use proto::{OctAddr, MAX_SLOT};

/// What a record represents: another network node, or a user (always a leaf).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ChildKind {
    Node,
    User,
}

/// A child edge, as returned by [`Topology::children_of`]: the slot a child
/// occupies under its parent, its kind, and its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Child {
    pub slot: u8,
    pub kind: ChildKind,
    pub child_id: String,
}

/// Stored record for one node: identity, kind, optional parent link, and the
/// set of occupied child slots (`0..=7`, at most 8 entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_id: String,
    pub kind: ChildKind,
    pub parent: Option<String>,
    pub slot: Option<u8>,
    pub children: BTreeSet<u8>,
}

/// The whole topology: nodes keyed by id, plus the root's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Topology {
    nodes: HashMap<String, NodeRecord>,
    root: String,
}

/// Errors raised by topology operations and [`Topology::validate`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TopologyError {
    #[error("node '{0}' not found")]
    NodeNotFound(String),
    #[error("node '{0}' already exists")]
    DuplicateNode(String),
    #[error("node '{0}' is a user and cannot have children")]
    UserCannotHaveChildren(String),
    #[error("slot {slot} under parent '{parent}' is already taken")]
    SlotTaken { parent: String, slot: u8 },
    #[error("slot {0} out of range (must be 0..=7)")]
    SlotOutOfRange(u8),
    #[error("parent '{0}' already has 8 children")]
    CapExceeded(String),
    #[error("{0}")]
    Cycle(String),
    #[error("node '{0}' is not attached")]
    NotAttached(String),
    #[error("node '{0}' is already attached")]
    AlreadyAttached(String),
    #[error("node '{0}' still has children")]
    NotLeaf(String),
    #[error("the root cannot be detached")]
    CannotDetachRoot,
    #[error("the root cannot be removed")]
    CannotRemoveRoot,
    #[error("the root cannot be attached under another node")]
    CannotAttachRoot,
    #[error("move of '{node}' to '{new_parent}' crosses regions (downward-only rule)")]
    CrossRegionMove { node: String, new_parent: String },
}

/// How a parent chain terminates when walking upward.
enum ChainTop {
    Root,
    Unattached,
}

impl Topology {
    /// Create a new topology with a single root node of kind
    /// [`ChildKind::Node`]. The root's address is `"0"`.
    pub fn new_root(node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        let root = NodeRecord {
            node_id: node_id.clone(),
            kind: ChildKind::Node,
            parent: None,
            slot: None,
            children: BTreeSet::new(),
        };
        let mut nodes = HashMap::new();
        nodes.insert(node_id.clone(), root);
        Topology { nodes, root: node_id }
    }

    /// Construct from raw parts *without* validating. Run
    /// [`Topology::validate`] before trusting the result (e.g. after
    /// deserializing persisted links).
    pub fn from_parts(nodes: HashMap<String, NodeRecord>, root: String) -> Self {
        Topology { nodes, root }
    }

    /// Add an unattached node.
    pub fn add_node(
        &mut self,
        node_id: impl Into<String>,
        kind: ChildKind,
    ) -> Result<(), TopologyError> {
        let node_id = node_id.into();
        if self.nodes.contains_key(&node_id) {
            return Err(TopologyError::DuplicateNode(node_id));
        }
        self.nodes.insert(
            node_id.clone(),
            NodeRecord {
                node_id,
                kind,
                parent: None,
                slot: None,
                children: BTreeSet::new(),
            },
        );
        Ok(())
    }

    /// Attach an unattached child under a parent (a join).
    ///
    /// Unrestricted: the parent only needs to exist and be of kind
    /// [`ChildKind::Node`]; it need not be connected to the root. `slot`
    /// `None` picks the lowest free slot.
    pub fn attach(
        &mut self,
        parent_id: &str,
        child_id: &str,
        slot: Option<u8>,
    ) -> Result<(), TopologyError> {
        if !self.nodes.contains_key(parent_id) {
            return Err(TopologyError::NodeNotFound(parent_id.to_string()));
        }
        if !self.nodes.contains_key(child_id) {
            return Err(TopologyError::NodeNotFound(child_id.to_string()));
        }
        if parent_id == child_id {
            return Err(TopologyError::Cycle(format!(
                "cannot attach '{child_id}' to itself"
            )));
        }
        if child_id == self.root {
            return Err(TopologyError::CannotAttachRoot);
        }
        if self.nodes[child_id].parent.is_some() {
            return Err(TopologyError::AlreadyAttached(child_id.to_string()));
        }
        if self.nodes[parent_id].kind != ChildKind::Node {
            return Err(TopologyError::UserCannotHaveChildren(parent_id.to_string()));
        }

        // Cycle check: the child may be the root of a floating island, and
        // must not be an ancestor of the parent (attaching it would create a
        // cycle). Walk up from the parent to detect that.
        {
            let mut cur: &str = parent_id;
            let mut steps = 0usize;
            loop {
                if cur == child_id {
                    return Err(TopologyError::Cycle(format!(
                        "cannot attach '{child_id}' under its descendant '{parent_id}'"
                    )));
                }
                match &self.nodes[cur].parent {
                    Some(p) => cur = p,
                    None => break,
                }
                steps += 1;
                if steps > self.nodes.len() {
                    return Err(TopologyError::Cycle(parent_id.to_string()));
                }
            }
        }

        let slot = self.resolve_slot(parent_id, child_id, slot)?;

        self.nodes.get_mut(child_id).unwrap().parent = Some(parent_id.to_string());
        self.nodes.get_mut(child_id).unwrap().slot = Some(slot);
        self.nodes.get_mut(parent_id).unwrap().children.insert(slot);
        Ok(())
    }

    /// Detach a node from its parent; the subtree becomes unattached.
    /// The root cannot be detached.
    pub fn detach(&mut self, child_id: &str) -> Result<(), TopologyError> {
        if !self.nodes.contains_key(child_id) {
            return Err(TopologyError::NodeNotFound(child_id.to_string()));
        }
        if child_id == self.root {
            return Err(TopologyError::CannotDetachRoot);
        }
        let (parent_id, slot) = match &self.nodes[child_id] {
            NodeRecord {
                parent: Some(p),
                slot: Some(s),
                ..
            } => (p.clone(), *s),
            _ => return Err(TopologyError::NotAttached(child_id.to_string())),
        };
        self.nodes.get_mut(&parent_id).unwrap().children.remove(&slot);
        let child = self.nodes.get_mut(child_id).unwrap();
        child.parent = None;
        child.slot = None;
        Ok(())
    }

    /// Re-parent an attached node, downward-only.
    ///
    /// `new_parent` must be the child's current parent or a descendant of it
    /// (moving within the same region); moving into the child's own subtree is
    /// rejected as a cycle. Cross-region renumbering is not built.
    pub fn move_child(
        &mut self,
        child_id: &str,
        new_parent_id: &str,
        slot: Option<u8>,
    ) -> Result<(), TopologyError> {
        if !self.nodes.contains_key(child_id) {
            return Err(TopologyError::NodeNotFound(child_id.to_string()));
        }
        if !self.nodes.contains_key(new_parent_id) {
            return Err(TopologyError::NodeNotFound(new_parent_id.to_string()));
        }
        let old_parent_id = match &self.nodes[child_id].parent {
            Some(p) => p.clone(),
            None => return Err(TopologyError::NotAttached(child_id.to_string())),
        };
        if self.nodes[new_parent_id].kind != ChildKind::Node {
            return Err(TopologyError::UserCannotHaveChildren(
                new_parent_id.to_string(),
            ));
        }

        // Downward-only + cycle check in one upward walk from new_parent:
        // reaching old_parent is legal; reaching child_id first is a cycle;
        // hitting a parentless node other than old_parent is cross-region.
        {
            let mut cur: &str = new_parent_id;
            let mut steps = 0usize;
            loop {
                if cur == child_id {
                    return Err(TopologyError::Cycle(format!(
                        "cannot move '{child_id}' into its own subtree"
                    )));
                }
                if cur == old_parent_id {
                    break; // legal: same parent or a descendant of it
                }
                let rec = &self.nodes[cur];
                match &rec.parent {
                    Some(p) => cur = p,
                    None => {
                        return Err(TopologyError::CrossRegionMove {
                            node: child_id.to_string(),
                            new_parent: new_parent_id.to_string(),
                        })
                    }
                }
                steps += 1;
                if steps > self.nodes.len() {
                    return Err(TopologyError::Cycle(new_parent_id.to_string()));
                }
            }
        }

        let slot = self.resolve_slot(new_parent_id, child_id, slot)?;

        let old_slot = self.nodes[child_id].slot.unwrap();
        if new_parent_id == old_parent_id && slot == old_slot {
            return Ok(()); // no-op
        }
        self.nodes.get_mut(&old_parent_id).unwrap().children.remove(&old_slot);
        self.nodes.get_mut(child_id).unwrap().parent = Some(new_parent_id.to_string());
        self.nodes.get_mut(child_id).unwrap().slot = Some(slot);
        self.nodes.get_mut(new_parent_id).unwrap().children.insert(slot);
        Ok(())
    }

    /// Remove a childless node. The root cannot be removed.
    pub fn remove_node(&mut self, node_id: &str) -> Result<(), TopologyError> {
        if !self.nodes.contains_key(node_id) {
            return Err(TopologyError::NodeNotFound(node_id.to_string()));
        }
        if node_id == self.root {
            return Err(TopologyError::CannotRemoveRoot);
        }
        if !self.nodes[node_id].children.is_empty() {
            return Err(TopologyError::NotLeaf(node_id.to_string()));
        }
        if let Some(parent_id) = self.nodes[node_id].parent.clone() {
            let slot = self.nodes[node_id].slot.unwrap();
            self.nodes.get_mut(&parent_id).unwrap().children.remove(&slot);
        }
        self.nodes.remove(node_id);
        Ok(())
    }

    /// Resolve an explicit or auto-assigned slot for `child_id` under
    /// `parent_id` without mutating anything.
    ///
    /// `None` picks the lowest free slot. If the child already occupies a slot
    /// under this parent (the same-parent re-slot case), its own slot counts
    /// as free for it.
    fn resolve_slot(
        &self,
        parent_id: &str,
        child_id: &str,
        slot: Option<u8>,
    ) -> Result<u8, TopologyError> {
        let parent = &self.nodes[parent_id];
        let self_slot = self.nodes.get(child_id).and_then(|c| match (&c.parent, c.slot) {
            (Some(p), Some(s)) if p == parent_id => Some(s),
            _ => None,
        });
        match slot {
            Some(s) => {
                if s > MAX_SLOT {
                    return Err(TopologyError::SlotOutOfRange(s));
                }
                if parent.children.contains(&s) {
                    if self_slot == Some(s) {
                        return Ok(s); // already in this slot: no-op
                    }
                    return Err(TopologyError::SlotTaken {
                        parent: parent_id.to_string(),
                        slot: s,
                    });
                }
                if parent.children.len() >= 8 {
                    return Err(TopologyError::CapExceeded(parent_id.to_string()));
                }
                Ok(s)
            }
            None => {
                for s in 0..=MAX_SLOT {
                    if !parent.children.contains(&s) || self_slot == Some(s) {
                        return Ok(s);
                    }
                }
                Err(TopologyError::CapExceeded(parent_id.to_string()))
            }
        }
    }

    /// The id of the node's parent, if it is attached.
    pub fn parent_of(&self, node_id: &str) -> Result<Option<&str>, TopologyError> {
        self.nodes
            .get(node_id)
            .map(|r| r.parent.as_deref())
            .ok_or_else(|| TopologyError::NodeNotFound(node_id.to_string()))
    }

    /// The node's children, sorted by slot.
    pub fn children_of(&self, node_id: &str) -> Result<Vec<Child>, TopologyError> {
        let rec = self
            .nodes
            .get(node_id)
            .ok_or_else(|| TopologyError::NodeNotFound(node_id.to_string()))?;
        let mut out = Vec::with_capacity(rec.children.len());
        for &slot in &rec.children {
            let child_id = self.child_at(node_id, slot).ok_or_else(|| {
                TopologyError::NodeNotFound(format!("child of '{node_id}' at slot {slot}"))
            })?;
            let child = self
                .nodes
                .get(&child_id)
                .ok_or_else(|| TopologyError::NodeNotFound(child_id.clone()))?;
            out.push(Child {
                slot,
                kind: child.kind,
                child_id,
            });
        }
        // children is a BTreeSet, so iteration is already sorted by slot.
        Ok(out)
    }

    /// Derive the octal address of a node by walking up to the root:
    /// root = `"0"`, child = parent's address + its slot digit.
    ///
    /// Nodes not connected to the root (floating/unattached) have no address
    /// ([`TopologyError::NotAttached`]).
    pub fn address_of(&self, node_id: &str) -> Result<OctAddr, TopologyError> {
        let (top, mut slots_rev) = self.walk_chain(node_id)?;
        match top {
            ChainTop::Unattached => {
                return Err(TopologyError::NotAttached(node_id.to_string()))
            }
            ChainTop::Root => {}
        }
        let depth = slots_rev.len() + 1;
        slots_rev.reverse();
        let mut digits = Vec::with_capacity(depth);
        digits.push(0);
        digits.extend(slots_rev);
        // Slots are validated by walk_chain (each <= MAX_SLOT, first digit 0),
        // so from_digits cannot fail here.
        Ok(OctAddr::from_digits(digits).expect("slots validated by walk_chain"))
    }

    /// Number of nodes in the topology (including the root).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The root's id.
    pub fn root_id(&self) -> &str {
        &self.root
    }

    /// Iterate over all node ids.
    pub fn node_ids(&self) -> impl Iterator<Item = &String> {
        self.nodes.keys()
    }

    /// The stored record for a node, if present.
    pub fn node(&self, node_id: &str) -> Option<&NodeRecord> {
        self.nodes.get(node_id)
    }

    /// Full invariant walk. Must pass after every legal operation, and
    /// rejects tampered/deserialized states.
    ///
    /// Checks: a single, parentless root; no orphaned parent references;
    /// link reciprocity (each attached child's slot appears in its parent's
    /// children set and no two nodes claim the same parent slot); slots in
    /// `0..=7`, at most 8 per parent; user nodes childless; no cycles;
    /// address injectivity (no two root-connected nodes share a derived
    /// address). Unattached (floating) components are legal and skipped for
    /// addressing.
    pub fn validate(&self) -> Result<(), TopologyError> {
        // 1. Single root: exists, and is the top of the tree.
        let root_rec = self
            .nodes
            .get(&self.root)
            .ok_or_else(|| TopologyError::NodeNotFound(self.root.clone()))?;
        if root_rec.parent.is_some() || root_rec.slot.is_some() {
            return Err(TopologyError::Cycle(self.root.clone()));
        }

        // 2. Per-node structural invariants.
        let mut claims: HashMap<(&str, u8), &str> = HashMap::new();
        for (id, rec) in &self.nodes {
            // Users are always leaves.
            if rec.kind == ChildKind::User && !rec.children.is_empty() {
                return Err(TopologyError::UserCannotHaveChildren(id.clone()));
            }
            // Children sets are bounded and in range.
            if rec.children.len() > 8 {
                return Err(TopologyError::CapExceeded(id.clone()));
            }
            for &s in &rec.children {
                if s > MAX_SLOT {
                    return Err(TopologyError::SlotOutOfRange(s));
                }
            }
            match &rec.parent {
                Some(p) => {
                    // No orphans: every parent reference exists.
                    let parent = self
                        .nodes
                        .get(p)
                        .ok_or_else(|| TopologyError::NodeNotFound(p.clone()))?;
                    // Users cannot be parents.
                    if parent.kind != ChildKind::Node {
                        return Err(TopologyError::UserCannotHaveChildren(p.clone()));
                    }
                    // No self-parent.
                    if p == id {
                        return Err(TopologyError::Cycle(id.clone()));
                    }
                    // Attached nodes carry a valid slot.
                    let s = rec
                        .slot
                        .ok_or_else(|| TopologyError::NotAttached(id.clone()))?;
                    if s > MAX_SLOT {
                        return Err(TopologyError::SlotOutOfRange(s));
                    }
                    // Link reciprocity: the parent's children set lists this slot.
                    if !parent.children.contains(&s) {
                        return Err(TopologyError::NotAttached(id.clone()));
                    }
                    // Slot uniqueness per parent.
                    if claims.insert((p.as_str(), s), id.as_str()).is_some() {
                        return Err(TopologyError::SlotTaken {
                            parent: p.clone(),
                            slot: s,
                        });
                    }
                }
                None => {
                    // Unattached (floating) nodes carry no slot.
                    if rec.slot.is_some() {
                        return Err(TopologyError::NotAttached(id.clone()));
                    }
                }
            }
        }

        // 3. No cycles anywhere (floating islands are legal, but acyclic).
        // 4. Address injectivity over the root-connected component.
        let mut seen: HashMap<OctAddr, &str> = HashMap::new();
        for id in self.nodes.keys() {
            let (top, mut slots_rev) = self.walk_chain(id)?;
            let ChainTop::Root = top else {
                continue; // unattached chain: no derived address
            };
            let depth = slots_rev.len() + 1;
            slots_rev.reverse();
            let mut digits = Vec::with_capacity(depth);
            digits.push(0);
            digits.extend(slots_rev);
            let addr = OctAddr::from_digits(digits).expect("slots validated by walk_chain");
            if seen.insert(addr.clone(), id).is_some() {
                // Two nodes share a derived address: structurally a duplicate
                // (parent, slot) claim along their common path.
                return Err(TopologyError::SlotTaken {
                    parent: addr.to_string(),
                    slot: addr.slot().unwrap_or(0),
                });
            }
        }
        Ok(())
    }

    /// Walk parent links from `node_id` up to the top of its chain. Returns
    /// how the chain ends and the slot digits along the path in reverse order
    /// (deepest first). Detects cycles via a visited set.
    fn walk_chain(&self, node_id: &str) -> Result<(ChainTop, Vec<u8>), TopologyError> {
        let mut slots_rev: Vec<u8> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut cur: &str = node_id;
        loop {
            if !seen.insert(cur) {
                return Err(TopologyError::Cycle(node_id.to_string()));
            }
            let rec = self
                .nodes
                .get(cur)
                .ok_or_else(|| TopologyError::NodeNotFound(node_id.to_string()))?;
            match &rec.parent {
                Some(p) => {
                    let s = rec
                        .slot
                        .ok_or_else(|| TopologyError::NotAttached(node_id.to_string()))?;
                    if s > MAX_SLOT {
                        return Err(TopologyError::SlotOutOfRange(s));
                    }
                    slots_rev.push(s);
                    cur = p;
                }
                None => {
                    return if cur == self.root {
                        Ok((ChainTop::Root, slots_rev))
                    } else {
                        Ok((ChainTop::Unattached, slots_rev))
                    }
                }
            }
        }
    }

    /// The id of the child of `parent_id` occupying `slot`, if any.
    fn child_at(&self, parent_id: &str, slot: u8) -> Option<String> {
        self.nodes.iter().find_map(|(id, r)| match (&r.parent, r.slot) {
            (Some(p), Some(s)) if p == parent_id && s == slot => Some(id.clone()),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_topo() -> Topology {
        Topology::new_root("root")
    }

    fn addr(s: &str) -> OctAddr {
        s.parse().unwrap()
    }

    #[test]
    fn new_root() {
        let t = node_topo();
        assert_eq!(t.root_id(), "root");
        assert_eq!(t.node_count(), 1);
        assert_eq!(t.node("root").unwrap().kind, ChildKind::Node);
        assert_eq!(t.address_of("root").unwrap(), addr("0"));
        assert!(t.validate().is_ok());
    }

    #[test]
    fn attach_auto_slot() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("b", ChildKind::Node).unwrap();
        t.attach("root", "a", None).unwrap();
        t.attach("root", "b", None).unwrap();
        assert_eq!(t.address_of("a").unwrap(), addr("0.0"));
        assert_eq!(t.address_of("b").unwrap(), addr("0.1"));
        assert_eq!(t.parent_of("a").unwrap(), Some("root"));
        assert!(t.validate().is_ok());
    }

    #[test]
    fn attach_explicit_slot() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.attach("root", "a", Some(5)).unwrap();
        assert_eq!(t.address_of("a").unwrap(), addr("0.5"));
        assert_eq!(t.parent_of("a").unwrap(), Some("root"));
    }

    #[test]
    fn attach_errors() {
        let mut t = node_topo();
        t.add_node("u", ChildKind::User).unwrap();
        t.add_node("a", ChildKind::Node).unwrap();
        // missing nodes
        assert_eq!(
            t.attach("nope", "a", None),
            Err(TopologyError::NodeNotFound("nope".into()))
        );
        assert_eq!(
            t.attach("root", "nope", None),
            Err(TopologyError::NodeNotFound("nope".into()))
        );
        // attaching a node to itself
        assert!(matches!(
            t.attach("root", "root", None),
            Err(TopologyError::Cycle(_))
        ));
        // user parents are rejected
        assert_eq!(
            t.attach("u", "a", None),
            Err(TopologyError::UserCannotHaveChildren("u".into()))
        );
        // once attached, attaching again is rejected
        t.attach("root", "a", None).unwrap();
        assert_eq!(
            t.attach("root", "a", None),
            Err(TopologyError::AlreadyAttached("a".into()))
        );
        // the root itself cannot be attached under another node
        let mut t2 = node_topo();
        t2.add_node("x", ChildKind::Node).unwrap();
        assert_eq!(t2.attach("x", "root", None), Err(TopologyError::CannotAttachRoot));
    }

    #[test]
    fn duplicate_node_rejected() {
        let mut t = node_topo();
        assert_eq!(
            t.add_node("root", ChildKind::Node),
            Err(TopologyError::DuplicateNode("root".into()))
        );
        t.add_node("a", ChildKind::Node).unwrap();
        assert_eq!(
            t.add_node("a", ChildKind::User),
            Err(TopologyError::DuplicateNode("a".into()))
        );
    }

    #[test]
    fn slot_conflict() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("b", ChildKind::Node).unwrap();
        t.attach("root", "a", Some(3)).unwrap();
        assert_eq!(
            t.attach("root", "b", Some(3)),
            Err(TopologyError::SlotTaken {
                parent: "root".into(),
                slot: 3
            })
        );
        // the tree is unchanged
        assert!(t.parent_of("b").unwrap().is_none());
        assert!(t.validate().is_ok());
    }

    #[test]
    fn ninth_child_rejected() {
        let mut t = node_topo();
        for i in 0..8 {
            let id = format!("n{i}");
            t.add_node(&id, ChildKind::Node).unwrap();
            t.attach("root", &id, None).unwrap();
        }
        t.add_node("n8", ChildKind::Node).unwrap();
        // auto slot: everything taken
        assert_eq!(
            t.attach("root", "n8", None),
            Err(TopologyError::CapExceeded("root".into()))
        );
        // explicit slot: all slots are taken by other children
        assert_eq!(
            t.attach("root", "n8", Some(4)),
            Err(TopologyError::SlotTaken {
                parent: "root".into(),
                slot: 4
            })
        );
        assert!(t.validate().is_ok());
        assert_eq!(t.node_count(), 10); // root + 8 attached children + unattached n8
    }

    #[test]
    fn slot_out_of_range() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        assert_eq!(
            t.attach("root", "a", Some(8)),
            Err(TopologyError::SlotOutOfRange(8))
        );
        assert!(t.parent_of("a").unwrap().is_none());
    }

    #[test]
    fn detach() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("a1", ChildKind::Node).unwrap();
        t.attach("root", "a", None).unwrap();
        t.attach("a", "a1", None).unwrap();
        t.detach("a").unwrap();
        // a is now floating; its subtree a1 stays attached to a
        assert!(t.parent_of("a").unwrap().is_none());
        assert!(t.address_of("a").is_err());
        assert_eq!(t.parent_of("a1").unwrap(), Some("a"));
        assert!(t.children_of("root").unwrap().is_empty());
        assert!(t.validate().is_ok());
        // errors
        assert_eq!(t.detach("root"), Err(TopologyError::CannotDetachRoot));
        assert_eq!(
            t.detach("a"),
            Err(TopologyError::NotAttached("a".into()))
        );
        assert_eq!(
            t.detach("nope"),
            Err(TopologyError::NodeNotFound("nope".into()))
        );
    }

    #[test]
    fn move_reslot_within_parent() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.attach("root", "a", Some(2)).unwrap();
        assert_eq!(t.address_of("a").unwrap(), addr("0.2"));
        t.move_child("a", "root", Some(5)).unwrap();
        assert_eq!(t.address_of("a").unwrap(), addr("0.5"));
        // a no-op move to the same parent and slot succeeds
        t.move_child("a", "root", Some(5)).unwrap();
        assert_eq!(t.address_of("a").unwrap(), addr("0.5"));
        assert!(t.validate().is_ok());
    }

    #[test]
    fn move_deeper_into_same_region() {
        // Downward subdivision: an admin inserts a new intermediate node under
        // `a` and moves one of `a`'s children under it.
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("a1", ChildKind::Node).unwrap();
        t.add_node("a2", ChildKind::Node).unwrap();
        t.add_node("mid", ChildKind::Node).unwrap();
        t.attach("root", "a", None).unwrap();
        t.attach("a", "a1", None).unwrap();
        t.attach("a", "a2", None).unwrap();
        t.attach("a", "mid", None).unwrap();
        t.move_child("a1", "mid", None).unwrap();
        // addresses: a=0.0, a2=0.0.1, mid=0.0.2, a1 now 0.0.2.0
        assert_eq!(t.address_of("a").unwrap(), addr("0.0"));
        assert_eq!(t.address_of("a2").unwrap(), addr("0.0.1"));
        assert_eq!(t.address_of("mid").unwrap(), addr("0.0.2"));
        assert_eq!(t.address_of("a1").unwrap(), addr("0.0.2.0"));
        assert!(t.validate().is_ok());
    }

    #[test]
    fn move_into_own_subtree_rejected() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("a1", ChildKind::Node).unwrap();
        t.add_node("a11", ChildKind::Node).unwrap();
        t.attach("root", "a", None).unwrap();
        t.attach("a", "a1", None).unwrap();
        t.attach("a1", "a11", None).unwrap();
        assert!(matches!(
            t.move_child("a", "a1", None),
            Err(TopologyError::Cycle(_))
        ));
        // the tree is unchanged
        assert_eq!(t.parent_of("a").unwrap(), Some("root"));
        assert!(t.validate().is_ok());
    }

    #[test]
    fn move_cross_region_rejected() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("a1", ChildKind::Node).unwrap();
        t.add_node("b", ChildKind::Node).unwrap();
        t.add_node("b1", ChildKind::Node).unwrap();
        t.attach("root", "a", None).unwrap();
        t.attach("root", "b", None).unwrap();
        t.attach("a", "a1", None).unwrap();
        t.attach("b", "b1", None).unwrap();
        // a1's old parent is `a`; b1 is outside a's subtree.
        assert!(matches!(
            t.move_child("a1", "b1", None),
            Err(TopologyError::CrossRegionMove { .. })
        ));
        // moving up to an ancestor is also cross-region for a1.
        assert!(matches!(
            t.move_child("a1", "root", None),
            Err(TopologyError::CrossRegionMove { .. })
        ));
        // the tree is unchanged
        assert_eq!(t.parent_of("a1").unwrap(), Some("a"));
        assert!(t.validate().is_ok());
    }

    #[test]
    fn move_unattached_rejected() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("b", ChildKind::Node).unwrap();
        t.attach("root", "a", None).unwrap();
        assert_eq!(
            t.move_child("b", "a", None),
            Err(TopologyError::NotAttached("b".into()))
        );
    }

    #[test]
    fn move_slot_out_of_range() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.attach("root", "a", None).unwrap();
        assert_eq!(
            t.move_child("a", "root", Some(9)),
            Err(TopologyError::SlotOutOfRange(9))
        );
    }

    #[test]
    fn remove_node() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("a1", ChildKind::Node).unwrap();
        t.attach("root", "a", None).unwrap();
        t.attach("a", "a1", None).unwrap();
        t.remove_node("a1").unwrap();
        assert_eq!(t.node_count(), 2);
        assert_eq!(
            t.parent_of("a1"),
            Err(TopologyError::NodeNotFound("a1".into()))
        );
        assert!(t.children_of("a").unwrap().is_empty());
        // now a is childless and can be removed
        t.remove_node("a").unwrap();
        assert_eq!(t.node_count(), 1);
        assert!(t.validate().is_ok());
        // errors
        assert_eq!(t.remove_node("root"), Err(TopologyError::CannotRemoveRoot));
        assert_eq!(
            t.remove_node("nope"),
            Err(TopologyError::NodeNotFound("nope".into()))
        );
    }

    #[test]
    fn remove_non_leaf_rejected() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("a1", ChildKind::Node).unwrap();
        t.attach("root", "a", None).unwrap();
        t.attach("a", "a1", None).unwrap();
        assert_eq!(t.remove_node("a"), Err(TopologyError::NotLeaf("a".into())));
        assert_eq!(t.node_count(), 3);
    }

    #[test]
    fn user_cannot_have_children() {
        let mut t = node_topo();
        t.add_node("u", ChildKind::User).unwrap();
        t.add_node("n", ChildKind::Node).unwrap();
        assert_eq!(
            t.attach("u", "n", None),
            Err(TopologyError::UserCannotHaveChildren("u".into()))
        );
        assert!(t.parent_of("n").unwrap().is_none());
        // moves under a user are rejected too
        t.attach("root", "n", None).unwrap();
        assert_eq!(
            t.move_child("n", "u", None),
            Err(TopologyError::UserCannotHaveChildren("u".into()))
        );
    }

    #[test]
    fn children_of_sorted_by_slot() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("b", ChildKind::User).unwrap();
        t.attach("root", "a", Some(5)).unwrap();
        t.attach("root", "b", Some(2)).unwrap();
        let children = t.children_of("root").unwrap();
        let slots: Vec<u8> = children.iter().map(|c| c.slot).collect();
        assert_eq!(slots, vec![2, 5]);
        let kinds: Vec<ChildKind> = children.iter().map(|c| c.kind).collect();
        assert_eq!(kinds, vec![ChildKind::User, ChildKind::Node]);
    }

    #[test]
    fn address_derivation() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("b", ChildKind::Node).unwrap();
        t.add_node("a1", ChildKind::Node).unwrap();
        t.add_node("u", ChildKind::User).unwrap();
        t.attach("root", "a", Some(3)).unwrap();
        t.attach("root", "b", Some(6)).unwrap();
        t.attach("a", "a1", Some(2)).unwrap();
        t.attach("a", "u", Some(7)).unwrap();
        assert_eq!(t.address_of("root").unwrap(), addr("0"));
        assert_eq!(t.address_of("a").unwrap(), addr("0.3"));
        assert_eq!(t.address_of("b").unwrap(), addr("0.6"));
        assert_eq!(t.address_of("a1").unwrap(), addr("0.3.2"));
        assert_eq!(t.address_of("u").unwrap(), addr("0.3.7"));
        // floating nodes have no address
        t.add_node("floating", ChildKind::Node).unwrap();
        assert_eq!(
            t.address_of("floating"),
            Err(TopologyError::NotAttached("floating".into()))
        );
        assert_eq!(
            t.address_of("nope"),
            Err(TopologyError::NodeNotFound("nope".into()))
        );
        assert!(t.validate().is_ok());
    }

    #[test]
    fn validate_rejects_tampered_states() {
        let mut t = node_topo();
        t.add_node("a", ChildKind::Node).unwrap();
        t.add_node("b", ChildKind::Node).unwrap();
        t.add_node("u", ChildKind::User).unwrap();
        t.attach("root", "a", Some(0)).unwrap();
        t.attach("root", "b", Some(1)).unwrap();
        t.attach("a", "u", Some(0)).unwrap();
        assert!(t.validate().is_ok());

        // orphaned parent reference
        let mut bad = t.clone();
        bad.nodes.get_mut("b").unwrap().parent = Some("ghost".into());
        assert_eq!(
            bad.validate(),
            Err(TopologyError::NodeNotFound("ghost".into()))
        );

        // two children claiming the same (parent, slot)
        let mut bad = t.clone();
        bad.nodes.get_mut("b").unwrap().parent = Some("root".into());
        bad.nodes.get_mut("b").unwrap().slot = Some(0);
        assert_eq!(
            bad.validate(),
            Err(TopologyError::SlotTaken {
                parent: "root".into(),
                slot: 0
            })
        );

        // root with a parent: single-root invariant broken
        let mut bad = t.clone();
        bad.nodes.get_mut("root").unwrap().parent = Some("a".into());
        bad.nodes.get_mut("root").unwrap().slot = Some(0);
        assert!(matches!(bad.validate(), Err(TopologyError::Cycle(_))));

        // a user with children
        let mut bad = t.clone();
        bad.nodes.get_mut("u").unwrap().children.insert(1);
        assert_eq!(
            bad.validate(),
            Err(TopologyError::UserCannotHaveChildren("u".into()))
        );

        // reciprocity broken: parent's children no longer lists the child's slot
        let mut bad = t.clone();
        bad.nodes.get_mut("a").unwrap().children.remove(&0);
        assert_eq!(bad.validate(), Err(TopologyError::NotAttached("u".into())));
    }
}
