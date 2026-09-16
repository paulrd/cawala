//! Operator netting harness: load real node data dirs and drive
//! [`cawala_ledger::net`] / [`cawala_ledger::verify_cascade`] over them.
//!
//! The ledger crate's reconciliation functions are pure and have no I/O, so an
//! operator needs a loader that assembles their inputs from the data dirs a
//! running network actually wrote:
//!
//! - the **topology** from each dir's `node.json` (parent/child links), or a
//!   saved [`Topology`] snapshot for historical re-slotting;
//! - the **peer registry** from each dir's self row plus every
//!   `ledger_peers.json` row, rejecting any conflict;
//! - the **ledgers** by replaying each `entries.log` into an in-memory
//!   [`Ledger<MemLog>`](cawala_ledger::Ledger);
//! - the **commitment chains** from each `<dir>/ledger/commitments.log`;
//! - the **orders** by merging every dir's journal with an optional
//!   operator-supplied source.
//!
//! `net`'s `RouteInvalid` findings are reported as **advisories**: topology is
//! live control-plane state, so a route that no longer reconstructs (e.g. a
//! re-slotted child) needs operator adjudication rather than a hard failure.
//! Everything else (`Fork`, `ChainInvalid`, `MirrorMismatch`, `Replay`,
//! `Overdraw`) is a hard finding. Advisories still suppress `nets`: the ledger
//! crate only collapses flows when `findings.is_empty()`, so a `RouteInvalid`
//! advisory yields no nets until it is resolved (e.g. by loading the matching
//! `--topology` snapshot).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use cawala_ledger::{
    AccountRef, Finding, HopRole, Ledger, LedgerSet, MemLog, NetTransfer, NodeId, OperatorPubKey,
    PaymentOrder, PeerKeys, PeerRegistry, PeerRole, SignedCommitment,
};
use cawala_topology::{ChildKind, Topology};
use serde::Serialize;

use crate::identity;
use crate::ledger_commitments::CommitmentLog;
use crate::ledger_keys;
use crate::ledger_peers;
use crate::ledger_store::{self, LedgerLock};
use crate::orders;
use crate::record;

/// A per-peer loading summary for the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerReport {
    /// The peer's node id.
    pub node_id: String,
    /// The peer's data dir as given on the command line.
    pub data_dir: String,
    /// Whether a non-empty commitment chain was loaded.
    pub chain_present: bool,
    /// Number of commitments loaded for this peer (0 when absent/empty).
    pub chain_len: usize,
    /// Loading notes (missing/empty chain, absent chain row, ...).
    pub notes: Vec<String>,
}

/// The assembled inputs for one reconciliation run.
#[derive(Debug)]
pub struct HarnessInputs {
    /// The derived (or supplied) topology.
    pub topology: Topology,
    /// The merged, conflict-free peer registry.
    pub registry: PeerRegistry,
    /// Each peer's replayed ledger.
    pub ledgers: LedgerSet,
    /// Each peer's validated commitment chain (possibly empty).
    pub commitments: BTreeMap<NodeId, Vec<SignedCommitment>>,
    /// The merged, deduplicated orders.
    pub orders: Vec<PaymentOrder>,
    /// Per-peer loading summaries.
    pub peers: Vec<PeerReport>,
    /// Report-level notes (e.g. no orders supplied).
    pub notes: Vec<String>,
}

/// The serializable reconciliation report.
#[derive(Debug, Clone, Serialize)]
pub struct HarnessReport {
    /// Per-peer loading summaries.
    pub peers: Vec<PeerReport>,
    /// Node ids with a non-empty commitment chain.
    pub chains_present: Vec<String>,
    /// `RouteInvalid` findings, kept separate for operator adjudication.
    pub advisories: Vec<Finding>,
    /// Hard findings (`Fork`/`ChainInvalid`/`MirrorMismatch`/`Replay`/`Overdraw`).
    pub findings: Vec<Finding>,
    /// Collapsed flows (only when there are no findings at all).
    pub nets: Vec<NetTransfer>,
    /// Report-level notes.
    pub notes: Vec<String>,
}

/// Load every `net` input from `peer_dirs`.
///
/// `orders_source` is an optional operator-supplied order source: a file path
/// or `-` for stdin, holding either a JSON array of orders or one JSON order
/// per line. `topology_file` optionally overrides the topology with a saved
/// snapshot.
///
/// Every peer dir is validated and held under a shared ledger lock for the
/// duration of the load (released before returning).
pub fn load(
    peer_dirs: &[PathBuf],
    orders_source: Option<&str>,
    topology_file: Option<&Path>,
) -> Result<HarnessInputs> {
    if peer_dirs.is_empty() {
        bail!("no peer data dirs supplied");
    }

    // Validate first (so a missing dir is reported before any lock creates
    // files), then hold a shared lock on each peer while reading.
    for dir in peer_dirs {
        validate_peer_dir(dir)?;
    }
    let mut _locks = Vec::with_capacity(peer_dirs.len());
    for dir in peer_dirs {
        _locks.push(
            LedgerLock::acquire_shared(dir)
                .with_context(|| format!("failed to lock peer {}", dir.display()))?,
        );
    }

    // --- records + topology -------------------------------------------------
    let mut records = Vec::with_capacity(peer_dirs.len());
    for dir in peer_dirs {
        records.push(read_record(dir)?);
    }
    let topology = match topology_file {
        Some(path) => load_topology_snapshot(path)?,
        None => build_topology(&records)?,
    };

    // --- registry + per-peer keys ------------------------------------------
    let mut candidates: BTreeMap<String, PeerKeys> = BTreeMap::new();
    let mut peers_meta: Vec<PeerLedger> = Vec::with_capacity(peer_dirs.len());
    for (dir, rec) in peer_dirs.iter().zip(&records) {
        let meta = ledger_store::load_meta(dir)
            .with_context(|| format!("failed to load ledger meta for peer {}", dir.display()))?;
        if meta.node_id != rec.node_id {
            bail!(
                "peer {} record node id '{}' does not match meta.json node id '{}'",
                dir.display(),
                rec.node_id,
                meta.node_id
            );
        }
        let ledger_key = load_ledger_key(dir)?;
        if ledger_key.public() != meta.ledger_id {
            bail!(
                "peer {} ledger_key does not match meta.json ledger id",
                dir.display()
            );
        }
        let operator = load_operator(dir)?;
        merge_peer(
            &mut candidates,
            PeerKeys {
                node_id: NodeId::from(rec.node_id.clone()),
                operator,
                ledger: Some(meta.ledger_id),
                role: PeerRole::Node,
            },
        )?;
        for row in read_peer_rows(dir)? {
            merge_peer(&mut candidates, row)?;
        }
        peers_meta.push(PeerLedger {
            data_dir: dir.clone(),
            node_id: rec.node_id.clone(),
            ledger_id: meta.ledger_id,
            key: ledger_key,
        });
    }
    let mut registry = PeerRegistry::new();
    for row in candidates.into_values() {
        registry
            .insert(row)
            .context("conflicting peer registry rows across peer dirs")?;
    }

    // --- ledgers ------------------------------------------------------------
    let mut ledgers = LedgerSet::new();
    for peer in &peers_meta {
        let file_ledger = ledger_store::open_ledger(&peer.data_dir, &peer.node_id, &peer.key)
            .with_context(|| format!("failed to replay peer {}", peer.data_dir.display()))?;
        let mut mem = Ledger::new_non_root_with_log(peer.ledger_id, MemLog::new());
        for index in 0..file_ledger.len() {
            let entry = file_ledger
                .get(index)?
                .ok_or_else(|| anyhow::anyhow!("peer {} entry {index} missing", peer.node_id))?;
            mem.append(entry)?;
        }
        ledgers
            .insert(NodeId::from(peer.node_id.clone()), mem)
            .map_err(|err| anyhow::anyhow!("duplicate peer ledger for {}: {err}", peer.node_id))?;
    }

    // --- commitment chains --------------------------------------------------
    let mut commitments: BTreeMap<NodeId, Vec<SignedCommitment>> = BTreeMap::new();
    let mut peers = Vec::with_capacity(peers_meta.len());
    for peer in &peers_meta {
        let log = CommitmentLog::open(&peer.data_dir, peer.ledger_id)
            .with_context(|| format!("failed to load commitment chain for {}", peer.data_dir.display()))?;
        let chain_len = log.len();
        let chain_present = !log.is_empty();
        let notes = if chain_present {
            vec![format!("commitment chain present ({chain_len})")]
        } else {
            vec!["missing/empty commitment chain".to_string()]
        };
        commitments.insert(NodeId::from(peer.node_id.clone()), log.chain().to_vec());
        peers.push(PeerReport {
            node_id: peer.node_id.clone(),
            data_dir: peer.data_dir.display().to_string(),
            chain_present,
            chain_len,
            notes,
        });
    }

    // --- orders -------------------------------------------------------------
    let mut merged = Vec::new();
    for peer in &peers_meta {
        merged.extend(orders::load_all(&peer.data_dir));
    }
    if let Some(source) = orders_source {
        merged.extend(read_orders_source(source)?);
    }
    dedup_orders(&mut merged);

    Ok(HarnessInputs {
        topology,
        registry,
        ledgers,
        commitments,
        orders: merged,
        peers,
        notes: Vec::new(),
    })
}

/// Run [`cawala_ledger::net`] over `inputs` and classify its findings.
pub fn report(inputs: &HarnessInputs) -> HarnessReport {
    let netting = cawala_ledger::net(
        &inputs.topology,
        &inputs.ledgers,
        &inputs.registry,
        &inputs.orders,
        &inputs.commitments,
    );

    let (advisories, findings) = classify_findings(netting.findings);

    let mut notes = inputs.notes.clone();
    if inputs.orders.is_empty() {
        notes.push("no orders supplied; route/replay audit skipped".to_string());
    }

    HarnessReport {
        peers: inputs.peers.clone(),
        chains_present: inputs
            .peers
            .iter()
            .filter(|peer| peer.chain_present)
            .map(|peer| peer.node_id.clone())
            .collect(),
        advisories,
        findings,
        nets: netting.nets,
        notes,
    }
}

/// Split findings into `(advisories, hard)`. Route findings are advisories
/// because the topology they are audited against is live control-plane state.
pub fn classify_findings(findings: Vec<Finding>) -> (Vec<Finding>, Vec<Finding>) {
    let mut advisories = Vec::new();
    let mut hard = Vec::new();
    for finding in findings {
        if matches!(finding, Finding::RouteInvalid { .. }) {
            advisories.push(finding);
        } else {
            hard.push(finding);
        }
    }
    (advisories, hard)
}

/// Read an order source: `-` for stdin, otherwise a file path. Accepts a JSON
/// array of orders or one JSON order per line.
pub fn read_orders_source(source: &str) -> Result<Vec<PaymentOrder>> {
    let text = if source == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("failed to read orders from stdin")?;
        text
    } else {
        std::fs::read_to_string(source)
            .with_context(|| format!("failed to read orders file {source}"))?
    };
    parse_orders_text(&text)
}

/// Parse orders from `text` (a JSON array or one JSON object per line).
pub fn parse_orders_text(text: &str) -> Result<Vec<PaymentOrder>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        return serde_json::from_str::<Vec<PaymentOrder>>(trimmed)
            .context("invalid orders JSON array");
    }
    let mut orders = Vec::new();
    for (index, line) in trimmed.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        orders.push(
            serde_json::from_str::<PaymentOrder>(line)
                .with_context(|| format!("invalid order JSON on line {}", index + 1))?,
        );
    }
    Ok(orders)
}

/// A stable display label for an account.
pub fn account_label(account: &AccountRef) -> String {
    match account {
        AccountRef::Parent => "parent".to_string(),
        AccountRef::Child(id) => format!("child:{id}"),
    }
}

/// A stable display label for a hop role.
pub fn role_label(role: HopRole) -> &'static str {
    match role {
        HopRole::Ascend => "ascend",
        HopRole::Lca => "lca",
        HopRole::Descend => "descend",
        HopRole::Direct => "direct",
    }
}

/// The per-peer ledger identity the loaders carry between phases.
struct PeerLedger {
    data_dir: PathBuf,
    node_id: String,
    ledger_id: cawala_ledger::LedgerPubKey,
    key: cawala_ledger::LedgerSecretKey,
}

/// Builder state for one topology node before conversion.
struct NodeBuilder {
    kind: ChildKind,
    parent: Option<(String, u8)>,
    children: BTreeSet<u8>,
}

fn validate_peer_dir(dir: &Path) -> Result<()> {
    if !dir.is_dir() {
        bail!("peer data dir {} does not exist", dir.display());
    }
    for (file, what) in [
        (record::NODE_RECORD_FILE, "node record"),
        (ledger_keys::LEDGER_KEY_FILE, "ledger key"),
        (identity::SECRET_KEY_FILE, "identity key"),
    ] {
        if !dir.join(file).exists() {
            bail!("peer {} has no {what} ({file}); run `init`", dir.display());
        }
    }
    Ok(())
}

fn read_record(dir: &Path) -> Result<record::NodeRecord> {
    let path = dir.join(record::NODE_RECORD_FILE);
    let bytes = std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let record: record::NodeRecord = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid node record", path.display()))?;
    record
        .validate()
        .with_context(|| format!("{} is not a valid node record", path.display()))?;
    Ok(record)
}

fn load_ledger_key(dir: &Path) -> Result<cawala_ledger::LedgerSecretKey> {
    // `validate_peer_dir` guarantees the file exists, so this never creates.
    ledger_keys::load_or_create_ledger_key(dir)
        .with_context(|| format!("failed to load ledger key for {}", dir.display()))
}

fn load_operator(dir: &Path) -> Result<OperatorPubKey> {
    let secret = identity::load_or_create_secret_key(dir)
        .with_context(|| format!("failed to load identity for {}", dir.display()))?;
    // The operator key is the same Ed25519 key as the iroh endpoint id, derived
    // from the stored secret exactly as the control plane does.
    Ok(cawala_ledger::OperatorSecretKey::from_bytes(secret.to_bytes()).public())
}

fn read_peer_rows(dir: &Path) -> Result<Vec<PeerKeys>> {
    let path = dir.join(ledger_peers::PEERS_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    // Validate through the registry's own deserializer (which rejects duplicate
    // keys *within* one file), then read the raw rows for merging.
    ledger_peers::load_peers(dir)
        .with_context(|| format!("{} is not a valid peer registry", path.display()))?;
    let bytes = std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let rows: Vec<PeerKeys> = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid peer registry", path.display()))?;
    Ok(rows)
}

/// Merge one candidate row into the aggregate, erroring on a conflicting node
/// id, and otherwise de-duplicating identical rows (a node appears in many
/// dirs' registries).
fn merge_peer(candidates: &mut BTreeMap<String, PeerKeys>, row: PeerKeys) -> Result<()> {
    let key = row.node_id.as_str().to_string();
    match candidates.get(&key) {
        Some(existing) if existing == &row => Ok(()),
        Some(existing) => bail!(
            "conflicting registry rows for node {}: {:?} vs {:?}",
            key,
            existing,
            row
        ),
        None => {
            candidates.insert(key, row);
            Ok(())
        }
    }
}

fn ensure_node(
    nodes: &mut HashMap<String, NodeBuilder>,
    id: &str,
    kind: ChildKind,
) -> Result<()> {
    let builder = nodes
        .entry(id.to_string())
        .or_insert_with(|| NodeBuilder {
            kind,
            parent: None,
            children: BTreeSet::new(),
        });
    if builder.kind != kind {
        bail!("topology node '{id}' is declared as both a node and a user");
    }
    Ok(())
}

fn set_parent(
    nodes: &mut HashMap<String, NodeBuilder>,
    id: &str,
    parent: &str,
    slot: u8,
) -> Result<()> {
    let builder = nodes
        .get_mut(id)
        .expect("ensure_node must run before set_parent");
    match &builder.parent {
        Some((existing_parent, existing_slot))
            if existing_parent != parent || *existing_slot != slot =>
        {
            bail!(
                "topology node '{id}' has conflicting parent links \
                 ('{existing_parent}'@{existing_slot} vs '{parent}'@{slot})"
            );
        }
        _ => builder.parent = Some((parent.to_string(), slot)),
    }
    Ok(())
}

/// Build a topology from peer records: each dir's node plus its recorded
/// children by parent/slot.
pub fn build_topology(records: &[record::NodeRecord]) -> Result<Topology> {
    let mut nodes: HashMap<String, NodeBuilder> = HashMap::new();

    for rec in records {
        ensure_node(&mut nodes, &rec.node_id, ChildKind::Node)?;
        if let Some(parent) = &rec.parent {
            set_parent(&mut nodes, &rec.node_id, &parent.parent_id, parent.slot)?;
        }
        for child in &rec.children {
            ensure_node(&mut nodes, &child.child_id, child.kind)?;
            set_parent(&mut nodes, &child.child_id, &rec.node_id, child.slot)?;
            nodes
                .get_mut(&rec.node_id)
                .expect("parent ensured")
                .children
                .insert(child.slot);
        }
    }

    // A child's `parent` link is authoritative for attachment, so synthesize
    // the reciprocal slot in the parent's children set when the parent's own
    // record did not list it (e.g. a re-parented child whose old parent record
    // is stale). Done in a second pass so the parent need not have been seen
    // first. A truly absent parent is left dangling for the root/validate
    // checks to reject.
    for rec in records {
        if let Some(parent) = &rec.parent
            && let Some(builder) = nodes.get_mut(&parent.parent_id)
        {
            builder.children.insert(parent.slot);
        }
    }

    let roots: Vec<String> = nodes
        .iter()
        .filter(|(_, builder)| builder.parent.is_none())
        .map(|(id, _)| id.clone())
        .collect();
    if roots.len() != 1 {
        bail!(
            "expected exactly one parent-less root, found {} ({})",
            roots.len(),
            roots.join(", ")
        );
    }

    let mut topo_nodes = HashMap::with_capacity(nodes.len());
    for (id, builder) in nodes {
        topo_nodes.insert(
            id.clone(),
            cawala_topology::NodeRecord {
                node_id: id,
                kind: builder.kind,
                parent: builder.parent.as_ref().map(|(parent, _)| parent.clone()),
                slot: builder.parent.as_ref().map(|(_, slot)| *slot),
                children: builder.children,
            },
        );
    }
    let topology = Topology::from_parts(topo_nodes, roots[0].clone());
    topology
        .validate()
        .context("peer records do not form a valid topology")?;
    Ok(topology)
}

fn load_topology_snapshot(path: &Path) -> Result<Topology> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let topology: Topology = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid topology snapshot", path.display()))?;
    topology
        .validate()
        .with_context(|| format!("{} is not a valid topology", path.display()))?;
    Ok(topology)
}

fn dedup_orders(orders: &mut Vec<PaymentOrder>) {
    let mut seen = BTreeSet::new();
    orders.retain(|order| seen.insert(order.hash()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::{Amount, SignedCommitment, build_commitment, commitment_hash};
    use cawala_topology::OctAddr;

    fn write_record(
        dir: &Path,
        node_id: &str,
        address: &str,
        parent: Option<(&str, u8)>,
        children: &[(&str, ChildKind, u8)],
    ) {
        std::fs::create_dir_all(dir).unwrap();
        let mut store = record::RecordStore::open(dir, node_id).unwrap();
        // Parent must be set before a non-root address is asserted.
        if let Some((parent_id, slot)) = parent {
            store.set_parent(parent_id, slot).unwrap();
        }
        store.set_address(address.parse::<OctAddr>().unwrap()).unwrap();
        for (child_id, kind, slot) in children {
            store.attach_child(child_id.to_string(), *kind, Some(*slot), 0).unwrap();
        }
        store.save().unwrap();
    }

    fn order(from: &str, to: &str, nonce: u64) -> PaymentOrder {
        PaymentOrder {
            from: NodeId::from(from),
            to: NodeId::from(to),
            amount: Amount::new(5),
            nonce,
            expiry: 1_000,
        }
    }

    #[test]
    fn build_topology_from_records_links_children() {
        let root = record::NodeRecord {
            node_id: "root".to_string(),
            address: Some("0".parse().unwrap()),
            parent: None,
            children: vec![record::ChildEntry {
                child_id: "leaf".to_string(),
                kind: ChildKind::Node,
                slot: 1,
                date_joined: 0,
            }],
        };
        let leaf = record::NodeRecord {
            node_id: "leaf".to_string(),
            address: Some("0.1".parse().unwrap()),
            parent: Some(record::ParentLink {
                parent_id: "root".to_string(),
                slot: 1,
            }),
            children: vec![record::ChildEntry {
                child_id: "user-a".to_string(),
                kind: ChildKind::User,
                slot: 3,
                date_joined: 0,
            }],
        };

        // Only peer (node) records are supplied; `user-a` is derived from the
        // leaf's recorded children.
        let topology = build_topology(&[root, leaf]).unwrap();
        assert_eq!(topology.root_id(), "root");
        assert_eq!(topology.node_count(), 3);
        assert_eq!(
            topology.address_of("user-a").unwrap(),
            "0.1.3".parse::<OctAddr>().unwrap()
        );
    }

    #[test]
    fn build_topology_rejects_zero_or_multiple_roots() {
        let orphan = record::NodeRecord {
            node_id: "orphan".to_string(),
            address: Some("0".parse().unwrap()),
            parent: None,
            children: vec![],
        };
        assert!(build_topology(std::slice::from_ref(&orphan)).is_ok());

        let other = record::NodeRecord {
            node_id: "other".to_string(),
            address: Some("0".parse().unwrap()),
            parent: None,
            children: vec![],
        };
        // Two parent-less roots.
        let err = build_topology(&[orphan, other]).unwrap_err();
        assert!(err.to_string().contains("exactly one parent-less root"));

        // A child whose parent is absent: the parent reference is dangling.
        let dangling = record::NodeRecord {
            node_id: "child".to_string(),
            address: Some("0.1".parse().unwrap()),
            parent: Some(record::ParentLink {
                parent_id: "missing".to_string(),
                slot: 1,
            }),
            children: vec![],
        };
        assert!(build_topology(&[dangling]).is_err());
    }

    #[test]
    fn merge_peer_rejects_conflict_and_dedups_identical() {
        let op = OperatorPubKey::from_bytes(&[1u8; 32]).unwrap();
        let ledger = cawala_ledger::LedgerSecretKey::from_bytes([2u8; 32]).public();
        let row = PeerKeys {
            node_id: NodeId::from("n1"),
            operator: op,
            ledger: Some(ledger),
            role: PeerRole::Node,
        };
        let mut map = BTreeMap::new();
        merge_peer(&mut map, row.clone()).unwrap();
        // Identical row from another dir: dedup.
        merge_peer(&mut map, row.clone()).unwrap();
        assert_eq!(map.len(), 1);

        // Different key for the same node id: conflict.
        let conflicting = PeerKeys {
            node_id: NodeId::from("n1"),
            operator: OperatorPubKey::from_bytes(&[9u8; 32]).unwrap(),
            ledger: Some(cawala_ledger::LedgerSecretKey::from_bytes([9u8; 32]).public()),
            role: PeerRole::Node,
        };
        assert!(merge_peer(&mut map, conflicting).is_err());
    }

    #[test]
    fn topology_snapshot_override_round_trips() {
        let topology = Topology::new_root("root");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("topology.json");
        std::fs::write(&path, serde_json::to_string(&topology).unwrap()).unwrap();
        let loaded = load_topology_snapshot(&path).unwrap();
        assert_eq!(loaded.root_id(), "root");

        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, b"{ not a topology").unwrap();
        assert!(load_topology_snapshot(&bad).is_err());
    }

    #[test]
    fn parse_orders_accepts_array_and_jsonl() {
        let a = order("u1", "u2", 1);
        let b = order("u1", "u2", 2);
        let array = serde_json::to_string(&vec![a.clone(), b.clone()]).unwrap();
        assert_eq!(parse_orders_text(&array).unwrap(), vec![a.clone(), b.clone()]);

        let jsonl = format!(
            "{}\n{}\n",
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
        assert_eq!(parse_orders_text(&jsonl).unwrap(), vec![a, b]);
        assert!(parse_orders_text("{ not json").is_err());
    }

    #[test]
    fn dedup_orders_keeps_first_occurrence() {
        let a = order("u1", "u2", 1);
        let mut orders = vec![a.clone(), order("u1", "u2", 2), a.clone()];
        dedup_orders(&mut orders);
        assert_eq!(orders.len(), 2);
        assert_eq!(orders[0], a);
    }

    #[test]
    fn report_classifies_route_invalid_as_advisory() {
        let route = Finding::RouteInvalid {
            payment_id: cawala_ledger::Hash::from_bytes([1u8; 32]),
            reason: "test".to_string(),
        };
        let hard = Finding::ChainInvalid {
            node: NodeId::from("n1"),
            reason: "test".to_string(),
        };
        let (advisories, findings) = classify_findings(vec![route, hard]);
        assert_eq!(advisories.len(), 1);
        assert!(matches!(advisories[0], Finding::RouteInvalid { .. }));
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0], Finding::ChainInvalid { .. }));

        // An empty-but-valid harness: no ledgers, no orders -> no findings.
        let inputs = HarnessInputs {
            topology: Topology::new_root("root"),
            registry: PeerRegistry::new(),
            ledgers: LedgerSet::new(),
            commitments: BTreeMap::new(),
            orders: vec![],
            peers: vec![],
            notes: vec![],
        };
        let report = report(&inputs);
        assert!(report.findings.is_empty());
        assert!(report.advisories.is_empty());
        assert!(report.nets.is_empty());
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("route/replay audit skipped"))
        );
    }

    /// End-to-end: two initialized peer dirs load into topology, registry,
    /// ledgers, chains, and a report.
    #[test]
    fn load_end_to_end_over_two_peer_dirs() {
        let root_dir = tempfile::tempdir().unwrap();
        let leaf_dir = tempfile::tempdir().unwrap();

        // Root peer.
        let root_secret = identity::load_or_create_secret_key(root_dir.path()).unwrap();
        let root_id = root_secret.public().to_string();
        let root_key = ledger_keys::load_or_create_ledger_key(root_dir.path()).unwrap();
        ledger_store::init_ledger(root_dir.path(), &root_id, &root_key.public()).unwrap();
        write_record(root_dir.path(), &root_id, "0", None, &[]);

        // Leaf peer, parented to the root at slot 1, holding user-a at slot 3.
        let leaf_secret = identity::load_or_create_secret_key(leaf_dir.path()).unwrap();
        let leaf_id = leaf_secret.public().to_string();
        let leaf_key = ledger_keys::load_or_create_ledger_key(leaf_dir.path()).unwrap();
        ledger_store::init_ledger(leaf_dir.path(), &leaf_id, &leaf_key.public()).unwrap();
        write_record(
            leaf_dir.path(),
            &leaf_id,
            "0.1",
            Some((&root_id, 1)),
            &[("user-a", ChildKind::User, 3)],
        );

        // Give the leaf an entry and a commitment so the chain is present.
        let mut leaf_svc =
            crate::ledger_service::LedgerService::open(leaf_dir.path(), &leaf_id).unwrap();
        let op_secret = cawala_ledger::OperatorSecretKey::from_bytes(leaf_secret.to_bytes());
        let operator = op_secret.public();
        let user = NodeId::from("user-a");
        leaf_svc.ensure_account_open(&user, ChildKind::User).unwrap();
        leaf_svc
            .fund(&user, ChildKind::User, 10, &op_secret, 1, 1_000)
            .unwrap();
        // Cross-check the operator the loader derives from `secret_key` is the
        // one the service registers.
        assert_eq!(
            leaf_svc
                .effective_registry()
                .unwrap()
                .get(&NodeId::from(leaf_id.clone()))
                .unwrap()
                .operator,
            operator
        );
        leaf_svc.commit().unwrap();

        let peers = vec![root_dir.path().to_path_buf(), leaf_dir.path().to_path_buf()];
        let inputs = load(&peers, None, None).unwrap();
        assert_eq!(inputs.topology.root_id(), root_id);
        assert_eq!(inputs.topology.node_count(), 3, "root, leaf, user-a");
        assert_eq!(inputs.ledgers.node_ids().count(), 2);
        assert!(inputs
            .commitments
            .get(&NodeId::from(leaf_id.clone()))
            .is_some_and(|c| c.len() == 1));
        assert!(inputs
            .commitments
            .get(&NodeId::from(root_id.clone()))
            .is_some_and(|c| c.is_empty()));

        // The registry holds both self rows.
        let registry = &inputs.registry;
        assert!(registry.ledger_of(&NodeId::from(root_id.clone())).is_some());
        assert!(registry.ledger_of(&NodeId::from(leaf_id.clone())).is_some());

        let report = report(&inputs);
        assert!(report.findings.is_empty(), "findings: {:?}", report.findings);
        assert_eq!(
            report.chains_present,
            vec![leaf_id.clone()],
            "only the leaf has a commitment"
        );
    }

    /// A commitment chain with a broken link is a load error.
    #[test]
    fn load_rejects_invalid_commitment_chain() {
        let dir = tempfile::tempdir().unwrap();
        let secret = identity::load_or_create_secret_key(dir.path()).unwrap();
        let node_id = secret.public().to_string();
        let key = ledger_keys::load_or_create_ledger_key(dir.path()).unwrap();
        ledger_store::init_ledger(dir.path(), &node_id, &key.public()).unwrap();
        write_record(dir.path(), &node_id, "0", None, &[]);

        // A genesis commitment that does not anchor at `Hash::ZERO`.
        let built = build_commitment(
            &Ledger::new_non_root_with_log(key.public(), MemLog::new()),
            cawala_ledger::Hash::from_bytes([7u8; 32]),
            0,
        )
        .unwrap();
        let signed = SignedCommitment::sign(built, &key).unwrap();
        assert_ne!(commitment_hash(&signed.commitment), cawala_ledger::Hash::ZERO);

        let log_path = crate::ledger_commitments::commitments_path(dir.path());
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        let frame = postcard::to_allocvec(&signed).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&frame);
        std::fs::write(&log_path, bytes).unwrap();

        let err = load(&[dir.path().to_path_buf()], None, None).unwrap_err();
        assert!(err.to_string().contains("commitment chain"), "unexpected: {err}");
    }
}
