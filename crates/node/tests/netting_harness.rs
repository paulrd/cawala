//! Hermetic, on-disk verification of the netting harness (Lane S3).
//!
//! Each test builds real peer data dirs (`node.json`, `secret_key`,
//! `ledger_key`, `meta.json`, `entries.log`, `commitments.log`, optionally
//! `ledger_peers.json`) exactly as a running node would, then drives
//! [`cawala_node::netting_harness::load`]/[`report`] over them. No network, no
//! shared state: every fixture owns a [`tempfile::TempDir`].
//!
//! Topology (peer dirs R, A, B):
//!
//! ```text
//!        R
//!      /   \
//!     A     B
//!     |     |
//!    uA    uB
//! ```
//!
//! `entries.log` is written through the node's [`ledger_store::FileLog`] layer
//! (via `open_ledger` + `append`, which re-verifies every frame), and
//! `commitments.log` through [`ledger_commitments::CommitmentLog`], so the
//! loader reads back exactly what an operator's CLI would.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cawala_ledger::{
    AccountRef, Amount, AuthRef, Entry, EntryBody, Finding, Hash, HopRole, Ledger, LedgerSecretKey,
    LedgerSet, MemLog, MirrorDirection, NetTransfer, NodeId, OperatorPubKey, OperatorSecretKey,
    PaymentOrder, PeerKeys, PeerRegistry, PeerRole, Posting, SignedAmount, SignedCommitment,
    SignedEntry, build_commitment, commitment_hash, execute_plan, plan_transfer, verify_chain,
};
use cawala_node::netting_harness::{self, HarnessInputs};
use cawala_node::{identity, ledger_commitments, ledger_keys, ledger_peers, ledger_store, record};
use cawala_topology::{ChildKind, Topology};

/// The payer's registered operator (uA).
const PAYER_OP: u8 = 11;
/// The payee's registered operator (uB).
const PAYEE_OP: u8 = 12;

fn n(id: &str) -> NodeId {
    NodeId::from(id)
}

fn op(seed: u8) -> OperatorSecretKey {
    OperatorSecretKey::from_bytes([seed; 32])
}

fn p(account: AccountRef, delta: i64) -> Posting {
    Posting {
        account,
        delta: SignedAmount::new(delta),
    }
}

fn user_row(id: &str, operator: &OperatorSecretKey) -> PeerKeys {
    PeerKeys {
        node_id: n(id),
        operator: operator.public(),
        ledger: None,
        role: PeerRole::User,
    }
}

fn dummy_auth() -> AuthRef {
    let operator = op(200);
    AuthRef {
        operator: operator.public(),
        nonce: 0,
        order_hash: Hash::ZERO,
        signature: operator.sign(b"setup"),
    }
}

fn order(nonce: u64) -> PaymentOrder {
    PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(100),
        nonce,
        expiry: 1000,
    }
}

/// Append an already-built body to an in-memory ledger.
fn append_entry(
    ledger: &mut Ledger<MemLog>,
    key: &LedgerSecretKey,
    body: EntryBody,
    postings: Vec<Posting>,
    auth: Option<AuthRef>,
) {
    let entry = Entry {
        ledger_id: key.public(),
        seq: ledger.len() as u64,
        height: ledger.len() as u64,
        prev_hash: ledger.head_hash(),
        issued_at: 0,
        body,
        postings,
        auth,
    };
    ledger
        .append(SignedEntry::sign(entry, key).unwrap())
        .unwrap();
}

fn open(ledger: &mut Ledger<MemLog>, key: &LedgerSecretKey, child: &NodeId, kind: ChildKind) {
    append_entry(
        ledger,
        key,
        EntryBody::OpenAccount {
            child: child.clone(),
            kind,
        },
        vec![],
        None,
    );
}

fn issue(ledger: &mut Ledger<MemLog>, key: &LedgerSecretKey, child: &NodeId, amount: u64) {
    append_entry(
        ledger,
        key,
        EntryBody::Issue {
            child: child.clone(),
            amount: Amount::new(amount),
        },
        vec![p(AccountRef::Child(child.clone()), amount as i64)],
        Some(dummy_auth()),
    );
}

fn descend(ledger: &mut Ledger<MemLog>, key: &LedgerSecretKey, child: &NodeId, amount: u64) {
    append_entry(
        ledger,
        key,
        EntryBody::Transfer {
            payment_id: Hash::ZERO,
            amount: Amount::new(amount),
            role: HopRole::Descend,
        },
        vec![
            p(AccountRef::Parent, amount as i64),
            p(AccountRef::Child(child.clone()), amount as i64),
        ],
        Some(dummy_auth()),
    );
}

/// One on-disk peer.
struct Peer {
    dir: PathBuf,
    node_id: String,
    key: LedgerSecretKey,
    operator: OperatorPubKey,
    record: record::NodeRecord,
}

impl Peer {
    fn id(&self) -> NodeId {
        n(&self.node_id)
    }
}

/// Create a peer data dir and its `node.json`; `node_id` is explicit so a
/// conflicting pair can be built for the registry test.
fn make_peer_at(
    dir: &Path,
    node_id: &str,
    address: &str,
    parent: Option<(&str, u8)>,
    children: &[(&str, ChildKind, u8)],
) -> Peer {
    std::fs::create_dir_all(dir).unwrap();
    let secret = identity::load_or_create_secret_key(dir).unwrap();
    let operator = OperatorSecretKey::from_bytes(secret.to_bytes()).public();
    let key = ledger_keys::load_or_create_ledger_key(dir).unwrap();
    ledger_store::init_ledger(dir, node_id, &key.public()).unwrap();

    let mut store = record::RecordStore::open(dir, node_id).unwrap();
    if let Some((parent_id, slot)) = parent {
        store.set_parent(parent_id, slot).unwrap();
    }
    store.set_address(address.parse().unwrap()).unwrap();
    for (child_id, kind, slot) in children {
        store
            .attach_child(child_id.to_string(), *kind, Some(*slot), 0)
            .unwrap();
    }
    store.save().unwrap();
    let record = store.record().clone();

    Peer {
        dir: dir.to_path_buf(),
        node_id: node_id.to_string(),
        key,
        operator,
        record,
    }
}

/// Append every in-memory entry not yet on disk to the peer's `entries.log`.
fn persist(peer: &Peer, ledger: &Ledger<MemLog>) {
    let mut disk = ledger_store::open_ledger(&peer.dir, &peer.node_id, &peer.key).unwrap();
    for index in disk.len()..ledger.len() {
        let entry = ledger.get(index).unwrap().expect("entry");
        disk.append(entry).unwrap();
    }
}

/// Append one linked commitment at the ledger's current head.
fn commit_peer(peer: &Peer, ledger: &Ledger<MemLog>, ts: u64) -> SignedCommitment {
    let mut log = ledger_commitments::CommitmentLog::open(&peer.dir, peer.key.public()).unwrap();
    let commitment = build_commitment(ledger, log.last_hash(), ts).unwrap();
    let signed = SignedCommitment::sign(commitment, &peer.key).unwrap();
    log.append(signed.clone()).unwrap();
    signed
}

/// Build a fresh in-memory ledger for `peer`, persist every entry to
/// `entries.log`, and record one linked commitment.
fn seed_peer(
    peer: &Peer,
    ts: u64,
    build: impl FnOnce(&mut Ledger<MemLog>, &LedgerSecretKey),
) {
    let mut ledger = Ledger::new_non_root_with_log(peer.key.public(), MemLog::new());
    build(&mut ledger, &peer.key);
    persist(peer, &ledger);
    commit_peer(peer, &ledger, ts);
}

/// Rewrite `commitments.log` verbatim (no validation), so a broken chain can be
/// planted.
fn write_chain(dir: &Path, chain: &[SignedCommitment]) {
    let mut out = Vec::new();
    for signed in chain {
        let frame = postcard::to_allocvec(signed).unwrap();
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&frame);
    }
    std::fs::write(ledger_commitments::commitments_path(dir), out).unwrap();
}

/// A three-peer fixture (R + leaves A/B) whose on-disk state can be advanced in
/// phases and then loaded by the harness.
struct Benches {
    root: tempfile::TempDir,
    r: Peer,
    a: Peer,
    b: Peer,
    topo: Topology,
    registry: PeerRegistry,
    keys: BTreeMap<NodeId, LedgerSecretKey>,
    set: LedgerSet,
}

impl Benches {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();

        let rdir = root.path().join("r");
        let rsecret = identity::load_or_create_secret_key(&rdir).unwrap();
        let rid = rsecret.public().to_string();
        let r = make_peer_at(&rdir, &rid, "0", None, &[]);

        let adir = root.path().join("a");
        let asecret = identity::load_or_create_secret_key(&adir).unwrap();
        let aid = asecret.public().to_string();
        let a = make_peer_at(
            &adir,
            &aid,
            "0.1",
            Some((&rid, 1)),
            &[("uA", ChildKind::User, 3)],
        );

        let bdir = root.path().join("b");
        let bsecret = identity::load_or_create_secret_key(&bdir).unwrap();
        let bid = bsecret.public().to_string();
        let b = make_peer_at(
            &bdir,
            &bid,
            "0.2",
            Some((&rid, 2)),
            &[("uB", ChildKind::User, 4)],
        );

        // The two users are not peer dirs: publish their operator rows in R's
        // registry file so the loader can resolve the payer's authorisation.
        let mut users = PeerRegistry::new();
        users.insert(user_row("uA", &op(PAYER_OP))).unwrap();
        users.insert(user_row("uB", &op(PAYEE_OP))).unwrap();
        ledger_peers::save_peers(&r.dir, &users).unwrap();

        let topo = netting_harness::build_topology(&[
            r.record.clone(),
            a.record.clone(),
            b.record.clone(),
        ])
        .unwrap();

        let mut registry = PeerRegistry::new();
        for peer in [&r, &a, &b] {
            registry
                .insert(PeerKeys {
                    node_id: peer.id(),
                    operator: peer.operator,
                    ledger: Some(peer.key.public()),
                    role: PeerRole::Node,
                })
                .unwrap();
        }
        registry.insert(user_row("uA", &op(PAYER_OP))).unwrap();
        registry.insert(user_row("uB", &op(PAYEE_OP))).unwrap();

        let mut keys = BTreeMap::new();
        keys.insert(r.id(), r.key.clone());
        keys.insert(a.id(), a.key.clone());
        keys.insert(b.id(), b.key.clone());

        let mut set = LedgerSet::new();
        set.insert(r.id(), Ledger::new_root(r.key.public())).unwrap();
        set.insert(a.id(), Ledger::new_non_root(a.key.public()))
            .unwrap();
        set.insert(b.id(), Ledger::new_non_root(b.key.public()))
            .unwrap();

        Benches {
            root,
            r,
            a,
            b,
            topo,
            registry,
            keys,
            set,
        }
    }

    fn peer_dirs(&self) -> Vec<PathBuf> {
        vec![self.r.dir.clone(), self.a.dir.clone(), self.b.dir.clone()]
    }

    /// R issues to A/B and A/B mirror with a `Descend` to their user; persist
    /// the setup and record the first commitment.
    fn fund_setup(&mut self, amount: u64) {
        let (rid, aid, bid) = (self.r.id(), self.a.id(), self.b.id());
        let (rkey, akey, bkey) = (
            self.r.key.clone(),
            self.a.key.clone(),
            self.b.key.clone(),
        );

        {
            let r = self.set.get_mut(&rid).unwrap();
            open(r, &rkey, &aid, ChildKind::Node);
            issue(r, &rkey, &aid, amount);
            open(r, &rkey, &bid, ChildKind::Node);
            issue(r, &rkey, &bid, amount);
        }
        open(self.set.get_mut(&aid).unwrap(), &akey, &n("uA"), ChildKind::User);
        descend(self.set.get_mut(&aid).unwrap(), &akey, &n("uA"), amount);
        open(self.set.get_mut(&bid).unwrap(), &bkey, &n("uB"), ChildKind::User);
        descend(self.set.get_mut(&bid).unwrap(), &bkey, &n("uB"), amount);

        self.persist_all();
        self.commit_all(1);
    }

    /// Plan and apply `order` through a full cross-subtree cascade, persist it,
    /// and record the next commitment for every peer.
    fn apply(&mut self, order: &PaymentOrder) -> AuthRef {
        let auth = order.authorize(&op(PAYER_OP)).unwrap();
        let plan = plan_transfer(&self.topo, order, &auth, &self.set, 42).unwrap();
        execute_plan(&plan, &mut self.set, &self.keys, &self.registry, 50).unwrap();
        self.persist_all();
        self.commit_all(100);
        auth
    }

    fn persist_all(&self) {
        for peer in [&self.r, &self.a, &self.b] {
            let ledger = self.set.get(&peer.id()).unwrap();
            persist(peer, ledger);
        }
    }

    fn commit_all(&self, ts: u64) {
        for peer in [&self.r, &self.a, &self.b] {
            let ledger = self.set.get(&peer.id()).unwrap();
            commit_peer(peer, ledger, ts);
        }
    }

    fn orders_path(&self, orders: &[PaymentOrder]) -> PathBuf {
        let path = self.root.path().join("orders.json");
        let mut text = String::new();
        for order in orders {
            text.push_str(&serde_json::to_string(order).unwrap());
            text.push('\n');
        }
        std::fs::write(&path, text).unwrap();
        path
    }

    fn load_raw(&self, orders: &[PaymentOrder]) -> anyhow::Result<HarnessInputs> {
        let path = self.orders_path(orders);
        netting_harness::load(&self.peer_dirs(), Some(path.to_str().unwrap()), None, None)
    }

    fn load(&self, orders: &[PaymentOrder]) -> HarnessInputs {
        self.load_raw(orders).expect("harness load")
    }
}

// ── 1. Happy path with nets ───────────────────────────────────────────────

#[test]
fn happy_path_with_nets_over_on_disk_peers() {
    let mut b = Benches::new();
    b.fund_setup(1000);
    let order = order(1);
    b.apply(&order);

    let inputs = b.load(std::slice::from_ref(&order));
    // Multi-entry, genesis-anchored chains for every peer.
    for peer in [&b.r, &b.a, &b.b] {
        let chain = inputs.commitments.get(&peer.id()).unwrap();
        assert_eq!(chain.len(), 2, "peer {} chain", peer.node_id);
        assert_eq!(chain[0].commitment.prev_commitment_hash, Hash::ZERO);
        assert!(verify_chain(chain, &peer.key.public()).is_ok());
    }

    let report = netting_harness::report(&inputs);
    assert!(report.findings.is_empty(), "findings: {:?}", report.findings);
    assert!(
        report.advisories.is_empty(),
        "advisories: {:?}",
        report.advisories
    );
    assert_eq!(report.chains_present.len(), 3);
    assert_eq!(
        report.nets,
        vec![NetTransfer {
            parent: b.r.id(),
            from: b.a.id(),
            to: b.b.id(),
            amount: Amount::new(100),
        }],
        "a clean reconciliation must collapse the opposing A<->B flow"
    );
}

// ── 2. Replay ─────────────────────────────────────────────────────────────

#[test]
fn replayed_cascade_is_a_hard_replay_finding() {
    let mut b = Benches::new();
    b.fund_setup(1000);
    let order = order(1);
    b.apply(&order);
    // The same authorisation applied a second time: two complete cascades.
    b.apply(&order);

    let inputs = b.load(std::slice::from_ref(&order));
    let report = netting_harness::report(&inputs);
    assert!(
        report.findings.iter().any(|f| matches!(
            f,
            Finding::Replay { payment_id, .. } if *payment_id == order.hash()
        )),
        "culprit {}: expected Replay, got {:?}",
        order.from,
        report.findings
    );
    assert!(report.nets.is_empty());
}

// ── 3. Mirror tamper ──────────────────────────────────────────────────────

#[test]
fn mirror_tamper_is_a_hard_mirror_mismatch() {
    let mut b = Benches::new();
    b.fund_setup(1000);
    let order = order(1);
    b.apply(&order);

    // A descends 50 more to uA without R extending Child(A): A's Parent asset
    // (950) no longer mirrors R's liability (900).
    let aid = b.a.id();
    let akey = b.a.key.clone();
    descend(b.set.get_mut(&aid).unwrap(), &akey, &n("uA"), 50);
    b.persist_all();

    let inputs = b.load(std::slice::from_ref(&order));
    let report = netting_harness::report(&inputs);
    let mismatch = report.findings.iter().find_map(|f| match f {
        Finding::MirrorMismatch {
            edge,
            parent_view,
            child_view,
            direction,
        } if edge.parent == b.r.id() && edge.child == b.a.id() => {
            Some((*parent_view, *child_view, *direction))
        }
        _ => None,
    });
    assert_eq!(
        mismatch,
        Some((
            Amount::new(900),
            Amount::new(950),
            MirrorDirection::UnbackedClaim,
        )),
        "culprit ledger A: expected an unbacked-claim mirror mismatch, got {:?}",
        report.findings
    );
    assert!(report.nets.is_empty());
}

// ── 4. Chain gap / broken link ────────────────────────────────────────────

#[test]
fn broken_or_gapped_chain_is_a_hard_load_error() {
    let mut b = Benches::new();
    b.fund_setup(1000);
    let order = order(1);
    b.apply(&order);

    let inputs = b.load(std::slice::from_ref(&order));
    let chain = inputs.commitments.get(&b.r.id()).unwrap().clone();
    assert_eq!(chain.len(), 2);

    // (a) Break the genesis anchor: rewrite the first commitment's prev.
    let mut broken_first = chain[0].clone();
    broken_first.commitment.prev_commitment_hash = Hash::from_bytes([9u8; 32]);
    let broken_first = SignedCommitment::sign(broken_first.commitment, &b.r.key).unwrap();
    write_chain(&b.r.dir, &[broken_first, chain[1].clone()]);
    let err = b.load_raw(std::slice::from_ref(&order)).unwrap_err();
    assert!(
        format!("{err:#}").contains("invalid commitment chain"),
        "unexpected error: {err:#}"
    );

    // (b) Drop the first frame: the surviving commitment's prev is not ZERO, so
    // it is no longer a genesis-anchored chain.
    write_chain(&b.r.dir, &[chain[1].clone()]);
    let err = b.load_raw(std::slice::from_ref(&order)).unwrap_err();
    assert!(
        format!("{err:#}").contains("invalid commitment chain"),
        "unexpected error: {err:#}"
    );
}

// ── 5. Fork ───────────────────────────────────────────────────────────────

#[test]
fn same_height_conflicting_commitments_are_a_hard_fork() {
    let mut b = Benches::new();
    b.fund_setup(1000);
    let order = order(1);
    b.apply(&order);

    let mut inputs = b.load(std::slice::from_ref(&order));
    let rid = b.r.id();
    let chain = inputs.commitments.get(&rid).unwrap().clone();
    let last = chain.last().unwrap().clone();

    // A second, validly signed commitment at the same height with different
    // roots.
    let mut conflicting = last.commitment.clone();
    conflicting.entry_root = Hash::from_bytes([0xAA; 32]);
    conflicting.state_root = Hash::from_bytes([0xBB; 32]);
    let fork = SignedCommitment::sign(conflicting, &b.r.key).unwrap();
    let height = last.commitment.height;

    // On disk a same-height fork is rejected outright by `CommitmentLog::open`
    // (verify_chain's strictly-increasing height rule), so it can never reach
    // `net` through the loader. Pin that hard rejection here...
    let mut on_disk = chain.clone();
    on_disk.push(fork.clone());
    write_chain(&b.r.dir, &on_disk);
    assert!(
        b.load_raw(std::slice::from_ref(&order)).is_err(),
        "a same-height on-disk fork must be a hard load error"
    );

    // ...then inject the fork on top of the loaded (on-disk) inputs, the
    // closest feasible way to exercise `net`'s Fork detection.
    inputs.commitments.get_mut(&rid).unwrap().push(fork);

    let report = netting_harness::report(&inputs);
    assert!(
        report.findings.iter().any(|f| matches!(
            f,
            Finding::Fork { ledger_id, height: h, heads }
                if *ledger_id == b.r.key.public() && *h == height && heads.len() == 2
        )),
        "culprit ledger R: expected Fork, got {:?}",
        report.findings
    );
    assert!(report.nets.is_empty());
}

// ── 6. Advisory (unapplied order) ─────────────────────────────────────────

#[test]
fn unapplied_order_is_an_advisory_not_a_hard_finding() {
    let mut b = Benches::new();
    b.fund_setup(1000);
    let applied = order(1);
    b.apply(&applied);
    let unapplied = order(2); // never applied: no on-ledger hops

    let inputs = b.load(&[applied.clone(), unapplied.clone()]);
    let report = netting_harness::report(&inputs);
    assert!(
        report.findings.is_empty(),
        "an unapplied order must not be a hard finding: {:?}",
        report.findings
    );
    assert!(
        report.advisories.iter().any(|f| matches!(
            f,
            Finding::RouteInvalid { payment_id, .. } if *payment_id == unapplied.hash()
        )),
        "expected a RouteInvalid advisory, got {:?}",
        report.advisories
    );
    assert!(
        report.nets.is_empty(),
        "advisories must suppress nets (the ledger crate gates on findings.is_empty())"
    );

    // Library-level exit-code inputs: `findings.is_empty()` is clean by default
    // (exit 0); `--strict` additionally fails on advisories (exit 1).
    let failed_default = !report.findings.is_empty();
    let failed_strict = !report.findings.is_empty() || !report.advisories.is_empty();
    assert!(!failed_default, "default run would exit 0");
    assert!(failed_strict, "strict run would exit 1");
}

// ── 7. Registry conflict ──────────────────────────────────────────────────

#[test]
fn conflicting_registry_rows_across_peers_are_a_hard_load_error() {
    let root = tempfile::tempdir().unwrap();
    let d1 = root.path().join("one");
    let d2 = root.path().join("two");
    // Two dirs claim the same node id but carry different identity/ledger keys.
    let p1 = make_peer_at(&d1, "same-node", "0", None, &[]);
    let p2 = make_peer_at(&d2, "same-node", "0", None, &[]);

    let err = netting_harness::load(&[p1.dir.clone(), p2.dir.clone()], None, None, None).unwrap_err();
    assert!(
        format!("{err:#}").contains("conflicting registry rows"),
        "unexpected error: {err:#}"
    );
}

// ── 8. Missing chain ──────────────────────────────────────────────────────

#[test]
fn missing_chain_is_a_note_and_net_still_runs() {
    let mut b = Benches::new();
    b.fund_setup(1000);
    let order = order(1);
    b.apply(&order);

    // Simulate a peer that never committed.
    let b_chain = ledger_commitments::commitments_path(&b.b.dir);
    if b_chain.exists() {
        std::fs::remove_file(&b_chain).unwrap();
    }

    let inputs = b.load(std::slice::from_ref(&order));
    let peer_b = inputs
        .peers
        .iter()
        .find(|peer| peer.node_id == b.b.node_id)
        .expect("peer B report");
    assert!(!peer_b.chain_present, "B has no chain");
    assert_eq!(peer_b.chain_len, 0);
    assert!(
        peer_b
            .notes
            .iter()
            .any(|note| note.contains("missing/empty")),
        "expected a missing-chain note, got {:?}",
        peer_b.notes
    );
    assert!(!report_chains_contains(&inputs, &b.b.id()));

    let report = netting_harness::report(&inputs);
    assert!(
        report
            .findings
            .iter()
            .all(|f| !matches!(f, Finding::ChainInvalid { .. })),
        "an absent chain is not a ChainInvalid finding: {:?}",
        report.findings
    );
}

fn report_chains_contains(inputs: &HarnessInputs, id: &NodeId) -> bool {
    inputs
        .commitments
        .get(id)
        .is_some_and(|chain| !chain.is_empty())
}

// ── 9. Chain verification depth ───────────────────────────────────────────

#[test]
fn multi_commitment_chain_verifies_and_a_broken_link_is_rejected() {
    let mut b = Benches::new();
    b.fund_setup(1000);
    let order = order(1);
    b.apply(&order);

    let inputs = b.load(std::slice::from_ref(&order));
    for peer in [&b.r, &b.a, &b.b] {
        let chain = inputs.commitments.get(&peer.id()).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].commitment.prev_commitment_hash, Hash::ZERO);
        assert_eq!(
            chain[1].commitment.prev_commitment_hash,
            commitment_hash(&chain[0].commitment)
        );
        assert!(chain[1].commitment.height > chain[0].commitment.height);
        assert!(verify_chain(chain, &peer.key.public()).is_ok());
    }

    // Replace the linked second commitment with one whose prev is wrong; the
    // loader rejects it rather than silently accepting a short chain.
    let chain = inputs.commitments.get(&b.r.id()).unwrap().clone();
    let mut broken_second = chain[1].clone();
    broken_second.commitment.prev_commitment_hash = Hash::from_bytes([7u8; 32]);
    let broken_second = SignedCommitment::sign(broken_second.commitment, &b.r.key).unwrap();
    write_chain(&b.r.dir, &[chain[0].clone(), broken_second]);
    let err = b.load_raw(std::slice::from_ref(&order)).unwrap_err();
    assert!(
        format!("{err:#}").contains("invalid commitment chain"),
        "unexpected error: {err:#}"
    );
}

// ── 10. Exited network: multiple components (M5 exit rights, P4) ───────────

/// A primary network plus two exited islands, both rebased to root `0`, load
/// and audit independently with no hard error. The islands surface as advisory
/// `Detached` findings and in the component partition.
#[test]
fn islands_both_rooted_at_zero_load_and_audit_independently() {
    let root = tempfile::tempdir().unwrap();

    // Primary R -> A (A holds user uA).
    let r = make_peer_at(
        &root.path().join("r"),
        "R",
        "0",
        None,
        &[("A", ChildKind::Node, 1)],
    );
    let a = make_peer_at(
        &root.path().join("a"),
        "A",
        "0.1",
        Some(("R", 1)),
        &[("uA", ChildKind::User, 0)],
    );
    // Two independent islands, each a root-0 subtree with a stranded claim.
    let x = make_peer_at(
        &root.path().join("x"),
        "X",
        "0",
        None,
        &[("uX", ChildKind::User, 0)],
    );
    let y = make_peer_at(
        &root.path().join("y"),
        "Y",
        "0",
        None,
        &[("uY", ChildKind::User, 0)],
    );

    // Primary is mirror-consistent: R funds A, A descends to uA.
    seed_peer(&r, 1, |ledger, key| {
        open(ledger, key, &n("A"), ChildKind::Node);
        issue(ledger, key, &n("A"), 100);
    });
    seed_peer(&a, 1, |ledger, key| {
        open(ledger, key, &n("uA"), ChildKind::User);
        descend(ledger, key, &n("uA"), 100);
    });
    // Each island descends to its own user without a parent extension, leaving
    // a stranded `Parent` claim.
    seed_peer(&x, 1, |ledger, key| {
        open(ledger, key, &n("uX"), ChildKind::User);
        descend(ledger, key, &n("uX"), 100);
    });
    seed_peer(&y, 1, |ledger, key| {
        open(ledger, key, &n("uY"), ChildKind::User);
        descend(ledger, key, &n("uY"), 50);
    });

    let peers = vec![r.dir.clone(), a.dir.clone(), x.dir.clone(), y.dir.clone()];
    let inputs = netting_harness::load(&peers, None, None, None).unwrap();
    assert_eq!(inputs.components.len(), 3, "primary + two islands");
    assert_eq!(inputs.topology.root_id(), "R");
    assert_eq!(inputs.components[1].topology.root_id(), "X");
    assert_eq!(inputs.components[2].topology.root_id(), "Y");

    let report = netting_harness::report(&inputs);
    assert!(
        report.findings.is_empty(),
        "islands must not be a hard failure: {:?}",
        report.findings
    );
    let detached: Vec<&Finding> = report
        .advisories
        .iter()
        .filter(|f| matches!(f, Finding::Detached { .. }))
        .collect();
    assert_eq!(detached.len(), 2, "advisories: {:?}", report.advisories);
    assert!(report.advisories.iter().all(|f| f.is_advisory()));
    assert_eq!(report.components.len(), 3);
    assert!(report.components[0].primary);
    assert_eq!(report.components[0].root, "R");
    assert!(!report.components[1].primary);
    assert!(report.components[1].nodes.contains(&"X".to_string()));
    assert!(report.components[1].nodes.contains(&"uX".to_string()));
    assert!(report
        .notes
        .iter()
        .any(|note| note.contains("topology components: 3")));
}

/// `load`'s `primary_root` selector: designating a **smaller** component as
/// primary reorders the partition so the report labels it `primary`, and an
/// unknown designated id is a clear load error.
#[test]
fn designated_primary_root_relabels_components() {
    let root = tempfile::tempdir().unwrap();
    let r = make_peer_at(
        &root.path().join("r"),
        "R",
        "0",
        None,
        &[("A", ChildKind::Node, 1)],
    );
    let a = make_peer_at(
        &root.path().join("a"),
        "A",
        "0.1",
        Some(("R", 1)),
        &[],
    );
    let x = make_peer_at(&root.path().join("x"), "X", "0", None, &[]);
    let peers = vec![r.dir.clone(), a.dir.clone(), x.dir.clone()];

    // Default: the larger R/A component leads.
    let default = netting_harness::load(&peers, None, None, None).unwrap();
    let report = netting_harness::report(&default);
    assert_eq!(report.components[0].root, "R");
    assert!(report.components[0].primary);
    assert_eq!(report.components[1].root, "X");
    assert!(!report.components[1].primary);

    // Designating the smaller island promotes it to primary.
    let designated = netting_harness::load(&peers, None, None, Some("X")).unwrap();
    let report = netting_harness::report(&designated);
    assert_eq!(report.components[0].root, "X");
    assert!(report.components[0].primary);
    assert_eq!(report.components[1].root, "R");
    assert!(!report.components[1].primary);
    assert!(
        report.notes.iter().any(|note| note.contains("primary root X")),
        "notes: {:?}",
        report.notes
    );

    // An id that names no peer record is a clear error.
    let err = netting_harness::load(&peers, None, None, Some("nope")).unwrap_err();
    assert!(
        err.to_string().contains("designated primary root 'nope'"),
        "unexpected error: {err:#}"
    );
}

/// A stale parent-side `children` row (the old parent still lists an exited
/// child) is ignored: the child's own parentless link wins and the row is an
/// advisory `StaleChildLink`.
#[test]
fn stale_parent_child_row_is_ignored_with_stale_child_link() {
    let root = tempfile::tempdir().unwrap();

    // R's record still lists X, but X rebased to root 0. A keeps R primary.
    let r = make_peer_at(
        &root.path().join("r"),
        "R",
        "0",
        None,
        &[("A", ChildKind::Node, 2), ("X", ChildKind::Node, 1)],
    );
    let a = make_peer_at(
        &root.path().join("a"),
        "A",
        "0.2",
        Some(("R", 2)),
        &[],
    );
    let x = make_peer_at(
        &root.path().join("x"),
        "X",
        "0",
        None,
        &[("uX", ChildKind::User, 0)],
    );

    let peers = vec![r.dir.clone(), a.dir.clone(), x.dir.clone()];
    let inputs = netting_harness::load(&peers, None, None, None).unwrap();
    assert_eq!(inputs.components.len(), 2, "primary R/A + island X");
    assert_eq!(inputs.topology.root_id(), "R");
    assert_eq!(inputs.components[1].topology.root_id(), "X");
    assert_eq!(inputs.components[1].stranded_parent, Some(n("R")));

    let stale: Vec<&Finding> = inputs
        .topology_findings
        .iter()
        .filter(|f| matches!(f, Finding::StaleChildLink { parent, child } if parent == &n("R") && child == &n("X")))
        .collect();
    assert_eq!(
        stale.len(),
        1,
        "topology findings: {:?}",
        inputs.topology_findings
    );

    let report = netting_harness::report(&inputs);
    assert!(
        report.findings.is_empty(),
        "a stale link must not be a hard finding: {:?}",
        report.findings
    );
    assert!(report
        .advisories
        .iter()
        .any(|f| matches!(f, Finding::StaleChildLink { .. })));
    assert!(report
        .advisories
        .iter()
        .any(|f| matches!(f, Finding::Detached { root, .. } if root == &n("X"))));
}

/// An order whose endpoints span two components has no common root and is an
/// advisory `RouteInvalid`, not a hard failure.
#[test]
fn cross_component_order_is_an_advisory_route_invalid() {
    let root = tempfile::tempdir().unwrap();
    let r = make_peer_at(
        &root.path().join("r"),
        "R",
        "0",
        None,
        &[("A", ChildKind::Node, 1)],
    );
    let a = make_peer_at(
        &root.path().join("a"),
        "A",
        "0.1",
        Some(("R", 1)),
        &[("uA", ChildKind::User, 0)],
    );
    let x = make_peer_at(
        &root.path().join("x"),
        "X",
        "0",
        None,
        &[("uX", ChildKind::User, 0)],
    );

    let order = PaymentOrder {
        from: n("uA"),
        to: n("uX"),
        amount: Amount::new(100),
        nonce: 1,
        expiry: 1_000,
    };
    let path = root.path().join("orders.json");
    std::fs::write(&path, serde_json::to_string(&order).unwrap()).unwrap();

    let peers = vec![r.dir.clone(), a.dir.clone(), x.dir.clone()];
    let inputs = netting_harness::load(&peers, Some(path.to_str().unwrap()), None, None).unwrap();
    let report = netting_harness::report(&inputs);
    assert!(
        report.findings.is_empty(),
        "a cross-component order is advisory: {:?}",
        report.findings
    );
    assert!(report.advisories.iter().any(
        |f| matches!(f, Finding::RouteInvalid { payment_id, .. } if *payment_id == order.hash())
    ));
    assert!(report.nets.is_empty());
}

/// After re-attach, the previously stranded pair is a normal single-root edge
/// and surfaces exactly once as an `UnbackedClaim` mirror mismatch.
#[test]
fn reattached_stranded_pair_surfaces_exactly_once() {
    let root = tempfile::tempdir().unwrap();
    let r = make_peer_at(
        &root.path().join("r"),
        "R",
        "0",
        None,
        &[("A", ChildKind::Node, 1)],
    );
    let a = make_peer_at(
        &root.path().join("a"),
        "A",
        "0.1",
        Some(("R", 1)),
        &[("uA", ChildKind::User, 0)],
    );

    // A exited, kept a 100 Parent claim, then re-attached; R never extended
    // Child(A).
    seed_peer(&a, 1, |ledger, key| {
        open(ledger, key, &n("uA"), ChildKind::User);
        descend(ledger, key, &n("uA"), 100);
    });

    let peers = vec![r.dir.clone(), a.dir.clone()];
    let inputs = netting_harness::load(&peers, None, None, None).unwrap();
    let report = netting_harness::report(&inputs);
    let mismatches: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| matches!(f, Finding::MirrorMismatch { .. }))
        .collect();
    assert_eq!(
        mismatches.len(),
        1,
        "the re-attached stranded pair must surface once: {:?}",
        report.findings
    );
    assert!(matches!(
        mismatches[0],
        Finding::MirrorMismatch {
            direction: MirrorDirection::UnbackedClaim,
            ..
        }
    ));
}

// ── 11. Netting gate: exit advisories don't suppress nets (G1) ─────────────

/// `Detached` and `StaleChildLink` are steady-state exit signals and must not
/// suppress `nets` for the still-healthy components.
#[test]
fn exit_advisories_do_not_suppress_nets() {
    let mut b = Benches::new();
    b.fund_setup(1000);
    let order = order(1);
    b.apply(&order);

    // An extra independent island Y, plus a stale parent-side row for it on R.
    let y = make_peer_at(
        &b.root.path().join("y"),
        "Y",
        "0",
        None,
        &[("uY", ChildKind::User, 0)],
    );
    let mut r_store = record::RecordStore::open(&b.r.dir, &b.r.node_id).unwrap();
    r_store
        .attach_child("Y", ChildKind::Node, Some(0), 0)
        .unwrap();
    r_store.save().unwrap();

    let peers = vec![
        b.r.dir.clone(),
        b.a.dir.clone(),
        b.b.dir.clone(),
        y.dir.clone(),
    ];
    let path = b.orders_path(std::slice::from_ref(&order));
    let inputs = netting_harness::load(&peers, Some(path.to_str().unwrap()), None, None).unwrap();
    let report = netting_harness::report(&inputs);

    assert!(
        report.findings.is_empty(),
        "exit advisories must not be hard findings: {:?}",
        report.findings
    );
    assert!(report
        .advisories
        .iter()
        .any(|f| matches!(f, Finding::Detached { root, .. } if root == &n("Y"))));
    assert!(report
        .advisories
        .iter()
        .any(|f| matches!(f, Finding::StaleChildLink { parent, child } if parent == &b.r.id() && child == &n("Y"))));
    assert_eq!(
        report.nets,
        vec![NetTransfer {
            parent: b.r.id(),
            from: b.a.id(),
            to: b.b.id(),
            amount: Amount::new(100),
        }],
        "an island and a stale link must not suppress the primary's nets"
    );
    // Advisory-only: the CLI exits 0.
    assert!(!(!report.findings.is_empty()));
}

// ── 12. Accepted residual: re-attach with a stranded Parent is hard ───────

/// Pin the accepted residual: a node that exits carrying a non-zero `Parent`
/// balance and then re-joins a **new** parent leaves a hard
/// `MirrorMismatch::UnbackedClaim` on the new edge (exit 1), while the old
/// severed edge is advisory — the orphaned old parent network is one
/// `Detached` island and the stale parent-side row is one `StaleChildLink` —
/// and is never a `MirrorMismatch`.
///
/// This is the operational rule "exit with zero `Parent` for a clean
/// re-attach": until v2 `EdgeClose`, a non-zero stranded claim blocks netting
/// on the new network.
#[test]
fn reattach_with_stranded_parent_blocks_netting_on_new_edge() {
    let root = tempfile::tempdir().unwrap();

    // N is the new parent (root 0); X re-joined it at slot 1.
    let new_parent = make_peer_at(
        &root.path().join("n"),
        "N",
        "0",
        None,
        &[("X", ChildKind::Node, 1)],
    );
    // X carries a 100 Parent claim from its exit and now hangs under N.
    let x = make_peer_at(
        &root.path().join("x"),
        "X",
        "0.1",
        Some(("N", 1)),
        &[("uX", ChildKind::User, 0)],
    );
    // P is the old parent: it still lists X (stale) and has no other links,
    // so its now-independent network is an island.
    let old_parent = make_peer_at(
        &root.path().join("p"),
        "P",
        "0",
        None,
        &[("X", ChildKind::Node, 1)],
    );

    seed_peer(&x, 1, |ledger, key| {
        open(ledger, key, &n("uX"), ChildKind::User);
        descend(ledger, key, &n("uX"), 100);
    });

    let peers = vec![
        old_parent.dir.clone(),
        new_parent.dir.clone(),
        x.dir.clone(),
    ];
    let inputs = netting_harness::load(&peers, None, None, None).unwrap();
    let report = netting_harness::report(&inputs);

    // The new edge N -> X is a hard UnbackedClaim.
    let hard: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| matches!(f, Finding::MirrorMismatch { .. }))
        .collect();
    assert_eq!(
        hard.len(),
        1,
        "exactly one hard mismatch on the new edge: {:?}",
        report.findings
    );
    assert!(matches!(
        hard[0],
        Finding::MirrorMismatch { edge, parent_view, child_view, direction }
            if edge.parent == n("N")
                && edge.child == n("X")
                && *parent_view == Amount::ZERO
                && *child_view == Amount::new(100)
                && *direction == MirrorDirection::UnbackedClaim
    ));

    // The old severed edge P -> X is advisory and never a MirrorMismatch.
    assert!(
        report
            .findings
            .iter()
            .all(|f| !matches!(f, Finding::MirrorMismatch { edge, .. } if edge.parent == n("P"))),
        "the severed old edge must never be a hard MirrorMismatch: {:?}",
        report.findings
    );
    assert!(report.advisories.iter().any(
        |f| matches!(f, Finding::Detached { root, .. } if root == &n("P"))
    ));
    assert!(report.advisories.iter().any(
        |f| matches!(f, Finding::StaleChildLink { parent, child } if parent == &n("P") && child == &n("X"))
    ));
    assert_eq!(
        report
            .advisories
            .iter()
            .filter(|f| matches!(
                f,
                Finding::Detached { .. } | Finding::StaleChildLink { .. }
            ))
            .count(),
        2,
        "the severed pair is reported exactly twice, both advisory: {:?}",
        report.advisories
    );

    // Exit 1 and no netting: a hard finding always blocks.
    assert!(!report.findings.is_empty());
    assert!(report.nets.is_empty());
}

// ── 13. Mixed components plus a hard finding ──────────────────────────────

/// An island (advisory `Detached`) and a genuine hard finding (a mirror
/// mismatch) coexist: both buckets are reported, `nets` is suppressed by the
/// hard finding, and the default CLI exit is 1. The island-only baseline (same
/// fixture, before the tamper) still collapses `nets` and exits 0, pinning that
/// the hard finding — not the island — is what blocks reconciliation.
#[test]
fn mixed_island_and_hard_finding_report_both_and_block_netting() {
    let mut b = Benches::new();
    b.fund_setup(1000);
    let order = order(1);
    b.apply(&order);

    // An independent island Y, plus a stale parent-side row for it on R.
    let y = make_peer_at(
        &b.root.path().join("y"),
        "Y",
        "0",
        None,
        &[("uY", ChildKind::User, 0)],
    );
    let mut r_store = record::RecordStore::open(&b.r.dir, &b.r.node_id).unwrap();
    r_store
        .attach_child("Y", ChildKind::Node, Some(0), 0)
        .unwrap();
    r_store.save().unwrap();

    let peers = vec![
        b.r.dir.clone(),
        b.a.dir.clone(),
        b.b.dir.clone(),
        y.dir.clone(),
    ];
    let path = b.orders_path(std::slice::from_ref(&order));

    // Baseline: advisory island only, no hard finding -> nets collapse, exit 0.
    let clean = netting_harness::load(&peers, Some(path.to_str().unwrap()), None, None).unwrap();
    let clean = netting_harness::report(&clean);
    assert!(
        clean.findings.is_empty(),
        "island-only must have no hard finding: {:?}",
        clean.findings
    );
    assert!(clean
        .advisories
        .iter()
        .any(|f| matches!(f, Finding::Detached { root, .. } if root == &n("Y"))));
    assert!(
        !clean.nets.is_empty(),
        "an island alone must not suppress nets"
    );

    // A genuine hard finding: A descends 50 more to uA without R extending
    // Child(A), so the R -> A edge no longer mirrors.
    let aid = b.a.id();
    let akey = b.a.key.clone();
    descend(b.set.get_mut(&aid).unwrap(), &akey, &n("uA"), 50);
    b.persist_all();

    let inputs = netting_harness::load(&peers, Some(path.to_str().unwrap()), None, None).unwrap();
    let report = netting_harness::report(&inputs);

    // Both buckets are populated and split correctly.
    assert!(
        report.findings.iter().any(|f| matches!(
            f,
            Finding::MirrorMismatch { edge, .. }
                if edge.parent == b.r.id() && edge.child == b.a.id()
        )),
        "expected the hard R -> A mirror mismatch: {:?}",
        report.findings
    );
    assert!(
        report.advisories.iter().any(
            |f| matches!(f, Finding::Detached { root, .. } if root == &n("Y"))
        ),
        "the island must stay advisory: {:?}",
        report.advisories
    );
    assert!(report.advisories.iter().any(
        |f| matches!(f, Finding::StaleChildLink { parent, child } if parent == &b.r.id() && child == &n("Y"))
    ));
    assert!(report.advisories.iter().all(|f| f.is_advisory()));

    // The hard finding suppresses netting and drives the default exit code.
    assert!(
        report.nets.is_empty(),
        "a hard finding must suppress nets even alongside an advisory island"
    );
    assert!(!report.findings.is_empty(), "the default CLI exits 1");
}

