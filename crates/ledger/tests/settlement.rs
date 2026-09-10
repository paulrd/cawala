//! End-to-end settlement tests over the worked example topology.
//!
//! ```text
//!            R
//!          /   \
//!         A     B
//!         |     |
//!        L_A   L_B
//!       /   \    \
//!     uA    uA2   uB
//! ```
//!
//! A payment `uA -> uB` ascends L_A, A, settles at R, then descends B, L_B.

use std::collections::BTreeMap;

use cawala_ledger::{
    AccountRef, Amount, AuthRef, Balances, Entry, EntryBody, Hash, HopRole, Ledger, LedgerError,
    LedgerSecretKey, LedgerSet, NodeId, OperatorSecretKey, PaymentOrder, PeerKeys, PeerRegistry,
    PeerRole, Posting, SignedAmount, SignedEntry, execute_plan, plan_transfer,
};
use cawala_topology::{ChildKind, Topology};

fn n(id: &str) -> NodeId {
    NodeId::from(id)
}

fn k(seed: u8) -> LedgerSecretKey {
    LedgerSecretKey::from_bytes([seed; 32])
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

fn ca(id: &str) -> AccountRef {
    AccountRef::Child(n(id))
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

fn worked_topology() -> Topology {
    let mut topo = Topology::new_root("R");
    for (id, kind) in [
        ("A", ChildKind::Node),
        ("B", ChildKind::Node),
        ("L_A", ChildKind::Node),
        ("L_B", ChildKind::Node),
        ("uA", ChildKind::User),
        ("uA2", ChildKind::User),
        ("uB", ChildKind::User),
    ] {
        topo.add_node(id, kind).unwrap();
    }
    topo.attach("R", "A", Some(0)).unwrap();
    topo.attach("R", "B", Some(1)).unwrap();
    topo.attach("A", "L_A", Some(0)).unwrap();
    topo.attach("B", "L_B", Some(0)).unwrap();
    topo.attach("L_A", "uA", Some(0)).unwrap();
    topo.attach("L_A", "uA2", Some(1)).unwrap();
    topo.attach("L_B", "uB", Some(0)).unwrap();
    topo
}

fn append(
    ledger: &mut Ledger,
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
    let signed = SignedEntry::sign(entry, key).unwrap();
    ledger.append(signed).unwrap();
}

fn open(ledger: &mut Ledger, key: &LedgerSecretKey, child: &str, kind: ChildKind) {
    append(
        ledger,
        key,
        EntryBody::OpenAccount {
            child: n(child),
            kind,
        },
        vec![],
        None,
    );
}

fn issue(ledger: &mut Ledger, key: &LedgerSecretKey, child: &str, amount: u64) {
    append(
        ledger,
        key,
        EntryBody::Issue {
            account: ca(child),
            amount: Amount::new(amount),
        },
        vec![
            p(ca(child), amount as i64),
            p(AccountRef::Equity, -(amount as i64)),
        ],
        Some(dummy_auth()),
    );
}

fn descend(ledger: &mut Ledger, key: &LedgerSecretKey, child: &str, amount: u64) {
    append(
        ledger,
        key,
        EntryBody::Transfer {
            payment_id: Hash::ZERO,
            amount: Amount::new(amount),
            role: HopRole::Descend,
        },
        vec![
            p(AccountRef::Parent, amount as i64),
            p(ca(child), amount as i64),
        ],
        Some(dummy_auth()),
    );
}

fn direct(ledger: &mut Ledger, key: &LedgerSecretKey, from: &str, to: &str, amount: u64) {
    append(
        ledger,
        key,
        EntryBody::Transfer {
            payment_id: Hash::ZERO,
            amount: Amount::new(amount),
            role: HopRole::Direct,
        },
        vec![p(ca(from), -(amount as i64)), p(ca(to), amount as i64)],
        Some(dummy_auth()),
    );
}

fn snapshot(set: &LedgerSet) -> BTreeMap<NodeId, Balances> {
    set.node_ids()
        .map(|id| (id.clone(), set.get(id).unwrap().balances().clone()))
        .collect()
}

fn transfer_role(entry: &Entry) -> HopRole {
    match &entry.body {
        EntryBody::Transfer { role, .. } => *role,
        other => panic!("expected a transfer body, got {other:?}"),
    }
}

fn equity_sum(set: &LedgerSet) -> i128 {
    set.node_ids()
        .map(|id| set.get(id).unwrap().balances().equity())
        .sum()
}

/// A fully funded worked example: every node ledger plus payer/payee users.
struct Fixture {
    topo: Topology,
    set: LedgerSet,
    keys: BTreeMap<NodeId, LedgerSecretKey>,
    registry: PeerRegistry,
}

impl Fixture {
    fn new() -> Self {
        let topo = worked_topology();
        let keys: BTreeMap<NodeId, LedgerSecretKey> = [
            ("R", 101u8),
            ("A", 102),
            ("B", 103),
            ("L_A", 104),
            ("L_B", 105),
        ]
        .into_iter()
        .map(|(id, seed)| (n(id), k(seed)))
        .collect();

        let mut set = LedgerSet::new();
        set.insert(n("R"), Ledger::new_root(keys[&n("R")].public()))
            .unwrap();
        for id in ["A", "B", "L_A", "L_B"] {
            set.insert(n(id), Ledger::new_non_root(keys[&n(id)].public()))
                .unwrap();
        }

        // Root issues to each branch.
        open(
            set.get_mut(&n("R")).unwrap(),
            &keys[&n("R")],
            "A",
            ChildKind::Node,
        );
        open(
            set.get_mut(&n("R")).unwrap(),
            &keys[&n("R")],
            "B",
            ChildKind::Node,
        );
        issue(set.get_mut(&n("R")).unwrap(), &keys[&n("R")], "A", 1000);
        issue(set.get_mut(&n("R")).unwrap(), &keys[&n("R")], "B", 1000);

        // A and B descend to their leaves (mirroring the root's liabilities).
        open(
            set.get_mut(&n("A")).unwrap(),
            &keys[&n("A")],
            "L_A",
            ChildKind::Node,
        );
        descend(set.get_mut(&n("A")).unwrap(), &keys[&n("A")], "L_A", 1000);
        open(
            set.get_mut(&n("B")).unwrap(),
            &keys[&n("B")],
            "L_B",
            ChildKind::Node,
        );
        descend(set.get_mut(&n("B")).unwrap(), &keys[&n("B")], "L_B", 1000);

        // Leaves descend to users.
        open(
            set.get_mut(&n("L_A")).unwrap(),
            &keys[&n("L_A")],
            "uA",
            ChildKind::User,
        );
        open(
            set.get_mut(&n("L_A")).unwrap(),
            &keys[&n("L_A")],
            "uA2",
            ChildKind::User,
        );
        descend(
            set.get_mut(&n("L_A")).unwrap(),
            &keys[&n("L_A")],
            "uA",
            1000,
        );
        open(
            set.get_mut(&n("L_B")).unwrap(),
            &keys[&n("L_B")],
            "uB",
            ChildKind::User,
        );
        descend(
            set.get_mut(&n("L_B")).unwrap(),
            &keys[&n("L_B")],
            "uB",
            1000,
        );

        let mut registry = PeerRegistry::new();
        for (id, seed) in [("R", 1u8), ("A", 2), ("B", 3), ("L_A", 4), ("L_B", 5)] {
            registry
                .insert(PeerKeys {
                    node_id: n(id),
                    operator: op(seed).public(),
                    ledger: Some(keys[&n(id)].public()),
                    role: PeerRole::Node,
                })
                .unwrap();
        }
        for (id, seed) in [("uA", 11u8), ("uA2", 12), ("uB", 13)] {
            registry
                .insert(PeerKeys {
                    node_id: n(id),
                    operator: op(seed).public(),
                    ledger: None,
                    role: PeerRole::User,
                })
                .unwrap();
        }

        Fixture {
            topo,
            set,
            keys,
            registry,
        }
    }
}

#[test]
fn ledger_set_insert_and_lookup() {
    let mut set = LedgerSet::new();
    set.insert(n("R"), Ledger::new_root(k(1).public())).unwrap();
    assert!(set.contains(&n("R")));
    assert!(set.get(&n("R")).is_some());
    assert!(set.get_mut(&n("R")).is_some());
    assert_eq!(set.node_ids().cloned().collect::<Vec<_>>(), vec![n("R")]);
    assert_eq!(
        set.insert(n("R"), Ledger::new_root(k(1).public())),
        Err(LedgerError::DuplicatePeer)
    );
}

#[test]
fn cross_subtree_plan_and_execute() {
    let mut fx = Fixture::new();
    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(100),
        nonce: 1,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();

    // Hop table: signer / role.
    let table: Vec<(&str, HopRole)> = plan
        .hops
        .iter()
        .map(|hop| (hop.signer.as_str(), transfer_role(&hop.entry)))
        .collect();
    assert_eq!(
        table,
        vec![
            ("L_A", HopRole::Ascend),
            ("A", HopRole::Ascend),
            ("R", HopRole::Lca),
            ("B", HopRole::Descend),
            ("L_B", HopRole::Descend),
        ]
    );

    // Posting shapes.
    assert_eq!(
        plan.hops[0].entry.postings,
        vec![p(AccountRef::Parent, -100), p(ca("uA"), -100)]
    );
    assert_eq!(
        plan.hops[1].entry.postings,
        vec![p(AccountRef::Parent, -100), p(ca("L_A"), -100)]
    );
    assert_eq!(
        plan.hops[2].entry.postings,
        vec![p(ca("A"), -100), p(ca("B"), 100)]
    );
    assert_eq!(
        plan.hops[3].entry.postings,
        vec![p(AccountRef::Parent, 100), p(ca("L_B"), 100)]
    );
    assert_eq!(
        plan.hops[4].entry.postings,
        vec![p(AccountRef::Parent, 100), p(ca("uB"), 100)]
    );

    // Each hop carries the payer's authorisation and the order's payment id.
    for hop in &plan.hops {
        assert_eq!(hop.entry.auth.as_ref(), Some(&auth));
        if let EntryBody::Transfer { payment_id, .. } = &hop.entry.body {
            assert_eq!(*payment_id, order.hash());
        }
    }

    let equity_before = equity_sum(&fx.set);
    let executed = execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();
    assert_eq!(executed.len(), 5);

    // Balances after the cascade.
    assert_eq!(
        fx.set
            .get(&n("L_A"))
            .unwrap()
            .balances()
            .child_balance(&n("uA")),
        Amount::new(900)
    );
    assert_eq!(
        fx.set.get(&n("L_A")).unwrap().balances().parent_balance(),
        Some(Amount::new(900))
    );
    assert_eq!(
        fx.set.get(&n("A")).unwrap().balances().parent_balance(),
        Some(Amount::new(900))
    );
    assert_eq!(
        fx.set
            .get(&n("A"))
            .unwrap()
            .balances()
            .child_balance(&n("L_A")),
        Amount::new(900)
    );
    assert_eq!(
        fx.set
            .get(&n("R"))
            .unwrap()
            .balances()
            .child_balance(&n("A")),
        Amount::new(900)
    );
    assert_eq!(
        fx.set
            .get(&n("R"))
            .unwrap()
            .balances()
            .child_balance(&n("B")),
        Amount::new(1100)
    );
    assert_eq!(
        fx.set.get(&n("B")).unwrap().balances().parent_balance(),
        Some(Amount::new(1100))
    );
    assert_eq!(
        fx.set
            .get(&n("B"))
            .unwrap()
            .balances()
            .child_balance(&n("L_B")),
        Amount::new(1100)
    );
    assert_eq!(
        fx.set.get(&n("L_B")).unwrap().balances().parent_balance(),
        Some(Amount::new(1100))
    );
    assert_eq!(
        fx.set
            .get(&n("L_B"))
            .unwrap()
            .balances()
            .child_balance(&n("uB")),
        Amount::new(1100)
    );

    // Every parent/child edge mirror holds.
    for (parent, child) in [("R", "A"), ("R", "B"), ("A", "L_A"), ("B", "L_B")] {
        assert_eq!(
            fx.set
                .get(&n(parent))
                .unwrap()
                .balances()
                .child_balance(&n(child)),
            fx.set
                .get(&n(child))
                .unwrap()
                .balances()
                .parent_balance()
                .unwrap(),
            "mirror {parent}->{child}"
        );
    }

    // Transfers conserve: total equity is unchanged.
    assert_eq!(equity_sum(&fx.set), equity_before);
}

#[test]
fn same_leaf_plan_is_a_single_direct_hop() {
    let mut fx = Fixture::new();
    let order = PaymentOrder {
        from: n("uA"),
        to: n("uA2"),
        amount: Amount::new(100),
        nonce: 2,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();

    assert_eq!(plan.hops.len(), 1);
    assert_eq!(plan.hops[0].signer, n("L_A"));
    assert_eq!(transfer_role(&plan.hops[0].entry), HopRole::Direct);
    assert_eq!(
        plan.hops[0].entry.postings,
        vec![p(ca("uA"), -100), p(ca("uA2"), 100)]
    );

    execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();
    assert_eq!(
        fx.set
            .get(&n("L_A"))
            .unwrap()
            .balances()
            .child_balance(&n("uA")),
        Amount::new(900)
    );
    assert_eq!(
        fx.set
            .get(&n("L_A"))
            .unwrap()
            .balances()
            .child_balance(&n("uA2")),
        Amount::new(100)
    );
}

#[test]
fn plan_rejects_payer_overdraw() {
    let fx = Fixture::new();
    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(2000),
        nonce: 3,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    assert_eq!(
        plan_transfer(&fx.topo, &order, &auth, &fx.set, 42),
        Err(LedgerError::InsufficientBalance)
    );
}

#[test]
fn plan_rejects_ascending_parent_overdraw() {
    let topo = worked_topology();
    let mut set = LedgerSet::new();
    // L_A has a funded payer account but no Parent funding.
    set.insert(n("L_A"), Ledger::new_non_root(k(104).public()))
        .unwrap();
    let l_a = set.get_mut(&n("L_A")).unwrap();
    open(l_a, &k(104), "uA", ChildKind::User);
    issue(l_a, &k(104), "uA", 2000);
    assert_eq!(
        set.get(&n("L_A")).unwrap().balances().parent_balance(),
        Some(Amount::ZERO)
    );

    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(1500),
        nonce: 4,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    assert_eq!(
        plan_transfer(&topo, &order, &auth, &set, 42),
        Err(LedgerError::InsufficientBalance)
    );
}

#[test]
fn plan_rejects_lca_branch_overdraw() {
    let topo = worked_topology();
    let mut set = LedgerSet::new();
    set.insert(n("L_A"), Ledger::new_non_root(k(104).public()))
        .unwrap();
    set.insert(n("A"), Ledger::new_non_root(k(102).public()))
        .unwrap();
    set.insert(n("R"), Ledger::new_root(k(101).public()))
        .unwrap();

    {
        let l_a = set.get_mut(&n("L_A")).unwrap();
        open(l_a, &k(104), "uA", ChildKind::User);
        issue(l_a, &k(104), "uA", 1000);
        descend(l_a, &k(104), "uA", 1000);
    }
    {
        let a = set.get_mut(&n("A")).unwrap();
        open(a, &k(102), "L_A", ChildKind::Node);
        descend(a, &k(102), "L_A", 1000);
    }
    // The root holds no balance for A, so the LCA branch is unfunded.
    open(set.get_mut(&n("R")).unwrap(), &k(101), "A", ChildKind::Node);

    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(500),
        nonce: 5,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    assert_eq!(
        plan_transfer(&topo, &order, &auth, &set, 42),
        Err(LedgerError::InsufficientBalance)
    );
}

#[test]
fn plan_rejects_non_user_endpoint() {
    let fx = Fixture::new();
    let order = PaymentOrder {
        from: n("A"),
        to: n("uB"),
        amount: Amount::new(10),
        nonce: 6,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    assert_eq!(
        plan_transfer(&fx.topo, &order, &auth, &fx.set, 42),
        Err(LedgerError::UnsupportedEndpoint)
    );
}

#[test]
fn execute_plan_rejects_unregistered_signer() {
    let mut fx = Fixture::new();
    let mut registry = PeerRegistry::new();
    // All nodes except L_A (whose ledger signs the first hop).
    for (id, seed) in [("R", 1u8), ("A", 2), ("B", 3), ("L_B", 5)] {
        registry
            .insert(PeerKeys {
                node_id: n(id),
                operator: op(seed).public(),
                ledger: Some(fx.keys[&n(id)].public()),
                role: PeerRole::Node,
            })
            .unwrap();
    }
    for (id, seed) in [("uA", 11u8), ("uA2", 12), ("uB", 13)] {
        registry
            .insert(PeerKeys {
                node_id: n(id),
                operator: op(seed).public(),
                ledger: None,
                role: PeerRole::User,
            })
            .unwrap();
    }

    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(100),
        nonce: 7,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();

    assert_eq!(
        execute_plan(&plan, &mut fx.set, &fx.keys, &registry, 50),
        Err(LedgerError::Unauthorized)
    );
}

#[test]
fn execute_plan_rejects_missing_signing_key() {
    let mut fx = Fixture::new();
    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(100),
        nonce: 8,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();

    let mut keys = fx.keys.clone();
    keys.remove(&n("B"));
    assert_eq!(
        execute_plan(&plan, &mut fx.set, &keys, &fx.registry, 50),
        Err(LedgerError::MissingLedger { node: n("B") })
    );
}

#[test]
fn plan_rejects_unopened_credit_account() {
    let topo = worked_topology();
    let mut set = LedgerSet::new();
    set.insert(n("L_A"), Ledger::new_non_root(k(104).public()))
        .unwrap();
    set.insert(n("A"), Ledger::new_non_root(k(102).public()))
        .unwrap();
    set.insert(n("R"), Ledger::new_root(k(101).public()))
        .unwrap();

    {
        let l_a = set.get_mut(&n("L_A")).unwrap();
        open(l_a, &k(104), "uA", ChildKind::User);
        issue(l_a, &k(104), "uA", 1000);
        descend(l_a, &k(104), "uA", 1000);
    }
    {
        let a = set.get_mut(&n("A")).unwrap();
        open(a, &k(102), "L_A", ChildKind::Node);
        descend(a, &k(102), "L_A", 1000);
    }
    {
        let r = set.get_mut(&n("R")).unwrap();
        open(r, &k(101), "A", ChildKind::Node);
        issue(r, &k(101), "A", 1000);
        // Child(B) is deliberately never opened.
    }

    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(500),
        nonce: 10,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    assert_eq!(
        plan_transfer(&topo, &order, &auth, &set, 42),
        Err(LedgerError::AccountNotOpened { account: ca("B") })
    );
}

#[test]
fn plan_rejects_ascending_child_overdraw() {
    let topo = worked_topology();
    let mut set = LedgerSet::new();
    set.insert(n("L_A"), Ledger::new_non_root(k(104).public()))
        .unwrap();
    set.insert(n("A"), Ledger::new_non_root(k(102).public()))
        .unwrap();
    set.insert(n("R"), Ledger::new_root(k(101).public()))
        .unwrap();

    {
        let l_a = set.get_mut(&n("L_A")).unwrap();
        open(l_a, &k(104), "uA", ChildKind::User);
        issue(l_a, &k(104), "uA", 1000);
        descend(l_a, &k(104), "uA", 1000);
    }
    {
        let a = set.get_mut(&n("A")).unwrap();
        open(a, &k(102), "L_A", ChildKind::Node);
        descend(a, &k(102), "L_A", 1000);
        open(a, &k(102), "L_X", ChildKind::Node);
        // Drain A's liability to L_A while keeping A's Parent asset high.
        direct(a, &k(102), "L_A", "L_X", 900);
    }
    {
        let r = set.get_mut(&n("R")).unwrap();
        open(r, &k(101), "A", ChildKind::Node);
        issue(r, &k(101), "A", 1000);
    }

    assert_eq!(
        set.get(&n("A")).unwrap().balances().parent_balance(),
        Some(Amount::new(1000))
    );
    assert_eq!(
        set.get(&n("A"))
            .unwrap()
            .balances()
            .child_balance(&n("L_A")),
        Amount::new(100)
    );

    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(500),
        nonce: 11,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    assert_eq!(
        plan_transfer(&topo, &order, &auth, &set, 42),
        Err(LedgerError::InsufficientBalance)
    );
}

#[test]
fn execute_plan_is_atomic_on_missing_key() {
    let mut fx = Fixture::new();
    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(100),
        nonce: 12,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();

    let before = snapshot(&fx.set);
    let mut keys = fx.keys.clone();
    keys.remove(&n("B"));
    assert_eq!(
        execute_plan(&plan, &mut fx.set, &keys, &fx.registry, 50),
        Err(LedgerError::MissingLedger { node: n("B") })
    );
    assert_eq!(snapshot(&fx.set), before);
}

#[test]
fn execute_plan_is_atomic_on_missing_ledger() {
    let fx = Fixture::new();
    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(100),
        nonce: 13,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();

    // A ledger set missing B's ledger.
    let mut partial = LedgerSet::new();
    for id in fx.set.node_ids() {
        if id != &n("B") {
            partial
                .insert(id.clone(), fx.set.get(id).unwrap().clone())
                .unwrap();
        }
    }
    let before = snapshot(&partial);
    assert_eq!(
        execute_plan(&plan, &mut partial, &fx.keys, &fx.registry, 50),
        Err(LedgerError::MissingLedger { node: n("B") })
    );
    assert_eq!(snapshot(&partial), before);
}

#[test]
fn execute_plan_is_atomic_on_verification_failure() {
    let mut fx = Fixture::new();
    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(100),
        nonce: 14,
        expiry: 1000,
    };
    // Authorised by an operator that is not the payer's registered operator.
    let auth = order.authorize(&op(99)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();

    let before = snapshot(&fx.set);
    assert_eq!(
        execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50),
        Err(LedgerError::Unauthorized)
    );
    assert_eq!(snapshot(&fx.set), before);
}

#[test]
fn execute_plan_is_atomic_on_stale_plan() {
    let mut fx = Fixture::new();
    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(100),
        nonce: 15,
        expiry: 1000,
    };
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();

    // Advance the first signer's ledger, invalidating the plan's seq/prev.
    open(
        fx.set.get_mut(&n("L_A")).unwrap(),
        &fx.keys[&n("L_A")],
        "z",
        ChildKind::User,
    );

    let before = snapshot(&fx.set);
    assert!(matches!(
        execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50),
        Err(LedgerError::SeqOutOfOrder { .. })
    ));
    assert_eq!(snapshot(&fx.set), before);
}
