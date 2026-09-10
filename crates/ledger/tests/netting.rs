//! Adversarial netting harness (Phase D).
//!
//! The topology extends the settlement worked example with a third branch so a
//! route can be redirected to a branch the order did not name:
//!
//! ```text
//!             R
//!          /  |  \
//!         A   B   C
//!         |   |   |
//!        L_A L_B L_C
//!       /  \   |   |
//!      uA  uA2 uB  uC
//! ```
//!
//! All ledgers are prefunded and mirror-consistent. Each test introduces one
//! adversary and asserts the corresponding [`Finding`], naming the culprit.

use std::collections::BTreeMap;

use cawala_ledger::{
    AccountRef, Amount, AuthRef, Entry, EntryBody, Finding, Hash, HopRole, Ledger, LedgerLog,
    LedgerSecretKey, LedgerSet, MemLog, NetTransfer, NodeId, OperatorSecretKey, PaymentOrder,
    PeerKeys, PeerRegistry, PeerRole, PlannedHop, Posting, SettlementPlan, SignedAmount,
    SignedCommitment, SignedEntry, build_commitment, execute_plan, net, plan_transfer,
    verify_cascade,
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

fn order(from: &str, to: &str, amount: u64, nonce: u64) -> PaymentOrder {
    PaymentOrder {
        from: n(from),
        to: n(to),
        amount: Amount::new(amount),
        nonce,
        expiry: 1000,
    }
}

fn netting_topology() -> Topology {
    let mut topo = Topology::new_root("R");
    for (id, kind) in [
        ("A", ChildKind::Node),
        ("B", ChildKind::Node),
        ("C", ChildKind::Node),
        ("L_A", ChildKind::Node),
        ("L_B", ChildKind::Node),
        ("L_C", ChildKind::Node),
        ("uA", ChildKind::User),
        ("uA2", ChildKind::User),
        ("uB", ChildKind::User),
        ("uC", ChildKind::User),
    ] {
        topo.add_node(id, kind).unwrap();
    }
    topo.attach("R", "A", Some(0)).unwrap();
    topo.attach("R", "B", Some(1)).unwrap();
    topo.attach("R", "C", Some(2)).unwrap();
    topo.attach("A", "L_A", Some(0)).unwrap();
    topo.attach("B", "L_B", Some(0)).unwrap();
    topo.attach("C", "L_C", Some(0)).unwrap();
    topo.attach("L_A", "uA", Some(0)).unwrap();
    topo.attach("L_A", "uA2", Some(1)).unwrap();
    topo.attach("L_B", "uB", Some(0)).unwrap();
    topo.attach("L_C", "uC", Some(0)).unwrap();
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

/// A fully funded, mirror-consistent three-branch fixture.
struct Fixture {
    topo: Topology,
    set: LedgerSet,
    keys: BTreeMap<NodeId, LedgerSecretKey>,
    registry: PeerRegistry,
}

impl Fixture {
    fn new() -> Self {
        let topo = netting_topology();
        let keys: BTreeMap<NodeId, LedgerSecretKey> = [
            ("R", 101u8),
            ("A", 102),
            ("B", 103),
            ("L_A", 104),
            ("L_B", 105),
            ("C", 106),
            ("L_C", 107),
        ]
        .into_iter()
        .map(|(id, seed)| (n(id), k(seed)))
        .collect();

        let mut set = LedgerSet::new();
        set.insert(n("R"), Ledger::new_root(keys[&n("R")].public()))
            .unwrap();
        for id in ["A", "B", "C", "L_A", "L_B", "L_C"] {
            set.insert(n(id), Ledger::new_non_root(keys[&n(id)].public()))
                .unwrap();
        }

        // Root issues to each branch.
        for child in ["A", "B", "C"] {
            open(
                set.get_mut(&n("R")).unwrap(),
                &keys[&n("R")],
                child,
                ChildKind::Node,
            );
            issue(set.get_mut(&n("R")).unwrap(), &keys[&n("R")], child, 1000);
        }

        // Each branch node descends to its leaf, mirroring the root's issue.
        for (node, leaf) in [("A", "L_A"), ("B", "L_B"), ("C", "L_C")] {
            open(
                set.get_mut(&n(node)).unwrap(),
                &keys[&n(node)],
                leaf,
                ChildKind::Node,
            );
            descend(set.get_mut(&n(node)).unwrap(), &keys[&n(node)], leaf, 1000);
        }

        // Leaves descend to their users.
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
        open(
            set.get_mut(&n("L_C")).unwrap(),
            &keys[&n("L_C")],
            "uC",
            ChildKind::User,
        );
        descend(
            set.get_mut(&n("L_C")).unwrap(),
            &keys[&n("L_C")],
            "uC",
            1000,
        );

        let mut registry = PeerRegistry::new();
        for (id, seed) in [
            ("R", 1u8),
            ("A", 2),
            ("B", 3),
            ("L_A", 4),
            ("L_B", 5),
            ("C", 6),
            ("L_C", 7),
        ] {
            registry
                .insert(PeerKeys {
                    node_id: n(id),
                    operator: op(seed).public(),
                    ledger: Some(keys[&n(id)].public()),
                    role: PeerRole::Node,
                })
                .unwrap();
        }
        for (id, seed) in [("uA", 11u8), ("uA2", 12), ("uB", 13), ("uC", 14)] {
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

    /// Build an unsigned hop for `signer` against its current ledger head.
    fn hop(
        &self,
        signer: &str,
        role: HopRole,
        postings: Vec<Posting>,
        auth: &AuthRef,
    ) -> PlannedHop {
        let ledger = self.set.get(&n(signer)).unwrap();
        PlannedHop {
            signer: n(signer),
            entry: Entry {
                ledger_id: self.keys[&n(signer)].public(),
                seq: ledger.len() as u64,
                height: ledger.len() as u64,
                prev_hash: ledger.head_hash(),
                issued_at: 0,
                body: EntryBody::Transfer {
                    payment_id: auth.order_hash,
                    amount: Amount::new(100),
                    role,
                },
                postings,
                auth: Some(auth.clone()),
            },
        }
    }

    /// Rebuild every ledger from a raw [`MemLog`] (bypassing `append`'s
    /// validation), appending any `extras` addressed to that node. Balances are
    /// not recomputed by `Ledger::new_*_with_log`, so both views of every mirror
    /// read as zero.
    fn with_injected(&self, extras: &BTreeMap<NodeId, Vec<SignedEntry>>) -> LedgerSet {
        let mut set = LedgerSet::new();
        for id in self.set.node_ids() {
            let source = self.set.get(id).unwrap();
            let mut log = MemLog::new();
            for index in 0..source.len() {
                LedgerLog::append(&mut log, source.get(index).unwrap().unwrap()).unwrap();
            }
            if let Some(entries) = extras.get(id) {
                for signed in entries {
                    LedgerLog::append(&mut log, signed.clone()).unwrap();
                }
            }
            let pubkey = self.keys[id].public();
            let ledger = if id.as_str() == self.topo.root_id() {
                Ledger::new_root_with_log(pubkey, log)
            } else {
                Ledger::new_non_root_with_log(pubkey, log)
            };
            set.insert(id.clone(), ledger).unwrap();
        }
        set
    }
}

/// A signed transfer hop with an explicit (possibly substituted) body
/// `payment_id`, leaving `auth` untouched.
fn signed_hop(
    fx: &Fixture,
    signer: &str,
    role: HopRole,
    postings: Vec<Posting>,
    auth: &AuthRef,
    payment_id: Hash,
) -> SignedEntry {
    let ledger = fx.set.get(&n(signer)).unwrap();
    let entry = Entry {
        ledger_id: fx.keys[&n(signer)].public(),
        seq: ledger.len() as u64,
        height: ledger.len() as u64,
        prev_hash: ledger.head_hash(),
        issued_at: 0,
        body: EntryBody::Transfer {
            payment_id,
            amount: Amount::new(100),
            role,
        },
        postings,
        auth: Some(auth.clone()),
    };
    SignedEntry::sign(entry, &fx.keys[&n(signer)]).unwrap()
}

#[test]
fn honest_run_has_no_findings_and_nets_the_edge() {
    let mut fx = Fixture::new();
    let order = order("uA", "uB", 100, 1);
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();
    execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();

    // The cascade rebuilds to exactly the planned hops.
    let cascade = verify_cascade(&fx.topo, &order, &fx.set, &fx.registry).unwrap();
    assert_eq!(cascade.len(), 5);

    let report = net(
        &fx.topo,
        &fx.set,
        &fx.registry,
        std::slice::from_ref(&order),
        &BTreeMap::new(),
    );
    assert!(
        report.findings.is_empty(),
        "honest run must be clean, got {:?}",
        report.findings
    );
    assert_eq!(
        report.nets,
        vec![NetTransfer {
            parent: n("R"),
            from: n("A"),
            to: n("B"),
            amount: Amount::new(100),
        }]
    );
}

#[test]
fn replayed_payment_is_detected() {
    let mut fx = Fixture::new();
    let order = order("uA", "uB", 100, 1);
    let auth = order.authorize(&op(11)).unwrap();

    // Recipient cascade 1: the honest route, crediting uB.
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();
    execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();

    // Recipient cascade 2: the same authorisation (one payment_id, one nonce)
    // is replayed onto a fully-mirrored cascade crediting uC instead. The
    // culprit is the double-spender uA, whose single order funds two payees.
    let second = SettlementPlan {
        order: order.clone(),
        hops: vec![
            fx.hop(
                "L_A",
                HopRole::Ascend,
                vec![p(AccountRef::Parent, -100), p(ca("uA"), -100)],
                &auth,
            ),
            fx.hop(
                "A",
                HopRole::Ascend,
                vec![p(AccountRef::Parent, -100), p(ca("L_A"), -100)],
                &auth,
            ),
            fx.hop(
                "R",
                HopRole::Lca,
                vec![p(ca("A"), -100), p(ca("C"), 100)],
                &auth,
            ),
            fx.hop(
                "C",
                HopRole::Descend,
                vec![p(AccountRef::Parent, 100), p(ca("L_C"), 100)],
                &auth,
            ),
            fx.hop(
                "L_C",
                HopRole::Descend,
                vec![p(AccountRef::Parent, 100), p(ca("uC"), 100)],
                &auth,
            ),
        ],
    };
    execute_plan(&second, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();

    let report = net(
        &fx.topo,
        &fx.set,
        &fx.registry,
        std::slice::from_ref(&order),
        &BTreeMap::new(),
    );
    assert!(
        report.findings.iter().any(|f| matches!(
            f,
            Finding::Replay { payment_id, .. } if *payment_id == order.hash()
        )),
        "culprit uA: expected Replay for its payment, got {:?}",
        report.findings
    );
}

#[test]
fn equivocating_commitments_are_detected() {
    let fx = Fixture::new();
    let height = fx.set.get(&n("R")).unwrap().len() as u64;
    let base = build_commitment(fx.set.get(&n("R")).unwrap(), Hash::ZERO, 1).unwrap();
    let first = SignedCommitment::sign(base.clone(), &fx.keys[&n("R")]).unwrap();

    let mut conflicting = base;
    conflicting.entry_root = Hash::from_bytes([0xAB; 32]);
    conflicting.state_root = Hash::from_bytes([0xCD; 32]);
    let second = SignedCommitment::sign(conflicting, &fx.keys[&n("R")]).unwrap();

    let mut commitments = BTreeMap::new();
    commitments.insert(n("R"), vec![first, second]);
    let report = net(&fx.topo, &fx.set, &fx.registry, &[], &commitments);

    let heads = report.findings.iter().find_map(|f| match f {
        Finding::Fork {
            ledger_id,
            height: h,
            heads,
        } if *ledger_id == fx.keys[&n("R")].public() && *h == height => Some(heads),
        _ => None,
    });
    let heads = heads.expect("culprit R: expected Fork for its ledger");
    assert_eq!(heads.len(), 2, "two distinct conflicting heads");
    assert!(
        report.nets.is_empty(),
        "a reconciliation with findings must not collapse nets"
    );
}

#[test]
fn branch_redirect_is_detected_even_though_every_hop_appends() {
    let mut fx = Fixture::new();
    let order = order("uA", "uB", 100, 1);
    let auth = order.authorize(&op(11)).unwrap();

    // Honest ascending hops, then a tampered LCA that credits branch C instead
    // of B, followed by a fully-mirrored descending cascade into C/uC. The
    // misrouting route node is R. Every entry below satisfies conservation,
    // carries the payer's valid authorisation, and mirrors its edge, so every
    // local `append` succeeds.
    let plan = SettlementPlan {
        order: order.clone(),
        hops: vec![
            fx.hop(
                "L_A",
                HopRole::Ascend,
                vec![p(AccountRef::Parent, -100), p(ca("uA"), -100)],
                &auth,
            ),
            fx.hop(
                "A",
                HopRole::Ascend,
                vec![p(AccountRef::Parent, -100), p(ca("L_A"), -100)],
                &auth,
            ),
            fx.hop(
                "R",
                HopRole::Lca,
                vec![p(ca("A"), -100), p(ca("C"), 100)],
                &auth,
            ),
            fx.hop(
                "C",
                HopRole::Descend,
                vec![p(AccountRef::Parent, 100), p(ca("L_C"), 100)],
                &auth,
            ),
            fx.hop(
                "L_C",
                HopRole::Descend,
                vec![p(AccountRef::Parent, 100), p(ca("uC"), 100)],
                &auth,
            ),
        ],
    };
    execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();

    let report = net(
        &fx.topo,
        &fx.set,
        &fx.registry,
        std::slice::from_ref(&order),
        &BTreeMap::new(),
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|f| matches!(f, Finding::MirrorMismatch { .. })),
        "the redirect must stay fully mirrored, got {:?}",
        report.findings
    );
    assert!(
        report.findings.iter().any(|f| matches!(
            f,
            Finding::RouteInvalid { payment_id, .. } if *payment_id == order.hash()
        )),
        "culprit R: expected RouteInvalid for the redirected payment, got {:?}",
        report.findings
    );
}

#[test]
fn mirror_tamper_is_detected() {
    let mut fx = Fixture::new();

    // A descends to L_A without the matching entry in R: its Parent asset no
    // longer mirrors R's liability. The culprit ledger is A.
    let a_key = fx.keys[&n("A")].clone();
    descend(fx.set.get_mut(&n("A")).unwrap(), &a_key, "L_A", 50);

    let report = net(&fx.topo, &fx.set, &fx.registry, &[], &BTreeMap::new());
    let mismatch = report.findings.iter().find_map(|f| match f {
        Finding::MirrorMismatch {
            edge,
            parent_view,
            child_view,
        } if edge.parent == n("R") && edge.child == n("A") => Some((*parent_view, *child_view)),
        _ => None,
    });
    assert_eq!(
        mismatch,
        Some((Amount::new(1000), Amount::new(1050))),
        "culprit ledger A: R still sees 1000 but A claims 1050"
    );
    assert!(
        report.nets.is_empty(),
        "a reconciliation with findings must not collapse nets"
    );
}

#[test]
fn negative_reconstructed_balance_is_flagged_as_overdraw() {
    // `Balances::apply` rejects negatives at append time, so this variant is
    // unreachable through the honest append path. It protects a committed or
    // restored ledger whose cached balances were not re-validated against its
    // entries, so we inject such a log directly and check the replay.
    let mut topo = Topology::new_root("R");
    topo.add_node("A", ChildKind::Node).unwrap();
    topo.attach("R", "A", Some(0)).unwrap();

    let r_key = k(101);
    let a_key = k(102);
    let mut set = LedgerSet::new();
    set.insert(n("R"), Ledger::new_root(r_key.public()))
        .unwrap();

    let mut log = MemLog::new();
    let entry = Entry {
        ledger_id: a_key.public(),
        seq: 0,
        height: 0,
        prev_hash: Hash::ZERO,
        issued_at: 0,
        body: EntryBody::Transfer {
            payment_id: Hash::ZERO,
            amount: Amount::new(50),
            role: HopRole::Ascend,
        },
        postings: vec![p(AccountRef::Parent, -50), p(ca("x"), -50)],
        auth: Some(dummy_auth()),
    };
    LedgerLog::append(&mut log, SignedEntry::sign(entry, &a_key).unwrap()).unwrap();
    set.insert(n("A"), Ledger::new_non_root_with_log(a_key.public(), log))
        .unwrap();

    let report = net(&topo, &set, &PeerRegistry::new(), &[], &BTreeMap::new());
    let deficit = report.findings.iter().find_map(|f| match f {
        Finding::Overdraw {
            node,
            account,
            deficit,
        } if node == &n("A") && account == &AccountRef::Parent => Some(*deficit),
        _ => None,
    });
    assert_eq!(
        deficit,
        Some(50),
        "culprit ledger A: reconstructed Parent went 50 below zero"
    );
}

#[test]
fn substituted_body_payment_id_is_still_audited_by_authorisation() {
    let mut fx = Fixture::new();
    let order = order("uA", "uB", 100, 1);
    let auth = order.authorize(&op(11)).unwrap();

    // Honest cascade: body `payment_id` == the authorisation hash.
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();
    execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();

    // Replay the *same* authorisation as a second complete cascade whose
    // mutable body `payment_id` was substituted for a different hash. The route
    // is otherwise honest. Selection keyed on the signed authorisation sees 10
    // hops (replay); selection keyed on the body field would see only the
    // honest 5 and report a clean reconciliation. Injected through raw MemLogs
    // so the substituted body bypasses `append`'s conservation invariant.
    let substituted = Hash::from_bytes([0x5A; 32]);
    let mut extras: BTreeMap<NodeId, Vec<SignedEntry>> = BTreeMap::new();
    extras.entry(n("L_A")).or_default().push(signed_hop(
        &fx,
        "L_A",
        HopRole::Ascend,
        vec![p(AccountRef::Parent, -100), p(ca("uA"), -100)],
        &auth,
        substituted,
    ));
    extras.entry(n("A")).or_default().push(signed_hop(
        &fx,
        "A",
        HopRole::Ascend,
        vec![p(AccountRef::Parent, -100), p(ca("L_A"), -100)],
        &auth,
        substituted,
    ));
    extras.entry(n("R")).or_default().push(signed_hop(
        &fx,
        "R",
        HopRole::Lca,
        vec![p(ca("A"), -100), p(ca("B"), 100)],
        &auth,
        substituted,
    ));
    extras.entry(n("B")).or_default().push(signed_hop(
        &fx,
        "B",
        HopRole::Descend,
        vec![p(AccountRef::Parent, 100), p(ca("L_B"), 100)],
        &auth,
        substituted,
    ));
    extras.entry(n("L_B")).or_default().push(signed_hop(
        &fx,
        "L_B",
        HopRole::Descend,
        vec![p(AccountRef::Parent, 100), p(ca("uB"), 100)],
        &auth,
        substituted,
    ));

    let set = fx.with_injected(&extras);
    let report = net(
        &fx.topo,
        &set,
        &fx.registry,
        std::slice::from_ref(&order),
        &BTreeMap::new(),
    );
    assert!(
        report.findings.iter().any(|f| matches!(
            f,
            Finding::Replay { payment_id, .. } if *payment_id == order.hash()
        )),
        "culprit uA: substituted-payment_id replay must be caught by auth, got {:?}",
        report.findings
    );
    assert!(report.nets.is_empty());
}

#[test]
fn forged_operator_cascade_is_not_silently_dropped() {
    let mut fx = Fixture::new();
    let order = order("uA", "uB", 100, 1);
    let auth = order.authorize(&op(11)).unwrap();

    // Honest cascade, authorised by uA's registered operator op(11).
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();
    execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();

    // A second cascade whose `auth.order_hash` equals the order's hash but
    // whose operator is a different key (op(99)): a forged operator. `append`
    // only checks signatures/conservation/shape, so this is locally acceptable
    // even though `verify_transfer` would reject the operator. Selection by
    // `auth.order_hash` alone must surface it; an operator filter would have
    // dropped it and reported a clean run.
    let forged_auth = order.authorize(&op(99)).unwrap();
    let forged = SettlementPlan {
        order: order.clone(),
        hops: vec![
            fx.hop(
                "L_A",
                HopRole::Ascend,
                vec![p(AccountRef::Parent, -100), p(ca("uA"), -100)],
                &forged_auth,
            ),
            fx.hop(
                "A",
                HopRole::Ascend,
                vec![p(AccountRef::Parent, -100), p(ca("L_A"), -100)],
                &forged_auth,
            ),
            fx.hop(
                "R",
                HopRole::Lca,
                vec![p(ca("A"), -100), p(ca("B"), 100)],
                &forged_auth,
            ),
            fx.hop(
                "B",
                HopRole::Descend,
                vec![p(AccountRef::Parent, 100), p(ca("L_B"), 100)],
                &forged_auth,
            ),
            fx.hop(
                "L_B",
                HopRole::Descend,
                vec![p(AccountRef::Parent, 100), p(ca("uB"), 100)],
                &forged_auth,
            ),
        ],
    };
    for hop in &forged.hops {
        let signed = SignedEntry::sign(hop.entry.clone(), &fx.keys[&hop.signer]).unwrap();
        fx.set.get_mut(&hop.signer).unwrap().append(signed).unwrap();
    }

    let report = net(
        &fx.topo,
        &fx.set,
        &fx.registry,
        std::slice::from_ref(&order),
        &BTreeMap::new(),
    );
    assert!(
        report.findings.iter().any(|f| matches!(
            f,
            Finding::Replay { payment_id, .. } | Finding::RouteInvalid { payment_id, .. }
                if *payment_id == order.hash()
        )),
        "culprit op(99): forged-operator cascade must be rejected, not ignored, got {:?}",
        report.findings
    );
    assert!(report.nets.is_empty());
}

#[test]
fn gapped_commitment_chain_is_reported_invalid() {
    let fx = Fixture::new();
    let height = fx.set.get(&n("R")).unwrap().len() as u64;
    let base = build_commitment(fx.set.get(&n("R")).unwrap(), Hash::ZERO, 1).unwrap();
    let first = SignedCommitment::sign(base.clone(), &fx.keys[&n("R")]).unwrap();

    // A later commitment whose `prev_commitment_hash` is ZERO instead of the
    // hash of `first`: the chain is unlinked/gapped.
    let mut second_commitment = base;
    second_commitment.height = height + 1;
    second_commitment.entry_count = height + 1;
    second_commitment.entry_root = Hash::from_bytes([0x11; 32]);
    second_commitment.state_root = Hash::from_bytes([0x22; 32]);
    second_commitment.prev_commitment_hash = Hash::ZERO;
    let second = SignedCommitment::sign(second_commitment, &fx.keys[&n("R")]).unwrap();

    let mut commitments = BTreeMap::new();
    commitments.insert(n("R"), vec![first, second]);
    let report = net(&fx.topo, &fx.set, &fx.registry, &[], &commitments);

    assert!(
        report.findings.iter().any(|f| matches!(
            f,
            Finding::ChainInvalid { node, .. } if node == &n("R")
        )),
        "expected ChainInvalid for R's unlinked chain, got {:?}",
        report.findings
    );
    assert!(report.nets.is_empty());
}
