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
    AccountRef, Amount, AuthRef, EdgeAccount, Entry, EntryBody, Finding, Hash, HopRole, Ledger,
    LedgerLog, LedgerSecretKey, LedgerSet, MemLog, MirrorDirection, NetComponent, NetTransfer,
    NodeId, OperatorSecretKey, PaymentOrder, PeerKeys, PeerRegistry, PeerRole, PlannedHop, Posting,
    SettlementPlan, SignedAmount, SignedCommitment, SignedEntry, build_commitment, entry_hop_accounts,
    execute_plan, net, net_partition, plan_transfer, verify_cascade,
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
            child: n(child),
            amount: Amount::new(amount),
        },
        vec![p(ca(child), amount as i64)],
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
            direction,
        } if edge.parent == n("R") && edge.child == n("A") => {
            Some((*parent_view, *child_view, *direction))
        }
        _ => None,
    });
    assert_eq!(
        mismatch,
        Some((
            Amount::new(1000),
            Amount::new(1050),
            MirrorDirection::UnbackedClaim,
        )),
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

/// `EdgeClose` is a `Parent` boundary op, not a `Transfer`, so the
/// `EntryBody::Transfer`-filtered route/replay audit must ignore it even when
/// it carries the order's authorisation hash.
#[test]
fn verify_cascade_ignores_edge_close_entries() {
    let mut fx = Fixture::new();
    let order = order("uA", "uB", 100, 1);
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();
    execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();

    // An `EdgeClose` on a parented ledger whose `auth.order_hash` equals the
    // order hash. If the audit did not filter to `Transfer`, this would be
    // selected as an extra hop and rejected by `verify_transfer`.
    let l_a_key = fx.keys[&n("L_A")].clone();
    let edge_auth = AuthRef {
        operator: op(11).public(),
        nonce: order.nonce,
        order_hash: order.hash(),
        signature: op(11).sign(order.hash().as_bytes()),
    };
    append(
        fx.set.get_mut(&n("L_A")).unwrap(),
        &l_a_key,
        EntryBody::EdgeClose {
            amount: Amount::new(10),
        },
        vec![p(AccountRef::Parent, -10)],
        Some(edge_auth),
    );

    let cascade = verify_cascade(&fx.topo, &order, &fx.set, &fx.registry).unwrap();
    assert_eq!(cascade.len(), 5, "the EdgeClose entry must not be a hop");

    let report = net(
        &fx.topo,
        &fx.set,
        &fx.registry,
        std::slice::from_ref(&order),
        &BTreeMap::new(),
    );
    assert!(
        !report.findings.iter().any(|f| matches!(
            f,
            Finding::RouteInvalid { payment_id, .. } | Finding::Replay { payment_id, .. }
                if *payment_id == order.hash()
        )),
        "an EdgeClose must not be a route/replay finding, got {:?}",
        report.findings
    );
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

/// A re-attached child with a stranded `Parent` claim (`Parent > 0`) whose new
/// parent never credited `Child(child)` (`Child == 0`) is a documented
/// [`Finding::MirrorMismatch`]: settling the stranded claim is the M5
/// "exit rights" obligation. Netting logic is unchanged; this pins the expected
/// detection so the obligation is not silently lost.
#[test]
fn stranded_parent_on_reattach_is_a_mirror_mismatch() {
    let mut topo = Topology::new_root("R");
    topo.add_node("A", ChildKind::Node).unwrap();
    topo.attach("R", "A", Some(0)).unwrap();

    let r_key = k(101);
    let a_key = k(102);
    let mut set = LedgerSet::new();
    set.insert(n("R"), Ledger::new_root(r_key.public())).unwrap();
    set.insert(n("A"), Ledger::new_non_root(a_key.public()))
        .unwrap();

    // A was attached and prefunded a child (Parent 100), then detached and was
    // re-attached under R; R never issued or descended to A.
    open(
        set.get_mut(&n("A")).unwrap(),
        &a_key,
        "uA",
        ChildKind::User,
    );
    descend(set.get_mut(&n("A")).unwrap(), &a_key, "uA", 100);
    assert_eq!(
        set.get(&n("A")).unwrap().balances().parent_balance(),
        Some(Amount::new(100))
    );
    assert_eq!(
        set.get(&n("R")).unwrap().balances().child_balance(&n("A")),
        Amount::ZERO
    );

    let report = net(&topo, &set, &PeerRegistry::new(), &[], &BTreeMap::new());
    assert_eq!(
        report.findings,
        vec![Finding::MirrorMismatch {
            edge: EdgeAccount {
                parent: n("R"),
                child: n("A"),
            },
            parent_view: Amount::ZERO,
            child_view: Amount::new(100),
            direction: MirrorDirection::UnbackedClaim,
        }],
        "expected the stranded Parent claim to surface as MirrorMismatch"
    );
    assert!(report.nets.is_empty());
}

/// A child that descends value to its own subtree without its parent ever
/// extending the edge has `Parent > 0` while the parent's `Child == 0`: a
/// `MirrorMismatch`. Local issuance is externally backed, but it is not a
/// cross-subtree prefund.
#[test]
fn descend_without_parent_extension_is_mirror_mismatch() {
    let mut topo = Topology::new_root("R");
    topo.add_node("A", ChildKind::Node).unwrap();
    topo.add_node("uA", ChildKind::User).unwrap();
    topo.attach("R", "A", Some(0)).unwrap();
    topo.attach("A", "uA", Some(0)).unwrap();

    let r_key = k(101);
    let a_key = k(102);
    let mut set = LedgerSet::new();
    set.insert(n("R"), Ledger::new_root(r_key.public())).unwrap();
    set.insert(n("A"), Ledger::new_non_root(a_key.public()))
        .unwrap();

    open(
        set.get_mut(&n("A")).unwrap(),
        &a_key,
        "uA",
        ChildKind::User,
    );
    descend(set.get_mut(&n("A")).unwrap(), &a_key, "uA", 100);

    let report = net(&topo, &set, &PeerRegistry::new(), &[], &BTreeMap::new());
    assert!(
        report.findings.iter().any(|f| matches!(
            f,
            Finding::MirrorMismatch { edge, parent_view, child_view, direction }
                if edge.parent == n("R")
                    && edge.child == n("A")
                    && *parent_view == Amount::ZERO
                    && *child_view == Amount::new(100)
                    && *direction == MirrorDirection::UnbackedClaim
        )),
        "expected an unbacked-claim MirrorMismatch for the un-extended R->A edge, got {:?}",
        report.findings
    );
}

/// The opposite direction: the parent has extended `Child(node)` but the child
/// has not mirrored it yet (`parent_view > child_view`). This is a **transient
/// pending handoff**, not an unbacked claim.
#[test]
fn unmirrored_extension_is_mirror_mismatch() {
    let mut topo = Topology::new_root("R");
    topo.add_node("A", ChildKind::Node).unwrap();
    topo.attach("R", "A", Some(0)).unwrap();

    let r_key = k(101);
    let a_key = k(102);
    let mut set = LedgerSet::new();
    set.insert(n("R"), Ledger::new_root(r_key.public()))
        .unwrap();
    set.insert(n("A"), Ledger::new_non_root(a_key.public()))
        .unwrap();

    // R opens and issues to Child(A): R's liability exists, but A has not yet
    // recorded the mirroring `Parent` asset.
    open(set.get_mut(&n("R")).unwrap(), &r_key, "A", ChildKind::Node);
    issue(set.get_mut(&n("R")).unwrap(), &r_key, "A", 100);
    assert_eq!(
        set.get(&n("R")).unwrap().balances().child_balance(&n("A")),
        Amount::new(100)
    );
    assert_eq!(
        set.get(&n("A")).unwrap().balances().parent_balance(),
        Some(Amount::ZERO)
    );

    let report = net(&topo, &set, &PeerRegistry::new(), &[], &BTreeMap::new());
    assert_eq!(
        report.findings,
        vec![Finding::MirrorMismatch {
            edge: EdgeAccount {
                parent: n("R"),
                child: n("A"),
            },
            parent_view: Amount::new(100),
            child_view: Amount::ZERO,
            direction: MirrorDirection::UnmirroredExtension,
        }],
        "expected the un-mirrored extension to surface as an UnmirroredExtension"
    );
    assert!(report.nets.is_empty());
}

/// A local `Issue` (boundary op on a child liability) is externally backed and
/// is not an anomaly by itself: it does not touch `Parent`, so every topology
/// edge mirror still holds.
#[test]
fn local_issue_yields_no_finding() {
    let mut topo = Topology::new_root("R");
    topo.add_node("A", ChildKind::Node).unwrap();
    topo.add_node("uA", ChildKind::User).unwrap();
    topo.attach("R", "A", Some(0)).unwrap();
    topo.attach("A", "uA", Some(0)).unwrap();

    let r_key = k(101);
    let a_key = k(102);
    let mut set = LedgerSet::new();
    set.insert(n("R"), Ledger::new_root(r_key.public())).unwrap();
    set.insert(n("A"), Ledger::new_non_root(a_key.public()))
        .unwrap();

    open(
        set.get_mut(&n("A")).unwrap(),
        &a_key,
        "uA",
        ChildKind::User,
    );
    issue(set.get_mut(&n("A")).unwrap(), &a_key, "uA", 50);

    let report = net(&topo, &set, &PeerRegistry::new(), &[], &BTreeMap::new());
    assert!(
        report.findings.is_empty(),
        "a local issue is not an anomaly: {:?}",
        report.findings
    );
    assert!(report.nets.is_empty());
}

/// Accepted residual: a still-attached child can hard-dirty its `(parent, child)`
/// mirror with an `EdgeClose` (or, equivalently, the pre-existing
/// `Issue` + `Ascend` path): the parent still holds `Child(A) = 100` while the
/// child's `Parent` asset has been reduced, so the edge reads as an
/// `UnmirroredExtension`. Neither path is a `Transfer`, so `append` accepts both
/// without any route/order verification. The capability already existed; mining
/// both end states proves `EdgeClose` adds legibility, not a new capability.
#[test]
fn attached_unilateral_write_off_is_an_unmirrored_extension() {
    // R -> A mirror: R holds Child(A) = 100 and A holds Parent = 100 (descended
    // to its user uA).
    fn fixture() -> (Topology, LedgerSet, LedgerSecretKey) {
        let mut topo = Topology::new_root("R");
        topo.add_node("A", ChildKind::Node).unwrap();
        topo.add_node("uA", ChildKind::User).unwrap();
        topo.attach("R", "A", Some(0)).unwrap();
        topo.attach("A", "uA", Some(0)).unwrap();

        let r_key = k(101);
        let a_key = k(102);
        let mut set = LedgerSet::new();
        set.insert(n("R"), Ledger::new_root(r_key.public())).unwrap();
        set.insert(n("A"), Ledger::new_non_root(a_key.public()))
            .unwrap();

        open(set.get_mut(&n("R")).unwrap(), &r_key, "A", ChildKind::Node);
        issue(set.get_mut(&n("R")).unwrap(), &r_key, "A", 100);
        open(
            set.get_mut(&n("A")).unwrap(),
            &a_key,
            "uA",
            ChildKind::User,
        );
        descend(set.get_mut(&n("A")).unwrap(), &a_key, "uA", 100);
        (topo, set, a_key)
    }

    fn mismatch(report: &cawala_ledger::NettingReport) -> Option<(Amount, Amount, MirrorDirection)> {
        report.findings.iter().find_map(|f| match f {
            Finding::MirrorMismatch {
                edge,
                parent_view,
                child_view,
                direction,
            } if edge.parent == n("R") && edge.child == n("A") => {
                Some((*parent_view, *child_view, *direction))
            }
            _ => None,
        })
    }

    // An `EdgeClose` write-off on the still-attached child.
    let (topo, mut set, a_key) = fixture();
    append(
        set.get_mut(&n("A")).unwrap(),
        &a_key,
        EntryBody::EdgeClose {
            amount: Amount::new(40),
        },
        vec![p(AccountRef::Parent, -40)],
        Some(dummy_auth()),
    );
    let report = net(&topo, &set, &PeerRegistry::new(), &[], &BTreeMap::new());
    assert_eq!(
        mismatch(&report),
        Some((
            Amount::new(100),
            Amount::new(60),
            MirrorDirection::UnmirroredExtension,
        )),
        "EdgeClose write-off: {:?}",
        report.findings
    );

    // The same end state via the pre-existing `Issue` + `Ascend` path.
    let (topo, mut set, a_key) = fixture();
    issue(set.get_mut(&n("A")).unwrap(), &a_key, "uA", 40);
    append(
        set.get_mut(&n("A")).unwrap(),
        &a_key,
        EntryBody::Transfer {
            payment_id: Hash::ZERO,
            amount: Amount::new(40),
            role: HopRole::Ascend,
        },
        vec![p(AccountRef::Parent, -40), p(ca("uA"), -40)],
        Some(dummy_auth()),
    );
    let report = net(&topo, &set, &PeerRegistry::new(), &[], &BTreeMap::new());
    assert_eq!(
        mismatch(&report),
        Some((
            Amount::new(100),
            Amount::new(60),
            MirrorDirection::UnmirroredExtension,
        )),
        "Issue+Ascend: {:?}",
        report.findings
    );
}

/// `entry_hop_accounts` is exported and enforces the role-canonical posting
/// shape (used by the node's carried-prefix hardening): `Ascend`/`Descend` name
/// `Parent` plus exactly one child; `Lca`/`Direct` name exactly one debited and
/// one credited child with no `Parent` leg.
#[test]
fn entry_hop_accounts_is_exported_and_enforces_canonical_shape() {
    let entry = |role: HopRole, postings: Vec<Posting>| Entry {
        ledger_id: k(1).public(),
        seq: 0,
        height: 0,
        prev_hash: Hash::ZERO,
        issued_at: 0,
        body: EntryBody::Transfer {
            payment_id: Hash::ZERO,
            amount: Amount::new(10),
            role,
        },
        postings,
        auth: Some(dummy_auth()),
    };

    // Canonical Ascend: `Parent` + one child.
    let ascend = entry(
        HopRole::Ascend,
        vec![p(AccountRef::Parent, -10), p(ca("x"), -10)],
    );
    assert_eq!(
        entry_hop_accounts(&ascend, HopRole::Ascend).unwrap(),
        (AccountRef::Parent, ca("x"))
    );

    // Canonical Lca/Direct: one debit + one credit, no `Parent` leg.
    let direct = entry(
        HopRole::Direct,
        vec![p(ca("x"), -10), p(ca("y"), 10)],
    );
    assert_eq!(
        entry_hop_accounts(&direct, HopRole::Direct).unwrap(),
        (ca("x"), ca("y"))
    );

    // Ascend with a second child leg is not canonical.
    let two_children = entry(
        HopRole::Ascend,
        vec![
            p(AccountRef::Parent, -10),
            p(ca("x"), -10),
            p(ca("y"), -10),
        ],
    );
    assert!(entry_hop_accounts(&two_children, HopRole::Ascend).is_err());

    // Direct with a `Parent` leg is not canonical.
    let with_parent = entry(
        HopRole::Direct,
        vec![
            p(AccountRef::Parent, -10),
            p(ca("x"), -10),
            p(ca("y"), 10),
        ],
    );
    assert!(entry_hop_accounts(&with_parent, HopRole::Direct).is_err());
}

// ── Component-aware audit (M5 exit rights, P4) ────────────────────────────

/// Island-internal parent/child edges are audited exactly like a single-root
/// tree's, and the island itself is reported once as an advisory `Detached`.
#[test]
fn island_internal_edges_are_compared_and_island_is_detached() {
    let mut primary = Topology::new_root("R");
    primary.add_node("A", ChildKind::Node).unwrap();
    primary.attach("R", "A", Some(0)).unwrap();

    let mut island = Topology::new_root("X");
    island.add_node("Y", ChildKind::Node).unwrap();
    island.add_node("uY", ChildKind::User).unwrap();
    island.attach("X", "Y", Some(0)).unwrap();
    island.attach("Y", "uY", Some(0)).unwrap();

    let (r_key, a_key, x_key, y_key) = (k(101), k(102), k(103), k(104));
    let mut set = LedgerSet::new();
    set.insert(n("R"), Ledger::new_root(r_key.public())).unwrap();
    set.insert(n("A"), Ledger::new_non_root(a_key.public()))
        .unwrap();
    set.insert(n("X"), Ledger::new_non_root(x_key.public()))
        .unwrap();
    set.insert(n("Y"), Ledger::new_non_root(y_key.public()))
        .unwrap();

    // X opens a liability to Y but never funds it; Y holds a 100 Parent claim.
    open(
        set.get_mut(&n("X")).unwrap(),
        &x_key,
        "Y",
        ChildKind::Node,
    );
    open(
        set.get_mut(&n("Y")).unwrap(),
        &y_key,
        "uY",
        ChildKind::User,
    );
    descend(set.get_mut(&n("Y")).unwrap(), &y_key, "uY", 100);

    let components = vec![
        NetComponent {
            topology: primary,
            stranded_parent: None,
        },
        NetComponent {
            topology: island,
            stranded_parent: Some(n("P")),
        },
    ];
    let report = net_partition(&components, &set, &PeerRegistry::new(), &[], &BTreeMap::new());

    let mismatch = report.findings.iter().find_map(|f| match f {
        Finding::MirrorMismatch {
            edge,
            parent_view,
            child_view,
            direction,
        } if edge.parent == n("X") && edge.child == n("Y") => {
            Some((*parent_view, *child_view, *direction))
        }
        _ => None,
    });
    assert_eq!(
        mismatch,
        Some((Amount::ZERO, Amount::new(100), MirrorDirection::UnbackedClaim)),
        "island edge X->Y must be compared normally, got {:?}",
        report.findings
    );

    let detached: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| matches!(f, Finding::Detached { .. }))
        .collect();
    assert_eq!(detached.len(), 1, "expected one Detached island");
    assert!(detached[0].is_advisory());
}

/// A severed pair (the island root's stranded `Parent` claim) is reported once
/// as `Detached` and never as a permanent `MirrorMismatch`.
#[test]
fn severed_pair_is_detached_once_and_never_a_mirror_mismatch() {
    let mut primary = Topology::new_root("R");
    primary.add_node("A", ChildKind::Node).unwrap();
    primary.attach("R", "A", Some(0)).unwrap();

    let island = Topology::new_root("X");
    let x_key = k(103);
    let mut set = LedgerSet::new();
    set.insert(n("R"), Ledger::new_root(k(101).public()))
        .unwrap();
    set.insert(n("A"), Ledger::new_non_root(k(102).public()))
        .unwrap();
    set.insert(n("X"), Ledger::new_non_root(x_key.public()))
        .unwrap();

    // X exited: it kept a stranded Parent claim from its old parent P.
    open(
        set.get_mut(&n("X")).unwrap(),
        &x_key,
        "uX",
        ChildKind::User,
    );
    descend(set.get_mut(&n("X")).unwrap(), &x_key, "uX", 100);

    let components = vec![
        NetComponent {
            topology: primary,
            stranded_parent: None,
        },
        NetComponent {
            topology: island,
            stranded_parent: Some(n("P")),
        },
    ];
    let report = net_partition(&components, &set, &PeerRegistry::new(), &[], &BTreeMap::new());

    assert!(
        report
            .findings
            .iter()
            .all(|f| !matches!(f, Finding::MirrorMismatch { .. })),
        "the severed pair must not be a MirrorMismatch: {:?}",
        report.findings
    );
    assert_eq!(
        report.findings,
        vec![Finding::Detached {
            root: n("X"),
            nodes: vec![n("X")],
            stranded_parent: Some(n("P")),
            parent_balance: Amount::new(100),
        }],
        "the severed pair must be reported exactly once as Detached"
    );
    assert!(report.findings[0].is_advisory());
}

/// An order whose endpoints are in different components has no common root and
/// is reported once as an advisory `RouteInvalid`.
#[test]
fn cross_component_order_is_route_invalid_advisory() {
    let mut primary = Topology::new_root("R");
    primary.add_node("A", ChildKind::Node).unwrap();
    primary.add_node("uA", ChildKind::User).unwrap();
    primary.attach("R", "A", Some(0)).unwrap();
    primary.attach("A", "uA", Some(0)).unwrap();

    let mut island = Topology::new_root("X");
    island.add_node("uX", ChildKind::User).unwrap();
    island.attach("X", "uX", Some(0)).unwrap();

    let mut set = LedgerSet::new();
    set.insert(n("R"), Ledger::new_root(k(101).public()))
        .unwrap();
    set.insert(n("A"), Ledger::new_non_root(k(102).public()))
        .unwrap();
    set.insert(n("X"), Ledger::new_non_root(k(103).public()))
        .unwrap();

    let components = vec![
        NetComponent {
            topology: primary,
            stranded_parent: None,
        },
        NetComponent {
            topology: island,
            stranded_parent: None,
        },
    ];
    let order = order("uA", "uX", 10, 1);
    let report = net_partition(
        &components,
        &set,
        &PeerRegistry::new(),
        std::slice::from_ref(&order),
        &BTreeMap::new(),
    );

    let route = report
        .findings
        .iter()
        .find(|f| matches!(f, Finding::RouteInvalid { payment_id, .. } if *payment_id == order.hash()))
        .expect("a cross-component order must be RouteInvalid");
    assert!(route.is_advisory());
    assert!(report.nets.is_empty());
}

/// A re-attached stranded pair is a normal single-root edge and surfaces once
/// as an `UnbackedClaim` mirror mismatch.
#[test]
fn reattached_stranded_pair_is_reported_exactly_once() {
    let mut topo = Topology::new_root("R");
    topo.add_node("A", ChildKind::Node).unwrap();
    topo.attach("R", "A", Some(0)).unwrap();

    let r_key = k(101);
    let a_key = k(102);
    let mut set = LedgerSet::new();
    set.insert(n("R"), Ledger::new_root(r_key.public()))
        .unwrap();
    set.insert(n("A"), Ledger::new_non_root(a_key.public()))
        .unwrap();

    // A re-attached but R never extended Child(A): A's stranded Parent remains.
    open(
        set.get_mut(&n("A")).unwrap(),
        &a_key,
        "uA",
        ChildKind::User,
    );
    descend(set.get_mut(&n("A")).unwrap(), &a_key, "uA", 100);

    let report = net(&topo, &set, &PeerRegistry::new(), &[], &BTreeMap::new());
    let mismatches: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| matches!(f, Finding::MirrorMismatch { .. }))
        .collect();
    assert_eq!(
        mismatches.len(),
        1,
        "the re-attached stranded pair must surface exactly once: {:?}",
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

// ── Netting gate: exit advisories must not suppress `nets` (G1) ───────────

/// Every finding suppresses netting except the two steady-state exit signals;
/// `RouteInvalid` keeps suppressing.
#[test]
fn suppresses_netting_rule_is_exact() {
    let det = Finding::Detached {
        root: n("X"),
        nodes: vec![n("X")],
        stranded_parent: None,
        parent_balance: Amount::ZERO,
    };
    let stale = Finding::StaleChildLink {
        parent: n("P"),
        child: n("X"),
    };
    let route = Finding::RouteInvalid {
        payment_id: Hash::from_bytes([1u8; 32]),
        reason: "test".to_string(),
    };
    let replay = Finding::Replay {
        payment_id: Hash::from_bytes([2u8; 32]),
        reason: "test".to_string(),
    };
    let chain = Finding::ChainInvalid {
        node: n("N"),
        reason: "test".to_string(),
    };
    let mirror = Finding::MirrorMismatch {
        edge: EdgeAccount {
            parent: n("N"),
            child: n("X"),
        },
        parent_view: Amount::ZERO,
        child_view: Amount::new(1),
        direction: MirrorDirection::UnbackedClaim,
    };
    let overdraw = Finding::Overdraw {
        node: n("N"),
        account: AccountRef::Parent,
        deficit: 1,
    };

    assert!(!det.suppresses_netting(), "Detached must not suppress");
    assert!(!stale.suppresses_netting(), "StaleChildLink must not suppress");
    // Advisory severity does not imply a free pass at the netting gate.
    assert!(route.is_advisory());
    assert!(route.suppresses_netting(), "RouteInvalid must keep suppressing");
    assert!(replay.suppresses_netting());
    assert!(chain.suppresses_netting());
    assert!(mirror.suppresses_netting());
    assert!(overdraw.suppresses_netting());
}

/// An island (`Detached`, advisory) with no hard finding still collapses nets
/// for the healthy components.
#[test]
fn island_without_hard_findings_still_nets() {
    let mut fx = Fixture::new();
    let order = order("uA", "uB", 100, 1);
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();
    execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();

    let components = vec![
        NetComponent {
            topology: fx.topo.clone(),
            stranded_parent: None,
        },
        NetComponent {
            topology: Topology::new_root("X"),
            stranded_parent: None,
        },
    ];
    let report = net_partition(
        &components,
        &fx.set,
        &fx.registry,
        std::slice::from_ref(&order),
        &BTreeMap::new(),
    );

    assert!(
        report.findings.iter().all(|f| matches!(f, Finding::Detached { .. })),
        "the only finding must be the Detached island: {:?}",
        report.findings
    );
    assert_eq!(
        report.nets,
        vec![NetTransfer {
            parent: n("R"),
            from: n("A"),
            to: n("B"),
            amount: Amount::new(100),
        }],
        "a Detached advisory must not suppress the healthy components' nets"
    );
}

/// A hard finding alongside an island keeps `nets` empty (the island does not
/// rescue a genuine soundness objection).
#[test]
fn hard_finding_plus_island_suppresses_nets() {
    let mut fx = Fixture::new();
    let order = order("uA", "uB", 100, 1);
    let auth = order.authorize(&op(11)).unwrap();
    let plan = plan_transfer(&fx.topo, &order, &auth, &fx.set, 42).unwrap();
    execute_plan(&plan, &mut fx.set, &fx.keys, &fx.registry, 50).unwrap();

    // A descends to L_A without R extending it: a hard MirrorMismatch.
    let a_key = fx.keys[&n("A")].clone();
    descend(fx.set.get_mut(&n("A")).unwrap(), &a_key, "L_A", 50);

    let components = vec![
        NetComponent {
            topology: fx.topo.clone(),
            stranded_parent: None,
        },
        NetComponent {
            topology: Topology::new_root("X"),
            stranded_parent: None,
        },
    ];
    let report = net_partition(
        &components,
        &fx.set,
        &fx.registry,
        std::slice::from_ref(&order),
        &BTreeMap::new(),
    );

    assert!(report
        .findings
        .iter()
        .any(|f| matches!(f, Finding::MirrorMismatch { .. })));
    assert!(report
        .findings
        .iter()
        .any(|f| matches!(f, Finding::Detached { .. })));
    assert!(
        report.nets.is_empty(),
        "a hard MirrorMismatch must keep suppressing even with an island present"
    );
}
