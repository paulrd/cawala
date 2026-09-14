//! Differential test: the node per-hop executor (`LedgerService::apply_hop`
//! over `Ledger<FileLog>`) must agree with the in-process `execute_plan` oracle
//! on the worked 5-hop cross-subtree route.
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
//! `uA -> uB` ascends `L_A`, `A`; reallocates at `R`; descends `B`, `L_B`. The
//! test prefunds the node ledgers exactly like `ledger::tests::settlement::
//! Fixture`, derives each signer's role with `classify_hop`, and compares roles,
//! postings, and final balances (never raw hashes: per-node `seq`/`issued_at`
//! differ).

use std::collections::BTreeMap;
use std::path::Path;

use cawala_ledger::{
    AccountRef, Amount, AuthRef, Entry, EntryBody, Hash, HopRole, Ledger, LedgerSecretKey, LedgerSet,
    NodeId, OperatorSecretKey, PaymentOrder, PeerKeys, PeerRegistry, PeerRole, Posting, SignedAmount,
    SignedEntry, classify_hop, execute_plan, expected_hops, hop_postings, plan_transfer,
};
use cawala_node::identity;
use cawala_node::ledger_service::{HopOutcome, LedgerService};
use cawala_node::record::RecordStore;
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

/// Append a helper entry to a MemLog oracle ledger.
fn oracle_append(
    ledger: &mut Ledger,
    key: &LedgerSecretKey,
    body: EntryBody,
    postings: Vec<Posting>,
    auth: Option<AuthRef>,
) {
    let seq = ledger.len() as u64;
    let entry = Entry {
        ledger_id: key.public(),
        seq,
        height: seq,
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

fn oracle_open(ledger: &mut Ledger, key: &LedgerSecretKey, child: &str, kind: ChildKind) {
    oracle_append(
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

fn oracle_issue(ledger: &mut Ledger, key: &LedgerSecretKey, child: &str, amount: u64) {
    oracle_append(
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

fn oracle_descend(ledger: &mut Ledger, key: &LedgerSecretKey, child: &str, amount: u64) {
    oracle_append(
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

/// A prefunded `LedgerSet` oracle, built exactly like
/// `crates/ledger/tests/settlement.rs::Fixture`.
fn oracle_set() -> (
    LedgerSet,
    BTreeMap<NodeId, LedgerSecretKey>,
    PeerRegistry,
) {
    let keys: BTreeMap<NodeId, LedgerSecretKey> =
        [("R", 101u8), ("A", 102), ("B", 103), ("L_A", 104), ("L_B", 105)]
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
    oracle_open(
        set.get_mut(&n("R")).unwrap(),
        &keys[&n("R")],
        "A",
        ChildKind::Node,
    );
    oracle_open(
        set.get_mut(&n("R")).unwrap(),
        &keys[&n("R")],
        "B",
        ChildKind::Node,
    );
    oracle_issue(set.get_mut(&n("R")).unwrap(), &keys[&n("R")], "A", 1000);
    oracle_issue(set.get_mut(&n("R")).unwrap(), &keys[&n("R")], "B", 1000);

    // A and B descend to their leaves.
    oracle_open(
        set.get_mut(&n("A")).unwrap(),
        &keys[&n("A")],
        "L_A",
        ChildKind::Node,
    );
    oracle_descend(set.get_mut(&n("A")).unwrap(), &keys[&n("A")], "L_A", 1000);
    oracle_open(
        set.get_mut(&n("B")).unwrap(),
        &keys[&n("B")],
        "L_B",
        ChildKind::Node,
    );
    oracle_descend(set.get_mut(&n("B")).unwrap(), &keys[&n("B")], "L_B", 1000);

    // Leaves descend to users.
    oracle_open(
        set.get_mut(&n("L_A")).unwrap(),
        &keys[&n("L_A")],
        "uA",
        ChildKind::User,
    );
    oracle_open(
        set.get_mut(&n("L_A")).unwrap(),
        &keys[&n("L_A")],
        "uA2",
        ChildKind::User,
    );
    oracle_descend(set.get_mut(&n("L_A")).unwrap(), &keys[&n("L_A")], "uA", 1000);
    oracle_descend(
        set.get_mut(&n("L_A")).unwrap(),
        &keys[&n("L_A")],
        "uA2",
        1000,
    );
    oracle_open(
        set.get_mut(&n("L_B")).unwrap(),
        &keys[&n("L_B")],
        "uB",
        ChildKind::User,
    );
    oracle_descend(set.get_mut(&n("L_B")).unwrap(), &keys[&n("L_B")], "uB", 1000);

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

    (set, keys, registry)
}

/// A node's `LedgerService`, its operator, and its ledger key, with the temp
/// dir kept alive by the caller.
struct NodeCtx {
    service: LedgerService,
    operator: OperatorSecretKey,
    ledger: cawala_ledger::LedgerPubKey,
}

fn node_operator(dir: &Path) -> OperatorSecretKey {
    let secret = identity::load_or_create_secret_key(dir).unwrap();
    OperatorSecretKey::from_bytes(secret.to_bytes())
}

fn open_node(
    dirs: &mut Vec<tempfile::TempDir>,
    node_id: &str,
    parent: Option<(&str, u8)>,
    children: &[(&str, ChildKind, u8)],
) -> NodeCtx {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut store = RecordStore::open(dir.path(), node_id).unwrap();
        if let Some((parent_id, slot)) = parent {
            store.set_parent(parent_id, slot).unwrap();
        }
        for (child_id, kind, slot) in children {
            store.attach_child(*child_id, *kind, Some(*slot), 0).unwrap();
        }
        store.save().unwrap();
    }
    let service = LedgerService::open(dir.path(), node_id).unwrap();
    let operator = node_operator(dir.path());
    let ledger = service.ledger_key_public();
    dirs.push(dir);
    NodeCtx {
        service,
        operator,
        ledger,
    }
}

#[test]
fn node_hops_match_the_memlog_oracle() {
    let topo = worked_topology();
    let now = 1_000u64;

    // --- node ledgers over FileLog ---------------------------------------
    let mut dirs: Vec<tempfile::TempDir> = Vec::new();
    let mut services: BTreeMap<String, NodeCtx> = BTreeMap::new();
    services.insert(
        "R".to_string(),
        open_node(
            &mut dirs,
            "R",
            None,
            &[("A", ChildKind::Node, 0), ("B", ChildKind::Node, 1)],
        ),
    );
    services.insert(
        "A".to_string(),
        open_node(&mut dirs, "A", Some(("R", 0)), &[("L_A", ChildKind::Node, 0)]),
    );
    services.insert(
        "B".to_string(),
        open_node(&mut dirs, "B", Some(("R", 1)), &[("L_B", ChildKind::Node, 0)]),
    );
    services.insert(
        "L_A".to_string(),
        open_node(
            &mut dirs,
            "L_A",
            Some(("A", 0)),
            &[
                ("uA", ChildKind::User, 0),
                ("uA2", ChildKind::User, 1),
            ],
        ),
    );
    services.insert(
        "L_B".to_string(),
        open_node(&mut dirs, "L_B", Some(("B", 0)), &[("uB", ChildKind::User, 0)]),
    );

    // --- prefund via P1 (Issue at the root, Descend down) ----------------
    {
        let r = services.get_mut("R").unwrap();
        r.service
            .fund(&n("A"), ChildKind::Node, 1000, &r.operator, 1, now)
            .unwrap();
        r.service
            .fund(&n("B"), ChildKind::Node, 1000, &r.operator, 2, now)
            .unwrap();
    }
    {
        let a = services.get_mut("A").unwrap();
        a.service
            .prefund(&n("L_A"), ChildKind::Node, 1000, &a.operator, 1, now)
            .unwrap();
    }
    {
        let b = services.get_mut("B").unwrap();
        b.service
            .prefund(&n("L_B"), ChildKind::Node, 1000, &b.operator, 1, now)
            .unwrap();
    }
    {
        let la = services.get_mut("L_A").unwrap();
        la.service
            .prefund(&n("uA"), ChildKind::User, 1000, &la.operator, 1, now)
            .unwrap();
        la.service
            .prefund(&n("uA2"), ChildKind::User, 1000, &la.operator, 2, now)
            .unwrap();
    }
    {
        let lb = services.get_mut("L_B").unwrap();
        lb.service
            .prefund(&n("uB"), ChildKind::User, 1000, &lb.operator, 1, now)
            .unwrap();
    }

    // --- registry: all 5 node rows + the payer row -----------------------
    let payer_op = op(11);
    let mut node_registry = PeerRegistry::new();
    for id in ["R", "A", "B", "L_A", "L_B"] {
        let ctx = services.get(id).unwrap();
        node_registry
            .insert(PeerKeys {
                node_id: n(id),
                operator: ctx.operator.public(),
                ledger: Some(ctx.ledger),
                role: PeerRole::Node,
            })
            .unwrap();
    }
    node_registry
        .insert(PeerKeys {
            node_id: n("uA"),
            operator: payer_op.public(),
            ledger: None,
            role: PeerRole::User,
        })
        .unwrap();

    // --- the order is authorised by the payer ----------------------------
    let order = PaymentOrder {
        from: n("uA"),
        to: n("uB"),
        amount: Amount::new(100),
        nonce: 1,
        expiry: now + 100,
    };
    let auth = order.authorize(&payer_op).unwrap();

    // --- oracle: plan + execute ------------------------------------------
    let (mut oracle, oracle_keys, oracle_registry) = oracle_set();
    let plan = plan_transfer(&topo, &order, &auth, &oracle, now).unwrap();
    execute_plan(&plan, &mut oracle, &oracle_keys, &oracle_registry, now).unwrap();

    // --- node path: classify, apply, and compare -------------------------
    let from_addr = topo.address_of("uA").unwrap();
    let to_addr = topo.address_of("uB").unwrap();
    let expected = expected_hops(&topo, &order).unwrap();
    assert_eq!(expected.len(), 5, "worked topology has a 5-hop route");
    let m = i64::try_from(order.amount.get()).unwrap();

    let mut applied: Vec<(NodeId, u64, Hash, usize)> = Vec::new();
    for (index, hop) in expected.iter().enumerate() {
        let signer_addr = topo.address_of(hop.signer.as_str()).unwrap();
        assert_eq!(
            classify_hop(&from_addr, &to_addr, &signer_addr),
            Some(hop.role),
            "hop {index}: classifier must match the oracle role"
        );
        assert_eq!(plan.hops[index].signer, hop.signer);
        assert_eq!(
            plan.hops[index].entry.postings,
            hop_postings(hop.role, &hop.first, &hop.second, m),
            "hop {index}: oracle postings must be the canonical shape"
        );

        let ctx = services.get_mut(hop.signer.as_str()).unwrap();
        let outcome = ctx.service.apply_hop(
            &order,
            &auth,
            hop.role,
            hop.first.clone(),
            hop.second.clone(),
            &node_registry,
            now,
        );
        match outcome {
            HopOutcome::Applied { seq, hash } => {
                let signed = ctx.service.ledger().get(seq as usize).unwrap().unwrap();
                assert_eq!(
                    signed.entry.postings,
                    hop_postings(hop.role, &hop.first, &hop.second, m),
                    "hop {index}: appended postings must be the canonical shape"
                );
                applied.push((hop.signer.clone(), seq, hash, ctx.service.ledger().len()));
            }
            other => panic!("hop {index} ({}) not applied: {other:?}", hop.signer),
        }
    }

    // --- differential: every account of every node matches the oracle ----
    for id in ["R", "A", "B", "L_A", "L_B"] {
        assert_eq!(
            services.get(id).unwrap().service.ledger().balances(),
            oracle.get(&n(id)).unwrap().balances(),
            "balances for {id} must match the execute_plan oracle"
        );
    }

    // --- idempotency: every applied hop duplicates with no append --------
    for ((signer, seq, hash, len), hop) in applied.iter().zip(expected.iter()) {
        let ctx = services.get_mut(signer.as_str()).unwrap();
        let repeat = ctx.service.apply_hop(
            &order,
            &auth,
            hop.role,
            hop.first.clone(),
            hop.second.clone(),
            &node_registry,
            now,
        );
        assert_eq!(
            repeat,
            HopOutcome::Duplicate {
                seq: *seq,
                hash: *hash
            },
            "re-applying {} must duplicate",
            hop.signer
        );
        assert_eq!(
            ctx.service.ledger().len(),
            *len,
            "a duplicate hop must not append ({})",
            hop.signer
        );
    }
}
