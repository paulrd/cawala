//! Hermetic end-to-end test for the P3 cross-subtree settlement transport.
//!
//! Real `cawala/msg/0` transport over IPv4 loopback (relays disabled, explicit
//! hints), a parent `P=0` with leaves `A=0.1` and `B=0.2`, and users `uA=0.1.3`
//! / `uB=0.2.4`. `P` issues to `A`/`B`; `A`/`B` prefund their users, so a
//! `uA -> uB` payment routes `A Ascend`, `P Lca`, `B Descend` hop by hop.
//!
//! Unlike the generic messaging tests, a settlement forward is not addressed to
//! the final payee leaf: each signer processes its hop and re-addresses the
//! envelope to the next expected signer. Only that way can the intermediate LCA
//! apply and sign its own hop (the transport delivers an envelope only to the
//! node it is addressed to).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cawala_ledger::{
    AccountRef, Amount, AuthRef, Balances, Entry, EntryBody, Hash,
    HopRole, LedgerPubKey, LedgerSecretKey, MAX_ENTRY_PROOF, NodeId, OperatorSecretKey, PaymentOrder,
    PeerKeys, PeerRegistry, PeerRole, Posting, SignedAmount, SignedCommitment, SignedEntry,
    build_commitment, entry_hash, entry_inclusion_proof, verify_applied_entry,
    verify_balance_attestation, verify_entry_inclusion,
};
use cawala_msg::{
    AckStatus, Envelope, EntryProofV1, LedgerPayloadV1, LedgerPayloadV2, LedgerPayloadV3,
    MSG_LEDGER_V1, MSG_SETTLE_V1, OrderRejectV1, OrderResultV3, OrderV2, PeerRef, SettleForwardV3,
    SettleHopV3, SettleOutcomeV3, SettlePayloadV3, SettleResultV3, SettlementStatusV2,
    VersionedLedgerPayload, append_hop, decode_versioned,
};
use cawala_node::LedgerService;
use cawala_node::identity;
use cawala_node::ledger_peers::{load_peers, save_peers};
use cawala_node::msg::{
    MsgConfig, NeighborSource, RoutableSnapshot, SETTLE_TIMEOUT_SECS, build_envelope,
    dispatch_ledger_envelope, dispatch_settle_envelope, send_envelope, spawn_msg_node_on,
    sweep_settlements,
};
use cawala_node::record::{ChildEntry, NodeRecord, ParentLink, RecordStore};
use cawala_topology::ChildKind;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use tokio::sync::mpsc;

fn config() -> MsgConfig {
    MsgConfig {
        hop_timeout: Duration::from_secs(2),
        ..MsgConfig::default()
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

async fn bind(secret: &SecretKey) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(secret.clone())
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind address")
        .bind()
        .await
        .expect("bind endpoint")
}

fn record(
    node_id: &str,
    address: &str,
    parent: Option<(&str, u8)>,
    children: &[(&str, u8, ChildKind)],
) -> NodeRecord {
    NodeRecord {
        node_id: node_id.to_string(),
        address: Some(address.parse().expect("valid octal address")),
        parent: parent.map(|(id, slot)| ParentLink {
            parent_id: id.to_string(),
            slot,
            generation: 0,
        }),
        children: children
            .iter()
            .map(|(id, slot, kind)| ChildEntry {
                child_id: id.to_string(),
                kind: *kind,
                slot: *slot,
                date_joined: 0,
            })
            .collect(),
        address_epoch: 0,
    }
}

fn snapshot(record: &NodeRecord, addrs: &HashMap<EndpointId, EndpointAddr>) -> RoutableSnapshot {
    let mut snap = RoutableSnapshot::from_record(record).expect("derive snapshot");
    if let Some(p) = &record.parent
        && let Ok(id) = p.parent_id.parse::<EndpointId>()
        && let Some(addr) = addrs.get(&id)
    {
        snap.hints.insert(id.to_string(), addr.clone());
    }
    for child in &record.children {
        if let Ok(id) = child.child_id.parse::<EndpointId>()
            && let Some(addr) = addrs.get(&id)
        {
            snap.hints.insert(id.to_string(), addr.clone());
        }
    }
    snap
}

fn write_record(dir: &Path, rec: &NodeRecord) {
    let mut store = RecordStore::open(dir, &rec.node_id).unwrap();
    if let Some(parent) = &rec.parent {
        store.set_parent(&parent.parent_id, parent.slot).unwrap();
    }
    if let Some(address) = &rec.address {
        store.set_address(address.clone()).unwrap();
    }
    for child in &rec.children {
        store
            .attach_child(child.child_id.clone(), child.kind, Some(child.slot), 0)
            .unwrap();
    }
    store.save().unwrap();
}

fn user_row(node_id: &str, operator: &OperatorSecretKey) -> PeerKeys {
    PeerKeys {
        node_id: NodeId::from(node_id),
        operator: operator.public(),
        ledger: None,
        role: PeerRole::User,
    }
}

fn node_row(node_id: &str, operator: &OperatorSecretKey, ledger: &LedgerPubKey) -> PeerKeys {
    PeerKeys {
        node_id: NodeId::from(node_id),
        operator: operator.public(),
        ledger: Some(*ledger),
        role: PeerRole::Node,
    }
}

/// Write a peer registry from `rows` (as `control approve`/`create-child`
/// persist, plus the P5a parent row a child learns on join).
fn register_peers(dir: &Path, rows: &[PeerKeys]) {
    let mut registry = PeerRegistry::new();
    for row in rows {
        registry.insert(row.clone()).unwrap();
    }
    save_peers(dir, &registry).unwrap();
}

/// A parent/leaf node: its ledger, settlement manager, and routing view.
struct Leaf {
    _dir: tempfile::TempDir,
    node_id: String,
    endpoint: Endpoint,
    source: NeighborSource,
    ledger: Arc<tokio::sync::Mutex<LedgerService>>,
    manager: Arc<tokio::sync::Mutex<cawala_node::SettlementManager>>,
}

/// A user endpoint (no ledger).
struct User {
    node_id: String,
    endpoint: Endpoint,
    snapshot: RoutableSnapshot,
    sink: mpsc::Receiver<Envelope>,
    operator: OperatorSecretKey,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Everything prefunded (success path and most failures).
    Full,
    /// The payee leaf's user account is never opened.
    PayeeUnopened,
    /// The payee leaf never runs its drain loop (its hop is never applied).
    StallTerminal,
    /// The LCA's liability account for the payer leaf is under-prefunded, so
    /// the LCA hop rejects after the payer's Ascend applied.
    LcaUnderfunded,
}

struct Harness {
    p: Leaf,
    a: Leaf,
    b: Leaf,
    ua: User,
    ub: User,
    routers: Vec<Router>,
    config: MsgConfig,
}

async fn setup(mode: Mode) -> Harness {
    let config = config();

    // Identities and data dirs.
    let p_dir = tempfile::tempdir().unwrap();
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();

    let p_secret = identity::load_or_create_secret_key(p_dir.path()).unwrap();
    let a_secret = identity::load_or_create_secret_key(a_dir.path()).unwrap();
    let b_secret = identity::load_or_create_secret_key(b_dir.path()).unwrap();
    let ua_secret = SecretKey::generate();
    let ub_secret = SecretKey::generate();

    let p_id = p_secret.public().to_string();
    let a_id = a_secret.public().to_string();
    let b_id = b_secret.public().to_string();
    let ua_id = ua_secret.public().to_string();
    let ub_id = ub_secret.public().to_string();

    let p_op = OperatorSecretKey::from_bytes(p_secret.to_bytes());
    let a_op = OperatorSecretKey::from_bytes(a_secret.to_bytes());
    let b_op = OperatorSecretKey::from_bytes(b_secret.to_bytes());
    let ua_op = OperatorSecretKey::from_bytes(ua_secret.to_bytes());
    let ub_op = OperatorSecretKey::from_bytes(ub_secret.to_bytes());

    // Records.
    let p_rec = record(
        &p_id,
        "0",
        None,
        &[(&a_id, 1, ChildKind::Node), (&b_id, 2, ChildKind::Node)],
    );
    let a_rec = record(
        &a_id,
        "0.1",
        Some((&p_id, 1)),
        &[(&ua_id, 3, ChildKind::User)],
    );
    let b_rec = record(
        &b_id,
        "0.2",
        Some((&p_id, 2)),
        &[(&ub_id, 4, ChildKind::User)],
    );
    let ua_rec = record(&ua_id, "0.1.3", Some((&a_id, 3)), &[]);
    let ub_rec = record(&ub_id, "0.2.4", Some((&b_id, 4)), &[]);

    write_record(p_dir.path(), &p_rec);
    write_record(a_dir.path(), &a_rec);
    write_record(b_dir.path(), &b_rec);

    // Ledger services (opened before the peer rows so we can distribute each
    // node's ledger public key, as P5a does on join).
    let now = unix_now();
    let mut p_svc = LedgerService::open(p_dir.path(), &p_id).unwrap();
    let mut a_svc = LedgerService::open(a_dir.path(), &a_id).unwrap();
    let mut b_svc = LedgerService::open(b_dir.path(), &b_id).unwrap();
    let p_ledger = p_svc.ledger_key_public();
    let a_ledger = a_svc.ledger_key_public();
    let b_ledger = b_svc.ledger_key_public();

    // Peer rows: each leaf knows its parent (the row a child persists from its
    // `JoinApproval`) and its own users; the LCA knows its node children.
    register_peers(
        a_dir.path(),
        &[user_row(&ua_id, &ua_op), node_row(&p_id, &p_op, &p_ledger)],
    );
    register_peers(
        b_dir.path(),
        &[user_row(&ub_id, &ub_op), node_row(&p_id, &p_op, &p_ledger)],
    );
    register_peers(
        p_dir.path(),
        &[
            node_row(&a_id, &a_op, &a_ledger),
            node_row(&b_id, &b_op, &b_ledger),
        ],
    );

    assert!(a_svc.ensure_account_open(&NodeId::from(ua_id.clone()), ChildKind::User).unwrap());
    if mode != Mode::PayeeUnopened {
        assert!(b_svc.ensure_account_open(&NodeId::from(ub_id.clone()), ChildKind::User).unwrap());
    }

    p_svc
        .fund(
            &NodeId::from(a_id.clone()),
            ChildKind::Node,
            if mode == Mode::LcaUnderfunded { 50 } else { 1000 },
            &p_op,
            1,
            now,
        )
        .unwrap();
    p_svc
        .fund(&NodeId::from(b_id.clone()), ChildKind::Node, 1000, &p_op, 2, now)
        .unwrap();
    a_svc
        .prefund(&NodeId::from(ua_id.clone()), ChildKind::User, 1000, &a_op, 1, now)
        .unwrap();
    if mode != Mode::PayeeUnopened {
        b_svc
            .prefund(&NodeId::from(ub_id.clone()), ChildKind::User, 1000, &b_op, 1, now)
            .unwrap();
    }

    // Endpoints and hints.
    let p_ep = bind(&p_secret).await;
    let a_ep = bind(&a_secret).await;
    let b_ep = bind(&b_secret).await;
    let ua_ep = bind(&ua_secret).await;
    let ub_ep = bind(&ub_secret).await;

    let mut addrs: HashMap<EndpointId, EndpointAddr> = HashMap::new();
    addrs.insert(p_secret.public(), p_ep.addr());
    addrs.insert(a_secret.public(), a_ep.addr());
    addrs.insert(b_secret.public(), b_ep.addr());
    addrs.insert(ua_secret.public(), ua_ep.addr());
    addrs.insert(ub_secret.public(), ub_ep.addr());

    let p_snap = snapshot(&p_rec, &addrs);
    let a_snap = snapshot(&a_rec, &addrs);
    let b_snap = snapshot(&b_rec, &addrs);
    let ua_snap = snapshot(&ua_rec, &addrs);
    let ub_snap = snapshot(&ub_rec, &addrs);

    let mut routers = Vec::new();

    // Parent `P`.
    let p_ledger = Arc::new(tokio::sync::Mutex::new(p_svc));
    let p_manager = Arc::new(tokio::sync::Mutex::new(cawala_node::SettlementManager::new()));
    let p_source = NeighborSource::Static(p_snap.clone());
    let (p_router, p_sink) = spawn_msg_node_on(p_ep.clone(), p_snap.clone(), config.clone());
    spawn_drain(
        &p_ep, &p_source, &config, &p_ledger, &p_manager, p_dir.path(), &p_id, p_sink,
    );
    routers.push(p_router);

    // Payer leaf `A`.
    let a_ledger = Arc::new(tokio::sync::Mutex::new(a_svc));
    let a_manager = Arc::new(tokio::sync::Mutex::new(cawala_node::SettlementManager::new()));
    let a_source = NeighborSource::Static(a_snap.clone());
    let (a_router, a_sink) = spawn_msg_node_on(a_ep.clone(), a_snap.clone(), config.clone());
    spawn_drain(
        &a_ep, &a_source, &config, &a_ledger, &a_manager, a_dir.path(), &a_id, a_sink,
    );
    routers.push(a_router);

    // Payee leaf `B` (its drain may be intentionally stalled).
    let b_ledger = Arc::new(tokio::sync::Mutex::new(b_svc));
    let b_manager = Arc::new(tokio::sync::Mutex::new(cawala_node::SettlementManager::new()));
    let b_source = NeighborSource::Static(b_snap.clone());
    let (b_router, b_sink) = spawn_msg_node_on(b_ep.clone(), b_snap.clone(), config.clone());
    if mode != Mode::StallTerminal {
        spawn_drain(
            &b_ep, &b_source, &config, &b_ledger, &b_manager, b_dir.path(), &b_id, b_sink,
        );
    }
    routers.push(b_router);

    // User endpoints (read their sinks directly).
    let (ua_router, ua_sink) = spawn_msg_node_on(ua_ep.clone(), ua_snap.clone(), config.clone());
    let (ub_router, ub_sink) = spawn_msg_node_on(ub_ep.clone(), ub_snap.clone(), config.clone());
    routers.push(ua_router);
    routers.push(ub_router);

    Harness {
        p: Leaf {
            _dir: p_dir,
            node_id: p_id,
            endpoint: p_ep,
            source: p_source,
            ledger: p_ledger,
            manager: p_manager,
        },
        a: Leaf {
            _dir: a_dir,
            node_id: a_id,
            endpoint: a_ep,
            source: a_source,
            ledger: a_ledger,
            manager: a_manager,
        },
        b: Leaf {
            _dir: b_dir,
            node_id: b_id,
            endpoint: b_ep,
            source: b_source,
            ledger: b_ledger,
            manager: b_manager,
        },
        ua: User {
            node_id: ua_id,
            endpoint: ua_ep,
            snapshot: ua_snap,
            sink: ua_sink,
            operator: ua_op,
        },
        ub: User {
            node_id: ub_id,
            endpoint: ub_ep,
            snapshot: ub_snap,
            sink: ub_sink,
            operator: ub_op,
        },
        routers,
        config,
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_drain(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    manager: &Arc<tokio::sync::Mutex<cawala_node::SettlementManager>>,
    dir: &Path,
    node_id: &str,
    mut sink: mpsc::Receiver<Envelope>,
) {
    let endpoint = endpoint.clone();
    let source = source.clone();
    let config = config.clone();
    let ledger = Arc::clone(ledger);
    let manager = Arc::clone(manager);
    let dir = dir.to_path_buf();
    let node_id = node_id.to_string();
    tokio::spawn(async move {
        while let Some(env) = sink.recv().await {
            match env.msg_type {
                MSG_LEDGER_V1 => {
                    dispatch_ledger_envelope(
                        &endpoint, &source, &config, &ledger, &manager, &dir, &node_id, env,
                    )
                    .await;
                }
                MSG_SETTLE_V1 => {
                    dispatch_settle_envelope(
                        &endpoint, &source, &config, &ledger, &manager, &dir, &node_id, env,
                    )
                    .await;
                }
                _ => {}
            }
        }
    });
}

fn order(user: &User, to: &str, amount: u64, nonce: u64, expiry: u64) -> PaymentOrder {
    PaymentOrder {
        from: NodeId::from(user.node_id.clone()),
        to: NodeId::from(to),
        amount: Amount::new(amount),
        nonce,
        expiry,
    }
}

fn order_env(user: &User, dst_leaf: &str, order: &PaymentOrder, payee_addr: &str) -> Envelope {
    let auth = order.authorize(&user.operator).unwrap();
    order_env_with_auth(user, dst_leaf, order, &auth, payee_addr)
}

fn order_env_with_auth(
    user: &User,
    dst_leaf: &str,
    order: &PaymentOrder,
    auth: &AuthRef,
    payee_addr: &str,
) -> Envelope {
    let payload = LedgerPayloadV2::Order(OrderV2 {
        order: order.clone(),
        auth: auth.clone(),
        payee_addr: payee_addr.parse().expect("valid octal address"),
    })
    .to_bytes()
    .unwrap();
    build_envelope(
        &user.snapshot.routable.this,
        dst_leaf.parse().expect("valid octal address"),
        MSG_LEDGER_V1,
        payload,
        config().ttl,
    )
    .unwrap()
}

async fn send_from_user(user: &User, env: &Envelope, timeout: Duration) -> AckStatus {
    send_envelope(&user.endpoint, &user.snapshot, env, timeout)
        .await
        .expect("send")
        .status
}

async fn recv_payload(rx: &mut mpsc::Receiver<Envelope>, what: &str) -> LedgerPayloadV1 {
    let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{what} within timeout"))
        .unwrap_or_else(|| panic!("{what} envelope"));
    LedgerPayloadV1::from_bytes(&env.payload).expect("valid ledger payload")
}

async fn recv_order_result(rx: &mut mpsc::Receiver<Envelope>) -> OrderResultV3 {
    let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("order result within timeout")
        .expect("order result envelope");
    match decode_versioned(&env.payload).expect("valid ledger payload") {
        // `Applied`/`Duplicate` results carry a proof and are v3; the remaining
        // statuses keep the v2 shape (no proof).
        VersionedLedgerPayload::V3(LedgerPayloadV3::OrderResult(result)) => result,
        VersionedLedgerPayload::V2(LedgerPayloadV2::OrderResult(result)) => OrderResultV3 {
            reply_to: result.reply_to,
            order_hash: result.order_hash,
            status: result.status,
            balance: result.balance,
            proof: None,
        },
        other => panic!("expected a v2/v3 OrderResult, got {other:?}"),
    }
}

async fn recv_receipt(rx: &mut mpsc::Receiver<Envelope>) -> cawala_msg::BalanceReceiptV1 {
    match recv_payload(rx, "balance receipt").await {
        LedgerPayloadV1::BalanceReceipt(receipt) => receipt,
        other => panic!("expected BalanceReceipt, got {other:?}"),
    }
}

/// Poll until the ledger holds at least `min` entries.
async fn wait_for_len(leaf: &Leaf, min: usize) {
    for _ in 0..200 {
        if leaf.ledger.lock().await.ledger().len() >= min {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("ledger {} never reached {min} entries", leaf.node_id);
}

async fn ledger_len(leaf: &Leaf) -> usize {
    leaf.ledger.lock().await.ledger().len()
}

#[tokio::test]
async fn cross_subtree_settlement_success() {
    let mut h = setup(Mode::Full).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 1, now + 3600);
    let env = order_env(&h.ua, "0.1", &order, "0.2.4");

    let ack = send_from_user(&h.ua, &env, h.config.hop_timeout).await;
    assert_eq!(ack, AckStatus::Delivered);

    // Wait for the cascade to land at B.
    wait_for_len(&h.b, 3).await;

    // A Ascend: A.Parent 900, A.Child(uA) 900.
    {
        let a = h.a.ledger.lock().await;
        assert_eq!(a.ledger().balances().parent_balance(), Some(Amount::new(900)));
        assert_eq!(a.balance_of(&NodeId::from(h.ua.node_id.clone())), Amount::new(900));
    }
    // P Lca: P.Child(A) 900, P.Child(B) 1100.
    {
        let p = h.p.ledger.lock().await;
        assert_eq!(p.balance_of(&NodeId::from(h.a.node_id.clone())), Amount::new(900));
        assert_eq!(p.balance_of(&NodeId::from(h.b.node_id.clone())), Amount::new(1100));
    }
    // B Descend: B.Parent 1100, B.Child(uB) 1100.
    {
        let b = h.b.ledger.lock().await;
        assert_eq!(b.ledger().balances().parent_balance(), Some(Amount::new(1100)));
        assert_eq!(b.balance_of(&NodeId::from(h.ub.node_id.clone())), Amount::new(1100));
    }

    // uA: Applied with a payer receipt (balance 900).
    let result = recv_order_result(&mut h.ua.sink).await;
    assert!(
        matches!(result.status, SettlementStatusV2::Applied { .. }),
        "status {:?}",
        result.status
    );
    assert_eq!(result.order_hash, order.hash());
    let receipt = result.balance.expect("applied result carries a payer receipt");
    assert_eq!(receipt.attestation.balance, Amount::new(900));
    verify_balance_attestation(&receipt.attestation, &receipt.commitment, &receipt.ledger_pubkey)
        .unwrap();

    // The origin forwarded the payee leaf's own terminal proof, and it
    // self-verifies as a `Descend` crediting the payee included in the leaf's
    // committed entry tree.
    let proof = result
        .proof
        .as_ref()
        .expect("applied result carries a terminal proof");
    assert!(proof.validate().is_ok(), "terminal proof must validate");
    assert_eq!(proof.leaf_addr, "0.2".parse().unwrap());
    assert!(
        verify_applied_entry(&proof.entry, &order, false).is_ok(),
        "terminal entry must credit the payee as a Descend"
    );
    assert!(
        verify_entry_inclusion(
            &proof.entry,
            &proof.inclusion,
            &proof.commitment.commitment.entry_root,
        ),
        "terminal entry must be included in the committed tree"
    );

    // uB: pushed receipt with a Descend notice.
    let push = recv_receipt(&mut h.ub.sink).await;
    assert_eq!(push.attestation.balance, Amount::new(1100));
    let notice = push.notice.expect("payee receipt carries a notice");
    assert_eq!(notice.from, NodeId::from(h.ua.node_id.clone()));
    assert_eq!(notice.to, NodeId::from(h.ub.node_id.clone()));
    assert_eq!(notice.amount, Amount::new(100));
    assert_eq!(notice.payment_id, order.hash());

    // S2: each hop journalled the order once its own hop applied — the origin's
    // reservation (A), the LCA handoff (P), and the terminal (B) — exactly once
    // per node despite the same order being applied at every hop.
    for leaf in [&h.a, &h.p, &h.b] {
        let journal = cawala_node::orders::load_all(leaf._dir.path());
        assert_eq!(
            journal.len(),
            1,
            "node {} journalled {} entries",
            leaf.node_id,
            journal.len()
        );
        assert_eq!(journal[0].hash(), order.hash());
    }

    // The honest LCA echoed its hop with an inclusion proof, and the origin's
    // accountability audit must accept it (the outcome is not degraded).
    {
        let mgr = h.a.manager.lock().await;
        let terminal = mgr
            .terminal(&order.hash())
            .expect("the accepted outcome is recorded");
        assert!(
            !terminal.degraded,
            "the honest path must not degrade the intermediate audit"
        );
    }

    for router in h.routers.drain(..) {
        router.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn payee_account_unopened_rejects_but_payer_and_lca_apply() {
    let mut h = setup(Mode::PayeeUnopened).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 1, now + 3600);
    let env = order_env(&h.ua, "0.1", &order, "0.2.4");
    send_from_user(&h.ua, &env, h.config.hop_timeout).await;

    // A Ascend and P Lca land; B has no account and does not move.
    wait_for_len(&h.p, 5).await;
    let result = recv_order_result(&mut h.ua.sink).await;
    match &result.status {
        SettlementStatusV2::Partial { failed_at, reason } => {
            assert_eq!(*reason, OrderRejectV1::AccountNotOpened);
            assert_eq!(failed_at, &NodeId::from(h.b.node_id.clone()));
        }
        other => panic!("expected Partial, got {other:?}"),
    }
    {
        let a = h.a.ledger.lock().await;
        assert_eq!(a.ledger().balances().parent_balance(), Some(Amount::new(900)));
    }
    {
        let b = h.b.ledger.lock().await;
        assert_eq!(b.ledger().len(), 0, "B never appended");
        assert_eq!(b.ledger().balances().parent_balance(), Some(Amount::ZERO));
    }
}

#[tokio::test]
async fn underfunded_payer_rejects_without_forwarding() {
    let mut h = setup(Mode::Full).await;
    let now = unix_now();
    // 2000 exceeds A's 1000 prefund.
    let order = order(&h.ua, &h.ub.node_id, 2000, 1, now + 3600);
    let env = order_env(&h.ua, "0.1", &order, "0.2.4");
    send_from_user(&h.ua, &env, h.config.hop_timeout).await;

    let result = recv_order_result(&mut h.ua.sink).await;
    match &result.status {
        SettlementStatusV2::Rejected { reason } => {
            assert_eq!(*reason, OrderRejectV1::InsufficientBalance);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    // No hop was forwarded: A is unchanged (2 prefund entries), P has only its
    // 4 funding entries, B its 2 prefund entries.
    assert_eq!(ledger_len(&h.p).await, 4);
    assert_eq!(ledger_len(&h.b).await, 2);
    assert_eq!(ledger_len(&h.a).await, 2);
}

#[tokio::test]
async fn expired_order_rejects() {
    let mut h = setup(Mode::Full).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 1, now.saturating_sub(1));
    let env = order_env(&h.ua, "0.1", &order, "0.2.4");
    send_from_user(&h.ua, &env, h.config.hop_timeout).await;

    let result = recv_order_result(&mut h.ua.sink).await;
    match &result.status {
        SettlementStatusV2::Rejected { reason } => assert_eq!(*reason, OrderRejectV1::Expired),
        other => panic!("expected Rejected, got {other:?}"),
    }
    assert_eq!(ledger_len(&h.a).await, 2);
    // S2: a fully rejected order must not be journalled (it has no applied hop,
    // so recording it would create a false `RouteInvalid` finding in `net`).
    assert!(
        cawala_node::orders::load_all(h.a._dir.path()).is_empty(),
        "a rejected order must not be journalled"
    );
}

#[tokio::test]
async fn duplicate_order_is_answered_from_the_cached_terminal() {
    let mut h = setup(Mode::Full).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 7, now + 3600);
    let auth = order.authorize(&h.ua.operator).unwrap();
    let env = order_env_with_auth(&h.ua, "0.1", &order, &auth, "0.2.4");
    send_from_user(&h.ua, &env, h.config.hop_timeout).await;
    let first = recv_order_result(&mut h.ua.sink).await;
    let first_seq = match first.status {
        SettlementStatusV2::Applied { entry_seq, .. } => entry_seq,
        other => panic!("expected Applied, got {other:?}"),
    };
    wait_for_len(&h.b, 3).await;

    let a_len = ledger_len(&h.a).await;
    let p_len = ledger_len(&h.p).await;
    let b_len = ledger_len(&h.b).await;

    // Resend the identical order in a fresh envelope.
    let dup_env = order_env_with_auth(&h.ua, "0.1", &order, &auth, "0.2.4");
    send_from_user(&h.ua, &dup_env, h.config.hop_timeout).await;
    let dup = recv_order_result(&mut h.ua.sink).await;
    match &dup.status {
        SettlementStatusV2::Duplicate { entry_seq, .. } => assert_eq!(*entry_seq, first_seq),
        other => panic!("expected Duplicate, got {other:?}"),
    }
    assert_eq!(dup.order_hash, order.hash());
    assert!(
        dup.proof.is_some(),
        "a duplicate answered from the cached terminal forwards its proof"
    );
    assert_eq!(ledger_len(&h.a).await, a_len);
    assert_eq!(ledger_len(&h.p).await, p_len);
    assert_eq!(ledger_len(&h.b).await, b_len);
}

#[tokio::test]
async fn stalled_terminal_times_out_then_retry_is_idempotent() {
    let mut h = setup(Mode::StallTerminal).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 3, now + 3600);
    let env = order_env(&h.ua, "0.1", &order, "0.2.4");
    send_from_user(&h.ua, &env, h.config.hop_timeout).await;

    // A reserves (Ascend) and P applies (Lca); B never runs its drain.
    wait_for_len(&h.p, 5).await;
    let a_len = ledger_len(&h.a).await;
    let p_len = ledger_len(&h.p).await;

    // Sweep far past the deadline: uA gets a synthesized Indeterminate result
    // (the payer's debit is committed) carrying a fresh payer receipt.
    sweep_settlements(
        &h.a.endpoint,
        &h.a.source,
        &h.config,
        &h.a.ledger,
        h.a._dir.path(),
        &h.a.node_id,
        &h.a.manager,
        now + SETTLE_TIMEOUT_SECS + 1,
    )
    .await;
    let timeout = recv_order_result(&mut h.ua.sink).await;
    match &timeout.status {
        SettlementStatusV2::Indeterminate { reason } => {
            assert_eq!(*reason, OrderRejectV1::Internal);
        }
        other => panic!("expected Indeterminate, got {other:?}"),
    }
    assert!(
        timeout.balance.is_some(),
        "an indeterminate result must surface the committed debit receipt"
    );

    // A's hop remains; a retry is a duplicate and appends nothing.
    assert_eq!(ledger_len(&h.a).await, a_len);
    let retry = order_env(&h.ua, "0.1", &order, "0.2.4");
    send_from_user(&h.ua, &retry, h.config.hop_timeout).await;
    let dup = recv_order_result(&mut h.ua.sink).await;
    assert!(
        matches!(dup.status, SettlementStatusV2::Duplicate { .. }),
        "expected Duplicate, got {:?}",
        dup.status
    );
    assert_eq!(ledger_len(&h.a).await, a_len);
    assert_eq!(ledger_len(&h.p).await, p_len);
}

#[tokio::test]
async fn too_deep_route_rejects_without_appending() {
    let mut h = setup(Mode::Full).await;
    let now = unix_now();
    let order = order(&h.ua, "uZ", 100, 1, now + 3600);
    // Payee address shares no grandparent with the payer leaf.
    let env = order_env(&h.ua, "0.1", &order, "0.3.5.7");
    send_from_user(&h.ua, &env, h.config.hop_timeout).await;

    let result = recv_order_result(&mut h.ua.sink).await;
    match &result.status {
        SettlementStatusV2::Rejected { reason } => assert_eq!(*reason, OrderRejectV1::BadRequest),
        other => panic!("expected Rejected, got {other:?}"),
    }
    assert_eq!(ledger_len(&h.a).await, 2, "origin guard must not append");
    assert_eq!(ledger_len(&h.p).await, 4);
}

/// **F1**: when the LCA hop rejects (its child liability for the payer leaf is
/// under-prefunded), the browser must receive `Partial { failed_at: LCA }` with a
/// payer receipt — not a timeout `Rejected`/`Indeterminate`.
#[tokio::test]
async fn lca_rejection_surfaces_as_partial_with_failed_hop() {
    let mut h = setup(Mode::LcaUnderfunded).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 5, now + 3600);
    let env = order_env(&h.ua, "0.1", &order, "0.2.4");
    send_from_user(&h.ua, &env, h.config.hop_timeout).await;

    let result = recv_order_result(&mut h.ua.sink).await;
    match &result.status {
        SettlementStatusV2::Partial { failed_at, reason } => {
            assert_eq!(*reason, OrderRejectV1::InsufficientBalance);
            assert_eq!(failed_at, &NodeId::from(h.p.node_id.clone()));
        }
        other => panic!("expected Partial at the LCA, got {other:?}"),
    }
    assert!(
        result.balance.is_some(),
        "a partial result carries the committed debit receipt"
    );

    // A's Ascend applied (the payer was debited); P's Lca did not.
    let a = h.a.ledger.lock().await;
    assert_eq!(
        a.ledger().balances().parent_balance(),
        Some(Amount::new(900))
    );
}

// ── Adversarial F1: forged settlement forwards from a User child ──────────

fn posting(account: AccountRef, delta: i64) -> Posting {
    Posting {
        account,
        delta: SignedAmount::new(delta),
    }
}

/// A fabricated (but shape-valid) hop entry signed by an attacker key.
fn fabricated_hop(signer_addr: &str, order: &PaymentOrder, role: HopRole, seed: u8) -> SettleHopV3 {
    let key = LedgerSecretKey::from_bytes([seed; 32]);
    let operator = OperatorSecretKey::from_bytes([seed; 32]);
    let auth = order.authorize(&operator).unwrap();
    let m = i64::try_from(order.amount.get()).unwrap();
    let postings = match role {
        HopRole::Ascend => vec![
            posting(AccountRef::Parent, -m),
            posting(AccountRef::Child(NodeId::from("x")), -m),
        ],
        HopRole::Descend => vec![
            posting(AccountRef::Parent, m),
            posting(AccountRef::Child(NodeId::from("y")), m),
        ],
        HopRole::Lca | HopRole::Direct => vec![
            posting(AccountRef::Child(NodeId::from("x")), -m),
            posting(AccountRef::Child(NodeId::from("y")), m),
        ],
    };
    let entry = Entry {
        ledger_id: key.public(),
        seq: 0,
        height: 0,
        prev_hash: Hash::ZERO,
        issued_at: 0,
        body: EntryBody::Transfer {
            payment_id: order.hash(),
            amount: order.amount,
            role,
        },
        postings,
        auth: Some(auth),
    };
    SettleHopV3 {
        signer_addr: signer_addr.parse().expect("valid octal address"),
        entry: SignedEntry::sign(entry, &key).unwrap(),
        // These fabricated hops exercise the next-hop checks, not origin proof
        // verification.
        proof: None,
    }
}

fn forged_forward(
    attacker: &User,
    order: &PaymentOrder,
    payer_addr: &str,
    payee_addr: &str,
    hops: Vec<SettleHopV3>,
) -> SettleForwardV3 {
    SettleForwardV3 {
        order: order.clone(),
        auth: order.authorize(&attacker.operator).unwrap(),
        payer_key: PeerKeys {
            node_id: NodeId::from(attacker.node_id.clone()),
            operator: attacker.operator.public(),
            ledger: None,
            role: PeerRole::User,
        },
        payer_addr: payer_addr.parse().expect("valid octal address"),
        payee_addr: payee_addr.parse().expect("valid octal address"),
        hops,
    }
}

async fn send_forged(
    h: &Harness,
    attacker: &User,
    order: &PaymentOrder,
    payer_addr: &str,
    payee_addr: &str,
    hops: Vec<SettleHopV3>,
    dst: &str,
) {
    let forward = forged_forward(attacker, order, payer_addr, payee_addr, hops);
    let bytes = SettlePayloadV3::Forward(forward).to_bytes().unwrap();
    let env = build_envelope(
        &attacker.snapshot.routable.this,
        dst.parse().expect("valid octal address"),
        MSG_SETTLE_V1,
        bytes,
        config().ttl,
    )
    .unwrap();
    let ack = send_from_user(attacker, &env, h.config.hop_timeout).await;
    assert!(
        matches!(ack, AckStatus::Delivered | AckStatus::Rejected(_)),
        "unexpected transport ack {ack:?}"
    );
}

async fn balances(leaf: &Leaf) -> Balances {
    leaf.ledger.lock().await.ledger().balances().clone()
}

/// **Lca theft**: attacker user `0.1.3` sends a one-hop forged forward to leaf
/// `0.1` with `payer_addr = 0.1.1.7` / `payee_addr = 0.1.2.5`. This makes the
/// leaf itself `signers[1]` (the LCA), so the pre-existing index check passes and
/// the message reaches the new chain<->signer-prefix binding. The leaf must not
/// touch its ledger.
#[tokio::test]
async fn forged_lca_theft_from_user_is_rejected() {
    let mut h = setup(Mode::Full).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 22, now + 3600);
    let (a_before, p_before) = (balances(&h.a).await, balances(&h.p).await);
    let (a_len, p_len) = (ledger_len(&h.a).await, ledger_len(&h.p).await);

    // signers = [0.1.1, 0.1, 0.1.2]; this leaf is signers[1].
    let hops = vec![fabricated_hop("0.1.1", &order, HopRole::Ascend, 43)];
    send_forged(&h, &h.ua, &order, "0.1.1.7", "0.1.2.5", hops, "0.1").await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(ledger_len(&h.a).await, a_len);
    assert_eq!(ledger_len(&h.p).await, p_len);
    assert_eq!(balances(&h.a).await, a_before);
    assert_eq!(balances(&h.p).await, p_before);

    for router in h.routers.drain(..) {
        router.shutdown().await.unwrap();
    }
}

/// **Terminal mint**: attacker user `0.2.4` sends a two-hop forged forward to
/// leaf `0.2` with `payee_addr = 0.2.4`. This makes the leaf `signers[2]` (the
/// terminal), so the pre-existing index check passes and the message reaches the
/// new `hop_chain.len() == index` binding. The leaf must not touch its ledger.
#[tokio::test]
async fn forged_terminal_mint_from_user_is_rejected() {
    let mut h = setup(Mode::Full).await;
    let now = unix_now();
    // Payer address is the legitimate A->B route, but the sender is the payee.
    let order = order(&h.ua, &h.ub.node_id, 100, 21, now + 3600);
    let (a_before, p_before, b_before) =
        (balances(&h.a).await, balances(&h.p).await, balances(&h.b).await);
    let (a_len, p_len, b_len) =
        (ledger_len(&h.a).await, ledger_len(&h.p).await, ledger_len(&h.b).await);

    // signers = [0.1, 0, 0.2]; this leaf is signers[2], index = 2.
    let hops = vec![
        fabricated_hop("0.1", &order, HopRole::Ascend, 41),
        fabricated_hop("0", &order, HopRole::Lca, 42),
    ];
    send_forged(&h, &h.ub, &order, "0.1.3", "0.2.4", hops, "0.2").await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(ledger_len(&h.a).await, a_len);
    assert_eq!(ledger_len(&h.p).await, p_len);
    assert_eq!(ledger_len(&h.b).await, b_len);
    assert_eq!(balances(&h.a).await, a_before);
    assert_eq!(balances(&h.p).await, p_before);
    assert_eq!(balances(&h.b).await, b_before);

    for router in h.routers.drain(..) {
        router.shutdown().await.unwrap();
    }
}

/// A User child routes a forged handoff to the LCA through its own leaf; the
/// authenticated hop chain does not start at the payer leaf, so the LCA must
/// not apply anything.
#[tokio::test]
async fn forged_handoff_from_non_signer_is_rejected() {
    let mut h = setup(Mode::Full).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 23, now + 3600);
    let (a_before, p_before, b_before) =
        (balances(&h.a).await, balances(&h.p).await, balances(&h.b).await);
    let (a_len, p_len, b_len) =
        (ledger_len(&h.a).await, ledger_len(&h.p).await, ledger_len(&h.b).await);

    let hops = vec![fabricated_hop("0.1", &order, HopRole::Ascend, 44)];
    // Addressed to the LCA; the transport relays it through the payer leaf.
    send_forged(&h, &h.ua, &order, "0.1.3", "0.2.4", hops, "0").await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(ledger_len(&h.a).await, a_len);
    assert_eq!(ledger_len(&h.p).await, p_len);
    assert_eq!(ledger_len(&h.b).await, b_len);
    assert_eq!(balances(&h.a).await, a_before);
    assert_eq!(balances(&h.p).await, p_before);
    assert_eq!(balances(&h.b).await, b_before);

    for router in h.routers.drain(..) {
        router.shutdown().await.unwrap();
    }
}

/// **F4**: a Forward relayed by the LCA to the terminal leaf carries a tampered
/// LCA hop — the right signer address (`0`) but signed by a *different
/// registered* node key. The terminal resolves the signer under the known
/// parent key and must reject without touching any ledger. The unit tests in
/// `msg.rs` pin the resolution logic; this exercises it over the real
/// transport, with the terminal authenticating the relaying LCA as its QUIC
/// predecessor.
#[tokio::test]
async fn relayed_tampered_lca_hop_is_rejected_at_terminal() {
    let mut h = setup(Mode::Full).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 31, now + 3600);

    // A second *registered* node row at the terminal, so the tampered hop is
    // signed by a key B can resolve — just not the key bound to the LCA.
    let decoy_key = LedgerSecretKey::from_bytes([77u8; 32]);
    let decoy_op = OperatorSecretKey::from_bytes([77u8; 32]);
    {
        let mut peers = load_peers(h.b._dir.path()).unwrap();
        peers
            .insert(PeerKeys {
                node_id: NodeId::from("decoy"),
                operator: decoy_op.public(),
                ledger: Some(decoy_key.public()),
                role: PeerRole::Node,
            })
            .unwrap();
        save_peers(h.b._dir.path(), &peers).unwrap();
    }

    let (a_before, p_before, b_before) = (
        balances(&h.a).await,
        balances(&h.p).await,
        balances(&h.b).await,
    );
    let (a_len, p_len, b_len) = (
        ledger_len(&h.a).await,
        ledger_len(&h.p).await,
        ledger_len(&h.b).await,
    );

    // signers = [0.1, 0, 0.2]; hop[0] has the honest payer shape, hop[1] names
    // the LCA address `0` but is signed by the decoy ledger key (`77`).
    let hops = vec![
        fabricated_hop("0.1", &order, HopRole::Ascend, 43),
        fabricated_hop("0", &order, HopRole::Lca, 77),
    ];
    let forward = forged_forward(&h.ua, &order, "0.1.3", "0.2.4", hops);
    let bytes = SettlePayloadV3::Forward(forward).to_bytes().unwrap();

    // Relay it as if it had travelled A -> P -> B: the envelope's origin is the
    // payer leaf, its chain carries the payer hop then the LCA hop, and it is
    // *sent by P* so the terminal authenticates the preceding signer over QUIC.
    let a_ref = PeerRef {
        addr: "0.1".parse().unwrap(),
        node: h.a.node_id.clone(),
    };
    let p_ref = PeerRef {
        addr: "0".parse().unwrap(),
        node: h.p.node_id.clone(),
    };
    let mut env = build_envelope(
        &a_ref,
        "0.2".parse().unwrap(),
        MSG_SETTLE_V1,
        bytes,
        // One hop is consumed by the relay below (mirroring the transport's
        // per-forward TTL decrement).
        config().ttl - 1,
    )
    .unwrap();
    append_hop(&mut env, &p_ref).unwrap();
    let p_snap = h.p.source.snapshot();
    let ack = send_envelope(&h.p.endpoint, &p_snap, &env, h.config.hop_timeout)
        .await
        .expect("relay");
    assert_eq!(ack.status, AckStatus::Delivered);
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(ledger_len(&h.a).await, a_len);
    assert_eq!(ledger_len(&h.p).await, p_len);
    assert_eq!(ledger_len(&h.b).await, b_len);
    assert_eq!(balances(&h.a).await, a_before);
    assert_eq!(balances(&h.p).await, p_before);
    assert_eq!(balances(&h.b).await, b_before);

    for router in h.routers.drain(..) {
        router.shutdown().await.unwrap();
    }
}

// ── R6a: adversarial terminal-proof verification at the origin ─────────────
//
// The origin `A` verifies a terminal `EntryProofV1` for self-consistency
// before accepting `Applied`; a proof failing any check must resolve the
// browser's result as `Indeterminate` and must not be recorded as a terminal.
// The attacker is the LCA `P` (a direct neighbor of `A`), which spoofs
// `env.src.addr` to the payee leaf `0.2` and injects a forged
// `SettleResultV3::Applied`.
//
// Residual (reported, not patched — tests-only scope): the origin has no
// registry row binding the sibling leaf's node id to its ledger key, so it
// cannot distinguish the real payee leaf from any other signer when the proof
// is fully self-consistent AND correctly credits the payee. These tests
// exercise exactly the checks the origin *can* make (order binding,
// signer/commitment binding, structural bounds, Merkle inclusion).

/// Build a self-consistent terminal `EntryProofV1` for `order` under
/// `leaf_key`, with a `Descend` entry crediting `paid_child` (normally
/// `order.to`). The commitment and inclusion proof come from a two-entry
/// in-memory ledger (`OpenAccount(paid_child)`, then the transfer at seq 1).
fn forged_terminal_proof(
    order: &PaymentOrder,
    leaf_key: &LedgerSecretKey,
    leaf_node: &str,
    paid_child: &NodeId,
) -> EntryProofV1 {
    let op = OperatorSecretKey::from_bytes([0x5a; 32]);
    let m = i64::try_from(order.amount.get()).expect("amount fits i64");

    let mut ledger = cawala_ledger::Ledger::new_root(leaf_key.public());
    let open = Entry {
        ledger_id: leaf_key.public(),
        seq: 0,
        height: 0,
        prev_hash: Hash::ZERO,
        issued_at: 0,
        body: EntryBody::OpenAccount {
            child: paid_child.clone(),
            kind: ChildKind::User,
        },
        postings: vec![],
        auth: None,
    };
    let open_signed = SignedEntry::sign(open, leaf_key).unwrap();
    let open_hash = entry_hash(&open_signed.entry).unwrap();
    ledger.append(open_signed).unwrap();

    let transfer = Entry {
        ledger_id: leaf_key.public(),
        seq: 1,
        height: 1,
        prev_hash: open_hash,
        issued_at: 0,
        body: EntryBody::Transfer {
            payment_id: order.hash(),
            amount: order.amount,
            role: HopRole::Descend,
        },
        postings: vec![
            posting(AccountRef::Parent, m),
            posting(AccountRef::Child(paid_child.clone()), m),
        ],
        auth: Some(order.authorize(&op).unwrap()),
    };
    let signed = SignedEntry::sign(transfer, leaf_key).unwrap();
    ledger.append(signed.clone()).unwrap();

    let inclusion = entry_inclusion_proof(&ledger, 1).unwrap();
    let commitment = build_commitment(&ledger, Hash::ZERO, 0).unwrap();
    let commitment = SignedCommitment::sign(commitment, leaf_key).unwrap();

    EntryProofV1 {
        entry: signed,
        signer: PeerKeys {
            node_id: NodeId::from(leaf_node),
            operator: op.public(),
            ledger: Some(leaf_key.public()),
            role: PeerRole::Node,
        },
        leaf_addr: "0.2".parse().expect("valid octal address"),
        commitment,
        inclusion,
    }
}

/// The honest outer coordinates for `proof`.
fn proof_coords(proof: &EntryProofV1) -> (u64, Hash) {
    (
        proof.entry.entry.seq,
        entry_hash(&proof.entry.entry).expect("entry hashes"),
    )
}

/// Send a crafted settlement `Result` to the origin `A` from its parent `P`,
/// spoofing the envelope origin to the payee leaf (`0.2`) and appending `P` so
/// `A` authenticates it as the last hop of the chain.
async fn send_forged_result(h: &Harness, result: SettleResultV3) {
    let b_ref = PeerRef {
        addr: "0.2".parse().expect("valid octal address"),
        node: h.b.node_id.clone(),
    };
    let p_ref = PeerRef {
        addr: "0".parse().expect("valid octal address"),
        node: h.p.node_id.clone(),
    };
    let payload = SettlePayloadV3::Result(result).to_bytes().unwrap();
    // One TTL unit is consumed by the appended hop (the envelope's
    // `hop_chain.len() + ttl <= MAX_HOPS + 1` invariant).
    let mut env = build_envelope(
        &b_ref,
        "0.1".parse().expect("valid octal address"),
        MSG_SETTLE_V1,
        payload,
        h.config.ttl - 1,
    )
    .unwrap();
    append_hop(&mut env, &p_ref).unwrap();
    let p_snap = h.p.source.snapshot();
    let ack = send_envelope(&h.p.endpoint, &p_snap, &env, h.config.hop_timeout)
        .await
        .expect("forged result send");
    assert_eq!(ack.status, AckStatus::Delivered);
}

/// Set up a stalled terminal (`B` never drains its sink), send one order so the
/// origin `A` reserves a pending settlement, and return the harness plus the
/// order. `P` has applied its LCA hop and relayed to the stalled `B`, so no
/// terminal result has reached `A`.
async fn setup_pending(nonce: u64) -> (Harness, PaymentOrder) {
    let h = setup(Mode::StallTerminal).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, nonce, now + 3600);
    let env = order_env(&h.ua, "0.1", &order, "0.2.4");
    let ack = send_from_user(&h.ua, &env, h.config.hop_timeout).await;
    assert_eq!(ack, AckStatus::Delivered);
    // `P`'s Lca applied (its 5th entry); the relay to `B` is stalled.
    wait_for_len(&h.p, 5).await;
    (h, order)
}

/// A rejected proof must produce an `Indeterminate` browser result (no proof),
/// record no terminal outcome, and resolve the pending settlement.
async fn assert_rejected_as_indeterminate(h: &Harness, result: &OrderResultV3) {
    assert!(
        matches!(result.status, SettlementStatusV2::Indeterminate { .. }),
        "expected Indeterminate, got {:?}",
        result.status
    );
    assert!(
        result.proof.is_none(),
        "an indeterminate result carries no proof"
    );
    let mgr = h.a.manager.lock().await;
    assert_eq!(mgr.terminal_len(), 0, "a failed proof must not be recorded");
    assert_eq!(mgr.pending_len(), 0, "the pending settlement is resolved");
}

async fn shutdown_harness(mut h: Harness) {
    for router in h.routers.drain(..) {
        router.shutdown().await.unwrap();
    }
}

/// **1. Forged `Applied` from a malicious LCA.** `P` spoofs the payee leaf and
/// injects a fully self-consistent proof (valid signature, commitment, and
/// inclusion under the attacker's key) whose `Descend` entry credits the wrong
/// child instead of the order's payee. The old shape-only check accepted this;
/// `verify_applied_entry` must reject it and the browser must see
/// `Indeterminate`.
#[tokio::test]
async fn forged_applied_from_lca_is_rejected() {
    let (mut h, order) = setup_pending(101).await;
    let attacker_key = LedgerSecretKey::from_bytes([0x11; 32]);
    let wrong_payee = NodeId::from("attacker-account");
    let proof = forged_terminal_proof(&order, &attacker_key, &h.b.node_id, &wrong_payee);
    assert!(
        proof.validate().is_ok(),
        "the forgery is structurally self-consistent"
    );

    let (seq, hash) = proof_coords(&proof);
    send_forged_result(
        &h,
        SettleResultV3 {
            payment_id: order.hash(),
            outcome: SettleOutcomeV3::Applied {
                terminal_seq: seq,
                terminal_hash: hash,
                proof,
                intermediates: vec![],
            },
        },
    )
    .await;

    let result = recv_order_result(&mut h.ua.sink).await;
    assert_rejected_as_indeterminate(&h, &result).await;
    shutdown_harness(h).await;
}

/// **2. Valid entry, wrong signer key.** The entry is signed by `leaf_key` but
/// the proof declares a different signer ledger key, so the entry does not
/// verify under `proof.signer.ledger`.
#[tokio::test]
async fn wrong_signer_key_is_rejected() {
    let (mut h, order) = setup_pending(102).await;
    let leaf_key = LedgerSecretKey::from_bytes([0x21; 32]);
    let mut proof = forged_terminal_proof(&order, &leaf_key, &h.b.node_id, &order.to);
    proof.signer.ledger = Some(LedgerSecretKey::from_bytes([0x22; 32]).public());

    let (seq, hash) = proof_coords(&proof);
    send_forged_result(
        &h,
        SettleResultV3 {
            payment_id: order.hash(),
            outcome: SettleOutcomeV3::Applied {
                terminal_seq: seq,
                terminal_hash: hash,
                proof,
                intermediates: vec![],
            },
        },
    )
    .await;

    let result = recv_order_result(&mut h.ua.sink).await;
    assert_rejected_as_indeterminate(&h, &result).await;
    shutdown_harness(h).await;
}

/// **3. Tampered `terminal_hash` / `terminal_seq`.** The outer coordinates no
/// longer match `entry_hash(entry)` / `entry.seq`.
#[tokio::test]
async fn tampered_terminal_coordinates_are_rejected() {
    let leaf_key = LedgerSecretKey::from_bytes([0x31; 32]);

    // (a) `terminal_hash` no longer matches the entry hash.
    let (mut h, order) = setup_pending(103).await;
    let proof = forged_terminal_proof(&order, &leaf_key, &h.b.node_id, &order.to);
    let (seq, _) = proof_coords(&proof);
    send_forged_result(
        &h,
        SettleResultV3 {
            payment_id: order.hash(),
            outcome: SettleOutcomeV3::Applied {
                terminal_seq: seq,
                terminal_hash: Hash::ZERO,
                proof,
                intermediates: vec![],
            },
        },
    )
    .await;
    let result = recv_order_result(&mut h.ua.sink).await;
    assert_rejected_as_indeterminate(&h, &result).await;
    shutdown_harness(h).await;

    // (b) `terminal_seq` no longer matches `entry.seq`.
    let (mut h, order) = setup_pending(104).await;
    let proof = forged_terminal_proof(&order, &leaf_key, &h.b.node_id, &order.to);
    let (_, hash) = proof_coords(&proof);
    let bad_seq = proof.entry.entry.seq + 7;
    send_forged_result(
        &h,
        SettleResultV3 {
            payment_id: order.hash(),
            outcome: SettleOutcomeV3::Applied {
                terminal_seq: bad_seq,
                terminal_hash: hash,
                proof,
                intermediates: vec![],
            },
        },
    )
    .await;
    let result = recv_order_result(&mut h.ua.sink).await;
    assert_rejected_as_indeterminate(&h, &result).await;
    shutdown_harness(h).await;
}

/// **4. Tampered inclusion.** A wrong leaf `index` and an inclusion path bound
/// to a different commitment root must both be rejected.
#[tokio::test]
async fn tampered_inclusion_is_rejected() {
    let leaf_key = LedgerSecretKey::from_bytes([0x41; 32]);

    // (a) the audit path is presented at the wrong leaf index.
    let (mut h, order) = setup_pending(105).await;
    let mut proof = forged_terminal_proof(&order, &leaf_key, &h.b.node_id, &order.to);
    // The honest proof is for index 1; index 0 reconstructs a different root.
    proof.inclusion.index = 0;
    let (seq, hash) = proof_coords(&proof);
    send_forged_result(
        &h,
        SettleResultV3 {
            payment_id: order.hash(),
            outcome: SettleOutcomeV3::Applied {
                terminal_seq: seq,
                terminal_hash: hash,
                proof,
                intermediates: vec![],
            },
        },
    )
    .await;
    let result = recv_order_result(&mut h.ua.sink).await;
    assert_rejected_as_indeterminate(&h, &result).await;
    shutdown_harness(h).await;

    // (b) the inclusion path is verified against a different commitment root.
    let (mut h, order) = setup_pending(106).await;
    let mut proof = forged_terminal_proof(&order, &leaf_key, &h.b.node_id, &order.to);
    proof.commitment.commitment.entry_root = Hash::from_bytes([0xab; 32]);
    let (seq, hash) = proof_coords(&proof);
    send_forged_result(
        &h,
        SettleResultV3 {
            payment_id: order.hash(),
            outcome: SettleOutcomeV3::Applied {
                terminal_seq: seq,
                terminal_hash: hash,
                proof,
                intermediates: vec![],
            },
        },
    )
    .await;
    let result = recv_order_result(&mut h.ua.sink).await;
    assert_rejected_as_indeterminate(&h, &result).await;
    shutdown_harness(h).await;
}

/// **5. Oversized proof.** An audit path longer than `MAX_ENTRY_PROOF` fails
/// `EntryProofV1::validate` and must be rejected.
#[tokio::test]
async fn oversized_inclusion_proof_is_rejected() {
    let (mut h, order) = setup_pending(107).await;
    let leaf_key = LedgerSecretKey::from_bytes([0x51; 32]);
    let mut proof = forged_terminal_proof(&order, &leaf_key, &h.b.node_id, &order.to);
    proof.inclusion.proof = vec![Hash::ZERO; MAX_ENTRY_PROOF + 1];
    assert!(
        proof.validate().is_err(),
        "validate rejects an over-long audit path"
    );

    let (seq, hash) = proof_coords(&proof);
    send_forged_result(
        &h,
        SettleResultV3 {
            payment_id: order.hash(),
            outcome: SettleOutcomeV3::Applied {
                terminal_seq: seq,
                terminal_hash: hash,
                proof,
                intermediates: vec![],
            },
        },
    )
    .await;

    let result = recv_order_result(&mut h.ua.sink).await;
    assert_rejected_as_indeterminate(&h, &result).await;
    shutdown_harness(h).await;
}

/// **P2/M2 end-to-end**: a *verified* `Applied` whose echoed intermediate fails
/// the origin's accountability audit must still resolve as `Applied` for the
/// browser — the terminal proof remains the funds-correctness gate — while the
/// origin records the terminal `degraded` and writes the
/// `settle-intermediate-degraded` audit line.
///
/// The intermediate here is an `Lca` hop naming the LCA address whose fabricated
/// entry carries no inclusion proof, so it fails the
/// `intermediate_proof_missing` check before the M1 account check. (The harness
/// does not expose the real LCA secret, so the M1 misposting case is covered by
/// the `msg.rs` unit tests instead.)
#[tokio::test]
async fn degraded_intermediate_still_applies_and_is_audited() {
    let (mut h, order) = setup_pending(110).await;
    let leaf_key = LedgerSecretKey::from_bytes([0x61; 32]);
    let proof = forged_terminal_proof(&order, &leaf_key, &h.b.node_id, &order.to);
    assert!(
        proof.validate().is_ok(),
        "the terminal forgery is structurally self-consistent and credits the payee"
    );
    let (seq, hash) = proof_coords(&proof);

    let intermediate = fabricated_hop("0", &order, HopRole::Lca, 0x62);
    assert!(
        intermediate.proof.is_none(),
        "the fabricated intermediate carries no proof"
    );

    send_forged_result(
        &h,
        SettleResultV3 {
            payment_id: order.hash(),
            outcome: SettleOutcomeV3::Applied {
                terminal_seq: seq,
                terminal_hash: hash,
                proof,
                intermediates: vec![intermediate],
            },
        },
    )
    .await;

    let result = recv_order_result(&mut h.ua.sink).await;
    assert!(
        matches!(result.status, SettlementStatusV2::Applied { .. }),
        "a degraded intermediate must not deny the verified Applied, got {:?}",
        result.status
    );
    assert!(
        result.proof.is_some(),
        "the verified terminal proof is still forwarded to the browser"
    );

    {
        let mgr = h.a.manager.lock().await;
        let terminal = mgr
            .terminal(&order.hash())
            .expect("the accepted outcome is recorded");
        assert!(
            terminal.degraded,
            "the audit failure must be recorded as degraded"
        );
    }

    let audit_path = h
        .a
        ._dir
        .path()
        .join(cawala_node::audit::CONTROL_AUDIT_FILE);
    let audit = std::fs::read_to_string(&audit_path).expect("the degraded audit line is written");
    assert!(
        audit.contains("settle-intermediate-degraded"),
        "audit log: {audit}"
    );

    shutdown_harness(h).await;
}

/// **6. Replay.** Re-sending the identical terminal result after the terminal
/// was recorded is a no-op (no pending settlement, no second browser result,
/// one terminal record). Re-sending the order is answered `Duplicate` from the
/// cached terminal carrying the same proof.
#[tokio::test]
async fn replaying_the_terminal_result_is_idempotent() {
    let mut h = setup(Mode::Full).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 9, now + 3600);
    let env = order_env(&h.ua, "0.1", &order, "0.2.4");
    let ack = send_from_user(&h.ua, &env, h.config.hop_timeout).await;
    assert_eq!(ack, AckStatus::Delivered);
    wait_for_len(&h.b, 3).await;

    let first = recv_order_result(&mut h.ua.sink).await;
    let (terminal_seq, terminal_hash) = match &first.status {
        SettlementStatusV2::Applied {
            entry_seq,
            entry_hash,
        } => (*entry_seq, *entry_hash),
        other => panic!("expected Applied, got {other:?}"),
    };
    let proof = first.proof.clone().expect("applied result carries a proof");
    assert_eq!(h.a.manager.lock().await.terminal_len(), 1);

    // Re-send the identical terminal result. The origin no longer holds a
    // pending settlement for this payment id, so it must be a silent no-op.
    send_forged_result(
        &h,
        SettleResultV3 {
            payment_id: order.hash(),
            outcome: SettleOutcomeV3::Applied {
                terminal_seq,
                terminal_hash,
                proof: proof.clone(),
                intermediates: vec![],
            },
        },
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), h.ua.sink.recv())
            .await
            .is_err(),
        "a replayed result with no pending settlement must not emit a browser result"
    );
    assert_eq!(h.a.manager.lock().await.terminal_len(), 1);

    // Re-sending the order is answered `Duplicate` from the cached terminal,
    // forwarding the same proof.
    let retry = order_env(&h.ua, "0.1", &order, "0.2.4");
    let ack = send_from_user(&h.ua, &retry, h.config.hop_timeout).await;
    assert_eq!(ack, AckStatus::Delivered);
    let dup = recv_order_result(&mut h.ua.sink).await;
    assert!(
        matches!(dup.status, SettlementStatusV2::Duplicate { .. }),
        "expected Duplicate, got {:?}",
        dup.status
    );
    assert_eq!(
        dup.proof.as_ref(),
        Some(&proof),
        "the duplicate forwards the same proof"
    );
    assert_eq!(h.a.manager.lock().await.terminal_len(), 1);

    shutdown_harness(h).await;
}

// ── C1: hardened carried-prefix checks at the terminal ─────────────────────

/// A fabricated hop with arbitrary postings, signed by `key` and declaring that
/// same key as its `ledger_id`.
fn fabricated_hop_with_postings(
    signer_addr: &str,
    order: &PaymentOrder,
    role: HopRole,
    key: &LedgerSecretKey,
    postings: Vec<Posting>,
) -> SettleHopV3 {
    let auth = order
        .authorize(&OperatorSecretKey::from_bytes([1u8; 32]))
        .unwrap();
    let entry = Entry {
        ledger_id: key.public(),
        seq: 0,
        height: 0,
        prev_hash: Hash::ZERO,
        issued_at: 0,
        body: EntryBody::Transfer {
            payment_id: order.hash(),
            amount: order.amount,
            role,
        },
        postings,
        auth: Some(auth),
    };
    SettleHopV3 {
        signer_addr: signer_addr.parse().expect("valid octal address"),
        entry: SignedEntry::sign(entry, key).unwrap(),
        proof: None,
    }
}

/// Relay a forged forward to the terminal `B` as if it had travelled A -> P -> B
/// (sent by `P` so the terminal authenticates the preceding signer over QUIC),
/// then wait for the terminal's drain to process it.
async fn relay_to_terminal(h: &Harness, order: &PaymentOrder, hops: Vec<SettleHopV3>) {
    let forward = forged_forward(&h.ua, order, "0.1.3", "0.2.4", hops);
    let bytes = SettlePayloadV3::Forward(forward).to_bytes().unwrap();
    let a_ref = PeerRef {
        addr: "0.1".parse().unwrap(),
        node: h.a.node_id.clone(),
    };
    let p_ref = PeerRef {
        addr: "0".parse().unwrap(),
        node: h.p.node_id.clone(),
    };
    let mut env = build_envelope(
        &a_ref,
        "0.2".parse().unwrap(),
        MSG_SETTLE_V1,
        bytes,
        config().ttl - 1,
    )
    .unwrap();
    append_hop(&mut env, &p_ref).unwrap();
    let p_snap = h.p.source.snapshot();
    let ack = send_envelope(&h.p.endpoint, &p_snap, &env, h.config.hop_timeout)
        .await
        .expect("relay");
    assert_eq!(ack.status, AckStatus::Delivered);
    tokio::time::sleep(Duration::from_millis(250)).await;
}

/// **C1**: the relayer forwards a hop signed under its own declared key but with
/// a posting shape that is not canonical for its role. The terminal cannot
/// resolve the payer leaf's registered key, so it must fall back to the internal
/// shape checks and refuse to append.
#[tokio::test]
async fn relayed_non_canonical_carried_hop_is_rejected_at_terminal() {
    let h = setup(Mode::Full).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 51, now + 3600);

    let (a_len, p_len, b_len) = (
        ledger_len(&h.a).await,
        ledger_len(&h.p).await,
        ledger_len(&h.b).await,
    );
    let b_before = balances(&h.b).await;

    // `Ascend` must be exactly `Parent + one child`; this hop adds a second
    // child leg (and is still self-signed under the key it declares).
    let attacker_key = LedgerSecretKey::from_bytes([44u8; 32]);
    let m = i64::try_from(order.amount.get()).unwrap();
    let malformed = fabricated_hop_with_postings(
        "0.1",
        &order,
        HopRole::Ascend,
        &attacker_key,
        vec![
            posting(AccountRef::Parent, -m),
            posting(AccountRef::Child(NodeId::from("x")), -m),
            posting(AccountRef::Child(NodeId::from("y")), m),
        ],
    );
    let hops = vec![malformed, fabricated_hop("0", &order, HopRole::Lca, 66)];
    relay_to_terminal(&h, &order, hops).await;

    assert_eq!(ledger_len(&h.b).await, b_len, "B must not append");
    assert_eq!(balances(&h.b).await, b_before);
    assert_eq!(ledger_len(&h.a).await, a_len);
    assert_eq!(ledger_len(&h.p).await, p_len);

    shutdown_harness(h).await;
}

/// **C1**: the relayer forwards a hop whose signature does not verify under the
/// `ledger_id` it declares. The terminal cannot resolve the signer's registered
/// key, so before this hardening only shape/role/conservation applied; it must
/// now reject the internally-inconsistent entry.
#[tokio::test]
async fn relayed_carried_hop_with_mismatched_signature_is_rejected_at_terminal() {
    let h = setup(Mode::Full).await;
    let now = unix_now();
    let order = order(&h.ua, &h.ub.node_id, 100, 52, now + 3600);

    let b_len = ledger_len(&h.b).await;
    let b_before = balances(&h.b).await;

    let other = LedgerSecretKey::from_bytes([46u8; 32]);
    let mut bad = fabricated_hop("0.1", &order, HopRole::Ascend, 45);
    // The entry declares the `45` key but is signed by a different key.
    bad.entry.signature = other.sign(b"forged");
    let hops = vec![bad, fabricated_hop("0", &order, HopRole::Lca, 66)];
    relay_to_terminal(&h, &order, hops).await;

    assert_eq!(ledger_len(&h.b).await, b_len, "B must not append");
    assert_eq!(balances(&h.b).await, b_before);

    shutdown_harness(h).await;
}
