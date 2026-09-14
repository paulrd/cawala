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
    AccountRef, Amount, AuthRef, Balances, Entry, EntryBody, Hash, HopRole, LedgerSecretKey, NodeId,
    OperatorSecretKey, PaymentOrder, PeerKeys, PeerRegistry, PeerRole, Posting, SignedAmount,
    SignedEntry, verify_balance_attestation,
};
use cawala_msg::{
    AckStatus, Envelope, LedgerPayloadV1, LedgerPayloadV2, MSG_LEDGER_V1, MSG_SETTLE_V1,
    OrderRejectV1, OrderStatusV1, OrderV2, SettleForwardV1, SettleHopV1, SettlePayloadV1,
};
use cawala_node::LedgerService;
use cawala_node::identity;
use cawala_node::ledger_peers::save_peers;
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

fn register_user(dir: &Path, node_id: &str, operator: &OperatorSecretKey) {
    let mut registry = PeerRegistry::new();
    registry
        .insert(PeerKeys {
            node_id: NodeId::from(node_id),
            operator: operator.public(),
            ledger: None,
            role: PeerRole::User,
        })
        .unwrap();
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

    // User rows in the leaves' peer registries.
    register_user(a_dir.path(), &ua_id, &ua_op);
    register_user(b_dir.path(), &ub_id, &ub_op);

    // Ledger services + prefund.
    let now = unix_now();
    let mut p_svc = LedgerService::open(p_dir.path(), &p_id).unwrap();
    let mut a_svc = LedgerService::open(a_dir.path(), &a_id).unwrap();
    let mut b_svc = LedgerService::open(b_dir.path(), &b_id).unwrap();
    assert!(a_svc.ensure_account_open(&NodeId::from(ua_id.clone()), ChildKind::User).unwrap());
    if mode != Mode::PayeeUnopened {
        assert!(b_svc.ensure_account_open(&NodeId::from(ub_id.clone()), ChildKind::User).unwrap());
    }

    p_svc
        .fund(&NodeId::from(a_id.clone()), ChildKind::Node, 1000, &p_op, 1, now)
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

async fn recv_order_result(rx: &mut mpsc::Receiver<Envelope>) -> cawala_msg::OrderResultV1 {
    match recv_payload(rx, "order result").await {
        LedgerPayloadV1::OrderResult(result) => result,
        other => panic!("expected OrderResult, got {other:?}"),
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
    assert_eq!(result.status, OrderStatusV1::Applied, "reason {:?}", result.reason);
    assert_eq!(result.order_hash, order.hash());
    let receipt = result.balance.expect("applied result carries a payer receipt");
    assert_eq!(receipt.attestation.balance, Amount::new(900));
    verify_balance_attestation(&receipt.attestation, &receipt.commitment, &receipt.ledger_pubkey)
        .unwrap();

    // uB: pushed receipt with a Descend notice.
    let push = recv_receipt(&mut h.ub.sink).await;
    assert_eq!(push.attestation.balance, Amount::new(1100));
    let notice = push.notice.expect("payee receipt carries a notice");
    assert_eq!(notice.from, NodeId::from(h.ua.node_id.clone()));
    assert_eq!(notice.to, NodeId::from(h.ub.node_id.clone()));
    assert_eq!(notice.amount, Amount::new(100));
    assert_eq!(notice.payment_id, order.hash());

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
    assert_eq!(result.status, OrderStatusV1::Rejected);
    assert_eq!(result.reason, Some(OrderRejectV1::AccountNotOpened));
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
    assert_eq!(result.status, OrderStatusV1::Rejected);
    assert_eq!(result.reason, Some(OrderRejectV1::InsufficientBalance));
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
    assert_eq!(result.status, OrderStatusV1::Rejected);
    assert_eq!(result.reason, Some(OrderRejectV1::Expired));
    assert_eq!(ledger_len(&h.a).await, 2);
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
    assert_eq!(first.status, OrderStatusV1::Applied);
    wait_for_len(&h.b, 3).await;

    let a_len = ledger_len(&h.a).await;
    let p_len = ledger_len(&h.p).await;
    let b_len = ledger_len(&h.b).await;

    // Resend the identical order in a fresh envelope.
    let dup_env = order_env_with_auth(&h.ua, "0.1", &order, &auth, "0.2.4");
    send_from_user(&h.ua, &dup_env, h.config.hop_timeout).await;
    let dup = recv_order_result(&mut h.ua.sink).await;
    assert_eq!(dup.status, OrderStatusV1::Duplicate);
    assert_eq!(dup.order_hash, order.hash());
    assert!(dup.entry_seq.is_some());
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

    // Sweep far past the deadline: uA gets a synthesized Internal rejection.
    sweep_settlements(
        &h.a.endpoint,
        &h.a.source,
        &h.config,
        &h.a.manager,
        now + SETTLE_TIMEOUT_SECS + 1,
    )
    .await;
    let timeout = recv_order_result(&mut h.ua.sink).await;
    assert_eq!(timeout.status, OrderStatusV1::Rejected);
    assert_eq!(timeout.reason, Some(OrderRejectV1::Internal));

    // A's hop remains; a retry is a duplicate and appends nothing.
    assert_eq!(ledger_len(&h.a).await, a_len);
    let retry = order_env(&h.ua, "0.1", &order, "0.2.4");
    send_from_user(&h.ua, &retry, h.config.hop_timeout).await;
    let dup = recv_order_result(&mut h.ua.sink).await;
    assert_eq!(dup.status, OrderStatusV1::Duplicate);
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
    assert_eq!(result.status, OrderStatusV1::Rejected);
    assert_eq!(result.reason, Some(OrderRejectV1::BadRequest));
    assert_eq!(ledger_len(&h.a).await, 2, "origin guard must not append");
    assert_eq!(ledger_len(&h.p).await, 4);
}

// ── Adversarial F1: forged settlement forwards from a User child ──────────

fn posting(account: AccountRef, delta: i64) -> Posting {
    Posting {
        account,
        delta: SignedAmount::new(delta),
    }
}

/// A fabricated (but shape-valid) hop entry signed by an attacker key.
fn fabricated_hop(signer_addr: &str, order: &PaymentOrder, role: HopRole, seed: u8) -> SettleHopV1 {
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
    SettleHopV1 {
        signer_addr: signer_addr.parse().expect("valid octal address"),
        entry: SignedEntry::sign(entry, &key).unwrap(),
    }
}

fn forged_forward(
    attacker: &User,
    order: &PaymentOrder,
    payer_addr: &str,
    payee_addr: &str,
    hops: Vec<SettleHopV1>,
) -> SettleForwardV1 {
    SettleForwardV1 {
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
    hops: Vec<SettleHopV1>,
    dst: &str,
) {
    let forward = forged_forward(attacker, order, payer_addr, payee_addr, hops);
    let bytes = SettlePayloadV1::Forward(forward).to_bytes().unwrap();
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
