//! Hermetic end-to-end test for the browser value-messaging v1 flow.
//!
//! This drives the **real** `cawala/msg/0` transport against a live leaf node
//! running the [`MsgHandler`] + [`dispatch_ledger_envelope`] drain loop and a
//! shared [`LedgerService`], with two user endpoints A and B under it:
//!
//!   A: signed same-leaf `Direct` `PaymentOrder` -> leaf verifies + appends
//!   leaf -> A: `OrderResult{Applied}` with a verifiable balance receipt
//!   B: `BalanceQuery` -> leaf -> B: signed `BalanceReceipt` for the credit
//!   A re-sends the identical order -> `Duplicate`, no ledger movement
//!   reopen from disk -> same balances; a removed record rejects the sender
//!
//! Everything binds IPv4 loopback with relay mode disabled and explicit
//! `EndpointAddr` hints, so no relay, no DNS, and no external address lookup are
//! used.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cawala_ledger::{
    Amount, Hash, NodeId, OperatorSecretKey, PaymentOrder, PeerKeys, PeerRegistry, PeerRole,
    entry_hash, verify_balance_attestation,
};
use cawala_msg::{
    AckStatus, BalanceQueryV1, LedgerPayloadV1, MSG_LEDGER_V1, OrderRejectV1, OrderStatusV1, OrderV1,
};
use cawala_node::LedgerService;
use cawala_node::identity;
use cawala_node::ledger_peers::save_peers;
use cawala_node::msg::{
    MsgConfig, NeighborSource, RoutableSnapshot, build_envelope, dispatch_ledger_envelope,
    send_envelope, spawn_msg_node_on, spawn_msg_node_with_source_on,
};
use cawala_node::record::{NodeRecord, ParentLink, RecordStore, NODE_RECORD_FILE};
use cawala_topology::ChildKind;
use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMode, SecretKey};
use tokio::sync::mpsc;

/// Per-hop deadline: loopback is fast, but the ledger dispatch runs off the
/// transport path, so leave headroom for the spawn_blocking apply + reply.
fn config() -> MsgConfig {
    MsgConfig {
        hop_timeout: Duration::from_secs(2),
        ..MsgConfig::default()
    }
}

/// Current unix seconds, the caller-supplied clock for ledger ops.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Bind a hermetic endpoint on IPv4 loopback with relays disabled.
async fn hermetic_endpoint(secret: &SecretKey) -> Endpoint {
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

/// A child endpoint's self-view: it sits at `address` under `parent_id`.
fn user_record(node_id: &str, address: &str, parent_id: &str, slot: u8) -> NodeRecord {
    NodeRecord {
        node_id: node_id.to_string(),
        address: Some(address.parse().expect("valid octal address")),
        parent: Some(ParentLink {
            parent_id: parent_id.to_string(),
            slot,
            generation: 0,
        }),
        children: Vec::new(),
        address_epoch: 0,
    }
}

/// Await one ledger reply envelope and decode its payload.
async fn recv_ledger_payload(rx: &mut mpsc::Receiver<cawala_msg::Envelope>) -> LedgerPayloadV1 {
    let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("ledger reply within timeout")
        .expect("ledger reply envelope");
    LedgerPayloadV1::from_bytes(&env.payload).expect("valid ledger payload")
}

/// A leaf that is a root at address `0`, with A at slot 3 and B at slot 4, both
/// registered as `User` peers and with open ledger accounts, and A funded 100.
struct Leaf {
    dir: tempfile::TempDir,
    node_id: String,
    a_endpoint: Endpoint,
    b_endpoint: Endpoint,
    a: NodeId,
    b: NodeId,
    a_operator: OperatorSecretKey,
    a_snap: RoutableSnapshot,
    b_snap: RoutableSnapshot,
    ledger: Arc<tokio::sync::Mutex<LedgerService>>,
    leaf_ledger_pub: cawala_ledger::LedgerPubKey,
    now: u64,
}

/// Stand up the whole fixture: record, peers, ledger, endpoints, live handler,
/// and the dispatch drain loop.
async fn setup() -> (
    Leaf,
    iroh::protocol::Router,
    iroh::protocol::Router,
    iroh::protocol::Router,
    mpsc::Receiver<cawala_msg::Envelope>,
    mpsc::Receiver<cawala_msg::Envelope>,
) {
    let dir = tempfile::tempdir().unwrap();
    let node_secret = identity::load_or_create_secret_key(dir.path()).unwrap();
    let node_id = node_secret.public().to_string();
    let node_operator = OperatorSecretKey::from_bytes(node_secret.to_bytes());

    let a_secret = SecretKey::generate();
    let b_secret = SecretKey::generate();
    let a_id = a_secret.public().to_string();
    let b_id = b_secret.public().to_string();
    let a = NodeId::from(a_id.clone());
    let b = NodeId::from(b_id.clone());
    let a_operator = OperatorSecretKey::from_bytes(a_secret.to_bytes());
    let b_operator = OperatorSecretKey::from_bytes(b_secret.to_bytes());

    // The leaf's persisted record: root address `0`, A/B as user children.
    {
        let mut store = RecordStore::open(dir.path(), &node_id).unwrap();
        store.set_address("0".parse().unwrap()).unwrap();
        store
            .attach_child(a_id.clone(), ChildKind::User, Some(3), 1)
            .unwrap();
        store
            .attach_child(b_id.clone(), ChildKind::User, Some(4), 1)
            .unwrap();
        store.save().unwrap();
    }

    // Register A and B as user peers, exactly as `control approve` does.
    {
        let mut registry = PeerRegistry::new();
        for (id, operator) in [(&a, &a_operator), (&b, &b_operator)] {
            registry
                .insert(PeerKeys {
                    node_id: id.clone(),
                    operator: operator.public(),
                    ledger: None,
                    role: PeerRole::User,
                })
                .unwrap();
        }
        save_peers(dir.path(), &registry).unwrap();
    }

    // Ledger: open both accounts and fund A with 100.
    let now = unix_now();
    let mut service = LedgerService::open(dir.path(), &node_id).unwrap();
    assert!(service.ensure_account_open(&a, ChildKind::User).unwrap());
    assert!(service.ensure_account_open(&b, ChildKind::User).unwrap());
    service.fund(&a, ChildKind::User, 100, &node_operator, 1, now).unwrap();
    assert_eq!(service.balance_of(&a), Amount::new(100));
    let leaf_ledger_pub = service.ledger_key_public();

    // Bind all three endpoints.
    let leaf_endpoint = hermetic_endpoint(&node_secret).await;
    let a_endpoint = hermetic_endpoint(&a_secret).await;
    let b_endpoint = hermetic_endpoint(&b_secret).await;

    // The leaf's live routing view carries hints so replies can be dialed
    // directly; neighbor status itself comes from node.json.
    let mut hints = HashMap::new();
    hints.insert(a_id.clone(), a_endpoint.addr());
    hints.insert(b_id.clone(), b_endpoint.addr());
    let source = NeighborSource::live(dir.path(), &node_id, hints).unwrap();

    let config = config();
    let (leaf_router, mut leaf_rx) =
        spawn_msg_node_with_source_on(leaf_endpoint.clone(), source.clone(), config.clone());

    // Dispatch drain loop, mirroring `run()`'s sink consumer.
    let ledger = Arc::new(tokio::sync::Mutex::new(service));
    let manager = Arc::new(tokio::sync::Mutex::new(cawala_node::SettlementManager::new()));
    {
        let dispatch_dir = dir.path().to_path_buf();
        let dispatch_node = node_id.clone();
        let dispatch_source = source.clone();
        let dispatch_ledger = Arc::clone(&ledger);
        let dispatch_manager = Arc::clone(&manager);
        let dispatch_endpoint = leaf_endpoint.clone();
        let dispatch_config = config.clone();
        let _dispatch = tokio::spawn(async move {
            while let Some(env) = leaf_rx.recv().await {
                dispatch_ledger_envelope(
                    &dispatch_endpoint,
                    &dispatch_source,
                    &dispatch_config,
                    &dispatch_ledger,
                    &dispatch_manager,
                    &dispatch_dir,
                    &dispatch_node,
                    env,
                )
                .await;
            }
        });
    }

    // A's and B's own views: children of the leaf in slots 3 and 4.
    let a_snap = {
        let mut snap = RoutableSnapshot::from_record(&user_record(&a_id, "0.3", &node_id, 3)).unwrap();
        snap.hints.insert(node_id.clone(), leaf_endpoint.addr());
        snap
    };
    let b_snap = {
        let mut snap = RoutableSnapshot::from_record(&user_record(&b_id, "0.4", &node_id, 4)).unwrap();
        snap.hints.insert(node_id.clone(), leaf_endpoint.addr());
        snap
    };
    let (a_router, a_rx) = spawn_msg_node_on(a_endpoint.clone(), a_snap.clone(), config.clone());
    let (b_router, b_rx) = spawn_msg_node_on(b_endpoint.clone(), b_snap.clone(), config.clone());

    let leaf = Leaf {
        dir,
        node_id,
        a_endpoint,
        b_endpoint,
        a,
        b,
        a_operator,
        a_snap,
        b_snap,
        ledger,
        leaf_ledger_pub,
        now,
    };
    (leaf, leaf_router, a_router, b_router, a_rx, b_rx)
}

/// Build and send a signed `Order` envelope from A to the leaf.
fn order_envelope(leaf: &Leaf, order: &PaymentOrder) -> cawala_msg::Envelope {
    let auth = order.authorize(&leaf.a_operator).unwrap();
    let payload = LedgerPayloadV1::Order(OrderV1 {
        order: order.clone(),
        auth,
    })
    .to_bytes()
    .unwrap();
    build_envelope(
        &leaf.a_snap.routable.this,
        "0".parse().unwrap(),
        MSG_LEDGER_V1,
        payload,
        config().ttl,
    )
    .unwrap()
}

#[tokio::test]
async fn same_leaf_payment_flow_applies_duplicates_and_survives_reopen() {
    let (leaf, leaf_router, _a_router, _b_router, mut a_rx, mut b_rx) = setup().await;

    // ---- A sends a signed same-leaf Direct order to B (25) ----------------
    let order = PaymentOrder {
        from: leaf.a.clone(),
        to: leaf.b.clone(),
        amount: Amount::new(25),
        nonce: 7,
        expiry: leaf.now + 3600,
    };
    let env = order_envelope(&leaf, &order);
    let ack = send_envelope(
        &leaf.a_endpoint,
        &leaf.a_snap,
        &env,
        config().hop_timeout,
    )
    .await
    .unwrap();
    assert_eq!(ack.status, AckStatus::Delivered);

    // ---- A receives Applied + a verifiable balance receipt (75) ----------
    let reply = recv_ledger_payload(&mut a_rx).await;
    let LedgerPayloadV1::OrderResult(result) = reply else {
        panic!("expected an OrderResult, got {reply:?}");
    };
    assert_eq!(result.reply_to, env.msg_id);
    assert_eq!(result.order_hash, order.hash());
    assert_eq!(result.status, OrderStatusV1::Applied);
    assert_eq!(result.reason, None);

    let balance = result
        .balance
        .expect("an applied result carries a balance receipt");
    assert_eq!(balance.ledger_pubkey, leaf.leaf_ledger_pub);
    assert_eq!(balance.attestation.edge.parent, NodeId::from(leaf.node_id.clone()));
    assert_eq!(balance.attestation.edge.child, leaf.a);
    assert_eq!(balance.attestation.balance, Amount::new(75));
    verify_balance_attestation(
        &balance.attestation,
        &balance.commitment,
        &leaf.leaf_ledger_pub,
    )
    .unwrap();

    // The payer's own receipt history shows the Direct transfer.
    assert_eq!(balance.history.len(), 1);
    assert_eq!(balance.history[0].from, leaf.a);
    assert_eq!(balance.history[0].to, leaf.b);
    assert_eq!(balance.history[0].amount, Amount::new(25));
    assert_eq!(balance.history[0].payment_id, order.hash());

    // The ledger moved: A 75, B 25, four entries (open A/B, issue A, transfer).
    {
        let service = leaf.ledger.lock().await;
        assert_eq!(service.balance_of(&leaf.a), Amount::new(75));
        assert_eq!(service.balance_of(&leaf.b), Amount::new(25));
        assert_eq!(service.ledger().len(), 4);
    }

    // ---- B queries its balance and sees the credit (25) ------------------
    let query_payload = LedgerPayloadV1::BalanceQuery(BalanceQueryV1 { query_id: 99 })
        .to_bytes()
        .unwrap();
    let query = build_envelope(
        &leaf.b_snap.routable.this,
        "0".parse().unwrap(),
        MSG_LEDGER_V1,
        query_payload,
        config().ttl,
    )
    .unwrap();
    let qack = send_envelope(
        &leaf.b_endpoint,
        &leaf.b_snap,
        &query,
        config().hop_timeout,
    )
    .await
    .unwrap();
    assert_eq!(qack.status, AckStatus::Delivered);

    let qreply = recv_ledger_payload(&mut b_rx).await;
    let LedgerPayloadV1::BalanceReceipt(receipt) = qreply else {
        panic!("expected a BalanceReceipt, got {qreply:?}");
    };
    assert_eq!(receipt.reply_to, Some(query.msg_id));
    assert_eq!(receipt.query_id, Some(99));
    assert_eq!(receipt.attestation.edge.parent, NodeId::from(leaf.node_id.clone()));
    assert_eq!(receipt.attestation.edge.child, leaf.b);
    assert_eq!(receipt.attestation.balance, Amount::new(25));
    verify_balance_attestation(
        &receipt.attestation,
        &receipt.commitment,
        &leaf.leaf_ledger_pub,
    )
    .unwrap();

    // ---- Re-send the same order in a fresh envelope -> Duplicate ----------
    let len_before = leaf.ledger.lock().await.ledger().len();
    let dup_env = order_envelope(&leaf, &order);
    let dack = send_envelope(
        &leaf.a_endpoint,
        &leaf.a_snap,
        &dup_env,
        config().hop_timeout,
    )
    .await
    .unwrap();
    assert_eq!(dack.status, AckStatus::Delivered);

    let dreply = recv_ledger_payload(&mut a_rx).await;
    let LedgerPayloadV1::OrderResult(dup) = dreply else {
        panic!("expected an OrderResult, got {dreply:?}");
    };
    assert_eq!(dup.order_hash, order.hash());
    assert_eq!(dup.status, OrderStatusV1::Duplicate);
    assert_eq!(dup.reason, None);
    assert_eq!(dup.entry_seq, result.entry_seq);
    assert_eq!(dup.entry_hash, result.entry_hash);
    let dup_balance = dup.balance.expect("a duplicate carries a balance receipt");
    assert_eq!(dup_balance.attestation.balance, Amount::new(75));

    // The duplicate must not append: length and balances are unchanged.
    {
        let service = leaf.ledger.lock().await;
        assert_eq!(service.ledger().len(), len_before);
        assert_eq!(service.balance_of(&leaf.a), Amount::new(75));
        assert_eq!(service.balance_of(&leaf.b), Amount::new(25));
    }

    // ---- Re-sending the exact same envelope is a transport Duplicate ------
    // (the leaf's `SeenSet` answers without dispatching a second order).
    let sack = send_envelope(
        &leaf.a_endpoint,
        &leaf.a_snap,
        &env,
        config().hop_timeout,
    )
    .await
    .unwrap();
    assert_eq!(sack.status, AckStatus::Duplicate);
    assert!(a_rx.try_recv().is_err(), "no second ledger reply is delivered");

    // ---- Reopen from disk: same balances and chain length -----------------
    let reopened = LedgerService::open(leaf.dir.path(), &leaf.node_id).unwrap();
    assert_eq!(reopened.balance_of(&leaf.a), Amount::new(75));
    assert_eq!(reopened.balance_of(&leaf.b), Amount::new(25));
    assert_eq!(reopened.ledger().len(), len_before);
    assert_eq!(reopened.ledger_key_public(), leaf.leaf_ledger_pub);

    // ---- Removing the record rejects a fresh sender at the leaf -----------
    // With `node.json` gone, the live source falls back to its last-good view
    // (A is still a direct neighbor, so the envelope is accepted and queued),
    // but the dispatch loop reloads a fresh, child-less record and answers with
    // `Rejected(NotAChild)` rather than silently dropping the sender.
    std::fs::remove_file(leaf.dir.path().join(NODE_RECORD_FILE)).unwrap();
    let late = PaymentOrder {
        from: leaf.a.clone(),
        to: leaf.b.clone(),
        amount: Amount::new(5),
        nonce: 8,
        expiry: leaf.now + 3600,
    };
    let late_env = order_envelope(&leaf, &late);
    let lack = send_envelope(
        &leaf.a_endpoint,
        &leaf.a_snap,
        &late_env,
        config().hop_timeout,
    )
    .await
    .unwrap();
    assert_eq!(lack.status, AckStatus::Delivered);

    let lreply = recv_ledger_payload(&mut a_rx).await;
    let LedgerPayloadV1::OrderResult(late_result) = lreply else {
        panic!("expected an OrderResult, got {lreply:?}");
    };
    assert_eq!(late_result.order_hash, late.hash());
    assert_eq!(late_result.status, OrderStatusV1::Rejected);
    assert_eq!(late_result.reason, Some(OrderRejectV1::NotAChild));
    assert!(late_result.balance.is_none());
    assert_eq!(leaf.ledger.lock().await.ledger().len(), len_before);

    leaf_router.shutdown().await.unwrap();
}

/// Two `LedgerService` instances on the same data dir serialize their writes via
/// the per-transaction ledger lock, so a CLI process and a running node can both
/// append without corruption and reconcile on reopen.
#[test]
fn two_services_on_one_data_dir_append_serialized_and_reconcile() {
    let dir = tempfile::tempdir().unwrap();
    let node_secret = identity::load_or_create_secret_key(dir.path()).unwrap();
    let node_id = node_secret.public().to_string();
    let operator = OperatorSecretKey::from_bytes(node_secret.to_bytes());
    let a = NodeId::from("user-a");
    let b = NodeId::from("user-b");
    let now = unix_now();

    // A "running node" service and a separate "CLI" service on the same dir.
    let mut node = LedgerService::open(dir.path(), &node_id).unwrap();
    node.ensure_account_open(&a, ChildKind::User).unwrap();
    let mut cli = LedgerService::open(dir.path(), &node_id).unwrap();

    // Interleaved appends from both processes (each refreshes under the lock).
    node.fund(&a, ChildKind::User, 100, &operator, 1, now).unwrap();
    cli.fund(&b, ChildKind::User, 50, &operator, 2, now).unwrap();
    node.fund(&a, ChildKind::User, 25, &operator, 3, now).unwrap();

    // A fresh open reconciles every append into one dense, linked chain.
    let reopened = LedgerService::open(dir.path(), &node_id).unwrap();
    assert_eq!(reopened.balance_of(&a), Amount::new(125));
    assert_eq!(reopened.balance_of(&b), Amount::new(50));
    // open A, issue A(100), open B, issue B(50), issue A(25) = 5 entries.
    assert_eq!(reopened.ledger().len(), 5);
    let mut prev = Hash::ZERO;
    for index in 0..reopened.ledger().len() {
        let entry = reopened.ledger().get(index).unwrap().unwrap();
        assert_eq!(entry.entry.seq, index as u64);
        assert_eq!(entry.entry.prev_hash, prev);
        prev = entry_hash(&entry.entry).unwrap();
    }
    assert_eq!(reopened.ledger().head_hash(), prev);
}

/// While another writer holds the exclusive ledger lock, a service mutation must
/// fail fast (no append), and must succeed once the lock is released.
#[test]
fn service_mutation_fails_fast_while_the_write_lock_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let node_secret = identity::load_or_create_secret_key(dir.path()).unwrap();
    let node_id = node_secret.public().to_string();
    let operator = OperatorSecretKey::from_bytes(node_secret.to_bytes());
    let a = NodeId::from("user-a");
    let now = unix_now();

    let mut service = LedgerService::open(dir.path(), &node_id).unwrap();

    // Simulate a concurrent writer holding the transaction lock.
    let held = cawala_node::LedgerLock::acquire_exclusive(dir.path()).unwrap();
    let err = service
        .fund(&a, ChildKind::User, 10, &operator, 1, now)
        .unwrap_err();
    assert!(
        err.to_string().contains("locked by another cawala writer"),
        "unexpected error: {err}"
    );
    assert_eq!(
        service.balance_of(&a),
        Amount::new(0),
        "a contended mutation must not append"
    );

    // Releasing the lock lets the same mutation through.
    drop(held);
    service
        .fund(&a, ChildKind::User, 10, &operator, 1, now)
        .unwrap();
    assert_eq!(service.balance_of(&a), Amount::new(10));
}
