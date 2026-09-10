//! Hermetic integration tests for the native `cawala/msg/0` handler.
//!
//! No relay and no external address lookup are used: every endpoint binds to
//! IPv4 loopback with relay mode disabled, and each routing snapshot gets
//! explicit address hints taken from `Endpoint::addr()` so direct dialing of a
//! neighbor always works.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use cawala_msg::{
    AckStatus, Envelope, MAX_NODE_ID_LEN, MSG_LEDGER_V1, MsgId, PeerRef, RejectReason,
};
use cawala_node::msg::{
    MsgConfig, MsgHandler, RoutableSnapshot, build_envelope, send_envelope, spawn_msg_node_on,
};
use cawala_node::record::{ChildEntry, NodeRecord, ParentLink};
use cawala_topology::ChildKind;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use tokio::sync::mpsc;

/// Default test config: a generous per-hop deadline for loopback exchanges.
fn config() -> MsgConfig {
    MsgConfig {
        hop_timeout: Duration::from_secs(2),
        ..MsgConfig::default()
    }
}

/// Config with a short deadline for tests that must fail fast.
fn short_config() -> MsgConfig {
    MsgConfig {
        hop_timeout: Duration::from_millis(300),
        ..MsgConfig::default()
    }
}

/// Bind a hermetic endpoint on IPv4 loopback with relays disabled.
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

/// Bind one endpoint per key and collect their addresses for hinting.
async fn bind_all(keys: &[SecretKey]) -> (Vec<Endpoint>, HashMap<EndpointId, EndpointAddr>) {
    let mut endpoints = Vec::with_capacity(keys.len());
    let mut addrs = HashMap::new();
    for key in keys {
        let endpoint = bind(key).await;
        addrs.insert(key.public(), endpoint.addr());
        endpoints.push(endpoint);
    }
    (endpoints, addrs)
}

/// Build a node record directly.
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

/// Derive a snapshot and fill hints for every neighbor from `addrs`.
///
/// Hint keys are canonicalized to the `EndpointId` `Display` form, matching the
/// canonical ids `RoutableSnapshot::from_record` stores.
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

/// A running node: router + locally delivered envelopes.
struct TestNode {
    router: Router,
    rx: mpsc::Receiver<Envelope>,
    endpoint: Endpoint,
    snapshot: RoutableSnapshot,
}

impl TestNode {
    fn spawn(
        endpoint: Endpoint,
        record: NodeRecord,
        addrs: &HashMap<EndpointId, EndpointAddr>,
        config: MsgConfig,
    ) -> Self {
        let snap = snapshot(&record, addrs);
        let (router, rx) = spawn_msg_node_on(endpoint.clone(), snap.clone(), config);
        TestNode {
            router,
            rx,
            endpoint,
            snapshot: snap,
        }
    }

    async fn shutdown(self) {
        self.router.shutdown().await.expect("router shutdown");
    }
}

#[tokio::test]
async fn local_delivery_same_node() {
    let self_key = SecretKey::generate();
    let child_key = SecretKey::generate();
    let self_id = self_key.public().to_string();
    let child_id = child_key.public().to_string();

    let endpoint = bind(&self_key).await;
    let rec = record(
        &self_id,
        "0",
        None,
        &[(child_id.as_str(), 1, ChildKind::Node)],
    );
    let snap = RoutableSnapshot::from_record(&rec).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let handler = MsgHandler::new(endpoint.clone(), snap, config(), tx);

    // A direct neighbor (the child) sends an envelope whose destination is us.
    let src = PeerRef {
        addr: "0.1".parse().unwrap(),
        node: child_id.clone(),
    };
    let env = build_envelope(
        &src,
        "0".parse().unwrap(),
        MSG_LEDGER_V1,
        b"local".to_vec(),
        8,
    )
    .unwrap();

    let ack = handler.handle(child_key.public(), env).await;
    assert_eq!(ack.status, AckStatus::Delivered);

    let got = rx.recv().await.unwrap();
    assert_eq!(got.payload, b"local");
    assert_eq!(got.dst, "0".parse().unwrap());

    endpoint.close().await;
}

#[tokio::test]
async fn two_node_parent_child_roundtrip() {
    let parent_key = SecretKey::generate();
    let child_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let child_id = child_key.public().to_string();

    let (endpoints, addrs) = bind_all(&[parent_key, child_key]).await;
    let parent_rec = record(
        &parent_id,
        "0",
        None,
        &[(child_id.as_str(), 1, ChildKind::Node)],
    );
    let child_rec = record(&child_id, "0.1", Some((parent_id.as_str(), 1)), &[]);

    let mut parent = TestNode::spawn(endpoints[0].clone(), parent_rec, &addrs, config());
    let mut child = TestNode::spawn(endpoints[1].clone(), child_rec, &addrs, config());

    // child -> parent: the parent is the destination, so it delivers locally.
    let up = build_envelope(
        &child.snapshot.routable.this,
        "0".parse().unwrap(),
        MSG_LEDGER_V1,
        b"up".to_vec(),
        8,
    )
    .unwrap();
    let ack = send_envelope(&child.endpoint, &child.snapshot, &up, config().hop_timeout)
        .await
        .unwrap();
    assert_eq!(ack.status, AckStatus::Delivered);
    let got = parent.rx.recv().await.unwrap();
    assert_eq!(got.payload, b"up");
    assert_eq!(got.src.node, child_id);

    // parent -> child: forwarded one hop, delivered locally at the child.
    let down = build_envelope(
        &parent.snapshot.routable.this,
        "0.1".parse().unwrap(),
        MSG_LEDGER_V1,
        b"down".to_vec(),
        8,
    )
    .unwrap();
    let ack = send_envelope(
        &parent.endpoint,
        &parent.snapshot,
        &down,
        config().hop_timeout,
    )
    .await
    .unwrap();
    assert_eq!(ack.status, AckStatus::Delivered);
    let got = child.rx.recv().await.unwrap();
    assert_eq!(got.payload, b"down");
    assert_eq!(got.src.node, parent_id);

    parent.shutdown().await;
    child.shutdown().await;
}

#[tokio::test]
async fn three_node_up_then_down_via_lca() {
    let root_key = SecretKey::generate();
    let a_key = SecretKey::generate();
    let b_key = SecretKey::generate();
    let root_id = root_key.public().to_string();
    let a_id = a_key.public().to_string();
    let b_id = b_key.public().to_string();

    let (endpoints, addrs) = bind_all(&[root_key, a_key, b_key]).await;
    let root_rec = record(&root_id, "0", None, &[(a_id.as_str(), 1, ChildKind::Node)]);
    let a_rec = record(
        &a_id,
        "0.1",
        Some((root_id.as_str(), 1)),
        &[(b_id.as_str(), 2, ChildKind::Node)],
    );
    let b_rec = record(&b_id, "0.1.2", Some((a_id.as_str(), 2)), &[]);

    let mut root = TestNode::spawn(endpoints[0].clone(), root_rec, &addrs, config());
    let mut a = TestNode::spawn(endpoints[1].clone(), a_rec, &addrs, config());
    let mut b = TestNode::spawn(endpoints[2].clone(), b_rec, &addrs, config());

    // b -> root ascends through a; a forwards, root delivers.
    let up = build_envelope(
        &b.snapshot.routable.this,
        "0".parse().unwrap(),
        MSG_LEDGER_V1,
        b"b-to-root".to_vec(),
        8,
    )
    .unwrap();
    let ack = send_envelope(&b.endpoint, &b.snapshot, &up, config().hop_timeout)
        .await
        .unwrap();
    assert_eq!(ack.status, AckStatus::Delivered);
    let got = root.rx.recv().await.unwrap();
    assert_eq!(got.payload, b"b-to-root");
    assert!(
        a.rx.try_recv().is_err(),
        "a must not deliver to its own sink"
    );

    // root -> b descends through a; a forwards, b delivers.
    let down = build_envelope(
        &root.snapshot.routable.this,
        "0.1.2".parse().unwrap(),
        MSG_LEDGER_V1,
        b"root-to-b".to_vec(),
        8,
    )
    .unwrap();
    let ack = send_envelope(&root.endpoint, &root.snapshot, &down, config().hop_timeout)
        .await
        .unwrap();
    assert_eq!(ack.status, AckStatus::Delivered);
    let got = b.rx.recv().await.unwrap();
    assert_eq!(got.payload, b"root-to-b");
    assert!(
        a.rx.try_recv().is_err(),
        "a must not deliver to its own sink"
    );

    root.shutdown().await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn forward_to_user_child() {
    let root_key = SecretKey::generate();
    let a_key = SecretKey::generate();
    let user_key = SecretKey::generate();
    let root_id = root_key.public().to_string();
    let a_id = a_key.public().to_string();
    let user_id = user_key.public().to_string();

    let (endpoints, addrs) = bind_all(&[root_key, a_key, user_key]).await;
    let root_rec = record(&root_id, "0", None, &[(a_id.as_str(), 1, ChildKind::Node)]);
    let a_rec = record(
        &a_id,
        "0.1",
        Some((root_id.as_str(), 1)),
        &[(user_id.as_str(), 3, ChildKind::User)],
    );
    let user_rec = record(&user_id, "0.1.3", Some((a_id.as_str(), 3)), &[]);

    let root = TestNode::spawn(endpoints[0].clone(), root_rec, &addrs, config());
    let mut a = TestNode::spawn(endpoints[1].clone(), a_rec, &addrs, config());
    let mut user = TestNode::spawn(endpoints[2].clone(), user_rec, &addrs, config());

    let env = build_envelope(
        &root.snapshot.routable.this,
        "0.1.3".parse().unwrap(),
        MSG_LEDGER_V1,
        b"for-user".to_vec(),
        8,
    )
    .unwrap();
    let ack = send_envelope(&root.endpoint, &root.snapshot, &env, config().hop_timeout)
        .await
        .unwrap();
    assert_eq!(ack.status, AckStatus::Delivered);

    let got = user.rx.recv().await.unwrap();
    assert_eq!(got.payload, b"for-user");
    assert!(a.rx.try_recv().is_err());

    root.shutdown().await;
    a.shutdown().await;
    user.shutdown().await;
}

#[tokio::test]
async fn replay_is_duplicate_and_delivers_once() {
    let parent_key = SecretKey::generate();
    let child_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let child_id = child_key.public().to_string();

    let (endpoints, addrs) = bind_all(&[parent_key, child_key]).await;
    let parent_rec = record(
        &parent_id,
        "0",
        None,
        &[(child_id.as_str(), 1, ChildKind::Node)],
    );
    let child_rec = record(&child_id, "0.1", Some((parent_id.as_str(), 1)), &[]);

    let mut parent = TestNode::spawn(endpoints[0].clone(), parent_rec, &addrs, config());
    let child = TestNode::spawn(endpoints[1].clone(), child_rec, &addrs, config());

    let env = build_envelope(
        &child.snapshot.routable.this,
        "0".parse().unwrap(),
        MSG_LEDGER_V1,
        b"once".to_vec(),
        8,
    )
    .unwrap();

    let first = send_envelope(&child.endpoint, &child.snapshot, &env, config().hop_timeout)
        .await
        .unwrap();
    assert_eq!(first.status, AckStatus::Delivered);
    let got = parent.rx.recv().await.unwrap();
    assert_eq!(got.payload, b"once");

    let second = send_envelope(&child.endpoint, &child.snapshot, &env, config().hop_timeout)
        .await
        .unwrap();
    assert_eq!(second.status, AckStatus::Duplicate);
    assert!(
        parent.rx.try_recv().is_err(),
        "duplicate must not re-deliver"
    );

    parent.shutdown().await;
    child.shutdown().await;
}

#[tokio::test]
async fn loop_hop_chain_rejected() {
    let self_key = SecretKey::generate();
    let self_id = self_key.public().to_string();

    let endpoint = bind(&self_key).await;
    let rec = record(&self_id, "0", None, &[]);
    let snap = RoutableSnapshot::from_record(&rec).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let handler = MsgHandler::new(endpoint.clone(), snap, config(), tx);

    // The origin is this node, so the chain already contains the receiver.
    let src = PeerRef {
        addr: "0".parse().unwrap(),
        node: self_id.clone(),
    };
    let env = build_envelope(
        &src,
        "0.2".parse().unwrap(),
        MSG_LEDGER_V1,
        b"loop".to_vec(),
        8,
    )
    .unwrap();

    let ack = handler.handle(self_key.public(), env).await;
    assert_eq!(ack.status, AckStatus::Rejected(RejectReason::BadHopChain));
    assert!(rx.try_recv().is_err());

    endpoint.close().await;
}

#[tokio::test]
async fn wrong_last_hop_rejected() {
    let self_key = SecretKey::generate();
    let child_key = SecretKey::generate();
    let unknown_key = SecretKey::generate();
    let self_id = self_key.public().to_string();
    let child_id = child_key.public().to_string();
    let unknown_id = unknown_key.public().to_string();

    let endpoint = bind(&self_key).await;
    let rec = record(
        &self_id,
        "0",
        None,
        &[(child_id.as_str(), 1, ChildKind::Node)],
    );
    let snap = RoutableSnapshot::from_record(&rec).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let handler = MsgHandler::new(endpoint.clone(), snap, config(), tx);

    // The last hop matches the QUIC remote, but it is not a configured neighbor.
    let src = PeerRef {
        addr: "0.5".parse().unwrap(),
        node: unknown_id,
    };
    let env = build_envelope(
        &src,
        "0.6".parse().unwrap(),
        MSG_LEDGER_V1,
        b"stranger".to_vec(),
        8,
    )
    .unwrap();

    let ack = handler.handle(unknown_key.public(), env).await;
    assert_eq!(ack.status, AckStatus::Rejected(RejectReason::NotNeighbor));
    assert!(rx.try_recv().is_err());

    endpoint.close().await;
}

#[tokio::test]
async fn ttl_exhausted_rejected() {
    let a_key = SecretKey::generate();
    let root_key = SecretKey::generate();
    let c_key = SecretKey::generate();
    let a_id = a_key.public().to_string();
    let root_id = root_key.public().to_string();
    let c_id = c_key.public().to_string();

    let endpoint = bind(&a_key).await;
    let rec = record(
        &a_id,
        "0.1",
        Some((root_id.as_str(), 1)),
        &[(c_id.as_str(), 2, ChildKind::Node)],
    );
    let snap = RoutableSnapshot::from_record(&rec).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let handler = MsgHandler::new(endpoint.clone(), snap, config(), tx);

    // A child sends toward an unrelated subtree, so forwarding is required,
    // but the TTL is already exhausted.
    let src = PeerRef {
        addr: "0.1.2".parse().unwrap(),
        node: c_id.clone(),
    };
    let env = build_envelope(
        &src,
        "0.3".parse().unwrap(),
        MSG_LEDGER_V1,
        b"no-ttl".to_vec(),
        0,
    )
    .unwrap();

    let ack = handler.handle(c_key.public(), env).await;
    assert_eq!(ack.status, AckStatus::Rejected(RejectReason::TtlExpired));
    assert!(rx.try_recv().is_err());

    endpoint.close().await;
}

#[tokio::test]
async fn root_no_route_rejected() {
    let root_key = SecretKey::generate();
    let child_key = SecretKey::generate();
    let root_id = root_key.public().to_string();
    let child_id = child_key.public().to_string();

    let endpoint = bind(&root_key).await;
    let rec = record(
        &root_id,
        "0",
        None,
        &[(child_id.as_str(), 1, ChildKind::Node)],
    );
    let snap = RoutableSnapshot::from_record(&rec).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let handler = MsgHandler::new(endpoint.clone(), snap, config(), tx);

    // Slot 4 is empty at the root, so there is no route.
    let src = PeerRef {
        addr: "0.1".parse().unwrap(),
        node: child_id.clone(),
    };
    let env = build_envelope(
        &src,
        "0.4".parse().unwrap(),
        MSG_LEDGER_V1,
        b"nowhere".to_vec(),
        8,
    )
    .unwrap();

    let ack = handler.handle(child_key.public(), env).await;
    assert_eq!(ack.status, AckStatus::Rejected(RejectReason::NoRoute));
    assert!(rx.try_recv().is_err());

    endpoint.close().await;
}

#[tokio::test]
async fn unreachable_next_hop_reports_rejection() {
    let root_key = SecretKey::generate();
    let x_key = SecretKey::generate();
    let y_key = SecretKey::generate();
    let root_id = root_key.public().to_string();
    let x_id = x_key.public().to_string();
    let y_id = y_key.public().to_string();

    let endpoint = bind(&root_key).await;
    let rec = record(
        &root_id,
        "0",
        None,
        &[
            (x_id.as_str(), 1, ChildKind::Node),
            (y_id.as_str(), 2, ChildKind::Node),
        ],
    );
    let mut snap = RoutableSnapshot::from_record(&rec).unwrap();

    // X's hint is a bogus endpoint with no reachable addresses.
    let bogus = SecretKey::generate().public();
    snap.hints.insert(x_id.clone(), EndpointAddr::from(bogus));

    let (tx, mut rx) = mpsc::channel(8);
    let handler = MsgHandler::new(endpoint.clone(), snap, short_config(), tx);

    // Y (a neighbor) sends into X's subtree, forcing a forward to the bogus X.
    let src = PeerRef {
        addr: "0.2".parse().unwrap(),
        node: y_id.clone(),
    };
    let env = build_envelope(
        &src,
        "0.1.5".parse().unwrap(),
        MSG_LEDGER_V1,
        b"to-x".to_vec(),
        8,
    )
    .unwrap();

    let ack = handler.handle(y_key.public(), env).await;
    assert_eq!(ack.status, AckStatus::Rejected(RejectReason::Unreachable));
    assert!(rx.try_recv().is_err());

    endpoint.close().await;
}

#[tokio::test]
async fn retry_after_unreachable_is_not_duplicate() {
    let a_key = SecretKey::generate();
    let mid_key = SecretKey::generate();
    let c_key = SecretKey::generate();
    let a_id = a_key.public().to_string();
    let mid_id = mid_key.public().to_string();
    let c_id = c_key.public().to_string();
    let c_public = c_key.public();

    let (endpoints, addrs) = bind_all(&[mid_key, c_key]).await;
    let mid_endpoint = &endpoints[0];
    let c_endpoint = &endpoints[1];
    let c_addr = addrs[&c_public].clone();

    // The forwarder's view: parent A, child C. C's hint starts out bogus, so
    // the first forward fails transiently.
    let mid_rec = record(
        &mid_id,
        "0.1",
        Some((a_id.as_str(), 1)),
        &[(c_id.as_str(), 2, ChildKind::Node)],
    );
    let mut mid_snap = RoutableSnapshot::from_record(&mid_rec).unwrap();
    let bogus = SecretKey::generate().public();
    mid_snap
        .hints
        .insert(c_id.clone(), EndpointAddr::from(bogus));

    let (tx, mut mid_rx) = mpsc::channel(8);
    let mut mid = MsgHandler::new(mid_endpoint.clone(), mid_snap, config(), tx);

    // C is a live node that will accept and deliver the forwarded envelope.
    let c_rec = record(&c_id, "0.1.2", Some((mid_id.as_str(), 2)), &[]);
    let mut c_node = TestNode::spawn(c_endpoint.clone(), c_rec, &HashMap::new(), config());

    let env = build_envelope(
        &PeerRef {
            addr: "0".parse().unwrap(),
            node: a_id.clone(),
        },
        "0.1.2".parse().unwrap(),
        MSG_LEDGER_V1,
        b"retry".to_vec(),
        8,
    )
    .unwrap();

    // First attempt: the bogus hint makes the next hop unreachable.
    let first = mid.handle(a_key.public(), env.clone()).await;
    assert_eq!(first.status, AckStatus::Rejected(RejectReason::Unreachable));
    assert!(mid_rx.try_recv().is_err());
    assert!(c_node.rx.try_recv().is_err());

    // Repair the hint with C's real address and resend the SAME envelope: the
    // transient rejection must not have left a replay mark, so this is not
    // answered `Duplicate` and the sink receives it exactly once.
    mid.set_hint(&c_id, c_addr).unwrap();
    let second = mid.handle(a_key.public(), env.clone()).await;
    assert_eq!(second.msg_id, env.msg_id);
    assert_eq!(second.status, AckStatus::Delivered);

    let got = c_node.rx.recv().await.unwrap();
    assert_eq!(got.payload, b"retry");
    assert!(c_node.rx.try_recv().is_err());

    mid_endpoint.close().await;
    c_node.shutdown().await;
}

#[tokio::test]
async fn long_node_id_is_rejected() {
    let self_key = SecretKey::generate();
    let self_id = self_key.public().to_string();

    let endpoint = bind(&self_key).await;
    let rec = record(&self_id, "0", None, &[]);
    let snap = RoutableSnapshot::from_record(&rec).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let handler = MsgHandler::new(endpoint.clone(), snap, config(), tx);

    let src = PeerRef {
        addr: "0".parse().unwrap(),
        node: "a".repeat(MAX_NODE_ID_LEN + 1),
    };
    let env = Envelope::new(
        src,
        "0.1".parse().unwrap(),
        MsgId::from_bytes([0x11; 16]),
        MSG_LEDGER_V1,
        1,
        b"oversized".to_vec(),
    );

    let ack = handler.handle(self_key.public(), env).await;
    assert_eq!(ack.status, AckStatus::Rejected(RejectReason::BadPayload));
    assert!(rx.try_recv().is_err());

    endpoint.close().await;
}
