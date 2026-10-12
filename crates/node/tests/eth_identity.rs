//! End-to-end integration tests for a user leaf's Ethereum anchor registration
//! and rotation (control v9 variant 24), driven over the **real** direct
//! `cawala/control/0` transport with a running node engine, plus the R1b
//! `Capabilities` handshake (variant 23).
//!
//! The inline unit tests in `crates/node/src/control.rs` exercise the handler
//! in-process; these prove the same write-once / incumbent-authorized contract
//! (spec Addendum B/C §3/§5) end-to-end: frame signing, the node's
//! precheck/replay/authority path, the persisted `ChildEntry.eth_address`, and
//! the reply bytes on the wire.
//!
//! Harness: every endpoint binds to IPv4 loopback with relays disabled and no
//! address lookup, and requests are dialed with an explicit [`EndpointAddr`]
//! hint from `Endpoint::addr()`.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cawala_control::{
    CONTROL_REQUEST_TTL_SECS, Capabilities, ChildKind, ControlReply, ControlRequest,
    NodeCapabilities, NodeId, OperatorSecretKey, RegisterEthAddress, RejectCode, SignedControl,
};
use cawala_eth::{EthProof, SigningKey as EthSigningKey};
use cawala_ledger::{PeerKeys, PeerRegistry, PeerRole};
use cawala_node::control::{
    ControlNode, NODE_CLIENT_API_VERSION, NODE_FEATURE_ETH_IDENTITY, spawn_control_only_on,
};
use cawala_node::control_store::ControlStore;
use cawala_node::record::RecordStore;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use tokio::sync::Mutex;

/// Per-exchange deadline for loopback tests.
fn timeout() -> Duration {
    Duration::from_secs(3)
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A process-unique request nonce, so distinct requests are never conflated by
/// the engine's replay guard.
fn fresh_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

/// Sign a control request at the current wall clock.
fn authorize(origin: NodeId, op: &OperatorSecretKey, request: ControlRequest) -> SignedControl {
    SignedControl::authorize(
        origin,
        op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        request,
    )
    .expect("sign control request")
}

fn node(id: &str) -> NodeId {
    NodeId::from(id)
}

/// The operator key derived from an iroh node key (`seed == NodeId == operator`).
fn operator(secret: &SecretKey) -> OperatorSecretKey {
    OperatorSecretKey::from_bytes(secret.to_bytes())
}

/// A `User` peer row (browsers are leaves and carry no ledger key).
fn user_peer(id: &str, op: &OperatorSecretKey) -> PeerKeys {
    PeerKeys {
        node_id: node(id),
        operator: op.public(),
        ledger: None,
        role: PeerRole::User,
    }
}

/// A `Node` peer row.
fn node_peer(id: &str, op: &OperatorSecretKey, ledger_seed: u8) -> PeerKeys {
    let ledger = cawala_ledger::LedgerSecretKey::from_bytes([ledger_seed; 32]).public();
    PeerKeys {
        node_id: node(id),
        operator: op.public(),
        ledger: Some(ledger),
        role: PeerRole::Node,
    }
}

// ---------------------------------------------------------------------------
// ETH proof helpers
// ---------------------------------------------------------------------------

/// A fixed-seed secp256k1 signing key.
fn eth_key(seed: u8) -> EthSigningKey {
    cawala_eth::signing_key_from_bytes(&[seed; 32]).expect("valid eth scalar")
}

fn eth_address(key: &EthSigningKey) -> [u8; 20] {
    cawala_eth::address_from_signing_key(key)
}

/// A fresh registration request proving control of `key`'s address.
fn registration(node_id: &str, key: &EthSigningKey) -> RegisterEthAddress {
    let address = eth_address(key);
    let digest = cawala_eth::eth_registration_digest(node_id, &address);
    RegisterEthAddress {
        address,
        proof: EthProof {
            signature: cawala_eth::sign_digest(key, &digest).expect("sign"),
            old_address: None,
        },
    }
}

/// A rotation request authorized by `old_key`, moving to `new_key`'s address.
fn rotation(node_id: &str, old_key: &EthSigningKey, new_key: &EthSigningKey) -> RegisterEthAddress {
    let old_address = eth_address(old_key);
    let new_address = eth_address(new_key);
    let digest = cawala_eth::eth_rotation_digest(node_id, &old_address, &new_address);
    RegisterEthAddress {
        address: new_address,
        proof: EthProof {
            signature: cawala_eth::sign_digest(old_key, &digest).expect("sign"),
            old_address: Some(old_address),
        },
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A child to install in a node record.
struct ChildSpec {
    id: String,
    kind: ChildKind,
    slot: u8,
    date_joined: u64,
}

/// Everything needed to stand up one hermetic control node.
struct NodeSpec<'a> {
    secret: &'a SecretKey,
    operator: OperatorSecretKey,
    dir: &'a Path,
    node_id: &'a str,
    address: Option<&'a str>,
    children: Vec<ChildSpec>,
    peers: Vec<PeerKeys>,
}

/// A running node: router + shared engine + bound address.
struct TestNode {
    router: Router,
    engine: Arc<Mutex<ControlNode>>,
    addr: EndpointAddr,
}

impl TestNode {
    async fn shutdown(self) {
        self.router.shutdown().await.expect("router shutdown");
    }

    async fn engine(&self) -> tokio::sync::MutexGuard<'_, ControlNode> {
        self.engine.lock().await
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

async fn spawn_node(spec: NodeSpec<'_>) -> TestNode {
    let endpoint = bind(spec.secret).await;
    let addr = endpoint.addr();

    let mut record = RecordStore::open(spec.dir, spec.node_id).expect("open record");
    if let Some(address) = spec.address {
        record
            .set_address(address.parse().expect("valid octal address"))
            .expect("set address");
    }
    for child in spec.children {
        record
            .attach_child(child.id, child.kind, Some(child.slot), child.date_joined)
            .expect("attach child");
    }
    record.save().expect("save record");

    let mut registry = PeerRegistry::new();
    for keys in spec.peers {
        registry.insert(keys).expect("insert peer");
    }
    let store = ControlStore::open(spec.dir).expect("open control store");
    let engine = ControlNode::new(
        spec.dir.to_path_buf(),
        spec.node_id,
        spec.operator,
        record,
        registry,
        store,
    );
    let shared = Arc::new(Mutex::new(engine));
    let router = spawn_control_only_on(endpoint.clone(), shared.clone());
    TestNode {
        router,
        engine: shared,
        addr,
    }
}

/// Send one signed request to `target` and return the reply.
async fn send(sender: &Endpoint, target: &EndpointAddr, signed: &SignedControl) -> ControlReply {
    ControlNode::send_direct_addr(sender, target.clone(), signed, timeout())
        .await
        .expect("control exchange")
}

/// Read the anchor the node currently holds (in-memory).
async fn anchor(node: &TestNode, child: &str) -> Option<[u8; 20]> {
    let engine = node.engine().await;
    engine
        .record()
        .children
        .iter()
        .find(|entry| entry.child_id == child)
        .and_then(|entry| entry.eth_address)
}

/// Read the anchor persisted to `node.json` (fresh disk read).
fn persisted_anchor(dir: &Path, node_id: &str, child: &str) -> Option<[u8; 20]> {
    RecordStore::open(dir, node_id)
        .expect("open record")
        .child_eth_address(child)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Scenario 1: a current `User` child registers its ETH anchor; the proof is
/// verified over `eth_registration_digest(node_id, address)`, the anchor is set,
/// and it is persisted to `node.json`.
#[tokio::test]
async fn registration_happy_path_sets_and_persists_anchor() {
    let parent_key = SecretKey::generate();
    let browser_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let browser_id = browser_key.public().to_string();
    let parent_op = operator(&parent_key);
    let browser_op = operator(&browser_key);

    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        children: vec![ChildSpec {
            id: browser_id.clone(),
            kind: ChildKind::User,
            slot: 0,
            date_joined: 1,
        }],
        peers: vec![user_peer(&browser_id, &browser_op)],
    })
    .await;
    // The transport sender is the leaf itself (`remote == origin`).
    let sender = bind(&browser_key).await;

    let key = eth_key(0x11);
    let address = eth_address(&key);
    let signed = authorize(
        node(&browser_id),
        &browser_op,
        ControlRequest::RegisterEthAddress(registration(&browser_id, &key)),
    );
    assert_eq!(send(&sender, &parent.addr, &signed).await, ControlReply::Accepted);

    assert_eq!(
        anchor(&parent, &browser_id).await,
        Some(address),
        "the child's in-memory anchor must be set"
    );
    assert_eq!(
        persisted_anchor(parent_dir.path(), &parent_id, &browser_id),
        Some(address),
        "the anchor must be persisted to node.json"
    );

    sender.close().await;
    parent.shutdown().await;
}

/// Scenario 2: write-once. Once anchored, a second registration (fresh frame,
/// registration-form proof, no `old_address`) is refused and the anchor is
/// unchanged; replaying the exact accepted frame is caught by the nonce guard.
#[tokio::test]
async fn write_once_second_registration_and_replay_are_refused() {
    let parent_key = SecretKey::generate();
    let browser_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let browser_id = browser_key.public().to_string();
    let parent_op = operator(&parent_key);
    let browser_op = operator(&browser_key);

    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        children: vec![ChildSpec {
            id: browser_id.clone(),
            kind: ChildKind::User,
            slot: 0,
            date_joined: 1,
        }],
        peers: vec![user_peer(&browser_id, &browser_op)],
    })
    .await;
    let sender = bind(&browser_key).await;

    let first_key = eth_key(0x11);
    let first_address = eth_address(&first_key);
    let first = authorize(
        node(&browser_id),
        &browser_op,
        ControlRequest::RegisterEthAddress(registration(&browser_id, &first_key)),
    );
    assert_eq!(send(&sender, &parent.addr, &first).await, ControlReply::Accepted);
    assert_eq!(anchor(&parent, &browser_id).await, Some(first_address));

    // A different key's registration-form proof against the anchored child is
    // refused: write-once.
    let second_key = eth_key(0x22);
    let second = authorize(
        node(&browser_id),
        &browser_op,
        ControlRequest::RegisterEthAddress(registration(&browser_id, &second_key)),
    );
    assert_eq!(
        send(&sender, &parent.addr, &second).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
    assert_eq!(
        anchor(&parent, &browser_id).await,
        Some(first_address),
        "the anchor must not change on a refused second registration"
    );
    assert_eq!(
        persisted_anchor(parent_dir.path(), &parent_id, &browser_id),
        Some(first_address)
    );

    // The byte-identical accepted frame is a replay.
    assert_eq!(
        send(&sender, &parent.addr, &first).await,
        ControlReply::Rejected(RejectCode::Replay)
    );
    assert_eq!(anchor(&parent, &browser_id).await, Some(first_address));

    sender.close().await;
    parent.shutdown().await;
}

/// Scenario 3: rotation must be authorized by the **incumbent** key. A rotation
/// signed by the new (non-incumbent) key is refused with the anchor unchanged;
/// the incumbent's proof rotates it.
#[tokio::test]
async fn rotation_requires_the_incumbent_key() {
    let parent_key = SecretKey::generate();
    let browser_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let browser_id = browser_key.public().to_string();
    let parent_op = operator(&parent_key);
    let browser_op = operator(&browser_key);

    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        children: vec![ChildSpec {
            id: browser_id.clone(),
            kind: ChildKind::User,
            slot: 0,
            date_joined: 1,
        }],
        peers: vec![user_peer(&browser_id, &browser_op)],
    })
    .await;
    let sender = bind(&browser_key).await;

    let old_key = eth_key(0x11);
    let new_key = eth_key(0x22);
    let old_address = eth_address(&old_key);
    let new_address = eth_address(&new_key);

    // Register the incumbent.
    let register = authorize(
        node(&browser_id),
        &browser_op,
        ControlRequest::RegisterEthAddress(registration(&browser_id, &old_key)),
    );
    assert_eq!(send(&sender, &parent.addr, &register).await, ControlReply::Accepted);
    assert_eq!(anchor(&parent, &browser_id).await, Some(old_address));

    // The anchor-swap bypass: a rotation proof signed by the NEW key over the
    // same digest must be refused; holding the operator (transport) key is not
    // enough to move the anchor.
    let digest = cawala_eth::eth_rotation_digest(&browser_id, &old_address, &new_address);
    let swap = RegisterEthAddress {
        address: new_address,
        proof: EthProof {
            signature: cawala_eth::sign_digest(&new_key, &digest).expect("sign"),
            old_address: Some(old_address),
        },
    };
    let signed_swap = authorize(
        node(&browser_id),
        &browser_op,
        ControlRequest::RegisterEthAddress(swap),
    );
    assert_eq!(
        send(&sender, &parent.addr, &signed_swap).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
    assert_eq!(
        anchor(&parent, &browser_id).await,
        Some(old_address),
        "a non-incumbent rotation must not move the anchor"
    );

    // The incumbent authorizes the rotation.
    let signed_rotation = authorize(
        node(&browser_id),
        &browser_op,
        ControlRequest::RegisterEthAddress(rotation(&browser_id, &old_key, &new_key)),
    );
    assert_eq!(
        send(&sender, &parent.addr, &signed_rotation).await,
        ControlReply::Accepted
    );
    assert_eq!(anchor(&parent, &browser_id).await, Some(new_address));
    assert_eq!(
        persisted_anchor(parent_dir.path(), &parent_id, &browser_id),
        Some(new_address)
    );

    sender.close().await;
    parent.shutdown().await;
}

/// Scenario 4a: a current **non-`User`** child (a `Node` leaf) is refused: the
/// anchor contract is only for user leaves.
#[tokio::test]
async fn non_user_child_origin_is_refused() {
    let parent_key = SecretKey::generate();
    let node_child_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let node_child_id = node_child_key.public().to_string();
    let parent_op = operator(&parent_key);
    let node_child_op = operator(&node_child_key);

    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        children: vec![ChildSpec {
            id: node_child_id.clone(),
            kind: ChildKind::Node,
            slot: 0,
            date_joined: 1,
        }],
        peers: vec![node_peer(&node_child_id, &node_child_op, 9)],
    })
    .await;
    let sender = bind(&node_child_key).await;

    let key = eth_key(0x11);
    let signed = authorize(
        node(&node_child_id),
        &node_child_op,
        ControlRequest::RegisterEthAddress(registration(&node_child_id, &key)),
    );
    assert_eq!(
        send(&sender, &parent.addr, &signed).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
    assert_eq!(anchor(&parent, &node_child_id).await, None);

    sender.close().await;
    parent.shutdown().await;
}

/// Scenario 4b: an authenticated origin that is **not a child** is `NotFound`.
#[tokio::test]
async fn non_child_origin_is_refused() {
    let parent_key = SecretKey::generate();
    let stranger_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let stranger_id = stranger_key.public().to_string();
    let parent_op = operator(&parent_key);
    let stranger_op = operator(&stranger_key);

    // `stranger` is a registered user peer but is not attached as a child.
    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        children: vec![],
        peers: vec![user_peer(&stranger_id, &stranger_op)],
    })
    .await;
    let sender = bind(&stranger_key).await;

    let key = eth_key(0x11);
    let signed = authorize(
        node(&stranger_id),
        &stranger_op,
        ControlRequest::RegisterEthAddress(registration(&stranger_id, &key)),
    );
    assert_eq!(
        send(&sender, &parent.addr, &signed).await,
        ControlReply::Rejected(RejectCode::NotFound)
    );

    sender.close().await;
    parent.shutdown().await;
}

/// Scenario 4c: a valid Ed25519 (operator-key) assertion is not enough. Without
/// a matching ETH proof the anchor is never set: an all-zero signature and a
/// signature from a *different* ETH key than the claimed address are both
/// refused.
#[tokio::test]
async fn operator_key_without_matching_eth_proof_is_refused() {
    let parent_key = SecretKey::generate();
    let browser_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let browser_id = browser_key.public().to_string();
    let parent_op = operator(&parent_key);
    let browser_op = operator(&browser_key);

    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        children: vec![ChildSpec {
            id: browser_id.clone(),
            kind: ChildKind::User,
            slot: 0,
            date_joined: 1,
        }],
        peers: vec![user_peer(&browser_id, &browser_op)],
    })
    .await;
    let sender = bind(&browser_key).await;

    let claimed_key = eth_key(0x11);
    let claimed_address = eth_address(&claimed_key);

    // No ETH proof at all: a zeroed 65-byte signature.
    let no_proof = RegisterEthAddress {
        address: claimed_address,
        proof: EthProof {
            signature: [0u8; 65],
            old_address: None,
        },
    };
    let signed = authorize(
        node(&browser_id),
        &browser_op,
        ControlRequest::RegisterEthAddress(no_proof),
    );
    assert_eq!(
        send(&sender, &parent.addr, &signed).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );

    // An operator-key-only assertion: the signature is over the right
    // registration challenge but by a different ETH key, so it recovers to an
    // address other than the claimed one.
    let attacker_key = eth_key(0x22);
    let digest = cawala_eth::eth_registration_digest(&browser_id, &claimed_address);
    let wrong_signer = RegisterEthAddress {
        address: claimed_address,
        proof: EthProof {
            signature: cawala_eth::sign_digest(&attacker_key, &digest).expect("sign"),
            old_address: None,
        },
    };
    let signed = authorize(
        node(&browser_id),
        &browser_op,
        ControlRequest::RegisterEthAddress(wrong_signer),
    );
    assert_eq!(
        send(&sender, &parent.addr, &signed).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );

    assert_eq!(
        anchor(&parent, &browser_id).await,
        None,
        "no rejected proof may set the anchor"
    );

    sender.close().await;
    parent.shutdown().await;
}

/// Scenario 5: a `Capabilities` request returns `ControlReply::Capabilities`
/// with the node's advertised API version and ETH-identity feature bit.
#[tokio::test]
async fn capabilities_request_returns_node_capabilities() {
    let parent_key = SecretKey::generate();
    let client_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let parent_op = operator(&parent_key);
    let client_op = operator(&client_key);
    let client_id = client_key.public().to_string();

    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        children: vec![],
        peers: vec![],
    })
    .await;
    let sender = bind(&client_key).await;

    let signed = authorize(
        node(&client_id),
        &client_op,
        ControlRequest::Capabilities(Capabilities {
            client_api_version: 1,
        }),
    );
    assert_eq!(
        send(&sender, &parent.addr, &signed).await,
        ControlReply::Capabilities(NodeCapabilities {
            client_api_version: NODE_CLIENT_API_VERSION,
            features: NODE_FEATURE_ETH_IDENTITY,
        })
    );

    sender.close().await;
    parent.shutdown().await;
}
