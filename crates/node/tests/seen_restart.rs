//! Restart durability for the control replay guard.
//!
//! The in-memory `SeenSet` forgets on restart, reopening a bounded replay
//! window. [`SeenStore`](cawala_node::seen_store::SeenStore) persists each
//! accepted `(origin, controller, nonce)` mark to
//! `<data-dir>/control_seen.json` before dispatch. These tests reopen a
//! `ControlNode` over the same data dir and assert that a byte-identical
//! `SignedControl` is answered `Replay`.

use std::time::{SystemTime, UNIX_EPOCH};

use cawala_control::{
    AdminJoinApprove, CONTROL_REQUEST_TTL_SECS, ChildKind, ControlReply, ControlRequest,
    JoinRequest, NodeId, OperatorSecretKey, RejectCode, SignedControl,
};
use cawala_ledger::PeerRegistry;
use cawala_node::AdminStore;
use cawala_node::control::ControlNode;
use cawala_node::control_store::ControlStore;
use cawala_node::record::RecordStore;
use iroh::{EndpointId, SecretKey};

/// Wall-clock seconds, matching the engine's `receive` clock.
fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A self-signed `Query` accepted by a fresh engine (it needs no record state
/// beyond this node's own operator key).
fn query(node_id: &str, operator: &OperatorSecretKey, nonce: u64, now: u64) -> SignedControl {
    SignedControl::authorize(
        NodeId::from(node_id),
        operator,
        nonce,
        now + CONTROL_REQUEST_TTL_SECS,
        ControlRequest::Query,
    )
    .expect("sign control request")
}

#[tokio::test]
async fn replay_mark_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let operator = OperatorSecretKey::from_bytes([1u8; 32]);
    let remote = EndpointId::from(SecretKey::generate().public());
    let now = now_unix_seconds();
    let signed = query("node-a", &operator, 42, now);

    let mut engine = ControlNode::open(dir.path(), "node-a", operator.clone()).unwrap();
    assert!(
        matches!(
            engine.receive_at(remote, signed.clone(), now).await,
            ControlReply::Snapshot(_)
        ),
        "the first frame must be accepted"
    );
    assert!(
        dir.path().join("control_seen.json").exists(),
        "the replay mark must be persisted before dispatch"
    );
    drop(engine);

    // A new engine over the same data dir must remember the mark.
    let mut reopened = ControlNode::open(dir.path(), "node-a", operator).unwrap();
    assert_eq!(
        reopened.receive_at(remote, signed.clone(), now).await,
        ControlReply::Rejected(RejectCode::Replay),
        "the persisted mark must reject the identical frame after a restart"
    );

    // A different nonce is still fresh after the restart (the guard is per
    // nonce, not a blanket block).
    let fresh = query("node-a", &OperatorSecretKey::from_bytes([1u8; 32]), 43, now);
    assert!(
        matches!(
            reopened.receive_at(remote, fresh, now).await,
            ControlReply::Snapshot(_)
        ),
        "a distinct nonce must still be accepted"
    );
}

#[tokio::test]
async fn failed_replay_mark_persist_is_rejected_without_dispatch() {
    // Force `SeenStore::save` to fail deterministically: make
    // `<data-dir>/control_seen.json` a *directory*, so the temp-file rename
    // cannot complete. This does not depend on the test user's permissions.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("control_seen.json")).unwrap();

    let operator = OperatorSecretKey::from_bytes([3u8; 32]);
    let applicant = OperatorSecretKey::from_bytes([4u8; 32]);
    let child = NodeId::from("applicant-x");
    let join = JoinRequest {
        node: child.clone(),
        kind: ChildKind::User,
        operator: applicant.public(),
        ledger: None,
        desired_slot: None,
        location_hint: None,
        nonce: 7,
        expiry: u64::MAX,
    };

    // A parent engine with an asserted address and one real pending join, built
    // through `new` so the setup never touches the (failing) sidecar path.
    let mut record = RecordStore::open(dir.path(), "parent").unwrap();
    record.set_address("0".parse().unwrap()).unwrap();
    record.save().unwrap();
    let mut pending = ControlStore::open(dir.path()).unwrap();
    pending.add_pending(join);
    pending.save().unwrap();
    let mut engine = ControlNode::new(
        dir.path(),
        "parent",
        operator.clone(),
        record,
        PeerRegistry::new(),
        pending,
        AdminStore::empty(),
    );

    let remote = EndpointId::from(SecretKey::generate().public());
    let now = now_unix_seconds();
    let approve = SignedControl::authorize(
        NodeId::from("parent"),
        &operator,
        99,
        now + CONTROL_REQUEST_TTL_SECS,
        ControlRequest::AdminApproveJoin(AdminJoinApprove {
            child: child.clone(),
            slot: Some(1),
        }),
    )
    .unwrap();

    // The replay mark cannot be persisted, so the request must fail closed
    // before dispatch.
    assert_eq!(
        engine.receive_at(remote, approve, now).await,
        ControlReply::Rejected(RejectCode::Internal),
        "an unpreservable replay mark must fail closed"
    );

    // Nothing dispatched: the pending row survives, no child was attached, and
    // no outbound decision was queued.
    assert!(
        engine.pending().pending_for(&child).is_some(),
        "the pending join must survive a failed replay-mark save"
    );
    assert!(
        engine.record().children.is_empty(),
        "no child may be attached when the replay mark is not durable"
    );
    assert!(
        engine.take_outbound().is_empty(),
        "no decision may be queued when the replay mark is not durable"
    );
}

#[tokio::test]
async fn corrupt_sidecar_does_not_block_open() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("control_seen.json"), b"{ not json").unwrap();
    let operator = OperatorSecretKey::from_bytes([2u8; 32]);
    let remote = EndpointId::from(SecretKey::generate().public());
    let now = now_unix_seconds();
    let signed = query("node-b", &operator, 7, now);

    // A corrupt replay sidecar must warn and start empty, never fail the open.
    let mut engine = ControlNode::open(dir.path(), "node-b", operator)
        .expect("a corrupt sidecar must not brick the node");
    assert!(
        matches!(
            engine.receive_at(remote, signed, now).await,
            ControlReply::Snapshot(_)
        ),
        "the empty guard must still accept a fresh frame"
    );
}
