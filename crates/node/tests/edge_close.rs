//! `LedgerService::edge_close` integration tests.
//!
//! A node lifts its `Parent` balance by `prefund`ing a child while attached,
//! then detaches (`control exit` semantics: `rebase_to_root`) before it may
//! write the claim off. `edge_close` is idempotent (an already-zero balance is
//! `Ok(None)`) and is refused while a parent link remains.

use std::path::Path;

use cawala_ledger::{Amount, NodeId, OperatorSecretKey};
use cawala_node::{LedgerService, identity, record};
use cawala_topology::ChildKind;

/// Attach `node_id` under `parent` (so `is_root()` is false).
fn attach(dir: &Path, node_id: &str, parent: &str) {
    let mut store = record::RecordStore::open(dir, node_id).unwrap();
    store.set_parent(parent, 1).unwrap();
    store.save().unwrap();
}

/// Detach `node_id` to a root at address 0 (control-exit semantics).
fn detach(dir: &Path, node_id: &str) {
    let mut store = record::RecordStore::open(dir, node_id).unwrap();
    store.rebase_to_root().unwrap();
    store.save().unwrap();
}

/// A data dir with an identity and an attached record; returns `(node_id, operator)`.
fn attached_node(dir: &Path) -> (String, OperatorSecretKey) {
    let secret = identity::load_or_create_secret_key(dir).unwrap();
    let node_id = secret.public().to_string();
    let operator = OperatorSecretKey::from_bytes(secret.to_bytes());
    attach(dir, &node_id, "old-parent");
    (node_id, operator)
}

#[test]
fn edge_close_zeroes_parent_after_detach_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let (node_id, operator) = attached_node(dir.path());
    let child = NodeId::from("child-1");
    let now = 1_000;

    // Attached: a prefund lifts `Parent` above zero.
    let mut service = LedgerService::open(dir.path(), &node_id).unwrap();
    service
        .prefund(&child, ChildKind::User, 100, &operator, 1, now)
        .unwrap();
    assert_eq!(
        service.ledger().balances().parent_balance(),
        Some(Amount::new(100))
    );

    // Detach, then close exactly the whole balance.
    detach(dir.path(), &node_id);
    let (seq, hash) = service
        .edge_close(&operator, 2, now, Some(&NodeId::from("old-parent")))
        .unwrap()
        .expect("a non-zero Parent balance must close");
    assert_eq!(
        service.ledger().balances().parent_balance(),
        Some(Amount::ZERO)
    );
    assert_eq!(
        service
            .ledger()
            .get(seq as usize)
            .unwrap()
            .expect("appended entry")
            .entry
            .body,
        cawala_ledger::EntryBody::EdgeClose {
            amount: Amount::new(100)
        }
    );

    // A second call is a zero-balance no-op.
    assert_eq!(service.edge_close(&operator, 3, now, None).unwrap(), None);

    // The success appended one best-effort audit line.
    let audit = std::fs::read_to_string(dir.path().join("control_audit.jsonl")).unwrap();
    assert!(audit.contains("\"event\":\"edge-close\""), "{audit}");
    assert!(audit.contains("\"amount\":100"), "{audit}");
    assert!(audit.contains(&format!("\"seq\":{seq}")), "{audit}");
    assert!(audit.contains(&format!("\"hash\":\"{hash}\"")), "{audit}");
    assert!(audit.contains("\"from\":\"old-parent\""), "{audit}");
}

#[test]
fn zero_balance_is_a_noop_both_attached_and_detached() {
    let dir = tempfile::tempdir().unwrap();
    let (node_id, operator) = attached_node(dir.path());
    let now = 1_000;
    let mut service = LedgerService::open(dir.path(), &node_id).unwrap();

    // Zero balance while attached: no-op, no rootness guard reached.
    assert_eq!(service.edge_close(&operator, 1, now, None).unwrap(), None);

    // Zero balance while detached: still a no-op.
    drop(service);
    detach(dir.path(), &node_id);
    let mut service = LedgerService::open(dir.path(), &node_id).unwrap();
    assert_eq!(service.edge_close(&operator, 2, now, None).unwrap(), None);
    assert!(service.ledger().is_empty());

    // No audit line is written for a no-op.
    assert!(!dir.path().join("control_audit.jsonl").exists());
}

#[test]
fn non_zero_while_attached_is_refused_without_appending() {
    let dir = tempfile::tempdir().unwrap();
    let (node_id, operator) = attached_node(dir.path());
    let child = NodeId::from("child-1");
    let now = 1_000;
    let mut service = LedgerService::open(dir.path(), &node_id).unwrap();
    service
        .prefund(&child, ChildKind::User, 100, &operator, 1, now)
        .unwrap();
    let len = service.ledger().len();

    let err = service.edge_close(&operator, 2, now, None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("still attached"), "unexpected error: {msg}");
    assert!(msg.contains("control exit"), "unexpected error: {msg}");
    // Nothing was appended and the balance is untouched.
    assert_eq!(service.ledger().len(), len);
    assert_eq!(
        service.ledger().balances().parent_balance(),
        Some(Amount::new(100))
    );

    // Detaching then retrying succeeds (the service refreshes rootness).
    detach(dir.path(), &node_id);
    let closed = service.edge_close(&operator, 3, now, None).unwrap();
    assert!(closed.is_some());
    assert_eq!(
        service.ledger().balances().parent_balance(),
        Some(Amount::ZERO)
    );
}
