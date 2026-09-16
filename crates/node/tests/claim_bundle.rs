//! Hermetic integration tests for the M5 P2 stranded-claim bundle CLI surface:
//! `claim-export`, `claim-review`, and the informational `parent-status`.
//!
//! The export/review half is pure disk state: a temp data dir with an identity,
//! an existing ledger key, a non-root record, and a committed ledger carrying a
//! `Parent` balance. The `parent-status` probe half binds hermetic loopback
//! endpoints (relays disabled) with a shared [`MemoryLookup`], exactly like the
//! exit/rebase tests.
//!
//! These tests call the library functions the CLI wraps, so no process spawn,
//! network, or relay is involved.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use cawala_control::ChildKind;
use cawala_ledger::{NodeId, OperatorSecretKey};
use cawala_node::claim_bundle::{
    Attachment, MAX_BUNDLE_FILE_BYTES, ParentReachability, attachment_state, export_bundle,
    review_bundle_file,
};
use cawala_node::control::{ControlNode, spawn_control_only_on};
use cawala_node::record::RecordStore;
use cawala_node::{LEDGER_KEY_FILE, LedgerService};
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMode, SecretKey};
use tokio::sync::Mutex;

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn node(id: &str) -> NodeId {
    NodeId::from(id)
}

/// The operator key derived from a persisted identity (node id == operator key).
fn node_operator(dir: &Path) -> OperatorSecretKey {
    let secret = cawala_node::identity::load_or_create_secret_key(dir).unwrap();
    OperatorSecretKey::from_bytes(secret.to_bytes())
}

/// A node data dir with an identity, a parent link, and (once [`prefund`] runs)
/// a ledger key and a committed ledger.
struct Fixture {
    dir: tempfile::TempDir,
    node_id: String,
    operator: OperatorSecretKey,
    parent_id: String,
}

fn fixture(parent_id: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let operator = node_operator(dir.path());
    let node_id = operator.public().to_string();
    let mut store = RecordStore::open(dir.path(), &node_id).unwrap();
    store.set_parent(parent_id, 0).unwrap();
    store.save().unwrap();
    Fixture {
        dir,
        node_id,
        operator,
        parent_id: parent_id.to_string(),
    }
}

/// Prefund `amount` into `child` (a `Descend`, so the node's `Parent` asset
/// becomes non-zero) and commit the resulting ledger head.
fn prefund_and_commit(fixture: &Fixture, child: &str, amount: u64, nonce: u64, now: u64) {
    let mut service = LedgerService::open(fixture.dir.path(), &fixture.node_id).unwrap();
    service
        .prefund(
            &node(child),
            ChildKind::User,
            amount,
            &fixture.operator,
            nonce,
            now,
        )
        .unwrap();
    service.commit().unwrap();
}

/// Add entries to the ledger without committing (exercises commit-before-prove).
fn prefund_uncommitted(fixture: &Fixture, child: &str, amount: u64, nonce: u64, now: u64) {
    let mut service = LedgerService::open(fixture.dir.path(), &fixture.node_id).unwrap();
    service
        .prefund(
            &node(child),
            ChildKind::User,
            amount,
            &fixture.operator,
            nonce,
            now,
        )
        .unwrap();
}

fn ledger_len(fixture: &Fixture) -> u64 {
    LedgerService::open(fixture.dir.path(), &fixture.node_id)
        .unwrap()
        .ledger()
        .len() as u64
}

fn ledger_parent_balance(fixture: &Fixture) -> i128 {
    LedgerService::open(fixture.dir.path(), &fixture.node_id)
        .unwrap()
        .ledger()
        .balances()
        .parent_balance()
        .unwrap()
        .get() as i128
}

fn write_bundle(
    dir: &Path,
    name: &str,
    bundle: &cawala_control::StrandedClaimBundle,
) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(bundle).unwrap()).unwrap();
    path
}

// ---------------------------------------------------------------------------
// (1) export -> write -> review round-trip; reported values match the ledger
// ---------------------------------------------------------------------------

#[test]
fn export_write_review_round_trip_matches_the_ledger_head() {
    let fixture = fixture("old-parent");
    prefund_and_commit(&fixture, "user-a", 100, 1, 1_000);

    let now = now_unix_seconds();
    let from = node(&fixture.parent_id);
    let outcome = export_bundle(
        fixture.dir.path(),
        &fixture.node_id,
        &fixture.operator,
        Some(&from),
        now,
    )
    .unwrap();

    assert_eq!(outcome.verified.parent_balance, 100);
    assert_eq!(outcome.bundle.child.as_str(), fixture.node_id.as_str());
    assert_eq!(outcome.bundle.child_operator, fixture.operator.public());
    assert_eq!(
        outcome
            .bundle
            .claim
            .claim
            .detached_from
            .as_ref()
            .map(NodeId::as_str),
        Some("old-parent")
    );
    assert_eq!(outcome.chain_total, 0, "one commitment, which is the head");

    let path = write_bundle(fixture.dir.path(), "bundle.json", &outcome.bundle);
    let verified = review_bundle_file(&path, now).unwrap();

    assert_eq!(verified.child, outcome.bundle.child);
    assert_eq!(verified.parent_balance, 100);
    assert_eq!(verified.commitment_height, ledger_len(&fixture));
    assert_eq!(verified.parent_balance, ledger_parent_balance(&fixture));
    assert_eq!(verified.detached_from, Some(from));
}

// ---------------------------------------------------------------------------
// (2) A6 commit-before-prove: new ledger entries still produce a verifiable head
// ---------------------------------------------------------------------------

#[test]
fn export_after_new_entries_commits_before_proving() {
    let fixture = fixture("old-parent");
    prefund_and_commit(&fixture, "user-a", 100, 1, 1_000);
    let committed_before = ledger_len(&fixture);

    // New entries land after the last commitment, with no fresh commit.
    prefund_uncommitted(&fixture, "user-b", 50, 2, 1_010);
    let head_now = ledger_len(&fixture);
    assert!(head_now > committed_before, "the ledger head advanced");

    let now = now_unix_seconds();
    let outcome = export_bundle(
        fixture.dir.path(),
        &fixture.node_id,
        &fixture.operator,
        None,
        now,
    )
    .unwrap();

    assert!(outcome.committed, "a fresh commitment was appended");
    assert_eq!(outcome.verified.parent_balance, 150);
    assert_eq!(outcome.verified.commitment_height, head_now);
    assert_eq!(
        ledger_len(&fixture),
        head_now,
        "commit does not add ledger entries"
    );
    // The pre-advance commitment is now an ancestor of the head and is carried.
    assert_eq!(outcome.chain_total, 1);
    assert_eq!(outcome.chain_included, 1);

    let path = write_bundle(fixture.dir.path(), "bundle.json", &outcome.bundle);
    let verified = review_bundle_file(&path, now).unwrap();
    assert_eq!(verified.parent_balance, 150);
    assert_eq!(verified.commitment_height, head_now);
}

// ---------------------------------------------------------------------------
// (3) tampered proof / foreign head are rejected by review
// ---------------------------------------------------------------------------

#[test]
fn tampered_proof_is_rejected_by_review() {
    let fixture = fixture("old-parent");
    prefund_and_commit(&fixture, "user-a", 100, 1, 1_000);
    let now = now_unix_seconds();
    let mut bundle = export_bundle(
        fixture.dir.path(),
        &fixture.node_id,
        &fixture.operator,
        None,
        now,
    )
    .unwrap()
    .bundle;

    // Flip the claimed magnitude; the proof still binds 100.
    bundle.parent_balance = 101;
    let path = write_bundle(fixture.dir.path(), "tampered.json", &bundle);
    let err = review_bundle_file(&path, now).unwrap_err();
    let chain = format!("{err:#}");
    assert!(
        chain.contains("failed verification")
            && chain.contains("invalid parent balance state proof"),
        "unexpected error: {chain}"
    );
}

#[test]
fn head_from_a_different_ledger_is_rejected_by_review() {
    let a = fixture("parent-a");
    prefund_and_commit(&a, "user-a", 100, 1, 1_000);
    let b = fixture("parent-b");
    prefund_and_commit(&b, "user-b", 100, 1, 1_000);

    let now = now_unix_seconds();
    let mut bundle = export_bundle(a.dir.path(), &a.node_id, &a.operator, None, now)
        .unwrap()
        .bundle;

    // Swap in another ledger's signed head: the child ledger key no longer
    // matches the commitment signature.
    let foreign = LedgerService::open(b.dir.path(), &b.node_id)
        .unwrap()
        .commitments()
        .unwrap()
        .chain()
        .last()
        .cloned()
        .unwrap();
    bundle.commitment = foreign;
    bundle.chain.clear();

    let path = write_bundle(a.dir.path(), "foreign-head.json", &bundle);
    let err = review_bundle_file(&path, now).unwrap_err();
    let chain = format!("{err:#}");
    assert!(
        chain.contains("failed verification") && chain.contains("invalid commitment signature"),
        "unexpected error: {chain}"
    );
}

// ---------------------------------------------------------------------------
// (4) detached node exports; missing ledger key errors clearly
// ---------------------------------------------------------------------------

#[test]
fn detached_node_exports_successfully() {
    let fixture = fixture("old-parent");
    prefund_and_commit(&fixture, "user-a", 100, 1, 1_000);

    // Post-exit: clear the parent link; the stranded Parent asset remains.
    {
        let mut store = RecordStore::open(fixture.dir.path(), &fixture.node_id).unwrap();
        store.unset_parent().unwrap();
        store.save().unwrap();
    }

    let now = now_unix_seconds();
    let from = node(&fixture.parent_id);
    let outcome = export_bundle(
        fixture.dir.path(),
        &fixture.node_id,
        &fixture.operator,
        Some(&from),
        now,
    )
    .unwrap();
    assert_eq!(outcome.verified.parent_balance, 100);

    let path = write_bundle(fixture.dir.path(), "detached.json", &outcome.bundle);
    assert!(review_bundle_file(&path, now).is_ok());
}

#[test]
fn export_without_a_ledger_key_errors_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let operator = node_operator(dir.path());
    let node_id = operator.public().to_string();

    let err = export_bundle(dir.path(), &node_id, &operator, None, now_unix_seconds()).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("no ledger key"),
        "unexpected error: {message}"
    );
    assert!(
        !dir.path().join(LEDGER_KEY_FILE).exists(),
        "export must never create a ledger key"
    );
}

// ---------------------------------------------------------------------------
// (5) base32 / garbage / oversized files are rejected with a clear error
// ---------------------------------------------------------------------------

#[test]
fn review_rejects_base32_garbage_and_oversized_files() {
    let dir = tempfile::tempdir().unwrap();
    let now = now_unix_seconds();

    // Base32 content (RFC 4648 alphabet), not JSON.
    let base32 = dir.path().join("base32.bundle");
    std::fs::write(&base32, "mfrggzdfmztwq2lk").unwrap();
    let err = review_bundle_file(&base32, now).unwrap_err();
    assert!(
        format!("{err:#}").contains("not a valid stranded claim bundle"),
        "unexpected error: {err:#}"
    );

    // Arbitrary garbage bytes.
    let garbage = dir.path().join("garbage.bundle");
    std::fs::write(&garbage, [0xff, 0x00, 0x12, 0x7f, 0x80]).unwrap();
    assert!(review_bundle_file(&garbage, now).is_err());

    // Oversized: larger than the read cap (sparse file, so this is cheap).
    let oversized = dir.path().join("oversized.bundle");
    std::fs::File::create(&oversized)
        .unwrap()
        .set_len(MAX_BUNDLE_FILE_BYTES + 1)
        .unwrap();
    let err = review_bundle_file(&oversized, now).unwrap_err();
    assert!(
        format!("{err:#}").contains("exceeding the"),
        "unexpected error: {err:#}"
    );
}

// ---------------------------------------------------------------------------
// (6) parent-status: reachable / unreachable / no-parent
// ---------------------------------------------------------------------------

/// Bind a hermetic loopback endpoint with relays disabled and an optional
/// shared address lookup (mirrors the exit/rebase harness).
async fn bind(secret: &SecretKey, lookup: Option<MemoryLookup>) -> Endpoint {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret.clone())
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind address");
    if let Some(lookup) = lookup {
        builder = builder.address_lookup(lookup);
    }
    builder.bind().await.expect("bind endpoint")
}

fn engine(dir: &Path, id: &str, operator: OperatorSecretKey) -> Arc<Mutex<ControlNode>> {
    Arc::new(Mutex::new(
        ControlNode::open(dir, id, operator).expect("open control engine"),
    ))
}

/// Build a child whose record names `parent_id` and return its endpoint +
/// control engine, with a shared lookup seeded from `known`.
async fn child_probe_setup(
    parent_id: &str,
    known: &[(String, Endpoint)],
) -> (tempfile::TempDir, Endpoint, Arc<Mutex<ControlNode>>, String) {
    let lookup = MemoryLookup::new();
    for (_, endpoint) in known {
        lookup.add_endpoint_info(endpoint.addr());
    }
    let child_secret = SecretKey::generate();
    let child_id = child_secret.public().to_string();
    let child_op = OperatorSecretKey::from_bytes(child_secret.to_bytes());

    let dir = tempfile::tempdir().unwrap();
    let mut store = RecordStore::open(dir.path(), &child_id).unwrap();
    store.set_parent(parent_id, 0).unwrap();
    store.save().unwrap();

    let endpoint = bind(&child_secret, Some(lookup)).await;
    let control = engine(dir.path(), &child_id, child_op);
    (dir, endpoint, control, child_id)
}

#[tokio::test]
async fn parent_status_reports_reachable_for_a_live_parent() {
    let lookup = MemoryLookup::new();
    let parent_secret = SecretKey::generate();
    let parent_id = parent_secret.public().to_string();
    let parent_op = OperatorSecretKey::from_bytes(parent_secret.to_bytes());

    let parent_endpoint = bind(&parent_secret, Some(lookup.clone())).await;
    lookup.add_endpoint_info(parent_endpoint.addr());
    let parent_dir = tempfile::tempdir().unwrap();
    let parent_control = engine(parent_dir.path(), &parent_id, parent_op);
    // Ping + control only: enough to answer a `RebasePull`.
    let _router = spawn_control_only_on(parent_endpoint.clone(), parent_control);

    let (_child_dir, child_endpoint, child_control, _child_id) =
        child_probe_setup(&parent_id, &[(parent_id.clone(), parent_endpoint)]).await;

    let reachability = cawala_node::claim_bundle::probe_parent(
        &child_endpoint,
        &child_control,
        Duration::from_secs(3),
        now_unix_seconds(),
    )
    .await
    .unwrap();
    assert_eq!(reachability, ParentReachability::Reachable);
}

#[tokio::test]
async fn parent_status_reports_unreachable_for_an_unknown_parent() {
    // A parent id that is not in the shared lookup and has no bound endpoint.
    let unknown = SecretKey::generate().public().to_string();
    let (_child_dir, child_endpoint, child_control, _child_id) =
        child_probe_setup(&unknown, &[]).await;

    let reachability = cawala_node::claim_bundle::probe_parent(
        &child_endpoint,
        &child_control,
        Duration::from_millis(500),
        now_unix_seconds(),
    )
    .await
    .unwrap();
    assert!(
        matches!(reachability, ParentReachability::Unreachable(_)),
        "unexpected reachability: {reachability:?}"
    );
}

#[tokio::test]
async fn parent_status_reports_no_parent_plainly() {
    let dir = tempfile::tempdir().unwrap();
    let secret = SecretKey::generate();
    let id = secret.public().to_string();
    let op = OperatorSecretKey::from_bytes(secret.to_bytes());
    let store = RecordStore::open(dir.path(), &id).unwrap();
    assert_eq!(attachment_state(store.record()), Attachment::NoParent);

    let endpoint = bind(&secret, None).await;
    let control = engine(dir.path(), &id, op);
    let reachability = cawala_node::claim_bundle::probe_parent(
        &endpoint,
        &control,
        Duration::from_millis(200),
        now_unix_seconds(),
    )
    .await
    .unwrap();
    assert_eq!(reachability, ParentReachability::NoParent);
}

#[test]
fn attachment_state_reports_root_for_a_parentless_root() {
    let dir = tempfile::tempdir().unwrap();
    let id = "root-node";
    let mut store = RecordStore::open(dir.path(), id).unwrap();
    store.set_address("0".parse().unwrap()).unwrap();
    store.save().unwrap();
    let store = RecordStore::open(dir.path(), id).unwrap();
    assert_eq!(attachment_state(store.record()), Attachment::Root);
}
