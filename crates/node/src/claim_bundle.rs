//! Node-side stranded-claim evidence bundle export/review and the
//! informational parent indicator (M5 P2).
//!
//! This module is the native, operator-facing half of
//! [`cawala_control::claim`]: it builds a [`StrandedClaimBundle`] from this
//! node's own record/ledger/commitment log (`claim-export`), verifies an
//! out-of-band bundle file (`claim-review`), and performs a one-shot liveness
//! probe of the recorded parent (`parent-status`).
//!
//! The bundle stays an **out-of-band artifact**: no wire format changes, no
//! `CONTROL_FORMAT_VERSION` bump, no new persisted health store, and no
//! automatic recovery behaviour. A verified bundle is review evidence only —
//! the child authors its own ledger, so the magnitude is self-attested (see
//! [`cawala_control::claim`]).
//!
//! # A6 obligations
//!
//! - A state proof over balances newer than the committed head cannot verify,
//!   so [`export_bundle`] appends a fresh commitment (via the existing
//!   [`LedgerService::commit`] path) whenever the ledger has entries past the
//!   commitment head, then proves against the new head.
//! - Every produced bundle is run through
//!   [`StrandedClaimBundle::verify_bundle`] before it is returned, so the
//!   commit/prove coupling is caught on the exporter's side.
//! - [`review_bundle_file`] caps the file read at [`MAX_BUNDLE_FILE_BYTES`].
//! - `chain` is the commitment log minus the head, ascending; it is truncated
//!   to the most recent [`MAX_BUNDLE_CHAIN`] ancestors when longer, which keeps
//!   continuity verifiable while giving up genesis anchoring.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use cawala_control::{
    STRANDED_CLAIM_VERSION, SignedStrandedClaim, StateProof, StrandedClaim, StrandedClaimBundle,
    VerifiedClaim,
};
use cawala_ledger::{
    AccountRef, Amount, LedgerSecretKey, NodeId, OperatorSecretKey, state_inclusion_proof,
};

use crate::control::ControlNode;
use crate::ledger_keys::LEDGER_KEY_FILE;
use crate::ledger_peers::load_peers;
use crate::ledger_service::LedgerService;
use crate::record::NodeRecord;

/// Maximum size of a bundle file accepted by [`review_bundle_file`].
///
/// A genesis-anchored bundle is bounded by the commitment log, but review must
/// never be an unbounded read of an operator-supplied path: 1 MiB is far above
/// any honest bundle and far below a memory concern.
pub const MAX_BUNDLE_FILE_BYTES: u64 = 1024 * 1024;

/// Maximum number of ancestor commitments carried in a bundle's `chain`.
///
/// The commitment log can hold up to
/// [`MAX_COMMITMENTS`](crate::ledger_commitments::MAX_COMMITMENTS), which would
/// exceed the file cap as JSON. When the chain is longer than this, export
/// carries the most recent suffix: child-to-head continuity still verifies, but
/// the chain no longer reaches genesis (so genesis anchoring is unavailable).
pub const MAX_BUNDLE_CHAIN: usize = 128;

/// The result of a successful [`export_bundle`].
#[derive(Debug, Clone)]
pub struct ExportOutcome {
    /// The self-verified bundle to write or print.
    pub bundle: StrandedClaimBundle,
    /// The display-only verification result.
    pub verified: VerifiedClaim,
    /// Whether a fresh commitment had to be appended before proving.
    pub committed: bool,
    /// Total ancestor commitments in the log (excluding the head).
    pub chain_total: usize,
    /// Ancestor commitments actually carried in `bundle.chain`.
    pub chain_included: usize,
}

/// Build a self-attested [`StrandedClaimBundle`] from this node's own state.
///
/// Loads the node's **existing** ledger key (never creating one — a clear error
/// is returned when it is absent), appends a fresh commitment when the ledger
/// has entries past the commitment head (A6), proves the `Parent` balance
/// against that head, and self-verifies the bundle before returning it.
///
/// `from` is the parent the node says it detached from; when supplied it is
/// carried as `detached_from` and, when present in the peer registry, as
/// `edge` (review context only — never verified).
pub fn export_bundle(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    from: Option<&NodeId>,
    now: u64,
) -> Result<ExportOutcome> {
    let ledger_key = load_existing_ledger_key(data_dir)?;

    let mut service = LedgerService::open(data_dir, node_id)?;
    let mut commitments = service.commitments()?;

    // A6: the proof is built over the current balances, which are only bound by
    // a commitment at the same height. If the ledger is ahead of (or has no)
    // commitment head, append one first; `commit` re-reads the log, signs with
    // the existing ledger key, and refuses a duplicate height.
    let ledger_len = service.ledger().len() as u64;
    if commitments.height() > ledger_len {
        bail!(
            "commitment head height {} is ahead of the ledger's {ledger_len} entries; \
             the commitment log and ledger disagree",
            commitments.height()
        );
    }
    let head_advanced = commitments.is_empty() || ledger_len > commitments.height();
    let committed = if head_advanced {
        service.commit().with_context(|| {
            format!(
                "refusing to export: could not append a commitment at the ledger head \
                 ({ledger_len} entries) so the state proof would match the head"
            )
        })?;
        commitments = service.commitments()?;
        true
    } else {
        false
    };

    let head = commitments
        .chain()
        .last()
        .cloned()
        .context("refusing to export: the commitment log is empty after committing")?;

    let balances = service.ledger().balances();
    let parent_balance = balances.parent_balance().unwrap_or(Amount::ZERO).get() as i128;
    let (index, proof) = state_inclusion_proof(balances, &AccountRef::Parent)
        .context("refusing to export: could not build a Parent inclusion proof")?;
    let tree_size = balances.accounts().count();

    // `chain` is everything before the head, ascending. Truncate to the most
    // recent suffix if it exceeds the bound.
    let ancestors = &commitments.chain()[..commitments.len() - 1];
    let chain_total = ancestors.len();
    let chain: Vec<_> = if ancestors.len() > MAX_BUNDLE_CHAIN {
        ancestors[ancestors.len() - MAX_BUNDLE_CHAIN..].to_vec()
    } else {
        ancestors.to_vec()
    };
    let chain_included = chain.len();

    let edge = match from {
        Some(id) => load_peers(data_dir)?.get(id).cloned(),
        None => None,
    };

    let child = NodeId::from(node_id.to_string());
    let bundle = StrandedClaimBundle {
        version: STRANDED_CLAIM_VERSION,
        child: child.clone(),
        child_operator: operator.public(),
        child_ledger: ledger_key.public(),
        claim: SignedStrandedClaim::authorize(
            StrandedClaim {
                version: STRANDED_CLAIM_VERSION,
                node: child,
                detached_from: from.cloned(),
                issued_at: now,
            },
            operator,
        )
        .map_err(|err| anyhow::anyhow!("could not sign the stranded claim: {err}"))?,
        edge,
        commitment: head,
        parent_balance,
        parent_proof: Some(StateProof {
            index,
            tree_size,
            proof,
        }),
        chain,
    };

    // A6 self-verify: catch the commit/prove coupling (and any other internal
    // inconsistency) before the operator ever sees a bundle that cannot verify.
    let verified = bundle.verify_bundle(now).with_context(|| {
        "refusing to export: the produced stranded claim bundle does not verify".to_string()
    })?;

    Ok(ExportOutcome {
        bundle,
        verified,
        committed,
        chain_total,
        chain_included,
    })
}

/// Load the node's existing ledger key, erroring clearly when it is absent.
///
/// Unlike [`crate::ledger_keys::load_or_create_ledger_key`] this never
/// generates key material: a `claim-export` must not create a ledger identity
/// as a side effect.
pub fn load_existing_ledger_key(data_dir: &Path) -> Result<LedgerSecretKey> {
    let path = data_dir.join(LEDGER_KEY_FILE);
    if !path.exists() {
        bail!(
            "no ledger key at {}; run `cawala-node ledger init` (or `init`) first — \
             claim-export never creates a ledger key",
            path.display()
        );
    }
    let bytes =
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "{} must contain exactly 32 ledger-key bytes, found {}",
            path.display(),
            bytes.len()
        )
    })?;
    Ok(LedgerSecretKey::from_bytes(key))
}

/// Read, parse, and verify a bundle file, returning the display-only
/// [`VerifiedClaim`].
///
/// The read is itself bounded at [`MAX_BUNDLE_FILE_BYTES`]: the file is opened
/// and read through a `take(MAX + 1)` so a file that grows between any prior
/// check and the read can never be read past the cap. An oversized file is
/// rejected with a clear error. Parse and verification failures carry the file
/// path in the error.
pub fn review_bundle_file(path: &Path, now: u64) -> Result<VerifiedClaim> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open bundle file {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_BUNDLE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read bundle file {}", path.display()))?;
    if bytes.len() as u64 > MAX_BUNDLE_FILE_BYTES {
        // The bounded read guarantees we never hold more than the cap + 1; the
        // best-effort stat is only to report the true on-disk size when known.
        let reported = std::fs::metadata(path)
            .map(|meta| meta.len())
            .unwrap_or(bytes.len() as u64);
        bail!(
            "bundle file {} is {reported} bytes, exceeding the {MAX_BUNDLE_FILE_BYTES}-byte cap",
            path.display(),
        );
    }
    let bundle: StrandedClaimBundle = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "{} is not a valid stranded claim bundle (JSON)",
            path.display()
        )
    })?;
    bundle.verify_bundle(now).with_context(|| {
        format!(
            "stranded claim bundle {} failed verification",
            path.display()
        )
    })
}

/// The state-proof-checked, self-attested magnitude and honesty notes for an
/// export, as plain text.
pub fn export_summary(outcome: &ExportOutcome) -> String {
    let mut lines = vec![
        format!(
            "state-proof-checked attested Parent balance: {}",
            outcome.verified.parent_balance
        ),
        format!("commitment height: {}", outcome.verified.commitment_height),
        format!(
            "chain: {} of {} ancestor commitment(s) included",
            outcome.chain_included, outcome.chain_total
        ),
    ];
    if outcome.chain_included < outcome.chain_total {
        lines.push(
            "note: chain truncated to the most recent suffix; genesis anchoring is \
             unavailable, but continuity still verifies"
                .to_string(),
        );
    }
    if outcome.committed {
        lines.push(
            "note: appended a fresh commitment so the state proof matches the ledger head"
                .to_string(),
        );
    }
    lines.push(
        "note: review evidence, not a guarantee — the child authors its own ledger, so \
         the magnitude is self-attested"
            .to_string(),
    );
    lines.join("\n")
}

/// What the review can *label* as `state-proof-checked attested Parent balance`
/// but cannot prove, spelled out so the label is never read as a payable debt.
///
/// The state proof only shows that the presenter's own committed head records
/// this `Parent` balance. The presenter authors that ledger, the committed head
/// need not be their latest, and the `edge`/`detached_from` registry row is
/// unverified context — none of it compels payment.
const NOT_PROVEN: &str = "not proven:\n  \
- the amount is self-attested: the presenter authors their own ledger, so the state proof \
shows only what the presenter's own committed head records\n  \
- the committed head may not be the presenter's latest state\n  \
- the edge/detached_from registry row is unverified context, not evidence that any old \
parent ever owed the amount\n  \
- nothing here compels payment or creates an obligation; recognising the balance is a \
discretionary operator decision";

/// The reviewer's exposure guidance for a verified bundle.
///
/// This always appends the [`NOT_PROVEN`] block: the positive branch's
/// "funding N to match" line is the only place in review that could be misread
/// as a payable debt, so the block is stated for both a zero and a non-zero
/// balance.
pub fn review_guidance(verified: &VerifiedClaim) -> String {
    let exposure = if verified.parent_balance > 0 {
        format!(
            "exposure: funding {} to match clears the hard UnbackedClaim on the new \
             parent's books; not funding leaves the parent balance visible as a stranded claim",
            verified.parent_balance
        )
    } else {
        "exposure: parent balance is zero; no prefund is needed to clear an UnbackedClaim"
            .to_string()
    };
    format!("{exposure}\n{NOT_PROVEN}")
}

/// This node's attachment state, derived from its record (control-plane only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attachment {
    /// The record has a parent link.
    Parented,
    /// No parent link and the asserted address is `0` (a top-level root).
    Root,
    /// No parent link and no root address (detached / never attached).
    NoParent,
}

impl Attachment {
    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Attachment::Parented => "parented",
            Attachment::Root => "root",
            Attachment::NoParent => "no parent",
        }
    }
}

/// Classify `record`'s attachment state.
pub fn attachment_state(record: &NodeRecord) -> Attachment {
    if record.parent.is_some() {
        Attachment::Parented
    } else if record.address.as_ref().is_some_and(|addr| addr.is_root()) {
        Attachment::Root
    } else {
        Attachment::NoParent
    }
}

/// The outcome of the one-shot parent liveness probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentReachability {
    /// The record has no parent link; nothing was dialed.
    NoParent,
    /// The parent answered a direct control request (any reply counts).
    Reachable,
    /// The parent could not be reached; the dial error is carried for display.
    Unreachable(String),
}

/// Probe this node's recorded parent with one short direct-control exchange.
///
/// Signs a `RebasePull` (the existing child→parent control dial) and sends it
/// with `timeout`; **any** reply — including a rejection — proves the parent is
/// reachable, so this is a pure liveness check with no state mutation and no
/// gating. Returns [`ParentReachability::NoParent`] when the record has no
/// parent link.
///
/// # Side effects on the parent are expected
///
/// The probe is signed with a fresh nonce, so a **parent that still lists this
/// node as a current child** audits a `rebase-pull` line for it. Independently,
/// the parent's replay guard persists a mark for that fresh nonce. Repeating
/// `parent-status` therefore leaves one audit line and one replay mark on the
/// **parent** per run by design; that is expected, not an error, and the probe
/// mutates no state on this node.
pub async fn probe_parent(
    endpoint: &iroh::Endpoint,
    control: &std::sync::Arc<tokio::sync::Mutex<ControlNode>>,
    timeout: Duration,
    now: u64,
) -> Result<ParentReachability> {
    let (parent_id, signed) = {
        let engine = control.lock().await;
        let Some(parent) = engine.record().parent.as_ref() else {
            return Ok(ParentReachability::NoParent);
        };
        let Some(signed) = engine.sign_rebase_pull(now) else {
            return Ok(ParentReachability::NoParent);
        };
        (parent.parent_id.clone(), signed)
    };
    let target: iroh::EndpointId = parent_id.parse().map_err(|err| {
        anyhow::anyhow!("recorded parent '{parent_id}' is not an endpoint id: {err}")
    })?;
    match ControlNode::send_direct(endpoint, target, &signed, timeout).await {
        Ok(_reply) => Ok(ParentReachability::Reachable),
        Err(err) => Ok(ParentReachability::Unreachable(err.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cawala_ledger::{OperatorPubKey, OperatorSecretKey};

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn node_id(operator: &OperatorSecretKey) -> String {
        operator.public().to_string()
    }

    fn record_with_parent(parent: &str) -> NodeRecord {
        let mut record = NodeRecord::new("self");
        record.parent = Some(crate::record::ParentLink {
            parent_id: parent.to_string(),
            slot: 0,
        });
        record
    }

    #[test]
    fn attachment_state_classifies_parent_root_and_detached() {
        let parented = record_with_parent("p");
        assert_eq!(attachment_state(&parented), Attachment::Parented);

        let mut root = NodeRecord::new("self");
        root.address = Some("0".parse().unwrap());
        assert_eq!(attachment_state(&root), Attachment::Root);

        let detached = NodeRecord::new("self");
        assert_eq!(attachment_state(&detached), Attachment::NoParent);
    }

    #[test]
    fn load_existing_ledger_key_errors_without_creating_one() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_existing_ledger_key(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("no ledger key"),
            "unexpected error: {err}"
        );
        assert!(!dir.path().join(LEDGER_KEY_FILE).exists());
    }

    #[test]
    fn guidance_reflects_the_magnitude() {
        let op: OperatorPubKey = operator(1).public();
        let positive = VerifiedClaim {
            child: NodeId::from("child"),
            child_operator: op,
            detached_from: None,
            issued_at: 1,
            parent_balance: 42,
            commitment_height: 3,
        };
        assert!(review_guidance(&positive).contains("funding 42 to match"));

        let zero = VerifiedClaim {
            parent_balance: 0,
            ..positive
        };
        assert!(review_guidance(&zero).contains("no prefund is needed"));
    }

    #[test]
    fn guidance_states_what_the_state_proof_does_not_prove() {
        let op: OperatorPubKey = operator(2).public();
        let positive = VerifiedClaim {
            child: NodeId::from("child"),
            child_operator: op,
            detached_from: None,
            issued_at: 1,
            parent_balance: 42,
            commitment_height: 3,
        };
        let text = review_guidance(&positive);

        // M1: the reviewer must see the four limits of the evidence, so the
        // "funding N to match" line is never read as a payable debt.
        for phrase in [
            "not proven:",
            "self-attested",
            "presenter authors their own ledger",
            "may not be the presenter's latest state",
            "unverified context",
            "not evidence that any old parent ever owed the amount",
            "nothing here compels payment or creates an obligation",
            "discretionary operator decision",
        ] {
            assert!(
                text.contains(phrase),
                "guidance is missing {phrase:?}:\n{text}"
            );
        }

        // The block is unconditional: a zero balance is still not a debt.
        let zero = VerifiedClaim {
            parent_balance: 0,
            ..positive
        };
        assert!(review_guidance(&zero).contains("not proven:"));
    }

    #[test]
    fn node_id_is_the_operator_hex() {
        // Guards the node-id == operator-key identity the bundle relies on.
        let op = operator(7);
        assert_eq!(node_id(&op).len(), 64);
        assert_eq!(node_id(&op), op.public().to_string());
    }
}
