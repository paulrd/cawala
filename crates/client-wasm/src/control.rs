//! Shared control-plane state, the inbound `cawala/control/0` accept handler,
//! and the direct request/response exchange used to send one control frame.
//!
//! The wire shape mirrors the native node exactly: one request/response per
//! bi-directional stream, a [`SignedControl`] request, and a [`ControlReply`]
//! response bounded by [`MAX_CONTROL_FRAME`]. The browser client only ever
//! receives `JoinApproved`/`JoinRejected` by reverse dial and answers
//! self-admin `Query`; everything else is refused as unauthorized.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use cawala_control::{
    CONTROL_ALPN, CONTROL_REQUEST_TTL_SECS, ControlReply, ControlRequest, DetachNotice, Invite,
    JoinApproval, JoinRejection, MAX_CONTROL_FRAME, NodeId, OperatorPubKey, OperatorSecretKey,
    ROUTED_CONTROL_VERSION, RebaseNotice, RejectCode, RoutedControlV1, RoutedForward,
    SignedControl, SignedRoutedReply, is_supported_control_version,
};
use cawala_msg::{Envelope, MSG_CONTROL_V1, MsgId, PeerRef};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{EndpointAddr, EndpointId, TransportAddr};
use tracing::info;

use crate::dto::ControlEventDto;
use crate::state::{LocalStateV1, Transition};
use crate::{now_unix_seconds, to_js_err};

/// Per-request direct-control deadline, mirroring the native client.
const CONTROL_TIMEOUT_SECS: u64 = 15;

/// Deadline for a correlated tree-routed control reply.
///
/// A routed request first walks up to the LCA and back down before the target
/// can answer, so this is deliberately generous; without a bound a browser
/// could await a reply that will never arrive.
pub(crate) const ROUTED_REPLY_TIMEOUT_SECS: u64 = 15;

/// Join requests created without an explicit expiry live this long.
pub(crate) const JOIN_TTL_SECONDS: u64 = 3600;

/// State shared between [`crate::ClientNode`] and the inbound control handler.
///
/// The two [`std::sync::Mutex`]es are always locked for a short synchronous
/// section and never held across an `.await`, matching the wasm single-thread
/// constraints.
pub(crate) struct SharedControl {
    node_id: String,
    pub(crate) operator: Option<OperatorSecretKey>,
    /// A delegated administrator key (K_admin), supplied by JS at runtime.
    ///
    /// This is **never** persisted on the Rust side and never enters
    /// [`LocalStateV1`] or the exported state blobs; the PWA owns its storage.
    admin: Mutex<Option<OperatorSecretKey>>,
    state: Mutex<LocalStateV1>,
    events: Mutex<VecDeque<ControlEventDto>>,
    /// In-memory ordering guard for inbound `Rebase` notices (see
    /// [`RebaseGuard`]).
    rebase_guard: Mutex<RebaseGuard>,
}

/// In-memory high-water mark of `RebaseNotice.generation` applied from the
/// current parent.
///
/// A browser `User` leaf has no children and runs **no** healing pull, so a
/// stale notice would otherwise stick until the parent happened to push again.
/// This guard ignores a notice whose generation is below the highest already
/// applied from the same parent, refuses an equal generation that disagrees on
/// the address, and applies a strictly higher one. It is reset whenever the
/// recorded parent changes (including a fresh join or a detach).
///
/// It is deliberately **not** part of [`LocalStateV1`]: adding a persisted field
/// would force a [`LOCAL_STATE_VERSION`](crate::state::LOCAL_STATE_VERSION) bump
/// and discard every existing user blob. Residual: the guard is lost across a
/// reload, so a stale notice that arrives *only after* a reload is theoretically
/// possible; the parent corrects it on its next push.
#[derive(Debug, Default)]
struct RebaseGuard {
    parent: Option<NodeId>,
    generation: u64,
}

impl SharedControl {
    /// Build shared control state for `node_id`; `operator` is `Some` only for
    /// endpoints bound with a stable control identity.
    pub(crate) fn new(node_id: String, operator: Option<OperatorSecretKey>) -> Self {
        SharedControl {
            node_id,
            operator,
            admin: Mutex::new(None),
            state: Mutex::new(LocalStateV1::new()),
            events: Mutex::new(VecDeque::new()),
            rebase_guard: Mutex::new(RebaseGuard::default()),
        }
    }

    /// Lock the in-memory re-base ordering guard, recovering from poisoning.
    fn lock_rebase_guard(&self) -> MutexGuard<'_, RebaseGuard> {
        self.rebase_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Drop the re-base ordering guard: the next notice re-seeds it for
    /// whatever parent is then recorded. Called on a fresh join or a detach.
    fn reset_rebase_guard(&self) {
        *self.lock_rebase_guard() = RebaseGuard::default();
    }

    /// This endpoint's node id.
    pub(crate) fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Install (or clear) the delegated admin key.
    pub(crate) fn set_admin(&self, admin: Option<OperatorSecretKey>) {
        let mut slot = self
            .admin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = admin;
    }

    /// The delegated admin key, if one is configured (cloned for signing).
    pub(crate) fn admin_key(&self) -> Option<OperatorSecretKey> {
        self.admin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Lock the local state, recovering from a poisoned lock.
    pub(crate) fn lock_state(&self) -> MutexGuard<'_, LocalStateV1> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Lock the event queue, recovering from a poisoned lock.
    pub(crate) fn lock_events(&self) -> MutexGuard<'_, VecDeque<ControlEventDto>> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Queue an event for [`crate::ClientNode::try_recv_control_event`].
    pub(crate) fn push_event(&self, event: ControlEventDto) {
        self.lock_events().push_back(event);
    }
}

/// Server side of the direct control protocol for a browser leaf.
///
/// In the A′ increment a browser only ever receives three request kinds:
/// `JoinApproved` and `JoinRejected` (reverse-dialed by its parent) and a
/// self-admin `Query`. All mutations of the local state happen here.
pub(crate) struct ControlHandler {
    shared: Arc<SharedControl>,
}

impl std::fmt::Debug for ControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlHandler")
            .field("node_id", &self.shared.node_id())
            .finish_non_exhaustive()
    }
}

impl ControlHandler {
    /// Wrap shared state.
    pub(crate) fn new(shared: Arc<SharedControl>) -> Self {
        ControlHandler { shared }
    }

    /// Dispatch exactly one signed request, synchronously.
    fn handle(&self, signed: &SignedControl) -> ControlReply {
        if !is_supported_control_version(signed.version) {
            return ControlReply::Rejected(RejectCode::BadVersion);
        }
        // Companion to the v3 wire change: never act on an already-expired
        // frame, even if its signature is otherwise valid.
        if signed.expiry < now_unix_seconds() {
            return ControlReply::Rejected(RejectCode::Expired);
        }
        match &signed.request {
            ControlRequest::JoinApproved(approval) => self.handle_join_approved(signed, approval),
            ControlRequest::JoinRejected(rejection) => self.handle_join_rejected(signed, rejection),
            ControlRequest::Rebase(notice) => self.handle_rebase(signed, notice),
            ControlRequest::DetachNotice(notice) => self.handle_detach_notice(signed, notice),
            ControlRequest::Query => self.handle_query(signed),
            _ => ControlReply::Rejected(RejectCode::Unauthorized),
        }
    }

    /// Apply a parent-signed [`RebaseNotice`] to the local address.
    ///
    /// # Trust rule
    ///
    /// A browser keeps no [`PeerRegistry`](cawala_ledger::PeerRegistry), so the
    /// native `verify_control` binding (origin → registered operator → signed
    /// controller) is reconstructed from what a joined leaf actually knows:
    ///
    /// 1. the frame self-signature verifies under `signed.controller`
    ///    ([`SignedControl::verify_signature`]);
    /// 2. `signed.controller` is the operator key named by `signed.origin`
    ///    ([`origin_binds_controller`]) — the node-id == operator-key invariant
    ///    the rest of this client already relies on
    ///    ([`operator_key_from_node`]), which closes the "claim the parent's
    ///    origin under an attacker key" forgery;
    /// 3. the sender is exactly the **endpoint id the join was sent to**,
    ///    recorded in `record.parent` — the sole routing neighbor whose
    ///    `JoinApproved` created the link — which is the same recorded-parent
    ///    match [`LocalStateV1::on_join_approved`] applies to approvals; steps 2
    ///    and 3 together bind the signing key to that endpoint id (node id ==
    ///    operator key), so the sender cannot claim the parent's origin under a
    ///    different key;
    /// 4. the notice targets this client and `notice.address ==
    ///    notice.parent_address.child(record.parent.slot)`, enforced again in
    ///    [`LocalStateV1::apply_rebase`].
    ///
    /// A stale former parent or a sibling fails step 3 (or step 2 if it forges
    /// the origin) and is refused. This is not an unpinned trust-on-first-use
    /// gap: the parent operator is key-bound to the endpoint id this client
    /// dialed, the same invariant `JoinApproved` relies on. An invite is
    /// stronger only in that it additionally pins the operator key out of band
    /// before the join; that pin is checked in `on_join_approved`.
    fn handle_rebase(&self, signed: &SignedControl, notice: &RebaseNotice) -> ControlReply {
        if signed.verify_signature().is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if notice.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        if notice.node.as_str() != self.shared.node_id() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        // Clone the parent link out of the lock before mutating the state.
        let parent = self.shared.lock_state().record.parent.clone();
        let Some(parent) = parent else {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        };
        if signed.origin != parent.node_id || !origin_binds_controller(signed) {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if notice.address != notice.parent_address.child(parent.slot) {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        // In-memory ordering guard, keyed to the current parent. The parent's
        // `generation` is its own monotonic address epoch; a browser leaf has no
        // healing pull, so a stale notice must not move it back. Reset whenever
        // the recorded parent changes.
        let stored = {
            let mut guard = self.shared.lock_rebase_guard();
            if guard.parent.as_ref() != Some(&parent.node_id) {
                guard.parent = Some(parent.node_id.clone());
                guard.generation = 0;
            }
            guard.generation
        };
        if notice.generation < stored {
            // Stale: ignore, but accept so the parent stops retrying.
            return ControlReply::Accepted;
        }
        if notice.generation == stored {
            let already =
                self.shared.lock_state().record.address.as_ref() == Some(&notice.address);
            if already {
                return ControlReply::Accepted;
            }
            // The same generation must not disagree on the address.
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        // Strictly newer: apply and advance the high-water mark.
        let transition = self
            .shared
            .lock_state()
            .apply_rebase(&notice.parent_address, &notice.address);
        if matches!(transition, Transition::Rebased | Transition::None) {
            self.shared.lock_rebase_guard().generation = notice.generation;
        }
        transition.reply()
    }

    /// Apply a parent-signed [`DetachNotice`]: clear the local parent and
    /// address (a browser is a `User` leaf, so it takes the clear-both branch
    /// of the address law).
    ///
    /// The trust rule is exactly [`ControlHandler::handle_rebase`]'s: valid
    /// self-signature, controller bound to the origin, and the sender equal to
    /// the recorded parent. This is a deliberate duplicate of that parent check
    /// rather than a shared helper because the two handlers differ in the
    /// topology validation they apply after it. An already-detached client
    /// accepts idempotently (mirroring the native handler) and emits no event.
    fn handle_detach_notice(&self, signed: &SignedControl, notice: &DetachNotice) -> ControlReply {
        if signed.verify_signature().is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if notice.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        if notice.node.as_str() != self.shared.node_id() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        // Already detached: nothing to verify or apply.
        let parent = self.shared.lock_state().record.parent.clone();
        let Some(parent) = parent else {
            return ControlReply::Accepted;
        };
        if signed.origin != parent.node_id || !origin_binds_controller(signed) {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        let transition = self.shared.lock_state().apply_detach();
        if matches!(transition, Transition::Detached) {
            // The parent is gone: drop the ordering guard with it.
            self.shared.reset_rebase_guard();
            self.shared
                .push_event(ControlEventDto::detached(&parent.node_id));
        }
        transition.reply()
    }

    /// Apply a parent's approval to the local record.
    fn handle_join_approved(
        &self,
        signed: &SignedControl,
        approval: &JoinApproval,
    ) -> ControlReply {
        if signed.verify_signature().is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        let transition = self.shared.lock_state().on_join_approved(
            self.shared.node_id(),
            approval,
            &signed.origin,
            &signed.controller,
        );
        if matches!(transition, Transition::Approved) {
            // A fresh link has no known generation: reset the ordering guard.
            self.shared.reset_rebase_guard();
            self.shared
                .push_event(ControlEventDto::accepted(&signed.origin, approval));
        }
        transition.reply()
    }

    /// Consume a parent's rejection of our outbound join.
    ///
    /// Matching (parent, pinned signer, and nonce staleness) is enforced by
    /// [`crate::state::LocalStateV1::on_join_rejected`], which is authoritative.
    fn handle_join_rejected(
        &self,
        signed: &SignedControl,
        rejection: &JoinRejection,
    ) -> ControlReply {
        if signed.verify_signature().is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if rejection.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        let transition = self.shared.lock_state().on_join_rejected(
            rejection,
            &signed.origin,
            &signed.controller,
        );
        if let Transition::Rejected { parent, reason } = &transition {
            self.shared
                .push_event(ControlEventDto::rejected(parent, Some(reason.clone())));
        }
        transition.reply()
    }

    /// Answer a self-admin `Query` with the local snapshot; refuse everyone
    /// else.
    fn handle_query(&self, signed: &SignedControl) -> ControlReply {
        let is_self = signed.origin.as_str() == self.shared.node_id();
        let is_own_operator = self
            .shared
            .operator
            .as_ref()
            .is_some_and(|operator| signed.controller == operator.public());
        if is_self && is_own_operator && signed.verify_signature().is_ok() {
            let snapshot = self
                .shared
                .lock_state()
                .to_node_snapshot(self.shared.node_id());
            ControlReply::Snapshot(snapshot)
        } else {
            ControlReply::Rejected(RejectCode::Unauthorized)
        }
    }
}

impl ProtocolHandler for ControlHandler {
    /// One request/response per bi-directional stream, mirroring
    /// `cawala_node::control::ControlHandler`.
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        let (mut send, mut recv) = connection.accept_bi().await?;
        let signed: SignedControl =
            proto::read_framed_with_limit::<SignedControl, _>(&mut recv, MAX_CONTROL_FRAME).await?;
        let reply = self.handle(&signed);
        info!(%remote, kind = reply_kind(&reply), "control reply");
        proto::write_framed(&mut send, &reply).await?;
        send.finish()?;

        // Keep the stream alive until the remote closes so the reply is
        // delivered before the connection tears down.
        connection.closed().await;
        Ok(())
    }
}

/// Build the direct dial target for an [`Invite`], applying its optional
/// `relay`/`ip` transport hints.
///
/// The native node keeps this logic in its `control` module, but that crate
/// pulls `tokio`/`fs` and is not wasm-safe, so the ~15-line conversion is
/// duplicated here.
pub(crate) fn invite_endpoint_addr(invite: &Invite) -> Result<EndpointAddr, wasm_bindgen::JsError> {
    let parent: EndpointId = invite.parent.as_str().parse().map_err(|err| {
        to_js_err(format!(
            "invalid parent endpoint id '{}': {err}",
            invite.parent
        ))
    })?;
    let mut addrs = Vec::new();
    if let Some(url) = &invite.relay {
        let relay: iroh::RelayUrl = url
            .as_str()
            .parse()
            .map_err(|err| to_js_err(format!("invalid relay URL in invite: {err}")))?;
        addrs.push(TransportAddr::Relay(relay));
    }
    if let Some(ip) = invite.ip {
        addrs.push(TransportAddr::Ip(ip));
    }
    Ok(if addrs.is_empty() {
        EndpointAddr::from(parent)
    } else {
        EndpointAddr::from_parts(parent, addrs)
    })
}

/// Dial `target` on [`CONTROL_ALPN`] and perform one signed request/response
/// exchange, bounded by [`CONTROL_TIMEOUT_SECS`].
///
/// Uses [`n0_future::time::timeout`] (never a `tokio` runtime) because this
/// runs on wasm.
pub(crate) async fn exchange_control(
    endpoint: &iroh::Endpoint,
    target: EndpointAddr,
    signed: &SignedControl,
) -> Result<ControlReply, wasm_bindgen::JsError> {
    let exchange = async {
        let connection = endpoint
            .connect(target, CONTROL_ALPN)
            .await
            .map_err(to_js_err)?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(to_js_err)?;
        proto::write_framed(&mut send, signed)
            .await
            .map_err(to_js_err)?;
        send.finish().map_err(to_js_err)?;
        let reply: ControlReply =
            proto::read_framed_with_limit::<ControlReply, _>(&mut recv, MAX_CONTROL_FRAME)
                .await
                .map_err(to_js_err)?;
        connection.close(0u8.into(), b"done");
        Ok::<ControlReply, wasm_bindgen::JsError>(reply)
    };
    n0_future::time::timeout(
        n0_future::time::Duration::from_secs(CONTROL_TIMEOUT_SECS),
        exchange,
    )
    .await
    .map_err(|_| wasm_bindgen::JsError::new("control request timed out"))?
}

/// Build an operator-signed admin request addressed to `target`.
///
/// `origin` is the target node id (the running node's engine requires
/// `signed.origin == self.node_id`), `controller` is the delegated admin key, the
/// nonce is fresh, and the expiry is `now + CONTROL_REQUEST_TTL_SECS` so a
/// browser clock cannot mint an over-long-lived frame.
pub(crate) fn sign_admin_request(
    target: EndpointId,
    admin: &OperatorSecretKey,
    request: ControlRequest,
) -> Result<SignedControl, wasm_bindgen::JsError> {
    let mut nonce_bytes = [0u8; 8];
    getrandom::fill(&mut nonce_bytes).map_err(to_js_err)?;
    SignedControl::authorize(
        NodeId::from(target.to_string()),
        admin,
        u64::from_le_bytes(nonce_bytes),
        now_unix_seconds().saturating_add(CONTROL_REQUEST_TTL_SECS),
        request,
    )
    .map_err(to_js_err)
}

/// Sign an admin request with `admin` and directly exchange it with `target` on
/// [`CONTROL_ALPN`].
///
/// Dialing uses an id-only [`EndpointAddr`], exactly like the join path, so the
/// N0 address-lookup service resolves the node.
pub(crate) async fn exchange_admin(
    endpoint: &iroh::Endpoint,
    target: EndpointId,
    admin: &OperatorSecretKey,
    request: ControlRequest,
) -> Result<ControlReply, wasm_bindgen::JsError> {
    let signed = sign_admin_request(target, admin, request)?;
    exchange_control(endpoint, EndpointAddr::from(target), &signed).await
}

/// Build the tree-routed request payload for one control `intent` addressed to
/// `target`.
///
/// The request is carried by a single [`RoutedForward`] signed under the
/// browser's **operator** key for `requester.node` — NOT the delegated admin
/// key that may have signed `intent`. The first relay verifies that forward
/// against its own child registry, which binds this browser node to its
/// operator key; the delegated `K_admin` travels inside `intent.controller`
/// and is checked end-to-end by the target.
///
/// `grant` is always `None`: a browser never holds a
/// [`SignedAdminGrant`](cawala_control::SignedAdminGrant), and a carried grant
/// is audit evidence only (a carried-but-unstored grant never authorises at
/// the destination), so omitting it loses nothing.
///
/// Returns a plain [`String`] error (not [`wasm_bindgen::JsError`]) so every
/// error path is testable on native targets; the wasm boundary wraps it with
/// [`to_js_err`].
pub(crate) fn build_routed_control(
    target: PeerRef,
    requester: PeerRef,
    intent: SignedControl,
    operator: &OperatorSecretKey,
    forward_nonce: u64,
    forward_expiry: u64,
) -> Result<RoutedControlV1, String> {
    let forward = SignedControl::authorize(
        NodeId::from(requester.node.clone()),
        operator,
        forward_nonce,
        forward_expiry,
        intent.request.clone(),
    )
    .map_err(|err| err.to_string())?;

    let routed = RoutedControlV1 {
        version: ROUTED_CONTROL_VERSION,
        target,
        requester: requester.clone(),
        intent,
        grant: None,
        forwards: vec![RoutedForward::new(requester, forward)],
    };
    routed.validate().map_err(|err| err.to_string())?;
    Ok(routed)
}

/// Wrap an encoded routed-control `payload` in a fresh `MSG_CONTROL_V1`
/// envelope addressed to `target.addr`, originating at `requester`.
pub(crate) fn routed_request_envelope(
    requester: &PeerRef,
    target: &PeerRef,
    msg_id: MsgId,
    nonce: u64,
    payload: Vec<u8>,
) -> Envelope {
    Envelope::new(
        requester.clone(),
        target.addr.clone(),
        msg_id,
        MSG_CONTROL_V1,
        nonce,
        payload,
    )
}

/// Decode and fully verify one routed reply against the request it answers.
///
/// Fails closed: the responder must be exactly `target` (by node id), the
/// `reply_to` must equal `request_msg_id`, the echoed `requester` must equal
/// our own `PeerRef`, and the signature must verify under the target node's
/// operator key. The key is parsed from `target.node` (the node-id == operator
/// key invariant); an unparseable id is refused rather than trusted, so an
/// unverified reply is never surfaced.
///
/// Returns a plain [`String`] error (not [`wasm_bindgen::JsError`]) so every
/// rejection is testable on native targets.
pub(crate) fn verify_routed_reply_bytes(
    payload: &[u8],
    request_msg_id: MsgId,
    target: &PeerRef,
    requester: &PeerRef,
) -> Result<SignedRoutedReply, String> {
    let signed = SignedRoutedReply::from_bytes(payload).map_err(|err| err.to_string())?;
    if signed.reply.reply_to != request_msg_id {
        return Err("routed reply does not answer this request".to_string());
    }
    if signed.reply.responder.node != target.node {
        return Err("routed reply responder is not the requested target".to_string());
    }
    if signed.reply.requester != *requester {
        return Err("routed reply requester is not this client".to_string());
    }
    let responder_key = operator_key_from_node(&target.node)?;
    signed
        .verify(&responder_key)
        .map_err(|err| err.to_string())?;
    Ok(signed)
}

/// Derive the operator public key from a node id string.
///
/// Node ids and operator keys are the same Ed25519 key, so a node id must
/// round-trip through [`EndpointId`]; anything else fails closed.
fn operator_key_from_node(node: &str) -> Result<OperatorPubKey, String> {
    let endpoint: EndpointId = node
        .parse()
        .map_err(|_| "routed reply responder node id is not a valid endpoint id".to_string())?;
    OperatorPubKey::from_bytes(endpoint.as_bytes()).map_err(|err| err.to_string())
}

/// Whether `signed.controller` is the operator key named by `signed.origin`.
///
/// Native nodes and browser leaves derive their operator key from the same
/// Ed25519 seed as their endpoint id, so a node id and its operator public key
/// are one key ([`operator_key_from_node`] is exactly that conversion). The
/// browser has no `PeerRegistry`, so this key identity is the binding
/// `verify_control` would otherwise supply; it fails closed when the origin is
/// not a parseable endpoint id.
fn origin_binds_controller(signed: &SignedControl) -> bool {
    operator_key_from_node(signed.origin.as_str()).is_ok_and(|key| key == signed.controller)
}

/// Whether a failed *direct* admin exchange should be retried over the routed
/// tree.
///
/// A delivered reply — including `Rejected(..)` — means the node answered, so
/// the routed path must never run (the answer would be identical at best, and
/// a fallback could mask a real authorization refusal). Only a transport
/// failure (dial error, timeout, no route) is retried.
pub(crate) fn should_try_routed<T, E>(direct: &Result<T, E>) -> bool {
    direct.is_err()
}

/// Stable label for a reply, for logs.
fn reply_kind(reply: &ControlReply) -> &'static str {
    match reply {
        ControlReply::Accepted => "accepted",
        ControlReply::Pending => "pending",
        ControlReply::Rejected(_) => "rejected",
        ControlReply::Snapshot(_) => "snapshot",
        ControlReply::AdminSnapshot(_) => "admin-snapshot",
        ControlReply::AdminApproved(_) => "admin-approved",
        ControlReply::AdminRejected(_) => "admin-rejected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_control::{ROUTED_REPLY_VERSION, RoutedReplyV1};

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn peer(addr: &str, node: &str) -> PeerRef {
        PeerRef {
            addr: addr.parse().expect("sample address parses"),
            node: node.to_string(),
        }
    }

    /// A delegated-admin-signed intent addressed to `target_node`, mirroring
    /// [`sign_admin_request`].
    fn admin_intent(target_node: &str, admin: &OperatorSecretKey) -> SignedControl {
        SignedControl::authorize(
            NodeId::from(target_node),
            admin,
            11,
            10_000,
            ControlRequest::AdminQuery,
        )
        .expect("intent signs")
    }

    fn routed_reply(
        reply_to: MsgId,
        requester: &PeerRef,
        responder: &PeerRef,
        reply: ControlReply,
    ) -> RoutedReplyV1 {
        RoutedReplyV1 {
            version: ROUTED_REPLY_VERSION,
            reply_to,
            requester: requester.clone(),
            responder: responder.clone(),
            reply,
        }
    }

    #[test]
    fn routed_control_builds_and_reply_round_trips() {
        let target_op = operator(7);
        let admin_op = operator(9);
        let browser_op = operator(1);
        let target = peer("0.3", &target_op.public().to_string());
        let requester = peer("0.1.2", &browser_op.public().to_string());

        let intent = admin_intent(&target.node, &admin_op);
        let routed = build_routed_control(
            target.clone(),
            requester.clone(),
            intent,
            &browser_op,
            42,
            9_000,
        )
        .expect("routed control builds");

        // One forward, no carried grant, and the forward is signed by the
        // browser's operator key (not the delegated admin key in `intent`).
        assert_eq!(routed.forwards.len(), 1);
        assert_eq!(routed.grant, None);
        assert_eq!(routed.forwards[0].hop, requester);
        assert_eq!(
            routed.forwards[0].signed.origin,
            NodeId::from(requester.node.clone())
        );
        assert_eq!(routed.forwards[0].signed.controller, browser_op.public());
        assert_eq!(routed.forwards[0].signed.request, routed.intent.request);
        assert_ne!(routed.intent.controller, browser_op.public());
        assert_eq!(routed.validate(), Ok(()));

        let payload = routed.to_bytes().expect("routed payload encodes");
        let msg_id = MsgId([0x11; 16]);
        let env = routed_request_envelope(&requester, &target, msg_id, 5, payload);
        assert_eq!(env.msg_type, MSG_CONTROL_V1);
        assert_eq!(env.src, requester);
        assert_eq!(env.dst, target.addr);
        assert_eq!(env.msg_id, msg_id);
        assert_eq!(env.hop_chain.len(), 1);

        // The synthetic target node answers; its operator signs the reply.
        let signed = SignedRoutedReply::authorize(
            routed_reply(env.msg_id, &requester, &target, ControlReply::Accepted),
            &target_op,
        )
        .expect("reply signs");
        let bytes = signed.to_bytes().expect("reply encodes");

        let verified = verify_routed_reply_bytes(&bytes, env.msg_id, &target, &requester)
            .expect("reply verifies");
        assert_eq!(verified.reply.reply_to, env.msg_id);
        assert_eq!(verified.reply.requester, requester);
        assert_eq!(verified.reply.responder, target);
        assert_eq!(verified.reply.reply, ControlReply::Accepted);
    }

    #[test]
    fn reply_signed_by_wrong_responder_key_is_rejected() {
        let target_op = operator(7);
        let impostor = operator(8);
        let target = peer("0.3", &target_op.public().to_string());
        let requester = peer("0.1.2", &operator(1).public().to_string());
        let msg_id = MsgId([0x22; 16]);

        // The responder field claims the real target, but the signature is
        // produced by a different key.
        let signed = SignedRoutedReply::authorize(
            routed_reply(msg_id, &requester, &target, ControlReply::Accepted),
            &impostor,
        )
        .expect("reply signs");
        let bytes = signed.to_bytes().expect("reply encodes");

        assert!(verify_routed_reply_bytes(&bytes, msg_id, &target, &requester).is_err());
    }

    #[test]
    fn reply_with_unparseable_target_node_is_rejected() {
        let target_op = operator(7);
        let target = peer("0.3", "node-d");
        let requester = peer("0.1.2", &operator(1).public().to_string());
        let msg_id = MsgId([0x23; 16]);

        // Correctly signed, but the claimed responder node id is not an
        // endpoint id, so no public key can be derived: fail closed.
        let signed = SignedRoutedReply::authorize(
            routed_reply(msg_id, &requester, &target, ControlReply::Accepted),
            &target_op,
        )
        .expect("reply signs");
        let bytes = signed.to_bytes().expect("reply encodes");

        assert!(verify_routed_reply_bytes(&bytes, msg_id, &target, &requester).is_err());
    }

    #[test]
    fn reply_with_mismatched_correlation_is_rejected() {
        let target_op = operator(7);
        let other_op = operator(8);
        let target = peer("0.3", &target_op.public().to_string());
        let requester = peer("0.1.2", &operator(1).public().to_string());
        let msg_id = MsgId([0x33; 16]);

        // Wrong `reply_to`.
        let wrong_reply_to = SignedRoutedReply::authorize(
            routed_reply(
                MsgId([0x44; 16]),
                &requester,
                &target,
                ControlReply::Accepted,
            ),
            &target_op,
        )
        .expect("reply signs");
        let bytes = wrong_reply_to.to_bytes().expect("reply encodes");
        assert!(verify_routed_reply_bytes(&bytes, msg_id, &target, &requester).is_err());

        // Wrong responder node (self-consistently signed by that other node).
        let other_responder = peer("0.4", &other_op.public().to_string());
        let wrong_responder = SignedRoutedReply::authorize(
            routed_reply(msg_id, &requester, &other_responder, ControlReply::Accepted),
            &other_op,
        )
        .expect("reply signs");
        let bytes = wrong_responder.to_bytes().expect("reply encodes");
        assert!(verify_routed_reply_bytes(&bytes, msg_id, &target, &requester).is_err());

        // Wrong requester (target signs a reply for someone else).
        let other_requester = peer("0.1.7", &operator(2).public().to_string());
        let wrong_requester = SignedRoutedReply::authorize(
            routed_reply(msg_id, &other_requester, &target, ControlReply::Accepted),
            &target_op,
        )
        .expect("reply signs");
        let bytes = wrong_requester.to_bytes().expect("reply encodes");
        assert!(verify_routed_reply_bytes(&bytes, msg_id, &target, &requester).is_err());
    }

    #[test]
    fn fallback_only_on_transport_error() {
        let transport: Result<ControlReply, &str> = Err("dial failed");
        assert!(should_try_routed(&transport));

        let refused: Result<ControlReply, &str> =
            Ok(ControlReply::Rejected(RejectCode::Unauthorized));
        assert!(!should_try_routed(&refused));

        let accepted: Result<ControlReply, &str> = Ok(ControlReply::Accepted);
        assert!(!should_try_routed(&accepted));
    }

    // ── M5 exit rights (format 4): Rebase / DetachNotice ─────────────

    /// A browser control handler joined at `0.2.3` under slot 3 of a parent
    /// whose node id and operator key are the same Ed25519 key.
    fn joined_browser() -> (Arc<SharedControl>, OperatorSecretKey, NodeId) {
        let browser_op = operator(1);
        let parent_op = operator(2);
        let browser_id = browser_op.public().to_string();
        let parent_id = NodeId::from(parent_op.public().to_string());
        let shared = Arc::new(SharedControl::new(browser_id, Some(browser_op)));
        {
            let mut state = shared.lock_state();
            state.record.address = Some("0.2.3".parse().expect("sample address parses"));
            state.record.parent = Some(crate::state::ParentLink {
                node_id: parent_id.clone(),
                slot: 3,
            });
        }
        (shared, parent_op, parent_id)
    }

    /// Sign `request` as `origin` under `key` with a far-future expiry.
    fn signed_by(
        origin: &NodeId,
        key: &OperatorSecretKey,
        request: ControlRequest,
    ) -> SignedControl {
        SignedControl::authorize(origin.clone(), key, 7, u64::MAX, request).expect("frame signs")
    }

    fn rebase_request(
        node: &str,
        parent_address: &str,
        address: &str,
        generation: u64,
    ) -> ControlRequest {
        ControlRequest::Rebase(RebaseNotice {
            node: NodeId::from(node),
            parent_address: parent_address.parse().expect("parent address parses"),
            address: address.parse().expect("address parses"),
            generation,
        })
    }

    #[test]
    fn rebase_from_recorded_parent_updates_address_in_place() {
        let (shared, parent_op, parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));
        let signed = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.4", "0.4.3", 2),
        );

        assert_eq!(handler.handle(&signed), ControlReply::Accepted);
        let state = shared.lock_state();
        assert_eq!(state.record.address, Some("0.4.3".parse().unwrap()));
        // The parent link (and slot) survives the prefix move.
        assert_eq!(
            state.record.parent,
            Some(crate::state::ParentLink {
                node_id: parent_id,
                slot: 3,
            })
        );
    }

    #[test]
    fn rebase_to_current_address_is_an_idempotent_accept() {
        let (shared, parent_op, parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));
        let signed = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.2", "0.2.3", 1),
        );

        assert_eq!(handler.handle(&signed), ControlReply::Accepted);
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.2.3".parse().unwrap())
        );
    }

    #[test]
    fn rebase_with_wrong_derivation_is_bad_request() {
        let (shared, parent_op, parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));
        // The slot is 3, so `0.4.4` is not `0.4.child(3)`.
        let signed = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.4", "0.4.4", 2),
        );

        assert_eq!(
            handler.handle(&signed),
            ControlReply::Rejected(RejectCode::BadRequest)
        );
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.2.3".parse().unwrap())
        );
    }

    #[test]
    fn rebase_claiming_parent_origin_under_attacker_key_is_rejected() {
        let (shared, _parent_op, parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));
        let attacker = operator(9);
        // `origin` claims the parent node id, but the frame is signed by the
        // attacker's operator key; the origin/controller binding must fail.
        let signed = signed_by(
            &parent_id,
            &attacker,
            rebase_request(shared.node_id(), "0.4", "0.4.3", 2),
        );

        assert_eq!(
            handler.handle(&signed),
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.2.3".parse().unwrap())
        );
    }

    #[test]
    fn rebase_from_a_stale_or_sibling_parent_is_rejected() {
        let (shared, _parent_op, _parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));
        // A different node (a former parent or a sibling) signs a plausible
        // re-base: the origin does not match the recorded parent.
        let other = operator(3);
        let signed = signed_by(
            &NodeId::from(other.public().to_string()),
            &other,
            rebase_request(shared.node_id(), "0.4", "0.4.3", 2),
        );

        assert_eq!(
            handler.handle(&signed),
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.2.3".parse().unwrap())
        );
    }

    // ── in-memory re-base ordering guard ─────────────────────────────

    /// A notice whose generation is below the highest already applied from the
    /// current parent is ignored: the stale address is not installed.
    #[test]
    fn rebase_lower_generation_is_ignored() {
        let (shared, parent_op, parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));

        let newer = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.5", "0.5.3", 3),
        );
        assert_eq!(handler.handle(&newer), ControlReply::Accepted);
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.5.3".parse().unwrap())
        );

        let stale = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.6", "0.6.3", 1),
        );
        assert_eq!(handler.handle(&stale), ControlReply::Accepted);
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.5.3".parse().unwrap()),
            "a lower generation must not move the leaf"
        );
    }

    /// The same generation may repeat the current address (idempotent) but must
    /// not disagree: a different address is refused and not installed.
    #[test]
    fn rebase_equal_generation_different_address_is_refused() {
        let (shared, parent_op, parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));

        let applied = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.5", "0.5.3", 2),
        );
        assert_eq!(handler.handle(&applied), ControlReply::Accepted);

        // Equal-and-same is an idempotent accept.
        let same = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.5", "0.5.3", 2),
        );
        assert_eq!(handler.handle(&same), ControlReply::Accepted);
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.5.3".parse().unwrap())
        );

        // Equal-and-different is refused.
        let disagree = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.6", "0.6.3", 2),
        );
        assert_eq!(
            handler.handle(&disagree),
            ControlReply::Rejected(RejectCode::BadRequest)
        );
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.5.3".parse().unwrap())
        );
    }

    /// A strictly higher generation is applied and advances the guard.
    #[test]
    fn rebase_higher_generation_applies() {
        let (shared, parent_op, parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));

        let first = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.5", "0.5.3", 1),
        );
        assert_eq!(handler.handle(&first), ControlReply::Accepted);
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.5.3".parse().unwrap())
        );

        let second = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.6", "0.6.3", 2),
        );
        assert_eq!(handler.handle(&second), ControlReply::Accepted);
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.6.3".parse().unwrap())
        );
    }

    /// The guard is keyed to the parent id: a new parent's first notice (low
    /// generation) applies rather than being treated as stale.
    #[test]
    fn rebase_guard_resets_on_parent_change() {
        let (shared, parent_op, parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));

        // Apply a high generation from the first parent.
        let high = signed_by(
            &parent_id,
            &parent_op,
            rebase_request(shared.node_id(), "0.5", "0.5.3", 5),
        );
        assert_eq!(handler.handle(&high), ControlReply::Accepted);

        // Re-home the leaf under a different parent, same slot.
        let new_parent_op = operator(4);
        let new_parent_id = NodeId::from(new_parent_op.public().to_string());
        {
            let mut state = shared.lock_state();
            state.record.parent = Some(crate::state::ParentLink {
                node_id: new_parent_id.clone(),
                slot: 3,
            });
        }

        // Generation 1 from the new parent must apply (guard reset).
        let fresh = signed_by(
            &new_parent_id,
            &new_parent_op,
            rebase_request(shared.node_id(), "0.7", "0.7.3", 1),
        );
        assert_eq!(handler.handle(&fresh), ControlReply::Accepted);
        assert_eq!(
            shared.lock_state().record.address,
            Some("0.7.3".parse().unwrap())
        );
    }

    #[test]
    fn detach_notice_from_recorded_parent_clears_parent_and_address() {
        let (shared, parent_op, parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));
        let signed = signed_by(
            &parent_id,
            &parent_op,
            ControlRequest::DetachNotice(DetachNotice {
                node: NodeId::from(shared.node_id()),
            }),
        );

        assert_eq!(handler.handle(&signed), ControlReply::Accepted);
        {
            let state = shared.lock_state();
            assert!(state.record.parent.is_none());
            assert!(state.record.address.is_none());
            assert_eq!(state.status_label(), "none");
        }
        let events = shared.lock_events();
        let event = events.front().expect("a detached event is queued");
        assert_eq!(event.kind(), "detached");
        assert_eq!(event.parent(), parent_id.to_string());
    }

    #[test]
    fn detach_notice_from_a_wrong_origin_is_rejected_and_state_retained() {
        let (shared, _parent_op, _parent_id) = joined_browser();
        let handler = ControlHandler::new(Arc::clone(&shared));
        let other = operator(3);
        let signed = signed_by(
            &NodeId::from(other.public().to_string()),
            &other,
            ControlRequest::DetachNotice(DetachNotice {
                node: NodeId::from(shared.node_id()),
            }),
        );

        assert_eq!(
            handler.handle(&signed),
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
        let state = shared.lock_state();
        assert!(state.record.parent.is_some());
        assert!(state.record.address.is_some());
        assert!(shared.lock_events().is_empty());
    }
}
