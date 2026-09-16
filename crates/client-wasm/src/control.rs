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
    CONTROL_ALPN, CONTROL_FORMAT_VERSION, CONTROL_REQUEST_TTL_SECS, ControlReply, ControlRequest,
    Invite, JoinApproval, JoinRejection, MAX_CONTROL_FRAME, NodeId, OperatorSecretKey, RejectCode,
    SignedControl,
};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{EndpointAddr, EndpointId, TransportAddr};
use tracing::info;

use crate::dto::ControlEventDto;
use crate::state::{LocalStateV1, Transition};
use crate::{now_unix_seconds, to_js_err};

/// Per-request direct-control deadline, mirroring the native client.
const CONTROL_TIMEOUT_SECS: u64 = 15;

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
        }
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
        if signed.version != CONTROL_FORMAT_VERSION {
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
            ControlRequest::Query => self.handle_query(signed),
            _ => ControlReply::Rejected(RejectCode::Unauthorized),
        }
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
            self.shared
                .push_event(ControlEventDto::accepted(&signed.origin, approval));
        }
        transition.reply()
    }

    /// Consume a parent's rejection of our outbound join.
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
