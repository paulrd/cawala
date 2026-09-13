//! Data-transfer objects exposed to JavaScript.
//!
//! All conversions are explicit and lossless-in-spirit: `u64` unix timestamps
//! become `f64` (JavaScript numbers must never receive a raw `u64`/BigInt),
//! wire types (`Url`, `SocketAddr`, `NodeId`, `OctAddr`, operator keys) become
//! strings, and the `ChildKind`/`RejectCode` enums become stable strings rather
//! than `Debug` renderings.

use cawala_control::{ChildKind, Invite, NodeId, OperatorPubKey, RejectCode};
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

use crate::state::LocalStateV1;
use crate::to_js_err;

/// Stable JS string for a [`ChildKind`].
pub(crate) fn child_kind_str(kind: ChildKind) -> &'static str {
    match kind {
        ChildKind::Node => "node",
        ChildKind::User => "user",
    }
}

/// Stable JS string for a [`RejectCode`].
///
/// This is an explicit mapping (never `Debug`) so a future Rust refactor cannot
/// silently change the strings the PWA switches on.
pub(crate) fn reject_code_str(code: RejectCode) -> &'static str {
    match code {
        RejectCode::BadVersion => "bad_version",
        RejectCode::Unauthorized => "unauthorized",
        RejectCode::NotFound => "not_found",
        RejectCode::Capacity => "capacity",
        RejectCode::SlotTaken => "slot_taken",
        RejectCode::SlotOutOfRange => "slot_out_of_range",
        RejectCode::BadRequest => "bad_request",
        RejectCode::NotAttached => "not_attached",
        RejectCode::CrossRegion => "cross_region",
        RejectCode::Internal => "internal",
    }
}

/// Parse and validate a `cawala://join?...` invite URI.
///
/// Returns a fully typed [`InviteInfo`] (operator key as 64-hex lowercase) or a
/// [`JsError`] describing the first structural problem.
#[wasm_bindgen]
pub fn parse_invite(uri: &str) -> Result<InviteInfo, JsError> {
    parse_invite_inner(uri).map_err(to_js_err)
}

/// Pure parse+validate used by [`parse_invite`] and unit tests.
///
/// Kept separate because [`JsError`] cannot be constructed on non-wasm targets,
/// which would make the error paths untestable natively.
fn parse_invite_inner(uri: &str) -> Result<InviteInfo, String> {
    let invite = Invite::parse(uri).map_err(|err| err.to_string())?;
    invite.validate().map_err(|err| err.to_string())?;
    Ok(InviteInfo::from(invite))
}

/// A parsed, validated Cawala invite.
#[wasm_bindgen]
pub struct InviteInfo {
    parent: String,
    operator: String,
    slot: Option<u8>,
    expiry: Option<f64>,
    label: Option<String>,
    relay: Option<String>,
    ip: Option<String>,
}

impl From<Invite> for InviteInfo {
    fn from(invite: Invite) -> Self {
        InviteInfo {
            parent: invite.parent.as_str().to_string(),
            // `Display` for the operator key is lowercase hex.
            operator: invite.operator.to_string(),
            slot: invite.slot,
            expiry: invite.expiry.map(|secs| secs as f64),
            label: invite.label,
            relay: invite.relay.map(|url| url.to_string()),
            ip: invite.ip.map(|ip| ip.to_string()),
        }
    }
}

#[wasm_bindgen]
impl InviteInfo {
    /// The parent node's endpoint id (iroh node public key), as a string.
    #[wasm_bindgen(getter)]
    pub fn parent(&self) -> String {
        self.parent.clone()
    }

    /// The parent's operator public key as 64 lowercase hex characters.
    #[wasm_bindgen(getter)]
    pub fn operator(&self) -> String {
        self.operator.clone()
    }

    /// The requested slot (`0..=7`), or `None` to let the parent pick.
    #[wasm_bindgen(getter)]
    pub fn slot(&self) -> Option<u8> {
        self.slot
    }

    /// Unix-seconds expiry, or `None` when the inviter set none.
    #[wasm_bindgen(getter)]
    pub fn expiry(&self) -> Option<f64> {
        self.expiry
    }

    /// Optional human-readable label.
    #[wasm_bindgen(getter)]
    pub fn label(&self) -> Option<String> {
        self.label.clone()
    }

    /// Optional relay URL transport hint.
    #[wasm_bindgen(getter)]
    pub fn relay(&self) -> Option<String> {
        self.relay.clone()
    }

    /// Optional direct `host:port` transport hint.
    #[wasm_bindgen(getter)]
    pub fn ip(&self) -> Option<String> {
        self.ip.clone()
    }
}

/// The immediate outcome of sending a `Join` request.
#[wasm_bindgen]
pub struct JoinOutcome {
    status: String,
    reject_code: Option<String>,
    reason: Option<String>,
}

impl JoinOutcome {
    /// The parent queued the request for admin approval.
    pub(crate) fn pending() -> Self {
        JoinOutcome {
            status: "pending".to_string(),
            reject_code: None,
            reason: None,
        }
    }

    /// The parent refused the request outright.
    pub(crate) fn rejected(reject_code: Option<String>, reason: Option<String>) -> Self {
        JoinOutcome {
            status: "rejected".to_string(),
            reject_code,
            reason,
        }
    }
}

#[wasm_bindgen]
impl JoinOutcome {
    /// One of `"pending"` or `"rejected"`.
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.clone()
    }

    /// The parent's coarse reject code, when `status == "rejected"`.
    #[wasm_bindgen(getter)]
    pub fn reject_code(&self) -> Option<String> {
        self.reject_code.clone()
    }

    /// A human-readable reason, when one was supplied.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> Option<String> {
        self.reason.clone()
    }
}

/// A local summary of the client's join state.
#[wasm_bindgen]
pub struct JoinStatus {
    state: String,
    parent: Option<String>,
    slot: Option<u8>,
    address: Option<String>,
    reason: Option<String>,
}

impl JoinStatus {
    /// Summarize `state` for the UI.
    pub(crate) fn from_state(state: &LocalStateV1) -> Self {
        let (parent, slot) = match &state.outbound {
            Some(outbound) => (
                Some(outbound.parent.as_str().to_string()),
                outbound.request.desired_slot,
            ),
            None => match &state.record.parent {
                Some(parent) => (Some(parent.node_id.as_str().to_string()), Some(parent.slot)),
                None => (None, None),
            },
        };
        JoinStatus {
            state: state.status_label().to_string(),
            parent,
            slot,
            address: state
                .record
                .address
                .as_ref()
                .map(|address| address.to_string()),
            reason: state
                .last_rejection
                .as_ref()
                .and_then(|rejection| rejection.reason.clone()),
        }
    }
}

#[wasm_bindgen]
impl JoinStatus {
    /// One of `"none"`, `"pending"`, `"joined"`, or `"rejected"`.
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> String {
        self.state.clone()
    }

    /// The parent we are pending under or joined to.
    #[wasm_bindgen(getter)]
    pub fn parent(&self) -> Option<String> {
        self.parent.clone()
    }

    /// The requested (pending) or assigned (joined) slot.
    #[wasm_bindgen(getter)]
    pub fn slot(&self) -> Option<u8> {
        self.slot
    }

    /// The assigned address, once joined.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<String> {
        self.address.clone()
    }

    /// The last rejection reason, if any.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> Option<String> {
        self.reason.clone()
    }
}

/// A control-plane event drained by [`crate::ClientNode::try_recv_control_event`].
#[wasm_bindgen]
pub struct ControlEventDto {
    kind: String,
    parent: String,
    slot: Option<u8>,
    address: Option<String>,
    date_joined: Option<f64>,
    reason: Option<String>,
}

impl ControlEventDto {
    /// An accepted join (a `JoinApproved` was applied).
    pub(crate) fn accepted(parent: &NodeId, approval: &cawala_control::JoinApproval) -> Self {
        ControlEventDto {
            kind: "accepted".to_string(),
            parent: parent.as_str().to_string(),
            slot: Some(approval.slot),
            address: Some(approval.address.to_string()),
            date_joined: Some(approval.date_joined as f64),
            reason: None,
        }
    }

    /// A rejected join.
    pub(crate) fn rejected(parent: &NodeId, reason: Option<String>) -> Self {
        ControlEventDto {
            kind: "rejected".to_string(),
            parent: parent.as_str().to_string(),
            slot: None,
            address: None,
            date_joined: None,
            reason,
        }
    }
}

#[wasm_bindgen]
impl ControlEventDto {
    /// Event kind: `"accepted"` or `"rejected"`.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The parent involved in the event.
    #[wasm_bindgen(getter)]
    pub fn parent(&self) -> String {
        self.parent.clone()
    }

    /// The assigned slot, for accepted events.
    #[wasm_bindgen(getter)]
    pub fn slot(&self) -> Option<u8> {
        self.slot
    }

    /// The assigned address, for accepted events.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<String> {
        self.address.clone()
    }

    /// Unix-seconds join time, for accepted events.
    #[wasm_bindgen(getter)]
    pub fn date_joined(&self) -> Option<f64> {
        self.date_joined
    }

    /// The rejection reason, for rejected events.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> Option<String> {
        self.reason.clone()
    }
}

/// This client's parent link, as returned in [`SnapshotDto`].
#[wasm_bindgen]
#[derive(Clone)]
pub struct ParentDto {
    node_id: String,
    slot: u8,
    address: String,
}

#[wasm_bindgen]
impl ParentDto {
    /// The parent node id.
    #[wasm_bindgen(getter)]
    pub fn node_id(&self) -> String {
        self.node_id.clone()
    }

    /// The slot this client occupies under its parent.
    #[wasm_bindgen(getter)]
    pub fn slot(&self) -> u8 {
        self.slot
    }

    /// The parent's derived address.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }
}

/// One child link, as returned in [`SnapshotDto`].
#[wasm_bindgen]
#[derive(Clone)]
pub struct ChildDto {
    child_id: String,
    kind: String,
    slot: u8,
    address: Option<String>,
    date_joined: f64,
}

#[wasm_bindgen]
impl ChildDto {
    /// The child node id.
    #[wasm_bindgen(getter)]
    pub fn child_id(&self) -> String {
        self.child_id.clone()
    }

    /// `"node"` or `"user"`.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The slot the child occupies under this client.
    #[wasm_bindgen(getter)]
    pub fn slot(&self) -> u8 {
        self.slot
    }

    /// The child's derived address, if this client has an asserted address.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<String> {
        self.address.clone()
    }

    /// Unix-seconds join time.
    #[wasm_bindgen(getter)]
    pub fn date_joined(&self) -> f64 {
        self.date_joined
    }
}

/// A snapshot of this client's local topology, for the PWA.
#[wasm_bindgen]
pub struct SnapshotDto {
    node_id: String,
    address: Option<String>,
    parent: Option<ParentDto>,
    children: Vec<ChildDto>,
}

impl SnapshotDto {
    /// Build a snapshot for `node_id` from local `state`.
    pub(crate) fn from_state(node_id: &str, state: &LocalStateV1) -> Self {
        let record = &state.record;
        let parent = match (&record.parent, &record.address) {
            (Some(parent), Some(address)) => address.parent().map(|parent_address| ParentDto {
                node_id: parent.node_id.as_str().to_string(),
                slot: parent.slot,
                address: parent_address.to_string(),
            }),
            _ => None,
        };
        let children = record
            .children
            .iter()
            .map(|child| ChildDto {
                child_id: child.child_id.as_str().to_string(),
                kind: child_kind_str(child.kind).to_string(),
                slot: child.slot,
                address: record
                    .address
                    .as_ref()
                    .map(|address| address.child(child.slot).to_string()),
                date_joined: child.date_joined as f64,
            })
            .collect();
        SnapshotDto {
            node_id: node_id.to_string(),
            address: record.address.as_ref().map(|address| address.to_string()),
            parent,
            children,
        }
    }
}

#[wasm_bindgen]
impl SnapshotDto {
    /// This client's node id.
    #[wasm_bindgen(getter)]
    pub fn node_id(&self) -> String {
        self.node_id.clone()
    }

    /// This client's asserted address, if any.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<String> {
        self.address.clone()
    }

    /// The parent link, if attached.
    #[wasm_bindgen(getter)]
    pub fn parent(&self) -> Option<ParentDto> {
        self.parent.clone()
    }

    /// The child links (copied to plain objects by the PWA glue).
    #[wasm_bindgen(getter)]
    pub fn children(&self) -> Vec<ChildDto> {
        self.children.clone()
    }
}

/// Parse a 64-hex operator public key.
///
/// Returns a plain [`String`] error (not [`JsError`]) so the error paths are
/// testable on native targets; the wasm boundary wraps it with [`to_js_err`].
pub(crate) fn parse_operator_hex(raw: &str) -> Result<OperatorPubKey, String> {
    let bytes = decode_hex_32(raw)
        .ok_or_else(|| "operator key must be exactly 64 hex characters".to_string())?;
    OperatorPubKey::from_bytes(&bytes).map_err(|err| err.to_string())
}

/// Decode 64 hex digits into 32 bytes.
fn decode_hex_32(raw: &str) -> Option<[u8; 32]> {
    let raw = raw.as_bytes();
    if raw.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let hi = hex_nibble(raw[i * 2])?;
        let lo = hex_nibble(raw[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(bytes)
}

/// One hex digit to its value, accepting either case.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_control::{ChildKind, Invite, NodeId, OctAddr, OperatorSecretKey};

    use crate::state::{ChildLink, LocalStateV1, ParentLink};

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    #[test]
    fn parse_invite_maps_and_validates() {
        let invite = Invite {
            parent: node("parent-node"),
            operator: operator(7).public(),
            slot: Some(3),
            expiry: Some(1_700_000_000),
            label: Some("Cawala Lab".to_string()),
            relay: Some("https://relay.example.com/".parse().unwrap()),
            ip: Some("127.0.0.1:9000".parse().unwrap()),
        };
        let info = parse_invite_inner(&invite.encode()).unwrap();
        assert_eq!(info.parent, "parent-node");
        assert_eq!(info.operator, operator(7).public().to_string());
        assert_eq!(info.operator.len(), 64);
        assert!(info.operator.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(info.slot, Some(3));
        assert_eq!(info.expiry, Some(1_700_000_000.0));
        assert_eq!(info.label.as_deref(), Some("Cawala Lab"));
        assert_eq!(info.relay.as_deref(), Some("https://relay.example.com/"));
        assert_eq!(info.ip.as_deref(), Some("127.0.0.1:9000"));
    }

    #[test]
    fn parse_invite_rejects_garbage() {
        assert!(parse_invite_inner("not an invite").is_err());
        assert!(parse_invite_inner("https://join?parent=x&op=00").is_err());
    }

    #[test]
    fn stable_code_strings_are_explicit() {
        assert_eq!(reject_code_str(RejectCode::Unauthorized), "unauthorized");
        assert_eq!(reject_code_str(RejectCode::SlotTaken), "slot_taken");
        assert_eq!(
            reject_code_str(RejectCode::SlotOutOfRange),
            "slot_out_of_range"
        );
        assert_eq!(reject_code_str(RejectCode::NotAttached), "not_attached");
        assert_eq!(reject_code_str(RejectCode::Internal), "internal");
        assert_eq!(child_kind_str(ChildKind::Node), "node");
        assert_eq!(child_kind_str(ChildKind::User), "user");
    }

    #[test]
    fn snapshot_dto_maps_names_and_addresses() {
        let mut state = LocalStateV1::new();
        state.record.address = Some("0.2".parse().unwrap());
        state.record.parent = Some(ParentLink {
            node_id: node("parent"),
            slot: 2,
        });
        state.record.children.push(ChildLink {
            child_id: node("kid"),
            kind: ChildKind::User,
            slot: 5,
            date_joined: 42,
        });

        let snapshot = SnapshotDto::from_state("me", &state);
        assert_eq!(snapshot.node_id, "me");
        assert_eq!(snapshot.address.as_deref(), Some("0.2"));
        let parent = snapshot.parent.as_ref().unwrap();
        assert_eq!(parent.node_id, "parent");
        assert_eq!(parent.slot, 2);
        assert_eq!(parent.address, "0");
        assert_eq!(snapshot.children.len(), 1);
        assert_eq!(snapshot.children[0].child_id, "kid");
        assert_eq!(snapshot.children[0].kind, "user");
        assert_eq!(snapshot.children[0].address.as_deref(), Some("0.2.5"));
        assert_eq!(snapshot.children[0].date_joined, 42.0);
    }

    #[test]
    fn join_status_tracks_pending_and_joined() {
        let mut state = LocalStateV1::new();
        let request = cawala_control::JoinRequest {
            node: node("me"),
            kind: ChildKind::User,
            operator: operator(1).public(),
            ledger: None,
            desired_slot: Some(4),
            location_hint: None,
            nonce: 1,
            expiry: 100,
        };
        state.set_outbound(request, node("parent"), None, 1);
        let pending = JoinStatus::from_state(&state);
        assert_eq!(pending.state, "pending");
        assert_eq!(pending.parent.as_deref(), Some("parent"));
        assert_eq!(pending.slot, Some(4));

        state.record.address = Some(OctAddr::from_digits(vec![0, 4]).unwrap());
        state.record.parent = Some(ParentLink {
            node_id: node("parent"),
            slot: 4,
        });
        state.clear_outbound();
        let joined = JoinStatus::from_state(&state);
        assert_eq!(joined.state, "joined");
        assert_eq!(joined.address.as_deref(), Some("0.4"));
        assert_eq!(joined.slot, Some(4));
    }

    #[test]
    fn parse_operator_hex_round_trips() {
        let key = operator(5).public();
        assert_eq!(parse_operator_hex(&key.to_string()).unwrap(), key);
        assert!(parse_operator_hex("00").is_err());
        assert!(parse_operator_hex(&"z".repeat(64)).is_err());
    }
}
