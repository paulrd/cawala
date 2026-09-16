//! Data-transfer objects exposed to JavaScript.
//!
//! All conversions are explicit and lossless-in-spirit: `u64` unix timestamps
//! become `f64` (JavaScript numbers must never receive a raw `u64`/BigInt),
//! wire types (`Url`, `SocketAddr`, `NodeId`, `OctAddr`, operator keys) become
//! strings, and the `ChildKind`/`RejectCode` enums become stable strings rather
//! than `Debug` renderings.

use cawala_control::{
    AdminApproved, AdminPendingJoin, AdminRejected, AdminSnapshot, ChildKind, DeliveryStatus,
    Invite, NodeId, NodeSnapshot, OperatorPubKey, RejectCode,
};
use cawala_ledger::{Hash, LedgerPubKey};
use cawala_msg::OctAddr;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

use crate::ledger_state::{
    ActivityEntryV1, LedgerStateV1, OrderResultApplication, SettlementApplication, SettlementRecordV1,
    VerifiedBalanceV1, hop_role_str, settlement_state_reason, settlement_state_str,
};
use crate::state::LocalStateV1;
use crate::to_js_err;

/// Lowercase hex rendering of a ledger [`Hash`] (64 characters).
pub(crate) fn hash_hex(hash: Hash) -> String {
    hash.to_hex()
}

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
        RejectCode::Expired => "expired",
        RejectCode::Replay => "replay",
        RejectCode::Internal => "internal",
    }
}

/// Stable JS string for a [`DeliveryStatus`].
///
/// A `Rejected` outcome embeds its stable reject code, e.g.
/// `"rejected:unauthorized"`.
pub(crate) fn delivery_status_str(status: &DeliveryStatus) -> String {
    match status {
        DeliveryStatus::Delivered => "delivered".to_string(),
        DeliveryStatus::Unreachable => "unreachable".to_string(),
        DeliveryStatus::TimedOut => "timed_out".to_string(),
        DeliveryStatus::Rejected(code) => format!("rejected:{}", reject_code_str(*code)),
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

/// The outcome of [`crate::ClientNode::leave`].
///
/// `status` is always `"detached"`: the local parent and address are cleared
/// before this is returned, so a failed or unreachable parent can never trap
/// the user. `delivery` reports the best-effort `Exit` notice to the former
/// parent and is one of `"accepted"`, `"rejected:<code>"`, `"unreachable"` (a
/// transport error or timeout), or `"unexpected"` (a structurally impossible
/// reply shape); it is diagnostic only.
#[wasm_bindgen]
pub struct LeaveOutcome {
    status: String,
    delivery: String,
}

impl LeaveOutcome {
    /// Build a `"detached"` outcome with the parent-notice `delivery` bucket.
    pub(crate) fn new(delivery: String) -> Self {
        LeaveOutcome {
            status: "detached".to_string(),
            delivery,
        }
    }
}

#[wasm_bindgen]
impl LeaveOutcome {
    /// Always `"detached"`.
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.clone()
    }

    /// The former parent's view of the `Exit` notice: `"accepted"`,
    /// `"rejected:<code>"`, `"unreachable"`, or `"unexpected"`.
    #[wasm_bindgen(getter)]
    pub fn delivery(&self) -> String {
        self.delivery.clone()
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

    /// This client left (or was detached from) `parent`; parent and address
    /// were cleared. `parent` is the former parent, carried for display.
    pub(crate) fn detached(parent: &NodeId) -> Self {
        ControlEventDto {
            kind: "detached".to_string(),
            parent: parent.as_str().to_string(),
            slot: None,
            address: None,
            date_joined: None,
            reason: None,
        }
    }
}

#[wasm_bindgen]
impl ControlEventDto {
    /// Event kind: `"accepted"`, `"rejected"`, or `"detached"`.
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

/// The immediate outcome of sending a payment order.
///
/// The terminal status arrives asynchronously as a
/// [`LedgerEventDto`] of kind `"order_result"`.
#[wasm_bindgen]
pub struct PaymentOutcome {
    order_hash_hex: String,
    ack: String,
}

impl PaymentOutcome {
    /// Build an outcome from the order hash and the leaf's ack bucket.
    pub(crate) fn new(order_hash_hex: String, ack: String) -> Self {
        PaymentOutcome {
            order_hash_hex,
            ack,
        }
    }
}

#[wasm_bindgen]
impl PaymentOutcome {
    /// The order's domain-separated hash as 64 lowercase hex characters.
    #[wasm_bindgen(getter)]
    pub fn order_hash_hex(&self) -> String {
        self.order_hash_hex.clone()
    }

    /// The leaf's ack bucket: `"delivered"`, `"duplicate"`, or `"rejected"`.
    ///
    /// This only reports that the leaf accepted the envelope, not that the
    /// order applied; wait for a `"order_result"` ledger event for that.
    #[wasm_bindgen(getter)]
    pub fn ack(&self) -> String {
        self.ack.clone()
    }
}

/// One decoded ledger event drained by
/// [`crate::ClientNode::try_recv_ledger_event`].
///
/// `kind` is `"order_result"`, `"balance_receipt"`, or `"invalid"`. Optional
/// fields are populated per kind; amounts/heights/timestamps are `f64` so
/// JavaScript never receives a raw `u64`. A settlement `status` is one of
/// `"applied"`, `"duplicate"`, `"partial"`, `"rejected"`, `"indeterminate"`,
/// or `"unverified"` (the last meaning a proof-less or unverifiable terminal
/// `Applied`/`Duplicate`, which must never be shown as success).
#[wasm_bindgen]
pub struct LedgerEventDto {
    kind: String,
    order_hash: Option<String>,
    status: Option<String>,
    reason: Option<String>,
    amount: Option<f64>,
    balance: Option<f64>,
    height: Option<f64>,
    counterparty: Option<String>,
    entry_seq: Option<f64>,
    failed_at: Option<String>,
}

impl LedgerEventDto {
    /// An order result (applied, duplicate, or rejected).
    pub(crate) fn order_result(app: &OrderResultApplication) -> Self {
        LedgerEventDto {
            kind: "order_result".to_string(),
            order_hash: Some(hash_hex(app.order_hash)),
            status: Some(app.status.to_string()),
            reason: app.reason.map(str::to_string),
            amount: Some(app.amount as f64),
            balance: app.balance.as_ref().map(|balance| balance.amount as f64),
            height: app.balance.as_ref().map(|balance| balance.height as f64),
            counterparty: Some(app.counterparty.as_str().to_string()),
            entry_seq: app.entry_seq.map(|seq| seq as f64),
            failed_at: None,
        }
    }

    /// A v2/v3 settlement order result; `partial` carries the failing hop and
    /// `unverified` carries the proof-failure reason.
    pub(crate) fn settlement(app: &SettlementApplication) -> Self {
        LedgerEventDto {
            kind: "order_result".to_string(),
            order_hash: Some(hash_hex(app.order_hash)),
            status: Some(app.status.to_string()),
            reason: app.reason.clone(),
            amount: Some(app.amount as f64),
            balance: app.balance.as_ref().map(|balance| balance.amount as f64),
            height: app.balance.as_ref().map(|balance| balance.height as f64),
            counterparty: Some(app.counterparty.as_str().to_string()),
            entry_seq: app.entry_seq.map(|seq| seq as f64),
            failed_at: app.failed_at.as_ref().map(|id| id.as_str().to_string()),
        }
    }

    /// A verified balance receipt.
    pub(crate) fn balance_receipt(balance: &VerifiedBalanceV1) -> Self {
        LedgerEventDto {
            kind: "balance_receipt".to_string(),
            order_hash: None,
            status: None,
            reason: None,
            amount: None,
            balance: Some(balance.amount as f64),
            height: Some(balance.height as f64),
            counterparty: None,
            entry_seq: None,
            failed_at: None,
        }
    }

    /// A malformed, unknown, or unverifiable ledger message. No state changed.
    pub(crate) fn invalid(reason: &str) -> Self {
        LedgerEventDto {
            kind: "invalid".to_string(),
            order_hash: None,
            status: None,
            reason: Some(reason.to_string()),
            amount: None,
            balance: None,
            height: None,
            counterparty: None,
            entry_seq: None,
            failed_at: None,
        }
    }
}

#[wasm_bindgen]
impl LedgerEventDto {
    /// Event kind: `"order_result"`, `"balance_receipt"`, or `"invalid"`.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The order's hash (hex), for `"order_result"` events.
    #[wasm_bindgen(getter)]
    pub fn order_hash(&self) -> Option<String> {
        self.order_hash.clone()
    }

    /// `"applied"`, `"duplicate"`, `"partial"`, `"rejected"`,
    /// `"indeterminate"`, or `"unverified"`, for order results.
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> Option<String> {
        self.status.clone()
    }

    /// A stable rejection/error reason, when one applies.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> Option<String> {
        self.reason.clone()
    }

    /// The order amount, for `"order_result"` events.
    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> Option<f64> {
        self.amount
    }

    /// The verified balance, for receipts (and results carrying one).
    #[wasm_bindgen(getter)]
    pub fn balance(&self) -> Option<f64> {
        self.balance
    }

    /// The ledger height the balance was attested at, when known.
    #[wasm_bindgen(getter)]
    pub fn height(&self) -> Option<f64> {
        self.height
    }

    /// The payee node id, for order results.
    #[wasm_bindgen(getter)]
    pub fn counterparty(&self) -> Option<String> {
        self.counterparty.clone()
    }

    /// The applied entry's ledger `seq`, when there is one.
    #[wasm_bindgen(getter)]
    pub fn entry_seq(&self) -> Option<f64> {
        self.entry_seq
    }

    /// The failing hop's node id, for a `"partial"` settlement result.
    #[wasm_bindgen(getter)]
    pub fn failed_at(&self) -> Option<String> {
        self.failed_at.clone()
    }
}

/// A snapshot of this client's ledger/balance state, for the UI.
#[wasm_bindgen]
pub struct LedgerStatusDto {
    address: Option<String>,
    parent: Option<String>,
    balance: Option<f64>,
    height: Option<f64>,
    pinned_ledger: Option<String>,
    pending: u32,
    activity: u32,
}

impl LedgerStatusDto {
    /// Build a status view from the topology links and the persisted ledger
    /// state.
    pub(crate) fn from_state(
        address: Option<String>,
        parent: Option<String>,
        state: &LedgerStateV1,
    ) -> Self {
        LedgerStatusDto {
            address,
            parent,
            balance: state.balance.as_ref().map(|balance| balance.amount as f64),
            height: state.balance.as_ref().map(|balance| balance.height as f64),
            pinned_ledger: state.pinned_ledger.map(|key| key.to_string()),
            pending: state.pending.len() as u32,
            activity: state.activity.len() as u32,
        }
    }
}

#[wasm_bindgen]
impl LedgerStatusDto {
    /// This client's assigned address, if joined.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<String> {
        self.address.clone()
    }

    /// This client's parent node id, if joined.
    #[wasm_bindgen(getter)]
    pub fn parent(&self) -> Option<String> {
        self.parent.clone()
    }

    /// The last verified balance, if any.
    #[wasm_bindgen(getter)]
    pub fn balance(&self) -> Option<f64> {
        self.balance
    }

    /// The height the balance was attested at, if any.
    #[wasm_bindgen(getter)]
    pub fn height(&self) -> Option<f64> {
        self.height
    }

    /// The pinned ledger key as 64 lowercase hex characters, if any.
    #[wasm_bindgen(getter)]
    pub fn pinned_ledger(&self) -> Option<String> {
        self.pinned_ledger.clone()
    }

    /// Number of in-flight orders.
    #[wasm_bindgen(getter)]
    pub fn pending(&self) -> u32 {
        self.pending
    }

    /// Number of recorded activity entries.
    #[wasm_bindgen(getter)]
    pub fn activity(&self) -> u32 {
        self.activity
    }
}

/// One remembered value-movement activity entry, exposed to JS so a reload can
/// rebuild the activity feed. `entry_seq`/`issued_at` are `f64` so JavaScript
/// never receives a raw `u64`; hashes are lowercase hex.
#[wasm_bindgen]
pub struct ActivityEntryDto {
    entry_seq: f64,
    entry_hash: String,
    payment_id: String,
    from: String,
    to: String,
    amount: f64,
    role: String,
    issued_at: f64,
}

impl ActivityEntryDto {
    /// Convert one persisted activity entry.
    pub(crate) fn from_entry(entry: &ActivityEntryV1) -> Self {
        ActivityEntryDto {
            entry_seq: entry.entry_seq as f64,
            entry_hash: hash_hex(entry.entry_hash),
            payment_id: hash_hex(entry.payment_id),
            from: entry.from.as_str().to_string(),
            to: entry.to.as_str().to_string(),
            amount: entry.amount as f64,
            role: hop_role_str(entry.role).to_string(),
            issued_at: entry.issued_at as f64,
        }
    }
}

#[wasm_bindgen]
impl ActivityEntryDto {
    /// The ledger `seq` of the entry that moved value.
    #[wasm_bindgen(getter)]
    pub fn entry_seq(&self) -> f64 {
        self.entry_seq
    }

    /// The entry's hash as 64 lowercase hex characters.
    #[wasm_bindgen(getter)]
    pub fn entry_hash(&self) -> String {
        self.entry_hash.clone()
    }

    /// The cascade `payment_id` as 64 lowercase hex characters.
    #[wasm_bindgen(getter)]
    pub fn payment_id(&self) -> String {
        self.payment_id.clone()
    }

    /// The payer node.
    #[wasm_bindgen(getter)]
    pub fn from(&self) -> String {
        self.from.clone()
    }

    /// The payee node.
    #[wasm_bindgen(getter)]
    pub fn to(&self) -> String {
        self.to.clone()
    }

    /// The amount moved.
    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> f64 {
        self.amount
    }

    /// The hop's role: `"ascend"`, `"lca"`, `"descend"`, or `"direct"`.
    #[wasm_bindgen(getter)]
    pub fn role(&self) -> String {
        self.role.clone()
    }

    /// Unix-seconds issuance time (as an `f64`; never a raw `u64`).
    #[wasm_bindgen(getter)]
    pub fn issued_at(&self) -> f64 {
        self.issued_at
    }
}

/// One remembered settlement outcome, exposed to JS so a reload can rebuild the
/// settlement history. `status` is the same stable string set as
/// [`LedgerEventDto`]'s `status`; optional fields are populated when the
/// resolving result carried them.
#[wasm_bindgen]
pub struct SettlementRecordDto {
    order_hash: String,
    status: String,
    reason: Option<String>,
    amount: Option<f64>,
    counterparty: Option<String>,
    entry_seq: Option<f64>,
}

impl SettlementRecordDto {
    /// Convert one persisted settlement record.
    pub(crate) fn from_record(record: &SettlementRecordV1) -> Self {
        SettlementRecordDto {
            order_hash: hash_hex(record.order_hash),
            status: settlement_state_str(&record.state).to_string(),
            reason: settlement_state_reason(&record.state).map(str::to_string),
            amount: record.amount.map(|amount| amount as f64),
            counterparty: record
                .counterparty
                .as_ref()
                .map(|id| id.as_str().to_string()),
            entry_seq: record.entry_seq.map(|seq| seq as f64),
        }
    }
}

#[wasm_bindgen]
impl SettlementRecordDto {
    /// The order's hash as 64 lowercase hex characters.
    #[wasm_bindgen(getter)]
    pub fn order_hash(&self) -> String {
        self.order_hash.clone()
    }

    /// One of `"applied"`, `"duplicate"`, `"partial"`, `"rejected"`,
    /// `"indeterminate"`, or `"unverified"`.
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.clone()
    }

    /// A stable reason, when the outcome carries one.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> Option<String> {
        self.reason.clone()
    }

    /// The order amount, when known.
    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> Option<f64> {
        self.amount
    }

    /// The payee node, when known.
    #[wasm_bindgen(getter)]
    pub fn counterparty(&self) -> Option<String> {
        self.counterparty.clone()
    }

    /// The verified terminal ledger `seq`, when the outcome carries one.
    #[wasm_bindgen(getter)]
    pub fn entry_seq(&self) -> Option<f64> {
        self.entry_seq
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
#[derive(Clone)]
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

    /// Build a snapshot from a remote node's [`NodeSnapshot`] (an admin query
    /// reply), where addresses are already materialized rather than derived.
    pub(crate) fn from_node_snapshot(snapshot: &NodeSnapshot) -> Self {
        SnapshotDto {
            node_id: snapshot.node_id.as_str().to_string(),
            address: snapshot.address.as_ref().map(|address| address.to_string()),
            parent: snapshot.parent.as_ref().map(|parent| ParentDto {
                node_id: parent.node_id.as_str().to_string(),
                slot: parent.slot,
                address: parent.address.to_string(),
            }),
            children: snapshot
                .children
                .iter()
                .map(|child| ChildDto {
                    child_id: child.child_id.as_str().to_string(),
                    kind: child_kind_str(child.kind).to_string(),
                    slot: child.slot,
                    address: child.address.as_ref().map(|address| address.to_string()),
                    date_joined: child.date_joined as f64,
                })
                .collect(),
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

/// One join awaiting admin approval, as returned by
/// [`crate::ClientNode::admin_query`].
#[wasm_bindgen]
#[derive(Clone)]
pub struct AdminPendingJoinDto {
    child_id: String,
    kind: String,
    operator: String,
    desired_slot: Option<u8>,
    expiry: f64,
}

impl AdminPendingJoinDto {
    /// Convert one wire pending-join row.
    pub(crate) fn from_pending(pending: &AdminPendingJoin) -> Self {
        AdminPendingJoinDto {
            child_id: pending.child.as_str().to_string(),
            kind: child_kind_str(pending.kind).to_string(),
            operator: pending.operator.to_string(),
            desired_slot: pending.desired_slot,
            expiry: pending.expiry as f64,
        }
    }
}

#[wasm_bindgen]
impl AdminPendingJoinDto {
    /// The applicant's node id.
    #[wasm_bindgen(getter)]
    pub fn child_id(&self) -> String {
        self.child_id.clone()
    }

    /// `"node"` or `"user"`.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The applicant's operator public key as 64 lowercase hex characters.
    #[wasm_bindgen(getter)]
    pub fn operator(&self) -> String {
        self.operator.clone()
    }

    /// The requested slot (`0..=7`), or `None` when the parent picks.
    #[wasm_bindgen(getter)]
    pub fn desired_slot(&self) -> Option<u8> {
        self.desired_slot
    }

    /// Unix-seconds expiry (as an `f64`; never a raw `u64`).
    #[wasm_bindgen(getter)]
    pub fn expiry(&self) -> f64 {
        self.expiry
    }
}

/// An admin view of a node: its topology snapshot plus pending joins.
#[wasm_bindgen]
pub struct AdminSnapshotDto {
    node: SnapshotDto,
    pending: Vec<AdminPendingJoinDto>,
}

impl AdminSnapshotDto {
    /// Convert an `AdminSnapshot` reply.
    pub(crate) fn from_snapshot(snapshot: &AdminSnapshot) -> Self {
        AdminSnapshotDto {
            node: SnapshotDto::from_node_snapshot(&snapshot.node),
            pending: snapshot
                .pending
                .iter()
                .map(AdminPendingJoinDto::from_pending)
                .collect(),
        }
    }
}

#[wasm_bindgen]
impl AdminSnapshotDto {
    /// The node's topology snapshot.
    #[wasm_bindgen(getter)]
    pub fn node(&self) -> SnapshotDto {
        self.node.clone()
    }

    /// The joins awaiting admin approval.
    #[wasm_bindgen(getter)]
    pub fn pending(&self) -> Vec<AdminPendingJoinDto> {
        self.pending.clone()
    }
}

/// The result of an admin approve/reject/redeliver action.
#[wasm_bindgen]
#[derive(Clone)]
pub struct AdminActionDto {
    child: String,
    slot: Option<u8>,
    address: Option<String>,
    delivery: String,
}

impl AdminActionDto {
    /// Convert an `AdminApproved` reply.
    pub(crate) fn from_approved(approved: &AdminApproved) -> Self {
        AdminActionDto {
            child: approved.child.as_str().to_string(),
            slot: Some(approved.slot),
            address: Some(approved.address.to_string()),
            delivery: delivery_status_str(&approved.delivery),
        }
    }

    /// Convert an `AdminRejected` reply.
    pub(crate) fn from_rejected(rejected: &AdminRejected) -> Self {
        AdminActionDto {
            child: rejected.child.as_str().to_string(),
            slot: None,
            address: None,
            delivery: delivery_status_str(&rejected.delivery),
        }
    }
}

#[wasm_bindgen]
impl AdminActionDto {
    /// The affected child node id.
    #[wasm_bindgen(getter)]
    pub fn child(&self) -> String {
        self.child.clone()
    }

    /// The assigned slot, for an approval.
    #[wasm_bindgen(getter)]
    pub fn slot(&self) -> Option<u8> {
        self.slot
    }

    /// The child's derived address, for an approval.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<String> {
        self.address.clone()
    }

    /// The applicant's view of delivery: `"delivered"`, `"unreachable"`,
    /// `"timed_out"`, or `"rejected:<code>"`.
    #[wasm_bindgen(getter)]
    pub fn delivery(&self) -> String {
        self.delivery.clone()
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

/// Parse a 64-hex ledger public key.
///
/// Returns a plain [`String`] error (not [`JsError`]) so the error paths are
/// testable on native targets; the wasm boundary wraps it with [`to_js_err`].
pub(crate) fn parse_ledger_hex(raw: &str) -> Result<LedgerPubKey, String> {
    let bytes = decode_hex_32(raw)
        .ok_or_else(|| "ledger key must be exactly 64 hex characters".to_string())?;
    LedgerPubKey::from_bytes(&bytes).map_err(|err| err.to_string())
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

/// Scheme of a payment receive URI.
pub const RECEIVE_SCHEME: &str = "cawala";
/// Host of a payment receive URI.
pub const RECEIVE_HOST: &str = "pay";

/// A parsed payment receive URI: the payee's node id, user address, and the
/// optional out-of-band leaf pin (`ln`/`lk`).
#[wasm_bindgen]
pub struct ReceiveUriInfo {
    node_id: String,
    address: String,
    leaf_node: Option<String>,
    leaf_ledger: Option<String>,
}

#[wasm_bindgen]
impl ReceiveUriInfo {
    /// The payee's `EndpointId` string.
    #[wasm_bindgen(getter)]
    pub fn node_id(&self) -> String {
        self.node_id.clone()
    }

    /// The payee's user `OctAddr` string.
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    /// The payee leaf's node id (the `ln` parameter), when the URI carried one.
    #[wasm_bindgen(getter)]
    pub fn leaf_node(&self) -> Option<String> {
        self.leaf_node.clone()
    }

    /// The payee leaf's ledger public key as 64 lowercase hex characters (the
    /// `lk` parameter), when the URI carried one.
    #[wasm_bindgen(getter)]
    pub fn leaf_ledger(&self) -> Option<String> {
        self.leaf_ledger.clone()
    }
}

/// Build a `cawala://pay?to=<EndpointId>&addr=<OctAddr>` receive URI.
///
/// Both values are query-safe (the endpoint id is base32/hex and an
/// `OctAddr` is dotted octal digits), so no percent-encoding is needed; this
/// mirrors the join invite's parameter style.
pub(crate) fn receive_uri_for(node_id: &str, address: &str) -> String {
    format!("{RECEIVE_SCHEME}://{RECEIVE_HOST}?to={node_id}&addr={address}")
}

/// Build a receive URI carrying the payee leaf's out-of-band pin:
/// `cawala://pay?to=..&addr=..&ln=<leaf node id>&lk=<leaf ledger key hex>`.
///
/// `ln` is the payee leaf's node id (the payee's parent) and `lk` is the ledger
/// key the payer must verify the terminal inclusion proof under.
pub(crate) fn receive_uri_with_leaf(
    node_id: &str,
    address: &str,
    leaf_node: &str,
    leaf_ledger: &str,
) -> String {
    format!(
        "{RECEIVE_SCHEME}://{RECEIVE_HOST}?to={node_id}&addr={address}&ln={leaf_node}&lk={leaf_ledger}"
    )
}

/// The parsed components of a pay receive URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedReceiveUri {
    pub node_id: String,
    pub address: OctAddr,
    pub leaf_node: Option<String>,
    pub leaf_ledger: Option<LedgerPubKey>,
}

/// Parse and validate a `cawala://pay?...` receive URI.
///
/// Enforces the scheme/host, the required `to`/`addr` parameters, the optional
/// `ln`/`lk` leaf-pin pair, no duplicates, and no extras.
#[wasm_bindgen]
pub fn parse_receive_uri(uri: &str) -> Result<ReceiveUriInfo, JsError> {
    let parsed = parse_receive_uri_inner(uri).map_err(to_js_err)?;
    Ok(ReceiveUriInfo {
        node_id: parsed.node_id,
        address: parsed.address.to_string(),
        leaf_node: parsed.leaf_node,
        leaf_ledger: parsed.leaf_ledger.map(|key| key.to_string()),
    })
}

/// Pure parse+validate used by [`parse_receive_uri`] and unit tests.
pub(crate) fn parse_receive_uri_inner(uri: &str) -> Result<ParsedReceiveUri, String> {
    let prefix = format!("{RECEIVE_SCHEME}://{RECEIVE_HOST}?");
    let query = uri
        .strip_prefix(&prefix)
        .ok_or_else(|| "not a cawala pay URI".to_string())?;

    let mut node: Option<String> = None;
    let mut addr: Option<OctAddr> = None;
    let mut leaf_node: Option<String> = None;
    let mut leaf_ledger: Option<LedgerPubKey> = None;
    for pair in query.split('&') {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| "malformed pay URI parameter".to_string())?;
        match key {
            "to" if node.is_none() => node = Some(value.to_string()),
            "addr" if addr.is_none() => {
                let parsed: OctAddr = value
                    .parse()
                    .map_err(|_| "invalid payee address".to_string())?;
                addr = Some(parsed);
            }
            "ln" if leaf_node.is_none() => {
                value
                    .parse::<iroh::EndpointId>()
                    .map_err(|_| "invalid leaf node id".to_string())?;
                leaf_node = Some(value.to_string());
            }
            "lk" if leaf_ledger.is_none() => {
                leaf_ledger = Some(parse_ledger_hex(value)?);
            }
            "to" | "addr" | "ln" | "lk" => {
                return Err("duplicate pay URI parameter".to_string());
            }
            _ => return Err("unexpected pay URI parameter".to_string()),
        }
    }

    let node = node.ok_or_else(|| "missing 'to' parameter".to_string())?;
    let addr = addr.ok_or_else(|| "missing 'addr' parameter".to_string())?;
    node.parse::<iroh::EndpointId>()
        .map_err(|_| "invalid payee node id".to_string())?;
    if leaf_node.is_some() != leaf_ledger.is_some() {
        return Err("incomplete leaf pin: 'ln' and 'lk' must appear together".to_string());
    }
    Ok(ParsedReceiveUri {
        node_id: node,
        address: addr,
        leaf_node,
        leaf_ledger,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_control::{ChildKind, Invite, NodeId, OctAddr, OperatorSecretKey};

    use crate::ledger_state::{ActivityEntryV1, SettlementRecordV1, SettlementStateV1};
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
    fn receive_uri_round_trips_without_leaf_pin_and_rejects_malformed() {
        let endpoint = iroh::SecretKey::generate().public().to_string();
        let uri = receive_uri_for(&endpoint, "0.1.3");
        assert_eq!(uri, format!("cawala://pay?to={endpoint}&addr=0.1.3"));

        let parsed = parse_receive_uri_inner(&uri).unwrap();
        assert_eq!(parsed.node_id, endpoint);
        assert_eq!(parsed.address, "0.1.3".parse::<OctAddr>().unwrap());
        assert!(parsed.leaf_node.is_none());
        assert!(parsed.leaf_ledger.is_none());

        for bad in [
            "not a uri",
            "https://pay?to=x&addr=0.1.3",
            "cawala://join?to=x&addr=0.1.3",
            "cawala://pay?addr=0.1.3",
            "cawala://pay?to=x",
            "cawala://pay?to=x&addr=bogus",
            "cawala://pay?to=x&addr=0.1.8",
            "cawala://pay?to=x&addr=0.1.3&extra=1",
            "cawala://pay?to=x&to=y&addr=0.1.3",
            // Partial, malformed, or duplicate leaf pins.
            "cawala://pay?to=x&addr=0.1.3&ln=not-a-node",
            "cawala://pay?to=x&addr=0.1.3&lk=zz",
            "cawala://pay?to=x&addr=0.1.3&ln=not-a-node&lk=zz",
            "cawala://pay?to=x&addr=0.1.3&lk=zz",
        ] {
            assert!(parse_receive_uri_inner(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn receive_uri_round_trips_with_leaf_pin() {
        let endpoint = iroh::SecretKey::generate().public().to_string();
        let leaf = iroh::SecretKey::generate().public().to_string();
        let ledger = cawala_ledger::LedgerSecretKey::from_bytes([7u8; 32]).public();
        let hex = ledger.to_string();
        assert_eq!(hex.len(), 64);

        let uri = receive_uri_with_leaf(&endpoint, "0.1.3", &leaf, &hex);
        assert_eq!(
            uri,
            format!("cawala://pay?to={endpoint}&addr=0.1.3&ln={leaf}&lk={hex}")
        );

        let parsed = parse_receive_uri_inner(&uri).unwrap();
        assert_eq!(parsed.node_id, endpoint);
        assert_eq!(parsed.address, "0.1.3".parse::<OctAddr>().unwrap());
        assert_eq!(parsed.leaf_node.as_deref(), Some(leaf.as_str()));
        assert_eq!(parsed.leaf_ledger, Some(ledger));

        // A node id that parses as an endpoint but an `ln`/`lk` mismatch pair is
        // still rejected when only one is present.
        let only_ln = format!("cawala://pay?to={endpoint}&addr=0.1.3&ln={leaf}");
        assert!(parse_receive_uri_inner(&only_ln).is_err());
        let only_lk = format!("cawala://pay?to={endpoint}&addr=0.1.3&lk={hex}");
        assert!(parse_receive_uri_inner(&only_lk).is_err());
        let dup = format!("cawala://pay?to={endpoint}&addr=0.1.3&ln={leaf}&lk={hex}&lk={hex}");
        assert!(parse_receive_uri_inner(&dup).is_err());
    }

    #[test]
    fn parse_ledger_hex_round_trips() {
        let key = cawala_ledger::LedgerSecretKey::from_bytes([5u8; 32]).public();
        assert_eq!(parse_ledger_hex(&key.to_string()).unwrap(), key);
        assert!(parse_ledger_hex("00").is_err());
        assert!(parse_ledger_hex(&"z".repeat(64)).is_err());
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
        assert_eq!(reject_code_str(RejectCode::Expired), "expired");
        assert_eq!(reject_code_str(RejectCode::Replay), "replay");
        assert_eq!(reject_code_str(RejectCode::Internal), "internal");
        assert_eq!(child_kind_str(ChildKind::Node), "node");
        assert_eq!(child_kind_str(ChildKind::User), "user");
    }

    #[test]
    fn delivery_status_strings_are_stable() {
        assert_eq!(delivery_status_str(&DeliveryStatus::Delivered), "delivered");
        assert_eq!(
            delivery_status_str(&DeliveryStatus::Unreachable),
            "unreachable"
        );
        assert_eq!(delivery_status_str(&DeliveryStatus::TimedOut), "timed_out");
        assert_eq!(
            delivery_status_str(&DeliveryStatus::Rejected(RejectCode::Expired)),
            "rejected:expired"
        );
        assert_eq!(
            delivery_status_str(&DeliveryStatus::Rejected(RejectCode::Replay)),
            "rejected:replay"
        );
    }

    #[test]
    fn admin_snapshot_dto_maps_node_and_pending() {
        let snapshot = AdminSnapshot {
            node: NodeSnapshot {
                node_id: node("parent"),
                address: Some("0.3".parse().unwrap()),
                parent: Some(cawala_control::ParentSnapshot {
                    node_id: node("grandparent"),
                    slot: 3,
                    address: "0".parse().unwrap(),
                }),
                children: vec![cawala_control::ChildSnapshot {
                    child_id: node("kid"),
                    kind: ChildKind::Node,
                    slot: 1,
                    address: Some("0.3.1".parse().unwrap()),
                    date_joined: 42,
                }],
            },
            pending: vec![AdminPendingJoin {
                child: node("applicant"),
                kind: ChildKind::User,
                operator: operator(5).public(),
                desired_slot: Some(2),
                expiry: 1_700_000_000,
            }],
        };

        let dto = AdminSnapshotDto::from_snapshot(&snapshot);
        assert_eq!(dto.node.node_id, "parent");
        assert_eq!(dto.node.address.as_deref(), Some("0.3"));
        let parent = dto.node.parent.as_ref().unwrap();
        assert_eq!(parent.node_id, "grandparent");
        assert_eq!(parent.slot, 3);
        assert_eq!(parent.address, "0");
        assert_eq!(dto.node.children.len(), 1);
        assert_eq!(dto.node.children[0].child_id, "kid");
        assert_eq!(dto.node.children[0].kind, "node");
        assert_eq!(dto.node.children[0].address.as_deref(), Some("0.3.1"));

        assert_eq!(dto.pending.len(), 1);
        let pending = &dto.pending[0];
        assert_eq!(pending.child_id, "applicant");
        assert_eq!(pending.kind, "user");
        assert_eq!(pending.operator, operator(5).public().to_string());
        assert_eq!(pending.operator.len(), 64);
        assert_eq!(pending.desired_slot, Some(2));
        assert_eq!(pending.expiry, 1_700_000_000.0);
    }

    #[test]
    fn admin_action_dto_maps_approved_and_rejected() {
        let approved = AdminApproved {
            child: node("applicant"),
            slot: 2,
            address: "0.2".parse().unwrap(),
            delivery: DeliveryStatus::Delivered,
        };
        let dto = AdminActionDto::from_approved(&approved);
        assert_eq!(dto.child, "applicant");
        assert_eq!(dto.slot, Some(2));
        assert_eq!(dto.address.as_deref(), Some("0.2"));
        assert_eq!(dto.delivery, "delivered");

        let rejected = AdminRejected {
            child: node("applicant"),
            delivery: DeliveryStatus::Rejected(RejectCode::Unauthorized),
        };
        let dto = AdminActionDto::from_rejected(&rejected);
        assert_eq!(dto.child, "applicant");
        assert_eq!(dto.slot, None);
        assert_eq!(dto.address, None);
        assert_eq!(dto.delivery, "rejected:unauthorized");
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

    #[test]
    fn hash_hex_is_lowercase_64_chars() {
        let hex = hash_hex(Hash::from_bytes([0xab; 32]));
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "ab".repeat(32));
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn order_result_event_maps_u64_to_f64_and_reason_string() {
        let app = OrderResultApplication {
            status: "applied",
            reason: None,
            order_hash: Hash::from_bytes([0x11; 32]),
            amount: 42,
            counterparty: cawala_ledger::NodeId::from("bob"),
            entry_seq: Some(7),
            balance: Some(VerifiedBalanceV1 {
                amount: 100,
                height: 9,
                state_root: Hash::ZERO,
            }),
        };
        let event = LedgerEventDto::order_result(&app);
        assert_eq!(event.kind, "order_result");
        assert_eq!(event.order_hash.as_deref(), Some(&"11".repeat(32) as &str));
        assert_eq!(event.status.as_deref(), Some("applied"));
        assert_eq!(event.amount, Some(42.0));
        assert_eq!(event.balance, Some(100.0));
        assert_eq!(event.height, Some(9.0));
        assert_eq!(event.counterparty.as_deref(), Some("bob"));
        assert_eq!(event.entry_seq, Some(7.0));
        assert!(event.reason.is_none());
    }

    #[test]
    fn invalid_event_carries_stable_reason_and_no_values() {
        let event = LedgerEventDto::invalid("unknown_order");
        assert_eq!(event.kind, "invalid");
        assert_eq!(event.reason.as_deref(), Some("unknown_order"));
        assert!(event.order_hash.is_none());
        assert!(event.balance.is_none());
        assert!(event.height.is_none());
    }

    #[test]
    fn ledger_status_dto_reports_counts_and_pin() {
        let mut state = LedgerStateV1::new();
        state.pinned_ledger = Some(cawala_ledger::LedgerSecretKey::from_bytes([3u8; 32]).public());
        state.balance = Some(VerifiedBalanceV1 {
            amount: 55,
            height: 4,
            state_root: Hash::ZERO,
        });
        let status = LedgerStatusDto::from_state(
            Some("0.4".to_string()),
            Some("parent".to_string()),
            &state,
        );
        assert_eq!(status.address.as_deref(), Some("0.4"));
        assert_eq!(status.parent.as_deref(), Some("parent"));
        assert_eq!(status.balance, Some(55.0));
        assert_eq!(status.height, Some(4.0));
        assert_eq!(status.pinned_ledger.as_deref().map(str::len), Some(64));
        assert_eq!(status.pending, 0);
        assert_eq!(status.activity, 0);
    }

    #[test]
    fn activity_entry_dto_maps_all_fields() {
        let entry = ActivityEntryV1 {
            entry_seq: 7,
            entry_hash: Hash::from_bytes([0x11; 32]),
            payment_id: Hash::from_bytes([0x22; 32]),
            from: node("n1"),
            to: node("n2"),
            amount: 42,
            role: cawala_ledger::HopRole::Descend,
            issued_at: 1_700_000_000,
        };
        let dto = ActivityEntryDto::from_entry(&entry);
        assert_eq!(dto.entry_seq, 7.0);
        assert_eq!(dto.entry_hash, "11".repeat(32));
        assert_eq!(dto.payment_id, "22".repeat(32));
        assert_eq!(dto.from, "n1");
        assert_eq!(dto.to, "n2");
        assert_eq!(dto.amount, 42.0);
        assert_eq!(dto.role, "descend");
        assert_eq!(dto.issued_at, 1_700_000_000.0);
    }

    #[test]
    fn settlement_record_dto_maps_statuses_and_optional_fields() {
        // A verified `Applied` carries amount/payee/seq.
        let applied = SettlementRecordV1 {
            order_hash: Hash::from_bytes([0x33; 32]),
            state: SettlementStateV1::Applied,
            amount: Some(100),
            counterparty: Some(node("n2")),
            entry_seq: Some(9),
        };
        let dto = SettlementRecordDto::from_record(&applied);
        assert_eq!(dto.order_hash, "33".repeat(32));
        assert_eq!(dto.status, "applied");
        assert_eq!(dto.reason, None);
        assert_eq!(dto.amount, Some(100.0));
        assert_eq!(dto.counterparty.as_deref(), Some("n2"));
        assert_eq!(dto.entry_seq, Some(9.0));

        // An `Unverified` outcome keeps its stable status and reason, and has no
        // verified seq.
        let unverified = SettlementRecordV1 {
            order_hash: Hash::from_bytes([0x44; 32]),
            state: SettlementStateV1::Unverified {
                reason: "missing proof".to_string(),
            },
            amount: Some(5),
            counterparty: None,
            entry_seq: None,
        };
        let dto = SettlementRecordDto::from_record(&unverified);
        assert_eq!(dto.status, "unverified");
        assert_eq!(dto.reason.as_deref(), Some("missing proof"));
        assert_eq!(dto.amount, Some(5.0));
        assert_eq!(dto.counterparty, None);
        assert_eq!(dto.entry_seq, None);

        // `Rejected`/`Partial`/`Indeterminate` map to their stable strings too.
        for (state, expected) in [
            (
                SettlementStateV1::Rejected {
                    reason: "insufficient_balance".to_string(),
                },
                "rejected",
            ),
            (
                SettlementStateV1::Partial {
                    failed_at: node("leaf-b"),
                },
                "partial",
            ),
            (
                SettlementStateV1::Indeterminate {
                    reason: "internal".to_string(),
                },
                "indeterminate",
            ),
            (SettlementStateV1::Duplicate, "duplicate"),
        ] {
            let record = SettlementRecordV1 {
                order_hash: Hash::ZERO,
                state,
                amount: None,
                counterparty: None,
                entry_seq: None,
            };
            assert_eq!(SettlementRecordDto::from_record(&record).status, expected);
        }
    }
}
