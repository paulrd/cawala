//! Cawala M4 control-plane payloads.
//!
//! This crate defines the signed request payload ([`SignedControl`] wrapping a
//! [`ControlRequest`]) and the direct reply surface ([`ControlReply`]). In M4
//! phase 1 control runs **directly** over [`CONTROL_ALPN`]
//! (`cawala/control/0`), one request/response per stream; tree-routed control
//! (which would ride `cawala/msg/0` envelopes with `msg_type =
//! MSG_CONTROL_V1`) is a later phase.
//!
//! # Trust boundary
//!
//! Envelope metadata (source, hop chain, nonce, TTL, `msg_type`) is
//! unauthenticated and may be forged by any relay; see the `cawala-msg` crate
//! docs. Authenticity lives entirely in the payload: control requests are
//! authorised by **operator-key signatures** over a domain-separated hash.
//!
//! A valid [`SignedControl`] proves *which operator key* signed the request,
//! and [`verify_control`] additionally proves that key is the one the
//! [`cawala_ledger::PeerRegistry`] binds to the `origin` node id. It does
//! **not** prove the request is *authorized*. Authorization — the senior-child
//! rule, target/topology rules, downward-only moves — is applied by the node
//! after verification. The registry binds node id -> operator key; a peer's
//! `ledger` key is irrelevant to control authority.
//!
//! # Purity
//!
//! This crate is pure, synchronous, and wasm-safe: no `tokio`, no `iroh`, no
//! filesystem, no RNG, no clocks. Signatures are deterministic over the
//! canonical encoding, and callers supply every key as raw bytes.

/// Maximum accepted control-frame payload in bytes.
///
/// Control messages are deliberately small — a [`SignedControl`] envelope plus
/// a handful of keys, addresses, and short strings — so this is far tighter
/// than the general [`cawala_msg`] frame cap. Nodes read control frames with
/// this limit (via `read_framed_with_limit`) so a peer cannot force a large
/// allocation or decode before validation runs.
///
/// [`cawala_msg`]: https://docs.rs/cawala-msg
pub const MAX_CONTROL_FRAME: u32 = 64 * 1024;

pub mod reply;
pub mod request;
pub mod senior;
pub mod sign;

pub use cawala_ledger::{NodeId, OperatorPubKey, OperatorSecretKey, Signature};
pub use cawala_topology::{ChildKind, OctAddr};
pub use reply::{
    CONTROL_ALPN, CONTROL_REPLY_VERSION, ChildSnapshot, ControlReply, NodeSnapshot, ParentSnapshot,
    RejectCode,
};
pub use request::{
    ControlRequest, CreateChild, DetachChild, JoinApproval, JoinRejection, JoinRequest,
    MAX_LOCATION_HINT_LEN, MAX_NODE_ID_LEN, MAX_REASON_LEN, MoveChild, SetAddress,
};
pub use senior::senior_child;
pub use sign::{
    CONTROL_CONTEXT, CONTROL_FORMAT_VERSION, ControlError, SignedControl, verify_control,
};
