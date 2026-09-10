//! Cawala messaging envelope, routing, and replay defense.
//!
//! Pure, synchronous, and wasm-safe: `std` + `serde` + `postcard` only. No
//! tokio, no iroh, no RNG, no clocks, no persistence. Callers supply the nonce
//! (see [`Envelope::new`]) and drive transport themselves.
//!
//! # Trust boundary
//!
//! This layer treats **all envelope metadata as unauthenticated**. The
//! `src` address, `hop_chain`, `nonce`, `ttl`, `msg_type`, and every other
//! header field can be spoofed or rewritten by any relay. Authenticity is
//! **payload-level**: the payload is verified at the destination by the
//! application (e.g. a signed ledger entry), not by this crate.
//!
//! Each hop authenticates only its **direct QUIC neighbor**; there is no
//! end-to-end transport authentication here. Relays are explicitly trusted to
//! the extent that they can **spoof, drop, reorder, duplicate, or replay**
//! frames by design. Nodes are not a zero-trust network. [`SeenSet`] is a
//! best-effort, bounded, in-memory replay guard, not a security boundary: it
//! forgets, and a malicious relay can bypass it by re-originating a frame.
//!
//! [`validate_hop_chain`] and [`Envelope::validate`] check only structural
//! routing invariants (path shape, length, origin); passing them proves
//! nothing about who sent the message.
//!
//! # Bounds (pre-auth hardening)
//!
//! Decoding happens before any validation, so every wire-controlled length is
//! capped: callers read a `cawala/msg/0` frame with a limit of
//! [`MAX_MSG_FRAME`] (via `proto::read_framed_with_limit`), the envelope's
//! `hop_chain` deserializer rejects more than [`MAX_HOPS`] entries without
//! materializing them, and [`Envelope::validate`] rejects node ids longer than
//! [`MAX_NODE_ID_LEN`]. Together these stop a hostile frame from forcing a
//! large allocation before authentication.

pub mod envelope;
pub mod replay;
pub mod route;

pub use envelope::{
    Ack, AckStatus, Envelope, Hop, MSG_CONTROL_V1, MSG_LEDGER_V1, MessageType, MsgError, MsgId,
    PROTOCOL_VERSION, PeerRef, RejectReason,
};
pub use proto::OctAddr;
pub use replay::{Seen, SeenConfig, SeenSet};
pub use route::{
    HopChainError, Neighbor, NeighborKind, Routable, RouteDecision, RouteError, Step, append_hop,
    next_step, route, validate_hop_chain,
};

/// ALPN negotiated on every cawala/msg/0 connection.
pub const ALPN: &[u8] = b"cawala/msg/0";

/// Maximum number of hops (including the origin) recorded in a hop chain.
pub const MAX_HOPS: usize = 32;

/// Maximum accepted opaque payload size in bytes.
pub const MAX_PAYLOAD: usize = 1024 * 1024;

/// Maximum accepted wire size of a single `cawala/msg/0` frame:
/// `MAX_PAYLOAD` plus headroom for envelope headers and the hop chain.
pub const MAX_MSG_FRAME: u32 = MAX_PAYLOAD as u32 + 64 * 1024;

/// Maximum byte length of any node-id string (`PeerRef::node`, `Hop::node`).
pub const MAX_NODE_ID_LEN: usize = 128;
