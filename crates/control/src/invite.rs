//! Portable, out-of-band connection invites.
//!
//! A new client/node must learn *which* native node to contact without public
//! discovery. An [`Invite`] is a URI carrying the parent node's iroh
//! [`NodeId`] plus its **operator public key**, so a joiner can verify the
//! signature on the resulting [`JoinApproval`](crate::JoinApproval) against a
//! key that was pinned out-of-band rather than trusting whatever key the
//! approval happens to deliver.
//!
//! The wire format is:
//!
//! ```text
//! cawala://join?parent=<EndpointId string>&op=<lowercase-hex-64>[&slot=<0..7>][&exp=<unix-seconds>][&label=<percent-encoded>][&relay=<url>][&ip=<host:port>]
//! ```
//!
//! `parent` and `op` are required; `slot`, `exp`, `label`, `relay`, and `ip`
//! are optional. At most one `relay` and at most one `ip` may appear. Unknown
//! query parameters are ignored, duplicated parameters are an error, and there
//! is no checksum in v1.
//!
//! # Transport hints
//!
//! `relay` and `ip` are optional transport hints that let a joiner dial the
//! parent without any iroh address-lookup service. A relay must be an absolute
//! URL with a host and an `http`/`https`/`ws`/`wss` scheme; an `ip` must be a
//! `SocketAddr` (`host:port`).
//!
//! # Purity
//!
//! Parsing and encoding are pure and synchronous. `url` is a pure-Rust,
//! wasm-safe crate; `std::net::SocketAddr` is available on wasm32. This module
//! adds no I/O, clock, or RNG dependency.

use std::net::SocketAddr;

use url::Url;

use cawala_ledger::{NodeId, OperatorPubKey};
use cawala_topology::MAX_SLOT;

/// Relay-URL schemes accepted in an invite's `relay` hint.
const RELAY_SCHEMES: [&str; 4] = ["http", "https", "ws", "wss"];

/// URI scheme of an invite.
pub const INVITE_SCHEME: &str = "cawala";

/// URI host of an invite (so `url::Url` parses the authority).
pub const INVITE_HOST: &str = "join";

/// Maximum accepted length, in bytes, of [`Invite::label`].
pub const MAX_LABEL_LEN: usize = 64;

/// A portable instruction to join a specific parent node.
///
/// The invite pins the parent's operator key: a joiner that dialed because of
/// an invite can require the `JoinApproved` it receives to be signed by
/// exactly this key, closing the trust-on-first-use gap of an unpinned join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The parent node to contact.
    pub parent: NodeId,
    /// The parent's operator public key, pinned out-of-band.
    pub operator: OperatorPubKey,
    /// Desired slot (`0..=7`), or `None` to let the parent pick.
    pub slot: Option<u8>,
    /// Unix-seconds expiry for the resulting join request, if the inviter set
    /// one.
    pub expiry: Option<u64>,
    /// Optional human-readable label (e.g. a network name).
    pub label: Option<String>,
    /// Optional relay URL transport hint, so a joiner can dial the parent
    /// without an address-lookup service.
    pub relay: Option<Url>,
    /// Optional direct IP transport hint (the parent's bound `SocketAddr`).
    pub ip: Option<SocketAddr>,
}

impl Invite {
    /// Encode as a `cawala://join?...` URI.
    ///
    /// Required parameters lead; optional ones are omitted when `None`. The
    /// label (and any other free-form value) is percent-encoded, so labels with
    /// spaces, ampersands, or non-ASCII text round-trip through [`Self::parse`].
    pub fn encode(&self) -> String {
        // `parent` is an endpoint id and `op` is lowercase hex; both consist
        // solely of query-safe characters, but encode `parent` defensively.
        let mut out = format!(
            "{INVITE_SCHEME}://{INVITE_HOST}?parent={}&op={}",
            percent_encode(self.parent.as_str()),
            self.operator
        );
        if let Some(slot) = self.slot {
            out.push_str("&slot=");
            out.push_str(&slot.to_string());
        }
        if let Some(expiry) = self.expiry {
            out.push_str("&exp=");
            out.push_str(&expiry.to_string());
        }
        if let Some(label) = &self.label {
            out.push_str("&label=");
            out.push_str(&percent_encode(label));
        }
        if let Some(relay) = &self.relay {
            out.push_str("&relay=");
            out.push_str(&percent_encode(relay.as_str()));
        }
        if let Some(ip) = &self.ip {
            out.push_str("&ip=");
            out.push_str(&percent_encode(&ip.to_string()));
        }
        out
    }

    /// Parse an optional `relay` transport hint.
    ///
    /// The value must be an absolute URL with a host and one of the
    /// `http`/`https`/`ws`/`wss` schemes; anything else is
    /// [`InviteError::BadRelay`].
    pub fn parse_relay(raw: &str) -> Result<Url, InviteError> {
        let url = Url::parse(raw).map_err(|_| InviteError::BadRelay(raw.to_string()))?;
        validate_relay_url(&url)?;
        Ok(url)
    }

    /// Parse an optional `ip` transport hint as a `SocketAddr` (`host:port`).
    pub fn parse_ip(raw: &str) -> Result<SocketAddr, InviteError> {
        raw.parse().map_err(|_| InviteError::BadIp(raw.to_string()))
    }

    /// Parse a `cawala://join?...` URI.
    ///
    /// Enforces scheme/host, the required `parent` and `op` parameters, exact
    /// 64-hex operator decoding, and numeric `slot`/`exp`. It does **not**
    /// enforce the slot range or the label length: call [`Self::validate`] for
    /// those.
    pub fn parse(input: &str) -> Result<Self, InviteError> {
        let url = Url::parse(input).map_err(|err| InviteError::Malformed(err.to_string()))?;
        if url.scheme() != INVITE_SCHEME || url.host_str() != Some(INVITE_HOST) {
            return Err(InviteError::NotAnInvite);
        }

        let mut parent: Option<String> = None;
        let mut op: Option<String> = None;
        let mut slot: Option<String> = None;
        let mut expiry: Option<String> = None;
        let mut label: Option<String> = None;
        let mut relay: Option<String> = None;
        let mut ip: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();

        for (key, value) in url.query_pairs() {
            let key = key.into_owned();
            if seen.contains(&key) {
                return Err(InviteError::Duplicate(key));
            }
            seen.push(key.clone());
            match key.as_str() {
                "parent" => parent = Some(value.into_owned()),
                "op" => op = Some(value.into_owned()),
                "slot" => slot = Some(value.into_owned()),
                "exp" => expiry = Some(value.into_owned()),
                "label" => label = Some(value.into_owned()),
                "relay" => relay = Some(value.into_owned()),
                "ip" => ip = Some(value.into_owned()),
                // Unknown parameters are ignored (forward-compatible).
                _ => {}
            }
        }

        let parent = match parent {
            Some(parent) if !parent.is_empty() => parent,
            _ => return Err(InviteError::Missing("parent")),
        };
        let op = op.ok_or(InviteError::Missing("op"))?;
        let operator = parse_operator_hex(&op).ok_or(InviteError::BadOperatorKey)?;

        let slot = match slot {
            None => None,
            Some(raw) => {
                let parsed = raw
                    .parse::<u8>()
                    .map_err(|_| InviteError::BadSlot(raw.clone()))?;
                if parsed > MAX_SLOT {
                    return Err(InviteError::BadSlot(raw));
                }
                Some(parsed)
            }
        };
        let expiry = match expiry {
            None => None,
            Some(raw) => Some(
                raw.parse::<u64>()
                    .map_err(|_| InviteError::BadExpiry(raw.clone()))?,
            ),
        };
        let relay = relay.map(|raw| Invite::parse_relay(&raw)).transpose()?;
        let ip = ip.map(|raw| Invite::parse_ip(&raw)).transpose()?;

        Ok(Invite {
            parent: NodeId::from(parent),
            operator,
            slot,
            expiry,
            label,
            relay,
            ip,
        })
    }

    /// Check the invite's bounded/range-constrained fields.
    ///
    /// `slot`, when present, must be in `0..=7`; `label`, when present, must be
    /// at most [`MAX_LABEL_LEN`] bytes. `relay`, when present, must be an
    /// absolute URL with a host and an `http`/`https`/`ws`/`wss` scheme. `parent`
    /// is required non-empty, `operator` is a typed key, and `ip` is a typed
    /// `SocketAddr`, so those cannot be structurally invalid.
    pub fn validate(&self) -> Result<(), InviteError> {
        if let Some(slot) = self.slot
            && slot > MAX_SLOT
        {
            return Err(InviteError::BadSlot(slot.to_string()));
        }
        if let Some(label) = &self.label
            && label.len() > MAX_LABEL_LEN
        {
            return Err(InviteError::LabelTooLong {
                len: label.len(),
                max: MAX_LABEL_LEN,
            });
        }
        if self.parent.as_str().is_empty() {
            return Err(InviteError::Missing("parent"));
        }
        if let Some(relay) = &self.relay {
            validate_relay_url(relay)?;
        }
        Ok(())
    }
}

/// Validate a relay transport hint: it must be an absolute URL with a host and
/// an `http`/`https`/`ws`/`wss` scheme.
fn validate_relay_url(url: &Url) -> Result<(), InviteError> {
    if url.host_str().is_none() {
        return Err(InviteError::BadRelay(url.as_str().to_string()));
    }
    if !RELAY_SCHEMES.contains(&url.scheme()) {
        return Err(InviteError::BadRelay(url.as_str().to_string()));
    }
    Ok(())
}

/// Percent-encode a query component.
///
/// Keeps only RFC 3986 unreserved characters (`ALPHA / DIGIT / "-" / "." / "_"
/// / "~"`) literal and encodes every other byte as `%XX` (uppercase hex). This
/// is the strict percent-encoding form; [`Self::parse`] uses
/// `application/x-www-form-urlencoded` decoding, which also accepts `+` for
/// space.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if matches!(
            byte,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
        ) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX_UPPER[(byte >> 4) as usize] as char);
            out.push(HEX_UPPER[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

/// Uppercase hex digits, indexed by nibble value.
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Decode exactly 64 hex characters into the 32-byte operator key.
fn parse_operator_hex(raw: &str) -> Option<OperatorPubKey> {
    let bytes = decode_hex_32(raw)?;
    OperatorPubKey::from_bytes(&bytes).ok()
}

/// Decode 64 hex digits (upper- or lower-case) into 32 bytes.
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

/// Lowercase hex encoding of `bytes` (used by tests and diagnostics).
#[cfg(test)]
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Errors raised while encoding, parsing, or validating an [`Invite`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    /// The URI is not a `cawala://join` invite at all.
    #[error("not a cawala invite")]
    NotAnInvite,
    /// A required parameter is absent (or empty).
    #[error("missing required parameter '{0}'")]
    Missing(&'static str),
    /// The `op` parameter is not a valid 64-hex operator public key.
    #[error("invalid operator key")]
    BadOperatorKey,
    /// The `slot` parameter is not an integer in `0..=7`.
    #[error("invalid slot '{0}'")]
    BadSlot(String),
    /// The `exp` parameter is not a `u64`.
    #[error("invalid expiry '{0}'")]
    BadExpiry(String),
    /// The `relay` parameter is not a usable relay URL (bad scheme, no host).
    #[error("invalid relay '{0}'")]
    BadRelay(String),
    /// The `ip` parameter is not a `SocketAddr`.
    #[error("invalid ip '{0}'")]
    BadIp(String),
    /// A parameter appeared more than once.
    #[error("duplicate parameter '{0}'")]
    Duplicate(String),
    /// The label exceeds [`MAX_LABEL_LEN`].
    #[error("label is {len} bytes, max {max}")]
    LabelTooLong {
        /// The observed label length in bytes.
        len: usize,
        /// The permitted maximum.
        max: usize,
    },
    /// The URI could not be parsed at all.
    #[error("malformed invite: {0}")]
    Malformed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::OperatorSecretKey;

    fn operator(seed: u8) -> OperatorPubKey {
        OperatorSecretKey::from_bytes([seed; 32]).public()
    }

    fn full() -> Invite {
        Invite {
            parent: NodeId::from("parent-node"),
            operator: operator(7),
            slot: Some(3),
            expiry: Some(1_700_000_000),
            label: Some("Cawala Lab".to_string()),
            relay: None,
            ip: None,
        }
    }

    fn relay(url: &str) -> Url {
        Url::parse(url).unwrap()
    }

    #[test]
    fn encode_has_frozen_shape() {
        let uri = full().encode();
        assert_eq!(
            uri,
            format!(
                "cawala://join?parent=parent-node&op={}&slot=3&exp=1700000000&label=Cawala%20Lab",
                to_hex(&operator(7).to_bytes())
            )
        );
    }

    #[test]
    fn round_trip_all_fields() {
        let invite = full();
        let parsed = Invite::parse(&invite.encode()).unwrap();
        assert_eq!(parsed, invite);
        assert_eq!(parsed.validate(), Ok(()));
    }

    #[test]
    fn round_trip_minimal() {
        let invite = Invite {
            parent: NodeId::from("only-parent"),
            operator: operator(1),
            slot: None,
            expiry: None,
            label: None,
            relay: None,
            ip: None,
        };
        let uri = invite.encode();
        assert!(!uri.contains("slot="));
        assert!(!uri.contains("exp="));
        assert!(!uri.contains("label="));
        assert!(!uri.contains("relay="));
        assert!(!uri.contains("ip="));
        assert_eq!(Invite::parse(&uri).unwrap(), invite);
    }

    #[test]
    fn round_trip_relay_and_ip() {
        let invite = Invite {
            relay: Some(relay("https://relay.example.com/")),
            ip: Some("127.0.0.1:9000".parse().unwrap()),
            ..full()
        };
        let uri = invite.encode();
        assert!(uri.contains("relay="), "{uri}");
        assert!(uri.contains("ip="), "{uri}");
        let parsed = Invite::parse(&uri).unwrap();
        assert_eq!(parsed, invite);
        assert_eq!(parsed.validate(), Ok(()));
        assert_eq!(parsed.relay, Some(relay("https://relay.example.com/")));
        assert_eq!(parsed.ip, Some("127.0.0.1:9000".parse().unwrap()));
    }

    #[test]
    fn round_trip_relay_only() {
        let invite = Invite {
            relay: Some(relay("wss://relay.example.com")),
            ..full()
        };
        let uri = invite.encode();
        assert!(uri.contains("relay="));
        assert!(!uri.contains("ip="));
        assert_eq!(Invite::parse(&uri).unwrap(), invite);
    }

    #[test]
    fn round_trip_ip_only() {
        let invite = Invite {
            ip: Some("[::1]:9000".parse().unwrap()),
            ..full()
        };
        let uri = invite.encode();
        assert!(!uri.contains("relay="));
        assert!(uri.contains("ip="));
        assert_eq!(Invite::parse(&uri).unwrap(), invite);
    }

    #[test]
    fn parse_rejects_bad_relay() {
        let op = to_hex(&operator(1).to_bytes());
        // No host.
        assert_eq!(
            Invite::parse(&format!(
                "cawala://join?parent=p&op={op}&relay=not%20a%20url"
            ))
            .unwrap_err(),
            InviteError::BadRelay("not a url".to_string())
        );
        // A valid URL with no host.
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=p&op={op}&relay=mailto:a@b")).unwrap_err(),
            InviteError::BadRelay("mailto:a@b".to_string())
        );
    }

    #[test]
    fn parse_rejects_bad_relay_scheme() {
        let op = to_hex(&operator(1).to_bytes());
        assert_eq!(
            Invite::parse(&format!(
                "cawala://join?parent=p&op={op}&relay=ftp%3A%2F%2Frelay.example.com%2F"
            ))
            .unwrap_err(),
            InviteError::BadRelay("ftp://relay.example.com/".to_string())
        );
    }

    #[test]
    fn parse_rejects_malformed_ip() {
        let op = to_hex(&operator(1).to_bytes());
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=p&op={op}&ip=nope")).unwrap_err(),
            InviteError::BadIp("nope".to_string())
        );
        // Missing port.
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=p&op={op}&ip=127.0.0.1")).unwrap_err(),
            InviteError::BadIp("127.0.0.1".to_string())
        );
    }

    #[test]
    fn parse_rejects_duplicate_relay_and_ip() {
        let op = to_hex(&operator(1).to_bytes());
        assert_eq!(
            Invite::parse(&format!(
                "cawala://join?parent=p&op={op}&relay=https%3A%2F%2Fa.example.com%2F&relay=https%3A%2F%2Fb.example.com%2F"
            ))
            .unwrap_err(),
            InviteError::Duplicate("relay".to_string())
        );
        assert_eq!(
            Invite::parse(&format!(
                "cawala://join?parent=p&op={op}&ip=127.0.0.1%3A1&ip=127.0.0.1%3A2"
            ))
            .unwrap_err(),
            InviteError::Duplicate("ip".to_string())
        );
    }

    #[test]
    fn validate_rejects_bad_relay() {
        let mut invite = full();
        invite.relay = Some(relay("ftp://relay.example.com/"));
        assert_eq!(
            invite.validate(),
            Err(InviteError::BadRelay(
                "ftp://relay.example.com/".to_string()
            ))
        );

        // A hostless URL cannot be produced by `Url::parse` for `http`, but a
        // non-network scheme has no host and must also be rejected.
        invite.relay = Some(relay("mailto:a@b"));
        assert_eq!(
            invite.validate(),
            Err(InviteError::BadRelay("mailto:a@b".to_string()))
        );
    }

    #[test]
    fn parse_relay_accepts_allowed_schemes() {
        for raw in [
            "http://relay.example.com/",
            "https://relay.example.com/",
            "ws://relay.example.com/",
            "wss://relay.example.com/",
        ] {
            assert!(Invite::parse_relay(raw).is_ok(), "{raw}");
        }
    }

    #[test]
    fn op_hex_is_lowercase_and_round_trips() {
        let invite = full();
        let uri = invite.encode();
        let expected = to_hex(&operator(7).to_bytes());
        assert!(uri.contains(&format!("op={expected}")));
        assert!(expected.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn parse_rejects_non_invite() {
        assert_eq!(
            Invite::parse("https://join?parent=x&op=00").unwrap_err(),
            InviteError::NotAnInvite
        );
        assert_eq!(
            Invite::parse("cawala://other?parent=x&op=00").unwrap_err(),
            InviteError::NotAnInvite
        );
        assert!(matches!(
            Invite::parse("definitely not a url"),
            Err(InviteError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_missing_required_parameters() {
        let op = to_hex(&operator(1).to_bytes());
        assert_eq!(
            Invite::parse(&format!("cawala://join?op={op}")).unwrap_err(),
            InviteError::Missing("parent")
        );
        assert_eq!(
            Invite::parse("cawala://join?parent=p").unwrap_err(),
            InviteError::Missing("op")
        );
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=&op={op}")).unwrap_err(),
            InviteError::Missing("parent")
        );
    }

    #[test]
    fn parse_rejects_bad_operator_hex() {
        // Too short.
        assert_eq!(
            Invite::parse("cawala://join?parent=p&op=abcd").unwrap_err(),
            InviteError::BadOperatorKey
        );
        // Right length, non-hex characters.
        let bad = "z".repeat(64);
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=p&op={bad}")).unwrap_err(),
            InviteError::BadOperatorKey
        );
    }

    #[test]
    fn parse_rejects_bad_slot() {
        let op = to_hex(&operator(1).to_bytes());
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=p&op={op}&slot=x")).unwrap_err(),
            InviteError::BadSlot("x".to_string())
        );
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=p&op={op}&slot=8")).unwrap_err(),
            InviteError::BadSlot("8".to_string())
        );
        // 7 is the largest legal slot.
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=p&op={op}&slot=7"))
                .unwrap()
                .slot,
            Some(7)
        );
    }

    #[test]
    fn parse_rejects_bad_expiry() {
        let op = to_hex(&operator(1).to_bytes());
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=p&op={op}&exp=soon")).unwrap_err(),
            InviteError::BadExpiry("soon".to_string())
        );
    }

    #[test]
    fn parse_rejects_duplicate_parameter() {
        let op = to_hex(&operator(1).to_bytes());
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=a&parent=b&op={op}")).unwrap_err(),
            InviteError::Duplicate("parent".to_string())
        );
        assert_eq!(
            Invite::parse(&format!("cawala://join?parent=p&op={op}&op={op}")).unwrap_err(),
            InviteError::Duplicate("op".to_string())
        );
    }

    #[test]
    fn validate_enforces_label_bound() {
        let mut invite = full();
        invite.label = Some("x".repeat(MAX_LABEL_LEN));
        assert_eq!(invite.validate(), Ok(()));

        invite.label = Some("x".repeat(MAX_LABEL_LEN + 1));
        assert_eq!(
            invite.validate(),
            Err(InviteError::LabelTooLong {
                len: MAX_LABEL_LEN + 1,
                max: MAX_LABEL_LEN,
            })
        );
    }

    #[test]
    fn validate_enforces_slot_range() {
        let mut invite = full();
        invite.slot = Some(MAX_SLOT);
        assert_eq!(invite.validate(), Ok(()));

        invite.slot = Some(MAX_SLOT + 1);
        assert_eq!(
            invite.validate(),
            Err(InviteError::BadSlot((MAX_SLOT + 1).to_string()))
        );
    }

    #[test]
    fn percent_encoded_label_round_trips() {
        let invite = Invite {
            label: Some("a b&c=d/e?f#g".to_string()),
            ..full()
        };
        let uri = invite.encode();
        // The raw separator characters must not leak into the query unescaped.
        assert!(!uri.contains("label=a b&c"));
        // Spaces use strict percent-encoding (`%20`), not form-urlencoded `+`.
        assert!(uri.contains("label=a%20b%26c%3Dd%2Fe%3Ff%23g"), "{uri}");
        let parsed = Invite::parse(&uri).unwrap();
        assert_eq!(parsed, invite);
        assert_eq!(parsed.label.as_deref(), Some("a b&c=d/e?f#g"));
    }

    #[test]
    fn parse_accepts_uppercase_operator_hex() {
        let op = to_hex(&operator(2).to_bytes()).to_ascii_uppercase();
        let invite = Invite::parse(&format!("cawala://join?parent=p&op={op}")).unwrap();
        assert_eq!(invite.operator, operator(2));
    }

    #[test]
    fn unknown_parameters_are_ignored() {
        let op = to_hex(&operator(1).to_bytes());
        let invite = Invite::parse(&format!(
            "cawala://join?parent=p&op={op}&future=value&other=x"
        ))
        .unwrap();
        assert_eq!(invite.parent, NodeId::from("p"));
        assert_eq!(invite.operator, operator(1));
    }
}
