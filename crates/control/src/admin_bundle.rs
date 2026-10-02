//! Portable, out-of-band signed admin-grant bundles.
//!
//! A `cawala://admin` URI lets a node operator hand a browser a
//! **node-operator-signed** [`AdminGrantV2`], so the browser's view of the
//! grant's scopes and TTL is truthful rather than locally invented. The wire
//! format is:
//!
//! ```text
//! cawala://admin?node=<endpoint-id>&grant=<base64url-nopad>
//! ```
//!
//! `node` is the granting node id and `grant` is the unpadded base64url
//! encoding of the postcard [`AdminGrantBundleV1`]. Both are required; unknown
//! query parameters are ignored, duplicated parameters are an error.
//!
//! # Trust boundary
//!
//! [`AdminGrantBundleV1::parse`] checks only the container: scheme/host,
//! required parameters, the bundle version, the byte bound (on both the encoded
//! `grant` string and the decoded bytes), trailing-byte rejection, and
//! `node == grant.node`. It does **not** validate the grant's TTL/label
//! and it does **not** verify the signature. Callers must
//! [`AdminGrantV2::validate`](crate::AdminGrantV2::validate) and
//! [`SignedAdminGrantV2::verify`](crate::SignedAdminGrantV2::verify) against
//! the operator key of `grant.node` before treating the grant as authority.
//!
//! # Purity
//!
//! Parsing/encoding are pure and synchronous. `url` and `base64` are
//! wasm-safe; no I/O, clock, or RNG is used.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::admin::SignedAdminGrantV2;

/// Wire format version for [`AdminGrantBundleV1`].
pub const ADMIN_BUNDLE_VERSION: u8 = 1;

/// Defensive cap, in bytes, on a decoded admin bundle.
///
/// A bundle is a handful of keys plus a short optional label, so this is far
/// larger than any valid bundle while still bounding a hostile URI.
pub const MAX_ADMIN_BUNDLE_BYTES: usize = 4096;

/// Defensive cap, in characters, on the **encoded** base64url `grant`
/// parameter.
///
/// base64 expands every 3 bytes to 4 characters, so this upper-bounds the
/// decoded bundle at [`MAX_ADMIN_BUNDLE_BYTES`] and lets [`AdminGrantBundleV1::parse`]
/// reject an oversized attacker URI (plus the `+ 4` slack/padding margin)
/// *before* allocating the decode buffer.
pub const MAX_ADMIN_BUNDLE_GRANT_CHARS: usize = MAX_ADMIN_BUNDLE_BYTES * 4 / 3 + 4;

/// Maximum accepted length, in bytes, of the `node` query parameter.
///
/// Node ids are endpoint-id strings; this mirrors the control request node-id
/// sanity bound and prevents a giant `node` value from being retained.
pub const MAX_ADMIN_BUNDLE_NODE_LEN: usize = 128;

/// URI scheme of an admin bundle.
pub const ADMIN_BUNDLE_SCHEME: &str = "cawala";

/// URI host of an admin bundle (so `url::Url` parses the authority).
pub const ADMIN_BUNDLE_HOST: &str = "admin";

/// A versioned container for a signed v2 admin grant.
///
/// Field order is frozen: postcard encodes `version` first, so
/// [`AdminGrantBundleV1::from_bytes`] can peek the version before decoding the
/// grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminGrantBundleV1 {
    /// [`ADMIN_BUNDLE_VERSION`].
    pub version: u8,
    /// The node-operator-signed v2 grant being delivered.
    pub grant: SignedAdminGrantV2,
}

impl AdminGrantBundleV1 {
    /// Encode the bundle as canonical postcard bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("admin bundle is always postcard-encodable")
    }

    /// Decode a bundle from postcard bytes.
    ///
    /// Rejects an over-bound input, an unknown version, a decode failure, and
    /// trailing bytes. It does **not** validate the grant's fields or verify
    /// its signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdminBundleError> {
        if bytes.len() > MAX_ADMIN_BUNDLE_BYTES {
            return Err(AdminBundleError::TooLarge {
                len: bytes.len(),
                max: MAX_ADMIN_BUNDLE_BYTES,
            });
        }
        // Peek the version first so an unknown version is a distinct error
        // rather than a generic decode failure.
        let (version, _rest) = postcard::take_from_bytes::<u8>(bytes)
            .map_err(|err| AdminBundleError::Malformed(err.to_string()))?;
        if version != ADMIN_BUNDLE_VERSION {
            return Err(AdminBundleError::UnsupportedVersion(version));
        }
        let (bundle, rest) = postcard::take_from_bytes::<AdminGrantBundleV1>(bytes)
            .map_err(|err| AdminBundleError::Malformed(err.to_string()))?;
        if !rest.is_empty() {
            return Err(AdminBundleError::Malformed(format!(
                "{} trailing bytes",
                rest.len()
            )));
        }
        Ok(bundle)
    }

    /// Encode as a `cawala://admin?node=...&grant=...` URI.
    pub fn encode(&self) -> String {
        format!(
            "{ADMIN_BUNDLE_SCHEME}://{ADMIN_BUNDLE_HOST}?node={}&grant={}",
            percent_encode(self.grant.grant.node.as_str()),
            URL_SAFE_NO_PAD.encode(self.to_bytes()),
        )
    }

    /// Parse a `cawala://admin?...` URI.
    ///
    /// Enforces the scheme/host, the required `node` and `grant` parameters,
    /// rejection of duplicate parameters, the base64url decode, the bundle
    /// version/bounds, and `node == grant.node`. It does **not** validate the
    /// grant's TTL/label or verify its signature.
    pub fn parse(input: &str) -> Result<Self, AdminBundleError> {
        let url = Url::parse(input).map_err(|err| AdminBundleError::Malformed(err.to_string()))?;
        if url.scheme() != ADMIN_BUNDLE_SCHEME || url.host_str() != Some(ADMIN_BUNDLE_HOST) {
            return Err(AdminBundleError::NotAnAdminBundle);
        }

        let mut node: Option<String> = None;
        let mut grant: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();
        for (key, value) in url.query_pairs() {
            let key = key.into_owned();
            if seen.contains(&key) {
                return Err(AdminBundleError::Duplicate(key));
            }
            seen.push(key.clone());
            match key.as_str() {
                "node" => node = Some(value.into_owned()),
                "grant" => grant = Some(value.into_owned()),
                // Unknown parameters are ignored (forward-compatible).
                _ => {}
            }
        }

        let node = match node {
            Some(node) if !node.is_empty() => node,
            _ => return Err(AdminBundleError::Missing("node")),
        };
        if node.len() > MAX_ADMIN_BUNDLE_NODE_LEN {
            return Err(AdminBundleError::FieldTooLong {
                field: "node",
                len: node.len(),
                max: MAX_ADMIN_BUNDLE_NODE_LEN,
            });
        }
        let grant = grant.ok_or(AdminBundleError::Missing("grant"))?;
        // Bound the *encoded* string before decoding, so a hostile URI cannot
        // force an allocation larger than the decoded bound.
        if grant.len() > MAX_ADMIN_BUNDLE_GRANT_CHARS {
            return Err(AdminBundleError::FieldTooLong {
                field: "grant",
                len: grant.len(),
                max: MAX_ADMIN_BUNDLE_GRANT_CHARS,
            });
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&grant)
            .map_err(|_| AdminBundleError::BadBase64)?;
        let bundle = Self::from_bytes(&bytes)?;
        let grant_node = bundle.grant.grant.node.as_str();
        if grant_node != node {
            return Err(AdminBundleError::NodeMismatch {
                found: node,
                expected: grant_node.to_string(),
            });
        }
        Ok(bundle)
    }
}

/// Percent-encode a query component, keeping only RFC 3986 unreserved
/// characters literal (uppercase hex escapes), mirroring [`crate::Invite`].
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

/// Errors raised while encoding, parsing, or decoding an admin bundle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdminBundleError {
    /// The URI is not a `cawala://admin` bundle at all.
    #[error("not a cawala admin bundle")]
    NotAnAdminBundle,
    /// A required parameter is absent (or empty).
    #[error("missing required parameter '{0}'")]
    Missing(&'static str),
    /// A parameter appeared more than once.
    #[error("duplicate parameter '{0}'")]
    Duplicate(String),
    /// The bundle is larger than [`MAX_ADMIN_BUNDLE_BYTES`].
    #[error("admin bundle is {len} bytes, max {max}")]
    TooLarge {
        /// The observed length in bytes.
        len: usize,
        /// The permitted maximum.
        max: usize,
    },
    /// The bundle's version is not [`ADMIN_BUNDLE_VERSION`].
    #[error("unsupported admin bundle version {0}")]
    UnsupportedVersion(u8),
    /// The `grant` parameter is not valid unpadded base64url.
    #[error("invalid base64 grant")]
    BadBase64,
    /// A bounded free-string field (`node` or the encoded `grant`) exceeded its
    /// maximum length.
    #[error("{field} is {len} bytes, max {max}")]
    FieldTooLong {
        /// The field name, for diagnostics.
        field: &'static str,
        /// The observed length in bytes.
        len: usize,
        /// The permitted maximum length in bytes.
        max: usize,
    },
    /// The bundle could not be parsed or postcard-decoded.
    #[error("malformed admin bundle: {0}")]
    Malformed(String),
    /// The URI's `node` does not match the grant's node.
    #[error("bundle node '{found}' does not match grant node '{expected}'")]
    NodeMismatch {
        /// The node named by the URI.
        found: String,
        /// The node named by the grant.
        expected: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::{
        ADMIN_GRANT_VERSION, AdminGrant, AdminGrantV2, AdminScope, AdminScopes,
        DEFAULT_ADMIN_TTL_SECS, SignedAdminGrant,
    };
    use crate::invite::MAX_LABEL_LEN;
    use cawala_ledger::{NodeId, OperatorSecretKey};

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn grant_v2(node_id: &str, admin_seed: u8) -> AdminGrantV2 {
        AdminGrantV2 {
            version: ADMIN_GRANT_VERSION,
            node: node(node_id),
            admin: operator(admin_seed).public(),
            scopes: AdminScopes {
                joins: true,
                topology: false,
                value: false,
            },
            granted_at: 1_000,
            expiry: 1_000 + DEFAULT_ADMIN_TTL_SECS,
            label: Some("bundle".to_string()),
        }
    }

    fn signed_v2(node_id: &str, signer_seed: u8, admin_seed: u8) -> SignedAdminGrantV2 {
        SignedAdminGrantV2::authorize(grant_v2(node_id, admin_seed), &operator(signer_seed)).unwrap()
    }

    fn bundle(node_id: &str, signer_seed: u8, admin_seed: u8) -> AdminGrantBundleV1 {
        AdminGrantBundleV1 {
            version: ADMIN_BUNDLE_VERSION,
            grant: signed_v2(node_id, signer_seed, admin_seed),
        }
    }

    #[test]
    fn postcard_round_trip_and_version_first() {
        let value = bundle("node-a", 1, 3);
        let bytes = value.to_bytes();
        assert_eq!(bytes[0], ADMIN_BUNDLE_VERSION, "version must lead");
        assert_eq!(AdminGrantBundleV1::from_bytes(&bytes).unwrap(), value);
    }

    #[test]
    fn uri_round_trip() {
        let value = bundle("node-a", 1, 3);
        let uri = value.encode();
        assert!(uri.starts_with("cawala://admin?node=node-a&grant="), "{uri}");
        let parsed = AdminGrantBundleV1::parse(&uri).unwrap();
        assert_eq!(parsed, value);
    }

    #[test]
    fn parse_rejects_oversize() {
        let bytes = vec![ADMIN_BUNDLE_VERSION; MAX_ADMIN_BUNDLE_BYTES + 1];
        assert_eq!(
            AdminGrantBundleV1::from_bytes(&bytes),
            Err(AdminBundleError::TooLarge {
                len: MAX_ADMIN_BUNDLE_BYTES + 1,
                max: MAX_ADMIN_BUNDLE_BYTES,
            })
        );
    }

    #[test]
    fn parse_rejects_oversize_encoded_grant_before_decode() {
        // The bound is on the encoded string, checked before base64-decoding,
        // so the URI cannot force a large decode allocation.
        let grant = "A".repeat(MAX_ADMIN_BUNDLE_GRANT_CHARS + 1);
        let err = AdminGrantBundleV1::parse(&format!("cawala://admin?node=node-a&grant={grant}"))
            .unwrap_err();
        assert_eq!(
            err,
            AdminBundleError::FieldTooLong {
                field: "grant",
                len: MAX_ADMIN_BUNDLE_GRANT_CHARS + 1,
                max: MAX_ADMIN_BUNDLE_GRANT_CHARS,
            }
        );

        // Exactly at the bound is not rejected for length (it then fails as
        // bad/invalid data, not `FieldTooLong`).
        let at_bound = "A".repeat(MAX_ADMIN_BUNDLE_GRANT_CHARS);
        assert!(!matches!(
            AdminGrantBundleV1::parse(&format!("cawala://admin?node=node-a&grant={at_bound}")),
            Err(AdminBundleError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn parse_rejects_oversize_node() {
        let node = "n".repeat(MAX_ADMIN_BUNDLE_NODE_LEN + 1);
        let err =
            AdminGrantBundleV1::parse(&format!("cawala://admin?node={node}&grant=AAAA")).unwrap_err();
        assert_eq!(
            err,
            AdminBundleError::FieldTooLong {
                field: "node",
                len: MAX_ADMIN_BUNDLE_NODE_LEN + 1,
                max: MAX_ADMIN_BUNDLE_NODE_LEN,
            }
        );
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let mut bytes = bundle("node-a", 1, 3).to_bytes();
        bytes.push(0);
        assert!(matches!(
            AdminGrantBundleV1::from_bytes(&bytes),
            Err(AdminBundleError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_unknown_version() {
        let mut bytes = bundle("node-a", 1, 3).to_bytes();
        bytes[0] = ADMIN_BUNDLE_VERSION + 1;
        assert_eq!(
            AdminGrantBundleV1::from_bytes(&bytes),
            Err(AdminBundleError::UnsupportedVersion(ADMIN_BUNDLE_VERSION + 1))
        );
    }

    #[test]
    fn parse_rejects_legacy_v1_grant_bytes() {
        // The postcard of a legacy signed grant is not a v2 bundle.
        let legacy = SignedAdminGrant::authorize(
            AdminGrant {
                version: crate::admin::ADMIN_GRANT_V1_VERSION,
                node: node("node-a"),
                admin: operator(3).public(),
                scope: AdminScope::Admin,
                granted_at: 1_000,
                expiry: 1_000 + DEFAULT_ADMIN_TTL_SECS,
                label: None,
            },
            &operator(1),
        )
        .unwrap();
        let bytes = postcard::to_allocvec(&legacy).unwrap();
        assert!(AdminGrantBundleV1::from_bytes(&bytes).is_err());
    }

    #[test]
    fn parse_rejects_bad_base64() {
        assert_eq!(
            AdminGrantBundleV1::parse("cawala://admin?node=node-a&grant=not base64!!").unwrap_err(),
            AdminBundleError::BadBase64
        );
    }

    #[test]
    fn parse_rejects_non_bundle() {
        assert_eq!(
            AdminGrantBundleV1::parse("https://admin?node=x&grant=y").unwrap_err(),
            AdminBundleError::NotAnAdminBundle
        );
        assert_eq!(
            AdminGrantBundleV1::parse("cawala://join?node=x&grant=y").unwrap_err(),
            AdminBundleError::NotAnAdminBundle
        );
        assert!(matches!(
            AdminGrantBundleV1::parse("definitely not a url"),
            Err(AdminBundleError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_missing_parameters() {
        assert_eq!(
            AdminGrantBundleV1::parse("cawala://admin?grant=y").unwrap_err(),
            AdminBundleError::Missing("node")
        );
        assert_eq!(
            AdminGrantBundleV1::parse("cawala://admin?node=node-a").unwrap_err(),
            AdminBundleError::Missing("grant")
        );
    }

    #[test]
    fn parse_rejects_duplicate_parameter() {
        assert_eq!(
            AdminGrantBundleV1::parse("cawala://admin?node=a&node=b&grant=x").unwrap_err(),
            AdminBundleError::Duplicate("node".to_string())
        );
    }

    #[test]
    fn parse_rejects_node_mismatch() {
        let value = bundle("node-a", 1, 3);
        let uri = value.encode().replace("node=node-a", "node=node-b");
        assert_eq!(
            AdminGrantBundleV1::parse(&uri).unwrap_err(),
            AdminBundleError::NodeMismatch {
                found: "node-b".to_string(),
                expected: "node-a".to_string(),
            }
        );
    }

    #[test]
    fn parse_does_not_verify_the_signature() {
        // A wrong signer is a parse-level *verify* concern, not a parse error:
        // parse must not reject it, so the caller can decide (and audit).
        let value = bundle("node-a", 9, 3);
        let uri = value.encode();
        assert_eq!(AdminGrantBundleV1::parse(&uri).unwrap(), value);
        assert_eq!(
            value.grant.verify(&operator(1).public()),
            Err(crate::ControlError::InvalidSignature)
        );
    }

    #[test]
    fn parse_rejects_empty_node() {
        assert_eq!(
            AdminGrantBundleV1::parse("cawala://admin?node=&grant=x").unwrap_err(),
            AdminBundleError::Missing("node")
        );
    }

    #[test]
    fn long_label_is_within_the_byte_bound_when_encoded() {
        // MAX_LABEL_LEN bytes of label still fit comfortably under the bundle
        // byte cap (guards against the cap being accidentally tiny).
        let mut g = grant_v2("node-a", 3);
        g.label = Some("x".repeat(MAX_LABEL_LEN));
        let signed = SignedAdminGrantV2::authorize(g, &operator(1)).unwrap();
        let value = AdminGrantBundleV1 {
            version: ADMIN_BUNDLE_VERSION,
            grant: signed,
        };
        assert!(value.to_bytes().len() <= MAX_ADMIN_BUNDLE_BYTES);
    }
}
