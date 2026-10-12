//! Shared Cawala Ethereum crypto primitives (P2c, Addendum C §1).
//!
//! This crate is the **single** implementation of the EIP-712 digest and
//! `ecrecover` used by both the native node and the wasm browser client, so
//! the two can never diverge on the authorization formula. It is
//! native-testable and wasm-safe: `std` + `serde` + `k256` + `sha3` only, no
//! tokio/iroh/fs/RNG.
//!
//! # Model (spec §1.1, Addendum A/C)
//!
//! - Root key: BIP-39 mnemonic (+ optional BIP-39 passphrase) derived on the
//!   BIP-44 Ethereum path `m/44'/60'/0'/0/{index}` (default index `0`).
//! - Address: `keccak256(uncompressed_pubkey[1..])[12..]`, rendered with the
//!   EIP-55 mixed-case checksum.
//! - Signing: EIP-712 typed-data digest, ECDSA over secp256k1 with **low-`s`
//!   (EIP-2)** normalization and a validated recovery id, serialized as a
//!   65-byte `r || s || v` (`v ∈ {27, 28}`).
//! - Domain: the EIP-712 domain separator carries the Cawala network/chain id
//!   ([`CAWALA_CHAIN_ID`]); the order struct binds the payer's
//!   [`PaymentOrder`] hash plus the payee address ([`order_digest`]).
//!
//! The BIP-39/BIP-44 derivation lives behind the `bip39` feature (enabled by
//! the browser client) so the node, which only recovers and verifies, does not
//! link the mnemonic machinery. `k256`'s `SigningKey` implements
//! `ZeroizeOnDrop`, so the scalar is wiped when dropped.

use std::fmt;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Re-export of the secp256k1 signing key so consumers of this crate's public
/// signing functions can name the type without a direct `k256` dependency.
pub use k256::ecdsa::SigningKey;

#[cfg(feature = "bip39")]
use coins_bip32::path::DerivationPath;
#[cfg(feature = "bip39")]
use coins_bip39::{English, Mnemonic};
#[cfg(feature = "bip39")]
use zeroize::Zeroizing;

use cawala_ledger::PaymentOrder;
use proto::OctAddr;

/// BIP-44 coin type for Ethereum (`60'`).
#[cfg(feature = "bip39")]
const ETH_COIN_TYPE: u32 = 60;
/// BIP-32 hardened-offset bit (`2^31`).
pub const HARDENED: u32 = 0x8000_0000;
/// Default account index (`m/44'/60'/0'/0/0`).
pub const DEFAULT_ACCOUNT_INDEX: u32 = 0;

/// BLAKE3 derive-key context for the browser **transport** (Ed25519) seed.
///
/// One BIP-39 mnemonic restores both the user's ETH identity and the browser's
/// iroh NodeId / operator key (Addendum B/C §6). The transport seed is
/// domain-separated from the BIP-39/BIP-44 secp256k1 material, so the
/// `seed == NodeId == operator` invariant is preserved without leaking the ETH
/// scalar derivation. Protocol-frozen: changing it re-keys every browser.
#[cfg(feature = "bip39")]
pub const TRANSPORT_DERIVE_CONTEXT: &str = "cawala-transport/ed25519/v1";

/// Cawala network/chain id used as the EIP-712 domain `chainId`.
///
/// ASCII `"cawala"` (`0x636177616c61`): a memorable, chain-id-sized constant.
/// Changing this invalidates every previously produced user signature, so it is
/// protocol-frozen.
pub const CAWALA_CHAIN_ID: u64 = 0x6361_7761_6c61;

/// EIP-712 domain name.
pub const EIP712_DOMAIN_NAME: &str = "Cawala";
/// EIP-712 domain version.
pub const EIP712_DOMAIN_VERSION: &str = "1";

/// EIP-712 `EIP712Domain` type string (name + version + chainId).
pub const EIP712_DOMAIN_TYPE: &str = "EIP712Domain(string name,string version,uint256 chainId)";

/// EIP-712 order-authorization type string.
///
/// The struct binds the payer's domain-separated [`PaymentOrder::hash`]
/// (`from ‖ to ‖ amount ‖ nonce ‖ expiry`) plus the payee's [`OctAddr`], and
/// nothing else (`msg_id`/`ttl` are never authorization inputs).
pub const ORDER_EIP712_TYPE: &str = "CawalaOrder(bytes32 orderHash,string payeeAddr)";

/// EIP-712 type string for the **registration** challenge.
///
/// Binds the registering node id to the new address; the proof is verified
/// against that new address (proof of control).
pub const ETH_REGISTRATION_EIP712_TYPE: &str =
    "CawalaEthRegistration(string nodeId,address newAddress)";

/// EIP-712 type string for the **rotation** challenge.
///
/// Binds the node id, the incumbent address, and the new address. The proof is
/// verified against the **incumbent** address (the old key authorizes the
/// change); the new key may optionally co-sign.
pub const ETH_ROTATION_EIP712_TYPE: &str =
    "CawalaEthRotation(string nodeId,address oldAddress,address newAddress)";

/// `n/2` for secp256k1: the boundary above which an ECDSA `s` is "high".
///
/// `n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Errors from the Ethereum identity primitives.
///
/// Kept as a plain `std` error (not a JS error) so the core is native-testable;
/// the wasm boundary converts via the client crate's `to_js_err`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthError {
    /// The mnemonic phrase failed validation (unknown word, bad checksum,
    /// wrong word count).
    InvalidMnemonic(String),
    /// BIP-32 derivation failed.
    Derivation(String),
    /// The raw 32-byte secret is not a valid secp256k1 scalar.
    InvalidSecretKey,
    /// The signature bytes are malformed.
    InvalidSignature,
    /// The recovery byte is not one of `{0, 1, 27, 28}`.
    InvalidRecoveryId(u8),
    /// The signature's `s` is not low (EIP-2); rejected on recovery.
    HighS,
    /// Public key recovery returned the identity point.
    RecoveryFailed,
    /// A byte field had the wrong length.
    InvalidLength {
        /// Human-readable field name.
        what: &'static str,
        /// Required length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },
    /// The recovered signer address does not match the claimed address.
    AddressMismatch {
        /// The address the signature was claimed to come from.
        expected: [u8; 20],
        /// The address actually recovered from the signature.
        recovered: [u8; 20],
    },
    /// A fresh **registration** proof carried an `old_address`; only a rotation
    /// may name an incumbent. A registration must be verified against the new
    /// address alone.
    RegistrationCarriesOldAddress,
    /// A **rotation** proof's `old_address` does not name the incumbent anchor;
    /// the old key must authorize the change.
    RotationIncumbentMismatch,
}

impl fmt::Display for EthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EthError::InvalidMnemonic(msg) => write!(f, "invalid BIP-39 mnemonic: {msg}"),
            EthError::Derivation(msg) => write!(f, "BIP-32 derivation failed: {msg}"),
            EthError::InvalidSecretKey => write!(f, "invalid secp256k1 secret key"),
            EthError::InvalidSignature => write!(f, "invalid ECDSA signature encoding"),
            EthError::InvalidRecoveryId(v) => write!(f, "invalid ECDSA recovery id: {v}"),
            EthError::HighS => write!(f, "ECDSA signature is not low-s (EIP-2)"),
            EthError::RecoveryFailed => write!(f, "ECDSA public key recovery failed"),
            EthError::InvalidLength {
                what,
                expected,
                got,
            } => write!(f, "{what} must be {expected} bytes, got {got}"),
            EthError::AddressMismatch { .. } => {
                write!(f, "recovered address does not match the claimed address")
            }
            EthError::RegistrationCarriesOldAddress => {
                write!(f, "a registration proof must not carry an old address")
            }
            EthError::RotationIncumbentMismatch => {
                write!(f, "rotation proof does not name the incumbent anchor")
            }
        }
    }
}

impl std::error::Error for EthError {}

/// Derive the BIP-44 Ethereum path `m/44'/60'/0'/0/{index}`.
///
/// Returns an error if `index` has the hardened bit set, which would silently
/// turn `index` into a hardened child (`index` must be `< 2^31`).
#[cfg(feature = "bip39")]
pub fn eth_derivation_path(index: u32) -> Result<DerivationPath, EthError> {
    if index >= HARDENED {
        return Err(EthError::Derivation(format!(
            "account index {index} is not a non-hardened child index"
        )));
    }
    Ok(DerivationPath::from(vec![
        HARDENED | 44,
        HARDENED | ETH_COIN_TYPE,
        HARDENED, // account 0
        0,        // external chain
        index,
    ]))
}

/// Convert a BIP-39 mnemonic (+ optional passphrase) into its 64-byte seed.
///
/// Exposed mainly for BIP-39 test-vector validation; the seed is never stored.
#[cfg(feature = "bip39")]
pub fn mnemonic_to_seed(
    mnemonic: &str,
    passphrase: Option<&str>,
) -> Result<Zeroizing<[u8; 64]>, EthError> {
    let parsed = Mnemonic::<English>::new_from_phrase(mnemonic)
        .map_err(|err| EthError::InvalidMnemonic(err.to_string()))?;
    parsed
        .to_seed(passphrase)
        .map_err(|err| EthError::InvalidMnemonic(err.to_string()))
}

/// Derive the deterministic 32-byte Ed25519 **transport** seed for a browser
/// from a BIP-39 mnemonic and optional passphrase.
///
/// This is `BLAKE3::derive_key("cawala-transport/ed25519/v1", BIP39-seed)`: a
/// domain-separated expansion of the same BIP-39 seed that roots the ETH
/// identity, so one mnemonic restores both (Addendum B/C §6). The result is a
/// valid Ed25519 seed by construction (an arbitrary 32-byte string); it is
/// deliberately **distinct** from the BIP-44 secp256k1 scalar material.
///
/// The seed is not secret-by-itself beyond the mnemonic, but it is key
/// material: the caller owns zeroization.
#[cfg(feature = "bip39")]
pub fn transport_seed_from_mnemonic(
    mnemonic: &str,
    passphrase: Option<&str>,
) -> Result<[u8; 32], EthError> {
    let seed = mnemonic_to_seed(mnemonic, passphrase)?;
    Ok(blake3::derive_key(TRANSPORT_DERIVE_CONTEXT, &*seed))
}

/// Derive the secp256k1 signing key at `m/44'/60'/0'/0/{index}`.
#[cfg(feature = "bip39")]
pub fn derive_signing_key(
    mnemonic: &str,
    passphrase: Option<&str>,
    index: u32,
) -> Result<SigningKey, EthError> {
    let parsed = Mnemonic::<English>::new_from_phrase(mnemonic)
        .map_err(|err| EthError::InvalidMnemonic(err.to_string()))?;
    let path = eth_derivation_path(index)?;
    let xpriv = parsed
        .master_key(passphrase)
        .map_err(|err| EthError::InvalidMnemonic(err.to_string()))?
        .derive_path(path)
        .map_err(|err| EthError::Derivation(err.to_string()))?;
    let signing_key: &SigningKey = xpriv.as_ref();
    Ok(signing_key.clone())
}

/// Build a signing key from a raw 32-byte scalar (bundle restore path).
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, EthError> {
    if bytes.len() != 32 {
        return Err(EthError::InvalidLength {
            what: "secret key",
            expected: 32,
            got: bytes.len(),
        });
    }
    SigningKey::from_slice(bytes).map_err(|_| EthError::InvalidSecretKey)
}

/// Keccak-256 (the pre-standard Ethereum hash, **not** SHA3-256).
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

/// Ethereum address derived from a signing key:
/// `keccak256(uncompressed_pubkey[1..])[12..]`.
#[must_use]
pub fn address_from_signing_key(key: &SigningKey) -> [u8; 20] {
    address_from_verifying_key(key.verifying_key())
}

/// Ethereum address derived from an already-computed verifying key.
#[must_use]
pub fn address_from_verifying_key(key: &VerifyingKey) -> [u8; 20] {
    let point = key.to_sec1_point(false);
    address_from_uncompressed_public_key(point.as_bytes())
}

/// Address from a 65-byte uncompressed secp256k1 public key (`0x04 || X || Y`).
#[must_use]
pub fn address_from_uncompressed_public_key(public_key: &[u8]) -> [u8; 20] {
    debug_assert_eq!(public_key.len(), 65, "uncompressed public key is 65 bytes");
    let digest = keccak256(&public_key[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..]);
    address
}

/// 65-byte uncompressed public key (`0x04 || X || Y`).
#[must_use]
pub fn uncompressed_public_key(key: &SigningKey) -> [u8; 65] {
    let point = key.verifying_key().to_sec1_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(point.as_bytes());
    out
}

/// Render an address with the EIP-55 mixed-case checksum (`0x` prefix).
#[must_use]
pub fn checksum_address(address: &[u8; 20]) -> String {
    let lower = bytes_to_hex_lower(address);
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, byte) in lower.bytes().enumerate() {
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        if byte.is_ascii_digit() || nibble < 8 {
            out.push(byte as char);
        } else {
            out.push((byte as char).to_ascii_uppercase());
        }
    }
    out
}

/// Lowercase hex encoding (no `0x` prefix).
#[must_use]
pub fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// EIP-712 `hashStruct`: `keccak256(typeHash ‖ encodedFields)`.
///
/// The EIP-712 *domain separator* has the same shape (its type hash plus the
/// ABI-encoded domain fields), so callers build it with this helper too.
#[must_use]
pub fn eip712_hash_struct(type_hash: &[u8; 32], encoded_fields: &[u8]) -> [u8; 32] {
    let mut buffer = Vec::with_capacity(32 + encoded_fields.len());
    buffer.extend_from_slice(type_hash);
    buffer.extend_from_slice(encoded_fields);
    keccak256(&buffer)
}

/// EIP-712 final digest: `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`.
#[must_use]
pub fn eip712_digest(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut buffer = [0u8; 66];
    buffer[0] = 0x19;
    buffer[1] = 0x01;
    buffer[2..34].copy_from_slice(domain_separator);
    buffer[34..].copy_from_slice(struct_hash);
    keccak256(&buffer)
}

/// Build an EIP-712 domain separator from a name, version, and chain id.
#[must_use]
pub fn eip712_domain_separator(name: &str, version: &str, chain_id: u64) -> [u8; 32] {
    let type_hash = keccak256(EIP712_DOMAIN_TYPE.as_bytes());
    let mut fields = Vec::with_capacity(96);
    fields.extend_from_slice(&keccak256(name.as_bytes()));
    fields.extend_from_slice(&keccak256(version.as_bytes()));
    fields.extend_from_slice(&chain_id_to_u256_be(chain_id));
    eip712_hash_struct(&type_hash, &fields)
}

/// The Cawala EIP-712 domain separator (name/version/[`CAWALA_CHAIN_ID`]).
#[must_use]
pub fn cawala_domain_separator() -> [u8; 32] {
    eip712_domain_separator(EIP712_DOMAIN_NAME, EIP712_DOMAIN_VERSION, CAWALA_CHAIN_ID)
}

/// The canonical EIP-712 digest a user signs to authorize one order.
///
/// Binds exactly `PaymentOrder::hash` (`from ‖ to ‖ amount ‖ nonce ‖ expiry`)
/// plus `payee_addr`, under the Cawala domain separator. Both the browser
/// (signing) and the node (recovering) MUST use this one function.
#[must_use]
pub fn order_digest(order: &PaymentOrder, payee_addr: &OctAddr) -> [u8; 32] {
    let type_hash = keccak256(ORDER_EIP712_TYPE.as_bytes());
    let payee_hash = keccak256(payee_addr.to_string().as_bytes());
    let mut fields = Vec::with_capacity(64);
    fields.extend_from_slice(order.hash().as_bytes());
    fields.extend_from_slice(&payee_hash);
    let struct_hash = eip712_hash_struct(&type_hash, &fields);
    eip712_digest(&cawala_domain_separator(), &struct_hash)
}

/// Encode a `u64` chain id as a 32-byte big-endian EIP-712 `uint256`.
fn chain_id_to_u256_be(chain_id: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&chain_id.to_be_bytes());
    out
}

/// ABI-encode a `string` EIP-712 field: `keccak256(utf8 bytes)`.
fn abi_encode_string(value: &str) -> [u8; 32] {
    keccak256(value.as_bytes())
}

/// ABI-encode an `address` EIP-712 field: left-padded to 32 bytes.
fn abi_encode_address(address: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address);
    out
}

/// The canonical EIP-712 digest a user signs (and the node recovers) to
/// **register** a fresh Ethereum anchor.
///
/// Binds the node id and the new address under the Cawala domain separator.
/// The proof is verified against `new_address` (proof of control): the browser
/// signs this digest and the node requires `ecrecover == new_address`.
#[must_use]
pub fn eth_registration_digest(node_id: &str, new_address: &[u8; 20]) -> [u8; 32] {
    let type_hash = keccak256(ETH_REGISTRATION_EIP712_TYPE.as_bytes());
    let mut fields = Vec::with_capacity(64);
    fields.extend_from_slice(&abi_encode_string(node_id));
    fields.extend_from_slice(&abi_encode_address(new_address));
    let struct_hash = eip712_hash_struct(&type_hash, &fields);
    eip712_digest(&cawala_domain_separator(), &struct_hash)
}

/// The canonical EIP-712 digest a user signs (and the node recovers) to
/// **rotate** an existing Ethereum anchor.
///
/// Binds the node id, the incumbent address, and the new address. The proof is
/// verified against `old_address` (the **incumbent**): an operator key thief
/// holding only the transport seed cannot rotate the anchor, because it lacks
/// the old key. The new key may optionally co-sign over the same digest.
#[must_use]
pub fn eth_rotation_digest(
    node_id: &str,
    old_address: &[u8; 20],
    new_address: &[u8; 20],
) -> [u8; 32] {
    let type_hash = keccak256(ETH_ROTATION_EIP712_TYPE.as_bytes());
    let mut fields = Vec::with_capacity(96);
    fields.extend_from_slice(&abi_encode_string(node_id));
    fields.extend_from_slice(&abi_encode_address(old_address));
    fields.extend_from_slice(&abi_encode_address(new_address));
    let struct_hash = eip712_hash_struct(&type_hash, &fields);
    eip712_digest(&cawala_domain_separator(), &struct_hash)
}

/// Sign a 32-byte prehash, returning a canonical 65-byte `r || s || v`.
///
/// `v` is the Ethereum-style recovery byte (`27` or `28`). The signature is
/// normalized to low-`s` (EIP-2); `k256` already does this by default, and the
/// explicit [`canonicalize`] call enforces it regardless of backend.
pub fn sign_digest(key: &SigningKey, digest: &[u8]) -> Result<[u8; 65], EthError> {
    require_digest_len(digest)?;
    let (signature, recovery_id) = key.sign_prehash_recoverable(digest);
    let (signature, recovery_id) = canonicalize(signature, recovery_id);
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(signature.to_bytes().as_slice());
    out[64] = recovery_id.to_byte() + 27;
    Ok(out)
}

/// Recover the signer's Ethereum address from a digest and 65-byte signature.
///
/// Accepts `v` in `{27, 28}` (canonical) or `{0, 1}` (raw recovery id). High-`s`
/// signatures are rejected (EIP-2).
pub fn recover_address(digest: &[u8], signature: &[u8]) -> Result<[u8; 20], EthError> {
    require_digest_len(digest)?;
    if signature.len() != 65 {
        return Err(EthError::InvalidLength {
            what: "signature",
            expected: 65,
            got: signature.len(),
        });
    }
    let sig = Signature::from_slice(&signature[..64]).map_err(|_| EthError::InvalidSignature)?;
    if is_high_s(&sig) {
        return Err(EthError::HighS);
    }
    let recovery_id = recovery_id_from_v(signature[64])?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, recovery_id)
        .map_err(|_| EthError::RecoveryFailed)?;
    Ok(address_from_verifying_key(&key))
}

/// Is the signature's `s` greater than `n/2` (non-canonical, high-`s`)?
#[must_use]
pub fn is_high_s(signature: &Signature) -> bool {
    let bytes = signature.to_bytes();
    let s: &[u8] = &bytes.as_slice()[32..];
    s > SECP256K1_HALF_ORDER.as_slice()
}

/// Enforce low-`s`: if `signature` was high-`s`, normalize it and flip the
/// recovery id's y-parity bit (the `s -> n - s` symmetry mirrors `R` about the
/// x-axis).
fn canonicalize(signature: Signature, recovery_id: RecoveryId) -> (Signature, RecoveryId) {
    let normalized = signature.normalize_s();
    if normalized.to_bytes() == signature.to_bytes() {
        (signature, recovery_id)
    } else {
        (
            normalized,
            RecoveryId::new(!recovery_id.is_y_odd(), recovery_id.is_x_reduced()),
        )
    }
}

fn recovery_id_from_v(v: u8) -> Result<RecoveryId, EthError> {
    let raw = match v {
        0 | 1 => v,
        27 | 28 => v - 27,
        other => return Err(EthError::InvalidRecoveryId(other)),
    };
    RecoveryId::from_byte(raw).ok_or(EthError::InvalidRecoveryId(v))
}

fn require_digest_len(digest: &[u8]) -> Result<(), EthError> {
    if digest.len() != 32 {
        return Err(EthError::InvalidLength {
            what: "digest",
            expected: 32,
            got: digest.len(),
        });
    }
    Ok(())
}

/// serde support for a fixed 65-byte array.
///
/// serde only derives array impls up to 32 elements, so the 65-byte signature
/// is (de)serialized as a byte string. Used by [`EthIdentity`] and [`EthProof`].
pub mod sig65 {
    use std::fmt;

    use serde::Serializer;
    use serde::de::{Deserializer, Error, SeqAccess, Visitor};

    /// Serialize a 65-byte signature as a byte string.
    pub fn serialize<S>(bytes: &[u8; 65], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    /// Deserialize a 65-byte signature from a byte string (or a 65-element seq).
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 65], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedVisitor;

        impl<'de> Visitor<'de> for FixedVisitor {
            type Value = [u8; 65];

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 65-byte signature")
            }

            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<[u8; 65], E> {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
            }

            fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<[u8; 65], E> {
                self.visit_bytes(&v)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 65], A::Error> {
                let mut out = [0u8; 65];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }

        deserializer.deserialize_bytes(FixedVisitor)
    }
}

/// A recovered/claimed Ethereum identity carried inside an order (v4).
///
/// `address` is the account the signature is asserted to come from; `signature`
/// is the canonical 65-byte `r ‖ s ‖ v` over the EIP-712 order digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthIdentity {
    /// The claimed user address (20 bytes, no checksum).
    pub address: [u8; 20],
    /// The 65-byte `r ‖ s ‖ v` signature over [`order_digest`].
    #[serde(with = "crate::sig65")]
    pub signature: [u8; 65],
}

impl EthIdentity {
    /// Recover the signer address for `digest` using this identity's signature.
    pub fn recovered_address(&self, digest: &[u8]) -> Result<[u8; 20], EthError> {
        recover_address(digest, &self.signature)
    }

    /// Verify that the signature recovers to [`Self::address`] for `digest`.
    ///
    /// This is pure recovery; the authoritative anchor comparison (the direct
    /// parent's `ChildEntry.eth_address`) is a separate, fail-closed gate.
    pub fn verify_for(&self, digest: &[u8]) -> Result<(), EthError> {
        let recovered = self.recovered_address(digest)?;
        if recovered == self.address {
            Ok(())
        } else {
            Err(EthError::AddressMismatch {
                expected: self.address,
                recovered,
            })
        }
    }
}

/// An ETH proof accompanying a control `RegisterEthAddress` (registration or
/// rotation).
///
/// `signature` is the user's signature over the domain-separated challenge
/// (see the node's registration handling); `old_address` is `Some` only for a
/// rotation, naming the incumbent anchor the proof must be verified against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthProof {
    /// The 65-byte `r ‖ s ‖ v` proof signature.
    #[serde(with = "crate::sig65")]
    pub signature: [u8; 65],
    /// The incumbent address for a rotation; `None` for a fresh registration.
    pub old_address: Option<[u8; 20]>,
}

impl EthProof {
    /// Verify a **fresh registration** proof for `node_id` against the new
    /// address.
    ///
    /// Rejects a proof that names an `old_address` (only a rotation may) and a
    /// signature that recovers to anything other than `new_address`.
    pub fn verify_registration(
        &self,
        node_id: &str,
        new_address: &[u8; 20],
    ) -> Result<(), EthError> {
        if self.old_address.is_some() {
            return Err(EthError::RegistrationCarriesOldAddress);
        }
        let digest = eth_registration_digest(node_id, new_address);
        let recovered = recover_address(&digest, &self.signature)?;
        if recovered == *new_address {
            Ok(())
        } else {
            Err(EthError::AddressMismatch {
                expected: *new_address,
                recovered,
            })
        }
    }

    /// Verify a **rotation** proof for `node_id` against the incumbent anchor.
    ///
    /// The proof's `old_address` must equal `incumbent` and the signature must
    /// recover to `incumbent` over the rotation challenge; this is what stops an
    /// operator-key-only assertion from swapping the anchor.
    pub fn verify_rotation(
        &self,
        node_id: &str,
        incumbent: &[u8; 20],
        new_address: &[u8; 20],
    ) -> Result<(), EthError> {
        if self.old_address != Some(*incumbent) {
            return Err(EthError::RotationIncumbentMismatch);
        }
        let digest = eth_rotation_digest(node_id, incumbent, new_address);
        let recovered = recover_address(&digest, &self.signature)?;
        if recovered == *incumbent {
            Ok(())
        } else {
            Err(EthError::AddressMismatch {
                expected: *incumbent,
                recovered,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical BIP-39 Trezor test-vector mnemonic.
    #[cfg(feature = "bip39")]
    const TREZOR_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// The standard BIP-44 Ethereum test mnemonic used by hardhat/anvil.
    #[cfg(feature = "bip39")]
    const ETH_TEST_MNEMONIC: &str =
        "test test test test test test test test test test test junk";

    /// hardhat/anvil account #0 secret key.
    const HARDHAT_KEY_0: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        assert!(hex.len().is_multiple_of(2), "odd hex length");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn hex32(hex: &str) -> [u8; 32] {
        let bytes = hex_to_bytes(hex);
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes_to_hex_lower(bytes)
    }

    #[test]
    fn keccak256_matches_known_vector() {
        // keccak256("") pre-NIST Keccak.
        assert_eq!(
            bytes_to_hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn known_eth_address_from_raw_secret() {
        // EIP-155 / hardhat account #0: address derives purely from the scalar,
        // so this vector is independent of the BIP-39 feature.
        let key = signing_key_from_bytes(&hex_to_bytes(HARDHAT_KEY_0)).expect("restore");
        assert_eq!(
            checksum_address(&address_from_signing_key(&key)),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
    }

    #[test]
    fn rejects_invalid_secret_key() {
        // Zero is not a valid secp256k1 scalar.
        assert_eq!(
            signing_key_from_bytes(&[0u8; 32]),
            Err(EthError::InvalidSecretKey)
        );
        assert!(signing_key_from_bytes(&[0u8; 31]).is_err());
    }

    #[test]
    fn checksum_address_is_eip55() {
        // Known EIP-55 vector.
        let address: [u8; 20] = hex_to_bytes("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
            .try_into()
            .unwrap();
        assert_eq!(
            checksum_address(&address),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }

    #[test]
    fn eip712_digest_layout() {
        let domain =
            hex32("0000000000000000000000000000000000000000000000000000000000000001");
        let structure =
            hex32("0000000000000000000000000000000000000000000000000000000000000002");
        let digest = eip712_digest(&domain, &structure);
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&[0x19, 0x01]);
        expected_input.extend_from_slice(&domain);
        expected_input.extend_from_slice(&structure);
        assert_eq!(digest, keccak256(&expected_input));
    }

    #[test]
    fn eip712_sign_recover_round_trip() {
        let key = signing_key_from_bytes(&hex_to_bytes(HARDHAT_KEY_0)).expect("restore");
        let expected = address_from_signing_key(&key);
        let domain =
            hex32("0101010101010101010101010101010101010101010101010101010101010101");
        let structure =
            hex32("0202020202020202020202020202020202020202020202020202020202020202");
        let digest = eip712_digest(&domain, &structure);

        let signature = sign_digest(&key, &digest).expect("sign");
        assert_eq!(signature.len(), 65);
        assert!(matches!(signature[64], 27 | 28));
        assert_eq!(
            recover_address(&digest, &signature).expect("recover"),
            expected
        );
    }

    #[test]
    fn eth_identity_verifies_and_rejects_mismatch() {
        let key = signing_key_from_bytes(&hex_to_bytes(HARDHAT_KEY_0)).expect("restore");
        let digest = keccak256(b"identity verify");
        let identity = EthIdentity {
            address: address_from_signing_key(&key),
            signature: sign_digest(&key, &digest).expect("sign"),
        };
        assert_eq!(identity.recovered_address(&digest), Ok(identity.address));
        assert_eq!(identity.verify_for(&digest), Ok(()));

        let mut wrong = identity.clone();
        wrong.address[0] ^= 0xff;
        assert!(matches!(
            wrong.verify_for(&digest),
            Err(EthError::AddressMismatch { .. })
        ));
    }

    #[test]
    fn signatures_are_low_s() {
        let key = signing_key_from_bytes(&hex_to_bytes(HARDHAT_KEY_0)).expect("restore");
        // Sign many distinct digests; all must be canonical.
        for i in 0..32u8 {
            let digest = keccak256(&[i]);
            let signature = sign_digest(&key, &digest).expect("sign");
            let parsed = Signature::from_slice(&signature[..64]).expect("parse");
            assert!(!is_high_s(&parsed), "digest {i} produced high-s");
        }
    }

    #[test]
    fn high_s_signature_is_rejected_on_recovery() {
        let key = signing_key_from_bytes(&hex_to_bytes(HARDHAT_KEY_0)).expect("restore");
        let digest = keccak256(b"high-s test");
        let mut signature = sign_digest(&key, &digest).expect("sign");
        assert!(!is_high_s(&Signature::from_slice(&signature[..64]).unwrap()));

        // Flip s -> n - s to make it high, and flip the y-parity bit to keep a
        // valid (if non-canonical) signature.
        let n = hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let s = hex32(&bytes_to_hex(&signature[32..64]));
        let mut high_s = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = n[i] as i16 - s[i] as i16 - borrow;
            if diff < 0 {
                high_s[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                high_s[i] = diff as u8;
                borrow = 0;
            }
        }
        signature[32..64].copy_from_slice(&high_s);
        signature[64] ^= 1;
        assert!(is_high_s(&Signature::from_slice(&signature[..64]).unwrap()));
        assert_eq!(recover_address(&digest, &signature), Err(EthError::HighS));
    }

    #[test]
    fn rejects_invalid_recovery_id() {
        let key = signing_key_from_bytes(&hex_to_bytes(HARDHAT_KEY_0)).expect("restore");
        let digest = keccak256(b"recovery-id test");
        let mut signature = sign_digest(&key, &digest).expect("sign");
        for bad in [2u8, 3, 26, 29, 255] {
            signature[64] = bad;
            assert_eq!(
                recover_address(&digest, &signature),
                Err(EthError::InvalidRecoveryId(bad))
            );
        }
    }

    #[test]
    fn recovery_accepts_zero_based_v() {
        let key = signing_key_from_bytes(&hex_to_bytes(HARDHAT_KEY_0)).expect("restore");
        let expected = address_from_signing_key(&key);
        let digest = keccak256(b"zero-based v");
        let mut signature = sign_digest(&key, &digest).expect("sign");
        signature[64] -= 27;
        assert_eq!(
            recover_address(&digest, &signature).expect("recover"),
            expected
        );
    }

    #[test]
    fn rejects_wrong_lengths() {
        let key = signing_key_from_bytes(&hex_to_bytes(HARDHAT_KEY_0)).expect("restore");
        assert!(matches!(
            sign_digest(&key, &[0u8; 31]),
            Err(EthError::InvalidLength { .. })
        ));
        assert!(matches!(
            recover_address(&[0u8; 32], &[0u8; 64]),
            Err(EthError::InvalidLength { .. })
        ));
    }

    #[test]
    fn cawala_domain_separator_is_stable_and_chain_bound() {
        // The domain separator must be deterministic and change with the chain
        // id (cross-network replay resistance).
        let base = cawala_domain_separator();
        assert_eq!(base, cawala_domain_separator());
        assert_eq!(
            base,
            eip712_domain_separator(EIP712_DOMAIN_NAME, EIP712_DOMAIN_VERSION, CAWALA_CHAIN_ID)
        );
        assert_ne!(
            base,
            eip712_domain_separator(EIP712_DOMAIN_NAME, EIP712_DOMAIN_VERSION, CAWALA_CHAIN_ID + 1)
        );
        assert_ne!(
            base,
            eip712_domain_separator("Other", EIP712_DOMAIN_VERSION, CAWALA_CHAIN_ID)
        );
    }

    #[test]
    fn order_digest_binds_order_and_payee() {
        use cawala_ledger::{Amount, NodeId};

        let order = PaymentOrder {
            from: NodeId::from("alice"),
            to: NodeId::from("bob"),
            amount: Amount::new(7),
            nonce: 5,
            expiry: 100,
        };
        let payee: OctAddr = "0.2.4".parse().expect("valid octal address");
        let digest = order_digest(&order, &payee);
        assert_eq!(digest, order_digest(&order, &payee));

        // A different payee address yields a different digest.
        let other: OctAddr = "0.2.5".parse().expect("valid octal address");
        assert_ne!(digest, order_digest(&order, &other));

        // A different order yields a different digest.
        let mut changed = order.clone();
        changed.amount = Amount::new(8);
        assert_ne!(digest, order_digest(&changed, &payee));

        // Sign/recover against the exact canonical digest round-trips.
        let key = signing_key_from_bytes(&hex_to_bytes(HARDHAT_KEY_0)).expect("restore");
        let identity = EthIdentity {
            address: address_from_signing_key(&key),
            signature: sign_digest(&key, &digest).expect("sign"),
        };
        assert_eq!(identity.verify_for(&digest), Ok(()));
    }

    #[test]
    fn registration_digest_binds_node_and_new_address() {
        let key = signing_key_from_bytes(&[0x11; 32]).expect("valid scalar");
        let address = address_from_signing_key(&key);
        let node_id = "node-alpha";

        let digest = eth_registration_digest(node_id, &address);
        assert_eq!(digest, eth_registration_digest(node_id, &address));
        // The node id and the new address are both bound.
        assert_ne!(digest, eth_registration_digest("node-beta", &address));
        assert_ne!(digest, eth_registration_digest(node_id, &[0xff; 20]));

        let proof = EthProof {
            signature: sign_digest(&key, &digest).expect("sign"),
            old_address: None,
        };
        assert_eq!(proof.verify_registration(node_id, &address), Ok(()));

        // Wrong node id / wrong claimed address are rejected.
        assert!(proof.verify_registration("node-beta", &address).is_err());
        assert!(matches!(
            proof.verify_registration(node_id, &[0xff; 20]),
            Err(EthError::AddressMismatch { .. })
        ));
        // A registration proof must not carry an old address.
        let carries_old = EthProof {
            old_address: Some(address),
            ..proof.clone()
        };
        assert_eq!(
            carries_old.verify_registration(node_id, &address),
            Err(EthError::RegistrationCarriesOldAddress)
        );
    }

    #[test]
    fn rotation_digest_is_authorized_by_the_incumbent() {
        // The incumbent key authorizes a rotation to a new address.
        let old_key = signing_key_from_bytes(&[0x11; 32]).expect("valid scalar");
        let new_key = signing_key_from_bytes(&[0x22; 32]).expect("valid scalar");
        let old_address = address_from_signing_key(&old_key);
        let new_address = address_from_signing_key(&new_key);
        let node_id = "node-alpha";

        let digest = eth_rotation_digest(node_id, &old_address, &new_address);
        assert_eq!(
            digest,
            eth_rotation_digest(node_id, &old_address, &new_address)
        );
        assert_ne!(digest, eth_registration_digest(node_id, &new_address));

        let proof = EthProof {
            signature: sign_digest(&old_key, &digest).expect("sign"),
            old_address: Some(old_address),
        };
        assert_eq!(
            proof.verify_rotation(node_id, &old_address, &new_address),
            Ok(())
        );

        // The anchor-swap bypass: a proof signed by the NEW (non-incumbent) key
        // over the rotation challenge must be rejected as non-incumbent.
        let swap = EthProof {
            signature: sign_digest(&new_key, &digest).expect("sign"),
            old_address: Some(old_address),
        };
        assert!(matches!(
            swap.verify_rotation(node_id, &old_address, &new_address),
            Err(EthError::AddressMismatch { .. })
        ));

        // A proof whose `old_address` does not name the incumbent is rejected
        // before any recovery.
        let wrong_incumbent = EthProof {
            old_address: Some(new_address),
            ..proof
        };
        assert_eq!(
            wrong_incumbent.verify_rotation(node_id, &old_address, &new_address),
            Err(EthError::RotationIncumbentMismatch)
        );
    }

    #[test]
    fn serde_round_trips_eth_identity_and_proof() {
        let key = signing_key_from_bytes(&hex_to_bytes(HARDHAT_KEY_0)).expect("restore");
        let digest = keccak256(b"serde round trip");
        let identity = EthIdentity {
            address: address_from_signing_key(&key),
            signature: sign_digest(&key, &digest).expect("sign"),
        };
        let bytes = postcard::to_allocvec(&identity).unwrap();
        let back: EthIdentity = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, identity);

        let proof = EthProof {
            signature: identity.signature,
            old_address: Some([0x11; 20]),
        };
        let bytes = postcard::to_allocvec(&proof).unwrap();
        let back: EthProof = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, proof);

        let fresh = EthProof {
            signature: identity.signature,
            old_address: None,
        };
        let bytes = postcard::to_allocvec(&fresh).unwrap();
        let back: EthProof = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, fresh);
    }

    #[cfg(feature = "bip39")]
    #[test]
    fn bip39_official_vector_seed() {
        // BIP-39 test vector: entropy `0x00...00`, passphrase "TREZOR".
        let seed = mnemonic_to_seed(TREZOR_MNEMONIC, Some("TREZOR")).expect("mnemonic parses");
        assert_eq!(
            bytes_to_hex(&*seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[cfg(feature = "bip39")]
    #[test]
    fn bip39_no_passphrase_seed() {
        let seed = mnemonic_to_seed(TREZOR_MNEMONIC, None).expect("mnemonic parses");
        assert_eq!(
            bytes_to_hex(&*seed),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[cfg(feature = "bip39")]
    #[test]
    fn bip39_rejects_bad_checksum() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(matches!(
            mnemonic_to_seed(bad, None),
            Err(EthError::InvalidMnemonic(_))
        ));
    }

    #[cfg(feature = "bip39")]
    #[test]
    fn transport_seed_is_deterministic() {
        let a = transport_seed_from_mnemonic(TREZOR_MNEMONIC, None).expect("derive");
        let b = transport_seed_from_mnemonic(TREZOR_MNEMONIC, None).expect("derive");
        assert_eq!(a, b);

        let with_pass =
            transport_seed_from_mnemonic(TREZOR_MNEMONIC, Some("TREZOR")).expect("derive");
        assert_ne!(a, with_pass, "the BIP-39 passphrase must change the seed");

        let other = transport_seed_from_mnemonic(ETH_TEST_MNEMONIC, None).expect("derive");
        assert_ne!(a, other, "different mnemonics derive different seeds");
    }

    #[cfg(feature = "bip39")]
    #[test]
    fn transport_seed_is_distinct_from_secp256k1_material() {
        let transport = transport_seed_from_mnemonic(TREZOR_MNEMONIC, None).expect("derive");
        let bip39_seed = mnemonic_to_seed(TREZOR_MNEMONIC, None).expect("seed");

        // Not a prefix of (or equal to) the raw BIP-39 seed.
        assert_ne!(transport.as_slice(), &bip39_seed[..32]);
        let mut tagged = Vec::with_capacity(64);
        tagged.extend_from_slice(&transport);
        assert_ne!(tagged.as_slice(), bip39_seed.as_slice());

        // Not the BIP-44 secp256k1 scalar either.
        let key = derive_signing_key(TREZOR_MNEMONIC, None, 0).expect("derive");
        assert_ne!(transport.as_slice(), key.to_bytes().as_slice());

        // The derive-key context is load-bearing: a different context differs.
        assert_ne!(
            transport,
            blake3::derive_key("cawala-transport/ed25519/v2", &*bip39_seed)
        );
    }

    #[cfg(feature = "bip39")]
    #[test]
    fn transport_seed_rejects_bad_mnemonic() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(matches!(
            transport_seed_from_mnemonic(bad, None),
            Err(EthError::InvalidMnemonic(_))
        ));
    }

    #[cfg(feature = "bip39")]
    #[test]
    fn eth_derivation_path_is_bip44() {
        let path = eth_derivation_path(0).expect("path");
        assert_eq!(path.derivation_string(), "m/44'/60'/0'/0/0");
        assert!(eth_derivation_path(HARDENED).is_err());
    }

    #[cfg(feature = "bip39")]
    #[test]
    fn known_eth_address_index_zero() {
        // Standard hardhat/anvil account #0.
        let key = derive_signing_key(ETH_TEST_MNEMONIC, None, 0).expect("derive");
        assert_eq!(
            checksum_address(&address_from_signing_key(&key)),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
    }

    #[cfg(feature = "bip39")]
    #[test]
    fn known_eth_address_index_one() {
        // Standard hardhat/anvil account #1.
        let key = derive_signing_key(ETH_TEST_MNEMONIC, None, 1).expect("derive");
        assert_eq!(
            checksum_address(&address_from_signing_key(&key)),
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        );
    }

    #[cfg(feature = "bip39")]
    #[test]
    fn raw_secret_key_matches_derivation() {
        let derived = derive_signing_key(ETH_TEST_MNEMONIC, None, 0).expect("derive");
        let raw = derived.to_bytes();
        let restored = signing_key_from_bytes(raw.as_slice()).expect("restore");
        assert_eq!(
            address_from_signing_key(&derived),
            address_from_signing_key(&restored)
        );
    }
}
