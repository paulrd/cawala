//! User-level secp256k1 / Ethereum identity primitives (R3, phase P2a).
//!
//! This module is **wire-free**: it derives, signs, recovers and hashes, but
//! never touches a control/msg payload. Its job is to be the single place where
//! the user's Ethereum secret is materialized so later lanes (P2b/P2c) can
//! consume it.
//!
//! Model (spec §1.1):
//!
//! - Root key: BIP-39 mnemonic (+ optional BIP-39 passphrase) derived on the
//!   BIP-44 Ethereum path `m/44'/60'/0'/0/{index}` (default index `0`).
//! - Address: `keccak256(uncompressed_pubkey[1..])[12..]`, rendered with the
//!   EIP-55 mixed-case checksum.
//! - Signing: EIP-712 typed-data digest, ECDSA over secp256k1 with **low-`s`
//!   (EIP-2)** normalization and a validated recovery id, serialized as a
//!   65-byte `r || s || v` (`v ∈ {27, 28}`).
//!
//! The raw secret never crosses the wasm boundary. [`UserIdentity`] is a
//! `wasm-bindgen` handle that owns a [`SigningKey`] internally and exposes only
//! the address, public key, signatures and digests. `k256`'s `SigningKey`
//! implements `ZeroizeOnDrop`, so the scalar is wiped when the handle is freed.

use std::fmt;

use coins_bip32::path::DerivationPath;
use coins_bip39::{English, Mnemonic};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

/// BIP-44 coin type for Ethereum (`60'`).
const ETH_COIN_TYPE: u32 = 60;
/// BIP-32 hardened-offset bit (`2^31`).
const HARDENED: u32 = 0x8000_0000;
/// Default account index (`m/44'/60'/0'/0/0`).
pub const DEFAULT_ACCOUNT_INDEX: u32 = 0;

/// `n/2` for secp256k1: the boundary above which an ECDSA `s` is "high".
///
/// `n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Errors from the identity primitives.
///
/// Kept as a plain `std` error (not [`wasm_bindgen::JsError`]) so the core is
/// native-testable; the wasm boundary converts via [`crate::to_js_err`].
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
        }
    }
}

impl std::error::Error for EthError {}

/// Derive the BIP-44 Ethereum path `m/44'/60'/0'/0/{index}`.
///
/// Returns an error if `index` has the hardened bit set, which would silently
/// turn `index` into a hardened child (`index` must be `< 2^31`).
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

/// Derive the secp256k1 signing key at `m/44'/60'/0'/0/{index}`.
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
fn canonicalize(
    signature: Signature,
    recovery_id: RecoveryId,
) -> (Signature, RecoveryId) {
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

fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// A wasm-bindgen handle holding the user's secp256k1 secret **inside wasm**.
///
/// The raw scalar is never returned to JS. Dropping the handle (via the
/// generated `free()`) wipes the key, because `k256`'s `SigningKey` implements
/// `ZeroizeOnDrop`.
#[wasm_bindgen]
pub struct UserIdentity {
    key: SigningKey,
    address: [u8; 20],
}

impl UserIdentity {
    fn from_signing_key(key: SigningKey) -> Self {
        let address = address_from_signing_key(&key);
        UserIdentity { key, address }
    }
}

#[wasm_bindgen]
impl UserIdentity {
    /// Derive the user identity from a BIP-39 mnemonic.
    ///
    /// `passphrase` is the optional BIP-39 passphrase; `index` is the
    /// `m/44'/60'/0'/0/{index}` account index (defaults to `0`).
    #[wasm_bindgen(js_name = fromMnemonic)]
    pub fn from_mnemonic(
        mnemonic: &str,
        passphrase: Option<String>,
        index: Option<u32>,
    ) -> Result<UserIdentity, wasm_bindgen::JsError> {
        let index = index.unwrap_or(DEFAULT_ACCOUNT_INDEX);
        let key =
            derive_signing_key(mnemonic, passphrase.as_deref(), index).map_err(crate::to_js_err)?;
        Ok(UserIdentity::from_signing_key(key))
    }

    /// Restore an identity from a raw 32-byte secp256k1 secret (bundle
    /// restore). The bytes are copied into wasm-owned zeroizing storage.
    #[wasm_bindgen(js_name = fromSecretKey)]
    pub fn from_secret_key(secret: &[u8]) -> Result<UserIdentity, wasm_bindgen::JsError> {
        let key = signing_key_from_bytes(secret).map_err(crate::to_js_err)?;
        Ok(UserIdentity::from_signing_key(key))
    }

    /// EIP-55 checksummed address (`0x…`).
    #[wasm_bindgen(js_name = address)]
    #[must_use]
    pub fn address(&self) -> String {
        checksum_address(&self.address)
    }

    /// Raw 20 address bytes (no checksum casing).
    #[wasm_bindgen(js_name = addressBytes)]
    #[must_use]
    pub fn address_bytes(&self) -> Vec<u8> {
        self.address.to_vec()
    }

    /// 65-byte uncompressed public key (`0x04 || X || Y`). Public, not secret.
    #[wasm_bindgen(js_name = publicKeyUncompressed)]
    #[must_use]
    pub fn public_key_uncompressed(&self) -> Vec<u8> {
        uncompressed_public_key(&self.key).to_vec()
    }

    /// Sign a 32-byte digest, returning canonical 65-byte `r || s || v`.
    #[wasm_bindgen(js_name = signDigest)]
    pub fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, wasm_bindgen::JsError> {
        sign_digest(&self.key, digest)
            .map(|signature| signature.to_vec())
            .map_err(crate::to_js_err)
    }

    /// EIP-712 final digest from a domain separator and struct hash:
    /// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`.
    #[wasm_bindgen(js_name = eip712Digest)]
    pub fn eip712_digest(
        domain_separator: &[u8],
        struct_hash: &[u8],
    ) -> Result<Vec<u8>, wasm_bindgen::JsError> {
        if domain_separator.len() != 32 {
            return Err(wasm_bindgen::JsError::new(
                "domain separator must be 32 bytes",
            ));
        }
        if struct_hash.len() != 32 {
            return Err(wasm_bindgen::JsError::new("struct hash must be 32 bytes"));
        }
        let mut domain = [0u8; 32];
        domain.copy_from_slice(domain_separator);
        let mut structure = [0u8; 32];
        structure.copy_from_slice(struct_hash);
        Ok(eip712_digest(&domain, &structure).to_vec())
    }

    /// Recover the EIP-55 signer address from a digest and a 65-byte signature.
    #[wasm_bindgen(js_name = recoverAddress)]
    pub fn recover_address(
        digest: &[u8],
        signature: &[u8],
    ) -> Result<String, wasm_bindgen::JsError> {
        let address = crate::eth_identity::recover_address(digest, signature)
            .map_err(crate::to_js_err)?;
        Ok(checksum_address(&address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical BIP-39 Trezor test-vector mnemonic.
    const TREZOR_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// The standard BIP-44 Ethereum test mnemonic used by hardhat/anvil.
    const ETH_TEST_MNEMONIC: &str =
        "test test test test test test test test test test test junk";

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
    fn bip39_official_vector_seed() {
        // BIP-39 test vector: entropy `0x00...00`, passphrase "TREZOR".
        // https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#user-content-Test_vectors
        let seed = mnemonic_to_seed(TREZOR_MNEMONIC, Some("TREZOR")).expect("mnemonic parses");
        assert_eq!(
            bytes_to_hex(&*seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn bip39_no_passphrase_seed() {
        // Same vector, no passphrase.
        let seed = mnemonic_to_seed(TREZOR_MNEMONIC, None).expect("mnemonic parses");
        assert_eq!(
            bytes_to_hex(&*seed),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn bip39_rejects_bad_checksum() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(matches!(
            mnemonic_to_seed(bad, None),
            Err(EthError::InvalidMnemonic(_))
        ));
    }

    #[test]
    fn eth_derivation_path_is_bip44() {
        let path = eth_derivation_path(0).expect("path");
        assert_eq!(path.derivation_string(), "m/44'/60'/0'/0/0");
        assert!(eth_derivation_path(HARDENED).is_err());
    }

    #[test]
    fn known_eth_address_index_zero() {
        // Standard hardhat/anvil account #0.
        let key = derive_signing_key(ETH_TEST_MNEMONIC, None, 0).expect("derive");
        assert_eq!(
            checksum_address(&address_from_signing_key(&key)),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
    }

    #[test]
    fn known_eth_address_index_one() {
        // Standard hardhat/anvil account #1.
        let key = derive_signing_key(ETH_TEST_MNEMONIC, None, 1).expect("derive");
        assert_eq!(
            checksum_address(&address_from_signing_key(&key)),
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        );
    }

    #[test]
    fn raw_secret_key_matches_derivation() {
        let derived = derive_signing_key(ETH_TEST_MNEMONIC, None, 0).expect("derive");
        let raw = derived.to_bytes();
        let restored = signing_key_from_bytes(raw.as_slice()).expect("restore");
        assert_eq!(
            address_from_signing_key(&derived),
            address_from_signing_key(&restored)
        );
        assert!(signing_key_from_bytes(&[0u8; 31]).is_err());
    }

    #[test]
    fn rejects_invalid_secret_key() {
        // Zero is not a valid secp256k1 scalar.
        assert_eq!(
            signing_key_from_bytes(&[0u8; 32]),
            Err(EthError::InvalidSecretKey)
        );
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
    fn eip712_digest_layout() {
        let domain = hex32(
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
        let structure = hex32(
            "0000000000000000000000000000000000000000000000000000000000000002",
        );
        let digest = eip712_digest(&domain, &structure);
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&[0x19, 0x01]);
        expected_input.extend_from_slice(&domain);
        expected_input.extend_from_slice(&structure);
        assert_eq!(digest, keccak256(&expected_input));
    }

    #[test]
    fn eip712_sign_recover_round_trip() {
        let key = derive_signing_key(ETH_TEST_MNEMONIC, None, 0).expect("derive");
        let expected = address_from_signing_key(&key);
        let domain = hex32(
            "0101010101010101010101010101010101010101010101010101010101010101",
        );
        let structure = hex32(
            "0202020202020202020202020202020202020202020202020202020202020202",
        );
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
    fn signatures_are_low_s() {
        let key = derive_signing_key(ETH_TEST_MNEMONIC, None, 0).expect("derive");
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
        let key = derive_signing_key(ETH_TEST_MNEMONIC, None, 0).expect("derive");
        let digest = keccak256(b"high-s test");
        let mut signature = sign_digest(&key, &digest).expect("sign");
        assert!(!is_high_s(&Signature::from_slice(&signature[..64]).unwrap()));

        // Flip s -> n - s to make it high, and flip the y-parity bit to keep a
        // valid (if non-canonical) signature.
        let n = hex32(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        );
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
        assert_eq!(
            recover_address(&digest, &signature),
            Err(EthError::HighS)
        );
    }

    #[test]
    fn rejects_invalid_recovery_id() {
        let key = derive_signing_key(ETH_TEST_MNEMONIC, None, 0).expect("derive");
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
        let key = derive_signing_key(ETH_TEST_MNEMONIC, None, 0).expect("derive");
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
        let key = derive_signing_key(ETH_TEST_MNEMONIC, None, 0).expect("derive");
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
    fn checksum_address_is_eip55() {
        // Known EIP-55 vector.
        let address: [u8; 20] =
            hex_to_bytes("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").try_into().unwrap();
        assert_eq!(
            checksum_address(&address),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }
}
