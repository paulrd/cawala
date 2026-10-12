//! User-level secp256k1 / Ethereum identity primitives (R3, phase P2a).
//!
//! Since P2c this module is a thin wasm boundary over the shared
//! [`cawala_eth`] crate, so the node and the browser use **one** EIP-712
//! digest / `ecrecover` implementation (Addendum C §1). The free functions are
//! re-exported here unchanged, keeping the `cawala_client::eth_identity` API
//! stable.
//!
//! This module is **wire-free**: it derives, signs, recovers and hashes, but
//! never touches a control/msg payload.
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

// Re-export the shared implementation so `cawala_client::eth_identity::*`
// resolves exactly as before (behavior and API unchanged).
pub use cawala_eth::{
    DEFAULT_ACCOUNT_INDEX, EthError, HARDENED, address_from_signing_key,
    address_from_uncompressed_public_key, address_from_verifying_key, bytes_to_hex_lower,
    checksum_address, derive_signing_key, eip712_digest, eip712_hash_struct, eth_derivation_path,
    is_high_s, keccak256, mnemonic_to_seed, recover_address, sign_digest, signing_key_from_bytes,
    uncompressed_public_key,
};

use k256::ecdsa::SigningKey;
use wasm_bindgen::prelude::wasm_bindgen;

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
        let address =
            crate::eth_identity::recover_address(digest, signature).map_err(crate::to_js_err)?;
        Ok(checksum_address(&address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::Signature;

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
