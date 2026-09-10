//! Ed25519 key types, separated by role.
//!
//! Operator keys authorise control-plane changes; ledger keys authorise ledger
//! entries. The two are deliberately distinct types, so an operator signature
//! can never be mistaken for (or accepted as) a ledger signature.
//!
//! This module never generates randomness: construct keys from 32 raw bytes
//! with `from_bytes`. Verification uses `ed25519-dalek`'s `verify_strict`.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::LedgerError;

fn fmt_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

macro_rules! define_public_key {
    ($name:ident, $label:literal) => {
        #[doc = concat!("A ", $label, " Ed25519 public key.")]
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $name(VerifyingKey);

        impl $name {
            /// Parse a public key from 32 bytes.
            pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, LedgerError> {
                VerifyingKey::from_bytes(bytes)
                    .map($name)
                    .map_err(|_| LedgerError::InvalidKey)
            }

            /// The 32-byte compressed public key.
            pub fn to_bytes(&self) -> [u8; 32] {
                self.0.to_bytes()
            }

            /// Verify `signature` over `message` with strict (non-malleable)
            /// Ed25519 verification.
            pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), LedgerError> {
                self.0
                    .verify_strict(message, &signature.0)
                    .map_err(|_| LedgerError::InvalidSignature)
            }
        }

        impl core::hash::Hash for $name {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                core::hash::Hash::hash(&self.0.to_bytes(), state);
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.0.to_bytes().cmp(&other.0.to_bytes())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                fmt_hex(f, &self.0.to_bytes())?;
                f.write_str(")")
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt_hex(f, &self.0.to_bytes())
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serde::Serialize::serialize(&self.0.to_bytes(), serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let bytes = <[u8; 32] as serde::Deserialize>::deserialize(deserializer)?;
                Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! define_secret_key {
    ($name:ident, $public:ident, $label:literal) => {
        #[doc = concat!("A ", $label, " Ed25519 secret key.")]
        #[derive(Clone)]
        pub struct $name(SigningKey);

        impl $name {
            /// Construct from 32 raw secret bytes. Deterministic: no RNG.
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                $name(SigningKey::from_bytes(&bytes))
            }

            /// The 32 raw secret bytes.
            pub fn to_bytes(&self) -> [u8; 32] {
                self.0.to_bytes()
            }

            /// The corresponding public key.
            pub fn public(&self) -> $public {
                $public(self.0.verifying_key())
            }

            /// Sign `message`.
            pub fn sign(&self, message: &[u8]) -> Signature {
                Signature(Signer::sign(&self.0, message))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serde::Serialize::serialize(&self.0.to_bytes(), serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let bytes = <[u8; 32] as serde::Deserialize>::deserialize(deserializer)?;
                Ok(Self::from_bytes(bytes))
            }
        }
    };
}

define_public_key!(LedgerPubKey, "ledger");
define_public_key!(OperatorPubKey, "operator");
define_secret_key!(LedgerSecretKey, LedgerPubKey, "ledger");
define_secret_key!(OperatorSecretKey, OperatorPubKey, "operator");

/// A ledger's public identity. Ledger ids are ledger public keys.
pub type LedgerId = LedgerPubKey;

/// An Ed25519 signature (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(ed25519_dalek::Signature);

impl Signature {
    /// The encoded signature length in bytes.
    pub const LENGTH: usize = 64;

    /// Parse a signature from 64 bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Signature(ed25519_dalek::Signature::from_bytes(bytes))
    }

    /// The 64 raw signature bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature(")?;
        fmt_hex(f, &self.0.to_bytes())?;
        f.write_str(")")
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex(f, &self.0.to_bytes())
    }
}

// serde lacks a built-in impl for arrays larger than 32 bytes, so encode the
// signature as a fixed-length tuple of 64 bytes (mirrors iroh-base).
impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(Signature::LENGTH)?;
        for byte in self.0.to_bytes() {
            seq.serialize_element(&byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ByteArrayVisitor;

        impl<'de> serde::de::Visitor<'de> for ByteArrayVisitor {
            type Value = [u8; Signature::LENGTH];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a byte array of length {}", Signature::LENGTH)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = [0u8; Signature::LENGTH];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                Ok(bytes)
            }
        }

        deserializer
            .deserialize_tuple(Signature::LENGTH, ByteArrayVisitor)
            .map(|bytes| Signature::from_bytes(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_key() -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([1u8; 32])
    }

    fn operator_key() -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([2u8; 32])
    }

    fn other_ledger_key() -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([3u8; 32])
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = ledger_key();
        let signature = key.sign(b"hello ledger");
        assert!(key.public().verify(b"hello ledger", &signature).is_ok());
    }

    #[test]
    fn tampered_message_is_rejected() {
        let key = ledger_key();
        let signature = key.sign(b"hello ledger");
        assert_eq!(
            key.public().verify(b"hello ledgre", &signature),
            Err(LedgerError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let signature = ledger_key().sign(b"hello ledger");
        assert_eq!(
            other_ledger_key()
                .public()
                .verify(b"hello ledger", &signature),
            Err(LedgerError::InvalidSignature)
        );
    }

    #[test]
    fn operator_key_cannot_verify_a_ledger_signature() {
        let ledger = ledger_key();
        let operator = operator_key();
        let signature = ledger.sign(b"ledger entry");
        // Wrong key type entirely: an operator public key must not accept a
        // ledger signature.
        assert_eq!(
            operator.public().verify(b"ledger entry", &signature),
            Err(LedgerError::InvalidSignature)
        );
        // And the operator's own signature must not verify under the ledger.
        let operator_signature = operator.sign(b"ledger entry");
        assert_eq!(
            ledger.public().verify(b"ledger entry", &operator_signature),
            Err(LedgerError::InvalidSignature)
        );
    }

    #[test]
    fn key_bytes_round_trip() {
        let key = ledger_key();
        assert_eq!(
            LedgerSecretKey::from_bytes(key.to_bytes()).to_bytes(),
            key.to_bytes()
        );
        let public = key.public();
        assert_eq!(
            LedgerPubKey::from_bytes(&public.to_bytes()).unwrap(),
            public
        );

        let operator = operator_key();
        assert_eq!(
            OperatorSecretKey::from_bytes(operator.to_bytes()).to_bytes(),
            operator.to_bytes()
        );
    }

    #[test]
    fn signature_bytes_round_trip() {
        let signature = ledger_key().sign(b"x");
        assert_eq!(Signature::from_bytes(&signature.to_bytes()), signature);
        assert_eq!(signature.to_bytes().len(), Signature::LENGTH);
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        // Not every 32-byte string decompresses to a valid Edwards point;
        // find one deterministically and check it is rejected.
        let mut invalid = None;
        for first in 0u8..=255 {
            let mut bytes = [0u8; 32];
            bytes[0] = first;
            if LedgerPubKey::from_bytes(&bytes).is_err() {
                invalid = Some(bytes);
                break;
            }
        }
        let bytes = invalid.expect("some byte pattern must be an invalid Edwards encoding");
        assert_eq!(
            LedgerPubKey::from_bytes(&bytes),
            Err(LedgerError::InvalidKey)
        );
        assert_eq!(
            OperatorPubKey::from_bytes(&bytes),
            Err(LedgerError::InvalidKey)
        );
    }

    #[test]
    fn serde_round_trip() {
        let key = ledger_key();
        let public = key.public();
        let signature = key.sign(b"payload");

        let back: LedgerPubKey =
            postcard::from_bytes(&postcard::to_allocvec(&public).unwrap()).unwrap();
        assert_eq!(back, public);

        let back: OperatorPubKey =
            postcard::from_bytes(&postcard::to_allocvec(&operator_key().public()).unwrap())
                .unwrap();
        assert_eq!(back, operator_key().public());

        let back: LedgerSecretKey =
            postcard::from_bytes(&postcard::to_allocvec(&key).unwrap()).unwrap();
        assert_eq!(back.to_bytes(), key.to_bytes());

        let back: Signature =
            postcard::from_bytes(&postcard::to_allocvec(&signature).unwrap()).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        assert_eq!(format!("{:?}", ledger_key()), "LedgerSecretKey(..)");
    }
}
