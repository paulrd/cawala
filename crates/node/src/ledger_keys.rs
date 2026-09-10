//! Ledger key persistence: the node's [`LedgerSecretKey`], persisted as raw
//! 32 bytes at `<data-dir>/ledger_key`.
//!
//! The ledger key is deliberately distinct from the operator key stored at
//! `<data-dir>/secret_key` (see [`crate::identity`]): the operator key
//! authorises control-plane actions, the ledger key signs ledger entries and
//! commitments. Both are raw 32-byte Ed25519 secrets written with the same
//! temp-file + rename convention.

use std::path::Path;

use anyhow::{Context, Result};
use cawala_ledger::LedgerSecretKey;
use iroh::SecretKey;

/// Name of the ledger key file inside the data dir.
pub const LEDGER_KEY_FILE: &str = "ledger_key";

/// Expected size of a serialized ledger key in bytes.
pub const LEDGER_KEY_LEN: usize = 32;

/// Load the persisted ledger key, or generate and persist a new one.
///
/// Creates `<data-dir>` on demand. The key file holds the raw 32 key bytes.
pub fn load_or_create_ledger_key(data_dir: &Path) -> Result<LedgerSecretKey> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let path = data_dir.join(LEDGER_KEY_FILE);
    if path.exists() {
        let bytes =
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let arr: [u8; LEDGER_KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "ledger key file must contain exactly {LEDGER_KEY_LEN} bytes, found {}",
                bytes.len()
            )
        })?;
        Ok(LedgerSecretKey::from_bytes(arr))
    } else {
        // iroh's `SecretKey::generate` is the RNG source for the node; the pure
        // ledger crate never generates randomness itself.
        let key = LedgerSecretKey::from_bytes(SecretKey::generate().to_bytes());
        persist_ledger_key(data_dir, &key)?;
        Ok(key)
    }
}

/// Persist `key` to `<data-dir>/ledger_key`, replacing any existing file.
pub fn persist_ledger_key(data_dir: &Path, key: &LedgerSecretKey) -> Result<()> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let path = data_dir.join(LEDGER_KEY_FILE);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, key.to_bytes())
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_ledger_key(dir.path()).unwrap();
        let key_again = load_or_create_ledger_key(dir.path()).unwrap();
        assert_eq!(key.to_bytes(), key_again.to_bytes());
        assert_eq!(key.public(), key_again.public());
        // The file exists with exactly the raw 32 bytes.
        let bytes = std::fs::read(dir.path().join(LEDGER_KEY_FILE)).unwrap();
        assert_eq!(bytes.len(), LEDGER_KEY_LEN);
        assert_eq!(bytes, key.to_bytes());
    }

    #[test]
    fn distinct_from_operator_secret_key() {
        let dir = tempfile::tempdir().unwrap();
        let operator = identity::load_or_create_secret_key(dir.path()).unwrap();
        let ledger = load_or_create_ledger_key(dir.path()).unwrap();
        assert_ne!(operator.to_bytes(), ledger.to_bytes());
        // Both files coexist in the same data dir.
        assert!(dir.path().join(LEDGER_KEY_FILE).exists());
        assert!(dir.path().join(identity::SECRET_KEY_FILE).exists());
    }

    #[test]
    fn wrong_length_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LEDGER_KEY_FILE), vec![1u8, 2, 3]).unwrap();
        let err = load_or_create_ledger_key(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("exactly 32 bytes"),
            "unexpected error: {err}"
        );
    }
}
