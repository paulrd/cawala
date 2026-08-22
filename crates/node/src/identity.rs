//! Identity persistence: the node's iroh [`SecretKey`], persisted as raw
//! 32 bytes at `<data-dir>/secret_key`.
//!
//! A stable key means a stable [`iroh::EndpointId`] across restarts. Only the
//! key material is persisted here — derived addresses are never stored (see
//! [`crate::record`]).

use std::path::Path;

use anyhow::{Context, Result};
use iroh::SecretKey;

/// Name of the secret key file inside the data dir.
pub const SECRET_KEY_FILE: &str = "secret_key";

/// Expected size of a serialized iroh [`SecretKey`] in bytes.
pub const SECRET_KEY_LEN: usize = 32;

/// Load the persisted secret key, or generate and persist a new one.
///
/// Creates `<data-dir>` on demand. The key file holds the raw 32 key bytes.
pub fn load_or_create_secret_key(data_dir: &Path) -> Result<SecretKey> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let path = data_dir.join(SECRET_KEY_FILE);
    if path.exists() {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let arr: [u8; SECRET_KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "secret key file must contain exactly {SECRET_KEY_LEN} bytes, found {}",
                bytes.len()
            )
        })?;
        Ok(SecretKey::from_bytes(&arr))
    } else {
        let key = SecretKey::generate();
        persist_secret_key(data_dir, &key)?;
        Ok(key)
    }
}

/// Persist `key` to `<data-dir>/secret_key`, replacing any existing file.
pub fn persist_secret_key(data_dir: &Path, key: &SecretKey) -> Result<()> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let path = data_dir.join(SECRET_KEY_FILE);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, key.to_bytes())
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_secret_key(dir.path()).unwrap();
        let key_again = load_or_create_secret_key(dir.path()).unwrap();
        // Same key material on the second load.
        assert_eq!(key.to_bytes(), key_again.to_bytes());
        assert_eq!(key.public(), key_again.public());
        // The file exists with exactly the raw 32 bytes.
        let bytes = std::fs::read(dir.path().join(SECRET_KEY_FILE)).unwrap();
        assert_eq!(bytes.len(), SECRET_KEY_LEN);
        assert_eq!(bytes, key.to_bytes());
    }

    #[test]
    fn generated_keys_are_unique() {
        let dir = tempfile::tempdir().unwrap();
        let k1 = load_or_create_secret_key(dir.path()).unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let k2 = load_or_create_secret_key(dir2.path()).unwrap();
        assert_ne!(k1.to_bytes(), k2.to_bytes());
    }

    #[test]
    fn corrupt_key_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SECRET_KEY_FILE), vec![1u8, 2, 3]).unwrap();
        assert!(load_or_create_secret_key(dir.path()).is_err());
    }
}
