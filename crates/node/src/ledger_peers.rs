//! Peer registry persistence: known peers' public identities and keys,
//! persisted as JSON at `<data-dir>/ledger_peers.json`.
//!
//! Only public data is stored (operator and ledger public keys). The registry
//! serializes as a JSON array of [`PeerKeys`]; deserialization re-validates key
//! uniqueness through [`PeerRegistry`]'s own serde impl (see the ledger crate).

use std::path::Path;

use anyhow::{Context, Result};
use cawala_ledger::PeerRegistry;

/// Name of the peer registry file inside the data dir.
pub const PEERS_FILE: &str = "ledger_peers.json";

/// Load the peer registry from `<data-dir>/ledger_peers.json`.
///
/// A missing file yields an empty registry; a present but malformed file is an
/// error (never silently ignored).
pub fn load_peers(data_dir: &Path) -> Result<PeerRegistry> {
    let path = data_dir.join(PEERS_FILE);
    if !path.exists() {
        return Ok(PeerRegistry::new());
    }
    let bytes =
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let registry: PeerRegistry = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid peer registry", path.display()))?;
    Ok(registry)
}

/// Persist `registry` to `<data-dir>/ledger_peers.json` (pretty JSON).
pub fn save_peers(data_dir: &Path, registry: &PeerRegistry) -> Result<()> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let path = data_dir.join(PEERS_FILE);
    let json = serde_json::to_string_pretty(registry)
        .with_context(|| format!("failed to encode {}", path.display()))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json).with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::{
        LedgerPubKey, LedgerSecretKey, NodeId, OperatorPubKey, OperatorSecretKey, PeerKeys,
        PeerRole,
    };

    fn operator(seed: u8) -> OperatorPubKey {
        OperatorSecretKey::from_bytes([seed; 32]).public()
    }

    fn ledger(seed: u8) -> LedgerPubKey {
        LedgerSecretKey::from_bytes([seed; 32]).public()
    }

    fn peer(id: &str, operator_seed: u8, ledger_seed: u8) -> PeerKeys {
        PeerKeys {
            node_id: NodeId::from(id),
            operator: operator(operator_seed),
            ledger: Some(ledger(ledger_seed)),
            role: PeerRole::Node,
        }
    }

    #[test]
    fn absent_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let registry = load_peers(dir.path()).unwrap();
        assert!(registry.is_empty());
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = PeerRegistry::new();
        registry.insert(peer("alice", 1, 11)).unwrap();
        registry
            .insert(PeerKeys {
                node_id: NodeId::from("u1"),
                operator: operator(2),
                ledger: None,
                role: PeerRole::User,
            })
            .unwrap();
        save_peers(dir.path(), &registry).unwrap();

        let path = dir.path().join(PEERS_FILE);
        assert!(path.exists());
        let loaded = load_peers(dir.path()).unwrap();
        assert_eq!(loaded, registry);
        assert_eq!(
            loaded.get(&NodeId::from("alice")),
            Some(&peer("alice", 1, 11))
        );
    }

    #[test]
    fn malformed_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PEERS_FILE), b"{ not json").unwrap();
        let err = load_peers(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("ledger_peers.json"),
            "unexpected error: {err}"
        );
    }
}
