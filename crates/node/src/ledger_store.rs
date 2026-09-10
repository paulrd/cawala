//! Filesystem-backed ledger log.
//!
//! Persistence layout:
//!
//! ```text
//! <data-dir>/ledger/entries.log   append-only, u32-LE length-prefixed
//!                                 postcard-encoded `SignedEntry` frames
//! <data-dir>/ledger/meta.json     format_version, node_id, ledger_id
//! ```
//!
//! The framing mirrors `proto`: a `u32` little-endian byte length followed by
//! the postcard payload. Frames are flushed and `sync_all`-ed on every append.
//!
//! [`FileLog`] implements [`cawala_ledger::LedgerLog`] so the pure ledger state
//! machine ([`Ledger`]) can run against the disk. On open the existing frames
//! are replayed to rebuild the entry cache, rolling head hash, and (through
//! [`Ledger::append`]) the account balances — balances are always re-derived
//! from the signed history, never read from a cached balance file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use cawala_ledger::{
    Hash, Ledger, LedgerLog, LedgerPubKey, LedgerSecretKey, SignedEntry, entry_hash,
};
use serde::{Deserialize, Serialize};

/// Directory (inside the data dir) holding all ledger persistence.
pub const LEDGER_DIR: &str = "ledger";

/// Name of the append-only frame log.
pub const ENTRIES_FILE: &str = "entries.log";

/// Name of the ledger metadata file.
pub const META_FILE: &str = "meta.json";

/// On-disk ledger format version.
pub const LEDGER_FORMAT_VERSION: u32 = 1;

/// Maximum accepted encoded frame size in bytes, mirroring `proto`'s bound.
pub const MAX_ENTRY_FRAME_SIZE: u32 = proto::MAX_FRAME_SIZE;

/// Metadata persisted alongside the frame log.
///
/// `node_id` and `ledger_id` bind the log to the node that owns it, so a log
/// cannot be silently replayed under the wrong identity or ledger key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerMeta {
    /// On-disk format version (see [`LEDGER_FORMAT_VERSION`]).
    pub format_version: u32,
    /// The owning node's operator id.
    pub node_id: String,
    /// The owning node's ledger public key.
    pub ledger_id: LedgerPubKey,
}

/// The ledger subdirectory for `data_dir`.
pub fn ledger_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(LEDGER_DIR)
}

/// Path of the frame log for `data_dir`.
pub fn entries_path(data_dir: &Path) -> PathBuf {
    ledger_dir(data_dir).join(ENTRIES_FILE)
}

/// Path of the metadata file for `data_dir`.
pub fn meta_path(data_dir: &Path) -> PathBuf {
    ledger_dir(data_dir).join(META_FILE)
}

/// Load `<data-dir>/ledger/meta.json`, rejecting an unsupported format version.
pub fn load_meta(data_dir: &Path) -> Result<LedgerMeta> {
    let path = meta_path(data_dir);
    let bytes =
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let meta: LedgerMeta = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid ledger meta file", path.display()))?;
    if meta.format_version != LEDGER_FORMAT_VERSION {
        bail!(
            "{}: unsupported ledger format version {} (expected {LEDGER_FORMAT_VERSION})",
            path.display(),
            meta.format_version
        );
    }
    Ok(meta)
}

/// Persist `meta` to `<data-dir>/ledger/meta.json` (pretty JSON, tmp+rename).
pub fn save_meta(data_dir: &Path, meta: &LedgerMeta) -> Result<()> {
    let dir = ledger_dir(data_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create ledger dir {}", dir.display()))?;
    let path = dir.join(META_FILE);
    let json = serde_json::to_string_pretty(meta)
        .with_context(|| format!("failed to encode {}", path.display()))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json).with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Load the metadata, or create and persist it if absent.
pub fn load_or_create_meta(
    data_dir: &Path,
    node_id: &str,
    ledger_id: &LedgerPubKey,
) -> Result<LedgerMeta> {
    if meta_path(data_dir).exists() {
        return load_meta(data_dir);
    }
    let meta = LedgerMeta {
        format_version: LEDGER_FORMAT_VERSION,
        node_id: node_id.to_string(),
        ledger_id: *ledger_id,
    };
    save_meta(data_dir, &meta)?;
    Ok(meta)
}

/// Create the full ledger layout (meta + empty frame log) if absent
/// (idempotent).
pub fn init_ledger(data_dir: &Path, node_id: &str, ledger_id: &LedgerPubKey) -> Result<LedgerMeta> {
    let meta = load_or_create_meta(data_dir, node_id, ledger_id)?;
    // Create the frame log eagerly so `ledger init` produces the whole layout.
    let _log = FileLog::open(data_dir)?;
    Ok(meta)
}

/// Open the on-disk ledger for `node_id`, re-deriving balances from the signed
/// history.
///
/// The frame log is replayed through [`Ledger::append`], which re-verifies each
/// entry's ledger signature, dense sequence, `prev_hash` chain, conservation,
/// and non-negativity. A corrupt or tampered log therefore fails here rather
/// than silently producing different balances.
pub fn open_ledger(
    data_dir: &Path,
    node_id: &str,
    key: &LedgerSecretKey,
) -> Result<Ledger<FileLog>> {
    let meta = load_or_create_meta(data_dir, node_id, &key.public())?;
    if meta.node_id != node_id {
        bail!(
            "ledger meta node id '{}' does not match '{}'",
            meta.node_id,
            node_id
        );
    }
    if meta.ledger_id != key.public() {
        bail!("ledger key does not match the ledger id recorded in meta.json");
    }

    let log = FileLog::open_for_replay(data_dir)?;
    let persisted = log.entry_count();
    let mut ledger = Ledger::new_root_with_log(key.public(), log);
    for index in 0..persisted {
        let entry = ledger
            .get(index)?
            .ok_or_else(|| anyhow::anyhow!("ledger log entry {index} missing during replay"))?;
        ledger.append(entry)?;
    }
    Ok(ledger)
}

/// An append-only [`LedgerLog`] backed by `<data-dir>/ledger/entries.log`.
///
/// Entries are cached in memory on open (the file is re-read in full), which
/// keeps [`LedgerLog::get`] allocation-only and lets [`LedgerLog::head_hash`]
/// stay total. The rolling head and per-index hashes are cached so replay and
/// `head_hash` never re-read the disk.
#[derive(Debug)]
pub struct FileLog {
    path: PathBuf,
    file: File,
    entries: Vec<SignedEntry>,
    /// `heads[i]` is the head after `i` entries; `heads[0] == Hash::ZERO`.
    heads: Vec<Hash>,
    /// Number of entries visible to the [`Ledger`] through this log.
    ///
    /// A normal open starts at `entries.len()`; a replay open starts at `0` and
    /// advances as persisted entries are replayed, so [`Ledger::append`] sees
    /// the dense sequence it expects without rewriting the file.
    cursor: usize,
}

impl FileLog {
    /// Open (creating if needed) the frame log, validating and caching every
    /// persisted frame. The returned log is ready to append at the end.
    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::open_with(data_dir, false)
    }

    /// Open the frame log in replay mode: the validated entries are cached but
    /// the log's visible length starts at zero, so replaying them through
    /// [`Ledger::append`] rebuilds state without appending duplicate frames.
    fn open_for_replay(data_dir: &Path) -> Result<Self> {
        Self::open_with(data_dir, true)
    }

    fn open_with(data_dir: &Path, replay: bool) -> Result<Self> {
        let dir = ledger_dir(data_dir);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create ledger dir {}", dir.display()))?;
        let path = dir.join(ENTRIES_FILE);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        let data =
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let (entries, heads) = parse_frames(&path, &data)?;
        let cursor = if replay { 0 } else { entries.len() };
        Ok(FileLog {
            path,
            file,
            entries,
            heads,
            cursor,
        })
    }

    /// Path of the backing frame log.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of frames persisted on disk (not the replay cursor).
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Parse and validate every frame in `data`.
///
/// A partial length prefix or body is reported as a truncation error (never
/// silently ignored). Each decoded entry must have the next dense `seq` and a
/// `prev_hash` matching the running head, which also catches field tampering in
/// any non-final frame.
fn parse_frames(path: &Path, data: &[u8]) -> Result<(Vec<SignedEntry>, Vec<Hash>)> {
    let mut entries = Vec::new();
    let mut heads = vec![Hash::ZERO];
    let mut offset = 0usize;

    while offset < data.len() {
        if data.len() - offset < 4 {
            bail!(
                "{}: truncated frame length prefix at offset {offset}",
                path.display()
            );
        }
        let len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        if len > MAX_ENTRY_FRAME_SIZE {
            bail!(
                "{}: frame length {len} exceeds max {MAX_ENTRY_FRAME_SIZE}",
                path.display()
            );
        }
        let len = len as usize;
        if data.len() - offset < len {
            bail!(
                "{}: truncated frame body at offset {offset} (need {len} bytes, have {})",
                path.display(),
                data.len() - offset
            );
        }
        let entry: SignedEntry =
            postcard::from_bytes(&data[offset..offset + len]).with_context(|| {
                format!(
                    "{}: invalid signed entry frame at offset {offset}",
                    path.display()
                )
            })?;
        offset += len;

        let expected_seq = entries.len() as u64;
        if entry.entry.seq != expected_seq {
            bail!(
                "{}: entry sequence out of order: expected {expected_seq}, found {}",
                path.display(),
                entry.entry.seq
            );
        }
        let expected_prev = *heads.last().expect("heads starts with the zero hash");
        if entry.entry.prev_hash != expected_prev {
            bail!(
                "{}: entry {expected_seq} prev_hash mismatch: expected {expected_prev}, found {}",
                path.display(),
                entry.entry.prev_hash
            );
        }
        let head = entry_hash(&entry.entry).with_context(|| {
            format!(
                "{}: entry {expected_seq} could not be hashed",
                path.display()
            )
        })?;
        heads.push(head);
        entries.push(entry);
    }

    Ok((entries, heads))
}

impl LedgerLog for FileLog {
    fn append(&mut self, entry: SignedEntry) -> Result<(), cawala_ledger::LedgerError> {
        let seq = entry.entry.seq as usize;

        // Replay of the persisted prefix: never writes, only advances the
        // cursor once the entry is confirmed against the hash we cached on open.
        if self.cursor < self.entries.len() {
            if seq != self.cursor {
                return Err(cawala_ledger::LedgerError::SeqOutOfOrder {
                    expected: self.cursor as u64,
                    found: entry.entry.seq,
                });
            }
            let expected = self.heads[self.cursor + 1];
            let actual = entry_hash(&entry.entry)?;
            if actual != expected {
                return Err(cawala_ledger::LedgerError::Encode(format!(
                    "replayed entry {seq} does not match the persisted log"
                )));
            }
            self.cursor += 1;
            return Ok(());
        }

        if seq != self.entries.len() {
            return Err(cawala_ledger::LedgerError::SeqOutOfOrder {
                expected: self.entries.len() as u64,
                found: entry.entry.seq,
            });
        }

        let frame = postcard::to_allocvec(&entry)
            .map_err(|err| cawala_ledger::LedgerError::Encode(err.to_string()))?;
        if frame.len() > MAX_ENTRY_FRAME_SIZE as usize {
            return Err(cawala_ledger::LedgerError::Encode(format!(
                "frame length {} exceeds max {MAX_ENTRY_FRAME_SIZE}",
                frame.len()
            )));
        }
        let io_err = |err: std::io::Error| {
            cawala_ledger::LedgerError::Encode(format!("ledger log i/o error: {err}"))
        };
        self.file
            .write_all(&(frame.len() as u32).to_le_bytes())
            .map_err(io_err)?;
        self.file.write_all(&frame).map_err(io_err)?;
        self.file.flush().map_err(io_err)?;
        self.file.sync_all().map_err(io_err)?;

        let head = entry_hash(&entry.entry)?;
        self.entries.push(entry);
        self.heads.push(head);
        self.cursor = self.entries.len();
        Ok(())
    }

    fn len(&self) -> usize {
        self.cursor
    }

    fn get(&self, index: usize) -> Result<Option<SignedEntry>, cawala_ledger::LedgerError> {
        Ok(self.entries.get(index).cloned())
    }

    fn head_hash(&self) -> Hash {
        self.heads[self.cursor]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::{
        AccountRef, Amount, AuthRef, Entry, EntryBody, LedgerLog, LedgerSecretKey, NodeId,
        OperatorSecretKey, Posting, SignedAmount,
    };

    const NODE: &str = "node-a";

    fn ledger_key() -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([7u8; 32])
    }

    fn child(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn auth(seq: u64) -> AuthRef {
        let operator = OperatorSecretKey::from_bytes([6u8; 32]);
        AuthRef {
            operator: operator.public(),
            nonce: seq,
            order_hash: Hash::ZERO,
            signature: operator.sign(b"order"),
        }
    }

    fn open_account(key: &LedgerSecretKey, seq: u64, prev: Hash, id: &str) -> SignedEntry {
        let entry = Entry {
            ledger_id: key.public(),
            seq,
            height: seq,
            prev_hash: prev,
            issued_at: 100 + seq,
            body: EntryBody::OpenAccount {
                child: child(id),
                kind: cawala_topology::ChildKind::Node,
            },
            postings: vec![],
            auth: None,
        };
        SignedEntry::sign(entry, key).unwrap()
    }

    fn issue(key: &LedgerSecretKey, seq: u64, prev: Hash, id: &str, amount: u64) -> SignedEntry {
        let entry = Entry {
            ledger_id: key.public(),
            seq,
            height: seq,
            prev_hash: prev,
            issued_at: 100 + seq,
            body: EntryBody::Issue {
                account: AccountRef::Child(child(id)),
                amount: Amount::new(amount),
            },
            postings: vec![
                Posting {
                    account: AccountRef::Child(child(id)),
                    delta: SignedAmount::new(amount as i64),
                },
                Posting {
                    account: AccountRef::Equity,
                    delta: SignedAmount::new(-(amount as i64)),
                },
            ],
            auth: Some(auth(seq)),
        };
        SignedEntry::sign(entry, key).unwrap()
    }

    fn encode_frames(entries: &[SignedEntry]) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in entries {
            let frame = postcard::to_allocvec(entry).unwrap();
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&frame);
        }
        out
    }

    /// Build a two-entry ledger (an account open, then a 100-unit issue).
    fn build_two_entry_ledger(data_dir: &Path, key: &LedgerSecretKey) -> Ledger<FileLog> {
        let mut ledger = open_ledger(data_dir, NODE, key).unwrap();
        let opened = open_account(key, 0, Hash::ZERO, "a");
        let head0 = entry_hash(&opened.entry).unwrap();
        ledger.append(opened).unwrap();
        let issued = issue(key, 1, head0, "a", 100);
        ledger.append(issued).unwrap();
        ledger
    }

    #[test]
    fn init_creates_meta_and_empty_log() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        let meta = init_ledger(dir.path(), NODE, &key.public()).unwrap();
        assert_eq!(meta.format_version, LEDGER_FORMAT_VERSION);
        assert_eq!(meta.node_id, NODE);
        assert_eq!(meta.ledger_id, key.public());
        assert!(meta_path(dir.path()).exists());
        assert!(entries_path(dir.path()).exists());

        let log = FileLog::open(dir.path()).unwrap();
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
        assert_eq!(log.head_hash(), Hash::ZERO);

        // Idempotent: a second init leaves the same metadata.
        let meta2 = init_ledger(dir.path(), NODE, &key.public()).unwrap();
        assert_eq!(meta, meta2);
    }

    #[test]
    fn append_reopen_roundtrip_preserves_entries_head_and_balances() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        let ledger = build_two_entry_ledger(dir.path(), &key);

        let head = ledger.head_hash();
        let balances = ledger.balances().clone();
        let entries: Vec<SignedEntry> = (0..ledger.len())
            .map(|index| ledger.get(index).unwrap().unwrap())
            .collect();
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.height(), 1);
        assert_eq!(
            ledger.balances().child_balance(&child("a")),
            Amount::new(100)
        );
        assert_eq!(ledger.balances().equity(), -100);
        drop(ledger);

        let reopened = open_ledger(dir.path(), NODE, &key).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.height(), 1);
        assert_eq!(reopened.head_hash(), head);
        assert_eq!(reopened.balances(), &balances);
        let reopened_entries: Vec<SignedEntry> = (0..reopened.len())
            .map(|index| reopened.get(index).unwrap().unwrap())
            .collect();
        assert_eq!(reopened_entries, entries);
        assert_eq!(
            reopened.balances().child_balance(&child("a")),
            Amount::new(100)
        );
        assert_eq!(reopened.balances().equity(), -100);
    }

    #[test]
    fn truncated_tail_frame_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        let _ = build_two_entry_ledger(dir.path(), &key);

        let path = entries_path(dir.path());
        let bytes = std::fs::read(&path).unwrap();
        // Drop the last two bytes of the final frame.
        std::fs::write(&path, &bytes[..bytes.len() - 2]).unwrap();

        let err = FileLog::open(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "unexpected error: {err}"
        );

        let err = open_ledger(dir.path(), NODE, &key).unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn tampered_entry_fails_verification_on_replay() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        let _ = build_two_entry_ledger(dir.path(), &key);

        // Read the persisted entries, tamper the final one without re-signing,
        // and rewrite the frame log.
        let log = FileLog::open(dir.path()).unwrap();
        let mut entries: Vec<SignedEntry> = (0..log.entry_count())
            .map(|index| log.get(index).unwrap().unwrap())
            .collect();
        assert_eq!(entries.len(), 2);
        entries[1].entry.issued_at += 1; // breaks the ledger signature
        std::fs::write(entries_path(dir.path()), encode_frames(&entries)).unwrap();

        // The raw log is structurally intact (dense seq + matching hash chain),
        // so `open` succeeds...
        let raw = FileLog::open(dir.path()).unwrap();
        assert_eq!(raw.entry_count(), 2);
        // ...but replaying through `Ledger::append` rejects the bad signature.
        let err = open_ledger(dir.path(), NODE, &key).unwrap_err();
        assert!(
            err.to_string().contains("invalid signature"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn wrong_ledger_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        let _ = build_two_entry_ledger(dir.path(), &key);

        let other = LedgerSecretKey::from_bytes([9u8; 32]);
        let err = open_ledger(dir.path(), NODE, &other).unwrap_err();
        assert!(
            err.to_string().contains("ledger id"),
            "unexpected error: {err}"
        );
    }
}
