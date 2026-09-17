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
///
/// v2: the `Equity` account and `EntryBody::Issue`/`Burn` equity legs were
/// removed (`Issue`/`Burn` are child-only boundary ops; equity is derived), and
/// the signed entry format advanced to
/// [`cawala_ledger::ENTRY_FORMAT_VERSION`] 3.
///
/// v3: `EntryBody::EdgeClose` was appended and the signed entry format advanced
/// to [`cawala_ledger::ENTRY_FORMAT_VERSION`] 4. Entry hashes/signatures changed,
/// so a v2 (or older) log cannot be replayed and must be recreated.
pub const LEDGER_FORMAT_VERSION: u32 = 3;

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

/// Name of the advisory ledger write lock file inside the ledger dir.
pub const LOCK_FILE: &str = ".lock";

/// Name of the process-instance lock file (not the ledger write lock).
pub const NODE_LOCK_FILE: &str = "node.lock";

/// An advisory file lock guarding the ledger.
///
/// # Writer discipline
///
/// [`FileLog`] has no internal mutual exclusion, so two processes that both
/// resync, build at the same `seq`, and append can interleave and publish a
/// divergent chain. [`LedgerService`](crate::ledger_service::LedgerService)
/// therefore takes an **exclusive** lock around each mutating transaction
/// (refresh + append) and a **shared** lock around each authoritative read.
/// Writer transactions across processes (a running node and operator CLI
/// commands) are serialized; a contended `try_lock` fails fast with a clear
/// message rather than waiting. The lock is released when the guard drops.
#[derive(Debug)]
pub struct LedgerLock {
    // Held only to keep the OS advisory lock alive; dropping releases it.
    _file: File,
}

impl LedgerLock {
    /// Acquire the exclusive (writer) ledger lock on
    /// `<data-dir>/ledger/.lock`, failing fast if any other process holds it in
    /// any mode.
    pub fn acquire_exclusive(data_dir: &Path) -> Result<Self> {
        Self::acquire_file(&ledger_dir(data_dir).join(LOCK_FILE), exclusive_message(data_dir), true)
    }

    /// Acquire a shared (reader) ledger lock on `<data-dir>/ledger/.lock`,
    /// failing fast if a writer currently holds the exclusive lock.
    pub fn acquire_shared(data_dir: &Path) -> Result<Self> {
        Self::acquire_file(&ledger_dir(data_dir).join(LOCK_FILE), exclusive_message(data_dir), false)
    }

    /// Acquire the process-instance lock on `<data-dir>/node.lock` exclusively.
    ///
    /// This only prevents two node processes from serving the same data dir; it
    /// is held for the process lifetime and is never taken by CLI commands, so
    /// operator commands can still run against a live node.
    pub fn acquire_process_instance(data_dir: &Path) -> Result<Self> {
        Self::acquire_file(
            &data_dir.join(NODE_LOCK_FILE),
            format!(
                "another cawala node is already running on data dir {}",
                data_dir.display()
            ),
            true,
        )
    }

    fn acquire_file(path: &Path, contention: String, exclusive: bool) -> Result<Self> {
        use std::fs::TryLockError;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        let locked = if exclusive {
            file.try_lock()
        } else {
            file.try_lock_shared()
        };
        match locked {
            Ok(()) => Ok(LedgerLock { _file: file }),
            Err(TryLockError::WouldBlock) => bail!("{contention}"),
            Err(TryLockError::Error(err)) => {
                Err(err).with_context(|| format!("failed to lock {}", path.display()))
            }
        }
    }
}

fn exclusive_message(data_dir: &Path) -> String {
    format!(
        "ledger data dir {} is locked by another cawala writer; retry once the \
         current transaction completes",
        data_dir.display()
    )
}

/// Load `<data-dir>/ledger/meta.json`, rejecting an unsupported format version.
pub fn load_meta(data_dir: &Path) -> Result<LedgerMeta> {
    let path = meta_path(data_dir);
    let bytes =
        std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let meta: LedgerMeta = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a valid ledger meta file", path.display()))?;
    if meta.format_version != LEDGER_FORMAT_VERSION {
        if meta.format_version < LEDGER_FORMAT_VERSION {
            // The on-disk format (including the signed entry format) changed, so
            // older frames cannot be replayed and the data dir must be recreated.
            bail!(
                "{}: unsupported ledger format version {} (expected {LEDGER_FORMAT_VERSION}); \
                 the on-disk ledger format changed, so recreate the data dir",
                path.display(),
                meta.format_version
            );
        }
        bail!(
            "{}: ledger format version {} is newer than this binary supports \
             (expected {LEDGER_FORMAT_VERSION}); upgrade the node or recreate the data dir",
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
/// Rootness is a **control-plane fact** (whether the node record currently has
/// a parent link), never a ledger property: the `Parent` account is universal,
/// so this replays a log with or without `Parent` postings identically. Attach
/// and detach therefore never brick the ledger.
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
    let mut ledger = Ledger::new_non_root_with_log(key.public(), log);
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
        let parsed = parse_frames(&path, &data)?;
        if parsed.complete_len < data.len() {
            // A torn final append left a partial frame after the last complete
            // one. Discard only that tail (the surviving prefix was already
            // validated frame-by-frame) so the log stays appendable and the
            // next frame lands on the correct boundary.
            tracing::warn!(
                path = %path.display(),
                complete_frames = parsed.entries.len(),
                discarded_bytes = data.len() - parsed.complete_len,
                "discarding trailing partial ledger frame from a torn append"
            );
            file.set_len(parsed.complete_len as u64)
                .with_context(|| format!("failed to truncate {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync {}", path.display()))?;
        }
        let cursor = if replay { 0 } else { parsed.entries.len() };
        Ok(FileLog {
            path,
            file,
            entries: parsed.entries,
            heads: parsed.heads,
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

/// The validated prefix of a frame log, plus the byte length of that prefix.
struct ParsedFrames {
    entries: Vec<SignedEntry>,
    heads: Vec<Hash>,
    /// Byte offset just past the last complete, validated frame. Any bytes at
    /// or after this offset are a torn final append.
    complete_len: usize,
}

/// Parse and validate the complete frames in `data`.
///
/// The truncation rule: frames are read sequentially. Parsing stops *without
/// error*, leaving [`ParsedFrames::complete_len`] at the last complete frame
/// boundary, only when the remaining bytes cannot form a full frame — fewer
/// than 4 bytes for the length prefix, or fewer body bytes than the declared
/// (and bounded) length. Both conditions require the frame to run past
/// end-of-file, so they can only describe a torn final append; the caller
/// truncates the tail. Every other problem is a hard error, even at
/// end-of-file: a length prefix above [`MAX_ENTRY_FRAME_SIZE`], a postcard
/// decode failure, a non-dense `seq`, or a `prev_hash` mismatch. Corrupt bytes
/// in the middle of the log are therefore never silently dropped.
///
/// Each decoded entry must have the next dense `seq` and a `prev_hash` matching
/// the running head, which also catches field tampering in any non-final frame.
fn parse_frames(path: &Path, data: &[u8]) -> Result<ParsedFrames> {
    let mut entries = Vec::new();
    let mut heads = vec![Hash::ZERO];
    let mut offset = 0usize;

    while offset < data.len() {
        if data.len() - offset < 4 {
            // Partial length prefix at end-of-file: a torn final append.
            break;
        }
        let len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        if len > MAX_ENTRY_FRAME_SIZE {
            bail!(
                "{}: frame length {len} exceeds max {MAX_ENTRY_FRAME_SIZE}",
                path.display()
            );
        }
        let len = len as usize;
        let body_start = offset + 4;
        if data.len() - body_start < len {
            // Declared body runs past end-of-file: a torn final append.
            break;
        }
        let entry: SignedEntry =
            postcard::from_bytes(&data[body_start..body_start + len]).with_context(|| {
                format!(
                    "{}: invalid signed entry frame at offset {body_start}",
                    path.display()
                )
            })?;
        offset = body_start + len;

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

    Ok(ParsedFrames {
        entries,
        heads,
        complete_len: offset,
    })
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
        AccountRef, Amount, AuthRef, Entry, EntryBody, HopRole, LedgerLog, LedgerSecretKey, NodeId,
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
                child: child(id),
                amount: Amount::new(amount),
            },
            postings: vec![Posting {
                account: AccountRef::Child(child(id)),
                delta: SignedAmount::new(amount as i64),
            }],
            auth: Some(auth(seq)),
        };
        SignedEntry::sign(entry, key).unwrap()
    }

    fn descend(key: &LedgerSecretKey, seq: u64, prev: Hash, id: &str, amount: u64) -> SignedEntry {
        let entry = Entry {
            ledger_id: key.public(),
            seq,
            height: seq,
            prev_hash: prev,
            issued_at: 100 + seq,
            body: EntryBody::Transfer {
                payment_id: Hash::ZERO,
                amount: Amount::new(amount),
                role: HopRole::Descend,
            },
            postings: vec![
                Posting {
                    account: AccountRef::Parent,
                    delta: SignedAmount::new(amount as i64),
                },
                Posting {
                    account: AccountRef::Child(child(id)),
                    delta: SignedAmount::new(amount as i64),
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
    fn load_meta_accepts_the_current_format_version() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        let meta = LedgerMeta {
            format_version: LEDGER_FORMAT_VERSION,
            node_id: NODE.to_string(),
            ledger_id: key.public(),
        };
        save_meta(dir.path(), &meta).unwrap();
        assert_eq!(load_meta(dir.path()).unwrap(), meta);
    }

    #[test]
    fn load_meta_rejects_older_format_with_a_version_generic_message() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        // Simulate a v2 meta written before `EdgeClose` (entry format 4).
        save_meta(
            dir.path(),
            &LedgerMeta {
                format_version: 2,
                node_id: NODE.to_string(),
                ledger_id: key.public(),
            },
        )
        .unwrap();

        let err = load_meta(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&format!(
                "unsupported ledger format version 2 (expected {LEDGER_FORMAT_VERSION})"
            )),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("the on-disk ledger format changed"),
            "the message must be version-generic, not cite a specific change: {msg}"
        );
        assert!(!msg.contains("Equity removed"), "stale message: {msg}");
        assert!(
            msg.contains("recreate the data dir"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn load_meta_rejects_a_newer_format_version() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        save_meta(
            dir.path(),
            &LedgerMeta {
                format_version: LEDGER_FORMAT_VERSION + 1,
                node_id: NODE.to_string(),
                ledger_id: key.public(),
            },
        )
        .unwrap();

        let err = load_meta(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("newer than this binary supports"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains(&format!("expected {LEDGER_FORMAT_VERSION}")),
            "unexpected error: {msg}"
        );
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
    fn replay_of_parent_postings_is_constructor_agnostic() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();

        // A history containing a `Parent` posting (a `Descend`).
        let (head, balances) = {
            let mut ledger = open_ledger(dir.path(), NODE, &key).unwrap();
            let opened = open_account(&key, 0, Hash::ZERO, "a");
            let head0 = entry_hash(&opened.entry).unwrap();
            ledger.append(opened).unwrap();
            let descended = descend(&key, 1, head0, "a", 100);
            ledger.append(descended).unwrap();
            (ledger.head_hash(), ledger.balances().clone())
        };

        // Reopening replays it identically: rootness is not a ledger property,
        // so no attachment state can make this fail (both ledger constructors
        // are aliases; see `cawala_ledger::log::Ledger`).
        let reopened = open_ledger(dir.path(), NODE, &key).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.head_hash(), head);
        assert_eq!(reopened.balances(), &balances);
        assert_eq!(
            reopened.balances().parent_balance(),
            Some(Amount::new(100))
        );
        assert_eq!(
            reopened.balances().child_balance(&child("a")),
            Amount::new(100)
        );
    }

    #[test]
    fn truncated_tail_frame_is_discarded_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        let _ = build_two_entry_ledger(dir.path(), &key);

        let path = entries_path(dir.path());
        let bytes = std::fs::read(&path).unwrap();
        // Drop the last two bytes of the final frame: a torn final append.
        std::fs::write(&path, &bytes[..bytes.len() - 2]).unwrap();

        // Only the incomplete final frame is discarded; the first stays valid.
        let log = FileLog::open(dir.path()).unwrap();
        assert_eq!(log.entry_count(), 1);
        assert_eq!(log.len(), 1);
        drop(log);

        // The file was truncated back to the last complete frame boundary.
        let frame0_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let after = std::fs::read(&path).unwrap();
        assert_eq!(after.len(), 4 + frame0_len);

        // Replay of the surviving prefix succeeds.
        let reopened = open_ledger(dir.path(), NODE, &key).unwrap();
        assert_eq!(reopened.len(), 1);
    }

    /// Append `n` valid entries (distinct accounts) to a fresh log and return
    /// them with the final head hash.
    fn build_n_entry_ledger(
        data_dir: &Path,
        key: &LedgerSecretKey,
        n: u64,
    ) -> (Vec<SignedEntry>, Hash) {
        let mut ledger = open_ledger(data_dir, NODE, key).unwrap();
        let mut prev = Hash::ZERO;
        let mut entries = Vec::new();
        for i in 0..n {
            let entry = open_account(key, i, prev, &format!("c{i}"));
            prev = entry_hash(&entry.entry).unwrap();
            ledger.append(entry.clone()).unwrap();
            entries.push(entry);
        }
        (entries, prev)
    }

    #[test]
    fn torn_tail_body_is_discarded_and_append_is_dense() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        let (_, prev) = build_n_entry_ledger(dir.path(), &key, 3);

        let path = entries_path(dir.path());
        let complete = std::fs::read(&path).unwrap();
        // Torn final append: a full 4-byte length prefix claiming 16 body bytes,
        // but only 3 body bytes reached the disk.
        let mut torn = complete.clone();
        torn.extend_from_slice(&16u32.to_le_bytes());
        torn.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        std::fs::write(&path, &torn).unwrap();

        let mut log = FileLog::open(dir.path()).unwrap();
        assert_eq!(log.entry_count(), 3);
        // The partial tail was truncated back to the last complete frame.
        assert_eq!(
            std::fs::metadata(&path).unwrap().len() as usize,
            complete.len()
        );

        // The next append continues the dense sequence at the correct offset.
        let next = open_account(&key, 3, prev, "c3");
        log.append(next).unwrap();
        assert_eq!(log.len(), 4);
        assert_eq!(log.entry_count(), 4);
        drop(log);

        // A fresh open sees exactly the four dense frames, and replay succeeds.
        let reopened = FileLog::open(dir.path()).unwrap();
        assert_eq!(reopened.entry_count(), 4);
        drop(reopened);
        let replayed = open_ledger(dir.path(), NODE, &key).unwrap();
        assert_eq!(replayed.len(), 4);
    }

    #[test]
    fn torn_tail_prefix_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        let _ = build_n_entry_ledger(dir.path(), &key, 2);

        let path = entries_path(dir.path());
        let complete = std::fs::read(&path).unwrap();
        // Only 2 of the 4 length-prefix bytes of the next frame were written.
        let mut torn = complete.clone();
        torn.extend_from_slice(&[0x01, 0x02]);
        std::fs::write(&path, &torn).unwrap();

        let log = FileLog::open(dir.path()).unwrap();
        assert_eq!(log.entry_count(), 2);
        assert_eq!(log.len(), 2);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len() as usize,
            complete.len()
        );
    }

    #[test]
    fn corrupt_middle_frame_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key();
        let (entries, _) = build_n_entry_ledger(dir.path(), &key, 3);

        // Corrupt the *middle* frame's length prefix to a small, bounded value
        // that is still followed by more bytes. That must not be mistaken for a
        // torn tail: the frame is indistinguishable from full-length garbage.
        let mut bytes = encode_frames(&entries);
        let frame0_len = {
            let body = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
            4 + body
        };
        bytes[frame0_len..frame0_len + 4].copy_from_slice(&1u32.to_le_bytes());
        std::fs::write(entries_path(dir.path()), &bytes).unwrap();

        let err = FileLog::open(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("invalid signed entry frame"),
            "unexpected error: {err}"
        );
        assert!(
            !err.to_string().contains("truncated"),
            "middle corruption must not be classified as truncation: {err}"
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

    #[test]
    fn ledger_lock_is_exclusive_then_shared_after_release() {
        let dir = tempfile::tempdir().unwrap();
        let first = LedgerLock::acquire_exclusive(dir.path()).unwrap();

        // A second exclusive acquisition fails while the first is held.
        let err = LedgerLock::acquire_exclusive(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("locked by another cawala writer"),
            "unexpected error: {err}"
        );
        // A shared read lock also fails while the writer holds the lock.
        assert!(LedgerLock::acquire_shared(dir.path()).is_err());

        drop(first);

        // After release, exclusive and repeated shared acquisitions succeed.
        let exclusive = LedgerLock::acquire_exclusive(dir.path()).unwrap();
        drop(exclusive);
        let shared_a = LedgerLock::acquire_shared(dir.path()).unwrap();
        let shared_b = LedgerLock::acquire_shared(dir.path()).unwrap();
        drop(shared_a);
        drop(shared_b);
    }

    #[test]
    fn process_instance_lock_is_separate_from_the_ledger_write_lock() {
        let dir = tempfile::tempdir().unwrap();
        let instance = LedgerLock::acquire_process_instance(dir.path()).unwrap();

        // A second instance lock fails, but the ledger write lock is still free.
        assert!(LedgerLock::acquire_process_instance(dir.path()).is_err());
        let write = LedgerLock::acquire_exclusive(dir.path()).unwrap();
        drop(write);

        drop(instance);
        let again = LedgerLock::acquire_process_instance(dir.path()).unwrap();
        drop(again);
    }
}
