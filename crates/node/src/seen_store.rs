//! Persisted sidecar for the control replay guard.
//!
//! [`SeenSet`](cawala_msg::SeenSet) is deliberately in-memory and
//! non-iterable: it has no timestamps, no seed API, and forgets under
//! eviction. The control engine needs its `(origin, nonce)` marks to survive a
//! restart, because control requests are terminal (a marked nonce is never
//! unobserved) and an expired frame can never be re-accepted (`receive_at`
//! rejects `now > signed.expiry` before consulting the guard).
//!
//! [`SeenStore`] therefore pairs a `SeenSet` with an ordered `VecDeque` of
//! [`SeenEntry`] rows (origin, message id, request expiry) that approximates
//! what the guard holds under the same [`SeenConfig`] caps. The approximation
//! is bounded, not exact: cross-origin eviction here is insertion-order LRU
//! while `SeenSet` uses `last_touch` LRU, and a duplicate re-observation
//! refreshes the guard's LRU *without* appending a sidecar row. Under cap
//! pressure (128 origins / 256 per origin) a still-valid mark held in memory
//! can therefore be absent from disk after a restart; it is simply re-marked on
//! next use, reopening at most the bounded retry window. It persists to
//! `<data-dir>/control_seen.json` with a temp file + `sync_all` + rename, so a
//! reader sees either the old or the new complete document (never a partial
//! one), and the mark survives a process restart before the engine dispatches.
//!
//! # Durability scope
//!
//! `sync_all` before the rename makes each mark durable across a process
//! restart. The parent directory is not fsynced, so power loss is best-effort —
//! the same idiom as `record::write_json_atomic`. Pruning is by the system
//! clock, so a backward wall-clock jump can prune a still-valid mark (the
//! in-memory `SeenSet` never prunes by time).
//!
//! # Fail open on load
//!
//! A missing, unreadable, unparseable, or wrong-version document starts an
//! **empty** guard with a warning: losing replay marks only reopens the
//! bounded window the node had before this store existed, whereas refusing to
//! open would brick the node.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::warn;

use cawala_msg::{MsgId, Seen, SeenConfig, SeenSet};

/// Name of the control replay sidecar inside the data dir.
pub const CONTROL_SEEN_FILE: &str = "control_seen.json";

/// On-disk format version for the control replay sidecar.
pub const CONTROL_SEEN_VERSION: u32 = 1;

/// The on-disk replay sidecar document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SeenDocument {
    /// [`CONTROL_SEEN_VERSION`].
    version: u32,
    /// Replay marks in insertion order, oldest first.
    entries: Vec<SeenEntry>,
}

/// One persisted replay mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenEntry {
    /// The replay key: `"{origin}:{controller}"`.
    pub origin: String,
    /// The message id the nonce was packed into.
    pub msg_id: MsgId,
    /// Unix-seconds expiry of the frame that produced the mark. A mark is
    /// prunable once `expiry < now`: its frame would be rejected as `Expired`
    /// before the guard, so it can never be replayed. Marks with
    /// `expiry >= now` are the still-valid ones and are retained and
    /// re-observed.
    pub expiry: u64,
}

/// A [`SeenSet`] plus an ordered, persisted sidecar of its entries.
#[derive(Debug)]
pub struct SeenStore {
    set: SeenSet,
    config: SeenConfig,
    entries: VecDeque<SeenEntry>,
}

impl SeenStore {
    /// An empty store with the given bounds.
    pub fn empty(config: SeenConfig) -> Self {
        SeenStore {
            set: SeenSet::new(config),
            config,
            entries: VecDeque::new(),
        }
    }

    /// Load the sidecar from `<data_dir>/control_seen.json`.
    ///
    /// A missing file is normal (empty guard). An unreadable, corrupt,
    /// unparseable, or wrong-version file logs a warning and yields an empty
    /// guard rather than failing. Retained entries are those with
    /// `expiry >= now`, capped to `config` in insertion order, then re-observed
    /// to rebuild the guard and re-seed the sidecar.
    pub fn open(data_dir: &Path, config: SeenConfig, now: u64) -> Self {
        let mut store = SeenStore::empty(config);
        let path = data_dir.join(CONTROL_SEEN_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return store,
            Err(err) => {
                warn!(
                    %err,
                    path = %path.display(),
                    "control replay sidecar is unreadable; starting with an empty replay guard"
                );
                return store;
            }
        };
        let document: SeenDocument = match serde_json::from_slice::<SeenDocument>(&bytes) {
            Ok(document) if document.version == CONTROL_SEEN_VERSION => document,
            Ok(document) => {
                warn!(
                    version = document.version,
                    "unsupported control replay sidecar version; starting with an empty replay guard"
                );
                return store;
            }
            Err(err) => {
                warn!(
                    %err,
                    path = %path.display(),
                    "control replay sidecar is corrupt; starting with an empty replay guard"
                );
                return store;
            }
        };

        let mut retained: VecDeque<SeenEntry> = document
            .entries
            .into_iter()
            .filter(|entry| entry.expiry >= now)
            .collect();
        enforce_caps(&mut retained, config);
        // Re-observing each retained pair rebuilds the guard *and* re-seeds the
        // sidecar (with the same order); the caps above guarantee nothing is
        // evicted during the rebuild.
        for entry in retained {
            store.observe(&entry.origin, entry.msg_id, entry.expiry);
        }
        store
    }

    /// Observe `(origin, msg_id)`.
    ///
    /// Delegates the guard decision to [`SeenSet::observe`] and records the
    /// mark in the sidecar on [`Seen::Fresh`]. The sidecar is capped with
    /// [`enforce_caps`], a bounded approximation of the guard's own eviction
    /// (see the module docs): it keeps memory from growing without bound, but
    /// may drop a mark the guard still holds.
    pub fn observe(&mut self, origin: &str, msg_id: MsgId, expiry: u64) -> Seen {
        let seen = self.set.observe(origin, msg_id);
        if seen == Seen::Fresh {
            self.entries.push_back(SeenEntry {
                origin: origin.to_string(),
                msg_id,
                expiry,
            });
            enforce_caps(&mut self.entries, self.config);
        }
        seen
    }

    /// Persist the sidecar to `<data-dir>/control_seen.json`.
    ///
    /// Entries with `expiry < now` are dropped (an expired frame can never be
    /// accepted again), the `config` caps are applied as a bounded
    /// approximation of the guard's eviction (see the module docs), and the
    /// document is written with a temp file + `sync_all` + rename. The rename
    /// makes the content durable across a process restart; the parent directory
    /// is not fsynced, so power loss is best-effort (mirrors
    /// `record::write_json_atomic`).
    pub fn save(&self, data_dir: &Path, now: u64) -> io::Result<()> {
        let mut retained: VecDeque<SeenEntry> = self
            .entries
            .iter()
            .filter(|entry| entry.expiry >= now)
            .cloned()
            .collect();
        enforce_caps(&mut retained, self.config);
        let document = SeenDocument {
            version: CONTROL_SEEN_VERSION,
            entries: retained.into_iter().collect(),
        };
        let path = data_dir.join(CONTROL_SEEN_FILE);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&document)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        write_json_atomic(&path, &json)
    }

    /// Number of sidecar entries currently held (all unexpired-ish marks).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the sidecar holds no marks.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Apply the [`SeenConfig`] bounds to `entries`, preserving insertion order.
///
/// Approximates [`SeenSet`]'s eviction: at most `max_per_origin` newest entries
/// per origin (per-origin FIFO, exact), and at most `max_origins` origins
/// chosen by their most recent appearance (insertion-order LRU, whereas
/// `SeenSet` evicts by `last_touch`, which duplicate observations also
/// refresh). A zero bound means "track nothing", so all entries are dropped.
fn enforce_caps(entries: &mut VecDeque<SeenEntry>, config: SeenConfig) {
    if config.max_origins == 0 || config.max_per_origin == 0 {
        entries.clear();
        return;
    }

    // Cross-origin LRU: walk from the newest end, keeping the first
    // `max_origins` distinct origins seen and dropping every earlier entry of
    // an origin that fell out.
    let mut keep = vec![false; entries.len()];
    {
        let mut kept_origins: HashSet<&str> = HashSet::new();
        for (index, entry) in entries.iter().enumerate().rev() {
            let origin = entry.origin.as_str();
            if kept_origins.contains(origin) {
                keep[index] = true;
            } else if kept_origins.len() < config.max_origins {
                kept_origins.insert(origin);
                keep[index] = true;
            }
        }
    }

    // Per-origin FIFO: within the surviving origins, keep only the newest
    // `max_per_origin` entries of each.
    {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (index, entry) in entries.iter().enumerate().rev() {
            if !keep[index] {
                continue;
            }
            let count = counts.entry(entry.origin.as_str()).or_insert(0);
            if *count >= config.max_per_origin {
                keep[index] = false;
            } else {
                *count += 1;
            }
        }
    }

    let mut index = 0;
    entries.retain(|_| {
        let keep = keep[index];
        index += 1;
        keep
    });
}

/// Write `json` to `path` atomically and durably: a sibling temp file that is
/// fsynced before the rename (mirrors `record::write_json_atomic`).
fn write_json_atomic(path: &Path, json: &str) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
    }
    // Preserve any existing file permissions across the rename (best effort).
    if let Ok(metadata) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, metadata.permissions());
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: SeenConfig = SeenConfig {
        max_per_origin: 4,
        max_origins: 4,
    };

    fn id(byte: u8) -> MsgId {
        MsgId::from_bytes([byte; 16])
    }

    #[test]
    fn absent_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = SeenStore::open(dir.path(), CONFIG, 100);
        assert!(store.is_empty());
    }

    #[test]
    fn fresh_then_duplicate_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SeenStore::empty(CONFIG);
        assert_eq!(store.observe("node-a:op", id(1), 1_000), Seen::Fresh);
        assert_eq!(store.observe("node-a:op", id(1), 1_000), Seen::Duplicate);
        assert_eq!(store.len(), 1);
        store.save(dir.path(), 100).unwrap();

        let mut reopened = SeenStore::open(dir.path(), CONFIG, 100);
        assert_eq!(reopened.observe("node-a:op", id(1), 1_000), Seen::Duplicate);
        assert_eq!(reopened.observe("node-a:op", id(2), 1_000), Seen::Fresh);
    }

    #[test]
    fn expired_entries_are_pruned_on_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SeenStore::empty(CONFIG);
        store.observe("node-a:op", id(1), 50);
        store.observe("node-a:op", id(2), 5_000);

        // Saving after the first entry's expiry drops it from disk.
        store.save(dir.path(), 100).unwrap();
        let raw: SeenDocument =
            serde_json::from_slice(&std::fs::read(dir.path().join(CONTROL_SEEN_FILE)).unwrap())
                .unwrap();
        assert_eq!(raw.entries.len(), 1);
        assert_eq!(raw.entries[0].msg_id, id(2));

        // Loading past the second entry's expiry prunes it in memory: the mark
        // does not resurrect.
        let mut reopened = SeenStore::open(dir.path(), CONFIG, 10_000);
        assert!(reopened.is_empty());
        assert_eq!(reopened.observe("node-a:op", id(2), 20_000), Seen::Fresh);
    }

    #[test]
    fn corrupt_file_yields_empty_guard_without_erroring() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CONTROL_SEEN_FILE), b"{ not json").unwrap();
        let mut store = SeenStore::open(dir.path(), CONFIG, 100);
        assert!(store.is_empty());
        assert_eq!(store.observe("node-a:op", id(1), 1_000), Seen::Fresh);
    }

    #[test]
    fn unsupported_version_yields_empty_guard() {
        let dir = tempfile::tempdir().unwrap();
        let document = serde_json::json!({
            "version": CONTROL_SEEN_VERSION + 1,
            "entries": [],
        });
        std::fs::write(
            dir.path().join(CONTROL_SEEN_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let mut store = SeenStore::open(dir.path(), CONFIG, 100);
        assert!(store.is_empty());
        assert_eq!(store.observe("node-a:op", id(1), 1_000), Seen::Fresh);
    }

    #[test]
    fn caps_bound_the_persisted_file() {
        let config = SeenConfig {
            max_per_origin: 2,
            max_origins: 2,
        };
        let dir = tempfile::tempdir().unwrap();
        let mut store = SeenStore::empty(config);
        for origin in 0..3u8 {
            for byte in 0..3u8 {
                store.observe(&format!("origin-{origin}"), id(byte), 1_000);
            }
        }
        store.save(dir.path(), 0).unwrap();

        let raw: SeenDocument =
            serde_json::from_slice(&std::fs::read(dir.path().join(CONTROL_SEEN_FILE)).unwrap())
                .unwrap();
        assert!(
            raw.entries.len() <= config.max_per_origin * config.max_origins,
            "the persisted file must be capped: {} entries",
            raw.entries.len()
        );
        let mut per_origin: HashMap<&str, usize> = HashMap::new();
        for entry in &raw.entries {
            *per_origin.entry(entry.origin.as_str()).or_insert(0) += 1;
        }
        assert!(per_origin.len() <= config.max_origins);
        assert!(
            per_origin
                .values()
                .all(|count| *count <= config.max_per_origin)
        );

        // The reloaded guard is equally bounded and agrees with the file.
        let reopened = SeenStore::open(dir.path(), config, 0);
        assert_eq!(reopened.len(), raw.entries.len());
    }
}
