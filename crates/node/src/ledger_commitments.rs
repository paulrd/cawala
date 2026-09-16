//! Filesystem-backed commitment chain.
//!
//! Persistence layout:
//!
//! ```text
//! <data-dir>/ledger/commitments.log   append-only, u32-LE length-prefixed
//!                                     postcard-encoded `SignedCommitment` frames
//! ```
//!
//! Framing mirrors [`crate::ledger_store::FileLog`]: a `u32` little-endian byte
//! length followed by the postcard payload, flushed and `sync_all`-ed on every
//! append. The frames form a **chain**: each commitment's
//! `prev_commitment_hash` is [`commitment_hash`] of its predecessor, and the
//! first anchors at [`Hash::ZERO`]. [`CommitmentLog::open`] re-verifies the whole
//! chain (signatures under the ledger key, linkage, and strictly increasing
//! heights) and treats a present-but-invalid file as a hard error; a missing
//! file is simply an empty chain.
//!
//! Unlike [`crate::ledger_store::FileLog`], a torn/truncated final frame is a
//! hard error here: a commitment chain is bounded and small, and a commit is an
//! explicit fsync-ed operator act, so a partial frame can only mean corruption.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use cawala_ledger::{Hash, LedgerPubKey, SignedCommitment, commitment_hash, verify_chain};

use crate::ledger_store::{MAX_ENTRY_FRAME_SIZE, ledger_dir};

/// Name of the append-only commitment frame log.
pub const COMMITMENTS_FILE: &str = "commitments.log";

/// Maximum number of commitments retained/loaded.
///
/// Bounds memory and load time; exceeding it is a hard error rather than a
/// silent truncation (dropping a prefix would break [chain
/// verification](verify_chain), which needs the genesis anchor).
pub const MAX_COMMITMENTS: usize = 4096;

/// Path of the commitment log for `data_dir`.
pub fn commitments_path(data_dir: &Path) -> PathBuf {
    ledger_dir(data_dir).join(COMMITMENTS_FILE)
}

/// An append-only, validated commitment chain backed by
/// `<data-dir>/ledger/commitments.log`.
#[derive(Debug)]
pub struct CommitmentLog {
    path: PathBuf,
    file: File,
    ledger_pubkey: LedgerPubKey,
    chain: Vec<SignedCommitment>,
}

impl CommitmentLog {
    /// Open (creating if needed) the commitment log for `ledger_pubkey`,
    /// replaying and validating every persisted frame.
    ///
    /// A missing/empty file yields an empty chain. A present file with a
    /// corrupt/truncated frame, an unverifiable signature, a broken link, or a
    /// height rollback/duplicate is a hard error.
    pub fn open(data_dir: &Path, ledger_pubkey: LedgerPubKey) -> Result<Self> {
        let dir = ledger_dir(data_dir);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create ledger dir {}", dir.display()))?;
        let path = dir.join(COMMITMENTS_FILE);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        let data =
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let chain = parse_frames(&path, &data)?;
        if chain.len() > MAX_COMMITMENTS {
            bail!(
                "{}: {} commitments exceeds max {MAX_COMMITMENTS}",
                path.display(),
                chain.len()
            );
        }
        verify_chain(&chain, &ledger_pubkey)
            .with_context(|| format!("{}: invalid commitment chain", path.display()))?;
        Ok(CommitmentLog {
            path,
            file,
            ledger_pubkey,
            chain,
        })
    }

    /// The validated chain, oldest first.
    pub fn chain(&self) -> &[SignedCommitment] {
        &self.chain
    }

    /// Whether the chain has no commitments yet.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Number of commitments in the chain.
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Height of the last commitment (0 for an empty chain).
    pub fn height(&self) -> u64 {
        self.chain
            .last()
            .map(|signed| signed.commitment.height)
            .unwrap_or(0)
    }

    /// [`commitment_hash`] of the last commitment ([`Hash::ZERO`] if empty),
    /// i.e. the value the next commitment must name as its `prev`.
    pub fn last_hash(&self) -> Hash {
        self.chain
            .last()
            .map(|signed| commitment_hash(&signed.commitment))
            .unwrap_or(Hash::ZERO)
    }

    /// Validate and append one commitment, fsync-ing before returning.
    ///
    /// Enforces the same invariants [`CommitmentLog::open`] checks — signature
    /// under the ledger key, `height == entry_count`, linkage to
    /// [`last_hash`](Self::last_hash), and a strictly greater height — so a
    /// caller can never publish a chain that would fail to reload.
    pub fn append(&mut self, commitment: SignedCommitment) -> Result<()> {
        if self.chain.len() >= MAX_COMMITMENTS {
            bail!(
                "{}: commitment log is full ({MAX_COMMITMENTS})",
                self.path.display()
            );
        }
        commitment
            .verify(&self.ledger_pubkey)
            .with_context(|| {
                format!(
                    "{}: refusing to append an unverifiable commitment",
                    self.path.display()
                )
            })?;
        if commitment.commitment.height != commitment.commitment.entry_count {
            bail!(
                "{}: commitment height {} does not equal entry_count {}",
                self.path.display(),
                commitment.commitment.height,
                commitment.commitment.entry_count
            );
        }
        let expected_prev = self.last_hash();
        if commitment.commitment.prev_commitment_hash != expected_prev {
            bail!(
                "{}: commitment prev {} does not link to {}",
                self.path.display(),
                commitment.commitment.prev_commitment_hash,
                expected_prev
            );
        }
        if let Some(last) = self.chain.last()
            && commitment.commitment.height <= last.commitment.height
        {
            bail!(
                "{}: commitment height {} is not greater than the previous {}",
                self.path.display(),
                commitment.commitment.height,
                last.commitment.height
            );
        }

        let frame = postcard::to_allocvec(&commitment)
            .map_err(|err| anyhow::anyhow!("failed to encode commitment: {err}"))?;
        if frame.len() > MAX_ENTRY_FRAME_SIZE as usize {
            bail!(
                "{}: commitment frame length {} exceeds max {MAX_ENTRY_FRAME_SIZE}",
                self.path.display(),
                frame.len()
            );
        }
        let io_err = |err: std::io::Error| {
            anyhow::anyhow!("{}: commitment log i/o error: {err}", self.path.display())
        };
        self.file
            .write_all(&(frame.len() as u32).to_le_bytes())
            .map_err(io_err)?;
        self.file.write_all(&frame).map_err(io_err)?;
        self.file.flush().map_err(io_err)?;
        self.file.sync_all().map_err(io_err)?;

        self.chain.push(commitment);
        Ok(())
    }
}

/// Parse every complete frame in `data`, rejecting any truncation or corruption.
///
/// A declared body that runs past end-of-file is an error (not a tolerated torn
/// tail): see the module docs.
fn parse_frames(path: &Path, data: &[u8]) -> Result<Vec<SignedCommitment>> {
    let mut chain = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        if data.len() - offset < 4 {
            bail!(
                "{}: truncated commitment length prefix at offset {offset}",
                path.display()
            );
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
            bail!(
                "{}: truncated commitment frame body at offset {body_start}",
                path.display()
            );
        }
        let commitment: SignedCommitment = postcard::from_bytes(&data[body_start..body_start + len])
            .with_context(|| {
                format!(
                    "{}: invalid signed commitment frame at offset {body_start}",
                    path.display()
                )
            })?;
        chain.push(commitment);
        offset = body_start + len;
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::{Commitment, LedgerSecretKey};

    fn ledger_key(seed: u8) -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([seed; 32])
    }

    /// A signed, internally consistent commitment at `height` (== entry_count).
    fn commitment(key: &LedgerSecretKey, height: u64, prev: Hash) -> SignedCommitment {
        let commitment = Commitment {
            ledger_id: key.public(),
            ledger_pubkey: key.public(),
            height,
            entry_count: height,
            entry_root: Hash::from_bytes([height as u8; 32]),
            state_root: Hash::from_bytes([0xAB; 32]),
            prev_commitment_hash: prev,
            issued_at: height,
        };
        SignedCommitment::sign(commitment, key).unwrap()
    }

    /// Write raw frames directly, bypassing [`CommitmentLog::append`]'s checks,
    /// so `open`'s validation can be exercised.
    fn write_raw(data_dir: &Path, commitments: &[SignedCommitment]) {
        let mut out = Vec::new();
        for signed in commitments {
            let frame = postcard::to_allocvec(signed).unwrap();
            out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            out.extend_from_slice(&frame);
        }
        let path = commitments_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, out).unwrap();
    }

    #[test]
    fn missing_file_is_an_empty_chain() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key(1);
        let log = CommitmentLog::open(dir.path(), key.public()).unwrap();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert_eq!(log.height(), 0);
        assert_eq!(log.last_hash(), Hash::ZERO);
        assert!(log.chain().is_empty());
    }

    #[test]
    fn genesis_and_linkage_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key(1);
        let mut log = CommitmentLog::open(dir.path(), key.public()).unwrap();

        let c0 = commitment(&key, 0, Hash::ZERO);
        log.append(c0.clone()).unwrap();
        let h0 = commitment_hash(&c0.commitment);
        assert_eq!(log.height(), 0);
        assert_eq!(log.last_hash(), h0);

        let c1 = commitment(&key, 1, h0);
        log.append(c1.clone()).unwrap();
        let h1 = commitment_hash(&c1.commitment);
        assert_eq!(log.height(), 1);
        assert_eq!(log.last_hash(), h1);

        let c2 = commitment(&key, 2, h1);
        log.append(c2.clone()).unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(log.chain(), &[c0.clone(), c1.clone(), c2.clone()]);
        assert!(!log.is_empty());
        drop(log);

        // Reload re-validates the whole chain.
        let reloaded = CommitmentLog::open(dir.path(), key.public()).unwrap();
        assert_eq!(reloaded.len(), 3);
        assert_eq!(reloaded.height(), 2);
        assert_eq!(reloaded.last_hash(), commitment_hash(&c2.commitment));
    }

    #[test]
    fn append_rejects_broken_link_and_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key(1);
        let mut log = CommitmentLog::open(dir.path(), key.public()).unwrap();
        let c0 = commitment(&key, 0, Hash::ZERO);
        log.append(c0.clone()).unwrap();
        let h0 = commitment_hash(&c0.commitment);

        // Broken link: claims a prev that is not the current head.
        let broken = commitment(&key, 1, Hash::from_bytes([0xCD; 32]));
        assert!(log.append(broken).is_err());
        // Height rollback/duplicate: cannot re-use the genesis height.
        let rollback = commitment(&key, 0, h0);
        assert!(log.append(rollback).is_err());
        // The valid next commitment still succeeds.
        log.append(commitment(&key, 1, h0)).unwrap();
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn append_rejects_a_wrong_key_signature() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key(1);
        let other = ledger_key(2);
        let mut log = CommitmentLog::open(dir.path(), key.public()).unwrap();
        assert!(log.append(commitment(&other, 0, Hash::ZERO)).is_err());
        assert!(log.is_empty());
    }

    #[test]
    fn open_rejects_broken_prev() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key(1);
        let c0 = commitment(&key, 0, Hash::ZERO);
        let bad = commitment(&key, 1, Hash::from_bytes([0xCD; 32]));
        write_raw(dir.path(), &[c0, bad]);

        let err = CommitmentLog::open(dir.path(), key.public()).unwrap_err();
        assert!(
            err.to_string().contains("invalid commitment chain"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn open_rejects_height_rollback_and_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key(1);
        let c0 = commitment(&key, 0, Hash::ZERO);
        let h0 = commitment_hash(&c0.commitment);
        let duplicate = commitment(&key, 0, h0);
        write_raw(dir.path(), &[c0, duplicate]);
        assert!(CommitmentLog::open(dir.path(), key.public()).is_err());

        // A genuine rollback (2 then 1) is rejected too.
        let dir2 = tempfile::tempdir().unwrap();
        let c0 = commitment(&key, 0, Hash::ZERO);
        let h0 = commitment_hash(&c0.commitment);
        let c2 = commitment(&key, 2, h0);
        let h2 = commitment_hash(&c2.commitment);
        let c1 = commitment(&key, 1, h2);
        write_raw(dir2.path(), &[c0, c2, c1]);
        assert!(CommitmentLog::open(dir2.path(), key.public()).is_err());
    }

    #[test]
    fn open_rejects_wrong_key_signature() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key(1);
        let other = ledger_key(2);
        write_raw(dir.path(), &[commitment(&other, 0, Hash::ZERO)]);
        assert!(CommitmentLog::open(dir.path(), key.public()).is_err());
    }

    #[test]
    fn open_rejects_truncated_and_corrupt_frames() {
        let dir = tempfile::tempdir().unwrap();
        let key = ledger_key(1);
        let c0 = commitment(&key, 0, Hash::ZERO);
        let c1 = commitment(&key, 1, commitment_hash(&c0.commitment));
        write_raw(dir.path(), &[c0.clone(), c1.clone()]);

        // Truncate the last frame body by two bytes.
        let path = commitments_path(dir.path());
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 2]).unwrap();
        assert!(CommitmentLog::open(dir.path(), key.public()).is_err());

        // Corrupt the first frame's body (still a bounded, length-prefixed frame).
        let dir2 = tempfile::tempdir().unwrap();
        let c0 = commitment(&ledger_key(1), 0, Hash::ZERO);
        let c1 = commitment(&ledger_key(1), 1, commitment_hash(&c0.commitment));
        write_raw(dir2.path(), &[c0.clone(), c1.clone()]);
        let path = commitments_path(dir2.path());
        let mut bytes = std::fs::read(&path).unwrap();
        let frame0_end = {
            let body = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
            4 + body
        };
        // Flip a byte inside the second frame's body (a valid frame boundary).
        bytes[frame0_end + 4] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();
        assert!(CommitmentLog::open(dir2.path(), ledger_key(1).public()).is_err());
    }
}
