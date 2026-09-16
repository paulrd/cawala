//! Durable, best-effort journal of accepted [`PaymentOrder`]s.
//!
//! Orders are otherwise in-memory only ([`SettlementManager`](crate::settlement::SettlementManager)
//! keeps the *origin's* pending reservations, but a leaf has no record of the
//! orders it accepted). This journal appends one serde-JSON `PaymentOrder` per
//! line to `<data-dir>/ledger/orders.jsonl`, deduplicated by the order's
//! domain-separated hash.
//!
//! It is deliberately **best-effort**: journaling must never fail an order. A
//! journal I/O error is logged at the call site and the request proceeds; a
//! later [`load_all`] simply sees whatever reached the disk.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cawala_ledger::{Hash, PaymentOrder};

use crate::ledger_store::ledger_dir;

/// Name of the JSON-lines order journal.
pub const ORDERS_FILE: &str = "orders.jsonl";

/// Path of the order journal for `data_dir`.
pub fn orders_path(data_dir: &Path) -> PathBuf {
    ledger_dir(data_dir).join(ORDERS_FILE)
}

/// Append `order` to the journal, skipping it when an order with the same hash
/// is already present. One JSON object per line, fsync-ed on append.
pub fn append(data_dir: &Path, order: &PaymentOrder) -> Result<()> {
    let path = orders_path(data_dir);
    if read_hashes(&path).contains(&order.hash()) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let line =
        serde_json::to_string(order).context("failed to encode payment order as JSON")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(file, "{line}").with_context(|| format!("failed to append {}", path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    Ok(())
}

/// Load every parseable order from the journal, in file order.
///
/// Malformed lines are skipped with a warning; a missing file is empty.
pub fn load_all(data_dir: &Path) -> Vec<PaymentOrder> {
    let path = orders_path(data_dir);
    let Ok(data) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut orders = Vec::new();
    for (index, line) in data.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<PaymentOrder>(line) {
            Ok(order) => orders.push(order),
            Err(err) => {
                tracing::warn!(
                    line = index + 1,
                    %err,
                    "skipping malformed order journal line"
                );
            }
        }
    }
    orders
}

/// The hashes of every parseable order currently in the journal (for dedup).
///
/// Malformed lines are ignored here without a warning: [`load_all`] is the
/// diagnostic path, and `append` must not log a warning per order.
fn read_hashes(path: &Path) -> HashSet<Hash> {
    let Ok(data) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    data.lines()
        .filter_map(|line| serde_json::from_str::<PaymentOrder>(line).ok())
        .map(|order| order.hash())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::{Amount, NodeId};

    fn order(nonce: u64) -> PaymentOrder {
        PaymentOrder {
            from: NodeId::from("alice"),
            to: NodeId::from("bob"),
            amount: Amount::new(10 + nonce),
            nonce,
            expiry: 1_000,
        }
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_all(dir.path()).is_empty());
    }

    #[test]
    fn append_dedups_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let a = order(1);
        let b = order(2);

        append(dir.path(), &a).unwrap();
        append(dir.path(), &a).unwrap(); // duplicate hash: skipped
        append(dir.path(), &b).unwrap();

        let loaded = load_all(dir.path());
        assert_eq!(loaded, vec![a, b]);

        // A reopen (fresh read) still sees exactly two lines.
        let text = std::fs::read_to_string(orders_path(dir.path())).unwrap();
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let a = order(1);
        append(dir.path(), &a).unwrap();

        // Append a malformed line and a valid one by hand.
        let mut file = OpenOptions::new()
            .append(true)
            .open(orders_path(dir.path()))
            .unwrap();
        writeln!(file, "{{not json}}").unwrap();
        let b = order(2);
        writeln!(file, "{}", serde_json::to_string(&b).unwrap()).unwrap();
        drop(file);

        let loaded = load_all(dir.path());
        assert_eq!(loaded, vec![a, b]);
    }

    #[test]
    fn dedup_ignores_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let a = order(1);
        append(dir.path(), &a).unwrap();
        let path = orders_path(dir.path());
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(file, "garbage").unwrap();
        drop(file);

        // Re-appending the same order is still a no-op despite the bad line.
        append(dir.path(), &a).unwrap();
        assert_eq!(load_all(dir.path()), vec![a]);
    }
}
