//! Best-effort JSONL audit log for control-plane admin actions.
//!
//! One writer format is shared by the running engine and the operator CLI:
//! every call appends one JSON object per line to
//! `<data-dir>/control_audit.jsonl`, inserting a `ts` (unix seconds) field when
//! the caller did not supply one.
//!
//! Appends are **best-effort**: any I/O or encoding failure is ignored, because
//! auditing must never fail a control request or a CLI command.

use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Name of the audit log inside the data dir.
pub const CONTROL_AUDIT_FILE: &str = "control_audit.jsonl";

/// Append `event` as one JSON line, inserting `ts` (unix seconds) if absent.
///
/// A non-object `event` is still written as a bare JSON line. Any failure is
/// silently ignored.
pub fn append(data_dir: &Path, mut event: serde_json::Value) {
    if let Some(object) = event.as_object_mut() {
        object
            .entry("ts")
            .or_insert_with(|| serde_json::json!(now_unix_seconds()));
    }
    let line = match serde_json::to_string(&event) {
        Ok(line) => line,
        Err(_) => return,
    };
    let path = data_dir.join(CONTROL_AUDIT_FILE);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{line}");
    }
}

/// Current time as unix seconds.
fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
