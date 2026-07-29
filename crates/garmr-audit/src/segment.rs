// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Segment files: append-only JSON-lines, one [`AuditRecord`] per line.
//!
//! JSONL keeps the ledger inspectable and easy to export/import, while integrity
//! is enforced over the canonical encoding (not the JSON bytes). A record is a
//! single line terminated by `\n`; a trailing line without a newline is a torn
//! write (crash mid-append) and is healed on open, not treated as tampering. A
//! *complete* line that fails to parse is corruption and is surfaced.

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::event::AuditRecord;

/// Segment file name for a segment id, zero-padded hex so lexical order == id
/// order.
pub fn segment_filename(id: u64) -> String {
    format!("{id:016x}.jsonl")
}

/// Checkpoint file name for the sequence it covers.
pub fn checkpoint_filename(seq: u64) -> String {
    format!("{seq:016x}.ckpt.json")
}

/// Sorted segment ids present under `segments_dir`.
pub fn list_segment_ids(segments_dir: &Path) -> Result<Vec<u64>> {
    let mut ids = Vec::new();
    if !segments_dir.exists() {
        return Ok(ids);
    }
    for entry in std::fs::read_dir(segments_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".jsonl") {
            if let Ok(id) = u64::from_str_radix(stem, 16) {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// Sorted checkpoint file paths under `checkpoints_dir`.
pub fn list_checkpoint_paths(checkpoints_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    if !checkpoints_dir.exists() {
        return Ok(paths);
    }
    for entry in std::fs::read_dir(checkpoints_dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("json") {
            paths.push(p);
        }
    }
    paths.sort();
    Ok(paths)
}

/// Result of reading a segment file for recovery.
pub struct SegmentRead {
    pub records: Vec<AuditRecord>,
    /// Byte length of the complete, newline-terminated prefix that parsed OK.
    pub valid_len: u64,
    /// True if the file ends with a partial (non-newline-terminated) record.
    pub torn_tail: bool,
}

/// Read a segment strictly: every complete line must parse. A partial trailing
/// line is reported via `torn_tail` (to be healed), not parsed.
pub fn read_segment(path: &Path) -> Result<SegmentRead> {
    let data = std::fs::read(path)?;
    let mut records = Vec::new();
    let mut valid_len: usize = 0;
    let mut start: usize = 0;
    for (i, &byte) in data.iter().enumerate() {
        if byte == b'\n' {
            let line = &data[start..i];
            if !line.is_empty() {
                let rec: AuditRecord = serde_json::from_slice(line)?;
                records.push(rec);
            }
            valid_len = i + 1;
            start = i + 1;
        }
    }
    let torn_tail = start < data.len();
    Ok(SegmentRead {
        records,
        valid_len: valid_len as u64,
        torn_tail,
    })
}