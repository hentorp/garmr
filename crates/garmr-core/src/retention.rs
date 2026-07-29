// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Cold-storage manifest record.
//!
//! When events age past the retention window they are sealed, one time-window at
//! a time, into an immutable cold archive (see `garmr-retention`). Each sealed
//! window is recorded as a [`ColdArchive`] in the state store so the cold tier
//! stays queryable: a cold query looks up the archives overlapping a time range,
//! thaws their parquet payloads, and runs SQL over them — the Splunk
//! frozen→thawed model. The record is the index; the archive file is the data.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One sealed cold-storage window.
///
/// `file` is a basename resolved against the configured `cold_dir` at read time
/// (so relocating the cold directory doesn't break the manifest). `start_us` is
/// inclusive and `end_us` exclusive, both microseconds since the Unix epoch —
/// the half-open window `[start_us, end_us)` of `event_ts` this archive covers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColdArchive {
    /// Stable window key (the window-start date, e.g. `2026-04-08`), also the
    /// manifest primary key — sealing a window twice overwrites in place.
    pub id: String,
    /// Archiver that produced the file: `"plain"` (raw parquet) or `"znippy"`.
    pub kind: String,
    /// Archive file basename, resolved against `cold_dir` at read time.
    pub file: String,
    /// Inclusive window start (`event_ts` micros).
    pub start_us: i64,
    /// Exclusive window end (`event_ts` micros).
    pub end_us: i64,
    /// Rows sealed into this archive.
    pub rows: u64,
    /// Uncompressed parquet size fed to the archiver.
    pub bytes_in: u64,
    /// Archive size on disk.
    pub bytes_out: u64,
    /// BLAKE3 hex of the archive file — content-addressed integrity check.
    pub checksum: String,
    /// Whether the sealed rows were also removed from the hot lakehouse. Always
    /// `false` today: the embedded skade store exposes no row-delete/expire, so
    /// the cold tier is currently additive (durable archive + manifest) and hot
    /// space is not yet reclaimed. Flips to `true` once skade grows an
    /// expiration primitive.
    pub hot_pruned: bool,
    /// When the window was sealed.
    pub sealed_at: DateTime<Utc>,
}

impl ColdArchive {
    /// Full path to the archive file under `cold_dir`.
    pub fn path(&self, cold_dir: &std::path::Path) -> PathBuf {
        cold_dir.join(&self.file)
    }

    /// Does this archive's window overlap the half-open range `[from_us, to_us)`?
    /// A `None` bound is unbounded on that side.
    pub fn overlaps(&self, from_us: Option<i64>, to_us: Option<i64>) -> bool {
        let after_from = to_us.is_none_or(|to| self.start_us < to);
        let before_to = from_us.is_none_or(|from| self.end_us > from);
        after_from && before_to
    }
}