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
    /// Whether the sealed rows have been removed from the hot lakehouse.
    /// Written `false` at seal time — the rows are still hot at that instant —
    /// and flipped by the first compaction whose rebuild ran with this window in
    /// its sealed-prune ranges: after that swap commits, every row of this
    /// window is provably gone from hot, which is exactly what the flag claims.
    pub hot_pruned: bool,
    /// When the window was sealed.
    pub sealed_at: DateTime<Utc>,
    /// Under legal hold: exempt from expiry until a human clears it.
    ///
    /// `#[serde(default)]` so archives sealed before this field existed decode
    /// as NOT held. That is the right default for compatibility but the wrong
    /// one for safety, which is why expiry is opt-in per deployment and every
    /// deletion is audited: an operator must choose to delete, and can prove
    /// afterwards what was deleted and when.
    #[serde(default)]
    pub legal_hold: bool,
}

/// What a deleted cold archive leaves behind.
///
/// Expiry removes the manifest row, so without this record an operator can say
/// *that* something was deleted but not *what*: the checksum, the row count and
/// the exact window are gone with it. "Defensible deletion" means being able to
/// answer a regulator's "prove what you removed" a year later, and an audit line
/// naming only an id cannot do that. The record is deliberately small and
/// content-free — it identifies the archive and its integrity hash, never any
/// event data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColdDeletion {
    /// The window key the archive had.
    pub id: String,
    /// BLAKE3 hex of the file that was deleted — the proof of WHICH bytes went.
    pub checksum: String,
    pub rows: u64,
    pub bytes_out: u64,
    pub start_us: i64,
    pub end_us: i64,
    /// When the deletion happened.
    pub deleted_at: DateTime<Utc>,
    /// Why: the operator-facing reason (e.g. "retention expiry, cutoff 400 days").
    pub reason: String,
    /// Whether the local archive file was removed. `false` is normal when the
    /// archive had already been uploaded to S3 and the local copy dropped.
    pub local_removed: bool,
    /// Whether the object-store copy was removed.
    ///
    /// `None` means no object store was configured, so there was never a remote
    /// copy. `Some(false)` is the case an operator MUST see: the remote copy
    /// outlived the deletion and the data is still out there.
    pub remote_removed: Option<bool>,
}

impl ColdDeletion {
    /// Did this deletion actually remove every copy garmr knows about?
    ///
    /// A deletion that left a remote object behind is not a deletion, and
    /// reporting it as one is how "we erased it" becomes a false statement to a
    /// regulator.
    pub fn is_complete(&self) -> bool {
        self.local_removed || self.remote_removed == Some(true)
    }
}

/// Which event attribute a targeted erasure selects on.
///
/// A CLOSED set on purpose: every field here must be enforceable in the
/// compaction prune hook (Arrow columns / the fields-JSON needle), in SQL
/// counting, and in the full-text index. An open predicate language would let
/// an operator place a tombstone nothing can actually enforce — which converges
/// to "erased" in the ledger and present on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EraseField {
    /// The `host` label (an Arrow column — exact match).
    Host,
    /// The extracted `src_ip` field (matched via the fields-JSON needle).
    SrcIp,
    /// The extracted `user` field (matched via the fields-JSON needle).
    User,
}

impl EraseField {
    /// The key inside the serialized `fields` JSON, for needle matching.
    /// `None` for attributes that are real columns.
    pub fn fields_key(self) -> Option<&'static str> {
        match self {
            EraseField::Host => None,
            EraseField::SrcIp => Some("src_ip"),
            EraseField::User => Some("user"),
        }
    }
}

/// A persistent erasure predicate: rows matching it must not exist.
///
/// Persistent is the point. A one-shot delete leaves the predicate satisfied
/// only until a LATE ARRIVAL lands — a retried batch, a collector that was
/// offline during the erasure, an imported backlog — and then the erased
/// subject is back. A tombstone outlives the delete: every later compaction
/// applies it again, so the store CONVERGES to erased instead of merely passing
/// through that state once.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tombstone {
    /// Stable id (also the certificate's name).
    pub id: String,
    pub field: EraseField,
    /// Exact value to erase. Never a pattern: a wildcard here is a mass
    /// deletion nobody can review row-by-row.
    pub value: String,
    /// Optional half-open `[from_us, to_us)` bound on `event_ts`.
    pub from_us: Option<i64>,
    pub to_us: Option<i64>,
    pub placed_at: DateTime<Utc>,
    /// Operator-facing why (e.g. the erasure-request reference).
    pub reason: String,
}

impl Tombstone {
    /// The substring needle that matches this tombstone inside the serialized
    /// `fields` JSON column — the same `"key":"value"` shape the agent's SQL
    /// tools already grep with, so store and hook agree on what matches.
    /// `None` when the field is a real column (matched directly).
    pub fn fields_needle(&self) -> Option<String> {
        self.field.fields_key().map(|k| {
            // serde_json string-escapes the value exactly as the ingest side
            // serialized it, so the needle survives quotes/backslashes in the
            // value instead of silently never matching.
            let quoted = serde_json::to_string(&self.value).unwrap_or_default();
            format!("\"{k}\":{quoted}")
        })
    }

    /// Is `ts` inside this tombstone's (optional) time bounds?
    pub fn covers_ts(&self, us: i64) -> bool {
        self.from_us.is_none_or(|f| us >= f) && self.to_us.is_none_or(|t| us < t)
    }
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

/// Which archives an expiry run would delete, given a cutoff.
///
/// Pure so the policy is testable without touching a store or a disk — deleting
/// evidence is the one operation in garmr that cannot be undone by a retry, so
/// the decision of WHAT to delete is kept separate from the act of deleting.
///
/// An archive expires only when its window lies ENTIRELY before `cutoff_us`:
/// a window straddling the boundary still holds retained data, and partial
/// deletion of an immutable, content-addressed archive is not possible anyway.
/// Anything under legal hold is skipped regardless of age.
pub fn expired_archives(
    archives: &[ColdArchive],
    cutoff_us: i64,
) -> (Vec<&ColdArchive>, Vec<&ColdArchive>) {
    let mut expiring = Vec::new();
    let mut held = Vec::new();
    for a in archives {
        if a.end_us > cutoff_us {
            continue; // still within retention
        }
        if a.legal_hold {
            held.push(a);
        } else {
            expiring.push(a);
        }
    }
    (expiring, held)
}

#[cfg(test)]
mod expiry_tests {
    use super::*;

    const DAY_US: i64 = 86_400_000_000;

    fn arc(id: &str, start_day: i64, end_day: i64, hold: bool) -> ColdArchive {
        ColdArchive {
            id: id.into(),
            kind: "znippy".into(),
            file: format!("{id}.znippy"),
            start_us: start_day * DAY_US,
            end_us: end_day * DAY_US,
            rows: 1,
            bytes_in: 10,
            bytes_out: 5,
            checksum: "deadbeef".into(),
            hot_pruned: false,
            sealed_at: Utc::now(),
            legal_hold: hold,
        }
    }

    #[test]
    fn only_windows_entirely_past_the_cutoff_expire() {
        let archives = vec![
            arc("old", 1, 2, false),         // wholly before
            arc("straddling", 9, 11, false), // crosses the cutoff
            arc("recent", 20, 21, false),    // wholly after
        ];
        let (expiring, held) = expired_archives(&archives, 10 * DAY_US);
        let ids: Vec<&str> = expiring.iter().map(|a| a.id.as_str()).collect();
        // A window crossing the boundary still holds retained data, and an
        // immutable content-addressed archive cannot be partially deleted — so
        // it must survive rather than take retained rows down with it.
        assert_eq!(ids, vec!["old"]);
        assert!(held.is_empty());
    }

    #[test]
    fn a_legal_hold_survives_expiry_and_is_reported() {
        let archives = vec![arc("held", 1, 2, true), arc("free", 1, 2, false)];
        let (expiring, held) = expired_archives(&archives, 10 * DAY_US);
        assert_eq!(
            expiring.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            vec!["free"]
        );
        // Held archives are RETURNED, not silently skipped: an operator running
        // an erasure request has to be told what was not deleted, or they will
        // report completion that did not happen.
        assert_eq!(
            held.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            vec!["held"]
        );
    }

    #[test]
    fn an_exact_boundary_expires() {
        // end_us == cutoff means the window's exclusive end has been reached, so
        // every row in it is older than the cutoff.
        let archives = vec![arc("boundary", 8, 10, false)];
        let (expiring, _) = expired_archives(&archives, 10 * DAY_US);
        assert_eq!(expiring.len(), 1);
    }
}
