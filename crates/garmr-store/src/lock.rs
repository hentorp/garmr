// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Non-destructive redb writer-liveness probe (Phase 13 backup/restore).
//!
//! The single-writer interlock in garmr is the redb exclusive file lock: exactly
//! one process can open `state.redb` (and the warehouse `catalog.redb`) at a time.
//! Backup-create and restore need to know a `serve` is NOT live before they copy
//! or swap, and to HOLD that exclusion for the critical section — but WITHOUT the
//! side effects of a full `Store::open_writable` (which creates the Tantivy writer
//! lock, commits to state.redb to ensure tables, and runs orphan cleanup that
//! deletes warehouse scratch). A bare [`redb::Database::open`] (never `create`)
//! takes the lock and performs no schema write, so it is a safe, side-effect-free
//! probe + hold.

use std::path::{Path, PathBuf};

use garmr_core::{Error, Result};

/// The restored-follower marker path for a given state DB (`<state_db>.restored`).
/// Its presence means a node was restored from a backup and has NOT been promoted
/// to writer; every writable open ([`crate::Store::open_writable`]) refuses while
/// it exists, and `garmr backup promote` clears it after an audited transition
/// (Phase-13 invariant #2: a restored node never silently becomes a writer).
pub fn restored_marker_path(state_db: &Path) -> PathBuf {
    let mut s = state_db.as_os_str().to_owned();
    s.push(".restored");
    PathBuf::from(s)
}

/// Holds an exclusive redb lock on one or more database files for its lifetime,
/// so no `serve` (or other opener) can start while a backup copy or a restore
/// swap is in progress. Dropping it releases the locks.
pub struct WriterExclusion {
    _dbs: Vec<redb::Database>,
}

/// Try to acquire exclusion over `paths` (redb DB files) WITHOUT mutating them —
/// a bare [`redb::Database::open`], never `create`, so no schema/ensure write. A
/// path that does not exist is skipped (nothing to lock). Returns:
///
/// - `Ok(Some(guard))` — all present paths acquired; hold the guard for the
///   critical section;
/// - `Ok(None)` — at least one path is locked by a live opener (a running
///   `serve`); the caller refuses fail-closed;
/// - `Err(..)` — an unexpected storage error (corrupt DB, upgrade required).
pub fn try_acquire_exclusion(paths: &[&Path]) -> Result<Option<WriterExclusion>> {
    let mut dbs = Vec::new();
    for p in paths {
        if !p.exists() {
            continue;
        }
        match redb::Database::open(p) {
            Ok(db) => dbs.push(db),
            Err(redb::DatabaseError::DatabaseAlreadyOpen) => return Ok(None),
            Err(e) => return Err(Error::store(e)),
        }
    }
    Ok(Some(WriterExclusion { _dbs: dbs }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn tmp(name: &str) -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "garmr-lock-{}-{}-{}.redb",
            name,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn restored_marker_is_the_state_db_plus_suffix() {
        assert_eq!(
            restored_marker_path(Path::new("/data/garmr/state.redb")),
            PathBuf::from("/data/garmr/state.redb.restored")
        );
    }

    #[test]
    fn missing_paths_acquire_trivially() {
        let p = tmp("missing");
        let _ = std::fs::remove_file(&p);
        assert!(try_acquire_exclusion(&[&p]).unwrap().is_some());
    }

    #[test]
    fn a_held_database_reports_not_acquirable() {
        let p = tmp("held");
        let _ = std::fs::remove_file(&p);
        // Create + hold the DB (simulating a live `serve`).
        let held = redb::Database::create(&p).unwrap();
        assert!(
            try_acquire_exclusion(&[&p]).unwrap().is_none(),
            "a held redb file must read as a live writer"
        );
        drop(held);
        // Once released, exclusion is acquirable again.
        assert!(try_acquire_exclusion(&[&p]).unwrap().is_some());
        let _ = std::fs::remove_file(&p);
    }
}