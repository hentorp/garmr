// Apache-2.0 licensed.

//! Crash-recovery for a local (`file://`) warehouse.
//!
//! The catalog pointer in `catalog.redb` is advanced under a durable (fsync'd)
//! redb transaction, but the Iceberg metadata JSON it points at is written via
//! `FileIO` *without* an fsync. On a local filesystem an unclean shutdown
//! (power loss, host reboot) can therefore land the durable pointer on metadata
//! bytes that were still only in the page cache — the file survives as a
//! zero-byte stub and the table fails to open (`EOF while parsing a value`).
//!
//! Two defences live here:
//! - **Prevention** — [`fsync_local_metadata`] flushes a just-written metadata
//!   blob (and its directory) before the pointer advances (called from the
//!   commit paths). Best-effort; object-store backends are a no-op.
//! - **Recovery** — [`RedbCatalog::heal_table`] detects a pointer that resolves
//!   to a missing/empty/unparseable metadata file and rolls it back to the
//!   newest metadata in the table's directory that fully parses and whose
//!   snapshot's manifest list is present and non-empty.

use iceberg::io::FileIO;
use iceberg::spec::TableMetadata;
use iceberg::{Result, TableIdent};

use crate::catalog::RedbCatalog;
use crate::error::map_redb;
use crate::keys::table_key;
use crate::store::{CommitOutcome, TABLES};

/// What [`RedbCatalog::heal_table`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealOutcome {
    /// The current pointer resolves to loadable metadata — nothing changed.
    Healthy,
    /// The pointer was corrupt; it was rolled back from `from` to `to`.
    Healed { from: String, to: String },
    /// The table is not in the catalog — nothing to heal.
    Unknown,
    /// A non-`file://` backend — local crash-recovery does not apply.
    Skipped,
    /// The pointer is corrupt and NO intact metadata was found in the table
    /// directory — manual intervention required.
    Unrecoverable { location: String },
}

/// Flush a just-written `file://` metadata blob and its parent directory to
/// disk. Call after writing metadata and BEFORE advancing the catalog pointer,
/// so a crash can never leave the durable pointer aimed at un-flushed bytes.
///
/// Best-effort: non-`file://` locations are a no-op (object stores have their
/// own durability), and I/O errors are swallowed — [`RedbCatalog::heal_table`]
/// is the backstop. The work is synchronous (a couple of `fsync`s) and runs on
/// the commit path, which already fsyncs the redb transaction next.
pub(crate) fn fsync_local_metadata(location: &str) {
    let Some(path) = location.strip_prefix("file://") else {
        return;
    };
    use std::fs::File;
    if let Ok(f) = File::open(path) {
        let _ = f.sync_all();
    }
    if let Some(dir) = std::path::Path::new(path).parent() {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

/// Does `location` resolve to fully loadable metadata: present, non-empty,
/// parseable, and (if it has a current snapshot) with a manifest list that
/// parses AND whose every referenced manifest file is present and non-empty?
///
/// `require_snapshot` distinguishes the two uses. For the CURRENT-pointer health
/// check it is `false`: an unappended table (no snapshot) is legitimately
/// healthy. For a ROLLBACK candidate it is `true`: a snapshot-less create-time
/// metadata must NEVER be accepted as a recovery target, or heal would silently
/// roll a table that HAD data back to empty (and `cleanup_orphans` would then GC
/// the retired data dir) — total data loss masked as success. When the only
/// intact candidate is the empty create-metadata, the caller returns
/// [`HealOutcome::Unrecoverable`] (loud) instead.
///
/// Checking the individual manifests — not just the manifest *list* — is what
/// lets heal recover from a torn compaction. A SIGTERM landing mid-compaction can
/// leave a zero-byte `*-m0.avro` manifest that an intact, parseable manifest LIST
/// still references; validating only the list would pass such a snapshot as
/// healthy, yet every later scan dies loading the 0-byte manifest. Statting each
/// manifest and rejecting the snapshot on the first missing/empty one makes heal
/// roll the pointer back past the torn commit automatically.
async fn metadata_is_intact(fileio: &FileIO, location: &str, require_snapshot: bool) -> bool {
    // `read_from` reads + parses; a missing/empty/truncated file errors here.
    let Ok(md) = TableMetadata::read_from(fileio, location).await else {
        return false;
    };
    // No current snapshot: healthy only when we are not demanding one (see the
    // `require_snapshot` contract above — a create-time metadata must never be a
    // rollback target).
    let Some(snap) = md.current_snapshot() else {
        return !require_snapshot;
    };
    // The manifest list must be present, non-empty AND parse — the commit that
    // wrote this metadata wrote the list in the same burst, so a torn commit
    // shows up as a zero-byte / truncated `snap-*.avro` and fails to load here.
    let Ok(manifest_list) = snap.load_manifest_list(fileio, &md).await else {
        return false;
    };
    // ...and every manifest the list references must be present and non-empty. A
    // 0-byte `*-m0.avro` (torn compaction) is invisible to the list check above
    // but fatal to any later scan. A `metadata()` stat is cheap and rejects both
    // a missing file (Err) and a 0-byte one (size == 0); short-circuit on the
    // first bad manifest so a rejected candidate costs one stat, not a full scan.
    for mf in manifest_list.entries() {
        let manifest_ok = match fileio.new_input(&mf.manifest_path) {
            Ok(input) => matches!(input.metadata().await, Ok(m) if m.size > 0),
            Err(_) => false,
        };
        if !manifest_ok {
            return false;
        }
    }
    true
}

/// Order `NNNNN-<uuid>.metadata.json` names newest-first by PARSED version.
/// Iceberg pads the version to a *minimum* of 5 digits (`{:0>5}`), not a fixed
/// width, so a plain lexicographic sort breaks the moment the version crosses
/// 100000 (`"99999"` sorts after `"100000"` as strings). Parse the leading
/// integer; non-conforming names sort last.
fn newest_first(mut names: Vec<String>) -> Vec<String> {
    fn version_of(name: &str) -> u64 {
        name.split('-')
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    }
    names.sort_by(|a, b| version_of(b).cmp(&version_of(a)).then_with(|| b.cmp(a)));
    names
}

impl RedbCatalog {
    /// If `ident`'s current metadata pointer resolves to a missing, empty, or
    /// unparseable metadata file (e.g. after an unclean shutdown left the file
    /// un-fsync'd while the durable pointer advanced), roll the pointer back to
    /// the newest metadata file in the table's directory that fully loads.
    ///
    /// A no-op ([`HealOutcome::Healthy`]) when the pointer is already sound, the
    /// table is unknown, or the backend is not `file://`. Data files are never
    /// touched — this only rewinds the pointer to an already-durable snapshot,
    /// so it is safe to call unconditionally at startup.
    pub async fn heal_table(&self, ident: &TableIdent) -> Result<HealOutcome> {
        let key = table_key(&self.name, ident);

        // The on-disk pointer (not the in-memory mirror — this runs at startup).
        let current = {
            let db = self.store.db.lock().await;
            let read = db.begin_read().map_err(map_redb)?;
            let tables = read.open_table(TABLES).map_err(map_redb)?;
            match tables.get(key.as_str()).map_err(map_redb)? {
                Some(v) => v.value().to_string(),
                None => return Ok(HealOutcome::Unknown),
            }
        };

        let Some(current_path) = current.strip_prefix("file://") else {
            return Ok(HealOutcome::Skipped);
        };
        if metadata_is_intact(&self.fileio, &current, false).await {
            return Ok(HealOutcome::Healthy);
        }

        // The pointer is corrupt. Scan the metadata directory for the newest
        // intact candidate that actually carries data (see `require_snapshot`).
        let Some(dir) = std::path::Path::new(current_path).parent() else {
            return Ok(HealOutcome::Unrecoverable { location: current });
        };
        let names: Vec<String> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".metadata.json"))
                .collect(),
            Err(_) => return Ok(HealOutcome::Unrecoverable { location: current }),
        };

        for name in newest_first(names) {
            let cand = format!("file://{}/{}", dir.display(), name);
            if cand == current {
                continue;
            }
            if metadata_is_intact(&self.fileio, &cand, true).await {
                // Repoint through the shared write-through path so the durable
                // TABLES entry and the in-memory L1 mirror move together. No
                // commit event: this rewinds to an existing snapshot, it does
                // not create one.
                let (k, loc) = (key.clone(), cand.clone());
                self.store
                    .group_commit(Box::new(move |write| {
                        let mut tables = write.open_table(TABLES).map_err(map_redb)?;
                        tables.insert(k.as_str(), loc.as_str()).map_err(map_redb)?;
                        Ok(CommitOutcome::insert(k, loc))
                    }))
                    .await?;
                return Ok(HealOutcome::Healed {
                    from: current,
                    to: cand,
                });
            }
        }
        Ok(HealOutcome::Unrecoverable { location: current })
    }
}

#[cfg(test)]
mod tests {
    use super::newest_first;

    #[test]
    fn newest_first_orders_by_numeric_version_not_lexicographically() {
        // The 100000 boundary: lexicographically "99999" > "100000", so a naive
        // string sort would wrongly rank v99999 as newest.
        let got = newest_first(vec![
            "00001-a.metadata.json".into(),
            "99999-b.metadata.json".into(),
            "100000-c.metadata.json".into(),
            "100001-d.metadata.json".into(),
            "00000-e.metadata.json".into(),
        ]);
        let versions: Vec<&str> = got.iter().map(|s| s.split('-').next().unwrap()).collect();
        assert_eq!(
            versions,
            vec!["100001", "100000", "99999", "00001", "00000"]
        );
    }
}
