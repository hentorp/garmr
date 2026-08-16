// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Cold-storage manifest persistence: the sealed-archive records (keyed by
//! window id in `cold_archives`) plus the monotonic retention watermark (a
//! single scalar in `cold_meta`). The retention job reads/advances these; the
//! cold-query planner uses `cold_archives_overlapping` to pick archives.

use garmr_core::{ColdArchive, ColdDeletion, Error, Result, Tombstone};
use redb::{ReadableTable, ReadableTableMetadata};

use super::{StateStore, COLD_ARCHIVES, COLD_DELETIONS, COLD_META, TOMBSTONES};

impl StateStore {
    /// Record (insert or overwrite by window id) a sealed cold archive.
    pub fn put_cold_archive(&self, arc: &ColdArchive) -> Result<()> {
        let bytes = serde_json::to_vec(arc).map_err(Error::store)?;
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(COLD_ARCHIVES).map_err(Error::store)?;
            t.insert(arc.id.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// All cold archives, oldest window first.
    pub fn list_cold_archives(&self) -> Result<Vec<ColdArchive>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(COLD_ARCHIVES).map_err(Error::store)?;
        let mut out = Vec::with_capacity(t.len().map_err(Error::store)? as usize);
        for row in t.iter().map_err(Error::store)? {
            let (_, v) = row.map_err(Error::store)?;
            out.push(serde_json::from_slice::<ColdArchive>(v.value()).map_err(Error::store)?);
        }
        out.sort_by_key(|a| a.start_us);
        Ok(out)
    }

    /// Cold archives whose window overlaps `[from_us, to_us)` (either bound
    /// `None` = unbounded), oldest first — the query planner for the cold tier.
    pub fn cold_archives_overlapping(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
    ) -> Result<Vec<ColdArchive>> {
        Ok(self
            .list_cold_archives()?
            .into_iter()
            .filter(|a| a.overlaps(from_us, to_us))
            .collect())
    }

    /// Remove a cold archive from the manifest.
    ///
    /// The manifest row only — the caller deletes the file, in that order: a
    /// manifest entry pointing at a missing file makes every cold query fail,
    /// whereas an orphaned file is inert and reclaimable. Returns whether a row
    /// was actually removed, so a caller can tell a real deletion from a no-op
    /// and not audit something that never happened.
    pub fn delete_cold_archive(&self, id: &str) -> Result<bool> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let existed;
        {
            let mut t = wtx.open_table(COLD_ARCHIVES).map_err(Error::store)?;
            existed = t.remove(id).map_err(Error::store)?.is_some();
        }
        wtx.commit().map_err(Error::store)?;
        Ok(existed)
    }

    /// Record that an archive was deleted, keyed by its old window id.
    ///
    /// Written in the SAME transaction that removes the manifest row, so the two
    /// can never disagree: there is no instant at which the archive is gone from
    /// the manifest with no tombstone explaining where it went, and no
    /// tombstone for an archive that is still live.
    pub fn delete_cold_archive_recorded(&self, del: &ColdDeletion) -> Result<bool> {
        let bytes = serde_json::to_vec(del).map_err(Error::store)?;
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let existed;
        {
            let mut t = wtx.open_table(COLD_ARCHIVES).map_err(Error::store)?;
            existed = t.remove(del.id.as_str()).map_err(Error::store)?.is_some();
        }
        {
            let mut d = wtx.open_table(COLD_DELETIONS).map_err(Error::store)?;
            d.insert(del.id.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(existed)
    }

    /// Every recorded deletion, oldest window first — the deletion ledger an
    /// operator shows when asked to prove what was removed.
    pub fn list_cold_deletions(&self) -> Result<Vec<ColdDeletion>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(COLD_DELETIONS).map_err(Error::store)?;
        let mut out = Vec::with_capacity(t.len().map_err(Error::store)? as usize);
        for row in t.iter().map_err(Error::store)? {
            let (_, v) = row.map_err(Error::store)?;
            out.push(serde_json::from_slice::<ColdDeletion>(v.value()).map_err(Error::store)?);
        }
        out.sort_by_key(|d| d.start_us);
        Ok(out)
    }

    /// Mark archives as having had their hot rows pruned by a compaction.
    ///
    /// Called AFTER the rebuild swap commits — the flag asserts "the hot store
    /// no longer holds this window's rows", and setting it any earlier would
    /// record something a crash could still make false.
    pub fn mark_cold_archives_hot_pruned(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(COLD_ARCHIVES).map_err(Error::store)?;
            for id in ids {
                let Some(raw) = t.get(id.as_str()).map_err(Error::store)? else {
                    continue; // expired between listing and now — nothing to mark
                };
                let mut arc: ColdArchive =
                    serde_json::from_slice(raw.value()).map_err(Error::store)?;
                drop(raw);
                if arc.hot_pruned {
                    continue;
                }
                arc.hot_pruned = true;
                let bytes = serde_json::to_vec(&arc).map_err(Error::store)?;
                t.insert(id.as_str(), bytes.as_slice())
                    .map_err(Error::store)?;
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Persist an erasure tombstone, keyed by id (idempotent overwrite).
    pub fn put_tombstone(&self, t: &Tombstone) -> Result<()> {
        let bytes = serde_json::to_vec(t).map_err(Error::store)?;
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut tab = wtx.open_table(TOMBSTONES).map_err(Error::store)?;
            tab.insert(t.id.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Every erasure tombstone, oldest placement first.
    pub fn list_tombstones(&self) -> Result<Vec<Tombstone>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(TOMBSTONES).map_err(Error::store)?;
        let mut out = Vec::with_capacity(t.len().map_err(Error::store)? as usize);
        for row in t.iter().map_err(Error::store)? {
            let (_, v) = row.map_err(Error::store)?;
            out.push(serde_json::from_slice::<Tombstone>(v.value()).map_err(Error::store)?);
        }
        out.sort_by_key(|t| t.placed_at);
        Ok(out)
    }

    /// Place or clear a legal hold. A held archive is exempt from expiry until
    /// a human clears it — the point of a hold is that a scheduled process
    /// cannot quietly override it.
    pub fn set_cold_legal_hold(&self, id: &str, hold: bool) -> Result<bool> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let changed;
        {
            let mut t = wtx.open_table(COLD_ARCHIVES).map_err(Error::store)?;
            // Read and decode into an owned value, then END the borrow before
            // the write — redb's accessor holds an immutable borrow of the table.
            let current: Option<ColdArchive> = match t.get(id).map_err(Error::store)? {
                Some(v) => Some(serde_json::from_slice(v.value()).map_err(Error::store)?),
                None => None,
            };
            match current {
                Some(mut arc) => {
                    changed = arc.legal_hold != hold;
                    arc.legal_hold = hold;
                    let body = serde_json::to_vec(&arc).map_err(Error::store)?;
                    t.insert(id, body.as_slice()).map_err(Error::store)?;
                }
                None => changed = false,
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(changed)
    }

    /// The retention watermark: the exclusive upper `event_ts` (micros) bound of
    /// windows already rolled to cold. `None` if retention has never run.
    pub fn cold_watermark_us(&self) -> Result<Option<i64>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(COLD_META).map_err(Error::store)?;
        Ok(t.get("watermark_us")
            .map_err(Error::store)?
            .map(|v| v.value()))
    }

    /// Advance the retention watermark. Monotonic: a lower value is ignored so a
    /// stale caller can never rewind what's already been archived.
    pub fn set_cold_watermark_us(&self, us: i64) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(COLD_META).map_err(Error::store)?;
            let cur = t
                .get("watermark_us")
                .map_err(Error::store)?
                .map(|v| v.value());
            if cur.is_none_or(|c| us > c) {
                t.insert("watermark_us", us).map_err(Error::store)?;
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use garmr_core::{expired_archives, ColdArchive};

    const DAY_US: i64 = 86_400_000_000;

    fn tmp_state() -> (crate::state::StateStore, std::path::PathBuf) {
        // Nanosecond suffix rather than a uuid dep: this crate does not carry
        // uuid, and a unique temp path is all the test needs.
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("garmr-cold-{n}"));
        (crate::state::StateStore::open(&p).unwrap(), p)
    }

    fn arc(id: &str, end_day: i64) -> ColdArchive {
        ColdArchive {
            id: id.into(),
            kind: "znippy".into(),
            file: format!("{id}.znippy"),
            start_us: (end_day - 1) * DAY_US,
            end_us: end_day * DAY_US,
            rows: 100,
            bytes_in: 1000,
            bytes_out: 200,
            checksum: "abc".into(),
            hot_pruned: false,
            sealed_at: chrono::Utc::now(),
            legal_hold: false,
        }
    }

    #[test]
    fn a_held_archive_survives_an_expiry_run_that_deletes_its_neighbour() {
        let (st, dir) = tmp_state();
        st.put_cold_archive(&arc("held", 2)).unwrap();
        st.put_cold_archive(&arc("free", 2)).unwrap();

        // Placing the hold must persist through a reload of the manifest — a
        // hold that lives only in memory is not a hold.
        assert!(st.set_cold_legal_hold("held", true).unwrap());
        let stored = st.list_cold_archives().unwrap();
        assert!(stored.iter().find(|a| a.id == "held").unwrap().legal_hold);

        let (expiring, held) = expired_archives(&stored, 10 * DAY_US);
        assert_eq!(expiring.len(), 1, "only the unheld archive may expire");
        assert_eq!(expiring[0].id, "free");
        assert_eq!(held.len(), 1);

        // Delete exactly what the policy chose, and nothing else.
        assert!(st.delete_cold_archive("free").unwrap());
        let after: Vec<String> = st
            .list_cold_archives()
            .unwrap()
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(after, vec!["held".to_string()]);

        // Deleting again reports false — the caller must be able to tell a real
        // deletion from a no-op, so it never audits something that did not happen.
        assert!(!st.delete_cold_archive("free").unwrap());

        // Clearing the hold makes it expirable, and reports that it changed.
        assert!(st.set_cold_legal_hold("held", false).unwrap());
        assert!(
            !st.set_cold_legal_hold("held", false).unwrap(),
            "a no-op hold change must report false"
        );
        let remaining = st.list_cold_archives().unwrap();
        let (expiring, held) = expired_archives(&remaining, 10 * DAY_US);
        assert_eq!(expiring.len(), 1);
        assert!(held.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_hold_on_an_unknown_archive_is_a_no_op_not_an_error() {
        // The CLI reports "no change" rather than failing: an operator typo must
        // not look like a system fault during an erasure request.
        let (st, dir) = tmp_state();
        assert!(!st.set_cold_legal_hold("does-not-exist", true).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }
}
