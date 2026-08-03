// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Cold-storage manifest persistence: the sealed-archive records (keyed by
//! window id in `cold_archives`) plus the monotonic retention watermark (a
//! single scalar in `cold_meta`). The retention job reads/advances these; the
//! cold-query planner uses `cold_archives_overlapping` to pick archives.

use garmr_core::{ColdArchive, Error, Result};
use redb::{ReadableTable, ReadableTableMetadata};

use super::{StateStore, COLD_ARCHIVES, COLD_META};

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
