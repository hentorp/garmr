// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! "Have we seen this before?" memory for detection: the per-dedup-key
//! suppression (realert) window and the new-template anomaly set. Both are
//! small dedup tables consulted on the hot path — a realert decision per case,
//! a first-seen check per log template.

use garmr_core::{Error, Result};
use redb::{ReadableTable, ReadableTableMetadata};

use super::{StateStore, SUPPRESSION, TEMPLATES};

impl StateStore {
    /// Return the last-seen unix seconds for a dedup key, if within memory.
    pub fn suppression_last(&self, dedup_key: &str) -> Result<Option<u64>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(SUPPRESSION).map_err(Error::store)?;
        Ok(t.get(dedup_key).map_err(Error::store)?.map(|v| v.value()))
    }

    /// Record that a case fired for this dedup key at `now_secs`.
    pub fn suppression_mark(&self, dedup_key: &str, now_secs: u64) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(SUPPRESSION).map_err(Error::store)?;
            t.insert(dedup_key, now_secs).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Record a template's FIRST-seen micros iff not already known; returns
    /// `true` if this call inserted it (i.e. the template is brand new). One
    /// write txn, so concurrent observers of the same new template race-safely
    /// and exactly one sees `true`.
    pub fn note_template(&self, id: &str, first_seen_us: i64) -> Result<bool> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let inserted;
        {
            let mut t = wtx.open_table(TEMPLATES).map_err(Error::store)?;
            if t.get(id).map_err(Error::store)?.is_some() {
                inserted = false;
            } else {
                t.insert(id, first_seen_us).map_err(Error::store)?;
                inserted = true;
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(inserted)
    }

    /// Is this template id already known?
    pub fn template_known(&self, id: &str) -> Result<bool> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(TEMPLATES).map_err(Error::store)?;
        Ok(t.get(id).map_err(Error::store)?.is_some())
    }

    /// Count of known templates (for status/diagnostics).
    pub fn template_count(&self) -> Result<u64> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(TEMPLATES).map_err(Error::store)?;
        t.len().map_err(Error::store)
    }
}