// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Hunt-report persistence: the threat-hunt audit trail, keyed by report id in
//! the `hunts` table.

use garmr_core::{Error, HuntReport, Result};
use redb::ReadableTable;

use super::{StateStore, HUNTS};

impl StateStore {
    /// Persist a hunt report (insert or overwrite by report id).
    pub fn put_hunt_report(&self, r: &HuntReport) -> Result<()> {
        let bytes = serde_json::to_vec(r).map_err(Error::store)?;
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(HUNTS).map_err(Error::store)?;
            t.insert(r.id.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Fetch one hunt report by id.
    pub fn get_hunt_report(&self, id: &str) -> Result<Option<HuntReport>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(HUNTS).map_err(Error::store)?;
        match t.get(id).map_err(Error::store)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).map_err(Error::store)?,
            )),
            None => Ok(None),
        }
    }

    /// All hunt reports, newest first.
    pub fn list_hunt_reports(&self) -> Result<Vec<HuntReport>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(HUNTS).map_err(Error::store)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(Error::store)? {
            let (_, v) = row.map_err(Error::store)?;
            out.push(serde_json::from_slice::<HuntReport>(v.value()).map_err(Error::store)?);
        }
        out.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        Ok(out)
    }
}
