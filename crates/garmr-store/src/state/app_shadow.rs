// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! DoD 19 champion/challenger **shadow-evaluation** summary — the running
//! comparison counters, one opaque JSON blob (the cli layer owns the shape)
//! stored under a single reserved key, exactly like the stateful-detector state.
//! Only the counters are durable; the recent disagreement examples are an
//! in-memory convenience the read API surfaces live.

use garmr_core::{Error, Result};

use super::{StateStore, APP_SHADOW};

/// The single reserved key the shadow summary lives under.
const KEY: &str = "summary";

impl StateStore {
    /// Persist the serialized shadow-evaluation summary (whole-blob upsert).
    pub fn put_app_shadow_summary(&self, json: &[u8]) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(APP_SHADOW).map_err(Error::store)?;
            t.insert(KEY, json).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Fetch the serialized shadow-evaluation summary, if one has been persisted.
    pub fn get_app_shadow_summary(&self) -> Result<Option<Vec<u8>>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(APP_SHADOW).map_err(Error::store)?;
        Ok(t.get(KEY).map_err(Error::store)?.map(|v| v.value().to_vec()))
    }
}