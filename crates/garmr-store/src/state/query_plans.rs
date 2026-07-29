// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Stored compiled query plans — the typed `HybridQuery` IR a natural-language
//! `ask` compiled to, keyed by a content id, so a past answer can be **reproduced
//! deterministically without the model**. Opaque JSON (the api layer owns the
//! shape); content-addressed keying means identical asks collapse to one entry.

use garmr_core::{Error, Result};

use super::{StateStore, QUERY_PLANS};

impl StateStore {
    /// Persist a compiled query plan (the `HybridQuery` IR, JSON) under its
    /// content id. Idempotent: the same plan re-stores to the same key.
    pub fn put_query_plan(&self, query_id: &str, json: &[u8]) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(QUERY_PLANS).map_err(Error::store)?;
            t.insert(query_id, json).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Fetch a stored query plan by content id (`None` if never stored / evicted).
    pub fn get_query_plan(&self, query_id: &str) -> Result<Option<Vec<u8>>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(QUERY_PLANS).map_err(Error::store)?;
        Ok(t.get(query_id)
            .map_err(Error::store)?
            .map(|v| v.value().to_vec()))
    }
}