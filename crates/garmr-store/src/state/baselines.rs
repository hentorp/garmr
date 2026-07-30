// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-host baseline blobs (opaque JSON, keyed by host) — the analytics layer
//! owns the shape; the store only persists and fetches the bytes.

use garmr_core::{Error, Result};

use super::{StateStore, BASELINES};

impl StateStore {
    /// Store a JSON baseline blob for a host.
    pub fn put_baseline(&self, host: &str, json: &[u8]) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(BASELINES).map_err(Error::store)?;
            t.insert(host, json).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Fetch a host baseline blob.
    pub fn get_baseline(&self, host: &str) -> Result<Option<Vec<u8>>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(BASELINES).map_err(Error::store)?;
        Ok(t.get(host)
            .map_err(Error::store)?
            .map(|v| v.value().to_vec()))
    }
}
