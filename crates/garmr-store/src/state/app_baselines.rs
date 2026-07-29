// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The application-audit behavioral-baseline store — a single serialized
//! `garmr_baseline::BaselineStore` blob (opaque JSON; the app-audit layer owns
//! the shape). Stored under one reserved key so load/flush is a whole-store
//! snapshot, mirroring how the environment model persists its learned state.

use garmr_core::{Error, Result};

use super::{StateStore, APP_BASELINES};

/// The single reserved key the whole behavioral-baseline store lives under.
const KEY: &str = "store";

impl StateStore {
    /// Persist the serialized behavioral-baseline store (whole-store snapshot).
    pub fn put_app_baselines(&self, json: &[u8]) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(APP_BASELINES).map_err(Error::store)?;
            t.insert(KEY, json).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Fetch the serialized behavioral-baseline store, if one has been persisted.
    pub fn get_app_baselines(&self) -> Result<Option<Vec<u8>>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(APP_BASELINES).map_err(Error::store)?;
        Ok(t.get(KEY)
            .map_err(Error::store)?
            .map(|v| v.value().to_vec()))
    }
}