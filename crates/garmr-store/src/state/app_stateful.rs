// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The application-audit **stateful detector** plane — a single serialized
//! `garmr_appdetect::stateful::StatefulState` blob (opaque JSON; the app-audit
//! layer owns the shape). Stored under one reserved key so load/flush is a
//! whole-store snapshot, exactly like the behavioral-baseline store — an
//! in-progress enumeration/probing episode survives a restart.

use garmr_core::{Error, Result};

use super::{StateStore, APP_STATEFUL};

/// The single reserved key the whole stateful-detector state lives under.
const KEY: &str = "store";

impl StateStore {
    /// Persist the serialized stateful-detector state (whole-store snapshot).
    pub fn put_app_stateful(&self, json: &[u8]) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(APP_STATEFUL).map_err(Error::store)?;
            t.insert(KEY, json).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Fetch the serialized stateful-detector state, if one has been persisted.
    pub fn get_app_stateful(&self) -> Result<Option<Vec<u8>>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(APP_STATEFUL).map_err(Error::store)?;
        Ok(t.get(KEY)
            .map_err(Error::store)?
            .map(|v| v.value().to_vec()))
    }
}
