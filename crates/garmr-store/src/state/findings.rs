// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7 findings persistence: the detection plane's `SecurityFinding`s, an
//! append-only analysis record (NOT protected state — it is output, joined to a
//! case by the lowered detection's dedup key). Keyed `{host}|{nanos}|{id}` so a
//! host's findings read back chronologically; readers tolerantly skip an
//! undecodable row (the Phase 3/4/5 idiom).

use garmr_core::{Error, Result, SecurityFinding};

use super::{StateStore, FINDINGS};

impl StateStore {
    /// Append a finding (append-only; never overwrites).
    pub fn put_finding(&self, f: &SecurityFinding) -> Result<()> {
        let key = format!(
            "{}|{:020}|{}",
            f.event.host,
            f.observed_at.timestamp_nanos_opt().unwrap_or(0),
            f.finding_id
        );
        let bytes = serde_json::to_vec(f).map_err(Error::store)?;
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(FINDINGS).map_err(Error::store)?;
            t.insert(key.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// All findings (tolerant scan).
    pub fn list_findings(&self) -> Result<Vec<SecurityFinding>> {
        self.scan_tolerant(FINDINGS, "security_finding")
    }

    /// Findings whose triggering event was on `host`.
    pub fn findings_for_entity(&self, host: &str) -> Result<Vec<SecurityFinding>> {
        Ok(self
            .list_findings()?
            .into_iter()
            .filter(|f| f.event.host == host)
            .collect())
    }
}