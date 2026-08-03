// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Case persistence: the triage cases + their transcripts, keyed by id in the
//! `cases` table. Includes the monotonic `event_count` merge (burst-collapse)
//! and the institutional-memory search over past cases.

use garmr_core::{Case, Error, Result};
use redb::{ReadableTable, ReadableTableMetadata};

use super::{StateStore, CASES};

impl StateStore {
    /// Persist a case (insert or overwrite by id). `event_count` is merged
    /// monotonically inside the write transaction: a caller holding a stale
    /// snapshot (e.g. a detached triage task that started when the count was 1)
    /// can never lower a count that the ingest pipeline has since bumped.
    /// redb serializes writers, so this read-then-write is atomic against other
    /// writers — no lost update.
    pub fn put_case(&self, case: &Case) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(CASES).map_err(Error::store)?;
            let mut to_write = case.clone();
            if let Some(existing) = t.get(case.id.as_str()).map_err(Error::store)? {
                if let Ok(prev) = serde_json::from_slice::<Case>(existing.value()) {
                    to_write.event_count = to_write.event_count.max(prev.event_count);
                }
            }
            let bytes = serde_json::to_vec(&to_write).map_err(Error::store)?;
            t.insert(case.id.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Atomically bump a case's `event_count` in a single write transaction
    /// (the burst-collapse path). Returns the new count, or `None` if the case
    /// no longer exists. Race-free: the read and write share one txn.
    pub fn bump_event_count(
        &self,
        id: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<u64>> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let new_count;
        {
            let mut t = wtx.open_table(CASES).map_err(Error::store)?;
            let Some(bytes) = t.get(id).map_err(Error::store)?.map(|v| v.value().to_vec()) else {
                return Ok(None);
            };
            let mut case: Case = serde_json::from_slice(&bytes).map_err(Error::store)?;
            case.event_count += 1;
            case.updated_at = at;
            new_count = case.event_count;
            let out = serde_json::to_vec(&case).map_err(Error::store)?;
            t.insert(id, out.as_slice()).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(Some(new_count))
    }

    /// Fetch one case by id.
    pub fn get_case(&self, id: &str) -> Result<Option<Case>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(CASES).map_err(Error::store)?;
        match t.get(id).map_err(Error::store)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).map_err(Error::store)?,
            )),
            None => Ok(None),
        }
    }

    /// All cases, newest first. Fine to scan for a single-person SOC.
    pub fn list_cases(&self) -> Result<Vec<Case>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(CASES).map_err(Error::store)?;
        let mut cases = Vec::with_capacity(t.len().map_err(Error::store)? as usize);
        for row in t.iter().map_err(Error::store)? {
            let (_, v) = row.map_err(Error::store)?;
            cases.push(serde_json::from_slice::<Case>(v.value()).map_err(Error::store)?);
        }
        cases.sort_by_key(|c| std::cmp::Reverse(c.opened_at));
        Ok(cases)
    }

    /// Delete the given case ids in one write transaction (case retention /
    /// cleanup). Returns the number actually removed; ids not present are
    /// silently skipped. The CLI (`garmr cases prune`) selects which ids to
    /// delete — the store just applies it atomically.
    pub fn delete_cases(&self, ids: &[String]) -> Result<usize> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let mut removed = 0usize;
        {
            let mut t = wtx.open_table(CASES).map_err(Error::store)?;
            for id in ids {
                if t.remove(id.as_str()).map_err(Error::store)?.is_some() {
                    removed += 1;
                }
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(removed)
    }

    /// Search past cases by a substring over host / IP / rule / rationale —
    /// the agent's institutional memory ("have we seen this before?").
    pub fn search_cases(&self, needle: &str) -> Result<Vec<Case>> {
        let needle = needle.to_lowercase();
        Ok(self
            .list_cases()?
            .into_iter()
            .filter(|c| {
                let hay = format!(
                    "{} {} {} {}",
                    c.trigger.event.host,
                    c.trigger.event.src_ip().unwrap_or(""),
                    c.trigger.rule_id,
                    c.verdict
                        .as_ref()
                        .map(|v| v.rationale.as_str())
                        .unwrap_or("")
                )
                .to_lowercase();
                hay.contains(&needle)
            })
            .collect())
    }
}
