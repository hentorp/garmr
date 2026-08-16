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
    /// Write a case, MERGING against the stored row so a stale snapshot cannot
    /// clobber concurrent state.
    ///
    /// The agent's triage loop holds a clone of the case for the whole loop —
    /// seconds to minutes — while an analyst may assign it, tag it, or leave a
    /// note. Without the merge, the loop's final `put_case` would silently wipe
    /// everything the analyst did in between: the lost-update bug that makes a
    /// two-analyst queue unusable. The rules, field by field:
    ///
    /// - `event_count`: max (a concurrent bump must not be lost) — pre-existing.
    /// - `assignee`: the incoming value wins only when SET. `put_case` never
    ///   UNASSIGNS: clearing an owner is an explicit human act and goes through
    ///   [`assign_case`](Self::assign_case), so a snapshot from before the
    ///   assignment cannot revert it.
    /// - `tags` / `linked_cases`: set union — both sides' additions survive.
    /// - `transcript`: entries with an `entry_id` (human notes) present in the
    ///   stored row but missing from the snapshot are re-inserted, ordered by
    ///   timestamp. Agent entries (empty id) are append-only by construction and
    ///   need no identity.
    /// - `state_changed_at`: stamped HERE, the one chokepoint every write
    ///   passes, whenever the state actually differs from the stored row — a
    ///   wrong SLA anchor is worse than none, so it is not left to call sites.
    pub fn put_case(&self, case: &Case) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(CASES).map_err(Error::store)?;
            let mut to_write = case.clone();
            match t.get(case.id.as_str()).map_err(Error::store)? {
                Some(existing) => {
                    if let Ok(prev) = serde_json::from_slice::<Case>(existing.value()) {
                        to_write.event_count = to_write.event_count.max(prev.event_count);
                        if to_write.assignee.is_none() {
                            to_write.assignee = prev.assignee.clone();
                        }
                        for tag in &prev.tags {
                            if !to_write.tags.contains(tag) {
                                to_write.tags.push(tag.clone());
                            }
                        }
                        for l in &prev.linked_cases {
                            if !to_write.linked_cases.contains(l) {
                                to_write.linked_cases.push(l.clone());
                            }
                        }
                        let have: std::collections::HashSet<&str> = to_write
                            .transcript
                            .iter()
                            .filter(|e| !e.entry_id.is_empty())
                            .map(|e| e.entry_id.as_str())
                            .collect();
                        let missing: Vec<_> = prev
                            .transcript
                            .iter()
                            .filter(|e| {
                                !e.entry_id.is_empty() && !have.contains(e.entry_id.as_str())
                            })
                            .cloned()
                            .collect();
                        if !missing.is_empty() {
                            to_write.transcript.extend(missing);
                            to_write.transcript.sort_by_key(|e| e.at);
                        }
                        to_write.state_changed_at = if to_write.state == prev.state {
                            prev.state_changed_at.or(to_write.state_changed_at)
                        } else {
                            Some(chrono::Utc::now())
                        };
                    }
                }
                None => {
                    if to_write.state_changed_at.is_none() {
                        to_write.state_changed_at = Some(to_write.opened_at);
                    }
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

    /// Read-modify-write one case atomically. The closure sees the STORED row
    /// (never a caller's possibly-stale clone) and returns whether it changed
    /// anything. This is how the ownership routes mutate: `put_case`'s merge
    /// protects analyst state from the agent, and these protect analyst edits
    /// from EACH OTHER.
    pub fn mutate_case(&self, id: &str, f: impl FnOnce(&mut Case) -> bool) -> Result<Option<Case>> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let out;
        {
            let mut t = wtx.open_table(CASES).map_err(Error::store)?;
            let Some(raw) = t.get(id).map_err(Error::store)? else {
                return Ok(None);
            };
            let mut case: Case = serde_json::from_slice(raw.value()).map_err(Error::store)?;
            drop(raw);
            if f(&mut case) {
                case.updated_at = chrono::Utc::now();
                let bytes = serde_json::to_vec(&case).map_err(Error::store)?;
                t.insert(id, bytes.as_slice()).map_err(Error::store)?;
            }
            out = Some(case);
        }
        wtx.commit().map_err(Error::store)?;
        Ok(out)
    }

    /// Link two cases, both directions, in ONE transaction — a one-sided link
    /// that survives a crash would point at a case that does not point back,
    /// and the console would render the relationship on one side only.
    pub fn link_cases(&self, a: &str, b: &str) -> Result<bool> {
        if a == b {
            return Ok(false);
        }
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let mut linked = false;
        {
            let mut t = wtx.open_table(CASES).map_err(Error::store)?;
            let read = |t: &redb::Table<&str, &[u8]>, id: &str| -> Result<Option<Case>> {
                Ok(match t.get(id).map_err(Error::store)? {
                    Some(raw) => Some(serde_json::from_slice(raw.value()).map_err(Error::store)?),
                    None => None,
                })
            };
            let (Some(mut ca), Some(mut cb)) = (read(&t, a)?, read(&t, b)?) else {
                return Ok(false); // both must exist — no dangling links
            };
            if !ca.linked_cases.contains(&cb.id) {
                ca.linked_cases.push(cb.id.clone());
                linked = true;
            }
            if !cb.linked_cases.contains(&ca.id) {
                cb.linked_cases.push(ca.id.clone());
                linked = true;
            }
            if linked {
                let now = chrono::Utc::now();
                ca.updated_at = now;
                cb.updated_at = now;
                let ba = serde_json::to_vec(&ca).map_err(Error::store)?;
                t.insert(a, ba.as_slice()).map_err(Error::store)?;
                let bb = serde_json::to_vec(&cb).map_err(Error::store)?;
                t.insert(b, bb.as_slice()).map_err(Error::store)?;
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(linked)
    }

    /// Apply SLA breach markers for one tick. Returns the cases that NEWLY
    /// breached (id, which clock) — the caller's digest is built from exactly
    /// this list, so one tick produces one digest and a second tick produces
    /// silence.
    ///
    /// Once-only is carried by the breach TAGS (`sla:ack` / `sla:resolve`):
    /// a tagged case is skipped, and tags survive both the put_case merge and
    /// analyst edits, so a breach can never re-fire because a snapshot raced.
    /// The transcript entry gets an entry_id for the same merge-survival
    /// reason any human-adjacent entry does.
    pub fn apply_sla_breaches(
        &self,
        cfg: &garmr_core::SlaConfig,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<(String, garmr_core::sla::SlaStatus)>> {
        if cfg.ack_minutes == 0 && cfg.resolve_minutes == 0 {
            return Ok(Vec::new());
        }
        let mut newly = Vec::new();
        for case in self.list_cases()? {
            let Some(status) = garmr_core::sla::sla_status(&case, cfg, now) else {
                continue;
            };
            let want_ack = status.ack_breached && !case.tags.iter().any(|t| t == "sla:ack");
            let want_resolve =
                status.resolve_breached && !case.tags.iter().any(|t| t == "sla:resolve");
            if !want_ack && !want_resolve {
                continue;
            }
            self.mutate_case(&case.id, |c| {
                let mut changed = false;
                if want_ack && !c.tags.iter().any(|t| t == "sla:ack") {
                    c.tags.push("sla:ack".into());
                    c.transcript.push(garmr_core::TranscriptEntry {
                        at: now,
                        actor: "sla".into(),
                        detail: format!(
                            "ack SLA breached — unassigned in the human queue past {} min",
                            cfg.ack_minutes
                        ),
                        // Deterministic: a breach is once-only per (case, clock),
                        // so a content-derived id makes any conceivable re-merge
                        // idempotent by construction — no randomness needed.
                        entry_id: format!("sla:ack:{}", c.id),
                    });
                    changed = true;
                }
                if want_resolve && !c.tags.iter().any(|t| t == "sla:resolve") {
                    c.tags.push("sla:resolve".into());
                    c.transcript.push(garmr_core::TranscriptEntry {
                        at: now,
                        actor: "sla".into(),
                        detail: format!(
                            "resolve SLA breached — open past {} min",
                            cfg.resolve_minutes
                        ),
                        entry_id: format!("sla:resolve:{}", c.id),
                    });
                    changed = true;
                }
                changed
            })?;
            newly.push((case.id.clone(), status));
        }
        Ok(newly)
    }

    /// Delete the given case ids in one write transaction (case retention /
    /// cleanup). Returns the number actually removed; ids not present are
    /// silently skipped. The CLI (`garmr cases prune`) selects which ids to
    /// delete — the store just applies it atomically.
    ///
    /// Cascades to the case-scoped record ranges (predictions and decisions,
    /// keyed `case_id|…`). Those tables are append-only and were never cleaned:
    /// pruning a case while keeping its records left rows no surface could
    /// reach — every reader goes through the case — so they were not "retained
    /// history", they were unreachable bytes accumulating forever. The cascade
    /// runs in the SAME transaction as the case removal: a crash between the
    /// two would otherwise strand exactly the orphans this exists to prevent.
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
        for table in [super::PREDICTIONS, super::DECISIONS] {
            let mut t = wtx.open_table(table).map_err(Error::store)?;
            for id in ids {
                // The same prefix bounds scan_case_limited uses: `|` keeps a
                // sibling id sharing the prefix (c1 vs c10) out of the range.
                let prefix = format!("{id}|");
                let end = format!("{prefix}\u{10ffff}");
                let keys: Vec<String> = t
                    .range(prefix.as_str()..=end.as_str())
                    .map_err(Error::store)?
                    .map(|row| row.map(|(k, _)| k.value().to_string()))
                    .collect::<std::result::Result<_, _>>()
                    .map_err(Error::store)?;
                for k in keys {
                    t.remove(k.as_str()).map_err(Error::store)?;
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
