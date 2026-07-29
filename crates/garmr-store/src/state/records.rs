// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 3 append-only record persistence: agent predictions, analyst decisions,
//! incident outcomes, feedback, false-negatives, and mistakes.
//!
//! Unlike `put_case` (overwrite by id), these tables are **append-only**: each
//! record lands under a unique key, so history is never overwritten — a
//! correction is a new row whose `supersedes` points at the id it replaces.
//! Case-scoped records key on `{case_id}|{created_at_nanos}|{id}` so a case's
//! history reads back chronologically; caseless-capable records key on their own
//! id. Every reader **tolerantly skips** an undecodable row (logs + continues)
//! so one poison row can never fail a whole listing — the opposite of
//! `list_cases`, which `?`s and would take the case surface down with it.

use chrono::{DateTime, Utc};
use garmr_core::{
    AgentPrediction, AnalystDecision, CaseDecisionView, Error, FalseNegativeRecord, FeedbackRecord,
    IncidentOutcome, MistakeRecord, Result,
};
use redb::{ReadableTable, TableDefinition};
use serde::de::DeserializeOwned;

use super::{
    StateStore, DECISIONS, FALSE_NEGATIVES, FEEDBACK_REC, INCIDENT_OUTCOMES, MISTAKES, PREDICTIONS,
};

/// Newest-N cap applied to each sub-list of a [`StateStore::case_view`] and the
/// default budget for a bounded read. A single case's append-only history is
/// unbounded in principle (every re-triage and correction appends a row), so a
/// hot case must never load its whole history into memory (issue #19). 1000 is
/// far more revisions than any real case accrues, yet caps the Vec. Override at
/// runtime with `GARMR_CASE_VIEW_MAX` for an unusually deep audit trail.
const CASE_VIEW_MAX_PER_LIST: usize = 1000;

/// Resolve the per-list newest-N cap, honoring the `GARMR_CASE_VIEW_MAX`
/// override (a non-parsing or zero value falls back to the compiled default).
fn case_view_cap() -> usize {
    std::env::var("GARMR_CASE_VIEW_MAX")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(CASE_VIEW_MAX_PER_LIST)
}

/// Case-scoped key: `{case_id}|{created_at_nanos:020}|{id}` — unique (append-only,
/// never overwrites) and lexicographically chronological within a case.
fn rec_key(case_id: &str, created_at: DateTime<Utc>, id: &str) -> String {
    format!(
        "{case_id}|{:020}|{id}",
        created_at.timestamp_nanos_opt().unwrap_or(0)
    )
}

impl StateStore {
    fn append_bytes(
        &self,
        table: TableDefinition<&str, &[u8]>,
        key: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(table).map_err(Error::store)?;
            t.insert(key, bytes).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Scan a whole table, tolerantly skipping any row that fails to decode.
    pub(crate) fn scan_tolerant<T: DeserializeOwned>(
        &self,
        table: TableDefinition<&str, &[u8]>,
        what: &str,
    ) -> Result<Vec<T>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(table).map_err(Error::store)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(Error::store)? {
            let (_, v) = row.map_err(Error::store)?;
            match serde_json::from_slice::<T>(v.value()) {
                Ok(r) => out.push(r),
                Err(e) => {
                    tracing::warn!(error = %e, table = what, "skipping undecodable record row")
                }
            }
        }
        Ok(out)
    }

    /// Newest-first, at most `limit` rows for one case from a **case-scoped**
    /// table keyed `{case_id}|{nanos}|{id}`. Reads only that case's key range and
    /// stops after `limit` decoded rows, so a case's history never materializes
    /// the whole table into memory (issue #19). Tolerantly skips undecodable rows.
    ///
    /// The `{case_id}|` .. `{case_id}|\u{10ffff}` range is exact even when one case
    /// id is a prefix of another (`c1` vs `c10`): the digit `0` (0x30) sorts BELOW
    /// the `|` separator (0x7C), so every `c10|…` key falls *before* the `c1|`
    /// start bound and is excluded — the same guard `predictions_for` relies on.
    pub(crate) fn scan_case_limited<T: DeserializeOwned>(
        &self,
        table: TableDefinition<&str, &[u8]>,
        case_id: &str,
        limit: usize,
        what: &str,
    ) -> Result<Vec<T>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(table).map_err(Error::store)?;
        let prefix = format!("{case_id}|");
        let end = format!("{prefix}\u{10ffff}");
        let mut out = Vec::new();
        // `.rev()` walks the case range newest → oldest so the cap keeps the most
        // recent revisions (redb `Range` is a DoubleEndedIterator).
        for row in t
            .range(prefix.as_str()..=end.as_str())
            .map_err(Error::store)?
            .rev()
        {
            if out.len() >= limit {
                break;
            }
            let (_, value) = row.map_err(Error::store)?;
            match serde_json::from_slice::<T>(value.value()) {
                Ok(r) => out.push(r),
                Err(e) => {
                    tracing::warn!(error = %e, table = what, "skipping undecodable record row")
                }
            }
        }
        Ok(out) // newest-first
    }

    /// Bounded whole-table scan: at most `limit` decoded rows, tolerantly
    /// skipping undecodable ones. Caps the returned Vec so a caseless-capable
    /// table (keyed by its own uuid, with no case range to scope a read) can
    /// never be loaded whole into memory the way [`Self::scan_tolerant`] would
    /// (issue #19). Iteration stops as soon as `limit` rows are collected.
    pub(crate) fn scan_tolerant_limited<T: DeserializeOwned>(
        &self,
        table: TableDefinition<&str, &[u8]>,
        what: &str,
        limit: usize,
    ) -> Result<Vec<T>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(table).map_err(Error::store)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(Error::store)? {
            if out.len() >= limit {
                break;
            }
            let (_, v) = row.map_err(Error::store)?;
            match serde_json::from_slice::<T>(v.value()) {
                Ok(r) => out.push(r),
                Err(e) => {
                    tracing::warn!(error = %e, table = what, "skipping undecodable record row")
                }
            }
        }
        Ok(out)
    }

    // ---- agent predictions (case-scoped) ----

    pub fn append_prediction(&self, p: &AgentPrediction) -> Result<()> {
        let bytes = serde_json::to_vec(p).map_err(Error::store)?;
        self.append_bytes(
            PREDICTIONS,
            &rec_key(&p.case_id, p.created_at, &p.prediction_id),
            &bytes,
        )
    }

    /// All predictions across all cases (for the RBA scoring pass).
    pub fn list_predictions(&self) -> Result<Vec<AgentPrediction>> {
        self.scan_tolerant(PREDICTIONS, "prediction")
    }

    /// A case's predictions, oldest → newest.
    pub fn predictions_for(&self, case_id: &str) -> Result<Vec<AgentPrediction>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(PREDICTIONS).map_err(Error::store)?;
        let prefix = format!("{case_id}|");
        let end = format!("{prefix}\u{10ffff}");
        let mut out = Vec::new();
        for row in t
            .range(prefix.as_str()..=end.as_str())
            .map_err(Error::store)?
        {
            let (_, value) = row.map_err(Error::store)?;
            match serde_json::from_slice::<AgentPrediction>(value.value()) {
                Ok(prediction) => out.push(prediction),
                Err(e) => {
                    tracing::warn!(error = %e, table = "prediction", "skipping undecodable record row")
                }
            }
        }
        Ok(out)
    }

    // ---- analyst decisions (case-scoped) ----

    pub fn append_decision(&self, d: &AnalystDecision) -> Result<()> {
        let bytes = serde_json::to_vec(d).map_err(Error::store)?;
        self.append_bytes(
            DECISIONS,
            &rec_key(&d.case_id, d.created_at, &d.decision_id),
            &bytes,
        )
    }

    pub fn list_decisions(&self) -> Result<Vec<AnalystDecision>> {
        self.scan_tolerant(DECISIONS, "decision")
    }

    pub fn decisions_for(&self, case_id: &str) -> Result<Vec<AnalystDecision>> {
        let mut v: Vec<AnalystDecision> = self
            .list_decisions()?
            .into_iter()
            .filter(|d| d.case_id == case_id)
            .collect();
        v.sort_by_key(|d| d.created_at);
        Ok(v)
    }

    // ---- incident outcomes (caseless-capable) ----

    pub fn append_incident_outcome(&self, o: &IncidentOutcome) -> Result<()> {
        let bytes = serde_json::to_vec(o).map_err(Error::store)?;
        self.append_bytes(INCIDENT_OUTCOMES, &o.outcome_id, &bytes)
    }

    pub fn list_incident_outcomes(&self) -> Result<Vec<IncidentOutcome>> {
        self.scan_tolerant(INCIDENT_OUTCOMES, "incident_outcome")
    }

    pub fn outcomes_for_case(&self, case_id: &str) -> Result<Vec<IncidentOutcome>> {
        let mut v: Vec<IncidentOutcome> = self
            .list_incident_outcomes()?
            .into_iter()
            .filter(|o| o.case_id.as_deref() == Some(case_id))
            .collect();
        v.sort_by_key(|o| o.created_at);
        Ok(v)
    }

    /// Case-scoped incident outcomes, capped at `limit` rows in memory (sorted
    /// oldest → newest). Like [`Self::false_negatives_for_case_limited`], the
    /// table is uuid-keyed so this walks the key space but never materializes
    /// more than `limit` matches — the bound `case_view` needs (issue #19).
    fn outcomes_for_case_limited(
        &self,
        case_id: &str,
        limit: usize,
    ) -> Result<Vec<IncidentOutcome>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(INCIDENT_OUTCOMES).map_err(Error::store)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(Error::store)? {
            if out.len() >= limit {
                break;
            }
            let (_, v) = row.map_err(Error::store)?;
            match serde_json::from_slice::<IncidentOutcome>(v.value()) {
                Ok(o) if o.case_id.as_deref() == Some(case_id) => out.push(o),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, table = "incident_outcome", "skipping undecodable record row")
                }
            }
        }
        out.sort_by_key(|o| o.created_at);
        Ok(out)
    }

    // ---- feedback (caseless-capable) ----

    pub fn append_feedback(&self, f: &FeedbackRecord) -> Result<()> {
        let bytes = serde_json::to_vec(f).map_err(Error::store)?;
        self.append_bytes(FEEDBACK_REC, &f.feedback_id, &bytes)
    }

    pub fn list_feedback(&self) -> Result<Vec<FeedbackRecord>> {
        self.scan_tolerant(FEEDBACK_REC, "feedback")
    }

    // ---- false negatives (caseless-capable) ----

    pub fn append_false_negative(&self, f: &FalseNegativeRecord) -> Result<()> {
        let bytes = serde_json::to_vec(f).map_err(Error::store)?;
        self.append_bytes(FALSE_NEGATIVES, &f.fn_id, &bytes)
    }

    pub fn list_false_negatives(&self) -> Result<Vec<FalseNegativeRecord>> {
        self.scan_tolerant(FALSE_NEGATIVES, "false_negative")
    }

    /// Bounded variant of [`Self::list_false_negatives`]: at most `limit` rows,
    /// so the `/api/false-negatives` read never deserializes the whole table
    /// just to slice out one page (issue #19). The handler passes the page
    /// window (`offset + limit`, already clamped to `MAX_PAGE_LIMIT`) as `limit`.
    pub fn list_false_negatives_limited(&self, limit: usize) -> Result<Vec<FalseNegativeRecord>> {
        self.scan_tolerant_limited(FALSE_NEGATIVES, "false_negative", limit)
    }

    pub fn false_negatives_for_case(&self, case_id: &str) -> Result<Vec<FalseNegativeRecord>> {
        Ok(self
            .list_false_negatives()?
            .into_iter()
            .filter(|f| f.case_id.as_deref() == Some(case_id))
            .collect())
    }

    /// Case-scoped false negatives, capped at `limit` rows in memory. The table
    /// is keyed by uuid (not case-scoped), so this still walks the key space, but
    /// collects at most `limit` matches — the memory bound `case_view` needs so a
    /// case with many misses can't load an unbounded Vec (issue #19).
    fn false_negatives_for_case_limited(
        &self,
        case_id: &str,
        limit: usize,
    ) -> Result<Vec<FalseNegativeRecord>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(FALSE_NEGATIVES).map_err(Error::store)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(Error::store)? {
            if out.len() >= limit {
                break;
            }
            let (_, v) = row.map_err(Error::store)?;
            match serde_json::from_slice::<FalseNegativeRecord>(v.value()) {
                Ok(f) if f.case_id.as_deref() == Some(case_id) => out.push(f),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, table = "false_negative", "skipping undecodable record row")
                }
            }
        }
        Ok(out)
    }

    // ---- mistakes (caseless-capable) ----

    pub fn append_mistake(&self, m: &MistakeRecord) -> Result<()> {
        let bytes = serde_json::to_vec(m).map_err(Error::store)?;
        self.append_bytes(MISTAKES, &m.mistake_id, &bytes)
    }

    pub fn list_mistakes(&self) -> Result<Vec<MistakeRecord>> {
        self.scan_tolerant(MISTAKES, "mistake")
    }

    /// Assemble the append-only decision history for one case. Each sub-list is
    /// bounded to the newest [`case_view_cap`] revisions so a hot case can never
    /// load an unbounded history into memory (issue #19) — folding to "current"
    /// (done by the core helpers) only ever needs the most recent rows, and no
    /// real case accrues anywhere near the cap. Case-scoped tables
    /// (predictions/decisions) are read by key range and returned oldest → newest
    /// to preserve the prior chronological order; the uuid-keyed caseless tables
    /// (outcomes/false_negatives) are capped by match count.
    pub fn case_view(&self, case_id: &str) -> Result<CaseDecisionView> {
        let cap = case_view_cap();
        // `scan_case_limited` returns newest-first; reverse back to the
        // oldest → newest order callers (and `predictions_for`) expect.
        let mut predictions: Vec<AgentPrediction> =
            self.scan_case_limited(PREDICTIONS, case_id, cap, "prediction")?;
        predictions.reverse();
        let mut decisions: Vec<AnalystDecision> =
            self.scan_case_limited(DECISIONS, case_id, cap, "decision")?;
        decisions.reverse();
        Ok(CaseDecisionView {
            case_id: case_id.to_string(),
            predictions,
            decisions,
            outcomes: self.outcomes_for_case_limited(case_id, cap)?,
            false_negatives: self.false_negatives_for_case_limited(case_id, cap)?,
        })
    }
}