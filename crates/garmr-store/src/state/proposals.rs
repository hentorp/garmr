// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Rule-proposal persistence: agent-authored detection rules awaiting a human
//! decision, keyed by uuid in the `proposals` table. `get_proposal` resolves an
//! exact id or a unique prefix; `decide_proposal` is the one-shot,
//! pending-only transition that keeps a decided proposal immutable.

use garmr_core::{Error, ProposalStatus, Result, RuleProposal};
use redb::ReadableTable;

use super::{StateStore, PROPOSALS};

impl StateStore {
    /// Persist a rule proposal (insert or overwrite by id).
    pub fn put_proposal(&self, p: &RuleProposal) -> Result<()> {
        let bytes = serde_json::to_vec(p).map_err(Error::store)?;
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(PROPOSALS).map_err(Error::store)?;
            t.insert(p.id.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Fetch one proposal by exact id, falling back to a unique id prefix.
    /// An empty id is rejected — every key starts_with("") and a bare
    /// `{"id": ""}` on the admin API must not resolve to the sole proposal.
    pub fn get_proposal(&self, id: &str) -> Result<Option<RuleProposal>> {
        if id.trim().is_empty() {
            return Err(Error::store("empty proposal id"));
        }
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(PROPOSALS).map_err(Error::store)?;
        if let Some(v) = t.get(id).map_err(Error::store)? {
            return Ok(Some(
                serde_json::from_slice(v.value()).map_err(Error::store)?,
            ));
        }
        let mut hit: Option<RuleProposal> = None;
        for row in t.iter().map_err(Error::store)? {
            let (k, v) = row.map_err(Error::store)?;
            if k.value().starts_with(id) {
                if hit.is_some() {
                    return Err(Error::store(format!(
                        "multiple proposals match the prefix {id}"
                    )));
                }
                hit = Some(serde_json::from_slice(v.value()).map_err(Error::store)?);
            }
        }
        Ok(hit)
    }

    /// All proposals, newest first.
    pub fn list_proposals(&self) -> Result<Vec<RuleProposal>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(PROPOSALS).map_err(Error::store)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(Error::store)? {
            let (_, v) = row.map_err(Error::store)?;
            out.push(serde_json::from_slice::<RuleProposal>(v.value()).map_err(Error::store)?);
        }
        out.sort_by_key(|p| std::cmp::Reverse(p.created_at));
        Ok(out)
    }

    /// Decide a proposal in ONE write transaction. Only `pending` proposals can
    /// be decided — a second reviewer racing the first gets a clean error, and
    /// a decided proposal is immutable.
    pub fn decide_proposal(
        &self,
        id: &str,
        status: ProposalStatus,
        note: Option<String>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<RuleProposal> {
        if status == ProposalStatus::Pending {
            return Err(Error::store("a decision cannot be pending"));
        }
        // Resolve prefix OUTSIDE the write txn (read-only), then transition
        // atomically inside it using the exact id.
        let resolved = self
            .get_proposal(id)?
            .ok_or_else(|| Error::store(format!("no proposal matches {id}")))?;
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let decided;
        {
            let mut t = wtx.open_table(PROPOSALS).map_err(Error::store)?;
            let cur = t
                .get(resolved.id.as_str())
                .map_err(Error::store)?
                .map(|v| v.value().to_vec())
                .ok_or_else(|| Error::store(format!("no proposal {}", resolved.id)))?;
            let mut p: RuleProposal = serde_json::from_slice(&cur).map_err(Error::store)?;
            if p.status != ProposalStatus::Pending {
                return Err(Error::store(format!(
                    "the proposal is already {:?}",
                    p.status
                )));
            }
            p.status = status;
            p.decided_at = Some(at);
            p.decision_note = note;
            let bytes = serde_json::to_vec(&p).map_err(Error::store)?;
            t.insert(p.id.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
            decided = p;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(decided)
    }
}