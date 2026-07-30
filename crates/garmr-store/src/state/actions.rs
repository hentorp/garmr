// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Response-action (SOAR) persistence: the propose→approve→act audit trail,
//! keyed by uuid in the `actions` table. The only agent-side write is a
//! `Proposed` proposal; every state advance goes through `transition_action`
//! so the state machine is enforced atomically in one place.

use garmr_core::{ActionProposal, ActionState, Error, Result};
use redb::ReadableTable;

use super::{StateStore, ACTIONS};

impl StateStore {
    /// Write a NEW action proposal (state must be `Proposed`). This is the only
    /// write the agent-side code performs; state advances go through the
    /// transition methods so the state machine is enforced in one place.
    pub fn put_action_proposal(&self, a: &ActionProposal) -> Result<()> {
        if a.state != ActionState::Proposed {
            return Err(Error::store("new action proposals must be Proposed"));
        }
        let bytes = serde_json::to_vec(a).map_err(Error::store)?;
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(ACTIONS).map_err(Error::store)?;
            if t.get(a.id.as_str()).map_err(Error::store)?.is_some() {
                return Err(Error::store("action id already exists"));
            }
            t.insert(a.id.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Fetch one action by exact id, else by a UNIQUE id prefix. Empty id is
    /// rejected (every key starts_with("")).
    pub fn get_action(&self, id: &str) -> Result<Option<ActionProposal>> {
        if id.trim().is_empty() {
            return Err(Error::store("empty action id"));
        }
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(ACTIONS).map_err(Error::store)?;
        if let Some(v) = t.get(id).map_err(Error::store)? {
            return Ok(Some(
                serde_json::from_slice(v.value()).map_err(Error::store)?,
            ));
        }
        let mut hit = None;
        for row in t.iter().map_err(Error::store)? {
            let (k, v) = row.map_err(Error::store)?;
            if k.value().starts_with(id) {
                if hit.is_some() {
                    return Err(Error::store(format!(
                        "multiple actions match the prefix {id}"
                    )));
                }
                hit = Some(serde_json::from_slice(v.value()).map_err(Error::store)?);
            }
        }
        Ok(hit)
    }

    /// All action proposals, newest first.
    pub fn list_actions(&self) -> Result<Vec<ActionProposal>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(ACTIONS).map_err(Error::store)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(Error::store)? {
            let (_, v) = row.map_err(Error::store)?;
            out.push(serde_json::from_slice::<ActionProposal>(v.value()).map_err(Error::store)?);
        }
        out.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        Ok(out)
    }

    /// Actions in a given state (the executor polls `Approved`).
    pub fn actions_in_state(&self, state: ActionState) -> Result<Vec<ActionProposal>> {
        Ok(self
            .list_actions()?
            .into_iter()
            .filter(|a| a.state == state)
            .collect())
    }

    /// Atomically transition an action from `from` to `to` in ONE write txn,
    /// appending an audit event and stamping the right timestamp. Fails if the
    /// action is not currently in `from` — so a human deciding a
    /// non-`Proposed` action, or the executor acting on a non-`Approved` one,
    /// or any double-transition, gets a clean error and the state machine
    /// holds. Prefixes are resolved read-only first, then matched by exact id.
    // A wide but flat signature: every parameter is a distinct, required facet
    // of one atomic transition (from/to gate, actor+detail audit, result,
    // timestamp) — bundling them into a struct would only move the noise.
    #[allow(clippy::too_many_arguments)]
    pub fn transition_action(
        &self,
        id: &str,
        from: &[ActionState],
        to: ActionState,
        actor: &str,
        detail: &str,
        result: Option<String>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<ActionProposal> {
        let resolved = self
            .get_action(id)?
            .ok_or_else(|| Error::store(format!("no action matches {id}")))?;
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let out;
        {
            let mut t = wtx.open_table(ACTIONS).map_err(Error::store)?;
            let cur = t
                .get(resolved.id.as_str())
                .map_err(Error::store)?
                .map(|v| v.value().to_vec())
                .ok_or_else(|| Error::store(format!("no action {}", resolved.id)))?;
            let mut a: ActionProposal = serde_json::from_slice(&cur).map_err(Error::store)?;
            // The from-state check lives INSIDE the write txn, so concurrent
            // transitions (double-approve, approve-vs-deny, executor-vs-deny)
            // serialize and exactly one wins; the losers see the new state and
            // get a clean error.
            if !from.contains(&a.state) {
                return Err(Error::store(format!(
                    "action {} is {:?}, not {:?} — transition refused",
                    a.id, a.state, from
                )));
            }
            a.state = to;
            a.record(actor, detail, at);
            match to {
                ActionState::Approved | ActionState::Denied => a.decided_at = Some(at),
                ActionState::Executed | ActionState::Failed => {
                    a.executed_at = Some(at);
                    if result.is_some() {
                        a.result = result;
                    }
                }
                ActionState::Proposed | ActionState::Executing => {}
            }
            let bytes = serde_json::to_vec(&a).map_err(Error::store)?;
            t.insert(a.id.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
            out = a;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(out)
    }
}
