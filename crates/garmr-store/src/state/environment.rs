// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 5 environment-model persistence: two append-only streams
//! (`ENV_OBSERVATIONS`, `ENV_TRANSITIONS`) plus a monotonic per-fact scalar
//! (`ENV_SIGHTINGS`), and the context builders the anti-poisoning gate reads.
//!
//! Observations are keyed by CONTENT (`{fact_id}|{observation_id}`, both 64-hex
//! so no delimiter escaping is needed), with a guarded insert — a re-sighting of
//! identical content is a true store no-op (it only bumps the sighting scalar).
//! Transitions are append-only and chronological within a fact. All list readers
//! tolerantly skip an undecodable row (the Phase 3/4 idiom).
//!
//! Two safety properties live in the context builders, not the gate:
//!   * `compromised_entity_set` reads the RAW AUDITED TRANSITION STREAM (not a
//!     TTL-folded materialized state), so a compromised entity can never fall out
//!     of the guarded set by the passage of time; and it ALSO includes any case
//!     with a Malicious verdict, so a malicious-closed case keeps its entity
//!     compromised even after the case leaves the open set.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use garmr_core::{
    current_transition, materialize_fact, materialize_fact_asof, Case, CaseState, Disposition,
    EntityKind, EntityRef, EnvFact, Error, ExclusionReason, FactObservation, FactTransition,
    Result, Sighting,
};
use redb::ReadableTable;

use super::{StateStore, COLD_META, ENV_OBSERVATIONS, ENV_SIGHTINGS, ENV_TRANSITIONS};

/// Scalar key (in the shared `COLD_META` single-key-scalar table) holding the
/// exclusive upper `event_ts` bound the environment learner has already consumed.
const ENV_LEARN_WM_KEY: &str = "env_learn_watermark_us";

/// Scalar key holding the exclusive upper `event_ts` bound the environment
/// *detector* has already examined. Independent of [`ENV_LEARN_WM_KEY`] so the
/// detector and learner loops advance separately — neither may inherit the
/// other's position (a shared watermark would let one loop skip the other's
/// unseen events).
const ENV_DETECT_WM_KEY: &str = "env_detect_watermark_us";

/// The entities a case touches — the same principals as `Detection::dedup_key`
/// (host, source ip, identity). The anti-poisoning join surface.
fn case_entities(case: &Case) -> Vec<EntityRef> {
    let ev = &case.trigger.event;
    let mut out = Vec::new();
    if !ev.host.is_empty() {
        out.push(EntityRef::new(EntityKind::Host, ev.host.clone()));
    }
    if let Some(ip) = ev.src_ip().filter(|s| !s.is_empty()) {
        out.push(EntityRef::new(EntityKind::Ip, ip.to_string()));
    }
    if let Some(u) = ev
        .field("db_user")
        .or_else(|| ev.field("user"))
        .filter(|s| !s.is_empty())
    {
        out.push(EntityRef::new(EntityKind::Identity, u.to_string()));
    }
    out
}

impl StateStore {
    /// Append an observation if its content is not already stored (the key IS the
    /// content id). Returns `true` when a new row was written, `false` when it was
    /// an idempotent repeat (the caller still bumps the sighting scalar).
    pub fn append_observation(&self, o: &FactObservation) -> Result<bool> {
        let key = format!("{}|{}", o.fact_id, o.observation_id);
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let inserted;
        {
            let mut t = wtx.open_table(ENV_OBSERVATIONS).map_err(Error::store)?;
            if t.get(key.as_str()).map_err(Error::store)?.is_some() {
                inserted = false;
            } else {
                let bytes = serde_json::to_vec(o).map_err(Error::store)?;
                t.insert(key.as_str(), bytes.as_slice())
                    .map_err(Error::store)?;
                inserted = true;
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(inserted)
    }

    /// The environment learner's scan watermark: the exclusive upper `event_ts`
    /// (micros) already consumed. `None` before the learner has ever run. Without
    /// it the learner re-scans the same recent window every tick and re-bumps the
    /// sighting counters, monotonically inflating `observation_count` and
    /// nullifying the `min_observations` anti-poisoning tier.
    pub fn env_learn_watermark_us(&self) -> Result<Option<i64>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(COLD_META).map_err(Error::store)?;
        Ok(t.get(ENV_LEARN_WM_KEY)
            .map_err(Error::store)?
            .map(|v| v.value()))
    }

    /// Advance the learner watermark. Monotonic: a lower value is ignored so a
    /// stale caller can never rewind and re-count already-consumed events.
    pub fn set_env_learn_watermark_us(&self, us: i64) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(COLD_META).map_err(Error::store)?;
            let cur = t
                .get(ENV_LEARN_WM_KEY)
                .map_err(Error::store)?
                .map(|v| v.value());
            if cur.is_none_or(|c| us > c) {
                t.insert(ENV_LEARN_WM_KEY, us).map_err(Error::store)?;
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// The environment *detector's* scan watermark: the exclusive upper
    /// `event_ts` (micros) already examined. `None` before the detector has ever
    /// run. Independent of the learner watermark
    /// ([`env_learn_watermark_us`](Self::env_learn_watermark_us)) so the two
    /// loops never skip each other's unseen events (#18).
    pub fn env_detect_watermark_us(&self) -> Result<Option<i64>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(COLD_META).map_err(Error::store)?;
        Ok(t.get(ENV_DETECT_WM_KEY)
            .map_err(Error::store)?
            .map(|v| v.value()))
    }

    /// Advance the detector watermark. Monotonic: a lower value is ignored so a
    /// stale caller can never rewind and re-examine (re-alert on) events already
    /// consumed.
    pub fn set_env_detect_watermark_us(&self, us: i64) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(COLD_META).map_err(Error::store)?;
            let cur = t
                .get(ENV_DETECT_WM_KEY)
                .map_err(Error::store)?
                .map(|v| v.value());
            if cur.is_none_or(|c| us > c) {
                t.insert(ENV_DETECT_WM_KEY, us).map_err(Error::store)?;
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Bump the monotonic sighting scalar for a fact: +1 observation, advance
    /// `last_seen`, and +1 for the bounded source (the influence-cap input). One
    /// write txn (the `put_case` idiom).
    pub fn bump_sighting(&self, fact_id: &str, source_id: &str, at: DateTime<Utc>) -> Result<()> {
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut t = wtx.open_table(ENV_SIGHTINGS).map_err(Error::store)?;
            let mut s: Sighting = match t.get(fact_id).map_err(Error::store)? {
                Some(v) => serde_json::from_slice(v.value()).map_err(Error::store)?,
                None => Sighting {
                    fact_id: fact_id.to_string(),
                    first_seen: at,
                    last_seen: at,
                    observation_count: 0,
                    per_source_counts: BTreeMap::new(),
                },
            };
            s.observation_count = s.observation_count.saturating_add(1);
            if at > s.last_seen {
                s.last_seen = at;
            }
            if at < s.first_seen {
                s.first_seen = at;
            }
            *s.per_source_counts
                .entry(source_id.to_string())
                .or_insert(0) += 1;
            let bytes = serde_json::to_vec(&s).map_err(Error::store)?;
            t.insert(fact_id, bytes.as_slice()).map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// Append a governance transition (append-only; never overwrites). Keyed
    /// `{fact_id}|{recorded_nanos:020}|{transition_id}` — chronological within a
    /// fact.
    pub fn append_transition(&self, t: &FactTransition) -> Result<()> {
        let key = format!(
            "{}|{:020}|{}",
            t.fact_id,
            t.recorded_at.timestamp_nanos_opt().unwrap_or(0),
            t.transition_id
        );
        let bytes = serde_json::to_vec(t).map_err(Error::store)?;
        let wtx = self.db.begin_write().map_err(Error::store)?;
        {
            let mut tbl = wtx.open_table(ENV_TRANSITIONS).map_err(Error::store)?;
            tbl.insert(key.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
        }
        wtx.commit().map_err(Error::store)?;
        Ok(())
    }

    /// All observations (tolerant scan).
    pub fn list_env_observations(&self) -> Result<Vec<FactObservation>> {
        self.scan_tolerant(ENV_OBSERVATIONS, "env_observation")
    }

    /// All transitions (tolerant scan).
    pub fn list_env_transitions(&self) -> Result<Vec<FactTransition>> {
        self.scan_tolerant(ENV_TRANSITIONS, "env_transition")
    }

    /// Observations for one fact.
    pub fn observations_for(&self, fact_id: &str) -> Result<Vec<FactObservation>> {
        Ok(self
            .list_env_observations()?
            .into_iter()
            .filter(|o| o.fact_id == fact_id)
            .collect())
    }

    /// Transitions for one fact.
    pub fn transitions_for(&self, fact_id: &str) -> Result<Vec<FactTransition>> {
        Ok(self
            .list_env_transitions()?
            .into_iter()
            .filter(|t| t.fact_id == fact_id)
            .collect())
    }

    /// The sighting scalar for one fact.
    pub fn sighting_for(&self, fact_id: &str) -> Result<Option<Sighting>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(ENV_SIGHTINGS).map_err(Error::store)?;
        match t.get(fact_id).map_err(Error::store)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).map_err(Error::store)?,
            )),
            None => Ok(None),
        }
    }

    /// Materialize the current view of every fact. `ttl` (when set) expires stale
    /// non-protected facts (see `materialize_fact`).
    pub fn list_env_facts(
        &self,
        ttl: Option<chrono::Duration>,
        now: DateTime<Utc>,
    ) -> Result<Vec<EnvFact>> {
        let observations = self.list_env_observations()?;
        let transitions = self.list_env_transitions()?;
        let sightings: HashMap<String, Sighting> = self
            .scan_tolerant::<Sighting>(ENV_SIGHTINGS, "env_sighting")?
            .into_iter()
            .map(|s| (s.fact_id.clone(), s))
            .collect();

        let mut by_obs: HashMap<String, Vec<FactObservation>> = HashMap::new();
        for o in observations {
            by_obs.entry(o.fact_id.clone()).or_default().push(o);
        }
        let mut by_tr: HashMap<String, Vec<FactTransition>> = HashMap::new();
        for t in transitions {
            by_tr.entry(t.fact_id.clone()).or_default().push(t);
        }
        // Every fact_id that appears in either stream.
        let mut fids: Vec<String> = by_obs.keys().cloned().collect();
        fids.extend(by_tr.keys().cloned());
        fids.sort();
        fids.dedup();

        let empty_o: Vec<FactObservation> = Vec::new();
        let empty_t: Vec<FactTransition> = Vec::new();
        let mut out = Vec::new();
        for fid in fids {
            let o = by_obs.get(&fid).unwrap_or(&empty_o);
            let t = by_tr.get(&fid).unwrap_or(&empty_t);
            if let Some(f) = materialize_fact(&fid, o, t, sightings.get(&fid), ttl, now) {
                out.push(f);
            }
        }
        Ok(out)
    }

    /// Materialize one fact by id.
    pub fn get_env_fact(
        &self,
        fact_id: &str,
        ttl: Option<chrono::Duration>,
        now: DateTime<Utc>,
    ) -> Result<Option<EnvFact>> {
        let o = self.observations_for(fact_id)?;
        let t = self.transitions_for(fact_id)?;
        let s = self.sighting_for(fact_id)?;
        Ok(materialize_fact(fact_id, &o, &t, s.as_ref(), ttl, now))
    }

    /// The bitemporal query: what did we believe about a fact at `as_of`?
    pub fn env_fact_asof(&self, fact_id: &str, as_of: DateTime<Utc>) -> Result<Option<EnvFact>> {
        let o = self.observations_for(fact_id)?;
        let t = self.transitions_for(fact_id)?;
        Ok(materialize_fact_asof(fact_id, as_of, &o, &t, None))
    }

    /// The active maintenance/change windows (Asserted ChangeRecord facts whose
    /// valid interval contains `now`).
    pub fn change_windows(&self, now: DateTime<Utc>) -> Result<Vec<EnvFact>> {
        Ok(self
            .list_env_facts(None, now)?
            .into_iter()
            .filter(|f| {
                f.entity.kind == EntityKind::ChangeRecord
                    && f.valid_from <= now
                    && f.valid_to.map(|end| now < end).unwrap_or(true)
            })
            .collect())
    }

    /// Entities touched by any case that is NOT closed — the open-case set (the
    /// core anti-poisoning input). New/Investigating/Triaged/Escalated/NeedsHuman
    /// are all "open".
    pub fn open_case_entity_set(&self) -> Result<HashSet<EntityRef>> {
        let mut set = HashSet::new();
        for case in self.list_cases()? {
            if case.state != CaseState::Closed {
                for e in case_entities(&case) {
                    set.insert(e);
                }
            }
        }
        Ok(set)
    }

    /// Entities the system considers COMPROMISED, from independent sources so
    /// neither time, a case-close, nor whose-judgement-it-was can re-open the
    /// poisoning door:
    ///   (a) a fact whose CURRENT audited transition is Suspicious/KnownMalicious
    ///       — read from the raw transition stream, so it is immune to TTL and to
    ///       any materialization fold; and
    ///   (b) any case adjudged Suspicious-or-worse — by the AGENT (`case.verdict`),
    ///       by a HUMAN analyst (`AnalystDecision`), or by a post-incident
    ///       `IncidentOutcome` — REGARDLESS of case state. The human/outcome
    ///       sources matter because a human's Malicious decision on an
    ///       agent-closed-benign case never rewrites `case.verdict`; the gate must
    ///       still honor the analyst's ground-truth over the agent's prediction
    ///       (the system's authority ordering everywhere else).
    pub fn compromised_entity_set(&self) -> Result<HashSet<EntityRef>> {
        let mut set = HashSet::new();

        // (a) audited compromised transitions
        let observations = self.list_env_observations()?;
        let entity_of: HashMap<String, EntityRef> = observations
            .iter()
            .map(|o| (o.fact_id.clone(), o.entity.clone()))
            .collect();
        let mut by_fact: HashMap<String, Vec<FactTransition>> = HashMap::new();
        for t in self.list_env_transitions()? {
            by_fact.entry(t.fact_id.clone()).or_default().push(t);
        }
        for (fid, ts) in &by_fact {
            if let Some(cur) = current_transition(ts) {
                if cur.to_state.is_compromised() {
                    if let Some(e) = entity_of.get(fid) {
                        set.insert(e.clone());
                    }
                }
            }
        }

        // (b) cases adjudged Suspicious-or-worse by ANY authority. Human decisions
        // and incident outcomes are case-scoped, so collect their case ids first,
        // then map back to the case's entities.
        let adverse =
            |d: Disposition| matches!(d, Disposition::Malicious | Disposition::Suspicious);
        let mut adverse_cases: HashSet<String> = HashSet::new();
        for d in self.list_decisions()? {
            if adverse(d.disposition) {
                adverse_cases.insert(d.case_id);
            }
        }
        for o in self.list_incident_outcomes()? {
            if adverse(o.disposition) {
                if let Some(cid) = o.case_id {
                    adverse_cases.insert(cid);
                }
            }
        }
        for case in self.list_cases()? {
            let agent_adverse = case
                .verdict
                .as_ref()
                .map(|v| adverse(v.disposition))
                .unwrap_or(false);
            if agent_adverse || adverse_cases.contains(&case.id) {
                for e in case_entities(&case) {
                    set.insert(e);
                }
            }
        }
        Ok(set)
    }

    /// A per-case exclusion candidate for Phase-8 dataset building: a case whose
    /// entities intersect the compromised set (→ `Compromised`, the stronger
    /// reason) or the open-case set (→ `OpenCase`). Reuses the SAME entity join
    /// as the anti-poisoning gate (`case_entities` + the two entity sets), kept
    /// here so `case_entities` stays private and the Phase-5 tests are untouched.
    ///
    /// This is only a CANDIDATE map: the dataset builder applies it ONLY to
    /// benign-labeled cases, because a human-adjudged-adverse case is itself in
    /// the compromised set (it IS the positive class the dangerous-FN guard
    /// protects) and must never be stripped.
    pub fn poisoned_case_reasons(
        &self,
    ) -> Result<std::collections::HashMap<String, ExclusionReason>> {
        let open = self.open_case_entity_set()?;
        let compromised = self.compromised_entity_set()?;
        let mut out = std::collections::HashMap::new();
        for case in self.list_cases()? {
            let ents = case_entities(&case);
            if ents.iter().any(|e| compromised.contains(e)) {
                out.insert(case.id.clone(), ExclusionReason::Compromised);
            } else if ents.iter().any(|e| open.contains(e)) {
                out.insert(case.id.clone(), ExclusionReason::OpenCase);
            }
        }
        Ok(out)
    }
}
