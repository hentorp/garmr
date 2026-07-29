// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 8 (stateful plane) — cross-event application-audit / insider-risk
//! detectors.
//!
//! [`crate::detect_access`] and [`crate::detect_behavioral`] decide from a single
//! access (plus its policy verdict and the entity's trusted baseline). The
//! detectors here need **cross-event state**: a pattern that only becomes visible
//! once you correlate many accesses by the same actor over time. The module docs
//! of [`crate`] deliberately left these out ("a stub would report clear and hide
//! misuse"); this is their real implementation.
//!
//! ## What it detects
//!
//! | detector id                     | signal                                              |
//! |---------------------------------|-----------------------------------------------------|
//! | `app-enumeration-low-and-slow`  | many DISTINCT sensitive subjects, slowly, across sessions |
//! | `app-enumeration-sequential`    | subject ids walked in adjacent numeric runs (scripted) |
//! | `app-split-bulk-extraction`     | a bulk volume assembled from many small reads (sub-threshold) |
//! | `app-denied-probing`            | repeated denied/failed access spread across DISTINCT resources |
//! | `app-cross-domain-access`       | one session touches a NOVEL combination of sensitive domains |
//!
//! ## Contracts (shared with the rest of the platform)
//!
//! * **Bounded state.** Per-actor windows are capped (entries *and* actors), and
//!   idle actors are pruned, so memory is O(active actors) regardless of the
//!   firehose. Nothing here grows without bound.
//! * **Event time, not ingest time.** Every window advances by the access's own
//!   `ev.ts`. A per-actor monotone **watermark** means a late (out-of-order)
//!   event still contributes but never *rewinds* a window, and eviction is by
//!   event time so replaying old data cannot resurrect a stale episode.
//! * **Restart recovery.** [`StatefulState`] is `Serialize`/`Deserialize`; the
//!   serve pipeline snapshots it next to the behavioral baselines, so an episode
//!   in progress survives a restart. The `cfg` is intentionally *not* persisted —
//!   a reload always picks up the current thresholds.
//! * **No double counting.** Distinct-subject / distinct-resource / distinct-
//!   domain sets dedup within their window, and each episode is **edge-triggered**
//!   with hysteresis (fires once when it crosses the threshold; re-arms only after
//!   the metric falls back below a lower re-arm level), so one episode ⇒ one case.
//! * **Explainable + immutable evidence.** Every finding carries the count, the
//!   window, and a bounded list of the *contributing* event ids — stable,
//!   content-addressed evidence pointers, never a mutable summary.
//! * **Policy ≠ anomaly, and forbidden stays forbidden.** These are anomaly
//!   detectors; they never downgrade or suppress the deterministic policy
//!   findings. `app-denied-probing` keys *on* failures/denials precisely because a
//!   repeated forbidden pattern is a signal — it is never learned into normality.
//! * **Trusted classification drives sensitivity.** The three "sensitive
//!   enumeration" detectors gate on a *trusted* classification (catalog-stamped
//!   `sensitive_resource`/`data_classification`, or a `watched_subject`), so a
//!   still-learning Candidate label can never make an access count as sensitive —
//!   and, conversely, can never manufacture a finding. The gate is configurable
//!   ([`StatefulConfig::require_sensitive`]) for labs without a catalog.
//!
//! Findings are appended to the same per-access finding vector as the stateless
//! detectors and flow through [`garmr_analytics::ensemble::fuse_access`]; their
//! ids are in [`crate::STANDALONE_DETECTORS`], so each episode keeps its own
//! explainable case rather than being blended into the generic behavioral bucket.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use garmr_core::{
    AccessProjection, AuditRecord, DetectorFamily, EnvBasis, Event, FindingSignal, SecurityFinding,
    SeverityBand,
};
use serde::{Deserialize, Serialize};

/// The stateful detector ids, in one place so the pipeline can register them as
/// standalone (each episode is its own case).
pub const STATEFUL_DETECTORS: &[&str] = &[
    "app-enumeration-low-and-slow",
    "app-enumeration-sequential",
    "app-split-bulk-extraction",
    "app-denied-probing",
    "app-cross-domain-access",
];

/// Tunable thresholds & window sizes for the stateful plane. Defaults are
/// deliberately conservative (favouring precision) and can be overridden from
/// config; they are **not** persisted with the state, so a threshold change takes
/// effect on the next reload without discarding learned windows.
/// `#[serde(default)]` at the struct level lets a challenger spec (DoD 19) carry
/// only the knobs it changes — every omitted field falls back to [`Default`], so
/// a shadow challenger is expressed as a minimal override, not a full restated
/// config. The config is not persisted with the learned state (see the module
/// note); it is rebuilt from the registry on load/reload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StatefulConfig {
    /// Gate the three sensitive-enumeration detectors on a trusted classification.
    /// `true` (default) = only sensitive accesses count — high precision, and it
    /// honours "trusted classification drives security decisions". Set `false` in
    /// a lab with no catalog to exercise the detectors on any per-record access.
    pub require_sensitive: bool,

    // --- low-and-slow enumeration ---
    /// Rolling window over which distinct sensitive subjects accumulate.
    pub slow_window_secs: i64,
    /// Distinct sensitive subjects in the window that trips the detector.
    pub slow_min_subjects: u32,
    /// The episode must span at least this long (else it's a burst, not "slow").
    pub slow_min_span_secs: i64,
    /// …and be spread across at least this many distinct sessions.
    pub slow_min_sessions: u32,
    /// Re-arm once distinct subjects fall back below this (hysteresis).
    pub slow_rearm_subjects: u32,

    // --- sequential enumeration ---
    /// Consecutive adjacent-id steps (same direction) that trip the detector.
    pub seq_run_len: u32,

    // --- split-bulk extraction ---
    /// Window over which many small reads accumulate.
    pub bulk_window_secs: i64,
    /// Total rows across the window that count as a bulk extraction.
    pub bulk_min_rows: u64,
    /// …assembled from at least this many separate (sub-threshold) queries.
    pub bulk_min_queries: u32,
    /// Re-arm once the windowed row-sum falls back below this (hysteresis).
    pub bulk_rearm_rows: u64,

    // --- denied probing ---
    /// Window over which distinct denied resources accumulate.
    pub denied_window_secs: i64,
    /// Distinct denied resources in the window that trip the detector.
    pub denied_min_resources: u32,
    /// Re-arm once distinct denied resources fall back below this.
    pub denied_rearm_resources: u32,

    // --- cross-domain access ---
    /// Distinct sensitive domains within one session that trip the detector.
    pub xdomain_min_domains: u32,

    // --- bounding ---
    /// Hard cap on tracked actors (LRU-by-watermark eviction beyond it).
    pub max_actors: usize,
    /// Drop an actor once idle (no access) for this long, in event time.
    pub actor_idle_ttl_secs: i64,
    /// Cap on entries retained per per-actor window (belt-and-braces vs. window).
    pub max_window_entries: usize,
}

impl Default for StatefulConfig {
    fn default() -> Self {
        StatefulConfig {
            require_sensitive: true,
            slow_window_secs: 14 * 24 * 3600,
            slow_min_subjects: 40,
            slow_min_span_secs: 6 * 3600,
            slow_min_sessions: 3,
            slow_rearm_subjects: 20,
            seq_run_len: 12,
            bulk_window_secs: 3600,
            bulk_min_rows: 100_000,
            bulk_min_queries: 12,
            bulk_rearm_rows: 20_000,
            denied_window_secs: 3600,
            denied_min_resources: 6,
            denied_rearm_resources: 2,
            xdomain_min_domains: 2,
            max_actors: 40_000,
            actor_idle_ttl_secs: 30 * 24 * 3600,
            max_window_entries: 4096,
        }
    }
}

/// The stateful detector engine: config + serializable state.
pub struct StatefulDetectors {
    cfg: StatefulConfig,
    state: StatefulState,
}

/// The persisted part of [`StatefulDetectors`] — everything needed to resume an
/// in-progress episode after a restart. Serialized whole (one blob) next to the
/// behavioral baselines.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatefulState {
    actors: HashMap<String, ActorState>,
    /// Global event-time high-watermark (µs) — the reference for idle pruning.
    global_watermark_us: i64,
    /// Monotone event counter, so pruning runs on an interval, not every event.
    events: u64,
}

impl StatefulDetectors {
    /// A fresh engine with the given config.
    pub fn new(cfg: StatefulConfig) -> Self {
        StatefulDetectors {
            cfg,
            state: StatefulState::default(),
        }
    }

    /// Resume from persisted [`StatefulState`] with the *current* config.
    pub fn from_state(cfg: StatefulConfig, state: StatefulState) -> Self {
        StatefulDetectors { cfg, state }
    }

    /// The persisted state, for snapshotting.
    pub fn state(&self) -> &StatefulState {
        &self.state
    }

    /// Number of actors currently tracked (observability / tests).
    pub fn tracked_actors(&self) -> usize {
        self.state.actors.len()
    }

    /// Observe one access in event order and return zero or more findings. The
    /// caller runs this in [`crate`]'s serial (ordered) finish stage, alongside
    /// `observe` into the baselines, so the cross-event state advances exactly
    /// once per access, in event time.
    ///
    /// `forbidden` is the policy `Deny` verdict and `failed` the DB-negative
    /// outcome for the same access (the caller already computed both). A denied or
    /// failed access still feeds `app-denied-probing` (that is its signal) but is
    /// never counted as a *successful* sensitive read by the enumeration/bulk
    /// detectors — a forbidden action is never folded into a "normal" volume.
    pub fn observe(
        &mut self,
        ev: &Event,
        rec: &AuditRecord,
        forbidden: bool,
        failed: bool,
    ) -> Vec<SecurityFinding> {
        self.observe_at(
            ev,
            rec,
            forbidden,
            failed,
            chrono::Utc::now().timestamp_micros(),
        )
    }

    fn observe_at(
        &mut self,
        ev: &Event,
        rec: &AuditRecord,
        forbidden: bool,
        failed: bool,
        received_at_us: i64,
    ) -> Vec<SecurityFinding> {
        let actor_id = rec.actor.actor_id.trim();
        if actor_id.is_empty() {
            return Vec::new();
        }
        let now_us = ev.ts.timestamp_micros();
        self.state.events = self.state.events.wrapping_add(1);
        // Sender-controlled event time is useful for each actor's windows, but a
        // future timestamp must not become the global eviction clock. Also heal a
        // previously persisted poisoned watermark on the first subsequent event.
        let pruning_event_us = now_us.min(received_at_us);
        self.state.global_watermark_us = self
            .state
            .global_watermark_us
            .min(received_at_us)
            .max(pruning_event_us);
        // Periodic idle pruning keeps the actor map bounded without an every-event
        // scan; the hard cap below is the backstop.
        if self.state.events % 4096 == 0 {
            let cutoff = self
                .state
                .global_watermark_us
                .saturating_sub(self.cfg.actor_idle_ttl_secs.saturating_mul(1_000_000));
            self.state.actors.retain(|_, a| a.watermark_us >= cutoff);
        }
        self.enforce_actor_cap(actor_id);

        let cfg = &self.cfg;
        let actor = self.state.actors.entry(actor_id.to_string()).or_default();
        // Monotone per-actor watermark: a late event contributes but never rewinds
        // a window. All eviction is relative to this, not to the raw `now_us`.
        if now_us > actor.watermark_us {
            actor.watermark_us = now_us;
        }
        let wm = actor.watermark_us;

        let sensitive = is_sensitive(rec);
        let gated = !cfg.require_sensitive || sensitive;
        let read_ok = !forbidden && !failed;

        let mut out = Vec::new();
        if read_ok && gated {
            actor.low_and_slow(cfg, ev, rec, wm, sensitive, &mut out);
            actor.sequential(cfg, ev, rec, sensitive, &mut out);
            actor.split_bulk(cfg, ev, rec, wm, sensitive, &mut out);
            actor.cross_domain(cfg, ev, rec, sensitive, &mut out);
        }
        // Probing keys on the denial/failure itself — independent of the sensitive
        // gate, and it is exactly the "repeated forbidden behaviour" signal.
        if forbidden || failed {
            actor.denied_probing(cfg, ev, rec, wm, &mut out);
        }
        out
    }

    /// Enforce the hard actor cap: if inserting a new actor would exceed it, evict
    /// the least-recently-active one (min watermark). Evictions are rare (only at
    /// the cap and only for a genuinely new actor), so the O(actors) min-scan is
    /// acceptable and keeps the structure a plain map.
    fn enforce_actor_cap(&mut self, incoming: &str) {
        if self.state.actors.len() < self.cfg.max_actors || self.state.actors.contains_key(incoming)
        {
            return;
        }
        if let Some(victim) = self
            .state
            .actors
            .iter()
            .min_by_key(|(_, a)| a.watermark_us)
            .map(|(k, _)| k.clone())
        {
            self.state.actors.remove(&victim);
        }
    }
}

/// A trusted-classification sensitivity test. Only a Trusted, catalog-stamped
/// classification (or a watched subject) counts — a Candidate label is never
/// stamped onto the record, so it cannot make an access "sensitive".
fn is_sensitive(rec: &AuditRecord) -> bool {
    if rec.classification.sensitive_resource || rec.classification.watched_subject {
        return true;
    }
    matches!(
        rec.classification
            .data_classification
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("confidential" | "restricted" | "secret" | "top_secret" | "top-secret")
    )
}

// --------------------------------------------------------------------------
// per-actor state
// --------------------------------------------------------------------------

const MAX_EVIDENCE: usize = 24;
const MAX_SESSIONS: usize = 256;
const MAX_SEEN_PAIRS: usize = 1024;
const MAX_SEQ_TRACKERS: usize = 64;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ActorState {
    watermark_us: i64,

    // low-and-slow: distinct sensitive subjects over a long window.
    slow: VecDeque<SubjectHit>,
    #[serde(default)]
    slow_subjects: HashMap<String, u32>,
    #[serde(default)]
    slow_sessions: HashMap<String, u32>,
    #[serde(default)]
    slow_fired: bool,

    // sequential enumeration, per object_type.
    #[serde(default)]
    seq: HashMap<String, SeqRun>,

    // split-bulk: rolling row-sum across many small reads.
    bulk: VecDeque<BulkHit>,
    #[serde(default)]
    bulk_rows: u64,
    #[serde(default)]
    bulk_fired: bool,

    // denied probing: distinct denied resources over a window.
    denied: VecDeque<ResourceHit>,
    #[serde(default)]
    denied_resources: HashMap<String, u32>,
    #[serde(default)]
    denied_fired: bool,

    // cross-domain: per-session distinct sensitive domains + reported combos.
    #[serde(default)]
    xdomain: HashMap<String, SessionDomains>,
    #[serde(default)]
    xdomain_seen: HashSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubjectHit {
    ts_us: i64,
    subject: String,
    session: String,
    evidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BulkHit {
    ts_us: i64,
    rows: u64,
    evidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResourceHit {
    ts_us: i64,
    resource: String,
    evidence: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SeqRun {
    last_id: i64,
    run_len: u32,
    ascending: bool,
    first_ev: String,
    reported: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SessionDomains {
    domains: BTreeSet<String>,
    evidence: Vec<String>,
}

impl ActorState {
    // ---- low-and-slow enumeration -------------------------------------------
    fn low_and_slow(
        &mut self,
        cfg: &StatefulConfig,
        ev: &Event,
        rec: &AuditRecord,
        wm: i64,
        sensitive: bool,
        out: &mut Vec<SecurityFinding>,
    ) {
        let Some(subject) = subject_key(rec) else {
            return;
        };
        let session = session_key(rec);
        let now = ev.ts.timestamp_micros();
        // Add this hit, then evict everything older than the window (relative to
        // the monotone watermark, so a late event cannot revive an expired one).
        self.slow.push_back(SubjectHit {
            ts_us: now,
            subject: subject.clone(),
            session: session.clone(),
            evidence: evidence_of(ev),
        });
        *self.slow_subjects.entry(subject).or_insert(0) += 1;
        *self.slow_sessions.entry(session).or_insert(0) += 1;
        let cutoff = wm - cfg.slow_window_secs * 1_000_000;
        while self
            .slow
            .front()
            .is_some_and(|h| h.ts_us < cutoff || self.slow.len() > cfg.max_window_entries)
        {
            let h = self.slow.pop_front().expect("front checked");
            dec(&mut self.slow_subjects, &h.subject);
            dec(&mut self.slow_sessions, &h.session);
        }

        let distinct = self.slow_subjects.len() as u32;
        // Hysteresis: re-arm only after the distinct count recedes.
        if self.slow_fired {
            if distinct <= cfg.slow_rearm_subjects {
                self.slow_fired = false;
            }
            return;
        }
        if distinct < cfg.slow_min_subjects {
            return;
        }
        let sessions = self.slow_sessions.len() as u32;
        let span = self.slow.front().map(|h| now - h.ts_us).unwrap_or(0);
        if sessions < cfg.slow_min_sessions || span < cfg.slow_min_span_secs * 1_000_000 {
            return;
        }
        self.slow_fired = true;
        let level = if sensitive { "high" } else { "medium" };
        out.push(emit(
            ev,
            "app-enumeration-low-and-slow",
            "Low-and-slow enumeration of many distinct sensitive subjects",
            level,
            &["T1213"],
            &[
                ("distinct_subjects", distinct.to_string()),
                ("distinct_sessions", sessions.to_string()),
                ("span_hours", format!("{:.1}", span as f64 / 3.6e9)),
                ("window_days", (cfg.slow_window_secs / 86400).to_string()),
                (
                    "contributing",
                    evidence_list(self.slow.iter().map(|h| &h.evidence)),
                ),
            ],
        ));
    }

    // ---- sequential enumeration ---------------------------------------------
    fn sequential(
        &mut self,
        cfg: &StatefulConfig,
        ev: &Event,
        rec: &AuditRecord,
        sensitive: bool,
        out: &mut Vec<SecurityFinding>,
    ) {
        let Some(id) = numeric_id(rec) else {
            return;
        };
        let object = object_type_key(rec);
        if self.seq.len() > MAX_SEQ_TRACKERS && !self.seq.contains_key(&object) {
            // Bounded: drop the whole tracker set rather than grow unbounded; a
            // real scripted run re-establishes itself within seq_run_len steps.
            self.seq.clear();
        }
        let ev_id = evidence_of(ev);
        let run = self.seq.entry(object.clone()).or_default();
        let step_up = id == run.last_id + 1;
        let step_down = id == run.last_id - 1;
        if run.run_len == 0 {
            run.run_len = 1;
            run.first_ev = ev_id.clone();
        } else if (step_up && run.ascending) || (step_down && !run.ascending) {
            run.run_len += 1;
        } else if step_up || step_down {
            // Direction (re)established from a length-2 seed.
            run.ascending = step_up;
            run.run_len = 2;
            // first_ev stays the previous id's event (the run's true start).
        } else {
            run.run_len = 1;
            run.first_ev = ev_id.clone();
            run.reported = false;
        }
        run.last_id = id;

        if run.run_len >= cfg.seq_run_len && !run.reported {
            run.reported = true;
            let first_ev = run.first_ev.clone();
            let run_len = run.run_len;
            let ascending = run.ascending;
            let level = if sensitive { "high" } else { "medium" };
            out.push(emit(
                ev,
                "app-enumeration-sequential",
                "Sequential enumeration — subject ids walked in an adjacent run",
                level,
                &["T1213"],
                &[
                    ("run_length", run_len.to_string()),
                    (
                        "direction",
                        if ascending { "ascending" } else { "descending" }.to_string(),
                    ),
                    ("object_type", object),
                    ("current_id", id.to_string()),
                    ("first_evidence", first_ev),
                ],
            ));
        }
    }

    // ---- split-bulk extraction ----------------------------------------------
    fn split_bulk(
        &mut self,
        cfg: &StatefulConfig,
        ev: &Event,
        rec: &AuditRecord,
        wm: i64,
        sensitive: bool,
        out: &mut Vec<SecurityFinding>,
    ) {
        // Only *sub-threshold* reads: a query already flagged bulk is the stateless
        // detector's job. This one catches extraction deliberately split to stay
        // under that bar.
        if rec.action.bulk_operation || rec.action.export_operation {
            return;
        }
        let Some(rows) = rec.action.rows_read.filter(|r| *r > 0) else {
            return;
        };
        let now = ev.ts.timestamp_micros();
        self.bulk.push_back(BulkHit {
            ts_us: now,
            rows,
            evidence: evidence_of(ev),
        });
        self.bulk_rows = self.bulk_rows.saturating_add(rows);
        let cutoff = wm - cfg.bulk_window_secs * 1_000_000;
        while self
            .bulk
            .front()
            .is_some_and(|h| h.ts_us < cutoff || self.bulk.len() > cfg.max_window_entries)
        {
            let h = self.bulk.pop_front().expect("front checked");
            self.bulk_rows = self.bulk_rows.saturating_sub(h.rows);
        }

        if self.bulk_fired {
            if self.bulk_rows <= cfg.bulk_rearm_rows {
                self.bulk_fired = false;
            }
            return;
        }
        let queries = self.bulk.len() as u32;
        if self.bulk_rows < cfg.bulk_min_rows || queries < cfg.bulk_min_queries {
            return;
        }
        self.bulk_fired = true;
        let level = if sensitive { "high" } else { "medium" };
        out.push(emit(
            ev,
            "app-split-bulk-extraction",
            "Bulk extraction assembled from many sub-threshold reads",
            level,
            &["T1213", "T1030"],
            &[
                ("total_rows", self.bulk_rows.to_string()),
                ("queries", queries.to_string()),
                ("window_secs", cfg.bulk_window_secs.to_string()),
                (
                    "contributing",
                    evidence_list(self.bulk.iter().map(|h| &h.evidence)),
                ),
            ],
        ));
    }

    // ---- repeated denied probing --------------------------------------------
    fn denied_probing(
        &mut self,
        cfg: &StatefulConfig,
        ev: &Event,
        rec: &AuditRecord,
        wm: i64,
        out: &mut Vec<SecurityFinding>,
    ) {
        let resource = object_key(rec);
        let now = ev.ts.timestamp_micros();
        self.denied.push_back(ResourceHit {
            ts_us: now,
            resource: resource.clone(),
            evidence: evidence_of(ev),
        });
        *self.denied_resources.entry(resource).or_insert(0) += 1;
        let cutoff = wm - cfg.denied_window_secs * 1_000_000;
        while self
            .denied
            .front()
            .is_some_and(|h| h.ts_us < cutoff || self.denied.len() > cfg.max_window_entries)
        {
            let h = self.denied.pop_front().expect("front checked");
            dec(&mut self.denied_resources, &h.resource);
        }

        let distinct = self.denied_resources.len() as u32;
        if self.denied_fired {
            if distinct <= cfg.denied_rearm_resources {
                self.denied_fired = false;
            }
            return;
        }
        if distinct < cfg.denied_min_resources {
            return;
        }
        self.denied_fired = true;
        out.push(emit(
            ev,
            "app-denied-probing",
            "Repeated denied/failed access probing distinct resources",
            "medium",
            &["T1069", "T1213"],
            &[
                ("distinct_resources", distinct.to_string()),
                ("window_secs", cfg.denied_window_secs.to_string()),
                (
                    "contributing",
                    evidence_list(self.denied.iter().map(|h| &h.evidence)),
                ),
            ],
        ));
    }

    // ---- cross-domain access ------------------------------------------------
    fn cross_domain(
        &mut self,
        cfg: &StatefulConfig,
        ev: &Event,
        rec: &AuditRecord,
        _sensitive: bool,
        out: &mut Vec<SecurityFinding>,
    ) {
        // A "domain" is the sensitive data domain touched — the schema, else the
        // object type. Only sensitive touches count (already gated by the caller
        // when require_sensitive is on).
        let Some(domain) = domain_key(rec) else {
            return;
        };
        let session = session_key(rec);
        if session == "-" {
            return; // cannot correlate a session-less access
        }
        if self.xdomain.len() > MAX_SESSIONS && !self.xdomain.contains_key(&session) {
            // Bounded: forget the oldest half of tracked sessions.
            let drop: Vec<String> = self
                .xdomain
                .keys()
                .take(self.xdomain.len() / 2)
                .cloned()
                .collect();
            for k in drop {
                self.xdomain.remove(&k);
            }
        }
        let entry = self.xdomain.entry(session).or_default();
        let is_new = entry.domains.insert(domain);
        if entry.evidence.len() < MAX_EVIDENCE {
            entry.evidence.push(evidence_of(ev));
        }
        if !is_new || (entry.domains.len() as u32) < cfg.xdomain_min_domains {
            return;
        }
        // Novel *combination* for this actor — fire once per distinct combo.
        let combo: Vec<String> = entry.domains.iter().cloned().collect();
        let combo_key = combo.join(" + ");
        if self.xdomain_seen.contains(&combo_key) {
            return;
        }
        if self.xdomain_seen.len() < MAX_SEEN_PAIRS {
            self.xdomain_seen.insert(combo_key.clone());
        }
        let evidence = evidence_list(entry.evidence.iter());
        out.push(emit(
            ev,
            "app-cross-domain-access",
            "Novel access spanning multiple sensitive data domains in one session",
            "high",
            &["T1213", "T1005"],
            &[
                ("domains", combo_key),
                ("domain_count", combo.len().to_string()),
                ("contributing", evidence),
            ],
        ));
    }
}

// --------------------------------------------------------------------------
// field extraction helpers
// --------------------------------------------------------------------------

/// The subject/record identity accessed (for distinct-subject enumeration).
fn subject_key(rec: &AuditRecord) -> Option<String> {
    rec.action
        .subject_id
        .as_deref()
        .or(rec.action.record_id.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The trailing integer of the subject/record id, for adjacent-run detection.
/// `acct-100045` → `100045`, `P-000123` → `123`, `100046` → `100046`.
fn numeric_id(rec: &AuditRecord) -> Option<i64> {
    let raw = rec
        .action
        .subject_id
        .as_deref()
        .or(rec.action.record_id.as_deref())?
        .trim();
    let digits: String = raw
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse::<i64>().ok()
}

/// A stable session identity for cross-session/within-session correlation.
fn session_key(rec: &AuditRecord) -> String {
    rec.context
        .session_id
        .as_deref()
        .or(rec.context.transaction_id.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "-".to_string())
}

/// The accessed resource identity (object name, else path, else type).
fn object_key(rec: &AuditRecord) -> String {
    rec.action
        .object_name
        .as_deref()
        .or(rec.action.resource_path.as_deref())
        .or(rec.action.object_type.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "-".to_string())
}

/// The resource *type* (for per-type sequential runs).
fn object_type_key(rec: &AuditRecord) -> String {
    rec.action
        .object_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| object_key(rec))
}

/// The sensitive data *domain* touched — schema, else object type. `None` when no
/// domain can be attributed (nothing to correlate across).
fn domain_key(rec: &AuditRecord) -> Option<String> {
    rec.context
        .database_schema
        .as_deref()
        .or(rec.action.object_type.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn evidence_of(ev: &Event) -> String {
    ev.field("event_id")
        .map(str::to_string)
        .unwrap_or_else(|| ev.ts.timestamp_micros().to_string())
}

/// A bounded, comma-joined list of the most recent contributing evidence ids.
fn evidence_list<'a>(it: impl Iterator<Item = &'a String>) -> String {
    let all: Vec<&String> = it.collect();
    let take = all.len().min(MAX_EVIDENCE);
    all[all.len() - take..]
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn dec(map: &mut HashMap<String, u32>, key: &str) {
    if let Some(n) = map.get_mut(key) {
        *n -= 1;
        if *n == 0 {
            map.remove(key);
        }
    }
}

/// Build a [`SecurityFinding`] for a stateful episode, stamping the explanatory
/// `extra` fields (counts, window, contributing evidence) onto a clone of the
/// triggering event so the case carries them.
fn emit(
    ev: &Event,
    detector: &str,
    title: &str,
    base_level: &str,
    attack: &[&str],
    extra: &[(&str, String)],
) -> SecurityFinding {
    let mut ev = ev.clone();
    for (k, v) in extra {
        ev.fields.insert((*k).to_string(), v.clone());
    }
    let weight = garmr_core::level_weight(base_level);
    let evidence = evidence_of(&ev);
    SecurityFinding {
        finding_id: format!("{detector}:{evidence}"),
        detector: detector.to_string(),
        title: title.to_string(),
        base_level: base_level.to_string(),
        attack: attack.iter().map(|s| s.to_string()).collect(),
        observed_at: ev.ts,
        signals: vec![FindingSignal {
            family: DetectorFamily::AppAudit,
            rule_id: detector.to_string(),
            level: base_level.to_string(),
            weight,
        }],
        score: weight,
        band: SeverityBand::from_level(base_level),
        level: base_level.to_string(),
        env_basis: EnvBasis::default(),
        subject: AccessProjection::from_event(&ev),
        event: ev,
    }
}

#[cfg(test)]
mod tests;