// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Champion/challenger **shadow evaluation** for the application-audit stateful
//! detector plane (DoD 19).
//!
//! When a `DetectorConfig` challenger is registered on the **`shadow`** promotion
//! channel, the live pipeline scores every eligible audit event through BOTH the
//! production ("champion") stateful config and the challenger, and records where
//! the two disagree — challenger-only detections (candidate new catches OR new
//! false positives) and champion-only detections (regressions; a dropped
//! high-severity champion detection is a **dangerous miss**). The champion output
//! is never altered — the challenger only observes — so this is a strictly
//! additive, human-gated comparison with **no auto-promotion**.
//!
//! Two safety properties make it deployable to a live SOC:
//!   1. It is dormant unless `GARMR_SHADOW` is set AND a challenger is live on the
//!      `shadow` channel — the default deployment runs exactly as before.
//!   2. The challenger runs on its OWN in-memory windows; a bug in it can add a
//!      spurious shadow row but can never change a champion detection or a case.
//!
//! The precision/recall/FPR/FNR the DoD asks for need ground truth, which live
//! traffic lacks; those numbers come from the labeled `garmr synth-eval` harness
//! (DoD 21) run over both configs. What this plane surfaces on LIVE traffic is the
//! honest, label-free signal: the champion-vs-challenger disagreement counts and a
//! recommended decision derived from them.

use std::collections::{BTreeSet, HashMap, VecDeque};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use garmr_appdetect::stateful::{StatefulConfig, StatefulDetectors, StatefulState};
use garmr_core::{active, AuditRecord, DetectorConfigSpec, Event, RegistryKind, SecurityFinding};
use garmr_store::StateStore;

/// The `shadow` promotion channel a challenger is registered on.
pub(crate) const SHADOW_CHANNEL: &str = "shadow";

/// Cap on the in-memory ring of recent disagreement examples surfaced by the read
/// API. The durable decision signal is the [`ShadowSummary`] counters; the ring is
/// a bounded convenience for eyeballing WHAT diverged, so it need not survive a
/// restart.
const RECENT_CAP: usize = 200;

/// `true` when the shadow-evaluation plane is switched on (`GARMR_SHADOW=1|true|
/// yes|on`). Off by default: a build ships inert, exactly like every other
/// `GARMR_*` opt-in, so deploying the binary changes nothing until an operator
/// enables it AND registers a challenger.
pub fn shadow_enabled() -> bool {
    matches!(
        std::env::var("GARMR_SHADOW").ok().as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Running counters for the live champion-vs-challenger comparison. Cheap to
/// upsert (a single blob), so it rides the existing baseline/stateful flush
/// cadence and survives a restart — the durable decision signal.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShadowSummary {
    /// The challenger these counters describe (registry name + version). A summary
    /// whose `(name, version)` no longer matches the live challenger is reset — a
    /// new challenger always starts from zero, never inherits stale tallies.
    pub challenger_name: String,
    pub challenger_version: String,
    /// Eligible audit events scored through both planes.
    pub events_scored: u64,
    /// Events where champion and challenger detections differed at all.
    pub diff_events: u64,
    /// Detector-firings the challenger produced that the champion did not (per
    /// event, summed) — candidate new catches OR new false positives.
    pub challenger_only: u64,
    /// Detector-firings the champion produced that the challenger did not — the
    /// challenger's regressions.
    pub champion_only: u64,
    /// Events with at least one champion-only high/critical drop — the regression
    /// class that must block a promotion. Counted per event, not per firing (an
    /// event with two dangerous drops counts once); the recommendation only tests
    /// `> 0`, so the distinction is informational.
    pub dangerous_misses: u64,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

/// One recorded champion-vs-challenger disagreement (an eyeball example).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShadowScore {
    pub at: DateTime<Utc>,
    pub evidence_id: String,
    pub actor: String,
    pub object: String,
    /// Champion stateful detector ids that fired on this event.
    pub champion: Vec<String>,
    /// Challenger stateful detector ids that fired on this event.
    pub challenger: Vec<String>,
    /// Challenger-only (added) detector ids.
    pub added: Vec<String>,
    /// Champion-only (removed) detector ids.
    pub removed: Vec<String>,
    /// A high/critical champion detection was among the removed — a dangerous miss.
    pub dangerous_miss: bool,
}

/// The live challenger plane: its own detector engine + windows, plus the running
/// comparison against the champion.
pub struct ShadowPlane {
    pub name: String,
    pub version: String,
    detectors: StatefulDetectors,
    summary: ShadowSummary,
    recent: VecDeque<ShadowScore>,
}

/// A champion detector base level that counts as "dangerous" to drop.
fn is_dangerous(base_level: &str) -> bool {
    matches!(
        base_level.trim().to_ascii_lowercase().as_str(),
        "high" | "critical"
    )
}

/// The set difference over detector ids: `(challenger_only, champion_only)`. Pure
/// and order-independent (dedupes within each side), so it is trivially testable.
pub fn diff_detectors(champion: &[String], challenger: &[String]) -> (Vec<String>, Vec<String>) {
    let champ: BTreeSet<&str> = champion.iter().map(String::as_str).collect();
    let chal: BTreeSet<&str> = challenger.iter().map(String::as_str).collect();
    let challenger_only = chal.difference(&champ).map(|s| s.to_string()).collect();
    let champion_only = champ.difference(&chal).map(|s| s.to_string()).collect();
    (challenger_only, champion_only)
}

/// The recommended decision, purely a function of the accumulated counters. No
/// auto-promotion — this is advice for a human operator, and it is deliberately
/// conservative: any dangerous miss vetoes, any plain regression demands review,
/// and only a strict superset (adds, drops nothing) is a promote candidate.
pub fn recommendation(s: &ShadowSummary, has_challenger: bool) -> String {
    if !has_challenger {
        return "no challenger registered on the shadow channel".into();
    }
    if s.events_scored == 0 {
        return "challenger registered; no eligible events scored yet".into();
    }
    if s.dangerous_misses > 0 {
        return format!(
            "REJECT — challenger drops {} high-severity champion detection(s) (dangerous miss)",
            s.dangerous_misses
        );
    }
    if s.champion_only > 0 {
        return format!(
            "REVIEW — challenger misses {} champion detection(s) (none high-severity)",
            s.champion_only
        );
    }
    if s.challenger_only > 0 {
        return format!(
            "PROMOTE CANDIDATE — challenger adds {} detection(s) and drops none over {} events",
            s.challenger_only, s.events_scored
        );
    }
    "NEUTRAL — champion and challenger agree on every scored event".into()
}

impl ShadowPlane {
    /// Score one event through the challenger and fold the champion-vs-challenger
    /// diff into the running counters + the recent-examples ring. `champion` is the
    /// champion stateful plane's findings for THIS event (already computed by the
    /// live pipeline), so the challenger is the only extra detector work.
    pub fn observe(
        &mut self,
        ev: &Event,
        rec: &AuditRecord,
        forbidden: bool,
        failed: bool,
        champion: &[SecurityFinding],
    ) {
        let chal = self.detectors.observe(ev, rec, forbidden, failed);

        let champ_ids: Vec<String> = champion.iter().map(|f| f.detector.clone()).collect();
        let chal_ids: Vec<String> = chal.iter().map(|f| f.detector.clone()).collect();
        let (added, removed) = diff_detectors(&champ_ids, &chal_ids);

        self.summary.events_scored += 1;
        if added.is_empty() && removed.is_empty() {
            return; // agreement — the common case; nothing to record
        }

        // A champion base level keyed by detector, to grade the dropped ones.
        let champ_level: HashMap<&str, &str> = champion
            .iter()
            .map(|f| (f.detector.as_str(), f.base_level.as_str()))
            .collect();
        let dangerous_miss = removed.iter().any(|d| {
            champ_level
                .get(d.as_str())
                .is_some_and(|lvl| is_dangerous(lvl))
        });

        self.summary.diff_events += 1;
        self.summary.challenger_only += added.len() as u64;
        self.summary.champion_only += removed.len() as u64;
        if dangerous_miss {
            self.summary.dangerous_misses += 1;
        }
        self.summary.updated_at = Some(ev.ts);

        if self.recent.len() >= RECENT_CAP {
            self.recent.pop_front();
        }
        self.recent.push_back(ShadowScore {
            at: ev.ts,
            evidence_id: ev.field("event_id").unwrap_or_default().to_string(),
            actor: rec.actor.actor_id.clone(),
            object: rec
                .action
                .object_name
                .clone()
                .or_else(|| rec.action.object_type.clone())
                .unwrap_or_default(),
            champion: champ_ids,
            challenger: chal_ids,
            added,
            removed,
            dangerous_miss,
        });
    }

    /// A snapshot of the counters (for the read API / persistence).
    pub fn summary(&self) -> ShadowSummary {
        self.summary.clone()
    }

    /// The most recent disagreement examples, newest first, capped at `limit`.
    pub fn recent(&self, limit: usize) -> Vec<ShadowScore> {
        self.recent.iter().rev().take(limit).cloned().collect()
    }
}

/// Load the live shadow challenger from the governed registry, or `None` when the
/// plane is disabled, no challenger is live on the `shadow` channel, or its spec
/// carries no stateful override. A `DetectorConfig` record activates a challenger
/// by carrying its stateful knobs under `spec.extra.stateful` (a partial
/// [`StatefulConfig`] — omitted knobs fall back to the champion defaults).
///
/// `prev` (the persisted summary, if any) seeds the counters ONLY when it belongs
/// to the same `(name, version)` challenger; a different challenger starts fresh.
///
/// `champion_state` is the champion stateful plane's CURRENT window state. The
/// challenger is seeded from a clone of it (not empty windows) so the comparison
/// is fair from the very first event: a warm champion catching an in-progress
/// long-horizon episode (low-and-slow / sequential) would otherwise show up as a
/// spurious `champion_only`/`dangerous_miss` against a cold challenger and mislead
/// the recommendation toward a false REJECT. The one inherent limitation of
/// starting mid-stream: the challenger inherits the champion's already-reported
/// episodes, so it is never credited for re-flagging an episode the champion
/// reported before the challenger was registered.
pub fn load_shadow_challenger(
    state: &StateStore,
    prev: Option<ShadowSummary>,
    champion_state: StatefulState,
) -> Option<ShadowPlane> {
    if !shadow_enabled() {
        return None;
    }
    let records = state.list_kind(RegistryKind::DetectorConfig).ok()?;
    let promotions = state.list_promotions().ok()?;
    let mut names: Vec<&str> = records.iter().map(|r| r.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();

    // The first name with a live record on the shadow channel wins; more than one
    // is a mis-registration we surface loudly rather than silently blending.
    let mut chosen = None;
    for name in names {
        if let Some(rec) = active(
            RegistryKind::DetectorConfig,
            name,
            SHADOW_CHANNEL,
            &records,
            &promotions,
        ) {
            if chosen.is_some() {
                tracing::warn!(
                    ignored = name,
                    "more than one challenger is live on the shadow channel; using the first by name"
                );
                continue;
            }
            chosen = Some(rec);
        }
    }
    let rec = chosen?;

    let spec: DetectorConfigSpec = serde_json::from_value(rec.spec.clone())
        .map_err(|e| tracing::warn!(challenger = %rec.name, error = %e, "shadow challenger spec is not a DetectorConfigSpec; ignoring"))
        .ok()?;
    let stateful_value = spec.extra.get("stateful").cloned().or_else(|| {
        tracing::warn!(
            challenger = %rec.name,
            "shadow challenger carries no `extra.stateful` override; the stateful plane has nothing to vary — ignoring"
        );
        None
    })?;
    let cfg: StatefulConfig = serde_json::from_value(stateful_value)
        .map_err(|e| tracing::warn!(challenger = %rec.name, error = %e, "shadow challenger `extra.stateful` is not a StatefulConfig; ignoring"))
        .ok()?;

    // Inherit prior counters only for the SAME challenger identity, else start fresh.
    let summary = match prev {
        Some(p) if p.challenger_name == rec.name && p.challenger_version == rec.version => p,
        _ => ShadowSummary {
            challenger_name: rec.name.clone(),
            challenger_version: rec.version.clone(),
            ..Default::default()
        },
    };

    tracing::info!(
        challenger = %rec.name,
        version = %rec.version,
        "shadow challenger loaded — champion/challenger evaluation active"
    );
    Some(ShadowPlane {
        name: rec.name.clone(),
        version: rec.version.clone(),
        // Seed from the champion's current windows (see the doc comment) so the
        // challenger diverges only where its CONFIG differs, not because it started
        // cold against a warm champion.
        detectors: StatefulDetectors::from_state(cfg, champion_state),
        summary,
        recent: VecDeque::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_is_symmetric_difference_of_detector_ids() {
        let champ = vec!["a".to_string(), "b".to_string(), "b".to_string()];
        let chal = vec!["b".to_string(), "c".to_string()];
        let (added, removed) = diff_detectors(&champ, &chal);
        assert_eq!(added, vec!["c".to_string()]); // challenger-only
        assert_eq!(removed, vec!["a".to_string()]); // champion-only (deduped)
    }

    #[test]
    fn identical_sets_have_no_diff() {
        let a = vec!["x".to_string(), "y".to_string()];
        let (added, removed) = diff_detectors(&a, &a);
        assert!(added.is_empty() && removed.is_empty());
    }

    #[test]
    fn recommendation_is_conservative() {
        let has = true;
        let mut s = ShadowSummary {
            events_scored: 100,
            ..Default::default()
        };
        // strict superset -> promote candidate
        s.challenger_only = 3;
        assert!(recommendation(&s, has).starts_with("PROMOTE CANDIDATE"));
        // any plain regression -> review
        s.champion_only = 1;
        assert!(recommendation(&s, has).starts_with("REVIEW"));
        // a dangerous miss vetoes everything
        s.dangerous_misses = 1;
        assert!(recommendation(&s, has).starts_with("REJECT"));
        // no events -> not-yet
        let empty = ShadowSummary::default();
        assert!(recommendation(&empty, has).contains("no eligible events"));
        // no challenger at all
        assert!(recommendation(&empty, false).contains("no challenger"));
    }

    #[test]
    fn dangerous_grading() {
        assert!(is_dangerous("high"));
        assert!(is_dangerous("CRITICAL"));
        assert!(!is_dangerous("medium"));
        assert!(!is_dangerous("low"));
    }

    // --- accounting through REAL detectors ----------------------------------

    use std::collections::BTreeMap;

    use garmr_core::app_audit::keys;

    /// A sensitive persons access carrying a sequential record id — the input the
    /// sequential-enumeration detector keys on. `sensitive_resource` is stamped
    /// directly (no catalog in a unit test) so the require-sensitive gate passes.
    fn sensitive_walk_event(actor: &str, record_id: i64, secs: i64) -> (Event, AuditRecord) {
        let mut f = BTreeMap::new();
        f.insert(keys::ACTOR.to_string(), actor.to_string());
        f.insert(keys::OBJECT_NAME.to_string(), "curated.persons".to_string());
        f.insert(keys::OBJECT_TYPE.to_string(), "persons".to_string());
        f.insert(keys::RECORD_ID.to_string(), record_id.to_string());
        f.insert(keys::ACTION.to_string(), "select".to_string());
        f.insert(keys::OUTCOME.to_string(), "success".to_string());
        let ev = Event {
            ts: DateTime::<Utc>::from_timestamp(1_770_000_000 + secs, 0).unwrap(),
            host: "db01".into(),
            service: "postgres".into(),
            source: "postgres-csvlog".into(),
            environment: "prod".into(),
            severity: "info".into(),
            log_type: "audit".into(),
            message: "AUDIT: select curated.persons".into(),
            fields: f,
        };
        let mut rec = AuditRecord::from_event(&ev);
        rec.classification.sensitive_resource = true;
        (ev, rec)
    }

    fn plane_from(detectors: StatefulDetectors) -> ShadowPlane {
        ShadowPlane {
            name: "challenger".into(),
            version: "1".into(),
            detectors,
            summary: ShadowSummary {
                challenger_name: "challenger".into(),
                challenger_version: "1".into(),
                ..Default::default()
            },
            recent: VecDeque::new(),
        }
    }

    fn plane_with(cfg: StatefulConfig) -> ShadowPlane {
        plane_from(StatefulDetectors::new(cfg))
    }

    /// A more sensitive challenger (fires the sequential walk earlier than the
    /// champion) shows up as challenger-only additions — never a dangerous miss.
    #[test]
    fn challenger_only_additions_are_tallied() {
        let champion_cfg = StatefulConfig::default(); // seq_run_len = 12
        let challenger_cfg = StatefulConfig {
            seq_run_len: 4,
            ..StatefulConfig::default()
        };
        let mut champion = StatefulDetectors::new(champion_cfg);
        let mut plane = plane_with(challenger_cfg);

        for i in 0..8 {
            let (ev, rec) = sensitive_walk_event("scanner", 100 + i, i * 7);
            let champ = champion.observe(&ev, &rec, false, false);
            plane.observe(&ev, &rec, false, false, &champ);
        }

        let s = plane.summary();
        assert_eq!(s.events_scored, 8);
        assert!(
            s.challenger_only > 0,
            "the seq_run_len=4 challenger should add detections"
        );
        assert_eq!(
            s.champion_only, 0,
            "champion (seq_run_len=12) added nothing to drop"
        );
        assert_eq!(
            s.dangerous_misses, 0,
            "a challenger-only add is never a dangerous miss"
        );
        assert!(plane
            .recent(10)
            .iter()
            .any(|r| r.added.iter().any(|d| d == "app-enumeration-sequential")));
    }

    /// A LESS sensitive challenger (misses a walk the champion catches) shows up
    /// as a champion-only drop, and because the sequential finding on a sensitive
    /// access is high-severity, that drop is a dangerous miss.
    #[test]
    fn champion_only_high_severity_drop_is_a_dangerous_miss() {
        let champion_cfg = StatefulConfig {
            seq_run_len: 4,
            ..StatefulConfig::default()
        };
        let challenger_cfg = StatefulConfig::default(); // seq_run_len = 12 — won't fire
        let mut champion = StatefulDetectors::new(champion_cfg);
        let mut plane = plane_with(challenger_cfg);

        for i in 0..8 {
            let (ev, rec) = sensitive_walk_event("scanner", 100 + i, i * 7);
            let champ = champion.observe(&ev, &rec, false, false);
            plane.observe(&ev, &rec, false, false, &champ);
        }

        let s = plane.summary();
        assert_eq!(s.events_scored, 8);
        assert!(
            s.champion_only > 0,
            "champion caught a walk the challenger missed"
        );
        assert_eq!(s.challenger_only, 0, "challenger added nothing");
        assert!(
            s.dangerous_misses > 0,
            "a dropped high-severity sensitive enumeration is dangerous"
        );
    }

    /// SF-2 regression: an identical-config challenger SEEDED from the champion's
    /// warm windows agrees exactly — no spurious champion-only / dangerous-miss —
    /// even when the champion is mid-episode. A COLD challenger (empty windows)
    /// would miss the champion's sequential trip and false-REJECT here.
    #[test]
    fn seeded_identical_challenger_has_no_spurious_diff_mid_episode() {
        let cfg = StatefulConfig::default(); // seq_run_len = 12
        let mut champion = StatefulDetectors::new(cfg.clone());
        // Warm the champion up mid-run (6 < 12 steps — nothing fired yet).
        for i in 0..6 {
            let (ev, rec) = sensitive_walk_event("scanner", 100 + i, i * 7);
            champion.observe(&ev, &rec, false, false);
        }
        // The challenger: SAME config, SEEDED from the champion's warm windows.
        let mut plane = plane_from(StatefulDetectors::from_state(cfg, champion.state().clone()));
        // Continue the run through the trip point on BOTH planes.
        for i in 6..14 {
            let (ev, rec) = sensitive_walk_event("scanner", 100 + i, i * 7);
            let champ = champion.observe(&ev, &rec, false, false);
            plane.observe(&ev, &rec, false, false, &champ);
        }
        let s = plane.summary();
        // Same config + same seed windows => exact agreement (champion trips
        // sequential; so does the seeded challenger, at the same event).
        assert_eq!(
            s.champion_only, 0,
            "a seeded identical challenger must not show champion-only drops"
        );
        assert_eq!(
            s.challenger_only, 0,
            "a seeded identical challenger must not add"
        );
        assert_eq!(
            s.dangerous_misses, 0,
            "no dangerous miss when the two agree"
        );
    }
}
