// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The challenger policy + a PURE, deterministic, offline per-row replay.
//!
//! A *challenger* is a candidate detection policy. This MLP tunes the Phase-7
//! ensemble score-band surface, so [`ChallengerPolicy`] carries an
//! [`EnsemblePolicy`] (the tuned knobs) plus the champion's [`RiskParams`]
//! verbatim (so the projected artifact is a complete, applyable config).
//!
//! [`replay`] scores a snapshot's rows through the EXACT serve scorer
//! [`assess`], with an EVAL-OWNED escalation rule (`band >= alert_floor`). This
//! is the same scoring FUNCTION serve uses; the population (trusted-labeled
//! cases) and the band→escalate threshold are eval-owned until the deferred
//! serve-adoption phase wires serve to a band threshold. `corr_coef` is not
//! measurable on single-signal rows (it is pinned to the champion by the
//! producer); `crit_coef` IS measurable because rows carry the real per-case
//! criticality.

use garmr_analytics::ensemble::{assess, EnsemblePolicy};
use garmr_analytics::risk::RiskParams;
use garmr_core::{
    is_dangerous, DatasetSnapshot, DetectorConfigSpec, DetectorFamily, EnvBasis, Event,
    FindingSignal, LabelRow, SecurityFinding, SeverityBand, SplitBucket,
};

/// A candidate (or the champion) detection policy.
#[derive(Debug, Clone)]
pub struct ChallengerPolicy {
    pub ensemble: EnsemblePolicy,
    pub risk: RiskParams,
}

impl ChallengerPolicy {
    /// Project into the canonical [`DetectorConfigSpec`] artifact: RBA knobs in
    /// the typed fields, the retuned ensemble policy in `extra.ensemble` (the
    /// forward-compat seam). The freq/anomaly knobs are out of this MLP's scope
    /// (0 = unspecified) — serve-adoption of the full config is a later phase.
    pub fn to_spec(&self) -> DetectorConfigSpec {
        DetectorConfigSpec {
            risk_threshold: self.risk.threshold,
            risk_halflife_hours: self.risk.halflife_hours,
            prediction_discount: self.risk.prediction_discount,
            extra: serde_json::json!({
                "ensemble": {
                    "crit_coef": self.ensemble.crit_coef,
                    "corr_coef": self.ensemble.corr_coef,
                    "bands": self.ensemble.bands,
                }
            }),
            ..Default::default()
        }
    }

    /// Reconstruct a policy from a spec (ensemble from `extra.ensemble`, falling
    /// back to defaults for any missing knob).
    pub fn from_spec(spec: &DetectorConfigSpec) -> Self {
        let mut ensemble = EnsemblePolicy::default();
        if let Some(e) = spec.extra.get("ensemble") {
            if let Some(c) = e.get("crit_coef").and_then(|v| v.as_f64()) {
                ensemble.crit_coef = c;
            }
            if let Some(c) = e.get("corr_coef").and_then(|v| v.as_f64()) {
                ensemble.corr_coef = c;
            }
            if let Some(b) = e.get("bands").and_then(|v| v.as_array()) {
                for (i, x) in b.iter().take(4).enumerate() {
                    if let Some(f) = x.as_f64() {
                        ensemble.bands[i] = f;
                    }
                }
            }
        }
        let risk = RiskParams {
            threshold: spec.risk_threshold,
            halflife_hours: spec.risk_halflife_hours,
            realert_secs: 0,
            prediction_discount: spec.prediction_discount,
        };
        ChallengerPolicy { ensemble, risk }
    }
}

/// The scored outcome of a replay over one split bucket. `dangerous_fn` is the
/// guard metric: dangerous positives (Malicious/Suspicious) the policy would NOT
/// escalate. Under the MLP's single positive class it equals `fn_`; the separate
/// name marks the guard's intent and lets the class widen later.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChallengerScore {
    pub rows: usize,
    pub tp: usize,
    pub fp: usize,
    pub tn: usize,
    pub fn_: usize,
    pub precision: f64,
    pub recall: f64,
    pub precision_at_budget: f64,
    pub brier_est: f64,
    pub dangerous_fn: usize,
}

fn epoch() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(0, 0).unwrap_or_default()
}

/// The `(score, band)` a policy assigns to one row — the shared scoring core,
/// a pure replay of the EXACT serve scorer [`assess`] over a single-signal
/// finding carrying the row's rule level + real criticality.
pub fn score_row(policy: &ChallengerPolicy, row: &LabelRow) -> (f64, SeverityBand) {
    let shell = SecurityFinding {
        finding_id: String::new(),
        detector: "replay".into(),
        title: String::new(),
        base_level: row.rule_level.clone(),
        attack: Vec::new(),
        event: Event {
            ts: epoch(),
            host: "".into(),
            service: "".into(),
            source: "".into(),
            environment: "".into(),
            severity: "".into(),
            log_type: "".into(),
            message: String::new(),
            fields: std::collections::BTreeMap::new(),
        },
        observed_at: epoch(),
        signals: vec![FindingSignal {
            family: DetectorFamily::EnvEdge,
            rule_id: "replay".into(),
            level: row.rule_level.clone(),
            weight: 0.0,
        }],
        score: 0.0,
        band: SeverityBand::Informational,
        level: String::new(),
        env_basis: EnvBasis {
            criticality: row.criticality,
            ..Default::default()
        },
        subject: None,
    };
    match assess(shell, &policy.ensemble) {
        Some(f) => (if f.score.is_finite() { f.score } else { 0.0 }, f.band),
        None => (0.0, SeverityBand::Informational),
    }
}

/// Replay a policy over one split bucket. Pure and deterministic — no LLM, no
/// egress, no clock in the scoring path.
pub fn replay(
    snapshot: &DatasetSnapshot,
    policy: &ChallengerPolicy,
    bucket: SplitBucket,
    alert_floor: SeverityBand,
    alert_budget: usize,
) -> ChallengerScore {
    let mut s = ChallengerScore::default();
    // (score, is_positive) for escalated rows — for precision@budget.
    let mut escalated: Vec<(f64, bool)> = Vec::new();
    let mut brier_sum = 0.0_f64;
    // Normalizer for the Brier estimate: the top band cutoff (guarded > 0).
    let top = if policy.ensemble.bands[3].is_finite() && policy.ensemble.bands[3] > 0.0 {
        policy.ensemble.bands[3]
    } else {
        13.0
    };

    for r in snapshot.rows.iter().filter(|r| r.split == bucket) {
        s.rows += 1;
        let (fscore, band) = score_row(policy, r);
        let is_alert = band >= alert_floor;
        let positive = is_dangerous(r.trusted_disposition);
        match (is_alert, positive) {
            (true, true) => s.tp += 1,
            (true, false) => s.fp += 1,
            (false, true) => {
                s.fn_ += 1;
                s.dangerous_fn += 1; // the dangerous miss the guard protects
            }
            (false, false) => s.tn += 1,
        }
        if is_alert {
            escalated.push((fscore, positive));
        }
        let p = (fscore / top).clamp(0.0, 1.0);
        let y = if positive { 1.0 } else { 0.0 };
        brier_sum += (p - y) * (p - y);
    }

    // Precision: a policy that escalates NOTHING scores 0 (never a spurious 1.0
    // — the exact vacuous-guard hole the reviewer flagged).
    s.precision = if s.tp + s.fp == 0 {
        0.0
    } else {
        s.tp as f64 / (s.tp + s.fp) as f64
    };
    s.recall = if s.tp + s.fn_ == 0 {
        0.0
    } else {
        s.tp as f64 / (s.tp + s.fn_) as f64
    };
    escalated.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let take = alert_budget.min(escalated.len());
    s.precision_at_budget = if take == 0 {
        0.0
    } else {
        escalated.iter().take(take).filter(|(_, p)| *p).count() as f64 / take as f64
    };
    s.brier_est = if s.rows == 0 {
        0.0
    } else {
        brier_sum / s.rows as f64
    };
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_core::{Disposition, LabelRow, TrustSource};

    fn row(level: &str, crit: f32, disp: Disposition) -> LabelRow {
        LabelRow {
            case_id: "c".into(),
            rule_level: level.into(),
            criticality: crit,
            trusted_disposition: disp,
            trusted_severity: 5,
            trusted_source: TrustSource::AnalystDecision,
            opened_at_us: 0,
            split: SplitBucket::Test,
        }
    }

    fn snap(rows: Vec<LabelRow>) -> DatasetSnapshot {
        DatasetSnapshot {
            rows,
            ..Default::default()
        }
    }

    fn champion() -> ChallengerPolicy {
        ChallengerPolicy {
            ensemble: EnsemblePolicy::default(),
            risk: RiskParams {
                threshold: 10.0,
                halflife_hours: 12.0,
                realert_secs: 0,
                prediction_discount: 0.5,
            },
        }
    }

    #[test]
    fn spec_roundtrips() {
        let p = champion();
        let back = ChallengerPolicy::from_spec(&p.to_spec());
        assert_eq!(p.ensemble.crit_coef, back.ensemble.crit_coef);
        assert_eq!(p.ensemble.bands, back.ensemble.bands);
        assert_eq!(p.risk.threshold, back.risk.threshold);
    }

    #[test]
    fn a_suppress_challenger_raises_dangerous_fn_on_the_tunable_surface() {
        // The ensemble FLOORS a finding's band at its base_level, so a
        // rule_level-"high" dangerous finding always escalates and is immune to
        // band tuning (a genuine safety property). The tunable surface is
        // LOW/MEDIUM-base findings that criticality/corroboration push up. Two
        // medium-base, high-criticality Malicious rows: the champion escalates
        // them (score 4×2 = 8 → High); a challenger that raises all band cutoffs
        // suppresses them back to their Medium floor → dangerous_fn spikes.
        let s = snap(vec![
            row("medium", 1.0, Disposition::Malicious),
            row("medium", 1.0, Disposition::Malicious),
        ]);
        let champ = champion();
        let champ_sc = replay(&s, &champ, SplitBucket::Test, SeverityBand::High, 50);
        assert_eq!(champ_sc.tp, 2, "champion escalates both via criticality");
        assert_eq!(champ_sc.dangerous_fn, 0);

        let mut suppress = champion();
        suppress.ensemble.bands = [1e9, 1e9, 1e9, 1e9];
        let sc = replay(&s, &suppress, SplitBucket::Test, SeverityBand::High, 50);
        assert_eq!(sc.tp, 0);
        assert_eq!(sc.dangerous_fn, 2);
        assert_eq!(
            sc.precision, 0.0,
            "empty predictions never score a spurious 1.0"
        );
    }

    #[test]
    fn nan_criticality_stays_finite() {
        let s = snap(vec![row("medium", f32::NAN, Disposition::Suspicious)]);
        let sc = replay(&s, &champion(), SplitBucket::Test, SeverityBand::Low, 10);
        assert!(sc.brier_est.is_finite());
    }

    #[test]
    fn precision_at_budget_respects_the_cap() {
        // 3 escalated: 2 positive, 1 negative. Budget 2 by top score.
        let s = snap(vec![
            row("critical", 1.0, Disposition::Malicious),
            row("critical", 1.0, Disposition::Malicious),
            row("critical", 1.0, Disposition::Benign),
        ]);
        let sc = replay(&s, &champion(), SplitBucket::Test, SeverityBand::Low, 2);
        // All three escalate; top-2 by score are ties, precision@2 in [0.5,1.0].
        assert!(sc.precision_at_budget >= 0.5 && sc.precision_at_budget <= 1.0);
    }
}