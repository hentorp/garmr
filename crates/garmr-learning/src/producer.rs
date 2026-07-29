// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The offline challenger PRODUCER: a bounded, gate-constrained grid search over
//! the safe, measurable knobs. Fits on Train, selects on Val, and NEVER proposes
//! a candidate that regresses dangerous false negatives — so a guard-violating
//! config cannot even be produced, let alone promoted.
//!
//! The search space is deliberately restricted to what the single-signal replay
//! actually scores: the ensemble band cutoffs (a uniform scale) and `crit_coef`.
//! `corr_coef` (unmeasurable without multi-signal findings) and the RBA knobs are
//! PINNED to the champion. A deterministic grid in plain Rust — no ML dependency
//! (invariant #5).

use garmr_analytics::ensemble::EnsemblePolicy;
use garmr_core::{DatasetSnapshot, DetectorConfigSpec, SeverityBand, SplitBucket};

use crate::challenger::{replay, ChallengerPolicy, ChallengerScore};

/// A produced challenger and its Val-split score.
#[derive(Debug, Clone)]
pub struct Challenger {
    pub policy: ChallengerPolicy,
    pub val_score: ChallengerScore,
}

/// Search parameters (the escalation rule the fit optimizes under).
#[derive(Debug, Clone, Copy)]
pub struct SearchConfig {
    pub alert_floor: SeverityBand,
    pub alert_budget: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            alert_floor: SeverityBand::High,
            alert_budget: 50,
        }
    }
}

const CRIT_COEFS: [f64; 5] = [0.0, 0.5, 1.0, 1.5, 2.0];
const BAND_SCALES: [f64; 4] = [0.75, 1.0, 1.25, 1.5];

/// Fit a challenger over the bounded grid. Returns `None` when nothing strictly
/// beats the champion inside the dangerous-FN guard.
pub fn fit_challenger(
    snapshot: &DatasetSnapshot,
    champion: &ChallengerPolicy,
    cfg: &SearchConfig,
) -> Option<Challenger> {
    let base_bands = EnsemblePolicy::default().bands;
    let champ_train = replay(
        snapshot,
        champion,
        SplitBucket::Train,
        cfg.alert_floor,
        cfg.alert_budget,
    );
    let champ_val = replay(
        snapshot,
        champion,
        SplitBucket::Val,
        cfg.alert_floor,
        cfg.alert_budget,
    );

    let mut best: Option<Challenger> = None;
    for &cc in &CRIT_COEFS {
        for &bs in &BAND_SCALES {
            let mut policy = champion.clone();
            policy.ensemble.crit_coef = cc;
            policy.ensemble.bands = [
                base_bands[0] * bs,
                base_bands[1] * bs,
                base_bands[2] * bs,
                base_bands[3] * bs,
            ];
            // corr_coef + RBA knobs stay pinned to the champion.

            // Fit filter (Train): no dangerous regression, no precision loss.
            let train = replay(
                snapshot,
                &policy,
                SplitBucket::Train,
                cfg.alert_floor,
                cfg.alert_budget,
            );
            if train.dangerous_fn > champ_train.dangerous_fn
                || train.precision_at_budget < champ_train.precision_at_budget
            {
                continue;
            }
            // Select (Val): strict improvement, still no dangerous regression.
            let val = replay(
                snapshot,
                &policy,
                SplitBucket::Val,
                cfg.alert_floor,
                cfg.alert_budget,
            );
            if val.dangerous_fn > champ_val.dangerous_fn
                || val.precision_at_budget <= champ_val.precision_at_budget
            {
                continue;
            }
            let better = match &best {
                None => true,
                Some(b) => {
                    (val.precision_at_budget, b.val_score.dangerous_fn)
                        > (b.val_score.precision_at_budget, val.dangerous_fn)
                }
            };
            if better {
                best = Some(Challenger {
                    policy,
                    val_score: val,
                });
            }
        }
    }
    best
}

/// Project a produced challenger into the canonical artifact + a content digest.
pub fn challenger_to_spec(ch: &Challenger) -> (DetectorConfigSpec, String) {
    let spec = ch.policy.to_spec();
    let bytes = serde_json::to_vec(&spec).unwrap_or_default();
    let digest = garmr_core::frame(&[b"detector_config", bytes.as_slice()]);
    (spec, digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_analytics::risk::RiskParams;
    use garmr_core::{Disposition, LabelRow, SplitBucket, TrustSource};

    fn row(level: &str, crit: f32, disp: Disposition, split: SplitBucket) -> LabelRow {
        LabelRow {
            case_id: "c".into(),
            rule_level: level.into(),
            criticality: crit,
            trusted_disposition: disp,
            trusted_severity: 5,
            trusted_source: TrustSource::AnalystDecision,
            opened_at_us: 0,
            split,
        }
    }

    // A snapshot where medium-base, high-criticality Malicious cases sit in both
    // Train and Val: a low crit_coef under-escalates them (dangerous misses); a
    // higher crit_coef lifts them over the High floor.
    fn under_escalating_snapshot() -> DatasetSnapshot {
        let mut rows = Vec::new();
        for split in [SplitBucket::Train, SplitBucket::Val] {
            for _ in 0..4 {
                rows.push(row("medium", 1.0, Disposition::Malicious, split));
            }
            for _ in 0..2 {
                rows.push(row("low", 0.0, Disposition::Benign, split));
            }
        }
        DatasetSnapshot {
            rows,
            ..Default::default()
        }
    }

    fn policy(crit_coef: f64) -> ChallengerPolicy {
        let ensemble = EnsemblePolicy {
            crit_coef,
            ..EnsemblePolicy::default()
        };
        ChallengerPolicy {
            ensemble,
            risk: RiskParams {
                threshold: 10.0,
                halflife_hours: 12.0,
                realert_secs: 0,
                prediction_discount: 0.5,
            },
        }
    }

    #[test]
    fn fit_finds_a_better_config_and_never_regresses_dangerous_fn() {
        let s = under_escalating_snapshot();
        let champ = policy(0.0); // under-escalates the dangerous medium cases
        let champ_val = replay(&s, &champ, SplitBucket::Val, SeverityBand::High, 50);
        let found = fit_challenger(&s, &champ, &SearchConfig::default())
            .expect("a higher crit_coef beats the under-escalating champion");
        assert!(found.policy.ensemble.crit_coef > 0.0);
        // The safety property: the produced challenger NEVER regresses dangerous FNs.
        assert!(found.val_score.dangerous_fn <= champ_val.dangerous_fn);
        assert!(found.val_score.precision_at_budget > champ_val.precision_at_budget);
    }

    #[test]
    fn fit_returns_none_when_the_champion_is_already_optimal() {
        let s = under_escalating_snapshot();
        let champ = policy(2.0); // already escalates everything correctly
        assert!(
            fit_challenger(&s, &champ, &SearchConfig::default()).is_none(),
            "nothing strictly beats an already-optimal champion"
        );
    }

    #[test]
    fn to_spec_is_deterministic() {
        let s = under_escalating_snapshot();
        let ch = fit_challenger(&s, &policy(0.0), &SearchConfig::default()).unwrap();
        let (_, d1) = challenger_to_spec(&ch);
        let (_, d2) = challenger_to_spec(&ch);
        assert_eq!(d1, d2);
        assert!(!d1.is_empty());
    }
}