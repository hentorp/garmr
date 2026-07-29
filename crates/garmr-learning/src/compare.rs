// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Champion vs challenger comparison + the promotion gate.
//!
//! The gate is a SAFETY rule, not an improvement rule (improving is the
//! producer's job): a challenger is refused if it raises dangerous false
//! negatives beyond the allowed delta, OR if the Test holdout is too small OR
//! has too few dangerous positives to make the guard meaningful (the exact
//! vacuous-guard hole the adversarial review flagged — a suppression regression
//! must never pass on an all-negative holdout).

use garmr_core::{BucketCount, SeverityBand};

use crate::challenger::ChallengerScore;

/// The diff between a champion and a challenger on the Test holdout.
#[derive(Debug, Clone, PartialEq)]
pub struct ChallengerReport {
    pub champion: ChallengerScore,
    pub challenger: ChallengerScore,
    pub dangerous_fn_delta: i64,
    pub precision_delta: f64,
    pub recall_delta: f64,
    pub precision_at_budget_delta: f64,
}

/// Diff two scores (challenger − champion).
pub fn compare(champion: ChallengerScore, challenger: ChallengerScore) -> ChallengerReport {
    let dangerous_fn_delta = challenger.dangerous_fn as i64 - champion.dangerous_fn as i64;
    let precision_delta = challenger.precision - champion.precision;
    let recall_delta = challenger.recall - champion.recall;
    let precision_at_budget_delta = challenger.precision_at_budget - champion.precision_at_budget;
    ChallengerReport {
        champion,
        challenger,
        dangerous_fn_delta,
        precision_delta,
        recall_delta,
        precision_at_budget_delta,
    }
}

/// The promotion gate parameters.
#[derive(Debug, Clone, Copy)]
pub struct PromotionPolicy {
    /// Alerts per scoring window (precision@budget cap).
    pub alert_budget: usize,
    /// The band at/above which a finding is an escalation.
    pub alert_floor: SeverityBand,
    /// Max allowed increase in dangerous false negatives (default 0 — a
    /// challenger may never newly miss a dangerous positive).
    pub max_dangerous_fn_increase: i64,
    /// Minimum Test-holdout rows for a meaningful comparison.
    pub min_test_rows: usize,
    /// Minimum Test-holdout DANGEROUS positives — below this the dangerous-FN
    /// guard is vacuous and promotion is refused.
    pub min_dangerous_test_rows: usize,
}

impl Default for PromotionPolicy {
    fn default() -> Self {
        Self {
            alert_budget: 50,
            alert_floor: SeverityBand::High,
            max_dangerous_fn_increase: 0,
            min_test_rows: 5,
            min_dangerous_test_rows: 1,
        }
    }
}

/// The gate verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotableVerdict {
    pub promotable: bool,
    pub reasons: Vec<String>,
}

/// Decide whether a challenger may be promoted. `test` is the Test-holdout
/// [`BucketCount`] (`snapshot.bucket_counts().test`) so the guard is proven
/// non-vacuous before it can pass.
pub fn promotable(
    report: &ChallengerReport,
    test: BucketCount,
    policy: &PromotionPolicy,
) -> PromotableVerdict {
    let mut reasons = Vec::new();
    if test.total < policy.min_test_rows {
        reasons.push(format!(
            "test holdout too small: {} rows < required {}",
            test.total, policy.min_test_rows
        ));
    }
    if test.dangerous < policy.min_dangerous_test_rows {
        reasons.push(format!(
            "test holdout has too few dangerous positives ({} < {}): the dangerous-FN guard would be vacuous",
            test.dangerous, policy.min_dangerous_test_rows
        ));
    }
    if report.dangerous_fn_delta > policy.max_dangerous_fn_increase {
        reasons.push(format!(
            "challenger increases dangerous false negatives by {} (max allowed {})",
            report.dangerous_fn_delta, policy.max_dangerous_fn_increase
        ));
    }
    PromotableVerdict {
        promotable: reasons.is_empty(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(dangerous_fn: usize, precision: f64) -> ChallengerScore {
        ChallengerScore {
            rows: 20,
            dangerous_fn,
            precision,
            ..Default::default()
        }
    }

    fn healthy_test() -> BucketCount {
        BucketCount {
            total: 20,
            dangerous: 5,
        }
    }

    #[test]
    fn identical_scores_have_zero_deltas_and_promote() {
        let r = compare(score(2, 0.8), score(2, 0.8));
        assert_eq!(r.dangerous_fn_delta, 0);
        let v = promotable(&r, healthy_test(), &PromotionPolicy::default());
        assert!(
            v.promotable,
            "no dangerous-FN increase on a healthy holdout"
        );
    }

    #[test]
    fn accuracy_up_but_dangerous_fn_up_is_blocked() {
        // The load-bearing case: precision improved, but a dangerous positive is
        // newly missed → refused despite the accuracy gain.
        let champ = score(1, 0.6);
        let chal = score(3, 0.95); // higher precision, MORE dangerous misses
        let r = compare(champ, chal);
        assert!(r.precision_delta > 0.0);
        let v = promotable(&r, healthy_test(), &PromotionPolicy::default());
        assert!(!v.promotable);
        assert!(v
            .reasons
            .iter()
            .any(|s| s.contains("dangerous false negatives")));
    }

    #[test]
    fn a_holdout_with_no_dangerous_positives_is_blocked() {
        // Even a "no regression" challenger cannot pass a vacuous guard.
        let r = compare(score(0, 0.9), score(0, 0.9));
        let empty = BucketCount {
            total: 20,
            dangerous: 0,
        };
        let v = promotable(&r, empty, &PromotionPolicy::default());
        assert!(!v.promotable);
        assert!(v.reasons.iter().any(|s| s.contains("vacuous")));
    }

    #[test]
    fn a_tiny_holdout_is_blocked() {
        let r = compare(score(0, 0.9), score(0, 0.9));
        let tiny = BucketCount {
            total: 2,
            dangerous: 1,
        };
        let v = promotable(&r, tiny, &PromotionPolicy::default());
        assert!(!v.promotable);
        assert!(v.reasons.iter().any(|s| s.contains("too small")));
    }
}