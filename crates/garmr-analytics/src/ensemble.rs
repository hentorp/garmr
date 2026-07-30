// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7 — the ensemble scorer (pure, no I/O): the RBA weighting model minus
//! the learning. Given a finding's signals + its asset-criticality, it computes a
//! fused score, a severity band, and the final level (floored at the detector's
//! declared `base_level`).
//!
//! The core poison-safety property: `criticality_mult` is MONOTONIC-UP (always
//! `>= 1`), so a poisoned Trusted criticality fact can at worst OVER-alert
//! (noise), never suppress — criticality can only raise attention, never hide.

use garmr_core::{level_weight, EnvBasis, SecurityFinding, SeverityBand};

/// Tunable ensemble coefficients (built from config; pure so it is fully
/// table-testable).
#[derive(Debug, Clone)]
pub struct EnsemblePolicy {
    /// Coefficient on asset-criticality `c in [0,1]`: mult = 1 + crit_coef*c.
    pub crit_coef: f64,
    /// Coefficient on corroboration (distinct extra signals): mult = 1 + corr_coef*(n-1).
    pub corr_coef: f64,
    /// Score cutoffs for [Low, Medium, High, Critical] (below Low → Informational).
    pub bands: [f64; 4],
}

impl Default for EnsemblePolicy {
    fn default() -> Self {
        // Cutoffs in level_weight units (info=1, low=2, medium=4, high=8, crit=13).
        Self {
            crit_coef: 1.0,
            corr_coef: 0.25,
            bands: [2.0, 4.0, 8.0, 13.0],
        }
    }
}

impl EnsemblePolicy {
    fn band(&self, score: f64) -> SeverityBand {
        if score >= self.bands[3] {
            SeverityBand::Critical
        } else if score >= self.bands[2] {
            SeverityBand::High
        } else if score >= self.bands[1] {
            SeverityBand::Medium
        } else if score >= self.bands[0] {
            SeverityBand::Low
        } else {
            SeverityBand::Informational
        }
    }
}

/// Score a finding shell (detector/title/base_level/event/signals/env_basis
/// already set) in place. Returns `None` when there is no signal to score. Every
/// arithmetic step is finite-guarded so a NaN/inf weight can never poison the
/// band comparison. The final level is `max(band, base_level)` — criticality
/// NEVER lowers a detector below its declared floor.
pub fn assess(finding: SecurityFinding, policy: &EnsemblePolicy) -> Option<SecurityFinding> {
    assess_with(finding, policy, 1.0)
}

/// [`assess`] with one extra multiplier folded in (e.g. a user-monitoring
/// attention multiplier). `extra_mult` is clamped `.max(1.0)` and a non-finite
/// value falls back to `1.0`, so — exactly like criticality and corroboration —
/// it is MONOTONIC-UP: it can only raise attention, never suppress a finding
/// below what its signals + floor already earn.
pub fn assess_with(
    mut finding: SecurityFinding,
    policy: &EnsemblePolicy,
    extra_mult: f64,
) -> Option<SecurityFinding> {
    if finding.signals.is_empty() {
        return None;
    }
    // base = the peak signal weight (explicit weight, else its level's weight).
    let base = finding
        .signals
        .iter()
        .map(|s| {
            if s.weight.is_finite() && s.weight > 0.0 {
                s.weight
            } else {
                level_weight(&s.level)
            }
        })
        .fold(0.0_f64, f64::max);
    if base <= 0.0 {
        return None;
    }

    let c = (finding.env_basis.criticality as f64).clamp(0.0, 1.0);
    // MONOTONIC-UP: criticality can only raise attention.
    let crit_mult = (1.0 + policy.crit_coef * c).max(1.0);
    let extra = finding.signals.len().saturating_sub(1) as f64;
    let corr_mult = (1.0 + policy.corr_coef * extra).max(1.0);
    // The extra (attention) multiplier is likewise monotonic-up + finite-safe.
    let attn_mult = if extra_mult.is_finite() {
        extra_mult.max(1.0)
    } else {
        1.0
    };

    let mut score = base * crit_mult * corr_mult * attn_mult;
    if !score.is_finite() {
        score = base; // NaN/inf guard — never poison the comparison
    }
    let band = policy.band(score);
    // Floor at the detector's declared base level.
    let floored = band.max(SeverityBand::from_level(&finding.base_level));

    finding.score = score;
    finding.band = floored;
    finding.level = floored.as_level().to_string();
    Some(finding)
}

/// The rule-id PREFIX of the fused behavioral finding (the weak-cluster case).
/// The actual detector is `app-insider-risk-<band>` (e.g. `app-insider-risk-high`)
/// so the dedup identity is tiered by severity — see [`fuse_access`].
pub const FUSED_DETECTOR: &str = "app-insider-risk";

/// Fuse one access's application-audit findings into the case set that reaches
/// the pipeline, honoring the **policy ≠ anomaly** invariant via a three-way
/// partition:
///
/// 1. **Deterministic policy** findings (`is_policy`) — each stays its own case,
///    assessed individually (criticality still applies, but nothing corroborates
///    into or out of it: a forbidden action is neither softened by an anomaly nor
///    lends its authority to one).
/// 2. **Standalone-notable** findings (`is_standalone`, e.g. watched-subject,
///    privilege-change, service-account-misuse) — each stays its own explainable
///    case, assessed individually.
/// 3. **The weak cluster** (everything else — novelty / off-hours / volume /
///    self / bulk / export / failed) — merged into ONE `app-insider-risk`
///    finding whose corroboration multiplier reflects how many weak indicators
///    co-fired on the SAME access. Its `base_level` is the strongest constituent
///    (so the floor never drops below the strongest indicator), its `signals`
///    are the union of the constituents' signals (preserving per-indicator
///    explainability), and its `criticality` is the max across constituents.
///
/// `extra_mult` (the monitoring attention multiplier) is folded into every
/// finding via [`assess_with`] — monotonic-up. Findings with no scorable signal
/// are dropped (as [`assess`] already does).
pub fn fuse_access(
    findings: Vec<SecurityFinding>,
    policy: &EnsemblePolicy,
    is_policy: impl Fn(&str) -> bool,
    is_standalone: impl Fn(&str) -> bool,
    extra_mult: f64,
) -> Vec<SecurityFinding> {
    let mut out = Vec::new();
    let mut weak: Vec<SecurityFinding> = Vec::new();
    for f in findings {
        if is_policy(&f.detector) || is_standalone(&f.detector) {
            if let Some(a) = assess_with(f, policy, extra_mult) {
                out.push(a);
            }
        } else {
            weak.push(f);
        }
    }
    if let Some(fused) = fuse_weak(weak, policy, extra_mult) {
        out.push(fused);
    }
    out
}

/// Merge the weak-cluster findings for one access into a single assessed
/// `app-insider-risk` finding. Returns `None` for an empty cluster.
fn fuse_weak(
    weak: Vec<SecurityFinding>,
    policy: &EnsemblePolicy,
    extra_mult: f64,
) -> Option<SecurityFinding> {
    if weak.is_empty() {
        return None;
    }
    // Spine = the constituent with the strongest declared floor; it donates the
    // shared access event + base_level so the fused floor never drops below the
    // strongest indicator.
    let spine = weak
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| {
            level_weight(&a.base_level).total_cmp(&level_weight(&b.base_level))
        })
        .map(|(i, _)| i)
        .unwrap_or(0);

    let mut signals = Vec::new();
    let mut attack: Vec<String> = Vec::new();
    let mut trusted_facts: Vec<String> = Vec::new();
    let mut criticality = 0.0_f32;
    let mut baseline_size = 0usize;
    let mut asset_role: Option<String> = None;
    for f in &weak {
        for s in &f.signals {
            if !signals
                .iter()
                .any(|x: &garmr_core::FindingSignal| x.rule_id == s.rule_id)
            {
                signals.push(s.clone());
            }
        }
        for a in &f.attack {
            if !attack.contains(a) {
                attack.push(a.clone());
            }
        }
        for t in &f.env_basis.trusted_facts_consulted {
            if !trusted_facts.contains(t) {
                trusted_facts.push(t.clone());
            }
        }
        criticality = criticality.max(f.env_basis.criticality);
        baseline_size = baseline_size.max(f.env_basis.baseline_size);
        if asset_role.is_none() {
            asset_role = f.env_basis.asset_role.clone();
        }
    }

    let base_level = weak[spine].base_level.clone();
    let event = weak[spine].event.clone();
    let observed_at = weak[spine].observed_at;
    let subject = weak[spine].subject.clone();
    let evidence = event
        .field("event_id")
        .map(str::to_string)
        .unwrap_or_else(|| observed_at.timestamp_micros().to_string());

    let shell = SecurityFinding {
        finding_id: format!("{FUSED_DETECTOR}:{evidence}"),
        detector: FUSED_DETECTOR.to_string(),
        title: "Application-audit behavioral indicators".to_string(),
        base_level,
        attack,
        event,
        observed_at,
        signals,
        score: 0.0,
        band: SeverityBand::Informational,
        level: String::new(),
        env_basis: EnvBasis {
            trusted_facts_consulted: trusted_facts,
            baseline_size,
            asset_role,
            criticality,
        },
        subject,
    };
    let mut fused = assess_with(shell, policy, extra_mult)?;
    // Tier the DEDUP identity by the assessed band. `dedup_key` is
    // `rule_id|host|principal` and is severity-blind, so a single fixed detector
    // would let a later HIGHER-severity corroboration silently bump (never
    // re-triaged, RBA under-counted) or be suppressed into a lower-severity open
    // case for the same entity. Suffixing the band means same-tier weak accesses
    // still accumulate into one case per entity, but an escalation opens its own
    // case that is triaged + risk-scored at its true level.
    let tag = fused.band.as_level();
    fused.detector = format!("{FUSED_DETECTOR}-{tag}");
    fused.finding_id = format!("{}:{evidence}", fused.detector);
    Some(fused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_core::{DetectorFamily, EnvBasis, Event, FindingSignal};

    fn ev() -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "web01".into(),
            service: "s".into(),
            source: "src".into(),
            environment: "prod".into(),
            severity: "warning".into(),
            log_type: "system".into(),
            message: "m".into(),
            fields: std::collections::BTreeMap::new(),
        }
    }

    fn shell(base_level: &str, signals: Vec<FindingSignal>, criticality: f32) -> SecurityFinding {
        SecurityFinding {
            finding_id: "f".into(),
            detector: "env-new-edge".into(),
            title: "t".into(),
            base_level: base_level.into(),
            attack: vec![],
            event: ev(),
            observed_at: chrono::Utc::now(),
            signals,
            score: 0.0,
            band: SeverityBand::Informational,
            level: String::new(),
            env_basis: EnvBasis {
                criticality,
                ..Default::default()
            },
            subject: None,
        }
    }

    fn sig(level: &str) -> FindingSignal {
        FindingSignal {
            family: DetectorFamily::EnvEdge,
            rule_id: "env-new-edge".into(),
            level: level.into(),
            weight: 0.0,
        }
    }

    #[test]
    fn empty_signals_yield_none() {
        assert!(assess(shell("medium", vec![], 0.0), &EnsemblePolicy::default()).is_none());
    }

    #[test]
    fn criticality_only_raises_score() {
        let pol = EnsemblePolicy::default();
        let plain = assess(shell("medium", vec![sig("medium")], 0.0), &pol)
            .unwrap()
            .score;
        let critical = assess(shell("medium", vec![sig("medium")], 1.0), &pol)
            .unwrap()
            .score;
        assert!(critical > plain, "criticality raises the score");
        // Even at criticality 0 the multiplier floors at 1.0 (never suppresses).
        assert_eq!(plain, level_weight("medium"));
    }

    #[test]
    fn level_never_drops_below_the_declared_floor() {
        // A low-scoring signal but a HIGH base_level floor → level stays High.
        let f = assess(
            shell("high", vec![sig("informational")], 0.0),
            &EnsemblePolicy::default(),
        )
        .unwrap();
        assert_eq!(f.level, "high");
    }

    #[test]
    fn a_nan_weight_stays_finite() {
        let mut s = sig("medium");
        s.weight = f64::NAN;
        let f = assess(shell("medium", vec![s], 0.5), &EnsemblePolicy::default()).unwrap();
        assert!(f.score.is_finite());
    }

    #[test]
    fn vault_criticality_can_push_a_band_up() {
        let pol = EnsemblePolicy::default();
        // medium signal (weight 4) * (1 + 1.0*1.0) = 8.0 → High band.
        let f = assess(shell("medium", vec![sig("medium")], 1.0), &pol).unwrap();
        assert_eq!(f.band, SeverityBand::High);
    }

    // ---- assess_with (monitoring attention multiplier) ------------------

    #[test]
    fn extra_mult_only_raises_and_is_finite_safe() {
        let pol = EnsemblePolicy::default();
        let base = assess_with(shell("medium", vec![sig("medium")], 0.0), &pol, 1.0)
            .unwrap()
            .score;
        // A >1 multiplier raises.
        let boosted = assess_with(shell("medium", vec![sig("medium")], 0.0), &pol, 2.0)
            .unwrap()
            .score;
        assert!(boosted > base);
        // A <1 multiplier is clamped to 1.0 (never suppresses).
        let clamped = assess_with(shell("medium", vec![sig("medium")], 0.0), &pol, 0.1)
            .unwrap()
            .score;
        assert_eq!(clamped, base);
        // NaN falls back to 1.0.
        let nan = assess_with(shell("medium", vec![sig("medium")], 0.0), &pol, f64::NAN)
            .unwrap()
            .score;
        assert_eq!(nan, base);
    }

    // ---- fuse_access (three-way partition) ------------------------------

    fn app_sig(detector: &str, level: &str) -> FindingSignal {
        FindingSignal {
            family: DetectorFamily::AppAudit,
            rule_id: detector.into(),
            level: level.into(),
            weight: 0.0,
        }
    }

    fn app_finding(detector: &str, base_level: &str, criticality: f32) -> SecurityFinding {
        let mut f = shell(base_level, vec![app_sig(detector, base_level)], criticality);
        f.detector = detector.into();
        f.finding_id = format!("{detector}:e1");
        f.event.fields.insert("event_id".into(), "e1".into());
        f
    }

    fn is_policy(d: &str) -> bool {
        matches!(
            d,
            "app-forbidden-access" | "app-missing-justification" | "app-missing-approval"
        )
    }
    fn is_standalone(d: &str) -> bool {
        matches!(
            d,
            "app-watched-subject-access" | "app-privilege-change" | "app-service-account-misuse"
        )
    }

    #[test]
    fn policy_and_standalone_pass_through_weak_cluster_fuses() {
        let pol = EnsemblePolicy::default();
        let raw = vec![
            app_finding("app-forbidden-access", "critical", 0.0),
            app_finding("app-watched-subject-access", "high", 0.0),
            app_finding("app-new-query-pattern", "low", 0.0),
            app_finding("app-off-hours", "medium", 0.0),
            app_finding("app-volume-deviation", "high", 0.0),
        ];
        let out = fuse_access(raw, &pol, is_policy, is_standalone, 1.0);
        let detectors: Vec<&str> = out.iter().map(|f| f.detector.as_str()).collect();
        // policy + standalone keep their own detector; the 3 weak indicators fuse.
        assert!(detectors.contains(&"app-forbidden-access"));
        assert!(detectors.contains(&"app-watched-subject-access"));
        assert!(detectors.iter().any(|d| d.starts_with(FUSED_DETECTOR)));
        assert_eq!(
            out.len(),
            3,
            "1 policy + 1 standalone + 1 fused: {detectors:?}"
        );
        // No policy/standalone signal leaked into the fused finding.
        let fused = out
            .iter()
            .find(|f| f.detector.starts_with(FUSED_DETECTOR))
            .unwrap();
        assert_eq!(fused.signals.len(), 3, "the 3 weak indicators only");
        assert!(fused
            .signals
            .iter()
            .all(|s| !is_policy(&s.rule_id) && !is_standalone(&s.rule_id)));
        // Floor = strongest weak constituent (volume-deviation, high).
        assert!(fused.band >= SeverityBand::High);
        // The forbidden finding stays Critical regardless of any anomaly.
        let forbidden = out
            .iter()
            .find(|f| f.detector == "app-forbidden-access")
            .unwrap();
        assert_eq!(forbidden.level, "critical");
    }

    #[test]
    fn corroboration_raises_the_fused_band_on_a_sensitive_object() {
        let pol = EnsemblePolicy::default();
        // novelty(low) + off-hours(medium) + volume(high) on a Restricted object.
        let raw = vec![
            app_finding("app-new-query-pattern", "low", 1.0),
            app_finding("app-off-hours", "medium", 1.0),
            app_finding("app-volume-deviation", "high", 1.0),
        ];
        let out = fuse_access(raw, &pol, is_policy, is_standalone, 1.0);
        assert_eq!(out.len(), 1);
        let fused = &out[0];
        // base 8 (peak) * crit(1+1) * corr(1+0.25*2)=1.5 = 24 >= 13 → Critical.
        assert_eq!(fused.detector, "app-insider-risk-critical");
        assert_eq!(fused.band, SeverityBand::Critical);
        assert_eq!(fused.signals.len(), 3);
    }

    #[test]
    fn a_single_weak_indicator_still_fuses_and_floors() {
        let pol = EnsemblePolicy::default();
        let raw = vec![app_finding("app-off-hours", "medium", 0.0)];
        let out = fuse_access(raw, &pol, is_policy, is_standalone, 1.0);
        assert_eq!(out.len(), 1);
        assert!(out[0].detector.starts_with(FUSED_DETECTOR));
        assert_eq!(out[0].signals.len(), 1);
        assert!(out[0].band >= SeverityBand::Medium);
    }

    #[test]
    fn no_weak_indicators_yields_no_fused_finding() {
        let pol = EnsemblePolicy::default();
        let raw = vec![app_finding("app-forbidden-access", "critical", 0.0)];
        let out = fuse_access(raw, &pol, is_policy, is_standalone, 1.0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].detector, "app-forbidden-access");
        assert!(!out.iter().any(|f| f.detector.starts_with(FUSED_DETECTOR)));
    }

    #[test]
    fn fused_floor_never_drops_below_the_strongest_indicator() {
        let pol = EnsemblePolicy::default();
        // high + low, zero criticality, zero corroboration boost beyond count.
        let raw = vec![
            app_finding("app-volume-deviation", "high", 0.0),
            app_finding("app-new-client", "low", 0.0),
        ];
        let out = fuse_access(raw, &pol, is_policy, is_standalone, 1.0);
        let fused = out
            .iter()
            .find(|f| f.detector.starts_with(FUSED_DETECTOR))
            .unwrap();
        assert!(
            fused.band >= SeverityBand::High,
            "floor must be the strongest constituent (high)"
        );
    }

    #[test]
    fn fused_dedup_is_tiered_by_band_so_an_escalation_is_not_masked() {
        // The regression the review caught: a later higher-severity access must
        // NOT share a dedup identity with a lower-severity one for the same
        // entity. The fused detector is suffixed with the assessed band, so a
        // Medium access and a Critical access get DIFFERENT detectors (→ different
        // dedup_key → separate, correctly-triaged + risk-scored cases).
        let pol = EnsemblePolicy::default();
        let medium = fuse_access(
            vec![app_finding("app-off-hours", "medium", 0.0)],
            &pol,
            is_policy,
            is_standalone,
            1.0,
        );
        let critical = fuse_access(
            vec![app_finding("app-volume-deviation", "high", 1.0)],
            &pol,
            is_policy,
            is_standalone,
            1.0,
        );
        assert_eq!(medium[0].detector, "app-insider-risk-medium");
        assert_eq!(critical[0].detector, "app-insider-risk-critical");
        assert_ne!(medium[0].detector, critical[0].detector);
        // Two same-band accesses DO share a detector (accumulate into one case).
        let medium2 = fuse_access(
            vec![app_finding("app-new-client", "medium", 0.0)],
            &pol,
            is_policy,
            is_standalone,
            1.0,
        );
        assert_eq!(medium[0].detector, medium2[0].detector);
    }
}
