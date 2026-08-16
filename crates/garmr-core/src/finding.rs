// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 7 — `SecurityFinding`, the detection plane's unified output.
//!
//! A finding wraps the triggering signal(s) + the ensemble score + the
//! environment basis (which TRUSTED facts justified it — never a Candidate). It
//! is the plane's RICHER internal record; it LOWERS to a [`Detection`] via
//! [`SecurityFinding::into_detection`] so it flows through the SAME
//! case → triage → propose → human-approve pipeline as every other signal. It
//! never replaces `Detection` and never opens a second path to a case: the plane
//! PRODUCES findings, it does not act.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AccessProjection, Detection, Event};

/// Rule-declared / detector-declared severity → base weight, in the SAME units
/// as the RBA risk score (the single source of truth; risk.rs delegates here).
/// Unknown levels fall back to "low".
pub fn level_weight(level: &str) -> f64 {
    // Compare case-insensitively without allocating: callers on the detection hot
    // path pass hardcoded lowercase literals, so the old `to_ascii_lowercase()`
    // minted a throwaway `String` per call for nothing. `eq_ignore_ascii_case`
    // is byte-identical to lowercase-then-match for this ASCII vocabulary.
    let eq = |c: &str| level.eq_ignore_ascii_case(c);
    if eq("critical") {
        13.0
    } else if eq("high") {
        8.0
    } else if eq("medium") {
        4.0
    } else if eq("low") {
        2.0
    } else if eq("informational") || eq("info") {
        1.0
    } else {
        2.0
    }
}

/// The detector family a signal came from. `Unknown` is the forward-compat
/// catch-all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorFamily {
    Sigma,
    Correlation,
    Anomaly,
    Baseline,
    Rba,
    Hunt,
    /// New-edge / new-identity vs the Trusted environment baseline (Phase 7).
    EnvEdge,
    /// Application-audit / insider-risk detectors over the canonical audit model
    /// (policy violations, sensitive access, enumeration, export, …).
    AppAudit,
    #[default]
    #[serde(other)]
    Unknown,
}

/// A severity band derived from the fused score. Ordered so a band can be
/// compared against a detector's declared floor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityBand {
    #[default]
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityBand {
    /// The level string a band lowers to (matches the rule-level vocabulary).
    pub fn as_level(self) -> &'static str {
        match self {
            SeverityBand::Informational => "informational",
            SeverityBand::Low => "low",
            SeverityBand::Medium => "medium",
            SeverityBand::High => "high",
            SeverityBand::Critical => "critical",
        }
    }

    /// The band a level string names (unknown → Low).
    pub fn from_level(level: &str) -> SeverityBand {
        // Allocation-free, byte-identical to the old lowercase-then-match (see
        // `level_weight`): the hot-path callers pass lowercase literals.
        let eq = |c: &str| level.eq_ignore_ascii_case(c);
        if eq("critical") {
            SeverityBand::Critical
        } else if eq("high") {
            SeverityBand::High
        } else if eq("medium") {
            SeverityBand::Medium
        } else if eq("informational") || eq("info") {
            SeverityBand::Informational
        } else {
            SeverityBand::Low
        }
    }
}

/// One signal that contributed to a finding — generalizes the RBA `Contributor`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FindingSignal {
    #[serde(default)]
    pub family: DetectorFamily,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub weight: f64,
}

/// The ENVIRONMENT basis of a finding — provenance for the score, never a
/// Candidate id. Every fact id here is a TRUSTED fact the detector consulted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EnvBasis {
    #[serde(default)]
    pub trusted_facts_consulted: Vec<String>,
    #[serde(default)]
    pub baseline_size: usize,
    #[serde(default)]
    pub asset_role: Option<String>,
    /// Asset-criticality in `[0, 1]` (from a TRUSTED role fact only) — the
    /// multiplier is monotonic-up, so this can only raise attention.
    #[serde(default)]
    pub criticality: f32,
}

/// The detection plane's unified output. (Not `Default`/`PartialEq` — it always
/// wraps a real `Event`, which is neither.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    #[serde(default)]
    pub finding_id: String,
    /// The detector name (also the lowered Detection's `rule_id`, so a burst
    /// dedups to one case per entity per detector).
    #[serde(default)]
    pub detector: String,
    #[serde(default)]
    pub title: String,
    /// The detector's declared severity floor — `level` is never below it.
    #[serde(default)]
    pub base_level: String,
    #[serde(default)]
    pub attack: Vec<String>,
    /// The triggering event (always present).
    pub event: Event,
    #[serde(default = "Utc::now")]
    pub observed_at: DateTime<Utc>,
    #[serde(default)]
    pub signals: Vec<FindingSignal>,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub band: SeverityBand,
    /// The final level = max(band, base_level) — criticality never lowers a
    /// detector below its own declared floor.
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub env_basis: EnvBasis,
    #[serde(default)]
    pub subject: Option<AccessProjection>,
}

impl SecurityFinding {
    /// Lower to a `Detection` so the finding flows through the existing case →
    /// triage pipeline. Injects the score/detector/asset-role into the event
    /// fields (so triage + the audit ledger see the reasoning) and carries the
    /// floored `level`. Inherits the standard `dedup_key`.
    pub fn into_detection(self) -> Detection {
        let mut event = self.event;
        event
            .fields
            .insert("finding_score".to_string(), format!("{:.2}", self.score));
        event
            .fields
            .insert("finding_detector".to_string(), self.detector.clone());
        // Preserve the PRE-boost base level as provenance. The lowered
        // `Detection.level` is the criticality-boosted, floored output, so the
        // raw base would otherwise be unrecoverable — and the Phase-8 learning
        // plane needs it to reconstruct the finding without double-counting
        // criticality on replay.
        event
            .fields
            .insert("finding_base_level".to_string(), self.base_level.clone());
        if let Some(role) = &self.env_basis.asset_role {
            event.fields.insert("asset_role".to_string(), role.clone());
        }
        // Per-signal breakdown so a FUSED finding (and any multi-signal finding)
        // stays explainable in the case/triage/ledger: which detectors co-fired,
        // at what level. App-audit findings lower to a Detection and are NOT
        // persisted via `put_finding`, so this is the only place the signal list
        // survives.
        if !self.signals.is_empty() {
            let signals = self
                .signals
                .iter()
                .map(|s| format!("{}:{}", s.rule_id, s.level))
                .collect::<Vec<_>>()
                .join(",");
            event.fields.insert("finding_signals".to_string(), signals);
            event.fields.insert(
                "finding_signal_count".to_string(),
                self.signals.len().to_string(),
            );
        }
        Detection {
            rule_id: self.detector,
            rule_title: self.title,
            level: self.level,
            attack: self.attack,
            event,
            observed_at: self.observed_at,
            realert_secs: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_floor_and_ordering() {
        assert!(SeverityBand::High > SeverityBand::Medium);
        assert_eq!(SeverityBand::from_level("critical"), SeverityBand::Critical);
        assert_eq!(SeverityBand::from_level("nonsense"), SeverityBand::Low);
        // max(band, floor) never drops below the declared floor.
        let floored = SeverityBand::Low.max(SeverityBand::from_level("high"));
        assert_eq!(floored, SeverityBand::High);
    }

    fn ev(host: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: host.into(),
            service: "s".into(),
            source: "src".into(),
            environment: "prod".into(),
            severity: "warning".into(),
            log_type: "system".into(),
            message: "m".into(),
            fields: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn lowering_injects_provenance_and_keeps_dedup() {
        let f = SecurityFinding {
            finding_id: "f1".into(),
            detector: "env-new-edge".into(),
            title: "new edge".into(),
            base_level: "medium".into(),
            attack: vec![],
            event: ev("web01"),
            observed_at: Utc::now(),
            signals: vec![],
            score: 12.5,
            band: SeverityBand::High,
            level: "high".into(),
            env_basis: EnvBasis {
                asset_role: Some("vault".into()),
                ..Default::default()
            },
            subject: None,
        };
        let d = f.clone().into_detection();
        assert_eq!(d.rule_id, "env-new-edge");
        assert_eq!(d.level, "high");
        assert_eq!(d.event.field("finding_detector"), Some("env-new-edge"));
        assert_eq!(d.event.field("asset_role"), Some("vault"));
        assert_eq!(d.event.field("finding_score"), Some("12.50"));
        // The lowered detection dedups by rule_id|host|principal as usual.
        assert!(d.dedup_key().contains("env-new-edge"));
        assert!(d.dedup_key().contains("web01"));
    }

    #[test]
    fn level_weight_matches_the_rba_scale() {
        assert_eq!(level_weight("critical"), 13.0);
        assert_eq!(level_weight("medium"), 4.0);
        assert_eq!(level_weight("unknown"), 2.0);
    }
}
