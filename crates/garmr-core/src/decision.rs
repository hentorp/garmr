// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 3 — prediction / decision / outcome records, and the trust resolver.
//!
//! The prototype used a single [`Verdict`](crate::Verdict) as BOTH the model's
//! output and the human's ground truth. That conflation is removed here: the
//! agent produces an [`AgentPrediction`], a human produces an [`AnalystDecision`],
//! and an incident review produces an [`IncidentOutcome`] — three distinct,
//! **immutable, append-only** record streams. A correction never overwrites an
//! earlier record; it appends a new one whose `supersedes` points at the id it
//! replaces, so the full history is always preserved.
//!
//! Downstream scoring (RBA) and the live-action gate consume these through
//! [`resolve_trusted`], which applies a strict precedence — trusted human/incident
//! outcome first, then a *discounted* agent prediction, then unresolved — with a
//! fallback to the case's shadow [`Verdict`](crate::Verdict) so a store that has
//! no Phase-3 records yet behaves exactly as before.
//!
//! This module is pure (no I/O): the store persists the records, the agent and
//! API build them, and these folds derive the current view from history.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Disposition;

// ---- value types -----------------------------------------------------------

/// Identity + content digest of the model that produced a prediction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelIdentity {
    #[serde(default)]
    pub name: String,
    /// Lowercase-hex digest of the model artifact/config (empty if unknown).
    #[serde(default)]
    pub artifact_digest: String,
}

/// The runtime that served the model (provider/endpoint identity).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIdentity {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
}

/// A versioned, content-addressed prompt reference.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptRef {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    /// Lowercase-hex digest of the prompt text.
    #[serde(default)]
    pub digest: String,
}

/// What kind of thing an evidence reference points at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    #[default]
    Event,
    Case,
    Transcript,
    Entity,
    External,
}

/// An immutable reference into the data plane (an event id, case id, …).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    #[serde(default)]
    pub kind: EvidenceKind,
    #[serde(default)]
    pub id: String,
}

/// A remediation the agent proposed (never executed by the agent itself).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedAction {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub arg: String,
}

/// Token accounting for one prediction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    #[serde(default)]
    pub prompt: u32,
    #[serde(default)]
    pub completion: u32,
    #[serde(default)]
    pub total: u32,
}

/// Whether the model's structured output validated.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaValidation {
    /// Output validated against the tool schema.
    #[default]
    Valid,
    /// One or more fields were missing and defaulted.
    Defaulted { fields: Vec<String> },
    /// Output could not be validated; recorded rather than swallowed.
    Invalid { error: String },
}

// ---- record types (immutable, append-only) ---------------------------------

/// The agent's conclusion for a case — a model PREDICTION, never ground truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPrediction {
    #[serde(default)]
    pub prediction_id: String,
    #[serde(default)]
    pub case_id: String,
    #[serde(default)]
    pub model: ModelIdentity,
    #[serde(default)]
    pub runtime: RuntimeIdentity,
    #[serde(default)]
    pub prompt: PromptRef,
    #[serde(default)]
    pub toolset_digest: String,
    #[serde(default)]
    pub detector_versions: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    #[serde(default)]
    pub disposition: Disposition,
    #[serde(default)]
    pub severity: u8,
    #[serde(default)]
    pub model_confidence: f32,
    #[serde(default)]
    pub calibrated_confidence: Option<f32>,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub proposed_actions: Vec<ProposedAction>,
    #[serde(default)]
    pub tokens: TokenUsage,
    #[serde(default)]
    pub latency_ms: u64,
    #[serde(default)]
    pub cost_micro_usd: u64,
    #[serde(default)]
    pub stop_reason: String,
    #[serde(default)]
    pub schema: SchemaValidation,
    /// The exact approved procedural-memory version the agent read (Phase 9),
    /// or empty when no lessons were active — provenance for reproducibility.
    #[serde(default)]
    pub lesson_set_version: String,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub audit_id: Option<String>,
}

/// A human analyst's decision — the ground-truth counterpart to a prediction.
/// A correction appends a new record with `supersedes` set; the prior one stays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystDecision {
    #[serde(default)]
    pub decision_id: String,
    #[serde(default)]
    pub case_id: String,
    #[serde(default)]
    pub principal: String,
    #[serde(default)]
    pub disposition: Disposition,
    #[serde(default)]
    pub severity: u8,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub narrative: String,
    #[serde(default)]
    pub accepted_evidence: Vec<EvidenceRef>,
    #[serde(default)]
    pub rejected_evidence: Vec<EvidenceRef>,
    /// Was the agent's prediction correct (analyst's assessment)?
    #[serde(default)]
    pub prediction_correct: Option<bool>,
    /// Did the agent miss important evidence?
    #[serde(default)]
    pub important_evidence_missed: Option<bool>,
    /// Was a proposed action justified?
    #[serde(default)]
    pub proposed_action_justified: Option<bool>,
    /// The decision id this one corrects, if any.
    #[serde(default)]
    pub supersedes: Option<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub audit_id: Option<String>,
}

/// How an incident resolved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionKind {
    #[default]
    Confirmed,
    FalsePositive,
    Contained,
    Benign,
    Duplicate,
}

/// Where an incident outcome came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeSource {
    #[default]
    HumanReview,
    ExternalIr,
    Automated,
}

/// The authoritative post-incident outcome. May reference no case (an incident
/// found out-of-band that never generated one).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentOutcome {
    #[serde(default)]
    pub outcome_id: String,
    #[serde(default)]
    pub case_id: Option<String>,
    #[serde(default)]
    pub resolution: ResolutionKind,
    #[serde(default)]
    pub source: OutcomeSource,
    #[serde(default)]
    pub disposition: Disposition,
    #[serde(default)]
    pub severity: u8,
    #[serde(default)]
    pub narrative: String,
    #[serde(default)]
    pub supersedes: Option<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub audit_id: Option<String>,
}

/// A lightweight thumbs-up/down or correction note on a prediction/case.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackLabel {
    #[default]
    Unspecified,
    Helpful,
    Unhelpful,
    Correction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRecord {
    #[serde(default)]
    pub feedback_id: String,
    #[serde(default)]
    pub case_id: Option<String>,
    #[serde(default)]
    pub prediction_id: Option<String>,
    #[serde(default)]
    pub principal: String,
    #[serde(default)]
    pub label: FeedbackLabel,
    #[serde(default)]
    pub note: String,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub audit_id: Option<String>,
}

/// A missed detection registered from a post-incident review — including an
/// incident that never generated a case (`case_id = None`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalseNegativeRecord {
    #[serde(default)]
    pub fn_id: String,
    #[serde(default)]
    pub case_id: Option<String>,
    #[serde(default)]
    pub principal: String,
    /// How the miss was discovered (external IR, threat hunt, …).
    #[serde(default)]
    pub discovered_via: String,
    #[serde(default)]
    pub disposition: Disposition,
    #[serde(default)]
    pub severity: u8,
    #[serde(default)]
    pub narrative: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub audit_id: Option<String>,
}

/// Category of an agent mistake (for the Phase 9 reflection job).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MistakeCategory {
    #[default]
    Unspecified,
    MissedEvidence,
    MisinterpretedEvidence,
    UnnecessaryTools,
    MissingTools,
    WrongAssumption,
    /// Forward-compat catch-all so a future writer's category never drops the
    /// whole `MistakeRecord` on decode (the `#[serde(other)]` idiom).
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MistakeRecord {
    #[serde(default)]
    pub mistake_id: String,
    #[serde(default)]
    pub case_id: Option<String>,
    #[serde(default)]
    pub principal: String,
    #[serde(default)]
    pub category: MistakeCategory,
    #[serde(default)]
    pub narrative: String,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub audit_id: Option<String>,
}

// ---- trust resolver --------------------------------------------------------

/// Where a resolved judgement's authority came from (most→least trusted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustSource {
    /// A final incident outcome (fully trusted).
    Outcome,
    /// A human analyst decision (fully trusted).
    AnalystDecision,
    /// The agent's prediction (or the shadow verdict) — discounted.
    DiscountedPrediction,
    /// No record and no shadow; a live/in-flight case (partial credit).
    #[default]
    Unresolved,
    /// Unresolved AND self-generated (a `garmr-risk-*` synthetic case): the
    /// system's own unresolved output must carry no positive learning weight.
    UnresolvedSelfGenerated,
}

/// The resolved judgement for a case, and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedJudgement {
    /// The effective disposition, or `None` when unresolved.
    pub disposition: Option<Disposition>,
    /// The effective severity, or `None` when unresolved.
    pub severity: Option<u8>,
    pub source: TrustSource,
}

/// The append-only decision history for one case (all revisions preserved).
#[derive(Debug, Clone, Default)]
pub struct CaseDecisionView {
    pub case_id: String,
    pub predictions: Vec<AgentPrediction>,
    pub decisions: Vec<AnalystDecision>,
    pub outcomes: Vec<IncidentOutcome>,
    pub false_negatives: Vec<FalseNegativeRecord>,
}

/// The current prediction = the newest by `created_at` (deterministic tie-break
/// on `prediction_id`).
pub fn current_prediction(predictions: &[AgentPrediction]) -> Option<&AgentPrediction> {
    predictions.iter().max_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.prediction_id.cmp(&b.prediction_id))
    })
}

/// The current decision = the newest decision that no other decision supersedes.
/// Every older revision remains in `decisions` (append-only).
pub fn current_decision(decisions: &[AnalystDecision]) -> Option<&AnalystDecision> {
    decisions
        .iter()
        .filter(|d| {
            !decisions
                .iter()
                .any(|o| o.supersedes.as_deref() == Some(d.decision_id.as_str()))
        })
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.decision_id.cmp(&b.decision_id))
        })
}

/// The current incident outcome (same supersede-fold as decisions).
pub fn current_outcome(outcomes: &[IncidentOutcome]) -> Option<&IncidentOutcome> {
    outcomes
        .iter()
        .filter(|d| {
            !outcomes
                .iter()
                .any(|o| o.supersedes.as_deref() == Some(d.outcome_id.as_str()))
        })
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.outcome_id.cmp(&b.outcome_id))
        })
}

/// Resolve the effective judgement for a case with strict precedence:
///
/// 1. current incident **outcome** → trusted, full weight;
/// 2. else current analyst **decision** → trusted, full weight;
/// 3. else current agent **prediction** → discounted;
/// 4. else the case's **shadow** verdict (`shadow`/`shadow_sev`) → discounted
///    (so a store with no Phase-3 records behaves exactly as before);
/// 5. else if the case is self-generated (`garmr-risk-*`) → unresolved with
///    **zero** learning weight;
/// 6. else → unresolved (operational partial credit for an in-flight case).
pub fn resolve_trusted(
    view: &CaseDecisionView,
    shadow: Option<Disposition>,
    shadow_sev: Option<u8>,
    is_self_generated: bool,
) -> TrustedJudgement {
    if let Some(o) = current_outcome(&view.outcomes) {
        return TrustedJudgement {
            disposition: Some(o.disposition),
            severity: Some(o.severity),
            source: TrustSource::Outcome,
        };
    }
    if let Some(d) = current_decision(&view.decisions) {
        return TrustedJudgement {
            disposition: Some(d.disposition),
            severity: Some(d.severity),
            source: TrustSource::AnalystDecision,
        };
    }
    if let Some(p) = current_prediction(&view.predictions) {
        return TrustedJudgement {
            disposition: Some(p.disposition),
            severity: Some(p.severity),
            source: TrustSource::DiscountedPrediction,
        };
    }
    if let Some(disp) = shadow {
        return TrustedJudgement {
            disposition: Some(disp),
            severity: shadow_sev,
            source: TrustSource::DiscountedPrediction,
        };
    }
    TrustedJudgement {
        disposition: None,
        severity: None,
        source: if is_self_generated {
            TrustSource::UnresolvedSelfGenerated
        } else {
            TrustSource::Unresolved
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pred(id: &str, disp: Disposition, at: i64) -> AgentPrediction {
        AgentPrediction {
            prediction_id: id.into(),
            case_id: "c1".into(),
            disposition: disp,
            severity: 5,
            created_at: DateTime::from_timestamp(at, 0).unwrap(),
            ..blank_pred()
        }
    }

    fn blank_pred() -> AgentPrediction {
        // A minimal prediction via a round-trip through `{}` proves every field
        // is `#[serde(default)]`-tolerant (forward-compat).
        serde_json::from_str("{}").unwrap()
    }

    fn decision(id: &str, disp: Disposition, at: i64, supersedes: Option<&str>) -> AnalystDecision {
        let mut d: AnalystDecision = serde_json::from_str("{}").unwrap();
        d.decision_id = id.into();
        d.case_id = "c1".into();
        d.disposition = disp;
        d.severity = 7;
        d.created_at = DateTime::from_timestamp(at, 0).unwrap();
        d.supersedes = supersedes.map(str::to_string);
        d
    }

    #[test]
    fn records_decode_from_empty_object() {
        // Tolerant decode: adding fields later never breaks old rows.
        let _p: AgentPrediction = serde_json::from_str("{}").unwrap();
        let _d: AnalystDecision = serde_json::from_str("{}").unwrap();
        let _o: IncidentOutcome = serde_json::from_str("{}").unwrap();
        let fnr: FalseNegativeRecord = serde_json::from_str("{}").unwrap();
        assert!(fnr.case_id.is_none()); // caseless-capable
    }

    #[test]
    fn round_trips_preserve_fields() {
        let p = pred("p1", Disposition::Malicious, 100);
        let s = serde_json::to_string(&p).unwrap();
        let back: AgentPrediction = serde_json::from_str(&s).unwrap();
        assert_eq!(back.disposition, Disposition::Malicious);
        assert_eq!(back.prediction_id, "p1");
    }

    #[test]
    fn current_decision_honors_supersede_chain() {
        // a -> b -> c: c is current, but all three remain in the history.
        let ds = vec![
            decision("a", Disposition::Malicious, 1, None),
            decision("b", Disposition::Suspicious, 2, Some("a")),
            decision("c", Disposition::Benign, 3, Some("b")),
        ];
        let cur = current_decision(&ds).unwrap();
        assert_eq!(cur.decision_id, "c");
        assert_eq!(cur.disposition, Disposition::Benign);
        assert_eq!(ds.len(), 3, "history preserved");
    }

    #[test]
    fn resolve_precedence_outcome_beats_decision_beats_prediction() {
        let mut view = CaseDecisionView {
            case_id: "c1".into(),
            predictions: vec![pred("p", Disposition::Suspicious, 1)],
            decisions: vec![decision("d", Disposition::Malicious, 2, None)],
            outcomes: vec![],
            false_negatives: vec![],
        };
        // decision wins over prediction
        let j = resolve_trusted(&view, None, None, false);
        assert_eq!(j.source, TrustSource::AnalystDecision);
        assert_eq!(j.disposition, Some(Disposition::Malicious));
        // outcome wins over decision
        view.outcomes.push(IncidentOutcome {
            outcome_id: "o".into(),
            disposition: Disposition::Benign,
            severity: 0,
            ..serde_json::from_str("{}").unwrap()
        });
        let j = resolve_trusted(&view, None, None, false);
        assert_eq!(j.source, TrustSource::Outcome);
        assert_eq!(j.disposition, Some(Disposition::Benign));
    }

    #[test]
    fn resolve_shadow_fallback_and_unresolved() {
        let empty = CaseDecisionView {
            case_id: "c1".into(),
            ..Default::default()
        };
        // No records + shadow malicious → discounted prediction (legacy case).
        let j = resolve_trusted(&empty, Some(Disposition::Malicious), Some(9), false);
        assert_eq!(j.source, TrustSource::DiscountedPrediction);
        assert_eq!(j.disposition, Some(Disposition::Malicious));
        assert_eq!(j.severity, Some(9));
        // No records, no shadow, not self → in-flight partial credit.
        let j = resolve_trusted(&empty, None, None, false);
        assert_eq!(j.source, TrustSource::Unresolved);
        assert!(j.disposition.is_none());
        // No records, no shadow, self-generated → zero-weight source.
        let j = resolve_trusted(&empty, None, None, true);
        assert_eq!(j.source, TrustSource::UnresolvedSelfGenerated);
    }
}