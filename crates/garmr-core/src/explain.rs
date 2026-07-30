// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 14 — the pure EXPLAINABILITY fold. Given a case's Phase-3 record view
//! (predictions/decisions/outcomes) plus the Phase-4 registry (records +
//! promotions), it assembles WHY the case has the disposition it does: the
//! effective judgement + its trust source, the reasoning provenance frozen on the
//! current prediction (model / prompt / toolset / lesson + rationale + audit ids),
//! and — the actionable part — REGISTRY DRIFT: the prompt/toolset that produced
//! the verdict versus what is live now.
//!
//! Pure: no I/O, no store, no mutation. The garmr-cli edge reads the records +
//! registry and renders this; the human corrects through the EXISTING audited
//! write paths (a decision/outcome/registry-rollback), never a new mutation here.
//!
//! Provenance honesty: drift is STRONG for prompt + toolset — their recorded
//! digest lives in the same content-addressed space as the registry
//! `content_digest`, so a mismatch is a real drift. Model (`artifact_digest` is
//! often empty for a hosted model) and lesson (a semver version, not a digest)
//! degrade to "provenance only" — the coordinate is shown, drift is `Unknown`.

use serde::Serialize;

use crate::case::Disposition;
use crate::decision::{
    current_decision, current_outcome, current_prediction, resolve_trusted, AgentPrediction,
    CaseDecisionView,
};
use crate::registry::{active, PromotionEvent, RegistryKind, RegistryRecord};

/// Whether a recorded coordinate still matches what is live in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftState {
    /// Recorded digest == the active production record's digest.
    Active,
    /// Recorded digest != the active record's digest — the live artifact changed.
    Drift,
    /// Not digest-comparable (empty digest / semver / no active record).
    Unknown,
}

/// One provenance coordinate of the verdict: which registry artifact produced it,
/// and whether that artifact is still the live one.
#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceRow {
    /// The registry kind tag (`prompt`, `toolset`, `model`, `lesson`).
    pub kind: String,
    pub name: String,
    /// The version/digest recorded on the prediction (what actually ran).
    pub recorded: String,
    /// The active production digest now, if resolvable.
    pub active: Option<String>,
    pub drift: DriftState,
}

/// The assembled explanation for one case.
#[derive(Debug, Clone, Serialize)]
pub struct Explanation {
    pub case_id: String,
    /// The effective disposition (via the trust precedence) as a lowercase tag.
    pub disposition: String,
    pub severity: Option<u8>,
    /// Where the authority came from: `outcome` | `analyst_decision` |
    /// `discounted_prediction` | `unresolved`.
    pub trust_source: String,
    /// The current prediction's free-text rationale (empty if none).
    pub rationale: String,
    pub provenance: Vec<ProvenanceRow>,
    /// Every audit id referenced by the current prediction/decision/outcome — each
    /// a token verifiable against the tamper-evident ledger.
    pub audit_ids: Vec<String>,
    /// Append-only revision counts (a growing count = an active correction trail).
    pub prediction_count: usize,
    pub decision_count: usize,
    pub outcome_count: usize,
    /// True when a human judgement (decision/outcome) outranks the agent's
    /// prediction — the correction loop has been exercised.
    pub human_corrected: bool,
}

/// Render an enum through serde so it emits the CANONICAL snake_case tag
/// (`needs_human`, `analyst_decision`, …) the rest of the codebase uses — NOT
/// `format!("{:?}").to_lowercase()`, which drops the CamelCase word boundary and
/// produced `needshuman`/`analystdecision` (review LOW).
fn serde_tag<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Resolve one coordinate to a provenance row. `recorded_digest` is what ran;
/// `name` names the registry artifact. Drift is only asserted when both the
/// recorded and the active digests are non-empty and comparable.
fn coordinate(
    kind: RegistryKind,
    name: &str,
    recorded_digest: &str,
    records: &[RegistryRecord],
    promotions: &[PromotionEvent],
) -> ProvenanceRow {
    let active_digest =
        active(kind, name, "production", records, promotions).map(|r| r.content_digest.clone());
    let drift = match (&active_digest, recorded_digest) {
        (Some(a), rec) if !a.is_empty() && !rec.is_empty() => {
            if a == rec {
                DriftState::Active
            } else {
                DriftState::Drift
            }
        }
        _ => DriftState::Unknown,
    };
    ProvenanceRow {
        kind: kind.tag().to_string(),
        name: name.to_string(),
        recorded: recorded_digest.to_string(),
        active: active_digest,
        drift,
    }
}

/// The name of the registry record whose `content_digest` equals `digest` (so a
/// prediction that carries only a toolset digest can be joined to its named
/// artifact). `None` if no record matches.
fn name_for_digest(kind: RegistryKind, digest: &str, records: &[RegistryRecord]) -> Option<String> {
    if digest.is_empty() {
        return None;
    }
    records
        .iter()
        .find(|r| r.kind == kind && r.content_digest == digest)
        .map(|r| r.name.clone())
}

fn provenance_rows(
    p: &AgentPrediction,
    records: &[RegistryRecord],
    promotions: &[PromotionEvent],
) -> Vec<ProvenanceRow> {
    let mut rows = Vec::new();
    // Prompt — name + digest are both on the prediction (strong drift).
    if !p.prompt.name.is_empty() || !p.prompt.digest.is_empty() {
        rows.push(coordinate(
            RegistryKind::Prompt,
            &p.prompt.name,
            &p.prompt.digest,
            records,
            promotions,
        ));
    }
    // Toolset — only a digest is recorded; join to its named record (strong drift).
    if !p.toolset_digest.is_empty() {
        let name = name_for_digest(RegistryKind::Toolset, &p.toolset_digest, records)
            .unwrap_or_else(|| "toolset".to_string());
        rows.push(coordinate(
            RegistryKind::Toolset,
            &name,
            &p.toolset_digest,
            records,
            promotions,
        ));
    }
    // Model — provenance only (artifact_digest is often empty for a hosted model).
    if !p.model.name.is_empty() {
        rows.push(coordinate(
            RegistryKind::Model,
            &p.model.name,
            &p.model.artifact_digest,
            records,
            promotions,
        ));
    }
    // Lesson — a semver version, not a content digest → Unknown drift.
    if !p.lesson_set_version.is_empty() {
        rows.push(ProvenanceRow {
            kind: RegistryKind::Lesson.tag().to_string(),
            name: "lessons".to_string(),
            recorded: p.lesson_set_version.clone(),
            active: None,
            drift: DriftState::Unknown,
        });
    }
    rows
}

/// Assemble the explanation. Pure over the case view + registry snapshot.
pub fn assemble(
    view: &CaseDecisionView,
    shadow: Option<Disposition>,
    shadow_sev: Option<u8>,
    is_self_generated: bool,
    records: &[RegistryRecord],
    promotions: &[PromotionEvent],
) -> Explanation {
    let judged = resolve_trusted(view, shadow, shadow_sev, is_self_generated);
    let cur = current_prediction(&view.predictions);

    let mut audit_ids: Vec<String> = Vec::new();
    if let Some(p) = cur {
        if let Some(a) = &p.audit_id {
            audit_ids.push(a.clone());
        }
    }
    if let Some(d) = current_decision(&view.decisions) {
        if let Some(a) = &d.audit_id {
            audit_ids.push(a.clone());
        }
    }
    if let Some(o) = current_outcome(&view.outcomes) {
        if let Some(a) = &o.audit_id {
            audit_ids.push(a.clone());
        }
    }

    let provenance = cur
        .map(|p| provenance_rows(p, records, promotions))
        .unwrap_or_default();

    // A HUMAN correction outranked the prediction — an analyst decision, or a
    // NON-automated incident outcome. An `Automated` outcome is authoritative but
    // not a human correction (review LOW).
    let human_corrected = match judged.source {
        crate::decision::TrustSource::AnalystDecision => true,
        crate::decision::TrustSource::Outcome => current_outcome(&view.outcomes)
            .is_some_and(|o| o.source != crate::decision::OutcomeSource::Automated),
        _ => false,
    };

    Explanation {
        case_id: view.case_id.clone(),
        disposition: judged
            .disposition
            .as_ref()
            .map(serde_tag)
            .unwrap_or_default(),
        severity: judged.severity,
        trust_source: serde_tag(&judged.source),
        rationale: cur.map(|p| p.rationale.clone()).unwrap_or_default(),
        provenance,
        audit_ids,
        prediction_count: view.predictions.len(),
        decision_count: view.decisions.len(),
        outcome_count: view.outcomes.len(),
        human_corrected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These records are tolerant serde types (every field `#[serde(default)]`), so
    // the fixtures are built from a partial JSON value rather than a struct literal
    // (neither derives Default).
    fn prediction(id: &str, prompt_digest: &str) -> AgentPrediction {
        serde_json::from_value(serde_json::json!({
            "prediction_id": id,
            "prompt": {"name": "system", "version": "v3", "digest": prompt_digest},
            "model": {"name": "claude", "artifact_digest": ""},
            "toolset_digest": "tsdigest",
            "lesson_set_version": "1.2.0",
            "rationale": "looks like a scan",
            "audit_id": "aud-1",
        }))
        .unwrap()
    }

    fn rec(kind: RegistryKind, name: &str, version: &str, digest: &str) -> RegistryRecord {
        serde_json::from_value(serde_json::json!({
            "kind": kind.tag(),
            "name": name,
            "version": version,
            "content_digest": digest,
        }))
        .unwrap()
    }

    fn promote(kind: RegistryKind, name: &str, target_digest: &str) -> PromotionEvent {
        // A minimal AUDITED Promote-to-Approved production binding. `active()`
        // resolves the live record by `target_digest`, and an empty audit id would
        // be inert on read.
        serde_json::from_value(serde_json::json!({
            "kind": kind.tag(),
            "name": name,
            "channel": "production",
            "op": "promote",
            "to_state": "approved",
            "target_digest": target_digest,
            "audit_id": "prom-aud",
        }))
        .unwrap()
    }

    fn view_with(pred: AgentPrediction) -> CaseDecisionView {
        CaseDecisionView {
            case_id: "c1".into(),
            predictions: vec![pred],
            decisions: vec![],
            outcomes: vec![],
            false_negatives: vec![],
        }
    }

    #[test]
    fn empty_object_decodes_and_assembles_unresolved() {
        let view = CaseDecisionView {
            case_id: "c0".into(),
            predictions: vec![],
            decisions: vec![],
            outcomes: vec![],
            false_negatives: vec![],
        };
        let e = assemble(&view, None, None, false, &[], &[]);
        assert_eq!(e.trust_source, "unresolved");
        assert!(e.provenance.is_empty());
        assert!(!e.human_corrected);
    }

    #[test]
    fn prompt_matching_active_is_not_drift_but_a_changed_active_is() {
        // Records: prompt system v3 (ran) + v4 (now live); promote v4 to production.
        let records = vec![
            rec(RegistryKind::Prompt, "system", "v3", "P3"),
            rec(RegistryKind::Prompt, "system", "v4", "P4"),
            rec(RegistryKind::Toolset, "core", "v1", "tsdigest"),
        ];
        // Case A: v3 is active → the verdict's prompt is ACTIVE.
        let promos_v3 = vec![promote(RegistryKind::Prompt, "system", "P3")];
        let e = assemble(
            &view_with(prediction("p1", "P3")),
            None,
            None,
            false,
            &records,
            &promos_v3,
        );
        let prompt = e.provenance.iter().find(|r| r.kind == "prompt").unwrap();
        assert_eq!(prompt.drift, DriftState::Active);

        // Case B: v4 is now active → the verdict (produced by v3/P3) is DRIFT.
        let promos_v4 = vec![promote(RegistryKind::Prompt, "system", "P4")];
        let e = assemble(
            &view_with(prediction("p1", "P3")),
            None,
            None,
            false,
            &records,
            &promos_v4,
        );
        let prompt = e.provenance.iter().find(|r| r.kind == "prompt").unwrap();
        assert_eq!(prompt.drift, DriftState::Drift);
        assert_eq!(prompt.active.as_deref(), Some("P4"));
    }

    #[test]
    fn tags_are_canonical_snake_case_and_outcome_source_gates_human() {
        use crate::case::Disposition;
        use crate::decision::TrustSource;
        // Canonical snake_case, NOT Debug-lowercase (needshuman/analystdecision).
        assert_eq!(serde_tag(&Disposition::NeedsHuman), "needs_human");
        assert_eq!(serde_tag(&TrustSource::AnalystDecision), "analyst_decision");
        assert_eq!(
            serde_tag(&TrustSource::DiscountedPrediction),
            "discounted_prediction"
        );

        // An analyst decision → human_corrected + the canonical tags.
        let decision: crate::decision::AnalystDecision =
            serde_json::from_value(serde_json::json!({
                "decision_id": "d1", "case_id": "c1", "disposition": "needs_human", "severity": 5,
            }))
            .unwrap();
        let view = CaseDecisionView {
            case_id: "c1".into(),
            predictions: vec![],
            decisions: vec![decision],
            outcomes: vec![],
            false_negatives: vec![],
        };
        let e = assemble(&view, None, None, false, &[], &[]);
        assert_eq!(e.trust_source, "analyst_decision");
        assert_eq!(e.disposition, "needs_human");
        assert!(e.human_corrected);

        // An AUTOMATED incident outcome is authoritative but NOT a human correction.
        let outcome: crate::decision::IncidentOutcome = serde_json::from_value(serde_json::json!({
            "outcome_id": "o1", "case_id": "c1", "disposition": "malicious", "severity": 8,
            "source": "automated",
        }))
        .unwrap();
        let view = CaseDecisionView {
            case_id: "c1".into(),
            predictions: vec![],
            decisions: vec![],
            outcomes: vec![outcome],
            false_negatives: vec![],
        };
        let e = assemble(&view, None, None, false, &[], &[]);
        assert_eq!(e.trust_source, "outcome");
        assert!(
            !e.human_corrected,
            "an automated outcome is not a human correction"
        );
    }

    #[test]
    fn toolset_joins_by_digest_and_lesson_is_provenance_only() {
        let records = vec![rec(RegistryKind::Toolset, "core", "v1", "tsdigest")];
        let e = assemble(
            &view_with(prediction("p1", "P3")),
            None,
            None,
            false,
            &records,
            &[],
        );
        let ts = e.provenance.iter().find(|r| r.kind == "toolset").unwrap();
        assert_eq!(ts.name, "core"); // joined by content digest
        let lesson = e.provenance.iter().find(|r| r.kind == "lesson").unwrap();
        assert_eq!(lesson.drift, DriftState::Unknown);
        assert_eq!(lesson.recorded, "1.2.0");
        assert_eq!(e.audit_ids, vec!["aud-1"]);
    }
}
