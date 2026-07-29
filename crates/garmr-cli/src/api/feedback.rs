// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The analyst-feedback surface (Phase 3): append-only decisions, incident
//! outcomes, false-negatives, feedback, and mistakes, plus the per-case history.
//!
//! Every write is **gated → audited (fail-closed) → appended**, in that order,
//! so a protected change is never acknowledged without a durable audit record
//! (the same house style as the admin surface). Analyst-tier writes use
//! [`check_analyst`]; sealing an authoritative [`IncidentOutcome`] (which
//! overrides RBA at full weight) requires [`check_admin`]. Corrections append a
//! new record with `supersedes` set — the prior revision is never overwritten.

use garmr_core::{
    AnalystDecision, Disposition, EvidenceRef, FalseNegativeRecord, FeedbackLabel, FeedbackRecord,
    IncidentOutcome, MistakeCategory, MistakeRecord, OutcomeSource, ResolutionKind,
};

use super::auth::{check_admin, check_analyst};
use super::*;

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ---- POST /api/cases/:id/decision ----

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecisionReq {
    disposition: Disposition,
    #[serde(default)]
    severity: u8,
    #[serde(default)]
    reason_codes: Vec<String>,
    #[serde(default)]
    narrative: String,
    #[serde(default)]
    accepted_evidence: Vec<EvidenceRef>,
    #[serde(default)]
    rejected_evidence: Vec<EvidenceRef>,
    #[serde(default)]
    prediction_correct: Option<bool>,
    #[serde(default)]
    important_evidence_missed: Option<bool>,
    #[serde(default)]
    proposed_action_justified: Option<bool>,
    /// The decision id this one corrects (the prior revision is preserved).
    #[serde(default)]
    supersedes: Option<String>,
}

pub(super) async fn submit_decision(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(case_id): Path<String>,
    Json(req): Json<DecisionReq>,
) -> ApiResult {
    let who = check_analyst(&st, &headers)?;
    let decision_id = new_id();
    let audit_id = st.record_decision(
        &who,
        garmr_audit::action::DECISION,
        "decision",
        Some(&decision_id),
        Some(&format!("case={case_id} disposition={:?}", req.disposition)),
    )?;
    let d = AnalystDecision {
        decision_id,
        case_id,
        principal: who.user,
        disposition: req.disposition,
        severity: req.severity.min(10),
        reason_codes: req.reason_codes,
        narrative: req.narrative,
        accepted_evidence: req.accepted_evidence,
        rejected_evidence: req.rejected_evidence,
        prediction_correct: req.prediction_correct,
        important_evidence_missed: req.important_evidence_missed,
        proposed_action_justified: req.proposed_action_justified,
        supersedes: req.supersedes,
        created_at: chrono::Utc::now(),
        audit_id,
    };
    st.store.state.append_decision(&d).map_err(oops)?;
    Ok(Json(json!({ "decision": d })))
}

// ---- POST /api/incidents (admin) ----

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IncidentReq {
    /// May be null: an incident found out-of-band that never generated a case.
    #[serde(default)]
    case_id: Option<String>,
    #[serde(default)]
    resolution: ResolutionKind,
    #[serde(default)]
    source: OutcomeSource,
    disposition: Disposition,
    #[serde(default)]
    severity: u8,
    #[serde(default)]
    narrative: String,
    #[serde(default)]
    supersedes: Option<String>,
}

pub(super) async fn submit_incident(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<IncidentReq>,
) -> ApiResult {
    // The authoritative trust source: Admin-gated even though it lives on the
    // writer surface (so it exists regardless of GARMR_ADMIN_TOKEN).
    let who = check_admin(&st, &headers)?;
    let outcome_id = new_id();
    let audit_id = st.record_admin(
        &who,
        garmr_audit::action::OUTCOME,
        "incident_outcome",
        Some(&outcome_id),
        Some(&format!(
            "disposition={:?} resolution={:?}",
            req.disposition, req.resolution
        )),
    )?;
    let o = IncidentOutcome {
        outcome_id,
        case_id: req.case_id,
        resolution: req.resolution,
        source: req.source,
        disposition: req.disposition,
        severity: req.severity.min(10),
        narrative: req.narrative,
        supersedes: req.supersedes,
        created_at: chrono::Utc::now(),
        audit_id,
    };
    st.store.state.append_incident_outcome(&o).map_err(oops)?;
    Ok(Json(json!({ "incident_outcome": o })))
}

// ---- POST /api/false-negatives ----

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FalseNegativeReq {
    /// Null for an incident that never generated a case.
    #[serde(default)]
    case_id: Option<String>,
    #[serde(default)]
    discovered_via: String,
    disposition: Disposition,
    #[serde(default)]
    severity: u8,
    #[serde(default)]
    narrative: String,
    #[serde(default)]
    evidence: Vec<EvidenceRef>,
}

pub(super) async fn register_false_negative(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<FalseNegativeReq>,
) -> ApiResult {
    let who = check_analyst(&st, &headers)?;
    let fn_id = new_id();
    let audit_id = st.record_decision(
        &who,
        garmr_audit::action::FALSE_NEGATIVE,
        "false_negative",
        Some(&fn_id),
        Some(&format!("disposition={:?}", req.disposition)),
    )?;
    let f = FalseNegativeRecord {
        fn_id,
        case_id: req.case_id,
        principal: who.user,
        discovered_via: req.discovered_via,
        disposition: req.disposition,
        severity: req.severity.min(10),
        narrative: req.narrative,
        evidence: req.evidence,
        created_at: chrono::Utc::now(),
        audit_id,
    };
    st.store.state.append_false_negative(&f).map_err(oops)?;
    Ok(Json(json!({ "false_negative": f })))
}

// ---- POST /api/feedback ----

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FeedbackReq {
    #[serde(default)]
    case_id: Option<String>,
    #[serde(default)]
    prediction_id: Option<String>,
    #[serde(default)]
    label: FeedbackLabel,
    #[serde(default)]
    note: String,
}

pub(super) async fn submit_feedback(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<FeedbackReq>,
) -> ApiResult {
    let who = check_analyst(&st, &headers)?;
    let feedback_id = new_id();
    let audit_id = st.record_decision(
        &who,
        garmr_audit::action::FEEDBACK,
        "feedback",
        Some(&feedback_id),
        Some(&format!("label={:?}", req.label)),
    )?;
    let f = FeedbackRecord {
        feedback_id,
        case_id: req.case_id,
        prediction_id: req.prediction_id,
        principal: who.user,
        label: req.label,
        note: req.note,
        created_at: chrono::Utc::now(),
        audit_id,
    };
    st.store.state.append_feedback(&f).map_err(oops)?;
    Ok(Json(json!({ "feedback": f })))
}

// ---- POST /api/mistakes ----

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MistakeReq {
    #[serde(default)]
    case_id: Option<String>,
    #[serde(default)]
    category: MistakeCategory,
    #[serde(default)]
    narrative: String,
}

pub(super) async fn record_mistake(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MistakeReq>,
) -> ApiResult {
    let who = check_analyst(&st, &headers)?;
    let mistake_id = new_id();
    let audit_id = st.record_decision(
        &who,
        garmr_audit::action::MISTAKE,
        "mistake",
        Some(&mistake_id),
        Some(&format!("category={:?}", req.category)),
    )?;
    let m = MistakeRecord {
        mistake_id,
        case_id: req.case_id,
        principal: who.user,
        category: req.category,
        narrative: req.narrative,
        created_at: chrono::Utc::now(),
        audit_id,
    };
    st.store.state.append_mistake(&m).map_err(oops)?;
    Ok(Json(json!({ "mistake": m })))
}

// ---- GET /api/cases/:id/history (read surface) ----

pub(super) async fn case_history(
    State(st): State<ApiState>,
    Path(case_id): Path<String>,
) -> ApiResult {
    let view = st.store.state.case_view(&case_id).map_err(oops)?;
    let current = garmr_core::current_decision(&view.decisions);
    let outcome = garmr_core::current_outcome(&view.outcomes);
    let prediction = garmr_core::current_prediction(&view.predictions);
    Ok(Json(json!({
        "case_id": view.case_id,
        "predictions": view.predictions,
        "decisions": view.decisions,
        "incident_outcomes": view.outcomes,
        "false_negatives": view.false_negatives,
        "current": {
            "prediction": prediction,
            "decision": current,
            "outcome": outcome,
        },
    })))
}

// ---- GET /api/false-negatives (read surface) ----

pub(super) async fn false_negatives(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let page = Page::from_query(&p);
    // Push the page window into the store read instead of loading the whole
    // table and slicing (issue #19: unbounded feedback-history reads). We fetch
    // `offset + limit` rows — the pager's own window, already clamped to
    // `MAX_PAGE_LIMIT` — plus ONE sentinel row so `envelope` still computes
    // `has_more` exactly (the sentinel is sliced off, never returned). `total`
    // is consequently a lower bound rather than the whole-table count: the exact
    // count can't be had without the unbounded scan this fix removes, and the
    // page contents + `has_more` — the pagination contract — stay exact.
    let budget = page
        .offset
        .saturating_add(page.limit)
        .min(MAX_PAGE_LIMIT)
        .saturating_add(1);
    let list = st
        .store
        .state
        .list_false_negatives_limited(budget)
        .map_err(oops)?;
    Ok(Json(page.envelope("false_negatives", list)))
}