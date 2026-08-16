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
    /// Close the case with this decision. The analyst's disposition becomes the
    /// case's resolution — the one-step "triage, decide, done" flow a queue
    /// needs, instead of a decision that leaves the case dangling open.
    #[serde(default)]
    resolve: bool,
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
    if req.resolve {
        let actor = d.principal.clone();
        let disposition = d.disposition;
        st.store
            .state
            .mutate_case(&d.case_id, move |c| {
                c.state = garmr_core::CaseState::Closed;
                // Stamped here as well as in put_case's chokepoint: mutate_case
                // writes directly, and a Closed case's SLA clocks stop at this
                // instant.
                c.state_changed_at = Some(chrono::Utc::now());
                c.record(
                    format!("analyst:{actor}"),
                    format!("closed by analyst decision ({disposition:?})"),
                    chrono::Utc::now(),
                );
                true
            })
            .map_err(oops)?;
    }
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

// ---- Case ownership + collaboration (2.9 M2) --------------------------------

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssignReq {
    /// The principal to assign, or `null` to unassign. Validated against
    /// /api/principals' directory when possible; unknown names are accepted on
    /// open-loopback deployments (no directory exists to validate against).
    pub assignee: Option<String>,
}

/// POST /api/cases/{id}/assign — set or clear the case owner. Analyst-gated,
/// audited. Goes through the atomic mutator, never through put_case: clearing
/// an owner must be an explicit act a stale snapshot cannot replay.
pub(super) async fn assign_case(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(case_id): Path<String>,
    Json(req): Json<AssignReq>,
) -> ApiResult {
    let who = check_analyst(&st, &headers)?;
    // Validate against the known principals when a directory exists: assigning
    // to a typo would file the case with nobody, silently. Open-loopback (no
    // configured identities) accepts any name — there is nothing to check
    // against, and blocking assignment there would break the dev posture.
    if let Some(name) = req.assignee.as_deref() {
        let known = !st.auth.is_empty();
        if known
            && !st.auth.principals().iter().any(|p| p.user == name)
            && !st.webauthn.as_ref().is_some_and(|_w| {
                super::passkey::passkey_principals(&st.store)
                    .iter()
                    .any(|p| p.user == name)
            })
        {
            return Err(bad(format!(
                "unknown assignee {name:?} — see /api/principals for who can own a case"
            )));
        }
    }
    st.record_decision(
        &who,
        garmr_audit::action::CASE_ASSIGN,
        "case",
        Some(&case_id),
        Some(&format!(
            "assignee={}",
            req.assignee.as_deref().unwrap_or("(unassigned)")
        )),
    )?;
    let assignee = req.assignee.clone();
    let actor = who.user.clone();
    let updated = st
        .store
        .state
        .mutate_case(&case_id, move |c| {
            let detail = match &assignee {
                Some(a) => format!("assigned to {a} by {actor}"),
                None => format!("unassigned by {actor}"),
            };
            c.assignee = assignee.clone();
            c.record(format!("analyst:{actor}"), detail, chrono::Utc::now());
            true
        })
        .map_err(oops)?
        .ok_or_else(|| not_found("no such case"))?;
    Ok(Json(json!({ "case": updated })))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommentReq {
    pub text: String,
}

/// POST /api/cases/{id}/comment — an analyst note in the transcript, with an
/// entry_id so it survives a concurrent agent snapshot's put_case merge.
pub(super) async fn comment_case(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(case_id): Path<String>,
    Json(req): Json<CommentReq>,
) -> ApiResult {
    let who = check_analyst(&st, &headers)?;
    let text = req.text.trim().to_string();
    if text.is_empty() {
        return Err(bad("an empty comment says nothing"));
    }
    if text.len() > 8_192 {
        return Err(bad("comment too long (> 8 KiB)"));
    }
    st.record_decision(
        &who,
        garmr_audit::action::CASE_COMMENT,
        "case",
        Some(&case_id),
        // The audit record carries a digest-sized fact, not the note text —
        // the transcript holds the content, the ledger holds who and when.
        Some(&format!("comment ({} chars)", text.len())),
    )?;
    let actor = who.user.clone();
    let updated = st
        .store
        .state
        .mutate_case(&case_id, move |c| {
            c.transcript.push(garmr_core::TranscriptEntry {
                at: chrono::Utc::now(),
                actor: format!("analyst:{actor}"),
                detail: text.clone(),
                entry_id: uuid::Uuid::new_v4().to_string(),
            });
            true
        })
        .map_err(oops)?
        .ok_or_else(|| not_found("no such case"))?;
    Ok(Json(json!({ "case": updated })))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TagsReq {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/// POST /api/cases/{id}/tags — add/remove tags atomically.
pub(super) async fn tag_case(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(case_id): Path<String>,
    Json(req): Json<TagsReq>,
) -> ApiResult {
    let who = check_analyst(&st, &headers)?;
    let add: Vec<String> = req
        .add
        .iter()
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty() && t.len() <= 64)
        .collect();
    let remove: Vec<String> = req.remove.iter().map(|t| t.trim().to_lowercase()).collect();
    if add.is_empty() && remove.is_empty() {
        return Err(bad("nothing to do"));
    }
    st.record_decision(
        &who,
        garmr_audit::action::CASE_TAG,
        "case",
        Some(&case_id),
        Some(&format!("add={add:?} remove={remove:?}")),
    )?;
    let updated = st
        .store
        .state
        .mutate_case(&case_id, move |c| {
            let mut changed = false;
            for t in &add {
                if !c.tags.contains(t) {
                    c.tags.push(t.clone());
                    changed = true;
                }
            }
            let before = c.tags.len();
            c.tags.retain(|t| !remove.contains(t));
            changed || c.tags.len() != before
        })
        .map_err(oops)?
        .ok_or_else(|| not_found("no such case"))?;
    Ok(Json(json!({ "case": updated })))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LinkReq {
    pub other: String,
}

/// POST /api/cases/{id}/link — link two cases, both directions, atomically.
pub(super) async fn link_case(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Path(case_id): Path<String>,
    Json(req): Json<LinkReq>,
) -> ApiResult {
    let who = check_analyst(&st, &headers)?;
    st.record_decision(
        &who,
        garmr_audit::action::CASE_LINK,
        "case",
        Some(&case_id),
        Some(&format!("other={}", req.other)),
    )?;
    let linked = st
        .store
        .state
        .link_cases(&case_id, &req.other)
        .map_err(oops)?;
    if !linked {
        return Err(bad(
            "cases not linked — both must exist, be distinct, and not already be linked",
        ));
    }
    Ok(Json(json!({ "linked": true })))
}
