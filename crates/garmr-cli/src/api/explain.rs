// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 14 — `GET /api/cases/:id/explain`: the explainability read. It joins the
//! case's Phase-3 records (predictions/decisions/outcomes) with the Phase-4
//! registry to answer WHY the case has its disposition — the effective judgement +
//! trust source, the reasoning provenance frozen on the current prediction, and
//! the registry DRIFT (the prompt/toolset that produced the verdict vs. what is
//! live now). Pure read joins over `garmr_core::explain::assemble`; no mutation —
//! a human corrects through the existing audited decision/outcome/rollback routes.
//! Mounted on the read surface, exactly like `case_history`.

use axum::extract::{Path, State};
use axum::Json;

use super::{oops, ApiResult, ApiState};

pub(super) async fn case_explain(
    State(st): State<ApiState>,
    Path(case_id): Path<String>,
) -> ApiResult {
    let view = st.store.state.case_view(&case_id).map_err(oops)?;
    let case = st.store.state.get_case(&case_id).map_err(oops)?;
    let records = st.store.state.list_registry().map_err(oops)?;
    let promotions = st.store.state.list_promotions().map_err(oops)?;
    // The shadow-verdict fallback + self-generated flag, derived from the case
    // exactly as the RBA does (garmr-analytics/src/risk.rs).
    let (shadow, shadow_sev, is_self) = match &case {
        Some(c) => (
            c.verdict.as_ref().map(|v| v.disposition),
            c.verdict.as_ref().map(|v| v.severity),
            c.trigger.rule_id.starts_with("garmr-risk-"),
        ),
        None => (None, None, false),
    };
    let explanation =
        garmr_core::explain::assemble(&view, shadow, shadow_sev, is_self, &records, &promotions);
    Ok(Json(serde_json::to_value(explanation).map_err(oops)?))
}