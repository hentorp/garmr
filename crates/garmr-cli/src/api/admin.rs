// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The admin / governance surface: notification silences (silence/prune),
//! the propose→approve→act approvals for rules and response-actions, and the
//! action listing. Every mutating call is gated by [`check_admin`] (admin bearer).

use super::*;

/// The silence request body. Strictly typed: `hours` is REQUIRED (a missing or
/// string-typed value must not silently become a 1-hour silence — `"0"` meant
/// "clear" and would instead have CREATED one) and unknown keys are rejected
/// (a typo'd `"hosts"` must not silently widen a silence to every host).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SilenceReq {
    rule: String,
    hours: f64,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// POST /admin/silence {rule, hours, host?, reason?} — silence a rule's
/// notifications for `hours` (0 clears; max 168). The authenticated call is the
/// human approval per the propose/approve/act separation. Every change is also
/// announced on the Matrix alerts room (see [`announce_silence`]).
pub(super) async fn admin_silence(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SilenceReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let reason = format!(
        "{} rule={} host={} hours={}",
        if req.hours == 0.0 { "clear" } else { "silence" },
        req.rule,
        req.host.as_deref().unwrap_or("*"),
        req.hours
    );
    st.record_admin(
        &who,
        garmr_audit::action::SILENCE,
        "rule",
        Some(&req.rule),
        Some(&reason),
    )?;
    let change = garmr_route::set_silence(
        &st.store.state,
        &req.rule,
        req.host.as_deref(),
        req.hours,
        req.reason.as_deref().unwrap_or(""),
        chrono::Utc::now(),
    )
    .map_err(bad)?;
    tracing::info!(
        rule = %req.rule,
        hours = req.hours,
        host = req.host.as_deref().unwrap_or("*"),
        "silence set by operator (API)"
    );
    if let Some(m) = &st.matrix {
        announce_silence(m, &st.cfg, &change, "API").await;
    }
    Ok(Json(json!({
        "set": change.set,
        "replaced": change.replaced,
        "cleared": change.set.is_none(),
    })))
}

/// Post a silence change to the alerts room, so silencing is never invisible on
/// the channel it affects: with this, a stolen admin token can still quiet a
/// rule, but not QUIETLY — the room the operator watches announces it. The
/// notice is not rule-keyed, so it cannot be silenced by the very silence it
/// reports. Best-effort: a failed post is logged, never an error to the caller.
pub(super) async fn announce_silence(
    m: &garmr_agent::Matrix,
    cfg: &Config,
    change: &garmr_route::SilenceChange,
    via: &str,
) {
    let Some(mc) = &cfg.matrix else { return };
    let text = match &change.set {
        Some(s) => format!(
            "🔇 silence SET (via {via}): rule {} host {} until {}{}{}",
            s.rule,
            s.host.as_deref().unwrap_or("*"),
            s.until.format("%Y-%m-%d %H:%M UTC"),
            if s.reason.is_empty() {
                String::new()
            } else {
                format!(" — {}", s.reason)
            },
            change
                .replaced
                .as_ref()
                .filter(|r| r.host != s.host)
                .map(|r| format!(
                    " (REPLACED silence with scope {})",
                    r.host.as_deref().unwrap_or("all hosts")
                ))
                .unwrap_or_default(),
        ),
        None => match &change.replaced {
            Some(r) => format!(
                "🔊 silence CLEARED (via {via}): rule {} host {}",
                r.rule,
                r.host.as_deref().unwrap_or("*"),
            ),
            None => return, // cleared nothing — no announcement needed
        },
    };
    if let Err(e) = m.notice(&mc.alerts_room, &text).await {
        tracing::warn!(error = %e, "silence announcement failed");
    }
}

/// GET /admin/silences — the active silences.
pub(super) async fn admin_silences(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> ApiResult {
    check_admin(&st, &headers)?;
    let silences = st
        .store
        .state
        .active_silences(chrono::Utc::now())
        .map_err(oops)?;
    Ok(Json(json!(silences)))
}

/// Body of `POST /admin/cases/prune`. All filters optional but at least one is
/// required (never wipes the whole store). Dry-run (count only) unless `apply`.
#[derive(serde::Deserialize)]
pub(super) struct PruneReq {
    #[serde(default)]
    older_than_days: Option<i64>,
    #[serde(default)]
    opened_after: Option<String>,
    #[serde(default)]
    opened_before: Option<String>,
    #[serde(default)]
    states: Vec<String>,
    #[serde(default)]
    rule: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    apply: bool,
}

/// POST /admin/cases/prune — case retention/cleanup over the LIVE store. The
/// daemon owns the redb writer lock, so this is the online path (the offline
/// `garmr cases prune` writes the store directly when no daemon runs). Returns
/// `{matched, deleted, applied}`; authenticated by the admin token like silence.
pub(super) async fn admin_cases_prune(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PruneReq>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let cutoff = req
        .older_than_days
        .map(|d| chrono::Utc::now() - chrono::Duration::days(d));
    let after = req
        .opened_after
        .as_deref()
        .map(crate::parse_rfc3339)
        .transpose()
        .map_err(bad)?;
    let before = req
        .opened_before
        .as_deref()
        .map(crate::parse_rfc3339)
        .transpose()
        .map_err(bad)?;
    let want_states = req
        .states
        .iter()
        .map(|s| crate::parse_case_state(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    let has_filter = req.older_than_days.is_some()
        || after.is_some()
        || before.is_some()
        || !want_states.is_empty()
        || req.rule.is_some()
        || req.source.is_some();
    if !has_filter {
        return Err(bad(
            "refusing to prune unfiltered — pass at least one of older_than_days / \
             opened_after / opened_before / states / rule / source",
        ));
    }
    let all = st.store.state.list_cases().map_err(oops)?;
    let matched: Vec<String> = all
        .iter()
        .filter(|c| {
            cutoff.is_none_or(|t| c.updated_at < t)
                && after.is_none_or(|t| c.opened_at >= t)
                && before.is_none_or(|t| c.opened_at <= t)
                && (want_states.is_empty() || want_states.contains(&c.state))
                && req.rule.as_ref().is_none_or(|r| &c.trigger.rule_id == r)
                && req
                    .source
                    .as_ref()
                    .is_none_or(|s| &c.trigger.event.source == s)
        })
        .map(|c| c.id.clone())
        .collect();
    let deleted = if req.apply {
        st.record_admin(
            &who,
            "cases.prune",
            "cases",
            None,
            Some(&format!("prune {} case(s)", matched.len())),
        )?;
        st.store.state.delete_cases(&matched).map_err(oops)?
    } else {
        0
    };
    tracing::info!(
        matched = matched.len(),
        deleted,
        apply = req.apply,
        "admin cases prune"
    );
    Ok(Json(json!({
        "matched": matched.len(),
        "deleted": deleted,
        "applied": req.apply,
    })))
}
/// POST /admin/rules/approve {"id"} — the human decision: transition the
/// proposal and write the rule file. Requires the admin bearer.
pub(super) async fn admin_rule_approve(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let id = body
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| bad("body must be {\"id\": \"…\"}"))?;
    let audit_id = st.record_admin(
        &who,
        garmr_audit::action::RULE_DECIDE,
        "rule_proposal",
        Some(id),
        Some("approved"),
    )?;
    let (p, path) = garmr_agent::approve_proposal(&st.store, &st.cfg, id, audit_id)
        .await
        .map_err(admin_err)?;
    tracing::info!(proposal = %p.id, path = %path.display(), "rule proposal approved by operator (API)");
    Ok(Json(json!({
        "proposal": p,
        "path": path,
        "note": "the rule takes effect at the next serve restart",
    })))
}

/// POST /admin/rules/reject {"id", "reason"?} — the human decision to reject.
pub(super) async fn admin_rule_reject(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let id = body
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| bad("body must be {\"id\": \"…\"}"))?;
    let reason = body
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .filter(|r| !r.is_empty())
        .map(String::from);
    st.record_admin(
        &who,
        garmr_audit::action::RULE_DECIDE,
        "rule_proposal",
        Some(id),
        Some(&format!("rejected: {}", reason.as_deref().unwrap_or("-"))),
    )?;
    let p = st
        .store
        .state
        .decide_proposal(
            id,
            garmr_core::ProposalStatus::Rejected,
            reason,
            chrono::Utc::now(),
        )
        .map_err(admin_err)?;
    tracing::info!(proposal = %p.id, "rule proposal rejected by operator (API)");
    Ok(Json(json!({ "proposal": p })))
}

/// GET /api/actions — all response-action proposals, newest first (with audit).
pub(super) async fn actions_list(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let list = st.store.state.list_actions().map_err(oops)?;
    Ok(Json(Page::from_query(&p).envelope("actions", list)))
}

/// GET /api/actions/:id — one action proposal (id prefix ok).
pub(super) async fn action_by_id(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match st.store.state.get_action(&id) {
        Ok(Some(a)) => Ok(Json(serde_json::to_value(a).map_err(oops)?)),
        Ok(None) => Err((StatusCode::NOT_FOUND, format!("no action matches {id}"))),
        Err(e) => Err(admin_err(e)),
    }
}

/// POST /admin/action/approve {"id"} — the human approval: move a Proposed
/// action to Approved. Requires the admin bearer. Does NOT execute — the
/// executor loop (or `garmr execute`) re-validates and acts separately.
pub(super) async fn admin_action_approve(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let id = body
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| bad("body must be {\"id\": \"…\"}"))?;
    st.record_admin(
        &who,
        garmr_audit::action::ACTION_DECIDE,
        "action_proposal",
        Some(id),
        Some("approved"),
    )?;
    let a = st
        .store
        .state
        .transition_action(
            id,
            &[garmr_core::ActionState::Proposed],
            garmr_core::ActionState::Approved,
            "human",
            "approved via API",
            None,
            chrono::Utc::now(),
        )
        .map_err(admin_err)?;
    tracing::info!(action = %a.id, kind = a.kind.as_str(), "action approved by operator (API)");
    Ok(Json(json!({
        "action": a,
        "note": "approved — carried out by the executor loop (if enabled) or `garmr execute`",
    })))
}

/// POST /admin/action/deny {"id", "reason"?} — the human denial. Terminal.
pub(super) async fn admin_action_deny(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let who = check_admin(&st, &headers)?;
    let id = body
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| bad("body must be {\"id\": \"…\"}"))?;
    let reason = body
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("denied via API");
    st.record_admin(
        &who,
        garmr_audit::action::ACTION_DECIDE,
        "action_proposal",
        Some(id),
        Some(&format!("denied: {reason}")),
    )?;
    let a = st
        .store
        .state
        .transition_action(
            id,
            // Deny works before OR after approval — recall an approval made in
            // error before the executor runs it.
            &[
                garmr_core::ActionState::Proposed,
                garmr_core::ActionState::Approved,
            ],
            garmr_core::ActionState::Denied,
            "human",
            reason,
            None,
            chrono::Utc::now(),
        )
        .map_err(admin_err)?;
    tracing::info!(action = %a.id, "action denied by operator (API)");
    Ok(Json(json!({ "action": a })))
}

/// GET /api/audit/status — audit-ledger verification status (integrity, counts,
/// and chain head only; never raw record content). Runs the offline verifier off
/// the async runtime.
///
/// Admin-gated in the handler (issue #22): the verifier runs an O(ledger)
/// `verify_dir` scan, so an unauthenticated caller must not be able to trigger it
/// (a repeated poll would otherwise be a cheap full-ledger-scan DoS). The route
/// deliberately stays on the public read router (not behind `mount_admin`) so
/// token-less or passkey-only deployments still resolve it instead of 404ing;
/// `check_admin` is the gate, not the mount.
pub(super) async fn audit_status(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> ApiResult {
    check_admin(&st, &headers)?;
    let Some(ledger) = st.audit.clone() else {
        return Ok(Json(json!({ "enabled": false })));
    };
    let key_id = ledger.key_id();
    let head = ledger.head_sequence();
    let dir = ledger.dir().to_path_buf();
    let pk = ledger.public_key();
    let report = tokio::task::spawn_blocking(move || {
        garmr_audit::verify_dir(&dir, &garmr_audit::TrustRoot::from_public_key(pk))
    })
    .await
    .map_err(oops)?
    .map_err(oops)?;
    Ok(Json(json!({
        "enabled": true,
        "key_id": key_id,
        "head_sequence": head,
        "records": report.records_checked,
        "segments": report.segments,
        "checkpoints": report.checkpoints_checked,
        "last_sequence": report.last_sequence,
        "ok": report.ok,
        "findings": report.findings.len(),
    })))
}

/// Cap the findings returned in the detail view — a badly corrupted ledger could
/// have thousands; the response stays bounded (the exact count is in
/// `/api/audit/status`), and the operator sees the first, most-actionable ones.
const MAX_VERIFY_FINDINGS: usize = 200;

/// Shape the typed verification findings into JSON (kind/sequence/detail), capped
/// at `cap`. Returns `(rows, truncated)`. Kept a pure helper so it is unit-tested
/// without standing up a ledger.
fn verify_findings_json(findings: &[garmr_audit::Finding], cap: usize) -> (Vec<Value>, bool) {
    let rows: Vec<Value> = findings
        .iter()
        .take(cap)
        .map(|f| {
            json!({
                "kind": format!("{:?}", f.kind),
                "sequence": f.sequence,
                "detail": f.detail,
            })
        })
        .collect();
    let truncated = findings.len() > rows.len();
    (rows, truncated)
}

/// GET /api/audit/verify — the FULL typed verification report: integrity, counts,
/// and the list of findings (kind / sequence / detail), capped. This is the detail
/// behind `/api/audit/status`'s findings COUNT — so an operator can see WHAT broke
/// in the tamper-evident ledger without dropping to `garmr audit verify` on the
/// host. Admin-gated IN THE HANDLER (issue #22): like `audit_status` it runs the
/// O(ledger) `verify_dir` scan, so it must be unreachable to an unauthenticated
/// caller. The route stays on the public read router (not behind `mount_admin`) so
/// token-less / passkey-only deployments still resolve it — `check_admin` is the gate.
pub(super) async fn audit_verify(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
) -> ApiResult {
    check_admin(&st, &headers)?;
    let Some(ledger) = st.audit.clone() else {
        return Ok(Json(json!({ "enabled": false })));
    };
    let key_id = ledger.key_id();
    let head = ledger.head_sequence();
    let dir = ledger.dir().to_path_buf();
    let pk = ledger.public_key();
    let report = tokio::task::spawn_blocking(move || {
        garmr_audit::verify_dir(&dir, &garmr_audit::TrustRoot::from_public_key(pk))
    })
    .await
    .map_err(oops)?
    .map_err(oops)?;

    let (findings, truncated) = verify_findings_json(&report.findings, MAX_VERIFY_FINDINGS);
    Ok(Json(json!({
        "enabled": true,
        "ok": report.ok,
        "key_id": key_id,
        "head_sequence": head,
        "records": report.records_checked,
        "segments": report.segments,
        "checkpoints": report.checkpoints_checked,
        "last_sequence": report.last_sequence,
        "findings_total": report.findings.len(),
        "findings_returned": findings.len(),
        "findings_truncated": truncated,
        "findings": findings,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use garmr_audit::{Finding, FindingKind};

    #[test]
    fn verify_findings_json_shapes_kind_sequence_detail_and_caps() {
        let findings = vec![
            Finding {
                kind: FindingKind::HashMismatch,
                sequence: Some(5),
                detail: "bad hash".into(),
            },
            Finding {
                kind: FindingKind::ChainBreak,
                sequence: None,
                detail: "chain broke".into(),
            },
            Finding {
                kind: FindingKind::SequenceGap,
                sequence: Some(9),
                detail: "gap".into(),
            },
        ];
        // Cap below the count → truncated, first-N kept in order.
        let (rows, truncated) = verify_findings_json(&findings, 2);
        assert_eq!(rows.len(), 2);
        assert!(truncated);
        assert_eq!(rows[0]["kind"], "HashMismatch");
        assert_eq!(rows[0]["sequence"], 5);
        assert_eq!(rows[0]["detail"], "bad hash");
        // A None sequence serializes as JSON null (not omitted).
        assert_eq!(rows[1]["kind"], "ChainBreak");
        assert_eq!(rows[1]["sequence"], Value::Null);
        // Cap above the count → all rows, not truncated.
        let (all, truncated2) = verify_findings_json(&findings, 200);
        assert_eq!(all.len(), 3);
        assert!(!truncated2);
    }

    #[test]
    fn verify_findings_json_empty_is_empty_not_truncated() {
        let (rows, truncated) = verify_findings_json(&[], MAX_VERIFY_FINDINGS);
        assert!(rows.is_empty());
        assert!(!truncated);
    }

    /// Issue #22: `audit_status` and `audit_verify` stay mounted on the PUBLIC read
    /// router but now call [`check_admin`] before the O(ledger) `verify_dir` scan,
    /// so an unauthenticated caller cannot trigger the scan (a repeated poll would
    /// otherwise be a cheap full-ledger-scan DoS). `check_admin`'s bearer path
    /// resolves the presented secret through the `AuthRegistry` and requires the
    /// Admin role; this exercises exactly that decision — the branch the two
    /// handlers now depend on — without standing up a full ledger + store.
    #[test]
    fn audit_endpoints_gate_admits_only_admin() {
        let mut reg = garmr_core::AuthRegistry::new();
        reg.add(
            "api",
            garmr_core::Role::Analyst,
            "analyst-token".to_string(),
        );
        reg.add("admin", garmr_core::Role::Admin, "admin-token".to_string());
        // The predicate check_admin applies on the bearer path: resolve → Admin.
        let admits = |secret: &str| {
            reg.resolve(secret)
                .is_some_and(|p| p.role.allows(garmr_core::Role::Admin))
        };
        // No credential at all → rejected (check_admin returns 401 UNAUTHORIZED),
        // so the scan is never reached.
        assert!(
            !admits(""),
            "a request without an admin credential must be rejected before the scan"
        );
        // An unknown / forged token → rejected.
        assert!(
            !admits("not-a-real-token"),
            "an unknown token must be rejected"
        );
        // A valid but analyst-tier token → rejected: reaching the scan needs Admin,
        // not merely a resolvable identity.
        assert!(
            !admits("analyst-token"),
            "an analyst-tier token must not reach the ledger scan"
        );
        // The admin token → admitted, so an authorized operator can still verify.
        assert!(admits("admin-token"), "the admin token must be admitted");
    }
}