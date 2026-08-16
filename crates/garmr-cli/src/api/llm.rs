// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The LLM-backed surface: natural-language `ask`, ad-hoc threat `hunt`, rule
//! drafting (`rules/propose`), the read-only hunt/rule inspection endpoints,
//! and the LLM/AI-center diagnostics — the provider read-model
//! (`/api/llm/status`, admin-gated, never a secret value) and the real
//! completion probe (`/admin/llm/test`, rate-limited process-wide; a paid call,
//! deliberately NOT charged to the daily budget). The ask/hunt/propose writes
//! charge the daily model-budget ledger and require the admin bearer whenever
//! an Admin principal is configured.

use super::*;
use axum::http::HeaderMap;

/// GET /api/ask?q=<query> — natural-language search ("ask, don't SPL").
/// Requires a configured LLM backend; the plan is the typed HybridQuery IR
/// (no raw SQL surface — the structured filter compiles to a parameter-safe
/// read-only SELECT) and both model calls charge the daily budget ledger.
pub(super) async fn ask(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    // `ask` SPENDS model budget (two model calls), so it is gated like its spend
    // siblings hunt/rules_propose: when an admin token is configured the bearer is
    // REQUIRED; without one the loopback-only default applies with the daily budget
    // as the guardrail. (Previously ungated beyond the surface auth — any Analyst
    // could burn the budget on an API-but-no-admin-token deployment.)
    if st.auth.has_role(garmr_core::Role::Admin) {
        check_admin(&st, &headers)?;
    }
    let q = p.get("q").ok_or_else(|| bad("missing ?q="))?;
    // Who is asking. Falls back to "unauthenticated" for the open loopback/
    // no-token stance, matching `record_read` on the rest of the read surface —
    // one deployment must not report two different names for the same anonymous
    // caller, or a reviewer cannot correlate the trail.
    let asker = super::auth::attributed_principal(&st, &headers)
        .map(|p| p.user)
        .unwrap_or_else(|| "unauthenticated".to_string());
    // Audit the query best-effort (digest-only: the question text is not stored,
    // only its digest). This is a budget-spending query surface.
    crate::audit::record_best_effort(
        garmr_audit::AuditRecord::new(garmr_audit::action::QUERY, "ask")
            .actor(garmr_audit::ActorType::Human, &asker, None)
            .auth_method("api_session")
            .classification(garmr_audit::DataClassification::Confidential)
            .input_digest(garmr_audit::digest_of(q.as_bytes()))
            .reason("natural-language ask (budget spend)"),
    );
    let llm = match garmr_llm::build_provider_for(
        &st.cfg.agent,
        st.cfg.route.router.default_classification,
    ) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "ask: no LLM backend");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "no LLM backend configured (ANTHROPIC_API_KEY?)".into(),
            ));
        }
    };
    // The live semantic backend (when the daemon has a loaded model) so an
    // `ask` whose plan carries a semantic clause actually fuses meaning in;
    // `None` on a lean/model-less build → the status is honestly "unavailable".
    #[cfg(feature = "semantic")]
    let sem = super::semantic::live_semantic(&st);
    #[cfg(feature = "semantic")]
    let sem_ref = sem.as_ref().map(|s| s as &dyn garmr_query::SemanticSearch);
    #[cfg(not(feature = "semantic"))]
    let sem_ref: Option<&dyn garmr_query::SemanticSearch> = None;
    // Generous cap: two model calls + one store query.
    let fut = garmr_agent::ask(&st.store, llm.as_ref(), &st.cfg, q, sem_ref);
    match tokio::time::timeout(std::time::Duration::from_secs(180), fut).await {
        Ok(Ok(a)) => {
            let mut v = serde_json::to_value(&a).map_err(oops)?;
            // Persist the compiled plan (the typed HybridQuery IR) under its
            // content id, so this answer can be REPRODUCED deterministically
            // without the model (GET /api/reproduce?query_id=). Content-addressed →
            // identical asks collapse to one entry. Best-effort: a store hiccup
            // must not fail the answer that already succeeded.
            if let Ok(plan_json) = serde_json::to_vec(&a.query) {
                let query_id = format!("q1:{}", &garmr_audit::digest_of(&plan_json).to_hex()[..24]);
                if let Err(e) = st.store.state.put_query_plan(&query_id, &plan_json) {
                    tracing::warn!(error = %e, "ask: failed to persist query plan for reproduce");
                } else {
                    // Tie the answer to its reproducible plan IN THE AUDIT LEDGER
                    // (the reserved `query_ref` field) so a past answer's exact
                    // retrieval can be looked up and replayed from the trail, not
                    // just from the live response. Best-effort, like the pre-call line.
                    crate::audit::record_best_effort(
                        garmr_audit::AuditRecord::new(garmr_audit::action::QUERY, "ask")
                            .actor(garmr_audit::ActorType::Human, &asker, None)
                            .auth_method("api_session")
                            .query(query_id.as_str())
                            .reason("ask plan persisted for deterministic reproduce"),
                    );
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert("query_id".into(), serde_json::json!(query_id));
                    }
                }
            }
            Ok(Json(v))
        }
        Ok(Err(e)) => {
            // Budget refusals and backend failures are the caller's business —
            // surface them readably (without internals) instead of opaque 500s.
            let msg = e.to_string();
            if msg.contains("budget") {
                Err((StatusCode::TOO_MANY_REQUESTS, msg))
            } else if msg.contains("llm error") {
                tracing::warn!(error = %msg, "ask: LLM backend failed");
                Err((
                    StatusCode::BAD_GATEWAY,
                    "the LLM backend responded with an error — check the key/endpoint".into(),
                ))
            } else {
                Err(oops(e))
            }
        }
        Err(_) => Err((StatusCode::REQUEST_TIMEOUT, "ask exceeded 180s".into())),
    }
}

/// POST /api/hunt {"hypothesis": …} — run one ad-hoc threat hunt now. This is
/// a SPEND surface (up to max_iterations model calls) and it writes the hunt
/// report — it is not part of the read-only query API. When GARMR_ADMIN_TOKEN
/// is configured the bearer is REQUIRED (defense in depth); without one the
/// loopback-only default applies, with the daily budget as the guardrail.
///
/// The hunt runs on a DETACHED task: an HTTP timeout or client disconnect
/// abandons the wait, never the hunt — it finishes, settles its budget and
/// persists its report (see /api/hunts). A budget-refused hunt maps to 429.
pub(super) async fn hunt(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    if st.auth.has_role(garmr_core::Role::Admin) {
        check_admin(&st, &headers)?;
    }
    let hypothesis = body
        .get("hypothesis")
        .and_then(serde_json::Value::as_str)
        .filter(|h| !h.trim().is_empty())
        .ok_or_else(|| bad("body must be {\"hypothesis\": \"…\"}"))?
        .trim()
        .to_string();
    let llm = match garmr_llm::build_provider_for(
        &st.cfg.agent,
        st.cfg.route.router.default_classification,
    ) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "hunt: no LLM backend");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "no LLM backend configured (ANTHROPIC_API_KEY?)".into(),
            ));
        }
    };
    let store = st.store.clone();
    let cfg = st.cfg.clone();
    // Phase 11: give the ad-hoc hunt the SAME loaded embedder the ask path uses,
    // so its hybrid_search semantic clause runs instead of reporting unavailable.
    #[cfg(feature = "semantic")]
    let sem = st.semantic.as_ref().map(super::semantic::agent_semantic);
    #[cfg(not(feature = "semantic"))]
    let sem: Option<std::sync::Arc<dyn garmr_query::SemanticSearch>> = None;
    let task = tokio::spawn(async move {
        garmr_agent::run_hunt(&store, llm.as_ref(), &cfg, "ad-hoc", &hypothesis, sem).await
    });
    match tokio::time::timeout(std::time::Duration::from_secs(600), task).await {
        Ok(Ok(Ok(report))) => {
            let budget_stopped = report
                .stop_reason
                .as_deref()
                .is_some_and(|r| r.contains("budget"));
            if budget_stopped && report.iterations == 0 {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "the daily budget is exhausted".into(),
                ));
            }
            Ok(Json(serde_json::to_value(report).map_err(oops)?))
        }
        Ok(Ok(Err(e))) => {
            let msg = e.to_string();
            if msg.contains("llm error") {
                tracing::warn!(error = %msg, "hunt: LLM backend failed");
                Err((
                    StatusCode::BAD_GATEWAY,
                    "the LLM backend responded with an error — check the key/endpoint".into(),
                ))
            } else {
                Err(oops(e))
            }
        }
        Ok(Err(join)) => Err(oops(join)),
        // A JSON 200: the CLI parses every 2xx body as JSON, and the work
        // genuinely continues on its detached task.
        Err(_) => Ok(Json(json!({
            "accepted": true,
            "note": "the hunt is taking longer than 600s and continues in the background — see /api/hunts",
        }))),
    }
}

/// GET /api/hunts — every persisted hunt report, newest first (transcripts
/// omitted; fetch one by id for the full audit trail).
pub(super) async fn hunts(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let reports = st.store.state.list_hunt_reports().map_err(oops)?;
    let rows: Vec<serde_json::Value> = reports
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "hunt_id": r.hunt_id,
                "hypothesis": r.hypothesis,
                "started_at": r.started_at,
                "outcome": r.outcome,
                "findings": r.findings.len(),
                "iterations": r.iterations,
                "cost_usd": r.cost_usd,
                "stop_reason": r.stop_reason,
            })
        })
        .collect();
    Ok(Json(Page::from_query(&p).envelope("hunts", rows)))
}

/// GET /api/hunts/:id — one hunt report with its full transcript. Accepts an
/// id prefix (the list prints 8-char prefixes), like /api/cases/:id.
pub(super) async fn hunt_by_id(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match st.store.state.get_hunt_report(&id) {
        Ok(Some(r)) => Ok(Json(serde_json::to_value(r).map_err(oops)?)),
        Ok(None) => match st.store.state.list_hunt_reports() {
            Ok(list) => match list.into_iter().find(|r| r.id.starts_with(&id)) {
                Some(r) => Ok(Json(serde_json::to_value(r).map_err(oops)?)),
                None => Err((
                    StatusCode::NOT_FOUND,
                    format!("no hunt report matches {id}"),
                )),
            },
            Err(e) => Err(oops(e)),
        },
        Err(e) => Err(oops(e)),
    }
}

/// POST /api/rules/propose {"request": …} — draft a detection rule. A SPEND
/// surface like /api/hunt: bearer-required when GARMR_ADMIN_TOKEN is set,
/// detached task (a timeout abandons the wait, not the draft), 429 on budget.
pub(super) async fn rules_propose(
    State(st): State<ApiState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    if st.auth.has_role(garmr_core::Role::Admin) {
        check_admin(&st, &headers)?;
    }
    let request = body
        .get("request")
        .and_then(serde_json::Value::as_str)
        .filter(|r| !r.trim().is_empty())
        .ok_or_else(|| bad("body must be {\"request\": \"…\"}"))?
        .trim()
        .to_string();
    let llm = match garmr_llm::build_provider_for(
        &st.cfg.agent,
        st.cfg.route.router.default_classification,
    ) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "rules/propose: no LLM backend");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "no LLM backend configured (ANTHROPIC_API_KEY?)".into(),
            ));
        }
    };
    let store = st.store.clone();
    let cfg = st.cfg.clone();
    let task = tokio::spawn(async move {
        garmr_agent::propose_rule(&store, llm.as_ref(), &cfg, &request).await
    });
    match tokio::time::timeout(std::time::Duration::from_secs(600), task).await {
        Ok(Ok(Ok(p))) => {
            // Record the agent's drafted proposal best-effort (read-only side —
            // it only creates a pending artifact; approval is the audited act).
            crate::audit::record_agent_best_effort(
                garmr_audit::action::RULE_PROPOSE,
                "rule_proposal",
                &p.id,
                &p.title,
            );
            Ok(Json(serde_json::to_value(p).map_err(oops)?))
        }
        Ok(Ok(Err(e))) => {
            let msg = e.to_string();
            if msg.contains("budget") {
                Err((StatusCode::TOO_MANY_REQUESTS, msg))
            } else if msg.contains("llm error") {
                tracing::warn!(error = %msg, "rules/propose: LLM backend failed");
                Err((
                    StatusCode::BAD_GATEWAY,
                    "the LLM backend responded with an error — check the key/endpoint".into(),
                ))
            } else {
                Err(oops(e))
            }
        }
        Ok(Err(join)) => Err(oops(join)),
        Err(_) => Ok(Json(json!({
            "accepted": true,
            "note": "the draft is taking longer than 600s and continues in the background — see /api/rules/proposals",
        }))),
    }
}

/// GET /api/rules/proposals — every proposal, newest first (bodies included;
/// they are rule files, not payloads).
pub(super) async fn rules_proposals(
    State(st): State<ApiState>,
    Query(p): Query<HashMap<String, String>>,
) -> ApiResult {
    let list = st.store.state.list_proposals().map_err(oops)?;
    Ok(Json(Page::from_query(&p).envelope("proposals", list)))
}

/// GET /api/rules/proposals/:id — one proposal (id prefix ok).
pub(super) async fn rule_proposal_by_id(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match st.store.state.get_proposal(&id) {
        Ok(Some(p)) => Ok(Json(serde_json::to_value(p).map_err(oops)?)),
        Ok(None) => Err((StatusCode::NOT_FOUND, format!("no proposal matches {id}"))),
        Err(e) => Err(oops(e)),
    }
}

// ---- LLM/AI center (Cycle 4): provider read-model + a real test-model probe ----

/// GET /api/llm/status — the configured LLM provider's full state (admin-gated).
/// Backend / model / key presence / external-vs-local / airgap eligibility /
/// budget. Never a secret value; surfaces the no-silent-external-fallback rule.
pub(super) async fn llm_status(State(st): State<ApiState>, headers: HeaderMap) -> ApiResult {
    super::auth::check_admin(&st, &headers)?;
    let airgap = garmr_core::egress::global().is_airgap();
    let backend = st.cfg.agent.backend;
    let external = match backend {
        garmr_core::LlmBackend::Anthropic => true,
        garmr_core::LlmBackend::OpenAiCompat => st
            .cfg
            .agent
            .openai_base_url
            .as_deref()
            .map(|b| !garmr_core::is_local(garmr_core::host_of(b).unwrap_or("")))
            .unwrap_or(false),
    };
    let key_secret = match backend {
        garmr_core::LlmBackend::Anthropic => "ANTHROPIC_API_KEY",
        garmr_core::LlmBackend::OpenAiCompat => "GARMR_OPENAI_API_KEY",
    };
    let sealed = st
        .cfg
        .store
        .state_db
        .parent()
        .and_then(crate::secrets::SealedSecretStore::from_env);
    let key_present = crate::secrets::source_of(key_secret, sealed.as_ref())
        != crate::secrets::SecretSource::Unset;
    Ok(axum::Json(serde_json::json!({
        "backend": format!("{backend:?}"),
        "model": st.cfg.agent.model,
        "prefilter_model": st.cfg.agent.prefilter_model,
        "base_url": st.cfg.agent.openai_base_url,
        "external": external,
        "airgap": airgap,
        // A local backend works under airgap; an external one is blocked.
        "airgap_eligible": !external,
        "blocked_by_airgap": airgap && external,
        "key_secret": key_secret,
        "key_configured": key_present,
        "daily_budget_usd": st.cfg.agent.daily_budget_usd,
        "max_tokens": st.cfg.agent.max_tokens,
        "max_iterations": st.cfg.agent.max_iterations,
        "allow_online_lookups": st.cfg.agent.allow_online_lookups,
        "no_silent_external_fallback": true,
    })))
}

/// POST /admin/llm/test — a REAL minimal completion probe (admin-gated). Upgrades
/// the readiness-only secret test to an actual round-trip: builds the provider
/// (which runs the egress check — airgap + external is refused here, not silently)
/// and asks the model for a one-word reply. Tiny (16 tokens); not charged to the
/// daily budget (a diagnostic must work regardless of spend).
pub(super) async fn llm_test(State(st): State<ApiState>, headers: HeaderMap) -> ApiResult {
    super::auth::check_admin(&st, &headers)?;
    // Rate-limit process-wide: this makes a real (paid, egressing) model call and
    // is deliberately NOT charged to the daily budget, so a tight loop — e.g. a
    // leaked admin bearer — could otherwise accrue unbounded spend/egress. One
    // probe per COOLDOWN bounds it to negligible. CAS so a burst can't slip two.
    {
        use std::sync::atomic::{AtomicI64, Ordering};
        static LAST_MS: AtomicI64 = AtomicI64::new(0);
        const COOLDOWN_MS: i64 = 30_000;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let last = LAST_MS.load(Ordering::Relaxed);
        if now_ms - last < COOLDOWN_MS
            || LAST_MS
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            let wait = ((COOLDOWN_MS - (now_ms - last)).max(0) + 999) / 1000;
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!("the LLM test is rate-limited (a real model call) — wait ~{wait}s"),
            ));
        }
    }
    let airgap = garmr_core::egress::global().is_airgap();
    let http = garmr_llm::LlmHttpConfig::from_env();
    let provider = match garmr_llm::build_backend_provider(
        st.cfg.agent.backend,
        st.cfg.agent.openai_base_url.as_deref(),
        garmr_core::egress::global(),
        http,
    ) {
        Ok(p) => p,
        Err(e) => {
            return Ok(axum::Json(serde_json::json!({
                "ok": false, "stage": "connect", "airgap": airgap,
                "error": e.to_string().chars().take(200).collect::<String>(),
            })));
        }
    };
    let req = garmr_llm::types::LlmRequest {
        model: st.cfg.agent.model.clone(),
        system: "You are a connectivity probe. Reply with exactly: OK".into(),
        messages: vec![garmr_llm::types::Message::user_text("Reply with OK.")],
        tools: vec![],
        max_tokens: 16,
    };
    let t0 = std::time::Instant::now();
    match provider.complete(&req).await {
        Ok(resp) => Ok(axum::Json(serde_json::json!({
            "ok": true, "stage": "complete", "airgap": airgap,
            "model": st.cfg.agent.model,
            "latency_ms": t0.elapsed().as_millis() as u64,
            "reply": resp.text.chars().take(120).collect::<String>(),
        }))),
        Err(e) => Ok(axum::Json(serde_json::json!({
            "ok": false, "stage": "model", "airgap": airgap,
            "error": e.to_string().chars().take(200).collect::<String>(),
        }))),
    }
}
