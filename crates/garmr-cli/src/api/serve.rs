// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Building and running the query API: the axum router (read surface always
//! mounted; write/LLM + admin only on a writer), the auth gate + RBAC wiring,
//! the optional web-console mount, and the fail-closed bind check.
//!
//! [`build_router`] assembles the fully-layered router (routes + auth + security
//! headers) WITHOUT binding a listener, so it is `oneshot`-testable; [`serve`]
//! resolves the env/tokens, builds the state, and drives it.

use super::auth::require_auth;
use super::explain::case_explain;
#[cfg(feature = "semantic")]
use super::semantic::{agent_semantic, build_semantic, semantic};
use super::*;
use super::{
    admin::*, appaudit::*, env::*, feedback::*, hsearch::*, llm::*, query::*, registry::*, views::*,
};

/// How the router should be assembled — the runtime-derived gates, so a test can
/// pick a configuration (admin on/off, auth on/off, read-only) without env vars.
pub(super) struct RouterOpts {
    /// An HA follower: omit every write / model-budget / admin route.
    pub read_only: bool,
    /// Mount the `/admin/*` surface (only when an admin token exists).
    pub mount_admin: bool,
    /// Layer `require_auth` (only when `GARMR_API_TOKEN` is set; loopback stays open).
    pub apply_auth: bool,
    /// Serve the web console (`dist/`) at `/` as the fallback.
    pub ui_dir: Option<std::path::PathBuf>,
}

/// Assemble the fully-layered router: routes (read surface always; writes/LLM +
/// admin per `opts`), the web-console fallback, state, the optional auth
/// middleware, and — UNCONDITIONALLY, outermost — the security-headers layer, so
/// they decorate every response including auth's 401s and the loopback default.
pub(super) fn build_router(state: ApiState, opts: RouterOpts) -> Router {
    // Cloned out before `with_state` consumes `state`, for the auth middleware.
    let auth = state.auth.clone();
    let creds = state.creds.clone();
    let webauthn = state.webauthn.clone();
    // The CSRF guard's allowed origin = passkey's origin (single source of truth).
    // Derived here before `webauthn` is moved into the auth closure below.
    let csrf_allowed_origin = webauthn.as_ref().map(|w| w.origin().to_string());

    let mut app = Router::new()
        .route("/health", get(|| async { "ok" }))
        // Runtime feature/permission/health manifest — the web console's single
        // source of "what can work here and why not" (never an authz decision).
        .route("/api/capabilities", get(super::capabilities::capabilities))
        // First-run setup completeness (admin-gated in the handler: it reports
        // secret presence + posture, the admin-only dimension /api/secrets withholds).
        .route("/api/setup/status", get(super::setup::setup_status))
        // LLM provider read-model (admin-gated in the handler). The real
        // test-model probe is the protected /admin/llm/test.
        .route("/api/llm/status", get(super::llm::llm_status))
        // Read-only configuration surface: typed schema metadata, the live
        // effective values + their source (secrets never included), and
        // severity-classified config diagnostics. Writes are a later cycle.
        .route("/api/config/schema", get(super::config::config_schema))
        .route(
            "/api/config/effective",
            get(super::config::config_effective),
        )
        .route("/api/config/status", get(super::config::config_status))
        // Applied-override revision history (admin-gated in the handler). The
        // write paths (validate/apply/rollback) are on /admin/config/*.
        .route(
            "/api/config/revisions",
            get(super::config::config_revisions),
        )
        // Honest panels for offline-only maintenance ops (never runs anything).
        .route("/api/config/offline-ops", get(super::config::offline_ops))
        // Scoped machine API credential metadata (admin-gated in the handler; the
        // plaintext token is only ever returned once, at issuance on /admin/…).
        .route("/api/credentials", get(super::credentials::credentials))
        // Secret status (admin-gated in the handler): configured/source/
        // fingerprint only — never a value. Writes are on /admin/secrets.
        .route("/api/secrets", get(super::secrets::secrets_status))
        .route("/api/search", get(search))
        .route("/api/query", get(query))
        .route("/api/query/cold", get(query_cold))
        .route("/api/cold-query", get(cold_query))
        .route("/api/tail", get(tail))
        .route("/api/risk", get(risk))
        .route("/api/attack/coverage", get(attack_coverage))
        .route("/api/graph/pivot", get(graph_pivot))
        .route("/api/graph", get(graph_full))
        .route("/api/cases", get(cases))
        // axum 0.7 capture syntax is `:id` — `{id}` (the 0.8 syntax) registers
        // a LITERAL segment and every case-detail fetch 404s.
        .route("/api/cases/:id", get(case_by_id))
        .route("/api/entity/host/:name", get(entity_host))
        .route("/api/entity/ip/:name", get(entity_ip))
        .route("/api/entity/user/:name", get(entity_user))
        .route("/api/entity/staff/:name", get(entity_staff))
        .route("/api/entity/person/:name", get(entity_person))
        .route("/api/hunts", get(hunts))
        .route("/api/hunts/:id", get(hunt_by_id))
        .route("/api/rules/proposals", get(rules_proposals))
        .route("/api/rules/proposals/:id", get(rule_proposal_by_id))
        .route("/api/actions", get(actions_list))
        .route("/api/actions/:id", get(action_by_id))
        // Audit-ledger verification status (integrity + counts only, no record
        // content). Mounted on the read router so token-less / passkey-only
        // deployments resolve it, but admin-gated IN THE HANDLER: it runs an
        // O(ledger) scan, so `check_admin` guards it against an unauthenticated
        // full-ledger-scan DoS (issue #22) — the gate is the handler, not the mount.
        .route("/api/audit/status", get(audit_status))
        // The full typed verification report (finding kind/sequence/detail) behind
        // the status endpoint's findings COUNT. Same O(ledger) scan, same in-handler
        // `check_admin` gate; kept here (not behind mount_admin) so it never 404s.
        .route("/api/audit/verify", get(audit_verify))
        // Read-only security posture + HA role (Phase 14): the loopback/no-token
        // dev stance is never invisible; `read_only` lets the console fence writes.
        .route(
            "/api/security/posture",
            get(super::security::security_posture),
        )
        .route("/api/ha/status", get(super::security::ha_status))
        // Read-only per-source ingest quality (event-time vs ingest-time lag,
        // source staleness) from the Event V2 provenance columns.
        .route("/api/ingest/health", get(ingest_health))
        // Per-collector delivery-sequence integrity (gaps/outstanding/replays) —
        // the Collectors surface, distinct from the event-lag ingest/health view.
        .route("/api/collectors", get(collectors))
        .route("/api/events/total", get(events_total))
        // Read-only Phase-3 record history: a case's full prediction/decision/
        // outcome revisions + the derived current view; and the false-negative
        // register (incl. incidents that never generated a case).
        .route("/api/cases/:id/history", get(case_history))
        // Read-only explainability: WHY the case has its disposition — the
        // reasoning chain + registry drift + audit tokens (Phase 14).
        .route("/api/cases/:id/explain", get(case_explain))
        .route("/api/false-negatives", get(false_negatives))
        // Read-only registry views (records + effective approval state + active).
        .route("/api/registry/active", get(registry_active))
        .route("/api/registry/verify", get(registry_verify))
        .route("/api/registry/:kind", get(registry_list))
        .route("/api/hsearch", axum::routing::post(hsearch))
        // Deterministic, LLM-free replay of a stored `ask` plan (query_id) —
        // reproduces a past answer's retrieval through the same hybrid executor.
        .route("/api/reproduce", get(super::hsearch::reproduce))
        .route("/api/env/facts", get(env_facts))
        .route("/api/env/candidates", get(env_candidates))
        .route("/api/env/verify", get(env_verify))
        .route("/api/env/entity/:kind/:id", get(env_entity))
        .route("/api/appaudit/baselines", get(appaudit_baselines))
        // Phase 9 user-vs-peer-group behavioral comparison (peer_novelty), with
        // explicit abstention when either baseline is not yet Trusted.
        .route("/api/appaudit/peers", get(appaudit_peers))
        // Read-only access-policy set (Phase 13): the rules the app-audit plane
        // enforces, so the console's Policies area can show them (authoring stays
        // a file + audited registry-promotion flow, never a console write).
        .route("/api/policies", get(super::policies::policies))
        .route("/api/policies/:id", get(super::policies::policy_by_id))
        // Non-mutating backtest of a DRAFT policy over recent history (Phase 6/13):
        // replay it through the same read path + projection the live pipeline uses
        // and report its blast radius. Analyst-tier (persists/enforces nothing).
        .route(
            "/api/policies/simulate",
            axum::routing::post(super::policies::simulate),
        )
        // Resource workspace (Phase B / DoD 5): the resource catalog joined with
        // recent lakehouse access history + per-resource policy coverage. Read-only
        // — registering/classifying/retiring a resource is a governed registry
        // promotion on the `catalog` kind, never a console write.
        .route("/api/resources", get(super::resources::resources))
        .route("/api/resources/:id", get(super::resources::resource_by_id))
        // Per-user behavioral profile (Phase B / DoD 3): the learned per-dimension
        // footprint + time-of-day + volume, plus a bounded sensitive-activity scan.
        .route("/api/users/:id", get(super::users::user_by_id))
        // Application inventory (Phase B / DoD 4): declared (catalog) reconciled with
        // observed (baselines + activity), surfacing shadow + dormant apps; per-app
        // footprint + top users/objects + sensitive activity.
        .route("/api/applications", get(super::applications::applications))
        .route(
            "/api/applications/:id",
            get(super::applications::application_by_id),
        )
        // Champion/challenger shadow evaluation (Phase E / DoD 19): the running
        // comparison of a `shadow`-channel challenger detector config against the
        // production one, with a recommended (human-gated, never auto-applied)
        // decision. Read-only; inert unless a challenger is registered.
        .route("/api/shadow/summary", get(super::shadow::shadow_summary))
        .route("/api/shadow/scores", get(super::shadow::shadow_scores))
        .route("/api/findings", get(findings))
        .route("/api/registry/:kind/:name", get(registry_show))
        .route("/api/registry/:kind/:name/:version", get(registry_version))
        // Passkey (WebAuthn) login. The login page + login/logout/status are
        // public (auth middleware allow-lists them); register is admin-gated
        // (inside the handler AND by the middleware, so bootstrap needs the
        // admin bearer token). All are no-ops with a 404 when passkey is off.
        .route("/login", get(super::passkey::login_page))
        .route("/auth/status", get(super::passkey::status))
        .route("/auth/logout", axum::routing::post(super::passkey::logout))
        .route(
            "/auth/passkey/login/start",
            get(super::passkey::login_start),
        )
        .route(
            "/auth/passkey/login/finish",
            axum::routing::post(super::passkey::login_finish),
        )
        .route(
            "/auth/passkey/register/start",
            get(super::passkey::register_start),
        )
        .route(
            "/auth/passkey/register/finish",
            axum::routing::post(super::passkey::register_finish),
        )
        // Credential + session administration (admin-gated inside the handlers;
        // revoke additionally requires step-up and refuses the last Admin key).
        .route(
            "/auth/passkey/credentials",
            get(super::passkey::credentials),
        )
        .route(
            "/auth/passkey/credentials/rename",
            axum::routing::post(super::passkey::credential_rename),
        )
        .route(
            "/auth/passkey/credentials/revoke",
            axum::routing::post(super::passkey::credential_revoke),
        )
        .route(
            "/auth/sessions/revoke-all",
            axum::routing::post(super::passkey::sessions_revoke_all),
        );
    #[cfg(feature = "semantic")]
    {
        app = app.route("/api/semantic", get(semantic));
        // Semantic index freshness / lag metric (Phase C / DoD 15).
        app = app.route(
            "/api/semantic/status",
            get(super::semantic::semantic_status),
        );
    }
    // Write / model-budget endpoints: a read replica must never spend budget or
    // persist state, so they exist only on a writer (`!read_only`).
    if !opts.read_only {
        app = app
            .route("/api/ask", get(ask))
            // POST: it spends model budget and writes hunt reports — not a read.
            .route("/api/hunt", axum::routing::post(hunt))
            // POST: drafting spends model budget and persists the proposal.
            .route("/api/rules/propose", axum::routing::post(rules_propose))
            // Phase-3 analyst-feedback writes (append-only; gated + fail-closed
            // audited). Decisions/false-negatives/feedback/mistakes are
            // analyst-tier; sealing an incident outcome is admin-gated in-handler.
            .route(
                "/api/cases/:id/decision",
                axum::routing::post(submit_decision),
            )
            .route("/api/incidents", axum::routing::post(submit_incident))
            .route(
                "/api/false-negatives",
                axum::routing::post(register_false_negative),
            )
            .route("/api/feedback", axum::routing::post(submit_feedback))
            .route("/api/mistakes", axum::routing::post(record_mistake));
    }
    // The admin surface (notification silences, rule/action approval, registry +
    // environment writes) is mounted only when an admin token is set, and every
    // call must carry it as a bearer. This keeps the default API strictly
    // read-only, and makes the authenticated call the human's out-of-band
    // approval: the agent proposes in chat but never holds this token.
    if opts.mount_admin {
        app = app
            .route("/admin/silence", axum::routing::post(admin_silence))
            .route("/admin/silences", get(admin_silences))
            // Rule approval is the ACT side of detection authoring: the
            // authenticated call is the human decision, like silences.
            .route(
                "/admin/rules/approve",
                axum::routing::post(admin_rule_approve),
            )
            .route(
                "/admin/rules/reject",
                axum::routing::post(admin_rule_reject),
            )
            // Action approval/denial is the HUMAN gate of the SOAR flow — the
            // authenticated call is the out-of-band approval the agent cannot
            // forge. Execution is a separate step (the executor loop / CLI).
            .route(
                "/admin/action/approve",
                axum::routing::post(admin_action_approve),
            )
            .route("/admin/action/deny", axum::routing::post(admin_action_deny))
            // Case retention/cleanup over the live store (admin-gated).
            .route("/admin/cases/prune", axum::routing::post(admin_cases_prune))
            // Scoped machine API credentials: issue/rotate/revoke (Admin +
            // step-up + audit; the token is returned once, at issue/rotate).
            .route(
                "/admin/credentials",
                axum::routing::post(super::credentials::issue),
            )
            .route(
                "/admin/credentials/rotate",
                axum::routing::post(super::credentials::rotate),
            )
            .route(
                "/admin/credentials/revoke",
                axum::routing::post(super::credentials::revoke),
            )
            // Write-only secret management (Admin + secrets:write + step-up +
            // audit; the store never returns a value, and airgap blocks external
            // connection tests).
            .route(
                "/admin/secrets",
                axum::routing::post(super::secrets::secret_set),
            )
            .route(
                "/admin/secrets/remove",
                axum::routing::post(super::secrets::secret_remove),
            )
            .route(
                "/admin/secrets/test",
                axum::routing::post(super::secrets::secret_test),
            )
            // Config write: dry-run validate (Admin), then apply/rollback the
            // generated override layer (Admin + config:write + step-up + audit;
            // persisted atomically as a versioned revision, restart to take effect).
            .route(
                "/admin/config/validate",
                axum::routing::post(super::config::config_validate),
            )
            .route(
                "/admin/config/apply",
                axum::routing::post(super::config::config_apply),
            )
            .route(
                "/admin/config/rollback",
                axum::routing::post(super::config::config_rollback),
            )
            // A real LLM test-model probe (Admin; airgap-aware via the egress
            // chokepoint; a tiny call not charged to the daily budget).
            .route("/admin/llm/test", axum::routing::post(super::llm::llm_test))
            // Registry register + promotion (the promote path enforces the
            // no-promotion-without-a-versioned-record-and-audit-event invariant).
            .route(
                "/admin/registry/register",
                axum::routing::post(registry_register),
            )
            // Typed policy draft (Phase B / DoD 6): validate + digest + auto-version
            // a Policy into a governed Draft record (activation is a separate promote).
            .route(
                "/admin/policies/draft",
                axum::routing::post(super::policies::draft),
            )
            .route(
                "/admin/registry/promote",
                axum::routing::post(registry_promote),
            )
            .route(
                "/admin/registry/rollback",
                axum::routing::post(registry_rollback),
            )
            .route(
                "/admin/registry/retire",
                axum::routing::post(registry_retire),
            )
            .route(
                "/admin/registry/reject",
                axum::routing::post(registry_reject),
            )
            // Phase 5 environment-model admin writes. Promote/approve re-check the
            // inviolable anti-poisoning blocks; all protected transitions are
            // fail-closed audited.
            .route("/admin/env/promote", axum::routing::post(env_promote))
            .route("/admin/env/approve", axum::routing::post(env_approve))
            .route("/admin/env/demote", axum::routing::post(env_demote))
            .route("/admin/env/retire", axum::routing::post(env_retire))
            .route("/admin/env/import", axum::routing::post(env_import))
            .route(
                "/admin/env/change-window",
                axum::routing::post(env_change_window),
            )
            // Phase 7/8 behavioral-baseline admin writes. Promote re-checks the
            // inviolable hard blocks (open case / prior policy violation /
            // suspicious) and is fail-closed audited; suspect/clear are the taint
            // + human-review lifecycle.
            .route(
                "/admin/appaudit/baselines/promote",
                axum::routing::post(appaudit_promote),
            )
            .route(
                "/admin/appaudit/baselines/suspect",
                axum::routing::post(appaudit_suspect),
            )
            .route(
                "/admin/appaudit/baselines/clear",
                axum::routing::post(appaudit_clear),
            )
            // Hot-reload the enforced config (policies/catalog/monitoring) without
            // a restart — a governance change takes effect immediately.
            .route(
                "/admin/appaudit/reload",
                axum::routing::post(appaudit_reload),
            );
    }
    // Host the web console (garmr-webui `dist/`) at `/` when configured. The API
    // routes above keep priority; the SPA is the fallback, and any unmatched path
    // falls back to index.html so the client-routed console reloads cleanly on any
    // URL. The auth + security layers below cover this static surface too.
    if let Some(dir) = &opts.ui_dir {
        let index = dir.join("index.html");
        if index.is_file() {
            let serve_dir = tower_http::services::ServeDir::new(dir)
                .append_index_html_on_directories(true)
                .fallback(tower_http::services::ServeFile::new(&index));
            app = app.fallback_service(serve_dir);
        }
    }

    let app = app.with_state(state);

    // Auth door: raised when a token is configured (a loopback bind stays open for
    // local curl). The registry resolves the presented secret to a named
    // principal; the admin-token holder is never locked out of the read surface.
    let app = if opts.apply_auth {
        app.layer(axum::middleware::from_fn(move |req, next| {
            require_auth(auth.clone(), creds.clone(), webauthn.clone(), req, next)
        }))
    } else {
        app
    };
    // CSRF Origin guard (belt-and-suspenders on top of SameSite=Strict + Json-only
    // mutators). Unconditional: it only fires on a cookie-bearing unsafe request or
    // /auth/logout, so bearer/loopback traffic is untouched. The allowed origin is
    // the SAME one passkey is bound to (single source of truth — session cookies
    // only exist when webauthn is Some), so the guard can never diverge from the
    // deployment's real origin (review MEDIUM).
    let csrf_origin = std::sync::Arc::new(csrf_allowed_origin);
    let app = app.layer(axum::middleware::from_fn(move |req, next| {
        super::security::csrf_layer(csrf_origin.clone(), req, next)
    }));
    // Content-Security-Policy: same-origin, no external host (connect-src 'self' is
    // the browser-enforced counterpart to the egress chokepoint). Built ONCE at
    // startup, hashing the compiled-in login page's inline script + any mounted
    // SPA index.html's inline scripts, so script-src stays strict (no unsafe-inline).
    let mut script_hashes = super::security::inline_script_hashes(super::passkey::login_html());
    if let Some(dir) = &opts.ui_dir {
        if let Ok(index) = std::fs::read_to_string(dir.join("index.html")) {
            script_hashes.extend(super::security::inline_script_hashes(&index));
        }
        // The embedded CodeVault map (garmr-map, eframe/WASM) is served from
        // <ui>/map/ in an iframe; its trunk bootstrap carries its own inline
        // scripts — hash them too or the strict CSP blocks the map from
        // initialising (its frame loads blank).
        if let Ok(map_index) = std::fs::read_to_string(dir.join("map").join("index.html")) {
            script_hashes.extend(super::security::inline_script_hashes(&map_index));
        }
    }
    let csp = std::sync::Arc::new(super::security::build_csp(&script_hashes));
    let app = app.layer(axum::middleware::from_fn(move |req, next| {
        super::security::csp_layer(csp.clone(), req, next)
    }));
    // Security response headers, applied UNCONDITIONALLY and OUTERMOST (after auth
    // + CSRF), so they decorate EVERY response — auth's own 401s, the CSRF 403,
    // static console + 404/500, and the loopback/no-token default deployment.
    app.layer(axum::middleware::from_fn(
        super::security::security_headers_layer,
    ))
}

/// Serve the query API. `read_only` (an HA follower) omits every route that
/// mutates state or spends model budget — the write/LLM endpoints and the whole
/// admin surface — leaving only the read surface (query, search, cases, …).
pub async fn serve(
    bind: &str,
    store: Store,
    cfg: Config,
    read_only: bool,
    app_audit: Option<std::sync::Arc<crate::appaudit::AppAudit>>,
    // The live triage/hunt agent (writer only; `None` for a read-only follower).
    // Phase 11: after the embedding model loads here, the SAME backend is injected
    // into the agent's hybrid_search tool so the model is loaded exactly once.
    agent: Option<std::sync::Arc<garmr_agent::Agent>>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let loopback = listener
        .local_addr()
        .map(|a| a.ip().is_loopback())
        .unwrap_or(false);
    // API authentication. `GARMR_API_TOKEN` gates the ENTIRE surface (read API
    // + UI + admin routes) — browsers are prompted via Basic, API clients send
    // it as a Bearer. It is REQUIRED for a non-loopback bind: the read API
    // alone exposes all logs + arbitrary read SQL + case transcripts, so
    // serving it unauthenticated to the network is refused (fail closed), not
    // merely warned. Loopback stays open (SSH-tunnel / dev).
    // Trim: `GARMR_API_TOKEN=$(cat file)` commonly carries a trailing newline,
    // which would become part of the secret and silently lock everyone out.
    let api_token = std::env::var("GARMR_API_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    if !loopback && api_token.is_none() {
        anyhow::bail!(
            "refusing to serve on a non-loopback address ({bind}) without authentication: \
             set GARMR_API_TOKEN (browsers get a login prompt; API clients send it as a \
             Bearer token — serve it over TLS, e.g. behind the Caddy reverse proxy), or \
             bind ingest.api_bind to a loopback address"
        );
    }
    match (loopback, api_token.is_some()) {
        (true, false) => tracing::info!(%bind, "query API listening (localhost, unauthenticated)"),
        (_, true) => tracing::info!(%bind, "query API listening (authenticated, GARMR_API_TOKEN)"),
        (false, false) => unreachable!("guarded by the fail-closed check above"),
    }
    if read_only {
        tracing::info!(
            "read-only mode (HA follower) — /api/ask, POST /api/hunt, POST /api/rules/propose and all /admin/* endpoints are disabled"
        );
    }
    let admin_token = std::env::var("GARMR_ADMIN_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    // RBAC registry: the two legacy env tokens map to synthetic principals
    // (api→Analyst read+operator, admin→Admin), and GARMR_USERS adds named
    // per-user tokens ([{token,user,role}, …]). The read-surface gate and
    // check_admin both resolve through this, giving audit-by-identity.
    let mut auth_reg = garmr_core::AuthRegistry::new();
    if let Some(t) = &api_token {
        auth_reg.add("api", garmr_core::Role::Analyst, t.clone());
    }
    if let Some(t) = &admin_token {
        auth_reg.add("admin", garmr_core::Role::Admin, t.clone());
    }
    if let Ok(users) = std::env::var("GARMR_USERS") {
        match auth_reg.add_json(&users) {
            Ok(n) if n > 0 => {
                tracing::info!(
                    count = n,
                    "RBAC: loaded named user token(s) from GARMR_USERS"
                )
            }
            Ok(_) => {}
            Err(e) => anyhow::bail!("GARMR_USERS: {e}"),
        }
    }
    let auth = std::sync::Arc::new(auth_reg);
    let mount_admin = !read_only && admin_token.is_some();
    if mount_admin {
        tracing::info!("admin endpoints enabled (GARMR_ADMIN_TOKEN set)");
    }
    if api_token.is_some() {
        match (&api_token, &admin_token) {
            // Same value → the two-tier model collapses (every API-token holder
            // resolves to Admin); surface it rather than surprise.
            (Some(t), Some(a)) if a == t => tracing::warn!(
                "GARMR_API_TOKEN == GARMR_ADMIN_TOKEN — the two-tier model is collapsed: every API-token holder can approve admin actions"
            ),
            // No admin token → the spend/write endpoints fall back to open, so
            // any API-token holder can burn the daily LLM budget and persist state.
            (Some(_), None) => tracing::warn!(
                "GARMR_API_TOKEN is set but GARMR_ADMIN_TOKEN is not — the LLM-spend endpoints (POST /api/hunt, /api/rules/propose) are reachable by ANY valid API-token holder; set GARMR_ADMIN_TOKEN to gate them"
            ),
            _ => {}
        }
        tracing::info!(principals = auth.len(), "API authentication enabled (RBAC)");
    }
    let ui_dir = std::env::var("GARMR_UI_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| cfg.ingest.ui_dir.clone());
    let matrix = cfg
        .matrix
        .as_ref()
        .and_then(garmr_agent::Matrix::from_env)
        .map(std::sync::Arc::new);
    // Live semantic search: load the model + index and spawn the read-lane
    // rebuild task (borrows store/cfg before they move into the state).
    #[cfg(feature = "semantic")]
    let semantic = build_semantic(&store, &cfg);
    // Phase 11: share the ONE loaded embedder + index with the triage/hunt agent's
    // hybrid_search tool, so the agent and the ask HTTP path use one model (never a
    // second 128 MB load on a 1-2 vCPU box). No-op when semantic is off or no agent
    // was passed (a read-only follower). The agent triages without a semantic clause
    // until this binds — hybrid_search reports it unavailable, never dropped.
    #[cfg(feature = "semantic")]
    if let (Some(agent), Some(h)) = (agent.as_ref(), semantic.as_ref()) {
        agent.set_semantic(agent_semantic(h));
    }
    // The agent is only used to bind the shared embedder, which needs `semantic`.
    #[cfg(not(feature = "semantic"))]
    let _ = &agent;
    // Shared by the pivot + the topology map. 5-min TTL so the (lake-scanning)
    // build stays warm across clicks; a 72h event-edge window plus skipping the
    // configured firehose source(s) keeps each scan well under the 30s query
    // timeout on a large store, while still surfacing recent host↔ip↔user
    // activity. Case edges (the backbone) are always present.
    let graph_cache = std::sync::Arc::new(garmr_graph::GraphCache::new(
        300,
        72,
        50_000,
        cfg.store.fulltext_exclude_sources.clone(),
    ));
    // Warm the entity-graph cache in the background at startup so the first Map
    // open serves a ready graph instead of blocking on the cold wide-window build.
    graph_cache.warm(&store);
    // Passkey (WebAuthn) login — enabled when GARMR_WEBAUTHN_RP_ID is set;
    // borrows the store (for the session key + credentials) before it moves.
    let webauthn = super::passkey::Webauthn::from_env(&store);
    // Tamper-evident audit ledger — the process-wide singleton (the daemon
    // initializes it before spawning tasks; a standalone API/follower initializes
    // it here). Shared with the detection pipeline via `audit::global()`.
    let audit = crate::audit::ensure_init(&cfg.audit)?;
    match &audit {
        Some(l) => {
            tracing::info!(dir = %l.dir().display(), key = %l.key_id(), "audit ledger active")
        }
        None => tracing::warn!(
            "audit ledger DISABLED (audit.enabled = false) — admin actions are not tamper-evidently recorded"
        ),
    }
    let creds = super::credentials::CredentialStore::new(&store);
    let state = ApiState {
        store,
        search_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SEARCHES)),
        cfg,
        auth,
        creds,
        matrix,
        graph_cache,
        webauthn,
        audit,
        app_audit,
        read_only,
        #[cfg(feature = "semantic")]
        semantic,
    };
    let app = build_router(
        state,
        RouterOpts {
            read_only,
            mount_admin,
            apply_auth: api_token.is_some(),
            ui_dir,
        },
    );
    axum::serve(listener, app).await?;
    Ok(())
}

/// Startup config validation, run by `main` BEFORE the API is spawned so a
/// misconfiguration aborts `garmr serve` loudly (non-zero exit → systemd shows
/// it) instead of the API task dying quietly while the daemon looks healthy.
/// Refuses a non-loopback API bind without `GARMR_API_TOKEN`. `serve()` re-checks
/// authoritatively against the actually-bound address; this is the early gate.
pub fn check_bind_auth(api_bind: &str) -> anyhow::Result<()> {
    use std::net::ToSocketAddrs;
    let has_token = std::env::var("GARMR_API_TOKEN")
        .ok()
        .map(|t| !t.trim().is_empty())
        .unwrap_or(false);
    if has_token {
        return Ok(());
    }
    // No token: every address this bind resolves to must be loopback. If it
    // doesn't resolve at all, let serve()'s bind surface the real error.
    let any_nonloopback = api_bind
        .to_socket_addrs()
        .map(|addrs| addrs.into_iter().any(|a| !a.ip().is_loopback()))
        .unwrap_or(false);
    if any_nonloopback {
        anyhow::bail!(
            "refusing to serve the API on a non-loopback address ({api_bind}) without \
             authentication: set GARMR_API_TOKEN (serve it over TLS, e.g. behind the Caddy \
             reverse proxy) or set ingest.api_bind to a loopback address"
        );
    }
    Ok(())
}