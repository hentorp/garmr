// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/capabilities` — the runtime feature/permission/health manifest.
//!
//! One authoritative, read-only self-report the web console consults on load to
//! decide **which task areas to show, which controls can ever work, and why a
//! feature is unavailable** — so a disabled plane reads as "not configured here",
//! never as a generic error, and the console adapts to air-gapped / no-LLM /
//! read-only-follower deployments without guessing.
//!
//! IMPORTANT: this is a *hint for the UI*, never an authorization decision. Every
//! protected endpoint still authorizes its own request independently (see
//! `auth::check_admin` / `check_analyst`). The manifest only prevents the console
//! from rendering a control that provably cannot succeed on this node; it never
//! grants access.

use axum::extract::State;

use super::{ApiResult, ApiState};

/// One feature's runtime state, as a small `{ state, reason? }` object.
///
/// - `healthy` — available, configured, and serving.
/// - `degraded` — available but impaired (e.g. an index still rebuilding).
/// - `disabled` — deliberately off in this deployment (a config switch).
/// - `not_configured` — available in the build but missing required setup.
fn feature(state: &'static str, reason: Option<&str>) -> serde_json::Value {
    match reason {
        Some(r) => serde_json::json!({ "state": state, "reason": r }),
        None => serde_json::json!({ "state": state }),
    }
}

/// `GET /api/capabilities` — the feature manifest. Read surface (any authenticated
/// principal on an authed deployment; open on loopback), never public to the
/// network unauthenticated, since it reveals deployment posture.
pub(super) async fn capabilities(State(st): State<ApiState>) -> ApiResult {
    let read_only = st.read_only;
    let airgap = garmr_core::egress::global().is_airgap();

    // Semantic search: gated by the build feature AND a loaded model+index.
    #[cfg(feature = "semantic")]
    let semantic = if st.semantic.is_some() {
        feature("healthy", None)
    } else {
        feature(
            "not_configured",
            Some("set GARMR_EMBED_MODEL and run `garmr embed-index` to enable meaning search"),
        )
    };
    #[cfg(not(feature = "semantic"))]
    let semantic = feature("disabled", Some("built without the `semantic` feature"));

    // Application-audit plane (behavioral baselines, users, applications, insider risk).
    let app_audit = if st.app_audit.is_some() {
        feature("healthy", None)
    } else {
        feature(
            "disabled",
            Some("set detect.app_audit_enabled = true to enable the application-audit plane"),
        )
    };

    // Temporal environment model (Phase 5).
    let environment = if st.cfg.environment.enabled {
        feature(
            if st.cfg.environment.learn {
                "healthy"
            } else {
                "degraded"
            },
            (!st.cfg.environment.learn)
                .then_some("query surface on; background learner off (environment.learn = false)"),
        )
    } else {
        feature(
            "disabled",
            Some("set environment.enabled = true to expose the environment model"),
        )
    };

    // Audit ledger.
    let audit_ledger = if st.audit.is_some() {
        feature("healthy", None)
    } else {
        feature(
            "disabled",
            Some("audit.enabled = false — admin actions are not tamper-evidently recorded"),
        )
    };

    // Natural-language / model-priced surfaces (ask, hunt, rule propose). The
    // ROUTES exist only on a writer; whether a call SUCCEEDS depends on the model
    // router (an air-gapped or ceiling-fenced case resolves to NeedsHuman, never a
    // silent external send). We report route availability + the fence honestly.
    let model_state = || {
        if read_only {
            feature("disabled", Some("this node is a read-only HA follower"))
        } else if airgap {
            feature(
                "degraded",
                Some("air-gap: only a LOCAL model is permitted; confidential/restricted data never leaves the box"),
            )
        } else {
            feature("healthy", None)
        }
    };

    // Response actions (SOAR). Proposals can always be approved/denied; the
    // executor LOOP that acts on approvals is opt-in.
    let response_actions = if read_only {
        feature("disabled", Some("read-only HA follower"))
    } else if st.cfg.executor.enabled {
        feature("healthy", None)
    } else {
        feature(
            "degraded",
            Some("propose + approve only — the executor loop is off (executor.enabled = false); run `garmr execute` to act"),
        )
    };

    // Access policies (Phase 13): count the policy files the engine loads.
    let policy_count = std::fs::read_dir(&st.cfg.detect.policies_dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| {
                    e.path()
                        .extension()
                        .is_some_and(|x| x.eq_ignore_ascii_case("toml"))
                })
                .count()
        })
        .unwrap_or(0);
    let policies = if policy_count > 0 {
        feature("healthy", None)
    } else {
        feature(
            "not_configured",
            Some("no access-policy files in detect.policies_dir"),
        )
    };

    // Cold storage / retention.
    let cold_storage = if st.cfg.retention.enabled {
        feature("healthy", None)
    } else {
        feature(
            "disabled",
            Some("retention.enabled = false — no cold tier configured"),
        )
    };

    Ok(axum::Json(serde_json::json!({
        "backend_version": env!("CARGO_PKG_VERSION"),
        "api_version": 1,
        "generated_us": now_us(),
        // Deployment posture (drives global affordances).
        "airgap": airgap,
        "read_only": read_only,
        "ha_role": if read_only { "follower" } else { "leader" },
        "writes_enabled": !read_only,
        "auth": {
            "enabled": !st.auth.is_empty(),
            "passkey_enabled": st.webauthn.is_some(),
        },
        // Per-feature runtime state. The console maps these to task areas and to
        // individual controls; anything not `healthy` renders a labelled
        // disabled/degraded state instead of a dead button.
        "features": {
            "full_text_search": feature("healthy", None),
            "structured_query": feature("healthy", None),
            "semantic_search": semantic,
            "hybrid_search": feature("healthy", None),
            "nl_ask": model_state(),
            "cases": feature("healthy", None),
            "findings": feature("healthy", None),
            "risk": feature("healthy", None),
            "app_audit": app_audit,
            "environment_model": environment,
            "graph": feature("healthy", None),
            "attack_coverage": feature("healthy", None),
            "hunts": model_state(),
            "rule_proposals": if read_only { feature("disabled", Some("read-only follower")) } else { feature("healthy", None) },
            "response_actions": response_actions,
            "policies": policies,
            "learning": feature("healthy", None),
            "audit_integrity": audit_ledger,
            "registry": feature("healthy", None),
            "data_sources": feature("healthy", None),
            "cold_storage": cold_storage,
            "backup": feature("healthy", None),
        },
    })))
}

/// Epoch microseconds, via the same clock the rest of the API uses.
fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}