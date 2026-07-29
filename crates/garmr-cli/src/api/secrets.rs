// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Secret management HTTP surface: status (never values), write-only set/remove,
//! and an airgap-aware connection readiness test. Every write requires Admin +
//! the `secrets:write` scope + step-up + a fail-closed audit record. The sealed
//! store never returns a stored secret — the console shows only configured /
//! source / fingerprint / updated.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::secrets::{self, SealedSecretStore, SecretSource};

use super::credentials::require_scope;
use super::passkey::require_step_up;
use super::{bad, oops, ApiResult, ApiState};

fn sealed(st: &ApiState) -> Option<SealedSecretStore> {
    st.cfg
        .store
        .state_db
        .parent()
        .and_then(SealedSecretStore::from_env)
}

/// GET /api/secrets — admin-gated. Per-secret status; never a value. Reports
/// whether the writable sealed store is available and which secrets are
/// env-configured (and therefore not replaceable through the UI).
pub(super) async fn secrets_status(State(st): State<ApiState>, headers: HeaderMap) -> ApiResult {
    super::auth::check_admin(&st, &headers)?;
    let store = sealed(&st);
    let writable = store.is_some();
    let airgap = garmr_core::egress::global().is_airgap();
    let rows: Vec<Value> = secrets::KNOWN_SECRETS
        .iter()
        .map(|name| {
            let source = secrets::source_of(name, store.as_ref());
            let sealed_status = store.as_ref().and_then(|s| s.status(name));
            let (fp, updated) = match &sealed_status {
                Some((f, u, _)) if source == SecretSource::Sealed => (Some(f.clone()), Some(*u)),
                _ => (None, None),
            };
            json!({
                "name": name,
                "configured": source != SecretSource::Unset,
                "source": source.as_str(),
                "fingerprint": fp,
                "updated": updated,
                // env-configured secrets cannot be replaced from the UI.
                "writable": writable && source != SecretSource::Env,
                "overridden_by_env": source == SecretSource::Env && sealed_status.is_some(),
            })
        })
        .collect();
    Ok(Json(json!({
        "secrets": rows,
        "writable_store": writable,
        "airgap": airgap,
    })))
}

#[derive(Deserialize)]
pub(super) struct SetReq {
    name: String,
    value: String,
}

/// POST /admin/secrets — write-only set/replace. Admin + secrets:write + step-up.
pub(super) async fn secret_set(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<SetReq>,
) -> ApiResult {
    let who = super::auth::check_admin(&st, &headers)?;
    require_scope(&st, &headers, "secrets:write")?;
    require_step_up(&st, &headers)?;
    if !secrets::KNOWN_SECRETS.contains(&req.name.as_str()) {
        return Err(bad("unknown secret name"));
    }
    if req.value.is_empty() {
        return Err(bad("empty value"));
    }
    let store = sealed(&st).ok_or((
        StatusCode::CONFLICT,
        "no secret master key configured — the writable store is unavailable (set GARMR_SECRET_KEY or provision /etc/garmr/secret.key)".to_string(),
    ))?;
    let fp = store.set(&req.name, &req.value).map_err(oops)?;
    // Audit fail-closed; only the fingerprint is recorded, never the value.
    st.record_admin(
        &who,
        garmr_audit::action::SECRET_SET,
        "secret",
        Some(&req.name),
        Some(&format!("set/replaced ({fp})")),
    )?;
    Ok(Json(json!({
        "ok": true,
        "fingerprint": fp,
        "restart_required": true,
    })))
}

#[derive(Deserialize)]
pub(super) struct NameReq {
    name: String,
}

/// POST /admin/secrets/remove {name} — Admin + secrets:write + step-up.
pub(super) async fn secret_remove(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NameReq>,
) -> ApiResult {
    let who = super::auth::check_admin(&st, &headers)?;
    require_scope(&st, &headers, "secrets:write")?;
    require_step_up(&st, &headers)?;
    let store = sealed(&st).ok_or((
        StatusCode::CONFLICT,
        "the writable secret store is unavailable".to_string(),
    ))?;
    let existed = store.remove(&req.name).map_err(oops)?;
    st.record_admin(
        &who,
        garmr_audit::action::SECRET_REMOVE,
        "secret",
        Some(&req.name),
        Some(if existed { "removed" } else { "no-op (absent)" }),
    )?;
    Ok(Json(json!({"ok": true, "removed": existed})))
}

/// POST /admin/secrets/test {name} — airgap-aware connection readiness test for
/// the LLM key. Verifies the key is configured (env or sealed) AND that egress
/// policy would permit the backend — WITHOUT making a paid model call or ever
/// returning the secret. A full completion probe is the Cycle-4 LLM center.
pub(super) async fn secret_test(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NameReq>,
) -> ApiResult {
    super::auth::check_admin(&st, &headers)?;
    require_scope(&st, &headers, "secrets:write")?;
    let airgap = garmr_core::egress::global().is_airgap();

    // Only the LLM keys are testable in this cycle.
    let is_llm = matches!(req.name.as_str(), "ANTHROPIC_API_KEY" | "GARMR_OPENAI_API_KEY");
    if !is_llm {
        return Err(bad("only the LLM keys support a connection test in this cycle"));
    }
    let store = sealed(&st);
    let configured = secrets::source_of(&req.name, store.as_ref()) != SecretSource::Unset;

    // Is the configured backend external, and does egress permit it?
    let backend = st.cfg.agent.backend;
    let external = match backend {
        garmr_core::LlmBackend::Anthropic => true,
        garmr_core::LlmBackend::OpenAiCompat => {
            let base = st
                .cfg
                .agent
                .openai_base_url
                .as_deref()
                .unwrap_or("http://localhost:11434/v1");
            !garmr_core::is_local(garmr_core::host_of(base).unwrap_or(""))
        }
    };

    if airgap && external {
        return Ok(Json(json!({
            "ok": false,
            "airgap": true,
            "external": true,
            "blocked_by_airgap": true,
            "note": "external LLM egress is blocked under airgap — only a local model is permitted",
        })));
    }
    let note = if !configured {
        "no key configured (env or sealed) — set one first"
    } else if external {
        "key configured and egress permits the external backend; it takes effect after a restart"
    } else {
        "local backend — no key required; egress permits it"
    };
    Ok(Json(json!({
        "ok": configured || !external,
        "airgap": airgap,
        "external": external,
        "key_present": configured,
        "note": note,
    })))
}