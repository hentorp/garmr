// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/setup/status` — the first-run setup read model (Cycle 3).
//!
//! An EXPLICIT, per-step view of setup completeness computed from LIVE signals
//! (config, auth registry, passkey store, sealed secrets, ingest health) — never
//! inferred from an empty event store, so a fresh airgapped install with no events
//! is not mislabelled "misconfigured". Each of the 11 steps reports a status the
//! wizard renders: `complete` / `incomplete` / `failed` / `info` / `optional`.
//! Only `required` steps that are not `complete` hold back overall completeness.
//!
//! Admin-gated: it reports secret PRESENCE + posture (which integrations are
//! wired, admin/passkey counts) — the same admin-only dimension `/api/secrets`
//! withholds — so it must not be readable by a non-admin principal. On first run
//! the operator holds the bootstrap admin token (`GARMR_ADMIN_TOKEN`) or an admin
//! passkey, so the wizard is still reachable.

use std::path::Path;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};

use super::{ApiResult, ApiState};

/// One setup step as the wizard renders it.
fn step(
    id: &str,
    title: &str,
    required: bool,
    status: &str,
    detail: String,
    extra: Value,
) -> Value {
    let mut v = json!({
        "id": id,
        "title": title,
        "required": required,
        "status": status,
        "detail": detail,
    });
    if let (Value::Object(map), Value::Object(ex)) = (&mut v, extra) {
        map.extend(ex);
    }
    v
}

/// A non-intrusive writability probe: create + remove a uniquely-named dotfile in
/// `dir` (pid + a per-call counter, so concurrent status polls never share a path).
fn writable(dir: &Path) -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let probe = dir.join(format!(
        ".garmr-setup-probe-{}-{}",
        std::process::id(),
        CTR.fetch_add(1, Ordering::Relaxed)
    ));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Count regular files directly under `dir` (0 if the dir is absent).
fn count_files(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|rd| rd.flatten().filter(|e| e.path().is_file()).count())
        .unwrap_or(0)
}

fn backend_str(b: garmr_core::LlmBackend) -> &'static str {
    match b {
        garmr_core::LlmBackend::Anthropic => "anthropic",
        garmr_core::LlmBackend::OpenAiCompat => "open_ai_compat",
    }
}

/// Distinct event sources seen in the last 24h — captures EVERY ingest path
/// (native/seq, Flight, Loki-compat), unlike the seq-tracked collector table. A
/// bounded count; `0` on any query error (data-sources is never a hard failure).
async fn active_source_count(st: &ApiState) -> usize {
    use skade::arrow_array::{Array, Int64Array};
    let sql = "SELECT count(distinct source) AS n FROM events \
               WHERE event_ts >= now() - INTERVAL '24 hours'"
        .to_string();
    let Ok(batches) = st.store.events.sql(sql).await else {
        return 0;
    };
    for b in &batches {
        if let Some(col) = b.column(0).as_any().downcast_ref::<Int64Array>() {
            if !col.is_empty() && !col.is_null(0) {
                return col.value(0).max(0) as usize;
            }
        }
    }
    0
}

pub(super) async fn setup_status(State(st): State<ApiState>, headers: HeaderMap) -> ApiResult {
    super::auth::check_admin(&st, &headers)?;
    let airgap = garmr_core::egress::global().is_airgap();
    let sealed = st
        .cfg
        .store
        .state_db
        .parent()
        .and_then(crate::secrets::SealedSecretStore::from_env);
    let secret_set = |name: &str| {
        crate::secrets::source_of(name, sealed.as_ref()) != crate::secrets::SecretSource::Unset
    };

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

    let mut steps: Vec<Value> = Vec::new();

    // 1. Deployment mode — derived, always determined (informational).
    let mode = if airgap {
        "airgapped"
    } else if external {
        "hybrid (external LLM)"
    } else {
        "local"
    };
    let security_impact = if airgap {
        "all external egress is blocked"
    } else if external {
        "the triage LLM egresses off-box — classify data sent to it accordingly"
    } else {
        "no external egress from the LLM plane"
    };
    steps.push(step(
        "deployment_mode",
        "Deployment mode",
        false,
        "info",
        format!(
            "{mode} — airgap {}, LLM backend {}",
            if airgap { "on" } else { "off" },
            if external { "external" } else { "local" }
        ),
        json!({ "mode": mode, "airgap": airgap, "security_impact": security_impact }),
    ));

    // 2. Storage — paths present + the state dir writable.
    let wh_ok = st.cfg.store.warehouse_dir.is_dir();
    let se_ok = st.cfg.store.search_dir.is_dir();
    let state_ok = st
        .cfg
        .store
        .state_db
        .parent()
        .map(|d| d.is_dir() && writable(d))
        .unwrap_or(false);
    let storage_ok = wh_ok && se_ok && state_ok;
    steps.push(step(
        "storage",
        "Storage",
        true,
        if storage_ok { "complete" } else { "failed" },
        if storage_ok {
            "warehouse, state DB and search index are present; the state dir is writable".into()
        } else {
            let mut miss = Vec::new();
            if !wh_ok {
                miss.push("warehouse");
            }
            if !state_ok {
                miss.push("state-db (or not writable)");
            }
            if !se_ok {
                miss.push("search");
            }
            format!("missing/unusable: {}", miss.join(", "))
        },
        json!({}),
    ));

    // 3. Admin bootstrap — an Admin env token OR an Admin passkey.
    let admin_pk = super::passkey::admin_passkey_count(&st.store);
    let admin_present = st.auth.has_role(garmr_core::Role::Admin) || admin_pk >= 1;
    steps.push(step(
        "admin",
        "Admin bootstrap",
        true,
        if admin_present {
            "complete"
        } else {
            "incomplete"
        },
        if admin_present {
            "an Admin principal is configured".into()
        } else {
            "no Admin principal — set GARMR_ADMIN_TOKEN or register an Admin passkey".into()
        },
        json!({}),
    ));

    // 4. Passkey registration — ideally >= 2 admin passkeys (so one loss isn't a lockout).
    let webauthn_on = st.webauthn.is_some();
    let (pk_status, pk_detail) = if !webauthn_on {
        (
            "incomplete",
            "passkeys are not enabled (set GARMR_WEBAUTHN_RP_ID)".to_string(),
        )
    } else if admin_pk >= 2 {
        ("complete", format!("{admin_pk} admin passkeys registered"))
    } else if admin_pk == 1 {
        (
            "incomplete",
            "1 admin passkey — register a 2nd so a lost key isn't a lockout".to_string(),
        )
    } else {
        ("incomplete", "no admin passkeys registered yet".to_string())
    };
    steps.push(step(
        "passkeys",
        "Passkey registration",
        true,
        pk_status,
        pk_detail,
        json!({ "admin_passkeys": admin_pk }),
    ));

    // 5. Recovery — CLI-only local break-glass. It needs no per-install setup
    // (it's a property of having host access + the binary), so it is inherently
    // available; nudge the operator to verify it once.
    steps.push(step(
        "recovery",
        "Recovery setup",
        true,
        "complete",
        "local break-glass available: run `garmr recover issue-admin` on the host (serve stopped) to mint a short-lived emergency admin (recorded to the audit ledger when it is enabled) — verify it once".into(),
        json!({ "kind": "cli-local" }),
    ));

    // 6. LLM configuration — the backend's key is present (local backends may need none).
    let key_secret = match backend {
        garmr_core::LlmBackend::Anthropic => "ANTHROPIC_API_KEY",
        garmr_core::LlmBackend::OpenAiCompat => "GARMR_OPENAI_API_KEY",
    };
    let key_present = secret_set(key_secret);
    let llm_ok = key_present || !external;
    steps.push(step(
        "llm",
        "LLM configuration",
        false,
        if llm_ok { "complete" } else { "incomplete" },
        if llm_ok {
            format!(
                "backend {}{}",
                backend_str(backend),
                if key_present {
                    " with a key set"
                } else {
                    " (local — no key required)"
                }
            )
        } else {
            format!(
                "{key_secret} is not set for the {} backend",
                backend_str(backend)
            )
        },
        json!({}),
    ));

    // 7. LLM reachability — airgap-aware egress-permits proxy (not a live model call).
    let (reach_status, reach_detail) = if !external {
        (
            "complete",
            "local backend — no external egress needed".to_string(),
        )
    } else if airgap {
        (
            "failed",
            "external LLM egress is blocked under airgap — switch to a local backend".to_string(),
        )
    } else if !key_present {
        (
            "incomplete",
            "no key set to reach the external backend".to_string(),
        )
    } else {
        ("info", "key set and egress permits the backend — use the LLM test in System → Access to confirm".to_string())
    };
    steps.push(step(
        "llm_reachable",
        "LLM reachability",
        false,
        reach_status,
        reach_detail,
        json!({}),
    ));

    // 8. Data sources — distinct sources seen recently (any ingest path). Empty is
    // INFO, never a failure (a fresh install legitimately has no data yet — the
    // explicit-state invariant: don't infer "misconfigured" from an empty store).
    let sources = active_source_count(&st).await;
    let seq_collectors = st
        .store
        .state
        .ingest_seq_health()
        .map(|h| h.len())
        .unwrap_or(0);
    steps.push(step(
        "data_sources",
        "Data sources",
        false,
        if sources > 0 { "complete" } else { "info" },
        if sources > 0 {
            format!("{sources} source(s) active in the last 24h ({seq_collectors} seq-tracked collector(s))")
        } else {
            "no sources active yet — point one at /ingest/v1/events, or import offline".into()
        },
        json!({ "sources_24h": sources, "seq_collectors": seq_collectors }),
    ));

    // 9. Detection & audit — the ledger on + at least one rule/correlation.
    let audit_on = st.audit.is_some();
    let app_audit_on = st.app_audit.is_some();
    let rules_n = count_files(&st.cfg.detect.rules_dir);
    let corr_n = count_files(&st.cfg.detect.correlations_dir);
    let det_ok = audit_on && (rules_n + corr_n) > 0;
    steps.push(step(
        "detection",
        "Detection & audit",
        true,
        if det_ok { "complete" } else { "incomplete" },
        format!(
            "audit ledger {}, app-audit {}, {rules_n} rule + {corr_n} correlation file(s)",
            if audit_on { "on" } else { "OFF" },
            if app_audit_on { "on" } else { "off" }
        ),
        json!({}),
    ));

    // 10. Notifications — optional, airgap-aware.
    let matrix_on = st.cfg.matrix.is_some() && secret_set("GARMR_MATRIX_TOKEN");
    let webhook_on = secret_set("GARMR_WEBHOOK_URL");
    let smtp_on = secret_set("GARMR_SMTP_PASSWORD");
    let any_notify = matrix_on || webhook_on || smtp_on;
    steps.push(step(
        "notifications",
        "Notifications",
        false,
        if any_notify { "complete" } else { "optional" },
        if any_notify {
            let mut ch = Vec::new();
            if matrix_on {
                ch.push("matrix");
            }
            if webhook_on {
                ch.push("webhook");
            }
            if smtp_on {
                ch.push("smtp");
            }
            format!("configured: {}", ch.join(", "))
        } else if airgap {
            "none — outbound notifications are blocked under airgap anyway".into()
        } else {
            "none configured (optional)".into()
        },
        json!({}),
    ));

    // 11. End-to-end self-test — CLI-only (offline, opens the store writable), so
    // it cannot run inside the read-only daemon; surface it honestly.
    steps.push(step(
        "selftest",
        "End-to-end self-test",
        false,
        "info",
        "run `garmr selftest` from the CLI for an end-to-end check (offline; not runnable from the live daemon)".into(),
        json!({}),
    ));

    let required_incomplete: Vec<String> = steps
        .iter()
        .filter(|s| s["required"] == json!(true) && s["status"] != json!("complete"))
        .filter_map(|s| s["id"].as_str().map(str::to_string))
        .collect();
    let complete = required_incomplete.is_empty();

    Ok(Json(json!({
        "steps": steps,
        "complete": complete,
        "required_incomplete": required_incomplete,
        "mode": mode,
        "airgap": airgap,
    })))
}
