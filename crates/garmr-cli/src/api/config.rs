// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/config/{schema,effective,status}` — the read-only configuration
//! surface (Cycle 1 of the WebUI-configurable-product work).
//!
//! garmr's config is Figment (compiled defaults → TOML → `GARMR_` env) read once
//! at startup; there was no way to see, from the console, WHAT is configured,
//! where a value came from, whether changing it needs a restart, or whether an
//! environment variable is silently overriding the file. These three endpoints
//! are that read-model — the honest inventory a Configuration Center renders. They
//! are strictly READ-ONLY (write/apply/rollback is a later cycle):
//!
//! - `schema` — typed, hand-curated metadata for the key settings: label,
//!   description, reload class, restart/airgap impact, the env var that overrides
//!   it, and whether it is a secret.
//! - `effective` — the live, post-Figment values (so any env override is already
//!   reflected) joined to the schema, with each field's source and an env-override
//!   flag. **Secret values are never included** — only whether one is configured.
//! - `status` — configuration diagnostics, classified by severity so a missing key
//!   or an unprotected bind is not one generic red error.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::credentials::require_scope;
use super::passkey::require_step_up;
use super::{bad, oops, ApiResult, ApiState};

/// How a change to a setting takes effect. This is the stable vocabulary the
/// console renders; `Hot` and `Offline` are part of it so the UI handles every
/// class from the start, but are first *emitted* in later cycles (live reload in
/// Cycle 2, offline-operation panels in Cycle 4) — hence allowed as not-yet-built.
#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum Reload {
    /// Fixed at install; changing it live is unsafe (store paths, node identity).
    Immutable,
    /// Read once at startup — a process restart applies a change.
    Restart,
    /// Live-reloadable without a restart.
    Hot,
    /// Governed artifact: draft → validate → approve → promote hot-swaps it.
    Governed,
    /// Offline maintenance operation (the daemon/writer must be stopped).
    Offline,
}

/// The value's shape, so the UI can render/validate it appropriately.
#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Kind {
    String,
    Int,
    Float,
    Bool,
    Path,
    Enum,
    List,
    Secret,
}

/// One configurable setting's metadata (no value — see `effective`).
#[derive(Serialize)]
struct ConfigField {
    key: &'static str,
    section: &'static str,
    label: &'static str,
    description: &'static str,
    kind: Kind,
    secret: bool,
    /// Whether a future Configuration Center write path is expected to edit this
    /// (Cycle 2+); false today for everything (this surface is read-only).
    editable: bool,
    /// Role required to change it once writes land.
    required_role: &'static str,
    reload: Reload,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart_impact: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    airgap_impact: Option<&'static str>,
    /// The environment variable that overrides this setting, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    env_var: Option<&'static str>,
}

impl ConfigField {
    fn new(
        key: &'static str,
        section: &'static str,
        label: &'static str,
        kind: Kind,
        reload: Reload,
        description: &'static str,
    ) -> Self {
        Self {
            key,
            section,
            label,
            description,
            kind,
            secret: matches!(kind, Kind::Secret),
            editable: false,
            required_role: "admin",
            reload,
            restart_impact: None,
            airgap_impact: None,
            env_var: None,
        }
    }
    fn env(mut self, v: &'static str) -> Self {
        self.env_var = Some(v);
        self
    }
    /// Mark this field editable from the console. The config-write path is
    /// DENY-BY-DEFAULT: an override may set ONLY fields flagged here. Everything
    /// else — unknown keys, capability/identity/path/egress/secret fields — is
    /// refused, so a new dangerous leaf is never silently editable.
    fn editable(mut self) -> Self {
        self.editable = true;
        self
    }
    fn restart_note(mut self, s: &'static str) -> Self {
        self.restart_impact = Some(s);
        self
    }
    fn airgap(mut self, s: &'static str) -> Self {
        self.airgap_impact = Some(s);
        self
    }
}

/// The curated section order for the UI.
const SECTIONS: &[&str] = &[
    "General",
    "Storage",
    "Network",
    "LLM & AI",
    "Detection",
    "Retention",
    "High availability",
    "Notifications",
    "Audit ledger",
    "Airgap & egress",
];

/// The hand-authored field catalog. Not exhaustive over every `Config` leaf —
/// `effective` serializes the whole live config so nothing is hidden — but it
/// carries rich metadata for the settings an operator actually reasons about.
fn schema() -> Vec<ConfigField> {
    use Kind::*;
    use Reload::*;
    vec![
        // General
        // Immutable install-time identity: node_id is stamped into every audit
        // record + HA snapshot, so it must not move from a running instance.
        ConfigField::new("audit.node_id", "General", "Node ID", String, Immutable,
            "Identity stamped into audit records and HA snapshots.")
            .env("GARMR_AUDIT__NODE_ID"),
        // Storage
        ConfigField::new("store.warehouse_dir", "Storage", "Warehouse directory", Path, Immutable,
            "Durable lakehouse (Iceberg/Parquet) root — the source of truth. Iceberg bakes absolute paths; moving it is unsafe."),
        ConfigField::new("store.state_db", "Storage", "State database", Path, Immutable,
            "redb state DB (cases, baselines, auth). Single-writer; changing it live is unsafe."),
        ConfigField::new("store.search_dir", "Storage", "Search index directory", Path, Immutable,
            "Tantivy full-text index. Rebuildable from the warehouse with `garmr reindex`."),
        ConfigField::new("store.retention_days", "Storage", "Hot retention (days)", Int, Restart,
            "How long events stay in the hot table before retention ages them to the cold tier.")
            .editable(),
        // Network
        ConfigField::new("ingest.api_bind", "Network", "Query/console bind", String, Restart,
            "Address the read/console API listens on. A non-loopback bind requires an API token.")
            .restart_note("rebinds the API listener")
            .env("GARMR_INGEST__API_BIND"),
        ConfigField::new("ingest.ingest_bind", "Network", "Native ingest bind", String, Restart,
            "Address the native /ingest/v1/events receiver listens on.")
            .restart_note("rebinds the ingest listener"),
        ConfigField::new("ingest.flight_bind", "Network", "Arrow-Flight bind", String, Restart,
            "Columnar Flight ingest listener (only active in a build with the `flight` feature)."),
        ConfigField::new("ingest.ui_dir", "Network", "Web console directory", Path, Restart,
            "Directory the Leptos console + /map/ are served from. GARMR_UI_DIR overrides it.")
            .env("GARMR_UI_DIR"),
        ConfigField::new("GARMR_COLLECTOR_TOKEN", "Network", "Collector ingest token", Secret, Restart,
            "Bearer token collectors present to the native /ingest/v1/events receiver. Managed via the sealed store; never shown here.")
            .env("GARMR_COLLECTOR_TOKEN"),
        // LLM & AI
        ConfigField::new("agent.backend", "LLM & AI", "LLM backend", Enum, Restart,
            "anthropic (external) or open_ai_compat (local/hosted).")
            .airgap("an external backend is refused under airgap; a local model still works"),
        ConfigField::new("agent.model", "LLM & AI", "Model", String, Restart,
            "Model for the triage loop (e.g. claude-opus-4-8 or an Ollama tag).")
            .editable(),
        ConfigField::new("agent.openai_base_url", "LLM & AI", "OpenAI-compatible base URL", String, Restart,
            "Base URL for the OpenAI-compatible endpoint (Ollama/llama.cpp/vLLM)."),
        ConfigField::new("agent.daily_budget_usd", "LLM & AI", "Daily budget (USD)", Float, Restart,
            "Spend ceiling per day; new cases queue as NeedsHuman past it.")
            .editable(),
        ConfigField::new("agent.prefilter_model", "LLM & AI", "Prefilter model", String, Restart,
            "Cheaper model for the triage prefilter pass (empty = use the main model).")
            .editable(),
        ConfigField::new("agent.max_tokens", "LLM & AI", "Max tokens", Int, Restart,
            "Maximum tokens per model response.")
            .editable(),
        ConfigField::new("agent.max_iterations", "LLM & AI", "Max agent iterations", Int, Restart,
            "Maximum tool-use iterations the triage agent runs per case.")
            .editable(),
        ConfigField::new("agent.mcp_servers", "LLM & AI", "MCP tool servers", List, Restart,
            "External MCP tool servers the agent may call; their env can carry secrets, so this is set in the base TOML only, never from the console."),
        ConfigField::new("GARMR_EMBED_MODEL", "LLM & AI", "Embedding model", String, Restart,
            "Sentence-embedding model for semantic search (env; empty disables semantic).")
            .env("GARMR_EMBED_MODEL"),
        ConfigField::new("agent.allow_online_lookups", "LLM & AI", "Allow online lookups", Bool, Restart,
            "Online IP-reputation lookups. Forced off under airgap.")
            .airgap("forced off"),
        ConfigField::new("GARMR_LLM_CONNECT_TIMEOUT_SECS", "LLM & AI", "LLM connect timeout (s)", Int, Restart,
            "Connect timeout for the LLM HTTP client (default 10).")
            .env("GARMR_LLM_CONNECT_TIMEOUT_SECS"),
        ConfigField::new("GARMR_LLM_REQUEST_TIMEOUT_SECS", "LLM & AI", "LLM request timeout (s)", Int, Restart,
            "Total request timeout (connect + send + read) for a model call (default 120).")
            .env("GARMR_LLM_REQUEST_TIMEOUT_SECS"),
        ConfigField::new("GARMR_LLM_MAX_RETRIES", "LLM & AI", "LLM max retries", Int, Restart,
            "Retries for a safe transient LLM failure (429/5xx/timeout); auth errors never retry (default 2).")
            .env("GARMR_LLM_MAX_RETRIES"),
        ConfigField::new("ANTHROPIC_API_KEY", "LLM & AI", "Anthropic API key", Secret, Restart,
            "Secret for the Anthropic backend. Set out of band; never shown here.")
            .env("ANTHROPIC_API_KEY"),
        ConfigField::new("GARMR_OPENAI_API_KEY", "LLM & AI", "OpenAI-compatible API key", Secret, Restart,
            "Optional secret for an authenticated OpenAI-compatible endpoint.")
            .env("GARMR_OPENAI_API_KEY"),
        // Detection
        ConfigField::new("detect.app_audit_enabled", "Detection", "Application-audit plane", Bool, Restart,
            "Enables behavioral baselines, users/applications/resources, and insider-risk fusion.")
            .editable(),
        ConfigField::new("detect.anomaly_enabled", "Detection", "Statistical anomaly detectors", Bool, Restart,
            "Volume/rate anomaly detectors over the event stream.")
            .editable(),
        ConfigField::new("detect.risk_enabled", "Detection", "Risk-based alerting (RBA)", Bool, Restart,
            "Per-host risk scoring that escalates once the threshold is crossed.")
            .editable(),
        ConfigField::new("detect.risk_threshold", "Detection", "Risk escalation threshold", Float, Restart,
            "Host risk score at which an RBA alert fires.")
            .editable(),
        ConfigField::new("detect.policies_dir", "Detection", "Access-policy directory", Path, Governed,
            "Access policies. Authored as files or promoted through the governed registry (hot-swaps).")
            .env("GARMR_REGISTRY_POLICIES"),
        ConfigField::new("detect.catalog_file", "Detection", "Resource catalog", Path, Governed,
            "Resource catalog. File or governed registry (hot-swaps on production-channel promotion).")
            .env("GARMR_REGISTRY_CATALOG"),
        ConfigField::new("detect.monitoring_file", "Detection", "User-monitoring config", Path, Governed,
            "User-monitoring policy. File or governed registry (hot-swaps).")
            .env("GARMR_REGISTRY_MONITORING"),
        // Retention
        ConfigField::new("retention.enabled", "Retention", "Cold tier enabled", Bool, Restart,
            "Whether retention seals aged data into the compressed cold archive.")
            .editable(),
        ConfigField::new("retention.window_days", "Retention", "Cold window (days)", Int, Restart,
            "Age at which hot data is sealed to the cold tier.")
            .editable(),
        // HA
        ConfigField::new("ha.role", "High availability", "HA role", Enum, Restart,
            "leader (writer) or follower (read-only). A restored node stays a follower until promoted."),
        // Notifications
        ConfigField::new("matrix.homeserver", "Notifications", "Matrix homeserver", String, Restart,
            "Matrix homeserver base URL for alert routing."),
        ConfigField::new("GARMR_MATRIX_TOKEN", "Notifications", "Matrix access token", Secret, Restart,
            "Secret access token; gates Matrix notifications entirely.")
            .env("GARMR_MATRIX_TOKEN"),
        ConfigField::new("GARMR_WEBHOOK_URL", "Notifications", "Webhook URL", Secret, Restart,
            "Webhook target (may embed a token — treated as a secret).")
            .env("GARMR_WEBHOOK_URL").airgap("outbound notifications are refused under airgap"),
        ConfigField::new("GARMR_SMTP_HOST", "Notifications", "SMTP host", String, Restart,
            "SMTP relay host for email alerts.")
            .env("GARMR_SMTP_HOST"),
        // Audit ledger
        ConfigField::new("audit.enabled", "Audit ledger", "Audit ledger enabled", Bool, Restart,
            "Tamper-evident hash-chained ledger of protected operations. Off means admin actions are not recorded."),
        ConfigField::new("audit.per_record_sign", "Audit ledger", "Per-record signing", Bool, Restart,
            "ed25519-sign every record (vs only checkpoints)."),
        // Airgap & egress
        ConfigField::new("GARMR_AIRGAP", "Airgap & egress", "Airgap mode", Bool, Restart,
            "Hard security override: blocks ALL external egress (LLM/feeds/webhooks/SMTP/S3/MCP). Cannot be overridden by the UI.")
            .env("GARMR_AIRGAP").airgap("this IS the airgap switch"),
        ConfigField::new("route.egress.allow", "Airgap & egress", "Egress allowlist", List, Restart,
            "Explicit allowlist of external destination classes permitted when not airgapped.")
            .airgap("ignored under airgap — all external egress is denied"),
        ConfigField::new("executor.enabled", "Detection", "Response executor", Bool, Restart,
            "The SOAR executor loop that acts on approved response actions (propose/approve always work)."),
        // Capability + safety fields — VISIBLE for transparency but never console-
        // editable (Immutable): the argv templates are a host capability and
        // never_block is the guardrail below the human. Base-TOML only.
        ConfigField::new("executor.block_ip", "Detection", "block_ip action template", List, Immutable,
            "argv template garmr runs to block an IP — a host capability. Set ONLY in the base TOML, never from the console."),
        ConfigField::new("executor.isolate_host", "Detection", "isolate_host action template", List, Immutable,
            "argv template garmr runs to isolate a host. Base-TOML only."),
        ConfigField::new("executor.never_block", "Detection", "never-block guardrail", List, Immutable,
            "Addresses that must NEVER be blocked (management IP, gateway, resolvers) — the guardrail below the human. Base-TOML only."),
    ]
}

/// `GET /api/config/schema` — typed metadata for the curated settings.
pub(super) async fn config_schema(State(_st): State<ApiState>) -> ApiResult {
    Ok(axum::Json(json!({
        "sections": SECTIONS,
        "fields": schema(),
    })))
}

/// Walk a dotted path (`agent.model`) into a serialized-config value.
fn dig(v: &Value, path: &str) -> Option<Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur.clone())
}

/// `GET /api/config/effective` — the live values joined to the schema, with each
/// field's source. Secret values are never emitted (only `configured`).
pub(super) async fn config_effective(State(st): State<ApiState>, headers: HeaderMap) -> ApiResult {
    // Admin-gated: it emits effective config values (executor argv templates,
    // binds, etc.) — the same value dimension /api/secrets + /api/config/revisions
    // withhold from non-admins.
    super::auth::check_admin(&st, &headers)?;
    // `st.cfg` is already the post-Figment merge, so any GARMR_ env override is
    // reflected in the value; the env var's PRESENCE tells us the source.
    let raw = serde_json::to_value(&st.cfg).map_err(super::oops)?;
    let airgap = garmr_core::egress::global().is_airgap();

    let fields: Vec<Value> = schema()
        .iter()
        .map(|f| {
            let env_present = f.env_var.is_some_and(|v| std::env::var(v).is_ok());
            if f.secret {
                // Never surface a secret value — only whether one is configured.
                return json!({
                    "key": f.key,
                    "configured": env_present,
                    "source": if env_present { "env" } else { "unset" },
                });
            }
            // Effective value: the special airgap switch reports the resolved
            // policy state; everything else digs the serialized config, falling
            // back to the raw env string for purely-environment settings.
            let value = if f.key == "GARMR_AIRGAP" {
                json!(airgap)
            } else if let Some(v) = dig(&raw, f.key) {
                v
            } else {
                f.env_var
                    .and_then(|v| std::env::var(v).ok())
                    .map(Value::String)
                    .unwrap_or(Value::Null)
            };
            let in_config = dig(&raw, f.key).is_some();
            let source = if env_present {
                "env"
            } else if in_config {
                "file_or_default"
            } else {
                "unset"
            };
            json!({
                "key": f.key,
                "value": value,
                "source": source,
                // Both a file/default value AND an env var present → the env wins;
                // the UI shows "configured in file but overridden by environment".
                "overridden_by_env": env_present && in_config,
            })
        })
        .collect();

    Ok(axum::Json(json!({
        "airgap": airgap,
        "read_only": st.read_only,
        "fields": fields,
    })))
}

/// A configuration diagnostic, classified so the console never shows one generic
/// red error.
fn diag(severity: &str, code: &str, title: &str, detail: String) -> Value {
    json!({ "severity": severity, "code": code, "title": title, "detail": detail })
}

/// `GET /api/config/status` — configuration health, classified by severity.
pub(super) async fn config_status(State(st): State<ApiState>) -> ApiResult {
    let airgap = garmr_core::egress::global().is_airgap();
    let mut out: Vec<Value> = Vec::new();

    // Security-critical: a non-loopback API bind with no auth token is an open door.
    if let Some(bind) = st.cfg.ingest.api_bind.as_deref() {
        let loopback = bind.starts_with("127.")
            || bind.starts_with("localhost")
            || bind.starts_with("[::1]");
        if !loopback && st.auth.is_empty() {
            out.push(diag("security_critical", "open_api_bind", "API bound to a non-loopback address without a token",
                format!("api_bind = {bind} is reachable off-box but no API token is set — set GARMR_API_TOKEN.")));
        }
    }

    // Operational: the configured LLM backend needs a key that is missing.
    if matches!(st.cfg.agent.backend, garmr_core::LlmBackend::Anthropic)
        && std::env::var("ANTHROPIC_API_KEY").is_err()
    {
        out.push(diag("operational", "missing_llm_key", "Anthropic backend selected but ANTHROPIC_API_KEY is unset",
            "Triage/ask/hunt will fail to build a provider. Set the key or switch to a local backend.".into()));
    }

    // Recommendation: the tamper-evident ledger is off.
    if st.audit.is_none() {
        out.push(diag("recommendation", "audit_disabled", "Audit ledger disabled",
            "Protected admin actions are not tamper-evidently recorded (audit.enabled = false).".into()));
    }

    // Degraded: executor enabled but nothing to act (mirrors the capability report).
    if st.cfg.executor.enabled && !st.read_only {
        // Enabled is fine; note only that acting still requires an approved action.
    }

    // Info: airgap posture and follower state are always worth surfacing.
    if airgap {
        out.push(diag("info", "airgap_on", "Airgap mode is active",
            "All external egress (LLM/feeds/webhooks/SMTP/S3/MCP) is blocked; only local models are permitted.".into()));
    }
    if st.read_only {
        out.push(diag("info", "read_only_follower", "This node is a read-only HA follower",
            "Writes, LLM, and the admin surface are unmounted until it is promoted to writer.".into()));
    }
    if st.app_audit.is_none() {
        out.push(diag("info", "app_audit_off", "Application-audit plane disabled",
            "Behavioral baselines / users / applications / insider-risk are off (detect.app_audit_enabled = false).".into()));
    }

    // Operational: a config apply/rollback is persisted but not yet loaded.
    let restart_pending = crate::config_store::restart_pending();
    if restart_pending {
        out.push(diag("operational", "restart_pending", "Configuration changes await a restart",
            "Applied config changes are saved but not yet loaded. Restart garmr (systemctl restart garmr) to apply them.".into()));
    }

    Ok(axum::Json(json!({ "diagnostics": out, "restart_pending": restart_pending })))
}

/// `GET /api/config/offline-ops` — an HONEST panel for offline-only maintenance
/// operations (compaction / reindex / restore / promote). It explains why each is
/// offline, the exact command to run on the host, prerequisites, and the cheap
/// status that is knowable — but it NEVER runs anything (these need `serve`
/// stopped / host access), so nothing here can imply an operation happened.
pub(super) async fn offline_ops(State(st): State<ApiState>, headers: HeaderMap) -> ApiResult {
    super::auth::check_admin(&st, &headers)?;
    let restore_pending = garmr_store::restored_marker_path(&st.cfg.store.state_db).exists();
    let restore_status = if restore_pending {
        "this node is restored and NOT promoted — promotion is pending"
    } else {
        "available (replaces the store from a bundle)"
    };
    let promote_status = if restore_pending {
        "promotion PENDING — this restored node is write-fenced until promoted"
    } else {
        "not applicable — this node is not a restored, unpromoted follower"
    };
    let ops = json!([
        {
            "id": "compact", "title": "Compact the lakehouse",
            "command": "garmr compact",
            "why_offline": "the lakehouse + state store are single-writer — stop `garmr serve` first",
            "prerequisites": ["stop garmr serve"],
            "status": "available",
        },
        {
            "id": "reindex", "title": "Rebuild the search index",
            "command": "garmr reindex",
            "why_offline": "rebuilds the Tantivy index over the single-writer store",
            "prerequisites": ["stop garmr serve", "the `semantic` feature + GARMR_EMBED_MODEL for the semantic index"],
            "status": "available",
        },
        {
            "id": "restore", "title": "Restore from a backup",
            "command": "garmr backup restore <backup-file>",
            "why_offline": "replaces the store from a bundle — the node comes back write-fenced until promoted",
            "prerequisites": ["stop garmr serve", "a backup bundle"],
            "status": restore_status,
        },
        {
            "id": "promote", "title": "Promote a restored node to writer",
            "command": "garmr backup promote",
            "why_offline": "clears the restored-follower fence and resumes writes",
            "prerequisites": ["a restored, unpromoted node"],
            "status": promote_status,
        }
    ]);
    Ok(axum::Json(json!({
        "operations": ops,
        "writer": !st.read_only,
        "restore_pending": restore_pending,
    })))
}

// ---------------------------------------------------------------------------
// Config-write validate / diff / restart-impact (Cycle 2).
//
// A proposed change is the FULL override document (not a delta). Validation is a
// pure dry-run that is DENY-BY-DEFAULT: it builds the Config the override would
// produce (type-check), then refuses the override unless EVERY key it sets is an
// explicitly-editable field. Unknown keys, capability fields (executor argv
// templates + never_block), identity/path fields, egress/airgap, audit-ledger
// location/key, and secret-bearing leaves are all refused because they are not on
// the allow-list — a new dangerous leaf is never silently editable. The refusal
// is enforced on the override BODY itself, so a currently-shadowing env var cannot
// hide an immutable edit. Nothing is persisted here — that is `apply`.
// ---------------------------------------------------------------------------

/// The reload class declared for a config key, or `Restart` for any leaf not in
/// the curated schema (unknown ⇒ assume a restart is needed — the safe default).
fn reload_of(key: &str) -> Reload {
    schema()
        .into_iter()
        .find(|f| f.key == key)
        .map(|f| f.reload)
        .unwrap_or(Reload::Restart)
}

fn reload_str(r: Reload) -> &'static str {
    match r {
        Reload::Immutable => "immutable",
        Reload::Restart => "restart",
        Reload::Hot => "hot",
        Reload::Governed => "governed",
        Reload::Offline => "offline",
    }
}

/// The env var that overrides a config key, if the schema names one.
fn env_var_of(key: &str) -> Option<&'static str> {
    schema().into_iter().find(|f| f.key == key).and_then(|f| f.env_var)
}

/// The `GARMR_` env var figment reads for a config key, per its
/// `GARMR_<SECTION>__<KEY>` convention (dots → `__`, upper-cased). This is what
/// actually shadows a value — independent of whether the schema declared a special
/// `.env()` — so the env-shadow warning can't be silently dead.
fn figment_env_var(key: &str) -> String {
    format!("GARMR_{}", key.replace('.', "__").to_uppercase())
}

/// The env var currently shadowing `key`, if any: the figment-convention var or a
/// schema-declared special var (e.g. `GARMR_UI_DIR`), whichever is set.
fn shadowing_env_var(key: &str) -> Option<String> {
    std::iter::once(figment_env_var(key))
        .chain(env_var_of(key).map(str::to_string))
        .find(|v| std::env::var(v).is_ok())
}

/// The deny-by-default allow-list: the only keys a console-generated override may
/// set. Everything else is refused (see the module comment). Derived from the
/// schema fields flagged `editable`.
fn editable_keys() -> std::collections::BTreeSet<&'static str> {
    schema().into_iter().filter(|f| f.editable).map(|f| f.key).collect()
}

/// The dotted leaf keys a proposed override BODY explicitly sets (env- and
/// base-independent — parsed from the body alone). Empty on a parse error (the
/// type-check via `preview_override` reports that separately).
fn override_body_keys(body: &str) -> Vec<String> {
    match toml::from_str::<Value>(body) {
        Ok(v) => {
            let mut m = std::collections::BTreeMap::new();
            flatten(&v, "", &mut m);
            m.into_keys().collect()
        }
        Err(_) => Vec::new(),
    }
}

/// Flatten a serialized config into dotted leaf keys. Recurses ONLY into objects;
/// arrays and scalars are compared as whole leaves (so `route.egress.allow` diffs
/// as one list, not per index).
fn flatten(v: &Value, prefix: &str, out: &mut std::collections::BTreeMap<String, Value>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(val, &key, out);
            }
        }
        _ => {
            out.insert(prefix.to_string(), v.clone());
        }
    }
}

/// Leaf-level diff of two serialized configs: `(key, old, new)` for every leaf
/// whose value changed (a missing side is `null`).
fn diff_configs(live: &Value, proposed: &Value) -> Vec<(String, Value, Value)> {
    let mut l = std::collections::BTreeMap::new();
    flatten(live, "", &mut l);
    let mut p = std::collections::BTreeMap::new();
    flatten(proposed, "", &mut p);
    let keys: std::collections::BTreeSet<&String> = l.keys().chain(p.keys()).collect();
    let mut changes = Vec::new();
    for k in keys {
        let ov = l.get(k).cloned().unwrap_or(Value::Null);
        let nv = p.get(k).cloned().unwrap_or(Value::Null);
        if ov != nv {
            changes.push((k.clone(), ov, nv));
        }
    }
    changes
}

/// Validate a proposed override, DENY-BY-DEFAULT. `baseline` is the serialized
/// config a restart-right-now would produce (base + the CURRENTLY-PERSISTED
/// override + env) so a same-session second apply diffs against real state, not
/// the frozen startup snapshot. Returns the JSON the write handlers surface.
fn validate_override(base_path: &std::path::Path, proposed_body: &str, baseline: &Value) -> Value {
    // 1. Parse + type-check into a Config.
    let proposed_cfg = match garmr_core::Config::preview_override(base_path, proposed_body) {
        Ok(c) => c,
        Err(e) => {
            return json!({
                "valid": false,
                "error": format!("invalid configuration: {e}"),
                "changes": [],
                "restart_required": false,
                "warnings": [],
            });
        }
    };

    // 2. DENY-BY-DEFAULT on the override BODY (env-independent): every key it sets
    // must be editable. This refuses capability / identity / path / egress / audit
    // / secret / unknown keys even if an env var currently masks them in the diff.
    let editable = editable_keys();
    let body_keys = override_body_keys(proposed_body);
    let mut refused: Vec<String> = body_keys
        .iter()
        .filter(|k| !editable.contains(k.as_str()))
        .cloned()
        .collect();
    refused.sort();
    refused.dedup();
    if !refused.is_empty() {
        return json!({
            "valid": false,
            "error": format!("these settings cannot be changed from the console: {}", refused.join(", ")),
            "changes": [],
            "restart_required": false,
            "warnings": [],
        });
    }

    // Domain validation for the editable numeric fields — mirror the serve.rs
    // startup checks so the console never green-lights a value that would fail to
    // boot (a non-positive risk_threshold with RBA on) or silently disable the
    // agent at runtime (max_tokens / max_iterations = 0).
    let mut domain: Vec<String> = Vec::new();
    if proposed_cfg.detect.risk_enabled
        && !(proposed_cfg.detect.risk_threshold.is_finite() && proposed_cfg.detect.risk_threshold > 0.0)
    {
        domain.push("detect.risk_threshold must be finite and > 0 when risk-based alerting is enabled".into());
    }
    if proposed_cfg.agent.max_tokens < 1 {
        domain.push("agent.max_tokens must be at least 1".into());
    }
    if proposed_cfg.agent.max_iterations < 1 {
        domain.push("agent.max_iterations must be at least 1".into());
    }
    if !domain.is_empty() {
        return json!({
            "valid": false,
            "error": domain.join("; "),
            "changes": [],
            "restart_required": false,
            "warnings": [],
        });
    }

    // 3. Diff proposed vs the baseline (what this apply actually changes).
    let proposed = serde_json::to_value(&proposed_cfg).unwrap_or(Value::Null);
    let changes: Vec<Value> = diff_configs(baseline, &proposed)
        .into_iter()
        .map(|(key, old, new)| {
            let reload = reload_str(reload_of(&key));
            json!({ "key": key, "old": old, "new": new, "reload": reload })
        })
        .collect();

    // 4. env-shadow warnings, decoupled from the diff: for every editable key the
    // body sets whose env var is present, figment env wins so the file value won't
    // take effect — warn even when the merged diff masks the change.
    let mut warnings: Vec<String> = Vec::new();
    for k in &body_keys {
        if let Some(v) = shadowing_env_var(k) {
            warnings.push(format!(
                "{k}: {v} is set in the environment and wins over the file — the applied value won't take effect until it is unset."
            ));
        }
    }

    // Config is read once at startup, so any accepted change needs a restart to
    // take effect (live hot-reload of the reloadable planes lands in a later cycle).
    let has_changes = !changes.is_empty();
    json!({
        "valid": true,
        "error": Value::Null,
        "changes": changes,
        "restart_required": has_changes,
        "warnings": warnings,
    })
}

/// The baseline a config diff should compare against: what a restart right now
/// would load — base TOML + the CURRENTLY-PERSISTED override + env — NOT the
/// frozen startup `st.cfg` (which never reflects a same-session apply).
fn diff_baseline(st: &ApiState) -> Result<Value, (axum::http::StatusCode, String)> {
    let base = crate::config_store::base_config_path();
    let persisted = store_for(st).active_override();
    let cfg = garmr_core::Config::preview_override(&base, &persisted).map_err(oops)?;
    serde_json::to_value(&cfg).map_err(oops)
}

// ---------------------------------------------------------------------------
// Config-write handlers. `validate` is a dry-run (Admin, read-only). `apply` and
// `rollback` are protected operations: Admin + the `config:write` scope + a
// recent user-verified passkey (step-up) + a fail-closed audit record. Applying
// persists the override the loader reads; the running process picks it up on the
// next restart (live hot-reload of the reloadable planes is a later cycle), so
// every response carries an honest `restart_required`.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct ValidateReq {
    #[serde(default)]
    override_toml: String,
}

#[derive(Deserialize)]
pub(super) struct ApplyReq {
    #[serde(default)]
    override_toml: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct RollbackReq {
    seq: u64,
}

fn store_for(st: &ApiState) -> crate::config_store::RevisionStore {
    // Prefer the loader-resolved override path (set at startup); fall back to the
    // merged-config derivation only if it was somehow never set. They agree unless
    // an out-of-band override moved state_db — which the write path forbids.
    let path = crate::config_store::override_path()
        .unwrap_or_else(|| st.cfg.config_override_path());
    crate::config_store::RevisionStore::new(path)
}

/// `POST /admin/config/validate` — dry-run a proposed override: parse/type-check,
/// diff against live, classify each change, refuse immutable edits, warn on
/// env-shadowed keys. Admin; persists nothing.
pub(super) async fn config_validate(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<ValidateReq>,
) -> ApiResult {
    super::auth::check_admin(&st, &headers)?;
    let base = crate::config_store::base_config_path();
    let baseline = diff_baseline(&st)?;
    Ok(Json(validate_override(&base, &req.override_toml, &baseline)))
}

/// `POST /admin/config/apply` — validate then persist a new revision + swap the
/// active override atomically. Admin + `config:write` + step-up + audit. Rejects
/// an invalid or immutable-touching change with 400 (call `validate` for detail).
pub(super) async fn config_apply(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<ApplyReq>,
) -> ApiResult {
    let who = super::auth::check_admin(&st, &headers)?;
    require_scope(&st, &headers, "config:write")?;
    require_step_up(&st, &headers)?;

    let base = crate::config_store::base_config_path();
    let baseline = diff_baseline(&st)?;
    let report = validate_override(&base, &req.override_toml, &baseline);
    if report["valid"] != json!(true) {
        return Err(bad(report["error"]
            .as_str()
            .unwrap_or("invalid configuration")));
    }
    // Refuse a no-op so the history isn't polluted with empty revisions. If an env
    // var is shadowing the edited keys, the "no change" is because env wins over the
    // file — say so, rather than a bare "no changes".
    if report["changes"].as_array().map(Vec::is_empty).unwrap_or(true) {
        let warns: Vec<&str> = report["warnings"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if warns.is_empty() {
            return Err(bad("no changes to apply"));
        }
        return Err(bad(format!("no effective change — {}", warns.join("; "))));
    }

    let note = req
        .note
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("apply from console");
    let now = chrono::Utc::now().timestamp();
    let rev = store_for(&st)
        .apply(req.override_toml.clone(), &who.user, note, now)
        .map_err(oops)?;
    // Fail-closed audit; only metadata is recorded (the body is on disk as a revision).
    st.record_admin(
        &who,
        garmr_audit::action::CONFIG_APPLY,
        "config",
        Some(&rev.seq.to_string()),
        Some(note),
    )?;
    Ok(Json(json!({
        "ok": true,
        "revision": { "seq": rev.seq, "hash": rev.short_hash(), "ts": rev.ts, "author": rev.author, "note": rev.note },
        "restart_required": report["restart_required"],
        "changes": report["changes"],
        "warnings": report["warnings"],
    })))
}

/// `GET /api/config/revisions` — the applied-override history (metadata only;
/// fetch a body via a specific revision if needed later). Admin.
pub(super) async fn config_revisions(State(st): State<ApiState>, headers: HeaderMap) -> ApiResult {
    super::auth::check_admin(&st, &headers)?;
    let store = store_for(&st);
    let active = store.active_override();
    let active_hash = blake3::hash(active.as_bytes()).to_hex().to_string();
    let list = store.list();
    // The live revision is the LATEST one (apply/rollback always write the override
    // to match the newest revision). Anchor `is_current` to the max seq — NOT to a
    // body-hash match, since rollback intentionally re-applies an identical body and
    // several revisions can share a hash. Also require the body to match the live
    // override, so a hand-edited override marks nothing current.
    let max_seq = list.iter().map(|r| r.seq).max();
    let revs: Vec<Value> = list
        .iter()
        .map(|r| {
            json!({
                "seq": r.seq,
                "ts": r.ts,
                "author": r.author,
                "note": r.note,
                "hash": r.short_hash(),
                "is_current": Some(r.seq) == max_seq && r.hash == active_hash,
            })
        })
        .collect();
    Ok(Json(json!({
        "revisions": revs,
        "override_active": !active.is_empty(),
    })))
}

/// `POST /admin/config/rollback {seq}` — re-apply an earlier revision's body as a
/// NEW revision (linear history). Re-validated against the CURRENT base+env first
/// (the base may have moved on). Admin + `config:write` + step-up + audit.
pub(super) async fn config_rollback(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<RollbackReq>,
) -> ApiResult {
    let who = super::auth::check_admin(&st, &headers)?;
    require_scope(&st, &headers, "config:write")?;
    require_step_up(&st, &headers)?;

    let store = store_for(&st);
    let target = store
        .get(req.seq)
        .ok_or_else(|| bad("no such config revision"))?;
    // The stored body was valid when applied, but base/env/allow-list may have
    // moved on; re-validate against the current baseline before installing it.
    let base = crate::config_store::base_config_path();
    let baseline = diff_baseline(&st)?;
    let report = validate_override(&base, &target.body, &baseline);
    if report["valid"] != json!(true) {
        return Err(bad(report["error"]
            .as_str()
            .unwrap_or("target revision is no longer valid against the current base config")));
    }
    let now = chrono::Utc::now().timestamp();
    let rev = store.rollback(req.seq, &who.user, now).map_err(oops)?;
    st.record_admin(
        &who,
        garmr_audit::action::CONFIG_ROLLBACK,
        "config",
        Some(&rev.seq.to_string()),
        Some(&rev.note),
    )?;
    Ok(Json(json!({
        "ok": true,
        "revision": { "seq": rev.seq, "hash": rev.short_hash(), "note": rev.note },
        "restart_required": report["restart_required"],
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_non_empty_and_every_section_is_declared() {
        let fields = schema();
        assert!(fields.len() >= 20);
        for f in &fields {
            assert!(
                SECTIONS.contains(&f.section),
                "field {} has undeclared section {}",
                f.key,
                f.section
            );
        }
    }

    #[test]
    fn secret_fields_are_flagged_and_paired_with_an_env_var() {
        for f in schema().iter().filter(|f| f.secret) {
            assert!(matches!(f.kind, Kind::Secret));
            assert!(
                f.env_var.is_some(),
                "secret field {} must name its env var",
                f.key
            );
        }
    }

    #[test]
    fn dig_walks_dotted_paths() {
        let v = json!({"agent": {"model": "claude", "nested": {"x": 1}}});
        assert_eq!(dig(&v, "agent.model"), Some(json!("claude")));
        assert_eq!(dig(&v, "agent.nested.x"), Some(json!(1)));
        assert_eq!(dig(&v, "agent.missing"), None);
        assert_eq!(dig(&v, "nope"), None);
    }

    #[test]
    fn diff_reports_changed_leaves_and_treats_arrays_as_whole() {
        let a = json!({"x": {"y": 1, "z": [1, 2]}, "k": "same"});
        let b = json!({"x": {"y": 2, "z": [1, 2]}, "k": "same"});
        let d = diff_configs(&a, &b);
        assert_eq!(d.len(), 1, "only x.y changed");
        assert_eq!(d[0].0, "x.y");
        assert_eq!(d[0].1, json!(1));
        assert_eq!(d[0].2, json!(2));
        // A changed array is one leaf change, not per-index.
        let c = json!({"x": {"y": 1, "z": [9]}, "k": "same"});
        let d2 = diff_configs(&a, &c);
        assert_eq!(d2.len(), 1);
        assert_eq!(d2[0].0, "x.z");
    }

    // The canonical shipped example is a complete, valid base config.
    fn example_base() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../garmr.example.toml")
    }

    fn live_of(base: &std::path::Path) -> Value {
        serde_json::to_value(garmr_core::Config::preview_override(base, "").unwrap()).unwrap()
    }

    #[test]
    fn validate_accepts_a_restart_field_and_flags_restart_required() {
        let base = example_base();
        let live = live_of(&base);
        // Propose a Restart-class scalar change guaranteed to differ from live.
        let cur = dig(&live, "store.retention_days")
            .and_then(|v| v.as_u64())
            .unwrap_or(10);
        let body = format!("[store]\nretention_days = {}\n", cur + 7);
        let report = validate_override(&base, &body, &live);
        assert_eq!(report["valid"], json!(true));
        assert_eq!(report["restart_required"], json!(true));
        let changes = report["changes"].as_array().unwrap();
        assert!(changes
            .iter()
            .any(|c| c["key"] == json!("store.retention_days") && c["reload"] == json!("restart")));
    }

    #[test]
    fn validate_refuses_a_non_editable_immutable_field() {
        let base = example_base();
        let live = live_of(&base);
        // store.warehouse_dir is Immutable and not on the editable allow-list.
        let report = validate_override(
            &base,
            "[store]\nwarehouse_dir = \"/definitely/not/the/base/warehouse\"\n",
            &live,
        );
        assert_eq!(report["valid"], json!(false), "immutable path change must be refused");
        let err = report["error"].as_str().unwrap();
        assert!(err.contains("cannot be changed"), "{err}");
        assert!(err.contains("store.warehouse_dir"), "{err}");
    }

    #[test]
    fn validate_refuses_a_capability_field_deny_by_default() {
        let base = example_base();
        let live = live_of(&base);
        // executor.block_ip is an argv command template — absent from the editable
        // allow-list, so deny-by-default must refuse it (would otherwise be RCE).
        let report = validate_override(
            &base,
            "[executor]\nenabled = true\nblock_ip = [\"/tmp/payload\", \"{arg}\"]\n",
            &live,
        );
        assert_eq!(report["valid"], json!(false), "executor capability edit must be refused");
        let err = report["error"].as_str().unwrap();
        assert!(err.contains("cannot be changed"), "{err}");
        assert!(err.contains("executor"), "{err}");
    }

    #[test]
    fn validate_refuses_an_unknown_field() {
        let base = example_base();
        let live = live_of(&base);
        // A key that isn't even a Config field must be refused, not silently dropped.
        let report = validate_override(&base, "[store]\nretention_days = 12\nbogus_key = 1\n", &live);
        assert_eq!(report["valid"], json!(false));
        assert!(report["error"].as_str().unwrap().contains("bogus_key"));
    }

    #[test]
    fn validate_rejects_a_type_error() {
        let base = example_base();
        let live = live_of(&base);
        // retention_days is an integer; a string must fail type-checking.
        let report = validate_override(&base, "[store]\nretention_days = \"lots\"\n", &live);
        assert_eq!(report["valid"], json!(false));
        assert!(report["error"].as_str().unwrap().contains("invalid configuration"));
    }

    #[test]
    fn figment_env_var_follows_the_convention() {
        // The env-shadow warning must key off figment's real GARMR_<SECTION>__<KEY>
        // mapping, not the schema's optional .env() (the editable fields declare none).
        assert_eq!(figment_env_var("agent.model"), "GARMR_AGENT__MODEL");
        assert_eq!(
            figment_env_var("store.retention_days"),
            "GARMR_STORE__RETENTION_DAYS"
        );
        assert_eq!(
            figment_env_var("detect.app_audit_enabled"),
            "GARMR_DETECT__APP_AUDIT_ENABLED"
        );
        // Every editable field resolves to a convention var (so the warning is live).
        for k in editable_keys() {
            assert!(figment_env_var(k).starts_with("GARMR_"));
        }
    }
}