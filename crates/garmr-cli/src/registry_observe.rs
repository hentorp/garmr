// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Startup auto-registration: record the artifacts the daemon is ACTUALLY
//! running (system prompt, built-in toolset, triage model) into the versioned
//! registry, and hand back their coordinates so every prediction the agent
//! emits links to the exact records.
//!
//! Two invariants shape this:
//!
//!   * **Observed, not approved.** Auto-registration writes `Draft`
//!     `RegistrySource::Observed` records — it never promotes. What the daemon
//!     happens to run does not become the blessed/live version without a human
//!     promotion (which is separately audited). The system describes reality; a
//!     person decides what is sanctioned.
//!   * **Content-addressed, so idempotent.** Each version is derived from the
//!     content digest (`obs-<digest12>`), so an unchanged config re-registers to
//!     the same key as a silent no-op across restarts; only a genuine change
//!     (new prompt, retuned model) mints a new record — and only then is a new
//!     audit event appended.

use anyhow::{Context, Result};
use garmr_agent::RegistryIdentities;
use garmr_audit::{ActorType, AuditRecord, Outcome, PolicyDecision};
use garmr_core::{ApprovalState, Config, RegistryKind, RegistryRecord, RegistrySource};
use garmr_store::state::RegisterOutcome;
use garmr_store::Store;

/// Register the running prompt/toolset/model as observed Draft records (audited,
/// idempotent) and return the registry coordinates to stamp onto predictions.
/// Best-effort in spirit but fail-closed on audit: a record is only written when
/// its audit event is durable (or auditing is disabled entirely, in which case
/// the Draft record is inert-for-promotion anyway).
pub(crate) fn observe_running(store: &Store, cfg: &Config) -> Result<RegistryIdentities> {
    use garmr_audit::action::*;

    // ---- system prompt --------------------------------------------------
    let prompt_digest = garmr_agent::system_prompt_digest();
    let prompt_version = obs_version(&prompt_digest);
    ensure_observed(
        store,
        RegistryKind::Prompt,
        "system",
        &prompt_version,
        &prompt_digest,
        PROMPT_PROPOSE,
        serde_json::json!({ "role": "system", "digest": prompt_digest }),
    )?;

    // ---- built-in toolset ----------------------------------------------
    let toolset_digest = garmr_agent::toolset_digest();
    let toolset_version = obs_version(&toolset_digest);
    ensure_observed(
        store,
        RegistryKind::Toolset,
        "builtin",
        &toolset_version,
        &toolset_digest,
        TOOLSET_REGISTER,
        serde_json::json!({ "digest": toolset_digest }),
    )?;

    // ---- detector configuration ----------------------------------------
    // The tuned detection thresholds the daemon is running with, addressed by a
    // canonical serialization of the detect config.
    let detect_json = serde_json::to_string(&cfg.detect).unwrap_or_default();
    let detect_digest = blake3::hash(detect_json.as_bytes()).to_hex().to_string();
    let detect_version = obs_version(&detect_digest);
    ensure_observed(
        store,
        RegistryKind::DetectorConfig,
        "detect",
        &detect_version,
        &detect_digest,
        THRESHOLD_PROPOSE,
        serde_json::json!({ "digest": detect_digest, "config": cfg.detect }),
    )?;

    // ---- triage model ---------------------------------------------------
    // The "content" of a config-defined model is its identity descriptor
    // (backend + model name + endpoint) — we can't hash remote weights, but this
    // stably distinguishes one model configuration from another.
    let model_digest = garmr_core::model_descriptor_digest(
        cfg.agent.backend,
        &cfg.agent.model,
        cfg.agent.openai_base_url.as_deref().unwrap_or(""),
    );
    let model_version = obs_version(&model_digest);
    ensure_observed(
        store,
        RegistryKind::Model,
        &cfg.agent.model,
        &model_version,
        &model_digest,
        MODEL_REGISTER,
        serde_json::json!({
            "backend": format!("{:?}", cfg.agent.backend),
            "model": cfg.agent.model,
            "endpoint": cfg.agent.openai_base_url,
            "digest": model_digest,
        }),
    )?;

    // Phase 10: register every ENABLED catalog model as an observed record, so a
    // routed model's stamped digest resolves to an audited RegistryKind::Model.
    for e in cfg.route.router.models.iter().filter(|e| e.enabled) {
        let d = e.descriptor_digest();
        let v = obs_version(&d);
        ensure_observed(
            store,
            RegistryKind::Model,
            &e.model,
            &v,
            &d,
            MODEL_REGISTER,
            serde_json::json!({
                "backend": format!("{:?}", e.backend),
                "model": e.model,
                "endpoint": e.openai_base_url,
                "role": e.role,
                "digest": d,
            }),
        )?;
    }

    Ok(RegistryIdentities {
        prompt_version,
        model_digest,
    })
}

/// `obs-<first 12 hex of the digest>` — a deterministic, content-addressed
/// version so a restart with the same artifact is a no-op.
fn obs_version(digest: &str) -> String {
    format!("obs-{}", &digest[..digest.len().min(12)])
}

/// Register one observed artifact if it isn't already present with this exact
/// digest. Silent (no audit) when the record already exists — restarts don't
/// spam the ledger. On a genuinely new record: audit fail-closed, THEN register.
fn ensure_observed(
    store: &Store,
    kind: RegistryKind,
    name: &str,
    version: &str,
    digest: &str,
    action: &str,
    spec: serde_json::Value,
) -> Result<()> {
    if let Some(existing) = store.state.get_record(kind, name, version)? {
        if existing.content_digest == digest {
            return Ok(()); // already observed — nothing changed, stay silent
        }
    }
    let coord = format!("{name}@{version}");
    let audit_id = audit_observe(action, &coord)?;
    let rec = RegistryRecord {
        id: uuid::Uuid::new_v4().to_string(),
        kind,
        name: name.to_string(),
        version: version.to_string(),
        content_digest: digest.to_string(),
        parent_version: None,
        rationale: "auto-registered running artifact at startup".to_string(),
        eval_run_refs: Vec::new(),
        approval: ApprovalState::Draft,
        source: RegistrySource::Observed,
        registered_at: chrono::Utc::now(),
        registered_by: "serve".to_string(),
        audit_id,
        spec,
    };
    match store.state.register_record(&rec)? {
        RegisterOutcome::Conflict { existing_digest } => tracing::warn!(
            kind = kind.tag(),
            name,
            version,
            existing_digest,
            "observed artifact conflicts with an existing record — leaving the existing one"
        ),
        RegisterOutcome::Inserted => {
            tracing::info!(
                kind = kind.tag(),
                name,
                version,
                "auto-registered running artifact"
            )
        }
        RegisterOutcome::AlreadyIdentical => {}
    }
    Ok(())
}

/// Append a fail-closed System-actor audit event for an observed registration.
/// Returns the audit id, or `None` when auditing is disabled (the resulting
/// Draft record is then inert-for-promotion — a human promotion would itself
/// need an audit event that a disabled ledger cannot produce).
fn audit_observe(action: &str, coord: &str) -> Result<Option<String>> {
    match crate::audit::global() {
        Some(led) => {
            let rec = AuditRecord::new(action, "registry_record")
                .actor(ActorType::System, "serve".to_string(), Some("observe"))
                .auth_method("startup")
                .outcome(Outcome::Success)
                .policy(PolicyDecision::Allowed)
                .object_id(coord)
                .reason("auto-registered running artifact at startup");
            let receipt = led
                .append(rec)
                .context("audit append for observed registration (fail closed)")?;
            Ok(Some(receipt.audit_id))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obs_version_is_content_addressed_and_stable() {
        let d = garmr_agent::system_prompt_digest();
        // Deterministic: the same digest always yields the same version, so a
        // restart with an unchanged prompt re-registers to the same key.
        assert_eq!(obs_version(&d), obs_version(&d));
        assert!(obs_version(&d).starts_with("obs-"));
        // A different artifact yields a different version (no accidental key
        // collision that would blank out a real record).
        assert_ne!(obs_version(&d), obs_version(&garmr_agent::toolset_digest()));
    }

    #[test]
    fn obs_version_tolerates_a_short_digest() {
        // min() guard: never panic-slices a digest shorter than 12 chars.
        assert_eq!(obs_version("abc"), "obs-abc");
    }
}
