// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr audit` — operate on the tamper-evident audit ledger, plus the shared
//! [`open_ledger`] helper the serve daemon uses to obtain a writer.
//!
//! `status`/`verify`/`export` are pure offline readers (no daemon, no writer);
//! `verify` exits non-zero on any tampering. `checkpoint` opens a writer and
//! should be run with `serve` stopped.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use anyhow::{bail, Context, Result};
use garmr_audit::{
    verify_dir, ActorType, AuditLedger, AuditRecord, ContentMode, LedgerConfig, Outcome,
    PolicyDecision, Signer, SoftwareSigner, TrustRoot,
};
use garmr_core::AuditConfig;

use crate::cli::{AuditCmd, Cli};
use crate::load_config;

/// The process-wide audit ledger, opened once at daemon startup and shared by
/// the API surface and the detection pipeline (both run as tasks in one
/// process). `None` inside means auditing is disabled; unset means not yet
/// initialized (treated as no-op).
static LEDGER: OnceLock<Option<Arc<AuditLedger>>> = OnceLock::new();

/// Initialize the process-wide ledger from config the first time, returning the
/// (possibly `None`) ledger. Idempotent: later calls return the already-set one.
pub(crate) fn ensure_init(audit: &AuditConfig) -> Result<Option<Arc<AuditLedger>>> {
    if let Some(existing) = LEDGER.get() {
        return Ok(existing.clone());
    }
    let led = open_ledger(audit)?;
    let _ = LEDGER.set(led.clone());
    Ok(led)
}

/// The process-wide ledger, or `None` if disabled/uninitialized.
pub(crate) fn global() -> Option<Arc<AuditLedger>> {
    LEDGER.get().cloned().flatten()
}

/// Append best-effort: for automatic, higher-frequency pipeline/agent events
/// that must never stall ingest or triage. A durable-write failure is logged,
/// not propagated (contrast the fail-closed admin path). No-op when disabled.
pub(crate) fn record_best_effort(rec: AuditRecord) {
    if let Some(led) = global() {
        if let Err(e) = led.append(rec) {
            tracing::warn!(error = %e, "audit append failed (best-effort event dropped)");
        }
    }
}

/// Fail-closed audit of a LOCAL admin decision made by running the CLI directly
/// (no daemon up — running the CLI *is* the human). Mirrors the API's
/// `record_admin`: returns the audit id so the caller can bind the change to it,
/// and propagates a durable-write failure so the change is refused rather than
/// applied unaudited. `Ok(None)` only when auditing is disabled in config.
///
/// The caller must have run [`ensure_init`] first (the local one-shot paths do,
/// and they only run when the daemon is down, so there is no writer conflict).
pub(crate) fn record_admin_local(
    action: &str,
    object_type: &str,
    object_id: Option<&str>,
    reason: Option<&str>,
) -> Result<Option<String>> {
    let Some(led) = global() else {
        return Ok(None);
    };
    let mut rec = AuditRecord::new(action, object_type)
        .actor(ActorType::Human, "cli".to_string(), Some("local-operator"))
        .auth_method("local_cli")
        .outcome(Outcome::Success)
        .policy(PolicyDecision::Allowed);
    if let Some(id) = object_id {
        rec = rec.object_id(id);
    }
    if let Some(r) = reason {
        rec = rec.reason(r);
    }
    let receipt = led
        .append(rec)
        .context("audit append for a local admin decision (fail closed)")?;
    Ok(Some(receipt.audit_id))
}

/// Best-effort audit of an executor apply-step (`response.execute`). By the time
/// the executor returns, the action's side effect has already happened, so a
/// ledger-write failure is logged, not propagated — but the ledger no longer
/// omits the apply step (its human approval was audited separately at decide).
/// Actor System "executor". No-op when auditing is disabled.
pub(crate) fn record_execute(id: &str, outcome: &garmr_agent::Outcome) {
    let (o, detail) = match outcome {
        garmr_agent::Outcome::Executed => (Outcome::Success, "executed".to_string()),
        garmr_agent::Outcome::Refused(r) => (Outcome::Denied, format!("refused: {r}")),
        garmr_agent::Outcome::Failed(e) => (Outcome::Error, format!("failed: {e}")),
    };
    let rec = AuditRecord::new(garmr_audit::action::ACTION_EXECUTE, "action_proposal")
        .actor(ActorType::System, "serve".to_string(), Some("executor"))
        .auth_method("system")
        .outcome(o)
        .policy(PolicyDecision::Allowed)
        .object_id(id)
        .reason(&detail);
    record_best_effort(rec);
}

/// Fail-closed audit of a SYSTEM action (an autonomous in-serve loop, e.g. the
/// environment auto-promote loop). Attributes to ActorType::System — NOT Human,
/// so the ledger's actor attribution stays honest — and propagates a durable-write
/// failure so the loop refuses to append a protected transition it couldn't
/// audit. `Ok(None)` only when auditing is disabled. Mirrors
/// `registry_observe::audit_observe`, but reusable and returning the id.
pub(crate) fn record_system(
    action: &str,
    object_type: &str,
    object_id: &str,
    reason: &str,
) -> Result<Option<String>> {
    let Some(led) = global() else {
        return Ok(None);
    };
    let rec = AuditRecord::new(action, object_type)
        .actor(ActorType::System, "serve".to_string(), Some("env-loop"))
        .auth_method("system")
        .outcome(Outcome::Success)
        .policy(PolicyDecision::Allowed)
        .object_id(object_id)
        .reason(reason);
    let receipt = led
        .append(rec)
        .context("audit append for an autonomous system action (fail closed)")?;
    Ok(Some(receipt.audit_id))
}

/// Best-effort audit of an ingest security event (Phase 12): a denied collector
/// auth or a sequence anomaly. System-tier, Denied outcome; a lost line must not
/// break ingest. The auditor already rate-limits, so this is called at most once
/// per window.
pub(crate) fn record_ingest_audit(action: &str, collector: Option<&str>, reason: &str) {
    record_best_effort(
        AuditRecord::new(action, "ingest")
            .actor(ActorType::System, "serve".to_string(), Some("ingest"))
            .outcome(Outcome::Denied)
            .policy(PolicyDecision::Denied)
            .object_id(collector.unwrap_or("-"))
            .reason(reason),
    );
}

/// Best-effort audit of an ingest sequence GAP (Phase 12): batches an
/// authenticated collector sent were never delivered (silent loss). System-tier;
/// the batch that revealed the gap WAS accepted, so the outcome is Success — the
/// gap is an informational anomaly, not a denial. The caller
/// ([`crate::ingest_seq::seq_observe_loop`]) aggregates gaps per collector over a
/// fixed window and calls this at most once per window, so a collector emitting a
/// stream of gaps cannot flood the append-only ledger. A lost line must not break
/// ingest.
pub(crate) fn record_ingest_seq_anomaly(collector: &str, reason: &str) {
    record_best_effort(
        AuditRecord::new(garmr_audit::action::INGEST_SEQ_ANOMALY, "ingest")
            .actor(ActorType::System, "serve".to_string(), Some("ingest"))
            .outcome(Outcome::Success)
            .policy(PolicyDecision::Allowed)
            .object_id(collector)
            .reason(reason),
    );
}

/// Best-effort audit of an Agent-tier action (e.g. a drafted rule proposal).
/// Proposing is the agent's read-only side — it only ever creates a *pending*
/// artifact — so a lost audit line must not fail the propose; it is recorded
/// best-effort, like a prediction. No-op when disabled/uninitialized.
pub(crate) fn record_agent_best_effort(
    action: &str,
    object_type: &str,
    object_id: &str,
    reason: &str,
) {
    record_best_effort(
        AuditRecord::new(action, object_type)
            .actor(ActorType::Agent, "triage-agent".to_string(), None)
            .outcome(Outcome::Success)
            .policy(PolicyDecision::Allowed)
            .object_id(object_id)
            .reason(reason),
    );
}

/// Map the config content-mode string to the ledger enum (default digest-only).
pub(crate) fn content_mode(s: &str) -> ContentMode {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" => ContentMode::Off,
        "redacted" => ContentMode::Redacted,
        "encrypted" => ContentMode::Encrypted,
        "full" => ContentMode::Full,
        _ => ContentMode::DigestOnly,
    }
}

fn key_path(audit: &AuditConfig) -> PathBuf {
    audit
        .key_path
        .clone()
        .unwrap_or_else(|| audit.dir.join("signing.key"))
}

fn ledger_config(audit: &AuditConfig) -> LedgerConfig {
    LedgerConfig {
        node_id: audit.node_id.clone(),
        content_mode: content_mode(&audit.content_mode),
        per_record_sign: audit.per_record_sign,
        segment_max_records: audit.segment_max_records.max(1),
        checkpoint_every: audit.checkpoint_every.max(1),
        fsync: audit.fsync,
    }
}

/// Open (or initialize) the ledger for a live daemon. Returns `None` when
/// auditing is disabled in config. Publishes the public key next to the ledger.
pub(crate) fn open_ledger(audit: &AuditConfig) -> Result<Option<Arc<AuditLedger>>> {
    if !audit.enabled {
        return Ok(None);
    }
    let kp = key_path(audit);
    let signer = SoftwareSigner::load_or_create(&kp)
        .with_context(|| format!("opening audit signing key {}", kp.display()))?;
    let ledger = AuditLedger::open(&audit.dir, ledger_config(audit), Arc::new(signer))
        .with_context(|| format!("opening audit ledger at {}", audit.dir.display()))?;
    let _ = ledger.export_public_key();
    Ok(Some(Arc::new(ledger)))
}

/// Parse a 64-hex ed25519 public key.
fn parse_public_key(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("public key must be hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be exactly 32 bytes (64 hex chars)"))
}

/// The public key to verify against: an explicit `--key`, else the published
/// `public_key.hex`, else derived from the local signing key.
fn resolve_public_key(audit: &AuditConfig, key_override: Option<&str>) -> Result<[u8; 32]> {
    if let Some(hex_str) = key_override {
        return parse_public_key(hex_str);
    }
    let published = audit.dir.join("public_key.hex");
    if published.exists() {
        let s = std::fs::read_to_string(&published)?;
        return parse_public_key(&s);
    }
    // Fall back to deriving from the signing key (creates it if absent).
    let signer = SoftwareSigner::load_or_create(&key_path(audit))?;
    Ok(signer.public_key())
}

pub(crate) async fn audit_cmd(cli: &Cli, what: &AuditCmd) -> Result<()> {
    let cfg = load_config(cli)?;
    let audit = &cfg.audit;
    match what {
        AuditCmd::Status => status(audit),
        AuditCmd::Verify { key } => verify(audit, key.as_deref()),
        AuditCmd::Export { dir } => export(audit, dir),
        AuditCmd::Checkpoint => checkpoint(audit),
    }
}

fn status(audit: &AuditConfig) -> Result<()> {
    if !audit.enabled {
        println!("audit ledger: DISABLED in config");
        return Ok(());
    }
    let trust = TrustRoot::from_public_key(resolve_public_key(audit, None)?);
    let report = verify_dir(&audit.dir, &trust)?;
    println!("audit ledger: {}", audit.dir.display());
    println!("  node:         {}", audit.node_id);
    println!("  content mode: {}", audit.content_mode);
    println!("  records:      {}", report.records_checked);
    println!("  segments:     {}", report.segments);
    println!("  checkpoints:  {}", report.checkpoints_checked);
    print!("  chain head:   seq {}", report.last_sequence);
    match report.last_hash {
        Some(h) => println!(" ({}…)", &h.to_hex()[..16]),
        None => println!(),
    }
    println!(
        "  integrity:    {}",
        if report.ok { "OK" } else { "FAILED" }
    );
    for f in &report.findings {
        println!("    - {:?} seq={:?}: {}", f.kind, f.sequence, f.detail);
    }
    Ok(())
}

fn verify(audit: &AuditConfig, key: Option<&str>) -> Result<()> {
    if !audit.enabled {
        println!("audit ledger disabled in config — nothing to verify");
        return Ok(());
    }
    let trust = TrustRoot::from_public_key(resolve_public_key(audit, key)?);
    let report = verify_dir(&audit.dir, &trust)?;
    if report.ok {
        println!(
            "audit OK: {} records, {} segments, {} checkpoints, head seq {}",
            report.records_checked,
            report.segments,
            report.checkpoints_checked,
            report.last_sequence
        );
        Ok(())
    } else {
        for f in &report.findings {
            eprintln!("FAIL {:?} seq={:?}: {}", f.kind, f.sequence, f.detail);
        }
        bail!(
            "audit verification FAILED: {} finding(s)",
            report.findings.len()
        );
    }
}

fn export(audit: &AuditConfig, dest: &PathBuf) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    let mut copied = 0u64;
    for sub in ["segments", "checkpoints"] {
        let from = audit.dir.join(sub);
        if !from.exists() {
            continue;
        }
        let to = dest.join(sub);
        std::fs::create_dir_all(&to)?;
        for entry in std::fs::read_dir(&from)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                std::fs::copy(entry.path(), to.join(entry.file_name()))?;
                copied += 1;
            }
        }
    }
    let pk = audit.dir.join("public_key.hex");
    if pk.exists() {
        std::fs::copy(&pk, dest.join("public_key.hex"))?;
    }
    println!(
        "exported {copied} file(s) to {} (verify with: garmr audit verify --config … after pointing audit.dir there, or an external verifier)",
        dest.display()
    );
    Ok(())
}

fn checkpoint(audit: &AuditConfig) -> Result<()> {
    match open_ledger(audit)? {
        Some(ledger) => {
            ledger.checkpoint()?;
            println!("checkpoint written at head seq {}", ledger.head_sequence());
            Ok(())
        }
        None => bail!("audit ledger disabled in config"),
    }
}
