// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Operational commands: notification `silence` management (direct or via the
//! daemon API) and `selftest` (an end-to-end pipeline smoke test).

use super::*;

pub(crate) async fn silence(cli: &Cli, what: &SilenceCmd) -> Result<()> {
    let cfg = load_config(cli)?;
    let token = std::env::var("GARMR_ADMIN_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    if let (Some(token), Some(bind)) = (&token, &cfg.ingest.api_bind) {
        match silence_via_api(bind, token, what).await {
            Ok(()) => return Ok(()),
            Err(e)
                if e.downcast_ref::<reqwest::Error>()
                    .is_some_and(|e| e.is_connect()) =>
            {
                tracing::debug!(error = %e, "daemon API not reachable; using the store directly");
            }
            Err(e) => return Err(e),
        }
    }
    let state = garmr_store::StateStore::open(&cfg.store.state_db).with_context(|| {
        format!(
            "opening state store {} — if `garmr serve` is running, set GARMR_ADMIN_TOKEN and \
             use the daemon API instead",
            cfg.store.state_db.display()
        )
    })?;
    match what {
        SilenceCmd::Set {
            rule,
            hours,
            host,
            reason,
        } => {
            // A silence suppresses alerting — a protected admin mutation. Refuse
            // on a restored-but-unpromoted follower, and audit fail-closed BEFORE
            // the write (running the CLI locally IS the human approval), matching
            // the daemon /admin path and the peer local-CLI fallbacks.
            refuse_if_restored(&cfg)?;
            crate::audit::ensure_init(&cfg.audit)?;
            crate::audit::record_admin_local(
                garmr_audit::action::SILENCE,
                "rule",
                Some(rule),
                Some(&format!(
                    "{} rule={rule} host={} hours={hours} (local CLI)",
                    if *hours == 0.0 { "clear" } else { "silence" },
                    host.as_deref().unwrap_or("*"),
                )),
            )?;
            let change =
                garmr_route::set_silence(&state, rule, host.as_deref(), *hours, reason, Utc::now())
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            print_silence_change(rule, &change);
            // Announce on the alerts room even from the CLI path, so silencing
            // is never invisible on the channel it affects. Best-effort.
            if let Some(m) = cfg.matrix.as_ref().and_then(Matrix::from_env) {
                if let Some(mc) = &cfg.matrix {
                    let text = silence_notice_text(&change, "CLI");
                    if let Some(text) = text {
                        if let Err(e) = m.notice(&mc.alerts_room, &text).await {
                            tracing::warn!(error = %e, "silence announcement failed");
                        }
                    }
                }
            }
        }
        SilenceCmd::List => print_silences(&state.active_silences(Utc::now())?),
    }
    Ok(())
}

fn silence_notice_text(change: &garmr_route::SilenceChange, via: &str) -> Option<String> {
    match (&change.set, &change.replaced) {
        (Some(s), replaced) => Some(format!(
            "🔇 silence SET (via {via}): rule {} host {} until {}{}{}",
            s.rule,
            s.host.as_deref().unwrap_or("*"),
            s.until.format("%Y-%m-%d %H:%M UTC"),
            if s.reason.is_empty() {
                String::new()
            } else {
                format!(" — {}", s.reason)
            },
            replaced
                .as_ref()
                .filter(|r| r.host != s.host)
                .map(|r| format!(
                    " (REPLACED silence with scope {})",
                    r.host.as_deref().unwrap_or("all hosts")
                ))
                .unwrap_or_default(),
        )),
        (None, Some(r)) => Some(format!(
            "🔊 silence CLEARED (via {via}): rule {} host {}",
            r.rule,
            r.host.as_deref().unwrap_or("*"),
        )),
        (None, None) => None,
    }
}

pub(crate) async fn silence_via_api(bind: &str, token: &str, what: &SilenceCmd) -> Result<()> {
    // Bounded client: a wedged daemon must fail the command, not hang it.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let base = format!("http://{bind}");
    let refused = |status: reqwest::StatusCode, body: String| -> anyhow::Error {
        if status == reqwest::StatusCode::NOT_FOUND {
            anyhow::anyhow!(
                "daemon is running but its admin surface is disabled — restart `garmr serve` \
                 with GARMR_ADMIN_TOKEN set (or stop it and re-run this command)"
            )
        } else {
            anyhow::anyhow!("daemon refused: {status} {body}")
        }
    };
    match what {
        SilenceCmd::Set {
            rule,
            hours,
            host,
            reason,
        } => {
            let resp = client
                .post(format!("{base}/admin/silence"))
                .bearer_auth(token)
                .json(&serde_json::json!({
                    "rule": rule, "hours": hours, "host": host, "reason": reason,
                }))
                .send()
                .await?;
            if !resp.status().is_success() {
                let status = resp.status();
                return Err(refused(status, resp.text().await.unwrap_or_default()));
            }
            let v: serde_json::Value = resp.json().await?;
            let change = garmr_route::SilenceChange {
                set: v
                    .get("set")
                    .and_then(|x| serde_json::from_value(x.clone()).ok()),
                replaced: v
                    .get("replaced")
                    .and_then(|x| serde_json::from_value(x.clone()).ok()),
            };
            print_silence_change(rule, &change);
            println!("(via daemon-API)");
        }
        SilenceCmd::List => {
            let resp = client
                .get(format!("{base}/admin/silences"))
                .bearer_auth(token)
                .send()
                .await?;
            if !resp.status().is_success() {
                let status = resp.status();
                return Err(refused(status, resp.text().await.unwrap_or_default()));
            }
            let silences: Vec<garmr_core::Silence> = resp.json().await?;
            print_silences(&silences);
        }
    }
    Ok(())
}

fn print_silence_change(rule: &str, change: &garmr_route::SilenceChange) {
    match &change.set {
        Some(s) => println!(
            "silenced: {}{} until {}{}",
            s.rule,
            s.host
                .as_deref()
                .map(|h| format!(" (host {h})"))
                .unwrap_or_default(),
            s.until.format("%Y-%m-%d %H:%M UTC"),
            if s.reason.is_empty() {
                String::new()
            } else {
                format!(" — {}", s.reason)
            },
        ),
        None => match &change.replaced {
            Some(_) => println!("silence cleared for {rule}"),
            None => println!("no silence existed for {rule}"),
        },
    }
    // One silence per rule: surface a scope change so a host-scoped set that
    // destroyed a fleet-wide silence (or vice versa) is never silent.
    if let (Some(s), Some(r)) = (&change.set, &change.replaced) {
        if r.host != s.host {
            println!(
                "  NOTE: replaced earlier silence with scope {} ({} hits)",
                r.host.as_deref().unwrap_or("all hosts"),
                r.hits,
            );
        }
    }
}

fn print_silences(silences: &[garmr_core::Silence]) {
    if silences.is_empty() {
        println!("(no active silences)");
    }
    for s in silences {
        println!(
            "{:<28} host={:<12} until {}  hits={}  {}",
            s.rule,
            s.host.as_deref().unwrap_or("*"),
            s.until.format("%Y-%m-%d %H:%M UTC"),
            s.hits,
            s.reason,
        );
    }
}

/// `garmr compact` — offline events-table compaction (see `Cmd::Compact`).
/// Collapses a bloated snapshot log to one snapshot; run with `serve` stopped.
pub(crate) async fn compact_cmd(cli: &Cli) -> Result<()> {
    let cfg = load_config(cli)?;
    println!("compacting events table (offline — rewriting into a single snapshot)…");
    let report = garmr_store::events::compact_now(&cfg)
        .await
        .context("compacting events (is `garmr serve` still running? stop it first)")?;
    println!(
        "done: {} snapshots \u{2192} 1, {} rows kept",
        report.snapshots_before, report.rows
    );
    Ok(())
}

pub(crate) async fn selftest(cli: &Cli) -> Result<()> {
    let cfg = load_config(cli)?;
    println!(
        "garmr selftest — backend: {:?}, model: {}",
        cfg.agent.backend, cfg.agent.model
    );

    // 1. Matrix reachability (if configured).
    if let Some(mc) = &cfg.matrix {
        match Matrix::from_env(mc) {
            Some(m) => match m.whoami().await {
                Ok(who) => println!("  matrix whoami: {who}"),
                Err(e) => println!("  matrix whoami FAILED: {e}"),
            },
            None => println!("  matrix: GARMR_MATRIX_TOKEN not set (skipping)"),
        }
    }

    // 2. Drive a canned brute-force case through detect + agent.
    let store = Store::open(&cfg).await.context("opening store")?;
    let (detector, agent, _provider) = build_agent_from(&store, &cfg, true).await?;
    let ev = canned_event();
    store.events.append(vec![ev.clone()]).await?;
    let dets = detector.evaluate(&ev);
    println!("  detection: {} rule(s) fired", dets.len());
    let Some(det) = dets.into_iter().next() else {
        println!("  no rule fired — check rules_dir; selftest cannot exercise the agent");
        return Ok(());
    };
    let mut case = Case::open(det);
    store.state.put_case(&case)?;
    match agent.triage(&mut case).await {
        Ok(()) => {
            println!("  triage state: {:?}", case.state);
            if let Some(v) = &case.verdict {
                println!(
                    "  verdict: {:?} sev{} — {}",
                    v.disposition, v.severity, v.rationale
                );
            }
        }
        Err(e) => println!("  triage FAILED: {e}"),
    }
    Ok(())
}

fn canned_event() -> Event {
    use std::collections::BTreeMap;
    let mut fields = BTreeMap::new();
    fields.insert("src_ip".into(), "203.0.113.7".into());
    fields.insert("user".into(), "root".into());
    fields.insert("port".into(), "51234".into());
    Event {
        ts: Utc::now(),
        host: "pve".into(),
        service: "sshd".into(),
        source: "journald".into(),
        environment: "prod".into(),
        severity: "warning".into(),
        log_type: "system".into(),
        message: "Failed password for root from 203.0.113.7 port 51234 ssh2".into(),
        fields,
    }
}

/// Break-glass recovery (`garmr recover`). Local-only, offline (serve stopped).
pub(crate) async fn recover(cli: &Cli, what: &RecoverCmd) -> Result<()> {
    match what {
        RecoverCmd::IssueAdmin { label, hours } => recover_issue_admin(cli, label, *hours).await,
    }
}

/// Mint a short-lived emergency Admin credential from the host and print its
/// token ONCE. Requires local host access (the root of trust) and `serve`
/// stopped (single-writer store). The issuance is recorded to the tamper-evident
/// audit ledger BEFORE the credential is persisted (fail-closed — never a bypass).
async fn recover_issue_admin(cli: &Cli, label: &str, hours: i64) -> Result<()> {
    let cfg = load_config(cli)?;
    // A node restored from a backup but not yet promoted is write-fenced: minting a
    // credential here would violate that fence and could silently vanish on the next
    // writer re-sync (false break-glass). Refuse, like the sibling `silence` path.
    refuse_if_restored(&cfg)?;
    let hours = hours.clamp(1, 168);
    let store = garmr_store::Store::open(&cfg).await.with_context(|| {
        "opening the store for recovery — stop `garmr serve` first (it holds the \
         single-writer state DB)"
    })?;
    let creds = crate::api::credentials::CredentialStore::new(&store);
    let ledger = crate::audit::open_ledger(&cfg.audit)?;
    let expires_at = Some(Utc::now().timestamp() + hours * 3600);

    let (token, _meta) = creds
        .issue_credential(
            label,
            "recovery",
            garmr_core::Role::Admin,
            vec!["system:admin".to_string()],
            expires_at,
            "cli-recovery",
            |id, fp| {
                // Fail-closed: with auditing ON the record MUST land before the
                // credential is saved. With auditing OFF there is nothing to
                // bypass — proceed, but say so loudly.
                let Some(ledger) = &ledger else {
                    eprintln!(
                        "WARNING: the audit ledger is disabled — this recovery will NOT be recorded"
                    );
                    return Ok(());
                };
                let rec = garmr_audit::AuditRecord::new(
                    garmr_audit::action::RECOVERY_ADMIN,
                    "recovery",
                )
                .actor(garmr_audit::ActorType::Human, "cli-recovery".to_string(), Some("Admin"))
                .auth_method("cli-local")
                .outcome(garmr_audit::Outcome::Success)
                .policy(garmr_audit::PolicyDecision::Allowed)
                .object_id(id)
                .reason(format!(
                    "emergency admin credential '{label}' ({fp}) expiring in {hours}h"
                ));
                ledger
                    .append(rec)
                    .map(|_| ())
                    .map_err(|e| format!("audit append failed (refusing to mint un-audited): {e}"))
            },
        )
        .map_err(|e| anyhow::anyhow!("issuing the recovery credential: {e}"))?;

    println!(
        "Emergency Admin credential '{label}' issued (expires in {hours}h), recorded to the audit ledger.\n"
    );
    println!("    {token}\n");
    println!(
        "Start `garmr serve`, then use this token as a Bearer to log in, register a fresh\n\
         admin passkey, and REVOKE this credential in System → Access. It is shown only here."
    );
    Ok(())
}