// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The one-shot CLI command handlers — every `garmr <subcommand>` except
//! `serve`: query/search/tail/cases/replay/eval/correlate/anomaly/risk/
//! baseline/graph/(semantic)/retention/cold-query/entity/ask/action/execute/
//! rules/hunt/silence/selftest — plus their shared print/parse/daemon-fallback
//! helpers. `main` dispatches here; each handler opens the store fresh and does
//! one thing. (Per-concern sub-modules are a further refinement.)

use super::*;

mod agent;
mod appbaseline;
mod collectors;
mod env;
mod learn;
mod ops;
mod pgaudit;
mod pipeline;
mod read;
mod reflect;
mod registry;
pub(crate) mod rules_import;
mod synth;

pub(crate) use agent::*;
pub(crate) use appbaseline::*;
pub(crate) use collectors::*;
pub(crate) use env::*;
pub(crate) use learn::*;
pub(crate) use ops::*;
pub(crate) use pgaudit::*;
pub(crate) use pipeline::*;
pub(crate) use read::*;
pub(crate) use reflect::*;
pub(crate) use registry::*;
pub(crate) use rules_import::*;
pub(crate) use synth::*;

/// Refuse a direct-store WRITE on a node restored from a backup but not yet
/// promoted (Phase-13 invariant #2). `Store::open_writable` already enforces this
/// at its choke point, but the local-CLI admin fallbacks that open the state store
/// directly (or via the read-only `Store::open`) bypass it — so they call this
/// first. Read-only commands do not. Mirrors `serve`'s startup refusal.
pub(crate) fn refuse_if_restored(cfg: &Config) -> Result<()> {
    let marker = garmr_store::restored_marker_path(&cfg.store.state_db);
    if marker.exists() {
        anyhow::bail!(
            "this node was restored from a backup and has NOT been promoted (marker {}) — run \
             `garmr backup promote` before any local write",
            marker.display()
        );
    }
    Ok(())
}

/// Parse an RFC3339 timestamp into UTC (for `cases prune` window filters).
pub(crate) fn parse_rfc3339(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    Ok(chrono::DateTime::parse_from_rfc3339(s)
        .with_context(|| format!("invalid RFC3339 time: {s}"))?
        .with_timezone(&chrono::Utc))
}

/// Parse a case-state name (as printed by `cases list`) for the `--state` filter.
pub(crate) fn parse_case_state(s: &str) -> Result<CaseState> {
    Ok(match s.to_ascii_lowercase().replace('-', "_").as_str() {
        "new" => CaseState::New,
        "investigating" => CaseState::Investigating,
        "triaged" => CaseState::Triaged,
        "escalated" => CaseState::Escalated,
        "closed" => CaseState::Closed,
        "needs_human" | "needshuman" => CaseState::NeedsHuman,
        other => anyhow::bail!(
            "unknown case state: {other} (new|investigating|triaged|escalated|closed|needs_human)"
        ),
    })
}

fn find_by_prefix(store: &Store, prefix: &str) -> Result<Option<Case>> {
    Ok(store
        .state
        .list_cases()?
        .into_iter()
        .find(|c| c.id.starts_with(prefix)))
}

fn print_case(c: &Case) {
    println!("case {}", c.id);
    println!("  state:     {:?}", c.state);
    println!(
        "  rule:      {} ({})",
        c.trigger.rule_title, c.trigger.rule_id
    );
    println!("  host:      {}", c.trigger.event.host);
    println!("  src_ip:    {}", c.trigger.event.src_ip().unwrap_or("-"));
    println!("  events:    {}", c.event_count);
    println!(
        "  opened:    {}",
        c.opened_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(v) = &c.verdict {
        println!(
            "  verdict:   {:?}  severity {}/10  confidence {:.0}%",
            v.disposition,
            v.severity,
            v.confidence * 100.0
        );
        println!("  rationale: {}", v.rationale);
        if let Some(a) = &v.proposed_action {
            println!("  proposed:  {a}");
        }
    }
    println!("  transcript:");
    for t in &c.transcript {
        println!(
            "    [{}] {}: {}",
            t.at.format("%H:%M:%S"),
            t.actor,
            truncate(&t.detail, 200)
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// Which end of a time range a bound sits on — decides how a bare date expands.
#[derive(Clone, Copy)]
pub(crate) enum Bound {
    Start,
    End,
}

/// Parse a `--from`/`--to` bound: an RFC3339 timestamp is exact; a bare
/// `YYYY-MM-DD` covers the whole named day — 00:00:00 for a start bound, and
/// midnight *after* the day for an (exclusive) end bound, so `--to 2026-04-08`
/// includes 2026-04-08 instead of silently excluding it. Returns micros.
pub(crate) fn parse_time(s: &str, bound: Bound) -> Result<i64> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc).timestamp_micros());
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let d = match bound {
            Bound::Start => d,
            Bound::End => d.succ_opt().context("date out of range")?,
        };
        let dt = d.and_hms_opt(0, 0, 0).unwrap().and_utc();
        return Ok(dt.timestamp_micros());
    }
    anyhow::bail!("expected RFC3339 timestamp or YYYY-MM-DD date, got {s:?}")
}

/// Set/list silences. Prefers the daemon API when GARMR_ADMIN_TOKEN is set and
/// the API answers (the store is single-process, so while `serve` runs the
/// daemon is the only writer); falls back to opening the state store directly
/// (works when the daemon is stopped — silences live in redb only, so this
/// doesn't touch the lakehouse or the search index).
/// GET a daemon API path if a daemon appears to be running; Ok(None) = no
/// daemon (fall back to the store), Err = daemon answered with an error.
///
/// Fallback discipline: ONLY a connection failure (nothing listening) means
/// "no daemon". Any other transport error (timeout, reset mid-flight) means a
/// daemon may well be running — falling back to direct store access would at
/// best hit its exclusive lock and at worst race its startup, so propagate.
pub(crate) async fn try_daemon_get(
    cfg: &garmr_core::Config,
    path_q: &str,
) -> Result<Option<serde_json::Value>> {
    try_daemon(cfg, path_q, None, std::time::Duration::from_secs(200)).await
}

/// Like [`try_daemon_get`] but POSTs `body` with a caller-chosen timeout (the
/// hunt endpoint runs the full agent loop — the client must outwait the
/// server's 600s budget, not kill the request a third of the way in). Sends
/// GARMR_ADMIN_TOKEN as bearer when set (the daemon requires it then).
pub(crate) async fn try_daemon(
    cfg: &garmr_core::Config,
    path_q: &str,
    body: Option<serde_json::Value>,
    timeout: std::time::Duration,
) -> Result<Option<serde_json::Value>> {
    let Some(bind) = &cfg.ingest.api_bind else {
        return Ok(None);
    };
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(std::time::Duration::from_secs(2))
        .build()?;
    let url = format!("http://{bind}{path_q}");
    let mut req = match &body {
        Some(b) => client.post(&url).json(b),
        None => client.get(&url),
    };
    if let Ok(token) = std::env::var("GARMR_ADMIN_TOKEN") {
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) if e.is_connect() => return Ok(None),
        Err(e) => anyhow::bail!("the daemon at {bind} did not respond cleanly: {e}"),
    };
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status == reqwest::StatusCode::NOT_FOUND && body.is_empty() {
        // Route missing entirely. For /admin paths the by-far most common
        // cause is a daemon started WITHOUT the admin token (those routes are
        // only mounted when it is set) — say so instead of misdiagnosing.
        if path_q.starts_with("/admin") {
            anyhow::bail!(
                "the daemon is running without GARMR_ADMIN_TOKEN — restart it with the token set                  (or stop it and run the command again against the store directly)"
            );
        }
        anyhow::bail!(
            "the daemon answers but is missing {path_q} — it is running an older binary; restart it with the new one"
        );
    }
    if !status.is_success() {
        anyhow::bail!("daemon refused: {status} {body}");
    }
    Ok(Some(
        serde_json::from_str(&body).context("daemon returned non-JSON")?,
    ))
}

/// Percent-encode every byte (path/query safe).
fn enc(v: &str) -> String {
    v.bytes().map(|b| format!("%{b:02X}")).collect()
}
