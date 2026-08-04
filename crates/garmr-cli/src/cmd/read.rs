// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Read/inspect commands: `query` (read-only SQL), `tail`, `cases`
//! (list/show/prune), `findings` (the detection plane's SecurityFindings),
//! `shadow` (the DoD-19 champion/challenger comparison summary), and `models`
//! (the model-router catalog + per-class fence decision, offline). Daemon-first
//! where a live in-memory view exists; direct store reads otherwise.

use super::*;

pub(crate) async fn query(cli: &Cli, sql: &str) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    let batches = store.events.sql(sql).await.context("running query")?;
    print!("{}", format_batches(&batches));
    Ok(())
}

pub(crate) async fn tail(cli: &Cli, limit: usize) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    let sql = format!(
        "SELECT event_ts, host, service, severity, message FROM events \
         ORDER BY event_ts DESC LIMIT {limit}"
    );
    let batches = store.events.sql(&sql).await?;
    print!("{}", format_batches(&batches));
    Ok(())
}

/// `garmr findings` — the detection plane's SecurityFindings (Phase 7), daemon-
/// first (GET /api/findings) then the local store.
pub(crate) async fn findings_cmd(cli: &Cli, host: Option<&str>) -> Result<()> {
    let cfg = load_config(cli)?;
    let path = match host {
        Some(h) => format!("/api/findings?host={}", enc(h)),
        None => "/api/findings".to_string(),
    };
    let rows = match try_daemon_get(&cfg, &path).await? {
        Some(v) => v["findings"].clone(),
        None => {
            let store = Store::open(&cfg).await?;
            let list = match host {
                Some(h) => store.state.findings_for_entity(h)?,
                None => store.state.list_findings()?,
            };
            serde_json::to_value(list)?
        }
    };
    let arr = rows.as_array().cloned().unwrap_or_default();
    if arr.is_empty() {
        println!("(no findings)");
    }
    for f in &arr {
        let ts = chrono::DateTime::parse_from_rfc3339(f["observed_at"].as_str().unwrap_or(""))
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        println!(
            "{:<8} {:<16} {:<8} {:<10} {}  (crit {:.1})",
            f["level"].as_str().unwrap_or("?"),
            f["detector"].as_str().unwrap_or("?"),
            ts.split(' ').next_back().unwrap_or(""),
            f["event"]["host"].as_str().unwrap_or("?"),
            f["title"].as_str().unwrap_or(""),
            f["env_basis"]["criticality"].as_f64().unwrap_or(0.0),
        );
    }
    Ok(())
}

/// `garmr shadow` — the DoD-19 champion/challenger comparison summary. Daemon-
/// first (the live plane owns the in-memory counters); falls back to the
/// persisted summary blob when the daemon is stopped.
pub(crate) async fn shadow_cmd(cli: &Cli) -> Result<()> {
    let cfg = load_config(cli)?;
    let v = match try_daemon_get(&cfg, "/api/shadow/summary").await? {
        Some(v) => v,
        None => {
            let store = Store::open(&cfg).await?;
            match store.state.get_app_shadow_summary()? {
                Some(bytes) => {
                    let s: crate::shadow::ShadowSummary = serde_json::from_slice(&bytes)?;
                    // Offline (daemon down): we can only report the LAST persisted
                    // comparison — we cannot confirm the challenger is still live, so
                    // `has_challenger` reflects whether one was ever recorded.
                    let had_challenger = !s.challenger_name.is_empty();
                    let recommendation = crate::shadow::recommendation(&s, had_challenger);
                    serde_json::json!({
                        "enabled": true,
                        "active_challenger": {
                            "name": s.challenger_name, "version": s.challenger_version,
                        },
                        "events_scored": s.events_scored,
                        "diff_events": s.diff_events,
                        "challenger_only": s.challenger_only,
                        "champion_only": s.champion_only,
                        "dangerous_misses": s.dangerous_misses,
                        "recommendation": recommendation,
                    })
                }
                None => serde_json::json!({
                    "enabled": crate::shadow::shadow_enabled(),
                    "active_challenger": serde_json::Value::Null,
                    "recommendation": "no challenger registered on the shadow channel",
                }),
            }
        }
    };
    if v["active_challenger"].is_null() {
        println!(
            "shadow evaluation: no challenger live (enabled={})",
            v["enabled"].as_bool().unwrap_or(false)
        );
        println!("  {}", v["recommendation"].as_str().unwrap_or(""));
        return Ok(());
    }
    let ch = &v["active_challenger"];
    println!(
        "shadow evaluation — challenger {} v{}",
        ch["name"].as_str().unwrap_or("?"),
        ch["version"].as_str().unwrap_or("?")
    );
    println!(
        "  events scored    : {}",
        v["events_scored"].as_u64().unwrap_or(0)
    );
    println!(
        "  diff events      : {}",
        v["diff_events"].as_u64().unwrap_or(0)
    );
    println!(
        "  challenger-only  : {}",
        v["challenger_only"].as_u64().unwrap_or(0)
    );
    println!(
        "  champion-only    : {}",
        v["champion_only"].as_u64().unwrap_or(0)
    );
    println!(
        "  dangerous misses : {}",
        v["dangerous_misses"].as_u64().unwrap_or(0)
    );
    println!(
        "  recommendation   : {}",
        v["recommendation"].as_str().unwrap_or("")
    );
    Ok(())
}

pub(crate) async fn cases(cli: &Cli, what: &CasesCmd) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    match what {
        CasesCmd::List => {
            let cases = store.state.list_cases()?;
            if cases.is_empty() {
                println!("(no cases)");
            }
            for c in &cases {
                println!(
                    "{}  {:<12}  {:<28}  host={:<10} ip={:<15} n={:<4} {}",
                    c.id.get(..8).unwrap_or(&c.id),
                    format!("{:?}", c.state),
                    c.trigger.rule_id,
                    c.trigger.event.host,
                    c.trigger.event.src_ip().unwrap_or("-"),
                    c.event_count,
                    c.verdict
                        .as_ref()
                        .map(|v| format!("{:?}/sev{}", v.disposition, v.severity))
                        .unwrap_or_default(),
                );
            }
        }
        CasesCmd::Show { id } => {
            let case = match store.state.get_case(id)? {
                Some(c) => c,
                None => {
                    find_by_prefix(&store, id)?.with_context(|| format!("no case matching {id}"))?
                }
            };
            print_case(&case);
        }
        CasesCmd::Prune {
            older_than_days,
            opened_after,
            opened_before,
            states,
            rule,
            source,
            yes,
        } => {
            let cutoff = older_than_days.map(|d| chrono::Utc::now() - chrono::Duration::days(d));
            let after = opened_after.as_deref().map(parse_rfc3339).transpose()?;
            let before = opened_before.as_deref().map(parse_rfc3339).transpose()?;
            let want_states = states
                .iter()
                .map(|s| parse_case_state(s))
                .collect::<Result<Vec<_>>>()?;
            let has_filter = older_than_days.is_some()
                || after.is_some()
                || before.is_some()
                || !want_states.is_empty()
                || rule.is_some()
                || source.is_some();
            if !has_filter {
                anyhow::bail!(
                    "cases prune: refusing to delete unfiltered — pass at least one of \
                     --older-than-days / --opened-after / --opened-before / --state / --rule / --source"
                );
            }
            let all = store.state.list_cases()?;
            let matched: Vec<&Case> = all
                .iter()
                .filter(|c| {
                    cutoff.is_none_or(|t| c.updated_at < t)
                        && after.is_none_or(|t| c.opened_at >= t)
                        && before.is_none_or(|t| c.opened_at <= t)
                        && (want_states.is_empty() || want_states.contains(&c.state))
                        && rule.as_ref().is_none_or(|r| &c.trigger.rule_id == r)
                        && source.as_ref().is_none_or(|s| &c.trigger.event.source == s)
                })
                .collect();
            println!("matched {} / {} cases:", matched.len(), all.len());
            for c in matched.iter().take(50) {
                println!(
                    "  {}  {:<12}  {:<24}  src={:<10} opened={}",
                    c.id.get(..8).unwrap_or(&c.id),
                    format!("{:?}", c.state),
                    c.trigger.rule_id,
                    c.trigger.event.source,
                    c.opened_at.format("%Y-%m-%dT%H:%M:%SZ"),
                );
            }
            if matched.len() > 50 {
                println!("  … and {} more", matched.len() - 50);
            }
            if *yes {
                let ids: Vec<String> = matched.iter().map(|c| c.id.clone()).collect();
                let n = store.state.delete_cases(&ids)?;
                println!("\ndeleted {n} cases");
            } else {
                println!(
                    "\n(dry-run — pass --yes to delete these {} cases)",
                    matched.len()
                );
            }
        }
    }
    Ok(())
}

/// `garmr models` — show the model-routing catalog + the fence decision per data
/// class, OFFLINE (config only, no store, no spend). Reflects the CURRENT egress
/// policy that `load_config` installed (GARMR_AIRGAP + [route.egress]).
pub(crate) async fn models_cmd(cli: &Cli, for_sensitivity: Option<&str>) -> Result<()> {
    use garmr_core::{
        decide, DataClassification, LlmBackend, ModelEntry, RouteDecision, RouteInput,
    };
    let cfg = load_config(cli)?;
    let egress = garmr_core::egress::global();
    let rcfg = &cfg.route.router;

    println!("air-gap:               {}", egress.is_airgap());
    println!(
        "classification floor:  {}",
        rcfg.default_classification.as_str()
    );
    println!("catalog ({} configured model(s)):", rcfg.models.len());

    let default_entry = ModelEntry {
        name: "agent (default)".into(),
        backend: cfg.agent.backend,
        model: cfg.agent.model.clone(),
        openai_base_url: cfg.agent.openai_base_url.clone(),
        max_sensitivity: None,
        enabled: true,
        role: "agent".into(),
    };
    let show = |e: &ModelEntry| {
        let host = e
            .openai_base_url
            .as_deref()
            .and_then(garmr_core::host_of)
            .map(|s| s.to_string())
            .unwrap_or_else(|| match e.backend {
                LlmBackend::Anthropic => "api.anthropic.com".into(),
                LlmBackend::OpenAiCompat => "localhost".into(),
            });
        println!(
            "  {:<18} [{:?}] model={} host={} {} ceiling={} enabled={}",
            e.name,
            e.backend,
            e.model,
            host,
            if e.is_local() { "local" } else { "external" },
            e.ceiling().as_str(),
            e.enabled,
        );
    };
    show(&default_entry);
    for e in &rcfg.models {
        show(e);
    }

    if let Some(s) = for_sensitivity {
        let class = DataClassification::from_tag(s).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown sensitivity '{s}' (public|internal|confidential|restricted|secret)"
            )
        })?;
        let candidates: &[ModelEntry] = if rcfg.models.is_empty() {
            std::slice::from_ref(&default_entry)
        } else {
            &rcfg.models
        };
        match decide(
            candidates,
            RouteInput {
                classification: class,
                airgap: egress.is_airgap(),
            },
        ) {
            RouteDecision::Use(i) => {
                println!(
                    "\n{} data → routes to: {}",
                    class.as_str(),
                    candidates[i].name
                )
            }
            RouteDecision::Degraded(r) => {
                println!("\n{} data → DEGRADED → NeedsHuman ({r})", class.as_str())
            }
        }
    }
    Ok(())
}
