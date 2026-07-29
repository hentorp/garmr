// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Draft validation + backtesting: the gate between an LLM-submitted rule and a
//! persisted proposal. A draft must parse (Sigma compiles / correlation TOML +
//! its read-only SQL guard), carry a rule id unique across the ruleset and open
//! proposals, and survive a backtest over recent events without being a
//! false-positive cannon. Every rejection is a plain-String message handed back
//! to the model so it can repair. Used at draft time by [`super::propose_rule`]
//! and again at enable time by [`super::approve`].

use chrono::Utc;
use garmr_core::{Backtest, Config, Event, ProposalKind, ProposalStatus};
use garmr_store::Store;
use serde_json::Value;

use crate::tools::reject_non_readonly;

/// Backtest window and caps.
const BACKTEST_HOURS: u32 = 24 * 7;
const BACKTEST_MAX_EVENTS: usize = 5_000;
const BACKTEST_SAMPLES: usize = 5;

/// Validate the submitted draft and backtest it. Returns the parsed fields or
/// a model-readable rejection.
pub(super) async fn validate_and_backtest(
    store: &Store,
    cfg: &Config,
    input: &Value,
) -> std::result::Result<(ProposalKind, String, String, String, Backtest), String> {
    let kind = match input.get("kind").and_then(Value::as_str) {
        Some("sigma") => ProposalKind::Sigma,
        Some("correlation") => ProposalKind::Correlation,
        other => return Err(format!("kind must be sigma|correlation (got {other:?})")),
    };
    let title = input
        .get("title")
        .and_then(Value::as_str)
        .filter(|t| !t.trim().is_empty())
        .ok_or("title missing")?
        .trim()
        .to_string();
    let rationale = input
        .get("rationale")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let rule_body = input
        .get("rule_body")
        .and_then(Value::as_str)
        .filter(|b| !b.trim().is_empty())
        .ok_or("rule_body missing")?
        .to_string();

    // The rule's id must be UNIQUE across the loaded ruleset and other
    // proposals — a colliding id silently cross-suppresses detections and
    // corrupts the get_rule audit map. Prompt guidance is not enforcement.
    let rule_id = extract_rule_id(kind, &rule_body).ok_or("the rule lacks an id field")?;
    if rule_id_in_use(store, cfg, &rule_id) {
        return Err(format!(
            "rule id '{rule_id}' is already in use (existing rule or another proposal) — choose a unique id"
        ));
    }

    let backtest = match kind {
        ProposalKind::Sigma => backtest_sigma(store, &rule_body).await?,
        ProposalKind::Correlation => backtest_correlation(store, &rule_body).await?,
    };
    // Gate before drafting: a rule that fires on a large fraction of all traffic
    // is a false-positive cannon. Hand the specifics back so the model tightens
    // the pattern instead of persisting a rule no analyst could ever live with.
    // A SILENT rule (0 hits) is allowed through — a detection for a threat that
    // hasn't happened is legitimately quiet; the human decides on that one.
    if backtest.health().is_noisy() {
        return Err(format!(
            "the rule is too noisy to propose: {}. Tighten the pattern (more specific \
             message|contains, more selectors, or a higher threshold).",
            backtest.describe()
        ));
    }
    Ok((kind, title, rationale, rule_body, backtest))
}

/// Pull the rule id out of the draft (sigma `id:` line / correlation `id =`).
fn extract_rule_id(kind: ProposalKind, body: &str) -> Option<String> {
    match kind {
        ProposalKind::Sigma => body.lines().find_map(|l| {
            l.strip_prefix("id:")
                .map(|v| v.trim().trim_matches(['"', '\'']).to_string())
        }),
        ProposalKind::Correlation => toml::from_str::<garmr_correlate::Rule>(body)
            .ok()
            .map(|r| r.id),
    }
    .filter(|id| !id.is_empty())
}

/// Is `rule_id` already taken by a rule ON DISK (either directory) or by a
/// pending/approved proposal? Best-effort reads; an unreadable dir counts as
/// no conflict (approval still lands in a dir the operator controls).
fn rule_id_in_use(store: &Store, cfg: &Config, rule_id: &str) -> bool {
    let dir_has = |dir: &std::path::Path, exts: &[&str], probe: &dyn Fn(&str) -> Option<String>| {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        entries.flatten().any(|e| {
            let path = e.path();
            let ok_ext = path
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| exts.contains(&x));
            ok_ext
                && std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|t| probe(&t))
                    .is_some_and(|id| id == rule_id)
        })
    };
    if dir_has(&cfg.detect.rules_dir, &["yml", "yaml"], &|t| {
        extract_rule_id(ProposalKind::Sigma, t)
    }) {
        return true;
    }
    if dir_has(&cfg.detect.correlations_dir, &["toml"], &|t| {
        extract_rule_id(ProposalKind::Correlation, t)
    }) {
        return true;
    }
    store.state.list_proposals().ok().is_some_and(|ps| {
        ps.iter().any(|p| {
            p.status != ProposalStatus::Rejected
                && extract_rule_id(p.kind, &p.rule_body).as_deref() == Some(rule_id)
        })
    })
}

/// Compile the Sigma YAML and replay recent events through it.
pub(super) async fn backtest_sigma(
    store: &Store,
    yaml: &str,
) -> std::result::Result<Backtest, String> {
    let detector = garmr_detect::Detector::from_yaml(yaml)
        .map_err(|e| format!("the sigma rule does not compile: {e}"))?;
    if detector.rule_count() == 0 {
        return Err("the yaml contains no rule".into());
    }
    let sql = format!(
        "SELECT event_ts, host, service, source, environment, severity, log_type, message, fields \
         FROM events WHERE event_ts >= now() - INTERVAL '{BACKTEST_HOURS} hours' \
         ORDER BY event_ts DESC LIMIT {BACKTEST_MAX_EVENTS}"
    );
    let batches = tokio::time::timeout(std::time::Duration::from_secs(60), store.events.sql(sql))
        .await
        .map_err(|_| "the backtest query took too long".to_string())?
        .map_err(|e| format!("the backtest query failed: {e}"))?;
    let events = events_from_batches(&batches);
    let scanned = events.len() as u64;
    let mut hits = 0u64;
    let mut samples = Vec::new();
    for ev in &events {
        if !detector.evaluate(ev).is_empty() {
            hits += 1;
            if samples.len() < BACKTEST_SAMPLES {
                samples.push(format!(
                    "{} {} {}: {}",
                    ev.ts, ev.host, ev.service, ev.message
                ));
            }
        }
    }
    Ok(Backtest {
        scanned,
        hits,
        samples,
        window_hours: BACKTEST_HOURS,
        // The human must know the coverage claim is capped — "0 hits" over a
        // truncated scan is weaker evidence than over the full window.
        scan_capped: events.len() >= BACKTEST_MAX_EVENTS,
    })
}

/// Parse the correlation TOML, guard its SQL, and run it over the rule's OWN
/// window (ending now) — running a threshold rule over a 168h span would
/// over-count relative to how it will actually fire on schedule.
pub(super) async fn backtest_correlation(
    store: &Store,
    toml_body: &str,
) -> std::result::Result<Backtest, String> {
    let rule: garmr_correlate::Rule =
        toml::from_str(toml_body).map_err(|e| format!("the toml does not parse: {e}"))?;
    let now_us = Utc::now().timestamp_micros();
    let since_us = now_us - (rule.window_secs() as i64) * 1_000_000;
    let sql = rule.render_sql(since_us, now_us);
    reject_non_readonly(&sql)
        .map_err(|e| format!("the rule's SQL was rejected by the guard: {e}"))?;
    let batches = tokio::time::timeout(std::time::Duration::from_secs(60), store.events.sql(sql))
        .await
        .map_err(|_| "the backtest query took too long".to_string())?
        .map_err(|e| format!("the rule's SQL failed: {e}"))?;
    let hits: u64 = batches.iter().map(|b| b.num_rows() as u64).sum();
    let mut samples = Vec::new();
    if let Some(b) = batches.first() {
        use skade::arrow_cast::display::{ArrayFormatter, FormatOptions};
        let opts = FormatOptions::default();
        if let Ok(fmts) = b
            .columns()
            .iter()
            .map(|c| ArrayFormatter::try_new(c.as_ref(), &opts))
            .collect::<std::result::Result<Vec<_>, _>>()
        {
            for row in 0..b.num_rows().min(BACKTEST_SAMPLES) {
                samples.push(
                    fmts.iter()
                        .map(|f| f.value(row).to_string())
                        .collect::<Vec<_>>()
                        .join(" | "),
                );
            }
        }
    }
    Ok(Backtest {
        scanned: 0, // rows-returned has no "examined" denominator — don't fake one
        hits,
        samples,
        window_hours: (rule.window_secs() / 3600).max(1) as u32,
        scan_capped: false,
    })
}

/// Rebuild `Event`s from the stringly SQL result (the inverse of the events
/// schema, for backtesting only — sub-second precision is irrelevant here).
fn events_from_batches(batches: &[skade::arrow_array::RecordBatch]) -> Vec<Event> {
    use skade::arrow_cast::display::{ArrayFormatter, FormatOptions};
    let opts = FormatOptions::default();
    let mut out = Vec::new();
    for b in batches {
        let names: Vec<String> = b
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().to_string())
            .collect();
        let Ok(fmts) = b
            .columns()
            .iter()
            .map(|c| ArrayFormatter::try_new(c.as_ref(), &opts))
            .collect::<std::result::Result<Vec<_>, _>>()
        else {
            continue;
        };
        let col = |name: &str, row: usize| -> String {
            names
                .iter()
                .position(|n| n == name)
                .map(|i| fmts[i].value(row).to_string())
                .unwrap_or_default()
        };
        for row in 0..b.num_rows() {
            let ts = chrono::NaiveDateTime::parse_from_str(
                &col("event_ts", row),
                "%Y-%m-%dT%H:%M:%S%.f",
            )
            .or_else(|_| {
                chrono::NaiveDateTime::parse_from_str(&col("event_ts", row), "%Y-%m-%d %H:%M:%S%.f")
            })
            .map(|n| n.and_utc())
            .unwrap_or_else(|_| Utc::now());
            let fields: std::collections::BTreeMap<String, String> =
                serde_json::from_str(&col("fields", row)).unwrap_or_default();
            out.push(Event {
                ts,
                host: col("host", row).into(),
                service: col("service", row).into(),
                source: col("source", row).into(),
                environment: col("environment", row).into(),
                severity: col("severity", row).into(),
                log_type: col("log_type", row).into(),
                message: col("message", row),
                fields,
            });
        }
    }
    out
}