// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-correlate` — correlation rules as code.
//!
//! Sigma (in `garmr-detect`) fires on a *single* event. Real incidents are
//! often multi-event and windowed: ten failed logins *then* a success from the
//! same IP, privileged activity *at night*, a burst of service failures. Those
//! are expressed here as TOML rules carrying a read-only SQL query over the
//! `events` lakehouse, a MITRE ATT&CK tag, a severity, a schedule and a window
//! — the "ES-content-as-code" pattern proven in soc-infra's warehouse, ported
//! onto garmr's schema.
//!
//! A rule's hits become synthetic [`Detection`]s, so a correlation finding
//! flows into the exact same [`Case`](garmr_core::Case) → agent-triage → Matrix
//! path as a Sigma detection. The SQL supports two run-time placeholders:
//! `{since_us}` (window start, µs) and `{now_us}` (now, µs).

mod rule;

use chrono::{DateTime, Utc};
use garmr_core::{Detection, Error, Event, Result};
use garmr_store::Store;
use skade::arrow_array::RecordBatch;
use skade::arrow_cast::display::array_value_to_string;
use std::collections::BTreeMap;
use std::path::Path;

pub use rule::{load_rules, Rule};

/// The loaded correlation rule set.
pub struct CorrelationEngine {
    rules: Vec<Rule>,
}

impl CorrelationEngine {
    /// Load every `*.toml` correlation rule under `dir`. A malformed rule is
    /// logged and skipped so one bad file can't disable the rest.
    pub fn load(dir: &Path) -> Self {
        Self {
            rules: load_rules(dir),
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Run every rule whose schedule is due at `now`, over the window each rule
    /// declares, returning the synthetic detections for all fresh hits. Used by
    /// the scheduled correlation task.
    pub async fn run_due(
        &self,
        store: &Store,
        now: DateTime<Utc>,
        last_run: &mut BTreeMap<String, i64>,
    ) -> Vec<Detection> {
        let now_us = now.timestamp_micros();
        let mut out = Vec::new();
        for rule in &self.rules {
            let prev = last_run.get(&rule.id).copied();
            let due = prev
                .map(|t| now_us - t >= rule.schedule_secs as i64 * 1_000_000)
                .unwrap_or(true);
            if !due {
                continue;
            }
            // Reach back to the window start, but never past the previous run —
            // so successive windows OVERLAP and an event that arrived after the
            // last query (but timestamped before this window's start) is still
            // scanned. Duplicate re-emission is harmless: the suppression window
            // dedupes it. Without this, tick granularity leaves a trailing-edge
            // blind spot when window_secs <= schedule_secs.
            let window_start = now_us - rule.window_secs() as i64 * 1_000_000;
            let since_us = prev.map_or(window_start, |p| window_start.min(p));
            match self.run_rule(store, rule, since_us, now_us, now).await {
                Ok(dets) => {
                    // Commit last_run only on success: a failed run (e.g. a
                    // transient store error racing a compaction swap) retries
                    // from the same `prev` next tick — advancing it first would
                    // permanently skip that window's detections.
                    last_run.insert(rule.id.clone(), now_us);
                    out.extend(dets);
                }
                Err(e) => {
                    tracing::warn!(rule = %rule.id, error = %e, "correlation rule failed (will retry next tick)")
                }
            }
        }
        out
    }

    /// Run every rule once over the window `[since_us, now]`, ignoring the
    /// schedule. `since_us = 0` correlates the entire event history. Used by the
    /// on-demand `garmr correlate` command and tests.
    pub async fn run_all(
        &self,
        store: &Store,
        since_us: i64,
        now: DateTime<Utc>,
    ) -> Result<Vec<Detection>> {
        let now_us = now.timestamp_micros();
        let mut out = Vec::new();
        for rule in &self.rules {
            // Log-and-continue (like run_due) so one malformed rule can't abort
            // the whole on-demand hunt.
            match self.run_rule(store, rule, since_us, now_us, now).await {
                Ok(dets) => out.extend(dets),
                Err(e) => {
                    tracing::warn!(rule = %rule.id, error = %e, "correlation rule failed (skipped)")
                }
            }
        }
        Ok(out)
    }

    /// Execute one rule's SQL and turn each hit row into a [`Detection`].
    async fn run_rule(
        &self,
        store: &Store,
        rule: &Rule,
        since_us: i64,
        now_us: i64,
        now: DateTime<Utc>,
    ) -> Result<Vec<Detection>> {
        let sql = rule.render_sql(since_us, now_us);
        reject_non_readonly(&sql)?;
        let batches = store.events.sql(sql).await?;
        Ok(rows_to_detections(rule, &batches, now))
    }
}

/// Convert result rows into synthetic detections. Convention: the query returns
/// a `host` column and (optionally) a `src_ip`/`key_ip`/`ip` column. The case
/// dedup key is name-based — `Detection::dedup_key` uses `rule_id | host |
/// (src_ip else user else '-')`, not column position — so a rule that wants
/// per-host dedup should simply not emit a `src_ip`. Every column is carried
/// into the event's `fields` so the agent sees the aggregate during triage.
/// A batch with at least this many hit rows fans its per-row detection build
/// across cores; below it the scoped-thread spawn would cost more than it saves.
const PARALLEL_ROW_THRESHOLD: usize = 512;

fn rows_to_detections(rule: &Rule, batches: &[RecordBatch], now: DateTime<Utc>) -> Vec<Detection> {
    let attack: Vec<String> = rule
        .attack
        .split("->")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let mut out = Vec::new();
    for b in batches {
        let names: Vec<String> = b
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().to_string())
            .collect();
        // Each row is an independent Detection (no cross-row state) and the body
        // is CPU-bound (per-cell Arrow formatting + a BTreeMap + a JSON serialize +
        // a format!), so for a wide result the rows fan across every core with
        // gatling's no-barrier fork-join (ROOT LAW #0 — no rayon). Results come
        // back in index order, so the order-sensitive downstream case dedup behaves
        // exactly as the old serial loop. `RecordBatch` columns are `Arc`
        // (Send+Sync), so the closure borrows the batch with no clone. Below the
        // threshold a serial pass avoids the scoped-thread spawn (most correlation
        // rules aggregate to a handful of hit rows).
        let n = b.num_rows();
        if n >= PARALLEL_ROW_THRESHOLD {
            out.extend(gatling::gatling_forkjoin::gatling_for_each(n, 0, |row| {
                row_to_detection(rule, b, &names, &attack, now, row)
            }));
        } else {
            out.extend((0..n).map(|row| row_to_detection(rule, b, &names, &attack, now, row)));
        }
    }
    out
}

/// Build one correlation [`Detection`] from row `row` of `b`. Split out of
/// [`rows_to_detections`] so the per-row work can be fanned across cores; pure and
/// self-contained (no shared mutable state), so it is safe to call concurrently.
#[allow(clippy::too_many_arguments)]
fn row_to_detection(
    rule: &Rule,
    b: &RecordBatch,
    names: &[String],
    attack: &[String],
    now: DateTime<Utc>,
    row: usize,
) -> Detection {
    let mut fields = BTreeMap::new();
    for (col, name) in names.iter().enumerate() {
        let v = array_value_to_string(b.column(col), row).unwrap_or_default();
        fields.insert(name.clone(), v);
    }
    let host = fields.get("host").cloned().unwrap_or_default();
    // Promote a source IP for the dedup key / agent tools if the row
    // carries one under a conventional name.
    if !fields.contains_key("src_ip") {
        for k in ["key_ip", "ip", "source_ip"] {
            if let Some(v) = fields.get(k) {
                fields.insert("src_ip".to_string(), v.clone());
                break;
            }
        }
    }
    let hit = serde_json::to_string(&fields).unwrap_or_default();
    let event = Event {
        ts: now,
        host: if host.is_empty() {
            "-".into()
        } else {
            host.into()
        },
        service: "correlation".into(),
        source: "garmr-correlate".into(),
        environment: fields
            .get("environment")
            .cloned()
            .unwrap_or_else(|| "prod".to_string())
            .into(),
        severity: rule.severity.clone().into(),
        log_type: "correlation".into(),
        message: format!(
            "{} [{}] — {} | hit: {}",
            rule.title, rule.attack, rule.message, hit
        ),
        fields,
    };
    Detection {
        rule_id: rule.id.clone(),
        rule_title: rule.title.clone(),
        level: rule.severity.clone(),
        attack: attack.to_vec(),
        event,
        observed_at: now,
        realert_secs: Some(rule.realert_secs),
    }
}

/// Correlation rules are operator-authored and trusted, but still guarded:
/// only a single `SELECT`/`WITH` query runs.
fn reject_non_readonly(sql: &str) -> Result<()> {
    let upper = sql.trim_start().to_uppercase();
    if upper.starts_with("SELECT") || upper.starts_with("WITH") {
        Ok(())
    } else {
        Err(Error::Detect(
            "correlation rule SQL must be SELECT/WITH".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use chrono::TimeZone;
    use garmr_core::{
        AgentConfig, Config, DetectConfig, Event, IngestConfig, LlmBackend, StoreConfig,
    };

    use super::*;

    /// The SHIPPED correlation rules live at the repo root, two levels up from
    /// this crate — the test fires the real files so a broken rule SQL (or a
    /// schema drift) is caught in CI, not just in production.
    fn shipped_correlations_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../correlations")
    }

    fn tmp(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("garmr-correlate-{tag}-{n}"))
    }

    fn cfg(base: &std::path::Path) -> Config {
        Config {
            audit: Default::default(),
            store: StoreConfig {
                warehouse_dir: base.join("wh"),
                state_db: base.join("state.redb"),
                search_dir: base.join("search"),
                retention_days: 90,
                compact_snapshot_threshold: 0,
                compact_gc_grace_secs: 300,
                fulltext_exclude_sources: vec![],
            },
            ingest: IngestConfig {
                ingest_bind: None,
                loki_bind: "127.0.0.1:0".into(),
                syslog_bind: None,
                default_environment: "test".into(),
                api_bind: None,
                ui_dir: None,
                dedup_recent: 0,
                flight_bind: None,
            },
            detect: DetectConfig {
                rules_dir: base.join("rules"),
                correlations_dir: shipped_correlations_dir(),
                realert_secs: 900,
                hunts_dir: base.join("hunts"),
                app_audit_enabled: false,
                policies_dir: std::path::PathBuf::from("policies"),
                catalog_file: None,
                monitoring_file: None,
                anomaly_enabled: false,
                anomaly_min_count: 3,
                anomaly_max_per_tick: 0,
                anomaly_exclude_sources: vec![],
                risk_enabled: false,
                risk_threshold: 20.0,
                risk_halflife_hours: 12.0,
                risk_realert_secs: 3600,
                freq_baseline_enabled: false,
                freq_k: 3.0,
                freq_min_count: 20,
                prediction_discount: 0.5,
            },
            agent: AgentConfig {
                backend: LlmBackend::Anthropic,
                model: "m".into(),
                prefilter_model: None,
                openai_base_url: None,
                max_iterations: 4,
                max_tokens: 1024,
                daily_budget_usd: 5.0,
                allow_online_lookups: false,
                geoip_dir: None,
                ioc_feeds: vec![],
                mcp_servers: vec![],
            },
            retention: Default::default(),
            route: Default::default(),
            executor: Default::default(),
            ha: Default::default(),
            environment: Default::default(),
            matrix: None,
        }
    }

    /// One access-audit event. `ts` is fixed (not `now`) so the off-hours rule's
    /// `date_part('hour', …)` is deterministic regardless of when the test runs.
    /// `flags` sets app-supplied boolean markers (e.g. "watched", "is_self").
    /// Note the source is a NON-Postgres label ("app-audit") — the rules key on
    /// log_type='audit', so they must fire regardless of the source string.
    fn audit_ev(
        db_user: &str,
        target: &str,
        ticket: Option<&str>,
        ts: chrono::DateTime<Utc>,
        flags: &[&str],
    ) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("db_user".into(), db_user.into());
        fields.insert("target_person".into(), target.into());
        fields.insert("object_table".into(), "person".into());
        fields.insert("client_addr".into(), "10.0.0.12".into());
        if let Some(t) = ticket {
            fields.insert("ticket_ref".into(), t.into());
        }
        for f in flags {
            fields.insert((*f).into(), "true".into());
        }
        Event {
            ts,
            host: "pgserver".into(),
            service: "registerlookup".into(),
            source: "app-audit".into(),
            environment: "test".into(),
            severity: "info".into(),
            log_type: "audit".into(),
            message: format!("access db_user={db_user} target={target}"),
            fields,
        }
    }

    #[tokio::test]
    async fn shipped_registerkontroll_rules_fire_per_staff() {
        let base = tmp("reg");
        std::fs::create_dir_all(&base).unwrap();
        let store = Store::open_writable(&cfg(&base)).await.unwrap();

        // A fixed working-hour weekday (2026-06-15 is a Monday) and a fixed
        // night, both in the past so `since_us = 0` includes them.
        let day = Utc.with_ymd_and_hms(2026, 6, 15, 10, 0, 0).unwrap();
        let night = Utc.with_ymd_and_hms(2026, 6, 15, 23, 30, 0).unwrap();

        let mut events = Vec::new();
        // anna.h: 60 in-hours lookups, all ticketed → bulk (>=50) only.
        for i in 0..60 {
            events.push(audit_ev(
                "anna.h",
                &format!("subject-{i:04}"),
                Some("AR-2026-4711"),
                day,
                &[],
            ));
        }
        // bob.k, night, watched flag, NO ticket → off-hours + watchlist + no-ticket.
        events.push(audit_ev(
            "bob.k",
            "subject-watched",
            None,
            night,
            &["watched"],
        ));
        // bob.k, in-hours, is_self flag → self-lookup.
        events.push(audit_ev(
            "bob.k",
            "subject-bob",
            Some("AR-1"),
            day,
            &["is_self"],
        ));
        store.events.append(events).await.unwrap();

        // since_us = 0 → correlate the whole (fixed) history.
        let dets = CorrelationEngine::load(&shipped_correlations_dir())
            .run_all(&store, 0, Utc::now())
            .await
            .unwrap();

        let ids: std::collections::BTreeSet<&str> =
            dets.iter().map(|d| d.rule_id.as_str()).collect();
        for expected in [
            "reg_bulk_lookups_by_user",
            "reg_off_hours_lookup",
            "reg_watchlist_target_lookup",
            "reg_lookup_without_ticket",
            "reg_self_lookup",
        ] {
            assert!(
                ids.contains(expected),
                "rule {expected} did not fire: {ids:?}"
            );
        }

        // Bulk is attributed to anna.h and dedups PER STAFF (db_user is the
        // principal), not per host.
        let bulk = dets
            .iter()
            .find(|d| d.rule_id == "reg_bulk_lookups_by_user")
            .unwrap();
        assert_eq!(bulk.event.field("db_user"), Some("anna.h"));
        assert_eq!(bulk.dedup_key(), "reg_bulk_lookups_by_user|pgserver|anna.h");
        assert_eq!(bulk.event.field("lookups"), Some("60"));

        // The staff-scoped rules for bob.k carry his db_user + the target person.
        let watch = dets
            .iter()
            .find(|d| d.rule_id == "reg_watchlist_target_lookup")
            .unwrap();
        assert_eq!(watch.event.field("db_user"), Some("bob.k"));
        assert_eq!(watch.event.field("target_person"), Some("subject-watched"));
        assert_eq!(watch.level, "critical");

        // anna.h's ticketed in-hours lookups must NOT trip off-hours / no-ticket.
        let anna_offenders = dets.iter().any(|d| {
            d.event.field("db_user") == Some("anna.h")
                && (d.rule_id == "reg_off_hours_lookup" || d.rule_id == "reg_lookup_without_ticket")
        });
        assert!(
            !anna_offenders,
            "clean in-hours ticketed lookups false-fired"
        );
    }

    /// The gatling fan-out over hit rows must produce EXACTLY the serial result —
    /// same detections, SAME ORDER (the downstream case dedup is order-sensitive).
    /// Drives a batch past `PARALLEL_ROW_THRESHOLD` so the parallel path runs, then
    /// checks every detection against a serial oracle. Red the instant the fan-out
    /// misorders a row or drops the index-order contract.
    #[test]
    fn parallel_rows_to_detections_match_serial_in_order() {
        use skade::arrow_array::{RecordBatch, StringArray};
        use skade::arrow_schema::{DataType, Field, Schema};
        use std::sync::Arc;

        let rule = Rule {
            id: "r1".into(),
            title: "t1".into(),
            attack: "T1110->T1078".into(),
            severity: "high".into(),
            schedule_secs: 60,
            window_secs: None,
            realert_secs: 900,
            message: "m".into(),
            sql: "SELECT host FROM events".into(),
            params: BTreeMap::new(),
        };
        let now = chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap();

        let n = PARALLEL_ROW_THRESHOLD + 137; // safely into the parallel regime
        let hosts: Vec<String> = (0..n).map(|i| format!("host-{i}")).collect();
        let batch = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("host", DataType::Utf8, false)])),
            vec![Arc::new(StringArray::from(hosts.clone())) as _],
        )
        .unwrap();

        let dets = rows_to_detections(&rule, std::slice::from_ref(&batch), now);
        assert_eq!(dets.len(), n);

        // Serial oracle, row by row: same host, same attack, same order.
        let attack = ["T1110".to_string(), "T1078".to_string()];
        for (i, d) in dets.iter().enumerate() {
            let oracle = row_to_detection(&rule, &batch, &["host".to_string()], &attack, now, i);
            assert_eq!(d.event.host, hosts[i], "row {i} host out of order");
            assert_eq!(d.event.host, oracle.event.host, "row {i} vs serial oracle");
            assert_eq!(d.event.message, oracle.event.message, "row {i} message");
            assert_eq!(d.attack, oracle.attack, "row {i} attack");
        }
    }
}
