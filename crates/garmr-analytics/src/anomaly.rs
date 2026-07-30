// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! New-template anomaly detection (M4) — adapted from the warehouse prototype
//! to garmr's architecture.
//!
//! A log line whose *shape* (its [`templatize`]d form) has never been seen
//! before is a strong, explainable signal (Drain/DeepLog-style). This detector
//! templatizes recent event messages, records each shape's first-seen time in
//! the state store, and — for shapes genuinely NEW since a baseline instant —
//! emits a synthetic [`Detection`] that flows through the SAME case machinery
//! as Sigma, correlation and hunt findings. garmr is the SIEM, so there is no
//! push-back to an upstream log store: a new template becomes a case like
//! everything else.
//!
//! KNOWN LIMITATION (inherent to shape-based detection): an attacker who
//! controls log content can evade the new-template signal by crafting a line
//! whose masked shape matches an EXISTING benign template (whitespace is
//! normalized and numbers/IPs/hex are masked, so the shape is coarse). This is
//! why new-template anomaly is ONE signal among many (Sigma, correlation,
//! hunts, RBA) and never the sole guard — it catches the un-careful, not the
//! shape-aware adversary.
//!
//! Two quiet-guards, same as the prototype:
//! - **Seed at startup.** [`seed`] records every template already present in
//!   the window WITHOUT alerting, so turning the detector on doesn't storm on
//!   the existing corpus — only shapes emerging AFTER the seed are flagged.
//! - **min_count.** A shape must recur at least `min_count` times in the
//!   window before it's worth a case (a single odd line is noise).

use garmr_core::{Detection, Event, Result};
use garmr_store::Store;
use skade::arrow_array::{Array, StringArray, TimestampMicrosecondArray};

use crate::template::templatize;

/// A window's worth of recent messages, oldest→newest, with host + ts.
struct Row {
    ts_us: i64,
    host: String,
    service: String,
    message: String,
}

/// Longest message length templatized — a pathological multi-KB line is
/// truncated first (templatize is linear, but there is no point shaping MBs).
const MAX_MSG_LEN: usize = 4096;

/// Build ` AND source NOT IN ('a','b')` (empty if no exclusions). Source names
/// are config-controlled; single-quotes are escaped defensively against SQLi.
fn source_excl(exclude: &[String]) -> String {
    if exclude.is_empty() {
        return String::new();
    }
    let list = exclude
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    format!("AND source NOT IN ({list}) ")
}

/// Pull recent event rows for templating — the DETECT input (needs per-shape
/// count + host + ts, so raw rows, newest first). A detect-window miss only
/// delays an alert to a later tick; it never causes a false positive, because
/// novelty is gated on the (thoroughly seeded) TEMPLATES table, not on this
/// window.
async fn recent_rows(store: &Store, hours: u32, limit: usize, excl: &str) -> Result<Vec<Row>> {
    let sql = format!(
        "SELECT event_ts, host, service, message FROM events \
         WHERE event_ts >= now() - INTERVAL '{hours} hours' \
           AND log_type <> 'anomaly' {excl}\
         ORDER BY event_ts DESC LIMIT {limit}"
    );
    let batches = store.events.sql(sql).await?;
    let mut out = Vec::new();
    for b in &batches {
        let ts = b
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>();
        let host = b.column(1).as_any().downcast_ref::<StringArray>();
        let svc = b.column(2).as_any().downcast_ref::<StringArray>();
        let msg = b.column(3).as_any().downcast_ref::<StringArray>();
        let (Some(ts), Some(host), Some(svc), Some(msg)) = (ts, host, svc, msg) else {
            continue;
        };
        for i in 0..b.num_rows() {
            if !msg.is_valid(i) {
                continue;
            }
            out.push(Row {
                ts_us: if ts.is_valid(i) { ts.value(i) } else { 0 },
                host: if host.is_valid(i) {
                    host.value(i).into()
                } else {
                    String::new()
                },
                service: if svc.is_valid(i) {
                    svc.value(i).into()
                } else {
                    String::new()
                },
                message: msg.value(i).into(),
            });
        }
    }
    Ok(out)
}

fn clamp(msg: &str) -> &str {
    if msg.len() <= MAX_MSG_LEN {
        return msg;
    }
    let mut cut = MAX_MSG_LEN;
    while !msg.is_char_boundary(cut) {
        cut -= 1;
    }
    &msg[..cut]
}

/// Record every DISTINCT shape currently in the window as baseline-known,
/// WITHOUT emitting anything, so turning the detector on doesn't storm on
/// history. Seeds from distinct messages (full shape coverage), not newest-N
/// rows. Returns `(recorded, truncated)`; `truncated` warns the operator that
/// the distinct-message cap was hit and the baseline is only partial (some old
/// shapes may later look "new").
pub async fn seed(
    store: &Store,
    hours: u32,
    limit: usize,
    exclude: &[String],
) -> Result<(usize, bool)> {
    // Seed on TEMPLATES, not distinct RAW messages. journald/Talos carry
    // millions of distinct raw lines (unique PIDs/timestamps/paths) but only
    // thousands of SHAPES; a `SELECT DISTINCT message` caps out on raw variation
    // and partial-seeds, then the detector floods on false-"new" common shapes.
    // Scan a bounded newest-row sample and record each DISTINCT template — shape
    // count is small, so a modest scan covers the common shapes completely.
    let excl = source_excl(exclude);
    let sql = format!(
        "SELECT message FROM events \
         WHERE event_ts >= now() - INTERVAL '{hours} hours' \
           AND log_type <> 'anomaly' {excl}\
         ORDER BY event_ts DESC LIMIT {limit}"
    );
    let batches = store.events.sql(sql).await?;
    let now_us = chrono::Utc::now().timestamp_micros();

    // Gather the valid messages across all batches (a cheap borrow of the Arrow
    // columns — no copy), then templatize them ACROSS CORES. Templatizing a
    // message is CPU-heavy and per-row independent, and seeding scans up to
    // SEED_LIMIT (400k) rows on startup while blocking the detector — so it uses
    // the SAME no-barrier fork-join `detect` uses for its window (ROOT LAW #0 —
    // no rayon), instead of the old fully-serial per-row templatize. Only the row
    // index crosses the channel (the closure borrows `msgs`), and `gatling_for_each`
    // returns in index order, so the serial dedup below sees template IDs in the
    // exact scan order the old loop did.
    let mut msgs: Vec<&str> = Vec::new();
    for b in &batches {
        let Some(msg) = b.column(0).as_any().downcast_ref::<StringArray>() else {
            continue;
        };
        for i in 0..b.num_rows() {
            if msg.is_valid(i) {
                msgs.push(msg.value(i));
            }
        }
    }
    let scanned = msgs.len();
    // Keep only the ID needed by the serial tail. Dropping each full Template in
    // the worker avoids retaining normalized text and attacker-controlled
    // parameter strings for every row in a seed of up to 400k messages.
    let template_ids: Vec<String> =
        gatling::gatling_forkjoin::gatling_for_each(msgs.len(), 0, |i| {
            templatize(clamp(msgs[i])).id
        });

    // Serial tail: the first-seen dedup + redb `note_template` write is
    // order-sensitive and hits the state store, so it stays serial — reading the
    // precomputed template IDs instead of recomputing each shape.
    let mut recorded = 0;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for id in &template_ids {
        if seen.insert(id.clone()) && store.state.note_template(id, now_us)? {
            recorded += 1;
        }
    }
    // `truncated` = the row scan hit its cap, so rare templates older than the
    // sample may be unseeded — they flag once when they next recur (correct).
    let truncated = scanned >= limit;
    Ok((recorded, truncated))
}

/// One detection pass. Templatize the window's messages, group by shape, and
/// for each shape that is (a) NOT already known AND (b) recurs at least
/// `min_count` times, emit a synthetic detection AND record it as known.
///
/// The record-only-on-alert order is the fix for the slow-introduction
/// evasion: a genuinely new shape seen only once or twice is left UNRECORDED,
/// so it can still fire the first tick it crosses `min_count` — an attacker
/// can't defeat the detector by drip-feeding a novel line below the threshold.
/// A shape that fires is recorded, so it never re-alerts.
pub async fn detect(
    store: &Store,
    hours: u32,
    limit: usize,
    min_count: u64,
    max_emit: usize,
    exclude: &[String],
) -> Result<Vec<Detection>> {
    let rows = recent_rows(store, hours, limit, &source_excl(exclude)).await?;
    // Group by shape: first row (for host/ts/service) + count + distinct hosts.
    struct Group {
        first_idx: usize,
        text: String,
        count: u64,
        hosts: std::collections::BTreeSet<String>,
    }
    let mut groups: std::collections::HashMap<String, Group> = std::collections::HashMap::new();
    let mut order: Vec<String> = Vec::new();
    // Phase 1 (PARALLEL, pure): templatizing a message is CPU-heavy and per-row
    // independent, so fan it out across a no-barrier worker pool. `gatling_for_each`
    // returns the results in index order, and only the row INDEX crosses the
    // channel (zero-copy — the closure borrows `rows`), so `templates[idx]`
    // corresponds exactly to `rows[idx]`.
    let templates: Vec<crate::template::Template> =
        gatling::gatling_forkjoin::gatling_for_each(rows.len(), 0, |i| {
            templatize(clamp(&rows[i].message))
        });
    // Phase 2 (SERIAL): the group-by is order-sensitive — first-seen shape decides
    // the `order`/`first_idx` — so it MUST stay serial to be byte-identical to the
    // original loop. It just reads the precomputed `templates[idx]` instead of
    // recomputing the shape.
    for (idx, r) in rows.iter().enumerate() {
        let t = &templates[idx];
        let g = groups.entry(t.id.clone()).or_insert_with(|| {
            order.push(t.id.clone());
            Group {
                first_idx: idx,
                text: t.text.clone(),
                count: 0,
                hosts: Default::default(),
            }
        });
        g.count += 1;
        if !r.host.is_empty() {
            g.hosts.insert(r.host.clone());
        }
    }

    let mut dets = Vec::new();
    let mut deferred = 0usize;
    for id in order {
        let g = &groups[&id];
        // Already-known (seeded or previously alerted) → skip WITHOUT touching
        // the table.
        if store.state.template_known(&id)? {
            continue;
        }
        // New but still below the noise floor → leave UNRECORDED so it can fire
        // when it later ramps up.
        if g.count < min_count {
            continue;
        }
        // Flood cap: emit at most `max_emit` new-template detections per tick.
        // Beyond it, leave the shape UNRECORDED (do NOT note_template) so it
        // fires on a later tick once the burst subsides — a log-landscape churn
        // (new sources/formats) can't storm the case store + agent budget in one
        // spike; no signal is lost, just paced. `0` = unlimited.
        if max_emit > 0 && dets.len() >= max_emit {
            deferred += 1;
            continue;
        }
        // Alert-worthy: record it now (race-safe — only the first caller that
        // inserts emits), then build the detection.
        if !store
            .state
            .note_template(&id, chrono::Utc::now().timestamp_micros())?
        {
            continue; // a concurrent pass already claimed it
        }
        let row = &rows[g.first_idx];
        dets.push(new_template_detection(&id, &g.text, g.count, &g.hosts, row));
    }
    if deferred > 0 {
        tracing::info!(
            emitted = dets.len(),
            deferred,
            "anomaly: new-template flood cap reached — deferring the rest to a later tick"
        );
    }
    Ok(dets)
}

fn new_template_detection(
    template_id: &str,
    template_text: &str,
    count: u64,
    hosts: &std::collections::BTreeSet<String>,
    row: &Row,
) -> Detection {
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("template_id".to_string(), template_id.to_string());
    fields.insert("template".to_string(), template_text.to_string());
    fields.insert("window_count".to_string(), count.to_string());
    // Cross-host spread is a signal in itself — a new shape on many hosts at
    // once is louder than one on a single host. Surface both.
    fields.insert("host_count".to_string(), hosts.len().to_string());
    if hosts.len() > 1 {
        fields.insert(
            "hosts".to_string(),
            hosts.iter().cloned().collect::<Vec<_>>().join(","),
        );
    }
    let observed =
        chrono::DateTime::from_timestamp_micros(row.ts_us).unwrap_or_else(chrono::Utc::now);
    Detection {
        rule_id: format!("garmr-anomaly-new-template-{template_id}"),
        rule_title: "New log template (never seen before)".into(),
        level: "medium".into(),
        attack: vec![],
        event: Event {
            ts: observed,
            host: row.host.clone().into(),
            service: row.service.clone().into(),
            source: "anomaly".into(),
            environment: "anomaly".into(),
            severity: "warning".into(),
            log_type: "anomaly".into(),
            message: format!("New log template ({count}x): {template_text}"),
            fields,
        },
        observed_at: observed,
        realert_secs: None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use garmr_core::{AgentConfig, Config, DetectConfig, IngestConfig, LlmBackend, StoreConfig};
    use garmr_store::Store;

    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("garmr-anomaly-{tag}-{n}"))
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
                correlations_dir: base.join("correlations"),
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
                model: "claude-opus-4-8".into(),
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

    fn ev(msg: &str) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "pve".into(),
            service: "sshd".into(),
            source: "journald".into(),
            environment: "test".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: msg.into(),
            fields: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn seed_suppresses_then_new_shape_fires() {
        let base = tmp("seed");
        std::fs::create_dir_all(&base).unwrap();
        let store = Store::open_writable(&cfg(&base)).await.unwrap();
        // Corpus: two shapes, each recurring (IP/port vary → same template).
        store
            .events
            .append(vec![
                ev("Failed password for root from 10.0.0.1 port 22"),
                ev("Failed password for root from 10.0.0.2 port 33"),
                ev("Accepted publickey for alice from 10.0.0.3 port 44"),
                ev("Accepted publickey for alice from 10.0.0.4 port 55"),
            ])
            .await
            .unwrap();

        // Seed records the existing shapes without alerting.
        let (recorded, truncated) = seed(&store, 24, 5000, &[]).await.unwrap();
        assert_eq!(recorded, 2, "two distinct shapes seeded");
        assert!(!truncated, "well under the cap");
        // A detect pass right after seeding flags nothing (all shapes known).
        let dets = detect(&store, 24, 5000, 2, 0, &[]).await.unwrap();
        assert!(dets.is_empty(), "seeded corpus must not alert");

        // A genuinely new shape appears, recurring twice.
        store
            .events
            .append(vec![
                ev("sudo: pam_unix authentication failure for user bob"),
                ev("sudo: pam_unix authentication failure for user bob"),
            ])
            .await
            .unwrap();
        let dets = detect(&store, 24, 5000, 2, 0, &[]).await.unwrap();
        assert_eq!(dets.len(), 1, "one new template shape");
        assert!(dets[0].rule_id.starts_with("garmr-anomaly-new-template-"));
        assert_eq!(dets[0].event.log_type, "anomaly");
        assert_eq!(
            dets[0].event.fields.get("window_count").map(String::as_str),
            Some("2")
        );

        // Idempotent: the shape is now known, so a re-run is silent.
        let again = detect(&store, 24, 5000, 2, 0, &[]).await.unwrap();
        assert!(again.is_empty(), "a recorded shape never fires twice");

        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn slow_introduction_still_fires_when_it_ramps_up() {
        // The security-critical fix: a novel shape seen ONCE (below min_count)
        // must NOT be permanently silenced — it fires the tick it crosses the
        // threshold, defeating a drip-feed evasion.
        let base = tmp("slow");
        std::fs::create_dir_all(&base).unwrap();
        let store = Store::open_writable(&cfg(&base)).await.unwrap();
        seed(&store, 24, 5000, &[]).await.unwrap(); // empty baseline

        // One occurrence, min_count=3 → no alert, and NOT recorded. (Vary only
        // a NUMBER so all three collapse to the same shape "novel beacon <N>".)
        store
            .events
            .append(vec![ev("novel beacon 1")])
            .await
            .unwrap();
        assert!(detect(&store, 24, 5000, 3, 0, &[])
            .await
            .unwrap()
            .is_empty());
        assert!(
            !store
                .state
                .template_known(&templatize("novel beacon 1").id)
                .unwrap(),
            "a below-threshold new shape stays UNRECORDED so it can fire later"
        );

        // It ramps up to the threshold → now it fires.
        store
            .events
            .append(vec![ev("novel beacon 2"), ev("novel beacon 3")])
            .await
            .unwrap();
        let dets = detect(&store, 24, 5000, 3, 0, &[]).await.unwrap();
        assert_eq!(
            dets.len(),
            1,
            "the ramped-up shape fires despite the slow start"
        );
        assert_eq!(
            dets[0].event.fields.get("window_count").map(String::as_str),
            Some("3")
        );
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn flood_cap_paces_emissions_without_losing_signal() {
        // A churn that surfaces many new shapes at once must not storm the case
        // store: the cap emits at most `max_emit` per tick and leaves the rest
        // UNRECORDED so they fire on later ticks — paced, never dropped.
        let base = tmp("cap");
        std::fs::create_dir_all(&base).unwrap();
        let store = Store::open_writable(&cfg(&base)).await.unwrap();
        seed(&store, 24, 5000, &[]).await.unwrap(); // empty baseline

        // Five DISTINCT new shapes (distinct words, so templatize doesn't collapse
        // them), each seen once → all alert-worthy at min_count=1.
        for word in ["apple", "banana", "cherry", "date", "fig"] {
            store
                .events
                .append(vec![ev(&format!("brand new {word} widget"))])
                .await
                .unwrap();
        }

        // Cap = 2: two fire per tick; the rest drain over subsequent ticks.
        assert_eq!(detect(&store, 24, 5000, 1, 2, &[]).await.unwrap().len(), 2);
        assert_eq!(detect(&store, 24, 5000, 1, 2, &[]).await.unwrap().len(), 2);
        assert_eq!(detect(&store, 24, 5000, 1, 2, &[]).await.unwrap().len(), 1);
        // All five now recorded → quiet (nothing lost, nothing double-fired).
        assert!(detect(&store, 24, 5000, 1, 2, &[])
            .await
            .unwrap()
            .is_empty());

        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn cross_host_spread_is_surfaced() {
        let base = tmp("xhost");
        std::fs::create_dir_all(&base).unwrap();
        let store = Store::open_writable(&cfg(&base)).await.unwrap();
        seed(&store, 24, 5000, &[]).await.unwrap();
        let on = |h: &str| Event {
            host: h.into(),
            ..ev("brand new shape on many hosts")
        };
        store
            .events
            .append(vec![on("pve"), on("njord"), on("wazuh")])
            .await
            .unwrap();
        let dets = detect(&store, 24, 5000, 3, 0, &[]).await.unwrap();
        assert_eq!(dets.len(), 1);
        assert_eq!(
            dets[0].event.fields.get("host_count").map(String::as_str),
            Some("3")
        );
        assert!(dets[0].event.fields.get("hosts").unwrap().contains("njord"));
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }
}
