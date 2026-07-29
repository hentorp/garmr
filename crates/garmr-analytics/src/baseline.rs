// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Frequency-baseline anomaly detection (M4) — "is this (host, service) far
//! above its own normal volume for this hour?".
//!
//! Splunk's classic statistical detection: compare a (host, service)'s event
//! volume in the **previous complete clock hour** against a robust baseline of
//! the SAME clock-hour on prior days (median ± MAD over ~14 days), and flag
//! bursts above `median + k·max(MAD, 1)`. A finding becomes a synthetic
//! [`Detection`] on the SAME case path as everything else — garmr is the SIEM,
//! so no push-back upstream. It complements the shape-based [`crate::anomaly`] detector
//! (a NEW shape) and feeds [`crate::risk`] (a burst is another weak signal).
//!
//! Design choices (and why they differ from the warehouse prototype it ports):
//! - **Keyed on (host, service), not (template, host).** garmr does not store a
//!   template id column, and templatizing 14 days of history every cycle would
//!   be far too costly. `service` is a stored column and a good proxy — a burst
//!   in sshd auth failures shows up as an sshd volume burst.
//! - **Previous COMPLETE clock hour, both sides.** The current window and the
//!   baseline buckets are the same clock hour, so a rolling window can't leak
//!   the previous hour's traffic into a comparison against this hour's baseline
//!   (that phase skew makes a nightly-batch service false-positive every
//!   morning). The cost is up to ~1h of detection latency — fine for a volume
//!   signal.
//! - **Robust stats.** median + MAD (not mean/stddev) so a single past spike
//!   doesn't inflate the baseline. `max(MAD, 1)` stops a flat series from
//!   alerting on +1, and `min_count` mutes tiny counts.
//! - **PER-KEY zero-padding + warmup.** A (host, service) absent on some prior
//!   days at this hour contributes a 0 for those days — but ONLY for days after
//!   the key first appeared. Padding a week-old key out to the whole store's age
//!   would bury its real median under zeros from before it existed and fire on
//!   its own normal volume. A key seen fewer than [`MIN_HISTORY_DAYS`] days is
//!   skipped (no baseline yet).
//!
//! KNOWN LIMITATIONS (inherent to a rolling-history baseline — RBA/anomaly cover
//! different angles, and this is one signal among many):
//! - **No day-of-week awareness.** Weekday and weekend hour-H are pooled, so a
//!   service that is busy only on weekdays has a baseline diluted by weekend
//!   zeros (and vice versa). A dow split is a later refinement.
//! - **Slow-ramp poisoning.** The baseline includes recent days, so an attacker
//!   who raises volume gradually over a week normalizes it. Sudden bursts are
//!   caught; boil-the-frog is not (that is what the shape/risk signals are for).
//! - **Ingest gaps / backfills.** An outage leaves prior hours at 0 (baseline
//!   too low → next real hour looks bursty); a backfill dumping a day into one
//!   hour inflates that hour. Both self-heal as the window rolls.
//! - **New activity at a previously-quiet hour.** Per-key padding uses the key's
//!   first-seen at ANY hour, so a long-lived (host, service) that only recently
//!   began emitting at THIS hour is zero-padded across the days it was silent
//!   here → it flags as a burst until the new pattern fills the median (~a
//!   week). This is the inherent cold-start of any per-hour baseline (padding to
//!   distinct-hour-days instead would over-fit a rarely-seen hour and miss real
//!   bursts); the realert window bounds it to one alert per hour, one signal
//!   among many.
//!
//! Stateless: the baseline is recomputed from the lakehouse each cycle, and
//! re-alert suppression is the standard per-dedup-key window on the case path.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use garmr_core::{Detection, Event, Result};
use garmr_store::Store;
use skade::arrow_array::{Array, Int64Array, StringArray, TimestampMicrosecondArray};

/// History depth for the baseline (days). Same-clock-hour counts over this
/// window are the sample set.
const LOOKBACK_DAYS: i64 = 14;
/// A key seen fewer than this many days has no usable baseline — stay silent.
const MIN_HISTORY_DAYS: i64 = 3;
/// A frequency burst re-opens at most this often for the same (host, service).
const REALERT_SECS: u64 = 3600;

/// The tunable knobs (from `[detect]` config).
#[derive(Debug, Clone, Copy)]
pub struct BaselineParams {
    /// MAD multiplier for the burst threshold.
    pub k: f64,
    /// Absolute floor on the current count.
    pub min_count: u64,
}

/// One detection pass. Returns a synthetic detection per (host, service) whose
/// previous-complete-hour volume exceeds `median + k·max(MAD, 1)` and the
/// `min_count` floor. Empty (no findings) is the overwhelming common case.
pub async fn detect(
    store: &Store,
    now: DateTime<Utc>,
    params: &BaselineParams,
) -> Result<Vec<Detection>> {
    // The window under test is the PREVIOUS complete clock hour; the baseline is
    // the SAME clock hour on prior days. Anchor EVERY query — and the Rust-side
    // `analyzed_day` below — to one instant (`now` inlined as a literal), not
    // SQL `now()`: skade builds a fresh DataFusion session per query, each
    // re-latching now(), so a cycle straddling the top of an hour would compare
    // hour H-1's count to hour H's baseline (the phase bug, as a boundary race).
    let now_lit = format!("to_timestamp_micros({})", now.timestamp_micros());
    let hour_start = format!("date_trunc('hour', {now_lit})");
    let prev_hour_start = format!("{hour_start} - INTERVAL '1 hour'");
    let excl = "log_type NOT IN ('anomaly', 'risk', 'baseline') AND host <> ''";

    // 1. Current: counts in the previous complete clock hour, floor in SQL.
    let current_sql = format!(
        "SELECT host, service, count(*) AS c FROM events \
         WHERE event_ts >= {prev_hour_start} AND event_ts < {hour_start} \
           AND {excl} \
         GROUP BY host, service HAVING count(*) >= {}",
        params.min_count
    );
    let current = read_counts(&store.events.sql(current_sql).await?);
    if current.is_empty() {
        return Ok(vec![]);
    }

    // 2. Baseline: per-day counts for the same clock-hour, STRICTLY BEFORE the
    //    window under test, over the lookback. Its hour is derived from now() so
    //    it always matches the current window's hour.
    let hist_sql = format!(
        "SELECT host, service, count(*) AS c FROM events \
         WHERE event_ts < {prev_hour_start} \
           AND event_ts >= {prev_hour_start} - INTERVAL '{LOOKBACK_DAYS} days' \
           AND date_part('hour', event_ts) = date_part('hour', {prev_hour_start}) \
           AND {excl} \
         GROUP BY host, service, date_trunc('day', event_ts)"
    );
    let mut history: HashMap<(String, String), Vec<f64>> = HashMap::new();
    for ((host, service), c) in read_counts(&store.events.sql(hist_sql).await?) {
        history.entry((host, service)).or_default().push(c as f64);
    }

    // 3. Per-key first-seen (any hour) within the lookback → how many prior days
    //    each key has existed, so a key is zero-padded only across days it could
    //    actually have appeared, not the whole store's age.
    let first_sql = format!(
        "SELECT host, service, min(event_ts) AS first FROM events \
         WHERE event_ts >= {prev_hour_start} - INTERVAL '{LOOKBACK_DAYS} days' AND {excl} \
         GROUP BY host, service"
    );
    let first_seen = read_first_seen(&store.events.sql(first_sql).await?);

    // The day of the window under test (for counting a key's prior day-slots).
    let analyzed_day = (now - chrono::Duration::hours(1)).date_naive();

    // 4. Flag bursts.
    let mut dets = Vec::new();
    for ((host, service), current_count) in current {
        let key = (host.clone(), service.clone());
        // Per-key warmup: how many prior days has this key existed at all?
        let Some(first) = first_seen.get(&key) else {
            continue;
        };
        let key_days = (analyzed_day - first.date_naive())
            .num_days()
            .clamp(0, LOOKBACK_DAYS);
        if key_days < MIN_HISTORY_DAYS {
            continue; // not enough history for THIS key
        }
        let mut days = history.remove(&key).unwrap_or_default();
        // Pad with zeros for the days this key existed but was silent at this
        // hour (never shrink: a key seen at this hour on more days keeps them).
        if (days.len() as i64) < key_days {
            days.resize(key_days as usize, 0.0);
        }
        let med = median(&mut days.clone());
        let mad = median(&mut days.iter().map(|x| (x - med).abs()).collect::<Vec<_>>());
        let threshold = med + params.k * mad.max(1.0);
        if (current_count as f64) <= threshold {
            continue;
        }
        dets.push(freq_detection(
            &host,
            &service,
            current_count,
            med,
            mad,
            threshold,
            now,
        ));
    }
    Ok(dets)
}

/// Read a `(host, service, count)` result into pairs. Skips null host/count.
fn read_counts(batches: &[skade::arrow_array::RecordBatch]) -> Vec<((String, String), i64)> {
    let mut out = Vec::new();
    for b in batches {
        let (Some(host), Some(service), Some(c)) = (
            b.column(0).as_any().downcast_ref::<StringArray>(),
            b.column(1).as_any().downcast_ref::<StringArray>(),
            b.column(2).as_any().downcast_ref::<Int64Array>(),
        ) else {
            continue;
        };
        for i in 0..b.num_rows() {
            if host.is_valid(i) && c.is_valid(i) {
                let service = if service.is_valid(i) {
                    service.value(i)
                } else {
                    ""
                };
                out.push(((host.value(i).to_string(), service.to_string()), c.value(i)));
            }
        }
    }
    out
}

/// Read a `(host, service, min(event_ts))` result into first-seen timestamps.
fn read_first_seen(
    batches: &[skade::arrow_array::RecordBatch],
) -> HashMap<(String, String), DateTime<Utc>> {
    let mut out = HashMap::new();
    for b in batches {
        let (Some(host), Some(service), Some(first)) = (
            b.column(0).as_any().downcast_ref::<StringArray>(),
            b.column(1).as_any().downcast_ref::<StringArray>(),
            b.column(2)
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>(),
        ) else {
            continue;
        };
        for i in 0..b.num_rows() {
            if host.is_valid(i) && first.is_valid(i) {
                if let Some(ts) = DateTime::from_timestamp_micros(first.value(i)) {
                    let service = if service.is_valid(i) {
                        service.value(i)
                    } else {
                        ""
                    };
                    out.insert((host.value(i).to_string(), service.to_string()), ts);
                }
            }
        }
    }
    out
}

/// Median of a slice (sorts in place). 0.0 for an empty slice.
fn median(v: &mut [f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

fn freq_detection(
    host: &str,
    service: &str,
    current: i64,
    median: f64,
    mad: f64,
    threshold: f64,
    now: DateTime<Utc>,
) -> Detection {
    let factor = current as f64 / median.max(1.0);
    let level = if current as f64 >= 3.0 * threshold {
        "high"
    } else {
        "medium"
    };

    let mut fields = std::collections::BTreeMap::new();
    fields.insert("current_count".to_string(), current.to_string());
    fields.insert("baseline_median".to_string(), format!("{median:.1}"));
    fields.insert("baseline_mad".to_string(), format!("{mad:.1}"));
    fields.insert("threshold".to_string(), format!("{threshold:.1}"));
    fields.insert("factor".to_string(), format!("{factor:.1}"));

    Detection {
        rule_id: format!("garmr-freq-{host}-{service}"),
        rule_title: "Unusual event volume (frequency baseline)".to_string(),
        level: level.to_string(),
        attack: vec![],
        event: Event {
            ts: now,
            host: host.into(),
            service: service.into(),
            source: "baseline".into(),
            environment: "baseline".into(),
            severity: "warning".into(),
            log_type: "baseline".into(),
            message: format!(
                "{service} on {host}: {current} events in the previous hour (baseline {median:.0}±{mad:.0}, threshold {threshold:.0} — {factor:.1}× normal)"
            ),
            fields,
        },
        observed_at: now,
        realert_secs: Some(REALERT_SECS),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{Duration, Timelike};
    use garmr_core::{
        AgentConfig, Config, DetectConfig, Event, IngestConfig, LlmBackend, StoreConfig,
    };
    use garmr_store::Store;

    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("garmr-baseline-{tag}-{n}"))
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

    fn ev_at(host: &str, service: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: host.into(),
            service: service.into(),
            source: "journald".into(),
            environment: "test".into(),
            severity: "info".into(),
            log_type: "system".into(),
            message: "m".into(),
            fields: BTreeMap::new(),
        }
    }

    fn params() -> BaselineParams {
        BaselineParams {
            k: 3.0,
            min_count: 20,
        }
    }

    /// Middle of the previous complete clock hour, relative to `now` — the point
    /// the current window covers, and (shifted by whole days) the baseline hour.
    fn prev_hour_mid(now: DateTime<Utc>) -> DateTime<Utc> {
        let hour_start = now
            .with_minute(0)
            .unwrap()
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap();
        hour_start - Duration::minutes(30)
    }

    #[tokio::test]
    async fn burst_over_baseline_fires_and_steady_state_does_not() {
        let base = tmp("burst");
        std::fs::create_dir_all(&base).unwrap();
        let store = Store::open_writable(&cfg(&base)).await.unwrap();
        let now = Utc::now();
        let win = prev_hour_mid(now);

        // Baseline: ~5 sshd events at this clock-hour on each of the last 5 days.
        let mut hist = Vec::new();
        for d in 1..=5 {
            for _ in 0..5 {
                hist.push(ev_at("pve", "sshd", win - Duration::days(d)));
            }
        }
        store.events.append(hist).await.unwrap();

        // The window under test: a 40-event sshd burst (median 5, min_count 20).
        let cur: Vec<Event> = (0..40).map(|_| ev_at("pve", "sshd", win)).collect();
        store.events.append(cur).await.unwrap();

        let dets = detect(&store, now, &params()).await.unwrap();
        assert_eq!(dets.len(), 1, "the burst should fire one finding");
        let d = &dets[0];
        assert_eq!(d.rule_id, "garmr-freq-pve-sshd");
        assert_eq!(d.event.log_type, "baseline");
        assert_eq!(
            d.event.fields.get("current_count").map(String::as_str),
            Some("40")
        );
        assert_eq!(
            d.event.fields.get("baseline_median").map(String::as_str),
            Some("5.0")
        );

        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn a_normal_hour_does_not_fire() {
        let base = tmp("normal");
        std::fs::create_dir_all(&base).unwrap();
        let store = Store::open_writable(&cfg(&base)).await.unwrap();
        let now = Utc::now();
        let win = prev_hour_mid(now);

        let mut hist = Vec::new();
        for d in 1..=5 {
            for _ in 0..30 {
                hist.push(ev_at("pve", "sshd", win - Duration::days(d)));
            }
        }
        store.events.append(hist).await.unwrap();
        let cur: Vec<Event> = (0..32).map(|_| ev_at("pve", "sshd", win)).collect();
        store.events.append(cur).await.unwrap();

        let dets = detect(&store, now, &params()).await.unwrap();
        assert!(dets.is_empty(), "a count near the baseline must not fire");
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn new_key_padded_to_its_own_age_not_store_age() {
        // The confirmed regression: on a store that ALSO holds a 14-day-old key,
        // a 5-day-old but STEADY key must be scored against its own 5 days, not
        // padded to the store's 14 → it must NOT fire on its own normal volume.
        let base = tmp("newkey");
        std::fs::create_dir_all(&base).unwrap();
        let store = Store::open_writable(&cfg(&base)).await.unwrap();
        let now = Utc::now();
        let win = prev_hour_mid(now);

        // An OLD unrelated key so the store's global age is 14 days.
        let mut old = Vec::new();
        for d in 1..=14 {
            old.push(ev_at("oldhost", "cron", win - Duration::days(d)));
        }
        store.events.append(old).await.unwrap();

        // The target: first seen 5 days ago, steady 30/hour at this clock-hour.
        let mut steady = Vec::new();
        for d in 1..=5 {
            for _ in 0..30 {
                steady.push(ev_at("newpve", "sshd", win - Duration::days(d)));
            }
        }
        store.events.append(steady).await.unwrap();
        // Its current window: 30 — exactly its normal volume.
        let cur: Vec<Event> = (0..30).map(|_| ev_at("newpve", "sshd", win)).collect();
        store.events.append(cur).await.unwrap();

        let dets = detect(&store, now, &params()).await.unwrap();
        assert!(
            dets.iter().all(|d| d.event.host != "newpve"),
            "a steady new key must not fire on its own normal volume (got {:?})",
            dets.iter().map(|d| &d.rule_id).collect::<Vec<_>>()
        );
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn below_min_count_never_fires() {
        let base = tmp("floor");
        std::fs::create_dir_all(&base).unwrap();
        let store = Store::open_writable(&cfg(&base)).await.unwrap();
        let now = Utc::now();
        let win = prev_hour_mid(now);

        let mut hist = Vec::new();
        for d in 1..=5 {
            for _ in 0..50 {
                hist.push(ev_at("pve", "kernel", win - Duration::days(d)));
            }
        }
        store.events.append(hist).await.unwrap();
        // 10 events this hour (< min_count 20) → SQL floor drops it.
        let cur: Vec<Event> = (0..10).map(|_| ev_at("pve", "kernel", win)).collect();
        store.events.append(cur).await.unwrap();

        let dets = detect(&store, now, &params()).await.unwrap();
        assert!(dets.is_empty(), "a count below min_count must not fire");
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn young_key_stays_silent_warmup() {
        let base = tmp("warmup");
        std::fs::create_dir_all(&base).unwrap();
        let store = Store::open_writable(&cfg(&base)).await.unwrap();
        let now = Utc::now();
        let win = prev_hour_mid(now);

        // Only ~1 day of history for this key (< MIN_HISTORY_DAYS) + a big burst.
        let mut all: Vec<Event> = (0..30)
            .map(|_| ev_at("pve", "sshd", win - Duration::days(1)))
            .collect();
        all.extend((0..80).map(|_| ev_at("pve", "sshd", win)));
        store.events.append(all).await.unwrap();

        let dets = detect(&store, now, &params()).await.unwrap();
        assert!(
            dets.is_empty(),
            "a key with too little history → warmup suppresses it"
        );
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn median_handles_even_and_odd() {
        assert_eq!(median(&mut [3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&mut [4.0, 1.0, 3.0, 2.0]), 2.5);
        assert_eq!(median(&mut []), 0.0);
    }
}