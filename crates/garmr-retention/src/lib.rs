// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr-retention` — cold storage / retention for the event lakehouse.
//!
//! Events age out of the hot skade lakehouse into an immutable, content-addressed
//! **cold tier** rather than being deleted. A [`RetentionManager`] pass seals each
//! aged time-window into a cold archive (znippy by default, plain zstd-parquet as
//! a pure-Rust fallback) and records it in the state-store manifest; a
//! [`ColdQuery`] thaws the relevant archives on demand and runs SQL over them.
//! This is the Splunk *frozen→thawed* model: aged data leaves the hot index but
//! stays queryable.
//!
//! See [`manager`] for the sealing pass (and the note on why hot-store pruning
//! is deferred), and [`query`] for the thaw-and-query path.

pub mod archiver;
mod erase;
mod ha;
mod manager;
mod query;
mod s3;

pub use archiver::{blake3_file, make_archiver, ColdArchiver, SealOutcome};
pub use erase::{rewrite_archives, RewriteOutcome};
pub use ha::{fence_verdict, status as ha_status, FenceVerdict, HaSync, Lease};
pub use manager::{ts_literal, RetentionManager, RetentionRun};
pub use query::{ColdQuery, ColdQueryResult};
pub use s3::S3Cold;

/// Retry/backoff shared by every object-store client this crate builds (the
/// cold tier and HA replication): the library defaults — up to 10 retries with
/// jittered exponential backoff, bounded to 3 minutes per request — so a
/// transient S3 hiccup is absorbed inside the client instead of failing a
/// whole seal, ship, or pull.
pub(crate) fn object_retry() -> object_store::RetryConfig {
    object_store::RetryConfig::default()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use chrono::{Duration, Utc};
    use garmr_core::{
        AgentConfig, ColdArchiverKind, Config, DetectConfig, Event, IngestConfig, LlmBackend,
        RetentionConfig, StoreConfig,
    };
    use garmr_store::Store;

    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("garmr-ret-{tag}-{}", uuid::Uuid::new_v4()))
    }

    fn test_config(base: &std::path::Path, archiver: ColdArchiverKind) -> Config {
        Config {
            audit: Default::default(),
            backup: Default::default(),
            store: StoreConfig {
                warehouse_dir: base.join("wh"),
                state_db: base.join("state.redb"),
                search_dir: base.join("search"),
                retention_days: 30,
                compact_snapshot_threshold: 0, // off in retention tests
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
                collectors_file: None,
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
            cases: Default::default(),
            agent: AgentConfig {
                backend: LlmBackend::Anthropic,
                model: "claude-opus-4-8".into(),
                prefilter_model: None,
                openai_base_url: None,
                max_iterations: 12,
                max_tokens: 4096,
                daily_budget_usd: 5.0,
                allow_online_lookups: false,
                geoip_dir: None,
                ioc_feeds: vec![],
                mcp_servers: vec![],
                pricing: Default::default(),
            },
            retention: RetentionConfig {
                enabled: true,
                cold_dir: base.join("cold"),
                archiver,
                window_days: 1,
                interval_secs: 3600,
                compression_level: 6,
                class: Vec::new(),
            },
            route: Default::default(),
            executor: Default::default(),
            ha: Default::default(),
            environment: Default::default(),
            matrix: None,
        }
    }

    fn event_at(ts: chrono::DateTime<Utc>, msg: &str, ip: &str) -> Event {
        let mut fields = BTreeMap::new();
        fields.insert("src_ip".into(), ip.to_string());
        Event {
            ts,
            host: "pve".into(),
            service: "sshd".into(),
            source: "journald".into(),
            environment: "test".into(),
            severity: "warning".into(),
            log_type: "system".into(),
            message: msg.into(),
            fields,
        }
    }

    /// A time-of-day-independent timestamp `days_ago` days back at a fixed UTC
    /// hour — keeps multi-event fixtures inside ONE UTC day no matter when the
    /// test runs (relative offsets from `now` straddle midnight when the suite
    /// runs late in the UTC day).
    fn days_ago_at(now: chrono::DateTime<Utc>, days: i64, hour: u32) -> chrono::DateTime<Utc> {
        (now - Duration::days(days))
            .date_naive()
            .and_hms_opt(hour, 0, 0)
            .expect("valid fixed hour")
            .and_utc()
    }

    async fn roundtrip_with(archiver: ColdArchiverKind) {
        let base = tmp("rt");
        std::fs::create_dir_all(base.join("rules")).unwrap();
        std::fs::create_dir_all(base.join("correlations")).unwrap();
        let cfg = test_config(&base, archiver);

        let store = Store::open_writable(&cfg).await.expect("open store");
        let now = Utc::now();

        // Three aged events in one UTC day (35 days ago, fixed hours) + two
        // recent (now).
        let aged = vec![
            event_at(
                days_ago_at(now, 35, 3),
                "Failed password for root from 203.0.113.7",
                "203.0.113.7",
            ),
            event_at(
                days_ago_at(now, 35, 4),
                "Failed password for admin",
                "203.0.113.7",
            ),
            event_at(
                days_ago_at(now, 35, 5),
                "Accepted password for root",
                "10.0.0.5",
            ),
        ];
        let recent = vec![
            event_at(now, "Failed password for root now", "203.0.113.9"),
            event_at(
                now - Duration::minutes(5),
                "sudo session opened",
                "10.0.0.6",
            ),
        ];
        store.events.append(aged.clone()).await.unwrap();
        store.events.append(recent.clone()).await.unwrap();

        // First pass: seals the aged window only.
        let mgr = RetentionManager::new(store.clone(), &cfg).unwrap();
        let run = mgr.run_once(now).await.unwrap();
        assert_eq!(run.windows, 1, "exactly one aged window has data");
        assert_eq!(run.rows, 3, "three aged rows sealed");
        assert!(run.bytes_out > 0, "run reports the sealed archive size");

        // Manifest recorded, archive on disk, checksum present, hot not pruned.
        let arcs = store.state.list_cold_archives().unwrap();
        assert_eq!(arcs.len(), 1);
        let a = &arcs[0];
        assert_eq!(a.rows, 3);
        assert_eq!(a.checksum.len(), 64);
        assert!(!a.hot_pruned);
        assert!(
            a.path(&cfg.retention.cold_dir).exists(),
            "archive file exists"
        );
        assert_eq!(
            a.kind,
            if matches!(archiver, ColdArchiverKind::Znippy) {
                "znippy"
            } else {
                "plain"
            }
        );

        // Idempotent: a second pass seals nothing new.
        let run2 = mgr.run_once(now).await.unwrap();
        assert_eq!(run2.windows, 0, "re-run is a no-op");
        assert_eq!(store.state.list_cold_archives().unwrap().len(), 1);

        // Cold query returns exactly the aged rows, thawed (checksum verified).
        let cq = ColdQuery::new(store.clone(), &cfg);
        let res = cq
            .query("SELECT count(*) AS c FROM events", None, None)
            .await
            .unwrap();
        assert_eq!(res.archives, 1, "one archive thawed");
        let c = res.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<skade::arrow_array::Int64Array>()
            .unwrap()
            .value(0);
        assert_eq!(c, 3, "cold tier holds the 3 aged rows");

        // A cold query for a window that predates every archive touches none.
        let ancient = (now - Duration::days(9999)).timestamp_micros();
        let empty = cq
            .query("SELECT count(*) AS c FROM events", None, Some(ancient))
            .await
            .unwrap();
        assert_eq!(empty.archives, 0, "no archive overlaps → nothing thawed");
        assert!(empty.batches.is_empty());

        // Tampering with the archive is caught: flip one byte → the thaw path
        // refuses with a checksum error instead of silently querying it.
        let apath = a.path(&cfg.retention.cold_dir);
        let mut bytes = std::fs::read(&apath).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&apath, &bytes).unwrap();
        let err = cq.query("SELECT count(*) FROM events", None, None).await;
        assert!(
            err.as_ref()
                .is_err_and(|e| e.to_string().contains("integrity")),
            "tampered archive must fail its integrity check, got {err:?}"
        );
        bytes[mid] ^= 0xFF; // restore for the hot-count assertion below
        std::fs::write(&apath, &bytes).unwrap();

        // Hot store still holds everything (cold tier is additive today).
        let hot = store
            .events
            .sql("SELECT count(*) AS c FROM events")
            .await
            .unwrap();
        let hot_c = hot[0]
            .column(0)
            .as_any()
            .downcast_ref::<skade::arrow_array::Int64Array>()
            .unwrap()
            .value(0);
        assert_eq!(hot_c, 5, "all 5 rows remain in the hot lakehouse");

        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn plain_cold_tier_round_trips() {
        roundtrip_with(ColdArchiverKind::Plain).await;
    }

    #[cfg(feature = "znippy")]
    #[tokio::test]
    async fn znippy_cold_tier_round_trips() {
        roundtrip_with(ColdArchiverKind::Znippy).await;
    }

    /// The streaming seal must handle a window far larger than one DataFusion
    /// batch (~8192 rows) — including a dense same-`event_ts` cluster that
    /// straddles batch boundaries — sealing every row exactly once. This is the
    /// case the old whole-window-in-RAM seal OOM-thrashed on, and the one a
    /// naive paginated `event_ts` cursor would silently lose or duplicate.
    #[tokio::test]
    async fn streaming_seal_handles_large_multi_batch_window() {
        let base = tmp("stream");
        std::fs::create_dir_all(base.join("rules")).unwrap();
        std::fs::create_dir_all(base.join("correlations")).unwrap();
        let cfg = test_config(&base, ColdArchiverKind::Plain);
        let store = Store::open_writable(&cfg).await.expect("open store");
        let now = Utc::now();
        let day = days_ago_at(now, 35, 3);

        let n_spread = 20_000usize; // > 2 default batches
        let n_cluster = 5_000usize; // all at the exact same event_ts
        let mut evs = Vec::with_capacity(n_spread + n_cluster);
        for i in 0..n_spread {
            // Unique-ish, still inside the one UTC day (20k ms = 20s past 03:00).
            evs.push(event_at(
                day + Duration::milliseconds(i as i64),
                &format!("spread event {i}"),
                "203.0.113.7",
            ));
        }
        for i in 0..n_cluster {
            evs.push(event_at(day, &format!("cluster event {i}"), "10.0.0.5"));
        }
        for chunk in evs.chunks(5_000) {
            store.events.append(chunk.to_vec()).await.unwrap();
        }

        let mgr = RetentionManager::new(store.clone(), &cfg).unwrap();
        let run = mgr.run_once(now).await.unwrap();
        assert_eq!(run.windows, 1, "one aged window");
        assert_eq!(
            run.rows as usize,
            n_spread + n_cluster,
            "every row sealed exactly once — no loss/dup across batches or the same-ts cluster"
        );

        // Thaw (checksum-verified) and re-count: the archive holds every row.
        let cq = ColdQuery::new(store.clone(), &cfg);
        let res = cq
            .query("SELECT count(*) AS c FROM events", None, None)
            .await
            .unwrap();
        let c = res.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<skade::arrow_array::Int64Array>()
            .unwrap()
            .value(0);
        assert_eq!(
            c as usize,
            n_spread + n_cluster,
            "cold tier holds every row"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    /// The seal query must stream in a SINGLE partition: DataFusion's default
    /// parallel plan inserts a round-robin `RepartitionExec` above the scan that
    /// reads it ahead of the (slow) parquet-seal writer and buffers it
    /// unboundedly — the retention OOM. `sql_stream` pins target_partitions(1)
    /// to remove it; assert the operator is gone from the plan.
    #[tokio::test]
    async fn seal_scan_is_single_partition_no_repartition() {
        use futures::StreamExt;
        use skade::arrow_array::Array;
        let base = tmp("plan");
        std::fs::create_dir_all(base.join("rules")).unwrap();
        std::fs::create_dir_all(base.join("correlations")).unwrap();
        let cfg = test_config(&base, ColdArchiverKind::Plain);
        let store = Store::open_writable(&cfg).await.expect("open store");
        store
            .events
            .append(vec![event_at(Utc::now(), "x", "1.2.3.4")])
            .await
            .unwrap();

        let mut s = store
            .events
            .sql_stream(
                "EXPLAIN SELECT event_ts, message FROM events \
                 WHERE event_ts >= TIMESTAMP '2000-01-01T00:00:00'",
            )
            .await
            .unwrap();
        let mut plan = String::new();
        while let Some(b) = s.next().await {
            let b = b.unwrap();
            for col in 0..b.num_columns() {
                if let Some(a) = b
                    .column(col)
                    .as_any()
                    .downcast_ref::<skade::arrow_array::StringArray>()
                {
                    for i in 0..a.len() {
                        if a.is_valid(i) {
                            plan.push_str(a.value(i));
                            plan.push('\n');
                        }
                    }
                }
            }
        }
        assert!(
            plan.to_lowercase().contains("scan"),
            "sanity: plan has a scan:\n{plan}"
        );
        assert!(
            !plan.contains("RepartitionExec"),
            "single-partition seal session must not repartition (the OOM source):\n{plan}"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn ts_literal_is_datafusion_shaped() {
        assert_eq!(ts_literal(0), "TIMESTAMP '1970-01-01T00:00:00.000000'");
    }

    #[tokio::test]
    async fn a_sealed_archive_contains_zero_excluded_class_rows() {
        // The exclusion has to happen AT THE SEAL: an archive is immutable and
        // outlives every policy change, so a class row sealed by mistake would
        // sit in cold storage for the archive's whole life.
        let base = tmp("class-excl");
        std::fs::create_dir_all(&base).unwrap();
        let mut cfg = test_config(&base, ColdArchiverKind::Plain);
        cfg.retention.class = vec![garmr_core::RetentionClass {
            source: "kunai".into(),
            hot_days: 10,
        }];
        let store = Store::open(&cfg).await.unwrap();
        let now = Utc::now();

        let mut kunai = event_at(days_ago_at(now, 35, 3), "exec /usr/bin/curl", "10.0.0.9");
        kunai.source = "kunai".into();
        let journald = event_at(
            days_ago_at(now, 35, 4),
            "Failed password for root",
            "203.0.113.7",
        );
        store.events.append(vec![kunai, journald]).await.unwrap();

        let mgr = RetentionManager::new(store.clone(), &cfg).unwrap();
        let run = mgr.run_once(now).await.unwrap();
        assert_eq!(run.windows, 1);
        assert_eq!(run.rows, 1, "only the journald row is sealed");

        // And the archive itself proves it: thaw and look for the class row.
        let cq = ColdQuery::new(store.clone(), &cfg);
        let res = cq
            .query(
                "SELECT count(*) AS c FROM events WHERE source = 'kunai'",
                None,
                None,
            )
            .await
            .unwrap();
        let c = res.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<skade::arrow_array::Int64Array>()
            .unwrap()
            .value(0);
        assert_eq!(c, 0, "no kunai row may exist in cold storage");
        let total = cq
            .query("SELECT count(*) AS c FROM events", None, None)
            .await
            .unwrap();
        let t = total.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<skade::arrow_array::Int64Array>()
            .unwrap()
            .value(0);
        assert_eq!(t, 1, "the journald row IS there — exclusion, not data loss");
    }

    #[tokio::test]
    async fn cold_rewrite_erases_the_subject_and_records_the_checksum_transition() {
        // The M3 cold acceptance: A erased from the archive, B survives, the
        // manifest records the transition, and a re-run is a zero-delta no-op.
        let base = tmp("cold-rewrite");
        std::fs::create_dir_all(&base).unwrap();
        let cfg = test_config(&base, ColdArchiverKind::Plain);
        let store = Store::open(&cfg).await.unwrap();
        let now = Utc::now();

        store
            .events
            .append(vec![
                event_at(days_ago_at(now, 35, 3), "login A", "203.0.113.7"),
                event_at(days_ago_at(now, 35, 4), "login B", "10.0.0.5"),
            ])
            .await
            .unwrap();
        let mgr = RetentionManager::new(store.clone(), &cfg).unwrap();
        assert_eq!(mgr.run_once(now).await.unwrap().rows, 2);
        let before = &store.state.list_cold_archives().unwrap()[0];
        let (old_id, old_checksum, old_rows) =
            (before.id.clone(), before.checksum.clone(), before.rows);
        assert_eq!(old_rows, 2);

        let tomb = garmr_core::Tombstone {
            id: "erase-cold-test".into(),
            field: garmr_core::EraseField::SrcIp,
            value: "203.0.113.7".into(),
            from_us: None,
            to_us: None,
            placed_at: now,
            reason: "test".into(),
        };
        let out = rewrite_archives(
            &store.state,
            &cfg.retention.cold_dir,
            cfg.retention.compression_level,
            std::slice::from_ref(&tomb),
        )
        .await
        .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rows_erased, 1, "A's row leaves the archive");
        assert_ne!(
            out[0].new_checksum, old_checksum,
            "the manifest must record a real transition"
        );

        // The manifest agrees with the rewrite, and the archive itself proves
        // the subject is gone while B remains.
        let after = &store.state.list_cold_archives().unwrap()[0];
        assert_eq!(after.id, old_id);
        assert_eq!(after.rows, 1);
        assert_eq!(after.checksum, out[0].new_checksum);
        let cq = ColdQuery::new(store.clone(), &cfg);
        let res = cq
            .query("SELECT message FROM events ORDER BY event_ts", None, None)
            .await
            .unwrap();
        use skade::arrow_array::Array as _;
        // Column-type agnostic read: the resealed parquet may come back as
        // Utf8View rather than Utf8 depending on the reader's defaults.
        let col = res.batches[0].column(0);
        assert_eq!(col.len(), 1);
        let msg = skade::datafusion::arrow::util::display::array_value_to_string(col, 0).unwrap();
        assert_eq!(msg, "login B", "B survives, A is gone");

        // Idempotent: the second pass scans, matches nothing, changes nothing.
        let again = rewrite_archives(
            &store.state,
            &cfg.retention.cold_dir,
            cfg.retention.compression_level,
            std::slice::from_ref(&tomb),
        )
        .await
        .unwrap();
        assert_eq!(again[0].rows_erased, 0);
        assert_eq!(
            again[0].old_checksum, again[0].new_checksum,
            "zero-delta re-run leaves the archive byte-identical"
        );
    }

    #[tokio::test]
    async fn cold_rewrite_refuses_a_held_archive() {
        let base = tmp("cold-rewrite-held");
        std::fs::create_dir_all(&base).unwrap();
        let cfg = test_config(&base, ColdArchiverKind::Plain);
        let store = Store::open(&cfg).await.unwrap();
        let now = Utc::now();
        store
            .events
            .append(vec![event_at(
                days_ago_at(now, 35, 3),
                "held row",
                "203.0.113.7",
            )])
            .await
            .unwrap();
        let mgr = RetentionManager::new(store.clone(), &cfg).unwrap();
        mgr.run_once(now).await.unwrap();
        let id = store.state.list_cold_archives().unwrap()[0].id.clone();
        store.state.set_cold_legal_hold(&id, true).unwrap();

        let tomb = garmr_core::Tombstone {
            id: "erase-held-test".into(),
            field: garmr_core::EraseField::SrcIp,
            value: "203.0.113.7".into(),
            from_us: None,
            to_us: None,
            placed_at: now,
            reason: "test".into(),
        };
        let err = rewrite_archives(
            &store.state,
            &cfg.retention.cold_dir,
            cfg.retention.compression_level,
            std::slice::from_ref(&tomb),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("legal hold"), "{err}");
    }
}
