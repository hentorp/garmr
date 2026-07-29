// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Unit tests for the hunt loop, definition loading, and finding→detection
//! conversion (MockLlm-driven, mirroring the triage/author test style).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use garmr_llm::types::{LlmResponse, ToolCall};

use super::*;

struct MockLlm {
    script: Mutex<Vec<LlmResponse>>,
    calls: AtomicUsize,
}

impl MockLlm {
    fn new(script: Vec<LlmResponse>) -> Self {
        Self {
            script: Mutex::new(script),
            calls: AtomicUsize::new(0),
        }
    }

    fn text_turn(text: &str) -> LlmResponse {
        LlmResponse {
            text: text.into(),
            tool_calls: vec![],
            assistant_blocks: vec![Block::Text(text.into())],
            stop_reason: StopReason::EndTurn,
            usage: garmr_llm::types::Usage {
                input_tokens: 100,
                output_tokens: 50,
            },
        }
    }

    fn tool_turn(name: &str, input: Value) -> LlmResponse {
        LlmResponse {
            text: String::new(),
            tool_calls: vec![ToolCall {
                id: "t1".into(),
                name: name.into(),
                input: input.clone(),
            }],
            assistant_blocks: vec![Block::ToolUse {
                id: "t1".into(),
                name: name.into(),
                input,
            }],
            stop_reason: StopReason::ToolUse,
            usage: garmr_llm::types::Usage {
                input_tokens: 200,
                output_tokens: 80,
            },
        }
    }
}

#[async_trait::async_trait]
impl garmr_llm::LlmProvider for MockLlm {
    async fn complete(&self, _req: &LlmRequest) -> garmr_core::Result<LlmResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut s = self.script.lock().unwrap();
        if s.is_empty() {
            panic!("mock script exhausted");
        }
        Ok(s.remove(0))
    }
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("garmr-hunt-{tag}-{n}"))
}

fn test_cfg(base: &std::path::Path) -> Config {
    use garmr_core::{AgentConfig, DetectConfig, IngestConfig, LlmBackend, StoreConfig};
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

async fn seeded_store(base: &std::path::Path) -> Store {
    std::fs::create_dir_all(base).unwrap();
    let store = Store::open_writable(&test_cfg(base)).await.unwrap();
    let events: Vec<garmr_core::Event> = (0..4)
        .map(|i| garmr_core::Event {
            ts: Utc::now(),
            host: "pve".into(),
            service: "sshd".into(),
            source: "journald".into(),
            environment: "test".into(),
            severity: "warning".into(),
            log_type: "auth".into(),
            message: format!("Failed password for root {i}"),
            fields: BTreeMap::new(),
        })
        .collect();
    store.events.append(events).await.unwrap();
    store
}

#[tokio::test]
async fn hunt_runs_tools_then_reports_findings_and_persists() {
    let base = tmp("happy");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let llm = MockLlm::new(vec![
        MockLlm::tool_turn(
            "query_events",
            serde_json::json!({"sql": "SELECT host, count(*) AS n FROM events GROUP BY host LIMIT 5"}),
        ),
        MockLlm::tool_turn(
            "submit_hunt_report",
            serde_json::json!({
                "outcome": "findings",
                "findings": [{
                    "title": "brute force against pve",
                    "severity": 6,
                    "evidence": "4 failed password on pve according to query_events",
                    "host": "pve"
                }]
            }),
        ),
    ]);
    let report = run_hunt(
        &store,
        &llm,
        &cfg,
        "test-hunt",
        "is a brute force under way?",
        None,
    )
    .await
    .unwrap();
    assert_eq!(report.outcome, HuntOutcome::Findings);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.iterations, 2);
    assert!(report.cost_usd > 0.0);
    assert!(
        report
            .transcript
            .iter()
            .any(|t| t.actor == "tool:query_events"),
        "tool call audited"
    );
    // Persisted and listable.
    let listed = store.state.list_hunt_reports().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, report.id);

    // Findings convert into case-machinery detections.
    let dets = findings_to_detections(&report);
    assert_eq!(dets.len(), 1);
    assert!(
        dets[0].rule_id.starts_with("garmr-hunt-test-hunt-"),
        "finding-specific dedup id: {}",
        dets[0].rule_id
    );
    assert_eq!(dets[0].event.host, "pve");
    assert_eq!(dets[0].level, "medium");

    // Two DIFFERENT findings on the same host must get different dedup
    // keys — otherwise the second is swallowed by the realert window.
    let mut two = report.clone();
    two.findings.push(garmr_core::HuntFinding {
        title: "another finding".into(),
        severity: 4,
        evidence: "other evidence".into(),
        host: Some("pve".into()),
        src_ip: None,
    });
    let d2 = findings_to_detections(&two);
    assert_ne!(
        d2[0].dedup_key(),
        d2[1].dedup_key(),
        "distinct findings, distinct keys"
    );

    // Budget arithmetic is pinned: the ledger holds the SETTLED actual
    // costs (2 calls x mock usage), not the worst-case reservations.
    let day = Utc::now().format("%Y-%m-%d").to_string();
    let expected = 2 * cost_micros(
        &cfg.agent.model,
        &garmr_llm::types::Usage {
            input_tokens: 200,
            output_tokens: 80,
        },
    );
    assert_eq!(
        store.state.budget_spent_micros(&day).unwrap(),
        expected,
        "ledger = settled actuals, reservations refunded"
    );
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn clean_hunt_reports_clean_and_no_detections() {
    let base = tmp("clean");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let llm = MockLlm::new(vec![MockLlm::tool_turn(
        "submit_hunt_report",
        serde_json::json!({"outcome": "clean"}),
    )]);
    let report = run_hunt(&store, &llm, &cfg, "ad-hoc", "anything strange?", None)
        .await
        .unwrap();
    assert_eq!(report.outcome, HuntOutcome::Clean);
    assert!(findings_to_detections(&report).is_empty());
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn iteration_cap_ends_as_needs_human() {
    let base = tmp("cap");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base); // max_iterations = 4
    let llm = MockLlm::new(vec![
        MockLlm::tool_turn("query_events", serde_json::json!({"sql": "SELECT 1"})),
        MockLlm::tool_turn("query_events", serde_json::json!({"sql": "SELECT 1"})),
        MockLlm::tool_turn("query_events", serde_json::json!({"sql": "SELECT 1"})),
        MockLlm::tool_turn("query_events", serde_json::json!({"sql": "SELECT 1"})),
    ]);
    let report = run_hunt(&store, &llm, &cfg, "ad-hoc", "loop?", None)
        .await
        .unwrap();
    assert_eq!(report.outcome, HuntOutcome::NeedsHuman);
    assert!(report
        .stop_reason
        .as_deref()
        .unwrap()
        .contains("iteration limit"));
    assert_eq!(report.iterations, 4);
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn exhausted_budget_stops_before_any_call() {
    let base = tmp("budget");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let day = Utc::now().format("%Y-%m-%d").to_string();
    store.state.budget_add_micros(&day, 10_000_000).unwrap(); // $10 > $5
    let llm = MockLlm::new(vec![]);
    let report = run_hunt(&store, &llm, &cfg, "ad-hoc", "expensive hunt", None)
        .await
        .unwrap();
    assert_eq!(report.outcome, HuntOutcome::NeedsHuman);
    assert!(report.stop_reason.as_deref().unwrap().contains("budget"));
    assert_eq!(llm.calls.load(Ordering::SeqCst), 0);
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn text_only_turn_without_report_needs_human() {
    let base = tmp("noreport");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let llm = MockLlm::new(vec![MockLlm::text_turn("I am done, I think")]);
    let report = run_hunt(&store, &llm, &cfg, "ad-hoc", "hm", None)
        .await
        .unwrap();
    assert_eq!(report.outcome, HuntOutcome::NeedsHuman);
    assert!(report
        .stop_reason
        .as_deref()
        .unwrap()
        .contains("without a report"));
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[test]
fn load_hunts_parses_toml_dir() {
    let dir = tmp("defs");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("beacon.toml"),
        "id = \"beacon-outbound\"\nhypothesis = \"outbound beacons?\"\nschedule_secs = 3600\n",
    )
    .unwrap();
    std::fs::write(dir.join("broken.toml"), "id = ").unwrap();
    std::fs::write(dir.join("ignored.txt"), "not toml").unwrap();
    let hunts = load_hunts(&dir);
    assert_eq!(hunts.len(), 1, "broken + non-toml skipped");
    assert_eq!(hunts[0].id, "beacon-outbound");
    assert_eq!(hunts[0].schedule_secs, 3600);
    std::fs::remove_dir_all(&dir).ok();
}