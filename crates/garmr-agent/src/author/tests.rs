// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Unit tests for the authoring loop: a scripted `MockLlm` drives
//! `propose_rule`/`approve_proposal` end to end — draft→validate→backtest→
//! persist, repair-on-rejection, id-collision + noisy-rule gating, and the
//! atomic approve/re-backtest path.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use garmr_core::{Backtest, Event, ProposalKind};
use garmr_llm::types::{LlmResponse, ToolCall};
use serde_json::Value;

use super::*;

struct MockLlm {
    script: Mutex<Vec<LlmResponse>>,
    calls: AtomicUsize,
    seen: Mutex<Vec<LlmRequest>>,
}

impl MockLlm {
    fn new(script: Vec<LlmResponse>) -> Self {
        Self {
            script: Mutex::new(script),
            calls: AtomicUsize::new(0),
            seen: Mutex::new(vec![]),
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
                output_tokens: 40,
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
    async fn complete(&self, req: &LlmRequest) -> garmr_core::Result<LlmResponse> {
        self.seen.lock().unwrap().push(req.clone());
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
    std::env::temp_dir().join(format!("garmr-author-{tag}-{n}"))
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

const VALID_SIGMA: &str = "\
title: Sudo auth failure burst
id: garmr-proposed-sudo-fail
status: experimental
description: test
logsource:
    product: linux
    service: sudo
detection:
    selection:
        service: sudo
        message|contains: 'authentication failure'
    condition: selection
level: medium
";

async fn seeded_store(base: &std::path::Path) -> Store {
    std::fs::create_dir_all(base).unwrap();
    let store = Store::open_writable(&test_cfg(base)).await.unwrap();
    let events: Vec<Event> = (0..3)
        .map(|i| Event {
            ts: Utc::now(),
            host: "pve".into(),
            service: "sudo".into(),
            source: "journald".into(),
            environment: "test".into(),
            severity: "warning".into(),
            log_type: "auth".into(),
            message: format!("pam_unix(sudo:auth): authentication failure {i}"),
            fields: BTreeMap::new(),
        })
        .collect();
    store.events.append(events).await.unwrap();
    store
}

/// A store with `n` sudo auth-failure events — enough to cross
/// `MIN_SCAN_FOR_RATE` so the noisy-rate gate engages.
async fn seeded_store_n(base: &std::path::Path, n: usize) -> Store {
    std::fs::create_dir_all(base).unwrap();
    let store = Store::open_writable(&test_cfg(base)).await.unwrap();
    let events: Vec<Event> = (0..n)
        .map(|i| Event {
            ts: Utc::now(),
            host: "pve".into(),
            service: "sudo".into(),
            source: "journald".into(),
            environment: "test".into(),
            severity: "warning".into(),
            log_type: "auth".into(),
            message: format!("pam_unix(sudo:auth): authentication failure {i}"),
            fields: BTreeMap::new(),
        })
        .collect();
    store.events.append(events).await.unwrap();
    store
}

#[tokio::test]
async fn drafts_validates_backtests_and_persists_sigma() {
    let base = tmp("sigma");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let llm = MockLlm::new(vec![MockLlm::tool_turn(
        "submit_rule_proposal",
        serde_json::json!({
            "kind": "sigma",
            "title": "Sudo auth failure",
            "rationale": "3 hits in the data",
            "rule_body": VALID_SIGMA,
        }),
    )]);
    let p = propose_rule(&store, &llm, &cfg, "catch sudo failures")
        .await
        .unwrap();
    assert_eq!(p.status, ProposalStatus::Pending);
    assert_eq!(p.backtest.hits, 3, "backtest replayed the seeded events");
    assert_eq!(p.backtest.scanned, 3);
    assert!(!p.backtest.samples.is_empty());
    assert_eq!(store.state.list_proposals().unwrap().len(), 1);
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn invalid_draft_is_returned_for_repair() {
    let base = tmp("repair");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let llm = MockLlm::new(vec![
        MockLlm::tool_turn(
            "submit_rule_proposal",
            serde_json::json!({
                "kind": "sigma",
                "title": "broken",
                "rationale": "",
                "rule_body": "this is not: [valid sigma",
            }),
        ),
        MockLlm::tool_turn(
            "submit_rule_proposal",
            serde_json::json!({
                "kind": "sigma",
                "title": "fixed",
                "rationale": "second attempt",
                "rule_body": VALID_SIGMA,
            }),
        ),
    ]);
    let p = propose_rule(&store, &llm, &cfg, "catch sudo failures")
        .await
        .unwrap();
    assert_eq!(p.title, "fixed", "the repaired second draft landed");
    assert_eq!(llm.calls.load(Ordering::SeqCst), 2);
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn correlation_with_write_sql_is_rejected_and_never_persisted() {
    let base = tmp("evil");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let evil = r#"
id = "evil"
title = "evil"
severity = "high"
message = "x"
sql = "DROP TABLE events"
"#;
    let llm = MockLlm::new(vec![
        MockLlm::tool_turn(
            "submit_rule_proposal",
            serde_json::json!({
                "kind": "correlation",
                "title": "evil",
                "rationale": "",
                "rule_body": evil,
            }),
        ),
        // The rejection goes back for repair; the model gives up.
        MockLlm::text_turn("I cannot write that rule"),
    ]);
    let err = propose_rule(&store, &llm, &cfg, "do something evil")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("without a rule proposal"), "{err}");
    assert_eq!(
        store.state.list_proposals().unwrap().len(),
        0,
        "no proposal persisted for a guard-rejected rule"
    );
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn approve_writes_rule_file_and_double_approve_fails() {
    let base = tmp("approve");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let llm = MockLlm::new(vec![MockLlm::tool_turn(
        "submit_rule_proposal",
        serde_json::json!({
            "kind": "sigma",
            "title": "Sudo auth failure",
            "rationale": "",
            "rule_body": VALID_SIGMA,
        }),
    )]);
    let p = propose_rule(&store, &llm, &cfg, "catch sudo failures")
        .await
        .unwrap();

    let (decided, path) = approve_proposal(&store, &cfg, &p.id[..8], None)
        .await
        .unwrap();
    assert_eq!(decided.status, ProposalStatus::Approved);
    assert!(path.exists(), "rule file written");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), VALID_SIGMA);
    // The written file loads as a real rule.
    assert!(
        garmr_detect::Detector::load(&cfg.detect.rules_dir)
            .unwrap()
            .rule_count()
            >= 1
    );

    // Immutable once decided: a second approval (or rejection) fails.
    assert!(approve_proposal(&store, &cfg, &p.id, None).await.is_err());
    assert!(store
        .state
        .decide_proposal(&p.id, ProposalStatus::Rejected, None, Utc::now())
        .is_err());
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

/// An approval carrying an audit id projects the rule into the registry AND
/// promotes it live on production, bound to that audit event.
#[tokio::test]
async fn approving_with_an_audit_id_projects_and_promotes_the_rule() {
    use garmr_core::{active, ApprovalState, RegistryKind};

    let base = tmp("registry-projection");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let llm = MockLlm::new(vec![MockLlm::tool_turn(
        "submit_rule_proposal",
        serde_json::json!({
            "kind": "sigma",
            "title": "sudo failures",
            "rationale": "repeated auth failures",
            "rule_body": VALID_SIGMA,
        }),
    )]);
    let p = propose_rule(&store, &llm, &cfg, "catch sudo failures")
        .await
        .unwrap();

    let (decided, _path) = approve_proposal(&store, &cfg, &p.id, Some("audit-xyz".into()))
        .await
        .unwrap();

    // One immutable Rule record, bound to the approval audit, marked Approved.
    let recs = store
        .state
        .records_for_name(RegistryKind::Rule, &decided.id)
        .unwrap();
    assert_eq!(recs.len(), 1, "one registered rule record");
    assert_eq!(recs[0].audit_id.as_deref(), Some("audit-xyz"));
    assert_eq!(recs[0].approval, ApprovalState::Approved);

    // And it is the LIVE record on production (an audited promotion).
    let promos = store
        .state
        .promotions_for(RegistryKind::Rule, &decided.id)
        .unwrap();
    let live = active(
        RegistryKind::Rule,
        &decided.id,
        "production",
        &recs,
        &promos,
    );
    assert_eq!(
        live.map(|r| r.content_digest.as_str()),
        Some(recs[0].content_digest.as_str()),
        "the approved rule is active on production"
    );

    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

/// With auditing disabled (no audit id), the approval still registers the rule
/// but leaves NO live promotion — the hard invariant: nothing goes live without
/// an audited promotion.
#[tokio::test]
async fn approving_without_an_audit_id_registers_but_never_promotes() {
    use garmr_core::{active, RegistryKind};

    let base = tmp("registry-noaudit");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let llm = MockLlm::new(vec![MockLlm::tool_turn(
        "submit_rule_proposal",
        serde_json::json!({
            "kind": "sigma",
            "title": "sudo failures",
            "rationale": "repeated auth failures",
            "rule_body": VALID_SIGMA,
        }),
    )]);
    let p = propose_rule(&store, &llm, &cfg, "catch sudo failures")
        .await
        .unwrap();

    let (decided, _path) = approve_proposal(&store, &cfg, &p.id, None).await.unwrap();

    let recs = store
        .state
        .records_for_name(RegistryKind::Rule, &decided.id)
        .unwrap();
    assert_eq!(recs.len(), 1, "registered even with auditing off");
    let promos = store
        .state
        .promotions_for(RegistryKind::Rule, &decided.id)
        .unwrap();
    assert!(promos.is_empty(), "no promotion without an audit id");
    assert!(
        active(
            RegistryKind::Rule,
            &decided.id,
            "production",
            &recs,
            &promos
        )
        .is_none(),
        "nothing is live without an audited promotion"
    );

    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn failed_reapprove_leaves_installed_rule_file_intact() {
    let base = tmp("reapprove");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    let llm = MockLlm::new(vec![MockLlm::tool_turn(
        "submit_rule_proposal",
        serde_json::json!({
            "kind": "sigma", "title": "x", "rationale": "",
            "rule_body": VALID_SIGMA,
        }),
    )]);
    let p = propose_rule(&store, &llm, &cfg, "catch sudo failures")
        .await
        .unwrap();
    let (_, path) = approve_proposal(&store, &cfg, &p.id, None).await.unwrap();
    assert!(path.exists());

    // A retried approve (operator double-click, client timeout retry) must
    // FAIL WITHOUT deleting the installed rule file.
    assert!(approve_proposal(&store, &cfg, &p.id, None).await.is_err());
    assert!(
        path.exists(),
        "retry must not delete the winner's rule file"
    );
    // No stray staging file left behind either.
    assert!(!path.with_extension("yml.tmp").exists());
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn rejection_answers_every_tool_use_in_the_turn() {
    let base = tmp("siblings");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    // One turn carrying BOTH a query_events call and an invalid submit:
    // the rejection round must answer BOTH ids or the next call 400s.
    let both = LlmResponse {
        text: String::new(),
        tool_calls: vec![
            ToolCall {
                id: "q1".into(),
                name: "query_events".into(),
                input: serde_json::json!({"sql": "SELECT count(*) FROM events"}),
            },
            ToolCall {
                id: "s1".into(),
                name: "submit_rule_proposal".into(),
                input: serde_json::json!({
                    "kind": "sigma", "title": "trasig", "rationale": "",
                    "rule_body": "not: [yaml",
                }),
            },
        ],
        assistant_blocks: vec![
            Block::ToolUse {
                id: "q1".into(),
                name: "query_events".into(),
                input: serde_json::json!({"sql": "SELECT count(*) FROM events"}),
            },
            Block::ToolUse {
                id: "s1".into(),
                name: "submit_rule_proposal".into(),
                input: serde_json::json!({}),
            },
        ],
        stop_reason: StopReason::ToolUse,
        usage: garmr_llm::types::Usage {
            input_tokens: 200,
            output_tokens: 80,
        },
    };
    let llm = MockLlm::new(vec![
        both,
        MockLlm::tool_turn(
            "submit_rule_proposal",
            serde_json::json!({
                "kind": "sigma", "title": "lagad", "rationale": "",
                "rule_body": VALID_SIGMA,
            }),
        ),
    ]);
    let p = propose_rule(&store, &llm, &cfg, "catch sudo failures")
        .await
        .unwrap();
    assert_eq!(p.title, "lagad");
    // The SECOND request's last user turn must carry tool_results for BOTH
    // q1 and s1 — a dangling tool_use id would 400 the real API.
    let seen = llm.seen.lock().unwrap();
    let last_user = seen[1]
        .messages
        .iter()
        .rev()
        .find(|m| matches!(m.role, Role::User))
        .expect("a user turn with tool results");
    let ids: Vec<&str> = last_user
        .content
        .iter()
        .filter_map(|b| match b {
            Block::ToolResult { tool_use_id, .. } => Some(tool_use_id.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        ids.contains(&"q1") && ids.contains(&"s1"),
        "both ids answered: {ids:?}"
    );
    drop(seen);
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn colliding_rule_id_is_rejected_for_repair() {
    let base = tmp("collide");
    let store = seeded_store(&base).await;
    let cfg = test_cfg(&base);
    // An existing on-disk rule owns the id already.
    std::fs::create_dir_all(&cfg.detect.rules_dir).unwrap();
    std::fs::write(cfg.detect.rules_dir.join("existing.yml"), VALID_SIGMA).unwrap();

    let llm = MockLlm::new(vec![
        MockLlm::tool_turn(
            "submit_rule_proposal",
            serde_json::json!({
                "kind": "sigma", "title": "collision", "rationale": "",
                "rule_body": VALID_SIGMA, // same id as existing.yml
            }),
        ),
        MockLlm::text_turn("giving up"),
    ]);
    let err = propose_rule(&store, &llm, &cfg, "duplicate")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("without a rule proposal"), "{err}");
    assert_eq!(store.state.list_proposals().unwrap().len(), 0);
    // The rejection reached the model (two calls happened).
    assert_eq!(llm.calls.load(Ordering::SeqCst), 2);
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn noisy_rule_is_rejected_at_draft() {
    // 60 events, all matching a broad rule → 100% hit-rate over >50 scanned
    // → Noisy. The draft must be handed back for repair, never persisted.
    let base = tmp("noisy-draft");
    let store = seeded_store_n(&base, 60).await;
    let cfg = test_cfg(&base);
    let llm = MockLlm::new(vec![
        MockLlm::tool_turn(
            "submit_rule_proposal",
            serde_json::json!({
                "kind": "sigma", "title": "everything", "rationale": "",
                "rule_body": VALID_SIGMA, // matches every seeded event
            }),
        ),
        MockLlm::text_turn("giving up"),
    ]);
    let err = propose_rule(&store, &llm, &cfg, "too broad")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("without a rule proposal"), "{err}");
    assert_eq!(
        store.state.list_proposals().unwrap().len(),
        0,
        "no noisy rule persisted"
    );
    // The rejection reached the model (it got a second turn to repair).
    assert_eq!(llm.calls.load(Ordering::SeqCst), 2);
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}

#[tokio::test]
async fn approve_refuses_a_rule_that_is_now_noisy() {
    // A proposal that passed draft-time backtest (against little data) but is
    // noisy against the CURRENT data must be refused at enable time — and the
    // rule file must not be written.
    let base = tmp("noisy-approve");
    let store = seeded_store_n(&base, 60).await;
    let cfg = test_cfg(&base);
    // Persist a pending proposal directly (bypass the draft gate) with a
    // stale, healthy-looking draft-time backtest.
    let proposal = RuleProposal {
        id: uuid::Uuid::new_v4().to_string(),
        kind: ProposalKind::Sigma,
        title: "stale".into(),
        rationale: "".into(),
        rule_body: VALID_SIGMA.into(),
        request: "x".into(),
        backtest: Backtest {
            scanned: 100,
            hits: 1,
            ..Default::default()
        },
        status: ProposalStatus::Pending,
        created_at: Utc::now(),
        decided_at: None,
        decision_note: None,
        cost_usd: 0.0,
    };
    store.state.put_proposal(&proposal).unwrap();

    let err = approve_proposal(&store, &cfg, &proposal.id, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("refusing to enable"), "{err}");
    // Not enabled: still pending, no rule file written.
    let after = store.state.get_proposal(&proposal.id).unwrap().unwrap();
    assert_eq!(after.status, ProposalStatus::Pending);
    let path = cfg
        .detect
        .rules_dir
        .join(format!("garmr-proposed-{}.yml", proposal.id));
    assert!(!path.exists(), "noisy rule must not be written on refusal");
    drop(store);
    std::fs::remove_dir_all(&base).ok();
}