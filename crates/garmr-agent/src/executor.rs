// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The response-action executor — the ONLY code in garmr that changes system
//! state, deliberately isolated from the agent's reasoning.
//!
//! It acts only on proposals a human moved to `Approved` (an authenticated,
//! out-of-band transition the agent cannot perform), and even then it never
//! trusts the stored proposal: it INDEPENDENTLY re-validates the argument
//! shape, re-checks that the linked case still supports acting, and refuses
//! anything irreversible. garmr ships no capability of its own — each action
//! runs an operator-configured argv template (no shell) with the validated
//! argument substituted; with none set the executor refuses and records the
//! exact manual command.
//!
//! Capability separation, concretely: the agent path only ever calls
//! `store.put_action_proposal` (state `Proposed`). Reaching `Approved` goes
//! through `store.transition_action(Proposed → Approved)`, invoked only by the
//! human gate (admin bearer / local CLI). This executor only ever transitions
//! `Approved → Executed|Failed`. No agent-reachable code calls it.

use std::process::Stdio;

use chrono::Utc;
use garmr_core::{ActionKind, ActionProposal, ActionState, Config, Disposition, Result};
use garmr_store::Store;

use crate::validate::{reversible, validate_arg};

/// Runs approved actions. Holds the store and the operator's action config.
pub struct Executor {
    store: Store,
    cfg: Config,
}

/// The outcome of processing one approved action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Executed,
    /// Refused by re-validation or missing capability (terminal `Failed`), with
    /// the reason.
    Refused(String),
    Failed(String),
}

impl Executor {
    pub fn new(store: Store, cfg: Config) -> Self {
        Self { store, cfg }
    }

    /// Process every currently-`Approved` action once. Returns (id, outcome)
    /// per action. Never panics; a failure on one action doesn't stop others.
    pub async fn run_once(&self) -> Result<Vec<(String, Outcome)>> {
        let approved = self.store.state.actions_in_state(ActionState::Approved)?;
        let mut out = Vec::new();
        for a in approved {
            let outcome = self.execute(&a).await;
            out.push((a.id.clone(), outcome));
        }
        Ok(out)
    }

    /// Per-command wall-clock cap: a hung firewall command must not wedge the
    /// serial executor loop for every other approved action.
    const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    /// Re-validate then act on ONE approved action, recording the terminal
    /// state. Public for `garmr execute` + tests.
    pub async fn execute(&self, a: &ActionProposal) -> Outcome {
        // 1. Independent re-validation — never trust the stored proposal.
        if let Err(why) = self.revalidate(a) {
            return self.fail(a, format!("re-validation rejected: {why}"));
        }
        // 2. Capability: an operator argv template, or refuse with the manual
        //    command spelled out.
        let Some(template) = self.cfg.executor.template(a.kind) else {
            let manual = format!(
                "no executor template for {} — run the action manually (arg: {}). Undo with: {}",
                a.kind.as_str(),
                a.arg,
                a.kind.reversal_hint()
            );
            return self.fail(a, manual);
        };
        // 3. Build argv with the validated arg substituted for `{arg}` (no
        //    shell — injection is impossible regardless, and the arg is
        //    already shape-validated).
        let argv: Vec<String> = template
            .iter()
            .map(|part| part.replace("{arg}", &a.arg))
            .collect();
        let Some((cmd, args)) = argv.split_first() else {
            return self.fail(a, "empty executor template".into());
        };
        // 4. CLAIM the action BEFORE the side effect: Approved → Executing,
        //    persisted. If the process dies mid-command the action is stuck in
        //    Executing (a human reconciles) — it is NEVER silently re-run,
        //    because run_once only picks Approved. This is the at-most-once
        //    guard for a non-idempotent firewall command.
        if let Err(e) = self.store.state.transition_action(
            &a.id,
            &[ActionState::Approved],
            ActionState::Executing,
            "executor",
            "running action",
            None,
            Utc::now(),
        ) {
            // Lost the race to a concurrent deny/executor — don't act.
            return Outcome::Failed(format!("could not claim action: {e}"));
        }
        // 5. Run it — with a hardened child: no inherited env (garmr's secrets
        //    must not leak to the operator command), no stdin, killed on
        //    timeout.
        let run = tokio::process::Command::new(cmd)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output();
        let result = tokio::time::timeout(Self::CMD_TIMEOUT, run).await;
        match result {
            Ok(Ok(o)) if o.status.success() => {
                let summary = format!(
                    "ran: {} {}\n{}",
                    cmd,
                    args.join(" "),
                    String::from_utf8_lossy(&o.stdout)
                        .chars()
                        .take(1000)
                        .collect::<String>()
                );
                match self.store.state.transition_action(
                    &a.id,
                    &[ActionState::Executing],
                    ActionState::Executed,
                    "executor",
                    "action executed",
                    Some(summary),
                    Utc::now(),
                ) {
                    Ok(_) => Outcome::Executed,
                    Err(e) => Outcome::Failed(format!("could not save result: {e}")),
                }
            }
            Ok(Ok(o)) => self.finish_failed(
                a,
                format!(
                    "the command exited {}: {}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr)
                        .chars()
                        .take(1000)
                        .collect::<String>()
                ),
            ),
            Ok(Err(e)) => self.finish_failed(a, format!("could not start the command: {e}")),
            Err(_) => self.finish_failed(
                a,
                format!(
                    "the command exceeded {}s and was aborted",
                    Self::CMD_TIMEOUT.as_secs()
                ),
            ),
        }
    }

    /// Record a terminal `Failed` for an action already moved to `Executing`
    /// (the command ran/attempted). Distinct from [`fail`], which fails an
    /// action still in `Approved` (rejected before the side effect).
    fn finish_failed(&self, a: &ActionProposal, reason: String) -> Outcome {
        tracing::warn!(action = %a.id, kind = a.kind.as_str(), %reason, "action command failed");
        let _ = self.store.state.transition_action(
            &a.id,
            &[ActionState::Executing],
            ActionState::Failed,
            "executor",
            &reason,
            Some(reason.clone()),
            Utc::now(),
        );
        Outcome::Failed(reason)
    }

    /// Independent re-validation: argument shape + evidence + reversibility.
    /// This is the executor's own check — the proposal is NOT trusted.
    fn revalidate(&self, a: &ActionProposal) -> std::result::Result<(), String> {
        // Reversibility bias (all current kinds are reversible by construction;
        // this refuses any future irreversible kind that slips in unhandled).
        if !reversible(a.kind) {
            return Err("the action is not reversible".into());
        }
        // Argument shape.
        validate_arg(a.kind, &a.arg)?;
        // Operator never-block list (own mgmt IP, gateway, resolvers). A
        // config guardrail BELOW the human — it can't be argued away by a
        // plausible rationale.
        if a.kind == ActionKind::BlockIp && self.cfg.executor.is_never_block(&a.arg) {
            return Err(format!("{} is on the never_block list", a.arg));
        }
        // Evidence: the case must still exist AND carry a non-benign EFFECTIVE
        // disposition. Phase 3 resolves it through the trust precedence — a final
        // incident outcome or human analyst decision overrides the agent's shadow
        // verdict, so a human "benign" de-authorizes a pending action even if the
        // agent called it malicious. With no human/incident record this is
        // exactly the pre-Phase-3 behavior (the shadow verdict): an un-triaged
        // case (no judgement at all) authorizes nothing, and a benign one is stale.
        let case = self
            .store
            .state
            .get_case(&a.case_id)
            .map_err(|e| format!("could not read the case: {e}"))?
            .ok_or("the case no longer exists")?;
        // Fail CLOSED on a read fault: a human's benign override lives in these
        // tables, so if they cannot be read we must refuse — never silently
        // revert to the agent's (stale) shadow verdict and re-authorize an action
        // a human may have de-authorized.
        let decisions = self
            .store
            .state
            .decisions_for(&a.case_id)
            .map_err(|e| format!("could not read the case's decisions: {e}"))?;
        let outcomes = self
            .store
            .state
            .outcomes_for_case(&a.case_id)
            .map_err(|e| format!("could not read the case's incident outcomes: {e}"))?;
        let effective = garmr_core::current_outcome(&outcomes)
            .map(|o| o.disposition)
            .or_else(|| garmr_core::current_decision(&decisions).map(|d| d.disposition))
            .or_else(|| case.verdict.as_ref().map(|v| v.disposition));
        match effective {
            None => return Err("the case is not yet triaged — no action authorized".into()),
            Some(Disposition::Benign) => {
                return Err("the case was judged benign — the action is no longer warranted".into())
            }
            Some(_) => {}
        }
        // The argument must be ATTESTED by the case's evidence — the executor's
        // core backstop against a plausible-but-injected proposal a human might
        // rubber-stamp. isolate_host: the host must be the case's host.
        // block_ip: the IP must appear in the case's evidence (src_ip or any
        // IP-shaped field value), not an arbitrary model-supplied address.
        match a.kind {
            ActionKind::IsolateHost => {
                if case.trigger.event.host != a.arg {
                    return Err("the host does not match the case's host".into());
                }
            }
            ActionKind::BlockIp => {
                if !case_attests_ip(&case, &a.arg) {
                    return Err(format!(
                        "IP {} does not appear in the case's evidence — refusing to block an unrelated address",
                        a.arg
                    ));
                }
            }
        }
        Ok(())
    }

    /// Fail an action still in `Approved` (rejected before any side effect).
    fn fail(&self, a: &ActionProposal, reason: String) -> Outcome {
        tracing::warn!(action = %a.id, kind = a.kind.as_str(), %reason, "action refused/failed");
        let refused = reason.starts_with("re-validation")
            || reason.starts_with("no executor template")
            || reason.contains("not reversible");
        let _ = self.store.state.transition_action(
            &a.id,
            &[ActionState::Approved],
            ActionState::Failed,
            "executor",
            &reason,
            Some(reason.clone()),
            Utc::now(),
        );
        if refused {
            Outcome::Refused(reason)
        } else {
            Outcome::Failed(reason)
        }
    }
}

/// Does the case's evidence reference `ip`? Checks the trigger event's src_ip
/// and every field value that parses as an IP — the executor only blocks an
/// address the case actually observed.
fn case_attests_ip(case: &garmr_core::Case, ip: &str) -> bool {
    let target: Option<std::net::IpAddr> = ip.parse().ok();
    let same = |candidate: &str| -> bool {
        match (target, candidate.parse::<std::net::IpAddr>()) {
            (Some(t), Ok(c)) => t == c,
            _ => candidate == ip,
        }
    };
    let ev = &case.trigger.event;
    if ev.src_ip().is_some_and(same) {
        return true;
    }
    ev.fields.values().any(|v| same(v))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use garmr_core::{
        ActionEvent, ActionKind, ActionProposal, ActionState, Case, Detection, Disposition, Event,
        Verdict,
    };

    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("garmr-exec-{tag}-{n}"))
    }

    fn cfg(base: &std::path::Path) -> Config {
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

    async fn store_with_case(base: &std::path::Path, disposition: Option<Disposition>) -> Store {
        std::fs::create_dir_all(base).unwrap();
        let store = Store::open_writable(&cfg(base)).await.unwrap();
        let mut ev = Event {
            ts: Utc::now(),
            host: "pve".into(),
            service: "sshd".into(),
            source: "journald".into(),
            environment: "test".into(),
            severity: "warning".into(),
            log_type: "auth".into(),
            message: "Failed password".into(),
            fields: BTreeMap::new(),
        };
        ev.fields.insert("src_ip".into(), "203.0.113.7".into());
        let mut case = Case::open(Detection {
            rule_id: "garmr-ssh-failed-password".into(),
            rule_title: "t".into(),
            level: "high".into(),
            attack: vec![],
            event: ev,
            observed_at: Utc::now(),
            realert_secs: None,
        });
        case.verdict = disposition.map(|d| Verdict {
            disposition: d,
            severity: 8,
            confidence: 0.9,
            rationale: "x".into(),
            proposed_action: None,
        });
        store.state.put_case(&case).unwrap();
        store
    }

    fn proposal(kind: ActionKind, arg: &str, case_id: &str) -> ActionProposal {
        ActionProposal {
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            arg: arg.into(),
            case_id: case_id.into(),
            rationale: "test".into(),
            state: ActionState::Approved,
            created_at: Utc::now(),
            decided_at: Some(Utc::now()),
            executed_at: None,
            result: None,
            audit: vec![ActionEvent {
                at: Utc::now(),
                actor: "test".into(),
                detail: "approved".into(),
            }],
        }
    }

    #[test]
    fn never_block_list_covers_ip_and_cidr() {
        use garmr_core::ExecutorConfig;
        let e = ExecutorConfig {
            never_block: vec!["192.0.2.1".into(), "203.0.113.0/24".into()],
            ..Default::default()
        };
        assert!(e.is_never_block("192.0.2.1"));
        assert!(e.is_never_block("203.0.113.7"), "inside the /24");
        assert!(!e.is_never_block("203.0.114.7"), "outside the /24");
        assert!(!e.is_never_block("8.8.8.8"));
    }

    #[tokio::test]
    async fn untriaged_case_does_not_authorize_an_action() {
        let base = tmp("untriaged");
        let store = store_with_case(&base, None).await; // no verdict
        let case_id = store.state.list_cases().unwrap()[0].id.clone();
        let mut c = cfg(&base);
        c.executor.block_ip = Some(vec!["true".into(), "{arg}".into()]);
        let a = proposal(ActionKind::BlockIp, "203.0.113.7", &case_id);
        store
            .state
            .put_action_proposal(&ActionProposal {
                state: ActionState::Proposed,
                ..a.clone()
            })
            .unwrap();
        store
            .state
            .transition_action(
                &a.id,
                &[ActionState::Proposed],
                ActionState::Approved,
                "human",
                "ok",
                None,
                Utc::now(),
            )
            .unwrap();
        let ex = Executor::new(store.clone(), c);
        let got = store.state.get_action(&a.id).unwrap().unwrap();
        assert!(matches!(ex.execute(&got).await, Outcome::Refused(ref r) if r.contains("triaged")));
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn block_ip_unrelated_to_case_is_refused() {
        let base = tmp("unrelated");
        let store = store_with_case(&base, Some(Disposition::Malicious)).await;
        let case_id = store.state.list_cases().unwrap()[0].id.clone();
        let mut c = cfg(&base);
        c.executor.block_ip = Some(vec!["true".into(), "{arg}".into()]);
        // A public IP NOT in the case evidence (case attests 203.0.113.7).
        let a = proposal(ActionKind::BlockIp, "1.1.1.1", &case_id);
        store
            .state
            .put_action_proposal(&ActionProposal {
                state: ActionState::Proposed,
                ..a.clone()
            })
            .unwrap();
        store
            .state
            .transition_action(
                &a.id,
                &[ActionState::Proposed],
                ActionState::Approved,
                "human",
                "ok",
                None,
                Utc::now(),
            )
            .unwrap();
        let ex = Executor::new(store.clone(), c);
        let got = store.state.get_action(&a.id).unwrap().unwrap();
        assert!(
            matches!(ex.execute(&got).await, Outcome::Refused(ref r) if r.contains("unrelated")),
            "an IP the case never observed must not be blocked"
        );
        assert_eq!(
            store.state.get_action(&a.id).unwrap().unwrap().state,
            ActionState::Failed
        );
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn never_block_refuses_even_a_case_attested_ip() {
        let base = tmp("neverblock");
        let store = store_with_case(&base, Some(Disposition::Malicious)).await;
        let case_id = store.state.list_cases().unwrap()[0].id.clone();
        let mut c = cfg(&base);
        c.executor.block_ip = Some(vec!["true".into(), "{arg}".into()]);
        c.executor.never_block = vec!["203.0.113.0/24".into()]; // covers the case IP
        let a = proposal(ActionKind::BlockIp, "203.0.113.7", &case_id);
        store
            .state
            .put_action_proposal(&ActionProposal {
                state: ActionState::Proposed,
                ..a.clone()
            })
            .unwrap();
        store
            .state
            .transition_action(
                &a.id,
                &[ActionState::Proposed],
                ActionState::Approved,
                "human",
                "ok",
                None,
                Utc::now(),
            )
            .unwrap();
        let ex = Executor::new(store.clone(), c);
        let got = store.state.get_action(&a.id).unwrap().unwrap();
        assert!(
            matches!(ex.execute(&got).await, Outcome::Refused(ref r) if r.contains("never_block"))
        );
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn no_template_refuses_with_manual_command_and_marks_failed() {
        let base = tmp("notmpl");
        let store = store_with_case(&base, Some(Disposition::Malicious)).await;
        let a = proposal(ActionKind::BlockIp, "203.0.113.7", "");
        // Point the proposal at the seeded case.
        let case_id = store.state.list_cases().unwrap()[0].id.clone();
        let a = ActionProposal { case_id, ..a };
        store
            .state
            .put_action_proposal(&ActionProposal {
                state: ActionState::Proposed,
                ..a.clone()
            })
            .unwrap();
        // Approve it (human gate), then execute.
        store
            .state
            .transition_action(
                &a.id,
                &[ActionState::Proposed],
                ActionState::Approved,
                "human",
                "ok",
                None,
                Utc::now(),
            )
            .unwrap();
        let ex = Executor::new(store.clone(), cfg(&base));
        let got = store.state.get_action(&a.id).unwrap().unwrap();
        let outcome = ex.execute(&got).await;
        assert!(matches!(outcome, Outcome::Refused(ref r) if r.contains("no executor template")));
        assert_eq!(
            store.state.get_action(&a.id).unwrap().unwrap().state,
            ActionState::Failed
        );
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn benign_case_evidence_refuses_the_action() {
        let base = tmp("benign");
        let store = store_with_case(&base, Some(Disposition::Benign)).await;
        let case_id = store.state.list_cases().unwrap()[0].id.clone();
        let mut c = cfg(&base);
        c.executor.block_ip = Some(vec!["true".into(), "{arg}".into()]); // would succeed if run
        let a = proposal(ActionKind::BlockIp, "203.0.113.7", &case_id);
        store
            .state
            .put_action_proposal(&ActionProposal {
                state: ActionState::Proposed,
                ..a.clone()
            })
            .unwrap();
        store
            .state
            .transition_action(
                &a.id,
                &[ActionState::Proposed],
                ActionState::Approved,
                "human",
                "ok",
                None,
                Utc::now(),
            )
            .unwrap();
        let ex = Executor::new(store.clone(), c);
        let got = store.state.get_action(&a.id).unwrap().unwrap();
        let outcome = ex.execute(&got).await;
        assert!(
            matches!(outcome, Outcome::Refused(ref r) if r.contains("benign")),
            "{outcome:?}"
        );
        assert_eq!(
            store.state.get_action(&a.id).unwrap().unwrap().state,
            ActionState::Failed
        );
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn trusted_benign_decision_deauthorizes_a_malicious_shadow() {
        // The agent called the case MALICIOUS (shadow verdict)...
        let base = tmp("decision-benign");
        let store = store_with_case(&base, Some(Disposition::Malicious)).await;
        let case_id = store.state.list_cases().unwrap()[0].id.clone();
        // ...but a human analyst DECIDED it benign — a trusted record that
        // overrides the agent's prediction in the executor gate (Phase 3).
        let mut d: garmr_core::AnalystDecision = serde_json::from_str("{}").unwrap();
        d.decision_id = "d1".into();
        d.case_id = case_id.clone();
        d.disposition = Disposition::Benign;
        d.created_at = Utc::now();
        store.state.append_decision(&d).unwrap();

        let mut c = cfg(&base);
        c.executor.block_ip = Some(vec!["true".into(), "{arg}".into()]);
        let a = proposal(ActionKind::BlockIp, "203.0.113.7", &case_id);
        store
            .state
            .put_action_proposal(&ActionProposal {
                state: ActionState::Proposed,
                ..a.clone()
            })
            .unwrap();
        store
            .state
            .transition_action(
                &a.id,
                &[ActionState::Proposed],
                ActionState::Approved,
                "human",
                "ok",
                None,
                Utc::now(),
            )
            .unwrap();
        let ex = Executor::new(store.clone(), c);
        let got = store.state.get_action(&a.id).unwrap().unwrap();
        let outcome = ex.execute(&got).await;
        assert!(
            matches!(outcome, Outcome::Refused(ref r) if r.contains("benign")),
            "a trusted benign decision must de-authorize the action: {outcome:?}"
        );
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn happy_path_runs_template_and_marks_executed() {
        let base = tmp("happy");
        let store = store_with_case(&base, Some(Disposition::Malicious)).await;
        let case_id = store.state.list_cases().unwrap()[0].id.clone();
        let mut c = cfg(&base);
        // `true` ignores its arg and exits 0 — a safe stand-in for a real cmd.
        c.executor.block_ip = Some(vec!["true".into(), "{arg}".into()]);
        let a = proposal(ActionKind::BlockIp, "203.0.113.7", &case_id);
        store
            .state
            .put_action_proposal(&ActionProposal {
                state: ActionState::Proposed,
                ..a.clone()
            })
            .unwrap();
        store
            .state
            .transition_action(
                &a.id,
                &[ActionState::Proposed],
                ActionState::Approved,
                "human",
                "ok",
                None,
                Utc::now(),
            )
            .unwrap();
        let ex = Executor::new(store.clone(), c);
        let got = store.state.get_action(&a.id).unwrap().unwrap();
        assert_eq!(ex.execute(&got).await, Outcome::Executed);
        let done = store.state.get_action(&a.id).unwrap().unwrap();
        assert_eq!(done.state, ActionState::Executed);
        assert!(done.result.is_some());
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn a_non_approved_action_is_never_executed() {
        let base = tmp("state");
        let store = store_with_case(&base, Some(Disposition::Malicious)).await;
        let case_id = store.state.list_cases().unwrap()[0].id.clone();
        let mut c = cfg(&base);
        c.executor.block_ip = Some(vec!["true".into()]);
        // A still-Proposed action (never approved by a human): run_once must
        // not touch it — capability separation's core guarantee.
        let a = ActionProposal {
            state: ActionState::Proposed,
            ..proposal(ActionKind::BlockIp, "203.0.113.7", &case_id)
        };
        store.state.put_action_proposal(&a).unwrap();
        let ex = Executor::new(store.clone(), c);
        let done = ex.run_once().await.unwrap();
        assert!(done.is_empty(), "run_once only touches Approved actions");
        assert_eq!(
            store.state.get_action(&a.id).unwrap().unwrap().state,
            ActionState::Proposed
        );
        drop(store);
        std::fs::remove_dir_all(&base).ok();
    }
}
