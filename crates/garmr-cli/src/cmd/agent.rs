// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Agent-backed + governance commands: entity pivot, natural-language `ask`,
//! the response-action propose/approve/execute flow, rule proposal review, and
//! ad-hoc threat `hunt` — several prefer a running daemon and fall back to the store.

use super::*;

pub(crate) async fn entity(cli: &Cli, kind: &str, name: &str) -> Result<()> {
    let cfg = load_config(cli)?;
    if !matches!(kind, "host" | "ip" | "user") {
        anyhow::bail!("entity type must be host, ip or user (got: {kind})");
    }
    let path = format!("/api/entity/{kind}/{}", enc(name));
    let page = match try_daemon_get(&cfg, &path).await? {
        Some(v) => v,
        None => {
            let store = Store::open(&cfg).await?;
            match kind {
                "host" => garmr_agent::entity::host_page(&store, name).await?,
                "ip" => garmr_agent::entity::ip_page(&store, name).await?,
                _ => garmr_agent::entity::user_page(&store, name).await?,
            }
        }
    };
    println!("{}", serde_json::to_string_pretty(&page)?);
    Ok(())
}

pub(crate) async fn ask(cli: &Cli, question: &str) -> Result<()> {
    let cfg = load_config(cli)?;
    let answer = match try_daemon_get(&cfg, &format!("/api/ask?q={}", enc(question))).await? {
        Some(v) => v,
        None => {
            let store = Store::open(&cfg).await?;
            let llm = build_provider_for(&cfg.agent, cfg.route.router.default_classification)
                .context("building LLM provider")?;
            // Local one-shot ask (daemon not running): no in-process semantic
            // backend here — the daemon path serves semantic-enabled asks.
            let a = garmr_agent::ask(&store, llm.as_ref(), &cfg, question, None).await?;
            serde_json::to_value(a)?
        }
    };
    // Human-first rendering: the grounded answer, then the plan + cited rows.
    if let Some(text) = answer.get("answer").and_then(|v| v.as_str()) {
        println!("{text}\n");
    }
    if let Some(query) = answer.get("query") {
        println!("query: {query}");
    }
    if let Some(status) = answer.get("semantic_status").and_then(|v| v.as_str()) {
        if status == "requested_but_unavailable" {
            println!("(semantic requested but unavailable — structured + full-text only)");
        }
    }
    if let Some(rows) = answer.get("rows").and_then(|v| v.as_array()) {
        for (i, row) in rows.iter().enumerate() {
            println!("[{i}] {row}");
        }
        if answer
            .get("truncated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            println!("[… truncated]");
        }
    }
    if let Some(cost) = answer.get("cost_usd").and_then(|v| v.as_f64()) {
        eprintln!("(cost: ${cost:.4})");
    }
    Ok(())
}

pub(crate) async fn action_cmd(cli: &Cli, what: &ActionCmd) -> Result<()> {
    let cfg = load_config(cli)?;
    match what {
        ActionCmd::Propose {
            kind,
            arg,
            case,
            rationale,
        } => {
            let k = match kind.as_str() {
                "block_ip" => garmr_core::ActionKind::BlockIp,
                "isolate_host" => garmr_core::ActionKind::IsolateHost,
                _ => anyhow::bail!("kind must be block_ip or isolate_host"),
            };
            garmr_agent::validate_arg(k, arg).map_err(|e| anyhow::anyhow!(e))?;
            // A hand-authored proposal writes directly to the store (operator
            // path — no daemon needed; requires serve stopped).
            let store = Store::open(&cfg).await?;
            // Accept a case id prefix (cases list prints 8-char prefixes).
            let case_id = store
                .state
                .get_case(case)?
                .map(|c| c.id)
                .or_else(|| {
                    store.state.list_cases().ok().and_then(|cs| {
                        cs.into_iter()
                            .find(|c| c.id.starts_with(case))
                            .map(|c| c.id)
                    })
                })
                .with_context(|| format!("no case matches {case}"))?;
            let a = garmr_core::ActionProposal {
                id: uuid::Uuid::new_v4().to_string(),
                kind: k,
                arg: arg.clone(),
                case_id,
                rationale: rationale.clone(),
                state: garmr_core::ActionState::Proposed,
                created_at: Utc::now(),
                decided_at: None,
                executed_at: None,
                result: None,
                audit: vec![garmr_core::ActionEvent {
                    at: Utc::now(),
                    actor: "operator".into(),
                    detail: format!("proposed {} {arg}", k.as_str()),
                }],
            };
            store.state.put_action_proposal(&a)?;
            println!(
                "proposal created: {}  {} {arg}  (case {case})",
                &a.id[..8],
                k.as_str()
            );
        }
        ActionCmd::List => {
            let list = match try_daemon_get(&cfg, "/api/actions").await? {
                Some(v) => v["actions"].clone(),
                None => {
                    let store = Store::open(&cfg).await?;
                    serde_json::to_value(store.state.list_actions()?)?
                }
            };
            for a in list.as_array().cloned().unwrap_or_default() {
                println!(
                    "{}  {}  {} {}  (case {})  {}",
                    a["id"]
                        .as_str()
                        .unwrap_or("?")
                        .chars()
                        .take(8)
                        .collect::<String>(),
                    a["state"].as_str().unwrap_or("?"),
                    a["kind"].as_str().unwrap_or("?"),
                    sanitize(a["arg"].as_str().unwrap_or("")),
                    a["case_id"]
                        .as_str()
                        .unwrap_or("?")
                        .chars()
                        .take(8)
                        .collect::<String>(),
                    a["result"].as_str().map(sanitize).unwrap_or_default(),
                );
            }
        }
        ActionCmd::Show { id } => {
            let v = match try_daemon_get(&cfg, &format!("/api/actions/{}", enc(id))).await? {
                Some(v) => v,
                None => {
                    let store = Store::open(&cfg).await?;
                    serde_json::to_value(
                        store
                            .state
                            .get_action(id)?
                            .with_context(|| format!("no action {id}"))?,
                    )?
                }
            };
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        ActionCmd::Approve { id } => {
            let v = match try_daemon(
                &cfg,
                "/admin/action/approve",
                Some(serde_json::json!({ "id": id })),
                std::time::Duration::from_secs(30),
            )
            .await?
            {
                Some(v) => v,
                None => {
                    // Local human gate (daemon down → running the CLI IS the
                    // approval). open_writable refuses on a restored follower;
                    // audit fail-closed BEFORE the transition, matching the
                    // rules-approve discipline (no unaudited protected mutation).
                    let store = Store::open_writable(&cfg).await?;
                    crate::audit::ensure_init(&cfg.audit)?;
                    crate::audit::record_admin_local(
                        garmr_audit::action::ACTION_DECIDE,
                        "action_proposal",
                        Some(id),
                        Some("approved (local CLI)"),
                    )?;
                    let a = store.state.transition_action(
                        id,
                        &[garmr_core::ActionState::Proposed],
                        garmr_core::ActionState::Approved,
                        "operator",
                        "approved via CLI",
                        None,
                        Utc::now(),
                    )?;
                    serde_json::json!({ "action": a })
                }
            };
            let _ = v;
            println!(
                "approved. Carried out by the executor loop, or run `garmr execute` (serve stopped)."
            );
        }
        ActionCmd::Deny { id, reason } => {
            let v = match try_daemon(
                &cfg,
                "/admin/action/deny",
                Some(serde_json::json!({ "id": id, "reason": reason })),
                std::time::Duration::from_secs(30),
            )
            .await?
            {
                Some(v) => v,
                None => {
                    // Local human gate — same discipline as Approve: open_writable
                    // refuses on a restored follower, audit fail-closed first.
                    let store = Store::open_writable(&cfg).await?;
                    crate::audit::ensure_init(&cfg.audit)?;
                    let detail = if reason.is_empty() {
                        "denied (local CLI)".to_string()
                    } else {
                        format!("denied (local CLI): {reason}")
                    };
                    crate::audit::record_admin_local(
                        garmr_audit::action::ACTION_DECIDE,
                        "action_proposal",
                        Some(id),
                        Some(&detail),
                    )?;
                    let a = store.state.transition_action(
                        id,
                        &[
                            garmr_core::ActionState::Proposed,
                            garmr_core::ActionState::Approved,
                        ],
                        garmr_core::ActionState::Denied,
                        "operator",
                        if reason.is_empty() {
                            "denied via CLI"
                        } else {
                            reason
                        },
                        None,
                        Utc::now(),
                    )?;
                    serde_json::json!({ "action": a })
                }
            };
            let _ = v;
            println!("denied.");
        }
    }
    Ok(())
}

pub(crate) async fn execute_cmd(cli: &Cli) -> Result<()> {
    let cfg = load_config(cli)?;
    // Manual run: only valid when serve is NOT holding the store. `open_writable`
    // enforces that (it takes the exclusive writer lock) AND refuses on a restored
    // but unpromoted follower — otherwise this path would re-run stale Approved
    // actions on a node that must stay a read-only follower. The executor
    // re-validates every approved action independently before acting.
    let store = Store::open_writable(&cfg)
        .await
        .context("could not open store (run `garmr execute` only when serve is stopped)")?;
    // The apply step is a protected mutation — make sure the ledger is live so
    // each executed action lands an audit record (fail-closed init).
    crate::audit::ensure_init(&cfg.audit)?;
    let ex = garmr_agent::Executor::new(store, cfg);
    let done = ex.run_once().await?;
    if done.is_empty() {
        println!("no approved actions to carry out.");
    }
    for (id, outcome) in done {
        crate::audit::record_execute(&id, &outcome);
        println!("{}  {:?}", id.chars().take(8).collect::<String>(), outcome);
    }
    Ok(())
}

pub(crate) async fn rules_cmd(cli: &Cli, what: &RulesCmd) -> Result<()> {
    let cfg = load_config(cli)?;
    match what {
        RulesCmd::Import {
            path,
            write,
            allow_unknown,
        } => {
            return crate::cmd::rules_import(cli, path, *write, *allow_unknown).await;
        }
        RulesCmd::Propose { request } => {
            let v = match try_daemon(
                &cfg,
                "/api/rules/propose",
                Some(serde_json::json!({ "request": request })),
                std::time::Duration::from_secs(660),
            )
            .await?
            {
                Some(v) => v,
                None => {
                    let store = Store::open(&cfg).await?;
                    let llm =
                        build_provider_for(&cfg.agent, cfg.route.router.default_classification)
                            .context("building LLM provider")?;
                    let p = garmr_agent::propose_rule(&store, llm.as_ref(), &cfg, request).await?;
                    // The agent's read-only side: record the drafted proposal
                    // best-effort (it only ever creates a pending artifact).
                    crate::audit::ensure_init(&cfg.audit)?;
                    crate::audit::record_agent_best_effort(
                        garmr_audit::action::RULE_PROPOSE,
                        "rule_proposal",
                        &p.id,
                        &p.title,
                    );
                    serde_json::to_value(p)?
                }
            };
            print_proposal(&v, true);
        }
        RulesCmd::Proposals => {
            let list = match try_daemon_get(&cfg, "/api/rules/proposals").await? {
                Some(v) => v["proposals"].clone(),
                None => {
                    let store = Store::open(&cfg).await?;
                    serde_json::to_value(store.state.list_proposals()?)?
                }
            };
            for p in list.as_array().cloned().unwrap_or_default() {
                println!(
                    "{}  {}  {}  [{}]  hits={}  {}",
                    p["id"]
                        .as_str()
                        .unwrap_or("?")
                        .chars()
                        .take(8)
                        .collect::<String>(),
                    p["created_at"].as_str().unwrap_or("?"),
                    p["status"].as_str().unwrap_or("?"),
                    p["kind"].as_str().unwrap_or("?"),
                    p["backtest"]["hits"].as_u64().unwrap_or(0),
                    p["title"].as_str().unwrap_or(""),
                );
            }
        }
        RulesCmd::Show { id } => {
            let v = match try_daemon_get(&cfg, &format!("/api/rules/proposals/{}", enc(id))).await?
            {
                Some(v) => v,
                None => {
                    let store = Store::open(&cfg).await?;
                    let p = store
                        .state
                        .get_proposal(id)?
                        .with_context(|| format!("no proposal matches {id}"))?;
                    serde_json::to_value(p)?
                }
            };
            print_proposal(&v, true);
        }
        RulesCmd::Approve { id } => {
            // The ACT side. Via daemon: /admin (requires the token = the human
            // approval). Without a daemon: running the CLI locally IS the human.
            let v = match try_daemon(
                &cfg,
                "/admin/rules/approve",
                Some(serde_json::json!({ "id": id })),
                std::time::Duration::from_secs(30),
            )
            .await?
            {
                Some(v) => v,
                None => {
                    let store = Store::open(&cfg).await?;
                    // Running the CLI locally IS the human approval — audit it
                    // fail-closed (the daemon down means no /admin audit happened
                    // for us). Init the ledger first; safe because this branch
                    // only runs when serve is not holding the writer.
                    crate::audit::ensure_init(&cfg.audit)?;
                    let audit_id = crate::audit::record_admin_local(
                        garmr_audit::action::RULE_DECIDE,
                        "rule_proposal",
                        Some(id),
                        Some("approved (local CLI)"),
                    )?;
                    let (p, path) =
                        garmr_agent::approve_proposal(&store, &cfg, id, audit_id).await?;
                    serde_json::json!({ "proposal": p, "path": path })
                }
            };
            println!(
                "approved → {}
NOTE: the rule takes effect at the next `garmr serve` restart.",
                v["path"].as_str().unwrap_or("?")
            );
        }
        RulesCmd::Reject { id, reason } => {
            let v = match try_daemon(
                &cfg,
                "/admin/rules/reject",
                Some(serde_json::json!({ "id": id, "reason": reason })),
                std::time::Duration::from_secs(30),
            )
            .await?
            {
                Some(v) => v,
                None => {
                    let store = Store::open(&cfg).await?;
                    let p = store.state.decide_proposal(
                        id,
                        garmr_core::ProposalStatus::Rejected,
                        Some(reason.clone()).filter(|r| !r.is_empty()),
                        Utc::now(),
                    )?;
                    serde_json::to_value(p)?
                }
            };
            let _ = v;
            println!("rejected.");
        }
    }
    Ok(())
}

/// Strip terminal control sequences from model/log-derived text before it is
/// printed — the approve decision is made from this display, and an ANSI
/// escape in a log line must not be able to redraw or spoof it.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

fn print_proposal(v: &serde_json::Value, full: bool) {
    if v.get("accepted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        println!(
            "{}",
            v["note"].as_str().unwrap_or("continuing in the background")
        );
        return;
    }
    println!(
        "{}  {}  [{}]  {}",
        v["id"]
            .as_str()
            .unwrap_or("?")
            .chars()
            .take(8)
            .collect::<String>(),
        v["status"].as_str().unwrap_or("?"),
        v["kind"].as_str().unwrap_or("?"),
        v["title"].as_str().unwrap_or(""),
    );
    if let Some(r) = v["rationale"].as_str().filter(|r| !r.is_empty()) {
        println!("rationale: {r}");
    }
    let bt = &v["backtest"];
    // Prefer the health verdict (healthy/silent/noisy/insufficient) — it's what a
    // reviewer needs to decide whether to enable. Fall back to raw counts if the
    // shape is unexpected.
    match serde_json::from_value::<garmr_core::Backtest>(bt.clone()) {
        Ok(b) => println!("backtest: {}", b.describe()),
        Err(_) => println!(
            "backtest: {} hits of {} scanned ({}h)",
            bt["hits"].as_u64().unwrap_or(0),
            bt["scanned"].as_u64().unwrap_or(0),
            bt["window_hours"].as_u64().unwrap_or(0),
        ),
    }
    for s in bt["samples"].as_array().cloned().unwrap_or_default() {
        println!("  e.g.: {}", s.as_str().unwrap_or(""));
    }
    if full {
        println!(
            "--- rule ---
{}",
            v["rule_body"].as_str().unwrap_or("")
        );
    }
    if let Some(c) = v["cost_usd"].as_f64() {
        eprintln!("(cost: ${c:.4})");
    }
}

pub(crate) async fn hunt_cmd(
    cli: &Cli,
    hypothesis: Option<&str>,
    report: Option<&str>,
) -> Result<()> {
    let cfg = load_config(cli)?;
    if let Some(prefix) = report {
        // One report, full transcript. Daemon first, store fallback.
        let v = match try_daemon_get(&cfg, &format!("/api/hunts/{}", enc(prefix))).await? {
            Some(v) => v,
            None => {
                let store = Store::open(&cfg).await?;
                let r = store
                    .state
                    .list_hunt_reports()?
                    .into_iter()
                    .find(|r| r.id.starts_with(prefix))
                    .with_context(|| format!("no hunt report matches {prefix}"))?;
                serde_json::to_value(r)?
            }
        };
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    let Some(hypothesis) = hypothesis else {
        // List reports.
        let v = match try_daemon_get(&cfg, "/api/hunts").await? {
            Some(v) => v["hunts"].clone(),
            None => {
                let store = Store::open(&cfg).await?;
                serde_json::to_value(
                    store
                        .state
                        .list_hunt_reports()?
                        .iter()
                        .map(|r| {
                            serde_json::json!({
                                "id": r.id, "hunt_id": r.hunt_id, "outcome": r.outcome,
                                "findings": r.findings.len(), "started_at": r.started_at,
                                "hypothesis": r.hypothesis, "cost_usd": r.cost_usd,
                            })
                        })
                        .collect::<Vec<_>>(),
                )?
            }
        };
        for r in v.as_array().cloned().unwrap_or_default() {
            println!(
                "{}  {}  {}  findings={}  ${:.4}  {}",
                r["id"]
                    .as_str()
                    .unwrap_or("?")
                    .chars()
                    .take(8)
                    .collect::<String>(),
                r["started_at"].as_str().unwrap_or("?"),
                r["outcome"].as_str().unwrap_or("?"),
                r["findings"].as_u64().unwrap_or(0),
                r["cost_usd"].as_f64().unwrap_or(0.0),
                r["hypothesis"].as_str().unwrap_or(""),
            );
        }
        return Ok(());
    };
    // Run an ad-hoc hunt. Daemon first (it holds the key + the store); local
    // fallback needs a key in THIS environment. Client timeout outlasts the
    // server's 600s hunt budget.
    let v = match try_daemon(
        &cfg,
        "/api/hunt",
        Some(serde_json::json!({ "hypothesis": hypothesis })),
        std::time::Duration::from_secs(660),
    )
    .await?
    {
        Some(v) => v,
        None => {
            let store = Store::open(&cfg).await?;
            let llm = build_provider_for(&cfg.agent, cfg.route.router.default_classification)
                .context("building LLM provider")?;
            // One-shot hunt: no daemon-loaded embedder to share, so no semantic
            // clause (matches one-shot triage). The daemon path (POST /api/hunt /
            // the scheduled loop) hands the shared backend in.
            let r = garmr_agent::run_hunt(&store, llm.as_ref(), &cfg, "ad-hoc", hypothesis, None)
                .await?;
            serde_json::to_value(r)?
        }
    };
    if v.get("accepted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        println!(
            "{}",
            v["note"].as_str().unwrap_or("continuing in the background")
        );
        return Ok(());
    }
    println!("outcome: {}", v["outcome"].as_str().unwrap_or("?"));
    if let Some(reason) = v["stop_reason"].as_str() {
        println!("stop: {reason}");
    }
    for f in v["findings"].as_array().cloned().unwrap_or_default() {
        println!(
            "\nFINDING [{}/10] {}\n  host={} src_ip={}\n  {}",
            f["severity"].as_u64().unwrap_or(0),
            sanitize(f["title"].as_str().unwrap_or("?")),
            sanitize(f["host"].as_str().unwrap_or("-")),
            sanitize(f["src_ip"].as_str().unwrap_or("-")),
            sanitize(f["evidence"].as_str().unwrap_or("")),
        );
    }
    eprintln!(
        "(report {} · {} iterations · ${:.4})",
        v["id"]
            .as_str()
            .unwrap_or("?")
            .chars()
            .take(8)
            .collect::<String>(),
        v["iterations"].as_u64().unwrap_or(0),
        v["cost_usd"].as_f64().unwrap_or(0.0),
    );
    Ok(())
}
