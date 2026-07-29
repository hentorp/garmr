// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr env` — inspect and govern the temporal environment model. Reads talk
//! to a running daemon's read API when one is up, else open the store directly;
//! writes (promote/demote/import) are admin-gated and go through the daemon
//! (GARMR_ADMIN_TOKEN), never a silently-unaudited local path.

use anyhow::Result;
use garmr_core::EntityKind;
use garmr_store::Store;

use super::*;
use crate::cli::EnvCmd;

/// POST an admin env write to the daemon. Like the registry writes, these have no
/// direct-store fallback — the anti-poisoning gate + fail-closed audit live in
/// the server handler, so a down daemon yields an instruction, not an unaudited
/// local write.
async fn post_admin(cfg: &garmr_core::Config, path: &str, body: serde_json::Value) -> Result<()> {
    match try_daemon(cfg, path, Some(body), std::time::Duration::from_secs(30)).await? {
        Some(v) => {
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        None => anyhow::bail!(
            "environment writes need a running daemon with GARMR_ADMIN_TOKEN — \
             start `garmr serve` (with the token set) and retry, or POST {path} directly"
        ),
    }
}

/// Print a materialized fact row compactly.
fn print_fact(f: &serde_json::Value) {
    println!(
        "{:<14} {:<26} {:<10} {:<10} obs={:<4} src={} {}",
        f["entity"]["kind"].as_str().unwrap_or("?"),
        f["entity"]["id"].as_str().unwrap_or("?"),
        f["state"].as_str().unwrap_or("?"),
        f["value"].as_str().unwrap_or(""),
        f["observation_count"].as_u64().unwrap_or(0),
        f["distinct_sources"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        if f["conflict_needs_human"].as_bool().unwrap_or(false) {
            "[conflict]"
        } else {
            ""
        },
    );
}

pub(crate) async fn env_cmd(cli: &Cli, what: &EnvCmd) -> Result<()> {
    let cfg = load_config(cli)?;
    match what {
        EnvCmd::Facts { state } => {
            let path = match state {
                Some(s) => format!("/api/env/facts?state={}", enc(s)),
                None => "/api/env/facts".to_string(),
            };
            let rows = match try_daemon_get(&cfg, &path).await? {
                Some(v) => v["facts"].clone(),
                None => {
                    let store = Store::open(&cfg).await?;
                    let ttl = Some(cfg.environment.to_policy().fact_ttl);
                    let mut facts = store.state.list_env_facts(ttl, chrono::Utc::now())?;
                    if let Some(want) = state {
                        facts.retain(|f| format!("{:?}", f.state).eq_ignore_ascii_case(want));
                    }
                    serde_json::to_value(facts)?
                }
            };
            for f in rows.as_array().cloned().unwrap_or_default() {
                print_fact(&f);
            }
        }
        EnvCmd::Candidates => {
            let rows = match try_daemon_get(&cfg, "/api/env/candidates").await? {
                Some(v) => v["candidates"].clone(),
                None => {
                    let store = Store::open(&cfg).await?;
                    let ttl = Some(cfg.environment.to_policy().fact_ttl);
                    let facts: Vec<_> = store
                        .state
                        .list_env_facts(ttl, chrono::Utc::now())?
                        .into_iter()
                        .filter(|f| f.state == garmr_core::FactState::Candidate)
                        .collect();
                    serde_json::to_value(facts)?
                }
            };
            for f in rows.as_array().cloned().unwrap_or_default() {
                print_fact(&f);
            }
        }
        EnvCmd::Show { kind, id, as_of } => {
            let k = EntityKind::from_tag(kind)
                .ok_or_else(|| anyhow::anyhow!("unknown entity kind '{kind}'"))?;
            let mut path = format!("/api/env/entity/{}/{}", k.tag(), enc(id));
            if let Some(t) = as_of {
                path.push_str(&format!("?as_of={}", enc(t)));
            }
            let v = match try_daemon_get(&cfg, &path).await? {
                Some(v) => v,
                None => {
                    let store = Store::open(&cfg).await?;
                    let ttl = Some(cfg.environment.to_policy().fact_ttl);
                    let now = chrono::Utc::now();
                    let all = store.state.list_env_facts(ttl, now)?;
                    let ours: Vec<_> = all
                        .iter()
                        .filter(|f| f.entity.kind == k && &f.entity.id == id)
                        .collect();
                    let facts = match as_of {
                        Some(s) => {
                            let t = chrono::DateTime::parse_from_rfc3339(s)
                                .map_err(|e| anyhow::anyhow!("invalid --as-of (rfc3339): {e}"))?
                                .with_timezone(&chrono::Utc);
                            ours.iter()
                                .filter_map(|f| {
                                    store.state.env_fact_asof(&f.fact_id, t).ok().flatten()
                                })
                                .collect::<Vec<_>>()
                        }
                        None => ours.into_iter().cloned().collect(),
                    };
                    serde_json::json!({ "facts": facts })
                }
            };
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        EnvCmd::Verify => {
            let v = match try_daemon_get(&cfg, "/api/env/verify").await? {
                Some(v) => v,
                None => {
                    let store = Store::open(&cfg).await?;
                    let obs = store.state.list_env_observations()?;
                    let tr = store.state.list_env_transitions()?;
                    let findings = garmr_core::verify_environment(&obs, &tr);
                    serde_json::json!({
                        "ok": findings.is_empty(),
                        "observations": obs.len(),
                        "transitions": tr.len(),
                        "findings": findings,
                    })
                }
            };
            let findings = v["findings"].as_array().cloned().unwrap_or_default();
            println!(
                "environment: {} observation(s), {} transition(s)",
                v["observations"].as_u64().unwrap_or(0),
                v["transitions"].as_u64().unwrap_or(0),
            );
            for f in &findings {
                println!(
                    "  FAIL {}  {}: {}",
                    f["category"].as_str().unwrap_or("?"),
                    f["coord"].as_str().unwrap_or("?"),
                    f["detail"].as_str().unwrap_or(""),
                );
            }
            if findings.is_empty() {
                println!("integrity: OK");
            } else {
                anyhow::bail!(
                    "environment integrity FAILED: {} finding(s)",
                    findings.len()
                );
            }
        }
        EnvCmd::Promote { fact_id, reason } => {
            post_admin(
                &cfg,
                "/admin/env/promote",
                serde_json::json!({ "fact_id": fact_id, "reason": reason }),
            )
            .await?;
        }
        EnvCmd::Approve { fact_id, reason } => {
            post_admin(
                &cfg,
                "/admin/env/approve",
                serde_json::json!({ "fact_id": fact_id, "reason": reason }),
            )
            .await?;
        }
        EnvCmd::Demote {
            fact_id,
            state,
            reason,
        } => {
            post_admin(
                &cfg,
                "/admin/env/demote",
                serde_json::json!({ "fact_id": fact_id, "state": state, "reason": reason }),
            )
            .await?;
        }
        EnvCmd::Retire { fact_id, reason } => {
            post_admin(
                &cfg,
                "/admin/env/retire",
                serde_json::json!({ "fact_id": fact_id, "reason": reason }),
            )
            .await?;
        }
        EnvCmd::Import {
            file,
            source,
            trust,
        } => {
            let content = std::fs::read_to_string(file)
                .with_context(|| format!("reading {}", file.display()))?;
            let format = match file.extension().and_then(|e| e.to_str()) {
                Some("json") => "json",
                _ => "toml",
            };
            let mut body = serde_json::json!({
                "source_id": source,
                "format": format,
                "content": content,
            });
            if let Some(t) = trust {
                body["trust"] = serde_json::json!(t);
            }
            post_admin(&cfg, "/admin/env/import", body).await?;
        }
    }
    Ok(())
}