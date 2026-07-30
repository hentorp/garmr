// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr app-baseline` — inspect and govern the Phase 7/8 application-audit
//! behavioral baselines. The daemon owns the authoritative in-memory store (the
//! detectors query it), so reads prefer the daemon API and every write goes
//! THROUGH it (GARMR_ADMIN_TOKEN) — never a second process opening the
//! single-writer state DB behind the daemon's back.

use anyhow::Result;

use super::*;
use crate::cli::AppBaselineCmd;

/// POST an admin baseline write to the daemon. Like the env/registry writes,
/// there is no direct-store fallback — the guard re-check + fail-closed audit
/// live in the server handler, and a down daemon must yield an instruction, not
/// an unaudited (and soon-to-be-clobbered) local write.
async fn post_admin(cfg: &garmr_core::Config, path: &str, body: serde_json::Value) -> Result<()> {
    match try_daemon(cfg, path, Some(body), std::time::Duration::from_secs(30)).await? {
        Some(v) => {
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        None => anyhow::bail!(
            "baseline writes need a running daemon with GARMR_ADMIN_TOKEN — start \
             `garmr serve` (with the token set) and retry, or POST {path} directly"
        ),
    }
}

pub(crate) async fn appbaseline_cmd(cli: &Cli, what: &AppBaselineCmd) -> Result<()> {
    let cfg = load_config(cli)?;
    match what {
        AppBaselineCmd::List => {
            let rows = match try_daemon_get(&cfg, "/api/appaudit/baselines").await? {
                Some(v) => v["baselines"].clone(),
                None => anyhow::bail!(
                    "the behavioral baselines live in the running daemon's memory — \
                     start `garmr serve` and query it (the store is single-process)"
                ),
            };
            let rows = rows.as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("no behavioral baselines learned yet");
                return Ok(());
            }
            println!(
                "{:<16} {:<24} {:<12} {:<10} {:>5} {:>5}d  quality",
                "KIND", "ID", "STATE", "MATURITY", "obs", "span"
            );
            for b in &rows {
                println!(
                    "{:<16} {:<24} {:<12} {:<10} {:>5} {:>5}  {}",
                    b["kind"].as_str().unwrap_or("?"),
                    b["id"].as_str().unwrap_or("?"),
                    b["state"].as_str().unwrap_or("?"),
                    b["maturity"].as_str().unwrap_or("?"),
                    b["observations"].as_u64().unwrap_or(0),
                    b["span_days"].as_i64().unwrap_or(0),
                    if b["data_quality_degraded"].as_bool().unwrap_or(false) {
                        "[degraded]"
                    } else {
                        "ok"
                    },
                );
            }
        }
        AppBaselineCmd::Promote { kind, id, reason } => {
            post_admin(
                &cfg,
                "/admin/appaudit/baselines/promote",
                serde_json::json!({ "kind": kind, "id": id, "reason": reason }),
            )
            .await?;
        }
        AppBaselineCmd::Suspect { kind, id, reason } => {
            post_admin(
                &cfg,
                "/admin/appaudit/baselines/suspect",
                serde_json::json!({ "kind": kind, "id": id, "reason": reason }),
            )
            .await?;
        }
        AppBaselineCmd::Clear { kind, id, reason } => {
            post_admin(
                &cfg,
                "/admin/appaudit/baselines/clear",
                serde_json::json!({ "kind": kind, "id": id, "reason": reason }),
            )
            .await?;
        }
    }
    Ok(())
}
