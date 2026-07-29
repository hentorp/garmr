// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr registry` — inspect the versioned registries. Talks to a running
//! daemon's read API when one is up; otherwise opens the store directly.

use anyhow::Result;
use garmr_core::{active, effective_state, RegistryKind};
use garmr_store::Store;

use super::*;
use crate::cli::RegistryCmd;

fn kind_or_err(s: &str) -> Result<RegistryKind> {
    RegistryKind::from_tag(s).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown registry kind '{s}' \
             (model|prompt|toolset|rule|detector_config|dataset|eval_run|release)"
        )
    })
}

fn short(v: &serde_json::Value, key: &str, n: usize) -> String {
    v[key].as_str().unwrap_or("").chars().take(n).collect()
}

/// POST an admin registry write to the daemon. Registry writes enforce the hard
/// invariant (a versioned record AND a fail-closed audit event) inside the
/// server handler, so — unlike reads — they have no direct-store fallback: a
/// down daemon means the operator gets a clear instruction, not a silently
/// unaudited local write.
async fn post_admin(cfg: &garmr_core::Config, path: &str, body: serde_json::Value) -> Result<()> {
    match try_daemon(cfg, path, Some(body), std::time::Duration::from_secs(30)).await? {
        Some(v) => {
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        None => anyhow::bail!(
            "registry writes need a running daemon with GARMR_ADMIN_TOKEN — \
             start `garmr serve` (with the token set) and retry, or POST {path} directly"
        ),
    }
}

pub(crate) async fn registry_cmd(cli: &Cli, what: &RegistryCmd) -> Result<()> {
    let cfg = load_config(cli)?;
    match what {
        RegistryCmd::List { kind } => {
            let k = kind_or_err(kind)?;
            let records = match try_daemon_get(&cfg, &format!("/api/registry/{}", k.tag())).await? {
                Some(v) => v["records"].clone(),
                None => {
                    let store = Store::open(&cfg).await?;
                    let recs = store.state.list_kind(k)?;
                    let promos = store.state.list_promotions()?;
                    serde_json::to_value(
                        recs.iter()
                            .map(|r| {
                                let mut m = serde_json::to_value(r).unwrap_or_default();
                                if let Some(o) = m.as_object_mut() {
                                    o.insert(
                                        "effective_state".into(),
                                        serde_json::json!(format!(
                                            "{:?}",
                                            effective_state(r, &promos)
                                        )),
                                    );
                                }
                                m
                            })
                            .collect::<Vec<_>>(),
                    )?
                }
            };
            for r in records.as_array().cloned().unwrap_or_default() {
                println!(
                    "{:<15} {:<24} {:<18} {}  [{}]",
                    r["kind"].as_str().unwrap_or("?"),
                    r["name"].as_str().unwrap_or("?"),
                    short(&r, "version", 18),
                    short(&r, "content_digest", 12),
                    r["effective_state"].as_str().unwrap_or("?"),
                );
            }
        }
        RegistryCmd::Show { kind, name } => {
            let k = kind_or_err(kind)?;
            let path = format!("/api/registry/{}/{}", k.tag(), enc(name));
            let v = match try_daemon_get(&cfg, &path).await? {
                Some(v) => v,
                None => {
                    let store = Store::open(&cfg).await?;
                    let recs = store.state.records_for_name(k, name)?;
                    let promos = store.state.promotions_for(k, name)?;
                    let active_d = active(k, name, "production", &recs, &promos)
                        .map(|r| r.content_digest.clone());
                    serde_json::json!({ "active_digest": active_d, "records": recs, "promotions": promos })
                }
            };
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        RegistryCmd::Active => {
            let rows = match try_daemon_get(&cfg, "/api/registry/active").await? {
                Some(v) => v["active"].clone(),
                None => {
                    let store = Store::open(&cfg).await?;
                    let recs = store.state.list_registry()?;
                    let promos = store.state.list_promotions()?;
                    let mut seen = std::collections::HashSet::new();
                    let mut out = Vec::new();
                    for r in &recs {
                        if !seen.insert(format!("{}|{}", r.kind.tag(), r.name)) {
                            continue;
                        }
                        if let Some(a) = active(r.kind, &r.name, "production", &recs, &promos) {
                            out.push(serde_json::to_value(a)?);
                        }
                    }
                    serde_json::Value::Array(out)
                }
            };
            for r in rows.as_array().cloned().unwrap_or_default() {
                println!(
                    "{:<15} {:<24} {:<18} {}",
                    r["kind"].as_str().unwrap_or("?"),
                    r["name"].as_str().unwrap_or("?"),
                    short(&r, "version", 18),
                    short(&r, "content_digest", 12),
                );
            }
        }
        RegistryCmd::Verify => {
            let v = match try_daemon_get(&cfg, "/api/registry/verify").await? {
                Some(v) => v,
                None => {
                    let store = Store::open(&cfg).await?;
                    let recs = store.state.list_registry()?;
                    let promos = store.state.list_promotions()?;
                    let findings = garmr_core::verify_registry(&recs, &promos);
                    serde_json::json!({
                        "ok": findings.is_empty(),
                        "records": recs.len(),
                        "promotions": promos.len(),
                        "findings": findings,
                    })
                }
            };
            let findings = v["findings"].as_array().cloned().unwrap_or_default();
            println!(
                "registry: {} record(s), {} promotion(s)",
                v["records"].as_u64().unwrap_or(0),
                v["promotions"].as_u64().unwrap_or(0),
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
                anyhow::bail!("registry integrity FAILED: {} finding(s)", findings.len());
            }
        }
        RegistryCmd::Register {
            kind,
            name,
            version,
            digest,
            rationale,
        } => {
            let k = kind_or_err(kind)?; // fail fast on a bad tag before the round trip
            post_admin(
                &cfg,
                "/admin/registry/register",
                serde_json::json!({
                    "kind": k.tag(),
                    "name": name,
                    "version": version,
                    "content_digest": digest,
                    "rationale": rationale,
                }),
            )
            .await?;
        }
        RegistryCmd::Promote {
            kind,
            name,
            version,
            channel,
            reason,
        } => promote_verb(&cfg, "promote", kind, name, version, channel, reason).await?,
        RegistryCmd::Rollback {
            kind,
            name,
            version,
            channel,
            reason,
        } => promote_verb(&cfg, "rollback", kind, name, version, channel, reason).await?,
        RegistryCmd::Retire {
            kind,
            name,
            version,
            channel,
            reason,
        } => promote_verb(&cfg, "retire", kind, name, version, channel, reason).await?,
        RegistryCmd::Reject {
            kind,
            name,
            version,
            channel,
            reason,
        } => promote_verb(&cfg, "reject", kind, name, version, channel, reason).await?,
    }
    Ok(())
}

/// The four channel-pointer verbs share one request shape; only the endpoint
/// differs. `op` is the last path segment (`promote|rollback|retire|reject`).
async fn promote_verb(
    cfg: &garmr_core::Config,
    op: &str,
    kind: &str,
    name: &str,
    version: &str,
    channel: &str,
    reason: &str,
) -> Result<()> {
    let k = kind_or_err(kind)?;
    post_admin(
        cfg,
        &format!("/admin/registry/{op}"),
        serde_json::json!({
            "kind": k.tag(),
            "name": name,
            "version": version,
            "channel": channel,
            "reason": reason,
        }),
    )
    .await
}