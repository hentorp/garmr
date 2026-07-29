// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `garmr` — a one-person agentic SOC in Rust.
//!
//! Subcommands wire the crates together: `serve` runs the live pipeline
//! (ingest → store → detect → agent → Matrix); `query`/`cases`/`tail` inspect
//! state; `replay` feeds a captured file deterministically; `selftest` exercises
//! the whole agent loop offline against a local model.

mod api;
mod appaudit;
mod audit;
mod backup;
mod bundle;
mod cli;
mod cmd;
mod config_store;
mod egress;
mod ingest_seq;
mod ioc;
mod pipeline;
mod registry_observe;
mod rules;
mod secrets;
mod serve;
mod shadow;

use cli::{ActionCmd, CasesCmd, Cli, Cmd, RecoverCmd, RetentionCmd, RulesCmd, SilenceCmd};
use cmd::*;
pub(crate) use cmd::{parse_case_state, parse_rfc3339, parse_time, Bound};
use ioc::{configured_ioc_feeds, ioc_refresh_loop};
use serve::{build_agent_from, serve};

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use garmr_agent::{format_batches, Agent, Matrix};
use garmr_core::{Case, CaseState, Config, Detection, Event};
use garmr_llm::{build_provider, build_provider_for};
use garmr_store::Store;

/// Airgap mode (`GARMR_AIRGAP=1|true|yes|on`): a single hard switch for the
/// Skidbladnir profile — a deployment with no internet at all. It forbids every
/// network-egress path regardless of what the config or other env vars say:
/// online IOC feed refresh (see [`configured_ioc_feeds`]) and the agent's online
/// lookups (enforced in [`load_config`]). Local file-based IOC feeds and the
/// local GeoIP database are unaffected — offline threat-intel still works.
fn airgap_mode() -> bool {
    // The single source of the GARMR_AIRGAP parse now lives in garmr-core so the
    // chokepoint and this belt-and-suspenders can never disagree.
    garmr_core::egress::airgap_from_env()
}

/// Raise the soft open-file limit to the hard maximum. A DataFusion scan — and,
/// far worse, a `compact_table` rebuild — of the events lakehouse opens every
/// parquet AND manifest file of the current snapshot at once (hundreds on a busy
/// table), on top of the redb + tantivy handles already held. The common 1024
/// soft default then trips EMFILE ("Too many open files") mid-scan, which fails
/// queries and stalls compaction into a leaking retry loop. Doing this in-process
/// makes `garmr serve` self-protecting on ANY host, regardless of whether the
/// service manager set `LimitNOFILE`. Best-effort: logs and continues on refusal.
#[cfg(unix)]
fn raise_fd_limit() {
    // SAFETY: FFI to get/setrlimit with RLIMIT_NOFILE and a fully-initialised
    // `rlimit`; both report failure via return value, checked below.
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "getrlimit(NOFILE) failed");
            return;
        }
        if lim.rlim_cur >= lim.rlim_max {
            return; // already at the ceiling
        }
        lim.rlim_cur = lim.rlim_max;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) == 0 {
            tracing::info!(
                soft = lim.rlim_cur,
                "raised open-file (NOFILE) soft limit to the hard maximum"
            );
        } else {
            tracing::warn!(error = %std::io::Error::last_os_error(), "setrlimit(NOFILE) failed — keeping the default");
        }
    }
}
#[cfg(not(unix))]
fn raise_fd_limit() {}

/// The config file path: `--config`, else `GARMR_CONFIG`, else `garmr.toml`.
fn config_path(cli: &Cli) -> PathBuf {
    cli.config
        .clone()
        .or_else(|| std::env::var("GARMR_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("garmr.toml"))
}

fn load_config(cli: &Cli) -> Result<Config> {
    let path = config_path(cli);
    let mut cfg =
        Config::load(&path).with_context(|| format!("loading config from {}", path.display()))?;
    // Airgap is a hard override, not a default: even if garmr.toml enables online
    // lookups, GARMR_AIRGAP wins. Defense-in-depth alongside the feed gate so no
    // single mis-set knob can open an egress path in an airgapped SOC.
    if airgap_mode() {
        if cfg.agent.allow_online_lookups {
            tracing::warn!("GARMR_AIRGAP set — forcing agent.allow_online_lookups off");
            cfg.agent.allow_online_lookups = false;
        }
        tracing::info!(
            "airgap mode active — no network egress (online IOC feeds + lookups disabled)"
        );
    }
    // Install the ONE egress chokepoint before any network client is built.
    // load_config is the universal entry for every subcommand, so the full
    // policy (config allowlist + ledger sink) is always in place; the airgap bool
    // comes from the env, so GARMR_AIRGAP structurally WINS over config.
    crate::egress::install_policy(airgap_mode(), &cfg.route.egress);
    Ok(cfg)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Give the process room to open the lakehouse (see raise_fd_limit) before
    // any subcommand touches the warehouse.
    raise_fd_limit();

    let cli = Cli::parse();
    // Record the base config path + the loader's override path for the
    // config-write API (process singletons; set here while single-threaded). The
    // override path is resolved from base+env exactly as the loader resolves it,
    // so the API writes the same file the loader reads.
    let base_cfg_path = config_path(&cli);
    crate::config_store::set_base_config_path(base_cfg_path.clone());
    if let Ok(p) = Config::resolve_override_path(&base_cfg_path) {
        // Record the override the process starts with, so the config API can later
        // detect a persisted-but-not-yet-loaded change (a restart is pending).
        let startup_body = std::fs::read_to_string(&p).unwrap_or_default();
        crate::config_store::set_startup_override_hash(crate::config_store::override_hash(&startup_body));
        crate::config_store::set_override_path(p);
    }
    // Hydrate secrets from the sealed store into the environment BEFORE the
    // multi-threaded tokio runtime spawns its worker threads — std::env::set_var
    // is only sound while the process is single-threaded. No-op without a master
    // key; env always wins over a sealed value.
    if let Ok(cfg) = Config::load(&base_cfg_path) {
        if let Some(dir) = cfg.store.state_db.parent() {
            crate::secrets::hydrate(dir);
        }
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(dispatch(cli))
}

async fn dispatch(cli: Cli) -> Result<()> {
    match &cli.cmd {
        Cmd::Serve => serve(&cli).await,
        Cmd::Compact => compact_cmd(&cli).await,
        Cmd::Query { sql } => query(&cli, sql).await,
        Cmd::Cases { what } => cases(&cli, what).await,
        Cmd::Tail { limit } => tail(&cli, *limit).await,
        Cmd::Replay { file, json, format } => replay(&cli, file, *json, format.as_deref()).await,
        Cmd::Search { query, limit } => search(&cli, query, *limit).await,
        Cmd::Findings { host } => findings_cmd(&cli, host.as_deref()).await,
        Cmd::Hsearch {
            text,
            semantic,
            host,
            service,
            source,
            environment,
            severity,
            log_type,
            field,
            since,
            limit,
            rrf_k,
        } => {
            hsearch_cmd(
                &cli,
                text,
                semantic,
                host,
                service,
                source,
                environment,
                severity,
                log_type,
                field,
                *since,
                *limit,
                *rrf_k,
            )
            .await
        }
        Cmd::Correlate { hours } => correlate(&cli, *hours).await,
        Cmd::Anomaly {
            min_count,
            seed_only,
        } => anomaly(&cli, *min_count, *seed_only).await,
        Cmd::Risk { top } => risk_cmd(&cli, *top).await,
        Cmd::Baseline { k, min_count } => baseline_cmd(&cli, *k, *min_count).await,
        Cmd::Graph {
            kind,
            name,
            depth,
            path_to,
            attack_paths,
        } => graph_cmd(&cli, kind, name, *depth, path_to.as_deref(), *attack_paths).await,
        Cmd::Reindex { hours } => reindex_cmd(&cli, *hours).await,
        Cmd::PgauditShip { once } => pgaudit_ship(&cli, *once).await,
        Cmd::SynthEval => synth_eval(&cli).await,
        Cmd::Shadow => shadow_cmd(&cli).await,
        #[cfg(feature = "semantic")]
        Cmd::EmbedIndex { hours, max } => embed_index(&cli, *hours, *max).await,
        #[cfg(feature = "semantic")]
        Cmd::EmbedVerify => embed_verify(&cli).await,
        #[cfg(feature = "semantic")]
        Cmd::Semantic { query, top } => semantic_cmd(&cli, query, *top).await,
        Cmd::Retention { what } => retention(&cli, what).await,
        Cmd::ColdQuery { sql, from, to } => {
            cold_query(&cli, sql, from.as_deref(), to.as_deref()).await
        }
        Cmd::Silence { what } => silence(&cli, what).await,
        Cmd::Entity { kind, name } => entity(&cli, kind, name).await,
        Cmd::Ask { question } => ask(&cli, question).await,
        Cmd::Hunt { hypothesis, report } => {
            hunt_cmd(&cli, hypothesis.as_deref(), report.as_deref()).await
        }
        Cmd::Rules { what } => rules_cmd(&cli, what).await,
        Cmd::Action { what } => action_cmd(&cli, what).await,
        Cmd::Execute => execute_cmd(&cli).await,
        Cmd::Selftest => selftest(&cli).await,
        Cmd::Recover { what } => recover(&cli, what).await,
        Cmd::Eval { file, json } => eval_cmd(&cli, file, *json).await,
        Cmd::Audit { what } => audit::audit_cmd(&cli, what).await,
        Cmd::Registry { what } => registry_cmd(&cli, what).await,
        Cmd::Env { what } => env_cmd(&cli, what).await,
        Cmd::AppBaseline { what } => appbaseline_cmd(&cli, what).await,
        Cmd::Learn { what } => learn_cmd(&cli, what).await,
        Cmd::Reflect { what } => reflect_cmd(&cli, what).await,
        Cmd::Models { for_sensitivity } => models_cmd(&cli, for_sensitivity.as_deref()).await,
        Cmd::Bundle { what } => bundle::bundle_cmd(&cli, what).await,
        Cmd::IngestHealth => ingest_seq::ingest_health_cmd(&cli),
        Cmd::Backup { what } => backup::backup_cmd(&cli, what).await,
    }
}