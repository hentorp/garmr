// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The `serve` daemon: opens the store, wires the full live pipeline (ingest
//! → detect → correlate/analytics → agent → notify, plus the scheduled loops
//! and IOC refresh), builds the detector+agent (build_agent_from), and runs the
//! HA read-only follower mode. The one long-running program mode; the one-shot
//! CLI commands live in their own modules.

use super::*;

/// Build the detector and agent from config against an already-opened store.
/// The caller chooses the store's search mode: writable for serve/replay
/// (they index), read-only for on-demand commands.
pub(crate) type AgentParts = (
    Arc<garmr_detect::Detector>,
    Arc<Agent>,
    Arc<dyn garmr_llm::LlmProvider>,
);

pub(crate) async fn build_agent_from(
    store: &Store,
    cfg: &Config,
    connect_mcp: bool,
) -> Result<AgentParts> {
    let (detector, rule_map) = rules::load(&cfg.detect.rules_dir).context("loading rules")?;
    let detector = Arc::new(detector);
    let rules = Arc::new(rule_map);

    let provider = build_provider(&cfg.agent).context("building LLM provider")?;
    let matrix = cfg.matrix.as_ref().and_then(Matrix::from_env).map(Arc::new);
    let escalate = cfg
        .matrix
        .as_ref()
        .map(|m| m.escalate_severity)
        .unwrap_or(7);
    // Multi-channel alert delivery: Matrix (rooms) + any env-configured sinks
    // (GARMR_WEBHOOK_URL, GARMR_SMTP_*). All gated uniformly by the router.
    let notifier = Arc::new(garmr_agent::Notifier::new(
        matrix,
        garmr_agent::Notifier::sinks_from_env(),
        cfg.environment.detect.profile,
    ));
    let router = Arc::new(garmr_route::AlertRouter::new(
        store.state.clone(),
        cfg.route.throttle_secs,
    ));
    // External MCP intel servers (opt-in; empty config = no children spawned).
    // Only commands that actually run triage connect them — a one-shot
    // correlate/anomaly shouldn't spawn intel children or pass their env.
    let mcp = if connect_mcp {
        garmr_agent::McpClients::connect(&cfg.agent.mcp_servers).await
    } else {
        garmr_agent::McpClients::disabled()
    };

    // Phase 10: the model router owns the default provider + the [route.router]
    // catalog, routing per case through the same egress chokepoint. Empty catalog
    // = today's single provider. `provider` is still returned for the hunt loop.
    let model_router = Arc::new(garmr_llm::ModelRouter::new(
        provider.clone(),
        &cfg.agent,
        &cfg.route.router,
        garmr_core::egress::global().clone(),
    ));
    let agent = Arc::new(Agent::new(
        model_router,
        store.clone(),
        rules,
        cfg.agent.clone(),
        notifier,
        router,
        escalate,
        mcp,
    ));
    Ok((detector, agent, provider))
}

/// HA follower: pull the writer's shipped warehouse snapshot on a timer and
/// serve the **read-only** API over it. Opens the store read-only (no writer
/// lock — `Store::open` creates an empty local state/search and reads the synced
/// warehouse), and reopens + rebinds the API whenever a newer snapshot lands. It
/// never ingests, detects, or runs the agent, so a follower can never become a
/// second writer — there is no split-brain on the write path.
///
/// UNVERIFIED beyond a single host: exercised only as one writer + one follower
/// on the same box. True multi-node failover and consistency-under-write-load
/// have not been proven. See docs/ha-design.md.
async fn serve_follower(cfg: Config) -> Result<()> {
    let ha = garmr_retention::HaSync::from_env()?
        .context("HA follower requires the object store (GARMR_S3_*) to be configured")?;
    let bind = cfg
        .ingest
        .api_bind
        .clone()
        .context("HA follower requires ingest.api_bind — it exists to serve the read API")?;
    api::check_bind_auth(&bind).context("follower API auth configuration")?;
    let wh = cfg.store.warehouse_dir.clone();
    let pull_secs = cfg.ha.pull_interval_secs.max(30);
    tracing::info!(%bind, pull_secs, "HA follower starting — read-only replica");

    let mut have_id = 0u64;
    let mut api_task: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        match ha.pull(&wh, have_id).await {
            Ok(Some(id)) => {
                have_id = id;
                // Rebind the read API over the freshly-synced warehouse. Abort
                // the prior server and give it a moment to release the listener
                // before the new one binds the same address.
                if let Some(t) = api_task.take() {
                    t.abort();
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                let store = Store::open(&cfg)
                    .await
                    .context("opening store (read-only follower)")?;
                let (b, c) = (bind.clone(), cfg.clone());
                api_task = Some(tokio::spawn(async move {
                    // A follower is read-only and runs no detection plane or agent.
                    if let Err(e) = api::serve(&b, store, c, true, None, None).await {
                        tracing::error!(error = %e, "follower read API stopped");
                    }
                }));
                tracing::info!(
                    snapshot = id,
                    "HA follower applied snapshot; read API (re)bound"
                );
            }
            Ok(None) => {
                if api_task.is_none() {
                    tracing::warn!("HA follower: no snapshot shipped yet — waiting for the writer");
                }
            }
            Err(e) => tracing::error!(error = %e, "HA follower pull failed; will retry next tick"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(pull_secs)).await;
    }
}

pub(crate) async fn serve(cli: &Cli) -> Result<()> {
    let cfg = load_config(cli)?;
    // HA read-replica: a follower never opens the store writable and never runs
    // ingest/detection/agent — it pulls the writer's shipped snapshot and serves
    // the read API only. Split off before the writable open so two nodes can
    // never both hold the writer role.
    if cfg.ha.role == garmr_core::HaRole::Follower {
        return serve_follower(cfg).await;
    }
    // A node restored from a backup is a read-only FOLLOWER until an audited
    // `garmr backup promote` clears the marker (Phase-13 invariant #2: a restored
    // node never silently becomes a writer).
    let restored_marker = crate::backup::restored_marker_path(&cfg);
    if restored_marker.exists() {
        anyhow::bail!(
            "this node was restored from a backup and has NOT been promoted — run \
             `garmr backup promote` before serving as a writer (marker: {})",
            restored_marker.display()
        );
    }
    let store = Store::open_writable(&cfg)
        .await
        .context("opening store (writable)")?;
    // Open the tamper-evident audit ledger BEFORE spawning any task, so the
    // detection pipeline (which reads the process-wide singleton) and the API
    // share one ledger. Fail startup loudly if the ledger cannot be opened.
    match crate::audit::ensure_init(&cfg.audit)? {
        Some(l) => {
            tracing::info!(dir = %l.dir().display(), key = %l.key_id(), "audit ledger active")
        }
        None => tracing::warn!(
            "audit ledger DISABLED (audit.enabled = false) — actions are not tamper-evidently recorded"
        ),
    }
    let (detector, agent, provider) = build_agent_from(&store, &cfg, true).await?;

    // Phase 4: auto-register the artifacts this daemon is actually running
    // (system prompt, built-in toolset, triage model) as observed Draft records,
    // and bind the agent to their registry coordinates so every prediction links
    // back to them. LEADER ONLY — the one-shot command paths (which also call
    // build_agent_from) never register or bind, so their predictions are
    // unchanged. Best-effort at the seam: a failure here must not stop serving.
    match crate::registry_observe::observe_running(&store, &cfg) {
        Ok(ids) => agent.set_registry_identities(ids),
        Err(e) => {
            tracing::warn!(error = %e, "registry auto-registration failed — predictions will carry empty registry coordinates")
        }
    }

    // Phase 9: bind the active approved procedural-memory LessonSet, if any.
    // Re-validate at load (defense-in-depth over the promote-time guard): a
    // lesson set that fails the injection/weakening/cap scan is NOT bound —
    // triage runs on the frozen system prompt alone.
    match store.state.active_lesson_set() {
        Ok(Some((version, set))) => {
            let findings = garmr_core::validate_lesson_set(&set.lessons, garmr_core::LESSON_CAPS);
            if findings.is_empty() {
                tracing::info!(version = %version, lessons = set.lessons.len(), "bound approved lesson set");
                agent.set_approved_lessons(version, set);
            } else {
                tracing::warn!(version = %version, findings = findings.len(), "active lesson set failed re-validation at load — running WITHOUT lessons");
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, "loading the active lesson set failed — running without lessons")
        }
    }

    // Startup recovery: resume any case orphaned by a prior crash/restart
    // (persisted New or Investigating but never finished). Runs in the
    // background so serving starts immediately.
    {
        let agent = agent.clone();
        tokio::spawn(async move {
            match agent.triage_pending().await {
                Ok(0) => {}
                Ok(n) => tracing::info!(resumed = n, "resumed orphaned cases from a prior run"),
                Err(e) => tracing::warn!(error = %e, "startup recovery failed"),
            }
        });
    }

    // Threat-intel: refresh the enricher's IOC set from free online feeds
    // (abuse.ch / blocklist.de by default; GARMR_IOC_FEED_URLS overrides, empty
    // disables). Keeps ip_reputation current instead of frozen at startup.
    {
        let feeds = configured_ioc_feeds();
        if !feeds.is_empty() {
            let secs = std::env::var("GARMR_IOC_REFRESH_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(21_600u64);
            tokio::spawn(ioc_refresh_loop(
                agent.enricher(),
                cfg.agent.ioc_feeds.clone(),
                feeds,
                std::time::Duration::from_secs(secs.max(300)),
            ));
        }
    }

    let inflight: pipeline::Inflight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (tx, rx) = tokio::sync::mpsc::channel::<garmr_ingest::IngestBatch>(256);

    // Ingest: native canonical endpoint (primary) + optional syslog, plus the
    // opt-in Loki push receiver under `loki-compat`. A dead ingest listener is
    // FATAL: a SOC daemon that looks healthy but silently collects nothing is
    // worse than one that exits — systemd (Restart=on-failure) brings it back.
    // Phase 12: authenticated collectors (env-source binding). GARMR_COLLECTORS
    // (a JSON array, secret from env — never config/logs) enables per-collector
    // bearer auth on the native endpoint; empty/unset = today's unauthenticated
    // path, byte-identical. Mirrors GARMR_USERS.
    let collectors = {
        let mut r = garmr_core::CollectorRegistry::new();
        if let Ok(json) = std::env::var("GARMR_COLLECTORS") {
            match r.add_json(&json) {
                Ok(n) if n > 0 => tracing::info!(
                    collectors = n,
                    "collector authentication ENABLED — native ingest requires a bearer token"
                ),
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("GARMR_COLLECTORS parse error: {e}");
                    std::process::exit(78);
                }
            }
        }
        std::sync::Arc::new(r)
    };

    // Migration diagnostic (Phase 12): in bind mode the environment learner keys
    // observations on the collector id, so `[environment].source_trust` entries
    // (keyed by source name) that match no active collector id will not apply and
    // those collectors fall back to `default_source_trust` — with
    // `default_source_trust = 0.0` that silently halts all promotion. Warn rather
    // than fail: re-keying is an operator decision.
    if !collectors.is_empty() && !cfg.environment.source_trust.is_empty() {
        let unmatched: Vec<&str> = cfg
            .environment
            .source_trust
            .keys()
            .filter(|k| !collectors.contains_id(k))
            .map(|k| k.as_str())
            .collect();
        if !unmatched.is_empty() {
            tracing::warn!(
                unmatched = ?unmatched,
                "environment.source_trust keys match no active collector id; in bind mode \
                 facts key on the collector id, so these weights will not apply and those \
                 collectors fall back to default_source_trust — re-key source_trust to collector ids"
            );
        }
    }
    let auditor =
        garmr_ingest::IngestAuditor::new(std::sync::Arc::new(|a: garmr_ingest::IngestAudit| {
            crate::audit::record_ingest_audit(a.action, a.collector.as_deref(), &a.reason);
        }));

    // Phase 12 sequence observer: only when collectors are configured (an
    // unauthenticated batch carries no collector id, so tracking never fires and
    // the extra state write is pointless without auth). The ingest handler only
    // ENQUEUES a mark (non-blocking); a single background task is the sole,
    // in-order writer of the sequence state — no redb/audit I/O on the hot path
    // and no concurrent-observation race.
    let seq_obs: Option<std::sync::Arc<dyn garmr_ingest::IngestSeqObserver>> =
        if collectors.is_empty() {
            None
        } else {
            let (seq_tx, seq_rx) = tokio::sync::mpsc::channel(16_384);
            tokio::spawn(crate::ingest_seq::seq_observe_loop(
                store.state.clone(),
                seq_rx,
            ));
            Some(std::sync::Arc::new(
                crate::ingest_seq::ChannelSeqObserver::new(seq_tx),
            ))
        };

    if let Some(ingest_bind) = cfg.ingest.ingest_bind.clone() {
        // Fail-closed, mirroring the API bind gate below: refuse to open native
        // ingest on a non-loopback address when NO collector authentication is
        // configured (empty CollectorRegistry). An open, unauthenticated ingest
        // port lets anyone who can reach it inject events into the SOC. Fatal so
        // the daemon refuses to start rather than the ingest task looking healthy
        // while it accepts forged events.
        check_ingest_bind_auth(&ingest_bind, !collectors.is_empty())
            .context("native ingest auth configuration")?;
        let env = cfg.ingest.default_environment.clone();
        let ingest_tx = tx.clone();
        let reg = collectors.clone();
        let aud = auditor.clone();
        let seq = seq_obs.clone();
        tokio::spawn(async move {
            if let Err(e) =
                garmr_ingest::run_ingest(&ingest_bind, ingest_tx, env, reg, aud, seq).await
            {
                tracing::error!(error = %e, "native ingest receiver died — exiting so supervision restarts us");
                std::process::exit(70);
            }
        });
    }
    #[cfg(feature = "loki-compat")]
    {
        let loki_bind = cfg.ingest.loki_bind.clone();
        let env = cfg.ingest.default_environment.clone();
        let loki_tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = garmr_ingest::run_loki(&loki_bind, loki_tx, env).await {
                tracing::error!(error = %e, "loki receiver died — exiting so supervision restarts us");
                std::process::exit(70);
            }
        });
    }
    if let Some(bind) = cfg.ingest.syslog_bind.clone() {
        let env = cfg.ingest.default_environment.clone();
        let udp_tx = tx.clone();
        let udp_bind = bind.clone();
        let udp_env = env.clone();
        tokio::spawn(async move {
            if let Err(e) = garmr_ingest::run_syslog_udp(&udp_bind, udp_tx, udp_env).await {
                tracing::error!(error = %e, "syslog UDP died — exiting so supervision restarts us");
                std::process::exit(70);
            }
        });
        let tcp_tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = garmr_ingest::run_syslog_tcp(&bind, tcp_tx, env).await {
                tracing::error!(error = %e, "syslog TCP died — exiting so supervision restarts us");
                std::process::exit(70);
            }
        });
    }
    // Arrow-Flight columnar ingest receiver (opt-in `flight` feature + a
    // configured bind). It swallows Arrow RecordBatches straight into the store
    // via `append_batch` — it does NOT go through the normalisation `tx` (the wire
    // is already columnar), so it clones `store.events` directly.
    #[cfg(feature = "flight")]
    if let Some(flight_bind) = cfg.ingest.flight_bind.clone() {
        let addr: std::net::SocketAddr = flight_bind
            .parse()
            .with_context(|| format!("invalid ingest.flight_bind: {flight_bind}"))?;
        // Fail-closed, like the native ingest bind: refuse an unauthenticated
        // Flight receiver on a non-loopback address (it would accept forged,
        // `unverified`-stamped batches from anyone who can reach the port).
        check_flight_bind_auth(&flight_bind, !collectors.is_empty())
            .context("Arrow Flight ingest auth configuration")?;
        let flight_events = store.events.clone();
        let flight_collectors = collectors.clone();
        tracing::info!(%addr, "Arrow-Flight columnar ingest receiver listening");
        tokio::spawn(async move {
            if let Err(e) =
                garmr_ingest::flight::serve(flight_events, flight_collectors, addr).await
            {
                tracing::error!(error = %e, "Arrow-Flight ingest receiver died — exiting so supervision restarts us");
                std::process::exit(70);
            }
        });
    }

    drop(tx); // consumers hold their own clones

    // Application-audit detection plane (Phases 1/3/5/7/8): loaded once, gated by
    // detect.app_audit_enabled, and SHARED (Arc) between the ingest pipeline (it
    // observes + detects per audit event) and the API admin surface (it
    // promotes/suspects the same in-memory baselines) — one authoritative store,
    // no second opener of the single-process state DB.
    let app_audit = cfg.detect.app_audit_enabled.then(|| {
        // Reuse the detection plane's ensemble tuning (same knobs the env-edge
        // ensemble uses) so app-audit fusion shares one coefficient set.
        let ensemble = garmr_analytics::ensemble::EnsemblePolicy {
            crit_coef: cfg.environment.detect.crit_coef,
            corr_coef: cfg.environment.detect.corr_coef,
            ..Default::default()
        };
        std::sync::Arc::new(crate::appaudit::AppAudit::load(
            &cfg.detect,
            ensemble,
            Some(store.state.clone()),
        ))
    });

    // Read-only query API: lets you search/query/inspect garmr while it
    // ingests, over the daemon's in-process store (the single-process store
    // can't be opened by a second CLI process).
    if let Some(api_bind) = cfg.ingest.api_bind.clone() {
        // Fail fast on an auth misconfig (non-loopback bind without a token) —
        // fatal here so the daemon refuses to start, rather than the API task
        // dying quietly while ingest keeps the process looking healthy.
        api::check_bind_auth(&api_bind).context("query API auth configuration")?;
        let api_store = store.clone();
        let api_cfg = cfg.clone();
        let api_app_audit = app_audit.clone();
        // Phase 11: hand the API the live agent so it can inject the shared
        // embedder into the agent's hybrid_search tool once the model loads.
        let api_agent = agent.clone();
        tokio::spawn(async move {
            if let Err(e) = api::serve(
                &api_bind,
                api_store,
                api_cfg,
                false,
                api_app_audit,
                Some(api_agent),
            )
            .await
            {
                tracing::error!(error = %e, "query API stopped");
            }
        });
    }

    // HA writer: ship a warehouse snapshot to object storage on a timer so
    // followers can pull it. Off unless ha.ship_interval_secs > 0 AND the object
    // store (GARMR_S3_*) is configured — a plain single-node writer ships nothing.
    if cfg.ha.ship_interval_secs > 0 {
        match garmr_retention::HaSync::from_env() {
            Ok(Some(ha)) => {
                let wh = cfg.store.warehouse_dir.clone();
                let every = cfg.ha.ship_interval_secs.max(30);
                tokio::spawn(async move {
                    let mut id = 0u64;
                    loop {
                        id += 1;
                        if let Err(e) = ha.ship(&wh, id).await {
                            tracing::error!(error = %e, "HA ship failed; will retry");
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(every)).await;
                    }
                });
                tracing::info!(
                    every_secs = cfg.ha.ship_interval_secs,
                    "HA: shipping warehouse snapshots to object storage"
                );
            }
            Ok(None) => tracing::warn!(
                "ha.ship_interval_secs is set but GARMR_S3_* is not configured — not shipping"
            ),
            Err(e) => tracing::error!(error = %e, "HA ship init failed — not shipping"),
        }
    }

    let realert = cfg.detect.realert_secs;

    // Scheduled correlation: windowed multi-event rules run on a tick and feed
    // the same case machinery as the per-event Sigma pipeline.
    {
        let engine = std::sync::Arc::new(garmr_correlate::CorrelationEngine::load(
            &cfg.detect.correlations_dir,
        ));
        let (cstore, cagent, cinflight) = (store.clone(), agent.clone(), inflight.clone());
        tokio::spawn(pipeline::correlation_loop(
            cstore, cagent, engine, realert, cinflight, 60,
        ));
    }

    // Scheduled threat hunts (hypothesis TOMLs in detect.hunts_dir): each due
    // hunt runs the agent's hypothesis loop; findings become synthetic
    // detections on the same case path. Only spawned when definitions exist —
    // hunts are model-spend.
    {
        let hunts = garmr_agent::load_hunts(&cfg.detect.hunts_dir);
        if !hunts.is_empty() {
            tokio::spawn(pipeline::hunt_loop(pipeline::HuntLoop {
                store: store.clone(),
                agent: agent.clone(),
                provider: provider.clone(),
                cfg: cfg.clone(),
                hunts,
                realert_secs: realert,
                inflight: inflight.clone(),
                tick_secs: 60,
            }));
        }
    }

    // Response-action executor: acts on human-approved actions. Opt-in, and
    // only spawned when at least one action template is configured — an
    // enabled-but-unconfigured executor would just refuse every action.
    if cfg.executor.enabled {
        let has_tmpl = cfg.executor.block_ip.is_some() || cfg.executor.isolate_host.is_some();
        if has_tmpl {
            tokio::spawn(pipeline::executor_loop(store.clone(), cfg.clone(), 30));
        } else {
            tracing::warn!("[executor] enabled but no action templates configured — not started");
        }
    }

    // New-template anomaly detection: flag never-before-seen log shapes as
    // synthetic detections. Opt-in; seeds the corpus at startup.
    if cfg.detect.anomaly_enabled {
        let (astore, aagent, ainflight) = (store.clone(), agent.clone(), inflight.clone());
        let min_count = cfg.detect.anomaly_min_count;
        tokio::spawn(pipeline::anomaly_loop(
            astore,
            aagent,
            realert,
            ainflight,
            min_count,
            cfg.detect.anomaly_max_per_tick,
            cfg.detect.anomaly_exclude_sources.clone(),
            300,
        ));
    }

    // Risk-based alerting: accumulate per-host risk from adjudicated cases and
    // open one risk case when a host crosses the threshold. Opt-in.
    if cfg.detect.risk_enabled {
        // Fail fast on a misconfigured knob (fatal): a non-finite/non-positive
        // threshold or half-life poisons scoring, and realert_secs=0 turns the
        // loop into a per-tick open+triage storm.
        let (th, hl, ra) = (
            cfg.detect.risk_threshold,
            cfg.detect.risk_halflife_hours,
            cfg.detect.risk_realert_secs,
        );
        if !th.is_finite() || th <= 0.0 {
            anyhow::bail!("detect.risk_threshold must be finite and > 0 (got {th})");
        }
        if !hl.is_finite() || hl <= 0.0 {
            anyhow::bail!("detect.risk_halflife_hours must be finite and > 0 (got {hl})");
        }
        if ra == 0 {
            anyhow::bail!(
                "detect.risk_realert_secs must be > 0 (0 re-opens a risk case every tick)"
            );
        }
        let pd = cfg.detect.prediction_discount;
        if !pd.is_finite() || !(0.0..=1.0).contains(&pd) {
            anyhow::bail!("detect.prediction_discount must be finite and in [0, 1] (got {pd})");
        }
        let (rstore, ragent, rinflight) = (store.clone(), agent.clone(), inflight.clone());
        let params = garmr_analytics::RiskParams {
            threshold: th,
            halflife_hours: hl,
            realert_secs: ra,
            prediction_discount: cfg.detect.prediction_discount,
        };
        tokio::spawn(pipeline::risk_loop(
            rstore, ragent, realert, rinflight, params, 300,
        ));
    }

    // Frequency-baseline anomaly: flag a (host, service) whose hourly volume is
    // far above its own same-clock-hour norm. Opt-in.
    if cfg.detect.freq_baseline_enabled {
        if !cfg.detect.freq_k.is_finite() || cfg.detect.freq_k <= 0.0 {
            // k must be > 0: at k=0 the threshold collapses to the bare median,
            // firing on any above-median hour (≈ half the time) — pure noise.
            anyhow::bail!(
                "detect.freq_k must be finite and > 0 (got {})",
                cfg.detect.freq_k
            );
        }
        let (bstore, bagent, binflight) = (store.clone(), agent.clone(), inflight.clone());
        let params = garmr_analytics::BaselineParams {
            k: cfg.detect.freq_k,
            min_count: cfg.detect.freq_min_count,
        };
        tokio::spawn(pipeline::baseline_loop(
            bstore, bagent, realert, binflight, params, 900,
        ));
    }

    // Phase 14 source-silence detection — OFF by default. GARMR_SOURCE_SILENCE_SECS
    // (a positive integer, the silence threshold) enables it; a source that was
    // active in the watch horizon and has since gone dark opens a case (logging
    // outage / telemetry tampering, T1562.001). Watch horizon + min-events are
    // env-overridable. A serve-runtime toggle, like the other env-gated loops.
    if let Some(silence_secs) = std::env::var("GARMR_SOURCE_SILENCE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|n| *n > 0)
    {
        let policy = garmr_analytics::silence::SilencePolicy {
            silence_secs,
            watch_hours: std::env::var("GARMR_SOURCE_SILENCE_WATCH_HOURS")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(168),
            min_events: std::env::var("GARMR_SOURCE_SILENCE_MIN_EVENTS")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .filter(|n| *n >= 0)
                .unwrap_or(10),
        };
        // Check ~4× per silence window so a newly-silent source is caught
        // promptly, bounded to [60s, 900s].
        let tick = (silence_secs / 4).clamp(60, 900) as u64;
        let (sstore, sagent, sinflight) = (store.clone(), agent.clone(), inflight.clone());
        tokio::spawn(pipeline::silence_loop(
            sstore, sagent, realert, sinflight, policy, tick,
        ));
        tracing::info!(
            silence_secs,
            "source-silence detection ENABLED (GARMR_SOURCE_SILENCE_SECS)"
        );
    }

    // Phase 5 environment model: the learner + auto-promote loops, both off any
    // hot path (periodic queries) and default OFF. `learn` gates them; the
    // auto-promote loop only ever writes Trusted through the fail-closed,
    // hard-block-gated path, so an open case or a compromised entity can never be
    // taught. Import + manual promote/demote stay on the admin API.
    if cfg.environment.enabled && cfg.environment.learn {
        // Phase 12 landed the authenticated env-source binding. Auto-learn is safe
        // ONLY when collectors are configured — then the learner keys facts on the
        // trusted collector id and drops unauthenticated events. UNBOUND learning
        // still trusts the shipper-set `event.source`, so a credential holder can
        // forge distinct sources to promote a Trusted (suppressive) fact.
        if collectors.is_empty() {
            tracing::warn!(
                "environment.learn is ON but NO collectors are configured (GARMR_COLLECTORS): \
                 the learner trusts shipper-set event.source and can be poisoned. Configure \
                 authenticated collectors before auto-learning in a hostile ingest environment"
            );
        } else {
            tracing::info!("environment auto-learn is collector-bound (authenticated sources)");
        }
        // bind = collectors are configured: the learner then keys facts on the
        // trusted collector id and drops unauthenticated (NULL-collector) events.
        tokio::spawn(pipeline::env_learn_loop(
            store.clone(),
            cfg.clone(),
            cfg.environment.learn_interval_secs,
            !collectors.is_empty(),
        ));
        tokio::spawn(pipeline::env_promote_loop(
            store.clone(),
            cfg.clone(),
            cfg.environment.promote_interval_secs,
        ));
        tracing::info!("environment learner + auto-promote loops started");
    }

    // Phase 7 environment-aware detection: the env_edge detector reads the Trusted
    // view and lowers findings to the same case path. Gated by
    // environment.enabled && environment.detect.enabled (default off). It is
    // analysis-only — it never mutates the env model, never auto-acts.
    if cfg.environment.enabled && cfg.environment.detect.enabled {
        // The env_edge detector reads the Trusted baseline; its trustworthiness
        // is exactly that of how the baseline was built. Unbound auto-learn is the
        // risk, and it is warned about at the learn-spawn site above (Phase 12's
        // collector binding is the mitigation), so no separate warning here.
        let (dstore, dagent, dinflight) = (store.clone(), agent.clone(), inflight.clone());
        tokio::spawn(pipeline::env_detect_loop(
            dstore,
            cfg.clone(),
            dagent,
            realert,
            dinflight,
            cfg.environment.detect.interval_secs,
        ));
        tracing::info!("environment detection loop started");
    }

    // Retention: seal aged event windows into the cold tier on a tick. Opt-in.
    if cfg.retention.enabled {
        match garmr_retention::RetentionManager::new(store.clone(), &cfg) {
            Ok(mgr) => {
                let interval = cfg.retention.interval_secs.max(60);
                tokio::spawn(pipeline::retention_loop(mgr, interval));
            }
            Err(e) => tracing::error!(error = %e, "retention not started"),
        }
    }

    // The application-audit plane was created above and shared with the API; the
    // pipeline takes the same Arc so its observe/detect and the API's
    // promote/suspect act on one in-memory baseline store.
    // Phase 12: SAFE behavioral-baseline auto-promotion — OFF by default. When
    // GARMR_BASELINE_AUTO_PROMOTE is truthy, a periodic pass promotes only the
    // baselines whose full anti-poisoning gate is clear (hard blocks AND maturity
    // thresholds), fail-closed audited. Like the environment auto-learn, it stays
    // opt-in: the default posture is operator-gated promotion only.
    let baseline_autopromote = std::env::var("GARMR_BASELINE_AUTO_PROMOTE")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if app_audit.is_some() && baseline_autopromote {
        let secs = std::env::var("GARMR_BASELINE_PROMOTE_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(3600);
        tokio::spawn(pipeline::baseline_promote_loop(
            store.clone(),
            app_audit.clone(),
            secs,
        ));
        tracing::info!(
            interval_secs = secs,
            "behavioral-baseline auto-promotion ENABLED (GARMR_BASELINE_AUTO_PROMOTE)"
        );
    }

    // A handle kept past the move into the pipeline task, so the shutdown path can
    // flush the app-audit learning (behavioral baselines + stateful detector
    // windows) that otherwise only persists on the 200-observation interval. A
    // graceful restart below that interval would otherwise drop an in-progress
    // enumeration/probing episode — exactly what the app_stateful table exists to
    // preserve across a restart.
    let shutdown_audit = app_audit.clone();
    let pipe = tokio::spawn(pipeline::run(
        store,
        detector,
        agent,
        realert,
        inflight.clone(),
        app_audit,
        rx,
    ));

    tracing::info!("garmr serving — Ctrl-C to stop");
    // SIGTERM is what systemd sends on `stop`/`restart`; without a handler the
    // unit would sit out its TimeoutStopSec and get SIGKILLed mid-triage.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down (SIGINT)"),
        _ = sigterm.recv() => tracing::info!("shutting down (SIGTERM)"),
        _ = pipe => tracing::warn!("pipeline task ended"),
    }

    // Persist the app-audit learning on the way out — a graceful restart then
    // preserves the LATEST baselines + in-progress stateful episodes, not just
    // state up to the last interval flush. Best-effort (a flush error is logged
    // inside; learning is reconstructible from the durable audit stream regardless).
    if let Some(aa) = &shutdown_audit {
        aa.flush();
        tracing::info!("flushed app-audit learning (baselines + stateful windows) on shutdown");
    }

    // Drain in-flight triage tasks (up to a grace window) so cases aren't
    // aborted mid-loop. Anything still running past the window is picked up by
    // startup recovery on the next boot.
    let grace = std::time::Duration::from_secs(15);
    let start = tokio::time::Instant::now();
    loop {
        let n = inflight.load(std::sync::atomic::Ordering::SeqCst);
        if n == 0 || start.elapsed() >= grace {
            if n > 0 {
                tracing::warn!(
                    inflight = n,
                    "shutdown grace elapsed; {n} triage task(s) will resume on next start"
                );
            }
            break;
        }
        tracing::info!(inflight = n, "draining in-flight triage…");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    Ok(())
}

/// Fail-closed gate for the native ingest bind, the ingest-side counterpart to
/// [`api::check_bind_auth`]. Unauthenticated native ingest on a non-loopback
/// address is refused: a collector token is the only thing that binds an event's
/// asserted `source` to a trusted shipper, so an open, unauthenticated ingest
/// port lets anyone on the network forge events into the SOC. Loopback binds are
/// always allowed (no remote exposure). Reads the developer override env var and
/// delegates the pure decision to [`ingest_bind_gate`].
fn check_ingest_bind_auth(ingest_bind: &str, has_collector_auth: bool) -> anyhow::Result<()> {
    ingest_bind_gate(ingest_bind, has_collector_auth, ingest_unauth_override())
}

/// Fail-closed gate for the Arrow Flight ingest bind, the Flight counterpart to
/// [`check_ingest_bind_auth`]. Flight authenticates per-batch against the SAME
/// collector registry (`GARMR_COLLECTORS`), so with no collector auth an
/// unauthenticated Flight receiver on a non-loopback address is refused for the
/// same reason: it would accept forged, `unverified`-stamped batches from anyone
/// on the network. Honours the same `GARMR_INGEST_ALLOW_UNAUTH` dev override.
#[cfg(feature = "flight")]
fn check_flight_bind_auth(flight_bind: &str, has_collector_auth: bool) -> anyhow::Result<()> {
    bind_auth_gate(
        flight_bind,
        has_collector_auth,
        ingest_unauth_override(),
        "Arrow Flight ingest",
    )
}

/// Read the insecure developer override once (`GARMR_INGEST_ALLOW_UNAUTH`),
/// shared by the native and Flight ingest gates.
fn ingest_unauth_override() -> bool {
    std::env::var("GARMR_INGEST_ALLOW_UNAUTH")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Native-ingest wrapper over [`bind_auth_gate`] (keeps the stable
/// `ingest_bind_gate` name + "native ingest" wording its unit tests assert on).
fn ingest_bind_gate(
    ingest_bind: &str,
    has_collector_auth: bool,
    allow_override: bool,
) -> anyhow::Result<()> {
    bind_auth_gate(
        ingest_bind,
        has_collector_auth,
        allow_override,
        "native ingest",
    )
}

/// Pure fail-closed decision for an ingest bind (env read out of the way so it is
/// unit-testable): authenticated ingest is allowed anywhere; an unauthenticated
/// loopback (or unresolvable) bind is allowed; an unauthenticated non-loopback
/// bind is refused unless `allow_override` is set, in which case it is permitted
/// with a prominent insecure-configuration warning. `what` names the receiver
/// (e.g. "native ingest", "Arrow Flight ingest") in the log/error text.
fn bind_auth_gate(
    bind: &str,
    has_collector_auth: bool,
    allow_override: bool,
    what: &str,
) -> anyhow::Result<()> {
    use std::net::ToSocketAddrs;
    // Collector authentication configured (GARMR_COLLECTORS): every event carries
    // a verified collector id and source binding — safe on any address.
    if has_collector_auth {
        return Ok(());
    }
    // No auth: every address this bind resolves to must be loopback. If it does
    // not resolve at all, let the receiver's own bind surface the real error.
    let any_nonloopback = bind
        .to_socket_addrs()
        .map(|addrs| addrs.into_iter().any(|a| !a.ip().is_loopback()))
        .unwrap_or(false);
    if !any_nonloopback {
        return Ok(());
    }
    if allow_override {
        tracing::warn!(
            bind = %bind,
            "GARMR_INGEST_ALLOW_UNAUTH is set: serving UNAUTHENTICATED {what} on a \
             non-loopback address ({bind}). Anyone who can reach this port can inject \
             forged events into the SOC. This is INSECURE and intended for local development \
             only — configure GARMR_COLLECTORS for authenticated ingest in production."
        );
        return Ok(());
    }
    anyhow::bail!(
        "refusing to serve {what} on a non-loopback address ({bind}) without collector \
         authentication: set GARMR_COLLECTORS to require per-collector bearer tokens, or set \
         the ingest bind to a loopback address. To override for local development only \
         (insecure), set GARMR_INGEST_ALLOW_UNAUTH=1"
    )
}

#[cfg(test)]
mod tests {
    use super::ingest_bind_gate;

    #[test]
    fn loopback_without_auth_is_allowed() {
        assert!(ingest_bind_gate("127.0.0.1:3110", false, false).is_ok());
        assert!(ingest_bind_gate("[::1]:3110", false, false).is_ok());
    }

    #[test]
    fn nonloopback_without_auth_is_refused() {
        let err = ingest_bind_gate("0.0.0.0:3110", false, false).unwrap_err();
        assert!(
            err.to_string().contains("refusing to serve native ingest"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn nonloopback_with_collector_auth_is_allowed() {
        // Authenticated ingest is safe on any address.
        assert!(ingest_bind_gate("0.0.0.0:3110", true, false).is_ok());
    }

    #[test]
    fn nonloopback_without_auth_with_override_is_allowed() {
        // The developer override permits the insecure bind (and logs a warning).
        assert!(ingest_bind_gate("0.0.0.0:3110", false, true).is_ok());
    }

    #[test]
    fn flight_nonloopback_without_auth_is_refused() {
        // The Flight bind fails closed the same way, with Flight-specific wording.
        let err =
            super::bind_auth_gate("0.0.0.0:3111", false, false, "Arrow Flight ingest").unwrap_err();
        assert!(
            err.to_string()
                .contains("refusing to serve Arrow Flight ingest"),
            "unexpected error: {err}"
        );
        // Authenticated / loopback Flight binds are allowed.
        assert!(super::bind_auth_gate("0.0.0.0:3111", true, false, "Arrow Flight ingest").is_ok());
        assert!(
            super::bind_auth_gate("127.0.0.1:3111", false, false, "Arrow Flight ingest").is_ok()
        );
    }
}