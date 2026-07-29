// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The analysis/pipeline commands: replay + eval harness, ad-hoc correlate/
//! anomaly/risk/baseline runs, the entity graph, semantic index/search (feature),
//! and the retention + cold-tier query commands.

use super::*;

pub(crate) async fn replay(
    cli: &Cli,
    file: &PathBuf,
    json: bool,
    format: Option<&str>,
) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open_writable(&cfg)
        .await
        .context("opening store (writable)")?;
    let (detector, agent, _provider) = build_agent_from(&store, &cfg, true).await?;

    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let events = match format {
        Some(fmt) => garmr_ingest::replay_format(&bytes, fmt, &cfg.ingest.default_environment)
            .with_context(|| format!("parsing {} as {fmt}", file.display()))?,
        None => {
            let as_json = json || file.extension().and_then(|e| e.to_str()) == Some("json");
            garmr_ingest::replay_bytes(&bytes, as_json, &cfg.ingest.default_environment)?
        }
    };
    println!("replaying {} events", events.len());

    store.events.append(events.clone()).await?;
    store.search.index(events.clone()).await?;

    // Detect + triage inline (deterministic) so the command reports outcomes.
    // CPU-parallel / async-serial split: the CPU-bound Sigma evaluation runs
    // across the rayon-free fork-join pool (zero-copy — only the event INDEX is
    // moved; each worker borrows `&events[i]`), then case-open + triage stays
    // serial and index-ordered so suppression/dedup behaves identically to the
    // old serial loop.
    let per_event: Vec<Vec<Detection>> =
        gatling::gatling_forkjoin::gatling_for_each(events.len(), 0, |i| {
            detector.evaluate(&events[i])
        });
    let mut opened = 0;
    for dets in per_event {
        for det in dets {
            if open_and_triage(&store, &agent, det).await? {
                opened += 1;
            }
        }
    }
    println!("opened {opened} case(s); run `garmr cases list` to inspect");
    Ok(())
}

/// Run a golden set through the agent and print/JSON the calibration report.
/// Exits non-zero if any case failed, so it can gate CI.
pub(crate) async fn eval_cmd(cli: &Cli, file: &PathBuf, json: bool) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open_writable(&cfg)
        .await
        .context("opening store (writable)")?;
    let (_detector, agent, _provider) = build_agent_from(&store, &cfg, true).await?;

    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let set = garmr_agent::eval::parse_golden_set(&bytes)?;
    println!("evaluating {} case(s)…", set.cases.len());

    let report = garmr_agent::run_eval(&store, &agent, &set).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let m = &report.metrics;
        for o in &report.outcomes {
            let mark = if o.passed { "PASS" } else { "FAIL" };
            let actual = o
                .actual
                .map(|d| format!("{d:?}"))
                .unwrap_or_else(|| "—".into());
            println!(
                "  [{mark}] {}  expected {:?}, got {actual}{}",
                o.id,
                o.expected,
                if o.failures.is_empty() {
                    String::new()
                } else {
                    format!("  ({})", o.failures.join("; "))
                }
            );
        }
        println!("\n— calibration —");
        println!("  pass:                 {}/{}", m.passed, m.total);
        println!(
            "  disposition-accuracy: {:.0}% ({}/{})",
            m.disposition_accuracy * 100.0,
            m.disposition_correct,
            m.total
        );
        println!(
            "  over-trigger:         {} (benign called malicious/high sev — alert fatigue)",
            m.over_trigger
        );
        println!(
            "  under-trigger:        {} (malicious called benign — dangerous misses)",
            m.under_trigger
        );
        println!(
            "  evidence-gated-action: {:.0}% ({}/{} proposed actions warranted)",
            m.evidence_gated_action_rate * 100.0,
            m.actions_warranted,
            m.actions_proposed
        );
        if m.injection_cases > 0 {
            println!(
                "  injection-violations: {}/{}",
                m.injection_violations, m.injection_cases
            );
        }
    }

    // Project the dataset + this eval run into the registry (best-effort — a
    // failing eval is still a real run worth recording, so this happens BEFORE
    // the failed-case bail). A projection error is logged, never fatal.
    if let Err(e) = project_eval_to_registry(&store, &cfg, file, &bytes, &report) {
        tracing::warn!(error = %e, "recording the eval run in the registry failed (the eval result stands)");
    }

    if report.metrics.failed > 0 {
        anyhow::bail!("{} eval-case(s) failed", report.metrics.failed);
    }
    Ok(())
}

/// Record a `garmr eval` invocation in the versioned registry: the golden set as
/// an immutable Dataset record and the run itself as an EvalRun record whose
/// content embeds the dataset digest, model identity, and metrics (no mutable
/// back-links — the linkage lives in the content, so it can't drift). Both are
/// content-addressed, so re-running an identical eval is idempotent. Audited
/// fail-closed per record; a genuinely-unchanged record is a silent no-op.
fn project_eval_to_registry(
    store: &Store,
    cfg: &Config,
    file: &std::path::Path,
    bytes: &[u8],
    report: &garmr_agent::EvalReport,
) -> Result<()> {
    use garmr_audit::action::{DATASET_CREATE, EVAL_RUN};

    // ---- the golden-set dataset (addressed by the raw file bytes) ----------
    let dataset_name = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("golden-set")
        .to_string();
    let dataset_digest = blake3::hash(bytes).to_hex().to_string();
    let dataset_version = format!("d-{}", &dataset_digest[..dataset_digest.len().min(12)]);
    ensure_registered_local(
        store,
        cfg,
        garmr_core::RegistryKind::Dataset,
        &dataset_name,
        &dataset_version,
        &dataset_digest,
        DATASET_CREATE,
        serde_json::json!({
            "cases": report.metrics.total,
            "source_file": file.display().to_string(),
        }),
    )?;

    // ---- the eval run (addressed by dataset + model + metrics) -------------
    // The model's identity descriptor, hashed the same way serve's
    // observe_running does, so an eval run and the running model agree.
    let model_digest = garmr_core::model_descriptor_digest(
        cfg.agent.backend,
        &cfg.agent.model,
        cfg.agent.openai_base_url.as_deref().unwrap_or(""),
    );
    let metrics_json = serde_json::to_string(&report.metrics).unwrap_or_default();
    let run_digest =
        blake3::hash(format!("{dataset_digest}|{model_digest}|{metrics_json}").as_bytes())
            .to_hex()
            .to_string();
    let run_version = format!("e-{}", &run_digest[..run_digest.len().min(12)]);
    ensure_registered_local(
        store,
        cfg,
        garmr_core::RegistryKind::EvalRun,
        &dataset_name,
        &run_version,
        &run_digest,
        EVAL_RUN,
        serde_json::json!({
            "dataset": dataset_name,
            "dataset_digest": dataset_digest,
            "model": cfg.agent.model,
            "model_digest": model_digest,
            "metrics": report.metrics,
        }),
    )?;
    Ok(())
}

/// Register a content-addressed reference record (Dataset / EvalRun) from a
/// local operator command. Check-first so a re-run of an identical eval neither
/// re-audits nor re-writes; on a genuinely new record, audit fail-closed
/// (binding the record to the event) then insert. Draft + Operator source —
/// these are provenance references, never promoted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ensure_registered_local(
    store: &Store,
    cfg: &Config,
    kind: garmr_core::RegistryKind,
    name: &str,
    version: &str,
    digest: &str,
    action: &str,
    spec: serde_json::Value,
) -> Result<()> {
    use garmr_core::{ApprovalState, RegistryRecord, RegistrySource};

    if let Some(existing) = store.state.get_record(kind, name, version)? {
        if existing.content_digest == digest {
            return Ok(()); // identical run already recorded — stay silent
        }
    }
    crate::audit::ensure_init(&cfg.audit)?;
    let coord = format!("{name}@{version}");
    let audit_id = crate::audit::record_admin_local(
        action,
        "registry_record",
        Some(&coord),
        Some("registered by garmr eval"),
    )?;
    let rec = RegistryRecord {
        id: uuid::Uuid::new_v4().to_string(),
        kind,
        name: name.to_string(),
        version: version.to_string(),
        content_digest: digest.to_string(),
        parent_version: None,
        rationale: "recorded by garmr eval".to_string(),
        eval_run_refs: Vec::new(),
        approval: ApprovalState::Draft,
        source: RegistrySource::Operator,
        registered_at: Utc::now(),
        registered_by: "cli".to_string(),
        audit_id,
        spec,
    };
    if let garmr_store::state::RegisterOutcome::Conflict { existing_digest } =
        store.state.register_record(&rec)?
    {
        tracing::warn!(
            kind = kind.tag(),
            name,
            version,
            existing_digest,
            "eval registry record conflicts with an existing digest — leaving the existing one"
        );
    }
    Ok(())
}

/// Open a case for a detection and triage it inline; returns whether a new case
/// was opened (vs suppressed as a repeat within the replay). A triage failure
/// (e.g. no LLM reachable) is logged, not fatal — the case is still persisted.
pub(crate) async fn open_and_triage(
    store: &Store,
    agent: &Arc<Agent>,
    det: Detection,
) -> Result<bool> {
    let key = det.dedup_key();
    if store.state.suppression_last(&key)?.is_some() {
        // Repeat within this replay — atomically bump the open case's count.
        if let Some(c) = store
            .state
            .list_cases()?
            .into_iter()
            .find(|c| c.dedup_key == key && c.state != garmr_core::CaseState::Closed)
        {
            store.state.bump_event_count(&c.id, Utc::now())?;
        }
        return Ok(false);
    }
    let mut case = Case::open(det);
    store.state.put_case(&case)?;
    store
        .state
        .suppression_mark(&key, Utc::now().timestamp() as u64)?;
    if let Err(e) = agent.triage(&mut case).await {
        tracing::warn!(case = %case.id, error = %e, "triage failed (case persisted)");
    }
    Ok(true)
}

pub(crate) async fn search(cli: &Cli, query: &str, limit: usize) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await?;
    let hits = store
        .search
        .search(query, limit)
        .context("running full-text search")?;
    if hits.is_empty() {
        println!("(no hits)");
    }
    for h in &hits {
        let ts = chrono::DateTime::from_timestamp_micros(h.ts_micros)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "-".into());
        println!(
            "{ts}  {:<8} {:<10} {:>5.2}  {}",
            h.severity, h.host, h.score, h.message
        );
    }
    Ok(())
}

pub(crate) async fn correlate(cli: &Cli, hours: Option<u64>) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await.context("opening store")?;
    let (_detector, agent, _provider) = build_agent_from(&store, &cfg, false).await?;
    let engine = garmr_correlate::CorrelationEngine::load(&cfg.detect.correlations_dir);
    println!("loaded {} correlation rule(s)", engine.rules().len());

    let now = Utc::now();
    let since_us = match hours {
        Some(h) => now.timestamp_micros() - (h as i64) * 3_600_000_000,
        None => 0, // all history
    };
    let dets = engine.run_all(&store, since_us, now).await?;
    println!("{} correlation hit(s)", dets.len());

    let mut opened = 0;
    for det in dets {
        if open_and_triage(&store, &agent, det).await? {
            opened += 1;
        }
    }
    println!("opened {opened} case(s); run `garmr cases list` to inspect");
    Ok(())
}

pub(crate) async fn anomaly(cli: &Cli, min_count: u64, seed_only: bool) -> Result<()> {
    const WINDOW_HOURS: u32 = 24;
    const SEED_LIMIT: usize = 400_000; // rows scanned; deduped by template (cheap), covers common shapes across the window
    const SCAN_LIMIT: usize = 20_000; // newest rows
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await.context("opening store")?;
    if seed_only {
        let (n, truncated) = garmr_analytics::seed(
            &store,
            WINDOW_HOURS,
            SEED_LIMIT,
            &cfg.detect.anomaly_exclude_sources,
        )
        .await?;
        if truncated {
            eprintln!("WARNING: the distinct-message cap was reached — the baseline is PARTIAL");
        }
        println!("seeded {n} existing templates; new shapes open cases from here on");
        return Ok(());
    }
    // A manual detect run must also seed first if the store has never been
    // baselined, or it would flag the whole corpus as new.
    let (seeded, _) = garmr_analytics::seed(
        &store,
        WINDOW_HOURS,
        SEED_LIMIT,
        &cfg.detect.anomaly_exclude_sources,
    )
    .await?;
    if seeded > 0 {
        eprintln!("(baselined {seeded} previously unseen templates this run)");
    }
    let (_detector, agent, _provider) = build_agent_from(&store, &cfg, false).await?;
    let dets = garmr_analytics::detect(
        &store,
        WINDOW_HOURS,
        SCAN_LIMIT,
        min_count,
        cfg.detect.anomaly_max_per_tick,
        &cfg.detect.anomaly_exclude_sources,
    )
    .await?;
    println!("{} new template shape(s)", dets.len());
    let mut opened = 0;
    for det in dets {
        if open_and_triage(&store, &agent, det).await? {
            opened += 1;
        }
    }
    println!("opened {opened} case(s); run `garmr cases list`");
    Ok(())
}

/// Show current per-host risk (RBA). Read-only: scores the case store and
/// prints hosts by risk. Opens the store directly, so run it while `serve` is
/// stopped; with `serve` running, GET /api/risk gives the same view live.
pub(crate) async fn risk_cmd(cli: &Cli, top: usize) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await.context("opening store")?;
    let params = garmr_analytics::RiskParams {
        threshold: cfg.detect.risk_threshold,
        halflife_hours: cfg.detect.risk_halflife_hours,
        realert_secs: cfg.detect.risk_realert_secs,
        prediction_discount: cfg.detect.prediction_discount,
    };
    let cases = store.state.list_cases()?;
    // Resolve each case through the Phase-3 trust precedence (trusted outcome >
    // analyst decision > discounted prediction/shadow > unresolved).
    let index = garmr_analytics::OutcomeIndex::build(
        &cases,
        &store.state.list_incident_outcomes()?,
        &store.state.list_decisions()?,
        &store.state.list_predictions()?,
    );
    let now = chrono::Utc::now();
    // Both risk axes: per-host and per-entity (staff / db_user). The staff axis
    // is where the per-detector app-audit cases accumulate into a caseworker's
    // cumulative insider-risk score.
    let mut objs = garmr_analytics::score_hosts_with(&cases, now, &params, &index);
    objs.extend(garmr_analytics::score_staff_with(
        &cases, now, &params, &index,
    ));
    objs.sort_by(|a, b| b.score.total_cmp(&a.score));
    if objs.is_empty() {
        println!(
            "no risk objects (no non-benign cases in the {:.0}h window)",
            garmr_analytics::WINDOW_HOURS
        );
        return Ok(());
    }
    println!(
        "Risk objects (threshold {:.0}, half-life {:.0}h, {:.0}h window) — '!' = over threshold:",
        params.threshold,
        params.halflife_hours,
        garmr_analytics::WINDOW_HOURS
    );
    for o in objs.iter().take(top) {
        let flag = if o.score >= params.threshold {
            '!'
        } else {
            ' '
        };
        println!(
            "{flag} {:>7.1}  {:<8} {:<20} {} signals",
            o.score,
            o.kind,
            o.host,
            o.contributors.len()
        );
    }
    Ok(())
}

/// Run one frequency-baseline pass and print the bursts (read-only inspection;
/// the serve loop is what turns them into cases). Opens the store directly, so
/// run it while `serve` is stopped.
pub(crate) async fn baseline_cmd(cli: &Cli, k: f64, min_count: u64) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await.context("opening store")?;
    let params = garmr_analytics::BaselineParams { k, min_count };
    let dets = garmr_analytics::baseline::detect(&store, chrono::Utc::now(), &params).await?;
    if dets.is_empty() {
        println!("no frequency anomalies this hour (k={k}, min_count={min_count})");
        return Ok(());
    }
    println!("{} frequency anomaly(ies) this hour:", dets.len());
    for d in &dets {
        println!("  {}", d.event.message);
    }
    Ok(())
}

/// Entity-graph pivot / shortest-path over the case store (read-only). Opens
/// the store directly, so run it with `serve` stopped; /api/graph is the live
/// equivalent.
pub(crate) async fn graph_cmd(
    cli: &Cli,
    kind: &str,
    name: &str,
    depth: usize,
    path_to: Option<&str>,
    attack_paths: bool,
) -> Result<()> {
    let cfg = load_config(cli)?;
    let depth = depth.clamp(1, 6); // match the API/tool bound; keeps output sane
    let store = Store::open(&cfg).await.context("opening store")?;
    // Case edges + event-co-occurrence edges (last 7 days, best-effort;
    // firehose sources skipped, as in the API graph).
    let graph = garmr_graph::build(
        &store,
        garmr_graph::TimeWindow::LastHours(168),
        garmr_graph::TimeWindow::LastHours(336),
        50_000,
        &cfg.store.fulltext_exclude_sources,
    )
    .await?;
    if graph.degraded() {
        eprintln!("(NOTE: the event-edge scan was skipped — the graph is case-only this run)");
    }
    let start = garmr_graph::node_id(kind, name);
    if !graph.contains(&start) {
        println!(
            "unknown entity {start} — not in the graph ({} nodes total)",
            graph.size().0
        );
        return Ok(());
    }

    if attack_paths {
        let ranked = graph.rank_paths(&start, depth);
        if ranked.is_empty() {
            println!("no risky attack paths from {start} (depth {depth})");
            return Ok(());
        }
        println!("attack paths from {start} (depth {depth}), ranked by risk:");
        for rp in ranked.iter().take(15) {
            let route: Vec<&str> = rp.path.iter().map(String::as_str).collect();
            println!(
                "  {:>6.1}  {}  [{}]",
                rp.score,
                route.join(" → "),
                rp.target.label
            );
        }
        return Ok(());
    }

    if let Some(target) = path_to {
        // `path_to` is a full "kind:name" node id.
        match graph.shortest_path(&start, target) {
            Some(path) => {
                println!(
                    "shortest path {start} → {target} ({} hops):",
                    path.len().saturating_sub(1)
                );
                let line: Vec<String> = path
                    .iter()
                    .map(|n| format!("{}:{}", n.kind, n.name))
                    .collect();
                println!("  {}", line.join("  →  "));
            }
            None => println!("no path {start} → {target} (unknown or disconnected)"),
        }
        return Ok(());
    }

    let reached = graph.pivot(&start, depth);
    println!(
        "connected to {start} (depth {depth}) — {} entities (via case/event):",
        reached.len()
    );
    // Group by kind for a readable pivot; each item shows hop + edge provenance.
    let mut by_kind: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
    for h in &reached {
        let (n, hop, via) = (h.node, h.hop, h.via.as_str());
        by_kind
            .entry(n.kind.as_str())
            .or_default()
            .push(if n.kind == garmr_graph::KIND_CASE {
                format!(
                    "{} ({}, {hop}h/{via})",
                    n.name.get(..8).unwrap_or(&n.name),
                    n.label
                )
            } else {
                format!("{} ({hop}h/{via})", n.name)
            });
    }
    for (k, items) in by_kind {
        println!("  {k}: {}", items.join(", "));
    }
    Ok(())
}

/// Where the semantic vector store lives (next to the warehouse), overridable
/// via GARMR_SEMANTIC_STORE.
#[cfg(feature = "semantic")]
fn semantic_store_path(cfg: &Config) -> std::path::PathBuf {
    std::env::var_os("GARMR_SEMANTIC_STORE")
        .map(Into::into)
        .unwrap_or_else(|| {
            cfg.store
                .warehouse_dir
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("semantic-vectors.bin")
        })
}

/// Does this full-text-index open error denote CORRUPTION/incompatibility (a
/// rebuild from the warehouse is the fix) rather than a transient/environmental
/// failure (fd exhaustion, ENOMEM mmap'ing a large HEALTHY index, EIO, a
/// permission blip)? We only ever move a healthy index aside on genuine
/// corruption; anything else fails closed so a transient blip can't destroy a
/// warm index. Errors cross the garmr-search boundary stringified, so match on
/// Tantivy's corruption signatures — verified against the real strings: a
/// scribbled segment gives "Footer magic byte mismatch" (io InvalidData), a
/// mangled meta.json gives "Data corruption (in file `meta.json`)".
fn index_error_is_corruption(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    // Transient/environmental — never a reason to move a healthy index aside.
    if m.contains("permission denied")
        || m.contains("too many open files")
        || m.contains("out of memory")
        || m.contains("cannot allocate")
        || m.contains("resource temporarily unavailable")
    {
        return false;
    }
    m.contains("footer magic byte mismatch")
        || m.contains("corrupt") // "Data corruption (in file ...)" / "Corrupted file"
        || m.contains("invaliddata")
        || m.contains("incompatible")
        || m.contains("was created using") // Tantivy version skew — rebuild is the fix
}

/// Ensure the full-text index directory can be opened before a rebuild. If it is
/// genuinely CORRUPT — partially-written or scribbled segments (a torn write, a
/// bad block), an unparseable meta.json, a version-incompatible index — move it
/// aside so the writable open recreates an empty index and the rebuild
/// repopulates it from the durable warehouse. This is what makes `reindex` an
/// actual recovery path for a corrupt index (its documented job): otherwise
/// `Store::open_writable` fails on the very corruption reindex exists to heal.
///
/// Guardrails (from adversarial review):
/// - A healthy index opens cleanly and is left untouched; a non-existent one is
///   recreated by the open.
/// - A TRANSIENT open error (fd exhaustion, ENOMEM, EIO, a permission blip) is
///   NOT treated as corruption — we fail closed instead of destroying a warm
///   healthy index ([`index_error_is_corruption`]).
/// - The destructive move is fenced behind the single-writer exclusion: if a
///   `serve` is live we refuse with ZERO filesystem mutation, so a running SOC's
///   index is never moved out from under it (open_writable would otherwise fail
///   on the corrupt footer BEFORE its own lock check).
/// - A restored-but-unpromoted follower is skipped — its writable open is refused
///   for the marker regardless, and a follower's index must not be mutated here.
///
/// Scope: detection uses the reader open (which eagerly footer-validates every
/// segment). A corruption visible ONLY to the writer path would fall through to
/// `open_writable` and error as before — reader-visible corruption is the case
/// this recovers.
fn reset_search_index_if_unreadable(
    search_dir: &std::path::Path,
    state_db: &std::path::Path,
    warehouse_dir: &std::path::Path,
) -> Result<()> {
    if garmr_store::restored_marker_path(state_db).exists() {
        return Ok(()); // a follower — leave its index alone; open_writable will refuse
    }
    if !search_dir.exists() {
        return Ok(()); // absent is not corrupt — the writable open creates a fresh index
    }
    // Probe read-only (no writer lock): a corrupt segment footer / meta.json fails
    // here exactly as it does for the writer open, so this detects the damage
    // without conflicting with the writable open that follows.
    let err = match garmr_store::SearchIndex::open_reader(search_dir) {
        Ok(_) => return Ok(()), // healthy — leave it untouched
        Err(e) => e,
    };
    if !index_error_is_corruption(&err.to_string()) {
        // Not corruption — a transient/environmental failure. Refuse without
        // touching the index; the operator resolves the condition and retries.
        return Err(err).context(
            "opening the full-text index (this is NOT an index-corruption error — refusing \
             to move the index aside; resolve the underlying condition and retry)",
        );
    }
    // A corrupt index must not be moved out from under a LIVE writer: reindex is a
    // serve-stopped operation, and open_writable would fail on the corrupt footer
    // BEFORE its own lock check, so fence here first. Holding the exclusion across
    // the rename guarantees no `serve` starts mid-move; the guard drops on return,
    // so the writable open below re-acquires cleanly.
    let catalog = warehouse_dir.join("catalog.redb");
    let _guard = match garmr_store::try_acquire_exclusion(&[state_db, catalog.as_path()])? {
        Some(guard) => guard,
        None => anyhow::bail!(
            "the full-text index is corrupt but a writer (a running `serve`?) holds the store \
             — stop it first; refusing to move the index aside under a live writer"
        ),
    };
    let base = search_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("search");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let aside = search_dir.with_file_name(format!("{base}.corrupt-{ts}"));
    tracing::warn!(
        dir = %search_dir.display(),
        moved_to = %aside.display(),
        "full-text index is corrupt — moving it aside and rebuilding from the warehouse"
    );
    std::fs::rename(search_dir, &aside).with_context(|| {
        format!(
            "moving the corrupt full-text index {} aside to {}",
            search_dir.display(),
            aside.display()
        )
    })?;
    println!(
        "full-text index was corrupt — moved aside to {} (safe to delete once the \
         rebuild is verified); rebuilding from the warehouse",
        aside.display()
    );
    Ok(())
}

/// Rebuild the full-text (Tantivy) index from the warehouse events — the recovery
/// path after a `restore` (which leaves FTS COLD) or an index loss/corruption. A
/// corrupt index is moved aside and rebuilt (see `reset_search_index_if_unreadable`)
/// so recovery is a single command. Opens the store WRITABLE, so run it with
/// `serve` stopped. `--hours` limits to recent events; omit to rebuild the whole
/// history. Clears the index first, then re-feeds it in disjoint time windows
/// (bounded memory, no duplicate/skipped documents).
pub(crate) async fn reindex_cmd(cli: &Cli, hours: Option<u64>) -> Result<()> {
    use skade::arrow_array::{Array, StringArray, TimestampMicrosecondArray};
    let cfg = load_config(cli)?;
    // A corrupt on-disk index must not block the very command meant to rebuild it.
    reset_search_index_if_unreadable(
        &cfg.store.search_dir,
        &cfg.store.state_db,
        &cfg.store.warehouse_dir,
    )?;
    let store = Store::open_writable(&cfg)
        .await
        .context("opening store (stop `serve` first — the embedded store is single-process)")?;

    // Bounds of the events table.
    let bounds = store
        .events
        .sql("SELECT min(event_ts) AS lo, max(event_ts) AS hi FROM events")
        .await?;
    let (lo, hi) = ts_bounds(&bounds);
    let (Some(mut w), Some(max_us)) = (lo, hi) else {
        println!("no events in the warehouse — nothing to reindex");
        return Ok(());
    };
    if let Some(h) = hours {
        let floor = Utc::now().timestamp_micros() - (h as i64).saturating_mul(3_600_000_000);
        w = w.max(floor);
    }

    // Clear then rebuild in disjoint 6h windows: an empty index + non-overlapping
    // complete windows = an exact rebuild with no duplicated or skipped docs.
    store.search.clear().await?;
    const STEP_US: i64 = 6 * 3_600_000_000;
    let mut total = 0usize;
    while w <= max_us {
        let end = w.saturating_add(STEP_US);
        let sql = format!(
            "SELECT event_ts, host, service, source, severity, log_type, message, fields \
             FROM events WHERE event_ts >= to_timestamp_micros({w}) \
             AND event_ts < to_timestamp_micros({end}) ORDER BY event_ts"
        );
        let batches = store.events.sql(sql).await?;
        let mut events = Vec::new();
        for b in &batches {
            let ts = b
                .column(0)
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>();
            let s = |c: usize| b.column(c).as_any().downcast_ref::<StringArray>();
            let (host, service, source, severity, log_type, message, fields) =
                (s(1), s(2), s(3), s(4), s(5), s(6), s(7));
            let (
                Some(ts),
                Some(host),
                Some(service),
                Some(source),
                Some(severity),
                Some(log_type),
                Some(message),
                Some(fields),
            ) = (
                ts, host, service, source, severity, log_type, message, fields,
            )
            else {
                continue;
            };
            let sv = |a: &StringArray, i: usize| {
                if a.is_valid(i) {
                    a.value(i).to_string()
                } else {
                    String::new()
                }
            };
            for i in 0..b.num_rows() {
                let fields_map = if fields.is_valid(i) {
                    serde_json::from_str(fields.value(i)).unwrap_or_default()
                } else {
                    std::collections::BTreeMap::new()
                };
                events.push(garmr_core::Event {
                    ts: ts
                        .is_valid(i)
                        .then(|| chrono::DateTime::from_timestamp_micros(ts.value(i)))
                        .flatten()
                        .unwrap_or_else(Utc::now),
                    host: sv(host, i).into(),
                    service: sv(service, i).into(),
                    source: sv(source, i).into(),
                    environment: "".into(), // not full-text indexed
                    severity: sv(severity, i).into(),
                    log_type: sv(log_type, i).into(),
                    message: sv(message, i),
                    fields: fields_map,
                });
            }
        }
        let n = events.len();
        store.search.index(events).await?;
        total += n;
        w = end;
    }
    println!("reindexed {total} events into the full-text index");
    Ok(())
}

/// Extract `(min, max)` epoch-micros from a `SELECT min(...), max(...)` result.
fn ts_bounds(batches: &[skade::arrow_array::RecordBatch]) -> (Option<i64>, Option<i64>) {
    use skade::arrow_array::{Array, TimestampMicrosecondArray};
    for b in batches {
        if b.num_rows() == 0 {
            continue;
        }
        let lo = b
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>();
        let hi = b
            .column(1)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>();
        if let (Some(lo), Some(hi)) = (lo, hi) {
            let lov = lo.is_valid(0).then(|| lo.value(0));
            let hiv = hi.is_valid(0).then(|| hi.value(0));
            return (lov, hiv);
        }
    }
    (None, None)
}

/// Load the embedding model from GARMR_EMBED_MODEL (offline, from disk).
#[cfg(feature = "semantic")]
fn load_embedder() -> Result<(garmr_embed::Embedder, String)> {
    let dir = std::env::var_os("GARMR_EMBED_MODEL").ok_or_else(|| {
        anyhow::anyhow!(
            "set GARMR_EMBED_MODEL to a directory with config.json, tokenizer.json and \
             model.safetensors (e.g. a bge-small-en-v1.5 export)"
        )
    })?;
    // Verify against the optional pin (same supply-chain gate as serve): a
    // digest mismatch is a hard error here, not a silent load.
    let pin = std::env::var("GARMR_EMBED_MODEL_DIGEST")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let (embedder, digest) =
        garmr_embed::Embedder::load_verified(std::path::Path::new(&dir), pin.as_deref())?;
    if pin.is_none() {
        tracing::warn!(digest = %digest, "embedding model loaded UNPINNED — set GARMR_EMBED_MODEL_DIGEST to pin it");
    }
    Ok((embedder, digest))
}

/// Embed recent DISTINCT event messages into the semantic vector store. Opens
/// the store directly, so run it with `serve` stopped.
#[cfg(feature = "semantic")]
pub(crate) async fn embed_index(cli: &Cli, hours: u64, max: usize) -> Result<()> {
    use skade::arrow_array::{Array, StringArray, TimestampMicrosecondArray};
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg)
        .await
        .context("opening store (stop `serve` first — the embedded store is single-process)")?;
    let (embedder, digest) = load_embedder()?;
    // Distinct (host, service, message) so identical lines are embedded once;
    // exclude the synthetic detection log_types.
    let sql = format!(
        "SELECT max(event_ts) AS ts, host, service, message FROM events \
         WHERE event_ts >= now() - INTERVAL '{hours} hours' \
           AND log_type NOT IN ('anomaly', 'risk', 'baseline') \
         GROUP BY host, service, message ORDER BY ts DESC LIMIT {}",
        max
    );
    let batches = store.events.sql(sql).await?;
    let path = semantic_store_path(&cfg);
    let mut vstore = garmr_embed::VectorStore::open(&path, max, &digest)?;
    let mut n = 0usize;
    for b in &batches {
        let ts = b
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>();
        let host = b.column(1).as_any().downcast_ref::<StringArray>();
        let svc = b.column(2).as_any().downcast_ref::<StringArray>();
        let msg = b.column(3).as_any().downcast_ref::<StringArray>();
        let (Some(ts), Some(host), Some(svc), Some(msg)) = (ts, host, svc, msg) else {
            continue;
        };
        for i in 0..b.num_rows() {
            if !msg.is_valid(i) {
                continue;
            }
            let message = msg.value(i).to_string();
            let vec = embedder.embed(&message)?;
            vstore.push(garmr_embed::Record {
                ts_micros: if ts.is_valid(i) { ts.value(i) } else { 0 },
                host: if host.is_valid(i) {
                    host.value(i).into()
                } else {
                    String::new()
                },
                service: if svc.is_valid(i) {
                    svc.value(i).into()
                } else {
                    String::new()
                },
                message,
                vec,
            });
            n += 1;
        }
    }
    vstore.flush()?;
    if n == 0 {
        eprintln!(
            "WARNING: no messages embedded — no events in the window (--hours {hours}), or \
             column type matching failed"
        );
    }
    println!(
        "embedded {n} distinct messages → {} ({} in the index)",
        path.display(),
        vstore.len()
    );
    Ok(())
}

/// Semantic search over the vector index. Reads only the vector file + the
/// model, so it works while `serve` runs.
#[cfg(feature = "semantic")]
pub(crate) async fn semantic_cmd(cli: &Cli, query: &str, top: usize) -> Result<()> {
    let cfg = load_config(cli)?;
    let path = semantic_store_path(&cfg);
    let (embedder, digest) = load_embedder()?;
    // A generous but finite backstop: normal indexes are bounded by embed-index's
    // --max, but a corrupt/oversized file shouldn't load unbounded into RAM. The
    // digest stamp means a file from a different model opens empty (not mis-scored).
    let store = garmr_embed::VectorStore::open(&path, 5_000_000, &digest)?;
    if store.is_empty() {
        println!(
            "semantic index empty or stale (model mismatch) — run `garmr embed-index` ({})",
            path.display()
        );
        return Ok(());
    }
    let qv = embedder.embed(query)?;
    let hits = store.search(&qv, top);
    println!(
        "top {} (semantic) for {query:?} — of {} indexed:",
        hits.len(),
        store.len()
    );
    for (score, r) in hits {
        let ts = chrono::DateTime::from_timestamp_micros(r.ts_micros)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        println!(
            "  {score:.3}  {ts}  {}/{}  {}",
            r.host, r.service, r.message
        );
    }
    Ok(())
}

/// `garmr embed-verify` — verify the semantic vector index (DoD 15): confirm the
/// on-disk file is stamped with the CURRENT embedding model (a model change makes
/// it open empty, forcing a rebuild), and report the record count and the index lag
/// (seconds between now and the newest indexed event).
#[cfg(feature = "semantic")]
pub(crate) async fn embed_verify(cli: &Cli) -> Result<()> {
    let cfg = load_config(cli)?;
    let path = semantic_store_path(&cfg);
    let existed = path.exists();
    // Compute the model digest WITHOUT loading the ~100MB weights — the digest is
    // the identity of the model files, exactly what `serve` stamps the store with.
    let dir = std::env::var_os("GARMR_EMBED_MODEL")
        .ok_or_else(|| anyhow::anyhow!("set GARMR_EMBED_MODEL to the model directory"))?;
    let digest = garmr_embed::model_digest(std::path::Path::new(&dir))?;
    if let Ok(pin) = std::env::var("GARMR_EMBED_MODEL_DIGEST") {
        let pin = pin.trim();
        if !pin.is_empty() && pin != digest {
            println!("  WARNING: model digest {digest} does not match the pin {pin} — a swapped model");
        }
    }
    let store = garmr_embed::VectorStore::open(&path, 5_000_000, &digest)?;
    let n = store.len();
    println!("semantic index verify — {}", path.display());
    println!("  model digest : {digest}");
    println!("  records      : {n}");
    if let Some(ts) = store.newest_ts() {
        let lag = (chrono::Utc::now().timestamp_micros() - ts).max(0) / 1_000_000;
        println!("  newest event : {ts}µs (index lag {lag}s)");
    }
    if existed && n == 0 {
        println!(
            "  status       : STALE/EMPTY — the file exists but opened with 0 records \
             (a model change discards mismatched vectors). Run `garmr embed-index` to rebuild."
        );
    } else if n == 0 {
        println!("  status       : EMPTY — no index yet. Run `garmr embed-index`.");
    } else {
        println!("  status       : OK — {n} vectors stamped with the current model.");
    }
    Ok(())
}

/// A local `SemanticSearch` over the on-disk vector index (only with the
/// `semantic` build) — lets `garmr hsearch --semantic` fuse meaning without a
/// running daemon.
#[cfg(feature = "semantic")]
struct LocalSemantic {
    embedder: garmr_embed::Embedder,
    store: garmr_embed::VectorStore,
}

#[cfg(feature = "semantic")]
impl garmr_query::SemanticSearch for LocalSemantic {
    fn search(&self, nl: &str, k: usize) -> Vec<garmr_query::SemanticHit> {
        let Ok(qv) = self.embedder.embed(nl) else {
            return Vec::new();
        };
        self.store
            .search(&qv, k)
            .into_iter()
            .map(|(score, r)| garmr_query::SemanticHit {
                ts_micros: r.ts_micros,
                host: r.host,
                service: r.service,
                message: r.message,
                score,
            })
            .collect()
    }
}

/// `garmr hsearch` — build the Query IR from flags, run it daemon-first (POST
/// /api/hsearch) then against a locally-opened store.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn hsearch_cmd(
    cli: &Cli,
    text: &Option<String>,
    semantic: &Option<String>,
    host: &[String],
    service: &[String],
    source: &[String],
    environment: &[String],
    severity: &[String],
    log_type: &[String],
    field: &[String],
    since: Option<f64>,
    limit: usize,
    rrf_k: u32,
) -> Result<()> {
    use garmr_query::{
        FieldPredicate, FusionConfig, FusionMethod, HybridQuery, SemanticClause, StructuredFilter,
        TextClause, TimeRange,
    };
    let cfg = load_config(cli)?;

    let mut fields = Vec::new();
    for kv in field {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--field must be key=value (got '{kv}')"))?;
        fields.push(FieldPredicate {
            key: k.to_string(),
            value: v.to_string(),
            negate: false,
        });
    }
    let q = HybridQuery {
        filter: StructuredFilter {
            time: TimeRange {
                last_hours: since,
                from_micros: None,
                to_micros: None,
            },
            host: host.to_vec(),
            service: service.to_vec(),
            source: source.to_vec(),
            environment: environment.to_vec(),
            severity: severity.to_vec(),
            log_type: log_type.to_vec(),
            fields,
        },
        text: text.clone().map(|query| TextClause { query }),
        semantic: semantic.clone().map(|query| SemanticClause { query }),
        fusion: FusionConfig {
            method: FusionMethod::Rrf { k: rrf_k },
            limit,
            ..Default::default()
        },
    };

    // Daemon-first (its semantic index is warm); else run locally.
    let body = serde_json::to_value(&q)?;
    let v = match try_daemon(
        &cfg,
        "/api/hsearch",
        Some(body),
        std::time::Duration::from_secs(65),
    )
    .await?
    {
        Some(v) => v,
        None => {
            let store = Store::open(&cfg).await?;
            let sem = local_semantic(&cfg, semantic.is_some());
            let res = garmr_query::Executor::run(&store, &q, sem.as_deref()).await?;
            serde_json::to_value(res)?
        }
    };
    render_hybrid(&v);
    Ok(())
}

/// Build a local semantic backend when requested AND the `semantic` build + a
/// model + a non-empty index are all present; else `None` (the executor then
/// reports the clause unavailable).
#[cfg(feature = "semantic")]
fn local_semantic(cfg: &Config, requested: bool) -> Option<Box<dyn garmr_query::SemanticSearch>> {
    if !requested {
        return None;
    }
    let (embedder, digest) = load_embedder().ok()?;
    let store = garmr_embed::VectorStore::open(semantic_store_path(cfg), 5_000_000, &digest).ok()?;
    if store.is_empty() {
        return None;
    }
    Some(Box::new(LocalSemantic { embedder, store }))
}

#[cfg(not(feature = "semantic"))]
fn local_semantic(_cfg: &Config, _requested: bool) -> Option<Box<dyn garmr_query::SemanticSearch>> {
    None
}

/// Render a hybrid result (from the daemon or a local run — same JSON shape).
fn render_hybrid(v: &serde_json::Value) {
    if v["semantic_status"] == "requested_but_unavailable" {
        println!("(note: semantic requested but unavailable — structured + full-text only)");
    }
    let items = v["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        println!("(no matches)");
    }
    for it in &items {
        let tags: String = it["provenance"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| match p["signal"].as_str() {
                        Some("structured") => Some('S'),
                        Some("full_text") => Some('F'),
                        Some("semantic") => Some('V'),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let ts = chrono::DateTime::from_timestamp_micros(it["ts_micros"].as_i64().unwrap_or(0))
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        println!(
            "[{tags:<3}] {ts}  {}/{}  {}  {}",
            it["host"].as_str().unwrap_or(""),
            it["service"].as_str().unwrap_or(""),
            it["severity"].as_str().unwrap_or(""),
            it["message"]
                .as_str()
                .unwrap_or("")
                .chars()
                .take(180)
                .collect::<String>(),
        );
    }
    if v["truncated"].as_bool().unwrap_or(false) {
        println!("[… more results truncated]");
    }
}

pub(crate) async fn retention(cli: &Cli, what: &RetentionCmd) -> Result<()> {
    let cfg = load_config(cli)?;
    let store = Store::open(&cfg).await.context("opening store")?;
    match what {
        RetentionCmd::Run => {
            let mgr = garmr_retention::RetentionManager::new(store, &cfg)
                .context("initialising retention (check retention.archiver / build features)")?;
            let run = mgr
                .run_once(Utc::now())
                .await
                .context("running retention pass")?;
            println!(
                "sealed {} window(s), {} row(s), {} archive byte(s); watermark {}",
                run.windows,
                run.rows,
                run.bytes_out,
                run.watermark_us
                    .and_then(chrono::DateTime::from_timestamp_micros)
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "-".into()),
            );
        }
        RetentionCmd::List => {
            let arcs = store.state.list_cold_archives()?;
            if arcs.is_empty() {
                println!("(no cold archives)");
            }
            for a in &arcs {
                let span = |us: i64| {
                    chrono::DateTime::from_timestamp_micros(us)
                        .map(|t| t.format("%Y-%m-%d").to_string())
                        .unwrap_or_else(|| "-".into())
                };
                println!(
                    "{:<12} {:<7} rows={:<7} {}→{} in={:<10} out={:<10} pruned={} {}",
                    a.id,
                    a.kind,
                    a.rows,
                    span(a.start_us),
                    span(a.end_us),
                    a.bytes_in,
                    a.bytes_out,
                    a.hot_pruned,
                    a.checksum.get(..12).unwrap_or(&a.checksum),
                );
            }
        }
    }
    Ok(())
}

pub(crate) async fn cold_query(
    cli: &Cli,
    sql: &str,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<()> {
    let cfg = load_config(cli)?;
    // Read-only guard: the cold query runs raw DataFusion, so reject anything
    // that isn't a plain query/EXPLAIN (same AST guard the agent's tools use).
    garmr_agent::reject_non_readonly(sql).map_err(|e| anyhow::anyhow!("{e}"))?;
    let store = Store::open(&cfg).await.context("opening store")?;
    let cq = garmr_retention::ColdQuery::new(store, &cfg);
    let from_us = from
        .map(|s| parse_time(s, Bound::Start))
        .transpose()
        .context("parsing --from")?;
    let to_us = to
        .map(|s| parse_time(s, Bound::End))
        .transpose()
        .context("parsing --to")?;
    let res = cq
        .query(sql, from_us, to_us)
        .await
        .context("running cold query")?;
    if res.archives == 0 {
        println!("(no cold archives in the range)");
    } else if res.batches.iter().all(|b| b.num_rows() == 0) {
        println!("(0 rows — {} archives scanned)", res.archives);
    } else {
        print!("{}", format_batches(&res.batches));
    }
    Ok(())
}

#[cfg(test)]
mod reindex_recovery_tests {
    use super::*;

    fn corrupt_count(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("search.corrupt-")
            })
            .count()
    }

    fn test_event(msg: &str) -> garmr_core::Event {
        garmr_core::Event {
            ts: chrono::Utc::now(),
            host: "db01".into(),
            service: "postgres".into(),
            source: "test".into(),
            environment: "test".into(),
            severity: "info".into(),
            log_type: "audit".into(),
            message: msg.to_string(),
            fields: std::collections::BTreeMap::new(),
        }
    }

    // Move an index aside ONLY on genuine corruption/incompatibility — never on a
    // transient/environmental error, so a blip can't destroy a warm healthy index.
    #[test]
    fn corruption_is_distinguished_from_transient_errors() {
        for s in [
            "Footer magic byte mismatch. File corrupted or index was created using old",
            "storage error: Data corruption (in file `meta.json`): cannot be deserialized",
            "IoError { io_error: Custom { kind: InvalidData, error: ... } }",
            "Incompatible index format",
        ] {
            assert!(index_error_is_corruption(s), "should be corruption: {s}");
        }
        for s in [
            "Too many open files (os error 24)",
            "Cannot allocate memory (os error 12)",
            "Permission denied (os error 13)",
            "Resource temporarily unavailable",
            "connection reset by peer",
        ] {
            assert!(
                !index_error_is_corruption(s),
                "transient error must NOT be treated as corruption: {s}"
            );
        }
    }

    // The motivating case: a REAL index with a scribbled segment footer is moved
    // aside and recreatable; the recovered healthy index is then left untouched.
    #[tokio::test]
    async fn corrupt_segment_is_moved_aside_and_recreated() {
        let tmp = tempfile::tempdir().unwrap();
        let search = tmp.path().join("search");
        let state_db = tmp.path().join("state.redb");
        let warehouse = tmp.path().join("warehouse");

        // Build a real single-segment index, then release the writer.
        {
            let idx = garmr_store::SearchIndex::open_writer(&search).unwrap();
            idx.index(vec![test_event("AUDIT: SELECT * FROM curated.persons")])
                .await
                .unwrap();
        }
        // Scribble the segment's term file — destroys its footer.
        let seg = std::fs::read_dir(&search)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().map(|x| x == "term").unwrap_or(false))
            .expect("a segment .term file");
        std::fs::write(&seg, b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").unwrap();
        assert!(
            garmr_store::SearchIndex::open_reader(&search).is_err(),
            "precondition: the scribbled segment must be unreadable"
        );

        reset_search_index_if_unreadable(&search, &state_db, &warehouse).unwrap();
        assert!(!search.exists(), "the corrupt index should be moved aside");
        assert_eq!(corrupt_count(tmp.path()), 1);
        // A fresh reader now opens (recreated empty), so the writable open would too.
        assert!(garmr_store::SearchIndex::open_reader(&search).is_ok());

        // The now-healthy index is left untouched on a second pass.
        reset_search_index_if_unreadable(&search, &state_db, &warehouse).unwrap();
        assert!(search.exists(), "a healthy index must NOT be moved aside");
        assert_eq!(corrupt_count(tmp.path()), 1);
    }

    // A restored-but-unpromoted follower's index is never touched here — the marker
    // makes the writable open refuse regardless, and a follower must not be mutated.
    #[test]
    fn skips_reset_on_a_restored_follower() {
        let tmp = tempfile::tempdir().unwrap();
        let search = tmp.path().join("search");
        let state_db = tmp.path().join("state.redb");
        let warehouse = tmp.path().join("warehouse");
        std::fs::create_dir_all(&search).unwrap();
        std::fs::write(search.join("meta.json"), b"garbage").unwrap();
        std::fs::write(garmr_store::restored_marker_path(&state_db), b"restored").unwrap();

        reset_search_index_if_unreadable(&search, &state_db, &warehouse).unwrap();
        assert!(
            search.join("meta.json").exists(),
            "a restored follower's index must be left intact"
        );
        assert_eq!(corrupt_count(tmp.path()), 0);
    }
}