// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The live pipeline: ingested events → store → detection → deduped case →
//! agent, plus every scheduled serve loop (correlation, hunts, the response
//! executor, template/frequency anomaly, source-silence, env learn/promote/
//! detect, risk, retention, baseline auto-promote) — all funnelling their hits
//! through the one [`handle_detection`] case path.
//!
//! [`run`] is the consumer end of the ingest channel. Each coalesced batch is
//! appended to the lakehouse (one group commit), indexed, ACKed, and evaluated
//! against the Sigma rules; a fired detection either bumps an open case (within
//! the realert window) or opens a new one and hands it to the agent. Triage
//! runs in a spawned task so ingest never blocks on an LLM call.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
use garmr_core::{Case, CaseState, Detection};
use garmr_detect::Detector;
use garmr_store::Store;
use tokio::sync::mpsc;

use garmr_agent::Agent;

/// Count of triage tasks currently running, so `serve` can drain them on
/// shutdown instead of aborting mid-loop.
pub type Inflight = Arc<AtomicUsize>;

/// Cap on events coalesced into one commit (bounds memory per commit).
const MAX_COALESCE_EVENTS: usize = 10_000;
/// Bound app-audit findings retained between the parallel prepare stage and
/// the serial finish stage. Findings own an event clone, so preparing the full
/// coalesced batch would amplify attacker-controlled event memory.
const APP_AUDIT_PREPARE_CHUNK_EVENTS: usize = 64;
/// Group-commit window: incoming batches are coalesced for up to this long
/// before one shared commit. Bounds the ACK latency a shipper sees.
const COALESCE_WINDOW: std::time::Duration = std::time::Duration::from_secs(3);

/// Consume ingested event batches until the channel closes.
///
/// Batches are **coalesced into group commits**: the embedded lakehouse pays a
/// full Iceberg snapshot commit (metadata rewrite + fsync) per append, so
/// committing every tiny shipper push individually melts down at ~1 commit/s
/// (each commit slower than the last as snapshot metadata grows — observed
/// live as ingest crawling at 1/40th of real time). Instead: drain everything
/// pending, dwell up to [`COALESCE_WINDOW`] for stragglers, then persist ONE
/// batch, index it, ACK every contributing push, and only then evaluate
/// detections. ACKs carry the append outcome — a failed commit 5xx:es every
/// coalesced push so the shipper retries (at-least-once, no silent loss).
pub async fn run(
    store: Store,
    detector: Arc<Detector>,
    agent: Arc<Agent>,
    realert_secs: u64,
    inflight: Inflight,
    app_audit: Option<Arc<crate::appaudit::AppAudit>>,
    mut rx: mpsc::Receiver<garmr_ingest::IngestBatch>,
) {
    while let Some(first) = rx.recv().await {
        let started = tokio::time::Instant::now();
        let mut events = first.events;
        // Per-event AUTHENTICATED collector id (Phase 12), aligned with `events`.
        // Coalescing must preserve per-batch attribution, so a parallel vec grows
        // in lockstep with `events`.
        let mut collector_ids: Vec<Option<String>> = vec![first.collector_id.clone(); events.len()];
        let mut acks = vec![first.ack];

        // Coalesce: drain whatever is queued; if the window still has time
        // left, wait for more. A closed channel commits what we hold and stops.
        let mut channel_open = true;
        while events.len() < MAX_COALESCE_EVENTS {
            match rx.try_recv() {
                Ok(b) => {
                    collector_ids.extend(std::iter::repeat_n(b.collector_id, b.events.len()));
                    events.extend(b.events);
                    acks.push(b.ack);
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    let elapsed = started.elapsed();
                    if elapsed >= COALESCE_WINDOW {
                        break;
                    }
                    match tokio::time::timeout(COALESCE_WINDOW - elapsed, rx.recv()).await {
                        Ok(Some(b)) => {
                            collector_ids
                                .extend(std::iter::repeat_n(b.collector_id, b.events.len()));
                            events.extend(b.events);
                            acks.push(b.ack);
                        }
                        Ok(None) => {
                            channel_open = false;
                            break;
                        }
                        Err(_) => break, // window over
                    }
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    channel_open = false;
                    break;
                }
            }
        }

        // 1. Persist to the lakehouse (ONE commit), then the full-text index.
        // Attribute each event with its authenticated collector id (Phase 12).
        let n = events.len();
        // Borrow-clone the collector ids here (rather than moving them) so the
        // per-event authenticated attribution is still available to the app-audit
        // plane below, which must gate on it (#14).
        let rows: Vec<(garmr_core::Event, Option<String>)> = events
            .iter()
            .cloned()
            .zip(collector_ids.iter().cloned())
            .collect();
        let append = store.events.append_attributed(rows).await;
        let outcome = match &append {
            Ok(_) => {
                if let Err(e) = store.search.index(events.clone()).await {
                    // Search is a secondary index — the events are durable, so
                    // the pushes still ACK ok; log and move on.
                    tracing::warn!(error = %e, "full-text index failed");
                }
                Ok(())
            }
            Err(e) => {
                tracing::warn!(error = %e, batched = n, "append failed; NACKing coalesced pushes");
                Err(e.to_string())
            }
        };
        for ack in acks.into_iter().flatten() {
            let _ = ack.send(outcome.clone());
        }

        // 2. Detect + case-manage (only on durably stored events).
        // CPU-parallel / async-serial split: the CPU-bound Sigma evaluation runs
        // across the rayon-free fork-join pool (zero-copy — only the event INDEX
        // is moved; each worker borrows `&events[i]`, never cloning the Event),
        // then detection handling stays serial and index-ordered so the
        // suppression/dedup window behaves identically to the old serial loop.
        if append.is_ok() {
            let per_event: Vec<Vec<Detection>> =
                gatling::gatling_forkjoin::gatling_for_each(events.len(), 0, |i| {
                    detector.evaluate(&events[i])
                });
            for dets in per_event {
                for det in dets {
                    if let Err(e) =
                        handle_detection(&store, &agent, realert_secs, &inflight, det).await
                    {
                        tracing::warn!(error = %e, "detection handling failed");
                    }
                }
            }

            // Application-audit / insider-risk plane (Phases 1/3/5/8): per audit
            // event, project → enrich → policy → detectors → lower into the SAME
            // case/triage sink. Gated behind detect.app_audit_enabled; the cheap
            // is_audit_event gate short-circuits non-audit events.
            if let Some(aa) = app_audit.as_deref() {
                // Same CPU-parallel / serial-ordered split as the Sigma path
                // above. Stage A: the CPU-heavy stateless prefix (project →
                // catalog stamp → policy evaluate → stateless detectors →
                // monitoring mult) fans across the rayon-free fork-join pool —
                // zero-copy (only the event INDEX crosses; each worker borrows
                // `&events[i]`) and lock-free (it touches no baseline). Stage B:
                // the baseline read+observe + fuse stays serial and index-ordered,
                // so a later event sees an earlier event's `observe` exactly as the
                // old serial loop did — the within-batch learning order is
                // preserved.
                // Prepare only a bounded window at a time. `PreparedAudit`
                // owns its stateless findings, and each finding owns an Event;
                // retaining one for every event in a coalesced batch permits
                // attacker-controlled memory amplification. Finishing every
                // window before preparing the next preserves global event order.
                // Walk `events` and `collector_ids` in lockstep chunks so each
                // event's AUTHENTICATED collector id is threaded into
                // `prepare_event`. #14: an audit event with no authenticated
                // collector attribution is short-circuited there (no prepared
                // audit), so the insider-risk plane never runs on unattributed
                // data — fail-closed (a no-collector deployment silences it).
                for (chunk, cid_chunk) in events
                    .chunks(APP_AUDIT_PREPARE_CHUNK_EVENTS)
                    .zip(collector_ids.chunks(APP_AUDIT_PREPARE_CHUNK_EVENTS))
                {
                    let prepared =
                        gatling::gatling_forkjoin::gatling_for_each(chunk.len(), 0, |i| {
                            aa.prepare_event(&chunk[i], cid_chunk[i].as_deref())
                        });
                    for (i, prep) in prepared.into_iter().enumerate() {
                        let Some(prep) = prep else { continue };
                        for det in aa.finish_event(&chunk[i], prep) {
                            if let Err(e) =
                                handle_detection(&store, &agent, realert_secs, &inflight, det).await
                            {
                                tracing::warn!(error = %e, "audit detection handling failed");
                            }
                        }
                    }
                }
            }
        }

        if !channel_open {
            break;
        }
    }
    // Persist any learning accumulated since the last flush interval.
    if let Some(aa) = app_audit.as_deref() {
        aa.flush();
    }
    tracing::info!("ingest channel closed; pipeline stopping");
}

/// Run the correlation engine on a fixed tick: every `tick_secs`, evaluate the
/// rules whose schedule is due and route each fresh hit through the same
/// case-open + triage path as Sigma detections.
pub async fn correlation_loop(
    store: Store,
    agent: Arc<Agent>,
    engine: Arc<garmr_correlate::CorrelationEngine>,
    realert_secs: u64,
    inflight: Inflight,
    tick_secs: u64,
) {
    let mut last_run: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    tracing::info!(rules = engine.rules().len(), "correlation engine started");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs)).await;
        let dets = engine.run_due(&store, Utc::now(), &mut last_run).await;
        for det in dets {
            if let Err(e) = handle_detection(&store, &agent, realert_secs, &inflight, det).await {
                tracing::warn!(error = %e, "correlation detection handling failed");
            }
        }
    }
}

/// Scheduled threat hunts: each due hunt runs the agent's hypothesis loop and
/// converts findings into synthetic detections on the SAME case path as Sigma
/// and correlation hits. Hunts are model-spend — the per-call budget
/// reservation inside `run_hunt` is the guardrail, and a failed run is logged
/// and retried at its next tick, never hot-looped.
pub struct HuntLoop {
    pub store: Store,
    pub agent: Arc<Agent>,
    pub provider: Arc<dyn garmr_llm::LlmProvider>,
    pub cfg: garmr_core::Config,
    pub hunts: Vec<garmr_agent::HuntDef>,
    pub realert_secs: u64,
    pub inflight: Inflight,
    pub tick_secs: u64,
}

pub async fn hunt_loop(l: HuntLoop) {
    let HuntLoop {
        store,
        agent,
        provider,
        cfg,
        hunts,
        realert_secs,
        inflight,
        tick_secs,
    } = l;
    // Seed the schedule from PERSISTED reports so a daemon restart doesn't
    // re-fire every hunt (each run is real model spend) — deploys and crashes
    // must not replay the whole hunt book.
    let mut last_run: std::collections::HashMap<String, chrono::DateTime<Utc>> =
        std::collections::HashMap::new();
    if let Ok(reports) = store.state.list_hunt_reports() {
        for r in reports {
            let e = last_run.entry(r.hunt_id.clone()).or_insert(r.started_at);
            if r.started_at > *e {
                *e = r.started_at;
            }
        }
    }
    tracing::info!(hunts = hunts.len(), "hunt scheduler started");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs)).await;
        for hunt in &hunts {
            let now = Utc::now();
            let due = last_run
                .get(&hunt.id)
                .is_none_or(|t| (now - *t).num_seconds() >= hunt.schedule_secs as i64);
            if !due {
                continue;
            }
            last_run.insert(hunt.id.clone(), now);
            // Wall-clock cap per run: the providers have no request timeout of
            // their own, and one hung call must not stall the whole schedule.
            // Cancellation is budget-safe (the reservation guard refunds).
            // Hand the hunt the SAME shared embedder the triage agent uses (Phase
            // 11); `None` until the model finishes loading, then picked up next tick.
            let run = garmr_agent::run_hunt(
                &store,
                provider.as_ref(),
                &cfg,
                &hunt.id,
                &hunt.hypothesis,
                agent.semantic(),
            );
            match tokio::time::timeout(std::time::Duration::from_secs(900), run).await {
                Ok(Ok(report)) => {
                    for det in garmr_agent::findings_to_detections(&report) {
                        if let Err(e) =
                            handle_detection(&store, &agent, realert_secs, &inflight, det).await
                        {
                            tracing::warn!(hunt = %hunt.id, error = %e, "hunt detection handling failed");
                        }
                    }
                }
                Ok(Err(e)) => tracing::warn!(hunt = %hunt.id, error = %e, "scheduled hunt failed"),
                Err(_) => {
                    tracing::warn!(hunt = %hunt.id, "scheduled hunt timed out (900s) — cancelled")
                }
            }
        }
    }
}

/// The response-action executor loop (opt-in via `[executor] enabled`): poll
/// human-`Approved` actions on a tick, re-validate + act (or refuse), record
/// the terminal state. Runs ONLY approved actions — the agent's proposals sit
/// untouched until a human moves them. Off by default.
pub async fn executor_loop(store: Store, cfg: garmr_core::Config, tick_secs: u64) {
    let ex = garmr_agent::Executor::new(store, cfg);
    tracing::info!("response-action executor loop started (acts only on human-approved actions)");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs)).await;
        match ex.run_once().await {
            Ok(done) => {
                for (id, outcome) in done {
                    crate::audit::record_execute(&id, &outcome);
                    tracing::info!(action = %id, ?outcome, "action processed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "executor poll failed"),
        }
    }
}

/// New-template anomaly detection loop. Seeds the existing corpus once at
/// startup (so enabling it doesn't storm on history), then on each tick
/// templatizes recent messages and turns genuinely-new shapes into synthetic
/// detections on the same case path as everything else. Log-and-continue on
/// error; no model spend (pure templating), so a short tick is fine.
#[allow(clippy::too_many_arguments)]
pub async fn anomaly_loop(
    store: Store,
    agent: Arc<Agent>,
    realert_secs: u64,
    inflight: Inflight,
    min_count: u64,
    max_per_tick: usize,
    exclude_sources: Vec<String>,
    tick_secs: u64,
) {
    const WINDOW_HOURS: u32 = 24;
    const SEED_LIMIT: usize = 400_000; // rows scanned; deduped by template (cheap), covers common shapes across the window
    const SCAN_LIMIT: usize = 20_000; // newest rows per detect tick
                                      // Seed FIRST — an unseeded detector can't tell new from historical, so it
                                      // must not detect until seeding succeeds (a failed seed then a detect pass
                                      // would flag the whole corpus as new). Retry seeding on the tick until it
                                      // works; only then start detecting.
    let mut seeded = false;
    loop {
        if !seeded {
            match garmr_analytics::seed(&store, WINDOW_HOURS, SEED_LIMIT, &exclude_sources).await {
                Ok((n, truncated)) => {
                    seeded = true;
                    if truncated {
                        tracing::warn!("anomaly: seed hit the distinct-message cap — baseline is PARTIAL; some old shapes may look new. Raise SEED_LIMIT or narrow the window.");
                    }
                    tracing::info!(
                        seeded = n,
                        "anomaly: baseline recorded; watching for new shapes"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "anomaly: seeding failed — NOT detecting until seeded (retry next tick)");
                    tokio::time::sleep(std::time::Duration::from_secs(tick_secs)).await;
                    continue;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs)).await;
        match garmr_analytics::detect(
            &store,
            WINDOW_HOURS,
            SCAN_LIMIT,
            min_count,
            max_per_tick,
            &exclude_sources,
        )
        .await
        {
            Ok(dets) => {
                for det in dets {
                    if let Err(e) =
                        handle_detection(&store, &agent, realert_secs, &inflight, det).await
                    {
                        tracing::warn!(error = %e, "anomaly detection handling failed");
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "anomaly detect cycle failed"),
        }
    }
}

/// Frequency-baseline anomaly loop. On each tick it compares every active
/// (host, service)'s last-hour volume against its own same-clock-hour baseline
/// (median ± MAD over ~14 days) and routes bursts through the SAME case path.
/// Stateless and cheap (two aggregate SQL reads), so it runs off the ingest hot
/// path; warmup keeps it silent until there is enough history. Off by default.
pub async fn baseline_loop(
    store: Store,
    agent: Arc<Agent>,
    realert_secs: u64,
    inflight: Inflight,
    params: garmr_analytics::BaselineParams,
    tick_secs: u64,
) {
    tracing::info!(
        k = params.k,
        min_count = params.min_count,
        "frequency-baseline loop started"
    );
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs)).await;
        match garmr_analytics::baseline::detect(&store, Utc::now(), &params).await {
            Ok(dets) => {
                for det in dets {
                    if let Err(e) =
                        handle_detection(&store, &agent, realert_secs, &inflight, det).await
                    {
                        tracing::warn!(error = %e, "baseline detection handling failed");
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "baseline detect cycle failed"),
        }
    }
}

/// Phase 14 source-silence loop. On each tick it reads per-source activity over
/// the watch horizon and opens a case for every source that was active and has
/// since gone silent (logging outage / telemetry tampering). Off the ingest hot
/// path; one case per source, realert-windowed. Enabled via env (default off).
pub async fn silence_loop(
    store: Store,
    agent: Arc<Agent>,
    realert_secs: u64,
    inflight: Inflight,
    policy: garmr_analytics::silence::SilencePolicy,
    tick_secs: u64,
) {
    tracing::info!(
        silence_secs = policy.silence_secs,
        watch_hours = policy.watch_hours,
        "source-silence loop started"
    );
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs.max(60))).await;
        match garmr_analytics::silence::detect(&store, Utc::now(), &policy).await {
            Ok(dets) => {
                for det in dets {
                    if let Err(e) =
                        handle_detection(&store, &agent, realert_secs, &inflight, det).await
                    {
                        tracing::warn!(error = %e, "source-silence detection handling failed");
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "source-silence detect cycle failed"),
        }
    }
}

/// Phase 5 environment LEARNER loop. On each tick it reads a window of recent
/// events, derives CANDIDATE observations (never Trusted), and persists them
/// (content-keyed idempotent append + a sighting bump). Off the ingest hot path
/// (a periodic query, not a pipeline tap). Gated by `environment.learn`.
/// The current maximum `event_ts` in the warehouse, as epoch micros. `None` if
/// the query fails or there are no events yet (used to seed the learner
/// watermark so a first run skips history instead of storming/re-counting it).
async fn max_event_ts_us(store: &Store) -> Option<i64> {
    let batches = store
        .events
        .sql("SELECT max(event_ts) AS m FROM events")
        .await
        .ok()?;
    for b in &batches {
        if b.num_rows() == 0 {
            continue;
        }
        let col = b
            .column(0)
            .as_any()
            .downcast_ref::<skade::arrow_array::TimestampMicrosecondArray>()?;
        if skade::arrow_array::Array::is_valid(col, 0) {
            return Some(col.value(0));
        }
    }
    None
}

pub async fn env_learn_loop(store: Store, cfg: garmr_core::Config, tick_secs: u64, bind: bool) {
    use skade::arrow_cast::display::array_value_to_string;
    const SCAN: usize = 5_000;
    let policy = cfg.environment.to_policy();
    tracing::info!(bind, "environment learner loop started");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs.max(60))).await;
        // Consume events STRICTLY AFTER the watermark so each event feeds the
        // learner (and its sighting counters) exactly once. On the very first run
        // (no watermark) seed to the current max event_ts and skip — learn from
        // live traffic forward, never re-count history or storm on backlog.
        let wm = match store.state.env_learn_watermark_us() {
            Ok(Some(w)) => w,
            Ok(None) => {
                match max_event_ts_us(&store).await {
                    Some(m) => {
                        let _ = store.state.set_env_learn_watermark_us(m);
                        tracing::info!(
                            watermark_us = m,
                            "env learner: seeded watermark, skipping history"
                        );
                    }
                    None => tracing::debug!("env learner: no events yet"),
                }
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "env learner: watermark read failed");
                continue;
            }
        };
        // Phase 12: `collector_id` is the TRUSTED source stamped at ingest. In
        // bind mode (collectors configured) events with a NULL collector_id are
        // dropped by `derive_candidates_bound` — unauthenticated events never
        // feed the learner once authentication is in force.
        let sql = format!(
            "SELECT event_ts, host, source, log_type, fields, collector_id FROM events \
             WHERE event_ts > to_timestamp_micros({wm}) ORDER BY event_ts ASC LIMIT {SCAN}"
        );
        let batches = match store.events.sql(&sql).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "env learner: event query failed");
                continue;
            }
        };
        let mut rows: Vec<(garmr_core::Event, Option<String>)> = Vec::new();
        let mut max_ts_us: i64 = wm;
        let mut scanned = 0usize;
        for b in &batches {
            let ts_col = b
                .column(0)
                .as_any()
                .downcast_ref::<skade::arrow_array::TimestampMicrosecondArray>();
            for row in 0..b.num_rows() {
                scanned += 1;
                if let Some(tc) = ts_col {
                    if skade::arrow_array::Array::is_valid(tc, row) {
                        max_ts_us = max_ts_us.max(tc.value(row));
                    }
                }
                let fields_json = array_value_to_string(b.column(4), row).unwrap_or_default();
                let fields = serde_json::from_str(&fields_json).unwrap_or_default();
                let collector_id = if b.column(5).is_null(row) {
                    None
                } else {
                    match array_value_to_string(b.column(5), row) {
                        Ok(s) if !s.is_empty() => Some(s),
                        _ => None,
                    }
                };
                let event = garmr_core::Event {
                    ts: Utc::now(),
                    host: array_value_to_string(b.column(1), row)
                        .unwrap_or_default()
                        .into(),
                    service: "".into(),
                    source: array_value_to_string(b.column(2), row)
                        .unwrap_or_default()
                        .into(),
                    environment: "".into(),
                    severity: "".into(),
                    log_type: array_value_to_string(b.column(3), row)
                        .unwrap_or_default()
                        .into(),
                    message: String::new(),
                    fields,
                };
                rows.push((event, collector_id));
            }
        }
        // Advance the watermark. If we hit the LIMIT the newest event_ts may be a
        // same-micros cluster split across the page boundary, so stop one micro
        // short and re-examine it next tick (bounded, safe-side re-count) rather
        // than skipping its tail; a drained batch advances to the max consumed.
        if scanned > 0 {
            let next = if scanned >= SCAN {
                max_ts_us.saturating_sub(1)
            } else {
                max_ts_us
            };
            if let Err(e) = store.state.set_env_learn_watermark_us(next) {
                tracing::warn!(error = %e, "env learner: watermark advance failed");
            }
        }
        let now = Utc::now();
        let obs = garmr_core::derive_candidates_bound(&rows, &policy, now, bind);
        let mut new_rows = 0usize;
        for o in &obs {
            match store.state.append_observation(o) {
                Ok(inserted) => {
                    if inserted {
                        new_rows += 1;
                    }
                    if let Err(e) = store
                        .state
                        .bump_sighting(&o.fact_id, &o.source.source_id, now)
                    {
                        tracing::warn!(error = %e, "env learner: sighting bump failed");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "env learner: observation append failed"),
            }
        }
        if !obs.is_empty() {
            // One best-effort System audit line per tick (candidate observations
            // are unprotected — like predictions).
            crate::audit::record_best_effort(
                garmr_audit::AuditRecord::new(garmr_audit::action::ENV_OBSERVE, "env_observation")
                    .actor(
                        garmr_audit::ActorType::System,
                        "serve".to_string(),
                        Some("env-learn"),
                    )
                    .outcome(garmr_audit::Outcome::Success)
                    .policy(garmr_audit::PolicyDecision::Allowed)
                    .reason(format!(
                        "learned {} candidate observations ({new_rows} new)",
                        obs.len()
                    )),
            );
        }
        tracing::debug!(observations = obs.len(), new = new_rows, "env learner tick");
    }
}

/// Phase 5 environment AUTO-PROMOTE loop. On each tick it materializes the
/// Candidate facts and promotes those that clear BOTH gate tiers to Trusted — a
/// SYSTEM-actor, fail-closed audited transition that blesses the current value.
/// An open/malicious case or a compromised entity (the inviolable hard blocks)
/// stops any promotion. Auditing-disabled ⇒ no promotion (an unaudited Trusted
/// transition would be inert anyway). Gated by `environment.learn`.
pub async fn env_promote_loop(store: Store, cfg: garmr_core::Config, tick_secs: u64) {
    use garmr_core::{
        current_transition, may_auto_promote, FactState, FactTransition, PromotionContext,
    };
    let policy = cfg.environment.to_policy();
    let ttl = Some(policy.fact_ttl);
    tracing::info!("environment auto-promote loop started");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs.max(60))).await;
        let now = Utc::now();
        let open = match store.state.open_case_entity_set() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "env promote: open-case set failed");
                continue;
            }
        };
        let comp = match store.state.compromised_entity_set() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "env promote: compromised set failed");
                continue;
            }
        };
        let windows = store.state.change_windows(now).unwrap_or_default();
        let facts = match store.state.list_env_facts(ttl, now) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "env promote: fact list failed");
                continue;
            }
        };
        for fact in facts.iter().filter(|f| f.state == FactState::Candidate) {
            let per_source = store
                .state
                .sighting_for(&fact.fact_id)
                .ok()
                .flatten()
                .map(|s| s.per_source_counts)
                .unwrap_or_default();
            let ctx = PromotionContext {
                fact,
                now,
                open_case_entities: &open,
                compromised_entities: &comp,
                change_windows: &windows,
                per_source_counts: &per_source,
                policy: &policy,
            };
            if !may_auto_promote(&ctx) {
                continue;
            }
            // Fail-closed System audit BEFORE the append; no audit ⇒ skip (an
            // unaudited protected transition is inert on read anyway).
            let audit_id = match crate::audit::record_system(
                garmr_audit::action::ENV_PROMOTE,
                "env_fact",
                &fact.fact_id,
                "auto-promote: anti-poisoning gate cleared",
            ) {
                Ok(Some(id)) => id,
                Ok(None) => continue, // auditing disabled — cannot promote
                Err(e) => {
                    tracing::warn!(error = %e, "env promote: audit failed — skipping");
                    continue;
                }
            };
            let blessed = store
                .state
                .observations_for(&fact.fact_id)
                .unwrap_or_default()
                .into_iter()
                .filter(|o| o.value == fact.value)
                .max_by_key(|o| o.recorded_at)
                .map(|o| o.observation_id)
                .unwrap_or_default();
            let prior = store
                .state
                .transitions_for(&fact.fact_id)
                .unwrap_or_default();
            let supersedes = current_transition(&prior).map(|t| t.transition_id.clone());
            let tr = FactTransition {
                transition_id: uuid::Uuid::new_v4().to_string(),
                fact_id: fact.fact_id.clone(),
                to_state: FactState::Trusted,
                from_state: fact.state,
                reason: "auto-promote".to_string(),
                actor: "serve".to_string(),
                target_observation_id: blessed,
                quarantine_until: None,
                supersedes,
                audit_id,
                recorded_at: now,
            };
            match store.state.append_transition(&tr) {
                Ok(()) => {
                    tracing::info!(fact = %fact.fact_id, entity = %fact.entity.id, "auto-promoted an environment fact to Trusted")
                }
                Err(e) => tracing::warn!(error = %e, "env promote: transition append failed"),
            }
        }
    }
}

/// Phase 12: SAFE behavioral-baseline auto-promotion — the exact analogue of
/// [`env_promote_loop`] for the Phase-7 baselines. Each tick, every Candidate
/// baseline whose anti-poisoning gate is FULLY clear (`may_auto_promote` — the
/// inviolable hard blocks AND the maturity thresholds) is promoted to Trusted,
/// fail-closed System-audited. An entity with an open case, a prior
/// forbidden-access (policy violation), or immature/thin data is NEVER
/// auto-trusted — a flood of a new pattern cannot self-promote. Off by default;
/// enabled only when the caller spawns this loop (GARMR_BASELINE_AUTO_PROMOTE).
pub async fn baseline_promote_loop(
    store: Store,
    app_audit: Option<Arc<crate::appaudit::AppAudit>>,
    tick_secs: u64,
) {
    let Some(aa) = app_audit else {
        return; // the plane is disabled — nothing to promote
    };
    tracing::info!("behavioral-baseline auto-promote loop started");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs.max(60))).await;
        // Compute the guard sources ONCE per tick (not per candidate): the case
        // list + the system's compromised-entity id set (the same poison-door
        // source the environment auto-promote loop consults — includes malicious
        // adjudications REGARDLESS of case state).
        let cases = store.state.list_cases().unwrap_or_default();
        let compromised = crate::appaudit::compromised_ids(&store.state);
        for entity in aa.candidate_baselines() {
            // Guards from real state (open case / prior policy violation / known
            // compromise). Auto semantics require BOTH hard blocks AND maturity
            // thresholds clear — never clears a threshold the way an analyst can.
            let guards = crate::appaudit::baseline_guards_from(&cases, &compromised, &entity);
            if !aa.auto_promotion_blocks(&entity, guards).is_empty() {
                continue;
            }
            let key = format!("{:?}:{}", entity.kind, entity.id);
            // Fail-closed System audit BEFORE the promotion; no audit ⇒ skip.
            match crate::audit::record_system(
                garmr_audit::action::BASELINE_PROMOTE,
                "app_baseline",
                &key,
                "auto-promote: behavioral-baseline gate cleared",
            ) {
                Ok(Some(_)) => {}
                Ok(None) => continue, // auditing disabled — cannot auto-promote
                Err(e) => {
                    tracing::warn!(error = %e, "baseline auto-promote: audit failed — skipping");
                    continue;
                }
            }
            if aa.auto_promote_baseline(&entity, guards) {
                tracing::info!(kind = ?entity.kind, id = %entity.id, "auto-promoted a behavioral baseline to Trusted");
            }
        }
    }
}

/// Phase 7 environment-aware detection loop. On each tick it reads a window of
/// recent events + a Trusted-only view of the environment model, runs the
/// env_edge detector (new peer / new identity vs the Trusted baseline), persists
/// each finding, and LOWERS it to a Detection through the SAME case path as every
/// other producer (so it can never act, only surface). Read-only against the env
/// model (TrustedView filters to Trusted, so a poisoned Candidate can't drive a
/// detection). Off any hot path; gated by environment.enabled && detect.enabled.
pub async fn env_detect_loop(
    store: Store,
    cfg: garmr_core::Config,
    agent: Arc<Agent>,
    realert_secs: u64,
    inflight: Inflight,
    tick_secs: u64,
) {
    use skade::arrow_cast::display::array_value_to_string;
    const SCAN: usize = 5_000;
    let policy = garmr_analytics::ensemble::EnsemblePolicy {
        crit_coef: cfg.environment.detect.crit_coef,
        corr_coef: cfg.environment.detect.corr_coef,
        ..Default::default()
    };
    let min_baseline = cfg.environment.detect.min_baseline;
    tracing::info!("environment detection loop started");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs.max(60))).await;
        let now = Utc::now();
        // #18: consume each `event_ts` page exactly once behind an INDEPENDENT,
        // monotonic detector cursor (never the learner's), so a poisoned backlog
        // of historical events can't be replayed as fresh findings every tick
        // (unbounded put_finding + repeated triage budget). On the very first run
        // (no watermark) seed to the current tip and skip history — detect from
        // live traffic forward. The cursor survives daemon restarts.
        let wm = match store.state.env_detect_watermark_us() {
            Ok(Some(w)) => w,
            Ok(None) => {
                match max_event_ts_us(&store).await {
                    Some(m) => {
                        if let Err(e) = store.state.set_env_detect_watermark_us(m) {
                            tracing::warn!(error = %e, "env detect: watermark seed failed");
                        } else {
                            tracing::info!(
                                watermark_us = m,
                                "env detect: seeded watermark, skipping history"
                            );
                        }
                    }
                    None => tracing::debug!("env detect: no events yet"),
                }
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "env detect: watermark read failed");
                continue;
            }
        };
        let view = match garmr_analytics::envdetect::TrustedView::load(&store, None, now) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "env detect: Trusted view load failed");
                continue;
            }
        };
        // Forward scan STRICTLY AFTER the watermark, oldest-first, so each page
        // advances the cursor deterministically.
        let sql = format!(
            "SELECT event_ts, host, source, log_type, fields FROM events \
             WHERE event_ts > to_timestamp_micros({wm}) ORDER BY event_ts ASC LIMIT {SCAN}"
        );
        let batches = match store.events.sql(&sql).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "env detect: event query failed");
                continue;
            }
        };
        let mut events = Vec::new();
        let mut max_ts_us: i64 = wm;
        let mut scanned = 0usize;
        for b in &batches {
            let ts_col = b
                .column(0)
                .as_any()
                .downcast_ref::<skade::arrow_array::TimestampMicrosecondArray>();
            for row in 0..b.num_rows() {
                scanned += 1;
                let event_ts_us = ts_col
                    .filter(|c| skade::arrow_array::Array::is_valid(*c, row))
                    .map(|c| c.value(row))
                    .unwrap_or(wm);
                max_ts_us = max_ts_us.max(event_ts_us);
                let fields_json = array_value_to_string(b.column(4), row).unwrap_or_default();
                let fields = serde_json::from_str(&fields_json).unwrap_or_default();
                events.push(garmr_core::Event {
                    // Preserve the SOURCE event time (not the tick `now`) so the
                    // event carries its real timestamp; a bad micros falls back to
                    // `now`.
                    ts: chrono::DateTime::from_timestamp_micros(event_ts_us).unwrap_or(now),
                    host: array_value_to_string(b.column(1), row)
                        .unwrap_or_default()
                        .into(),
                    service: "".into(),
                    source: array_value_to_string(b.column(2), row)
                        .unwrap_or_default()
                        .into(),
                    environment: "".into(),
                    severity: "".into(),
                    log_type: array_value_to_string(b.column(3), row)
                        .unwrap_or_default()
                        .into(),
                    message: String::new(),
                    fields,
                });
            }
        }
        let findings = garmr_analytics::envdetect::env_edge_findings(
            &events,
            &view,
            &policy,
            min_baseline,
            now,
        );
        for f in findings {
            if let Err(e) = store.state.put_finding(&f) {
                tracing::warn!(error = %e, "env detect: put_finding failed");
            }
            crate::audit::record_best_effort(
                garmr_audit::AuditRecord::new(garmr_audit::action::FINDING, "security_finding")
                    .actor(
                        garmr_audit::ActorType::System,
                        "serve".to_string(),
                        Some("env-detect"),
                    )
                    .outcome(garmr_audit::Outcome::Success)
                    .policy(garmr_audit::PolicyDecision::Allowed)
                    .object_id(&f.finding_id)
                    .reason(format!(
                        "{} on {} (level {})",
                        f.detector, f.event.host, f.level
                    )),
            );
            let det = f.into_detection();
            if let Err(e) = handle_detection(&store, &agent, realert_secs, &inflight, det).await {
                tracing::warn!(error = %e, "env detect: finding handling failed");
            }
        }
        // Advance the durable detector watermark once the whole page is handled.
        // #18 boundary guard (mirrors env_learn_loop): a FULL page (scanned >=
        // SCAN) may have split a same-microsecond cluster across the page edge, so
        // advancing to `max_ts_us` would skip the cluster's tail and SILENTLY DROP
        // its findings. On a full page stop one micro short and re-examine that
        // boundary next tick (a bounded, safe-side re-scan); a drained page (not
        // full) has no tail beyond it, so it advances to the max consumed.
        //
        // The bounded re-examine does NOT re-alert: an env finding's id is
        // (detector, host, principal) — independent of event_ts — and a replayed
        // boundary event lowers to the same `dedup_key`, so `handle_detection`
        // suppresses it within `realert_secs`. The re-examine happens on the very
        // next tick (<= 60s), far inside any realert window, so no duplicate case
        // is opened and no extra triage budget is spent.
        if scanned > 0 {
            let next = if scanned >= SCAN {
                max_ts_us.saturating_sub(1)
            } else {
                max_ts_us
            };
            if let Err(e) = store.state.set_env_detect_watermark_us(next) {
                tracing::warn!(error = %e, "env detect: watermark advance failed");
            }
        }
    }
}

/// Risk-based alerting loop. On each tick it scores every host AND every
/// register caseworker (db_user) from the case store (adjudicated risk,
/// decayed over the window) and, for any subject over the threshold, routes ONE
/// synthetic risk detection through the SAME case path as everything else — the
/// standard suppression window (carried on the detection) keeps a subject from
/// re-opening a risk case every tick. Scoring itself is a
/// cheap read, but a threshold crossing opens a case and therefore spends the
/// agent's (budget-capped) triage — a persistently-hot host re-triages at most
/// once per `risk_realert_secs`. A failed cycle is logged and retried. Off by
/// default; the config is validated at startup.
pub async fn risk_loop(
    store: Store,
    agent: Arc<Agent>,
    realert_secs: u64,
    inflight: Inflight,
    params: garmr_analytics::RiskParams,
    tick_secs: u64,
) {
    tracing::info!(
        threshold = params.threshold,
        halflife_hours = params.halflife_hours,
        "risk-based alerting loop started (per-host + per-staff)"
    );
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(tick_secs)).await;
        let cases = match store.state.list_cases() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "risk: listing cases failed");
                continue;
            }
        };
        let now = Utc::now();
        // Resolve each case through the Phase-3 trust precedence (trusted outcome
        // > analyst decision > discounted prediction/shadow > unresolved), so a
        // human decision or incident outcome outweighs the discounted prediction.
        let index = garmr_analytics::OutcomeIndex::build(
            &cases,
            &store.state.list_incident_outcomes().unwrap_or_default(),
            &store.state.list_decisions().unwrap_or_default(),
            &store.state.list_predictions().unwrap_or_default(),
        );
        // Per-host risk (always) plus per-staff risk (registerkontroll — group
        // by the acting db_user; empty on a deployment with no Postgres
        // access-audit feed). Each vec is score-descending, so `break` on the
        // first sub-threshold object skips the rest of that vec.
        for objs in [
            garmr_analytics::score_hosts_with(&cases, now, &params, &index),
            garmr_analytics::score_staff_with(&cases, now, &params, &index),
        ] {
            for obj in objs {
                if obj.score < params.threshold {
                    break;
                }
                let det = garmr_analytics::risk_detection(&obj, &params, now);
                if let Err(e) = handle_detection(&store, &agent, realert_secs, &inflight, det).await
                {
                    tracing::warn!(kind = %obj.kind, subject = %obj.host, error = %e, "risk detection handling failed");
                }
            }
        }
    }
}

/// Roll aged event windows to the cold tier on a fixed tick. Runs immediately,
/// then every `interval_secs`. Off the ingest hot path and on the concurrent
/// read lane, so it never blocks ingest; a failed pass is logged and retried
/// next tick.
pub async fn retention_loop(mgr: garmr_retention::RetentionManager, interval_secs: u64) {
    tracing::info!(interval_secs, "retention loop started");
    loop {
        match mgr.run_once(Utc::now()).await {
            Ok(run) if run.windows > 0 => tracing::info!(
                windows = run.windows,
                rows = run.rows,
                bytes_out = run.bytes_out,
                "retention sealed cold windows"
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "retention pass failed"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

async fn handle_detection(
    store: &Store,
    agent: &Arc<Agent>,
    realert_secs: u64,
    inflight: &Inflight,
    det: Detection,
) -> garmr_core::Result<()> {
    let key = det.dedup_key();
    let now = unix_secs();
    // A detection may carry its own suppression window (correlation rules do);
    // otherwise use the pipeline's global one.
    let realert = det.realert_secs.unwrap_or(realert_secs);

    let recent = store
        .state
        .suppression_last(&key)?
        .map(|last| now.saturating_sub(last) < realert)
        .unwrap_or(false);

    if recent {
        if let Some(c) = find_open_case(store, &key)? {
            // Burst continues on an OPEN case — bump its count atomically and
            // refresh the window.
            store.state.bump_event_count(&c.id, Utc::now())?;
            store.state.suppression_mark(&key, now)?;
            return Ok(());
        }
        // Within the realert window and the only case is Closed (or gone):
        // SUPPRESS. This (rule, host, key) was handled recently, so we neither
        // reopen nor slide the window. Reopening here would churn on the
        // correlation path, which re-scans the same aggregate every tick and
        // would otherwise reopen + re-triage a benign-closed case on each run.
        // The window is NOT re-marked, so once realert_secs elapses a genuine
        // later recurrence opens a fresh case below.
        return Ok(());
    }

    // Fresh incident (window expired or first sighting): open a case and triage.
    let case = Case::open(det);
    store.state.put_case(&case)?;
    store.state.suppression_mark(&key, now)?;
    tracing::info!(case = %case.id, rule = %case.trigger.rule_id, host = %case.trigger.event.host, "case opened");
    // Best-effort audit of the auto case-open (never blocks the detect loop).
    crate::audit::record_best_effort(
        garmr_audit::AuditRecord::new("case.open", "case")
            .actor(garmr_audit::ActorType::System, "detector", None)
            .object_id(case.id.clone())
            .detector(case.trigger.rule_id.clone())
            .reason(format!(
                "rule={} host={}",
                case.trigger.rule_id, case.trigger.event.host
            ))
            .cases([case.id.clone()]),
    );

    let agent = agent.clone();
    let inflight = inflight.clone();
    let store = store.clone();
    inflight.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        let mut case = case;
        if let Err(e) = agent.triage(&mut case).await {
            tracing::warn!(case = %case.id, error = %e, "triage failed");
        }
        // Record the agent's conclusion (best-effort; off the ingest path). This
        // is the agent's immutable PREDICTION, not human ground truth (Phase 3
        // splits the types). finish() appended an AgentPrediction to the store;
        // reference the newest one's id so the ledger points at the record.
        let (disposition, severity) = case
            .verdict
            .as_ref()
            .map(|v| (format!("{:?}", v.disposition), v.severity))
            .unwrap_or_else(|| ("none".to_string(), 0));
        let prediction_id = store
            .state
            .predictions_for(&case.id)
            .ok()
            .and_then(|mut v| v.pop())
            .map(|p| p.prediction_id)
            .unwrap_or_default();
        crate::audit::record_best_effort(
            garmr_audit::AuditRecord::new(garmr_audit::action::PREDICTION, "prediction")
                .actor(garmr_audit::ActorType::Agent, "triage", None)
                .object_id(prediction_id)
                .detector(case.trigger.rule_id.clone())
                .reason(format!(
                    "disposition={disposition} severity={severity} state={:?}",
                    case.state
                ))
                .cases([case.id.clone()]),
        );
        inflight.fetch_sub(1, Ordering::SeqCst);
    });
    Ok(())
}

/// Newest non-closed case for a dedup key (list-scan is fine at home-lab scale).
fn find_open_case(store: &Store, key: &str) -> garmr_core::Result<Option<Case>> {
    Ok(store
        .state
        .list_cases()?
        .into_iter()
        .find(|c| c.dedup_key == key && c.state != CaseState::Closed))
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
