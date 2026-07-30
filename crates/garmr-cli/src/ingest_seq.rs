// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 12 — ingest sequence observation wiring and the `ingest-health` surface.
//!
//! The native ingest receiver calls [`ChannelSeqObserver::observe`] from each
//! request handler AFTER the batch is durably persisted. That call is NON-blocking
//! — it only enqueues a [`SeqMark`] — so the ingest hot path never performs a redb
//! commit or an audit fsync inline. A single background task ([`seq_observe_loop`])
//! drains the channel IN ORDER and is the sole writer of the sequence state, which
//! removes the concurrent-observation race that made coalesced/pipelined batches
//! look like phantom gaps. Confirmed gaps are audited through a per-collector
//! windowed aggregator so a collector emitting a stream of gaps cannot flood the
//! append-only ledger.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use garmr_ingest::IngestSeqObserver;
use garmr_store::state::{SeqVerdict, StateStore};

use crate::cli::Cli;
use crate::load_config;

/// One durably-persisted batch's sequence coordinates, awaiting observation.
#[derive(Debug)]
pub(crate) struct SeqMark {
    pub collector_id: String,
    pub epoch: u64,
    pub seq: u64,
}

/// A best-effort, NON-blocking sequence observer: `observe` only enqueues onto the
/// channel drained by [`seq_observe_loop`]. On a full channel (extreme sustained
/// load) the mark is dropped — observability is best-effort and must never stall
/// or fail ingest.
pub(crate) struct ChannelSeqObserver {
    tx: mpsc::Sender<SeqMark>,
}

impl ChannelSeqObserver {
    pub(crate) fn new(tx: mpsc::Sender<SeqMark>) -> Self {
        Self { tx }
    }
}

impl IngestSeqObserver for ChannelSeqObserver {
    fn observe(&self, collector_id: &str, epoch: u64, seq: u64) {
        let mark = SeqMark {
            collector_id: collector_id.to_string(),
            epoch,
            seq,
        };
        if self.tx.try_send(mark).is_err() {
            tracing::debug!(
                collector = collector_id,
                "ingest seq mark dropped (observer channel full)"
            );
        }
    }
}

/// The window over which confirmed-gap audits are aggregated per collector, so a
/// gap-emitting collector writes at most one ledger line per window (mirrors the
/// auth-denied DenyLimiter rather than one append per gap).
const GAP_AUDIT_WINDOW_SECS: u64 = 60;

#[derive(Default)]
struct GapWindow {
    window_start: u64,
    pending_lost: u64,
    /// The most recent (epoch, seq) that revealed loss — for the audit reason.
    last_epoch: u64,
    last_seq: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The single ordered consumer of sequence marks. Sole writer of the per-collector
/// sequence state; drains in channel order so observations are never racing, and
/// aggregates confirmed-gap audits per collector over a fixed window.
pub(crate) async fn seq_observe_loop(state: StateStore, mut rx: mpsc::Receiver<SeqMark>) {
    let mut windows: HashMap<String, GapWindow> = HashMap::new();
    tracing::info!("ingest sequence observer loop started");
    while let Some(m) = rx.recv().await {
        match state.observe_ingest_seq(&m.collector_id, m.epoch, m.seq) {
            Ok(SeqVerdict::Gap { newly_lost }) => {
                let w = windows.entry(m.collector_id.clone()).or_default();
                let now = now_secs();
                if w.window_start == 0 {
                    w.window_start = now;
                }
                w.pending_lost = w.pending_lost.saturating_add(newly_lost);
                w.last_epoch = m.epoch;
                w.last_seq = m.seq;
                if now >= w.window_start + GAP_AUDIT_WINDOW_SECS {
                    flush_gap_window(&m.collector_id, w);
                    w.window_start = now;
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, collector = %m.collector_id, "ingest seq observe failed")
            }
        }
    }
    tracing::info!("ingest sequence observer loop stopped (channel closed)");
}

fn flush_gap_window(collector_id: &str, w: &mut GapWindow) {
    if w.pending_lost == 0 {
        return;
    }
    let lost = w.pending_lost;
    tracing::warn!(
        collector = collector_id,
        missing = lost,
        "ingest sequence gap — batches confirmed never delivered"
    );
    crate::audit::record_ingest_seq_anomaly(
        collector_id,
        &format!(
            "ingest sequence gap: {lost} batch(es) confirmed never delivered \
             (collector {collector_id}, up to epoch {} seq {})",
            w.last_epoch, w.last_seq
        ),
    );
    w.pending_lost = 0;
}

/// `garmr ingest-health` — print the per-collector delivery state (high-water
/// seq, confirmed gaps, still-outstanding seqs, replays), newest-updated first. A
/// LOCAL read-only operator view over the shared state DB; the air-gap-friendly
/// counterpart to a network health endpoint. Reads the state store directly.
pub(crate) fn ingest_health_cmd(cli: &Cli) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg = load_config(cli)?;
    let state = StateStore::open(&cfg.store.state_db)
        .with_context(|| format!("opening state store {}", cfg.store.state_db.display()))?;
    let rows = state.ingest_seq_health()?;
    if rows.is_empty() {
        println!(
            "ingest health: no per-collector sequence data yet \
             (collectors send X-Garmr-Seq/X-Garmr-Epoch once authenticated)"
        );
        return Ok(());
    }
    println!(
        "{:<24} {:>8} {:>12} {:>8} {:>12} {:>8}",
        "COLLECTOR", "EPOCH", "HIGH_SEQ", "GAPS", "OUTSTANDING", "REPLAYS"
    );
    for r in &rows {
        println!(
            "{:<24} {:>8} {:>12} {:>8} {:>12} {:>8}",
            r.collector_id, r.epoch, r.high_seq, r.gaps, r.outstanding, r.replays
        );
    }
    let total_gaps: u64 = rows.iter().map(|r| r.gaps).sum();
    if total_gaps > 0 {
        println!(
            "\nWARNING: {total_gaps} confirmed missing batch(es) across all collectors — investigate silent loss."
        );
    }
    Ok(())
}
