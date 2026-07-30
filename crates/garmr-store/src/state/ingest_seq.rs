// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 12 — per-collector ingest sequence tracking (delivery observability).
//!
//! An authenticated collector stamps each batch with a monotonic sequence number
//! (`X-Garmr-Seq`) inside an epoch (`X-Garmr-Epoch`, bumped on collector restart).
//! After the batch is durably persisted the server records the observation and
//! classifies it against the per-`(collector_id, epoch)` state.
//!
//! ## Reorder tolerance (why a plain "seq > last ⇒ gap" is wrong)
//!
//! Observations do NOT arrive in seq order: a collector may pipeline batches over
//! several connections, and the pipeline coalesces in-flight batches into one
//! commit whose acks all fire together — so batch N+1 can be observed before
//! batch N even when both were delivered. A high-water-mark-only classifier would
//! call that a phantom Gap. Instead we keep a bounded set of `missing` seqs (below
//! the high-water mark, not yet seen): a forward jump adds the skipped seqs to
//! `missing` (candidate loss, NOT yet a gap); a later lower seq that fills a
//! `missing` slot is a resolved reorder, not a replay. A seq is only counted as a
//! confirmed **gap** when it is evicted from `missing` — either the set overflows
//! its cap (so many later batches arrived that the hole is real loss, not delay)
//! or the epoch ends. This keeps the at-least-once NACK+retry guarantee (a retry
//! re-presents a seq at/below the high-water mark and not in `missing` ⇒ Replay)
//! while never fabricating a gap from mere out-of-order observation.

use chrono::Utc;
use garmr_core::{Error, Result};
use redb::ReadableTable;
use serde::{Deserialize, Serialize};

use super::{StateStore, INGEST_SEQ};

/// Max outstanding `missing` seqs tracked per `(collector, epoch)`. A hole that
/// survives this many later arrivals is treated as real loss, not reordering.
const MISSING_CAP: usize = 4096;
/// Max distinct epochs retained per collector. A legitimate collector uses one
/// epoch per boot; capping bounds the state a malicious authenticated collector
/// can create by incrementing `X-Garmr-Epoch` on every request (review finding).
const EPOCHS_PER_COLLECTOR_CAP: usize = 16;

/// Persisted per-`(collector, epoch)` sequence state (JSON blob).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SeqState {
    first_seq: u64,
    /// Highest seq observed (the high-water mark).
    high: u64,
    /// Seqs below `high` not yet seen (candidate loss / in-flight reorder), sorted.
    #[serde(default)]
    missing: Vec<u64>,
    /// Confirmed lost: evicted from `missing` (cap overflow or epoch end).
    #[serde(default)]
    gaps: u64,
    #[serde(default)]
    replays: u64,
    updated_us: i64,
}

/// The classification of one observed batch sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqVerdict {
    /// No prior state for this `(collector, epoch)` — a fresh boot or reset.
    FirstOfEpoch,
    /// In-order (`seq == high + 1`) or a forward jump whose skipped seqs are only
    /// *candidate* loss (added to `missing`, not yet a gap).
    Advance,
    /// A lower seq arrived and filled a `missing` slot — a resolved reorder.
    Reordered,
    /// `seq <= high` and not outstanding: a retry (dedup-idempotent) or duplicate.
    Replay,
    /// One or more seqs were CONFIRMED lost on this observation (a `missing` entry
    /// aged out of the bounded set). `newly_lost` is how many.
    Gap { newly_lost: u64 },
}

impl SeqVerdict {
    /// Does this verdict warrant a durable audit line?
    pub fn is_gap(&self) -> bool {
        matches!(self, SeqVerdict::Gap { .. })
    }
}

/// A read-model row for the ingest-health surface: the live state of one
/// `(collector, epoch)` sequence.
#[derive(Debug, Clone, Serialize)]
pub struct SeqHealth {
    pub collector_id: String,
    pub epoch: u64,
    pub first_seq: u64,
    pub high_seq: u64,
    /// Confirmed lost (evicted from the outstanding set).
    pub gaps: u64,
    /// Outstanding seqs below the high-water mark not yet seen (lost OR in flight).
    pub outstanding: u64,
    pub replays: u64,
    pub updated_us: i64,
}

fn seq_prefix(collector_id: &str) -> String {
    format!("{collector_id}|")
}

fn seq_key(collector_id: &str, epoch: u64) -> String {
    // collector_id is the trusted, server-assigned id (the configured key, not a
    // hostile shipper's data), so a plain separator is unambiguous. The epoch is
    // zero-padded so a lexicographic range scan over the collector prefix returns
    // epochs in numeric order (used by the epoch-cap eviction).
    format!("{collector_id}|{epoch:020}")
}

impl StateStore {
    /// Observe a batch sequence for an authenticated collector AFTER the batch is
    /// durably persisted, updating the per-`(collector, epoch)` state and
    /// returning the classification. One synchronous redb write; only ever called
    /// with a trusted `collector_id` (the caller enforces FIX#4: no sequence
    /// tracking for unauthenticated ingest).
    pub fn observe_ingest_seq(
        &self,
        collector_id: &str,
        epoch: u64,
        seq: u64,
    ) -> Result<SeqVerdict> {
        let key = seq_key(collector_id, epoch);
        let now_us = Utc::now().timestamp_micros();
        let wtx = self.db.begin_write().map_err(Error::store)?;
        let verdict;
        {
            let mut t = wtx.open_table(INGEST_SEQ).map_err(Error::store)?;
            let cur: Option<SeqState> = t
                .get(key.as_str())
                .map_err(Error::store)?
                .and_then(|v| serde_json::from_slice(v.value()).ok());
            let is_new_epoch = cur.is_none();
            let mut s = cur.unwrap_or_default();
            verdict = classify(&mut s, seq, is_new_epoch);
            s.updated_us = now_us;
            let bytes = serde_json::to_vec(&s).map_err(Error::store)?;
            t.insert(key.as_str(), bytes.as_slice())
                .map_err(Error::store)?;
            if is_new_epoch {
                evict_stale_epochs(&mut t, collector_id, &key)?;
            }
        }
        wtx.commit().map_err(Error::store)?;
        Ok(verdict)
    }

    /// The full ingest-health read model: one row per `(collector, epoch)`,
    /// newest-updated first. Powers the operator health surface (silent-loss
    /// visibility). Read-only; safe to call on any tick.
    pub fn ingest_seq_health(&self) -> Result<Vec<SeqHealth>> {
        let rtx = self.db.begin_read().map_err(Error::store)?;
        let t = rtx.open_table(INGEST_SEQ).map_err(Error::store)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(Error::store)? {
            let (k, v) = row.map_err(Error::store)?;
            let key = k.value();
            let Some((collector_id, epoch_str)) = key.rsplit_once('|') else {
                continue;
            };
            let epoch: u64 = epoch_str.trim_start_matches('0').parse().unwrap_or(0);
            if let Ok(s) = serde_json::from_slice::<SeqState>(v.value()) {
                out.push(SeqHealth {
                    collector_id: collector_id.to_string(),
                    epoch,
                    first_seq: s.first_seq,
                    high_seq: s.high,
                    gaps: s.gaps,
                    outstanding: s.missing.len() as u64,
                    replays: s.replays,
                    updated_us: s.updated_us,
                });
            }
        }
        out.sort_by_key(|r| std::cmp::Reverse(r.updated_us));
        Ok(out)
    }
}

/// Classify `seq` against `s` and mutate `s` in place. See the module docs for the
/// reorder-tolerant model. Overflow-safe: the `seq <= high` case is tested first,
/// so the remaining `high + 1` comparison can never overflow (`high < seq`).
/// `is_new` (the row did not exist) anchors the epoch on the first observation,
/// so a legitimate first seq of 0 is not re-classified on a later duplicate.
fn classify(s: &mut SeqState, seq: u64, is_new: bool) -> SeqVerdict {
    if is_new {
        s.first_seq = seq;
        s.high = seq;
        return SeqVerdict::FirstOfEpoch;
    }
    if seq <= s.high {
        // At or below the high-water mark: a filled hole is a resolved reorder;
        // anything else is a replay/duplicate. `high` is never lowered.
        if let Ok(idx) = s.missing.binary_search(&seq) {
            s.missing.remove(idx);
            return SeqVerdict::Reordered;
        }
        s.replays = s.replays.saturating_add(1);
        return SeqVerdict::Replay;
    }
    // seq > high: the skipped seqs (high+1 ..= seq-1) become candidate-missing.
    // They are appended in increasing order after all existing entries (which are
    // < old high < high+1), so `missing` stays sorted.
    let mut n = s.high.saturating_add(1);
    while n < seq {
        s.missing.push(n);
        n = n.saturating_add(1);
    }
    s.high = seq;
    // Bound the outstanding set: overflow is treated as real loss (a hole that
    // survived MISSING_CAP later arrivals is not mere reordering).
    let mut newly_lost = 0u64;
    if s.missing.len() > MISSING_CAP {
        let evict = s.missing.len() - MISSING_CAP;
        s.missing.drain(0..evict);
        newly_lost = evict as u64;
        s.gaps = s.gaps.saturating_add(newly_lost);
    }
    if newly_lost > 0 {
        SeqVerdict::Gap { newly_lost }
    } else {
        SeqVerdict::Advance
    }
}

/// Keep at most `EPOCHS_PER_COLLECTOR_CAP` epoch rows per collector. Any
/// confirmed `missing` seqs on an evicted (oldest) epoch are folded into the
/// KEPT-oldest epoch's gap count so real loss is not silently forgotten by the
/// cap. `keep_key` is the row just written (never evicted).
fn evict_stale_epochs(
    t: &mut redb::Table<'_, &str, &[u8]>,
    collector_id: &str,
    keep_key: &str,
) -> Result<()> {
    let prefix = seq_prefix(collector_id);
    // Full scan + prefix filter (the codebase idiom; this table is tiny and this
    // runs only when a NEW epoch row is created). `iter()` yields keys ascending,
    // and the zero-padded epoch means that is oldest-epoch-first for a collector.
    let mut keys: Vec<String> = Vec::new();
    for row in t.iter().map_err(Error::store)? {
        let (k, _) = row.map_err(Error::store)?;
        let key = k.value();
        if key.starts_with(&prefix) {
            keys.push(key.to_string());
        }
    }
    if keys.len() <= EPOCHS_PER_COLLECTOR_CAP {
        return Ok(());
    }
    let excess = keys.len() - EPOCHS_PER_COLLECTOR_CAP;
    // Oldest keys are at the front. Never evict the row we just wrote.
    let victims: Vec<String> = keys
        .iter()
        .take(excess)
        .filter(|k| *k != keep_key)
        .cloned()
        .collect();
    // Preserve any outstanding-on-eviction as a durable gap count so real loss is
    // not silently forgotten when its epoch row is reclaimed. Fold it into the
    // oldest KEPT epoch (the first key past the victims).
    let mut orphaned_gaps = 0u64;
    for k in &victims {
        if let Some(v) = t.get(k.as_str()).map_err(Error::store)? {
            if let Ok(s) = serde_json::from_slice::<SeqState>(v.value()) {
                orphaned_gaps = orphaned_gaps.saturating_add(s.missing.len() as u64);
            }
        }
    }
    for k in &victims {
        t.remove(k.as_str()).map_err(Error::store)?;
    }
    if orphaned_gaps > 0 {
        if let Some(kept) = keys.iter().find(|k| !victims.contains(k)) {
            // Read into an owned value so the get-guard is dropped before insert.
            let existing: Option<SeqState> = t
                .get(kept.as_str())
                .map_err(Error::store)?
                .and_then(|v| serde_json::from_slice(v.value()).ok());
            if let Some(mut s) = existing {
                s.gaps = s.gaps.saturating_add(orphaned_gaps);
                let bytes = serde_json::to_vec(&s).map_err(Error::store)?;
                t.insert(kept.as_str(), bytes.as_slice())
                    .map_err(Error::store)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn tmp() -> StateStore {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "garmr-seq-test-{}-{}.redb",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&p);
        StateStore::open(&p).unwrap()
    }

    #[test]
    fn first_and_in_order_advance() {
        let s = tmp();
        assert_eq!(
            s.observe_ingest_seq("c1", 1, 5).unwrap(),
            SeqVerdict::FirstOfEpoch
        );
        assert_eq!(
            s.observe_ingest_seq("c1", 1, 6).unwrap(),
            SeqVerdict::Advance
        );
        assert_eq!(
            s.observe_ingest_seq("c1", 1, 7).unwrap(),
            SeqVerdict::Advance
        );
        let h = &s.ingest_seq_health().unwrap()[0];
        assert_eq!(h.high_seq, 7);
        assert_eq!(h.gaps, 0);
        assert_eq!(h.outstanding, 0);
    }

    #[test]
    fn out_of_order_within_tolerance_is_not_a_gap() {
        let s = tmp();
        s.observe_ingest_seq("c1", 0, 1).unwrap();
        // Pipelined delivery observed as 3 before 2 (the coalescing race): 3 is a
        // forward jump that marks 2 as outstanding, NOT a gap...
        assert_eq!(
            s.observe_ingest_seq("c1", 0, 3).unwrap(),
            SeqVerdict::Advance
        );
        assert_eq!(s.ingest_seq_health().unwrap()[0].outstanding, 1);
        // ...and 2 arriving is a resolved reorder that clears it — zero gaps.
        assert_eq!(
            s.observe_ingest_seq("c1", 0, 2).unwrap(),
            SeqVerdict::Reordered
        );
        let h = &s.ingest_seq_health().unwrap()[0];
        assert_eq!(h.gaps, 0);
        assert_eq!(h.outstanding, 0);
        assert_eq!(h.high_seq, 3);
    }

    #[test]
    fn retry_below_watermark_is_a_replay_never_a_gap() {
        let s = tmp();
        s.observe_ingest_seq("c1", 0, 10).unwrap();
        s.observe_ingest_seq("c1", 0, 11).unwrap();
        // NACK+retry re-presents an already-seen seq: Replay, high unchanged.
        assert_eq!(
            s.observe_ingest_seq("c1", 0, 11).unwrap(),
            SeqVerdict::Replay
        );
        assert_eq!(
            s.observe_ingest_seq("c1", 0, 10).unwrap(),
            SeqVerdict::Replay
        );
        let h = &s.ingest_seq_health().unwrap()[0];
        assert_eq!(h.high_seq, 11);
        assert_eq!(h.gaps, 0);
        assert_eq!(h.replays, 2);
    }

    #[test]
    fn a_jump_beyond_the_cap_confirms_loss() {
        let s = tmp();
        s.observe_ingest_seq("c1", 0, 0).unwrap();
        // Jump far past the reorder window. From high=0 to seq=S the skipped seqs
        // are 1..=S-1 (S-1 of them); with S = CAP+101 that is CAP+100 outstanding,
        // so exactly 100 overflow the cap and are confirmed lost.
        let big = (MISSING_CAP as u64) + 101;
        match s.observe_ingest_seq("c1", 0, big).unwrap() {
            SeqVerdict::Gap { newly_lost } => assert_eq!(newly_lost, 100),
            v => panic!("expected Gap, got {v:?}"),
        }
        let h = &s.ingest_seq_health().unwrap()[0];
        assert_eq!(h.gaps, 100);
        assert_eq!(h.outstanding, MISSING_CAP as u64);
    }

    #[test]
    fn seq_max_then_zero_does_not_overflow_or_lower_high() {
        let s = tmp();
        // First observation is u64::MAX (anchors high at MAX)...
        assert_eq!(
            s.observe_ingest_seq("c1", 0, u64::MAX).unwrap(),
            SeqVerdict::FirstOfEpoch
        );
        // ...then seq 0 must be a Replay (below high), never a wrapping Advance.
        assert_eq!(
            s.observe_ingest_seq("c1", 0, 0).unwrap(),
            SeqVerdict::Replay
        );
        assert_eq!(s.ingest_seq_health().unwrap()[0].high_seq, u64::MAX);
    }

    #[test]
    fn new_epoch_resets_and_epochs_are_capped_per_collector() {
        let s = tmp();
        // Create more epochs than the cap; each is a fresh sequence namespace.
        for e in 0..(EPOCHS_PER_COLLECTOR_CAP as u64 + 5) {
            assert_eq!(
                s.observe_ingest_seq("c1", e, 0).unwrap(),
                SeqVerdict::FirstOfEpoch
            );
        }
        let rows: Vec<_> = s
            .ingest_seq_health()
            .unwrap()
            .into_iter()
            .filter(|r| r.collector_id == "c1")
            .collect();
        assert!(
            rows.len() <= EPOCHS_PER_COLLECTOR_CAP,
            "epochs per collector must be capped, got {}",
            rows.len()
        );
    }

    #[test]
    fn distinct_collectors_are_isolated() {
        let s = tmp();
        s.observe_ingest_seq("a", 0, 1).unwrap();
        s.observe_ingest_seq("b", 0, 50).unwrap();
        assert_eq!(
            s.observe_ingest_seq("a", 0, 2).unwrap(),
            SeqVerdict::Advance
        );
        assert_eq!(
            s.observe_ingest_seq("b", 0, 51).unwrap(),
            SeqVerdict::Advance
        );
        assert_eq!(s.ingest_seq_health().unwrap().len(), 2);
    }
}
