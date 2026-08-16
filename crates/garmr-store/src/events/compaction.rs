// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The compaction mechanics the writer actor drives: rebuild+swap the events
//! table, the sealed-row prune hook that shrinks the hot store during a rebuild,
//! and the startup sweep of scratch tables / retired data dirs left by a crash
//! mid-compaction. The trigger DECISION (when to compact) lives with the actor
//! in the parent [`super`] module; this file is the how.

use std::time::Duration;

use garmr_core::{Error, Result};
use skade::arrow_array::{Array, RecordBatch, TimestampMicrosecondArray};
use skade::iceberg::Catalog; // for `catalog().drop_table` in orphan cleanup

use crate::schema::T_EVENTS;

use super::CompactCfg;

/// Rebuild+swap the events table, reload the actor's handle, and schedule GC of
/// the retired data dir. Returns whether the compaction succeeded. A reload
/// failure after the swap is fatal: continuing with a stale handle would append
/// into the just-retired directory, so after one retry we exit and let
/// supervision restart us cleanly (the swap already committed, so the data is
/// safe under the new directory).
pub(super) async fn run_compaction(
    events: &mut skade::Table,
    wh: &std::sync::Arc<skade::Warehouse>,
    compact: &CompactCfg,
) -> bool {
    let built = build_prune_hook(compact);
    let (prune, stats, sealed_ids) = match built {
        Some((h, st, ids)) => (Some(h), Some(st), ids),
        None => (None, None, Vec::new()),
    };
    let prune_ref = prune
        .as_ref()
        .map(|f| f as &(dyn Fn(RecordBatch) -> skade::Result<RecordBatch> + Send + Sync));
    // Rebuild with the bloom-carrying props so the `event_id` filter survives the
    // compaction (a plain `compact_table` rebuild would drop it, and under the
    // firehose compaction fires often enough that the append-time bloom would
    // otherwise be short-lived).
    let props = crate::schema::events_compact_write_props();
    match wh.compact_table_props(T_EVENTS, prune_ref, &props).await {
        Ok(report) => {
            if let Err(e) = events.refresh().await {
                tracing::warn!(error = %e, "reload after compaction failed; retrying once");
                tokio::time::sleep(Duration::from_secs(2)).await;
                if let Err(e) = events.refresh().await {
                    tracing::error!(error = %e, "reload after compaction failed — exiting so supervision restarts us");
                    std::process::exit(70);
                }
            }
            if let Some(dir) = report.old_data_dir {
                let grace = compact.gc_grace;
                tokio::spawn(async move {
                    tokio::time::sleep(grace).await;
                    let dir_for_log = dir.clone();
                    let r =
                        tokio::task::spawn_blocking(move || std::fs::remove_dir_all(&dir)).await;
                    if let Ok(Err(e)) = r {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            tracing::warn!(dir = %dir_for_log.display(), error = %e, "retired-dir GC failed");
                        }
                    }
                });
            }
            let (sealed_pruned, class_pruned, erased_pruned) = stats
                .map(|s| {
                    (
                        s.sealed.load(std::sync::atomic::Ordering::Relaxed),
                        s.class.load(std::sync::atomic::Ordering::Relaxed),
                        s.erased.load(std::sync::atomic::Ordering::Relaxed),
                    )
                })
                .unwrap_or((0, 0, 0));
            tracing::info!(
                snapshots_before = report.snapshots_before,
                rows = report.rows,
                rows_pruned = report.rows_pruned,
                sealed_pruned,
                class_pruned,
                erased_pruned,
                "compacted events table"
            );
            // The rebuild filtered EVERY batch through the hook, so every row
            // inside a sealed window is now provably gone from the hot store —
            // which is exactly what the archive's `hot_pruned` flag claims.
            // Flipped only after the swap committed: flipping before would
            // assert something a crash could still make false.
            if !sealed_ids.is_empty() {
                if let Err(e) = compact.state.mark_cold_archives_hot_pruned(&sealed_ids) {
                    tracing::warn!(error = %e, "could not record hot_pruned on sealed archives");
                }
            }
            garmr_core::metrics::registry()
                .compaction_runs_total
                .inc(&[("outcome", "ok")]);
            true
        }
        Err(e) => {
            garmr_core::metrics::registry()
                .compaction_runs_total
                .inc(&[("outcome", "failed")]);
            tracing::error!(error = %e, "compaction failed; cooling down on current table");
            false
        }
    }
}

/// Evaluates rows against the persistent erasure tombstones.
///
/// One matcher shared by the serve-path prune hook and the offline erase pass,
/// so the two can never disagree about what "matches" means — a predicate that
/// erased rows offline but let late arrivals through in serve (or vice versa)
/// would leave the store oscillating instead of converging.
pub struct TombstoneMatcher {
    /// (tombstone, precomputed fields-JSON needle for non-column fields).
    entries: Vec<(garmr_core::Tombstone, Option<String>)>,
}

impl TombstoneMatcher {
    pub fn new(tombstones: Vec<garmr_core::Tombstone>) -> Self {
        let entries = tombstones
            .into_iter()
            .map(|t| {
                let needle = t.fields_needle();
                (t, needle)
            })
            .collect();
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Does this row match any tombstone? `fields` is the serialized JSON
    /// column (None when the column is absent/null — then only column-backed
    /// predicates can match, and needle predicates keep the row: never guess a
    /// deletion).
    pub fn matches(&self, host: &str, fields: Option<&str>, ts_us: i64) -> bool {
        self.entries.iter().any(|(t, needle)| {
            if !t.covers_ts(ts_us) {
                return false;
            }
            match needle {
                None => host == t.value,
                Some(n) => fields.is_some_and(|f| f.contains(n.as_str())),
            }
        })
    }
}

/// Per-reason prune counters, so the compaction log can say WHY rows went.
///
/// "rows_pruned=120000" alone cannot distinguish routine sealed-window cleanup
/// from a class policy quietly eating a source an operator still wanted — the
/// split is what makes the log line auditable against intent.
pub(super) struct PruneStats {
    /// Rows dropped because their window is sealed into a cold archive.
    pub sealed: std::sync::atomic::AtomicU64,
    /// Rows dropped by a `[[retention.class]]` hot-window policy.
    pub class: std::sync::atomic::AtomicU64,
    /// Rows dropped because they match a persistent erasure tombstone — the
    /// late-arrival convergence half of targeted erasure.
    pub erased: std::sync::atomic::AtomicU64,
}

/// Build the prune hook for one compaction run, or `None` when there is nothing
/// to prune. Returns the hook, its counters, and the ids of the sealed archives
/// whose rows the rebuild removes (for the `hot_pruned` flip afterwards).
///
/// Two independent prune reasons compose here:
///
/// - **Sealed membership** (unchanged): a row whose `event_ts` falls inside a
///   sealed cold window is dropped — the archive holds it, immutably and
///   queryably. Membership, not "below the watermark", so a pathologically late
///   row that was never archived stays hot.
/// - **Class expiry**: a row whose `source` is listed in `[[retention.class]]`
///   and whose age exceeds that class's `hot_days` is dropped. These classes
///   are excluded from sealing, so the hot copy is the ONLY copy — which is why
///   class pruning defers to legal holds: a row inside a HELD archive's window
///   is kept even when its class says prune. A hold marks a period under
///   litigation, and destroying the only copy of in-period data because a
///   volume policy said so is indefensible. Sealed-membership pruning has no
///   such exemption — there the archive itself preserves the data, held or not.
///
/// Both are gated on `[retention].enabled`: pruning is part of the retention
/// lifecycle, and a disabled lifecycle must not delete anything.
///
/// Fails safe throughout: an unreadable manifest, a missing `event_ts` or
/// `source` column, or an unexpected column type keeps rows rather than
/// guessing.
/// What [`build_prune_hook`] hands back: the batch filter, its per-reason
/// counters, and the sealed-archive ids to flip `hot_pruned` on afterwards.
type BuiltPruneHook = (
    Box<dyn Fn(RecordBatch) -> skade::Result<RecordBatch> + Send + Sync>,
    std::sync::Arc<PruneStats>,
    Vec<String>,
);

fn build_prune_hook(compact: &CompactCfg) -> Option<BuiltPruneHook> {
    use std::sync::atomic::Ordering;

    if !compact.prune_sealed {
        return None;
    }
    let archives = match compact.state.list_cold_archives() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "cold manifest unreadable; compacting without pruning");
            return None;
        }
    };
    let mut ranges: Vec<(i64, i64)> = archives.iter().map(|a| (a.start_us, a.end_us)).collect();
    ranges.sort_unstable();
    let sealed_ids: Vec<String> = archives
        .iter()
        .filter(|a| !a.hot_pruned)
        .map(|a| a.id.clone())
        .collect();
    // Held windows exempt CLASS pruning (the hot copy is the only copy there).
    let mut held: Vec<(i64, i64)> = archives
        .iter()
        .filter(|a| a.legal_hold)
        .map(|a| (a.start_us, a.end_us))
        .collect();
    held.sort_unstable();

    // source -> prune-before cutoff (µs). hot_days floors at 1 so a zero can
    // never race ingest and prune rows moments after they arrive.
    let now_us = chrono::Utc::now().timestamp_micros();
    let class_cutoffs: std::collections::HashMap<String, i64> = compact
        .classes
        .iter()
        .map(|c| {
            let days = i64::from(c.hot_days.max(1));
            (c.source.clone(), now_us - days * 86_400_000_000)
        })
        .collect();

    let tombstones = match compact.state.list_tombstones() {
        Ok(t) => TombstoneMatcher::new(t),
        Err(e) => {
            // Fail SAFE for the erasure direction too: an unreadable tombstone
            // table must not silently disable convergence forever, but this one
            // compaction keeps rows rather than guessing. The next run retries.
            tracing::warn!(error = %e, "tombstones unreadable; this compaction will not erase");
            TombstoneMatcher::new(Vec::new())
        }
    };
    if ranges.is_empty() && class_cutoffs.is_empty() && tombstones.is_empty() {
        return None;
    }

    let in_ranges = |ranges: &[(i64, i64)], us: i64| -> bool {
        match ranges.partition_point(|&(start, _)| start <= us) {
            0 => false,
            i => us < ranges[i - 1].1,
        }
    };
    let stats = std::sync::Arc::new(PruneStats {
        sealed: std::sync::atomic::AtomicU64::new(0),
        class: std::sync::atomic::AtomicU64::new(0),
        erased: std::sync::atomic::AtomicU64::new(0),
    });
    let hook_stats = stats.clone();
    let hook = move |batch: RecordBatch| -> skade::Result<RecordBatch> {
        let Some(col) = batch.column_by_name("event_ts") else {
            return Ok(batch);
        };
        let Some(ts) = col.as_any().downcast_ref::<TimestampMicrosecondArray>() else {
            return Ok(batch);
        };
        // The source column is needed only for class pruning; without it the
        // batch still gets sealed-membership pruning.
        let src = batch
            .column_by_name("source")
            .and_then(|c| c.as_any().downcast_ref::<skade::arrow_array::StringArray>());
        let host_col = batch
            .column_by_name("host")
            .and_then(|c| c.as_any().downcast_ref::<skade::arrow_array::StringArray>());
        let fields_col = batch
            .column_by_name("fields")
            .and_then(|c| c.as_any().downcast_ref::<skade::arrow_array::StringArray>());
        let mut sealed_n = 0u64;
        let mut class_n = 0u64;
        let mut erased_n = 0u64;
        let keep: skade::arrow_array::BooleanArray = (0..ts.len())
            .map(|i| {
                if ts.is_null(i) {
                    return Some(true); // no timestamp — never guess a deletion
                }
                let us = ts.value(i);
                // Class membership is decided FIRST, and a class row is governed
                // by its class policy ALONE. Class rows are excluded from
                // sealing, so a sealed window's archive does not contain them —
                // pruning one by sealed-membership would destroy the only copy
                // while the flag on the archive claims it is preserved. (An
                // archive sealed BEFORE the class was configured does hold them;
                // the cost of this ordering there is a duplicate row kept hot
                // until the class window passes — keeping too long, never
                // destroying.)
                if !class_cutoffs.is_empty() {
                    if let Some(src) = src {
                        if !src.is_null(i) {
                            if let Some(cutoff) = class_cutoffs.get(src.value(i)) {
                                if us < *cutoff && !in_ranges(&held, us) {
                                    class_n += 1;
                                    return Some(false);
                                }
                                return Some(true);
                            }
                        }
                    }
                }
                if in_ranges(&ranges, us) {
                    sealed_n += 1;
                    return Some(false);
                }
                // Erasure tombstones LAST: sealed/class rows are gone either
                // way, so the erased counter names only rows that would
                // otherwise have survived — the late arrivals convergence
                // exists for.
                if !tombstones.is_empty() {
                    let host = host_col
                        .filter(|h| !h.is_null(i))
                        .map(|h| h.value(i))
                        .unwrap_or("");
                    let fields = fields_col.filter(|f| !f.is_null(i)).map(|f| f.value(i));
                    if tombstones.matches(host, fields, us) {
                        erased_n += 1;
                        return Some(false);
                    }
                }
                Some(true)
            })
            .collect();
        hook_stats.sealed.fetch_add(sealed_n, Ordering::Relaxed);
        hook_stats.class.fetch_add(class_n, Ordering::Relaxed);
        hook_stats.erased.fetch_add(erased_n, Ordering::Relaxed);
        skade::datafusion::arrow::compute::filter_record_batch(&batch, &keep)
            .map_err(|e| skade::SkadeError::other(e.to_string()))
    };
    Some((Box::new(hook), stats, sealed_ids))
}

/// A scratch name is `<name>__c` + DIGITS ONLY — the digit check keeps a future
/// legitimate table that merely shares the prefix (say `events__cold`) from
/// being destroyed at every startup.
fn is_scratch(candidate: &str, scratch_prefix: &str) -> bool {
    candidate
        .strip_prefix(scratch_prefix)
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}

/// Drop leftover compaction scratch tables (`<name>__c<stamp>`) and remove data
/// directories orphaned by a crash mid-compaction. Never touches the live
/// table's current data dir. Runs at startup, before serving — no in-flight
/// readers exist yet, so it deletes without a grace window.
pub(super) async fn cleanup_orphans(wh: &skade::Warehouse, name: &str) -> Result<()> {
    let scratch_prefix = format!("{name}__c");
    // 1. Drop scratch table catalog entries (a swap on success removes them; a
    //    surviving one means a pre-swap crash — the live table is authoritative).
    for ident in wh.table_idents().await.map_err(Error::store)? {
        if is_scratch(ident.name(), &scratch_prefix) {
            if let Err(e) = wh.catalog().drop_table(&ident).await {
                tracing::warn!(table = %ident.name(), error = %e, "dropping scratch table failed");
            } else {
                tracing::info!(table = %ident.name(), "dropped leftover compaction scratch table");
            }
        }
    }
    // 2. Remove sibling data dirs for `name` that aren't the live table's dir
    //    (retired originals + scratch dirs whose table we just dropped).
    let live = wh.table(name).await.map_err(Error::store)?;
    let live_dir = live
        .inner()
        .metadata()
        .location()
        .strip_prefix("file://")
        .map(std::path::PathBuf::from);
    // Fail SAFE: if we can't resolve the live dir to a local path (e.g. a
    // non-file:// / object-store location), delete nothing — never risk the
    // live table. `open()` always yields a file:// location, so this is a guard,
    // not the normal path.
    let Some(live_dir) = live_dir else {
        tracing::warn!("live events location is not a local path; skipping orphan-dir GC");
        return Ok(());
    };
    let ns_dir = wh.root().join("warehouse").join(skade::DEFAULT_NAMESPACE);
    let Ok(entries) = std::fs::read_dir(&ns_dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();
        let is_this_table = fname == name || is_scratch(&fname, &scratch_prefix);
        // Only remove a dir we can positively distinguish from the live one.
        if is_this_table && path != live_dir {
            tracing::info!(dir = %path.display(), "removing orphaned compaction data dir");
            let _ = std::fs::remove_dir_all(&path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::StateStore;
    use skade::arrow_array::{ArrayRef, StringArray};
    use std::sync::Arc;

    const DAY_US: i64 = 86_400_000_000;

    fn tmp_state() -> StateStore {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "garmr-compact-test-{}-{}.redb",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&p);
        StateStore::open(&p).unwrap()
    }

    fn cfg_with(
        state: StateStore,
        classes: Vec<garmr_core::RetentionClass>,
    ) -> super::super::CompactCfg {
        super::super::CompactCfg {
            threshold: 8,
            gc_grace: Duration::from_secs(0),
            prune_sealed: true,
            state,
            classes,
        }
    }

    fn batch(rows: &[(i64, &str)]) -> RecordBatch {
        let schema = Arc::new(skade::arrow_schema::Schema::new(vec![
            skade::arrow_schema::Field::new(
                "event_ts",
                skade::arrow_schema::DataType::Timestamp(
                    skade::arrow_schema::TimeUnit::Microsecond,
                    None,
                ),
                true,
            ),
            skade::arrow_schema::Field::new("source", skade::arrow_schema::DataType::Utf8, true),
        ]));
        let ts: TimestampMicrosecondArray = rows.iter().map(|(t, _)| Some(*t)).collect();
        let src: StringArray = rows.iter().map(|(_, s)| Some(*s)).collect();
        RecordBatch::try_new(
            schema,
            vec![Arc::new(ts) as ArrayRef, Arc::new(src) as ArrayRef],
        )
        .unwrap()
    }

    fn arc_at(id: &str, start_us: i64, end_us: i64, held: bool) -> garmr_core::ColdArchive {
        garmr_core::ColdArchive {
            id: id.into(),
            kind: "plain".into(),
            file: format!("{id}.parquet"),
            start_us,
            end_us,
            rows: 1,
            bytes_in: 1,
            bytes_out: 1,
            checksum: "c".into(),
            hot_pruned: false,
            sealed_at: chrono::Utc::now(),
            legal_hold: held,
        }
    }

    fn kunai_10d() -> Vec<garmr_core::RetentionClass> {
        vec![garmr_core::RetentionClass {
            source: "kunai".into(),
            hot_days: 10,
        }]
    }

    #[test]
    fn class_rows_past_their_hot_window_prune_and_other_sources_stay() {
        // The acceptance line: 10-day-old kunai rows pruned, journald retained.
        let now = chrono::Utc::now().timestamp_micros();
        let cfg = cfg_with(tmp_state(), kunai_10d());
        let (hook, stats, _) = build_prune_hook(&cfg).expect("hook builds");

        let out = hook(batch(&[
            (now - 12 * DAY_US, "kunai"),    // past the class window — pruned
            (now - 12 * DAY_US, "journald"), // same age, unlisted source — kept
            (now - 2 * DAY_US, "kunai"),     // young class row — kept
        ]))
        .unwrap();
        assert_eq!(out.num_rows(), 2, "only the aged kunai row goes");
        assert_eq!(stats.class.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(stats.sealed.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn a_legal_hold_keeps_class_rows_that_would_otherwise_prune() {
        // Class rows are never archived, so inside a held window the hot copy is
        // the ONLY copy — a volume policy must not destroy it during litigation.
        let now = chrono::Utc::now().timestamp_micros();
        let state = tmp_state();
        // A HELD archive covering [now-15d, now-11d): the aged kunai row falls
        // inside it. (An unheld sealed row of the same window WOULD prune —
        // that is the next assertion.)
        state
            .put_cold_archive(&arc_at("held", now - 15 * DAY_US, now - 11 * DAY_US, true))
            .unwrap();
        let cfg = cfg_with(state, kunai_10d());
        let (hook, stats, _) = build_prune_hook(&cfg).expect("hook builds");

        let out = hook(batch(&[
            (now - 12 * DAY_US, "kunai"), // in the held window — KEPT
            (now - 20 * DAY_US, "kunai"), // outside it — pruned by class
            (now - 12 * DAY_US, "journald"), // sealed-membership still applies:
                                          // the archive preserves it — pruned
        ]))
        .unwrap();
        assert_eq!(out.num_rows(), 1, "only the held kunai row survives");
        assert_eq!(stats.class.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(stats.sealed.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn per_reason_counters_split_sealed_from_class() {
        let now = chrono::Utc::now().timestamp_micros();
        let state = tmp_state();
        state
            .put_cold_archive(&arc_at("w", now - 30 * DAY_US, now - 20 * DAY_US, false))
            .unwrap();
        let cfg = cfg_with(state, kunai_10d());
        let (hook, stats, sealed_ids) = build_prune_hook(&cfg).expect("hook builds");
        assert_eq!(
            sealed_ids,
            vec!["w".to_string()],
            "flip candidates reported"
        );

        let out = hook(batch(&[
            (now - 25 * DAY_US, "journald"), // sealed window — the archive holds it
            (now - 25 * DAY_US, "kunai"),    // class row IN a sealed window: the
            // archive does NOT hold it (classes
            // are excluded at seal), so it is
            // counted as a CLASS prune
            (now - 12 * DAY_US, "kunai"), // class expiry
            (now - DAY_US, "journald"),   // kept
        ]))
        .unwrap();
        assert_eq!(out.num_rows(), 1);
        assert_eq!(stats.sealed.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(stats.class.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn without_retention_enabled_nothing_ever_prunes() {
        // Class policies live under [retention]; a disabled lifecycle deletes
        // nothing, however the classes are configured.
        let mut cfg = cfg_with(tmp_state(), kunai_10d());
        cfg.prune_sealed = false;
        assert!(build_prune_hook(&cfg).is_none());
    }

    #[test]
    fn marking_hot_pruned_flips_only_the_named_archives() {
        let now = chrono::Utc::now().timestamp_micros();
        let state = tmp_state();
        state
            .put_cold_archive(&arc_at("a", now - 30 * DAY_US, now - 20 * DAY_US, false))
            .unwrap();
        state
            .put_cold_archive(&arc_at("b", now - 20 * DAY_US, now - 10 * DAY_US, false))
            .unwrap();
        state
            .mark_cold_archives_hot_pruned(&["a".to_string(), "missing".to_string()])
            .unwrap();
        let arcs = state.list_cold_archives().unwrap();
        let by_id = |id: &str| arcs.iter().find(|x| x.id == id).unwrap();
        assert!(by_id("a").hot_pruned, "named archive flipped");
        assert!(!by_id("b").hot_pruned, "unnamed archive untouched");
    }
}
