// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! The compaction mechanics the writer actor drives: rebuild+swap the events
//! table, the sealed-row prune hook that shrinks the hot store during a rebuild,
//! and the startup sweep of scratch tables / retired data dirs left by a crash
//! mid-compaction. The trigger DECISION (when to compact) lives with the actor
//! in the parent [`super`] module; this file is the how.

use std::time::Duration;

use garmr_core::{Error, Result};
use skade::arrow_array::{RecordBatch, TimestampMicrosecondArray};
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
    let prune = sealed_prune_hook(compact);
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
            tracing::info!(
                snapshots_before = report.snapshots_before,
                rows = report.rows,
                rows_pruned = report.rows_pruned,
                "compacted events table"
            );
            true
        }
        Err(e) => {
            tracing::error!(error = %e, "compaction failed; cooling down on current table");
            false
        }
    }
}

/// Build the sealed-row prune hook for one compaction run: drop rows whose
/// `event_ts` falls INSIDE a sealed cold window (immutable archives, still
/// queryable via cold-query). Membership in a sealed `[start_us, end_us)`
/// range — not "below the watermark" — is the criterion, because a
/// pathologically late row (an epoch-clock device, an imported history) can sit
/// below the watermark without ever having been archived; window membership
/// keeps such rows hot instead of destroying them. The one remaining edge: a
/// row arriving >retention_days late INTO an already-sealed window is pruned
/// without being in that archive — that class is operator-driven (re-imported
/// history of an archived period) and documented in `garmr-retention`.
///
/// `None` — prune nothing — unless retention is enabled AND sealed archives
/// exist. Fails safe: a batch whose `event_ts` column is missing or
/// unexpectedly typed is kept whole rather than guessed at.
fn sealed_prune_hook(
    compact: &CompactCfg,
) -> Option<impl Fn(RecordBatch) -> skade::Result<RecordBatch> + Send + Sync + use<>> {
    if !compact.prune_sealed {
        return None;
    }
    let mut ranges: Vec<(i64, i64)> = match compact.state.list_cold_archives() {
        Ok(archives) => archives.iter().map(|a| (a.start_us, a.end_us)).collect(),
        Err(e) => {
            tracing::warn!(error = %e, "cold manifest unreadable; compacting without pruning");
            return None;
        }
    };
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_unstable();
    let sealed = move |us: i64| -> bool {
        // Windows are disjoint: the only candidate is the last range starting
        // at or before `us`.
        match ranges.partition_point(|&(start, _)| start <= us) {
            0 => false,
            i => us < ranges[i - 1].1,
        }
    };
    Some(move |batch: RecordBatch| -> skade::Result<RecordBatch> {
        let Some(col) = batch.column_by_name("event_ts") else {
            return Ok(batch);
        };
        let Some(ts) = col.as_any().downcast_ref::<TimestampMicrosecondArray>() else {
            return Ok(batch);
        };
        let keep: skade::arrow_array::BooleanArray =
            ts.iter().map(|v| Some(!v.is_some_and(&sealed))).collect();
        skade::datafusion::arrow::compute::filter_record_batch(&batch, &keep)
            .map_err(|e| skade::SkadeError::other(e.to_string()))
    })
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
