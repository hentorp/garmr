// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/capacity` — how much of this node is used, and what bounds it.
//!
//! "What hardware do I need for 10k EPS and 13 months of retention?" is a
//! day-one evaluation question whose honest answer used to be "read the source".
//! This endpoint turns it into one request: tier sizes on disk, free space, a
//! growth rate, days until the disk fills, and — the part evaluators actually
//! miss — the **hard caps** that shape capacity on a single node, as data rather
//! than folklore.
//!
//! Two rules shape the implementation:
//!
//! 1. **Never touch the query semaphore.** garmr allows two concurrent searches
//!    and one warehouse read lane. A capacity endpoint that queued behind them
//!    would make a monitoring poll compete with an analyst's search, so the
//!    event total is read from the existing single-flight cache and never
//!    triggers a fresh scan.
//! 2. **Tolerate a moving tree.** Compaction and sealing delete directories
//!    while this walk runs; a vanished entry is normal, not an error.

use axum::extract::State;
use serde_json::{json, Value};

use super::{ApiResult, ApiState};

/// GET /api/capacity — storage occupancy, growth projection and the static caps.
pub(super) async fn capacity(State(st): State<ApiState>) -> ApiResult {
    let cfg = &st.cfg.store;
    let warehouse = dir_size(&cfg.warehouse_dir);
    let search = dir_size(&cfg.search_dir);
    let state_db = file_size(&cfg.state_db);
    let cold_dir = st.cfg.retention.cold_dir.clone();
    let cold_bytes = dir_size(&cold_dir);
    let free = free_bytes(&cfg.warehouse_dir);

    // Cold-tier aggregation from the manifest — rows, compression achieved, and
    // the window span actually covered. `bytes_in`/`bytes_out` are recorded per
    // archive at seal time, so the ratio is measured, not assumed.
    let archives = st.store.state.list_cold_archives().unwrap_or_default();
    let cold_rows: u64 = archives.iter().map(|a| a.rows).sum();
    let cold_in: u64 = archives.iter().map(|a| a.bytes_in).sum();
    let cold_out: u64 = archives.iter().map(|a| a.bytes_out).sum();
    let cold_span = archives
        .iter()
        .map(|a| a.start_us)
        .min()
        .zip(archives.iter().map(|a| a.end_us).max());

    // Growth: derived from the cold manifest's own window span, which is the one
    // measurement of real throughput this node has. With retention disabled
    // there are no archives, so we say so rather than extrapolating from zero.
    let retention_on = st.cfg.retention.enabled;
    let per_day = daily_bytes(cold_out, cold_span);
    let days_to_full = per_day
        .filter(|d| *d > 0.0)
        .zip(free)
        .map(|(d, f)| f as f64 / d);

    Ok(axum::Json(json!({
        "storage": {
            "warehouse_bytes": warehouse,
            "search_index_bytes": search,
            "state_db_bytes": state_db,
            "cold_bytes": cold_bytes,
            "free_bytes": free,
        },
        "cold": {
            "archives": archives.len(),
            "rows": cold_rows,
            "bytes_in": cold_in,
            "bytes_out": cold_out,
            "compression_ratio": ratio(cold_in, cold_out),
            "window_start_us": cold_span.map(|(s, _)| s),
            "window_end_us": cold_span.map(|(_, e)| e),
        },
        "growth": {
            "retention_enabled": retention_on,
            // Null rather than 0 when unmeasurable: a zero here would read as
            // "this node is not growing", which is the opposite of the truth.
            "bytes_per_day": per_day,
            "days_until_disk_full": days_to_full,
            "note": growth_note(retention_on, per_day.is_some()),
        },
        "limits": limits(cfg.retention_days),
    })))
}

/// The static caps that bound a single node, reported as data so an evaluator
/// does not have to find them in the source. Each carries the constant's home.
///
/// The semantic cap is only reported when the `semantic` feature is compiled in.
/// A build without it has no semantic lane at all, so naming a vector limit
/// would describe a constraint that does not exist in this binary — an
/// evaluator sizing against it would be sizing for the wrong product.
fn limits(retention_days: u32) -> Value {
    // Only the `semantic` build pushes a further entry below, so without that
    // feature the binding is never mutated. Scoped to exactly that
    // configuration rather than a blanket allow, so a genuinely unused `mut`
    // introduced later still fails the build.
    #[cfg_attr(not(feature = "semantic"), allow(unused_mut))]
    let mut caps = vec![
        json!({
            "name": "concurrent_searches",
            "value": super::MAX_CONCURRENT_SEARCHES,
            "where": "api/mod.rs MAX_CONCURRENT_SEARCHES",
            "effect": "Full-text searches beyond this queue rather than run in parallel."
        }),
        json!({
            "name": "retention_days",
            "value": retention_days,
            "where": "store.retention_days",
            "effect": "Events older than this roll to the cold tier when retention is enabled."
        }),
    ];
    #[cfg(feature = "semantic")]
    caps.push(json!({
        "name": "semantic_index_vectors",
        "value": super::semantic::semantic_max(),
        "where": "api/semantic.rs SEMANTIC_MAX (GARMR_SEMANTIC_MAX)",
        "effect": "Semantic search covers at most this many events; the index rebuild is not incremental."
    }));
    Value::Array(caps)
}

fn growth_note(retention_on: bool, measured: bool) -> &'static str {
    match (retention_on, measured) {
        (false, _) => {
            "Retention is disabled: nothing rolls to cold, so the hot tier grows without bound \
             and no growth rate can be derived from sealed windows."
        }
        (true, false) => {
            "Retention is enabled but no window has been sealed yet — the growth rate becomes \
             available after the first seal."
        }
        (true, true) => {
            "Derived from sealed cold windows (compressed bytes per day of covered event time)."
        }
    }
}

/// Bytes per day of covered event time, or `None` when the span is unusable.
/// Kept pure so the projection math is testable without a store.
fn daily_bytes(bytes_out: u64, span_us: Option<(i64, i64)>) -> Option<f64> {
    let (start, end) = span_us?;
    let micros = end.checked_sub(start).filter(|d| *d > 0)? as f64;
    let days = micros / 86_400_000_000.0;
    if days <= 0.0 {
        return None;
    }
    Some(bytes_out as f64 / days)
}

/// Compression ratio in:out, `None` when nothing has been sealed (never 0.0,
/// which would render as "compresses to nothing").
fn ratio(bytes_in: u64, bytes_out: u64) -> Option<f64> {
    if bytes_in == 0 || bytes_out == 0 {
        return None;
    }
    Some(bytes_in as f64 / bytes_out as f64)
}

/// Recursive size of `dir`, tolerating entries that vanish mid-walk (compaction
/// and sealing delete directories under us — that is normal, not an error) and
/// never following symlinks out of the tree.
fn dir_size(dir: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue; // vanished or unreadable — skip, do not fail the request
        };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(e.path());
            } else if let Ok(m) = e.metadata() {
                total += m.len();
            }
        }
    }
    total
}

fn file_size(p: &std::path::Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

/// Free bytes on the filesystem holding `path`, via `statvfs`. `None` when the
/// call fails — reporting 0 free would trigger a false disk-full alarm.
fn free_bytes(path: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: `c` is a valid NUL-terminated path and `stat` is a
        // freshly-zeroed, correctly-sized libc::statvfs the call fills in.
        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c.as_ptr(), &mut stat) != 0 {
                return None;
            }
            Some(stat.f_bavail as u64 * stat.f_frsize as u64)
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_bytes_uses_the_covered_event_span() {
        let day = 86_400_000_000i64;
        // 2 GiB sealed across exactly two days of event time.
        let per_day = daily_bytes(2 * 1024 * 1024 * 1024, Some((0, 2 * day))).unwrap();
        assert!(
            (per_day - 1024.0 * 1024.0 * 1024.0).abs() < 1.0,
            "expected ~1 GiB/day, got {per_day}"
        );
    }

    #[test]
    fn projection_is_none_rather_than_zero_when_unmeasurable() {
        // No archives, a zero-length span, and a reversed span must all decline
        // to answer. A 0.0 here would render as "not growing" — the opposite of
        // the truth on a node that simply has not sealed a window yet.
        assert!(daily_bytes(0, None).is_none());
        assert!(daily_bytes(1024, Some((5, 5))).is_none());
        assert!(daily_bytes(1024, Some((10, 5))).is_none());
    }

    #[test]
    fn compression_ratio_declines_on_empty_input() {
        assert!(ratio(0, 0).is_none());
        assert!(ratio(1000, 0).is_none());
        assert_eq!(ratio(1000, 250), Some(4.0));
    }

    #[test]
    fn dir_size_sums_nested_files_and_tolerates_a_missing_dir() {
        let root = std::env::temp_dir().join(format!("garmr-cap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("data/nested")).unwrap();
        std::fs::write(root.join("data/a.parquet"), vec![0u8; 100]).unwrap();
        std::fs::write(root.join("data/nested/b.parquet"), vec![0u8; 50]).unwrap();
        assert_eq!(dir_size(&root), 150);
        // A path that does not exist is 0, not a panic: the tree moves under us.
        assert_eq!(dir_size(&root.join("gone")), 0);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn growth_note_states_unbounded_growth_when_retention_is_off() {
        // The dangerous case to get wrong: with retention disabled the hot tier
        // grows forever, and the note must say so instead of implying a plateau.
        assert!(growth_note(false, false).contains("without bound"));
        assert!(growth_note(true, false).contains("after the first seal"));
        assert!(growth_note(true, true).contains("sealed cold windows"));
    }
}
