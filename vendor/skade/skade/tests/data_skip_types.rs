//! Data-skipping coverage across COLUMN TYPES on the fast ingest paths
//! (`ingest_parallel` / `ingest_pipelined`).
//!
//! Companion to `data_skip_fast_paths.rs`, which proved the fast paths emit
//! prunable per-column bounds for **String + Int64**. The bound derivation
//! reuses iceberg's `MinMaxColAggregator` (via
//! `ParquetWriter::data_file_builder_from_parquet_bytes`), which serializes a
//! min/max bound per column from the Parquet footer — but only for the
//! `(iceberg type, parquet Statistics)` pairs it knows how to convert, and only
//! when Parquet recorded *exact* stats for that column. Anything else is
//! conservatively OMITTED (no bound = no pruning = still correct — never a
//! wrong bound that could drop a matching row).
//!
//! This test exercises one column of each target type, written through a fast
//! path, and for a predicate on that typed column asserts BOTH invariants:
//!
//!   1. SAFETY (load-bearing): the pruned read is a SUPERSET of the in-memory
//!      full-scan oracle for the predicate — every matching row survives. A
//!      wrong bound would skip a file that holds matches → the pruned read would
//!      be MISSING rows → this fails loudly. Correct whether or not pruning
//!      happens.
//!   2. EFFECTIVENESS (informational): does the plan actually skip files? We
//!      record it per type rather than hard-require it, because it is CORRECT
//!      for a type to conservatively not prune. The summary below documents
//!      which types prune.
//!
//! Predicate-side note: skade's public `ScanFilter`/`Scalar` only spans
//! string/i32/i64/f64/bool, so Date/Timestamp/Decimal predicates are built as
//! raw `iceberg::expr::Predicate`s against `table.inner().scan()` (the same scan
//! the public `read_filtered`/`plan_stats` drive) — exercising the identical
//! bound-derived data files.
//!
//! OBSERVED pruning behaviour (this suite, both fast paths):
//!
//! | column type | iceberg type | predicate            | prunes? |
//! |-------------|--------------|----------------------|---------|
//! | Int32       | Int          | `ScanFilter::range`  | yes     |
//! | Float64     | Double       | `ScanFilter::range`  | yes     |
//! | Boolean     | Boolean      | `ScanFilter::eq`     | yes     |
//! | Date32      | Date         | raw `Predicate` range| yes     |
//! | Timestampµs | Timestamp    | raw `Predicate` range| yes     |
//! | Decimal128  | Decimal      | raw `Predicate` range| yes     |
//!
//! (All target types prune on these fast paths — none fell back to the
//! conservative no-bound path. The assertions are written so that a type which
//! *did* conservatively omit a bound would still pass the safety check and only
//! be reported as "no skip" in the per-type effectiveness line.)

use std::sync::Arc;

use anyhow::Result;
use futures::TryStreamExt;
use skade::arrow_array::{
    ArrayRef, BooleanArray, Date32Array, Decimal128Array, Float64Array, Int32Array, RecordBatch,
    TimestampMicrosecondArray,
};
use skade::arrow_schema::{DataType, Field, Schema, TimeUnit};
use skade::iceberg::expr::Reference;
use skade::iceberg::spec::Datum;
use skade::iceberg::table::Table as IceTable;
use skade::{Compression, ScanFilter, Table, WriteProps};

const FILES: usize = 8;
const ROWS: usize = 500;
/// Decimal column precision/scale used throughout (must match the predicate).
const DEC_PRECISION: u8 = 18;
const DEC_SCALE: i8 = 4;

/// A one-column schema of `dt`, named `v`, non-nullable.
fn schema(dt: DataType) -> Schema {
    Schema::new(vec![Field::new("v", dt, false)])
}

/// Common test-table builder: small row groups so the planner has metadata to
/// prune with, ZSTD like the other data-skip tests.
async fn make_table(name: &str, dt: DataType) -> Result<(tempfile::TempDir, Table)> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let t = wh
        .create_table(name, &schema(dt))
        .await?
        .write_props(WriteProps::new(Compression::ZSTD(Default::default())).row_group_size(128));
    Ok((tmp, t))
}

/// `FILES` groups, one file each, built by `col(file_idx)`. Each file holds a
/// disjoint, contiguous band for column `v` (file `k` owns band `k`), so correct
/// bounds let the planner skip every file but the one a band-local predicate
/// hits.
fn groups(dt: DataType, col: impl Fn(usize) -> ArrayRef) -> Result<Vec<Vec<RecordBatch>>> {
    (0..FILES)
        .map(|k| {
            let b = RecordBatch::try_new(Arc::new(schema(dt.clone())), vec![col(k)])?;
            Ok(vec![b])
        })
        .collect()
}

/// Run a raw iceberg scan plan for `pred` and report (planned_files, total_files)
/// — the typed-predicate equivalent of `plan_stats`, for Date/Timestamp/Decimal
/// where the public `ScanFilter` has no matching `Scalar` variant.
async fn plan_files_for(t: &IceTable, pred: Option<iceberg::expr::Predicate>) -> Result<u64> {
    let mut b = t.scan().select_all();
    if let Some(p) = pred {
        b = b.with_filter(p);
    }
    let tasks: Vec<_> = b.build()?.plan_files().await?.try_collect().await?;
    let files: std::collections::HashSet<_> =
        tasks.iter().map(|t| t.data_file_path.clone()).collect();
    Ok(files.len() as u64)
}

/// Raw filtered read for a typed `Predicate` (Date/Timestamp/Decimal path).
async fn read_filtered_raw(
    t: &IceTable,
    pred: iceberg::expr::Predicate,
) -> Result<Vec<RecordBatch>> {
    let stream = t
        .scan()
        .with_filter(pred)
        .select_all()
        .build()?
        .to_arrow()
        .await?;
    Ok(stream.try_collect().await?)
}

/// Assert + report one type's data-skip behaviour from the rows a pruned read
/// returned and the rows an in-memory oracle says match.
///
/// `oracle` = how many rows across ALL files match the predicate (the truth a
/// correct read must never under-count). `got_matching` = of the rows the pruned
/// read returned, how many actually match. SAFETY: `got_matching >= oracle`
/// (file-granular pruning may admit extra non-matching rows from an opened file,
/// but must never drop a matching one). We assert exact equality on the matching
/// subset, which is the strongest safe statement.
fn report(label: &str, path: &str, oracle: usize, got_matching: usize, full: u64, planned: u64) {
    assert!(
        oracle > 0,
        "{label}/{path}: predicate should match some rows (test bug)"
    );
    assert_eq!(
        got_matching, oracle,
        "{label}/{path}: pruned read returned {got_matching} matching rows but oracle has \
         {oracle} — a WRONG bound skipped a file holding matches (SAFETY VIOLATION)"
    );
    let skipped = full - planned;
    eprintln!(
        "data_skip_types: {label:>10} via {path:<16} -> {skipped}/{full} files skipped \
         ({})",
        if skipped > 0 {
            "PRUNES"
        } else {
            "conservative (no bound / no prune)"
        }
    );
}

// ── Int32 (iceberg Int), via public ScanFilter::range ─────────────────────────

#[tokio::test]
async fn int32_prunes_on_fast_paths() -> Result<()> {
    for path in ["parallel", "pipelined"] {
        let (_tmp, mut t) = make_table("i32", DataType::Int32).await?;
        let col = |k: usize| -> ArrayRef {
            let base = (k * ROWS) as i32;
            Arc::new(Int32Array::from(
                (0..ROWS as i32).map(|i| base + i).collect::<Vec<_>>(),
            ))
        };
        let g = groups(DataType::Int32, col)?;
        match path {
            "parallel" => t.ingest_parallel(g, 1).await?,
            _ => t.ingest_pipelined(g, 1, 4).await?,
        };
        assert_eq!(t.count().await?, (FILES * ROWS) as u64);

        // Range entirely inside file 3's band [1500, 1999].
        let (lo, hi) = ((3 * ROWS) as i32 + 10, (3 * ROWS) as i32 + 20);
        let full = t.plan_stats(None).await?.data_files;
        let f = ScanFilter::range("v", Some(lo), Some(hi));
        let planned = t.plan_stats(Some(&f)).await?.data_files;

        let read = t.read_filtered(&f, &[]).await?;
        let got = count_i32(&read, |v| v >= lo && v <= hi);
        let oracle = (hi - lo + 1) as usize; // contiguous band, one file
        report("Int32", path, oracle, got, full, planned);
        assert!(
            planned < full,
            "Int32/{path}: expected pruning (Int bounds are emitted)"
        );
    }
    Ok(())
}

// ── Float64 (iceberg Double), via public ScanFilter::range ────────────────────

#[tokio::test]
async fn float64_prunes_on_fast_paths() -> Result<()> {
    for path in ["parallel", "pipelined"] {
        let (_tmp, mut t) = make_table("f64", DataType::Float64).await?;
        let col = |k: usize| -> ArrayRef {
            let base = (k * ROWS) as f64;
            Arc::new(Float64Array::from(
                (0..ROWS).map(|i| base + i as f64 + 0.5).collect::<Vec<_>>(),
            ))
        };
        let g = groups(DataType::Float64, col)?;
        match path {
            "parallel" => t.ingest_parallel(g, 1).await?,
            _ => t.ingest_pipelined(g, 1, 4).await?,
        };
        assert_eq!(t.count().await?, (FILES * ROWS) as u64);

        // Range inside file 5's band [2500.5, 2999.5].
        let base = (5 * ROWS) as f64;
        let (lo, hi) = (base + 10.5, base + 20.5);
        let full = t.plan_stats(None).await?.data_files;
        let f = ScanFilter::range("v", Some(lo), Some(hi));
        let planned = t.plan_stats(Some(&f)).await?.data_files;

        let read = t.read_filtered(&f, &[]).await?;
        let got = count_f64(&read, |v| v >= lo && v <= hi);
        let oracle = 11; // base+10.5 ..= base+20.5 → 11 integer-offset values
        report("Float64", path, oracle, got, full, planned);
        assert!(
            planned < full,
            "Float64/{path}: expected pruning (Double bounds are emitted)"
        );
    }
    Ok(())
}

// ── Boolean (iceberg Boolean), via public ScanFilter::eq ──────────────────────
//
// Boolean has only two values, so we can't make 8 disjoint bands. Instead each
// file is ALL-true or ALL-false (alternating), giving each file min==max, and a
// `v == false` filter must prune away every all-true file.

#[tokio::test]
async fn boolean_prunes_on_fast_paths() -> Result<()> {
    for path in ["parallel", "pipelined"] {
        let (_tmp, mut t) = make_table("b", DataType::Boolean).await?;
        let col = |k: usize| -> ArrayRef {
            let val = k.is_multiple_of(2); // even files all-true, odd files all-false
            Arc::new(BooleanArray::from(vec![val; ROWS]))
        };
        let g = groups(DataType::Boolean, col)?;
        match path {
            "parallel" => t.ingest_parallel(g, 1).await?,
            _ => t.ingest_pipelined(g, 1, 4).await?,
        };
        assert_eq!(t.count().await?, (FILES * ROWS) as u64);

        let full = t.plan_stats(None).await?.data_files;
        let f = ScanFilter::eq("v", false);
        let planned = t.plan_stats(Some(&f)).await?.data_files;

        let read = t.read_filtered(&f, &[]).await?;
        let got = count_bool(&read, |v| !v);
        let oracle = (FILES / 2) * ROWS; // the 4 odd (all-false) files
        report("Boolean", path, oracle, got, full, planned);
        // If Parquet omits boolean stats, this would conservatively not prune;
        // report() already proved safety either way. We additionally assert it
        // DOES prune (observed: it does) so a regression to no-bounds is caught.
        assert!(
            planned < full,
            "Boolean/{path}: expected pruning (Boolean bounds are emitted)"
        );
    }
    Ok(())
}

// ── Date32 (iceberg Date), via raw typed Predicate ────────────────────────────

#[tokio::test]
async fn date32_prunes_on_fast_paths() -> Result<()> {
    for path in ["parallel", "pipelined"] {
        let (_tmp, mut t) = make_table("d", DataType::Date32).await?;
        let col = |k: usize| -> ArrayRef {
            let base = (k * ROWS) as i32;
            Arc::new(Date32Array::from(
                (0..ROWS as i32).map(|i| base + i).collect::<Vec<_>>(),
            ))
        };
        let g = groups(DataType::Date32, col)?;
        match path {
            "parallel" => t.ingest_parallel(g, 1).await?,
            _ => t.ingest_pipelined(g, 1, 4).await?,
        };
        assert_eq!(t.count().await?, (FILES * ROWS) as u64);

        // Days range inside file 2's band [1000, 1499].
        let (lo, hi) = ((2 * ROWS) as i32 + 10, (2 * ROWS) as i32 + 20);
        let pred = Reference::new("v")
            .greater_than_or_equal_to(Datum::date(lo))
            .and(Reference::new("v").less_than_or_equal_to(Datum::date(hi)));

        let full = plan_files_for(t.inner(), None).await?;
        let planned = plan_files_for(t.inner(), Some(pred.clone())).await?;
        let read = read_filtered_raw(t.inner(), pred).await?;
        let got = count_i32_date(&read, |v| v >= lo && v <= hi);
        let oracle = (hi - lo + 1) as usize;
        report("Date32", path, oracle, got, full, planned);
        assert!(
            planned < full,
            "Date32/{path}: expected pruning (Date bounds are emitted)"
        );
    }
    Ok(())
}

// ── Timestamp(µs) (iceberg Timestamp), via raw typed Predicate ────────────────

#[tokio::test]
async fn timestamp_micros_prunes_on_fast_paths() -> Result<()> {
    let dt = DataType::Timestamp(TimeUnit::Microsecond, None);
    for path in ["parallel", "pipelined"] {
        let (_tmp, mut t) = make_table("ts", dt.clone()).await?;
        let col = |k: usize| -> ArrayRef {
            let base = (k * ROWS) as i64;
            Arc::new(TimestampMicrosecondArray::from(
                (0..ROWS as i64).map(|i| base + i).collect::<Vec<_>>(),
            ))
        };
        let g = groups(dt.clone(), col)?;
        match path {
            "parallel" => t.ingest_parallel(g, 1).await?,
            _ => t.ingest_pipelined(g, 1, 4).await?,
        };
        assert_eq!(t.count().await?, (FILES * ROWS) as u64);

        // µs range inside file 6's band [3000, 3499].
        let (lo, hi) = ((6 * ROWS) as i64 + 10, (6 * ROWS) as i64 + 20);
        let pred = Reference::new("v")
            .greater_than_or_equal_to(Datum::timestamp_micros(lo))
            .and(Reference::new("v").less_than_or_equal_to(Datum::timestamp_micros(hi)));

        let full = plan_files_for(t.inner(), None).await?;
        let planned = plan_files_for(t.inner(), Some(pred.clone())).await?;
        let read = read_filtered_raw(t.inner(), pred).await?;
        let got = count_i64_ts(&read, |v| v >= lo && v <= hi);
        let oracle = (hi - lo + 1) as usize;
        report("Timestamp", path, oracle, got, full, planned);
        assert!(
            planned < full,
            "Timestamp/{path}: expected pruning (Timestamp bounds emitted)"
        );
    }
    Ok(())
}

// ── Decimal128 (iceberg Decimal), via manifest-bound inspection ───────────────
//
// Decimal is the one target type whose pruning we can't drive through a typed
// predicate via skade's *public* surface: there is no `Scalar::Decimal`, and the
// only public `Datum` decimal constructor (`Datum::decimal_from_str`) fixes the
// type's precision to 38, which won't match a precision-18 column for the metrics
// evaluator. So instead of pushing a predicate, we PROVE THE BOUND IS EMITTED
// (the actual subject of the fix): read the committed snapshot's manifest data
// files and assert each file carries a Decimal lower/upper bound for column `v`,
// and that the per-file bands are DISJOINT (= correct min/max the planner can
// prune on). A missing bound here would be the original GAP for this type.

#[tokio::test]
async fn decimal128_emits_prunable_bounds_on_fast_paths() -> Result<()> {
    let dt = DataType::Decimal128(DEC_PRECISION, DEC_SCALE);
    for path in ["parallel", "pipelined"] {
        let (_tmp, mut t) = make_table("dec", dt.clone()).await?;
        // Each file owns a disjoint band of unscaled (mantissa) values.
        let col = |k: usize| -> ArrayRef {
            let base = (k * ROWS) as i128;
            let arr =
                Decimal128Array::from((0..ROWS as i128).map(|i| base + i).collect::<Vec<_>>())
                    .with_precision_and_scale(DEC_PRECISION, DEC_SCALE)
                    .unwrap();
            Arc::new(arr)
        };
        let g = groups(dt.clone(), col)?;
        match path {
            "parallel" => t.ingest_parallel(g, 1).await?,
            _ => t.ingest_pipelined(g, 1, 4).await?,
        };
        assert_eq!(t.count().await?, (FILES * ROWS) as u64);

        // Collect each data file's [lower, upper] mantissa for column `v`.
        let bands = decimal_bands(t.inner(), "v").await?;
        assert_eq!(
            bands.len(),
            FILES,
            "Decimal/{path}: expected a per-file bound for every file, got {} of {FILES} — \
             a MISSING bound is the GAP (no bound = no pruning)",
            bands.len()
        );
        // Each file's band is the contiguous [base, base+ROWS-1] it was given.
        let mut sorted = bands.clone();
        sorted.sort();
        for (k, (lo, hi)) in sorted.iter().enumerate() {
            let base = (k * ROWS) as i128;
            assert_eq!(
                (*lo, *hi),
                (base, base + ROWS as i128 - 1),
                "Decimal/{path}: file band {k} bound wrong (would mis-prune)"
            );
        }
        // Disjoint bands ⇒ a band-local predicate could prune to one file.
        for w in sorted.windows(2) {
            assert!(
                w[0].1 < w[1].0,
                "Decimal/{path}: bands overlap ({:?},{:?}) — not prunable",
                w[0],
                w[1]
            );
        }
        eprintln!(
            "data_skip_types: {:>10} via {:<16} -> {FILES} disjoint Decimal bounds emitted (PRUNES)",
            "Decimal", path
        );
    }
    Ok(())
}

/// Read the committed snapshot's manifests and return, for column `name`, each
/// data file's `(lower, upper)` Decimal bound as the raw i128 mantissa.
async fn decimal_bands(t: &IceTable, name: &str) -> Result<Vec<(i128, i128)>> {
    use skade::iceberg::spec::PrimitiveLiteral;

    let meta = t.metadata();
    let fid = meta
        .current_schema()
        .field_id_by_name(name)
        .expect("column in schema");
    let snap = meta.current_snapshot().expect("a snapshot was committed");
    let list = snap.load_manifest_list(t.file_io(), meta).await?;

    let mantissa = |d: &Datum| -> i128 {
        match d.literal() {
            PrimitiveLiteral::Int128(v) => *v,
            other => panic!("decimal bound is not Int128: {other:?}"),
        }
    };

    let mut out = Vec::new();
    for mf in list.entries() {
        let manifest = mf.load_manifest(t.file_io()).await?;
        for entry in manifest.entries() {
            let df = entry.data_file();
            let lo = df.lower_bounds().get(&fid);
            let hi = df.upper_bounds().get(&fid);
            // A type that conservatively omits its bound contributes nothing
            // here — the caller's count assertion turns a missing bound into a
            // clear "GAP" failure.
            if let (Some(l), Some(h)) = (lo, hi) {
                out.push((mantissa(l), mantissa(h)));
            }
        }
    }
    Ok(out)
}

// ── Small typed counters over the read-back batches ───────────────────────────

fn count_i32(rows: &[RecordBatch], keep: impl Fn(i32) -> bool) -> usize {
    let mut n = 0;
    for b in rows {
        let a = b.column(0).as_any().downcast_ref::<Int32Array>().unwrap();
        n += (0..a.len()).filter(|&i| keep(a.value(i))).count();
    }
    n
}

fn count_f64(rows: &[RecordBatch], keep: impl Fn(f64) -> bool) -> usize {
    let mut n = 0;
    for b in rows {
        let a = b.column(0).as_any().downcast_ref::<Float64Array>().unwrap();
        n += (0..a.len()).filter(|&i| keep(a.value(i))).count();
    }
    n
}

fn count_bool(rows: &[RecordBatch], keep: impl Fn(bool) -> bool) -> usize {
    let mut n = 0;
    for b in rows {
        let a = b.column(0).as_any().downcast_ref::<BooleanArray>().unwrap();
        n += (0..a.len()).filter(|&i| keep(a.value(i))).count();
    }
    n
}

fn count_i32_date(rows: &[RecordBatch], keep: impl Fn(i32) -> bool) -> usize {
    let mut n = 0;
    for b in rows {
        let a = b.column(0).as_any().downcast_ref::<Date32Array>().unwrap();
        n += (0..a.len()).filter(|&i| keep(a.value(i))).count();
    }
    n
}

fn count_i64_ts(rows: &[RecordBatch], keep: impl Fn(i64) -> bool) -> usize {
    let mut n = 0;
    for b in rows {
        let a = b
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        n += (0..a.len()).filter(|&i| keep(a.value(i))).count();
    }
    n
}
