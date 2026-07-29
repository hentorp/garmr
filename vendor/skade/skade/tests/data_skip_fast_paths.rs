//! Data-skipping proof for the FAST ingest paths (`ingest_parallel` /
//! `ingest_pipelined`).
//!
//! Background: the streaming `append` path uses iceberg's `DataFileWriter`,
//! which records per-column min/max bounds, so the scan planner can prune files.
//! The fast paths build the `DataFile` by hand. They USED to set only
//! `record_count` + `file_size` (no bounds), so a table written that way could
//! never be file-pruned — silently undercutting the sort/min-max work (see
//! `.nornir/data-skipping-bench.md`, "GAP"). The fix derives per-column bounds
//! from each encoded Parquet file's own footer statistics.
//!
//! TWO things are asserted, and both must hold for the fix to be correct:
//!
//!   1. SAFETY (never drop a matching row): the rows returned by a *pruned*
//!      filtered read are IDENTICAL to a full-scan filtered with the same
//!      predicate in memory. Wrong bounds would skip a file that holds matching
//!      rows → the pruned read would be MISSING rows → this fails loudly. This
//!      is the load-bearing assertion: it is RED if bounds are wrong.
//!
//!   2. EFFECTIVENESS (pruning actually happens): `plan_stats` shows files were
//!      skipped (`full.data_files - pruned.data_files > 0`). This is RED if the
//!      fix regresses to "no bounds emitted" (the original GAP).
//!
//! Both string columns (`repo`, `symbol`) and an Int64 column (`value`, via a
//! `range` predicate) are exercised, covering the two riskiest single-value
//! bound serializations.

use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};
use skade::{Compression, ScanFilter, Table, WriteProps};

const REPOS: usize = 8;
const ROWS: usize = 1_000;

fn schema() -> Schema {
    Schema::new(vec![
        Field::new("repo", DataType::Utf8, false),
        Field::new("symbol", DataType::Utf8, false),
        Field::new("value", DataType::Int64, false),
    ])
}

/// One file's worth of rows for a single `repo`, with a disjoint, contiguous
/// `symbol`/`value` range per repo so each file's per-column min==max-band is
/// non-overlapping — i.e. correct bounds let the planner skip every other file.
fn repo_batch(repo_idx: usize, rows: usize) -> Result<RecordBatch> {
    let base = (repo_idx * rows) as i64;
    let repo = format!("repo{repo_idx:02}");
    let repos: Vec<&str> = std::iter::repeat(repo.as_str()).take(rows).collect();
    let syms: Vec<String> = (0..rows)
        .map(|i| format!("SYM{:08}", base + i as i64))
        .collect();
    let vals: Vec<i64> = (0..rows).map(|i| base + i as i64).collect();
    Ok(RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(StringArray::from(repos)),
            Arc::new(StringArray::from(syms)),
            Arc::new(Int64Array::from(vals)),
        ],
    )?)
}

/// All rows the table holds (the source of truth for the full-scan oracle).
fn all_rows() -> Result<Vec<RecordBatch>> {
    (0..REPOS).map(|r| repo_batch(r, ROWS)).collect()
}

/// In-memory oracle: full-scan every batch and keep only rows matching `filter`.
/// This is the answer a correct pruned read MUST equal (never a superset is
/// allowed to be MISSING a matching row; file-granular pruning may admit extra
/// non-matching rows, so we compare on the *matching subset*, see below).
fn oracle_matching(filter: &Filter) -> Result<Vec<(String, String, i64)>> {
    let mut out = Vec::new();
    for b in all_rows()? {
        let repo = b.column(0).as_any().downcast_ref::<StringArray>().unwrap();
        let sym = b.column(1).as_any().downcast_ref::<StringArray>().unwrap();
        let val = b.column(2).as_any().downcast_ref::<Int64Array>().unwrap();
        for i in 0..b.num_rows() {
            let row = (
                repo.value(i).to_string(),
                sym.value(i).to_string(),
                val.value(i),
            );
            if filter.matches(&row) {
                out.push(row);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// A predicate expressed both as a `ScanFilter` (pushed into the scan) and as a
/// closure (the in-memory oracle), so the two cannot drift.
struct Filter {
    scan: ScanFilter,
    pred: Box<dyn Fn(&(String, String, i64)) -> bool>,
}

impl Filter {
    fn matches(&self, row: &(String, String, i64)) -> bool {
        (self.pred)(row)
    }
}

fn filter_repo(repo: &'static str) -> Filter {
    Filter {
        scan: ScanFilter::eq("repo", repo),
        pred: Box::new(move |r| r.0 == repo),
    }
}

fn filter_symbol(sym: String) -> Filter {
    let s = sym.clone();
    Filter {
        scan: ScanFilter::eq("symbol", sym.as_str()),
        pred: Box::new(move |r| r.1 == s),
    }
}

fn filter_value_range(lo: i64, hi: i64) -> Filter {
    Filter {
        scan: ScanFilter::range("value", Some(lo), Some(hi)),
        pred: Box::new(move |r| r.2 >= lo && r.2 <= hi),
    }
}

/// Read `table` with `filter` pushed down (file pruning), and reduce to the rows
/// that ACTUALLY match the predicate — file-granular pruning may admit extra
/// non-matching rows from an opened file, but it must never DROP a matching row.
fn pruned_matching(rows: &[RecordBatch], filter: &Filter) -> Vec<(String, String, i64)> {
    let mut out = Vec::new();
    for b in rows {
        let repo = b.column(0).as_any().downcast_ref::<StringArray>().unwrap();
        let sym = b.column(1).as_any().downcast_ref::<StringArray>().unwrap();
        let val = b.column(2).as_any().downcast_ref::<Int64Array>().unwrap();
        for i in 0..b.num_rows() {
            let row = (
                repo.value(i).to_string(),
                sym.value(i).to_string(),
                val.value(i),
            );
            if filter.matches(&row) {
                out.push(row);
            }
        }
    }
    out.sort();
    out
}

/// The shared assertion body, run against a table written by whichever fast
/// path the caller used. Asserts, for several predicates: (1) the pruned plan
/// skipped > 0 files (effectiveness) and (2) the pruned read returns EXACTLY the
/// oracle's matching rows (safety — no matching row dropped by wrong bounds).
async fn assert_skips_and_correct(t: &Table, path_name: &str) -> Result<()> {
    assert_eq!(
        t.count().await?,
        (REPOS * ROWS) as u64,
        "{path_name}: all rows present"
    );

    let full = t.plan_stats(None).await?;
    assert_eq!(
        full.data_files, REPOS as u64,
        "{path_name}: one data file per repo"
    );
    assert_eq!(
        full.rows_planned,
        (REPOS * ROWS) as u64,
        "{path_name}: full plan reads all rows"
    );

    // Predicates spanning string (repo, symbol) and Int64 (value range) bounds.
    let cases: Vec<Filter> = vec![
        filter_repo("repo03"),
        filter_symbol(format!("SYM{:08}", (5 * ROWS) as i64 + 7)),
        // A value range entirely inside repo02's band [2000, 2999].
        filter_value_range((2 * ROWS) as i64 + 10, (2 * ROWS) as i64 + 20),
    ];

    for f in &cases {
        // (2) SAFETY — the load-bearing check: pruned read == in-memory oracle.
        let read = t.read_filtered(&f.scan, &[]).await?;
        let got = pruned_matching(&read, f);
        let want = oracle_matching(f)?;
        assert!(
            !want.is_empty(),
            "{path_name}: test predicate should match some rows"
        );
        assert_eq!(
            got, want,
            "{path_name}: pruned read dropped/changed matching rows for {:?} \
             (WRONG BOUNDS would cause this by skipping a file that holds matches)",
            f.scan
        );

        // (1) EFFECTIVENESS — pruning actually skipped files via the new bounds.
        let pruned = t.plan_stats(Some(&f.scan)).await?;
        let skipped = full.data_files - pruned.data_files;
        assert!(
            skipped > 0,
            "{path_name}: expected files SKIPPED for {:?}, but {} of {} planned \
             (the GAP: fast path emitted no column bounds)",
            f.scan,
            pruned.data_files,
            full.data_files
        );
    }
    Ok(())
}

/// One group (file) per repo, in repo order.
fn groups() -> Result<Vec<Vec<RecordBatch>>> {
    (0..REPOS).map(|r| Ok(vec![repo_batch(r, ROWS)?])).collect()
}

#[tokio::test]
async fn ingest_parallel_emits_prunable_bounds() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("syms", &schema()).await?.write_props(
        WriteProps::new(Compression::ZSTD(Default::default()))
            .bloom_columns(["symbol"])
            .row_group_size(128),
    );
    // FAST PATH under test: one file per repo, commit each file separately.
    t.ingest_parallel(groups()?, 1).await?;
    assert_skips_and_correct(&t, "ingest_parallel").await
}

#[tokio::test]
async fn ingest_pipelined_emits_prunable_bounds() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("syms", &schema()).await?.write_props(
        WriteProps::new(Compression::ZSTD(Default::default()))
            .bloom_columns(["symbol"])
            .row_group_size(128),
    );
    // FAST PATH under test: pipelined encode→write, one file per repo.
    t.ingest_pipelined(groups()?, 1, 4).await?;
    assert_skips_and_correct(&t, "ingest_pipelined").await
}
