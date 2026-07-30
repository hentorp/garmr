//! Data-skipping: the scan planner prunes data files it doesn't need via the
//! Iceberg manifest's per-file column min/max bounds. `plan_stats` exposes how
//! many files / rows SURVIVE pruning, so a caller can prove the skip.
//!
//! LAW 1 — assert on real output: write N files (one repo per file, so each
//! file's `repo` min==max), then assert a `WHERE repo = X` plan opens exactly
//! one file and skips the other N-1. RED if pruning regresses.

use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};
use skade::{Compression, ScanFilter, WriteProps};

fn schema() -> Schema {
    Schema::new(vec![
        Field::new("repo", DataType::Utf8, false),
        Field::new("symbol", DataType::Utf8, false),
        Field::new("value", DataType::Int64, false),
    ])
}

/// One file's worth of rows, all for a single `repo` (so the file's `repo`
/// min==max==repo) and a disjoint, contiguous `symbol`/`value` range per repo.
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

#[tokio::test]
async fn manifest_min_max_pruning_skips_other_repos_files() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    const REPOS: usize = 8;
    const ROWS: usize = 1_000;

    // Bloom on symbol + small row groups (the read-side knobs), one file per repo.
    let mut t = wh.create_table("syms", &schema()).await?.write_props(
        WriteProps::new(Compression::ZSTD(Default::default()))
            .bloom_columns(["symbol"])
            .row_group_size(128),
    );
    // One `append` per repo → one data file per repo. This case uses `append`
    // (iceberg's DataFileWriter); the fast `ingest_parallel`/`ingest_pipelined`
    // paths now emit the SAME per-column min/max bounds via
    // `data_file_builder_from_parquet_bytes` (fix 7682d2b), so they prune too —
    // proven across column types in `data_skip_types.rs`.
    for r in 0..REPOS {
        t.append(&[repo_batch(r, ROWS)?]).await?;
    }
    assert_eq!(t.count().await?, (REPOS * ROWS) as u64);

    // Full plan: every file is planned.
    let full = t.plan_stats(None).await?;
    assert_eq!(full.data_files, REPOS as u64, "one data file per repo");
    assert_eq!(
        full.rows_planned,
        (REPOS * ROWS) as u64,
        "full plan reads all rows"
    );

    // Filtered plan on `repo`: min/max bounds skip every other repo's file.
    let pruned = t
        .plan_stats(Some(&ScanFilter::eq("repo", "repo03")))
        .await?;
    assert_eq!(
        pruned.data_files, 1,
        "repo=repo03 plans exactly its one file"
    );
    assert_eq!(
        pruned.rows_planned, ROWS as u64,
        "only that repo's rows planned"
    );
    assert_eq!(
        full.data_files - pruned.data_files,
        (REPOS - 1) as u64,
        "the other {} files are skipped",
        REPOS - 1
    );

    // Min/max pruning also works on `symbol` (disjoint contiguous range per file):
    // a point lookup in repo05's range plans only that file.
    let sym = format!("SYM{:08}", (5 * ROWS) as i64 + 7);
    let sym_plan = t
        .plan_stats(Some(&ScanFilter::eq("symbol", sym.as_str())))
        .await?;
    assert_eq!(
        sym_plan.data_files, 1,
        "symbol point-lookup prunes to one file via min/max"
    );

    // The filtered READ returns that repo's rows (file-granular pruning may admit
    // a superset, but here each file is one repo so it's exact).
    let rows = t
        .read_filtered(&ScanFilter::eq("repo", "repo03"), &[])
        .await?;
    let got: usize = rows.iter().map(|b| b.num_rows()).sum();
    assert_eq!(got, ROWS, "filtered read returns exactly repo03's rows");
    Ok(())
}
