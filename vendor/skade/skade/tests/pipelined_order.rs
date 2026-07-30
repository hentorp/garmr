//! Ordering guard for `ingest_pipelined` after it was re-homed onto the async
//! `gatling::io::run_ordered` engine (#20).
//!
//! `run_ordered` executes the FileIO write jobs out of order (fastest-first, up
//! to `channel_depth` in flight) but re-sequences their results into **submission
//! order**. The writer stamps each output file's sequence (`-{seq:08}.parquet`)
//! from the submission index, so file `k` MUST hold group `k` — regardless of
//! which write finished first. The old mpsc pipeline consumed writes in
//! *completion* order and stamped `seq` from its own recv counter, which could
//! scramble that mapping; this test proves the new engine does not.
//!
//! To make the assertion end-to-end and robust, each group `i` carries `i + 1`
//! rows all equal to `i` — so BOTH the value and the row count encode the
//! submission index. We ingest with a small `channel_depth` (so writes really do
//! overlap and can finish out of order), then read every data file back in
//! filename order and assert file `k` decodes to exactly `k + 1` rows all `== k`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Array, Int64Array, RecordBatch};
use skade::arrow_schema::{DataType, Field, Schema};
use skade::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

fn schema() -> Schema {
    Schema::new(vec![Field::new("k", DataType::Int64, false)])
}

/// Group `i`: one batch of `i + 1` rows, every value `== i`.
fn group(i: i64) -> Result<Vec<RecordBatch>> {
    let vals: Vec<i64> = std::iter::repeat(i).take((i + 1) as usize).collect();
    Ok(vec![RecordBatch::try_new(
        Arc::new(schema()),
        vec![Arc::new(Int64Array::from(vals))],
    )?])
}

/// Recursively collect every `*.parquet` file under `dir` (the warehouse's only
/// Parquet files are data files; iceberg metadata is JSON/Avro).
fn parquet_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            parquet_files(&p, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("parquet") {
            out.push(p);
        }
    }
}

/// Decode a single Parquet data file into a flat `Vec<i64>` of its `k` column.
fn read_k_column(path: &Path) -> Result<Vec<i64>> {
    let file = fs::File::open(path)?;
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)?.build()?;
    let mut vals = Vec::new();
    for batch in reader {
        let batch = batch?;
        let col = batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("k is Int64");
        for r in 0..col.len() {
            vals.push(col.value(r));
        }
    }
    Ok(vals)
}

#[tokio::test]
async fn ingest_pipelined_preserves_submission_order() -> Result<()> {
    const N: i64 = 48;

    let tmp = tempfile::tempdir()?;
    let lake = tmp.path().join("lake");
    let wh = skade::open(&lake).await?;
    let mut t = wh.create_table("ordered", &schema()).await?;

    let groups: Vec<Vec<RecordBatch>> = (0..N).map(group).collect::<Result<_>>()?;

    // Small channel_depth (3) with 48 varying-size groups → writes really overlap
    // and finish out of order, exercising run_ordered's re-sequencing. Commit in
    // batches of 8 so the commit loop walks the re-sequenced results.
    let stats = t.ingest_pipelined(groups, 8, 3).await?;

    // Row accounting: 1 + 2 + … + N.
    let expected_rows: u64 = (1..=N as u64).sum();
    assert_eq!(stats.rows, expected_rows, "row accounting");

    // End-to-end read-back completeness (exercises the scan path).
    let batches = t.read().await?;
    let read_rows: u64 = batches.iter().map(|b| b.num_rows() as u64).sum();
    assert_eq!(read_rows, expected_rows, "read-back row count");

    // ORDER PROOF: files are named `-{seq:08}.parquet` in submission order, so a
    // lexical sort of the filenames IS the submission order. File k must decode to
    // exactly k+1 rows, all == k.
    let mut files = Vec::new();
    parquet_files(&lake, &mut files);
    files.sort();
    assert_eq!(files.len(), N as usize, "one data file per group");

    for (k, path) in files.iter().enumerate() {
        let vals = read_k_column(path)?;
        assert_eq!(
            vals.len(),
            k + 1,
            "file {k} ({}) row count out of submission order",
            path.display()
        );
        assert!(
            vals.iter().all(|v| *v == k as i64),
            "file {k} ({}) holds a different group's rows: {vals:?}",
            path.display()
        );
    }

    Ok(())
}
