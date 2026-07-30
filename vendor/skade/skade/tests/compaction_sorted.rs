//! `Warehouse::compact_table_sorted` — the additive index-column (clustering)
//! rebuild. LAW 1: assert on real read-back output. Rows are appended in
//! arrival (unsorted) order across several files; after a sorted compaction the
//! table is clustered ascending by the index column, and no row is lost or
//! altered (same id multiset). RED if the clustering or the losslessness breaks.

use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};

fn schema() -> Schema {
    Schema::new(vec![
        Field::new("ts", DataType::Int64, false), // the index / clustering column
        Field::new("id", DataType::Int64, false),
        Field::new("payload", DataType::Utf8, false),
    ])
}

/// One file's worth of rows with the given `ts` values (deliberately not sorted).
fn batch(ts: &[i64]) -> Result<RecordBatch> {
    let ids: Vec<i64> = ts.iter().map(|t| t * 10).collect();
    let pay: Vec<String> = ts.iter().map(|t| format!("row-{t}")).collect();
    Ok(RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(Int64Array::from(ts.to_vec())),
            Arc::new(Int64Array::from(ids)),
            Arc::new(StringArray::from(pay)),
        ],
    )?)
}

async fn read_col(wh: &skade::Warehouse, name: &str, col: &str) -> Result<Vec<i64>> {
    let t = wh.table(name).await?; // fresh handle (post-swap the old one is retired)
    let mut out = Vec::new();
    for b in t.read().await? {
        let idx = b.schema().index_of(col)?;
        let a = b.column(idx).as_any().downcast_ref::<Int64Array>().unwrap();
        out.extend(a.values().iter().copied());
    }
    Ok(out)
}

#[tokio::test]
async fn compact_sorted_clusters_by_index_col_and_preserves_rows() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("events", &schema()).await?;

    // Three appends (three data files), each with interleaved ts — so arrival
    // order is NOT ts order and the per-file [min,max] ranges overlap.
    t.append(&[batch(&[50, 10, 90, 30])?]).await?;
    t.append(&[batch(&[70, 20, 100, 40])?]).await?;
    t.append(&[batch(&[60, 5, 80, 15])?]).await?;

    // Precondition: the table is unsorted on ts.
    let before_ts = read_col(&wh, "events", "ts").await?;
    assert_eq!(before_ts.len(), 12);
    assert!(
        before_ts.windows(2).any(|w| w[0] > w[1]),
        "precondition: arrival order must be unsorted, got {before_ts:?}"
    );
    let mut before_ids = read_col(&wh, "events", "id").await?;
    before_ids.sort_unstable();

    // Sorted compaction by the index column.
    let rep = wh.compact_table_sorted("events", "ts", None).await?;
    assert_eq!(rep.rows, 12, "all rows carried");
    assert_eq!(rep.rows_pruned, 0, "no prune hook -> nothing dropped");

    // Postcondition 1 — clustered ascending by ts (single output file -> the
    // read is in physical order).
    let after_ts = read_col(&wh, "events", "ts").await?;
    assert!(
        after_ts.windows(2).all(|w| w[0] <= w[1]),
        "after compact_table_sorted, ts must be non-decreasing, got {after_ts:?}"
    );
    assert_eq!(
        after_ts,
        vec![5, 10, 15, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    );

    // Postcondition 2 — lossless: same id multiset, same count.
    let mut after_ids = read_col(&wh, "events", "id").await?;
    after_ids.sort_unstable();
    assert_eq!(before_ids, after_ids, "row content preserved (id multiset)");

    Ok(())
}

#[tokio::test]
async fn compact_sorted_rejects_unsupported_index_type() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("events", &schema()).await?;
    t.append(&[batch(&[1, 2, 3])?]).await?;
    // `payload` is Utf8 — not a supported clustering key.
    let err = wh.compact_table_sorted("events", "payload", None).await;
    assert!(
        err.is_err(),
        "clustering on a Utf8 column must error, not silently misorder"
    );
    Ok(())
}
