//! GAP 3 — additive schema evolution (`Table::ensure_schema`).
//!
//! Mirrors nornir's `ensure_table_schema` (warehouse/iceberg.rs): create a
//! table with a narrow schema, append rows, evolve the schema forward by adding
//! a column, append more rows against the wider schema, then read back and
//! assert old rows carry `null` for the new column while new rows carry the
//! value. Also asserts the call is idempotent (a second `ensure_schema` with the
//! same desired schema is a no-op — no new schema id).

use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Array, Float64Array, Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};

/// The original (narrow) schema the table is first created with: [id, name].
fn narrow_schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
    ])
}

/// The evolved (wide) schema the writer later produces: [id, name, score].
fn wide_schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("score", DataType::Float64, true), // the added column
    ])
}

fn narrow_batch(ids: Vec<i64>) -> Result<RecordBatch> {
    let names: Vec<String> = ids.iter().map(|i| format!("old-{i}")).collect();
    Ok(RecordBatch::try_new(
        Arc::new(narrow_schema()),
        vec![
            Arc::new(Int64Array::from(ids)),
            Arc::new(StringArray::from(names)),
        ],
    )?)
}

fn wide_batch(ids: Vec<i64>, scores: Vec<f64>) -> Result<RecordBatch> {
    let names: Vec<String> = ids.iter().map(|i| format!("new-{i}")).collect();
    Ok(RecordBatch::try_new(
        Arc::new(wide_schema()),
        vec![
            Arc::new(Int64Array::from(ids)),
            Arc::new(StringArray::from(names)),
            Arc::new(Float64Array::from(scores)),
        ],
    )?)
}

/// Concatenate every read batch's `(id, score)` so we can assert per-id that the
/// new `score` column is null for the rows written before the evolution and
/// present for the rows written after.
fn collect_id_score(batches: &[RecordBatch]) -> Vec<(i64, Option<f64>)> {
    let mut out = Vec::new();
    for b in batches {
        let id_idx = b.schema().index_of("id").expect("id column");
        let score_idx = b.schema().index_of("score").expect("score column");
        let ids = b
            .column(id_idx)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("Int64 id");
        let scores = b
            .column(score_idx)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("Float64 score");
        for i in 0..b.num_rows() {
            let s = if scores.is_null(i) {
                None
            } else {
                Some(scores.value(i))
            };
            out.push((ids.value(i), s));
        }
    }
    out
}

#[tokio::test]
async fn ensure_schema_additive_evolution_and_idempotent() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    // 1) Create with the NARROW schema, append two "old" rows (no `score`).
    let mut t = wh.create_table("rows", &narrow_schema()).await?;
    t.append(&[narrow_batch(vec![1, 2])?]).await?;

    // The freshly-created table has exactly [id, name].
    let before: Vec<String> = t
        .arrow_schema()?
        .fields()
        .iter()
        .map(|f| f.name().to_string())
        .collect();
    assert_eq!(before, vec!["id", "name"]);
    let schema_id_before = t.inner().metadata().current_schema().schema_id();
    // Field ids the two existing columns were created with (must be preserved).
    let ids_before: Vec<i32> = t
        .inner()
        .metadata()
        .current_schema()
        .as_struct()
        .fields()
        .iter()
        .map(|f| f.id)
        .collect();

    // 2) Evolve forward to the WIDE schema — adds `score` as an optional column.
    let wide = wide_schema();
    t.ensure_schema(&wide).await?;

    // The evolved table now carries all three columns, in order.
    let after: Vec<String> = t
        .arrow_schema()?
        .fields()
        .iter()
        .map(|f| f.name().to_string())
        .collect();
    assert_eq!(after, vec!["id", "name", "score"]);

    // Field-id stability: the two original columns kept their exact ids, and the
    // new column got a fresh id above the old highest.
    let struct_after = t.inner().metadata().current_schema().as_struct().clone();
    let ids_after: Vec<i32> = struct_after.fields().iter().map(|f| f.id).collect();
    assert_eq!(
        &ids_after[..2],
        &ids_before[..],
        "existing field ids preserved"
    );
    assert!(
        ids_after[2] > *ids_before.iter().max().unwrap(),
        "new column id ({}) must exceed the old highest field id",
        ids_after[2]
    );
    // The new column is OPTIONAL (existing rows have no value for it).
    let score_field = struct_after
        .fields()
        .iter()
        .find(|f| f.name == "score")
        .expect("score field");
    assert!(!score_field.required, "added column must be optional");
    // A new schema id was registered.
    let schema_id_after = t.inner().metadata().current_schema().schema_id();
    assert!(
        schema_id_after > schema_id_before,
        "evolution must register a new schema id"
    );

    // 3) Append "new" rows that DO carry `score`.
    t.append(&[wide_batch(vec![10, 11], vec![1.5, 2.5])?])
        .await?;

    // 4) Read back the whole table: old rows → null score, new rows → value.
    let rows = collect_id_score(&t.read().await?);
    let mut by_id: std::collections::HashMap<i64, Option<f64>> = rows.into_iter().collect();
    assert_eq!(by_id.len(), 4, "all four rows present");
    assert_eq!(
        by_id.remove(&1).unwrap(),
        None,
        "old row 1 reads null score"
    );
    assert_eq!(
        by_id.remove(&2).unwrap(),
        None,
        "old row 2 reads null score"
    );
    assert_eq!(
        by_id.remove(&10).unwrap(),
        Some(1.5),
        "new row 10 carries score"
    );
    assert_eq!(
        by_id.remove(&11).unwrap(),
        Some(2.5),
        "new row 11 carries score"
    );

    // 5) Idempotency: ensuring the SAME wide schema again is a no-op — no new
    // schema id, no change to the column set.
    let schema_id_before_noop = t.inner().metadata().current_schema().schema_id();
    t.ensure_schema(&wide).await?;
    let schema_id_after_noop = t.inner().metadata().current_schema().schema_id();
    assert_eq!(
        schema_id_before_noop, schema_id_after_noop,
        "second ensure_schema with same desired schema must be a no-op"
    );
    let cols_noop: Vec<String> = t
        .arrow_schema()?
        .fields()
        .iter()
        .map(|f| f.name().to_string())
        .collect();
    assert_eq!(cols_noop, vec!["id", "name", "score"]);

    // And the data is unchanged after the no-op evolution.
    let rows2 = collect_id_score(&t.read().await?);
    assert_eq!(rows2.len(), 4, "no-op evolution must not change the data");

    Ok(())
}
