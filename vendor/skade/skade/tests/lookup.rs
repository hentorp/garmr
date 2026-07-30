//! `Table::lookup` — the embedded delta-join probe: resolve a row by its
//! equality-key column(s), pinned to a snapshot or the latest. No container: a
//! temp-dir Iceberg warehouse, an insert, then an "update" modelled as an
//! equality-delete + append, and assertions that the latest probe sees the new
//! value while a snapshot-pinned probe still sees the old one.
//!
//! This also exercises the merge-on-read full scan over an equality-delete table
//! (`equality_delete_full_scan_no_panic`) — the path that previously panicked in
//! the vendored engine's delete loader when the equality-delete parquet carried
//! no Iceberg field-ids. skade now stamps those ids in `delete_equality`.

use std::sync::Arc;

use anyhow::Result;
use skade::Scalar;
use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};

fn schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
    ])
}

fn row(id: i64, name: &str) -> Result<RecordBatch> {
    Ok(RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(Int64Array::from(vec![id])),
            Arc::new(StringArray::from(vec![name.to_string()])),
        ],
    )?)
}

/// The `id` equality-delete key batch (just the identity column).
fn key(id: i64) -> Result<RecordBatch> {
    let s = Schema::new(vec![Field::new("id", DataType::Int64, false)]);
    Ok(RecordBatch::try_new(
        Arc::new(s),
        vec![Arc::new(Int64Array::from(vec![id]))],
    )?)
}

fn name_of(batch: &RecordBatch) -> String {
    batch
        .column_by_name("name")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap()
        .value(0)
        .to_string()
}

#[tokio::test]
async fn lookup_returns_latest_and_pinned_snapshot_value() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("dim", &schema()).await?;

    // v1: insert (id=7, "alice").
    t.append(&[row(7, "alice")?]).await?;
    let snap_v1 = t.current_snapshot_id().expect("snapshot v1");

    // A second, unrelated key so the table isn't single-row (proves the probe
    // is a real filtered lookup, not "return the only row").
    t.append(&[row(9, "zed")?]).await?;

    // "Update" id=7 → "bob": delete the old identity, append the new row.
    t.delete_equality(&key(7)?, &["id"]).await?;
    t.append(&[row(7, "bob")?]).await?;
    let snap_latest = t.current_snapshot_id().expect("latest snapshot");
    assert_ne!(snap_v1, snap_latest);

    // Latest probe sees the NEW value.
    let latest = t
        .lookup(&[("id", Scalar::I64(7))], None)
        .await?
        .expect("id=7 exists at latest");
    assert_eq!(name_of(&latest), "bob", "latest lookup resolves the update");

    // Snapshot-pinned probe (v1, before the update) sees the OLD value.
    let pinned = t
        .lookup(&[("id", Scalar::I64(7))], Some(snap_v1))
        .await?
        .expect("id=7 exists at v1");
    assert_eq!(name_of(&pinned), "alice", "pinned lookup time-travels");

    // The untouched key resolves at latest.
    let other = t
        .lookup(&[("id", Scalar::I64(9))], None)
        .await?
        .expect("id=9 exists");
    assert_eq!(name_of(&other), "zed");

    // A miss resolves to None.
    assert!(
        t.lookup(&[("id", Scalar::I64(404))], None).await?.is_none(),
        "absent key → None"
    );
    Ok(())
}

/// A full merge-on-read scan over a table carrying an equality-delete file must
/// not panic — regression for the vendored delete-loader field-id bug. Before
/// the fix, `read()` (full MOR scan) over an equality-delete table panicked with
/// "Field id not found in metadata" because `delete_equality` wrote the delete
/// parquet without Iceberg field-ids.
#[tokio::test]
async fn equality_delete_full_scan_no_panic() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("dim", &schema()).await?;

    t.append(&[row(1, "a")?]).await?;
    t.append(&[row(2, "b")?]).await?;
    t.append(&[row(3, "c")?]).await?;

    // Remove id=2 via an equality delete → the table now has a delete file, so a
    // full read exercises the engine's merge-on-read delete loader.
    t.delete_equality(&key(2)?, &["id"]).await?;

    // Full MOR scan: must complete (not panic) and drop the deleted row.
    let batches = t.read().await?;
    let mut ids: Vec<i64> = Vec::new();
    for b in &batches {
        let c = b
            .column_by_name("id")
            .unwrap()
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        ids.extend((0..c.len()).map(|i| c.value(i)));
    }
    ids.sort();
    assert_eq!(ids, vec![1, 3], "equality delete applied, id=2 gone");
    Ok(())
}
