//! Incremental read (`Table::read_delta`) — the manifest-level snapshot diff.
//! No container: a temp-dir Iceberg warehouse, several `fast_append` snapshots,
//! and assertions that a delta reads ONLY the rows appended in its window.

use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};

fn schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
    ])
}

fn batch(ids: &[i64]) -> Result<RecordBatch> {
    let names: Vec<String> = ids.iter().map(|i| format!("r{i}")).collect();
    Ok(RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(Int64Array::from(ids.to_vec())),
            Arc::new(StringArray::from(names)),
        ],
    )?)
}

fn ids_of(batches: &[RecordBatch]) -> Vec<i64> {
    let mut out = Vec::new();
    for b in batches {
        let col = b
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("Int64 id column");
        out.extend((0..col.len()).map(|i| col.value(i)));
    }
    out.sort();
    out
}

#[tokio::test]
async fn read_delta_reads_only_appended_rows() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    // Snapshot A: 3 rows.
    t.append(&[batch(&[1, 2, 3])?]).await?;
    let snap_a = t.current_snapshot_id().expect("snapshot A");

    // Snapshot B: 2 MORE rows (a separate fast_append commit).
    t.append(&[batch(&[4, 5])?]).await?;
    let snap_b = t.current_snapshot_id().expect("snapshot B");
    assert_ne!(snap_a, snap_b);

    // From the beginning to A → all 3 rows.
    let (b0, plan) = t.read_delta(None, snap_a).await?;
    assert_eq!(ids_of(&b0), vec![1, 2, 3]);
    assert!(!plan.needs_full_reload);
    assert_eq!(plan.snapshots, vec![snap_a]);
    assert_eq!(plan.added_files.len(), 1);

    // THE DELTA A→B → ONLY {4,5}, not the full 5 rows.
    let (delta, plan) = t.read_delta(Some(snap_a), snap_b).await?;
    assert_eq!(ids_of(&delta), vec![4, 5], "delta = B's appended rows only");
    assert_eq!(plan.snapshots, vec![snap_b]);
    assert_eq!(plan.added_files.len(), 1);

    // Caught-up cursor → empty.
    let (none, plan) = t.read_delta(Some(snap_b), snap_b).await?;
    assert!(none.is_empty());
    assert!(plan.snapshots.is_empty() && plan.added_files.is_empty());
    Ok(())
}

#[tokio::test]
async fn read_delta_spans_multiple_snapshots() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    t.append(&[batch(&[1, 2])?]).await?;
    let a = t.current_snapshot_id().unwrap();
    t.append(&[batch(&[3, 4])?]).await?;
    let b = t.current_snapshot_id().unwrap();
    t.append(&[batch(&[5, 6])?]).await?;
    let c = t.current_snapshot_id().unwrap();

    // A → C spans both new snapshots B and C: rows {3,4,5,6} only (not A's).
    let (delta, plan) = t.read_delta(Some(a), c).await?;
    assert_eq!(ids_of(&delta), vec![3, 4, 5, 6]);
    assert_eq!(plan.snapshots, vec![b, c], "oldest-first lineage");
    assert_eq!(plan.added_files.len(), 2);
    Ok(())
}

/// CDC delete: a `Delete` snapshot adds an **equality-delete** file; the delta
/// must surface it as a `delete_file` (with the equality columns), and
/// `read_equality_deletes` must read back the deleted identity (id=2).
#[tokio::test]
async fn read_delta_surfaces_equality_deletes() -> Result<()> {
    use skade::arrow_array::Int64Array;
    use skade::arrow_schema::{DataType, Field, Schema as ArrowSchema};

    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    // Snapshot A: 3 rows {1,2,3}.
    t.append(&[batch(&[1, 2, 3])?]).await?;
    let snap_a = t.current_snapshot_id().expect("snapshot A");

    // Snapshot B: a real Iceberg equality-delete removing id=2.
    let key = RecordBatch::try_new(
        Arc::new(ArrowSchema::new(vec![Field::new(
            "id",
            DataType::Int64,
            false,
        )])),
        vec![Arc::new(Int64Array::from(vec![2i64]))],
    )?;
    t.delete_equality(&key, &["id"]).await?;
    let snap_b = t.current_snapshot_id().expect("snapshot B");
    assert_ne!(snap_a, snap_b, "delete made a new snapshot");

    // THE DELTA A→B: no new *inserts*, one equality-delete file, NOT a reload.
    let (inserts, plan) = t.read_delta(Some(snap_a), snap_b).await?;
    assert!(inserts.is_empty(), "a delete adds no insert rows");
    assert!(
        !plan.needs_full_reload,
        "an equality-delete delta is expressible (no full reload)",
    );
    assert_eq!(plan.snapshots, vec![snap_b]);
    assert_eq!(
        plan.delete_files.len(),
        1,
        "exactly one equality-delete file"
    );

    // The delete names the `id` column as its equality key.
    let id_field = t.arrow_schema()?; // table schema carries iceberg field ids
    let _ = id_field;
    let dels = t.read_equality_deletes(&plan).await?;
    assert_eq!(dels.len(), 1);
    let (eq_ids, batches) = &dels[0];
    assert!(!eq_ids.is_empty(), "equality_ids resolved");
    assert_eq!(ids_of(batches), vec![2], "the deleted identity is id=2");
    Ok(())
}
