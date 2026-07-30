//! CDC changelog encoder (`Table::read_changelog` / `skade::read_changelog`) —
//! the re-tagging layer over `read_delta` + `read_equality_deletes`. A temp-dir
//! Iceberg warehouse, real `fast_append` + equality-delete snapshots, and
//! assertions that inserts/deletes/updates carry the right `_change_type` tags
//! and collapse to net change. No Spark, no container.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Array, Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};
use skade::change_type;
use skade::iceberg::spec::{
    FormatVersion, ManifestFile, ManifestListWriter, NestedField, Operation, PrimitiveType,
    Schema as IceSchema, Snapshot, SnapshotReference, SnapshotRetention, Summary, Type,
};
use skade::iceberg::table::Table as IceTable;
use skade::iceberg::{Catalog, TableCreation, TableRequirement, TableUpdate};

mod common;
use common::emit_for;

fn schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
    ])
}

fn batch(ids: &[i64], tag: &str) -> Result<RecordBatch> {
    let names: Vec<String> = ids.iter().map(|i| format!("{tag}{i}")).collect();
    Ok(RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(Int64Array::from(ids.to_vec())),
            Arc::new(StringArray::from(names)),
        ],
    )?)
}

/// All `(id, _change_type)` pairs across a changelog, `id = None` for a widened
/// DELETE row that carried only some other identity column.
fn id_tags(cl: &skade::ChangelogBatch) -> Vec<(Option<i64>, String)> {
    let mut out = Vec::new();
    for b in &cl.rows {
        let ids = b
            .column_by_name("id")
            .unwrap()
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("id is Int64");
        let tags = b
            .column_by_name(change_type::COLUMN)
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("_change_type is Utf8");
        for i in 0..b.num_rows() {
            let id = if ids.is_null(i) {
                None
            } else {
                Some(ids.value(i))
            };
            out.push((id, tags.value(i).to_string()));
        }
    }
    out
}

fn cell(b: &RecordBatch, col: &str, i: usize) -> Option<String> {
    let a = b.column_by_name(col).unwrap();
    if a.is_null(i) {
        None
    } else {
        Some(skade::arrow_cast::display::array_value_to_string(a, i).unwrap())
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The op strings + column name are byte-for-byte knut-bifrost's vocabulary.
#[test]
fn changelog_column_name_and_verbs_match_bifrost() {
    assert_eq!(change_type::INSERT, "INSERT");
    assert_eq!(change_type::UPDATE_BEFORE, "UPDATE_BEFORE");
    assert_eq!(change_type::UPDATE_AFTER, "UPDATE_AFTER");
    assert_eq!(change_type::DELETE, "DELETE");
    assert_eq!(change_type::COLUMN, "_change_type");
    emit_for(
        "skade/read_changelog",
        "changelog_column_name_and_verbs_match_bifrost",
        true,
        "INSERT/UPDATE_BEFORE/UPDATE_AFTER/DELETE/_change_type verbatim",
    );
}

/// A window with both appended rows and an equality delete → INSERT-tagged
/// insert rows ∪ a DELETE-tagged, schema-widened deleted identity.
#[tokio::test]
async fn read_changelog_tags_inserts_and_deletes() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    t.append(&[batch(&[1, 2, 3], "r")?]).await?;
    let a = t.current_snapshot_id().unwrap();
    t.append(&[batch(&[4, 5], "r")?]).await?;
    // A real Iceberg equality delete of id=2.
    let key = RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)])),
        vec![Arc::new(Int64Array::from(vec![2i64]))],
    )?;
    t.delete_equality(&key, &["id"]).await?;
    let c = t.current_snapshot_id().unwrap();

    let cl = t.read_changelog(Some(a), c).await?;
    assert!(!cl.plan.needs_full_reload);
    // Schema is the table schema + the sentinel column.
    assert!(cl.schema().column_with_name("_change_type").is_some());
    assert!(cl.schema().column_with_name("id").is_some());

    let mut got = id_tags(&cl);
    got.sort();
    assert_eq!(
        got,
        vec![
            (Some(2), "DELETE".to_string()),
            (Some(4), "INSERT".to_string()),
            (Some(5), "INSERT".to_string()),
        ],
        "two inserts tagged INSERT, one deleted identity tagged DELETE"
    );
    emit_for(
        "skade/read_changelog",
        "read_changelog_tags_inserts_and_deletes",
        got.len() == 3,
        "INSERT {4,5} + DELETE {2}",
    );
    Ok(())
}

/// A window whose head is an **overwrite** snapshot can't be expressed as an
/// additive delta → `read_changelog` falls back to re-reading the whole `to`
/// snapshot as a pure INSERT stream (`needs_full_reload`).
#[tokio::test]
async fn read_changelog_full_reload_on_overwrite() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    t.append(&[batch(&[1, 2, 3], "r")?]).await?;
    let a = t.current_snapshot_id().unwrap();

    // Forge a no-op OVERWRITE snapshot (carry the parent manifests forward with
    // `operation = overwrite`) so the additive delta path must bail.
    let over = commit_overwrite(&wh, t.inner()).await?;
    t.refresh().await?;
    assert_eq!(t.current_snapshot_id(), Some(over));

    let cl = t.read_changelog(Some(a), over).await?;
    assert!(cl.plan.needs_full_reload, "overwrite forces a full reload");
    // The full `to` snapshot re-read as INSERTs: all 3 rows, all INSERT.
    let got = id_tags(&cl);
    assert_eq!(got.len(), 3, "full snapshot re-read as changelog");
    assert!(
        got.iter().all(|(_, t)| t == "INSERT"),
        "full-reload rows are all INSERT"
    );
    let mut ids: Vec<i64> = got.iter().filter_map(|(i, _)| *i).collect();
    ids.sort();
    assert_eq!(ids, vec![1, 2, 3]);
    emit_for(
        "skade/read_changelog",
        "read_changelog_full_reload_on_overwrite",
        cl.plan.needs_full_reload && got.len() == 3,
        "overwrite → full reload as 3 INSERTs",
    );
    Ok(())
}

/// Net-change collapse on a LOG table: a row inserted then deleted in the same
/// window cancels to nothing.
#[tokio::test]
async fn changelog_collapses_insert_then_delete_to_nothing() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    t.append(&[batch(&[1, 2, 3], "r")?]).await?;
    let a = t.current_snapshot_id().unwrap();
    // Insert id=7, then delete id=7 — within one window.
    t.append(&[batch(&[7], "r")?]).await?;
    let key = RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)])),
        vec![Arc::new(Int64Array::from(vec![7i64]))],
    )?;
    t.delete_equality(&key, &["id"]).await?;
    let c = t.current_snapshot_id().unwrap();

    // Raw: one INSERT(7) + one DELETE(7).
    let raw = t.read_changelog(Some(a), c).await?;
    assert_eq!(raw.num_rows(), 2, "raw window: an INSERT and a DELETE");

    // Collapsed: the pair cancels → nothing.
    let collapsed = raw.collapsed()?;
    assert_eq!(
        collapsed.num_rows(),
        0,
        "insert-then-delete of id=7 nets to zero rows"
    );
    emit_for(
        "skade/read_changelog",
        "changelog_collapses_insert_then_delete_to_nothing",
        collapsed.num_rows() == 0,
        "log-table collapse: +I(7) then -D(7) = nothing",
    );
    Ok(())
}

/// Net-change collapse on a PRIMARY-KEY table: a delete of a key + an insert of
/// the same key is an update → `UPDATE_BEFORE` (old identity) + `UPDATE_AFTER`
/// (new row).
#[tokio::test]
async fn pk_table_changelog_emits_update_before_after() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    // A PK table: `id` is the Iceberg identifier field (row identity).
    let ice_schema = IceSchema::builder()
        .with_schema_id(0)
        .with_identifier_field_ids([1])
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
            NestedField::optional(2, "name", Type::Primitive(PrimitiveType::String)).into(),
        ])
        .build()?;
    let ident = wh.table_ident("kv")?;
    let creation = TableCreation::builder()
        .name(ident.name().to_string())
        .schema(ice_schema)
        .format_version(FormatVersion::V3)
        .build();
    wh.catalog()
        .create_table(ident.namespace(), creation)
        .await?;
    let mut t = wh.table("kv").await?;
    assert!(matches!(
        skade::TableKind::of(t.inner()),
        skade::TableKind::PrimaryKey(_)
    ));

    // key 1 = "a".
    t.append(&[batch(&[1], "a")?]).await?;
    let a = t.current_snapshot_id().unwrap();
    // Upsert key 1 → "b": delete the old identity, then insert the new row.
    let key = RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)])),
        vec![Arc::new(Int64Array::from(vec![1i64]))],
    )?;
    t.delete_equality(&key, &["id"]).await?;
    t.append(&[batch(&[1], "b")?]).await?;
    let c = t.current_snapshot_id().unwrap();

    let cl = t.read_changelog(Some(a), c).await?.collapsed()?;
    assert_eq!(cl.num_rows(), 2, "an update is a before/after pair");

    // Find the UPDATE_BEFORE and UPDATE_AFTER rows.
    let mut before = None;
    let mut after = None;
    for b in &cl.rows {
        for i in 0..b.num_rows() {
            match cell(b, "_change_type", i).as_deref() {
                Some("UPDATE_BEFORE") => before = Some((cell(b, "id", i), cell(b, "name", i))),
                Some("UPDATE_AFTER") => after = Some((cell(b, "id", i), cell(b, "name", i))),
                other => panic!("unexpected tag {other:?} on a PK update"),
            }
        }
    }
    let before = before.expect("an UPDATE_BEFORE row");
    let after = after.expect("an UPDATE_AFTER row");
    assert_eq!(before.0.as_deref(), Some("1"), "before-image keeps the key");
    assert_eq!(after.0.as_deref(), Some("1"), "after-image keeps the key");
    assert_eq!(
        after.1.as_deref(),
        Some("b1"),
        "after-image carries the new value"
    );

    emit_for(
        "skade/read_changelog",
        "pk_table_changelog_emits_update_before_after",
        true,
        "PK upsert → -U(1) + +U(1,'b1')",
    );
    Ok(())
}

/// Column pruning keeps only the requested columns (plus the `_change_type`
/// sentinel), reading a subset of the changelog width.
#[tokio::test]
async fn changelog_column_pruning_reads_subset() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.table_or_create("events", &schema()).await?;

    t.append(&[batch(&[1, 2], "r")?]).await?;
    let a = t.current_snapshot_id().unwrap();
    t.append(&[batch(&[3, 4], "r")?]).await?;
    let c = t.current_snapshot_id().unwrap();

    let pruned = t.read_changelog(Some(a), c).await?.project_columns(&["id"]);
    let pruned = pruned?;
    // Only `id` + `_change_type`; `name` dropped.
    assert!(pruned.schema().column_with_name("id").is_some());
    assert!(pruned.schema().column_with_name("_change_type").is_some());
    assert!(
        pruned.schema().column_with_name("name").is_none(),
        "pruned away `name`"
    );
    assert_eq!(pruned.schema().fields().len(), 2, "id + _change_type only");
    assert_eq!(pruned.num_rows(), 2, "both appended rows retained");
    emit_for(
        "skade/read_changelog",
        "changelog_column_pruning_reads_subset",
        pruned.schema().fields().len() == 2,
        "projected {id,_change_type}",
    );
    Ok(())
}

/// Commit a no-op OVERWRITE snapshot: carry the parent's manifests forward with
/// `operation = overwrite`, so the additive delta path must fall back to a full
/// reload. Mirrors the metadata-layer commit `delete_equality` performs.
async fn commit_overwrite(wh: &skade::Warehouse, table: &IceTable) -> Result<i64> {
    let metadata = table.metadata();
    let file_io = table.file_io().clone();
    let parent = metadata.current_snapshot().cloned();
    let parent_id = parent.as_ref().map(|s| s.snapshot_id());
    let new_seq = metadata.last_sequence_number() + 1;
    let snapshot_id = {
        let ns = now_ms().max(1) * 1_000_000 + 7;
        if Some(ns) == parent_id { ns + 1 } else { ns }
    };
    let location = metadata.location().to_string();

    let existing: Vec<ManifestFile> = if let Some(p) = &parent {
        p.load_manifest_list(&file_io, metadata)
            .await?
            .entries()
            .to_vec()
    } else {
        Vec::new()
    };
    let list_path = format!("{location}/metadata/ovr-{snapshot_id}.avro");
    let mut lw = ManifestListWriter::v2(
        file_io.new_output(&list_path)?,
        snapshot_id,
        parent_id,
        new_seq,
    );
    lw.add_manifests(existing.into_iter())?;
    lw.close().await?;

    let snapshot = Snapshot::builder()
        .with_snapshot_id(snapshot_id)
        .with_parent_snapshot_id(parent_id)
        .with_sequence_number(new_seq)
        .with_timestamp_ms(now_ms())
        .with_manifest_list(list_path)
        .with_row_range(metadata.next_row_id(), 0)
        .with_schema_id(metadata.current_schema().schema_id())
        .with_summary(Summary {
            operation: Operation::Overwrite,
            additional_properties: HashMap::new(),
        })
        .build();

    let ident = table.identifier().clone();
    let requirements = vec![TableRequirement::RefSnapshotIdMatch {
        r#ref: "main".into(),
        snapshot_id: parent_id,
    }];
    let updates = vec![
        TableUpdate::AddSnapshot { snapshot },
        TableUpdate::SetSnapshotRef {
            ref_name: "main".into(),
            reference: SnapshotReference {
                snapshot_id,
                retention: SnapshotRetention::Branch {
                    min_snapshots_to_keep: None,
                    max_snapshot_age_ms: None,
                    max_ref_age_ms: None,
                },
            },
        },
    ];
    wh.catalog()
        .commit_table(ident, requirements, updates)
        .await?;
    Ok(snapshot_id)
}
