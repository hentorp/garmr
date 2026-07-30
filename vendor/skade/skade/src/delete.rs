//! Identity (equality) deletes — the **CDC delete** write primitive.
//!
//! iceberg-rust 0.9.1's transaction layer only implements `fast_append` (it
//! rejects any non-`Data` content type, see `validate_added_data_files`), so it
//! cannot produce delete files through `Transaction`. This module writes an
//! Iceberg **equality-delete** snapshot at the metadata layer instead: a delete
//! parquet (the identity columns of the removed rows) + a `Deletes` manifest +
//! a manifest list that carries the table's existing manifests forward, then
//! commits it through the catalog as an `AddSnapshot` with `operation = delete`.
//!
//! This is the writer that lets the pure-Rust delta path (`read_delta`'s
//! `delete_files` / `read_equality_deletes`) see a row-level delete — and the
//! inject side of the inject-assert CDC test, with no Spark.

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_schema::Schema as ArrowSchema;
use iceberg::spec::{
    DataContentType, DataFileBuilder, DataFileFormat, FormatVersion, ManifestFile,
    ManifestListWriter, ManifestWriterBuilder, Operation, Snapshot, Struct, Summary,
};
use iceberg::{TableRequirement, TableUpdate};
use parquet::arrow::ArrowWriter;

use crate::error::{Result, SkadeError};
use crate::table::Table;

impl Table {
    /// Commit an **equality-delete** snapshot: every row in `keys` names rows to
    /// delete, matched on the `equality_columns` (the identity columns). `keys`
    /// must contain exactly the `equality_columns` (in any order). Returns once
    /// the new `Delete` snapshot is the table head.
    ///
    /// This is a true Iceberg delete file (CDC delete), readable back by
    /// [`crate::read_delta`] as a [`crate::EqualityDeleteFile`]. It is the only
    /// way to produce a delete with iceberg-rust 0.9.1 (whose `fast_append`
    /// refuses non-data content) short of running Spark.
    pub async fn delete_equality(
        &mut self,
        keys: &RecordBatch,
        equality_columns: &[&str],
    ) -> Result<()> {
        let table = self.inner();
        let metadata = table.metadata();
        if metadata.format_version() < FormatVersion::V2 {
            return Err(SkadeError::Other(
                "equality deletes require Iceberg format v2+".into(),
            ));
        }
        let schema = metadata.current_schema().clone();
        let equality_ids: Vec<i32> = equality_columns
            .iter()
            .map(|c| {
                schema
                    .field_id_by_name(c)
                    .ok_or_else(|| SkadeError::Other(format!("no field id for column {c}")))
            })
            .collect::<Result<_>>()?;

        let file_io = table.file_io().clone();
        let parent = metadata.current_snapshot();
        let parent_id = parent.map(|s| s.snapshot_id());
        let new_seq = metadata.last_sequence_number() + 1;
        // A snapshot id distinct from the parent's; derived from the wall clock
        // (ns) so successive deletes in one test get different ids.
        let snapshot_id: i64 = {
            let ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(1)
                .max(1);
            if Some(ns) == parent_id { ns + 1 } else { ns }
        };
        let location = metadata.location().to_string();

        // ── 1. the equality-delete parquet (just the identity columns) ────────
        //
        // Stamp each identity column with its Iceberg **field-id** metadata
        // (`PARQUET_FIELD_ID_META_KEY`). A raw `keys.schema()` from a caller's
        // plain Arrow batch carries no field ids, and a later merge-on-read scan
        // that loads this delete file calls `arrow_schema_to_schema` on the
        // parquet's own schema — which errors ("Field id not found in metadata")
        // when a column lacks an id, and that error surfaces as a panic deep in
        // the engine's equality-delete loader. Writing the ids here (matched by
        // column name to the table's equality field-ids) is both the correct
        // Iceberg on-disk form and the fix for that latent full-scan panic.
        let delete_path = format!("{location}/data/eqdel-{snapshot_id}.parquet");
        let id_by_name: HashMap<&str, i32> = equality_columns
            .iter()
            .copied()
            .zip(equality_ids.iter().copied())
            .collect();
        let keyed_fields: Vec<arrow_schema::Field> = keys
            .schema()
            .fields()
            .iter()
            .map(|f| {
                let mut md = f.metadata().clone();
                if let Some(fid) = id_by_name.get(f.name().as_str()) {
                    md.insert(
                        parquet::arrow::PARQUET_FIELD_ID_META_KEY.to_string(),
                        fid.to_string(),
                    );
                }
                f.as_ref().clone().with_metadata(md)
            })
            .collect();
        let arrow_schema = Arc::new(ArrowSchema::new(keyed_fields));
        let keys = RecordBatch::try_new(arrow_schema.clone(), keys.columns().to_vec())
            .map_err(|e| SkadeError::Other(format!("stamp delete field-ids: {e}")))?;
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = ArrowWriter::try_new(&mut buf, arrow_schema, None)
                .map_err(|e| SkadeError::Other(format!("delete parquet writer: {e}")))?;
            w.write(&keys)
                .map_err(|e| SkadeError::Other(format!("write delete parquet: {e}")))?;
            w.close()
                .map_err(|e| SkadeError::Other(format!("close delete parquet: {e}")))?;
        }
        let delete_len = buf.len() as u64;
        let out = file_io.new_output(&delete_path)?;
        out.write(buf.into())
            .await
            .map_err(|e| SkadeError::Other(format!("persist delete parquet: {e}")))?;

        // ── 2. an equality-delete DataFile + a Deletes manifest ───────────────
        let delete_file = DataFileBuilder::default()
            .content(DataContentType::EqualityDeletes)
            .file_format(DataFileFormat::Parquet)
            .file_path(delete_path.clone())
            .file_size_in_bytes(delete_len)
            .record_count(keys.num_rows() as u64)
            .partition(Struct::empty())
            .partition_spec_id(metadata.default_partition_spec_id())
            .equality_ids(Some(equality_ids.clone()))
            .build()
            .map_err(|e| SkadeError::Other(format!("build delete data file: {e}")))?;

        let manifest_path = format!("{location}/metadata/eqdel-m-{snapshot_id}.avro");
        let mut mw = ManifestWriterBuilder::new(
            file_io.new_output(&manifest_path)?,
            Some(snapshot_id),
            None,
            schema.clone(),
            metadata.default_partition_spec().as_ref().clone(),
        )
        .build_v2_deletes();
        // An *added* delete file (status Added) at the new sequence number.
        mw.add_file(delete_file, new_seq)?;
        let delete_manifest: ManifestFile = mw.write_manifest_file().await?;

        // ── 3. manifest list: existing manifests carried forward + the new one ─
        let list_path = format!("{location}/metadata/snap-{snapshot_id}.avro");
        let mut existing: Vec<ManifestFile> = Vec::new();
        if let Some(p) = parent {
            existing = p
                .load_manifest_list(&file_io, metadata)
                .await?
                .entries()
                .to_vec();
        }
        let mut lw = ManifestListWriter::v2(
            file_io.new_output(&list_path)?,
            snapshot_id,
            parent_id,
            new_seq,
        );
        lw.add_manifests(existing.into_iter())?;
        lw.add_manifests(std::iter::once(delete_manifest))?;
        lw.close().await?;

        // ── 4. the Delete snapshot + commit through the catalog ───────────────
        let snapshot = Snapshot::builder()
            .with_snapshot_id(snapshot_id)
            .with_parent_snapshot_id(parent_id)
            .with_sequence_number(new_seq)
            .with_timestamp_ms(now_ms())
            .with_manifest_list(list_path)
            // Format v3 requires a row range; a delete adds zero data rows, so
            // the range is [next_row_id, +0).
            .with_row_range(metadata.next_row_id(), 0)
            .with_schema_id(schema.schema_id())
            .with_summary(Summary {
                operation: Operation::Delete,
                additional_properties: HashMap::from([(
                    "deleted-records".into(),
                    keys.num_rows().to_string(),
                )]),
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
                reference: iceberg::spec::SnapshotReference {
                    snapshot_id,
                    retention: iceberg::spec::SnapshotRetention::Branch {
                        min_snapshots_to_keep: None,
                        max_snapshot_age_ms: None,
                        max_ref_age_ms: None,
                    },
                },
            },
        ];

        let updated = self
            .catalog()
            .commit_table(ident, requirements, updates)
            .await?;
        self.set_inner(updated);
        // Lineage (feature `lineage`): one `Delete` fact on the new snapshot.
        #[cfg(feature = "lineage")]
        self.emit_lineage(
            crate::lineage::Operation::Delete,
            self.current_snapshot_id(),
        )
        .await;
        // MOR write marker: one equality-delete snapshot committed.
        crate::functional_status(
            "skade/delete_equality",
            "mor_equality_delete_commit",
            true,
            &format!(
                "{} row(s) on [{}]",
                keys.num_rows(),
                equality_columns.join(",")
            ),
        );
        Ok(())
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
