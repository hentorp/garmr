//! [`Table`] — a catalog-bound Iceberg table handle with ergonomic append,
//! read-to-Arrow, and per-table SQL.

use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_schema::{Schema as ArrowSchema, SchemaRef as ArrowSchemaRef};
use iceberg::table::Table as IceTable;
use iceberg::{Catalog as _, TableIdent};
use skade_katalog::RedbCatalog;

use crate::error::Result;
use crate::read::{
    DeltaPlan, ScanFilter, arrow_schema_of, read_all, read_delta, read_equality_deletes,
    read_filtered, read_limited, scan_count,
};
use parquet::basic::Compression;

use crate::write::{
    IngestStats, WriteProps, append_props, ingest_parallel_props, ingest_pipelined_props,
    ingest_props,
};

/// A handle to one Iceberg table inside a [`crate::Warehouse`]. Writes go
/// through the catalog (`fast_append` snapshots); the handle tracks the table
/// state of its **own** last commit — call [`Table::refresh`] to pick up
/// commits made through other handles.
pub struct Table {
    catalog: Arc<RedbCatalog>,
    inner: IceTable,
    /// Parquet `WriterProperties` knobs (compression, bloom filters, row-group
    /// size, dictionary) applied to this handle's writes. Default: uncompressed,
    /// dictionary on, no bloom, default row-group size.
    write_props: WriteProps,
    /// Optional lineage sink: when present (and the `lineage` feature is on),
    /// each [`append`](Self::append) emits a [`LineageEvent`](crate::lineage::LineageEvent)
    /// to it post-commit. Best-effort: a sink error never fails the write.
    #[cfg(feature = "lineage")]
    lineage_sink: Option<Arc<dyn crate::lineage::LineageSink>>,
    /// The actor stamped onto emitted lineage events (default `"skade"`).
    #[cfg(feature = "lineage")]
    lineage_actor: String,
}

impl Table {
    pub(crate) fn new(catalog: Arc<RedbCatalog>, inner: IceTable) -> Self {
        Table {
            catalog,
            inner,
            write_props: WriteProps::default(),
            #[cfg(feature = "lineage")]
            lineage_sink: None,
            #[cfg(feature = "lineage")]
            lineage_actor: "skade".to_string(),
        }
    }

    /// Set the actor (who performed the write) stamped onto lineage events this
    /// handle emits (builder form). Requires the `lineage` feature; defaults to
    /// `"skade"`.
    #[cfg(feature = "lineage")]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.lineage_actor = actor.into();
        self
    }

    /// Emit one lineage event for `operation` on the table's `snapshot`, to the
    /// attached sink (best-effort — a sink error never fails the write). Stamps
    /// the actor and, when readable, the catalog `commit_seq`. No-op when no sink
    /// is attached.
    #[cfg(feature = "lineage")]
    pub(crate) async fn emit_lineage(
        &self,
        operation: crate::lineage::Operation,
        snapshot: Option<i64>,
    ) {
        let Some(sink) = &self.lineage_sink else {
            return;
        };
        let label = {
            let id = self.inner.identifier();
            format!("{}.{}", id.namespace().to_url_string(), id.name())
        };
        let mut event = crate::lineage::LineageEvent::new(
            operation,
            crate::lineage::DatasetRef::skade(label, snapshot),
        )
        .with_actor(self.lineage_actor.clone());
        // Tie the edge to the exact catalog commit when available.
        if let Ok(seq) = self.catalog.commit_seq().await {
            event = event.with_commit_seq(seq);
        }
        let ok = sink.emit(&event).await.is_ok();
        // Best-effort by contract: `ok=false` never fails the write.
        crate::functional_status(
            "skade/lineage",
            "sink_emit",
            ok,
            self.inner.identifier().name(),
        );
    }

    /// Attach a [`LineageSink`](crate::lineage::LineageSink) so each
    /// [`append`](Self::append) emits a lineage event post-commit (builder form).
    /// Requires the `lineage` feature; emission is best-effort and never fails a
    /// write. The same sink handle (e.g. a [`CapturingSink`](crate::lineage::CapturingSink)
    /// clone, or a `lineage_events`-table appender) can be shared across handles.
    #[cfg(feature = "lineage")]
    pub fn with_lineage_sink(mut self, sink: Arc<dyn crate::lineage::LineageSink>) -> Self {
        self.lineage_sink = Some(sink);
        self
    }

    /// Set the Parquet compression codec for this handle's writes (builder form):
    /// `table.compression(Compression::ZSTD(Default::default()))`. Compression
    /// trades CPU for smaller files + less read I/O; in `ingest_parallel` it runs
    /// inside the all-core encode stage, so it's parallelised for free.
    pub fn compression(mut self, compression: Compression) -> Self {
        self.write_props.compression = compression;
        self
    }

    /// Set the compression codec in place (non-consuming).
    pub fn set_compression(&mut self, compression: Compression) {
        self.write_props.compression = compression;
    }

    /// Replace this handle's full [`WriteProps`] (compression + bloom filters +
    /// row-group size + dictionary) — builder form. Use this to enable
    /// point-lookup row-group skipping via bloom filters on chosen columns.
    ///
    /// ```no_run
    /// # use skade::{Table, WriteProps, Compression};
    /// # fn f(t: Table) -> Table {
    /// t.write_props(
    ///     WriteProps::new(Compression::ZSTD(Default::default()))
    ///         .bloom_columns(["symbol", "sha"])
    ///         .row_group_size(128 * 1024),
    /// )
    /// # }
    /// ```
    pub fn write_props(mut self, props: WriteProps) -> Self {
        self.write_props = props;
        self
    }

    /// Replace this handle's [`WriteProps`] in place (non-consuming).
    pub fn set_write_props(&mut self, props: WriteProps) {
        self.write_props = props;
    }

    /// This handle's current [`WriteProps`].
    pub fn props(&self) -> &WriteProps {
        &self.write_props
    }

    /// The table's identifier (`namespace` + name).
    pub fn ident(&self) -> &TableIdent {
        self.inner.identifier()
    }

    /// The underlying `iceberg::table::Table` (escape hatch: `scan()`,
    /// metadata, snapshots, `file_io()`, …).
    pub fn inner(&self) -> &IceTable {
        &self.inner
    }

    pub(crate) fn catalog(&self) -> &Arc<RedbCatalog> {
        &self.catalog
    }

    pub(crate) fn set_inner(&mut self, inner: IceTable) {
        self.inner = inner;
    }

    /// The Arrow schema (with Iceberg field-id metadata) of the current schema.
    pub fn arrow_schema(&self) -> Result<ArrowSchemaRef> {
        arrow_schema_of(&self.inner)
    }

    /// Append `batches` as one `fast_append` snapshot (one commit). Batches are
    /// recast to the table schema automatically (see [`crate::recast`]).
    pub async fn append(&mut self, batches: &[RecordBatch]) -> Result<()> {
        self.inner = append_props(
            self.catalog.as_ref(),
            &self.inner,
            batches,
            &self.write_props,
        )
        .await?;
        // Lineage emit hook (feature `lineage`, default off): one append = one
        // `Append` lineage fact on the table's new snapshot, stamped with the
        // actor + catalog commit_seq. Best-effort — a sink error is swallowed so
        // lineage can never fail a write.
        #[cfg(feature = "lineage")]
        self.emit_lineage(
            crate::lineage::Operation::Append,
            self.current_snapshot_id(),
        )
        .await;
        // Write-path marker: one append = one fast_append snapshot committed.
        crate::functional_status(
            "skade/write",
            "append_fast_append",
            true,
            self.inner.identifier().name(),
        );
        Ok(())
    }

    /// Bulk-ingest batches, committing every `batches_per_commit` batches.
    /// Returns throughput stats.
    pub async fn ingest(
        &mut self,
        batches: impl IntoIterator<Item = RecordBatch>,
        batches_per_commit: usize,
    ) -> Result<IngestStats> {
        let (table, stats) = ingest_props(
            self.catalog.as_ref(),
            self.inner.clone(),
            batches,
            batches_per_commit,
            &self.write_props,
        )
        .await?;
        self.inner = table;
        // Lineage (feature `lineage`): one summarizing `Append` per ingest run,
        // on the final snapshot. Best-effort.
        #[cfg(feature = "lineage")]
        self.emit_lineage(
            crate::lineage::Operation::Append,
            self.current_snapshot_id(),
        )
        .await;
        Ok(stats)
    }

    /// Parallel bulk ingest — each `Vec<RecordBatch>` becomes one Parquet file,
    /// encoded across **all cores** (the znippy-zoomies `gatling_forkjoin` engine)
    /// and committed by one sequential writer every `files_per_commit` files (the
    /// gatling topology). Single partition per call. Returns throughput stats.
    pub async fn ingest_parallel(
        &mut self,
        groups: Vec<Vec<RecordBatch>>,
        files_per_commit: usize,
    ) -> Result<IngestStats> {
        let (table, stats) = ingest_parallel_props(
            self.catalog.as_ref(),
            self.inner.clone(),
            groups,
            files_per_commit,
            &self.write_props,
        )
        .await?;
        self.inner = table;
        // Concurrent-ingest marker: all-core encode → one sequential committer.
        crate::functional_status(
            "skade/ingest_parallel",
            "gatling_all_core_encode",
            true,
            &format!("{} rows / {} commits", stats.rows, stats.commits),
        );
        #[cfg(feature = "lineage")]
        self.emit_lineage(
            crate::lineage::Operation::Append,
            self.current_snapshot_id(),
        )
        .await;
        Ok(stats)
    }

    /// Bulk ingest across **both** gatling engines: the all-core `gatling_forkjoin`
    /// Parquet encode, then the FileIO writes fanned through the async sibling
    /// `gatling::io::run_ordered` with ≤ `channel_depth` writes in flight —
    /// no-barrier, backpressured, and re-sequenced into **submission order** so the
    /// file sequence and row order match the input `groups`. Unlike
    /// [`ingest_parallel`](Self::ingest_parallel), which writes files serially,
    /// this overlaps the write round-trips. Per-file partition; commits every
    /// `files_per_commit` files.
    pub async fn ingest_pipelined(
        &mut self,
        groups: Vec<Vec<RecordBatch>>,
        files_per_commit: usize,
        channel_depth: usize,
    ) -> Result<IngestStats> {
        let (table, stats) = ingest_pipelined_props(
            self.catalog.as_ref(),
            self.inner.clone(),
            groups,
            files_per_commit,
            channel_depth,
            &self.write_props,
        )
        .await?;
        self.inner = table;
        // Concurrent-ingest marker: bounded-channel pipeline (encode ‖ writer).
        crate::functional_status(
            "skade/ingest_pipelined",
            "no_barrier_pipeline",
            true,
            &format!("{} rows / {} commits", stats.rows, stats.commits),
        );
        #[cfg(feature = "lineage")]
        self.emit_lineage(
            crate::lineage::Operation::Append,
            self.current_snapshot_id(),
        )
        .await;
        Ok(stats)
    }

    /// Full-scan the current snapshot into Arrow record batches.
    pub async fn read(&self) -> Result<Vec<RecordBatch>> {
        let batches = read_all(&self.inner).await?;
        // Read-path marker: full-snapshot scan → Arrow.
        crate::functional_status(
            "skade/read",
            "full_scan_to_arrow",
            true,
            self.inner.identifier().name(),
        );
        Ok(batches)
    }

    /// Like [`read`](Self::read) but projects only `columns` — column pruning is
    /// pushed into the scan, so only those columns are read from Parquet.
    pub async fn read_columns(&self, columns: &[&str]) -> Result<Vec<RecordBatch>> {
        crate::read::read_columns(&self.inner, columns).await
    }

    /// Row count of the current snapshot (full scan, batches not materialized).
    pub async fn count(&self) -> Result<u64> {
        scan_count(&self.inner).await
    }

    /// **O(1) row-count HINT** from the current snapshot's `total-records`
    /// summary — no scan, no Parquet decompression. iceberg maintains it on every
    /// append/rewrite, so it is authoritative for a skade-written table; use it
    /// for cheap dashboards/polling instead of [`count`](Self::count) (a full
    /// scan). `None` when there is no snapshot or the summary lacks the key (fall
    /// back to `count` then).
    pub fn count_hint(&self) -> Option<u64> {
        self.inner
            .metadata()
            .current_snapshot()?
            .summary()
            .additional_properties
            .get("total-records")?
            .parse()
            .ok()
    }

    /// **Filtered / pushdown read.** Like [`read`](Self::read) but pushes a
    /// backend-neutral [`ScanFilter`] into the scan planner (partition / file /
    /// row-group pruning) and projects only `columns` (empty = all columns,
    /// preserving order). See [`read_filtered`] for the pruning semantics: it
    /// prunes at file granularity, not per row, so the result may still contain
    /// rows the predicate would reject — keep a residual per-row guard if you
    /// need exact filtering.
    ///
    /// ```no_run
    /// # use skade::{Table, ScanFilter};
    /// # async fn run(t: &Table) -> skade::Result<()> {
    /// // Read only the `znippy` partition, all columns.
    /// let rows = t.read_filtered(&ScanFilter::eq("repo", "znippy"), &[]).await?;
    /// # let _ = rows; Ok(()) }
    /// ```
    pub async fn read_filtered(
        &self,
        filter: &ScanFilter,
        columns: &[&str],
    ) -> Result<Vec<RecordBatch>> {
        let batches = read_filtered(&self.inner, filter, columns).await?;
        // Partition/file-pruned read marker.
        crate::functional_status(
            "skade/read_filtered",
            "pushdown_pruned_scan",
            true,
            self.inner.identifier().name(),
        );
        Ok(batches)
    }

    /// Plan-time data-skipping stats (see [`crate::read::plan_stats`]): how many
    /// data files / rows survive pruning for `filter` (`None` = the whole table),
    /// computed from the scan plan without reading data. Diff a filtered plan
    /// against the `None` baseline to get files SKIPPED — the headline metric for
    /// the Iceberg manifest-pruning win.
    pub async fn plan_stats(
        &self,
        filter: Option<&ScanFilter>,
    ) -> Result<crate::read::ScanPlanStats> {
        crate::read::plan_stats(&self.inner, filter).await
    }

    /// **Limit / early-break streaming read.** Like [`read`](Self::read) but
    /// stops once `max_rows` rows are in hand instead of materializing the whole
    /// table — it drives the scan's Arrow stream and cancels the rest of the
    /// scan, so on a big table a preview reads only the first data file(s).
    /// Returns at most `max_rows` worth of rows (the last batch may carry the
    /// count slightly over; truncate if you need an exact count).
    /// `max_rows == 0` falls back to a full [`read`](Self::read). See
    /// [`read_limited`].
    pub async fn read_limited(&self, max_rows: usize) -> Result<Vec<RecordBatch>> {
        read_limited(&self.inner, max_rows).await
    }

    /// **Incremental read** — the rows appended between snapshots `from` and `to`
    /// (only the data files those snapshots added, not the whole table). See
    /// [`read_delta`] for the manifest-diff approach and its limitations.
    /// `from = None` reads from the beginning up to `to`. Returns the batches
    /// plus the [`DeltaPlan`] describing what was read.
    pub async fn read_delta(
        &self,
        from: Option<i64>,
        to: i64,
    ) -> Result<(Vec<RecordBatch>, DeltaPlan)> {
        let (batches, plan) = read_delta(&self.inner, from, to).await?;
        // CDC read marker: incremental manifest-diff delta. `ok=false` flags the
        // overwrite/position-delete fallback that forced a full reload instead.
        crate::functional_status(
            "skade/read_delta",
            "cdc_incremental_delta",
            !plan.needs_full_reload,
            &format!(
                "{} added, {} delete file(s) across {} snapshot(s)",
                plan.added_files.len(),
                plan.delete_files.len(),
                plan.snapshots.len()
            ),
        );
        Ok((batches, plan))
    }

    /// **CDC changelog read** — the rows changed between snapshots `from` and
    /// `to` as a [`ChangelogBatch`]: inserts tagged `INSERT`, equality-deleted
    /// identities tagged `DELETE` (widened to the table schema). `from = None`
    /// reads full history up to `to`. Call [`ChangelogBatch::collapsed`] for
    /// net-change semantics. See [`read_changelog`].
    pub async fn read_changelog(
        &self,
        from: Option<i64>,
        to: i64,
    ) -> Result<crate::read::ChangelogBatch> {
        let cl = crate::read::read_changelog(&self.inner, from, to).await?;
        // CDC changelog marker: re-tagged delta window. `ok=false` flags the
        // overwrite/position-delete fallback that re-read `to` in full.
        crate::functional_status(
            "skade/read_changelog",
            "cdc_changelog",
            !cl.plan.needs_full_reload,
            &format!(
                "{} change row(s) to snapshot {}",
                cl.num_rows(),
                cl.to_snapshot
            ),
        );
        Ok(cl)
    }

    /// Read the deleted-row identities for a [`DeltaPlan`]'s equality-delete
    /// files (one `(equality_ids, batches)` per file). See
    /// [`read_equality_deletes`].
    pub async fn read_equality_deletes(
        &self,
        plan: &DeltaPlan,
    ) -> Result<Vec<(Vec<i32>, Vec<RecordBatch>)>> {
        let out = read_equality_deletes(&self.inner, plan).await?;
        // MOR read marker: equality-delete files resolved to deleted identities.
        crate::functional_status(
            "skade/read_equality_deletes",
            "mor_equality_delete_read",
            true,
            &format!("{} delete file(s)", out.len()),
        );
        Ok(out)
    }

    /// **Embedded delta-join probe (point lookup).** Resolve the single current
    /// row whose equality-key column(s) in `key` match, as of a snapshot-pinned
    /// `as_of` (time-travel) or the latest snapshot (`as_of = None`). See
    /// [`crate::read::lookup`]: it is a merge-on-read scan (so a deleted or
    /// updated key resolves correctly), pushed down to the key.
    ///
    /// ```no_run
    /// # use skade::{Table, Scalar};
    /// # async fn run(t: &Table) -> skade::Result<()> {
    /// // Probe the latest row for id == 7.
    /// let row = t.lookup(&[("id", Scalar::I64(7))], None).await?;
    /// # let _ = row; Ok(()) }
    /// ```
    pub async fn lookup(
        &self,
        key: &[(&str, crate::read::Scalar)],
        as_of: Option<i64>,
    ) -> Result<Option<RecordBatch>> {
        let row = crate::read::lookup(&self.inner, key, as_of).await?;
        // Lookup marker: point probe over the equality-delete-aware MOR path.
        crate::functional_status(
            "skade/lookup",
            "embedded_delta_join_probe",
            row.is_some(),
            self.inner.identifier().name(),
        );
        Ok(row)
    }

    /// The current snapshot id (the natural `to` for [`read_delta`]), or `None`
    /// if the table has no snapshots yet.
    pub fn current_snapshot_id(&self) -> Option<i64> {
        self.inner
            .metadata()
            .current_snapshot()
            .map(|s| s.snapshot_id())
    }

    /// Reload the table from the catalog (pick up commits made elsewhere).
    pub async fn refresh(&mut self) -> Result<()> {
        self.inner = self.catalog.load_table(self.inner.identifier()).await?;
        Ok(())
    }

    /// **Additive schema evolution.** Ensure the table carries every top-level
    /// column in `desired` (an Arrow schema, same mapping as
    /// [`crate::arrow_to_iceberg`]); any column the table is *missing* is added
    /// as an **optional** Iceberg column via an add-column metadata commit. This
    /// is idempotent and purely additive:
    ///
    /// * **Idempotent** — if every `desired` column is already present (by name)
    ///   it is a no-op (no catalog write); calling it twice in a row does nothing
    ///   the second time.
    /// * **Additive only** — columns are only *added*. Columns present in the
    ///   table but absent from `desired` are left untouched; nothing is ever
    ///   dropped or renamed. Type changes on existing columns are ignored (the
    ///   stored field wins) — this method only closes the "table is missing a
    ///   column the writer now produces" gap.
    /// * **Field-id stable** — every existing column keeps the exact field id it
    ///   was created with (the evolved schema reuses the table's current
    ///   `NestedField`s verbatim); each new column gets a fresh id above the
    ///   table's current `highest_field_id`. Old data files are untouched
    ///   (add-column is metadata-only), so rows written before the evolution
    ///   read back `null` for the new column, and rows written after carry it.
    ///
    /// Use this before [`append`](Self::append) when the writer always builds the
    /// full (current) batch but the table may have been created by an older
    /// binary with fewer columns — it evolves the stale table forward so the
    /// append's recast finds every column. After it returns, this handle points
    /// at the evolved table (no separate [`refresh`](Self::refresh) needed).
    ///
    /// New columns are added **optional** regardless of the `desired` field's
    /// nullability, because existing rows have no value for them (Iceberg
    /// add-column cannot make a column required without a default).
    ///
    /// ```no_run
    /// # use skade::arrow_schema::{DataType, Field, Schema};
    /// # async fn run(t: &mut skade::Table) -> skade::Result<()> {
    /// // Table was created with [id, name]; writer now also produces `score`.
    /// let desired = Schema::new(vec![
    ///     Field::new("id", DataType::Int64, false),
    ///     Field::new("name", DataType::Utf8, false),
    ///     Field::new("score", DataType::Float64, true), // new column
    /// ]);
    /// t.ensure_schema(&desired).await?; // adds `score`; no-op if already present
    /// # Ok(()) }
    /// ```
    pub async fn ensure_schema(&mut self, desired: &ArrowSchema) -> Result<()> {
        use std::collections::HashSet;

        use iceberg::TableUpdate;
        use iceberg::spec::{NestedField, NestedFieldRef, Schema};

        let current = self.inner.metadata().current_schema();
        let have: HashSet<&str> = current
            .as_struct()
            .fields()
            .iter()
            .map(|f| f.name.as_str())
            .collect();

        // Names in `desired` the table does not yet have, in `desired` order.
        let missing_names: Vec<&str> = desired
            .fields()
            .iter()
            .map(|f| f.name().as_str())
            .filter(|n| !have.contains(n))
            .collect();
        if missing_names.is_empty() {
            // Steady state: every desired column is already present — no commit.
            return Ok(());
        }

        // Derive Iceberg types for the *desired* columns once, reusing the exact
        // Arrow→Iceberg mapping the table was created with. (Field ids here are
        // a throwaway `1..N`; we re-stamp ids below.)
        let desired_ice = crate::bridge::arrow_to_iceberg(desired)?;
        let desired_by_name: std::collections::HashMap<&str, &NestedFieldRef> = desired_ice
            .as_struct()
            .fields()
            .iter()
            .map(|f| (f.name.as_str(), f))
            .collect();

        // Evolved schema = the table's current fields verbatim (ids preserved) …
        let mut fields: Vec<NestedFieldRef> = current.as_struct().fields().to_vec();
        // … plus each missing column as a fresh OPTIONAL field above the current
        // highest id (add-column has no value for pre-existing rows).
        for (next_id, name) in (current.highest_field_id() + 1..).zip(missing_names.iter()) {
            let ty = desired_by_name
                .get(name)
                .map(|f| f.field_type.as_ref().clone())
                .ok_or_else(|| {
                    crate::error::SkadeError::other(format!(
                        "ensure_schema: desired column `{name}` vanished from derived schema"
                    ))
                })?;
            fields.push(Arc::new(NestedField::optional(next_id, *name, ty)));
        }

        // A new schema id (current + 1) so `AddSchema` registers a new schema
        // rather than colliding with the existing one; `-1` in SetCurrentSchema
        // = "the schema just added" (iceberg metadata-builder convention).
        let new_schema_id = current.schema_id() + 1;
        let evolved = Schema::builder()
            .with_schema_id(new_schema_id)
            .with_fields(fields)
            .build()?;

        let updates = vec![
            TableUpdate::AddSchema { schema: evolved },
            TableUpdate::SetCurrentSchema { schema_id: -1 },
        ];
        let ident = self.inner.identifier().clone();
        self.inner = self
            .catalog
            .commit_table(ident, Vec::new(), updates)
            .await?;
        Ok(())
    }
}

#[cfg(feature = "sql")]
mod sql {
    use super::*;
    use datafusion::prelude::SessionContext;
    use iceberg_datafusion::IcebergStaticTableProvider;

    impl Table {
        /// Run one SQL statement over **this** table, registered under its bare
        /// name (`SELECT … FROM <name> …`), against the handle's current
        /// snapshot. For multi-table SQL use [`crate::Warehouse::sql`].
        pub async fn sql(&self, query: &str) -> Result<Vec<RecordBatch>> {
            let ctx = SessionContext::new();
            let provider =
                IcebergStaticTableProvider::try_new_from_table(self.inner.clone()).await?;
            ctx.register_table(self.ident().name(), Arc::new(provider))?;
            Ok(ctx.sql(query).await?.collect().await?)
        }
    }
}
