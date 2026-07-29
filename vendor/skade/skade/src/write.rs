//! The writer stack as one call: ParquetWriter → RollingFileWriter →
//! DataFileWriter → `fast_append` commit.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arrow_array::{
    Array, ArrayRef, GenericStringArray, Int64Array, OffsetSizeTrait, RecordBatch,
    TimestampMicrosecondArray, TimestampNanosecondArray,
};
use arrow_schema::SchemaRef as ArrowSchemaRef;
use arrow_schema::{DataType, TimeUnit};
use arrow_select::interleave::interleave;
use bytes::Bytes;
use iceberg::Catalog;
use iceberg::spec::SchemaRef as IceSchemaRef;
use iceberg::spec::{
    DataContentType, DataFile, DataFileFormat, Literal, PartitionKey, Struct, Transform,
};
use iceberg::table::Table as IceTable;
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::writer::base_writer::data_file_writer::DataFileWriterBuilder;
use iceberg::writer::file_writer::location_generator::{
    DefaultFileNameGenerator, DefaultLocationGenerator,
};
use iceberg::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
use iceberg::writer::file_writer::{ParquetWriter, ParquetWriterBuilder};
use iceberg::writer::{IcebergWriter, IcebergWriterBuilder};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use parquet::schema::types::ColumnPath;
use znippy_zoomies::gatling_forkjoin::gatling_map_owned;

use crate::bridge::recast;
use crate::error::{Result, SkadeError};
use crate::read::arrow_schema_of;

/// Tunable Parquet `WriterProperties` for skade writes — the knobs that live in
/// skade (compression, per-column bloom filters, row-group size, dictionary)
/// rather than in the catalog. These complement nornir's sort/`SortOrder`
/// file-level data-skipping with **intra-file row-group skipping** on point
/// lookups: a bloom filter on a high-cardinality column (e.g. `symbol`, `sha`)
/// lets a reader skip row groups whose chunk cannot contain the probed value.
///
/// Build with [`WriteProps::new`] (a chosen [`Compression`]) then the builder
/// setters, or `WriteProps::default()` for the bare Parquet defaults
/// (uncompressed, dictionary on, no bloom, default row-group size).
///
/// ```
/// # use skade::{WriteProps, Compression};
/// let props = WriteProps::new(Compression::ZSTD(Default::default()))
///     .bloom_columns(["symbol", "sha"])   // point-lookup row-group skipping
///     .row_group_size(128 * 1024)         // smaller groups → finer skipping
///     .dictionary(true);
/// # let _ = props;
/// ```
#[derive(Debug, Clone)]
pub struct WriteProps {
    /// Parquet compression codec (`UNCOMPRESSED` / `SNAPPY` / `ZSTD(level)` / …).
    pub compression: Compression,
    /// Columns to enable a per-column bloom filter on (by leaf column name).
    /// Empty (the default) writes no bloom filters.
    pub bloom_columns: Vec<String>,
    /// `set_max_row_group_size` when `Some`; otherwise the Parquet default
    /// (1,048,576 rows). Smaller groups → finer row-group skipping, more metadata.
    pub row_group_size: Option<usize>,
    /// Whether dictionary encoding is enabled (Parquet default: `true`).
    pub dictionary: bool,
}

impl Default for WriteProps {
    fn default() -> Self {
        WriteProps {
            compression: Compression::UNCOMPRESSED,
            bloom_columns: Vec::new(),
            row_group_size: None,
            dictionary: true,
        }
    }
}

impl WriteProps {
    /// A `WriteProps` with the given compression codec and otherwise Parquet
    /// defaults (dictionary on, no bloom, default row-group size).
    pub fn new(compression: Compression) -> Self {
        WriteProps {
            compression,
            ..Self::default()
        }
    }

    /// Enable a bloom filter on each named column (builder form). Replaces any
    /// previously set list.
    pub fn bloom_columns<I, S>(mut self, columns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.bloom_columns = columns.into_iter().map(Into::into).collect();
        self
    }

    /// Set `set_max_row_group_size` (builder form).
    pub fn row_group_size(mut self, rows: usize) -> Self {
        self.row_group_size = Some(rows);
        self
    }

    /// Set dictionary encoding on/off (builder form).
    pub fn dictionary(mut self, enabled: bool) -> Self {
        self.dictionary = enabled;
        self
    }

    /// Translate into Parquet [`WriterProperties`] used by both the iceberg
    /// `ParquetWriterBuilder` (single-file [`append`] path) and the in-memory
    /// `ArrowWriter` ([`ingest_parallel`]/[`ingest_pipelined`] encode path), so
    /// every write surface honours the same knobs.
    fn to_writer_properties(&self) -> WriterProperties {
        let mut b = WriterProperties::builder()
            .set_compression(self.compression)
            .set_dictionary_enabled(self.dictionary);
        if let Some(n) = self.row_group_size {
            // `set_max_row_group_row_count` is the un-deprecated name for the
            // old `set_max_row_group_size` (rows, not bytes) in parquet 58.
            b = b.set_max_row_group_row_count(Some(n));
        }
        for col in &self.bloom_columns {
            b = b.set_column_bloom_filter_enabled(ColumnPath::from(col.as_str()), true);
        }
        b.build()
    }
}

/// Process-unique data-file name prefix so repeated commits (and concurrent
/// writers in one process) never collide on file names.
fn unique_prefix() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!(
        "skade-{}-{nanos:x}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Throughput of an [`ingest`] run.
#[derive(Debug, Clone)]
pub struct IngestStats {
    pub rows: u64,
    pub commits: u64,
    pub elapsed: Duration,
}

impl IngestStats {
    pub fn rows_per_sec(&self) -> f64 {
        let s = self.elapsed.as_secs_f64();
        if s > 0.0 { self.rows as f64 / s } else { 0.0 }
    }
    pub fn commits_per_sec(&self) -> f64 {
        let s = self.elapsed.as_secs_f64();
        if s > 0.0 {
            self.commits as f64 / s
        } else {
            0.0
        }
    }
}

/// Prove a string column is **uniform** — every row byte-identical and non-null
/// — in one contiguous pass over its offset buffer plus a single `memcmp`,
/// returning that shared value; `None` when it can't prove uniformity (the
/// column is empty, carries any null, or holds ≥2 distinct values), leaving the
/// caller to fall back to the exact per-row scan.
///
/// The proof needs no per-row `&str` construction: for `n` rows of one `l`-byte
/// value the offset deltas are all `l` **and** the values buffer is that value
/// repeated — i.e. the buffer shifted left by `l` bytes equals itself,
/// `region[l..] == region[..len-l]`. Both are cache-friendly linear scans (int
/// subtractions, then one SIMD-friendly slice compare), so a 250k-row identity
/// partition collapses in a fraction of the old `value(i)`-per-row loop's cost.
/// Being a *strict accelerator* it only ever returns `Some` when uniformity is
/// proven, so it can never mis-tag a batch that actually spans partitions.
pub(crate) fn uniform_str_value<O: OffsetSizeTrait>(a: &GenericStringArray<O>) -> Option<&str> {
    let n = a.len();
    // A null makes "the value" ill-defined here; defer to the exact scan.
    if n == 0 || a.null_count() != 0 {
        return None;
    }
    let offsets = a.value_offsets();
    let start = offsets[0].as_usize();
    let l = offsets[1].as_usize() - start;
    // Every row the same byte length? (Necessary for uniformity; a cheap reject.)
    for w in offsets.windows(2) {
        if w[1].as_usize() - w[0].as_usize() != l {
            return None;
        }
    }
    // All rows the empty string ⇒ uniformly "".
    if l == 0 {
        return Some("");
    }
    let end = offsets[n].as_usize();
    let region = &a.value_data()[start..end];
    // Buffer periodic with period `l` ⇒ every `l`-byte block equals the first,
    // so all rows share one value. `region[0]` is a valid non-null UTF-8 row.
    if region[l..] == region[..region.len() - l] {
        Some(a.value(0))
    } else {
        None
    }
}

/// Derive the single [`PartitionKey`] for `batches` from `table`'s default
/// partition spec, or `None` for an unpartitioned table (the common case).
///
/// Supports **identity** transforms over **string** columns (`Utf8`/`LargeUtf8`).
/// Every row across every batch must share the same partition value — an
/// [`append`] commits one group of data files as one snapshot, so it writes a
/// single partition. A batch that spans partitions, or a non-identity/non-string
/// partition column, errors loudly rather than mis-tagging the files (which
/// would silently break partition pruning on read).
fn partition_key_for<B: std::borrow::Borrow<RecordBatch>>(
    table: &IceTable,
    batches: &[B],
) -> Result<Option<PartitionKey>> {
    // Scan one string column for its single partition value, downcast ONCE per
    // batch (not per row). The uniform (all-equal) column — the overwhelmingly
    // common identity-partition shape — is collapsed in one offsets pass + one
    // `memcmp` via [`uniform_str_value`], skipping the per-row `value(i)` `&str`
    // build entirely; only a non-uniform / nullable column walks the exact
    // per-row loop (which stays the sole source of the "spans partitions" error).
    fn scan_str_col<O: OffsetSizeTrait>(
        a: &GenericStringArray<O>,
        name: &str,
        value: &mut Option<String>,
    ) -> Result<()> {
        // Fast path: a proven-uniform, non-null column short-circuits to its one
        // value. A strict accelerator — it NEVER accepts a column it can't prove
        // uniform, so it can only match the slow scan's verdict, never override it.
        if let Some(v) = uniform_str_value(a) {
            match value {
                None => *value = Some(v.to_string()),
                Some(prev) if prev.as_str() == v => {}
                Some(prev) => {
                    return Err(SkadeError::other(format!(
                        "skade::append: batch spans multiple `{name}` partitions (`{prev}` vs `{v}`); \
                         single-partition appends only"
                    )));
                }
            }
            return Ok(());
        }
        for i in 0..a.len() {
            let v = a.value(i);
            if value.is_none() {
                *value = Some(v.to_string());
            } else if value.as_deref() != Some(v) {
                let v0 = value.as_deref().unwrap_or_default();
                return Err(SkadeError::other(format!(
                    "skade::append: batch spans multiple `{name}` partitions (`{v0}` vs `{v}`); \
                     single-partition appends only"
                )));
            }
        }
        Ok(())
    }

    let meta = table.metadata();
    let spec = meta.default_partition_spec();
    if spec.fields().is_empty() {
        return Ok(None);
    }
    let schema = meta.current_schema();
    let mut lits: Vec<Option<Literal>> = Vec::with_capacity(spec.fields().len());
    for f in spec.fields() {
        if f.transform != Transform::Identity {
            return Err(SkadeError::other(format!(
                "skade::append: only identity partition transforms are supported (got {:?} on `{}`)",
                f.transform, f.name
            )));
        }
        let src = schema.field_by_id(f.source_id).ok_or_else(|| {
            SkadeError::other(format!(
                "partition source field id {} not in schema",
                f.source_id
            ))
        })?;
        // Single partition value across every batch (None ⇒ all batches empty).
        let mut value: Option<String> = None;
        for b in batches {
            let col = b.borrow().column_by_name(&src.name).ok_or_else(|| {
                SkadeError::other(format!(
                    "partition column `{}` missing from batch",
                    src.name
                ))
            })?;
            if let Some(a) = col.as_any().downcast_ref::<GenericStringArray<i32>>() {
                scan_str_col(a, &src.name, &mut value)?;
            } else if let Some(a) = col.as_any().downcast_ref::<GenericStringArray<i64>>() {
                scan_str_col(a, &src.name, &mut value)?;
            } else {
                return Err(SkadeError::other(format!(
                    "partition column `{}` is not a string (only Utf8/LargeUtf8 identity partitions)",
                    src.name
                )));
            }
        }
        match value {
            Some(v) => lits.push(Some(Literal::string(v))),
            None => return Ok(None),
        }
    }
    Ok(Some(PartitionKey::new(
        spec.as_ref().clone(),
        schema.clone(),
        Struct::from_iter(lits),
    )))
}

/// Write `batches` into one group of Parquet data files and commit them as a
/// single `fast_append` snapshot. Batches are [`recast`] to the table's
/// field-id Arrow schema first (covers `Utf8 → LargeUtf8` etc.), so any
/// column-compatible batches work. For a partitioned table the (single)
/// partition key is derived from the batch via [`partition_key_for`]. Returns
/// the updated table.
pub async fn append(
    catalog: &dyn Catalog,
    table: &IceTable,
    batches: &[RecordBatch],
) -> Result<IceTable> {
    append_props(catalog, table, batches, &WriteProps::default()).await
}

/// Like [`append`] but with an explicit Parquet `Compression` codec
/// (`UNCOMPRESSED` / `SNAPPY` / `ZSTD(level)` / …). skade defaults to
/// uncompressed; compression trades CPU for smaller files + less read I/O.
/// Shorthand for [`append_props`] with compression-only [`WriteProps`].
pub async fn append_with(
    catalog: &dyn Catalog,
    table: &IceTable,
    batches: &[RecordBatch],
    compression: Compression,
) -> Result<IceTable> {
    append_props(catalog, table, batches, &WriteProps::new(compression)).await
}

/// Like [`append`] but with full [`WriteProps`] control — compression plus
/// per-column bloom filters, row-group size, and dictionary encoding. Use this
/// to enable point-lookup row-group skipping (`bloom_columns`).
pub async fn append_props(
    catalog: &dyn Catalog,
    table: &IceTable,
    batches: &[RecordBatch],
    props: &WriteProps,
) -> Result<IceTable> {
    let target = arrow_schema_of(table)?;
    let batches = recast(batches, target)?;
    let partition = partition_key_for(table, &batches)?;

    let schema = table.metadata().current_schema().clone();
    let data_location = format!("{}/data", table.metadata().location());
    let location_gen = DefaultLocationGenerator::with_data_location(data_location);
    let file_name_gen =
        DefaultFileNameGenerator::new(unique_prefix(), None, DataFileFormat::Parquet);

    let pw = ParquetWriterBuilder::new(props.to_writer_properties(), schema);
    let rolling = RollingFileWriterBuilder::new_with_default_file_size(
        pw,
        table.file_io().clone(),
        location_gen,
        file_name_gen,
    );
    let mut writer = DataFileWriterBuilder::new(rolling).build(partition).await?;
    for b in &batches {
        writer.write(b.clone()).await?;
    }
    let data_files = writer.close().await?;

    let tx = Transaction::new(table);
    let action = tx.fast_append().add_data_files(data_files);
    let tx = action.apply(tx)?;
    Ok(tx.commit(catalog).await?)
}

/// Stream batches into `table` as rolled Parquet files and commit them all in
/// **one** `fast_append` snapshot. This is the writer for rebuild-style bulk
/// copies (see `Warehouse::compact_table`): peak memory is one Parquet row
/// group (not the table), the output is a handful of large files, and the
/// resulting table gains exactly one snapshot — unlike per-group [`append`]
/// calls, which each add a snapshot and manifest.
///
/// `map` (when given) transforms each batch before it is written — e.g. a
/// filter that drops rows already sealed to cold storage. Returns the updated
/// table, rows read from the stream, and rows actually written (they differ
/// only when `map` drops rows).
///
/// Unpartitioned tables only: a stream can span many partition keys, and skade
/// appends are single-partition (errors otherwise, like [`append`]).
pub async fn append_stream_props(
    catalog: &dyn Catalog,
    table: &IceTable,
    mut batches: impl futures::Stream<Item = Result<RecordBatch>> + Unpin,
    map: Option<&(dyn Fn(RecordBatch) -> Result<RecordBatch> + Send + Sync)>,
    props: &WriteProps,
) -> Result<(IceTable, u64, u64)> {
    use futures::StreamExt;
    if !table
        .metadata()
        .default_partition_spec()
        .fields()
        .is_empty()
    {
        return Err(SkadeError::other(
            "skade::append_stream_props: partitioned tables are not supported",
        ));
    }
    let target = arrow_schema_of(table)?;

    let schema = table.metadata().current_schema().clone();
    let data_location = format!("{}/data", table.metadata().location());
    let location_gen = DefaultLocationGenerator::with_data_location(data_location);
    let file_name_gen =
        DefaultFileNameGenerator::new(unique_prefix(), None, DataFileFormat::Parquet);

    let pw = ParquetWriterBuilder::new(props.to_writer_properties(), schema);
    let rolling = RollingFileWriterBuilder::new_with_default_file_size(
        pw,
        table.file_io().clone(),
        location_gen,
        file_name_gen,
    );
    let mut writer = DataFileWriterBuilder::new(rolling).build(None).await?;

    let (mut rows_in, mut rows_out) = (0u64, 0u64);
    while let Some(batch) = batches.next().await {
        let batch = batch?;
        rows_in += batch.num_rows() as u64;
        let batch = match map {
            Some(f) => f(batch)?,
            None => batch,
        };
        if batch.num_rows() == 0 {
            continue;
        }
        rows_out += batch.num_rows() as u64;
        let recasted = recast(std::slice::from_ref(&batch), target.clone())?;
        for b in recasted {
            writer.write(b).await?;
        }
    }
    let data_files = writer.close().await?;
    if data_files.is_empty() {
        // Nothing written (empty source or map dropped everything): no commit,
        // the table keeps its current (0-snapshot, for a fresh one) state.
        return Ok((table.clone(), rows_in, rows_out));
    }

    let tx = Transaction::new(table);
    let action = tx.fast_append().add_data_files(data_files);
    let tx = action.apply(tx)?;
    Ok((tx.commit(catalog).await?, rows_in, rows_out))
}

/// Extract an `index_col`'s values as `i64` sort keys. Supports the columns a
/// clustering index makes sense on: a microsecond/nanosecond timestamp or a
/// plain `Int64` id. Null slots read as their raw buffer value (a clustering
/// column is expected to be non-null); the caller sorts ascending. The keys are
/// borrowed straight from the Arrow value buffer (no copy) — the caller only
/// iterates them once to build the tiny `(key, batch, row)` index tuples.
fn index_col_keys(col: &dyn Array) -> Result<&[i64]> {
    match col.data_type() {
        DataType::Timestamp(TimeUnit::Microsecond, _) => Ok(col
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .ok_or_else(|| SkadeError::other("append_sorted: ts(us) downcast failed"))?
            .values()),
        DataType::Timestamp(TimeUnit::Nanosecond, _) => Ok(col
            .as_any()
            .downcast_ref::<TimestampNanosecondArray>()
            .ok_or_else(|| SkadeError::other("append_sorted: ts(ns) downcast failed"))?
            .values()),
        DataType::Int64 => Ok(col
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or_else(|| SkadeError::other("append_sorted: i64 downcast failed"))?
            .values()),
        other => Err(SkadeError::other(format!(
            "append_sorted: unsupported index column type {other:?} (expected Timestamp(us|ns) or Int64)"
        ))),
    }
}

/// Additive sibling of [`append_stream_props`] that writes the (already-pruned)
/// `input` batches **clustered ascending by `index_col`**, so each output file's
/// and row-group's min/max on that column is tight and non-overlapping — turning
/// a range predicate on it into file/row-group **pruning** instead of a full
/// decompress. Nothing existing changes: this is a new path used by
/// [`Warehouse::compact_table_sorted`](crate::Warehouse::compact_table_sorted).
///
/// **Memory:** a global sort needs the whole (pruned) input in RAM at once — the
/// honest cost of clustering, and why this rides the compaction rebuild (a full
/// rewrite already). OUTPUT is materialised one `chunk_rows` slice at a time via
/// `arrow_select::interleave` (no whole-table copy), and the Parquet encode still
/// rides the gatling all-core rolling writer. For tables that exceed RAM keep the
/// bounded, unsorted [`append_stream_props`] until an external merge-sort lands.
///
/// Returns `(committed_table, rows_in, rows_out)` (equal — clustering drops
/// nothing; prune, if any, is applied by the caller before this).
pub async fn append_sorted_props(
    catalog: &dyn Catalog,
    table: &IceTable,
    input: Vec<RecordBatch>,
    index_col: &str,
    chunk_rows: usize,
    props: &WriteProps,
) -> Result<(IceTable, u64, u64)> {
    if !table
        .metadata()
        .default_partition_spec()
        .fields()
        .is_empty()
    {
        return Err(SkadeError::other(
            "skade::append_sorted_props: partitioned tables are not supported",
        ));
    }
    let input: Vec<RecordBatch> = input.into_iter().filter(|b| b.num_rows() > 0).collect();
    let total: u64 = input.iter().map(|b| b.num_rows() as u64).sum();
    if input.is_empty() || total == 0 {
        return Ok((table.clone(), 0, 0));
    }
    let chunk_rows = chunk_rows.max(1);
    let src_schema = input[0].schema();
    let col_idx = src_schema.index_of(index_col).map_err(|_| {
        SkadeError::other(format!("append_sorted: no column '{index_col}' in schema"))
    })?;

    // Build the global ascending order as (key, batch_idx, row_idx). Sorting the
    // whole tuple is deterministic (stable across equal keys). Only the tiny
    // index tuples are materialised here — never the row data.
    let mut order: Vec<(i64, u32, u32)> = Vec::with_capacity(total as usize);
    for (bi, b) in input.iter().enumerate() {
        let keys = index_col_keys(b.column(col_idx).as_ref())?;
        for (ri, &k) in keys.iter().enumerate() {
            order.push((k, bi as u32, ri as u32));
        }
    }
    order.sort_unstable();

    // Per-column view across all input batches, so `interleave` can gather each
    // output chunk directly from the inputs by (batch, row) index — zero-copy of
    // the row payload (only the selected values are copied into the output slice).
    let ncols = src_schema.fields().len();
    let col_refs: Vec<Vec<&dyn Array>> = (0..ncols)
        .map(|c| input.iter().map(|b| b.column(c).as_ref()).collect())
        .collect();

    // Writer setup — identical shape to `append_stream_props` (one rolling
    // DataFileWriter, one fast_append commit).
    let target = arrow_schema_of(table)?;
    let ice_schema = table.metadata().current_schema().clone();
    let data_location = format!("{}/data", table.metadata().location());
    let location_gen = DefaultLocationGenerator::with_data_location(data_location);
    let file_name_gen =
        DefaultFileNameGenerator::new(unique_prefix(), None, DataFileFormat::Parquet);
    let pw = ParquetWriterBuilder::new(props.to_writer_properties(), ice_schema);
    let rolling = RollingFileWriterBuilder::new_with_default_file_size(
        pw,
        table.file_io().clone(),
        location_gen,
        file_name_gen,
    );
    let mut writer = DataFileWriterBuilder::new(rolling).build(None).await?;

    for chunk in order.chunks(chunk_rows) {
        let idx: Vec<(usize, usize)> = chunk
            .iter()
            .map(|&(_, b, r)| (b as usize, r as usize))
            .collect();
        let cols: Vec<ArrayRef> = col_refs
            .iter()
            .map(|refs| interleave(refs, &idx).map_err(SkadeError::from))
            .collect::<Result<Vec<_>>>()?;
        let batch = RecordBatch::try_new(src_schema.clone(), cols).map_err(SkadeError::from)?;
        for b in recast(std::slice::from_ref(&batch), target.clone())? {
            writer.write(b).await?;
        }
    }

    let data_files = writer.close().await?;
    if data_files.is_empty() {
        return Ok((table.clone(), total, total));
    }
    let tx = Transaction::new(table);
    let action = tx.fast_append().add_data_files(data_files);
    let tx = action.apply(tx)?;
    Ok((tx.commit(catalog).await?, total, total))
}

/// Ingest all batches, committing every `batches_per_commit` batches via
/// [`append`]. Returns the final table + throughput.
pub async fn ingest(
    catalog: &dyn Catalog,
    table: IceTable,
    batches: impl IntoIterator<Item = RecordBatch>,
    batches_per_commit: usize,
) -> Result<(IceTable, IngestStats)> {
    ingest_props(
        catalog,
        table,
        batches,
        batches_per_commit,
        &WriteProps::default(),
    )
    .await
}

/// Like [`ingest`] with an explicit Parquet `Compression` codec.
pub async fn ingest_with(
    catalog: &dyn Catalog,
    table: IceTable,
    batches: impl IntoIterator<Item = RecordBatch>,
    batches_per_commit: usize,
    compression: Compression,
) -> Result<(IceTable, IngestStats)> {
    ingest_props(
        catalog,
        table,
        batches,
        batches_per_commit,
        &WriteProps::new(compression),
    )
    .await
}

/// Like [`ingest`] with full [`WriteProps`] control (compression + bloom +
/// row-group size + dictionary). Each commit group is written via
/// [`append_props`].
pub async fn ingest_props(
    catalog: &dyn Catalog,
    table: IceTable,
    batches: impl IntoIterator<Item = RecordBatch>,
    batches_per_commit: usize,
    props: &WriteProps,
) -> Result<(IceTable, IngestStats)> {
    let bpc = batches_per_commit.max(1);
    let mut table = table;
    let (mut rows, mut commits) = (0u64, 0u64);
    let mut group: Vec<RecordBatch> = Vec::with_capacity(bpc);
    let start = Instant::now();
    for batch in batches {
        rows += batch.num_rows() as u64;
        group.push(batch);
        if group.len() >= bpc {
            table = append_props(catalog, &table, &group, props).await?;
            commits += 1;
            group.clear();
        }
    }
    if !group.is_empty() {
        table = append_props(catalog, &table, &group, props).await?;
        commits += 1;
    }
    Ok((
        table,
        IngestStats {
            rows,
            commits,
            elapsed: start.elapsed(),
        },
    ))
}

/// Parallel bulk ingest — the gatling topology: **all cores encode** (the
/// znippy-zoomies `gatling_forkjoin` engine), **one** sequential writer commits.
///
/// Each inner `Vec<RecordBatch>` is encoded into one in-memory Parquet file
/// across the no-barrier gatling fork-join pool (pure CPU, no I/O), then a single
/// writer streams the files to the table's `FileIO` and commits every
/// `files_per_commit` files via
/// `fast_append`. Single-partition per call (same rule as [`append`]); for a
/// partitioned table every file is tagged with the derived partition key.
///
/// The encode phase holds all files in memory before the write phase, so size
/// `groups` to your memory budget for very large loads (chunk across calls).
pub async fn ingest_parallel(
    catalog: &dyn Catalog,
    table: IceTable,
    groups: Vec<Vec<RecordBatch>>,
    files_per_commit: usize,
) -> Result<(IceTable, IngestStats)> {
    ingest_parallel_props(
        catalog,
        table,
        groups,
        files_per_commit,
        &WriteProps::default(),
    )
    .await
}

/// Like [`ingest_parallel`] with an explicit Parquet `Compression` codec — the
/// compression runs inside the all-core encode stage, so it's parallelised free.
pub async fn ingest_parallel_with(
    catalog: &dyn Catalog,
    table: IceTable,
    groups: Vec<Vec<RecordBatch>>,
    files_per_commit: usize,
    compression: Compression,
) -> Result<(IceTable, IngestStats)> {
    ingest_parallel_props(
        catalog,
        table,
        groups,
        files_per_commit,
        &WriteProps::new(compression),
    )
    .await
}

/// Like [`ingest_parallel`] with full [`WriteProps`] control — compression,
/// per-column bloom filters, row-group size, and dictionary. All of it (bloom
/// hashing included) runs inside the all-core encode stage, so it's parallelised
/// for free across the gatling fork-join pool.
pub async fn ingest_parallel_props(
    catalog: &dyn Catalog,
    table: IceTable,
    groups: Vec<Vec<RecordBatch>>,
    files_per_commit: usize,
    props: &WriteProps,
) -> Result<(IceTable, IngestStats)> {
    let fpc = files_per_commit.max(1);
    let target = arrow_schema_of(&table)?;
    let start = Instant::now();

    // Recast each group to the table's field-id Arrow schema (so the Parquet
    // columns carry the field ids the scan maps back through).
    let groups: Vec<Vec<RecordBatch>> = groups
        .into_iter()
        .map(|g| recast(&g, target.clone()))
        .collect::<Result<_>>()?;

    // One partition key for the whole call (single-partition rule), derived from
    // every batch — `None` for an unpartitioned table. Borrow the batches (no
    // per-batch clone): `partition_key_for` only reads the partition column.
    let all: Vec<&RecordBatch> = groups.iter().flatten().collect();
    let partition = partition_key_for(&table, &all)?;
    drop(all);

    // ── Encode stage: all cores, pure CPU, no I/O. The ONE fork-join engine
    // (znippy-zoomies `gatling_forkjoin`) fans each group's Parquet encode across
    // a no-barrier self-dispatching pool and returns the files in input order —
    // so no `seq` tag and no post-sort are needed (the index IS the order). ──
    let encoded: Vec<(Vec<u8>, u64)> =
        gatling_map_owned(groups, |g| encode_parquet(target.clone(), &g, props))
            .into_iter()
            .collect::<Result<Vec<_>>>()?;

    // ── Writer stage: exactly ONE sequential writer + committer. ──
    let prefix = unique_prefix();
    let data_dir = format!("{}/data", table.metadata().location());
    let ice_schema = table.metadata().current_schema().clone();
    let mut table = table;
    let (mut rows, mut commits) = (0u64, 0u64);
    let mut pending: Vec<DataFile> = Vec::with_capacity(fpc);
    for (seq, (bytes, record_count)) in encoded.into_iter().enumerate() {
        let path = format!("{data_dir}/{prefix}-{seq:08}.parquet");
        let bytes = Bytes::from(bytes);
        let len = bytes.len() as u64;
        let data_file = build_data_file(
            &ice_schema,
            &bytes,
            path.clone(),
            record_count,
            len,
            partition.as_ref(),
        )?;
        table.file_io().new_output(&path)?.write(bytes).await?;
        rows += record_count;
        pending.push(data_file);
        if pending.len() >= fpc {
            table = commit_files(catalog, &table, std::mem::take(&mut pending)).await?;
            commits += 1;
        }
    }
    if !pending.is_empty() {
        table = commit_files(catalog, &table, pending).await?;
        commits += 1;
    }
    Ok((
        table,
        IngestStats {
            rows,
            commits,
            elapsed: start.elapsed(),
        },
    ))
}

/// One Parquet file encoded in memory by a gatling worker. `gatling_map_owned`
/// returns these in **input (submission) order**, so `encoded[i]` is group `i`;
/// the writer stage stamps the filename sequence from that index and
/// [`gatling::io::run_ordered`](znippy_zoomies::gatling::io::run_ordered)
/// preserves it end-to-end (no per-file `seq` tag needed).
struct EncodedFile {
    bytes: Vec<u8>,
    record_count: u64,
    partition: Option<iceberg::spec::PartitionKey>,
}

/// Bulk ingest across **both** gatling engines: the CPU-bound Parquet encode
/// fans across all cores on the sync `gatling_forkjoin` pool, then the I/O-bound
/// FileIO writes fan out through the async sibling
/// [`gatling::io::run_ordered`](znippy_zoomies::gatling::io::run_ordered) with
/// ≤ `channel_depth` writes **in flight** (no-barrier, bounded, backpressured on
/// admission). The write jobs *execute* out of order (fastest-first, fully
/// overlapped up to the cap) but their results are re-sequenced into **submission
/// order**, so the emitted file sequence and row order match the input `groups`
/// order regardless of which write finishes first. This is the one-engine
/// replacement for the old hand-rolled `spawn_blocking` + mpsc + `blocking_send`
/// pipeline.
///
/// Each inner `Vec<RecordBatch>` becomes one file; the partition key is derived
/// per file (so a partitioned table is tagged correctly). Commits every
/// `files_per_commit` files via `fast_append`, in submission order. Unlike
/// [`ingest_parallel`] — which writes files strictly serially — this overlaps the
/// FileIO round-trips; both encode every file before the write phase begins.
pub async fn ingest_pipelined(
    catalog: &dyn Catalog,
    table: IceTable,
    groups: Vec<Vec<RecordBatch>>,
    files_per_commit: usize,
    channel_depth: usize,
    compression: Compression,
) -> Result<(IceTable, IngestStats)> {
    ingest_pipelined_props(
        catalog,
        table,
        groups,
        files_per_commit,
        channel_depth,
        &WriteProps::new(compression),
    )
    .await
}

/// Like [`ingest_pipelined`] with full [`WriteProps`] control — compression,
/// per-column bloom filters, row-group size, and dictionary, all applied inside
/// the overlapped all-core encode stage.
pub async fn ingest_pipelined_props(
    catalog: &dyn Catalog,
    table: IceTable,
    groups: Vec<Vec<RecordBatch>>,
    files_per_commit: usize,
    channel_depth: usize,
    props: &WriteProps,
) -> Result<(IceTable, IngestStats)> {
    let fpc = files_per_commit.max(1);
    let target = arrow_schema_of(&table)?;
    let start = Instant::now();
    // Immutable handle for the encoders (schema + partition spec don't change
    // during the ingest); the writer advances its own `table` via commits.
    let meta = Arc::new(table.clone());
    // Shared, owned write props for the encoder closure.
    let props = Arc::new(props.clone());

    // ── Encode stage: the ONE CPU fork-join engine (znippy-zoomies
    // `gatling_forkjoin`) fans the Parquet encode across a no-barrier
    // self-dispatching pool (one worker per core) on a single `spawn_blocking`
    // thread so the async runtime stays free during the all-core burn.
    // `gatling_map_owned` returns results in **input order**, so `encoded[i]` is
    // group `i` — the submission order the write stage preserves. ──
    let target_enc = target.clone();
    let encoded: Vec<EncodedFile> = tokio::task::spawn_blocking(move || {
        gatling_map_owned(groups, |group| -> Result<EncodedFile> {
            let batches = recast(&group, target_enc.clone())?;
            let partition = partition_key_for(&meta, &batches)?;
            let (bytes, record_count) = encode_parquet(target_enc.clone(), &batches, &props)?;
            Ok(EncodedFile {
                bytes,
                record_count,
                partition,
            })
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()
    })
    .await
    .expect("encode task panicked")?;

    // ── Write stage: the ONE async I/O engine `gatling::io::run_ordered` drives
    // the FileIO writes with ≤ `channel_depth` in flight (no-barrier, bounded,
    // backpressured on admission), and delivers each finished write's `DataFile`
    // in **submission order** — so the file sequence (`-{seq:08}`) and row order
    // match the input `groups` order regardless of which write finishes first.
    // This replaces the old mpsc + `blocking_send` reordering. ──
    let prefix = unique_prefix();
    let data_dir = format!("{}/data", table.metadata().location());
    let ice_schema = table.metadata().current_schema().clone();
    let file_io = table.file_io().clone();

    // One async write job per encoded file; `seq` (the submission index) names the
    // file and `run_ordered` re-sequences the results back into this order.
    let jobs = encoded.into_iter().enumerate().map(|(seq, ef)| {
        let path = format!("{data_dir}/{prefix}-{seq:08}.parquet");
        let ice_schema = ice_schema.clone();
        let file_io = file_io.clone();
        async move {
            let bytes = Bytes::from(ef.bytes);
            let len = bytes.len() as u64;
            // Per-column bounds from this file's Parquet footer (see
            // `ingest_parallel_props`): identical stats path to `append`, so the
            // hand-committed DataFile is file-prunable.
            let data_file = build_data_file(
                &ice_schema,
                &bytes,
                path.clone(),
                ef.record_count,
                len,
                ef.partition.as_ref(),
            )?;
            file_io.new_output(&path)?.write(bytes).await?;
            Ok::<(DataFile, u64), anyhow::Error>((data_file, ef.record_count))
        }
    });
    let written: Vec<(DataFile, u64)> =
        znippy_zoomies::gatling::io::run_ordered(jobs, channel_depth.max(1), |x| x)
            .await
            .map_err(SkadeError::other)?;

    // ── Commit stage: exactly ONE sequential committer walking the writes in
    // submission order, committing every `files_per_commit` files. ──
    let mut table = table;
    let (mut rows, mut commits) = (0u64, 0u64);
    let mut pending: Vec<DataFile> = Vec::with_capacity(fpc);
    for (data_file, record_count) in written {
        rows += record_count;
        pending.push(data_file);
        if pending.len() >= fpc {
            table = commit_files(catalog, &table, std::mem::take(&mut pending)).await?;
            commits += 1;
        }
    }
    if !pending.is_empty() {
        table = commit_files(catalog, &table, pending).await?;
        commits += 1;
    }
    Ok((
        table,
        IngestStats {
            rows,
            commits,
            elapsed: start.elapsed(),
        },
    ))
}

/// Encode a group of batches into one in-memory Parquet file — CPU only, the
/// part that fans out across cores. `schema` must carry the iceberg field ids.
fn encode_parquet(
    schema: ArrowSchemaRef,
    batches: &[RecordBatch],
    props: &WriteProps,
) -> Result<(Vec<u8>, u64)> {
    let mut buf: Vec<u8> = Vec::new();
    let mut rows = 0u64;
    {
        let mut w = ArrowWriter::try_new(&mut buf, schema, Some(props.to_writer_properties()))?;
        for b in batches {
            rows += b.num_rows() as u64;
            w.write(b)?;
        }
        w.close()?;
    }
    Ok((buf, rows))
}

/// Build the `DataFile` for one already-encoded in-memory Parquet file, with the
/// per-column Iceberg statistics (`lower_bounds`/`upper_bounds`, `value_counts`,
/// `null_value_counts`, `column_sizes`, `split_offsets`) derived from the file's
/// own Parquet footer via [`ParquetWriter::data_file_builder_from_parquet_bytes`]
/// — the SAME statistics path the streaming [`append`]/`DataFileWriter` close
/// uses. This is what makes the fast `ingest_parallel`/`ingest_pipelined` paths
/// produce file-prunable data files (matching `append`); previously they emitted
/// only `record_count` + `file_size`, so the scan planner could never skip them.
///
/// `ice_schema` is the table's current Iceberg schema (carries field ids).
/// Bounds for column types the iceberg stats path can't serialize are simply
/// omitted by that path (no bound = no pruning = correct), never guessed.
fn build_data_file(
    ice_schema: &IceSchemaRef,
    bytes: &Bytes,
    path: String,
    record_count: u64,
    file_size: u64,
    partition: Option<&PartitionKey>,
) -> Result<DataFile> {
    let mut b =
        ParquetWriter::data_file_builder_from_parquet_bytes(ice_schema.clone(), bytes, path)
            .map_err(SkadeError::other)?;
    // The stats helper already sets content/format/record_count/file_size, but we
    // re-assert record_count + file_size from the writer's own accounting (the
    // FileIO-written byte length and the rows we counted) so they always match
    // the bytes actually committed, independent of footer parsing.
    b.content(DataContentType::Data)
        .file_format(DataFileFormat::Parquet)
        .record_count(record_count)
        .file_size_in_bytes(file_size);
    if let Some(pk) = partition {
        // Override the empty partition struct the stats helper defaults to.
        b.partition(pk.data().clone());
        b.partition_spec_id(pk.spec().spec_id());
    }
    b.build().map_err(SkadeError::other)
}

/// One `fast_append` commit of already-written data files.
async fn commit_files(
    catalog: &dyn Catalog,
    table: &IceTable,
    files: Vec<DataFile>,
) -> Result<IceTable> {
    let tx = Transaction::new(table);
    let action = tx.fast_append().add_data_files(files);
    let tx = action.apply(tx)?;
    Ok(tx.commit(catalog).await?)
}

#[cfg(test)]
mod tests {
    //! White-box guards for the [`uniform_str_value`] partition-scan accelerator.
    //! These are RED-when-broken: if the fast path ever claims a column uniform
    //! that isn't (which would silently mis-tag a partition), the `is_none()`
    //! assertions below fail and the build goes red.
    use super::uniform_str_value;
    use arrow_array::{GenericStringArray, LargeStringArray, StringArray};

    #[test]
    fn uniform_column_collapses_to_its_value() {
        let a = StringArray::from(vec!["znippy"; 10_000]);
        assert_eq!(uniform_str_value(&a), Some("znippy"));
        // i64-offset (LargeUtf8) column takes the same path.
        let big = LargeStringArray::from(vec!["holger"; 4096]);
        assert_eq!(uniform_str_value(&big), Some("holger"));
    }

    #[test]
    fn single_row_and_empty_strings_are_uniform() {
        assert_eq!(
            uniform_str_value(&StringArray::from(vec!["solo"])),
            Some("solo")
        );
        // Every row the empty string ⇒ uniformly "".
        assert_eq!(
            uniform_str_value(&StringArray::from(vec![""; 500])),
            Some("")
        );
    }

    #[test]
    fn a_single_differing_row_is_not_uniform() {
        // Differs in the LAST row — guards the periodicity `memcmp`.
        let mut v = vec!["repo"; 4096];
        *v.last_mut().unwrap() = "other";
        assert_eq!(uniform_str_value(&StringArray::from(v)), None);

        // Differs in a MIDDLE row (same length, so the length pre-check passes and
        // only the buffer-shift compare can catch it).
        let mut v = vec!["AAAA"; 4096];
        v[2048] = "BBBB";
        assert_eq!(uniform_str_value(&StringArray::from(v)), None);

        // Two distinct values of DIFFERENT length — rejected by the length pass.
        let a = StringArray::from(vec!["short", "longer-value"]);
        assert_eq!(uniform_str_value(&a), None);
    }

    #[test]
    fn nulls_and_empty_array_defer_to_the_slow_scan() {
        let a = StringArray::from(vec![Some("znippy"), None, Some("znippy")]);
        assert_eq!(
            uniform_str_value(&a),
            None,
            "a null makes the value ill-defined"
        );
        let empty: GenericStringArray<i32> = StringArray::from(Vec::<&str>::new());
        assert_eq!(uniform_str_value(&empty), None);
    }
}
