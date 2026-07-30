//! The read primitive: full table → Arrow in one call.

use std::collections::HashSet;
use std::sync::Arc;

use arrow_array::array::new_null_array;
use arrow_array::{
    Array, ArrayRef, BooleanArray, Float64Array, Int32Array, Int64Array, LargeStringArray,
    RecordBatch, StringArray,
};
use arrow_schema::{DataType, Field, Schema as ArrowSchema, SchemaRef as ArrowSchemaRef};
use arrow_select::filter::filter_record_batch;
use futures::{StreamExt, TryStreamExt};
use iceberg::expr::{Predicate, Reference};
use iceberg::spec::Datum;
use iceberg::table::Table as IceTable;
use znippy_zoomies::gatling_forkjoin::gatling_map_owned;

use crate::error::{Result, SkadeError};

/// The Arrow schema (with Iceberg field-id metadata) of `table`'s current
/// schema — the schema batches must carry to be written, and the schema scans
/// come back with.
pub fn arrow_schema_of(table: &IceTable) -> Result<ArrowSchemaRef> {
    let s = iceberg::arrow::schema_to_arrow_schema(table.metadata().current_schema())?;
    Ok(Arc::new(s))
}

/// Fast full-scan path: when the current snapshot is a plain append-only,
/// single-schema table with **no** delete files, its data-file bytes can be
/// decoded directly through the ONE fork-join engine (gatling) across all cores
/// — the same fast pattern [`read_delta`] uses — bypassing the Iceberg engine's
/// per-file async `to_arrow` pipeline (which does not fan the CPU-bound Parquet
/// decode across cores).
///
/// Returns `Ok(None)` — signalling the caller to fall back to the engine's
/// correctness-complete `to_arrow` scan — whenever the raw decode would be
/// **wrong**:
/// - more than one schema in the metadata (schema evolution: raw Parquet decode
///   wouldn't apply Iceberg's field-id remap);
/// - any **delete** manifest, equality-delete, or position-delete file present
///   (row-level deletes need Iceberg's delete-merge — dropping them would return
///   deleted rows).
///
/// `Ok(Some(vec![]))` means "no current snapshot" (genuinely empty table).
async fn read_all_gatling(table: &IceTable) -> Result<Option<Vec<RecordBatch>>> {
    use iceberg::spec::{DataContentType, Manifest, ManifestContentType, ManifestStatus};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let metadata = table.metadata();

    // Schema evolution: a raw Parquet decode reads the file's own schema and
    // cannot apply Iceberg's field-id → current-schema remap. Defer to the
    // engine, which resolves fields by id.
    if metadata.schemas_iter().len() > 1 {
        return Ok(None);
    }

    // No snapshot ⇒ genuinely empty table (fast path applies: zero batches).
    let Some(snapshot) = metadata.current_snapshot() else {
        return Ok(Some(Vec::new()));
    };

    let file_io = table.file_io();
    let manifest_list = snapshot.load_manifest_list(file_io, metadata).await?;

    let mut data_files: Vec<String> = Vec::new();
    for mf in manifest_list.entries() {
        // A delete manifest means row-level deletes exist — the engine must
        // merge them; a raw scan would wrongly surface deleted rows.
        if mf.content == ManifestContentType::Deletes {
            return Ok(None);
        }
        let bytes = file_io.new_input(&mf.manifest_path)?.read().await?;
        let manifest = Manifest::parse_avro(&bytes)?;
        for entry in manifest.entries() {
            // Live rows are Added|Existing; Deleted entries are tombstoned.
            match entry.status() {
                ManifestStatus::Added | ManifestStatus::Existing => {}
                ManifestStatus::Deleted => continue,
            }
            let df = entry.data_file();
            match df.content_type() {
                DataContentType::Data => data_files.push(df.file_path().to_string()),
                // Any delete file ⇒ defer to the engine's delete-merge.
                DataContentType::EqualityDeletes | DataContentType::PositionDeletes => {
                    return Ok(None);
                }
            }
        }
    }
    data_files.sort();
    data_files.dedup();

    // Async-read each data file's bytes (I/O), then fan the CPU-bound Parquet
    // decode across ALL cores via the ONE fork-join engine (gatling), results
    // kept in file order — EXACTLY like `read_delta`'s decode.
    let mut raw = Vec::with_capacity(data_files.len());
    for path in &data_files {
        raw.push(file_io.new_input(path)?.read().await?);
    }
    let decoded = gatling_map_owned(raw, |bytes| -> Result<Vec<RecordBatch>> {
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?.build()?;
        reader
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(SkadeError::from)
    });
    let mut batches = Vec::new();
    for d in decoded {
        batches.extend(d?);
    }
    Ok(Some(batches))
}

/// Full-scan `table` (current snapshot, all columns) into Arrow record batches.
///
/// **Fast path.** For a plain append-only, single-schema table with no delete
/// files, this decodes the data-file bytes directly through the ONE fork-join
/// engine (gatling) across all cores (see [`read_all_gatling`]) — the same fast
/// pattern [`read_delta`] uses — which is markedly faster than the Iceberg
/// engine's per-file async `to_arrow` pipeline.
///
/// **Fallback.** Whenever the fast path would be *wrong* — schema evolution
/// (field-id remap) or any delete file (row-level delete-merge) — it declines
/// (`read_all_gatling` returns `None`) and this falls back to the engine's
/// correctness-complete `scan().select_all().build()?.to_arrow()`, which
/// handles those cases. Correctness first: the fast path never drops deleted
/// rows or mis-maps evolved schemas.
pub async fn read_all(table: &IceTable) -> Result<Vec<RecordBatch>> {
    if let Some(batches) = read_all_gatling(table).await? {
        return Ok(batches);
    }
    let stream = table.scan().select_all().build()?.to_arrow().await?;
    Ok(stream.try_collect().await?)
}

/// Full-scan but **project only `columns`** — column pruning pushed into the
/// scan, so the engine reads only those columns from Parquet (less I/O + decode
/// than [`read_all`]). Empty `columns` is equivalent to [`read_all`].
pub async fn read_columns(table: &IceTable, columns: &[&str]) -> Result<Vec<RecordBatch>> {
    if columns.is_empty() {
        return read_all(table).await;
    }
    let stream = table
        .scan()
        .select(columns.iter())
        .build()?
        .to_arrow()
        .await?;
    Ok(stream.try_collect().await?)
}

/// A backend-neutral scalar value used in a [`ScanFilter`] predicate.
///
/// This is deliberately a tiny, engine-agnostic set (string / signed-int /
/// float / bool) — *not* an iceberg `Datum` — so the predicate surface does not
/// leak the Iceberg engine into skade's public API. A future non-Iceberg
/// backend (e.g. DuckDB) can implement the same [`ScanFilter`] contract by
/// mapping these scalars onto its own predicate type. The Iceberg backend maps
/// each variant onto an `iceberg::spec::Datum` in [`Scalar::to_datum`].
#[derive(Debug, Clone, PartialEq)]
pub enum Scalar {
    /// A UTF-8 string value (the common case — partition columns like `repo`).
    Str(String),
    /// A signed 64-bit integer (`Datum::long`).
    I64(i64),
    /// A signed 32-bit integer (`Datum::int`).
    I32(i32),
    /// A 64-bit float (`Datum::double`).
    F64(f64),
    /// A boolean (`Datum::bool`).
    Bool(bool),
}

impl Scalar {
    /// Map this backend-neutral scalar onto the Iceberg engine's `Datum`.
    fn to_datum(&self) -> Datum {
        match self {
            Scalar::Str(s) => Datum::string(s),
            Scalar::I64(v) => Datum::long(*v),
            Scalar::I32(v) => Datum::int(*v),
            Scalar::F64(v) => Datum::double(*v),
            Scalar::Bool(v) => Datum::bool(*v),
        }
    }
}

impl From<&str> for Scalar {
    fn from(s: &str) -> Self {
        Scalar::Str(s.to_string())
    }
}
impl From<String> for Scalar {
    fn from(s: String) -> Self {
        Scalar::Str(s)
    }
}
impl From<i64> for Scalar {
    fn from(v: i64) -> Self {
        Scalar::I64(v)
    }
}
impl From<i32> for Scalar {
    fn from(v: i32) -> Self {
        Scalar::I32(v)
    }
}
impl From<f64> for Scalar {
    fn from(v: f64) -> Self {
        Scalar::F64(v)
    }
}
impl From<bool> for Scalar {
    fn from(v: bool) -> Self {
        Scalar::Bool(v)
    }
}

/// A backend-neutral scan predicate pushed **into** the read path so the engine
/// prunes data files / row-groups instead of reading them.
///
/// Kept intentionally small — `column <op> value` on a single column, which
/// covers every pushdown nornir's warehouse does today (filter by the `repo`
/// partition column). It is **not** the Iceberg `Predicate` type: that would
/// leak the engine into the public signature. A future backend (DuckDB, …)
/// implements the same enum by mapping it onto its own predicate. The Iceberg
/// backend lowers each variant to an `iceberg::expr::Predicate` in
/// [`ScanFilter::to_iceberg`].
///
/// Use the constructors ([`ScanFilter::eq`], [`ScanFilter::is_in`],
/// [`ScanFilter::range`]) for readable call sites:
/// `ScanFilter::eq("repo", "znippy")`.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanFilter {
    /// `column == value` (today: `repo == "<repo>"`, partition pruning).
    Eq { column: String, value: Scalar },
    /// `column IN (values…)` — matches any of the values.
    In { column: String, values: Vec<Scalar> },
    /// A range on a column: `lo <= column` and/or `column <= hi` (inclusive
    /// bounds). Either bound may be absent (`None`) for a one-sided range.
    Range {
        column: String,
        lo: Option<Scalar>,
        hi: Option<Scalar>,
    },
}

impl ScanFilter {
    /// `column == value`. The common partition-pruning case.
    pub fn eq(column: impl Into<String>, value: impl Into<Scalar>) -> Self {
        ScanFilter::Eq {
            column: column.into(),
            value: value.into(),
        }
    }

    /// `column IN (values…)`.
    pub fn is_in<S: Into<Scalar>>(
        column: impl Into<String>,
        values: impl IntoIterator<Item = S>,
    ) -> Self {
        ScanFilter::In {
            column: column.into(),
            values: values.into_iter().map(Into::into).collect(),
        }
    }

    /// An inclusive range `lo <= column <= hi`; pass `None` for an open bound.
    pub fn range(
        column: impl Into<String>,
        lo: Option<impl Into<Scalar>>,
        hi: Option<impl Into<Scalar>>,
    ) -> Self {
        ScanFilter::Range {
            column: column.into(),
            lo: lo.map(Into::into),
            hi: hi.map(Into::into),
        }
    }

    /// Lower this backend-neutral filter onto the Iceberg engine's `Predicate`,
    /// which the scan builder pushes down (file/row-group pruning). Returns
    /// `None` for an empty range (no bounds) — caller skips the filter.
    fn to_iceberg(&self) -> Option<Predicate> {
        match self {
            ScanFilter::Eq { column, value } => {
                Some(Reference::new(column).equal_to(value.to_datum()))
            }
            ScanFilter::In { column, values } => {
                if values.is_empty() {
                    // `IN ()` matches nothing. iceberg's set predicate needs ≥1
                    // literal, and leaving the scan *unfiltered* would wrongly
                    // match everything — so emit an always-false predicate the
                    // engine can evaluate: `col IS NULL AND col IS NOT NULL`.
                    return Some(
                        Reference::new(column)
                            .is_null()
                            .and(Reference::new(column).is_not_null()),
                    );
                }
                Some(Reference::new(column).is_in(values.iter().map(|v| v.to_datum())))
            }
            ScanFilter::Range { column, lo, hi } => {
                let lo_pred = lo
                    .as_ref()
                    .map(|v| Reference::new(column).greater_than_or_equal_to(v.to_datum()));
                let hi_pred = hi
                    .as_ref()
                    .map(|v| Reference::new(column).less_than_or_equal_to(v.to_datum()));
                match (lo_pred, hi_pred) {
                    (Some(l), Some(h)) => Some(l.and(h)),
                    (Some(l), None) => Some(l),
                    (None, Some(h)) => Some(h),
                    (None, None) => None,
                }
            }
        }
    }
}

/// **Filtered / pushdown read.** Scan `table` but push `filter` into the scan
/// planner so the engine prunes other partitions' data files / row-groups
/// instead of reading them, and project only `columns` (empty = all columns,
/// preserving column order so positional downcasts stay valid).
///
/// This is the public, backend-neutral equivalent of reaching through to the
/// raw Iceberg scan builder (`table.scan().with_filter(Reference::new("repo")
/// .equal_to(Datum::string(r)))`) — the predicate is expressed as the engine-
/// agnostic [`ScanFilter`], so the public signature never names an Iceberg type.
///
/// Pushdown prunes at file/row-group granularity, **not** per row: the result
/// may still contain rows the predicate would reject, so a caller that needs
/// exact filtering must keep a residual per-row guard. (This matches Iceberg's
/// partition-pruning semantics — pruning is a read-amplification optimization,
/// not a row filter.)
pub async fn read_filtered(
    table: &IceTable,
    filter: &ScanFilter,
    columns: &[&str],
) -> Result<Vec<RecordBatch>> {
    let mut builder = table.scan();
    if let Some(pred) = filter.to_iceberg() {
        builder = builder.with_filter(pred);
    }
    if columns.is_empty() {
        builder = builder.select_all();
    } else {
        builder = builder.select(columns.iter());
    }
    let stream = builder.build()?.to_arrow().await?;
    Ok(stream.try_collect().await?)
}

/// Plan-time data-skipping stats: how many data files / file-splits / rows
/// SURVIVE pruning (Iceberg manifest min/max + partition pruning) for a scan,
/// computed from the scan plan WITHOUT reading any data.
///
/// This is the observable headline metric for the data-skipping win — it counts
/// what the engine will actually OPEN, not a guess. Diff a filtered plan against
/// the unfiltered baseline to get files SKIPPED:
/// `files_skipped = plan_stats(t, None).data_files − plan_stats(t, Some(f)).data_files`.
///
/// Row-group / bloom skipping happens later, inside the Parquet reader, and is
/// NOT visible at plan time — measure that via wall time + the file's row-group
/// count (Parquet metadata), not here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanPlanStats {
    /// Distinct data files the plan will open after pruning.
    pub data_files: u64,
    /// File-scan tasks (one file may split into several) — the unit of scan work.
    pub splits: u64,
    /// Rows the plan will read (sum of the planned files' record counts).
    pub rows_planned: u64,
}

/// Plan (do NOT execute) a scan and report its [`ScanPlanStats`]. Pushes
/// `filter` into the planner exactly like [`read_filtered`]; `filter = None`
/// plans the whole table (the baseline to diff a filtered plan against).
pub async fn plan_stats(table: &IceTable, filter: Option<&ScanFilter>) -> Result<ScanPlanStats> {
    let mut builder = table.scan().select_all();
    if let Some(pred) = filter.and_then(|f| f.to_iceberg()) {
        builder = builder.with_filter(pred);
    }
    let tasks: Vec<_> = builder.build()?.plan_files().await?.try_collect().await?;
    let mut files = std::collections::HashSet::new();
    let mut rows_planned = 0u64;
    for t in &tasks {
        files.insert(t.data_file_path.clone());
        rows_planned += t.record_count.unwrap_or(0);
    }
    Ok(ScanPlanStats {
        data_files: files.len() as u64,
        splits: tasks.len() as u64,
        rows_planned,
    })
}

/// **Limit / early-break streaming read.** Scan `table` but **stop once
/// `max_rows` rows are in hand** instead of materializing the whole table the
/// way [`read_all`] does (it `try_collect`s every data file before the caller
/// can truncate).
///
/// It drives the Iceberg scan's Arrow **stream** and breaks as soon as it has
/// accumulated `max_rows` rows; dropping the stream cancels the rest of the
/// scan, so the remaining data files are never opened or decoded. On a big
/// table (e.g. a multi-GB preview) this turns a multi-second full scan into a
/// few-millisecond read of the first data file(s). A small `with_batch_size`
/// keeps the first batch from overshooting `max_rows` by much.
///
/// Returns *at most* `max_rows` worth of rows — actually the smallest whole
/// number of batches whose row total reaches `max_rows` (the last batch may
/// carry the count slightly over `max_rows`; the caller truncates if it needs
/// an exact count). `max_rows == 0` falls back to a full [`read_all`].
///
/// Caveat: Iceberg gives no ordering guarantee, so this returns *some*
/// `max_rows` rows, not a deterministic top-N — fine for previews (which never
/// promised an order) but not for ranked reads.
pub async fn read_limited(table: &IceTable, max_rows: usize) -> Result<Vec<RecordBatch>> {
    if max_rows == 0 {
        return read_all(table).await;
    }
    // Cap per-batch rows so the stream can stop close to `max_rows` rather than
    // pulling one giant batch. Clamp to a sane floor for tiny limits.
    let batch_size = max_rows.clamp(256, 8192);
    let mut stream = table
        .scan()
        .select_all()
        .with_batch_size(Some(batch_size))
        .build()?
        .to_arrow()
        .await?;
    let mut batches = Vec::new();
    let mut have = 0usize;
    while have < max_rows {
        match stream.next().await {
            Some(b) => {
                let b = b?;
                have += b.num_rows();
                batches.push(b);
            }
            None => break, // table smaller than the limit
        }
    }
    // Dropping `stream` here cancels the rest of the scan: no further parquet
    // files are opened or decoded.
    Ok(batches)
}

/// Row-group pruning stats from one [`lookup_gatling`] probe: how many of the
/// fast path's row groups a written bloom filter let it skip without ever being
/// decoded. Exposed only to `#[cfg(test)]` so a test can assert the probe
/// actually skipped I/O (via [`Sbbf::read_from_column_chunk`]), not merely that
/// it returned the right row.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LookupGatlingStats {
    /// Row groups the probe considered (summed across every data file it opened).
    pub row_groups_seen: u64,
    /// Of those, how many a column's bloom filter proved could not contain the
    /// key (definitely absent) — skipped without decoding.
    pub row_groups_skipped_by_bloom: u64,
}

/// Outcome of the [`lookup_gatling`] fast path.
enum FastLookup {
    /// The fast path does not apply (schema evolution, a delete file, an
    /// as-of snapshot that no longer exists, a key column missing from the
    /// file, or a key column whose Arrow type doesn't match its [`Scalar`]
    /// variant) — caller must fall back to the Iceberg engine's scan.
    Declined,
    /// The fast path resolved the probe: `Some(row)` on a match, `None` when
    /// genuinely absent — either way this is the final answer, correctness
    /// guaranteed (same MOR-safety preconditions as [`read_all_gatling`]).
    Resolved(Option<RecordBatch>, LookupGatlingStats),
}

/// Whether `dt` is the Arrow type a bloom-filter-eligible [`Scalar`] variant
/// would have been written as. Used to gate **both** the bloom probe and the
/// row-level exact match on the same type check — a mismatch here means
/// "unknown", so the fast path declines entirely rather than risk silently
/// skipping a row group that does contain the key (or silently returning no
/// match when the slow engine path might resolve it via numeric promotion).
fn scalar_type_matches(val: &Scalar, dt: &DataType) -> bool {
    matches!(
        (val, dt),
        (Scalar::Str(_), DataType::Utf8 | DataType::LargeUtf8)
            | (Scalar::I64(_), DataType::Int64)
            | (Scalar::I32(_), DataType::Int32)
            | (Scalar::F64(_), DataType::Float64)
            | (Scalar::Bool(_), DataType::Boolean)
    )
}

/// Exact row-level equality check of column `col` at row `i` against `val`.
/// Only called after [`scalar_type_matches`] has confirmed the column's Arrow
/// type lines up with `val`'s variant, so the downcast is expected to succeed;
/// a failed downcast (defensive) counts as "not a match", never a false match.
fn scalar_eq_at(col: &ArrayRef, i: usize, val: &Scalar) -> bool {
    match val {
        Scalar::Str(s) => {
            if let Some(a) = col.as_any().downcast_ref::<StringArray>() {
                !a.is_null(i) && a.value(i) == s.as_str()
            } else if let Some(a) = col.as_any().downcast_ref::<LargeStringArray>() {
                !a.is_null(i) && a.value(i) == s.as_str()
            } else {
                false
            }
        }
        Scalar::I64(v) => col
            .as_any()
            .downcast_ref::<Int64Array>()
            .map(|a| !a.is_null(i) && a.value(i) == *v)
            .unwrap_or(false),
        Scalar::I32(v) => col
            .as_any()
            .downcast_ref::<Int32Array>()
            .map(|a| !a.is_null(i) && a.value(i) == *v)
            .unwrap_or(false),
        Scalar::F64(v) => col
            .as_any()
            .downcast_ref::<Float64Array>()
            .map(|a| !a.is_null(i) && a.value(i) == *v)
            .unwrap_or(false),
        Scalar::Bool(v) => col
            .as_any()
            .downcast_ref::<BooleanArray>()
            .map(|a| !a.is_null(i) && a.value(i) == *v)
            .unwrap_or(false),
    }
}

/// Whether `bloom` proves `val` cannot be in the row group (`true` = definitely
/// absent, safe to skip). Only called once [`scalar_type_matches`] has already
/// confirmed the column's Arrow type matches `val`'s variant, so the hashed
/// bytes line up with whatever the writer inserted for that physical type
/// (parquet's bloom hash is over the raw value bytes, independent of the
/// wrapping Rust type — `str`'s UTF-8 bytes match a `ByteArray` insert, an
/// `i64`'s little-endian bytes match an `Int64` insert, etc).
fn scalar_bloom_says_absent(bloom: &parquet::bloom_filter::Sbbf, val: &Scalar) -> bool {
    match val {
        Scalar::Str(s) => !bloom.check(s.as_str()),
        Scalar::I64(v) => !bloom.check(v),
        Scalar::I32(v) => !bloom.check(v),
        Scalar::F64(v) => !bloom.check(v),
        Scalar::Bool(v) => !bloom.check(v),
    }
}

/// The first row in `batch` whose `key` columns all match, or `None`.
fn first_matching_row(batch: &RecordBatch, key: &[(&str, Scalar)]) -> Result<Option<RecordBatch>> {
    let key_idx: Vec<usize> = key
        .iter()
        .map(|(col, _)| {
            batch
                .schema()
                .index_of(col)
                .map_err(|e| SkadeError::Other(e.to_string()))
        })
        .collect::<Result<_>>()?;
    for i in 0..batch.num_rows() {
        let all_match = key_idx
            .iter()
            .zip(key.iter())
            .all(|(&idx, (_, val))| scalar_eq_at(batch.column(idx), i, val));
        if all_match {
            return Ok(Some(batch.slice(i, 1)));
        }
    }
    Ok(None)
}

/// **Bloom-pruned raw-Parquet point-lookup fast path.** Mirrors
/// [`read_all_gatling`]'s decline conditions exactly (schema evolution, any
/// delete file ⇒ [`FastLookup::Declined`], caller falls back to the Iceberg
/// engine's merge-on-read scan) — this only ever runs on a plain append-only,
/// single-schema table with no delete files, so bypassing the engine cannot
/// drop a deleted/updated row.
///
/// For each candidate data file, this reads the row-group metadata and — for
/// every key column whose Arrow type matches its [`Scalar`] variant — probes
/// that column's Parquet bloom filter (written by [`WriteProps::bloom_columns`](crate::WriteProps::bloom_columns),
/// read back via [`Sbbf::read_from_column_chunk`](parquet::bloom_filter::Sbbf::read_from_column_chunk)).
/// A row group whose bloom filter proves the key absent is skipped without
/// ever being decoded; surviving row groups are decoded and scanned row-by-row
/// for an exact match (bloom filters only prune at row-group granularity, so a
/// "maybe present" verdict still needs the exact check — same as a false-
/// positive on any bloom filter).
async fn lookup_gatling(
    table: &IceTable,
    key: &[(&str, Scalar)],
    as_of: Option<i64>,
) -> Result<FastLookup> {
    use iceberg::spec::{DataContentType, Manifest, ManifestContentType, ManifestStatus};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use parquet::bloom_filter::Sbbf;

    let metadata = table.metadata();

    // Schema evolution: see `read_all_gatling` — a raw decode can't apply the
    // field-id remap, defer to the engine.
    if metadata.schemas_iter().len() > 1 {
        return Ok(FastLookup::Declined);
    }

    let snapshot = match as_of {
        Some(id) => metadata.snapshot_by_id(id),
        None => metadata.current_snapshot(),
    };
    let Some(snapshot) = snapshot else {
        // No snapshot at all ⇒ genuinely nothing to find (matches
        // `read_all_gatling`'s "empty table" fast-path semantics).
        return Ok(FastLookup::Resolved(None, LookupGatlingStats::default()));
    };
    // An `as_of` id the metadata doesn't recognise: decline (let the engine
    // produce its normal "snapshot not found" error).
    if let Some(id) = as_of
        && metadata.snapshot_by_id(id).is_none()
    {
        return Ok(FastLookup::Declined);
    }

    let file_io = table.file_io();
    let manifest_list = snapshot.load_manifest_list(file_io, metadata).await?;

    let mut data_files: Vec<String> = Vec::new();
    for mf in manifest_list.entries() {
        // Any delete manifest ⇒ merge-on-read needed, defer to the engine.
        if mf.content == ManifestContentType::Deletes {
            return Ok(FastLookup::Declined);
        }
        let bytes = file_io.new_input(&mf.manifest_path)?.read().await?;
        let manifest = Manifest::parse_avro(&bytes)?;
        for entry in manifest.entries() {
            match entry.status() {
                ManifestStatus::Added | ManifestStatus::Existing => {}
                ManifestStatus::Deleted => continue,
            }
            let df = entry.data_file();
            match df.content_type() {
                DataContentType::Data => data_files.push(df.file_path().to_string()),
                DataContentType::EqualityDeletes | DataContentType::PositionDeletes => {
                    return Ok(FastLookup::Declined);
                }
            }
        }
    }
    data_files.sort();
    data_files.dedup();

    let mut stats = LookupGatlingStats::default();

    for path in &data_files {
        let bytes = file_io.new_input(path)?.read().await?;
        // Cheap (refcounted) clone: `bytes` feeds the bloom-filter reads below,
        // `bloom_src` is consumed by the record-batch reader builder.
        let bloom_src = bytes.clone();
        let builder = ParquetRecordBatchReaderBuilder::try_new(bloom_src)?;
        let arrow_schema = builder.schema().clone();

        // Resolve each key column to its Arrow field index, and require its
        // type to line up with the Scalar variant — anything else and we
        // can't safely bloom-prune OR exact-match, so decline the whole probe
        // (never guess; the engine's scan handles it correctly).
        let mut key_idx: Vec<usize> = Vec::with_capacity(key.len());
        for (col, val) in key {
            let Ok(idx) = arrow_schema.index_of(col) else {
                return Ok(FastLookup::Declined);
            };
            if !scalar_type_matches(val, arrow_schema.field(idx).data_type()) {
                return Ok(FastLookup::Declined);
            }
            key_idx.push(idx);
        }

        let rg_meta = builder.metadata().clone();
        let num_rg = rg_meta.num_row_groups();
        let mut candidate_rgs: Vec<usize> = Vec::with_capacity(num_rg);
        'rg: for rg_idx in 0..num_rg {
            stats.row_groups_seen += 1;
            let rg = rg_meta.row_group(rg_idx);
            for (&col_idx, (_, val)) in key_idx.iter().zip(key.iter()) {
                let col_meta = rg.column(col_idx);
                if let Some(bloom) = Sbbf::read_from_column_chunk(col_meta, &bytes)?
                    && scalar_bloom_says_absent(&bloom, val)
                {
                    stats.row_groups_skipped_by_bloom += 1;
                    continue 'rg;
                }
            }
            candidate_rgs.push(rg_idx);
        }

        if candidate_rgs.is_empty() {
            continue;
        }

        let reader = builder.with_row_groups(candidate_rgs).build()?;
        for batch in reader {
            let batch = batch?;
            if let Some(row) = first_matching_row(&batch, key)? {
                return Ok(FastLookup::Resolved(Some(row), stats));
            }
        }
    }

    Ok(FastLookup::Resolved(None, stats))
}

/// **Embedded delta-join probe (point lookup).** Resolve the single current row
/// whose equality-key column(s) in `key` match, as of a snapshot-pinned `as_of`
/// (time-travel) or — `as_of = None` — the table's latest snapshot.
///
/// This is the "externalize the join state, probe the latest at emit" idea (a
/// Flink/Fluss *delta join* probes an external PK-table for the current build-
/// side row) done **embedded**: skade's catalog *is* the point-lookup store, so
/// there is no external state service — the probe is a merge-on-read scan pinned
/// to a snapshot, pushed down to the matching key.
///
/// The scan is **equality-delete aware**: it runs through the engine's
/// merge-on-read path, so a key whose latest state is an equality-delete
/// (an upsert modelled as delete-old + append-new) resolves to the *new* row,
/// and a key that was deleted resolves to `None`. `key` is one or more
/// `(column, value)` equality constraints AND-ed together (the identity
/// columns); the predicate is both pushed down (file/row-group pruning) and
/// applied as an exact row filter, so the result is the matching row(s).
///
/// Returns `Ok(None)` when nothing matches (never inserted, or deleted). When
/// several rows share the key (a non-unique key on a log table) the first is
/// returned; use [`read_filtered`] for the full set.
pub async fn lookup(
    table: &IceTable,
    key: &[(&str, Scalar)],
    as_of: Option<i64>,
) -> Result<Option<RecordBatch>> {
    // Bloom-pruned raw-Parquet fast path (see `lookup_gatling`): on a plain
    // append-only, single-schema table with no delete files it probes each key
    // column's written bloom filter to skip whole row groups the key can't be
    // in, decoding only the survivors. Any precondition it can't guarantee
    // (schema evolution, delete files, a type it doesn't recognise, …) and it
    // declines, falling through to the engine's correctness-complete scan
    // below — exactly the `read_all`/`read_all_gatling` pattern.
    if let FastLookup::Resolved(row, _stats) = lookup_gatling(table, key, as_of).await? {
        return Ok(row);
    }

    // AND the per-column equality constraints into one pushdown predicate.
    let mut pred: Option<Predicate> = None;
    for (col, val) in key {
        let p = Reference::new(*col).equal_to(val.to_datum());
        pred = Some(match pred {
            Some(acc) => acc.and(p),
            None => p,
        });
    }

    let mut builder = table.scan().select_all();
    // Pin the probe to `as_of` (time-travel is free on the catalog); absent,
    // the current snapshot is used by the scan builder.
    if let Some(snap) = as_of {
        builder = builder.snapshot_id(snap);
    }
    if let Some(p) = pred {
        builder = builder.with_filter(p);
    }
    let mut stream = builder.build()?.to_arrow().await?;
    // Return the first batch that carries a matching row (the engine applies the
    // predicate as an exact RowFilter, so any returned row already matches).
    while let Some(batch) = stream.next().await {
        let batch = batch?;
        if batch.num_rows() > 0 {
            let one = batch.slice(0, 1);
            return Ok(Some(one));
        }
    }
    Ok(None)
}

/// Full-scan `table` and count rows without materializing the batches.
pub async fn scan_count(table: &IceTable) -> Result<u64> {
    let stream = table.scan().select_all().build()?.to_arrow().await?;
    Ok(stream
        .try_fold(0u64, |acc, batch| async move {
            Ok(acc + batch.num_rows() as u64)
        })
        .await?)
}

/// One equality-delete file added in a delta window: the file path plus the
/// Iceberg field-ids that define row equality (`equality_ids`). The delete
/// applies to any row whose values in those fields match a row in the file —
/// for a graph that means "remove the node(s) with this identity".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqualityDeleteFile {
    /// Absolute path of the equality-delete parquet file.
    pub path: String,
    /// Iceberg field-ids that define equality (the identity columns).
    pub equality_ids: Vec<i32>,
}

/// What a [`read_delta`] resolved to: the new snapshots and the data files they
/// appended. Returned so a caller can see/assert *what* the delta was (which
/// snapshots advanced, which files were read) without re-deriving it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeltaPlan {
    /// Snapshot ids strictly after `from`, up to and including `to`, oldest-first.
    pub snapshots: Vec<i64>,
    /// Absolute data-file paths added by those snapshots (the rows to read).
    pub added_files: Vec<String>,
    /// Equality-delete files added in the window — the rows they name are
    /// **removed** (CDC deletes). Read with [`read_equality_deletes`].
    pub delete_files: Vec<EqualityDeleteFile>,
    /// `true` when a commit in the window removes rows in a way the append +
    /// equality-delete delta can't express — a **position**-delete file
    /// (deletes by file+row-offset, not by identity) or a non-`Append`/non-
    /// `Delete` operation (overwrite/replace). The caller should re-read the
    /// whole `to` snapshot instead. An `Append` (inserts) or a `Delete`
    /// operation that only adds *equality*-delete files does **not** set this.
    pub needs_full_reload: bool,
}

/// **Incremental read.** The data files appended to `table` by the snapshots
/// strictly after `from` up to (and including) `to`, read into Arrow batches —
/// *only* those files, not the whole table.
///
/// iceberg-rust 0.9.1 exposes no incremental/changelog scan (only time-travel
/// `snapshot_id()`), so this is built from the manifest layer: walk the snapshot
/// lineage (`parent_snapshot_id`) from `to` back to `from`, then for each new
/// snapshot take the **data** manifests it added (`ManifestFile.added_snapshot_id`)
/// and their `Added` entries — those `DataFile`s are exactly the appended rows.
///
/// `from = None` means "from the beginning" (every data file up to `to`).
///
/// **CDC-aware.** It sees inserts (appended data files) **and** identity-based
/// deletes (equality-delete files added by `Delete` snapshots): the returned
/// [`DeltaPlan::delete_files`] names them, and [`read_equality_deletes`] reads
/// the deleted-row identities. It does **not** handle *position* deletes (delete
/// by file+row-offset) or overwrite/replace commits — those set
/// `DeltaPlan.needs_full_reload` and return **no** batches (the caller does a
/// full [`read_all`] of `to` instead).
pub async fn read_delta(
    table: &IceTable,
    from: Option<i64>,
    to: i64,
) -> Result<(Vec<RecordBatch>, DeltaPlan)> {
    use iceberg::spec::{
        DataContentType, Manifest, ManifestContentType, ManifestStatus, Operation,
    };
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let metadata = table.metadata();
    let file_io = table.file_io();
    let mut plan = DeltaPlan::default();
    if from == Some(to) {
        return Ok((Vec::new(), plan)); // already caught up
    }

    // Lineage: to → parent → … until we hit `from` (exclusive) or the root.
    let mut chain: Vec<i64> = Vec::new();
    let mut cur = Some(to);
    while let Some(id) = cur {
        if Some(id) == from {
            break;
        }
        let snap = metadata
            .snapshot_by_id(id)
            .ok_or_else(|| SkadeError::Other(format!("snapshot {id} not in lineage")))?;
        // Append (inserts) and Delete (equality-delete files) are both
        // expressible as a CDC delta. Overwrite/Replace rewrite rows in place,
        // which an additive delta can't follow — fall back to a full re-read.
        if !matches!(
            snap.summary().operation,
            Operation::Append | Operation::Delete
        ) {
            plan.needs_full_reload = true;
        }
        chain.push(id);
        cur = snap.parent_snapshot_id();
    }
    chain.reverse();
    plan.snapshots = chain.clone();
    if plan.needs_full_reload {
        return Ok((Vec::new(), plan));
    }
    let want: std::collections::HashSet<i64> = chain.into_iter().collect();
    if want.is_empty() {
        return Ok((Vec::new(), plan));
    }

    // The target's manifest list names every live manifest; each carries
    // `added_snapshot_id`. Take the manifests added in our window — both Data
    // (inserts) and Deletes (equality/position deletes).
    let target = metadata
        .snapshot_by_id(to)
        .ok_or_else(|| SkadeError::Other(format!("target snapshot {to} not found")))?;
    let manifest_list = target.load_manifest_list(file_io, metadata).await?;
    for mf in manifest_list.entries() {
        if !want.contains(&mf.added_snapshot_id) {
            continue;
        }
        let bytes = file_io.new_input(&mf.manifest_path)?.read().await?;
        let manifest = Manifest::parse_avro(&bytes)?;
        for entry in manifest.entries() {
            if entry.status() != ManifestStatus::Added {
                continue;
            }
            let df = entry.data_file();
            match df.content_type() {
                DataContentType::Data if mf.content == ManifestContentType::Data => {
                    plan.added_files.push(df.file_path().to_string());
                }
                DataContentType::EqualityDeletes => {
                    plan.delete_files.push(EqualityDeleteFile {
                        path: df.file_path().to_string(),
                        equality_ids: df.equality_ids().unwrap_or_default(),
                    });
                }
                // Position deletes name rows by (file, offset), not identity —
                // a graph upsert keyed on a business id can't resolve them, so
                // re-read the whole snapshot to stay correct.
                DataContentType::PositionDeletes => {
                    plan.needs_full_reload = true;
                }
                _ => {}
            }
        }
    }
    if plan.needs_full_reload {
        plan.added_files.clear();
        plan.delete_files.clear();
        return Ok((Vec::new(), plan));
    }
    plan.added_files.sort();
    plan.added_files.dedup();
    plan.delete_files.sort_by(|a, b| a.path.cmp(&b.path));
    plan.delete_files.dedup();

    // Read only those data files, through Iceberg's FileIO. The async reads are
    // I/O; the CPU-bound Parquet decode then fans across all cores via the ONE
    // fork-join engine (gatling), results kept in file order.
    let mut raw = Vec::with_capacity(plan.added_files.len());
    for path in &plan.added_files {
        raw.push(file_io.new_input(path)?.read().await?);
    }
    let decoded = gatling_map_owned(raw, |bytes| -> Result<Vec<RecordBatch>> {
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?.build()?;
        reader
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(SkadeError::from)
    });
    let mut batches = Vec::new();
    for d in decoded {
        batches.extend(d?);
    }
    Ok((batches, plan))
}

/// Read the deleted-row identities out of the equality-delete files in a
/// [`DeltaPlan`]. An equality-delete file is a parquet file whose columns are
/// the equality fields; each row names rows to delete (any data row whose
/// equality-field values match). Returns one `(equality_ids, batches)` pair per
/// file so the caller knows which columns define the deleted identity.
pub async fn read_equality_deletes(
    table: &IceTable,
    plan: &DeltaPlan,
) -> Result<Vec<(Vec<i32>, Vec<RecordBatch>)>> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let file_io = table.file_io();
    // Async-read each delete file's bytes (I/O), then fan the CPU-bound Parquet
    // decode across all cores via the ONE fork-join engine (gatling), carrying
    // each file's equality_ids alongside its bytes; order preserved.
    let mut raw = Vec::with_capacity(plan.delete_files.len());
    for d in &plan.delete_files {
        let bytes = file_io.new_input(&d.path)?.read().await?;
        raw.push((d.equality_ids.clone(), bytes));
    }
    let decoded = gatling_map_owned(
        raw,
        |(ids, bytes)| -> Result<(Vec<i32>, Vec<RecordBatch>)> {
            let reader = ParquetRecordBatchReaderBuilder::try_new(bytes)?.build()?;
            let batches = reader
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(SkadeError::from)?;
            Ok((ids, batches))
        },
    );
    decoded.into_iter().collect::<Result<Vec<_>>>()
}

// ===========================================================================
// CDC changelog encoder — a re-tagging layer over `read_delta` +
// `read_equality_deletes`. This is the natural home for the vocabulary + logic
// knut-bifrost currently keeps private (`tag_change_type`/`widen_to_schema`), so
// bifrost can import `skade::read_changelog` and delete its copy.
// ===========================================================================

/// CDC op vocabulary — the exact strings knut-bifrost's `mapping.rs` uses, so a
/// skade changelog and a bifrost/Flink/Spark consumer agree with **zero
/// translation** (this is also Iceberg's `create_changelog_view` vocabulary).
pub mod change_type {
    /// A newly inserted row.
    pub const INSERT: &str = "INSERT";
    /// The pre-image of an updated row (a PK table; usually dropped downstream).
    pub const UPDATE_BEFORE: &str = "UPDATE_BEFORE";
    /// The post-image of an updated row (a PK table).
    pub const UPDATE_AFTER: &str = "UPDATE_AFTER";
    /// A deleted row (named by its identity columns).
    pub const DELETE: &str = "DELETE";
    /// The sentinel Arrow `Utf8` column name carrying the op string on each row.
    pub const COLUMN: &str = "_change_type";
}

/// How a table's changelog collapses (Fluss/Paimon's LogTable vs PrimaryKeyTable
/// distinction, on ONE Iceberg table — no RocksDB/LSM):
///
/// * [`TableKind::Log`] — append-only: a matched insert+delete of one identity
///   in a window **cancels** (net nothing).
/// * [`TableKind::PrimaryKey`] — upsert: a matched delete+insert of one key is an
///   **update**, emitted as `UPDATE_BEFORE` (old identity) + `UPDATE_AFTER` (new
///   row).
///
/// Derived from the schema's Iceberg **identifier-field-ids** (the row-identity
/// marker); a table with none is a [`TableKind::Log`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableKind {
    /// Append-only log table (no primary key).
    Log,
    /// Primary-key (upsert) table; carries the identity field-ids.
    PrimaryKey(Vec<i32>),
}

impl TableKind {
    /// Classify `table` from its current schema's identifier-field-ids.
    pub fn of(table: &IceTable) -> TableKind {
        let ids: Vec<i32> = table
            .metadata()
            .current_schema()
            .identifier_field_ids()
            .collect();
        if ids.is_empty() {
            TableKind::Log
        } else {
            TableKind::PrimaryKey(ids)
        }
    }

    /// Whether this is a primary-key (upsert) table.
    pub fn is_primary_key(&self) -> bool {
        matches!(self, TableKind::PrimaryKey(_))
    }
}

/// A CDC changelog window for a [`DeltaPlan`]: every row carries a
/// [`change_type::COLUMN`] `Utf8` op tag. Inserts are tagged
/// [`INSERT`](change_type::INSERT); equality-deleted identities are tagged
/// [`DELETE`](change_type::DELETE) and widened to the full table schema (nulls
/// for the non-identity columns). Built purely from [`read_delta`] +
/// [`read_equality_deletes`] — a re-tagging layer, **not** a new scan path.
///
/// Call [`ChangelogBatch::collapsed`] for net-change semantics (drop
/// insert-then-delete on a log table; fold delete+insert into `UPDATE_*` on a PK
/// table), and [`ChangelogBatch::project_columns`] to prune columns.
pub struct ChangelogBatch {
    /// The change rows, each carrying the `_change_type` column. Uniform schema
    /// ([`ChangelogBatch::schema`]).
    pub rows: Vec<RecordBatch>,
    /// The snapshots/files this window covered (see [`DeltaPlan`]).
    pub plan: DeltaPlan,
    /// The new cursor: advance the consumer to here after applying `rows`.
    pub to_snapshot: i64,
    /// Whether this table collapses as a log or a PK table.
    pub kind: TableKind,
    /// Identity (delete equality) columns used to join inserts↔deletes in
    /// [`ChangelogBatch::collapsed`]. Empty when the window carries no deletes.
    key_columns: Vec<String>,
    /// The uniform output schema of every row batch (table schema, all data
    /// columns made nullable, plus the non-null `_change_type` column).
    schema: ArrowSchemaRef,
}

/// The changelog output schema: every base field made **nullable** (a DELETE row
/// populates only its identity columns) plus a non-null `_change_type` `Utf8`
/// column appended last.
fn changelog_schema(base: &ArrowSchemaRef) -> ArrowSchemaRef {
    let mut fields: Vec<Field> = base
        .fields()
        .iter()
        .map(|f| f.as_ref().clone().with_nullable(true))
        .collect();
    fields.push(Field::new(change_type::COLUMN, DataType::Utf8, false));
    Arc::new(ArrowSchema::new(fields))
}

/// Build one output-schema row batch from `src`, tagging every row `tag`.
/// Columns present in `src` (matched by name, cast if needed) pass through;
/// absent columns (a DELETE's non-identity columns) become nulls.
fn build_row_batch(out: &ArrowSchemaRef, src: &RecordBatch, tag: &str) -> Result<RecordBatch> {
    let len = src.num_rows();
    let mut cols: Vec<ArrayRef> = Vec::with_capacity(out.fields().len());
    for f in out.fields().iter() {
        if f.name() == change_type::COLUMN {
            cols.push(Arc::new(StringArray::from(vec![tag; len])) as ArrayRef);
        } else if let Some(c) = src.column_by_name(f.name()) {
            if c.data_type() == f.data_type() {
                cols.push(Arc::clone(c));
            } else {
                cols.push(arrow_cast::cast(c, f.data_type())?);
            }
        } else {
            cols.push(new_null_array(f.data_type(), len));
        }
    }
    Ok(RecordBatch::try_new(out.clone(), cols)?)
}

/// **CDC changelog read.** `read_delta`'s inserts tagged `INSERT` ∪
/// `read_equality_deletes`'s identities tagged `DELETE`, schema-aligned into one
/// [`ChangelogBatch`]. When the window needs a full reload (overwrite / position
/// delete — [`DeltaPlan::needs_full_reload`]), it re-reads the whole `to`
/// snapshot as an `INSERT` stream instead of a delta (exactly bifrost's rule).
///
/// `from = None` starts from the beginning (full history up to `to`). The result
/// is the raw per-row tagging; call [`ChangelogBatch::collapsed`] for net-change
/// semantics.
pub async fn read_changelog(
    table: &IceTable,
    from: Option<i64>,
    to: i64,
) -> Result<ChangelogBatch> {
    let base = arrow_schema_of(table)?;
    let out_schema = changelog_schema(&base);
    let kind = TableKind::of(table);
    let (inserts, plan) = read_delta(table, from, to).await?;

    // Full reload: the additive delta can't express an overwrite / position
    // delete — re-read the whole `to` snapshot as a pure INSERT stream.
    if plan.needs_full_reload {
        let all = read_all(table).await?;
        let mut rows = Vec::with_capacity(all.len());
        for b in &all {
            rows.push(build_row_batch(&out_schema, b, change_type::INSERT)?);
        }
        return Ok(ChangelogBatch {
            rows,
            plan,
            to_snapshot: to,
            kind,
            key_columns: Vec::new(),
            schema: out_schema,
        });
    }

    let mut rows = Vec::new();
    for b in &inserts {
        rows.push(build_row_batch(&out_schema, b, change_type::INSERT)?);
    }

    // Equality-deleted identities → DELETE, widened to the output schema. The
    // delete files' equality columns are the join key `collapsed()` uses.
    let mut key_columns: Vec<String> = Vec::new();
    let dels = read_equality_deletes(table, &plan).await?;
    let schema = table.metadata().current_schema();
    for (eq_ids, batches) in &dels {
        for id in eq_ids {
            if let Some(name) = schema.name_by_field_id(*id) {
                if !key_columns.iter().any(|k| k == name) {
                    key_columns.push(name.to_string());
                }
            }
        }
        for b in batches {
            rows.push(build_row_batch(&out_schema, b, change_type::DELETE)?);
        }
    }

    Ok(ChangelogBatch {
        rows,
        plan,
        to_snapshot: to,
        kind,
        key_columns,
        schema: out_schema,
    })
}

/// The `_change_type` column of a changelog batch.
fn change_col(b: &RecordBatch) -> Result<&StringArray> {
    b.column_by_name(change_type::COLUMN)
        .and_then(|c| c.as_any().downcast_ref::<StringArray>())
        .ok_or_else(|| SkadeError::other("changelog batch missing _change_type column"))
}

/// The join key for row `i`: the identity columns joined with `\x1f`.
fn row_key(b: &RecordBatch, key_idx: &[usize], i: usize) -> Result<String> {
    let mut key = String::new();
    for (n, &idx) in key_idx.iter().enumerate() {
        if n > 0 {
            key.push('\x1f');
        }
        key.push_str(&arrow_cast::display::array_value_to_string(
            b.column(idx),
            i,
        )?);
    }
    Ok(key)
}

/// Rebuild `b` replacing its `_change_type` column with `tags`.
fn replace_change_col(b: &RecordBatch, tags: &[&str]) -> Result<RecordBatch> {
    let schema = b.schema();
    let idx = schema.index_of(change_type::COLUMN)?;
    let mut cols: Vec<ArrayRef> = b.columns().to_vec();
    cols[idx] = Arc::new(StringArray::from(tags.to_vec())) as ArrayRef;
    Ok(RecordBatch::try_new(schema, cols)?)
}

impl ChangelogBatch {
    /// **Net-change collapse.** Join inserts and deletes on the delete files'
    /// identity columns:
    ///
    /// * [`TableKind::Log`] — a key present as **both** an INSERT and a DELETE in
    ///   the window cancels (both rows dropped: insert-then-delete nets nothing).
    /// * [`TableKind::PrimaryKey`] — such a key is an update: its DELETE row is
    ///   re-tagged [`UPDATE_BEFORE`](change_type::UPDATE_BEFORE) and its INSERT
    ///   row [`UPDATE_AFTER`](change_type::UPDATE_AFTER).
    ///
    /// Unmatched inserts stay `INSERT`; unmatched deletes stay `DELETE`. A
    /// no-delete window or a full-reload batch is returned unchanged. Call this
    /// **before** [`project_columns`](Self::project_columns) (collapse needs the
    /// identity columns).
    pub fn collapsed(self) -> Result<ChangelogBatch> {
        if self.key_columns.is_empty() || self.plan.needs_full_reload {
            return Ok(self);
        }
        let key_idx: Vec<usize> = self
            .key_columns
            .iter()
            .filter_map(|n| self.schema.index_of(n).ok())
            .collect();
        if key_idx.is_empty() {
            return Ok(self);
        }

        // Pass 1: which identities appear as INSERT, as DELETE.
        let mut inserted: HashSet<String> = HashSet::new();
        let mut deleted: HashSet<String> = HashSet::new();
        for b in &self.rows {
            let tags = change_col(b)?;
            for i in 0..b.num_rows() {
                let key = row_key(b, &key_idx, i)?;
                match tags.value(i) {
                    change_type::INSERT => {
                        inserted.insert(key);
                    }
                    change_type::DELETE => {
                        deleted.insert(key);
                    }
                    _ => {}
                }
            }
        }
        let both: HashSet<String> = inserted.intersection(&deleted).cloned().collect();
        let pk = self.kind.is_primary_key();

        // Pass 2: re-tag matched rows; drop cancelled rows (log tables).
        let mut out_rows = Vec::new();
        for b in &self.rows {
            let tags = change_col(b)?;
            let mut new_tags: Vec<&str> = Vec::with_capacity(b.num_rows());
            let mut keep: Vec<bool> = Vec::with_capacity(b.num_rows());
            for i in 0..b.num_rows() {
                let key = row_key(b, &key_idx, i)?;
                let matched = both.contains(&key);
                let (tag, keep_row) = match tags.value(i) {
                    change_type::INSERT if matched => {
                        if pk {
                            (change_type::UPDATE_AFTER, true)
                        } else {
                            (change_type::INSERT, false)
                        }
                    }
                    change_type::DELETE if matched => {
                        if pk {
                            (change_type::UPDATE_BEFORE, true)
                        } else {
                            (change_type::DELETE, false)
                        }
                    }
                    other => (other, true),
                };
                new_tags.push(tag);
                keep.push(keep_row);
            }
            let rebuilt = replace_change_col(b, &new_tags)?;
            let filtered = filter_record_batch(&rebuilt, &BooleanArray::from(keep))?;
            if filtered.num_rows() > 0 {
                out_rows.push(filtered);
            }
        }

        Ok(ChangelogBatch {
            rows: out_rows,
            plan: self.plan,
            to_snapshot: self.to_snapshot,
            kind: self.kind,
            key_columns: self.key_columns,
            schema: self.schema,
        })
    }

    /// **Column pruning.** Keep only `columns` (plus the `_change_type` sentinel,
    /// always retained) — the Fluss columnar win, free from Arrow projection.
    /// Empty `columns` is a no-op. Prune **after** [`collapsed`](Self::collapsed)
    /// (collapse needs the identity columns).
    pub fn project_columns(self, columns: &[&str]) -> Result<ChangelogBatch> {
        if columns.is_empty() {
            return Ok(self);
        }
        let mut want: Vec<&str> = columns.to_vec();
        if !want.contains(&change_type::COLUMN) {
            want.push(change_type::COLUMN);
        }
        let indices: Vec<usize> = want
            .iter()
            .filter_map(|n| self.schema.index_of(n).ok())
            .collect();
        let new_fields: Vec<Field> = indices
            .iter()
            .map(|&i| self.schema.field(i).clone())
            .collect();
        let new_schema: ArrowSchemaRef = Arc::new(ArrowSchema::new(new_fields));
        let mut rows = Vec::with_capacity(self.rows.len());
        for b in &self.rows {
            let cols: Vec<ArrayRef> = indices.iter().map(|&i| Arc::clone(b.column(i))).collect();
            rows.push(RecordBatch::try_new(new_schema.clone(), cols)?);
        }
        Ok(ChangelogBatch {
            rows,
            plan: self.plan,
            to_snapshot: self.to_snapshot,
            kind: self.kind,
            key_columns: self.key_columns,
            schema: new_schema,
        })
    }

    /// Total change rows across all batches.
    pub fn num_rows(&self) -> usize {
        self.rows.iter().map(|b| b.num_rows()).sum()
    }

    /// The uniform output schema every row batch carries.
    pub fn schema(&self) -> &ArrowSchemaRef {
        &self.schema
    }
}

#[cfg(test)]
mod tests {
    //! White-box test for the bloom-pruned `lookup_gatling` fast path (called
    //! directly, bypassing `Table::lookup`, so the assertions can see the
    //! pruning stats — not just the returned row).

    use std::sync::Arc;

    use arrow_array::{Int64Array, RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema as ArrowSchema};
    use parquet::basic::Compression;

    use super::*;
    use crate::WriteProps;

    fn two_symbol_schema() -> ArrowSchema {
        ArrowSchema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("symbol", DataType::Utf8, false),
        ])
    }

    /// One 100-row batch split cleanly in two by `symbol`: rows 0..50 are
    /// "AAA", rows 50..100 are "ZZZ" — with a 50-row `row_group_size` this
    /// writes exactly two row groups, each containing only one symbol value,
    /// so a bloom filter on `symbol` can prove the *other* group empty.
    fn two_symbol_batch() -> RecordBatch {
        let ids: Vec<i64> = (0..100).collect();
        let syms: Vec<String> = (0..100)
            .map(|i| {
                if i < 50 {
                    "AAA".to_string()
                } else {
                    "ZZZ".to_string()
                }
            })
            .collect();
        RecordBatch::try_new(
            Arc::new(two_symbol_schema()),
            vec![
                Arc::new(Int64Array::from(ids)),
                Arc::new(StringArray::from(syms)),
            ],
        )
        .unwrap()
    }

    /// A bloom filter on `symbol` lets the fast path skip the row group that
    /// cannot contain the probed key, and still returns the exact right row.
    #[tokio::test]
    async fn lookup_gatling_skips_row_group_via_bloom() {
        let tmp = tempfile::tempdir().unwrap();
        let wh = crate::open(tmp.path().join("lake")).await.unwrap();

        let props = WriteProps::new(Compression::UNCOMPRESSED)
            .bloom_columns(["symbol"])
            .row_group_size(50);
        let mut t = wh
            .create_table("trades", &two_symbol_schema())
            .await
            .unwrap()
            .write_props(props);
        t.append(&[two_symbol_batch()]).await.unwrap();

        // Probing "ZZZ" (only in row group 1) should skip row group 0.
        let key = [("symbol", Scalar::Str("ZZZ".to_string()))];
        let outcome = lookup_gatling(t.inner(), &key, None).await.unwrap();
        let FastLookup::Resolved(row, stats) = outcome else {
            panic!("fast path declined; expected it to resolve directly");
        };
        assert_eq!(stats.row_groups_seen, 2, "two 50-row groups written");
        assert_eq!(
            stats.row_groups_skipped_by_bloom, 1,
            "bloom on `symbol` should prove row group 0 (\"AAA\" only) absent"
        );
        let row = row.expect("ZZZ is in the table");
        let id_col = row.column_by_name("id").unwrap();
        let id = id_col
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap()
            .value(0);
        assert!(
            (50..100).contains(&id),
            "matched row should come from the ZZZ half, got id={id}"
        );

        // Probing "AAA" (only in row group 0) should skip row group 1, the
        // mirror image of the above — proves the pruning isn't one-directional.
        let key = [("symbol", Scalar::Str("AAA".to_string()))];
        let outcome = lookup_gatling(t.inner(), &key, None).await.unwrap();
        let FastLookup::Resolved(row, stats) = outcome else {
            panic!("fast path declined; expected it to resolve directly");
        };
        assert_eq!(stats.row_groups_skipped_by_bloom, 1);
        let row = row.expect("AAA is in the table");
        let id_col = row.column_by_name("id").unwrap();
        let id = id_col
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap()
            .value(0);
        assert!(
            (0..50).contains(&id),
            "matched row should come from the AAA half, got id={id}"
        );

        // A key that isn't in the table at all: both row groups' blooms should
        // prove it absent and the probe resolves to `None` without a match.
        let key = [("symbol", Scalar::Str("NOPE".to_string()))];
        let outcome = lookup_gatling(t.inner(), &key, None).await.unwrap();
        let FastLookup::Resolved(row, stats) = outcome else {
            panic!("fast path declined; expected it to resolve directly");
        };
        assert!(row.is_none(), "NOPE was never written");
        assert_eq!(
            stats.row_groups_skipped_by_bloom, 2,
            "neither row group's bloom can contain a never-written key"
        );
    }

    /// End-to-end through the public API: `Table::lookup` (which calls
    /// `lookup_gatling` internally) returns the right row via the fast path.
    #[tokio::test]
    async fn table_lookup_uses_bloom_fast_path() {
        let tmp = tempfile::tempdir().unwrap();
        let wh = crate::open(tmp.path().join("lake")).await.unwrap();

        let props = WriteProps::new(Compression::UNCOMPRESSED)
            .bloom_columns(["symbol"])
            .row_group_size(50);
        let mut t = wh
            .create_table("trades2", &two_symbol_schema())
            .await
            .unwrap()
            .write_props(props);
        t.append(&[two_symbol_batch()]).await.unwrap();

        let row = t
            .lookup(&[("id", Scalar::I64(73))], None)
            .await
            .unwrap()
            .expect("id 73 exists");
        let sym = row
            .column_by_name("symbol")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap()
            .value(0);
        assert_eq!(sym, "ZZZ");

        assert!(
            t.lookup(&[("id", Scalar::I64(999))], None)
                .await
                .unwrap()
                .is_none(),
            "id 999 was never written"
        );
    }
}
