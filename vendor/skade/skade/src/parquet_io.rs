//! Windowed, all-core Parquet reading.
//!
//! The building blocks for bounded-memory bulk ingest (billions of rows):
//! [`parquet_layout`] inspects a file without reading data, [`rowgroup_windows`]
//! groups its row groups into ~`window_rows`-sized windows, and
//! [`read_row_groups`] decodes one window across all cores on the ONE fork-join
//! engine (znippy-zoomies `gatling_forkjoin`) — no private thread pool. A
//! streaming ingest reads a window, appends it, frees it, then reads the next —
//! peak memory is one window, not the whole file.
//!
//! (Lifted from skade-katalog's bench data-plane, where it feeds the OSM /
//! GeoParquet ingest benchmarks.)

use std::path::Path;

use arrow_array::RecordBatch;
use arrow_schema::SchemaRef as ArrowSchemaRef;
use iceberg::spec::Schema;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use znippy_zoomies::gatling_forkjoin::gatling_map_owned;

use crate::bridge::arrow_to_iceberg;
use crate::error::{Result, SkadeError};

/// Open a Parquet file and return (derived Iceberg schema, the file's Arrow
/// schema, per-row-group row counts) — without reading any data.
pub fn parquet_layout(path: impl AsRef<Path>) -> Result<(Schema, ArrowSchemaRef, Vec<usize>)> {
    let path = path.as_ref();
    let file = std::fs::File::open(path)
        .map_err(|e| SkadeError::Other(format!("open parquet {}: {e}", path.display())))?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let ice = arrow_to_iceberg(builder.schema())?;
    let file_schema: ArrowSchemaRef = builder.schema().clone();
    let meta = builder.metadata();
    let rg_rows: Vec<usize> = (0..meta.num_row_groups())
        .map(|i| meta.row_group(i).num_rows() as usize)
        .collect();
    Ok((ice, file_schema, rg_rows))
}

/// Group row-group indices into windows whose row counts each sum to about
/// `window_rows`, stopping once `max_rows` total is covered. Returns one `Vec`
/// of row-group indices per window — feed each to [`read_row_groups`].
pub fn rowgroup_windows(rg_rows: &[usize], window_rows: usize, max_rows: usize) -> Vec<Vec<usize>> {
    let win = window_rows.max(1);
    let mut windows: Vec<Vec<usize>> = Vec::new();
    let mut cur: Vec<usize> = Vec::new();
    let (mut cur_rows, mut total) = (0usize, 0usize);
    for (i, &rows) in rg_rows.iter().enumerate() {
        if total >= max_rows {
            break;
        }
        cur.push(i);
        cur_rows += rows;
        total += rows;
        if cur_rows >= win {
            windows.push(std::mem::take(&mut cur));
            cur_rows = 0;
        }
    }
    if !cur.is_empty() {
        windows.push(cur);
    }
    windows
}

/// Read exactly the row groups in `rgs`, decoded in `rows_per_batch` batches.
/// The row groups are split into up to `threads` buckets and each bucket is
/// decoded on its own no-barrier worker of the ONE fork-join engine (gatling) —
/// not a private OS-thread pool (Parquet page decompression is single-threaded
/// per reader, so a many-row-group file otherwise pins one core). Batches keep
/// the file's own Arrow schema ([`crate::recast`] them to a table's field-id
/// schema before ingest). Batch order across buckets is not preserved.
pub fn read_row_groups(
    path: impl AsRef<Path>,
    rgs: &[usize],
    rows_per_batch: usize,
    threads: usize,
) -> Result<Vec<RecordBatch>> {
    let path = path.as_ref();
    if rgs.is_empty() {
        return Ok(Vec::new());
    }
    let nbuckets = threads.max(1).min(rgs.len());
    // Round-robin row groups across buckets for even load (one gatling worker
    // per bucket).
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); nbuckets];
    for (k, rg) in rgs.iter().copied().enumerate() {
        buckets[k % nbuckets].push(rg);
    }
    let rpb = rows_per_batch.max(1);
    // The ONE fork-join engine (znippy-zoomies `gatling_forkjoin`) decodes each
    // bucket on its own no-barrier worker (Parquet page decompression is
    // single-threaded per reader). `path` is shared read-only across workers.
    let path_buf = path.to_path_buf();
    let buckets: Vec<Vec<usize>> = buckets.into_iter().filter(|b| !b.is_empty()).collect();
    let results = gatling_map_owned(buckets, |bucket| -> Result<Vec<RecordBatch>> {
        let f = std::fs::File::open(&path_buf)?;
        let rdr = ParquetRecordBatchReaderBuilder::try_new(f)?
            .with_row_groups(bucket)
            .with_batch_size(rpb)
            .build()?;
        rdr.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(SkadeError::from)
    });
    let mut out = Vec::new();
    for r in results {
        out.extend(r?);
    }
    Ok(out)
}

/// A bounded-memory, all-core **streaming** window reader over one Parquet file.
///
/// This is the single-call composition of [`parquet_layout`] +
/// [`rowgroup_windows`] + [`read_row_groups`]: [`ParquetWindows::open`] inspects
/// the file (no data read) and precomputes the row-group windows; each
/// [`Iterator::next`] decodes exactly ONE window across all cores (gatling) and
/// yields its `RecordBatch`es. Peak memory is one window, never the whole file,
/// so a consumer can stream billions of rows and process-then-drop each window.
///
/// It is the intended **reuse surface** for a map/geo consumer (e.g. korp's
/// `MapLayer` OSM source): open an OSM/GeoParquet `nodes.parquet`, then stream
/// windows of geometry rows viewport-by-viewport rather than re-parsing the file.
/// The file's own Arrow schema is returned up front (batches keep it — call
/// [`crate::recast`] before ingesting into a field-id table).
///
/// ```no_run
/// # fn run() -> skade::Result<()> {
/// let (ice_schema, arrow_schema, windows) =
///     skade::ParquetWindows::open("nodes.parquet", 1_000_000, usize::MAX, 8192, 8)?;
/// let _ = (ice_schema, arrow_schema);
/// for window in windows {
///     let batches = window?;              // one window's worth, all-core decoded
///     // … draw / ingest / drop; peak memory stays at one window …
///     let _rows: usize = batches.iter().map(|b| b.num_rows()).sum();
/// }
/// # Ok(()) }
/// ```
pub struct ParquetWindows {
    path: std::path::PathBuf,
    windows: std::vec::IntoIter<Vec<usize>>,
    rows_per_batch: usize,
    threads: usize,
}

impl ParquetWindows {
    /// Open `path`, derive its schema + row-group layout, and precompute the
    /// windows (each ~`window_rows` rows, stopping after `max_rows` total).
    /// Returns the derived Iceberg [`Schema`], the file's Arrow schema, and the
    /// streaming iterator. Each yielded window decodes in `rows_per_batch`
    /// batches split across up to `threads` gatling workers. Reads no row data.
    pub fn open(
        path: impl AsRef<Path>,
        window_rows: usize,
        max_rows: usize,
        rows_per_batch: usize,
        threads: usize,
    ) -> Result<(Schema, ArrowSchemaRef, Self)> {
        let path = path.as_ref();
        let (ice, file_schema, rg_rows) = parquet_layout(path)?;
        let windows = rowgroup_windows(&rg_rows, window_rows, max_rows);
        let reader = ParquetWindows {
            path: path.to_path_buf(),
            windows: windows.into_iter(),
            rows_per_batch: rows_per_batch.max(1),
            threads: threads.max(1),
        };
        Ok((ice, file_schema, reader))
    }

    /// Number of windows not yet yielded.
    pub fn windows_remaining(&self) -> usize {
        self.windows.len()
    }
}

impl Iterator for ParquetWindows {
    type Item = Result<Vec<RecordBatch>>;

    fn next(&mut self) -> Option<Self::Item> {
        let rgs = self.windows.next()?;
        Some(read_row_groups(
            &self.path,
            &rgs,
            self.rows_per_batch,
            self.threads,
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.windows.len();
        (n, Some(n))
    }
}

impl ExactSizeIterator for ParquetWindows {}
