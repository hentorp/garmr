//! Data-plane: ingest rows into an Iceberg table (Parquet data files +
//! `fast_append` commits) and scan them back. Runs over whatever `FileIO` the
//! catalog was built with — local FS or, for the vs-competitor benchmark, a
//! shared RustFS S3 warehouse.
//!
//! Schema is a flat OSM **node** projection: `id:long, lat:double, lon:double,
//! tags:string` (tags joined `k=v;…`). Ways/relations/geometry are out of scope
//! — nodes give a clean columnar table that exercises write + scan throughput.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use arrow_array::{ArrayRef, Float64Array, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Schema as ArrowSchema, SchemaRef as ArrowSchemaRef};
use futures::TryStreamExt;
use iceberg::spec::{DataFileFormat, NestedField, PrimitiveType, Schema, Type};
use iceberg::table::Table;
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::writer::base_writer::data_file_writer::DataFileWriterBuilder;
use iceberg::writer::file_writer::location_generator::{
    DefaultFileNameGenerator, DefaultLocationGenerator,
};
use iceberg::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
use iceberg::writer::file_writer::ParquetWriterBuilder;
use iceberg::writer::{IcebergWriter, IcebergWriterBuilder};
use iceberg::Catalog;
use iceberg::TableIdent;
use parquet::file::properties::WriterProperties;

/// Iceberg schema for the flat OSM-node table.
pub fn node_schema() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
            NestedField::required(2, "lat", Type::Primitive(PrimitiveType::Double)).into(),
            NestedField::required(3, "lon", Type::Primitive(PrimitiveType::Double)).into(),
            NestedField::required(4, "tags", Type::Primitive(PrimitiveType::String)).into(),
        ])
        .build()
        .expect("node schema")
}

/// One column-oriented batch of nodes.
#[derive(Default)]
pub struct NodeColumns {
    pub id: Vec<i64>,
    pub lat: Vec<f64>,
    pub lon: Vec<f64>,
    pub tags: Vec<String>,
}

impl NodeColumns {
    pub fn len(&self) -> usize {
        self.id.len()
    }
    pub fn is_empty(&self) -> bool {
        self.id.is_empty()
    }
    pub fn push(&mut self, id: i64, lat: f64, lon: f64, tags: String) {
        self.id.push(id);
        self.lat.push(lat);
        self.lon.push(lon);
        self.tags.push(tags);
    }
    pub fn clear(&mut self) {
        self.id.clear();
        self.lat.clear();
        self.lon.clear();
        self.tags.clear();
    }
    /// Build an Arrow `RecordBatch` against the table's (field-id-tagged) schema.
    pub fn to_batch(&self, arrow_schema: ArrowSchemaRef) -> Result<RecordBatch> {
        Ok(RecordBatch::try_new(arrow_schema, vec![
            Arc::new(Int64Array::from(self.id.clone())),
            Arc::new(Float64Array::from(self.lat.clone())),
            Arc::new(Float64Array::from(self.lon.clone())),
            Arc::new(StringArray::from(self.tags.clone())),
        ])?)
    }
}

/// Throughput of an ingest run.
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
        if s > 0.0 { self.commits as f64 / s } else { 0.0 }
    }
}

/// The Arrow schema (with parquet field-id metadata) for `table`.
fn arrow_schema_of(table: &Table) -> Result<ArrowSchemaRef> {
    let s = iceberg::arrow::schema_to_arrow_schema(table.metadata().current_schema())?;
    Ok(Arc::new(s))
}

/// Write one group of batches into a single Parquet data file and commit it as
/// one `fast_append` snapshot. Returns the updated table.
async fn commit_group(
    catalog: &dyn Catalog,
    table: &Table,
    batches: &[RecordBatch],
    commit_idx: usize,
) -> Result<Table> {
    let schema = table.metadata().current_schema().clone();
    let data_location = format!("{}/data", table.metadata().location());
    let location_gen = DefaultLocationGenerator::with_data_location(data_location);
    let file_name_gen =
        DefaultFileNameGenerator::new(format!("bench-{commit_idx}"), None, DataFileFormat::Parquet);

    let pw = ParquetWriterBuilder::new(WriterProperties::builder().build(), schema);
    let rolling =
        RollingFileWriterBuilder::new_with_default_file_size(pw, table.file_io().clone(), location_gen, file_name_gen);
    let mut writer = DataFileWriterBuilder::new(rolling).build(None).await?;
    for b in batches {
        writer.write(b.clone()).await?;
    }
    let data_files = writer.close().await?;

    let tx = Transaction::new(table);
    let action = tx.fast_append().add_data_files(data_files);
    let tx = action.apply(tx)?;
    Ok(tx.commit(catalog).await?)
}

/// Ingest all batches, committing every `batches_per_commit` batches via
/// `fast_append`. Returns the final table + throughput.
pub async fn ingest(
    catalog: &dyn Catalog,
    table: Table,
    batches: impl IntoIterator<Item = RecordBatch>,
    batches_per_commit: usize,
) -> Result<(Table, IngestStats)> {
    let bpc = batches_per_commit.max(1);
    let mut table = table;
    let (mut rows, mut commits, mut idx) = (0u64, 0u64, 0usize);
    let mut group: Vec<RecordBatch> = Vec::with_capacity(bpc);
    let start = Instant::now();
    for batch in batches {
        rows += batch.num_rows() as u64;
        group.push(batch);
        if group.len() >= bpc {
            table = commit_group(catalog, &table, &group, idx).await?;
            commits += 1;
            idx += 1;
            group.clear();
        }
    }
    if !group.is_empty() {
        table = commit_group(catalog, &table, &group, idx).await?;
        commits += 1;
    }
    Ok((table, IngestStats { rows, commits, elapsed: start.elapsed() }))
}

/// Full-scan the table to Arrow and count rows. Returns (rows, elapsed).
pub async fn scan_count(table: &Table) -> Result<(u64, Duration)> {
    let start = Instant::now();
    let stream = table.scan().select_all().build()?.to_arrow().await?;
    let rows: u64 = stream
        .try_fold(0u64, |acc, batch| async move { Ok(acc + batch.num_rows() as u64) })
        .await?;
    Ok((rows, start.elapsed()))
}

/// Convenience: create the node table under `ident`'s namespace.
pub async fn create_node_table(catalog: &dyn Catalog, ident: &TableIdent) -> Result<Table> {
    use iceberg::TableCreation;
    let creation = TableCreation::builder()
        .name(ident.name().to_string())
        .schema(node_schema())
        .build();
    Ok(catalog.create_table(&ident.namespace, creation).await?)
}

/// The Arrow schema for the node table (for callers building batches).
pub fn node_arrow_schema(table: &Table) -> Result<ArrowSchemaRef> {
    arrow_schema_of(table)
}

/// The Arrow schema for the node table without needing a built `Table` — derived
/// straight from [`node_schema`], so the field-id metadata matches tables created
/// from that schema.
pub fn node_arrow_schema_standalone() -> Result<ArrowSchemaRef> {
    Ok(Arc::new(iceberg::arrow::schema_to_arrow_schema(&node_schema())?))
}

/// Build `total_rows` of synthetic node rows in `rows_per_batch` Arrow batches.
/// Deterministic pseudo-geo + a small tag string. Shared by the `data`/`data-pipe`
/// bench modes and the nornir-bench example.
pub fn synthetic_batches(
    arrow_schema: ArrowSchemaRef,
    total_rows: usize,
    rows_per_batch: usize,
) -> Vec<RecordBatch> {
    let mut out = Vec::new();
    let mut produced = 0usize;
    let mut id: i64 = 0;
    while produced < total_rows {
        let n = rows_per_batch.min(total_rows - produced);
        let mut cols = NodeColumns::default();
        for _ in 0..n {
            id += 1;
            let lat = -90.0 + (id as f64 * 0.000_137) % 180.0;
            let lon = -180.0 + (id as f64 * 0.000_271) % 360.0;
            let tags = if id % 4 == 0 { format!("amenity=bench;ref={id}") } else { String::new() };
            cols.push(id, lat, lon, tags);
        }
        out.push(cols.to_batch(arrow_schema.clone()).expect("batch"));
        produced += n;
    }
    out
}

fn join_tags<'a>(tags: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    let mut s = String::new();
    for (k, v) in tags {
        if !s.is_empty() {
            s.push(';');
        }
        s.push_str(k);
        s.push('=');
        s.push_str(v);
    }
    s
}

/// Read up to `max_rows` OSM nodes (dense + plain) from a `.osm.pbf` file into a
/// single column set. Ways/relations are skipped. Parse once, then slice across
/// parallel writers with [`NodeColumns::slice_batches`].
pub fn osm_columns(pbf_path: &str, max_rows: usize) -> Result<NodeColumns> {
    use osmpbf::{Element, ElementReader};
    let reader = ElementReader::from_path(pbf_path)?;
    let mut all = NodeColumns::default();
    reader.for_each(|el| {
        if all.len() >= max_rows {
            return;
        }
        match el {
            Element::DenseNode(n) => all.push(n.id(), n.lat(), n.lon(), join_tags(n.tags())),
            Element::Node(n) => all.push(n.id(), n.lat(), n.lon(), join_tags(n.tags())),
            _ => {}
        }
    })?;
    Ok(all)
}

// ---- GeoParquet ingest -----------------------------------------------------
// Ingest a Parquet file produced by the `katana-osm` / `osm2geoparquet`
// converter (OSM `.osm`/`.bz2`/`.pbf` → `nodes.parquet`, schema
// `id:Int64, geometry:Binary(WKB), tags:Utf8(JSON), version:Int32,
// changeset:Int64, timestamp:Utf8`). Unlike `osm_columns` (a fixed flat-node
// projection via the `osmpbf` crate), this is schema-generic: it derives the
// Iceberg table schema from whatever the file carries, so it ingests the real
// converter output as-is into the catalog.

/// The Arrow schema (with parquet field-id metadata) for an existing `table`.
pub fn table_arrow_schema(table: &Table) -> Result<ArrowSchemaRef> {
    arrow_schema_of(table)
}

/// Map an Arrow schema (e.g. a GeoParquet file's) to an Iceberg schema: field
/// ids `1..N` in column order, nullable Arrow fields → optional else required.
/// Primitives + Binary only (OSM `nodes`); List/Struct (ways' `node_refs`,
/// relations' `members`) bail with a clear error.
pub fn arrow_to_iceberg(schema: &ArrowSchema) -> Result<Schema> {
    let mut fields = Vec::with_capacity(schema.fields().len());
    for (i, f) in schema.fields().iter().enumerate() {
        let pt = match f.data_type() {
            DataType::Boolean => PrimitiveType::Boolean,
            DataType::Int8 | DataType::Int16 | DataType::Int32 => PrimitiveType::Int,
            DataType::Int64 => PrimitiveType::Long,
            DataType::Float32 => PrimitiveType::Float,
            DataType::Float64 => PrimitiveType::Double,
            DataType::Date32 => PrimitiveType::Date,
            DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => PrimitiveType::String,
            DataType::Binary | DataType::LargeBinary | DataType::BinaryView => PrimitiveType::Binary,
            other => anyhow::bail!("unmapped arrow type {other:?} for column {}", f.name()),
        };
        let id = (i + 1) as i32;
        let nf = if f.is_nullable() {
            NestedField::optional(id, f.name(), Type::Primitive(pt))
        } else {
            NestedField::required(id, f.name(), Type::Primitive(pt))
        };
        fields.push(nf.into());
    }
    Ok(Schema::builder().with_schema_id(0).with_fields(fields).build()?)
}

/// Read a Parquet file into (derived Iceberg schema, source `RecordBatch`es),
/// capped at `max_rows`, in `rows_per_batch`-sized batches. Batches keep the
/// file's own Arrow schema; [`recast`] them to the created table's field-id
/// schema before ingest.
pub fn read_parquet(
    path: &str,
    max_rows: usize,
    rows_per_batch: usize,
) -> Result<(Schema, Vec<RecordBatch>)> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("open parquet {path}: {e}"))?;
    let builder =
        ParquetRecordBatchReaderBuilder::try_new(file)?.with_batch_size(rows_per_batch.max(1));
    let ice = arrow_to_iceberg(builder.schema())?;
    let reader = builder.build()?;
    let mut out = Vec::new();
    let mut rows = 0usize;
    for batch in reader {
        if rows >= max_rows {
            break;
        }
        let batch = batch?;
        let take = (max_rows - rows).min(batch.num_rows());
        let batch = if take < batch.num_rows() { batch.slice(0, take) } else { batch };
        rows += batch.num_rows();
        out.push(batch);
    }
    Ok((ice, out))
}

/// Like [`read_parquet`] but decodes row groups across `threads` OS threads
/// (zstd decode is single-threaded per reader, so a 7000-row-group file otherwise
/// pins one core). Returns the derived Iceberg schema + up to `max_rows` rows;
/// batch order is not preserved (irrelevant for ingest/scan-count).
pub fn read_parquet_parallel(
    path: &str,
    max_rows: usize,
    rows_per_batch: usize,
    threads: usize,
) -> Result<(Schema, Vec<RecordBatch>)> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let file = std::fs::File::open(path).map_err(|e| anyhow::anyhow!("open parquet {path}: {e}"))?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let meta = builder.metadata().clone();
    let ice = arrow_to_iceberg(builder.schema())?;

    // Pick the leading row groups that cover `max_rows`.
    let mut needed: Vec<usize> = Vec::new();
    let mut acc = 0usize;
    for i in 0..meta.num_row_groups() {
        if acc >= max_rows {
            break;
        }
        needed.push(i);
        acc += meta.row_group(i).num_rows() as usize;
    }
    let nthreads = threads.max(1).min(needed.len().max(1));
    // Round-robin row groups across threads for even load.
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); nthreads];
    for (k, rg) in needed.into_iter().enumerate() {
        buckets[k % nthreads].push(rg);
    }

    let rpb = rows_per_batch.max(1);
    let mut handles = Vec::with_capacity(nthreads);
    for rgs in buckets.into_iter().filter(|b| !b.is_empty()) {
        let path = path.to_string();
        handles.push(std::thread::spawn(move || -> Result<Vec<RecordBatch>> {
            let f = std::fs::File::open(&path)?;
            let rdr = ParquetRecordBatchReaderBuilder::try_new(f)?
                .with_row_groups(rgs)
                .with_batch_size(rpb)
                .build()?;
            rdr.collect::<std::result::Result<Vec<_>, _>>().map_err(anyhow::Error::from)
        }));
    }
    // Concatenate, trimming the total to exactly `max_rows`.
    let mut out = Vec::new();
    let mut rows = 0usize;
    for h in handles {
        for b in h.join().map_err(|_| anyhow::anyhow!("parquet read thread panicked"))?? {
            if rows >= max_rows {
                break;
            }
            let take = (max_rows - rows).min(b.num_rows());
            let b = if take < b.num_rows() { b.slice(0, take) } else { b };
            rows += b.num_rows();
            out.push(b);
        }
    }
    Ok((ice, out))
}

/// Open a Parquet file and return (derived Iceberg schema, the file's Arrow
/// schema, per-row-group row counts) — without reading any data. Lets a caller
/// stream the file in row-group windows ([`read_row_groups`]) so memory stays
/// bounded regardless of total size (needed to ingest billions of rows).
pub fn parquet_layout(path: &str) -> Result<(Schema, ArrowSchemaRef, Vec<usize>)> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let file = std::fs::File::open(path).map_err(|e| anyhow::anyhow!("open parquet {path}: {e}"))?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let ice = arrow_to_iceberg(builder.schema())?;
    let file_schema: ArrowSchemaRef = builder.schema().clone();
    let meta = builder.metadata();
    let rg_rows: Vec<usize> = (0..meta.num_row_groups()).map(|i| meta.row_group(i).num_rows() as usize).collect();
    Ok((ice, file_schema, rg_rows))
}

/// Read exactly the row groups in `rgs` (parallel across `threads`), each decoded
/// in `rows_per_batch` batches. Batches keep the file's Arrow schema. This is the
/// windowed building block: a streaming ingest reads one window of row groups,
/// ingests it, frees it, then reads the next — so peak memory is one window, not
/// the whole file.
pub fn read_row_groups(
    path: &str,
    rgs: &[usize],
    rows_per_batch: usize,
    threads: usize,
) -> Result<Vec<RecordBatch>> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    if rgs.is_empty() {
        return Ok(Vec::new());
    }
    let nthreads = threads.max(1).min(rgs.len());
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); nthreads];
    for (k, rg) in rgs.iter().copied().enumerate() {
        buckets[k % nthreads].push(rg);
    }
    let rpb = rows_per_batch.max(1);
    let mut handles = Vec::with_capacity(nthreads);
    for bucket in buckets.into_iter().filter(|b| !b.is_empty()) {
        let path = path.to_string();
        handles.push(std::thread::spawn(move || -> Result<Vec<RecordBatch>> {
            let f = std::fs::File::open(&path)?;
            let rdr = ParquetRecordBatchReaderBuilder::try_new(f)?
                .with_row_groups(bucket)
                .with_batch_size(rpb)
                .build()?;
            rdr.collect::<std::result::Result<Vec<_>, _>>().map_err(anyhow::Error::from)
        }));
    }
    let mut out = Vec::new();
    for h in handles {
        out.extend(h.join().map_err(|_| anyhow::anyhow!("parquet read thread panicked"))??);
    }
    Ok(out)
}

/// Group row-group indices into windows whose row counts each sum to about
/// `window_rows`, stopping once `max_rows` total is covered. Returns one `Vec` of
/// row-group indices per window — feed each to [`read_row_groups`].
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

/// Read real OSM data and return the **geometry** (WKB point) value bytes split
/// into `chunk_bytes`-sized pieces — an authentic, uncompressed corpus for zstd
/// (de)compression benchmarks. Chunking to ~parquet-page size (vs one giant blob
/// per batch) is both representative of how the codec is really driven and what
/// makes per-frame allocation visible. Falls back to the `id` value buffer if the
/// file has no geometry column.
pub fn osm_value_chunks(
    path: &str,
    max_rows: usize,
    threads: usize,
    chunk_bytes: usize,
) -> Result<Vec<Vec<u8>>> {
    let (_ice, batches) = read_parquet_parallel(path, max_rows, 1_000_000, threads)?;
    let cz = chunk_bytes.max(1);
    let mut out = Vec::new();
    for b in &batches {
        let col = if b.num_columns() > 1 { 1 } else { 0 };
        let data = b.column(col).to_data();
        // Binary: data bytes are the last buffer (after offsets); primitive: the
        // sole buffer is the values.
        if let Some(buf) = data.buffers().last() {
            for piece in buf.as_slice().chunks(cz) {
                out.push(piece.to_vec());
            }
        }
    }
    anyhow::ensure!(!out.is_empty(), "no value bytes extracted from {path}");
    Ok(out)
}

/// Re-cast each batch's columns to `target` (the table's field-id Arrow schema),
/// handling Iceberg's `Utf8`→`LargeUtf8` / `Binary`→`LargeBinary` widening so the
/// written Parquet carries the field ids the catalog scan needs.
pub fn recast(batches: &[RecordBatch], target: ArrowSchemaRef) -> Result<Vec<RecordBatch>> {
    let n = target.fields().len();
    let mut out = Vec::with_capacity(batches.len());
    for b in batches {
        anyhow::ensure!(
            b.num_columns() == n,
            "column count mismatch: file has {}, schema has {n}",
            b.num_columns()
        );
        let cols: Vec<ArrayRef> = (0..n)
            .map(|i| arrow_cast::cast(b.column(i), target.field(i).data_type()).map_err(anyhow::Error::from))
            .collect::<Result<_>>()?;
        out.push(RecordBatch::try_new(target.clone(), cols)?);
    }
    Ok(out)
}

impl NodeColumns {
    /// Slice rows `[start, start+len)` (clamped) into `rows_per_batch` batches.
    pub fn slice_batches(
        &self,
        start: usize,
        len: usize,
        rows_per_batch: usize,
        arrow_schema: ArrowSchemaRef,
    ) -> Result<Vec<RecordBatch>> {
        let end = (start + len).min(self.len());
        let bpr = rows_per_batch.max(1);
        let mut out = Vec::new();
        let mut i = start;
        while i < end {
            let j_end = (i + bpr).min(end);
            let mut c = NodeColumns::default();
            for j in i..j_end {
                c.push(self.id[j], self.lat[j], self.lon[j], self.tags[j].clone());
            }
            out.push(c.to_batch(arrow_schema.clone())?);
            i = j_end;
        }
        Ok(out)
    }
}
