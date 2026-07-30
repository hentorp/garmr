#![allow(clippy::arithmetic_side_effects)]

use std::{collections::HashMap, fs, path::Path, sync::Arc};

use anyhow::Context as _;
use arrow::{
    array::{BinaryBuilder, Int32Builder, Int64Builder, ListBuilder, StringBuilder},
    datatypes::Schema,
    record_batch::RecordBatch,
};
use parquet::{
    arrow::ArrowWriter,
    arrow::arrow_writer::{ArrowColumnChunk, ArrowRowGroupWriterFactory, compute_leaves},
    basic::Compression,
    file::properties::WriterProperties,
    file::writer::SerializedFileWriter,
};

use crate::shared::schema;

use crate::{
    metadata,
    reader::{NodeRecord, RelationRecord, WayRecord},
};

pub(crate) const ROW_GROUP_SIZE: usize = 524_288; // 512 K rows → fewer zstd calls, better compression

/// Map the CLI compression name onto a parquet codec.
pub(crate) fn codec(compression: &str) -> Compression {
    match compression {
        "snappy" => Compression::SNAPPY,
        "none" => Compression::UNCOMPRESSED,
        _ => Compression::ZSTD(Default::default()),
    }
}

/// Writer properties carrying the GeoParquet `geo` document as a **file-level
/// Parquet key-value metadata entry**.
///
/// This is the fix for the defect that made osm-katana's output *Parquet-with-WKB*
/// rather than GeoParquet. Putting `geo` only in the Arrow `Schema`'s metadata
/// (what `schema_with_geo` does, and all this crate used to do) buries it inside
/// the base64 `ARROW:schema` blob: arrow-rs and pyarrow decode that blob and so
/// "see" the key, but the spec requires `geo` in the Parquet metadata itself, and
/// GDAL/OGR, DuckDB-spatial and every non-Arrow reader look only there. Measured
/// on the shipped Stockholm pack before this change:
///
/// ```text
/// FILE-LEVEL parquet key_value_metadata keys: [b'ARROW:schema']   ← no 'geo'
/// arrow schema metadata: {b'geo': b'{"version":"1.0.0",…}'}       ← hidden here
/// ```
///
/// We now write it in BOTH places: the Arrow-schema copy keeps the existing
/// round-trip behaviour (purely additive), the file-level copy is what makes the
/// file GeoParquet.
fn writer_props(compression: &str, geo_json: &str) -> WriterProperties {
    use parquet::file::metadata::KeyValue;
    WriterProperties::builder()
        .set_compression(codec(compression))
        .set_max_row_group_row_count(Some(ROW_GROUP_SIZE))
        .set_key_value_metadata(Some(vec![KeyValue::new(
            String::from(metadata::GEO_KEY),
            String::from(geo_json),
        )]))
        .build()
}

fn schema_with_geo(schema: Schema, geo_json: String) -> Schema {
    let mut meta = HashMap::new();
    meta.insert(String::from(metadata::GEO_KEY), geo_json);
    schema.with_metadata(meta)
}

// ── Nodes ─────────────────────────────────────────────────────────────────────

pub fn write_nodes(path: &Path, records: &[NodeRecord], compression: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let geo_json = metadata::geo_metadata(&["Point"], None);
    let props = writer_props(compression, &geo_json);
    let schema = Arc::new(schema_with_geo(schema::nodes_schema(), geo_json));

    let file = fs::File::create(path).with_context(|| format!("create {path:?}"))?;
    let mut w = ArrowWriter::try_new(file, schema.clone(), Some(props))?;

    for chunk in records.chunks(ROW_GROUP_SIZE) {
        let mut ids = Int64Builder::new();
        let mut geoms = BinaryBuilder::new();
        let mut tags = StringBuilder::new();
        let mut versions = Int32Builder::new();
        let mut changesets = Int64Builder::new();
        let mut timestamps = StringBuilder::new();

        for r in chunk {
            ids.append_value(r.id);
            geoms.append_value(crate::geometry::encode_point_inline(
                r.lon_lat.0,
                r.lon_lat.1,
            ));
            tags.append_option(Some(&r.tags_json));
            versions.append_option(r.version);
            changesets.append_null();
            timestamps.append_null();
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(ids.finish()),
                Arc::new(geoms.finish()),
                Arc::new(tags.finish()),
                Arc::new(versions.finish()),
                Arc::new(changesets.finish()),
                Arc::new(timestamps.finish()),
            ],
        )?;
        w.write(&batch)?;
    }

    w.close()?;
    Ok(())
}

// ── Ways ──────────────────────────────────────────────────────────────────────

pub fn write_ways(path: &Path, records: &[WayRecord], compression: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let geo_json = metadata::geo_metadata(&["LineString", "Polygon"], None);
    let props = writer_props(compression, &geo_json);
    let schema = Arc::new(schema_with_geo(schema::ways_schema(), geo_json));

    let file = fs::File::create(path).with_context(|| format!("create {path:?}"))?;
    let mut w = ArrowWriter::try_new(file, schema.clone(), Some(props))?;

    for chunk in records.chunks(ROW_GROUP_SIZE) {
        let mut ids = Int64Builder::new();
        let mut geoms = BinaryBuilder::new();
        let mut tags = StringBuilder::new();
        let mut node_refs = ListBuilder::new(Int64Builder::new());
        let mut versions = Int32Builder::new();

        for r in chunk {
            ids.append_value(r.id);
            match &r.geometry {
                Some(g) => geoms.append_value(g),
                None => geoms.append_null(),
            }
            tags.append_value(&r.tags_json);
            for &ref_id in &r.node_refs {
                node_refs.values().append_value(ref_id);
            }
            node_refs.append(true);
            versions.append_option(r.version);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(ids.finish()),
                Arc::new(geoms.finish()),
                Arc::new(tags.finish()),
                Arc::new(node_refs.finish()),
                Arc::new(versions.finish()),
            ],
        )?;
        w.write(&batch)?;
    }

    w.close()?;
    Ok(())
}

// ── NodeWriter — streaming sink for pass-1 node records ──────────────────────

/// Streams `NodeRecord`s to a Parquet file in batches of `ROW_GROUP_SIZE`.
/// Avoids accumulating all nodes in a `Vec` — pass 1 can push records directly.
///
/// Serial reference writer for the retained `RawParquetTypedSink` fallback; the
/// live raw/resolved paths use the parallel `ParallelNodeWriter` (worker-encode).
#[allow(dead_code)]
pub struct NodeWriter {
    writer: ArrowWriter<fs::File>,
    schema: Arc<Schema>,
    ids: Int64Builder,
    geoms: BinaryBuilder,
    tags: StringBuilder,
    vers: Int32Builder,
    changes: Int64Builder,
    times: StringBuilder,
    count: usize,
}

#[allow(dead_code)] // retained serial fallback (see NodeWriter doc)
impl NodeWriter {
    pub fn new(path: &Path, compression: &str) -> anyhow::Result<Self> {
        let geo_json = metadata::geo_metadata(&["Point"], None);
        let props = writer_props(compression, &geo_json);
        let schema = Arc::new(schema_with_geo(schema::nodes_schema(), geo_json));
        let file = fs::File::create(path).with_context(|| format!("create {path:?}"))?;
        let writer = ArrowWriter::try_new(file, schema.clone(), Some(props))?;
        Ok(Self {
            writer,
            schema,
            ids: Int64Builder::new(),
            geoms: BinaryBuilder::new(),
            tags: StringBuilder::new(),
            vers: Int32Builder::new(),
            changes: Int64Builder::new(),
            times: StringBuilder::new(),
            count: 0,
        })
    }

    pub fn push(&mut self, r: &crate::reader::NodeRecord) -> anyhow::Result<()> {
        self.ids.append_value(r.id);
        self.geoms
            .append_value(crate::geometry::encode_point_inline(
                r.lon_lat.0,
                r.lon_lat.1,
            ));
        self.tags.append_option(Some(&r.tags_json));
        self.vers.append_option(r.version);
        self.changes.append_null();
        self.times.append_null();
        self.count += 1;
        if self.count >= ROW_GROUP_SIZE {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        if self.count == 0 {
            return Ok(());
        }
        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![
                Arc::new(self.ids.finish()),
                Arc::new(self.geoms.finish()),
                Arc::new(self.tags.finish()),
                Arc::new(self.vers.finish()),
                Arc::new(self.changes.finish()),
                Arc::new(self.times.finish()),
            ],
        )?;
        self.writer.write(&batch)?;
        self.count = 0;
        Ok(())
    }

    pub fn finish(mut self) -> anyhow::Result<()> {
        self.flush()?;
        self.writer.close()?;
        Ok(())
    }
}

// ── WayWriter — streaming sink for pass-2 way records ────────────────────────

pub struct WayWriter {
    pub(crate) writer: ArrowWriter<fs::File>,
    schema: Arc<Schema>,
    ids: Int64Builder,
    geoms: BinaryBuilder,
    tags: StringBuilder,
    node_refs: ListBuilder<Int64Builder>,
    vers: Int32Builder,
    count: usize,
}

impl WayWriter {
    pub fn new(path: &Path, compression: &str) -> anyhow::Result<Self> {
        let geo_json = metadata::geo_metadata(&["LineString", "Polygon"], None);
        let props = writer_props(compression, &geo_json);
        let schema = Arc::new(schema_with_geo(schema::ways_schema(), geo_json));
        let file = fs::File::create(path).with_context(|| format!("create {path:?}"))?;
        let writer = ArrowWriter::try_new(file, schema.clone(), Some(props))?;
        Ok(Self {
            writer,
            schema,
            ids: Int64Builder::new(),
            geoms: BinaryBuilder::new(),
            tags: StringBuilder::new(),
            node_refs: ListBuilder::new(Int64Builder::new()),
            vers: Int32Builder::new(),
            count: 0,
        })
    }

    pub fn push(&mut self, r: &crate::reader::WayRecord) -> anyhow::Result<()> {
        self.ids.append_value(r.id);
        match &r.geometry {
            Some(g) => self.geoms.append_value(g),
            None => self.geoms.append_null(),
        }
        self.tags.append_value(&r.tags_json);
        for &ref_id in &r.node_refs {
            self.node_refs.values().append_value(ref_id);
        }
        self.node_refs.append(true);
        self.vers.append_option(r.version);
        self.count += 1;
        if self.count >= ROW_GROUP_SIZE {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        if self.count == 0 {
            return Ok(());
        }
        let batch = self.take_batch()?;
        self.writer.write(&batch)?;
        Ok(())
    }

    /// Build a RecordBatch from buffered rows and reset builders.
    /// Returns None if no rows are buffered.
    pub fn take_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![
                Arc::new(self.ids.finish()),
                Arc::new(self.geoms.finish()),
                Arc::new(self.tags.finish()),
                Arc::new(self.node_refs.finish()),
                Arc::new(self.vers.finish()),
            ],
        )?;
        self.count = 0;
        Ok(batch)
    }

    pub fn finish(mut self) -> anyhow::Result<()> {
        self.flush()?;
        self.writer.close()?;
        Ok(())
    }
}

pub struct RelWriter {
    pub(crate) writer: ArrowWriter<fs::File>,
    schema: Arc<Schema>,
    ids: Int64Builder,
    geoms: BinaryBuilder,
    tags: StringBuilder,
    members: StringBuilder,
    vers: Int32Builder,
    count: usize,
}

impl RelWriter {
    pub fn new(path: &Path, compression: &str) -> anyhow::Result<Self> {
        let geo_json = metadata::geo_metadata(&["MultiPolygon"], None);
        let props = writer_props(compression, &geo_json);
        let schema = Arc::new(schema_with_geo(schema::relations_schema(), geo_json));
        let file = fs::File::create(path).with_context(|| format!("create {path:?}"))?;
        let writer = ArrowWriter::try_new(file, schema.clone(), Some(props))?;
        Ok(Self {
            writer,
            schema,
            ids: Int64Builder::new(),
            geoms: BinaryBuilder::new(),
            tags: StringBuilder::new(),
            members: StringBuilder::new(),
            vers: Int32Builder::new(),
            count: 0,
        })
    }

    pub fn push(&mut self, r: &crate::reader::RelationRecord) -> anyhow::Result<()> {
        self.ids.append_value(r.id);
        self.geoms.append_null();
        self.tags.append_value(&r.tags_json);
        self.members.append_value(&r.members_json);
        self.vers.append_option(r.version);
        self.count += 1;
        if self.count >= ROW_GROUP_SIZE {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        if self.count == 0 {
            return Ok(());
        }
        let batch = self.take_batch()?;
        self.writer.write(&batch)?;
        Ok(())
    }

    /// Build a RecordBatch from buffered rows and reset builders.
    pub fn take_batch(&mut self) -> anyhow::Result<RecordBatch> {
        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![
                Arc::new(self.ids.finish()),
                Arc::new(self.geoms.finish()),
                Arc::new(self.tags.finish()),
                Arc::new(self.members.finish()),
                Arc::new(self.vers.finish()),
            ],
        )?;
        self.count = 0;
        Ok(batch)
    }

    pub fn finish(mut self) -> anyhow::Result<()> {
        self.flush()?;
        self.writer.close()?;
        Ok(())
    }
}

// ── Relations ─────────────────────────────────────────────────────────────────

pub fn write_relations(
    path: &Path,
    records: &[RelationRecord],
    compression: &str,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let geo_json = metadata::geo_metadata(&["MultiPolygon"], None);
    let props = writer_props(compression, &geo_json);
    let schema = Arc::new(schema_with_geo(schema::relations_schema(), geo_json));

    let file = fs::File::create(path).with_context(|| format!("create {path:?}"))?;
    let mut w = ArrowWriter::try_new(file, schema.clone(), Some(props))?;

    for chunk in records.chunks(ROW_GROUP_SIZE) {
        let mut ids = Int64Builder::new();
        let mut geoms = BinaryBuilder::new();
        let mut tags = StringBuilder::new();
        let mut members = StringBuilder::new();
        let mut versions = Int32Builder::new();

        for r in chunk {
            ids.append_value(r.id);
            geoms.append_null(); // relation geometry resolution is future work
            tags.append_value(&r.tags_json);
            members.append_value(&r.members_json);
            versions.append_option(r.version);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(ids.finish()),
                Arc::new(geoms.finish()),
                Arc::new(tags.finish()),
                Arc::new(members.finish()),
                Arc::new(versions.finish()),
            ],
        )?;
        w.write(&batch)?;
    }

    w.close()?;
    Ok(())
}

// ── Accumulators — build RecordBatches on parse side, no file I/O ─────────────

/// Accumulates node records into Arrow builders; emits a RecordBatch at ROW_GROUP_SIZE.
/// Pair with [`ParquetSink`] so the collector only does cheap builder appends
/// and the writer thread handles zstd + I/O off the hot path.
pub struct NodeAccumulator {
    schema: Arc<Schema>,
    ids: Int64Builder,
    geoms: BinaryBuilder,
    tags: StringBuilder,
    vers: Int32Builder,
    changes: Int64Builder,
    times: StringBuilder,
    count: usize,
}

impl NodeAccumulator {
    pub fn new() -> Self {
        let geo_json = metadata::geo_metadata(&["Point"], None);
        let schema = Arc::new(schema_with_geo(schema::nodes_schema(), geo_json));
        Self {
            schema,
            ids: Int64Builder::new(),
            geoms: BinaryBuilder::new(),
            tags: StringBuilder::new(),
            vers: Int32Builder::new(),
            changes: Int64Builder::new(),
            times: StringBuilder::new(),
            count: 0,
        }
    }

    pub fn push(&mut self, r: &crate::reader::NodeRecord) {
        self.ids.append_value(r.id);
        self.geoms
            .append_value(crate::geometry::encode_point_inline(
                r.lon_lat.0,
                r.lon_lat.1,
            ));
        self.tags.append_option(Some(&r.tags_json));
        self.vers.append_option(r.version);
        self.changes.append_null();
        self.times.append_null();
        self.count += 1;
    }

    pub fn take_if_full(&mut self) -> anyhow::Result<Option<RecordBatch>> {
        if self.count >= ROW_GROUP_SIZE {
            Ok(Some(self.take()?))
        } else {
            Ok(None)
        }
    }

    pub fn take_remaining(&mut self) -> anyhow::Result<Option<RecordBatch>> {
        if self.count > 0 {
            Ok(Some(self.take()?))
        } else {
            Ok(None)
        }
    }

    fn take(&mut self) -> anyhow::Result<RecordBatch> {
        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![
                Arc::new(self.ids.finish()),
                Arc::new(self.geoms.finish()),
                Arc::new(self.tags.finish()),
                Arc::new(self.vers.finish()),
                Arc::new(self.changes.finish()),
                Arc::new(self.times.finish()),
            ],
        )?;
        self.count = 0;
        Ok(batch)
    }
}

impl Default for NodeAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Accumulates way records into Arrow builders; emits a RecordBatch at ROW_GROUP_SIZE.
pub struct WayAccumulator {
    schema: Arc<Schema>,
    ids: Int64Builder,
    geoms: BinaryBuilder,
    tags: StringBuilder,
    node_refs: ListBuilder<Int64Builder>,
    vers: Int32Builder,
    count: usize,
}

impl WayAccumulator {
    pub fn new() -> Self {
        let geo_json = metadata::geo_metadata(&["LineString", "Polygon"], None);
        let schema = Arc::new(schema_with_geo(schema::ways_schema(), geo_json));
        Self {
            schema,
            ids: Int64Builder::new(),
            geoms: BinaryBuilder::new(),
            tags: StringBuilder::new(),
            node_refs: ListBuilder::new(Int64Builder::new()),
            vers: Int32Builder::new(),
            count: 0,
        }
    }

    pub fn push(&mut self, r: &WayRecord) {
        self.ids.append_value(r.id);
        match &r.geometry {
            Some(g) => self.geoms.append_value(g),
            None => self.geoms.append_null(),
        }
        self.tags.append_value(&r.tags_json);
        for &ref_id in &r.node_refs {
            self.node_refs.values().append_value(ref_id);
        }
        self.node_refs.append(true);
        self.vers.append_option(r.version);
        self.count += 1;
    }

    /// Returns a batch if we've hit ROW_GROUP_SIZE.
    pub fn take_if_full(&mut self) -> anyhow::Result<Option<RecordBatch>> {
        if self.count >= ROW_GROUP_SIZE {
            Ok(Some(self.take()?))
        } else {
            Ok(None)
        }
    }

    /// Drain remaining rows (call at end).
    pub fn take_remaining(&mut self) -> anyhow::Result<Option<RecordBatch>> {
        if self.count > 0 {
            Ok(Some(self.take()?))
        } else {
            Ok(None)
        }
    }

    fn take(&mut self) -> anyhow::Result<RecordBatch> {
        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![
                Arc::new(self.ids.finish()),
                Arc::new(self.geoms.finish()),
                Arc::new(self.tags.finish()),
                Arc::new(self.node_refs.finish()),
                Arc::new(self.vers.finish()),
            ],
        )?;
        self.count = 0;
        Ok(batch)
    }
}

/// Accumulates relation records into Arrow builders; emits a RecordBatch at ROW_GROUP_SIZE.
pub struct RelAccumulator {
    schema: Arc<Schema>,
    ids: Int64Builder,
    geoms: BinaryBuilder,
    tags: StringBuilder,
    members: StringBuilder,
    vers: Int32Builder,
    count: usize,
}

impl RelAccumulator {
    pub fn new() -> Self {
        let geo_json = metadata::geo_metadata(&["MultiPolygon"], None);
        let schema = Arc::new(schema_with_geo(schema::relations_schema(), geo_json));
        Self {
            schema,
            ids: Int64Builder::new(),
            geoms: BinaryBuilder::new(),
            tags: StringBuilder::new(),
            members: StringBuilder::new(),
            vers: Int32Builder::new(),
            count: 0,
        }
    }

    pub fn push(&mut self, r: &RelationRecord) {
        self.ids.append_value(r.id);
        self.geoms.append_null();
        self.tags.append_value(&r.tags_json);
        self.members.append_value(&r.members_json);
        self.vers.append_option(r.version);
        self.count += 1;
    }

    pub fn take_if_full(&mut self) -> anyhow::Result<Option<RecordBatch>> {
        if self.count >= ROW_GROUP_SIZE {
            Ok(Some(self.take()?))
        } else {
            Ok(None)
        }
    }

    pub fn take_remaining(&mut self) -> anyhow::Result<Option<RecordBatch>> {
        if self.count > 0 {
            Ok(Some(self.take()?))
        } else {
            Ok(None)
        }
    }

    fn take(&mut self) -> anyhow::Result<RecordBatch> {
        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![
                Arc::new(self.ids.finish()),
                Arc::new(self.geoms.finish()),
                Arc::new(self.tags.finish()),
                Arc::new(self.members.finish()),
                Arc::new(self.vers.finish()),
            ],
        )?;
        self.count = 0;
        Ok(batch)
    }
}

/// One fully-encoded, compressed Parquet row group: the column chunks for a
/// contiguous run of rows, ready to be stitched into the file without any
/// further compression. Produced on a Gatling worker, consumed (appended) by
/// the single in-order collector.
pub type EncodedRowGroup = Vec<ArrowColumnChunk>;

/// Encodes node `RecordBatch`es into compressed Parquet row groups.
///
/// Cheaply cloneable (`Arc` inside) and `Sync`, so every Gatling worker can
/// encode **its own** segment's row group in parallel: the zstd compression and
/// page encoding run on the worker thread, *not* on the single collector. This
/// is pure CPU on the calling thread — it spawns no threads and uses no rayon.
#[derive(Clone)]
pub struct NodeColumnEncoder {
    factory: Arc<ArrowRowGroupWriterFactory>,
    schema: Arc<Schema>,
}

impl NodeColumnEncoder {
    /// Encode one `RecordBatch` into a compressed row group (one column chunk
    /// per leaf column, in schema order). Runs entirely on the caller's thread.
    pub fn encode(&self, batch: &RecordBatch) -> anyhow::Result<EncodedRowGroup> {
        let mut writers = self.factory.create_column_writers(0)?;
        let mut w = writers.iter_mut();
        for (field, col) in self.schema.fields().iter().zip(batch.columns()) {
            for leaf in compute_leaves(field.as_ref(), col)? {
                w.next()
                    .ok_or_else(|| anyhow::anyhow!("column writer/leaf count mismatch"))?
                    .write(&leaf)?;
            }
        }
        writers
            .into_iter()
            .map(|cw| cw.close().map_err(anyhow::Error::from))
            .collect()
    }
}

/// In-order Parquet file writer that only **stitches** pre-compressed row
/// groups produced by the workers. Runs on the single collector thread but does
/// no compression — it appends already-encoded column chunks and writes the
/// footer, so the collector is no longer the serial zstd bottleneck.
pub struct ParallelNodeWriter {
    writer: SerializedFileWriter<fs::File>,
}

impl ParallelNodeWriter {
    /// Append one pre-encoded row group to the file (pure I/O + metadata).
    pub fn append(&mut self, rg: EncodedRowGroup) -> anyhow::Result<()> {
        if rg.is_empty() {
            return Ok(());
        }
        let mut rgw = self.writer.next_row_group()?;
        for chunk in rg {
            chunk.append_to_row_group(&mut rgw)?;
        }
        rgw.close()?;
        Ok(())
    }

    pub fn finish(self) -> anyhow::Result<()> {
        self.writer.close()?;
        Ok(())
    }
}

/// Build a parallel node writer together with the matching column encoder.
///
/// The encoder (handed to the Gatling workers) and the writer (kept by the
/// collector) share the same Arrow/Parquet schema and the GeoParquet `geo`
/// metadata, so the stitched file is byte-for-byte a valid GeoParquet node
/// table — just encoded in parallel instead of on one thread.
pub fn parallel_node_writer(
    path: &Path,
    compression: &str,
) -> anyhow::Result<(NodeColumnEncoder, ParallelNodeWriter)> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let geo_json = metadata::geo_metadata(&["Point"], None);
    let props = writer_props(compression, &geo_json);
    let schema = Arc::new(schema_with_geo(schema::nodes_schema(), geo_json));
    let file = fs::File::create(path).with_context(|| format!("create {path:?}"))?;
    // ArrowWriter sets up the file metadata (geo + ARROW:schema); we then split
    // it into the low-level SerializedFileWriter + the row-group factory so the
    // actual encode can happen off-thread on the workers.
    let aw = ArrowWriter::try_new(file, schema.clone(), Some(props))?;
    let (writer, factory) = aw.into_serialized_writer()?;
    Ok((
        NodeColumnEncoder {
            factory: Arc::new(factory),
            schema,
        },
        ParallelNodeWriter { writer },
    ))
}

/// Schema-agnostic alias: the column encoder works for ANY Arrow schema (it
/// iterates `self.schema.fields()`), so the same type drives node, way and
/// relation row-group encoding on the workers. Named `NodeColumnEncoder` for
/// historical reasons; the way/rel pass-2 parallel path reuses it verbatim.
pub type ColumnEncoder = NodeColumnEncoder;
/// Schema-agnostic alias for the in-order row-group stitcher (see
/// [`ParallelNodeWriter`]). Reused by the pass-2 way/rel parallel path.
pub type ParallelRowGroupWriter = ParallelNodeWriter;

/// Build a parallel **way** writer + its column encoder. Mirror of
/// [`parallel_node_writer`] for the ways GeoParquet table (LineString/Polygon
/// geometry). The encoder is handed to the pass-2 Gatling workers so each
/// builds + zstd-encodes its own way row groups in parallel; the writer stays
/// on the collector and only stitches the pre-encoded groups in order.
pub fn parallel_way_writer(
    path: &Path,
    compression: &str,
) -> anyhow::Result<(ColumnEncoder, ParallelRowGroupWriter)> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let geo_json = metadata::geo_metadata(&["LineString", "Polygon"], None);
    let props = writer_props(compression, &geo_json);
    let schema = Arc::new(schema_with_geo(schema::ways_schema(), geo_json));
    let file = fs::File::create(path).with_context(|| format!("create {path:?}"))?;
    let aw = ArrowWriter::try_new(file, schema.clone(), Some(props))?;
    let (writer, factory) = aw.into_serialized_writer()?;
    Ok((
        NodeColumnEncoder {
            factory: Arc::new(factory),
            schema,
        },
        ParallelNodeWriter { writer },
    ))
}

/// Build a parallel **relation** writer + its column encoder. Mirror of
/// [`parallel_node_writer`] for the relations table (no geometry).
pub fn parallel_rel_writer(
    path: &Path,
    compression: &str,
) -> anyhow::Result<(ColumnEncoder, ParallelRowGroupWriter)> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let geo_json = metadata::geo_metadata(&["MultiPolygon"], None);
    let props = writer_props(compression, &geo_json);
    let schema = Arc::new(schema_with_geo(schema::relations_schema(), geo_json));
    let file = fs::File::create(path).with_context(|| format!("create {path:?}"))?;
    let aw = ArrowWriter::try_new(file, schema.clone(), Some(props))?;
    let (writer, factory) = aw.into_serialized_writer()?;
    Ok((
        NodeColumnEncoder {
            factory: Arc::new(factory),
            schema,
        },
        ParallelNodeWriter { writer },
    ))
}

// The former `ParquetSink` background-writer thread (single-thread node zstd +
// I/O, fed by a per-record `NodeAccumulator` on the collector) was removed once
// every convert path — raw single-pass and both resolved 2-pass entries — moved
// node encoding onto the Gatling workers via `NodeColumnEncoder` +
// `ParallelNodeWriter` (the collector only stitches pre-compressed row groups).

#[cfg(test)]
mod parallel_node_tests {
    use super::*;
    use crate::reader::NodeRecord;
    use std::time::Instant;

    fn make_batch(start: i64, n: i64) -> RecordBatch {
        let mut acc = NodeAccumulator::new();
        for i in start..start + n {
            acc.push(&NodeRecord {
                id: i,
                lon_lat: (i as f64 * 1e-6, i as f64 * 2e-6),
                tags_json: r#"{"amenity":"bench","note":"parallel-encode-bench"}"#.to_string(),
                version: Some(1),
            });
        }
        acc.take_remaining().unwrap().unwrap()
    }

    fn total_rows_in(path: &std::path::Path) -> (i64, usize, bool) {
        let file = fs::File::open(path).unwrap();
        let builder =
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file).unwrap();
        let meta = builder.metadata();
        let rows = meta.file_metadata().num_rows();
        let rgs = meta.num_row_groups();
        // GeoParquet `geo` metadata is carried inside the `ARROW:schema` kv (as
        // arrow-rs does for the normal ArrowWriter path); the reader merges it
        // back into the recovered Arrow schema's metadata.
        let has_geo = builder.schema().metadata().contains_key("geo");
        (rows, rgs, has_geo)
    }

    /// Regression for the 32 767-row-group parquet cap (planet SIGSEGV).
    ///
    /// Before the fix, each worker-segment flushed its sub-full remainder as its
    /// own row group (`take_remaining` per segment) → ~one group per segment →
    /// >32 767 groups on planet → parquet `append` error → gatling UAF crash.
    ///
    /// The fix persists one `NodeAccumulator` per worker across its segments and
    /// only seals full `ROW_GROUP_SIZE` batches mid-stream (`take_if_full`),
    /// flushing the remainder once at the end. This test mirrors that: many small
    /// segments fed into a single persistent accumulator must coalesce into
    /// `ceil(total / ROW_GROUP_SIZE)` groups — NOT one per segment — with every
    /// group but the last exactly `ROW_GROUP_SIZE`.
    #[test]
    fn persistent_accumulator_packs_segments_into_full_row_groups() {
        let seg_rows = 160_000usize; // ~one bz2 segment's worth, < ROW_GROUP_SIZE
        let n_segments = 40usize; // would be 40 tiny groups under the old path
        let total = seg_rows * n_segments;

        let mut acc = NodeAccumulator::new();
        let mut group_sizes: Vec<usize> = Vec::new();
        let mut next_id = 0i64;
        for _ in 0..n_segments {
            for _ in 0..seg_rows {
                acc.push(&NodeRecord {
                    id: next_id,
                    lon_lat: (0.0, 0.0),
                    tags_json: String::new(),
                    version: None,
                });
                next_id += 1;
                // Seal full groups mid-segment, exactly like the worker does.
                if let Some(b) = acc.take_if_full().unwrap() {
                    group_sizes.push(b.num_rows());
                }
            }
            // NOTE: no per-segment take_remaining — the remainder carries forward.
        }
        // End-of-worker flush (finish_worker).
        if let Some(b) = acc.take_remaining().unwrap() {
            group_sizes.push(b.num_rows());
        }

        let expected_groups = total.div_ceil(ROW_GROUP_SIZE);
        assert_eq!(
            group_sizes.len(),
            expected_groups,
            "expected coalesced groups, got one-per-segment fragmentation"
        );
        assert!(
            group_sizes.len() < n_segments,
            "packing must produce fewer groups than segments"
        );
        for (i, &sz) in group_sizes.iter().enumerate() {
            if i + 1 < group_sizes.len() {
                assert_eq!(sz, ROW_GROUP_SIZE, "non-final group {i} must be full");
            } else {
                assert_eq!(
                    sz,
                    total - ROW_GROUP_SIZE * (expected_groups - 1),
                    "final group is the remainder"
                );
            }
        }
        assert_eq!(group_sizes.iter().sum::<usize>(), total, "no rows lost");
    }

    /// Each gatling unit encodes its own row group in parallel — exactly how the
    /// Gatling pass-1 workers feed the collector.
    /// Verifies the stitched file is valid GeoParquet with the right row count
    /// and one row group per worker batch.
    #[test]
    fn parallel_encode_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nodes.parquet");
        let (enc, mut w) = parallel_node_writer(&path, "zstd").unwrap();

        let k: i64 = 8;
        let n: i64 = 20_000;
        let batches: Vec<RecordBatch> = (0..k).map(|j| make_batch(j * n, n)).collect();

        // Parallel encode, ROOT LAW #0: gatling fan-out (NOT a hand-rolled
        // `thread::scope` pool), all units sharing the same (Sync) encoder — no
        // rayon, no shared writer lock. Results come back in batch order, which
        // is what the collector stitches.
        let groups: Vec<EncodedRowGroup> = gatling::gatling_forkjoin::gatling_map_balanced(
            &batches,
            0,
            1,
            |b: &RecordBatch| b.num_rows() as u64,
            |_i, b: &RecordBatch| enc.encode(b).unwrap(),
        );

        // Collector stitches the pre-compressed row groups in order.
        for g in groups {
            w.append(g).unwrap();
        }
        w.finish().unwrap();

        let (rows, rgs, has_geo) = total_rows_in(&path);
        assert_eq!(rows, k * n, "row count must match");
        assert_eq!(rgs, k as usize, "one row group per worker batch");
        assert!(has_geo, "GeoParquet `geo` metadata must be preserved");
    }

    /// Pass-2 saturation fix: way + relation row groups must be Arrow-built +
    /// zstd-encoded ON THE WORKERS (parallel, shared `ColumnEncoder`) and merely
    /// stitched in order by the collector — exactly like the pass-1 node path.
    /// Injects real Way/RelationRecords across several "worker" threads, stitches
    /// the pre-encoded groups, and asserts the round-tripped file has the right
    /// row count, one group per worker batch, and preserved GeoParquet metadata.
    #[test]
    fn parallel_way_rel_encode_roundtrip() {
        use crate::reader::{RelationRecord, WayRecord};

        let dir = tempfile::tempdir().unwrap();

        // ── Ways ──────────────────────────────────────────────────────────────
        let way_path = dir.path().join("ways.parquet");
        let (way_enc, mut way_w) = parallel_way_writer(&way_path, "zstd").unwrap();
        let k = 6usize;
        let n = 5_000i64;
        let way_batches: Vec<RecordBatch> = (0..k as i64)
            .map(|j| {
                let mut acc = WayAccumulator::new();
                for i in j * n..(j + 1) * n {
                    acc.push(&WayRecord {
                        id: i,
                        geometry: Some(vec![1u8, 2, 3, 4]), // dummy WKB
                        tags_json: r#"{"highway":"residential"}"#.to_string(),
                        node_refs: vec![i, i + 1, i + 2],
                        version: Some(3),
                    });
                }
                acc.take_remaining().unwrap().unwrap()
            })
            .collect();
        // Parallel encode across gatling units sharing one Sync encoder (ROOT LAW
        // #0 — no rayon, no hand-rolled `thread::scope` pool).
        let way_groups: Vec<EncodedRowGroup> = gatling::gatling_forkjoin::gatling_map_balanced(
            &way_batches,
            0,
            1,
            |b: &RecordBatch| b.num_rows() as u64,
            |_i, b: &RecordBatch| way_enc.encode(b).unwrap(),
        );
        for g in way_groups {
            way_w.append(g).unwrap();
        }
        way_w.finish().unwrap();
        let (rows, rgs, has_geo) = total_rows_in(&way_path);
        assert_eq!(
            rows,
            k as i64 * n,
            "way row count must match injected records"
        );
        assert_eq!(rgs, k, "one way row group per worker batch");
        assert!(has_geo, "ways GeoParquet `geo` metadata must be preserved");

        // ── Relations ───────────────────────────────────────────────────────────
        let rel_path = dir.path().join("relations.parquet");
        let (rel_enc, mut rel_w) = parallel_rel_writer(&rel_path, "zstd").unwrap();
        let rel_batches: Vec<RecordBatch> = (0..k as i64)
            .map(|j| {
                let mut acc = RelAccumulator::new();
                for i in j * n..(j + 1) * n {
                    acc.push(&RelationRecord {
                        id: i,
                        tags_json: r#"{"type":"multipolygon"}"#.to_string(),
                        members_json: r#"[{"type":"way","ref":1,"role":"outer"}]"#.to_string(),
                        version: Some(2),
                    });
                }
                acc.take_remaining().unwrap().unwrap()
            })
            .collect();
        let rel_groups: Vec<EncodedRowGroup> = gatling::gatling_forkjoin::gatling_map_balanced(
            &rel_batches,
            0,
            1,
            |b: &RecordBatch| b.num_rows() as u64,
            |_i, b: &RecordBatch| rel_enc.encode(b).unwrap(),
        );
        for g in rel_groups {
            rel_w.append(g).unwrap();
        }
        rel_w.finish().unwrap();
        let (rrows, rrgs, rgeo) = total_rows_in(&rel_path);
        assert_eq!(
            rrows,
            k as i64 * n,
            "relation row count must match injected records"
        );
        assert_eq!(rrgs, k, "one relation row group per worker batch");
        assert!(
            rgeo,
            "relations GeoParquet `geo` metadata must be preserved"
        );
    }

    /// Benchmark: parallel (per-worker-thread) encode vs serial single-thread
    /// encode of the same row groups. Prints the speedup; asserts the parallel
    /// path is not slower than serial within noise (so a regression that
    /// accidentally serializes the encode is caught). Run with
    /// `cargo test -p osm2geoparquet --release -- --nocapture parallel_encode_speedup`.
    #[test]
    fn parallel_encode_speedup() {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let k: i64 = threads as i64 * 2; // a couple of row groups per core
        let n: i64 = 50_000;
        let batches: Vec<RecordBatch> = (0..k).map(|j| make_batch(j * n, n)).collect();

        let dir = tempfile::tempdir().unwrap();
        let (enc, _w) = parallel_node_writer(&dir.path().join("bench.parquet"), "zstd").unwrap();

        // Serial: encode every row group on one thread.
        let t0 = Instant::now();
        for b in &batches {
            std::hint::black_box(enc.encode(b).unwrap());
        }
        let serial = t0.elapsed();

        // Parallel: gatling fan-out over the row groups, shared encoder. Same
        // engine the convert path uses, so this measures the real thing.
        let t1 = Instant::now();
        std::hint::black_box(gatling::gatling_forkjoin::gatling_map_balanced(
            &batches,
            0,
            1,
            |b: &RecordBatch| b.num_rows() as u64,
            |_i, b: &RecordBatch| std::hint::black_box(enc.encode(b).unwrap()),
        ));
        let parallel = t1.elapsed();

        let speedup = serial.as_secs_f64() / parallel.as_secs_f64();
        eprintln!(
            "parallel node encode: {k} row groups × {n} rows on {threads} cores → \
             serial={serial:?} parallel={parallel:?} speedup={speedup:.2}×"
        );

        // The encode must genuinely run in parallel: allow generous slack for a
        // busy or low-core CI box, but a fully-serialized regression (speedup
        // ≈ 1 or worse on a multi-core box) should fail here.
        if threads >= 4 {
            assert!(
                speedup > 1.5,
                "expected parallel encode speedup > 1.5× on {threads} cores, got {speedup:.2}×"
            );
        }
    }
}
