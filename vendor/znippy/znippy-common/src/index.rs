// index.rs — v0.6 format: blobs stored inline, Arrow IPC is a pure metadata index.
//
// File layout:
//   [blob_0][blob_1]...[blob_N]  — compressed/raw chunk bytes, written as produced
//   [Arrow IPC stream]           — metadata index, written after all blobs
//   [8 bytes LE u64]             — byte offset where Arrow IPC starts (footer)
//
// Arrow schema columns:
//   relative_path, chunk_seq, fdata_offset, checksum_group,
//   compressed, uncompressed_size, blob_offset, blob_size, checksum

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::common_config::StrategicConfig;
use crate::decompress_archive;
use crate::meta::BlobMeta;
use crate::plugin::ExtensionRow;
use anyhow::Result;
use arrow::array::{
    Array, ArrayRef, BooleanBuilder, FixedSizeBinaryBuilder, Int8Builder, StringBuilder,
    UInt32Builder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use once_cell::sync::Lazy;

/// Per-file extension metadata carried into the Arrow index.
/// (plugin_type_id, extracted fields) — None for files with no matching plugin.
pub type FileExtMeta = Option<(i8, ExtensionRow)>;

/// v0.6 schema: Arrow IPC is a pure metadata index; blobs are stored inline before it.
/// Base index columns — present in every archive, type-agnostic.
/// Package-type modules contribute their own columns on top via `schema_fields()`;
/// the writer composes the on-disk schema with [`compose_index_schema`].
pub static ZNIPPY_INDEX_SCHEMA: Lazy<Arc<Schema>> =
    Lazy::new(|| Arc::new(Schema::new(base_index_fields())));

fn base_index_fields() -> Vec<Field> {
    vec![
        Field::new("relative_path", DataType::Utf8, false),
        Field::new("chunk_seq", DataType::UInt32, false),
        Field::new("fdata_offset", DataType::UInt64, false),
        Field::new("compressed", DataType::Boolean, false),
        Field::new("uncompressed_size", DataType::UInt64, false),
        Field::new("blob_offset", DataType::UInt64, false),
        Field::new("blob_size", DataType::UInt64, false),
        Field::new("checksum", DataType::FixedSizeBinary(32), false),
    ]
}

pub fn znippy_index_schema() -> &'static Arc<Schema> {
    &ZNIPPY_INDEX_SCHEMA
}

/// Compose the on-disk index schema: base columns, plus — when a module contributes columns —
/// a `pkg_type` discriminator followed by the module's own `ext_fields`.
/// With no module fields, this is exactly the base schema (v0.6 layout, directly DuckDB-queryable).
pub fn compose_index_schema(ext_fields: &[Field]) -> Arc<Schema> {
    let mut fields = base_index_fields();
    if !ext_fields.is_empty() {
        fields.push(Field::new("pkg_type", DataType::Int8, true));
        fields.extend(ext_fields.iter().cloned());
    }
    Arc::new(Schema::new(fields))
}

/// On-disk archive format version, recorded in the Arrow index schema metadata
/// under `znippy_format_version`. The reader refuses any archive whose recorded
/// version is greater than this — a newer format it cannot safely parse — with a
/// clear error instead of panicking or mis-parsing. Bump only on a real on-disk
/// format change.
pub const ZNIPPY_FORMAT_VERSION: u32 = 3;

/// Schema-metadata key holding the on-disk [`ZNIPPY_FORMAT_VERSION`].
pub const FORMAT_VERSION_KEY: &str = "znippy_format_version";

/// Enforce that an archive's recorded format version is one this reader supports.
/// `metadata` is an Arrow schema's key/value metadata. A *newer* version yields a
/// clear error instead of a panic or silent mis-parse; equal/older versions — and
/// archives with no recorded version — read exactly as before.
pub fn check_format_version(metadata: &HashMap<String, String>) -> Result<()> {
    if let Some(raw) = metadata.get(FORMAT_VERSION_KEY) {
        let version: u32 = raw
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid znippy archive format version {raw:?}"))?;
        anyhow::ensure!(
            version <= ZNIPPY_FORMAT_VERSION,
            "znippy archive format v{version} is newer than this reader supports \
             (max v{ZNIPPY_FORMAT_VERSION}) — upgrade znippy",
        );
    }
    Ok(())
}

/// Build Arrow schema metadata containing config (no checksum entries — those live in column).
pub fn build_arrow_metadata_for_config(config: &StrategicConfig) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(FORMAT_VERSION_KEY.into(), ZNIPPY_FORMAT_VERSION.to_string());
    m.insert(
        "max_core_in_flight".into(),
        config.max_core_in_flight.to_string(),
    );
    m.insert(
        "max_core_in_compress".into(),
        config.max_core_in_compress.to_string(),
    );
    m.insert("max_mem_allowed".into(), config.max_mem_allowed.to_string());
    m.insert(
        "min_free_memory_ratio".into(),
        config.min_free_memory_ratio.to_string(),
    );
    m.insert(
        "file_split_block_size".into(),
        config.file_split_block_size.to_string(),
    );
    m.insert("max_chunks".into(), config.max_chunks.to_string());
    m.insert(
        "compression_level".into(),
        config.compression_level.to_string(),
    );
    m.insert(
        "zstd_output_buffer_size".into(),
        config.zstd_output_buffer_size.to_string(),
    );
    m
}

pub fn extract_config_from_arrow_metadata(
    metadata: &HashMap<String, String>,
) -> anyhow::Result<StrategicConfig> {
    Ok(StrategicConfig {
        max_core_allowed: 0,
        max_core_in_flight: metadata
            .get("max_core_in_flight")
            .ok_or_else(|| anyhow::anyhow!("Missing 'max_core_in_flight'"))?
            .parse()?,
        max_core_in_compress: metadata
            .get("max_core_in_compress")
            .ok_or_else(|| anyhow::anyhow!("Missing 'max_core_in_compress'"))?
            .parse()?,
        max_mem_allowed: metadata
            .get("max_mem_allowed")
            .ok_or_else(|| anyhow::anyhow!("Missing 'max_mem_allowed'"))?
            .parse()?,
        min_free_memory_ratio: metadata
            .get("min_free_memory_ratio")
            .ok_or_else(|| anyhow::anyhow!("Missing 'min_free_memory_ratio'"))?
            .parse()?,
        file_split_block_size: metadata
            .get("file_split_block_size")
            .ok_or_else(|| anyhow::anyhow!("Missing 'file_split_block_size'"))?
            .parse()?,
        max_chunks: metadata
            .get("max_chunks")
            .ok_or_else(|| anyhow::anyhow!("Missing 'max_chunks'"))?
            .parse()?,
        compression_level: metadata
            .get("compression_level")
            .ok_or_else(|| anyhow::anyhow!("Missing 'compression_level'"))?
            .parse()?,
        zstd_output_buffer_size: metadata
            .get("zstd_output_buffer_size")
            .ok_or_else(|| anyhow::anyhow!("Missing 'zstd_output_buffer_size'"))?
            .parse()?,
    })
}

/// Build the Arrow metadata index batch from blob positions.
///
/// Every row carries its own per-slice BLAKE3 in the `checksum` column
/// (over the chunk's uncompressed bytes).
pub fn build_metadata_batch<F>(
    blobs: &[BlobMeta],
    path_resolver: F,
    ext_meta: &[FileExtMeta],
    ext_fields: &[Field],
) -> arrow::error::Result<RecordBatch>
where
    F: Fn(u64) -> String,
{
    let len = blobs.len();

    let mut path_builder = StringBuilder::with_capacity(len, len * 64);
    let mut seq_builder = UInt32Builder::with_capacity(len);
    let mut fdata_builder = UInt64Builder::with_capacity(len);
    let mut compressed_builder = BooleanBuilder::with_capacity(len);
    let mut size_builder = UInt64Builder::with_capacity(len);
    let mut blob_offset_builder = UInt64Builder::with_capacity(len);
    let mut blob_size_builder = UInt64Builder::with_capacity(len);
    let mut checksum_builder = FixedSizeBinaryBuilder::with_capacity(len, 32);

    for blob in blobs {
        let m = &blob.chunk_meta;
        path_builder.append_value(path_resolver(m.file_index));
        seq_builder.append_value(m.chunk_seq);
        fdata_builder.append_value(m.fdata_offset);
        compressed_builder.append_value(m.compressed);
        size_builder.append_value(m.uncompressed_size);
        blob_offset_builder.append_value(blob.blob_offset);
        blob_size_builder.append_value(blob.blob_size);
        checksum_builder.append_value(m.checksum)?;
    }

    let mut columns: Vec<ArrayRef> = vec![
        Arc::new(path_builder.finish()),
        Arc::new(seq_builder.finish()),
        Arc::new(fdata_builder.finish()),
        Arc::new(compressed_builder.finish()),
        Arc::new(size_builder.finish()),
        Arc::new(blob_offset_builder.finish()),
        Arc::new(blob_size_builder.finish()),
        Arc::new(checksum_builder.finish()),
    ];

    // Module-contributed columns: a pkg_type discriminator + one column per ext field.
    if !ext_fields.is_empty() {
        let mut pkg_type_builder = Int8Builder::with_capacity(len);
        for blob in blobs {
            match ext_meta
                .get(blob.chunk_meta.file_index as usize)
                .and_then(|x| x.as_ref())
            {
                Some((type_id, _)) => pkg_type_builder.append_value(*type_id),
                None => pkg_type_builder.append_null(),
            }
        }
        columns.push(Arc::new(pkg_type_builder.finish()));

        for field in ext_fields {
            columns.push(build_ext_column(field, blobs, ext_meta));
        }
    }

    RecordBatch::try_new(compose_index_schema(ext_fields), columns)
}

/// Build one extension column from the per-file `ExtensionRow`, keyed by the field name.
/// Supports the Arrow types modules currently declare (Utf8, UInt32); other types yield nulls.
fn build_ext_column(field: &Field, blobs: &[BlobMeta], ext_meta: &[FileExtMeta]) -> ArrayRef {
    use crate::plugin::ExtensionValue;
    let len = blobs.len();
    let value_for = |blob: &BlobMeta| -> Option<&ExtensionValue> {
        ext_meta
            .get(blob.chunk_meta.file_index as usize)
            .and_then(|x| x.as_ref())
            .and_then(|(_, row)| row.fields.get(field.name()))
    };

    match field.data_type() {
        DataType::UInt32 => {
            let mut b = UInt32Builder::with_capacity(len);
            for blob in blobs {
                match value_for(blob) {
                    Some(ExtensionValue::U32(n)) => b.append_value(*n),
                    _ => b.append_null(),
                }
            }
            Arc::new(b.finish())
        }
        // Default to Utf8 for string-like fields (Str / OptStr).
        _ => {
            let mut b = StringBuilder::with_capacity(len, len * 16);
            for blob in blobs {
                match value_for(blob) {
                    Some(ExtensionValue::Str(s)) => b.append_value(s),
                    Some(ExtensionValue::OptStr(Some(s))) => b.append_value(s),
                    _ => b.append_null(),
                }
            }
            Arc::new(b.finish())
        }
    }
}

// ─── Multi-index container codec (planned v0.7, see design.md §6) ──────────────
//
// A multi-type archive holds several Arrow IPC index streams (one per (pkg_type, repo)
// sub-znippy, each with its own narrow schema), followed by a manifest stream that points
// at them, and a footer. The footer layout still *distinguishes* the legacy v0.6 trailer
// from the v0.7 one, but v0.6 archives are no longer readable — they are detected only to
// emit a clear "unsupported, re-compress with v0.7" error (see `read_znippy_index_filtered`):
//
//   v0.6 single index:  [...index...] [8-byte LE u64 index_offset]
//   v0.7 multi index:   [...sub-indexes...][manifest] [8-byte MAGIC] [8-byte LE u64 manifest_offset]
//
// A reader peeks the 8 bytes preceding the trailing offset: if they equal MAGIC it's a
// multi-index (v0.7) archive; otherwise it's a legacy v0.6 single index, which the reader
// rejects rather than parses.

/// Magic preceding the trailing offset that marks a multi-index (v0.7) archive.
pub const MULTI_INDEX_MAGIC: [u8; 8] = *b"ZNPYMIDX";

/// One entry in the multi-index manifest: a sub-znippy's identity + byte range.
#[derive(Debug, Clone, PartialEq)]
pub struct ManifestEntry {
    pub pkg_type: i8,
    pub repo: String,
    pub module_name: String,
    pub index_offset: u64,
    pub index_len: u64,
    pub row_count: u64,
}

/// Reserved `module_name` for the sorted random-access lookup sub-index.
/// Its rows are the base index columns re-sorted by `(relative_path, chunk_seq)`,
/// so external tools can `SELECT … WHERE relative_path = …` in O(log n) and the
/// native reader can binary-search it. Manifest readers filter this entry out of
/// the data sub-index set; [`read_znippy_lookup`] reads it explicitly.
pub const LOOKUP_MODULE: &str = "__znippy_lookup__";

/// Reserved `module_name` for the fst trie blob: an `fst::Map` of
/// `relative_path → first row index in the lookup sub-index`. Not Arrow IPC —
/// raw fst bytes — so it must never be parsed as a sub-index.
pub const TRIE_MODULE: &str = "__znippy_trie__";

/// Reserved `module_name` for the per-artifact detached CMS signatures
/// (feature `sign`). An Arrow IPC sub-index of `(relative_path, cms)` rows — one
/// detached CMS `SignedData` per file, over that file's merkle-folded chunk
/// hashes. Additive: readers that don't know it simply skip it (it is reserved),
/// so unsigned archives are byte-identical and old readers ignore signed ones.
pub const SIGN_ARTIFACTS_MODULE: &str = "__znippy_sign_artifacts__";

/// Reserved `module_name` for the per-archive detached CMS signature (feature
/// `sign`): raw CMS `SignedData` (DER) over the archive root digest.
pub const SIGN_ARCHIVE_MODULE: &str = "__znippy_sign_archive__";

/// `pkg_type` discriminant carried by reserved (non-data) manifest entries.
pub const RESERVED_PKG_TYPE: i8 = i8::MIN;

/// A reserved manifest entry holds a derived structure (lookup / trie / detached
/// signatures), not file rows. The merge + manifest readers skip these so data
/// consumers are unaffected — which is exactly what makes the signature sections
/// additive and backward-compatible.
pub fn is_reserved_module(module_name: &str) -> bool {
    module_name == LOOKUP_MODULE
        || module_name == TRIE_MODULE
        || module_name == SIGN_ARTIFACTS_MODULE
        || module_name == SIGN_ARCHIVE_MODULE
}

/// Read the raw bytes of one reserved sub-section by module name, if present.
/// Public entry point for the signature layer (feature `sign`) and any other
/// reader that needs a reserved section's bytes without re-implementing the
/// manifest walk.
pub fn read_reserved_section_bytes(path: &Path, module_name: &str) -> Result<Option<Vec<u8>>> {
    read_reserved_section(path, module_name)
}

/// Schema of the lookup sub-index — identical to the base index columns. The
/// lookup is the same per-chunk rows, re-sorted by `(relative_path, chunk_seq)`
/// and stripped of any plugin columns, so one path's chunks are contiguous.
pub fn lookup_schema() -> Arc<Schema> {
    Arc::new(Schema::new(base_index_fields()))
}

/// One chunk's location for single-file random access.
#[derive(Debug, Clone)]
pub struct ChunkLoc {
    pub chunk_seq: u32,
    pub fdata_offset: u64,
    pub blob_offset: u64,
    pub blob_size: u64,
    pub uncompressed_size: u64,
    pub compressed: bool,
    pub checksum: [u8; 32],
}

/// What the trailing footer of an archive points at.
#[derive(Debug, Clone, PartialEq)]
pub enum IndexFooter {
    /// Legacy v0.6: a single Arrow IPC index began at this offset. Still detected
    /// so the reader can reject v0.6 archives with a clear "re-compress with v0.7"
    /// error — it is no longer a live read path.
    Single { index_offset: u64 },
    /// v0.7: the manifest stream begins at this offset.
    Multi { manifest_offset: u64 },
}

/// Interpret an archive's trailing bytes. `tail` must be the last 16 bytes of the file
/// (or last 8 for tiny v0.6 files — then it's always Single).
pub fn interpret_footer(tail: &[u8]) -> IndexFooter {
    let n = tail.len();
    let offset = u64::from_le_bytes(tail[n - 8..].try_into().unwrap());
    if n >= 16 && tail[n - 16..n - 8] == MULTI_INDEX_MAGIC {
        IndexFooter::Multi {
            manifest_offset: offset,
        }
    } else {
        IndexFooter::Single {
            index_offset: offset,
        }
    }
}

fn manifest_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("pkg_type", DataType::Int8, false),
        Field::new("repo", DataType::Utf8, false),
        Field::new("module_name", DataType::Utf8, false),
        Field::new("index_offset", DataType::UInt64, false),
        Field::new("index_len", DataType::UInt64, false),
        Field::new("row_count", DataType::UInt64, false),
    ]))
}

/// Serialize manifest entries to an Arrow IPC stream (itself DuckDB-readable).
pub fn write_manifest_bytes(entries: &[ManifestEntry]) -> Result<Vec<u8>> {
    use arrow::ipc::writer::StreamWriter;

    let len = entries.len();
    let mut pkg_type = Int8Builder::with_capacity(len);
    let mut repo = StringBuilder::with_capacity(len, len * 16);
    let mut module_name = StringBuilder::with_capacity(len, len * 16);
    let mut index_offset = UInt64Builder::with_capacity(len);
    let mut index_len = UInt64Builder::with_capacity(len);
    let mut row_count = UInt64Builder::with_capacity(len);
    for e in entries {
        pkg_type.append_value(e.pkg_type);
        repo.append_value(&e.repo);
        module_name.append_value(&e.module_name);
        index_offset.append_value(e.index_offset);
        index_len.append_value(e.index_len);
        row_count.append_value(e.row_count);
    }

    let schema = manifest_schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(pkg_type.finish()),
            Arc::new(repo.finish()),
            Arc::new(module_name.finish()),
            Arc::new(index_offset.finish()),
            Arc::new(index_len.finish()),
            Arc::new(row_count.finish()),
        ],
    )?;

    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::try_new(&mut buf, &schema)?;
        w.write(&batch)?;
        w.finish()?;
    }
    Ok(buf)
}

/// Parse a manifest Arrow IPC stream back into entries.
pub fn read_manifest_bytes(bytes: &[u8]) -> Result<Vec<ManifestEntry>> {
    use arrow::array::{Int8Array, StringArray, UInt64Array};
    use arrow::ipc::reader::StreamReader;

    let reader = StreamReader::try_new(std::io::Cursor::new(bytes), None)?;
    let mut out = Vec::new();
    for batch in reader {
        let batch = batch?;
        let col = |name: &str| {
            batch
                .column_by_name(name)
                .ok_or_else(|| anyhow::anyhow!("manifest missing column {name}"))
        };
        let pkg_type = col("pkg_type")?
            .as_any()
            .downcast_ref::<Int8Array>()
            .ok_or_else(|| anyhow::anyhow!("pkg_type type"))?;
        let repo = col("repo")?
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| anyhow::anyhow!("repo type"))?;
        let module_name = col("module_name")?
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| anyhow::anyhow!("module_name type"))?;
        let index_offset = col("index_offset")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow::anyhow!("index_offset type"))?;
        let index_len = col("index_len")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow::anyhow!("index_len type"))?;
        let row_count = col("row_count")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow::anyhow!("row_count type"))?;
        for i in 0..batch.num_rows() {
            out.push(ManifestEntry {
                pkg_type: pkg_type.value(i),
                repo: repo.value(i).to_string(),
                module_name: module_name.value(i).to_string(),
                index_offset: index_offset.value(i),
                index_len: index_len.value(i),
                row_count: row_count.value(i),
            });
        }
    }
    Ok(out)
}

/// Read the Arrow IPC index from a v0.7 .znippy file.
///
/// Reads the 16-byte footer (8-byte `ZNPYMIDX` magic + 8-byte LE u64 manifest_offset),
/// parses the manifest, reads every sub-index, and merges all batches into one so callers
/// need no format-version awareness.
pub fn read_znippy_index(path: &Path) -> Result<(Arc<Schema>, Vec<RecordBatch>)> {
    read_znippy_index_filtered(path, &IndexFilter::default())
}

/// Selective sub-index filter: keep only sub-indexes whose manifest entry
/// matches. A `None` field matches anything, so `IndexFilter::default()` reads
/// the whole archive (what [`read_znippy_index`] does). Filtering happens at the
/// `(pkg_type, repo)` sub-index granularity — whole Arrow IPC streams are
/// skipped, never read — so a selective extract touches only the matching rows.
#[derive(Debug, Clone, Default)]
pub struct IndexFilter {
    /// Keep only this package-type discriminant (`ManifestEntry::pkg_type`).
    pub pkg_type: Option<i8>,
    /// Keep only this repo (`ManifestEntry::repo`).
    pub repo: Option<String>,
}

impl IndexFilter {
    pub fn is_empty(&self) -> bool {
        self.pkg_type.is_none() && self.repo.is_none()
    }
    fn matches(&self, e: &ManifestEntry) -> bool {
        self.pkg_type.is_none_or(|t| e.pkg_type == t)
            && self.repo.as_deref().is_none_or(|r| e.repo == r)
    }
}

/// Like [`read_znippy_index`] but keeps only sub-indexes matching `filter`.
pub fn read_znippy_index_filtered(
    path: &Path,
    filter: &IndexFilter,
) -> Result<(Arc<Schema>, Vec<RecordBatch>)> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    anyhow::ensure!(file_len >= 16, "file too small to be a v0.7 znippy archive");

    file.seek(SeekFrom::End(-16))?;
    let mut tail = [0u8; 16];
    file.read_exact(&mut tail)?;

    match interpret_footer(&tail) {
        IndexFooter::Multi { manifest_offset } => {
            read_multi_index(&mut file, file_len, manifest_offset, filter)
        }
        IndexFooter::Single { .. } => {
            anyhow::bail!("v0.6 archives are not supported; re-compress with v0.7")
        }
    }
}

/// Read all sub-indexes from a v0.7 multi-index archive and concatenate them.
fn read_multi_index(
    file: &mut File,
    file_len: u64,
    manifest_offset: u64,
    filter: &IndexFilter,
) -> Result<(Arc<Schema>, Vec<RecordBatch>)> {
    use arrow::ipc::reader::StreamReader;

    // manifest lives between manifest_offset and (file_len − 16): 8-byte magic + 8-byte offset
    let manifest_end = file_len
        .checked_sub(16)
        .ok_or_else(|| anyhow::anyhow!("v0.7 archive too small"))?;
    anyhow::ensure!(
        manifest_offset <= manifest_end,
        "corrupt v0.7 manifest_offset"
    );
    let manifest_len = (manifest_end - manifest_offset) as usize;

    file.seek(SeekFrom::Start(manifest_offset))?;
    let mut manifest_bytes = vec![0u8; manifest_len];
    file.read_exact(&mut manifest_bytes)?;
    let entries = read_manifest_bytes(&manifest_bytes)?;

    let mut all_batches: Vec<RecordBatch> = Vec::new();
    let mut schema: Option<Arc<Schema>> = None;

    for entry in &entries {
        // Skip derived structures (lookup sub-index, trie blob) — they are not
        // file-row data and must not be merged into the index.
        if is_reserved_module(&entry.module_name) {
            continue;
        }
        // Selective read: skip whole sub-indexes that don't match the filter.
        if !filter.matches(entry) {
            continue;
        }
        file.seek(SeekFrom::Start(entry.index_offset))?;
        let mut sub_bytes = vec![0u8; entry.index_len as usize];
        file.read_exact(&mut sub_bytes)?;
        let cursor = std::io::Cursor::new(sub_bytes);
        let reader = StreamReader::try_new(cursor, None)?;
        if schema.is_none() {
            let sub_schema = reader.schema();
            // Refuse archives written by a newer znippy than this reader supports,
            // before parsing any sub-index batches we might mis-interpret.
            check_format_version(sub_schema.metadata())?;
            schema = Some(sub_schema);
        }
        for batch in reader {
            all_batches.push(batch.map_err(|e| anyhow::anyhow!("sub-index read error: {}", e))?);
        }
    }

    let schema = schema.unwrap_or_else(|| Arc::new(Schema::new(base_index_fields())));

    // Merge all sub-index batches into one so callers stay format-agnostic.
    let merged = if all_batches.len() <= 1 {
        all_batches
    } else {
        let batch = arrow_select::concat::concat_batches(&schema, all_batches.iter())
            .map_err(|e| anyhow::anyhow!("concat sub-indexes: {}", e))?;
        vec![batch]
    };

    Ok((schema, merged))
}

/// Read the manifest from a v0.7 multi-index archive.
/// Returns an error if the file is a plain v0.6 single-index archive.
pub fn read_znippy_manifest(path: &Path) -> Result<Vec<ManifestEntry>> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    anyhow::ensure!(file_len >= 16, "file too small to be a v0.7 archive");

    file.seek(SeekFrom::End(-16))?;
    let mut tail = [0u8; 16];
    file.read_exact(&mut tail)?;

    match interpret_footer(&tail) {
        IndexFooter::Single { .. } => {
            anyhow::bail!("not a v0.7 multi-index archive (no MULTI_INDEX_MAGIC)")
        }
        IndexFooter::Multi { manifest_offset } => {
            let manifest_end = file_len - 16;
            anyhow::ensure!(manifest_offset <= manifest_end, "corrupt manifest_offset");
            let manifest_len = (manifest_end - manifest_offset) as usize;
            file.seek(SeekFrom::Start(manifest_offset))?;
            let mut manifest_bytes = vec![0u8; manifest_len];
            file.read_exact(&mut manifest_bytes)?;
            let mut entries = read_manifest_bytes(&manifest_bytes)?;
            // Hide reserved (lookup/trie) entries from data-manifest consumers.
            entries.retain(|e| !is_reserved_module(&e.module_name));
            Ok(entries)
        }
    }
}

/// Read **all** manifest entries of a sealed v0.7 archive, *including* the
/// reserved (lookup/trie) ones, plus the manifest's byte offset.
///
/// Public entrypoint used by the append/resume sink
/// ([`ArrowIpcSinkAppend::open_existing`](crate::ArrowIpcSinkAppend::open_existing)):
/// it needs the reserved sections (to find the blob-region end and to recover
/// the sorted lookup) which `read_znippy_manifest` hides. Read-only — does not
/// touch the original write path.
pub fn read_znippy_full_manifest(path: &Path) -> Result<(Vec<ManifestEntry>, u64)> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    read_full_manifest(&mut file, file_len)
}

/// Read all manifest entries, *including* reserved (lookup/trie) ones.
fn read_full_manifest(file: &mut File, file_len: u64) -> Result<(Vec<ManifestEntry>, u64)> {
    anyhow::ensure!(file_len >= 16, "file too small to be a v0.7 archive");
    file.seek(SeekFrom::End(-16))?;
    let mut tail = [0u8; 16];
    file.read_exact(&mut tail)?;
    let manifest_offset = match interpret_footer(&tail) {
        IndexFooter::Multi { manifest_offset } => manifest_offset,
        IndexFooter::Single { .. } => anyhow::bail!("not a v0.7 multi-index archive"),
    };
    let manifest_end = file_len
        .checked_sub(16)
        .ok_or_else(|| anyhow::anyhow!("v0.7 archive too small"))?;
    anyhow::ensure!(manifest_offset <= manifest_end, "corrupt manifest_offset");
    let manifest_len = (manifest_end - manifest_offset) as usize;
    file.seek(SeekFrom::Start(manifest_offset))?;
    let mut manifest_bytes = vec![0u8; manifest_len];
    file.read_exact(&mut manifest_bytes)?;
    Ok((read_manifest_bytes(&manifest_bytes)?, manifest_offset))
}

/// Read the raw bytes of one reserved sub-section (lookup or trie), if present.
fn read_reserved_section(path: &Path, module_name: &str) -> Result<Option<Vec<u8>>> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let (entries, _) = read_full_manifest(&mut file, file_len)?;
    let Some(entry) = entries.iter().find(|e| e.module_name == module_name) else {
        return Ok(None);
    };
    file.seek(SeekFrom::Start(entry.index_offset))?;
    let mut bytes = vec![0u8; entry.index_len as usize];
    file.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

/// Decode the lookup sub-index bytes into parallel column vectors (already sorted
/// by `(relative_path, chunk_seq)` on disk).
fn decode_lookup(bytes: &[u8]) -> Result<LookupColumns> {
    use arrow::array::{BooleanArray, FixedSizeBinaryArray, StringArray, UInt32Array, UInt64Array};
    use arrow::ipc::reader::StreamReader;

    let reader = StreamReader::try_new(std::io::Cursor::new(bytes), None)?;
    let mut cols = LookupColumns::default();
    for batch in reader {
        let batch = batch?;
        let get = |n: &str| {
            batch
                .column_by_name(n)
                .ok_or_else(|| anyhow::anyhow!("lookup missing column {n}"))
        };
        let paths = get("relative_path")?
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| anyhow::anyhow!("relative_path type"))?;
        let chunk_seq = get("chunk_seq")?
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or_else(|| anyhow::anyhow!("chunk_seq type"))?;
        let fdata = get("fdata_offset")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow::anyhow!("fdata_offset type"))?;
        let compressed = get("compressed")?
            .as_any()
            .downcast_ref::<BooleanArray>()
            .ok_or_else(|| anyhow::anyhow!("compressed type"))?;
        let usize_col = get("uncompressed_size")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow::anyhow!("uncompressed_size type"))?;
        let blob_offset = get("blob_offset")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow::anyhow!("blob_offset type"))?;
        let blob_size = get("blob_size")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow::anyhow!("blob_size type"))?;
        let checksum = get("checksum")?
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .ok_or_else(|| anyhow::anyhow!("checksum type"))?;
        for i in 0..batch.num_rows() {
            cols.paths.push(paths.value(i).to_string());
            let mut ck = [0u8; 32];
            ck.copy_from_slice(checksum.value(i));
            cols.locs.push(ChunkLoc {
                chunk_seq: chunk_seq.value(i),
                fdata_offset: fdata.value(i),
                blob_offset: blob_offset.value(i),
                blob_size: blob_size.value(i),
                uncompressed_size: usize_col.value(i),
                compressed: compressed.value(i),
                checksum: ck,
            });
        }
    }
    Ok(cols)
}

#[derive(Default)]
struct LookupColumns {
    paths: Vec<String>,
    locs: Vec<ChunkLoc>,
}

/// Locate every chunk of `target` for single-file random access.
///
/// Fast paths, in order: the fst trie (O(key length)) → binary search of the
/// sorted lookup sub-index (O(log n)) → linear scan of the merged main index
/// (O(n), for archives written before the lookup layer existed). Returns the
/// chunks sorted by `chunk_seq`, or an empty vec if `target` is not in the archive.
pub fn locate_file(path: &Path, target: &str) -> Result<Vec<ChunkLoc>> {
    if let Some(lookup_bytes) = read_reserved_section(path, LOOKUP_MODULE)? {
        let cols = decode_lookup(&lookup_bytes)?;
        let n = cols.paths.len();

        // Find any row whose path == target.
        let hit = if let Some(trie_bytes) = read_reserved_section(path, TRIE_MODULE)? {
            let map = fst::Map::new(trie_bytes).map_err(|e| anyhow::anyhow!("trie open: {e}"))?;
            map.get(target.as_bytes()).map(|v| v as usize)
        } else {
            // Lookup is sorted by path; binary-search the path column.
            match cols.paths.binary_search_by(|p| p.as_str().cmp(target)) {
                Ok(i) => Some(i),
                Err(_) => None,
            }
        };

        let Some(hit) = hit else {
            return Ok(Vec::new());
        };

        // Expand to the contiguous run of rows sharing this path.
        let mut start = hit;
        while start > 0 && cols.paths[start - 1] == target {
            start -= 1;
        }
        let mut end = hit + 1;
        while end < n && cols.paths[end] == target {
            end += 1;
        }

        let mut out: Vec<ChunkLoc> = cols.locs[start..end].to_vec();
        out.sort_by_key(|c| c.chunk_seq);
        return Ok(out);
    }

    // Fallback: no lookup layer — scan the merged main index.
    locate_file_via_index(path, target)
}

/// Slim per-file (per-artifact) metadata for browsing an archive without
/// reading file bytes. One row per file, aggregated across its chunks.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactMeta {
    pub relative_path: String,
    /// Total uncompressed size across all of the file's chunks.
    pub uncompressed_size: u64,
    pub chunk_count: u32,
    /// Whether the file's data was compressed (false on the stored-raw skip path).
    pub compressed: bool,
}

/// Metadata for **every** file in the archive, sorted by `relative_path`.
///
/// Reads only the lookup sub-index (not the file bytes); falls back to the main
/// index for archives written before the lookup layer.
pub fn get_all_files_meta(path: &Path) -> Result<Vec<ArtifactMeta>> {
    files_meta_impl(path, None)
}

/// Metadata for the files whose `relative_path` starts with `prefix` — for when
/// you don't want all files (e.g. one `group/artifact/` subtree).
///
/// When the trie is present this jumps straight to the first matching key via the
/// fst's ordered range (O(prefix) to seek, then O(matches)); otherwise it binary
/// -searches the sorted lookup; otherwise it scans the legacy main index.
pub fn get_files_meta_with_prefix(path: &Path, prefix: &str) -> Result<Vec<ArtifactMeta>> {
    files_meta_impl(path, Some(prefix))
}

fn files_meta_impl(path: &Path, prefix: Option<&str>) -> Result<Vec<ArtifactMeta>> {
    use fst::{IntoStreamer, Streamer};

    if let Some(lookup_bytes) = read_reserved_section(path, LOOKUP_MODULE)? {
        let cols = decode_lookup(&lookup_bytes)?; // sorted by (relative_path, chunk_seq)
        let n = cols.paths.len();

        // Resolve the contiguous row window [lo, hi) to aggregate.
        let (lo, hi) = match prefix {
            None | Some("") => (0, n),
            Some(pre) => {
                // Seek the first key >= prefix. Use the trie's ordered range when
                // present (the "trie search"); else binary-search the sorted paths.
                let lo = if let Some(trie_bytes) = read_reserved_section(path, TRIE_MODULE)? {
                    let map =
                        fst::Map::new(trie_bytes).map_err(|e| anyhow::anyhow!("trie open: {e}"))?;
                    let mut stream = map.range().ge(pre.as_bytes()).into_stream();
                    match stream.next() {
                        Some((k, v)) if k.starts_with(pre.as_bytes()) => v as usize,
                        _ => return Ok(Vec::new()),
                    }
                } else {
                    cols.paths.partition_point(|p| p.as_str() < pre)
                };
                if lo >= n || !cols.paths[lo].starts_with(pre) {
                    return Ok(Vec::new());
                }
                let mut hi = lo;
                while hi < n && cols.paths[hi].starts_with(pre) {
                    hi += 1;
                }
                (lo, hi)
            }
        };

        // Aggregate contiguous chunk rows per path.
        let mut out = Vec::new();
        let mut i = lo;
        while i < hi {
            let p = &cols.paths[i];
            let mut total = 0u64;
            let mut count = 0u32;
            let mut compressed = false;
            while i < hi && &cols.paths[i] == p {
                total += cols.locs[i].uncompressed_size;
                count += 1;
                compressed |= cols.locs[i].compressed;
                i += 1;
            }
            out.push(ArtifactMeta {
                relative_path: p.clone(),
                uncompressed_size: total,
                chunk_count: count,
                compressed,
            });
        }
        return Ok(out);
    }

    files_meta_via_index(path, prefix)
}

/// Legacy fallback: aggregate per-file metadata from the merged main index.
fn files_meta_via_index(path: &Path, prefix: Option<&str>) -> Result<Vec<ArtifactMeta>> {
    use arrow::array::{BooleanArray, StringArray, UInt64Array};

    let (schema, batches) = read_znippy_index(path)?;
    let batch = match batches.len() {
        0 => return Ok(Vec::new()),
        1 => batches.into_iter().next().unwrap(),
        _ => arrow_select::concat::concat_batches(&schema, batches.iter())?,
    };
    let col = |n: &str| {
        batch
            .column_by_name(n)
            .ok_or_else(|| anyhow::anyhow!("index missing column {n}"))
    };
    let paths = col("relative_path")?
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let usize_col = col("uncompressed_size")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .unwrap();
    let compressed = col("compressed")?
        .as_any()
        .downcast_ref::<BooleanArray>()
        .unwrap();

    // Main index rows are not path-sorted, so aggregate via a map.
    let mut agg: HashMap<&str, (u64, u32, bool)> = HashMap::new();
    for i in 0..batch.num_rows() {
        let p = paths.value(i);
        if let Some(pre) = prefix {
            if !p.starts_with(pre) {
                continue;
            }
        }
        let e = agg.entry(p).or_insert((0, 0, false));
        e.0 += usize_col.value(i);
        e.1 += 1;
        e.2 |= compressed.value(i);
    }
    let mut out: Vec<ArtifactMeta> = agg
        .into_iter()
        .map(|(p, (sz, c, comp))| ArtifactMeta {
            relative_path: p.to_string(),
            uncompressed_size: sz,
            chunk_count: c,
            compressed: comp,
        })
        .collect();
    out.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(out)
}

/// O(n) fallback for archives written before the lookup sub-index existed.
fn locate_file_via_index(path: &Path, target: &str) -> Result<Vec<ChunkLoc>> {
    use arrow::array::{BooleanArray, FixedSizeBinaryArray, StringArray, UInt32Array, UInt64Array};

    let (schema, batches) = read_znippy_index(path)?;
    let batch = match batches.len() {
        0 => return Ok(Vec::new()),
        1 => batches.into_iter().next().unwrap(),
        _ => arrow_select::concat::concat_batches(&schema, batches.iter())?,
    };
    let col = |n: &str| {
        batch
            .column_by_name(n)
            .ok_or_else(|| anyhow::anyhow!("index missing column {n}"))
    };
    let paths = col("relative_path")?
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let chunk_seq = col("chunk_seq")?
        .as_any()
        .downcast_ref::<UInt32Array>()
        .unwrap();
    let fdata = col("fdata_offset")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .unwrap();
    let compressed = col("compressed")?
        .as_any()
        .downcast_ref::<BooleanArray>()
        .unwrap();
    let usize_col = col("uncompressed_size")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .unwrap();
    let blob_offset = col("blob_offset")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .unwrap();
    let blob_size = col("blob_size")?
        .as_any()
        .downcast_ref::<UInt64Array>()
        .unwrap();
    let checksum = col("checksum")?
        .as_any()
        .downcast_ref::<FixedSizeBinaryArray>()
        .unwrap();

    let mut out = Vec::new();
    for i in 0..batch.num_rows() {
        if paths.value(i) == target {
            let mut ck = [0u8; 32];
            ck.copy_from_slice(checksum.value(i));
            out.push(ChunkLoc {
                chunk_seq: chunk_seq.value(i),
                fdata_offset: fdata.value(i),
                blob_offset: blob_offset.value(i),
                blob_size: blob_size.value(i),
                uncompressed_size: usize_col.value(i),
                compressed: compressed.value(i),
                checksum: ck,
            });
        }
    }
    out.sort_by_key(|c| c.chunk_seq);
    Ok(out)
}

pub fn is_probably_compressed(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext = ext.to_ascii_lowercase();
        matches!(
            ext.as_str(),
            "zip"
                | "gz"
                | "bz2"
                | "xz"
                | "lz"
                | "lzma"
                | "7z"
                | "rar"
                | "cab"
                | "jar"
                | "war"
                | "ear"
                | "zst"
                | "sz"
                | "lz4"
                | "tgz"
                | "txz"
                | "tbz"
                | "apk"
                | "dmg"
                | "deb"
                | "rpm"
                | "arrow"
                | "mpeg"
                | "mpg"
                | "jpeg"
                | "jpg"
                | "gif"
                | "bmp"
                | "png"
                | "crate"
                | "znippy"
                | "zdata"
                | "parquet"
                | "webp"
                | "webm"
        )
    } else {
        false
    }
}

pub fn should_skip_compression(path: &Path) -> bool {
    is_probably_compressed(path)
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub total_files: usize,
    pub verified_files: usize,
    pub corrupt_files: usize,
    pub total_bytes: u64,
    pub verified_bytes: u64,
    pub corrupt_bytes: u64,
    pub chunks: u64,
}

pub fn list_archive_contents(path: &Path) -> Result<()> {
    let (_schema, batches) = read_znippy_index(path)?;
    for batch in &batches {
        let paths = batch
            .column_by_name("relative_path")
            .and_then(|c| c.as_any().downcast_ref::<arrow::array::StringArray>())
            .ok_or_else(|| anyhow::anyhow!("missing relative_path column"))?;
        let sizes = batch
            .column_by_name("uncompressed_size")
            .and_then(|c| c.as_any().downcast_ref::<arrow::array::UInt64Array>())
            .ok_or_else(|| anyhow::anyhow!("missing uncompressed_size column"))?;
        let chunk_seqs = batch
            .column_by_name("chunk_seq")
            .and_then(|c| c.as_any().downcast_ref::<arrow::array::UInt32Array>());
        let group_ids = batch
            .column_by_name("group_id")
            .and_then(|c| c.as_any().downcast_ref::<arrow::array::StringArray>());
        let artifact_ids = batch
            .column_by_name("artifact_id")
            .and_then(|c| c.as_any().downcast_ref::<arrow::array::StringArray>());
        let versions = batch
            .column_by_name("version")
            .and_then(|c| c.as_any().downcast_ref::<arrow::array::StringArray>());
        for i in 0..batch.num_rows() {
            // Only print once per file (chunk_seq == 0)
            if let Some(seqs) = chunk_seqs {
                if seqs.value(i) != 0 {
                    continue;
                }
            }
            if let (Some(g), Some(a), Some(v)) = (group_ids, artifact_ids, versions) {
                if !g.is_null(i) {
                    println!(
                        "{}\t{}\t{}:{}:{}",
                        paths.value(i),
                        sizes.value(i),
                        g.value(i),
                        a.value(i),
                        v.value(i)
                    );
                    continue;
                }
            }
            println!("{}\t{}", paths.value(i), sizes.value(i));
        }
    }
    Ok(())
}

pub fn verify_archive_integrity(path: &Path) -> Result<VerifyReport> {
    let out_dir = PathBuf::from("/dev/null");
    decompress_archive(path, false, &out_dir)
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn current_and_older_versions_are_accepted() {
        let mut m = HashMap::new();
        // No version recorded (legacy / pre-version archives): read as before.
        check_format_version(&m).unwrap();
        // Exactly the supported version.
        m.insert(FORMAT_VERSION_KEY.into(), ZNIPPY_FORMAT_VERSION.to_string());
        check_format_version(&m).unwrap();
        // An older version.
        m.insert(
            FORMAT_VERSION_KEY.into(),
            (ZNIPPY_FORMAT_VERSION - 1).to_string(),
        );
        check_format_version(&m).unwrap();
    }

    #[test]
    fn newer_version_is_rejected_clearly() {
        let mut m = HashMap::new();
        m.insert(
            FORMAT_VERSION_KEY.into(),
            (ZNIPPY_FORMAT_VERSION + 1).to_string(),
        );
        let err = check_format_version(&m).unwrap_err().to_string();
        assert!(
            err.contains("newer than this reader supports"),
            "got: {err}"
        );
        assert!(err.contains("upgrade znippy"), "got: {err}");
    }

    #[test]
    fn writer_records_the_current_version() {
        let meta = build_arrow_metadata_for_config(&crate::common_config::CONFIG);
        assert_eq!(
            meta.get(FORMAT_VERSION_KEY).map(String::as_str),
            Some(ZNIPPY_FORMAT_VERSION.to_string().as_str())
        );
    }
}
