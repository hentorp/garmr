//! `ArchiveMetaSink` — abstraction over the archive's metadata layer.
//!
//! After the (unchanged) compression pipeline writes all blob bytes to disk, the
//! metadata layer — one Arrow IPC sub-index per `(pkg_type, repo)` group, a
//! manifest, and the `MULTI_INDEX_MAGIC` footer — is written through this trait.
//!
//! [`ArrowIpcSink`] reproduces the v0.7 on-disk format byte-for-byte. Future
//! backends (e.g. Iceberg) implement the same trait without touching the blob
//! pipeline.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use arrow::array::{
    BooleanArray, BooleanBuilder, FixedSizeBinaryArray, FixedSizeBinaryBuilder, StringArray,
    StringBuilder, UInt32Array, UInt32Builder, UInt64Array, UInt64Builder,
};
use arrow::datatypes::Schema;
use arrow::ipc::writer::StreamWriter;
use arrow::record_batch::RecordBatch;

use crate::index::{
    ChunkLoc, LOOKUP_MODULE, MULTI_INDEX_MAGIC, ManifestEntry, RESERVED_PKG_TYPE, TRIE_MODULE,
    lookup_schema, write_manifest_bytes,
};
#[cfg(feature = "sign")]
use crate::index::{SIGN_ARCHIVE_MODULE, SIGN_ARTIFACTS_MODULE};

/// Identifies the logical sub-archive a sub-index belongs to.
#[derive(Debug, Clone)]
pub struct GroupKey {
    pub pkg_type: i8,
    pub repo: String,
    pub module_name: String,
}

/// Writes the archive metadata layer (sub-indexes + manifest + footer).
///
/// The blob bytes have already been written to the output by the compression
/// pipeline; implementations only decide how the metadata is materialized.
pub trait ArchiveMetaSink {
    /// Serialize one sub-index — an Arrow IPC stream of `batches` (one or more)
    /// — place it after the previously written region, and record a manifest
    /// entry for it.
    fn push_subindex(
        &mut self,
        schema: &Schema,
        batches: &[RecordBatch],
        key: GroupKey,
    ) -> Result<()>;

    /// Write the manifest + footer, fsync, and return the total file length.
    fn finish(self: Box<Self>) -> Result<u64>;
}

/// Builds the metadata sink once the compression pipeline knows the output file
/// handle and the byte offset just past the last blob. The factory shape lets a
/// caller (e.g. the CLI) choose the backend — `ArrowIpcSink` (inline, default)
/// or a tokio-backed `IcebergSink` (off in a warehouse dir) — **without**
/// `znippy-compress` taking a dependency on the heavy/async backend: the
/// `IcebergSink` is constructed by the caller's closure, so its tokio/iceberg
/// deps stay in the binary that opted in.
///
/// `args`: `(output_file, blob_end_offset)`. An `ArrowIpcSink` uses both; an
/// `IcebergSink` ignores them (it writes its own warehouse, not the `.znippy`).
pub type MetaSinkFactory = Box<dyn FnOnce(Arc<File>, u64) -> Box<dyn ArchiveMetaSink> + Send>;

/// The default backend: inline Arrow IPC sub-indexes + manifest + 8-byte footer,
/// i.e. the v0.7 znippy container format. Behaviour is identical to the
/// previously-inlined writer tail in `slot_packer` / `stream_packer`.
pub struct ArrowIpcSink {
    file: Arc<File>,
    cursor: u64,
    entries: Vec<ManifestEntry>,
    /// Accumulated base columns of every data sub-index, used to build the sorted
    /// lookup sub-index + trie in [`finish`](ArrowIpcSink::finish).
    lookup_paths: Vec<String>,
    lookup_locs: Vec<ChunkLoc>,
    /// Optional provenance signer (feature `sign`). When set, [`finish`] emits the
    /// per-artifact + per-archive detached CMS signatures as two additional
    /// *reserved* manifest sections — additive and backward-compatible. When
    /// `None` (the default), the produced archive is byte-identical to today's.
    #[cfg(feature = "sign")]
    signer: Option<Box<dyn crate::sign::ArchiveSigner + Send>>,
}

impl ArrowIpcSink {
    /// `blob_end_offset` is the byte offset just past the last blob — where the
    /// first sub-index is placed.
    pub fn new(file: Arc<File>, blob_end_offset: u64) -> Self {
        Self {
            file,
            cursor: blob_end_offset,
            entries: Vec::new(),
            lookup_paths: Vec::new(),
            lookup_locs: Vec::new(),
            #[cfg(feature = "sign")]
            signer: None,
        }
    }

    /// Attach a provenance signer (feature `sign`). On [`finish`], per-artifact and
    /// per-archive detached CMS signatures are written as reserved sections.
    #[cfg(feature = "sign")]
    pub fn with_signer(mut self, signer: Box<dyn crate::sign::ArchiveSigner + Send>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Pull the base index columns from one batch into the lookup accumulator.
    /// Every composed schema carries these columns; if any is absent we skip the
    /// batch (the lookup degrades gracefully — readers fall back to a scan).
    fn accumulate_lookup(&mut self, batch: &RecordBatch) {
        let cols = (|| {
            Some((
                batch
                    .column_by_name("relative_path")?
                    .as_any()
                    .downcast_ref::<StringArray>()?,
                batch
                    .column_by_name("chunk_seq")?
                    .as_any()
                    .downcast_ref::<UInt32Array>()?,
                batch
                    .column_by_name("fdata_offset")?
                    .as_any()
                    .downcast_ref::<UInt64Array>()?,
                batch
                    .column_by_name("compressed")?
                    .as_any()
                    .downcast_ref::<BooleanArray>()?,
                batch
                    .column_by_name("uncompressed_size")?
                    .as_any()
                    .downcast_ref::<UInt64Array>()?,
                batch
                    .column_by_name("blob_offset")?
                    .as_any()
                    .downcast_ref::<UInt64Array>()?,
                batch
                    .column_by_name("blob_size")?
                    .as_any()
                    .downcast_ref::<UInt64Array>()?,
                batch
                    .column_by_name("checksum")?
                    .as_any()
                    .downcast_ref::<FixedSizeBinaryArray>()?,
            ))
        })();
        let Some((paths, chunk_seq, fdata, compressed, usz, blob_off, blob_sz, checksum)) = cols
        else {
            return;
        };
        for i in 0..batch.num_rows() {
            let mut ck = [0u8; 32];
            ck.copy_from_slice(checksum.value(i));
            self.lookup_paths.push(paths.value(i).to_string());
            self.lookup_locs.push(ChunkLoc {
                chunk_seq: chunk_seq.value(i),
                fdata_offset: fdata.value(i),
                blob_offset: blob_off.value(i),
                blob_size: blob_sz.value(i),
                uncompressed_size: usz.value(i),
                compressed: compressed.value(i),
                checksum: ck,
            });
        }
    }

    /// Write the sorted lookup sub-index + fst trie as two reserved manifest
    /// entries. Called from `finish` before the manifest is emitted.
    fn write_lookup_and_trie(&mut self) -> Result<()> {
        let n = self.lookup_paths.len();
        // Row order sorted by (path, chunk_seq) so each file's chunks are
        // contiguous and paths are in byte-lexicographic order (fst requirement).
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by(|&a, &b| {
            self.lookup_paths[a].cmp(&self.lookup_paths[b]).then(
                self.lookup_locs[a]
                    .chunk_seq
                    .cmp(&self.lookup_locs[b].chunk_seq),
            )
        });

        // Build the lookup sub-index batch (base schema, sorted).
        let mut path_b = StringBuilder::with_capacity(n, n * 16);
        let mut seq_b = UInt32Builder::with_capacity(n);
        let mut fdata_b = UInt64Builder::with_capacity(n);
        let mut comp_b = BooleanBuilder::with_capacity(n);
        let mut usz_b = UInt64Builder::with_capacity(n);
        let mut boff_b = UInt64Builder::with_capacity(n);
        let mut bsz_b = UInt64Builder::with_capacity(n);
        let mut ck_b = FixedSizeBinaryBuilder::with_capacity(n, 32);
        for &i in &order {
            let loc = &self.lookup_locs[i];
            path_b.append_value(&self.lookup_paths[i]);
            seq_b.append_value(loc.chunk_seq);
            fdata_b.append_value(loc.fdata_offset);
            comp_b.append_value(loc.compressed);
            usz_b.append_value(loc.uncompressed_size);
            boff_b.append_value(loc.blob_offset);
            bsz_b.append_value(loc.blob_size);
            ck_b.append_value(loc.checksum)
                .expect("checksum is 32 bytes");
        }
        let schema = lookup_schema();
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(path_b.finish()),
                Arc::new(seq_b.finish()),
                Arc::new(fdata_b.finish()),
                Arc::new(comp_b.finish()),
                Arc::new(usz_b.finish()),
                Arc::new(boff_b.finish()),
                Arc::new(bsz_b.finish()),
                Arc::new(ck_b.finish()),
            ],
        )?;
        self.push_subindex(
            &schema,
            &[batch],
            GroupKey {
                pkg_type: RESERVED_PKG_TYPE,
                repo: String::new(),
                module_name: LOOKUP_MODULE.to_string(),
            },
        )?;

        // Build the fst trie: distinct relative_path → first row index in the
        // (sorted) lookup. Keys must be inserted in lexicographic order — `order`
        // already gives that.
        let mut builder = fst::MapBuilder::memory();
        let mut prev: Option<&str> = None;
        for (sorted_idx, &orig) in order.iter().enumerate() {
            let p = self.lookup_paths[orig].as_str();
            if prev != Some(p) {
                builder
                    .insert(p.as_bytes(), sorted_idx as u64)
                    .map_err(|e| anyhow!("trie insert: {e}"))?;
                prev = Some(p);
            }
        }
        let trie_bytes = builder
            .into_inner()
            .map_err(|e| anyhow!("trie finish: {e}"))?;
        self.write_raw_section(
            &trie_bytes,
            GroupKey {
                pkg_type: RESERVED_PKG_TYPE,
                repo: String::new(),
                module_name: TRIE_MODULE.to_string(),
            },
        )
    }

    /// Emit the per-artifact + per-archive detached CMS signatures as two reserved
    /// sections, computed from the already-accumulated chunk hashes (Law 3 order).
    /// Never re-hashes content. Called from `finish` (before the manifest) only
    /// when a signer is attached.
    #[cfg(feature = "sign")]
    fn write_signatures(&mut self) -> Result<()> {
        use std::collections::BTreeMap;
        let Some(signer) = self.signer.take() else {
            return Ok(());
        };

        // Group chunk hashes by path (borrows self immutably). Produce owned
        // outputs so the borrow is released before we write to the file.
        let (file_digests, artifact_paths, artifact_cms): (
            Vec<(String, [u8; 32])>,
            Vec<String>,
            Vec<Vec<u8>>,
        ) = {
            let mut by_path: BTreeMap<&str, Vec<(u32, &[u8; 32])>> = BTreeMap::new();
            for (p, loc) in self.lookup_paths.iter().zip(self.lookup_locs.iter()) {
                by_path
                    .entry(p.as_str())
                    .or_default()
                    .push((loc.chunk_seq, &loc.checksum));
            }
            let mut digs = Vec::with_capacity(by_path.len());
            let mut paths = Vec::with_capacity(by_path.len());
            let mut cmss = Vec::with_capacity(by_path.len());
            for (path, mut chunks) in by_path {
                chunks.sort_by_key(|(seq, _)| *seq);
                let n = chunks.len();
                let digest = crate::sign::file_digest_from_parts(
                    path,
                    chunks.iter().map(|(s, c)| (*s, *c)),
                    n,
                );
                let cms = signer.sign_digest(&digest)?;
                digs.push((path.to_string(), digest));
                paths.push(path.to_string());
                cmss.push(cms);
            }
            (digs, paths, cmss)
        };

        // Per-archive root signature. The footer is always Multi (v0.7).
        let footer = crate::index::IndexFooter::Multi { manifest_offset: 0 };
        let root = crate::sign::archive_root(&file_digests, &footer);
        let archive_cms = signer.sign_digest(&root)?;

        let artifacts_bytes = serialize_artifact_signatures(&artifact_paths, &artifact_cms)?;
        self.write_raw_section(
            &artifacts_bytes,
            GroupKey {
                pkg_type: RESERVED_PKG_TYPE,
                repo: String::new(),
                module_name: SIGN_ARTIFACTS_MODULE.to_string(),
            },
        )?;
        self.write_raw_section(
            &archive_cms,
            GroupKey {
                pkg_type: RESERVED_PKG_TYPE,
                repo: String::new(),
                module_name: SIGN_ARCHIVE_MODULE.to_string(),
            },
        )?;
        Ok(())
    }

    /// Write a raw (non-Arrow) byte section at the cursor and record a manifest
    /// entry whose `index_offset`/`index_len` frame it.
    fn write_raw_section(&mut self, bytes: &[u8], key: GroupKey) -> Result<()> {
        let start = self.cursor;
        self.file.write_all_at(bytes, start)?;
        self.cursor += bytes.len() as u64;
        self.entries.push(ManifestEntry {
            pkg_type: key.pkg_type,
            repo: key.repo,
            module_name: key.module_name,
            index_offset: start,
            index_len: bytes.len() as u64,
            row_count: 0,
        });
        Ok(())
    }
}

impl ArchiveMetaSink for ArrowIpcSink {
    fn push_subindex(
        &mut self,
        schema: &Schema,
        batches: &[RecordBatch],
        key: GroupKey,
    ) -> Result<()> {
        let sub_start = self.cursor;
        let mut sub_bytes: Vec<u8> = Vec::new();
        let mut sw = StreamWriter::try_new(&mut sub_bytes, schema)
            .map_err(|e| anyhow!("sub-index writer: {e}"))?;
        let mut row_count = 0u64;
        for batch in batches {
            row_count += batch.num_rows() as u64;
            sw.write(batch)
                .map_err(|e| anyhow!("sub-index write: {e}"))?;
        }
        sw.finish().map_err(|e| anyhow!("sub-index finish: {e}"))?;

        // Accumulate base columns for the lookup layer — but not from the reserved
        // lookup sub-index itself (that would recurse / double-count).
        if key.module_name != LOOKUP_MODULE && key.module_name != TRIE_MODULE {
            for batch in batches {
                self.accumulate_lookup(batch);
            }
        }

        let sub_len = sub_bytes.len() as u64;
        self.file.write_all_at(&sub_bytes, sub_start)?;
        self.cursor += sub_len;

        self.entries.push(ManifestEntry {
            pkg_type: key.pkg_type,
            repo: key.repo,
            module_name: key.module_name,
            index_offset: sub_start,
            index_len: sub_len,
            row_count,
        });
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> Result<u64> {
        // Emit the sorted lookup sub-index + trie before the manifest so their
        // byte ranges are recorded as (reserved) manifest entries.
        self.write_lookup_and_trie()?;

        // Emit the detached provenance signatures (feature `sign`) — also reserved
        // sections, also before the manifest. A no-op when no signer is attached,
        // so unsigned archives stay byte-identical to today's format.
        #[cfg(feature = "sign")]
        self.write_signatures()?;

        let manifest_offset = self.cursor;
        let manifest_bytes =
            write_manifest_bytes(&self.entries).map_err(|e| anyhow!("manifest: {e}"))?;
        self.file.write_all_at(&manifest_bytes, manifest_offset)?;

        let after = manifest_offset + manifest_bytes.len() as u64;
        self.file.write_all_at(&MULTI_INDEX_MAGIC, after)?;
        self.file.write_all_at(
            &manifest_offset.to_le_bytes(),
            after + MULTI_INDEX_MAGIC.len() as u64,
        )?;
        self.file.sync_all()?;

        Ok(after + MULTI_INDEX_MAGIC.len() as u64 + 8)
    }
}

/// Serialize the per-artifact detached CMS signatures as an Arrow IPC stream with
/// columns `(relative_path: Utf8, cms: Binary)` — one row per file. Itself a
/// valid Arrow IPC file (DuckDB/Polars-queryable), stored as a reserved section.
#[cfg(feature = "sign")]
fn serialize_artifact_signatures(paths: &[String], cms: &[Vec<u8>]) -> Result<Vec<u8>> {
    use arrow::array::BinaryBuilder;
    use arrow::datatypes::{DataType, Field, Schema};

    let n = paths.len();
    let schema = Arc::new(Schema::new(vec![
        Field::new("relative_path", DataType::Utf8, false),
        Field::new("cms", DataType::Binary, false),
    ]));
    let mut path_b = StringBuilder::with_capacity(n, n * 32);
    let mut cms_b = BinaryBuilder::with_capacity(n, n * 512);
    for (p, c) in paths.iter().zip(cms.iter()) {
        path_b.append_value(p);
        cms_b.append_value(c);
    }
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(path_b.finish()), Arc::new(cms_b.finish())],
    )?;
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::try_new(&mut buf, &schema)
            .map_err(|e| anyhow!("artifact-sig writer: {e}"))?;
        w.write(&batch)
            .map_err(|e| anyhow!("artifact-sig write: {e}"))?;
        w.finish()
            .map_err(|e| anyhow!("artifact-sig finish: {e}"))?;
    }
    Ok(buf)
}
