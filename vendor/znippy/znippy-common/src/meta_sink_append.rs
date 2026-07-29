//! `ArrowIpcSinkAppend` — the **append/resume-capable v2 clone** of
//! [`ArrowIpcSink`](crate::ArrowIpcSink).
//!
//! ## Why a clone and not a refactor
//! The original [`ArrowIpcSink`] is the A baseline of the arrow-ipc write/seal
//! A/B audit — its hot path (`push_subindex` + `finish`) must stay byte- and
//! perf-identical. So this is a *near-identical copy* that adds the two new
//! capabilities **without touching the original**:
//!
//!  * **fresh path** — [`ArrowIpcSinkAppend::new`] + `push_subindex` + `finish`
//!    is a line-for-line clone of `ArrowIpcSink`. It writes the **same v0.7
//!    on-disk bytes** (same sub-index serialisation, same sorted lookup, same
//!    fst trie, same manifest, same `ZNPYMIDX` footer). The A/B parity test
//!    proves this clone is a zero-cost superset on the normal write path.
//!
//!  * **resume/append path** — [`ArrowIpcSinkAppend::open_existing`] reopens an
//!    already-sealed `.znippy`, recovers its existing data rows, repositions the
//!    cursor at the **end of the blob region** (truncating the old metadata
//!    tail), and lets the caller `push_subindex` more blobs' rows. `finish()`
//!    then re-seals the merged old+new row set — the **first-class native blob
//!    append** that the iceberg lifecycle test (#23) previously had to do by
//!    hand.
//!
//! ### The resume mechanism, in bytes
//! A sealed v0.7 archive is:
//! ```text
//! [ blob_0 … blob_N ][ data sub-idx(es) ][ lookup sub-idx ][ trie ][ manifest ][ ZNPYMIDX ][off]
//! ^0                 ^blob_end           (the whole metadata tail is rebuildable)
//! ```
//! To append we must:
//!   1. read the full manifest (incl. reserved lookup/trie entries),
//!   2. find `blob_end` = the lowest `index_offset` over all sub-index entries
//!      (where the blob region stops and the rebuildable tail begins),
//!   3. recover the existing **data** rows from the sorted lookup sub-index (one
//!      cheap read of the already-sorted reserved section — no per-sub-index
//!      re-scan), seeding the lookup accumulator,
//!   4. set the cursor to `blob_end` so the caller's new blob bytes + new data
//!      sub-index overwrite the old (now-stale) metadata tail,
//!   5. on `finish()`, re-sort the merged rows and re-emit lookup + trie +
//!      manifest + footer.
//!
//! The new blob bytes are written by the caller (the compress pipeline / a
//! library append entrypoint such as [`append_files`]) to the file at
//! `blob_end()` exactly as a fresh archive
//! writes blobs at offset 0; this sink owns only the metadata tail, identical to
//! the original's contract.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
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
    is_reserved_module, lookup_schema, read_znippy_full_manifest, write_manifest_bytes,
};
use crate::meta_sink::{ArchiveMetaSink, GroupKey};

/// Append/resume-capable v2 clone of [`ArrowIpcSink`](crate::ArrowIpcSink).
///
/// Field-for-field identical to the original; the only added surface is the
/// [`open_existing`](Self::open_existing) constructor and the [`blob_end`](Self::blob_end)
/// accessor. The fresh-write path is byte-identical to the original.
pub struct ArrowIpcSinkAppend {
    file: Arc<File>,
    cursor: u64,
    entries: Vec<ManifestEntry>,
    lookup_paths: Vec<String>,
    lookup_locs: Vec<ChunkLoc>,
    /// On resume, the recovered pre-existing data rows. They are re-emitted as a
    /// data sub-index in `finish()` (so the ordinary reader, which reads data
    /// sub-indexes, still sees them) AND merged into the rebuilt lookup. Empty
    /// for a fresh sink. Kept separate from `lookup_*` so they aren't
    /// double-counted before the re-emit.
    carried: Vec<(String, ChunkLoc)>,
}

impl ArrowIpcSinkAppend {
    /// Fresh archive: identical to [`ArrowIpcSink::new`](crate::ArrowIpcSink::new).
    /// `blob_end_offset` is the byte offset just past the last blob.
    pub fn new(file: Arc<File>, blob_end_offset: u64) -> Self {
        Self {
            file,
            cursor: blob_end_offset,
            entries: Vec::new(),
            lookup_paths: Vec::new(),
            lookup_locs: Vec::new(),
            carried: Vec::new(),
        }
    }

    /// Reopen an **already-sealed** v0.7 `.znippy` for append/resume.
    ///
    /// Recovers the existing data rows from the sorted lookup sub-index, drops
    /// the (rebuildable) metadata tail by positioning the cursor at the end of
    /// the blob region, and returns a sink ready to accept more `push_subindex`
    /// calls. The caller appends its new blob bytes to the same file starting at
    /// [`blob_end`](Self::blob_end) before pushing the matching index rows.
    ///
    /// The file is opened read+write; nothing is mutated until `push_subindex` /
    /// `finish` overwrite the old tail.
    pub fn open_existing(path: &Path) -> Result<Self> {
        let file = Arc::new(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|e| anyhow!("append: open {} for resume: {e}", path.display()))?,
        );

        // 1. Full manifest (incl. reserved lookup/trie entries).
        let (entries, _manifest_offset) = read_znippy_full_manifest(path)?;
        if entries.is_empty() {
            return Err(anyhow!(
                "append: archive {} has an empty manifest",
                path.display()
            ));
        }

        // 2. blob_end = lowest index_offset over all sub-index/reserved sections.
        //    Everything from there to EOF is the rebuildable metadata tail.
        let blob_end = entries
            .iter()
            .map(|e| e.index_offset)
            .min()
            .ok_or_else(|| anyhow!("append: no sections in manifest"))?;

        // 3. Recover existing DATA rows from the sorted lookup sub-index (one
        //    read of the already-sorted reserved section). Fall back to scanning
        //    the data sub-indexes if (unexpectedly) no lookup section is present.
        let (paths, locs) = recover_rows(path, &entries)?;
        let carried: Vec<(String, ChunkLoc)> = paths.into_iter().zip(locs).collect();

        Ok(Self {
            file,
            cursor: blob_end,
            entries: Vec::new(), // rebuilt fresh by push_subindex + finish
            lookup_paths: Vec::new(),
            lookup_locs: Vec::new(),
            carried,
        })
    }

    /// Byte offset where the blob region ends in a resumed archive — where the
    /// caller writes its newly-appended blob bytes (and where the first new data
    /// sub-index will be placed). For a fresh sink this is the `blob_end_offset`
    /// passed to [`new`](Self::new) until the first `push_subindex`.
    pub fn blob_end(&self) -> u64 {
        self.cursor
    }

    /// Number of pre-existing data rows recovered on resume (0 for a fresh sink).
    pub fn recovered_rows(&self) -> usize {
        self.carried.len()
    }

    /// Re-emit the carried (recovered) rows as a single data sub-index so the
    /// ordinary reader — which reads data sub-indexes, not the lookup — still
    /// lists them after the re-seal. `push_subindex` also folds them into the
    /// rebuilt lookup accumulator. No-op for a fresh sink.
    fn emit_carried(&mut self) -> Result<()> {
        if self.carried.is_empty() {
            return Ok(());
        }
        let n = self.carried.len();
        let mut path_b = StringBuilder::with_capacity(n, n * 16);
        let mut seq_b = UInt32Builder::with_capacity(n);
        let mut fdata_b = UInt64Builder::with_capacity(n);
        let mut comp_b = BooleanBuilder::with_capacity(n);
        let mut usz_b = UInt64Builder::with_capacity(n);
        let mut boff_b = UInt64Builder::with_capacity(n);
        let mut bsz_b = UInt64Builder::with_capacity(n);
        let mut ck_b = FixedSizeBinaryBuilder::with_capacity(n, 32);
        for (p, loc) in &self.carried {
            path_b.append_value(p);
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
        self.carried.clear(); // moved into the sub-index + lookup by push_subindex
        self.push_subindex(
            &schema,
            &[batch],
            GroupKey {
                pkg_type: 0,
                repo: String::new(),
                module_name: String::new(),
            },
        )
    }

    // ── below: a line-for-line clone of ArrowIpcSink's private machinery ──

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

    fn write_lookup_and_trie(&mut self) -> Result<()> {
        let n = self.lookup_paths.len();
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by(|&a, &b| {
            self.lookup_paths[a].cmp(&self.lookup_paths[b]).then(
                self.lookup_locs[a]
                    .chunk_seq
                    .cmp(&self.lookup_locs[b].chunk_seq),
            )
        });

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

impl ArchiveMetaSink for ArrowIpcSinkAppend {
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
        // Resume: re-emit recovered rows as a data sub-index (the ordinary reader
        // reads data sub-indexes, not the lookup). No-op on the fresh path.
        self.emit_carried()?;
        self.write_lookup_and_trie()?;

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
        // Resume overwrites the old (longer-or-shorter) tail in place; if the new
        // tail is shorter than the old one, truncate so no stale footer lingers.
        let final_len = after + MULTI_INDEX_MAGIC.len() as u64 + 8;
        self.file.set_len(final_len)?;
        self.file.sync_all()?;

        Ok(final_len)
    }
}

/// Outcome of a native [`append_files`] call.
#[derive(Debug, Clone)]
pub struct AppendReport {
    /// Data rows that existed in the archive before the append (recovered).
    pub rows_before: u64,
    /// New rows (one per appended file/chunk) written by the append.
    pub rows_added: u64,
    /// Byte offset where the appended blob region started (old blob_end).
    pub blob_append_offset: u64,
    /// Bytes of new blob payload appended (compressed/stored).
    pub blob_bytes_added: u64,
    /// Final size of the re-sealed archive.
    pub sealed_total_bytes: u64,
}

/// First-class **native blob append** — the caller-facing library primitive that
/// the iceberg lifecycle test (#23) previously had to perform by hand. (There is
/// no `compress --append` CLI verb today; this is the in-process entry point.)
///
/// Opens an existing sealed v0.7 `.znippy`, compresses each `(relative_path,
/// bytes)` in `new_files` with the znippy codec, appends the resulting blobs to
/// the same file past the existing blob region, then re-seals (merged old+new
/// lookup + trie + manifest + footer) via [`ArrowIpcSinkAppend`]. The original
/// blob bytes and existing rows are reused verbatim — nothing is recompressed.
///
/// Mirrors the real compress path's per-blob accounting: blake3 over the
/// ORIGINAL bytes, store-raw when the codec frame is not smaller, one chunk per
/// file (`chunk_seq = 0`). `compression_level` is the codec level (e.g. 3).
pub fn append_files(
    archive: &Path,
    new_files: &[(String, Vec<u8>)],
    compression_level: i32,
) -> Result<AppendReport> {
    let sink = ArrowIpcSinkAppend::open_existing(archive)?;
    let rows_before = sink.recovered_rows() as u64;
    let blob_append_offset = sink.blob_end();
    write_files_into_sink(
        sink,
        new_files,
        compression_level,
        rows_before,
        blob_append_offset,
    )
}

/// Create a fresh `.znippy` archive from in-memory `files` — the bootstrap inverse
/// of [`append_files`], which requires an already-sealed archive (it rejects an
/// empty manifest). Seed a new writable archive with this, then grow it with
/// [`append_files`]. Overwrites `archive` if it already exists.
pub fn create_archive(
    archive: &Path,
    files: &[(String, Vec<u8>)],
    compression_level: i32,
) -> Result<AppendReport> {
    let blob_file = Arc::new(
        File::create(archive).map_err(|e| anyhow!("create archive {}: {e}", archive.display()))?,
    );
    let sink = ArrowIpcSinkAppend::new(blob_file, 0);
    write_files_into_sink(sink, files, compression_level, 0, 0)
}

/// Build a complete `.znippy` archive **entirely in memory** from in-memory
/// `files` and return its bytes — no staging directory, no named output file. The
/// sink needs a positioned-write fd, so this seals into an **anonymous temp file**
/// (`O_TMPFILE` where the OS supports it → never linked into the filesystem
/// namespace), then reads the sealed bytes straight back out. The returned `Vec`
/// is byte-identical to what [`create_archive`] would write to a path.
///
/// Use this for zero-disk pipelines: build a release/airgap archive from product
/// bytes held in RAM and stream it across the gap without ever touching disk on
/// the build side. Pair with [`append_files`] (path) or hold the bytes and re-seal.
pub fn create_archive_to_vec(
    files: &[(String, Vec<u8>)],
    compression_level: i32,
) -> Result<(Vec<u8>, AppendReport)> {
    let anon = Arc::new(tempfile::tempfile().map_err(|e| anyhow!("anonymous archive fd: {e}"))?);
    let sink = ArrowIpcSinkAppend::new(anon.clone(), 0);
    let report = write_files_into_sink(sink, files, compression_level, 0, 0)?;
    // The Arc keeps the anonymous fd alive past `finish()`; read the sealed bytes.
    let mut bytes = vec![0u8; report.sealed_total_bytes as usize];
    anon.read_exact_at(&mut bytes, 0)
        .map_err(|e| anyhow!("read back anonymous archive: {e}"))?;
    Ok((bytes, report))
}

/// Shared core of [`append_files`] / [`create_archive`]: compress each file's bytes
/// (store-raw if not smaller), write the blobs at the sink's running blob cursor,
/// then push one base-schema data sub-index and seal. `sink` is either a fresh
/// [`ArrowIpcSinkAppend::new`] or an [`ArrowIpcSinkAppend::open_existing`].
fn write_files_into_sink(
    mut sink: ArrowIpcSinkAppend,
    new_files: &[(String, Vec<u8>)],
    compression_level: i32,
    rows_before: u64,
    blob_append_offset: u64,
) -> Result<AppendReport> {
    use crate::codec::CompressCtx;
    use crate::meta::{BlobMeta, ChunkMeta};

    // Append the new blob bytes to the file at the running blob cursor, mirroring
    // the compress pipeline (hash original bytes; store-raw if not smaller).
    let blob_file = sink.file.clone();
    let mut ctx = CompressCtx::new(compression_level)?;
    let mut blobs: Vec<BlobMeta> = Vec::with_capacity(new_files.len());
    let mut paths: Vec<String> = Vec::with_capacity(new_files.len());
    let mut cursor = blob_append_offset;
    let mut blob_bytes_added = 0u64;

    for (file_index, (rel, bytes)) in new_files.iter().enumerate() {
        let checksum = *blake3::hash(bytes).as_bytes();
        let frame = ctx.compress(bytes)?;
        let (on_disk, compressed): (&[u8], bool) = if frame.len() < bytes.len() {
            (&frame, true)
        } else {
            (bytes, false)
        };
        let blob_offset = cursor;
        blob_file.write_all_at(on_disk, blob_offset)?;
        cursor += on_disk.len() as u64;
        blob_bytes_added += on_disk.len() as u64;

        paths.push(rel.clone());
        blobs.push(BlobMeta {
            blob_offset,
            blob_size: on_disk.len() as u64,
            chunk_meta: ChunkMeta {
                fdata_offset: 0,
                file_index: file_index as u64,
                chunk_seq: 0,
                checksum,
                compressed,
                uncompressed_size: bytes.len() as u64,
                compressed_size: on_disk.len() as u64,
            },
        });
    }
    blob_file.sync_all()?;

    // Advance the sink's cursor past the freshly-written blob region so the new
    // data sub-index lands after the appended blobs (not over them).
    sink.cursor = cursor;

    // Build the base-schema batch and push it (accumulates into the merged
    // lookup alongside the recovered rows).
    let resolver = {
        let paths = paths.clone();
        move |fi: u64| paths[fi as usize].clone()
    };
    let batch = crate::build_metadata_batch(&blobs, resolver, &[], &[])
        .map_err(|e| anyhow!("append: build_metadata_batch: {e}"))?;
    let schema = lookup_schema();
    let rows_added = batch.num_rows() as u64;
    sink.push_subindex(
        schema.as_ref(),
        &[batch],
        GroupKey {
            pkg_type: 0,
            repo: String::new(),
            module_name: String::new(),
        },
    )?;

    let sealed_total_bytes = Box::new(sink).finish()?;

    Ok(AppendReport {
        rows_before,
        rows_added,
        blob_append_offset,
        blob_bytes_added,
        sealed_total_bytes,
    })
}

/// Recover existing DATA rows for the resume accumulator. Reads the sorted
/// lookup reserved section (the cheapest source — already the exact per-chunk
/// rows, sorted) when present; otherwise concatenates the data sub-indexes.
fn recover_rows(path: &Path, entries: &[ManifestEntry]) -> Result<(Vec<String>, Vec<ChunkLoc>)> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = File::open(path)?;

    // Prefer the sorted lookup section: it is exactly the base-schema per-chunk
    // rows, one cheap stream decode.
    if let Some(lk) = entries.iter().find(|e| e.module_name == LOOKUP_MODULE) {
        file.seek(SeekFrom::Start(lk.index_offset))?;
        let mut bytes = vec![0u8; lk.index_len as usize];
        file.read_exact(&mut bytes)?;
        return decode_base_rows(&bytes);
    }

    // Fallback: read every NON-reserved data sub-index and concatenate its rows.
    let mut paths = Vec::new();
    let mut locs = Vec::new();
    for e in entries {
        if is_reserved_module(&e.module_name) {
            continue;
        }
        file.seek(SeekFrom::Start(e.index_offset))?;
        let mut bytes = vec![0u8; e.index_len as usize];
        file.read_exact(&mut bytes)?;
        let (mut p, mut l) = decode_base_rows(&bytes)?;
        paths.append(&mut p);
        locs.append(&mut l);
    }
    Ok((paths, locs))
}

// ── inject-assert tests (the "tests inject values, not just no-crash" LAW) ──
#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::CompressCtx;
    use crate::meta::{BlobMeta, ChunkMeta};
    use crate::{ArrowIpcSink, ZnippyArchive, ZnippyReader};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(tag: &str) -> std::path::PathBuf {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!(
            "znippy_append_{tag}_{ns}_{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Deterministic synthetic rows — distinct, lexicographically-spread paths
    /// (same flavour as the bench's `synth_blobs`, so the sort/fst do real work).
    fn synth(n: usize, salt: u64) -> Vec<(String, Vec<u8>)> {
        (0..n)
            .map(|i| {
                let g = (i.wrapping_mul(2_654_435_761) ^ salt as usize) % 1000;
                let p = format!("repo/grp{g:03}/file{:08}_{salt}.bin", i);
                let body = format!("payload {i} salt {salt} {}\n", "z".repeat(8 + (i % 40)));
                (p, body.into_bytes())
            })
            .collect()
    }

    /// Write a fresh sealed archive with `sink` (codec-compressed blobs + one
    /// base-schema data sub-index + the seal). Returns the sealed length. Generic
    /// over a closure so we can drive BOTH ArrowIpcSink (A) and the clone (B)
    /// through the *identical* fresh path and compare bytes.
    fn write_fresh<S: ArchiveMetaSink + 'static>(
        path: &Path,
        files: &[(String, Vec<u8>)],
        make_sink: impl FnOnce(Arc<File>, u64) -> S,
    ) -> u64 {
        let file = Arc::new(File::create(path).unwrap());
        let mut ctx = CompressCtx::new(3).unwrap();
        let mut blobs = Vec::new();
        let mut paths = Vec::new();
        let mut cursor = 0u64;
        for (fi, (rel, bytes)) in files.iter().enumerate() {
            let checksum = *blake3::hash(bytes).as_bytes();
            let frame = ctx.compress(bytes).unwrap();
            let (on_disk, compressed): (&[u8], bool) = if frame.len() < bytes.len() {
                (&frame, true)
            } else {
                (bytes, false)
            };
            file.write_all_at(on_disk, cursor).unwrap();
            let blob_offset = cursor;
            cursor += on_disk.len() as u64;
            paths.push(rel.clone());
            blobs.push(BlobMeta {
                blob_offset,
                blob_size: on_disk.len() as u64,
                chunk_meta: ChunkMeta {
                    fdata_offset: 0,
                    file_index: fi as u64,
                    chunk_seq: 0,
                    checksum,
                    compressed,
                    uncompressed_size: bytes.len() as u64,
                    compressed_size: on_disk.len() as u64,
                },
            });
        }
        let resolver = {
            let p = paths.clone();
            move |fi: u64| p[fi as usize].clone()
        };
        let batch = crate::build_metadata_batch(&blobs, resolver, &[], &[]).unwrap();
        let schema = lookup_schema();
        let mut sink = make_sink(file.clone(), cursor);
        sink.push_subindex(
            schema.as_ref(),
            &[batch],
            GroupKey {
                pkg_type: 0,
                repo: String::new(),
                module_name: String::new(),
            },
        )
        .unwrap();
        Box::new(sink).finish().unwrap()
    }

    /// PARITY: the clone's fresh write+seal must produce a BYTE-IDENTICAL archive
    /// to the original `ArrowIpcSink` over the same rows. This is the structural
    /// proof that the clone is a zero-cost superset on the normal path (the
    /// throughput parity number lives in the bench; this asserts correctness).
    #[test]
    fn clone_fresh_path_is_byte_identical_to_original() {
        let dir = unique_dir("parity");
        let files = synth(2_000, 1);

        let a = dir.join("a.znippy");
        let b = dir.join("b.znippy");
        let len_a = write_fresh(&a, &files, ArrowIpcSink::new);
        let len_b = write_fresh(&b, &files, ArrowIpcSinkAppend::new);

        assert_eq!(len_a, len_b, "clone seal produced a different total length");
        let bytes_a = std::fs::read(&a).unwrap();
        let bytes_b = std::fs::read(&b).unwrap();
        assert_eq!(
            bytes_a, bytes_b,
            "clone's fresh write path is NOT byte-identical to ArrowIpcSink — parity broken"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// RESUME: native append → reopen with the ORDINARY arrow-ipc reader → both
    /// the original AND the appended files read back byte-exact, and the index
    /// lists exactly old+new. Inject real bytes, assert real bytes out.
    #[test]
    fn native_append_roundtrips_old_and_new_files() {
        let dir = unique_dir("resume");
        let archive = dir.join("store.znippy");
        let orig = synth(1_500, 7);
        write_fresh(&archive, &orig, ArrowIpcSink::new);

        let added = synth(300, 99);
        let report = append_files(&archive, &added, 3).unwrap();
        assert_eq!(
            report.rows_before,
            orig.len() as u64,
            "must recover all original rows"
        );
        assert_eq!(report.rows_added, added.len() as u64);
        assert!(
            report.blob_bytes_added > 0,
            "append must write new blob bytes"
        );
        assert!(
            report.sealed_total_bytes > report.blob_append_offset,
            "re-sealed file must be larger than the old blob region"
        );

        // Reopen with the plain reader (no append awareness) and verify EVERY
        // file — original and appended — comes back byte-exact.
        let ar = ZnippyArchive::open(&archive).unwrap();
        let mut listed = ar.list_files().unwrap();
        listed.sort();
        let mut expected: Vec<String> = orig
            .iter()
            .chain(added.iter())
            .map(|(p, _)| p.clone())
            .collect();
        expected.sort();
        assert_eq!(
            listed, expected,
            "index must list exactly old+new files after append"
        );

        for (p, bytes) in orig.iter().chain(added.iter()) {
            let got = ar.extract_file(p).unwrap();
            assert_eq!(&got, bytes, "byte mismatch after append for {p}");
        }

        // Random-access lookup of an appended file via the rebuilt trie+lookup.
        let probe = &added[123].0;
        let chunks = crate::locate_file(&archive, probe).unwrap();
        assert!(
            !chunks.is_empty(),
            "appended file must be locatable via the re-sealed lookup"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// BOOTSTRAP: `create_archive` seeds a fresh archive that (a) is byte-identical
    /// to the proven fresh write path, (b) reads back byte-exact via the ordinary
    /// reader, and (c) can then be grown by `append_files` — the create→append flow
    /// holger's writable `put` relies on. Inject real bytes, assert real bytes out.
    #[test]
    fn create_archive_seeds_then_grows() {
        let dir = unique_dir("create");
        let seed = synth(40, 5);

        // (a) create_archive == write_fresh(_, ArrowIpcSinkAppend::new) byte-for-byte.
        let made = dir.join("made.znippy");
        let report = create_archive(&made, &seed, 3).unwrap();
        assert_eq!(report.rows_before, 0, "fresh archive has no prior rows");
        assert_eq!(report.rows_added, seed.len() as u64);

        let ref_path = dir.join("ref.znippy");
        write_fresh(&ref_path, &seed, ArrowIpcSinkAppend::new);
        assert_eq!(
            std::fs::read(&made).unwrap(),
            std::fs::read(&ref_path).unwrap(),
            "create_archive must be byte-identical to the proven fresh write path"
        );

        // (b) seeded files read back byte-exact via the plain reader.
        let ar = ZnippyArchive::open(&made).unwrap();
        for (p, bytes) in &seed {
            assert_eq!(
                &ar.extract_file(p).unwrap(),
                bytes,
                "seed byte mismatch for {p}"
            );
        }

        // (c) append_files grows the bootstrapped archive; old+new read back exact.
        let added = synth(15, 88);
        let rep2 = append_files(&made, &added, 3).unwrap();
        assert_eq!(
            rep2.rows_before,
            seed.len() as u64,
            "append must recover seeded rows"
        );
        assert_eq!(rep2.rows_added, added.len() as u64);

        let ar2 = ZnippyArchive::open(&made).unwrap();
        for (p, bytes) in seed.iter().chain(added.iter()) {
            assert_eq!(
                &ar2.extract_file(p).unwrap(),
                bytes,
                "byte mismatch after grow for {p}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ZERO-COPY / no-filesystem: `create_archive_to_vec` builds a valid archive
    /// from in-memory bytes with NO staging tree and NO named output file (it seals
    /// into an anonymous fd). Assert the returned bytes are byte-identical to
    /// `create_archive`'s file output AND read back byte-exact through the reader.
    #[test]
    fn create_archive_to_vec_is_filesystem_free_and_round_trips() {
        let files = synth(24, 7);
        let (bytes, report) = create_archive_to_vec(&files, 3).unwrap();
        assert_eq!(
            report.rows_before, 0,
            "fresh in-memory archive has no prior rows"
        );
        assert_eq!(report.rows_added, files.len() as u64);
        assert_eq!(
            bytes.len() as u64,
            report.sealed_total_bytes,
            "vec len == sealed size"
        );

        let dir = unique_dir("tovec");
        // (1) byte-identical to the proven path (`create_archive` → file).
        let ref_path = dir.join("ref.znippy");
        create_archive(&ref_path, &files, 3).unwrap();
        assert_eq!(
            bytes,
            std::fs::read(&ref_path).unwrap(),
            "in-memory archive must be byte-identical to create_archive's file output"
        );
        // (2) the in-memory bytes ARE a real archive: persist + read back byte-exact.
        let p = dir.join("from_mem.znippy");
        std::fs::write(&p, &bytes).unwrap();
        let ar = ZnippyArchive::open(&p).unwrap();
        for (name, content) in &files {
            assert_eq!(
                &ar.extract_file(name).unwrap(),
                content,
                "byte mismatch for {name}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Decode an Arrow-IPC sub-index stream of the base schema into parallel
/// `(paths, locs)` vectors (mirrors `index::decode_lookup`, kept here so the
/// original stays untouched).
fn decode_base_rows(bytes: &[u8]) -> Result<(Vec<String>, Vec<ChunkLoc>)> {
    use arrow::ipc::reader::StreamReader;

    let reader = StreamReader::try_new(std::io::Cursor::new(bytes), None)
        .map_err(|e| anyhow!("append: lookup ipc reader: {e}"))?;
    let mut paths = Vec::new();
    let mut locs = Vec::new();
    for batch in reader {
        let batch = batch.map_err(|e| anyhow!("append: lookup batch decode: {e}"))?;
        let get = |n: &str| {
            batch
                .column_by_name(n)
                .ok_or_else(|| anyhow!("append: lookup missing column {n}"))
        };
        let p = get("relative_path")?
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| anyhow!("relative_path type"))?;
        let seq = get("chunk_seq")?
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or_else(|| anyhow!("chunk_seq type"))?;
        let fdata = get("fdata_offset")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow!("fdata_offset type"))?;
        let comp = get("compressed")?
            .as_any()
            .downcast_ref::<BooleanArray>()
            .ok_or_else(|| anyhow!("compressed type"))?;
        let usz = get("uncompressed_size")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow!("uncompressed_size type"))?;
        let boff = get("blob_offset")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow!("blob_offset type"))?;
        let bsz = get("blob_size")?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow!("blob_size type"))?;
        let ck = get("checksum")?
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .ok_or_else(|| anyhow!("checksum type"))?;
        for i in 0..batch.num_rows() {
            let mut c = [0u8; 32];
            c.copy_from_slice(ck.value(i));
            paths.push(p.value(i).to_string());
            locs.push(ChunkLoc {
                chunk_seq: seq.value(i),
                fdata_offset: fdata.value(i),
                blob_offset: boff.value(i),
                blob_size: bsz.value(i),
                uncompressed_size: usz.value(i),
                compressed: comp.value(i),
                checksum: c,
            });
        }
    }
    Ok((paths, locs))
}
