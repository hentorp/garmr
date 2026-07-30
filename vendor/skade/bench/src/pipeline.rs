//! Single-writer / many-processor ingest pipeline (znippy pattern).
//!
//! Today the default ingest (`data.rs`) has each writer task both ENCODE Parquet
//! and WRITE it, so N tasks contend on the storage write path. znippy's model is
//! the opposite and faster on NVMe: many CPU threads PROCESS data, **one** thread
//! WRITES (sequential, uncontended). This module implements that topology:
//!
//! ```text
//!   N encode workers              bounded channel           1 writer task
//!   RecordBatch -> Parquet bytes  ──►  mpsc(depth)  ──►  sequential put + fast_append
//!        (CPU, all cores)                                  (I/O + commit, 1 core)
//! ```
//!
//! **This is a client-side change and is backend-agnostic** — it speeds up the
//! warehouse write path for *whatever* `Catalog` is behind it (nornir, Nessie,
//! …). It is NOT a nornir-vs-Nessie lever; run every target through it to keep a
//! comparison fair. The nornir-specific commit-path lever is group-commit, which
//! the `commit-burst` scenario exercises. (See `.nornir/plan.md`.) It is also
//! primarily an NVMe win — on S3 a few parallel multipart uploaders can beat one
//! writer, so measure before assuming the single-writer topology wins there.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use arrow_array::RecordBatch;
use arrow_schema::SchemaRef as ArrowSchemaRef;
use bytes::Bytes;
// gatling::io — znippy's no-barrier async I/O task pool drives the concurrent S3
// multi-PUT fan-out (see `run_concurrent_writer_ingest`).
use znippy_zoomies::gatling::io as gatling_io;
use iceberg::spec::{DataContentType, DataFile, DataFileBuilder, DataFileFormat};
use iceberg::table::Table;
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::Catalog;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use tokio::sync::{mpsc, Semaphore};

/// One Parquet file encoded in memory by a CPU worker, handed to the lone writer.
pub struct EncodedFile {
    /// Stable sequence number → deterministic, collision-free file name.
    pub seq: usize,
    pub bytes: Vec<u8>,
    pub record_count: u64,
}

/// Encode a group of `RecordBatch`es into one in-memory Parquet file. Pure
/// CPU + allocation, **no I/O** — this is the part that fans out across cores.
/// The Arrow schema must carry iceberg field ids (`PARQUET:field_id` metadata,
/// which `iceberg::arrow::schema_to_arrow_schema` sets) so the file's columns map
/// back to the table schema on scan.
/// Parse `BENCH_PIPE_COMPRESSION` into `(codec, optional level)`.
fn compression_spec() -> (String, Option<i32>) {
    let spec = std::env::var("BENCH_PIPE_COMPRESSION").unwrap_or_default();
    spec.split_once(':')
        .map(|(c, l)| (c.to_string(), l.parse::<i32>().ok()))
        .unwrap_or((spec, None))
}

/// Parquet codec for the encode stage, from `BENCH_PIPE_COMPRESSION`
/// (`uncompressed` [default] | `snappy` | `zstd` | `zstd:<level>` | `gzip` | `lz4`
/// | `zstd-sys` | `zstd-sys:<level>`).
/// Compression moves the encode from memcpy-cheap (memory-bandwidth bound — a few
/// cores already exceed the writer, so CPU can't saturate) to genuinely CPU-bound,
/// so the all-core encode stage saturates the box — the realistic shape of a
/// compressed columnar ingest.
///
/// NOTE: the `zstd:<level>` codec runs zstd *inside* the Parquet writer, i.e.
/// through parquet's transitively-pulled stock `zstd`/`zstd-sys` crate. The
/// `zstd-sys` codec (see [`encode_parquet`]) instead routes the heavy zstd work
/// through the user's **`zstd-sys-rs`** crate (statically-linked libzstd 1.5.7),
/// while still producing a valid Parquet file — see [`zstd_sys_roundtrip`].
fn encode_compression(codec: &str, lvl: Option<i32>) -> parquet::basic::Compression {
    use parquet::basic::{BrotliLevel, Compression, GzipLevel, ZstdLevel};
    match codec.to_ascii_lowercase().as_str() {
        "snappy" => Compression::SNAPPY,
        "zstd" => Compression::ZSTD(ZstdLevel::try_new(lvl.unwrap_or(3)).unwrap_or_default()),
        "gzip" => Compression::GZIP(GzipLevel::try_new(lvl.unwrap_or(6) as u32).unwrap_or_default()),
        "brotli" => Compression::BROTLI(BrotliLevel::try_new(lvl.unwrap_or(3) as u32).unwrap_or_default()),
        "lz4" => Compression::LZ4,
        // `zstd-sys` writes the Parquet UNCOMPRESSED and then runs the bytes through
        // the user's zstd-sys-rs round-trip (compress→decompress). The stored file is
        // valid Parquet, so the iceberg scan reads it back unchanged.
        _ => Compression::UNCOMPRESSED,
    }
}

/// Compress `src` with the user's **`zstd-sys-rs`** crate (statically-linked
/// libzstd 1.5.7, raw C FFI), then decompress it straight back, and return the
/// round-tripped bytes. The returned `Vec` is byte-for-byte equal to `src` (the
/// caller asserts/relies on this), so feeding it a valid Parquet file yields a
/// valid Parquet file — only now the heavy zstd CPU work (compress + decompress)
/// has gone through the user's bindings instead of parquet's internal `zstd` crate.
///
/// Mirrors `osm-katana::pbf_enc::compress_zstd` (ZSTD_compressBound → vec →
/// ZSTD_compress → truncate) and adds the matching decompress half so the path is
/// a verifiable round-trip. `unsafe`: `zstd-sys-rs` is raw C FFI.
#[allow(unsafe_code)]
pub fn zstd_sys_roundtrip(src: &[u8], level: i32) -> Result<Vec<u8>> {
    // ── compress (user's static libzstd 1.5.7) ──
    let bound = unsafe { zstd_sys_rs::ZSTD_compressBound(src.len()) };
    let mut comp = vec![0u8; bound];
    let clen = unsafe {
        zstd_sys_rs::ZSTD_compress(
            comp.as_mut_ptr().cast(),
            comp.len(),
            src.as_ptr().cast(),
            src.len(),
            level,
        )
    };
    if unsafe { zstd_sys_rs::ZSTD_isError(clen) } != 0 {
        anyhow::bail!("zstd-sys-rs ZSTD_compress error code {clen}");
    }
    comp.truncate(clen);

    // ── decompress straight back (same bindings) ──
    // The frame carries the content size (single-shot ZSTD_compress always does),
    // so ZSTD_getFrameContentSize gives us the exact output length.
    let dlen = unsafe { zstd_sys_rs::ZSTD_getFrameContentSize(comp.as_ptr().cast(), comp.len()) };
    // ZSTD_CONTENTSIZE_UNKNOWN = -1, ZSTD_CONTENTSIZE_ERROR = -2 (as u64).
    if dlen == u64::MAX || dlen == u64::MAX - 1 {
        anyhow::bail!("zstd-sys-rs ZSTD_getFrameContentSize unknown/error ({dlen})");
    }
    let mut out = vec![0u8; dlen as usize];
    let n = unsafe {
        zstd_sys_rs::ZSTD_decompress(
            out.as_mut_ptr().cast(),
            out.len(),
            comp.as_ptr().cast(),
            comp.len(),
        )
    };
    if unsafe { zstd_sys_rs::ZSTD_isError(n) } != 0 {
        anyhow::bail!("zstd-sys-rs ZSTD_decompress error code {n}");
    }
    out.truncate(n);
    Ok(out)
}

pub fn encode_parquet(arrow_schema: ArrowSchemaRef, batches: &[RecordBatch]) -> Result<(Vec<u8>, u64)> {
    let (codec, lvl) = compression_spec();
    // `zstd-sys` is special: parquet writes UNCOMPRESSED, then we route the file's
    // bytes through the user's zstd-sys-rs round-trip below.
    let zstd_sys = codec.eq_ignore_ascii_case("zstd-sys");

    let mut buf: Vec<u8> = Vec::new();
    let mut rows = 0u64;
    {
        let props = WriterProperties::builder()
            .set_compression(encode_compression(&codec, lvl))
            .build();
        let mut w = ArrowWriter::try_new(&mut buf, arrow_schema, Some(props))?;
        for b in batches {
            rows += b.num_rows() as u64;
            w.write(b)?;
        }
        w.close()?;
    }

    if zstd_sys {
        // Route the CPU-heavy zstd work through the user's zstd-sys-rs (static
        // libzstd 1.5.7). The round-trip returns the SAME bytes, so what we store is
        // still a valid Parquet file → the iceberg scan reads it back unchanged
        // (scan_count == rows), while the compress+decompress saturated the cores
        // through the user's bindings. Level defaults to 9 (CPU-bound, like zstd:9).
        let level = lvl.unwrap_or(9);
        let round = zstd_sys_roundtrip(&buf, level)?;
        debug_assert_eq!(round, buf, "zstd-sys-rs round-trip changed the Parquet bytes");
        buf = round;
    }

    Ok((buf, rows))
}

/// Throughput of a single-writer pipeline run.
#[derive(Debug, Clone)]
pub struct PipelineStats {
    pub rows: u64,
    pub files: u64,
    pub commits: u64,
    pub bytes_written: u64,
    pub encode_workers: usize,
    pub elapsed: Duration,
    /// How many file writes (PUTs) the writer stage allowed in flight at once.
    /// `1` for the sequential local path; `>1` for the concurrent S3 path. The
    /// `peak_inflight` field records how many actually overlapped at the busiest
    /// moment, so a test can assert the concurrency really happened.
    pub write_concurrency: usize,
    pub peak_inflight: usize,
}

impl PipelineStats {
    pub fn rows_per_sec(&self) -> f64 {
        let s = self.elapsed.as_secs_f64();
        if s > 0.0 { self.rows as f64 / s } else { 0.0 }
    }
}

/// Run a single-writer / many-processor ingest into one `table`:
/// - up to `available_parallelism` CPU workers encode each group → Parquet bytes
///   in parallel (bounded by a semaphore so we use all cores, not more);
/// - **one** writer drains the bounded channel and writes each file
///   *sequentially* to the table's `FileIO`, builds its `DataFile`, and commits
///   every `files_per_commit` files via `fast_append` (which for `RedbCatalog`
///   flows through `group_commit`).
///
/// `channel_depth` bounds how far encoders may run ahead of the writer
/// (backpressure). Returns the final table handle + throughput.
///
/// This is the **sequential** writer — optimal on local NVMe/RAM, where a write
/// is a memcpy-class syscall: one uncontended writer saturates the device and
/// extra writers only add lock/seek contention. On S3 a single sequential PUT is
/// *latency-bound* (each PUT is a full HTTP round-trip), so the device sits idle
/// during every round-trip. For object stores use
/// [`run_concurrent_writer_ingest`], which keeps N PUTs in flight to hide that
/// latency. Pick by target: local → this; s3 → the concurrent one.
pub async fn run_single_writer_ingest(
    catalog: Arc<dyn Catalog>,
    table: Table,
    groups: Vec<Vec<RecordBatch>>,
    arrow_schema: ArrowSchemaRef,
    channel_depth: usize,
    files_per_commit: usize,
    // Data-file name prefix. Must be unique per call when ingesting into the SAME
    // table across multiple calls (e.g. streaming OSM windows), else the file
    // names collide and fast_append rejects "files already referenced by table".
    file_prefix: &str,
) -> Result<(Table, PipelineStats)> {
    // `write_concurrency = 1` ⇒ the sequential writer below.
    run_ingest(catalog, table, groups, arrow_schema, channel_depth, files_per_commit, file_prefix, 1)
        .await
}

/// Run the same many-processor ingest but with a **concurrent writer**: up to
/// `write_concurrency` file PUTs are kept in flight at once, driven by znippy's
/// [`gatling::io`](znippy_zoomies::gatling::io) no-barrier async task pool, so
/// per-PUT latency overlaps instead of serializing. This is the object-store
/// (S3) path — it recovers throughput a single sequential writer loses to
/// HTTP round-trips. The encode stage and the commit batching are identical to
/// the sequential path, and the resulting table holds exactly the same files, so
/// the two paths are interchangeable for *correctness* — only the write topology
/// differs. Use it for the `skade-s3`/`nessie`/`polaris` targets; keep
/// [`run_single_writer_ingest`] for local NVMe/RAM where sequential is optimal.
pub async fn run_concurrent_writer_ingest(
    catalog: Arc<dyn Catalog>,
    table: Table,
    groups: Vec<Vec<RecordBatch>>,
    arrow_schema: ArrowSchemaRef,
    channel_depth: usize,
    files_per_commit: usize,
    file_prefix: &str,
    write_concurrency: usize,
) -> Result<(Table, PipelineStats)> {
    run_ingest(
        catalog,
        table,
        groups,
        arrow_schema,
        channel_depth,
        files_per_commit,
        file_prefix,
        write_concurrency.max(1),
    )
    .await
}

/// Shared implementation of the encode→write→commit pipeline. The encode stage is
/// identical for both paths; only the writer differs by `write_concurrency`:
/// `1` ⇒ the original sequential single-writer; `>1` ⇒ up to that many PUTs in
/// flight via znippy's `gatling::io` async task pool (the S3 latency-hiding path).
#[allow(clippy::too_many_arguments)]
async fn run_ingest(
    catalog: Arc<dyn Catalog>,
    table: Table,
    groups: Vec<Vec<RecordBatch>>,
    arrow_schema: ArrowSchemaRef,
    channel_depth: usize,
    files_per_commit: usize,
    file_prefix: &str,
    write_concurrency: usize,
) -> Result<(Table, PipelineStats)> {
    let encode_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1);
    let fpc = files_per_commit.max(1);
    let wconc = write_concurrency.max(1);

    let (tx, mut rx) = mpsc::channel::<EncodedFile>(channel_depth.max(1));
    let sem = Arc::new(Semaphore::new(encode_workers));
    let start = Instant::now();

    // ---- Encode stage: many CPU workers (≤ one per core), bounded channel.
    let mut encoders = Vec::with_capacity(groups.len());
    for (seq, group) in groups.into_iter().enumerate() {
        let tx = tx.clone();
        let sem = Arc::clone(&sem);
        let schema = arrow_schema.clone();
        encoders.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("encode semaphore closed");
            let (bytes, record_count) =
                tokio::task::spawn_blocking(move || encode_parquet(schema, &group))
                    .await
                    .expect("encode task panicked")?;
            // Backpressure: blocks here when the writer is `channel_depth` behind.
            let _ = tx.send(EncodedFile { seq, bytes, record_count }).await;
            Ok::<(), anyhow::Error>(())
        }));
    }
    drop(tx); // channel closes once every encoder's clone is dropped

    // ---- Writer stage.
    let data_dir = format!("{}/data", table.metadata().location());
    let file_io = table.file_io().clone();
    let mut table = table;
    let (mut rows, mut files, mut commits, mut bytes_written) = (0u64, 0u64, 0u64, 0u64);
    let mut pending: Vec<DataFile> = Vec::with_capacity(fpc);
    // Tracks the largest number of PUTs that overlapped (1 on the sequential
    // path, up to `wconc` on the concurrent one) so callers/tests can assert the
    // concurrency actually happened rather than merely being requested.
    let inflight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    if wconc == 1 {
        // === Sequential, uncontended writer — the single-writer (local) payoff. ===
        while let Some(ef) = rx.recv().await {
            let path = format!("{data_dir}/{file_prefix}-{:08}.parquet", ef.seq);
            let len = ef.bytes.len() as u64;
            file_io.new_output(&path)?.write(Bytes::from(ef.bytes)).await?;
            bytes_written += len;
            rows += ef.record_count;
            files += 1;
            pending.push(data_file(path, ef.record_count, len)?);
            if pending.len() >= fpc {
                table = commit_files(catalog.as_ref(), &table, std::mem::take(&mut pending)).await?;
                commits += 1;
            }
        }
    } else {
        // === Concurrent writer (S3): up to `wconc` PUTs in flight at once. ===
        //
        // The PUT fan-out is driven by znippy's `gatling::io` — the *async* sibling
        // of the sync gatling engine. gatling's sync `run`/`run_typed` is the wrong
        // substrate here: it is a CPU thread pool over a `Read` byte stream, and our
        // work is the opposite shape — latency-bound async S3 PUTs of already-encoded
        // Parquet blobs. `gatling::io` keeps gatling's no-barrier / bounded / ordered
        // / zero-copy (`Bytes`) philosophy on a tokio substrate: it admits a new job
        // the instant a slot frees, caps the in-flight set at `wconc`, and re-orders
        // results back into submission (seq) order so commit batches stay deterministic.
        //
        // We drain the encode channel into a job iterator (each job = one PUT future
        // returning its `DataFile` descriptor). Encoders are already bounded by the
        // semaphore + `channel_depth`, so draining is just moving the encoded blobs;
        // each blob's `Bytes` is moved straight into its PUT job (no copy).
        let mut encoded: Vec<EncodedFile> = Vec::new();
        while let Some(ef) = rx.recv().await {
            encoded.push(ef);
        }

        // Build one async PUT job per encoded file. The job moves the blob's bytes
        // into the network write zero-copy and bumps the shared in-flight counter so
        // a test can prove the overlap really happened (not merely was requested).
        let jobs = encoded.into_iter().map(|ef| {
            let path = format!("{data_dir}/{file_prefix}-{:08}.parquet", ef.seq);
            let file_io = file_io.clone();
            let inflight = Arc::clone(&inflight);
            let peak = Arc::clone(&peak);
            async move {
                let len = ef.bytes.len() as u64;
                let now = inflight.fetch_add(1, Ordering::AcqRel) + 1;
                peak.fetch_max(now, Ordering::AcqRel);
                // Let every PUT gatling::io admitted register as in-flight before any
                // can complete: on S3 the round-trip yields anyway; on a fast local
                // store this one yield is what makes the overlap real (and observable)
                // instead of each PUT finishing before the next is polled.
                tokio::task::yield_now().await;
                let res = file_io
                    .new_output(&path)
                    .map_err(anyhow::Error::from)?
                    .write(Bytes::from(ef.bytes))
                    .await
                    .map_err(anyhow::Error::from);
                inflight.fetch_sub(1, Ordering::AcqRel);
                res.map(|()| (path, ef.record_count, len))
            }
        });

        // ≤ `wconc` PUTs in flight, results re-sequenced into submission (seq) order.
        let landed: Vec<(String, u64, u64)> =
            gatling_io::run_ordered(jobs, wconc, |x| x).await?;

        // Commit the ordered results in `fpc`-sized batches via fast_append, exactly
        // as the sequential path does — so both paths produce identical table state.
        let mut done: Vec<DataFile> = Vec::with_capacity(fpc);
        for (path, record_count, len) in landed {
            bytes_written += len;
            rows += record_count;
            files += 1;
            done.push(data_file(path, record_count, len)?);
            if done.len() >= fpc {
                table = commit_files(catalog.as_ref(), &table, std::mem::take(&mut done)).await?;
                commits += 1;
            }
        }
        if !done.is_empty() {
            table = commit_files(catalog.as_ref(), &table, done).await?;
            commits += 1;
        }
    }
    if !pending.is_empty() {
        table = commit_files(catalog.as_ref(), &table, pending).await?;
        commits += 1;
    }

    // Propagate any encoder error (channel close already let the writer finish).
    for e in encoders {
        e.await.expect("encoder task panicked")?;
    }

    Ok((
        table,
        PipelineStats {
            rows,
            files,
            commits,
            bytes_written,
            encode_workers,
            elapsed: start.elapsed(),
            write_concurrency: wconc,
            peak_inflight: peak.load(Ordering::Acquire).max(1),
        },
    ))
}

/// Build the iceberg `DataFile` descriptor for one written Parquet file.
fn data_file(path: String, record_count: u64, len: u64) -> Result<DataFile> {
    Ok(DataFileBuilder::default()
        .content(DataContentType::Data)
        .file_path(path)
        .file_format(DataFileFormat::Parquet)
        .record_count(record_count)
        .file_size_in_bytes(len)
        .build()?)
}

/// One `fast_append` commit of a batch of already-written data files.
async fn commit_files(catalog: &dyn Catalog, table: &Table, files: Vec<DataFile>) -> Result<Table> {
    let tx = Transaction::new(table);
    let action = tx.fast_append().add_data_files(files);
    let tx = action.apply(tx)?;
    Ok(tx.commit(catalog).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{data, factory};
    use iceberg::{NamespaceIdent, TableIdent};

    /// Build a fresh local (LocalFs) catalog + a node table, plus the synthetic
    /// batches grouped one-file-per-batch, for the ingest-path tests.
    async fn fixture(
        files: usize,
        rows_per_file: usize,
    ) -> Result<(Arc<dyn Catalog>, tempfile::TempDir, Vec<Vec<RecordBatch>>, ArrowSchemaRef)> {
        let tmp = factory::tempdir_in(&factory::nvme_dir())?;
        let cat = factory::embedded_in(&tmp).await?;
        let cat: Arc<dyn Catalog> = Arc::new(cat);
        let ns = NamespaceIdent::new("t".to_string());
        cat.create_namespace(&ns, Default::default()).await?;
        let schema = data::node_arrow_schema_standalone()?;
        let total = files * rows_per_file;
        let batches = data::synthetic_batches(schema.clone(), total, rows_per_file);
        let groups: Vec<Vec<RecordBatch>> = batches.into_iter().map(|b| vec![b]).collect();
        Ok((cat, tmp, groups, schema))
    }

    async fn make_table(cat: &dyn Catalog, name: &str) -> Result<Table> {
        let ident = TableIdent::new(NamespaceIdent::new("t".to_string()), name.to_string());
        data::create_node_table(cat, &ident).await
    }

    /// LAW (inject-and-assert): compress a KNOWN buffer through the user's
    /// `zstd-sys-rs` bindings (statically-linked libzstd 1.5.7) and assert it
    /// decompresses back to the EXACT original bytes. Proves the user's bindings
    /// are actually exercised — not merely "didn't panic": we feed real input and
    /// assert real output equals it.
    #[test]
    fn zstd_sys_rs_roundtrip_recovers_known_bytes() -> Result<()> {
        // A buffer with real structure (compressible runs + a unique tail) so the
        // assertion is meaningful, not a trivial all-zeros case.
        let mut original = Vec::with_capacity(64 * 1024);
        for i in 0..(64u32 * 1024) {
            original.push((i % 251) as u8); // periodic but not all-equal
        }
        original.extend_from_slice(b"skade-bench zstd-sys-rs sentinel \x00\xFF\x7E");

        let recovered = zstd_sys_roundtrip(&original, 9)?;
        assert_eq!(
            recovered, original,
            "zstd-sys-rs round-trip did not recover the original bytes"
        );

        // And prove it actually compressed (smaller frame) before decompressing —
        // i.e. the libzstd compressor really ran, the bytes weren't passed through.
        #[allow(unsafe_code)]
        let frame_len = {
            let bound = unsafe { zstd_sys_rs::ZSTD_compressBound(original.len()) };
            let mut comp = vec![0u8; bound];
            let n = unsafe {
                zstd_sys_rs::ZSTD_compress(
                    comp.as_mut_ptr().cast(),
                    comp.len(),
                    original.as_ptr().cast(),
                    original.len(),
                    9,
                )
            };
            assert_eq!(unsafe { zstd_sys_rs::ZSTD_isError(n) }, 0, "compress errored");
            n
        };
        assert!(
            frame_len < original.len(),
            "zstd-sys-rs did not compress (frame {} >= original {})",
            frame_len,
            original.len()
        );
        Ok(())
    }

    /// LAW (inject-and-assert): the `BENCH_PIPE_COMPRESSION=zstd-sys` encode path
    /// must still produce a VALID Parquet file (the round-trip returns the same
    /// bytes), so the iceberg scan reads back exactly the rows we ingested. We
    /// encode a real batch with the codec engaged and assert the resulting bytes
    /// parse as Parquet with the expected row count.
    #[test]
    fn zstd_sys_encode_path_yields_valid_parquet() -> Result<()> {
        use parquet::file::reader::{FileReader, SerializedFileReader};

        let schema = data::node_arrow_schema_standalone()?;
        let rows = 2_000usize;
        let batches = data::synthetic_batches(schema.clone(), rows, rows);

        // Engage the user's-bindings codec for this thread of execution.
        // SAFETY: single-threaded test, env set before the encode reads it.
        unsafe { std::env::set_var("BENCH_PIPE_COMPRESSION", "zstd-sys:9") };
        let (bytes, encoded_rows) = encode_parquet(schema, &batches)?;
        unsafe { std::env::remove_var("BENCH_PIPE_COMPRESSION") };

        assert_eq!(encoded_rows, rows as u64, "encode reported wrong row count");

        // The stored bytes must be a readable Parquet file with all the rows.
        let reader = SerializedFileReader::new(Bytes::from(bytes))?;
        let meta = reader.metadata();
        let file_rows: i64 = meta.file_metadata().num_rows();
        assert_eq!(
            file_rows, rows as i64,
            "zstd-sys-encoded file did not parse back to the right row count"
        );
        Ok(())
    }

    /// LAW (inject-and-assert): feed the SAME real batches through both the
    /// sequential single-writer and the concurrent multi-PUT writer, then assert
    /// they produce the SAME data (row count + file count scanned back) — the two
    /// paths are interchangeable for correctness. Also assert the concurrent path
    /// actually overlapped writes (`peak_inflight > 1`), not merely requested it,
    /// while the sequential path stayed at exactly 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writer_matches_sequential_and_overlaps() -> Result<()> {
        let files = 24usize;
        let rows_per_file = 500usize;

        // --- sequential (local-optimal) path ---
        let (cat, _tmp, groups, schema) = fixture(files, rows_per_file).await?;
        let seq_table = make_table(cat.as_ref(), "seq").await?;
        let (seq_table, seq_stats) = run_single_writer_ingest(
            Arc::clone(&cat), seq_table, groups, schema, 8, 8, "seq",
        )
        .await?;
        let (seq_scanned, _) = data::scan_count(&seq_table).await?;

        // --- concurrent (S3-style) path, fresh identical input ---
        let (cat2, _tmp2, groups2, schema2) = fixture(files, rows_per_file).await?;
        let conc_table = make_table(cat2.as_ref(), "conc").await?;
        let (conc_table, conc_stats) = run_concurrent_writer_ingest(
            Arc::clone(&cat2), conc_table, groups2, schema2, 8, 8, "conc", 16,
        )
        .await?;
        let (conc_scanned, _) = data::scan_count(&conc_table).await?;

        // Correctness: same rows ingested AND same rows scanned back.
        let expected = (files * rows_per_file) as u64;
        assert_eq!(seq_stats.rows, expected, "sequential ingested wrong row count");
        assert_eq!(conc_stats.rows, expected, "concurrent ingested wrong row count");
        assert_eq!(seq_scanned, expected, "sequential scan mismatch");
        assert_eq!(conc_scanned, expected, "concurrent scan mismatch");
        assert_eq!(
            seq_scanned, conc_scanned,
            "concurrent path produced different data than sequential"
        );
        assert_eq!(seq_stats.files, conc_stats.files, "different file counts");

        // Concurrency really happened on the concurrent path…
        assert_eq!(conc_stats.write_concurrency, 16);
        assert!(
            conc_stats.peak_inflight > 1,
            "concurrent writer never overlapped PUTs (peak_inflight={})",
            conc_stats.peak_inflight
        );
        // …and the sequential path stayed strictly serial.
        assert_eq!(seq_stats.write_concurrency, 1);
        assert_eq!(
            seq_stats.peak_inflight, 1,
            "sequential writer overlapped writes (peak_inflight={})",
            seq_stats.peak_inflight
        );
        Ok(())
    }
}
