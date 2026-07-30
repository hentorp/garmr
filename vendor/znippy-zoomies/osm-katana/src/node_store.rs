use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use memmap2::{Mmap, MmapOptions};
// ROOT LAW #0: every fan-out in this file goes through `gatling`. There is no
// rayon and, since 2026-07-22, no hand-rolled `std::thread::scope` pool either.

use crate::stree64::{STree64, STree64Mmap};
// Parallel sort lives in znippy-zoomies (`psort`); the single-chunk fast path
// of `external_merge_sort` calls into it.
use znippy_zoomies::psort::samplesort_aos_by_i64_key;

// AoS record on disk: [i64 le id][f32 le lat][f32 le lon] = 16 bytes, no padding.
const RECORD_SIZE: usize = 16;

// Sequential I/O buffer for NVMe — large enough to amortise syscall overhead.
const IO_BUF_BYTES: usize = 128 * 1024 * 1024;

// Sort chunks of ~8 GB in RAM; switch to external merge sort above this.
// 512 M records × 16 B = 8 GB per chunk → keeps peak RSS under 32 GB (Europe).
const SORT_CHUNK_RECORDS: usize = 512 * 1024 * 1024; // 512 M records × 16 B = 8 GB

// ── NodeStore ─────────────────────────────────────────────────────────────────

pub struct NodeStore {
    inner: Inner,
}

enum Inner {
    Vecs {
        ids: Vec<i64>,
        coords: Vec<(f32, f32)>,
    },
    STree {
        tree: STree64,
        coords: Vec<(f32, f32)>,
    },
    MmapTree {
        tree: STree64Mmap,
        mmap: Mmap,
    },
    /// Single-batch Arrow IPC file mmap'd zero-copy (PR 2c). One backing mmap;
    /// the id/lat/lon value buffers are sub-ranges at `*_off`.
    ArrowMmap {
        tree: STree64Mmap,
        mmap: Mmap,
        id_off: usize,
        lat_off: usize,
        lon_off: usize,
        count: usize,
    },
}

impl NodeStore {
    pub fn new() -> Self {
        Self {
            inner: Inner::Vecs {
                ids: Vec::new(),
                coords: Vec::new(),
            },
        }
    }

    pub fn from_coords(mut nodes: Vec<(i64, f32, f32)>) -> Self {
        // Was par_sort; now serial (only called from PBF path on small in-RAM Vecs).
        nodes.sort_unstable_by_key(|&(id, _, _)| id);
        let mut ids = Vec::with_capacity(nodes.len());
        let mut coords = Vec::with_capacity(nodes.len());
        for (id, lat, lon) in nodes {
            ids.push(id);
            coords.push((lat, lon));
        }
        let tree = STree64::new(&ids);
        Self {
            inner: Inner::STree { tree, coords },
        }
    }

    pub fn from_mmap(mmap: Mmap, count: usize) -> Self {
        eprintln!("  building STree64Mmap index ({count} records) …");
        let t = std::time::Instant::now();
        let tree = STree64Mmap::new(mmap.as_ref(), count);
        eprintln!("  STree64Mmap built in {:.1}s", t.elapsed().as_secs_f64());
        Self {
            inner: Inner::MmapTree { tree, mmap },
        }
    }

    /// Create from a single-batch Arrow IPC file mmap'd zero-copy (PR 2c).
    /// `id_off`/`lat_off`/`lon_off` are byte offsets into `mmap` of the three
    /// value buffers. The STree is built over the id buffer (stride=8).
    pub fn from_arrow_mmap(
        mmap: Mmap,
        id_off: usize,
        lat_off: usize,
        lon_off: usize,
        count: usize,
    ) -> Self {
        eprintln!("  building STree64Mmap index (Arrow IPC mmap, {count} records) …");
        let t = std::time::Instant::now();
        let id_bytes = &mmap.as_ref()[id_off..id_off + count * 8];
        let tree = STree64Mmap::new_with_stride(id_bytes, count, 8);
        eprintln!("  STree64Mmap built in {:.1}s", t.elapsed().as_secs_f64());
        Self {
            inner: Inner::ArrowMmap {
                tree,
                mmap,
                id_off,
                lat_off,
                lon_off,
                count,
            },
        }
    }

    #[allow(dead_code, reason = "XML reader path uses this")]
    pub fn insert(&mut self, id: i64, lat: f32, lon: f32) {
        if let Inner::Vecs { ids, coords } = &mut self.inner {
            ids.push(id);
            coords.push((lat, lon));
        }
    }

    pub fn len(&self) -> usize {
        match &self.inner {
            Inner::Vecs { ids, .. } => ids.len(),
            Inner::STree { coords, .. } => coords.len(),
            Inner::MmapTree { tree, .. } => tree.count,
            Inner::ArrowMmap { count, .. } => *count,
        }
    }

    #[inline]
    pub fn lookup(&self, id: i64) -> Option<(f32, f32)> {
        match &self.inner {
            Inner::Vecs { ids, coords } => {
                let pos = ids.binary_search(&id).ok()?;
                coords.get(pos).copied()
            }
            Inner::STree { tree, coords } => {
                let pos = tree.find_exact(id)?;
                coords.get(pos).copied()
            }
            Inner::MmapTree { tree, mmap } => {
                let pos = tree.find_exact(id, mmap.as_ref())?;
                let off = pos * RECORD_SIZE;
                let lat = f32::from_le_bytes(mmap[off + 8..off + 12].try_into().ok()?);
                let lon = f32::from_le_bytes(mmap[off + 12..off + 16].try_into().ok()?);
                Some((lat, lon))
            }
            Inner::ArrowMmap {
                tree,
                mmap,
                id_off,
                lat_off,
                lon_off,
                count,
            } => {
                let bytes = mmap.as_ref();
                let id_bytes = bytes.get(*id_off..*id_off + *count * 8)?;
                let pos = tree.find_exact(id, id_bytes)?;
                let lat = f32::from_le_bytes(
                    bytes
                        .get(*lat_off + pos * 4..*lat_off + pos * 4 + 4)?
                        .try_into()
                        .ok()?,
                );
                let lon = f32::from_le_bytes(
                    bytes
                        .get(*lon_off + pos * 4..*lon_off + pos * 4 + 4)?
                        .try_into()
                        .ok()?,
                );
                Some((lat, lon))
            }
        }
    }

    /// Batch lookup — resolve many ids in one call. On the on-disk `MmapTree`
    /// variant this dispatches to `STree64Mmap::lookup_batch`, which:
    ///   1. Tree-routes every id in RAM (cheap)
    ///   2. Sorts by leaf-block index for sequential mmap walk
    ///   3. `madvise(WILLNEED)` so the kernel issues parallel readahead
    ///   4. Scans leaves in sorted order, scatters results back
    ///
    /// For the other variants (small in-memory stores) the implementation just
    /// loops `lookup` — there's nothing to batch when the data is already in
    /// RAM. Returns `out[i]` aligned with `ids[i]`.
    pub fn lookup_batch(&self, ids: &[i64]) -> Vec<Option<(f32, f32)>> {
        match &self.inner {
            Inner::MmapTree { tree, mmap } => {
                let bytes = mmap.as_ref();
                tree.lookup_batch_pipeline::<16>(ids, bytes)
                    .into_iter()
                    .map(|p| {
                        p.and_then(|pos| {
                            let off = pos * RECORD_SIZE;
                            let lat =
                                f32::from_le_bytes(bytes.get(off + 8..off + 12)?.try_into().ok()?);
                            let lon =
                                f32::from_le_bytes(bytes.get(off + 12..off + 16)?.try_into().ok()?);
                            Some((lat, lon))
                        })
                    })
                    .collect()
            }
            Inner::ArrowMmap {
                tree,
                mmap,
                id_off,
                lat_off,
                lon_off,
                count,
            } => {
                let bytes = mmap.as_ref();
                let id_bytes = &bytes[*id_off..*id_off + *count * 8];
                let (lat_off, lon_off) = (*lat_off, *lon_off);
                tree.lookup_batch_pipeline::<16>(ids, id_bytes)
                    .into_iter()
                    .map(|p| {
                        p.and_then(|pos| {
                            let lat = f32::from_le_bytes(
                                bytes
                                    .get(lat_off + pos * 4..lat_off + pos * 4 + 4)?
                                    .try_into()
                                    .ok()?,
                            );
                            let lon = f32::from_le_bytes(
                                bytes
                                    .get(lon_off + pos * 4..lon_off + pos * 4 + 4)?
                                    .try_into()
                                    .ok()?,
                            );
                            Some((lat, lon))
                        })
                    })
                    .collect()
            }
            _ => ids.iter().map(|&id| self.lookup(id)).collect(),
        }
    }
}

impl Default for NodeStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── CoordFileWriter ───────────────────────────────────────────────────────────
//
// STREAMING CHUNKED SORTER (overlap sort with pass-1 decode).
//
// Records (id, lat, lon) arrive during pass 1 via `push`/`write_raw` on the
// collector thread. They accumulate in an in-RAM `Vec<[u8; 16]>`. When the
// buffer reaches `NC_CHUNK_RECORDS`, it is MOVED out (`mem::replace`) and handed
// to a BACKGROUND `std::thread` that sample-sorts it and spills one sorted chunk
// file `_nc_chunk_{i}.bin`. The collector keeps ingesting the next chunk's
// records while that sort runs → the sort overlaps the ongoing decode instead of
// being a stop-the-world barrier after pass 1.
//
// At most ONE background sort is in flight (join sorter i-1 before spawning i):
// `samplesort_aos_by_i64_key` itself saturates every core, so allowing two
// concurrent sorts would only oversubscribe; one sort overlapping the next
// chunk's decode is the sweet spot.
//
// `finalize()` sorts+spills the final partial buffer, joins all background
// sorters, then runs the SAME phase-2 Arrow-SoA k-way merge
// (`merge_sorted_chunks_to_arrow`) used by the multi-chunk `external_merge_sort`
// path to produce the single-batch `node_coords.arrow`, mmaps it, and builds the
// STree via `from_arrow_mmap` (UNCHANGED).
//
// BYTE-IDENTICAL: node ids are globally unique, so sorting by id is a
// deterministic total order. A k-way merge of per-chunk id-sorted files yields
// exactly the same record sequence as a single-shot sort of all records — the
// bytes of `node_coords.arrow` are independent of how the input was chunked.

// ~33.5 M records/chunk (≈ 512 MB AoS) base. Sweden's ~105 M node coords → ≥3
// chunks, so ≥3 sorts overlap pass-1 decode. Small inputs stay a single chunk.
// The threshold GROWS as chunks accumulate (see `spill_threshold`) so the chunk
// COUNT stays bounded on planet-scale — the k-way merge opens one reader per
// chunk per thread, so unbounded chunks would blow merge RAM.
const NC_CHUNK_RECORDS: usize = 32 * 1024 * 1024;

pub struct CoordFileWriter {
    dir: PathBuf,
    buf: Vec<[u8; RECORD_SIZE]>,
    count: usize,
    next_chunk: usize,
    chunks: Vec<(PathBuf, usize)>,
    // Depth-1 overlap: the previous chunk sorts+writes on a gatling background
    // job while pass-1 keeps decoding. Routed through the engine crate so this
    // stays within the one-engine ("rayon-free") law — no hand-rolled thread.
    pending: Option<gatling::background::Job<Result<()>>>,
}

impl CoordFileWriter {
    pub fn new(path: &Path) -> Result<Self> {
        // `path` is the legacy `node_coords.bin` location; we only use its parent
        // directory (chunk files + the final `node_coords.arrow` live there).
        let dir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Ok(Self {
            dir,
            buf: Vec::with_capacity(NC_CHUNK_RECORDS),
            count: 0,
            next_chunk: 0,
            chunks: Vec::new(),
            pending: None,
        })
    }

    #[inline]
    pub fn push(&mut self, id: i64, lat: f32, lon: f32) -> Result<()> {
        let mut rec = [0u8; RECORD_SIZE];
        rec[0..8].copy_from_slice(&id.to_le_bytes());
        rec[8..12].copy_from_slice(&lat.to_le_bytes());
        rec[12..16].copy_from_slice(&lon.to_le_bytes());
        self.buf.push(rec);
        self.count += 1;
        if self.buf.len() >= self.spill_threshold() {
            self.spill_chunk()?;
        }
        Ok(())
    }

    /// Append a pre-packed buffer of 16-byte records (i64 le id, f32 le lat,
    /// f32 le lon). Used by the pass-1 sink: workers pack their coords in
    /// parallel, the collector hands the whole buffer over in one call,
    /// avoiding ~10 M serial `push()` calls per slot.
    #[inline]
    pub fn write_raw(&mut self, raw: &[u8]) -> Result<()> {
        debug_assert_eq!(raw.len() % RECORD_SIZE, 0);
        self.buf.extend(raw.chunks_exact(RECORD_SIZE).map(|s| {
            let mut r = [0u8; RECORD_SIZE];
            r.copy_from_slice(s);
            r
        }));
        self.count += raw.len() / RECORD_SIZE;
        if self.buf.len() >= self.spill_threshold() {
            self.spill_chunk()?;
        }
        Ok(())
    }

    /// Records that trigger a spill. Grows with the number of chunks already
    /// spilled so the total chunk COUNT stays bounded on huge inputs — the k-way
    /// merge opens one reader per chunk per thread, so an unbounded chunk count
    /// would blow merge RAM on planet-scale. Doubles every 8 chunks, capped at
    /// 512 M records (~8 GB AoS, the samplesort in-RAM budget). Sweden/Europe stay
    /// at the base size (< 8 chunks) → unchanged chunking, byte-identical output.
    #[inline]
    fn spill_threshold(&self) -> usize {
        NC_CHUNK_RECORDS << (self.next_chunk / 8).min(4)
    }

    /// Move the current buffer to a background sorter that sample-sorts it and
    /// writes one sorted `_nc_chunk_{i}.bin`. Joins the previous sorter first so
    /// at most one sort (each already all-core) runs at a time.
    fn spill_chunk(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        self.join_pending()?;
        let mut buf = std::mem::replace(&mut self.buf, Vec::with_capacity(NC_CHUNK_RECORDS));
        let chunk_i = self.next_chunk;
        self.next_chunk += 1;
        let chunk_path = self.dir.join(format!("_nc_chunk_{chunk_i}.bin"));
        let n = buf.len();
        self.chunks.push((chunk_path.clone(), n));
        let handle = gatling::background::Job::spawn(move || -> Result<()> {
            samplesort_aos_by_i64_key(&mut buf);
            let mut f = std::io::BufWriter::with_capacity(
                IO_BUF_BYTES,
                std::fs::File::create(&chunk_path)
                    .with_context(|| format!("create {}", chunk_path.display()))?,
            );
            // `[u8; 16]` is Copy, contiguous, no padding → reinterpret the whole
            // Vec as one contiguous byte slice for a single sequential write.
            let bytes = unsafe {
                std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * RECORD_SIZE)
            };
            f.write_all(bytes)?;
            f.flush()?;
            Ok(())
        });
        self.pending = Some(handle);
        Ok(())
    }

    fn join_pending(&mut self) -> Result<()> {
        if let Some(h) = self.pending.take() {
            h.join()
                .map_err(|_| anyhow::anyhow!("node-coord background sorter panicked"))??;
        }
        Ok(())
    }

    /// Spill+sort the tail buffer, join all background sorters, k-way-merge the
    /// sorted chunks into a single-batch `node_coords.arrow`, mmap it and build
    /// the STree over the id buffer (stride=8). See `coords_ipc` + DESIGN.md §4.1.
    pub fn finalize(mut self) -> Result<NodeStore> {
        let count = self.count;
        let arrow_path = self.dir.join("node_coords.arrow");

        if count == 0 {
            // Emit a valid empty IPC file for downstream interop.
            write_empty_arrow(&arrow_path)?;
            return Ok(NodeStore::new());
        }

        // Sort+spill the final partial buffer, then wait for every background
        // sorter so all sorted chunk files exist before the merge.
        self.spill_chunk()?;
        self.join_pending()?;
        let chunk_paths = std::mem::take(&mut self.chunks);

        // Reuse the phase-2 Arrow-SoA merge (identical output to the single-shot
        // path). A k-way merge of id-sorted chunks == a single-shot sort because
        // node ids are globally unique.
        let t_arrow = std::time::Instant::now();
        merge_sorted_chunks_to_arrow(&chunk_paths, count, &arrow_path)?;
        eprintln!(
            "  node_coords.arrow written in {:.1}s",
            t_arrow.elapsed().as_secs_f64()
        );

        // Zero-copy mmap the Arrow IPC value buffers and build the STree on the
        // id buffer. The file stays on disk for DuckDB/pyarrow/polars interop.
        let mc = crate::coords_ipc::open_mmap(&arrow_path)?;
        Ok(NodeStore::from_arrow_mmap(
            mc.mmap, mc.id_off, mc.lat_off, mc.lon_off, mc.count,
        ))
    }
}

/// Write a valid empty single-batch-less Arrow IPC file (count == 0).
fn write_empty_arrow(path: &Path) -> Result<()> {
    use arrow::ipc::writer::FileWriter;
    let schema = std::sync::Arc::new(crate::coords_ipc::coord_schema());
    let f = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut w = FileWriter::try_new(f, &schema).context("create Arrow IPC writer")?;
    w.finish().context("finish empty Arrow IPC file")?;
    Ok(())
}

// ── Sort helpers ──────────────────────────────────────────────────────────────
//
// `CoordFileWriter` now sorts incrementally (streaming chunked sorter, overlaps
// pass-1 decode) and merges via `merge_sorted_chunks_to_arrow`. The
// `external_merge_sort{,_inner}` / `adaptive_chunk_records` / `available_ram_bytes`
// entry points below are the post-pass "sort a finished AoS file" reference path;
// they remain exercised by the unit tests (and share `merge_sorted_chunks_to_arrow`
// for their phase-2) but are no longer on the live convert path — hence
// `#[allow(dead_code)]` for the non-test build.

#[allow(dead_code)]
pub fn available_ram_bytes() -> usize {
    #[cfg(target_os = "linux")]
    if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
        for line in s.lines() {
            if line.starts_with("MemAvailable:") {
                if let Some(kb) = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<usize>().ok())
                {
                    return kb * 1024;
                }
            }
        }
    }
    8 * 1024 * 1024 * 1024 // 8 GB fallback
}

/// External k-way merge sort for sorted (id, lat, lon) records.
///
/// Phase 1: read the unsorted AoS file in `SORT_CHUNK_RECORDS`-sized slices,
///          sort each chunk in RAM with the parallel sample sort
///          ([`samplesort_aos_by_i64_key`] — the same sorter as the fast path),
///          processed sequentially so each chunk gets all cores with no nested-
///          thread oversubscription, then write to a temp chunk file (AoS).
///          When `n_chunks <= 1` the whole input fits in one chunk and we take
///          a **fast path**: read AoS into a Vec, sample-sort it, stream the
///          single-batch Arrow IPC body directly. No temp chunk file, no merger.
/// Phase 2: parallel partition merge — binary-search the ID space to find
///          `n_threads` balanced partition boundaries, then each thread
///          merges its ID range from all chunks. **Writes directly into the
///          three pre-laid body regions of the single-batch `node_coords.arrow`
///          file** — no AoS write-back, no separate col-split phase, no
///          intermediate `_col_*.bin`. The input AoS file is left untouched.
/// Cleanup: delete all chunk files.
///
/// PR 2c: the sort emits the final Arrow IPC file directly (one record batch,
/// fixed-width columns → contiguous id buffer mmap'd zero-copy at runtime),
/// eliminating both the `_col_*.bin` write and the separate SoA→Arrow pass.
#[allow(dead_code)]
fn external_merge_sort(path: &Path, count: usize, arrow_path: &Path) -> Result<()> {
    let avail = available_ram_bytes();
    let chunk = adaptive_chunk_records(count, avail);
    if chunk >= count.max(1) {
        eprintln!(
            "  ext-sort: {count} records fit single-shot (need ~{} GB, {} GB avail) → in-RAM sample sort, no merge",
            (count.saturating_mul(RECORD_SIZE * 2)) / (1024 * 1024 * 1024),
            avail / (1024 * 1024 * 1024),
        );
    }
    external_merge_sort_inner(path, count, arrow_path, chunk)
}

/// Pick the sample-sort chunk size that **bounds peak RSS regardless of how much
/// RAM is free**.
///
/// REGRESSION FIX 2026-06-17: the previous version (a6fe22a) chose the
/// single-shot path whenever `2 × count × 16 B + 16 GB` fit in `avail_bytes`.
/// On this box (499 GB free) that meant *every* real-world input — sweden, even
/// the 60 GB europe AoS — collapsed onto the single-shot path, whose load and
/// body-write brackets were SERIAL (one core copying the whole mmap into a `Vec`
/// + three sequential body writes). That is the CPU dip the convert hit in the
/// sort phase, plus a Law-1/Law-2 violation (full mmap → `Vec` copy + a huge
/// alloc proportional to `avail`, not to a fixed budget).
///
/// The new policy ignores `avail_bytes` for the routing decision and bounds peak
/// RAM by a FIXED budget: anything above `SORT_CHUNK_RECORDS` (≈ 8 GB of records;
/// the sample sort's out-of-place scratch doubles that to ≈ 16 GB peak per chunk
/// — well within the historical "planet ~13 GB" envelope) takes the multi-chunk,
/// RAM-bounded, fully-parallel k-way-merge path. The single-shot path now fires
/// ONLY for genuinely small inputs (`count <= SORT_CHUNK_RECORDS`) — and that
/// path is itself parallelized (parallel mmap→Vec load, parallel body write), so
/// even single-shot saturates all cores. `avail_bytes` is retained only as a
/// reported diagnostic in the caller.
///
/// Returns a chunk size `>= count` (single-shot) only when `count` already fits
/// the fixed per-chunk budget; otherwise `SORT_CHUNK_RECORDS` (multi-chunk).
#[allow(dead_code)]
fn adaptive_chunk_records(count: usize, _avail_bytes: usize) -> usize {
    if count <= SORT_CHUNK_RECORDS {
        count.max(1)
    } else {
        SORT_CHUNK_RECORDS
    }
}

#[allow(dead_code)]
fn external_merge_sort_inner(
    path: &Path,
    count: usize,
    arrow_path: &Path,
    chunk_records: usize,
) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let n_chunks = count.div_ceil(chunk_records);

    // ── Fast path: whole dataset fits in one chunk ─────────────────────────
    // Read the AoS file into a Vec, parallel sample-sort it across all cores,
    // then stream the single-batch Arrow IPC file (prologue, 3 body regions,
    // epilogue) sequentially. Taken when `chunk_records >= count` — either a
    // small input (≤ SORT_CHUNK_RECORDS ≈ Europe) or a large-RAM box where
    // `adaptive_chunk_records` chose single-shot (e.g. planet on a >360 GB box).
    if n_chunks <= 1 {
        eprintln!(
            "  ext-sort fast path: {count} records ≤ chunk size → in-RAM PARALLEL sample sort"
        );
        let n_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1);

        // ── Load: parallel mmap→Vec copy ──────────────────────────────────────
        // REGRESSION FIX 2026-06-17: the old `aos_mmap.chunks_exact(16).collect()`
        // copied the whole AoS file into a `Vec` on ONE core — the serial 1-core
        // dip at the head of the sort phase. Allocate the destination once, then
        // fault+copy the mmap into it across all cores.
        //
        // ROOT LAW #0 (2026-07-22): the fan-out was a hand-rolled
        // `std::thread::scope` pool with one statically-sized range per thread —
        // a scoped work pool, i.e. exactly the disguise the law names. It is now
        // `gatling_run` (side-effects only, disjoint per-unit output). The unit is
        // also FOUR TIMES finer than the old one-range-per-thread carve-up: this
        // is page-fault + memory-bandwidth work on a box that is rarely idle, and
        // with exactly `n_threads` units there is nothing left to self-dispatch —
        // one slow core holds the whole load. Bounded RAM (one `Vec`, ≤ 8 GB here).
        let t_load = std::time::Instant::now();
        let input_file =
            std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let aos_mmap = unsafe { MmapOptions::new().map(&input_file)? };
        debug_assert_eq!(aos_mmap.len(), count * RECORD_SIZE);
        // calloc'd: `[0u8; RECORD_SIZE]` is IsZero, so this is alloc_zeroed —
        // lazy zero pages, ~free, and the page-fault-on-write cost is identical
        // to an uninit Vec. Every slot is overwritten by the parallel copy below.
        // Avoids clippy::uninit_vec and any read-of-uninit UB (no unsafe set_len).
        let mut records: Vec<[u8; RECORD_SIZE]> = vec![[0u8; RECORD_SIZE]; count];
        {
            // Raw pointers aren't `Send`; pass addresses as `usize` so the worker
            // closure compiles.
            let src_addr = aos_mmap.as_ptr() as usize;
            let dst_addr = records.as_mut_ptr() as usize;
            let n_units = (n_threads * 4).max(1);
            let chunk = count.div_ceil(n_units);
            let n_units = count.div_ceil(chunk.max(1));
            gatling::gatling_forkjoin::gatling_run(n_units, n_threads, |u| {
                let start = u * chunk;
                let end = (start + chunk).min(count);
                let src = src_addr as *const u8;
                let dst = dst_addr as *mut [u8; RECORD_SIZE];
                // SAFETY: units partition `0..count` into disjoint, in-bounds
                // ranges (`u * chunk .. min(start + chunk, count)`), each claimed
                // by exactly one worker via the engine's atomic cursor, so no two
                // writes alias. `records` is `count` elements long and the mmap is
                // `count * RECORD_SIZE` bytes (debug-asserted above). The engine
                // joins every worker before the borrow ends.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        src.add(start * RECORD_SIZE),
                        dst.add(start) as *mut u8,
                        (end - start) * RECORD_SIZE,
                    );
                }
            });
        }
        drop(aos_mmap);
        drop(input_file);
        eprintln!(
            "    loaded in {:.1}s ({n_threads} parallel streams)",
            t_load.elapsed().as_secs_f64()
        );

        let t_sort = std::time::Instant::now();
        samplesort_aos_by_i64_key(&mut records);
        eprintln!(
            "    sample-sorted in {:.1}s",
            t_sort.elapsed().as_secs_f64()
        );

        // ── Write: parallel body write into the pre-laid Arrow IPC regions ─────
        // REGRESSION FIX 2026-06-17: the old path wrote the 3 body regions with
        // three SERIAL `for rec in &records { w.write_all(..) }` loops on ONE
        // core. Mirror the multi-chunk phase-2 scheme: lay the prologue, pre-size
        // the file, then each thread writes its record range into all 3 regions
        // (id/lat/lon) at the correct seeked offset. All cores, bounded buffers.
        let t_write = std::time::Instant::now();
        let layout = {
            use std::io::Write as _;
            let f = std::fs::File::create(arrow_path)
                .with_context(|| format!("create {}", arrow_path.display()))?;
            let mut w = std::io::BufWriter::new(f);
            let l = crate::coords_ipc::write_prologue(&mut w, count)?;
            w.flush()?;
            l
        };
        std::fs::OpenOptions::new()
            .write(true)
            .open(arrow_path)?
            .set_len(layout.body_start + layout.body_total)?;

        // ROOT LAW #0 (2026-07-22): was a hand-rolled `std::thread::scope` pool,
        // one thread per static record range, each holding three seeked 32 MB
        // `BufWriter`s (96 MB of freshly-faulted scratch PER THREAD — 3 GB on a
        // 32-core box) and issuing three `write_all` calls PER RECORD.
        //
        // The ranges are disjoint slices of a PRE-SIZED file, which is the
        // `parwrite` shape, so this is now `gatling_run` over the ranges with the
        // same exact-size staging + one positional `write_all_at` per column that
        // `merge_sorted_chunks_to_arrow` uses. Same bytes, same offsets, same
        // pre-sized file — byte-identical by construction.
        let records_ref = &records;
        let layout_ref = &layout;
        let arrow_out = arrow_path.to_path_buf();
        let arrow_out_ref = &arrow_out;
        let chunk = count.div_ceil(n_threads);
        let n_units = count.div_ceil(chunk.max(1));
        let write_errors: Vec<Option<anyhow::Error>> = gatling::gatling_forkjoin::gatling_for_each(
            n_units,
            n_threads,
            |u| -> Option<anyhow::Error> {
                use std::os::unix::fs::FileExt;
                let layout = layout_ref;
                let records = records_ref;
                let arrow_out = arrow_out_ref;
                let start = u * chunk;
                let end = (start + chunk).min(count);
                let n = end - start;

                // Exact-size staging for this range's three SoA column slices.
                let mut buf_id = Vec::<u8>::with_capacity(n * 8);
                let mut buf_lat = Vec::<u8>::with_capacity(n * 4);
                let mut buf_lon = Vec::<u8>::with_capacity(n * 4);
                for rec in &records[start..end] {
                    buf_id.extend_from_slice(&rec[0..8]);
                    buf_lat.extend_from_slice(&rec[8..12]);
                    buf_lon.extend_from_slice(&rec[12..16]);
                }

                let f = match std::fs::OpenOptions::new()
                    .write(true)
                    .open(arrow_out)
                    .with_context(|| format!("open {}", arrow_out.display()))
                {
                    Ok(f) => f,
                    Err(e) => return Some(e),
                };
                for (bytes, abs, width) in [
                    (&buf_id, layout.id_abs, 8usize),
                    (&buf_lat, layout.lat_abs, 4),
                    (&buf_lon, layout.lon_abs, 4),
                ] {
                    if let Err(e) = f.write_all_at(bytes, abs + (start * width) as u64) {
                        return Some(e.into());
                    }
                }
                None
            },
        );
        if let Some(e) = write_errors.into_iter().flatten().next() {
            return Err(e);
        }

        // Append the IPC footer after the fully-written body.
        {
            use std::io::{Seek, SeekFrom};
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(arrow_path)
                .with_context(|| format!("open {}", arrow_path.display()))?;
            f.seek(SeekFrom::Start(layout.body_start + layout.body_total))?;
            let mut w = std::io::BufWriter::new(f);
            crate::coords_ipc::write_epilogue(&mut w, &layout)?;
        }
        eprintln!(
            "    node_coords.arrow body written in {:.1}s ({n_threads} parallel streams)",
            t_write.elapsed().as_secs_f64()
        );
        return Ok(());
    }

    // ── Multi-chunk path ──────────────────────────────────────────────────
    let chunk_bytes = chunk_records * RECORD_SIZE;
    let chunk_gb = chunk_bytes / (1024 * 1024 * 1024);
    let avail = available_ram_bytes();
    eprintln!(
        "  ext-sort: {count} records → {n_chunks} chunks × {chunk_gb} GB  (RAM: {}G avail)",
        avail / (1024 * 1024 * 1024)
    );

    // ── Phase 1: write sorted chunk files ────────────────────────────────────
    // Each chunk is sorted with the parallel sample sort (`samplesort_aos_by_i64_key`,
    // the Ragnar-successor in znippy-zoomies::psort) — the SAME sorter as the
    // single-chunk fast path. The sample sort already spawns
    // `available_parallelism()` worker threads internally, so chunks are
    // processed SEQUENTIALLY: each chunk gets the whole machine for its sort and
    // there is no nested-thread oversubscription. This also keeps RAM pressure to
    // a single chunk resident at a time (≈ `chunk_bytes`) rather than up to
    // `max_par` chunks, which matters on planet (~8 GB/chunk).
    let input_file = std::fs::File::open(path)?;
    let input_mmap = unsafe { MmapOptions::new().map(&input_file)? };

    let mut chunk_paths: Vec<(PathBuf, usize)> = Vec::with_capacity(n_chunks);

    for chunk_i in 0..n_chunks {
        let t0 = std::time::Instant::now();
        let start = chunk_i * chunk_records;
        let n = (count - start).min(chunk_records);
        let byte_start = start * RECORD_SIZE;

        let mut records: Vec<[u8; RECORD_SIZE]> = input_mmap
            [byte_start..byte_start + n * RECORD_SIZE]
            .chunks_exact(RECORD_SIZE)
            .map(|s| s.try_into().unwrap())
            .collect();

        samplesort_aos_by_i64_key(&mut records);

        let chunk_path = dir.join(format!("_nc_chunk_{chunk_i}.bin"));
        {
            use std::io::Write as _;
            let mut f = std::io::BufWriter::with_capacity(
                IO_BUF_BYTES,
                std::fs::File::create(&chunk_path)
                    .with_context(|| format!("create {}", chunk_path.display()))?,
            );
            for rec in &records {
                f.write_all(rec)?;
            }
            f.flush()?;
        }
        drop(records);
        chunk_paths.push((chunk_path, n));
        eprintln!(
            "  ext-sort chunk {}/{n_chunks} sample-sorted + written  ({:.1}s)",
            chunk_i + 1,
            t0.elapsed().as_secs_f64()
        );
    }

    drop(input_mmap);
    drop(input_file); // original file is safe to overwrite

    // ── Phase 2: parallel partition merge (shared with CoordFileWriter) ─────────
    merge_sorted_chunks_to_arrow(&chunk_paths, count, arrow_path)
}

/// Phase-2 parallel partition merge: k-way merge the sorted AoS chunk files into
/// a single-batch `node_coords.arrow` (id/lat/lon SoA regions written via seeked
/// offset writes, then epilogue), and delete the chunk files.
///
/// Shared by BOTH the `external_merge_sort` multi-chunk path AND
/// `CoordFileWriter::finalize` (the streaming chunked sorter). Node ids are
/// globally unique, so a k-way merge of per-chunk id-sorted files yields exactly
/// the same record sequence as a single-shot sort of all records → the emitted
/// `node_coords.arrow` bytes are independent of how the input was chunked
/// (byte-identical).
///
/// Divide the global sorted output into `n_threads` equal-count ID ranges. Each
/// thread gets its own BufReader per chunk (seeks to its range start) and writes
/// its slice of the three pre-laid body regions of the arrow file. All I/O is
/// sequential per thread — no shared mutable state, no page-cache thrashing.
fn merge_sorted_chunks_to_arrow(
    chunk_paths: &[(PathBuf, usize)],
    count: usize,
    arrow_path: &Path,
) -> Result<()> {
    let n_chunks = chunk_paths.len();
    // Never partition into more streams than there are records: with more threads
    // than records the per-thread quantile targets would be 0 (empty partitions),
    // which is wasteful and, historically, tripped the find_quantile edge case.
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
        .min(count.max(1));
    eprintln!("  ext-sort merging {n_chunks} chunks ({n_threads} parallel streams) …");
    let t_merge = std::time::Instant::now();

    // Open chunks as mmaps only for the cheap boundary search (O(n_threads×n_chunks×log N)).
    let chunk_files_q: Vec<std::fs::File> = chunk_paths
        .iter()
        .map(|(p, _)| std::fs::File::open(p).with_context(|| format!("open {}", p.display())))
        .collect::<Result<_>>()?;
    let chunk_mmaps: Vec<Mmap> = chunk_files_q
        .iter()
        .map(|f| unsafe { MmapOptions::new().map(f) }.map_err(anyhow::Error::from))
        .collect::<Result<_>>()?;
    let chunk_counts: Vec<usize> = chunk_paths.iter().map(|(_, n)| *n).collect();

    let split_ids: Vec<i64> = (1..n_threads)
        .map(|t| {
            let target = (count as u128 * t as u128 / n_threads as u128) as usize;
            find_quantile(&chunk_mmaps, &chunk_counts, target)
        })
        .collect();

    let chunk_part_starts: Vec<Vec<usize>> = chunk_mmaps
        .iter()
        .zip(chunk_counts.iter())
        .map(|(mmap, &n)| {
            let mut starts = Vec::with_capacity(n_threads + 1);
            starts.push(0usize);
            for &id in &split_ids {
                starts.push(lb_id(mmap, n, id));
            }
            starts.push(n);
            starts
        })
        .collect();

    // Boundary search done — drop mmaps before the merge to free page-cache pressure.
    drop(chunk_mmaps);
    drop(chunk_files_q);

    let part_counts: Vec<usize> = (0..n_threads)
        .map(|t| {
            (0..n_chunks)
                .map(|c| chunk_part_starts[c][t + 1] - chunk_part_starts[c][t])
                .sum()
        })
        .collect();
    let part_offsets: Vec<usize> = {
        let mut off = vec![0usize; n_threads + 1];
        for t in 0..n_threads {
            off[t + 1] = off[t] + part_counts[t];
        }
        off
    };
    debug_assert_eq!(part_offsets[n_threads], count);

    // Write the Arrow IPC prologue (magic + schema + record-batch metadata),
    // then pre-size the file so every merge thread can seek into its slice of
    // the three body regions. The footer is appended after the merge.
    let layout = {
        use std::io::Write as _;
        let f = std::fs::File::create(arrow_path)
            .with_context(|| format!("create {}", arrow_path.display()))?;
        let mut w = std::io::BufWriter::new(f);
        let l = crate::coords_ipc::write_prologue(&mut w, count)?;
        w.flush()?;
        l
    };
    std::fs::OpenOptions::new()
        .write(true)
        .open(arrow_path)?
        .set_len(layout.body_start + layout.body_total)?;

    // Per-chunk-stream read buffer CAP. It is a cap, not a size: a partition that
    // only holds a few MB gets a buffer sized to what it will actually read.
    //
    // This used to be a flat 16 MB read buffer per chunk stream and a flat 32 MB
    // BufWriter per output column — i.e. `n_threads × (n_chunks × 16 MB + 3 ×
    // 32 MB)`. On a 32-core box merging 2 chunks that is **4 GB of freshly
    // allocated, freshly page-faulted buffers to move 565 MB of records**, and the
    // fault storm is why this phase sat at ~4 of 32 cores while every worker was
    // otherwise idle: it was memory-bandwidth bound on its own scratch space, not
    // on the merge. Buffers are now sized to the partition.
    const IN_BUF_CAP: usize = 16 * 1024 * 1024;

    let cpath_strs: Vec<PathBuf> = chunk_paths.iter().map(|(p, _)| p.clone()).collect();
    let arrow_out: PathBuf = arrow_path.to_path_buf();

    // ROOT LAW #0: fan-out is gatling, not a hand-rolled `thread::scope` pool.
    // Partitions are disjoint slices of both the input chunks and the pre-sized
    // output file, so this is the `parwrite` shape — each unit merges its range
    // into exact-size staging buffers and lands them with ONE positional write
    // per column. LPT by partition record count so an uneven quantile split
    // cannot strand the tail on one core.
    let merge_errors: Vec<anyhow::Error> = gatling::gatling_forkjoin::gatling_for_each_balanced(
        n_threads,
        0,
        1,
        |t| part_counts[t] as u64,
        |t| -> Option<anyhow::Error> {
            use std::cmp::Reverse;
            use std::collections::BinaryHeap;
            use std::io::{BufReader, Read as _, Seek, SeekFrom};
            use std::os::unix::fs::FileExt;

            let my_rows = part_counts[t];
            if my_rows == 0 {
                return None;
            }

            // Open each non-empty chunk segment with its own BufReader, seeked to
            // [start). The buffer is sized to the bytes this partition will read
            // from that chunk (capped), not to a flat 16 MB.
            let mut readers: Vec<(BufReader<std::fs::File>, usize)> = Vec::new();
            for c in 0..n_chunks {
                let (start, end) = (chunk_part_starts[c][t], chunk_part_starts[c][t + 1]);
                if start >= end {
                    continue;
                }
                let f = match std::fs::File::open(&cpath_strs[c]) {
                    Ok(f) => f,
                    Err(e) => return Some(anyhow::anyhow!("open chunk {c}: {e}")),
                };
                let want = ((end - start) * RECORD_SIZE).clamp(64 * 1024, IN_BUF_CAP);
                let mut br = BufReader::with_capacity(want, f);
                if let Err(e) = br.seek(SeekFrom::Start((start * RECORD_SIZE) as u64)) {
                    return Some(e.into());
                }
                readers.push((br, end - start));
            }

            // Exact-size staging for this partition's three SoA column slices —
            // allocated once, at the size the merge will fill, never grown.
            let mut buf_id = Vec::<u8>::with_capacity(my_rows * 8);
            let mut buf_lat = Vec::<u8>::with_capacity(my_rows * 4);
            let mut buf_lon = Vec::<u8>::with_capacity(my_rows * 4);

            // Seed the heap with the first record from each active reader.
            let mut cur: Vec<[u8; RECORD_SIZE]> = vec![[0u8; RECORD_SIZE]; readers.len()];
            let mut heap: BinaryHeap<Reverse<(i64, usize)>> = BinaryHeap::new();
            for (i, (br, rem)) in readers.iter_mut().enumerate() {
                if let Err(e) = br.read_exact(&mut cur[i]) {
                    return Some(e.into());
                }
                let id = i64::from_le_bytes(cur[i][..8].try_into().unwrap());
                heap.push(Reverse((id, i)));
                *rem -= 1;
            }

            while let Some(Reverse((_, ri))) = heap.pop() {
                // Split the 16-byte AoS record into the 3 SoA columns.
                buf_id.extend_from_slice(&cur[ri][0..8]);
                buf_lat.extend_from_slice(&cur[ri][8..12]);
                buf_lon.extend_from_slice(&cur[ri][12..16]);
                if readers[ri].1 > 0 {
                    if let Err(e) = readers[ri].0.read_exact(&mut cur[ri]) {
                        return Some(e.into());
                    }
                    let next_id = i64::from_le_bytes(cur[ri][..8].try_into().unwrap());
                    heap.push(Reverse((next_id, ri)));
                    readers[ri].1 -= 1;
                }
            }

            // One positional write per column into this partition's disjoint slice
            // of the pre-sized file — the exact bytes, at the exact offsets, the
            // seeked BufWriters produced. No shared file offset, no ordering.
            let f = match std::fs::OpenOptions::new()
                .write(true)
                .open(&arrow_out)
                .with_context(|| format!("open {}", arrow_out.display()))
            {
                Ok(f) => f,
                Err(e) => return Some(e),
            };
            for (bytes, abs, width) in [
                (&buf_id, layout.id_abs, 8usize),
                (&buf_lat, layout.lat_abs, 4),
                (&buf_lon, layout.lon_abs, 4),
            ] {
                if let Err(e) = f.write_all_at(bytes, abs + (part_offsets[t] * width) as u64) {
                    return Some(e.into());
                }
            }
            None
        },
    )
    .into_iter()
    .flatten()
    .collect();

    if let Some(e) = merge_errors.into_iter().next() {
        return Err(e);
    }

    for (p, _) in chunk_paths {
        let _ = std::fs::remove_file(p);
    }

    // Append the IPC footer after the (now fully written) body.
    {
        use std::io::{Seek, SeekFrom};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(arrow_path)
            .with_context(|| format!("open {}", arrow_path.display()))?;
        f.seek(SeekFrom::Start(layout.body_start + layout.body_total))?;
        let mut w = std::io::BufWriter::new(f);
        crate::coords_ipc::write_epilogue(&mut w, &layout)?;
    }
    eprintln!(
        "  ext-sort merge done  ({count} records, {:.0}s)",
        t_merge.elapsed().as_secs_f64()
    );
    Ok(())
}

/// K-way merge pre-sorted chunk files into `out_path`, return a mmap-backed NodeStore.
/// Chunk files are deleted after the merge.  Single-chunk case: rename + mmap directly.
pub fn merge_sorted_chunks(
    chunk_paths: Vec<(PathBuf, usize)>,
    out_path: &Path,
    total_count: usize,
) -> Result<NodeStore> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    use std::io::{BufReader, Read as _, Seek, SeekFrom};

    if total_count == 0 {
        return Ok(NodeStore::new());
    }

    let n_chunks = chunk_paths.len();

    if n_chunks == 1 {
        let src = &chunk_paths[0].0;
        if src != out_path {
            if std::fs::rename(src, out_path).is_err() {
                std::fs::copy(src, out_path)?;
                let _ = std::fs::remove_file(src);
            }
        }
        let file = std::fs::File::open(out_path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let _ = std::fs::remove_file(out_path);
        return Ok(NodeStore::from_mmap(mmap, total_count));
    }

    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1);
    eprintln!("  merging {n_chunks} sorted chunks ({n_threads} parallel streams) …");
    let t_merge = std::time::Instant::now();

    let chunk_files_q: Vec<std::fs::File> = chunk_paths
        .iter()
        .map(|(p, _)| std::fs::File::open(p).with_context(|| format!("open {}", p.display())))
        .collect::<Result<_>>()?;
    let chunk_mmaps: Vec<Mmap> = chunk_files_q
        .iter()
        .map(|f| unsafe { MmapOptions::new().map(f) }.map_err(anyhow::Error::from))
        .collect::<Result<_>>()?;
    let chunk_counts: Vec<usize> = chunk_paths.iter().map(|(_, n)| *n).collect();

    let split_ids: Vec<i64> = (1..n_threads)
        .map(|t| {
            let target = (total_count as u128 * t as u128 / n_threads as u128) as usize;
            find_quantile(&chunk_mmaps, &chunk_counts, target)
        })
        .collect();

    let chunk_part_starts: Vec<Vec<usize>> = chunk_mmaps
        .iter()
        .zip(chunk_counts.iter())
        .map(|(mmap, &n)| {
            let mut starts = Vec::with_capacity(n_threads + 1);
            starts.push(0usize);
            for &id in &split_ids {
                starts.push(lb_id(mmap, n, id));
            }
            starts.push(n);
            starts
        })
        .collect();

    drop(chunk_mmaps);
    drop(chunk_files_q);

    let part_counts: Vec<usize> = (0..n_threads)
        .map(|t| {
            (0..n_chunks)
                .map(|c| chunk_part_starts[c][t + 1] - chunk_part_starts[c][t])
                .sum()
        })
        .collect();
    let part_offsets: Vec<usize> = {
        let mut off = vec![0usize; n_threads + 1];
        for t in 0..n_threads {
            off[t + 1] = off[t] + part_counts[t];
        }
        off
    };

    {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(out_path)?;
        f.set_len((total_count * RECORD_SIZE) as u64)?;
    }

    // Per-chunk-stream read buffer CAP (a cap, not a size — a partition that only
    // reads a few MB gets a buffer sized to what it will actually read; see the
    // same reasoning in `merge_sorted_chunks_to_arrow`).
    const IN_BUF_CAP: usize = 16 * 1024 * 1024;

    let cpath_strs: Vec<PathBuf> = chunk_paths.iter().map(|(p, _)| p.clone()).collect();
    let out_path_buf = out_path.to_path_buf();

    // ROOT LAW #0 (2026-07-22): was a hand-rolled `std::thread::scope` pool (the
    // comment above it even advertised the rayon→scope swap as if that settled
    // it — it does not; a scoped work pool IS the rayon replacement the law
    // forbids). Now `gatling_for_each_balanced` over the partitions, LPT-weighted
    // by partition record count so an uneven quantile split cannot leave the tail
    // on one core, with the same exact-size staging + single positional write the
    // Arrow-SoA sibling uses instead of a seeked 64 MB `BufWriter` per thread
    // doing one `write_all` per record.
    let merge_errors: Vec<anyhow::Error> = gatling::gatling_forkjoin::gatling_for_each_balanced(
        n_threads,
        0,
        1,
        |t| part_counts[t] as u64,
        |t| -> Option<anyhow::Error> {
            use std::os::unix::fs::FileExt;
            let my_rows = part_counts[t];
            if my_rows == 0 {
                return None;
            }
            let mut readers: Vec<(BufReader<std::fs::File>, usize)> = Vec::new();
            for c in 0..n_chunks {
                let (start, end) = (chunk_part_starts[c][t], chunk_part_starts[c][t + 1]);
                if start >= end {
                    continue;
                }
                let f = match std::fs::File::open(&cpath_strs[c]) {
                    Ok(f) => f,
                    Err(e) => return Some(anyhow::anyhow!("open chunk {c}: {e}")),
                };
                let want = ((end - start) * RECORD_SIZE).clamp(64 * 1024, IN_BUF_CAP);
                let mut br = BufReader::with_capacity(want, f);
                if let Err(e) = br.seek(SeekFrom::Start((start * RECORD_SIZE) as u64)) {
                    return Some(e.into());
                }
                readers.push((br, end - start));
            }

            // Exact-size staging for this partition's slice of the pre-sized file.
            let mut buf = Vec::<u8>::with_capacity(my_rows * RECORD_SIZE);

            let mut cur: Vec<[u8; RECORD_SIZE]> = vec![[0u8; RECORD_SIZE]; readers.len()];
            let mut heap: BinaryHeap<Reverse<(i64, usize)>> = BinaryHeap::new();
            for (i, (br, rem)) in readers.iter_mut().enumerate() {
                if let Err(e) = br.read_exact(&mut cur[i]) {
                    return Some(e.into());
                }
                let id = i64::from_le_bytes(cur[i][..8].try_into().unwrap());
                heap.push(Reverse((id, i)));
                *rem -= 1;
            }

            while let Some(Reverse((_, ri))) = heap.pop() {
                buf.extend_from_slice(&cur[ri]);
                if readers[ri].1 > 0 {
                    if let Err(e) = readers[ri].0.read_exact(&mut cur[ri]) {
                        return Some(e.into());
                    }
                    let next_id = i64::from_le_bytes(cur[ri][..8].try_into().unwrap());
                    heap.push(Reverse((next_id, ri)));
                    readers[ri].1 -= 1;
                }
            }

            // ONE positional write into this partition's disjoint slice — the
            // exact bytes, at the exact offset, the seeked BufWriter produced.
            let f = match std::fs::OpenOptions::new().write(true).open(&out_path_buf) {
                Ok(f) => f,
                Err(e) => return Some(e.into()),
            };
            f.write_all_at(&buf, (part_offsets[t] * RECORD_SIZE) as u64)
                .err()
                .map(Into::into)
        },
    )
    .into_iter()
    .flatten()
    .collect();

    if let Some(e) = merge_errors.into_iter().next() {
        return Err(e);
    }

    for (p, _) in &chunk_paths {
        let _ = std::fs::remove_file(p);
    }
    eprintln!(
        "  merge done  ({total_count} records, {:.0}s)",
        t_merge.elapsed().as_secs_f64()
    );

    let file = std::fs::File::open(out_path)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };
    let _ = std::fs::remove_file(out_path);
    Ok(NodeStore::from_mmap(mmap, total_count))
}

/// Find the smallest ID such that the global count of records with id ≤ that ID
/// is ≥ `target`.  Binary searches the i64 ID value space.
fn find_quantile(mmaps: &[Mmap], counts: &[usize], target: usize) -> i64 {
    let mut lo = i64::MIN;
    let mut hi = i64::MAX;
    while lo < hi {
        // Floor the midpoint toward `lo` (computed in i128 to avoid overflow of
        // `hi - lo`). Plain `(lo + hi) / 2` truncates toward zero, so for adjacent
        // negatives (`lo`, `hi = lo + 1`) it yields `mid == hi`; the `else` branch
        // then sets `hi = mid` with no progress → an infinite loop. This bites
        // whenever a quantile `target` is 0 (i.e. `count < n_threads`, tiny inputs
        // on a many-core box), where the search walks `hi` down into i64::MIN
        // territory. Flooring guarantees `lo <= mid < hi`, so both branches shrink.
        let mid = (lo as i128 + (hi as i128 - lo as i128) / 2) as i64;
        let cnt: usize = mmaps
            .iter()
            .zip(counts.iter())
            .map(|(m, &n)| ub_id(m.as_ref(), n, mid))
            .sum();
        if cnt < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Lower bound: first index in sorted chunk where id ≥ `key`.
#[inline]
fn lb_id(mmap: &[u8], count: usize, key: i64) -> usize {
    let (mut lo, mut hi) = (0usize, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if id_at(mmap, mid) < key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Upper bound: first index where id > `key` (= count of records with id ≤ key).
#[inline]
fn ub_id(mmap: &[u8], count: usize, key: i64) -> usize {
    let (mut lo, mut hi) = (0usize, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if id_at(mmap, mid) <= key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

#[inline]
fn id_at(mmap: &[u8], idx: usize) -> i64 {
    i64::from_le_bytes(
        mmap[idx * RECORD_SIZE..idx * RECORD_SIZE + 8]
            .try_into()
            .unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: `find_quantile` must terminate when a quantile target is 0,
    /// which happens whenever the record count is smaller than the merge stream
    /// count (tiny inputs on a many-core box). The old truncate-toward-zero
    /// midpoint spun forever on adjacent negative bounds (`lo`, `hi = lo + 1`
    /// gave `mid == hi`, and `hi = mid` made no progress) — this DEADLOCKED
    /// `convert` on small fixtures (e.g. a 3-node clip test on a 12-core host).
    #[test]
    fn find_quantile_terminates_on_zero_and_small_targets() {
        let ids: [i64; 3] = [1_000_000_001, 1_000_000_050, 2_000_000_000];
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("chunk.bin");
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&path).unwrap();
            for &id in &ids {
                let mut rec = [0u8; RECORD_SIZE];
                rec[..8].copy_from_slice(&id.to_le_bytes());
                f.write_all(&rec).unwrap();
            }
            f.flush().unwrap();
        }
        let file = std::fs::File::open(&path).unwrap();
        let mmap = unsafe { MmapOptions::new().map(&file).unwrap() };
        let mmaps = vec![mmap];
        let counts = vec![ids.len()];

        // target == 0 previously hung. Sweep 0..=count; each call must return,
        // and the returned threshold id must be a valid quantile boundary.
        let mut prev = i64::MIN;
        for target in 0..=ids.len() {
            let q = find_quantile(&mmaps, &counts, target);
            assert!(
                q >= prev,
                "quantile must be monotonic: target={target} q={q} prev={prev}"
            );
            prev = q;
            let cnt_at_q = ub_id(mmaps[0].as_ref(), counts[0], q);
            assert!(
                cnt_at_q >= target,
                "target={target} q={q} cnt_at_q={cnt_at_q}"
            );
        }
    }

    /// Smoke test that the fast-path sorter (now `znippy_zoomies::psort`) is
    /// correctly wired and sorts node-coord records by id. Exhaustive sort
    /// correctness lives in the `psort` crate's own test suite.
    #[test]
    fn samplesort_fast_path_sorts_by_id() {
        let n = 100_000;
        let mut records: Vec<[u8; RECORD_SIZE]> = (0..n)
            .map(|i| {
                let id = ((i as u64).wrapping_mul(0x9E3779B97F4A7C15) % (1u64 << 50)) as i64 + 1;
                let mut rec = [0u8; RECORD_SIZE];
                rec[..8].copy_from_slice(&id.to_le_bytes());
                rec[8..12].copy_from_slice(&(i as f32).to_le_bytes());
                rec
            })
            .collect();
        let mut expected = records.clone();
        expected.sort_unstable_by_key(|r| i64::from_le_bytes(r[..8].try_into().unwrap()));
        samplesort_aos_by_i64_key(&mut records);
        assert_eq!(records, expected);
    }

    /// RED-WHEN-BROKEN cross-path oracle: the in-RAM **fast path** and the forced
    /// **multi-chunk merge** path must emit a BYTE-IDENTICAL `node_coords.arrow`
    /// for the same input. They share `coords_ipc::write_prologue`/`write_epilogue`
    /// and both lay their body into the same pre-sized regions, so any divergence
    /// — a changed offset, a partial write, a dropped record, a scheduling-order
    /// leak — shows up here as a byte diff, with no golden hash to go stale.
    ///
    /// This is what pins the 2026-07-22 gatling conversion of the fast path's
    /// mmap→Vec copy and its three-column body writer: both now stage exact-size
    /// buffers and land them with one positional `write_all_at` per column, and
    /// the multi-chunk sibling (converted separately) is the independent witness.
    #[test]
    fn fast_path_and_merge_path_produce_identical_arrow_bytes() {
        let n = 200_000usize;
        let tmp = tempfile::tempdir().expect("tempdir");
        let aos = tmp.path().join("aos.bin");
        {
            let mut f = std::io::BufWriter::new(std::fs::File::create(&aos).expect("create aos"));
            for i in 0..n {
                let id = (((i as u64).wrapping_mul(2654435761) % n as u64) as i64) + 1_000_000;
                let lat = f32::from_bits(((id as u64) & 0xffffffff) as u32);
                let lon = f32::from_bits(((id as u64 >> 32) & 0xffffffff) as u32);
                f.write_all(&id.to_le_bytes()).unwrap();
                f.write_all(&lat.to_le_bytes()).unwrap();
                f.write_all(&lon.to_le_bytes()).unwrap();
            }
            f.flush().unwrap();
        }

        let fast = tmp.path().join("fast.arrow");
        let merged = tmp.path().join("merged.arrow");
        external_merge_sort_inner(&aos, n, &fast, usize::MAX).expect("fast path");
        external_merge_sort_inner(&aos, n, &merged, 70_000).expect("merge path");

        let a = std::fs::read(&fast).expect("read fast");
        let b = std::fs::read(&merged).expect("read merged");
        assert_eq!(a.len(), b.len(), "fast/merge arrow files differ in LENGTH");
        assert!(
            a == b,
            "fast path and multi-chunk merge produced different node_coords.arrow bytes"
        );

        // Re-running the fast path must reproduce the same bytes (no
        // scheduling-order dependence in the parallel copy or the body writer).
        let fast2 = tmp.path().join("fast2.arrow");
        external_merge_sort_inner(&aos, n, &fast2, usize::MAX).expect("fast path rerun");
        assert!(
            std::fs::read(&fast2).expect("read fast2") == a,
            "fast path is not reproducible run-to-run"
        );
    }

    /// Build an unsorted AoS file with `n` synthetic (id, lat, lon) records,
    /// write the single-batch Arrow IPC file via both the fast path and the
    /// forced multi-chunk merge path, and verify the zero-copy reader recovers
    /// every record sorted, complete, and pairwise consistent. Also confirms
    /// arrow-rs's own FileReader accepts our hand-laid file (interop proxy for
    /// pyarrow/DuckDB). Exercises PR 2c without a planet-sized input.
    #[test]
    fn external_merge_sort_writes_single_batch_arrow() {
        for (label, chunk_records, n) in [
            ("fast_path", usize::MAX, 200_000usize),
            ("merge_3chunk", 70_000usize, 200_000usize),
            ("merge_uneven", 64usize, 1000usize),
        ] {
            let tmp = tempfile::tempdir().expect("tempdir");
            let aos = tmp.path().join("aos.bin");
            let arrow = tmp.path().join("node_coords.arrow");

            // Pseudo-shuffled IDs; lat/lon encode the id so pairing survives.
            {
                let mut f =
                    std::io::BufWriter::new(std::fs::File::create(&aos).expect("create aos"));
                for i in 0..n {
                    let id = (((i as u64).wrapping_mul(2654435761) % n as u64) as i64) + 1_000_000;
                    let lat = f32::from_bits(((id as u64) & 0xffffffff) as u32);
                    let lon = f32::from_bits(((id as u64 >> 32) & 0xffffffff) as u32);
                    f.write_all(&id.to_le_bytes()).unwrap();
                    f.write_all(&lat.to_le_bytes()).unwrap();
                    f.write_all(&lon.to_le_bytes()).unwrap();
                }
                f.flush().unwrap();
            }

            external_merge_sort_inner(&aos, n, &arrow, chunk_records)
                .unwrap_or_else(|e| panic!("[{label}] external_merge_sort: {e:?}"));

            // 1) Zero-copy reader recovers everything, sorted + paired.
            let mc = crate::coords_ipc::open_mmap(&arrow)
                .unwrap_or_else(|e| panic!("[{label}] open_mmap: {e:?}"));
            assert_eq!(mc.count, n, "[{label}] count");
            let bytes = mc.mmap.as_ref();
            let mut prev: i64 = i64::MIN;
            for i in 0..n {
                let id = i64::from_le_bytes(
                    bytes[mc.id_off + i * 8..mc.id_off + i * 8 + 8]
                        .try_into()
                        .unwrap(),
                );
                let lat = f32::from_le_bytes(
                    bytes[mc.lat_off + i * 4..mc.lat_off + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                );
                let lon = f32::from_le_bytes(
                    bytes[mc.lon_off + i * 4..mc.lon_off + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                );
                assert!(
                    id >= prev,
                    "[{label}] ids not sorted at {i}: prev={prev} cur={id}"
                );
                assert_eq!(
                    lat.to_bits(),
                    f32::from_bits(((id as u64) & 0xffffffff) as u32).to_bits(),
                    "[{label}] lat mismatch id {id}"
                );
                assert_eq!(
                    lon.to_bits(),
                    f32::from_bits(((id as u64 >> 32) & 0xffffffff) as u32).to_bits(),
                    "[{label}] lon mismatch id {id}"
                );
                prev = id;
            }

            // 2) arrow-rs FileReader (reference impl) reads our hand-laid file.
            let f = std::fs::File::open(&arrow).unwrap();
            let reader = arrow::ipc::reader::FileReader::try_new(f, None).unwrap_or_else(|e| {
                panic!("[{label}] arrow-rs FileReader rejected our file: {e:?}")
            });
            let total: usize = reader.map(|b| b.expect("batch").num_rows()).sum();
            assert_eq!(total, n, "[{label}] arrow-rs row count");
        }
    }

    /// REGRESSION FIX 2026-06-17 (streaming parallel sort): drive the PUBLIC
    /// `external_merge_sort` entry — i.e. through the real `adaptive_chunk_records`
    /// routing — twice via `external_merge_sort_inner` with a SMALL forced chunk
    /// so the input genuinely exceeds one chunk (`n_chunks > 1`), exercising the
    /// RAM-bounded parallel k-way-merge path end to end. Feeds an UNSORTED set of
    /// (id, lat, lon) records, then asserts the output Arrow IPC is FULLY SORTED
    /// by id AND every coord is preserved and correctly paired with its id (the
    /// inject-assert contract: real input → real asserted output). This is the
    /// path the planet/europe convert takes; the previous regression bypassed it
    /// entirely by collapsing onto the serial single-shot path.
    #[test]
    fn streaming_multi_chunk_sort_is_sorted_and_lossless() {
        // > chunk-size: 250 K records across a 60 K chunk → 5 chunks (n_chunks=5).
        let n: usize = 250_000;
        let chunk_records: usize = 60_000;
        assert!(
            n.div_ceil(chunk_records) > 1,
            "test must force the multi-chunk path"
        );

        let tmp = tempfile::tempdir().expect("tempdir");
        let aos = tmp.path().join("aos.bin");
        let arrow = tmp.path().join("node_coords.arrow");

        // Unsorted, deterministic shuffle; lat/lon encode id so pairing is checked.
        // The expected (id -> (lat, lon)) map lets us assert losslessness.
        let mut expected: std::collections::HashMap<i64, (u32, u32)> =
            std::collections::HashMap::with_capacity(n);
        {
            let mut f = std::io::BufWriter::new(std::fs::File::create(&aos).expect("create aos"));
            for i in 0..n {
                // Pseudo-random unique-ish ids spread across the i64 space,
                // guaranteed unique by adding the index.
                let id = (((i as u64).wrapping_mul(0x9E3779B97F4A7C15) >> 12) as i64)
                    .wrapping_add(i as i64)
                    | 1;
                let lat_bits = (id as u64 & 0xffff_ffff) as u32;
                let lon_bits = ((id as u64 >> 32) & 0xffff_ffff) as u32;
                expected.insert(id, (lat_bits, lon_bits));
                f.write_all(&id.to_le_bytes()).unwrap();
                f.write_all(&f32::from_bits(lat_bits).to_le_bytes())
                    .unwrap();
                f.write_all(&f32::from_bits(lon_bits).to_le_bytes())
                    .unwrap();
            }
            f.flush().unwrap();
        }
        let unique = expected.len();

        external_merge_sort_inner(&aos, n, &arrow, chunk_records)
            .expect("external_merge_sort_inner (multi-chunk)");

        let mc = crate::coords_ipc::open_mmap(&arrow).expect("open_mmap");
        assert_eq!(mc.count, n, "record count preserved");
        let bytes = mc.mmap.as_ref();
        let mut prev = i64::MIN;
        let mut seen = std::collections::HashSet::with_capacity(unique);
        for i in 0..n {
            let id = i64::from_le_bytes(
                bytes[mc.id_off + i * 8..mc.id_off + i * 8 + 8]
                    .try_into()
                    .unwrap(),
            );
            let lat = u32::from_le_bytes(
                bytes[mc.lat_off + i * 4..mc.lat_off + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            let lon = u32::from_le_bytes(
                bytes[mc.lon_off + i * 4..mc.lon_off + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            assert!(id >= prev, "ids not sorted at {i}: prev={prev} cur={id}");
            let &(elat, elon) = expected
                .get(&id)
                .unwrap_or_else(|| panic!("unexpected id {id} in output"));
            assert_eq!(lat, elat, "lat mismatch for id {id}");
            assert_eq!(lon, elon, "lon mismatch for id {id}");
            seen.insert(id);
            prev = id;
        }
        assert_eq!(
            seen.len(),
            unique,
            "every input id must appear in the sorted output"
        );
    }

    /// REGRESSION FIX 2026-06-17: routing is RAM-bounded, NOT RAM-greedy. The
    /// chunk size that decides single-shot vs multi-chunk must bound peak RSS by
    /// a FIXED budget (`SORT_CHUNK_RECORDS`), regardless of how much RAM is free
    /// — otherwise a 499 GB box collapses every real input onto the (previously
    /// serial) single-shot path. Big inputs must ALWAYS chunk; only inputs that
    /// already fit the fixed per-chunk budget take single-shot.
    #[test]
    fn adaptive_chunk_records_is_ram_bounded_not_ram_greedy() {
        let gb = 1024usize * 1024 * 1024;
        // planet-scale: 10.5 B records ≈ 168 GB.
        let planet = 10_500_000_000usize;

        // Even on a 499 GB box (this machine), planet must CHUNK, not single-shot.
        assert_eq!(
            adaptive_chunk_records(planet, 499 * gb),
            SORT_CHUNK_RECORDS,
            "planet must chunk even with 499 GB free (RAM-bounded routing)",
        );
        // And on a small box, obviously chunk.
        assert_eq!(adaptive_chunk_records(planet, 32 * gb), SORT_CHUNK_RECORDS);

        // europe-scale (~3.7 B records) must also chunk regardless of free RAM.
        let europe = 3_700_000_000usize;
        assert_eq!(adaptive_chunk_records(europe, 499 * gb), SORT_CHUNK_RECORDS);

        // Exactly at the budget: single-shot (chunk == count).
        assert_eq!(
            adaptive_chunk_records(SORT_CHUNK_RECORDS, 8 * gb),
            SORT_CHUNK_RECORDS,
            "count == budget stays single-shot",
        );
        // One over the budget: must chunk.
        assert_eq!(
            adaptive_chunk_records(SORT_CHUNK_RECORDS + 1, 499 * gb),
            SORT_CHUNK_RECORDS,
            "one record over the budget must chunk, even with 499 GB free",
        );

        // sweden-scale (~104 M records) is under the budget → single-shot
        // (chunk >= count), but the single-shot path is now itself parallel.
        let sweden = 104_326_671usize;
        assert!(
            adaptive_chunk_records(sweden, 499 * gb) >= sweden,
            "sweden (under budget) takes the parallel single-shot path",
        );
        // Free-RAM independence: the decision does not depend on avail_bytes.
        assert_eq!(
            adaptive_chunk_records(sweden, gb),
            adaptive_chunk_records(sweden, 499 * gb),
            "routing must be independent of free RAM",
        );
    }
}
