//! VTD-style index for OSM XML files — the OSM specialization of the generic
//! parallel XML scanner in [`crate::xml`].
//!
//! This module owns everything OSM-shaped: `ElemKind`, the node/way/relation
//! tag table, lat/lon e7 coordinate parsing, tag-flag extraction, the mmap'd
//! `ElemIndex` store and its zone-map summaries. The scanning machinery itself
//! (SIMD forward scan, safe split points, the parallel rendezvous) lives in
//! [`crate::xml`] and is shared with any other element vocabulary.
//!
//! Pass 1: SIMD forward scan over a mmap'd OSM XML file.
//!         Emits one `ElemIndex` entry per top-level element (node/way/relation).
//!         Populates the node store inline — no second read of node bytes needed.
//!
//! Pass 2: filter `ElemIndex` by kind/bbox/tag_flags, seek to matching byte
//!         offsets, parse only those elements. Skips ~85% of planet file (nodes).
//!
//! The ElemIndex array is sorted by file_offset (forward scan order) and
//! written to a mmap'd output file. The OS page cache handles RAM vs NVMe
//! transparently — same code for Sweden (2 GB) and planet (1 TB).

use std::{
    fs::{File, OpenOptions},
    path::Path,
    sync::LazyLock,
};

use anyhow::{Context as _, Result};
use memchr::memchr;
use memmap2::{Mmap, MmapMut, MmapOptions};

use crate::xml::{self, ElemSpan, TagSet, next_close, next_open};

// Byte-level attr parsers are generic — re-exported so existing
// `vtd::find_attr` / `vtd::parse_i64` call sites keep working unchanged.
pub use crate::xml::{find_attr, parse_i64};

// ── Element kinds ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ElemKind {
    Node = 0,
    Way = 1,
    Relation = 2,
}

impl ElemKind {
    /// Inverse of `kind as u8` — only ever fed kind ids from `OSM_TAGS`.
    #[inline]
    fn from_u8(kind: u8) -> Self {
        match kind {
            0 => ElemKind::Node,
            1 => ElemKind::Way,
            2 => ElemKind::Relation,
            _ => unreachable!("kind id not in OSM tag table"),
        }
    }
}

// ── OSM tag tables (the specialization fed to the generic scanner) ───────────

/// Indexed top-level elements: the scanner's vocabulary.
static OSM_TAGS: LazyLock<TagSet> = LazyLock::new(|| {
    TagSet::new(&[
        (b"node".as_slice(), ElemKind::Node as u8),
        (b"way".as_slice(), ElemKind::Way as u8),
        (b"relation".as_slice(), ElemKind::Relation as u8),
    ])
});

/// Slot-boundary vocabulary for `find_safe_slot_end` — wider than the indexed
/// set: `<changeset>` closes with a full tag, while `<bound>` / `<note>` only
/// occur self-closing in OSM streams. Kind ids are unused here.
static BOUNDARY_PAIRED: LazyLock<TagSet> = LazyLock::new(|| {
    TagSet::new(&[
        (b"node".as_slice(), 0),
        (b"way".as_slice(), 0),
        (b"relation".as_slice(), 0),
        (b"changeset".as_slice(), 0),
    ])
});

static BOUNDARY_SELF_CLOSING: LazyLock<TagSet> = LazyLock::new(|| {
    TagSet::new(&[
        (b"node".as_slice(), 0),
        (b"way".as_slice(), 0),
        (b"relation".as_slice(), 0),
        (b"changeset".as_slice(), 0),
        (b"bound".as_slice(), 0),
        (b"note".as_slice(), 0),
    ])
});

// ── Tag flag bitmask (extendable) ────────────────────────────────────────────

pub mod tag_flags {
    pub const HIGHWAY: u32 = 1 << 0;
    pub const BUILDING: u32 = 1 << 1;
    pub const NATURAL: u32 = 1 << 2;
    pub const LANDUSE: u32 = 1 << 3;
    pub const WATERWAY: u32 = 1 << 4;
    pub const RAILWAY: u32 = 1 << 5;
    pub const AMENITY: u32 = 1 << 6;
    pub const BOUNDARY: u32 = 1 << 7;
}

// ── ElemIndex entry ───────────────────────────────────────────────────────────

/// One entry per top-level OSM element. 32 bytes, cache-line friendly in bulk.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ElemIndex {
    /// Byte offset of the element's opening `<` in the mmap'd file.
    pub file_offset: u64,
    /// Byte length of the complete element (opening tag through closing tag).
    pub file_length: u32,
    pub kind: ElemKind,
    pub _pad: [u8; 3],
    pub id: i64,
    /// Latitude in degrees × 1e7 as i32 (nodes only, else 0).
    pub lat_e7: i32,
    /// Longitude in degrees × 1e7 as i32 (nodes only, else 0).
    pub lon_e7: i32,
    /// Bitmask of notable tags present in this element.
    pub tag_flags: u32,
}

// ── Mmap helpers ─────────────────────────────────────────────────────────────

/// Open a file read-only and mmap it. Returns the Mmap (keep alive alongside slice).
pub fn mmap_input(path: &Path) -> Result<Mmap> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    // SAFETY: we hold the File open for the lifetime of the Mmap.
    let mmap = unsafe { MmapOptions::new().map(&file) }
        .with_context(|| format!("cannot mmap {}", path.display()))?;
    Ok(mmap)
}

/// Create / truncate an output file and mmap it read-write at `capacity` bytes.
pub fn mmap_output(path: &Path, capacity: usize) -> Result<MmapMut> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.set_len(capacity as u64)
        .context("cannot pre-allocate ElemIndex file")?;
    // SAFETY: we hold the File open for the lifetime of the MmapMut.
    let mmap = unsafe { MmapOptions::new().map_mut(&file) }
        .with_context(|| format!("cannot mmap output {}", path.display()))?;
    Ok(mmap)
}

// ── OSM attribute parsing ─────────────────────────────────────────────────────

/// Parse a decimal float (lat/lon) × 1e7 as i32 from ASCII bytes.
/// Avoids any float parsing — works directly on the digit string.
fn parse_coord_e7(bytes: &[u8]) -> i32 {
    // e.g. b"59.3293" → 59_329_300i32
    let (neg, digits) = match bytes.first() {
        Some(&b'-') => (true, &bytes[1..]),
        _ => (false, bytes),
    };
    let dot = memchr(b'.', digits).unwrap_or(digits.len());
    let int_part = &digits[..dot];
    let frac_part = if dot < digits.len() {
        &digits[dot + 1..]
    } else {
        b""
    };

    let mut val: i64 = 0;
    for &b in int_part {
        if b.is_ascii_digit() {
            val = val * 10 + (b - b'0') as i64;
        }
    }
    val *= 10_000_000; // scale to e7

    let mut frac: i64 = 0;
    let mut scale: i64 = 1_000_000; // first decimal = 1_000_000 out of 10_000_000
    for &b in frac_part {
        if b.is_ascii_digit() && scale > 0 {
            frac += (b - b'0') as i64 * scale;
            scale /= 10;
        }
    }
    let result = (val + frac) as i32;
    if neg { -result } else { result }
}

// ── Tag flag detection ────────────────────────────────────────────────────────

fn tag_flag_for(key: &[u8]) -> u32 {
    match key {
        b"highway" => tag_flags::HIGHWAY,
        b"building" => tag_flags::BUILDING,
        b"natural" => tag_flags::NATURAL,
        b"landuse" => tag_flags::LANDUSE,
        b"waterway" => tag_flags::WATERWAY,
        b"railway" => tag_flags::RAILWAY,
        b"amenity" => tag_flags::AMENITY,
        b"boundary" => tag_flags::BOUNDARY,
        _ => 0,
    }
}

// ── Pass 1: build ElemIndex ───────────────────────────────────────────────────

/// Scan forward from `from` to the start of the next top-level OSM element
/// (`<node`, `<way`, `<relation`). Returns the byte offset of the `<`.
/// Returns `bytes.len()` if none is found.
pub fn find_top_level_start(bytes: &[u8], from: usize) -> usize {
    xml::find_top_level_start(bytes, from, &OSM_TAGS)
}

/// Decode one scanned element span into an `ElemIndex`: id/lat/lon from the
/// start tag, tag_flags from `<tag k=…/>` children. Runs on the scanning
/// thread (parallel variants decode in parallel), zero-copy over `slice`.
fn elem_index_from_span(slice: &[u8], base: usize, kind: u8, span: ElemSpan) -> ElemIndex {
    let rel = span.offset as usize - base;
    let kind = ElemKind::from_u8(kind);

    let raw_tag = &slice[rel + 1..rel + 1 + span.tag_len as usize];
    let tag = if span.self_closing {
        &raw_tag[..raw_tag.len() - 1]
    } else {
        raw_tag
    };

    let id = find_attr(tag, b"id").map(parse_i64).unwrap_or(0);
    let lat_e7 = find_attr(tag, b"lat").map(parse_coord_e7).unwrap_or(0);
    let lon_e7 = find_attr(tag, b"lon").map(parse_coord_e7).unwrap_or(0);

    let tag_flags = if span.self_closing {
        0u32
    } else {
        // Walk `<tag k=…/>` children until the element's own closing tag.
        let close_pos = rel + 1 + span.tag_len as usize; // the start tag's '>'
        let mut flags = 0u32;
        let mut inner = close_pos + 1;

        loop {
            let child_open = match next_open(slice, inner) {
                Some(p) => p,
                None => break,
            };
            let child_tag_start = child_open + 1;
            let child_close = match next_close(slice, child_tag_start) {
                Some(p) => p,
                None => break,
            };
            let child_tag = &slice[child_tag_start..child_close];
            if child_tag.starts_with(b"/") {
                break;
            }

            let child_name_end = memchr(b' ', child_tag).unwrap_or(child_tag.len());
            if &child_tag[..child_name_end] == b"tag" {
                if let Some(key) = find_attr(child_tag, b"k") {
                    flags |= tag_flag_for(key);
                }
            }
            inner = child_close + 1;
        }
        flags
    };

    ElemIndex {
        file_offset: span.offset,
        file_length: span.len,
        kind,
        _pad: [0; 3],
        id,
        lat_e7,
        lon_e7,
        tag_flags,
    }
}

/// Core scanner: emit one `ElemIndex` per top-level OSM element in `slice`.
/// `base` is added to every `file_offset` so entries carry absolute positions
/// into the original mmap'd file (not positions within the slice).
pub fn build_elem_index_slice(
    slice: &[u8],
    base: usize,
    on_elem: &mut impl FnMut(ElemIndex),
) -> u64 {
    xml::scan_slice(slice, base, &OSM_TAGS, &mut |kind, span| {
        on_elem(elem_index_from_span(slice, base, kind, span));
    })
}

/// Single-threaded scan. Kept for tests and small files.
pub fn build_elem_index<F>(bytes: &[u8], mut on_elem: F) -> Result<u64>
where
    F: FnMut(ElemIndex),
{
    Ok(build_elem_index_slice(bytes, 0, &mut on_elem))
}

/// Parallel scan: divides the mmap'd file into `n_workers` ranges via the
/// generic rendezvous engine ([`xml::scan_parallel`]) — candidate offsets +
/// forward seek, no barrier. Per-element decoding (`ElemIndex` construction)
/// runs on the worker threads; results are merged in file order and fed to
/// `on_elem` on the calling thread.
pub fn build_elem_index_parallel<F>(bytes: &[u8], n_workers: usize, mut on_elem: F) -> Result<u64>
where
    F: FnMut(ElemIndex),
{
    xml::scan_parallel(
        bytes,
        n_workers,
        &OSM_TAGS,
        |kind, span| elem_index_from_span(bytes, 0, kind, span),
        |e| on_elem(e),
    )
}

// ── Mmap streaming index ─────────────────────────────────────────────────────

/// Count top-level OSM elements in `slice` without full parsing.
/// Scans for `<node `, `<way `, `<relation ` — these byte sequences only
/// appear as top-level element starts in valid OSM XML (tag values containing
/// `<` must be escaped as `&lt;`). ~10× faster than a full parse.
pub fn count_elements(slice: &[u8]) -> usize {
    xml::count_elements(slice, &OSM_TAGS)
}

/// Cast a mmap written by `build_elem_index_to_mmap` back to a typed slice.
/// The mmap must be page-aligned (guaranteed by the OS) and its length must
/// be a multiple of `size_of::<ElemIndex>()`.
pub fn as_elem_index(mmap: &Mmap) -> &[ElemIndex] {
    let bytes = mmap.as_ref();
    let elem_size = std::mem::size_of::<ElemIndex>();
    assert_eq!(
        bytes.len() % elem_size,
        0,
        "mmap length not aligned to ElemIndex"
    );
    // SAFETY: ElemIndex is repr(C) + Copy. Mmap is page-aligned (4096 B) which
    // is ≥ align_of::<ElemIndex>() (8 B). Length and origin are both controlled
    // by this module.
    unsafe {
        std::slice::from_raw_parts(bytes.as_ptr() as *const ElemIndex, bytes.len() / elem_size)
    }
}

/// Planet-scale parallel scan: writes the ElemIndex directly to a mmap'd file
/// without ever accumulating the full index in RAM.
///
/// Two scopes, N threads each (N = n_workers):
///
/// **Scope 1 — rendezvous + count** (same AtomicU64 rendezvous as
/// `build_elem_index_parallel`):
///   Thread i posts its actual_start to `actual_slots[i]`.
///   Thread i spins on `actual_slots[i+1]` to learn its actual_end.
///   Then counts elements in `[actual_start, actual_end)` and posts the count.
///   All N threads run concurrently; the spin waits are ~microseconds since
///   every thread posts its start immediately after one memchr scan.
///
/// After scope 1: prefix-sum the counts → allocate the mmap at the exact size.
///
/// **Scope 2 — parse + write**:
///   Each thread knows its write offset from the prefix sum.
///   Writes each `ElemIndex` entry directly to its exclusive mmap region.
///   Zero Vec accumulation — the index lives only in the OS page cache.
///
/// Peak extra RAM: `2 × n_workers × sizeof(AtomicU64)` for the slot arrays.
pub fn build_elem_index_to_mmap(bytes: &[u8], n_workers: usize, idx_path: &Path) -> Result<u64> {
    use std::sync::atomic::{AtomicU64, Ordering};

    let n = n_workers.max(1);
    let chunk_size = (bytes.len() / n).max(1);
    const SENTINEL: u64 = u64::MAX;

    // actual_slots[i] = actual_start of chunk i (thread i posts, thread i-1 reads).
    let actual_slots: Vec<AtomicU64> = (0..n).map(|_| AtomicU64::new(SENTINEL)).collect();
    // count_slots[i]  = element count of chunk i (posted after counting).
    let count_slots: Vec<AtomicU64> = (0..n).map(|_| AtomicU64::new(SENTINEL)).collect();

    // ── Scope 1: rendezvous + count ──────────────────────────────────────────
    std::thread::scope(|s| {
        (0..n)
            .map(|i| {
                let bytes = bytes;
                let actual_slots = &actual_slots[..];
                let count_slots = &count_slots[..];
                s.spawn(move || {
                    // Find and immediately post own actual_start.
                    let actual_start = find_top_level_start(bytes, i * chunk_size);
                    actual_slots[i].store(actual_start as u64, Ordering::Release);

                    // Spin on the next chunk's slot to learn our actual_end.
                    // The next thread posts nearly instantly (one memchr scan).
                    let actual_end = if i + 1 == n {
                        bytes.len()
                    } else {
                        loop {
                            let v = actual_slots[i + 1].load(Ordering::Acquire);
                            if v != SENTINEL {
                                break v as usize;
                            }
                            std::hint::spin_loop();
                        }
                    };

                    let count = count_elements(&bytes[actual_start..actual_end]);
                    count_slots[i].store(count as u64, Ordering::Release);
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|h| h.join().expect("rendezvous+count thread panicked"));
    });

    // All threads done — relaxed loads are fine.
    let actual_starts: Vec<usize> = actual_slots
        .iter()
        .map(|a| a.load(Ordering::Relaxed) as usize)
        .collect();
    let counts: Vec<usize> = count_slots
        .iter()
        .map(|a| a.load(Ordering::Relaxed) as usize)
        .collect();

    // Prefix-sum → per-chunk write offsets → exact mmap size.
    let mut write_offsets = vec![0usize; n];
    for i in 1..n {
        write_offsets[i] = write_offsets[i - 1] + counts[i - 1];
    }
    let total = write_offsets[n - 1] + counts[n - 1];
    let capacity = total * std::mem::size_of::<ElemIndex>();

    let mut idx_mmap = mmap_output(idx_path, capacity)?;
    let mmap_ptr: usize = idx_mmap.as_mut_ptr() as usize; // usize is Send

    // ── Scope 2: parse + write directly to mmap ──────────────────────────────
    std::thread::scope(|s| {
        (0..n)
            .map(|i| {
                let bytes = bytes;
                let actual_start = actual_starts[i];
                let actual_end = if i + 1 < n {
                    actual_starts[i + 1]
                } else {
                    bytes.len()
                };
                let write_offset = write_offsets[i];
                let expected = counts[i];
                s.spawn(move || {
                    let mut idx = 0usize;
                    build_elem_index_slice(
                        &bytes[actual_start..actual_end],
                        actual_start,
                        &mut |e| {
                            // SAFETY: [write_offset, write_offset + expected) is
                            // exclusive to this thread — guaranteed by prefix sum.
                            // The mmap pointer is valid for the scope's duration.
                            unsafe {
                                std::ptr::write(
                                    (mmap_ptr as *mut ElemIndex).add(write_offset + idx),
                                    e,
                                );
                            }
                            idx += 1;
                        },
                    );
                    debug_assert_eq!(
                        idx, expected,
                        "chunk {i}: counted {expected} but parsed {idx}"
                    );
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|h| h.join().expect("parse+write thread panicked"));
    });

    idx_mmap.flush().context("flushing ElemIndex mmap")?;
    Ok(total as u64)
}

// ── ChunkRevolver: no-barrier parallel mmap writer ───────────────────────────

/// True revolver: threads parse freely into a local Vec, then commit in file
/// order via a `next_to_commit` counter. No barrier between chunks — a thread
/// that finishes early immediately picks up the next chunk.
///
/// Output is in file order (required by pass 2). The ordered-commit spin is
/// brief because chunks of similar size finish close together.
/// Workers parse freely and send `(chunk_index, vec)` over an mpsc channel.
/// A single committer thread drains the channel in file order using a BTreeMap
/// and writes each run directly to the mmap — writes overlap parsing.
///
/// Workers never wait on each other. The committer's BTreeMap holds at most
/// `n_workers` entries (one per in-flight chunk). Peak RAM:
/// `n_workers × chunk_bytes / compression_ratio`, where chunk_bytes ≈ file/n_chunks.
pub fn build_elem_index_revolver(bytes: &[u8], n_workers: usize, idx_path: &Path) -> Result<u64> {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    let n = n_workers.max(1);
    let n_chunks = n * 5 / 4; // +25% over-provision keeps cores busy during commits
    let chunk_size = (bytes.len() / n_chunks).max(1);

    // Pre-compute boundaries once on the calling thread (cheap: n_chunks memchr scans).
    let mut boundaries: Vec<usize> = Vec::with_capacity(n_chunks + 1);
    for i in 0..n_chunks {
        boundaries.push(find_top_level_start(bytes, i * chunk_size));
    }
    boundaries.push(bytes.len());
    let boundaries = Arc::new(boundaries);

    // Count elements in parallel over the pre-computed chunks — no extra sequential scan.
    let counts: Vec<usize> = {
        let b = &*boundaries;
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..n_chunks)
                .map(|i| s.spawn(move || count_elements(&bytes[b[i]..b[i + 1]])))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("count thread panicked"))
                .collect()
        })
    };
    let total = counts.iter().sum::<usize>();
    let capacity = (total + 1) * std::mem::size_of::<ElemIndex>();
    let mut idx_mmap = mmap_output(idx_path, capacity)?;
    let mmap_ptr: usize = idx_mmap.as_mut_ptr() as usize;

    let next_chunk = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel::<(usize, Vec<ElemIndex>)>();

    std::thread::scope(|s| {
        // ── Worker threads ────────────────────────────────────────────────────
        for _ in 0..n {
            let next_chunk = Arc::clone(&next_chunk);
            let boundaries = Arc::clone(&boundaries);
            let tx = tx.clone();
            s.spawn(move || {
                loop {
                    let ci = next_chunk.fetch_add(1, Ordering::Relaxed);
                    if ci >= n_chunks {
                        break;
                    }

                    let start = boundaries[ci];
                    let end = boundaries[ci + 1];
                    if start >= end {
                        tx.send((ci, Vec::new())).ok();
                        continue;
                    }

                    let mut local: Vec<ElemIndex> = Vec::new();
                    build_elem_index_slice(&bytes[start..end], start, &mut |e| local.push(e));
                    tx.send((ci, local)).ok();
                }
            });
        }
        drop(tx); // close sender side so rx.recv() returns Err when all workers done

        // ── Committer thread (runs on this scope thread) ──────────────────────
        // Drains the channel in file order. BTreeMap buffers out-of-order arrivals.
        // The hot path (in-order arrival) commits immediately without BTreeMap churn.
        let mut pending: BTreeMap<usize, Vec<ElemIndex>> = BTreeMap::new();
        let mut next_expected = 0usize;
        let mut write_head = 0usize;

        while let Ok((ci, vec)) = rx.recv() {
            pending.insert(ci, vec);
            while let Some(v) = pending.remove(&next_expected) {
                let slot = write_head;
                for (i, e) in v.iter().enumerate() {
                    // SAFETY: [slot, slot+v.len()) is exclusive to this thread.
                    // mmap pointer is valid for the scope duration.
                    unsafe {
                        std::ptr::write((mmap_ptr as *mut ElemIndex).add(slot + i), *e);
                    }
                }
                write_head += v.len();
                next_expected += 1;
            }
        }

        // Flush and trim.
        let actual_bytes = write_head * std::mem::size_of::<ElemIndex>();
        idx_mmap.flush().context("flushing revolver mmap")?;
        drop(idx_mmap);
        std::fs::OpenOptions::new()
            .write(true)
            .open(idx_path)?
            .set_len(actual_bytes as u64)?;

        Ok(write_head as u64)
    })
}

// ── PipelinedReader ───────────────────────────────────────────────────────────

pub const SLOT_BYTES: usize = 100 * 1024 * 1024; // 100 MB per I/O slot
pub const RING_DEPTH: usize = 4; // reader prefetch depth
const MAX_ELEM_BYTES: usize = 512 * 1024; // max OSM element size for carry-over

/// Position just past the last complete top-level OSM element in `bytes`.
/// Searches the last `MAX_ELEM_BYTES` to bound work. Returns 0 if none found.
pub fn find_safe_slot_end(bytes: &[u8]) -> usize {
    xml::find_safe_slot_end(
        bytes,
        MAX_ELEM_BYTES,
        &BOUNDARY_PAIRED,
        &BOUNDARY_SELF_CLOSING,
    )
}

/// Planet-scale pipelined reader: one I/O thread reads 100 MB slots into a ring
/// buffer while all worker cores parse the current slot in parallel.
///
/// ```text
/// [Reader]   slot0  →  slot1  →  slot2  →  …   (bounded, RING_DEPTH capacity)
/// [Workers]            parse slot0  |  parse slot1  |  …
/// ```
///
/// Per slot: find N sub-chunk borders (N × ~50-byte memchr, nanoseconds), then
/// parse N sub-chunks in parallel on the gatling fork-join pool
/// ([`gatling_for_each`](crate::gatling_forkjoin::gatling_for_each) —
/// `std::thread::scope` + a shared atomic cursor, no global pool). Slots are
/// processed sequentially so output is always in file order — no sorting, no
/// BTreeMap.
///
/// At planet scale (100 GB XML, NVMe ~7 GB/s):
///   read time per slot ≈ 14 ms, parse time (12 cores) < 14 ms → I/O bound.
pub fn build_elem_index_pipelined(path: &Path, n_workers: usize, idx_path: &Path) -> Result<u64> {
    build_elem_index_pipelined_cfg(path, n_workers, idx_path, SLOT_BYTES, RING_DEPTH)
}

/// Slot-size-parameterised core of [`build_elem_index_pipelined`]. Production
/// calls it with [`SLOT_BYTES`]/[`RING_DEPTH`]; tests pass a tiny `slot_bytes`
/// (and a small `ring_depth`) to drive the **multi-slot** carry-trim + changeset
/// discard→store flip cheaply. A real planet's ~86 GB changeset prologue spans
/// hundreds of 100 MB slots before the first `<node>`; the reader must find a
/// safe cut *inside* each pure-changeset slot (`changeset ∈ BOUNDARY_PAIRED`)
/// so `carry` never grows unbounded, then flip to emitting entries the moment
/// indexed elements begin (`node`/`way`/`relation ∈ OSM_TAGS`, `changeset ∉`).
/// A few-hundred-KB prologue over a 64 KiB `slot_bytes` exercises the identical
/// code path.
pub(crate) fn build_elem_index_pipelined_cfg(
    path: &Path,
    n_workers: usize,
    idx_path: &Path,
    slot_bytes: usize,
    ring_depth: usize,
) -> Result<u64> {
    use crate::gatling_forkjoin::gatling_for_each;
    use std::io::{Read, Write};
    use std::sync::mpsc;

    let n = n_workers.max(1);
    let slot_bytes = slot_bytes.max(1);
    let ring_depth = ring_depth.max(1);

    let out_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(idx_path)
        .context("creating index file")?;
    let mut out = std::io::BufWriter::with_capacity(8 * 1024 * 1024, out_file);
    let mut total = 0u64;

    // Bounded channel — reader stays at most RING_DEPTH slots ahead.
    // Message: (slot_id, absolute file offset of slot[0], slot bytes)
    let (tx, rx) = mpsc::sync_channel::<(usize, usize, Vec<u8>)>(ring_depth);

    std::thread::scope(|s| -> Result<()> {
        // ── Reader thread ─────────────────────────────────────────────────────
        s.spawn(move || {
            let mut file = File::open(path).expect("open input");
            let mut carry = Vec::<u8>::new();
            let mut buf_start = 0usize; // absolute file offset of carry[0]
            let mut slot_id = 0usize;

            loop {
                // Append up to slot_bytes of new data — reserve without zeroing.
                let prev_len = carry.len();
                carry.reserve(slot_bytes);
                let mut n_new = 0usize;
                while n_new < slot_bytes {
                    let spare = carry.spare_capacity_mut();
                    let want = (slot_bytes - n_new).min(spare.len());
                    // SAFETY: read() fills the buffer; we only advance len by bytes actually read.
                    let dst = unsafe {
                        std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, want)
                    };
                    match file.read(dst) {
                        Ok(0) => break,
                        Ok(k) => {
                            unsafe {
                                carry.set_len(prev_len + n_new + k);
                            }
                            n_new += k;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => panic!("read: {e}"),
                    }
                }

                if n_new == 0 {
                    // EOF — flush remaining carry as final slot.
                    if !carry.is_empty() {
                        tx.send((slot_id, buf_start, carry)).ok();
                    }
                    break;
                }

                let safe = find_safe_slot_end(&carry);
                if safe == 0 {
                    continue;
                } // huge element still accumulating

                // split_off copies only the small tail; parse_buf moves without copy.
                let new_carry = carry.split_off(safe);
                let parse_buf = carry;
                carry = new_carry;
                let send_start = buf_start;
                buf_start += safe;

                if tx.send((slot_id, send_start, parse_buf)).is_err() {
                    break;
                }
                slot_id += 1;
            }
        });

        // ── Processor (scope thread) ──────────────────────────────────────────
        while let Ok((_slot_id, file_pos, slot)) = rx.recv() {
            // OVERSPLIT + self-dispatch. The old shape cut each slot into exactly
            // `n` byte-equal sub-chunks and ran `n` workers (one sub-chunk each,
            // no stealing): a sub-chunk that lands on a denser element region left
            // its worker running alone while the others drained their light
            // sub-chunks and sat idle. Cutting into MANY more sub-chunks than
            // cores and letting the engine self-dispatch (workers = 0 ⇒ one per
            // core, shared atomic cursor) means an idle core just claims the next
            // sub-chunk — the dense tail spreads across all cores. Borders are
            // top-level-aligned so no element straddles a cut; the finer partition
            // yields the byte-identical ElemIndex list, in the same file order.
            const SPLIT: usize = 8;
            let units = (n * SPLIT).min(slot.len().max(1)).max(1);
            let chunk_size = (slot.len() / units).max(1);
            let mut borders = Vec::with_capacity(units + 1);
            for i in 0..units {
                borders.push(find_top_level_start(&slot, i * chunk_size));
            }
            borders.push(slot.len());

            // Parallel parse — each sub-chunk is independent; self-dispatched.
            let sub_results: Vec<Vec<ElemIndex>> = gatling_for_each(units, 0, |i| {
                let start = borders[i];
                let end = borders[i + 1];
                let mut v = Vec::new();
                build_elem_index_slice(&slot[start..end], file_pos + start, &mut |e| v.push(e));
                v
            });

            // Write in sub-chunk order (= file order). One write per sub-chunk.
            let esz = std::mem::size_of::<ElemIndex>();
            for sub in &sub_results {
                if sub.is_empty() {
                    continue;
                }
                // SAFETY: ElemIndex is repr(C)+Copy; mmap cast on read uses same layout.
                let raw = unsafe {
                    std::slice::from_raw_parts(sub.as_ptr() as *const u8, sub.len() * esz)
                };
                out.write_all(raw)?;
                total += sub.len() as u64;
            }
        }

        out.flush()?;
        Ok(())
    })?;

    Ok(total)
}

// ── Pass 2: filter and seek ───────────────────────────────────────────────────

/// Filter criteria for pass 2.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    /// If set, only yield elements of this kind.
    pub kind: Option<ElemKind>,
    /// If set, only yield elements whose tag_flags intersect this mask.
    pub tag_mask: u32,
    /// If set, only yield nodes within this lat/lon box (e7 units).
    pub bbox: Option<[i32; 4]>, // [min_lat, min_lon, max_lat, max_lon]
}

impl Filter {
    pub fn ways() -> Self {
        Self {
            kind: Some(ElemKind::Way),
            ..Default::default()
        }
    }
    pub fn relations() -> Self {
        Self {
            kind: Some(ElemKind::Relation),
            ..Default::default()
        }
    }
    pub fn nodes() -> Self {
        Self {
            kind: Some(ElemKind::Node),
            ..Default::default()
        }
    }

    fn matches(&self, e: &ElemIndex) -> bool {
        if let Some(k) = self.kind {
            if e.kind != k {
                return false;
            }
        }
        if self.tag_mask != 0 && (e.tag_flags & self.tag_mask) == 0 {
            return false;
        }
        if let Some([min_lat, min_lon, max_lat, max_lon]) = self.bbox {
            if e.kind == ElemKind::Node {
                if e.lat_e7 < min_lat
                    || e.lat_e7 > max_lat
                    || e.lon_e7 < min_lon
                    || e.lon_e7 > max_lon
                {
                    return false;
                }
            }
        }
        true
    }
}

/// Iterate over a pre-built ElemIndex slice, yield byte slices for matching elements.
/// `file_bytes` is the mmap of the original XML file.
/// `index` is sorted by file_offset (forward scan order).
pub fn iter_filtered<'a>(
    file_bytes: &'a [u8],
    index: &'a [ElemIndex],
    filter: &'a Filter,
) -> impl Iterator<Item = (ElemIndex, &'a [u8])> + 'a {
    index.iter().filter_map(move |e| {
        if !filter.matches(e) {
            return None;
        }
        let start = e.file_offset as usize;
        let end = start + e.file_length as usize;
        file_bytes.get(start..end).map(|slice| (*e, slice))
    })
}

// ── ChunkSummary: zone-map index over ElemIndex ───────────────────────────────

/// Number of ElemIndex entries per ChunkSummary. Power of two keeps division cheap.
pub const CHUNK_SIZE: usize = 1_024;

/// Kind presence bits — one bit per ElemKind variant.
pub mod kind_bits {
    pub const NODE: u8 = 1 << 0; // ElemKind::Node
    pub const WAY: u8 = 1 << 1; // ElemKind::Way
    pub const RELATION: u8 = 1 << 2; // ElemKind::Relation
}

#[inline]
fn kind_bit(k: ElemKind) -> u8 {
    1 << (k as u8)
}

/// Zone-map summary over CHUNK_SIZE ElemIndex entries. 32 bytes, cache-line friendly.
///
/// One sequential scan of the summary array skips whole chunks:
///   - kind_mask: skip if no matching kind present (e.g. skip 88 % of planet for way-only)
///   - tag_flags: skip if no matching tag present (e.g. skip 99 % of ways for highway-only)
///   - lat/lon bbox: skip node-only queries outside the chunk's spatial extent
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ChunkSummary {
    pub index_start: u32,
    pub index_end: u32,
    pub kind_mask: u8,
    pub _pad: [u8; 3],
    pub tag_flags: u32,
    pub lat_min: i32, // i32::MAX if chunk has no nodes
    pub lat_max: i32, // i32::MIN if chunk has no nodes
    pub lon_min: i32,
    pub lon_max: i32,
}

impl ChunkSummary {
    /// Returns false if the entire chunk can be skipped for `filter`.
    pub fn might_match(&self, filter: &Filter) -> bool {
        if let Some(k) = filter.kind {
            if self.kind_mask & kind_bit(k) == 0 {
                return false;
            }
        }
        if filter.tag_mask != 0 && (self.tag_flags & filter.tag_mask) == 0 {
            return false;
        }
        // Bbox skip is only safe when querying nodes specifically — ways/relations
        // have no coordinates in ElemIndex so their chunks can't be pruned by bbox.
        if filter.kind == Some(ElemKind::Node) {
            if let Some([min_lat, min_lon, max_lat, max_lon]) = filter.bbox {
                // lat_max = i32::MIN (sentinel) means no nodes → correctly fails any real bbox
                if self.lat_max < min_lat
                    || self.lat_min > max_lat
                    || self.lon_max < min_lon
                    || self.lon_min > max_lon
                {
                    return false;
                }
            }
        }
        true
    }
}

/// Build a ChunkSummary array from a complete ElemIndex slice.
/// O(N) single pass, no allocation beyond the output Vec.
pub fn build_chunk_summaries(index: &[ElemIndex]) -> Vec<ChunkSummary> {
    index
        .chunks(CHUNK_SIZE)
        .enumerate()
        .map(|(ci, chunk)| {
            let mut kind_mask: u8 = 0;
            let mut tag_flags: u32 = 0;
            let mut lat_min = i32::MAX;
            let mut lat_max = i32::MIN;
            let mut lon_min = i32::MAX;
            let mut lon_max = i32::MIN;

            for e in chunk {
                kind_mask |= kind_bit(e.kind);
                tag_flags |= e.tag_flags;
                if e.kind == ElemKind::Node {
                    lat_min = lat_min.min(e.lat_e7);
                    lat_max = lat_max.max(e.lat_e7);
                    lon_min = lon_min.min(e.lon_e7);
                    lon_max = lon_max.max(e.lon_e7);
                }
            }

            ChunkSummary {
                index_start: (ci * CHUNK_SIZE) as u32,
                index_end: (ci * CHUNK_SIZE + chunk.len()) as u32,
                kind_mask,
                _pad: [0; 3],
                tag_flags,
                lat_min,
                lat_max,
                lon_min,
                lon_max,
            }
        })
        .collect()
}

/// Write a ChunkSummary array to a flat binary file (same pattern as ElemIndex).
pub fn write_chunk_summaries(summaries: &[ChunkSummary], path: &Path) -> Result<()> {
    use std::io::Write as _;
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    let mut w = std::io::BufWriter::with_capacity(4 * 1024 * 1024, file);
    let esz = std::mem::size_of::<ChunkSummary>();
    // SAFETY: ChunkSummary is repr(C)+Copy, no padding bytes that matter for I/O.
    let raw = unsafe {
        std::slice::from_raw_parts(summaries.as_ptr() as *const u8, summaries.len() * esz)
    };
    w.write_all(raw).context("writing chunk summaries")?;
    Ok(())
}

/// Cast a mmap written by `write_chunk_summaries` back to a typed slice.
pub fn as_chunk_summaries(mmap: &Mmap) -> &[ChunkSummary] {
    let bytes = mmap.as_ref();
    let esz = std::mem::size_of::<ChunkSummary>();
    assert_eq!(
        bytes.len() % esz,
        0,
        "mmap length not aligned to ChunkSummary"
    );
    // SAFETY: same alignment/origin guarantees as as_elem_index.
    unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const ChunkSummary, bytes.len() / esz) }
}

/// Like `iter_filtered` but skips entire CHUNK_SIZE blocks using zone-map statistics.
/// Drop-in replacement — yields identical results, faster on kind/tag/bbox filters.
pub fn iter_filtered_chunked<'a>(
    file_bytes: &'a [u8],
    index: &'a [ElemIndex],
    summaries: &'a [ChunkSummary],
    filter: &'a Filter,
) -> impl Iterator<Item = (ElemIndex, &'a [u8])> + 'a {
    summaries
        .iter()
        .filter(move |s| s.might_match(filter))
        .flat_map(move |s| {
            iter_filtered(
                file_bytes,
                &index[s.index_start as usize..s.index_end as usize],
                filter,
            )
        })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // These tests were originally pinned to the multi-MB sibling fixture
    // `../katana-osm/liechtenstein.osm`, which is not vendored into this repo.
    // They now run on the self-contained `synth_osm()` generator (defined below),
    // so they need no external files while still exercising the same code paths.
    // `synth_osm(SYNTH_N)` yields exactly SYNTH_N nodes, SYNTH_N ways and
    // SYNTH_N rels; SYNTH_N is chosen so the index spans several CHUNK_SIZE
    // (1024) blocks, giving the ChunkSummary tests real chunk boundaries.
    const SYNTH_N: usize = 1_000; // → 3_000 indexed elements → 3 chunks

    fn load_index() -> (Vec<u8>, Vec<ElemIndex>) {
        let bytes = synth_osm(SYNTH_N);
        let mut index = Vec::new();
        build_elem_index(&bytes, |e| index.push(e)).expect("build_elem_index failed");
        (bytes, index)
    }

    #[test]
    fn element_counts() {
        let (_, index) = load_index();
        let nodes = index.iter().filter(|e| e.kind == ElemKind::Node).count();
        let ways = index.iter().filter(|e| e.kind == ElemKind::Way).count();
        let rels = index
            .iter()
            .filter(|e| e.kind == ElemKind::Relation)
            .count();
        // synth_osm(SYNTH_N) emits exactly SYNTH_N of each kind.
        assert_eq!(nodes, SYNTH_N, "node count mismatch");
        assert_eq!(ways, SYNTH_N, "way count mismatch");
        assert_eq!(rels, SYNTH_N, "relation count mismatch");
    }

    #[test]
    fn first_node_coords() {
        let (_, index) = load_index();
        let first = index.iter().find(|e| e.kind == ElemKind::Node).unwrap();
        // synth_osm's first node (i=0): <node id="1" lat="47.0000000" lon="9.0000000"/>
        assert_eq!(first.id, 1);
        assert_eq!(first.lat_e7, 470_000_000);
        assert_eq!(first.lon_e7, 90_000_000);
    }

    #[test]
    fn natural_tag_flag() {
        let (_, index) = load_index();
        // synth_osm tags some child-bearing nodes with natural=x; the NATURAL
        // flag must be detected on at least one node.
        assert!(
            index
                .iter()
                .any(|e| e.kind == ElemKind::Node && e.tag_flags & tag_flags::NATURAL != 0),
            "no node carried the NATURAL flag",
        );
    }

    #[test]
    fn highway_tag_flag() {
        let (_, index) = load_index();
        // synth_osm tags some child-bearing nodes with highway=x; the HIGHWAY
        // flag must be detected on at least one node.
        assert!(
            index
                .iter()
                .any(|e| e.kind == ElemKind::Node && e.tag_flags & tag_flags::HIGHWAY != 0),
            "no node carried the HIGHWAY flag",
        );
    }

    #[test]
    fn byte_slice_roundtrip() {
        let (bytes, index) = load_index();
        // Every entry's byte slice must start with '<' and end with '>'
        for e in &index {
            let start = e.file_offset as usize;
            let end = start + e.file_length as usize;
            let slice = &bytes[start..end];
            assert_eq!(slice.first(), Some(&b'<'), "id={} bad start", e.id);
            assert_eq!(slice.last(), Some(&b'>'), "id={} bad end", e.id);
        }
    }

    #[test]
    fn filter_ways_only() {
        let (bytes, index) = load_index();
        let filter = Filter::ways();
        let count = iter_filtered(&bytes, &index, &filter).count();
        assert_eq!(count, SYNTH_N);
    }

    #[test]
    fn parallel_matches_sequential() {
        // Larger corpus than SYNTH_N so the 2/4/8-worker splits land at varied
        // element boundaries; the sequential builder is the oracle.
        let bytes = synth_osm(2_000);

        let mut seq: Vec<ElemIndex> = Vec::new();
        build_elem_index(&bytes, |e| seq.push(e)).unwrap();

        // Test with 2, 4, and 8 workers to exercise different split points.
        for n in [2, 4, 8] {
            let mut par: Vec<ElemIndex> = Vec::new();
            build_elem_index_parallel(&bytes, n, |e| par.push(e)).unwrap();

            assert_eq!(par.len(), seq.len(), "n={n}: count mismatch");
            for (i, (p, s)) in par.iter().zip(&seq).enumerate() {
                assert_eq!(p.file_offset, s.file_offset, "n={n} entry {i}: file_offset");
                assert_eq!(p.file_length, s.file_length, "n={n} entry {i}: file_length");
                assert_eq!(p.id, s.id, "n={n} entry {i}: id");
                assert_eq!(p.kind, s.kind, "n={n} entry {i}: kind");
                assert_eq!(p.tag_flags, s.tag_flags, "n={n} entry {i}: tag_flags");
            }
        }
    }

    // (xml_to_pbf_smoke test removed in extraction — it depended on katana-osm's
    //  xml_to_pbf encoder, which is not part of this crate.)

    #[test]
    fn filter_tag_mask() {
        let (bytes, index) = load_index();
        let filter = Filter {
            kind: Some(ElemKind::Way),
            tag_mask: tag_flags::HIGHWAY,
            bbox: None,
        };
        let count = iter_filtered(&bytes, &index, &filter).count();
        assert!(count > 0, "expected some highway ways");
        // all results must have HIGHWAY flag
        for (e, _) in iter_filtered(&bytes, &index, &filter) {
            assert_ne!(e.tag_flags & tag_flags::HIGHWAY, 0);
        }
    }

    // ── ChunkSummary tests ────────────────────────────────────────────────────

    #[test]
    fn chunk_summaries_cover_all() {
        let (_, index) = load_index();
        let summaries = build_chunk_summaries(&index);
        let covered: usize = summaries
            .iter()
            .map(|s| (s.index_end - s.index_start) as usize)
            .sum();
        assert_eq!(
            covered,
            index.len(),
            "summaries must cover all index entries"
        );
        // index ranges must be contiguous and non-overlapping
        for (i, s) in summaries.iter().enumerate() {
            assert_eq!(s.index_start as usize, i * CHUNK_SIZE);
            assert!(s.index_end > s.index_start);
            assert!(s.index_end as usize <= index.len());
        }
    }

    #[test]
    fn chunk_summaries_kind_mask_correct() {
        let (_, index) = load_index();
        let summaries = build_chunk_summaries(&index);
        for s in &summaries {
            let chunk = &index[s.index_start as usize..s.index_end as usize];
            let mut expected: u8 = 0;
            for e in chunk {
                expected |= 1 << (e.kind as u8);
            }
            assert_eq!(
                s.kind_mask, expected,
                "kind_mask mismatch for chunk starting at {}",
                s.index_start
            );
        }
    }

    #[test]
    fn chunk_summaries_tag_flags_correct() {
        let (_, index) = load_index();
        let summaries = build_chunk_summaries(&index);
        for s in &summaries {
            let chunk = &index[s.index_start as usize..s.index_end as usize];
            let expected: u32 = chunk.iter().fold(0, |acc, e| acc | e.tag_flags);
            assert_eq!(s.tag_flags, expected);
        }
    }

    #[test]
    fn chunk_summaries_bbox_covers_nodes() {
        let (_, index) = load_index();
        let summaries = build_chunk_summaries(&index);
        for s in &summaries {
            let chunk = &index[s.index_start as usize..s.index_end as usize];
            for e in chunk.iter().filter(|e| e.kind == ElemKind::Node) {
                assert!(
                    e.lat_e7 >= s.lat_min && e.lat_e7 <= s.lat_max,
                    "lat {} outside [{}, {}]",
                    e.lat_e7,
                    s.lat_min,
                    s.lat_max
                );
                assert!(
                    e.lon_e7 >= s.lon_min && e.lon_e7 <= s.lon_max,
                    "lon {} outside [{}, {}]",
                    e.lon_e7,
                    s.lon_min,
                    s.lon_max
                );
            }
        }
    }

    #[test]
    fn chunked_filter_matches_simple_filter() {
        let (bytes, index) = load_index();
        let summaries = build_chunk_summaries(&index);

        let filters = [
            Filter::nodes(),
            Filter::ways(),
            Filter::relations(),
            Filter {
                kind: Some(ElemKind::Way),
                tag_mask: tag_flags::HIGHWAY,
                bbox: None,
            },
        ];

        for filter in &filters {
            let simple: Vec<ElemIndex> = iter_filtered(&bytes, &index, filter)
                .map(|(e, _)| e)
                .collect();
            let chunked: Vec<ElemIndex> = iter_filtered_chunked(&bytes, &index, &summaries, filter)
                .map(|(e, _)| e)
                .collect();
            assert_eq!(
                simple.len(),
                chunked.len(),
                "count mismatch for filter {:?}",
                filter
            );
            for (s, c) in simple.iter().zip(&chunked) {
                assert_eq!(s.file_offset, c.file_offset);
            }
        }
    }

    #[test]
    fn chunked_filter_skips_node_chunks_for_ways() {
        let (_, index) = load_index();
        let summaries = build_chunk_summaries(&index);
        let filter = Filter::ways();
        // synth_osm lays out all nodes, then all ways, then all rels, so some
        // chunks contain no way at all. The skip decision must be sound: a chunk
        // is skippable for a way-only filter iff it holds no Way — and some chunks
        // must actually be skipped while others are kept.
        for s in &summaries {
            let chunk = &index[s.index_start as usize..s.index_end as usize];
            let has_way = chunk.iter().any(|e| e.kind == ElemKind::Way);
            assert_eq!(
                s.might_match(&filter),
                has_way,
                "chunk starting at {} skip decision must track presence of ways",
                s.index_start
            );
        }
        assert!(
            summaries.iter().any(|s| !s.might_match(&filter)),
            "expected at least one chunk skipped for way-only filter"
        );
        assert!(
            summaries.iter().any(|s| s.might_match(&filter)),
            "expected at least one chunk kept for way-only filter"
        );
    }

    #[test]
    fn write_and_load_chunk_summaries() {
        let (_, index) = load_index();
        let summaries = build_chunk_summaries(&index);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("synth.chunks.idx");
        write_chunk_summaries(&summaries, &path).expect("write");
        let mmap = mmap_input(&path).expect("mmap");
        let loaded = as_chunk_summaries(&mmap);
        assert_eq!(loaded.len(), summaries.len());
        for (a, b) in summaries.iter().zip(loaded.iter()) {
            assert_eq!(a.index_start, b.index_start);
            assert_eq!(a.kind_mask, b.kind_mask);
            assert_eq!(a.tag_flags, b.tag_flags);
            assert_eq!(a.lat_min, b.lat_min);
        }
    }

    // ── Synthetic-OSM parity: gatling paths vs the sequential baseline ─────────
    //
    // These tests need NO external fixture — they generate a self-contained OSM
    // document in-memory, so they run everywhere and directly guard the
    // rayon→`gatling_for_each` port of `build_elem_index_pipelined` (commits
    // 43c571a / d42c974). The sequential `build_elem_index` is the oracle; every
    // parallel path must reproduce its ElemIndex list byte-for-byte for any
    // worker count, including counts that force splits at every element boundary.

    /// Assert two ElemIndex slices are field-for-field identical.
    fn assert_elem_eq(got: &[ElemIndex], want: &[ElemIndex], ctx: &str) {
        assert_eq!(got.len(), want.len(), "{ctx}: element count mismatch");
        for (i, (g, w)) in got.iter().zip(want).enumerate() {
            assert_eq!(g.file_offset, w.file_offset, "{ctx} entry {i}: file_offset");
            assert_eq!(g.file_length, w.file_length, "{ctx} entry {i}: file_length");
            assert_eq!(g.kind, w.kind, "{ctx} entry {i}: kind");
            assert_eq!(g.id, w.id, "{ctx} entry {i}: id");
            assert_eq!(g.lat_e7, w.lat_e7, "{ctx} entry {i}: lat_e7");
            assert_eq!(g.lon_e7, w.lon_e7, "{ctx} entry {i}: lon_e7");
            assert_eq!(g.tag_flags, w.tag_flags, "{ctx} entry {i}: tag_flags");
        }
    }

    /// Build a self-contained OSM XML document with `n` of each element kind and
    /// a deliberate mix of shapes: self-closing vs child-bearing nodes, ways with
    /// `<nd>`/`<tag>` children, relations with `<member>`/`<tag>` children,
    /// negative coordinates, varied ids, and every tag_flag key. Interspersed
    /// `<bound/>`/`<note>` and a `<changeset>` exercise the boundary vocabulary
    /// the streaming reader trims on.
    fn synth_osm(n: usize) -> Vec<u8> {
        let flag_keys = [
            "highway", "building", "natural", "landuse", "waterway", "railway", "amenity",
            "boundary",
        ];
        let mut s = String::new();
        s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<osm version=\"0.6\">\n");
        s.push_str("  <bound box=\"45,8,48,10\" origin=\"test\"/>\n");
        s.push_str("  <note>generated by synth_osm — contains no real data</note>\n");
        for i in 0..n {
            let id = i as i64 + 1;
            // Latitude negative for odd ids to cover the sign path in parse_coord_e7.
            let lat = if i % 2 == 0 {
                format!("47.{:07}", i % 9_999_999)
            } else {
                format!("-1.{:07}", i % 9_999_999)
            };
            let lon = format!("9.{:07}", (i * 7) % 9_999_999);
            if i % 3 == 0 {
                // Self-closing node, no tags.
                s.push_str(&format!(
                    "  <node id=\"{id}\" lat=\"{lat}\" lon=\"{lon}\"/>\n"
                ));
            } else {
                // Child-bearing node with one flag tag.
                let k = flag_keys[i % flag_keys.len()];
                s.push_str(&format!(
                    "  <node id=\"{id}\" lat=\"{lat}\" lon=\"{lon}\">\n    <tag k=\"{k}\" v=\"x\"/>\n  </node>\n"
                ));
            }
        }
        for i in 0..n {
            let id = i as i64 + 1_000_000;
            let k = flag_keys[(i + 1) % flag_keys.len()];
            s.push_str(&format!("  <way id=\"{id}\">\n"));
            s.push_str("    <nd ref=\"1\"/>\n    <nd ref=\"2\"/>\n");
            s.push_str(&format!("    <tag k=\"{k}\" v=\"yes\"/>\n"));
            s.push_str("  </way>\n");
        }
        for i in 0..n {
            let id = i as i64 + 2_000_000;
            s.push_str(&format!("  <relation id=\"{id}\">\n"));
            s.push_str("    <member type=\"way\" ref=\"1000000\" role=\"outer\"/>\n");
            s.push_str("    <tag k=\"boundary\" v=\"administrative\"/>\n");
            s.push_str("  </relation>\n");
        }
        // A changeset (paired boundary vocabulary) and the doc close.
        s.push_str("  <changeset id=\"5\">\n    <tag k=\"comment\" v=\"c\"/>\n  </changeset>\n");
        s.push_str("</osm>\n");
        s.into_bytes()
    }

    fn seq_index(bytes: &[u8]) -> Vec<ElemIndex> {
        let mut v = Vec::new();
        build_elem_index(bytes, |e| v.push(e)).unwrap();
        v
    }

    /// Load an ElemIndex file written by one of the mmap/pipelined builders.
    fn load_idx_file(path: &Path) -> Vec<ElemIndex> {
        let mmap = mmap_input(path).expect("mmap idx");
        as_elem_index(&mmap).to_vec()
    }

    #[test]
    fn synth_osm_is_well_formed_and_has_expected_kinds() {
        let bytes = synth_osm(20);
        let idx = seq_index(&bytes);
        let nodes = idx.iter().filter(|e| e.kind == ElemKind::Node).count();
        let ways = idx.iter().filter(|e| e.kind == ElemKind::Way).count();
        let rels = idx.iter().filter(|e| e.kind == ElemKind::Relation).count();
        assert_eq!(nodes, 20);
        assert_eq!(ways, 20);
        assert_eq!(rels, 20);
        // Some node must carry a tag flag; a self-closing node must carry none.
        assert!(
            idx.iter()
                .any(|e| e.kind == ElemKind::Node && e.tag_flags != 0)
        );
        assert!(
            idx.iter()
                .any(|e| e.kind == ElemKind::Node && e.tag_flags == 0)
        );
        // Negative-latitude nodes round-trip through parse_coord_e7.
        assert!(idx.iter().any(|e| e.kind == ElemKind::Node && e.lat_e7 < 0));
        // Every span slices back to a well-formed element.
        for e in &idx {
            let start = e.file_offset as usize;
            let slice = &bytes[start..start + e.file_length as usize];
            assert_eq!(slice.first(), Some(&b'<'));
            assert_eq!(slice.last(), Some(&b'>'));
        }
    }

    #[test]
    fn pipelined_matches_sequential_synth() {
        // The gatling_for_each-ported path. Reads a file, sub-chunks each slot on
        // the fork-join pool, writes the index in file order.
        let bytes = synth_osm(2_000); // ~6k elements, comfortably one 100 MB slot
        let expected = seq_index(&bytes);
        assert!(
            expected.len() >= 6_000,
            "sanity: {} elements",
            expected.len()
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let osm_path = dir.path().join("synth.osm");
        std::fs::write(&osm_path, &bytes).expect("write osm");

        for n in [1usize, 2, 3, 4, 5, 8, 13, 16, 32] {
            let idx_path = dir.path().join(format!("synth.{n}.idx"));
            let total =
                build_elem_index_pipelined(&osm_path, n, &idx_path).expect("pipelined scan");
            assert_eq!(total as usize, expected.len(), "n={n}: total mismatch");
            let got = load_idx_file(&idx_path);
            assert_elem_eq(&got, &expected, &format!("pipelined n={n}"));
        }
    }

    /// Build an OSM doc that mirrors a **planet's shape**: a large leading run of
    /// `<changeset>` elements (the ~86 GB prologue a real planet dump carries
    /// before the first `<node>`), then the real node/way/relation data. Returns
    /// `(bytes, prologue_len)`.
    fn synth_osm_changeset_prologue(n_changesets: usize, n_elems: usize) -> (Vec<u8>, usize) {
        let mut s = String::new();
        s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<osm version=\"0.6\">\n");
        s.push_str("  <bound box=\"45,8,48,10\" origin=\"test\"/>\n");
        // ── The prologue: only changesets (NOT indexed → discarded). ──
        for i in 0..n_changesets {
            let id = i as i64 + 1;
            s.push_str(&format!(
                "  <changeset id=\"{id}\" created_by=\"synth\" comment=\"skip me — prologue padding {id}\">\n    <tag k=\"comment\" v=\"planet changeset prologue entry {id}\"/>\n  </changeset>\n"
            ));
        }
        let prologue_len = s.len();
        // ── The real data (indexed → stored). Reuse synth_osm's element bodies. ──
        let body = synth_osm(n_elems);
        // Splice in only the element region of `body` (drop its header/<bound>/close),
        // by taking everything from its first "  <node" to just before "</osm>".
        let bs = String::from_utf8(body).unwrap();
        let start = bs.find("  <node").expect("body has nodes");
        let end = bs.find("</osm>").expect("body closes");
        s.push_str(&bs[start..end]);
        s.push_str("</osm>\n");
        (s.into_bytes(), prologue_len)
    }

    /// The load-bearing fast-skip invariant: a slot containing ONLY complete
    /// `<changeset>` elements (no indexed element in sight) must still yield a
    /// non-zero safe cut, so the streaming reader can trim it and `carry` stays
    /// bounded across the whole 86 GB prologue. This holds iff `changeset` is in
    /// `BOUNDARY_PAIRED` even though it is absent from `OSM_TAGS`. If it were ever
    /// dropped from the boundary vocabulary, `find_safe_slot_end` on a pure-
    /// changeset slot would return 0 and the reader would accumulate the entire
    /// prologue into one buffer.
    #[test]
    fn pure_changeset_slot_is_trimmable() {
        let (bytes, prologue_len) = synth_osm_changeset_prologue(400, 4);
        // A window fully inside the prologue — no node/way/relation anywhere in it.
        let window = &bytes[100..(prologue_len - 100).min(bytes.len())];
        assert!(
            !window.windows(6).any(|w| w == b"<node "),
            "window must be changeset-only"
        );
        let safe = find_safe_slot_end(window);
        assert!(
            safe > 0,
            "pure-changeset slot returned no safe cut — carry would grow unbounded"
        );
    }

    /// End-to-end fast-skip: a leading changeset prologue spanning MANY slots
    /// (tiny injected `slot_bytes`), then real data. Proves (1) discard — the
    /// prologue produces zero index entries; (2) flip — indexing starts at the
    /// first real element and the output is byte-identical to the sequential
    /// oracle; (3) bounded carry — the scan completes across dozens of pure-
    /// changeset slots without accumulating the prologue.
    #[test]
    fn pipelined_fast_skips_changeset_prologue() {
        // ~400 changesets ≈ 60 KB prologue; a 4 KiB slot ⇒ ~15 pure-changeset
        // slots trimmed before the first indexed element is even seen.
        let (bytes, prologue_len) = synth_osm_changeset_prologue(400, 500);
        assert!(
            prologue_len > 8 * 4096,
            "prologue must span many 4 KiB slots ({prologue_len} B)"
        );

        let expected = seq_index(&bytes); // oracle: changesets absent, real data only
        assert!(
            expected
                .iter()
                .all(|e| e.kind != ElemKind::Relation || e.id >= 2_000_000)
        );
        // The oracle proves nothing indexed lands inside the prologue (all real
        // elements start after it).
        assert!(
            expected
                .iter()
                .all(|e| (e.file_offset as usize) >= prologue_len),
            "no indexed element may fall inside the discarded prologue"
        );
        assert!(
            expected.len() >= 1_500,
            "sanity: {} indexed elements",
            expected.len()
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let osm_path = dir.path().join("planetish.osm");
        std::fs::write(&osm_path, &bytes).expect("write osm");

        for n in [1usize, 3, 8] {
            let idx_path = dir.path().join(format!("planetish.{n}.idx"));
            // 4 KiB slots, ring depth 2 — forces the multi-slot carry path the
            // production 100 MB slot only hits on a real planet.
            let total = build_elem_index_pipelined_cfg(&osm_path, n, &idx_path, 4096, 2)
                .expect("pipelined fast-skip scan");
            assert_eq!(
                total as usize,
                expected.len(),
                "n={n}: discarded/stored count mismatch"
            );
            let got = load_idx_file(&idx_path);
            assert_elem_eq(&got, &expected, &format!("fast-skip n={n}"));
        }
    }

    #[test]
    fn mmap_and_revolver_match_sequential_synth() {
        // Siblings of the pipelined path that share the count/prefix-sum + merge
        // machinery. Cross-checking them on the same synthetic corpus guards the
        // ordered-merge contract for every no-barrier writer, not just the ported
        // one.
        let bytes = synth_osm(1_500);
        let expected = seq_index(&bytes);

        let dir = tempfile::tempdir().expect("tempdir");
        for n in [1usize, 2, 3, 4, 8, 16] {
            let mmap_path = dir.path().join(format!("m.{n}.idx"));
            let total = build_elem_index_to_mmap(&bytes, n, &mmap_path).expect("to_mmap");
            assert_eq!(total as usize, expected.len(), "to_mmap n={n}: total");
            assert_elem_eq(
                &load_idx_file(&mmap_path),
                &expected,
                &format!("to_mmap n={n}"),
            );

            let rev_path = dir.path().join(format!("r.{n}.idx"));
            let total = build_elem_index_revolver(&bytes, n, &rev_path).expect("revolver");
            assert_eq!(total as usize, expected.len(), "revolver n={n}: total");
            assert_elem_eq(
                &load_idx_file(&rev_path),
                &expected,
                &format!("revolver n={n}"),
            );
        }
    }

    #[test]
    fn in_memory_parallel_matches_sequential_synth() {
        // `build_elem_index_parallel` (xml::scan_parallel rendezvous). Stays
        // single-threaded below its 4 MiB threshold, so also test a >4 MiB corpus
        // to actually cross into the multi-thread rendezvous path.
        for elems in [800usize, 60_000] {
            let bytes = synth_osm(elems);
            let expected = seq_index(&bytes);
            for n in [1usize, 2, 4, 8, 16] {
                let mut got = Vec::new();
                build_elem_index_parallel(&bytes, n, |e| got.push(e)).unwrap();
                assert_elem_eq(&got, &expected, &format!("parallel elems={elems} n={n}"));
            }
        }
    }

    #[test]
    fn pipelined_handles_tiny_and_empty_docs() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Documents with zero indexed elements and with a single one.
        let cases: &[&[u8]] = &[
            b"",
            b"<osm></osm>\n",
            b"<osm>\n  <node id=\"7\" lat=\"1.0\" lon=\"2.0\"/>\n</osm>\n",
        ];
        for (ci, case) in cases.iter().enumerate() {
            let expected = seq_index(case);
            let osm_path = dir.path().join(format!("tiny.{ci}.osm"));
            std::fs::write(&osm_path, case).expect("write");
            for n in [1usize, 2, 4] {
                let idx_path = dir.path().join(format!("tiny.{ci}.{n}.idx"));
                let total =
                    build_elem_index_pipelined(&osm_path, n, &idx_path).expect("pipelined tiny");
                assert_eq!(total as usize, expected.len(), "case {ci} n={n}");
                if expected.is_empty() {
                    // Zero-element output: nothing to compare beyond the count.
                    continue;
                }
                assert_elem_eq(
                    &load_idx_file(&idx_path),
                    &expected,
                    &format!("tiny {ci} n={n}"),
                );
            }
        }
    }
}
