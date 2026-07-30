# lzip-rs Design Document

> **Note (2025):** The decompression backend is now **linflate** (shared SIMD
> DEFLATE engine, extracted to [linflate-rs](https://codeberg.org/nordisk/znippy)).
> All references to `miniz_oxide` below are historical — production builds use
> linflate exclusively. The internal `src/inflate/` module remains as a historical
> reference; see `src/inflate/DESIGN.md` for its original design notes.

## Rule 1 — Core Algorithm: Mirror lbzip2-rs

lzip-rs uses the same parallel pipeline as lbzip2-rs, adapted for ZIP/DEFLATE.

**lbzip2-rs pipeline (source of truth):**
```
reader thread fills 6-slot ring buffer (200 MB slots)
→ main thread: prepend carry, parallel split-point scan (N splits, one per core)
→ post work items (zero-copy ptr into slot) → N worker threads decode segments
→ collector thread: assemble in order → writer thread: single sequential write
→ collector recycles slot back to reader
```

**lzip-rs equivalent:**
```
reader thread fills 6-slot ring buffer per large entry
→ main thread: parallel full-flush scan (N splits, one per physical core)
→ post work items (zero-copy ptr into slot) → N worker threads DEFLATE-decode
→ collector: per-entry assembly in order → writer: channel, single thread, by offset
→ collector recycles slot
```

**Key structural difference from bzip2:**
- bzip2 blocks are self-contained (BWT is independent per block).
- DEFLATE blocks share a 32 KB LZ77 back-reference window. Independent decompression
  is only possible at **Z_FULL_FLUSH** boundaries — zero-length stored blocks that
  reset the window to empty.
- Entries without full-flush markers fall back to Rule 3 (single-core).

**DEFLATE full-flush marker in the byte stream:**
After the preceding block ends and bits are padded to a byte boundary:
```
00          ← stored block header (BFINAL=0, BTYPE=00) + 5 zero padding bits
00 00       ← LEN = 0x0000
FF FF       ← NLEN = 0xFFFF (one's complement)
```
Scan is byte-level — roughly 100× cheaper per byte than lbzip2's bit-level scan.

**Q1 — False positive handling:**
**Answer:** No look-behind verification. Same approach as lbzip2-rs: calculate candidate
offsets, each core forward-scans to the next `00 00 FF FF` pattern. The scan is
cheap (~500 bytes forward per split point) and false positives are extremely rare in
real DEFLATE streams. Trust the forward scan, do not add look-behind overhead.

---

## Rule 2 — Large ZIP Entries: Chunked Parallel Decompress

**Threshold:** entries with compressed size ≥ 4 MB (see Rule 3).

### 2.1 Ring Buffer (ChunkRevolver)

Mirrors lbzip2-rs exactly:

| Parameter | lbzip2-rs | lzip-rs |
|-----------|-----------|---------|
| `RING_SLOTS` | 6 | 6 |
| `CHUNK_SIZE` | 200 MB | 200 MB |
| `CARRY_HEADROOM` | 32 MB | 32 MB |
| `SLOT_SIZE` | 232 MB | 232 MB |

Six slots are pre-allocated at startup. The reader fills one slot while workers
drain another. Finished slots are recycled back to the reader via channel.

**Q2 — Buffer count:**
**Answer:** 6 slots, exactly as lbzip2-rs. Provides enough pipeline depth so the
reader is never idle while workers are busy.

### 2.2 Carry Mechanism

Same as lbzip2-rs: after each chunk is split, bytes from the last incomplete segment
are carried forward into the 32 MB headroom of the next slot. No reallocation needed.

```
slot N:  [carry_headroom=32MB | read_data=200MB]
                  ↑
         previous slot's tail bytes prepended here
```

### 2.3 Split-Point Search Phase (N cores in parallel)

Given `N = physical cores` and a chunk buffer of `len` bytes:

1. Calculate N−1 nominal byte offsets: `offset[i] = len * i / N` for i = 1..N−1.
2. Dispatch as N−1 rayon tasks simultaneously — each task forward-scans for next
   `00 00 FF FF` marker from its nominal offset.
3. Deduplicate; result is up to N−1 interior split points → up to N segments.
4. One segment per physical core — no overcommitment. This matches lbzip2-rs's
   binary exactly (`split_chunk(data, n_workers, ...)`).

Note: lbzip2-rs's library also has a `decode_chunk_segments()` path with an
`LBZIP2_OVERSPLIT` tunable (default ×8), but the binary does not use it.
lzip-rs follows the binary pattern: N workers, N segments, no oversplit.

If zero markers found → entry falls back to Rule 3.

### 2.4 Zero-Copy Work Dispatch

Workers receive a **raw pointer** into the slot buffer — no copy of compressed data:

```rust
struct WorkItem {
    chunk_id:   u64,
    segment_id: usize,
    data_ptr:   *const u8,   // points into slot — zero copy
    data_len:   usize,
    start_byte: usize,
    end_byte:   usize,
}
unsafe impl Send for WorkItem {}
// Safety: slot lives until collector confirms all segments done, then recycles.
```

### 2.5 Decompression Phase (N dedicated worker threads on shared channel)

Each segment: `linflate` decode on `data[start_byte..end_byte]`.
Full-flush boundary guarantees no LZ77 dependency between segments.
Workers produce `Vec<u8>` output sent to collector via channel.

**Critical: workers are dedicated `std::thread::spawn` threads, NOT a rayon pool.**
They share one `Arc<Mutex<mpsc::Receiver<WorkItem>>>` and sit in a tight loop:

```rust
loop {
    let item = work_rx.lock().unwrap().recv()?;   // blocking
    // Safety: data_ptr valid until collector recycles slot
    let data = unsafe { slice::from_raw_parts(item.data_ptr, item.data_len) };
    let output = decode_segment_into(&data[item.start_byte..item.end_byte])?;
    collector_tx.send(SegmentResult { chunk_id, segment_id, output })?;
}
```

**Why not rayon `par_iter` over segments?** Rayon's fork-join leaves an implicit
barrier at the end of each parallel block — workers idle until the next chunk
is split. With a dedicated worker channel + multi-chunk in-flight, a worker
that finishes a small segment of chunk N immediately pulls a segment of chunk N+1
without waiting. **Workers are never idle while work is pending anywhere.**

Rayon IS used inside `split_boundaries_parallel` (Rule 2.3) — a sub-millisecond
bursty parallel scan. Decode workers are plain threads.

### 2.6 Multi-chunk Streaming

For entries larger than 200 MB, successive chunks overlap I/O and decode:

```
chunk 0: [read] → [split] → [decode]
chunk 1:          [read]  → [split] → [decode]
chunk 2:                    [read]  → [split] → [decode]
```

Six ring slots give up to 6 chunks in flight simultaneously.

---

## Rule 3 — Small ZIP Entries: Single-Core

**Threshold:** compressed size < 4 MB.

**Q3 — Strategy:**
**Answer:** Treat a small entry as a **single-slot single-worker task** — one worker
from the pool takes the whole entry, no split-point scan. This integrates naturally
with the work-stealing scheduler (uniform task model). No special last-queue logic
needed. If the file offsets in the Central Directory make random access easy, a small
entry can be dispatched as one `WorkItem` with `start_byte=0, end_byte=compressed_size`.

Single call to `linflate::decompress(compressed)`.
No chunking, no full-flush scan, no carry overhead.

---

## Rule 4 — Decompression Algorithm and SIMD

### 4.1 Algorithm: DEFLATE, not BWT

bzip2: **BWT → MTF → Huffman → RLE2** — `iBWT` is the expensive step.
lbzip2-rs uses thread-local `tt[]` + prefetch-optimised `decode_block_into` to avoid
per-block heap allocation in the hot path.

**lzip-rs uses DEFLATE:**
- **Huffman coding** on literal/length and distance alphabets.
- **LZ77 back-references** — `(distance, length)` pairs referencing the 32 KB window.
- No BWT, no MTF, no iBWT.

### 4.2 SIMD Applicability

| Operation | SIMD | Notes |
|-----------|------|-------|
| CRC32 verification | **Yes — hardware** | x86 SSE4.2 `_mm_crc32_u32`; ARM ARMv8 `__crc32cw` |
| LZ77 back-copy distance > 16 B | **Yes** | Non-overlapping → SIMD memcpy; compiler auto-vectorizes |
| LZ77 back-copy distance ≤ 16 B | No | Overlapping (self-referential) — must be scalar |
| Huffman symbol decode | Limited | Table-driven 15-bit lookup; serial by nature |
| Adler32 | **Yes** | SSE2/NEON dot-product (used by zlib-ng) |

### 4.3 Decompressor Backend

**Current state (2025):** The production backend is **linflate** — a shared SIMD
DEFLATE engine extracted from this project into
[linflate-rs](https://codeberg.org/nordisk/znippy). It provides AVX-512,
AVX2, and scalar paths. `miniz_oxide` is no longer a production dependency
(retained in dev-dependencies for benchmarking only).

The optional `zlib-ng` feature flag remains available for comparison benchmarking:

```toml
[dependencies]
linflate = { path = "../linflate-rs" }           # default, always available
flate2 = { version = "1", optional = true, features = ["zlib-ng-compat"] }

[features]
default = []
zlib-ng = ["dep:flate2"]
```

---

## Rule 5 — Zero-Copy

### 5.1 Zero-Copy Compressed Input

Mirrors lbzip2-rs `lbunzip2.rs` exactly: workers receive a raw `*const u8` pointer
into the ring-buffer slot. The compressed data is **never copied** to workers —
they read directly from the slot memory.

Slot lifetime is guaranteed by the collector: the slot is not recycled until
`done_count == decode_segments` for that `chunk_id`.

### 5.2 Zero-Copy Decompressed Output

Mirror lbzip2-rs's `decode_block_into` pattern:

```rust
// Reserve spare capacity; write directly into it; adjust len after.
output.reserve(segment_cap);
let cur = output.len();
unsafe { output.set_len(cur + segment_cap); }
let written = inflate_into(&compressed, &mut output[cur..])?;
unsafe { output.set_len(cur + written); }
```

No intermediate `Vec` → no extra copy between decompressor output and segment buffer.

### 5.3 Zero-Copy is the Primary Design Goal

Zero-copy throughout is what lzip-rs is built for, same as lbzip2-rs. katana-osm
and Holger's artifact will use lzip-rs through the zero-copy pipeline — workers
decompress directly to pre-allocated output areas, writer thread receives data
with no intermediate copy.

The convenience APIs (`decompress_zip`, `decompress_zip_stream`) exist for testing
and simple callers, but the production pipeline is zero-copy end to end.

### 5.4 API Shape (both paths)

```rust
// Internal — used by pipeline workers (zero-copy write into segment Vec)
pub fn inflate_entry_into(compressed: &[u8], out: &mut Vec<u8>) -> Result<usize, ZipError>;

// External — convenience, allocates
pub fn decompress_zip(data: &[u8]) -> Result<Vec<ZipEntry>, ZipError>;
pub fn decompress_zip_stream<R: Read + Seek>(src: R) -> Result<Vec<ZipEntry>, ZipError>;
pub struct StreamingZipRead<R: Read + Seek>;  // Iterator<Item = Result<ZipEntry, ZipError>>
```

---

## Rule 6 — File Creation: Single Writer Thread via Channel

Mirrors lbzip2-rs's writer pipeline exactly.

### 6.1 Pipeline

```
Workers ──(segment, chunk_id, segment_id, data)──→ Collector
                                                        │
                                              assemble in chunk_id order
                                                        │
                                           ──(entry_name, uncompressed_data)──→ Writer thread
                                                        │
                                                 write file at known offset
                                                        │
                                           recycle slot → Reader
```

### 6.2 Writer Thread

Single dedicated thread receives `(path, data)` or `(path, offset, data)` via
`mpsc::SyncSender`. No locking on the output side:

```rust
let (write_tx, write_rx) = mpsc::sync_channel::<WriteMsg>(RING_SLOTS);

// Writer thread
std::thread::spawn(move || {
    for msg in write_rx {
        match msg {
            WriteMsg::Entry { path, data } => {
                std::fs::write(&path, &data).expect("write entry");
            }
        }
    }
});
```

### 6.3 Zero-Copy Offset Variant

Since each ZIP entry's uncompressed size is known from the Central Directory
**before** decompression begins, the writer can:

1. Pre-allocate an output buffer (or mmap) of total uncompressed size.
2. Workers decompress directly into `output[entry_uncompressed_offset..]`.
3. Writer thread receives `(entry_index, written_len)` confirmation only —
   **no data copy**, just offset tracking.

This mirrors lbzip2-rs's `data_ptr` approach: the pre-allocated slab is the
equivalent of the ring-buffer slot for output.

### 6.4 Ordering

The collector tracks `chunk_id` / `segment_id` in-flight, identical to lbzip2-rs:
- Out-of-order completions are held until the previous chunk_id is fully written.
- Collector flushes contiguous completed chunks to the writer in sequence.
- No barrier at the worker level — a worker that finishes early immediately picks
  up the next available work item.

---

## Full Pipeline Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         ZIP Central Directory                            │
│              seek to tail → parse once → sort by file offset             │
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │ Vec<EntryLocation>
                    ┌─────────────▼──────────────┐
                    │       Entry Dispatcher      │
                    │  size < 4 MB → Rule 3 task  │
                    │  size ≥ 4 MB → Rule 2 slots │
                    └──────┬──────────────────────┘
                           │
     ┌─────────────────────▼──────────────────────┐
     │           6-Slot Ring Buffer                │  pre-allocated
     │  slot = 32 MB carry headroom + 200 MB data  │  recycled by collector
     └──────────────┬──────────────────────────────┘
                    │
     ┌──────────────▼──────────────┐
     │   Reader Thread              │  fills slots sequentially
     │   reads entry bytes from     │  200 MB / slot
     │   ZIP via seek               │
     └──────────────┬──────────────┘
                    │ filled slot + carry prepended
     ┌──────────────▼──────────────┐
     │   Main Thread                │
     │   parallel full-flush scan   │  N−1 rayon tasks
     │   → up to N−1 split points   │  ~500 bytes forward each
     │   compute carry for next slot│
     │   post WorkItems (zero-copy) │
     └──────────────┬──────────────┘
                    │ WorkItem { data_ptr, start, end }
     ┌──────────────▼──────────────┐
     │   N Worker Threads           │  work-stealing, no barrier
     │   miniz_oxide inflate_into   │  zero-copy read from slot
     │   → Vec<u8> segment output   │  direct write to output Vec
     └──────────────┬──────────────┘
                    │ SegmentResult { chunk_id, segment_id, data }
     ┌──────────────▼──────────────┐
     │   Collector Thread           │  single channel, no polling
     │   reassemble in chunk order  │
     │   flush complete chunks      │
     │   recycle slot to reader     │
     └──────────────┬──────────────┘
                    │ WriteMsg { path | offset, data }
     ┌──────────────▼──────────────┐
     │   Writer Thread              │  single thread, no locking
     │   write entry to disk        │  sequential or by offset
     │   (or zero-copy offset into  │
     │    pre-allocated output slab)│
     └─────────────────────────────┘
```

---

## Open Questions (resolved)

- **Q1 ✓** No look-behind — forward scan trusted as-is (same as lbzip2-rs).
- **Q2 ✓** 6 ring slots, 200 MB chunk, 32 MB carry headroom.
- **Q3 ✓** Small entries = single-worker task from pool; no separate queue.
- **Q4 ✓** Use zlib-ng via `flate2` as optional feature; default stays `miniz_oxide`.

---

## Implementation Status (2026-05-19)

### What is implemented

| Component                                            | Status |
|------------------------------------------------------|--------|
| DEFLATE full-flush scanner (`deflate_scan.rs`)       | ✅ done |
| Parallel split-point search (`split_boundaries_parallel`) | ✅ done — N rayon tasks, no oversplit |
| Chunk split + parallel segment decode (`chunk.rs`)   | ✅ done — `decode_chunk` uses rayon `par_iter` |
| `decode_segment_into` (linflate)                     | ✅ done — handles non-final segments |
| Central Directory parser (`central_dir.rs`)          | ✅ done (incl. ZIP64) |
| Streaming reader (`reader.rs`)                       | ✅ done |
| Library API (`decompress_zip`, `decompress_zip_stream`) | ✅ done |
| Dedicated rayon pool (`lzip::thread_pool`)           | ✅ done |
| Physical-core detection (Linux sysfs)                | ✅ done |
| Carry mechanism (Rule 2.2)                           | ✅ done — single slot reused |
| Z_FULL_FLUSH absent → single-core fallback (Rule 1)  | ✅ done |
| **Full pipeline binary (`src/bin/lzip.rs`)`)**         | ✅ done (v1) |
| Dedicated reader thread                              | ✅ done |
| N dedicated decoder threads on shared channel        | ✅ done — `Arc<Mutex<Receiver<WorkItem>>>` |
| Dedicated collector thread                           | ✅ done |
| Dedicated writer thread                              | ✅ done |
| 6-slot ring buffer cycling via channel               | ✅ done |
| Concurrent in-flight chunks                          | ✅ done (up to 6) |
| No-flush fallback (accumulate + single segment)      | ✅ done |

### What is NOT yet implemented

| Property                                       | Status |
|------------------------------------------------|--------|
| Zero-copy decompressed output (DESIGN Rule 5.2 + 6.3) | ❌ workers allocate `Vec<u8>` per segment |
| Benchmark harness (B5)                         | ❌ not started |
| `zlib-ng` feature flag (Rule 4.3)              | ❌ not started |
