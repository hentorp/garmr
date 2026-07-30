//! bzip2 block decoder.
//!
//! Decodes a single bzip2 compressed block given a `BitReader` positioned
//! right after the 48-bit block magic (0x314159265359).
//!
//! Designed for parallel use: each worker gets a byte slice + bit offset,
//! decodes independently, returns decompressed `Vec<u8>`.

use crate::bitreader::BitReader;
use crate::bwt;
use crate::huffman::HuffmanTree;
use crate::mtf::MtfDecoder;

use std::cell::RefCell;

/// Maximum block size: 9 × 100,000 bytes.
const MAX_BLOCKSIZE: usize = 900_000;
/// Maximum number of selectors (15-bit field, practical limit ~18001).
const MAX_SELECTORS: usize = 18002;

thread_local! {
    // A STACK of reusable `tt` buffers, not a single slot. The single-thread MLP
    // decode ([`decode_blocks_interleaved`]) keeps several blocks' `tt` arrays alive
    // at once (N chains interleaved), so the pool must serve that many buffers
    // concurrently. Balanced take/return keeps the stack depth at ~N; each buffer
    // retains its capacity across reuse. The multi-worker (serial) path pushes/pops
    // a single buffer, byte-identical to the old single-slot behaviour.
    static TT_POOL: RefCell<Vec<Vec<u32>>> = const { RefCell::new(Vec::new()) };
    // Reusable per-block RLE1 output scratch buffers, used ONLY by the interleaved
    // single-thread path (each chain writes into its own buffer, then the buffers are
    // copied into the segment output in stream order).
    static OUT_POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Take a `tt` buffer from the thread-local pool, avoiding repeated heap allocation.
fn take_tt_buffer(capacity: usize) -> Vec<u32> {
    let mut buf = TT_POOL
        .with(|cell| cell.borrow_mut().pop())
        .unwrap_or_default();
    buf.clear();
    if buf.capacity() < capacity {
        buf.reserve(capacity - buf.len());
    }
    buf
}

/// Return a `tt` buffer to the thread-local pool for reuse.
fn return_tt_buffer(buf: Vec<u32>) {
    TT_POOL.with(|cell| cell.borrow_mut().push(buf));
}

/// Take a per-block RLE1 output scratch buffer from the thread-local pool
/// (interleaved single-thread path only).
fn take_out_buffer() -> Vec<u8> {
    OUT_POOL
        .with(|cell| cell.borrow_mut().pop())
        .unwrap_or_default()
}

/// Return a per-block RLE1 output scratch buffer to the thread-local pool.
fn return_out_buffer(buf: Vec<u8>) {
    OUT_POOL.with(|cell| cell.borrow_mut().push(buf));
}

/// Error type for block decoding.
#[derive(Debug)]
pub struct BlockError(pub &'static str);

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bzip2 block error: {}", self.0)
    }
}

impl std::error::Error for BlockError {}

/// bzip2 CRC-32 table (polynomial 0x04C11DB7, MSB-first — *not* the reflected
/// gzip/zlib variant). Built once at compile time.
const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ 0x04C1_1DB7
            } else {
                c << 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = make_crc_table();

/// Compute the bzip2 block CRC over decompressed bytes (MSB-first CRC-32,
/// init/final XOR 0xFFFFFFFF).
///
/// Exposed to the crate so the stream decoder can fold each block's CRC into the
/// combined stream CRC and verify it against the stored value after FINAL_MAGIC.
pub(crate) fn block_crc(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc = crc_update(crc, b);
    }
    !crc
}

/// Single-byte bzip2 CRC-32 step (MSB-first). Folded directly into the RLE1 emit
/// loops (`rle2_decode_append`, `chain_process`) so each output byte is CRC'd while
/// still hot in a register — replacing a second full byte-at-a-time pass over the
/// (up to ~1 GB) decompressed output that re-read long-evicted data from L3/DRAM.
/// The running CRC is seeded with `0xFFFF_FFFF` and finalized with a bitwise NOT,
/// exactly matching [`block_crc`].
#[inline(always)]
fn crc_update(crc: u32, b: u8) -> u32 {
    (crc << 8) ^ CRC_TABLE[(((crc >> 24) ^ (b as u32)) & 0xFF) as usize]
}

/// Decode header + Huffman + MTF + RLE1 → inverse BWT, returning (tt, t_pos, crc).
/// `crc` is the block's stored CRC-32, to be checked against the decompressed bytes.
/// Shared logic for both `decode_block` and `decode_block_into`.
fn decode_block_common(
    reader: &mut BitReader<'_>,
    max_blocksize: u32,
) -> Result<(Vec<u32>, u32, u32), BlockError> {
    // ── Block header ──────────────────────────────────────────────────────
    let expected_crc = reader
        .read_u32(32)
        .ok_or(BlockError("block CRC truncated"))?;

    let randomised = reader
        .read_bit()
        .ok_or(BlockError("randomised flag truncated"))?;
    if randomised {
        return Err(BlockError("randomised blocks not supported"));
    }

    let orig_ptr = reader
        .read_u32(24)
        .ok_or(BlockError("orig_ptr truncated"))? as usize;

    // ── Symbol bitmap (which bytes appear in this block) ──────────────────
    let mut used_bytes = [0u8; 256];
    let mut n_used: usize = 0;

    // 16 range flags: each covers 16 byte values.
    let mut ranges_present = [false; 16];
    for range in &mut ranges_present {
        *range = reader
            .read_bit()
            .ok_or(BlockError("symbol range truncated"))?;
    }

    for (range_idx, &present) in ranges_present.iter().enumerate() {
        if !present {
            continue;
        }
        for sub in 0..16u8 {
            if reader
                .read_bit()
                .ok_or(BlockError("symbol bitmap truncated"))?
            {
                used_bytes[n_used] = range_idx as u8 * 16 + sub;
                n_used += 1;
            }
        }
    }

    if n_used == 0 {
        return Err(BlockError("no symbols in block"));
    }

    let n_symbols = n_used + 2; // +2 for RUNA, RUNB; EOB = n_symbols - 1

    // ── Huffman table selectors ───────────────────────────────────────────
    let n_groups = reader
        .read_u8(3)
        .ok_or(BlockError("huffman groups truncated"))?;
    if n_groups < 2 || n_groups > 6 {
        return Err(BlockError("invalid number of huffman groups"));
    }

    let n_selectors = reader
        .read_u16(15)
        .ok_or(BlockError("selectors_used truncated"))? as usize;
    if n_selectors > MAX_SELECTORS {
        return Err(BlockError("too many selectors"));
    }

    let mut selectors = [0u8; MAX_SELECTORS];
    let mut sel_mtf = MtfDecoder::new();
    for i in 0..n_selectors {
        let mut trees = 0u8;
        while reader
            .read_bit()
            .ok_or(BlockError("selector bit truncated"))?
        {
            trees += 1;
            if trees >= n_groups {
                return Err(BlockError("selector tree index too large"));
            }
        }
        selectors[i] = sel_mtf.decode(trees);
    }

    // ── Huffman code lengths → trees ──────────────────────────────────────
    let mut trees = [const { HuffmanTree::empty() }; 6];
    let mut n_trees: usize = 0;
    for _ in 0..n_groups {
        let mut length = reader
            .read_u8(5)
            .ok_or(BlockError("huffman start length truncated"))? as i32;
        let mut lengths = [0u8; 258];

        for j in 0..n_symbols {
            loop {
                if length < 1 || length > 20 {
                    return Err(BlockError("huffman code length out of range"));
                }
                if !reader
                    .read_bit()
                    .ok_or(BlockError("length adjust bit1 truncated"))?
                {
                    break;
                }
                if reader
                    .read_bit()
                    .ok_or(BlockError("length adjust bit2 truncated"))?
                {
                    length -= 1;
                } else {
                    length += 1;
                }
            }
            lengths[j] = length as u8;
        }

        trees[n_trees] = HuffmanTree::from_lengths(&lengths[..n_symbols])
            .map_err(|_| BlockError("invalid huffman tree"))?;
        n_trees += 1;
    }

    // ── Huffman decode → MTF + RLE1 decode → tt array ─────────────────────
    // Perf: `take_tt_buffer(max_blocksize)` guarantees capacity >= max_blocksize
    // (it reserves up front and never shrinks below it). We fill the buffer via
    // raw pointer writes into that reserved spare capacity and track the length
    // in `tt_len`, calling `set_len` once at the very end. This removes the
    // per-symbol `Vec::push`/`resize` capacity/realloc branch from the hot loop
    // (mirroring the RLE2 stage in `rle2_decode_*`). The existing per-symbol /
    // per-run `<= max_blocksize` guards keep every write in-bounds.
    let mut tt: Vec<u32> = take_tt_buffer(max_blocksize as usize);
    debug_assert!(tt.capacity() >= max_blocksize as usize);
    let tt_ptr = tt.as_mut_ptr();
    let mut tt_len: usize = 0; // logical length; tt.set_len is called once below
    let mut c = [0u32; 256]; // byte frequency counts for BWT

    // Build MTF decoder with the actual used-byte alphabet.
    let mut byte_symbols = [0u8; 256];
    byte_symbols[..n_used].copy_from_slice(&used_bytes[..n_used]);
    let mut mtf = MtfDecoder::with_symbols(byte_symbols);

    let mut sel_idx: usize = 0;
    let mut current_tree = &trees[selectors[0] as usize];

    let mut repeat: u32 = 0;
    let mut repeat_power: u32 = 0;

    let eob_symbol = (n_symbols - 1) as u16;

    'outer: loop {
        for _ in 0..50 {
            let sym = current_tree
                .decode(reader)
                .ok_or(BlockError("huffman bitstream truncated"))?;

            // RUNA (0) or RUNB (1): run-length encoding.
            if sym < 2 {
                if repeat == 0 {
                    repeat_power = 1;
                }
                repeat += repeat_power << sym;
                repeat_power <<= 1;

                if repeat as usize > MAX_BLOCKSIZE {
                    return Err(BlockError("repeat count too large"));
                }
                continue;
            }

            // Flush pending run.
            if repeat > 0 {
                let b = mtf.first();
                if tt_len + repeat as usize > max_blocksize as usize {
                    return Err(BlockError("data exceeds block size"));
                }
                // Raw fill: write `repeat` copies of b into the reserved buffer.
                // In-bounds by the guard above (tt_len + repeat <= max_blocksize
                // <= capacity).
                let val = u32::from(b);
                unsafe {
                    let mut p = tt_ptr.add(tt_len);
                    for _ in 0..repeat {
                        p.write(val);
                        p = p.add(1);
                    }
                }
                tt_len += repeat as usize;
                c[b as usize] += repeat;
                repeat = 0;
            }

            // EOB: end of block.
            if sym == eob_symbol {
                break 'outer;
            }

            // Regular symbol: MTF decode.
            let b = mtf.decode((sym - 1) as u8);
            if tt_len >= max_blocksize as usize {
                return Err(BlockError("data exceeds block size"));
            }
            // Raw single write into reserved capacity (in-bounds by the guard).
            unsafe {
                tt_ptr.add(tt_len).write(u32::from(b));
            }
            tt_len += 1;
            c[b as usize] += 1;
        }

        // Switch Huffman table for next group of 50 symbols.
        sel_idx += 1;
        if sel_idx >= n_selectors {
            return Err(BlockError("ran out of selectors"));
        }
        let sel = selectors[sel_idx] as usize;
        if sel >= n_trees {
            return Err(BlockError("selector out of range"));
        }
        current_tree = &trees[sel];
    }

    // Commit the raw-written entries as the Vec's length. Safe: we wrote
    // tt_len contiguous u32 values starting at offset 0, all within the
    // reserved capacity, and never reallocated (no push/reserve in the loop).
    unsafe {
        tt.set_len(tt_len);
    }

    if orig_ptr >= tt_len {
        return Err(BlockError("orig_ptr out of bounds"));
    }

    // ── Inverse BWT ───────────────────────────────────────────────────────
    // A consistency-checked chase: a mis-decoded block whose byte histogram
    // does not match `tt` is rejected here rather than scattering/reading out
    // of bounds (which would SIGSEGV the process).
    let t_pos = bwt::inverse_bwt(&mut tt, orig_ptr, c).ok_or(BlockError(
        "inverse-BWT: inconsistent byte counts (corrupt or mis-decoded block)",
    ))?;

    Ok((tt, t_pos, expected_crc))
}

/// RLE1-reverse (the final bzip2 stage) from tt[], **appending** onto `out` and
/// growing it as needed, and returning the block's finalized CRC-32.
///
/// Uses raw pointer writes; the inner dependent-load pointer-chase
/// `entry = tt[t_pos]; t_pos = entry >> 8` is irreducible — DO NOT CHANGE the reads.
///
/// CRC fold: every emitted byte is CRC'd inline via [`crc_update`] while still hot in
/// a register (like libbzip2's `BZ_UPDATE_CRC` inside `unRLE_obuf_to_output_FAST`), so
/// there is NO separate byte-at-a-time pass over the (up to ~1 GB) decompressed output
/// afterward — that pass re-read long-evicted data from L3/DRAM and was the code
/// review's #1 target. The returned value is the finalized block CRC (init
/// `0xFFFF_FFFF`, final NOT), identical to `block_crc(emitted bytes)`.
///
/// Growth is mandatory, not a micro-opt: bzip2's block-size limit bounds the
/// RLE1-*encoded* stream (the ≤ `max_blocksize` bytes fed into the BWT), but this
/// stage *reverses* RLE1, and a 5-byte run marker `b b b b <count>` expands to up
/// to 259 output bytes (~52×). A highly-repetitive-but-perfectly-valid block —
/// e.g. the long whitespace / tag runs in planet OSM-XML — therefore decodes to
/// many times `max_blocksize`. A fixed `max_blocksize + 25%` buffer is NOT a valid
/// bound; assuming it overflowed the segment buffer on real planet input (an
/// assert-panic on the checked path, a raw heap overrun / SIGSEGV on the lenient
/// convert path). Appending into a growable `Vec` is the only correct sink.
fn rle2_decode_append(tt: &[u32], mut t_pos: u32, out: &mut Vec<u8>) -> u32 {
    let n = tt.len();
    let start = out.len();
    // First-guess capacity: the overwhelmingly common block is ≤ 1.25×. The
    // count-run branch below grows on demand for the pathological case.
    out.reserve(n + n / 4 + 1);
    let mut out_len: usize = start;
    let tt_ptr = tt.as_ptr();
    // Hoist the write base and capacity out of the per-byte path — `out.as_mut_ptr()`
    // and `out.capacity()` were reloaded from the Vec header every byte. Refresh both
    // ONLY on a reserve (the sole realloc site), which is rare.
    let mut base = out.as_mut_ptr();
    let mut cap = out.capacity();
    let mut crc: u32 = 0xFFFF_FFFF;
    // `last_byte` as a u16 with a 0x100 sentinel = "no previous byte" (initially, and
    // reset after every run). Folds the old `has_last` bool + `u8` into one compare, so
    // the per-byte run-detect is a single `last_byte == b` with no extra `has_last &&`.
    let mut last_byte: u16 = 0x100;
    let mut byte_repeats: u8 = 0;

    for _ in 0..n {
        let entry = unsafe { *tt_ptr.add(t_pos as usize) };
        let b = entry as u8;
        t_pos = entry >> 8;

        if byte_repeats == 3 {
            let count = b as usize;
            // Ensure `count` for this run PLUS `n` trailing bytes of slack — the max
            // number of single-byte literals that can follow before the next run (there
            // are only `n` iterations total). That invariant lets the literal path below
            // write UNCHECKED: no per-byte capacity branch.
            if out_len + count + n > cap {
                unsafe {
                    out.set_len(out_len);
                }
                out.reserve(count + n + 1);
                base = out.as_mut_ptr();
                cap = out.capacity();
            }
            let ch = last_byte as u8;
            unsafe {
                std::ptr::write_bytes(base.add(out_len), ch, count);
            }
            // CRC the run's `count` copies (still cheaper than re-reading the whole
            // decompressed output in a separate pass).
            let mut i = 0;
            while i < count {
                crc = crc_update(crc, ch);
                i += 1;
            }
            out_len += count;
            byte_repeats = 0;
            last_byte = 0x100; // run consumed → no previous byte
            continue;
        }

        if last_byte == b as u16 {
            byte_repeats += 1;
        } else {
            byte_repeats = 0;
        }
        last_byte = b as u16;
        crc = crc_update(crc, b);
        // Unchecked: the initial `reserve(n + n/4)` and the run path both guarantee
        // ≥ `n` bytes of trailing slack, and ≤ `n` literals ever follow, so this write
        // is always in bounds.
        unsafe {
            *base.add(out_len) = b;
        }
        out_len += 1;
    }

    unsafe {
        out.set_len(out_len);
    }
    !crc
}

/// RLE1-reverse into a freshly allocated `Vec<u8>` (sequential/whole-block path).
/// Returns the decoded bytes and the block's finalized CRC-32.
fn rle2_decode_alloc(tt: &[u32], t_pos: u32) -> (Vec<u8>, u32) {
    let mut output = Vec::new();
    let crc = rle2_decode_append(tt, t_pos, &mut output);
    (output, crc)
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory-level parallelism (MLP) — interleaved multi-block inverse-BWT chase.
// SINGLE-THREAD ONLY (gated by the caller): at 12 cores the decode is memory-
// bandwidth-bound so this is neutral-to-harmful, but on ONE core it hides the
// dependent-load latency and nearly doubles throughput.
//
// The bottleneck of `rle2_decode_append` is the serial dependent-load chain
// `entry = tt[t_pos]; t_pos = entry >> 8`: each load's ADDRESS depends on the
// previous load's RESULT, so they cannot overlap and the loop is pinned at DRAM/
// L3 latency per step. Each bzip2 BLOCK, however, has its OWN independent chain.
// By stepping several blocks' chains in lockstep within one worker — issue all N
// loads, then process all N results — the N loads are mutually independent and
// their memory latencies OVERLAP in the out-of-order window (memory-level
// parallelism), hiding the per-step stall behind the others.
//
// Output bytes of each block must still land in stream order, so each chain writes
// into its OWN scratch buffer and the buffers are copied into the segment output in
// stream order afterward (a cheap sequential streaming copy, not latency-bound).
// ─────────────────────────────────────────────────────────────────────────────

/// The parsed core of one bzip2 block: its inverse-BWT `tt` array, the initial
/// traversal position, and the stored CRC-32. Produced by [`decode_block_core`]
/// (header + Huffman + MTF + RLE2 + inverse-BWT), consumed by
/// [`decode_blocks_interleaved`] (the RLE1 pointer-chase, done N-at-a-time).
pub(crate) struct BlockCore {
    tt: Vec<u32>,
    t_pos: u32,
    crc: u32,
}

/// Decode a block up to (and including) the inverse BWT, returning its [`BlockCore`]
/// WITHOUT running the final RLE1 pointer-chase. This is the "gather" half of the
/// single-thread MLP decode: a segment gathers up to `N` cores (advancing the
/// bitstream sequentially), then chases them interleaved via
/// [`decode_blocks_interleaved`].
pub(crate) fn decode_block_core(
    reader: &mut BitReader<'_>,
    max_blocksize: u32,
) -> Result<BlockCore, BlockError> {
    let (tt, t_pos, crc) = decode_block_common(reader, max_blocksize)?;
    Ok(BlockCore { tt, t_pos, crc })
}

/// Live state of one block's RLE1 pointer-chase. Mirrors the locals of
/// [`rle2_decode_append`] exactly (same capacity/slack invariants); the only
/// difference is that several `Chain`s are advanced in lockstep to overlap their
/// dependent loads. `tt` is retained so its buffer can be returned to the pool.
struct Chain {
    tt_ptr: *const u32,
    t_pos: u32,
    /// tt entries still to consume (starts at tt.len()).
    remaining: u32,
    /// The entry loaded this lockstep round, consumed by `chain_process`.
    pending: u32,
    out: Vec<u8>,
    out_len: usize,
    base: *mut u8,
    cap: usize,
    last_byte: u16,
    byte_repeats: u8,
    n: usize,
    /// Original stream order, to restore after the chase (which reorders by length).
    order: u32,
    /// The block's stored (expected) CRC-32.
    crc: u32,
    /// Running CRC-32 folded over emitted bytes (Phase 1); finalized with NOT and
    /// compared against `crc` after the chase — no separate output re-read pass.
    crc_acc: u32,
    tt: Vec<u32>,
}

/// Process ONE already-loaded tt `entry` for a chain: the RLE1-reverse state
/// machine + output write. Byte-for-byte identical to the body of
/// [`rle2_decode_append`] (minus the load, which the caller issued). Kept separate
/// from the load so the caller can issue all N chains' loads back-to-back first.
#[inline(always)]
fn chain_process(c: &mut Chain, entry: u32) {
    let b = entry as u8;

    if c.byte_repeats == 3 {
        let count = b as usize;
        if c.out_len + count + c.n > c.cap {
            unsafe {
                c.out.set_len(c.out_len);
            }
            c.out.reserve(count + c.n + 1);
            c.base = c.out.as_mut_ptr();
            c.cap = c.out.capacity();
        }
        let ch = c.last_byte as u8;
        unsafe {
            std::ptr::write_bytes(c.base.add(c.out_len), ch, count);
        }
        let mut crc = c.crc_acc;
        let mut i = 0;
        while i < count {
            crc = crc_update(crc, ch);
            i += 1;
        }
        c.crc_acc = crc;
        c.out_len += count;
        c.byte_repeats = 0;
        c.last_byte = 0x100;
        return;
    }

    if c.last_byte == b as u16 {
        c.byte_repeats += 1;
    } else {
        c.byte_repeats = 0;
    }
    c.last_byte = b as u16;
    c.crc_acc = crc_update(c.crc_acc, b);
    unsafe {
        *c.base.add(c.out_len) = b;
    }
    c.out_len += 1;
}

/// Drive a slice of ACTIVE chains (each with `remaining >= steps`) for `steps`
/// lockstep iterations. Each iteration issues every chain's dependent load FIRST
/// (all mutually independent → their latencies overlap), then processes the loaded
/// entries. This is the memory-level-parallelism hot loop.
#[inline]
fn lockstep(active: &mut [Chain], steps: u32) {
    for _ in 0..steps {
        for c in active.iter_mut() {
            let e = unsafe { *c.tt_ptr.add(c.t_pos as usize) };
            c.t_pos = e >> 8;
            c.pending = e;
        }
        for c in active.iter_mut() {
            let e = c.pending;
            chain_process(c, e);
        }
    }
    for c in active.iter_mut() {
        c.remaining -= steps;
    }
}

/// Run the interleaved chase over all chains to completion. Chains are sorted by
/// remaining length so the active set is a contiguous suffix; each lockstep round
/// runs `min(remaining)` iterations (retiring at least the shortest chain) over the
/// whole active set, preserving overlap for as long as ≥2 chains remain.
fn chase_all(chains: &mut [Chain]) {
    chains.sort_by_key(|c| c.remaining);
    let k = chains.len();
    let mut done = 0usize;
    while done < k {
        if chains[done].remaining == 0 {
            done += 1;
            continue;
        }
        let step = chains[done].remaining;
        lockstep(&mut chains[done..k], step);
        while done < k && chains[done].remaining == 0 {
            done += 1;
        }
    }
}

/// MLP decode of a batch of gathered block cores (single-thread path): chase all of
/// them interleaved, then CRC-verify and append their decompressed bytes into
/// `output` in STREAM ORDER (the order of `cores`), pushing each verified CRC into
/// `block_crcs`.
///
/// On a CRC mismatch the batch's earlier (in-order) blocks are already appended;
/// the failing block's bytes are NOT appended and the error is returned — matching
/// the per-block truncate-and-error behaviour of [`decode_block_into`]. Every `tt`
/// and output scratch buffer is returned to the thread-local pools regardless.
pub(crate) fn decode_blocks_interleaved(
    cores: &mut Vec<BlockCore>,
    output: &mut Vec<u8>,
    block_crcs: &mut Vec<u32>,
) -> Result<(), BlockError> {
    let m = cores.len();
    let mut chains: Vec<Chain> = Vec::with_capacity(m);
    for (i, core) in cores.drain(..).enumerate() {
        let tt = core.tt;
        let n = tt.len();
        let tt_ptr = tt.as_ptr();
        let mut out = take_out_buffer();
        out.clear();
        // Same first-guess capacity + trailing-slack invariant as rle2_decode_append.
        out.reserve(n + n / 4 + 1);
        let base = out.as_mut_ptr();
        let cap = out.capacity();
        chains.push(Chain {
            tt_ptr,
            t_pos: core.t_pos,
            remaining: n as u32,
            pending: 0,
            out,
            out_len: 0,
            base,
            cap,
            last_byte: 0x100,
            byte_repeats: 0,
            n,
            order: i as u32,
            crc: core.crc,
            crc_acc: 0xFFFF_FFFF,
            tt,
        });
    }

    // The interleaved memory-level-parallel chase.
    chase_all(&mut chains);

    // Restore stream order for in-order CRC-check + append.
    chains.sort_by_key(|c| c.order);
    for c in chains.iter_mut() {
        // Commit the raw-written bytes as the scratch Vec's length.
        unsafe {
            c.out.set_len(c.out_len);
        }
    }

    let mut err: Option<BlockError> = None;
    for c in chains.into_iter() {
        if err.is_none() {
            if !c.crc_acc != c.crc {
                err = Some(BlockError("block CRC mismatch"));
            } else {
                output.extend_from_slice(&c.out);
                block_crcs.push(c.crc);
            }
        }
        return_tt_buffer(c.tt);
        return_out_buffer(c.out);
    }

    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Decode one bzip2 block.
///
/// `reader` must be positioned right after the 48-bit block magic.
/// `max_blocksize` comes from the stream header (100_000 × blocksize_level).
///
/// Returns the fully decompressed block data.
pub fn decode_block(reader: &mut BitReader<'_>, max_blocksize: u32) -> Result<Vec<u8>, BlockError> {
    let (tt, t_pos, expected_crc) = decode_block_common(reader, max_blocksize)?;
    let (output, crc) = rle2_decode_alloc(&tt, t_pos);
    return_tt_buffer(tt);
    if crc != expected_crc {
        return Err(BlockError("block CRC mismatch"));
    }
    Ok(output)
}

/// Decode one bzip2 block, **appending** its bytes to `out` (which grows as
/// needed). Zero per-block temporary `Vec`: the segment buffer is extended in
/// place. The decoded size is data-dependent and can exceed `max_blocksize` by a
/// large factor (see [`rle2_decode_append`]), so `out` MUST be a growable `Vec`,
/// never a fixed slice.
///
/// Returns `(bytes_written, block_crc)` where `block_crc` is the block's verified
/// CRC-32 (equal to the stored value — a mismatch is returned as an error, never
/// silently accepted, and `out` is rolled back to its pre-block length). Callers
/// fold the returned CRC into the running combined stream CRC so the whole-stream
/// checksum can be verified on the parallel path.
pub fn decode_block_into(
    reader: &mut BitReader<'_>,
    max_blocksize: u32,
    out: &mut Vec<u8>,
) -> Result<(usize, u32), BlockError> {
    let (tt, t_pos, expected_crc) = decode_block_common(reader, max_blocksize)?;
    let start = out.len();
    let crc = rle2_decode_append(&tt, t_pos, out);
    return_tt_buffer(tt);
    let written = out.len() - start;
    if crc != expected_crc {
        out.truncate(start);
        return Err(BlockError("block CRC mismatch"));
    }
    Ok((written, expected_crc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_known_block() {
        // Use a real bzip2 file: compress "Hello, World!\n" and decode.
        // This is a minimal integration test.
        let compressed = include_bytes!("../test_data/hello.bz2");
        let expected = b"Hello, World!\n";

        // Parse header (4 bytes: "BZh9").
        assert_eq!(&compressed[..3], b"BZh");
        let level = compressed[3] - b'0';
        let max_blocksize = 100_000 * level as u32;

        // Skip header, read block magic.
        let mut reader = BitReader::from_bit_offset(compressed, 4 * 8);
        let magic = reader.read_u64(48).unwrap();
        assert_eq!(magic, crate::BLOCK_MAGIC, "expected block magic");

        let output = decode_block(&mut reader, max_blocksize).unwrap();
        assert_eq!(&output, expected);
    }
}
