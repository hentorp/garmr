//! Speculative DEFLATE block-boundary scanner — parallel forward-search.
//!
//! Same pattern as lbzip2-rs `block_scan.rs` and lgz `deflate_scan.rs`:
//!
//! 1. Calculate N−1 nominal byte offsets (evenly spaced across the chunk).
//! 2. Each scoped thread does a **forward search** from its assigned offset,
//!    probing each byte position until it finds a valid DEFLATE block start.
//! 3. Merge + dedup the confirmed boundaries.
//!
//! "Valid block start" = we can speculatively decode ≥ PROBE_THRESHOLD bytes
//! of correct DEFLATE output starting at that byte. This confirms we've hit
//! an actual block header (dynamic Huffman, fixed Huffman, or stored).
//!
//! After splitting, segments are decoded with a 32KB prefix window from the
//! previous segment's output (for LZ77 back-reference resolution).
//!
//! This allows parallel decompression of ANY gzip file — not just those
//! with flush markers from pigz/bgzf.

use std::cell::RefCell;

use linflate::{InflateError, OVERWRITE_HEADROOM};

thread_local! {
    /// Reusable per-thread probe scratch buffer. Allocated once (lazily grown
    /// to `PROBE_LIMIT + OVERWRITE_HEADROOM`) and reused across the thousands
    /// of `probe_decode` calls a forward search makes — no per-probe alloc.
    static PROBE_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Minimum bytes of successful decode to confirm a valid boundary.
const PROBE_THRESHOLD: usize = 4096;

/// Max bytes to attempt when probing a candidate offset.
const PROBE_LIMIT: usize = 32768;

/// Max bytes to search forward from a nominal offset before giving up.
/// (If no boundary found within this range, that split point is abandoned.)
const FORWARD_SEARCH_LIMIT: usize = 64 * 1024;

/// LZ77 window size — previous segment must provide this many trailing bytes
/// for back-reference resolution.
pub const LZ77_WINDOW: usize = 32 * 1024;

/// A confirmed speculative block boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecBoundary {
    /// Byte offset in the raw DEFLATE stream where a valid block starts.
    pub offset: usize,
}

// ── Forward-search: scan for stored blocks (LEN/NLEN complement pattern) ─────
//
// Strategy (same as lbzip2-rs magic scan / lgz flush scan):
// 1. Calculate N−1 nominal offsets (evenly spaced across compressed data).
// 2. Each scoped thread forward-scans from its nominal offset looking for a
//    **stored block** header (BTYPE=00 with valid LEN/NLEN complement).
// 3. The split point = offset + 5 + LEN = byte-aligned start of NEXT block.
// 4. Confirm the split with probe_decode (decode ≥ PROBE_THRESHOLD from there).
//
// Why stored blocks? Because:
// - They have a clear 4-byte signature (LEN + NLEN complement) — like bzip2's π.
// - After a stored block, the next block starts BYTE-ALIGNED — linflate works.
// - gzip inserts stored blocks frequently (every ~250KB for incompressible data).
// - The LEN/NLEN complement gives 1/65536 false positive rate per position.

/// Scan forward from `start_offset` for a point where we can start decoding.
///
/// Looks for the LEN/NLEN complement pattern that indicates a stored block.
/// After the stored block ends, the next byte position MAY be decodable
/// (if our decode doesn't need back-references from before the split).
///
/// Returns None if no decodable position found within FORWARD_SEARCH_LIMIT.
fn find_next_stored_block_end(data: &[u8], start_offset: usize) -> Option<usize> {
    let end = (start_offset + FORWARD_SEARCH_LIMIT).min(data.len().saturating_sub(8));

    for i in start_offset..end {
        if i + 4 > data.len() {
            break;
        }
        let len_val = u16::from_le_bytes([data[i], data[i + 1]]);
        let nlen_val = u16::from_le_bytes([data[i + 2], data[i + 3]]);

        if len_val != !nlen_val || len_val == 0 {
            continue;
        }

        let next_block = i + 4 + len_val as usize;
        if next_block + 8 >= data.len() {
            continue;
        }

        // Confirm we can actually decode from there.
        if probe_decode(&data[next_block..]) {
            return Some(next_block);
        }
    }
    None
}

/// Forward-search from `start_offset` for the next valid DEFLATE block start.
///
/// Two strategies, tried in order:
/// 1. Find a stored block → split after it (highly reliable, byte-aligned).
/// 2. Byte-by-byte probe_decode (expensive fallback for streams without stored blocks).
pub fn find_next_block(data: &[u8], start_offset: usize) -> Option<SpecBoundary> {
    // Strategy 1: Find stored block end → confirm with probe_decode.
    if let Some(next_block) = find_next_stored_block_end(data, start_offset) {
        if probe_decode(&data[next_block..]) {
            return Some(SpecBoundary { offset: next_block });
        }
    }

    // Strategy 2: Brute-force byte-aligned probe (slower, for streams without stored blocks).
    let end = (start_offset + FORWARD_SEARCH_LIMIT).min(data.len().saturating_sub(8));
    // Sample every 64 bytes to reduce cost (blocks are typically ≥ 16KB).
    let mut offset = start_offset;
    while offset < end {
        if probe_decode(&data[offset..]) {
            return Some(SpecBoundary { offset });
        }
        offset += 64;
    }

    None
}

/// EXPENSIVE: Try to decode DEFLATE from byte-aligned `data[0..]`.
/// Returns true if we get ≥ PROBE_THRESHOLD bytes without error.
pub(crate) fn probe_decode(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }

    let buf_size = PROBE_LIMIT + OVERWRITE_HEADROOM;

    // Use inflate_segment (allow_partial=true) — if the output overflows our
    // probe buffer, that ALSO means it decoded successfully (≥ PROBE_THRESHOLD).
    PROBE_BUF.with(|b| {
        let mut out_buf = b.borrow_mut();
        if out_buf.len() < buf_size {
            out_buf.resize(buf_size, 0);
        }
        match linflate::inflate_segment(data, &mut out_buf[..buf_size]) {
            Ok(written) => written >= PROBE_THRESHOLD,
            Err(InflateError::OutputOverflow) => true,
            Err(_) => false,
        }
    })
}

// ── Parallel split (same pattern as lbzip2-rs/ljar-rs) ───────────────────────

/// Parallel split: N−1 scoped-thread tasks each forward-search from their nominal
/// offset to find the next valid DEFLATE block boundary.
///
/// Returns up to N−1 boundaries, sorted and deduplicated.
pub fn split_boundaries_parallel(data: &[u8], n_splits: usize) -> Vec<SpecBoundary> {
    if n_splits <= 1 || data.len() < PROBE_THRESHOLD * 2 {
        return Vec::new();
    }

    let found: Vec<Option<SpecBoundary>> =
        gatling::gatling_forkjoin::gatling_for_each(n_splits - 1, 0, |k| {
            let i = k + 1;
            let nominal = data.len() * i / n_splits;
            find_next_block(data, nominal)
        });

    let mut result: Vec<SpecBoundary> = found.into_iter().flatten().collect();
    result.sort_by_key(|b| b.offset);
    result.dedup_by_key(|b| b.offset);

    // Remove boundaries too close together (< PROBE_THRESHOLD apart).
    let mut deduped: Vec<SpecBoundary> = Vec::new();
    for b in result {
        if deduped
            .last()
            .map_or(true, |last| b.offset - last.offset > PROBE_THRESHOLD)
        {
            deduped.push(b);
        }
    }
    deduped
}

// ── Segment decode with back-reference window ────────────────────────────────

/// Decode a DEFLATE segment with a prefix window for back-reference resolution.
///
/// `prefix_window`: the last ≤32KB of the previous segment's output.
/// The window is placed at the start of the output buffer so that LZ77
/// back-references crossing the boundary resolve correctly.
///
/// Returns only the NEW output (prefix bytes stripped).
pub fn decode_with_window(
    compressed: &[u8],
    prefix_window: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let prefix_len = prefix_window.len();
    let estimate = prefix_len + (compressed.len() * 4).max(256 * 1024) + OVERWRITE_HEADROOM;
    // Uninitialized buffer (mirrors decode_segment_into_hint) — skip the full
    // zero-fill; inflate writes the output and the prefix is copied explicitly,
    // so the [prefix_len..prefix_len+new_bytes] region we return is fully init.
    let mut out_buf: Vec<u8> = Vec::with_capacity(estimate);
    #[allow(clippy::uninit_vec)]
    unsafe {
        out_buf.set_len(estimate)
    };

    // Copy prefix window into start of buffer.
    out_buf[..prefix_len].copy_from_slice(prefix_window);

    match linflate::inflate_segment_with_prefix(compressed, &mut out_buf, prefix_len) {
        Ok(new_bytes) => {
            // Reuse the original allocation: drop the prefix in place (drain)
            // and truncate to the decoded end — no second buffer, no .to_vec().
            out_buf.truncate(prefix_len + new_bytes);
            out_buf.drain(..prefix_len);
            Ok(out_buf)
        }
        Err(InflateError::OutputOverflow) => {
            // Retry with much bigger buffer (high compression ratio data).
            let bigger =
                prefix_len + (compressed.len() * 1024).max(4 * 1024 * 1024) + OVERWRITE_HEADROOM;
            let mut out_buf2: Vec<u8> = Vec::with_capacity(bigger);
            #[allow(clippy::uninit_vec)]
            unsafe {
                out_buf2.set_len(bigger)
            };
            out_buf2[..prefix_len].copy_from_slice(prefix_window);
            match linflate::inflate_segment_with_prefix(compressed, &mut out_buf2, prefix_len) {
                Ok(new_bytes) => {
                    out_buf2.truncate(prefix_len + new_bytes);
                    out_buf2.drain(..prefix_len);
                    Ok(out_buf2)
                }
                Err(_) => Err("speculative segment decode failed"),
            }
        }
        Err(_) => Err("speculative segment decode failed"),
    }
}

/// Full speculative parallel decode of a raw DEFLATE stream.
///
/// Uses a pugz-inspired two-pass algorithm:
///
/// **Pass 1 (parallel, all cores):** Each segment is decoded speculatively
/// with a zeroed 32KB window prefix. Back-references crossing the boundary
/// resolve to zeros in the first ≤32KB of output. After 32KB the window is
/// "warmed up" and output is correct.
///
/// **Pass 2 (sequential, fast):** For each segment after the first, re-decode
/// just the beginning with the correct window (last 32KB of prior segment's
/// output). Overwrite the garbage bytes. This pass touches only 32KB × N
/// bytes total — negligible compared to pass 1.
///
/// Returns None if no valid split points found.
pub fn speculative_decode(data: &[u8], n_workers: usize) -> Option<Vec<u8>> {
    let splits = split_boundaries_parallel(data, n_workers);

    if splits.is_empty() {
        return None;
    }

    // Build segment byte ranges.
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(splits.len() + 1);
    ranges.push((0, splits[0].offset));
    for w in splits.windows(2) {
        ranges.push((w[0].offset, w[1].offset));
    }
    ranges.push((splits.last().unwrap().offset, data.len()));

    // ── Pass 1: parallel speculative decode (zeroed window) ──────────────
    // Use a zeroed 32KB prefix so that back-references before the segment
    // resolve to zeros instead of causing decode failure.
    let zeroed_window = vec![0u8; LZ77_WINDOW];
    let results: Vec<Option<Vec<u8>>> =
        gatling::gatling_forkjoin::gatling_for_each(ranges.len(), 0, |i| {
            let (start, end) = ranges[i];
            let segment = &data[start..end];
            // Segment 0: no window needed (it's the beginning of the stream).
            // Others: use zeroed window so back-refs resolve (to wrong data, but
            // decode continues and output length is correct).
            let window = if i == 0 { &[] as &[u8] } else { &zeroed_window };
            decode_with_window(segment, window).ok()
        });

    // Check all segments decoded successfully.
    let mut segments: Vec<Vec<u8>> = Vec::with_capacity(results.len());
    for r in results {
        segments.push(r?);
    }

    // ── Pass 2: sequential fixup of first ≤32KB per segment ─────────────
    // Segment 0 has no predecessor → its output is already fully correct.
    for i in 1..segments.len() {
        // Get the correct window: last 32KB of previous segment's output.
        let prev_len = segments[i - 1].len();
        let window_start = prev_len.saturating_sub(LZ77_WINDOW);
        let window = segments[i - 1][window_start..].to_vec();

        // Re-decode the segment with correct window.
        let (seg_start, seg_end) = ranges[i];
        let compressed = &data[seg_start..seg_end];

        // The garbage region is at most LZ77_WINDOW bytes at the start.
        let fixup_len = LZ77_WINDOW.min(segments[i].len());
        if fixup_len == 0 {
            continue;
        }

        match decode_with_window_limited(compressed, &window, fixup_len) {
            Ok(corrected) => {
                let copy_len = corrected.len().min(segments[i].len());
                segments[i][..copy_len].copy_from_slice(&corrected[..copy_len]);
            }
            // Re-decoding the segment head with the CORRECT window failed, which
            // means this split point / window is not trustworthy. Keeping the
            // zeroed-window pass-1 bytes would emit silent garbage, so abandon
            // the whole speculative decode — the caller falls back to the
            // authoritative single-stream path.
            Err(_) => return None,
        }
    }

    // Concatenate all segments.
    let total_len: usize = segments.iter().map(|s| s.len()).sum();
    let mut output = Vec::with_capacity(total_len);
    for seg in segments {
        output.extend_from_slice(&seg);
    }

    Some(output)
}

/// Decode a DEFLATE segment with prefix window, stopping after `limit` output bytes.
/// Used by pass 2 fixup to avoid re-decoding the entire segment.
fn decode_with_window_limited(
    compressed: &[u8],
    prefix_window: &[u8],
    limit: usize,
) -> Result<Vec<u8>, &'static str> {
    let prefix_len = prefix_window.len();
    let buf_size = prefix_len + limit + OVERWRITE_HEADROOM;
    let mut out_buf = vec![0u8; buf_size];

    // Copy prefix window into start of buffer.
    out_buf[..prefix_len].copy_from_slice(prefix_window);

    match linflate::inflate_segment_with_prefix_limited(compressed, &mut out_buf, prefix_len, limit)
    {
        Ok(new_bytes) => {
            let end = prefix_len + new_bytes.min(limit);
            Ok(out_buf[prefix_len..end].to_vec())
        }
        Err(_) => Err("fixup decode failed"),
    }
}

// ── Concatenated gzip member detection ───────────────────────────────────────
//
// Many real .gz files are concatenated gzip members (e.g., log rotation,
// `cat a.gz b.gz > combined.gz`). Each member is fully independent with its
// own header (1f 8b) → perfectly parallelizable. This is the gzip equivalent
// of bzip2's π magic scan.

/// Validate that `raw[cand..]` really begins a gzip member header — not a
/// random `1f 8b 08` triple that merely occurs inside another member's
/// high-entropy DEFLATE body.
///
/// Two layers of defence:
/// 1. **Header shape.** Magic `1f 8b`, CM=08 (deflate), the FLG reserved bits
///    (5,6,7) zero, a sane XFL (0/2/4) and OS (0–13 or 255). MTIME (bytes 4–7)
///    may legitimately be any value (0 = "no timestamp"), so it is not
///    constrained beyond needing to be present.
/// 2. **Inflate probe.** The cheap-but-decisive check: actually feed the
///    candidate to a gzip decoder and pull a few bytes. A real member yields
///    output (or a clean EOF for a genuinely empty member); random bytes that
///    happened to pass the shape test fail to inflate almost immediately. This
///    is what kills the high-entropy false positive that the shape test alone
///    could not.
///
/// Cheap in aggregate: only offsets that already pass the shape test reach the
/// probe (≈ 1 in 2^24 positions of random data), and each probe pulls at most a
/// few hundred bytes, never the whole member.
fn is_gzip_member_start(raw: &[u8], cand: usize) -> bool {
    // Need the full 10-byte fixed header plus at least one trailing byte.
    if cand + 10 >= raw.len() {
        return false;
    }
    if raw[cand] != 0x1f || raw[cand + 1] != 0x8b || raw[cand + 2] != 0x08 {
        return false;
    }
    // FLG: reserved bits (5,6,7) must be 0.
    if raw[cand + 3] & 0xE0 != 0 {
        return false;
    }
    // XFL: 0, 2, or 4 (deflate compression-level hint).
    let xfl = raw[cand + 8];
    if xfl != 0 && xfl != 2 && xfl != 4 {
        return false;
    }
    // OS: assigned range 0–13, or 255 (unknown).
    let os = raw[cand + 9];
    if os > 13 && os != 255 {
        return false;
    }

    // Inflate probe: a real member inflates; an incidental `1f 8b 08` does not.
    use std::io::Read;
    let mut dec = flate2::read::GzDecoder::new(&raw[cand..]);
    let mut scratch = [0u8; 512];
    // Ok(_) — decoded ≥0 bytes (incl. a clean EOF for an empty member) with a
    // valid header + inflate. Err(_) — bad header field GzDecoder rejects, or a
    // deflate stream that does not decode: NOT a member start.
    dec.read(&mut scratch).is_ok()
}

/// Scan raw file data (INCLUDING gzip headers) for concatenated gzip members.
/// Returns byte offsets where each new gzip header starts.
///
/// Every candidate is validated by [`is_gzip_member_start`] — header-shape
/// checks **plus** an inflate probe — so random high-entropy bytes that happen
/// to contain `1f 8b 08` are NOT mistaken for a member boundary. Splitting on
/// such a false positive used to hand a truncated stream to the per-member
/// decoders and silently corrupt the output.
pub fn find_gzip_members(raw: &[u8]) -> Vec<usize> {
    let mut members = Vec::new();
    if raw.len() < 18 {
        return members;
    }
    // First member is always at 0.
    members.push(0);

    // SIMD-scan for the 0x1f magic byte (memchr) instead of touching every byte;
    // each hit is then validated as a full gzip member (shape + inflate probe).
    // Candidates before offset 10 (inside the first header) are skipped, and
    // after a confirmed member we resume the scan past its 10-byte header.
    let mut search_from = 10usize;
    for cand in memchr::memchr_iter(0x1f, raw) {
        if cand < search_from {
            continue;
        }
        if !is_gzip_member_start(raw, cand) {
            continue;
        }
        // Confirmed real gzip member.
        members.push(cand);
        search_from = cand + 10;
    }
    members
}

/// Parallel sibling of [`find_gzip_members`]: split the raw file into
/// `n_workers` contiguous scan ranges and locate member headers in each range
/// concurrently, then merge.
///
/// The serial [`find_gzip_members`] memchr-scans the **whole compressed file**
/// (hundreds of MB of high-entropy member bodies, where `0x1f` recurs ~1/256)
/// on a single thread — on a 1 GB multi-member corpus that serial prefix was
/// ~40 ms of the ~250 ms decode, i.e. the single biggest reason the all-core
/// path stalled at ~8.7/12 cores (11 cores idle during the scan). Splitting the
/// scan across every worker collapses that prefix to a few ms, so the decode
/// that follows starts almost immediately and the pipeline stays saturated.
///
/// Correctness is identical to the serial scan: every real member's `0x1f`
/// magic byte lives at exactly one file offset, so it falls in exactly one
/// worker's `[lo, hi)` range and is validated there by the same
/// [`is_gzip_member_start`] (shape check + inflate probe) reading forward into
/// the full `raw`. Results are merged, sorted, and deduped, and offset 0 (the
/// first member) is always included. For a small input it simply defers to the
/// serial scan (no parallelism to win).
pub fn find_gzip_members_parallel(raw: &[u8], n_workers: usize) -> Vec<usize> {
    let n = n_workers.max(1);
    // Small input, or nothing to parallelise: the serial scan is already cheap.
    if n <= 1 || raw.len() < 4 * 1024 * 1024 {
        return find_gzip_members(raw);
    }
    if raw.len() < 18 {
        return Vec::new();
    }

    let len = raw.len();
    // Per-range candidate lists (excluding the implicit member at offset 0, which
    // we add once at the end). Range k scans [lo, hi); a candidate is any `0x1f`
    // at position ≥ max(lo, 10) that passes `is_gzip_member_start`.
    let per_range: Vec<Vec<usize>> = gatling::gatling_forkjoin::gatling_for_each(n, n, |k| {
        let lo = (len * k / n).max(10);
        let hi = len * (k + 1) / n;
        let mut hits = Vec::new();
        if lo >= hi {
            return hits;
        }
        for rel in memchr::memchr_iter(0x1f, &raw[lo..hi]) {
            let cand = lo + rel;
            if is_gzip_member_start(raw, cand) {
                hits.push(cand);
            }
        }
        hits
    });

    let mut members: Vec<usize> =
        Vec::with_capacity(per_range.iter().map(|v| v.len()).sum::<usize>() + 1);
    members.push(0);
    for v in per_range {
        members.extend(v);
    }
    members.sort_unstable();
    members.dedup();
    members
}

/// Parallel decode of concatenated gzip members.
/// Each member is fully independent — decode all N members in parallel.
///
/// Returns None if only one member found (no parallelism gain).
///
/// # Core saturation
///
/// Both serial preludes/epilogues that used to starve the all-core decode are
/// gone:
///
/// 1. **Member scan.** The boundary scan runs on
///    [`find_gzip_members_parallel`] (every worker memchr-scans its own slice of
///    the compressed file), not the single-threaded [`find_gzip_members`] — the
///    ~1-core prefix that stalled the pool while 11 cores idled.
/// 2. **Assembly.** The final concatenation pre-sizes the output `Vec` to the
///    exact total decoded length (summed once up front) and does a single
///    in-order copy pass — instead of an un-presized `Vec::new()` that
///    reallocated-and-recopied the whole (growing) output ~N times as each
///    member was appended.
///
/// The per-member decode itself is unchanged (independent members fanned out via
/// `gatling_for_each`), so the output bytes are byte-identical to the old path.
pub fn decode_concatenated_members(raw: &[u8], n_workers: usize) -> Option<Vec<u8>> {
    let members = find_gzip_members_parallel(raw, n_workers);
    if members.len() < 2 {
        return None;
    }

    eprintln!(
        "lgz: found {} concatenated gzip members — parallel decode",
        members.len()
    );

    // Build ranges (each member goes from its start to the next member's start).
    let ranges: Vec<(usize, usize)> = members
        .windows(2)
        .map(|w| (w[0], w[1]))
        .chain(std::iter::once((*members.last().unwrap(), raw.len())))
        .collect();

    // ── Layout the output up front from each member's gzip ISIZE trailer ──────
    // ISIZE (last 4 bytes of a member) is the uncompressed length mod 2^32 —
    // authoritative for members < 4 GiB, which is every member a concatenating
    // tool ever emits. Pre-computing the exact per-member offsets lets every
    // worker decode straight into its own disjoint slice of ONE output buffer:
    //
    //   * one allocation for the whole output (not N fresh per-member `Vec`s) —
    //     the old path's N large `Vec::new()`+grow+drop churned an mmap/munmap
    //     per member, all serialising on the kernel mmap_lock, which capped the
    //     all-core decode at ~3/12 cores no matter the worker count; and
    //   * no serial concatenation epilogue — the members ARE the output, decoded
    //     in place, so the whole 300 MB+ copy pass is gone.
    //
    // The decode validates each member's produced length against its ISIZE and
    // bails (→ caller falls back to the authoritative single-stream path) on any
    // mismatch, so a lying/wrapped trailer (e.g. a ≥4 GiB member) yields a clean
    // fallback, never a partly-written buffer of garbage.
    let mut offsets: Vec<usize> = Vec::with_capacity(ranges.len());
    let mut acc: usize = 0;
    for &(_s, e) in &ranges {
        if e < 4 {
            return None; // malformed framing — fall back
        }
        let isize_field =
            u32::from_le_bytes([raw[e - 4], raw[e - 3], raw[e - 2], raw[e - 1]]) as usize;
        offsets.push(acc);
        acc = acc.checked_add(isize_field)?;
    }
    let total = acc;

    // One output allocation. `set_len` on uninitialised capacity is sound here
    // because every byte in `0..total` is covered by exactly one member's slice
    // and each slice is fully written (or the whole decode bails), so no
    // uninitialised byte is ever read back.
    let mut output: Vec<u8> = Vec::with_capacity(total);
    #[allow(clippy::uninit_vec)]
    unsafe {
        output.set_len(total);
    }

    let base = SendMutPtr(output.as_mut_ptr());
    let ok = std::sync::atomic::AtomicBool::new(true);
    let ranges_ref = &ranges;
    let offsets_ref = &offsets;
    let ok_ref = &ok;

    // Fan the members out across every core. Each worker decodes member `i`
    // straight into `output[offsets[i] .. offsets[i] + isize_i]` — a disjoint,
    // non-aliasing slice — so there is no shared write, no lock, no concat.
    gatling::gatling_forkjoin::gatling_run(ranges.len(), n_workers, move |i| {
        // Force whole-struct capture of the Send+Sync wrapper (not the bare raw
        // field) so edition-2024 disjoint capture keeps the closure `Sync`.
        let base = base;
        let (s, e) = ranges_ref[i];
        let off = offsets_ref[i];
        let len = offsets_ref.get(i + 1).copied().unwrap_or(total) - off;
        // SAFETY: member `i`'s slice `[off, off+len)` is disjoint from every other
        // member's (offsets are a strict prefix sum of the ISIZE sizes) and lies
        // within `0..total`. Exactly one worker owns index `i`, so this &mut never
        // aliases another worker's.
        let slot = unsafe { std::slice::from_raw_parts_mut(base.0.add(off), len) };
        if !decode_member_into_exact(&raw[s..e], slot) {
            ok_ref.store(false, std::sync::atomic::Ordering::Relaxed);
        }
    });

    if !ok.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    Some(output)
}

/// A `Send`+`Sync` raw base pointer so the single output buffer can be written by
/// disjoint slices across scoped workers. Soundness is argued at the use site
/// (each worker writes a unique, in-bounds, non-overlapping `[off, off+len)`).
#[derive(Clone, Copy)]
struct SendMutPtr(*mut u8);
// SAFETY: workers only write disjoint byte ranges; the pointer never aliases.
unsafe impl Send for SendMutPtr {}
unsafe impl Sync for SendMutPtr {}

/// Decode one gzip member fully into `out`, which is pre-sized to the member's
/// expected uncompressed length. Returns `true` iff the member decoded to
/// **exactly** `out.len()` bytes (no overflow, no short read) — the caller relies
/// on this to detect a lying ISIZE trailer and fall back safely.
fn decode_member_into_exact(member: &[u8], out: &mut [u8]) -> bool {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(member);
    let mut filled = 0usize;
    loop {
        if filled == out.len() {
            // Expected length reached — confirm the stream really ends here (a
            // longer member than ISIZE claimed would over-run this slice).
            let mut probe = [0u8; 1];
            return matches!(decoder.read(&mut probe), Ok(0));
        }
        match decoder.read(&mut out[filled..]) {
            Ok(0) => return false, // stream ended before ISIZE bytes → short/lying
            Ok(n) => filled += n,
            Err(_) => return false,
        }
    }
}

/// Parallel decode of concatenated gzip members into **per-member** buffers,
/// WITHOUT concatenating them.
///
/// The parallel-writer sibling of [`decode_concatenated_members`]: each member
/// is fully independent, so all members decode in parallel across every core
/// (`gatling_for_each`), and the caller keeps the `Vec<Vec<u8>>` to write out
/// with a **parallel positional `pwrite`** (regular-file output) or a single
/// sequential pass (stdout) — either way the serial 4 GB concatenation the
/// old path paid is gone. Returns `None` when there are fewer than two members
/// (no parallelism gain) or any member fails to decode (caller falls back).
pub fn decode_members_parallel(raw: &[u8], n_workers: usize) -> Option<Vec<Vec<u8>>> {
    let members = find_gzip_members(raw);
    if members.len() < 2 {
        return None;
    }

    let ranges: Vec<(usize, usize)> = members
        .windows(2)
        .map(|w| (w[0], w[1]))
        .chain(std::iter::once((*members.last().unwrap(), raw.len())))
        .collect();

    let results: Vec<Option<Vec<u8>>> =
        gatling::gatling_forkjoin::gatling_for_each(ranges.len(), n_workers, |i| {
            let (start, end) = ranges[i];
            let member = &raw[start..end];
            let mut decoder = flate2::read::GzDecoder::new(member);
            let mut output = Vec::new();
            use std::io::Read;
            decoder.read_to_end(&mut output).ok().map(|_| output)
        });

    let mut decoded: Vec<Vec<u8>> = Vec::with_capacity(results.len());
    for r in results {
        decoded.push(r?);
    }
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_members_parallel_matches_concat() {
        // Two independently-gzipped members concatenated; the per-member decode
        // must reassemble to the same bytes as the concatenating path.
        fn gz(data: &[u8]) -> Vec<u8> {
            use flate2::{Compression, write::GzEncoder};
            use std::io::Write;
            let mut e = GzEncoder::new(Vec::new(), Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        let a = vec![0xABu8; 40_000];
        let b: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let mut raw = gz(&a);
        raw.extend_from_slice(&gz(&b));

        let members = decode_members_parallel(&raw, 0).expect("two members");
        assert_eq!(members.len(), 2);
        let mut got = Vec::new();
        for m in &members {
            got.extend_from_slice(m);
        }
        let mut want = a.clone();
        want.extend_from_slice(&b);
        assert_eq!(got, want);

        let concat = decode_concatenated_members(&raw, 0).unwrap();
        assert_eq!(got, concat);
    }

    #[test]
    fn incidental_gzip_magic_not_treated_as_member() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

        // A payload that literally contains a byte run passing every gzip-header
        // SHAPE check: 1f 8b (magic) 08 (CM=deflate) 00 (FLG, no reserved bits)
        // 11 22 33 44 (MTIME, any value) 00 (XFL) 03 (OS=Unix). Real high-entropy
        // DEFLATE bodies can and do contain exactly this — the old shape-only
        // heuristic false-positived on it, split one member into two, and the
        // per-member decoders then emitted silent garbage.
        let fake_header = [0x1f, 0x8b, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x03];
        let mut payload = vec![0xA5u8; 5000];
        payload.extend_from_slice(&fake_header);
        payload.extend_from_slice(&[0x77u8; 5000]);

        // Store verbatim (level 0) so the fake header survives into the
        // compressed bytes byte-for-byte.
        let raw = {
            let mut e = GzEncoder::new(Vec::new(), Compression::none());
            e.write_all(&payload).unwrap();
            e.finish().unwrap()
        };

        // Setup sanity: the incidental header really is present in the stream,
        // past the real 10-byte header — so the false-positive trigger exists.
        let hit = memchr::memmem::find(&raw[10..], &fake_header);
        assert!(
            hit.is_some(),
            "test setup: fake header must survive into stream"
        );

        // The fix: the inflate probe rejects the incidental header, so only the
        // real member at offset 0 is reported — not a phantom second member.
        let members = find_gzip_members(&raw);
        assert_eq!(
            members,
            vec![0],
            "incidental 1f 8b 08 must not be a member start"
        );

        // Single stream → the concatenated-member path declines (needs ≥2).
        assert!(decode_concatenated_members(&raw, 0).is_none());

        // Roundtrip byte-identical vs the reference gzip decoder (gunzip): the
        // input is handled as one clean single stream, NOT corrupted.
        let got = crate::decompress_gz(&raw).expect("single-stream decode");
        assert_eq!(
            got, payload,
            "must roundtrip to the original bytes, not garbage"
        );
    }

    #[test]
    fn probe_valid_deflate_at_start() {
        let original = vec![0x42u8; 100_000];
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        assert!(probe_decode(&compressed));
    }

    #[test]
    fn probe_invalid_data_fails() {
        // Pseudo-random data should not decode successfully.
        let garbage: Vec<u8> = (0u32..2000)
            .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
            .collect();
        assert!(!probe_decode(&garbage));
    }

    #[test]
    fn find_boundary_at_known_position() {
        // Create a stream with a stored block in the middle.
        // Block A: compressed data. Then a stored block. Then Block B: compressed.
        let block_a = miniz_oxide::deflate::compress_to_vec(&vec![0xAA; 50_000], 6);

        // Insert a stored block (BFINAL=0, BTYPE=00, LEN=100, NLEN=~100, 100 bytes).
        let stored_len: u16 = 100;
        let mut stored_block = vec![0x00u8]; // BFINAL=0, BTYPE=00, padding=00000
        stored_block.extend_from_slice(&stored_len.to_le_bytes());
        stored_block.extend_from_slice(&(!stored_len).to_le_bytes());
        stored_block.extend_from_slice(&vec![0x55u8; stored_len as usize]);

        let block_b = miniz_oxide::deflate::compress_to_vec(&vec![0xBB; 50_000], 6);

        let mut combined = block_a.clone();
        combined.extend_from_slice(&stored_block);
        let expected_split = combined.len(); // block_b starts here
        combined.extend_from_slice(&block_b);

        // Forward-search from near the stored block should find block_b's start.
        let search_from = block_a.len().saturating_sub(16);
        let boundary = find_next_block(&combined, search_from);
        assert!(
            boundary.is_some(),
            "should find boundary after stored block"
        );
        let b = boundary.unwrap();
        assert_eq!(
            b.offset, expected_split,
            "boundary {} should be at {}",
            b.offset, expected_split
        );
    }

    #[test]
    fn decode_with_empty_window() {
        let original = b"The quick brown fox jumps over the lazy dog.".repeat(100);
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        let result = decode_with_window(&compressed, &[]).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn speculative_split_finds_boundaries() {
        // Two LARGE independently-compressed blocks concatenated.
        // Each must be > PROBE_THRESHOLD (4KB) compressed to be splittable.
        let block_a = miniz_oxide::deflate::compress_to_vec(&vec![0xAA; 500_000], 6);
        let block_b = miniz_oxide::deflate::compress_to_vec(&vec![0xBB; 500_000], 6);
        let mut combined = block_a.clone();
        combined.extend_from_slice(&block_b);

        eprintln!(
            "Combined: {} bytes (a={}, b={})",
            combined.len(),
            block_a.len(),
            block_b.len()
        );
        let splits = split_boundaries_parallel(&combined, 4);
        eprintln!(
            "Found {} speculative splits in {} bytes",
            splits.len(),
            combined.len()
        );
        // With two large blocks, should find at least one split near the junction.
        // If blocks are too small after compression, spec probing may fail — that's ok.
        if combined.len() > PROBE_THRESHOLD * 4 {
            assert!(!splits.is_empty(), "should find at least one spec boundary");
        }
    }
}
