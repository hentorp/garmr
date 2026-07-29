//! DEFLATE full-flush boundary scanner — shared SIMD primitive.
//!
//! A Z_FULL_FLUSH point resets the LZ77 back-reference window to empty,
//! making all bytes that follow independently decompressible. In the
//! compressed byte stream this always produces the 5-byte sequence:
//!
//!   00          BFINAL=0, BTYPE=00 (stored), 5 padding zero-bits
//!   00 00       LEN  = 0x0000 (zero-length stored block)
//!   FF FF       NLEN = 0xFFFF (one's complement)
//!
//! We scan for the 4-byte LEN+NLEN pattern `00 00 FF FF`. The next
//! independently-decompressible segment starts at `match_pos + 4`.
//!
//! This is the single canonical home for the scanner; the `lgz`, `ljar` and
//! `lzip-parallel` codecs build their crate-specific parallel split (and, for
//! `lgz`, `probe_decode` validation) on top of these primitives. The raw
//! `00 00 FF FF` pattern occurs coincidentally inside Huffman-coded data, so
//! callers that decode from a returned offset must validate it themselves.

/// A full-flush boundary.
///
/// `start` is the byte offset where the next independently-decompressible
/// segment begins (the byte immediately after the `FF FF` NLEN field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushBoundary {
    pub start: usize,
}

/// SIMD tier resolved once at first use. The per-call
/// `is_x86_feature_detected!` macro expands to an atomic load + branch on every
/// invocation; in tight candidate-skip loops that is paid thousands of times
/// per chunk. Cache the chosen scanner as a function pointer so detection
/// happens exactly once.
#[cfg(target_arch = "x86_64")]
type FlushScanFn = fn(&[u8], usize) -> Option<FlushBoundary>;

#[cfg(target_arch = "x86_64")]
fn resolve_flush_scan() -> FlushScanFn {
    use std::sync::OnceLock;
    static SCAN: OnceLock<FlushScanFn> = OnceLock::new();
    *SCAN.get_or_init(|| {
        if std::arch::is_x86_feature_detected!("avx512bw") {
            // Safe wrapper: the OnceLock guarantees the feature was detected.
            |buf, from| unsafe { find_next_flush_avx512(buf, from) }
        } else if std::arch::is_x86_feature_detected!("avx2") {
            |buf, from| unsafe { find_next_flush_avx2(buf, from) }
        } else {
            find_next_flush_scalar
        }
    })
}

/// Scan forward from `from` for the next `00 00 FF FF` pattern.
///
/// Returns a `FlushBoundary` whose `start` is the first byte of the
/// segment that follows the flush marker, or `None` if not found.
pub fn find_next_flush(buf: &[u8], from: usize) -> Option<FlushBoundary> {
    if buf.len() < 4 || from + 4 > buf.len() {
        return None;
    }

    #[cfg(target_arch = "x86_64")]
    {
        // Detection resolved once (cached fn ptr) instead of per-call.
        return resolve_flush_scan()(buf, from);
    }

    #[cfg(not(target_arch = "x86_64"))]
    find_next_flush_scalar(buf, from)
}

/// Scalar fallback for flush scan.
#[inline]
pub fn find_next_flush_scalar(buf: &[u8], from: usize) -> Option<FlushBoundary> {
    if buf.len() < 4 {
        return None;
    }
    let end = buf.len() - 3;
    let mut i = from;
    while i < end {
        // Fast skip: the pattern requires buf[i+2]==0xFF.
        if buf[i + 2] != 0xFF {
            i += 1;
            continue;
        }
        if buf[i] == 0x00 && buf[i + 1] == 0x00 && buf[i + 3] == 0xFF {
            return Some(FlushBoundary { start: i + 4 });
        }
        i += 1;
    }
    None
}

/// AVX-512BW flush scan: searches 64 bytes at a time.
///
/// # Safety
/// Requires AVX-512BW. Caller ensures `buf.len() >= 4`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
#[inline]
pub unsafe fn find_next_flush_avx512(buf: &[u8], from: usize) -> Option<FlushBoundary> {
    use core::arch::x86_64::*;

    unsafe {
        let zero_vec = _mm512_setzero_si512();
        let ff_vec = _mm512_set1_epi8(-1i8);

        let ptr = buf.as_ptr();
        let len = buf.len();
        let mut i = from;

        while i + 67 <= len {
            let chunk = _mm512_loadu_si512(ptr.add(i) as *const __m512i);
            let zero_mask = _mm512_cmpeq_epi8_mask(chunk, zero_vec);
            let ff_mask = _mm512_cmpeq_epi8_mask(chunk, ff_vec);
            let candidates = (zero_mask & (zero_mask >> 1)) & ((ff_mask >> 2) & (ff_mask >> 3));

            if candidates != 0 {
                let bit_pos = candidates.trailing_zeros() as usize;
                let pos = i + bit_pos;
                if pos + 4 <= len
                    && buf[pos] == 0x00
                    && buf[pos + 1] == 0x00
                    && buf[pos + 2] == 0xFF
                    && buf[pos + 3] == 0xFF
                {
                    return Some(FlushBoundary { start: pos + 4 });
                }
                i += bit_pos + 1;
                continue;
            }
            // The candidate mask only resolves columns whose `FF FF` tail stays
            // inside the 64-bit window (start column <= 60); a marker starting in
            // the final 3 columns needs bits 64/65 and is invisible here. Advance
            // by `width - 3` so those straddling columns become the head of the
            // next window instead of being skipped.
            i += 64 - 3;
        }

        find_next_flush_scalar(buf, i)
    }
}

/// AVX2 flush scan: searches 32 bytes at a time using SIMD comparison.
///
/// # Safety
/// Requires AVX2. Caller ensures `buf.len() >= 4`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
pub unsafe fn find_next_flush_avx2(buf: &[u8], from: usize) -> Option<FlushBoundary> {
    use core::arch::x86_64::*;

    unsafe {
        let zero_vec = _mm256_setzero_si256();
        let ff_vec = _mm256_set1_epi8(-1);

        let ptr = buf.as_ptr();
        let len = buf.len();
        let mut i = from;

        while i + 35 <= len {
            let chunk = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
            let eq_zero = _mm256_cmpeq_epi8(chunk, zero_vec);
            let eq_ff = _mm256_cmpeq_epi8(chunk, ff_vec);
            let zero_mask = _mm256_movemask_epi8(eq_zero) as u32;
            let ff_mask = _mm256_movemask_epi8(eq_ff) as u32;
            let candidates = (zero_mask & (zero_mask >> 1)) & ((ff_mask >> 2) & (ff_mask >> 3));

            if candidates != 0 {
                let bit_pos = candidates.trailing_zeros() as usize;
                let pos = i + bit_pos;
                if pos + 4 <= len
                    && buf[pos] == 0x00
                    && buf[pos + 1] == 0x00
                    && buf[pos + 2] == 0xFF
                    && buf[pos + 3] == 0xFF
                {
                    return Some(FlushBoundary { start: pos + 4 });
                }
                i += bit_pos + 1;
                continue;
            }
            // The candidate mask only resolves columns whose `FF FF` tail stays
            // inside the 32-bit window (start column <= 28); a marker starting in
            // the final 3 columns needs bits 32/33 and is invisible here. Advance
            // by `width - 3` so those straddling columns become the head of the
            // next window instead of being skipped.
            i += 32 - 3;
        }

        find_next_flush_scalar(buf, i)
    }
}

/// Find all full-flush boundaries in `buf` (raw, unvalidated scanner).
///
/// Returns every position matching the `00 00 FF FF` pattern. Callers that
/// decode from these offsets must validate them — the pattern occurs
/// coincidentally inside Huffman-coded data.
pub fn find_all_flushes(buf: &[u8]) -> Vec<FlushBoundary> {
    // Resolve the tier once and run the whole scan loop inside the matching
    // target-feature context so the inner scanner stays inlined across
    // iterations.
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512bw") {
            return unsafe { find_all_flushes_avx512(buf) };
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { find_all_flushes_avx2(buf) };
        }
    }
    find_all_flushes_scalar(buf)
}

/// Scalar variant of the all-flushes scan loop.
#[inline]
fn find_all_flushes_scalar(buf: &[u8]) -> Vec<FlushBoundary> {
    let mut result = Vec::new();
    let mut pos = 0;
    while let Some(b) = find_next_flush_scalar(buf, pos) {
        result.push(b);
        pos = b.start;
    }
    result
}

/// AVX2 all-flushes scan loop (inner scanner inlined across iterations).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn find_all_flushes_avx2(buf: &[u8]) -> Vec<FlushBoundary> {
    let mut result = Vec::new();
    let mut pos = 0;
    while let Some(b) = unsafe { find_next_flush_avx2(buf, pos) } {
        result.push(b);
        pos = b.start;
    }
    result
}

/// AVX-512 all-flushes scan loop.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn find_all_flushes_avx512(buf: &[u8]) -> Vec<FlushBoundary> {
    let mut result = Vec::new();
    let mut pos = 0;
    while let Some(b) = unsafe { find_next_flush_avx512(buf, pos) } {
        result.push(b);
        pos = b.start;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_flush_marker() -> Vec<u8> {
        vec![0x00, 0x00, 0x00, 0xFF, 0xFF]
    }

    #[test]
    fn find_flush_at_start() {
        let mut buf = make_flush_marker();
        buf.extend_from_slice(&[0xAA, 0xBB]);
        let b = find_next_flush(&buf, 0).unwrap();
        assert_eq!(b.start, 5);
    }

    #[test]
    fn find_flush_mid_buffer() {
        let mut buf = vec![0xDE, 0xAD, 0xBE, 0xEF];
        buf.extend_from_slice(&make_flush_marker());
        buf.extend_from_slice(&[0x01, 0x02]);
        let b = find_next_flush(&buf, 0).unwrap();
        assert_eq!(b.start, 9);
    }

    #[test]
    fn no_flush_in_random_data() {
        let buf: Vec<u8> = (0..64).map(|i| (i * 37 + 1) as u8).collect();
        let _ = find_next_flush(&buf, 0);
    }

    #[test]
    fn find_all_flushes_two_markers() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&make_flush_marker());
        buf.extend_from_slice(&[0xAA; 10]);
        buf.extend_from_slice(&make_flush_marker());
        let all = find_all_flushes(&buf);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].start, 5);
        assert_eq!(all[1].start, 20);
    }

    #[test]
    fn raw_scan_finds_synthetic_boundary() {
        // The raw scanner matches the byte pattern without decoding.
        let mut buf = vec![0xAA; 64];
        buf.extend_from_slice(&make_flush_marker());
        buf.extend_from_slice(&[0xBB; 64]);
        let b = find_next_flush(&buf, 0).unwrap();
        assert_eq!(b.start, 69);
    }
}
