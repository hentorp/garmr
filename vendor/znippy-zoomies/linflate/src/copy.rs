//! SIMD-accelerated LZ77 match copy.
//!
//! Uses const-generic chunk size N (zlib-rs pattern):
//! - N=32 on x86_64 (AVX2) → LLVM emits vmovdqu ymm load/store
//! - N=16 on aarch64 (NEON) → LLVM emits ldr/str q-register
//! - N=8 fallback
//!
//! Short back-references (dist 2..7) use AVX2 shuffle tiling when available
//! (zlib-ng pattern: single _mm256_shuffle_epi8 tiles any short pattern).

/// Platform-appropriate chunk size for SIMD match copy.
#[cfg(target_arch = "x86_64")]
pub const CHUNK_SIZE: usize = 32;

#[cfg(target_arch = "aarch64")]
pub const CHUNK_SIZE: usize = 16;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const CHUNK_SIZE: usize = 8;

/// Copy `length` bytes from `src` to `dst` using N-byte chunks.
///
/// Caller guarantees: `dst + length + N` is within bounds (overwrite headroom),
/// and `src` does NOT overlap with `dst..dst+length` (i.e., `dist >= N`).
///
/// # Safety
/// Caller must ensure all pointer arithmetic is valid and non-overlapping.
#[inline(always)]
pub unsafe fn copy_chunks<const N: usize>(mut src: *const u8, mut dst: *mut u8, length: usize) {
    unsafe {
        let end = dst.add(length);
        core::ptr::copy_nonoverlapping(src, dst, N);
        src = src.add(N);
        dst = dst.add(N);
        while dst < end {
            core::ptr::copy_nonoverlapping(src, dst, N);
            src = src.add(N);
            dst = dst.add(N);
        }
    }
}

/// Copy `length` bytes with word-stride for distances 8..CHUNK_SIZE-1.
///
/// Each iteration copies 8 bytes from `dst - dist` (already-written data),
/// advances dst by 8. Since `dist >= 8`, each 8-byte read is from data that
/// was committed by a previous write (the overlapping "tile" pattern).
///
/// # Safety
/// Caller must ensure pointer validity and `dist >= 8`.
#[inline(always)]
pub unsafe fn copy_stride_word(_src: *const u8, mut dst: *mut u8, dist: usize, length: usize) {
    unsafe {
        let end = dst.add(length);
        // Unroll: 2x 8-byte copies per iteration for better ILP
        let end_unrolled = dst.add(length.saturating_sub(8));
        while dst < end_unrolled {
            let word0 = core::ptr::read_unaligned(dst.sub(dist) as *const u64);
            core::ptr::write_unaligned(dst as *mut u64, word0);
            dst = dst.add(8);
            let word1 = core::ptr::read_unaligned(dst.sub(dist) as *const u64);
            core::ptr::write_unaligned(dst as *mut u64, word1);
            dst = dst.add(8);
        }
        while dst < end {
            let word = core::ptr::read_unaligned(dst.sub(dist) as *const u64);
            core::ptr::write_unaligned(dst as *mut u64, word);
            dst = dst.add(8);
        }
    }
}

/// Cached AVX2 detection — checked once, used for every match copy.
#[cfg(target_arch = "x86_64")]
static HAS_AVX2: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::arch::is_x86_feature_detected!("avx2"));

/// Cached AVX-512BW detection — checked once at startup.
#[cfg(target_arch = "x86_64")]
static HAS_AVX512BW: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::arch::is_x86_feature_detected!("avx512bw"));

/// Main match copy dispatch.
///
/// Copies `length` bytes from `out_pos - dist` to `out_pos`.
///
/// # Safety
/// Caller guarantees:
/// - `dist <= out_pos - out_start` (back-reference is within decompressed data)
/// - `out_pos + length + CHUNK_SIZE` is within the output buffer (overwrite headroom)
#[inline(always)]
pub unsafe fn copy_match(out_pos: *mut u8, dist: usize, length: usize) {
    let src = unsafe { out_pos.sub(dist) };

    #[cfg(target_arch = "x86_64")]
    {
        // AVX-512: 64-byte non-overlapping copies for large distances
        if dist >= 64 && *HAS_AVX512BW {
            unsafe { copy_chunks_avx512(src, out_pos, length) };
            return;
        }
    }

    if dist >= CHUNK_SIZE {
        // dist >= 32: no overlap in 32-byte chunks
        unsafe { copy_chunks::<CHUNK_SIZE>(src, out_pos, length) };
    } else if dist == 1 {
        // RLE: memset
        unsafe { core::ptr::write_bytes(out_pos, *src, length) };
    } else if dist >= 8 {
        unsafe { copy_stride_word(src, out_pos, dist, length) };
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            if *HAS_AVX2 {
                unsafe { copy_short_avx2(src, out_pos, dist, length) };
                return;
            }
        }
        unsafe { copy_short_scalar(src, out_pos, dist, length) };
    }
}

// ── AVX-512 64-byte match copy ───────────────────────────────────────────────

/// AVX-512BW 64-byte non-overlapping match copy.
///
/// For distances >= 64, each 64-byte load/store is fully independent.
/// On Zen 4+ and Intel Skylake-X+, this doubles throughput vs 32-byte AVX2.
///
/// # Safety
/// Requires AVX-512BW. Caller ensures `dist >= 64` and sufficient headroom.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn copy_chunks_avx512(mut src: *const u8, mut dst: *mut u8, length: usize) {
    use core::arch::x86_64::*;

    unsafe {
        let end = dst.add(length);
        // First 64-byte copy
        let chunk = _mm512_loadu_si512(src as *const __m512i);
        _mm512_storeu_si512(dst as *mut __m512i, chunk);
        src = src.add(64);
        dst = dst.add(64);
        // Remaining copies
        while dst < end {
            let chunk = _mm512_loadu_si512(src as *const __m512i);
            _mm512_storeu_si512(dst as *mut __m512i, chunk);
            src = src.add(64);
            dst = dst.add(64);
        }
    }
}

/// Scalar fallback for short distances: copy byte-by-byte from output.
/// Since dist < 8 and length may exceed dist, each write depends on a
/// previous write (overlapping tiling pattern).
#[inline(always)]
unsafe fn copy_short_scalar(_src: *const u8, dst: *mut u8, dist: usize, length: usize) {
    unsafe {
        for i in 0..length {
            *dst.add(i) = *dst.add(i).sub(dist);
        }
    }
}

// ── AVX2 short-distance tiling ───────────────────────────────────────────────

/// Pre-computed shuffle indices for dist 2..7.
/// Each row tiles the first `dist` source bytes across 32 bytes via vpshufb.
/// _mm256_shuffle_epi8 operates on each 128-bit lane independently, so the
/// high lane indices must account for the 16-byte lane offset in the pattern.
#[cfg(target_arch = "x86_64")]
#[repr(align(32))]
struct AlignedPerm([u8; 32]);

#[cfg(target_arch = "x86_64")]
static PERM_LUT: [AlignedPerm; 6] = {
    const fn make_perm(dist: usize) -> [u8; 32] {
        let mut perm = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            // _mm256_shuffle_epi8 operates within each 128-bit lane independently.
            // Both lanes contain the same source bytes (0..dist-1 tiled to 0..15).
            // Index (i % dist) selects the correct source byte within each lane
            // because (global_pos % dist) is the tiling position, and the same
            // source copy exists in both lanes.
            perm[i] = (i % dist) as u8;
            i += 1;
        }
        perm
    }
    [
        AlignedPerm(make_perm(2)),
        AlignedPerm(make_perm(3)),
        AlignedPerm(make_perm(4)),
        AlignedPerm(make_perm(5)),
        AlignedPerm(make_perm(6)),
        AlignedPerm(make_perm(7)),
    ]
};

/// AVX2 short-distance match copy using vpshufb tiling.
///
/// Loads the first `dist` source bytes, tiles across 32 bytes using shuffle,
/// stores in 32-byte chunks. For lengths > 32 where 32 % dist != 0, uses
/// a chunked copy from already-tiled output for subsequent stores.
///
/// # Safety
/// Requires AVX2. Caller ensures pointer validity and overwrite headroom.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn copy_short_avx2(src: *const u8, mut dst: *mut u8, dist: usize, length: usize) {
    use core::arch::x86_64::*;

    debug_assert!((2..=7).contains(&dist));

    unsafe {
        let src_vec = _mm_loadu_si128(src as *const __m128i);
        let wide = _mm256_inserti128_si256(_mm256_castsi128_si256(src_vec), src_vec, 1);

        let perm = _mm256_load_si256(PERM_LUT[dist - 2].0.as_ptr() as *const __m256i);
        let tiled = _mm256_shuffle_epi8(wide, perm);

        // First 32-byte store
        _mm256_storeu_si256(dst as *mut __m256i, tiled);

        if length <= 32 {
            return;
        }

        // For subsequent bytes, copy from already-tiled output.
        // Since dist is 2-7, the output repeats every `dist` bytes.
        // We can copy in chunks of `dist` from `dst + i - dist`.
        let end = dst.add(length);
        dst = dst.add(32);
        while dst < end {
            // Read 8 bytes from `dist` bytes back (already written, correctly tiled)
            let word = core::ptr::read_unaligned(dst.sub(dist) as *const u64);
            core::ptr::write_unaligned(dst as *mut u64, word);
            dst = dst.add(dist);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_chunks_basic() {
        let src = vec![
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 0, 0, 0, 0, 0, 0, 0, 0,
        ]; // overwrite headroom
        let mut dst = vec![0u8; 40]; // 32 + headroom
        unsafe { copy_chunks::<8>(src.as_ptr(), dst.as_mut_ptr(), 24) };
        assert_eq!(&dst[..24], &src[..24]);
    }

    #[test]
    fn copy_match_rle() {
        // dist=1: replicate one byte
        let mut buf = vec![0u8; 64];
        buf[0] = 0xAB;
        unsafe { copy_match(buf.as_mut_ptr().add(1), 1, 31) };
        assert!(buf[1..32].iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn copy_match_non_overlapping() {
        let mut buf = vec![0u8; 128];
        for i in 0..CHUNK_SIZE {
            buf[i] = (i + 1) as u8;
        }
        let length = CHUNK_SIZE;
        unsafe { copy_match(buf.as_mut_ptr().add(CHUNK_SIZE), CHUNK_SIZE, length) };
        assert_eq!(&buf[CHUNK_SIZE..CHUNK_SIZE * 2], &buf[..CHUNK_SIZE]);
    }

    #[test]
    fn copy_match_short_dist() {
        // dist=3: pattern [A, B, C] should tile to [A, B, C, A, B, C, ...]
        let mut buf = vec![0u8; 128];
        buf[0] = b'A';
        buf[1] = b'B';
        buf[2] = b'C';
        let length = 30;
        unsafe { copy_match(buf.as_mut_ptr().add(3), 3, length) };
        for i in 0..length {
            assert_eq!(buf[3 + i], buf[i % 3], "mismatch at offset {i}");
        }
    }

    #[test]
    fn copy_stride_word_basic() {
        let mut buf = vec![0u8; 128];
        for i in 0..8 {
            buf[i] = (i + 1) as u8;
        }
        unsafe { copy_stride_word(buf.as_ptr(), buf.as_mut_ptr().add(8), 8, 24) };
        // Should replicate the first 8 bytes three times.
        for i in 0..24 {
            assert_eq!(buf[8 + i], buf[i % 8], "mismatch at {i}");
        }
    }
}

#[cfg(test)]
mod avx2_tests {
    use super::*;

    #[test]
    fn copy_short_dist_extensive() {
        // Test all short distances (2-7) with various lengths and patterns
        for dist in 2..=7usize {
            for length in [1, 2, 3, 5, 7, 8, 15, 16, 30, 31, 32, 33, 63, 64, 100, 200] {
                let mut buf = vec![0u8; 512];
                // Set up pattern bytes at positions 0..dist
                for i in 0..dist {
                    buf[i] = (i as u8).wrapping_mul(37).wrapping_add(11); // arbitrary non-zero pattern
                }
                // Use copy_match (which dispatches to AVX2 on x86_64)
                unsafe { copy_match(buf.as_mut_ptr().add(dist), dist, length) };

                // Verify: byte-by-byte reference
                let mut expected = vec![0u8; 512];
                for i in 0..dist {
                    expected[i] = buf[i];
                }
                for i in 0..length {
                    expected[dist + i] = expected[dist + i - dist]; // = expected[i]
                }

                for i in 0..length {
                    assert_eq!(
                        buf[dist + i],
                        expected[dist + i],
                        "dist={dist} length={length}: mismatch at offset {i}, got {} expected {}",
                        buf[dist + i],
                        expected[dist + i]
                    );
                }
            }
        }
    }
}
