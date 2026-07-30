//! DEFLATE full-flush boundary scanner — crate-local validated split.
//!
//! The raw SIMD scanner now lives in the shared `linflate` crate
//! (`linflate::deflate_scan`). This module keeps lgz's extra layer on top:
//! `probe_decode` validation of candidate boundaries plus the parallel
//! split-point search, neither of which can live in `linflate` (they depend on
//! lgz's `speculative` decoder probe and its scoped-thread `par_map_indexed`).
//!
//! The raw 4-byte `00 00 FF FF` LEN/NLEN pattern occurs coincidentally inside
//! Huffman-coded data, and a *sync*-flush (where the encoder keeps the LZ77
//! dictionary, e.g. plain `pigz`) emits the very same bytes as a *full*-flush
//! (where the dictionary is reset). Decoding the segment after a sync-flush or
//! a coincidental match from an empty window silently corrupts output. Each
//! candidate is therefore confirmed with `probe_decode`, which requires a
//! substantial clean decode from the boundary — a true full-flush has no
//! back-references reaching before it, whereas dependent/false boundaries hit a
//! distance-too-far or invalid-table error first. Unconfirmed candidates are
//! skipped and the scan continues.

pub use linflate::deflate_scan::{FlushBoundary, find_all_flushes, find_next_flush};

use linflate::deflate_scan::find_next_flush_scalar;
#[cfg(target_arch = "x86_64")]
use linflate::deflate_scan::{find_next_flush_avx2, find_next_flush_avx512};

/// Scan forward from `from` for the next *validated* full-flush boundary.
pub fn find_next_valid_flush(buf: &[u8], from: usize) -> Option<FlushBoundary> {
    // The candidate-skip loop runs thousands of times per chunk (one iteration
    // per coincidental `00 00 FF FF` false positive). Resolve the SIMD tier
    // ONCE and run the entire skip loop inside the matching `#[target_feature]`
    // context, so the inner scanner stays inlinable instead of crossing the
    // non-inlinable target-feature boundary on every candidate.
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512bw") {
            return unsafe { find_next_valid_flush_avx512(buf, from) };
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { find_next_valid_flush_avx2(buf, from) };
        }
    }
    find_next_valid_flush_scalar(buf, from)
}

/// Scalar candidate-skip validation loop.
#[inline]
fn find_next_valid_flush_scalar(buf: &[u8], from: usize) -> Option<FlushBoundary> {
    let mut pos = from;
    while let Some(b) = find_next_flush_scalar(buf, pos) {
        if crate::speculative::probe_decode(&buf[b.start..]) {
            return Some(b);
        }
        pos = b.start;
    }
    None
}

/// AVX2 candidate-skip validation loop. The `find_next_flush_avx2` calls stay
/// inlined within this AVX2-enabled context across all false-positive skips.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn find_next_valid_flush_avx2(buf: &[u8], from: usize) -> Option<FlushBoundary> {
    let mut pos = from;
    while let Some(b) = unsafe { find_next_flush_avx2(buf, pos) } {
        if crate::speculative::probe_decode(&buf[b.start..]) {
            return Some(b);
        }
        pos = b.start;
    }
    None
}

/// AVX-512 candidate-skip validation loop (same shape as the AVX2 variant).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn find_next_valid_flush_avx512(buf: &[u8], from: usize) -> Option<FlushBoundary> {
    let mut pos = from;
    while let Some(b) = unsafe { find_next_flush_avx512(buf, pos) } {
        if crate::speculative::probe_decode(&buf[b.start..]) {
            return Some(b);
        }
        pos = b.start;
    }
    None
}

/// Parallel split-point search: N−1 scoped-thread tasks each find the nearest
/// flush boundary at or after their nominal byte offset.
///
/// `n_splits` is typically the number of physical cores.
/// Returns up to `n_splits − 1` boundaries, sorted and deduplicated.
pub fn split_boundaries_parallel(buf: &[u8], n_splits: usize) -> Vec<FlushBoundary> {
    if n_splits <= 1 || buf.len() < 8 {
        return Vec::new();
    }

    let mut found: Vec<Option<FlushBoundary>> =
        gatling::gatling_forkjoin::gatling_for_each(n_splits - 1, 0, |k| {
            let i = k + 1;
            let nominal = buf.len() * i / n_splits;
            find_next_valid_flush(buf, nominal)
        });

    let mut result: Vec<FlushBoundary> = found.drain(..).flatten().collect();
    result.sort_by_key(|b| b.start);
    result.dedup_by_key(|b| b.start);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_flush_marker() -> Vec<u8> {
        vec![0x00, 0x00, 0x00, 0xFF, 0xFF]
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

    #[test]
    fn parallel_split_rejects_false_positive() {
        // Synthetic 0xAA/0xBB padding is not valid DEFLATE, so the validated
        // parallel split must reject the coincidental pattern match.
        let mut buf = vec![0xAA; 64];
        buf.extend_from_slice(&make_flush_marker());
        buf.extend_from_slice(&[0xBB; 64]);
        let boundaries = split_boundaries_parallel(&buf, 4);
        assert!(boundaries.is_empty());
    }
}
