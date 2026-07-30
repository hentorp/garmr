//! Integration tests for the DEFLATE full-flush boundary scanner
//! (`linflate::deflate_scan`).
//!
//! The scanner locates the 4-byte `00 00 FF FF` (stored-block LEN+NLEN) pattern
//! that a `Z_FULL_FLUSH` emits, returning a `FlushBoundary` whose `start` is the
//! first byte of the next independently-decompressible segment (marker + 4).
//!
//! These tests inject crafted byte streams with markers at known offsets and
//! assert the exact returned positions, then differentially compare the scalar
//! reference against the runtime-selected SIMD path and against each SIMD kernel
//! directly.
//!
//! ## Window-straddle correctness (previously a known bug, now fixed)
//! The SIMD kernels scan in fixed windows (32 B for AVX2, 64 B for AVX-512). The
//! candidate mask only resolves a marker whose 4-byte `00 00 FF FF` body stays
//! fully inside the window; a marker starting in the final three columns needs
//! tail bits past the window edge. The kernels now advance the scan cursor by
//! `width - 3` so consecutive windows overlap by 3 bytes — the 4-byte marker is
//! therefore always fully contained in some window, and the SIMD path agrees with
//! scalar at *every* offset, including the formerly-missed cases `(off - from) %
//! 64 ∈ {61,62,63}` (AVX-512) and `(off - from) % 32 ∈ {29,30,31}` (AVX2). These
//! tests assert that agreement directly.

use linflate::deflate_scan::{
    FlushBoundary, find_all_flushes, find_next_flush, find_next_flush_scalar,
};

const MARKER: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];

/// Pure-scalar reference: every `start` position, found by repeatedly calling the
/// scalar kernel. Independent of any SIMD tier.
fn scalar_reference(buf: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(b) = find_next_flush_scalar(buf, pos) {
        out.push(b.start);
        pos = b.start;
    }
    out
}

/// Tiny deterministic xorshift64* so the corpus is identical on every machine
/// (no `rand` dev-dependency in this crate).
struct Rng(u64);
impl Rng {
    fn next_u8(&mut self) -> u8 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 33) as u8
    }
}

#[test]
fn marker_at_start() {
    // `00 00 FF FF` is the whole front of the buffer; segment starts at 4.
    let mut buf = MARKER.to_vec();
    buf.extend_from_slice(&[0x11, 0x22, 0x33]);
    assert_eq!(find_next_flush(&buf, 0), Some(FlushBoundary { start: 4 }));
}

#[test]
fn marker_mid_buffer_crafted_stream() {
    // Craft a stream resembling Huffman-coded bytes, a full-flush marker, then
    // more data. The scanner is a raw byte matcher; it must land exactly after
    // the marker (offset 6 + 4 = 10).
    let mut buf = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34]; // 6 bytes of "coded" data
    buf.extend_from_slice(&MARKER); // marker at offset 6
    buf.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
    assert_eq!(find_next_flush(&buf, 0), Some(FlushBoundary { start: 10 }));
}

#[test]
fn marker_at_very_end() {
    // Marker occupies the final four bytes; `start` is exactly buf.len().
    let mut buf = vec![0x55u8; 20];
    buf.extend_from_slice(&MARKER);
    let n = buf.len();
    assert_eq!(find_next_flush(&buf, 0), Some(FlushBoundary { start: n }));
    // Scalar agrees.
    assert_eq!(
        find_next_flush_scalar(&buf, 0),
        Some(FlushBoundary { start: n })
    );
}

#[test]
fn no_marker_and_near_misses() {
    // None of these 4-byte windows is `00 00 FF FF`:
    //   00 00 FF 7F  (last byte not FF)
    //   00 01 FF FF  (second byte not 00)
    //   AA 00 00 FF  (no leading 00 00 before FF FF)
    //   FF FF 00 00  (reversed)
    let buf = [
        0x00, 0x00, 0xFF, 0x7F, 0xAA, 0x00, 0x01, 0xFF, 0xFF, 0xAA, 0xFF, 0xFF, 0x00, 0x00,
    ];
    assert_eq!(find_next_flush(&buf, 0), None);
    assert_eq!(find_next_flush_scalar(&buf, 0), None);
    assert!(find_all_flushes(&buf).is_empty());
}

#[test]
fn from_offset_skips_earlier_marker() {
    // Two markers; starting the scan past the first must return the second.
    let mut buf = vec![0x01, 0x02, 0x03];
    buf.extend_from_slice(&MARKER); // marker A at offset 3, start 7
    buf.extend_from_slice(&[0x09; 5]);
    buf.extend_from_slice(&MARKER); // marker B at offset 12, start 16
    buf.extend_from_slice(&[0x77]);
    assert_eq!(find_next_flush(&buf, 0), Some(FlushBoundary { start: 7 }));
    // Scan resuming at the first segment start finds the second marker.
    assert_eq!(find_next_flush(&buf, 7), Some(FlushBoundary { start: 16 }));
}

#[test]
fn buffer_shorter_than_pattern_is_none() {
    assert_eq!(find_next_flush(&[0x00, 0x00, 0xFF], 0), None);
    assert_eq!(find_next_flush(&[], 0), None);
    // `from` so close to the end that no 4-byte window remains.
    let buf = MARKER.to_vec();
    assert_eq!(find_next_flush(&buf, 1), None);
}

#[test]
fn find_all_flushes_exact_positions() {
    // Three markers at controlled, well-separated offsets; assert the full list.
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0xAA; 5]);
    buf.extend_from_slice(&MARKER); // start = 9
    buf.extend_from_slice(&[0xBB; 10]);
    buf.extend_from_slice(&MARKER); // offset 19, start = 23
    buf.extend_from_slice(&[0xCC; 7]);
    buf.extend_from_slice(&MARKER); // offset 30, start = 34
    buf.extend_from_slice(&[0xDD; 3]);

    let all = find_all_flushes(&buf);
    let starts: Vec<usize> = all.iter().map(|b| b.start).collect();
    assert_eq!(starts, vec![9, 23, 34]);
    // The runtime SIMD path must agree with the scalar reference here.
    assert_eq!(starts, scalar_reference(&buf));
}

/// Marker stride. Since `find_all_flushes` re-aligns its SIMD windows to each
/// boundary's `start`, the per-window offset of the next marker is `gap - 4`.
/// `GAP = 65` gives `(65 - 4) % 64 = 61` and `(65 - 4) % 32 = 29` — precisely the
/// window-straddle offsets that the old (non-overlapping) kernels MISSED. With
/// the `width - 3` overlap fix the SIMD path must now find every one of them, so
/// this stride turns the corpus into a regression guard for the fixed bug.
const MARKER_GAP: usize = 65;

/// Build a corpus filled with a benign non-pattern byte (`0xAA`) and `count`
/// evenly spaced markers (stride [`MARKER_GAP`]) that land on the formerly-missed
/// window-straddle offsets. Returns the buffer and the expected `start` positions.
fn corpus_with_markers(count: usize) -> (Vec<u8>, Vec<usize>) {
    let first = 40usize; // first marker offset (window interior for from=0)
    let total = first + count * MARKER_GAP + 16;
    let mut buf = vec![0xAAu8; total];
    let mut starts = Vec::new();
    let mut cursor = first;
    for _ in 0..count {
        buf[cursor..cursor + 4].copy_from_slice(&MARKER);
        starts.push(cursor + 4);
        cursor += MARKER_GAP;
    }
    (buf, starts)
}

#[test]
fn simd_path_matches_scalar_reference() {
    // Differential test: the runtime-selected `find_all_flushes` (AVX-512 / AVX2 /
    // scalar) must agree byte-for-byte with the independent scalar reference, and
    // must actually detect every injected marker (guards against a vacuous pass).
    let (buf, expected) = corpus_with_markers(40);

    let simd: Vec<usize> = find_all_flushes(&buf).iter().map(|b| b.start).collect();
    let scalar = scalar_reference(&buf);

    assert_eq!(simd, scalar, "SIMD path disagrees with scalar reference");
    assert_eq!(simd, expected, "scanner missed/added an injected marker");
    assert_eq!(simd.len(), 40, "expected exactly 40 detected boundaries");
}

#[test]
fn simd_kernels_match_scalar_directly() {
    // Drive each SIMD kernel directly (when its feature is present at runtime),
    // not just the dispatcher, since the dispatcher prefers AVX-512 and would
    // never exercise AVX2 on an AVX-512 host. Sweep EVERY scan-start position so
    // that a marker lands at every possible window column — including the final
    // three columns ({29,30,31} for AVX2, {61,62,63} for AVX-512) that the old
    // non-overlapping kernels straddle-missed. After the `width - 3` overlap fix
    // each kernel must agree with scalar at all of them.
    #[cfg(target_arch = "x86_64")]
    {
        use linflate::deflate_scan::{find_next_flush_avx2, find_next_flush_avx512};
        let (buf, _) = corpus_with_markers(24);

        // Dense sweep: each `from` shifts every downstream marker's window column
        // by one, so 0..buf.len() exercises all alignments modulo 32 and 64.
        let froms: Vec<usize> = (0..buf.len()).collect();

        if std::arch::is_x86_feature_detected!("avx2") {
            for &from in &froms {
                let want = find_next_flush_scalar(&buf, from);
                let got = unsafe { find_next_flush_avx2(&buf, from) };
                assert_eq!(got, want, "avx2 != scalar at from={from}");
            }
        }
        if std::arch::is_x86_feature_detected!("avx512bw") {
            for &from in &froms {
                let want = find_next_flush_scalar(&buf, from);
                let got = unsafe { find_next_flush_avx512(&buf, from) };
                assert_eq!(got, want, "avx512 != scalar at from={from}");
            }
        }
    }
}

#[test]
fn random_data_has_no_spurious_boundaries() {
    // Pseudo-random bytes with the two pattern-forming values (0x00, 0xFF)
    // explicitly excluded cannot contain `00 00 FF FF`; the scanner must agree
    // with that (empty) and the SIMD path must match scalar.
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let buf: Vec<u8> = (0..4096)
        .map(|_| {
            let mut b = rng.next_u8();
            if b == 0x00 || b == 0xFF {
                b = 0x7E;
            }
            b
        })
        .collect();
    assert!(find_all_flushes(&buf).is_empty());
    assert_eq!(
        find_all_flushes(&buf)
            .iter()
            .map(|b| b.start)
            .collect::<Vec<_>>(),
        scalar_reference(&buf)
    );
}
