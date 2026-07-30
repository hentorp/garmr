//! Chunk-level parallel DEFLATE decoder.
//!
//! Mirrors lbzip2-rs chunk.rs: the caller reads up to 200 MB of compressed data
//! into a ring-buffer slot, prepends any carry from the previous slot, then calls
//! `split_chunk` to find flush boundaries and `decode_chunk` to decode all segments
//! in parallel.
//!
//! Full-flush boundaries (`00 00 FF FF`) guarantee no LZ77 back-reference crosses
//! a segment boundary, so each segment is independently decompressible.
//!
//! Segments are decompressed using our custom DEFLATE decoder (`inflate_segment`)
//! which handles non-final segments (no BFINAL=1 requirement). Falls back to
//! miniz_oxide for robustness.

use crate::deflate_scan::{self, FlushBoundary};
use crate::entry::ZipError;

/// Result of splitting a chunk into independently-decompressible segments.
pub struct ChunkSplit {
    /// Byte offsets of segment starts (first entry is always 0).
    pub segment_starts: Vec<usize>,
    /// Number of segments to decode (all if `is_last`, else n−1).
    pub decode_segments: usize,
    /// Bytes consumed from the chunk (for carry computation).
    pub consumed: usize,
}

/// Split a chunk of compressed DEFLATE data into segment boundaries.
///
/// Uses `split_boundaries_parallel` with `n_workers` splits (no oversplit —
/// one segment per physical core, mirroring lbzip2-rs binary behaviour).
///
/// Returns `None` if no full-flush boundary is found (caller falls back to
/// single-core decompression for this chunk).
pub fn split_chunk(data: &[u8], n_workers: usize, is_last: bool) -> Option<ChunkSplit> {
    let boundaries: Vec<FlushBoundary> = deflate_scan::split_boundaries_parallel(data, n_workers);

    if boundaries.is_empty() {
        return None;
    }

    // Build deduplicated segment start list: always start at 0.
    let mut segment_starts = Vec::with_capacity(boundaries.len() + 1);
    segment_starts.push(0usize);
    for b in &boundaries {
        if *segment_starts.last().unwrap() != b.start {
            segment_starts.push(b.start);
        }
    }

    let n = segment_starts.len();
    let decode_segments = if is_last {
        n
    } else if n > 1 {
        n - 1
    } else {
        return None;
    };

    let consumed = if decode_segments < n {
        segment_starts[decode_segments]
    } else {
        data.len()
    };

    Some(ChunkSplit {
        segment_starts,
        decode_segments,
        consumed,
    })
}

/// Decompress one segment of DEFLATE data that may NOT end on BFINAL=1.
///
/// Uses linflate (shared fast SIMD inflate) for non-final segments.
///
/// Writes directly into the tail of `output` (zero per-segment allocation
/// beyond the output vector itself).
pub fn decode_segment_into(compressed: &[u8], output: &mut Vec<u8>) -> Result<(), ZipError> {
    let headroom = linflate::OVERWRITE_HEADROOM;
    let out_start = output.len();
    let mut buf_size = (compressed.len() * 4).max(4096) + headroom;

    loop {
        output.reserve(buf_size);
        let spare_len = output.capacity() - out_start;
        let out_buf = unsafe {
            std::slice::from_raw_parts_mut(output.as_mut_ptr().add(out_start), spare_len)
        };

        match linflate::inflate_segment(compressed, out_buf) {
            Ok(written) => {
                unsafe { output.set_len(out_start + written) };
                return Ok(());
            }
            Err(linflate::InflateError::OutputOverflow) => {
                buf_size = buf_size.saturating_mul(2);
                if buf_size > 4 * 1024 * 1024 * 1024 {
                    return Err(ZipError("DEFLATE segment too large"));
                }
            }
            Err(_) => return Err(ZipError("DEFLATE segment decompression failed")),
        }
    }
}

/// Decompress one segment and return the output as an owned `Vec<u8>`.
pub fn decode_segment(compressed: &[u8]) -> Result<Vec<u8>, ZipError> {
    let mut out = Vec::new();
    decode_segment_into(compressed, &mut out)?;
    Ok(out)
}

/// Decode a full chunk in parallel.
///
/// 1. Split the chunk at full-flush boundaries (N−1 segments).
/// 2. If no boundaries found, fall back: returns `Err` with a sentinel so the
///    caller can decompress the chunk single-core.
/// 3. Otherwise decode `decode_segments` segments in parallel via the shared
///    gatling fork-join engine.
///
/// Returns `(segment_outputs, consumed_bytes)`.
/// `consumed_bytes` is the byte offset up to which the chunk was decoded —
/// bytes from `consumed_bytes..` must be carried into the next slot.
pub fn decode_chunk(
    data: &[u8],
    n_workers: usize,
    is_last: bool,
) -> Result<(Vec<Vec<u8>>, usize), ZipError> {
    let split = split_chunk(data, n_workers, is_last).ok_or(ZipError(
        "no full-flush boundaries — fallback to single-core",
    ))?;

    let segments: Vec<&[u8]> = (0..split.decode_segments)
        .map(|i| {
            let start = split.segment_starts[i];
            let end = if i + 1 < split.segment_starts.len() {
                split.segment_starts[i + 1]
            } else {
                split.consumed
            };
            &data[start..end]
        })
        .collect();

    let outputs: Vec<Result<Vec<u8>, ZipError>> =
        gatling::gatling_forkjoin::gatling_for_each(segments.len(), 0, |i| {
            decode_segment(segments[i])
        });

    let mut result = Vec::with_capacity(outputs.len());
    for r in outputs {
        result.push(r?);
    }

    Ok((result, split.consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid stored DEFLATE stream with Z_FULL_FLUSH after `payload`.
    ///
    /// Layout: non-final stored block(s) carrying `payload`, then flush marker.
    fn stored_block(payload: &[u8], bfinal: bool) -> Vec<u8> {
        // Stored block: BFINAL | BTYPE=00 | pad bits | LEN | NLEN | data
        let mut out = Vec::new();
        let header: u8 = if bfinal { 0x01 } else { 0x00 };
        out.push(header);
        let len = payload.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn flush_marker() -> Vec<u8> {
        // Z_FULL_FLUSH: stored block header + zero-length LEN/NLEN
        vec![0x00, 0x00, 0x00, 0xFF, 0xFF]
    }

    // ── split_chunk ──────────────────────────────────────────────────────────

    #[test]
    fn split_chunk_no_boundaries_returns_none() {
        // Plain bytes with no 00 00 FF FF pattern — split_chunk returns None.
        let data: Vec<u8> = (0u8..=255).cycle().take(128).collect();
        assert!(split_chunk(&data, 4, true).is_none());
    }

    #[test]
    fn split_chunk_single_boundary_is_last() {
        // Flush boundary must appear AFTER buf.len()/2 so the forward scan
        // from the nominal split point (midpoint) reaches it.
        //
        // Layout: 20-byte non-final stored block | 5-byte flush marker | 10-byte final stored block
        //   Total = 35, midpoint = 17, pattern `00 00 FF FF` at position 21 > 17 ✓
        let payload_a = vec![0xAA_u8; 15];
        let mut buf = stored_block(&payload_a, false); // 20 bytes
        buf.extend_from_slice(&flush_marker()); // 5 bytes
        buf.extend_from_slice(&stored_block(b"world", true)); // 10 bytes

        let split = split_chunk(&buf, 2, true).expect("should find boundary");
        assert!(split.decode_segments >= 1);
        assert_eq!(split.consumed, buf.len());
    }

    #[test]
    fn split_chunk_single_boundary_not_last() {
        // With is_last=false and flush boundary in the first half (small buffer,
        // n_splits=2 nominal=midpoint > boundary position), split_chunk may
        // return None — that is acceptable (caller falls back to single-core).
        let mut buf = stored_block(b"hello", false);
        buf.extend_from_slice(&flush_marker());
        buf.extend_from_slice(&stored_block(b"world", false));

        let result = split_chunk(&buf, 2, false);
        if let Some(s) = result {
            assert!(s.consumed <= buf.len());
            assert!(s.decode_segments >= 1);
        }
        // None is also acceptable — caller falls back to single-core.
    }

    // ── decode_segment ───────────────────────────────────────────────────────

    #[test]
    fn decode_segment_stored_final() {
        let data = stored_block(b"Hello, World!\n", true);
        let out = decode_segment(&data).expect("decode stored block");
        assert_eq!(out, b"Hello, World!\n");
    }

    #[test]
    fn decode_segment_stored_non_final() {
        // A non-final stored block (BFINAL=0) — decompress_to_vec would fail.
        let data = stored_block(b"partial segment", false);
        let out = decode_segment(&data).expect("decode non-final stored block");
        assert_eq!(out, b"partial segment");
    }

    #[test]
    fn decode_segment_real_deflate() {
        // Compress with miniz_oxide and decompress a final segment.
        use miniz_oxide::deflate::compress_to_vec;
        let original = b"The quick brown fox jumps over the lazy dog".repeat(50);
        let compressed = compress_to_vec(&original, 6);
        let out = decode_segment(&compressed).expect("decode real deflate");
        assert_eq!(out, original.to_vec());
    }

    // ── decode_chunk ─────────────────────────────────────────────────────────

    #[test]
    fn decode_chunk_no_boundaries_returns_err() {
        // Data with no flush marker → fallback error.
        let data = stored_block(b"no flush here", true);
        assert!(decode_chunk(&data, 4, true).is_err());
    }

    #[test]
    fn decode_chunk_two_segments() {
        // Flush boundary must be past midpoint so parallel scan finds it.
        //
        // Layout: 27-byte non-final block | 5-byte flush | 10-byte final block
        //   Total = 42, midpoint = 21, pattern at position 28 > 21 ✓
        let payload_a = vec![0xAA_u8; 22]; // stored block = 27 bytes
        let payload_b = vec![0xBB_u8; 5]; // stored block = 10 bytes
        let mut buf = stored_block(&payload_a, false);
        buf.extend_from_slice(&flush_marker());
        buf.extend_from_slice(&stored_block(&payload_b, true));

        let (outputs, consumed) = decode_chunk(&buf, 2, true).expect("decode two segments");
        assert_eq!(consumed, buf.len());
        let combined: Vec<u8> = outputs.into_iter().flatten().collect();
        let expected: Vec<u8> = payload_a.iter().chain(payload_b.iter()).copied().collect();
        assert_eq!(combined, expected);
    }
}
