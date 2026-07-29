//! Chunk-level parallel DEFLATE decoder for gzip streams.
//!
//! Mirrors ljar-rs/lbzip2-rs chunk.rs: the caller reads up to CHUNK_SIZE bytes
//! of compressed data into a ring-buffer slot, prepends any carry from the
//! previous slot, then calls `split_chunk` to find flush boundaries and
//! `decode_chunk` to decode all segments in parallel.
//!
//! Full-flush boundaries (`00 00 FF FF`) guarantee no LZ77 back-reference
//! crosses a segment boundary — each segment is independently decompressible.

use crate::deflate_scan::{self, FlushBoundary};
use crate::parallel::GzError;

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
/// Uses `split_boundaries_parallel` with `n_workers` splits.
/// Returns `None` if no full-flush boundary is found (caller falls back to
/// single-core decompression).
pub fn split_chunk(data: &[u8], n_workers: usize, is_last: bool) -> Option<ChunkSplit> {
    let boundaries: Vec<FlushBoundary> = deflate_scan::split_boundaries_parallel(data, n_workers);

    if boundaries.is_empty() {
        return None;
    }

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

/// Decompress one segment of raw DEFLATE data.
pub fn decode_segment(compressed: &[u8]) -> Result<Vec<u8>, GzError> {
    let mut output = Vec::new();
    decode_segment_into(compressed, &mut output)?;
    Ok(output)
}

/// Decompress one DEFLATE segment, appending to `output`.
///
/// Uses linflate: SIMD match-copy, branchless refill, segment-aware (handles non-BFINAL).
pub fn decode_segment_into(compressed: &[u8], output: &mut Vec<u8>) -> Result<(), GzError> {
    decode_segment_into_hint(compressed, output, 0)
}

/// Decompress with a size hint (e.g. from gzip ISIZE field).
/// If hint > 0, allocates that much upfront (one-shot, no retry loop).
pub fn decode_segment_into_hint(
    compressed: &[u8],
    output: &mut Vec<u8>,
    size_hint: usize,
) -> Result<(), GzError> {
    let headroom = linflate::OVERWRITE_HEADROOM;
    let out_start = output.len();

    // If we have a size hint, allocate exactly that + headroom (one-shot).
    let initial = if size_hint > 0 {
        size_hint + headroom
    } else {
        (compressed.len() * 4).max(64 * 1024) + headroom
    };

    let mut buf_size = initial;

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
                // Double the buffer and retry.
                buf_size = buf_size.saturating_mul(2);
                if buf_size > 4 * 1024 * 1024 * 1024 {
                    return Err(GzError("DEFLATE segment too large"));
                }
            }
            Err(_) => return decode_via_flate2(compressed, output, out_start),
        }
    }
}

/// Single-threaded flate2 fallback for raw DEFLATE that linflate's segment
/// decoder cannot handle (e.g. a whole standard-gzip stream with no full-flush
/// boundaries). Appends to `output` from `out_start`.
fn decode_via_flate2(
    compressed: &[u8],
    output: &mut Vec<u8>,
    out_start: usize,
) -> Result<(), GzError> {
    use std::io::Read;
    output.truncate(out_start);
    let mut dec = flate2::read::DeflateDecoder::new(compressed);
    dec.read_to_end(output)
        .map_err(|_| GzError("DEFLATE segment decompression failed"))?;
    Ok(())
}

/// Decode a full chunk in parallel.
///
/// 1. Split the chunk at full-flush boundaries (N−1 scoped-thread tasks).
/// 2. If no boundaries found, returns `Err` — caller falls back to single-core.
/// 3. Otherwise decode `decode_segments` segments in parallel via scoped threads.
///
/// Returns `(concatenated_output, consumed_bytes)`.
pub fn decode_chunk(
    data: &[u8],
    n_workers: usize,
    is_last: bool,
) -> Result<(Vec<u8>, usize), GzError> {
    let split = split_chunk(data, n_workers, is_last).ok_or(GzError(
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

    let outputs: Vec<Result<Vec<u8>, GzError>> =
        gatling::gatling_forkjoin::gatling_for_each(segments.len(), 0, |i| {
            decode_segment(segments[i])
        });

    // Propagate any segment error before we touch the buffers, and pre-size the
    // result so the concatenating extend loop never reallocates (avoids the
    // grow-and-memcpy churn of an un-presized Vec on the second full copy).
    let mut decoded: Vec<Vec<u8>> = Vec::with_capacity(outputs.len());
    for r in outputs {
        decoded.push(r?);
    }
    let total: usize = decoded.iter().map(|v| v.len()).sum();
    let mut result = Vec::with_capacity(total);
    for seg in &decoded {
        result.extend_from_slice(seg);
    }

    Ok((result, split.consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_block(payload: &[u8], bfinal: bool) -> Vec<u8> {
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
        vec![0x00, 0x00, 0x00, 0xFF, 0xFF]
    }

    #[test]
    fn split_no_boundaries_returns_none() {
        let data: Vec<u8> = (0u8..=255).cycle().take(128).collect();
        assert!(split_chunk(&data, 4, true).is_none());
    }

    #[test]
    fn decode_stored_segment() {
        let data = stored_block(b"Hello, World!", true);
        let out = decode_segment(&data).expect("decode stored");
        assert_eq!(out, b"Hello, World!");
    }

    #[test]
    fn decode_real_deflate() {
        use miniz_oxide::deflate::compress_to_vec;
        let original = b"The quick brown fox jumps over the lazy dog".repeat(50);
        let compressed = compress_to_vec(&original, 6);
        let out = decode_segment(&compressed).expect("decode deflate");
        assert_eq!(out, original.to_vec());
    }

    #[test]
    fn decode_chunk_two_segments() {
        // payload_a > payload_b so the n=2 nominal split point (midpoint) lands
        // before the flush boundary; both segments ≥ PROBE_THRESHOLD so the
        // validated split confirms the boundary.
        let payload_a = vec![0xAA_u8; 8000];
        let payload_b = vec![0xBB_u8; 5000];
        let mut buf = stored_block(&payload_a, false);
        buf.extend_from_slice(&flush_marker());
        buf.extend_from_slice(&stored_block(&payload_b, true));

        let (output, consumed) = decode_chunk(&buf, 2, true).expect("decode two segments");
        assert_eq!(consumed, buf.len());
        let expected: Vec<u8> = payload_a.iter().chain(payload_b.iter()).copied().collect();
        assert_eq!(output, expected);
    }
}
