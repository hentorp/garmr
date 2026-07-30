//! Parallel bzip2 decompression — decode N blocks concurrently.
//!
//! Uses `block_scan::find_all_blocks()` to locate every block boundary,
//! then decodes all blocks in parallel (scoped threads). Results are concatenated
//! in order.

use crate::block::BlockError;
use crate::block_scan;
use crate::chunk;

/// Decompress a complete bzip2 stream using parallel block decode.
///
/// `data` must be a complete bzip2 stream (header + blocks + EOS).
/// Blocks are decoded concurrently on scoped worker threads.
pub fn decompress_parallel(data: &[u8]) -> Result<Vec<u8>, BlockError> {
    // ── Parse stream header ─────────────────────────────────────────────
    if data.len() < 4 {
        return Err(BlockError("input too short for bzip2 header"));
    }
    if &data[..2] != b"BZ" {
        return Err(BlockError("bad bzip2 signature"));
    }
    if data[2] != b'h' {
        return Err(BlockError("only huffman bzip2 supported"));
    }
    let level = data[3];
    if !(b'1'..=b'9').contains(&level) {
        return Err(BlockError("invalid bzip2 block size level"));
    }
    let max_blocksize = 100_000 * (level - b'0') as u32;

    // ── Scan for all block boundaries ───────────────────────────────────
    // Parallel bit-scan for BZh block magics. The serial `find_all_blocks`
    // walks the whole stream on one thread (a serial prefix that dominates on
    // large inputs); the parallel scan splits the buffer across cores and
    // merges, producing the identical boundary set.
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let boundaries = block_scan::find_all_blocks_parallel(data, n_threads);

    if boundaries.is_empty() {
        // Might be an empty file or just EOS marker
        return Ok(Vec::new());
    }

    // ── Group blocks into one segment per worker ────────────────────────
    // Perf: rather than decode every block into its own `Vec<u8>` and then
    // concatenate ~N_blocks buffers (≈1 GB of extra copying for a large stream,
    // plus a heap allocation per block), we split the blocks into `n_threads`
    // contiguous segments. Each worker runs the `chunk::decode_segment` path,
    // which appends every block in its range directly into a single growing
    // buffer via `decode_block_into` — no per-block Vec. The final assembly
    // then concatenates only `n_threads` segment buffers instead of N_blocks.
    let total_bits = data.len() as u64 * 8;
    let n_blocks = boundaries.len();
    // Oversubscribe segments relative to thread count so the balanced pool's
    // heaviest-first (LPT) claim can absorb uneven block decode costs (a single
    // fat segment must not strand a whole worker on the tail). ~8 segments/thread
    // keeps each segment to a few blocks — fine enough for the scheduler to keep
    // all cores busy to the end — while still amortising the per-block-Vec + concat
    // savings (only `n_segments` buffers get concatenated, not `n_blocks`).
    let n_segments = (n_threads * 8).min(n_blocks).max(1);

    // Segment i owns blocks [seg_start(i) .. seg_start(i+1)). We record each
    // segment's first-block bit offset and the end bit (= next segment's first
    // block, or end-of-stream for the last segment).
    let mut segments: Vec<(u64, u64)> = Vec::with_capacity(n_segments);
    for i in 0..n_segments {
        let first_block = i * n_blocks / n_segments;
        let next_first_block = (i + 1) * n_blocks / n_segments;
        let start_bit = boundaries[first_block].bit_offset;
        let end_bit = if next_first_block < n_blocks {
            boundaries[next_first_block].bit_offset
        } else {
            total_bits
        };
        segments.push((start_bit, end_bit));
    }

    // ── Parallel decode: one segment buffer per worker ──────────────────
    // Heaviest-first (LPT) balanced dispatch: weight each segment by its
    // compressed bit-span (`end_bit - start_bit`), a proxy for decode cost, so
    // the fat segments are claimed first and the cheap ones fill the tail. With
    // plain `gatling_for_each` (in-index-order claim) a heavy segment claimed late
    // stranded one core while the rest idled — the multicore tail that cost us
    // ~0.3 cores-busy vs lbzip2. Results still come back in original segment order.
    let results: Vec<Result<chunk::SegmentDecoded, BlockError>> =
        gatling::gatling_forkjoin::gatling_for_each_balanced(
            segments.len(),
            0, // one worker per core
            1, // batch=1 — segments are already coarse; claim one at a time for the tightest tail
            |si| segments[si].1 - segments[si].0,
            |si| {
                let (start_bit, end_bit) = segments[si];
                chunk::decode_segment_checked(data, start_bit, end_bit, max_blocksize)
            },
        );

    // ── Integrity: propagate any per-block CRC failure ──────────────────
    // A tampered/truncated block whose stored CRC-32 does not match is now a
    // hard error instead of silently-truncated output (the security finding).
    let mut decoded: Vec<chunk::SegmentDecoded> = Vec::with_capacity(results.len());
    for r in results {
        decoded.push(r?);
    }

    // Fold every block's verified CRC into the combined stream CRC, in stream
    // order (segments are ordered by start_bit; blocks within a segment are in
    // order), matching the sequential decoder's rotate-left-1-then-XOR scheme.
    let mut combined_crc: u32 = 0;
    for seg in &decoded {
        for &c in &seg.block_crcs {
            combined_crc = (combined_crc << 1) | (combined_crc >> 31);
            combined_crc ^= c;
        }
    }

    // Verify the whole-stream combined CRC for a single bzip2 stream (exactly
    // one FINAL_MAGIC + stored CRC). Concatenated (pbzip2) inputs carry one CRC
    // per sub-stream; the per-block CRCs above already validate their integrity,
    // so we skip the whole-stream fold there rather than risk a false rejection.
    let stream_crcs = block_scan::find_stream_crcs_parallel(data, n_threads);
    if stream_crcs.len() == 1 && stream_crcs[0] != combined_crc {
        return Err(BlockError("stream CRC mismatch"));
    }

    // ── Assemble output in order (only n_segments copies) ───────────────
    let total_size: usize = decoded.iter().map(|s| s.data.len()).sum();
    let mut output = Vec::with_capacity(total_size);
    for seg in decoded {
        output.extend_from_slice(&seg.data);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_hello() {
        let compressed = include_bytes!("../test_data/hello.bz2");
        let output = decompress_parallel(compressed).unwrap();
        assert_eq!(&output, b"Hello, World!\n");
    }

    #[test]
    fn parallel_liechtenstein() {
        let compressed = include_bytes!("../test_data/liechtenstein.osm.bz2");
        let output = decompress_parallel(compressed).unwrap();
        // Compare with sequential decode
        let sequential = crate::stream::decompress(compressed).unwrap();
        assert_eq!(output.len(), sequential.len(), "size mismatch");
        assert_eq!(output, sequential, "content mismatch");
    }

    #[test]
    fn parallel_matches_sequential() {
        let compressed = include_bytes!("../test_data/liechtenstein.osm.bz2");
        let par = decompress_parallel(compressed).unwrap();
        let seq = crate::stream::decompress(compressed).unwrap();
        assert_eq!(par, seq);
    }
}
