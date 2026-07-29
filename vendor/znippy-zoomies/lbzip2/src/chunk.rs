//! Chunk-level parallel bzip2 decoder.
//!
//! Designed for zero-copy operation: the caller reads ~100 MB of
//! compressed data into a chunk buffer, then passes the `&[u8]`
//! directly to the decoder — no per-block copy.
//!
//! The decoder scans for block boundaries, parallel-decodes all
//! complete blocks, and returns:
//!   - `decompressed`: the concatenated output (~800–1000 MB)
//!   - `consumed`:     how many bytes were fully decoded
//!
//! The caller carries `data[consumed..]` into the next slot.

use crate::bitreader::BitReader;
use crate::block;
use crate::block_scan;
use crate::{BLOCK_MAGIC, FINAL_MAGIC};

/// Which inverse-BWT / RLE1 chase strategy a segment decode uses.
///
/// GATING: [`DecodeMode::Interleaved`] runs several blocks' inverse-BWT pointer
/// chases in lockstep to overlap their dependent-load latency (memory-level
/// parallelism, see [`block::decode_blocks_interleaved`]). This is a large win on a
/// SINGLE core but neutral-to-harmful at high core counts (the socket is already
/// memory-bandwidth-bound), so the CLI selects it ONLY when decoding with one
/// worker. [`DecodeMode::Serial`] is the block-by-block baseline — the default and
/// the exact path every multi-worker and library decode takes (byte-identical to
/// before this option existed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeMode {
    /// Block-by-block chase directly into the output (baseline; all multi-worker
    /// and library decodes).
    Serial,
    /// Interleaved multi-block chase (single-worker CLI decode only).
    Interleaved,
}

/// Result of splitting a chunk into segment boundaries.
pub struct ChunkSplit {
    /// Segment start boundaries (one per segment found).
    pub segment_starts: Vec<block_scan::BlockBoundary>,
    /// Number of segments to decode (all if is_last, else n-1).
    pub decode_segments: usize,
    /// Bytes consumed from the data (for carry computation).
    pub consumed: usize,
}

/// Split a chunk of compressed data into segment boundaries.
///
/// `n_segments` is typically n_cores (one segment per worker).
/// Uses parallel scanning (scoped-thread `par_map`) for speed.
///
/// Returns `None` if no block boundary found in data.
pub fn split_chunk(
    data: &[u8],
    n_segments: usize,
    max_blocksize: u32,
    is_last: bool,
) -> Option<ChunkSplit> {
    let first_block = block_scan::find_next_block(data, 0)?;

    let splits = block_scan::split_boundaries_parallel(data, n_segments, max_blocksize);

    let mut segment_starts = Vec::with_capacity(n_segments);
    segment_starts.push(first_block);
    for s in &splits {
        if segment_starts
            .last()
            .map_or(true, |prev: &block_scan::BlockBoundary| {
                prev.bit_offset != s.bit_offset
            })
        {
            segment_starts.push(*s);
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
        segment_starts[decode_segments].byte_offset()
    } else {
        data.len()
    };

    Some(ChunkSplit {
        segment_starts,
        decode_segments,
        consumed,
    })
}

/// A decoded segment: the concatenated block output plus the ordered list of
/// each decoded block's (verified) CRC-32.
///
/// The per-block CRCs are folded by the caller into the running combined stream
/// CRC so the whole-stream checksum can be verified after a parallel decode.
pub struct SegmentDecoded {
    pub data: Vec<u8>,
    /// One entry per decoded block, in stream order (already CRC-verified).
    pub block_crcs: Vec<u32>,
}

/// Decode a single segment of compressed bzip2 data.
///
/// Reads blocks from `start_bit` (after the 48-bit BLOCK_MAGIC) up to `end_bit`.
/// Handles pbzip2 concatenated streams (FINAL_MAGIC boundaries).
///
/// Zero per-block allocation: decodes directly into the output buffer
/// using `decode_block_into()`. Only the segment Vec grows (amortised).
///
/// This is the **lenient** entry point kept for backward compatibility: on a
/// decode failure it returns the bytes decoded so far (never panics). Callers
/// that must REJECT a corrupt/tampered stream (the parallel library API and the
/// `lbunzip2` CLI) use [`decode_segment_checked`], which surfaces the per-block
/// CRC failure as an error instead of yielding silently-truncated output.
pub fn decode_segment(data: &[u8], start_bit: u64, end_bit: u64, max_blocksize: u32) -> Vec<u8> {
    let mut output = Vec::with_capacity(seg_cap_hint(start_bit, end_bit));
    let mut block_crcs: Vec<u32> = Vec::new();
    decode_segment_inner(
        data,
        start_bit,
        end_bit,
        max_blocksize,
        &mut output,
        &mut block_crcs,
        DecodeMode::Serial,
    );
    output
}

/// Integrity-checked variant of [`decode_segment`].
///
/// SECURITY: a block whose stored CRC-32 does not match its decompressed bytes
/// (a truncated or tampered stream) is returned as a [`block::BlockError`] — it
/// is **never** silently accepted as partial output. This is the parallel-path
/// counterpart of the per-block check the sequential [`crate::stream::decompress`]
/// already performs. Structural framing markers (end-of-segment, FINAL_MAGIC,
/// EOF) still terminate the segment cleanly.
///
/// Returns the decompressed output plus the ordered per-block CRC list (which the
/// caller folds into the combined whole-stream CRC).
pub fn decode_segment_checked(
    data: &[u8],
    start_bit: u64,
    end_bit: u64,
    max_blocksize: u32,
) -> Result<SegmentDecoded, block::BlockError> {
    let mut output = Vec::with_capacity(seg_cap_hint(start_bit, end_bit));
    let mut block_crcs: Vec<u32> = Vec::new();
    match decode_segment_inner(
        data,
        start_bit,
        end_bit,
        max_blocksize,
        &mut output,
        &mut block_crcs,
        DecodeMode::Serial,
    ) {
        None => Ok(SegmentDecoded {
            data: output,
            block_crcs,
        }),
        Some(e) => Err(e),
    }
}

/// Shared decode loop. Decodes as far as it can and returns the accumulated
/// output plus the first decode error encountered (if any). The lenient wrapper
/// discards the error (returning the partial output, preserving the historical
/// behaviour); the checked wrapper turns a present error into `Err`.
/// Estimated decoded size of a segment from its compressed bit-span (×4: bzip2 text
/// decompresses ~4–8×). Used to presize the output so `decode_block_into` appends
/// without doubling reallocs (each of which memcpys the whole buffer).
#[inline]
fn seg_cap_hint(start_bit: u64, end_bit: u64) -> usize {
    let comp_span = (end_bit.saturating_sub(start_bit) / 8) as usize;
    comp_span.saturating_mul(4).min(256 * 1024 * 1024)
}

/// Decode the segment into the caller-supplied `output`/`block_crcs` buffers,
/// appending. The caller owns (and may recycle) both — this fn never allocates them,
/// so a warmed buffer pool decodes with ZERO per-segment allocation. Returns the first
/// decode error (if any); on error the partial output is left in `output`.
fn decode_segment_inner(
    data: &[u8],
    start_bit: u64,
    end_bit: u64,
    max_blocksize: u32,
    output: &mut Vec<u8>,
    block_crcs: &mut Vec<u32>,
    mode: DecodeMode,
) -> Option<block::BlockError> {
    match mode {
        // Single-worker CLI decode: interleave N blocks' inverse-BWT chases (MLP).
        DecodeMode::Interleaved => {
            decode_segment_interleaved(data, start_bit, end_bit, max_blocksize, output, block_crcs)
        }
        // Everything else: the block-by-block baseline (byte-identical to before).
        DecodeMode::Serial => {
            decode_segment_serial(data, start_bit, end_bit, max_blocksize, output, block_crcs)
        }
    }
}

/// Baseline block-by-block segment decode: each block is chased directly onto the
/// tail of `output`. This is the exact path all multi-worker and library decodes
/// take — unchanged by the single-thread MLP work.
fn decode_segment_serial(
    data: &[u8],
    start_bit: u64,
    end_bit: u64,
    max_blocksize: u32,
    output: &mut Vec<u8>,
    block_crcs: &mut Vec<u32>,
) -> Option<block::BlockError> {
    let total_bits = data.len() as u64 * 8;

    let mut reader = BitReader::from_bit_offset(data, (start_bit + 48) as usize);
    // The segment's first block MUST decode: a CRC mismatch or malformed block
    // here is corruption, not a framing boundary.
    match decode_block_into_vec(output, &mut reader, max_blocksize) {
        Ok(crc) => block_crcs.push(crc),
        Err(e) => return Some(e),
    }

    loop {
        let pos = reader.position() as u64;
        if pos + 48 > total_bits || pos >= end_bit {
            break;
        }
        let magic = match reader.read_u64(48) {
            Some(v) => v,
            None => break,
        };
        if magic == BLOCK_MAGIC {
            // A block magic we chose to decode: any decode failure (including a
            // CRC mismatch) is corruption, recorded and surfaced by the checked
            // wrapper rather than silently swallowed.
            match decode_block_into_vec(output, &mut reader, max_blocksize) {
                Ok(crc) => block_crcs.push(crc),
                Err(e) => return Some(e),
            }
        } else if magic == FINAL_MAGIC {
            if reader.read_u32(32).is_none() {
                break;
            }
            let p = reader.position();
            let pad = (8 - (p % 8)) % 8;
            if pad > 0 {
                BitReader::skip(&mut reader, pad);
            }
            match reader.read_u32(32) {
                Some(h) => {
                    let b = h.to_be_bytes();
                    if &b[..3] != b"BZh" {
                        break;
                    }
                }
                None => break,
            }
        } else {
            break;
        }
    }

    None
}

/// Interleave factor for the single-thread memory-level-parallel decode: how many
/// blocks' inverse-BWT pointer-chases run in lockstep. The chains are independent,
/// so their dependent-load latencies overlap (see `block::decode_blocks_interleaved`).
/// N=4 measured best on this microarchitecture (single-thread cycles 78 B → 47 B);
/// N=2 leaves ~half the win on the table, N>4 adds working-set pressure for little
/// further latency hiding.
const MLP_N: usize = 4;

/// Single-thread MLP segment decode: gather up to `MLP_N` block cores (advancing the
/// bitstream sequentially), chase them interleaved to overlap their dependent-load
/// latency, and append their bytes in stream order. Produces byte-identical output to
/// [`decode_segment_serial`]; only the chase scheduling differs.
fn decode_segment_interleaved(
    data: &[u8],
    start_bit: u64,
    end_bit: u64,
    max_blocksize: u32,
    output: &mut Vec<u8>,
    block_crcs: &mut Vec<u32>,
) -> Option<block::BlockError> {
    let total_bits = data.len() as u64 * 8;

    let mut reader = BitReader::from_bit_offset(data, (start_bit + 48) as usize);
    let mut first = true;
    let mut cores: Vec<block::BlockCore> = Vec::with_capacity(MLP_N);

    loop {
        // ── Gather up to MLP_N block cores (header+Huffman+MTF+RLE2+inverse-BWT),
        //    advancing the bitstream sequentially. ────────────────────────────────
        cores.clear();
        let mut ended = false;
        let mut gather_err: Option<block::BlockError> = None;
        while cores.len() < MLP_N {
            match next_block_core(&mut reader, end_bit, total_bits, max_blocksize, &mut first) {
                Ok(Some(core)) => cores.push(core),
                Ok(None) => {
                    ended = true;
                    break;
                }
                Err(e) => {
                    gather_err = Some(e);
                    break;
                }
            }
        }

        // ── Chase the gathered cores INTERLEAVED (the MLP hot loop) and append
        //    their bytes in stream order, CRC-checking each. ────────────────────
        if !cores.is_empty() {
            if let Err(e) = block::decode_blocks_interleaved(&mut cores, output, block_crcs) {
                return Some(e);
            }
        }

        // A gather error surfaces only AFTER the already-parsed (earlier-in-stream)
        // cores have been chased+appended, matching the block-by-block order.
        if let Some(e) = gather_err {
            return Some(e);
        }
        if ended {
            break;
        }
    }

    None
}

/// Advance the reader to the next block and decode its core (header → inverse-BWT),
/// WITHOUT the final RLE1 pointer-chase. Returns `Ok(None)` at a clean framing
/// boundary (end-of-segment, EOF, FINAL_MAGIC with no following stream, or a non-
/// magic word), `Ok(Some(core))` for a block to chase, or `Err` on a malformed block.
///
/// Encapsulates the exact framing state machine [`decode_segment_serial`] uses: the
/// segment's first block MUST decode; subsequent blocks are gated on BLOCK_MAGIC, and
/// FINAL_MAGIC + a valid following `BZh` header continues into a concatenated (pbzip2)
/// stream.
#[inline]
fn next_block_core(
    reader: &mut BitReader<'_>,
    end_bit: u64,
    total_bits: u64,
    max_blocksize: u32,
    first: &mut bool,
) -> Result<Option<block::BlockCore>, block::BlockError> {
    if *first {
        // The segment's first block MUST decode: a CRC mismatch or malformed block
        // here is corruption, not a framing boundary.
        *first = false;
        return block::decode_block_core(reader, max_blocksize).map(Some);
    }

    loop {
        // Inherent `BitReader::position` (fully qualified: `&mut BitReader` also
        // implements `Iterator`, whose `position` would otherwise shadow it).
        let pos = BitReader::position(reader) as u64;
        if pos + 48 > total_bits || pos >= end_bit {
            return Ok(None);
        }
        let magic = match reader.read_u64(48) {
            Some(v) => v,
            None => return Ok(None),
        };
        if magic == BLOCK_MAGIC {
            return block::decode_block_core(reader, max_blocksize).map(Some);
        } else if magic == FINAL_MAGIC {
            if reader.read_u32(32).is_none() {
                return Ok(None);
            }
            let p = BitReader::position(reader);
            let pad = (8 - (p % 8)) % 8;
            if pad > 0 {
                BitReader::skip(reader, pad);
            }
            match reader.read_u32(32) {
                Some(h) => {
                    let b = h.to_be_bytes();
                    if &b[..3] != b"BZh" {
                        return Ok(None);
                    }
                }
                None => return Ok(None),
            }
            // Concatenated stream: loop to read the next stream's first block magic.
        } else {
            return Ok(None);
        }
    }
}

// Per-worker scratch for the CRC list the streaming `_into` path does not return
// (each block is CRC-checked inline; the whole-stream fold is the library path's job).
// Thread-local + reused, so the zero-alloc decode stays zero-alloc.
thread_local! {
    static CRC_SCRATCH: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Zero-alloc, CRC-checked segment decode into a caller-owned **reused** buffer.
///
/// Identical integrity guarantees to [`decode_segment_checked`] (a per-block CRC
/// mismatch → `Err`), but the output buffer is supplied by the caller (a recycled
/// slot) and the per-block CRC list lands in a thread-local scratch instead of a
/// fresh `Vec`. A warmed pool of `out` buffers therefore decodes with no allocation.
pub fn decode_segment_checked_into(
    data: &[u8],
    start_bit: u64,
    end_bit: u64,
    max_blocksize: u32,
    out: &mut Vec<u8>,
    mode: DecodeMode,
) -> Result<(), block::BlockError> {
    out.clear();
    out.reserve(seg_cap_hint(start_bit, end_bit));
    CRC_SCRATCH.with(|c| {
        let mut crcs = c.borrow_mut();
        crcs.clear();
        match decode_segment_inner(
            data,
            start_bit,
            end_bit,
            max_blocksize,
            out,
            &mut crcs,
            mode,
        ) {
            None => Ok(()),
            Some(e) => Err(e),
        }
    })
}

/// Decode one block directly onto the tail of `output`, avoiding a temporary Vec.
/// `output` grows to fit the block's actual (data-dependent, possibly ≫
/// max_blocksize) RLE1-expanded size; on error it is rolled back to its prior
/// length by [`block::decode_block_into`]. Returns the block's verified CRC-32.
#[inline]
fn decode_block_into_vec(
    output: &mut Vec<u8>,
    reader: &mut BitReader<'_>,
    max_blocksize: u32,
) -> Result<u32, block::BlockError> {
    let (_written, crc) = block::decode_block_into(reader, max_blocksize, output)?;
    Ok(crc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn max_blocksize(data: &[u8]) -> u32 {
        100_000 * (data[3] - b'0') as u32
    }

    #[test]
    fn chunk_hello() {
        let data = include_bytes!("../test_data/hello.bz2");
        let split = split_chunk(data, 4, max_blocksize(data), true).unwrap();
        let total_bits = data.len() as u64 * 8;
        let mut output = Vec::new();
        for i in 0..split.decode_segments {
            let start = split.segment_starts[i].bit_offset;
            let end = if i + 1 < split.segment_starts.len() {
                split.segment_starts[i + 1].bit_offset
            } else {
                total_bits
            };
            output.extend_from_slice(&decode_segment(data, start, end, max_blocksize(data)));
        }
        assert_eq!(&output, b"Hello, World!\n");
    }

    /// Decode the whole stream as ONE segment (so every block lands in the same
    /// interleave-batch sequence) with the chosen [`DecodeMode`].
    fn decode_whole(data: &[u8], mode: DecodeMode) -> Vec<u8> {
        let split = split_chunk(data, 1, max_blocksize(data), true).unwrap();
        let total_bits = data.len() as u64 * 8;
        let mut out_all = Vec::new();
        let mut buf = Vec::new();
        for i in 0..split.decode_segments {
            let start = split.segment_starts[i].bit_offset;
            let end = if i + 1 < split.segment_starts.len() {
                split.segment_starts[i + 1].bit_offset
            } else {
                total_bits
            };
            decode_segment_checked_into(data, start, end, max_blocksize(data), &mut buf, mode)
                .unwrap();
            out_all.extend_from_slice(&buf);
        }
        out_all
    }

    /// The single-thread `DecodeMode::Interleaved` (MLP) path must produce
    /// byte-identical output to the serial baseline and the sequential reference.
    #[test]
    fn interleaved_matches_serial() {
        let data = include_bytes!("../test_data/liechtenstein.osm.bz2");
        let reference = crate::stream::decompress(data).unwrap();
        let serial = decode_whole(data, DecodeMode::Serial);
        let interleaved = decode_whole(data, DecodeMode::Interleaved);
        assert_eq!(serial, reference, "serial mode diverged from reference");
        assert_eq!(
            interleaved.len(),
            reference.len(),
            "interleaved size mismatch"
        );
        assert_eq!(
            interleaved, reference,
            "interleaved mode diverged from reference"
        );
    }

    /// A valid `bzip2 -9` stream of 4 MiB of a single byte. RLE1 collapses the
    /// 4 MiB to ~49 bytes on disk, and the whole thing is ONE block whose final
    /// RLE1-*decode* expands back to 4 MiB — ~3.7× the old `max_blocksize + 25%`
    /// (1.125 MiB) segment-buffer bound. Before the growable-append fix this
    /// overflowed the fixed slice: an assert-panic on the checked path, a raw
    /// heap overrun / SIGSEGV on the lenient planet-convert path. Regression for
    /// the "non-deterministic planet bz2 crash" — planet OSM-XML has exactly this
    /// shape (long whitespace / repeated-tag runs). See `block::rle2_decode_append`.
    const REP_4M_A_BZ2: [u8; 49] = [
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xf7, 0x09, 0x6c, 0x45, 0x00,
        0x20, 0x22, 0x0c, 0x00, 0x80, 0x04, 0x20, 0x00, 0x00, 0x08, 0x20, 0x00, 0x30, 0xcc, 0x05,
        0x49, 0xea, 0x71, 0x01, 0x80, 0x50, 0x06, 0x01, 0xe2, 0xee, 0x48, 0xa7, 0x0a, 0x12, 0x1e,
        0xe1, 0x2d, 0x88, 0xa0,
    ];

    #[test]
    fn rle1_expansion_far_exceeds_blocksize() {
        let data = &REP_4M_A_BZ2;
        let expected = vec![b'A'; 4 * 1024 * 1024];

        // Sequential whole-block path.
        assert_eq!(crate::stream::decompress(data).unwrap(), expected);

        // Parallel block-decode path (the one that crashed on the planet).
        assert_eq!(
            crate::parallel::decompress_parallel(data).unwrap(),
            expected
        );

        // Segment path directly (checked wrapper — must NOT panic/overflow).
        let split = split_chunk(data, 4, max_blocksize(data), true).unwrap();
        let total_bits = data.len() as u64 * 8;
        let mut out = Vec::new();
        for i in 0..split.decode_segments {
            let start = split.segment_starts[i].bit_offset;
            let end = if i + 1 < split.segment_starts.len() {
                split.segment_starts[i + 1].bit_offset
            } else {
                total_bits
            };
            let seg = decode_segment_checked(data, start, end, max_blocksize(data)).unwrap();
            out.extend_from_slice(&seg.data);
        }
        assert_eq!(out, expected);

        // Single-thread interleaved (MLP) path must survive the same RLE1-run
        // expansion (the per-chain capacity-growth invariant, exercised here).
        assert_eq!(decode_whole(data, DecodeMode::Interleaved), expected);
    }

    #[test]
    fn chunk_liechtenstein() {
        let data = include_bytes!("../test_data/liechtenstein.osm.bz2");
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let split = split_chunk(data, n, max_blocksize(data), true).unwrap();
        let total_bits = data.len() as u64 * 8;
        let mut output = Vec::new();
        for i in 0..split.decode_segments {
            let start = split.segment_starts[i].bit_offset;
            let end = if i + 1 < split.segment_starts.len() {
                split.segment_starts[i + 1].bit_offset
            } else {
                total_bits
            };
            output.extend_from_slice(&decode_segment(data, start, end, max_blocksize(data)));
        }
        let reference = crate::stream::decompress(data).unwrap();
        assert_eq!(output.len(), reference.len());
        assert_eq!(output, reference);
    }

    #[test]
    fn chunk_split_simulation() {
        let data = include_bytes!("../test_data/liechtenstein.osm.bz2");
        let mbs = max_blocksize(data);
        let mid = data.len() / 2;
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let split1 = split_chunk(&data[..mid], n, mbs, false).unwrap();
        let consumed1 = split1.consumed;
        assert!(consumed1 <= mid);

        let total_bits1 = mid as u64 * 8;
        let mut out1 = Vec::new();
        for i in 0..split1.decode_segments {
            let start = split1.segment_starts[i].bit_offset;
            let end = if i + 1 < split1.segment_starts.len() {
                split1.segment_starts[i + 1].bit_offset
            } else {
                total_bits1
            };
            out1.extend_from_slice(&decode_segment(&data[..mid], start, end, mbs));
        }
        assert!(!out1.is_empty());

        let chunk2 = &data[consumed1..];
        let split2 = split_chunk(chunk2, n, mbs, true).unwrap();
        let total_bits2 = chunk2.len() as u64 * 8;
        let mut out2 = Vec::new();
        for i in 0..split2.decode_segments {
            let start = split2.segment_starts[i].bit_offset;
            let end = if i + 1 < split2.segment_starts.len() {
                split2.segment_starts[i + 1].bit_offset
            } else {
                total_bits2
            };
            out2.extend_from_slice(&decode_segment(chunk2, start, end, mbs));
        }

        let mut combined = out1;
        combined.extend_from_slice(&out2);
        let reference = crate::stream::decompress(data).unwrap();
        assert_eq!(combined.len(), reference.len());
        assert_eq!(combined, reference);
    }
}
