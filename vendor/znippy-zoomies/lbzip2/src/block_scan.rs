//! Bit-level scanner for bzip2 block boundaries.
//!
//! bzip2 blocks start with the 48-bit magic 0x314159265359 at arbitrary
//! **bit** offsets (not byte-aligned).  We scan a 64-bit sliding window
//! over the input, checking all 16 bit offsets per 2-byte step.
//!
//! For a 100 MB compressed chunk split 12 ways, each split point requires
//! scanning ~500 bytes forward — total work per slot is ~6 KB, effectively
//! zero cost.

use crate::BLOCK_MAGIC;
use crate::FINAL_MAGIC;
use crate::bitreader::BitReader;

/// A block boundary: byte offset and bit offset within that byte (0–7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockBoundary {
    /// Bit offset from the start of the buffer where the 48-bit magic begins.
    pub bit_offset: u64,
}

impl BlockBoundary {
    #[inline]
    pub fn byte_offset(self) -> usize {
        (self.bit_offset / 8) as usize
    }

    #[inline]
    pub fn bit_within_byte(self) -> u8 {
        (self.bit_offset % 8) as u8
    }
}

/// Scan `buf` for the first bzip2 block magic starting at or after bit
/// position `start_bit`.  Returns the bit offset of the magic, or `None`.
///
/// Uses a 64-bit sliding window with unrolled 16-way bit checks per
/// 2-byte step — ~32 bytes/cycle throughput on modern CPUs.
pub fn find_next_block(buf: &[u8], start_bit: u64) -> Option<BlockBoundary> {
    let start_byte = (start_bit / 8) as usize;

    if buf.len() < start_byte + 8 {
        return None;
    }

    let search = &buf[start_byte..];

    // Step through 2 bytes at a time with an 8-byte window.
    let mut byte_idx = 0usize;
    while byte_idx + 8 <= search.len() {
        let window = u64::from_be_bytes(search[byte_idx..byte_idx + 8].try_into().unwrap());

        // Check all 16 bit offsets within this 2-byte step.
        for shift in 0u32..16 {
            let candidate = (window >> (16 - shift)) & 0xFFFF_FFFF_FFFF;
            if candidate == BLOCK_MAGIC {
                let abs_bit = (start_byte + byte_idx) as u64 * 8 + shift as u64;
                if abs_bit >= start_bit {
                    return Some(BlockBoundary {
                        bit_offset: abs_bit,
                    });
                }
            }
        }

        byte_idx += 2;
    }

    None
}

/// Find every stream-end marker (the 48-bit FINAL_MAGIC) in `buf` and read the
/// 32-bit combined stream CRC stored immediately after each one, in order.
///
/// A well-formed single bzip2 stream has exactly one FINAL_MAGIC (at the very
/// end); pbzip2-style concatenations have one per sub-stream. The parallel
/// decoder uses this to verify the combined stream CRC without re-walking every
/// block sequentially. Like the block-magic scan, a coincidental 48-bit pattern
/// inside compressed data can produce a spurious extra entry — callers treat a
/// count other than one conservatively (skip the whole-stream check and rely on
/// the always-correct per-block CRCs) so this never causes a false rejection.
pub fn find_stream_crcs(buf: &[u8]) -> Vec<u32> {
    let mut crcs = Vec::new();
    let total_bits = buf.len() as u64 * 8;
    let mut bit = 0u64;
    while bit + 48 <= total_bits {
        match find_next_magic(buf, bit, FINAL_MAGIC) {
            Some(abs_bit) => {
                let after = abs_bit + 48;
                let mut reader = BitReader::from_bit_offset(buf, after as usize);
                if let Some(crc) = reader.read_u32(32) {
                    crcs.push(crc);
                }
                bit = after;
            }
            None => break,
        }
    }
    crcs
}

/// Parallel sibling of [`find_stream_crcs`].
///
/// The serial version walks the WHOLE compressed buffer on one thread to locate
/// the (usually single) trailing FINAL_MAGIC — a pure serial pass that runs on
/// one core while the other 11 sit idle right after the parallel decode. This
/// splits the buffer into `n_threads` chunks, scans each for FINAL_MAGIC in
/// parallel, and reads the trailing 32-bit CRC from the **global** buffer (so a
/// CRC straddling a chunk edge still reads whole). Results are merged in
/// bit-offset order with the same overlap + sort/dedup discipline as
/// [`find_all_blocks_parallel`], so the returned CRC list is identical to the
/// serial scan for both single and concatenated (pbzip2) streams.
pub fn find_stream_crcs_parallel(buf: &[u8], n_threads: usize) -> Vec<u32> {
    let n = n_threads.max(1);
    if buf.len() < 16 || n == 1 {
        return find_stream_crcs(buf);
    }

    let chunk_size = buf.len() / n;

    let per_thread: Vec<Vec<(u64, u32)>> = gatling::gatling_forkjoin::gatling_for_each(n, 0, |i| {
        let start_byte = i * chunk_size;
        // Overlap +8 bytes into the next chunk so a magic spanning the boundary
        // is caught; the global sort/dedup below drops the duplicate that the
        // neighbouring chunk also sees.
        let end_byte = if i + 1 < n {
            ((i + 1) * chunk_size) + 8
        } else {
            buf.len()
        };
        let start_bit = start_byte as u64 * 8;
        let end_bit = end_byte as u64 * 8;

        let mut result: Vec<(u64, u32)> = Vec::new();
        let mut bit = start_bit;
        while bit < end_bit {
            match find_next_magic(buf, bit, FINAL_MAGIC) {
                Some(abs_bit) if abs_bit < end_bit => {
                    let after = abs_bit + 48;
                    let mut reader = BitReader::from_bit_offset(buf, after as usize);
                    if let Some(crc) = reader.read_u32(32) {
                        result.push((abs_bit, crc));
                    }
                    bit = after;
                }
                _ => break,
            }
        }
        result
    });

    let mut all: Vec<(u64, u32)> = per_thread.into_iter().flatten().collect();
    all.sort_by_key(|&(bit, _)| bit);
    all.dedup_by_key(|&mut (bit, _)| bit);
    all.into_iter().map(|(_, crc)| crc).collect()
}

/// Scan `buf` for the first occurrence of the 48-bit `magic` at or after bit
/// position `start_bit`. Shared bit-window scanner used for both BLOCK_MAGIC and
/// FINAL_MAGIC.
fn find_next_magic(buf: &[u8], start_bit: u64, magic: u64) -> Option<u64> {
    let start_byte = (start_bit / 8) as usize;
    if buf.len() < start_byte + 8 {
        return None;
    }
    let search = &buf[start_byte..];
    let mut byte_idx = 0usize;
    while byte_idx + 8 <= search.len() {
        let window = u64::from_be_bytes(search[byte_idx..byte_idx + 8].try_into().unwrap());
        for shift in 0u32..16 {
            let candidate = (window >> (16 - shift)) & 0xFFFF_FFFF_FFFF;
            if candidate == magic {
                let abs_bit = (start_byte + byte_idx) as u64 * 8 + shift as u64;
                if abs_bit >= start_bit {
                    return Some(abs_bit);
                }
            }
        }
        byte_idx += 2;
    }
    None
}

/// Find all block boundaries in `buf`.
pub fn find_all_blocks(buf: &[u8]) -> Vec<BlockBoundary> {
    let mut result = Vec::new();
    let mut bit = 0u64;
    while let Some(b) = find_next_block(buf, bit) {
        result.push(b);
        bit = b.bit_offset + 48; // skip past this magic
    }
    result
}

/// Find all block boundaries using parallel chunk scanning.
///
/// Splits the buffer into `n_threads` chunks, scans each in parallel,
/// then merges and deduplicates the results in bit-offset order.
pub fn find_all_blocks_parallel(buf: &[u8], n_threads: usize) -> Vec<BlockBoundary> {
    let n = n_threads.max(1);
    if buf.len() < 16 || n == 1 {
        return find_all_blocks(buf);
    }

    let chunk_size = buf.len() / n;

    let per_thread: Vec<Vec<BlockBoundary>> =
        gatling::gatling_forkjoin::gatling_for_each(n, 0, |i| {
            let start_byte = i * chunk_size;
            // Each chunk scans until the START of the next chunk + 8 bytes overlap
            // (so we don't miss a magic that spans the boundary)
            let end_byte = if i + 1 < n {
                ((i + 1) * chunk_size) + 8
            } else {
                buf.len()
            };
            let start_bit = start_byte as u64 * 8;
            let end_bit = end_byte as u64 * 8;

            let mut result = Vec::new();
            let mut bit = start_bit;
            while bit < end_bit {
                match find_next_block(buf, bit) {
                    Some(b) if b.bit_offset < end_bit => {
                        result.push(b);
                        bit = b.bit_offset + 48;
                    }
                    _ => break,
                }
            }
            result
        });
    let mut all: Vec<BlockBoundary> = per_thread.into_iter().flatten().collect();
    all.sort_by_key(|b| b.bit_offset);
    all.dedup_by_key(|b| b.bit_offset);
    all
}

/// Given a compressed buffer and N desired splits, find the N-1 interior
/// block boundaries closest to the nominal split points.
///
/// Returns up to `n_splits - 1` boundaries.  The caller uses these plus
/// bit 0 and EOF to define the N ranges for parallel decompression.
pub fn split_boundaries(buf: &[u8], n_splits: usize) -> Vec<BlockBoundary> {
    if n_splits <= 1 || buf.is_empty() {
        return Vec::new();
    }

    let total_bits = buf.len() as u64 * 8;
    let mut boundaries = Vec::with_capacity(n_splits - 1);

    for i in 1..n_splits {
        let nominal_bit = total_bits * i as u64 / n_splits as u64;
        if let Some(b) = find_next_block(buf, nominal_bit) {
            // Deduplicate: don't add the same boundary twice.
            if boundaries
                .last()
                .map_or(true, |prev: &BlockBoundary| prev.bit_offset != b.bit_offset)
            {
                boundaries.push(b);
            }
        }
    }

    boundaries
}

/// Cheap false-positive check: read the block header fields after
/// the 48-bit magic and verify they're structurally valid.
///
/// Reads only 73 bits (~10 bytes) — no Huffman/MTF/BWT decode.
/// Catches random false positives almost instantly.
#[inline]
fn quick_verify_block(buf: &[u8], magic_bit_offset: u64, max_blocksize: u32) -> bool {
    use crate::bitreader::BitReader;

    let total_bits = buf.len() as u64 * 8;
    let after_magic = magic_bit_offset + 48;
    // Need at least 73 bits: CRC(32) + randomised(1) + orig_ptr(24) + bitmap(16)
    if after_magic + 73 > total_bits {
        return false;
    }

    let mut reader = BitReader::from_bit_offset(buf, after_magic as usize);

    // CRC32 — any value is fine
    if reader.read_u32(32).is_none() {
        return false;
    }

    // Randomised flag — must be 0 (randomised blocks are obsolete)
    match reader.read_bit() {
        Some(false) => {}
        _ => return false,
    }

    // orig_ptr — must be < max_blocksize
    match reader.read_u32(24) {
        Some(v) if v < max_blocksize => {}
        _ => return false,
    }

    // Symbol group bitmap — at least one of 16 groups must be present
    match reader.read_u16(16) {
        Some(v) if v != 0 => {}
        _ => return false,
    }

    true
}

/// Find a **quick-verified** block boundary starting from `start_bit`.
///
/// Forward-scans for the 48-bit magic, then checks 73 bits of block
/// header structure to reject false positives.  No full decode needed.
pub fn find_quick_boundary(
    buf: &[u8],
    start_bit: u64,
    max_blocksize: u32,
) -> Option<BlockBoundary> {
    let total_bits = buf.len() as u64 * 8;
    let mut search_bit = start_bit;

    loop {
        let candidate = find_next_block(buf, search_bit)?;
        if candidate.bit_offset + 48 + 73 > total_bits {
            return None;
        }
        if quick_verify_block(buf, candidate.bit_offset, max_blocksize) {
            return Some(candidate);
        }
        search_bit = candidate.bit_offset + 1;
    }
}

/// Parallel split boundary search: each of N cores finds its own boundary.
///
/// Each thread calculates its nominal split position, forward-scans for
/// the next BLOCK_MAGIC, and quick-verifies the header (~10 bytes).
/// All N-1 splits run simultaneously — 12x faster than sequential.
pub fn split_boundaries_parallel(
    buf: &[u8],
    n_splits: usize,
    max_blocksize: u32,
) -> Vec<BlockBoundary> {
    if n_splits <= 1 || buf.is_empty() {
        return Vec::new();
    }

    let total_bits = buf.len() as u64 * 8;

    let boundaries: Vec<Option<BlockBoundary>> =
        gatling::gatling_forkjoin::gatling_for_each(n_splits - 1, 0, |idx| {
            let i = idx + 1;
            let nominal_bit = total_bits * i as u64 / n_splits as u64;
            find_quick_boundary(buf, nominal_bit, max_blocksize)
        });

    // Filter, sort, deduplicate
    let mut result: Vec<BlockBoundary> = boundaries.into_iter().flatten().collect();
    result.sort_by_key(|b| b.bit_offset);
    result.dedup_by_key(|b| b.bit_offset);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_magic_byte_aligned() {
        // Place magic at byte offset 10, bit-aligned (bit offset 80).
        let mut buf = vec![0u8; 64];
        let magic_bytes: [u8; 6] = [0x31, 0x41, 0x59, 0x26, 0x53, 0x59];
        buf[10..16].copy_from_slice(&magic_bytes);

        let b = find_next_block(&buf, 0).unwrap();
        assert_eq!(b.bit_offset, 80);
        assert_eq!(b.byte_offset(), 10);
        assert_eq!(b.bit_within_byte(), 0);
    }

    #[test]
    fn test_find_magic_bit_shifted() {
        // Place magic shifted by 3 bits into byte offset 10.
        // 48-bit magic at bit offset 83 (byte 10, bit 3).
        let mut buf = vec![0u8; 64];
        let magic: u64 = BLOCK_MAGIC;
        // Write magic at bit offset 83: byte 10 bit 3.
        // That means bits 83..131 carry the magic.
        let shifted = magic << (64 - 48 - 3); // align to bit 3 of a 64-bit word
        let bytes = shifted.to_be_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if 10 + i < buf.len() {
                buf[10 + i] |= b;
            }
        }

        let b = find_next_block(&buf, 0).unwrap();
        assert_eq!(b.bit_offset, 83);
        assert_eq!(b.byte_offset(), 10);
        assert_eq!(b.bit_within_byte(), 3);
    }

    #[test]
    fn test_no_magic() {
        let buf = vec![0xFFu8; 64];
        assert!(find_next_block(&buf, 0).is_none());
    }

    /// Core-saturation invariant for the readers' switch from the serial
    /// `find_all_blocks` to `find_all_blocks_parallel`: on a REAL multi-block
    /// bzip2 stream the parallel chunk-scan must return the EXACT same boundary
    /// set (same order, no dupes, no misses) as the serial walk, for every core
    /// count. If these agree, the parallel-scanned readers decode identically.
    #[test]
    fn parallel_scan_matches_serial_multiblock() {
        use bzip2::write::BzEncoder;
        use std::io::Write;

        // Level-1 ⇒ 100 KB uncompressed blocks; ~700 KB of varied (barely
        // compressible) data ⇒ several genuine blocks, hence several magics.
        let payload: Vec<u8> = (0..700_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let mut enc = BzEncoder::new(Vec::new(), bzip2::Compression::new(1));
        enc.write_all(&payload).unwrap();
        let compressed = enc.finish().unwrap();

        let serial = find_all_blocks(&compressed);
        assert!(
            serial.len() >= 3,
            "test needs a multi-block stream; got {} block(s)",
            serial.len()
        );

        for n in [2usize, 3, 4, 8, 12, 16, 32] {
            let par = find_all_blocks_parallel(&compressed, n);
            assert_eq!(
                par, serial,
                "parallel scan (n={n}) must equal the serial boundary set"
            );
        }
    }
}
