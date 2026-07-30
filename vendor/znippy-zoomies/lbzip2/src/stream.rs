//! bzip2 stream decoder — sequential multi-block decompression.
//!
//! Decodes a complete bzip2 stream (header + N blocks + EOS marker).
//! This is the single-threaded reference path; the parallel pipeline
//! will split blocks across workers instead.

use crate::BLOCK_MAGIC;
use crate::FINAL_MAGIC;
use crate::bitreader::BitReader;
use crate::block;

/// Decompress a complete bzip2 stream from `data`.
/// Returns the fully decompressed output.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, block::BlockError> {
    if data.len() < 4 {
        return Err(block::BlockError("input too short for bzip2 header"));
    }
    if &data[..2] != b"BZ" {
        return Err(block::BlockError("bad bzip2 signature"));
    }
    if data[2] != b'h' {
        return Err(block::BlockError("only huffman bzip2 supported"));
    }
    let level = data[3];
    if !(b'1'..=b'9').contains(&level) {
        return Err(block::BlockError("invalid bzip2 block size level"));
    }
    let max_blocksize = 100_000 * (level - b'0') as u32;

    let mut reader = BitReader::from_bit_offset(data, 4 * 8); // skip "BZhN"
    let mut output = Vec::new();
    let mut combined_crc: u32 = 0;

    loop {
        let magic = reader
            .read_u64(48)
            .ok_or(block::BlockError("unexpected end of stream"))?;

        if magic == BLOCK_MAGIC {
            let block_data = block::decode_block(&mut reader, max_blocksize)?;
            // Fold this block's CRC into the running combined stream CRC
            // (bzip2: rotate-left-1 then XOR the block CRC).
            combined_crc = (combined_crc << 1) | (combined_crc >> 31);
            combined_crc ^= block::block_crc(&block_data);
            output.extend_from_slice(&block_data);
        } else if magic == FINAL_MAGIC {
            // End of stream — verify the combined stream CRC32 (32 bits).
            let stream_crc = reader
                .read_u32(32)
                .ok_or(block::BlockError("stream CRC truncated"))?;
            if stream_crc != combined_crc {
                return Err(block::BlockError("stream CRC mismatch"));
            }
            break;
        } else {
            return Err(block::BlockError("invalid block magic"));
        }
    }

    Ok(output)
}

/// Sentinel message for "decompressed output exceeded the caller's `max_out`
/// cap". Mirrors `lgz`'s `OUTPUT_TOO_LARGE`; callers can match on this to degrade
/// gracefully instead of risking an unbounded allocation / OOM.
pub const OUTPUT_TOO_LARGE: &str = "decompressed output exceeds max_out cap";

/// Decompress a complete bzip2 stream with a hard output cap.
///
/// Decodes block by block, but errors with [`block::BlockError`] carrying
/// [`OUTPUT_TOO_LARGE`] as soon as the cumulative decompressed output would
/// exceed `max_out`. A single bzip2 block decodes to at most `max_blocksize`
/// (≤ 900 KB), so peak allocation stays at roughly `max_out` + one block — a
/// highly compressible bomb yields an `Err` rather than an OOM abort.
pub fn decompress_capped(data: &[u8], max_out: usize) -> Result<Vec<u8>, block::BlockError> {
    if data.len() < 4 {
        return Err(block::BlockError("input too short for bzip2 header"));
    }
    if &data[..2] != b"BZ" {
        return Err(block::BlockError("bad bzip2 signature"));
    }
    if data[2] != b'h' {
        return Err(block::BlockError("only huffman bzip2 supported"));
    }
    let level = data[3];
    if !(b'1'..=b'9').contains(&level) {
        return Err(block::BlockError("invalid bzip2 block size level"));
    }
    let max_blocksize = 100_000 * (level - b'0') as u32;

    let mut reader = BitReader::from_bit_offset(data, 4 * 8); // skip "BZhN"
    let mut output = Vec::new();
    let mut combined_crc: u32 = 0;

    loop {
        let magic = reader
            .read_u64(48)
            .ok_or(block::BlockError("unexpected end of stream"))?;

        if magic == BLOCK_MAGIC {
            let block_data = block::decode_block(&mut reader, max_blocksize)?;
            if output.len() + block_data.len() > max_out {
                return Err(block::BlockError(OUTPUT_TOO_LARGE));
            }
            // Fold this block's CRC into the running combined stream CRC
            // (bzip2: rotate-left-1 then XOR the block CRC).
            combined_crc = (combined_crc << 1) | (combined_crc >> 31);
            combined_crc ^= block::block_crc(&block_data);
            output.extend_from_slice(&block_data);
        } else if magic == FINAL_MAGIC {
            // End of stream — verify the combined stream CRC32 (32 bits).
            let stream_crc = reader
                .read_u32(32)
                .ok_or(block::BlockError("stream CRC truncated"))?;
            if stream_crc != combined_crc {
                return Err(block::BlockError("stream CRC mismatch"));
            }
            break;
        } else {
            return Err(block::BlockError("invalid block magic"));
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompress_hello() {
        let compressed = include_bytes!("../test_data/hello.bz2");
        let output = decompress(compressed).unwrap();
        assert_eq!(&output, b"Hello, World!\n");
    }

    fn bz2(data: &[u8]) -> Vec<u8> {
        use bzip2::write::BzEncoder;
        use std::io::Write;
        let mut enc = BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn capped_small_input_roundtrips() {
        let original = b"a small bzip2 payload";
        let compressed = bz2(original);
        let out = decompress_capped(&compressed, 1024).unwrap();
        assert_eq!(&out, original);
    }

    #[test]
    fn capped_bomb_errors_not_ooms() {
        // 1 MiB of zeros bzips to a few dozen bytes but expands past a tiny cap.
        // The capped decoder must Err(OUTPUT_TOO_LARGE), never buffer the full MiB.
        let bomb = bz2(&vec![0u8; 1024 * 1024]);
        assert!(
            bomb.len() < 4096,
            "zeros must compress tiny: {} bytes",
            bomb.len()
        );
        let err = decompress_capped(&bomb, 4096).unwrap_err();
        assert_eq!(
            err.0, OUTPUT_TOO_LARGE,
            "expected output-too-large sentinel"
        );
    }

    #[test]
    fn capped_normal_matches_uncapped() {
        let original: Vec<u8> = (0..50_000u32).map(|i| (i % 256) as u8).collect();
        let compressed = bz2(&original);
        let capped = decompress_capped(&compressed, 10 * 1024 * 1024).unwrap();
        let uncapped = decompress(&compressed).unwrap();
        assert_eq!(capped, uncapped);
        assert_eq!(capped, original);
    }

    #[test]
    fn decompress_liechtenstein() {
        let compressed = include_bytes!("../test_data/liechtenstein.osm.bz2");
        let output = decompress(compressed).unwrap();
        // Verify non-empty and starts with XML header
        assert!(output.len() > 1_000_000, "expected multi-MB output");
        let header = std::str::from_utf8(&output[..100]).unwrap();
        assert!(
            header.contains("<?xml"),
            "expected XML header, got: {}",
            &header[..60]
        );
    }
}
