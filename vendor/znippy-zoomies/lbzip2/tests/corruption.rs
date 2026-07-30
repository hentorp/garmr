//! Security regression: the parallel bzip2 decoder must REJECT a corrupt or
//! tampered stream (per-block CRC-32 and the combined stream CRC), never decode
//! it to silent garbage / truncated output.
//!
//! Before the fix, `chunk::decode_segment` swallowed a per-block CRC failure and
//! returned the partially-decoded bytes, and `decompress_parallel` never checked
//! the whole-stream CRC — so a flipped byte produced wrong output with no error.

use bzip2::write::BzEncoder;
use std::io::Write;

/// Compress `data` to a single-stream bzip2 buffer.
fn bz2(data: &[u8]) -> Vec<u8> {
    let mut enc = BzEncoder::new(Vec::new(), bzip2::Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// A varied, non-trivially-compressible payload so the encoded stream has real
/// block content (and a genuine CRC) to tamper with.
fn payload() -> Vec<u8> {
    (0..200_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

#[test]
fn parallel_roundtrip_is_byte_identical() {
    let original = payload();
    let compressed = bz2(&original);

    let par = lbzip2::parallel::decompress_parallel(&compressed).unwrap();
    let seq = lbzip2::stream::decompress(&compressed).unwrap();

    assert_eq!(par, original, "parallel decode must reproduce the input");
    assert_eq!(par, seq, "parallel and sequential decode must agree");
}

#[test]
fn parallel_rejects_corrupted_block_data() {
    let original = payload();
    let mut compressed = bz2(&original);

    // Flip a byte well inside the compressed block data. This changes the
    // decompressed bytes, so the block's stored CRC-32 no longer matches.
    let mid = compressed.len() / 2;
    compressed[mid] ^= 0xFF;

    let result = lbzip2::parallel::decompress_parallel(&compressed);
    assert!(
        result.is_err(),
        "a corrupted block must be REJECTED, got Ok({} bytes)",
        result.map(|v| v.len()).unwrap_or(0)
    );
}

#[test]
fn parallel_rejects_corrupted_stream_crc() {
    let original = payload();
    let mut compressed = bz2(&original);

    // The stored combined stream CRC-32 is the 32 bits immediately after the
    // trailing FINAL_MAGIC, i.e. within the last ~5 bytes. Flipping byte
    // (len - 3) hits the CRC (not the magic, which precedes it, nor the ≤1 byte
    // of trailing bit-padding). Every per-block CRC still matches, so ONLY the
    // whole-stream combined-CRC check can catch this.
    let n = compressed.len();
    assert!(n > 5);
    compressed[n - 3] ^= 0xFF;

    let result = lbzip2::parallel::decompress_parallel(&compressed);
    assert!(
        result.is_err(),
        "a tampered stream CRC must be REJECTED, got Ok({} bytes)",
        result.map(|v| v.len()).unwrap_or(0)
    );
}
