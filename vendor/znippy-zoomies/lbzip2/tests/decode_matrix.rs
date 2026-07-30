//! Test-matrix self-emitter for the `lbzip2` parallel bzip2 decoder — the codec
//! decode surface that had NO red-when-broken matrix cell (only the `lbunzip2`
//! CLI's success/failure markers). Mirrors the sanctioned `vann_matrix.rs`
//! doctrine: every check is a REAL byte-identity / rejection assertion FIRST
//! (the test's gate), and the `functional_status` emit is the matrix
//! observation carrying the same verdict.
//!
//! Red-when-broken: if the multi-core Burrows-Wheeler decode ever reproduces the
//! wrong bytes, or the per-block / whole-stream CRC-32 stops rejecting a
//! tampered stream, the `assert!` fails RED and the emitted row is FAIL.
//!
//! A plain `cargo test -p lbzip2` runs every assertion; the emit is a stripped
//! `#[inline]` no-op unless `--features testmatrix` is on.

use std::io::Write;

use bzip2::write::BzEncoder;

/// `assert!`-with-emit under the `lbzip2::decode` component.
macro_rules! assert_emit {
    ($check:expr, $ok:expr, $($detail:tt)+) => {{
        let __ok: bool = $ok;
        let __detail = format!($($detail)+);
        lbzip2::functional_status("lbzip2::decode", $check, __ok, &__detail);
        assert!(__ok, "lbzip2::decode::{} — {}", $check, __detail);
    }};
}

fn bz2(data: &[u8]) -> Vec<u8> {
    let mut enc = BzEncoder::new(Vec::new(), bzip2::Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// A varied, multi-block payload (bzip2 caps a block at 900 KiB, so ~2.4 MiB is
/// several blocks) that decodes across worker boundaries.
fn payload() -> Vec<u8> {
    (0..2_400_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

/// LAW — the parallel bzip2 decode reproduces the input BYTE-FOR-BYTE and agrees
/// with the sequential baseline. The core-saturation correctness gate: fanning
/// blocks across more cores must never change an output byte.
#[test]
fn matrix_parallel_decode_is_byte_identical() {
    let original = payload();
    let compressed = bz2(&original);

    let par = lbzip2::parallel::decompress_parallel(&compressed).expect("valid bz2 must decode");
    let seq = lbzip2::stream::decompress(&compressed).expect("valid bz2 must decode (serial)");

    assert_emit!(
        "parallel_decode_byte_identical",
        par == original && par == seq,
        "in={} compressed={} out={} bytes: parallel == input == serial bit-for-bit",
        original.len(),
        compressed.len(),
        par.len()
    );
}

/// LAW — a corrupted block (flipped payload byte) is REJECTED by the per-block
/// CRC-32, never decoded to silent garbage.
#[test]
fn matrix_corrupt_block_is_rejected() {
    let original = payload();
    let mut compressed = bz2(&original);
    let mid = compressed.len() / 2;
    compressed[mid] ^= 0xFF;

    let result = lbzip2::parallel::decompress_parallel(&compressed);

    assert_emit!(
        "corrupt_block_rejected",
        result.is_err(),
        "flipped byte @ {mid}: block CRC-32 rejects tamper (got {})",
        match &result {
            Ok(v) => format!("Ok({} bytes)", v.len()),
            Err(e) => format!("Err({e})"),
        }
    );
}

/// LAW — a tampered whole-stream CRC-32 (every per-block CRC still valid) is
/// REJECTED by the combined-stream check.
#[test]
fn matrix_corrupt_stream_crc_is_rejected() {
    let original = payload();
    let mut compressed = bz2(&original);
    let n = compressed.len();
    assert!(n > 5);
    compressed[n - 3] ^= 0xFF; // hits the trailing combined-CRC, not the magic

    let result = lbzip2::parallel::decompress_parallel(&compressed);

    assert_emit!(
        "corrupt_stream_crc_rejected",
        result.is_err(),
        "flipped combined-CRC byte @ {}: whole-stream CRC rejects tamper (got {})",
        n - 3,
        match &result {
            Ok(v) => format!("Ok({} bytes)", v.len()),
            Err(e) => format!("Err({e})"),
        }
    );
}
