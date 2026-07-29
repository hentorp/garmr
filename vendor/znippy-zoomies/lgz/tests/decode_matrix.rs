//! Test-matrix self-emitter for the `lgz` parallel gzip decoder — the codec
//! decode surface that had NO red-when-broken matrix cell (only the CLI bin's
//! hard-coded `ok=true` success marker). This mirrors the sanctioned
//! `vann_matrix.rs` / korp-collectors doctrine: every check is a REAL
//! return-value / byte-identity assertion FIRST (the test's gate), and the
//! `functional_status` emit is the matrix observation.
//!
//! Red-when-broken: if the parallel `chunk::decode_chunk` path ever reproduces
//! the wrong bytes, or the trailer/CRC check stops rejecting a tampered stream,
//! the `assert!` fails RED — and the emitted row carries the same verdict.
//!
//! A plain `cargo test -p lgz` runs every assertion; the emit is a stripped
//! `#[inline]` no-op unless `--features testmatrix` is on (lgz::functional_status
//! pulls no nornir dep by default).

use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;

/// `assert!`-with-emit under the `lgz::decode` component: assert on the real
/// value AND record the verdict as a matrix row (the korp `assert_emit!` shape,
/// specialised to lgz's public `functional_status`).
macro_rules! assert_emit {
    ($check:expr, $ok:expr, $($detail:tt)+) => {{
        let __ok: bool = $ok;
        let __detail = format!($($detail)+);
        lgz::functional_status("lgz::decode", $check, __ok, &__detail);
        assert!(__ok, "lgz::decode::{} — {}", $check, __detail);
    }};
}

/// Deterministic, compressible "loggy" text so the DEFLATE stream does real
/// work (members compress ~4-5x) rather than storing incompressible noise.
fn corpus(len: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the",
        "quick",
        "brown",
        "fox",
        "GET",
        "POST",
        "200",
        "404",
        "error",
        "info",
        "debug",
        "user",
        "session",
        "token",
        "request",
        "response",
        "latency",
        "bytes",
        "cache",
        "hit",
        "miss",
        "shard",
        "commit",
        "deploy",
        "node",
        "cluster",
        "worker",
        "thread",
        "queue",
        "buffer",
        "stream",
        "decode",
        "payload",
        "checksum",
        "offset",
        "length",
        "dur_ms=42",
    ];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut out = Vec::with_capacity(len + 256);
    while out.len() < len {
        let n = 6 + (next() % 10) as usize;
        for i in 0..n {
            if i > 0 {
                out.push(b' ');
            }
            out.extend_from_slice(WORDS[(next() as usize) % WORDS.len()].as_bytes());
        }
        out.push(b'\n');
    }
    out.truncate(len);
    out
}

/// A single-member gzip stream carrying periodic `Z_SYNC_FLUSH` boundaries
/// (`00 00 FF FF`) every `chunk` bytes — exactly the shape (pigz / bgzf) that
/// makes `decompress_gz` take its multi-core `chunk::decode_chunk` path instead
/// of the single-threaded flate2 fallback.
fn gz_with_flush_boundaries(data: &[u8], chunk: usize) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    let mut off = 0;
    while off < data.len() {
        let end = (off + chunk).min(data.len());
        e.write_all(&data[off..end]).unwrap();
        // A flush emits a full-flush boundary the parallel scanner splits on.
        e.flush().unwrap();
        off = end;
    }
    e.finish().unwrap()
}

/// LAW — the parallel gzip decode reproduces the input BYTE-FOR-BYTE. The corpus
/// is > `PARALLEL_THRESHOLD` (4 MiB) with flush boundaries so the multi-core
/// path is genuinely exercised (not the serial fallback). This is the
/// core-saturation correctness gate: saturating more cores must never change a
/// single output byte.
#[test]
fn matrix_parallel_decode_is_byte_identical() {
    let original = corpus(6 * 1024 * 1024); // > PARALLEL_THRESHOLD
    let compressed = gz_with_flush_boundaries(&original, 512 * 1024);

    let decoded = lgz::decompress_gz(&compressed).expect("valid gzip must decode");

    assert_emit!(
        "parallel_decode_byte_identical",
        decoded == original,
        "in={} compressed={} out={} bytes: multi-core decode == input bit-for-bit",
        original.len(),
        compressed.len(),
        decoded.len()
    );
}

/// LAW — the sequential (small-input) path also round-trips byte-for-byte, so
/// the size-selector in `decompress_gz` never changes the result.
#[test]
fn matrix_small_decode_is_byte_identical() {
    let original = corpus(64 * 1024); // < PARALLEL_THRESHOLD ⇒ flate2 path
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(&original).unwrap();
    let compressed = e.finish().unwrap();

    let decoded = lgz::decompress_gz(&compressed).expect("valid gzip must decode");

    assert_emit!(
        "small_decode_byte_identical",
        decoded == original,
        "in={} out={} bytes: single-threaded decode == input bit-for-bit",
        original.len(),
        decoded.len()
    );
}

/// LAW — a tampered gzip stream is REJECTED (trailer CRC-32 + ISIZE mismatch),
/// never decoded to silent garbage. Flipping a byte inside the DEFLATE payload
/// changes the decoded bytes, so the trailer check must fail the decode.
#[test]
fn matrix_corrupt_stream_is_rejected() {
    let original = corpus(6 * 1024 * 1024);
    let mut compressed = gz_with_flush_boundaries(&original, 512 * 1024);

    // Flip a byte well inside the compressed payload (past the header, before
    // the trailer): the output no longer matches the stored CRC-32 / ISIZE.
    let mid = compressed.len() * 3 / 5;
    compressed[mid] ^= 0xFF;

    // The trailer CRC-32 / ISIZE check must turn the tamper into an `Err`;
    // returning `Ok` at all means corruption slipped through silently.
    let result = lgz::decompress_gz(&compressed);
    let rejected = result.is_err();

    assert_emit!(
        "corrupt_stream_rejected",
        rejected,
        "flipped byte @ {mid}/{}: tampered stream rejected (got {})",
        compressed.len(),
        match &result {
            Ok(v) => format!("Ok({} bytes)", v.len()),
            Err(e) => format!("Err({e})"),
        }
    );
}
