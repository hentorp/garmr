//! linflate — Fast pure-Rust DEFLATE decompressor.
//!
//! Full-buffer, zero-copy, SIMD-optimized. Follows libdeflate's architecture
//! with zlib-ng's branchless refill and SIMD match copy, thread-local table
//! pool and segment-aware `inflate_segment` API.
//!
//! # Usage
//! ```no_run
//! # fn try_main(compressed: &[u8], expected_size: usize) -> Result<(), linflate::InflateError> {
//! let mut output = vec![0u8; expected_size + linflate::OVERWRITE_HEADROOM];
//! let written = linflate::inflate_into(compressed, &mut output)?;
//! output.truncate(written);
//! # Ok(()) }
//! ```

pub mod bitreader;
pub mod copy;
pub mod deflate_scan;
pub mod fastloop;
pub mod fixed;
pub mod tables;

use bitreader::BitReader;
use tables::DecompressTables;

/// **Introspection / emit marker** — record one functional-status row for the
/// nornir test matrix. Wraps `nornir_testmatrix::functional_status` behind the
/// `testmatrix` feature (a compiled-out `#[inline]` no-op otherwise, with no
/// nornir dep in the default build). Mirrors the korp-collectors reference
/// wiring so `nornir test --features testmatrix` SEES each inflate surface.
#[inline]
pub fn functional_status(component: &str, check: &str, ok: bool, detail: &str) {
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(component, check, ok, detail);
    #[cfg(not(feature = "testmatrix"))]
    {
        let _ = (component, check, ok, detail);
    }
}

/// Extra bytes of output buffer headroom required for SIMD overwrite.
/// Caller must allocate `uncompressed_size + OVERWRITE_HEADROOM`.
pub const OVERWRITE_HEADROOM: usize = copy::CHUNK_SIZE + 258;

/// Errors from the DEFLATE decompressor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateError {
    InvalidBlockType,
    InvalidStoredLength,
    InvalidHuffmanTable,
    InvalidDistance,
    InvalidCodeLengths,
    OutputOverflow,
    UnexpectedEof,
    DataError,
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBlockType => write!(f, "invalid DEFLATE block type"),
            Self::InvalidStoredLength => write!(f, "invalid stored block length"),
            Self::InvalidHuffmanTable => write!(f, "invalid Huffman table"),
            Self::InvalidDistance => write!(f, "invalid back-reference distance"),
            Self::InvalidCodeLengths => write!(f, "invalid code lengths"),
            Self::OutputOverflow => write!(f, "output buffer overflow"),
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::DataError => write!(f, "DEFLATE data error"),
        }
    }
}

impl std::error::Error for InflateError {}

/// Decompress raw DEFLATE data into a pre-allocated output buffer.
///
/// Returns the number of bytes written.
///
/// The output buffer must have at least `OVERWRITE_HEADROOM` extra bytes
/// beyond the expected decompressed size for SIMD overwrite safety.
pub fn inflate_into(compressed: &[u8], output: &mut [u8]) -> Result<usize, InflateError> {
    inflate_impl(compressed, output, false)
}

/// Decompress a DEFLATE segment that may not end on BFINAL=1.
///
/// Used by the chunk-level parallel decoder for segments split at
/// Z_FULL_FLUSH boundaries. After BFINAL=0 blocks, if input is exhausted,
/// returns success with the bytes decompressed so far.
pub fn inflate_segment(compressed: &[u8], output: &mut [u8]) -> Result<usize, InflateError> {
    inflate_impl(compressed, output, true)
}

/// Decompress a DEFLATE segment with a prefix window for LZ77 back-reference
/// resolution across segment boundaries.
///
/// `output[..prefix_len]` must already contain the window bytes (typically the
/// last 32KB of the previous segment's output). Decoding starts at `prefix_len`
/// and back-references can reach into the prefix.
///
/// Returns the number of NEW bytes written (not counting the prefix).
pub fn inflate_segment_with_prefix(
    compressed: &[u8],
    output: &mut [u8],
    prefix_len: usize,
) -> Result<usize, InflateError> {
    inflate_impl_at(compressed, output, prefix_len, true, 0)
}

/// Same as `inflate_segment_with_prefix` but stops after `limit` output bytes.
/// Used for pass-2 fixup where only the first 32KB needs correction.
///
/// Returns the number of NEW bytes written (not counting the prefix).
pub fn inflate_segment_with_prefix_limited(
    compressed: &[u8],
    output: &mut [u8],
    prefix_len: usize,
    limit: usize,
) -> Result<usize, InflateError> {
    inflate_impl_at(compressed, output, prefix_len, true, limit)
}

fn inflate_impl(
    compressed: &[u8],
    output: &mut [u8],
    allow_partial: bool,
) -> Result<usize, InflateError> {
    inflate_impl_at(compressed, output, 0, allow_partial, 0)
}

/// Core implementation with configurable start position and output limit.
/// `start_pos`: where to begin writing (prefix window lives before this).
/// `limit`: if > 0, stop after this many new bytes written.
fn inflate_impl_at(
    compressed: &[u8],
    output: &mut [u8],
    start_pos: usize,
    allow_partial: bool,
    limit: usize,
) -> Result<usize, InflateError> {
    tables::with_tables(|tables| {
        let mut bits = BitReader::new(compressed);
        let mut out_pos = start_pos;

        let stop_at = if limit > 0 { start_pos + limit } else { 0 };

        loop {
            // Check output limit.
            if stop_at > 0 && out_pos >= stop_at {
                return Ok(out_pos - start_pos);
            }

            // Ensure we have bits for block header.
            unsafe { bits.refill() };

            if bits.bits_remaining() < 3 {
                if allow_partial && out_pos > start_pos {
                    return Ok(out_pos - start_pos);
                }
                return Err(InflateError::UnexpectedEof);
            }

            let bfinal = bits.take(1);
            let btype = bits.take(2);

            match btype {
                0 => {
                    // Stored block.
                    out_pos = decode_stored(&mut bits, output, out_pos)?;
                }
                1 => {
                    // Fixed Huffman.
                    fixed::load_fixed_tables(tables);
                    let written =
                        unsafe { fastloop::inflate_fast(&mut bits, tables, output, out_pos) }?;
                    out_pos += written;
                }
                2 => {
                    // Dynamic Huffman.
                    decode_dynamic_header(&mut bits, tables)?;
                    let written =
                        unsafe { fastloop::inflate_fast(&mut bits, tables, output, out_pos) }?;
                    out_pos += written;
                }
                _ => return Err(InflateError::InvalidBlockType),
            }

            if bfinal != 0 {
                break;
            }
        }

        Ok(out_pos - start_pos)
    })
}

/// Convenience: decompress into a newly allocated Vec.
pub fn inflate_to_vec(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, InflateError> {
    let total = expected_size + OVERWRITE_HEADROOM;
    let mut output = Vec::with_capacity(total);
    // SAFETY: inflate_into writes to the buffer and we truncate to `written` bytes.
    // The OVERWRITE_HEADROOM may contain uninitialized overwrite bytes from SIMD,
    // but truncate() ensures they're never exposed. The hot path must not pay for
    // zero-initializing a buffer that inflate_into is about to overwrite, so we
    // deliberately accept the uninit_vec pattern here.
    #[allow(clippy::uninit_vec)]
    unsafe {
        output.set_len(total);
    }
    let written = inflate_into(compressed, &mut output)?;
    output.truncate(written);
    // Introspection marker: a full-buffer inflate completed.
    #[cfg(feature = "testmatrix")]
    functional_status(
        "linflate",
        "inflate_to_vec",
        true,
        &format!("in={} out={} bytes", compressed.len(), written),
    );
    Ok(output)
}

// ── Stored block decode ──────────────────────────────────────────────────────

fn decode_stored(
    bits: &mut BitReader,
    output: &mut [u8],
    mut out_pos: usize,
) -> Result<usize, InflateError> {
    // Align to byte boundary (discard partial-byte bits).
    bits.align_to_byte();

    // Need at least 32 bits for LEN + NLEN.
    if bits.bits_remaining() < 32 {
        unsafe { bits.refill() };
    }
    if bits.bits_remaining() < 32 {
        return Err(InflateError::UnexpectedEof);
    }

    let len = bits.take_u16() as usize;
    let nlen = bits.take_u16() as usize;

    if len != (!nlen & 0xFFFF) {
        return Err(InflateError::InvalidStoredLength);
    }

    if out_pos + len > output.len() {
        return Err(InflateError::OutputOverflow);
    }

    // Copy `len` bytes. The refill machinery may already hold some of the
    // payload in the bit buffer, so first drain those whole bytes; the buffer is
    // byte-aligned here, so it empties cleanly (bits_remaining hits 0, never 1..7).
    let mut remaining = len;
    while remaining > 0 && bits.bits_remaining() >= 8 {
        output[out_pos] = bits.take(8) as u8;
        out_pos += 1;
        remaining -= 1;
    }

    // The rest is a byte-aligned run sitting in the input remainder: memcpy it
    // straight across and advance the reader past it. (A stored block is
    // byte-aligned by definition, so no bit-shifting is needed — reading it back
    // through the 8-bits-at-a-time refill path would be both slower and, near
    // EOF, unable to satisfy an 8-bit refill on the final partial word.)
    if remaining > 0 {
        let ptr = bits.input_ptr();
        let avail = unsafe { bits.input_end().offset_from(ptr) } as usize;
        if avail < remaining {
            return Err(InflateError::UnexpectedEof);
        }
        // SAFETY: `avail >= remaining` guarantees `ptr..ptr+remaining` is in
        // bounds of the input, and `out_pos + remaining <= output.len()` was
        // checked above. The bit buffer is drained (bits_remaining == 0), so
        // `advance_bytes` correctly resynchronises the reader.
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, output.as_mut_ptr().add(out_pos), remaining);
            bits.advance_bytes(remaining);
        }
        out_pos += remaining;
    }

    Ok(out_pos)
}

// ── Dynamic Huffman header decode ────────────────────────────────────────────

/// Code-length alphabet order (RFC 1951 §3.2.7).
static CODELEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn decode_dynamic_header(
    bits: &mut BitReader,
    tables: &mut DecompressTables,
) -> Result<(), InflateError> {
    unsafe { bits.refill() };

    if bits.bits_remaining() < 14 {
        return Err(InflateError::UnexpectedEof);
    }

    let hlit = bits.take(5) as usize + 257; // 257..286
    let hdist = bits.take(5) as usize + 1; // 1..32
    let hclen = bits.take(4) as usize + 4; // 4..19

    if hlit > 286 || hdist > 32 {
        return Err(InflateError::InvalidCodeLengths);
    }

    // Step 1: Read code-length code lengths (3 bits each).
    let mut codelen_lens = [0u8; 19];
    for i in 0..hclen {
        if bits.bits_remaining() < 3 {
            unsafe { bits.refill() };
        }
        codelen_lens[CODELEN_ORDER[i]] = bits.take(3) as u8;
    }

    // Build the code-length decode table.
    tables::build_decode_table(
        &codelen_lens,
        &mut tables.precode,
        tables::PRECODE_TABLEBITS,
        tables::TableKind::Precode,
    )?;

    // Step 2: Read litlen + dist code lengths using the code-length table.
    let total = hlit + hdist;
    let mut lens_buf = [0u8; 286 + 32]; // max litlen(286) + dist(32) = 318, on stack
    let lens = &mut lens_buf[..total];
    let mut i = 0;

    while i < total {
        if bits.bits_remaining() < 15 {
            unsafe { bits.refill() };
        }

        let idx = (bits.raw_buf() as u32) & ((1u32 << tables::PRECODE_TABLEBITS) - 1);
        let entry = tables.precode[idx as usize];
        let code_len = entry & 0xF;
        bits.consume(code_len);

        let sym = (entry >> 16) & 0xFF;

        match sym as usize {
            0..=15 => {
                lens[i] = sym as u8;
                i += 1;
            }
            16 => {
                // Repeat previous length 3-6 times.
                if bits.bits_remaining() < 2 {
                    unsafe { bits.refill() };
                }
                let repeat = bits.take(2) as usize + 3;
                if i == 0 || i + repeat > total {
                    return Err(InflateError::InvalidCodeLengths);
                }
                let prev = lens[i - 1];
                for _ in 0..repeat {
                    lens[i] = prev;
                    i += 1;
                }
            }
            17 => {
                // Repeat 0 for 3-10 times.
                if bits.bits_remaining() < 3 {
                    unsafe { bits.refill() };
                }
                let repeat = bits.take(3) as usize + 3;
                if i + repeat > total {
                    return Err(InflateError::InvalidCodeLengths);
                }
                for _ in 0..repeat {
                    lens[i] = 0;
                    i += 1;
                }
            }
            18 => {
                // Repeat 0 for 11-138 times.
                if bits.bits_remaining() < 7 {
                    unsafe { bits.refill() };
                }
                let repeat = bits.take(7) as usize + 11;
                if i + repeat > total {
                    return Err(InflateError::InvalidCodeLengths);
                }
                for _ in 0..repeat {
                    lens[i] = 0;
                    i += 1;
                }
            }
            _ => return Err(InflateError::InvalidCodeLengths),
        }
    }

    // Step 3: Build litlen and dist tables.
    let litlen_lens = &lens[..hlit];
    let dist_lens = &lens[hlit..];

    tables::build_decode_table(
        litlen_lens,
        &mut tables.litlen,
        tables::LITLEN_TABLEBITS,
        tables::TableKind::Litlen,
    )?;

    tables::build_decode_table(
        dist_lens,
        &mut tables.dist,
        tables::DIST_TABLEBITS,
        tables::TableKind::Dist,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal LSB-first DEFLATE bit writer for hand-building streams that end
    /// in a stored (uncompressed) block. Only what the stored-block regression
    /// tests need: raw bits, fixed-Huffman codes (MSB-first), and byte-align.
    struct DeflateBitWriter {
        bytes: Vec<u8>,
        cur: u8,
        nbits: u8,
    }
    impl DeflateBitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                cur: 0,
                nbits: 0,
            }
        }
        fn bit(&mut self, b: u32) {
            self.cur |= ((b & 1) as u8) << self.nbits;
            self.nbits += 1;
            if self.nbits == 8 {
                self.bytes.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }
        fn bits(&mut self, v: u32, n: u32) {
            for i in 0..n {
                self.bit(v >> i);
            }
        }
        /// Emit a Huffman code (packed MSB-first per RFC 1951 §3.1.1).
        fn huff(&mut self, code: u32, len: u32) {
            for i in (0..len).rev() {
                self.bit(code >> i);
            }
        }
        fn align(&mut self) {
            if self.nbits > 0 {
                self.bytes.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }
    }

    /// Regression: a valid DEFLATE stream whose final block is a *stored*
    /// (uncompressed) block whose payload runs to end-of-input must decode.
    ///
    /// `decode_stored` used to memcpy the byte-aligned remainder correctly and
    /// then redundantly re-copy it 8 bits at a time through the refill path,
    /// bailing with `UnexpectedEof` when the last partial machine word couldn't
    /// satisfy an 8-bit refill. The fix drops the re-copy and advances the reader
    /// past the memcpy'd bytes. We sweep the *bit alignment* of the stored block
    /// (0..16 preceding fixed-Huffman literals shift where the byte-aligned copy
    /// starts) crossed with the payload length (0..600 bytes, spanning the
    /// in-buffer / direct-copy / near-EOF-partial-word cases).
    #[test]
    fn inflate_stored_final_block_to_eof() {
        for nlit in 0usize..16 {
            for np in 0usize..600 {
                let mut w = DeflateBitWriter::new();
                // Fixed-Huffman block (BFINAL=0, BTYPE=01) carrying `nlit`
                // literals + EOB, to bit-shift the following stored block.
                w.bit(0);
                w.bits(1, 2);
                let lits: Vec<u8> = (0..nlit).map(|i| ((i * 17 + 3) % 144) as u8).collect();
                for &l in &lits {
                    w.huff(0x30 + l as u32, 8);
                } // literals 0..143 => 8-bit codes
                w.huff(0, 7); // end-of-block symbol (256)
                // Final stored block (BFINAL=1, BTYPE=00), byte-aligned.
                w.bit(1);
                w.bits(0, 2);
                w.align();
                let len = np as u16;
                w.bytes.extend_from_slice(&len.to_le_bytes());
                w.bytes.extend_from_slice(&(!len).to_le_bytes());
                let payload: Vec<u8> = (0..np).map(|i| (i * 31 + 7) as u8).collect();
                w.bytes.extend_from_slice(&payload); // payload ends exactly at EOF

                let total = nlit + np;
                let mut out = vec![0u8; total + OVERWRITE_HEADROOM];
                let wn = inflate_into(&w.bytes, &mut out)
                    .unwrap_or_else(|e| panic!("nlit={} np={} failed: {:?}", nlit, np, e));
                assert_eq!(wn, total, "nlit={} np={}", nlit, np);
                assert_eq!(&out[..nlit], &lits[..], "literals nlit={} np={}", nlit, np);
                assert_eq!(
                    &out[nlit..total],
                    &payload[..],
                    "payload nlit={} np={}",
                    nlit,
                    np
                );
            }
        }
    }

    #[test]
    fn inflate_empty_stored() {
        // A stored block with 0 bytes: BFINAL=1, BTYPE=00, LEN=0, NLEN=0xFFFF
        let data = [
            0b00000001u8, // BFINAL=1 (bit 0), BTYPE=00 (bits 1-2), padding zeros
            0x00,
            0x00, // LEN = 0
            0xFF,
            0xFF, // NLEN = ~0
        ];
        let mut out = vec![0u8; OVERWRITE_HEADROOM];
        let written = inflate_into(&data, &mut out).expect("stored block");
        assert_eq!(written, 0);
    }

    #[test]
    fn inflate_stored_hello() {
        // Stored block: BFINAL=1, BTYPE=00, LEN=5, NLEN=~5, "Hello"
        let mut data = vec![0b00000001u8]; // BFINAL=1, BTYPE=00
        let len: u16 = 5;
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&(!len).to_le_bytes());
        data.extend_from_slice(b"Hello");

        let mut out = vec![0u8; 5 + OVERWRITE_HEADROOM];
        let written = inflate_into(&data, &mut out).expect("stored hello");
        assert_eq!(written, 5);
        assert_eq!(&out[..5], b"Hello");
    }

    #[test]
    fn inflate_fixed_roundtrip() {
        let original = b"The quick brown fox jumps over the lazy dog. \
                         The quick brown fox jumps over the lazy dog.";
        // Use compression level 1 to get fixed Huffman blocks.
        let compressed = miniz_oxide::deflate::compress_to_vec(original, 1);
        let mut out = vec![0u8; original.len() + OVERWRITE_HEADROOM];
        let written = inflate_into(&compressed, &mut out).expect("inflate fixed");
        assert_eq!(written, original.len());
        assert_eq!(&out[..written], original.as_slice());
    }

    #[test]
    fn inflate_dynamic_roundtrip() {
        let original = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(100);
        // Level 6 typically produces dynamic Huffman blocks.
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        let mut out = vec![0u8; original.len() + OVERWRITE_HEADROOM];
        let written = inflate_into(&compressed, &mut out).expect("inflate dynamic");
        assert_eq!(written, original.len());
        assert_eq!(&out[..written], original.as_slice());
    }

    #[test]
    fn inflate_to_vec_convenience() {
        let original = b"Hello, World!".repeat(50);
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        let result = inflate_to_vec(&compressed, original.len()).expect("inflate_to_vec");
        assert_eq!(result, original);
    }

    #[test]
    fn inflate_large_data() {
        // 64 KB of pseudo-random data to exercise match copies.
        let mut original = vec![0u8; 65536];
        for (i, b) in original.iter_mut().enumerate() {
            *b = ((i * 7 + 13) % 256) as u8;
        }
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        let result = inflate_to_vec(&compressed, original.len()).expect("large inflate");
        assert_eq!(result.len(), original.len());
        assert_eq!(result, original);
    }

    #[test]
    fn inflate_all_zeros() {
        // All-zeros: tests RLE (dist=1) match copy path.
        let original = vec![0u8; 32768];
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        let result = inflate_to_vec(&compressed, original.len()).expect("all zeros");
        assert_eq!(result, original);
    }

    /// Regression: the fast-loop literal-burst path requires the bit buffer to
    /// be refilled to the full ≥56-bit budget at the top of each iteration.
    /// The 1- and 2-literal exit paths used to refill only conditionally (when
    /// < 32 bits), which could leave as few as ~10 bits for the next iteration's
    /// speculative `entry2` decode. With LITLEN_TABLEBITS = 11, an 11-bit literal
    /// code would then be indexed with a zero in its top bit → wrong symbol and a
    /// silently corrupt (and length-shifted) output. This deterministic,
    /// multibyte-heavy corpus reproduces the exact bit alignment that triggered
    /// the bug on real (pigz / zlib level-6) gzip streams.
    #[test]
    fn inflate_burst_refill_regression() {
        // Deterministic multibyte text: diverse Unicode (Latin/Cyrillic/CJK/
        // Arabic/Hiragana) produces a deep literal Huffman tree (11-bit codes)
        // interleaved with literal runs (the burst path).
        let mut original = Vec::new();
        let mut s: u64 = 18 | 1;
        let mut rng = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let tags = [
            "name", "name:en", "name:de", "name:ru", "name:zh", "name:ar", "name:ja", "alt_name",
        ];
        while original.len() < 200_000 {
            original.extend_from_slice(b"    <tag k=\"");
            original.extend_from_slice(tags[(rng() as usize) % tags.len()].as_bytes());
            original.extend_from_slice(b"\" v=\"");
            let words = (rng() % 4 + 1) as usize;
            for _ in 0..words {
                let len = (rng() % 8 + 2) as usize;
                for _ in 0..len {
                    let cp = match rng() % 5 {
                        0 => 0x41 + (rng() % 26),
                        1 => 0x400 + (rng() % 0x60),
                        2 => 0x4E00 + (rng() % 0x500),
                        3 => 0x600 + (rng() % 0x50),
                        _ => 0x3040 + (rng() % 0x90),
                    };
                    if let Some(c) = char::from_u32(cp as u32) {
                        let mut b = [0u8; 4];
                        original.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
                    }
                }
                original.push(b' ');
            }
            original.extend_from_slice(b"\"/>\n");
        }

        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 1);
        let result = inflate_to_vec(&compressed, original.len()).expect("burst regression");
        assert_eq!(result.len(), original.len(), "length must match exactly");
        assert_eq!(result, original, "byte-exact decode (no burst corruption)");
    }

    #[test]
    fn inflate_short_repeats() {
        // Pattern with dist 2..7 back-references.
        let mut original = Vec::with_capacity(4096);
        for _ in 0..512 {
            original.extend_from_slice(b"ABCABCABC");
        }
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        let result = inflate_to_vec(&compressed, original.len()).expect("short repeats");
        assert_eq!(result, original);
    }

    #[test]
    fn inflate_vs_miniz_many_sizes() {
        // Test our inflate against miniz_oxide across many data sizes and patterns.
        let patterns: Vec<Vec<u8>> = vec![
            // Java class file-like: starts with cafebabe, then mixed data
            {
                let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
                for i in 0..2000 {
                    v.push((i * 37 + 13) as u8);
                }
                v
            },
            // Highly repetitive
            b"package org.json;\nimport java.util.*;\n".repeat(200),
            // Mixed: some unique, some repeated
            {
                let mut v = Vec::with_capacity(16384);
                for i in 0..4096 {
                    if i % 10 < 3 {
                        v.extend_from_slice(&[0u8; 4]);
                    } else {
                        v.push((i * 7 + 3) as u8);
                    }
                }
                v
            },
        ];

        for (idx, original) in patterns.iter().enumerate() {
            for level in [1, 6, 9] {
                let compressed = miniz_oxide::deflate::compress_to_vec(original, level);
                let miniz_out = miniz_oxide::inflate::decompress_to_vec(&compressed).unwrap();
                let our_out = inflate_to_vec(&compressed, original.len())
                    .unwrap_or_else(|e| panic!("pattern {idx} level {level}: {e:?}"));
                assert_eq!(
                    our_out,
                    miniz_out,
                    "pattern {idx} level {level}: output mismatch (lens {} vs {})",
                    our_out.len(),
                    miniz_out.len()
                );
            }
        }
    }

    #[test]
    fn inflate_real_jar_entry() {
        // Test with a real compressed JAR entry if available.
        let comp_path = "/tmp/xml_class_compressed.bin";
        let exp_path = "/tmp/xml_class_expected.bin";
        if !std::path::Path::new(comp_path).exists() {
            return;
        }

        let compressed = std::fs::read(comp_path).unwrap();
        let expected = std::fs::read(exp_path).unwrap();

        let mut out = vec![0u8; expected.len() + OVERWRITE_HEADROOM];
        match inflate_into(&compressed, &mut out) {
            Ok(written) => {
                out.truncate(written);
                if out != expected {
                    let pos = out
                        .iter()
                        .zip(expected.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(out.len().min(expected.len()));
                    panic!(
                        "MISMATCH at byte {} (got 0x{:02x} vs expected 0x{:02x}, lens {} vs {})",
                        pos,
                        if pos < out.len() { out[pos] } else { 0 },
                        if pos < expected.len() {
                            expected[pos]
                        } else {
                            0
                        },
                        out.len(),
                        expected.len()
                    );
                }
            }
            Err(e) => panic!("inflate error: {e:?}"),
        }
    }
}
