//! The hot DEFLATE decode loop.
//!
//! Design: libdeflate's preload-before-copy pattern with zlib-ng's 3-literal
//! unroll. The next litlen entry is preloaded BEFORE the match copy runs,
//! hiding L1 load latency behind copy instructions.
//!
//! Optimizations over baseline:
//! - 4-literal burst with single u32 store (fewer store-buffer entries)
//! - Merged consume for consecutive literals (single shift)
//! - Preload-before-copy hides L1 latency

use super::InflateError;
use super::bitreader::BitReader;
use super::copy::{self, CHUNK_SIZE};
use super::tables::{
    DIST_TABLEBITS, DecompressTables, HUFFDEC_END_OF_BLOCK, HUFFDEC_LITERAL, HUFFDEC_SUBTABLE,
    LITLEN_TABLEBITS,
};

/// Minimum input bytes remaining to stay in the fast loop.
/// A DEFLATE symbol can read at most 15+15+13 = 43 bits ≈ 6 bytes,
/// plus we need 8 bytes for the branchless refill overread.
const FASTLOOP_INPUT_MARGIN: usize = 15;

/// Minimum output bytes remaining to stay in the fast loop.
/// Maximum match length is 258, plus CHUNK_SIZE overwrite headroom.
const FASTLOOP_OUTPUT_MARGIN: usize = 258 + CHUNK_SIZE;

/// Decode one litlen entry from the table (fast path: single lookup).
#[inline(always)]
fn decode_litlen_entry(tables: &DecompressTables, bits_buf: u64) -> u32 {
    let idx = (bits_buf as u32) & ((1u32 << LITLEN_TABLEBITS) - 1);
    tables.litlen[idx as usize]
}

/// Decode a distance entry from the table.
#[inline(always)]
fn decode_dist_entry(tables: &DecompressTables, bits_buf: u64) -> u32 {
    let idx = (bits_buf as u32) & ((1u32 << DIST_TABLEBITS) - 1);
    tables.dist[idx as usize]
}

/// Resolve a subtable entry if needed.
#[cold]
#[inline(never)]
fn resolve_subtable(table: &[u32], entry: u32, bits_buf: u64) -> u32 {
    let main_bits = (entry & 0xF) as u32;
    let sub_bits = ((entry >> 8) & 0x7F) as u32;
    let sub_offset = ((entry >> 16) & 0x7FFF) as usize;
    let sub_idx = ((bits_buf >> main_bits) as u32) & ((1u32 << sub_bits) - 1);
    table[sub_offset + sub_idx as usize]
}

/// The fast decode loop.
///
/// Decompresses DEFLATE symbols from `bits` into `out[out_pos..]`.
/// Caller has already parsed the block header (BFINAL, BTYPE) and built
/// the Huffman tables.
///
/// Returns the number of bytes written to `out` starting from `out_pos`.
///
/// # Safety
/// - `out` must have at least `FASTLOOP_OUTPUT_MARGIN` bytes of headroom
///   past the expected decompressed size (for SIMD overwrite).
/// - BitReader must be valid and properly initialized.
pub unsafe fn inflate_fast(
    bits: &mut BitReader,
    tables: &DecompressTables,
    out: &mut [u8],
    out_pos: usize,
) -> Result<usize, InflateError> {
    // SAFETY: entire function is unsafe — caller guarantees buffer validity.
    unsafe {
        let out_ptr = out.as_mut_ptr();
        let out_len = out.len();
        let mut pos = out_pos;

        let out_fast_end = if out_len > FASTLOOP_OUTPUT_MARGIN {
            out_len - FASTLOOP_OUTPUT_MARGIN
        } else {
            0
        };

        let in_fast_end = bits.input_end().sub(FASTLOOP_INPUT_MARGIN);

        bits.refill();
        let mut entry = decode_litlen_entry(tables, bits.raw_buf());

        while bits.input_ptr() < in_fast_end && pos < out_fast_end {
            if entry & HUFFDEC_SUBTABLE != 0 {
                entry = resolve_subtable(&tables.litlen, entry, bits.raw_buf());
            }

            // ── Literal fast path (up to 4 per iteration with burst store) ──
            if entry & HUFFDEC_LITERAL != 0 {
                let lit0 = (entry >> 16) as u8;
                let len0 = entry & 0xF;
                bits.consume(len0);

                // Try to decode up to 3 more literals for a burst write
                let entry1 = decode_litlen_entry(tables, bits.raw_buf());
                if entry1 & HUFFDEC_LITERAL != 0 && entry1 & HUFFDEC_SUBTABLE == 0 {
                    let lit1 = (entry1 >> 16) as u8;
                    let len1 = entry1 & 0xF;
                    bits.consume(len1);

                    let entry2 = decode_litlen_entry(tables, bits.raw_buf());
                    if entry2 & HUFFDEC_LITERAL != 0 && entry2 & HUFFDEC_SUBTABLE == 0 {
                        let lit2 = (entry2 >> 16) as u8;
                        let len2 = entry2 & 0xF;
                        bits.consume(len2);

                        // Refill before 4th literal — we may have consumed up to 45 bits
                        if bits.bits_remaining() < 15 {
                            bits.refill();
                        }

                        let entry3 = decode_litlen_entry(tables, bits.raw_buf());
                        if entry3 & HUFFDEC_LITERAL != 0 && entry3 & HUFFDEC_SUBTABLE == 0 {
                            let lit3 = (entry3 >> 16) as u8;
                            let len3 = entry3 & 0xF;
                            bits.consume(len3);

                            // 4-literal burst: single u32 store
                            let word = (lit0 as u32)
                                | ((lit1 as u32) << 8)
                                | ((lit2 as u32) << 16)
                                | ((lit3 as u32) << 24);
                            core::ptr::write_unaligned(out_ptr.add(pos) as *mut u32, word);
                            pos += 4;

                            bits.refill();
                            entry = decode_litlen_entry(tables, bits.raw_buf());
                            continue;
                        }

                        // 3 literals: write as u16 + u8
                        let half = (lit0 as u16) | ((lit1 as u16) << 8);
                        core::ptr::write_unaligned(out_ptr.add(pos) as *mut u16, half);
                        *out_ptr.add(pos + 2) = lit2;
                        pos += 3;

                        bits.refill();
                        entry = entry3;
                        continue;
                    }

                    // 2 literals: write as u16
                    core::ptr::write_unaligned(
                        out_ptr.add(pos) as *mut u16,
                        (lit0 as u16) | ((lit1 as u16) << 8),
                    );
                    pos += 2;

                    // Refill unconditionally so the next iteration starts with the
                    // full ≥56-bit budget the literal burst relies on. A conditional
                    // refill (e.g. only when < 32 bits) can leave too few bits for
                    // the burst's speculative `entry2` decode (which can run with as
                    // little as ~10 bits after consuming two ≤11-bit codes), reading
                    // a zero for the 11th table-index bit and decoding a wrong symbol.
                    bits.refill();
                    entry = entry2;
                    continue;
                }

                // 1 literal
                *out_ptr.add(pos) = lit0;
                pos += 1;

                // Refill unconditionally (see 2-literal path) so the next iteration
                // always has the full bit budget for the speculative burst decode.
                bits.refill();
                if entry1 & HUFFDEC_SUBTABLE != 0 {
                    entry = resolve_subtable(&tables.litlen, entry1, bits.raw_buf());
                    continue;
                }
                entry = entry1;
                continue;
            }

            // ── End of block ─────────────────────────────────────────────
            if entry & HUFFDEC_END_OF_BLOCK != 0 {
                let code_len = entry & 0xF;
                bits.consume(code_len);
                return Ok(pos - out_pos);
            }

            // ── Match: decode length ─────────────────────────────────────
            // After refill we have 56+ bits; a full match needs at most
            // 15 (len code) + 5 (len extra) + 15 (dist code) + 13 (dist extra) = 48 bits
            bits.refill();

            // Combined consume: extract extra bits from shifted buffer in one go
            let total_bits = entry & 0x1F;
            let code_len = (entry >> 8) & 0xF;
            let length_base = (entry >> 16) & 0x1FF;
            let extra_bits = total_bits - code_len;
            // Extract length extra bits from buf >> code_len, then consume total_bits
            let length = (length_base
                + ((bits.peek_at(code_len) as u32) & ((1u32 << extra_bits) - 1)))
                as usize;
            bits.consume(total_bits);

            // ── Decode distance ──────────────────────────────────────────
            let mut dist_entry = decode_dist_entry(tables, bits.raw_buf());
            if dist_entry & HUFFDEC_SUBTABLE != 0 {
                dist_entry = resolve_subtable(&tables.dist, dist_entry, bits.raw_buf());
            }

            let dist_total = dist_entry & 0x1F;
            let dist_code_len = (dist_entry >> 8) & 0xF;
            let dist_base = (dist_entry >> 16) & 0xFFFF;
            let dist_extra = dist_total - dist_code_len;
            let dist = (dist_base
                + ((bits.peek_at(dist_code_len) as u32) & ((1u32 << dist_extra) - 1)))
                as usize;
            bits.consume(dist_total);

            if dist == 0 || dist > pos {
                return Err(InflateError::InvalidDistance);
            }

            // ── PRELOAD next entry BEFORE match copy (hide L1 latency) ──
            bits.refill();
            entry = decode_litlen_entry(tables, bits.raw_buf());

            // ── Match copy (SIMD-accelerated) ────────────────────────────
            copy::copy_match(out_ptr.add(pos), dist, length);
            pos += length;
        }

        // ── Generic (safe) loop for remainder near buffer edges ──────────
        loop {
            if bits.bits_remaining() < 15 {
                bits.refill();
                if bits.bits_remaining() == 0 {
                    return Err(InflateError::DataError);
                }
            }

            entry = decode_litlen_entry(tables, bits.raw_buf());
            if entry & HUFFDEC_SUBTABLE != 0 {
                bits.refill();
                entry = resolve_subtable(&tables.litlen, entry, bits.raw_buf());
            }

            if entry & HUFFDEC_LITERAL != 0 {
                let code_len = entry & 0xF;
                bits.consume(code_len);
                if pos >= out_len {
                    return Err(InflateError::OutputOverflow);
                }
                *out_ptr.add(pos) = (entry >> 16) as u8;
                pos += 1;
                continue;
            }

            if entry & HUFFDEC_END_OF_BLOCK != 0 {
                let code_len = entry & 0xF;
                bits.consume(code_len);
                return Ok(pos - out_pos);
            }

            // Length
            let code_len = (entry >> 8) & 0xF;
            let total_bits = entry & 0x1F;
            let extra_bits = total_bits - code_len;
            let length_base = (entry >> 16) & 0x1FF;
            bits.consume(code_len);

            if bits.bits_remaining() < extra_bits + 15 {
                bits.refill();
            }

            let length = if extra_bits > 0 {
                let extra = bits.peek(extra_bits);
                bits.consume(extra_bits);
                length_base + extra
            } else {
                length_base
            } as usize;

            // Distance
            let mut dist_entry = decode_dist_entry(tables, bits.raw_buf());
            if dist_entry & HUFFDEC_SUBTABLE != 0 {
                dist_entry = resolve_subtable(&tables.dist, dist_entry, bits.raw_buf());
            }

            let dist_code_len = (dist_entry >> 8) & 0xF;
            let dist_total = dist_entry & 0x1F;
            let dist_extra = dist_total - dist_code_len;
            let dist_base = (dist_entry >> 16) & 0xFFFF;
            bits.consume(dist_code_len);

            if bits.bits_remaining() < dist_extra {
                bits.refill();
            }

            let dist = if dist_extra > 0 {
                let extra = bits.peek(dist_extra);
                bits.consume(dist_extra);
                dist_base + extra
            } else {
                dist_base
            } as usize;

            if dist == 0 || dist > pos {
                return Err(InflateError::InvalidDistance);
            }

            if pos + length > out_len {
                return Err(InflateError::OutputOverflow);
            }
            for i in 0..length {
                *out_ptr.add(pos + i) = *out_ptr.add(pos - dist + i);
            }
            pos += length;
        }
    } // unsafe
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed;

    #[test]
    fn inflate_fast_stored_like() {
        // Compress with higher level to ensure fixed/dynamic Huffman (not stored).
        let original = b"Hello, World! This is a test of the inflate fast loop. \
                         Repeating to ensure compressor uses Huffman: Hello, World!";
        let compressed = miniz_oxide::deflate::compress_to_vec(original, 6);

        // Parse block header (BFINAL + BTYPE).
        let mut bits = BitReader::new(&compressed);
        unsafe { bits.refill() };
        let _bfinal = bits.take(1);
        let btype = bits.take(2);

        // btype should be 1 (fixed) or 2 (dynamic) depending on miniz_oxide.
        // For this test, we need to handle both.
        let mut tables = DecompressTables::zeroed();

        if btype == 1 {
            fixed::load_fixed_tables(&mut tables);
        } else if btype == 2 {
            // Skip this test if dynamic — we test that through mod.rs.
            return;
        } else {
            panic!("unexpected btype {btype}");
        }

        let mut out = vec![0u8; original.len() + FASTLOOP_OUTPUT_MARGIN];
        let written = unsafe { inflate_fast(&mut bits, &tables, &mut out, 0) }
            .expect("inflate_fast should succeed");

        assert_eq!(&out[..written], original.as_slice());
    }
}
