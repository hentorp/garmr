//! Huffman table builder with packed u32 entries.
//!
//! Design follows libdeflate: 11-bit litlen first-level table, 8-bit dist,
//! 7-bit precode. Packed u32 entries encode literal/length/subtable-pointer
//! in a single word so the fast loop needs one table lookup per symbol.
//!
//! Thread-local table pool avoids per-block heap allocation (lbzip2-rs pattern).

use std::cell::UnsafeCell;

use super::InflateError;

// ── Table dimensions (libdeflate) ────────────────────────────────────────────

pub const LITLEN_TABLEBITS: u32 = 11;
pub const LITLEN_TABLE_SIZE: usize = 2342; // ENOUGH for 11-bit first level

pub const DIST_TABLEBITS: u32 = 8;
pub const DIST_TABLE_SIZE: usize = 402;

pub const PRECODE_TABLEBITS: u32 = 7;
pub const PRECODE_TABLE_SIZE: usize = 128;

// ── Entry format flags ───────────────────────────────────────────────────────

/// Bit 31: this entry is a literal (not a length/match).
pub const HUFFDEC_LITERAL: u32 = 1 << 31;

/// Bit 15: this entry is a subtable pointer (codes longer than table_bits).
pub const HUFFDEC_SUBTABLE: u32 = 1 << 15;

/// End-of-block marker (symbol 256). We encode it as a non-literal,
/// non-subtable entry with length_base = 0 and a special flag.
pub const HUFFDEC_END_OF_BLOCK: u32 = 1 << 30;

// ── Entry encoding helpers ───────────────────────────────────────────────────

/// Pack a literal entry: bit31 set | byte_value in bits 23-16 | code_len in bits 3-0.
#[inline(always)]
pub const fn pack_literal(byte_val: u8, code_len: u8) -> u32 {
    HUFFDEC_LITERAL | ((byte_val as u32) << 16) | (code_len as u32)
}

/// Pack a length entry: length_base in bits 24-16 | code_len in bits 11-8 |
/// (code_len + extra_bits) in bits 4-0.
#[inline(always)]
pub const fn pack_length(length_base: u16, code_len: u8, extra_bits: u8) -> u32 {
    ((length_base as u32) << 16) | ((code_len as u32) << 8) | ((code_len + extra_bits) as u32)
}

/// Pack an end-of-block entry.
#[inline(always)]
pub const fn pack_eob(code_len: u8) -> u32 {
    HUFFDEC_END_OF_BLOCK | (code_len as u32)
}

/// Pack a distance entry: dist_base in bits 31-16 (16 bits) | code_len in bits 11-8 |
/// (code_len + extra_bits) in bits 4-0.
/// Distance bases can be up to 24577, requiring 15 bits.
#[inline(always)]
pub const fn pack_distance(dist_base: u16, code_len: u8, extra_bits: u8) -> u32 {
    ((dist_base as u32) << 16) | ((code_len as u32) << 8) | ((code_len + extra_bits) as u32)
}

/// Pack a subtable pointer: subtable_offset in bits 30-16 | SUBTABLE flag |
/// subtable_bits in bits 11-8 | main_table_bits in bits 3-0.
#[inline(always)]
pub const fn pack_subtable(offset: u16, subtable_bits: u8, main_bits: u8) -> u32 {
    ((offset as u32) << 16) | HUFFDEC_SUBTABLE | ((subtable_bits as u32) << 8) | (main_bits as u32)
}

// ── DEFLATE static tables ────────────────────────────────────────────────────

/// Length base values for litlen symbols 257..285.
pub static LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];

/// Extra bits for litlen symbols 257..285.
pub static LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// Distance base values for dist symbols 0..29.
pub static DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

/// Extra bits for dist symbols 0..29.
pub static DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

// ── Decode tables struct ─────────────────────────────────────────────────────

/// All Huffman decode tables for one DEFLATE block.
///
/// ~14 KB total — fits in L1-D with room for the hot loop's stack frame.
/// Allocated once per thread via thread-local pool.
pub struct DecompressTables {
    pub litlen: [u32; LITLEN_TABLE_SIZE],
    pub dist: [u32; DIST_TABLE_SIZE],
    pub precode: [u32; PRECODE_TABLE_SIZE],
}

impl DecompressTables {
    pub fn zeroed() -> Self {
        Self {
            litlen: [0u32; LITLEN_TABLE_SIZE],
            dist: [0u32; DIST_TABLE_SIZE],
            precode: [0u32; PRECODE_TABLE_SIZE],
        }
    }
}

// ── Thread-local pool (lbzip2-rs pattern) ────────────────────────────────────

thread_local! {
    static TABLES: UnsafeCell<Option<Box<DecompressTables>>> = const { UnsafeCell::new(None) };
}

/// Borrow the thread-local DecompressTables, creating it on first use.
/// SAFETY: thread_local guarantees single-threaded access within each thread.
pub fn with_tables<R>(f: impl FnOnce(&mut DecompressTables) -> R) -> R {
    TABLES.with(|cell| {
        let opt = unsafe { &mut *cell.get() };
        let tables = opt.get_or_insert_with(|| Box::new(DecompressTables::zeroed()));
        f(tables)
    })
}

// ── Table builder ────────────────────────────────────────────────────────────

/// What kind of table we're building.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    Litlen,
    Dist,
    /// Code-length alphabet (symbols 0-18): value stored as literal in bits 23-16.
    Precode,
}

/// Build a Huffman decode table from code lengths.
///
/// `lens[i]` is the bit-length of symbol `i` (0 = not used).
/// `table` is the output table to fill.
/// `table_bits` is the first-level table size in bits (e.g. 11 for litlen).
/// `kind` controls how entries are packed.
///
/// Returns the total number of table entries written (including subtables).
pub fn build_decode_table(
    lens: &[u8],
    table: &mut [u32],
    table_bits: u32,
    kind: TableKind,
) -> Result<usize, InflateError> {
    let num_syms = lens.len();
    let table_size = 1usize << table_bits;

    // Step 1: Count codes of each length.
    let mut bl_count = [0u32; 16]; // max DEFLATE code length is 15
    let mut max_len: u32 = 0;
    for &len in lens.iter() {
        if len > 0 {
            bl_count[len as usize] += 1;
            if (len as u32) > max_len {
                max_len = len as u32;
            }
        }
    }

    if max_len == 0 {
        // All lengths are 0 — empty table (valid for dist table with no distance codes).
        for entry in table[..table_size].iter_mut() {
            *entry = 0;
        }
        return Ok(table_size);
    }

    // Reject over-subscribed code lengths (Kraft–McMillan inequality).
    //
    // Garbage bytes — e.g. from lgz's speculative DEFLATE block probing —
    // routinely produce oversubscribed trees. Without this guard the canonical
    // code assignment below overflows the code space and writes past the decode
    // table, panicking with an out-of-bounds index. Returning Err lets callers
    // reject an invalid candidate offset instead of aborting the process.
    {
        let mut left: i32 = 1;
        for bits in 1..=15usize {
            left <<= 1;
            left -= bl_count[bits] as i32;
            if left < 0 {
                return Err(InflateError::InvalidHuffmanTable);
            }
        }
    }

    // Step 2: Compute first code for each length (DEFLATE canonical ordering).
    let mut next_code = [0u32; 16];
    {
        let mut code = 0u32;
        for bits in 1..=15 {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
        }
    }

    // Step 3: Assign codes to symbols in a single pass and fill the table.
    // Clear main table entries
    for entry in table[..table_size].iter_mut() {
        *entry = 0;
    }

    let mut table_end = table_size; // next free position for subtables

    // Pre-compute subtable allocation: find which main-table indices need subtables,
    // and their maximum sub-code length.
    // subtable_info[main_idx] = max_sub_bits (0 = no subtable needed)
    let mut subtable_max_bits = [0u8; 2048]; // max table_size = 2048 for 11-bit
    debug_assert!(table_size <= 2048);

    if max_len > table_bits {
        // First pass: compute codes and determine subtable sizes
        let mut codes_tmp = next_code;
        for sym in 0..num_syms {
            let len = lens[sym] as u32;
            if len <= table_bits || len == 0 {
                continue;
            }
            let code = codes_tmp[len as usize];
            codes_tmp[len as usize] += 1;
            let reversed = bit_reverse(code, len);
            let main_idx = (reversed & ((1u32 << table_bits) - 1)) as usize;
            let sub_bits = (len - table_bits) as u8;
            if sub_bits > subtable_max_bits[main_idx] {
                subtable_max_bits[main_idx] = sub_bits;
            }
        }

        // Allocate subtables
        for main_idx in 0..table_size {
            let max_sub = subtable_max_bits[main_idx];
            if max_sub > 0 {
                let sub_size = 1usize << max_sub;
                let sub_offset = table_end;
                table_end += sub_size;
                if table_end > table.len() {
                    return Err(InflateError::InvalidHuffmanTable);
                }
                // Clear subtable
                for e in table[sub_offset..sub_offset + sub_size].iter_mut() {
                    *e = 0;
                }
                table[main_idx] = pack_subtable(sub_offset as u16, max_sub, table_bits as u8);
            }
        }
    }

    // Second pass: assign all symbols to their table entries (single pass, O(n))
    let mut next_code2 = next_code;
    for sym in 0..num_syms {
        let len = lens[sym] as u32;
        if len == 0 {
            continue;
        }

        let code = next_code2[len as usize];
        next_code2[len as usize] += 1;

        let entry = match kind {
            TableKind::Litlen => pack_litlen_entry(sym, len as u8),
            TableKind::Dist => pack_dist_entry(sym, len as u8),
            TableKind::Precode => pack_literal(sym as u8, len as u8),
        };

        let reversed = bit_reverse(code, len);

        if len <= table_bits {
            // Fill all aliased positions in the main table.
            let step = 1u32 << len;
            let mut idx = reversed;
            while (idx as usize) < table_size {
                table[idx as usize] = entry;
                idx += step;
            }
        } else {
            // Subtable entry
            let main_idx = (reversed & ((1u32 << table_bits) - 1)) as usize;
            let sub_entry = table[main_idx];
            let sub_offset = ((sub_entry >> 16) & 0x7FFF) as usize;
            let max_sub_bits = ((sub_entry >> 8) & 0x7F) as u32;
            let sub_bits = len - table_bits;

            let sub_idx = (reversed >> table_bits) & ((1u32 << max_sub_bits) - 1);
            let step = 1u32 << sub_bits;
            let sub_size = 1u32 << max_sub_bits;
            let mut idx = sub_idx;
            while idx < sub_size {
                table[sub_offset + idx as usize] = entry;
                idx += step;
            }
        }
    }

    Ok(table_end)
}

/// Compute the canonical Huffman code for symbol `sym` given `lens`.
/// Test-only helper (verifies decode-table entries against RFC 1951 codes).
#[cfg(test)]
fn compute_code_for_sym(lens: &[u8], sym: usize) -> u32 {
    let len = lens[sym] as u32;
    if len == 0 {
        return 0;
    }

    let mut bl_count = [0u32; 16];
    for &l in lens.iter() {
        if l > 0 {
            bl_count[l as usize] += 1;
        }
    }
    let mut next_code = [0u32; 16];
    let mut code = 0u32;
    for bits in 1..=15 {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    next_code[len as usize] + (0..sym).filter(|&i| lens[i] as u32 == len).count() as u32
}

/// Bit-reverse `code` of `len` bits.
#[inline(always)]
fn bit_reverse(code: u32, len: u32) -> u32 {
    // Use the full 32-bit reverse then shift right to get `len` bits.
    code.reverse_bits() >> (32 - len)
}

/// Pack a litlen symbol into a table entry.
fn pack_litlen_entry(sym: usize, code_len: u8) -> u32 {
    if sym < 256 {
        pack_literal(sym as u8, code_len)
    } else if sym == 256 {
        pack_eob(code_len)
    } else if sym <= 285 {
        let idx = sym - 257;
        pack_length(LENGTH_BASE[idx], code_len, LENGTH_EXTRA[idx])
    } else {
        0 // invalid symbol
    }
}

/// Pack a distance symbol into a table entry.
fn pack_dist_entry(sym: usize, code_len: u8) -> u32 {
    if sym < 30 {
        pack_distance(DIST_BASE[sym], code_len, DIST_EXTRA[sym])
    } else {
        0 // invalid symbol
    }
}

// ── Decode helpers (used by fastloop) ────────────────────────────────────────

/// Decode a litlen symbol from the table. Returns the packed entry.
///
/// Fast path (no subtable): single table lookup + consume.
/// Slow path (subtable): two lookups.
#[inline(always)]
pub fn decode_entry(table: &[u32], bits_buf: u64, table_bits: u32) -> u32 {
    let idx = (bits_buf as u32) & ((1u32 << table_bits) - 1);
    let entry = table[idx as usize];
    if entry & HUFFDEC_SUBTABLE == 0 {
        return entry;
    }
    // Subtable lookup
    let main_bits = (entry & 0xF) as u32;
    let sub_bits = ((entry >> 8) & 0x7F) as u32;
    let sub_offset = ((entry >> 16) & 0x7FFF) as usize;
    let sub_idx = ((bits_buf >> main_bits) as u32) & ((1u32 << sub_bits) - 1);
    table[sub_offset + sub_idx as usize]
}

/// Extract the code length from an entry (bits 3-0 for main, or full for subtable result).
#[inline(always)]
pub fn entry_code_len(entry: u32) -> u32 {
    entry & 0xF
}

/// Extract the total bits to consume from an entry (bits 4-0).
/// For literals: same as code_len. For lengths/distances: code_len + extra_bits.
#[inline(always)]
pub fn entry_total_bits(entry: u32) -> u32 {
    entry & 0x1F
}

/// Extract the literal byte value from a literal entry (bits 23-16).
#[inline(always)]
pub fn entry_literal(entry: u32) -> u8 {
    (entry >> 16) as u8
}

/// Extract the length/distance base value from an entry (bits 24-16).
#[inline(always)]
pub fn entry_base(entry: u32) -> u32 {
    (entry >> 16) & 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_literal() {
        let entry = pack_literal(b'A', 7);
        assert!(entry & HUFFDEC_LITERAL != 0);
        assert_eq!(entry_literal(entry), b'A');
        assert_eq!(entry_code_len(entry), 7);
    }

    #[test]
    fn pack_unpack_length() {
        // Symbol 257: length_base=3, extra=0, code_len=7
        let entry = pack_length(3, 7, 0);
        assert!(entry & HUFFDEC_LITERAL == 0);
        assert!(entry & HUFFDEC_END_OF_BLOCK == 0);
        assert_eq!(entry_base(entry), 3);
        assert_eq!((entry >> 8) & 0xF, 7); // code_len in bits 11-8
        assert_eq!(entry_total_bits(entry), 7); // 7 + 0 extra
    }

    #[test]
    fn pack_unpack_eob() {
        let entry = pack_eob(7);
        assert!(entry & HUFFDEC_END_OF_BLOCK != 0);
        assert!(entry & HUFFDEC_LITERAL == 0);
        assert_eq!(entry_code_len(entry), 7);
    }

    #[test]
    fn bit_reverse_basic() {
        assert_eq!(bit_reverse(0b110, 3), 0b011);
        assert_eq!(bit_reverse(0b1010, 4), 0b0101);
        assert_eq!(bit_reverse(0b1, 1), 0b1);
    }

    #[test]
    fn build_simple_table() {
        // Two symbols with lengths [1, 1]: codes 0, 1.
        let lens = [1u8, 1];
        let mut table = [0u32; 4]; // 2-bit table
        let result = build_decode_table(&lens, &mut table, 2, TableKind::Litlen);
        assert!(result.is_ok());
        // Symbol 0 (code 0, len 1) should appear at indices 0 and 2
        assert!(table[0] & HUFFDEC_LITERAL != 0);
        assert_eq!(entry_literal(table[0]), 0);
        assert!(table[2] & HUFFDEC_LITERAL != 0);
        assert_eq!(entry_literal(table[2]), 0);
        // Symbol 1 (code 1, len 1) should appear at indices 1 and 3
        assert!(table[1] & HUFFDEC_LITERAL != 0);
        assert_eq!(entry_literal(table[1]), 1);
        assert!(table[3] & HUFFDEC_LITERAL != 0);
        assert_eq!(entry_literal(table[3]), 1);
    }

    #[test]
    fn build_fixed_litlen_table() {
        // Build the fixed Huffman litlen table (RFC 1951 section 3.2.6).
        let mut lens = [0u8; 288];
        for i in 0..=143 {
            lens[i] = 8;
        }
        for i in 144..=255 {
            lens[i] = 9;
        }
        for i in 256..=279 {
            lens[i] = 7;
        }
        for i in 280..=287 {
            lens[i] = 8;
        }

        let mut table = [0u32; LITLEN_TABLE_SIZE];
        let result = build_decode_table(&lens, &mut table, LITLEN_TABLEBITS, TableKind::Litlen);
        assert!(result.is_ok());

        // Verify some known entries:
        // Symbol 0 (literal NUL) should have code_len 8.
        // Its 8-bit code, reversed to LSB-first, is looked up via 11-bit index.
        // Just verify the entry is a literal.
        // The 11-bit table captures all 7-bit and 8-bit codes directly.
        // Symbol 256 (EOB) has code_len 7.
        // Find it: peek 11 bits where low 7 bits = reversed 7-bit code for sym 256.
        let eob_code = compute_code_for_sym(&lens, 256);
        let eob_rev = bit_reverse(eob_code, 7);
        let entry = table[eob_rev as usize];
        assert!(
            entry & HUFFDEC_END_OF_BLOCK != 0,
            "EOB entry should have EOB flag"
        );
    }
}
