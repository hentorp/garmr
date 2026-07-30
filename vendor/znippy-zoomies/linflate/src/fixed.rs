//! Pre-built fixed Huffman tables for BTYPE=1 blocks (RFC 1951 §3.2.6).
//!
//! Built once at first use (OnceLock), shared across all threads.

use std::sync::OnceLock;

use super::tables::{
    self, DIST_TABLE_SIZE, DIST_TABLEBITS, DecompressTables, LITLEN_TABLE_SIZE, LITLEN_TABLEBITS,
};

/// Fixed litlen code lengths (RFC 1951 §3.2.6):
///   0-143:   8 bits
///   144-255: 9 bits
///   256-279: 7 bits
///   280-287: 8 bits
fn fixed_litlen_lens() -> [u8; 288] {
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
    lens
}

/// Fixed distance code lengths: all 32 symbols have 5 bits.
fn fixed_dist_lens() -> [u8; 32] {
    [5u8; 32]
}

struct FixedTables {
    litlen: [u32; LITLEN_TABLE_SIZE],
    dist: [u32; DIST_TABLE_SIZE],
}

static FIXED: OnceLock<FixedTables> = OnceLock::new();

fn get_fixed() -> &'static FixedTables {
    FIXED.get_or_init(|| {
        let litlen_lens = fixed_litlen_lens();
        let dist_lens = fixed_dist_lens();
        let mut litlen = [0u32; LITLEN_TABLE_SIZE];
        let mut dist = [0u32; DIST_TABLE_SIZE];

        tables::build_decode_table(
            &litlen_lens,
            &mut litlen,
            LITLEN_TABLEBITS,
            tables::TableKind::Litlen,
        )
        .expect("fixed litlen table build must succeed");
        tables::build_decode_table(
            &dist_lens,
            &mut dist,
            DIST_TABLEBITS,
            tables::TableKind::Dist,
        )
        .expect("fixed dist table build must succeed");

        FixedTables { litlen, dist }
    })
}

/// Load fixed Huffman tables into the provided DecompressTables.
pub fn load_fixed_tables(tables: &mut DecompressTables) {
    let fixed = get_fixed();
    tables.litlen.copy_from_slice(&fixed.litlen);
    tables.dist[..DIST_TABLE_SIZE].copy_from_slice(&fixed.dist);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::{HUFFDEC_END_OF_BLOCK, HUFFDEC_LITERAL, entry_literal};

    #[test]
    fn fixed_tables_build_successfully() {
        let fixed = get_fixed();
        // Verify a few entries:
        // Symbol 0 (NUL literal, 8-bit code) should be marked as literal
        // Symbol 256 (EOB, 7-bit code) should have EOB flag
        let mut found_eob = false;
        let mut found_lit = false;
        for &entry in fixed.litlen.iter().take(1 << LITLEN_TABLEBITS) {
            if entry & HUFFDEC_END_OF_BLOCK != 0 {
                found_eob = true;
            }
            if entry & HUFFDEC_LITERAL != 0 && entry_literal(entry) == b'A' {
                found_lit = true;
            }
        }
        assert!(found_eob, "should find EOB in fixed litlen table");
        assert!(found_lit, "should find 'A' literal in fixed litlen table");
    }
}
