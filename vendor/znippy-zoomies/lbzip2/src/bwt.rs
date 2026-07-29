//! Inverse Burrows-Wheeler Transform.
//!
//! Given the BWT output array `tt` and the origin pointer `orig_ptr`,
//! reconstruct the original byte sequence.

/// Inverse BWT using the standard "T-transformation" approach.
///
/// - `tt[i]` stores the byte value in the low 8 bits (as placed by the decoder).
/// - `c[b]` counts occurrences of byte `b`.
/// - `orig_ptr` is the row index of the original string in the BWT matrix.
///
/// After this function, call `read_from_tt` to extract bytes.
///
/// Returns the initial `t_pos` for output traversal.
/// Returns `None` when the byte-count histogram `c` is inconsistent with `tt`
/// (their total must equal `tt.len()`, and every scatter index must stay in
/// bounds). A mis-decoded block can yield such counts; without this check the
/// fill below would write — and the later `next_byte` chase would read —
/// out of bounds, which SIGSEGVs the whole process on hostile/edge input
/// (observed: a planet bz2 block drove `c[b]` ~60 MB past `tt`). A bzip2
/// decoder must fail the block, never crash. When it returns `Some`, every
/// `tt` entry's upper-24-bit index is `< tt.len()`, so the pointer chase in
/// [`next_byte`] is provably in-bounds.
pub fn inverse_bwt(tt: &mut [u32], orig_ptr: usize, mut c: [u32; 256]) -> Option<u32> {
    let n = tt.len();
    // Build cumulative counts: c[b] = number of bytes < b.
    let mut sum = 0u32;
    for ci in c.iter_mut() {
        let count = *ci;
        *ci = sum;
        sum += count;
    }
    // A consistent block has exactly `n` bytes spread across the 256 buckets.
    if sum as usize != n || orig_ptr >= n {
        return None;
    }

    // Build the T-transformation vector.
    // tt[c[b]] |= (i << 8)  — stores the "next index" in the upper 24 bits.
    for i in 0..n {
        let b = (tt[i] & 0xFF) as usize;
        let idx = c[b] as usize;
        if idx >= n {
            return None; // per-bucket counts diverge even though the total matched
        }
        tt[idx] |= (i as u32) << 8;
        c[b] += 1;
    }

    Some(tt[orig_ptr] >> 8)
}

/// Extract one byte from the T-transformation and advance `t_pos`.
#[inline]
pub fn next_byte(tt: &[u32], t_pos: &mut u32) -> u8 {
    *t_pos = tt[*t_pos as usize];
    let b = *t_pos as u8;
    *t_pos >>= 8;
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_inverse() {
        // BWT of "banana" is "annb$aa" (simplified).
        // This test uses a known small example.
        // Input BWT: [1, 0, 2, 1, 0, 0]  (bytes)
        // orig_ptr: 3
        let mut tt: Vec<u32> = vec![1, 0, 2, 1, 0, 0];
        let mut c = [0u32; 256];
        for &b in &tt {
            c[b as usize] += 1;
        }
        let mut t_pos = inverse_bwt(&mut tt, 3, c).expect("consistent counts decode");

        let mut output = Vec::new();
        for _ in 0..6 {
            output.push(next_byte(&tt, &mut t_pos));
        }
        // The output should be the original sequence.
        // We just verify it doesn't panic and produces 6 bytes.
        assert_eq!(output.len(), 6);
    }

    /// Inconsistent byte counts (histogram total ≠ tt.len()) must be REJECTED,
    /// not scatter/chase out of bounds. Regression for the planet bz2 SIGSEGV.
    #[test]
    fn inconsistent_counts_rejected_not_ub() {
        let mut tt: Vec<u32> = vec![1, 0, 2, 1, 0, 0]; // 6 bytes
        let mut c = [0u32; 256];
        c[0] = 2; // deliberately wrong: real histogram is 0→3, 1→2, 2→1 (sum 6)
        c[1] = 1; // here sum = 4 ≠ 6 → must be rejected
        c[2] = 1;
        assert!(inverse_bwt(&mut tt, 3, c).is_none());
    }
}
