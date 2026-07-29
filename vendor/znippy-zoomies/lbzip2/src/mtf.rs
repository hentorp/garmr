//! Move-to-front transform decoder.
//!
//! bzip2 applies MTF encoding after BWT to cluster repeated symbols near
//! index 0, making Huffman coding more effective.

pub struct MtfDecoder {
    symbols: [u8; 256],
}

impl MtfDecoder {
    /// Standard MTF decoder: symbols[i] = i.
    pub fn new() -> Self {
        let mut symbols = [0u8; 256];
        for (i, s) in symbols.iter_mut().enumerate() {
            *s = i as u8;
        }
        Self { symbols }
    }

    /// MTF decoder with a custom initial symbol order.
    pub fn with_symbols(symbols: [u8; 256]) -> Self {
        Self { symbols }
    }

    /// Decode: return the symbol at position `n`, then move it to front.
    #[inline(always)]
    pub fn decode(&mut self, n: u8) -> u8 {
        let idx = n as usize;
        let b = self.symbols[idx];
        if idx == 0 {
            return b;
        }
        if idx == 1 {
            self.symbols[1] = self.symbols[0];
            self.symbols[0] = b;
            return b;
        }
        // Perf: MTF after BWT clusters strongly near index 0, so almost every
        // symbol has idx < 16. Shift the first 16 bytes as a single u128 read +
        // shift + write instead of a byte-at-a-time `copy_within`, which the
        // compiler lowers to a `memmove`/loop. This collapses the dominant
        // O(idx) shift to a couple of register ops for the common case.
        if idx < 16 {
            // Read the leading 16 bytes as one little-endian u128, where byte i
            // of `symbols` sits at bit position i*8. We must move bytes [0..idx)
            // up one slot (byte i -> slot i+1), set slot 0 = b, and leave slots
            // (idx..16) untouched.
            //
            //   moved: (head << 8) keeps the shifted bytes, masked to the bit
            //          window [8 .. (idx+1)*8) — i.e. slots 1..=idx.
            //   high:  original bytes in slots (idx+1..16), bit window
            //          [(idx+1)*8 .. 128).
            // slot 0 is then overwritten with b.
            let head = u128::from_le_bytes(self.symbols[..16].try_into().unwrap());
            let top_bit = (idx + 1) * 8; // first bit not covered by the moved window
            // bits [0 .. top_bit); top_bit == 128 (idx==15) means "all bits".
            let window = if top_bit >= 128 {
                !0u128
            } else {
                (1u128 << top_bit) - 1
            };
            let moved = (head << 8) & window; // shifted bytes, slots 1..=idx
            let high = head & !window; // untouched high bytes, slots idx+1..15
            let mut bytes = (moved | high).to_le_bytes();
            bytes[0] = b; // place decoded symbol at front
            self.symbols[..16].copy_from_slice(&bytes);
            return b;
        }
        // Cold path for large indices: shift symbols[0..idx] right by one.
        self.symbols.copy_within(..idx, 1);
        self.symbols[0] = b;
        b
    }

    /// Return the symbol currently at front (position 0).
    #[inline]
    pub fn first(&self) -> u8 {
        self.symbols[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference MTF decode (naive shift) to validate the fast path against.
    fn ref_decode(symbols: &mut [u8; 256], n: u8) -> u8 {
        let idx = n as usize;
        let b = symbols[idx];
        symbols.copy_within(..idx, 1);
        symbols[0] = b;
        b
    }

    #[test]
    fn fast_path_matches_reference_all_indices() {
        // Drive both the optimized decoder and a naive reference with the same
        // pseudo-random index stream; states and outputs must stay identical.
        let mut init = [0u8; 256];
        for (i, s) in init.iter_mut().enumerate() {
            *s = i as u8;
        }
        let mut fast = MtfDecoder::with_symbols(init);
        let mut refs = init;

        // LCG for reproducible "random" indices across the full 0..256 range,
        // biased toward small indices (the common MTF case) but covering all.
        let mut state: u32 = 0x1234_5678;
        for step in 0..200_000u32 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            // Mix small and large indices to exercise every branch.
            let idx = if step % 3 == 0 {
                (state >> 8) as u8 % 16 // small: u128 fast path
            } else {
                (state >> 8) as u8 // full range: cold path too
            };
            let got = fast.decode(idx);
            let want = ref_decode(&mut refs, idx);
            assert_eq!(got, want, "output mismatch at step {step}, idx {idx}");
            assert_eq!(
                fast.symbols, refs,
                "state mismatch at step {step}, idx {idx}"
            );
        }
    }

    #[test]
    fn basic_mtf() {
        let mut mtf = MtfDecoder::new();
        assert_eq!(mtf.decode(5), 5);
        assert_eq!(mtf.first(), 5);
        // After decoding 5: symbols = [5, 0, 1, 2, 3, 4, 6, 7, ...]
        assert_eq!(mtf.decode(0), 5); // 5 is at front
        assert_eq!(mtf.decode(1), 0); // 0 is at position 1
    }
}
