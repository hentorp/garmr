//! Branchless 64-bit DEFLATE bit reader.
//!
//! Design: libdeflate/zlib-ng style — 64-bit shift register with branchless
//! refill in 4 instructions. 32-byte struct fits one cache line.
//!
//! After `refill()`, at least 56 bits are available. A single DEFLATE symbol
//! (litlen + extra + dist + extra) needs at most 48 bits, so one refill per
//! symbol is always sufficient.

/// Branchless bit reader for DEFLATE decompression.
///
/// Reads bits LSB-first from a byte stream. All methods are `#[inline(always)]`
/// for the hot decode loop.
pub struct BitReader {
    /// Current read position in the input.
    ptr: *const u8,
    /// One-past-end of safe read zone (input end minus 7 for overread safety).
    safe_end: *const u8,
    /// Absolute end of input.
    end: *const u8,
    /// 64-bit shift register, LSB = next bit to consume.
    buf: u64,
    /// Number of valid bits currently in `buf` (0..=63).
    bits: u32,
}

// SAFETY: BitReader holds raw pointers into caller-provided slices.
// The caller guarantees the slice outlives the BitReader.
unsafe impl Send for BitReader {}

impl BitReader {
    /// Create a new BitReader over the given compressed data.
    ///
    /// The input slice must remain valid for the lifetime of the BitReader.
    #[inline]
    pub fn new(input: &[u8]) -> Self {
        let ptr = input.as_ptr();
        let end = unsafe { ptr.add(input.len()) };
        // safe_end = end - 7 (or ptr if input < 8 bytes) — we can always
        // read 8 bytes from ptr when ptr < safe_end without overread.
        let safe_end = if input.len() >= 8 {
            unsafe { end.sub(7) }
        } else {
            ptr
        };
        Self {
            ptr,
            safe_end,
            end,
            buf: 0,
            bits: 0,
        }
    }

    /// Branchless refill: guarantee at least 56 valid bits in `buf`.
    ///
    /// Uses the zlib-ng/libdeflate XOR trick:
    /// - Load 8 bytes (unaligned) and OR into buf shifted by current bit count
    /// - Advance ptr by `(63 ^ bits) >> 3` bytes (branchless)
    /// - Set bits |= 56
    ///
    /// 4 instructions, no branch. After refill: `self.bits >= 56`.
    #[inline(always)]
    pub unsafe fn refill(&mut self) {
        debug_assert!(self.bits <= 63);
        if self.ptr < self.safe_end {
            unsafe {
                let raw = core::ptr::read_unaligned(self.ptr as *const u64);
                self.buf |= u64::from_le(raw) << (self.bits as u8);
                let advance = ((63 ^ self.bits) >> 3) as usize;
                self.ptr = self.ptr.add(advance);
            }
            self.bits |= 56;
        } else {
            self.refill_slow();
        }
    }

    /// Slow-path refill for the last few bytes of input.
    ///
    /// Loop bound is `< 56`, NOT `<= 56`: entering with exactly 56 bits (what a
    /// fast refill leaves) must be a no-op. `<= 56` would push `bits` to 64,
    /// breaking the `bits <= 63` invariant — and the next fast refill's
    /// `<< bits` becomes a shift-by-64 (masked to `<< 0` on x86 in release),
    /// OR-ing 8 raw bytes over the whole register: silent corruption.
    /// Max exit value: enter at 55 → 63. Post-condition unchanged: ≥56 bits
    /// available whenever input remains.
    #[cold]
    #[inline(never)]
    fn refill_slow(&mut self) {
        while self.bits < 56 && self.ptr < self.end {
            self.buf |= (unsafe { *self.ptr } as u64) << self.bits;
            self.ptr = unsafe { self.ptr.add(1) };
            self.bits += 8;
        }
    }

    /// Peek at the lowest `n` bits without consuming them.
    #[inline(always)]
    pub fn peek(&self, n: u32) -> u32 {
        debug_assert!(n <= 32 && n <= self.bits);
        (self.buf as u32) & ((1u32 << n) - 1)
    }

    /// Peek at the lowest `n` bits as u64 without consuming them.
    #[inline(always)]
    pub fn peek64(&self, n: u32) -> u64 {
        debug_assert!(n <= 56 && n <= self.bits);
        self.buf & ((1u64 << n) - 1)
    }

    /// Peek at bits starting at offset `skip` (skip the first `skip` bits).
    /// Returns the value of bits [skip..skip+N) but without consuming anything.
    /// Used for combined length+extra decode pattern.
    #[inline(always)]
    pub fn peek_at(&self, skip: u32) -> u32 {
        (self.buf >> skip) as u32
    }

    /// Consume `n` bits (shift them out of the buffer).
    /// In release mode, saturates to available bits (avoids UB at end-of-stream padding).
    #[inline(always)]
    pub fn consume(&mut self, n: u32) {
        debug_assert!(n <= 64);
        let n = n.min(self.bits);
        self.buf >>= n;
        self.bits -= n;
    }

    /// Consume `n` bits without bounds checking (hot loop only).
    /// Caller must guarantee `n <= self.bits`.
    #[inline(always)]
    pub unsafe fn consume_unchecked(&mut self, n: u32) {
        debug_assert!(n <= self.bits);
        self.buf >>= n;
        self.bits -= n;
    }

    /// Consume `n` bits and return their value.
    #[inline(always)]
    pub fn take(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.consume(n);
        v
    }

    /// Extract variable-length bits from the saved buffer value.
    /// Equivalent to `saved_buf & ((1 << n) - 1)`.
    /// On x86_64 with BMI2, uses the BZHI instruction (single uop).
    #[inline(always)]
    pub fn extract_var(value: u64, n: u32) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            if cfg!(target_feature = "bmi2") {
                return unsafe { core::arch::x86_64::_bzhi_u64(value, n) };
            }
        }
        value & ((1u64 << n) - 1)
    }

    /// Number of valid bits remaining in the buffer.
    #[inline(always)]
    pub fn bits_remaining(&self) -> u32 {
        self.bits
    }

    /// Whether we've consumed all input AND the bit buffer is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.ptr >= self.end && self.bits == 0
    }

    /// Current input pointer (for fastloop bounds checking).
    #[inline(always)]
    pub fn input_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Input end pointer.
    #[inline(always)]
    pub fn input_end(&self) -> *const u8 {
        self.end
    }

    /// Advance the input pointer by `n` whole bytes without routing them through
    /// the bit buffer. Used after a byte-aligned bulk copy (stored blocks), where
    /// the payload is memcpy'd straight from the input remainder.
    ///
    /// # Safety
    /// The bit buffer must be empty (`bits == 0`, i.e. byte-aligned and drained)
    /// and `n` must not exceed `input_end() - input_ptr()`.
    #[inline(always)]
    pub unsafe fn advance_bytes(&mut self, n: usize) {
        debug_assert!(self.bits == 0);
        debug_assert!(unsafe { self.end.offset_from(self.ptr) } as usize >= n);
        self.ptr = unsafe { self.ptr.add(n) };
        // Clear any stale high bits left in `buf` by the last fast `refill`.
        // A fast refill loads 8 bytes but only counts 56 bits valid; the extra
        // top byte stays in `buf` and is normally harmless because the next
        // refill re-reads that same byte from `ptr` (an idempotent OR). Moving
        // `ptr` past it here breaks that correspondence, so the next refill would
        // OR fresh bytes on top of stale bits and corrupt stream alignment.
        // With `bits == 0` the buffer holds no valid bits, so resetting it is safe.
        self.buf = 0;
    }

    /// Align to byte boundary (discard partial byte bits).
    /// Used for stored blocks which start byte-aligned.
    #[inline(always)]
    pub fn align_to_byte(&mut self) {
        let discard = self.bits & 7;
        self.consume(discard);
    }

    /// Read a u16 from the bit buffer (byte-aligned).
    /// Used for stored block LEN/NLEN fields.
    #[inline(always)]
    pub fn take_u16(&mut self) -> u16 {
        debug_assert!(self.bits >= 16);
        let v = (self.buf as u16).to_le();
        self.consume(16);
        v
    }

    /// The raw bit buffer value (for preloading Huffman entries).
    #[inline(always)]
    pub fn raw_buf(&self) -> u64 {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_read() {
        let data = [
            0b10110100u8,
            0b01101001u8,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
        ];
        let mut br = BitReader::new(&data);
        unsafe { br.refill() };
        assert!(br.bits_remaining() >= 56);
        // LSB-first: first byte 0xB4 = 10110100
        assert_eq!(br.take(4), 0b0100); // low 4 bits of 0xB4
        assert_eq!(br.take(4), 0b1011); // high 4 bits of 0xB4
        assert_eq!(br.take(8), 0b01101001); // second byte 0x69
    }

    #[test]
    fn refill_guarantees_56_bits() {
        let data = vec![0xAAu8; 64];
        let mut br = BitReader::new(&data);
        unsafe { br.refill() };
        assert!(br.bits_remaining() >= 56);
        br.consume(48);
        unsafe { br.refill() };
        assert!(br.bits_remaining() >= 56);
    }

    #[test]
    fn small_input() {
        let data = [0x42u8, 0x37];
        let mut br = BitReader::new(&data);
        unsafe { br.refill() };
        assert!(br.bits_remaining() >= 16);
        assert_eq!(br.take(8), 0x42);
        assert_eq!(br.take(8), 0x37);
    }

    #[test]
    fn align_to_byte() {
        let data = [0xFF; 8];
        let mut br = BitReader::new(&data);
        unsafe { br.refill() };
        br.consume(3); // consume 3 bits
        br.align_to_byte(); // should discard 5 more to reach byte boundary
        assert_eq!(br.bits_remaining() % 8, 0);
    }

    #[test]
    fn extract_var_matches_mask() {
        assert_eq!(BitReader::extract_var(0xDEADBEEF, 8), 0xEF);
        assert_eq!(BitReader::extract_var(0xDEADBEEF, 16), 0xBEEF);
        assert_eq!(BitReader::extract_var(0xDEADBEEF, 32), 0xDEADBEEF);
    }

    #[test]
    fn peek_does_not_consume() {
        let data = [0xAB; 8];
        let mut br = BitReader::new(&data);
        unsafe { br.refill() };
        let a = br.peek(8);
        let b = br.peek(8);
        assert_eq!(a, b);
        assert_eq!(a, 0xAB);
    }

    #[test]
    fn empty_input() {
        let data: &[u8] = &[];
        let br = BitReader::new(data);
        assert!(br.is_empty());
    }

    #[test]
    fn advance_bytes_clears_stale_high_bits() {
        // Regression: a fast refill loads 8 bytes but counts only 56 bits valid,
        // leaving the 8th byte as stale high bits in `buf`. Draining to bits==0
        // and then `advance_bytes` past that byte must clear `buf`, else the next
        // refill ORs fresh bytes over stale ones and corrupts alignment.
        // Bytes 0..7 are 0xFF (so the stale 8th byte would be 0xFF); after
        // advancing over them, byte 8 == 0x00 must read back cleanly as 0x00.
        let mut data = vec![0xFFu8; 8];
        data.push(0x00); // byte 8 — must read as 0x00, not 0xFF, after advance
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        let mut br = BitReader::new(&data);
        unsafe { br.refill() };
        assert_eq!(br.bits_remaining(), 56);
        // Drain the 7 valid bytes (0..7) to reach the byte-aligned bits==0 state.
        for _ in 0..7 {
            let _ = br.take(8);
        }
        assert_eq!(br.bits_remaining(), 0);
        // ptr is at byte 7; advance one more to skip the re-read byte (index 7).
        unsafe { br.advance_bytes(1) };
        unsafe { br.refill() };
        // Byte 8 must read as 0x00 — a stale 0xFF here signals the bug.
        assert_eq!(
            br.take(8),
            0x00,
            "stale high bits leaked past advance_bytes"
        );
    }

    #[test]
    fn refill_slow_at_56_bits_keeps_invariant() {
        // Regression: 10-byte input. The first (fast) refill advances ptr by 7,
        // past safe_end = end-7, leaving bits == 56. The second refill takes the
        // slow path with input remaining; the old `bits <= 56` loop bound pushed
        // bits to 64 (invariant breach → shift-by-64 corruption in release).
        let data = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        let mut br = BitReader::new(&data);
        unsafe { br.refill() };
        assert_eq!(br.bits_remaining(), 56);
        unsafe { br.refill() }; // must be a no-op, not bits=64
        assert!(br.bits_remaining() <= 63);
        // Stream still decodes correctly after the double refill.
        assert_eq!(br.take(8), 0x11);
        assert_eq!(br.take(8), 0x22);
        unsafe { br.refill() };
        assert!(br.bits_remaining() <= 63);
        assert_eq!(br.take(8), 0x33);
    }
}
