//! Bit-level reader over a byte slice.  Zero-copy — borrows the slice.
//!
//! Uses a 64-bit buffer with bulk refill for high throughput.
//! Supports arbitrary bit-offset start (for block boundaries that aren't
//! byte-aligned).

/// A non-allocating bit reader over a borrowed byte slice.
///
/// Maintains a 64-bit internal buffer that is refilled in bulk,
/// avoiding per-bit byte lookups.
pub struct BitReader<'a> {
    bytes: &'a [u8],
    /// Byte position: next byte to load into the buffer.
    byte_pos: usize,
    /// 64-bit shift register, MSB-first.
    buf: u64,
    /// Number of valid bits remaining in `buf` (counted from MSB).
    bits_in_buf: u8,
}

impl<'a> BitReader<'a> {
    /// Create a new reader starting at bit 0 of `bytes`.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Self {
        let mut r = Self {
            bytes,
            byte_pos: 0,
            buf: 0,
            bits_in_buf: 0,
        };
        r.refill();
        r
    }

    /// Create a new reader starting at an arbitrary bit offset.
    /// Used for block boundaries that aren't byte-aligned.
    #[inline]
    pub fn from_bit_offset(bytes: &'a [u8], bit_offset: usize) -> Self {
        let byte_off = bit_offset / 8;
        let sub_bits = (bit_offset % 8) as u8;
        let mut r = Self {
            bytes,
            byte_pos: byte_off,
            buf: 0,
            bits_in_buf: 0,
        };
        r.refill();
        // Discard sub-byte offset bits
        if sub_bits > 0 {
            r.buf <<= sub_bits;
            r.bits_in_buf = r.bits_in_buf.saturating_sub(sub_bits);
        }
        r
    }

    /// Current bit position in the original byte stream.
    #[inline]
    pub fn position(&self) -> usize {
        self.byte_pos * 8 - self.bits_in_buf as usize
    }

    /// Remaining bits available.
    #[inline]
    pub fn remaining(&self) -> usize {
        (self.bytes.len() - self.byte_pos) * 8 + self.bits_in_buf as usize
    }

    /// Refill the buffer from the byte stream.
    /// Bulk-loads up to 8 bytes in a single read when possible.
    #[inline(always)]
    fn refill(&mut self) {
        if self.byte_pos + 8 <= self.bytes.len() {
            // Fast path: single 8-byte big-endian load
            let word = u64::from_be_bytes(unsafe {
                *(self.bytes.as_ptr().add(self.byte_pos) as *const [u8; 8])
            });
            self.buf |= word >> self.bits_in_buf;
            let loaded = ((64 - self.bits_in_buf) / 8) as usize;
            self.byte_pos += loaded;
            self.bits_in_buf += (loaded * 8) as u8;
        } else {
            // Near end of stream: byte-at-a-time fallback
            while self.bits_in_buf <= 56 && self.byte_pos < self.bytes.len() {
                self.buf |= (self.bytes[self.byte_pos] as u64) << (56 - self.bits_in_buf);
                self.byte_pos += 1;
                self.bits_in_buf += 8;
            }
        }
    }

    /// Read a single bit as bool.
    #[inline(always)]
    pub fn read_bit(&mut self) -> Option<bool> {
        if self.bits_in_buf == 0 {
            self.refill();
            if self.bits_in_buf == 0 {
                return None;
            }
        }
        let bit = self.buf >> 63;
        self.buf <<= 1;
        self.bits_in_buf -= 1;
        if self.bits_in_buf <= 32 {
            self.refill();
        }
        Some(bit != 0)
    }

    /// Read up to 8 bits as u8.
    #[inline]
    pub fn read_u8(&mut self, n: u8) -> Option<u8> {
        debug_assert!(n <= 8);
        self.read_bits(n as usize).map(|v| v as u8)
    }

    /// Read up to 16 bits as u16.
    #[inline]
    pub fn read_u16(&mut self, n: u8) -> Option<u16> {
        debug_assert!(n <= 16);
        self.read_bits(n as usize).map(|v| v as u16)
    }

    /// Read up to 32 bits as u32.
    #[inline]
    pub fn read_u32(&mut self, n: u8) -> Option<u32> {
        debug_assert!(n <= 32);
        self.read_bits(n as usize).map(|v| v as u32)
    }

    /// Read up to 64 bits as u64.
    #[inline]
    pub fn read_u64(&mut self, n: u8) -> Option<u64> {
        debug_assert!(n <= 64);
        self.read_bits(n as usize)
    }

    /// Skip `n` bits.
    #[inline]
    pub fn skip(&mut self, n: usize) {
        let mut remaining = n;
        while remaining > 0 {
            if self.bits_in_buf == 0 {
                self.refill();
                if self.bits_in_buf == 0 {
                    return;
                }
            }
            let take = remaining.min(self.bits_in_buf as usize);
            self.buf <<= take;
            self.bits_in_buf -= take as u8;
            remaining -= take;
        }
    }

    /// Peek at the top `n` bits without consuming them (n ≤ 56).
    #[inline(always)]
    pub fn peek(&mut self, n: u8) -> Option<u64> {
        debug_assert!(n <= 56);
        if self.bits_in_buf < n {
            self.refill();
            if self.bits_in_buf < n {
                return None;
            }
        }
        Some(self.buf >> (64 - n))
    }

    /// Consume `n` bits (after a peek).
    #[inline(always)]
    pub fn consume(&mut self, n: u8) {
        self.buf <<= n;
        self.bits_in_buf -= n;
    }

    /// Read `n` bits (up to 57) as u64, MSB first.
    /// Uses the 64-bit buffer for bulk extraction.
    #[inline(always)]
    fn read_bits(&mut self, n: usize) -> Option<u64> {
        debug_assert!(n <= 57);
        if self.bits_in_buf < n as u8 {
            self.refill();
            if (self.bits_in_buf as usize) < n {
                return None;
            }
        }
        let val = self.buf >> (64 - n);
        self.buf <<= n;
        self.bits_in_buf -= n as u8;
        if self.bits_in_buf <= 32 {
            self.refill();
        }
        Some(val)
    }
}

impl<'a> Iterator for BitReader<'a> {
    type Item = bool;

    #[inline]
    fn next(&mut self) -> Option<bool> {
        self.read_bit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_byte_aligned() {
        let data = [0b10110010, 0b01010101];
        let mut r = BitReader::new(&data);
        assert_eq!(r.read_u8(4), Some(0b1011));
        assert_eq!(r.read_u8(4), Some(0b0010));
        assert_eq!(r.read_u8(8), Some(0b01010101));
        assert_eq!(r.read_bit(), None);
    }

    #[test]
    fn read_cross_byte() {
        let data = [0xFF, 0x00];
        let mut r = BitReader::new(&data);
        assert_eq!(r.read_u16(12), Some(0xFF0));
    }

    #[test]
    fn from_bit_offset() {
        let data = [0b10110010, 0b01010101];
        let mut r = BitReader::from_bit_offset(&data, 4);
        assert_eq!(r.read_u8(4), Some(0b0010));
    }

    #[test]
    fn peek_and_consume() {
        let data = [0b11001010, 0b11110000];
        let mut r = BitReader::new(&data);
        assert_eq!(r.peek(8), Some(0b11001010));
        assert_eq!(r.peek(4), Some(0b1100)); // peek again, same bits
        r.consume(4);
        assert_eq!(r.peek(4), Some(0b1010));
        r.consume(4);
        assert_eq!(r.read_u8(8), Some(0b11110000));
    }
}
