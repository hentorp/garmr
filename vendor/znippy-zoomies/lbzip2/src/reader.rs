//! Streaming parallel bzip2 decompressor implementing `Read`.
//!
//! Reads compressed data in ~100 MB chunks from any `Read` source,
//! finds block boundaries per chunk, decodes all complete blocks in
//! parallel, and streams decompressed output via the `Read` trait.
//!
//! Pipeline: disk I/O → 100 MB chunk → scan blocks → N-worker decode → XML out
//! Reading the next chunk overlaps with consuming the current decoded output.

use std::io::{self, Read};

use crate::bitreader::BitReader;
use crate::block::{self, BlockError};
use crate::block_scan;

/// Size of compressed data read per cycle.
/// 100 MB compressed ≈ 100-150 bzip2 blocks ≈ 800-1000 MB decompressed.
const CHUNK_BYTES: usize = 100 * 1024 * 1024;

/// A streaming parallel bzip2 decompressor.
///
/// Reads compressed data from `R` in ~100 MB chunks, parallel-decodes
/// bzip2 blocks within each chunk, and serves decompressed output via `Read`.
///
/// ```ignore
/// let file = std::fs::File::open("planet.osm.bz2")?;
/// let reader = StreamingBz2Read::new(file)?;
/// // reader implements Read — feeds decompressed XML
/// ```
pub struct StreamingBz2Read<R: Read> {
    source: R,
    max_blocksize: u32,
    /// Compressed data buffer — accumulates until we have a full chunk.
    comp_buf: Vec<u8>,
    /// Decompressed output waiting to be consumed via read().
    out_buf: Vec<u8>,
    out_pos: usize,
    /// Source is exhausted.
    source_eof: bool,
}

impl<R: Read> StreamingBz2Read<R> {
    /// Create a streaming parallel decompressor.
    ///
    /// Reads the 4-byte bzip2 header immediately to validate the stream.
    pub fn new(mut source: R) -> Result<Self, BlockError> {
        let mut header = [0u8; 4];
        source
            .read_exact(&mut header)
            .map_err(|_| BlockError("failed to read bzip2 header"))?;

        if &header[..2] != b"BZ" {
            return Err(BlockError("bad bzip2 signature"));
        }
        if header[2] != b'h' {
            return Err(BlockError("only huffman bzip2 supported"));
        }
        let level = header[3];
        if !(b'1'..=b'9').contains(&level) {
            return Err(BlockError("invalid bzip2 block size level"));
        }
        let max_blocksize = 100_000 * (level - b'0') as u32;

        // Seed comp_buf with header (block_scan skips it, but BitReader
        // needs correct byte offsets for the first block).
        let mut comp_buf = Vec::with_capacity(CHUNK_BYTES + 1024 * 1024);
        comp_buf.extend_from_slice(&header);

        Ok(Self {
            source,
            max_blocksize,
            comp_buf,
            out_buf: Vec::new(),
            out_pos: 0,
            source_eof: false,
        })
    }

    /// Read a chunk of compressed data from source, find complete blocks,
    /// decode them in parallel, buffer the decompressed output.
    fn fill(&mut self) -> io::Result<()> {
        if self.source_eof && self.comp_buf.len() <= 4 {
            // Nothing left to decode
            self.out_buf.clear();
            self.out_pos = 0;
            return Ok(());
        }

        // ── Read ~CHUNK_BYTES of compressed data ────────────────────────
        if !self.source_eof {
            let old_len = self.comp_buf.len();
            let target = old_len + CHUNK_BYTES;
            self.comp_buf.resize(target, 0);

            let mut filled = 0;
            while filled < CHUNK_BYTES {
                match self
                    .source
                    .read(&mut self.comp_buf[old_len + filled..target])
                {
                    Ok(0) => {
                        self.source_eof = true;
                        break;
                    }
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            self.comp_buf.truncate(old_len + filled);
        }

        // ── Find block boundaries in the buffer ─────────────────────────
        // Parallel bit-scan across cores (splits the buffer, merges + dedups to
        // the identical boundary set as the serial `find_all_blocks`) so the
        // whole-stream magic walk doesn't run as a 1-core serial prefix.
        let n_threads = gatling::gatling_forkjoin::default_workers();
        let boundaries = block_scan::find_all_blocks_parallel(&self.comp_buf, n_threads);

        if boundaries.is_empty() {
            if self.source_eof {
                // No more blocks, we're done
                self.comp_buf.clear();
                self.out_buf.clear();
                self.out_pos = 0;
            }
            return Ok(());
        }

        // If source is NOT eof, skip the last block (might be incomplete —
        // its data could extend into the next chunk).
        // If source IS eof, decode all blocks (everything is in memory).
        let decode_count = if self.source_eof {
            boundaries.len()
        } else if boundaries.len() > 1 {
            boundaries.len() - 1
        } else {
            // Only 1 block found and not eof — need more data.
            // The block might span into next chunk.
            return Ok(());
        };

        let decode_boundaries = &boundaries[..decode_count];

        // ── Parallel decode ─────────────────────────────────────────────
        let comp_data: &[u8] = &self.comp_buf;
        let max_bs = self.max_blocksize;

        let results: Vec<Result<Vec<u8>, BlockError>> =
            gatling::gatling_forkjoin::gatling_for_each(decode_boundaries.len(), 0, |bi| {
                let boundary = &decode_boundaries[bi];
                let bit_after_magic = boundary.bit_offset + 48;
                let mut reader = BitReader::from_bit_offset(comp_data, bit_after_magic as usize);
                block::decode_block(&mut reader, max_bs)
            });

        // ── Assemble decompressed output ────────────────────────────────
        self.out_buf.clear();
        self.out_pos = 0;
        for r in results {
            let decoded = r.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.0))?;
            self.out_buf.extend_from_slice(&decoded);
        }

        // ── Drain decoded portion from comp_buf ─────────────────────────
        // Keep everything from the last undecoded block boundary onward.
        if decode_count < boundaries.len() {
            let keep_from_byte = boundaries[decode_count].byte_offset();
            let remaining = self.comp_buf[keep_from_byte..].to_vec();
            self.comp_buf.clear();
            self.comp_buf.extend_from_slice(&remaining);
        } else {
            self.comp_buf.clear();
        }

        Ok(())
    }
}

impl<R: Read> Read for StreamingBz2Read<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Serve from output buffer if available
        if self.out_pos < self.out_buf.len() {
            let available = &self.out_buf[self.out_pos..];
            let n = buf.len().min(available.len());
            buf[..n].copy_from_slice(&available[..n]);
            self.out_pos += n;
            return Ok(n);
        }

        // Need more data — decode next chunk
        self.fill()?;

        if self.out_buf.is_empty() {
            return Ok(0); // EOF
        }

        let available = &self.out_buf[self.out_pos..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.out_pos += n;
        Ok(n)
    }
}

// Keep the mmap-based reader for benchmarks and in-memory use cases.

/// A parallel bzip2 decompressor over a byte slice (e.g. mmap'd file).
///
/// Scans all block boundaries up front, decodes in parallel batches.
/// For streaming from disk, use `StreamingBz2Read` instead.
pub struct ParallelBz2Read<'a> {
    data: &'a [u8],
    max_blocksize: u32,
    boundaries: Vec<block_scan::BlockBoundary>,
    next_block: usize,
    buf: Vec<u8>,
    buf_pos: usize,
}

/// Number of blocks to decode per parallel batch (mmap reader).
const BATCH_SIZE: usize = 64;

impl<'a> ParallelBz2Read<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, BlockError> {
        if data.len() < 4 {
            return Err(BlockError("input too short for bzip2 header"));
        }
        if &data[..2] != b"BZ" {
            return Err(BlockError("bad bzip2 signature"));
        }
        if data[2] != b'h' {
            return Err(BlockError("only huffman bzip2 supported"));
        }
        let level = data[3];
        if !(b'1'..=b'9').contains(&level) {
            return Err(BlockError("invalid bzip2 block size level"));
        }
        let max_blocksize = 100_000 * (level - b'0') as u32;

        // Parallel bit-scan (same boundary set as serial `find_all_blocks`, just
        // split across cores) instead of a 1-core serial walk of the whole mmap.
        let n_threads = gatling::gatling_forkjoin::default_workers();
        let boundaries = block_scan::find_all_blocks_parallel(data, n_threads);

        Ok(Self {
            data,
            max_blocksize,
            boundaries,
            next_block: 0,
            buf: Vec::new(),
            buf_pos: 0,
        })
    }

    pub fn block_count(&self) -> usize {
        self.boundaries.len()
    }

    fn fill_batch(&mut self) -> io::Result<()> {
        let remaining = self.boundaries.len() - self.next_block;
        if remaining == 0 {
            self.buf.clear();
            self.buf_pos = 0;
            return Ok(());
        }

        let batch_end = self.next_block + remaining.min(BATCH_SIZE);
        let batch = &self.boundaries[self.next_block..batch_end];
        let data = self.data;
        let max_bs = self.max_blocksize;

        let results: Vec<Result<Vec<u8>, BlockError>> =
            gatling::gatling_forkjoin::gatling_for_each(batch.len(), 0, |bi| {
                let boundary = &batch[bi];
                let bit_after_magic = boundary.bit_offset + 48;
                let mut reader = BitReader::from_bit_offset(data, bit_after_magic as usize);
                block::decode_block(&mut reader, max_bs)
            });

        let mut total = 0usize;
        for r in &results {
            match r {
                Ok(v) => total += v.len(),
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.0)),
            }
        }

        self.buf.clear();
        self.buf.reserve(total);
        for r in results {
            self.buf.extend_from_slice(
                &r.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.0))?,
            );
        }

        self.buf_pos = 0;
        self.next_block = batch_end;
        Ok(())
    }
}

impl Read for ParallelBz2Read<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.buf_pos >= self.buf.len() {
            self.fill_batch()?;
            if self.buf.is_empty() {
                return Ok(0);
            }
        }

        let available = &self.buf[self.buf_pos..];
        let n = buf.len().min(available.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.buf_pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_hello() {
        let compressed = include_bytes!("../test_data/hello.bz2");
        let cursor = io::Cursor::new(compressed.as_slice());
        let mut reader = StreamingBz2Read::new(cursor).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(&output, b"Hello, World!\n");
    }

    #[test]
    fn streaming_liechtenstein() {
        let compressed = include_bytes!("../test_data/liechtenstein.osm.bz2");
        let cursor = io::Cursor::new(compressed.as_slice());
        let mut reader = StreamingBz2Read::new(cursor).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();

        let sequential = crate::stream::decompress(compressed).unwrap();
        assert_eq!(output.len(), sequential.len());
        assert_eq!(output, sequential);
    }

    #[test]
    fn streaming_incremental() {
        let compressed = include_bytes!("../test_data/liechtenstein.osm.bz2");
        let cursor = io::Cursor::new(compressed.as_slice());
        let mut reader = StreamingBz2Read::new(cursor).unwrap();

        let mut output = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            output.extend_from_slice(&buf[..n]);
        }

        let sequential = crate::stream::decompress(compressed).unwrap();
        assert_eq!(output, sequential);
    }

    #[test]
    fn mmap_hello() {
        let compressed = include_bytes!("../test_data/hello.bz2");
        let mut reader = ParallelBz2Read::new(compressed).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(&output, b"Hello, World!\n");
    }

    #[test]
    fn mmap_liechtenstein() {
        let compressed = include_bytes!("../test_data/liechtenstein.osm.bz2");
        let mut reader = ParallelBz2Read::new(compressed).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();

        let sequential = crate::stream::decompress(compressed).unwrap();
        assert_eq!(output, sequential);
    }
}
