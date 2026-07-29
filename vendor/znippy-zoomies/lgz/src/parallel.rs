//! Parallel gzip decompression.
//!
//! Strategy:
//! 1. Parse gzip header to locate the raw DEFLATE stream.
//! 2. If stream is large enough (> PARALLEL_THRESHOLD), scan for full-flush
//!    boundaries using SIMD-accelerated parallel search.
//! 3. If flush boundaries exist, decode segments in parallel via scoped threads.
//! 4. If no boundaries (standard gzip), fall back to single-threaded flate2.
//!
//! For streaming large files, the CLI binary uses the full ring-slot pipeline
//! (Reader → Main → Workers → Collector → Writer). The library API here
//! handles in-memory slices.

use std::io::Read;

use crate::PARALLEL_THRESHOLD;
use crate::chunk;

/// Error type for gzip decompression
#[derive(Debug)]
pub struct GzError(pub &'static str);

/// Sentinel message for "decompressed output exceeded the caller's `max_out`
/// cap". Callers (e.g. ingest paths) can match on this to degrade gracefully
/// instead of risking an unbounded allocation / OOM. Exposed as a constant so
/// the meaning is shared rather than string-matched ad hoc.
pub const OUTPUT_TOO_LARGE: &str = "decompressed output exceeds max_out cap";

/// Construct the canonical "output too large" error.
#[inline]
pub fn output_too_large() -> GzError {
    GzError(OUTPUT_TOO_LARGE)
}

impl std::fmt::Display for GzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lgz: {}", self.0)
    }
}

impl std::error::Error for GzError {}

/// Gzip header parsing result.
struct GzipHeader {
    /// Byte offset where the raw DEFLATE stream starts.
    deflate_start: usize,
}

/// Return the byte offset where the raw DEFLATE stream begins (just past the
/// gzip header). Lets callers strip the header and feed raw DEFLATE to the
/// chunk API (`split_chunk` / `decode_segment`).
pub fn deflate_offset(data: &[u8]) -> Result<usize, GzError> {
    Ok(parse_gzip_header(data)?.deflate_start)
}

/// Parse the gzip header and return the offset of the DEFLATE data.
///
/// Gzip format: 10-byte header + optional FEXTRA/FNAME/FCOMMENT/FHCRC fields.
fn parse_gzip_header(data: &[u8]) -> Result<GzipHeader, GzError> {
    if data.len() < 10 {
        return Err(GzError("input too short for gzip header"));
    }
    if data[0] != 0x1f || data[1] != 0x8b {
        return Err(GzError("not a gzip file (bad magic)"));
    }
    if data[2] != 0x08 {
        return Err(GzError("unsupported compression method (not DEFLATE)"));
    }

    let flags = data[3];
    let mut pos = 10;

    // FEXTRA
    if flags & 0x04 != 0 {
        if pos + 2 > data.len() {
            return Err(GzError("truncated FEXTRA"));
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
    }

    // FNAME (null-terminated)
    if flags & 0x08 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1; // skip null
    }

    // FCOMMENT (null-terminated)
    if flags & 0x10 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }

    // FHCRC (2-byte header CRC)
    if flags & 0x02 != 0 {
        pos += 2;
    }

    if pos >= data.len() {
        return Err(GzError("gzip header extends past input"));
    }

    Ok(GzipHeader { deflate_start: pos })
}

/// Decompress a gzip byte slice. Returns decompressed bytes.
///
/// Attempts parallel decompression for large inputs with flush boundaries.
/// Falls back to single-threaded flate2 for standard gzip streams.
pub fn decompress_gz(data: &[u8]) -> Result<Vec<u8>, GzError> {
    let header = parse_gzip_header(data)?;
    let deflate_data = &data[header.deflate_start..];

    // Strip the 8-byte gzip trailer (4 CRC32 + 4 ISIZE) from the DEFLATE stream
    let deflate_len = if deflate_data.len() > 8 {
        deflate_data.len() - 8
    } else {
        deflate_data.len()
    };
    let raw_deflate = &deflate_data[..deflate_len];

    // Try parallel path for large inputs
    if raw_deflate.len() >= PARALLEL_THRESHOLD {
        let n_workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        match chunk::decode_chunk(raw_deflate, n_workers, true) {
            Ok((output, _consumed)) => {
                // Verify the gzip trailer (CRC32 + ISIZE) against the parallel
                // output — the single-threaded flate2 fallback already checks
                // these, so the parallel path must too or corruption slips through.
                if deflate_data.len() >= 8 {
                    let trailer = &deflate_data[deflate_data.len() - 8..];
                    let expected_crc =
                        u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
                    let expected_isize =
                        u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
                    let mut crc = flate2::Crc::new();
                    crc.update(&output);
                    if crc.sum() != expected_crc || (output.len() as u32) != expected_isize {
                        return Err(GzError("gzip checksum mismatch"));
                    }
                }
                return Ok(output);
            }
            Err(_) => {
                // No flush boundaries found — fall through to single-threaded
            }
        }
    }

    // Single-threaded fallback (works for all valid gzip)
    decompress_gz_flate2(data)
}

/// Decompress a gzip byte slice with a hard output cap.
///
/// Returns the decompressed bytes, or [`GzError`] with message
/// [`OUTPUT_TOO_LARGE`] once the cumulative decompressed output would exceed
/// `max_out`. Unlike [`decompress_gz`], this **never** buffers the full output
/// of a decompression bomb: it streams the gzip output in bounded chunks and
/// bails as soon as the running total crosses the cap (peak allocation stays at
/// roughly `max_out` + one chunk), so an attacker-controlled, highly compressible
/// input yields an `Err` rather than an OOM abort.
///
/// This always uses the single-threaded streaming path; the cap is the point, so
/// the (uncapped) parallel fast path is intentionally not used here.
pub fn decompress_gz_capped(data: &[u8], max_out: usize) -> Result<Vec<u8>, GzError> {
    // Validate the header up front so a non-gzip input fails the same way the
    // uncapped path would (rather than as a generic read error).
    let _ = parse_gzip_header(data)?;
    let mut decoder = flate2::read::GzDecoder::new(data);
    read_capped(&mut decoder, max_out)
}

/// Read all of `reader` into a `Vec`, erroring with [`OUTPUT_TOO_LARGE`] once the
/// accumulated length would exceed `max_out`. Reads in bounded chunks so peak
/// memory stays near `max_out` even for a bomb input.
pub(crate) fn read_capped<R: Read>(reader: &mut R, max_out: usize) -> Result<Vec<u8>, GzError> {
    // Bounded read chunk — large enough to amortize syscalls/decode overhead,
    // small enough that overshoot past the cap is negligible.
    const CHUNK: usize = 64 * 1024;
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; CHUNK];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| GzError("gzip decompression failed"))?;
        if n == 0 {
            break;
        }
        if out.len() + n > max_out {
            return Err(output_too_large());
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// Decompress gzip into a pre-allocated buffer. Returns bytes written.
pub fn decompress_gz_into(data: &[u8], out: &mut [u8]) -> Result<usize, GzError> {
    let decompressed = decompress_gz(data)?;
    if decompressed.len() > out.len() {
        return Err(GzError("output buffer too small"));
    }
    out[..decompressed.len()].copy_from_slice(&decompressed);
    Ok(decompressed.len())
}

/// Decompress gzip from a reader (streaming). Returns all decompressed bytes.
///
/// For the streaming case, reads the full input then applies parallel decode.
pub fn decompress_gz_stream<R: Read>(mut reader: R) -> Result<Vec<u8>, GzError> {
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .map_err(|_| GzError("failed to read input"))?;
    decompress_gz(&data)
}

/// Single-threaded flate2 fallback.
fn decompress_gz_flate2(data: &[u8]) -> Result<Vec<u8>, GzError> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|_| GzError("gzip decompression failed"))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_gz(data: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Create a gzip stream with Z_FULL_FLUSH points (using flate2's flush API).
    fn make_gz_with_flushes(chunks: &[&[u8]]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        for (i, chunk) in chunks.iter().enumerate() {
            encoder.write_all(chunk).unwrap();
            if i < chunks.len() - 1 {
                // Z_FULL_FLUSH via flate2
                encoder.flush().unwrap();
            }
        }
        encoder.finish().unwrap()
    }

    #[test]
    fn roundtrip_basic() {
        let original = b"Hello, lgz! This is a test of parallel gzip decompression.";
        let compressed = make_gz(original);
        let decompressed = decompress_gz(&compressed).unwrap();
        assert_eq!(&decompressed, original);
    }

    #[test]
    fn roundtrip_large() {
        let original: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let compressed = make_gz(&original);
        let decompressed = decompress_gz(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn decompress_into_buffer() {
        let original = b"fixed size test";
        let compressed = make_gz(original);
        let mut buf = vec![0u8; 1024];
        let n = decompress_gz_into(&compressed, &mut buf).unwrap();
        assert_eq!(&buf[..n], original.as_slice());
    }

    #[test]
    fn invalid_data_returns_error() {
        let bad = b"not gzip at all";
        assert!(decompress_gz(bad).is_err());
    }

    #[test]
    fn stream_decompress() {
        let original = b"streaming test data for lgz";
        let compressed = make_gz(original);
        let decompressed = decompress_gz_stream(compressed.as_slice()).unwrap();
        assert_eq!(&decompressed, original);
    }

    #[test]
    fn parse_header_basic() {
        let compressed = make_gz(b"test");
        let header = parse_gzip_header(&compressed).unwrap();
        assert!(header.deflate_start >= 10);
        assert!(header.deflate_start < compressed.len());
    }

    #[test]
    fn capped_small_input_roundtrips() {
        let original = b"a normal, small payload that fits well under the cap";
        let compressed = make_gz(original);
        let out = decompress_gz_capped(&compressed, 1024).unwrap();
        assert_eq!(&out, original);
    }

    #[test]
    fn capped_bomb_errors_not_ooms() {
        // A few KB of zeros gzips to ~tens of bytes but expands well past a tiny
        // cap. The capped decoder must Err(OUTPUT_TOO_LARGE), never allocate the
        // full output.
        let bomb = make_gz(&vec![0u8; 256 * 1024]);
        assert!(
            bomb.len() < 1024,
            "zeros must compress tiny: {} bytes",
            bomb.len()
        );
        let err = decompress_gz_capped(&bomb, 4096).unwrap_err();
        assert_eq!(
            err.0, OUTPUT_TOO_LARGE,
            "expected the output-too-large sentinel"
        );
    }

    #[test]
    fn capped_exact_boundary_ok() {
        // Output exactly equal to the cap must succeed (cap is "exceeds", >).
        let original = vec![7u8; 4096];
        let compressed = make_gz(&original);
        let out = decompress_gz_capped(&compressed, 4096).unwrap();
        assert_eq!(out, original);
    }

    #[test]
    fn capped_invalid_data_errors() {
        assert!(decompress_gz_capped(b"not gzip at all", 1024).is_err());
    }

    #[test]
    fn roundtrip_with_flushes() {
        // Create data large enough to actually trigger parallel path
        let chunk_data: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        let chunks: Vec<&[u8]> = chunk_data.chunks(50_000).collect();
        let compressed = make_gz_with_flushes(&chunks);
        let decompressed = decompress_gz(&compressed).unwrap();
        assert_eq!(decompressed, chunk_data);
    }
}
