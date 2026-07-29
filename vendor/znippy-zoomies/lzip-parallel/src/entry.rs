//! ZIP entry decompressor.
//!
//! Decompresses a single ZIP entry given the file data and an `EntryLocation`
//! from the Central Directory.  Supports STORE (method 0) and DEFLATE (method 8).
//!
//! Designed for parallel use: each worker gets the full `data` slice (read-only)
//! plus its own `EntryLocation`, decompresses independently, returns `Vec<u8>`.

use std::borrow::Cow;

use crate::central_dir::EntryLocation;

const LOCAL_HEADER_SIG: u32 = 0x04034b50;

#[derive(Debug)]
pub struct ZipError(pub &'static str);

impl std::fmt::Display for ZipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZIP error: {}", self.0)
    }
}

impl std::error::Error for ZipError {}

/// The shared `zip_core` Central Directory parser reports `ScanError`; lzip's
/// public error surface is `ZipError`, so `?` converts through here.
impl From<zip_core::ScanError> for ZipError {
    fn from(e: zip_core::ScanError) -> Self {
        ZipError(e.0)
    }
}

pub struct ZipEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Decompress one ZIP entry.
///
/// `data` is the full ZIP file bytes.  `loc` comes from the Central Directory.
/// We read name/extra lengths from the local file header to locate the compressed
/// data, then use the CD's already-resolved `compressed_size` (ZIP64-aware).
pub fn decompress_entry(data: &[u8], loc: &EntryLocation) -> Result<Vec<u8>, ZipError> {
    let compressed = locate_compressed(data, loc)?;
    decompress_entry_raw(
        compressed,
        loc.compression_method,
        loc.uncompressed_size as usize,
    )
}

/// Borrowing decode: same as `decompress_entry` but returns `Cow` so that
/// STORE entries (method 0) borrow directly from `data` instead of copying.
///
/// The returned `Cow::Borrowed` aliases the input slice, so the caller must
/// keep `data` alive for the lifetime of the result (true for the in-memory
/// parallel/batch paths where the source buffer outlives the call). Avoids the
/// `.to_vec()` clone of already-stored bytes (.png, nested .jar, .so) — Law 1.
pub fn decompress_entry_cow<'a>(
    data: &'a [u8],
    loc: &EntryLocation,
) -> Result<Cow<'a, [u8]>, ZipError> {
    let compressed = locate_compressed(data, loc)?;
    decompress_entry_raw_cow(
        compressed,
        loc.compression_method,
        loc.uncompressed_size as usize,
    )
}

/// Locate the compressed-data slice of an entry within the full ZIP `data`.
///
/// Reads name/extra lengths from the LOCAL header (which can differ from the
/// Central Directory) to find where the compressed bytes start, then uses the
/// CD's ZIP64-resolved `compressed_size` for the length.
fn locate_compressed<'a>(data: &'a [u8], loc: &EntryLocation) -> Result<&'a [u8], ZipError> {
    let hdr = loc.local_header_offset as usize;

    let sig = data
        .get(hdr..hdr + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ZipError("local file header out of bounds"))?;
    if sig != LOCAL_HEADER_SIG {
        return Err(ZipError("invalid local file header signature"));
    }

    // Name/extra lengths in the LOCAL header can differ from the CD — must read them here.
    let name_len = data
        .get(hdr + 26..hdr + 28)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ZipError("local header truncated at name len"))? as usize;

    let extra_len = data
        .get(hdr + 28..hdr + 30)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ZipError("local header truncated at extra len"))? as usize;

    let data_start = hdr + 30 + name_len + extra_len;
    let data_end = data_start + loc.compressed_size as usize;

    data.get(data_start..data_end)
        .ok_or(ZipError("compressed data out of bounds"))
}

/// Decompress pre-read compressed bytes using the given ZIP compression method.
///
/// `expected_size` is the uncompressed size from the Central Directory (0 if unknown).
///
/// Used by the streaming reader which reads entry bytes into a buffer before
/// handing them to gatling workers — no full-file slice needed.
pub fn decompress_entry_raw(
    compressed: &[u8],
    method: u16,
    expected_size: usize,
) -> Result<Vec<u8>, ZipError> {
    match method {
        0 => Ok(compressed.to_vec()),
        8 => inflate_raw(compressed, expected_size),
        _ => Err(ZipError("unsupported compression method")),
    }
}

/// Borrowing variant of `decompress_entry_raw`: STORE (method 0) returns
/// `Cow::Borrowed(compressed)` — no copy — while DEFLATE returns `Cow::Owned`.
/// The borrow lives as long as the `compressed` slice the caller passed in.
pub fn decompress_entry_raw_cow(
    compressed: &[u8],
    method: u16,
    expected_size: usize,
) -> Result<Cow<'_, [u8]>, ZipError> {
    match method {
        0 => Ok(Cow::Borrowed(compressed)),
        8 => inflate_raw(compressed, expected_size).map(Cow::Owned),
        _ => Err(ZipError("unsupported compression method")),
    }
}

#[cfg(not(feature = "zlib-ng"))]
fn inflate_raw(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, ZipError> {
    let size = if expected_size > 0 {
        expected_size
    } else {
        (compressed.len() * 4).max(4096)
    };
    linflate::inflate_to_vec(compressed, size).map_err(|_| ZipError("DEFLATE decompression failed"))
}

#[cfg(feature = "zlib-ng")]
fn inflate_raw(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, ZipError> {
    use std::io::Read;
    let mut decoder = flate2::read::DeflateDecoder::new(compressed);
    let mut out = if expected_size > 0 {
        Vec::with_capacity(expected_size)
    } else {
        Vec::new()
    };
    decoder
        .read_to_end(&mut out)
        .map_err(|_| ZipError("DEFLATE decompression failed (zlib-ng)"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::central_dir::EntryLocation;

    /// Minimal STORE entry: "hello.txt" → "Hello, World!\n"
    #[rustfmt::skip]
    static HELLO_JAR: &[u8] = &[
        // Local file header
        0x50, 0x4B, 0x03, 0x04,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,         // CRC32 (not validated)
        0x0E, 0x00, 0x00, 0x00,         // compressed size: 14
        0x0E, 0x00, 0x00, 0x00,         // uncompressed size: 14
        0x09, 0x00,                     // name len: 9
        0x00, 0x00,                     // extra len: 0
        b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't',
        b'H', b'e', b'l', b'l', b'o', b',', b' ',
        b'W', b'o', b'r', b'l', b'd', b'!', b'\n',
    ];

    #[test]
    fn store_entry() {
        let loc = EntryLocation {
            name: "hello.txt".into(),
            local_header_offset: 0,
            compressed_size: 14,
            uncompressed_size: 14,
            compression_method: 0,
            crc32: 0,
            is_directory: false,
        };
        let out = decompress_entry(HELLO_JAR, &loc).unwrap();
        assert_eq!(out, b"Hello, World!\n");
    }
}
