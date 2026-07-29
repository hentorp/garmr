//! JAR entry decompressor.
//!
//! Decompresses a single JAR entry given the file data and an `EntryLocation`
//! from the Central Directory.  Supports STORE (method 0) and DEFLATE (method 8).
//!
//! Designed for parallel use: each worker gets the full `data` slice (read-only)
//! plus its own `EntryLocation`, decompresses independently, returns `Vec<u8>`.

use std::borrow::Cow;

use crate::central_dir::EntryLocation;

const LOCAL_HEADER_SIG: u32 = 0x04034b50;

#[derive(Debug)]
pub struct JarError(pub &'static str);

impl std::fmt::Display for JarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JAR error: {}", self.0)
    }
}

impl std::error::Error for JarError {}

/// The shared `zip_core` Central Directory parser reports `ScanError`; ljar's
/// public error surface is `JarError`, so `?` converts through here.
impl From<zip_core::ScanError> for JarError {
    fn from(e: zip_core::ScanError) -> Self {
        JarError(e.0)
    }
}

pub struct JarEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Standard (reflected) CRC-32 table — polynomial 0xEDB88320, as used by ZIP.
const fn make_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC32_TABLE: [u32; 256] = make_crc32_table();

/// Compute the ZIP CRC-32 of `data`.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc = CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Validate decompressed `bytes` against the Central Directory's stored CRC-32.
fn verify_crc32(bytes: &[u8], expected_crc: u32) -> Result<(), JarError> {
    if crc32(bytes) != expected_crc {
        return Err(JarError("CRC32 mismatch"));
    }
    Ok(())
}

/// Decompress one JAR entry.
///
/// `data` is the full JAR file bytes.  `loc` comes from the Central Directory.
/// We read name/extra lengths from the local file header to locate the compressed
/// data, then use the CD's already-resolved `compressed_size` (ZIP64-aware).
pub fn decompress_entry(data: &[u8], loc: &EntryLocation) -> Result<Vec<u8>, JarError> {
    let hdr = loc.local_header_offset as usize;

    let sig = data
        .get(hdr..hdr + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(JarError("local file header out of bounds"))?;
    if sig != LOCAL_HEADER_SIG {
        return Err(JarError("invalid local file header signature"));
    }

    // Name/extra lengths in the LOCAL header can differ from the CD — must read them here.
    let name_len = data
        .get(hdr + 26..hdr + 28)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(JarError("local header truncated at name len"))? as usize;

    let extra_len = data
        .get(hdr + 28..hdr + 30)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(JarError("local header truncated at extra len"))? as usize;

    let data_start = hdr + 30 + name_len + extra_len;
    let data_end = data_start + loc.compressed_size as usize;

    let compressed = data
        .get(data_start..data_end)
        .ok_or(JarError("compressed data out of bounds"))?;

    decompress_entry_raw(
        compressed,
        loc.compression_method,
        loc.uncompressed_size as usize,
        loc.crc32,
    )
}

/// Decompress pre-read compressed bytes using the given ZIP compression method.
///
/// `expected_size` is the uncompressed size from the Central Directory (0 if unknown).
/// `expected_crc` is the Central Directory's CRC-32; the decompressed bytes are
/// validated against it and a mismatch is an error.
///
/// Used by the streaming reader which reads entry bytes into a buffer before
/// handing them to gatling workers — no full-file slice needed.
pub fn decompress_entry_raw(
    compressed: &[u8],
    method: u16,
    expected_size: usize,
    expected_crc: u32,
) -> Result<Vec<u8>, JarError> {
    let out = match method {
        0 => compressed.to_vec(),
        8 => inflate_raw(compressed, expected_size)?,
        _ => return Err(JarError("unsupported compression method")),
    };
    verify_crc32(&out, expected_crc)?;
    Ok(out)
}

/// Borrowing variant of [`decompress_entry_raw`].
///
/// For STORE (method 0) this returns `Cow::Borrowed` — the already-stored bytes
/// are handed back as a slice with no copy. DEFLATE (method 8) still allocates
/// (`Cow::Owned`). Callers whose backing `compressed` slice outlives the result
/// (e.g. the in-memory batch buffer in `batch.rs`) should prefer this to avoid
/// the needless `to_vec()` on stored entries. The streaming reader, which owns
/// per-entry buffers with no longer-lived backing slice, keeps using
/// `decompress_entry_raw`.
pub fn decompress_entry_raw_cow<'a>(
    compressed: &'a [u8],
    method: u16,
    expected_size: usize,
    expected_crc: u32,
) -> Result<Cow<'a, [u8]>, JarError> {
    match method {
        0 => {
            verify_crc32(compressed, expected_crc)?;
            Ok(Cow::Borrowed(compressed))
        }
        8 => {
            let out = inflate_raw(compressed, expected_size)?;
            verify_crc32(&out, expected_crc)?;
            Ok(Cow::Owned(out))
        }
        _ => Err(JarError("unsupported compression method")),
    }
}

#[cfg(not(feature = "zlib-ng"))]
fn inflate_raw(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, JarError> {
    let size = if expected_size > 0 {
        expected_size
    } else {
        (compressed.len() * 4).max(4096)
    };
    linflate::inflate_to_vec(compressed, size).map_err(|_| JarError("DEFLATE decompression failed"))
}

#[cfg(feature = "zlib-ng")]
fn inflate_raw(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, JarError> {
    use std::io::Read;
    let mut decoder = flate2::read::DeflateDecoder::new(compressed);
    let mut out = if expected_size > 0 {
        Vec::with_capacity(expected_size)
    } else {
        Vec::new()
    };
    decoder
        .read_to_end(&mut out)
        .map_err(|_| JarError("DEFLATE decompression failed (zlib-ng)"))?;
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
            crc32: 0xb4e8_9e84, // CRC-32 of "Hello, World!\n"
            is_directory: false,
        };
        let out = decompress_entry(HELLO_JAR, &loc).unwrap();
        assert_eq!(out, b"Hello, World!\n");
    }
}
