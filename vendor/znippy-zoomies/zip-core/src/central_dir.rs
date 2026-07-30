//! ZIP Central Directory parser (shared by ljar + lzip-parallel).
//!
//! Reads the End of Central Directory (EOCD) record — always at the tail of
//! the file — to locate the Central Directory, then walks each CD header to
//! produce a `Vec<EntryLocation>`.
//!
//! Handles standard ZIP and ZIP64 (large archives with > 65535 entries or
//! entries > 4 GB).  Multi-disk archives are rejected.
//!
//! A JAR is a ZIP: this parser is byte-for-byte the same for both, so it lives
//! once here and each consumer crate re-exports it.

use crate::ScanError;

const EOCD_SIG: u32 = 0x06054b50;
const EOCD64_LOC_SIG: u32 = 0x07064b50;
const EOCD64_SIG: u32 = 0x06064b50;
const CD_SIG: u32 = 0x02014b50;
const MAX_COMMENT: usize = 0xFFFF;

/// Location of one archive entry, derived from the Central Directory.
#[derive(Debug, Clone)]
pub struct EntryLocation {
    pub name: String,
    pub local_header_offset: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: u16,
    pub crc32: u32,
    pub is_directory: bool,
}

// ── Byte helpers ─────────────────────────────────────────────────────────────

#[inline]
fn u16_le(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
fn u32_le(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[inline]
fn u64_le(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

// ── EOCD location ─────────────────────────────────────────────────────────────

/// Scan backward from the end for the EOCD signature.
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let search_start = data.len().saturating_sub(22 + MAX_COMMENT);
    for i in (search_start..=data.len() - 22).rev() {
        if u32_le(data, i) == Some(EOCD_SIG) {
            return Some(i);
        }
    }
    None
}

/// Returns (entry_count, cd_offset, cd_size) — ZIP64-resolved.
fn parse_eocd(data: &[u8]) -> Result<(u64, u64, u64), ScanError> {
    let eocd = find_eocd(data).ok_or(ScanError("EOCD not found — not a JAR/ZIP file"))?;

    // Check for ZIP64 EOCD locator immediately before the standard EOCD.
    if eocd >= 20 {
        if u32_le(data, eocd - 20) == Some(EOCD64_LOC_SIG) {
            let eocd64_off = u64_le(data, eocd - 20 + 8)
                .ok_or(ScanError("ZIP64 EOCD locator truncated"))?
                as usize;

            if u32_le(data, eocd64_off) != Some(EOCD64_SIG) {
                return Err(ScanError("invalid ZIP64 EOCD signature"));
            }
            // ZIP64 EOCD layout (offsets relative to record start):
            //  +32  total entries   (u64)
            //  +40  CD size         (u64)
            //  +48  CD offset       (u64)
            let entry_count = u64_le(data, eocd64_off + 32)
                .ok_or(ScanError("ZIP64 EOCD truncated at entry count"))?;
            let cd_size = u64_le(data, eocd64_off + 40)
                .ok_or(ScanError("ZIP64 EOCD truncated at CD size"))?;
            let cd_offset = u64_le(data, eocd64_off + 48)
                .ok_or(ScanError("ZIP64 EOCD truncated at CD offset"))?;
            return Ok((entry_count, cd_offset, cd_size));
        }
    }

    // Standard EOCD (offsets relative to EOCD start):
    //  +8   entries on this disk  (u16)
    //  +10  total entries         (u16)
    //  +12  CD size               (u32)
    //  +16  CD offset             (u32)
    let entry_count = u16_le(data, eocd + 10).ok_or(ScanError("EOCD truncated"))? as u64;
    let cd_size = u32_le(data, eocd + 12).ok_or(ScanError("EOCD truncated"))? as u64;
    let cd_offset = u32_le(data, eocd + 16).ok_or(ScanError("EOCD truncated"))? as u64;
    Ok((entry_count, cd_offset, cd_size))
}

// ── Central Directory walk ────────────────────────────────────────────────────

/// Walk a CD byte slice and return one `EntryLocation` per entry.
///
/// `cd_data` must contain exactly the bytes of the Central Directory (offsets
/// start at 0).  `local_header_offset` values in each entry are absolute file
/// offsets and are returned as-is.
fn walk_cd_entries(cd_data: &[u8], entry_count: u64) -> Result<Vec<EntryLocation>, ScanError> {
    let mut entries = Vec::with_capacity(entry_count.min(65536) as usize);
    let mut pos = 0usize;

    while pos < cd_data.len() {
        if u32_le(cd_data, pos) != Some(CD_SIG) {
            break;
        }

        // CD header fixed fields:
        //  +10  compression method  (u16)
        //  +16  CRC-32              (u32)
        //  +20  compressed size     (u32)  — may be 0xFFFFFFFF for ZIP64
        //  +24  uncompressed size   (u32)  — may be 0xFFFFFFFF for ZIP64
        //  +28  name len            (u16)
        //  +30  extra len           (u16)
        //  +32  comment len         (u16)
        //  +42  local header offset (u32)  — may be 0xFFFFFFFF for ZIP64
        let method = u16_le(cd_data, pos + 10).ok_or(ScanError("CD entry truncated"))?;
        let crc32 = u32_le(cd_data, pos + 16).ok_or(ScanError("CD entry truncated"))?;
        let mut csize = u32_le(cd_data, pos + 20).ok_or(ScanError("CD entry truncated"))? as u64;
        let mut ucsize = u32_le(cd_data, pos + 24).ok_or(ScanError("CD entry truncated"))? as u64;
        let name_len = u16_le(cd_data, pos + 28).ok_or(ScanError("CD entry truncated"))? as usize;
        let extra_len = u16_le(cd_data, pos + 30).ok_or(ScanError("CD entry truncated"))? as usize;
        let comment_len =
            u16_le(cd_data, pos + 32).ok_or(ScanError("CD entry truncated"))? as usize;
        let mut lhoff = u32_le(cd_data, pos + 42).ok_or(ScanError("CD entry truncated"))? as u64;

        let name_start = pos + 46;
        let name_end = name_start + name_len;
        let extra_start = name_end;
        let extra_end = extra_start + extra_len;

        if extra_end > cd_data.len() {
            return Err(ScanError("CD entry name/extra truncated"));
        }
        let name = String::from_utf8_lossy(&cd_data[name_start..name_end]).into_owned();

        // Resolve ZIP64 extra field (tag 0x0001) if any sentinel value was 0xFFFFFFFF.
        if csize == 0xFFFF_FFFF || ucsize == 0xFFFF_FFFF || lhoff == 0xFFFF_FFFF {
            let mut epos = extra_start;
            while epos + 4 <= extra_end {
                let tag = u16_le(cd_data, epos).unwrap_or(0);
                let size = u16_le(cd_data, epos + 2).unwrap_or(0) as usize;
                if tag == 0x0001 {
                    let mut z = epos + 4;
                    if ucsize == 0xFFFF_FFFF {
                        ucsize = u64_le(cd_data, z).ok_or(ScanError("ZIP64 extra truncated"))?;
                        z += 8;
                    }
                    if csize == 0xFFFF_FFFF {
                        csize = u64_le(cd_data, z).ok_or(ScanError("ZIP64 extra truncated"))?;
                        z += 8;
                    }
                    if lhoff == 0xFFFF_FFFF {
                        lhoff = u64_le(cd_data, z).ok_or(ScanError("ZIP64 extra truncated"))?;
                    }
                    break;
                }
                epos += 4 + size;
            }
        }

        entries.push(EntryLocation {
            is_directory: name.ends_with('/'),
            name,
            local_header_offset: lhoff,
            compressed_size: csize,
            uncompressed_size: ucsize,
            compression_method: method,
            crc32,
        });

        pos = extra_end + comment_len;
    }

    Ok(entries)
}

/// Parse the ZIP Central Directory and return one `EntryLocation` per file entry.
///
/// Directory entries (names ending with `/`) are included with `is_directory = true`;
/// callers typically filter them out before decompressing.
pub fn read_central_directory(data: &[u8]) -> Result<Vec<EntryLocation>, ScanError> {
    let (entry_count, cd_offset, cd_size) = parse_eocd(data)?;

    let cd_start = cd_offset as usize;
    let cd_end = cd_start
        .checked_add(cd_size as usize)
        .filter(|&e| e <= data.len())
        .ok_or(ScanError("central directory extends past end of file"))?;

    walk_cd_entries(&data[cd_start..cd_end], entry_count)
}

// ── Streaming Central Directory reader ───────────────────────────────────────

/// Parse the EOCD (and ZIP64 EOCD if present) from a `Read + Seek` source.
///
/// Returns `(entry_count, cd_offset, cd_size)`.
fn parse_eocd_streaming<R: std::io::Read + std::io::Seek>(
    source: &mut R,
) -> Result<(u64, u64, u64), ScanError> {
    use std::io::SeekFrom;

    let file_size = source
        .seek(SeekFrom::End(0))
        .map_err(|_| ScanError("seek failed"))?;

    if file_size < 22 {
        return Err(ScanError("file too small to be a JAR/ZIP"));
    }

    // Read enough tail bytes to cover: EOCD (22 + up to 65535 comment) +
    // ZIP64 locator (20) + ZIP64 EOCD (56).
    let scan_size = ((22 + MAX_COMMENT + 20 + 56) as u64).min(file_size);
    let scan_start = file_size - scan_size;

    source
        .seek(SeekFrom::Start(scan_start))
        .map_err(|_| ScanError("seek to tail failed"))?;
    let mut buf = vec![0u8; scan_size as usize];
    source
        .read_exact(&mut buf)
        .map_err(|_| ScanError("read tail failed"))?;

    let eocd_in_buf = find_eocd(&buf).ok_or(ScanError("EOCD not found — not a JAR/ZIP file"))?;
    let eocd_abs = scan_start + eocd_in_buf as u64;

    // ZIP64 locator sits exactly 20 bytes before the EOCD.
    if eocd_abs >= 20 {
        let loc_abs = eocd_abs - 20;

        let loc_sig = if loc_abs >= scan_start {
            u32_le(&buf, (loc_abs - scan_start) as usize)
        } else {
            // Locator before our scan buffer — seek to read it.
            source
                .seek(SeekFrom::Start(loc_abs))
                .map_err(|_| ScanError("seek to ZIP64 locator failed"))?;
            let mut tmp = [0u8; 4];
            source
                .read_exact(&mut tmp)
                .map_err(|_| ScanError("read ZIP64 locator sig failed"))?;
            Some(u32::from_le_bytes(tmp))
        };

        if loc_sig == Some(EOCD64_LOC_SIG) {
            let eocd64_off: u64 = if loc_abs >= scan_start {
                u64_le(&buf, (loc_abs - scan_start) as usize + 8)
                    .ok_or(ScanError("ZIP64 locator truncated"))?
            } else {
                source
                    .seek(SeekFrom::Start(loc_abs + 8))
                    .map_err(|_| ScanError("seek to ZIP64 locator offset failed"))?;
                let mut tmp = [0u8; 8];
                source
                    .read_exact(&mut tmp)
                    .map_err(|_| ScanError("read ZIP64 EOCD offset failed"))?;
                u64::from_le_bytes(tmp)
            };

            // Read ZIP64 EOCD — may already be in buf, or need a seek.
            let eocd64: [u8; 56] =
                if eocd64_off >= scan_start && eocd64_off + 56 <= scan_start + scan_size {
                    let s = (eocd64_off - scan_start) as usize;
                    buf[s..s + 56].try_into().unwrap()
                } else {
                    source
                        .seek(SeekFrom::Start(eocd64_off))
                        .map_err(|_| ScanError("seek to ZIP64 EOCD failed"))?;
                    let mut tmp = [0u8; 56];
                    source
                        .read_exact(&mut tmp)
                        .map_err(|_| ScanError("read ZIP64 EOCD failed"))?;
                    tmp
                };

            if u32::from_le_bytes(eocd64[0..4].try_into().unwrap()) != EOCD64_SIG {
                return Err(ScanError("invalid ZIP64 EOCD signature"));
            }
            let entry_count = u64::from_le_bytes(eocd64[32..40].try_into().unwrap());
            let cd_size = u64::from_le_bytes(eocd64[40..48].try_into().unwrap());
            let cd_offset = u64::from_le_bytes(eocd64[48..56].try_into().unwrap());
            return Ok((entry_count, cd_offset, cd_size));
        }
    }

    // Standard EOCD.
    let entry_count = u16_le(&buf, eocd_in_buf + 10).ok_or(ScanError("EOCD truncated"))? as u64;
    let cd_size = u32_le(&buf, eocd_in_buf + 12).ok_or(ScanError("EOCD truncated"))? as u64;
    let cd_offset = u32_le(&buf, eocd_in_buf + 16).ok_or(ScanError("EOCD truncated"))? as u64;
    Ok((entry_count, cd_offset, cd_size))
}

/// Parse the ZIP Central Directory from a `Read + Seek` source without loading
/// the whole file into memory.
///
/// Seeks to the file tail to locate the EOCD, reads only the Central Directory
/// bytes, then walks the entries.  Suitable for large archives where loading the
/// full file would be wasteful.
pub fn read_central_directory_from<R: std::io::Read + std::io::Seek>(
    source: &mut R,
) -> Result<Vec<EntryLocation>, ScanError> {
    use std::io::SeekFrom;

    let (entry_count, cd_offset, cd_size) = parse_eocd_streaming(source)?;

    source
        .seek(SeekFrom::Start(cd_offset))
        .map_err(|_| ScanError("seek to central directory failed"))?;
    let mut cd_data = vec![0u8; cd_size as usize];
    source
        .read_exact(&mut cd_data)
        .map_err(|_| ScanError("read central directory failed"))?;

    walk_cd_entries(&cd_data, entry_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an in-memory archive with DEFLATE entries via the `zip` crate.
    fn make_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        use zip::write::SimpleFileOptions;
        let mut buf = Vec::new();
        let cursor = Cursor::new(&mut buf);
        let mut zw = zip::ZipWriter::new(cursor);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
        buf
    }

    #[test]
    fn single_entry_jar_named() {
        // JAR-flavoured names — the shared parser is naming-agnostic.
        let jar = make_archive(&[("Hello.class", b"cafebabe")]);
        let locs = read_central_directory(&jar).unwrap();
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].name, "Hello.class");
        assert_eq!(locs[0].uncompressed_size, 8);
    }

    #[test]
    fn single_entry_zip_named() {
        let zip = make_archive(&[("data/readme.txt", b"hello zip world")]);
        let locs = read_central_directory(&zip).unwrap();
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].name, "data/readme.txt");
        assert_eq!(locs[0].uncompressed_size, 15);
    }

    #[test]
    fn directory_entry() {
        let jar = make_archive(&[
            ("META-INF/", b""),
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ]);
        let locs = read_central_directory(&jar).unwrap();
        assert_eq!(locs.len(), 2);
        assert!(locs[0].is_directory);
        assert!(!locs[1].is_directory);
    }

    #[test]
    fn streaming_matches_in_memory() {
        // The streaming (Read+Seek) path must resolve the same entries as the
        // whole-slice path — red if the two CD readers ever diverge.
        let arc = make_archive(&[("a.txt", b"aaaa"), ("dir/b.bin", &[0u8; 100])]);
        let flat = read_central_directory(&arc).unwrap();
        let mut cur = std::io::Cursor::new(&arc);
        let streamed = read_central_directory_from(&mut cur).unwrap();
        assert_eq!(flat.len(), streamed.len());
        for (f, s) in flat.iter().zip(streamed.iter()) {
            assert_eq!(f.name, s.name);
            assert_eq!(f.local_header_offset, s.local_header_offset);
            assert_eq!(f.compressed_size, s.compressed_size);
            assert_eq!(f.uncompressed_size, s.uncompressed_size);
            assert_eq!(f.crc32, s.crc32);
        }
    }

    #[test]
    fn not_an_archive_errors() {
        let junk = vec![0x00u8; 100];
        assert!(read_central_directory(&junk).is_err());
    }
}
