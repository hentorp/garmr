//! Batch parallel ZIP extraction pipeline.
//!
//! Reads multiple ZIP files into a ~200 MB buffer, resolves all entries
//! (Central Directory parse), then dispatches inflate work across N workers.
//! While workers inflate batch N, the reader fills the buffer with batch N+1.
//!
//! This amortises I/O, Central Directory parsing, and gatling dispatch overhead
//! across many ZIPs — achieving throughput that scales with core count.
//!
//! # Architecture
//!
//! ```text
//! Reader thread                        Worker pool (8 cores)
//! ────────────────                     ─────────────────────
//! read ZIP₁..ZIPₖ into buf            inflate entries from prev buf
//! parse CDs → entry list              write decompressed to disk
//! partition entries across workers     ↓
//!          ──── swap buffers ────→     receive new entry list
//! ```

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::central_dir::{self, EntryLocation};
use crate::entry::{self, ZipError};

/// Maximum buffer size for batching ZIP file data.
const CHUNK_BUFFER_SIZE: usize = 200 * 1024 * 1024; // 200 MB

/// A resolved entry: knows where its compressed data lives in the batch buffer.
#[derive(Clone)]
struct ResolvedEntry {
    /// Destination path relative to extraction root.
    dest_rel: PathBuf,
    /// Byte range in the batch buffer containing compressed data.
    buf_offset: usize,
    buf_len: usize,
    /// ZIP compression method (0=stored, 8=deflate).
    method: u16,
    /// Expected decompressed size (from Central Directory).
    uncompressed_size: u64,
}

/// Statistics returned after batch extraction.
#[derive(Debug, Default)]
pub struct BatchStats {
    pub zips_processed: usize,
    pub entries_extracted: usize,
    pub compressed_bytes_read: u64,
    pub decompressed_bytes_written: u64,
    pub elapsed_secs: f64,
}

impl BatchStats {
    pub fn throughput_mb_per_sec(&self) -> f64 {
        let mb = self.decompressed_bytes_written as f64 / (1024.0 * 1024.0);
        if self.elapsed_secs > 0.0 {
            mb / self.elapsed_secs
        } else {
            0.0
        }
    }
}

/// Extract multiple ZIP files in parallel using a pipelined batch approach.
///
/// Reads ZIPs into a large buffer, resolves entries, then inflates in parallel.
/// `dest` is the root output directory. Each ZIP's contents are extracted into
/// a subdirectory named after the ZIP file (without extension).
///
/// Returns extraction statistics.
pub fn extract_zips(zips: &[PathBuf], dest: &Path, flat: bool) -> Result<BatchStats, ZipError> {
    let t0 = std::time::Instant::now();
    let mut stats = BatchStats::default();

    // Process ZIPs in batches that fit in the buffer.
    let mut zip_idx = 0;
    while zip_idx < zips.len() {
        let (entries, buffer, zips_in_batch) = fill_buffer(&zips[zip_idx..], dest, flat)?;
        zip_idx += zips_in_batch;
        stats.zips_processed += zips_in_batch;

        // Parallel inflate + write
        let batch_stats = inflate_and_write(&entries, &buffer, dest)?;
        stats.entries_extracted += batch_stats.0;
        stats.decompressed_bytes_written += batch_stats.1;
        stats.compressed_bytes_read += buffer.len() as u64;
    }

    stats.elapsed_secs = t0.elapsed().as_secs_f64();
    Ok(stats)
}

/// Extract multiple ZIPs in-memory (no disk write). Returns all entries.
///
/// Used for benchmarking the decompression pipeline without I/O overhead.
pub fn decompress_zips(zips: &[PathBuf]) -> Result<(Vec<(String, Vec<u8>)>, BatchStats), ZipError> {
    let t0 = std::time::Instant::now();
    let mut stats = BatchStats::default();
    let mut all_entries = Vec::new();

    let mut zip_idx = 0;
    while zip_idx < zips.len() {
        let (entries, buffer, zips_in_batch) = fill_buffer_no_dest(&zips[zip_idx..])?;
        zip_idx += zips_in_batch;
        stats.zips_processed += zips_in_batch;

        // Parallel inflate (LPT / heaviest-first): weight each entry by its
        // uncompressed size so a fat entry among tiny ones can't strand one
        // core while the other 11 sit idle. Mirrors ljar's batch decode.
        let results: Vec<Result<(String, Vec<u8>), ZipError>> =
            gatling::gatling_forkjoin::gatling_for_each_balanced(
                entries.len(),
                0,
                1,
                |i| entries[i].uncompressed_size as u64,
                |i| {
                    let e = &entries[i];
                    let compressed = &buffer[e.buf_offset..e.buf_offset + e.buf_len];
                    let data = entry::decompress_entry_raw(
                        compressed,
                        e.method,
                        e.uncompressed_size as usize,
                    )?;
                    Ok((e.dest_rel.to_string_lossy().into_owned(), data))
                },
            );

        for r in results {
            let (name, data) = r?;
            stats.decompressed_bytes_written += data.len() as u64;
            all_entries.push((name, data));
        }
        stats.entries_extracted += entries.len();
        stats.compressed_bytes_read += buffer.len() as u64;
    }

    stats.elapsed_secs = t0.elapsed().as_secs_f64();
    Ok((all_entries, stats))
}

/// Fill the batch buffer with as many ZIPs as fit.
/// Returns (resolved_entries, buffer, num_zips_consumed).
fn fill_buffer(
    zips: &[PathBuf],
    _dest: &Path,
    flat: bool,
) -> Result<(Vec<ResolvedEntry>, Vec<u8>, usize), ZipError> {
    let mut buffer = Vec::with_capacity(CHUNK_BUFFER_SIZE);
    let mut entries = Vec::new();
    let mut zips_consumed = 0;

    for zip_path in zips {
        let file_size = fs::metadata(zip_path)
            .map_err(|_| ZipError("cannot stat ZIP file"))?
            .len() as usize;

        // If adding this ZIP would exceed buffer, stop (unless buffer is empty).
        if !buffer.is_empty() && buffer.len() + file_size > CHUNK_BUFFER_SIZE {
            break;
        }

        let buf_start = buffer.len();

        // Read entire ZIP into buffer.
        let mut f = fs::File::open(zip_path).map_err(|_| ZipError("cannot open ZIP file"))?;
        buffer.resize(buf_start + file_size, 0);
        f.read_exact(&mut buffer[buf_start..])
            .map_err(|_| ZipError("cannot read ZIP file"))?;

        // Parse Central Directory from the ZIP data in the buffer.
        let zip_data = &buffer[buf_start..buf_start + file_size];
        let locations = central_dir::read_central_directory(zip_data)?;

        // Determine output subdirectory for this ZIP.
        let zip_subdir = if flat {
            PathBuf::new()
        } else {
            let stem = zip_path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".into());
            PathBuf::from(stem)
        };

        // Resolve each entry.
        for loc in &locations {
            if loc.is_directory {
                continue;
            }
            let compressed_range = resolve_compressed_range(zip_data, loc)?;
            entries.push(ResolvedEntry {
                dest_rel: zip_subdir.join(&loc.name),
                buf_offset: buf_start + compressed_range.0,
                buf_len: compressed_range.1,
                method: loc.compression_method,
                uncompressed_size: loc.uncompressed_size,
            });
        }

        zips_consumed += 1;
    }

    Ok((entries, buffer, zips_consumed))
}

/// Fill buffer variant without destination paths (for in-memory benchmarks).
fn fill_buffer_no_dest(zips: &[PathBuf]) -> Result<(Vec<ResolvedEntry>, Vec<u8>, usize), ZipError> {
    let mut buffer = Vec::with_capacity(CHUNK_BUFFER_SIZE);
    let mut entries = Vec::new();
    let mut zips_consumed = 0;

    for zip_path in zips {
        let file_size = fs::metadata(zip_path)
            .map_err(|_| ZipError("cannot stat ZIP file"))?
            .len() as usize;

        if !buffer.is_empty() && buffer.len() + file_size > CHUNK_BUFFER_SIZE {
            break;
        }

        let buf_start = buffer.len();
        let mut f = fs::File::open(zip_path).map_err(|_| ZipError("cannot open ZIP file"))?;
        buffer.resize(buf_start + file_size, 0);
        f.read_exact(&mut buffer[buf_start..])
            .map_err(|_| ZipError("cannot read ZIP file"))?;

        let zip_data = &buffer[buf_start..buf_start + file_size];
        let locations = central_dir::read_central_directory(zip_data)?;

        let zip_name = zip_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        for loc in &locations {
            if loc.is_directory {
                continue;
            }
            let compressed_range = resolve_compressed_range(zip_data, loc)?;
            entries.push(ResolvedEntry {
                dest_rel: PathBuf::from(format!("{}/{}", zip_name, loc.name)),
                buf_offset: buf_start + compressed_range.0,
                buf_len: compressed_range.1,
                method: loc.compression_method,
                uncompressed_size: loc.uncompressed_size,
            });
        }

        zips_consumed += 1;
    }

    Ok((entries, buffer, zips_consumed))
}

/// Given a ZIP data slice and an EntryLocation, return (offset, len) of
/// the compressed data within that slice.
fn resolve_compressed_range(
    zip_data: &[u8],
    loc: &EntryLocation,
) -> Result<(usize, usize), ZipError> {
    let hdr = loc.local_header_offset as usize;

    let sig = zip_data
        .get(hdr..hdr + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ZipError("local file header out of bounds"))?;
    if sig != 0x04034b50 {
        return Err(ZipError("invalid local file header signature"));
    }

    let name_len = zip_data
        .get(hdr + 26..hdr + 28)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ZipError("local header truncated"))? as usize;

    let extra_len = zip_data
        .get(hdr + 28..hdr + 30)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ZipError("local header truncated"))? as usize;

    let data_start = hdr + 30 + name_len + extra_len;
    let data_len = loc.compressed_size as usize;

    Ok((data_start, data_len))
}

/// Inflate all resolved entries in parallel and write to disk.
/// Returns (entries_written, bytes_written).
fn inflate_and_write(
    entries: &[ResolvedEntry],
    buffer: &[u8],
    dest: &Path,
) -> Result<(usize, u64), ZipError> {
    // Pre-create all necessary directories.
    let mut dirs: Vec<&Path> = entries.iter().filter_map(|e| e.dest_rel.parent()).collect();
    dirs.sort();
    dirs.dedup();
    for dir in dirs {
        let full = dest.join(dir);
        if !full.exists() {
            fs::create_dir_all(&full).map_err(|_| ZipError("cannot create output directory"))?;
        }
    }

    // Parallel inflate + write (LPT / heaviest-first): weight each entry by its
    // uncompressed size so a fat entry among tiny ones can't strand one core.
    let results: Vec<Result<u64, ZipError>> = gatling::gatling_forkjoin::gatling_for_each_balanced(
        entries.len(),
        0,
        1,
        |i| entries[i].uncompressed_size as u64,
        |i| {
            let e = &entries[i];
            let compressed = &buffer[e.buf_offset..e.buf_offset + e.buf_len];
            // Cow-borrowing decode: STORE (method 0) writes the buffer slice
            // directly — no to_vec round-trip for already-stored bytes (Law 1).
            let data = entry::decompress_entry_raw_cow(
                compressed,
                e.method,
                e.uncompressed_size as usize,
            )?;

            let out_path = dest.join(&e.dest_rel);
            let mut f =
                fs::File::create(&out_path).map_err(|_| ZipError("cannot create output file"))?;
            f.write_all(&data).map_err(|_| ZipError("write failed"))?;

            Ok(data.len() as u64)
        },
    );

    let mut total_written = 0u64;
    let mut count = 0usize;
    for r in results {
        total_written += r?;
        count += 1;
    }

    Ok((count, total_written))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn make_zip_file(items: &[(&str, &[u8])]) -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        let mut buf = Vec::new();
        let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in items {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
        buf
    }

    #[test]
    fn batch_extract_two_zips() {
        let tmp = tempfile::tempdir().unwrap();
        let zip1_path = tmp.path().join("one.zip");
        let zip2_path = tmp.path().join("two.zip");

        fs::write(&zip1_path, make_zip_file(&[("a.txt", b"aaa")])).unwrap();
        fs::write(&zip2_path, make_zip_file(&[("b.txt", b"bbb")])).unwrap();

        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&out_dir).unwrap();

        let stats = extract_zips(&[zip1_path, zip2_path], &out_dir, false).unwrap();

        assert_eq!(stats.zips_processed, 2);
        assert_eq!(stats.entries_extracted, 2);
        assert_eq!(fs::read(out_dir.join("one/a.txt")).unwrap(), b"aaa");
        assert_eq!(fs::read(out_dir.join("two/b.txt")).unwrap(), b"bbb");
    }

    #[test]
    fn batch_decompress_in_memory() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("test.zip");
        fs::write(
            &zip_path,
            make_zip_file(&[("x.txt", b"xxx"), ("y.txt", b"yyy")]),
        )
        .unwrap();

        let (entries, stats) = decompress_zips(&[zip_path]).unwrap();
        assert_eq!(stats.zips_processed, 1);
        assert_eq!(entries.len(), 2);
    }
}
