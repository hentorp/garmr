//! Batch parallel JAR extraction pipeline.
//!
//! Reads multiple JAR files into a ~200 MB buffer, resolves all entries
//! (Central Directory parse), then dispatches inflate work across N workers.
//! While workers inflate batch N, the reader fills the buffer with batch N+1.
//!
//! This amortises I/O, Central Directory parsing, and gatling dispatch overhead
//! across many JARs — achieving throughput that scales with core count.
//!
//! # Architecture
//!
//! ```text
//! Reader thread                        Worker pool (8 cores)
//! ────────────────                     ─────────────────────
//! read JAR₁..JARₖ into buf            inflate entries from prev buf
//! parse CDs → entry list              write decompressed to disk
//! partition entries across workers     ↓
//!          ──── swap buffers ────→     receive new entry list
//! ```

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::central_dir::{self, EntryLocation};
use crate::entry::{self, JarError};

/// Maximum buffer size for batching JAR file data.
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
    /// Expected CRC-32 (from Central Directory), validated after decompression.
    crc32: u32,
}

/// Statistics returned after batch extraction.
#[derive(Debug, Default)]
pub struct BatchStats {
    pub jars_processed: usize,
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

/// Extract multiple JAR files in parallel using a pipelined batch approach.
///
/// Reads JARs into a large buffer, resolves entries, then inflates in parallel.
/// `dest` is the root output directory. Each JAR's contents are extracted into
/// a subdirectory named after the JAR file (without extension).
///
/// Returns extraction statistics.
pub fn extract_jars(jars: &[PathBuf], dest: &Path, flat: bool) -> Result<BatchStats, JarError> {
    let t0 = std::time::Instant::now();
    let mut stats = BatchStats::default();

    // Process JARs in batches that fit in the buffer.
    let mut jar_idx = 0;
    while jar_idx < jars.len() {
        let (entries, buffer, jars_in_batch) = fill_buffer(&jars[jar_idx..], dest, flat)?;
        jar_idx += jars_in_batch;
        stats.jars_processed += jars_in_batch;

        // Parallel inflate + write
        let batch_stats = inflate_and_write(&entries, &buffer, dest)?;
        stats.entries_extracted += batch_stats.0;
        stats.decompressed_bytes_written += batch_stats.1;
        stats.compressed_bytes_read += buffer.len() as u64;
    }

    stats.elapsed_secs = t0.elapsed().as_secs_f64();
    Ok(stats)
}

/// Extract multiple JARs in-memory (no disk write). Returns all entries.
///
/// Used for benchmarking the decompression pipeline without I/O overhead.
pub fn decompress_jars(jars: &[PathBuf]) -> Result<(Vec<(String, Vec<u8>)>, BatchStats), JarError> {
    let t0 = std::time::Instant::now();
    let mut stats = BatchStats::default();
    let mut all_entries = Vec::new();

    let mut jar_idx = 0;
    while jar_idx < jars.len() {
        let (entries, buffer, jars_in_batch) = fill_buffer_no_dest(&jars[jar_idx..])?;
        jar_idx += jars_in_batch;
        stats.jars_processed += jars_in_batch;

        // Parallel inflate (LPT / heaviest-first): weight each entry by its
        // uncompressed size so a fat entry can't leave the tail on one core.
        let results: Vec<Result<(String, Vec<u8>), JarError>> =
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
                        e.crc32,
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

/// Fill the batch buffer with as many JARs as fit.
/// Returns (resolved_entries, buffer, num_jars_consumed).
fn fill_buffer(
    jars: &[PathBuf],
    _dest: &Path,
    flat: bool,
) -> Result<(Vec<ResolvedEntry>, Vec<u8>, usize), JarError> {
    let mut buffer = Vec::with_capacity(CHUNK_BUFFER_SIZE);
    let mut entries = Vec::new();
    let mut jars_consumed = 0;

    for jar_path in jars {
        let file_size = fs::metadata(jar_path)
            .map_err(|_| JarError("cannot stat JAR file"))?
            .len() as usize;

        // If adding this JAR would exceed buffer, stop (unless buffer is empty).
        if !buffer.is_empty() && buffer.len() + file_size > CHUNK_BUFFER_SIZE {
            break;
        }

        let buf_start = buffer.len();

        // Read entire JAR into buffer.
        let mut f = fs::File::open(jar_path).map_err(|_| JarError("cannot open JAR file"))?;
        buffer.resize(buf_start + file_size, 0);
        f.read_exact(&mut buffer[buf_start..])
            .map_err(|_| JarError("cannot read JAR file"))?;

        // Parse Central Directory from the JAR data in the buffer.
        let jar_data = &buffer[buf_start..buf_start + file_size];
        let locations = central_dir::read_central_directory(jar_data)?;

        // Determine output subdirectory for this JAR.
        let jar_subdir = if flat {
            PathBuf::new()
        } else {
            let stem = jar_path
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
            let compressed_range = resolve_compressed_range(jar_data, loc)?;
            entries.push(ResolvedEntry {
                dest_rel: jar_subdir.join(&loc.name),
                buf_offset: buf_start + compressed_range.0,
                buf_len: compressed_range.1,
                method: loc.compression_method,
                uncompressed_size: loc.uncompressed_size,
                crc32: loc.crc32,
            });
        }

        jars_consumed += 1;
    }

    Ok((entries, buffer, jars_consumed))
}

/// Fill buffer variant without destination paths (for in-memory benchmarks).
fn fill_buffer_no_dest(jars: &[PathBuf]) -> Result<(Vec<ResolvedEntry>, Vec<u8>, usize), JarError> {
    let mut buffer = Vec::with_capacity(CHUNK_BUFFER_SIZE);
    let mut entries = Vec::new();
    let mut jars_consumed = 0;

    for jar_path in jars {
        let file_size = fs::metadata(jar_path)
            .map_err(|_| JarError("cannot stat JAR file"))?
            .len() as usize;

        if !buffer.is_empty() && buffer.len() + file_size > CHUNK_BUFFER_SIZE {
            break;
        }

        let buf_start = buffer.len();
        let mut f = fs::File::open(jar_path).map_err(|_| JarError("cannot open JAR file"))?;
        buffer.resize(buf_start + file_size, 0);
        f.read_exact(&mut buffer[buf_start..])
            .map_err(|_| JarError("cannot read JAR file"))?;

        let jar_data = &buffer[buf_start..buf_start + file_size];
        let locations = central_dir::read_central_directory(jar_data)?;

        let jar_name = jar_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());

        for loc in &locations {
            if loc.is_directory {
                continue;
            }
            let compressed_range = resolve_compressed_range(jar_data, loc)?;
            entries.push(ResolvedEntry {
                dest_rel: PathBuf::from(format!("{}/{}", jar_name, loc.name)),
                buf_offset: buf_start + compressed_range.0,
                buf_len: compressed_range.1,
                method: loc.compression_method,
                uncompressed_size: loc.uncompressed_size,
                crc32: loc.crc32,
            });
        }

        jars_consumed += 1;
    }

    Ok((entries, buffer, jars_consumed))
}

/// Given a JAR data slice and an EntryLocation, return (offset, len) of
/// the compressed data within that slice.
fn resolve_compressed_range(
    jar_data: &[u8],
    loc: &EntryLocation,
) -> Result<(usize, usize), JarError> {
    let hdr = loc.local_header_offset as usize;

    let sig = jar_data
        .get(hdr..hdr + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(JarError("local file header out of bounds"))?;
    if sig != 0x04034b50 {
        return Err(JarError("invalid local file header signature"));
    }

    let name_len = jar_data
        .get(hdr + 26..hdr + 28)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(JarError("local header truncated"))? as usize;

    let extra_len = jar_data
        .get(hdr + 28..hdr + 30)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(JarError("local header truncated"))? as usize;

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
) -> Result<(usize, u64), JarError> {
    // Pre-create all necessary directories.
    let mut dirs: Vec<&Path> = entries.iter().filter_map(|e| e.dest_rel.parent()).collect();
    dirs.sort();
    dirs.dedup();
    for dir in dirs {
        let full = dest.join(dir);
        if !full.exists() {
            fs::create_dir_all(&full).map_err(|_| JarError("cannot create output directory"))?;
        }
    }

    // Parallel inflate + write (LPT / heaviest-first): weight by uncompressed
    // size so a fat entry decodes alongside the tail instead of after it.
    let results: Vec<Result<u64, JarError>> = gatling::gatling_forkjoin::gatling_for_each_balanced(
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
                e.crc32,
            )?;

            let out_path = dest.join(&e.dest_rel);
            let mut f =
                fs::File::create(&out_path).map_err(|_| JarError("cannot create output file"))?;
            f.write_all(&data).map_err(|_| JarError("write failed"))?;

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

    fn make_jar_file(items: &[(&str, &[u8])]) -> Vec<u8> {
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
    fn batch_extract_two_jars() {
        let tmp = tempfile::tempdir().unwrap();
        let jar1_path = tmp.path().join("one.jar");
        let jar2_path = tmp.path().join("two.jar");

        fs::write(&jar1_path, make_jar_file(&[("a.txt", b"aaa")])).unwrap();
        fs::write(&jar2_path, make_jar_file(&[("b.txt", b"bbb")])).unwrap();

        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&out_dir).unwrap();

        let stats = extract_jars(&[jar1_path, jar2_path], &out_dir, false).unwrap();

        assert_eq!(stats.jars_processed, 2);
        assert_eq!(stats.entries_extracted, 2);
        assert_eq!(fs::read(out_dir.join("one/a.txt")).unwrap(), b"aaa");
        assert_eq!(fs::read(out_dir.join("two/b.txt")).unwrap(), b"bbb");
    }

    #[test]
    fn batch_decompress_in_memory() {
        let tmp = tempfile::tempdir().unwrap();
        let jar_path = tmp.path().join("test.jar");
        fs::write(
            &jar_path,
            make_jar_file(&[("x.txt", b"xxx"), ("y.txt", b"yyy")]),
        )
        .unwrap();

        let (entries, stats) = decompress_jars(&[jar_path]).unwrap();
        assert_eq!(stats.jars_processed, 1);
        assert_eq!(entries.len(), 2);
    }
}
