//! Streaming parallel ZIP decompressor for large files.
//!
//! Pipeline mirrors lbzip2-rs's StreamingBz2Read:
//!   seek to tail → parse Central Directory → sort entries by file offset →
//!   read compressed bytes sequentially in batches of BATCH_SIZE →
//!   parallel DEFLATE decode → yield ZipEntry items.
//!
//! Only one batch of decompressed output is live at a time, bounding peak
//! memory regardless of ZIP size.  The file is never fully loaded into RAM.
//!
//! For in-memory byte slices use `parallel::decompress_parallel` instead.

use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom};

use crate::central_dir;
use crate::entry::{self, ZipEntry, ZipError};

/// Entries decoded per parallel batch.
const BATCH_SIZE: usize = 64;

const LOCAL_HEADER_SIG: u32 = 0x04034b50;

/// Streaming parallel ZIP decompressor.
///
/// Parses the Central Directory by seeking to the file tail, sorts entries by
/// their file offset for sequential I/O, then decodes them in parallel batches.
/// Implements `Iterator<Item = Result<ZipEntry, ZipError>>`.
///
/// ```no_run
/// use lzip_parallel::reader::StreamingZipRead;
/// let f = std::fs::File::open("archive.zip").unwrap();
/// for entry in StreamingZipRead::new(f).unwrap() {
///     let e = entry.unwrap();
///     println!("{}: {} bytes", e.name, e.data.len());
/// }
/// ```
pub struct StreamingZipRead<R: Read + Seek> {
    source: R,
    /// File entries sorted by local_header_offset for sequential disk reads.
    locations: Vec<crate::central_dir::EntryLocation>,
    next_entry: usize,
    buf: VecDeque<ZipEntry>,
    error: bool,
}

impl<R: Read + Seek> StreamingZipRead<R> {
    /// Open a streaming decompressor over any `Read + Seek` source.
    ///
    /// Seeks to the file tail to parse the Central Directory; no full-file
    /// read is performed here.
    pub fn new(mut source: R) -> Result<Self, ZipError> {
        let all_locs = central_dir::read_central_directory_from(&mut source)?;
        let mut locations: Vec<_> = all_locs.into_iter().filter(|l| !l.is_directory).collect();
        locations.sort_by_key(|l| l.local_header_offset);
        Ok(Self {
            source,
            locations,
            next_entry: 0,
            buf: VecDeque::new(),
            error: false,
        })
    }

    /// Open with a name filter — only entries containing `needle` are decompressed.
    ///
    /// Non-matching entries are excluded at the central directory level,
    /// never read from disk or inflated.
    pub fn with_filter(mut source: R, needle: &str) -> Result<Self, ZipError> {
        let all_locs = central_dir::read_central_directory_from(&mut source)?;
        let mut locations: Vec<_> = all_locs
            .into_iter()
            .filter(|l| !l.is_directory && l.name.contains(needle))
            .collect();
        locations.sort_by_key(|l| l.local_header_offset);
        Ok(Self {
            source,
            locations,
            next_entry: 0,
            buf: VecDeque::new(),
            error: false,
        })
    }

    /// Open with an exact-name filter — only entries whose name is in `names` are decompressed.
    ///
    /// Non-matching entries are excluded at the central directory level.
    pub fn with_filter_set(mut source: R, names: &[&str]) -> Result<Self, ZipError> {
        use std::collections::HashSet;
        let name_set: HashSet<&str> = names.iter().copied().collect();
        let all_locs = central_dir::read_central_directory_from(&mut source)?;
        let mut locations: Vec<_> = all_locs
            .into_iter()
            .filter(|l| !l.is_directory && name_set.contains(l.name.as_str()))
            .collect();
        locations.sort_by_key(|l| l.local_header_offset);
        Ok(Self {
            source,
            locations,
            next_entry: 0,
            buf: VecDeque::new(),
            error: false,
        })
    }

    /// Open with a suffix filter — only entries whose name ends with one of `suffixes`.
    ///
    /// Non-matching entries are excluded at the central directory level.
    pub fn with_filter_suffixes(mut source: R, suffixes: &[&str]) -> Result<Self, ZipError> {
        let all_locs = central_dir::read_central_directory_from(&mut source)?;
        let mut locations: Vec<_> = all_locs
            .into_iter()
            .filter(|l| !l.is_directory && suffixes.iter().any(|s| l.name.ends_with(s)))
            .collect();
        locations.sort_by_key(|l| l.local_header_offset);
        Ok(Self {
            source,
            locations,
            next_entry: 0,
            buf: VecDeque::new(),
            error: false,
        })
    }

    fn fill_batch(&mut self) -> Result<(), ZipError> {
        let remaining = self.locations.len() - self.next_entry;
        if remaining == 0 {
            return Ok(());
        }

        let batch_end = self.next_entry + remaining.min(BATCH_SIZE);
        let batch = &self.locations[self.next_entry..batch_end];

        // ── Read compressed bytes sequentially (entries sorted by offset) ──
        let mut raw: Vec<(String, Vec<u8>, u16, usize)> = Vec::with_capacity(batch.len());
        for loc in batch {
            self.source
                .seek(SeekFrom::Start(loc.local_header_offset))
                .map_err(|_| ZipError("seek to local header failed"))?;

            let mut hdr = [0u8; 30];
            self.source
                .read_exact(&mut hdr)
                .map_err(|_| ZipError("read local header failed"))?;

            if u32::from_le_bytes(hdr[0..4].try_into().unwrap()) != LOCAL_HEADER_SIG {
                return Err(ZipError("invalid local file header signature"));
            }

            // Name and extra lengths in the local header may differ from the CD.
            let skip = u16::from_le_bytes([hdr[26], hdr[27]]) as i64
                + u16::from_le_bytes([hdr[28], hdr[29]]) as i64;
            self.source
                .seek(SeekFrom::Current(skip))
                .map_err(|_| ZipError("seek past local header name/extra failed"))?;

            // Uninitialised read buffer: read_exact fully overwrites it, so the
            // vec![0u8; len] zero-fill was wasted work on the hot path.
            let len = loc.compressed_size as usize;
            let mut compressed = Vec::with_capacity(len);
            // SAFETY: len <= capacity; read_exact writes exactly `len` bytes
            // before any byte is read, and errors out (returning) otherwise.
            #[allow(clippy::uninit_vec)]
            unsafe {
                compressed.set_len(len);
            }
            self.source
                .read_exact(&mut compressed)
                .map_err(|_| ZipError("read compressed data failed"))?;

            raw.push((
                loc.name.clone(),
                compressed,
                loc.compression_method,
                loc.uncompressed_size as usize,
            ));
        }

        // ── Parallel decode ────────────────────────────────────────────────
        // Fan out per-entry decode across the shared gatling engine; `raw[i]`
        // is borrowed (the owned `name` is cloned into its ZipEntry) so the
        // closure can be a plain `Fn` over the shared index cursor.
        // LPT / heaviest-first: weight each unit by its uncompressed size so a
        // skewed archive (one fat entry among many tiny ones) can't tail-choke on
        // a single core — heavy entries claimed first, cheap tail backfills.
        let results: Vec<Result<ZipEntry, ZipError>> =
            gatling::gatling_forkjoin::gatling_for_each_balanced(
                raw.len(),
                0,
                1,
                |i| raw[i].3 as u64,
                |i| {
                    let (name, compressed, method, expected_size) = &raw[i];
                    let data = entry::decompress_entry_raw(compressed, *method, *expected_size)?;
                    Ok(ZipEntry {
                        name: name.clone(),
                        data,
                    })
                },
            );

        // ── Buffer results ─────────────────────────────────────────────────
        for r in results {
            self.buf.push_back(r?);
        }
        self.next_entry = batch_end;
        Ok(())
    }
}

impl<R: Read + Seek> Iterator for StreamingZipRead<R> {
    type Item = Result<ZipEntry, ZipError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.error {
            return None;
        }
        if let Some(entry) = self.buf.pop_front() {
            return Some(Ok(entry));
        }
        if self.next_entry >= self.locations.len() {
            return None;
        }
        match self.fill_batch() {
            Err(e) => {
                self.error = true;
                Some(Err(e))
            }
            Ok(()) => self.buf.pop_front().map(Ok),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn make_jar(items: &[(&str, &[u8])]) -> Vec<u8> {
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
    fn streaming_single() {
        let jar = make_jar(&[("Hello.class", b"cafebabe")]);
        let entries: Vec<_> = StreamingZipRead::new(Cursor::new(&jar))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Hello.class");
        assert_eq!(entries[0].data, b"cafebabe");
    }

    #[test]
    fn streaming_multi() {
        let jar = make_jar(&[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);
        let entries: Vec<_> = StreamingZipRead::new(Cursor::new(&jar))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn streaming_skips_directories() {
        let jar = make_jar(&[
            ("META-INF/", b""),
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ]);
        let entries: Vec<_> = StreamingZipRead::new(Cursor::new(&jar))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "META-INF/MANIFEST.MF");
    }

    #[test]
    fn streaming_many_batches() {
        let items: Vec<(String, Vec<u8>)> = (0..200)
            .map(|i| (format!("Class{i}.class"), format!("data{i}").into_bytes()))
            .collect();
        let item_refs: Vec<(&str, &[u8])> = items
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let jar = make_jar(&item_refs);

        let entries: Vec<_> = StreamingZipRead::new(Cursor::new(&jar))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 200);
    }

    #[test]
    fn streaming_matches_parallel() {
        let items: Vec<(String, Vec<u8>)> = (0..100)
            .map(|i| (format!("{i}.txt"), format!("content {i}").into_bytes()))
            .collect();
        let item_refs: Vec<(&str, &[u8])> = items
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let jar = make_jar(&item_refs);

        let par = crate::parallel::decompress_parallel(&jar).unwrap();
        let stream: Vec<_> = StreamingZipRead::new(Cursor::new(&jar))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // streaming returns entries in file-offset order (sorted); sort par to match
        let mut par_sorted = par;
        par_sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut stream_sorted = stream;
        stream_sorted.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(par_sorted.len(), stream_sorted.len());
        for (p, s) in par_sorted.iter().zip(stream_sorted.iter()) {
            assert_eq!(p.name, s.name);
            assert_eq!(p.data, s.data);
        }
    }

    /// Core-saturation correctness: a deliberately SKEWED archive — one fat
    /// entry among many tiny ones — must decode byte-for-byte identically under
    /// the LPT (heaviest-first) balanced fan-out. The rebalance only reorders
    /// which worker claims which entry; the decoded bytes are unchanged.
    #[test]
    fn streaming_skewed_roundtrip_byte_identical() {
        let big: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let mut items: Vec<(String, Vec<u8>)> = Vec::new();
        items.push(("Fat.class".to_string(), big.clone()));
        for i in 0..300 {
            items.push((format!("Tiny{i}.class"), format!("t{i}").into_bytes()));
        }
        let item_refs: Vec<(&str, &[u8])> = items
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let jar = make_jar(&item_refs);

        let entries: Vec<_> = StreamingZipRead::new(Cursor::new(&jar))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(entries.len(), items.len());
        let got: std::collections::HashMap<&str, &[u8]> = entries
            .iter()
            .map(|e| (e.name.as_str(), e.data.as_slice()))
            .collect();
        for (name, data) in &items {
            assert_eq!(
                got.get(name.as_str()),
                Some(&data.as_slice()),
                "entry {name} mismatch"
            );
        }
    }
}
