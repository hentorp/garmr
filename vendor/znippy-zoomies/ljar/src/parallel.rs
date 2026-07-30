//! Parallel JAR decompression for small files (< SMALL_FILE_THRESHOLD).
//!
//! Reads the Central Directory once, then decompresses all entries
//! concurrently on the shared gatling fork-join engine
//! (`gatling::gatling_forkjoin::gatling_for_each_balanced`).  Results are
//! returned in Central Directory order.
//!
//! For large files use `reader::decompress_batched` instead.

use crate::central_dir;
use crate::entry::{self, JarEntry, JarError};

/// Decompress all file entries in `data` in parallel.
///
/// `data` must be a complete JAR/ZIP file in memory.
/// Directory entries are skipped.  All file entries are decoded
/// concurrently and returned in Central Directory order.
pub fn decompress_parallel(data: &[u8]) -> Result<Vec<JarEntry>, JarError> {
    decompress_parallel_filter(data, "")
}

/// Decompress only entries whose name contains `needle`.
///
/// Empty needle matches all entries (same as `decompress_parallel`).
/// Filtering happens before decompression — non-matching entries are never inflated.
pub fn decompress_parallel_filter(data: &[u8], needle: &str) -> Result<Vec<JarEntry>, JarError> {
    let locations = central_dir::read_central_directory(data)?;
    let matched: Vec<_> = locations
        .iter()
        .filter(|l| !l.is_directory && (needle.is_empty() || l.name.contains(needle)))
        .collect();

    let results: Vec<Result<JarEntry, JarError>> =
        gatling::gatling_forkjoin::gatling_for_each_balanced(
            matched.len(),
            0,
            1,
            |i| matched[i].uncompressed_size,
            |i| {
                let loc = matched[i];
                let bytes = entry::decompress_entry(data, loc)?;
                Ok(JarEntry {
                    name: loc.name.clone(),
                    data: bytes,
                })
            },
        );

    results.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_jar(items: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Cursor;
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
    fn parallel_single() {
        let jar = make_jar(&[("Hello.class", b"cafebabe deadbeef")]);
        let entries = decompress_parallel(&jar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Hello.class");
        assert_eq!(entries[0].data, b"cafebabe deadbeef");
    }

    #[test]
    fn parallel_multi() {
        let jar = make_jar(&[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);
        let entries = decompress_parallel(&jar).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].data, b"aaa");
        assert_eq!(entries[1].data, b"bbb");
        assert_eq!(entries[2].data, b"ccc");
    }

    #[test]
    fn parallel_skips_directories() {
        let jar = make_jar(&[
            ("META-INF/", b""),
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ]);
        let entries = decompress_parallel(&jar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "META-INF/MANIFEST.MF");
    }

    #[test]
    fn filter_by_needle() {
        let jar = make_jar(&[
            ("com/example/App.class", b"bytecode"),
            ("META-INF/maven/com.example/app/pom.xml", b"<project/>"),
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ]);
        let entries = decompress_parallel_filter(&jar, "pom.xml").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "META-INF/maven/com.example/app/pom.xml");
        assert_eq!(entries[0].data, b"<project/>");
    }

    #[test]
    fn filter_empty_matches_all() {
        let jar = make_jar(&[("a.txt", b"a"), ("b.txt", b"b")]);
        let entries = decompress_parallel_filter(&jar, "").unwrap();
        assert_eq!(entries.len(), 2);
    }
}
