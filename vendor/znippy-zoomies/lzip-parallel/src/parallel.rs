//! Parallel ZIP decompression for small files (< SMALL_FILE_THRESHOLD).
//!
//! Reads the Central Directory once, then decompresses all entries
//! concurrently on the shared gatling fork-join engine
//! (`gatling::gatling_forkjoin::gatling_for_each_balanced`).  Results are
//! returned in Central Directory order.
//!
//! For large files use `reader::decompress_batched` instead.

use crate::central_dir;
use crate::entry::{self, ZipEntry, ZipError};

/// Decompress all file entries in `data` in parallel.
///
/// `data` must be a complete ZIP file in memory.
/// Directory entries are skipped.  All file entries are decoded
/// concurrently and returned in Central Directory order.
pub fn decompress_parallel(data: &[u8]) -> Result<Vec<ZipEntry>, ZipError> {
    decompress_parallel_filter(data, "")
}

/// Decompress only entries whose name contains `needle`.
///
/// Empty needle matches all entries (same as `decompress_parallel`).
/// Pre-filters at the central directory level — non-matching entries are never inflated.
pub fn decompress_parallel_filter(data: &[u8], needle: &str) -> Result<Vec<ZipEntry>, ZipError> {
    let locations = central_dir::read_central_directory(data)?;
    let matched: Vec<_> = locations
        .iter()
        .filter(|l| !l.is_directory && (needle.is_empty() || l.name.contains(needle)))
        .collect();

    let results: Vec<Result<ZipEntry, ZipError>> =
        gatling::gatling_forkjoin::gatling_for_each_balanced(
            matched.len(),
            0,
            1,
            |i| matched[i].uncompressed_size,
            |i| {
                let loc = matched[i];
                let bytes = entry::decompress_entry(data, loc)?;
                Ok(ZipEntry {
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

/// Decompress only entries whose name exactly matches one of `names`.
///
/// Empty slice returns nothing. Pre-filters at the central directory level —
/// only matching entries are dispatched to gatling workers.
pub fn decompress_parallel_filter_set(
    data: &[u8],
    names: &[&str],
) -> Result<Vec<ZipEntry>, ZipError> {
    use std::collections::HashSet;
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let name_set: HashSet<&str> = names.iter().copied().collect();
    let locations = central_dir::read_central_directory(data)?;
    let matched: Vec<_> = locations
        .iter()
        .filter(|l| !l.is_directory && name_set.contains(l.name.as_str()))
        .collect();

    let results: Vec<Result<ZipEntry, ZipError>> =
        gatling::gatling_forkjoin::gatling_for_each_balanced(
            matched.len(),
            0,
            1,
            |i| matched[i].uncompressed_size,
            |i| {
                let loc = matched[i];
                let bytes = entry::decompress_entry(data, loc)?;
                Ok(ZipEntry {
                    name: loc.name.clone(),
                    data: bytes,
                })
            },
        );

    results.into_iter().collect()
}

/// Decompress only entries whose name ends with one of `suffixes`.
///
/// Empty slice returns nothing. Pre-filters at the central directory level —
/// only matching entries are dispatched to gatling workers.
pub fn decompress_parallel_filter_suffixes(
    data: &[u8],
    suffixes: &[&str],
) -> Result<Vec<ZipEntry>, ZipError> {
    if suffixes.is_empty() {
        return Ok(Vec::new());
    }
    let locations = central_dir::read_central_directory(data)?;
    let matched: Vec<_> = locations
        .iter()
        .filter(|l| !l.is_directory && suffixes.iter().any(|s| l.name.ends_with(s)))
        .collect();

    let results: Vec<Result<ZipEntry, ZipError>> =
        gatling::gatling_forkjoin::gatling_for_each_balanced(
            matched.len(),
            0,
            1,
            |i| matched[i].uncompressed_size,
            |i| {
                let loc = matched[i];
                let bytes = entry::decompress_entry(data, loc)?;
                Ok(ZipEntry {
                    name: loc.name.clone(),
                    data: bytes,
                })
            },
        );

    results.into_iter().collect()
}

#[cfg(all(test, feature = "gen"))]
mod filter_set_tests {
    use super::*;
    use std::io::Write;

    fn make_zip(items: &[(&str, &[u8])]) -> Vec<u8> {
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
    fn filter_set_exact_match() {
        let zip = make_zip(&[
            ("numpy/__init__.py", b"import numpy"),
            ("numpy-1.26.0.dist-info/METADATA", b"Name: numpy"),
            ("numpy-1.26.0.dist-info/RECORD", b"files here"),
            ("numpy/core/setup.py", b"setup()"),
        ]);
        let entries = decompress_parallel_filter_set(
            &zip,
            &[
                "numpy-1.26.0.dist-info/METADATA",
                "numpy-1.26.0.dist-info/RECORD",
            ],
        )
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.data == b"Name: numpy"));
        assert!(entries.iter().any(|e| e.data == b"files here"));
    }

    #[test]
    fn filter_set_empty_returns_nothing() {
        let zip = make_zip(&[("a.txt", b"a")]);
        let entries = decompress_parallel_filter_set(&zip, &[]).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn filter_set_no_match() {
        let zip = make_zip(&[("a.txt", b"a"), ("b.txt", b"b")]);
        let entries = decompress_parallel_filter_set(&zip, &["c.txt"]).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn filter_suffixes_py() {
        let zip = make_zip(&[
            ("lib/__init__.py", b"init"),
            ("lib/core.py", b"core"),
            ("lib/types.pyi", b"types"),
            ("lib/data.json", b"{}"),
        ]);
        let entries = decompress_parallel_filter_suffixes(&zip, &[".py", ".pyi"]).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(
            entries
                .iter()
                .all(|e| e.name.ends_with(".py") || e.name.ends_with(".pyi"))
        );
    }

    #[test]
    fn filter_suffixes_empty_returns_nothing() {
        let zip = make_zip(&[("a.py", b"a")]);
        let entries = decompress_parallel_filter_suffixes(&zip, &[]).unwrap();
        assert_eq!(entries.len(), 0);
    }
}
