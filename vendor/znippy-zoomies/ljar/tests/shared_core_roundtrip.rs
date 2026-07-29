//! Byte-identical decode through the shared `zip_core` Central Directory path.
//!
//! Self-contained (no network): builds a small in-memory .jar with the `zip`
//! crate, decodes it via ljar's public API — which parses the CD through the
//! shared `zip_core::central_dir` parser — and asserts every entry comes back
//! byte-for-byte.  Red if the shared parser mis-resolves an entry offset/size
//! or the JAR wrapper regresses.

use std::io::{Cursor, Write};
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

/// Build an in-memory JAR whose entries mix DEFLATE and STORE.
fn build_jar(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
        for (name, data, method) in entries {
            let opts = SimpleFileOptions::default().compression_method(*method);
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
    }
    buf
}

#[test]
fn jar_decode_byte_identical_through_shared_core() {
    let payloads: Vec<(&str, Vec<u8>, CompressionMethod)> = vec![
        (
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\n".to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "com/example/App.class",
            (0u8..255).cycle().take(9000).collect(),
            CompressionMethod::Deflated,
        ),
        (
            "resources/data.bin",
            vec![0xABu8; 4096],
            CompressionMethod::Stored,
        ),
        (
            "readme.txt",
            b"a jar is a zip".to_vec(),
            CompressionMethod::Deflated,
        ),
    ];
    let refs: Vec<(&str, &[u8], CompressionMethod)> = payloads
        .iter()
        .map(|(n, d, m)| (*n, d.as_slice(), *m))
        .collect();
    let jar = build_jar(&refs);

    let out = ljar::decompress_jar(&jar).expect("decode jar");

    // Every non-directory entry must round-trip byte-for-byte.
    for (name, data, _) in &payloads {
        let got = out
            .iter()
            .find(|e| &e.name == name)
            .unwrap_or_else(|| panic!("entry {name} missing from decode"));
        assert_eq!(&got.data, data, "byte mismatch for {name}");
    }
    assert_eq!(out.len(), payloads.len(), "entry count mismatch");
}

#[test]
fn jar_filter_uses_shared_cd() {
    let jar = build_jar(&[
        ("keep/one.txt", b"first", CompressionMethod::Deflated),
        ("drop/two.txt", b"second", CompressionMethod::Deflated),
        ("keep/three.txt", b"third", CompressionMethod::Deflated),
    ]);
    let out = ljar::decompress_jar_filter(&jar, "keep/").expect("filtered decode");
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|e| e.name.starts_with("keep/")));
}
