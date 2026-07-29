//! Byte-identical decode through the shared `zip_core` Central Directory path.
//!
//! Self-contained (no network): builds a small in-memory .zip with the `zip`
//! crate, decodes it via lzip-parallel's public API — which parses the CD
//! through the shared `zip_core::central_dir` parser — and asserts every entry
//! comes back byte-for-byte.  Red if the shared parser mis-resolves an entry
//! offset/size or the ZIP wrapper regresses.

use std::io::{Cursor, Write};
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

/// Build an in-memory ZIP whose entries mix DEFLATE and STORE.
fn build_zip(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
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
fn zip_decode_byte_identical_through_shared_core() {
    let payloads: Vec<(&str, Vec<u8>, CompressionMethod)> = vec![
        (
            "dir/notes.txt",
            b"a zip is a jar too\n".to_vec(),
            CompressionMethod::Deflated,
        ),
        (
            "payload/large.bin",
            (0u8..255).cycle().take(9000).collect(),
            CompressionMethod::Deflated,
        ),
        (
            "stored/raw.dat",
            vec![0x5Au8; 4096],
            CompressionMethod::Stored,
        ),
        ("root.txt", b"hello".to_vec(), CompressionMethod::Deflated),
    ];
    let refs: Vec<(&str, &[u8], CompressionMethod)> = payloads
        .iter()
        .map(|(n, d, m)| (*n, d.as_slice(), *m))
        .collect();
    let zip = build_zip(&refs);

    let out = lzip_parallel::decompress_zip(&zip).expect("decode zip");

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
fn zip_filter_suffixes_uses_shared_cd() {
    let zip = build_zip(&[
        ("pkg/a.py", b"print(1)", CompressionMethod::Deflated),
        ("pkg/a.txt", b"text", CompressionMethod::Deflated),
        ("pkg/b.py", b"print(2)", CompressionMethod::Deflated),
    ]);
    let out = lzip_parallel::decompress_zip_filter_suffixes(&zip, &[".py"]).expect("suffix decode");
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|e| e.name.ends_with(".py")));
}
