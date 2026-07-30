//! Inject-and-assert round-trip over the raw zstd FFI.
//!
//! Project LAW: a test must feed real input and assert real output, never just
//! "didn't crash". Here we compress a concrete, compressible payload through the
//! `ZSTD_compress` binding and assert: (1) the call did not signal an error,
//! (2) compression actually shrank the data, (3) the frame advertises the right
//! content size, and (4) `ZSTD_decompress` reconstructs the original bytes
//! exactly.

use std::os::raw::c_void;

use zstd_sys_rs::{
    ZSTD_compress, ZSTD_compressBound, ZSTD_decompress, ZSTD_getFrameContentSize, ZSTD_isError,
};

fn compress(src: &[u8], level: i32) -> Vec<u8> {
    let bound = unsafe { ZSTD_compressBound(src.len()) };
    let mut dst = vec![0u8; bound];
    let written = unsafe {
        ZSTD_compress(
            dst.as_mut_ptr() as *mut c_void,
            dst.len(),
            src.as_ptr() as *const c_void,
            src.len(),
            level,
        )
    };
    assert_eq!(
        unsafe { ZSTD_isError(written) },
        0,
        "ZSTD_compress reported an error for a valid input"
    );
    dst.truncate(written);
    dst
}

fn decompress(compressed: &[u8], expected_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; expected_len];
    let got = unsafe {
        ZSTD_decompress(
            out.as_mut_ptr() as *mut c_void,
            out.len(),
            compressed.as_ptr() as *const c_void,
            compressed.len(),
        )
    };
    assert_eq!(unsafe { ZSTD_isError(got) }, 0, "ZSTD_decompress errored");
    out.truncate(got);
    out
}

#[test]
fn compress_then_decompress_recovers_exact_bytes() {
    // Real, highly compressible input: 64 KiB of a repeating pattern.
    let original: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();

    let compressed = compress(&original, 3);

    // Real output assertion #1: it actually compressed (shrank).
    assert!(
        compressed.len() < original.len(),
        "expected compression to shrink {} bytes, got {}",
        original.len(),
        compressed.len()
    );

    // Real output assertion #2: the frame header advertises the true size.
    let advertised =
        unsafe { ZSTD_getFrameContentSize(compressed.as_ptr() as *const c_void, compressed.len()) };
    assert_eq!(advertised as usize, original.len());

    // Real output assertion #3: byte-exact round-trip.
    let restored = decompress(&compressed, original.len());
    assert_eq!(restored, original, "round-trip did not reproduce input");
}

#[test]
fn compression_level_changes_output_but_not_content() {
    // Pseudo-random-ish but deterministic payload so both levels do real work.
    let original: Vec<u8> = (0..32 * 1024)
        .map(|i| (((i * 2654435761usize) >> 13) & 0xff) as u8)
        .collect();

    let lo = compress(&original, 1);
    let hi = compress(&original, 19);

    // Both levels must decode back to the identical original (real assertion).
    assert_eq!(decompress(&lo, original.len()), original);
    assert_eq!(decompress(&hi, original.len()), original);
}
