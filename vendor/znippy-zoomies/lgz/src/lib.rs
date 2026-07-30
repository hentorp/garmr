//! lgz — Pure Rust parallel gzip decompressor.
//!
//! Architecture (mirrors lbzip2-rs / ljar-rs):
//!
//! ```text
//! Reader ──→ Main(carry+split) ──→ N Workers ──→ Collector ──→ Writer
//!   ↑                                                  │
//!   └────────────── ring-slot recycle ─────────────────┘
//! ```
//!
//! Gzip is a gzip header + DEFLATE stream + trailer.
//! Full-flush boundaries (`00 00 FF FF`) in the DEFLATE stream mark points
//! where the LZ77 window resets — each segment between flushes is independently
//! decompressible.
//!
//! For streams without flush boundaries (standard `gzip` output), falls back
//! to single-threaded flate2. Streams from `pigz`, bgzf, or any compressor
//! using Z_FULL_FLUSH are fully parallelized.
//!
//! # Zero-Copy API
//!
//! ```
//! let original = b"test data for lgz";
//! let compressed = {
//!     use std::io::Write;
//!     let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
//!     e.write_all(original).unwrap();
//!     e.finish().unwrap()
//! };
//! let decompressed = lgz::decompress_gz(&compressed).unwrap();
//! assert_eq!(&decompressed, original);
//! ```

pub mod chunk;
pub mod deflate_scan;
pub mod parallel;
pub mod speculative;

/// **Introspection / emit marker** — record one functional-status row for the
/// nornir test matrix. Wraps `nornir_testmatrix::functional_status` behind the
/// `testmatrix` feature (a compiled-out `#[inline]` no-op otherwise, with no
/// nornir dep in the default build). Mirrors the korp-collectors reference
/// wiring so `nornir test --features testmatrix` SEES the lgz CLI.
#[inline]
pub fn functional_status(component: &str, check: &str, ok: bool, detail: &str) {
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(component, check, ok, detail);
    #[cfg(not(feature = "testmatrix"))]
    {
        let _ = (component, check, ok, detail);
    }
}

pub use parallel::{
    GzError, OUTPUT_TOO_LARGE, decompress_gz, decompress_gz_capped, decompress_gz_into,
    decompress_gz_stream, deflate_offset, output_too_large,
};

/// Files below this threshold are decompressed single-threaded.
pub const PARALLEL_THRESHOLD: usize = 4 * 1024 * 1024; // 4 MB

/// Decompress tar.gz with an optional filter on entry names.
pub fn decompress_tar_gz_filter(
    data: &[u8],
    needle: &str,
) -> Result<Vec<(String, Vec<u8>)>, GzError> {
    let decompressed = decompress_gz(data)?;
    extract_tar_entries(&decompressed, needle, usize::MAX)
}

/// Like [`decompress_tar_gz_filter`], but with a hard output cap.
///
/// The cap applies BOTH to the gzip output stream (the outer decompression never
/// buffers more than ~`max_out`, via [`decompress_gz_capped`]) AND to each
/// collected tar entry (a single entry read is bounded by `max_out`). On either
/// overshoot it returns [`GzError`] carrying [`OUTPUT_TOO_LARGE`] instead of
/// allocating the full bomb — so an ingest caller can degrade gracefully rather
/// than OOM.
pub fn decompress_tar_gz_filter_capped(
    data: &[u8],
    needle: &str,
    max_out: usize,
) -> Result<Vec<(String, Vec<u8>)>, GzError> {
    let decompressed = decompress_gz_capped(data, max_out)?;
    extract_tar_entries(&decompressed, needle, max_out)
}

fn extract_tar_entries(
    tar_data: &[u8],
    needle: &str,
    max_entry: usize,
) -> Result<Vec<(String, Vec<u8>)>, GzError> {
    use std::io::Read;
    let mut archive = tar::Archive::new(tar_data);
    let mut results = Vec::new();

    let entries = archive.entries().map_err(|_| GzError("tar parse failed"))?;

    for entry in entries {
        let mut entry = entry.map_err(|_| GzError("tar entry read failed"))?;
        let path = entry
            .path()
            .map_err(|_| GzError("tar entry path failed"))?
            .to_string_lossy()
            .to_string();

        if needle.is_empty() || path.contains(needle) {
            // Cap the per-entry read: `take(max_entry)` bounds the allocation,
            // and a full-to-the-cap read means the entry met/exceeded the cap →
            // treat as too large rather than silently truncating.
            let mut data = Vec::new();
            let read = entry
                .by_ref()
                .take(max_entry as u64)
                .read_to_end(&mut data)
                .map_err(|_| GzError("tar entry data read failed"))?;
            if read >= max_entry && max_entry != usize::MAX {
                return Err(parallel::output_too_large());
            }
            results.push((path, data));
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a gzip+tar with a single entry `name` holding `body`.
    fn make_tar_gz(name: &str, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::fast());
            let mut tar = tar::Builder::new(enc);
            let mut h = tar::Header::new_gnu();
            h.set_path(name).unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append(&h, body).unwrap();
            tar.finish().unwrap();
        }
        out
    }

    #[test]
    fn tar_gz_filter_capped_small_roundtrips() {
        let archive = make_tar_gz("package/package.json", br#"{"name":"x"}"#);
        let entries =
            decompress_tar_gz_filter_capped(&archive, "package.json", 1024 * 1024).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "package/package.json");
        assert_eq!(entries[0].1, br#"{"name":"x"}"#);
    }

    #[test]
    fn tar_gz_filter_capped_outer_bomb_errors() {
        // A tar whose single entry is 256 KiB of zeros — the gzip-output cap trips
        // before we ever reach the tar layer.
        let archive = make_tar_gz("package/big.bin", &vec![0u8; 256 * 1024]);
        let err = decompress_tar_gz_filter_capped(&archive, "", 4096).unwrap_err();
        assert_eq!(err.0, OUTPUT_TOO_LARGE);
    }

    #[test]
    fn tar_gz_filter_capped_entry_cap_trips() {
        // Outer gzip output is small enough to pass the gzip cap, but a single
        // matched entry exceeds the per-entry cap → OUTPUT_TOO_LARGE, no full
        // buffer of the entry.
        let body = vec![0u8; 200 * 1024];
        let archive = make_tar_gz("package/package.json", &body);
        // Cap large enough for the (incompressible-after-gunzip) gzip output of
        // ~200 KiB zeros, but the entry read itself is capped the same → trips.
        let err = decompress_tar_gz_filter_capped(&archive, "package.json", 64 * 1024).unwrap_err();
        assert_eq!(err.0, OUTPUT_TOO_LARGE);
    }

    /// Sanity: the uncapped legacy API still works (backward-compat).
    #[test]
    fn legacy_uncapped_still_works() {
        let archive = make_tar_gz("a/b.json", b"hello");
        let entries = decompress_tar_gz_filter(&archive, "b.json").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"hello");
    }
}
