//! ljar — Pure Rust parallel JAR decompressor.
//!
//! Architecture:
//!   Parse the ZIP Central Directory (at file tail) → Vec<EntryLocation>.
//!   Dispatch every file entry to a gatling worker that DEFLATE-decodes it
//!   independently.  Results reassembled in Central Directory order.
//!
//! In-memory slice (< 10 MB): all entries decoded in one parallel pass.
//! Streaming (Read + Seek): Central Directory parsed by seeking to tail;
//!   entries read and decoded in parallel batches of 64 — the file is
//!   never fully loaded into RAM.

pub mod batch;
pub mod central_dir;
pub mod chunk;
pub mod deflate_scan;
pub mod entry;
pub mod parallel;
pub mod reader;

/// The DEFLATE core lives in the `linflate` crate (it grew out of this module
/// and is shared with lgz/lzip-parallel). Re-exported under the old path so
/// `ljar::inflate::*` keeps working; the embedded copy was deleted — it had
/// diverged and still carried the refill_slow bits==56 corruption bug that
/// linflate fixed.
pub use linflate as inflate;

pub use entry::{JarEntry, JarError};
pub use reader::StreamingJarRead;

/// **Introspection / emit marker** — record one functional-status row for the
/// nornir test matrix. Wraps `nornir_testmatrix::functional_status` behind the
/// `testmatrix` feature (a compiled-out `#[inline]` no-op otherwise, with no
/// nornir dep in the default build). Mirrors the korp-collectors reference
/// wiring so `nornir test --features testmatrix` SEES the ljar CLI.
#[inline]
pub fn functional_status(component: &str, check: &str, ok: bool, detail: &str) {
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(component, check, ok, detail);
    #[cfg(not(feature = "testmatrix"))]
    {
        let _ = (component, check, ok, detail);
    }
}

/// Files below this threshold are decompressed in a single parallel pass.
/// Files at or above use batched parallel decode.
const SMALL_FILE_THRESHOLD: usize = 10 * 1024 * 1024; // 10 MB

// ── Parallelism ───────────────────────────────────────────────────────────────
//
// Per-entry / per-segment DEFLATE decode fans out through the constellation's
// ONE shared no-barrier engine — `gatling::gatling_forkjoin::gatling_for_each`
// (N workers draining a shared atomic cursor, one per core). The old private
// rayon `ThreadPool` (`thread_pool()` / `LJAR_THREADS`) is gone; rayon is no
// longer a dependency.

// ── Public API ────────────────────────────────────────────────────────────────

/// Decompress all file entries in a JAR/ZIP byte slice.
///
/// For small slices (< 10 MB) decodes all entries in one parallel pass.
/// For larger slices uses the streaming reader with a `Cursor` wrapper.
/// Returns entries in Central Directory order; directory entries are excluded.
pub fn decompress_jar(data: &[u8]) -> Result<Vec<JarEntry>, JarError> {
    if data.len() < SMALL_FILE_THRESHOLD {
        parallel::decompress_parallel(data)
    } else {
        decompress_jar_stream(std::io::Cursor::new(data))
    }
}

/// Decompress only entries whose name contains `needle`.
///
/// Filters at the central directory level — non-matching entries are never
/// read or decompressed.  Fast prefix/suffix/substring match.
///
/// ```no_run
/// // Extract only pom.xml files from a JAR
/// let data = std::fs::read("some-artifact.jar").unwrap();
/// let entries = ljar::decompress_jar_filter(&data, "pom.xml").unwrap();
/// ```
pub fn decompress_jar_filter(data: &[u8], needle: &str) -> Result<Vec<JarEntry>, JarError> {
    if data.len() < SMALL_FILE_THRESHOLD {
        parallel::decompress_parallel_filter(data, needle)
    } else {
        let reader = StreamingJarRead::with_filter(std::io::Cursor::new(data), needle)?;
        reader.collect()
    }
}

/// Decompress all file entries from any `Read + Seek` source without loading
/// the full file into memory.
///
/// Parses the Central Directory by seeking to the file tail, then reads and
/// decodes entries in parallel batches of 64.  Directory entries are excluded.
/// Entries are returned sorted by their position in the file.
pub fn decompress_jar_stream<R: std::io::Read + std::io::Seek>(
    source: R,
) -> Result<Vec<JarEntry>, JarError> {
    StreamingJarRead::new(source)?.collect()
}
