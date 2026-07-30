//! lbzip2-rs — Pure Rust parallel bzip2 decompressor.
//!
//! Architecture:
//!   1 reader thread reads ~100 MB of raw compressed bzip2 data into a
//!   chunk buffer.
//!
//!   Per chunk the reader does a cheap bit-scan to locate bzip2 block
//!   boundaries (magic 0x314159265359 at arbitrary bit offsets), then
//!   fans the N sub-ranges out through the shared `gatling` engine
//!   (`gatling::gatling_forkjoin::gatling_for_each`) — the one constellation
//!   worker pool, NOT a private one.
//!
//!   Each worker independently decodes its Burrows-Wheeler blocks and
//!   produces decompressed output.  Results are reassembled in order and
//!   emitted as a streaming `Read`.

pub mod bitreader;
pub mod block;
pub mod block_scan;
pub mod bwt;
pub mod chunk;
pub mod huffman;
pub mod mtf;
pub mod parallel;
pub mod reader;
pub mod stream;

/// **Introspection / emit marker** — record one functional-status row for the
/// nornir test matrix. Wraps `nornir_testmatrix::functional_status` behind the
/// `testmatrix` feature (a compiled-out `#[inline]` no-op otherwise, with no
/// nornir dep in the default build). Mirrors the korp-collectors reference
/// wiring so `nornir test --features testmatrix` SEES the lbunzip2 CLI.
#[inline]
pub fn functional_status(component: &str, check: &str, ok: bool, detail: &str) {
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(component, check, ok, detail);
    #[cfg(not(feature = "testmatrix"))]
    {
        let _ = (component, check, ok, detail);
    }
}

/// bzip2 block magic: π digits — 0x314159265359 (48 bits, bit-aligned).
pub const BLOCK_MAGIC: u64 = 0x314159265359;

/// bzip2 end-of-stream magic: √π digits — 0x177245385090 (48 bits).
pub const FINAL_MAGIC: u64 = 0x177245385090;

// ── Parallelism ──────────────────────────────────────────────────────────────
//
// bzip2 decode is parallelised on the constellation's ONE shared no-barrier
// engine — `gatling::gatling_forkjoin::gatling_for_each` (N workers draining a
// shared atomic cursor, one per core). The old private scoped-thread pool
// (`par::par_map`) is gone.
