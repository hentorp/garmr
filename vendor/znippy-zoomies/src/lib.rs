//! znippy-zoomies — fast-as-hell building blocks extracted from katana-osm.
//!
//! - [`xml`]: generic VTD-style parallel XML element scanner (tag-vocabulary
//!   agnostic) — the scanning machinery [`vtd`] is now layered on top of.
//! - [`vtd`]: VTD-style parallel OSM-XML scanner producing a compact `ElemIndex`
//!   (byte offsets into the file), plus zone-map summaries and byte-level attr parsers.
//! - [`stree`]: Ragnar Groot Koerkamp's static search tree over sorted `i64` keys
//!   (AVX2), including an mmap-backed variant whose leaf layer IS the sorted file.
//! - [`stree32`]: a clean clone of [`stree`] restored to Ragnar's ORIGINAL `u32`
//!   key width (B=16, `_mm256_cmpgt_epi32`) for future non-OSM use. A separate
//!   concrete type, never a generic `STree<T>` (the i64 path stays for OSM/skade).
//! - [`chunk_revolver`]: zero-allocation slot pool for 1-reader / N-worker streaming.
//! - [`gatling`]: generic no-barrier worker-pool engine (split → N decode → in-order
//!   collect → sink), parameterised by a [`gatling::Codec`] + [`gatling::Sink`].
//!   Its [`gatling::io`] submodule is the **async** sibling — a no-barrier, bounded,
//!   ordered async task pool for I/O-bound (network/PUT/GET) fan-out, same
//!   philosophy, tokio substrate instead of OS threads.
//! - [`psort`]: parallel sample sort (and reference LSD radix) over 16-byte AoS
//!   records keyed by their leading `i64`.
//! - [`gatling_sort`]: generic parallel comparison sort (`gatling_sort_by`
//!   stable / `gatling_sort_unstable_by` / `gatling_sort`), a merge sort fanned
//!   out on the gatling fork-join — the drop-in parallel `slice::sort_by`.
//! - [`gatling_bfs`]: frontier-parallel BFS (`gatling_bfs` / `gatling_bfs_reachable`)
//!   over a generic `node -> neighbors` graph — expands each BFS level in parallel
//!   on the fork-join pool, merges the visited-set dedup at the level barrier.
//! - [`json`]: zero-copy parallel NDJSON record scanner (the vtd pattern for
//!   JSON) — memchr newline split is safe by RFC 8259, plus an escape-aware
//!   top-level `find_key` field probe.
//! - [`vann`]: pure vector-ANN engine — an exact brute-force ("flat") `f32`
//!   nearest-neighbour index (100%-recall oracle) with runtime-detected SIMD +
//!   int8/VNNI cosine kernels. Extracted from nornir.

/// **Introspection / emit marker** — record one functional-status row for the
/// nornir test matrix. Wraps `nornir_testmatrix::functional_status` behind the
/// `testmatrix` feature (a compiled-out `#[inline]` no-op otherwise, with no
/// nornir dep in the default build). `component` is the reporting surface (e.g.
/// `"gatling_forkjoin"`), `check` what it verified, `ok` the verdict, `detail` a
/// short human note. Mirrors the korp-collectors reference wiring so `nornir
/// test --features testmatrix` SEES each gatling run.
#[inline]
pub fn functional_status(component: &str, check: &str, ok: bool, detail: &str) {
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(component, check, ok, detail);
    #[cfg(not(feature = "testmatrix"))]
    {
        let _ = (component, check, ok, detail);
    }
}

// The no-barrier engine now lives in its own leaf crate (`gatling`) so the
// codec sub-crates can depend on it without a cycle through this crate. Re-
// exported unchanged so external consumers' `znippy_zoomies::gatling` /
// `::gatling_forkjoin` / `::chunk_revolver` paths (and their submodules
// `gatling::io` / `gatling::ordered`) keep resolving.
pub use ::gatling::{
    background, chunk_revolver, gatling, gatling_bfs, gatling_forkjoin, gatling_sort,
};
pub mod json;
pub mod psort;
pub mod stree;
pub mod stree32;
pub mod stree32_range;
pub mod vann;
pub mod vtd;
pub mod vtd_single_pass;
pub mod xml;
