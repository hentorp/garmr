//! DEFLATE full-flush boundary scanner — thin re-export of the shared `zip_core`.
//!
//! The crate-local parallel split-point search (gatling fan-out) is identical
//! for JAR and ZIP, so it lives once in [`zip_core::deflate_scan`] (reuse-law,
//! task #19).  ljar re-exports it here; the SIMD scanner underneath is
//! linflate's `FlushBoundary` / `find_all_flushes`.

pub use zip_core::deflate_scan::{FlushBoundary, find_all_flushes, split_boundaries_parallel};
