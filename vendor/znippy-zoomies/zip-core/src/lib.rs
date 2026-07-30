//! zip-core — the shared streaming-ZIP machinery.
//!
//! A JAR *is* a ZIP: both formats share the exact same End-of-Central-Directory
//! (EOCD) record, ZIP64 extensions, Central Directory header layout, and the
//! DEFLATE full-flush boundaries that make parallel decode possible.  Rather
//! than carry two near-verbatim copies (ljar's `Jar*` twin and lzip-parallel's
//! `Zip*` twin), the format-agnostic core lives here **once** and both crates
//! consume it as thin wrappers (reuse-law, task #19).
//!
//! What lives here:
//!   - [`central_dir`] — EOCD / ZIP64 EOCD parser + Central Directory walk,
//!     both the in-memory (`&[u8]`) and streaming (`Read + Seek`) entry points,
//!     producing [`EntryLocation`] records.
//!   - [`deflate_scan`] — the crate-local parallel full-flush split-point search
//!     (fans out through gatling), re-exporting linflate's `FlushBoundary` /
//!     `find_all_flushes`.
//!
//! The format-specific bits (entry decode, CRC policy, batch/streaming readers,
//! CLI) stay in each consumer crate, because they *have* diverged.

pub mod central_dir;
pub mod deflate_scan;

pub use central_dir::EntryLocation;

/// Error returned by the shared Central Directory parser.
///
/// A plain `&'static str` wrapper — each consumer crate converts it into its own
/// `JarError` / `ZipError` via a `From` impl so the historical error surface is
/// preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanError(pub &'static str);

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZIP error: {}", self.0)
    }
}

impl std::error::Error for ScanError {}
