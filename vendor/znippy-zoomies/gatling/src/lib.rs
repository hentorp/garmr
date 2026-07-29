//! gatling — the constellation's **ONE** shared no-barrier worker-pool engine.
//!
//! Extracted into its own leaf crate so every codec (`lgz`, `ljar`, `lbzip2`,
//! `lzip-parallel`, …) *and* the `znippy-zoomies` root crate can depend on the
//! same engine without a dependency cycle: this crate depends on no codec, so
//! there is no cycle and no reason for any codec to hand-roll a private thread
//! pool (the sin the rayon-free law forbids).
//!
//! - [`gatling`]: generic no-barrier worker-pool engine (split → N decode →
//!   in-order collect → sink), parameterised by a [`gatling::Codec`] + a
//!   [`gatling::Sink`]. Its [`gatling::io`] submodule is the **async** sibling —
//!   a no-barrier, bounded, ordered async task pool for I/O-bound fan-out; its
//!   [`gatling::ordered`] submodule is the item-oriented ordered-sink variant.
//! - [`gatling_forkjoin`]: the fork-join gatling — `gatling_for_each` /
//!   `gatling_for_each_balanced` / `gatling_run`: all `n` units are known now,
//!   so N workers drain a shared atomic cursor at full tilt (no reader thread).
//! - [`gatling_bfs`]: the frontier-parallel **BFS** primitive — `gatling_bfs`
//!   (returns BFS layers) / `gatling_bfs_reachable` (flattened visited set).
//!   Walks a `node -> neighbors` graph one radius at a time, expanding each
//!   frontier level in parallel over `gatling_forkjoin` (one unit per node) and
//!   merging the visited-set dedup single-threaded at the level barrier. The
//!   reusable walk under transitive `what-breaks` / `expand_call_radius`.
//! - [`gatling_sort`]: the parallel **sort** primitive — `gatling_sort_by`
//!   (stable, byte-identical to `slice::sort_by`) / `gatling_sort_unstable_by` /
//!   `gatling_sort`. A parallel merge sort built ON `gatling_forkjoin` (its only
//!   pool), so sort-bound hot paths saturate all cores without a private pool.
//! - [`background`]: the depth-1 gatling — a single background [`background::Job`]
//!   for producer/consumer *overlap* (double-buffering a spill/sort/write stage
//!   behind the next decode pass). The sanctioned home for the one background
//!   `thread::spawn` non-engine crates would otherwise hand-roll.
//! - [`gatling::revolver`]: zero-allocation slot pool for 1-reader / N-worker
//!   streaming — the buffer substrate the streaming engine fans over. Folded in
//!   as a `gatling` submodule (was the top-level `chunk_revolver` module); still
//!   re-exported crate-root as [`chunk_revolver`] for API compatibility.
//!
//! `znippy-zoomies` re-exports these modules unchanged (`pub use gatling::…`) so
//! external consumers' `znippy_zoomies::gatling` / `::gatling_forkjoin` /
//! `::chunk_revolver` paths keep working.

/// **Introspection / emit marker** — record one functional-status row for the
/// nornir test matrix. Wraps `nornir_testmatrix::functional_status` behind the
/// `testmatrix` feature (a compiled-out `#[inline]` no-op otherwise, with no
/// nornir dep in the default build). `component` is the reporting surface (e.g.
/// `"gatling_forkjoin"`), `check` what it verified, `ok` the verdict, `detail` a
/// short human note. The gatling engines call this so `nornir test --features
/// testmatrix` SEES each gatling run.
#[inline]
pub fn functional_status(component: &str, check: &str, ok: bool, detail: &str) {
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(component, check, ok, detail);
    #[cfg(not(feature = "testmatrix"))]
    {
        let _ = (component, check, ok, detail);
    }
}

pub mod background;
pub mod gatling;
pub mod gatling_bfs;
pub mod gatling_forkjoin;
pub mod gatling_sort;

/// Backwards-compatible alias for the slot pool, now folded in as
/// [`gatling::revolver`]. Preserves the historical `gatling::chunk_revolver`
/// (and, through the znippy-zoomies re-export, `znippy_zoomies::chunk_revolver`)
/// path for external consumers.
pub use crate::gatling::revolver as chunk_revolver;

/// Parallel-writer gatling — the shared extract/decode/**write** fan-out that
/// removes the single ordered writer from the critical path (independent files,
/// or independent regions of one pre-sized stream). Unix-only: it uses
/// positional `pread`/`pwrite` (`std::os::unix::fs::FileExt`) so N workers read
/// and write disjoint regions concurrently with no shared file offset.
#[cfg(unix)]
pub mod parwrite;
