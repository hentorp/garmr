//! Zero-allocation slot pool for 1-reader / N-worker streaming pipelines.
//!
//! Reachable as [`gatling::revolver`](crate::gatling::revolver) — folded in as a
//! `gatling` submodule (the buffer substrate the streaming engine fans over),
//! alongside `gatling::io` / `gatling::ordered`. The former top-level
//! `chunk_revolver` module name survives as a crate-root re-export alias
//! ([`crate::chunk_revolver`]) so external consumers are unaffected.
//!
//! Moved verbatim into znippy-zoomies from the former standalone `chunk-revolver`
//! crate. One reader thread fills pre-allocated fixed-size slots; N workers borrow
//! each slot as `&[u8]` (zero-copy) via [`get_chunk_slice`](crate::gatling::revolver::get_chunk_slice)
//! and process it.
//!
//! **Status (2026-07):** this is a public, exported primitive with NO in-tree
//! *runtime* consumer today — the codec CLIs stream through the `gatling` /
//! `gatling::ordered` engines, and znippy currently runs a *fork* of this pool
//! (`znippy-common`'s "Magazine"). It is NOT dead code, though: it is the
//! CANONICAL slot pool that `.nornir/chunk_revolver-unsorted.md` ("Magazine →
//! chunk_revolver consolidation") designates as the survivor — Phase 1 adds
//! Magazine's coalescing/ref-count mode here, Phase 2 flips znippy's
//! `slot_packer.rs` onto it and deletes the fork. Its behaviour is pinned by
//! `tests/chunk_revolver.rs`. Do not delete without retiring that plan first.
#![allow(
    unsafe_code,
    reason = "raw pointer slot pool — safety documented per site"
)]

mod revolver;
mod ring;

pub use revolver::{Chunk, ChunkRevolver, SendPtr, get_chunk_slice};
pub use ring::{HUGE, LARGE, MEDIUM, MINI};
