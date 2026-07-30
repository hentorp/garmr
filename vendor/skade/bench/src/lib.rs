//! Library surface of the bench crate.
//!
//! A binary crate's modules can't be imported by integration tests or examples,
//! so the scenarios live here as a lib and `main.rs` is a thin front-end over it.
//! This is what lets `examples/nornir-bench.rs` (the nornir bencher contract) and
//! `tests/` reuse the same `data` / `pipeline` / `scenarios` / `factory` code.

#[allow(dead_code)]
#[allow(dead_code)]
pub mod containers;
// The front-page capability matrix, emitted through the nornir static-capabilities
// bench seam and rendered into `.nornir/README-full.md` from one source of truth.
pub mod capabilities;
pub mod data;
pub mod factory;
#[allow(dead_code)]
pub mod pipeline;
pub mod rest_shim;
pub mod scenarios;
// Shared synthetic workload for the `skade.*` throughput benchers (migrated from
// the old criterion suite `skade/benches/throughput.rs`).
pub mod skade_throughput;
// rust-s3 is gated: nornir (a dev-dep) pulls gix → maybe-async/is_sync, which
// unifies globally and flips rust-s3's maybe-async into sync mode (await in sync
// fns → won't compile under `cargo test`). Keeping S3 behind a non-default
// feature lets the default test build (and the S3-free REST tests) compile.
#[cfg(feature = "s3")]
#[allow(dead_code)]
pub mod s3_storage;
