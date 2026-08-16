//! SILENCED. `light` is default-on, `heavy` is not — so this whole file
//! compiles to an empty test binary and `cargo test` prints `0 tests ... ok`.
//! The guard must report it with `hidden_tests = 3`.
#![cfg(all(feature = "light", feature = "heavy"))]

#[test]
fn hidden_one() {}

#[test]
fn hidden_two() {}

#[test]
fn hidden_three() {}
