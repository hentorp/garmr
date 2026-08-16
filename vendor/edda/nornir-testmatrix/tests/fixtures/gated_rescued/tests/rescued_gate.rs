//! Not default-reachable — but the repo's declared arm
//! `cargo test -p gated_rescued --features heavy --test rescued_gate` runs it,
//! so it is COVERED, not silenced.
#![cfg(all(feature = "light", feature = "heavy"))]

#[test]
fn rescued_one() {}

#[test]
fn rescued_two() {}
