//! RUNS. Gated, but on a default-ON feature — the guard must classify it
//! `Default` and never report it. This is the sibling the dark file hides behind.
#![cfg(feature = "light")]

#[test]
fn visible_one() {}
