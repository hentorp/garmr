//! RUNS via a TRANSITIVE default chain: `default → bundle → light`. A guard
//! that only reads the literal `default` array would false-alarm here.
#![cfg(feature = "light")]

#[test]
fn visible_one() {}
