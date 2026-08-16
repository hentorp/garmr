//! Rescued by a workspace-wide arm whose feature (`bundle`) enables `heavy`
//! only TRANSITIVELY — the arm's feature closure must be resolved, not compared
//! literally.
#![cfg(feature = "heavy")]

#[test]
fn transitively_rescued_one() {}
