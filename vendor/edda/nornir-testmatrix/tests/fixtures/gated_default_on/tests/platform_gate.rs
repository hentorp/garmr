//! Not a feature gate at all — a platform gate. The guard evaluates non-feature
//! predicates as UNKNOWN, so this must never be reported (and, mentioning no
//! feature, must not even be listed as a gated file).
#![cfg(not(target_os = "solaris"))]

#[test]
fn visible_two() {}
