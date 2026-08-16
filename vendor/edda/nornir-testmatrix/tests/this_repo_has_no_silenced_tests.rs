//! **edda audits itself.** The repo that SHIPS the silenced-test guard did not run
//! it on its own tree.
//!
//! `gated_tests_guard.rs` next door proves the engine against three fixture repos,
//! and `rescue_arms_are_real.rs` proves edda's declared arms compile. Neither ever
//! asked the one question the guard exists for: *does edda itself have a test file
//! that compiles to zero tests?* On 2026-08-01 it did —
//! `crates/korp-installer/tests/secure_boot.rs`, gated on `secure-boot`, hiding
//! three tests including the negative assertion that an UNSIGNED chain is refused.
//! The guard's own workspace, dark, for as long as the guard has existed.
//!
//! That is not an edda-specific slip. A fleet audit the same day found the guard
//! consumed by exactly zero of twenty repos, while 38 dark targets hiding 122
//! `#[test]` fns had accumulated behind ten `.nornir/testmatrix-arms.json` files
//! that nothing read. This file is the four-line adoption every one of those repos
//! is being asked to copy, so it lives first in the repo that wrote the guard.
//!
//! Deliberately NOT feature-gated — see the joke that writes itself, next door.

use std::path::{Path, PathBuf};

/// `crates/nornir-testmatrix/` → the edda repo root.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate sits two levels below the repo root")
        .to_path_buf()
}

#[test]
fn edda_has_no_silenced_test_files() {
    nornir_testmatrix::assert_no_silenced_tests(&repo_root());
}
