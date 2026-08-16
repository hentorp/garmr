//! **edda's own comments must not cite tests that do not exist.**
//!
//! This is the three-line adoption any repo copies — the audit itself lives in
//! [`nornir_testmatrix::audit_citations`], so repos reuse it rather than growing a
//! private twin of it.
//!
//! It is deliberately run against the whole edda checkout rather than one crate:
//! a phantom citation in the repo that owns the shared test tooling is inherited
//! by everyone who reads that tooling to learn the pattern.

use std::path::{Path, PathBuf};

use nornir_testmatrix::{audit_citations, sibling_checkouts};

/// crates/nornir-testmatrix/ -> the edda repo root.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate sits two levels below the repo root")
        .to_path_buf()
}

#[test]
fn no_comment_cites_a_test_file_that_does_not_exist() {
    let root = repo_root();
    // Sibling checkouts count: a comment here naming `tests/viz_surface.rs` means
    // nornir's file, and that is a legitimate cross-repo pointer, not a phantom.
    let rep = audit_citations(&root, &sibling_checkouts(&root));

    assert!(
        rep.is_trustworthy(),
        "the audit examined ZERO citations in {} — that is a broken scan, not a clean repo",
        root.display()
    );
    assert!(rep.phantoms.is_empty(), "{}", rep.summary());
}
