//! **Step-0 proof — functional-row landing across the test subprocess.**
//!
//! A leaf repo's [`functional_status`](nornir_testmatrix::functional_status) emit
//! happens INSIDE its `cargo test --features testmatrix` child process, whose
//! process-global buffer dies on exit. This test proves the fix: the matrix
//! runner points that child at a `NORNIR_TESTMATRIX_OUT` JSONL sink, reads the
//! rows back ([`MatrixRun::functional_rows`]), and the aspect engine folds them
//! into the `Aspect::Functional` drain — so the leaf's RED self-report lands as a
//! RED matrix row in the PARENT.
//!
//! RED-when-broken / GREEN-when-fixed: before the runner.rs + aspect.rs fix the
//! parent collected NOTHING from the subprocess and both assertions below fail.
//!
//! Gated on `testmatrix` (run with `--features testmatrix`) because it drives the
//! real recorder + the feature-ON aspect drain.
#![cfg(feature = "testmatrix")]

use std::path::PathBuf;

use nornir_testmatrix::{
    Aspect, detect_runner, drain_functional_rows, run_full_matrix, run_matrix, status,
};

/// The standalone leaf fixture crate (its own `[workspace]` + target dir).
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("leaf_emitter")
}

#[test]
fn leaf_functional_status_lands_as_red_matrix_row_through_the_subprocess() {
    let dir = fixture_dir();

    // Build the fixture into a roomy tmpfs target dir, NOT the parent's
    // CARGO_TARGET_DIR — sharing it would contend on the build lock with the
    // outer `cargo test` and pile artifacts onto a possibly near-full project
    // disk. `CARGO_TARGET_DIR` (env) takes precedence over any `.cargo/config`,
    // and the child inherits this process's env. This is the only test in this
    // binary, so the env write is single-threaded.
    let tmp_target = std::env::temp_dir().join("nornir-testmatrix-fixture-target");
    let saved = std::env::var_os("CARGO_TARGET_DIR");
    // SAFETY: single test in this binary ⇒ no concurrent env access.
    unsafe { std::env::set_var("CARGO_TARGET_DIR", &tmp_target) };

    // ── 1. runner.rs: the child's emit is read back into MatrixRun ──────────
    let run = run_matrix(&dir, detect_runner()).expect("the fixture matrix runs");
    let frows: Vec<_> = run
        .functional_rows
        .iter()
        .filter(|r| r.test_name == "subprocess_render")
        .collect();
    assert_eq!(
        frows.len(),
        1,
        "run_matrix reads the subprocess functional sink back (got cases={:?}, functional_rows={:?})",
        run.cases,
        run.functional_rows,
    );
    assert_eq!(
        frows[0].status,
        status::FAIL,
        "the leaf reported ok=false → RED"
    );
    assert!(status::is_red(&frows[0].status));
    assert_eq!(frows[0].suite, "leaf-emitter", "component → suite");
    assert_eq!(
        frows[0].repo, "leaf_emitter",
        "stamped with NORNIR_TESTMATRIX_REPO (the repo dir name)"
    );
    assert_eq!(frows[0].message, "blank framebuffer from a leaf subprocess");

    // ── 2. aspect.rs end-to-end: run_full_matrix([Unit, Functional]) ────────
    // Unit spawns the child + folds its functional rows into the buffer;
    // Functional drains them into the matrix. Clear the buffer first so the only
    // functional rows are the fixture's.
    let _ = drain_functional_rows();
    let rows = run_full_matrix(&dir, &[Aspect::Unit, Aspect::Functional]);
    let red: Vec<_> = rows
        .iter()
        .filter(|r| r.aspect == "functional" && r.test_name == "subprocess_render")
        .collect();
    assert_eq!(
        red.len(),
        1,
        "the leaf's functional self-report is one RED functional matrix row (rows={rows:?})",
    );
    assert_eq!(red[0].status, status::FAIL);
    assert!(status::is_red(&red[0].status), "matrix reads it as RED");
    assert_eq!(red[0].suite, "leaf-emitter");
    assert_eq!(red[0].message, "blank framebuffer from a leaf subprocess");

    // Restore the parent's CARGO_TARGET_DIR.
    // SAFETY: single test in this binary ⇒ no concurrent env access.
    unsafe {
        match saved {
            Some(v) => std::env::set_var("CARGO_TARGET_DIR", v),
            None => std::env::remove_var("CARGO_TARGET_DIR"),
        }
    }
}
