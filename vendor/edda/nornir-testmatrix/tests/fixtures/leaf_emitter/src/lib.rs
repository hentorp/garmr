//! Fixture leaf repo for the Step-0 functional-row-landing proof.
//!
//! With the `testmatrix` feature ON (its default), this unit test calls
//! [`nornir_testmatrix::functional_status`] — the REAL recorder. When the matrix
//! runner spawns this repo's `cargo test`, it sets `NORNIR_TESTMATRIX_OUT`, so
//! the emit is appended to that cross-process JSONL sink (the child's in-memory
//! buffer is otherwise lost on exit). The parent reads it back.
//!
//! The check is `ok = false`, so it must materialize as a RED matrix row.

#[cfg(feature = "testmatrix")]
#[test]
fn leaf_reports_a_red_functional_status() {
    // The unit test itself PASSES (it just records); the *functional* verdict it
    // reports is RED. That asymmetry is the whole point — a green unit run can
    // still carry a red functional self-report.
    nornir_testmatrix::functional_status(
        "leaf-emitter",
        "subprocess_render",
        false,
        "blank framebuffer from a leaf subprocess",
    );
}
