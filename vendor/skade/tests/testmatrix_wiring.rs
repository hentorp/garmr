//! L4 wiring proof for the published `nornir-testmatrix` crate.
//!
//! The whole file is gated on the `testmatrix` feature: `nornir-testmatrix` is
//! an OPTIONAL dependency (linked only under `--features testmatrix`), so a
//! plain `cargo test` must compile this file down to nothing rather than fail
//! on the unresolved `nornir_testmatrix` import. Run the proof with
//! `cargo test --features testmatrix`.
//!
//! This is an INJECT-AND-ASSERT test (project LAW): it feeds canned
//! `TestResultRow`s — varied status / aspect / metric — through the real
//! `JsonFileSink` round-trip and the `summarize_runs` + `render_matrix`
//! renderers, then asserts on the REAL output (counts, surviving fields, the
//! red marker in the grid). It runs fast and fully offline: NO cargo
//! subprocess, no network. It proves skade can build against the crate AND
//! that the crate's core data path works from this repo.

#![cfg(feature = "testmatrix")]

use nornir_testmatrix::{
    JsonFileSink, TestResultRow, TestSink, render_matrix, status, summarize_runs,
};

/// A fixed run's worth of canned rows spanning several aspects, statuses and
/// metric values. `ts_micros` is shared (one run); the run_id groups them.
fn canned_rows() -> Vec<TestResultRow> {
    let run_id = "run-L4-skade-0001";
    let repo = "skade-katalog";
    let ts = 1_700_000_000_000_000_i64;
    let mk = |suite: &str, name: &str, st: &str, aspect: &str, metric: f64, msg: &str| {
        let mut r = TestResultRow::unit(run_id, repo, suite, name, st, 12.5, ts, msg);
        r.aspect = aspect.to_string();
        r.metric = metric;
        r
    };
    vec![
        mk(
            "catalog",
            "commit_table_roundtrip",
            status::PASS,
            "unit",
            0.0,
            "",
        ),
        mk("build", "build", status::PASS, "build", 0.0, ""),
        // a genuinely red case — this MUST surface as ✗ in the matrix.
        mk(
            "clippy",
            "clippy",
            status::FAIL,
            "clippy",
            7.0,
            "7 warnings denied",
        ),
        mk(
            "time_travel",
            "snapshot_skip",
            status::IGNORED,
            "unit",
            0.0,
            "needs fixture",
        ),
        mk("coverage", "coverage", status::PASS, "coverage", 84.3, ""),
    ]
}

#[test]
fn testmatrix_roundtrip_and_render_inject_assert() {
    let rows = canned_rows();

    // ── 1. JsonFileSink round-trip: append then read_all must return the SAME
    //       rows, with aspect + metric surviving serde. ──────────────────────
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("quality-matrix.jsonl");
    let sink = JsonFileSink::new(&path);
    sink.append(&rows).expect("append rows");

    let read_back = sink.read_all().expect("read_all");
    assert_eq!(read_back.len(), rows.len(), "row count must round-trip");
    assert_eq!(
        read_back, rows,
        "rows must round-trip byte-for-byte (incl. aspect+metric)"
    );

    // The clippy row's metric (7 warnings) and aspect must have survived.
    let clippy = read_back
        .iter()
        .find(|r| r.test_name == "clippy")
        .expect("clippy row survives");
    assert_eq!(clippy.aspect, "clippy");
    assert_eq!(clippy.metric, 7.0);
    assert!(status::is_red(&clippy.status), "fail must classify as red");

    let coverage = read_back
        .iter()
        .find(|r| r.aspect == "coverage")
        .expect("coverage row survives");
    assert_eq!(coverage.metric, 84.3, "coverage metric must survive");
    assert!(status::is_green(&coverage.status));

    // ── 2. summarize_runs: exact tallies for the single run. ────────────────
    let summaries = summarize_runs(&read_back);
    assert_eq!(summaries.len(), 1, "exactly one run id");
    let s = &summaries[0];
    assert_eq!(s.passed, 3, "3 pass (unit + build + coverage)");
    assert_eq!(s.failed, 1, "1 fail (clippy)");
    assert_eq!(s.ignored, 1, "1 ignored (snapshot_skip)");
    assert_eq!(s.total(), 5);
    assert!(!s.green(), "a failed run is not green");

    // ── 3. render_matrix: the human grid must contain the red marker AND the
    //       failing aspect/case, plus the repo name. ─────────────────────────
    let grid = render_matrix(&read_back);
    assert!(
        grid.contains('✗'),
        "rendered grid must show a red marker:\n{grid}"
    );
    assert!(
        grid.contains("skade-katalog"),
        "grid names the repo:\n{grid}"
    );
    assert!(
        grid.contains("[clippy]") && grid.contains("clippy::clippy"),
        "grid surfaces the failing clippy case with its aspect:\n{grid}"
    );
    assert!(
        grid.contains("7 warnings denied"),
        "grid carries the failure message:\n{grid}"
    );

    // Feed this wiring test's own real result into the matrix (the engine's
    // functional emitter), gated so release strips it.
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "testmatrix",
        "testmatrix_roundtrip_and_render_inject_assert",
        read_back == rows && s.passed == 3 && s.failed == 1 && grid.contains('✗'),
        &format!(
            "roundtrip {} rows; summary {}p/{}f/{}i; grid shows red marker={}",
            read_back.len(),
            s.passed,
            s.failed,
            s.ignored,
            grid.contains('✗')
        ),
    );
}
