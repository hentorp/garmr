//! **Shared test-matrix harness primitives** — the two helpers every repo's
//! `*_matrix.rs` matrix test hand-rolled: run a `cargo` invocation and turn its
//! REAL exit status into an aspect verdict ([`run_cargo`]), and stamp that
//! verdict into a [`TestResultRow`] ([`cell`]).
//!
//! # Why here (L5 / L5a)
//! `holger/xtask/tests/holger_matrix.rs` and `korp/tests/korp_matrix.rs` carried
//! **byte-identical** `run_cargo` bodies, and near-identical `cell` builders that
//! differed only in the hard-coded `repo` string. That is the twin L5 forbids.
//!
//! The home is *this* crate, not `nornir-xtask-support`: `run_cargo` speaks the
//! test-matrix vocabulary — it returns a [`status`] string and a duration that
//! become a matrix cell — so it is coupled to the row schema this crate owns.
//! `nornir-xtask-support` is deliberately **std-only with zero deps by default**
//! (its `run` maps a non-zero exit to `Err`, a different and generic shape);
//! putting a `TestResultRow`-shaped helper there would force it to link
//! `nornir-testmatrix` unconditionally and break that contract. Litmus: "would a
//! third unrelated consumer want this exact thing?" — yes, every repo that
//! publishes a matrix, and what it wants is *this crate's* row.
//!
//! Pure std: no process is spawned unless the caller asks for one, and nothing
//! here touches the warehouse.

use std::path::Path;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::model::{ASPECT_UNIT, TestResultRow, status};

/// Now, in microseconds since the Unix epoch (UTC) — the `ts_micros` stamp a
/// matrix run shares across all of its rows.
#[must_use]
pub fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// Run a cargo invocation in `root`; **pass iff it exits 0**. Returns
/// `(status, duration_ms, message)`: the REAL exit status drives the cell colour
/// (inject-assert friendly — nothing is inferred from parsing stdout), the
/// duration is wall-clock milliseconds, and the message is empty on pass or the
/// last non-blank stderr line (prefixed with the invocation) on fail.
///
/// A spawn failure is a **fail**, not a panic: a missing/blocked `cargo` must
/// show up as a red cell rather than abort the whole matrix run.
#[must_use]
pub fn run_cargo(root: &Path, args: &[&str]) -> (String, f64, String) {
    let t0 = Instant::now();
    let out = Command::new("cargo").args(args).current_dir(root).output();
    let dur = t0.elapsed().as_secs_f64() * 1000.0;
    match out {
        Ok(o) if o.status.success() => (status::PASS.into(), dur, String::new()),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let last = stderr
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("non-zero exit");
            (
                status::FAIL.into(),
                dur,
                format!("cargo {} → {}", args.join(" "), last),
            )
        }
        Err(e) => (status::FAIL.into(), dur, format!("spawn cargo failed: {e}")),
    }
}

/// Stamp one matrix cell: a [`TestResultRow`] for `repo`/`component` in `run_id`,
/// carrying the verdict `st`, the wall-clock `duration_ms`, the failure
/// `message` and the `aspect` the cell belongs to. `ts_micros` is stamped now;
/// `metric` is `0.0` (aspects that measure something set it themselves).
///
/// `repo` is a parameter precisely because it was the ONLY thing that differed
/// between the per-repo copies of this builder.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn cell(
    run_id: &str,
    repo: &str,
    component: &str,
    aspect: &str,
    test_name: &str,
    st: &str,
    duration_ms: f64,
    message: &str,
) -> TestResultRow {
    TestResultRow {
        run_id: run_id.into(),
        repo: repo.into(),
        suite: component.into(),
        test_name: test_name.into(),
        status: st.into(),
        duration_ms,
        ts_micros: now_micros(),
        message: message.into(),
        aspect: if aspect.is_empty() {
            ASPECT_UNIT.into()
        } else {
            aspect.into()
        },
        metric: 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_cargo_reports_the_real_exit_status_not_a_guess() {
        let root = Path::new(".");
        // `cargo --version` exits 0 → PASS, no message.
        let (st, dur, msg) = run_cargo(root, &["--version"]);
        assert_eq!(st, status::PASS, "a zero exit is a pass");
        assert!(msg.is_empty(), "a passing cell carries no failure message");
        assert!(dur >= 0.0, "duration is wall-clock ms");

        // A bogus subcommand exits non-zero → FAIL, with the invocation echoed.
        let (st, _, msg) = run_cargo(root, &["definitely-not-a-cargo-subcommand-9f3a", "--quiet"]);
        assert_eq!(
            st,
            status::FAIL,
            "a non-zero exit is a fail — RED when broken"
        );
        assert!(
            msg.contains("definitely-not-a-cargo-subcommand-9f3a"),
            "the failure message names the invocation: {msg}"
        );
    }

    #[test]
    fn cell_stamps_the_row_the_matrix_reads() {
        let r = cell(
            "run-1",
            "holger",
            "holger-server",
            "unit",
            "holger::lib",
            status::FAIL,
            12.5,
            "boom",
        );
        assert_eq!(r.run_id, "run-1");
        assert_eq!(
            r.repo, "holger",
            "repo is a parameter — the only per-repo difference"
        );
        assert_eq!(r.suite, "holger-server");
        assert_eq!(r.test_name, "holger::lib");
        assert_eq!(r.status, status::FAIL);
        assert_eq!(r.duration_ms, 12.5);
        assert_eq!(r.message, "boom");
        assert_eq!(r.aspect, "unit");
        assert_eq!(r.metric, 0.0);
        assert!(r.ts_micros > 0, "stamped now");

        // An empty aspect falls back to the default unit aspect, never "".
        let d = cell(
            "run-1",
            "korp",
            "korp",
            "",
            "korp::lib",
            status::PASS,
            1.0,
            "",
        );
        assert_eq!(d.aspect, ASPECT_UNIT);
    }
}
