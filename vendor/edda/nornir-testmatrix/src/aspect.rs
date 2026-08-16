//! The **multi-aspect engine** — test MANY aspects of a repo's health, not just
//! its unit tests. Each [`Aspect`] shells the right `cargo` subcommand, parses
//! its result into an [`AspectOutcome`], and emits [`TestResultRow`]s carrying
//! the aspect tag + a numeric `metric` (coverage %, warning count, advisory
//! count …).
//!
//! ## Graceful skip
//! Optional tools (clippy, audit, llvm-cov, hack, fmt) may be absent. When the
//! tool isn't on PATH the aspect records a single neutral `skip` row (see
//! [`status::SKIP`]) with a reason — it never hard-fails the matrix.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::model::{TestResultRow, new_run_id, status};
use crate::runner::{detect_runner, run_matrix};

/// One measurable aspect of a repo's health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Aspect {
    /// `cargo build --all-features` — does it compile?
    Build,
    /// the native test matrix (`run_matrix` — nextest or cargo test).
    Unit,
    /// `cargo test --doc` — do the doctests pass?
    Doctest,
    /// `cargo clippy --all-targets -- -D warnings` — lint clean? (metric = warning count)
    Clippy,
    /// `cargo fmt --check` — formatted?
    Fmt,
    /// `cargo audit` — advisory scan (metric = advisory count; feeds the SBOM).
    Audit,
    /// `cargo bench --no-run` — do the benches at least compile?
    BenchSmoke,
    /// `cargo llvm-cov --summary-only` — line coverage (metric = coverage %).
    Coverage,
    /// `cargo hack check --feature-powerset` — every feature combo compiles.
    FeaturePowerset,
    /// read `rust-version` + `cargo +<msrv> check` if that toolchain is present.
    Msrv,
    /// `cargo build --examples` — do the examples compile?
    Examples,
    /// Run `cargo test --test funnel_decompose -- --test-threads=1` — the offline
    /// funnel task-decomposition simulation (EPIC #45). Uses the real compiler as
    /// judge. Results also written to warehouse `test_results` (aspect "funnel").
    FunnelDecompose,
    /// Run the **funnel demo** injection tests — `cargo test --test funnel_demo
    /// --test funnel_viz` (+ `--features viz` for the viz half). These inject the
    /// deterministic demo DAG (the `🌱 Run demo` button's code path), reopen the
    /// warehouse to prove durability, and assert the exact nodes/edges/ready set
    /// + the viz `state_json` reflects it. The metric is the passing test count;
    /// results land in warehouse `test_results` (aspect "funnel-demo"). This is
    /// the matrix row that PROVES the viz funnel demo button works end-to-end.
    FunnelDemo,
    /// **Functional self-report** — a component's own pass/fail verdict on
    /// whether it actually *works* (e.g. `facett-map / basemap_rendered /
    /// ok=false / "0 ways, blank framebuffer"`), recorded via
    /// [`crate::functional::functional_status`] from the component's
    /// headless-render / self-test path and drained into rows by
    /// [`crate::functional::drain_functional_rows`]. Unlike the other aspects
    /// this one is **not** shelled by [`run_aspect`] (it never spawns cargo);
    /// the component emits the status during its own test, so a broken render
    /// shows up as a RED matrix row WITHOUT anyone eyeballing a GUI. The
    /// status-emission code is gated behind the `testmatrix` cargo feature so
    /// release builds strip it entirely.
    Functional,
    /// **Silenced-test guard** — every `tests/*.rs` whose crate-level
    /// `#![cfg(feature = "X")]` is not satisfied by its crate's `default`
    /// features compiles to an EMPTY test binary and reports `0 tests ... ok`.
    /// [`crate::gatedtests::audit_repo`] walks the workspace, resolves each
    /// crate's transitive `default` closure, and emits a RED row per dark file
    /// unless the repo DECLARES the matrix arm that re-invokes it
    /// (`.nornir/testmatrix-arms.json`). Like [`Aspect::Functional`] it never
    /// runs the tests — it audits which ones can never run. Silence is not
    /// success.
    GatedTests,
}

impl Aspect {
    /// Every aspect, in a stable order (build first, optional/slow last).
    pub const ALL: &'static [Aspect] = &[
        Aspect::Build,
        Aspect::Unit,
        Aspect::Doctest,
        Aspect::Clippy,
        Aspect::Fmt,
        Aspect::Audit,
        Aspect::BenchSmoke,
        Aspect::Coverage,
        Aspect::FeaturePowerset,
        Aspect::Msrv,
        Aspect::Examples,
        Aspect::FunnelDecompose,
        Aspect::FunnelDemo,
        Aspect::Functional,
        Aspect::GatedTests,
    ];

    /// The "sensible default" set — fast, always-useful checks. Skips the slow /
    /// optional aspects (coverage, feature-powerset, msrv, bench-smoke, examples)
    /// unless the caller asks for them.
    pub const DEFAULT: &'static [Aspect] = &[
        Aspect::Build,
        Aspect::Unit,
        Aspect::Doctest,
        Aspect::Clippy,
        Aspect::Fmt,
        Aspect::Audit,
        Aspect::FunnelDecompose,
        Aspect::FunnelDemo,
        Aspect::Functional,
        Aspect::GatedTests,
    ];

    /// The aspect tag stored in [`TestResultRow::aspect`] / parsed by [`parse_aspect`].
    pub fn label(self) -> &'static str {
        match self {
            Aspect::Build => "build",
            Aspect::Unit => "unit",
            Aspect::Doctest => "doctest",
            Aspect::Clippy => "clippy",
            Aspect::Fmt => "fmt",
            Aspect::Audit => "audit",
            Aspect::BenchSmoke => "bench-smoke",
            Aspect::Coverage => "coverage",
            Aspect::FeaturePowerset => "feature-powerset",
            Aspect::Msrv => "msrv",
            Aspect::Examples => "examples",
            Aspect::GatedTests => crate::gatedtests::ASPECT_GATED_TESTS,
            Aspect::FunnelDecompose => "funnel",
            Aspect::FunnelDemo => "funnel-demo",
            Aspect::Functional => "functional",
        }
    }
}

/// Free-function alias for [`Aspect::label`] (handy in the façade).
pub fn aspect_label(a: Aspect) -> &'static str {
    a.label()
}

/// Parse an aspect tag (CLI `--aspects build,unit,clippy`) back to an [`Aspect`].
/// Accepts both `bench-smoke` and `bench_smoke` / `feature-powerset` etc.
pub fn parse_aspect(s: &str) -> Option<Aspect> {
    match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "build" => Some(Aspect::Build),
        "unit" | "test" | "tests" => Some(Aspect::Unit),
        "doctest" | "doc" | "doctests" => Some(Aspect::Doctest),
        "clippy" | "lint" => Some(Aspect::Clippy),
        "fmt" | "format" | "rustfmt" => Some(Aspect::Fmt),
        "audit" => Some(Aspect::Audit),
        "bench-smoke" | "bench" => Some(Aspect::BenchSmoke),
        "coverage" | "cov" => Some(Aspect::Coverage),
        "feature-powerset" | "powerset" | "hack" => Some(Aspect::FeaturePowerset),
        "msrv" => Some(Aspect::Msrv),
        "examples" | "example" => Some(Aspect::Examples),
        "funnel" | "funnel-decompose" | "funnel_decompose" => Some(Aspect::FunnelDecompose),
        "funnel-demo" | "funnel_demo" | "demo" => Some(Aspect::FunnelDemo),
        "functional" | "func" | "self-test" => Some(Aspect::Functional),
        "gated-tests" | "gated" | "silenced" | "silenced-tests" => Some(Aspect::GatedTests),
        _ => None,
    }
}

/// The outcome of running one aspect: its status + metric + a human message, and
/// (for the unit aspect) the per-test rows it expanded into.
#[derive(Debug, Clone, PartialEq)]
pub struct AspectOutcome {
    pub aspect: Aspect,
    /// `pass` | `fail` | `skip` (aspects don't `ignore`; the unit aspect's
    /// per-test rows can be `ignored`/`stalled`).
    pub status: String,
    /// The numeric metric (coverage %, warning count, advisory count; 0.0 = N/A).
    pub metric: f64,
    /// A one-line summary / skip reason / failure detail.
    pub message: String,
    /// Wall-clock duration of the aspect, milliseconds.
    pub duration_ms: f64,
    /// For [`Aspect::Unit`]: the per-test cases. Empty for the other aspects
    /// (which collapse to a single synthetic row).
    pub cases: Vec<TestResultRow>,
}

impl AspectOutcome {
    fn skip(aspect: Aspect, reason: impl Into<String>) -> Self {
        Self {
            aspect,
            status: status::SKIP.into(),
            metric: 0.0,
            message: reason.into(),
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    }
}

/// Run one aspect against the repo rooted at `repo_root`. Never panics on a
/// missing tool — that's a `skip`.
pub fn run_aspect(repo_root: &Path, aspect: Aspect) -> AspectOutcome {
    let t0 = Instant::now();
    let mut outcome = match aspect {
        Aspect::Unit => run_unit(repo_root),
        Aspect::Build => run_cargo_check(repo_root, aspect, &["build", "--all-features"]),
        Aspect::Doctest => run_cargo_check(repo_root, aspect, &["test", "--doc"]),
        Aspect::Examples => run_cargo_check(repo_root, aspect, &["build", "--examples"]),
        Aspect::BenchSmoke => run_cargo_check(repo_root, aspect, &["bench", "--no-run"]),
        Aspect::Clippy => run_clippy(repo_root),
        Aspect::Fmt => run_fmt(repo_root),
        Aspect::Audit => run_audit(repo_root),
        Aspect::Coverage => run_coverage(repo_root),
        Aspect::FeaturePowerset => run_powerset(repo_root),
        Aspect::Msrv => run_msrv(repo_root),
        Aspect::FunnelDecompose => run_funnel_decompose(repo_root),
        Aspect::FunnelDemo => run_funnel_demo(repo_root),
        Aspect::Functional => run_functional(),
        Aspect::GatedTests => run_gated_tests(repo_root),
    };
    if outcome.duration_ms == 0.0 {
        outcome.duration_ms = t0.elapsed().as_secs_f64() * 1000.0;
    }
    outcome
}

/// Run a *set* of aspects and return every [`TestResultRow`] under ONE run id.
/// The unit aspect expands to one row per test case; every other aspect
/// contributes a single synthetic row tagged with its aspect + metric.
pub fn run_full_matrix(repo_root: &Path, aspects: &[Aspect]) -> Vec<TestResultRow> {
    let run_id = new_run_id();
    let ts_micros = now_micros();
    let repo = repo_name(repo_root);
    let mut rows = Vec::new();
    for &aspect in aspects {
        let out = run_aspect(repo_root, aspect);
        rows.extend(outcome_to_rows(&out, &run_id, &repo, ts_micros));
    }
    rows
}

/// Expand one [`AspectOutcome`] into its [`TestResultRow`]s, stamped with the
/// shared run id / repo / timestamp. (Public so a caller that drives aspects
/// itself — e.g. nornir's CLI building one big run across many repos — can reuse
/// the row shaping.)
pub fn outcome_to_rows(
    out: &AspectOutcome,
    run_id: &str,
    repo: &str,
    ts_micros: i64,
) -> Vec<TestResultRow> {
    // Aspects that already carry per-case rows (Unit's per-test rows, Functional's
    // per-component self-reports) restamp each case onto this run, preserving its
    // own suite/test_name/status so a single broken component is its own RED cell.
    if matches!(
        out.aspect,
        Aspect::Unit | Aspect::Functional | Aspect::GatedTests
    ) && !out.cases.is_empty()
    {
        let label = out.aspect.label().to_string();
        return out
            .cases
            .iter()
            .map(|c| TestResultRow {
                run_id: run_id.to_string(),
                repo: repo.to_string(),
                suite: if c.suite.is_empty() {
                    repo.to_string()
                } else {
                    c.suite.clone()
                },
                test_name: c.test_name.clone(),
                status: c.status.clone(),
                duration_ms: c.duration_ms,
                ts_micros,
                message: c.message.clone(),
                aspect: label.clone(),
                metric: c.metric,
            })
            .collect();
    }
    // Every other aspect (or a unit run with no cases) → one synthetic row.
    vec![TestResultRow {
        run_id: run_id.to_string(),
        repo: repo.to_string(),
        suite: repo.to_string(),
        test_name: out.aspect.label().to_string(),
        status: out.status.clone(),
        duration_ms: out.duration_ms,
        ts_micros,
        message: out.message.clone(),
        aspect: out.aspect.label().to_string(),
        metric: out.metric,
    }]
}

// ─── per-aspect runners ─────────────────────────────────────────────────

/// The [`Aspect::Functional`] runner. It NEVER shells cargo — it drains the
/// process-global functional-status buffer ([`crate::functional::drain_functional_rows`])
/// that components filled via [`crate::functional::functional_status`] during
/// their own self-tests (INCLUDING rows the unit aspect folded in from a leaf
/// repo's `--features testmatrix` subprocess), UNION any `NORNIR_TESTMATRIX_OUT`
/// JSONL sink, and folds those into per-component `cases`. The aspect
/// status is `fail` if any drained row is red, `pass` if there is at least one
/// row and none are red, and `skip` when nothing was recorded (e.g. a release
/// build where the `testmatrix` feature stripped every emit).
fn run_functional() -> AspectOutcome {
    // The in-process buffer (nornir's own self-tests + any subprocess rows the
    // unit aspect folded in via `record_rows`) UNION a directly-set
    // `NORNIR_TESTMATRIX_OUT` sink. The latter is a safety net for a subprocess
    // that emitted to a parent-coordinated file outside `run_matrix` (which
    // normally already drained + removed its own per-run file); a missing file is
    // simply empty, so both sources collect without double-counting.
    let mut cases = crate::functional::drain_functional_rows();
    if let Some(path) = std::env::var_os("NORNIR_TESTMATRIX_OUT") {
        let path = std::path::PathBuf::from(path);
        if !path.as_os_str().is_empty() {
            cases.extend(crate::functional::drain_functional_file(&path));
        }
    }
    if cases.is_empty() {
        return AspectOutcome::skip(
            Aspect::Functional,
            "no functional status recorded (build with --features testmatrix and run the self-tests)",
        );
    }
    let red = cases.iter().filter(|c| status::is_red(&c.status)).count();
    let status = if red > 0 { status::FAIL } else { status::PASS };
    AspectOutcome {
        aspect: Aspect::Functional,
        status: status.into(),
        metric: red as f64,
        message: format!("{} functional check(s), {} red", cases.len(), red),
        duration_ms: 0.0,
        cases,
    }
}

/// The [`Aspect::GatedTests`] runner — the **silenced-test guard**. It never
/// runs tests; it audits which ones can never run. Every `tests/*.rs` whose
/// crate-level `#![cfg(feature = …)]` is unsatisfiable under its crate's
/// `default` features, and which no arm declared in
/// `.nornir/testmatrix-arms.json` re-invokes, becomes a RED case row. A repo
/// with no feature-gated test files at all is a neutral `skip` — nothing to
/// guard, never a false green.
fn run_gated_tests(repo_root: &Path) -> AspectOutcome {
    let report = match crate::gatedtests::audit_repo(repo_root, &new_run_id()) {
        Ok(r) => r,
        // `cargo metadata` unavailable / unparsable is a SKIP, never a red —
        // same graceful-degradation contract as a missing clippy.
        Err(e) => {
            return AspectOutcome::skip(
                Aspect::GatedTests,
                &format!("cannot read the workspace feature graph: {e:#}"),
            );
        }
    };
    if report.files.is_empty() {
        return AspectOutcome::skip(
            Aspect::GatedTests,
            &format!(
                "no feature-gated test files ({} test targets scanned)",
                report.scanned
            ),
        );
    }
    let silenced = report.silenced().len();
    AspectOutcome {
        aspect: Aspect::GatedTests,
        status: if silenced > 0 {
            status::FAIL
        } else {
            status::PASS
        }
        .into(),
        metric: report.hidden_tests() as f64,
        message: report.summary(),
        duration_ms: 0.0,
        cases: report.rows(),
    }
}

fn run_unit(repo_root: &Path) -> AspectOutcome {
    let runner = detect_runner();
    match run_matrix(repo_root, runner) {
        Ok(run) => {
            // The unit subprocess (built with `--features testmatrix`) may have
            // emitted functional self-reports into its cross-process sink; fold
            // them into the process-global buffer so the later `Aspect::Functional`
            // runner drains them exactly like an in-process emit. (A no-op in
            // release builds where the buffer is stripped.)
            if !run.functional_rows.is_empty() {
                crate::functional::record_rows(run.functional_rows.clone());
            }
            let run_id = new_run_id();
            let ts = now_micros();
            let repo = repo_name(repo_root);
            let cases: Vec<TestResultRow> = run
                .cases
                .iter()
                .map(|c| TestResultRow {
                    run_id: run_id.clone(),
                    repo: repo.clone(),
                    suite: if c.suite.is_empty() {
                        repo.clone()
                    } else {
                        c.suite.clone()
                    },
                    test_name: c.name.clone(),
                    status: c.status.clone(),
                    duration_ms: c.duration_ms,
                    ts_micros: ts,
                    message: c.message.clone(),
                    aspect: Aspect::Unit.label().to_string(),
                    metric: 0.0,
                })
                .collect();
            let st = if run.green() {
                status::PASS
            } else {
                status::FAIL
            };
            AspectOutcome {
                aspect: Aspect::Unit,
                status: st.into(),
                metric: run.failed() as f64,
                message: format!(
                    "{} passed · {} failed · {} ignored · {} stalled",
                    run.passed(),
                    run.failed(),
                    run.ignored(),
                    run.stalled_count(),
                ),
                duration_ms: 0.0,
                cases,
            }
        }
        Err(e) => AspectOutcome {
            aspect: Aspect::Unit,
            status: status::FAIL.into(),
            metric: 0.0,
            message: format!("could not run tests: {e}"),
            duration_ms: 0.0,
            cases: Vec::new(),
        },
    }
}

/// A plain `cargo <args>` aspect: pass iff exit-zero, fail otherwise. The metric
/// is 0.0; the message carries the first error line on failure.
fn run_cargo_check(repo_root: &Path, aspect: Aspect, args: &[&str]) -> AspectOutcome {
    let out = match run_capture(repo_root, "cargo", args) {
        Ok(o) => o,
        Err(e) => {
            return AspectOutcome {
                aspect,
                status: status::FAIL.into(),
                metric: 0.0,
                message: format!("cargo {} failed to launch: {e}", args.join(" ")),
                duration_ms: 0.0,
                cases: Vec::new(),
            };
        }
    };
    if out.ok {
        AspectOutcome {
            aspect,
            status: status::PASS.into(),
            metric: 0.0,
            message: format!("cargo {} ok", args.join(" ")),
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    } else {
        AspectOutcome {
            aspect,
            status: status::FAIL.into(),
            metric: 0.0,
            message: first_error_line(&out.stderr),
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    }
}

fn run_clippy(repo_root: &Path) -> AspectOutcome {
    if !subcommand_present("clippy") {
        return AspectOutcome::skip(Aspect::Clippy, "cargo-clippy not on PATH");
    }
    match run_capture(
        repo_root,
        "cargo",
        &["clippy", "--all-targets", "--", "-D", "warnings"],
    ) {
        Ok(o) => parse_clippy(o.ok, &o.stderr),
        Err(e) => AspectOutcome {
            aspect: Aspect::Clippy,
            status: status::FAIL.into(),
            metric: 0.0,
            message: format!("clippy failed to launch: {e}"),
            duration_ms: 0.0,
            cases: Vec::new(),
        },
    }
}

/// Count the UNIQUE files `cargo fmt --check` flags. rustfmt prints a
/// `Diff in <path> at line N:` header **once per hunk**, so a file with many
/// hunks appears repeatedly — dedupe on the path to get a true file count.
fn fmt_files_needing_format(stdout: &str, stderr: &str) -> usize {
    stdout
        .lines()
        .chain(stderr.lines())
        .filter_map(|l| l.trim_start().strip_prefix("Diff in "))
        // rustfmt prints one header PER HUNK in two known shapes:
        //   `Diff in /p/f.rs at line 12:`  (older)
        //   `Diff in /p/f.rs:12:`          (newer)
        // Key on the path up to & including `.rs` so all hunks of a file collapse
        // to one entry (rustfmt only ever diffs `.rs` files).
        .filter_map(|rest| rest.find(".rs").map(|i| &rest[..i + 3]))
        .collect::<std::collections::BTreeSet<&str>>()
        .len()
}

fn run_fmt(repo_root: &Path) -> AspectOutcome {
    if !subcommand_present("fmt") {
        return AspectOutcome::skip(Aspect::Fmt, "rustfmt / cargo-fmt not on PATH");
    }
    match run_capture(repo_root, "cargo", &["fmt", "--check"]) {
        Ok(o) => {
            if o.ok {
                AspectOutcome {
                    aspect: Aspect::Fmt,
                    status: status::PASS.into(),
                    metric: 0.0,
                    message: "formatted".into(),
                    duration_ms: 0.0,
                    cases: Vec::new(),
                }
            } else {
                let n = fmt_files_needing_format(&o.stdout, &o.stderr);
                AspectOutcome {
                    aspect: Aspect::Fmt,
                    status: status::FAIL.into(),
                    metric: n as f64,
                    message: format!("{n} file(s) need formatting"),
                    duration_ms: 0.0,
                    cases: Vec::new(),
                }
            }
        }
        Err(e) => AspectOutcome {
            aspect: Aspect::Fmt,
            status: status::FAIL.into(),
            metric: 0.0,
            message: format!("fmt failed to launch: {e}"),
            duration_ms: 0.0,
            cases: Vec::new(),
        },
    }
}

fn run_audit(repo_root: &Path) -> AspectOutcome {
    if !subcommand_present("audit") {
        return AspectOutcome::skip(Aspect::Audit, "cargo-audit not on PATH");
    }
    match run_capture(repo_root, "cargo", &["audit"]) {
        Ok(o) => parse_audit(o.ok, &format!("{}\n{}", o.stdout, o.stderr)),
        Err(e) => AspectOutcome {
            aspect: Aspect::Audit,
            status: status::FAIL.into(),
            metric: 0.0,
            message: format!("audit failed to launch: {e}"),
            duration_ms: 0.0,
            cases: Vec::new(),
        },
    }
}

fn run_coverage(repo_root: &Path) -> AspectOutcome {
    if !subcommand_present("llvm-cov") {
        return AspectOutcome::skip(Aspect::Coverage, "cargo-llvm-cov not on PATH");
    }
    match run_capture(repo_root, "cargo", &["llvm-cov", "--summary-only"]) {
        Ok(o) => parse_coverage(o.ok, &format!("{}\n{}", o.stdout, o.stderr)),
        Err(e) => AspectOutcome {
            aspect: Aspect::Coverage,
            status: status::FAIL.into(),
            metric: 0.0,
            message: format!("llvm-cov failed to launch: {e}"),
            duration_ms: 0.0,
            cases: Vec::new(),
        },
    }
}

fn run_powerset(repo_root: &Path) -> AspectOutcome {
    if !subcommand_present("hack") {
        return AspectOutcome::skip(Aspect::FeaturePowerset, "cargo-hack not on PATH");
    }
    match run_capture(repo_root, "cargo", &["hack", "check", "--feature-powerset"]) {
        Ok(o) => {
            if o.ok {
                AspectOutcome {
                    aspect: Aspect::FeaturePowerset,
                    status: status::PASS.into(),
                    metric: 0.0,
                    message: "every feature combo compiles".into(),
                    duration_ms: 0.0,
                    cases: Vec::new(),
                }
            } else {
                AspectOutcome {
                    aspect: Aspect::FeaturePowerset,
                    status: status::FAIL.into(),
                    metric: 0.0,
                    message: first_error_line(&o.stderr),
                    duration_ms: 0.0,
                    cases: Vec::new(),
                }
            }
        }
        Err(e) => AspectOutcome {
            aspect: Aspect::FeaturePowerset,
            status: status::FAIL.into(),
            metric: 0.0,
            message: format!("hack failed to launch: {e}"),
            duration_ms: 0.0,
            cases: Vec::new(),
        },
    }
}

fn run_msrv(repo_root: &Path) -> AspectOutcome {
    let msrv = match read_rust_version(repo_root) {
        Some(v) => v,
        None => return AspectOutcome::skip(Aspect::Msrv, "no rust-version in Cargo.toml"),
    };
    if !toolchain_present(&msrv) {
        return AspectOutcome::skip(Aspect::Msrv, format!("toolchain {msrv} not installed"));
    }
    let plus = format!("+{msrv}");
    match run_capture(repo_root, "cargo", &[&plus, "check"]) {
        Ok(o) => {
            if o.ok {
                AspectOutcome {
                    aspect: Aspect::Msrv,
                    status: status::PASS.into(),
                    metric: 0.0,
                    message: format!("compiles on declared MSRV {msrv}"),
                    duration_ms: 0.0,
                    cases: Vec::new(),
                }
            } else {
                AspectOutcome {
                    aspect: Aspect::Msrv,
                    status: status::FAIL.into(),
                    metric: 0.0,
                    message: format!(
                        "does NOT compile on declared MSRV {msrv}: {}",
                        first_error_line(&o.stderr)
                    ),
                    duration_ms: 0.0,
                    cases: Vec::new(),
                }
            }
        }
        Err(e) => AspectOutcome {
            aspect: Aspect::Msrv,
            status: status::FAIL.into(),
            metric: 0.0,
            message: format!("msrv check failed to launch: {e}"),
            duration_ms: 0.0,
            cases: Vec::new(),
        },
    }
}

fn run_funnel_decompose(repo_root: &Path) -> AspectOutcome {
    // `cargo test --test funnel_decompose --test funnel_prompt_planner --
    // --test-threads=1` — the offline funnel task-decomposition simulation
    // PLUS the funnel-prompt-planner keystone matrix (prompt-as-mother, the
    // mode gate, accept/reject, auto-assign, migration-safety — both publish
    // `test_results` rows under this SAME `funnel` aspect). No model, no
    // network; the compiler is the oracle. We parse pass/fail counts from the
    // libtest output lines:
    //   `test funnel_decompose_matrix ... ok`  →  pass
    //   `test funnel_decompose_matrix ... FAILED` → fail
    // The metric is `pass_count` (so the grid shows the number of passing
    // pipeline properties, not just green/red).
    let out = match run_capture(
        repo_root,
        "cargo",
        &[
            "test",
            "--test",
            "funnel_decompose",
            "--test",
            "funnel_prompt_planner",
            "--",
            "--test-threads=1",
        ],
    ) {
        Ok(o) => o,
        Err(e) => {
            return AspectOutcome {
                aspect: Aspect::FunnelDecompose,
                status: status::FAIL.into(),
                metric: 0.0,
                message: format!("funnel_decompose test failed to launch: {e}"),
                duration_ms: 0.0,
                cases: Vec::new(),
            };
        }
    };
    let combined = format!(
        "{}
{}",
        out.stdout, out.stderr
    );
    parse_funnel_decompose(out.ok, &combined)
}

/// Run the **funnel demo** injection tests: the `funnel_demo` (data-only golden
/// roundtrip) + `funnel_viz` (the `🌱 Run demo` button's viz path) integration
/// tests. The `funnel_viz` half needs `--features viz`, so we pass it; the
/// `funnel_demo` half ignores it. `NORNIR_VIZ_NO_DURABLE_ACTIONLOG=1` keeps the
/// viz app from holding the catalog's exclusive lock for its lifetime (so the
/// demo's writable `Store::open` succeeds in-process). The metric is the passing
/// test count. Results are written to warehouse `test_results` (aspect
/// "funnel-demo") by the matrix sink — this row PROVES the demo button works.
fn run_funnel_demo(repo_root: &Path) -> AspectOutcome {
    let out = match run_capture(
        repo_root,
        "cargo",
        &[
            "test",
            "--features",
            "viz",
            "--test",
            "funnel_demo",
            "--test",
            "funnel_viz",
            "--",
            "--test-threads=1",
        ],
    ) {
        Ok(o) => o,
        Err(e) => {
            return AspectOutcome {
                aspect: Aspect::FunnelDemo,
                status: status::FAIL.into(),
                metric: 0.0,
                message: format!("funnel_demo tests failed to launch: {e}"),
                duration_ms: 0.0,
                cases: Vec::new(),
            };
        }
    };
    let combined = format!("{}\n{}", out.stdout, out.stderr);
    parse_funnel_demo(out.ok, &combined)
}

/// Parse `cargo test --test funnel_decompose` output into an [`AspectOutcome`].
/// Public so it can be fed canned output by unit tests.
pub fn parse_funnel_decompose(exit_ok: bool, output: &str) -> AspectOutcome {
    let mut pass = 0usize;
    let mut fail = 0usize;
    for line in output.lines() {
        let l = line.trim();
        if l.starts_with("test ") && l.ends_with(" ... ok") {
            pass += 1;
        } else if l.starts_with("test ")
            && (l.ends_with(" ... FAILED") || l.ends_with(" ... failed"))
        {
            fail += 1;
        }
    }
    // Also accept the `N passed` summary line as a fallback when individual
    // lines aren't emitted (e.g. `--nocapture` changes the format).
    if pass == 0 && fail == 0 {
        for line in output.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_suffix(" passed;") {
                let n: usize = rest
                    .split_whitespace()
                    .last()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                pass += n;
            }
            if let Some(rest) = l.strip_suffix(" failed;") {
                let n: usize = rest
                    .split_whitespace()
                    .last()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                fail += n;
            }
            // libtest summary: `test result: ok. N passed; M failed;`
            if l.starts_with("test result:") {
                for part in l.split(';') {
                    let p = part.trim();
                    if let Some(n_str) = p.strip_suffix(" passed") {
                        let n: usize = n_str
                            .trim()
                            .split_whitespace()
                            .last()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        if n > pass {
                            pass = n;
                        }
                    }
                    if let Some(n_str) = p.strip_suffix(" failed") {
                        let n: usize = n_str
                            .trim()
                            .split_whitespace()
                            .last()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        if n > fail {
                            fail = n;
                        }
                    }
                }
            }
        }
    }
    let total = pass + fail;
    if exit_ok && fail == 0 {
        AspectOutcome {
            aspect: Aspect::FunnelDecompose,
            status: status::PASS.into(),
            metric: pass as f64,
            message: format!("funnel decompose: {pass}/{total} pass"),
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    } else {
        AspectOutcome {
            aspect: Aspect::FunnelDecompose,
            status: status::FAIL.into(),
            metric: pass as f64,
            message: if fail > 0 {
                format!("funnel decompose: {pass}/{total} pass, {fail} FAILED")
            } else {
                first_error_line(output)
            },
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    }
}

/// Parse the **funnel demo** injection-test libtest output (PURE; the tests feed
/// it canned output). Counts `... ok` / `... FAILED` lines across the
/// `funnel_demo` + `funnel_viz` binaries, with the same `N passed; M failed;`
/// summary fallback as [`parse_funnel_decompose`]. Pass iff exit-zero AND zero
/// failures; metric = passing test count.
pub fn parse_funnel_demo(exit_ok: bool, output: &str) -> AspectOutcome {
    let mut pass = 0usize;
    let mut fail = 0usize;
    for line in output.lines() {
        let l = line.trim();
        if l.starts_with("test ") && l.ends_with(" ... ok") {
            pass += 1;
        } else if l.starts_with("test ")
            && (l.ends_with(" ... FAILED") || l.ends_with(" ... failed"))
        {
            fail += 1;
        }
    }
    if pass == 0 && fail == 0 {
        for line in output.lines() {
            let l = line.trim();
            if l.starts_with("test result:") {
                for part in l.split(';') {
                    let p = part.trim();
                    if let Some(n_str) = p.strip_suffix(" passed") {
                        let n: usize = n_str
                            .trim()
                            .split_whitespace()
                            .last()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        pass += n;
                    }
                    if let Some(n_str) = p.strip_suffix(" failed") {
                        let n: usize = n_str
                            .trim()
                            .split_whitespace()
                            .last()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        fail += n;
                    }
                }
            }
        }
    }
    let total = pass + fail;
    if exit_ok && fail == 0 {
        AspectOutcome {
            aspect: Aspect::FunnelDemo,
            status: status::PASS.into(),
            metric: pass as f64,
            message: format!("funnel demo: {pass}/{total} injection tests pass"),
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    } else {
        AspectOutcome {
            aspect: Aspect::FunnelDemo,
            status: status::FAIL.into(),
            metric: pass as f64,
            message: if fail > 0 {
                format!("funnel demo: {pass}/{total} pass, {fail} FAILED")
            } else {
                first_error_line(output)
            },
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    }
}

// ─── parsers (PURE — fed canned output by the tests) ────────────────────

/// Parse a clippy run: pass iff exit-zero AND zero `warning:` lines, else fail
/// with the warning count as the metric. (With `-D warnings` clippy already
/// exits non-zero on the first warning, but we still count them for the metric.)
pub fn parse_clippy(exit_ok: bool, stderr: &str) -> AspectOutcome {
    // clippy summary line: `warning: `... and a trailing
    // `warning: `N warnings emitted`` / `error: aborting due to N ...`.
    let warnings = count_clippy_warnings(stderr);
    if exit_ok && warnings == 0 {
        AspectOutcome {
            aspect: Aspect::Clippy,
            status: status::PASS.into(),
            metric: 0.0,
            message: "no clippy warnings".into(),
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    } else {
        AspectOutcome {
            aspect: Aspect::Clippy,
            status: status::FAIL.into(),
            metric: warnings as f64,
            message: format!("{warnings} clippy warning(s)"),
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    }
}

/// Count clippy warnings from stderr. Prefers the explicit summary
/// `warning: N warnings emitted`; else counts distinct `warning:` lead lines
/// (ignoring the `warning: unused` continuation noise is out of scope — the
/// summary line is authoritative when present).
fn count_clippy_warnings(stderr: &str) -> usize {
    for line in stderr.lines() {
        let l = line.trim();
        // `warning: 7 warnings emitted` or `warning: 1 warning emitted`.
        if let Some(rest) = l.strip_prefix("warning: ") {
            if let Some(n_str) = rest
                .strip_suffix(" warnings emitted")
                .or_else(|| rest.strip_suffix(" warning emitted"))
            {
                if let Ok(n) = n_str.trim().parse::<usize>() {
                    return n;
                }
            }
        }
    }
    // No summary line — count `warning:` lead lines as a fallback.
    stderr
        .lines()
        .filter(|l| l.trim_start().starts_with("warning:") && !l.contains("emitted"))
        .count()
}

/// Parse `cargo audit`: pass iff exit-zero and no advisories; else fail with the
/// vulnerability count as the metric. cargo-audit prints
/// `Vulnerabilities found! ... N vulnerabilities found` or
/// `error: N vulnerabilities found!`.
pub fn parse_audit(exit_ok: bool, output: &str) -> AspectOutcome {
    let count = count_audit_advisories(output);
    if exit_ok && count == 0 {
        AspectOutcome {
            aspect: Aspect::Audit,
            status: status::PASS.into(),
            metric: 0.0,
            message: "no advisories".into(),
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    } else {
        AspectOutcome {
            aspect: Aspect::Audit,
            status: status::FAIL.into(),
            metric: count as f64,
            message: format!("{count} advisory/ies found"),
            duration_ms: 0.0,
            cases: Vec::new(),
        }
    }
}

fn count_audit_advisories(output: &str) -> usize {
    for line in output.lines() {
        let l = line.trim().trim_start_matches("error: ");
        // `2 vulnerabilities found!` / `1 vulnerability found!`.
        for suffix in [" vulnerabilities found", " vulnerability found"] {
            if let Some(idx) = l.find(suffix) {
                let prefix = l[..idx]
                    .rsplit(|c: char| !c.is_ascii_digit())
                    .next()
                    .unwrap_or("");
                if let Ok(n) = prefix.parse::<usize>() {
                    return n;
                }
            }
        }
    }
    0
}

/// Parse `cargo llvm-cov --summary-only`. The `TOTAL` row's last percentage is
/// the line-coverage %. Pass iff parsed (any %); the % is the metric. (A
/// threshold gate is the caller's job; the aspect just reports.)
pub fn parse_coverage(exit_ok: bool, output: &str) -> AspectOutcome {
    let pct = parse_total_coverage_pct(output);
    match pct {
        Some(p) if exit_ok => AspectOutcome {
            aspect: Aspect::Coverage,
            status: status::PASS.into(),
            metric: p,
            message: format!("{p:.2}% line coverage"),
            duration_ms: 0.0,
            cases: Vec::new(),
        },
        Some(p) => AspectOutcome {
            aspect: Aspect::Coverage,
            status: status::FAIL.into(),
            metric: p,
            message: format!("coverage ran but cargo exited non-zero ({p:.2}%)"),
            duration_ms: 0.0,
            cases: Vec::new(),
        },
        None => AspectOutcome {
            aspect: Aspect::Coverage,
            status: status::FAIL.into(),
            metric: 0.0,
            message: "could not parse a TOTAL coverage % from llvm-cov output".into(),
            duration_ms: 0.0,
            cases: Vec::new(),
        },
    }
}

/// Pull the line-coverage % from llvm-cov's `TOTAL` summary row. The row looks
/// like (whitespace-separated columns, each region's `count missed cover%`):
/// `TOTAL  1234  56  95.46%  789  10  98.73%  ...` — we take the LAST `NN.NN%`
/// token on the TOTAL line, which llvm-cov puts as the overall line coverage.
fn parse_total_coverage_pct(output: &str) -> Option<f64> {
    let line = output
        .lines()
        .find(|l| l.trim_start().starts_with("TOTAL"))?;
    let mut last = None;
    for tok in line.split_whitespace() {
        if let Some(num) = tok.strip_suffix('%') {
            if let Ok(p) = num.parse::<f64>() {
                last = Some(p);
            }
        }
    }
    last
}

/// First error-ish line of a stderr blob (bounded). The `cargo <thing>` failure
/// detail for the matrix row.
fn first_error_line(stderr: &str) -> String {
    for line in stderr.lines() {
        let l = line.trim();
        if l.starts_with("error") || l.contains("error[") || l.starts_with("Error:") {
            return l.chars().take(240).collect();
        }
    }
    // No clear error line — return the last non-empty line (cargo's summary).
    stderr
        .lines()
        .rev()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .map(|l| l.chars().take(240).collect())
        .unwrap_or_else(|| "failed (no stderr)".into())
}

// ─── host probes + small helpers ────────────────────────────────────────

struct Capture {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run_capture(repo_root: &Path, prog: &str, args: &[&str]) -> std::io::Result<Capture> {
    let out = Command::new(prog)
        .args(args)
        .current_dir(repo_root)
        .stdin(Stdio::null())
        .output()?;
    Ok(Capture {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Is `cargo <sub>` available? Probes `cargo <sub> --version` quietly.
pub fn subcommand_present(sub: &str) -> bool {
    Command::new("cargo")
        .args([sub, "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Is the `+<toolchain>` rustup toolchain installed? Probes `cargo +<tc> --version`.
fn toolchain_present(tc: &str) -> bool {
    let plus = format!("+{tc}");
    Command::new("cargo")
        .args([&plus, "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Read `rust-version` (the declared MSRV) from a repo's root `Cargo.toml`.
/// Pure text scan (no toml dep) — looks for a `rust-version = "X.Y"` /
/// `rust-version = "X.Y.Z"` line in `[package]`.
pub fn read_rust_version(repo_root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(repo_root.join("Cargo.toml")).ok()?;
    parse_rust_version(&text)
}

/// Pure parser for [`read_rust_version`] — fed canned manifest text by tests.
pub fn parse_rust_version(manifest: &str) -> Option<String> {
    for line in manifest.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("rust-version") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let v = rest.trim().trim_matches('"').trim_matches('\'');
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// The repo name = the directory file name of `repo_root` (falls back to the
/// whole path string).
fn repo_name(repo_root: &Path) -> String {
    repo_root
        .file_name()
        .and_then(|f| f.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| repo_root.display().to_string())
}

fn now_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_aspect_round_trips_every_label() {
        for &a in Aspect::ALL {
            assert_eq!(
                parse_aspect(a.label()),
                Some(a),
                "{} round-trips",
                a.label()
            );
        }
        // Aliases.
        assert_eq!(parse_aspect("tests"), Some(Aspect::Unit));
        assert_eq!(parse_aspect("LINT"), Some(Aspect::Clippy));
        assert_eq!(parse_aspect("bench_smoke"), Some(Aspect::BenchSmoke));
        assert_eq!(parse_aspect("nope"), None);
    }

    #[test]
    fn fmt_counts_unique_files_not_hunks() {
        // rustfmt emits a `Diff in <path> at line N:` header PER HUNK — two hunks
        // in a.rs + one in b.rs must count as 2 files, not 3 diff lines.
        let stdout = "\
Diff in /repo/src/a.rs at line 10:
-old
+new
Diff in /repo/src/a.rs at line 42:
-foo
+bar
Diff in /repo/src/b.rs at line 3:
-baz
+qux
";
        assert_eq!(
            fmt_files_needing_format(stdout, ""),
            2,
            "a.rs (2 hunks) + b.rs (1 hunk) = 2 unique files"
        );
        assert_eq!(fmt_files_needing_format("", ""), 0, "clean run = 0 files");
    }

    #[test]
    fn clippy_parser_counts_warnings_from_summary() {
        let stderr = "\
warning: unused variable: `x`
 --> src/a.rs:1:5
warning: this could be simpler
 --> src/b.rs:2:1
warning: 7 warnings emitted
";
        // exit non-zero (clippy -D warnings) AND a summary count → fail, metric 7.
        let o = parse_clippy(false, stderr);
        assert_eq!(o.status, status::FAIL);
        assert_eq!(o.metric, 7.0, "the summary line's count is authoritative");
        assert!(o.message.contains("7 clippy warning"));
    }

    #[test]
    fn clippy_parser_clean_run_passes() {
        let o = parse_clippy(true, "    Checking foo v0.1.0\n    Finished\n");
        assert_eq!(o.status, status::PASS);
        assert_eq!(o.metric, 0.0);
    }

    #[test]
    fn clippy_parser_counts_lead_lines_without_summary() {
        let stderr = "warning: a\nwarning: b\n";
        let o = parse_clippy(false, stderr);
        assert_eq!(o.metric, 2.0, "fallback counts warning: lead lines");
    }

    #[test]
    fn audit_parser_counts_vulnerabilities() {
        let out = "\
Crate:     openssl
error: 2 vulnerabilities found!
";
        let o = parse_audit(false, out);
        assert_eq!(o.status, status::FAIL);
        assert_eq!(o.metric, 2.0);
        assert!(o.message.contains("2 advisory"));
    }

    #[test]
    fn audit_parser_singular_and_clean() {
        let one = parse_audit(false, "1 vulnerability found!");
        assert_eq!(one.metric, 1.0);
        let clean = parse_audit(true, "Success No vulnerable packages found");
        assert_eq!(clean.status, status::PASS);
        assert_eq!(clean.metric, 0.0);
    }

    #[test]
    fn coverage_parser_reads_total_line_pct() {
        let out = "\
Filename                Regions  Missed  Cover  Lines  Missed  Cover
src/lib.rs              100      5       95.00% 200    8       96.00%
TOTAL                   100      5       95.00% 200    8       87.50%
";
        let o = parse_coverage(true, out);
        assert_eq!(o.status, status::PASS);
        assert!(
            (o.metric - 87.50).abs() < 1e-9,
            "last % on TOTAL line = line coverage: {}",
            o.metric
        );
        assert!(o.message.contains("87.50%"));
    }

    #[test]
    fn coverage_parser_no_total_is_fail() {
        let o = parse_coverage(true, "no summary here");
        assert_eq!(o.status, status::FAIL);
        assert_eq!(o.metric, 0.0);
    }

    #[test]
    fn rust_version_parser_extracts_msrv() {
        let manifest = "[package]\nname = \"x\"\nrust-version = \"1.85\"\nedition = \"2021\"\n";
        assert_eq!(parse_rust_version(manifest), Some("1.85".into()));
        assert_eq!(parse_rust_version("[package]\nname=\"x\"\n"), None);
    }

    #[test]
    fn outcome_to_rows_synthetic_aspect_row_carries_metric() {
        let out = AspectOutcome {
            aspect: Aspect::Coverage,
            status: status::PASS.into(),
            metric: 91.3,
            message: "91.30% line coverage".into(),
            duration_ms: 12.0,
            cases: Vec::new(),
        };
        let rows = outcome_to_rows(&out, "run1", "znippy", 100);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].aspect, "coverage");
        assert_eq!(rows[0].test_name, "coverage");
        assert_eq!(rows[0].metric, 91.3);
        assert_eq!(rows[0].repo, "znippy");
        assert_eq!(rows[0].run_id, "run1");
    }

    #[test]
    fn outcome_to_rows_unit_expands_cases() {
        let out = AspectOutcome {
            aspect: Aspect::Unit,
            status: status::FAIL.into(),
            metric: 1.0,
            message: "1 failed".into(),
            duration_ms: 5.0,
            cases: vec![
                TestResultRow::unit("inner", "z", "", "a::ok", status::PASS, 1.0, 9, ""),
                TestResultRow::unit(
                    "inner",
                    "z",
                    "suite",
                    "a::bad",
                    status::FAIL,
                    2.0,
                    9,
                    "boom",
                ),
            ],
        };
        let rows = outcome_to_rows(&out, "run1", "znippy", 100);
        assert_eq!(rows.len(), 2, "unit aspect expands to per-test rows");
        // blank suite defaulted to repo.
        assert_eq!(rows[0].suite, "znippy");
        assert_eq!(rows[1].suite, "suite");
        assert!(
            rows.iter()
                .all(|r| r.run_id == "run1" && r.ts_micros == 100)
        );
        assert!(rows.iter().all(|r| r.aspect == "unit"));
    }

    #[test]
    fn run_aspect_fmt_on_this_worktree_returns_a_row() {
        // Real run: run_aspect(Fmt) against this crate's own dir. fmt may be
        // absent (skip) or present (pass/fail) — in every case we must get a
        // well-formed outcome that expands to exactly one fmt-tagged row, never
        // a panic. (LAW #1: assert real output of a real invocation.)
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = run_aspect(dir, Aspect::Fmt);
        assert_eq!(out.aspect, Aspect::Fmt);
        assert!(
            matches!(
                out.status.as_str(),
                status::PASS | status::FAIL | status::SKIP
            ),
            "fmt outcome is one of pass/fail/skip: {}",
            out.status
        );
        let rows = outcome_to_rows(&out, "r", "nornir-testmatrix", now_micros());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].aspect, "fmt");
        assert_eq!(rows[0].test_name, "fmt");
        assert!(out.duration_ms >= 0.0);
    }

    #[test]
    fn run_full_matrix_one_run_id_across_aspects() {
        // Real run over a couple of cheap-to-skip / fast aspects on this crate.
        // We can't guarantee which tools exist, so pick aspects that always
        // resolve to a row: Fmt (skip or run) + Audit (skip or run). Assert one
        // run id groups all rows.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let rows = run_full_matrix(dir, &[Aspect::Fmt, Aspect::Audit]);
        assert!(!rows.is_empty(), "got rows back");
        let run_ids: std::collections::HashSet<_> = rows.iter().map(|r| r.run_id.clone()).collect();
        assert_eq!(run_ids.len(), 1, "all rows share ONE run id");
        let aspects: std::collections::HashSet<_> = rows.iter().map(|r| r.aspect.clone()).collect();
        assert!(aspects.contains("fmt"));
        assert!(aspects.contains("audit"));
    }

    // ── FunnelDemo aspect (the viz demo-button proof row) ───────────────

    #[test]
    fn funnel_demo_parser_all_pass_counts_both_binaries() {
        // Canned libtest output for the two demo injection-test binaries all
        // green (2 from funnel_demo + 3 from funnel_viz = 5). PURE parser; the
        // matrix feeds it real `cargo test` output at runtime.
        let output = "\
running 2 tests
test inject_demo_is_idempotent ... ok
test inject_demo_roundtrips_to_exact_golden_dag ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 3 tests
test demo_button_injects_dag_into_state_json ... ok
test nuke_confirm_guard_is_two_click ... ok
test nuke_is_disk_only_funnel_persists ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
";
        let o = parse_funnel_demo(true, output);
        assert_eq!(o.aspect, Aspect::FunnelDemo);
        assert_eq!(o.status, status::PASS);
        assert_eq!(o.metric, 5.0, "5 passing demo injection tests");
        assert!(o.message.contains("5/5"), "msg: {}", o.message);
    }

    #[test]
    fn funnel_demo_parser_one_failure_is_fail_with_count() {
        let output = "\
test inject_demo_roundtrips_to_exact_golden_dag ... ok
test demo_button_injects_dag_into_state_json ... FAILED

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
";
        let o = parse_funnel_demo(false, output);
        assert_eq!(o.status, status::FAIL);
        assert_eq!(o.metric, 1.0);
        assert!(o.message.contains("1 FAILED"), "msg: {}", o.message);
    }

    #[test]
    fn funnel_demo_aspect_is_registered_and_parses() {
        // It's in ALL + DEFAULT, has the stable label, and round-trips through
        // parse_aspect (so `nornir test run --aspects funnel-demo` resolves).
        assert!(Aspect::ALL.contains(&Aspect::FunnelDemo));
        assert!(Aspect::DEFAULT.contains(&Aspect::FunnelDemo));
        assert_eq!(Aspect::FunnelDemo.label(), "funnel-demo");
        assert_eq!(parse_aspect("funnel-demo"), Some(Aspect::FunnelDemo));
        assert_eq!(parse_aspect("funnel_demo"), Some(Aspect::FunnelDemo));
        assert_eq!(parse_aspect("demo"), Some(Aspect::FunnelDemo));
        // And it expands to exactly one "funnel-demo"-tagged synthetic row.
        let out = parse_funnel_demo(true, "test x ... ok\ntest result: ok. 1 passed; 0 failed;");
        let rows = outcome_to_rows(&out, "r", "nornir", now_micros());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].aspect, "funnel-demo");
    }

    #[test]
    fn functional_aspect_is_registered_and_parses() {
        assert!(Aspect::ALL.contains(&Aspect::Functional));
        assert!(Aspect::DEFAULT.contains(&Aspect::Functional));
        assert_eq!(Aspect::Functional.label(), "functional");
        assert_eq!(parse_aspect("functional"), Some(Aspect::Functional));
        assert_eq!(parse_aspect("func"), Some(Aspect::Functional));
    }

    /// The full matrix path, feature ON: a component emits a RED functional
    /// status → `run_aspect(Functional)` drains it → `outcome_to_rows` shapes a
    /// RED `TestResultRow` (suite=component, aspect=functional) the matrix reads
    /// back. This is the "broken render = RED row, no GUI" proof.
    #[cfg(feature = "testmatrix")]
    #[test]
    fn functional_aspect_drains_emitted_red_status_into_red_matrix_row() {
        use crate::functional::{drain_functional_rows, functional_status, test_lock};
        use std::path::Path;
        // Serialize + clear so the drained set is exactly our one record.
        let _guard = test_lock();
        let _ = drain_functional_rows();
        functional_status(
            "facett-map",
            "basemap_rendered",
            false,
            "0 ways, blank framebuffer",
        );
        // The aspect runner drains + folds; run_aspect never shells cargo here.
        let out = run_aspect(Path::new("."), Aspect::Functional);
        assert_eq!(out.status, status::FAIL, "any red drained → aspect is FAIL");
        assert_eq!(out.metric, 1.0, "one red check");
        let rows = outcome_to_rows(&out, "runX", "nornir", 4242);
        let red: Vec<_> = rows
            .iter()
            .filter(|r| r.test_name == "basemap_rendered")
            .collect();
        assert_eq!(red.len(), 1, "exactly the emitted check as its own row");
        assert_eq!(red[0].suite, "facett-map", "component → suite");
        assert_eq!(red[0].aspect, "functional");
        assert_eq!(red[0].status, status::FAIL);
        assert!(status::is_red(&red[0].status), "matrix reads it as RED");
        assert_eq!(red[0].message, "0 ways, blank framebuffer");
        assert_eq!(red[0].run_id, "runX", "restamped onto the run");
        assert_eq!(red[0].repo, "nornir");
        assert_eq!(red[0].ts_micros, 4242);
    }

    /// Full matrix path, feature ON, GREEN: an `ok=true` emit drains to a PASS
    /// row and the aspect summary is green when nothing red is in the set.
    #[cfg(feature = "testmatrix")]
    #[test]
    fn functional_aspect_green_when_all_checks_ok() {
        use crate::functional::{drain_functional_rows, functional_status, test_lock};
        use std::path::Path;
        let _guard = test_lock();
        let _ = drain_functional_rows();
        functional_status("facett-map", "basemap_rendered", true, "1024 ways drawn");
        let out = run_aspect(Path::new("."), Aspect::Functional);
        assert_eq!(out.status, status::PASS, "no red → aspect PASS");
        assert_eq!(out.metric, 0.0);
        let rows = outcome_to_rows(&out, "runG", "nornir", 7);
        let mine: Vec<_> = rows
            .iter()
            .filter(|r| r.test_name == "basemap_rendered")
            .collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].status, status::PASS);
        assert!(status::is_green(&mine[0].status));
    }

    /// Feature OFF (release): `run_aspect(Functional)` drains nothing → a neutral
    /// `skip` row, never a false red/green and never a warehouse write.
    #[cfg(not(feature = "testmatrix"))]
    #[test]
    fn functional_aspect_is_skip_noop_in_release() {
        use std::path::Path;
        let out = run_aspect(Path::new("."), Aspect::Functional);
        assert_eq!(out.status, status::SKIP, "release: nothing recorded → skip");
        assert!(out.cases.is_empty(), "no rows compiled/written in release");
        let rows = outcome_to_rows(&out, "r", "nornir", 1);
        // The single synthetic row is a neutral skip — never red, never green.
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, status::SKIP);
        assert!(status::is_neutral(&rows[0].status));
    }
}
