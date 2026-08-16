//! **Standardized test-matrix runner** — wrap a repo's *native* Rust test
//! framework, parse per-test pass/fail + duration, and hand the rows back.
//!
//! ## Why wrap, not reinvent
//! Any plain `#[test]` (incl. the inject-value + snapshot tests THE_BIG_PLAN
//! mandates) is ingested automatically: we run the repo's existing
//! `cargo test` / `cargo nextest run` and read its machine-readable output.
//! There is no bespoke runner to register tests with.
//!
//! ## Runner selection
//! [`detect_runner`] prefers **nextest** (`cargo nextest run
//! --message-format libtest-json`) when the `cargo-nextest` binary is on PATH —
//! it emits one structured JSON line per test event. Otherwise it falls back to
//! parsing the human/default lines of plain `cargo test` (the
//! `test NAME ... ok|FAILED|ignored` grammar), which every Rust toolchain emits.
//! Both paths produce the same [`TestCase`] rows.
//!
//! ## Stall watchdog
//! [`run_matrix`] drives the subprocess through a line-reader thread and a
//! watchdog: if no output arrives for `NORNIR_TEST_STALL_SECS` (default 120),
//! the run is declared **STALLED**, the child is killed, and a single red
//! `stalled` [`TestCase`] is recorded so a hung/crap test is *visible* in the
//! matrix, never silently eating the wall clock.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::model::{parse_cargo_test_list, parse_nextest_list, status};

/// Default stall threshold (seconds of no subprocess output → STALLED).
pub const DEFAULT_STALL_SECS: u64 = 120;

/// The comma-separated cargo feature list to build the unit test subprocess with,
/// from `NORNIR_TEST_FEATURES` (e.g. `testmatrix` to turn on a repo's
/// functional-status self-report rows, or `viz,server`). Empty/unset ⇒ `None`
/// (default feature set). This is the ONE knob that makes
/// `nornir test run … --features testmatrix`-equivalent rows appear: the matrix
/// runner compiles the repo's own `#[test]`s with `--features <list>`, so any
/// `functional_status(...)` emit gated behind `#[cfg(feature = "testmatrix")]`
/// fires and lands as a functional row.
pub fn test_features() -> Option<String> {
    std::env::var("NORNIR_TEST_FEATURES")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Which native runner [`run_matrix`] drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runner {
    /// `cargo nextest run --message-format libtest-json` (structured JSON).
    Nextest,
    /// `cargo test` fallback (terse lines).
    CargoTest,
}

impl Runner {
    pub fn label(self) -> &'static str {
        match self {
            Runner::Nextest => "cargo nextest run",
            Runner::CargoTest => "cargo test",
        }
    }
}

/// One parsed test case: its identity + verdict + duration.
#[derive(Debug, Clone, PartialEq)]
pub struct TestCase {
    /// The crate / test target the case lives in (the suite). Empty if the
    /// runner didn't name one; callers default it to the repo name.
    pub suite: String,
    /// The test function path (`module::path::test_fn`).
    pub name: String,
    /// `pass` | `fail` | `ignored` | `stalled` (see [`crate::model::status`]).
    pub status: String,
    /// Wall-clock duration, milliseconds (`0.0` when the runner gave none).
    pub duration_ms: f64,
    /// Failure / stall detail (`""` = none).
    pub message: String,
}

/// The outcome of a `nornir test` run: the runner used, every parsed case, and
/// whether the watchdog tripped.
#[derive(Debug, Clone)]
pub struct MatrixRun {
    pub runner: Runner,
    pub cases: Vec<TestCase>,
    /// True iff the stall watchdog fired (a synthetic `stalled` case is in `cases`).
    pub stalled: bool,
    /// Functional-status rows the test SUBPROCESS emitted. A leaf repo's
    /// `cargo test --features testmatrix` calls
    /// [`functional_status`](crate::functional::functional_status) from inside the
    /// child process, whose in-memory buffer is lost on exit — so [`run_matrix`]
    /// points the child at a `NORNIR_TESTMATRIX_OUT` JSONL sink and reads those
    /// rows back here. They are NOT in `cases` (those are the unit verdicts); the
    /// aspect engine folds them into the [`Aspect::Functional`](crate::Aspect::Functional)
    /// buffer. Empty when the child emitted nothing (e.g. it wasn't built with the
    /// `testmatrix` feature).
    pub functional_rows: Vec<crate::model::TestResultRow>,
}

impl MatrixRun {
    pub fn passed(&self) -> usize {
        self.cases
            .iter()
            .filter(|c| c.status == status::PASS)
            .count()
    }
    pub fn failed(&self) -> usize {
        self.cases
            .iter()
            .filter(|c| c.status == status::FAIL)
            .count()
    }
    pub fn ignored(&self) -> usize {
        self.cases
            .iter()
            .filter(|c| c.status == status::IGNORED)
            .count()
    }
    pub fn stalled_count(&self) -> usize {
        self.cases
            .iter()
            .filter(|c| c.status == status::STALLED)
            .count()
    }
    /// Green iff no case is red (no `fail`, no `stalled`).
    pub fn green(&self) -> bool {
        !self.cases.iter().any(|c| status::is_red(&c.status))
    }
}

/// Pick the runner: nextest if its binary is discoverable, else plain cargo test.
pub fn detect_runner() -> Runner {
    if nextest_available() {
        Runner::Nextest
    } else {
        Runner::CargoTest
    }
}

/// Is `cargo-nextest` on PATH? Probes `cargo nextest --version`.
fn nextest_available() -> bool {
    Command::new("cargo")
        .args(["nextest", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The stall threshold from `NORNIR_TEST_STALL_SECS` (default
/// [`DEFAULT_STALL_SECS`]). A value of `0` disables the watchdog.
pub fn stall_secs() -> u64 {
    std::env::var("NORNIR_TEST_STALL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_STALL_SECS)
}

/// Whether the HEAVY (`#[ignore]`'d) test arms should run. Default **OFF** —
/// heavy tests (large corpora, network downloads, model fetches, scale matrices)
/// only run on EXPLICIT request, so a plain `nornir test` / `nornir release` /
/// viz "Run full matrix" stays fast and never spins the fans by default.
///
/// Turn it ON with `NORNIR_RUN_HEAVY=1` (the CLI's global `--heavy` flag sets it)
/// or the back-compat `NORNIR_HEAVY_TESTS=1`. The legacy `NORNIR_SKIP_HEAVY` /
/// `--skip-heavy` is now redundant (off IS the default) and is honoured as a
/// no-op, so old scripts/CI don't break.
pub fn heavy_enabled() -> bool {
    let truthy = |v: String| !v.is_empty() && v != "0";
    std::env::var("NORNIR_RUN_HEAVY")
        .map(truthy)
        .unwrap_or(false)
        || matches!(std::env::var("NORNIR_HEAVY_TESTS").as_deref(), Ok("1"))
}

/// Run the test matrix for the repo rooted at `repo_root` with `runner`, parsing
/// every test case and enforcing the stall watchdog. The subprocess inherits
/// `repo_root` as its CWD so each repo's own `[workspace]` is the test scope.
///
/// On a clean exit the parsed cases are returned. On a stall the child is
/// killed, a single synthetic red `stalled` case is appended, and `stalled` is
/// set. A non-zero exit with no parsed failures still yields whatever cases were
/// seen (cargo's own compile errors surface on stderr, not as test rows).
///
/// ## Functional self-reports from the subprocess
/// A repo built with `--features testmatrix` (via [`test_features`]) calls
/// [`functional_status`](crate::functional::functional_status) from inside its
/// own `#[test]`s — but that runs in the cargo CHILD process, whose in-memory
/// buffer is lost on exit. So we point the child at a per-run JSONL sink
/// (`NORNIR_TESTMATRIX_OUT`) stamped with `NORNIR_TESTMATRIX_REPO`, and after the
/// run read those rows back into [`MatrixRun::functional_rows`]. Without this the
/// `Aspect::Functional` runner would collect NOTHING from a leaf repo.
pub fn run_matrix(repo_root: &Path, runner: Runner) -> std::io::Result<MatrixRun> {
    let mut cmd = Command::new("cargo");
    match runner {
        Runner::Nextest => {
            // `--message-format libtest-json` needs the nextest-experimental flag.
            cmd.args(["nextest", "run", "--message-format", "libtest-json"])
                .env("NEXTEST_EXPERIMENTAL_LIBTEST_JSON", "1");
            // `NORNIR_TEST_FEATURES` (e.g. `testmatrix`) → build the unit tests
            // with those features so functional-status emits fire. (cargo arg, so
            // it goes BEFORE the `--` harness separator nextest doesn't use here.)
            if let Some(feats) = test_features() {
                cmd.args(["--features", &feats]);
            }
            // Heavy arms only run on explicit `--heavy` (default OFF); otherwise
            // the `#[ignore]`'d corpus/network/scale tests stay out of the matrix.
            if heavy_enabled() {
                cmd.args(["--run-ignored", "all"]);
            }
        }
        Runner::CargoTest => {
            // libtest's machine-readable JSON is nightly-only; the *default*
            // human grammar (`test NAME ... ok|FAILED|ignored`) is stable and
            // emitted by every toolchain — that's what `feed_cargo` parses.
            // `--no-fail-fast` so one red target doesn't hide the rest.
            cmd.args(["test", "--no-fail-fast"]);
            // `NORNIR_TEST_FEATURES` → cargo arg, BEFORE the `--` harness separator.
            if let Some(feats) = test_features() {
                cmd.args(["--features", &feats]);
            }
            // `--include-ignored` is a harness arg → after `--`. Default OFF.
            if heavy_enabled() {
                cmd.args(["--", "--include-ignored"]);
            }
        }
    }
    // Per-run cross-process functional sink: the child's `functional_status`
    // emits append here (its own in-memory buffer dies with the process). A fresh
    // unique path per run so concurrent / repeated runs never read each other's
    // rows. Stamp the repo so the drained rows scope to the repo under test.
    let out_path = functional_out_path(repo_root);
    let _ = std::fs::remove_file(&out_path); // start clean (best-effort)
    cmd.env("NORNIR_TESTMATRIX_OUT", &out_path)
        .env("NORNIR_TESTMATRIX_REPO", repo_name(repo_root))
        .current_dir(repo_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");

    // Reader threads push each line down a channel; the main thread folds lines
    // into cases and arms the stall watchdog off the channel's recv timeout.
    let (tx, rx) = mpsc::channel::<String>();
    let tx_err = tx.clone();
    let h_out = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let h_err = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            // Tag stderr so the parser can ignore it for case extraction but the
            // watchdog still counts it as "the process is alive".
            if tx_err.send(format!("\u{1}STDERR\u{1}{line}")).is_err() {
                break;
            }
        }
    });

    let stall = stall_secs();
    let mut parser = Parser::new(runner);
    let mut stalled = false;
    let poll = Duration::from_millis(500);
    let mut last_activity = Instant::now();

    loop {
        match rx.recv_timeout(poll) {
            Ok(line) => {
                last_activity = Instant::now();
                if let Some(rest) = line.strip_prefix("\u{1}STDERR\u{1}") {
                    let _ = rest;
                } else {
                    parser.feed(&line);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if stall > 0 && last_activity.elapsed() >= Duration::from_secs(stall) {
                    // Watchdog: silence past the threshold → kill + record red.
                    let _ = child.kill();
                    stalled = true;
                    parser.push_stalled(stall);
                    break;
                }
                // Has the child exited (with the channel still draining)? Check.
                if let Ok(Some(_)) = child.try_wait() {
                    while let Ok(line) = rx.try_recv() {
                        if let Some(rest) = line.strip_prefix("\u{1}STDERR\u{1}") {
                            let _ = rest;
                        } else {
                            parser.feed(&line);
                        }
                    }
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Reap the child + reader threads (best-effort).
    let _ = child.wait();
    let _ = h_out.join();
    let _ = h_err.join();

    // Read back (and remove) whatever functional self-reports the child wrote.
    let functional_rows = crate::functional::drain_functional_file(&out_path);

    Ok(MatrixRun {
        runner,
        cases: parser.into_cases(),
        stalled,
        functional_rows,
    })
}

/// The per-run cross-process functional sink path for a [`run_matrix`] of
/// `repo_root` — a unique JSONL file under the system temp dir. Unique per call
/// (random run id) so parallel/repeat runs never collide or read stale rows. The
/// repo name is woven in only as a readable hint.
fn functional_out_path(repo_root: &Path) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "nornir-testmatrix-fn-{}-{}.jsonl",
        repo_name(repo_root),
        crate::model::new_run_id(),
    ))
}

/// The repo name = the directory file name of `repo_root` (falls back to the
/// whole path string). Stamped onto the child's functional rows.
fn repo_name(repo_root: &Path) -> String {
    repo_root
        .file_name()
        .and_then(|f| f.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| repo_root.display().to_string())
}

// ─── list phase (test inventory) ──────────────────────────────────────────

/// **PHASE 1 of `nornir test run`**: discover every `#[test]` in the repo
/// *without running them*, so the matrix can seed a `listed` row per test (=
/// NotRun until it actually runs).
///
/// With **nextest**: `cargo nextest list --message-format json` (one JSON doc,
/// parsed by [`parse_nextest_list`]). Otherwise the **stable libtest fallback**
/// `cargo test -- --list --format terse` (one `name: test` line per item, parsed
/// by [`parse_cargo_test_list`]). The subprocess runs with `repo_root` as CWD so
/// each repo's own `[workspace]` is the scope.
///
/// Returns the fully-qualified `suite::test` names, sorted + deduped. On a
/// launch error or a non-listing toolchain we return an empty inventory (the run
/// phase still records the real verdicts) — discovery never hard-fails the run.
pub fn list_tests(repo_root: &Path, runner: Runner) -> std::io::Result<Vec<String>> {
    let feats = test_features();
    let out = match runner {
        Runner::Nextest => {
            let mut c = Command::new("cargo");
            c.args(["nextest", "list", "--message-format", "json"])
                .env("NEXTEST_EXPERIMENTAL_LIBTEST_JSON", "1");
            if let Some(f) = &feats {
                c.args(["--features", f]);
            }
            c.current_dir(repo_root).stdin(Stdio::null()).output()?
        }
        Runner::CargoTest => {
            let mut c = Command::new("cargo");
            // `--list` enumerates without running; `--format terse` gives the
            // stable `name: test` grammar `parse_cargo_test_list` reads.
            c.args(["test"]);
            if let Some(f) = &feats {
                c.args(["--features", f]);
            }
            c.args(["--", "--list", "--format", "terse"])
                .current_dir(repo_root)
                .stdin(Stdio::null())
                .output()?
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let names = match runner {
        Runner::Nextest => parse_nextest_list(&stdout),
        Runner::CargoTest => parse_cargo_test_list(&stdout),
    };
    Ok(names)
}

// ─── output parsing ──────────────────────────────────────────────────────

/// Incrementally folds runner output lines into [`TestCase`]s. Handles both the
/// nextest libtest-json events and the plain `cargo test` terse grammar.
struct Parser {
    runner: Runner,
    cases: Vec<TestCase>,
    /// Current binary/suite name (cargo test prints `Running ... (target/.../suite-hash)`).
    current_suite: String,
}

impl Parser {
    fn new(runner: Runner) -> Self {
        Self {
            runner,
            cases: Vec::new(),
            current_suite: String::new(),
        }
    }

    fn feed(&mut self, line: &str) {
        match self.runner {
            Runner::Nextest => self.feed_json(line),
            Runner::CargoTest => self.feed_cargo(line),
        }
    }

    /// nextest `--message-format libtest-json`: one JSON object per line, e.g.
    /// `{ "type":"test","event":"ok","name":"suite$mod::case","exec_time":0.01 }`.
    fn feed_json(&mut self, line: &str) {
        let line = line.trim();
        if !line.starts_with('{') {
            return;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            return;
        };
        if v.get("type").and_then(|t| t.as_str()) != Some("test") {
            return;
        }
        let event = v.get("event").and_then(|e| e.as_str()).unwrap_or("");
        let st = match event {
            "ok" => status::PASS,
            "failed" => status::FAIL,
            "ignored" => status::IGNORED,
            _ => return,
        };
        let raw_name = v
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let (suite, name) = match raw_name.split_once('$') {
            Some((s, n)) => (s.to_string(), n.to_string()),
            None => (String::new(), raw_name),
        };
        let duration_ms = v
            .get("exec_time")
            .and_then(|t| t.as_f64())
            .map(|s| s * 1000.0)
            .unwrap_or(0.0);
        let message = v
            .get("stdout")
            .and_then(|s| s.as_str())
            .map(first_failure_line)
            .unwrap_or_default();
        self.cases.push(TestCase {
            suite,
            name,
            status: st.into(),
            duration_ms,
            message,
        });
    }

    /// Plain `cargo test` terse output. Lines of interest:
    ///   `     Running unittests src/lib.rs (target/debug/deps/nornir-abc123)`
    ///   `test my_mod::my_test ... ok`
    ///   `test my_mod::other ... FAILED`
    ///   `test my_mod::skip ... ignored`
    fn feed_cargo(&mut self, line: &str) {
        let t = line.trim();
        if let Some(idx) = t.find("Running ") {
            if let Some(open) = t[idx..].rfind('(') {
                let inside = &t[idx + open + 1..];
                if let Some(close) = inside.find(')') {
                    let path = &inside[..close];
                    self.current_suite = suite_from_path(path);
                }
            }
            return;
        }
        let Some(rest) = t.strip_prefix("test ") else {
            return;
        };
        let Some((name, verdict)) = rest.rsplit_once(" ... ") else {
            return;
        };
        let name = name.trim();
        if name == "result:" || name.is_empty() {
            return;
        }
        let st = match verdict.trim() {
            "ok" => status::PASS,
            "FAILED" => status::FAIL,
            v if v.starts_with("ignored") => status::IGNORED,
            _ => return,
        };
        self.cases.push(TestCase {
            suite: self.current_suite.clone(),
            name: name.to_string(),
            status: st.into(),
            duration_ms: 0.0,
            message: String::new(),
        });
    }

    /// The watchdog tripped: append one synthetic red `stalled` case so the run
    /// is visibly red in the matrix.
    fn push_stalled(&mut self, stall_secs: u64) {
        self.cases.push(TestCase {
            suite: String::new(),
            name: "<test-run>".into(),
            status: status::STALLED.into(),
            duration_ms: (stall_secs as f64) * 1000.0,
            message: format!("no test output for {stall_secs}s — watchdog killed the run"),
        });
    }

    fn into_cases(self) -> Vec<TestCase> {
        self.cases
    }
}

/// Extract a suite name from a cargo test binary path like
/// `target/debug/deps/nornir-3f9a1c…` → `nornir`.
fn suite_from_path(path: &str) -> String {
    let file = Path::new(path)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(path);
    match file.rsplit_once('-') {
        Some((stem, hash)) if hash.chars().all(|c| c.is_ascii_hexdigit()) => stem.to_string(),
        _ => file.to_string(),
    }
}

/// Pull the first meaningful failure line out of a captured stdout blob (the
/// `assertion failed` / `panicked at` line), bounded so a row's message stays small.
fn first_failure_line(stdout: &str) -> String {
    for line in stdout.lines() {
        let l = line.trim();
        if l.contains("panicked at") || l.contains("assertion") || l.starts_with("Error:") {
            return l.chars().take(240).collect();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cargo_test_default_grammar() {
        let mut p = Parser::new(Runner::CargoTest);
        p.feed("     Running unittests src/lib.rs (target/debug/deps/nornir-3f9a1c0011223344)");
        p.feed("test warehouse::tests::round_trip ... ok");
        p.feed("test warehouse::tests::flaky ... FAILED");
        p.feed("test warehouse::tests::skipped ... ignored");
        p.feed("test result: FAILED. 1 passed; 1 failed; 1 ignored");
        let cases = p.into_cases();
        assert_eq!(
            cases.len(),
            3,
            "3 cases parsed, not the summary line: {cases:?}"
        );
        assert_eq!(cases[0].suite, "nornir", "suite from binary path");
        assert_eq!(cases[0].name, "warehouse::tests::round_trip");
        assert_eq!(cases[0].status, status::PASS);
        assert_eq!(cases[1].status, status::FAIL);
        assert_eq!(cases[2].status, status::IGNORED);
    }

    /// Heavy is OFF by default and only opts IN via `NORNIR_RUN_HEAVY`/`--heavy`
    /// (or back-compat `NORNIR_HEAVY_TESTS=1`); the legacy `--skip-heavy` is a
    /// no-op. Injects each env combination and asserts the real verdict.
    /// (nextest runs each test in its own process, so the env writes are isolated.)
    #[test]
    fn heavy_is_opt_in_default_off() {
        let keys = [
            "NORNIR_RUN_HEAVY",
            "NORNIR_HEAVY_TESTS",
            "NORNIR_SKIP_HEAVY",
        ];
        let saved: Vec<(&str, Option<String>)> =
            keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        // TODO: Audit that the environment access only happens in single-threaded code.
        let clear = || keys.iter().for_each(|k| unsafe { std::env::remove_var(k) });

        clear();
        assert!(!heavy_enabled(), "default OFF with no env set");

        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("NORNIR_SKIP_HEAVY", "1") };
        assert!(!heavy_enabled(), "--skip-heavy is a no-op: still OFF");

        clear();
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("NORNIR_RUN_HEAVY", "1") };
        assert!(heavy_enabled(), "--heavy / NORNIR_RUN_HEAVY=1 opts IN");

        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("NORNIR_SKIP_HEAVY", "1") };
        assert!(heavy_enabled(), "--heavy wins even with a stray skip flag");

        clear();
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("NORNIR_HEAVY_TESTS", "1") };
        assert!(heavy_enabled(), "back-compat NORNIR_HEAVY_TESTS=1 opts IN");

        clear();
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("NORNIR_RUN_HEAVY", "0") };
        assert!(!heavy_enabled(), "RUN_HEAVY=0 is falsy → OFF");

        clear();
        for (k, v) in saved {
            match v {
                // TODO: Audit that the environment access only happens in single-threaded code.
                Some(v) => unsafe { std::env::set_var(k, v) },
                // TODO: Audit that the environment access only happens in single-threaded code.
                None => unsafe { std::env::remove_var(k) },
            }
        }
    }

    #[test]
    fn parse_nextest_libtest_json_events() {
        let mut p = Parser::new(Runner::Nextest);
        p.feed(r#"{"type":"suite","event":"started","test_count":2}"#);
        p.feed(r#"{"type":"test","event":"started","name":"nornir::bin$mod::a"}"#);
        p.feed(r#"{"type":"test","event":"ok","name":"nornir::bin$mod::a","exec_time":0.012}"#);
        p.feed(r#"{"type":"test","event":"failed","name":"nornir::bin$mod::b","exec_time":0.5,"stdout":"thread 'x' panicked at src/y.rs:3:1:\nassertion `left == right` failed"}"#);
        let cases = p.into_cases();
        assert_eq!(
            cases.len(),
            2,
            "only the two terminal events become rows: {cases:?}"
        );
        assert_eq!(cases[0].suite, "nornir::bin");
        assert_eq!(cases[0].name, "mod::a");
        assert_eq!(cases[0].status, status::PASS);
        assert!(
            (cases[0].duration_ms - 12.0).abs() < 0.001,
            "exec_time 0.012s → 12ms"
        );
        assert_eq!(cases[1].status, status::FAIL);
        assert!(
            cases[1].message.contains("panicked at"),
            "failure line captured: {:?}",
            cases[1].message
        );
    }

    #[test]
    fn matrix_run_counts_and_green() {
        let cases = vec![
            TestCase {
                suite: "s".into(),
                name: "a".into(),
                status: status::PASS.into(),
                duration_ms: 1.0,
                message: String::new(),
            },
            TestCase {
                suite: "s".into(),
                name: "b".into(),
                status: status::FAIL.into(),
                duration_ms: 2.0,
                message: "boom".into(),
            },
            TestCase {
                suite: "s".into(),
                name: "c".into(),
                status: status::IGNORED.into(),
                duration_ms: 0.0,
                message: String::new(),
            },
        ];
        let run = MatrixRun {
            runner: Runner::CargoTest,
            cases,
            stalled: false,
            functional_rows: Vec::new(),
        };
        assert_eq!((run.passed(), run.failed(), run.ignored()), (1, 1, 1));
        assert!(!run.green(), "a failing case makes the run red");
    }

    #[test]
    fn watchdog_pushes_red_stalled_case() {
        let mut p = Parser::new(Runner::CargoTest);
        p.feed("test s::slow ... ok");
        p.push_stalled(120);
        let cases = p.into_cases();
        assert_eq!(cases.len(), 2);
        let stalled = cases.iter().find(|c| c.status == status::STALLED).unwrap();
        assert!(
            stalled.message.contains("120s"),
            "stall note carries the threshold"
        );
        assert!(status::is_red(&stalled.status), "stalled is a red verdict");
    }

    #[test]
    fn test_features_reads_env_and_trims_blank_to_none() {
        // inject + assert: the env knob that turns on `--features testmatrix` for
        // the remote/local unit subprocess. A guard key keeps this isolated from
        // any ambient value the host may have set.
        let key = "NORNIR_TEST_FEATURES";
        let saved = std::env::var(key).ok();
        // SAFETY: test-local, single-threaded mutation of a process env var.
        unsafe { std::env::set_var(key, "testmatrix,viz") };
        assert_eq!(test_features().as_deref(), Some("testmatrix,viz"));
        unsafe { std::env::set_var(key, "   ") };
        assert_eq!(test_features(), None, "all-whitespace ⇒ no features");
        unsafe { std::env::remove_var(key) };
        assert_eq!(test_features(), None, "unset ⇒ no features");
        // Restore whatever the host had.
        match saved {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    fn suite_from_path_strips_hash() {
        assert_eq!(
            suite_from_path("target/debug/deps/nornir-3f9a1c00"),
            "nornir"
        );
        assert_eq!(
            suite_from_path("target/debug/deps/release_pipeline-aabbcc"),
            "release_pipeline"
        );
        assert_eq!(
            suite_from_path("target/debug/deps/weird_name"),
            "weird_name"
        );
    }

    #[test]
    fn list_tests_discovers_this_crates_own_tests() {
        // Real list phase against this crate's own dir with whatever runner the
        // host has. Discovery must surface THIS test (and its siblings) by name —
        // a real injected expectation, not "didn't panic".
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let runner = detect_runner();
        let names = list_tests(dir, runner).expect("list phase runs");
        assert!(
            !names.is_empty(),
            "the crate has tests to discover: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| n.contains("list_tests_discovers_this_crates_own_tests")),
            "discovery names this very test: {names:?}"
        );
        // Every name is a fully-qualified path (no empty strings, no whitespace).
        assert!(names.iter().all(|n| !n.trim().is_empty()));
    }

    #[test]
    fn detect_runner_returns_a_known_variant() {
        // Real probe of the host: detect_runner must pick one of the two real
        // variants (never panic), whether or not cargo-nextest is installed.
        let r = detect_runner();
        assert!(matches!(r, Runner::Nextest | Runner::CargoTest));
        assert!(!r.label().is_empty());
    }
}
