//! **Functional-status mode** — a component reports whether it *actually works*.
//!
//! The other aspects ([`crate::Aspect`]) shell `cargo` and judge a repo from the
//! outside. This one lets a component judge ITSELF from the inside: during its
//! headless-render / self-test path a component calls
//! [`functional_status`]`(component, check, ok, detail)` to record e.g.
//! `facett-map / basemap_rendered / ok=false / "0 ways, blank framebuffer"`. The
//! [`Aspect::Functional`](crate::Aspect::Functional) runner drains those records
//! ([`drain_functional_rows`]) into [`TestResultRow`]s so a broken render shows
//! up as a **RED matrix row** in `nornir test` / the viz 🧪 Test pane —
//! *automatically, without anyone looking at a GUI*.
//!
//! ## Release-gating (the whole point)
//! The recording machinery lives behind the **`testmatrix` cargo feature** so a
//! release build pays ZERO cost:
//!
//! * `testmatrix` ON  → [`functional_status`] pushes a record into a
//!   process-global buffer; [`drain_functional_rows`] returns + clears them.
//! * `testmatrix` OFF → [`functional_status`] is an `#[inline]` empty stub that
//!   takes no args by value it can't drop cheaply, touches no global, and
//!   compiles to nothing; [`drain_functional_rows`] returns an empty `Vec`.
//!
//! ```text
//!   #[cfg(feature = "testmatrix")] pub fn functional_status(..) { record }
//!   #[cfg(not(feature = "testmatrix"))] #[inline] pub fn functional_status(..) {} // no-op
//! ```
//!
//! ### Two adoption patterns (a consumer uses ONE per call site)
//! 1. **Cheap detail** — just call it; the stub strips the call in release:
//!    ```ignore
//!    nornir_testmatrix::functional_status("facett-map", "basemap_rendered", ok, "0 ways");
//!    ```
//! 2. **Expensive detail** — if building `detail` costs real work (formatting a
//!    scene dump, counting framebuffer pixels), wrap the WHOLE thing so even the
//!    string-building is stripped in release:
//!    ```ignore
//!    #[cfg(feature = "testmatrix")]
//!    {
//!        let detail = format!("{} ways, {} px lit", scene.way_count(), fb.lit_pixels());
//!        nornir_testmatrix::functional_status("facett-map", "basemap_rendered", ok, &detail);
//!    }
//!    ```

use crate::model::{TestResultRow, status};

/// Build a single functional [`TestResultRow`] (aspect `functional`) for one
/// component's self-reported check. `suite = component`, `test_name = check`,
/// `status = pass|fail`, `message = detail`. PURE — no globals, always
/// available (release too) so the row shape is testable without the feature.
///
/// The `run_id` / `repo` / `ts_micros` are left blank/zero here because the
/// [`Aspect::Functional`](crate::Aspect::Functional) runner restamps every
/// drained row with the run's shared identity (see `outcome_to_rows`).
/// The `aspect` string stamped on every functional-status row.
pub const ASPECT_FUNCTIONAL: &str = "functional";

pub fn functional_row(component: &str, check: &str, ok: bool, detail: &str) -> TestResultRow {
    TestResultRow {
        run_id: String::new(),
        repo: String::new(),
        suite: component.to_string(),
        test_name: check.to_string(),
        status: if ok { status::PASS } else { status::FAIL }.to_string(),
        duration_ms: 0.0,
        ts_micros: 0,
        message: detail.to_string(),
        aspect: "functional".to_string(),
        metric: if ok { 0.0 } else { 1.0 },
    }
}

// ─── feature ON: record into a process-global buffer ────────────────────────

#[cfg(feature = "testmatrix")]
mod recorder {
    use super::functional_row;
    use crate::model::TestResultRow;
    use std::sync::{Mutex, OnceLock};

    fn buffer() -> &'static Mutex<Vec<TestResultRow>> {
        static BUF: OnceLock<Mutex<Vec<TestResultRow>>> = OnceLock::new();
        BUF.get_or_init(|| Mutex::new(Vec::new()))
    }

    /// Record a component's functional self-report (feature ON). Lock poisoning
    /// is recovered from — a panic mid-record must never wedge the matrix.
    ///
    /// Cross-process emit: when `NORNIR_TESTMATRIX_OUT` is set (a leaf repo's
    /// `cargo test --features testmatrix` spawned by the matrix harness), the row
    /// is ALSO appended to that JSONL sink immediately — a subprocess's in-memory
    /// buffer is lost on exit, so the parent reads the rows back from the file.
    /// Stamped with `NORNIR_TESTMATRIX_REPO` so rows scope to the repo under test.
    /// Best-effort: a sink error never wedges the test. With the env unset (normal
    /// in-process runs) this is just the buffer push — no I/O.
    pub fn record(component: &str, check: &str, ok: bool, detail: &str) {
        let row = functional_row(component, check, ok, detail);
        if let Ok(out) = std::env::var("NORNIR_TESTMATRIX_OUT") {
            if !out.is_empty() {
                let mut frow = row.clone();
                if let Ok(repo) = std::env::var("NORNIR_TESTMATRIX_REPO") {
                    if !repo.is_empty() {
                        frow.repo = repo;
                    }
                }
                // Concurrency-safe: cargo runs tests in PARALLEL, so a
                // read-modify-write (JsonFileSink::append) would race and lose
                // rows. O_APPEND of one compact JSON-array line (< PIPE_BUF) is
                // atomic; `JsonFileSink::read_all` flattens each line's array.
                if let Ok(mut line) = serde_json::to_string(std::slice::from_ref(&frow)) {
                    // ONE pre-built buffer → ONE write_all syscall. `writeln!` can
                    // fragment into several write() calls which, under parallel
                    // test threads + O_APPEND, interleave into corrupt lines that
                    // fail to parse. A single <PIPE_BUF append write is atomic.
                    line.push('\n');
                    use std::io::Write;
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&out)
                    {
                        let _ = f.write_all(line.as_bytes());
                    }
                }
            }
        }
        let mut buf = buffer().lock().unwrap_or_else(|p| p.into_inner());
        buf.push(row);
    }

    /// Take + clear every recorded row (feature ON).
    pub fn drain() -> Vec<TestResultRow> {
        let mut buf = buffer().lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut *buf)
    }

    /// Push already-built rows into the buffer (feature ON). Used to fold
    /// functional rows a leaf-repo SUBPROCESS emitted — which the matrix harness
    /// read back from the `NORNIR_TESTMATRIX_OUT` JSONL sink — into the same
    /// process-global buffer the [`Aspect::Functional`](crate::Aspect::Functional)
    /// runner drains, so a subprocess's self-reports land exactly like in-process
    /// ones. Lock poisoning is recovered from.
    pub fn push_rows<I: IntoIterator<Item = TestResultRow>>(rows: I) {
        let mut buf = buffer().lock().unwrap_or_else(|p| p.into_inner());
        buf.extend(rows);
    }
}

/// Record a component's **functional status** for the test matrix.
///
/// `component` is the unit reporting (e.g. `"facett-map"`), `check` is what it
/// verified (e.g. `"basemap_rendered"`), `ok` is the verdict, and `detail` is a
/// short human note (e.g. `"0 ways, blank framebuffer"`). With the `testmatrix`
/// feature ON the record lands in a process-global buffer that the
/// [`Aspect::Functional`](crate::Aspect::Functional) runner drains into matrix
/// rows. With the feature OFF this is an `#[inline]` no-op (see the module-level
/// release-gating note) — nothing is compiled or written.
#[cfg(feature = "testmatrix")]
pub fn functional_status(component: &str, check: &str, ok: bool, detail: &str) {
    recorder::record(component, check, ok, detail);
}

/// No-op stub when the `testmatrix` feature is OFF (release builds). Inlined and
/// empty so the call — and, with the wrap-the-call-site pattern, the detail
/// string-building — is stripped entirely.
#[cfg(not(feature = "testmatrix"))]
#[inline]
pub fn functional_status(_component: &str, _check: &str, _ok: bool, _detail: &str) {}

/// Drain (take + clear) the recorded functional rows. The
/// [`Aspect::Functional`](crate::Aspect::Functional) runner calls this. With the
/// `testmatrix` feature OFF this is an `#[inline]` empty `Vec` — no global, no
/// allocation path compiled in.
#[cfg(feature = "testmatrix")]
pub fn drain_functional_rows() -> Vec<TestResultRow> {
    recorder::drain()
}

/// No-op drain when the `testmatrix` feature is OFF: always empty.
#[cfg(not(feature = "testmatrix"))]
#[inline]
pub fn drain_functional_rows() -> Vec<TestResultRow> {
    Vec::new()
}

/// Fold already-built functional rows into the process-global buffer (feature
/// ON) so the [`Aspect::Functional`](crate::Aspect::Functional) runner drains
/// them alongside in-process emits. The matrix harness uses this to inject the
/// rows a leaf-repo `cargo test --features testmatrix` SUBPROCESS wrote to its
/// `NORNIR_TESTMATRIX_OUT` sink (the in-process buffer of that child is lost on
/// exit, so the parent reads the file and re-records the rows here).
#[cfg(feature = "testmatrix")]
pub fn record_rows<I: IntoIterator<Item = TestResultRow>>(rows: I) {
    recorder::push_rows(rows);
}

/// No-op fold when the `testmatrix` feature is OFF (release builds): there is no
/// buffer to push into, so the rows are dropped — matching the zero-cost stub.
#[cfg(not(feature = "testmatrix"))]
#[inline]
pub fn record_rows<I: IntoIterator<Item = TestResultRow>>(_rows: I) {}

/// Drain the cross-process functional sink at `path` — the JSONL file a leaf
/// repo's `cargo test --features testmatrix` subprocess appended its
/// [`functional_status`] emits to (via `NORNIR_TESTMATRIX_OUT`). Reads every row
/// back (the same JSONL-of-arrays format [`crate::sink::JsonFileSink`] writes),
/// then REMOVES the file so a later drain can't double-count the same run.
/// Always available (pure file I/O, no feature gate) so the runner / aspect
/// engine can collect subprocess emits regardless of how the parent was built. A
/// missing or unreadable file yields an empty `Vec` — collection never hard-fails.
pub fn drain_functional_file(path: &std::path::Path) -> Vec<TestResultRow> {
    let rows = crate::sink::JsonFileSink::new(path.to_path_buf())
        .read_all()
        .unwrap_or_default();
    let _ = std::fs::remove_file(path);
    rows
}

/// Test-only serialization lock for the process-global functional buffer. Tests
/// that emit-then-drain across the whole crate take this so an interleaving
/// drain in another test never steals their records. (Re-used by `aspect.rs`'s
/// functional-aspect tests — same buffer, same lock.)
#[cfg(all(test, feature = "testmatrix"))]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ASPECT_UNIT;

    #[test]
    fn functional_row_maps_ok_false_to_red_fail() {
        // ok=false → a RED fail row the matrix reads as broken, carrying the detail.
        let r = functional_row(
            "facett-map",
            "basemap_rendered",
            false,
            "0 ways, blank framebuffer",
        );
        assert_eq!(r.suite, "facett-map", "component → suite");
        assert_eq!(r.test_name, "basemap_rendered", "check → test_name");
        assert_eq!(r.status, status::FAIL, "ok=false is a fail");
        assert!(
            status::is_red(&r.status),
            "and it reads as RED for the matrix"
        );
        assert_eq!(r.message, "0 ways, blank framebuffer", "detail preserved");
        assert_eq!(r.aspect, "functional");
        assert_eq!(r.metric, 1.0, "one red check");
        // sanity: it is NOT the legacy unit aspect.
        assert_ne!(r.aspect, ASPECT_UNIT);
    }

    #[test]
    fn functional_row_maps_ok_true_to_green_pass() {
        let r = functional_row("facett-map", "basemap_rendered", true, "1024 ways drawn");
        assert_eq!(r.status, status::PASS, "ok=true is a pass");
        assert!(status::is_green(&r.status), "GREEN for the matrix");
        assert!(!status::is_red(&r.status));
        assert_eq!(r.metric, 0.0, "no red checks");
        assert_eq!(r.message, "1024 ways drawn");
    }

    // ── feature ON: emit → drain → it materializes as the matrix sees it ──
    #[cfg(feature = "testmatrix")]
    #[test]
    fn emit_red_then_drain_yields_red_row_and_clears() {
        // Serialize against every other emit/drain test (shared global buffer).
        let _guard = super::test_lock();
        let _ = drain_functional_rows();
        functional_status("facett-map", "drain_red_check", false, "blank framebuffer");
        let rows = drain_functional_rows();
        let mine: Vec<_> = rows
            .iter()
            .filter(|r| r.test_name == "drain_red_check")
            .collect();
        assert_eq!(mine.len(), 1, "exactly the one I emitted");
        assert_eq!(mine[0].status, status::FAIL);
        assert!(status::is_red(&mine[0].status), "broken render = RED row");
        assert_eq!(mine[0].message, "blank framebuffer");
        // Drained → buffer cleared: a re-drain has none of mine.
        let again = drain_functional_rows();
        assert!(
            !again.iter().any(|r| r.test_name == "drain_red_check"),
            "drain clears the buffer"
        );
    }

    #[cfg(feature = "testmatrix")]
    #[test]
    fn emit_green_drains_as_green_row() {
        let _guard = super::test_lock();
        let _ = drain_functional_rows();
        functional_status("facett-map", "drain_green_check", true, "1024 ways");
        let rows = drain_functional_rows();
        let mine: Vec<_> = rows
            .iter()
            .filter(|r| r.test_name == "drain_green_check")
            .collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].status, status::PASS);
        assert!(status::is_green(&mine[0].status));
    }

    // ── feature OFF: prove the release path is a true no-op ──
    #[cfg(not(feature = "testmatrix"))]
    #[test]
    fn release_path_is_a_noop_drain_is_empty() {
        // The emit compiles to nothing; the drain is hard-wired empty regardless
        // of how many times we "record". No global, no write.
        functional_status("facett-map", "basemap_rendered", false, "would be red");
        functional_status("facett-map", "anything", true, "");
        assert!(
            drain_functional_rows().is_empty(),
            "release build records + drains NOTHING — zero matrix write"
        );
    }
}
