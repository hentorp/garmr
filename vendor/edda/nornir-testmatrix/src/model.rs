//! The **pure** test-matrix model: rows, summaries, selectors, status tags, and
//! the human/JSON renderers. Zero heavy deps — `std` only (no chrono, no uuid):
//! a tiny RFC3339 formatter + a getrandom-free UUIDv4 keep the crate lean.
//!
//! `nornir` re-exports every item here verbatim (`nornir::warehouse::test_results::*`),
//! and implements the Iceberg writer/reader on top of [`TestResultRow`].

use serde::{Deserialize, Serialize};

/// Canonical status tags for a test/aspect case.
///
/// `STALLED` is the watchdog's verdict for a subprocess that went silent past
/// the stall threshold — recorded red so a hung test is *visible*. `SKIP` is the
/// multi-aspect engine's verdict for an aspect whose tool isn't on PATH
/// (clippy/audit/llvm-cov/hack/fmt may be absent): **neither green nor red** —
/// amber/neutral — so a missing tool never fails the matrix.
pub mod status {
    pub const PASS: &str = "pass";
    pub const FAIL: &str = "fail";
    pub const IGNORED: &str = "ignored";
    pub const STALLED: &str = "stalled";
    /// An aspect whose tool wasn't installed — neutral, never red, never green.
    pub const SKIP: &str = "skip";
    /// A test that the runner **discovered** (via `cargo nextest list` /
    /// `cargo test -- --list`) but has **not yet run** in the latest run. A row
    /// with this status seeds the matrix so an existing-but-unrun test shows as
    /// **NotRun** (blank cell) — never green, never red, and never neutral/skip.
    /// It is overridden by a real `pass`/`fail`/`ignored` row once the test runs.
    pub const LISTED: &str = "listed";

    /// Is this status a red (failing) verdict? `fail` + `stalled` are red;
    /// `pass`, `ignored`, `skip`, and `listed` are not.
    pub fn is_red(s: &str) -> bool {
        s == FAIL || s == STALLED
    }

    /// Is this status the discovery-only `listed` verdict (test exists but has
    /// not run yet → renders as NotRun)? Distinct from `skip` (neutral) so the
    /// grid can blank the cell instead of counting it.
    pub fn is_listed(s: &str) -> bool {
        s == LISTED
    }

    /// Is this status a clean green (counts toward a passing run)? Only `pass`.
    /// `ignored` + `skip` are neutral (neither green nor red).
    pub fn is_green(s: &str) -> bool {
        s == PASS
    }

    /// Is this status neutral (neither green nor red): `ignored` or `skip`.
    pub fn is_neutral(s: &str) -> bool {
        s == IGNORED || s == SKIP
    }
}

/// The default aspect tag for rows that predate the multi-aspect engine (a plain
/// `cargo test` matrix row). Iceberg rows written before the `aspect` column
/// existed read back with this value.
pub const ASPECT_UNIT: &str = "unit";

/// One row of the `test_results` table — a single test case (or aspect result)
/// in a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestResultRow {
    /// The test-run identity (groups a run's rows). One per `nornir test` invocation.
    pub run_id: String,
    /// The workspace repo the tests ran in (partition key).
    pub repo: String,
    /// The crate / test target the case lives in (e.g. `nornir`, `roundtrip`).
    pub suite: String,
    /// The test function name (`module::path::test_fn`), or the aspect's synthetic
    /// case name (e.g. `clippy`, `coverage`).
    pub test_name: String,
    /// `pass` | `fail` | `ignored` | `stalled` | `skip` (see [`status`]).
    pub status: String,
    /// Wall-clock duration of the case, milliseconds. `0.0` when the runner gave none.
    pub duration_ms: f64,
    /// Run time, microseconds since the Unix epoch (UTC). Shared across a run's rows.
    pub ts_micros: i64,
    /// Failure detail / stall note / skip reason (`""` = none, never null).
    pub message: String,
    /// Which **aspect** produced this row: `unit` (default, plain test), `build`,
    /// `doctest`, `clippy`, `fmt`, `audit`, `bench-smoke`, `coverage`,
    /// `feature-powerset`, `msrv`, `examples`. Defaulted to [`ASPECT_UNIT`] so
    /// existing call sites + pre-aspect Iceberg rows stay valid.
    #[serde(default = "default_aspect")]
    pub aspect: String,
    /// A numeric metric the aspect measured: coverage % (coverage), warning count
    /// (clippy), advisory count (audit feeds the SBOM), etc. `0.0` when N/A.
    /// Defaulted to `0.0` so existing call sites + pre-aspect rows stay valid.
    #[serde(default)]
    pub metric: f64,
}

fn default_aspect() -> String {
    ASPECT_UNIT.to_string()
}

impl TestResultRow {
    /// The `(ts_micros, run_id, suite, test_name)` stable sort key. nornir's
    /// Iceberg reader sorts query results by this (Iceberg gives no scan order).
    pub fn key(&self) -> (i64, String, String, String) {
        (
            self.ts_micros,
            self.run_id.clone(),
            self.suite.clone(),
            self.test_name.clone(),
        )
    }

    /// Build a row with `aspect = unit`, `metric = 0.0` — the back-compat
    /// constructor for plain test cases (so existing nornir call sites that built
    /// the struct field-by-field keep their shape via the public fields, while
    /// this is the convenient path).
    #[allow(clippy::too_many_arguments)]
    pub fn unit(
        run_id: impl Into<String>,
        repo: impl Into<String>,
        suite: impl Into<String>,
        test_name: impl Into<String>,
        status: impl Into<String>,
        duration_ms: f64,
        ts_micros: i64,
        message: impl Into<String>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            repo: repo.into(),
            suite: suite.into(),
            test_name: test_name.into(),
            status: status.into(),
            duration_ms,
            ts_micros,
            message: message.into(),
            aspect: ASPECT_UNIT.to_string(),
            metric: 0.0,
        }
    }
}

/// Which test results to read.
#[derive(Debug, Clone)]
pub enum TestSelector {
    /// Exactly one run (its `run_id`).
    Run(String),
    /// Every result whose `repo` matches — across all that repo's runs.
    Repo(String),
    /// Everything in the table.
    All,
}

// ─── test inventory (list phase) ─────────────────────────────────────────

/// Parse `cargo nextest list --message-format json` output into the fully
/// qualified `suite::test_name` strings of every discovered `#[test]`.
///
/// nextest's list JSON is one object with a `rust-suites` map; each suite has a
/// `testcases` map keyed by the test path. We join `<suite>::<case>` so the name
/// matches what the run phase records (`suite` + `test_name`). Robust to extra
/// fields and to the binary having no tests. PURE — fed canned JSON by tests.
pub fn parse_nextest_list(json: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let suites = v.get("rust-suites").and_then(|s| s.as_object());
    if let Some(suites) = suites {
        for (suite_name, suite) in suites {
            // Prefer the suite's `binary-id` (e.g. `nornir::bin`) when present,
            // else the map key.
            let suite_label = suite
                .get("binary-id")
                .and_then(|b| b.as_str())
                .unwrap_or(suite_name.as_str());
            if let Some(cases) = suite.get("testcases").and_then(|c| c.as_object()) {
                for case_name in cases.keys() {
                    out.push(format!("{suite_label}::{case_name}"));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Parse the plain `cargo test -- --list` grammar (the libtest fallback when
/// nextest is absent) into discovered test names. libtest prints one line per
/// item: `module::path::test_fn: test` (and `...: benchmark` for benches, which
/// we drop). PURE — fed canned output by tests.
pub fn parse_cargo_test_list(output: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in output.lines() {
        let l = line.trim();
        // `name: test` — keep tests; skip `: benchmark` and summary lines.
        if let Some(name) = l.strip_suffix(": test") {
            let name = name.trim();
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Turn discovered test names (from [`parse_nextest_list`] /
/// [`parse_cargo_test_list`]) into `listed`-status [`TestResultRow`]s for one run.
///
/// Each name is split on the **last** `::` into `(suite, test_name)` so the row's
/// `suite` matches the run phase; names without `::` keep the whole string as the
/// test name and default the suite to `repo`. All rows share `run_id`, `repo`,
/// `ts_micros`, `aspect = unit`, and `status = listed`. This is the inventory
/// seed: a `listed` row with no later `pass`/`fail` row in the run = **NotRun**.
pub fn listed_rows(
    names: &[String],
    run_id: &str,
    repo: &str,
    ts_micros: i64,
) -> Vec<TestResultRow> {
    names
        .iter()
        .map(|full| {
            let (suite, test_name) = match full.rsplit_once("::") {
                Some((s, n)) if !s.is_empty() => (s.to_string(), n.to_string()),
                _ => (repo.to_string(), full.clone()),
            };
            TestResultRow {
                run_id: run_id.to_string(),
                repo: repo.to_string(),
                suite,
                test_name,
                status: status::LISTED.to_string(),
                duration_ms: 0.0,
                ts_micros,
                message: String::new(),
                aspect: ASPECT_UNIT.to_string(),
                metric: 0.0,
            }
        })
        .collect()
}

// ─── rendering: JSON + human view ────────────────────────────────────────

/// Serialize rows to a stable JSON array (one object per case). Pure string
/// assembly so the renderer stays dependency-light. Carries the new `aspect` +
/// `metric` fields.
pub fn rows_to_json(rows: &[TestResultRow]) -> String {
    fn esc(s: &str) -> String {
        let mut o = String::with_capacity(s.len() + 2);
        for c in s.chars() {
            match c {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str("\\\\"),
                '\n' => o.push_str("\\n"),
                '\t' => o.push_str("\\t"),
                '\r' => o.push_str("\\r"),
                c => o.push(c),
            }
        }
        o
    }
    let mut s = String::from("[\n");
    for (i, r) in rows.iter().enumerate() {
        let ts_rfc = rfc3339_from_micros(r.ts_micros);
        s.push_str(&format!(
            "  {{\"run_id\": \"{}\", \"repo\": \"{}\", \"suite\": \"{}\", \
             \"test_name\": \"{}\", \"status\": \"{}\", \"duration_ms\": {:.3}, \
             \"ts\": \"{}\", \"message\": \"{}\", \"aspect\": \"{}\", \"metric\": {:.3}}}{}\n",
            esc(&r.run_id),
            esc(&r.repo),
            esc(&r.suite),
            esc(&r.test_name),
            esc(&r.status),
            r.duration_ms,
            esc(&ts_rfc),
            esc(&r.message),
            esc(&r.aspect),
            r.metric,
            if i + 1 < rows.len() { "," } else { "" },
        ));
    }
    s.push(']');
    s
}

/// A per-run summary: pass / fail / ignored / stalled / skipped counts for one
/// `run_id`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub repo: String,
    pub ts_micros: i64,
    pub passed: usize,
    pub failed: usize,
    pub ignored: usize,
    pub stalled: usize,
    pub skipped: usize,
    /// Discovered-but-not-run cases (`listed` status). Counted separately so a
    /// listed-only run reads as "N tests known, 0 run", never as red/green.
    pub listed: usize,
}

impl RunSummary {
    /// Total cases recorded in this run.
    pub fn total(&self) -> usize {
        self.passed + self.failed + self.ignored + self.stalled + self.skipped + self.listed
    }
    /// True iff no case is red (no `fail` and no `stalled`). Skips don't count red.
    pub fn green(&self) -> bool {
        self.failed == 0 && self.stalled == 0
    }
}

/// Roll rows up into one [`RunSummary`] per `run_id`, **newest run first**.
pub fn summarize_runs(rows: &[TestResultRow]) -> Vec<RunSummary> {
    use std::collections::BTreeMap;
    let mut by_run: BTreeMap<String, RunSummary> = BTreeMap::new();
    for r in rows {
        let s = by_run
            .entry(r.run_id.clone())
            .or_insert_with(|| RunSummary {
                run_id: r.run_id.clone(),
                repo: r.repo.clone(),
                ts_micros: r.ts_micros,
                ..Default::default()
            });
        s.ts_micros = s.ts_micros.max(r.ts_micros);
        match r.status.as_str() {
            status::PASS => s.passed += 1,
            status::FAIL => s.failed += 1,
            status::IGNORED => s.ignored += 1,
            status::STALLED => s.stalled += 1,
            status::SKIP => s.skipped += 1,
            // `listed` = discovered-but-not-run: counted as not-run, never red.
            status::LISTED => s.listed += 1,
            _ => s.failed += 1, // unknown status counts as red, never silently dropped
        }
    }
    let mut out: Vec<RunSummary> = by_run.into_values().collect();
    out.sort_by(|a, b| b.ts_micros.cmp(&a.ts_micros));
    out
}

/// Serialize a slice of [`RunSummary`] (newest-first) to a pretty JSON array,
/// folding in the derived `green` verdict + `total` count on each row so a
/// consumer never has to recompute them. The canonical wire shape for
/// `nornir test history <repo> --json`'s per-run view and the `test_history`
/// MCP tool (CLI⇄MCP parity). Input order is preserved verbatim.
pub fn runs_to_json(summaries: &[RunSummary]) -> String {
    let arr: Vec<serde_json::Value> = summaries
        .iter()
        .map(|s| {
            serde_json::json!({
                "run_id": s.run_id,
                "repo": s.repo,
                "ts_micros": s.ts_micros,
                "passed": s.passed,
                "failed": s.failed,
                "ignored": s.ignored,
                "stalled": s.stalled,
                "skipped": s.skipped,
                "listed": s.listed,
                "total": s.total(),
                "green": s.green(),
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::Value::Array(arr))
        .unwrap_or_else(|_| "[]".to_string())
}

/// Human-readable matrix: each run's pass/fail counts (newest first), then the
/// red cases under it. The CLI `nornir test history` view.
pub fn render_matrix(rows: &[TestResultRow]) -> String {
    use std::collections::BTreeMap;
    if rows.is_empty() {
        return "(no test runs recorded)\n".to_string();
    }
    let summaries = summarize_runs(rows);
    let mut by_run: BTreeMap<String, Vec<&TestResultRow>> = BTreeMap::new();
    for r in rows {
        by_run.entry(r.run_id.clone()).or_default().push(r);
    }
    let mut out = String::new();
    for s in &summaries {
        let mark = if s.green() { "✓" } else { "✗" };
        let ts = rfc3339_from_micros(s.ts_micros);
        out.push_str(&format!(
            "{mark} {repo}  run {run}  [{ts}]\n     {p} passed · {f} failed · {ig} ignored · {st} stalled · {sk} skipped  ({tot} total)\n",
            repo = s.repo,
            run = short_run(&s.run_id),
            p = s.passed,
            f = s.failed,
            ig = s.ignored,
            st = s.stalled,
            sk = s.skipped,
            tot = s.total(),
        ));
        if let Some(cases) = by_run.get(&s.run_id) {
            for c in cases.iter().filter(|c| status::is_red(&c.status)) {
                let detail = if c.message.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", c.message)
                };
                out.push_str(&format!(
                    "       ✗ [{}] {}::{} {}{}\n",
                    c.aspect, c.suite, c.test_name, c.status, detail
                ));
            }
        }
        out.push('\n');
    }
    out
}

/// Abbreviate a run id for compact display (first 8 chars of a UUID, else whole).
pub fn short_run(run_id: &str) -> String {
    if run_id.len() > 12 {
        format!("{}…", &run_id[..8])
    } else {
        run_id.to_string()
    }
}

/// A fresh run id (UUIDv4 string). Std-only: seeds 16 bytes from a couple of
/// non-deterministic sources (time + a heap address + a thread-local counter)
/// and formats them per RFC 4122 v4 — good enough to group a run's rows; no
/// `uuid`/`getrandom` dep pulled into a leaf repo.
pub fn new_run_id() -> String {
    let mut b = seed_16();
    // Set version (4) and variant (RFC 4122) bits.
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    )
}

// ─── std-only helpers (no uuid / chrono) ────────────────────────────────

/// 16 pseudo-random bytes mixed from nanosecond time, a per-call counter, and a
/// stack address via a SplitMix64 hash. Not cryptographic — only used to make
/// run ids collide-resistant within a process.
fn seed_16() -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let ctr = CTR.fetch_add(1, Ordering::Relaxed);
    let stack = &nanos as *const _ as u64;
    let mut state = nanos ^ ctr.rotate_left(17) ^ stack.rotate_left(31);
    let mut out = [0u8; 16];
    for chunk in out.chunks_mut(8) {
        // SplitMix64.
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    out
}

/// Format a UTC timestamp (microseconds since the Unix epoch) as RFC 3339
/// (`YYYY-MM-DDTHH:MM:SS.ssssss+00:00`). Std-only civil-date math (no chrono).
pub fn rfc3339_from_micros(ts_micros: i64) -> String {
    let secs = ts_micros.div_euclid(1_000_000);
    let micros = ts_micros.rem_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{micros:06}+00:00")
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's civil-date
/// algorithm (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        run: &str,
        repo: &str,
        name: &str,
        st: &str,
        aspect: &str,
        metric: f64,
        ts: i64,
    ) -> TestResultRow {
        TestResultRow {
            run_id: run.into(),
            repo: repo.into(),
            suite: repo.into(),
            test_name: name.into(),
            status: st.into(),
            duration_ms: 1.0,
            ts_micros: ts,
            message: String::new(),
            aspect: aspect.into(),
            metric,
        }
    }

    #[test]
    fn summarize_counts_every_status_including_skip() {
        let rows = vec![
            row("r", "z", "a", status::PASS, "unit", 0.0, 100),
            row("r", "z", "b", status::FAIL, "unit", 0.0, 100),
            row("r", "z", "c", status::IGNORED, "unit", 0.0, 100),
            row("r", "z", "d", status::STALLED, "unit", 0.0, 100),
            row("r", "z", "clippy", status::SKIP, "clippy", 0.0, 100),
        ];
        let s = summarize_runs(&rows);
        assert_eq!(s.len(), 1);
        assert_eq!(
            (
                s[0].passed,
                s[0].failed,
                s[0].ignored,
                s[0].stalled,
                s[0].skipped
            ),
            (1, 1, 1, 1, 1)
        );
        assert_eq!(s[0].total(), 5);
        assert!(!s[0].green(), "a fail makes the run red");
    }

    #[test]
    fn skip_is_neither_red_nor_green() {
        assert!(!status::is_red(status::SKIP));
        assert!(!status::is_green(status::SKIP));
        assert!(status::is_neutral(status::SKIP));
        assert!(status::is_red(status::FAIL));
        assert!(status::is_red(status::STALLED));
        assert!(status::is_green(status::PASS));
    }

    #[test]
    fn summarize_orders_newest_first() {
        let rows = vec![
            row("old", "z", "a", status::PASS, "unit", 0.0, 100),
            row("new", "z", "b", status::PASS, "unit", 0.0, 500),
        ];
        let s = summarize_runs(&rows);
        assert_eq!(s[0].run_id, "new", "newest run id first");
        assert_eq!(s[1].run_id, "old");
    }

    #[test]
    fn runs_to_json_newest_first_with_green_and_total() {
        // Older all-green run + a newer run with one failure → the summary JSON
        // must lead with the newer (red) run and fold in green/total per row.
        let rows = vec![
            row("old", "z", "a", status::PASS, "unit", 0.0, 100),
            row("old", "z", "b", status::PASS, "unit", 0.0, 100),
            row("new", "z", "a", status::PASS, "unit", 0.0, 500),
            row("new", "z", "c", status::FAIL, "unit", 0.0, 500),
        ];
        let summaries = summarize_runs(&rows);
        let json = runs_to_json(&summaries);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2, "one summary per run");
        // Newest (red) first.
        assert_eq!(arr[0]["run_id"], "new");
        assert_eq!(arr[0]["failed"], 1);
        assert_eq!(arr[0]["total"], 2);
        assert_eq!(arr[0]["green"], false, "newest run has a failure");
        // Older run trails and is green.
        assert_eq!(arr[1]["run_id"], "old");
        assert_eq!(arr[1]["passed"], 2);
        assert_eq!(arr[1]["green"], true);
        // RunSummary round-trips through serde (the RPC path relies on this).
        let back: RunSummary =
            serde_json::from_str(&serde_json::to_string(&summaries[0]).unwrap()).unwrap();
        assert_eq!(back, summaries[0]);
    }

    #[test]
    fn json_carries_aspect_and_metric() {
        let rows = vec![row(
            "r",
            "z",
            "coverage",
            status::PASS,
            "coverage",
            87.5,
            100,
        )];
        let json = rows_to_json(&rows);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let o = &v.as_array().unwrap()[0];
        assert_eq!(o["aspect"], "coverage");
        assert_eq!(o["metric"], 87.5);
        assert_eq!(o["status"], "pass");
    }

    #[test]
    fn render_matrix_tags_red_case_with_aspect() {
        let rows = vec![
            row("r", "z", "build", status::FAIL, "build", 0.0, 100),
            row("r", "z", "ok", status::PASS, "unit", 0.0, 100),
        ];
        let m = render_matrix(&rows);
        assert!(
            m.contains("[build]"),
            "red case is tagged with its aspect: {m}"
        );
        assert!(m.contains("1 failed"), "summary line counts the failure");
        assert!(m.contains("skipped"), "summary line names the skip bucket");
    }

    #[test]
    fn rfc3339_is_correct_for_known_epoch() {
        // 2021-01-01T00:00:00Z = 1609459200 s.
        assert_eq!(
            rfc3339_from_micros(1_609_459_200_000_000),
            "2021-01-01T00:00:00.000000+00:00"
        );
        // Unix epoch.
        assert_eq!(rfc3339_from_micros(0), "1970-01-01T00:00:00.000000+00:00");
        // With a sub-second component.
        assert_eq!(
            rfc3339_from_micros(1_609_459_200_123_456),
            "2021-01-01T00:00:00.123456+00:00"
        );
    }

    #[test]
    fn new_run_id_is_uuid_v4_shaped_and_unique() {
        let a = new_run_id();
        let b = new_run_id();
        assert_ne!(a, b, "two ids differ");
        assert_eq!(a.len(), 36, "uuid string length");
        assert_eq!(a.as_bytes()[14], b'4', "version nibble is 4");
        let variant = a.as_bytes()[19];
        assert!(
            matches!(variant, b'8' | b'9' | b'a' | b'b'),
            "RFC4122 variant nibble: {variant}"
        );
    }

    #[test]
    fn unit_constructor_defaults_aspect_and_metric() {
        let r = TestResultRow::unit("r", "z", "z", "t", status::PASS, 5.0, 100, "");
        assert_eq!(r.aspect, ASPECT_UNIT);
        assert_eq!(r.metric, 0.0);
    }

    #[test]
    fn parse_nextest_list_extracts_exact_test_names() {
        // A canned `cargo nextest list --message-format json` blob: two suites,
        // three testcases. We must recover exactly `<binary-id>::<case>` per case.
        let json = r#"{
          "rust-suites": {
            "nornir": {
              "binary-id": "nornir",
              "testcases": {
                "warehouse::tests::round_trip": {"ignored": false},
                "viz::tests::renders": {"ignored": false}
              }
            },
            "roundtrip": {
              "binary-id": "nornir::roundtrip",
              "testcases": {
                "end_to_end": {"ignored": false}
              }
            }
          }
        }"#;
        let names = parse_nextest_list(json);
        assert_eq!(
            names,
            vec![
                "nornir::roundtrip::end_to_end".to_string(),
                "nornir::viz::tests::renders".to_string(),
                "nornir::warehouse::tests::round_trip".to_string(),
            ],
            "exact discovered names, sorted: {names:?}"
        );
    }

    #[test]
    fn parse_nextest_list_handles_empty_and_garbage() {
        assert!(parse_nextest_list("not json").is_empty());
        assert!(parse_nextest_list(r#"{"rust-suites":{}}"#).is_empty());
        assert!(
            parse_nextest_list(r#"{"rust-suites":{"s":{"binary-id":"s","testcases":{}}}}"#)
                .is_empty(),
            "a suite with no testcases yields nothing"
        );
    }

    #[test]
    fn parse_cargo_test_list_keeps_tests_drops_benches() {
        let out = "\
warehouse::tests::round_trip: test
viz::tests::renders: test
bench_throughput: benchmark

2 tests, 1 benchmark
";
        let names = parse_cargo_test_list(out);
        assert_eq!(
            names,
            vec![
                "viz::tests::renders".to_string(),
                "warehouse::tests::round_trip".to_string(),
            ],
            "only `: test` lines, sorted; benchmark + summary dropped: {names:?}"
        );
    }

    #[test]
    fn listed_rows_builds_listed_status_rows_with_split_suite() {
        let names = vec![
            "nornir::warehouse::tests::round_trip".to_string(),
            "bare_name".to_string(),
        ];
        let rows = listed_rows(&names, "run1", "nornir", 4242);
        assert_eq!(rows.len(), 2);
        // qualified name → suite is everything before the last ::, test the tail.
        assert_eq!(rows[0].suite, "nornir::warehouse::tests");
        assert_eq!(rows[0].test_name, "round_trip");
        assert_eq!(rows[0].status, status::LISTED);
        assert_eq!(rows[0].run_id, "run1");
        assert_eq!(rows[0].repo, "nornir");
        assert_eq!(rows[0].ts_micros, 4242);
        assert_eq!(rows[0].aspect, ASPECT_UNIT);
        // bare name (no ::) → suite defaults to repo, whole string is the name.
        assert_eq!(rows[1].suite, "nornir");
        assert_eq!(rows[1].test_name, "bare_name");
        assert_eq!(rows[1].status, status::LISTED);
    }

    #[test]
    fn listed_status_is_not_red_green_or_neutral() {
        assert!(!status::is_red(status::LISTED));
        assert!(!status::is_green(status::LISTED));
        assert!(
            !status::is_neutral(status::LISTED),
            "listed is its own bucket, not skip"
        );
        assert!(status::is_listed(status::LISTED));
    }

    #[test]
    fn summarize_counts_listed_separately_not_as_failed() {
        let rows = vec![
            row("r", "z", "a", status::PASS, "unit", 0.0, 100),
            row("r", "z", "b", status::LISTED, "unit", 0.0, 100),
            row("r", "z", "c", status::LISTED, "unit", 0.0, 100),
        ];
        let s = summarize_runs(&rows);
        assert_eq!(s[0].listed, 2, "listed rows counted in their own bucket");
        assert_eq!(s[0].failed, 0, "listed must NEVER count as a failure");
        assert!(
            s[0].green(),
            "a run of pass + listed is still green (no red)"
        );
        assert_eq!(s[0].total(), 3);
    }

    #[test]
    fn deserialize_legacy_row_without_aspect_defaults() {
        // A pre-aspect JSON row (no aspect/metric) must deserialize with defaults.
        let json = r#"{"run_id":"r","repo":"z","suite":"z","test_name":"t","status":"pass","duration_ms":1.0,"ts_micros":100,"message":""}"#;
        let r: TestResultRow = serde_json::from_str(json).unwrap();
        assert_eq!(r.aspect, ASPECT_UNIT);
        assert_eq!(r.metric, 0.0);
        assert_eq!(r.status, status::PASS);
    }
}
