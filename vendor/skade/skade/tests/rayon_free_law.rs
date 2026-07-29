//! Guard test for the constellation's **rayon-free law** and the **one-engine
//! law**, scoped to the `skade` data-plane crate.
//!
//! Rule zero (mirror of znippy-zoomies `tests/rayon_free_law.rs`): the
//! constellation carries no rayon, and there is exactly ONE parallel engine — the
//! `gatling` engine (`gatling_forkjoin` fork-join + the async `gatling::io`
//! sibling), built on `std::thread::scope` + an atomic cursor. skade's data plane
//! must never hand-roll a private work-stealing pool or reach for rayon; every
//! CPU fan-out (Parquet encode/decode) routes through
//! `znippy_zoomies::gatling_forkjoin::gatling_map_owned`.
//!
//! History: skade had gone serial, then grown a rayon layer mislabelled "gatling";
//! the `fix/gatling` remake ripped rayon out and routed every ingest-encode and
//! parallel-read fan-out through the real `gatling_forkjoin` engine. This test
//! mechanically re-checks the claim so a future edit that reaches for rayon OR
//! stands up a private thread pool trips a red test instead of silently
//! re-arming the global pool the law forbids. skade was previously ungated.
//!
//! Scoped to THIS crate's `src/` (`CARGO_MANIFEST_DIR`): the vendored arrow-58
//! iceberg forks under `../vendor/` and the sibling skade-katalog crate are NOT
//! skade's data plane and keep their own upstream patterns, so they are out of
//! scope here.

use std::path::{Path, PathBuf};

/// Strip `//`-to-end-of-line comments so the token scan only sees live code — the
/// module's own `// was rayon …` doc mentions are commentary, not violations.
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Recursively collect every `*.rs` path under `dir`.
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// This crate's `src/` tree (the skade data plane).
fn skade_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn norm(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Tokens that can only appear when **rayon** is actually being *used*. Matched as
/// method calls (`.par_iter(`) so a plain identifier is never a false positive.
const FORBIDDEN_RAYON: &[&str] = &[
    "use rayon",
    "rayon::",
    "extern crate rayon",
    ".into_par_iter(",
    ".par_iter(",
    ".par_iter_mut(",
    ".par_bridge(",
    ".par_chunks(",
    ".par_sort(",
    ".par_sort_by(",
    ".par_sort_unstable(",
    "ParallelIterator",
    "IntoParallelIterator",
];

/// Tokens that stand up a **private worker pool** — the sin the one-engine law
/// forbids anywhere but the leaf `gatling` engine. `thread::spawn` (a detached
/// compute thread), `crossbeam` (scoped/work-steal helpers), rayon's pool
/// builders, and a hand-rolled `thread::scope` worker pool (gatling's own
/// primitive — reinventing it here is banned). Note: `tokio::task::spawn_blocking`
/// does NOT match `thread::spawn`, so the legitimate gatling-on-blocking-thread
/// bridge in `write.rs` is not tripped.
const FORBIDDEN_PRIVATE_POOL: &[&str] = &[
    "thread::spawn",
    "thread::scope",
    "crossbeam",
    "rayon::ThreadPool",
    "ThreadPoolBuilder",
];

#[test]
fn skade_data_plane_is_rayon_free() {
    let mut files = Vec::new();
    rs_files(&skade_src(), &mut files);
    assert!(
        !files.is_empty(),
        "expected to find .rs files under skade/src"
    );

    let mut violations = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        for (lineno, raw) in text.lines().enumerate() {
            let code = strip_line_comment(raw);
            for tok in FORBIDDEN_RAYON {
                if code.contains(tok) {
                    violations.push(format!(
                        "{}:{}: live `{tok}` — {}",
                        norm(file),
                        lineno + 1,
                        code.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "rayon-free law violated (skade's data plane must carry no rayon — route \
         CPU fan-out through `gatling_forkjoin`):\n{}",
        violations.join("\n"),
    );
}

#[test]
fn skade_data_plane_owns_no_private_pool() {
    let mut files = Vec::new();
    rs_files(&skade_src(), &mut files);
    assert!(
        !files.is_empty(),
        "expected to find .rs files under skade/src"
    );

    let mut violations = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        for (lineno, raw) in text.lines().enumerate() {
            let code = strip_line_comment(raw);
            for tok in FORBIDDEN_PRIVATE_POOL {
                if code.contains(tok) {
                    violations.push(format!(
                        "{}:{}: private pool `{tok}` — {}",
                        norm(file),
                        lineno + 1,
                        code.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "one-engine law violated (skade must not hand-roll a worker pool; route \
         decode/encode fan-out through `gatling_forkjoin::gatling_map_owned`, and \
         concurrent async I/O through `gatling::io`):\n{}",
        violations.join("\n"),
    );
}

/// skade's manifest must declare no `rayon` dependency — a transitive re-add would
/// quietly re-arm the global pool the law forbids. Scans dependency-table lines of
/// `skade/Cargo.toml` (comments may freely discuss rayon).
#[test]
fn skade_manifest_declares_no_rayon() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest).expect("read skade Cargo.toml");

    let mut offenders = Vec::new();
    let mut in_deps = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_deps = line.contains("dependencies]");
            continue;
        }
        if !in_deps {
            continue;
        }
        let code = strip_line_comment(line);
        let key = code.split('=').next().unwrap_or("").trim();
        if key == "rayon" {
            offenders.push(format!("{}: {}", norm(&manifest), code.trim()));
        }
    }

    assert!(
        offenders.is_empty(),
        "skade/Cargo.toml declares a rayon dependency (law forbids it):\n{}",
        offenders.join("\n"),
    );
}
