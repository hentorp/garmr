//! Guard test for the constellation's **rayon-free law** and the **one-engine
//! law**, now scoped to the ENTIRE workspace (root crate + every member).
//!
//! Rule zero (`.nornir/design.md`, `.nornir/gatling-guide.md`): the constellation
//! carries no rayon, and there is exactly ONE parallel engine — the leaf
//! `gatling` crate (`gatling` / `gatling_forkjoin` streaming + fork-join pools,
//! built on `std::thread::scope` + an atomic cursor). No codec may hand-roll a
//! private work-stealing pool; every decode fan-out routes through
//! `gatling::gatling_forkjoin::gatling_for_each` (or the streaming `gatling::run`).
//!
//! The `fix/gatling` port made this true across the whole tree: the engine moved
//! into its own leaf crate (so the codecs can depend on it without a cycle), and
//! the last private pools were deleted —
//!   - `lgz::par_map_indexed` (scoped-thread map)          → gatling_for_each
//!   - `lbzip2::par::par_map` (hand-rolled work-steal map)  → gatling_for_each
//!   - `ljar` / `lzip-parallel` `rayon::ThreadPool` + `par_iter` → gatling_for_each
//! and the root `rayon` dep plus the two codec `rayon` deps were dropped.
//!
//! This test mechanically re-checks both claims so a future edit that reaches
//! for rayon OR stands up a private thread pool trips a red test instead of
//! silently falsifying the documented laws. The old `ljar` / `lzip-parallel`
//! carve-out is GONE — those crates are now held to the same law as the rest.
//!
//! Reinvented pools are banned in three flavours: rayon adaptors/deps
//! ([`FORBIDDEN_RAYON`]), detached/work-stealing pools (`thread::spawn`,
//! `thread::Builder`, `crossbeam`, `ThreadPoolBuilder` — [`FORBIDDEN_PRIVATE_POOL`]), and — new
//! here — scoped `std::thread::scope` worker pools ([`FORBIDDEN_SCOPED_POOL`]).
//! `thread::scope` is gatling's own primitive, so it is legal in the engine
//! crate and in a short, enumerated allowlist ([`SCOPED_POOL_ALLOW`]) of
//! pre-gatling algorithms (psort / xml / vtd); a NEW file that hand-rolls one
//! instead of calling `gatling_for_each` trips the guard. As of 2026-07-22 the
//! whole of osm-katana and both static-search-tree builds are OFF that
//! allowlist — the only scope pools left outside the engine are the root
//! crate's sample sort and its VTD/XML scanners.

use std::path::{Path, PathBuf};

/// Strip `//`-to-end-of-line comments from a source line so the token scan only
/// sees live code — the many `// was rayon …` / `//! off rayon` doc mentions are
/// commentary about the law, not violations of it.
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

/// The workspace root (this crate's manifest dir) and every member's `src/`
/// tree. Members are read straight from the root `Cargo.toml` `members = [...]`
/// list, so a newly-added crate is covered automatically (no carve-outs).
fn workspace_src_roots() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut roots = vec![root.join("src")];

    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("read root Cargo.toml");
    // Grab the single-line `members = ["a", "b", …]` array and split out names.
    if let Some(line) = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("members"))
    {
        if let (Some(a), Some(b)) = (line.find('['), line.find(']')) {
            for raw in line[a + 1..b].split(',') {
                let name = raw.trim().trim_matches('"');
                if !name.is_empty() {
                    roots.push(root.join(name).join("src"));
                }
            }
        }
    }
    roots
}

/// Tokens that can only appear when **rayon** is actually being *used*. Forbidden
/// in EVERY crate, no exceptions — the whole tree is rayon-free.
const FORBIDDEN_RAYON: &[&str] = &[
    "use rayon",
    "rayon::",
    "extern crate rayon",
    // Rayon parallel-iterator adaptors, matched as *method calls* (`.par_iter(`)
    // so a plain identifier like `par_sorted` in unrelated code is not a false
    // positive — only an actual rayon call trips the law.
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
/// forbids anywhere but the sanctioned leaf `gatling` crate. `thread::spawn`
/// (a detached compute thread), `crossbeam` (scoped/work-steal helpers), and
/// rayon's own pool builders. `thread::scope` is a reinvented pool too, but it
/// is the gatling engine's *own* primitive and predates the port in a handful of
/// root/osm-katana algorithms, so it gets its own check with a documented
/// one-engine-guard allowlist ([`FORBIDDEN_SCOPED_POOL`] /
/// [`SCOPED_POOL_ALLOW`]) rather than living here.
const FORBIDDEN_PRIVATE_POOL: &[&str] = &[
    "thread::spawn",
    // A `std::thread::Builder` (`thread::Builder::new()…spawn()`) is the exact same
    // detached OS thread as `thread::spawn`, just with a name/stack-size — a
    // Builder-based worker pool would otherwise evade the `thread::spawn` token
    // entirely. Matched on the fully-qualified `thread::Builder` segment (NOT a bare
    // `Builder::new`, which the Arrow codecs use for hundreds of column builders).
    "thread::Builder",
    "crossbeam",
    "rayon::ThreadPool",
    "ThreadPoolBuilder",
];

/// A **scoped** worker pool built straight on `std::thread::scope`. This IS the
/// gatling engine's own primitive, so it is legal inside the engine crate; the
/// one-engine law forbids reinventing it anywhere else. A short, explicit
/// allowlist ([`SCOPED_POOL_ALLOW`]) grandfathers the pre-gatling algorithms
/// that still hand-roll it — so a NEW file reaching for `thread::scope` to fan
/// out work (instead of routing through `gatling_for_each`) trips a red test.
const FORBIDDEN_SCOPED_POOL: &[&str] = &["thread::scope"];

/// Documented, path-scoped one-engine guards: the pre-gatling parallel
/// algorithms that still fan out on their own `std::thread::scope` rather than
/// `gatling::gatling_forkjoin::gatling_for_each`. These predate the engine
/// extraction and are the SAME std primitive gatling is built on (a scoped span
/// of workers, not a rayon-style global/work-stealing pool); each is a
/// deliberate, enumerated exception, NOT a blanket crate carve-out — a new
/// scope-pool in any unlisted file trips the law.
///   root crate — sample sort + VTD/XML scanners:
///     `/src/psort.rs`, `/src/xml.rs`, `/src/vtd.rs`
///
/// 2026-07-22: **osm-katana is now empty of scope pools** — `par.rs`,
/// `optimize.rs`, `writer.rs`, `verify.rs`, `side_outputs/search.rs`,
/// `geo2arrow.rs` and `node_store.rs` all came off this list, so a scope pool
/// anywhere in that crate now trips the law with no exception to hide behind.
/// The two static-search-tree builds (`stree.rs`/`stree32.rs`) came off in the
/// same pass — their per-layer block fill is `gatling_scanlines` now. What is
/// left is the root crate's sample sort and the VTD/XML scanners. The list only
/// ever shrinks.
const SCOPED_POOL_ALLOW: &[&str] = &["/src/psort.rs", "/src/xml.rs", "/src/vtd.rs"];

/// The one crate allowed to build worker pools: it IS the engine.
const ENGINE_CRATE_DIR: &str = "/gatling/src/";

/// Documented, path-scoped exemptions to the private-pool ban for legitimately
/// non-pool uses of `std::thread::spawn` / `std::thread::Builder`: single
/// long-lived **streaming / I/O / telemetry** threads (one reader, one
/// writer-sink, one collector draining an mpsc channel, one progress sampler),
/// NOT work-stealing decode pools. These predate the gatling port and model the
/// same reader→sink shape the engine itself uses; forcing a serial sink onto
/// `gatling_for_each` would be nonsense. The old blanket `/bin/` carve-out is
/// GONE — the lbunzip2/lgz/lzip decode bins route through
/// `gatling::ordered::run_ordered_sink` and hold no private thread; a bin that
/// stands one up again trips the law.
///  - osm-katana xml_to_pbf     : ONE named blob-writer sink thread draining an
///                                mpsc channel (serial output stream, not fan-out).
///  - osm-katana phase_log      : one long-lived, named `phase-{name}` progress
///                                sampler thread per phase (a telemetry loop that
///                                emits a JSON line every interval until its stop
///                                flag fires — NOT an N-worker pool).
const PRIVATE_POOL_ALLOW: &[&str] = &[
    "/osm-katana/src/xml_to_pbf.rs",
    "/osm-katana/src/phase_log.rs",
];

fn norm(path: &Path) -> String {
    // Forward-slash form so the substring checks are OS-agnostic.
    path.to_string_lossy().replace('\\', "/")
}

#[test]
fn whole_workspace_is_rayon_free() {
    let mut files = Vec::new();
    for root in workspace_src_roots() {
        rs_files(&root, &mut files);
    }
    assert!(
        !files.is_empty(),
        "expected to find .rs files across the workspace"
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
        "rayon-free law violated (rayon must not appear anywhere in the workspace):\n{}",
        violations.join("\n"),
    );
}

#[test]
fn only_the_gatling_leaf_crate_owns_a_worker_pool() {
    let mut files = Vec::new();
    for root in workspace_src_roots() {
        rs_files(&root, &mut files);
    }
    assert!(
        !files.is_empty(),
        "expected to find .rs files across the workspace"
    );

    let mut violations = Vec::new();
    for file in &files {
        let p = norm(file);
        // The engine crate is the one sanctioned home for worker-pool primitives.
        if p.contains(ENGINE_CRATE_DIR) {
            continue;
        }
        let allowed = PRIVATE_POOL_ALLOW.iter().any(|a| p.contains(a));
        let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        for (lineno, raw) in text.lines().enumerate() {
            let code = strip_line_comment(raw);
            for tok in FORBIDDEN_PRIVATE_POOL {
                if code.contains(tok) {
                    // `thread::spawn` / `thread::Builder` are exempt in the
                    // documented streaming/IO/telemetry sites (single long-lived
                    // I/O or sampler threads); the pool-builder / crossbeam tokens
                    // are never allowed outside the engine.
                    if allowed && (*tok == "thread::spawn" || *tok == "thread::Builder") {
                        continue;
                    }
                    violations.push(format!(
                        "{}:{}: private pool `{tok}` — {}",
                        p,
                        lineno + 1,
                        code.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "one-engine law violated (only the leaf `gatling` crate may build a worker pool; \
         route decode fan-out through `gatling::gatling_forkjoin::gatling_for_each`):\n{}",
        violations.join("\n"),
    );
}

#[test]
fn no_reinvented_scoped_pool_outside_gatling() {
    let mut files = Vec::new();
    for root in workspace_src_roots() {
        rs_files(&root, &mut files);
    }
    assert!(
        !files.is_empty(),
        "expected to find .rs files across the workspace"
    );

    let mut violations = Vec::new();
    for file in &files {
        let p = norm(file);
        // The engine crate owns `thread::scope` — it IS the one sanctioned pool.
        if p.contains(ENGINE_CRATE_DIR) {
            continue;
        }
        // Explicitly grandfathered pre-gatling algorithms.
        if SCOPED_POOL_ALLOW.iter().any(|a| p.contains(a)) {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        for (lineno, raw) in text.lines().enumerate() {
            let code = strip_line_comment(raw);
            for tok in FORBIDDEN_SCOPED_POOL {
                if code.contains(tok) {
                    violations.push(format!(
                        "{}:{}: reinvented scoped pool `{tok}` — {}",
                        p,
                        lineno + 1,
                        code.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "one-engine law violated (a new file hand-rolls a `std::thread::scope` worker pool \
         outside the leaf `gatling` crate; route decode/scan fan-out through \
         `gatling::gatling_forkjoin::gatling_for_each`, or — if it is a legitimate pre-gatling \
         algorithm — add it to SCOPED_POOL_ALLOW with a rationale):\n{}",
        violations.join("\n"),
    );
}

/// No manifest in the workspace may declare a `rayon` dependency — the port
/// dropped every one, and a transitive re-add would quietly re-arm the global
/// pool the law forbids. Scans dependency-table lines of the root + every member
/// `Cargo.toml` (comments in a manifest freely discuss rayon).
#[test]
fn no_manifest_declares_rayon() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut manifests = vec![root.join("Cargo.toml")];
    let root_manifest =
        std::fs::read_to_string(root.join("Cargo.toml")).expect("read root Cargo.toml");
    if let Some(line) = root_manifest
        .lines()
        .find(|l| l.trim_start().starts_with("members"))
    {
        if let (Some(a), Some(b)) = (line.find('['), line.find(']')) {
            for raw in line[a + 1..b].split(',') {
                let name = raw.trim().trim_matches('"');
                if !name.is_empty() {
                    manifests.push(root.join(name).join("Cargo.toml"));
                }
            }
        }
    }

    let mut offenders = Vec::new();
    for manifest in &manifests {
        let Ok(text) = std::fs::read_to_string(manifest) else {
            continue;
        };
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
                offenders.push(format!("{}: {}", norm(manifest), code.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a workspace Cargo.toml declares a rayon dependency (law forbids it):\n{}",
        offenders.join("\n"),
    );
}
