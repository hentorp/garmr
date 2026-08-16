//! **Silenced-test guard** — catch `tests/*.rs` files that compile to ZERO tests.
//!
//! ## The trap
//!
//! A test file carrying a *crate-level inner attribute*
//!
//! ```ignore
//! #![cfg(all(feature = "viz", feature = "server", feature = "testmatrix"))]
//! ```
//!
//! compiles to an **empty test binary** whenever any required feature is absent
//! from the crate's `default` set. `cargo test` then reports
//! `running 0 tests ... ok` and the whole file is green-by-vacuum. The
//! 2026-07-21 constellation sweep found **78 such files across 11 repos, hiding
//! ~216 test functions**. Silence is not success.
//!
//! Three camouflage forms make it invisible to review:
//!
//! 1. **`all(default-on, default-on, default-OFF)`** — the file reads exactly
//!    like its many running siblings; only the last conjunct is dark.
//! 2. **Near-miss arm names** — the file needs `lineage-http`, CI passes
//!    `lineage`; a *different* feature that does not imply it.
//! 3. **Sibling asymmetry** — one test in a directory runs on default features,
//!    the eight next to it are dark. The directory reads as green.
//!
//! ## The guard
//!
//! [`audit_gated_tests`] walks every `test` target of every workspace member
//! (via `cargo metadata --no-deps`), extracts the leading crate-level `#![cfg]`,
//! resolves each crate's transitive `default` feature closure from its own
//! feature table, and asks: *does this file compile under a plain
//! `cargo test`?* If not, it must be **rescued** by a declared matrix arm — an
//! explicit `cargo test -p P --features F --test T` re-invocation the repo runs.
//! Anything neither reachable-by-default nor rescued is a **RED**
//! [`TestResultRow`] on the `gated-tests` aspect, so it fails a gate instead of
//! merely printing.
//!
//! The rescue model is holger's (`xtask/tests/holger_matrix.rs`), the
//! constellation's reference mitigation: per-file
//! `cargo test -p holger-ui --features gui --test robot_ui_app` cells. A repo
//! declares those arms once, in `.nornir/testmatrix-arms.json`:
//!
//! ```json
//! {
//!   "arms": [
//!     { "package": "holger-ui", "features": ["gui"], "test": "robot_ui_app" },
//!     { "package": "holger-ui", "features": ["gui"], "test": "demo_walk" },
//!     { "package": "holger-ui", "features": ["gui"] },
//!     { "features": ["testmatrix"] }
//!   ]
//! }
//! ```
//!
//! An arm with no `test` covers **every** test target of the package; an arm
//! with no `package` covers every package (a workspace-wide
//! `cargo test --workspace --features X`). `no_default_features` and
//! `all_features` mirror the cargo flags.
//!
//! ## Semantics, precisely
//!
//! Non-feature predicates (`unix`, `target_os = "linux"`, `test`) are
//! **unknown**, never false: the guard evaluates the cfg tree three-valued and
//! only reports a file whose gate is *definitively* false under the resolved
//! feature set. `not(feature = "x")` with `x` off is therefore satisfied, and
//! `not(target_os = "windows")` is never flagged. The guard reports
//! feature-driven silence and nothing else.
//!
//! ```no_run
//! use nornir_testmatrix::{audit_gated_tests, MatrixArms};
//! use std::path::Path;
//!
//! let arms = MatrixArms::load(Path::new(".")).unwrap_or_default();
//! let report = audit_gated_tests(Path::new("."), "myrepo", "run-1", &arms).unwrap();
//! assert!(report.is_green(), "{}", report.summary());
//! ```

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::model::{TestResultRow, status};

/// The aspect tag every row this module emits carries.
pub const ASPECT_GATED_TESTS: &str = "gated-tests";

/// Where a repo declares the matrix arms that re-invoke its feature-gated tests.
pub const ARMS_FILE: &str = ".nornir/testmatrix-arms.json";

// ─── cfg expression ────────────────────────────────────────────────────────

/// A parsed `#![cfg(...)]` predicate tree.
///
/// `Other` is any predicate that is not `feature = "..."` (`unix`,
/// `target_os = "linux"`, `test`, `docsrs` …). It evaluates to **unknown**, so
/// it can never make a file look silenced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CfgExpr {
    /// `feature = "name"`.
    Feature(String),
    /// `all(a, b, …)`.
    All(Vec<CfgExpr>),
    /// `any(a, b, …)`.
    Any(Vec<CfgExpr>),
    /// `not(a)`.
    Not(Box<CfgExpr>),
    /// A non-feature predicate, kept verbatim for the report message.
    Other(String),
}

impl CfgExpr {
    /// Three-valued evaluation against an enabled-feature set. `None` = unknown
    /// (a non-feature predicate was decisive).
    pub fn eval(&self, enabled: &BTreeSet<String>) -> Option<bool> {
        match self {
            CfgExpr::Feature(f) => Some(enabled.contains(f)),
            CfgExpr::Other(_) => None,
            CfgExpr::Not(inner) => inner.eval(enabled).map(|b| !b),
            CfgExpr::All(items) => {
                let mut unknown = false;
                for it in items {
                    match it.eval(enabled) {
                        Some(false) => return Some(false),
                        None => unknown = true,
                        Some(true) => {}
                    }
                }
                if unknown { None } else { Some(true) }
            }
            CfgExpr::Any(items) => {
                let mut unknown = false;
                for it in items {
                    match it.eval(enabled) {
                        Some(true) => return Some(true),
                        None => unknown = true,
                        Some(false) => {}
                    }
                }
                if unknown { None } else { Some(false) }
            }
        }
    }

    /// Does the file behind this gate **compile** with `enabled` on? Unknown
    /// counts as yes — only a definitively-false gate silences a file.
    pub fn compiles_with(&self, enabled: &BTreeSet<String>) -> bool {
        self.eval(enabled) != Some(false)
    }

    /// Every `feature = "..."` name mentioned anywhere in the tree.
    pub fn features(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        self.collect_features(&mut out);
        out
    }

    fn collect_features(&self, out: &mut BTreeSet<String>) {
        match self {
            CfgExpr::Feature(f) => {
                out.insert(f.clone());
            }
            CfgExpr::Other(_) => {}
            CfgExpr::Not(i) => i.collect_features(out),
            CfgExpr::All(v) | CfgExpr::Any(v) => {
                for i in v {
                    i.collect_features(out)
                }
            }
        }
    }

    /// Does this gate reference any cargo feature at all? A purely
    /// platform-conditional file is not this guard's business.
    pub fn mentions_features(&self) -> bool {
        !self.features().is_empty()
    }
}

// ─── source scanning ───────────────────────────────────────────────────────

/// Strip `//` / `/* */` (nesting-aware) comments, respecting string, char, and
/// raw-string literals, so an attribute-looking thing inside a doc comment or a
/// string is never mistaken for a real one.
fn strip_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        // raw string: r"..." / r#"..."#
        if c == 'r' && i + 1 < b.len() && (b[i + 1] == '"' || b[i + 1] == '#') {
            let mut j = i + 1;
            let mut hashes = 0usize;
            while j < b.len() && b[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == '"' {
                out.push(c);
                out.extend(b[i + 1..=j].iter());
                let mut k = j + 1;
                loop {
                    if k >= b.len() {
                        i = k;
                        break;
                    }
                    if b[k] == '"' {
                        let mut h = 0usize;
                        while h < hashes && k + 1 + h < b.len() && b[k + 1 + h] == '#' {
                            h += 1;
                        }
                        if h == hashes {
                            out.extend(b[k..=k + hashes].iter());
                            i = k + hashes + 1;
                            break;
                        }
                    }
                    out.push(b[k]);
                    k += 1;
                }
                continue;
            }
        }
        if c == '"' {
            out.push(c);
            let mut k = i + 1;
            while k < b.len() {
                if b[k] == '\\' {
                    out.push(b[k]);
                    if k + 1 < b.len() {
                        out.push(b[k + 1]);
                    }
                    k += 2;
                    continue;
                }
                out.push(b[k]);
                if b[k] == '"' {
                    k += 1;
                    break;
                }
                k += 1;
            }
            i = k;
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            out.push('\n');
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == '*' {
            let mut depth = 1usize;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && i + 1 < b.len() && b[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Skip whitespace and comments (`//`, `//!`, nesting-aware `/* */`) from `i`,
/// returning the index of the first character that is neither.
fn skip_trivia(t: &[char], mut i: usize) -> usize {
    loop {
        while i < t.len() && t[i].is_whitespace() {
            i += 1;
        }
        if t.get(i) == Some(&'/') && t.get(i + 1) == Some(&'/') {
            while i < t.len() && t[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if t.get(i) == Some(&'/') && t.get(i + 1) == Some(&'*') {
            let mut depth = 1usize;
            i += 2;
            while i < t.len() && depth > 0 {
                if t[i] == '/' && t.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if t[i] == '*' && t.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        return i;
    }
}

/// If a string literal starts at `i` (`"…"` with escapes, or `r"…"` / `r#"…"#`),
/// return the index just past its closing quote. `prev` guards the raw-string
/// form: the `r` of `feature` must not start one.
fn skip_string(t: &[char], i: usize, prev: Option<char>) -> Option<usize> {
    match t.get(i) {
        Some('"') => {
            let mut k = i + 1;
            while k < t.len() {
                if t[k] == '\\' {
                    k += 2;
                    continue;
                }
                if t[k] == '"' {
                    return Some(k + 1);
                }
                k += 1;
            }
            Some(t.len())
        }
        Some('r')
            if !prev
                .map(|c| c.is_alphanumeric() || c == '_')
                .unwrap_or(false) =>
        {
            let mut j = i + 1;
            let mut hashes = 0usize;
            while t.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if t.get(j) != Some(&'"') {
                return None;
            }
            let mut k = j + 1;
            while k < t.len() {
                if t[k] == '"' {
                    let mut h = 0usize;
                    while h < hashes && t.get(k + 1 + h) == Some(&'#') {
                        h += 1;
                    }
                    if h == hashes {
                        return Some(k + 1 + hashes);
                    }
                }
                k += 1;
            }
            Some(t.len())
        }
        _ => None,
    }
}

/// Index of the delimiter closing the `(` or `[` at `open`, skipping string
/// literals and comments so a `)` or `]` inside `"…"` cannot close it.
fn match_delim(t: &[char], open: usize) -> Option<usize> {
    let (o, c) = match t.get(open)? {
        '(' => ('(', ')'),
        '[' => ('[', ']'),
        _ => return None,
    };
    let mut depth = 0usize;
    let mut i = open;
    let mut prev: Option<char> = None;
    while i < t.len() {
        if let Some(next) = skip_string(t, i, prev) {
            prev = Some('"');
            i = next;
            continue;
        }
        let after = skip_trivia(t, i);
        if after > i {
            prev = Some(' ');
            i = after;
            continue;
        }
        let ch = t[i];
        if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        prev = Some(ch);
        i += 1;
    }
    None
}

/// Extract the inner text of the crate-level `#![cfg(...)]` inner attribute of a
/// source file, e.g. `all(feature = "a", feature = "b")`.
///
/// Returns `None` when the file carries no crate-level cfg gate.
/// `#![cfg_attr(...)]` is deliberately NOT matched.
///
/// ## Why this walks the prologue instead of scanning for the text `#![cfg(`
///
/// A textual scan — even a comment-stripped one — reports files that merely
/// *talk about* gates. The live example is nornir's
/// `tests/ra_ingest_coverage_wiring.rs`: an **ungated** tripwire test that
/// asserts a sibling file keeps its gate, so it contains the line
///
/// ```ignore
/// smoke.contains("#![cfg(feature = \"ra-ingest\")]"),
/// ```
///
/// The old scan matched inside that string literal and reported the file as
/// SILENCED with missing feature `ra-ingest"` — the trailing quote being the
/// fingerprint of having parsed an escaped literal. That file runs on default
/// features; the finding was pure noise, and a guard that cries wolf gets
/// ignored. The same naive match can equally MIS-ATTRIBUTE a real gate by
/// picking up a quoted one further down the file.
///
/// So the rule is structural, matching what rustc actually accepts: **inner
/// attributes may only appear in the file's prologue**, before the first item.
/// This walks that prologue — skipping whitespace and comments, stepping over
/// each `#![…]` whose path is not `cfg` — and stops dead at the first token
/// that is not an inner attribute. A `#![cfg(` inside a string literal, a
/// `//`/`//!` comment, or a `/* */` block therefore cannot be reached at all,
/// because by then the walk has already stopped at the first `use`/`fn`/`const`.
///
/// The mirror-image failure is guarded too: whitespace and comments are skipped
/// rather than required-absent, so an indented gate, a gate preceded by
/// `#![allow(...)]` or a doc-comment header, and a `#![cfg(all(feature = "a",
/// feature = "b"))]` broken across several lines are all still detected. Paren
/// matching is string-aware, so a feature name containing `)` cannot truncate
/// the capture.
pub fn extract_crate_cfg(src: &str) -> Option<String> {
    let t: Vec<char> = src.chars().collect();
    let mut i = 0usize;
    // A `#!/usr/bin/env …` shebang on line 1 is legal Rust and is not an
    // attribute; skip the line so it does not end the prologue walk.
    if t.first() == Some(&'#') && t.get(1) == Some(&'!') && t.get(2) != Some(&'[') {
        while i < t.len() && t[i] != '\n' {
            i += 1;
        }
    }
    loop {
        i = skip_trivia(&t, i);
        // First non-inner-attribute token ends the prologue: no gate can follow.
        if !(t.get(i) == Some(&'#') && t.get(i + 1) == Some(&'!') && t.get(i + 2) == Some(&'[')) {
            return None;
        }
        let bracket = i + 2;
        let mut j = skip_trivia(&t, i + 3);
        let start = j;
        while j < t.len() && (t[j].is_alphanumeric() || t[j] == '_') {
            j += 1;
        }
        let name: String = t[start..j].iter().collect();
        j = skip_trivia(&t, j);
        if name == "cfg" && t.get(j) == Some(&'(') {
            let close = match_delim(&t, j)?;
            let inner: String = t[j + 1..close].iter().collect();
            return Some(inner.trim().to_string());
        }
        // Some other inner attribute (`#![allow]`, `#![cfg_attr]`, …): step over
        // the whole thing — brackets matched string-aware — and keep walking.
        i = match_delim(&t, bracket)? + 1;
    }
}

/// Parse a cfg predicate list body (the text inside `cfg(...)`).
pub fn parse_cfg_expr(src: &str) -> Option<CfgExpr> {
    let toks = tokenize(src);
    let mut pos = 0usize;
    let e = parse_expr(&toks, &mut pos)?;
    Some(e)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Str(String),
    Open,
    Close,
    Comma,
    Eq,
}

fn tokenize(src: &str) -> Vec<Tok> {
    let c: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch == '(' {
            out.push(Tok::Open);
            i += 1;
        } else if ch == ')' {
            out.push(Tok::Close);
            i += 1;
        } else if ch == ',' {
            out.push(Tok::Comma);
            i += 1;
        } else if ch == '=' {
            out.push(Tok::Eq);
            i += 1;
        } else if ch == '"' {
            let mut s = String::new();
            i += 1;
            while i < c.len() && c[i] != '"' {
                if c[i] == '\\' && i + 1 < c.len() {
                    i += 1;
                }
                s.push(c[i]);
                i += 1;
            }
            i += 1;
            out.push(Tok::Str(s));
        } else if ch.is_alphanumeric() || ch == '_' || ch == '-' {
            let mut s = String::new();
            while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_' || c[i] == '-') {
                s.push(c[i]);
                i += 1;
            }
            out.push(Tok::Ident(s));
        } else {
            i += 1;
        }
    }
    out
}

fn parse_expr(toks: &[Tok], pos: &mut usize) -> Option<CfgExpr> {
    let name = match toks.get(*pos)? {
        Tok::Ident(s) => s.clone(),
        _ => return None,
    };
    *pos += 1;
    match toks.get(*pos) {
        Some(Tok::Open) => {
            *pos += 1;
            let mut items = Vec::new();
            loop {
                match toks.get(*pos) {
                    Some(Tok::Close) => {
                        *pos += 1;
                        break;
                    }
                    Some(Tok::Comma) => {
                        *pos += 1;
                    }
                    None => return None,
                    _ => {
                        let e = parse_expr(toks, pos)?;
                        items.push(e);
                    }
                }
            }
            match name.as_str() {
                "all" => Some(CfgExpr::All(items)),
                "any" => Some(CfgExpr::Any(items)),
                "not" => items.into_iter().next().map(|e| CfgExpr::Not(Box::new(e))),
                other => Some(CfgExpr::Other(other.to_string())),
            }
        }
        Some(Tok::Eq) => {
            *pos += 1;
            let val = match toks.get(*pos) {
                Some(Tok::Str(s)) => s.clone(),
                Some(Tok::Ident(s)) => s.clone(),
                _ => String::new(),
            };
            *pos += 1;
            if name == "feature" {
                Some(CfgExpr::Feature(val))
            } else {
                Some(CfgExpr::Other(format!("{name} = \"{val}\"")))
            }
        }
        _ => Some(CfgExpr::Other(name)),
    }
}

/// Count the `#[test]`-family attributes in a source file — the number of test
/// functions a silenced file is hiding. Comment-stripped, so a `#[test]` inside
/// a doc example is not counted.
///
/// Matches any attribute whose path's **last segment** is `test`, with or
/// without arguments: `#[test]`, `#[tokio::test]`,
/// `#[tokio::test(flavor = "multi_thread")]`, `#[actix_web::test]`. Does NOT
/// match `#[test_case(..)]` or `#[should_panic]` (different last segment).
pub fn count_test_fns(src: &str) -> usize {
    strip_comments(src)
        .lines()
        .filter(|l| is_test_attr(l.trim()))
        .count()
}

/// Is this trimmed line an outer `#[…test…]` attribute?
fn is_test_attr(t: &str) -> bool {
    if !t.starts_with("#[") || t.starts_with("#![") {
        return false;
    }
    // The attribute path: everything up to the first `(` (args) or `]` (end).
    let body = &t[2..];
    let end = body.find(['(', ']']).unwrap_or(body.len());
    let path = body[..end].trim();
    path.rsplit("::")
        .next()
        .map(|seg| seg.trim() == "test")
        .unwrap_or(false)
}

// ─── feature graph ─────────────────────────────────────────────────────────

/// The transitive closure of a crate's own features reachable from `seeds`.
///
/// `dep:x` entries and cross-crate `pkg/feat` (and the weak `pkg?/feat`) forms
/// enable features on *dependencies*, never on self, so they are skipped.
pub fn feature_closure(
    table: &BTreeMap<String, Vec<String>>,
    seeds: &[String],
) -> BTreeSet<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = seeds.iter().cloned().collect();
    while let Some(f) = queue.pop_front() {
        if f.starts_with("dep:") || f.contains('/') {
            continue;
        }
        if !seen.insert(f.clone()) {
            continue;
        }
        if let Some(children) = table.get(&f) {
            for c in children {
                queue.push_back(c.clone());
            }
        }
    }
    seen
}

/// The features a plain `cargo test` turns on: the closure of `default`.
pub fn default_features(table: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut set = feature_closure(table, &["default".to_string()]);
    // `default` is itself a feature name; keep it, it is legal to `cfg` on.
    if !table.contains_key("default") {
        set.remove("default");
    }
    set
}

// ─── workspace model (cargo metadata) ──────────────────────────────────────

/// One `[[test]]` target of a crate (an integration test — a `tests/*.rs` file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestTarget {
    /// The target name (`robot_ui_app` for `tests/robot_ui_app.rs`).
    pub name: String,
    /// Absolute path to the test's root source file.
    pub src_path: PathBuf,
}

/// A workspace member's feature table + test targets — everything the guard
/// needs, read once from `cargo metadata --no-deps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrateManifest {
    /// The package name (what `-p` takes).
    pub name: String,
    /// The raw `[features]` table, including cargo's implicit optional-dep
    /// features.
    pub features: BTreeMap<String, Vec<String>>,
    /// Every `test`-kind target of the package.
    pub tests: Vec<TestTarget>,
}

impl CrateManifest {
    /// The features a plain `cargo test -p <name>` enables.
    pub fn default_set(&self) -> BTreeSet<String> {
        default_features(&self.features)
    }

    /// The features an explicit `--features a,b` (plus default unless
    /// suppressed) enables.
    pub fn arm_set(&self, arm: &MatrixArm) -> BTreeSet<String> {
        if arm.all_features {
            return self.features.keys().cloned().collect();
        }
        let mut seeds: Vec<String> = arm.features.clone();
        if !arm.no_default_features {
            seeds.push("default".to_string());
        }
        let mut set = feature_closure(&self.features, &seeds);
        if !self.features.contains_key("default") {
            set.remove("default");
        }
        set
    }
}

/// Parse `cargo metadata --no-deps --format-version 1` output into the crates
/// the guard inspects. Pure — no subprocess — so it is unit-testable.
pub fn parse_metadata(json: &str) -> Result<Vec<CrateManifest>> {
    let v: serde_json::Value = serde_json::from_str(json).context("parse cargo metadata JSON")?;
    let pkgs = v
        .get("packages")
        .and_then(|p| p.as_array())
        .ok_or_else(|| anyhow!("cargo metadata has no `packages` array"))?;
    let mut out = Vec::new();
    for p in pkgs {
        let name = p
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let mut features = BTreeMap::new();
        if let Some(map) = p.get("features").and_then(|f| f.as_object()) {
            for (k, val) in map {
                let deps = val
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|d| d.as_str().map(str::to_string))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                features.insert(k.clone(), deps);
            }
        }
        let mut tests = Vec::new();
        if let Some(tgts) = p.get("targets").and_then(|t| t.as_array()) {
            for t in tgts {
                let is_test = t
                    .get("kind")
                    .and_then(|k| k.as_array())
                    .map(|k| k.iter().any(|x| x.as_str() == Some("test")))
                    .unwrap_or(false);
                if !is_test {
                    continue;
                }
                tests.push(TestTarget {
                    name: t
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string(),
                    src_path: PathBuf::from(
                        t.get("src_path").and_then(|s| s.as_str()).unwrap_or(""),
                    ),
                });
            }
        }
        out.push(CrateManifest {
            name,
            features,
            tests,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Read the workspace's members (features + test targets) via
/// `cargo metadata --no-deps`.
pub fn workspace_crates(repo_root: &Path) -> Result<Vec<CrateManifest>> {
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("spawn cargo metadata in {}", repo_root.display()))?;
    if !out.status.success() {
        return Err(anyhow!(
            "cargo metadata failed in {}: {}",
            repo_root.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_metadata(&String::from_utf8_lossy(&out.stdout))
}

// ─── declared rescue arms ──────────────────────────────────────────────────

/// One matrix arm a repo declares: an explicit re-invocation of `cargo test`
/// with extra features that rescues otherwise-silenced test files.
///
/// Mirrors what holger's `xtask/tests/holger_matrix.rs` cells actually run:
/// `cargo test -p holger-ui --features gui --test robot_ui_app`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixArm {
    /// `-p <package>`. `None` = the arm runs across the whole workspace.
    #[serde(default)]
    pub package: Option<String>,
    /// `--test <name>`. `None` = the arm runs every test target of the package.
    #[serde(default)]
    pub test: Option<String>,
    /// `--features a,b`.
    #[serde(default)]
    pub features: Vec<String>,
    /// `--no-default-features`.
    #[serde(default)]
    pub no_default_features: bool,
    /// `--all-features`.
    #[serde(default)]
    pub all_features: bool,
    /// Optional free-text note (where the arm lives, why it exists).
    #[serde(default)]
    pub note: String,
}

impl MatrixArm {
    /// `cargo test --features <features>` across the workspace.
    pub fn features<I, S>(feats: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            features: feats.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    /// Narrow this arm to one package (`-p`).
    pub fn package(mut self, pkg: impl Into<String>) -> Self {
        self.package = Some(pkg.into());
        self
    }

    /// Narrow this arm to one test target (`--test`).
    pub fn test(mut self, t: impl Into<String>) -> Self {
        self.test = Some(t.into());
        self
    }

    /// Attach a human note (surfaces in the report message).
    pub fn note(mut self, n: impl Into<String>) -> Self {
        self.note = n.into();
        self
    }

    /// Does this arm target the given package + test target at all (before
    /// asking whether its features actually satisfy the gate)?
    pub fn targets(&self, package: &str, test: &str) -> bool {
        self.package
            .as_deref()
            .map(|p| p == package)
            .unwrap_or(true)
            && self.test.as_deref().map(|t| t == test).unwrap_or(true)
    }

    /// The `cargo test …` command line this arm stands for — what shows up in
    /// the report so the rescue is auditable.
    pub fn command(&self) -> String {
        let mut s = String::from("cargo test");
        if let Some(p) = &self.package {
            s.push_str(&format!(" -p {p}"));
        }
        if self.no_default_features {
            s.push_str(" --no-default-features");
        }
        if self.all_features {
            s.push_str(" --all-features");
        } else if !self.features.is_empty() {
            s.push_str(&format!(" --features {}", self.features.join(",")));
        }
        if let Some(t) = &self.test {
            s.push_str(&format!(" --test {t}"));
        }
        s
    }
}

/// The set of arms a repo declares (`.nornir/testmatrix-arms.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixArms {
    /// The declared re-invocations.
    #[serde(default)]
    pub arms: Vec<MatrixArm>,
}

impl MatrixArms {
    /// Build from arms in memory (for repos that declare them in Rust).
    pub fn new(arms: impl IntoIterator<Item = MatrixArm>) -> Self {
        Self {
            arms: arms.into_iter().collect(),
        }
    }

    /// Load `<repo_root>/.nornir/testmatrix-arms.json`. A repo with no
    /// declaration file gets an empty set (every gated file must then be
    /// default-reachable) — `Ok(None)` distinguishes "no file" from a parse
    /// error.
    pub fn read(repo_root: &Path) -> Result<Option<MatrixArms>> {
        let p = repo_root.join(ARMS_FILE);
        if !p.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
        let arms: MatrixArms =
            serde_json::from_str(&text).with_context(|| format!("parse {}", p.display()))?;
        Ok(Some(arms))
    }

    /// [`MatrixArms::read`] collapsing "no file" to an empty declaration.
    pub fn load(repo_root: &Path) -> Result<MatrixArms> {
        Ok(Self::read(repo_root)?.unwrap_or_default())
    }
}

// ─── findings ──────────────────────────────────────────────────────────────

/// Why a gated test file is (or is not) actually run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateVerdict {
    /// The gate is satisfied by the crate's `default` features — a plain
    /// `cargo test` compiles and runs it.
    Default,
    /// Not default-reachable, but a declared matrix arm re-invokes it with the
    /// features it needs.
    Rescued,
    /// Not default-reachable and no declared arm re-invokes it. **RED** — the
    /// file compiles to zero tests and reports green by vacuum.
    Silenced,
}

impl GateVerdict {
    /// The [`status`] tag this verdict records.
    pub fn status(self) -> &'static str {
        match self {
            GateVerdict::Silenced => status::FAIL,
            _ => status::PASS,
        }
    }
}

/// One `tests/*.rs` file carrying a crate-level `#![cfg(...)]` gate, and the
/// guard's verdict on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatedTestFile {
    /// The owning package.
    pub crate_name: String,
    /// The test target name (`--test <this>`).
    pub target: String,
    /// Path relative to the repo root, e.g. `server/ui/tests/robot_ui_app.rs`.
    pub path: String,
    /// The gate source text, e.g. `all(feature = "viz", feature = "testmatrix")`.
    pub cfg: String,
    /// The parsed gate.
    pub expr: CfgExpr,
    /// Feature names the gate mentions that are NOT reachable from `default` —
    /// the actual dark conjuncts.
    pub missing_features: Vec<String>,
    /// How many `#[test]`-family functions the file holds (what is hidden).
    pub hidden_tests: usize,
    /// The verdict.
    pub verdict: GateVerdict,
    /// The `cargo test …` command of the arm that rescued it, when rescued.
    pub rescued_by: Option<String>,
}

impl GatedTestFile {
    /// Is this file dark (compiles to zero tests, nothing re-invokes it)?
    pub fn is_silenced(&self) -> bool {
        self.verdict == GateVerdict::Silenced
    }

    /// The report line / row message.
    pub fn message(&self) -> String {
        match self.verdict {
            GateVerdict::Default => {
                format!(
                    "{} · #![cfg({})] satisfied by default features",
                    self.path, self.cfg
                )
            }
            GateVerdict::Rescued => format!(
                "{} · #![cfg({})] not default-reachable, rescued by `{}`",
                self.path,
                self.cfg,
                self.rescued_by.as_deref().unwrap_or("<arm>")
            ),
            GateVerdict::Silenced => format!(
                "{} · #![cfg({})] compiles to ZERO tests under `cargo test` \
                 ({} hidden test fn{}); feature{} {} not in the crate's `default` \
                 closure and no declared matrix arm re-invokes this file — \
                 declare one in {} or move the feature into `default`",
                self.path,
                self.cfg,
                self.hidden_tests,
                if self.hidden_tests == 1 { "" } else { "s" },
                if self.missing_features.len() == 1 {
                    ""
                } else {
                    "s"
                },
                self.missing_features.join(", "),
                ARMS_FILE,
            ),
        }
    }
}

/// The guard's structured finding for a whole repo — the `gated-tests` sibling
/// of [`crate::GateReport`]: a verdict that can fail a gate, not just print.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatedTestReport {
    /// The test-run identity these rows join on.
    pub run_id: String,
    /// The repo the scan ran in (partition key on every row).
    pub repo: String,
    /// Every gated test file found, in path order (all three verdicts).
    pub files: Vec<GatedTestFile>,
    /// How many test targets were inspected in total (gated or not).
    pub scanned: usize,
    /// The arms the repo declared (echoed so the excuse is visible).
    pub arms: Vec<MatrixArm>,
}

impl GatedTestReport {
    /// The dark files — the actionable set.
    pub fn silenced(&self) -> Vec<&GatedTestFile> {
        self.files.iter().filter(|f| f.is_silenced()).collect()
    }

    /// Total `#[test]` functions hidden by the dark files.
    pub fn hidden_tests(&self) -> usize {
        self.silenced().iter().map(|f| f.hidden_tests).sum()
    }

    /// GREEN ⟺ no silenced file. The HARD-zero gate.
    pub fn is_green(&self) -> bool {
        self.silenced().is_empty()
    }

    /// One-line human summary for the CLI.
    pub fn summary(&self) -> String {
        let rescued = self
            .files
            .iter()
            .filter(|f| f.verdict == GateVerdict::Rescued)
            .count();
        format!(
            "{} test target{} scanned · {} feature-gated · {} rescued by declared arms · \
             {} SILENCED ({} hidden test fns) — {}",
            self.scanned,
            if self.scanned == 1 { "" } else { "s" },
            self.files.len(),
            rescued,
            self.silenced().len(),
            self.hidden_tests(),
            if self.is_green() { "GREEN" } else { "RED" },
        )
    }

    /// The persisted rows: one [`TestResultRow`] per gated file on the
    /// `gated-tests` aspect. Silenced → `fail`, otherwise `pass`; `metric`
    /// carries the hidden-test count so the matrix can rank by damage.
    pub fn rows(&self) -> Vec<TestResultRow> {
        let ts = now_micros();
        self.files
            .iter()
            .map(|f| TestResultRow {
                run_id: self.run_id.clone(),
                repo: self.repo.clone(),
                suite: f.crate_name.clone(),
                test_name: format!("gated-tests::{}", f.target),
                status: f.verdict.status().to_string(),
                duration_ms: 0.0,
                ts_micros: ts,
                message: f.message(),
                aspect: ASPECT_GATED_TESTS.to_string(),
                metric: f.hidden_tests as f64,
            })
            .collect()
    }
}

fn now_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

// ─── the audit ─────────────────────────────────────────────────────────────

/// Classify one already-read test file against a crate's features + the
/// declared arms. Pure — the unit-testable heart of the guard.
pub fn classify(
    krate: &CrateManifest,
    target: &TestTarget,
    src: &str,
    rel_path: &str,
    arms: &[MatrixArm],
) -> Option<GatedTestFile> {
    let cfg = extract_crate_cfg(src)?;
    let expr = parse_cfg_expr(&cfg)?;
    if !expr.mentions_features() {
        // A purely platform-conditional file is not this guard's business.
        return None;
    }
    let defaults = krate.default_set();
    let hidden_tests = count_test_fns(src);
    let missing_features: Vec<String> = expr
        .features()
        .into_iter()
        .filter(|f| !defaults.contains(f))
        .collect();

    let (verdict, rescued_by) = if expr.compiles_with(&defaults) {
        (GateVerdict::Default, None)
    } else {
        let hit = arms
            .iter()
            .filter(|a| a.targets(&krate.name, &target.name))
            .find(|a| expr.compiles_with(&krate.arm_set(a)));
        match hit {
            Some(a) => (GateVerdict::Rescued, Some(a.command())),
            None => (GateVerdict::Silenced, None),
        }
    };

    Some(GatedTestFile {
        crate_name: krate.name.clone(),
        target: target.name.clone(),
        path: rel_path.to_string(),
        cfg,
        expr,
        missing_features,
        hidden_tests,
        verdict,
        rescued_by,
    })
}

/// **The guard.** Walk every `tests/*.rs` of every workspace member, resolve
/// each crate's `default` feature closure, and report every file whose
/// crate-level `#![cfg]` is not satisfied by default and that no declared
/// matrix arm re-invokes.
///
/// The result is a structured [`GatedTestReport`]; call
/// [`GatedTestReport::is_green`] to fail a gate and [`GatedTestReport::rows`]
/// to persist it through any [`crate::TestSink`].
pub fn audit_gated_tests(
    repo_root: &Path,
    repo: &str,
    run_id: &str,
    arms: &MatrixArms,
) -> Result<GatedTestReport> {
    let crates = workspace_crates(repo_root)?;
    let mut files = Vec::new();
    let mut scanned = 0usize;
    for krate in &crates {
        for target in &krate.tests {
            scanned += 1;
            let Ok(src) = std::fs::read_to_string(&target.src_path) else {
                continue;
            };
            let rel = target
                .src_path
                .strip_prefix(repo_root)
                .unwrap_or(&target.src_path)
                .to_string_lossy()
                .to_string();
            if let Some(f) = classify(krate, target, &src, &rel, &arms.arms) {
                files.push(f);
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(GatedTestReport {
        run_id: run_id.to_string(),
        repo: repo.to_string(),
        files,
        scanned,
        arms: arms.arms.clone(),
    })
}

/// Convenience: audit `repo_root` with the arms it declares in
/// `.nornir/testmatrix-arms.json`, using the directory name as the repo tag.
pub fn audit_repo(repo_root: &Path, run_id: &str) -> Result<GatedTestReport> {
    let repo = repo_root
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "unknown".to_string());
    let arms = MatrixArms::load(repo_root)?;
    audit_gated_tests(repo_root, &repo, run_id, &arms)
}

/// **The whole adoption, in one call** — a repo's own `cargo test` goes RED when
/// any of its test files compiles to zero tests.
///
/// This exists because the guard above was, on 2026-08-01, consumed by **nobody**.
/// Ten repos carried a hand-written `.nornir/testmatrix-arms.json` from the
/// 2026-07-21 sweep, and not one of them ever ran [`audit_repo`]: the declarations
/// were prose. In the eleven days that followed, 38 fresh dark test targets
/// appeared across the fleet, hiding 122 `#[test]` fns, and nothing said a word.
/// A guard that ships and is never invoked is indistinguishable from a guard that
/// does not exist.
///
/// So the adoption had to cost four lines, not forty, or it would not happen. Each
/// repo writes exactly:
///
/// ```no_run
/// #[test]
/// fn this_repo_has_no_silenced_test_files() {
///     nornir_testmatrix::assert_no_silenced_tests(env!("CARGO_MANIFEST_DIR").as_ref());
/// }
/// ```
///
/// # Why this cannot pass vacuously
///
/// Three ways an "all green" could be a lie, all three refused here:
///
/// 1. **Wrong root.** Point it at a directory with no workspace and `cargo
///    metadata` fails — an `Err` is a panic, never a green.
/// 2. **Zero targets scanned.** A root that resolves but contains no `tests/*.rs`
///    at all (a stale path, a `--exclude`d member set, a metadata call that
///    silently degraded) reports `0 silenced` because it looked at nothing. That
///    is the exact shape LAW 2 calls "check output, not exit code", so
///    `scanned == 0` is a FAILURE, not a pass.
/// 3. **Arms that rescue nothing.** Declaring an arm makes a dark file green. This
///    call deliberately does NOT verify the arms compile — that is
///    [`crate::armcheck::verify_arms`], which costs a build. A repo that declares
///    arms should run BOTH; the panic message says so when arms are present.
///
/// The one thing it cannot decide for you is where the repo root is. Pass a path
/// that contains the workspace `Cargo.toml`; from a root-package test that is
/// `env!("CARGO_MANIFEST_DIR")`, from a crate `N` levels down it is that path's
/// `.ancestors().nth(N)`.
pub fn assert_no_silenced_tests(repo_root: &Path) {
    let rep = match audit_repo(repo_root, "self-audit") {
        Ok(r) => r,
        Err(e) => panic!(
            "the silenced-test audit could not run at {} — this is a RED, not a skip: {e:#}",
            repo_root.display()
        ),
    };

    assert!(
        rep.scanned > 0,
        "the silenced-test audit scanned ZERO test targets under {} — it proved nothing. \
         Either the path is not the workspace root, or `cargo metadata --no-deps` \
         returned no members with test targets. A guard that looks at nothing and \
         reports green is the disease it exists to cure.",
        repo_root.display()
    );

    if rep.is_green() {
        return;
    }

    let mut msg = format!("SILENCED TESTS in `{}` — {}\n", rep.repo, rep.summary());
    for f in rep.silenced() {
        msg.push_str(&format!("  · {}\n", f.message()));
    }
    msg.push_str(
        "\nEach file above compiles to an EMPTY test binary under a plain `cargo test` \
         and prints `running 0 tests ... ok`. Fix by either (a) making the feature \
         default-reachable, or (b) declaring the re-invocation that runs it in \
         .nornir/testmatrix-arms.json — and then proving that arm real with \
         `nornir_testmatrix::verify_arms`, because a declared arm nobody compiles is \
         silence wearing a badge.",
    );
    panic!("{msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    #[test]
    fn extracts_the_crate_level_cfg_past_doc_comments() {
        let src = r#"
//! A doc comment that says #![cfg(feature = "decoy")] in prose.
/* block /* nested */ #![cfg(feature = "decoy2")] */
#![allow(dead_code)]
#![cfg(all(feature = "viz", feature = "server", feature = "testmatrix"))]

#[test]
fn t() {}
"#;
        assert_eq!(
            extract_crate_cfg(src).as_deref(),
            Some(r#"all(feature = "viz", feature = "server", feature = "testmatrix")"#)
        );
    }

    /// The false positive that motivated the prologue walk: nornir's
    /// `tests/ra_ingest_coverage_wiring.rs`, an UNGATED tripwire test that
    /// asserts a sibling file keeps its gate — so the text `#![cfg(` appears in
    /// a string literal and a doc comment. The old textual scan reported it
    /// SILENCED with missing feature `ra-ingest"`, trailing quote and all.
    #[test]
    fn a_gate_quoted_in_a_string_or_doc_comment_is_not_the_files_gate() {
        let src = r####"
//! Tripwire: the smoke test must stay `#![cfg(feature = "ra-ingest")]`.
use std::fs;

#[test]
fn smoke_stays_gated() {
    let smoke = fs::read_to_string("tests/ra_ingest_smoke.rs").unwrap();
    assert!(smoke.contains("#![cfg(feature = \"ra-ingest\")]"));
    assert!(smoke.contains(r#"#![cfg(feature = "raw-quoted")]"#));
    /* even in a block comment: #![cfg(feature = "blocked")] */
}
"####;
        assert_eq!(
            extract_crate_cfg(src),
            None,
            "the file has no crate-level gate; every `#![cfg(` in it is quoted or commented"
        );
        assert!(
            classify(&krate(), &target("wiring"), src, "tests/wiring.rs", &[]).is_none(),
            "an ungated tripwire test must not be a finding at all"
        );
    }

    /// The mirror-image failure: do not tighten so far that a real gate is
    /// missed. Indentation, a doc header, a preceding `#![allow]`, and a
    /// multi-line `all(...)` must all still be detected.
    #[test]
    fn an_indented_multi_line_gate_after_other_inner_attrs_is_still_found() {
        let src = r#"
//! Header prose.
#![allow(dead_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
   #![cfg(all(
       feature = "light",
       // a comment mid-gate
       feature = "heavy"
   ))]

#[test]
fn a() {}
"#;
        let cfg = extract_crate_cfg(src).expect("multi-line indented gate must be found");
        let e = parse_cfg_expr(&cfg).expect("and must parse");
        assert_eq!(
            e.features(),
            ["heavy", "light"].iter().map(|s| s.to_string()).collect()
        );

        let f = classify(&krate(), &target("dark"), src, "tests/dark.rs", &[]).unwrap();
        assert_eq!(
            f.verdict,
            GateVerdict::Silenced,
            "`heavy` is not in default"
        );
        assert_eq!(f.missing_features, vec!["heavy".to_string()]);
    }

    /// A `)` or `]` inside a feature name must not truncate the capture, and the
    /// prologue walk must step over earlier attributes whose brackets are
    /// themselves quoted.
    #[test]
    fn bracket_matching_is_string_aware() {
        let src = "#![doc = \"a ] bracket in prose\"]\n#![cfg(feature = \"we)ird\")]\n#[test]\nfn a() {}\n";
        assert_eq!(
            extract_crate_cfg(src).as_deref(),
            Some(r#"feature = "we)ird""#)
        );
    }

    #[test]
    fn cfg_attr_is_not_a_cfg_gate() {
        let src = "#![cfg_attr(docsrs, feature(doc_cfg))]\n#[test]\nfn t() {}\n";
        assert_eq!(extract_crate_cfg(src), None);
    }

    #[test]
    fn all_any_not_and_nesting_parse_and_evaluate() {
        let e = parse_cfg_expr(
            r#"all(feature = "a", any(feature = "b", feature = "c"), not(feature = "d"))"#,
        )
        .unwrap();
        let on = |v: &[&str]| -> BTreeSet<String> { v.iter().map(|s| s.to_string()).collect() };
        assert_eq!(e.eval(&on(&["a", "b"])), Some(true));
        assert_eq!(e.eval(&on(&["a", "b", "d"])), Some(false), "not(d) fails");
        assert_eq!(e.eval(&on(&["b"])), Some(false), "a missing");
        assert_eq!(e.eval(&on(&["a"])), Some(false), "neither b nor c");
        assert_eq!(
            e.features(),
            ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect()
        );
    }

    #[test]
    fn the_camouflage_shape_two_on_one_off_is_definitively_false() {
        // `all(default-on, default-on, default-OFF)` — reads like its running
        // siblings, compiles to nothing.
        let e =
            parse_cfg_expr(r#"all(feature = "viz", feature = "server", feature = "testmatrix")"#)
                .unwrap();
        let defaults: BTreeSet<String> = ["viz", "server"].iter().map(|s| s.to_string()).collect();
        assert!(!e.compiles_with(&defaults));
    }

    #[test]
    fn non_feature_predicates_are_unknown_never_silenced() {
        let e = parse_cfg_expr(r#"not(target_os = "windows")"#).unwrap();
        assert_eq!(e.eval(&BTreeSet::new()), None);
        assert!(e.compiles_with(&BTreeSet::new()));

        let e = parse_cfg_expr(r#"all(unix, feature = "a")"#).unwrap();
        assert!(
            !e.compiles_with(&BTreeSet::new()),
            "the feature conjunct is decisive"
        );
        assert!(e.compiles_with(&["a".to_string()].into_iter().collect()));
    }

    #[test]
    fn default_closure_is_transitive_and_skips_cross_crate_entries() {
        let t = table(&[
            ("default", &["light", "dep:serde", "other/feat"]),
            ("light", &["tiny"]),
            ("tiny", &[]),
            ("heavy", &[]),
        ]);
        let d = default_features(&t);
        assert!(
            d.contains("light") && d.contains("tiny"),
            "transitive: {d:?}"
        );
        assert!(!d.contains("heavy"));
        assert!(!d.iter().any(|f| f.contains('/') || f.starts_with("dep:")));
    }

    fn krate() -> CrateManifest {
        CrateManifest {
            name: "demo".into(),
            features: table(&[
                ("default", &["light"]),
                ("light", &[]),
                ("heavy", &[]),
                ("bundle", &["heavy"]),
            ]),
            tests: vec![],
        }
    }

    fn target(n: &str) -> TestTarget {
        TestTarget {
            name: n.into(),
            src_path: PathBuf::from(format!("tests/{n}.rs")),
        }
    }

    const DARK: &str = "#![cfg(all(feature = \"light\", feature = \"heavy\"))]\n#[test]\nfn a() {}\n#[tokio::test]\nasync fn b() {}\n";
    const LIT: &str = "#![cfg(feature = \"light\")]\n#[test]\nfn a() {}\n";

    #[test]
    fn default_on_gate_is_not_reported() {
        let f = classify(&krate(), &target("lit"), LIT, "tests/lit.rs", &[]).unwrap();
        assert_eq!(f.verdict, GateVerdict::Default);
        assert!(!f.is_silenced());
    }

    #[test]
    fn default_off_gate_is_silenced_and_counts_its_hidden_tests() {
        let f = classify(&krate(), &target("dark"), DARK, "tests/dark.rs", &[]).unwrap();
        assert_eq!(f.verdict, GateVerdict::Silenced);
        assert_eq!(f.hidden_tests, 2, "counts #[test] and #[tokio::test]");
        assert_eq!(f.missing_features, vec!["heavy".to_string()]);
        assert!(f.message().contains("ZERO tests"));
    }

    #[test]
    fn a_declared_arm_rescues_the_file_and_a_near_miss_arm_does_not() {
        // holger's shape: `cargo test -p demo --features heavy --test dark`.
        let good = MatrixArm::features(["heavy"]).package("demo").test("dark");
        let f = classify(&krate(), &target("dark"), DARK, "tests/dark.rs", &[good]).unwrap();
        assert_eq!(f.verdict, GateVerdict::Rescued);
        assert_eq!(
            f.rescued_by.as_deref(),
            Some("cargo test -p demo --features heavy --test dark")
        );

        // Near-miss (skade's `lineage` vs `lineage-http`): a different feature
        // that does not imply the needed one rescues NOTHING.
        let near = MatrixArm::features(["light"]).package("demo").test("dark");
        let f = classify(&krate(), &target("dark"), DARK, "tests/dark.rs", &[near]).unwrap();
        assert_eq!(f.verdict, GateVerdict::Silenced);

        // Wrong test target — the arm does not target this file.
        let other = MatrixArm::features(["heavy"])
            .package("demo")
            .test("something_else");
        let f = classify(&krate(), &target("dark"), DARK, "tests/dark.rs", &[other]).unwrap();
        assert_eq!(f.verdict, GateVerdict::Silenced);
    }

    #[test]
    fn workspace_wide_and_transitive_arms_rescue() {
        // No `package`, no `test` → `cargo test --workspace --features bundle`,
        // and `bundle` transitively enables `heavy`.
        let wide = MatrixArm::features(["bundle"]);
        let f = classify(&krate(), &target("dark"), DARK, "tests/dark.rs", &[wide]).unwrap();
        assert_eq!(f.verdict, GateVerdict::Rescued);

        let all = MatrixArm {
            all_features: true,
            ..Default::default()
        };
        let f = classify(&krate(), &target("dark"), DARK, "tests/dark.rs", &[all]).unwrap();
        assert_eq!(f.verdict, GateVerdict::Rescued);
    }

    #[test]
    fn no_default_features_arm_can_lose_a_conjunct() {
        // `--no-default-features --features heavy` drops `light` → still dark.
        let arm = MatrixArm {
            features: vec!["heavy".into()],
            no_default_features: true,
            ..Default::default()
        };
        let f = classify(&krate(), &target("dark"), DARK, "tests/dark.rs", &[arm]).unwrap();
        assert_eq!(f.verdict, GateVerdict::Silenced);
    }

    #[test]
    fn every_test_attribute_shape_is_counted_and_lookalikes_are_not() {
        // The real shapes the constellation's silenced files carry — knut's
        // `robot_web_viewer.rs` is `#[tokio::test(flavor = "multi_thread")]`,
        // which a naive `ends_with("test]")` match misses entirely.
        let src = r#"
#[test]
fn a() {}
#[tokio::test]
async fn b() {}
#[tokio::test(flavor = "multi_thread")]
async fn c() {}
#[actix_web::test]
async fn d() {}
    #[test]
    fn nested_and_indented() {}
// #[test] in a comment does not count
#[test_case(1, 2)]
fn not_a_test_attr() {}
#[should_panic]
#[ignore = "test"]
#[cfg(test)]
fn neither() {}
"#;
        assert_eq!(count_test_fns(src), 5);
    }

    #[test]
    fn ungated_files_are_not_findings() {
        assert!(
            classify(
                &krate(),
                &target("plain"),
                "#[test]\nfn a() {}\n",
                "t.rs",
                &[]
            )
            .is_none()
        );
    }

    #[test]
    fn metadata_parses_features_and_test_targets() {
        let json = r#"{"packages":[{"name":"demo","features":{"default":["light"],"light":[],"heavy":[]},
            "targets":[{"kind":["lib"],"name":"demo","src_path":"/r/src/lib.rs"},
                       {"kind":["test"],"name":"dark","src_path":"/r/tests/dark.rs"}]}]}"#;
        let c = parse_metadata(json).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(
            c[0].tests,
            vec![TestTarget {
                name: "dark".into(),
                src_path: PathBuf::from("/r/tests/dark.rs")
            }]
        );
        assert_eq!(
            c[0].default_set(),
            ["default", "light"].iter().map(|s| s.to_string()).collect()
        );
    }

    #[test]
    fn report_rows_are_red_for_silenced_and_carry_the_hidden_count() {
        let k = krate();
        let files = vec![
            classify(&k, &target("dark"), DARK, "tests/dark.rs", &[]).unwrap(),
            classify(&k, &target("lit"), LIT, "tests/lit.rs", &[]).unwrap(),
        ];
        let rep = GatedTestReport {
            run_id: "r1".into(),
            repo: "demo".into(),
            files,
            scanned: 2,
            arms: vec![],
        };
        assert!(!rep.is_green());
        assert_eq!(rep.hidden_tests(), 2);
        let rows = rep.rows();
        assert_eq!(rows.len(), 2);
        let dark = rows
            .iter()
            .find(|r| r.test_name == "gated-tests::dark")
            .unwrap();
        assert_eq!(dark.status, status::FAIL);
        assert!(status::is_red(&dark.status));
        assert_eq!(dark.aspect, ASPECT_GATED_TESTS);
        assert_eq!(dark.metric, 2.0);
        assert_eq!(dark.repo, "demo");
        assert_eq!(dark.suite, "demo");
        let lit = rows
            .iter()
            .find(|r| r.test_name == "gated-tests::lit")
            .unwrap();
        assert_eq!(lit.status, status::PASS);
    }

    #[test]
    fn arms_round_trip_through_the_declaration_file_shape() {
        let json = r#"{"arms":[
            {"package":"holger-ui","features":["gui"],"test":"robot_ui_app"},
            {"features":["testmatrix"],"note":"workspace-wide functional lane"}
        ]}"#;
        let a: MatrixArms = serde_json::from_str(json).unwrap();
        assert_eq!(a.arms.len(), 2);
        assert_eq!(
            a.arms[0].command(),
            "cargo test -p holger-ui --features gui --test robot_ui_app"
        );
        assert_eq!(a.arms[1].command(), "cargo test --features testmatrix");
        assert!(a.arms[1].targets("anything", "anything"));
    }
}
