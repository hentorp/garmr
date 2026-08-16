//! **A cited guard must exist** — the phantom-citation audit.
//!
//! Comments justify code by naming the test that covers it: *"(Integration tests
//! against a live FalkorDB instance live in the integration test file.)"*. That
//! sentence is load-bearing — a reader who sees it stops looking for coverage.
//! When the named file does not exist the comment is a **phantom guard**, and a
//! pointer to an imaginary guard is *indistinguishable from a real one*. It reads
//! as green.
//!
//! This is the sibling of [`crate::gatedtests`]: that one catches tests that can
//! never RUN, this one catches tests that never EXISTED.
//!
//! ## Found in the wild
//!
//! * knut's `graphar-falkordb/src/tests.rs` cited an integration-test file that has
//!   never existed in that repo — directly above a `#[tokio::test]` whose name promised query
//!   verification and whose body asserted only that its own fixture had three rows.
//!   Under both sat a row-render loop written out twice, tested on one copy only:
//!   dropping `_gar_id` from the untested copy left all 42 tests green while the
//!   loader silently stopped emitting the property every edge insert matches on.
//! * facett's `saga.proto` header cited a `test_saga_wire` python file as proof
//!   the wire subset could not drift. No file of that name has ever existed in any
//!   repo. (Named without its path on purpose — this audit reads its own source,
//!   and a post-mortem is indistinguishable from a claim.)
//!
//! ## Why it is quiet enough to keep
//!
//! A guard that cries wolf gets switched off, so this one refuses to guess:
//!
//! * **Comments only.** `classify(…, "tests/foo.rs")` passes a *fixture name* to
//!   a parser; it does not claim a file exists. String literals are stripped.
//!   (Written with a placeholder stem on purpose — this audit runs over its own
//!   source, and it is right to.)
//! * **Siblings resolve.** A comment in edda naming `tests/viz_surface.rs` means
//!   nornir's file. Pass the sibling checkouts and cross-repo citations resolve
//!   instead of being reported as missing.
//! * **Placeholders are not citations.** `<c>/tests/foo.rs → "<c>::tests::foo"`
//!   illustrates a path→module mapping. Stems in [`PLACEHOLDER_STEMS`], and any
//!   stem of one or two characters (`src/a.rs`, `src/a/b.rs`), are skipped.
//! * **`.nornir/` is not scanned.** That is the design/planning dir; a proposal
//!   naming the file it intends to add is a plan, not a false coverage claim.
//! * **A visible escape hatch.** `.nornir/citation-allow.txt` (one path per line,
//!   `#` comments) suppresses the rest — enumerable, reviewable, and burnable,
//!   the same shape as autonom's allowlist.
//!
//! Measured on the fleet before those three rules existed, ~4 of every 5 hits were
//! illustrative or cross-repo rather than defects. The rules are the difference
//! between a finding and a nuisance.
//!
//! ```no_run
//! let rep = nornir_testmatrix::audit_citations(std::path::Path::new("."), &[]);
//! assert!(rep.phantoms.is_empty(), "{}", rep.summary());
//! ```

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The allowlist a repo may keep to suppress a citation this audit cannot resolve.
pub const ALLOW_FILE: &str = ".nornir/citation-allow.txt";

/// File stems that are universally illustrative, never a real coverage claim.
pub const PLACEHOLDER_STEMS: &[&str] = &[
    "foo",
    "bar",
    "baz",
    "qux",
    "t",
    "x",
    "y",
    "example",
    "my_test",
    "some_test",
];

/// First path segments a citation must start with to be considered repo-relative.
/// Anything else is a URL path or another project's layout — not ours to guess at.
const OURS: &[&str] = &["tests", "src", "crates", "xtask", "benches", "py", "server"];

/// Extensions a comment can cite as coverage.
const CITED_EXT: &[&str] = &["rs", "py", "js", "ts", "go", "sh"];

/// One comment that names a file which does not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhantomCitation {
    /// Repo-relative path of the file holding the comment.
    pub file: String,
    /// 1-based line of the citation.
    pub line: usize,
    /// The cited path, exactly as written.
    pub cited: String,
}

/// The audit's verdict for one repo.
#[derive(Debug, Clone, Default)]
pub struct CitationReport {
    /// Citations that resolve to nothing, here or in any sibling passed in.
    pub phantoms: Vec<PhantomCitation>,
    /// How many citations were examined (a zero here means the scan is broken,
    /// not that the repo is clean — [`CitationReport::is_trustworthy`]).
    pub checked: usize,
    /// Entries read from [`ALLOW_FILE`].
    pub allowed: usize,
}

impl CitationReport {
    /// A scan that examined nothing proves nothing.
    pub fn is_trustworthy(&self) -> bool {
        self.checked > 0
    }

    /// A one-block, paste-into-a-failure summary.
    pub fn summary(&self) -> String {
        if self.phantoms.is_empty() {
            return format!(
                "{} citation(s) checked, {} allowlisted, 0 phantom",
                self.checked, self.allowed
            );
        }
        let mut s = String::from(
            "PHANTOM GUARD CITATIONS — a comment names a test file that does not exist.\n\
             A pointer to an imaginary guard reads exactly like a real one; a reader who\n\
             sees it stops looking for coverage. Fix the path, or delete the claim.\n\n",
        );
        for p in &self.phantoms {
            s.push_str(&format!(
                "  {}:{}  cites  {}  — NO SUCH FILE\n",
                p.file, p.line, p.cited
            ));
        }
        s.push_str(&format!(
            "\n({} checked, {} allowlisted via {})",
            self.checked, self.allowed, ALLOW_FILE
        ));
        s
    }
}

fn tracked(root: &Path) -> Vec<String> {
    let Ok(out) = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("ls-files")
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// Everything that is a comment in Rust source, with string literals removed so a
/// fixture NAME passed as an argument is never mistaken for a claim of coverage.
/// Newlines are preserved so line numbers survive.
fn rust_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let (mut i, mut in_str, mut in_raw, mut esc) = (0usize, false, false, false);
    while i < b.len() {
        let c = b[i] as char;
        if in_str {
            if in_raw {
                if c == '"' {
                    in_str = false;
                    in_raw = false;
                }
            } else if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            if c == '\n' {
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if c == 'r' && i + 1 < b.len() && (b[i + 1] == b'"' || b[i + 1] == b'#') {
            let mut j = i + 1;
            while j < b.len() && b[j] == b'#' {
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                in_str = true;
                in_raw = true;
                i = j + 1;
                continue;
            }
        }
        if c == '"' {
            in_str = true;
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == b'/' {
            let end = src[i..].find('\n').map(|n| i + n).unwrap_or(b.len());
            out.push_str(&src[i..end]);
            i = end;
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == b'*' {
            let end = src[i + 2..]
                .find("*/")
                .map(|n| i + 2 + n + 2)
                .unwrap_or(b.len());
            out.push_str(&src[i..end]);
            i = end;
            continue;
        }
        if c == '\n' {
            out.push('\n');
        }
        i += 1;
    }
    out
}

/// Pull `a/b/c.rs`-shaped tokens, with their 1-based line numbers, out of prose.
fn citations(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let mut seen = BTreeSet::new();
        for raw in
            line.split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/')))
        {
            let tok = raw.trim_matches(|c| c == '.' || c == '/');
            if !tok.contains('/') || tok.contains("..") {
                continue;
            }
            let Some((stem_path, ext)) = tok.rsplit_once('.') else {
                continue;
            };
            if !CITED_EXT.contains(&ext) {
                continue;
            }
            let stem = stem_path.rsplit('/').next().unwrap_or("");
            if PLACEHOLDER_STEMS.contains(&stem) || stem.chars().count() <= 2 {
                continue;
            }
            if !OURS.contains(&tok.split('/').next().unwrap_or("")) {
                continue;
            }
            if seen.insert(tok.to_string()) {
                found.push((idx + 1, tok.to_string()));
            }
        }
    }
    found
}

/// The crate directory a file belongs to (nearest ancestor holding a Cargo.toml).
fn crate_dir_of(root: &Path, file: &str) -> Option<String> {
    let mut cur = Path::new(file).parent()?;
    loop {
        if root.join(cur).join("Cargo.toml").is_file() {
            let s = cur.to_string_lossy().to_string();
            return Some(if s.is_empty() { s } else { format!("{s}/") });
        }
        cur = cur.parent()?;
    }
}

fn resolves(
    cited: &str,
    citing: &str,
    root: &Path,
    own: &BTreeSet<String>,
    sib: &BTreeSet<String>,
) -> bool {
    if own.contains(cited) {
        return true;
    }
    if let Some(dir) = crate_dir_of(root, citing) {
        if own.contains(&format!("{dir}{cited}")) {
            return true;
        }
    }
    // In a SIBLING checkout the citation is that repo's root-relative path, so an
    // exact hit counts as well as a suffix hit. (Missing this made every legitimate
    // cross-repo pointer look like a phantom.)
    if sib.contains(cited) {
        return true;
    }
    let suffix = format!("/{cited}");
    own.iter().any(|f| f.ends_with(&suffix)) || sib.iter().any(|f| f.ends_with(&suffix))
}

/// Audit one repo's comments for citations of files that do not exist.
///
/// `siblings` are other checkouts whose files may legitimately be cited (a comment
/// in edda naming `tests/viz_surface.rs` means nornir's). Pass `&[]` to require
/// every citation to resolve inside `repo_root` alone.
pub fn audit_citations(repo_root: &Path, siblings: &[PathBuf]) -> CitationReport {
    let own_files = tracked(repo_root);
    let own: BTreeSet<String> = own_files.iter().cloned().collect();
    let mut sib: BTreeSet<String> = BTreeSet::new();
    for s in siblings {
        sib.extend(tracked(s));
    }

    let allow: BTreeSet<String> = std::fs::read_to_string(repo_root.join(ALLOW_FILE))
        .unwrap_or_default()
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut rep = CitationReport {
        allowed: allow.len(),
        ..Default::default()
    };
    for f in &own_files {
        if f.starts_with("vendor/") || f.contains("/vendor/") {
            continue;
        }
        // The design/planning dir: a proposal naming the file it intends to add is
        // a plan, not a claim that coverage already exists.
        if f.starts_with(".nornir/") || f.contains("/.nornir/") {
            continue;
        }
        let is_rs = f.ends_with(".rs");
        let is_prose = f.ends_with(".md") || f.ends_with(".proto");
        if !is_rs && !is_prose {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(repo_root.join(f)) else {
            continue;
        };
        let text = if is_rs { rust_comments(&src) } else { src };
        for (line, cited) in citations(&text) {
            if allow.contains(&cited) {
                continue;
            }
            rep.checked += 1;
            if !resolves(&cited, f, repo_root, &own, &sib) {
                rep.phantoms.push(PhantomCitation {
                    file: f.clone(),
                    line,
                    cited,
                });
            }
        }
    }
    rep
}

/// Sibling checkouts of `repo_root` — every directory beside it that is a git
/// repo. The nordisk layout is one flat parent dir of sibling repos.
pub fn sibling_checkouts(repo_root: &Path) -> Vec<PathBuf> {
    let Some(parent) = repo_root.parent() else {
        return Vec::new();
    };
    let Ok(rd) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let me = repo_root.canonicalize().ok();
    rd.filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join(".git").exists() && p.canonicalize().ok() != me)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_literals_are_not_citations() {
        let src = "let f = classify(src, \"tests/dark.rs\");\n// see tests/real.rs\n";
        let c = rust_comments(src);
        assert!(
            !c.contains("tests/dark.rs"),
            "a fixture name in a literal is not a claim"
        );
        assert!(c.contains("tests/real.rs"));
    }

    #[test]
    fn line_numbers_survive_literal_stripping() {
        let src = "let a = \"tests/x.rs\";\n\n// covered by tests/three.rs\n";
        let hits = citations(&rust_comments(src));
        assert_eq!(hits, vec![(3, "tests/three.rs".to_string())]);
    }

    #[test]
    fn placeholders_are_not_citations() {
        let hits = citations("// `<c>/tests/foo.rs` -> `<c>::tests::foo`; also tests/t.rs\n");
        assert!(
            hits.is_empty(),
            "illustrative stems must not be reported: {hits:?}"
        );
    }

    #[test]
    fn another_projects_layout_is_not_ours_to_guess() {
        let hits = citations("// mirrors facett-demo/tests/robot_demo.rs\n");
        assert!(
            hits.is_empty(),
            "cross-project paths are skipped, not guessed: {hits:?}"
        );
    }

    #[test]
    fn a_real_citation_is_found_with_its_line() {
        let hits = citations("//! header\n//! see tests/support/mcp_harness.rs for the template\n");
        assert_eq!(hits, vec![(2, "tests/support/mcp_harness.rs".to_string())]);
    }

    #[test]
    fn an_empty_scan_is_not_trustworthy() {
        let rep = CitationReport::default();
        assert!(
            !rep.is_trustworthy(),
            "zero checked means broken, not clean"
        );
    }
}
