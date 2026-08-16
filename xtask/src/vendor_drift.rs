// SPDX-FileCopyrightText: 2026 Vetra Automation AB
// SPDX-License-Identifier: AGPL-3.0-only

//! Vendored-subtree drift — the check garmr did not have.
//!
//! garmr vendors five sibling repos as committed git subtrees under `vendor/`
//! and *builds against them* (`skade = { path = "vendor/skade/skade" }`,
//! `znippy-common = { path = "vendor/znippy/znippy-common" }`, and
//! `znippy_zoomies::vann` behind garmr-embed's ANN index). Nothing compared
//! those trees to the repos they came from, so a hand-edit to a vendored file,
//! or an upstream that has moved on, was invisible.
//!
//! Two arms, because they catch different things and fail for different reasons:
//!
//! 1. **working tree** — any uncommitted modification under `vendor/`. A
//!    vendored subtree is upstream's content; editing it in place is how the
//!    fork silently starts. Asserts wherever the repo is checked out, needs no
//!    sibling.
//! 2. **upstream** — every tracked blob under `vendor/<sibling>/` compared by
//!    git blob oid against the same relative path in the sibling's
//!    `origin/<default>`. Needs the sibling repo on disk.
//!
//! Comparison is by **blob oid from the committed tree**, never by hashing the
//! working-tree file: `docs/manual.pdf` and 24 vendored assets are Git-LFS, so
//! the committed blob is the LFS *pointer* while the checked-out file is the
//! smudged content. Hashing the file would report all 25 as drifted forever —
//! a check that is always red is as useless as one that is always green.
//!
//! ## Why a baseline set and not a count
//!
//! The measured drift is large and mostly *staleness* (facett's upstream has
//! advanced 853 commits past the recorded subtree-split; znippy-zoomies' 245),
//! not local edits. Resyncing it is a product decision, not this check's job.
//! So the check records the exact drifted **paths** and fails when that set
//! changes in either direction:
//!
//! * a path that used to match upstream now differs → drift GREW;
//! * a path the baseline lists as drifted now matches → the baseline is STALE.
//!
//! A `<=` count budget would have a net-zero blind spot: one file drifting
//! while another is resynced leaves the count untouched. A set cannot sit on
//! that identity value.
//!
//! ## Honest degradation
//!
//! A sibling that is not on disk, or has no `origin/<default>`, is reported as
//! `NOT COVERED` and asserted against nothing — never folded into the pass. If
//! *no* sibling could be measured the run says so on its own line, so a green
//! log cannot be mistaken for a green check. `--require-coverage` turns that
//! into a failure for a machine that is supposed to have the siblings.
//!
//! ```text
//! cargo xtask vendor-drift                     # report + assert vs baseline
//! cargo xtask vendor-drift --require-coverage   # also fail if a sibling is missing
//! cargo xtask vendor-drift --bless              # rewrite the baseline after review
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// The vendored siblings and the upstream branch each is vendored from.
/// znippy and znippy-zoomies are `master`, not `main` — getting this wrong
/// would silently turn a sibling into `NOT COVERED`, which is why the run
/// prints the resolved ref for every covered sibling.
const SIBLINGS: &[(&str, &str)] = &[
    ("edda", "main"),
    ("facett", "main"),
    ("skade", "main"),
    ("znippy", "master"),
    ("znippy-zoomies", "master"),
];

/// Baseline location, relative to the garmr repo root.
const BASELINE: &str = "supply-chain/vendor-drift.baseline";

/// How a vendored path relates to its upstream counterpart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Status {
    /// Present upstream at the same path, different blob.
    Drift,
    /// Tracked here, absent from the sibling's `origin/<default>` tree.
    AbsentUpstream,
}

impl Status {
    fn tag(self) -> &'static str {
        match self {
            Status::Drift => "drift",
            Status::AbsentUpstream => "absent-upstream",
        }
    }
}

/// One baseline row: `<sibling>\t<status>\t<relpath>`.
fn row(sibling: &str, status: Status, rel: &str) -> String {
    format!("{sibling}\t{}\t{rel}", status.tag())
}

/// What measuring one sibling produced.
enum Outcome {
    /// The sibling could not be measured. Asserted nothing.
    NotCovered(String),
    Measured {
        /// The sibling ref this was measured against, resolved to a commit oid,
        /// so a baseline can be read back against a known upstream point.
        r#ref: String,
        oid: String,
        /// Tracked files under `vendor/<sibling>/`.
        total: usize,
        same: usize,
        rows: Vec<String>,
        drift: usize,
        absent: usize,
    },
}

/// Run a git command, and fail on a non-zero status *carrying its stderr*.
///
/// A malformed git invocation exits non-zero with an empty stdout, and an empty
/// stdout is shaped exactly like "no drift". Checking the status and quoting
/// stderr is what keeps a broken command from reading as a clean result.
fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .with_context(|| format!("spawning git {args:?} in {}", dir.display()))?;
    if !out.status.success() {
        bail!(
            "git {args:?} in {} failed ({}): {}",
            dir.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

/// `git ls-tree -rz <refspec> [-- <pathspec>]` → `relpath -> blob oid`.
///
/// `-z` (NUL-delimited) rather than plain `-r`: without it git *quotes* paths
/// containing unusual bytes, and a quoted path would never match its upstream
/// twin — a silent false "drift".
fn tree_blobs(
    dir: &Path,
    refspec: &str,
    pathspec: Option<&str>,
    strip: &str,
) -> Result<BTreeMap<String, String>> {
    let mut args = vec!["ls-tree", "-r", "-z", refspec];
    if let Some(p) = pathspec {
        args.push("--");
        args.push(p);
    }
    let raw = git(dir, &args)?;
    let mut map = BTreeMap::new();
    for rec in raw.split(|b| *b == 0) {
        if rec.is_empty() {
            continue;
        }
        let rec = String::from_utf8_lossy(rec);
        // "<mode> SP <type> SP <oid> TAB <path>"
        let (meta, path) = match rec.split_once('\t') {
            Some(p) => p,
            None => continue,
        };
        let mut f = meta.split(' ');
        let _mode = f.next();
        let kind = f.next().unwrap_or("");
        let oid = f.next().unwrap_or("");
        if kind != "blob" || oid.is_empty() {
            continue; // submodule/commit entries have no comparable content
        }
        let rel = path.strip_prefix(strip).unwrap_or(path).to_string();
        map.insert(rel, oid.to_string());
    }
    Ok(map)
}

/// The garmr repo root (this crate's parent directory).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent")
        .to_path_buf()
}

/// Where the sibling checkouts live. `GARMR_SIBLING_ROOT` overrides; otherwise
/// the directory holding garmr itself (the fleet layout: sibling checkouts
/// beside this repo).
fn sibling_root() -> Option<PathBuf> {
    if let Some(v) = std::env::var_os("GARMR_SIBLING_ROOT") {
        return Some(PathBuf::from(v));
    }
    repo_root().parent().map(Path::to_path_buf)
}

/// Uncommitted modifications to tracked files under `vendor/`.
fn working_tree_edits(root: &Path) -> Result<Vec<String>> {
    let raw = git(root, &["status", "--porcelain=1", "-z", "--", "vendor"])?;
    let mut out = Vec::new();
    let mut it = raw.split(|b| *b == 0);
    while let Some(rec) = it.next() {
        if rec.len() < 4 {
            continue;
        }
        let rec = String::from_utf8_lossy(rec).to_string();
        let (xy, path) = rec.split_at(3);
        // A rename/copy entry is followed by its origin path in the next
        // NUL-delimited field; consume it so it is not read as a status line.
        if xy.starts_with('R') || xy.starts_with('C') {
            let _ = it.next();
        }
        out.push(format!("{} {}", xy.trim_end(), path));
    }
    out.sort();
    Ok(out)
}

/// Compare every vendored sibling against its upstream.
fn measure(root: &Path) -> Vec<(&'static str, Outcome)> {
    let sib_root = sibling_root();
    SIBLINGS
        .iter()
        .map(|&(name, branch)| {
            let outcome = match measure_one(root, sib_root.as_deref(), name, branch) {
                Ok(o) => o,
                Err(e) => Outcome::NotCovered(format!("{e:#}")),
            };
            (name, outcome)
        })
        .collect()
}

fn measure_one(root: &Path, sib_root: Option<&Path>, name: &str, branch: &str) -> Result<Outcome> {
    let sib_root = match sib_root {
        Some(p) => p,
        None => return Ok(Outcome::NotCovered("no sibling root".into())),
    };
    let sib = sib_root.join(name);
    if !sib.join(".git").exists() {
        return Ok(Outcome::NotCovered(format!(
            "no checkout at {} (set GARMR_SIBLING_ROOT)",
            sib.display()
        )));
    }
    let refspec = format!("origin/{branch}");
    let oid = match git(&sib, &["rev-parse", "--verify", "--quiet", &refspec]) {
        Ok(o) => String::from_utf8_lossy(&o).trim().to_string(),
        Err(_) => {
            return Ok(Outcome::NotCovered(format!(
                "{} has no {refspec}",
                sib.display()
            )))
        }
    };
    if oid.is_empty() {
        return Ok(Outcome::NotCovered(format!(
            "{} resolved {refspec} to nothing",
            sib.display()
        )));
    }

    let prefix = format!("vendor/{name}/");
    let ours = tree_blobs(root, "HEAD", Some(&format!("vendor/{name}")), &prefix)?;
    // An empty `ours` means the pathspec matched nothing — a typo'd sibling name
    // or a moved vendor dir. That is a broken measurement, not zero drift, and
    // it must never be reported as a pass.
    if ours.is_empty() {
        bail!("no tracked files under {prefix} — the measurement, not the drift, is empty");
    }
    let theirs = tree_blobs(&sib, &oid, None, "")?;
    if theirs.is_empty() {
        bail!("{} at {refspec} listed no blobs", sib.display());
    }

    let mut rows = Vec::new();
    let (mut same, mut drift, mut absent) = (0usize, 0usize, 0usize);
    for (rel, our_oid) in &ours {
        match theirs.get(rel) {
            None => {
                absent += 1;
                rows.push(row(name, Status::AbsentUpstream, rel));
            }
            Some(up) if up == our_oid => same += 1,
            Some(_) => {
                drift += 1;
                rows.push(row(name, Status::Drift, rel));
            }
        }
    }
    Ok(Outcome::Measured {
        r#ref: refspec,
        oid,
        total: ours.len(),
        same,
        rows,
        drift,
        absent,
    })
}

fn pct(n: usize, d: usize) -> String {
    if d == 0 {
        "n/a".into()
    } else {
        format!("{:.1}%", 100.0 * n as f64 / d as f64)
    }
}

/// Parse a baseline file into its row set, ignoring comments and blank lines.
fn parse_baseline(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

fn render_baseline(measured: &[(&'static str, Outcome)], rows: &BTreeSet<String>) -> String {
    let mut s = String::new();
    s.push_str("# garmr vendored-subtree drift baseline.\n");
    s.push_str("# One row per vendored path that does NOT match its upstream counterpart:\n");
    s.push_str("#   <sibling>\\t<drift|absent-upstream>\\t<path relative to vendor/<sibling>/>\n");
    s.push_str("#\n");
    s.push_str("# Generated by `cargo xtask vendor-drift --bless`. Reviewed, not aspirational:\n");
    s.push_str("# it records the drift that EXISTS so the check can fail when it CHANGES —\n");
    s.push_str("# in either direction. Resyncing or de-vendoring these trees is a separate\n");
    s.push_str("# product decision; this file only makes the current state observable.\n");
    s.push_str("#\n");
    s.push_str("# Measured against (informational — not asserted, so a sibling commit does\n");
    s.push_str("# not invalidate the file by itself):\n");
    for (name, o) in measured {
        match o {
            Outcome::NotCovered(why) => {
                s.push_str(&format!("#   {name}: NOT COVERED — {why}\n"));
            }
            Outcome::Measured {
                r#ref,
                oid,
                total,
                same,
                drift,
                absent,
                ..
            } => s.push_str(&format!(
                "#   {name}: {ref}@{} total={total} same={same} drift={drift} ({}) absent-upstream={absent}\n",
                &oid[..oid.len().min(12)],
                pct(*drift, *total),
            )),
        }
    }
    s.push('\n');
    for r in rows {
        s.push_str(r);
        s.push('\n');
    }
    s
}

/// `cargo xtask vendor-drift [--bless] [--require-coverage]`
pub fn vendor_drift(rest: Vec<String>) -> Result<()> {
    let bless = rest.iter().any(|a| a == "--bless");
    let require = rest.iter().any(|a| a == "--require-coverage");
    if let Some(bad) = rest
        .iter()
        .find(|a| !matches!(a.as_str(), "--bless" | "--require-coverage"))
    {
        bail!("unknown vendor-drift flag: {bad}");
    }
    let root = repo_root();

    // ---- arm 1: the working tree -----------------------------------------
    let edits = working_tree_edits(&root)?;
    if !edits.is_empty() {
        eprintln!("vendor/ has {} uncommitted modification(s):", edits.len());
        for e in &edits {
            eprintln!("  {e}");
        }
    }

    // ---- arm 2: upstream --------------------------------------------------
    let measured = measure(&root);
    let mut rows = BTreeSet::new();
    let mut covered = 0usize;
    println!("vendored-subtree drift (blob oids, committed trees):");
    for (name, o) in &measured {
        match o {
            Outcome::NotCovered(why) => println!("  {name:<16} NOT COVERED — {why}"),
            Outcome::Measured {
                r#ref,
                oid,
                total,
                same,
                drift,
                absent,
                rows: r,
            } => {
                covered += 1;
                rows.extend(r.iter().cloned());
                println!(
                    "  {name:<16} vs {ref}@{}  total={total} same={same} drift={drift} ({}) absent-upstream={absent}",
                    &oid[..oid.len().min(8)],
                    pct(*drift, *total),
                );
            }
        }
    }
    if covered == 0 {
        println!(
            "NOT COVERED — asserted nothing: 0 of {} siblings resolvable; this run gates nothing",
            SIBLINGS.len()
        );
    } else {
        println!(
            "covered {covered}/{} siblings; {} drifted path(s) recorded",
            SIBLINGS.len(),
            rows.len()
        );
    }

    let baseline_path = root.join(BASELINE);
    if bless {
        if covered == 0 {
            bail!("refusing to bless a baseline measured from 0 siblings — it would record an empty drift set as truth");
        }
        if let Some(p) = baseline_path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(&baseline_path, render_baseline(&measured, &rows))
            .with_context(|| format!("writing {}", baseline_path.display()))?;
        println!("blessed {} ({} rows)", baseline_path.display(), rows.len());
        return Ok(());
    }

    let mut failures: Vec<String> = Vec::new();
    if !edits.is_empty() {
        failures.push(format!(
            "{} vendored file(s) modified in the working tree — a vendored subtree is \
             upstream's content; edit it upstream and re-pull the subtree",
            edits.len()
        ));
    }
    if require && covered < SIBLINGS.len() {
        failures.push(format!(
            "--require-coverage: only {covered}/{} siblings measurable",
            SIBLINGS.len()
        ));
    }
    if covered > 0 {
        let want = parse_baseline(
            &std::fs::read_to_string(&baseline_path)
                .with_context(|| format!("reading {}", baseline_path.display()))?,
        );
        // Only compare the siblings actually measured; an absent sibling must
        // not make its baseline rows look "resolved".
        let measured_names: BTreeSet<&str> = measured
            .iter()
            .filter(|(_, o)| matches!(o, Outcome::Measured { .. }))
            .map(|(n, _)| *n)
            .collect();
        let want: BTreeSet<String> = want
            .into_iter()
            .filter(|r| {
                r.split('\t')
                    .next()
                    .is_some_and(|n| measured_names.contains(n))
            })
            .collect();
        let grew: Vec<&String> = rows.difference(&want).collect();
        let resolved: Vec<&String> = want.difference(&rows).collect();
        if !grew.is_empty() {
            failures.push(format!("vendor drift GREW by {} path(s)", grew.len()));
            for r in grew.iter().take(20) {
                eprintln!("  + {r}");
            }
        }
        if !resolved.is_empty() {
            failures.push(format!(
                "baseline is STALE: {} path(s) it lists as drifted now match upstream",
                resolved.len()
            ));
            for r in resolved.iter().take(20) {
                eprintln!("  - {r}");
            }
        }
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("✗ {f}");
        }
        bail!(
            "vendored-subtree drift check failed; after review: cargo xtask vendor-drift --bless"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The drift check itself, run against the real trees.
    ///
    /// RED before green: `touch`ing any vendored file makes the working-tree arm
    /// fail; committing a one-byte change to a vendored file that currently
    /// MATCHES upstream makes the upstream arm fail with "vendor drift GREW".
    /// Both were provoked and observed before this test was trusted.
    #[test]
    fn vendored_trees_match_the_drift_baseline() {
        let root = repo_root();
        let measured = measure(&root);
        let covered: Vec<&str> = measured
            .iter()
            .filter(|(_, o)| matches!(o, Outcome::Measured { .. }))
            .map(|(n, _)| *n)
            .collect();
        if covered.is_empty() {
            // A real skip, not a pass: name what was not checked.
            for (name, o) in &measured {
                if let Outcome::NotCovered(why) = o {
                    eprintln!("  {name}: NOT COVERED — {why}");
                }
            }
            eprintln!(
                "NOT COVERED — asserted nothing: no sibling checkout found \
                 (set GARMR_SIBLING_ROOT); this test gated nothing"
            );
            return;
        }

        // A measurement that found no files is a broken measurement, not zero
        // drift — `measure_one` already refuses it, so assert the population is
        // real rather than trusting an empty set.
        for (name, o) in &measured {
            if let Outcome::Measured { total, .. } = o {
                assert!(*total > 0, "{name}: measured 0 vendored files");
            }
        }

        let rows: BTreeSet<String> = measured
            .iter()
            .filter_map(|(_, o)| match o {
                Outcome::Measured { rows, .. } => Some(rows.clone()),
                _ => None,
            })
            .flatten()
            .collect();

        let text = std::fs::read_to_string(root.join(BASELINE))
            .unwrap_or_else(|e| panic!("reading {BASELINE}: {e}"));
        let want: BTreeSet<String> = parse_baseline(&text)
            .into_iter()
            .filter(|r| r.split('\t').next().is_some_and(|n| covered.contains(&n)))
            .collect();
        assert!(
            !want.is_empty(),
            "the baseline has no rows for the covered siblings {covered:?} — an \
             empty expectation cannot tell drift from a broken comparison"
        );

        let grew: Vec<&String> = rows.difference(&want).collect();
        let resolved: Vec<&String> = want.difference(&rows).collect();
        assert!(
            grew.is_empty(),
            "vendor drift GREW by {} path(s) — a vendored file no longer matches \
             its upstream: {:?}\nafter review: cargo xtask vendor-drift --bless",
            grew.len(),
            grew.iter().take(10).collect::<Vec<_>>()
        );
        assert!(
            resolved.is_empty(),
            "the drift baseline is STALE: {} path(s) it lists as drifted now match \
             upstream: {:?}\nrefresh it: cargo xtask vendor-drift --bless",
            resolved.len(),
            resolved.iter().take(10).collect::<Vec<_>>()
        );

        let edits = working_tree_edits(&root).expect("git status under vendor/");
        assert!(
            edits.is_empty(),
            "vendored file(s) modified in the working tree: {edits:?} — a vendored \
             subtree is upstream's content; edit it upstream and re-pull"
        );
    }

    /// The baseline parser must ignore provenance comments and blank lines, and
    /// keep exactly the rows. If it swallowed real rows the expectation would
    /// shrink toward empty and the check would quietly stop failing.
    #[test]
    fn baseline_parser_keeps_rows_and_drops_comments() {
        let got = parse_baseline(
            "# header\n#   skade: main@abc total=1\n\nskade\tdrift\tsrc/a.rs\nfacett\tabsent-upstream\tb.rs\n",
        );
        assert_eq!(
            got,
            ["skade\tdrift\tsrc/a.rs", "facett\tabsent-upstream\tb.rs"]
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<_>>()
        );
    }

    /// `git ls-tree -z` parsing: a tab separates metadata from the path, and a
    /// path may itself contain spaces. Getting this wrong would mis-key every
    /// entry and report total drift.
    #[test]
    fn tree_blobs_parses_real_ls_tree_output() {
        let root = repo_root();
        let blobs = tree_blobs(&root, "HEAD", Some("Cargo.toml"), "").expect("ls-tree HEAD");
        let oid = blobs
            .get("Cargo.toml")
            .expect("garmr's root Cargo.toml is tracked");
        let want = String::from_utf8(git(&root, &["rev-parse", "HEAD:Cargo.toml"]).unwrap())
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(oid, &want, "parsed blob oid must be the real one");
    }
}
