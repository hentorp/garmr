//! Guard test for this crate's **leaf law**: the DEFAULT build must have ZERO
//! dependencies — std only.
//!
//! Why this is mechanical rather than a comment. `nornir-warehouse-trait` is named
//! like a seam but pulls arrow 58, iceberg, skade, uuid, chrono and nornir-bench,
//! and every consumer of that "trait" inherits all of it. Nothing stopped that
//! happening except intent. So the rule here is checked: this test parses this
//! crate's own `Cargo.toml` and fails if ANY `[dependencies]` entry is not
//! `optional = true`, which is exactly the condition under which
//! `cargo tree -e normal` (default features) prints a single line.
//!
//! Adding a normal dependency without `optional = true` — or a `default` feature
//! that switches one on — turns this red.

use std::path::Path;

/// Rough-and-ready TOML slicing: enough to read a `[dependencies]` table without
/// adding a TOML parser to a crate whose entire point is having no dependencies.
/// (Using `toml` here would itself be a dev-dep, which is allowed, but parsing the
/// manifest with the thing the manifest forbids reads badly and is not needed.)
fn section<'a>(manifest: &'a str, header: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            inside = t == header;
            continue;
        }
        if inside && !t.is_empty() && !t.starts_with('#') {
            out.push(t);
        }
    }
    out
}

#[test]
fn the_default_build_has_no_dependencies() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read own Cargo.toml");

    let deps = section(&manifest, "[dependencies]");
    assert!(
        !deps.is_empty(),
        "parsed no [dependencies] at all — the guard would be blind"
    );

    let mandatory: Vec<&str> = deps
        .iter()
        .filter(|l| !l.contains("optional = true"))
        .copied()
        .collect();
    assert!(
        mandatory.is_empty(),
        "nornir-graph must be a TRUE LEAF: every dependency has to be optional so the \
         default build is std-only. These are not:\n  {}",
        mandatory.join("\n  ")
    );

    // The default feature set must not switch any of them on either.
    let features = section(&manifest, "[features]");
    let default = features
        .iter()
        .find(|l| l.starts_with("default"))
        .expect("an explicit `default = [...]` line, so this cannot pass by omission");
    assert_eq!(
        default.replace(' ', ""),
        "default=[]",
        "the default feature set must be empty; got: {default}"
    );
}

/// The guard above only means something if the dependency list it walks is the real
/// one. Pin the backends by name so a rename or a silent removal is visible.
#[test]
fn the_optional_backends_are_the_expected_ones() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read own Cargo.toml");
    for dep in ["serde", "petgraph", "cozo"] {
        assert!(
            section(&manifest, "[dependencies]")
                .iter()
                .any(|l| l.starts_with(dep)),
            "expected optional dependency `{dep}` is missing"
        );
    }
    // cozo must never take its default features (they bundle the SQLite C source).
    let cozo = section(&manifest, "[dependencies]")
        .into_iter()
        .find(|l| l.starts_with("cozo"))
        .expect("cozo dependency line");
    assert!(
        cozo.contains("default-features = false"),
        "cozo must keep `default-features = false`; got: {cozo}"
    );
}
