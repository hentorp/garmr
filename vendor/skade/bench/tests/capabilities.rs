//! Front-page capability-matrix drift guard.
//!
//! The `.nornir/README-full.md` competitive table is generated from
//! `skade_katalog_bench::capabilities` (one source of truth, also emitted through
//! the nornir static-capabilities bench seam). This test fails if the committed
//! table has drifted from what the code renders — so the front-page ✓/✗/◐/NA
//! claims can never diverge from the matrix the code emits.
//!
//! Regenerate the table after editing the matrix:
//!
//! ```text
//! UPDATE_CAPABILITIES=1 cargo test -p skade-katalog-bench --test capabilities
//! ```

use std::path::PathBuf;

use skade_katalog_bench::capabilities;

const START_PREFIX: &str = "<!-- skade:gen:start:capabilities";
const END_MARKER: &str = "<!-- skade:gen:end:capabilities -->";

fn readme_full_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/bench ; the doc lives at <repo>/.nornir/…
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.nornir/README-full.md")
}

/// Return `(start_marker_line, generated_body, end_marker_line)` for the
/// capability region, or panic with a clear message if the markers are missing.
fn split_region(text: &str) -> (String, String, String) {
    let start_line = text
        .lines()
        .find(|l| l.trim_start().starts_with(START_PREFIX))
        .unwrap_or_else(|| panic!("`{START_PREFIX}` marker not found in README-full.md"))
        .to_string();
    let end_line = text
        .lines()
        .find(|l| l.trim() == END_MARKER)
        .unwrap_or_else(|| panic!("`{END_MARKER}` marker not found in README-full.md"))
        .to_string();

    let after_start = &text[text.find(&start_line).unwrap() + start_line.len()..];
    let body_end = after_start
        .find(&end_line)
        .expect("end marker after start marker");
    let body = after_start[..body_end].trim_matches('\n').to_string();
    (start_line, body, end_line)
}

#[test]
fn readme_capability_table_matches_the_matrix() {
    let path = readme_full_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let (start_line, body, end_line) = split_region(&text);
    let expected = capabilities::render_markdown();

    if std::env::var_os("UPDATE_CAPABILITIES").is_some() {
        // Rewrite the region between the markers with the freshly rendered table.
        let start_at = text.find(&start_line).unwrap() + start_line.len();
        let end_at = text[start_at..].find(&end_line).unwrap() + start_at;
        let mut updated = String::with_capacity(text.len() + expected.len());
        updated.push_str(&text[..start_at]);
        updated.push('\n');
        updated.push_str(&expected);
        updated.push('\n');
        updated.push_str(&text[end_at..]);
        std::fs::write(&path, updated).expect("rewrite README-full.md");
        eprintln!("updated capability table in {}", path.display());
        return;
    }

    assert_eq!(
        body, expected,
        "\n.nornir/README-full.md capability table has drifted from \
         bench/src/capabilities.rs.\nRegenerate with: \
         UPDATE_CAPABILITIES=1 cargo test -p skade-katalog-bench --test capabilities\n"
    );
}

#[test]
fn matrix_emits_through_the_static_capabilities_seam() {
    // The exact row the `SkadeCapabilities` bencher emits, built the same way.
    let row = nornir::bench::BenchResult::static_capabilities(
        capabilities::RESULT_NAME,
        capabilities::numeric_metrics(),
    );
    assert!(row.is_static(), "capability row must be tagged Static, not Measured");

    let json = serde_json::to_string(&row).expect("serialize static row");
    assert!(json.contains("\"source\":\"static\""), "missing Static tag: {json}");
    // No false ✓: Iceberg-Java is ✗ (code 0.0) on the pure-Rust/in-process row,
    // and skade is ✅ (code 1.0) — the numbers must match the glyphs shown.
    assert!(json.contains("\"cap.pure_rust_in_process.skade\":1.0"), "{json}");
    assert!(json.contains("\"cap.pure_rust_in_process.iceberg_java\":0.0"), "{json}");
}
