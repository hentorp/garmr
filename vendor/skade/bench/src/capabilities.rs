//! The skade **capability matrix** — the single source of truth for the
//! front-page competitive table in [`.nornir/README-full.md`].
//!
//! Historically this table was hand-authored markdown. Issue #13 landed the
//! nornir **static-capabilities bench seam** (`BenchResult::static_capabilities`,
//! `BenchSource::Static`): a way to emit "un-runnable rivals + ✓/✗ feature-matrix"
//! rows alongside the measured benchmarks, tagged so the warehouse keeps them and
//! the no-regression gate skips them (a feature-matrix cell is not a perf number).
//!
//! This module is that seam's skade consumer. The matrix is defined **once** here
//! and used two ways, so the two can never drift:
//!
//! 1. [`numeric_metrics`] projects every cell to a numeric coverage code and is
//!    emitted through the seam as the `skade.capabilities` static row (the
//!    `nornir-bench` example wraps it in `BenchResult::static_capabilities`). All
//!    facts are numeric (like nornir's own `machine_capabilities`) so they survive
//!    the warehouse's numeric ingest.
//! 2. [`render_markdown`] renders the exact ✓/✗/◐/NA markdown table. The
//!    `.nornir/README-full.md` capability region is generated from it (regenerate
//!    with `UPDATE_CAPABILITIES=1 cargo test -p skade-katalog-bench --test
//!    capabilities`), and the same test fails on any drift — so the front-page
//!    claims can never diverge from what the code emits.
//!
//! nornir ships the data seam but not (yet) a matrix *renderer*, so skade owns the
//! markdown rendering; the generated region uses a `skade:gen:*` marker that
//! `nornir docs render`/`check` ignore (they only parse `nornir:gen:*`).

use serde_json::{json, Map, Value};

/// One cell's capability level. `glyph` is what the README shows; `code` is the
/// numeric projection emitted through the (numeric-only) warehouse ingest so a
/// static row persists and the no-regression gate can skip it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cov {
    /// Full support (`✅`).
    Full,
    /// Partial / caveated support (`◐`).
    Partial,
    /// Not supported (`✗`).
    No,
    /// Not applicable — the rival has no concept for this (`NA`).
    Na,
    /// Unknown / not measured (`—`).
    Unknown,
}

impl Cov {
    /// The markdown glyph shown in the table.
    pub fn glyph(self) -> &'static str {
        match self {
            Cov::Full => "✅",
            Cov::Partial => "◐",
            Cov::No => "✗",
            Cov::Na => "NA",
            Cov::Unknown => "—",
        }
    }

    /// Numeric coverage code for the warehouse ingest (booleans-as-floats, same
    /// convention as nornir's `machine_capabilities`). Distinct per level so the
    /// glyph is recoverable from the persisted number.
    pub fn code(self) -> f64 {
        match self {
            Cov::Full => 1.0,
            Cov::Partial => 0.5,
            Cov::No => 0.0,
            Cov::Na => -1.0,
            Cov::Unknown => -2.0,
        }
    }
}

/// One `(coverage, note, bold)` cell. `note` is the parenthetical qualifier shown
/// after the glyph (e.g. `(JVM)`), empty when there is none; `bold` reproduces the
/// table's editorial emphasis (`**✅**`).
#[derive(Clone, Copy, Debug)]
pub struct Cell {
    pub cov: Cov,
    pub note: &'static str,
    pub bold: bool,
}

impl Cell {
    const fn new(cov: Cov, note: &'static str, bold: bool) -> Self {
        Self { cov, note, bold }
    }

    /// The rendered markdown for this cell (`**✅**`, `✗ (JVM)`, `NA`, `—`, …).
    pub fn markdown(self) -> String {
        let mut s = self.cov.glyph().to_string();
        if !self.note.is_empty() {
            s.push(' ');
            s.push_str(self.note);
        }
        if self.bold {
            format!("**{s}**")
        } else {
            s
        }
    }
}

/// One capability row: the left-column label plus the four rival cells.
#[derive(Clone, Copy, Debug)]
pub struct Row {
    /// A short stable slug used to key the numeric metrics (`cap.<slug>.<rival>`).
    pub slug: &'static str,
    /// The capability label (markdown allowed).
    pub capability: &'static str,
    pub skade: Cell,
    pub iceberg_java: Cell,
    pub pyiceberg: Cell,
    pub delta: Cell,
}

/// The four rival columns, in table order. `.0` = header label, `.1` = metric-key
/// suffix.
pub const RIVALS: [(&str, &str); 4] = [
    ("**skade**", "skade"),
    ("Iceberg (Java)", "iceberg_java"),
    ("PyIceberg", "pyiceberg"),
    ("Delta Lake", "delta"),
];

/// The markdown header + alignment separator (the first two lines of the table).
pub const HEADER: &str = "| capability | **skade** | Iceberg (Java) | PyIceberg | Delta Lake |\n|---|:--:|:--:|:--:|:--:|";

/// The capability matrix — the single source of truth. Preserves the prior
/// hand-authored claims exactly (glyphs, qualifiers, and emphasis).
pub const ROWS: &[Row] = &[
    Row {
        slug: "pure_rust_in_process",
        capability: "Pure-**Rust**, in-process — no JVM, no network catalog hop",
        skade: Cell::new(Cov::Full, "", true),
        iceberg_java: Cell::new(Cov::No, "(JVM)", false),
        pyiceberg: Cell::new(Cov::Partial, "(Python)", false),
        delta: Cell::new(Cov::Full, "", false),
    },
    Row {
        slug: "embedded_acid_catalog",
        capability: "Embedded **single-file ACID catalog** (redb) — no catalog service to run",
        skade: Cell::new(Cov::Full, "", true),
        iceberg_java: Cell::new(Cov::No, "(Nessie/Polaris/Hive/Glue)", false),
        pyiceberg: Cell::new(Cov::No, "(SQL/REST)", false),
        delta: Cell::new(Cov::Partial, "", false),
    },
    Row {
        slug: "fast_catalog_reads",
        capability: "Catalog reads **~492× Nessie · ~677× Polaris** (`table_exists`, 2.0M ops/s)",
        skade: Cell::new(Cov::Full, "", true),
        iceberg_java: Cell::new(Cov::Partial, "", false),
        pyiceberg: Cell::new(Cov::Partial, "", false),
        delta: Cell::new(Cov::Unknown, "", false),
    },
    Row {
        slug: "multi_table_atomic_commit",
        capability: "**Multi-table atomic commit** — flip N tables in one txn (`atomic_release`)",
        skade: Cell::new(Cov::Full, "", true),
        iceberg_java: Cell::new(Cov::No, "", false),
        pyiceberg: Cell::new(Cov::No, "", false),
        delta: Cell::new(Cov::Na, "", true),
    },
    Row {
        slug: "lockfree_time_travel_index",
        capability: "Lock-free static **time-travel index** (Ragnar `STree64`)",
        skade: Cell::new(Cov::Full, "", true),
        iceberg_java: Cell::new(Cov::Na, "", true),
        pyiceberg: Cell::new(Cov::Na, "", true),
        delta: Cell::new(Cov::Na, "", true),
    },
    Row {
        slug: "all_core_parallel_ingest",
        capability: "All-core **parallel ingest** that saturates the box (gatling no-barrier)",
        skade: Cell::new(Cov::Full, "", true),
        iceberg_java: Cell::new(Cov::Partial, "(Spark)", false),
        pyiceberg: Cell::new(Cov::No, "", false),
        delta: Cell::new(Cov::Partial, "", false),
    },
    Row {
        slug: "mature_engine_ecosystem",
        capability: "Mature engine ecosystem (Spark/Trino/Flink) + schema-evolution writes today",
        skade: Cell::new(Cov::Partial, "", false),
        iceberg_java: Cell::new(Cov::Full, "", true),
        pyiceberg: Cell::new(Cov::Partial, "", false),
        delta: Cell::new(Cov::Full, "", true),
    },
];

impl Row {
    /// The four cells in table (rival) order.
    fn cells(&self) -> [Cell; 4] {
        [self.skade, self.iceberg_java, self.pyiceberg, self.delta]
    }

    /// This row rendered as one markdown table line.
    fn markdown(&self) -> String {
        let cells = self.cells();
        format!(
            "| {} | {} | {} | {} | {} |",
            self.capability,
            cells[0].markdown(),
            cells[1].markdown(),
            cells[2].markdown(),
            cells[3].markdown(),
        )
    }
}

/// Render the full capability matrix as the markdown that lives between the
/// `skade:gen:*` markers in `.nornir/README-full.md` (header + separator + one
/// line per capability). No trailing newline.
pub fn render_markdown() -> String {
    let mut out = String::from(HEADER);
    for r in ROWS {
        out.push('\n');
        out.push_str(&r.markdown());
    }
    out
}

/// Project every cell to its numeric coverage code, keyed `cap.<slug>.<rival>`,
/// for emission as the `skade.capabilities` static row. Also records the row count
/// so a consumer can tell the matrix is fully present.
pub fn numeric_metrics() -> Map<String, Value> {
    let mut m = Map::new();
    for r in ROWS {
        let cells = r.cells();
        for (cell, (_, key)) in cells.iter().zip(RIVALS.iter()) {
            m.insert(format!("cap.{}.{}", r.slug, key), json!(cell.cov.code()));
        }
    }
    m.insert("capability_rows".into(), json!(ROWS.len() as f64));
    m
}

/// Canonical name for the static-capabilities row (the `<repo>.capabilities`
/// convention nornir's `machine_capabilities` uses).
pub const RESULT_NAME: &str = "skade.capabilities";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_cell_code_is_finite_and_matches_a_known_glyph() {
        for r in ROWS {
            for c in r.cells() {
                assert!(c.cov.code().is_finite());
                assert!(!c.cov.glyph().is_empty());
            }
        }
    }

    #[test]
    fn numeric_codes_round_trip_to_the_rendered_glyph() {
        // No false ✓: a cell's persisted code must map back to the glyph shown.
        let by_code = |code: f64| -> &'static str {
            for cov in [Cov::Full, Cov::Partial, Cov::No, Cov::Na, Cov::Unknown] {
                if (cov.code() - code).abs() < f64::EPSILON {
                    return cov.glyph();
                }
            }
            panic!("code {code} maps to no coverage level")
        };
        let m = numeric_metrics();
        for r in ROWS {
            let cells = r.cells();
            for (cell, (_, key)) in cells.iter().zip(RIVALS.iter()) {
                let code = m[&format!("cap.{}.{}", r.slug, key)].as_f64().unwrap();
                assert_eq!(by_code(code), cell.cov.glyph(), "row {}", r.slug);
            }
        }
    }

    #[test]
    fn markdown_has_a_header_and_one_line_per_capability() {
        let md = render_markdown();
        let lines: Vec<&str> = md.lines().collect();
        assert_eq!(lines.len(), 2 + ROWS.len(), "header + separator + rows");
        assert!(lines[0].starts_with("| capability |"));
        assert!(lines[1].contains(":--:"));
        // Ours (skade) column is emphasised on every genuine claim row.
        assert!(md.contains("**✅**"));
    }
}
