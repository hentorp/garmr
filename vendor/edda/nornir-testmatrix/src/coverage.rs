//! # autonom coverage gate — the PURE verdict model (AUT2 / n-005)
//!
//! [`discover`](crate::discover) builds the testable [`Surface`] and
//! [`compute_gap`] differences it against the covered + allowlisted sets. This
//! module adds the **persistence + gate-verdict** shapes that nornir's iceberg
//! sink and the `nornir test coverage` CLI / `test_coverage` MCP tool / viz Test
//! pane all share — kept here, PURE (std + serde), so the whole gate is unit
//! testable by feeding sample rows and asserting the verdict.
//!
//! ```text
//! Surface  = discover::* enumerators                         (the testable surface)
//! Covered  = a surface node reached by an inject-assert test (call_edges / tools/list / registry)
//! Allowed  = a checked-in autonom-allow.toml entry           (excused, with a reason)
//! Gap      = Surface − Covered − Allowed
//! GATE: Gap == ∅  AND  no STALE allowlist entry              (HARD zero, not a ratchet)
//! ```
//!
//! The [`CoverageRow`] is the warehouse row (one per `surface × mode × workspace
//! × verdict`) — the same shape as `tests/mcp_tool_coverage.json` generalized to
//! the whole surface. nornir's `surface_coverage` iceberg table writes/reads it.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::discover::{Gap, Surface, SurfaceNode};
use crate::utfallsrum::UtfallsrumSummary;

/// Default minimum outcome classes a surface's functions must sweep before it
/// counts as covered (the gate's "≥K classes swept" rule). `2` means a surface
/// must exercise at least two equivalence partitions / boundaries of its outcome
/// space — a single-value smoke test (`1`) does NOT flip a surface to covered.
pub const DEFAULT_UTFALLSRUM_THRESHOLD: usize = 2;

/// A surface's measured outcome-space coverage this run: the rolled-up
/// utfallsrum score for the function(s) on its call chain. The gate joins this on
/// the surface key, so a surface is **covered** only when it BOTH ran end-to-end
/// (it's in the `ran` set) AND meets the [`UtfallsrumSummary::meets_threshold`]
/// bar. Persisted on [`CoverageRow::utfallsrum_covered`] so the warehouse carries
/// outcome-space coverage per surface, not just pass/fail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurfaceUtfallsrum {
    /// The surface key (`"kind:id@mode"`) this score belongs to.
    pub surface_key: String,
    /// The rolled-up outcome-space summary for the surface's function(s).
    pub summary: UtfallsrumSummary,
}

/// Compute the **covered** set under the utfallsrum rule: a surface key is
/// covered iff it is in `ran` (the surface ran end-to-end — reached by a test)
/// AND its outcome-space score meets `min_classes` (≥K classes swept). A surface
/// that ran but only swept one value is NOT covered — it falls to the gap /
/// allowlist, exactly the one-value-smoke loophole the gate is meant to close.
///
/// `ran` is the set of surface keys an inject-assert test reached (the existing
/// reachability-derived covered set). `utfallsrum` maps a surface key to its
/// measured outcome-space coverage. A surface in `ran` with NO utfallsrum entry
/// is treated as below threshold (it ran but declared no outcome space) unless
/// `min_classes == 0` (threshold off → ran-set is the covered set, the legacy
/// behaviour).
pub fn covered_with_utfallsrum(
    ran: &BTreeSet<String>,
    utfallsrum: &BTreeMap<String, UtfallsrumSummary>,
    min_classes: usize,
) -> BTreeSet<String> {
    if min_classes == 0 {
        // Threshold off: legacy behaviour — ran ⟺ covered.
        return ran.clone();
    }
    ran.iter()
        .filter(|key| {
            utfallsrum
                .get(*key)
                .map(|s| s.meets_threshold(min_classes))
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// The verdict a single surface node earned this gate run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Reached by an inject-assert test — the gate is happy.
    Covered,
    /// Not covered, but excused by a checked-in `autonom-allow.toml` entry.
    Allowlisted,
    /// Not covered and not excused — this is what makes the gate RED.
    Missing,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Covered => "covered",
            Verdict::Allowlisted => "allowlisted",
            Verdict::Missing => "missing",
        }
    }

    pub fn parse(s: &str) -> Option<Verdict> {
        match s {
            "covered" => Some(Verdict::Covered),
            "allowlisted" => Some(Verdict::Allowlisted),
            "missing" => Some(Verdict::Missing),
            _ => None,
        }
    }
}

/// One persisted coverage row — the `surface_coverage` warehouse fact, mirroring
/// `tests/mcp_tool_coverage.json` but for the WHOLE discovered surface. One row
/// per `(surface_key, mode, workspace)` with its [`Verdict`].
///
/// `surface_key` is [`SurfaceNode::key_str`] (`"kind:id@mode"`) — the stable join
/// key the gate matched coverage on. `kind`/`id`/`mode` are split out as columns
/// so the warehouse / viz can filter without re-parsing the key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageRow {
    /// The run that produced this row (groups one gate run's rows).
    pub run_id: String,
    /// The workspace this surface belongs to (so a multi-workspace warehouse
    /// keeps each workspace's surface distinct).
    pub workspace: String,
    /// `SurfaceNode::key_str()` — `"kind:id@mode"`. The stable identity.
    pub surface_key: String,
    /// The enumerator kind tag (`facett_component` / `viz_tab` / `cli_command` /
    /// `mcp_tool` / `function`).
    pub kind: String,
    /// The surface id within its kind (component / tab / cmd / tool / fn path).
    pub id: String,
    /// The thin/fat mode (`fat` / `thin` / `na`).
    pub mode: String,
    /// `covered` / `allowlisted` / `missing`.
    pub verdict: String,
    /// The allowlist reason (only set when `verdict == allowlisted`).
    #[serde(default)]
    pub reason: String,
    /// Row timestamp (micros). Shared across one run's rows.
    #[serde(default)]
    pub ts_micros: i64,
    /// The measured **outcome-space coverage** for this surface's function(s) —
    /// `utfallsrum_covered ∈ [0,1]` = exercised-classes / declared-classes. `0.0`
    /// when no outcome space was declared/measured for the surface (a surface that
    /// ran but swept a single value scores low here even if its verdict is
    /// `covered` under a threshold-off gate). This is the column that lets the
    /// warehouse carry outcome-space coverage per surface, not just pass/fail.
    #[serde(default)]
    pub utfallsrum_covered: f64,
}

impl CoverageRow {
    /// Build a row from a node + verdict (the writer's per-node mapping).
    pub fn from_node(
        run_id: &str,
        workspace: &str,
        node: &SurfaceNode,
        verdict: Verdict,
        reason: &str,
        ts_micros: i64,
    ) -> Self {
        CoverageRow {
            run_id: run_id.to_string(),
            workspace: workspace.to_string(),
            surface_key: node.key_str(),
            kind: node.kind.label().to_string(),
            id: node.id.clone(),
            mode: node.mode.label().to_string(),
            verdict: verdict.label().to_string(),
            reason: reason.to_string(),
            ts_micros,
            utfallsrum_covered: 0.0,
        }
    }

    /// Set the measured outcome-space coverage (`[0,1]`) for this row (builder).
    pub fn with_utfallsrum(mut self, score: f64) -> Self {
        self.utfallsrum_covered = score;
        self
    }

    /// The parsed verdict (defaults to [`Verdict::Missing`] for an unknown tag —
    /// fail-safe: an unrecognized verdict counts against the gate, never for it).
    pub fn verdict(&self) -> Verdict {
        Verdict::parse(&self.verdict).unwrap_or(Verdict::Missing)
    }
}

/// One allowlist entry from the checked-in `autonom-allow.toml`. An entry
/// **excuses** a surface node from the gate — but it must carry a `reason`
/// (often a `TODO`/issue ref) so the excuse is visible and burns down by
/// deletion, never silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowEntry {
    /// `SurfaceNode::key_str()` — `"kind:id@mode"`. The node this excuses.
    pub key: String,
    /// Why it's excused (a TODO / issue link). REQUIRED — a blank reason is a
    /// stale-ish smell the seeder fills with a placeholder.
    #[serde(default)]
    pub reason: String,
}

/// The parsed `autonom-allow.toml` — a flat list of [`AllowEntry`]. Serializes
/// to/from `[[allow]]` tables (the caller does the toml (de)serialize; this
/// stays serde-pure).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowlist {
    #[serde(default, rename = "allow")]
    pub entries: Vec<AllowEntry>,
}

impl Allowlist {
    pub fn new() -> Self {
        Self::default()
    }

    /// The set of excused keys — what [`compute_gap`](crate::discover::compute_gap)
    /// consumes as its `allowlist` argument.
    pub fn key_set(&self) -> BTreeSet<String> {
        self.entries.iter().map(|e| e.key.clone()).collect()
    }

    /// Map key → reason for annotating allowlisted rows.
    pub fn reasons(&self) -> BTreeMap<String, String> {
        self.entries
            .iter()
            .map(|e| (e.key.clone(), e.reason.clone()))
            .collect()
    }
}

/// SEED an allowlist with EVERY currently-uncovered surface node (`--seed-allowlist`).
///
/// Every node **not** in `covered` gets an entry with a TODO reason, so the gate
/// goes GREEN *now* and the allowlist burns down by deleting entries as tests are
/// wired. Already-covered nodes are NOT seeded (they don't need an excuse).
/// Existing entries' reasons are preserved (re-seeding doesn't clobber a hand
/// reason); new uncovered nodes are appended. Sorted by key for a stable file.
pub fn seed_allowlist(
    surface: &Surface,
    covered: &BTreeSet<String>,
    existing: &Allowlist,
) -> Allowlist {
    let prior: BTreeMap<String, String> = existing.reasons();
    let mut entries: Vec<AllowEntry> = Vec::new();
    for node in &surface.nodes {
        let key = node.key_str();
        if covered.contains(&key) {
            continue; // covered → no excuse needed
        }
        let reason = prior
            .get(&key)
            .filter(|r| !r.is_empty())
            .cloned()
            .unwrap_or_else(|| format!("TODO(autonom): wire an inject-assert test for {key}"));
        entries.push(AllowEntry { key, reason });
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    Allowlist { entries }
}

/// STALE allowlist entries: keys on the allowlist that are **no longer needed** —
/// either the node is now covered, or the node no longer exists in the surface.
/// A stale entry FAILS the gate (the allowlist must burn down, not rot): an
/// excuse outliving its surface is exactly the drift autonom kills.
///
/// Returns the offending [`AllowEntry`]s sorted by key.
pub fn stale_allowlist_entries(
    surface: &Surface,
    covered: &BTreeSet<String>,
    allowlist: &Allowlist,
) -> Vec<AllowEntry> {
    let surface_keys: BTreeSet<String> = surface.nodes.iter().map(|n| n.key_str()).collect();
    let mut stale: Vec<AllowEntry> = allowlist
        .entries
        .iter()
        .filter(|e| covered.contains(&e.key) || !surface_keys.contains(&e.key))
        .cloned()
        .collect();
    stale.sort_by(|a, b| a.key.cmp(&b.key));
    stale
}

/// The full gate verdict for one run — the thing the CLI prints, the viz Test
/// pane shows, and the release gate fails on. Combines the [`Gap`] (missing /
/// allowlisted / covered counts) with the STALE-allowlist check.
///
/// `is_green()` is the HARD-zero verdict: **no missing surface AND no stale
/// allowlist entry**.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    pub run_id: String,
    pub workspace: String,
    /// The differenced gap (missing + allowlisted + covered/total counts).
    pub gap: Gap,
    /// Allowlist entries that are no longer needed (covered or surface-gone).
    pub stale: Vec<AllowEntry>,
}

impl GateReport {
    /// Build the report by differencing the surface against covered + allowlist,
    /// then checking for stale allowlist entries.
    pub fn compute(
        run_id: &str,
        workspace: &str,
        surface: &Surface,
        covered: &BTreeSet<String>,
        allowlist: &Allowlist,
    ) -> GateReport {
        let gap = crate::discover::compute_gap(surface, covered, &allowlist.key_set());
        let stale = stale_allowlist_entries(surface, covered, allowlist);
        GateReport {
            run_id: run_id.to_string(),
            workspace: workspace.to_string(),
            gap,
            stale,
        }
    }

    /// GREEN ⟺ no missing surface AND no stale allowlist entry. The HARD-zero
    /// gate: `Gap == ∅` and the allowlist is fully justified.
    pub fn is_green(&self) -> bool {
        self.gap.is_clean() && self.stale.is_empty()
    }

    /// One-line human summary for the CLI.
    pub fn summary(&self) -> String {
        format!(
            "{} · {} stale allowlist entr{} — {}",
            self.gap.summary(),
            self.stale.len(),
            if self.stale.len() == 1 { "y" } else { "ies" },
            if self.is_green() { "GREEN" } else { "RED" },
        )
    }

    /// The persisted rows for this report (covered are NOT in the gap, so they're
    /// reconstructed from `surface − missing − allowlisted` by the writer; here we
    /// emit the missing + allowlisted rows which carry the actionable verdicts).
    /// The caller passes the full surface + the covered set to also emit covered
    /// rows; see [`rows_for`].
    pub fn actionable_rows(&self, ts_micros: i64) -> Vec<CoverageRow> {
        let reasons: BTreeMap<String, String> = BTreeMap::new(); // gap has no reasons
        let mut rows = Vec::new();
        for node in &self.gap.missing {
            rows.push(CoverageRow::from_node(
                &self.run_id,
                &self.workspace,
                node,
                Verdict::Missing,
                "",
                ts_micros,
            ));
        }
        for node in &self.gap.allowlisted {
            let reason = reasons.get(&node.key_str()).cloned().unwrap_or_default();
            rows.push(CoverageRow::from_node(
                &self.run_id,
                &self.workspace,
                node,
                Verdict::Allowlisted,
                &reason,
                ts_micros,
            ));
        }
        rows
    }
}

/// Build the FULL per-node coverage rows (covered + allowlisted + missing) for
/// persistence — one row per surface node. This is the writer's source: a row
/// for every discovered surface node, tagged with its verdict (and an allowlist
/// reason where applicable). The gate joins these back on `surface_key`.
pub fn rows_for(
    run_id: &str,
    workspace: &str,
    surface: &Surface,
    covered: &BTreeSet<String>,
    allowlist: &Allowlist,
    ts_micros: i64,
) -> Vec<CoverageRow> {
    rows_for_with_utfallsrum(
        run_id,
        workspace,
        surface,
        covered,
        allowlist,
        &BTreeMap::new(),
        ts_micros,
    )
}

/// Like [`rows_for`] but stamps each row's [`CoverageRow::utfallsrum_covered`]
/// from `utfallsrum` (surface key → its outcome-space summary), so the persisted
/// rows carry per-surface outcome-space coverage alongside the verdict. A surface
/// with no entry keeps `0.0`. The verdict is still the caller's `covered` set —
/// pass `covered_with_utfallsrum(...)` there so the verdict already reflects the
/// threshold, and the score column shows HOW WELL each covered surface swept.
pub fn rows_for_with_utfallsrum(
    run_id: &str,
    workspace: &str,
    surface: &Surface,
    covered: &BTreeSet<String>,
    allowlist: &Allowlist,
    utfallsrum: &BTreeMap<String, UtfallsrumSummary>,
    ts_micros: i64,
) -> Vec<CoverageRow> {
    let allow_keys = allowlist.key_set();
    let reasons = allowlist.reasons();
    let mut rows: Vec<CoverageRow> = surface
        .nodes
        .iter()
        .map(|node| {
            let key = node.key_str();
            let (verdict, reason) = if covered.contains(&key) {
                (Verdict::Covered, String::new())
            } else if allow_keys.contains(&key) {
                (
                    Verdict::Allowlisted,
                    reasons.get(&key).cloned().unwrap_or_default(),
                )
            } else {
                (Verdict::Missing, String::new())
            };
            let score = utfallsrum.get(&key).map(|s| s.covered).unwrap_or(0.0);
            CoverageRow::from_node(run_id, workspace, node, verdict, &reason, ts_micros)
                .with_utfallsrum(score)
        })
        .collect();
    rows.sort_by(|a, b| a.surface_key.cmp(&b.surface_key));
    rows
}

/// Summarize persisted [`CoverageRow`]s back into a compact verdict for the viz
/// Test pane (`state_json["test"]["coverage"]`) and the `test_coverage` tool.
/// Counts by verdict + lists the missing keys (the actionable gap).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub run_id: String,
    pub workspace: String,
    pub total: usize,
    pub covered: usize,
    pub allowlisted: usize,
    pub gap: usize,
    /// The missing surface keys (`"kind:id@mode"`), sorted — the burn-down list.
    pub missing: Vec<String>,
    /// GREEN ⟺ gap == 0.
    pub green: bool,
}

impl CoverageSummary {
    /// Roll persisted rows (one run) into the viz/CLI summary.
    pub fn from_rows(rows: &[CoverageRow]) -> CoverageSummary {
        let run_id = rows.first().map(|r| r.run_id.clone()).unwrap_or_default();
        let workspace = rows
            .first()
            .map(|r| r.workspace.clone())
            .unwrap_or_default();
        let mut covered = 0;
        let mut allowlisted = 0;
        let mut missing: Vec<String> = Vec::new();
        for r in rows {
            match r.verdict() {
                Verdict::Covered => covered += 1,
                Verdict::Allowlisted => allowlisted += 1,
                Verdict::Missing => missing.push(r.surface_key.clone()),
            }
        }
        missing.sort();
        let gap = missing.len();
        CoverageSummary {
            run_id,
            workspace,
            total: rows.len(),
            covered,
            allowlisted,
            gap,
            green: gap == 0,
            missing,
        }
    }

    /// The JSON the viz Test pane nests under `state_json["test"]["coverage"]`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "run_id": self.run_id,
            "workspace": self.workspace,
            "total": self.total,
            "covered": self.covered,
            "allowlisted": self.allowlisted,
            "gap": self.gap,
            "green": self.green,
            "missing": self.missing,
        })
    }
}

/// XML-escape a label for safe inclusion in SVG text (local copy so this module
/// stays PURE std — no dependency on the `introspect` SVG helpers).
fn svg_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render the persisted [`CoverageRow`]s as a **self-contained, static SVG** — the
/// autonom completeness gate's *visual twin* (MEGA-PLAN S6: "the metrics SVG —
/// surface × {ran, utfallsrum, reachable} per workspace"). No JavaScript, no
/// diagram engine: the markup is emitted directly so it renders verbatim in any
/// markdown/web viewer and is available in every feature set (NUKE-MERMAID house
/// style, matching `introspect::Graph::to_svg`).
///
/// The matrix has one section per workspace and one row per surface, scored on
/// three axes read straight from the rows:
/// - **ran** — the surface was reached end-to-end by an inject-assert test ⟺
///   `verdict == Covered` (a filled ● vs a hollow ○).
/// - **utfallsrum** — the outcome-space score `utfallsrum_covered ∈ [0,1]`,
///   rendered as a graded bar (a surface that ran but swept a single value reads
///   low here even when its verdict is `covered`).
/// - **reachable** — the surface is on the accounted UI-plane rather than a hard
///   gap ⟺ `verdict != Missing` (`Covered` or `Allowlisted`). This is the honest
///   proxy for LAW-9 UI-plane reachability available from the persisted gate rows;
///   a `Missing` surface is an un-reached gap.
///
/// Deterministic: workspaces and surfaces are sorted, so the same rows always
/// yield byte-identical SVG (safe to commit / snapshot-test).
pub fn coverage_svg(rows: &[CoverageRow]) -> String {
    // ── group rows by workspace, surfaces sorted within each ──────────────────
    let mut by_ws: BTreeMap<&str, Vec<&CoverageRow>> = BTreeMap::new();
    for r in rows {
        by_ws.entry(r.workspace.as_str()).or_default().push(r);
    }
    for v in by_ws.values_mut() {
        v.sort_by(|a, b| a.surface_key.cmp(&b.surface_key));
    }

    if by_ws.is_empty() {
        return String::from(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"260\" height=\"40\">\
             <text x=\"8\" y=\"24\" font-family=\"sans-serif\" font-size=\"12\">\
             (no surface_coverage rows)</text></svg>\n",
        );
    }

    // ── geometry ──────────────────────────────────────────────────────────────
    let label_w = 320.0f64; // surface-key column
    let cell_w = 90.0f64; // each of the 3 metric columns
    let row_h = 18.0f64;
    let head_h = 26.0f64; // per-workspace header band
    let section_gap = 10.0f64;
    let margin = 12.0f64;
    let top = 30.0f64; // column-title band
    let n_cols = 3usize;
    let width = margin * 2.0 + label_w + cell_w * n_cols as f64;

    // running height
    let mut height = top;
    for v in by_ws.values() {
        height += head_h + v.len() as f64 * row_h + section_gap;
    }
    height += margin;

    // colours (house palette)
    const GREEN: &str = "#1a7f37";
    const RED: &str = "#cf222e";
    const GREY: &str = "#8c959f";
    const INK: &str = "#1f2328";
    const FG: &str = "sans-serif";

    let col_x = |c: usize| margin + label_w + cell_w * c as f64 + cell_w / 2.0;

    let mut s = String::new();
    s.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width:.0}\" height=\"{height:.0}\" \
         font-family=\"{FG}\">\n"
    ));
    s.push_str("<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n");

    // column titles
    let titles = ["ran", "utfallsrum", "reachable"];
    for (c, t) in titles.iter().enumerate() {
        s.push_str(&format!(
            "<text x=\"{x:.0}\" y=\"18\" font-size=\"11\" font-weight=\"bold\" \
             text-anchor=\"middle\" fill=\"{INK}\">{t}</text>\n",
            x = col_x(c),
        ));
    }
    s.push_str(&format!(
        "<text x=\"{x:.0}\" y=\"18\" font-size=\"11\" font-weight=\"bold\" fill=\"{INK}\">surface</text>\n",
        x = margin,
    ));

    let mut y = top;
    for (ws, surfaces) in &by_ws {
        let summary = {
            let owned: Vec<CoverageRow> = surfaces.iter().map(|r| (*r).clone()).collect();
            CoverageSummary::from_rows(&owned)
        };
        let badge = if summary.green { GREEN } else { RED };
        let verdict = if summary.green { "GREEN" } else { "RED" };
        // workspace header band
        s.push_str(&format!(
            "<rect x=\"{x:.0}\" y=\"{y:.0}\" width=\"{w:.0}\" height=\"{h:.0}\" \
             fill=\"#f6f8fa\" stroke=\"{badge}\" stroke-width=\"1.5\"/>\n",
            x = margin,
            w = label_w + cell_w * n_cols as f64,
            h = head_h,
        ));
        s.push_str(&format!(
            "<text x=\"{x:.0}\" y=\"{ty:.0}\" font-size=\"12\" font-weight=\"bold\" fill=\"{INK}\">\
             {ws} — <tspan fill=\"{badge}\">{verdict}</tspan> \
             <tspan fill=\"{GREY}\">({cov}/{tot} covered, {gap} gap)</tspan></text>\n",
            x = margin + 6.0,
            ty = y + head_h - 8.0,
            ws = svg_escape(ws),
            cov = summary.covered,
            tot = summary.total,
            gap = summary.gap,
        ));
        y += head_h;

        for r in surfaces {
            let verd = r.verdict();
            let ran = verd == Verdict::Covered;
            let reachable = verd != Verdict::Missing;
            let cy = y + row_h / 2.0;

            // surface key label
            s.push_str(&format!(
                "<text x=\"{x:.0}\" y=\"{ty:.0}\" font-size=\"10\" fill=\"{INK}\">{lab}</text>\n",
                x = margin,
                ty = cy + 3.5,
                lab = svg_escape(&r.surface_key),
            ));

            // ran: filled ● green / hollow ○ grey
            let (ran_fill, ran_stroke) = if ran { (GREEN, GREEN) } else { ("none", GREY) };
            s.push_str(&format!(
                "<circle cx=\"{cx:.0}\" cy=\"{cy:.1}\" r=\"5\" fill=\"{ran_fill}\" \
                 stroke=\"{ran_stroke}\" stroke-width=\"1.5\"/>\n",
                cx = col_x(0),
            ));

            // utfallsrum: graded bar [0,1]
            let frac = r.utfallsrum_covered.clamp(0.0, 1.0);
            let bar_w = cell_w - 28.0;
            let bx = col_x(1) - bar_w / 2.0;
            let by = cy - 5.0;
            let fill = if frac >= 0.999 {
                GREEN
            } else if frac > 0.0 {
                "#bf8700"
            } else {
                GREY
            };
            s.push_str(&format!(
                "<rect x=\"{bx:.0}\" y=\"{by:.0}\" width=\"{bw:.0}\" height=\"10\" rx=\"2\" \
                 fill=\"#eaeef2\" stroke=\"{GREY}\" stroke-width=\"0.5\"/>\n",
                bw = bar_w,
            ));
            if frac > 0.0 {
                s.push_str(&format!(
                    "<rect x=\"{bx:.0}\" y=\"{by:.0}\" width=\"{fw:.1}\" height=\"10\" rx=\"2\" fill=\"{fill}\"/>\n",
                    fw = bar_w * frac,
                ));
            }
            s.push_str(&format!(
                "<text x=\"{tx:.0}\" y=\"{ty:.1}\" font-size=\"8\" fill=\"{INK}\">{pct:.0}%</text>\n",
                tx = bx + bar_w + 3.0,
                ty = cy + 3.0,
                pct = frac * 100.0,
            ));

            // reachable: ✓ green / ✗ red
            let (mark, color) = if reachable {
                ("✓", GREEN)
            } else {
                ("✗", RED)
            };
            s.push_str(&format!(
                "<text x=\"{cx:.0}\" y=\"{ty:.1}\" font-size=\"12\" font-weight=\"bold\" \
                 text-anchor=\"middle\" fill=\"{color}\">{mark}</text>\n",
                cx = col_x(2),
                ty = cy + 4.0,
            ));

            y += row_h;
        }
        y += section_gap;
    }

    s.push_str("</svg>\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::{cli_commands, mcp_tools, viz_tabs};
    use crate::utfallsrum::Outcome;

    fn util_summary(function: &str, classes: &[&str], hit: &[&str]) -> UtfallsrumSummary {
        let mut o = Outcome::for_fn(function);
        for c in classes {
            o = o.class(*c, format!("contract for {c}"));
        }
        for h in hit {
            o.hit(h, format!("{h}-evidence"));
        }
        o.summary()
    }

    /// The flagship gate rule: a surface that RAN end-to-end but only swept ONE
    /// outcome class is NOT covered under a ≥2 threshold — the one-value-smoke
    /// loophole is closed. A surface that swept ≥2 classes IS covered.
    #[test]
    fn covered_requires_both_ran_and_utfallsrum_threshold() {
        let ran: BTreeSet<String> = [
            "viz_tab:Bench@fat",
            "viz_tab:Test@fat",
            "mcp_tool:search@na",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let mut util = BTreeMap::new();
        // Bench swept 3 of 3 classes → well over threshold.
        util.insert(
            "viz_tab:Bench@fat".to_string(),
            util_summary(
                "bench_history",
                &["empty", "one", "many"],
                &["empty", "one", "many"],
            ),
        );
        // Test swept only 1 of 3 → a single-value smoke, BELOW threshold 2.
        util.insert(
            "viz_tab:Test@fat".to_string(),
            util_summary("test_history", &["empty", "one", "many"], &["one"]),
        );
        // search has NO utfallsrum entry → ran but declared no outcome space.

        let covered = covered_with_utfallsrum(&ran, &util, 2);
        assert!(
            covered.contains("viz_tab:Bench@fat"),
            "3 classes swept → covered"
        );
        assert!(
            !covered.contains("viz_tab:Test@fat"),
            "1 class swept (a smoke) → NOT covered even though it ran + was green",
        );
        assert!(
            !covered.contains("mcp_tool:search@na"),
            "ran but no declared outcome space → below threshold → not covered",
        );

        // Threshold OFF (0) → legacy behaviour: ran ⟺ covered.
        let legacy = covered_with_utfallsrum(&ran, &util, 0);
        assert_eq!(legacy, ran, "threshold 0 restores the ran-set as covered");
    }

    /// The persisted rows carry the per-surface outcome-space score.
    #[test]
    fn rows_carry_utfallsrum_score_per_surface() {
        let mut surface = Surface::new();
        surface.extend(viz_tabs(["Bench"])); // Bench@fat, Bench@thin

        let mut util = BTreeMap::new();
        util.insert(
            "viz_tab:Bench@fat".to_string(),
            util_summary(
                "bench_history",
                &["empty", "one", "many"],
                &["empty", "one"],
            ),
        );
        let covered: BTreeSet<String> = ["viz_tab:Bench@fat".to_string()].into_iter().collect();

        let rows =
            rows_for_with_utfallsrum("r", "ws", &surface, &covered, &Allowlist::new(), &util, 1);
        let fat = rows
            .iter()
            .find(|r| r.surface_key == "viz_tab:Bench@fat")
            .unwrap();
        assert!(
            (fat.utfallsrum_covered - 2.0 / 3.0).abs() < 1e-9,
            "2/3 swept score persisted"
        );
        assert_eq!(fat.verdict(), Verdict::Covered);
        let thin = rows
            .iter()
            .find(|r| r.surface_key == "viz_tab:Bench@thin")
            .unwrap();
        assert_eq!(
            thin.utfallsrum_covered, 0.0,
            "no outcome space measured → 0.0"
        );
        assert_eq!(thin.verdict(), Verdict::Missing);

        // The score survives serde (the warehouse row).
        let json = serde_json::to_string(&rows).unwrap();
        let back: Vec<CoverageRow> = serde_json::from_str(&json).unwrap();
        let fat_back = back
            .iter()
            .find(|r| r.surface_key == "viz_tab:Bench@fat")
            .unwrap();
        assert!((fat_back.utfallsrum_covered - 2.0 / 3.0).abs() < 1e-9);
    }

    /// The workspace dimension: the same tab in two workspaces is two surfaces.
    #[test]
    fn workspace_dimension_distinguishes_same_tab_across_workspaces() {
        use crate::discover::{SERVED_WORKSPACES, workspace_keys, workspace_surface_key};
        let mut surface = Surface::new();
        surface.extend(viz_tabs(["Bench"]));
        let node = surface
            .nodes
            .iter()
            .find(|n| n.mode == crate::discover::Mode::Fat)
            .unwrap();
        assert_eq!(
            workspace_surface_key("knut", node),
            "knut/viz_tab:Bench@fat"
        );
        assert_eq!(
            workspace_surface_key("nornir", node),
            "nornir/viz_tab:Bench@fat"
        );

        let knut = workspace_keys("knut", &surface);
        let nornir = workspace_keys("nornir", &surface);
        assert!(
            knut.is_disjoint(&nornir),
            "each workspace's surface keys are distinct"
        );
        assert!(SERVED_WORKSPACES.contains(&"knut") && SERVED_WORKSPACES.contains(&"nornir"));
        assert_eq!(
            SERVED_WORKSPACES.len(),
            8,
            "eight served workspaces in the dimension"
        );
    }

    fn sample_surface() -> Surface {
        let mut s = Surface::new();
        s.extend(viz_tabs(["Test"])) // viz_tab:Test@fat, viz_tab:Test@thin
            .extend(mcp_tools(["search"])) // mcp_tool:search@na
            .extend(cli_commands(["doctor"])); // cli_command:doctor@na
        s
    }

    #[test]
    fn seed_excuses_only_uncovered_with_reasons() {
        let surface = sample_surface(); // 4 nodes
        // Only Test@fat is covered.
        let covered: BTreeSet<String> = ["viz_tab:Test@fat".to_string()].into_iter().collect();
        let seeded = seed_allowlist(&surface, &covered, &Allowlist::new());
        // 3 uncovered nodes seeded; the covered one is NOT.
        assert_eq!(seeded.entries.len(), 3);
        assert!(
            seeded
                .entries
                .iter()
                .all(|e| e.reason.contains("TODO(autonom)"))
        );
        assert!(!seeded.entries.iter().any(|e| e.key == "viz_tab:Test@fat"));
        assert!(seeded.entries.iter().any(|e| e.key == "viz_tab:Test@thin"));

        // With the seeded allowlist, the gate is GREEN now (everything excused).
        let report = GateReport::compute("r1", "ws", &surface, &covered, &seeded);
        assert!(
            report.is_green(),
            "seeded allowlist makes the gate green now"
        );
        assert_eq!(report.gap.covered, 1);
        assert_eq!(report.gap.allowlisted.len(), 3);
        assert_eq!(report.gap.missing.len(), 0);
    }

    #[test]
    fn reseed_preserves_existing_reasons() {
        let surface = sample_surface();
        let covered = BTreeSet::new();
        let existing = Allowlist {
            entries: vec![AllowEntry {
                key: "viz_tab:Test@thin".into(),
                reason: "hand-written reason #42".into(),
            }],
        };
        let seeded = seed_allowlist(&surface, &covered, &existing);
        let thin = seeded
            .entries
            .iter()
            .find(|e| e.key == "viz_tab:Test@thin")
            .unwrap();
        assert_eq!(
            thin.reason, "hand-written reason #42",
            "existing reason preserved"
        );
        // New nodes still get the TODO placeholder.
        let other = seeded
            .entries
            .iter()
            .find(|e| e.key == "mcp_tool:search@na")
            .unwrap();
        assert!(other.reason.contains("TODO(autonom)"));
    }

    #[test]
    fn unreached_makes_gap_reachable_does_not_allowlisted_excused() {
        let surface = sample_surface();
        // Cover everything EXCEPT Test@thin; allowlist Test@thin.
        let covered: BTreeSet<String> = [
            "viz_tab:Test@fat",
            "mcp_tool:search@na",
            "cli_command:doctor@na",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let allowlist = Allowlist {
            entries: vec![AllowEntry {
                key: "viz_tab:Test@thin".into(),
                reason: "RPC wiring tracked in n-006".into(),
            }],
        };
        let report = GateReport::compute("r1", "ws", &surface, &covered, &allowlist);
        // Reachable (covered) → NOT in gap. Allowlisted → excused, not missing.
        assert!(report.is_green(), "all covered or excused → green");
        assert_eq!(report.gap.covered, 3);
        assert_eq!(report.gap.allowlisted.len(), 1);
        assert!(report.stale.is_empty());

        // Now REMOVE the cover for the cli command and DON'T allowlist it → RED.
        let covered2: BTreeSet<String> = ["viz_tab:Test@fat", "mcp_tool:search@na"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let report2 = GateReport::compute("r1", "ws", &surface, &covered2, &allowlist);
        assert!(
            !report2.is_green(),
            "an uncovered, un-allowlisted node makes it RED"
        );
        assert_eq!(report2.gap.missing.len(), 1);
        assert_eq!(report2.gap.missing[0].key_str(), "cli_command:doctor@na");
    }

    #[test]
    fn stale_allowlist_entry_fails_the_gate() {
        let surface = sample_surface();
        // Everything covered.
        let covered: BTreeSet<String> = surface.nodes.iter().map(|n| n.key_str()).collect();
        // But the allowlist still excuses a now-COVERED node (stale) AND a
        // node that no longer exists in the surface (also stale).
        let allowlist = Allowlist {
            entries: vec![
                AllowEntry {
                    key: "viz_tab:Test@thin".into(),
                    reason: "old".into(),
                },
                AllowEntry {
                    key: "viz_tab:Ghost@fat".into(),
                    reason: "deleted tab".into(),
                },
            ],
        };
        let stale = stale_allowlist_entries(&surface, &covered, &allowlist);
        assert_eq!(
            stale.len(),
            2,
            "both a now-covered and a surface-gone entry are stale"
        );
        let report = GateReport::compute("r1", "ws", &surface, &covered, &allowlist);
        // Gap itself is empty (all covered) BUT the stale entries make it RED.
        assert!(report.gap.is_clean(), "no missing surface");
        assert!(
            !report.is_green(),
            "stale allowlist entries fail the HARD-zero gate"
        );
        assert!(report.summary().contains("RED"));
    }

    #[test]
    fn rows_and_summary_round_trip_through_serde() {
        let surface = sample_surface();
        let covered: BTreeSet<String> = ["viz_tab:Test@fat".to_string()].into_iter().collect();
        let allowlist = Allowlist {
            entries: vec![AllowEntry {
                key: "viz_tab:Test@thin".into(),
                reason: "excused".into(),
            }],
        };
        let rows = rows_for("r1", "ws", &surface, &covered, &allowlist, 123);
        assert_eq!(rows.len(), 4, "one row per surface node");
        // Verdicts: 1 covered, 1 allowlisted, 2 missing.
        let by_verdict = |v: Verdict| rows.iter().filter(|r| r.verdict() == v).count();
        assert_eq!(by_verdict(Verdict::Covered), 1);
        assert_eq!(by_verdict(Verdict::Allowlisted), 1);
        assert_eq!(by_verdict(Verdict::Missing), 2);
        // The allowlisted row carries the reason.
        let allow_row = rows
            .iter()
            .find(|r| r.verdict() == Verdict::Allowlisted)
            .unwrap();
        assert_eq!(allow_row.reason, "excused");
        assert_eq!(allow_row.surface_key, "viz_tab:Test@thin");

        // Each row round-trips through serde (the warehouse row shape).
        let json = serde_json::to_string(&rows).unwrap();
        let back: Vec<CoverageRow> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rows);

        // The summary rolls the rows up for the viz/CLI.
        let summary = CoverageSummary::from_rows(&rows);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.covered, 1);
        assert_eq!(summary.allowlisted, 1);
        assert_eq!(summary.gap, 2);
        assert!(!summary.green);
        assert_eq!(summary.missing.len(), 2);
        // The viz JSON shape carries the burn-down list.
        let vj = summary.to_json();
        assert_eq!(vj["gap"], 2);
        assert_eq!(vj["green"], false);
        assert!(
            vj["missing"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("mcp_tool:search@na"))
        );
    }

    /// Build a small mixed-verdict row set across two workspaces for the SVG twin.
    fn svg_sample_rows() -> Vec<CoverageRow> {
        let row = |ws: &str, key: &str, verdict: Verdict, util: f64| CoverageRow {
            run_id: "run1".into(),
            workspace: ws.into(),
            surface_key: key.into(),
            kind: key.split(':').next().unwrap_or("").into(),
            id: key.into(),
            mode: "fat".into(),
            verdict: verdict.label().into(),
            reason: String::new(),
            ts_micros: 1,
            utfallsrum_covered: util,
        };
        vec![
            row("nornir", "viz_tab:Bench@fat", Verdict::Covered, 1.0),
            row("nornir", "viz_tab:Test@fat", Verdict::Allowlisted, 0.33),
            row("nornir", "mcp_tool:search@na", Verdict::Missing, 0.0),
            row("skade", "cli_command:bench@na", Verdict::Covered, 0.5),
        ]
    }

    /// The metrics SVG is self-contained, names every workspace with its verdict,
    /// carries the three axis titles, and is deterministic (snapshot-safe).
    #[test]
    fn coverage_svg_is_self_contained_and_deterministic() {
        let rows = svg_sample_rows();
        let svg = coverage_svg(&rows);

        assert!(svg.starts_with("<svg"), "starts with <svg");
        assert!(svg.trim_end().ends_with("</svg>"), "well-formed close");
        assert!(!svg.contains("<script"), "no JavaScript — static SVG");

        // both workspaces appear, each with a verdict word
        assert!(svg.contains("nornir"), "names the nornir workspace");
        assert!(svg.contains("skade"), "names the skade workspace");
        assert!(svg.contains("RED"), "nornir has a Missing gap → RED");
        assert!(svg.contains("GREEN"), "skade is all-covered → GREEN");

        // the three axes
        for axis in ["ran", "utfallsrum", "reachable"] {
            assert!(svg.contains(axis), "axis `{axis}` titled");
        }
        // a surface key is rendered
        assert!(svg.contains("viz_tab:Bench@fat"));

        // deterministic: same rows → byte-identical SVG
        assert_eq!(
            svg,
            coverage_svg(&svg_sample_rows()),
            "render is idempotent"
        );
    }

    /// Empty rows render a placeholder, never a panic or malformed SVG.
    #[test]
    fn coverage_svg_empty_is_placeholder() {
        let svg = coverage_svg(&[]);
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("no surface_coverage rows"));
    }
}
