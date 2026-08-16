//! # autonom self-discovery — the anti-drift core of the completeness gate
//!
//! AUT2. autonom refuses to be green if any **surface** ships untested. To do
//! that without a hand-maintained list (which drifts — the #1 recurring
//! failure), it **discovers** the testable surface *from data*:
//!
//! ```text
//! Surface = every fn / tab / cmd / tool in {viz(thin+fat), CLI, MCP, core fns}   ← discovered
//! Covered = every surface reached by an inject-assert test                       ← call_edges / tools/list / registry
//! Gap     = Surface − Covered − Allowlist
//! GATE: Gap == ∅   (else the build/release fails, and the gap is shown)
//! ```
//!
//! This module is **pure**: every enumerator takes the raw facts (rows the
//! caller pulls from the symbol graph / `tools/list` / clap introspection / the
//! facett registry) and returns [`SurfaceNode`]s as plain structs. No warehouse,
//! no iceberg, no MCP client lives here — those feeders live in `nornir`. That
//! keeps the whole thing unit-testable by feeding sample rows and asserting the
//! computed [`Surface`] / [`Gap`].
//!
//! The proven template is the MCP `tools/list` gate (`tests/support/mcp_harness.rs`
//! self-discovers 56 tools and fails on any uncovered one). [`mcp_tools`] +
//! [`compute_gap`] generalize that "no silent gaps" rule to the whole surface.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Which *kind* of surface a node belongs to. The enumerator that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceKind {
    /// A facett component — `{T : impl Facet for T} ∩ registry()`.
    FacettComponent,
    /// A viz tab in one mode — the tab enum × {thin, fat}.
    VizTab,
    /// A CLI subcommand (clap introspection).
    CliCommand,
    /// An MCP tool (`tools/list` — the proven template).
    McpTool,
    /// A gRPC service handler — `Service.verb` (the thin/server backend a marker
    /// crosses). Enumerated from the tonic handler impls (arch's grpc handler map),
    /// so every RPC is a must-be-covered surface, not an invisible backend.
    Grpc,
    /// A core function — `symbol_facts − test-reachable-closure(call_edges)`.
    Function,
    /// A **UI atom** — one interactive/labelled AccessKit node the live atom-walk
    /// discovered in a viz tab (a button, a label, a field). The L0 oracle's
    /// per-atom surface: a station the metro map would draw must correspond to a
    /// `ui_atom` the viz actually renders. `id` is `"<tab>/<atom-label>"`.
    UiAtom,
    /// A **hot-path that must carry a bencher** — one perf-critical module/crate
    /// (Task #39). Benchers self-register via `inventory`
    /// ([`crate::discover::BencherRow`] is the fed data shape the caller fills from
    /// that seam); a hot-path is *covered* iff a registered [`Bencher`] targets it,
    /// so a module that should be benched but isn't is a `Bencher` surface gap. `id`
    /// is the owning module/crate key (`<repo>.<scenario>` namespace, e.g.
    /// `"nornir.dep_graph"`).
    Bencher,
}

impl SurfaceKind {
    /// The stable tag stored in [`SurfaceNode::kind`] string form / warehouse rows.
    pub fn label(self) -> &'static str {
        match self {
            SurfaceKind::FacettComponent => "facett_component",
            SurfaceKind::VizTab => "viz_tab",
            SurfaceKind::CliCommand => "cli_command",
            SurfaceKind::McpTool => "mcp_tool",
            SurfaceKind::Grpc => "grpc",
            SurfaceKind::Function => "function",
            SurfaceKind::UiAtom => "ui_atom",
            SurfaceKind::Bencher => "bencher",
        }
    }

    /// The canonical **layer** this surface sits at: `ui` · `grpc` · `cli` · `mcp`
    /// · `core`. This is the AUT8-GAP-LAYER resolution — the layer is **DERIVED**
    /// from the kind, not a stored column: a `functional_status` emit site can't
    /// know its own layer, but the surface enumerator does, so the matrix groups
    /// by `layer()` without bloating `test_results`. Maps 1:1 to
    /// [`crate::discover`]'s peer `arch::NodeKind::layer` (ui≙Component, grpc≙Grpc,
    /// cli≙Cli, core≙CoreFn).
    pub fn layer(self) -> &'static str {
        match self {
            SurfaceKind::VizTab | SurfaceKind::FacettComponent => "ui",
            SurfaceKind::Grpc => "grpc",
            SurfaceKind::CliCommand => "cli",
            SurfaceKind::McpTool => "mcp",
            SurfaceKind::Function => "core",
            // A rendered UI atom is part of the ui layer (same as a viz tab).
            SurfaceKind::UiAtom => "ui",
            // A bencher sits at its own perf layer — not ui/grpc/cli/mcp/core.
            SurfaceKind::Bencher => "bench",
        }
    }
}

/// The thin/fat axis (autonom §4). Every data surface has **two** entrypoints —
/// `load()` (fat / embedded) and `fetch_*()` (thin / RPC) — and **both** must be
/// covered (the invariant is thin == fat parity). A non-data surface uses
/// [`Mode::NA`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Embedded / in-process path (`load()`), reads the warehouse directly.
    Fat,
    /// Thin client path (`fetch_*()`), reads over an RPC.
    Thin,
    /// Not a thin/fat data surface (e.g. a stateless CLI command).
    #[serde(rename = "na")]
    NA,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Fat => "fat",
            Mode::Thin => "thin",
            Mode::NA => "na",
        }
    }
}

/// One discovered, testable surface node — the unit of the completeness gate.
///
/// `id` is the **stable key** the gate matches coverage against (e.g. a facett
/// component named in `registry()`, an MCP tool name from `tools/list`, a fully
/// qualified fn path). Two nodes are the same surface iff their [`SurfaceNode::key`]
/// (kind + id + mode) is equal — so the same tab in thin vs fat are *distinct*
/// nodes (both must be covered).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceNode {
    pub kind: SurfaceKind,
    /// The stable identity within its kind (component name / tab name / cmd /
    /// tool name / fn path). Matched against coverage rows.
    pub id: String,
    /// The thin/fat mode this node covers ([`Mode::NA`] for non-data surfaces).
    pub mode: Mode,
    /// Human label for display (defaults to `id` when not given).
    pub label: String,
    /// Capability flags the enumerator surfaced (e.g. facett `reads_warehouse`,
    /// `has_local`, `has_remote`). Free-form, so each repo plugs its own caps;
    /// `BTreeSet` keeps them stable-ordered + deduped for deterministic output.
    pub caps: BTreeSet<String>,
}

impl SurfaceNode {
    /// The stable match key: `(kind, id, mode)`. The gate joins coverage on this.
    pub fn key(&self) -> (SurfaceKind, &str, Mode) {
        (self.kind, self.id.as_str(), self.mode)
    }

    /// A flat string key (`"kind:id@mode"`) for set membership / serde maps.
    pub fn key_str(&self) -> String {
        format!("{}:{}@{}", self.kind.label(), self.id, self.mode.label())
    }

    fn new(kind: SurfaceKind, id: impl Into<String>, mode: Mode) -> Self {
        let id = id.into();
        Self {
            kind,
            label: id.clone(),
            id,
            mode,
            caps: BTreeSet::new(),
        }
    }

    /// A [`SurfaceKind::UiAtom`] node with an explicit `id` + display `label`,
    /// [`Mode::NA`]. The single public atom-node constructor — used by both the
    /// live atom-walk enumerator ([`ui_atoms`], id `"<tab>/<label>"`) and the
    /// atom-layer verifier ([`crate::atom`], id `"<tab>/<atom>/<state>"`). There is
    /// exactly ONE atom surface kind; the verifier folds the state axis into the
    /// id, not a second variant.
    pub fn ui_atom(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self::new(SurfaceKind::UiAtom, id, Mode::NA).with_label(label)
    }

    fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    fn with_caps<I, S>(mut self, caps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.caps = caps.into_iter().map(Into::into).collect();
        self
    }
}

// ─── input row shapes (what the caller feeds in) ────────────────────────────

/// One `impl Facet for T` row, as the caller reads it from the symbol graph /
/// warehouse. nornir-testmatrix can't depend on facett, so this is the DATA
/// SHAPE the caller fills from `symbol_facts` + the facett registry.
///
/// The discovery contract: a component is a surface iff it both `impl Facet`s
/// **and** is in `registry()` — so [`facett_components`] intersects them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacetRow {
    /// The component type name (`T` in `impl Facet for T`) — the stable id.
    pub component: String,
    /// Is this `T` a member of `registry()`? Only registered components count
    /// (a `impl Facet` not in the registry is not yet a live surface).
    #[serde(default)]
    pub in_registry: bool,
    /// Does it expose a `local(...)` (fat) constructor? → a fat node.
    #[serde(default)]
    pub has_local_ctor: bool,
    /// Does it expose a `remote(...)` (thin) constructor? → a thin node.
    #[serde(default)]
    pub has_remote_ctor: bool,
    /// Free-form capability tags from `caps()`/`FacetCaps` (e.g. `reads_warehouse`,
    /// `interactive`). Copied onto each emitted node's `caps`.
    #[serde(default)]
    pub caps: Vec<String>,
    /// **The REAL headless-drive verdict** (not a name match): `true` when the
    /// caller actually built this component, drove it through a `Msg` script via
    /// `facett_core::harness`, and got a clean snapshot/render. The caller (the
    /// `nornir` binary, which alone has the facett deps) fills this from the live
    /// drive; [`covered_facetts`] turns it into the covered-key set — mirroring how
    /// [`DiscoveredAtom::ran`]/[`DiscoveredAtom::clean`] feed [`covered_atoms`].
    /// Defaults `false` (a row with no live drive is an uncovered surface).
    #[serde(default)]
    pub driven: bool,
    /// **The STRUCTURAL severity the drive observed** (RESOLVED decision (a)): the
    /// pane's `facett_core::Panel::severity()` folded to a tag — `"info"` (green),
    /// `"warning"`, or `"error"` (RED). This is the ERROR SIGNAL the gate asserts on
    /// *structurally*, replacing the `error_atoms()`/`ERROR_MARKERS` substring scan
    /// (which survives only as a MIGRATION FALLBACK, already folded into
    /// [`driven`](FacetRow::driven) by the caller). A driven pane whose severity is
    /// `"error"` is **NOT** counted covered by [`covered_facetts`] — so its surface
    /// node stays MISSING and the HARD gate goes RED, even though it "drove". Empty /
    /// absent defaults to `"info"` (the green floor), so the field is purely
    /// ADDITIVE for callers that have not yet adopted structural severity.
    #[serde(default = "default_severity")]
    pub severity: String,
}

/// The serde default for [`FacetRow::severity`] — the [`Severity::Info`] green
/// floor, so an old row with no `severity` column deserializes as green.
fn default_severity() -> String {
    "info".to_string()
}

/// Is a [`FacetRow::severity`] tag the RED, gate-failing severity? Lenient (the same
/// synonyms `facett_core::Severity::parse` accepts), so the string channel between
/// facett-core and this lean lib stays robust. Anything not recognizably "error"
/// (including `"info"`/`"warning"`/unknown) is NOT red.
pub fn severity_is_error(tag: &str) -> bool {
    matches!(
        tag.trim().to_ascii_lowercase().as_str(),
        "error" | "err" | "red"
    )
}

/// One symbol-graph function row (`symbol_facts`). The id used for reachability
/// is [`SymbolRow::fqn`] (fully-qualified name) — the same id `call_edges` use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRow {
    /// Fully-qualified function name (`crate::module::func`). The reachability id.
    pub fqn: String,
    /// Is this a test function (`#[test]` / a known test target)? Test fns are
    /// the **roots** of the reachable closure, not surface to be covered.
    #[serde(default)]
    pub is_test: bool,
    /// Display label (defaults to `fqn`).
    #[serde(default)]
    pub label: Option<String>,
}

/// One `caller → callee` edge from `call_edges`. Used to compute the
/// test-reachable closure (a fn is reachable iff a test fn can reach it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
}

/// One **discovered UI atom** from the live atom-walk — the row shape `nornir`
/// fills from `nornir_robotui::all_atoms` (the lib can't depend on egui/robotui,
/// so this is the DATA SHAPE the binary feeds in). `(tab, label)` is the stable
/// identity; `ran` + `clean` drive the verdict the [`ui_atoms`] enumerator's peer
/// producer assigns (covered ⟺ the tab ran AND no error atom leaked in that state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredAtom {
    /// The viz tab the atom was rendered in (the `state_json` section key).
    pub tab: String,
    /// The atom's visible text/label (`Atom::text` from the walk).
    pub label: String,
    /// The atom's AccessKit role (`Atom::role`, e.g. `Button`/`Label`) — kept as a
    /// cap so the warehouse row carries what kind of atom it is.
    #[serde(default)]
    pub role: String,
    /// Did the owning tab actually RUN (render) in the walk? A tab the walk never
    /// reached yields no atoms, so in practice this is `true` for every produced
    /// atom; kept explicit so a future per-state walk can mark a non-rendered state.
    #[serde(default)]
    pub ran: bool,
    /// Was the tab's rendered state CLEAN (no error atom) when this atom was seen?
    /// `covered` ⟺ `ran && clean` — the producer's verdict rule.
    #[serde(default)]
    pub clean: bool,
}

/// One **hot-path that should carry a bencher** — the row shape `nornir` fills
/// from the `inventory` bencher registry (the lib can't depend on `nornir-bench`,
/// so this is the DATA SHAPE the binary feeds in). `module` is the owning
/// module/crate key (`<repo>.<scenario>` namespace, e.g. `"nornir.dep_graph"`) —
/// the stable identity. `has_bencher` is the REAL discovery verdict: `true` iff
/// the caller found a registered [`Bencher`] targeting this hot-path when it swept
/// `inventory::iter::<BencherRegistration>()`. `bench_ids` records which
/// bencher(s) covered it (carried as caps for the warehouse row). A row with
/// `has_bencher == false` is an uncovered `Bencher` surface — exactly the "this
/// hot-path has no bencher" gap Task #39 makes enforceable. Mirrors
/// [`FacetRow::driven`] (a real verdict, not a name match).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BencherRow {
    /// The owning module/crate key (`<repo>.<scenario>` namespace) — the stable id.
    pub module: String,
    /// Did the `inventory` sweep find a registered [`Bencher`] targeting this
    /// hot-path? `false` ⟹ an uncovered surface (the gate gap / allowlist candidate).
    #[serde(default)]
    pub has_bencher: bool,
    /// The registered bencher id(s) covering this hot-path (carried as `bench:<id>`
    /// caps so the warehouse row records WHICH bencher(s) satisfy it). Empty when
    /// `has_bencher == false`.
    #[serde(default)]
    pub bench_ids: Vec<String>,
}

// ─── enumerators (PURE — feed facts, return SurfaceNodes) ───────────────────

/// **facett components**: `{T : impl Facet for T} ∩ registry()`.
///
/// One node per registered component **per mode it supports**: a `local()` ctor
/// → a [`Mode::Fat`] node, a `remote()` ctor → a [`Mode::Thin`] node (both must
/// be covered — thin == fat parity). A component with neither ctor (a stateless
/// view) gets a single [`Mode::NA`] node. Components not in `registry()` are
/// dropped (the intersection).
pub fn facett_components(rows: &[FacetRow]) -> Vec<SurfaceNode> {
    let mut out = Vec::new();
    for r in rows.iter().filter(|r| r.in_registry) {
        let mk = |mode: Mode| {
            SurfaceNode::new(SurfaceKind::FacettComponent, &r.component, mode)
                .with_caps(r.caps.iter().cloned())
        };
        match (r.has_local_ctor, r.has_remote_ctor) {
            (false, false) => out.push(mk(Mode::NA)),
            (l, t) => {
                if l {
                    out.push(mk(Mode::Fat));
                }
                if t {
                    out.push(mk(Mode::Thin));
                }
            }
        }
    }
    out
}

/// The drift between the authoritative Facet **registry** and the declared **tab
/// roster** (RESOLVED decision (b)). korp's SURFACE is the registry (self-discovering);
/// the 17-tab list is a CROSS-CHECK. Both sets empty ⟺ the registry and the tab bar
/// agree — every tab is backed by a registered Facet, and every registered Facet is
/// reachable as a tab.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabFacetDrift {
    /// Tab keys that have **no** registered Facet backing them — a tab the user sees
    /// with no tested component behind it (the "unwired surface ships green" bug).
    pub tabs_without_facet: Vec<String>,
    /// Registered Facet ids that are **not** reachable as any tab — a tested
    /// component the user can never navigate to (dead surface / a dropped tab).
    pub facets_without_tab: Vec<String>,
}

impl TabFacetDrift {
    /// Clean ⟺ the registry and the tab roster agree (both drift sets empty). The
    /// gate treats a non-clean result as a DISCOVERY failure (fail RED).
    pub fn is_clean(&self) -> bool {
        self.tabs_without_facet.is_empty() && self.facets_without_tab.is_empty()
    }
}

/// Cross-check the korp SURFACE (the authoritative Facet registry, given as the set
/// of registered Facet ids) against the declared tab roster (the tab keys) — decision
/// (b). Flags any tab with no registered Facet and any registered Facet unreachable
/// as a tab. Pure set difference; both id spaces are the stable `Tab::key()` /
/// component-id namespace, so they join directly. Sorted for deterministic output.
pub fn cross_check_tabs<'a, I, J>(registered_facets: I, tab_keys: J) -> TabFacetDrift
where
    I: IntoIterator<Item = &'a str>,
    J: IntoIterator<Item = &'a str>,
{
    let facets: BTreeSet<&str> = registered_facets.into_iter().collect();
    let tabs: BTreeSet<&str> = tab_keys.into_iter().collect();
    TabFacetDrift {
        tabs_without_facet: tabs.difference(&facets).map(|s| s.to_string()).collect(),
        facets_without_tab: facets.difference(&tabs).map(|s| s.to_string()).collect(),
    }
}

/// **viz tabs × {thin, fat}**: one node per tab per mode. The caller supplies the
/// tab names (the tab enum, discovered by introspection, never hand-listed at
/// the gate). Each tab yields a [`Mode::Fat`] *and* a [`Mode::Thin`] node —
/// that's the axis the old matrix missed (the `Test.Results RPC TODO` bug class).
pub fn viz_tabs<I, S>(tabs: I) -> Vec<SurfaceNode>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut out = Vec::new();
    for tab in tabs {
        let tab = tab.into();
        for mode in [Mode::Fat, Mode::Thin] {
            out.push(SurfaceNode::new(SurfaceKind::VizTab, &tab, mode));
        }
    }
    out
}

/// **CLI subcommands**: one [`Mode::NA`] node per clap subcommand name the caller
/// introspects (`Command::get_subcommands`). Modelled from a provided list — the
/// caller does the clap introspection, the gate just records the surface.
pub fn cli_commands<I, S>(subcommands: I) -> Vec<SurfaceNode>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    subcommands
        .into_iter()
        .map(|c| SurfaceNode::new(SurfaceKind::CliCommand, c, Mode::NA))
        .collect()
}

/// **MCP tools**: one [`Mode::NA`] node per tool name from a `tools/list` set —
/// the proven template (the MCP harness already self-discovers 56 tools and
/// fails on any uncovered one). The caller feeds the `tools/list` names.
pub fn mcp_tools<I, S>(tool_names: I) -> Vec<SurfaceNode>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    tool_names
        .into_iter()
        .map(|t| SurfaceNode::new(SurfaceKind::McpTool, t, Mode::NA))
        .collect()
}

/// **gRPC handlers**: one [`Mode::Thin`] node per `Service.verb` label — the
/// server-side backend a thin marker calls. gRPC is inherently the thin path, so
/// each handler is a `Thin`-mode surface that must be covered (an RPC with no test
/// is the `Test.Results RPC TODO` bug class the matrix is meant to catch). The
/// caller feeds the handler labels (arch's `grpc_handlers_from_symbols` values).
pub fn grpc_handlers<I, S>(labels: I) -> Vec<SurfaceNode>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    labels
        .into_iter()
        .map(|l| SurfaceNode::new(SurfaceKind::Grpc, l, Mode::Thin))
        .collect()
}

/// **functions**: `symbol_facts − test-reachable-closure(call_edges)`.
///
/// A core fn is a surface node iff **no test function can reach it** through the
/// call graph (a covered fn is reached by some test and so is *not* in the
/// surface gap). This is the pure graph op: BFS from every `is_test` root over
/// the `caller → callee` edges; whatever a test can reach is dropped; the
/// remainder are the unreached [`SurfaceKind::Function`] nodes.
///
/// Test functions themselves are never surface nodes (they're the roots, not the
/// thing to be tested).
pub fn unreached_functions(symbols: &[SymbolRow], edges: &[CallEdge]) -> Vec<SurfaceNode> {
    let reachable = test_reachable(symbols, edges);
    symbols
        .iter()
        .filter(|s| !s.is_test && !reachable.contains(s.fqn.as_str()))
        .map(|s| {
            let label = s.label.clone().unwrap_or_else(|| s.fqn.clone());
            SurfaceNode::new(SurfaceKind::Function, &s.fqn, Mode::NA).with_label(label)
        })
        .collect()
}

/// **UI atoms**: one [`Mode::NA`] node per discovered atom — `id =
/// "<tab>/<label>"`, `kind = ui_atom`. This is the per-atom surface the live
/// atom-walk feeds in (via [`DiscoveredAtom`]); it lets the completeness gate
/// count rendered atoms as surface nodes, not just whole tabs. The atom's role is
/// carried as a cap. Deduped by `(tab, label)` so a label repeated across galley
/// nodes is one surface node.
pub fn ui_atoms<'a, I>(atoms: I) -> Vec<SurfaceNode>
where
    I: IntoIterator<Item = &'a DiscoveredAtom>,
{
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for a in atoms {
        let id = format!("{}/{}", a.tab, a.label);
        if !seen.insert(id.clone()) {
            continue;
        }
        let mut node = SurfaceNode::new(SurfaceKind::UiAtom, &id, Mode::NA).with_label(&a.label);
        if !a.role.is_empty() {
            node = node.with_caps([format!("role:{}", a.role)]);
        }
        out.push(node);
    }
    out
}

/// The covered set for a batch of [`DiscoveredAtom`]s: an atom's surface key is
/// covered iff the tab RAN and its state was CLEAN (no error atom) when the atom
/// was seen — the producer's verdict rule, pure so it's unit-testable. The keys
/// match [`ui_atoms`]' node keys (`ui_atom:<tab>/<label>@na`).
pub fn covered_atoms<'a, I>(atoms: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = &'a DiscoveredAtom>,
{
    atoms
        .into_iter()
        .filter(|a| a.ran && a.clean)
        .map(|a| {
            format!(
                "{}:{}/{}@{}",
                SurfaceKind::UiAtom.label(),
                a.tab,
                a.label,
                Mode::NA.label()
            )
        })
        .collect()
}

/// **facett-component COVERAGE from the REAL headless drive** — the peer producer
/// to [`covered_atoms`], but for [`SurfaceKind::FacettComponent`] nodes. A component
/// counts as covered iff the caller actually built it, drove it through a `Msg`
/// script via `facett_core::harness`, and got a clean snapshot/render — recorded as
/// [`FacetRow::driven`]. This REPLACES the old static handler-name match for facett
/// surfaces: a component is green because it *drove*, not because a fn shares its name.
///
/// The emitted keys match [`facett_components`] node-for-node (same kind/id/mode
/// split), so `covered.extend(covered_facetts(rows))` marks exactly the driven
/// component's node(s) covered. A row with `driven == false` (never driven, or drove
/// dirty) yields no key — it stays an uncovered surface, exactly as an un-run atom does.
pub fn covered_facetts(rows: &[FacetRow]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    // Covered ⟺ registered AND driven AND NOT structurally RED (decision (a)): a
    // pane that drove but reported `Severity::Error` is a red surface — it emits no
    // covered key, so it stays MISSING and the HARD gate fails on it.
    for r in rows
        .iter()
        .filter(|r| r.in_registry && r.driven && !severity_is_error(&r.severity))
    {
        let key = |mode: Mode| {
            SurfaceNode::new(SurfaceKind::FacettComponent, &r.component, mode).key_str()
        };
        match (r.has_local_ctor, r.has_remote_ctor) {
            (false, false) => {
                out.insert(key(Mode::NA));
            }
            (l, t) => {
                if l {
                    out.insert(key(Mode::Fat));
                }
                if t {
                    out.insert(key(Mode::Thin));
                }
            }
        }
    }
    out
}

/// **benchers**: one [`SurfaceKind::Bencher`] node per hot-path that should carry
/// a bencher — `id = <module>`, [`Mode::NA`]. This is the per-hot-path surface the
/// bencher-coverage gate counts (Task #39): the caller feeds the canonical
/// hot-path list as [`BencherRow`]s (each with the `inventory`-derived
/// `has_bencher` verdict). The covering bencher id(s) ride along as `bench:<id>`
/// caps so the warehouse row records WHAT satisfies it. Deduped by `module` so a
/// hot-path listed twice is one surface node.
pub fn benchers(rows: &[BencherRow]) -> Vec<SurfaceNode> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in rows {
        if !seen.insert(r.module.clone()) {
            continue;
        }
        let node = SurfaceNode::new(SurfaceKind::Bencher, &r.module, Mode::NA)
            .with_caps(r.bench_ids.iter().map(|id| format!("bench:{id}")));
        out.push(node);
    }
    out
}

/// **bencher COVERAGE from the `inventory` seam** — the peer producer to
/// [`covered_facetts`] / [`covered_atoms`], for [`SurfaceKind::Bencher`] nodes. A
/// hot-path counts as covered iff the caller found a registered [`Bencher`]
/// targeting it when it swept `inventory::iter::<BencherRegistration>()`
/// (recorded as [`BencherRow::has_bencher`]). The emitted keys match
/// [`benchers`]' node keys, so `covered.extend(covered_benchers(rows))` marks
/// exactly the benched hot-paths covered. A row with `has_bencher == false`
/// yields no key — it stays an uncovered surface (the "no bencher" gap), exactly
/// as an un-driven facett or un-run atom does.
pub fn covered_benchers(rows: &[BencherRow]) -> BTreeSet<String> {
    rows.iter()
        .filter(|r| r.has_bencher)
        .map(|r| SurfaceNode::new(SurfaceKind::Bencher, &r.module, Mode::NA).key_str())
        .collect()
}

/// The set of fn fqns reachable from any test function over `call_edges`
/// (the test-reachable closure). Public so a caller / test can assert it
/// directly. The test roots themselves are included in the returned set.
pub fn test_reachable<'a>(symbols: &'a [SymbolRow], edges: &'a [CallEdge]) -> BTreeSet<&'a str> {
    use std::collections::BTreeMap;
    // Adjacency: caller → [callees].
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for e in edges {
        adj.entry(e.caller.as_str())
            .or_default()
            .push(e.callee.as_str());
    }
    let mut reached: BTreeSet<&str> = BTreeSet::new();
    let mut stack: Vec<&str> = symbols
        .iter()
        .filter(|s| s.is_test)
        .map(|s| s.fqn.as_str())
        .collect();
    while let Some(n) = stack.pop() {
        if !reached.insert(n) {
            continue; // already visited — handles cycles
        }
        if let Some(callees) = adj.get(n) {
            for &c in callees {
                if !reached.contains(c) {
                    stack.push(c);
                }
            }
        }
    }
    reached
}

// ─── the Surface + Gap model ────────────────────────────────────────────────

/// The full discovered surface — every [`SurfaceNode`] across all enumerators.
/// Built once per gate run, then differenced against coverage to compute the
/// [`Gap`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Surface {
    pub nodes: Vec<SurfaceNode>,
}

impl Surface {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge a batch of nodes from one enumerator into the surface.
    pub fn extend(&mut self, nodes: impl IntoIterator<Item = SurfaceNode>) -> &mut Self {
        self.nodes.extend(nodes);
        self
    }

    /// Total discovered surface nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Count of nodes of a given kind.
    pub fn count_kind(&self, kind: SurfaceKind) -> usize {
        self.nodes.iter().filter(|n| n.kind == kind).count()
    }
}

/// The served workspaces the completeness gate sweeps — the **workspace
/// dimension** of the surface. The full surface is `workspace × {cli_command,
/// viz_tab@{fat,thin}, mcp_tool, …}`: each served workspace must clean-slate →
/// populate → verify its own GUI/CLI surface, so a tab that works for `nornir`
/// but is blank for `knut` is a distinct gap. The caller (nornir) reads the live
/// served set from `workspaces_list`; this const is the canonical fallback /
/// reference so the dimension is discoverable from the lib.
pub const SERVED_WORKSPACES: &[&str] = &[
    "facett", "holger", "knut", "korp", "nornir", "ordning", "skade", "znippy",
];

/// The workspace-scoped surface key: `"<workspace>/<kind:id@mode>"`. The gate
/// joins coverage on THIS when the workspace dimension is active, so the same tab
/// in two workspaces are two distinct surfaces (both must be covered from their
/// own populated warehouse). [`workspace_keys`] maps a whole surface for one
/// workspace.
pub fn workspace_surface_key(workspace: &str, node: &SurfaceNode) -> String {
    format!("{workspace}/{}", node.key_str())
}

/// Every surface node's workspace-scoped key for `workspace` (the join keys the
/// gate uses when sweeping `workspace × surface`).
pub fn workspace_keys(workspace: &str, surface: &Surface) -> BTreeSet<String> {
    surface
        .nodes
        .iter()
        .map(|n| workspace_surface_key(workspace, n))
        .collect()
}

/// The completeness verdict: `Gap = Surface − Covered − Allowlist`.
///
/// `missing` is the set of surface nodes with **no covering test** and **not**
/// on the allowlist — the gate fails iff `missing` is non-empty. `allowlisted`
/// records which surface nodes were excused (so the excuse is visible, never
/// silent). `is_clean()` is the green/red verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    /// Surface nodes that are neither covered nor allowlisted — the gate fails
    /// if this is non-empty. Sorted by `key_str` for deterministic output.
    pub missing: Vec<SurfaceNode>,
    /// Surface nodes excused by the allowlist (recorded so the excuse is visible).
    pub allowlisted: Vec<SurfaceNode>,
    /// How many surface nodes were actually covered by a test.
    pub covered: usize,
    /// Total discovered surface nodes (`covered + allowlisted + missing`).
    pub total: usize,
}

impl Gap {
    /// The gate verdict: **green ⟺ no missing surface**. `Gap == ∅`.
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty()
    }

    /// A one-line summary for the CLI / viz.
    pub fn summary(&self) -> String {
        format!(
            "{}/{} surface nodes covered · {} allowlisted · {} MISSING — {}",
            self.covered,
            self.total,
            self.allowlisted.len(),
            self.missing.len(),
            if self.is_clean() {
                "GREEN"
            } else {
                "RED (gap not empty)"
            },
        )
    }
}

/// Compute `Gap = Surface − Covered − Allowlist`.
///
/// - `covered` is the set of surface keys (`SurfaceNode::key_str`) reached by an
///   inject-assert test (the caller derives it from coverage rows / call_edges /
///   `tools/list` exercised-set / the facett registry's covered components).
/// - `allowlist` is the set of surface keys explicitly excused (recorded as
///   `allowlisted`, never silently dropped).
///
/// Pure: feed the surface + two key sets, get the verdict back.
pub fn compute_gap(
    surface: &Surface,
    covered: &BTreeSet<String>,
    allowlist: &BTreeSet<String>,
) -> Gap {
    let mut missing = Vec::new();
    let mut allowlisted = Vec::new();
    let mut covered_count = 0usize;
    for node in &surface.nodes {
        let key = node.key_str();
        if covered.contains(&key) {
            covered_count += 1;
        } else if allowlist.contains(&key) {
            allowlisted.push(node.clone());
        } else {
            missing.push(node.clone());
        }
    }
    missing.sort_by_key(|n| n.key_str());
    allowlisted.sort_by_key(|n| n.key_str());
    Gap {
        covered: covered_count,
        total: surface.nodes.len(),
        missing,
        allowlisted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_of(n: &SurfaceNode) -> Vec<&str> {
        n.caps.iter().map(String::as_str).collect()
    }

    fn atom(tab: &str, label: &str, role: &str, ran: bool, clean: bool) -> DiscoveredAtom {
        DiscoveredAtom {
            tab: tab.into(),
            label: label.into(),
            role: role.into(),
            ran,
            clean,
        }
    }

    /// The `ui_atoms` enumerator turns discovered atoms into `ui_atom:<tab>/<label>`
    /// surface nodes (deduped, role carried as a cap), and `covered_atoms` marks an
    /// atom covered iff its tab ran AND its state was clean — the producer's rule.
    #[test]
    fn ui_atoms_enumerate_and_cover_per_atom() {
        let atoms = vec![
            atom("test", "Run full matrix", "Button", true, true), // covered
            atom("test", "Status: idle", "Label", true, true),     // covered
            atom("test", "Run full matrix", "Button", true, true), // dup → folded
            atom("nornir", "✗ is not served", "Label", true, false), // ran but dirty → NOT covered
        ];
        let nodes = ui_atoms(&atoms);
        // 3 distinct surface nodes (the dup folded).
        assert_eq!(nodes.len(), 3, "deduped per (tab,label): {nodes:?}");
        let keys: BTreeSet<String> = nodes.iter().map(|n| n.key_str()).collect();
        assert!(keys.contains("ui_atom:test/Run full matrix@na"));
        assert!(keys.contains("ui_atom:test/Status: idle@na"));
        assert!(keys.contains("ui_atom:nornir/✗ is not served@na"));
        // The role rides along as a cap for the warehouse row.
        let btn = nodes
            .iter()
            .find(|n| n.id == "test/Run full matrix")
            .unwrap();
        assert!(
            btn.caps.contains("role:Button"),
            "role cap carried: {:?}",
            btn.caps
        );

        let covered = covered_atoms(&atoms);
        assert!(
            covered.contains("ui_atom:test/Run full matrix@na"),
            "clean tab atom covered"
        );
        assert!(covered.contains("ui_atom:test/Status: idle@na"));
        assert!(
            !covered.contains("ui_atom:nornir/✗ is not served@na"),
            "an atom in a dirty (error) tab state is NOT covered",
        );
    }

    // ── bencher hot-path enumerator (Task #39) ──────────────────────────────

    fn bench_row(module: &str, has: bool, ids: &[&str]) -> BencherRow {
        BencherRow {
            module: module.into(),
            has_bencher: has,
            bench_ids: ids.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// The `benchers` enumerator turns hot-path rows into `bencher:<module>@na`
    /// surface nodes (deduped, covering bench ids carried as caps), and
    /// `covered_benchers` marks a hot-path covered iff a registered bencher targets
    /// it (`has_bencher`). A hot-path with NO bencher stays an uncovered surface —
    /// which makes the gate row RED unless allowlisted.
    #[test]
    fn benchers_enumerate_and_cover_per_hot_path() {
        let rows = vec![
            bench_row("nornir.dep_graph", true, &["nornir.dep_graph_build"]),
            bench_row("nornir.vector_search", false, &[]), // hot-path with NO bencher
            bench_row("nornir.dep_graph", true, &["nornir.dep_graph_build"]), // dup → folded
        ];
        let nodes = benchers(&rows);
        assert_eq!(nodes.len(), 2, "deduped per module: {nodes:?}");
        let keys: BTreeSet<String> = nodes.iter().map(|n| n.key_str()).collect();
        assert!(keys.contains("bencher:nornir.dep_graph@na"));
        assert!(keys.contains("bencher:nornir.vector_search@na"));
        // The covering bench id rides along as a cap on the benched hot-path.
        let dg = nodes.iter().find(|n| n.id == "nornir.dep_graph").unwrap();
        assert!(
            dg.caps.contains("bench:nornir.dep_graph_build"),
            "bench id cap: {:?}",
            dg.caps
        );

        let covered = covered_benchers(&rows);
        assert!(
            covered.contains("bencher:nornir.dep_graph@na"),
            "benched hot-path covered"
        );
        assert!(
            !covered.contains("bencher:nornir.vector_search@na"),
            "a hot-path with no registered bencher is NOT covered",
        );
    }

    /// A hot-path lacking a bencher is a gate gap; allowlisting it excuses the row.
    #[test]
    fn missing_bencher_is_gap_unless_allowlisted() {
        let rows = vec![
            bench_row("nornir.dep_graph", true, &["nornir.dep_graph_build"]),
            bench_row("nornir.vector_search", false, &[]),
        ];
        let mut surface = Surface::new();
        surface.extend(benchers(&rows));
        assert_eq!(surface.count_kind(SurfaceKind::Bencher), 2);

        let covered = covered_benchers(&rows);
        // No allowlist: the un-benched hot-path is the lone gap → RED.
        let gap = compute_gap(&surface, &covered, &BTreeSet::new());
        assert_eq!(gap.missing.len(), 1, "the un-benched hot-path is a gap");
        assert_eq!(gap.missing[0].key_str(), "bencher:nornir.vector_search@na");
        assert!(
            !gap.is_clean(),
            "a hot-path with no bencher makes the gate RED"
        );

        // Allowlist the known-missing hot-path → GREEN (the honest burn-down escape).
        let allow: BTreeSet<String> = ["bencher:nornir.vector_search@na".to_string()]
            .into_iter()
            .collect();
        let gap2 = compute_gap(&surface, &covered, &allow);
        assert!(gap2.is_clean(), "an allowlisted hot-path passes the gate");
        assert_eq!(gap2.allowlisted.len(), 1);
        assert_eq!(gap2.covered, 1, "the benched hot-path is covered");
    }

    #[test]
    fn bencher_kind_labels_and_layers() {
        assert_eq!(SurfaceKind::Bencher.label(), "bencher");
        assert_eq!(SurfaceKind::Bencher.layer(), "bench");
    }

    // ── facett component enumerator ─────────────────────────────────────────

    #[test]
    fn covered_facetts_marks_only_driven_registered_rows_matching_node_keys() {
        // NA component driven → its NA node key; fat+thin component driven → both;
        // a driven-but-unregistered row → nothing; a registered-but-undriven row → nothing.
        let rows = vec![
            FacetRow {
                component: "facett-helix".into(),
                in_registry: true,
                has_local_ctor: false,
                has_remote_ctor: false,
                caps: vec![],
                driven: true,
                severity: "info".into(),
            },
            FacetRow {
                component: "WarehouseView".into(),
                in_registry: true,
                has_local_ctor: true,
                has_remote_ctor: true,
                caps: vec![],
                driven: true,
                severity: "info".into(),
            },
            FacetRow {
                component: "NotRegistered".into(),
                in_registry: false,
                has_local_ctor: false,
                has_remote_ctor: false,
                caps: vec![],
                driven: true,
                severity: "info".into(),
            },
            FacetRow {
                component: "NeverDriven".into(),
                in_registry: true,
                has_local_ctor: false,
                has_remote_ctor: false,
                caps: vec![],
                driven: false,
                severity: "info".into(),
            },
        ];
        let covered = covered_facetts(&rows);
        // The covered keys must be EXACTLY the surface-node keys the enumerator emits
        // for the driven, registered rows.
        let nodes = facett_components(&rows);
        let driven_ids = ["facett-helix", "WarehouseView"];
        let want: BTreeSet<String> = nodes
            .iter()
            .filter(|n| driven_ids.contains(&n.id.as_str()))
            .map(|n| n.key_str())
            .collect();
        assert_eq!(
            covered, want,
            "covered keys match the driven rows' node keys"
        );
        // helix (NA) → 1 key, WarehouseView (fat+thin) → 2 keys.
        assert_eq!(covered.len(), 3);
        assert!(covered.contains("facett_component:facett-helix@na"));
        assert!(covered.contains("facett_component:WarehouseView@fat"));
        assert!(covered.contains("facett_component:WarehouseView@thin"));
        // Nothing for the unregistered or undriven rows.
        assert!(!covered.iter().any(|k| k.contains("NotRegistered")));
        assert!(!covered.iter().any(|k| k.contains("NeverDriven")));
    }

    #[test]
    fn a_red_pane_severity_error_is_not_covered_and_fails_the_gate() {
        // Two registered, driven components. One reported Severity::Error (a RED
        // pane) — the STRUCTURAL error signal (decision (a)). It must NOT count as
        // covered, so its surface node stays MISSING and the HARD gate goes RED —
        // even though it "drove".
        let rows = vec![
            FacetRow {
                component: "GreenPane".into(),
                in_registry: true,
                has_local_ctor: false,
                has_remote_ctor: false,
                caps: vec![],
                driven: true,
                severity: "info".into(),
            },
            FacetRow {
                component: "RedPane".into(),
                in_registry: true,
                has_local_ctor: false,
                has_remote_ctor: false,
                caps: vec![],
                driven: true,             // it DID drive …
                severity: "error".into(), // … but it rendered a RED pane.
            },
        ];
        let covered = covered_facetts(&rows);
        assert!(
            covered.contains("facett_component:GreenPane@na"),
            "green pane covered"
        );
        assert!(
            !covered.contains("facett_component:RedPane@na"),
            "a driven-but-RED (Severity::Error) pane is NOT covered — this is the gate signal",
        );

        // Wire it through the full gate: the red pane is the MISSING surface.
        let surface = {
            let mut s = Surface::new();
            s.extend(facett_components(&rows));
            s
        };
        let gap = compute_gap(&surface, &covered, &BTreeSet::new());
        assert!(
            !gap.is_clean(),
            "the gate is RED while a red pane is uncovered"
        );
        assert_eq!(gap.missing.len(), 1);
        assert_eq!(gap.missing[0].id, "RedPane");

        // A `warning` severity still counts as covered (it does not fail the gate).
        let mut warn = rows.clone();
        warn[1].severity = "warning".into();
        assert!(
            covered_facetts(&warn).contains("facett_component:RedPane@na"),
            "a Warning pane is degraded-but-covered — only Error fails the gate",
        );
    }

    #[test]
    fn cross_check_flags_tabs_without_facets_and_facets_without_tabs() {
        // decision (b): the registry is authoritative, the tab roster is the cross-check.
        let facets = ["map", "graph", "timeline", "orphan_facet"];
        let tabs = ["map", "graph", "timeline", "ghost_tab"];
        let drift = cross_check_tabs(facets, tabs);
        assert!(!drift.is_clean());
        assert_eq!(
            drift.tabs_without_facet,
            vec!["ghost_tab".to_string()],
            "a tab with no Facet"
        );
        assert_eq!(
            drift.facets_without_tab,
            vec!["orphan_facet".to_string()],
            "a Facet no tab reaches",
        );

        // Perfect agreement → clean.
        let ok = cross_check_tabs(["map", "graph"], ["graph", "map"]);
        assert!(ok.is_clean(), "registry == tab roster is clean drift");
    }

    #[test]
    fn severity_is_error_is_lenient() {
        assert!(severity_is_error("error"));
        assert!(severity_is_error("ERROR"));
        assert!(severity_is_error(" red "));
        assert!(!severity_is_error("info"));
        assert!(!severity_is_error("warning"));
        assert!(!severity_is_error(""));
    }

    #[test]
    fn facett_row_severity_defaults_to_info_on_deserialize() {
        // A row from an OLD schema (no `severity` column) deserializes as green —
        // the field is purely additive (serde default).
        let row: FacetRow =
            serde_json::from_str(r#"{"component":"Legacy","in_registry":true,"driven":true}"#)
                .unwrap();
        assert_eq!(
            row.severity, "info",
            "absent severity defaults to the green floor"
        );
        assert!(covered_facetts(&[row]).contains("facett_component:Legacy@na"));
    }

    #[test]
    fn facett_intersects_registry_and_splits_thin_fat() {
        let rows = vec![
            // A data component with both ctors → a Fat AND a Thin node.
            FacetRow {
                component: "WarehouseView".into(),
                in_registry: true,
                has_local_ctor: true,
                has_remote_ctor: true,
                caps: vec!["reads_warehouse".into(), "interactive".into()],
                driven: false,
                severity: "info".into(),
            },
            // Registered but stateless (no ctors) → a single NA node.
            FacetRow {
                component: "AboutPanel".into(),
                in_registry: true,
                has_local_ctor: false,
                has_remote_ctor: false,
                caps: vec![],
                driven: false,
                severity: "info".into(),
            },
            // impl Facet but NOT in registry() → dropped (the intersection).
            FacetRow {
                component: "ScratchView".into(),
                in_registry: false,
                has_local_ctor: true,
                has_remote_ctor: true,
                caps: vec![],
                driven: false,
                severity: "info".into(),
            },
        ];
        let nodes = facett_components(&rows);
        // WarehouseView → 2 nodes (fat+thin); AboutPanel → 1 (na); ScratchView → 0.
        assert_eq!(nodes.len(), 3, "registry intersection + thin/fat split");

        let wh: Vec<_> = nodes.iter().filter(|n| n.id == "WarehouseView").collect();
        assert_eq!(wh.len(), 2, "data component yields a fat AND a thin node");
        let modes: BTreeSet<_> = wh.iter().map(|n| n.mode).collect();
        assert!(modes.contains(&Mode::Fat) && modes.contains(&Mode::Thin));
        assert_eq!(caps_of(wh[0]), vec!["interactive", "reads_warehouse"]);

        assert!(
            nodes
                .iter()
                .any(|n| n.id == "AboutPanel" && n.mode == Mode::NA),
            "stateless registered component is a single NA node"
        );
        assert!(
            !nodes.iter().any(|n| n.id == "ScratchView"),
            "a Facet impl absent from registry() is NOT a surface"
        );
    }

    // ── viz tabs × {thin,fat} ───────────────────────────────────────────────

    #[test]
    fn viz_tabs_yield_thin_and_fat_each() {
        let nodes = viz_tabs(["Search", "Test", "Bench"]);
        assert_eq!(nodes.len(), 6, "3 tabs × 2 modes");
        let test_thin = nodes
            .iter()
            .find(|n| n.id == "Test" && n.mode == Mode::Thin)
            .expect("Test tab has a thin node — the bug class autonom kills");
        assert_eq!(test_thin.kind, SurfaceKind::VizTab);
        assert_eq!(test_thin.key_str(), "viz_tab:Test@thin");
    }

    // ── cli + mcp from provided lists ───────────────────────────────────────

    #[test]
    fn cli_and_mcp_model_provided_lists() {
        let cli = cli_commands(["test", "bench", "viz"]);
        assert_eq!(cli.len(), 3);
        assert!(
            cli.iter()
                .all(|n| n.kind == SurfaceKind::CliCommand && n.mode == Mode::NA)
        );

        let mcp = mcp_tools(["search", "build_order", "viz_state"]);
        assert_eq!(mcp.len(), 3);
        assert_eq!(mcp[1].key_str(), "mcp_tool:build_order@na");
    }

    #[test]
    fn surface_kind_layer_groups_ui_grpc_cli_mcp_core() {
        // AUT8-GAP-LAYER: layer is DERIVED from kind (no stored column).
        assert_eq!(SurfaceKind::VizTab.layer(), "ui");
        assert_eq!(SurfaceKind::FacettComponent.layer(), "ui");
        assert_eq!(SurfaceKind::Grpc.layer(), "grpc");
        assert_eq!(SurfaceKind::CliCommand.layer(), "cli");
        assert_eq!(SurfaceKind::McpTool.layer(), "mcp");
        assert_eq!(SurfaceKind::Function.layer(), "core");
    }

    #[test]
    fn grpc_handlers_make_thin_nodes() {
        let g = grpc_handlers(["Viz.Architecture", "Bench.Submit"]);
        assert_eq!(g.len(), 2);
        // gRPC is the thin/server backend → every handler is a Thin-mode surface
        // that must be covered (no invisible RPC).
        assert!(
            g.iter()
                .all(|n| n.kind == SurfaceKind::Grpc && n.mode == Mode::Thin)
        );
        assert_eq!(SurfaceKind::Grpc.label(), "grpc");
        assert_eq!(g[0].key_str(), "grpc:Viz.Architecture@thin");
    }

    // ── function reachability (the pure graph op) ───────────────────────────

    #[test]
    fn unreached_fn_shows_in_gap_covered_one_does_not() {
        // test_a → helper_covered → deep_covered ; orphan_fn reached by nobody.
        let symbols = vec![
            SymbolRow {
                fqn: "test_a".into(),
                is_test: true,
                label: None,
            },
            SymbolRow {
                fqn: "helper_covered".into(),
                is_test: false,
                label: None,
            },
            SymbolRow {
                fqn: "deep_covered".into(),
                is_test: false,
                label: None,
            },
            SymbolRow {
                fqn: "orphan_fn".into(),
                is_test: false,
                label: Some("orphan".into()),
            },
        ];
        let edges = vec![
            CallEdge {
                caller: "test_a".into(),
                callee: "helper_covered".into(),
            },
            CallEdge {
                caller: "helper_covered".into(),
                callee: "deep_covered".into(),
            },
        ];

        let reach = test_reachable(&symbols, &edges);
        assert!(reach.contains("helper_covered") && reach.contains("deep_covered"));
        assert!(!reach.contains("orphan_fn"));

        let unreached = unreached_functions(&symbols, &edges);
        assert_eq!(unreached.len(), 1, "only the orphan is unreached");
        assert_eq!(unreached[0].id, "orphan_fn");
        assert_eq!(
            unreached[0].label, "orphan",
            "label carried from symbol row"
        );
        // The transitively-covered fn must NOT appear, and a test fn never does.
        assert!(!unreached.iter().any(|n| n.id == "deep_covered"));
        assert!(!unreached.iter().any(|n| n.id == "test_a"));
    }

    #[test]
    fn reachability_handles_cycles() {
        // a ↔ b cycle, both reached from a test; c is an unreached cycle.
        let symbols = vec![
            SymbolRow {
                fqn: "t".into(),
                is_test: true,
                label: None,
            },
            SymbolRow {
                fqn: "a".into(),
                is_test: false,
                label: None,
            },
            SymbolRow {
                fqn: "b".into(),
                is_test: false,
                label: None,
            },
            SymbolRow {
                fqn: "c".into(),
                is_test: false,
                label: None,
            },
        ];
        let edges = vec![
            CallEdge {
                caller: "t".into(),
                callee: "a".into(),
            },
            CallEdge {
                caller: "a".into(),
                callee: "b".into(),
            },
            CallEdge {
                caller: "b".into(),
                callee: "a".into(),
            }, // cycle
            CallEdge {
                caller: "c".into(),
                callee: "c".into(),
            }, // self-loop, unreached
        ];
        let unreached = unreached_functions(&symbols, &edges);
        let ids: BTreeSet<_> = unreached.iter().map(|n| n.id.clone()).collect();
        assert_eq!(
            ids,
            BTreeSet::from(["c".to_string()]),
            "cycle doesn't hang; c is the only gap"
        );
    }

    // ── Gap = Surface − Covered − Allowlist ─────────────────────────────────

    #[test]
    fn compute_gap_subtracts_covered_and_allowlist() {
        let mut surface = Surface::new();
        surface
            .extend(viz_tabs(["Search", "Test"])) // 4 nodes
            .extend(mcp_tools(["search"])) // 1 node
            .extend(cli_commands(["doctor"])); // 1 node — the one we'll allowlist

        assert_eq!(surface.len(), 6);
        assert_eq!(surface.count_kind(SurfaceKind::VizTab), 4);

        // Covered: every viz node EXCEPT Test@thin, plus the mcp tool.
        let covered: BTreeSet<String> = [
            "viz_tab:Search@fat",
            "viz_tab:Search@thin",
            "viz_tab:Test@fat",
            "mcp_tool:search@na",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // Allowlist the doctor CLI command (excused on purpose).
        let allowlist: BTreeSet<String> =
            ["cli_command:doctor@na".to_string()].into_iter().collect();

        let gap = compute_gap(&surface, &covered, &allowlist);
        assert_eq!(gap.covered, 4);
        assert_eq!(gap.total, 6);
        assert_eq!(gap.allowlisted.len(), 1);
        assert_eq!(gap.allowlisted[0].id, "doctor");
        // The one true gap: Test@thin — the RPC-TODO bug class, now caught.
        assert_eq!(
            gap.missing.len(),
            1,
            "exactly one uncovered, un-allowlisted node"
        );
        assert_eq!(gap.missing[0].key_str(), "viz_tab:Test@thin");
        assert!(!gap.is_clean(), "a missing surface makes the gate RED");
        assert!(gap.summary().contains("RED"));
    }

    #[test]
    fn empty_gap_is_green() {
        let mut surface = Surface::new();
        surface.extend(mcp_tools(["a", "b"]));
        let covered: BTreeSet<String> = ["mcp_tool:a@na", "mcp_tool:b@na"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let gap = compute_gap(&surface, &covered, &BTreeSet::new());
        assert!(gap.is_clean(), "every surface covered → Gap == ∅ → GREEN");
        assert_eq!(gap.covered, 2);
        assert_eq!(gap.missing.len(), 0);
        assert!(gap.summary().contains("GREEN"));
    }

    #[test]
    fn end_to_end_full_surface_round_trips_through_serde() {
        // Build a full surface from all five enumerators, then serialize the Gap
        // (the warehouse row shape) and read it back — proves the model is the
        // schema the gate persists.
        let facets = vec![FacetRow {
            component: "GraphView".into(),
            in_registry: true,
            has_local_ctor: true,
            has_remote_ctor: true,
            caps: vec!["reads_warehouse".into()],
            driven: false,
            severity: "info".into(),
        }];
        let symbols = vec![
            SymbolRow {
                fqn: "t".into(),
                is_test: true,
                label: None,
            },
            SymbolRow {
                fqn: "wired".into(),
                is_test: false,
                label: None,
            },
            SymbolRow {
                fqn: "dead".into(),
                is_test: false,
                label: None,
            },
        ];
        let edges = vec![CallEdge {
            caller: "t".into(),
            callee: "wired".into(),
        }];

        let mut surface = Surface::new();
        surface
            .extend(facett_components(&facets))
            .extend(viz_tabs(["Graph"]))
            .extend(cli_commands(["graph"]))
            .extend(mcp_tools(["dep_graph_mermaid"]))
            .extend(unreached_functions(&symbols, &edges));

        // facett: 2 (fat+thin) · viz: 2 · cli: 1 · mcp: 1 · fns: 1 (dead) = 7.
        assert_eq!(surface.len(), 7);
        assert!(
            surface
                .nodes
                .iter()
                .any(|n| n.kind == SurfaceKind::Function && n.id == "dead")
        );

        let covered = BTreeSet::new();
        let gap = compute_gap(&surface, &covered, &BTreeSet::new());
        assert_eq!(gap.missing.len(), 7, "nothing covered → all 7 are gaps");

        let json = serde_json::to_string(&gap).unwrap();
        let back: Gap = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back, gap,
            "Gap round-trips through serde (the warehouse row)"
        );
        // The dead fn's node survives the round trip with its kind tag.
        assert!(
            back.missing
                .iter()
                .any(|n| n.kind == SurfaceKind::Function && n.id == "dead")
        );
    }
}
