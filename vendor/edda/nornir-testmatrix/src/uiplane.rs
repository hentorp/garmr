//! # uiplane — UI-PLANE reachability (LAW 9): the running app's navigation graph
//!
//! The mega-matrix tests components **in isolation** — it renders each surface
//! standalone and greens *"the component can render"*. But the user runs a
//! *running app* on which that surface lives on some **plane** (a tab / dialog /
//! view / app-mode), reachable only by **navigating** there. The classic failure:
//! the matrix greened "the Sverige showcase buttons render" while the *shipped*
//! app could not even **navigate** to the plane those buttons were on — they were
//! orphaned on an unreachable plane, or absent from the shipped wasm.
//!
//! This module models the UI as **planes + a navigation plan** and walks it on the
//! REAL app, so the matrix asserts the thing the user actually does: *reach* every
//! surface and *prove it ran* there.
//!
//! ```text
//!   UiPlane   = a tagged view-state (id + label + the interactive SURFACES on it)
//!   UiPlan    = a navigation graph: planes are nodes, TRANSITIONS are edges
//!               (a transition = a named action that moves plane A → B)
//!   PlaneDriver = the seam: drive the SAME plan against different backends
//!               (native robot-UI / kittest, or a deployed-wasm headless browser)
//!   RobotPlan::walk(plan, driver) = from the start plane, BFS the plan to REACH
//!               every plane, and on each assert every declared surface is
//!               PRESENT + RAN (read from the app's emitted trace / state_json).
//! ```
//!
//! ## The LAW 9 verdict
//! A declared surface that is **not reachable** via the plan, or is reachable but
//! **did not run**, is **RED** — and the row names the unreachable plane + the
//! missing transition. A declared plane that the start plane cannot reach (an
//! **orphan**) is RED. A surface declared on no plane (or on an unreachable plane)
//! is RED — that is the exact Sverige-buttons catch.
//!
//! ## Generic + UI-agnostic
//! No viz/facett/egui types leak here. A headless library with no UI simply has an
//! **empty plan** (zero planes, zero transitions) — `walk` on it is trivially green
//! (nothing to reach). nornir-viz, facett-demo, korp, etc. each supply their OWN
//! `UiPlan` + a `PlaneDriver` over their own app; this core walks any of them.
//!
//! ## Composes with — does NOT duplicate
//! - [`crate::functional`] — every (plane, surface) verdict is emitted as a
//!   `functional_status` row, so LAW 9 lands in the SAME matrix as everything else.
//! - [`crate::utfallsrum`] — a surface with an outcome space attaches its
//!   [`Outcome`](crate::utfallsrum::Outcome) and the walk records its sweep too.
//! - facett's `Navigable` (pan/zoom data struct) — orthogonal: `Navigable` is the
//!   *within-plane* spatial model; `UiPlan` is the *between-plane* navigation graph.
//!   A `PlaneDriver` impl uses `Navigable` to move within a plane if it needs to.
//! - `nornir-robotui` — the native `PlaneDriver` impl wraps its `RobotSession`
//!   clicks; this module only defines the seam, nornir wires the robot to it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::model::{TestResultRow, status};

/// The aspect tag carried by UI-plane reachability [`TestResultRow`]s — distinct
/// from `"functional"` / `"utfallsrum"` so the matrix can group LAW 9 rows.
pub const UIPLANE_ASPECT: &str = "uiplane";

// ─── the declared model: planes, surfaces, transitions ──────────────────────

/// One **interactive surface** that lives on a [`UiPlane`] — a button, slider,
/// pane, control. The unit LAW 9 proves *reachable + ran*.
///
/// `id` is the stable id within its plane (matched against the driver's emitted
/// present/ran sets). `must_run` marks a surface that MUST have fired its emitter
/// once its plane is reached (a data-bearing pane, an auto-running view); a
/// passive surface (a static label) may be present-only. Default `must_run = true`
/// — pessimism (LAW 7): presume a surface should run unless declared passive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiSurface {
    /// Stable id within the plane (matched against the driver's emit set).
    pub id: String,
    /// Human label for display (defaults to `id`).
    pub label: String,
    /// Must this surface have RAN (fired its emitter) once its plane is reached?
    /// `true` (default) = present-AND-ran required; `false` = present is enough.
    #[serde(default = "default_true")]
    pub must_run: bool,
}

fn default_true() -> bool {
    true
}

impl UiSurface {
    /// A surface that must be present AND ran once its plane is reached.
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            label: id.clone(),
            id,
            must_run: true,
        }
    }

    /// A present-only surface (a static label / chrome) — present is enough, it
    /// need not fire an emitter.
    pub fn passive(id: impl Into<String>) -> Self {
        let mut s = Self::new(id);
        s.must_run = false;
        s
    }

    /// Set a display label distinct from the id.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }
}

/// One **plane** of the running app: a tagged view-state with the interactive
/// surfaces that live on it.
///
/// `id` is the stable plane id (a tab name, a dialog id, `"workspace=nornir/tab=Bench"`).
/// Two planes are the same iff their `id` matches. Surfaces are keyed by id within
/// the plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiPlane {
    /// Stable plane id — the driver's `current_plane()` returns this when the app
    /// is on this plane.
    pub id: String,
    /// Human label for display (defaults to `id`).
    pub label: String,
    /// The interactive surfaces declared to live on this plane, keyed by id.
    pub surfaces: BTreeMap<String, UiSurface>,
}

impl UiPlane {
    /// A plane with no surfaces yet.
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            label: id.clone(),
            id,
            surfaces: BTreeMap::new(),
        }
    }

    /// Set a display label distinct from the id.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Declare a surface on this plane (idempotent by surface id).
    pub fn surface(mut self, s: UiSurface) -> Self {
        self.surfaces.entry(s.id.clone()).or_insert(s);
        self
    }

    /// Declare many surfaces at once.
    pub fn surfaces<I: IntoIterator<Item = UiSurface>>(mut self, ss: I) -> Self {
        for s in ss {
            self = self.surface(s);
        }
        self
    }
}

/// A **transition**: a named action that moves the app from plane `from` to plane
/// `to`. The driver's [`PlaneDriver::apply`] interprets `action` (e.g. "click tab
/// Bench", "open dialog", "switch workspace knut") and the walk asserts the app
/// actually landed on `to` afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    /// The plane this transition departs from.
    pub from: String,
    /// The plane this transition is declared to reach.
    pub to: String,
    /// The named action the driver applies (a click label, a command, …). The
    /// driver maps this string to a real action; the plan stays UI-agnostic.
    pub action: String,
}

impl Transition {
    pub fn new(from: impl Into<String>, to: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            action: action.into(),
        }
    }
}

/// The **navigation graph**: planes (nodes) + transitions (edges) + the start
/// plane the app boots on. [`RobotPlan::walk`] BFS-walks this against a
/// [`PlaneDriver`] to reach every plane and prove every surface ran.
///
/// A headless library with no UI builds an empty plan (no planes, no transitions);
/// `walk` on it is trivially green (nothing to reach), so the primitive is truly
/// UI-agnostic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiPlan {
    /// Every declared plane, keyed by id.
    pub planes: BTreeMap<String, UiPlane>,
    /// Every declared transition (plane→plane edges).
    pub transitions: Vec<Transition>,
    /// The plane the app boots on — the BFS root. Empty for an empty plan.
    pub start: String,
}

impl UiPlan {
    /// A plan whose start plane is `start` (the app's boot plane).
    pub fn new(start: impl Into<String>) -> Self {
        Self {
            start: start.into(),
            ..Default::default()
        }
    }

    /// An empty plan — a headless library with no UI. `walk` is trivially green.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Declare a plane (idempotent by id).
    pub fn plane(mut self, p: UiPlane) -> Self {
        self.planes.entry(p.id.clone()).or_insert(p);
        self
    }

    /// Declare a transition edge.
    pub fn transition(mut self, t: Transition) -> Self {
        self.transitions.push(t);
        self
    }

    /// Convenience: declare a transition by parts.
    pub fn edge(
        self,
        from: impl Into<String>,
        to: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        self.transition(Transition::new(from, to, action))
    }

    /// Is this an empty (no-UI) plan?
    pub fn is_empty(&self) -> bool {
        self.planes.is_empty()
    }

    /// Total declared surfaces across all planes.
    pub fn surface_count(&self) -> usize {
        self.planes.values().map(|p| p.surfaces.len()).sum()
    }

    /// The set of plane ids **reachable** from `start` over the transition edges
    /// (a pure BFS — no driver needed). The start plane is included iff it is a
    /// declared plane. Used by [`UiPlan::orphan_planes`] and by the walk's
    /// reachability check.
    pub fn reachable_planes(&self) -> BTreeSet<String> {
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for t in &self.transitions {
            adj.entry(t.from.as_str()).or_default().push(t.to.as_str());
        }
        let mut reached: BTreeSet<String> = BTreeSet::new();
        if self.start.is_empty() {
            return reached;
        }
        let mut q: VecDeque<&str> = VecDeque::new();
        // The start is reachable only if it is actually a declared plane.
        if self.planes.contains_key(&self.start) {
            q.push_back(self.start.as_str());
        }
        while let Some(n) = q.pop_front() {
            if !reached.insert(n.to_string()) {
                continue;
            }
            if let Some(succ) = adj.get(n) {
                for &s in succ {
                    // Only traverse into declared planes.
                    if self.planes.contains_key(s) && !reached.contains(s) {
                        q.push_back(s);
                    }
                }
            }
        }
        reached
    }

    /// Declared planes that the start plane **cannot reach** — ORPHANS. A
    /// non-empty result is a LAW 9 RED: a plane (and every surface on it) the
    /// running app can never navigate to. Sorted.
    pub fn orphan_planes(&self) -> Vec<String> {
        let reachable = self.reachable_planes();
        let mut orphans: Vec<String> = self
            .planes
            .keys()
            .filter(|id| !reachable.contains(*id))
            .cloned()
            .collect();
        orphans.sort();
        orphans
    }

    /// Transitions whose `from` or `to` names a plane that is not declared — a
    /// dangling edge (the plan references a plane it never defined). Sorted by the
    /// `(from,to)` pair. A dangling edge is a plan-authoring bug, surfaced so it is
    /// never silent.
    pub fn dangling_transitions(&self) -> Vec<&Transition> {
        let mut out: Vec<&Transition> = self
            .transitions
            .iter()
            .filter(|t| !self.planes.contains_key(&t.from) || !self.planes.contains_key(&t.to))
            .collect();
        out.sort_by(|a, b| (a.from.as_str(), a.to.as_str()).cmp(&(b.from.as_str(), b.to.as_str())));
        out
    }

    /// A BFS **plan**: an ordered list of `(plane, Option<transition-action>)`
    /// steps that reaches every reachable plane from start, each annotated with the
    /// transition action that gets there (`None` for the start plane). This is the
    /// driving script [`RobotPlan::walk`] executes. Planes are visited once; the
    /// path to each is the first BFS path found (the SHORTEST in edge count).
    pub fn bfs_route(&self) -> Vec<RouteStep> {
        let mut adj: BTreeMap<&str, Vec<&Transition>> = BTreeMap::new();
        for t in &self.transitions {
            if self.planes.contains_key(&t.from) && self.planes.contains_key(&t.to) {
                adj.entry(t.from.as_str()).or_default().push(t);
            }
        }
        let mut route = Vec::new();
        if self.start.is_empty() || !self.planes.contains_key(&self.start) {
            return route;
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut q: VecDeque<(&str, Option<&Transition>)> = VecDeque::new();
        q.push_back((self.start.as_str(), None));
        while let Some((plane, via)) = q.pop_front() {
            if !seen.insert(plane) {
                continue;
            }
            route.push(RouteStep {
                plane: plane.to_string(),
                via_action: via.map(|t| t.action.clone()),
                from: via.map(|t| t.from.clone()),
            });
            if let Some(succ) = adj.get(plane) {
                for &t in succ {
                    if !seen.contains(t.to.as_str()) {
                        q.push_back((t.to.as_str(), Some(t)));
                    }
                }
            }
        }
        route
    }
}

/// One step of a [`UiPlan::bfs_route`]: the plane to be on, and the transition
/// action that reaches it from a previously-visited plane (`None` = the start).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteStep {
    /// The plane this step lands on.
    pub plane: String,
    /// The transition action that reaches it (`None` for the start plane). When
    /// `Some`, the driver applies this action to move to `plane`.
    pub via_action: Option<String>,
    /// The plane the transition departs FROM (`None` for the start).
    pub from: Option<String>,
}

// ─── the driver seam ────────────────────────────────────────────────────────

/// The seam that lets the SAME [`UiPlan`] run against different backends — a
/// native robot-UI (egui_kittest / `nornir-robotui`) **or** a deployed-wasm
/// headless-browser driver that reads `window.__facett_state()` (LAW 1: drive the
/// SHIPPED artifact). The walk only ever talks to this trait, so a plan written
/// once runs against both the native build and the shipped wasm.
///
/// ## Contract
/// - [`current_plane`](PlaneDriver::current_plane): the app's current plane id —
///   read from the app's emitted state (`state_json["tab"]` / `window.__facett_state().plane`).
/// - [`apply`](PlaneDriver::apply): perform a transition's named action (click the
///   tab, switch the workspace, open the dialog) and settle (run frames / await).
///   Returns `Ok(())` if the action was performed; the WALK (not the driver)
///   verifies the resulting plane matches the transition's `to`.
/// - [`surfaces_present`](PlaneDriver::surfaces_present): the set of surface ids
///   the app reports PRESENT on the current plane (read from its trace / state).
/// - [`surfaces_ran`](PlaneDriver::surfaces_ran): the set of surface ids that have
///   RAN (fired their emitter) on the current plane.
///
/// A driver reads PRESENT/RAN from the app's *emitted data*, never from pixels
/// (LAW 6). The native impl reads `state_json`; the wasm impl reads the JS hook.
pub trait PlaneDriver {
    /// The plane id the app is currently on (from its emitted state).
    fn current_plane(&mut self) -> String;

    /// Apply a transition's named `action` (move the app). The walk verifies the
    /// landing plane; this only performs the action. An error means the action
    /// itself could not be performed (e.g. the control wasn't found) — the walk
    /// records that as a RED unreachable verdict naming the missing transition.
    fn apply(&mut self, action: &str) -> Result<(), String>;

    /// The surface ids the app reports PRESENT on the current plane.
    fn surfaces_present(&mut self) -> BTreeSet<String>;

    /// The surface ids that have RAN (fired their emitter) on the current plane.
    fn surfaces_ran(&mut self) -> BTreeSet<String>;
}

// ─── the walk + its verdict ─────────────────────────────────────────────────

/// The per-(plane, surface) outcome of a [`RobotPlan::walk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceVerdict {
    /// Reached the plane, surface present AND ran (or present-only if passive).
    ReachableAndRan,
    /// Reached the plane, but the surface was PRESENT and never RAN (its emitter
    /// never fired). RED — a button that exists but whose handler never fires.
    ReachableNotRan,
    /// Reached the plane, but the declared surface was ABSENT. RED — the shipped
    /// app is on the plane but the surface isn't there (the wasm-parity catch).
    ReachableAbsent,
    /// The plane itself was UNREACHABLE (orphan / a transition failed to land), so
    /// the surface could never be reached. RED — the Sverige-buttons catch.
    Unreachable,
}

impl SurfaceVerdict {
    /// Is this verdict a RED (failing) one? Everything but [`ReachableAndRan`].
    pub fn is_red(self) -> bool {
        !matches!(self, SurfaceVerdict::ReachableAndRan)
    }

    pub fn label(self) -> &'static str {
        match self {
            SurfaceVerdict::ReachableAndRan => "reachable_and_ran",
            SurfaceVerdict::ReachableNotRan => "reachable_not_ran",
            SurfaceVerdict::ReachableAbsent => "reachable_absent",
            SurfaceVerdict::Unreachable => "unreachable",
        }
    }
}

/// One row of a walk report: a (plane, surface) and its [`SurfaceVerdict`], plus
/// the transition action that reached the plane (so a RED names the missing
/// transition). Converts to a [`TestResultRow`] / `functional_status` emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalkRow {
    pub plane: String,
    pub surface: String,
    pub verdict: SurfaceVerdict,
    /// The transition action that reaches this surface's plane (`None` for the
    /// start plane / for an unreachable plane that had no working path).
    pub via_action: Option<String>,
    /// Whether the surface required running (`must_run`).
    pub must_run: bool,
}

impl WalkRow {
    /// The `functional_status`-style check id: `"<plane>/<surface>"`.
    pub fn check(&self) -> String {
        format!("{}/{}", self.plane, self.surface)
    }

    /// A human detail explaining the verdict (and, on RED, what's missing).
    pub fn detail(&self) -> String {
        match self.verdict {
            SurfaceVerdict::ReachableAndRan => format!(
                "reached plane '{}'{} · surface present{}",
                self.plane,
                self.via_action
                    .as_deref()
                    .map(|a| format!(" via '{a}'"))
                    .unwrap_or_else(|| " (start)".into()),
                if self.must_run {
                    " AND ran"
                } else {
                    " (passive)"
                },
            ),
            SurfaceVerdict::ReachableNotRan => format!(
                "LAW 9 RED: plane '{}' reached but surface '{}' PRESENT and never RAN \
                 (its emitter never fired — present ≠ ran)",
                self.plane, self.surface,
            ),
            SurfaceVerdict::ReachableAbsent => format!(
                "LAW 9 RED: plane '{}' reached but declared surface '{}' is ABSENT \
                 (shipped surface missing — the wasm-parity / orphan-surface catch)",
                self.plane, self.surface,
            ),
            SurfaceVerdict::Unreachable => format!(
                "LAW 9 RED: surface '{}' UNREACHABLE — plane '{}' is an orphan or no \
                 transition lands on it (name + add the missing transition)",
                self.surface, self.plane,
            ),
        }
    }

    /// Convert to a matrix [`TestResultRow`] (aspect [`UIPLANE_ASPECT`]). `suite`
    /// = `component`, `test_name` = `"<plane>/<surface>"`, pass iff
    /// [`SurfaceVerdict::ReachableAndRan`].
    pub fn to_row(&self, component: &str) -> TestResultRow {
        let ok = !self.verdict.is_red();
        TestResultRow {
            run_id: String::new(),
            repo: String::new(),
            suite: component.to_string(),
            test_name: self.check(),
            status: if ok { status::PASS } else { status::FAIL }.to_string(),
            duration_ms: 0.0,
            ts_micros: 0,
            message: self.detail(),
            aspect: UIPLANE_ASPECT.to_string(),
            metric: if ok { 0.0 } else { 1.0 },
        }
    }
}

/// The whole result of a [`RobotPlan::walk`]: every (plane, surface) verdict, the
/// orphan planes, the dangling transitions, and the reached-plane set. The
/// LAW 9 verdict ([`WalkReport::is_green`]) is *green ⟺ every declared plane was
/// reached AND every declared surface was reachable-and-ran*.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalkReport {
    /// One row per (plane, surface) declared in the plan.
    pub rows: Vec<WalkRow>,
    /// Declared planes the walk never reached (orphans + transitions that failed
    /// to land). Sorted. Non-empty ⇒ RED.
    pub unreachable_planes: Vec<String>,
    /// Plan-authoring dangling edges (referenced an undeclared plane). Sorted.
    pub dangling_edges: Vec<Transition>,
    /// Planes actually reached during the walk (drove-and-landed). Sorted.
    pub reached_planes: Vec<String>,
    /// Total declared planes in the plan.
    pub total_planes: usize,
}

impl WalkReport {
    /// LAW 9 verdict: green ⟺ no unreachable plane, no dangling edge, and every
    /// (plane, surface) row is [`SurfaceVerdict::ReachableAndRan`]. An empty plan
    /// (no planes) is trivially green — a headless library has nothing to reach.
    pub fn is_green(&self) -> bool {
        self.unreachable_planes.is_empty()
            && self.dangling_edges.is_empty()
            && self.rows.iter().all(|r| !r.verdict.is_red())
    }

    /// The RED rows (the failing (plane, surface) verdicts).
    pub fn red_rows(&self) -> Vec<&WalkRow> {
        self.rows.iter().filter(|r| r.verdict.is_red()).collect()
    }

    /// A one-line summary for the CLI / viz.
    pub fn summary(&self) -> String {
        let red = self.red_rows().len();
        format!(
            "{}/{} planes reached · {} surfaces · {} RED · {} orphan-planes · {} dangling — {}",
            self.reached_planes.len(),
            self.total_planes,
            self.rows.len(),
            red,
            self.unreachable_planes.len(),
            self.dangling_edges.len(),
            if self.is_green() {
                "GREEN"
            } else {
                "RED (LAW 9)"
            },
        )
    }

    /// Convert every walk row to a matrix [`TestResultRow`] (aspect
    /// [`UIPLANE_ASPECT`]), `suite = component`.
    pub fn to_rows(&self, component: &str) -> Vec<TestResultRow> {
        self.rows.iter().map(|r| r.to_row(component)).collect()
    }

    /// Emit every walk row to the process-global functional buffer (feature
    /// `testmatrix` ON) so `nornir test` / the matrix drains LAW 9 verdicts like
    /// any other functional row. One emit per (plane, surface). A no-op in release.
    #[cfg(feature = "testmatrix")]
    pub fn emit(&self, component: &str) {
        for r in &self.rows {
            crate::functional::functional_status(
                component,
                &r.check(),
                !r.verdict.is_red(),
                &r.detail(),
            );
        }
    }

    /// No-op emit in release (feature OFF).
    #[cfg(not(feature = "testmatrix"))]
    #[inline]
    pub fn emit(&self, _component: &str) {}
}

/// The walker: BFS the [`UiPlan`] against a [`PlaneDriver`], reaching every plane
/// and proving every surface present + ran. Stateless — a free function dressed as
/// a type for a tidy call site (`RobotPlan::walk(&plan, &mut driver)`).
pub struct RobotPlan;

impl RobotPlan {
    /// Walk `plan` with `driver`: from the start plane, BFS to reach every plane,
    /// and on each reached plane assert every declared surface is PRESENT + RAN.
    ///
    /// ## Algorithm
    /// 1. Compute the BFS route ([`UiPlan::bfs_route`]) + the orphan set
    ///    ([`UiPlan::orphan_planes`]) + dangling edges.
    /// 2. For each route step: if it has a transition action, [`apply`] it and
    ///    verify the driver's [`current_plane`] now equals the target — a mismatch
    ///    (or an `apply` error) marks the plane (and below it) UNREACHABLE.
    /// 3. On a reached plane, read [`surfaces_present`] + [`surfaces_ran`] and emit
    ///    one [`WalkRow`] per declared surface:
    ///    `present && (ran || !must_run)` → ReachableAndRan;
    ///    present but not ran (and must_run) → ReachableNotRan;
    ///    absent → ReachableAbsent.
    /// 4. Every surface on an unreachable/orphan plane → Unreachable.
    ///
    /// The result is one [`WalkRow`] for EVERY declared surface in the plan, so the
    /// report is provably complete (LAW 9 reachability completeness): no declared
    /// surface is silently skipped.
    pub fn walk(plan: &UiPlan, driver: &mut dyn PlaneDriver) -> WalkReport {
        let mut report = WalkReport {
            total_planes: plan.planes.len(),
            ..Default::default()
        };
        report.dangling_edges = plan.dangling_transitions().into_iter().cloned().collect();

        let route = plan.bfs_route();
        // The action that reached each plane (for naming the missing transition on
        // a RED row), keyed by plane id.
        let mut via_of: BTreeMap<String, Option<String>> = BTreeMap::new();
        let mut reached: BTreeSet<String> = BTreeSet::new();

        for step in &route {
            via_of.insert(step.plane.clone(), step.via_action.clone());
            // Drive the transition (if any) and verify we landed on the target.
            let landed = match &step.via_action {
                None => {
                    // Start plane: verify the app actually boots here.
                    driver.current_plane() == step.plane
                }
                Some(action) => match driver.apply(action) {
                    Ok(()) => driver.current_plane() == step.plane,
                    Err(_) => false,
                },
            };
            if landed {
                reached.insert(step.plane.clone());
                Self::record_plane(plan, &step.plane, &step.via_action, driver, &mut report);
            }
            // If not landed, the plane stays unreached; its surfaces are recorded
            // as Unreachable in the final sweep below.
        }

        // Reachability completeness: EVERY declared plane must have been reached.
        // Any plane not in `reached` (orphan, or a transition that failed to land)
        // → record all its surfaces Unreachable + add to unreachable_planes.
        for (plane_id, plane) in &plan.planes {
            if !reached.contains(plane_id) {
                report.unreachable_planes.push(plane_id.clone());
                let via = via_of.get(plane_id).cloned().flatten();
                for s in plane.surfaces.values() {
                    report.rows.push(WalkRow {
                        plane: plane_id.clone(),
                        surface: s.id.clone(),
                        verdict: SurfaceVerdict::Unreachable,
                        via_action: via.clone(),
                        must_run: s.must_run,
                    });
                }
            }
        }

        report.unreachable_planes.sort();
        report.unreachable_planes.dedup();
        report.reached_planes = reached.into_iter().collect();
        report.reached_planes.sort();
        // Stable row order: (plane, surface).
        report.rows.sort_by(|a, b| {
            (a.plane.as_str(), a.surface.as_str()).cmp(&(b.plane.as_str(), b.surface.as_str()))
        });
        report
    }

    /// Record one reached plane's surfaces (present/ran sweep).
    fn record_plane(
        plan: &UiPlan,
        plane_id: &str,
        via_action: &Option<String>,
        driver: &mut dyn PlaneDriver,
        report: &mut WalkReport,
    ) {
        let plane = match plan.planes.get(plane_id) {
            Some(p) => p,
            None => return,
        };
        let present = driver.surfaces_present();
        let ran = driver.surfaces_ran();
        for s in plane.surfaces.values() {
            let verdict = if !present.contains(&s.id) {
                SurfaceVerdict::ReachableAbsent
            } else if s.must_run && !ran.contains(&s.id) {
                SurfaceVerdict::ReachableNotRan
            } else {
                SurfaceVerdict::ReachableAndRan
            };
            report.rows.push(WalkRow {
                plane: plane_id.to_string(),
                surface: s.id.clone(),
                verdict,
                via_action: via_action.clone(),
                must_run: s.must_run,
            });
        }
    }
}

// ─── a tiny in-memory driver: the test double + the reference shape ─────────

/// A pure, in-memory [`PlaneDriver`] for unit-testing a [`UiPlan`] without any UI
/// — and the reference shape a real driver mimics. You hand it a transition table
/// (`action → target plane`) and, per plane, the present + ran surface sets the
/// "app" would report. The walk drives it exactly as it would a real app.
///
/// This is also how the harness's OWN tests prove the LAW 9 verdicts (orphan →
/// RED, absent → RED, present-not-ran → RED, present+ran → GREEN) without standing
/// up egui.
#[derive(Debug, Clone, Default)]
pub struct MockDriver {
    /// The current plane id.
    pub current: String,
    /// `action → plane it lands on`. An action not in here fails to land (apply
    /// returns Err) — modelling a missing/broken transition.
    pub transitions: BTreeMap<String, String>,
    /// Per plane: the surface ids the app reports PRESENT.
    pub present: BTreeMap<String, BTreeSet<String>>,
    /// Per plane: the surface ids the app reports RAN.
    pub ran: BTreeMap<String, BTreeSet<String>>,
}

impl MockDriver {
    /// A driver booted on `start`.
    pub fn new(start: impl Into<String>) -> Self {
        Self {
            current: start.into(),
            ..Default::default()
        }
    }

    /// Register a transition `action → target plane`.
    pub fn with_transition(mut self, action: impl Into<String>, to: impl Into<String>) -> Self {
        self.transitions.insert(action.into(), to.into());
        self
    }

    /// Declare, for `plane`, the present + ran surface id sets the app reports.
    pub fn with_plane_state<I, J, S, T>(mut self, plane: &str, present: I, ran: J) -> Self
    where
        I: IntoIterator<Item = S>,
        J: IntoIterator<Item = T>,
        S: Into<String>,
        T: Into<String>,
    {
        self.present.insert(
            plane.to_string(),
            present.into_iter().map(Into::into).collect(),
        );
        self.ran
            .insert(plane.to_string(), ran.into_iter().map(Into::into).collect());
        self
    }
}

impl PlaneDriver for MockDriver {
    fn current_plane(&mut self) -> String {
        self.current.clone()
    }

    fn apply(&mut self, action: &str) -> Result<(), String> {
        match self.transitions.get(action) {
            Some(to) => {
                self.current = to.clone();
                Ok(())
            }
            None => Err(format!("MockDriver: no transition for action '{action}'")),
        }
    }

    fn surfaces_present(&mut self) -> BTreeSet<String> {
        self.present.get(&self.current).cloned().unwrap_or_default()
    }

    fn surfaces_ran(&mut self) -> BTreeSet<String> {
        self.ran.get(&self.current).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2-plane plan: Home --click Bench--> Bench. Bench declares a data surface.
    fn home_bench_plan() -> UiPlan {
        UiPlan::new("Home")
            .plane(UiPlane::new("Home").surface(UiSurface::passive("title")))
            .plane(UiPlane::new("Bench").surface(UiSurface::new("bench_chart")))
            .edge("Home", "Bench", "click:Bench")
    }

    #[test]
    fn reachable_planes_is_bfs_from_start() {
        // A --x--> B --y--> C, plus an orphan D with no inbound edge.
        let plan = UiPlan::new("A")
            .plane(UiPlane::new("A"))
            .plane(UiPlane::new("B"))
            .plane(UiPlane::new("C"))
            .plane(UiPlane::new("D"))
            .edge("A", "B", "x")
            .edge("B", "C", "y");
        let reach = plan.reachable_planes();
        assert!(reach.contains("A") && reach.contains("B") && reach.contains("C"));
        assert!(!reach.contains("D"), "D has no inbound edge → orphan");
        assert_eq!(
            plan.orphan_planes(),
            vec!["D".to_string()],
            "D named as the orphan"
        );
    }

    #[test]
    fn dangling_transition_references_undeclared_plane() {
        let plan = UiPlan::new("A")
            .plane(UiPlane::new("A"))
            .edge("A", "GHOST", "x"); // GHOST never declared
        let dangling = plan.dangling_transitions();
        assert_eq!(dangling.len(), 1);
        assert_eq!(dangling[0].to, "GHOST");
    }

    #[test]
    fn bfs_route_reaches_every_reachable_plane_with_actions() {
        let plan = home_bench_plan();
        let route = plan.bfs_route();
        assert_eq!(route.len(), 2, "Home + Bench");
        assert_eq!(route[0].plane, "Home");
        assert!(route[0].via_action.is_none(), "start has no via");
        assert_eq!(route[1].plane, "Bench");
        assert_eq!(route[1].via_action.as_deref(), Some("click:Bench"));
        assert_eq!(route[1].from.as_deref(), Some("Home"));
    }

    // ── the four LAW 9 verdicts, sensitivity-proven ──────────────────────────

    #[test]
    fn walk_green_when_every_surface_present_and_ran() {
        let plan = home_bench_plan();
        let mut driver = MockDriver::new("Home")
            .with_transition("click:Bench", "Bench")
            .with_plane_state("Home", ["title"], [] as [&str; 0]) // passive: present, need not run
            .with_plane_state("Bench", ["bench_chart"], ["bench_chart"]); // present + ran
        let report = RobotPlan::walk(&plan, &mut driver);
        assert!(
            report.is_green(),
            "all surfaces reachable+ran → GREEN: {}",
            report.summary()
        );
        assert_eq!(report.rows.len(), 2, "title + bench_chart");
        assert!(report.unreachable_planes.is_empty());
        assert_eq!(
            report.reached_planes,
            vec!["Bench".to_string(), "Home".to_string()]
        );
        let chart = report
            .rows
            .iter()
            .find(|r| r.surface == "bench_chart")
            .unwrap();
        assert_eq!(chart.verdict, SurfaceVerdict::ReachableAndRan);
    }

    #[test]
    fn walk_red_when_surface_present_but_never_ran() {
        // SENSITIVITY: the SAME plan goes RED when the data surface didn't run.
        let plan = home_bench_plan();
        let mut driver = MockDriver::new("Home")
            .with_transition("click:Bench", "Bench")
            .with_plane_state("Home", ["title"], [] as [&str; 0])
            .with_plane_state("Bench", ["bench_chart"], [] as [&str; 0]); // present, NOT ran
        let report = RobotPlan::walk(&plan, &mut driver);
        assert!(!report.is_green(), "present-but-not-ran → RED");
        let chart = report
            .rows
            .iter()
            .find(|r| r.surface == "bench_chart")
            .unwrap();
        assert_eq!(chart.verdict, SurfaceVerdict::ReachableNotRan);
        assert!(chart.detail().contains("never RAN"), "names the failure");
    }

    #[test]
    fn walk_red_when_declared_surface_absent_on_reached_plane() {
        // The wasm-parity catch: on the plane but the surface isn't there.
        let plan = home_bench_plan();
        let mut driver = MockDriver::new("Home")
            .with_transition("click:Bench", "Bench")
            .with_plane_state("Home", ["title"], [] as [&str; 0])
            .with_plane_state("Bench", [] as [&str; 0], [] as [&str; 0]); // ABSENT
        let report = RobotPlan::walk(&plan, &mut driver);
        assert!(!report.is_green(), "absent surface → RED");
        let chart = report
            .rows
            .iter()
            .find(|r| r.surface == "bench_chart")
            .unwrap();
        assert_eq!(chart.verdict, SurfaceVerdict::ReachableAbsent);
        assert!(chart.detail().contains("ABSENT"));
    }

    #[test]
    fn walk_red_when_plane_is_orphan_unreachable() {
        // The Sverige-buttons catch: a surface declared on a plane no transition
        // reaches. Add an orphan "Sverige" plane with a button, NO edge to it.
        let plan = home_bench_plan()
            .plane(UiPlane::new("Sverige").surface(UiSurface::new("sverige_button")));
        let mut driver = MockDriver::new("Home")
            .with_transition("click:Bench", "Bench")
            .with_plane_state("Home", ["title"], [] as [&str; 0])
            .with_plane_state("Bench", ["bench_chart"], ["bench_chart"]);
        let report = RobotPlan::walk(&plan, &mut driver);
        assert!(!report.is_green(), "orphan plane → RED");
        assert_eq!(
            report.unreachable_planes,
            vec!["Sverige".to_string()],
            "names the orphan plane"
        );
        let btn = report
            .rows
            .iter()
            .find(|r| r.surface == "sverige_button")
            .unwrap();
        assert_eq!(btn.verdict, SurfaceVerdict::Unreachable);
        assert!(
            btn.detail().contains("UNREACHABLE"),
            "names the missing transition need"
        );
        // The OTHER surfaces are still green — the orphan didn't poison them.
        let chart = report
            .rows
            .iter()
            .find(|r| r.surface == "bench_chart")
            .unwrap();
        assert_eq!(chart.verdict, SurfaceVerdict::ReachableAndRan);
    }

    #[test]
    fn walk_red_when_transition_fails_to_land() {
        // The transition exists in the plan but the DRIVER can't perform it (the
        // control is missing in the shipped app) → the plane is unreachable.
        let plan = home_bench_plan();
        let mut driver = MockDriver::new("Home")
            // NO "click:Bench" transition registered → apply() errors.
            .with_plane_state("Home", ["title"], [] as [&str; 0])
            .with_plane_state("Bench", ["bench_chart"], ["bench_chart"]);
        let report = RobotPlan::walk(&plan, &mut driver);
        assert!(!report.is_green(), "broken transition → RED");
        assert!(report.unreachable_planes.contains(&"Bench".to_string()));
        let chart = report
            .rows
            .iter()
            .find(|r| r.surface == "bench_chart")
            .unwrap();
        assert_eq!(chart.verdict, SurfaceVerdict::Unreachable);
    }

    #[test]
    fn walk_red_when_app_boots_on_wrong_start_plane() {
        // The app claims to start on Home but actually boots elsewhere → even the
        // start plane is unreached.
        let plan = home_bench_plan();
        let mut driver = MockDriver::new("SomewhereElse")
            .with_transition("click:Bench", "Bench")
            .with_plane_state("Bench", ["bench_chart"], ["bench_chart"]);
        let report = RobotPlan::walk(&plan, &mut driver);
        assert!(!report.is_green());
        assert!(
            report.unreachable_planes.contains(&"Home".to_string()),
            "start plane unreached when the app boots elsewhere"
        );
    }

    #[test]
    fn empty_plan_is_trivially_green() {
        // A headless library with no UI: nothing to reach, nothing to run.
        let plan = UiPlan::empty();
        let mut driver = MockDriver::new("");
        let report = RobotPlan::walk(&plan, &mut driver);
        assert!(report.is_green(), "no planes → trivially green");
        assert_eq!(report.rows.len(), 0);
        assert_eq!(report.total_planes, 0);
    }

    #[test]
    fn report_is_complete_one_row_per_declared_surface() {
        // Reachability completeness: EVERY declared surface gets exactly one row,
        // reachable or not — no surface is silently skipped.
        let plan = home_bench_plan().plane(UiPlane::new("Orphan").surface(UiSurface::new("lost")));
        let mut driver = MockDriver::new("Home")
            .with_transition("click:Bench", "Bench")
            .with_plane_state("Home", ["title"], [] as [&str; 0])
            .with_plane_state("Bench", ["bench_chart"], ["bench_chart"]);
        let report = RobotPlan::walk(&plan, &mut driver);
        // title + bench_chart + lost = 3 declared surfaces → 3 rows.
        assert_eq!(report.rows.len(), plan.surface_count());
        assert_eq!(report.rows.len(), 3);
    }

    #[test]
    fn walk_rows_convert_to_matrix_rows_with_uiplane_aspect() {
        let plan = home_bench_plan();
        let mut driver = MockDriver::new("Home")
            .with_transition("click:Bench", "Bench")
            .with_plane_state("Home", ["title"], [] as [&str; 0])
            .with_plane_state("Bench", ["bench_chart"], [] as [&str; 0]); // not ran → red row
        let report = RobotPlan::walk(&plan, &mut driver);
        let rows = report.to_rows("viz");
        assert_eq!(rows.len(), 2);
        let chart = rows
            .iter()
            .find(|r| r.test_name == "Bench/bench_chart")
            .unwrap();
        assert_eq!(chart.aspect, UIPLANE_ASPECT);
        assert_eq!(
            chart.status,
            status::FAIL,
            "not-ran surface → RED matrix row"
        );
        assert_eq!(chart.suite, "viz");
        assert_eq!(chart.metric, 1.0);
        let title = rows.iter().find(|r| r.test_name == "Home/title").unwrap();
        assert_eq!(
            title.status,
            status::PASS,
            "passive present surface → green"
        );
    }

    // ── feature ON: emit drains the LAW 9 rows into the functional buffer ─────
    #[cfg(feature = "testmatrix")]
    #[test]
    fn emit_drains_uiplane_rows_into_functional_buffer() {
        let _guard = crate::functional::test_lock();
        let _ = crate::functional::drain_functional_rows();
        let plan = home_bench_plan();
        let mut driver = MockDriver::new("Home")
            .with_transition("click:Bench", "Bench")
            .with_plane_state("Home", ["title"], [] as [&str; 0])
            .with_plane_state("Bench", ["bench_chart"], ["bench_chart"]);
        let report = RobotPlan::walk(&plan, &mut driver);
        report.emit("viz-uiplane");
        let rows = crate::functional::drain_functional_rows();
        let mine: Vec<_> = rows.iter().filter(|r| r.suite == "viz-uiplane").collect();
        assert_eq!(mine.len(), 2, "title + bench_chart emitted");
        assert!(
            mine.iter().all(|r| r.status == status::PASS),
            "all green this run"
        );
        let chart = mine
            .iter()
            .find(|r| r.test_name == "Bench/bench_chart")
            .unwrap();
        assert!(chart.message.contains("present AND ran"));
    }
}
