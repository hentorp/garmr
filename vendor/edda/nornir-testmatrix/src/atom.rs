//! # atom-layer verifier (L0) — the per-atom oracle on top of [`SurfaceKind::UiAtom`]
//!
//! The marker/metro layers above are the *declared* truth — which UI surface ↔
//! which gRPC — but they are per-button / per-tab, so sub-panel widgets (the 🧬
//! tab's CloneEvents "populate status" + Jobs panels) slip through: an
//! `is not served` error-text *leaks* untested. The atom layer closes that by
//! enumerating the surface at **atom granularity** and **verifying** each against
//! what the live UI actually rendered.
//!
//! ## Where this sits relative to [`crate::discover`]
//!
//! `discover` already owns the atom **surface kind** ([`SurfaceKind::UiAtom`]) and
//! the simple enumerator/coverage pair ([`ui_atoms`](crate::discover::ui_atoms) /
//! [`covered_atoms`](crate::discover::covered_atoms)) that the autonom path feeds
//! from a live walk. This module adds the missing piece: a UI-agnostic
//! **verifier verdict** that turns raw observations into a covered set + NAMED
//! failures, reusing the EXISTING [`SurfaceKind::UiAtom`] surface kind — there is
//! exactly ONE atom variant.
//!
//! This module owns only the **generic CONCEPT** (UI-agnostic — no egui / kittest
//! / AccessKit here):
//!
//! 1. [`AtomState`] — the state axis (`empty` vs `populated`): a surface must be
//!    correct in BOTH the clean-slate state (no error atom) and the populated
//!    state (the expected atoms present, LAW 2 RAGNARÖK).
//! 2. [`AtomSpec`] + [`atom_surface`] — the **enumerator**: from a list of
//!    expected atoms per `(tab, atom, state)`, build [`SurfaceKind::UiAtom`]
//!    [`SurfaceNode`]s that drop straight into the existing
//!    [`Surface`](crate::discover::Surface) / gate.
//! 3. [`AtomObservation`] — the UI-agnostic record of what the walk SAW for one
//!    atom in one state (present? is it an error atom?). nornir's kittest walk
//!    produces these from the real AccessKit tree; the framework never sees a
//!    widget.
//! 4. [`verify_atoms`] — the **verifier verdict**: the generic oracle — *(a)* NO
//!    error atom in the `empty` state, *(b)* the expected atom PRESENT in the
//!    `populated` state — applied to the observations to yield the **covered**
//!    key-set (which feeds the existing
//!    [`compute_gap`](crate::discover::compute_gap) / coverage gate verbatim) plus
//!    the list of [`AtomFailure`]s that explain a RED. So the atom layer reuses the
//!    whole gate machinery: green ⟺ every atom × state ran AND was correct.
//!
//! ```text
//!   walk the UI ──▶ Vec<AtomObservation>  (UI-specific, lives in nornir)
//!                          │
//!        atom_surface(specs) ──▶ Surface (UiAtom nodes)
//!                          │           │
//!                   verify_atoms(specs, &obs) ──▶ covered set + failures
//!                          │
//!         compute_gap(surface, covered, allowlist) ──▶ GREEN ⟺ every atom covered
//! ```
//!
//! ## Key convention (ONE variant, ONE shape)
//!
//! Every node this module emits is a [`SurfaceKind::UiAtom`] with [`Mode::NA`].
//! The per-state granularity is folded into the node **id** as a suffix:
//!
//! ```text
//!   ui_atom:<tab>/<atom>/<state>@na
//! ```
//!
//! This is the SAME `kind:id@mode` shape every other surface uses, and a strict
//! extension of `discover`'s state-free `ui_atom:<tab>/<label>@na` id (the live
//! atom-walk path stays as-is; the verifier path carries the extra `/<state>`
//! axis). There is no second surface variant — `SurfaceKind::Atom` does not exist.
//!
//! Pure `std` + `serde`; every type round-trips so the verdict persists to the
//! warehouse like any other coverage fact.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::discover::{Mode, SurfaceKind, SurfaceNode};

/// The stable atom surface key: `"ui_atom:<tab>/<atom>/<state>@na"`. The state is
/// folded into the id so the key fits the standard `kind:id@mode` shape the gate
/// joins on (the thin/fat [`Mode`] axis stays NA — an atom's axis is its state).
fn atom_key(tab: &str, atom: &str, state: AtomState) -> String {
    format!(
        "{}:{}/{}/{}@{}",
        SurfaceKind::UiAtom.label(),
        tab,
        atom,
        state.label(),
        Mode::NA.label(),
    )
}

/// The state-bearing node id (`"<tab>/<atom>/<state>"`).
fn atom_id(tab: &str, atom: &str, state: AtomState) -> String {
    format!("{}/{}/{}", tab, atom, state.label())
}

/// The **state axis** of an atom surface. Every atom must be verified in both
/// states: the clean-slate `Empty` state (where an error atom like `is not served`
/// must NOT appear) and the `Populated` state (where the expected data atom MUST
/// appear — LAW 2 RAGNARÖK, no silently-blank pane).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomState {
    /// Clean-slate / empty registry — the state that leaks `is not served`,
    /// `Failed to load`, `unavailable` error atoms when a surface is unguarded.
    Empty,
    /// Populated — the surface has data; its expected atoms must be present.
    Populated,
}

impl AtomState {
    /// The stable tag used in the atom node's id slot / warehouse rows.
    pub fn label(self) -> &'static str {
        match self {
            AtomState::Empty => "empty",
            AtomState::Populated => "populated",
        }
    }

    pub fn parse(s: &str) -> Option<AtomState> {
        match s {
            "empty" => Some(AtomState::Empty),
            "populated" => Some(AtomState::Populated),
            _ => None,
        }
    }
}

/// One expected **atom** the gate enumerates: a widget (`atom`) that must behave
/// correctly inside `tab` in a given [`AtomState`]. The `expected_present` flag
/// encodes the oracle's polarity for this `(tab, atom, state)`:
///
/// - `expected_present == true`  → the atom MUST be present (the `Populated`-state
///   data atom; LAW 2 — a blank pane is a RED).
/// - `expected_present == false` → the atom must NOT be present (the `Empty`-state
///   error atom; an `is not served` leak is a RED).
///
/// This is the UI-agnostic declaration; nornir lists its atoms here, the kittest
/// walk produces the matching [`AtomObservation`]s, and [`verify_atoms`] joins them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomSpec {
    /// The tab / panel this atom lives in (`"nornir"`, `"clone_events"`).
    pub tab: String,
    /// The atom's stable label — the AccessKit label the walk addresses it by
    /// (`"populate_status_panel"`, `"is not served"`).
    pub atom: String,
    /// Which state this expectation is asserted in.
    pub state: AtomState,
    /// Oracle polarity: `true` ⇒ the atom must be present; `false` ⇒ it must be
    /// absent (an error-atom ban).
    pub expected_present: bool,
}

impl AtomSpec {
    /// An atom that MUST be present in `state` (a populated-state data atom).
    pub fn present(tab: impl Into<String>, atom: impl Into<String>, state: AtomState) -> Self {
        AtomSpec {
            tab: tab.into(),
            atom: atom.into(),
            state,
            expected_present: true,
        }
    }

    /// An atom that must be ABSENT in `state` (an error-atom ban — typically the
    /// empty-state `is not served` leak).
    pub fn absent(tab: impl Into<String>, atom: impl Into<String>, state: AtomState) -> Self {
        AtomSpec {
            tab: tab.into(),
            atom: atom.into(),
            state,
            expected_present: false,
        }
    }

    /// The human atom id (`"<tab>/<atom>"`) — what the display shows, state-free.
    pub fn id(&self) -> String {
        format!("{}/{}", self.tab, self.atom)
    }

    /// The full surface key this spec maps to (`"ui_atom:<tab>/<atom>/<state>@na"`),
    /// the join key shared with the observation + the covered set + the node.
    pub fn key_str(&self) -> String {
        atom_key(&self.tab, &self.atom, self.state)
    }

    /// The [`SurfaceNode`] for this atom — a [`SurfaceKind::UiAtom`] node with the
    /// state folded into the id so the node's own `key_str` equals
    /// [`Self::key_str`] (the gate keys on `kind:id@mode`).
    fn surface_node(&self) -> SurfaceNode {
        SurfaceNode::ui_atom(atom_id(&self.tab, &self.atom, self.state), self.id())
    }
}

/// Build the **atom surface**: one [`SurfaceKind::UiAtom`] [`SurfaceNode`] per
/// [`AtomSpec`] (`tab × atom × state`). Drops straight into a
/// [`Surface`](crate::discover::Surface) via `surface.extend(atom_surface(&specs))`,
/// so the atom layer is gated by the SAME
/// [`compute_gap`](crate::discover::compute_gap) machinery as every other surface
/// kind. Deduped + deterministic.
pub fn atom_surface(specs: &[AtomSpec]) -> Vec<SurfaceNode> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for spec in specs {
        if seen.insert(spec.key_str()) {
            out.push(spec.surface_node());
        }
    }
    out
}

/// What the UI walk OBSERVED for one atom in one state. nornir's kittest walk
/// produces these from the real AccessKit tree (`Queryable::query_all` +
/// `error_atoms()`); the framework joins them against the [`AtomSpec`]s. The
/// `present` flag is the raw fact (did the walk find a node with this label?); the
/// verdict (is that correct?) is computed by [`verify_atoms`] against the spec's
/// `expected_present`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomObservation {
    pub tab: String,
    pub atom: String,
    pub state: AtomState,
    /// Did the walk find a node with this atom's label in this tab+state?
    pub present: bool,
}

impl AtomObservation {
    pub fn new(
        tab: impl Into<String>,
        atom: impl Into<String>,
        state: AtomState,
        present: bool,
    ) -> Self {
        AtomObservation {
            tab: tab.into(),
            atom: atom.into(),
            state,
            present,
        }
    }

    /// The surface key this observation pertains to — joins to [`AtomSpec::key_str`].
    pub fn key_str(&self) -> String {
        atom_key(&self.tab, &self.atom, self.state)
    }
}

/// One atom-verdict FAILURE — why the gate went RED for a specific atom. Carried
/// so the gate message can NAME the offending atom (e.g. the CloneEvents
/// `is not served` leak), never a bare count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomFailure {
    /// The surface key (`"ui_atom:<tab>/<atom>/<state>@na"`) that failed.
    pub key: String,
    /// Why: `error_atom_leaked` (banned atom present in empty state),
    /// `expected_atom_missing` (data atom absent when populated), or
    /// `not_observed` (the walk never visited this atom — a coverage hole).
    pub reason: AtomFailReason,
}

/// Why an atom failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomFailReason {
    /// An atom that must be ABSENT was found present (the `is not served` leak).
    ErrorAtomLeaked,
    /// An atom that must be PRESENT was absent (a blank pane — LAW 2 violated).
    ExpectedAtomMissing,
    /// No observation for this spec — the walk never reached it (coverage hole).
    NotObserved,
}

impl AtomFailReason {
    pub fn label(self) -> &'static str {
        match self {
            AtomFailReason::ErrorAtomLeaked => "error_atom_leaked",
            AtomFailReason::ExpectedAtomMissing => "expected_atom_missing",
            AtomFailReason::NotObserved => "not_observed",
        }
    }
}

/// The result of running the atom verifier over the walk's observations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomVerdict {
    /// Surface keys that PASSED — feed this straight into the gate's `covered` set
    /// ([`compute_gap`](crate::discover::compute_gap) / coverage rows). Only an atom
    /// that was BOTH observed AND correct lands here.
    pub covered: BTreeSet<String>,
    /// The failures, sorted by key — what makes the gate RED, with a named reason.
    pub failures: Vec<AtomFailure>,
}

impl AtomVerdict {
    /// GREEN ⟺ no failures (every declared atom was observed and correct).
    pub fn is_green(&self) -> bool {
        self.failures.is_empty()
    }

    /// One-line human summary naming the failing atoms (never a bare count).
    pub fn summary(&self) -> String {
        if self.is_green() {
            return format!("{} atom(s) covered — GREEN", self.covered.len());
        }
        let named: Vec<String> = self
            .failures
            .iter()
            .map(|f| format!("{} ({})", f.key, f.reason.label()))
            .collect();
        format!(
            "{} atom(s) covered · {} FAILING: {} — RED",
            self.covered.len(),
            self.failures.len(),
            named.join(", "),
        )
    }
}

/// The **verifier verdict** — the generic L0 oracle.
///
/// For every declared [`AtomSpec`], join the matching [`AtomObservation`] and apply
/// the oracle:
///
/// - **no observation** → [`AtomFailReason::NotObserved`] (the walk never reached
///   it — a coverage hole, RED; "autonom only FINDS, never marks" — an unwalked
///   atom is uncovered, not silently green).
/// - **`expected_present` but absent** → [`AtomFailReason::ExpectedAtomMissing`]
///   (a blank pane — LAW 2 RAGNARÖK, RED).
/// - **must be absent but present** → [`AtomFailReason::ErrorAtomLeaked`] (the
///   `is not served` leak, RED).
/// - otherwise → the atom is **covered** (observed AND correct).
///
/// The returned `covered` set drops directly into the existing gate, so the atom
/// layer needs no new gate code — `green ⟺ every atom × state ran AND was correct`
/// reuses [`compute_gap`](crate::discover::compute_gap) verbatim.
pub fn verify_atoms(specs: &[AtomSpec], observations: &[AtomObservation]) -> AtomVerdict {
    use std::collections::BTreeMap;
    let obs_by_key: BTreeMap<String, &AtomObservation> =
        observations.iter().map(|o| (o.key_str(), o)).collect();

    let mut covered = BTreeSet::new();
    let mut failures = Vec::new();
    for spec in specs {
        let key = spec.key_str();
        match obs_by_key.get(&key) {
            None => failures.push(AtomFailure {
                key,
                reason: AtomFailReason::NotObserved,
            }),
            Some(obs) => {
                let correct = obs.present == spec.expected_present;
                if correct {
                    covered.insert(key);
                } else if spec.expected_present {
                    // expected present, observed absent → blank pane.
                    failures.push(AtomFailure {
                        key,
                        reason: AtomFailReason::ExpectedAtomMissing,
                    });
                } else {
                    // expected absent, observed present → error atom leaked.
                    failures.push(AtomFailure {
                        key,
                        reason: AtomFailReason::ErrorAtomLeaked,
                    });
                }
            }
        }
    }
    failures.sort_by(|a, b| a.key.cmp(&b.key));
    AtomVerdict { covered, failures }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::{Allowlist, GateReport};
    use crate::discover::{Surface, compute_gap};

    /// The three nornir atoms: the 🧬 tab's CloneEvents "populate status" + Jobs
    /// panels (must be present when populated) and the `is not served` error atom
    /// (must be absent when empty).
    fn nornir_atom_specs() -> Vec<AtomSpec> {
        vec![
            AtomSpec::absent("clone_events", "is not served", AtomState::Empty),
            AtomSpec::present(
                "clone_events",
                "populate_status_panel",
                AtomState::Populated,
            ),
            AtomSpec::present("clone_events", "jobs_panel", AtomState::Populated),
        ]
    }

    #[test]
    fn atom_surface_enumerates_one_uiatom_node_per_tab_atom_state() {
        let specs = nornir_atom_specs();
        let nodes = atom_surface(&specs);
        assert_eq!(nodes.len(), 3, "one atom node per (tab, atom, state)");
        // ONE variant: every node is a UiAtom (there is no SurfaceKind::Atom).
        assert!(nodes.iter().all(|n| n.kind == SurfaceKind::UiAtom));
        // The empty-state error-atom node and the populated data-atom nodes are
        // DISTINCT surfaces (the state axis).
        let keys: BTreeSet<String> = nodes.iter().map(|n| n.key_str()).collect();
        assert!(keys.contains("ui_atom:clone_events/is not served/empty@na"));
        assert!(keys.contains("ui_atom:clone_events/populate_status_panel/populated@na"));
        assert!(keys.contains("ui_atom:clone_events/jobs_panel/populated@na"));
        // Every spec's key matches its node's key (the join key is consistent).
        for spec in &specs {
            assert!(
                keys.contains(&spec.key_str()),
                "{} has a node",
                spec.key_str()
            );
        }
        // Atoms are the UI layer.
        assert_eq!(SurfaceKind::UiAtom.layer(), "ui");
    }

    /// The flagship RED-when-uncovered / GREEN-when-covered proof, driven through
    /// the REAL gate ([`compute_gap`] / [`GateReport`]) — the atom layer reuses the
    /// whole completeness-gate machinery.
    #[test]
    fn gate_red_when_atom_leaks_or_blank_green_when_all_atoms_correct() {
        let specs = nornir_atom_specs();
        let mut surface = Surface::new();
        surface.extend(atom_surface(&specs));
        assert_eq!(surface.len(), 3);

        // ── BROKEN UI: the empty CloneEvents pane LEAKS `is not served`, and the
        // Jobs panel never rendered (blank) when populated. populate_status DID
        // render correctly.
        let broken = vec![
            AtomObservation::new("clone_events", "is not served", AtomState::Empty, true), // leaked!
            AtomObservation::new(
                "clone_events",
                "populate_status_panel",
                AtomState::Populated,
                true,
            ),
            AtomObservation::new("clone_events", "jobs_panel", AtomState::Populated, false), // blank!
        ];
        let verdict = verify_atoms(&specs, &broken);
        assert!(!verdict.is_green(), "a leak + a blank pane → RED verdict");
        assert_eq!(verdict.failures.len(), 2);
        // The failures NAME the offending atoms (never a bare count).
        let leaked = verdict
            .failures
            .iter()
            .find(|f| f.reason == AtomFailReason::ErrorAtomLeaked)
            .expect("the is-not-served leak is reported");
        assert_eq!(leaked.key, "ui_atom:clone_events/is not served/empty@na");
        let blank = verdict
            .failures
            .iter()
            .find(|f| f.reason == AtomFailReason::ExpectedAtomMissing)
            .expect("the blank Jobs panel is reported");
        assert_eq!(blank.key, "ui_atom:clone_events/jobs_panel/populated@na");
        // Only the one correct atom is covered.
        assert_eq!(verdict.covered.len(), 1);
        assert!(
            verdict
                .covered
                .contains("ui_atom:clone_events/populate_status_panel/populated@na")
        );

        // Feed the covered set into the REAL gate → RED, and the gate's missing
        // set names the two uncovered atoms.
        let report = GateReport::compute(
            "r1",
            "nornir",
            &surface,
            &verdict.covered,
            &Allowlist::new(),
        );
        assert!(
            !report.is_green(),
            "uncovered atoms make the completeness gate RED"
        );
        let missing: BTreeSet<String> = report.gap.missing.iter().map(|n| n.key_str()).collect();
        assert_eq!(missing.len(), 2);
        assert!(missing.contains("ui_atom:clone_events/is not served/empty@na"));
        assert!(missing.contains("ui_atom:clone_events/jobs_panel/populated@na"));
        assert!(report.summary().contains("RED"));

        // ── FIXED UI (the empty-workspace guard landed): no leak, both panels
        // render when populated.
        let fixed = vec![
            AtomObservation::new("clone_events", "is not served", AtomState::Empty, false), // guarded
            AtomObservation::new(
                "clone_events",
                "populate_status_panel",
                AtomState::Populated,
                true,
            ),
            AtomObservation::new("clone_events", "jobs_panel", AtomState::Populated, true),
        ];
        let verdict2 = verify_atoms(&specs, &fixed);
        assert!(verdict2.is_green(), "every atom observed + correct → GREEN");
        assert_eq!(verdict2.covered.len(), 3);
        assert!(verdict2.failures.is_empty());
        assert!(verdict2.summary().contains("GREEN"));

        // The gate is now GREEN — every atom surface covered.
        let report2 = GateReport::compute(
            "r2",
            "nornir",
            &surface,
            &verdict2.covered,
            &Allowlist::new(),
        );
        assert!(report2.is_green(), "all atoms covered → Gap == ∅ → GREEN");
        assert_eq!(report2.gap.covered, 3);
        assert!(report2.gap.missing.is_empty());

        // Cross-check against the raw gap op too.
        let gap = compute_gap(&surface, &verdict2.covered, &BTreeSet::new());
        assert!(gap.is_clean());
    }

    /// "autonom only FINDS, never marks": a declared atom the walk NEVER VISITED
    /// is a coverage hole (RED), NOT silently green. This is the property that
    /// makes the atom layer trustworthy — an un-walked sub-panel can't pass.
    #[test]
    fn unobserved_atom_is_a_coverage_hole_not_silently_green() {
        let specs = nornir_atom_specs();
        // The walk only visited ONE of the three declared atoms.
        let partial = vec![AtomObservation::new(
            "clone_events",
            "is not served",
            AtomState::Empty,
            false,
        )];
        let verdict = verify_atoms(&specs, &partial);
        assert!(
            !verdict.is_green(),
            "two unvisited atoms → RED, never vacuous green"
        );
        assert_eq!(
            verdict.covered.len(),
            1,
            "only the observed-correct atom is covered"
        );
        let holes: Vec<&AtomFailure> = verdict
            .failures
            .iter()
            .filter(|f| f.reason == AtomFailReason::NotObserved)
            .collect();
        assert_eq!(
            holes.len(),
            2,
            "the two unvisited atoms are NotObserved holes"
        );
        assert!(holes.iter().all(|f| f.key.contains("/populated@na")));
    }

    #[test]
    fn observation_and_spec_keys_join_and_round_trip_through_serde() {
        let spec = AtomSpec::absent("clone_events", "is not served", AtomState::Empty);
        let obs = AtomObservation::new("clone_events", "is not served", AtomState::Empty, false);
        assert_eq!(
            spec.key_str(),
            obs.key_str(),
            "spec and observation join on the same key"
        );
        assert_eq!(
            spec.key_str(),
            "ui_atom:clone_events/is not served/empty@na"
        );

        // Every type round-trips (the warehouse row shape).
        let verdict = verify_atoms(&[spec.clone()], &[obs.clone()]);
        let json = serde_json::to_string(&verdict).unwrap();
        let back: AtomVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, verdict);

        let sj = serde_json::to_string(&spec).unwrap();
        let spec_back: AtomSpec = serde_json::from_str(&sj).unwrap();
        assert_eq!(spec_back, spec);
        assert_eq!(AtomState::parse("empty"), Some(AtomState::Empty));
        assert_eq!(AtomState::parse("populated"), Some(AtomState::Populated));
        assert_eq!(AtomState::parse("nope"), None);
    }
}
