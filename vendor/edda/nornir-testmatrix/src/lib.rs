//! # nornir-testmatrix
//!
//! The portable core of nornir's **multi-aspect test matrix** — extracted from
//! `nornir` (EPIC L) so any leaf repo (znippy, skade, lbzip2-rs …) can run the
//! same matrix with a *tiny* dep set: `std` + `serde`/`serde_json` + `anyhow`.
//! No iceberg, arrow, eframe, tantivy, or skade.
//!
//! ## What it does
//! 1. **Runner** ([`runner`]) — wrap a repo's *native* Rust test framework
//!    (`cargo nextest run --message-format libtest-json` if nextest is on PATH,
//!    else plain `cargo test`), parse each test's pass/fail + duration, enforce a
//!    stall watchdog. Pure subprocess driving — no test registration.
//! 2. **Multi-aspect engine** ([`aspect`]) — beyond unit tests, run MANY
//!    *aspects* of a repo's health ([`Aspect`]): build, doctest, clippy, fmt,
//!    audit, bench-smoke, coverage, feature-powerset, msrv, examples. Each
//!    shells the right `cargo` subcommand, parses its result, and emits
//!    [`TestResultRow`]s carrying an `aspect` tag + a numeric `metric` (coverage
//!    %, warning count, advisory count …). A missing tool is a **skip**, never a
//!    hard fail.
//! 3. **Model** ([`model`]) — the pure row/summary types ([`TestResultRow`],
//!    [`RunSummary`], [`TestSelector`], the [`status`] tags) + the renderers
//!    ([`render_matrix`], [`summarize_runs`], [`rows_to_json`]).
//! 4. **Sinks** ([`sink`]) — the [`TestSink`] trait + built-in [`JsonFileSink`]
//!    and [`NullSink`] so a leaf repo with no warehouse can still persist its
//!    matrix. nornir implements `TestSink` over its Iceberg warehouse.
//! 5. **Discovery** ([`discover`]) — the autonom (AUT2) anti-drift core: pure
//!    enumerators that build the testable [`Surface`] from data (facett
//!    components, viz tabs × {thin,fat}, CLI subcommands, MCP tools, and the
//!    unreached-function set from `symbol_facts − test-reachable(call_edges)`),
//!    then [`compute_gap`] differences it against coverage so the gate can
//!    enforce `Gap == ∅`. No warehouse here — the caller feeds the rows.
//! 6. **Functional-status mode** ([`functional`]) — a component reports whether
//!    it *actually works* (`functional_status(component, check, ok, detail)`)
//!    from its own headless-render / self-test path. The
//!    [`Aspect::Functional`] runner drains those into rows so a broken render is
//!    a RED matrix row WITHOUT eyeballing a GUI. Gated behind the **`testmatrix`
//!    cargo feature**: release builds (feature off) strip the emit to a no-op.
//! 7b. **uiplane — UI-PLANE reachability (LAW 9)** ([`uiplane`]) — model a running
//!    app as **planes** ([`UiPlane`]) + a **navigation plan** ([`UiPlan`]: planes
//!    as nodes, transitions as edges), then [`RobotPlan::walk`] a [`PlaneDriver`]
//!    over it to REACH every plane and prove every declared surface is
//!    **present + RAN**. A surface that is unreachable (orphan plane / missing
//!    transition) or reachable-but-didn't-run is a **RED** row. Generic +
//!    UI-agnostic: a headless library has an empty plan (trivially green); the
//!    native robot-UI and the deployed-wasm headless-browser are two backends
//!    behind the same [`PlaneDriver`] seam.
//! 7c. **gatedtests — the silenced-test guard** ([`gatedtests`]) — a
//!    `tests/*.rs` carrying a crate-level `#![cfg(feature = "X")]` where `X` is
//!    not in that crate's `default` set compiles to an **empty test binary** and
//!    reports `0 tests ... ok`. [`audit_gated_tests`] walks every test target of
//!    every workspace member (`cargo metadata`), parses the leading `#![cfg]`
//!    (`all`/`any`/`not`, nested), resolves the crate's transitive `default`
//!    closure, and emits a RED [`TestResultRow`] on the `gated-tests` aspect for
//!    every file that neither compiles by default nor is re-invoked by a matrix
//!    arm the repo DECLARES in `.nornir/testmatrix-arms.json`. Silence is not
//!    success.
//! 8. **utfallsrum — outcome-space coverage** ([`utfallsrum`]) — declare a
//!    function's whole OUTCOME SPACE as equivalence partitions + boundary values
//!    ([`Outcome`]), record which classes a test exercised with the exact output,
//!    and score `utfallsrum_covered ∈ [0,1]` = exercised / declared. A single-value
//!    test scores low even when green; the gate requires ≥K classes swept before a
//!    surface counts as covered. Boundary-value + equivalence-partition analysis,
//!    made first-class and persistable next to the functional verdict.
//!
//! ## How a leaf repo uses it
//! ```no_run
//! use nornir_testmatrix::{run_full_matrix, Aspect, JsonFileSink, TestSink};
//! use std::path::Path;
//!
//! let aspects = [Aspect::Build, Aspect::Unit, Aspect::Doctest, Aspect::Clippy, Aspect::Fmt];
//! let rows = run_full_matrix(Path::new("."), &aspects);
//! let sink = JsonFileSink::new("target/nornir-testmatrix.json");
//! sink.append(&rows).unwrap();
//! ```

pub mod appliance;
pub mod armcheck;
pub mod aspect;
pub mod atom;
pub mod citations;
pub mod coverage;
pub mod discover;
pub mod functional;
pub mod gatedtests;
// The SHARED matrix-harness primitives (`run_cargo` + `cell`) every repo's
// `*_matrix.rs` used to hand-roll byte-identically (holger, korp) — L5.
pub mod harness;
pub mod model;
pub mod runner;
pub mod sink;
pub mod uiplane;
pub mod utfallsrum;

// ─── flat re-exports (the crate's public façade) ───────────────────────────

pub use appliance::{
    APPLIANCE_PRODUCTS, APPLIANCE_PROOFS, ApplianceRollup, ProofVerdict, appliance_product,
};
pub use armcheck::{
    ArmCheck, ArmVerification, arm_args, arm_target_dir, count_listed_tests, test_artifacts,
    verify_arm, verify_arms,
};
pub use aspect::{
    Aspect, AspectOutcome, aspect_label, parse_aspect, parse_funnel_decompose, run_aspect,
    run_full_matrix,
};
pub use atom::{
    AtomFailReason, AtomFailure, AtomObservation, AtomSpec, AtomState, AtomVerdict, atom_surface,
    verify_atoms,
};
pub use citations::{
    ALLOW_FILE, CitationReport, PLACEHOLDER_STEMS, PhantomCitation, audit_citations,
    sibling_checkouts,
};
pub use coverage::{
    AllowEntry, Allowlist, CoverageRow, CoverageSummary, DEFAULT_UTFALLSRUM_THRESHOLD, GateReport,
    SurfaceUtfallsrum, Verdict, covered_with_utfallsrum, rows_for, rows_for_with_utfallsrum,
    seed_allowlist, stale_allowlist_entries,
};
pub use discover::{
    CallEdge, FacetRow, Gap, Mode, SERVED_WORKSPACES, Surface, SurfaceKind, SurfaceNode, SymbolRow,
    cli_commands, compute_gap, facett_components, mcp_tools, test_reachable, unreached_functions,
    viz_tabs, workspace_keys, workspace_surface_key,
};
pub use functional::ASPECT_FUNCTIONAL;
pub use functional::{
    drain_functional_file, drain_functional_rows, functional_row, functional_status, record_rows,
};
pub use gatedtests::{
    ARMS_FILE, ASPECT_GATED_TESTS, CfgExpr, CrateManifest, GateVerdict, GatedTestFile,
    GatedTestReport, MatrixArm, MatrixArms, TestTarget, assert_no_silenced_tests,
    audit_gated_tests, audit_repo, classify, count_test_fns, default_features, extract_crate_cfg,
    feature_closure, parse_cfg_expr, parse_metadata, workspace_crates,
};
pub use harness::{cell, now_micros, run_cargo};
pub use model::{
    RunSummary, TestResultRow, TestSelector, listed_rows, new_run_id, parse_cargo_test_list,
    parse_nextest_list, render_matrix, rows_to_json, short_run, status, summarize_runs,
};
pub use runner::{
    DEFAULT_STALL_SECS, MatrixRun, Runner, TestCase, detect_runner, heavy_enabled, list_tests,
    run_matrix, stall_secs,
};
pub use sink::{JsonFileSink, NullSink, TestSink};
pub use uiplane::{
    MockDriver, PlaneDriver, RobotPlan, RouteStep, SurfaceVerdict, Transition, UIPLANE_ASPECT,
    UiPlan, UiPlane, UiSurface, WalkReport, WalkRow,
};
pub use utfallsrum::{Outcome, OutcomeClass, UTFALLSRUM_ASPECT, UtfallsrumSummary};
