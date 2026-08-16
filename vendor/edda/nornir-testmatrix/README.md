# nornir-testmatrix

The portable core of nornir's **multi-aspect test matrix** — wrap a repo's
native Rust test framework *and* test many aspects of its health (build,
doctest, clippy, fmt, audit, coverage, feature-powerset, msrv, examples),
parse the results into rows, and ship them to any `TestSink`.

Pure `std` + `serde`/`serde_json` + `anyhow`. No iceberg, arrow, eframe,
tantivy, or skade — so any leaf repo can pull it cheaply.

```rust
use nornir_testmatrix::{run_full_matrix, Aspect, JsonFileSink, TestSink};
use std::path::Path;

let aspects = Aspect::DEFAULT; // build, unit, doctest, clippy, fmt, audit
let rows = run_full_matrix(Path::new("."), aspects);
JsonFileSink::new("target/nornir-testmatrix.json").append(&rows).unwrap();
```

A missing tool (clippy/audit/llvm-cov/hack/fmt) is recorded as a neutral
`skip` row — never a hard failure. See `.nornir/testmatrix-crate.md`.

## Functional-status mode (`testmatrix` feature)

A component can report whether it *actually works* — even when the result can't
be eyeballed (a map that renders nothing). Behind the **`testmatrix` cargo
feature** (off for release → zero cost), call from your self-test path:

```rust
nornir_testmatrix::functional_status("facett-map", "basemap_rendered", ok, "0 ways, blank framebuffer");
```

`Aspect::Functional` drains these into `test_results` rows (`ok=false` → a RED
matrix row), so a dead render shows up in `nornir test` / the viz Test pane
**without anyone looking at a GUI**. With the feature off, `functional_status`
is an inlined no-op. See `.nornir/testmatrix-functional-status.md`.

## Silenced-test guard (`gatedtests` module, `Aspect::GatedTests`)

**Silence is not success.** A `tests/*.rs` carrying a crate-level
`#![cfg(feature = "X")]` where `X` is not in that crate's `default` set compiles
to an **empty test binary**: `cargo test` prints `running 0 tests ... ok` and the
file is green by vacuum. A 2026-07-21 sweep found 78 such files across 11 repos,
hiding ~216 test functions — most in the camouflage shape
`all(default-on, default-on, default-OFF)`, which reads exactly like its running
siblings.

```rust
let rep = nornir_testmatrix::audit_repo(std::path::Path::new("."), &nornir_testmatrix::new_run_id())?;
assert!(rep.is_green(), "{}", rep.summary());
// 93 test targets scanned · 21 feature-gated · 0 rescued by declared arms ·
// 15 SILENCED (66 hidden test fns) — RED
```

The guard walks every test target (`cargo metadata`), parses the leading
`#![cfg]` (`all`/`any`/`not`, nested; non-feature predicates evaluate to
*unknown*, never false), resolves each crate's **transitive** `default` closure,
and emits a RED `TestResultRow` on the `gated-tests` aspect per dark file. A file
IS covered when the repo **declares** the arm that re-invokes it, in
`.nornir/testmatrix-arms.json` (holger's `xtask/tests/holger_matrix.rs` pattern):

```json
{ "arms": [ { "package": "holger-ui", "features": ["gui"], "test": "robot_ui_app" },
            { "features": ["testmatrix"] } ] }
```

It is in `Aspect::DEFAULT`, so every repo running the matrix inherits it. See
`.nornir/testmatrix-gated-tests.md`.

## UI-plane reachability — LAW 9 (`uiplane` module)

Isolation tests green *"the component renders"* while the running app can't
**navigate** to it. `uiplane` models the UI as **planes** (`UiPlane`: a tab /
dialog / view) + a **navigation plan** (`UiPlan`: planes as nodes, transitions
as edges) and `RobotPlan::walk(&plan, &mut driver)` walks the REAL app via a
`PlaneDriver` seam — reaching every plane and asserting each declared surface is
**present + RAN** (read from emitted data, not pixels). A surface that is
unreachable (orphan plane / missing transition) or reachable-but-didn't-run is a
**RED** row. Generic + UI-agnostic (a headless library has an empty plan →
trivially green); the native robot-UI and the deployed-wasm headless browser are
two backends behind the same `PlaneDriver`. See `.nornir/testmatrix-uiplane.md`.
