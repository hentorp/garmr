//! **The silenced-test guard, proved against real fixture repos.**
//!
//! Three standalone fixture crates under `tests/fixtures/` stand in for the
//! three cases the guard must separate. Each is driven through the REAL
//! [`audit_repo`] path — `cargo metadata` on the fixture, the fixture's own
//! `Cargo.toml` feature table, the fixture's own `.nornir/testmatrix-arms.json`:
//!
//! | fixture | shape | expected |
//! |---|---|---|
//! | `gated_dark` | `#![cfg(all(feature="light", feature="heavy"))]`, `heavy` NOT in `default` | **REPORTED** (RED), 3 hidden tests; its default-ON sibling is not |
//! | `gated_default_on` | gates satisfied through a transitive `default` chain + a platform-only gate | **NOT reported** (GREEN) |
//! | `gated_rescued` | same dark gate as `gated_dark`, plus a declared matrix arm | **NOT reported** (GREEN, `Rescued`) |
//!
//! RED-when-broken: with the classifier's dark branch stubbed to
//! `GateVerdict::Default` (i.e. the guard not shipped), `gated_dark` reports
//! GREEN and the first assertion here fails. With the arm-matching branch
//! removed, `gated_rescued` reports RED and the third fails. The three cases
//! pin each other.
//!
//! Deliberately NOT feature-gated — a guard against silenced tests that is
//! itself silenced would be the joke that writes itself.

use std::path::{Path, PathBuf};

use nornir_testmatrix::{ASPECT_GATED_TESTS, GateVerdict, audit_repo, status};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// `cargo metadata` on a fixture writes a `Cargo.lock` beside it; the fixtures
/// have zero dependencies so this is offline and instant.
fn audit(name: &str) -> nornir_testmatrix::GatedTestReport {
    let dir = fixture(name);
    assert!(
        dir.join("Cargo.toml").exists(),
        "fixture {name} exists at {}",
        dir.display()
    );
    audit_repo(&dir, "guard-run").unwrap_or_else(|e| panic!("audit {name}: {e:#}"))
}

#[test]
fn a_default_off_gated_test_file_is_reported_red_with_its_hidden_count() {
    let rep = audit("gated_dark");

    assert!(
        !rep.is_green(),
        "the dark fixture must FAIL the gate — {}",
        rep.summary()
    );

    let silenced = rep.silenced();
    assert_eq!(
        silenced.len(),
        1,
        "exactly one silenced file (got {:?}) — {}",
        silenced.iter().map(|f| &f.path).collect::<Vec<_>>(),
        rep.summary()
    );
    let f = silenced[0];
    assert_eq!(f.target, "dark_gate");
    assert_eq!(f.crate_name, "gated_dark");
    assert!(
        f.path.ends_with("tests/dark_gate.rs"),
        "path is repo-relative: {}",
        f.path
    );
    assert_eq!(f.hidden_tests, 3, "all three #[test] fns are hidden");
    assert_eq!(
        f.missing_features,
        vec!["heavy".to_string()],
        "only the dark conjunct is named, not its default-on siblings"
    );
    assert_eq!(rep.hidden_tests(), 3);
    assert!(
        f.message().contains("ZERO tests"),
        "message: {}",
        f.message()
    );
    assert!(
        f.message().contains("heavy"),
        "message names the dark feature"
    );

    // Sibling asymmetry: the default-ON gate next to it is classified, not
    // reported. This is the camouflage the audit called out.
    let lit = rep
        .files
        .iter()
        .find(|f| f.target == "lit_gate")
        .expect("the default-on sibling is classified");
    assert_eq!(lit.verdict, GateVerdict::Default);
    assert!(!lit.is_silenced());

    // The ungated file is not a finding at all.
    assert!(
        rep.files.iter().all(|f| f.target != "plain"),
        "ungated files are not listed: {:?}",
        rep.files.iter().map(|f| &f.target).collect::<Vec<_>>()
    );
    assert_eq!(rep.scanned, 3, "all three test targets were inspected");

    // The finding is a structured, persistable row — not a println.
    let rows = rep.rows();
    let dark = rows
        .iter()
        .find(|r| r.test_name == "gated-tests::dark_gate")
        .expect("a row per gated file");
    assert_eq!(dark.aspect, ASPECT_GATED_TESTS);
    assert_eq!(dark.status, status::FAIL);
    assert!(
        status::is_red(&dark.status),
        "the row is RED, so it can fail a gate"
    );
    assert_eq!(dark.metric, 3.0, "metric carries the hidden-test count");
    assert_eq!(dark.repo, "gated_dark");
    assert_eq!(dark.suite, "gated_dark");
    assert_eq!(dark.run_id, "guard-run");
    let lit_row = rows
        .iter()
        .find(|r| r.test_name == "gated-tests::lit_gate")
        .unwrap();
    assert_eq!(lit_row.status, status::PASS);
}

#[test]
fn a_default_on_gate_is_never_reported() {
    let rep = audit("gated_default_on");
    assert!(
        rep.is_green(),
        "a repo whose gates are all default-reachable is GREEN — {} · silenced={:?}",
        rep.summary(),
        rep.silenced().iter().map(|f| &f.path).collect::<Vec<_>>()
    );
    assert_eq!(rep.hidden_tests(), 0);

    // The transitive chain `default → bundle → light` must resolve.
    let t = rep
        .files
        .iter()
        .find(|f| f.target == "transitive_gate")
        .expect("the transitively-default gate is classified");
    assert_eq!(t.verdict, GateVerdict::Default);

    // A platform-only gate mentions no feature → not this guard's business.
    assert!(
        rep.files.iter().all(|f| f.target != "platform_gate"),
        "non-feature gates are not listed"
    );
}

#[test]
fn a_gate_rescued_by_a_declared_arm_is_not_reported() {
    let rep = audit("gated_rescued");
    assert!(
        rep.is_green(),
        "a declared matrix arm covers the file — {} · silenced={:?}",
        rep.summary(),
        rep.silenced().iter().map(|f| &f.path).collect::<Vec<_>>()
    );
    assert_eq!(rep.arms.len(), 2, "the repo's declaration file was read");

    let r = rep
        .files
        .iter()
        .find(|f| f.target == "rescued_gate")
        .expect("classified");
    assert_eq!(r.verdict, GateVerdict::Rescued);
    assert_eq!(
        r.rescued_by.as_deref(),
        Some("cargo test -p gated_rescued --features heavy --test rescued_gate"),
        "the report names the exact command that rescues it"
    );
    assert!(
        r.message().contains("rescued by"),
        "message: {}",
        r.message()
    );

    // The workspace-wide arm's feature closure (`bundle → heavy`) rescues the
    // second file — arm features are resolved transitively, not compared literally.
    let t = rep
        .files
        .iter()
        .find(|f| f.target == "transitively_rescued_gate")
        .expect("classified");
    assert_eq!(t.verdict, GateVerdict::Rescued);
    assert_eq!(
        t.rescued_by.as_deref(),
        Some("cargo test --features bundle")
    );

    // Rescued files still emit rows — the excuse is visible, never silent.
    let rows = rep.rows();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| r.status == status::PASS && r.aspect == ASPECT_GATED_TESTS)
    );
}

/// Run `assert_no_silenced_tests` and return its panic message, or `None` if it
/// passed. The hook is silenced so a *deliberate* failure does not print a
/// backtrace into the middle of a green run.
fn panic_message_of(dir: &Path) -> Option<String> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let dir = dir.to_path_buf();
    let r = std::panic::catch_unwind(move || {
        nornir_testmatrix::assert_no_silenced_tests(&dir);
    });
    std::panic::set_hook(prev);
    match r {
        Ok(()) => None,
        Err(e) => Some(
            e.downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "<non-string panic>".to_string()),
        ),
    }
}

/// **The four-line adoption must actually be able to fail.**
///
/// `assert_no_silenced_tests` is the call every repo in the fleet is being asked
/// to add, so it is exactly the place a hollow guard would do the most damage: one
/// blind helper would make twenty repos report green at once. Its three exits are
/// pinned here against real fixtures.
#[test]
fn the_four_line_adoption_goes_red_on_a_dark_repo() {
    let msg = panic_message_of(&fixture("gated_dark"))
        .expect("the dark fixture MUST panic — a helper that cannot fail is the disease");
    assert!(msg.contains("SILENCED TESTS"), "message: {msg}");
    assert!(
        msg.contains("dark_gate"),
        "the message names the file: {msg}"
    );
    assert!(
        msg.contains("heavy"),
        "the message names the dark feature: {msg}"
    );
    assert!(
        msg.contains("testmatrix-arms.json"),
        "the message says how to fix it: {msg}"
    );
    // Sibling asymmetry survives into the message: the default-ON file next to it
    // is not reported as a problem.
    assert!(
        !msg.contains("lit_gate"),
        "only the dark file is listed, not its running sibling: {msg}"
    );
}

/// A repo whose gates are all default-reachable, and one whose dark gate is
/// covered by a declared arm, both pass. Without this the helper could "work" by
/// always panicking.
#[test]
fn the_four_line_adoption_passes_a_clean_repo_and_a_rescued_one() {
    assert_eq!(panic_message_of(&fixture("gated_default_on")), None);
    assert_eq!(panic_message_of(&fixture("gated_rescued")), None);
}

/// **The vacuous green.** A root that resolves but has no test targets reports
/// "0 silenced" because it inspected nothing — the same shape as a stale path or a
/// degraded `cargo metadata`. LAW 2: check output, not exit code.
#[test]
fn a_repo_with_no_test_targets_at_all_is_a_red_not_a_pass() {
    let dir = fixture("no_test_targets");
    // Precondition, stated rather than assumed: the fixture really has none.
    assert!(
        !dir.join("tests").exists(),
        "the fixture must have no tests/ dir"
    );
    let rep = audit_repo(&dir, "vacuity").expect("the audit itself succeeds");
    assert_eq!(rep.scanned, 0, "…scanning nothing…");
    assert!(rep.is_green(), "…and reporting green, which is the trap");

    let msg = panic_message_of(&dir)
        .expect("scanning ZERO targets must panic — otherwise the guard proves nothing");
    assert!(msg.contains("ZERO test targets"), "message: {msg}");
}

/// A path that is not a cargo workspace at all is a RED, never a skip: an audit
/// that could not run has not cleared anything.
#[test]
fn an_unresolvable_root_is_a_red_not_a_skip() {
    let msg = panic_message_of(&fixture("this_fixture_does_not_exist"))
        .expect("a root `cargo metadata` cannot read must panic");
    assert!(
        msg.contains("could not run") && msg.contains("RED, not a skip"),
        "message: {msg}"
    );
}

#[test]
fn the_declaration_file_is_optional_and_a_missing_one_is_not_an_error() {
    // `gated_dark` declares nothing; the audit still runs and simply rescues
    // nothing.
    let rep = audit("gated_dark");
    assert!(rep.arms.is_empty());
    assert!(
        !Path::new(&fixture("gated_dark"))
            .join(nornir_testmatrix::ARMS_FILE)
            .exists()
    );
}
