//! **edda's declared rescue arms must actually rescue tests.**
//!
//! This is the five-line adoption any repo copies; the work lives in
//! [`nornir_testmatrix::verify_arms`], so repos reuse it rather than growing a
//! private twin.
//!
//! The gated-tests guard treats a declared arm in `.nornir/testmatrix-arms.json`
//! as proof that a silenced test file IS run somewhere. Until this existed,
//! nothing checked that proof: `MatrixArm::command()` renders a display string,
//! and that string was the entire extent of an arm's existence. Forty arms across
//! eleven repos were hand-verified once — korp's arms file still says
//! `Verified 2026-07-22` — and a hand-verification does not survive a feature
//! rename.
//!
//! COST, stated honestly: this compiles each arm (`cargo test --no-run`) into
//! `target/armcheck` (override with `NORNIR_ARM_TARGET_DIR`). It is the slowest
//! test in this crate, and it is the only one that can tell you an arm is real.

use std::path::{Path, PathBuf};

use nornir_testmatrix::{MatrixArms, verify_arms};

/// crates/nornir-testmatrix/ -> the edda repo root.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate sits two levels below the repo root")
        .to_path_buf()
}

#[test]
fn every_declared_rescue_arm_compiles_and_rescues_tests() {
    let root = repo_root();
    let arms = MatrixArms::load(&root).expect("read .nornir/testmatrix-arms.json");

    // An empty arm set makes `all_ok()` vacuously true. edda declares two, and if
    // that ever becomes zero it must be because someone deleted them, not because
    // the file failed to parse into nothing.
    assert!(
        !arms.arms.is_empty(),
        "edda declares rescue arms in .nornir/testmatrix-arms.json and this read none — \
         a guard asserting on an empty set proves nothing"
    );

    let v = verify_arms(&root, &arms);
    assert_eq!(
        v.declared(),
        arms.arms.len(),
        "every declared arm must be examined"
    );
    assert!(v.all_ok(), "{}", v.summary());

    // Not just "no problems" — the arms must have rescued something. An arm whose
    // binary lists zero tests is already a `problem`, but asserting the total here
    // means a future refactor that silently stops counting cannot pass.
    let rescued: usize = v.checks.iter().map(|c| c.tests_listed).sum();
    assert!(
        rescued > 0,
        "the arms compiled but rescued 0 tests in total — that is the silence they \
         exist to break.\n{}",
        v.summary()
    );
}
