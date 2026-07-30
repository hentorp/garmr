//! Shared test-matrix emit helper (in `tests/common/` so it is NOT compiled as
//! its own integration-test binary). A real check in a sibling test file calls
//! [`emit`] / [`emit_for`] with a stable `check_id` + verdict; with
//! `--features testmatrix` that becomes a real
//! `nornir_testmatrix::functional_status` row (the nornir test-matrix reads them
//! back), and without the feature it is a compiled-out no-op (no nornir dep in
//! the default build). Mirrors the korp-collectors reference pattern.

#![allow(dead_code)]

/// Emit one functional-status row for component `skade`. No-op unless built
/// `--features testmatrix`.
pub fn emit(check_id: &str, passed: bool, detail: &str) {
    emit_for("skade", check_id, passed, detail);
}

/// Emit under a per-surface component name (e.g. `"skade/lineage"`). No-op
/// unless built `--features testmatrix`.
pub fn emit_for(component: &str, check_id: &str, passed: bool, detail: &str) {
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(component, check_id, passed, detail);
    #[cfg(not(feature = "testmatrix"))]
    {
        let _ = (component, check_id, passed, detail);
    }
}
