//! Test-matrix self-emitters for the `vann` vector-ANN engine (the newest
//! engine in the tree). vann already carries a thorough in-crate `#[cfg(test)]`
//! suite; this integration file adds the missing piece: it turns vann's
//! correctness LAWS into nornir `functional_status` rows so `cargo test
//! --features testmatrix` (and the nornir Architecture tab that reads the rows)
//! SEE the exact-search guarantees, matching the wiring already present on the
//! gatling engine + the codec CLIs.
//!
//! EMIT-DOCTRINE (korp-collectors reference): every `assert_emit!` is a REAL
//! return-value assertion FIRST — the `assert!` is the test's gate — and the
//! emit is the matrix observation. Uses ONLY vann's public API. A plain `cargo
//! test` still runs every assertion; the emit is a stripped `#[inline]` no-op
//! unless the `testmatrix` feature is on (znippy_zoomies::functional_status is a
//! compiled-out no-op by default, pulling no nornir dep). Additive: this file
//! touches no existing code.

use znippy_zoomies::functional_status;
use znippy_zoomies::vann::{I8_SCAN_THRESHOLD, VectorIndex, active_simd, bench_kernels};

/// `assert!`-with-emit under the `vann::search` component: assert on the real
/// value AND record the verdict as a matrix row (the korp `assert_emit!` shape,
/// specialised to this crate's public `functional_status`).
macro_rules! assert_emit {
    ($check:expr, $ok:expr, $($detail:tt)+) => {{
        let __ok: bool = $ok;
        let __detail = format!($($detail)+);
        functional_status("vann::search", $check, __ok, &__detail);
        assert!(__ok, "vann::search::{} — {}", $check, __detail);
    }};
}

/// Deterministic dim-dimensional direction from a scalar seed (same generator
/// the in-crate suite uses).
fn mk(dim: usize, seed: f32) -> Vec<f32> {
    (0..dim).map(|i| ((i as f32 + 1.0) * seed).sin()).collect()
}

fn build(dim: usize, n: u64, seed0: f32, step: f32, id: impl Fn(u64) -> u64) -> VectorIndex {
    let mut idx = VectorIndex::new(dim).unwrap();
    let mut flat = Vec::with_capacity(n as usize * dim);
    let mut ids = Vec::with_capacity(n as usize);
    for r in 0..n {
        flat.extend(mk(dim, seed0 + r as f32 * step));
        ids.push(id(r));
    }
    idx.add(&flat, &ids).unwrap();
    idx
}

/// LAW — the wired int8 path (`search_i8_rerank`, what `search_auto` dispatches
/// to for large corpora) is IDENTICAL to the exact f32 `search`: same ids, same
/// order, same score bits. Quant can never silently change live results.
#[test]
fn matrix_i8_rerank_is_exact() {
    let dim = 768;
    let n = 500u64;
    let idx = build(dim, n, 0.003, 0.00051, |r| r * 7 + 1);

    let mut identical = true;
    for &qs in &[0.003 + 17.0 * 0.00051, 0.05, 0.731, 0.003 + 480.0 * 0.00051] {
        let query = mk(dim, qs);
        for k in [1usize, 5, 20, 50] {
            let exact = idx.search(&query, k);
            let wired = idx.search_i8_rerank(&query, k);
            identical &= exact.len() == wired.len()
                && exact
                    .iter()
                    .zip(&wired)
                    .all(|(a, b)| a.0 == b.0 && a.1.to_bits() == b.1.to_bits());
        }
    }
    assert_emit!(
        "i8_rerank_identical_to_exact_f32",
        identical,
        "n={n} dim={dim} queries=4 k∈[1,5,20,50]: id+score-bit identical to f32 oracle"
    );
}

/// LAW — `search_auto` is a SIZE selector only: below `I8_SCAN_THRESHOLD` it is
/// `search`; at/above it it is the int8-rerank path. BOTH branches equal the
/// exact f32 oracle.
#[test]
fn matrix_search_auto_stays_exact_across_the_threshold() {
    let dim = 64;

    let small = build(dim, 128, 0.01, 0.002, |r| r);
    assert!(
        small.len() < I8_SCAN_THRESHOLD,
        "small corpus must be below threshold"
    );
    let qs = mk(dim, 0.37);
    let small_exact = small.search_auto(&qs, 5) == small.search(&qs, 5);

    let big = build(dim, I8_SCAN_THRESHOLD as u64 + 37, 0.001, 0.00013, |r| r);
    assert!(
        big.len() >= I8_SCAN_THRESHOLD,
        "big corpus must cross threshold"
    );
    let qb = mk(dim, 0.912);
    let big_exact = big.search_auto(&qb, 10) == big.search(&qb, 10);

    assert_emit!(
        "search_auto_exact_both_branches",
        small_exact && big_exact,
        "f32-branch(n={}) & int8-rerank-branch(n={}) both == exact search",
        small.len(),
        big.len()
    );
}

/// LAW — batched multi-query `search_batch` is byte-identical to running
/// `search` once per query (the amortized single corpus read changes no result).
#[test]
fn matrix_search_batch_equals_per_query() {
    let dim = 64;
    let n = 3072u64; // multicore batch path
    let idx = build(dim, n, 0.002, 0.00017, |r| r * 3 + 5);

    let seeds = [
        0.002 + 42.0 * 0.00017,
        0.19,
        0.55,
        0.913,
        0.002 + 3000.0 * 0.00017,
    ];
    let mut batch = Vec::with_capacity(seeds.len() * dim);
    for &s in &seeds {
        batch.extend(mk(dim, s));
    }

    let mut identical = true;
    for k in [1usize, 5, 20] {
        let batched = idx.search_batch(&batch, k);
        identical &= batched.len() == seeds.len();
        for (qi, &s) in seeds.iter().enumerate() {
            let solo = idx.search(&mk(dim, s), k);
            identical &= batched[qi].len() == solo.len()
                && batched[qi]
                    .iter()
                    .zip(&solo)
                    .all(|(a, b)| a.0 == b.0 && a.1.to_bits() == b.1.to_bits());
        }
    }
    assert_emit!(
        "search_batch_identical_to_per_query",
        identical,
        "n={n} dim={dim} queries={} k∈[1,5,20]: batch == per-query oracle bit-for-bit",
        seeds.len()
    );
}

/// LAW — the runtime SIMD/int8 kernels agree with the scalar reference: the
/// bench harness doubles as a correctness gate (SIMD within f32 rounding, int8
/// within quantization tolerance). No timing numbers are recorded — verdict only.
#[test]
fn matrix_kernels_agree_with_scalar_reference() {
    let rep = bench_kernels(2000, 768, 3);
    let has_all = rep.timings.iter().any(|t| t.name == "scalar")
        && rep.timings.iter().any(|t| t.name.starts_with("simd"))
        && rep.timings.iter().any(|t| t.name.starts_with("int8"));
    let simd_ok = rep
        .timings
        .iter()
        .find(|t| t.name.starts_with("simd"))
        .is_some_and(|t| t.max_err < 1e-4);
    let i8_ok = rep
        .timings
        .iter()
        .find(|t| t.name.starts_with("int8"))
        .is_some_and(|t| t.max_err < 4e-2);
    assert_emit!(
        "kernels_agree_with_scalar",
        has_all && simd_ok && i8_ok,
        "active={} scalar+simd+int8 present; simd_err<1e-4 & int8_err<4e-2",
        active_simd()
    );
}
