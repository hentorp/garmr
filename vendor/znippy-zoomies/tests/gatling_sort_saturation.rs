//! RED-when-broken **core-saturation** guard for [`gatling_sort`].
//!
//! Correctness (matches std, stability, edges) is unit-tested inside the gatling
//! crate. THIS test defends the *performance contract* the whole primitive
//! exists for: on a multi-core box the parallel merge sort must keep well more
//! than one core busy. It sorts a large input while measuring CPU-time/wall-time
//! (cores_busy) via `getrusage`; a regression that drops the sort back onto a
//! single core collapses cores_busy to ~1.0 and turns this test RED.
//!
//! Skipped on <4-core boxes (no saturation to assert) and off Linux (no
//! `getrusage` here), where it degrades to a plain correctness check.

use std::time::Instant;

use rand::{RngCore, SeedableRng, rngs::StdRng};
use znippy_zoomies::gatling_sort::{gatling_sort_by, gatling_sort_unstable_by};

#[cfg(target_os = "linux")]
fn cpu_secs() -> f64 {
    // SAFETY: `getrusage` fills a caller-owned, zero-initialized `rusage`.
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut ru);
        let u = ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 * 1e-6;
        let s = ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 * 1e-6;
        u + s
    }
}
#[cfg(not(target_os = "linux"))]
fn cpu_secs() -> f64 {
    f64::NAN
}

fn cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[test]
fn large_unstable_sort_saturates_cores() {
    let nc = cores();
    // 4M i64 (~32 MB) — large enough to dwarf pool spin-up even in a debug test,
    // small enough to stay quick. Sorted result is verified regardless of cores.
    let n = 4_000_000usize;
    let mut rng = StdRng::seed_from_u64(0x5A17_0000);
    let base: Vec<i64> = (0..n).map(|_| rng.next_u64() as i64).collect();

    let mut want = base.clone();
    want.sort_unstable();

    let mut got = base.clone();
    let cpu0 = cpu_secs();
    let t0 = Instant::now();
    gatling_sort_unstable_by(&mut got, |a, b| a.cmp(b));
    let wall = t0.elapsed().as_secs_f64();
    let cpu = cpu_secs() - cpu0;

    assert_eq!(got, want, "parallel sort produced the wrong result");

    let cores_busy = if wall > 0.0 && cpu.is_finite() {
        cpu / wall
    } else {
        f64::NAN
    };
    eprintln!(
        "gatling_sort saturation: n={n} cores={nc} wall={wall:.3}s cpu={cpu:.3}s cores_busy={cores_busy:.2}"
    );

    if nc >= 4 && cores_busy.is_finite() {
        // Conservative floor (0.30·cores, ≥2.0): a real parallel sort clears it
        // comfortably; a serial regression (cores_busy ≈ 1.0) can never.
        let floor = (nc as f64 * 0.30).max(2.0);
        assert!(
            cores_busy >= floor,
            "cores_busy {cores_busy:.2} < floor {floor:.2}: the sort is not saturating \
             a {nc}-core box (serial regression?)"
        );
    } else {
        eprintln!("saturation floor skipped (cores={nc}, cores_busy={cores_busy:.2})");
    }
}

/// The stable variant must ALSO stay parallel (its per-run `sort_by` + merge is
/// the same fork-join), so guard its saturation too — and re-confirm it is
/// byte-identical to `slice::sort_by` on a large, tie-heavy input.
#[test]
fn large_stable_sort_saturates_and_matches_std() {
    let nc = cores();
    let n = 4_000_000usize;
    let mut rng = StdRng::seed_from_u64(0x57AB_1E00);
    // Tie-heavy keys (mod 4096) so stability is genuinely exercised at scale.
    let base: Vec<(u32, u32)> = (0..n)
        .map(|i| ((rng.next_u64() % 4096) as u32, i as u32))
        .collect();

    let mut want = base.clone();
    want.sort_by(|a, b| a.0.cmp(&b.0));

    let mut got = base.clone();
    let cpu0 = cpu_secs();
    let t0 = Instant::now();
    gatling_sort_by(&mut got, |a, b| a.0.cmp(&b.0));
    let wall = t0.elapsed().as_secs_f64();
    let cpu = cpu_secs() - cpu0;

    assert_eq!(got, want, "stable parallel sort != slice::sort_by at scale");

    let cores_busy = if wall > 0.0 && cpu.is_finite() {
        cpu / wall
    } else {
        f64::NAN
    };
    eprintln!("gatling_sort_by saturation: n={n} cores={nc} cores_busy={cores_busy:.2}");
    if nc >= 4 && cores_busy.is_finite() {
        let floor = (nc as f64 * 0.30).max(2.0);
        assert!(
            cores_busy >= floor,
            "stable sort cores_busy {cores_busy:.2} < floor {floor:.2}"
        );
    }
}
