//! Custom bench harness for the generic [`gatling_sort`] parallel merge sort.
//!
//! Criterion measures wall time only; the load-bearing number for a parallel
//! sort is **cores_busy** = CPU-time / wall-time (how many cores it actually
//! kept saturated), which needs `getrusage`. So this is a `harness = false`
//! binary (like `examples/nornir-bench`): it times `gatling_sort_unstable` vs
//! the serial `slice::sort_unstable` at several sizes (ints AND a struct with a
//! composite comparator), printing throughput (Melem/s), the parallel speedup,
//! and cores_busy. It asserts a cores_busy floor at the largest size, so a
//! regression that silently drops the sort back onto one core turns this bench
//! RED instead of merely slower.
//!
//! Env knobs:
//!   * `GSORT_SIZES` — comma-separated element counts (default `1000000,8000000`).
//!   * `GSORT_ITERS` — timed iterations per case, min-of-N (default 3).

use std::time::Instant;

use rand::{RngCore, SeedableRng, rngs::StdRng};
use znippy_zoomies::gatling_sort::gatling_sort_unstable_by;

/// Process CPU time (user + system, all threads) in seconds — the numerator of
/// cores_busy. Linux-only via `getrusage`; elsewhere NaN so the floor is skipped.
#[cfg(target_os = "linux")]
fn cpu_secs() -> f64 {
    // SAFETY: `getrusage` fills a caller-owned `rusage`; zeroed init is valid.
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

fn sizes() -> Vec<usize> {
    std::env::var("GSORT_SIZES")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|x| x.trim().parse().ok())
                .collect::<Vec<_>>()
        })
        .filter(|v: &Vec<usize>| !v.is_empty())
        .unwrap_or_else(|| vec![1_000_000, 8_000_000])
}

fn iters() -> usize {
    std::env::var("GSORT_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3)
        .max(1)
}

/// Min-of-N timing of `sort(&mut buf)`. Re-clones `base` each iter (sort is
/// in-place) OUTSIDE the timed region. Returns `(best_wall_s, cores_busy)`.
fn time_sort<T, S, C>(base: &[T], iters: usize, is_sorted: C, mut sort: S) -> (f64, f64)
where
    T: Clone,
    S: FnMut(&mut [T]),
    C: Fn(&[T]) -> bool,
{
    let mut best = f64::INFINITY;
    let mut best_busy = 0.0;
    for _ in 0..iters {
        let mut buf = base.to_vec();
        let cpu0 = cpu_secs();
        let t0 = Instant::now();
        sort(&mut buf);
        let wall = t0.elapsed().as_secs_f64();
        let cpu = cpu_secs() - cpu0;
        assert!(is_sorted(&buf), "sort produced unsorted output");
        if wall < best {
            best = wall;
            best_busy = if wall > 0.0 && cpu.is_finite() {
                cpu / wall
            } else {
                f64::NAN
            };
        }
    }
    (best, best_busy)
}

#[derive(Clone)]
struct Item {
    weight: i32,
    name: u32,
}

fn main() {
    let nc = cores();
    let it = iters();
    let szs = sizes();
    println!("gatling_sort bench — {nc} cores, {it} iters/case (min-of-N)");
    println!(
        "{:>14}  {:>10}  {:>10}  {:>8}  {:>11}  {:>10}",
        "case/n", "std M/s", "gat M/s", "speedup", "cores_busy", "gat s"
    );

    let mut last_busy = f64::NAN;
    for &n in &szs {
        // ── i64 ints ─────────────────────────────────────────────────────────
        let mut rng = StdRng::seed_from_u64(0xB0BA_CAFE ^ n as u64);
        let base: Vec<i64> = (0..n).map(|_| rng.next_u64() as i64).collect();
        let sorted = |b: &[i64]| b.windows(2).all(|w| w[0] <= w[1]);
        let (std_wall, _) = time_sort(&base, it, sorted, |b| b.sort_unstable());
        let (gat_wall, busy) = time_sort(&base, it, sorted, |b| {
            gatling_sort_unstable_by(b, |a, c| a.cmp(c))
        });
        println!(
            "{:>14}  {:>10.1}  {:>10.1}  {:>7.2}x  {:>11.2}  {:>10.3}",
            format!("i64/{n}"),
            n as f64 / std_wall / 1e6,
            n as f64 / gat_wall / 1e6,
            std_wall / gat_wall,
            busy,
            gat_wall
        );
        last_busy = busy;
    }

    // ── struct with a composite comparator (weight desc, then name asc) ───────
    // One representative size so the generic (non-int) path is measured too.
    {
        let n = *szs.iter().max().unwrap();
        let mut rng = StdRng::seed_from_u64(0x57AB_C0DE ^ n as u64);
        let base: Vec<Item> = (0..n)
            .map(|_| Item {
                weight: (rng.next_u64() % 100_000) as i32,
                name: (rng.next_u64() % 1_000_000) as u32,
            })
            .collect();
        let cmp = |a: &Item, b: &Item| b.weight.cmp(&a.weight).then_with(|| a.name.cmp(&b.name));
        let sorted = |b: &[Item]| {
            b.windows(2)
                .all(|w| cmp(&w[0], &w[1]) != std::cmp::Ordering::Greater)
        };
        let (std_wall, _) = time_sort(&base, it, sorted, |b| b.sort_unstable_by(cmp));
        let (gat_wall, busy) = time_sort(&base, it, sorted, |b| gatling_sort_unstable_by(b, cmp));
        println!(
            "{:>14}  {:>10.1}  {:>10.1}  {:>7.2}x  {:>11.2}  {:>10.3}",
            format!("struct/{n}"),
            n as f64 / std_wall / 1e6,
            n as f64 / gat_wall / 1e6,
            std_wall / gat_wall,
            busy,
            gat_wall
        );
    }

    // ── cores_busy floor (RED on a serial regression) ────────────────────────
    // On a multi-core box the parallel sort must keep well more than one core
    // busy; a regression to a serial (or single-run) sort collapses cores_busy
    // to ~1.0 and trips this. Conservative floor so it holds across machines and
    // in debug builds, but a serial regression can never clear it.
    if nc >= 4 && last_busy.is_finite() {
        let floor = (nc as f64 * 0.30).max(2.0);
        assert!(
            last_busy >= floor,
            "cores_busy floor breached: {last_busy:.2} < {floor:.2} \
             (sort fell back to too few cores on a {nc}-core box)"
        );
        println!("cores_busy floor OK: {last_busy:.2} >= {floor:.2} ({nc} cores)");
    } else {
        println!("cores_busy floor skipped (cores={nc}, busy={last_busy:.2})");
    }
}
