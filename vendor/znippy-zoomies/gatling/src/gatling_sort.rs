//! Gatling **parallel sort** — the sort primitive the constellation was missing.
//!
//! Rule zero (`.nornir/design.md`, memory ROOT LAW #0): every parallel hot path
//! in the constellation fans out through the ONE sanctioned engine — the leaf
//! `gatling` crate — never rayon, never a hand-rolled `thread::spawn` /
//! `thread::scope` pool. That left a hole: `gatling` had a parallel *map*
//! ([`gatling_for_each`](crate::gatling_forkjoin::gatling_for_each)), *reduce*
//! ([`gatling_reduce`](crate::gatling_forkjoin::gatling_reduce)) and *raster*
//! ([`gatling_scanlines`](crate::gatling_forkjoin::gatling_scanlines)) but **no
//! parallel sort**. So sort-bound hot paths across the tree (nornir
//! `RagnarLog::build`, …) were stuck on a single core: saturating them would
//! have meant a private pool, which the law forbids. This module closes the hole
//! by adding the primitive *to the law's own library*.
//!
//! # What it is
//! A generic comparison sort whose signatures mirror `slice::sort_by` /
//! `slice::sort_unstable_by`, so a caller swaps `v.sort_unstable_by(cmp)` for
//! [`gatling_sort_unstable_by(v, cmp)`](gatling_sort_unstable_by) with no other
//! change (the comparator must be `Fn + Sync` — it is shared across workers).
//!
//! - [`gatling_sort`] / [`gatling_sort_unstable`] — convenience for `T: Ord`.
//! - [`gatling_sort_by`] — **stable**: output is byte-identical to
//!   `slice::sort_by`, equal elements keep their input order.
//! - [`gatling_sort_unstable_by`] — faster per-run sort, equal-element order
//!   unspecified (like `slice::sort_unstable_by`); output is a correct total
//!   order and an exact permutation of the input.
//!
//! # Algorithm — parallel merge sort, built ON the gatling fork-join
//! All internal parallelism routes through
//! [`gatling_run`](crate::gatling_forkjoin::gatling_run) — the no-barrier,
//! self-dispatching fork-join pool. There is **no** `thread::scope` / `spawn` /
//! rayon in this file; the sort is a *consumer* of the engine, exactly as the
//! law wants (grep this diff: the only pool is `gatling_run`).
//!
//! 1. **Serial floor.** `len < PARALLEL_THRESHOLD` (or a 1-core box) ⇒ plain
//!    `slice::sort[_unstable]_by`; the fork-join teardown would dominate a small
//!    input, so we never make it slower than std below the floor.
//! 2. **Parallel run sort.** Split the slice into a power-of-two run count ≥
//!    cores and sort each **in place** on the pool (`gatling_run` over the runs).
//!    This is the O(n·log(n/runs)) comparison bulk, fully parallel, and — being
//!    in place — leaves the slice valid even if a comparator unwinds here.
//! 3. **Parallel merge.** Merge the sorted runs pairwise up a tree, ping-ponging
//!    between the slice and one scratch buffer. Each pairwise merge is itself
//!    **cut into `~8·cores` segments by a merge-path (co-rank) binary search**,
//!    and every segment across every pair in a round is flattened into ONE
//!    `gatling_run` — so even the final, single-pair round keeps all cores busy
//!    (a naive tree would run the last merge on one core). A power-of-two run
//!    count means `log2(runs)` rounds, EVEN, with no odd leftover-copy — the
//!    result lands back in `v` with no extra copy-back pass. The merge takes the
//!    left run on ties, which is what makes the stable variant stable.
//!
//! Correctness is pinned to `std`: the stable variant equals `slice::sort_by`
//! byte-for-byte; both variants sort every edge shape (empty / 1 / sorted /
//! reverse / all-equal). See the unit tests at the bottom.
//!
//! # Safety note
//! The merge moves elements between the slice and the scratch buffer bitwise
//! (`ptr::copy_nonoverlapping`), so mid-merge the two buffers jointly own each
//! `T` exactly once. This is sound for a well-behaved comparator (a total order
//! that does not panic — the documented contract). Should a comparator panic
//! *during the merge*, leaving the two buffers in a partially-moved state would
//! risk a double-drop, so a bomb guard converts such a panic into an abort. The
//! per-run sort in step 2 is in place and needs no such guard.

use std::cmp::Ordering;
use std::mem::MaybeUninit;

use crate::gatling_forkjoin::{default_workers, gatling_run};

/// Below this length the sort runs serially (`slice::sort[_unstable]_by`): the
/// fork-join spin-up/merge scaffolding costs more than it saves on a small
/// input, so the parallel path must never make a small sort slower than std.
pub const PARALLEL_THRESHOLD: usize = 8 * 1024;

/// Minimum records per run — keeps each parallel run big enough that a per-run
/// `sort` amortizes the pool hand-off (and bounds the run count on small input).
const MIN_RUN: usize = 2 * 1024;

/// Parallel **stable** sort by a comparator — the drop-in for `slice::sort_by`.
///
/// Output is byte-identical to `slice::sort_by(cmp)`: total order, and equal
/// elements retain their original relative order. `compare` is shared across
/// workers, so it is `Fn + Sync` (a plain closure or fn pointer).
pub fn gatling_sort_by<T, F>(v: &mut [T], compare: F)
where
    T: Send,
    F: Fn(&T, &T) -> Ordering + Sync,
{
    parallel_sort(v, compare, true);
}

/// Parallel **unstable** sort by a comparator — the drop-in for
/// `slice::sort_unstable_by`.
///
/// Faster per-run sort (no per-run scratch); equal-element order is unspecified,
/// exactly as `slice::sort_unstable_by`. The result is always a correct total
/// order and an exact permutation of the input.
pub fn gatling_sort_unstable_by<T, F>(v: &mut [T], compare: F)
where
    T: Send,
    F: Fn(&T, &T) -> Ordering + Sync,
{
    parallel_sort(v, compare, false);
}

/// Parallel **stable** sort for `T: Ord` — the drop-in for `slice::sort`.
pub fn gatling_sort<T: Ord + Send>(v: &mut [T]) {
    gatling_sort_by(v, |a, b| a.cmp(b));
}

/// Parallel **unstable** sort for `T: Ord` — the drop-in for
/// `slice::sort_unstable`.
pub fn gatling_sort_unstable<T: Ord + Send>(v: &mut [T]) {
    gatling_sort_unstable_by(v, |a, b| a.cmp(b));
}

/// A `Send + Sync + Copy` raw base pointer so a slice/scratch base can cross the
/// fork-join worker boundary. Soundness is argued at every use site: workers
/// only ever touch **disjoint** index ranges, so the pointer is never used to
/// alias across threads.
struct Bp<T>(*mut T);
impl<T> Clone for Bp<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Bp<T> {}
// SAFETY: workers address disjoint ranges only (per-run sort → disjoint runs;
// merge → disjoint output segments + disjoint input sub-ranges), so the base is
// never used to form aliasing references or writes across threads.
unsafe impl<T: Send> Send for Bp<T> {}
unsafe impl<T: Send> Sync for Bp<T> {}

/// A contiguous sorted run `[start, start+len)` inside the current source buffer.
#[derive(Clone, Copy)]
struct Run {
    start: usize,
    len: usize,
}

/// One unit of merge-round work handed to the fork-join pool. Every task writes
/// a **disjoint** span of the destination buffer, so the round is contention-free.
#[derive(Clone, Copy)]
enum Task {
    /// Merge output ranks `[k_lo, k_hi)` of the pair (run A, run B) — the
    /// co-ranks that bound the two input sub-ranges are found per-task by a
    /// merge-path binary search, so the task struct stays tiny.
    Merge {
        a_start: usize,
        a_len: usize,
        b_start: usize,
        b_len: usize,
        out_start: usize,
        k_lo: usize,
        k_hi: usize,
    },
    /// Copy `[start, start+len)` verbatim from src to dst — the odd, unpaired run
    /// of a round (nothing to merge it with), split for parallelism. Only arises
    /// for a non-power-of-two run count (e.g. a run cap hit near the threshold).
    Copy { start: usize, len: usize },
}

/// Bomb guard: if a comparator panics *inside the bitwise-move merge*, the two
/// buffers are mid-transfer and unwinding could double-drop, so we abort instead.
/// Disarmed (`std::mem::forget`) the instant the sort commits its result to `v`.
struct AbortOnPanic;
impl Drop for AbortOnPanic {
    fn drop(&mut self) {
        // Reached only while unwinding through the merge region (the normal path
        // forgets the guard). A partially-moved buffer pair is unsafe to unwind.
        eprintln!(
            "gatling_sort: comparator panicked during parallel merge — aborting to avoid unsafe partial-move state"
        );
        std::process::abort();
    }
}

fn parallel_sort<T, F>(v: &mut [T], compare: F, stable: bool)
where
    T: Send,
    F: Fn(&T, &T) -> Ordering + Sync,
{
    let n = v.len();
    let workers = default_workers();

    // ── Serial floor ────────────────────────────────────────────────────────
    if n < PARALLEL_THRESHOLD || workers <= 1 {
        if stable {
            v.sort_by(|a, b| compare(a, b));
        } else {
            v.sort_unstable_by(|a, b| compare(a, b));
        }
        return;
    }

    // ── Run layout ──────────────────────────────────────────────────────────
    // A power-of-two run count ≥ workers: ≥1 run/worker gives the per-run sort
    // some self-dispatch stealing headroom, and a power of two makes the merge
    // tree exactly `log2(runs)` rounds with NO odd leftover-copy and an EVEN
    // round count (data lands back in `v` — no final copy-back bandwidth pass).
    // Cap = largest power of two ≤ n/MIN_RUN (floor, so every run stays ≥ MIN_RUN).
    let cap = {
        let m = n / MIN_RUN;
        if m < 2 {
            2
        } else {
            1usize << (usize::BITS - 1 - m.leading_zeros())
        }
    };
    let runs_n = workers.next_power_of_two().min(cap).max(2);
    let base = n / runs_n;
    let rem = n % runs_n;
    let mut runs: Vec<Run> = Vec::with_capacity(runs_n);
    {
        let mut start = 0;
        for r in 0..runs_n {
            let len = base + if r < rem { 1 } else { 0 };
            runs.push(Run { start, len });
            start += len;
        }
        debug_assert_eq!(start, n);
    }

    // ── Phase 1: sort each run in place, in parallel ─────────────────────────
    // In-place ⇒ `v` stays fully valid even if `compare` unwinds here (std's
    // per-run sort is itself panic-safe), so this phase needs no bomb guard.
    {
        let vbase = Bp(v.as_mut_ptr());
        let cmp = &compare;
        let runs_ref = &runs;
        // `move` so the whole `Bp` (Send+Sync) is captured; then `let vbase =
        // &vbase;` forces whole-struct capture (edition-2024 disjoint capture
        // would otherwise grab the raw `*mut T` field, which is !Sync).
        gatling_run(runs_ref.len(), workers, move |r| {
            let vbase = &vbase;
            let run = runs_ref[r];
            // SAFETY: runs are disjoint contiguous ranges of `v`; run `r` is
            // claimed by exactly one worker, so this &mut slice never aliases.
            let slice = unsafe { std::slice::from_raw_parts_mut(vbase.0.add(run.start), run.len) };
            if stable {
                slice.sort_by(|a, b| cmp(a, b));
            } else {
                slice.sort_unstable_by(|a, b| cmp(a, b));
            }
        });
    }

    if runs.len() == 1 {
        return; // whole slice was one run (n just over the floor on few cores).
    }

    // ── Phase 2: parallel merge rounds (merge-path segmented, ping-ponged) ────
    // Scratch is `MaybeUninit<T>` so it NEVER auto-drops a `T`: the bitwise
    // moves leave stale bit-duplicates behind, and only `v` (the live buffer at
    // the end) must own — and drop — each `T` exactly once.
    let mut scratch: Vec<MaybeUninit<T>> = Vec::with_capacity(n);
    scratch.resize_with(n, MaybeUninit::uninit);

    // Target ≈ 8 segments/worker in the biggest (final, one-pair) round so the
    // merge saturates every core instead of running one big merge serially.
    let seg_len = (n / (workers * 8)).max(4096);

    let mut src = Bp(v.as_mut_ptr());
    let mut dst = Bp(scratch.as_mut_ptr() as *mut T);

    // From here the merge moves `T`s bitwise between `v` and `scratch`; a
    // comparator panic mid-move is converted to an abort (see `AbortOnPanic`).
    let bomb = AbortOnPanic;

    while runs.len() > 1 {
        let mut next_runs: Vec<Run> = Vec::with_capacity(runs.len().div_ceil(2));
        let mut tasks: Vec<Task> = Vec::new();

        let mut r = 0;
        while r < runs.len() {
            if r + 1 < runs.len() {
                let a = runs[r];
                let b = runs[r + 1];
                debug_assert_eq!(a.start + a.len, b.start, "runs must be contiguous");
                let m = a.len + b.len;
                let out_start = a.start;
                next_runs.push(Run {
                    start: out_start,
                    len: m,
                });
                let nseg = m.div_ceil(seg_len).max(1);
                for s in 0..nseg {
                    let k_lo = s * m / nseg;
                    let k_hi = (s + 1) * m / nseg;
                    if k_lo == k_hi {
                        continue;
                    }
                    tasks.push(Task::Merge {
                        a_start: a.start,
                        a_len: a.len,
                        b_start: b.start,
                        b_len: b.len,
                        out_start,
                        k_lo,
                        k_hi,
                    });
                }
                r += 2;
            } else {
                // Odd run out: copy it through unchanged (same offset in dst).
                let s_run = runs[r];
                next_runs.push(s_run);
                let nseg = s_run.len.div_ceil(seg_len).max(1);
                for s in 0..nseg {
                    let c_lo = s * s_run.len / nseg;
                    let c_hi = (s + 1) * s_run.len / nseg;
                    if c_lo == c_hi {
                        continue;
                    }
                    tasks.push(Task::Copy {
                        start: s_run.start + c_lo,
                        len: c_hi - c_lo,
                    });
                }
                r += 1;
            }
        }

        {
            let cmp = &compare;
            let tasks_ref = &tasks;
            let src = src;
            let dst = dst;
            // `move` + `let (src, dst) = (&src, &dst);` ⇒ whole-`Bp` capture.
            gatling_run(tasks_ref.len(), workers, move |t| {
                let (src, dst) = (&src, &dst);
                // SAFETY: each task writes a disjoint dst span and reads disjoint
                // src sub-ranges (co-rank tiles the two input runs across the
                // round's segments), so no two workers touch the same slot.
                unsafe { run_task(&tasks_ref[t], *src, *dst, cmp) };
            });
        }

        // The freshly-written buffer becomes next round's source.
        std::mem::swap(&mut src, &mut dst);
        runs = next_runs;
    }

    // Result lives in `src`. With a power-of-two run count that is `v` (even
    // round count); the copy-back branch only fires for a non-power-of-two run
    // count (run cap near the threshold) that lands an odd round in scratch.
    if src.0 != v.as_mut_ptr() {
        // SAFETY: `src` holds `n` initialized `T`s (the completed merge); `v` is
        // wholly moved-from (uninit). A disjoint parallel copy moves each `T`
        // once into its final home; scratch keeps the stale bit-copies but,
        // being `MaybeUninit`, never drops them.
        let vbase = Bp(v.as_mut_ptr());
        let srcb = src;
        let cparts = workers.max(1);
        let cbase = n / cparts;
        let crem = n % cparts;
        gatling_run(cparts, workers, move |p| {
            let (vbase, srcb) = (&vbase, &srcb);
            let start = p * cbase + p.min(crem);
            let len = cbase + if p < crem { 1 } else { 0 };
            if len == 0 {
                return;
            }
            unsafe { std::ptr::copy_nonoverlapping(srcb.0.add(start), vbase.0.add(start), len) };
        });
    }

    // Committed: `v` owns every `T` exactly once. Disarm the abort bomb and drop
    // the scratch allocation (MaybeUninit ⇒ no `T` is dropped from it).
    std::mem::forget(bomb);
    drop(scratch);

    // Introspection marker: a parallel sort completed across `workers`.
    #[cfg(feature = "testmatrix")]
    crate::functional_status(
        "gatling_sort",
        if stable {
            "gatling_sort_by"
        } else {
            "gatling_sort_unstable_by"
        },
        true,
        &format!("n={n} runs={runs_n} workers={workers} completed"),
    );
}

/// Execute one merge/copy task, moving elements bitwise from `src` to `dst`.
///
/// SAFETY: `task`'s dst span and src sub-ranges are disjoint from every sibling
/// task's (guaranteed by the round's segment tiling), all indices are in-bounds
/// and initialized in `src`, and each source element is moved exactly once
/// across the whole round — so `dst` ends fully initialized and `src` fully
/// consumed with no aliasing and no double-move.
unsafe fn run_task<T, F>(task: &Task, src: Bp<T>, dst: Bp<T>, cmp: &F)
where
    F: Fn(&T, &T) -> Ordering,
{
    match *task {
        Task::Copy { start, len } => unsafe {
            std::ptr::copy_nonoverlapping(src.0.add(start), dst.0.add(start), len);
        },
        Task::Merge {
            a_start,
            a_len,
            b_start,
            b_len,
            out_start,
            k_lo,
            k_hi,
        } => unsafe {
            let a = src.0.add(a_start) as *const T;
            let b = src.0.add(b_start) as *const T;
            let d = dst.0;

            let i_lo = co_rank(k_lo, a_len, b_len, a, b, cmp);
            let i_hi = co_rank(k_hi, a_len, b_len, a, b, cmp);
            let j_lo = k_lo - i_lo;
            let j_hi = k_hi - i_hi;
            debug_assert!(i_lo <= i_hi && j_lo <= j_hi, "co-rank must be monotone");

            let (mut ia, mut jb) = (i_lo, j_lo);
            let mut o = out_start + k_lo;
            while ia < i_hi && jb < j_hi {
                // `!= Greater` ⇒ take A on ties: A is the left (earlier-origin)
                // run, so equal elements keep input order ⇒ stable.
                if cmp(&*a.add(ia), &*b.add(jb)) != Ordering::Greater {
                    std::ptr::copy_nonoverlapping(a.add(ia), d.add(o), 1);
                    ia += 1;
                } else {
                    std::ptr::copy_nonoverlapping(b.add(jb), d.add(o), 1);
                    jb += 1;
                }
                o += 1;
            }
            if ia < i_hi {
                let c = i_hi - ia;
                std::ptr::copy_nonoverlapping(a.add(ia), d.add(o), c);
                o += c;
            }
            if jb < j_hi {
                let c = j_hi - jb;
                std::ptr::copy_nonoverlapping(b.add(jb), d.add(o), c);
                o += c;
            }
            debug_assert_eq!(o, out_start + k_hi);
        },
    }
}

/// Merge-path **co-rank**: for merged rank `k`, return `i` = how many of the
/// first `k` merged elements come from run A (so `k - i` come from B), under the
/// stable merge rule (A wins ties). Runs A/B are the sorted `*const T` ranges of
/// length `la`/`lb`.
///
/// A valid split takes A[..i] and B[..k-i] as exactly the `k` smallest, ties
/// broken toward A. `i` is the LARGEST value in `[k-lb, min(k,la)]` for which the
/// last A taken is not ordered after the next B (`A[i-1] <= B[k-i]`); that value
/// is the unique stable co-rank. A monotone binary search finds it in O(log).
///
/// SAFETY: `a`/`b` point to `la`/`lb` initialized `T`s; only in-bounds indices
/// are read (`mid-1 < la`, `k-mid < lb`), and only for comparison (no move).
#[inline]
unsafe fn co_rank<T, F>(k: usize, la: usize, lb: usize, a: *const T, b: *const T, cmp: &F) -> usize
where
    F: Fn(&T, &T) -> Ordering,
{
    let mut lo = k.saturating_sub(lb); // smallest i keeping j = k-i ≤ lb
    let mut hi = k.min(la); // largest i (≤ available A and ≤ k)
    while lo < hi {
        // Upper mid so `lo` can advance to `mid`; `mid ≥ 1` since `hi > lo ≥ 0`.
        let mid = lo + (hi - lo + 1) / 2;
        let j = k - mid;
        // C1: taking `mid` from A is still ordered — the last A, A[mid-1], is not
        // greater than the next B, B[j] (or all of B is already consumed).
        let c1 = j == lb || unsafe { cmp(&*a.add(mid - 1), &*b.add(j)) } != Ordering::Greater;
        if c1 {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* — no `rand` dep needed for the input corpus.
    struct Xs(u64);
    impl Xs {
        fn new(seed: u64) -> Self {
            Xs(seed | 1)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
    }

    fn shuffled_i64(n: usize, seed: u64) -> Vec<i64> {
        let mut r = Xs::new(seed);
        (0..n).map(|_| r.next_u64() as i64).collect()
    }

    /// Sizes that straddle the parallel threshold and the run layout on any core
    /// count, plus a few edge shapes, so the parallel path is always exercised.
    const SIZES: &[usize] = &[
        0,
        1,
        2,
        7,
        PARALLEL_THRESHOLD - 1,
        PARALLEL_THRESHOLD,
        PARALLEL_THRESHOLD + 1,
        50_000,
        300_000,
    ];

    #[test]
    fn stable_equals_std_sort_by_exactly() {
        for &n in SIZES {
            let v = shuffled_i64(n, 0xABCD ^ n as u64);
            let mut want = v.clone();
            want.sort_by(|a, b| a.cmp(b));
            let mut got = v.clone();
            gatling_sort_by(&mut got, |a, b| a.cmp(b));
            assert_eq!(got, want, "stable sort != std::sort_by at n={n}");
        }
    }

    #[test]
    fn unstable_is_sorted_permutation() {
        for &n in SIZES {
            let v = shuffled_i64(n, 0x1234 ^ n as u64);
            let mut want = v.clone();
            want.sort_unstable();
            let mut got = v.clone();
            gatling_sort_unstable_by(&mut got, |a, b| a.cmp(b));
            // Unstable: order among equals is unspecified, so assert the two real
            // invariants — sorted ascending, and an exact permutation of input.
            assert!(got.windows(2).all(|w| w[0] <= w[1]), "not sorted at n={n}");
            assert_eq!(got, want, "not a sorted permutation at n={n}");
        }
    }

    #[test]
    fn convenience_ord_wrappers_match_std() {
        let v = shuffled_i64(120_000, 0x9E37);
        let mut want_s = v.clone();
        want_s.sort();
        let mut got_s = v.clone();
        gatling_sort(&mut got_s);
        assert_eq!(got_s, want_s, "gatling_sort != slice::sort");

        let mut want_u = v.clone();
        want_u.sort_unstable();
        let mut got_u = v.clone();
        gatling_sort_unstable(&mut got_u);
        assert_eq!(
            got_u, want_u,
            "gatling_sort_unstable not a sorted permutation"
        );
    }

    /// **Stability, RED-when-broken:** keys with many duplicates carry their
    /// original index as a tiebreak the comparator IGNORES. A stable sort must
    /// leave equal-key elements in ascending original-index order — identical to
    /// `slice::sort_by`. A merge that took the RIGHT run on ties (or an unstable
    /// per-run sort leaking through) would reorder equals and trip this.
    #[test]
    fn stable_preserves_equal_element_order() {
        for &n in &[PARALLEL_THRESHOLD + 1, 50_000, 250_000] {
            let mut r = Xs::new(0x5A5A ^ n as u64);
            // Few distinct keys ⇒ long tie runs that MUST stay index-ordered.
            let data: Vec<(u32, u32)> = (0..n)
                .map(|i| ((r.next_u64() % 16) as u32, i as u32))
                .collect();

            let mut want = data.clone();
            want.sort_by(|a, b| a.0.cmp(&b.0));
            let mut got = data.clone();
            gatling_sort_by(&mut got, |a, b| a.0.cmp(&b.0));

            assert_eq!(got, want, "stable order diverged from std at n={n}");
            // Independent check: within each key group, original indices ascend.
            for w in got.windows(2) {
                if w[0].0 == w[1].0 {
                    assert!(
                        w[0].1 < w[1].1,
                        "equal keys reordered at n={n}: {:?} {:?}",
                        w[0],
                        w[1]
                    );
                }
            }
        }
    }

    #[test]
    fn edge_shapes_sorted_and_permuted() {
        let n = 40_000usize;
        let cases: Vec<Vec<i64>> = vec![
            Vec::new(),
            vec![42],
            (0..n as i64).collect(),                // already sorted
            (0..n as i64).rev().collect(),          // reverse
            vec![7; n],                             // all equal
            (0..n as i64).map(|i| i % 5).collect(), // few distinct
        ];
        for case in cases {
            for stable in [true, false] {
                let mut want = case.clone();
                want.sort();
                let mut got = case.clone();
                if stable {
                    gatling_sort_by(&mut got, |a, b| a.cmp(b));
                } else {
                    gatling_sort_unstable_by(&mut got, |a, b| a.cmp(b));
                }
                assert_eq!(
                    got,
                    want,
                    "edge case wrong (stable={stable}, len={})",
                    case.len()
                );
            }
        }
    }

    /// A struct with a non-trivial, multi-field comparator (descending by weight,
    /// then ascending by name) — proves the generic path matches std for a real
    /// composite ordering, not just integers.
    #[test]
    fn struct_with_custom_cmp_matches_std() {
        #[derive(Clone, PartialEq, Eq, Debug)]
        struct Item {
            weight: i32,
            name: String,
        }
        let mut r = Xs::new(0xC0FFEE);
        let v: Vec<Item> = (0..60_000)
            .map(|_| Item {
                weight: (r.next_u64() % 1000) as i32,
                name: format!("n{}", r.next_u64() % 10_000),
            })
            .collect();
        let cmp = |a: &Item, b: &Item| b.weight.cmp(&a.weight).then_with(|| a.name.cmp(&b.name));

        let mut want = v.clone();
        want.sort_by(cmp);
        let mut got = v.clone();
        gatling_sort_by(&mut got, cmp);
        assert_eq!(got, want, "struct custom-cmp stable sort != std");
    }

    /// Direct co-rank oracle: for random run-pairs, the co-rank at every rank `k`
    /// must equal the reference (a full stable merge counting A-origins), so the
    /// merge-path split is exact — the invariant the segmented merge relies on.
    #[test]
    fn co_rank_matches_reference_merge() {
        let mut r = Xs::new(0xDEAD);
        for _ in 0..200 {
            let la = (r.next_u64() % 40) as usize;
            let lb = (r.next_u64() % 40) as usize;
            let mut a: Vec<i32> = (0..la).map(|_| (r.next_u64() % 20) as i32).collect();
            let mut b: Vec<i32> = (0..lb).map(|_| (r.next_u64() % 20) as i32).collect();
            a.sort();
            b.sort();
            // Reference stable merge, recording which side each output came from.
            let mut from_a = Vec::with_capacity(la + lb);
            let (mut i, mut j) = (0usize, 0usize);
            while i < la && j < lb {
                if a[i] <= b[j] {
                    from_a.push(true);
                    i += 1;
                } else {
                    from_a.push(false);
                    j += 1;
                }
            }
            while i < la {
                from_a.push(true);
                i += 1;
            }
            while j < lb {
                from_a.push(false);
                j += 1;
            }
            let cmp = |x: &i32, y: &i32| x.cmp(y);
            for k in 0..=(la + lb) {
                let want_i = from_a[..k].iter().filter(|&&x| x).count();
                let got_i = unsafe { co_rank(k, la, lb, a.as_ptr(), b.as_ptr(), &cmp) };
                assert_eq!(got_i, want_i, "co_rank({k}) wrong for la={la} lb={lb}");
            }
        }
    }
}
