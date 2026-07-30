//! Rayon-free parallel map — a thin adapter over the one workspace engine.
//!
//! This used to hand-roll its own `std::thread::scope` + atomic-cursor +
//! per-slot `Mutex` pool. That was a *second* parallel engine, which the
//! one-engine law (`.nornir/gatling-guide.md`, rule zero) forbids. It now
//! delegates straight to `gatling::gatling_forkjoin::gatling_for_each`, which
//! provides the identical contract — dynamic self-dispatch via a shared atomic
//! cursor so uneven units (PBF blobs of differing sizes) stay balanced, results
//! returned in index order — with no `Mutex` per slot (disjoint `MaybeUninit`
//! writes instead) and no private pool.
//!
//! For fan-outs with a known per-unit cost (e.g. blob byte length), prefer
//! `gatling::gatling_forkjoin::gatling_for_each_balanced` directly for a
//! heaviest-first (LPT) schedule; this `par_map` keeps the plain, weightless
//! contract its callers were written against.

/// Apply `f` to every index `0..n` across one-worker-per-core, returning the
/// results in index order. `f` must be `Sync` (shared by all workers). Indices
/// are claimed dynamically (shared atomic cursor inside the engine) so longer
/// units don't stall a thread that could be draining the queue.
#[inline]
pub fn par_map<T, F>(n: usize, f: F) -> Vec<T>
where
    T: Send,
    F: Fn(usize) -> T + Sync,
{
    gatling::gatling_forkjoin::gatling_for_each(n, 0, f)
}
