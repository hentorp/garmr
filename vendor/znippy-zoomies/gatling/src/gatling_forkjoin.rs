//! Gatling (fork-join) — the no-barrier worker pool for work known **upfront**.
//!
//! The streaming [`crate::gatling`] engine is `Reader → split → N workers →
//! collector` for data that *arrives* a chunk at a time. This is its sibling for
//! the case where the whole work set already exists (a fixed `0..n` index range,
//! or a grid of scanlines): there is no reader and no carry, but the gatling
//! **soul is identical** —
//!
//! - **No barrier.** Workers never sync at a unit boundary. The instant a worker
//!   finishes unit `i` it claims the next free index and starts — it does **not**
//!   wait for a slow sibling. A 32-core box stays 32-busy even when units cost
//!   wildly different amounts (a dense scanline vs an empty one).
//! - **Self-dispatch.** A single shared atomic counter hands out the next index
//!   (`fetch_add`). No central scheduler, no per-unit channel send, no work queue
//!   to drain — the cheapest possible hand-off (1→N self-feeding).
//! - **Zero-copy / zero-contention output.** Each unit owns a **disjoint** slice
//!   of the output (a scanline = `width` pixels at row `y`); workers write in
//!   place, never sharing a cache line, never locking.
//! - **rayon-free.** Pure `std::thread::scope`; no global pool, no rayon
//!   (forbidden in the constellation). Threads are scoped to the call, so borrows
//!   of caller stack data are sound with no `'static` / `Arc` ceremony.
//!
//! # When to use which gatling
//! - Bytes streaming in, order matters out → [`crate::gatling::run`] /
//!   [`run_typed`](crate::gatling::run_typed).
//! - A fixed `0..n` of independent units, or a pixel/row grid → here.
//!
//! # Examples
//! ```
//! use gatling::gatling_forkjoin::gatling_for_each;
//! let mut data = vec![0u32; 1000];
//! // Each index is an independent unit; workers self-dispatch, no barrier.
//! gatling_for_each(data.len(), 0, |i| i as u32 * 2).into_iter()
//!     .enumerate().for_each(|(i, v)| data[i] = v);
//! assert_eq!(data[500], 1000);
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};

/// Default worker count: every core the box has. `0` passed to the entry points
/// resolves to this.
#[inline]
pub fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(1)
        .max(1)
}

#[inline]
fn resolve_workers(requested: usize, units: usize) -> usize {
    let w = if requested == 0 {
        default_workers()
    } else {
        requested
    };
    w.max(1).min(units.max(1))
}

/// Run `f(i)` for every `i in 0..n` across a no-barrier self-dispatching worker
/// pool, returning the results **in index order**. `n_workers == 0` ⇒ one per
/// core. `f` is shared (`Sync`); each worker claims the next free index via an
/// atomic and runs without waiting on any sibling.
///
/// This is the fork-join gatling: all `n` units are known now, so there is no
/// reader — just N workers draining a shared counter at full tilt.
pub fn gatling_for_each<T, F>(n: usize, n_workers: usize, f: F) -> Vec<T>
where
    T: Send,
    F: Fn(usize) -> T + Sync,
{
    if n == 0 {
        return Vec::new();
    }
    let workers = resolve_workers(n_workers, n);
    if workers == 1 {
        return (0..n).map(f).collect();
    }

    // One pre-allocated output slot per unit. Each index is written by exactly one
    // worker, so the raw-pointer writes below never alias — no lock, no contention.
    let mut out: Vec<std::mem::MaybeUninit<T>> = Vec::with_capacity(n);
    out.resize_with(n, std::mem::MaybeUninit::uninit);

    let next = AtomicUsize::new(0);
    {
        let next_ref = &next;
        let f_ref = &f;
        // SAFETY: the worker only ever writes `out[i]` for the `i` it uniquely
        // claimed from the atomic counter; no two workers see the same `i`, so the
        // pointer writes are non-aliasing. The scope joins all workers before we
        // read `out`, so every slot is initialized exactly once by then.
        let out_ptr = OutPtr(out.as_mut_ptr());
        std::thread::scope(|s| {
            for _ in 0..workers {
                let out_ptr = out_ptr;
                s.spawn(move || {
                    // Force whole-struct capture (not the raw field) so the Send
                    // wrapper's impl applies under edition-2024 disjoint capture.
                    let out_ptr = &out_ptr;
                    loop {
                        let i = next_ref.fetch_add(1, Ordering::Relaxed);
                        if i >= n {
                            break;
                        }
                        let v = f_ref(i);
                        unsafe { out_ptr.write_at(i, v) };
                    }
                });
            }
        });
    }

    // Introspection marker: the no-barrier fan-out completed across `workers`.
    #[cfg(feature = "testmatrix")]
    crate::functional_status(
        "gatling_forkjoin",
        "gatling_for_each",
        true,
        &format!("n={n} workers={workers} completed"),
    );

    // SAFETY: every slot was written exactly once (each `0..n` claimed once, scope
    // joined). Transmute the fully-initialized `MaybeUninit<T>` Vec to `Vec<T>`.
    let mut out = std::mem::ManuallyDrop::new(out);
    unsafe { Vec::from_raw_parts(out.as_mut_ptr() as *mut T, out.len(), out.capacity()) }
}

/// A `Send`+`Copy` raw-pointer wrapper so the output base can cross the scoped
/// thread boundary. Soundness is argued at every use site (disjoint indices).
struct OutPtr<T>(*mut std::mem::MaybeUninit<T>);
// Hand-rolled Copy/Clone with NO `T: Copy` bound (a raw pointer is always Copy).
impl<T> Clone for OutPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for OutPtr<T> {}
// SAFETY: workers only write disjoint indices; the pointer is never used to alias.
unsafe impl<T: Send> Send for OutPtr<T> {}

impl<T> OutPtr<T> {
    /// Write `v` into slot `i`. SAFETY: caller guarantees `i` is unique to this
    /// worker (claimed from the atomic) and in-bounds, so no aliasing write.
    #[inline]
    unsafe fn write_at(&self, i: usize, v: T) {
        unsafe { self.0.add(i).write(std::mem::MaybeUninit::new(v)) };
    }
}

/// Run `f(i)` for every `i in 0..n` purely for side effects (no collected output),
/// across the no-barrier self-dispatch pool. Use when `f` writes into external
/// per-`i` state the caller owns. `n_workers == 0` ⇒ one per core.
pub fn gatling_run<F>(n: usize, n_workers: usize, f: F)
where
    F: Fn(usize) + Sync,
{
    if n == 0 {
        return;
    }
    let workers = resolve_workers(n_workers, n);
    if workers == 1 {
        (0..n).for_each(f);
        return;
    }
    let next = AtomicUsize::new(0);
    let next_ref = &next;
    let f_ref = &f;
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(move || {
                loop {
                    let i = next_ref.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    f_ref(i);
                }
            });
        }
    });

    // Introspection marker: the side-effect run completed across `workers`.
    #[cfg(feature = "testmatrix")]
    crate::functional_status(
        "gatling_forkjoin",
        "gatling_run",
        true,
        &format!("n={n} workers={workers} completed"),
    );
}

/// **Parallel fold / scatter-reduce** — the reduction sibling of [`gatling_for_each`].
///
/// `gatling_for_each` maps `0..n` to *disjoint* output slots (no cross-index combine).
/// The moment a computation must **combine across indices** — a running min/max, a sum,
/// or a **scatter-reduce** where each unit writes into *several, overlapping* slots of a
/// shared accumulator (`disp[a] += …; disp[b] += …`) — that per-slot write hazard makes
/// `gatling_for_each` unusable. This is the primitive for exactly that case.
///
/// The `0..n` index range is split into **`workers` fixed, contiguous partitions**; each
/// worker folds its own partition into a **private local accumulator** (`init()` → then
/// `fold(&mut acc, i)` for each `i` in its range), so nothing is shared and there is no
/// write hazard. The private partials are then combined into the result by `merge`, **in
/// ascending partition order** — a fixed, worker-count-stable order, so a floating-point
/// reduction is **reproducible run-to-run** (identical partition boundaries ⇒ identical
/// summation order ⇒ byte-identical result). rayon-free scoped threads, one per core.
///
/// `init` must return the fold **identity** (the empty accumulator); `fold(&mut acc, i)`
/// absorbs unit `i`; `merge(&mut acc, partial)` combines a worker's partial into the
/// running accumulator. For a scatter-reduce, `A` is the whole accumulator buffer (e.g.
/// `Vec<[f32; D]>`): `fold` scatters unit `i`'s contributions into it, `merge` adds two
/// buffers element-wise — `workers` buffers, merged once, no per-unit contention.
///
/// # Example
/// ```
/// use gatling::gatling_forkjoin::gatling_reduce;
/// // Parallel sum of 0..1000 (deterministic: fixed partitions, fixed merge order).
/// let total: u64 = gatling_reduce(1000, 0, || 0u64, |acc, i| *acc += i as u64, |acc, p| *acc += p);
/// assert_eq!(total, (0..1000u64).sum());
/// ```
pub fn gatling_reduce<A, I, F, M>(n: usize, n_workers: usize, init: I, fold: F, merge: M) -> A
where
    A: Send,
    I: Fn() -> A + Sync,
    F: Fn(&mut A, usize) + Sync,
    M: Fn(&mut A, A),
{
    // Empty range ⇒ the identity. Single worker ⇒ a plain serial fold (the reference
    // the parallel path must match, and the no-thread fast path).
    let workers = resolve_workers(n_workers, n);
    if n == 0 || workers == 1 {
        let mut acc = init();
        for i in 0..n {
            fold(&mut acc, i);
        }
        return acc;
    }

    // `workers` fixed contiguous partitions: partition `p` owns `[lo, hi)` where the
    // first `rem` partitions carry one extra index (a deterministic, balanced split).
    let base = n / workers;
    let rem = n % workers;
    let mut partials: Vec<Option<A>> = (0..workers).map(|_| None).collect();
    {
        let init_ref = &init;
        let fold_ref = &fold;
        std::thread::scope(|s| {
            for (p, slot) in partials.iter_mut().enumerate() {
                // Each thread owns a distinct `&mut slot` and a distinct index range —
                // no aliasing, no shared mutable state, so no lock and no hazard.
                s.spawn(move || {
                    let lo = p * base + p.min(rem);
                    let hi = lo + base + if p < rem { 1 } else { 0 };
                    let mut acc = init_ref();
                    for i in lo..hi {
                        fold_ref(&mut acc, i);
                    }
                    *slot = Some(acc);
                });
            }
        });
    }

    // Deterministic merge: fold every partial into the accumulator in ascending
    // partition order (fixed ⇒ float-reproducible).
    let mut acc = init();
    for slot in partials {
        if let Some(part) = slot {
            merge(&mut acc, part);
        }
    }

    // Introspection marker: the fork-join reduction completed across `workers`.
    #[cfg(feature = "testmatrix")]
    crate::functional_status(
        "gatling_forkjoin",
        "gatling_reduce",
        true,
        &format!("n={n} workers={workers} merged in order"),
    );

    acc
}

/// Load-balanced sibling of [`gatling_for_each`] for **skewed unit costs**.
///
/// Same no-barrier self-dispatch soul, with two refinements that matter when a
/// few units cost far more than the rest (e.g. one 5 000-line source file among
/// hundreds of tiny ones):
///
/// - **Heaviest-first (LPT) schedule.** A caller-supplied `weight(i)` (e.g. a
///   file's byte size) orders the units biggest→smallest, so the expensive ones
///   are claimed first and the cheap tail fills the gaps — no worker gets stuck
///   on a monster while its siblings sit idle having drained the small end.
/// - **Batched claims.** A worker grabs `batch` indices per atomic `fetch_add`
///   instead of one, amortizing the counter hand-off across many cheap units.
///   `batch == 0` is treated as `1`.
///
/// Results are returned in the **original `0..n` index order** (not schedule
/// order), so the output is identical to a serial `(0..n).map(f)`.
///
/// `n_workers == 0` ⇒ one per core.
///
/// ```
/// use gatling::gatling_forkjoin::gatling_for_each_balanced;
/// // One expensive unit (index 0) among many cheap ones; still index-ordered out.
/// let out = gatling_for_each_balanced(1000, 0, 16, |i| if i == 0 { 1_000_000 } else { 1 }, |i| i * 2);
/// assert_eq!(out[500], 1000);
/// ```
pub fn gatling_for_each_balanced<T, F, W>(
    n: usize,
    n_workers: usize,
    batch: usize,
    weight: W,
    f: F,
) -> Vec<T>
where
    T: Send,
    F: Fn(usize) -> T + Sync,
    W: Fn(usize) -> u64,
{
    if n == 0 {
        return Vec::new();
    }
    let workers = resolve_workers(n_workers, n);
    if workers == 1 {
        return (0..n).map(f).collect();
    }
    let batch = batch.max(1);

    // Heaviest-first schedule: positions into `0..n` ordered by descending weight.
    // `weight` is computed once into a side table so the sort comparator is cheap.
    let weights: Vec<u64> = (0..n).map(&weight).collect();
    let mut schedule: Vec<usize> = (0..n).collect();
    schedule.sort_by(|&a, &b| weights[b].cmp(&weights[a]));

    let mut out: Vec<std::mem::MaybeUninit<T>> = Vec::with_capacity(n);
    out.resize_with(n, std::mem::MaybeUninit::uninit);

    let next = AtomicUsize::new(0);
    {
        let next_ref = &next;
        let f_ref = &f;
        let sched_ref = &schedule;
        // SAFETY: each schedule position is claimed by exactly one worker (the
        // batched atomic `fetch_add` hands out disjoint `[start, end)` spans), and
        // each position maps to a distinct original index `schedule[p]`, so every
        // `out[orig]` is written exactly once and never aliased. The scope joins
        // all workers before we read `out`.
        let out_ptr = OutPtr(out.as_mut_ptr());
        std::thread::scope(|s| {
            for _ in 0..workers {
                let out_ptr = out_ptr;
                s.spawn(move || {
                    // Whole-struct capture so the Send wrapper applies (edition-2024
                    // disjoint capture would otherwise grab the raw field).
                    let out_ptr = &out_ptr;
                    loop {
                        let start = next_ref.fetch_add(batch, Ordering::Relaxed);
                        if start >= n {
                            break;
                        }
                        let end = (start + batch).min(n);
                        for &orig in &sched_ref[start..end] {
                            let v = f_ref(orig);
                            // SAFETY: `orig` is unique to this worker (its schedule
                            // span is disjoint), in-bounds, written exactly once.
                            unsafe { out_ptr.write_at(orig, v) };
                        }
                    }
                });
            }
        });
    }

    // SAFETY: every slot was written exactly once (each `0..n` claimed once, scope
    // joined). Transmute the fully-initialized `MaybeUninit<T>` Vec to `Vec<T>`.
    let mut out = std::mem::ManuallyDrop::new(out);
    unsafe { Vec::from_raw_parts(out.as_mut_ptr() as *mut T, out.len(), out.capacity()) }
}

/// Map over an **owned work list** `&[T]` with the balanced (LPT + batched) pool,
/// handing each closure call the item **by reference** (plus its index) and
/// returning `Vec<R>` in the original `items` order.
///
/// This is the [`gatling_for_each_balanced`] body for the common case where you do
/// not hold a bare `0..n` range but a `Vec` of heterogeneous **work tags** — e.g.
/// a flattened `(group_key, path, size, …)` list — and want a `Vec<R>` of owned
/// per-item results to fold/group afterwards (group-by-key). Two things make it its
/// own variant rather than a call into `gatling_for_each_balanced(items.len(), …,
/// |i| f(i, &items[i]))`:
///
/// - **Item-ref dispatch (no index gymnastics).** `weight(&T)` and `f(i, &T)` read
///   the item directly, so the LPT key (e.g. a byte size stored *in* the tag) and
///   the work both come off the same borrow — the caller never re-indexes an
///   external slice inside the hot closure. The slice is `T: Sync`, borrowed for the
///   scope; **item bytes are never copied into the pool** (only the tag is read; a
///   file-parsing `f` reads the file inside the worker). That is the zero-copy
///   *distribution* the gatling soul asks for: tags in by shared borrow, owned `R`
///   out by disjoint slot.
/// - **Owned `R` out, original order.** Each `R` is written into its own
///   pre-allocated output slot (the same `MaybeUninit` + disjoint-write machinery as
///   the rest of this module — no per-worker `Vec` + final sort), so a caller can
///   immediately `for r in out { group.entry(r.key).push(r) }` deterministically.
///
/// Schedule and batching are identical to [`gatling_for_each_balanced`]: units are
/// claimed **heaviest-first** by `size_of(&item)`, workers steal `batch` per atomic
/// `fetch_add` (`batch == 0` ⇒ `1`), and `n_workers == 0` ⇒ one per core. Reach for
/// it when the work set is a `Vec` of skew-costed items you want to map-then-group.
///
/// ```
/// use gatling::gatling_forkjoin::gatling_map_balanced;
/// // Owned tags in (value = LPT weight), owned results out, original order.
/// let items = vec![3u64, 1, 4, 1, 5, 9, 2, 6];
/// let out = gatling_map_balanced(&items, 0, 4, |&v| v, |i, &v| (i, v * 10));
/// assert_eq!(out[0], (0, 30));
/// assert_eq!(out[5], (5, 90));
/// ```
pub fn gatling_map_balanced<T, R, S, F>(
    items: &[T],
    n_workers: usize,
    batch: usize,
    size_of: S,
    f: F,
) -> Vec<R>
where
    T: Sync,
    R: Send,
    S: Fn(&T) -> u64,
    F: Fn(usize, &T) -> R + Sync,
{
    let n = items.len();
    if n == 0 {
        return Vec::new();
    }
    let workers = resolve_workers(n_workers, n);
    if workers == 1 {
        return items.iter().enumerate().map(|(i, t)| f(i, t)).collect();
    }
    let batch = batch.max(1);

    // Heaviest-first schedule: positions into `items` ordered by descending weight.
    // `size_of` is read once into a side table so the sort comparator stays cheap.
    let weights: Vec<u64> = items.iter().map(&size_of).collect();
    let mut schedule: Vec<usize> = (0..n).collect();
    schedule.sort_by(|&a, &b| weights[b].cmp(&weights[a]));

    let mut out: Vec<std::mem::MaybeUninit<R>> = Vec::with_capacity(n);
    out.resize_with(n, std::mem::MaybeUninit::uninit);

    let next = AtomicUsize::new(0);
    {
        let next_ref = &next;
        let f_ref = &f;
        let sched_ref = &schedule;
        let items_ref = items;
        // SAFETY: each schedule position is claimed by exactly one worker (the
        // batched atomic `fetch_add` hands out disjoint `[start, end)` spans), and
        // each position maps to a distinct original index `schedule[p]`, so every
        // `out[orig]` is written exactly once and never aliased. The scope joins all
        // workers before we read `out`.
        let out_ptr = OutPtr(out.as_mut_ptr());
        std::thread::scope(|s| {
            for _ in 0..workers {
                let out_ptr = out_ptr;
                s.spawn(move || {
                    // Whole-struct capture so the Send wrapper applies (edition-2024
                    // disjoint capture would otherwise grab the raw field).
                    let out_ptr = &out_ptr;
                    loop {
                        let start = next_ref.fetch_add(batch, Ordering::Relaxed);
                        if start >= n {
                            break;
                        }
                        let end = (start + batch).min(n);
                        for &orig in &sched_ref[start..end] {
                            let v = f_ref(orig, &items_ref[orig]);
                            // SAFETY: `orig` is unique to this worker (its schedule
                            // span is disjoint), in-bounds, written exactly once.
                            unsafe { out_ptr.write_at(orig, v) };
                        }
                    }
                });
            }
        });
    }

    // SAFETY: every slot was written exactly once (each `0..n` claimed once, scope
    // joined). Transmute the fully-initialized `MaybeUninit<R>` Vec to `Vec<R>`.
    let mut out = std::mem::ManuallyDrop::new(out);
    unsafe { Vec::from_raw_parts(out.as_mut_ptr() as *mut R, out.len(), out.capacity()) }
}

/// Rayon-free, work-stealing parallel map that **consumes** its input items —
/// each `T` is moved into exactly one worker. The owned-item sibling of
/// [`gatling_for_each`] (which only takes `Fn(usize) -> T + Sync`): the gatling
/// shape for work that carries per-item OWNED, `!Sync` state. Each item is moved
/// in by value, so a `!Sync` payload (e.g. a per-item handle that cannot live
/// behind a shared `Fn(usize)`) is built on the caller thread and handed to a
/// single worker. `std::thread::scope` + an atomic cursor — no rayon (the
/// constellation forbids it); results returned in input order, identical to a
/// serial `items.into_iter().map(f).collect()`.
///
/// ```
/// use gatling::gatling_forkjoin::gatling_map_owned;
/// let items: Vec<u64> = (0..1000).collect();
/// let out = gatling_map_owned(items, |v| v * 2);
/// assert_eq!(out[500], 1000);
/// ```
pub fn gatling_map_owned<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> R + Sync,
{
    let n = items.len();
    if n == 0 {
        return Vec::new();
    }
    let workers = std::thread::available_parallelism()
        .map(|w| w.get())
        .unwrap_or(1)
        .min(n);
    if workers <= 1 {
        return items.into_iter().map(f).collect();
    }

    use std::cell::UnsafeCell;
    use std::mem::MaybeUninit;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Disjoint-index slots: each index is claimed by exactly one worker via the
    // atomic cursor, so the input move-out and the output write never alias — no
    // lock needed. A thin `Sync` wrapper lets the cell vecs cross the scope.
    struct Slots<X>(Vec<UnsafeCell<MaybeUninit<X>>>);
    // SAFETY: workers only touch the unique index they claimed from `cursor`; no
    // two threads access the same cell, and all accesses complete before join.
    unsafe impl<X: Send> Sync for Slots<X> {}

    let inputs = Slots(
        items
            .into_iter()
            .map(|t| UnsafeCell::new(MaybeUninit::new(t)))
            .collect::<Vec<_>>(),
    );
    let outputs: Slots<R> = Slots(
        (0..n)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect(),
    );
    let cursor = AtomicUsize::new(0);

    let inputs_ref = &inputs;
    let outputs_ref = &outputs;
    let cursor_ref = &cursor;
    let f_ref = &f;

    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(move || {
                loop {
                    let i = cursor_ref.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    // SAFETY: `i` is claimed exactly once (atomic fetch_add), so this is
                    // the sole move-out of input slot `i` and the sole write of output
                    // slot `i` — no aliasing with any sibling worker.
                    let item = unsafe { (*inputs_ref.0[i].get()).assume_init_read() };
                    let r = f_ref(item);
                    unsafe { (*outputs_ref.0[i].get()).write(r) };
                }
            });
        }
    });

    // SAFETY: every output slot was written exactly once before the scope joined.
    // Inputs were each moved out via `assume_init_read`; dropping the now-uninit
    // `MaybeUninit` cells does not drop `T` again, so there is no double-free.
    outputs
        .0
        .into_iter()
        .map(|c| unsafe { c.into_inner().assume_init() })
        .collect()
}

/// Raster a `rows`-tall buffer with a no-barrier worker pool, each worker claiming
/// whole **scanlines** and writing into its row's **disjoint** mutable slice. This
/// is the gatling for a pixel grid: `buf` is `rows * stride` elements, row `y`
/// owns `buf[y*stride .. (y+1)*stride]`, and `f(y, row_slice)` fills it. No two
/// workers ever touch the same row, so there is no lock and no false sharing
/// across rows (rows are `stride` elements apart).
///
/// `n_workers == 0` ⇒ one per core. Below `min_rows_for_threads` the call stays
/// single-threaded (no pool spin-up for a tooltip-sized frame).
pub fn gatling_scanlines<P, F>(
    buf: &mut [P],
    rows: usize,
    stride: usize,
    n_workers: usize,
    min_rows_for_threads: usize,
    f: F,
) where
    P: Send,
    F: Fn(usize, &mut [P]) + Sync,
{
    debug_assert_eq!(buf.len(), rows * stride, "buf must be rows*stride");
    if rows == 0 || stride == 0 {
        return;
    }
    let workers = resolve_workers(n_workers, rows);
    if workers == 1 || rows < min_rows_for_threads {
        for (y, row) in buf.chunks_mut(stride).enumerate() {
            f(y, row);
        }
        return;
    }

    let next = AtomicUsize::new(0);
    let next_ref = &next;
    let f_ref = &f;
    // SAFETY: each worker writes only the row `y` it uniquely claimed; row slices
    // [y*stride, (y+1)*stride) are disjoint, so the raw slices never alias. The
    // scope joins before `buf` is used again.
    let base = RowBase(buf.as_mut_ptr());
    std::thread::scope(|s| {
        for _ in 0..workers {
            let base = base;
            s.spawn(move || {
                let base = &base; // whole-struct capture (Send wrapper applies)
                loop {
                    let y = next_ref.fetch_add(1, Ordering::Relaxed);
                    if y >= rows {
                        break;
                    }
                    // SAFETY: row y is uniquely claimed; [y*stride,(y+1)*stride) is
                    // disjoint from every other worker's row, so no aliasing.
                    let row = unsafe { base.row(y, stride) };
                    f_ref(y, row);
                }
            });
        }
    });
}

struct RowBase<P>(*mut P);
impl<P> Clone for RowBase<P> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<P> Copy for RowBase<P> {}
// SAFETY: workers slice disjoint rows; the base pointer is never used to alias.
unsafe impl<P: Send> Send for RowBase<P> {}

impl<P> RowBase<P> {
    /// The `stride`-long mutable slice for row `y`. SAFETY: caller guarantees `y`
    /// is unique to this worker and in-bounds (disjoint rows ⇒ no aliasing).
    #[inline]
    unsafe fn row<'a>(&self, y: usize, stride: usize) -> &'a mut [P] {
        unsafe { std::slice::from_raw_parts_mut(self.0.add(y * stride), stride) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// INJECT-ASSERT: `gatling_for_each` returns results in index order and runs
    /// every unit exactly once, regardless of worker count.
    #[test]
    fn for_each_is_ordered_and_complete() {
        for &workers in &[0usize, 1, 2, 8] {
            let n = 10_000;
            let out = gatling_for_each(n, workers, |i| i * 3);
            assert_eq!(out.len(), n);
            for (i, v) in out.iter().enumerate() {
                assert_eq!(*v, i * 3, "unit {i} wrong (workers={workers})");
            }
        }
    }

    /// **RED-when-broken:** the parallel `gatling_reduce` fold equals the serial fold
    /// for every worker count, and every unit is folded exactly once. A dropped/duplicated
    /// partition, or a merge that skips a partial, changes the sum and trips this.
    #[test]
    fn reduce_matches_serial_fold_all_worker_counts() {
        let n = 10_000usize;
        let serial: u64 = (0..n as u64).map(|i| i * 3).sum();
        for &workers in &[0usize, 1, 2, 3, 8, 16] {
            let got = gatling_reduce(
                n,
                workers,
                || 0u64,
                |acc, i| *acc += (i as u64) * 3,
                |acc, p| *acc += p,
            );
            assert_eq!(got, serial, "reduce != serial fold (workers={workers})");
        }
        // Empty range ⇒ the identity.
        assert_eq!(
            gatling_reduce(0, 0, || 42u64, |acc, _| *acc += 1, |acc, p| *acc += p),
            42
        );
    }

    /// **RED-when-broken (scatter-reduce, the write-hazard case):** each unit writes into
    /// TWO overlapping slots of a shared buffer (`buf[a] += w; buf[b] += w`) — the exact
    /// hazard `gatling_for_each` cannot express. The parallel scatter-reduce (per-worker
    /// partial buffers, element-wise merged) must equal the serial scatter, bit-for-bit,
    /// for any worker count. A lost partial or aliased write diverges a bin and trips this.
    #[test]
    fn scatter_reduce_matches_serial_scatter() {
        let bins = 64usize;
        let edges: Vec<(usize, usize)> =
            (0..5_000).map(|i| (i % bins, (i * 7 + 3) % bins)).collect();
        // Serial reference.
        let mut want = vec![0.0f64; bins];
        for &(a, b) in &edges {
            want[a] += 1.5;
            want[b] += 1.5;
        }
        for &workers in &[0usize, 1, 2, 5, 12] {
            let got = gatling_reduce(
                edges.len(),
                workers,
                || vec![0.0f64; bins],
                |acc, i| {
                    let (a, b) = edges[i];
                    acc[a] += 1.5;
                    acc[b] += 1.5;
                },
                |acc, part| {
                    for (a, p) in acc.iter_mut().zip(part) {
                        *a += p;
                    }
                },
            );
            assert_eq!(
                got, want,
                "scatter-reduce != serial scatter (workers={workers})"
            );
        }
    }

    /// INJECT-ASSERT: the load-balanced variant returns results in ORIGINAL index
    /// order and runs every unit exactly once — across every worker/batch combo and
    /// a heavily skewed weight (a few monster units among many cheap ones). The
    /// heaviest-first schedule must not perturb the output ordering.
    #[test]
    fn balanced_is_ordered_and_complete() {
        for &workers in &[0usize, 1, 2, 8] {
            for &batch in &[1usize, 4, 32] {
                let n = 5_000;
                let out = gatling_for_each_balanced(
                    n,
                    workers,
                    batch,
                    // Skew: every 500th unit is a "monster", the rest are cheap.
                    |i| if i % 500 == 0 { 1_000_000 } else { 1 },
                    |i| i * 3,
                );
                assert_eq!(out.len(), n);
                for (i, v) in out.iter().enumerate() {
                    assert_eq!(
                        *v,
                        i * 3,
                        "unit {i} wrong (workers={workers}, batch={batch})"
                    );
                }
            }
        }
    }

    /// INJECT-ASSERT: `gatling_map_balanced` maps an owned work list to owned
    /// results in ORIGINAL item order, runs each item exactly once, passes the
    /// correct (index, &item) to `f`, and weights by the item itself — across every
    /// worker/batch combo and a skewed weight. Empty in ⇒ empty out.
    #[test]
    fn map_balanced_is_ordered_complete_and_item_ref() {
        for &workers in &[0usize, 1, 2, 8] {
            for &batch in &[1usize, 4, 32] {
                let n = 5_000usize;
                // Items carry their own LPT weight; a few are monsters.
                let items: Vec<u64> = (0..n as u64)
                    .map(|i| if i % 500 == 0 { 1_000_000 } else { 1 })
                    .collect();
                let out = gatling_map_balanced(
                    &items,
                    workers,
                    batch,
                    |&w| w,         // weight straight off the item
                    |i, &w| (i, w), // echo back (index, item) to verify
                );
                assert_eq!(out.len(), n);
                for (i, &(gi, gw)) in out.iter().enumerate() {
                    assert_eq!(
                        gi, i,
                        "item {i} out of order (workers={workers}, batch={batch})"
                    );
                    assert_eq!(gw, items[i], "item {i} got wrong &T");
                }
            }
        }
        let empty: Vec<u64> = Vec::new();
        assert!(gatling_map_balanced(&empty, 8, 4, |&w| w, |i, &w| (i, w)).is_empty());
    }

    /// INJECT-ASSERT: `batch == 0` is treated as `1` (no divide-by-zero / no hang),
    /// and a single unit still resolves.
    #[test]
    fn balanced_batch_zero_and_single_unit() {
        let out = gatling_for_each_balanced(1, 8, 0, |_| 1, |i| i + 7);
        assert_eq!(out, vec![7]);
        let out = gatling_for_each_balanced(3, 4, 0, |i| i as u64, |i| i * 10);
        assert_eq!(out, vec![0, 10, 20]);
    }

    /// INJECT-ASSERT: every index is visited exactly once (no dupes, no misses) —
    /// the self-dispatch counter hands each `i` to exactly one worker.
    #[test]
    fn run_visits_each_index_exactly_once() {
        let n = 50_000;
        let hits: Vec<AtomicUsize> = (0..n).map(|_| AtomicUsize::new(0)).collect();
        gatling_run(n, 0, |i| {
            hits[i].fetch_add(1, Ordering::Relaxed);
        });
        for (i, h) in hits.iter().enumerate() {
            assert_eq!(
                h.load(Ordering::Relaxed),
                1,
                "index {i} not visited exactly once"
            );
        }
    }

    /// INJECT-ASSERT: scanline raster fills every row's disjoint slice; the result
    /// equals the single-threaded fill (no row crosstalk).
    #[test]
    fn scanlines_fill_disjoint_rows_matching_sequential() {
        let (rows, stride) = (300usize, 256usize);
        let fill = |y: usize, row: &mut [u32]| {
            for (x, p) in row.iter_mut().enumerate() {
                *p = (y as u32) << 16 | x as u32;
            }
        };

        let mut par = vec![0u32; rows * stride];
        gatling_scanlines(&mut par, rows, stride, 0, 1, |y, row| fill(y, row));

        let mut seq = vec![0u32; rows * stride];
        for (y, row) in seq.chunks_mut(stride).enumerate() {
            fill(y, row);
        }
        assert_eq!(par, seq, "parallel scanline raster matches sequential");
        // Spot-check a known pixel.
        assert_eq!(par[42 * stride + 7], (42u32 << 16) | 7);
    }

    /// INJECT-ASSERT: the small-frame guard keeps tiny grids single-threaded but
    /// still correct.
    #[test]
    fn scanlines_small_frame_stays_correct() {
        let (rows, stride) = (4usize, 8usize);
        let mut buf = vec![0u8; rows * stride];
        gatling_scanlines(&mut buf, rows, stride, 0, 1024, |y, row| {
            row.iter_mut().for_each(|p| *p = y as u8);
        });
        for y in 0..rows {
            for x in 0..stride {
                assert_eq!(buf[y * stride + x], y as u8);
            }
        }
    }

    /// INJECT-ASSERT: `gatling_map_owned` consumes its input and returns the SAME
    /// elements in the SAME order as a serial `into_iter().map(f).collect()`, across
    /// sizes 0, 1, small and large — and works for a non-`Copy` payload (`String`),
    /// proving the move-out path drops nothing twice and re-orders nothing.
    #[test]
    fn map_owned_equals_serial_map_all_sizes() {
        for &n in &[0usize, 1, 7, 10_000] {
            // Copy payload: u64 -> u64.
            let v: Vec<u64> = (0..n as u64).map(|i| i.wrapping_mul(2654435761)).collect();
            let f = |x: u64| x.wrapping_add(123).rotate_left(7);
            let got = gatling_map_owned(v.clone(), f);
            let want: Vec<u64> = v.into_iter().map(f).collect();
            assert_eq!(got, want, "u64 map mismatch at n={n}");

            // Non-Copy payload: String -> String (move-out path).
            let s: Vec<String> = (0..n).map(|i| format!("item-{i}")).collect();
            let g = |mut x: String| {
                x.push_str("!");
                x
            };
            let got_s = gatling_map_owned(s.clone(), g);
            let want_s: Vec<String> = s.into_iter().map(g).collect();
            assert_eq!(got_s, want_s, "String map mismatch at n={n}");
        }
    }

    #[test]
    fn empty_inputs_are_noops() {
        assert!(gatling_for_each(0, 4, |i| i).is_empty());
        gatling_run(0, 4, |_| panic!("should not run"));
        let mut empty: Vec<u8> = Vec::new();
        gatling_scanlines(&mut empty, 0, 0, 4, 1, |_, _| panic!("should not run"));
    }
}
