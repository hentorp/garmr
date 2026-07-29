//! Gatling (ordered streaming sink) — the **item-oriented** sibling of the byte
//! streaming engine, for a labelled-discrete-entry pipeline.
//!
//! Where [`crate::gatling::run`] / [`run_typed`](crate::gatling::run_typed) own
//! the reader and *split* one byte stream into segments, this variant does **no
//! reading and no splitting**. The caller stays the producer: it yields discrete
//! **labelled items** `(Label, Input)` (e.g. znippy's io_uring batched small-file
//! reader handing over `(path, bytes)`), the engine fans them across N workers
//! that run a caller `map`, and the outputs are streamed to a caller [`OrderedSink`]
//! in **producer order** through a **bounded** reorder buffer.
//!
//! ```text
//! Producer.next() → [dispatch] → N Workers(map) → [collector: reorder] → Sink.emit(seq, out)
//!        ▲ pulled only when a permit is free (≤ cap items alive)                │
//!        └──────────────── permit released after each in-order emit ───────────┘
//! ```
//!
//! # The gatling soul, kept
//! - **No barrier / self-dispatch.** Workers pull the next item the instant they
//!   finish the last one (LPT) — never a static chunk-per-worker carve-up. A slow
//!   item never idles a sibling.
//! - **rayon-free.** Pure `std::thread::scope` + `std::sync::mpsc`; no global pool.
//! - **Ordered out.** The collector emits strictly in producer sequence, so the
//!   sink can `pwrite` to an archive and record offsets/metadata incrementally.
//!
//! # What this variant adds over the existing API
//! - **Lazy pull + backpressure.** The producer is pulled **only when a worker
//!   slot is free** — at most `cap` items are *alive* (pulled-but-not-yet-emitted)
//!   at any instant. A single counting-permit pool (primed with `cap` tokens)
//!   gates the producer: acquire a permit before pulling, release it after the
//!   item is emitted. Memory is bounded by `cap`, not by the input length.
//! - **Streaming sink, never a RAM `Vec`.** Outputs are handed to the sink one at
//!   a time as each in-order output becomes ready; the reorder buffer holds at
//!   most `cap` outputs, so a slow item near the front applies backpressure to the
//!   producer instead of letting the buffer grow without bound.
//! - **Deterministic.** Same producer sequence + same `map` ⇒ identical ordered
//!   output for any worker count (emit order is the producer order, `map` is pure).
//!
//! # Example
//! ```
//! use gatling::gatling::ordered::{run_ordered_sink, OrderedSink};
//!
//! // Producer: 100 labelled items, pulled lazily.
//! let mut next = 0usize;
//! let producer = move || {
//!     if next < 100 { let i = next; next += 1; Some((i, vec![i as u8; 4])) }
//!     else { None }
//! };
//!
//! // Sink: collect outputs in producer order.
//! let mut out: Vec<(u64, usize)> = Vec::new();
//! run_ordered_sink(
//!     producer,
//!     /* workers */ 8,
//!     /* cap     */ 16,
//!     /* map     */ |label: usize, bytes: Vec<u8>| (label, bytes.len()),
//!     /* sink    */ &mut |seq, (label, len)| { out.push((seq, label)); let _ = len; Ok(()) },
//! ).unwrap();
//!
//! assert_eq!(out.len(), 100);
//! assert!(out.iter().enumerate().all(|(i, &(seq, label))| seq as usize == i && label == i));
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};

use anyhow::Result;

/// Streaming consumer of ordered outputs. The collector calls [`emit`](Self::emit)
/// exactly once per item, in **strict producer order** (`seq = 0, 1, 2, …`), as
/// each in-order output becomes ready. A `&mut` method, so the sink owns mutable
/// state (an archive writer, an offset table) and updates it incrementally — it is
/// never handed the whole output set at once.
///
/// A blanket impl is provided for `FnMut(u64, O) -> Result<()>`, so a closure can
/// be passed directly as the sink.
pub trait OrderedSink<O> {
    /// Consume the output for producer sequence `seq`. Called in order, once per
    /// item. Returning `Err` aborts the run; the error propagates out of
    /// [`run_ordered_sink`].
    fn emit(&mut self, seq: u64, output: O) -> Result<()>;
}

impl<O, F> OrderedSink<O> for F
where
    F: FnMut(u64, O) -> Result<()>,
{
    #[inline]
    fn emit(&mut self, seq: u64, output: O) -> Result<()> {
        self(seq, output)
    }
}

/// Run an **item-oriented, ordered, streaming-sink** gatling to completion.
///
/// - `producer` is pulled lazily — `next()`-style `FnMut` returning `Some((label,
///   input))` per item and `None` at end of stream. It is pulled **only when a
///   worker slot is free** (≤ `cap` items alive), so the caller's reader is itself
///   back-pressured and total memory is bounded by `cap`, never by stream length.
/// - `n_workers` map workers run `map(label, input) -> output` with no barrier
///   (self-dispatch: each pulls the next item as soon as it finishes its last).
/// - `cap` is the in-flight / reorder-buffer bound: the maximum number of items
///   that may be pulled-but-not-yet-emitted at once. `0` ⇒ `max(2 * n_workers, 1)`.
/// - `sink` receives outputs via [`OrderedSink::emit`] in strict producer order,
///   one at a time as they become ready — the reorder buffer holds ≤ `cap` outputs.
///
/// Determinism: same producer sequence + same `map` ⇒ identical ordered emit
/// sequence for any `n_workers`.
///
/// Threading: the collector runs on the **calling thread** (so `sink` need not be
/// `Send` and stays where the caller built it); the producer dispatch loop and the
/// `n_workers` map workers run on scoped threads joined before return.
pub fn run_ordered_sink<L, I, O, P, M, S>(
    producer: P,
    n_workers: usize,
    cap: usize,
    map: M,
    sink: &mut S,
) -> Result<()>
where
    L: Send,
    I: Send,
    O: Send,
    P: FnMut() -> Option<(L, I)> + Send,
    M: Fn(L, I) -> O + Sync,
    S: OrderedSink<O>,
{
    let n_workers = n_workers.max(1);
    let cap = if cap == 0 {
        (2 * n_workers).max(1)
    } else {
        cap
    };

    // ── Permit pool (the backpressure / boundedness invariant) ────────────────
    // Primed with exactly `cap` tokens. The dispatch thread must hold a token to
    // pull the producer; the collector returns one after each in-order emit. So at
    // every instant: (items pulled) − (items emitted) ≤ cap. That single counter
    // bounds the sum over { work channel, workers, result channel, reorder buffer }.
    let (permit_tx, permit_rx) = mpsc::channel::<()>();
    for _ in 0..cap {
        permit_tx.send(()).expect("prime permit pool");
    }

    let map_ref = &map;

    let result = std::thread::scope(|s| -> Result<()> {
        // Work channel: dispatch → workers (shared receiver = self-dispatch).
        let (work_tx, work_rx) = mpsc::sync_channel::<(u64, L, I)>(n_workers * 2);
        let work_rx = Arc::new(Mutex::new(work_rx));
        // Result channel: workers → collector (this thread).
        let (result_tx, result_rx) = mpsc::sync_channel::<(u64, O)>(n_workers * 4);

        // ── Dispatch thread: lazy pull + sequence-number stamp ────────────────
        // Acquire a permit, pull one item, stamp it with the next producer seq,
        // hand it to a worker. When the producer is drained (or its permit can no
        // longer be acquired because the run is ending) the loop exits and drops
        // `work_tx`, which closes the work channel and lets the workers finish.
        s.spawn(move || {
            let mut producer = producer;
            let mut seq: u64 = 0;
            loop {
                // Blocks here once `cap` items are alive — this is the backpressure
                // that stops the producer from racing ahead of the sink.
                if permit_rx.recv().is_err() {
                    break;
                }
                match producer() {
                    Some((label, input)) => {
                        if work_tx.send((seq, label, input)).is_err() {
                            break;
                        }
                        seq += 1;
                    }
                    None => break,
                }
            }
        });

        // ── Map workers (persistent, no barrier, self-dispatch) ───────────────
        for _ in 0..n_workers {
            let work_rx = Arc::clone(&work_rx);
            let result_tx = result_tx.clone();
            s.spawn(move || {
                loop {
                    let item = {
                        let rx = work_rx.lock().expect("work_rx lock");
                        match rx.recv() {
                            Ok(item) => item,
                            Err(_) => break,
                        }
                    };
                    let (seq, label, input) = item;
                    let output = map_ref(label, input);
                    if result_tx.send((seq, output)).is_err() {
                        break;
                    }
                }
            });
        }
        // Drop the main-thread handles so the channels close once the spawned
        // owners (dispatch / workers) drop theirs.
        drop(work_rx);
        drop(result_tx);

        // ── Collector (this thread): bounded reorder + ordered streaming emit ──
        // `buffer` holds outputs that arrived ahead of their turn; it never exceeds
        // `cap` entries because a permit is released only *after* an emit, so the
        // producer cannot pull past `cap` un-emitted items.
        let mut buffer: HashMap<u64, O> = HashMap::new();
        let mut next_emit: u64 = 0;
        while let Ok((seq, output)) = result_rx.recv() {
            buffer.insert(seq, output);
            while let Some(out) = buffer.remove(&next_emit) {
                sink.emit(next_emit, out)?;
                next_emit += 1;
                // Release a permit so the producer may pull one more item.
                permit_tx.send(()).ok();
            }
        }

        Ok(())
    });

    // Introspection marker: the bounded ordered run finished (ok = clean drain).
    #[cfg(feature = "testmatrix")]
    crate::functional_status(
        "gatling_ordered",
        "run_ordered_sink",
        result.is_ok(),
        &format!("n_workers={n_workers} cap={cap} ok={}", result.is_ok()),
    );

    result
}
