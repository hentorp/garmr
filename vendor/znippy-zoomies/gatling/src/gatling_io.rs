//! Gatling I/O — the **async** sibling of the sync [`gatling`](crate::gatling) engine.
//!
//! [`gatling::run`](crate::gatling::run) / [`gatling::run_typed`](crate::gatling::run_typed)
//! are a **sync, OS-thread** engine: they own a `std::thread::scope`, pull a
//! [`Read`](std::io::Read) byte stream, split it into zero-copy slot slices, and
//! fan **CPU transforms** across N worker *threads*. That is exactly right when the
//! work is **CPU-bound** (bz2 decode, XML parse, Parquet encode): one thread per
//! core, no executor, pointers straight into the slot ring.
//!
//! It is exactly *wrong* for the other shape of work: **I/O-bound** jobs that are
//! already-formed payloads (a pre-encoded Parquet blob to `PUT` to S3, a ranged
//! `GET`, an `fsync`). There the cost is **per-op latency** (an HTTP round-trip),
//! not CPU; a thread blocked on a socket is a thread doing nothing, and the
//! `Read`-split / slot-ring substrate has nothing to split — the unit of work is a
//! whole `Bytes` value, not a byte range a worker carves out of a stream.
//!
//! # Same philosophy, different substrate
//!
//! `gatling::io` keeps **every** gatling invariant and swaps only the substrate:
//!
//! | property                | sync [`gatling::run`](crate::gatling::run) | async [`gatling::io::run`](run) |
//! |-------------------------|--------------------------------------------|---------------------------------|
//! | concurrency primitive   | `std::thread::scope`, N OS threads         | N in-flight `Future`s on tokio  |
//! | work shape              | **CPU-bound** transform of byte ranges     | **I/O-bound** async job → result |
//! | input                   | a [`Read`] stream the engine splits        | an **iterator/stream of jobs**  |
//! | no barrier              | slot N+1 dispatched while N still decoding  | job N+1 admitted while N in flight |
//! | bounded / N-in-flight   | `ring_slots` slots, workers block on pool  | `max_in_flight`, like `buffer_unordered` |
//! | backpressure            | reader blocks when the slot pool drains    | admission blocks when the cap is full |
//! | ordered output          | collector flushes by `chunk_id`            | [`run_ordered`] re-sequences by job index |
//! | zero-copy payload       | raw pointer into the slot                  | [`bytes::Bytes`] moved, never cloned |
//!
//! Both are **no-barrier**: there is no "submit all, then await all" stall. New
//! work is admitted the instant a slot/permit frees, so the pipeline runs at the
//! steady-state width (`ring_slots` / `max_in_flight`) from the first job to the
//! last — the property that lets the sync engine overlap decode with read, and
//! lets this engine overlap PUT *k+1*'s round-trip with PUT *k*'s.
//!
//! # When to reach for which
//!
//! - **CPU transform of a stream** (decode, parse, encode) → [`gatling::run`](crate::gatling::run)
//!   / [`run_typed`](crate::gatling::run_typed). Threads, not tasks.
//! - **Latency-bound async I/O over a set of ready payloads** (S3 PUT/GET fan-out,
//!   many `fsync`s, network calls) → this module. Tasks, not threads.
//!
//! # API
//!
//! Submit a stream of async jobs; the engine keeps ≤ `max_in_flight` running,
//! applies backpressure on admission, and yields results as they finish
//! ([`run`], fastest-first) or re-sequenced into submission order ([`run_ordered`]).
//! A job is any `Future` you build per item — typically `async move { put(bytes).await }`.
//! Payloads are [`bytes::Bytes`], so the buffer is moved into the job and out as a
//! result with no deep copy.
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use gatling::gatling::io;
//! use bytes::Bytes;
//!
//! let jobs = (0..100u64).map(|seq| async move {
//!     // …PUT a pre-encoded blob to S3 and return its descriptor…
//!     let body = Bytes::from(vec![0u8; 1024]);
//!     upload(seq, body).await
//! });
//!
//! // ≤ 16 PUTs in flight; results delivered in submission order.
//! let descriptors: Vec<Descriptor> =
//!     io::run_ordered(jobs, 16, |d| d).await?;
//! # Ok(()) }
//! # struct Descriptor;
//! # async fn upload(_: u64, _: bytes::Bytes) -> anyhow::Result<Descriptor> { Ok(Descriptor) }
//! ```

use std::future::Future;

use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};

/// Drive an iterator of async jobs with **no barrier** and at most `max_in_flight`
/// running at once, invoking `on_result` for each finished job **as it completes**
/// (fastest-first, *not* submission order — use [`run_ordered`] when you need order).
///
/// This is `buffer_unordered` with explicit admission control: the loop tops the
/// in-flight set up to the cap, awaits the next finished job, hands its value to
/// `on_result`, then refills — so a new job starts the instant a slot frees, and
/// the iterator is only pulled (and the next payload only materialised) when there
/// is room. That bounds memory to ≈ `max_in_flight` outstanding payloads and lets
/// the producer block naturally when the consumer falls behind (backpressure).
///
/// The first error returned by any job (or by `on_result`) short-circuits: the
/// remaining in-flight jobs are dropped and the error is propagated.
///
/// `Jobs` yields the `Future`s; `Fut::Output` is `Result<T>`; `on_result` consumes
/// each `T` (e.g. pushes a `DataFile` descriptor, bumps a counter). Keeping the
/// reduction in a closure means the engine never has to buffer all results.
pub async fn run<Jobs, Fut, T, R>(
    jobs: Jobs,
    max_in_flight: usize,
    mut on_result: impl FnMut(T) -> Result<R>,
) -> Result<()>
where
    Jobs: IntoIterator<Item = Fut>,
    Fut: Future<Output = Result<T>>,
{
    let cap = max_in_flight.max(1);
    let mut jobs = jobs.into_iter();
    let mut in_flight = FuturesUnordered::new();
    let mut exhausted = false;

    loop {
        // No barrier: admit new jobs up to the cap the moment there is room. The
        // iterator is pulled lazily, so payload k+1 is only built once a slot frees.
        while !exhausted && in_flight.len() < cap {
            match jobs.next() {
                Some(fut) => in_flight.push(fut),
                None => exhausted = true,
            }
        }
        if in_flight.is_empty() {
            break; // nothing running and nothing left to admit
        }
        // Await whichever job finishes first, reduce it, then loop to refill.
        match in_flight.next().await {
            Some(res) => {
                let value = res?;
                on_result(value)?;
            }
            None => break,
        }
    }
    Ok(())
}

/// Like [`run`], but delivers results **in submission order** — job 0's result is
/// handed to `on_result` first, then job 1, … — while still keeping up to
/// `max_in_flight` jobs running concurrently (no barrier, bounded, backpressured).
///
/// Concurrency and ordering are independent here: jobs *execute* out of order
/// (fastest-first, fully overlapped up to the cap), but their *outputs* are
/// re-sequenced by the index the engine stamps on each job at admission. A small
/// reorder buffer holds at most `max_in_flight` finished-early results until the
/// next in-order index lands, so peak buffered results never exceeds the in-flight
/// cap. This is the async analogue of the sync collector flushing slots strictly
/// by `chunk_id`.
///
/// Returns the collected `Vec<R>` in submission order, where `R` is what
/// `map_result` produces from each job's `T`.
pub async fn run_ordered<Jobs, Fut, T, R>(
    jobs: Jobs,
    max_in_flight: usize,
    mut map_result: impl FnMut(T) -> R,
) -> Result<Vec<R>>
where
    Jobs: IntoIterator<Item = Fut>,
    Fut: Future<Output = Result<T>>,
{
    let cap = max_in_flight.max(1);
    let mut jobs = jobs.into_iter().enumerate();
    // Each in-flight future carries its submission index so completions can be
    // re-sequenced regardless of the order they finish in.
    let mut in_flight = FuturesUnordered::new();
    let mut exhausted = false;

    // Reorder buffer: index → finished result awaiting its turn to be emitted.
    let mut pending: std::collections::BTreeMap<usize, R> = std::collections::BTreeMap::new();
    let mut next_emit = 0usize;
    let mut out: Vec<R> = Vec::new();

    loop {
        while !exhausted && in_flight.len() < cap {
            match jobs.next() {
                Some((idx, fut)) => {
                    in_flight.push(async move { (idx, fut.await) });
                }
                None => exhausted = true,
            }
        }
        if in_flight.is_empty() {
            break;
        }
        match in_flight.next().await {
            Some((idx, res)) => {
                pending.insert(idx, map_result(res?));
                // Drain every result that is now contiguous from `next_emit`.
                while let Some(val) = pending.remove(&next_emit) {
                    out.push(val);
                    next_emit += 1;
                }
            }
            None => break,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// LAW (inject-and-assert): inject N real jobs, assert ALL run, assert the
    /// observed concurrency never exceeds the cap AND actually reaches it (so the
    /// no-barrier admission really overlapped work, not merely requested it), and
    /// assert the collected results are correct **and in submission order**.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn run_ordered_keeps_cap_and_preserves_order() {
        const N: usize = 100;
        const CAP: usize = 8;

        let ran = Arc::new(AtomicUsize::new(0));
        let inflight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        // Jobs finish in a deliberately scrambled order (later jobs sometimes
        // finish first) so the ordered collector has real reordering to do.
        let jobs = (0..N).map(|i| {
            let ran = Arc::clone(&ran);
            let inflight = Arc::clone(&inflight);
            let peak = Arc::clone(&peak);
            async move {
                let now = inflight.fetch_add(1, Ordering::AcqRel) + 1;
                peak.fetch_max(now, Ordering::AcqRel);
                // Scramble completion order: invert the delay so high i finishes
                // sooner, forcing the reorder buffer to hold low-i results.
                let delay = ((N - i) % 11 + 1) as u64;
                tokio::time::sleep(Duration::from_millis(delay)).await;
                ran.fetch_add(1, Ordering::AcqRel);
                inflight.fetch_sub(1, Ordering::AcqRel);
                // Return the squared value so we can assert real output per index.
                Ok::<usize, anyhow::Error>(i * i)
            }
        });

        let out = run_ordered(jobs, CAP, |v| v)
            .await
            .expect("run_ordered failed");

        // All jobs ran.
        assert_eq!(ran.load(Ordering::Acquire), N, "not every job ran");
        // Results are correct AND in submission order (0², 1², …, (N-1)²).
        assert_eq!(out.len(), N, "wrong number of results");
        for (i, v) in out.iter().enumerate() {
            assert_eq!(*v, i * i, "result {i} out of order or wrong value");
        }
        // Concurrency was bounded by the cap…
        let peak = peak.load(Ordering::Acquire);
        assert!(peak <= CAP, "exceeded in-flight cap: peak={peak} cap={CAP}");
        // …and actually reached it (the no-barrier admission overlapped work).
        assert_eq!(peak, CAP, "never reached the in-flight cap: peak={peak}");
    }

    /// `run` (unordered) must also bound concurrency and run every job, reducing
    /// each result through the closure. Assert the reduced sum is exact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn run_unordered_bounds_concurrency_and_reduces_all() {
        const N: usize = 50;
        const CAP: usize = 5;

        let inflight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let jobs = (0..N).map(|i| {
            let inflight = Arc::clone(&inflight);
            let peak = Arc::clone(&peak);
            async move {
                let now = inflight.fetch_add(1, Ordering::AcqRel) + 1;
                peak.fetch_max(now, Ordering::AcqRel);
                tokio::time::sleep(Duration::from_millis(2)).await;
                inflight.fetch_sub(1, Ordering::AcqRel);
                Ok::<u64, anyhow::Error>(i as u64)
            }
        });

        let sum = Arc::new(AtomicUsize::new(0));
        let sum2 = Arc::clone(&sum);
        run(jobs, CAP, move |v| {
            sum2.fetch_add(v as usize, Ordering::AcqRel);
            Ok(())
        })
        .await
        .expect("run failed");

        // Every job's value was reduced exactly once: 0+1+…+(N-1).
        let expected: usize = (0..N).sum();
        assert_eq!(
            sum.load(Ordering::Acquire),
            expected,
            "reduce dropped/dup'd a job"
        );
        let peak = peak.load(Ordering::Acquire);
        assert!(peak <= CAP, "exceeded cap: peak={peak} cap={CAP}");
        assert_eq!(peak, CAP, "never reached cap: peak={peak}");
    }

    /// A failing job short-circuits and propagates its error.
    #[tokio::test]
    async fn run_propagates_first_error() {
        let jobs = (0..10usize).map(|i| async move {
            if i == 3 {
                Err(anyhow::anyhow!("boom at {i}"))
            } else {
                Ok::<usize, anyhow::Error>(i)
            }
        });
        let err = run(jobs, 4, |_v| Ok(()))
            .await
            .expect_err("should have errored");
        assert!(err.to_string().contains("boom"), "wrong error: {err}");
    }
}
