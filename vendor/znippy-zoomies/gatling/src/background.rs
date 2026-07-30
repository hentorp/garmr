//! Single background job — the one-worker degenerate of the gatling pool.
//!
//! For **producer/consumer overlap** (double-buffering), not fan-out: run one
//! `Send` closure on a dedicated thread while the caller keeps producing, then
//! [`Job::join`] for its result. The canonical use is a spill/sort/write stage
//! that overlaps the next decode pass — one job in flight at a time (join the
//! previous before spawning the next), so it is a depth-1 pipeline, not a pool.
//!
//! This module is the sanctioned home for the raw `std::thread::spawn` that the
//! one-engine "rayon-free" law forbids in every non-engine crate: callers get
//! overlap by calling [`Job::spawn`] instead of hand-rolling a thread, so all
//! threading in the constellation still originates in `gatling`. It deliberately
//! owns no work-stealing, no shared cursor, no reader — for parallel fan-out use
//! [`crate::gatling_forkjoin::gatling_for_each`] or the streaming
//! [`crate::gatling::run`] engine instead.

use std::thread::{self, JoinHandle};

/// A single closure running on its own thread. Create with [`Job::spawn`], reap
/// with [`Job::join`]. Dropping a `Job` without joining detaches the thread (the
/// closure runs to completion but its result and any panic are lost) — the
/// overlap pattern always joins, so prefer explicit [`Job::join`].
#[must_use = "a Job runs in the background; join it to observe its result / propagate panics"]
pub struct Job<T: Send + 'static> {
    handle: JoinHandle<T>,
}

impl<T: Send + 'static> Job<T> {
    /// Spawn `f` on a fresh background thread and return immediately. The caller
    /// keeps working; call [`Job::join`] later to block for the result.
    #[inline]
    pub fn spawn<F>(f: F) -> Self
    where
        F: FnOnce() -> T + Send + 'static,
    {
        Job {
            handle: thread::spawn(f),
        }
    }

    /// Block until the job finishes and return its value. A panic inside the job
    /// is surfaced as `Err` (identical semantics to [`JoinHandle::join`]) rather
    /// than aborting the caller.
    #[inline]
    pub fn join(self) -> thread::Result<T> {
        self.handle.join()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_and_returns_value() {
        let job = Job::spawn(|| 2 + 2);
        assert_eq!(job.join().unwrap(), 4);
    }

    #[test]
    fn overlaps_caller_work() {
        // The producer keeps working while the job runs; the sum is observed
        // only after join — a depth-1 pipeline.
        let job = Job::spawn(|| (0u64..1_000).sum::<u64>());
        let mut local = 0u64;
        for i in 0..1_000 {
            local += i;
        }
        assert_eq!(job.join().unwrap(), local);
    }

    #[test]
    fn panic_becomes_err_not_abort() {
        let job = Job::spawn(|| panic!("boom"));
        assert!(job.join().is_err());
    }
}
