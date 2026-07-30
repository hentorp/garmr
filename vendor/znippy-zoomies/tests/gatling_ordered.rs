//! Integration tests for the item-oriented **ordered streaming-sink** gatling
//! (`gatling::ordered::run_ordered_sink`).
//!
//! Contract under test:
//! - ordered output equals a serial baseline **byte-for-byte** across worker
//!   counts (1 vs 8);
//! - the sink receives outputs in **strict producer order** (`seq = 0,1,2,…`);
//! - the reorder buffer / in-flight set is **bounded** — a deliberately-slow item
//!   near the front does NOT let the pulled-but-not-emitted count exceed `cap`
//!   (proving backpressure / bounded memory);
//! - **determinism** — same input ⇒ same ordered output.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use znippy_zoomies::gatling::ordered::{OrderedSink, run_ordered_sink};

/// Deterministic xorshift64* item-byte generator (no `rand`): item `i` is a small
/// `Vec<u8>` whose contents depend only on `i`, so the whole input is reproducible.
fn make_item(i: usize) -> Vec<u8> {
    let mut s = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let len = 1 + (i % 17);
    (0..len)
        .map(|_| {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8
        })
        .collect()
}

/// The per-item map: a pure, label-dependent transform standing in for "compress
/// this chunk → (BlobMeta, bytes)". Output carries the label so ordering is checkable.
fn map_item(label: usize, input: Vec<u8>) -> (usize, Vec<u8>) {
    let out: Vec<u8> = input
        .iter()
        .map(|&b| b.wrapping_add(label as u8) ^ 0x3C)
        .collect();
    (label, out)
}

/// Serial reference: pull items `0..n` in order and map them on this thread.
fn serial_baseline(n: usize) -> Vec<(usize, Vec<u8>)> {
    (0..n).map(|i| map_item(i, make_item(i))).collect()
}

/// Build a lazy producer over items `0..n`.
fn producer_for(n: usize) -> impl FnMut() -> Option<(usize, Vec<u8>)> + Send {
    let mut next = 0usize;
    move || {
        if next < n {
            let i = next;
            next += 1;
            Some((i, make_item(i)))
        } else {
            None
        }
    }
}

/// Sink that records every emitted `(seq, output)` and asserts strict in-order
/// delivery as it goes.
struct OrderCheckSink {
    seen: Vec<(usize, Vec<u8>)>,
    expect_seq: u64,
}

impl OrderedSink<(usize, Vec<u8>)> for OrderCheckSink {
    fn emit(&mut self, seq: u64, output: (usize, Vec<u8>)) -> Result<()> {
        assert_eq!(
            seq, self.expect_seq,
            "sink received outputs out of producer order"
        );
        self.expect_seq += 1;
        self.seen.push(output);
        Ok(())
    }
}

fn run_collect(n: usize, n_workers: usize, cap: usize) -> Vec<(usize, Vec<u8>)> {
    let mut sink = OrderCheckSink {
        seen: Vec::new(),
        expect_seq: 0,
    };
    run_ordered_sink(producer_for(n), n_workers, cap, map_item, &mut sink)
        .expect("run_ordered_sink");
    sink.seen
}

#[test]
fn ordered_output_matches_serial_baseline_1_vs_8() {
    // The core contract: ordered output equals the serial baseline byte-for-byte,
    // and is identical for 1 vs 8 workers (worker count must not change output).
    let n = 5_000;
    let baseline = serial_baseline(n);
    let one = run_collect(n, 1, 32);
    let many = run_collect(n, 8, 32);
    assert_eq!(one, baseline, "1-worker output != serial baseline");
    assert_eq!(many, baseline, "8-worker output != serial baseline");
    assert_eq!(one, many, "worker count changed the ordered output");
}

#[test]
fn sink_receives_strict_producer_order() {
    // `OrderCheckSink::emit` already asserts seq monotonicity in-flight; here we
    // also confirm the recorded labels are exactly 0,1,2,…,n-1.
    let n = 2_000;
    let seen = run_collect(n, 8, 16);
    assert_eq!(seen.len(), n);
    assert!(
        seen.iter().enumerate().all(|(i, (label, _))| *label == i),
        "emitted labels are not in producer order"
    );
}

#[test]
fn reorder_buffer_is_bounded_under_slow_front_item() {
    // A deliberately-slow item near the FRONT (seq 0) stalls every later output in
    // the reorder buffer. Boundedness contract: the pulled-but-not-emitted count
    // must never exceed `cap`. We instrument the producer (increment on pull) and
    // the sink (decrement on emit) with a shared counter and track its peak.
    let n = 1_000;
    let n_workers = 4;
    let cap = 16;

    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));

    // Producer: count each pulled item and record the running peak.
    let prod = {
        let in_flight = Arc::clone(&in_flight);
        let max_seen = Arc::clone(&max_seen);
        let mut next = 0usize;
        move || {
            if next >= n {
                return None;
            }
            let i = next;
            next += 1;
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(now, Ordering::SeqCst);
            Some((i, make_item(i)))
        }
    };

    // Map: stall item 0 so all later items pile into the reorder buffer behind it.
    let map = |label: usize, input: Vec<u8>| {
        if label == 0 {
            std::thread::sleep(Duration::from_millis(300));
        }
        map_item(label, input)
    };

    // Sink: decrement the in-flight counter as each in-order output is emitted.
    let in_flight_sink = Arc::clone(&in_flight);
    let mut emitted = 0usize;
    let mut sink = move |seq: u64, _out: (usize, Vec<u8>)| -> Result<()> {
        assert_eq!(
            seq as usize, emitted,
            "out-of-order emit under slow front item"
        );
        emitted += 1;
        in_flight_sink.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    };

    run_ordered_sink(prod, n_workers, cap, map, &mut sink).expect("run_ordered_sink");

    let peak = max_seen.load(Ordering::SeqCst);
    assert!(
        peak <= cap,
        "in-flight/buffered peak {peak} exceeded cap {cap} (unbounded!)"
    );
    // And prove the reorder buffer actually held items beyond the active workers —
    // i.e. backpressure didn't collapse the pipeline to serial; it buffered up to cap.
    assert!(
        peak > n_workers,
        "peak {peak} did not exceed worker count {n_workers}; reorder buffering never engaged"
    );
}

#[test]
fn deterministic_same_input_same_output() {
    // Same producer sequence + same map ⇒ identical ordered output across runs,
    // regardless of worker scheduling.
    let n = 3_333;
    let a = run_collect(n, 8, 64);
    let b = run_collect(n, 8, 64);
    let c = run_collect(n, 3, 7);
    assert_eq!(a, b, "two identical runs diverged");
    assert_eq!(a, c, "different worker/cap changed the ordered output");
}

#[test]
fn empty_producer_is_a_noop() {
    let seen = run_collect(0, 8, 16);
    assert!(seen.is_empty());
}

#[test]
fn cap_smaller_than_workers_is_correct() {
    // cap < n_workers throttles to fewer alive items than workers — still correct,
    // just less parallel. Output must remain the serial baseline.
    let n = 500;
    let seen = run_collect(n, 8, 2);
    assert_eq!(seen, serial_baseline(n));
}
