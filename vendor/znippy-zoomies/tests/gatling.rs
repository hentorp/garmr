//! Integration tests for the sync `gatling` no-barrier streaming engine.
//!
//! The engine's defining contract is **ordered** output: the reader splits each
//! chunk into N segments, N worker threads decode/transform them out of order,
//! and the collector must re-emit the results in strict stream order. These
//! tests drive both `gatling::run` (byte mode) and `gatling::run_typed` (typed
//! mode) over real inputs with multiple chunks and multiple segments per chunk,
//! and assert the assembled output equals a serial baseline byte-for-byte — any
//! reordering or dropped segment corrupts the comparison.

use znippy_zoomies::gatling::{self, Codec, Config, Sink, SlotFill, Split, TypedCodec, TypedSink};

use anyhow::Result;

/// Deterministic xorshift64* corpus generator (no `rand` needed for the input).
fn make_input(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            (s.wrapping_mul(0x2545F4914F6CDD1D) >> 33) as u8
        })
        .collect()
}

/// The transform both modes apply per byte: a non-trivial, position-independent
/// map so the serial baseline is just `b.wrapping_add(0x5A) ^ 0x3C`.
#[inline]
fn xform(b: u8) -> u8 {
    b.wrapping_add(0x5A) ^ 0x3C
}

fn serial_baseline(input: &[u8]) -> Vec<u8> {
    input.iter().map(|&b| xform(b)).collect()
}

// ── Byte mode (`run`) ─────────────────────────────────────────────────────────

/// Splits each chunk into `n_workers` contiguous segments covering the whole
/// chunk, decode = per-byte `xform`. `Seg` is a (start,end) range into the slice
/// `split` was given (the same slice `decode` receives).
struct ByteCodec;

impl Codec for ByteCodec {
    type Seg = (usize, usize);

    fn split(&self, data: &[u8], n_workers: usize, _is_last: bool) -> Option<Split<Self::Seg>> {
        if data.is_empty() {
            return None;
        }
        let n = n_workers.max(1).min(data.len());
        let base = data.len() / n;
        let mut segments = Vec::with_capacity(n);
        let mut start = 0;
        for i in 0..n {
            let end = if i == n - 1 { data.len() } else { start + base };
            segments.push((start, end));
            start = end;
        }
        // Consume the whole chunk: no carry, so the assembled stream is exactly
        // the transformed input in order.
        Some(Split {
            segments,
            consumed: data.len(),
        })
    }

    fn decode(&self, data: &[u8], seg: &Self::Seg) -> Vec<u8> {
        data[seg.0..seg.1].iter().map(|&b| xform(b)).collect()
    }
}

/// Sink that consumes every decoded byte (safe_end = full length) and appends it
/// in delivery order, so the accumulated buffer reflects the engine's ordering.
struct CollectSink {
    out: Vec<u8>,
    calls: usize,
}

impl Sink for CollectSink {
    fn safe_end(&self, assembled: &[u8], _is_last: bool) -> usize {
        assembled.len()
    }
    fn process(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.extend_from_slice(bytes);
        self.calls += 1;
        Ok(())
    }
}

fn run_byte_mode(input: &[u8], n_workers: usize, chunk_size: usize) -> Vec<u8> {
    let mut sink = CollectSink {
        out: Vec::new(),
        calls: 0,
    };
    let cfg = Config {
        chunk_size,
        carry_headroom: 0,
        ring_slots: 4,
        initial_carry: Vec::new(),
        slot_fill: SlotFill::Incremental,
    };
    gatling::run(input, ByteCodec, &mut sink, n_workers, cfg).expect("gatling::run");
    sink.out
}

#[test]
fn byte_mode_output_is_ordered_multi_chunk() {
    // Input spans ~160 chunks, each fanned to 4 workers → ~640 segments decoded
    // out of order. Ordered assembly must reproduce the serial transform exactly.
    let input = make_input(10_240, 0xABCDEF);
    let got = run_byte_mode(&input, 4, 64);
    assert_eq!(got.len(), input.len());
    assert_eq!(
        got,
        serial_baseline(&input),
        "byte-mode output not in stream order"
    );
}

#[test]
fn byte_mode_single_worker_matches_multi_worker() {
    // Determinism across worker counts: 1 vs 8 workers must yield identical bytes.
    let input = make_input(7_000, 0x13579B);
    let one = run_byte_mode(&input, 1, 100);
    let many = run_byte_mode(&input, 8, 100);
    assert_eq!(one, serial_baseline(&input));
    assert_eq!(one, many, "worker count changed the output");
}

#[test]
fn byte_mode_input_smaller_than_one_chunk() {
    // Single-chunk path (input < chunk_size): still must transform correctly.
    let input = make_input(50, 0x2468);
    let got = run_byte_mode(&input, 4, 4096);
    assert_eq!(got, serial_baseline(&input));
}

// ── Typed mode (`run_typed`) ──────────────────────────────────────────────────

/// Typed codec: transform returns the (identity) bytes of its segment as a
/// `Vec<u8>` tagged with nothing — the collector forwards each output in stream
/// order, so concatenating the outputs must reproduce the original input.
struct TypedIdentityCodec;

impl TypedCodec for TypedIdentityCodec {
    type Seg = (usize, usize);
    type Output = Vec<u8>;

    fn split(&self, data: &[u8], n_workers: usize, _is_last: bool) -> Option<Split<Self::Seg>> {
        if data.is_empty() {
            return None;
        }
        let n = n_workers.max(1).min(data.len());
        let base = data.len() / n;
        let mut segments = Vec::with_capacity(n);
        let mut start = 0;
        for i in 0..n {
            let end = if i == n - 1 { data.len() } else { start + base };
            segments.push((start, end));
            start = end;
        }
        Some(Split {
            segments,
            consumed: data.len(),
        })
    }

    fn transform(&self, data: &[u8], seg: &Self::Seg) -> Self::Output {
        data[seg.0..seg.1].to_vec()
    }
}

struct TypedCollectSink {
    out: Vec<u8>,
    saw_last: bool,
}

impl TypedSink<Vec<u8>> for TypedCollectSink {
    fn process(&mut self, output: Vec<u8>, is_last: bool) -> Result<()> {
        self.out.extend_from_slice(&output);
        if is_last {
            self.saw_last = true;
        }
        Ok(())
    }
}

#[test]
fn typed_mode_forwards_segments_in_order() {
    // Identity transform: ordered concatenation of every segment's output must
    // equal the original input. Reordering would scramble the bytes.
    // Length is deliberately an EXACT multiple of chunk_size (64 * 150 = 9_600),
    // so every read returns a full chunk and no trailing short read ever occurs.
    // This is the case that used to drop the final `is_last` flag; the reader's
    // one-byte EOF peek must now flag the final segment `is_last` regardless.
    let input = make_input(9_600, 0xFEEDC0DE);
    let mut sink = TypedCollectSink {
        out: Vec::new(),
        saw_last: false,
    };
    let cfg = Config {
        chunk_size: 64,
        carry_headroom: 0,
        ring_slots: 4,
        initial_carry: Vec::new(),
        slot_fill: SlotFill::Incremental,
    };
    gatling::run_typed(&input[..], TypedIdentityCodec, &mut sink, 6, cfg)
        .expect("gatling::run_typed");

    assert_eq!(sink.out, input, "typed-mode output not in stream order");
    assert!(sink.saw_last, "final segment was never flagged is_last");
}

/// Typed codec that refuses to split until it has accumulated a large unit,
/// forcing the engine's carry to grow past `carry_headroom`. Models a single
/// element/record (planet-scale OSM block) that spans many chunk reads with no
/// interior split boundary — the case that used to panic with
/// `carry … exceeds carry_headroom`.
struct TypedHugeUnitCodec {
    /// Minimum buffered length before a non-final chunk is allowed to split.
    flush_at: usize,
}

impl TypedCodec for TypedHugeUnitCodec {
    type Seg = (usize, usize);
    type Output = Vec<u8>;

    fn split(&self, data: &[u8], n_workers: usize, is_last: bool) -> Option<Split<Self::Seg>> {
        if data.is_empty() {
            return None;
        }
        // Withhold any split until the carry has grown large (or the stream
        // ends), so the engine must prepend a carry far larger than the headroom.
        if !is_last && data.len() < self.flush_at {
            return None;
        }
        let n = n_workers.max(1).min(data.len());
        let base = data.len() / n;
        let mut segments = Vec::with_capacity(n);
        let mut start = 0;
        for i in 0..n {
            let end = if i == n - 1 { data.len() } else { start + base };
            segments.push((start, end));
            start = end;
        }
        Some(Split {
            segments,
            consumed: data.len(),
        })
    }

    fn transform(&self, data: &[u8], seg: &Self::Seg) -> Self::Output {
        data[seg.0..seg.1].to_vec()
    }
}

#[test]
fn typed_mode_carry_exceeds_headroom() {
    // The unit only "completes" once 3000+ bytes are buffered, but each read is
    // 512 bytes into a 1024-byte headroom — so the carry blows past the headroom
    // (reaching ~2.5 KiB) before any split is taken. The pre-fix engine asserted
    // `carry <= carry_headroom` here and panicked. Identity transform means the
    // ordered concatenation of outputs must still reproduce the input exactly.
    let input = make_input(10_000, 0x0BADF00D);
    let mut sink = TypedCollectSink {
        out: Vec::new(),
        saw_last: false,
    };
    let cfg = Config {
        chunk_size: 512,
        carry_headroom: 1024,
        ring_slots: 4,
        initial_carry: Vec::new(),
        slot_fill: SlotFill::Incremental,
    };
    gatling::run_typed(
        &input[..],
        TypedHugeUnitCodec { flush_at: 3000 },
        &mut sink,
        6,
        cfg,
    )
    .expect("gatling::run_typed must not panic when carry exceeds headroom");

    assert_eq!(
        sink.out, input,
        "carry-overflow path corrupted stream order"
    );
    assert!(sink.saw_last, "final segment was never flagged is_last");
}
