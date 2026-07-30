//! Tiny round-trip bench for the sync `gatling` engine (byte mode).
//!
//! Times an end-to-end `gatling::run`: reader → split → N workers (per-byte
//! transform) → ordered collector → sink, over a small in-memory corpus. The
//! point is to exercise the engine's thread fan-out / ordered-assembly path, not
//! to benchmark a heavy codec — the transform is deliberately trivial.
//!
//! Kept SMALL (256 KB, reduced sample size) — this runs on a laptop.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use anyhow::Result;
use znippy_zoomies::gatling::{self, Codec, Config, Sink, SlotFill, Split};

#[inline]
fn xform(b: u8) -> u8 {
    b.wrapping_add(0x5A) ^ 0x3C
}

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
        Some(Split {
            segments,
            consumed: data.len(),
        })
    }
    fn decode(&self, data: &[u8], seg: &Self::Seg) -> Vec<u8> {
        data[seg.0..seg.1].iter().map(|&b| xform(b)).collect()
    }
}

struct CountSink {
    bytes: usize,
}
impl Sink for CountSink {
    fn safe_end(&self, assembled: &[u8], _is_last: bool) -> usize {
        assembled.len()
    }
    fn process(&mut self, bytes: &[u8]) -> Result<()> {
        self.bytes += bytes.len();
        Ok(())
    }
}

fn corpus(len: usize) -> Vec<u8> {
    let mut s = 0x9E3779B97F4A7C15u64;
    (0..len)
        .map(|_| {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            (s >> 33) as u8
        })
        .collect()
}

fn bench_roundtrip(c: &mut Criterion) {
    let len = 256 * 1024;
    let data = corpus(len);

    let mut group = c.benchmark_group("gatling");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(len as u64));
    group.bench_function("run_roundtrip_256k_4w", |b| {
        b.iter(|| {
            let mut sink = CountSink { bytes: 0 };
            let cfg = Config {
                chunk_size: 16 * 1024,
                carry_headroom: 0,
                ring_slots: 4,
                initial_carry: Vec::new(),
                slot_fill: SlotFill::Incremental,
            };
            gatling::run(black_box(&data[..]), ByteCodec, &mut sink, 4, cfg).expect("gatling::run");
            black_box(sink.bytes)
        })
    });
    group.finish();
}

criterion_group!(benches, bench_roundtrip);
criterion_main!(benches);
