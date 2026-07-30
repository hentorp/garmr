//! Throughput bench for the DEFLATE full-flush boundary scanner
//! (`linflate::deflate_scan::find_all_flushes`).
//!
//! The scanner skips through compressed bytes hunting the `00 00 FF FF` pattern;
//! its cost is dominated by the candidate-skip inner loop, so the realistic case
//! is a buffer with very few real markers (the SIMD path mostly fast-skips).
//!
//! Kept SMALL (1 MB corpus, reduced sample size) — this runs on a laptop.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use linflate::deflate_scan::find_all_flushes;

/// 1 MB of benign non-pattern bytes with a sparse sprinkle of real markers —
/// mimics a real DEFLATE stream where full-flush points are rare.
fn corpus(len: usize, marker_every: usize) -> Vec<u8> {
    let mut buf = vec![0xAAu8; len];
    // xorshift to vary the filler a little (avoids 0x00/0xFF so no spurious hits).
    let mut s = 0x2545F4914F6CDD1Du64;
    for b in buf.iter_mut() {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        let v = (s >> 33) as u8;
        *b = if v == 0x00 || v == 0xFF { 0x7E } else { v };
    }
    let mut off = marker_every;
    while off + 4 <= len {
        buf[off..off + 4].copy_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
        off += marker_every;
    }
    buf
}

fn bench_scan(c: &mut Criterion) {
    let len = 1 << 20; // 1 MB
    let buf = corpus(len, 64 * 1024); // ~16 markers in 1 MB

    let mut group = c.benchmark_group("deflate_scan");
    group.sample_size(30);
    group.throughput(Throughput::Bytes(len as u64));
    group.bench_function("find_all_flushes_1mb", |b| {
        b.iter(|| {
            let flushes = find_all_flushes(black_box(&buf));
            black_box(flushes.len())
        })
    });
    group.finish();
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);
