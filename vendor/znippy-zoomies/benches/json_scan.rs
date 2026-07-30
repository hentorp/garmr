//! NDJSON scanner throughput: sequential vs parallel vs serde_json baseline.
//!
//! Corpus: ~200 MB of deterministic synthetic NDJSON — varied record sizes,
//! escaped quotes/backslashes inside strings, nested objects/arrays, and an
//! empty line every 97 records. Same corpus for all three measurements so the
//! MB/s figures are directly comparable.
//!
//! - `scan_seq`:    `json::scan_records_slice` single-threaded
//! - `scan_par`:    `json::scan_records_parallel` at available cores
//! - `serde_value`: `serde_json::from_slice::<Value>` per line (the "just
//!                  parse everything" baseline the span scanner replaces)
//!
//! Run: `cargo bench -p znippy-zoomies --bench json_scan`

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::io::Write as _;
use znippy_zoomies::json::{scan_records_parallel, scan_records_slice};

const TARGET_BYTES: usize = 200 * 1024 * 1024; // ~200 MB

/// xorshift64* — deterministic, no dependency.
#[inline]
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// Build the synthetic corpus. Record shapes rotate through small / medium /
/// large with PRNG-driven padding; every name string carries escaped quotes
/// and backslashes; every 97th record is followed by an empty line.
fn build_corpus(target: usize) -> Vec<u8> {
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut buf = Vec::with_capacity(target + 4096);
    let mut i = 0u64;

    while buf.len() < target {
        let r = xorshift(&mut rng);
        // Varied record sizes: 0–63, 0–511, or 0–4095 bytes of padding.
        let pad_len = match i % 3 {
            0 => (r % 64) as usize,
            1 => (r % 512) as usize,
            _ => (r % 4096) as usize,
        };
        let pad: String = std::iter::repeat('x').take(pad_len).collect();

        write!(
            buf,
            "{{\"id\":{i},\"name\":\"user_{i}\\\"esc\\\\path\",\"score\":{},\
             \"meta\":{{\"depth\":2,\"ok\":{}}},\"tags\":[\"a\",\"b\"],\"pad\":\"{pad}\"}}\n",
            r % 100_000,
            i % 2 == 0,
        )
        .expect("write to Vec");

        if i % 97 == 96 {
            buf.push(b'\n'); // tolerated empty line
        }
        i += 1;
    }
    buf
}

fn bench(c: &mut Criterion) {
    let n_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let corpus = build_corpus(TARGET_BYTES);
    eprintln!("corpus: {} bytes, workers: {n_workers}", corpus.len(),);

    let mut group = c.benchmark_group("json_scan");
    group.throughput(Throughput::Bytes(corpus.len() as u64));
    group.sample_size(10);

    // (a) Sequential span scan.
    group.bench_function("scan_seq", |b| {
        b.iter(|| {
            let mut count = 0u64;
            scan_records_slice(black_box(&corpus), 0, &mut |_r| count += 1);
            black_box(count)
        })
    });

    // (b) Parallel span scan at available cores.
    group.bench_function(format!("scan_par_{n_workers}"), |b| {
        b.iter(|| {
            let mut count = 0u64;
            scan_records_parallel(black_box(&corpus), n_workers, |_r| count += 1);
            black_box(count)
        })
    });

    // (c) Baseline: full serde_json parse of every line.
    group.bench_function("serde_value_per_line", |b| {
        b.iter(|| {
            let mut count = 0u64;
            for line in black_box(&corpus).split(|&b| b == b'\n') {
                let line = match line.last() {
                    Some(&b'\r') => &line[..line.len() - 1],
                    _ => line,
                };
                if line.is_empty() {
                    continue;
                }
                let v: serde_json::Value = serde_json::from_slice(line).expect("valid NDJSON line");
                black_box(&v);
                count += 1;
            }
            black_box(count)
        })
    });

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
