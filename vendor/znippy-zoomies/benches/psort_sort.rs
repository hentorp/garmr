//! Criterion bench for the `psort` AoS sorters.
//!
//! Times both `samplesort_aos_by_i64_key` (the parallel sample-sort fast path)
//! and `radix_sort_aos_by_i64_key` (the reference LSD radix sort) over 16-byte
//! records keyed by their leading little-endian `i64`, on a pseudo-random,
//! OSM-node-ID-shaped key distribution. Each sample re-clones the unsorted
//! input (the sort is in-place) via `iter_batched`, so the timed region is only
//! the sort. Kept modest (up to ~1M records) so it runs on a laptop.

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand::{RngCore, SeedableRng, rngs::StdRng};

use znippy_zoomies::psort::{RECORD_SIZE, radix_sort_aos_by_i64_key, samplesort_aos_by_i64_key};

/// Build `n` records with dense-ish positive i64 keys (OSM node-ID shaped) and
/// arbitrary payload in the trailing 8 bytes.
fn make_records(n: usize, seed: u64) -> Vec<[u8; RECORD_SIZE]> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut v = vec![[0u8; RECORD_SIZE]; n];
    for (i, rec) in v.iter_mut().enumerate() {
        // Keys cluster in a dense positive range (like OSM node IDs) with jitter.
        let key = 1_000_000_000i64 + i as i64 * 7 + (rng.next_u32() % 64) as i64;
        rec[..8].copy_from_slice(&key.to_le_bytes());
        rec[8..].copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    v
}

fn bench_psort(c: &mut Criterion) {
    let mut group = c.benchmark_group("psort_aos_i64");
    for &n in &[64_usize * 1024, 256 * 1024, 1024 * 1024] {
        let base = make_records(n, 0x5EED_1234 ^ n as u64);
        group.throughput(Throughput::Bytes((n * RECORD_SIZE) as u64));

        group.bench_function(format!("samplesort/{n}"), |b| {
            b.iter_batched_ref(
                || base.clone(),
                |recs| samplesort_aos_by_i64_key(black_box(recs)),
                BatchSize::LargeInput,
            );
        });

        group.bench_function(format!("radix/{n}"), |b| {
            b.iter_batched_ref(
                || base.clone(),
                |recs| radix_sort_aos_by_i64_key(black_box(recs)),
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_psort);
criterion_main!(benches);
