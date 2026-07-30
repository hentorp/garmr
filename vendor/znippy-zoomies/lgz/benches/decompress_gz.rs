//! Criterion bench for lgz's parallel gzip decode hot path
//! (`lgz::parallel::decompress_gz`) — the `znippy-gz` decode arm.
//!
//! Builds a compressible in-memory corpus, gzips it with flate2 (a dev-dep), and
//! times the full-buffer parallel decode. Two sizes are used: one below the
//! 4 MB `PARALLEL_THRESHOLD` (single-core path) and one comfortably above it
//! (the multi-core split → N workers → ordered assembly path). Kept to tens of
//! MB so it runs on a laptop.

use std::io::Write;

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use flate2::{Compression, write::GzEncoder};

use lgz::parallel::decompress_gz;

/// Deterministic, moderately compressible bytes (text-like, so DEFLATE finds
/// matches but the stream is not degenerate).
fn make_corpus(len: usize) -> Vec<u8> {
    let words: [&[u8]; 8] = [
        b"the quick brown fox ",
        b"jumps over the lazy ",
        b"dog while parsing ",
        b"osm ways and nodes ",
        b"into geoparquet at ",
        b"many megabytes per ",
        b"second without any ",
        b"external c toolchain ",
    ];
    let mut out = Vec::with_capacity(len + 32);
    let mut i = 0usize;
    while out.len() < len {
        out.extend_from_slice(words[i % words.len()]);
        // Sprinkle some entropy so it isn't perfectly periodic.
        out.push((i as u8).wrapping_mul(31).wrapping_add(7));
        i += 1;
    }
    out.truncate(len);
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::new(6));
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn bench_decompress_gz(c: &mut Criterion) {
    let mut group = c.benchmark_group("lgz_decompress_gz");
    for &mb in &[2usize, 32] {
        let raw = make_corpus(mb * 1024 * 1024);
        let gz = gzip(&raw);
        group.throughput(Throughput::Bytes(raw.len() as u64));
        group.bench_function(format!("{mb}MB"), |b| {
            b.iter(|| {
                let out = decompress_gz(black_box(&gz)).expect("decode");
                black_box(out.len())
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_decompress_gz);
criterion_main!(benches);
