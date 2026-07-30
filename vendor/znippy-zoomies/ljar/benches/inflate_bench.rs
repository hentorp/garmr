//! Benchmarks for the inflate (DEFLATE decompression) pipeline.
//!
//! Covers: Huffman table build, inflate decode, and flush boundary scan.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

// ── Test data generators ─────────────────────────────────────────────────────

fn make_repetitive_data(size: usize) -> Vec<u8> {
    let pattern = b"The quick brown fox jumps over the lazy dog. ";
    let repeats = (size / pattern.len()) + 2;
    pattern.repeat(repeats)[..size].to_vec()
}

fn make_mixed_data(size: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(size);
    for i in 0..size {
        if i % 10 < 3 {
            v.push(0);
        } else {
            v.push(((i * 7 + 13) % 256) as u8);
        }
    }
    v
}

fn make_class_like_data(size: usize) -> Vec<u8> {
    let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
    let chunk = b"package org.example;\nimport java.util.*;\npublic class Foo {\n    private final String name;\n}\n";
    while v.len() < size {
        v.extend_from_slice(chunk);
    }
    v.truncate(size);
    v
}

// ── Inflate benchmarks ───────────────────────────────────────────────────────

fn bench_inflate(c: &mut Criterion) {
    let mut group = c.benchmark_group("inflate");

    // Repetitive 4K
    {
        let original = make_repetitive_data(4096);
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        group.throughput(Throughput::Bytes(original.len() as u64));
        group.bench_function("repetitive_4k", |b| {
            b.iter(|| {
                black_box(ljar::inflate::inflate_to_vec(&compressed, original.len()).unwrap())
            })
        });
    }

    // Repetitive 64K
    {
        let original = make_repetitive_data(65536);
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        group.throughput(Throughput::Bytes(original.len() as u64));
        group.bench_function("repetitive_64k", |b| {
            b.iter(|| {
                black_box(ljar::inflate::inflate_to_vec(&compressed, original.len()).unwrap())
            })
        });
    }

    // Repetitive 256K
    {
        let original = make_repetitive_data(256 * 1024);
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        group.throughput(Throughput::Bytes(original.len() as u64));
        group.bench_function("repetitive_256k", |b| {
            b.iter(|| {
                black_box(ljar::inflate::inflate_to_vec(&compressed, original.len()).unwrap())
            })
        });
    }

    // Mixed 64K
    {
        let original = make_mixed_data(65536);
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        group.throughput(Throughput::Bytes(original.len() as u64));
        group.bench_function("mixed_64k", |b| {
            b.iter(|| {
                black_box(ljar::inflate::inflate_to_vec(&compressed, original.len()).unwrap())
            })
        });
    }

    // Class-like 64K
    {
        let original = make_class_like_data(65536);
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
        group.throughput(Throughput::Bytes(original.len() as u64));
        group.bench_function("class_like_64k", |b| {
            b.iter(|| {
                black_box(ljar::inflate::inflate_to_vec(&compressed, original.len()).unwrap())
            })
        });
    }

    group.finish();
}

// ── Table build benchmarks ───────────────────────────────────────────────────

fn bench_table_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("table_build");

    // Fixed litlen table (288 symbols, realistic)
    let mut lens = [0u8; 288];
    for i in 0..=143 {
        lens[i] = 8;
    }
    for i in 144..=255 {
        lens[i] = 9;
    }
    for i in 256..=279 {
        lens[i] = 7;
    }
    for i in 280..=287 {
        lens[i] = 8;
    }

    group.bench_function("litlen_288sym", |b| {
        b.iter(|| {
            let mut table = [0u32; ljar::inflate::tables::LITLEN_TABLE_SIZE];
            black_box(
                ljar::inflate::tables::build_decode_table(
                    &lens,
                    &mut table,
                    ljar::inflate::tables::LITLEN_TABLEBITS,
                    ljar::inflate::tables::TableKind::Litlen,
                )
                .unwrap(),
            );
        })
    });

    // Distance table (30 symbols)
    let dist_lens = [5u8; 32];
    group.bench_function("dist_32sym", |b| {
        b.iter(|| {
            let mut table = [0u32; ljar::inflate::tables::DIST_TABLE_SIZE];
            black_box(
                ljar::inflate::tables::build_decode_table(
                    &dist_lens,
                    &mut table,
                    ljar::inflate::tables::DIST_TABLEBITS,
                    ljar::inflate::tables::TableKind::Dist,
                )
                .unwrap(),
            );
        })
    });

    group.finish();
}

// ── Deflate scan benchmarks ──────────────────────────────────────────────────

fn bench_flush_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("flush_scan");

    // 1MB with markers
    {
        let mut buf = vec![0xAAu8; 1024 * 1024];
        for pos in [100_000, 300_000, 600_000, 900_000] {
            buf[pos] = 0x00;
            buf[pos + 1] = 0x00;
            buf[pos + 2] = 0xFF;
            buf[pos + 3] = 0xFF;
        }
        group.throughput(Throughput::Bytes(buf.len() as u64));
        group.bench_function("with_markers_1mb", |b| {
            b.iter(|| black_box(ljar::deflate_scan::find_all_flushes(&buf)))
        });
    }

    // 1MB no match (worst case)
    {
        let buf = vec![0x42u8; 1024 * 1024];
        group.throughput(Throughput::Bytes(buf.len() as u64));
        group.bench_function("no_match_1mb", |b| {
            b.iter(|| black_box(ljar::deflate_scan::find_all_flushes(&buf)))
        });
    }

    group.finish();
}

// ── Comparison vs miniz_oxide ────────────────────────────────────────────────

fn bench_vs_miniz(c: &mut Criterion) {
    let mut group = c.benchmark_group("inflate_vs_miniz");

    let original = make_repetitive_data(65536);
    let compressed = miniz_oxide::deflate::compress_to_vec(&original, 6);
    group.throughput(Throughput::Bytes(original.len() as u64));

    group.bench_function("ljar_64k", |b| {
        b.iter(|| black_box(ljar::inflate::inflate_to_vec(&compressed, original.len()).unwrap()))
    });

    group.bench_function("miniz_oxide_64k", |b| {
        b.iter(|| black_box(miniz_oxide::inflate::decompress_to_vec(&compressed).unwrap()))
    });

    let original_256k = make_repetitive_data(256 * 1024);
    let compressed_256k = miniz_oxide::deflate::compress_to_vec(&original_256k, 6);
    group.throughput(Throughput::Bytes(original_256k.len() as u64));

    group.bench_function("ljar_256k", |b| {
        b.iter(|| {
            black_box(ljar::inflate::inflate_to_vec(&compressed_256k, original_256k.len()).unwrap())
        })
    });

    group.bench_function("miniz_oxide_256k", |b| {
        b.iter(|| black_box(miniz_oxide::inflate::decompress_to_vec(&compressed_256k).unwrap()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_inflate,
    bench_table_build,
    bench_flush_scan,
    bench_vs_miniz
);
criterion_main!(benches);
