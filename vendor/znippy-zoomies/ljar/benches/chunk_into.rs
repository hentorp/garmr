//! B6 before/after: the chunk-decode **output assembly** path.
//!
//! `decode_chunk` returns `Vec<Vec<u8>>` which the caller must
//! `flatten().collect()` — a fresh allocation + copy of the whole chunk every
//! call. `decode_chunk_into` (B6) decodes the segments in parallel into one
//! pre-allocated buffer at candidate offsets, then forward-seek compacts — and
//! the caller reuses the buffer across chunks, so the per-chunk output
//! allocation disappears. Stored blocks make the *decode* trivial so the
//! measurement isolates the assembly/allocation cost B6 targets.
//!
//! Run: `cargo bench -p ljar --bench chunk_into`

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use ljar::chunk::{decode_chunk, decode_chunk_into};

fn stored_block(payload: &[u8], bfinal: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(if bfinal { 0x01 } else { 0x00 });
    let len = payload.len() as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// `nblocks` non-final stored blocks of `block` bytes, each followed by a
/// Z_FULL_FLUSH marker, then one final block. Returns (stream, decoded_len).
fn build_stream(nblocks: usize, block: usize) -> (Vec<u8>, usize) {
    let payload = vec![0x5A_u8; block];
    let flush = [0x00u8, 0x00, 0x00, 0xFF, 0xFF];
    let mut buf = Vec::new();
    for _ in 0..nblocks {
        buf.extend_from_slice(&stored_block(&payload, false));
        buf.extend_from_slice(&flush);
    }
    buf.extend_from_slice(&stored_block(b"end", true));
    (buf, nblocks * block + 3)
}

fn bench(c: &mut Criterion) {
    let n_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let (buf, decoded) = build_stream(256, 16 * 1024); // ~4 MB decoded, many flush points

    let mut group = c.benchmark_group("chunk_into");
    group.throughput(Throughput::Bytes(decoded as u64));

    // BEFORE: Vec<Vec<u8>> + a fresh flatten().collect() per call.
    group.bench_function("decode_chunk_flatten", |b| {
        b.iter(|| {
            let (outs, _) = decode_chunk(black_box(&buf), n_workers, true).unwrap();
            let v: Vec<u8> = outs.into_iter().flatten().collect();
            black_box(v.len())
        })
    });

    // AFTER (B6): candidate-offset zero-copy decode into ONE reused buffer.
    group.bench_function("decode_chunk_into_reused", |b| {
        let mut out = Vec::with_capacity(decoded + (1 << 20));
        b.iter(|| {
            out.clear();
            decode_chunk_into(black_box(&buf), n_workers, true, &mut out).unwrap();
            black_box(out.len())
        })
    });

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
