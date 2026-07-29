//! Throughput bench for the DEFLATE decode hot path (`inflate_into`).
//!
//! Three corpora exercise the match-copy distributions that drive `copy_match`:
//!   - `text`  : source-code-like, many short/medium back-refs (the common case)
//!   - `binary`: lower redundancy, longer literals, fewer matches
//!   - `rle`   : highly repetitive, long matches (stresses the 32-byte copy loop)
//! Each is compressed once with miniz_oxide level 6; the bench times linflate
//! decoding into a reused output buffer (no per-iter alloc). Throughput is over
//! the *uncompressed* output.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

fn corpus_text(n: usize) -> Vec<u8> {
    // Repeated token soup with drift → realistic back-reference distances.
    let toks: &[&str] = &[
        "let mut ",
        "self.",
        "pub fn ",
        "return Ok(",
        "unsafe { ",
        "for i in 0..",
        "match x {",
        "println!(",
        "buffer",
        "_index",
        " = ",
        ";\n",
        "    ",
        "}\n",
        "compressed",
        "out_pos",
        "InflateError",
        "BitReader",
        "tables",
    ];
    let mut out = Vec::with_capacity(n);
    let mut s = 0x2545F4914F6CDD1Du64;
    while out.len() < n {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        let t = toks[(s as usize) % toks.len()].as_bytes();
        out.extend_from_slice(t);
    }
    out.truncate(n);
    out
}

fn corpus_binary(n: usize) -> Vec<u8> {
    // Pseudo-random with occasional repeats → few, longer-distance matches.
    let mut out = Vec::with_capacity(n);
    let mut s = 0x9E3779B97F4A7C15u64;
    while out.len() < n {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        let v = s.wrapping_mul(0x2545F4914F6CDD1D);
        out.extend_from_slice(&v.to_le_bytes());
        if (v & 0x3f) == 0 && out.len() > 64 {
            // splice a repeat to create a match
            let from = out.len() - 64;
            let win = out[from..from + 32].to_vec();
            out.extend_from_slice(&win);
        }
    }
    out.truncate(n);
    out
}

fn corpus_rle(n: usize) -> Vec<u8> {
    // Long runs → long matches, the 32-byte copy_chunks loop dominates.
    let mut out = Vec::with_capacity(n);
    let mut s = 1u64;
    while out.len() < n {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        let b = (s & 0xff) as u8;
        let run = 16 + (s >> 8) as usize % 240;
        out.resize((out.len() + run).min(n), b);
    }
    out
}

fn bench(c: &mut Criterion) {
    let n = 4 * 1024 * 1024;
    let corpora: [(&str, Vec<u8>); 3] = [
        ("text", corpus_text(n)),
        ("binary", corpus_binary(n)),
        ("rle", corpus_rle(n)),
    ];

    let mut g = c.benchmark_group("inflate");
    for (name, raw) in &corpora {
        let comp = miniz_oxide::deflate::compress_to_vec(raw, 6);
        // sanity: linflate must reproduce it
        let check = linflate::inflate_to_vec(&comp, raw.len()).expect("decode");
        assert_eq!(&check, raw, "linflate roundtrip mismatch for {name}");

        let mut out = vec![0u8; raw.len() + 64]; // FASTLOOP headroom
        g.throughput(Throughput::Bytes(raw.len() as u64));
        g.bench_function(*name, |b| {
            b.iter(|| {
                let w = linflate::inflate_into(black_box(&comp), black_box(&mut out)).unwrap();
                black_box(w);
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
