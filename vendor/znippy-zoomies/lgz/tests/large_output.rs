//! Regression (Codeberg #1): the parallel multi-member gzip decoder must
//! reproduce an output **larger than 512 MiB** byte-for-byte — there is no
//! 2^29 (536,870,912-byte) truncation anywhere in the decode/assembly path.
//!
//! The phantom "512 MiB cap" reported by the heavy bake-off was in fact the
//! bench harness reusing a STALE 512 MiB-corpus `.gz` against a freshly
//! regenerated 1 GiB corpus (fixed in `examples/nornir-bench.rs`). These tests
//! lock the decoder itself: they build a genuine multi-member gzip stream and
//! run the real `lgz` binary end-to-end (the exact path the bake-off drives:
//! `lgz corpus.gz > out`), asserting the decoded bytes equal the input.
//!
//! The heavy case is `#[ignore]` (it materialises >512 MiB on disk + in RAM);
//! run it with `cargo test -p lgz --release -- --ignored`. A light multi-member
//! case runs by default so the assembly path is always covered in CI.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::Compression;
use flate2::write::GzEncoder;

/// Deterministic, compressible "loggy" text — same shape as the bake-off corpus,
/// so the members compress ~4-5x and the decode does real work.
fn corpus(len: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the",
        "quick",
        "brown",
        "fox",
        "GET",
        "POST",
        "200",
        "404",
        "error",
        "info",
        "debug",
        "user",
        "session",
        "token",
        "request",
        "response",
        "latency",
        "bytes",
        "cache",
        "hit",
        "miss",
        "shard",
        "commit",
        "deploy",
        "node",
        "cluster",
        "worker",
        "thread",
        "queue",
        "buffer",
        "stream",
        "decode",
        "payload",
        "checksum",
        "offset",
        "length",
        "dur_ms=42",
    ];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut out = Vec::with_capacity(len + 256);
    while out.len() < len {
        let n = 6 + (next() % 10) as usize;
        for i in 0..n {
            if i > 0 {
                out.push(b' ');
            }
            out.extend_from_slice(WORDS[(next() as usize) % WORDS.len()].as_bytes());
        }
        out.push(b'\n');
    }
    out.truncate(len);
    out
}

/// Write `data` as a concatenated **multi-member** gzip (`member_bytes` of input
/// per member, gzipped independently and concatenated) — the format `lgz`'s
/// parallel fast path is built for.
fn write_multimember_gz(path: &Path, data: &[u8], member_bytes: usize) {
    let f = File::create(path).expect("create gz");
    let mut w = std::io::BufWriter::new(f);
    for chunk in data.chunks(member_bytes) {
        let mut enc = GzEncoder::new(Vec::new(), Compression::new(6));
        enc.write_all(chunk).expect("gz member write");
        let member = enc.finish().expect("gz member finish");
        w.write_all(&member).expect("append member");
    }
    w.flush().expect("flush gz");
}

/// Run the built `lgz` binary decoding `gz_path` to stdout, capturing the output
/// to `out_path` (`lgz corpus.gz > out` — exactly the bake-off's verify command).
fn run_lgz_to_file(gz_path: &Path, out_path: &Path) {
    let out = File::create(out_path).expect("create out");
    let status = Command::new(env!("CARGO_BIN_EXE_lgz"))
        .arg(gz_path)
        .stdout(out)
        .status()
        .expect("spawn lgz");
    assert!(status.success(), "lgz exited with {status}");
}

fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("lgz-large-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn roundtrip_multimember(total: usize, member_bytes: usize, tag: &str) {
    let dir = tmp_dir(tag);
    let gz = dir.join("corpus.gz");
    let out = dir.join("out.bin");

    let data = corpus(total);
    assert_eq!(data.len(), total);
    write_multimember_gz(&gz, &data, member_bytes);

    run_lgz_to_file(&gz, &out);

    let decoded = std::fs::read(&out).expect("read decoded");
    assert_eq!(
        decoded.len(),
        data.len(),
        "decoded length {} != input length {} (truncation?)",
        decoded.len(),
        data.len()
    );
    assert!(
        decoded == data,
        "decoded bytes differ from the input corpus"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Light guard (runs in CI): a multi-member stream well under the boundary still
/// reassembles byte-identically across the parallel decode.
#[test]
fn multimember_roundtrip_is_byte_identical() {
    // 24 MiB across 8 MiB members → 3 members, real parallel assembly, fast.
    roundtrip_multimember(24 * 1024 * 1024, 8 * 1024 * 1024, "light");
}

/// HEAVY guard: decoded output **strictly greater than 512 MiB** (2^29) must be
/// byte-identical — the exact size class where the reported truncation lived.
/// `#[ignore]`d because it writes/holds >512 MiB; run with `-- --ignored`.
#[test]
#[ignore = "heavy: materialises >512 MiB; run with --ignored"]
fn over_512_mib_roundtrip_is_byte_identical() {
    // 2^29 + 16 MiB, comfortably past the boundary, across 8 MiB members.
    let total = 512 * 1024 * 1024 + 16 * 1024 * 1024;
    roundtrip_multimember(total, 8 * 1024 * 1024, "heavy");
}
