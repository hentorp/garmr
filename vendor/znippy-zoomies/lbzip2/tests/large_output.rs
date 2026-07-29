//! Regression (Codeberg #1): the parallel bzip2 decoder must reproduce an
//! output **larger than 512 MiB** byte-for-byte — there is no 2^29
//! (536,870,912-byte) truncation in the chunk/segment/bit-offset path.
//!
//! The phantom "512 MiB cap" reported by the heavy bake-off was in fact the
//! bench harness reusing a STALE 512 MiB-corpus `.bz2` against a freshly
//! regenerated 1 GiB corpus (fixed in `examples/nornir-bench.rs`). These tests
//! lock the decoder itself: they build a genuine multi-block bzip2 stream and
//! run the real `lbunzip2` binary end-to-end (the exact path the bake-off
//! drives: `lbunzip2 corpus.bz2 out`), asserting the decoded bytes equal input.
//!
//! The heavy case is `#[ignore]` (it materialises >512 MiB on disk + in RAM);
//! run it with `cargo test -p lbzip2 --release -- --ignored`. A light multi-block
//! case runs by default so the streaming/segment path is always covered in CI.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use bzip2::write::BzEncoder;

/// Deterministic, compressible "loggy" text so the stream has many real bzip2
/// blocks (max 900 KiB input each) for the parallel segment decode to reassemble.
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

/// Compress `data` to a single-stream `bzip2 -9` file (the stock format
/// `lbunzip2` decodes).
fn write_bz2(path: &Path, data: &[u8]) {
    let f = File::create(path).expect("create bz2");
    let mut enc = BzEncoder::new(std::io::BufWriter::new(f), bzip2::Compression::best());
    enc.write_all(data).expect("bz2 write");
    enc.finish()
        .expect("bz2 finish")
        .flush()
        .expect("flush bz2");
}

/// Run the built `lbunzip2` binary: `lbunzip2 <in.bz2> <out>` (the exact
/// bake-off verify command).
fn run_lbunzip2(bz2_path: &Path, out_path: &Path) {
    let status = Command::new(env!("CARGO_BIN_EXE_lbunzip2"))
        .arg(bz2_path)
        .arg(out_path)
        .status()
        .expect("spawn lbunzip2");
    assert!(status.success(), "lbunzip2 exited with {status}");
}

fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("lbz-large-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn roundtrip(total: usize, tag: &str) {
    let dir = tmp_dir(tag);
    let bz2 = dir.join("corpus.bz2");
    let out = dir.join("out.bin");

    let data = corpus(total);
    assert_eq!(data.len(), total);
    write_bz2(&bz2, &data);

    run_lbunzip2(&bz2, &out);

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

/// Light guard (runs in CI): a multi-block stream well under the boundary
/// reassembles byte-identically through the parallel segment decode.
#[test]
fn multiblock_roundtrip_is_byte_identical() {
    // 24 MiB ≈ 27 bzip2 blocks: real multi-segment assembly, fast.
    roundtrip(24 * 1024 * 1024, "light");
}

/// HEAVY guard: decoded output **strictly greater than 512 MiB** (2^29) must be
/// byte-identical — the exact size class where the reported truncation lived.
/// `#[ignore]`d because it writes/holds >512 MiB; run with `-- --ignored`.
#[test]
#[ignore = "heavy: materialises >512 MiB; run with --ignored"]
fn over_512_mib_roundtrip_is_byte_identical() {
    let total = 512 * 1024 * 1024 + 16 * 1024 * 1024;
    roundtrip(total, "heavy");
}
