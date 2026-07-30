//! RED-when-broken **core-saturation** + **round-trip** guard for the
//! concatenated-multi-member decode (`decode_concatenated_members`).
//!
//! Correctness (byte-identical vs the reference decoder) is asserted
//! unconditionally. On a multi-core Linux box we ALSO assert the parallel
//! contract the path exists for: N independent gzip members must decode across
//! many cores, not collapse onto one. A regression that reintroduces the serial
//! prelude/epilogue (single-threaded member scan, or per-member `Vec::new()`
//! alloc churn serialising on the kernel mmap_lock) drops cores_busy back toward
//! the old ~3/12 and turns this test RED.
//!
//! Off Linux (no `getrusage`) or on a <4-core box (no saturation to assert) it
//! degrades to the plain round-trip check.

use std::io::Write;
use std::time::Instant;

use flate2::{Compression, write::GzEncoder};

#[cfg(target_os = "linux")]
fn cpu_secs() -> f64 {
    // SAFETY: `getrusage` fills a caller-owned, zero-initialized `rusage`.
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut ru);
        let u = ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 * 1e-6;
        let s = ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 * 1e-6;
        u + s
    }
}
#[cfg(not(target_os = "linux"))]
fn cpu_secs() -> f64 {
    f64::NAN
}

fn cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Realistic ~3.5x-compressible bytes (dictionary words + an xorshift entropy
/// tail) so each member's DEFLATE decode is genuine CPU work — a degenerate
/// all-RLE corpus decodes at multi-GB/s and would hide any saturation stall.
fn make_corpus(len: usize, seed: u64) -> Vec<u8> {
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
    let mut out = Vec::with_capacity(len + 64);
    let mut state = seed | 1;
    let mut i = 0usize;
    while out.len() < len {
        out.extend_from_slice(words[i % words.len()]);
        for _ in 0..6 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push(state as u8);
        }
        i += 1;
    }
    out.truncate(len);
    out
}

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::new(6));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn concatenated_members_roundtrip_and_saturate() {
    let nc = cores();
    // One member per core × 4 (≥ a few waves), each ~4 MiB uncompressed → enough
    // work that the fan-out dominates pool spin-up while staying quick.
    let n_members = (nc * 4).max(8);
    let per = 4 * 1024 * 1024;

    let mut original = Vec::with_capacity(n_members * per);
    let mut multi = Vec::new();
    for k in 0..n_members {
        let part = make_corpus(per, 0x1234 + k as u64);
        multi.extend_from_slice(&gz(&part));
        original.extend_from_slice(&part);
    }

    // Warm once (fault pages / spin the pool) so the timed run measures steady
    // state, then time the decode.
    let warm = lgz::speculative::decode_concatenated_members(&multi, nc)
        .expect("multi-member decode returns Some for ≥2 members");
    assert_eq!(
        warm, original,
        "concatenated-members decode is not byte-identical"
    );

    let cpu0 = cpu_secs();
    let t0 = Instant::now();
    let got = lgz::speculative::decode_concatenated_members(&multi, nc)
        .expect("multi-member decode returns Some");
    let wall = t0.elapsed().as_secs_f64();
    let cpu = cpu_secs() - cpu0;

    // Correctness is the hard gate, asserted on every platform.
    assert_eq!(
        got, original,
        "concatenated-members decode is not byte-identical"
    );

    let cores_busy = if wall > 0.0 && cpu.is_finite() {
        cpu / wall
    } else {
        f64::NAN
    };
    eprintln!(
        "decode_concatenated_members: members={n_members} cores={nc} wall={wall:.3}s \
         cpu={cpu:.3}s cores_busy={cores_busy:.2}"
    );

    if nc >= 4 && cores_busy.is_finite() {
        // Conservative floor (0.35·cores, ≥2.5): the parallel single-buffer decode
        // clears it comfortably (~7/12 on a 12-core box); the old serial-prelude /
        // per-member-alloc path (~3/12) does not.
        let floor = (nc as f64 * 0.35).max(2.5);
        assert!(
            cores_busy >= floor,
            "cores_busy {cores_busy:.2} < floor {floor:.2}: concatenated-members decode \
             is not saturating a {nc}-core box (serial-prelude / per-member-alloc regression?)"
        );
    } else {
        eprintln!("saturation floor skipped (cores={nc}, cores_busy={cores_busy:.2})");
    }
}
