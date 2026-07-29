//! Single-core inflate comparison: ljar vs flate2(zlib-ng) vs miniz_oxide.
//!
//! Extracts raw DEFLATE entries from a JAR and benchmarks inflate speed.
//!
//! Usage: cargo run --release --features zlib-ng --bin bench_inflate_cmp -- <file.jar>

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: bench_inflate_cmp <file.jar>");

    let data = std::fs::read(path).unwrap();
    let cursor = std::io::Cursor::new(&data);
    let mut archive = zip::ZipArchive::new(cursor).unwrap();

    // Collect deflated entries (raw compressed data + expected sizes)
    let mut entries: Vec<(Vec<u8>, usize)> = Vec::new();
    let mut total_decompressed = 0usize;

    for i in 0..archive.len() {
        let mut entry = archive.by_index_raw(i).unwrap();
        if entry.is_dir() || entry.compression() != zip::CompressionMethod::Deflated {
            continue;
        }
        let mut raw = Vec::new();
        entry.read_to_end(&mut raw).unwrap();
        let expected = entry.size() as usize;
        total_decompressed += expected;
        entries.push((raw, expected));
    }

    eprintln!(
        "{} deflated entries, {:.2} MB compressed, {:.2} MB decompressed",
        entries.len(),
        entries.iter().map(|(r, _)| r.len()).sum::<usize>() as f64 / 1e6,
        total_decompressed as f64 / 1e6,
    );

    let n_runs = 20;

    // Benchmark ljar inflate (single-threaded)
    let mut ljar_times = Vec::new();
    for _ in 0..n_runs {
        let t = std::time::Instant::now();
        for (raw, expected) in &entries {
            let _ = ljar::inflate::inflate_to_vec(raw, *expected).unwrap();
        }
        ljar_times.push(t.elapsed().as_secs_f64());
    }

    // Benchmark flate2 (zlib-ng backend) inflate (single-threaded)
    let mut flate2_times = Vec::new();
    #[cfg(feature = "zlib-ng")]
    for _ in 0..n_runs {
        let t = std::time::Instant::now();
        for (raw, expected) in &entries {
            let mut decoder = flate2::read::DeflateDecoder::new(raw.as_slice());
            let mut out = Vec::with_capacity(*expected);
            decoder.read_to_end(&mut out).unwrap();
        }
        flate2_times.push(t.elapsed().as_secs_f64());
    }

    // Benchmark miniz_oxide inflate (single-threaded)
    let mut miniz_times = Vec::new();
    for _ in 0..n_runs {
        let t = std::time::Instant::now();
        for (raw, _expected) in &entries {
            let _ = miniz_oxide::inflate::decompress_to_vec(raw).unwrap();
        }
        miniz_times.push(t.elapsed().as_secs_f64());
    }

    // Drop first 2 warmup runs
    let ljar_avg = ljar_times[2..].iter().sum::<f64>() / (n_runs - 2) as f64;
    let miniz_avg = miniz_times[2..].iter().sum::<f64>() / (n_runs - 2) as f64;

    let ljar_min = ljar_times[2..]
        .iter()
        .cloned()
        .fold(f64::INFINITY, f64::min);
    let miniz_min = miniz_times[2..]
        .iter()
        .cloned()
        .fold(f64::INFINITY, f64::min);

    #[cfg(feature = "zlib-ng")]
    let (flate2_avg, flate2_min) = {
        let avg = flate2_times[2..].iter().sum::<f64>() / (n_runs - 2) as f64;
        let min = flate2_times[2..]
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
        (avg, min)
    };

    eprintln!("\n─── Single-core inflate: {} ──────────────────", path);
    eprintln!(
        "  ljar:        avg {:.1} ms  best {:.1} ms  ({:.0} MB/s)",
        ljar_avg * 1000.0,
        ljar_min * 1000.0,
        total_decompressed as f64 / ljar_min / 1e6
    );
    #[cfg(feature = "zlib-ng")]
    eprintln!(
        "  flate2/zng:  avg {:.1} ms  best {:.1} ms  ({:.0} MB/s)",
        flate2_avg * 1000.0,
        flate2_min * 1000.0,
        total_decompressed as f64 / flate2_min / 1e6
    );
    eprintln!(
        "  miniz_oxide: avg {:.1} ms  best {:.1} ms  ({:.0} MB/s)",
        miniz_avg * 1000.0,
        miniz_min * 1000.0,
        total_decompressed as f64 / miniz_min / 1e6
    );
    eprintln!("  ");
    #[cfg(feature = "zlib-ng")]
    eprintln!("  ljar vs zlib-ng: {:.2}×", flate2_avg / ljar_avg);
    eprintln!("  ljar vs miniz:   {:.2}×", miniz_avg / ljar_avg);
    eprintln!("────────────────────────────────────────────────────────");
}
