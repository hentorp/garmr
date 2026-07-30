//! Benchmark ljar on a large ZIP file with wall-clock timing.
//!
//! Usage: cargo run --release --bin bench_large -- /path/to/scratch/large_test.zip

use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: bench_large <file.zip>");

    let ncpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    eprintln!("CPUs available: {ncpus}");
    eprintln!(
        "LJAR_THREADS: {}",
        std::env::var("LJAR_THREADS").unwrap_or_else(|_| format!("{ncpus}"))
    );

    // Read entire file into memory (we're benchmarking decompression, not I/O)
    eprintln!("Loading {path} into memory...");
    let t0 = Instant::now();
    let data = std::fs::read(path).expect("read file");
    let load_time = t0.elapsed();
    eprintln!(
        "  Loaded {:.2} MB in {:.1}ms ({:.1} GB/s I/O)",
        data.len() as f64 / 1e6,
        load_time.as_secs_f64() * 1000.0,
        data.len() as f64 / load_time.as_secs_f64() / 1e9,
    );

    // Warm up (first call initializes thread pool + fixed tables)
    eprintln!("Warm-up run...");
    let t1 = Instant::now();
    let entries = ljar::decompress_jar(&data).expect("decompress");
    let warmup = t1.elapsed();
    let total_uncompressed: usize = entries.iter().map(|e| e.data.len()).sum();
    eprintln!(
        "  Warmup: {} entries, {:.2} GB decompressed in {:.1}ms",
        entries.len(),
        total_uncompressed as f64 / 1e9,
        warmup.as_secs_f64() * 1000.0,
    );
    drop(entries);

    // Timed runs
    eprintln!("\nBenchmark (5 runs):");
    let mut times = Vec::new();
    for i in 0..5 {
        let t = Instant::now();
        let entries = ljar::decompress_jar(&data).expect("decompress");
        let elapsed = t.elapsed();
        let n_entries = entries.len();
        let decomp_bytes: usize = entries.iter().map(|e| e.data.len()).sum();
        drop(entries);

        let secs = elapsed.as_secs_f64();
        let throughput_compressed = data.len() as f64 / secs / 1e9;
        let throughput_decompressed = decomp_bytes as f64 / secs / 1e9;
        eprintln!(
            "  Run {}: {:.1}ms | {n_entries} entries | {:.2} GB/s (compressed) | {:.2} GB/s (decompressed)",
            i + 1,
            secs * 1000.0,
            throughput_compressed,
            throughput_decompressed
        );
        times.push(secs);
    }

    let avg = times.iter().sum::<f64>() / times.len() as f64;
    let min = times.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = times.iter().cloned().fold(0.0f64, f64::max);

    eprintln!("\n─── Summary ───────────────────────────────────────────");
    eprintln!("  File:         {path}");
    eprintln!("  Compressed:   {:.2} MB", data.len() as f64 / 1e6);
    eprintln!("  Decompressed: {:.2} GB", total_uncompressed as f64 / 1e9);
    eprintln!("  Entries:      {}", 163840); // known from gen
    eprintln!("  Threads:      {ncpus}");
    eprintln!("  Avg time:     {:.1} ms", avg * 1000.0);
    eprintln!("  Min time:     {:.1} ms", min * 1000.0);
    eprintln!("  Max time:     {:.1} ms", max * 1000.0);
    eprintln!(
        "  Throughput:   {:.2} GB/s (decompressed output)",
        total_uncompressed as f64 / avg / 1e9
    );
    eprintln!(
        "  Per-core:     {:.2} GB/s (÷ {ncpus})",
        total_uncompressed as f64 / avg / 1e9 / ncpus as f64
    );
    eprintln!("───────────────────────────────────────────────────────");
}
