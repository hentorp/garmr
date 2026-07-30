//! Benchmark: lbzip2-rs vs bzip2 crate decompression speed.
//!
//! Run with: cargo test --release bench_decompress -- --nocapture --ignored

use std::time::Instant;

/// Reference decompressor using the `bzip2` crate.
fn decompress_bzip2_crate(data: &[u8]) -> Vec<u8> {
    use bzip2::read::BzDecoder;
    use std::io::Read;
    let mut decoder = BzDecoder::new(data);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .expect("bzip2 crate decompress failed");
    output
}

/// Our sequential decompressor.
fn decompress_sequential(data: &[u8]) -> Vec<u8> {
    lbzip2::stream::decompress(data).expect("lbzip2-rs decompress failed")
}

/// Our parallel decompressor.
fn decompress_parallel(data: &[u8]) -> Vec<u8> {
    lbzip2::parallel::decompress_parallel(data).expect("lbzip2-rs parallel decompress failed")
}

#[test]
fn bench_decompress() {
    let compressed = include_bytes!("../test_data/liechtenstein.osm.bz2");
    let comp_size = compressed.len();

    println!("\n=== bzip2 Decompression Benchmark ===");
    println!(
        "Input: liechtenstein.osm.bz2 ({:.2} MB compressed)",
        comp_size as f64 / 1_048_576.0
    );

    // ── Correctness check ───────────────────────────────────────────────
    let ref_output = decompress_bzip2_crate(compressed);
    let seq_output = decompress_sequential(compressed);
    let par_output = decompress_parallel(compressed);
    let decomp_size = ref_output.len();

    assert_eq!(ref_output.len(), seq_output.len(), "seq size mismatch");
    assert_eq!(ref_output, seq_output, "seq content mismatch");
    assert_eq!(ref_output.len(), par_output.len(), "par size mismatch");
    assert_eq!(ref_output, par_output, "par content mismatch");

    println!(
        "Output: {:.2} MB decompressed — all 3 outputs match ✓",
        decomp_size as f64 / 1_048_576.0
    );
    println!("Ratio: {:.1}×\n", decomp_size as f64 / comp_size as f64);

    let iterations = 3;

    // ── Benchmark: bzip2 crate ──────────────────────────────────────────
    let mut times = Vec::new();
    for _ in 0..iterations {
        let start = Instant::now();
        let out = decompress_bzip2_crate(compressed);
        times.push(start.elapsed());
        std::hint::black_box(&out);
    }
    let best = *times.iter().min().unwrap();
    println!("bzip2 crate (C libbz2, single-thread):");
    println!(
        "  best:  {:>8.1} ms  ({:.1} MB/s)\n",
        best.as_secs_f64() * 1000.0,
        decomp_size as f64 / best.as_secs_f64() / 1_048_576.0
    );
    let c_best = best;

    // ── Benchmark: our sequential ───────────────────────────────────────
    let mut times = Vec::new();
    for _ in 0..iterations {
        let start = Instant::now();
        let out = decompress_sequential(compressed);
        times.push(start.elapsed());
        std::hint::black_box(&out);
    }
    let best = *times.iter().min().unwrap();
    println!("lbzip2-rs (pure Rust, single-thread):");
    println!(
        "  best:  {:>8.1} ms  ({:.1} MB/s)  {:.1}× vs C\n",
        best.as_secs_f64() * 1000.0,
        decomp_size as f64 / best.as_secs_f64() / 1_048_576.0,
        c_best.as_secs_f64() / best.as_secs_f64()
    );

    // ── Benchmark: our parallel ─────────────────────────────────────────
    // Warmup scoped-thread workers
    let _ = decompress_parallel(compressed);
    let mut times = Vec::new();
    for _ in 0..iterations {
        let start = Instant::now();
        let out = decompress_parallel(compressed);
        times.push(start.elapsed());
        std::hint::black_box(&out);
    }
    let best_par = *times.iter().min().unwrap();
    let ncpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!("lbzip2-rs (pure Rust, parallel, {} threads):", ncpus);
    println!(
        "  best:  {:>8.1} ms  ({:.1} MB/s)  {:.1}× vs C\n",
        best_par.as_secs_f64() * 1000.0,
        decomp_size as f64 / best_par.as_secs_f64() / 1_048_576.0,
        c_best.as_secs_f64() / best_par.as_secs_f64()
    );
}
