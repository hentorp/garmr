use std::time::Instant;

fn main() {
    let path_str = concat!(env!("CARGO_MANIFEST_DIR"), "/../liechtenstein.osm");
    let path = std::path::Path::new(path_str);
    let bytes = std::fs::read(path).expect("liechtenstein.osm not found");
    let n_cores = std::thread::available_parallelism().unwrap().get();
    println!("file: {} MB,  cores: {}", bytes.len() / 1_048_576, n_cores);

    // ── single-threaded ──────────────────────────────────────────────────────
    let runs = 5;
    let mut seq_total = std::time::Duration::ZERO;
    let mut seq_count = 0u64;
    for _ in 0..runs {
        let mut count = 0u64;
        let t = Instant::now();
        osm_katana::xml_vtd::build_elem_index(&bytes, |_| count += 1).unwrap();
        seq_total += t.elapsed();
        seq_count = count;
    }
    println!(
        "single-threaded:  {:>7.1} ms avg  ({seq_count} elements)",
        seq_total.as_secs_f64() * 1000.0 / runs as f64
    );

    // ── parallel (build_elem_index_parallel) ─────────────────────────────────
    let mut par_total = std::time::Duration::ZERO;
    for _ in 0..runs {
        let mut count = 0u64;
        let t = Instant::now();
        osm_katana::xml_vtd::build_elem_index_parallel(&bytes, n_cores - 1, |_| count += 1)
            .unwrap();
        par_total += t.elapsed();
    }
    println!(
        "parallel ({:2} workers): {:>7.1} ms avg",
        n_cores - 1,
        par_total.as_secs_f64() * 1000.0 / runs as f64
    );

    // ── mmap streaming ───────────────────────────────────────────────────────
    let idx_path = std::path::Path::new("/tmp/bench_elem.idx");
    let mut mmap_total = std::time::Duration::ZERO;
    for _ in 0..runs {
        let t = Instant::now();
        osm_katana::xml_vtd::build_elem_index_to_mmap(&bytes, n_cores - 1, idx_path).unwrap();
        mmap_total += t.elapsed();
    }
    println!(
        "mmap stream ({:2} workers): {:>7.1} ms avg  (index → disk, zero Vec)",
        n_cores - 1,
        mmap_total.as_secs_f64() * 1000.0 / runs as f64
    );

    // ── revolver (no-barrier) ────────────────────────────────────────────────
    let rev_path = std::path::Path::new("/tmp/bench_elem_rev.idx");
    let mut rev_total = std::time::Duration::ZERO;
    let mut rev_count = 0u64;
    for _ in 0..runs {
        let t = Instant::now();
        rev_count =
            osm_katana::xml_vtd::build_elem_index_revolver(&bytes, n_cores - 1, rev_path).unwrap();
        rev_total += t.elapsed();
    }
    println!(
        "revolver  ({:2} workers): {:>7.1} ms avg  ({rev_count} elements, no barrier)",
        n_cores - 1,
        rev_total.as_secs_f64() * 1000.0 / runs as f64
    );

    // ── pipelined reader ─────────────────────────────────────────────────────
    let pipe_path = std::path::Path::new("/tmp/bench_elem_pipe.idx");
    let mut pipe_total = std::time::Duration::ZERO;
    let mut pipe_count = 0u64;
    for _ in 0..runs {
        let t = Instant::now();
        pipe_count =
            osm_katana::xml_vtd::build_elem_index_pipelined(path, n_cores - 1, pipe_path).unwrap();
        pipe_total += t.elapsed();
    }
    println!(
        "pipelined ({:2} workers): {:>7.1} ms avg  ({pipe_count} elements, I/O+parse overlap)",
        n_cores - 1,
        pipe_total.as_secs_f64() * 1000.0 / runs as f64
    );

    let speedup_par = seq_total.as_secs_f64() / par_total.as_secs_f64();
    let speedup_mmap = seq_total.as_secs_f64() / mmap_total.as_secs_f64();
    let speedup_rev = seq_total.as_secs_f64() / rev_total.as_secs_f64();
    let speedup_pipe = seq_total.as_secs_f64() / pipe_total.as_secs_f64();
    println!(
        "\nspeedup  parallel: {speedup_par:.1}×   mmap-stream: {speedup_mmap:.1}×   revolver: {speedup_rev:.1}×   pipelined: {speedup_pipe:.1}×"
    );
}
