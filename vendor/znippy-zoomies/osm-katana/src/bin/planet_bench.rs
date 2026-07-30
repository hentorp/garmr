//! Planet unpack+clip bencher (dev-only).
//!
//! Build/run with the fixture feature:
//!     cargo run --release -p osm-katana --features dev --bin planet_bench
//! (or `--features planet-fixture`). Without the feature it compiles to a stub.
//!
//! Fetches the OSM planet `.osm.bz2` via pure-Rust torrent (off T9, under
//! ~/.cache — see `osm_katana::fixture`), then for each region times the
//! one-call unpack+clip (`osm_katana::convert`) and prints a bench_history-shaped
//! row. It does NOT append to bench_history.json (a human/real-run artifact).

#[cfg(not(feature = "planet-fixture"))]
fn main() {
    eprintln!("planet_bench: rebuild with --features planet-fixture (or --features dev)");
}

#[cfg(feature = "planet-fixture")]
fn main() -> anyhow::Result<()> {
    use std::sync::Arc;
    use std::time::Instant;

    use osm_katana::fixture::{ensure_planet_osm, planet_cache_path};
    use osm_katana::{Bounds, Clip, ConvertOptions, convert};

    let planet = ensure_planet_osm()?;
    let input_bytes = std::fs::metadata(&planet)?.len();
    let input_mb = input_bytes as f64 / (1024.0 * 1024.0);
    let all_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let cache_dir = planet_cache_path()
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    eprintln!(
        "planet_bench: input {} ({:.1} MiB), {} cores",
        planet.display(),
        input_mb,
        all_cores
    );

    // Header matching the bench_history per-result schema.
    println!(
        "{:<28} {:>12} {:>10} {:>16} {:>15} {:>10}",
        "name", "input_format", "input_mb", "single_core_mbs", "multi_core_mbs", "cores_used"
    );

    for region in ["nordics", "europe"] {
        let clip = Some(Arc::new(Clip::Bbox(Bounds::parse(region)?)));

        // Single core: one VTD worker.
        let out_single = cache_dir.join(format!("{region}-geo-single"));
        let opts_single = ConvertOptions {
            output_dir: out_single,
            clip: clip.clone(),
            skip_changesets: true,
            vtd_workers: 1,
            ..Default::default()
        };
        let t0 = Instant::now();
        convert(&planet, &opts_single)?;
        let single_mbs = input_mb / t0.elapsed().as_secs_f64();

        // Multi core: all cores (vtd_workers = 0 → all-but-one inside convert).
        let out_multi = cache_dir.join(format!("{region}-geo"));
        let opts_multi = ConvertOptions {
            output_dir: out_multi,
            clip: clip.clone(),
            skip_changesets: true,
            ..Default::default()
        };
        let t1 = Instant::now();
        convert(&planet, &opts_multi)?;
        let multi_mbs = input_mb / t1.elapsed().as_secs_f64();

        println!(
            "{:<28} {:>12} {:>10.1} {:>16.1} {:>15.1} {:>10}",
            format!("planet_bz2_clip_{region}"),
            "bz2",
            input_mb,
            single_mbs,
            multi_mbs,
            all_cores
        );
    }

    Ok(())
}
