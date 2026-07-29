//! HEAD-TO-HEAD OSM-conversion bencher for osm-katana → the nornir warehouse.
//!
//! `nornir bench run osm-katana` subprocess-spawns this example
//! (`cargo run --release --example nornir-bench`), reads the LAST stdout line as
//! one `nornir::bench::BenchRun` JSON object, and appends it to the warehouse
//! `bench_runs` table under `repo=osm-katana`. `nornir docs render` then fills a
//! `<!-- nornir:gen:start:mashup … -->` / `:benches …` marker (in
//! `osm-katana/README.md`) from it — exactly the path the decode bake-off uses,
//! so osm-katana's "convert vs osmium/osmconvert" story renders on a page too.
//!
//! This mirrors `znippy-zoomies/examples/nornir-bench.rs`: a plain `main` that
//! hand-builds the `BenchRun` JSON with `serde_json` (no `nornir` dependency) and
//! prints it as the final stdout line — the whole contract.
//!
//! ## What it measures
//!
//! One OSM input is converted to GeoParquet by **osm-katana** (all cores, and a
//! deliberately single-worker `_st` row) and — when installed — by the legacy
//! reference tools **osmium** / **osmconvert**. Each system is one row; the
//! contested metrics are the columns:
//!
//!   * `convert_mbs`  — input MB / wall (conversion throughput)   [High]
//!   * `percore_mbs`  — throughput per host core                  [High]
//!   * `convert_s`    — conversion wall time                      [Low]
//!
//! osm-katana IS an OSM converter, so `convert_mbs` is the headline; the `_st`
//! row is the single-core lens (and the core-saturation gate's exempt-serial
//! marker). Rivals not installed are skipped and named.
//!
//! ## Input — small by default, heavy only when the parent asks
//!
//! By default a deterministic synthetic `.osm` (XML) corpus is generated so the
//! wiring is exercised on ANY box with NO download — this is NOT a heavy bench.
//! The parent runs the real HEAVY planet bench by pointing the bencher at a real
//! OSM file:
//!
//!   * `NORNIR_OSM_KATANA_INPUT` — path to a real `.osm`/`.osm.gz` XML file to
//!     convert instead of the synthetic corpus (the heavy-run knob).
//!   * `NORNIR_OSM_KATANA_MB`    — synthetic corpus size in MB (default 24).
//!   * `NORNIR_OSM_KATANA_ITERS` — timed iterations per system (default 3, min 1).
//!   * `NORNIR_OSM_KATANA_WORK`  — scratch dir (default a temp dir, off T9).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use osm_katana::{ConvertOptions, convert};
use serde_json::json;

fn cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn corpus_mb() -> usize {
    std::env::var("NORNIR_OSM_KATANA_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24)
}

/// Timed iterations per system. Clamped to ≥1 (a heavy planet run sets 1).
fn bench_iters() -> usize {
    std::env::var("NORNIR_OSM_KATANA_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3)
        .max(1)
}

/// Scratch dir for the corpus + per-run output. Off T9 by law: a caller-supplied
/// dir, else a process-unique temp dir under the OS temp root (never T9).
fn workdir() -> PathBuf {
    std::env::var("NORNIR_OSM_KATANA_WORK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::temp_dir().join(format!("osm-katana-bench-{}", std::process::id()))
        })
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn eprint_flush(s: &str) {
    eprintln!("{s}");
    let _ = std::io::stderr().flush();
}

fn file_len(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

/// Generate a deterministic synthetic OSM XML corpus of ~`target_bytes` bytes:
/// a grid of `<node>`s then `<way>`s referencing them, with a couple of tags —
/// enough for osm-katana's raw single-pass and any reference tool to churn on.
fn generate_osm_xml(path: &Path, target_bytes: u64) -> anyhow::Result<()> {
    if file_len(path) == target_bytes && target_bytes > 0 {
        eprint_flush(&format!(
            "corpus: reuse {} ({} MB)",
            path.display(),
            target_bytes / (1 << 20)
        ));
        return Ok(());
    }
    eprint_flush(&format!(
        "corpus: generating {} MB synthetic OSM XML …",
        target_bytes / (1 << 20)
    ));
    let f = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
    w.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")?;
    w.write_all(b"<osm version=\"0.6\" generator=\"nornir-bench\">\n")?;
    // Deterministic pseudo-random coords (splitmix64) around a fixed region.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut written: u64 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<osm version=\"0.6\" generator=\"nornir-bench\">\n".len() as u64
        + "</osm>\n".len() as u64;
    let mut id: u64 = 1;
    let mut line = String::with_capacity(256);
    // Nodes take ~85% of the budget; ways reference the last few node ids.
    let node_budget = (target_bytes as f64 * 0.85) as u64;
    let mut last_ids: Vec<u64> = Vec::new();
    while written < node_budget {
        let lat = 50.0 + (next() % 2_000_000) as f64 / 1e6; // 50.0 .. 52.0
        let lon = 8.0 + (next() % 2_000_000) as f64 / 1e6; //  8.0 .. 10.0
        line.clear();
        line.push_str(&format!(
            "  <node id=\"{id}\" lat=\"{lat:.6}\" lon=\"{lon:.6}\" version=\"1\"><tag k=\"amenity\" v=\"bench\"/></node>\n"
        ));
        w.write_all(line.as_bytes())?;
        written += line.len() as u64;
        last_ids.push(id);
        if last_ids.len() > 8 {
            last_ids.remove(0);
        }
        id += 1;
    }
    // A block of ways referencing recent nodes, filling the remaining budget.
    let mut way_id: u64 = 1;
    while written < target_bytes && last_ids.len() >= 2 {
        line.clear();
        line.push_str(&format!("  <way id=\"{way_id}\" version=\"1\">"));
        for nid in &last_ids {
            line.push_str(&format!("<nd ref=\"{nid}\"/>"));
        }
        line.push_str("<tag k=\"highway\" v=\"residential\"/></way>\n");
        w.write_all(line.as_bytes())?;
        written += line.len() as u64;
        way_id += 1;
        // Roll the node window forward deterministically so ways vary.
        let bump = 1 + (next() % 4);
        for v in last_ids.iter_mut() {
            *v = v.wrapping_add(bump).max(1);
        }
    }
    w.write_all(b"</osm>\n")?;
    w.flush()?;
    Ok(())
}

/// A benchmarked conversion system → one warehouse row.
struct System {
    /// Row name in the warehouse / rendered table.
    name: &'static str,
    /// How to run one conversion pass (returns on success).
    run: Box<dyn Fn(&Path, &Path) -> anyhow::Result<()>>,
}

/// One timed row's numbers → the `BenchResult`-shaped JSON object. Rounded like
/// the decode bake-off so the rendered cells are stable. Pure + testable.
fn result_row(name: &str, input_mb: f64, best_secs: f64, cores: usize) -> serde_json::Value {
    let mbs = if best_secs > 0.0 {
        input_mb / best_secs
    } else {
        0.0
    };
    json!({
        "name": name,
        "convert_mbs": (mbs * 100.0).round() / 100.0,
        "percore_mbs": (mbs / cores as f64 * 100.0).round() / 100.0,
        "convert_s": (best_secs * 1000.0).round() / 1000.0,
    })
}

/// Assemble the full `BenchRun`-shaped JSON (the LAST-stdout-line contract). Pure
/// + testable: given rows/tests/host facts it yields the object nornir ingests.
fn assemble_run(
    date: &str,
    timestamp: &str,
    version: &str,
    machine: &str,
    cores: usize,
    results: Vec<serde_json::Value>,
    tests: Vec<serde_json::Value>,
) -> serde_json::Value {
    json!({
        "date": date,
        "timestamp": timestamp,
        "version": version,
        "machine": machine,
        "cores": cores as u32,
        "results": results,
        "tests": tests,
    })
}

fn main() -> anyhow::Result<()> {
    let wd = workdir();
    std::fs::create_dir_all(&wd)?;
    let n = cores();
    let iters = bench_iters();

    // ── resolve the input (heavy real file, or synthetic corpus) ─────────────
    let input: PathBuf = match std::env::var("NORNIR_OSM_KATANA_INPUT") {
        Ok(p) if !p.is_empty() => {
            let p = PathBuf::from(p);
            eprint_flush(&format!(
                "input: real file {} ({} MB)",
                p.display(),
                file_len(&p) / (1 << 20)
            ));
            p
        }
        _ => {
            let corpus = wd.join("corpus.osm");
            generate_osm_xml(&corpus, corpus_mb() as u64 * (1 << 20))?;
            corpus
        }
    };
    let input_mb = file_len(&input) as f64 / (1024.0 * 1024.0);
    // Raw single-pass XML → GeoParquet is what osm-katana and the reference tools
    // race on (XML in, no node-resolution requirement). PBF/other inputs would
    // need `geometry=resolved`; the heavy knob can point at such a file and the
    // reference commands still apply.
    let is_xml = input.extension().is_some_and(|e| {
        ["osm", "gz", "bz2"]
            .iter()
            .any(|x| e.eq_ignore_ascii_case(x))
    });

    eprint_flush(&format!(
        "osm-katana bench: input={input_mb:.1} MB · {n} cores · {iters} iters (min-of-N)"
    ));

    // ── the system roster ────────────────────────────────────────────────────
    let mut systems: Vec<System> = Vec::new();

    // osm-katana, all cores (in-process; the honest lib path).
    {
        let xml = is_xml;
        systems.push(System {
            name: "osm-katana",
            run: Box::new(move |inp: &Path, out: &Path| {
                let opts = ConvertOptions {
                    output_dir: out.to_path_buf(),
                    vtd_workers: 0, // all cores minus one
                    geometry: if xml { "raw".into() } else { "resolved".into() },
                    skip_changesets: true,
                    log_path: Some(out.join("phase.log")),
                    ..Default::default()
                };
                convert(inp, &opts)
            }),
        });
        // Single-worker `_st` row — the single-core lens + core-sat exempt marker.
        let xml_st = is_xml;
        systems.push(System {
            name: "osm-katana_st",
            run: Box::new(move |inp: &Path, out: &Path| {
                let opts = ConvertOptions {
                    output_dir: out.to_path_buf(),
                    vtd_workers: 1,
                    geometry: if xml_st {
                        "raw".into()
                    } else {
                        "resolved".into()
                    },
                    skip_changesets: true,
                    log_path: Some(out.join("phase.log")),
                    ..Default::default()
                };
                convert(inp, &opts)
            }),
        });
    }

    // Reference tools (legacy) — only when installed. They convert to PBF; the
    // contested metric is input-MB/wall, same as osm-katana. Named + skipped when
    // absent, exactly like the decode bake-off's optional rivals.
    if have("osmium") {
        systems.push(System {
            name: "osmium",
            run: Box::new(|inp: &Path, out: &Path| {
                let dst = out.join("ref.osm.pbf");
                let st = Command::new("osmium")
                    .args(["cat", "--overwrite", "-o"])
                    .arg(&dst)
                    .arg(inp)
                    .status()?;
                if !st.success() {
                    anyhow::bail!("osmium cat failed: {st}");
                }
                Ok(())
            }),
        });
    }
    if have("osmconvert") {
        systems.push(System {
            name: "osmconvert",
            run: Box::new(|inp: &Path, out: &Path| {
                let dst = out.join("ref.pbf");
                let st = Command::new("sh")
                    .arg("-c")
                    .arg(format!("osmconvert {} -o={}", inp.display(), dst.display()))
                    .status()?;
                if !st.success() {
                    anyhow::bail!("osmconvert failed: {st}");
                }
                Ok(())
            }),
        });
    }

    // ── run each system (warmup, then min-of-N timed) ────────────────────────
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut tests: Vec<serde_json::Value> = Vec::new();
    for sys in &systems {
        let out = wd.join(format!("out-{}", sys.name));
        eprint_flush(&format!(
            "convert: {} … (warmup + {iters} timed, min-of-N)",
            sys.name
        ));
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out)?;
        // Untimed warmup pass (page-cache the input, warm the allocator).
        if let Err(e) = (sys.run)(&input, &out) {
            eprint_flush(&format!("  {} FAILED (warmup): {e}", sys.name));
            continue;
        }
        let mut best_secs = f64::INFINITY;
        let mut failed: Option<String> = None;
        for it in 0..iters {
            let _ = std::fs::remove_dir_all(&out);
            let _ = std::fs::create_dir_all(&out);
            let t0 = Instant::now();
            match (sys.run)(&input, &out) {
                Ok(()) => {
                    let secs = t0.elapsed().as_secs_f64();
                    best_secs = best_secs.min(secs);
                    eprint_flush(&format!("    iter {}/{iters}: {secs:.3}s", it + 1));
                }
                Err(e) => {
                    failed = Some(e.to_string());
                    break;
                }
            }
        }
        let _ = std::fs::remove_dir_all(&out);
        if let Some(e) = failed {
            eprint_flush(&format!("  {} FAILED: {e}", sys.name));
            continue;
        }
        let mbs = if best_secs > 0.0 {
            input_mb / best_secs
        } else {
            0.0
        };
        eprint_flush(&format!(
            "  {} → {mbs:.1} MB/s  ({best_secs:.2}s)",
            sys.name
        ));
        results.push(result_row(sys.name, input_mb, best_secs, n));
    }

    // ── correctness: osm-katana must produce a non-empty nodes.parquet ───────
    {
        let out = wd.join("verify");
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out)?;
        let opts = ConvertOptions {
            output_dir: out.clone(),
            geometry: if is_xml {
                "raw".into()
            } else {
                "resolved".into()
            },
            skip_changesets: true,
            log_path: Some(out.join("phase.log")),
            ..Default::default()
        };
        let ok = convert(&input, &opts).is_ok() && file_len(&out.join("nodes.parquet")) > 0;
        tests.push(json!({ "name": "osm_katana_convert_emits_nodes_parquet", "passed": ok }));
        let _ = std::fs::remove_dir_all(&out);
    }

    // Best-effort cleanup of the synthetic corpus + workdir (off-T9 scratch).
    if std::env::var("NORNIR_OSM_KATANA_INPUT")
        .map(|v| v.is_empty())
        .unwrap_or(true)
    {
        let _ = std::fs::remove_file(wd.join("corpus.osm"));
    }

    // ── host facts + emit (LAST stdout line = the contract) ──────────────────
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|m| m.trim().to_string())
        })
        .unwrap_or_else(|| "unknown-cpu".into());
    let mem_gb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|k| k.parse::<u64>().ok())
        })
        .map(|kb| kb / (1024 * 1024))
        .unwrap_or(0);
    let machine = format!("{cpu} · {mem_gb} GiB · input {input_mb:.0} MB · min-of-{iters}");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let days = now / 86400;
    let date = epoch_days_to_date(days as i64);
    let tod = now % 86400;
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let timestamp = format!("{date}T{hh:02}:{mm:02}:{ss:02}Z");

    let run = assemble_run(
        &date,
        &timestamp,
        env!("CARGO_PKG_VERSION"),
        &machine,
        n,
        results,
        tests,
    );
    println!("{}", serde_json::to_string(&run)?);
    Ok(())
}

/// Days-since-epoch → `YYYY-MM-DD` (civil calendar, Howard Hinnant's algorithm).
fn epoch_days_to_date(z: i64) -> String {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The emit contract: `assemble_run` yields a single-line-serializable object
    /// carrying every field nornir's `BenchRun` deserializer needs — `date`,
    /// `results` (each a `BenchResult`: a `name` + numeric metric columns), and
    /// `tests` — so `nornir bench run osm-katana` ingests it into `bench_runs`.
    #[test]
    fn assemble_run_matches_benchrun_shape() {
        let rows = vec![
            result_row("osm-katana", 100.0, 0.5, 12),
            result_row("osmium", 100.0, 2.0, 12),
        ];
        let tests = vec![serde_json::json!({ "name": "t", "passed": true })];
        let run = assemble_run(
            "2026-07-08",
            "2026-07-08T00:00:00Z",
            "0.2.1",
            "test-cpu · 61 GiB",
            12,
            rows,
            tests,
        );

        // Top-level BenchRun fields.
        assert_eq!(run["date"], "2026-07-08");
        assert!(run["timestamp"].is_string());
        assert_eq!(run["cores"], 12);
        let results = run["results"].as_array().expect("results is an array");
        assert_eq!(results.len(), 2);

        // Each result is a BenchResult: a name + numeric metric columns.
        let k = &results[0];
        assert_eq!(k["name"], "osm-katana");
        assert!(k["convert_mbs"].is_number(), "convert_mbs must be numeric");
        assert!(k["percore_mbs"].is_number());
        assert!(k["convert_s"].is_number());
        // 100 MB / 0.5 s = 200 MB/s; per-core = 200/12.
        assert!((k["convert_mbs"].as_f64().unwrap() - 200.0).abs() < 1e-6);
        assert!(
            (k["percore_mbs"].as_f64().unwrap() - (200.0f64 / 12.0 * 100.0).round() / 100.0).abs()
                < 1e-6
        );

        // The whole run must round-trip through serde as ONE stdout line (no
        // embedded newline) — the last-line contract nornir reads.
        let line = serde_json::to_string(&run).unwrap();
        assert!(
            !line.contains('\n'),
            "the emitted BenchRun must be a single line"
        );
        let reparsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reparsed["results"].as_array().unwrap().len(), 2);
        assert_eq!(reparsed["tests"].as_array().unwrap()[0]["passed"], true);
    }

    /// A slower system yields a lower `convert_mbs` and higher `convert_s` — the
    /// direction the mashup renderer bolds on (`_mbs` High, `_s` Low).
    #[test]
    fn slower_system_has_lower_throughput() {
        let fast = result_row("osm-katana", 100.0, 0.5, 12);
        let slow = result_row("osmium", 100.0, 2.0, 12);
        assert!(fast["convert_mbs"].as_f64().unwrap() > slow["convert_mbs"].as_f64().unwrap());
        assert!(fast["convert_s"].as_f64().unwrap() < slow["convert_s"].as_f64().unwrap());
    }
}
