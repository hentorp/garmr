//! HEAVY head-to-head decompressor bake-off for znippy-zoomies.
//!
//! `nornir bench run znippy-zoomies` subprocess-spawns this example
//! (`cargo run --release --example nornir-bench`), reads the LAST stdout
//! line as one `nornir::bench::BenchRun` JSON object, and appends it to the
//! warehouse `bench_runs` table. `nornir docs render` then fills the
//! `<!-- nornir:gen:start:mashup … -->` marker in `.nornir/README.md` from it.
//!
//! ## What it measures — a WIDE, honest, all-cores-maxed bake-off
//!
//! One large deterministic corpus is compressed into every rival's own format,
//! then decompressed back by **every** decompressor on the box — znippy-zoomies'
//! parallel `lgz` / `lbunzip2` against the legacy serial tools *and* the other
//! parallel C decompressors, all at full cores + max memory. Each system is one
//! row; the contested metrics are the columns. Our two decoders ALSO emit a
//! single-worker `_st` row (`LGZ_THREADS=1` / `LBZIP2_THREADS=1`) so the README's
//! single-core lens can race one core each, and the core-saturation gate exempts
//! the deliberately-serial `_st` variants:
//!
//!   * `decompress_mbs` — decode throughput (output MB / wall)      [High]
//!   * `percore_mbs`    — decode throughput per host core           [High]
//!   * `compress_mbs`   — how fast that format was produced         [High]
//!   * `ratio`          — corpus / compressed size (compression)    [High]
//!   * `decompress_s`   — decode wall time                          [Low]
//!   * `peak_mem_mb`    — peak RSS of the decode (GNU time -v)       [Low]
//!
//! znippy-zoomies IS a decompressor family, so decode throughput is the
//! headline. `lgz` parallel-decodes **multi-member gzip** (a standard,
//! concatenatable format every gzip tool reads); `lbunzip2` parallel-decodes
//! stock `bzip2 -9` blocks. Rivals not installed are skipped and named.
//!
//! ## Stable timing — warmup + min-of-N
//!
//! Every decoder is timed over **N ≥ 3** iterations after one untimed **warmup**
//! pass (which page-caches the compressed input and JIT-warms the allocator).
//! We keep the **min** wall time — the least-perturbed sample, the standard
//! choice for throughput micro-benchmarks (noise only ever *slows* a run) — and
//! the **max** peak RSS across the timed iterations (the true high-water mark).
//! Single-iteration numbers were noisy run-to-run; min-of-N is reproducible.
//!
//! ## PREVIEW (light) runs — the loop-and-fix enabler
//!
//! The heavy bake-off builds a 1 GB corpus in every rival format; that is minutes
//! of setup before a single osm-katana number appears, which is useless when you
//! are iterating on osm-katana's core occupancy. `NORNIR_ZOOMIES_CORPUS_MB=0` is
//! the light lens on the SAME vocabulary: it means "no decompressor corpus", so
//! the decoder roster is empty and only the osm-katana convert arm runs. Every
//! osm-katana code path, row and metric key is identical to the heavy run — same
//! `convert`, same per-phase occupancy rows, same digest gate — just at small
//! scale, so a fix can be measured in seconds:
//!
//! ```sh
//! NORNIR_ZOOMIES_CORPUS_MB=0 NORNIR_ZOOMIES_WORK=/tmp/zb \
//!   cargo run --release --example nornir-bench
//! ```
//!
//! A run is **PREVIEW** whenever the decompressor corpus is under the heavy
//! default OR the osm-katana input is under [`OSM_HEAVY_MIN_MB`]. A preview run
//! **never prints a `BenchRun` contract line on stdout** — the numbers go to
//! stderr under a loud banner and stdout carries a `PREVIEW RUN` notice instead.
//! `nornir bench run` therefore cannot warehouse a light number, and a preview
//! can never overwrite a real host row in a README table.
//!
//! Env knobs:
//!   * `NORNIR_ZOOMIES_CORPUS_MB` — decompressor corpus size in MB.
//!     `1024` (default) = heavy · `256` = light · `0` = none (osm-katana only).
//!   * `NORNIR_ZOOMIES_WORK`      — scratch dir (default /mnt/work4t/zoomies-bench).
//!   * `NORNIR_ZOOMIES_ITERS`     — timed iterations per decoder (default 3, min 3).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use serde_json::json;

fn workdir() -> PathBuf {
    std::env::var("NORNIR_ZOOMIES_WORK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/mnt/work4t/zoomies-bench"))
}

fn cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// The corpus size a *publishable* decompressor bake-off runs at. Anything less
/// is a preview (see [`Preview`]).
const HEAVY_CORPUS_MB: usize = 1024;

/// Smallest osm-katana input that counts as a publishable convert measurement.
/// Below this the run is dominated by process start-up / thread-pool spawn /
/// parquet footer work — exactly the regime `.nornir/benchmarks.md` already
/// warns about ("Do not read 12-core scaling — or any throughput ranking — from
/// this table"). Liechtenstein (3.3 MB) and any small synthetic corpus are
/// therefore always PREVIEW.
const OSM_HEAVY_MIN_MB: u64 = 1024;

fn corpus_mb() -> usize {
    std::env::var("NORNIR_ZOOMIES_CORPUS_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(HEAVY_CORPUS_MB)
}

/// `NORNIR_ZOOMIES_CORPUS_MB=0` ⇒ build no decompressor corpus at all. The
/// decoder roster is then empty and the run is the osm-katana convert arm only —
/// the seconds-turnaround lens for the osm-katana optimise loop.
fn decoder_bakeoff_enabled() -> bool {
    corpus_mb() > 0
}

/// Timed iterations per decoder (min-of-N). Clamped to ≥3 so the reported number
/// is always a min over at least three samples, never a lone measurement.
fn bench_iters() -> usize {
    std::env::var("NORNIR_ZOOMIES_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3)
        .max(3)
}

/// Directory holding the freshly-built znippy-zoomies member binaries. `cargo`
/// (driven by `nornir bench run` with our `CARGO_TARGET_DIR`) leaves them under
/// `<target>/release`.
fn bin_dir() -> PathBuf {
    if let Ok(t) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(t).join("release");
    }
    PathBuf::from("target/release")
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

/// Run a `sh -c` command to completion, bailing on non-zero exit.
fn sh(cmd: &str) -> anyhow::Result<()> {
    let st = Command::new("sh").arg("-c").arg(cmd).status()?;
    if !st.success() {
        anyhow::bail!("command failed ({st}): {cmd}");
    }
    Ok(())
}

/// Parsed fields of a GNU `time -v` report: `(peak_rss_mb, cpu_seconds,
/// elapsed_wall_seconds)`. `elapsed_wall_seconds` is `None` if the "Elapsed
/// (wall clock) time" line is absent/unparseable. `cpu_seconds` = User + System.
///
/// Pure + shell-free (L9) so the throughput math can be asserted against a known
/// `/usr/bin/time -v` oracle report in a unit test (H1: reconcile `decompress_mbs`
/// with the wall clock `/usr/bin/time` itself reports — the exact quantity the
/// "standalone via `/usr/bin/time`" baseline is read from).
fn parse_time_report(txt: &str) -> (f64, f64, Option<f64>) {
    let mut rss_mb = 0.0;
    let mut user_s = 0.0;
    let mut sys_s = 0.0;
    let mut elapsed_s: Option<f64> = None;
    for line in txt.lines() {
        let l = line.trim();
        if l.starts_with("Maximum resident set size") {
            if let Some(kb) = l
                .rsplit(':')
                .next()
                .and_then(|s| s.trim().parse::<f64>().ok())
            {
                rss_mb = kb / 1024.0;
            }
        } else if l.starts_with("User time (seconds)") {
            if let Some(v) = l
                .rsplit(':')
                .next()
                .and_then(|s| s.trim().parse::<f64>().ok())
            {
                user_s = v;
            }
        } else if l.starts_with("System time (seconds)") {
            if let Some(v) = l
                .rsplit(':')
                .next()
                .and_then(|s| s.trim().parse::<f64>().ok())
            {
                sys_s = v;
            }
        } else if l.starts_with("Elapsed (wall clock) time") {
            // Value is the tail after the LAST ": " label separator, formatted
            // `h:mm:ss` or `m:ss(.frac)` — parse right-to-left: seconds, minutes,
            // hours. (The label itself contains colons, so split the VALUE only.)
            if let Some(val) = l.rsplit(": ").next() {
                elapsed_s = parse_hms(val.trim());
            }
        }
    }
    (rss_mb, user_s + sys_s, elapsed_s)
}

/// Parse a GNU-time elapsed value `h:mm:ss` / `m:ss` / `s` into seconds.
fn parse_hms(v: &str) -> Option<f64> {
    let mut secs = 0.0;
    let mut any = false;
    for (i, part) in v.rsplit(':').enumerate() {
        let n: f64 = part.trim().parse().ok()?;
        any = true;
        secs += n * 60f64.powi(i as i32);
        if i >= 2 {
            break; // h:mm:ss — nothing coarser than hours in GNU time output.
        }
    }
    any.then_some(secs)
}

/// Time a decode command (`sh -c cmd`) under `/usr/bin/time -v`, returning
/// `(wall_seconds, peak_rss_mb, cpu_seconds)`. Peak RSS, CPU time AND the wall
/// clock are parsed from GNU time's report, written to a side file so the tool's
/// own stderr never corrupts it.
///
/// `wall_seconds` is GNU time's own **"Elapsed (wall clock) time"** — the SAME
/// number a hand-run `/usr/bin/time <decoder>` prints, i.e. the exact basis the
/// byte-verified "standalone" baseline is measured on. We deliberately do NOT use
/// the Rust `Instant` around the wrapper: that additionally bills every decode for
/// the `/usr/bin/time` fork/exec + the extra outer `sh -c` + report-file teardown,
/// a fixed per-invocation tax that skews the fast decoders' throughput. The
/// `Instant` is kept only as a fallback when the report has no parseable elapsed.
///
/// `cpu_seconds` is GNU time's `User time + System time`, which `wait4()`
/// aggregates over the whole subtree of the `sh` it launched — so it captures the
/// child rival tool (gzip/pigz/lbzip2/…) exactly as it captures our own codecs
/// (all decoders here are spawned as subprocesses). Dividing by wall then gives
/// the REAL average cores kept busy during the decode (`cores_busy`), not the
/// `total ÷ nproc` proxy that `percore_mbs` is.
fn timed(cmd: &str) -> anyhow::Result<(f64, f64, f64)> {
    let rpt = workdir().join(".time.txt");
    let wrapped = format!(
        "/usr/bin/time -v -o {} sh -c {}",
        rpt.display(),
        shell_quote(cmd)
    );
    let t0 = Instant::now();
    let st = Command::new("sh").arg("-c").arg(&wrapped).status()?;
    let instant_wall = t0.elapsed().as_secs_f64();
    if !st.success() {
        anyhow::bail!("decode failed ({st}): {cmd}");
    }
    let (rss_mb, cpu_s, elapsed) = std::fs::read_to_string(&rpt)
        .map(|txt| parse_time_report(&txt))
        .unwrap_or((0.0, 0.0, None));
    // Prefer /usr/bin/time's reported elapsed (the standalone basis); fall back to
    // the Instant only if the report lacked a parseable wall clock.
    let wall = elapsed.unwrap_or(instant_wall);
    Ok((wall, rss_mb, cpu_s))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn file_len(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

// ── osm-katana convert bake-off knobs (approach A: convert rows share this ────
// harness so they warehouse under repo=znippy-zoomies; osm-katana/README.md's
// mashup marker `compare=osm-katana,osmium,osmconvert` renders from these rows).
//
//   * `NORNIR_OSM_KATANA_INPUT` — a real `.osm` XML file to convert instead of
//     the synthetic corpus (point at a planet cut for the HEAVY number).
//   * `NORNIR_OSM_KATANA_MB`    — synthetic OSM-XML corpus size in MB (default 24).
fn osm_katana_input() -> Option<PathBuf> {
    if let Some(p) = std::env::var("NORNIR_OSM_KATANA_INPUT")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.exists())
    {
        return Some(p);
    }
    // PREVIEW convenience: with no decompressor corpus asked for, the operator is
    // running the light osm-katana lens — reach for the small local extract if it
    // is there, so `NORNIR_ZOOMIES_CORPUS_MB=0 cargo run --example nornir-bench`
    // exercises the REAL PBF convert path (pass1 → sort_and_stree → pass2) rather
    // than the synthetic single-pass XML corpus. Never used for a heavy run.
    if !decoder_bakeoff_enabled() {
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home).join("work/liechtenstein-latest.osm.pbf");
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}
fn osm_katana_mb() -> u64 {
    std::env::var("NORNIR_OSM_KATANA_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24)
}
// `NORNIR_OSM_KATANA_CLIP` — a region clip preset (europe|nordics) or a raw
// `min_lon,min_lat,max_lon,max_lat` bbox. When set (together with a real planet
// `NORNIR_OSM_KATANA_INPUT`), the osm-katana row runs the HEAVY staged clip
// ("cut this region out of the planet with our tool", resolved geometry, all
// cores) instead of the small XML head-to-head — the planet headline number.
fn osm_katana_clip() -> Option<String> {
    std::env::var("NORNIR_OSM_KATANA_CLIP")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
// `NORNIR_OSM_KATANA_CHAIN` — when set (truthy), also run the STAGED pipeline the
// old planet bench used: file → file2 → file3 → file4, each stage consuming the
// previous stage's OUTPUT file. `xml2pbf` (OSM XML/bz2 → PBF), then `pbf2geo`
// (PBF → GeoParquet), then `geo2arrow` (GeoParquet → Arrow IPC). One deterministic
// pass per stage (its input exists exactly once); rows are per-stage throughput.
fn osm_katana_chain() -> bool {
    std::env::var("NORNIR_OSM_KATANA_CHAIN")
        .ok()
        .is_some_and(|v| {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        })
}

/// One osm-katana pipeline phase, read back from the converter's own `--log`
/// JSONL. These are the fields commit `e1038b6` made REAL (`busy_pct` used to be
/// the collector fraction and read ~0); the bench does not re-instrument
/// anything, it reports what the converter already measures.
struct PhaseOcc {
    /// `pass1` | `sort_and_stree` | `pass2` | `convert`.
    name: String,
    wall_s: f64,
    /// Average cores held over the phase (process CPU-seconds / wall-seconds).
    cpu_cores: f64,
    /// `cpu_cores / n_cores * 100` — the fraction of the whole box this phase held.
    busy_pct: f64,
    /// Diagnostic: fraction of wall the single collector spent inside `process()`.
    /// High here with a low `busy_pct` means collector-bound (workers starve).
    collector_pct: f64,
    n_cores: f64,
}

/// Read a numeric field out of one phase-log JSONL line. The log is hand-written
/// JSON (no serde on the converter side), so a tiny scanner keeps this dependency-
/// free and tolerant of fields being added.
fn json_num(line: &str, key: &str) -> Option<f64> {
    let pat = format!("\"{key}\":");
    let i = line.find(&pat)? + pat.len();
    let rest = &line[i..];
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    rest[..end].trim().parse().ok()
}

/// Read a string field out of one phase-log JSONL line.
fn json_str(line: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let i = line.find(&pat)? + pat.len();
    let rest = &line[i..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Parse the `done` events out of an osm-katana `--log` JSONL file, in emission
/// order (`pass1`, `sort_and_stree`, `pass2`, then the outer `convert`).
fn parse_phase_log(path: &Path) -> Vec<PhaseOcc> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| l.contains("\"ev\":\"done\""))
        .filter_map(|l| {
            Some(PhaseOcc {
                name: json_str(l, "phase")?,
                wall_s: json_num(l, "wall_s")?,
                cpu_cores: json_num(l, "cpu_cores").unwrap_or(0.0),
                busy_pct: json_num(l, "busy_pct").unwrap_or(0.0),
                collector_pct: json_num(l, "collector_pct").unwrap_or(0.0),
                n_cores: json_num(l, "n_cores").unwrap_or(0.0),
            })
        })
        .collect()
}

/// Layout-invariant content digest of a convert output dir, via
/// `osm-katana verify --digest`. Returns one `"table set-digest rows"` triple per
/// table, joined — the equivalence gate for "did this perf change alter output?".
///
/// It is the `set` (order-independent multiset) column that is compared: the
/// converter flushes each gatling worker's partial row group at end of pass, so
/// the tail rows land in worker-completion order and neither the parquet BYTES
/// nor the row ORDER are reproducible run-to-run. The row multiset is.
fn osm_katana_digest(bin: &Path, out: &Path) -> Option<String> {
    let o = Command::new(bin)
        .arg("verify")
        .arg(out)
        .arg("--digest")
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&o.stdout);
    let mut parts: Vec<String> = Vec::new();
    for l in text.lines() {
        let Some((lhs, rhs)) = l.split_once(':') else {
            continue;
        };
        let table = lhs.trim();
        if !table.ends_with(".parquet") {
            continue;
        }
        let Some(i) = rhs.find("set ") else { continue };
        let set = rhs[i + 4..].split_whitespace().next().unwrap_or("?");
        let rows = rhs.split_whitespace().next().unwrap_or("?");
        parts.push(format!("{table}={set}/{rows}"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

/// Total bytes of a file, or the summed size of a directory's immediate files
/// (GeoParquet output is a dir of `*.parquet`). Best-effort; 0 if missing.
fn path_bytes(p: &Path) -> u64 {
    let Ok(md) = std::fs::metadata(p) else {
        return 0;
    };
    if md.is_file() {
        return md.len();
    }
    let mut total = 0u64;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            if let Ok(m) = e.metadata() {
                if m.is_file() {
                    total += m.len();
                }
            }
        }
    }
    total
}

/// Write a deterministic synthetic OSM XML corpus (splitmix64 coords, ~85% nodes
/// then a block of ways referencing recent nodes) of ~`target_bytes`. Reused if
/// already the exact size — same generator as osm-katana's own bench harness so
/// the convert rows are comparable across both entry points.
fn generate_osm_xml(path: &Path, target_bytes: u64) -> anyhow::Result<()> {
    if file_len(path) == target_bytes && target_bytes > 0 {
        return Ok(());
    }
    eprint_flush(&format!(
        "osm-katana corpus: generating {} MB synthetic OSM XML …",
        target_bytes / (1 << 20)
    ));
    let f = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
    let head = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<osm version=\"0.6\" generator=\"nornir-bench\">\n";
    w.write_all(head.as_bytes())?;
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut written: u64 = head.len() as u64 + "</osm>\n".len() as u64;
    let mut id: u64 = 1;
    let mut line = String::with_capacity(256);
    let node_budget = (target_bytes as f64 * 0.85) as u64;
    let mut last_ids: Vec<u64> = Vec::new();
    while written < node_budget {
        let lat = 50.0 + (next() % 2_000_000) as f64 / 1e6;
        let lon = 8.0 + (next() % 2_000_000) as f64 / 1e6;
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
        let bump = 1 + (next() % 4);
        for v in last_ids.iter_mut() {
            *v = v.wrapping_add(bump).max(1);
        }
    }
    w.write_all(b"</osm>\n")?;
    w.flush()?;
    Ok(())
}

/// Last-modified time of `p` in nanoseconds since the epoch, or `None` if the
/// file is missing / has no mtime.
fn mtime_nanos(p: &Path) -> Option<u128> {
    std::fs::metadata(p)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
}

/// Decide whether a derived artifact (a compressed `corpus.<ext>`, the
/// multi-member `corpus.gz`) may be **reused** rather than rebuilt.
///
/// The bug this guards (Codeberg #1): `generate_corpus` regenerates `corpus.bin`
/// whenever the requested size changes, but the compressed artifacts were reused
/// on the mere `file_len(out) > 0` check — so a run at a NEW corpus size decoded
/// a STALE compressed file from a prior (e.g. 512 MiB) run and cmp'd it against
/// the fresh (e.g. 1 GiB) corpus, failing with `EOF on verify after byte
/// 536870912` (== the previous corpus size, not any decoder cap).
///
/// An artifact is fresh iff it exists, is non-empty, and is **at least as new as
/// the corpus it was derived from**. Regenerating `corpus.bin` bumps its mtime
/// past every stale artifact, forcing a rebuild; an unchanged corpus keeps its
/// mtime, so genuinely-current artifacts are still reused.
fn artifact_is_fresh(artifact: &Path, corpus: &Path) -> bool {
    if file_len(artifact) == 0 {
        return false;
    }
    match (mtime_nanos(artifact), mtime_nanos(corpus)) {
        (Some(a), Some(c)) => a >= c,
        // No mtime available (exotic FS) → be safe and rebuild.
        _ => false,
    }
}

/// A compressed variant of the corpus + how it was produced.
struct Format {
    /// stable id, used in the compressed file name.
    id: &'static str,
    /// path of the compressed artifact.
    comp: PathBuf,
    /// MB/s achieved producing it (all cores).
    compress_mbs: f64,
    /// corpus_bytes / comp_bytes.
    ratio: f64,
}

/// A decoder row in the bake-off.
struct Decoder {
    /// System row name. The `mashup` section's `system_token` splits on `_`, so a
    /// bare `_st` core-count variant collapses into its base system there — the
    /// single-core lens instead targets these rows explicitly with a `benches
    /// compare=<full-name>` token, which matches the whole name.
    name: &'static str,
    /// `sh -c` command that decodes to /dev/null.
    cmd: String,
    /// which Format id it reads (inherits compress_mbs + ratio).
    fmt: &'static str,
}

/// Sanity gate for the single-thread (`_st`) rows.
///
/// A `_st` decoder is deliberately pinned to ONE worker, so its decode
/// throughput can NEVER exceed its all-core sibling's — one worker physically
/// cannot outrun all cores. When it appears to, the measurement is broken: the
/// classic failure is a decode that silently short-circuits (e.g. streaming to
/// only the final chunk) yet still gets the FULL corpus size billed against its
/// near-instant wall, yielding an impossible MB/s. This gate catches that whole
/// class of bug — not just one instance — and fails the run so a physically
/// impossible number can never be warehoused.
///
/// A small slack (`SLACK`) absorbs run-to-run noise on memory-bound decoders
/// where the two can land within a few percent; anything beyond it is a bug.
fn check_single_thread_sane(results: &[serde_json::Value]) -> Result<(), String> {
    const SLACK: f64 = 1.10; // _st may read up to 10% over all-core on noise, no more.
    let mbs = |name: &str| -> Option<f64> {
        results
            .iter()
            .find(|r| r.get("name").and_then(|v| v.as_str()) == Some(name))
            .and_then(|r| r.get("decompress_mbs"))
            .and_then(|v| v.as_f64())
    };
    for (st, base) in [
        ("znippy-gz_st", "znippy-gz"),
        ("znippy-bz2_st", "znippy-bz2"),
    ] {
        if let (Some(s), Some(b)) = (mbs(st), mbs(base)) {
            if s > b * SLACK {
                return Err(format!(
                    "IMPOSSIBLE single-thread throughput: {st} decode {s:.2} MB/s exceeds all-core \
                     {base} {b:.2} MB/s (a lone worker cannot beat all cores) — the {st} \
                     measurement is broken, most likely a short-circuited / truncated decode \
                     billed against the full corpus size"
                ));
            }
        }
    }
    Ok(())
}

/// Bump when the corpus GENERATOR changes (seed, word dictionary, line algorithm).
/// The freshness check below reuses a corpus only when BOTH its size AND this
/// version match — so a generator change at an unchanged size can never silently
/// serve STALE bytes (which would decode fine but make bench numbers
/// non-comparable across the change). Sibling guard to the stale-artifact fix
/// (Codeberg #1), which covered size changes but not generator changes.
const CORPUS_GEN_VERSION: u32 = 1;

fn generate_corpus(path: &Path, target_bytes: u64) -> anyhow::Result<()> {
    // Sidecar tag: "<gen-version> <bytes>". Reuse only on an exact match — a
    // missing/old tag (e.g. a corpus from before this guard, or a generator bump)
    // forces regeneration, which bumps corpus.bin's mtime and thereby invalidates
    // every derived compressed artifact via `artifact_is_fresh`.
    let tag_path = path.with_extension("gen");
    let want_tag = format!("{CORPUS_GEN_VERSION} {target_bytes}");
    let tag_ok = std::fs::read_to_string(&tag_path)
        .map(|s| s.trim() == want_tag)
        .unwrap_or(false);
    if file_len(path) == target_bytes && tag_ok {
        eprint_flush(&format!(
            "corpus: reuse {} ({} MB, gen v{CORPUS_GEN_VERSION})",
            path.display(),
            target_bytes / (1 << 20)
        ));
        return Ok(());
    }
    // Stale tag/size → drop it now so a crash mid-generate can't leave a tag that
    // vouches for a half-written corpus.
    let _ = std::fs::remove_file(&tag_path);
    eprint_flush(&format!(
        "corpus: generating {} MB deterministic text (gen v{CORPUS_GEN_VERSION}) …",
        target_bytes / (1 << 20)
    ));
    // A fixed dictionary of ~loggy tokens → realistic ~3-5x text compressibility.
    const WORDS: &[&str] = &[
        "the",
        "quick",
        "brown",
        "fox",
        "jumps",
        "over",
        "lazy",
        "dog",
        "GET",
        "POST",
        "200",
        "404",
        "error",
        "warn",
        "info",
        "debug",
        "trace",
        "user",
        "session",
        "token",
        "request",
        "response",
        "latency",
        "bytes",
        "connection",
        "timeout",
        "retry",
        "cache",
        "hit",
        "miss",
        "index",
        "shard",
        "commit",
        "branch",
        "merge",
        "deploy",
        "rollback",
        "node",
        "cluster",
        "region",
        "zone",
        "avail",
        "throughput",
        "gigabyte",
        "parallel",
        "worker",
        "thread",
        "queue",
        "buffer",
        "stream",
        "decode",
        "encode",
        "gzip",
        "bzip2",
        "zstd",
        "payload",
        "header",
        "footer",
        "checksum",
        "offset",
        "length",
        "2026-07-04T10:15:00Z",
        "id=af39c0",
        "path=/api/v1/resource",
        "status=ok",
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
    let f = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
    let mut written: u64 = 0;
    let mut line = String::with_capacity(256);
    while written < target_bytes {
        line.clear();
        let n = 6 + (next() % 10) as usize;
        for i in 0..n {
            if i > 0 {
                line.push(' ');
            }
            line.push_str(WORDS[(next() as usize) % WORDS.len()]);
        }
        line.push('\n');
        w.write_all(line.as_bytes())?;
        written += line.len() as u64;
    }
    w.flush()?;
    // Trim to the exact target so a re-run's length check matches.
    let f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.set_len(target_bytes)?;
    // Stamp the generator tag LAST — its presence now vouches that the corpus was
    // produced by THIS generator version at THIS size.
    std::fs::write(&tag_path, &want_tag)?;
    Ok(())
}

/// Build a multi-member gzip (`split` → `gzip` each chunk in parallel → `cat`).
/// This is what unlocks `lgz`'s parallel decode; every gzip tool still reads it.
fn build_multimember_gz(corpus: &Path, out: &Path, n_jobs: usize) -> anyhow::Result<f64> {
    if artifact_is_fresh(out, corpus) {
        eprint_flush(&format!("format: reuse {}", out.display()));
        return Ok(f64::NAN);
    }
    let tmp = workdir().join("gzchunks");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let raw_mb = file_len(corpus) as f64 / (1024.0 * 1024.0);
    let t0 = Instant::now();
    // 8 MB members → ~128 members for a 1 GB corpus: ample parallelism.
    sh(&format!(
        "split -b 8M -d -a 4 {} {}/seg_",
        corpus.display(),
        tmp.display()
    ))?;
    sh(&format!(
        "ls {dir}/seg_* | xargs -P {jobs} -I{{}} gzip -6 -n {{}}",
        dir = tmp.display(),
        jobs = n_jobs
    ))?;
    sh(&format!(
        "cat {}/seg_*.gz > {}",
        tmp.display(),
        out.display()
    ))?;
    let secs = t0.elapsed().as_secs_f64();
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(raw_mb / secs)
}

/// Multi-ENTRY zip (128 × 8 MB entries) so `lzip`'s per-ENTRY parallelism has work
/// to fan out — a single-entry archive would decode serially and misreport it as
/// slow. Mirrors [`build_multimember_gz`]; entry names are bare `seg_*`.
fn build_multientry_zip(corpus: &Path, out: &Path, _n_jobs: usize) -> anyhow::Result<f64> {
    if artifact_is_fresh(out, corpus) {
        eprint_flush(&format!("format: reuse {}", out.display()));
        return Ok(f64::NAN);
    }
    let tmp = workdir().join("zipsegs");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let _ = std::fs::remove_file(out);
    let raw_mb = file_len(corpus) as f64 / (1024.0 * 1024.0);
    let t0 = Instant::now();
    sh(&format!(
        "split -b 8M -d -a 4 {} {}/seg_",
        corpus.display(),
        tmp.display()
    ))?;
    // zip from INSIDE the seg dir so entries are bare `seg_*` (no path prefix).
    sh(&format!(
        "cd {dir} && zip -q -6 {out} seg_*",
        dir = tmp.display(),
        out = out.display()
    ))?;
    let secs = t0.elapsed().as_secs_f64();
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(raw_mb / secs)
}

/// Multi-ENTRY jar (128 × 8 MB entries) via the JDK `jar` tool (DEFLATE), so
/// `ljar`'s per-entry parallelism has work to fan out.
fn build_multientry_jar(corpus: &Path, out: &Path, _n_jobs: usize) -> anyhow::Result<f64> {
    if artifact_is_fresh(out, corpus) {
        eprint_flush(&format!("format: reuse {}", out.display()));
        return Ok(f64::NAN);
    }
    let tmp = workdir().join("jarsegs");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let _ = std::fs::remove_file(out);
    let raw_mb = file_len(corpus) as f64 / (1024.0 * 1024.0);
    let t0 = Instant::now();
    sh(&format!(
        "split -b 8M -d -a 4 {} {}/seg_",
        corpus.display(),
        tmp.display()
    ))?;
    sh(&format!(
        "jar -c -f {out} -C {dir} .",
        out = out.display(),
        dir = tmp.display()
    ))?;
    let secs = t0.elapsed().as_secs_f64();
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(raw_mb / secs)
}

/// Produce a compressed variant via a stdin→stdout compressor, measuring MB/s.
fn build_format(
    id: &'static str,
    corpus: &Path,
    ext: &str,
    cmd_prefix: &str,
) -> anyhow::Result<Format> {
    let out = workdir().join(format!("corpus.{ext}"));
    let raw = file_len(corpus);
    let raw_mb = raw as f64 / (1024.0 * 1024.0);
    let compress_mbs = if artifact_is_fresh(&out, corpus) {
        eprint_flush(&format!("format: reuse {}", out.display()));
        f64::NAN
    } else {
        eprint_flush(&format!("format[{id}]: compressing → {}", out.display()));
        let t0 = Instant::now();
        sh(&format!(
            "{cmd_prefix} < {} > {}",
            corpus.display(),
            out.display()
        ))?;
        raw_mb / t0.elapsed().as_secs_f64()
    };
    let comp = file_len(&out).max(1);
    Ok(Format {
        id,
        comp: out,
        compress_mbs,
        ratio: raw as f64 / comp as f64,
    })
}

fn main() -> anyhow::Result<()> {
    let wd = workdir();
    std::fs::create_dir_all(&wd)?;
    let n = cores();
    let corpus = wd.join("corpus.bin");
    let target = corpus_mb() as u64 * (1 << 20);
    if decoder_bakeoff_enabled() {
        generate_corpus(&corpus, target)?;
    } else {
        eprint_flush(
            "NORNIR_ZOOMIES_CORPUS_MB=0 → decompressor bake-off SKIPPED \
             (osm-katana convert arm only, PREVIEW lens)",
        );
    }
    let raw_bytes = if decoder_bakeoff_enabled() {
        file_len(&corpus)
    } else {
        0
    };
    let raw_mb = raw_bytes as f64 / (1024.0 * 1024.0);
    let lgz = bin_dir().join("lgz");
    let lbunzip2 = bin_dir().join("lbunzip2");
    let lzip = bin_dir().join("lzip");
    let ljar = bin_dir().join("ljar");
    eprint_flush(&format!(
        "bake-off: corpus={raw_mb:.0} MB · {n} cores · lgz={} lbunzip2={}",
        lgz.exists(),
        lbunzip2.exists()
    ));

    // ── build every compressed format (cached) ──────────────────────────────
    // Skipped wholesale when there is no corpus (`NORNIR_ZOOMIES_CORPUS_MB=0`):
    // with `formats` empty every `fmt_path(..)` below is `None`, so the decoder
    // roster, the warm/timed rounds and the round-trip checks all fall out
    // naturally — the osm-katana arm is the only thing left standing.
    let mut formats: Vec<Format> = Vec::new();

    if decoder_bakeoff_enabled() {
        // multi-member gzip (unlocks lgz parallel decode; all gzip tools read it).
        {
            let out = wd.join("corpus.gz");
            let cmbs = build_multimember_gz(&corpus, &out, n)?;
            let comp = file_len(&out).max(1);
            formats.push(Format {
                id: "gz",
                comp: out,
                compress_mbs: cmbs,
                ratio: raw_bytes as f64 / comp as f64,
            });
        }
        formats.push(build_format("bz2", &corpus, "bz2", "bzip2 -c -9")?);
        if have("zstd") {
            formats.push(build_format(
                "zst",
                &corpus,
                "zst",
                &format!("zstd -c -12 -T{n} -q"),
            )?);
        }
        if have("lz4") {
            formats.push(build_format("lz4", &corpus, "lz4", "lz4 -c -9")?);
        }
        if have("xz") {
            formats.push(build_format(
                "xz",
                &corpus,
                "xz",
                &format!("xz -c -6 -T{n}"),
            )?);
        }
        if have("brotli") {
            formats.push(build_format("br", &corpus, "br", "brotli -c -q 5")?);
        }
        if have("plzip") {
            formats.push(build_format(
                "lz",
                &corpus,
                "lz",
                &format!("plzip -c -6 -n {n}"),
            )?);
        }
        // Multi-ENTRY zip / jar — the corpora that unlock lzip's / ljar's per-entry
        // parallel DEFLATE decode (our shipped .zip + .jar decoders finally benched).
        if have("zip") {
            let out = wd.join("corpus.zip");
            let cmbs = build_multientry_zip(&corpus, &out, n)?;
            let comp = file_len(&out).max(1);
            formats.push(Format {
                id: "zip",
                comp: out,
                compress_mbs: cmbs,
                ratio: raw_bytes as f64 / comp as f64,
            });
        }
        if have("jar") {
            let out = wd.join("corpus.jar");
            let cmbs = build_multientry_jar(&corpus, &out, n)?;
            let comp = file_len(&out).max(1);
            formats.push(Format {
                id: "jar",
                comp: out,
                compress_mbs: cmbs,
                ratio: raw_bytes as f64 / comp as f64,
            });
        }
    } // end `if decoder_bakeoff_enabled()`

    let fmt_path = |id: &str| formats.iter().find(|f| f.id == id).map(|f| f.comp.clone());

    // ── the decoder roster ──────────────────────────────────────────────────
    let mut decoders: Vec<Decoder> = Vec::new();
    let mut push = |name: &'static str, fmt: &'static str, cmd: String| {
        decoders.push(Decoder { name, cmd, fmt })
    };

    if let Some(p) = fmt_path("gz") {
        if lgz.exists() {
            // All-core row FIRST — the mashup's `compare=` first-match wins, so the
            // all-core variant must precede its `_st` sibling to stay the one the
            // multi-core / vs-vanilla lenses pick.
            push(
                "znippy-gz",
                "gz",
                format!("{} {} > /dev/null", lgz.display(), p.display()),
            );
            // Single-core row: `LGZ_THREADS=1` pins one gatling worker. The `_st`
            // suffix is the core-saturation gate's exempt-single-thread marker AND
            // the single-core lens's row (targeted by a `benches compare=` full-name
            // token, since the `mashup` collapses `_st` into the base system token).
            push(
                "znippy-gz_st",
                "gz",
                format!(
                    "LGZ_THREADS=1 {} {} > /dev/null",
                    lgz.display(),
                    p.display()
                ),
            );
        }
        if have("pigz") {
            push(
                "pigz",
                "gz",
                format!("pigz -dc -p {n} {} > /dev/null", p.display()),
            );
        }
        // Serial gzip = the single-core / vanilla gzip rival for lenses B & C.
        push(
            "gzip",
            "gz",
            format!("gzip -dc {} > /dev/null", p.display()),
        );
    }
    if let Some(p) = fmt_path("bz2") {
        if lbunzip2.exists() {
            push(
                "znippy-bz2",
                "bz2",
                format!("{} {} /dev/null", lbunzip2.display(), p.display()),
            );
            // Single-core row (`LBZIP2_THREADS=1`) — see the lgz `_st` note above.
            push(
                "znippy-bz2_st",
                "bz2",
                format!(
                    "LBZIP2_THREADS=1 {} {} /dev/null",
                    lbunzip2.display(),
                    p.display()
                ),
            );
        }
        // NOTE order: the mashup's `compare=` matches a system by substring, and
        // `bzip2` ⊂ `lbzip2`/`pbzip2` — so the base (serial, also the single-core /
        // vanilla rival for lenses B & C) tool must be discovered first.
        push(
            "bzip2",
            "bz2",
            format!("bzip2 -dc {} > /dev/null", p.display()),
        );
        if have("lbzip2") {
            push(
                "lbzip2",
                "bz2",
                format!("lbzip2 -dc -n {n} {} > /dev/null", p.display()),
            );
            // Single-core row: pin system lbzip2 to ONE decode thread so it appears
            // in the single-core table too — every algorithm shown at one core.
            // (`lbzip2` CAN parallel-decode, so this is a deliberate `_st` pin, like
            // our zoomies `_st` rows — not a can't-parallelize collapse.)
            push(
                "lbzip2_st",
                "bz2",
                format!("lbzip2 -dc -n 1 {} > /dev/null", p.display()),
            );
        }
        if have("pbzip2") {
            push(
                "pbzip2",
                "bz2",
                format!("pbzip2 -d -c -p{n} {} > /dev/null", p.display()),
            );
        }
    }
    // ── zip: our `lzip` (parallel per-entry DEFLATE) vs stock `unzip` ─────────
    // Archive decoders EXTRACT to a scratch dir (overwritten each run — no cleanup
    // in the timed path). `_st` pins to one worker via `-n1`.
    if let Some(p) = fmt_path("zip") {
        let zo = wd.join("zipout");
        let _ = std::fs::create_dir_all(&zo);
        if lzip.exists() {
            push(
                "znippy-zip",
                "zip",
                format!(
                    "{} {} {} >/dev/null 2>&1",
                    lzip.display(),
                    p.display(),
                    zo.display()
                ),
            );
            push(
                "znippy-zip_st",
                "zip",
                format!(
                    "{} -n1 {} {} >/dev/null 2>&1",
                    lzip.display(),
                    p.display(),
                    zo.display()
                ),
            );
        }
        if have("unzip") {
            push(
                "unzip",
                "zip",
                format!(
                    "unzip -o -q {} -d {} >/dev/null 2>&1",
                    p.display(),
                    zo.display()
                ),
            );
        }
    }
    // ── jar: our `ljar` (parallel per-entry DEFLATE) vs the JDK `jar` tool ────
    if let Some(p) = fmt_path("jar") {
        let jo = wd.join("jarout");
        let _ = std::fs::create_dir_all(&jo);
        if ljar.exists() {
            push(
                "znippy-jar",
                "jar",
                format!(
                    "{} {} {} >/dev/null 2>&1",
                    ljar.display(),
                    p.display(),
                    jo.display()
                ),
            );
            push(
                "znippy-jar_st",
                "jar",
                format!(
                    "{} -n1 {} {} >/dev/null 2>&1",
                    ljar.display(),
                    p.display(),
                    jo.display()
                ),
            );
        }
        // JDK `jar -x` extracts to CWD, so run it inside the scratch dir.
        if have("jar") {
            push(
                "jar",
                "jar",
                format!(
                    "cd {} && jar -x -f {} >/dev/null 2>&1",
                    jo.display(),
                    p.display()
                ),
            );
        }
    }
    if let Some(p) = fmt_path("zst") {
        push(
            "zstd",
            "zst",
            format!("zstd -dc {} > /dev/null", p.display()),
        );
    }
    if let Some(p) = fmt_path("lz4") {
        push("lz4", "lz4", format!("lz4 -dc {} > /dev/null", p.display()));
    }
    if let Some(p) = fmt_path("xz") {
        push(
            "xz",
            "xz",
            format!("xz -dc -T{n} {} > /dev/null", p.display()),
        );
        if have("pixz") {
            push("pixz", "xz", format!("pixz -d {} /dev/null", p.display()));
        }
    }
    if let Some(p) = fmt_path("br") {
        push(
            "brotli",
            "br",
            format!("brotli -dc {} > /dev/null", p.display()),
        );
    }
    if let Some(p) = fmt_path("lz") {
        push(
            "plzip",
            "lz",
            format!("plzip -dc -n {n} {} > /dev/null", p.display()),
        );
    }

    // ── run every decoder: warm ALL, then time INTERLEAVED (round-robin) ─────
    // H1 fix — the bz2 row's harness-vs-standalone skew was a THERMAL/BOOST-ORDER
    // bias, not a wall arithmetic bug: timing each decoder's iterations back-to-
    // back samples every decoder in a DIFFERENT turbo window (in the full roster
    // `lbzip2` runs after the long single-core serial `bzip2`, so its all-core
    // boost budget is fully replenished → it read ~8% high; our `znippy-bz2` ran
    // earlier in a worse window → read low). Sampling ROUND-ROBIN puts every
    // decoder across the SAME set of windows, so min-of-N picks each one's best
    // under equivalent conditions — the fair, standalone-faithful comparison.
    // Purely a measurement-scheduling change; no decoder is touched (L2).
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut tests: Vec<serde_json::Value> = Vec::new();
    let compress_of = |id: &str| {
        formats
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.compress_mbs)
            .unwrap_or(f64::NAN)
    };
    let ratio_of = |id: &str| {
        formats
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.ratio)
            .unwrap_or(f64::NAN)
    };

    let iters = bench_iters();

    /// Per-decoder min-of-N accumulator. `best_cpu_s` is paired with the SAME
    /// (min-wall) sample whose throughput we report, so the two describe one run.
    struct Acc {
        best_secs: f64,
        best_cpu_s: f64,
        peak_rss_mb: f64,
        failed: Option<String>,
    }
    let mut accs: Vec<Acc> = decoders
        .iter()
        .map(|_| Acc {
            best_secs: f64::INFINITY,
            best_cpu_s: 0.0,
            peak_rss_mb: 0.0,
            failed: None,
        })
        .collect();

    // One untimed warm pass over EVERY decoder first (page-cache each compressed
    // input + warm the allocator) — so the first timed round is never penalised by
    // a cold cache for the decoders that would otherwise be timed later.
    for d in &decoders {
        eprint_flush(&format!("warmup: {} …", d.name));
        let _ = sh(&format!("{} 2>/dev/null", d.cmd));
    }
    // N timed rounds, round-robin across all decoders (min wall + max peak RSS).
    for it in 0..iters {
        eprint_flush(&format!(
            "── timed round {}/{iters} (interleaved, min-of-N) ──",
            it + 1
        ));
        for (di, d) in decoders.iter().enumerate() {
            if accs[di].failed.is_some() {
                continue;
            }
            match timed(&d.cmd) {
                Ok((secs, rss_mb, cpu_s)) => {
                    let a = &mut accs[di];
                    if secs < a.best_secs {
                        a.best_secs = secs;
                        a.best_cpu_s = cpu_s;
                    }
                    a.peak_rss_mb = a.peak_rss_mb.max(rss_mb);
                    let busy = if secs > 0.0 { cpu_s / secs } else { 0.0 };
                    eprint_flush(&format!(
                        "    {}: {secs:.3}s ({rss_mb:.0} MB RSS, {busy:.2} cores busy)",
                        d.name
                    ));
                }
                Err(e) => {
                    accs[di].failed = Some(e.to_string());
                }
            }
        }
    }

    for (di, d) in decoders.iter().enumerate() {
        if let Some(e) = &accs[di].failed {
            eprint_flush(&format!("  {} FAILED: {e}", d.name));
            continue;
        }
        let (secs, rss_mb) = (accs[di].best_secs, accs[di].peak_rss_mb);
        let best_cpu_s = accs[di].best_cpu_s;
        let cores_busy = if secs > 0.0 { best_cpu_s / secs } else { 0.0 };
        let mbs = raw_mb / secs;
        let mut m = serde_json::Map::new();
        m.insert("name".into(), json!(d.name));
        m.insert(
            "decompress_mbs".into(),
            json!((mbs * 100.0).round() / 100.0),
        );
        m.insert(
            "percore_mbs".into(),
            json!((mbs / n as f64 * 100.0).round() / 100.0),
        );
        // REAL average cores kept busy during the decode (CPU time / wall), the
        // honest saturation signal the nornir core-saturation gate needs — a
        // parallel decoder well under `cores` here is a core-starvation bug.
        m.insert(
            "cores_busy".into(),
            json!((cores_busy * 100.0).round() / 100.0),
        );
        m.insert(
            "decompress_s".into(),
            json!((secs * 1000.0).round() / 1000.0),
        );
        m.insert("peak_mem_mb".into(), json!((rss_mb * 10.0).round() / 10.0));
        let cm = compress_of(d.fmt);
        if cm.is_finite() {
            m.insert("compress_mbs".into(), json!((cm * 100.0).round() / 100.0));
        }
        let r = ratio_of(d.fmt);
        if r.is_finite() {
            m.insert("ratio".into(), json!((r * 100.0).round() / 100.0));
        }
        eprint_flush(&format!(
            "  {} → {mbs:.0} MB/s  ({secs:.2}s, {rss_mb:.0} MB RSS, {cores_busy:.2} cores busy, ratio {r:.2}x)",
            d.name
        ));
        results.push(serde_json::Value::Object(m));
    }

    // ── osm-katana convert bake-off (approach A) ─────────────────────────────
    // osm-katana is a sub-crate of this workspace; its `convert` (OSM XML →
    // GeoParquet, no-barrier gatling pipeline, all cores) is benched here as
    // extra rows in the SAME BenchRun so they warehouse under repo=znippy-zoomies.
    // osm-katana/README.md's `compare=osm-katana,osmium,osmconvert` marker then
    // renders straight from these rows — no standalone repo, no hand-editing.
    // Reference tools osmium/osmconvert convert the same XML → PBF when installed.
    // osm-katana is a SEPARATE workspace member, so `cargo run --example` (how
    // `nornir bench run` drives us) does not build its binary — ensure it, into
    // the same CARGO_TARGET_DIR `bin_dir()` reads. Cargo is incremental, so this
    // is a near-no-op once built; a build failure just skips the convert rows.
    let okbin = bin_dir().join("osm-katana");
    if !okbin.exists() {
        eprint_flush("osm-katana convert bake-off: building osm-katana binary (separate member) …");
        let _ = Command::new("cargo")
            .args([
                "build",
                "--release",
                "-p",
                "osm-katana",
                "--bin",
                "osm-katana",
                "--quiet",
            ])
            .status();
    }
    if okbin.exists() {
        let inp = match osm_katana_input() {
            Some(p) => {
                eprint_flush(&format!(
                    "osm-katana corpus: reuse real input {}",
                    p.display()
                ));
                p
            }
            None => {
                let p = wd.join("osm-katana-corpus.osm");
                let bytes = osm_katana_mb() * (1 << 20);
                generate_osm_xml(&p, bytes)?;
                p
            }
        };
        let in_mb = file_len(&inp) as f64 / (1024.0 * 1024.0);
        // Each system is a `sh -c` string so `timed()` wraps it identically to the
        // decoders (peak RSS + CPU-time-over-wall = the honest cores_busy signal).
        // osm-katana uses `--geometry raw` (1-pass, keep node-ID list) on XML,
        // matching osm-katana's own harness; `_st` pins a single VTD worker.
        let out = wd.join("osm-katana-out");
        let pbf = wd.join("osm-katana-ref.pbf");
        // The converter's own per-phase JSONL. `timed()` runs the command through
        // `sh -c`, so the log path is baked into the command string; it is deleted
        // before every timed iteration so the parsed phases always belong to ONE run.
        let plog = wd.join("osm-katana-phase.jsonl");
        // PBF input runs the RESOLVED 2-pass pipeline (pass1 → sort_and_stree →
        // pass2) — the path with the phase barrier we are hunting. `--geometry raw`
        // is XML-only (it keeps node-ID lists instead of resolving coords) and the
        // converter rejects it for PBF, so pick the mode from the extension.
        let is_pbf = inp
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("pbf"));
        let geom_flag = if is_pbf { "" } else { " --geometry raw" };
        let mut convert_systems: Vec<(&str, String)> = Vec::new();
        if let Some(clip) = osm_katana_clip() {
            // HEAVY staged clip: cut the region out of the planet with our tool
            // (resolved geometry — full node store + STree, ways/rels resolved to
            // WKB inside the bbox). osmium/osmconvert have no planet→clipped-
            // GeoParquet equivalent, so this is an osm-katana-only headline row.
            convert_systems.push((
                "osm-katana",
                format!(
                    "rm -rf {o} && {b} convert {i} -o {o} --clip {c} --skip-changesets --log {l}",
                    o = out.display(),
                    b = okbin.display(),
                    i = inp.display(),
                    c = clip,
                    l = plog.display()
                ),
            ));
            eprint_flush(&format!(
                "osm-katana HEAVY clip: input={in_mb:.0} MB · region={clip} · {n} cores (resolved)"
            ));
        } else {
            // Small head-to-head: osm-katana (all cores + single-worker `_st`) vs
            // osmium/osmconvert on the same input.
            convert_systems.push((
                "osm-katana",
                format!(
                    "rm -rf {o} && {b} convert {i} -o {o}{g} --log {l}",
                    o = out.display(),
                    b = okbin.display(),
                    i = inp.display(),
                    g = geom_flag,
                    l = plog.display()
                ),
            ));
            convert_systems.push((
                "osm-katana_st",
                format!(
                    "rm -rf {o} && {b} convert {i} -o {o}{g} --vtd-workers 1",
                    o = out.display(),
                    b = okbin.display(),
                    i = inp.display(),
                    g = geom_flag
                ),
            ));
            if have("osmium") {
                convert_systems.push((
                    "osmium",
                    format!(
                        "osmium cat --overwrite -o {p} {i}",
                        p = pbf.display(),
                        i = inp.display()
                    ),
                ));
            }
            if have("osmconvert") {
                convert_systems.push((
                    "osmconvert",
                    format!(
                        "osmconvert {i} -o={p}",
                        i = inp.display(),
                        p = pbf.display()
                    ),
                ));
            }
            eprint_flush(&format!(
                "osm-katana convert bake-off: input={in_mb:.0} MB · {n} cores · osmium={} osmconvert={}",
                have("osmium"),
                have("osmconvert")
            ));
        }
        // The HEAVY planet clip is a multi-hour, deterministic single pass — never
        // warm it up or repeat it (that would be 4× hours for no signal). The small
        // head-to-head keeps warmup + min-of-N.
        let clip_mode = osm_katana_clip().is_some();
        let osm_iters = if clip_mode { 1 } else { iters };
        // Per-phase occupancy of the FASTEST osm-katana iteration (the same sample
        // whose wall/throughput we publish, so the two describe one run), and the
        // content digest of every iteration's output (the equivalence gate).
        let mut best_phases: Vec<PhaseOcc> = Vec::new();
        let mut digests: Vec<String> = Vec::new();
        for (name, cmd) in &convert_systems {
            let is_primary = *name == "osm-katana";
            if clip_mode {
                eprint_flush(&format!("convert: {name} … (heavy clip, single pass)"));
            } else {
                eprint_flush(&format!(
                    "convert: {name} … (warmup + {osm_iters} timed, min-of-N)"
                ));
                let _ = sh(&format!("{cmd} 2>/dev/null"));
            }
            let mut best_secs = f64::INFINITY;
            let mut best_cpu_s = 0.0;
            let mut peak_rss_mb: f64 = 0.0;
            let mut failed: Option<String> = None;
            for it in 0..osm_iters {
                // One run per log file — otherwise `--log` appends and the phases
                // of several iterations pile up in one file.
                let _ = std::fs::remove_file(&plog);
                match timed(cmd) {
                    Ok((secs, rss_mb, cpu_s)) => {
                        if secs < best_secs {
                            best_secs = secs;
                            best_cpu_s = cpu_s;
                            if is_primary {
                                best_phases = parse_phase_log(&plog);
                            }
                        }
                        if is_primary && let Some(d) = osm_katana_digest(&okbin, &out) {
                            digests.push(d);
                        }
                        peak_rss_mb = peak_rss_mb.max(rss_mb);
                        let busy = if secs > 0.0 { cpu_s / secs } else { 0.0 };
                        eprint_flush(&format!(
                            "    iter {}/{osm_iters}: {secs:.3}s ({rss_mb:.0} MB RSS, {busy:.2} cores busy)",
                            it + 1
                        ));
                    }
                    Err(e) => {
                        failed = Some(e.to_string());
                        break;
                    }
                }
            }
            if let Some(e) = failed {
                eprint_flush(&format!("  {name} FAILED: {e}"));
                continue;
            }
            let secs = best_secs;
            let cores_busy = if secs > 0.0 { best_cpu_s / secs } else { 0.0 };
            let mbs = in_mb / secs;
            let mut m = serde_json::Map::new();
            m.insert("name".into(), json!(name));
            m.insert("convert_mbs".into(), json!((mbs * 100.0).round() / 100.0));
            m.insert(
                "percore_mbs".into(),
                json!((mbs / n as f64 * 100.0).round() / 100.0),
            );
            m.insert(
                "cores_busy".into(),
                json!((cores_busy * 100.0).round() / 100.0),
            );
            m.insert("convert_s".into(), json!((secs * 1000.0).round() / 1000.0));
            m.insert(
                "peak_mem_mb".into(),
                json!((peak_rss_mb * 10.0).round() / 10.0),
            );
            eprint_flush(&format!(
                "  {name} → {mbs:.0} MB/s  ({secs:.2}s, {peak_rss_mb:.0} MB RSS, {cores_busy:.2} cores busy)"
            ));
            results.push(serde_json::Value::Object(m));
        }

        // ── PER-PHASE CORE OCCUPANCY (the thing this arm exists for) ─────────
        //
        // Wall time alone cannot tell you WHY osm-katana leaves the box idle. The
        // converter already measures it per phase (`e1038b6`: `busy_pct` is real
        // process-CPU-over-wall occupancy, not the collector fraction it used to
        // be), so the bench just reads its `--log` back and publishes one row per
        // phase. `pass1` / `sort_and_stree` / `pass2` are the fan-out phases;
        // `convert` is the whole run including the barriers between them, so
        // `convert.busy_pct` < min(phase busy_pct) is exactly the "pool drains
        // between bursts" signature.
        //
        // Row names use the established `osm-katana_<variant>` shape (same as the
        // existing `osm-katana_st` row) so an `osm-katana` mashup marker keeps
        // claiming the plain row by exact match.
        if !best_phases.is_empty() {
            eprint_flush("osm-katana per-phase core occupancy (fastest iteration):");
            for p in &best_phases {
                let mut m = serde_json::Map::new();
                m.insert("name".into(), json!(format!("osm-katana_{}", p.name)));
                m.insert(
                    "phase_s".into(),
                    json!((p.wall_s * 1000.0).round() / 1000.0),
                );
                m.insert(
                    "cores_busy".into(),
                    json!((p.cpu_cores * 100.0).round() / 100.0),
                );
                m.insert("busy_pct".into(), json!((p.busy_pct * 10.0).round() / 10.0));
                m.insert(
                    "collector_pct".into(),
                    json!((p.collector_pct * 10.0).round() / 10.0),
                );
                m.insert("n_cores".into(), json!(p.n_cores));
                eprint_flush(&format!(
                    "  {:<18} {:>7.3}s  {:>6.2} / {:.0} cores  busy {:>5.1}%  collector {:>5.1}%",
                    p.name, p.wall_s, p.cpu_cores, p.n_cores, p.busy_pct, p.collector_pct
                ));
                results.push(serde_json::Value::Object(m));
            }
            // RED-when-broken: the converter must actually report occupancy. If
            // `busy_pct` regresses to the collector-only formula (the pre-e1038b6
            // bug) every phase reads ~0 and this row goes false.
            let occ_ok = best_phases
                .iter()
                .any(|p| p.cpu_cores > 1.0 && p.busy_pct > 0.0);
            tests.push(json!({ "name": "osm_katana_phase_occupancy_reported", "passed": occ_ok }));
        }

        // ── output-equivalence gate ─────────────────────────────────────────
        // The parquet BYTES are not reproducible (row groups are encoded on the
        // gatling workers and stitched in whatever segmentation that run produced)
        // and neither is row ORDER (each worker flushes its partial row group at
        // end of pass, in completion order). The row MULTISET is. So the gate is
        // `osm-katana verify --digest`'s order-independent `set` column: equal
        // across iterations ⇒ every run emitted exactly the same rows.
        if digests.len() >= 2 {
            let stable = digests.iter().all(|d| d == &digests[0]);
            eprint_flush(&format!(
                "osm-katana output digest ({} runs): {}  → {}",
                digests.len(),
                digests[0],
                if stable { "STABLE" } else { "DIVERGED" }
            ));
            if !stable {
                for (i, d) in digests.iter().enumerate() {
                    eprint_flush(&format!("    run {i}: {d}"));
                }
            }
            tests.push(json!({ "name": "osm_katana_output_digest_stable", "passed": stable }));
        }

        let _ = std::fs::remove_dir_all(&out);
        let _ = std::fs::remove_file(&pbf);
        let _ = std::fs::remove_file(&plog);

        // ── Staged pipeline: file → file2 → file3 → file4 ────────────────────
        // The old planet bench's shape — each stage consumes the PREVIOUS stage's
        // output file. xml2pbf (OSM XML/bz2 → PBF) → pbf2geo (PBF → GeoParquet) →
        // geo2arrow (GeoParquet → Arrow IPC). One deterministic pass per stage;
        // per-stage throughput = that stage's input size / wall. A failed stage
        // aborts the chain (downstream stages need its output).
        if osm_katana_chain() {
            let f1 = inp.clone(); // OSM XML / .osm.bz2   (input)
            let f2 = wd.join("chain-stage.pbf"); // xml2pbf → PBF        (file2)
            let f3 = wd.join("chain-stage-geo"); // pbf2geo → GeoParquet (file3, dir)
            let f3_nodes = f3.join("nodes.parquet"); // the bulk layer geo2arrow reads
            let f4 = wd.join("chain-stage.arrow"); // geo2arrow → Arrow    (file4)
            let stages: [(&str, String, &Path); 3] = [
                // NB: clap kebab-cases the subcommands — `xml2-pbf`, `pbf2-geo`,
                // `geo2-arrow` (not xml2pbf/…). Row names stay the compact form.
                (
                    "xml2pbf",
                    format!(
                        "rm -f {o} && {b} xml2-pbf {i} {o} --skip-changesets",
                        o = f2.display(),
                        b = okbin.display(),
                        i = f1.display()
                    ),
                    f1.as_path(),
                ),
                (
                    "pbf2geo",
                    format!(
                        "rm -rf {o} && {b} pbf2-geo {i} -o {o}",
                        o = f3.display(),
                        b = okbin.display(),
                        i = f2.display()
                    ),
                    f2.as_path(),
                ),
                // geo2-arrow reads ONE parquet file, not the dir — feed it the
                // (bulk) nodes layer that pbf2-geo just wrote.
                (
                    "geo2arrow",
                    format!(
                        "rm -f {o} && {b} geo2-arrow {i} {o}",
                        o = f4.display(),
                        b = okbin.display(),
                        i = f3_nodes.display()
                    ),
                    f3_nodes.as_path(),
                ),
            ];
            eprint_flush(&format!(
                "osm-katana staged pipeline: {} → xml2pbf → pbf2geo → geo2arrow ({n} cores)",
                f1.display()
            ));
            for (stage, cmd, in_path) in &stages {
                // This stage's input is the previous stage's output — it exists now.
                let in_mb = path_bytes(in_path) as f64 / (1024.0 * 1024.0);
                eprint_flush(&format!(
                    "chain: {stage} … (single pass, input {in_mb:.0} MB)"
                ));
                match timed(cmd) {
                    Ok((secs, rss_mb, cpu_s)) => {
                        let cores_busy = if secs > 0.0 { cpu_s / secs } else { 0.0 };
                        let mbs = if secs > 0.0 { in_mb / secs } else { 0.0 };
                        let mut m = serde_json::Map::new();
                        m.insert("name".into(), json!(stage));
                        m.insert("stage_mbs".into(), json!((mbs * 100.0).round() / 100.0));
                        m.insert(
                            "percore_mbs".into(),
                            json!((mbs / n as f64 * 100.0).round() / 100.0),
                        );
                        m.insert(
                            "cores_busy".into(),
                            json!((cores_busy * 100.0).round() / 100.0),
                        );
                        m.insert("stage_s".into(), json!((secs * 1000.0).round() / 1000.0));
                        m.insert("peak_mem_mb".into(), json!((rss_mb * 10.0).round() / 10.0));
                        eprint_flush(&format!(
                            "  {stage} → {mbs:.0} MB/s ({secs:.2}s, {rss_mb:.0} MB RSS, {cores_busy:.2} cores busy)"
                        ));
                        results.push(serde_json::Value::Object(m));
                    }
                    Err(e) => {
                        eprint_flush(&format!(
                            "  {stage} FAILED: {e} — aborting chain (downstream needs its output)"
                        ));
                        break;
                    }
                }
            }
            let _ = std::fs::remove_file(&f2);
            let _ = std::fs::remove_dir_all(&f3);
            let _ = std::fs::remove_file(&f4);
        }
    } else {
        eprint_flush(&format!(
            "osm-katana convert bake-off: SKIP (binary not built at {})",
            okbin.display()
        ));
    }

    // ── correctness: znippy-zoomies decoders must byte-match the corpus ──────
    if lgz.exists() {
        if let Some(p) = fmt_path("gz") {
            let out = wd.join("verify.lgz");
            let ok = sh(&format!(
                "{} {} > {}",
                lgz.display(),
                p.display(),
                out.display()
            ))
            .and_then(|_| sh(&format!("cmp {} {}", corpus.display(), out.display())))
            .is_ok();
            tests.push(json!({ "name": "lgz_roundtrip_matches_corpus", "passed": ok }));
            let _ = std::fs::remove_file(&out);
        }
    }
    if lbunzip2.exists() {
        if let Some(p) = fmt_path("bz2") {
            let out = wd.join("verify.lbz2");
            let ok = sh(&format!(
                "{} {} {}",
                lbunzip2.display(),
                p.display(),
                out.display()
            ))
            .and_then(|_| sh(&format!("cmp {} {}", corpus.display(), out.display())))
            .is_ok();
            tests.push(json!({ "name": "lbunzip2_roundtrip_matches_corpus", "passed": ok }));
            let _ = std::fs::remove_file(&out);
        }
    }

    // ── sanity gate: a single-worker `_st` row can never out-throughput its ──
    // all-core sibling. Fail LOUDLY before emitting, so a broken (physically
    // impossible) measurement can never be printed as the contract line and
    // warehoused.
    if let Err(e) = check_single_thread_sane(&results) {
        eprint_flush(&format!("bench sanity gate FAILED: {e}"));
        anyhow::bail!(e);
    }

    // ── emit the BenchRun (LAST stdout line = the contract) ──────────────────
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
    // ── PREVIEW classification ──────────────────────────────────────────────
    // A run is preview if EITHER lens ran light: the decompressor corpus below
    // the heavy default, or an osm-katana input below OSM_HEAVY_MIN_MB. Both are
    // derived from the knobs already in play — no separate "preview" switch to
    // forget to set, and no way to produce a light number that *looks* heavy.
    let osm_in_mb = osm_katana_input()
        .map(|p| file_len(&p) / (1024 * 1024))
        .unwrap_or_else(osm_katana_mb);
    let mut preview_why: Vec<String> = Vec::new();
    if corpus_mb() < HEAVY_CORPUS_MB {
        preview_why.push(format!(
            "decompressor corpus {} MB < heavy {HEAVY_CORPUS_MB} MB",
            corpus_mb()
        ));
    }
    if osm_katana_clip().is_none() && osm_in_mb < OSM_HEAVY_MIN_MB {
        preview_why.push(format!(
            "osm-katana input {osm_in_mb} MB < heavy {OSM_HEAVY_MIN_MB} MB"
        ));
    }
    let preview = !preview_why.is_empty();

    let machine = if preview {
        format!(
            "PREVIEW · {cpu} · {mem_gb} GiB · corpus {raw_mb:.0} MB · osm-katana input {osm_in_mb} MB · min-of-{iters}"
        )
    } else {
        format!("{cpu} · {mem_gb} GiB · corpus {raw_mb:.0} MB · min-of-{iters}")
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let days = now / 86400;
    let date = epoch_days_to_date(days as i64);
    let tod = now % 86400;
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let timestamp = format!("{date}T{hh:02}:{mm:02}:{ss:02}Z");

    let run = json!({
        "date": date,
        "timestamp": timestamp,
        "version": env!("CARGO_PKG_VERSION"),
        "machine": machine,
        "cores": n as u32,
        "preview": preview,
        "results": results,
        "tests": tests,
    });

    // ── the contract line — WITHHELD for a preview run ───────────────────────
    // `nornir bench run` reads the LAST stdout line as a `BenchRun` and appends
    // it to the warehouse, from which `nornir docs render` fills the README
    // mashup tables. A light number that reached that path would render as an
    // authoritative host measurement and silently replace a real one — the exact
    // failure this repo keeps hitting. So a preview never emits the contract
    // line at all: the numbers go to stderr for the human/agent driving the
    // optimise loop, and stdout says plainly that nothing is publishable. There
    // is no flag to override this; run it heavy to publish.
    if preview {
        eprint_flush("── PREVIEW BenchRun (stderr only, NOT warehoused) ──");
        eprint_flush(&serde_json::to_string_pretty(&run)?);
        println!(
            "PREVIEW RUN — no BenchRun emitted ({}). These numbers are for the \
             optimise loop only. For a publishable run: NORNIR_ZOOMIES_CORPUS_MB={HEAVY_CORPUS_MB} \
             and an osm-katana input ≥ {OSM_HEAVY_MIN_MB} MB (or NORNIR_OSM_KATANA_CLIP=<region> \
             against a planet file).",
            preview_why.join("; ")
        );
        return Ok(());
    }
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

    /// H1 ORACLE — `decompress_mbs` must be computed from the SAME wall clock
    /// `/usr/bin/time -v` itself reports ("Elapsed (wall clock) time"), the exact
    /// basis the byte-verified standalone baseline is read on. Feed a known,
    /// verbatim GNU-time report (shell-free, L9) and assert the parse + throughput
    /// math is EXACT: 1024 MiB over the reported 1.39 s wall = 736.69 MB/s — NOT
    /// the User-time (16.68 s) CPU basis, which would nonsensically read ~61 MB/s.
    #[test]
    fn decompress_mbs_uses_time_reported_wall_not_cpu() {
        // Verbatim `/usr/bin/time -v` block (fields trimmed to the ones we read).
        let report = "\
\tCommand being timed: \"sh -c lbunzip2 corpus.bz2 /dev/null\"
\tUser time (seconds): 16.68
\tSystem time (seconds): 0.12
\tPercent of CPU this job got: 1209%
\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:01.39
\tMaximum resident set size (kbytes): 2097152
";
        let (rss_mb, cpu_s, elapsed) = parse_time_report(report);
        let wall = elapsed.expect("elapsed wall must parse from a real GNU-time report");
        // Wall is time's OWN elapsed (1.39 s), not the Instant and not CPU time.
        assert!(
            (wall - 1.39).abs() < 1e-9,
            "wall must be the reported 1.39 s, got {wall}"
        );
        assert!(
            (cpu_s - 16.80).abs() < 1e-9,
            "cpu = user+sys = 16.80 s, got {cpu_s}"
        );
        assert!(
            (rss_mb - 2048.0).abs() < 1e-6,
            "rss = 2097152 KiB / 1024 = 2048 MB, got {rss_mb}"
        );

        let raw_mb = 1024.0_f64; // 1 GiB corpus decodes to 1024 MiB.
        let mbs_wall = raw_mb / wall;
        assert!(
            (mbs_wall - 736.69).abs() < 0.01,
            "wall-basis MB/s must be ~736.69, got {mbs_wall}"
        );
        // RED-when-broken: a CPU-time basis would read a physically impossible
        // ~61 MB/s for an 11-core-busy decode — the gate that a regression to the
        // wrong denominator would trip.
        let mbs_cpu = raw_mb / cpu_s;
        assert!(
            mbs_cpu < 100.0,
            "sanity: CPU-basis is the WRONG denominator (~{mbs_cpu:.0})"
        );
        assert!(
            mbs_wall > 7.0 * mbs_cpu,
            "wall basis must be far above the bogus CPU basis"
        );
    }

    /// `parse_hms` must decode every GNU-time elapsed shape into seconds.
    #[test]
    fn parse_hms_handles_all_time_formats() {
        assert_eq!(parse_hms("0:01.39"), Some(1.39)); // m:ss.frac
        assert_eq!(parse_hms("1:02.50"), Some(62.5)); // m:ss
        assert_eq!(parse_hms("1:02:03"), Some(3723.0)); // h:mm:ss
        assert_eq!(parse_hms("12.34"), Some(12.34)); // bare seconds
        assert_eq!(parse_hms("nope"), None);
        // A report with NO elapsed line → None, so timed() falls back to Instant.
        let (_, _, e) =
            parse_time_report("\tUser time (seconds): 1.0\n\tSystem time (seconds): 0.0\n");
        assert_eq!(
            e, None,
            "missing elapsed line must yield None (Instant fallback)"
        );
    }

    /// Regression (Codeberg #1): a compressed artifact left over from a PRIOR
    /// corpus (a different size) must NOT be reused once the corpus is
    /// regenerated — otherwise the bake-off decodes the stale artifact and cmp
    /// fails at the previous corpus size (the phantom "512 MiB decode cap").
    ///
    /// This is the exact failure mode, in miniature and with no gigabytes: write
    /// a "corpus", derive an "artifact", then rewrite the corpus (newer mtime) —
    /// the artifact must now read as stale.
    #[test]
    fn stale_artifact_is_not_reused_after_corpus_regen() {
        let dir = std::env::temp_dir().join(format!("nornir-fresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let corpus = dir.join("corpus.bin");
        let artifact = dir.join("corpus.gz");

        // Prior run: corpus, then its derived artifact (artifact newer → fresh).
        std::fs::File::create(&corpus)
            .unwrap()
            .write_all(b"old-512-corpus")
            .unwrap();
        std::fs::File::create(&artifact)
            .unwrap()
            .write_all(b"gz-of-old")
            .unwrap();
        assert!(
            artifact_is_fresh(&artifact, &corpus),
            "an artifact built AFTER its corpus must be reusable"
        );

        // New run at a different corpus size: regenerating corpus.bin bumps its
        // mtime past the stale artifact, which must now be rebuilt, not reused.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::File::create(&corpus)
            .unwrap()
            .write_all(b"new-1024-corpus-larger")
            .unwrap();
        assert!(
            !artifact_is_fresh(&artifact, &corpus),
            "a STALE artifact (older than the regenerated corpus) must NOT be reused"
        );

        // A missing / empty artifact is never fresh.
        assert!(!artifact_is_fresh(&dir.join("nope.gz"), &corpus));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The single-thread sanity gate must PASS on physically plausible data
    /// (`_st` slower than its all-core sibling) and TRIP on the impossible
    /// field observation (`znippy-bz2_st` 9202.86 MB/s while all-core
    /// `znippy-bz2` is only 549 MB/s) — the exact class of bug it guards.
    #[test]
    fn single_thread_gate_passes_good_trips_impossible() {
        // Good: both `_st` rows below their all-core siblings.
        let good = vec![
            json!({"name": "znippy-gz",     "decompress_mbs": 549.0}),
            json!({"name": "znippy-gz_st",  "decompress_mbs": 494.0}),
            json!({"name": "znippy-bz2",    "decompress_mbs": 549.0}),
            json!({"name": "znippy-bz2_st", "decompress_mbs": 45.0}),
        ];
        assert!(
            check_single_thread_sane(&good).is_ok(),
            "plausible data must pass"
        );

        // Bad: the literal impossible row from tonight's honest heavy run.
        let bad = vec![
            json!({"name": "znippy-bz2",    "decompress_mbs": 549.0}),
            json!({"name": "znippy-bz2_st", "decompress_mbs": 9202.86}),
        ];
        assert!(
            check_single_thread_sane(&bad).is_err(),
            "impossible _st row must trip the gate"
        );

        // Within slack (noise): a hair above all-core is tolerated, not failed.
        let noisy = vec![
            json!({"name": "znippy-gz",    "decompress_mbs": 500.0}),
            json!({"name": "znippy-gz_st", "decompress_mbs": 520.0}),
        ];
        assert!(
            check_single_thread_sane(&noisy).is_ok(),
            "small noise must not trip the gate"
        );

        // A missing sibling (decoder not built) must not spuriously trip.
        let partial = vec![json!({"name": "znippy-bz2_st", "decompress_mbs": 9999.0})];
        assert!(
            check_single_thread_sane(&partial).is_ok(),
            "no all-core sibling → no comparison"
        );
    }
}
