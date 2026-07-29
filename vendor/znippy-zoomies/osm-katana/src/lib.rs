mod coords_ipc;
mod geometry;
pub mod metadata;
mod node_store;
pub mod par;
mod pbf_decomp;
mod pbf_enc;
mod pbf_io;
pub mod phase_log;
pub mod shared;
#[allow(clippy::all, reason = "generated protobuf code")]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto_mod.rs"));
}
mod reader;
mod relations;
pub use relations::{PbfAdminRelation, load_admin_boundaries_pbf};
mod geo2arrow;
pub mod side_outputs;
mod tags;
pub(crate) mod writer;
mod xml_reader;
pub mod xml_to_pbf;
pub use geo2arrow::geo2arrow;
mod optimize;
pub use optimize::{OptimizeOptions, optimize};
pub mod digest;
#[cfg(feature = "planet-fixture")]
pub mod fixture;
pub mod spatial;
pub mod verify;

// The XML parallel parser and Ragnar's static search tree now live in the
// `znippy-zoomies` crate. Re-export under their original module names so
// existing `crate::xml_vtd::…` / `crate::stree64::…` / `osm2geoparquet::xml_vtd::…`
// references keep working unchanged.
pub use znippy_zoomies::stree as stree64;
pub use znippy_zoomies::vtd as xml_vtd;

/// **Introspection / emit marker** — record one functional-status row for the
/// nornir test matrix. Wraps `nornir_testmatrix::functional_status` behind the
/// `testmatrix` feature (a compiled-out `#[inline]` no-op otherwise, with no
/// nornir dep in the default build). Mirrors the korp-collectors reference
/// wiring so `nornir test --features testmatrix` SEES the osm-katana CLIs.
#[inline]
pub fn functional_status(component: &str, check: &str, ok: bool, detail: &str) {
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(component, check, ok, detail);
    #[cfg(not(feature = "testmatrix"))]
    {
        let _ = (component, check, ok, detail);
    }
}

/// Slim record returned by `load_ways_pbf` — carries only what the viewer needs.
pub struct PbfWayRecord {
    pub id: i64,
    /// WKB-encoded geometry (LineString or Polygon); `None` if < 2 resolvable nodes.
    pub geometry: Option<Vec<u8>>,
    /// JSON-serialised tag map, e.g. `{"highway":"primary","name":"E4"}`.
    pub tags: String,
}

/// Two-pass PBF → way records, skipping Parquet output entirely.
///
/// Pass 1 builds a node-ID → (lat, lon) store.
/// Pass 2 resolves way node-refs and WKB-encodes the geometry.
/// Progress bars are suppressed (use the full `convert()` API for CLI feedback).
pub fn load_ways_pbf(pbf_path: &str) -> anyhow::Result<Vec<PbfWayRecord>> {
    use anyhow::Context as _;
    use memmap2::MmapOptions;

    let file = std::fs::File::open(pbf_path).with_context(|| format!("open {pbf_path}"))?;
    // SAFETY: file is not modified while the mmap is alive.
    let mmap =
        unsafe { MmapOptions::new().map(&file) }.with_context(|| format!("mmap {pbf_path}"))?;

    let t0 = std::time::Instant::now();
    let positions = pbf_io::scan_blob_positions_par(&mmap);
    eprintln!(
        "  pbf scan:               {:.2}s  {} blobs",
        t0.elapsed().as_secs_f64(),
        positions.len()
    );

    let t1 = std::time::Instant::now();
    // Pass 1 also reports which blobs carry ways/relations, so pass 2 can skip the
    // node-only ones instead of re-inflating them. The flag costs nothing: pass 1
    // already parses each block and walks its primitivegroups.
    let (store, pass2_plan) = reader::read_pass1_mmap_planned(&mmap, &positions)?;
    eprintln!(
        "  pbf pass1 (node store): {:.2}s  {} nodes",
        t1.elapsed().as_secs_f64(),
        store.len()
    );

    let t2 = std::time::Instant::now();
    let backend = crate::shared::gpu_backend::CpuBackend;
    let (way_records, _rels) =
        reader::read_pass2_mmap_planned(&mmap, &positions, &pass2_plan, &store, &backend)?;
    eprintln!(
        "  pbf pass2 (ways):       {:.2}s  {} ways  ({} of {} blobs carried ways/rels)",
        t2.elapsed().as_secs_f64(),
        way_records.len(),
        pass2_plan.len(),
        positions.len()
    );

    Ok(way_records
        .into_iter()
        .map(|w| PbfWayRecord {
            id: w.id,
            geometry: w.geometry,
            tags: w.tags_json,
        })
        .collect())
}

use std::path::{Path, PathBuf};
use std::sync::Arc;

use indicatif::{HumanCount, ProgressBar, ProgressStyle};

// ── region clip — bbox + polygon, applied at coordinate decode ──────────────────
//
// The clip is a per-node test run INSIDE the Gatling pass-1 workers, right after a
// node's (lon, lat) are decoded and before any tag-JSON work. There is NO extra
// pass and NO serial scan — every core that decodes a blob also clips it (the
// `agent-gatling-serial-hunter.md` law). `clip == None` (no `--clip`/`--poly`) is
// a never-taken `if let Some` branch the optimiser folds away, so the lean convert
// is byte-identical to a build that never knew about clipping.

/// Axis-aligned geographic bounding box. The cheap fast-path of [`Clip`]: a node
/// outside the box is rejected with four float compares, so it never reaches the
/// (far more expensive) polygon ray-cast.
///
/// Box edges are **inclusive** so adjoining tiles share boundary nodes
/// deterministically.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bounds {
    pub min_lon: f64,
    pub min_lat: f64,
    pub max_lon: f64,
    pub max_lat: f64,
}

impl Bounds {
    /// Construct from `(min_lon, min_lat, max_lon, max_lat)`.
    #[inline]
    pub const fn new(min_lon: f64, min_lat: f64, max_lon: f64, max_lat: f64) -> Self {
        Self {
            min_lon,
            min_lat,
            max_lon,
            max_lat,
        }
    }

    /// Branchless inclusive containment — four float compares `&`-combined (no
    /// short-circuit branches) so the predicate stays a straight line in registers.
    #[inline]
    pub fn contains(&self, lon: f64, lat: f64) -> bool {
        (lon >= self.min_lon)
            & (lon <= self.max_lon)
            & (lat >= self.min_lat)
            & (lat <= self.max_lat)
    }

    /// Rough continental Europe bbox.
    #[inline]
    pub const fn europe() -> Self {
        Self::new(-31.5, 27.0, 69.0, 81.5)
    }

    /// Rough Nordic bbox (Norway, Sweden, Finland, Denmark, Iceland).
    #[inline]
    pub const fn nordics() -> Self {
        Self::new(-25.0, 54.0, 42.0, 72.0)
    }

    /// Bounding box that encloses every vertex of `rings` (the polygon's own bbox).
    fn of_rings(rings: &[Vec<(f64, f64)>]) -> Self {
        let mut b = Self::new(
            f64::INFINITY,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NEG_INFINITY,
        );
        for ring in rings {
            for &(lon, lat) in ring {
                b.min_lon = b.min_lon.min(lon);
                b.max_lon = b.max_lon.max(lon);
                b.min_lat = b.min_lat.min(lat);
                b.max_lat = b.max_lat.max(lat);
            }
        }
        b
    }

    /// Parse a `--clip` argument: a preset (`europe`, `nordics`, case-insensitive)
    /// or a raw bbox `min_lon,min_lat,max_lon,max_lat`.
    ///
    /// ```
    /// use osm_katana::Bounds;
    /// assert_eq!(Bounds::parse("europe").unwrap(),  Bounds::europe());
    /// assert_eq!(Bounds::parse("nordics").unwrap(), Bounds::nordics());
    /// let b = Bounds::parse("9.47,47.05,9.64,47.27").unwrap();
    /// assert!(b.contains(9.5, 47.1));
    /// assert!(!b.contains(0.0, 0.0));
    /// assert!(Bounds::parse("not-a-bbox").is_err());
    /// ```
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "europe" => return Ok(Self::europe()),
            "nordics" => return Ok(Self::nordics()),
            _ => {}
        }
        let parts: Vec<&str> = s.split(',').map(str::trim).collect();
        anyhow::ensure!(
            parts.len() == 4,
            "clip must be a preset (europe|nordics) or 'min_lon,min_lat,max_lon,max_lat', got {s:?}"
        );
        let v: Vec<f64> = parts
            .iter()
            .map(|p| {
                p.parse::<f64>()
                    .map_err(|_| anyhow::anyhow!("clip bbox component {p:?} is not a number"))
            })
            .collect::<anyhow::Result<_>>()?;
        let b = Self::new(v[0], v[1], v[2], v[3]);
        anyhow::ensure!(
            b.max_lon >= b.min_lon && b.max_lat >= b.min_lat,
            "clip bbox must have max >= min (got {b:?})"
        );
        Ok(b)
    }
}

/// A (multi-)polygon clip region. Each entry of `rings` is a closed (or
/// implicitly-closed) ring of `(lon, lat)` vertices. `contains` uses the
/// even-odd ray-cast rule across **all** rings combined, so a `.poly` file's
/// hole/island sections compose the way Osmosis intends.
///
/// `bbox` is the polygon's own bounding box, precomputed once: a node outside the
/// bbox is rejected before the (expensive) ray-cast even runs — the bbox is a
/// free pre-filter for the polygon path.
#[derive(Clone, Debug)]
pub struct Polygon {
    rings: Vec<Vec<(f64, f64)>>,
    bbox: Bounds,
}

impl Polygon {
    /// Build from one or more rings of `(lon, lat)` vertices.
    pub fn new(rings: Vec<Vec<(f64, f64)>>) -> anyhow::Result<Self> {
        anyhow::ensure!(!rings.is_empty(), "polygon must have at least one ring");
        anyhow::ensure!(
            rings.iter().any(|r| r.len() >= 3),
            "polygon must have a ring of at least 3 vertices"
        );
        let bbox = Bounds::of_rings(&rings);
        Ok(Self { rings, bbox })
    }

    /// The polygon's bounding box — the cheap pre-filter applied before the ray-cast.
    #[inline]
    pub fn bbox(&self) -> Bounds {
        self.bbox
    }

    /// Total vertex count across all rings (for diagnostics / tests).
    pub fn vertex_count(&self) -> usize {
        self.rings.iter().map(Vec::len).sum()
    }

    /// Number of rings.
    pub fn ring_count(&self) -> usize {
        self.rings.len()
    }

    /// Even-odd ray-cast point-in-polygon test across all rings. A point on the
    /// edge is treated consistently but not guaranteed in/out (standard ray-cast
    /// caveat); the bbox pre-filter handles the common "far outside" case cheaply.
    #[inline]
    pub fn contains(&self, lon: f64, lat: f64) -> bool {
        // Free pre-filter: outside the polygon's own bbox ⇒ definitely outside.
        if !self.bbox.contains(lon, lat) {
            return false;
        }
        let mut inside = false;
        for ring in &self.rings {
            let n = ring.len();
            if n < 3 {
                continue;
            }
            let mut j = n - 1;
            for i in 0..n {
                let (xi, yi) = ring[i];
                let (xj, yj) = ring[j];
                // Does the horizontal ray at `lat` cross edge (j -> i)?
                if ((yi > lat) != (yj > lat)) && (lon < (xj - xi) * (lat - yi) / (yj - yi) + xi) {
                    inside = !inside;
                }
                j = i;
            }
        }
        inside
    }

    /// Parse a clip polygon from a file: Osmosis `.poly` format (by extension or
    /// content) or a GeoJSON `Polygon` / `MultiPolygon` / `Feature` /
    /// `FeatureCollection`.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read clip polygon {path:?}"))?;
        let is_geojson = path.extension().is_some_and(|e| {
            let e = e.to_ascii_lowercase();
            e == "json" || e == "geojson"
        }) || text.trim_start().starts_with('{');
        if is_geojson {
            Self::from_geojson_str(&text)
        } else {
            Self::from_poly_str(&text)
        }
    }

    /// Parse an Osmosis `.poly` file. Format: a name line, then one or more ring
    /// sections (`section-name` line, `   lon   lat` lines, `END`), then a final
    /// `END`. Lines whose section name starts with `!` are holes — for an even-odd
    /// ray-cast they compose automatically, so we keep every ring.
    pub fn from_poly_str(text: &str) -> anyhow::Result<Self> {
        let mut rings: Vec<Vec<(f64, f64)>> = Vec::new();
        let mut cur: Option<Vec<(f64, f64)>> = None;
        let mut lines = text.lines();
        // First non-empty line is the polygon name — skip it.
        let _name = lines.by_ref().find(|l| !l.trim().is_empty());
        for line in lines {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if t.eq_ignore_ascii_case("END") {
                if let Some(r) = cur.take() {
                    rings.push(r); // END of a ring section
                }
                continue; // (the trailing file-level END just no-ops)
            }
            // A coordinate line has two parseable floats; otherwise it's a
            // section header that opens a new ring.
            let mut it = t.split_whitespace();
            let a = it.next().and_then(|s| s.parse::<f64>().ok());
            let b = it.next().and_then(|s| s.parse::<f64>().ok());
            match (a, b) {
                (Some(lon), Some(lat)) => {
                    cur.get_or_insert_with(Vec::new).push((lon, lat));
                }
                _ => {
                    // section header — start a fresh ring
                    if let Some(r) = cur.take() {
                        rings.push(r);
                    }
                    cur = Some(Vec::new());
                }
            }
        }
        if let Some(r) = cur.take() {
            rings.push(r);
        }
        rings.retain(|r| r.len() >= 3);
        Self::new(rings)
    }

    /// Parse a GeoJSON `Polygon` / `MultiPolygon` (also unwraps `Feature` and
    /// `FeatureCollection`). Coordinates are `[lon, lat]` per the GeoJSON spec.
    pub fn from_geojson_str(text: &str) -> anyhow::Result<Self> {
        let v: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| anyhow::anyhow!("clip polygon is not valid GeoJSON: {e}"))?;
        let geom = Self::geojson_geometry(&v)
            .ok_or_else(|| anyhow::anyhow!("GeoJSON has no Polygon/MultiPolygon geometry"))?;
        let ty = geom
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or_default();
        let coords = geom
            .get("coordinates")
            .ok_or_else(|| anyhow::anyhow!("GeoJSON geometry has no coordinates"))?;
        let mut rings: Vec<Vec<(f64, f64)>> = Vec::new();
        match ty {
            "Polygon" => Self::push_geojson_rings(coords, &mut rings),
            "MultiPolygon" => {
                if let Some(polys) = coords.as_array() {
                    for poly in polys {
                        Self::push_geojson_rings(poly, &mut rings);
                    }
                }
            }
            other => anyhow::bail!(
                "unsupported GeoJSON geometry type {other:?} (need Polygon/MultiPolygon)"
            ),
        }
        rings.retain(|r| r.len() >= 3);
        Self::new(rings)
    }

    /// Descend Feature / FeatureCollection wrappers to the first geometry object.
    fn geojson_geometry(v: &serde_json::Value) -> Option<serde_json::Value> {
        match v.get("type").and_then(|t| t.as_str()) {
            Some("FeatureCollection") => v
                .get("features")?
                .as_array()?
                .iter()
                .find_map(Self::geojson_geometry),
            Some("Feature") => Self::geojson_geometry(v.get("geometry")?),
            Some("Polygon") | Some("MultiPolygon") => Some(v.clone()),
            _ => None,
        }
    }

    /// Push each ring (array of `[lon, lat]`) of one polygon's coordinate array.
    fn push_geojson_rings(coords: &serde_json::Value, rings: &mut Vec<Vec<(f64, f64)>>) {
        let Some(arr) = coords.as_array() else { return };
        for ring in arr {
            let Some(pts) = ring.as_array() else { continue };
            let mut r = Vec::with_capacity(pts.len());
            for p in pts {
                if let Some(c) = p.as_array() {
                    if let (Some(lon), Some(lat)) = (
                        c.first().and_then(|x| x.as_f64()),
                        c.get(1).and_then(|x| x.as_f64()),
                    ) {
                        r.push((lon, lat));
                    }
                }
            }
            if !r.is_empty() {
                rings.push(r);
            }
        }
    }
}

/// The active region clip. `Bbox` is the cheap axis-aligned path; `Poly` carries a
/// (multi-)polygon and tests its own bbox first (free pre-filter) before the
/// ray-cast. Shared read-only across all Gatling workers behind an `Arc`.
#[derive(Clone, Debug)]
pub enum Clip {
    Bbox(Bounds),
    Poly(Polygon),
}

impl Clip {
    /// True if `(lon, lat)` survives the clip. Bbox is a straight-line compare;
    /// Poly does its own bbox pre-filter then the ray-cast.
    #[inline]
    pub fn contains(&self, lon: f64, lat: f64) -> bool {
        match self {
            Clip::Bbox(b) => b.contains(lon, lat),
            Clip::Poly(p) => p.contains(lon, lat),
        }
    }
}

/// Convenience for callers / tests: borrow an `Option<&Clip>` and test a point,
/// keeping `None` (no clip) as a trivially-true free branch.
#[inline]
pub(crate) fn clip_keeps(clip: Option<&Clip>, lon: f64, lat: f64) -> bool {
    match clip {
        None => true,
        Some(c) => c.contains(lon, lat),
    }
}

/// Decode every node from in-memory PBF `bytes` through the **real** pass-1 decode
/// path (`scan_blob_positions_par` → `blob_nodes_and_coords`), honouring an
/// optional region `clip`. Returns the number of nodes that survive. This is the
/// exact decode the converter's PBF pass-1 worker runs, so a green clip test here
/// proves the production clip — `None` is the lean hot path.
pub fn decode_pbf_node_count(bytes: &[u8], clip: Option<&Clip>) -> usize {
    let positions = pbf_io::scan_blob_positions_par(bytes);
    positions
        .iter()
        .map(|p| reader::blob_nodes_and_coords(bytes, p, clip).0.len())
        .sum()
}

// ── bzip2 streaming reader ────────────────────────────────────────────────────

pub struct ConvertOptions {
    pub output_dir: PathBuf,
    pub include_nodes: bool,
    pub include_ways: bool,
    pub include_rels: bool,
    pub compression: String,
    /// Number of parallel VTD workers for XML input. 0 = all cores minus one.
    pub vtd_workers: usize,
    /// Geometry mode: "resolved" (default, 2-pass, ways → WKB) or
    /// "raw" (single-pass, ways keep node-ID list, no node store).
    pub geometry: String,
    /// Skip the changeset prologue in `.osm.bz2` input (seek to the first
    /// node/way/relation block). Output is identical — converters never emit
    /// changesets — just faster. Only affects bz2 input.
    pub skip_changesets: bool,
    /// Optional JSONL log file path. `None` = stderr-only phase logging.
    pub log_path: Option<PathBuf>,
    /// Optional region clip applied at coordinate decode in the pass-1 workers.
    /// `None` (default) is the lean, zero-overhead path. A node whose `(lon,lat)`
    /// is outside the clip is dropped before any tag-JSON work; ways are then
    /// kept iff at least one of their endpoints survived (node-membership
    /// semantics — see [`Clip`]).
    pub clip: Option<Arc<Clip>>,
    /// Keep the `node_coords.arrow` intermediate (and any `_nc_chunk_*.bin`
    /// spill files) after the convert finishes.
    ///
    /// The file is the mmap-backed node store pass 2 resolves way geometry
    /// through, so it is always written; this only controls whether it survives.
    /// It is large — 75 MB for Stockholm, 1.68 GB for Sweden — and a shipped
    /// GeoParquet pack has no use for it. `true` (the default) preserves the
    /// historical behaviour exactly.
    pub keep_node_coords: bool,
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("out"),
            include_nodes: true,
            include_ways: true,
            include_rels: true,
            compression: String::from("zstd"),
            vtd_workers: 0,
            geometry: String::from("resolved"),
            skip_changesets: false,
            log_path: None,
            clip: None,
            keep_node_coords: true,
        }
    }
}

/// Resolve the active region clip from options as a worker-shareable handle.
fn active_clip(opts: &ConvertOptions) -> Option<Arc<Clip>> {
    opts.clip.clone()
}

/// Region-clip public entry point: parse a `--clip`-style bbox/preset `region`
/// string and run `convert` with that clip. (For polygon clips, build a
/// [`Polygon`] / [`Clip::Poly`] and set `ConvertOptions.clip` directly.)
pub fn extract_region(input: &Path, output_dir: &Path, region: &str) -> anyhow::Result<()> {
    let bounds = Bounds::parse(region)?;
    let opts = ConvertOptions {
        output_dir: output_dir.to_path_buf(),
        clip: Some(Arc::new(Clip::Bbox(bounds))),
        ..Default::default()
    };
    convert(input, &opts)
}

pub fn convert(input: &Path, opts: &ConvertOptions) -> anyhow::Result<()> {
    let sink = phase_log::PhaseSink::new(opts.log_path.as_deref())?;
    let file_size_meta = std::fs::metadata(input).map(|m| m.len()).unwrap_or(0);
    let file_size_str = file_size_meta.to_string();
    let workers_str = {
        let nw = if opts.vtd_workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get().saturating_sub(1).max(1))
                .unwrap_or(1)
        } else {
            opts.vtd_workers
        };
        nw.to_string()
    };
    let convert_phase = sink.phase(
        "convert",
        &[
            ("input_path", &input.display().to_string()),
            ("input_bytes", &file_size_str),
            ("workers", &workers_str),
            ("geometry", &opts.geometry),
            (
                "skip_changesets",
                if opts.skip_changesets {
                    "true"
                } else {
                    "false"
                },
            ),
        ],
    );
    let r = convert_inner(input, opts, &sink);
    // The node-coord store is an INTERMEDIATE: pass 2 mmaps it to resolve way
    // geometry, and by here every parquet writer is closed and the store dropped.
    // Historically it was left behind unconditionally — 75 MB for Stockholm,
    // 1.68 GB for Sweden — even for a run that only wanted the parquet.
    if !opts.keep_node_coords {
        let freed = remove_node_coords(&opts.output_dir);
        if freed > 0 {
            eprintln!(
                "  removed node_coords intermediates ({freed} bytes) — --keep-node-coords false"
            );
        }
    }
    match &r {
        Ok(_) => convert_phase.done(&[("ok", "true".into())]),
        Err(e) => convert_phase.done(&[("ok", "false".into()), ("err", e.to_string())]),
    }
    r
}

/// Delete `node_coords.arrow` and any `_nc_chunk_*.bin` spill files from
/// `dir`, returning the bytes reclaimed. Best-effort: a file that cannot be
/// removed is skipped rather than failing the convert, since the parquet — the
/// actual product — is already on disk and correct.
fn remove_node_coords(dir: &Path) -> u64 {
    let mut freed = 0u64;
    let mut drop_one = |p: PathBuf| {
        if let Ok(m) = std::fs::metadata(&p) {
            if std::fs::remove_file(&p).is_ok() {
                freed += m.len();
            }
        }
    };
    drop_one(dir.join("node_coords.arrow"));
    drop_one(dir.join("node_coords.bin"));
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("_nc_chunk_") && name.ends_with(".bin") {
                drop_one(e.path());
            }
        }
    }
    freed
}

fn convert_inner(
    input: &Path,
    opts: &ConvertOptions,
    sink: &phase_log::PhaseSink,
) -> anyhow::Result<()> {
    let is_bz2 = input
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("bz2"));
    let is_gz = input
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("gz"));
    let is_xml = is_bz2
        || is_gz
        || input
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("osm"));

    if opts.geometry != "raw" && opts.geometry != "resolved" {
        anyhow::bail!(
            "--geometry must be 'raw' or 'resolved', got '{}'",
            opts.geometry
        );
    }
    if opts.geometry == "raw" && !is_xml {
        anyhow::bail!(
            "--geometry raw supports XML inputs (.osm, .osm.bz2, .osm.gz) only \
             (got {input:?}); use the default 'resolved' mode for PBF input"
        );
    }
    if opts.geometry == "raw" && opts.clip.is_some() {
        anyhow::bail!(
            "region clip (--clip/--poly) requires the default 'resolved' geometry \
             mode (raw keeps node-ID lists, not resolved coords, so node-membership \
             clipping does not apply)"
        );
    }

    let file_size = std::fs::metadata(input).map(|m| m.len()).unwrap_or(0);

    // Region clip (bbox/polygon) shared read-only across every pass-1 worker.
    // `None` ⇒ the lean, branch-folded hot path.
    let clip = active_clip(opts);

    // For bz2, the progress bar length is the compressed size × 2 (two passes).
    // The bar will look slow during pass 1 decompression and fast otherwise —
    // that's acceptable; the message field always shows current activity.
    let pb = ProgressBar::new(file_size.saturating_mul(2));
    pb.set_style(
        ProgressStyle::with_template(
            "[{bar:50.cyan/237}]  {bytes:>9} / {total_bytes}  {bytes_per_sec:>10}  eta {eta}  {msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("█▉▊▋▌▍▎▏ "),
    );
    pb.set_message("init …");

    let backend = crate::shared::gpu_backend::CpuBackend;

    std::fs::create_dir_all(&opts.output_dir)?;

    pb.set_message("pass 1/2");
    let (node_records, way_records, rel_records);
    let mut node_count_override: Option<usize> = None; // set when nodes written in pass 1
    let mut way_count_override: Option<usize> = None; // set when ways written during pass 2
    let mut rel_count_override: Option<usize> = None; // set when rels written during pass 2

    if (is_bz2 || is_gz) && opts.geometry == "raw" {
        // Raw streaming: ONE decompression pass, no node store, no pass 2.
        // Per slot, parse all kinds and write directly — ways keep node_refs, geometry null.
        let n_workers = if opts.vtd_workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get().saturating_sub(1).max(1))
                .unwrap_or(1)
        } else {
            opts.vtd_workers
        };

        let (node_count, way_count, rel_count) = if is_bz2 {
            // Fast path: Gatling engine (parallel bz2 decode, no barrier) → Parquet.
            pb.set_message("raw bz2 (Gatling, 1 pass)");
            xml_reader::read_raw_bz2(
                input,
                &opts.output_dir,
                &opts.compression,
                opts.include_nodes,
                opts.include_ways,
                opts.include_rels,
                n_workers,
                opts.skip_changesets,
                pb.clone(),
            )?
        } else {
            // gz: Gatling engine (lgz DEFLATE decode in workers, no rayon) → Parquet.
            pb.set_message("raw gz (Gatling, 1 pass)");
            xml_reader::read_raw_gz(
                input,
                &opts.output_dir,
                &opts.compression,
                opts.include_nodes,
                opts.include_ways,
                opts.include_rels,
                n_workers,
                pb.clone(),
            )?
        };

        node_count_override = Some(node_count);
        way_count_override = Some(way_count);
        rel_count_override = Some(rel_count);

        node_records = vec![];
        way_records = vec![];
        rel_records = vec![];
    } else if is_bz2 || is_gz {
        // Streaming path: decompress slot-by-slot, two passes.
        // Node records are written to Parquet during pass 1 (no Vec accumulation).
        // Node coords are streamed to a temp binary file, sorted, then mmap'd
        // (managed inside the read_resolved_* readers).
        let n_workers = if opts.vtd_workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get().saturating_sub(1).max(1))
                .unwrap_or(1)
        } else {
            opts.vtd_workers
        };

        if is_bz2 {
            // Fast path: resolved 2-pass through the Gatling engine.
            pb.set_message("resolved bz2 (Gatling, 2-pass)");
            let (nc, wc, rc) = xml_reader::read_resolved_bz2(
                input,
                &opts.output_dir,
                &opts.compression,
                opts.include_nodes,
                opts.include_ways,
                opts.include_rels,
                n_workers,
                opts.skip_changesets,
                pb.clone(),
                &backend,
                Some(sink),
                clip.clone(),
            )?;
            node_count_override = Some(nc);
            way_count_override = Some(wc);
            rel_count_override = Some(rc);
        } else {
            // gz: resolved 2-pass through the Gatling engine (lgz DEFLATE decode
            // in workers, no rayon). Mirrors the bz2 fast path.
            pb.set_message("resolved gz (Gatling, 2-pass)");
            let (nc, wc, rc) = xml_reader::read_resolved_gz(
                input,
                &opts.output_dir,
                &opts.compression,
                opts.include_nodes,
                opts.include_ways,
                opts.include_rels,
                n_workers,
                pb.clone(),
                &backend,
                Some(sink),
                clip.clone(),
            )?;
            node_count_override = Some(nc);
            way_count_override = Some(wc);
            rel_count_override = Some(rc);
        }

        node_records = vec![]; // written to Parquet during pass 1
        way_records = vec![]; // written to Parquet during pass 2
        rel_records = vec![]; // written to Parquet during pass 2
    } else if is_xml {
        let input_str = input
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 path"))?;
        let idx_path = opts.output_dir.join("elem.idx");
        let n_workers = if opts.vtd_workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get().saturating_sub(1).max(1))
                .unwrap_or(1)
        } else {
            opts.vtd_workers
        };

        if opts.geometry == "raw" {
            // Single-pass: no node store, no coord resolution. Writes directly.
            let (nc, wc, rc) = xml_reader::read_raw(
                input_str,
                &idx_path,
                n_workers,
                pb.clone(),
                &opts.output_dir,
                &opts.compression,
                opts.include_nodes,
                opts.include_ways,
                opts.include_rels,
            )?;
            node_count_override = Some(nc);
            way_count_override = Some(wc);
            rel_count_override = Some(rc);
            node_records = vec![];
            way_records = vec![];
            rel_records = vec![];
        } else {
            let (nc, wc, rc) = xml_reader::read_resolved_osm(
                input_str,
                &idx_path,
                n_workers,
                pb.clone(),
                &opts.output_dir,
                &opts.compression,
                opts.include_nodes,
                opts.include_ways,
                opts.include_rels,
                &backend,
                clip.clone(),
            )?;
            node_count_override = Some(nc);
            way_count_override = Some(wc);
            rel_count_override = Some(rc);
            node_records = vec![];
            way_records = vec![];
            rel_records = vec![];
        }
    } else {
        // PBF path: Gatling worker-pool engine (NO rayon). `split` cuts the byte
        // stream at blob frame boundaries; each worker zlib+protobuf-decodes one
        // blob. Two passes (coords+nodes, then ways+rels) share the same coord-
        // sort / node-store path as the bz2 and gz converters.
        let n_workers = if opts.vtd_workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get().saturating_sub(1).max(1))
                .unwrap_or(1)
        } else {
            opts.vtd_workers
        };

        pb.set_message("resolved pbf (Gatling, 2-pass)");
        let (nc, wc, rc) = xml_reader::read_resolved_pbf(
            input,
            &opts.output_dir,
            &opts.compression,
            opts.include_nodes,
            opts.include_ways,
            opts.include_rels,
            n_workers,
            pb.clone(),
            &backend,
            Some(sink),
            clip.clone(),
        )?;
        node_count_override = Some(nc);
        way_count_override = Some(wc);
        rel_count_override = Some(rc);

        node_records = vec![];
        way_records = vec![];
        rel_records = vec![];
    }
    let node_count = node_count_override.unwrap_or(node_records.len());
    let way_count = way_count_override.unwrap_or(way_records.len());
    let rel_count = rel_count_override.unwrap_or(rel_records.len());
    pb.set_message("writing …");

    // For bz2/gz paths nodes/ways/rels are already written during streaming passes.
    if opts.include_nodes && node_count_override.is_none() {
        writer::write_nodes(
            &opts.output_dir.join("nodes.parquet"),
            &node_records,
            &opts.compression,
        )?;
    }
    if opts.include_ways && way_count_override.is_none() {
        writer::write_ways(
            &opts.output_dir.join("ways.parquet"),
            &way_records,
            &opts.compression,
        )?;
    }
    if opts.include_rels && rel_count_override.is_none() {
        writer::write_relations(
            &opts.output_dir.join("relations.parquet"),
            &rel_records,
            &opts.compression,
        )?;
    }

    pb.finish_with_message(format!(
        "done  {} nodes  {} ways  {} relations",
        HumanCount(node_count as u64),
        HumanCount(way_count as u64),
        HumanCount(rel_count as u64),
    ));

    Ok(())
}

// ── region-clip inject-assert tests ─────────────────────────────────────────────
#[cfg(test)]
mod clip_tests {
    use super::*;
    use std::io::Cursor;

    /// Build a real PBF in-memory containing a `cols × rows` lattice of dense
    /// nodes spanning the bbox `[lon0..lon1] × [lat0..lat1]`. Goes through the
    /// production PBF encoder (`pbf_enc`), so decoding it exercises the exact
    /// `parse_nodes` path the converter runs — not a parallel re-implementation.
    fn synth_pbf(cols: usize, rows: usize, lon0: f64, lat0: f64, lon1: f64, lat1: f64) -> Vec<u8> {
        let mut st = pbf_enc::StringTable::new();
        // one real tag so the dense key/value cursor path is exercised
        let k = st.intern(b"natural");
        let v = st.intern(b"point");
        let mut dn = pbf_enc::DenseNodesBuilder::new();
        let mut id = 1i64;
        for r in 0..rows {
            for c in 0..cols {
                let fx = if cols > 1 {
                    c as f64 / (cols - 1) as f64
                } else {
                    0.0
                };
                let fy = if rows > 1 {
                    r as f64 / (rows - 1) as f64
                } else {
                    0.0
                };
                let lon = lon0 + fx * (lon1 - lon0);
                let lat = lat0 + fy * (lat1 - lat0);
                let lon_e7 = (lon * 1e7).round() as i32;
                let lat_e7 = (lat * 1e7).round() as i32;
                dn.push(id, lat_e7, lon_e7, &[(k, v)]);
                id += 1;
            }
        }
        let block = pbf_enc::encode_primitive_block(&st, Some(&dn), &[], &[]);
        let zstd = pbf_enc::compress_zstd(&block).unwrap();
        let mut out: Vec<u8> = Vec::new();
        {
            let mut cur = Cursor::new(&mut out);
            pbf_enc::write_osm_header(&mut cur).unwrap();
            pbf_enc::write_blob(&mut cur, b"OSMData", block.len(), &zstd).unwrap();
        }
        out
    }

    /// FAIL-ON-BUG / PASS-ON-FIX: feed a 20×20 lattice over a known box, then
    /// clip with a bbox covering exactly the left half — assert the kept count is
    /// the in-box subset, strictly fewer than total and strictly more than zero,
    /// and that `None` keeps everything. If the clip branch were removed (the
    /// bug), `half` would equal `total` and this fails.
    #[test]
    fn bbox_clip_drops_outside_keeps_inside() {
        // lattice over lon 0..10, lat 0..10
        let bytes = synth_pbf(20, 20, 0.0, 0.0, 10.0, 10.0);
        let total = decode_pbf_node_count(&bytes, None);
        assert_eq!(
            total, 400,
            "synthetic lattice should decode 400 nodes, got {total}"
        );

        // Left half: lon 0..5 inclusive. 20 cols span lon 0..10 at spacing
        // 10/19≈0.526, so cols 0..=9 (lon up to 4.74) are ≤5 and col 10 (5.26)
        // is out → 10 of 20 cols × 20 rows = 200 survive.
        let left = Clip::Bbox(Bounds::new(0.0, 0.0, 5.0, 10.0));
        let kept = decode_pbf_node_count(&bytes, Some(&left));
        assert!(kept > 0, "left-half bbox must keep some nodes, got {kept}");
        assert!(
            kept < total,
            "left-half bbox must drop nodes (kept {kept} of {total})"
        );
        assert_eq!(
            kept, 200,
            "left-half bbox should keep exactly 200 nodes, got {kept}"
        );

        // Far-away box keeps nothing.
        let far = Clip::Bbox(Bounds::new(100.0, 100.0, 101.0, 101.0));
        assert_eq!(
            decode_pbf_node_count(&bytes, Some(&far)),
            0,
            "far box must keep zero"
        );
    }

    /// FAIL-ON-BUG: a triangle polygon over the same lattice keeps strictly fewer
    /// nodes than its own bounding box (proving the ray-cast runs, not just the
    /// bbox pre-filter). A triangle covering the lower-left half of a square keeps
    /// roughly half the bbox's nodes.
    #[test]
    fn polygon_clip_is_tighter_than_its_bbox() {
        let bytes = synth_pbf(40, 40, 0.0, 0.0, 10.0, 10.0);
        let total = decode_pbf_node_count(&bytes, None);
        assert_eq!(total, 1600);

        // Right triangle: (0,0) (10,0) (0,10) — lower-left half of the square.
        let tri =
            Polygon::new(vec![vec![(0.0, 0.0), (10.0, 0.0), (0.0, 10.0), (0.0, 0.0)]]).unwrap();
        let bbox_clip = Clip::Bbox(tri.bbox());
        let bbox_kept = decode_pbf_node_count(&bytes, Some(&bbox_clip));
        let poly_kept = decode_pbf_node_count(&bytes, Some(&Clip::Poly(tri)));

        assert_eq!(
            bbox_kept, total,
            "triangle bbox == full square == all nodes"
        );
        assert!(
            poly_kept > 0,
            "triangle must keep some nodes, got {poly_kept}"
        );
        assert!(
            poly_kept < bbox_kept,
            "polygon ray-cast must keep STRICTLY fewer than its bbox \
             (poly {poly_kept} vs bbox {bbox_kept}) — else the ray-cast is a no-op"
        );
        // Lower-left triangle is ~half the square; allow generous slack.
        assert!(
            (poly_kept as f64) < 0.65 * bbox_kept as f64,
            "triangle should keep ~half, kept {poly_kept} of {bbox_kept}"
        );
    }

    /// Polygon::contains ray-cast unit test on a unit square with a precise point.
    #[test]
    fn polygon_contains_pointwise() {
        let sq = Polygon::new(vec![vec![(0.0, 0.0), (4.0, 0.0), (4.0, 4.0), (0.0, 4.0)]]).unwrap();
        assert!(sq.contains(2.0, 2.0), "centre is inside");
        assert!(
            !sq.contains(5.0, 2.0),
            "right of square is outside (bbox pre-filter)"
        );
        assert!(!sq.contains(-1.0, 2.0), "left of square is outside");
        assert!(!sq.contains(2.0, 9.0), "above square is outside");

        // Concave L-shape: the notch must be excluded by the ray-cast.
        let l = Polygon::new(vec![vec![
            (0.0, 0.0),
            (4.0, 0.0),
            (4.0, 2.0),
            (2.0, 2.0),
            (2.0, 4.0),
            (0.0, 4.0),
            (0.0, 0.0),
        ]])
        .unwrap();
        assert!(l.contains(1.0, 1.0), "inside the arm");
        assert!(l.contains(1.0, 3.0), "inside the vertical arm");
        assert!(
            !l.contains(3.0, 3.0),
            "the notch (upper-right) is OUTSIDE the L"
        );
    }

    /// Osmosis `.poly` parsing: a named single-ring square round-trips.
    #[test]
    fn poly_file_parse_osmosis() {
        let text = "test_region\n\
                    polygon-1\n\
                    \t1.0\t1.0\n\
                    \t3.0\t1.0\n\
                    \t3.0\t3.0\n\
                    \t1.0\t3.0\n\
                    \t1.0\t1.0\n\
                    END\n\
                    END\n";
        let p = Polygon::from_poly_str(text).unwrap();
        assert_eq!(p.ring_count(), 1, "one ring");
        assert_eq!(p.vertex_count(), 5, "five vertices incl. closing point");
        assert!(p.contains(2.0, 2.0), "centre inside");
        assert!(!p.contains(0.0, 0.0), "origin outside");
        assert_eq!(p.bbox(), Bounds::new(1.0, 1.0, 3.0, 3.0));
    }

    /// GeoJSON Polygon parsing (lon/lat order).
    #[test]
    fn poly_file_parse_geojson() {
        let gj = r#"{"type":"Polygon","coordinates":[[[1,1],[3,1],[3,3],[1,3],[1,1]]]}"#;
        let p = Polygon::from_geojson_str(gj).unwrap();
        assert!(p.contains(2.0, 2.0));
        assert!(!p.contains(5.0, 5.0));
        assert_eq!(p.bbox(), Bounds::new(1.0, 1.0, 3.0, 3.0));

        // Feature wrapper unwraps to the same geometry.
        let feat = r#"{"type":"Feature","properties":{},"geometry":{"type":"Polygon","coordinates":[[[1,1],[3,1],[3,3],[1,3]]]}}"#;
        let p2 = Polygon::from_geojson_str(feat).unwrap();
        assert!(p2.contains(2.0, 2.0));
    }

    /// Build a PBF with two node clusters and one way per cluster, plus a way
    /// straddling both. Returns the raw PBF bytes. Cluster A is near (1,1),
    /// cluster B near (50,50). Way 100 = all-A, way 200 = all-B, way 300 = A+B.
    fn synth_pbf_with_ways() -> Vec<u8> {
        let mut st = pbf_enc::StringTable::new();
        let k = st.intern(b"highway");
        let v = st.intern(b"residential");
        let mut dn = pbf_enc::DenseNodesBuilder::new();
        // cluster A: ids 1,2,3 near (1,1)
        dn.push(1, (1.00 * 1e7) as i32, (1.00 * 1e7) as i32, &[]);
        dn.push(2, (1.01 * 1e7) as i32, (1.01 * 1e7) as i32, &[]);
        dn.push(3, (1.02 * 1e7) as i32, (1.02 * 1e7) as i32, &[]);
        // cluster B: ids 11,12,13 near (50,50)
        dn.push(11, (50.00 * 1e7) as i32, (50.00 * 1e7) as i32, &[]);
        dn.push(12, (50.01 * 1e7) as i32, (50.01 * 1e7) as i32, &[]);
        dn.push(13, (50.02 * 1e7) as i32, (50.02 * 1e7) as i32, &[]);
        let way_a = pbf_enc::encode_way(100, &[(k, v)], &[1, 2, 3]);
        let way_b = pbf_enc::encode_way(200, &[(k, v)], &[11, 12, 13]);
        let way_ab = pbf_enc::encode_way(300, &[(k, v)], &[1, 11]); // straddles
        let block = pbf_enc::encode_primitive_block(&st, Some(&dn), &[way_a, way_b, way_ab], &[]);
        let zstd = pbf_enc::compress_zstd(&block).unwrap();
        let mut out: Vec<u8> = Vec::new();
        {
            let mut cur = Cursor::new(&mut out);
            pbf_enc::write_osm_header(&mut cur).unwrap();
            pbf_enc::write_blob(&mut cur, b"OSMData", block.len(), &zstd).unwrap();
        }
        out
    }

    fn parquet_rows(path: &std::path::Path) -> usize {
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let b =
            ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).unwrap()).unwrap();
        b.metadata().file_metadata().num_rows() as usize
    }

    /// FAIL-ON-BUG: full `convert` with a bbox covering ONLY cluster A must keep
    /// way 100 (all-A) and way 300 (straddles → has an in-region endpoint) but
    /// DROP way 200 (all-B). Without the pass-2 way-membership filter, all 3 ways
    /// would survive (geometry just null) and this fails at `ways == 2`.
    #[test]
    fn way_clip_keeps_in_region_and_crossing_drops_outside() {
        let bytes = synth_pbf_with_ways();
        let dir = tempfile::tempdir().unwrap();
        let pbf = dir.path().join("in.osm.pbf");
        std::fs::write(&pbf, &bytes).unwrap();
        let out = dir.path().join("out");

        // Clip to a box around cluster A only (lon/lat 0..2).
        let opts = ConvertOptions {
            output_dir: out.clone(),
            clip: Some(Arc::new(Clip::Bbox(Bounds::new(0.0, 0.0, 2.0, 2.0)))),
            ..Default::default()
        };
        convert(&pbf, &opts).unwrap();

        // 3 of 6 nodes are in cluster A.
        assert_eq!(
            parquet_rows(&out.join("nodes.parquet")),
            3,
            "only cluster-A nodes survive"
        );
        // way 100 (all-A) + way 300 (straddle, 1 endpoint in A) = 2; way 200 dropped.
        assert_eq!(
            parquet_rows(&out.join("ways.parquet")),
            2,
            "in-region way + straddling way kept, fully-outside way dropped"
        );

        // Control: NO clip keeps all 6 nodes and all 3 ways.
        let out2 = dir.path().join("out_noclip");
        let opts2 = ConvertOptions {
            output_dir: out2.clone(),
            clip: None,
            ..Default::default()
        };
        convert(&pbf, &opts2).unwrap();
        assert_eq!(
            parquet_rows(&out2.join("nodes.parquet")),
            6,
            "no clip keeps all nodes"
        );
        assert_eq!(
            parquet_rows(&out2.join("ways.parquet")),
            3,
            "no clip keeps all ways"
        );
    }

    /// FAIL-ON-BUG: full `convert` with a **polygon** `Clip` (the path facett-demo's
    /// Sverige button drives in-process) keeps only the nodes inside the polygon.
    /// Build a lattice straddling a triangle's diagonal; assert the surviving node
    /// count equals the in-polygon subset (strictly fewer than the no-clip total and
    /// fewer than the triangle's own bbox), proving the per-node ray-cast runs end to
    /// end through `convert()` → Parquet, not just the bbox pre-filter.
    #[test]
    fn convert_with_polygon_clip_keeps_only_inside_nodes() {
        let bytes = synth_pbf(40, 40, 0.0, 0.0, 10.0, 10.0);
        let dir = tempfile::tempdir().unwrap();
        let pbf = dir.path().join("in.osm.pbf");
        std::fs::write(&pbf, &bytes).unwrap();

        // Lower-left triangle (0,0)(10,0)(0,10): its bbox == the whole square.
        let tri =
            Polygon::new(vec![vec![(0.0, 0.0), (10.0, 0.0), (0.0, 10.0), (0.0, 0.0)]]).unwrap();
        let inside_expected = decode_pbf_node_count(&bytes, Some(&Clip::Poly(tri.clone())));
        let total = decode_pbf_node_count(&bytes, None);
        assert_eq!(total, 1600);
        assert!(
            inside_expected > 0 && inside_expected < total,
            "sanity: {inside_expected} of {total}"
        );

        let out = dir.path().join("out");
        let opts = ConvertOptions {
            output_dir: out.clone(),
            clip: Some(Arc::new(Clip::Poly(tri))),
            ..Default::default()
        };
        convert(&pbf, &opts).unwrap();

        let kept = parquet_rows(&out.join("nodes.parquet"));
        assert_eq!(
            kept, inside_expected,
            "convert() with a polygon clip must write exactly the in-polygon nodes \
             ({inside_expected}), got {kept}"
        );
        assert!(
            kept < total,
            "polygon clip must drop the out-of-region half"
        );

        // Control: no clip writes the full lattice.
        let out2 = dir.path().join("out_noclip");
        let opts2 = ConvertOptions {
            output_dir: out2.clone(),
            clip: None,
            ..Default::default()
        };
        convert(&pbf, &opts2).unwrap();
        assert_eq!(
            parquet_rows(&out2.join("nodes.parquet")),
            total,
            "no clip keeps all nodes"
        );
    }

    /// Bounds::parse presets + bbox + error cases.
    #[test]
    fn bounds_parse_roundtrip_and_errors() {
        assert_eq!(Bounds::parse("europe").unwrap(), Bounds::europe());
        assert_eq!(Bounds::parse("NORDICS").unwrap(), Bounds::nordics());
        let b = Bounds::parse("9.47,47.05,9.64,47.27").unwrap();
        assert!(b.contains(9.5, 47.1));
        assert!(!b.contains(0.0, 0.0));
        assert!(Bounds::parse("garbage").is_err());
        assert!(Bounds::parse("1,2,3").is_err(), "wrong arity errors");
        assert!(
            Bounds::parse("9.6,47.0,9.4,47.2").is_err(),
            "max<min errors"
        );
    }
}
