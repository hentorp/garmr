//! `osm-katana optimize` — shrink a GeoParquet dir into a small, embed-ready
//! GeoParquet (a few-hundred-KB to ~2 MB knob) for a wasm demo's `include_bytes!`.
//!
//! This is the first-class home for what the facett team hand-rolled: trim to
//! `geometry` + a slimmed `tags`, keep named POIs first, cap to ~40 k features,
//! zstd. Output is schema-compatible with `facett-osm::read_points` /
//! `read_ways` (a Binary **WKB** `geometry` column + a Utf8 JSON `tags` column).
//!
//! ## Gatling shape (N → 1)
//!
//! ```text
//!            N GATLING WORKERS                     1 WRITER
//!    each claims a ROW GROUP (LPT, by             saves ONLY
//!    compressed size), opens its OWN              ranks named-first,
//!    projected reader over just that   ───────►   applies the global
//!    group, and carries it fully through          --max-features cap,
//!    decode → filter → prune → tag-slim           writes ONE zstd
//!    → cap-rank. No barrier.                      GeoParquet
//! ```
//!
//! - **N workers do ALL the work** — parquet zstd-decompress + arrow-decode, WKB
//!   validation, named-POI detection, tag JSON parse + slim re-serialise, column
//!   pruning. Fan-out is `gatling_for_each_balanced` over `0..n_row_groups`
//!   (ROOT LAW #0: no rayon, no hand-rolled `thread::scope` pool), scheduled
//!   heaviest-group-first so a fat row group cannot strand the tail on one core.
//!   Nothing is decoded on the calling thread.
//! - **1 writer only saves**: it merges the per-group output in row-group order,
//!   ranks named features first, caps at `--max-features`, and writes a single
//!   zstd GeoParquet.
//!
//! Cores-busy is emitted as data via [`crate::phase_log`] (the `optimize.process`
//! phase's `cpu_cores` / `busy_pct`), exactly like convert's per-phase telemetry.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use arrow::array::{Array, BinaryArray, BinaryBuilder, StringArray, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::arrow::ProjectionMask;
use parquet::arrow::arrow_reader::{
    ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReaderBuilder,
};
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;

use crate::metadata;
use crate::phase_log::PhaseSink;

/// Tag keys that mark a feature as a "named" POI worth keeping first. A feature
/// is **named** if its `tags` JSON has any of these keys with a non-empty value.
/// Ordered roughly by how demo-interesting they are; presence of ANY qualifies.
const NAMED_KEYS: &[&str] = &[
    "name",
    "place",
    "amenity",
    "shop",
    "tourism",
    "historic",
    "leisure",
    "natural",
    "aeroway",
    "railway",
    "public_transport",
    "office",
    "man_made",
];

/// The slimmed tag set kept in the output (everything else is dropped to shrink
/// the JSON). `geometry` is always kept; this is the `tags` whitelist. A superset
/// of [`NAMED_KEYS`] plus the few keys facett's theme classifier reads for ways
/// (`highway`, `waterway`, `landuse`, `building`, `barrier`, `boundary`).
const KEEP_TAG_KEYS: &[&str] = &[
    "name",
    "place",
    "amenity",
    "shop",
    "tourism",
    "historic",
    "leisure",
    "natural",
    "aeroway",
    "railway",
    "public_transport",
    "office",
    "man_made",
    "highway",
    "waterway",
    "landuse",
    "building",
    "barrier",
    "boundary",
    "bridge",
    "tunnel",
    // 3D extrusion needs the building height tags so the facett map3d viewer can
    // raise each footprint to its real metric height (`height` wins, else
    // `building:levels` × ~3 m); kept whenever present, never name-gated.
    "height",
    "building:levels",
];

/// Knobs for [`optimize`]. Built by the CLI from its flags.
#[derive(Clone, Debug)]
pub struct OptimizeOptions {
    /// Output file path (a single `.parquet`).
    pub output: PathBuf,
    /// Keep only node points — read `nodes.parquet`, skip ways/relations.
    pub points_only: bool,
    /// Also fold `ways.parquet` in (LineString/Polygon WKB) when not points-only.
    pub include_ways: bool,
    /// Keep ONLY features that have a name/place/POI tag (drops unnamed).
    pub named_only: bool,
    /// **Buildings mode** — keep every `building=*` way (regardless of name) and,
    /// cheaply, the roads (`highway`) + water (`waterway` / `natural=water`) ways,
    /// preserving the `height` / `building:levels` tags so the facett map3d viewer
    /// can extrude real city footprints. A feature is kept if it is a building /
    /// road / water OR is a named POI (so the demo keeps its labelled points too);
    /// everything else (unnamed clutter) is dropped. Buildings are ranked FIRST
    /// under `--max-features`. Mutually exclusive with `named_only` (buildings wins).
    pub buildings: bool,
    /// Rank named features first when applying `--max-features` (default true).
    pub named_first: bool,
    /// Cap on total output features (0 = unlimited). Named-first if `named_first`.
    pub max_features: usize,
    /// Parquet compression: `zstd` (default) | `snappy` | `none`.
    pub compression: String,
    /// Optional `--log` path for the phase JSONL (also always to stderr).
    pub log_path: Option<PathBuf>,
}

impl Default for OptimizeOptions {
    fn default() -> Self {
        Self {
            output: PathBuf::from("optimized.parquet"),
            points_only: false,
            include_ways: true,
            named_only: false,
            buildings: false,
            named_first: true,
            max_features: 0,
            compression: String::from("zstd"),
            log_path: None,
        }
    }
}

/// One slimmed output feature: a WKB geometry blob + its slimmed JSON tags (or
/// `None` for an empty tag object) + whether it is a named POI (for ranking).
struct Feature {
    /// Ranked-first under `--max-features`. In default/named mode this is "is a
    /// named POI"; in [`OptimizeOptions::buildings`] mode it is "is a building"
    /// (so the cap keeps the city's footprints, not its labels).
    named: bool,
    geometry: Vec<u8>,
    tags: Option<String>,
}

fn compression(s: &str) -> Compression {
    match s {
        "snappy" => Compression::SNAPPY,
        "none" => Compression::UNCOMPRESSED,
        _ => Compression::ZSTD(Default::default()),
    }
}

/// The embed output schema — exactly the two columns facett-osm reads.
fn output_schema(geo_json: String) -> Schema {
    let mut meta = HashMap::new();
    meta.insert(String::from("geo"), geo_json);
    Schema::new(vec![
        Field::new("geometry", DataType::Binary, true),
        Field::new("tags", DataType::Utf8, true),
    ])
    .with_metadata(meta)
}

/// Does this tags-JSON string mark a named POI? Cheap substring pre-check, then a
/// real JSON parse only if a candidate key appears (avoids parsing every blob).
fn is_named(tags: &str) -> bool {
    if tags.is_empty() || tags == "{}" {
        return false;
    }
    // Quick reject: if none of the named keys even appear as a substring, skip the
    // parse. (A false positive substring just costs one parse; never wrong.)
    if !NAMED_KEYS.iter().any(|k| tags.contains(k)) {
        return false;
    }
    let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(tags) else {
        return false;
    };
    NAMED_KEYS.iter().any(|k| {
        m.get(*k)
            .map(|v| !matches!(v, serde_json::Value::Null) && !v_is_empty(v))
            .unwrap_or(false)
    })
}

fn v_is_empty(v: &serde_json::Value) -> bool {
    matches!(v, serde_json::Value::String(s) if s.is_empty())
}

/// Does this tags-JSON carry a `building=*` key with a non-empty value? Cheap
/// substring pre-check, then a real parse only if `"building"` appears. This marks
/// the footprints the 3D extruder turns into prisms — kept REGARDLESS of name in
/// [`OptimizeOptions::buildings`] mode (the whole point: keep the city, not just
/// the labelled POIs).
fn is_building(tags: &str) -> bool {
    if tags.is_empty() || !tags.contains("building") {
        return false;
    }
    let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(tags) else {
        return false;
    };
    m.get("building")
        .map(|v| !matches!(v, serde_json::Value::Null) && !v_is_empty(v))
        .unwrap_or(false)
}

/// In **buildings mode**, is this feature worth keeping? A building (kept for the
/// 3D city), a road (`highway`) or water (`waterway` / `natural=water`) — the cheap
/// context that makes a city read — OR an already-named POI (so the demo keeps its
/// labelled points). Everything else (unnamed clutter) is dropped. A cheap
/// substring gate first; the real `building` / `named` checks parse only on a hit.
fn keep_in_buildings_mode(tags: &str, named: bool) -> bool {
    if named || is_building(tags) {
        return true;
    }
    if tags.is_empty() {
        return false;
    }
    // Roads + water are the cheap-to-keep context for a readable city.
    if tags.contains("highway") || tags.contains("waterway") {
        let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(tags)
        else {
            return false;
        };
        let nonempty = |k: &str| {
            m.get(k)
                .map(|v| !matches!(v, serde_json::Value::Null) && !v_is_empty(v))
                .unwrap_or(false)
        };
        if nonempty("highway") || nonempty("waterway") {
            return true;
        }
    }
    if tags.contains("water") {
        let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(tags)
        else {
            return false;
        };
        if m.get("natural").and_then(|v| v.as_str()) == Some("water") {
            return true;
        }
    }
    false
}

/// Slim a tags-JSON object down to [`KEEP_TAG_KEYS`]. Returns `None` if nothing
/// survives (so the writer can store a null tag, shrinking the column further).
fn slim_tags(tags: &str) -> Option<String> {
    if tags.is_empty() || tags == "{}" {
        return None;
    }
    let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(tags) else {
        return None;
    };
    let mut kept = serde_json::Map::new();
    for &k in KEEP_TAG_KEYS {
        if let Some(v) = m.get(k)
            && !matches!(v, serde_json::Value::Null)
            && !v_is_empty(v)
        {
            kept.insert(k.to_string(), v.clone());
        }
    }
    if kept.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(kept).to_string())
    }
}

/// Process one arrow batch (geometry + tags columns) into slimmed [`Feature`]s,
/// applying the named-only filter. This is the per-unit heavy work a worker does.
fn process_batch(batch: &RecordBatch, opts: &OptimizeOptions) -> Vec<Feature> {
    let geom = batch
        .column_by_name("geometry")
        .and_then(|c| c.as_any().downcast_ref::<BinaryArray>());
    let tags = batch
        .column_by_name("tags")
        .and_then(|c| c.as_any().downcast_ref::<StringArray>());
    let Some(geom) = geom else { return Vec::new() };
    let n = geom.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        if geom.is_null(i) {
            continue; // no geometry → nothing to embed (e.g. relations)
        }
        let g = geom.value(i);
        if g.len() < 5 {
            continue; // not a valid WKB header
        }
        let raw_tags = tags
            .filter(|t| !t.is_null(i))
            .map(|t| t.value(i))
            .unwrap_or("");
        let named = is_named(raw_tags);
        // Buildings mode wins over named_only: keep buildings/roads/water + named
        // POIs (drop the rest), and RANK buildings first so the cap keeps the city.
        // The `named` flag carried into ranking becomes "is a building" here.
        let (keep, rank_first) = if opts.buildings {
            let bldg = is_building(raw_tags);
            (keep_in_buildings_mode(raw_tags, named), bldg)
        } else {
            (!opts.named_only || named, named)
        };
        if !keep {
            continue;
        }
        out.push(Feature {
            named: rank_first,
            geometry: g.to_vec(),
            tags: slim_tags(raw_tags),
        });
    }
    out
}

/// Two output streams from the gatling: `named` features and `unnamed` ones,
/// kept apart so the writer can take named-first WITHOUT a 100 M-row global sort
/// (a partition, not a sort). Each is already the slimmed, embed-ready form.
#[derive(Default)]
struct Collected {
    named: Vec<Feature>,
    unnamed: Vec<Feature>,
}

impl Collected {
    fn merge(&mut self, mut other: Collected) {
        self.named.append(&mut other.named);
        self.unnamed.append(&mut other.unnamed);
    }
}

/// Run the gatling fan-out over one source parquet, returning its kept features
/// split into named / unnamed.
///
/// **ROOT LAW #0.** This used to be a hand-rolled `std::thread::scope` pool — one
/// spawned "reader" thread pushing row-group indices down a `sync_channel` and N
/// spawned "workers" self-dispatching off a `Mutex<Receiver>`. That is a rayon
/// replacement wearing a gatling costume: a doc-comment calling it "gatling-shape"
/// does not make it gatling. It is now the real thing —
/// [`gatling::gatling_forkjoin::gatling_for_each_balanced`] over `0..n_row_groups`,
/// LPT-scheduled by each group's **compressed byte size** so a fat group cannot
/// leave the tail on one core (the index-order channel could not do that at all).
///
/// The shape is otherwise unchanged: **N workers each open their OWN projected
/// reader over a single row group**, so the heavy work (zstd-decompress +
/// arrow-decode, then filter / tag-slim / prune) runs on every core with no
/// barrier; nothing decodes on the calling thread. Per-worker results land in
/// disjoint output slots and are merged in row-group order — the same order the
/// old channel produced, so output is unchanged.
fn gatling_collect(
    path: &Path,
    opts: &OptimizeOptions,
    phase: &crate::phase_log::Phase,
) -> anyhow::Result<Collected> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(
        File::open(path).with_context(|| format!("open {path:?}"))?,
    )?;
    let meta = builder.metadata().clone();
    let n_rg = meta.num_row_groups();
    if n_rg == 0 {
        return Ok(Collected::default());
    }
    // Project to ONLY geometry + tags (never decode version/changeset/node_refs/…).
    let has_tags = builder.schema().index_of("tags").is_ok();
    let proj_cols: &[&str] = if has_tags {
        &["geometry", "tags"]
    } else {
        &["geometry"]
    };
    let mask = ProjectionMask::columns(builder.parquet_schema(), proj_cols.iter().copied());

    // LPT weight: the compressed bytes of the row group — the honest proxy for
    // "how long will decoding this cost".
    let weights: Vec<u64> = meta
        .row_groups()
        .iter()
        .map(|rg| rg.compressed_size().max(0) as u64)
        .collect();

    let busy = Arc::clone(&phase.busy_ns);
    let per_group: Vec<anyhow::Result<Collected>> =
        gatling::gatling_forkjoin::gatling_for_each_balanced(
            n_rg,
            0, // all cores
            1, // claim one row group per dispatch (they are coarse already)
            |i| weights[i],
            |rg| -> anyhow::Result<Collected> {
                let t0 = std::time::Instant::now();
                // Open a reader over THIS row group only, reusing the parsed
                // footer (cheap), projected to geometry+tags. The decode here is
                // the per-worker CPU cost that keeps all cores busy.
                let arm = ArrowReaderMetadata::try_new(meta.clone(), ArrowReaderOptions::new())?;
                let rdr = ParquetRecordBatchReaderBuilder::new_with_metadata(
                    File::open(path).with_context(|| format!("open {path:?}"))?,
                    arm,
                )
                .with_row_groups(vec![rg])
                .with_projection(mask.clone())
                .with_batch_size(16_384)
                .build()?;
                let mut local = Collected::default();
                for batch in rdr {
                    for f in process_batch(&batch?, opts) {
                        if f.named {
                            local.named.push(f);
                        } else {
                            local.unnamed.push(f);
                        }
                    }
                }
                busy.fetch_add(
                    t0.elapsed().as_nanos() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                Ok(local)
            },
        );

    let mut all = Collected::default();
    for part in per_group {
        all.merge(part?);
    }
    Ok(all)
}

/// Optimize a GeoParquet directory into a small, embed-ready GeoParquet.
///
/// Reads `nodes.parquet` (always) and — unless `points_only` — `ways.parquet`
/// (if present and `include_ways`). Relations are skipped (their geometry is
/// null, nothing to embed). Applies the named / cap / prune knobs and writes a
/// single zstd GeoParquet to `opts.output`.
pub fn optimize(input_dir: &Path, opts: &OptimizeOptions) -> anyhow::Result<()> {
    let sink = PhaseSink::new(opts.log_path.as_deref())?;

    // Which sources to fold in.
    let mut sources: Vec<PathBuf> = Vec::new();
    let nodes = input_dir.join("nodes.parquet");
    if nodes.exists() {
        sources.push(nodes);
    }
    if !opts.points_only && opts.include_ways {
        let ways = input_dir.join("ways.parquet");
        if ways.exists() {
            sources.push(ways);
        }
    }
    if sources.is_empty() {
        anyhow::bail!("no nodes.parquet (or ways.parquet) found in {input_dir:?}");
    }

    // --- 1 → N → 1: read+process each source through the gatling ---
    // Workers already hand back features split named/unnamed, so there is NO
    // global sort (a 100 M-row sort was the serial tail). Named-first is just a
    // partition: emit named, then top up with unnamed to the cap.
    let mut collected = Collected::default();
    {
        let phase = sink.phase("optimize.process", &[]);
        for src in &sources {
            let part = gatling_collect(src, opts, &phase)?;
            collected.merge(part);
        }
        phase.done(&[
            ("sources", sources.len().to_string()),
            (
                "features_in",
                (collected.named.len() + collected.unnamed.len()).to_string(),
            ),
            ("named", collected.named.len().to_string()),
            (
                "workers",
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
                    .to_string(),
            ),
        ]);
    }

    // --- rank named-first, then cap (a partition + truncate, not a sort) ---
    let features: Vec<Feature> = {
        let phase = sink.phase("optimize.rank", &[]);
        let Collected {
            mut named,
            mut unnamed,
        } = collected;
        let cap = opts.max_features;
        let out: Vec<Feature> = if opts.named_first {
            // Named first; top up with unnamed only if there's cap headroom.
            if cap > 0 {
                named.truncate(cap);
                let room = cap.saturating_sub(named.len());
                unnamed.truncate(room);
            }
            named.append(&mut unnamed);
            named
        } else {
            // No ranking preference: concat, then cap.
            named.append(&mut unnamed);
            if cap > 0 {
                named.truncate(cap);
            }
            named
        };
        phase.done(&[("features_out", out.len().to_string())]);
        out
    };

    // --- 1 WRITER: build ONE arrow batch, write one zstd GeoParquet ---
    let phase = sink.phase("optimize.write", &[]);
    if let Some(parent) = opts.output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let geom_types: &[&str] = if opts.points_only {
        &["Point"]
    } else {
        &["Point", "LineString", "Polygon"]
    };
    let geo_json = metadata::geo_metadata(geom_types, None);
    let schema = Arc::new(output_schema(geo_json));

    let mut geo_b = BinaryBuilder::new();
    let mut tag_b = StringBuilder::new();
    for f in &features {
        geo_b.append_value(&f.geometry);
        match &f.tags {
            Some(t) => tag_b.append_value(t),
            None => tag_b.append_null(),
        }
    }
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(geo_b.finish()), Arc::new(tag_b.finish())],
    )?;

    let props = WriterProperties::builder()
        .set_compression(compression(&opts.compression))
        .build();
    let mut w = ArrowWriter::try_new(
        File::create(&opts.output).with_context(|| format!("create {:?}", opts.output))?,
        schema,
        Some(props),
    )?;
    w.write(&batch)?;
    w.close()?;

    let out_bytes = std::fs::metadata(&opts.output)
        .map(|m| m.len())
        .unwrap_or(0);
    phase.done(&[
        ("rows", features.len().to_string()),
        ("out_bytes", out_bytes.to_string()),
    ]);

    eprintln!(
        "optimize: wrote {:?} — {} features, {} KB ({})",
        opts.output,
        features.len(),
        out_bytes / 1024,
        opts.compression,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    fn wkb_point(lon: f64, lat: f64) -> Vec<u8> {
        let mut b = vec![1u8]; // little-endian
        b.extend_from_slice(&1u32.to_le_bytes()); // Point
        b.extend_from_slice(&lon.to_le_bytes());
        b.extend_from_slice(&lat.to_le_bytes());
        b
    }

    /// Write a `nodes.parquet`-shaped source (id, geometry WKB, tags JSON, version)
    /// into `dir`. `n_named` of the `n` rows get a `name` tag; many small row groups
    /// so the gatling reorders/​fans across workers.
    fn write_nodes_source(dir: &Path, n: usize, n_named: usize) -> anyhow::Result<PathBuf> {
        use arrow::array::{BinaryBuilder, Int32Builder, Int64Builder, StringBuilder};
        use parquet::basic::Compression;
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("geometry", DataType::Binary, true),
            Field::new("tags", DataType::Utf8, true),
            Field::new("version", DataType::Int32, true),
        ]));
        let mut id = Int64Builder::new();
        let mut geo = BinaryBuilder::new();
        let mut tag = StringBuilder::new();
        let mut ver = Int32Builder::new();
        for i in 0..n {
            id.append_value(i as i64);
            geo.append_value(&wkb_point(i as f64 * 0.001, 59.0 + i as f64 * 0.0001));
            if i < n_named {
                tag.append_value(&format!(
                    "{{\"name\":\"poi{i}\",\"amenity\":\"cafe\",\"opening_hours\":\"24/7\"}}"
                ));
            } else {
                tag.append_value("{\"created_by\":\"JOSM\"}");
            }
            ver.append_value(1);
        }
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id.finish()),
                Arc::new(geo.finish()),
                Arc::new(tag.finish()),
                Arc::new(ver.finish()),
            ],
        )?;
        let path = dir.join("nodes.parquet");
        let props = WriterProperties::builder()
            .set_max_row_group_row_count(Some(64)) // many row groups
            .set_compression(Compression::ZSTD(Default::default()))
            .build();
        let mut w = ArrowWriter::try_new(File::create(&path)?, schema, Some(props))?;
        w.write(&batch)?;
        w.close()?;
        Ok(path)
    }

    fn read_out(path: &Path) -> anyhow::Result<Vec<(Vec<u8>, Option<String>)>> {
        let rdr = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?.build()?;
        let mut out = Vec::new();
        for batch in rdr {
            let b = batch?;
            let g = b
                .column_by_name("geometry")
                .unwrap()
                .as_any()
                .downcast_ref::<BinaryArray>()
                .unwrap();
            let t = b
                .column_by_name("tags")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..b.num_rows() {
                let tag = if t.is_null(i) {
                    None
                } else {
                    Some(t.value(i).to_string())
                };
                out.push((g.value(i).to_vec(), tag));
            }
        }
        Ok(out)
    }

    #[test]
    fn optimize_caps_named_first_and_prunes_tags() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        // 1000 features, 100 named.
        write_nodes_source(dir.path(), 1000, 100)?;
        let out = dir.path().join("opt.parquet");
        let opts = OptimizeOptions {
            output: out.clone(),
            points_only: true,
            named_first: true,
            max_features: 150,
            ..Default::default()
        };
        optimize(dir.path(), &opts)?;

        let rows = read_out(&out)?;
        // Capped at 150.
        assert_eq!(rows.len(), 150, "cap not applied");
        // Named-first: the first 100 must all carry a name tag; cap pulls 100
        // named + 50 unnamed.
        let named_in_first_100 = rows[..100]
            .iter()
            .filter(|(_, t)| {
                t.as_deref()
                    .map(|s| s.contains("\"name\""))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(named_in_first_100, 100, "named features not ranked first");
        // Tag pruning: the dropped `opening_hours` / `created_by` must be gone.
        for (_, t) in &rows {
            if let Some(s) = t {
                assert!(!s.contains("opening_hours"), "opening_hours not pruned");
                assert!(!s.contains("created_by"), "created_by not pruned");
            }
        }
        // WKB still valid (5-byte header, type 1 = Point).
        for (g, _) in &rows {
            assert!(g.len() >= 21, "Point WKB too short");
            assert_eq!(g[0], 1, "WKB not little-endian Point");
        }
        Ok(())
    }

    #[test]
    fn optimize_named_only_drops_unnamed() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        write_nodes_source(dir.path(), 500, 40)?;
        let out = dir.path().join("named.parquet");
        let opts = OptimizeOptions {
            output: out.clone(),
            points_only: true,
            named_only: true,
            ..Default::default()
        };
        optimize(dir.path(), &opts)?;
        let rows = read_out(&out)?;
        assert_eq!(
            rows.len(),
            40,
            "named_only should keep exactly the named ones"
        );
        for (_, t) in &rows {
            assert!(
                t.as_deref()
                    .map(|s| s.contains("\"name\""))
                    .unwrap_or(false),
                "named_only kept an unnamed feature"
            );
        }
        Ok(())
    }

    #[test]
    fn optimize_output_is_smaller_and_facett_readable() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let src = write_nodes_source(dir.path(), 5000, 500)?;
        let src_bytes = std::fs::metadata(&src)?.len();
        let out = dir.path().join("opt.parquet");
        let opts = OptimizeOptions {
            output: out.clone(),
            points_only: true,
            max_features: 1000,
            ..Default::default()
        };
        optimize(dir.path(), &opts)?;
        let out_bytes = std::fs::metadata(&out)?.len();
        assert!(
            out_bytes < src_bytes,
            "output {out_bytes} not smaller than input {src_bytes}"
        );
        // facett-osm read_points contract: a Binary `geometry` WKB column decodes.
        let rows = read_out(&out)?;
        assert_eq!(rows.len(), 1000);
        Ok(())
    }

    /// Write a `ways.parquet`-shaped source whose rows are a mix of: unnamed
    /// buildings (with `height` / `building:levels`), a named POI building, roads,
    /// water, and pure unnamed clutter. Geometry is a Point WKB (the optimize path
    /// only cares the blob is a valid WKB ≥5 bytes), tags is the JSON object.
    fn write_tagged_source(dir: &Path, rows: &[&str]) -> anyhow::Result<PathBuf> {
        use arrow::array::{BinaryBuilder, StringBuilder};
        use parquet::basic::Compression;
        let schema = Arc::new(Schema::new(vec![
            Field::new("geometry", DataType::Binary, true),
            Field::new("tags", DataType::Utf8, true),
        ]));
        let mut geo = BinaryBuilder::new();
        let mut tag = StringBuilder::new();
        for (i, t) in rows.iter().enumerate() {
            geo.append_value(&wkb_point(i as f64 * 0.001, 59.0 + i as f64 * 0.0001));
            tag.append_value(t);
        }
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(geo.finish()), Arc::new(tag.finish())],
        )?;
        let path = dir.join("ways.parquet");
        let props = WriterProperties::builder()
            .set_max_row_group_row_count(Some(4))
            .set_compression(Compression::ZSTD(Default::default()))
            .build();
        let mut w = ArrowWriter::try_new(File::create(&path)?, schema, Some(props))?;
        w.write(&batch)?;
        w.close()?;
        Ok(path)
    }

    /// INJECT-ASSERT (the whole point of `--buildings`): unnamed buildings are
    /// KEPT (the default named-first path would drop them), their `height` /
    /// `building:levels` tags survive the slim, roads + water are kept, and pure
    /// unnamed clutter is dropped.
    #[test]
    fn buildings_mode_keeps_unnamed_buildings_with_height() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        write_tagged_source(
            dir.path(),
            &[
                r#"{"building":"yes","height":"12"}"#, // unnamed building + height
                r#"{"building":"house","building:levels":"3"}"#, // unnamed building + levels
                r#"{"building":"yes","name":"Town Hall","height":"30"}"#, // named building
                r#"{"highway":"residential"}"#,        // road (kept, cheap)
                r#"{"natural":"water"}"#,              // water (kept, cheap)
                r#"{"created_by":"JOSM"}"#,            // unnamed clutter → DROP
                r#"{"surface":"asphalt"}"#,            // unnamed clutter → DROP
            ],
        )?;
        // Optimize as the embed pipeline would: ways folded in, buildings mode.
        let out = dir.path().join("b.parquet");
        let opts = OptimizeOptions {
            output: out.clone(),
            points_only: false,
            include_ways: true,
            buildings: true,
            ..Default::default()
        };
        // The source has no nodes.parquet; optimize reads ways.parquet too. But it
        // requires at least one of nodes/ways — ways exists, so it runs.
        optimize(dir.path(), &opts)?;
        let rows = read_out(&out)?;

        // 3 buildings + 1 road + 1 water kept; the 2 clutter rows dropped.
        assert_eq!(
            rows.len(),
            5,
            "buildings + road + water kept, clutter dropped"
        );
        // The two height tags survived the slim.
        let all: String = rows
            .iter()
            .filter_map(|(_, t)| t.clone())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            all.contains("\"height\""),
            "the building height tag survived"
        );
        assert!(
            all.contains("\"building:levels\""),
            "building:levels survived"
        );
        // Both unnamed buildings are present (the default path would have dropped them).
        let buildings = rows
            .iter()
            .filter(|(_, t)| {
                t.as_deref()
                    .map(|s| s.contains("\"building\""))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            buildings, 3,
            "all three building footprints kept (named + unnamed)"
        );
        // No clutter leaked through.
        for (_, t) in &rows {
            if let Some(s) = t {
                assert!(!s.contains("created_by"), "clutter pruned");
                assert!(!s.contains("surface"), "non-whitelisted clutter pruned");
            }
        }
        Ok(())
    }

    /// Buildings rank FIRST under `--max-features`: with a tight cap the buildings
    /// survive and the cheaper road/water context is what gets truncated.
    #[test]
    fn buildings_mode_ranks_buildings_first_under_cap() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        write_tagged_source(
            dir.path(),
            &[
                r#"{"highway":"residential"}"#,
                r#"{"natural":"water"}"#,
                r#"{"building":"yes","height":"12"}"#,
                r#"{"building":"house"}"#,
                r#"{"highway":"service"}"#,
            ],
        )?;
        let out = dir.path().join("bcap.parquet");
        let opts = OptimizeOptions {
            output: out.clone(),
            buildings: true,
            named_first: true,
            max_features: 2,
            ..Default::default()
        };
        optimize(dir.path(), &opts)?;
        let rows = read_out(&out)?;
        assert_eq!(rows.len(), 2, "capped at 2");
        // Both kept rows are buildings (ranked first ahead of the roads/water).
        for (_, t) in &rows {
            assert!(
                t.as_deref()
                    .map(|s| s.contains("\"building\""))
                    .unwrap_or(false),
                "the cap kept the buildings first, got {t:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn is_building_detects_building_tag() {
        assert!(is_building(r#"{"building":"yes"}"#));
        assert!(is_building(r#"{"building":"house","height":"9"}"#));
        assert!(!is_building(r#"{"highway":"primary"}"#));
        assert!(!is_building(r#"{"building":""}"#));
        assert!(!is_building("{}"));
        assert!(!is_building(""));
        // height + building:levels survive the slim.
        let s =
            slim_tags(r#"{"building":"yes","height":"12.5","building:levels":"4","foo":"bar"}"#)
                .unwrap();
        assert!(s.contains("\"height\"") && s.contains("\"building:levels\""));
        assert!(!s.contains("foo"));
    }

    #[test]
    fn is_named_and_slim_tags() {
        assert!(is_named("{\"name\":\"Sigtuna\"}"));
        assert!(is_named("{\"amenity\":\"cafe\"}"));
        assert!(!is_named("{\"created_by\":\"JOSM\"}"));
        assert!(!is_named("{}"));
        assert!(!is_named(""));
        // empty name value does not qualify
        assert!(!is_named("{\"name\":\"\"}"));

        assert_eq!(slim_tags("{}"), None);
        assert_eq!(slim_tags("{\"created_by\":\"x\"}"), None);
        let s = slim_tags("{\"name\":\"A\",\"created_by\":\"x\",\"highway\":\"primary\"}").unwrap();
        assert!(s.contains("\"name\""));
        assert!(s.contains("\"highway\""));
        assert!(!s.contains("created_by"));
    }
}
