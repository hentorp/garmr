use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "osm-katana", about = "Fast OSM format converter")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Convert OSM (XML / BZ2 / GZ / PBF) → GeoParquet
    Convert {
        input: PathBuf,
        #[arg(short, long, default_value = "out")]
        output: PathBuf,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        nodes: bool,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        ways: bool,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        relations: bool,
        #[arg(long, default_value = "zstd")]
        compression: String,
        #[arg(long, default_value_t = 0)]
        vtd_workers: usize,
        /// resolved (2-pass, ways → WKB) | raw (1-pass, keep node-ID list)
        #[arg(long, default_value = "resolved")]
        geometry: String,
        #[arg(long, default_value_t = false)]
        skip_changesets: bool,
        #[arg(long)]
        log: Option<PathBuf>,
        /// Region clip: a preset (europe|nordics) or a raw bbox
        /// min_lon,min_lat,max_lon,max_lat. Nodes outside are dropped at decode
        /// (during the parallel convert — zero extra pass). Mutually exclusive
        /// with --poly. Requires the default 'resolved' geometry.
        #[arg(long, conflicts_with = "poly")]
        clip: Option<String>,
        /// Region clip from a polygon file: Osmosis `.poly` or GeoJSON
        /// (Polygon/MultiPolygon). Clips to the region's REAL shape via a
        /// per-node ray-cast inside the workers (bbox pre-filtered). Mutually
        /// exclusive with --clip.
        #[arg(long)]
        poly: Option<PathBuf>,
        /// Keep the `node_coords.arrow` intermediate after the convert finishes.
        ///
        /// It is the mmap-backed node store pass 2 resolves way geometry through,
        /// so it is always WRITTEN; this only controls whether it is kept. It is
        /// large — 75 MB for Stockholm, **1.68 GB for Sweden** — and buys nothing
        /// for a shipped GeoParquet pack. `--keep-node-coords false` deletes it
        /// (and any `_nc_chunk_*.bin` spill files) once the parquet is closed.
        /// Defaults to `true`, so existing behaviour is unchanged.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        keep_node_coords: bool,
    },

    /// **Spatially pack** a GeoParquet dir/file: sort rows on a Hilbert curve
    /// over their geometry and add a GeoParquet 1.1 `covering.bbox` column, so a
    /// reader can prune whole row groups by min/max statistics and fetch only the
    /// byte ranges its viewport touches. Content-preserving — same rows, same
    /// values, new order (`verify --digest` `set` is unchanged).
    SpatialPack {
        /// Input GeoParquet directory (nodes/ways/relations.parquet) or a single file.
        input: PathBuf,
        /// Output directory (or file, if `input` is a file).
        #[arg(short, long, default_value = "packed")]
        output: PathBuf,
        /// Rows per row group. Smaller ⇒ finer pruning, more footer bytes.
        /// Default measured on Stockholm — see `spatial::PackOptions`.
        #[arg(long, default_value_t = 8_192)]
        row_group_rows: usize,
        /// Emit the `covering.bbox` column. `false` = Hilbert ordering only
        /// (schema unchanged) — useful to isolate ordering from covering.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        covering: bool,
        #[arg(long, default_value = "zstd")]
        compression: String,
    },

    /// Convert OSM XML (or .osm.bz2) → zstd-compressed PBF
    Xml2Pbf {
        input: PathBuf,
        output: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        skip_changesets: bool,
    },

    /// Convert OSM PBF → GeoParquet
    Pbf2Geo {
        input: PathBuf,
        #[arg(short, long, default_value = "out")]
        output: PathBuf,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        nodes: bool,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        ways: bool,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        relations: bool,
        #[arg(long, default_value = "zstd")]
        compression: String,
    },

    /// Convert GeoParquet → Arrow IPC
    Geo2Arrow { input: PathBuf, output: PathBuf },

    /// Shrink a GeoParquet dir into a small, embed-ready GeoParquet (for a wasm
    /// demo's `include_bytes!`). Trims to geometry + a slimmed tag set, keeps
    /// named POIs first, caps the feature count, and zstd-compresses — the
    /// gatling (1 reader → N workers → 1 writer) way.
    Optimize {
        /// Input GeoParquet directory (with nodes.parquet / ways.parquet).
        input: PathBuf,
        /// Output GeoParquet FILE.
        #[arg(short, long, default_value = "optimized.parquet")]
        output: PathBuf,
        /// Keep only node points (read nodes.parquet, skip ways/relations).
        #[arg(long, default_value_t = false)]
        points_only: bool,
        /// Fold ways.parquet in too (ignored with --points-only). Default on.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        ways: bool,
        /// Rank named (name/place/POI-tagged) features first under --max-features.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        named_first: bool,
        /// Keep ONLY named features (drops everything without a name/place/POI tag).
        #[arg(long, default_value_t = false)]
        named_only: bool,
        /// **Buildings mode** — keep every `building=*` way (regardless of name) +
        /// the roads/water ways, preserving `height` / `building:levels` so the
        /// 3D map viewer can extrude real city footprints. Named POIs are kept too;
        /// unnamed clutter is dropped. Buildings are ranked first under
        /// `--max-features`. Overrides `--named-only`.
        #[arg(long, default_value_t = false)]
        buildings: bool,
        /// Cap total output features (0 = unlimited), named-first if --named-first.
        #[arg(long, default_value_t = 0)]
        max_features: usize,
        /// Parquet compression: zstd (default) | snappy | none.
        #[arg(long, default_value = "zstd")]
        compression: String,
        /// Optional phase-log JSONL path (cores-busy is always echoed to stderr).
        #[arg(long)]
        log: Option<PathBuf>,
    },

    /// Inspect / verify GeoParquet output directory
    Verify {
        #[arg(default_value = "out")]
        dir: PathBuf,
        /// Also print a layout-invariant CONTENT digest per table (`table rows
        /// digest`). Two converts of the same input agree here iff they produced
        /// the same rows in the same order — the equivalence gate a raw file
        /// checksum cannot give, because row-GROUP boundaries move run-to-run
        /// (the writer encodes groups on the gatling workers). Use it to prove a
        /// perf change did not alter output.
        #[arg(long)]
        digest: bool,
    },

    /// Build an inverted text/tag search index over a GeoParquet dir (or a single
    /// optimized `.parquet`) and save it as JSON. With `--query`, also run the
    /// query and print the top hits (id, name, lon/lat). The gatling way
    /// (one LPT-scheduled unit per row group, results in row-group order, so the
    /// index is reproducible). Feature-gated: `--features search-index`.
    #[cfg(feature = "search-index")]
    Search {
        /// Input GeoParquet dir (nodes.parquet / ways.parquet) or a single .parquet.
        input: PathBuf,
        /// Output index FILE (JSON).
        #[arg(short, long, default_value = "search.idx.json")]
        output: PathBuf,
        /// Optional query to run after building; prints the top matching hits.
        #[arg(short, long)]
        query: Option<String>,
        /// Max hits to print for `--query`.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

/// Resolve `--clip`/`--poly` into an optional shared [`osm_katana::Clip`].
/// `--clip` is a bbox/preset; `--poly` loads a `.poly` / GeoJSON polygon. The two
/// are mutually exclusive (enforced by clap); at most one is `Some`.
fn parse_clip(
    clip: Option<&str>,
    poly: Option<&std::path::Path>,
) -> anyhow::Result<Option<std::sync::Arc<osm_katana::Clip>>> {
    use osm_katana::{Bounds, Clip, Polygon};
    if let Some(path) = poly {
        let p = Polygon::from_file(path)?;
        eprintln!(
            "clip: polygon {path:?} — {} ring(s), {} vertices, bbox {:?}",
            p.ring_count(),
            p.vertex_count(),
            p.bbox(),
        );
        return Ok(Some(std::sync::Arc::new(Clip::Poly(p))));
    }
    if let Some(s) = clip {
        let b = Bounds::parse(s)?;
        eprintln!("clip: bbox {b:?}");
        return Ok(Some(std::sync::Arc::new(Clip::Bbox(b))));
    }
    Ok(None)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Introspection: name the CLI verb before it's consumed by the dispatch match.
    let verb = match &cli.cmd {
        Cmd::Convert { .. } => "convert",
        Cmd::SpatialPack { .. } => "spatial-pack",
        Cmd::Xml2Pbf { .. } => "xml2pbf",
        Cmd::Pbf2Geo { .. } => "pbf2geo",
        Cmd::Geo2Arrow { .. } => "geo2arrow",
        Cmd::Optimize { .. } => "optimize",
        Cmd::Verify { .. } => "verify",
        #[cfg(feature = "search-index")]
        Cmd::Search { .. } => "search",
    };
    let result: anyhow::Result<()> = match cli.cmd {
        Cmd::Convert {
            input,
            output,
            nodes,
            ways,
            relations,
            compression,
            vtd_workers,
            geometry,
            skip_changesets,
            log,
            clip,
            poly,
            keep_node_coords,
        } => {
            let clip = parse_clip(clip.as_deref(), poly.as_deref())?;
            let opts = osm_katana::ConvertOptions {
                output_dir: output,
                include_nodes: nodes,
                include_ways: ways,
                include_rels: relations,
                compression,
                vtd_workers,
                geometry,
                skip_changesets,
                log_path: log,
                clip,
                keep_node_coords,
            };
            osm_katana::convert(&input, &opts)
        }

        Cmd::SpatialPack {
            input,
            output,
            row_group_rows,
            covering,
            compression,
        } => {
            use osm_katana::spatial::{PackOptions, spatial_pack, spatial_pack_dir};
            let opts = PackOptions {
                compression,
                row_group_rows,
                covering,
            };
            let report = if input.is_dir() {
                spatial_pack_dir(&input, &output, &opts)?
            } else {
                let st = spatial_pack(&input, &output, &opts)?;
                vec![(input.display().to_string(), st)]
            };
            for (name, s) in &report {
                println!(
                    "{name:>20}: {:>9} rows  {:>5} row groups  {:>12} bytes{}",
                    s.rows,
                    s.row_groups,
                    s.bytes,
                    if s.rows_no_geometry > 0 {
                        format!("  ({} without geometry, sorted last)", s.rows_no_geometry)
                    } else {
                        String::new()
                    },
                );
            }
            Ok(())
        }

        Cmd::Xml2Pbf {
            input,
            output,
            skip_changesets,
        } => {
            use std::time::Instant;
            let is_bz2 = input
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("bz2"));
            let n = std::thread::available_parallelism()
                .map(|n| n.get().saturating_sub(1).max(1))
                .unwrap_or(1);
            let file_mb = std::fs::metadata(&input)
                .map(|m| m.len() / 1_048_576)
                .unwrap_or(0);
            if is_bz2 {
                let pbf = output.unwrap_or_else(|| {
                    let stem = PathBuf::from(input.file_stem().unwrap_or_default());
                    let inner = stem.file_stem().unwrap_or_default();
                    input.with_file_name(format!("{}.osm.pbf", inner.to_string_lossy()))
                });
                println!(
                    "input: {} ({file_mb} MB bz2)  output: {}  workers: {n}",
                    input.display(),
                    pbf.display()
                );
                let t = Instant::now();
                let (total, _) =
                    osm_katana::xml_to_pbf::xml_to_pbf_bz2_path(&input, &pbf, n, skip_changesets)?;
                let pbf_mb = std::fs::metadata(&pbf)
                    .map(|m| m.len() / 1_048_576)
                    .unwrap_or(0);
                println!(
                    "done: {:.1}s  {total} elements  {pbf_mb} MB PBF",
                    t.elapsed().as_secs_f64()
                );
            } else {
                let pbf = output.unwrap_or_else(|| input.with_extension("osm.pbf"));
                println!(
                    "input: {} ({file_mb} MB xml)  output: {}  workers: {n}",
                    input.display(),
                    pbf.display()
                );
                let t = Instant::now();
                let (total, _) = osm_katana::xml_to_pbf::xml_to_pbf_raw_path(&input, &pbf, n)?;
                let pbf_mb = std::fs::metadata(&pbf)
                    .map(|m| m.len() / 1_048_576)
                    .unwrap_or(0);
                println!(
                    "done: {:.1}s  {total} elements  {pbf_mb} MB PBF",
                    t.elapsed().as_secs_f64()
                );
            }
            Ok(())
        }

        Cmd::Pbf2Geo {
            input,
            output,
            nodes,
            ways,
            relations,
            compression,
        } => {
            let opts = osm_katana::ConvertOptions {
                output_dir: output,
                include_nodes: nodes,
                include_ways: ways,
                include_rels: relations,
                compression,
                vtd_workers: 0,
                geometry: "resolved".into(),
                skip_changesets: false,
                log_path: None,
                clip: None,
                keep_node_coords: true,
            };
            osm_katana::convert(&input, &opts)
        }

        Cmd::Geo2Arrow { input, output } => osm_katana::geo2arrow(&input, &output),

        Cmd::Optimize {
            input,
            output,
            points_only,
            ways,
            named_first,
            named_only,
            buildings,
            max_features,
            compression,
            log,
        } => {
            let opts = osm_katana::OptimizeOptions {
                output,
                points_only,
                include_ways: ways,
                named_first,
                named_only,
                buildings,
                max_features,
                compression,
                log_path: log,
            };
            osm_katana::optimize(&input, &opts)
        }

        Cmd::Verify { dir, digest } => {
            for name in ["nodes.parquet", "ways.parquet", "relations.parquet"] {
                let path = dir.join(name);
                if !path.exists() {
                    println!("{name:>20}: (absent)");
                    continue;
                }
                let v = osm_katana::verify::verify(&path)?;
                print!("{name:>20}: {:>9} rows", v.rows);
                if v.has_geom {
                    print!("  | geometry: {} set, {} null", v.geom_set, v.geom_null);
                }
                if v.has_refs {
                    print!(
                        "  | node_refs: {} non-empty, {} ids",
                        v.refs_nonempty, v.refs_total
                    );
                }
                println!();
            }
            if digest {
                println!(
                    "content digest (layout-invariant). `set` = order-independent multiset \
                     digest — THE equivalence gate; `ord` also pins row order:"
                );
                for (name, d) in osm_katana::digest::digest_dir(&dir)? {
                    match d {
                        Some(d) => println!(
                            "{name:>20}: {:>9} rows  set {}  ord {}",
                            d.rows,
                            d.set_hex(),
                            d.hex()
                        ),
                        None => println!("{name:>20}: (absent)"),
                    }
                }
            }
            Ok(())
        }

        #[cfg(feature = "search-index")]
        Cmd::Search {
            input,
            output,
            query,
            limit,
        } => {
            use osm_katana::side_outputs::search::SearchIndex;
            let idx = SearchIndex::build(&input)?;
            idx.save(&output)?;
            println!(
                "search: indexed {} features, {} tokens → {}",
                idx.len(),
                idx.token_count(),
                output.display(),
            );
            if let Some(q) = query {
                let hits = idx.search_limit(&q, limit);
                println!("query {q:?}: {} hit(s)", hits.len());
                for h in hits {
                    println!(
                        "  #{:<8} {:<40} {:.5},{:.5}",
                        h.id,
                        h.name.as_deref().unwrap_or("(unnamed)"),
                        h.lon,
                        h.lat,
                    );
                }
            }
            Ok(())
        }
    };
    // Introspection marker: report the CLI verb's terminal health to the matrix.
    osm_katana::functional_status(
        "osm-katana",
        verb,
        result.is_ok(),
        if result.is_ok() {
            "cli command completed"
        } else {
            "cli command failed"
        },
    );
    result
}
