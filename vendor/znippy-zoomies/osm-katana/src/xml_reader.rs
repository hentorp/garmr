//! Two-pass XML reader via VTD index (xml_vtd).
//!
//! Pass 1 — parallel mmap scan, streamed to disk:
//!   `build_elem_index_to_mmap` writes ElemIndex entries directly to a
//!   mmap'd `.elem.idx` file — no Vec accumulation in RAM.
//!   Sweden: 320 MB index stays warm in page cache.
//!   Planet: 64 GB index streams through without touching heap.
//!   Node records are then extracted in a second sequential pass over the index.
//!
//! Pass 2 — VTD-guided parallel parse:
//!   ElemIndex filtered to ways+relations. `plan_chunks` groups entries into
//!   ~4 MB batches with exact byte boundaries. Rayon distributes chunks across
//!   all cores. Each worker parses its batch using the pre-known byte offsets —
//!   no boundary scanning, no partial elements.

#![allow(
    clippy::float_arithmetic,
    clippy::arithmetic_side_effects,
    reason = "e7 ↔ degree conversions and index arithmetic are intentional"
)]
#![allow(
    unsafe_code,
    reason = "find_ways_rels_offset mmaps the input read-only — safety documented at the call site"
)]

use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::Result;
use memchr::memchr;
use znippy_zoomies::gatling;

use crate::shared::gpu_backend::GpuBackend;

use crate::{
    geometry,
    node_store::{CoordFileWriter, NodeStore},
    reader::{CollectedWay, MemberEntry, NodeRecord, RelationRecord, WayRecord},
    tags,
    writer::{self, NodeWriter, RelWriter, WayWriter},
    xml_vtd::{self, ElemIndex, ElemKind},
};

// ~4 MB of element bytes per Rayon chunk (ways avg ~1 KB → ~4 000 ways/chunk)
const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;

// ── Gatling typed pipeline for raw .osm → Parquet ────────────────────────────

/// Chunk/carry sizes for raw XML streaming through Gatling.
const RAW_XML_CHUNK_SIZE: usize = 200 * 1024 * 1024; // 200 MB per read
const RAW_XML_CARRY_HEADROOM: usize = 32 * 1024 * 1024; // 32 MB (largest element)
const RAW_XML_RING_SLOTS: usize = 6;

/// Like `find_top_level_start` but also matches `<changeset` and `<bound`.
/// Needed because the planet file starts with ~72 GB of changesets before any nodes.
fn find_any_top_level_start(bytes: &[u8], from: usize) -> usize {
    let mut pos = from;
    while pos < bytes.len() {
        let Some(rel) = memchr::memchr(b'<', &bytes[pos..]) else {
            break;
        };
        let lt = pos + rel;
        let rest = bytes.get(lt + 1..).unwrap_or_default();
        if rest.starts_with(b"node ")
            || rest.starts_with(b"node\t")
            || rest.starts_with(b"way ")
            || rest.starts_with(b"way\t")
            || rest.starts_with(b"relation ")
            || rest.starts_with(b"relation\t")
            || rest.starts_with(b"changeset ")
            || rest.starts_with(b"changeset\t")
            || rest.starts_with(b"bound ")
            || rest.starts_with(b"bound\t")
        {
            return lt;
        }
        pos = lt + 1;
    }
    bytes.len()
}

/// Byte offset of the first top-level `<way>`/`<relation>` element in an
/// uncompressed `.osm` file. OSM XML is ordered `bounds < nodes < ways <
/// relations`, so resolved pass 2 can start the reader here and never re-parse
/// the (node-heavy) node section. On a node-heavy planet the first `<way>` sits
/// ~80% into the file, so a single-threaded `memmem` scan reads ~80 GB on one
/// core — a serial trough that dragged the whole convert's core average down.
/// This scans the mmap in parallel (one gatling unit per file slice, global
/// minimum of the per-slice hits), all cores busy. Returns `0` when no
/// way/relation exists (pass 2 is then trivially empty but still correct) or on
/// any mmap error (safe fallback: parse all).
fn find_ways_rels_offset(path: &str) -> u64 {
    use memchr::memmem;
    let Ok(file) = std::fs::File::open(path) else {
        return 0;
    };
    let Ok(mmap) = (unsafe { memmap2::Mmap::map(&file) }) else {
        return 0;
    };
    let bytes: &[u8] = &mmap;
    let n = bytes.len();
    if n == 0 {
        return 0;
    }

    // `<way`/`<relation` prefixes cover every delimiter form (`<way `, `<way>`,
    // `<way\n`, …) since OSM has no other tag starting with these — one scan each
    // instead of five per tag. MAX_NEEDLE bytes of inter-slice overlap so a
    // needle straddling a boundary is still found by the earlier slice.
    const NEEDLES: [&[u8]; 2] = [b"<way", b"<relation"];
    const MAX_NEEDLE: usize = 9; // len("<relation")

    let n_workers = std::thread::available_parallelism().map_or(4, |w| w.get());
    let units = (n_workers * 8).clamp(1, n);
    let chunk = n.div_ceil(units);

    let hits = crate::par::par_map(units, |i| {
        let start = i * chunk;
        if start >= n {
            return usize::MAX;
        }
        let end = ((i + 1) * chunk + MAX_NEEDLE - 1).min(n);
        let win = &bytes[start..end];
        NEEDLES
            .iter()
            .filter_map(|nd| memmem::find(win, nd))
            .map(|off| start + off)
            .min()
            .unwrap_or(usize::MAX)
    });
    hits.into_iter()
        .min()
        .filter(|&m| m != usize::MAX)
        .map_or(0, |m| m as u64)
}

/// Split `data` into N worker segments at XML element boundaries.
/// Shared by all typed codecs in this module (and the typed PBF path).
pub(crate) fn xml_split_typed(
    data: &[u8],
    n_workers: usize,
    is_last: bool,
) -> Option<gatling::Split<(usize, usize)>> {
    let consumed = if is_last {
        data.len()
    } else {
        xml_vtd::find_safe_slot_end(data)
    };
    if consumed == 0 {
        return None;
    }
    // Oversubscribe: cut each slot into ~SPLIT× more segments than workers so the
    // engine self-dispatches (a worker that drains its unit steals the next) —
    // uneven node density can't strand a core, and finer units keep the reader→
    // worker→collector pipeline full. Row-group size is unaffected: the per-worker
    // NODE_ACC thread-local coalesces across a worker's segments into full groups.
    // (Same trick the VTD pipelined reader uses; see vtd.rs SPLIT.)
    const SPLIT: usize = 8;
    let n = n_workers.max(1) * SPLIT;
    let chunk_size = (consumed / n).max(1);
    let mut borders: Vec<usize> = Vec::with_capacity(n + 1);
    for i in 0..n {
        borders.push(find_any_top_level_start(data, i * chunk_size));
    }
    borders.push(consumed);
    let segments: Vec<(usize, usize)> = (0..n)
        .filter_map(|i| {
            let s = borders[i];
            let e = borders[i + 1];
            if s < e { Some((s, e)) } else { None }
        })
        .collect();
    if segments.is_empty() {
        return None;
    }
    Some(gatling::Split { segments, consumed })
}

/// TypedCodec for raw XML: split at element boundaries, workers VTD-parse → records.
///
/// PRIOR SERIAL FALLBACK (superseded 2026-07-14 by [`RawXmlParallelCodec`] +
/// [`RawParallelParquetSink`], which encode row groups on the workers). Retained
/// per the additive/no-regression law as the reference serial encoder; not on the
/// live `read_raw` path.
#[allow(dead_code)]
struct RawXmlTypedCodec {
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
}

#[allow(dead_code)] // consumed only by the retained serial `RawXmlTypedCodec` fallback
type RawRecords = (Vec<NodeRecord>, Vec<WayRecord>, Vec<RelationRecord>);

impl gatling::TypedCodec for RawXmlTypedCodec {
    type Seg = (usize, usize);
    type Output = RawRecords;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<Self::Seg>> {
        xml_split_typed(data, n_workers, is_last)
    }

    fn transform(&self, data: &[u8], seg: &Self::Seg) -> Self::Output {
        let sub = &data[seg.0..seg.1];
        let base = seg.0;
        let mut nodes: Vec<NodeRecord> = Vec::new();
        let mut ways: Vec<WayRecord> = Vec::new();
        let mut rels: Vec<RelationRecord> = Vec::new();

        xml_vtd::build_elem_index_slice(sub, base, &mut |e| {
            let lo = (e.file_offset as usize).saturating_sub(base);
            let hi = lo.saturating_add(e.file_length as usize).min(sub.len());
            let b = sub.get(lo..hi).unwrap_or_default();
            match e.kind {
                ElemKind::Node if self.include_nodes => {
                    let lat = e.lat_e7 as f32 / 1e7_f32;
                    let lon = e.lon_e7 as f32 / 1e7_f32;
                    nodes.push(NodeRecord {
                        id: e.id,
                        lon_lat: (f64::from(lon), f64::from(lat)),
                        tags_json: parse_tags_json(b),
                        version: parse_attr_i32(opening_tag(b), b"version"),
                    });
                }
                ElemKind::Way if self.include_ways => ways.push(parse_way_raw(&e, b)),
                ElemKind::Relation if self.include_rels => rels.push(parse_relation(&e, b)),
                _ => {}
            }
        });
        (nodes, ways, rels)
    }
}

/// TypedSink: pushes records to three Parquet writers on the collector thread —
/// Arrow-build + zstd compression are ALL serial here. This is the former
/// `read_raw` sink (the ~1.8-core all-core gate). Superseded 2026-07-14 by the
/// worker-encode [`RawParallelParquetSink`]; kept as the reference serial
/// fallback per the additive/no-regression law.
#[allow(dead_code)]
struct RawParquetTypedSink {
    node_writer: Option<NodeWriter>,
    way_writer: Option<WayWriter>,
    rel_writer: Option<RelWriter>,
    node_count: usize,
    way_count: usize,
    rel_count: usize,
    pb: indicatif::ProgressBar,
}

impl gatling::TypedSink<RawRecords> for RawParquetTypedSink {
    fn process(&mut self, output: RawRecords, _is_last: bool) -> Result<()> {
        let (nodes, ways, rels) = output;
        self.node_count += nodes.len();
        self.way_count += ways.len();
        self.rel_count += rels.len();
        let progress = nodes.len() + ways.len() + rels.len();
        if let Some(w) = &mut self.node_writer {
            for r in &nodes {
                w.push(r)?;
            }
        }
        if let Some(w) = &mut self.way_writer {
            for r in &ways {
                w.push(r)?;
            }
        }
        if let Some(w) = &mut self.rel_writer {
            for r in &rels {
                w.push(r)?;
            }
        }
        self.pb.inc(progress as u64);
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if let Some(w) = self.node_writer.take() {
            w.finish()?;
        }
        if let Some(w) = self.way_writer.take() {
            w.finish()?;
        }
        if let Some(w) = self.rel_writer.take() {
            w.finish()?;
        }
        Ok(())
    }
}

/// Raw single-pass `.osm` → GeoParquet on the Gatling typed engine.
///
/// Streams the file through Gatling's ring buffer. N workers VTD-parse their
/// element-aligned segments AND Arrow-build + zstd-encode their own node/way/rel
/// Parquet row groups (parallel), exactly like the bz2/gz raw paths; the
/// collector ([`RawParallelParquetSink`]) only stitches the pre-compressed groups
/// in order. No mmap, no pre-built index — single sequential pass, all cores hot.
///
/// Before 2026-07-14 the collector compressed every row group on a single thread
/// (`RawParquetTypedSink`), pegging the all-core convert at ~1.8 cores despite the
/// parallel parse; moving the encode onto the workers lifts core-busy toward the
/// core-saturation-law target. Row VALUES and counts are unchanged (row ORDER
/// across segments coalesces per-worker, exactly as the shipped bz2/gz raw paths
/// already do — Parquet row order is not semantically meaningful).
///
/// Returns `(node_count, way_count, rel_count)`.
#[allow(clippy::too_many_arguments)]
pub fn read_raw(
    path: &str,
    _idx_path: &Path,
    n_workers: usize,
    pb: indicatif::ProgressBar,
    out_dir: &Path,
    compression: &str,
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
) -> Result<(usize, usize, usize)> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::with_capacity(8 * 1024 * 1024, file);

    let (mut sink, encoders) = raw_typed_sink(
        out_dir,
        compression,
        include_nodes,
        include_ways,
        include_rels,
        pb,
    )?;
    let codec = RawXmlParallelCodec {
        include_nodes,
        include_ways,
        include_rels,
        node_encoder: encoders.node,
        way_encoder: encoders.way,
        rel_encoder: encoders.rel,
    };

    let cfg = gatling::Config {
        chunk_size: RAW_XML_CHUNK_SIZE,
        carry_headroom: RAW_XML_CARRY_HEADROOM,
        ring_slots: RAW_XML_RING_SLOTS,
        initial_carry: Vec::new(),
        // Big: long sequential XML read, slots reused full → no resize churn.
        slot_fill: gatling::SlotFill::Big,
    };

    gatling::run_typed(reader, codec, &mut sink, n_workers, cfg)?;
    sink.finish()
}

// ── Resolved .osm → GeoParquet on the Gatling typed engine (2-pass) ──────────
// Pass-1 uses `RawXmlPass1Codec` + `Pass1TypedSink` (workers Arrow-build + zstd
// their own node row groups; the collector only stitches + write_raws coords) —
// the same parallel machinery as the bz2/gz paths. The former serial
// `Pass1ResolvedCodec`/`Pass1ResolvedSink` (per-record `NodeAccumulator` on the
// single collector) was removed after it was found to peg raw `.osm` convert at
// ~3 cores.

struct Pass2ResolvedCodec {
    store: Arc<NodeStore>,
    clip_active: bool,
}
type Pass2ResolvedOutput = (Vec<CollectedWay>, Vec<RelationRecord>);

impl gatling::TypedCodec for Pass2ResolvedCodec {
    type Seg = (usize, usize);
    type Output = Pass2ResolvedOutput;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<Self::Seg>> {
        xml_split_typed(data, n_workers, is_last)
    }

    fn transform(&self, data: &[u8], seg: &(usize, usize)) -> Pass2ResolvedOutput {
        let sub = &data[seg.0..seg.1];
        let base = seg.0;

        // Pass A: parse way metadata + relations, collect all refs flat.
        let mut way_metas: Vec<WayMeta> = Vec::new();
        let mut rels: Vec<RelationRecord> = Vec::new();
        let mut all_refs: Vec<i64> = Vec::new();
        let mut ref_offsets: Vec<usize> = Vec::new();
        ref_offsets.push(0);

        xml_vtd::build_elem_index_slice(sub, base, &mut |e| {
            let lo = (e.file_offset as usize).saturating_sub(base);
            let hi = lo.saturating_add(e.file_length as usize).min(sub.len());
            let b = sub.get(lo..hi).unwrap_or_default();
            match e.kind {
                ElemKind::Way => {
                    let meta = parse_way_meta(&e, b);
                    all_refs.extend_from_slice(&meta.refs);
                    ref_offsets.push(all_refs.len());
                    way_metas.push(meta);
                }
                ElemKind::Relation => rels.push(parse_relation(&e, b)),
                ElemKind::Node => {}
            }
        });

        // Pass B: one batch lookup for every ref in the slot — sorts +
        // madvise() to convert random page faults into sequential walk.
        let resolved = self.store.lookup_batch(&all_refs);

        // Pass C: assemble CollectedWay from batched coord results.
        let mut ways: Vec<CollectedWay> = Vec::with_capacity(way_metas.len());
        for (w_idx, meta) in way_metas.into_iter().enumerate() {
            let lo = ref_offsets[w_idx];
            let hi = ref_offsets[w_idx + 1];
            let coords: Vec<(f64, f64)> = resolved[lo..hi]
                .iter()
                .filter_map(|opt| opt.map(|(lat, lon)| (f64::from(lon), f64::from(lat))))
                .collect();
            // Region-clip way semantics: drop ways with no in-region coords.
            if self.clip_active && coords.is_empty() {
                continue;
            }
            ways.push(CollectedWay {
                id: meta.id,
                coords,
                tags_json: meta.tags_json,
                node_refs: meta.refs,
                version: meta.version,
                is_area: meta.is_area,
            });
        }

        (ways, rels)
    }
}

struct Pass2ResolvedSink<'a> {
    backend: &'a dyn GpuBackend,
    way_writer: Option<WayWriter>,
    rel_writer: Option<RelWriter>,
    way_count: usize,
    rel_count: usize,
    pb: indicatif::ProgressBar,
}

impl gatling::TypedSink<Pass2ResolvedOutput> for Pass2ResolvedSink<'_> {
    fn process(&mut self, output: Pass2ResolvedOutput, _is_last: bool) -> Result<()> {
        let (collected, rels) = output;
        let ways = collected_to_way_records(collected, self.backend);
        self.way_count += ways.len();
        self.rel_count += rels.len();
        if let Some(w) = &mut self.way_writer {
            for r in &ways {
                w.push(r)?;
            }
        }
        if let Some(w) = &mut self.rel_writer {
            for r in &rels {
                w.push(r)?;
            }
        }
        self.pb.inc((ways.len() + rels.len()) as u64);
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        if let Some(w) = self.way_writer.take() {
            w.finish()?;
        }
        if let Some(w) = self.rel_writer.take() {
            w.finish()?;
        }
        Ok(())
    }
}

/// Resolved 2-pass `.osm` → GeoParquet on the Gatling typed engine.
///
/// Pass 1: workers VTD-parse nodes → nodes.parquet + node_coords.bin (sorted).
/// Pass 2: workers VTD-parse ways/relations, resolve coords against the store
/// → ways/relations.parquet. Two file reads; no elem.idx, no in-RAM accumulation.
/// Returns `(node_count, way_count, rel_count)`.
#[allow(clippy::too_many_arguments)]
pub fn read_resolved_osm(
    path: &str,
    _idx_path: &Path,
    n_workers: usize,
    pb: indicatif::ProgressBar,
    out_dir: &Path,
    compression: &str,
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    backend: &dyn GpuBackend,
    clip: Option<Arc<crate::Clip>>,
) -> Result<(usize, usize, usize)> {
    let mk_cfg = || gatling::Config {
        chunk_size: RAW_XML_CHUNK_SIZE,
        carry_headroom: RAW_XML_CARRY_HEADROOM,
        ring_slots: RAW_XML_RING_SLOTS,
        initial_carry: Vec::new(),
        // Big: long sequential XML read (resolved 2-pass), slots reused full.
        slot_fill: gatling::SlotFill::Big,
    };

    // ── Pass 1: nodes ─────────────────────────────────────────────────────────
    // Parallel node encode: workers Arrow-build + zstd their own row groups
    // (RawXmlPass1Codec → pass1_parse_decoded, the same template the bz2/gz paths
    // use); the collector only stitches pre-compressed groups + write_raws coords.
    pb.set_message("pass 1/2  (nodes)");
    let (node_encoder, node_writer) = if include_nodes {
        let (enc, w) = writer::parallel_node_writer(&out_dir.join("nodes.parquet"), compression)?;
        (Some(enc), Some(w))
    } else {
        (None, None)
    };
    let node_acc = if include_nodes {
        Some(writer::NodeAccumulator::new())
    } else {
        None
    };
    let mut p1 = Pass1TypedSink {
        coord_writer: CoordFileWriter::new(&out_dir.join("node_coords.bin"))?,
        node_acc,
        node_encoder: node_encoder.clone(),
        node_writer,
        node_count: 0,
        pb: pb.clone(),
        prev_stub: Vec::new(),
        include_nodes,
        busy_ns: None,
    };
    {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::with_capacity(8 * 1024 * 1024, file);
        let codec = RawXmlPass1Codec {
            include_nodes,
            node_encoder,
            clip: clip.clone(),
        };
        gatling::run_typed(reader, codec, &mut p1, n_workers, mk_cfg())?;
    }
    let (coord_writer, node_count) = p1.finish()?;

    pb.set_message("sorting node coords …");
    let store = Arc::new(coord_writer.finalize()?);

    // ── Pass 2: ways + relations ──────────────────────────────────────────────
    pb.set_message(format!("pass 2/2  ({} nodes)", store.len()));
    let mut p2 = Pass2ResolvedSink {
        backend,
        way_writer: if include_ways {
            Some(WayWriter::new(&out_dir.join("ways.parquet"), compression)?)
        } else {
            None
        },
        rel_writer: if include_rels {
            Some(RelWriter::new(
                &out_dir.join("relations.parquet"),
                compression,
            )?)
        } else {
            None
        },
        way_count: 0,
        rel_count: 0,
        pb: pb.clone(),
    };
    {
        let mut file = std::fs::File::open(path)?;
        // Skip the entire node section: resolved pass 2 only needs ways +
        // relations, but Pass2ResolvedCodec::transform VTD-parses every element
        // in its slice. Seeking past the nodes avoids re-parsing ~all of a
        // node-heavy file (the dominant post-Gatling pass-2 cost).
        let start = find_ways_rels_offset(path);
        if start > 0 {
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(start))?;
        }
        let reader = std::io::BufReader::with_capacity(8 * 1024 * 1024, file);
        gatling::run_typed(
            reader,
            Pass2ResolvedCodec {
                store,
                clip_active: clip.is_some(),
            },
            &mut p2,
            n_workers,
            mk_cfg(),
        )?;
    }

    Ok((node_count, p2.way_count, p2.rel_count))
}

/// Raw way parser — collects node-ref IDs and tags but does NOT resolve coords.
/// `geometry` is always `None`; the node-ID list is preserved in `node_refs`.
fn parse_way_raw(e: &ElemIndex, elem: &[u8]) -> WayRecord {
    let version = parse_attr_i32(opening_tag(elem), b"version");

    let mut refs: Vec<i64> = Vec::new();
    let mut tag_pairs: Vec<(String, String)> = Vec::new();

    scan_children(elem, |name, child| {
        if name == b"nd" {
            if let Some(r) = xml_vtd::find_attr(child, b"ref") {
                refs.push(xml_vtd::parse_i64(r));
            }
        } else if name == b"tag" {
            if let (Some(k), Some(v)) = (
                xml_vtd::find_attr(child, b"k"),
                xml_vtd::find_attr(child, b"v"),
            ) {
                tag_pairs.push((unescape(k), unescape(v)));
            }
        }
    });

    let tags_json = tags::serialize_tags(tag_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));

    WayRecord {
        id: e.id,
        geometry: None,
        tags_json,
        node_refs: refs,
        version,
    }
}

// ── VTD-guided chunk planner ──────────────────────────────────────────────────

/// Group ElemIndex entries into batches of at most `max_bytes` total element
/// bytes. Returns `(start, end)` index pairs (exclusive end) into `index`.
/// Every element fits entirely within its batch — no spanning, no partial parses.
fn plan_chunks(index: &[&ElemIndex], max_bytes: usize) -> Vec<(usize, usize)> {
    let mut chunks = Vec::new();
    let mut start = 0usize;
    let mut accum = 0usize;

    for (i, e) in index.iter().enumerate() {
        accum = accum.saturating_add(e.file_length as usize);
        if accum >= max_bytes {
            chunks.push((start, i.saturating_add(1)));
            start = i.saturating_add(1);
            accum = 0;
        }
    }
    if start < index.len() {
        chunks.push((start, index.len()));
    }
    chunks
}

// ── Per-chunk parallel parser ─────────────────────────────────────────────────

/// Way metadata before coord resolution — refs, tags, version, is_area.
struct WayMeta {
    id: i64,
    refs: Vec<i64>,
    tags_json: String,
    is_area: bool,
    version: Option<i32>,
}

fn parse_chunk(
    bytes: &[u8],
    chunk: &[&ElemIndex],
    store: &Arc<NodeStore>,
    base_offset: usize,
    clip_active: bool,
) -> (Vec<CollectedWay>, Vec<RelationRecord>) {
    // Pass A: parse every way's metadata (refs + tags), collect all refs in
    // one flat Vec for a single batch lookup. Relations parsed inline (no
    // coord resolution needed).
    let mut way_metas: Vec<WayMeta> = Vec::new();
    let mut rels: Vec<RelationRecord> = Vec::new();
    let mut all_refs: Vec<i64> = Vec::new();
    let mut ref_offsets: Vec<usize> = Vec::with_capacity(chunk.len() + 1);
    ref_offsets.push(0);

    for e in chunk {
        let start = (e.file_offset as usize).saturating_sub(base_offset);
        let end = start.saturating_add(e.file_length as usize);
        let elem = bytes.get(start..end).unwrap_or_default();

        match e.kind {
            ElemKind::Way => {
                let meta = parse_way_meta(e, elem);
                all_refs.extend_from_slice(&meta.refs);
                ref_offsets.push(all_refs.len());
                way_metas.push(meta);
            }
            ElemKind::Relation => rels.push(parse_relation(e, elem)),
            ElemKind::Node => {}
        }
    }

    // Pass B: one batch lookup for every ref in the chunk. STree64Mmap sorts
    // by leaf-block index and madvise()s the touched range — random page
    // faults across the 144 GB coord mmap become a near-sequential walk
    // with parallel kernel readahead.
    let resolved = store.lookup_batch(&all_refs);

    // Pass C: assemble CollectedWay using sliced coord results per way.
    let mut ways: Vec<CollectedWay> = Vec::with_capacity(way_metas.len());
    for (w_idx, meta) in way_metas.into_iter().enumerate() {
        let lo = ref_offsets[w_idx];
        let hi = ref_offsets[w_idx + 1];
        let coords: Vec<(f64, f64)> = resolved[lo..hi]
            .iter()
            .filter_map(|opt| opt.map(|(lat, lon)| (f64::from(lon), f64::from(lat))))
            .collect();
        // Region-clip way semantics: store holds only in-region nodes, so a way
        // with zero resolvable coords is wholly outside the region → drop it.
        if clip_active && coords.is_empty() {
            continue;
        }
        ways.push(CollectedWay {
            id: meta.id,
            coords,
            tags_json: meta.tags_json,
            node_refs: meta.refs,
            version: meta.version,
            is_area: meta.is_area,
        });
    }

    (ways, rels)
}

// ── Element parsers ───────────────────────────────────────────────────────────

/// Parse a way's metadata without resolving node coords. Caller batches refs
/// across all ways in a slot/chunk and does one `store.lookup_batch` for the
/// whole batch — turns N serial mmap page faults into a sorted, prefetched
/// sequential walk.
fn parse_way_meta(e: &ElemIndex, elem: &[u8]) -> WayMeta {
    let version = parse_attr_i32(opening_tag(elem), b"version");

    let mut refs: Vec<i64> = Vec::new();
    let mut tag_pairs: Vec<(String, String)> = Vec::new();

    scan_children(elem, |name, child| {
        if name == b"nd" {
            if let Some(r) = xml_vtd::find_attr(child, b"ref") {
                refs.push(xml_vtd::parse_i64(r));
            }
        } else if name == b"tag" {
            if let (Some(k), Some(v)) = (
                xml_vtd::find_attr(child, b"k"),
                xml_vtd::find_attr(child, b"v"),
            ) {
                tag_pairs.push((unescape(k), unescape(v)));
            }
        }
    });

    let tags_map: HashMap<String, String> = tag_pairs.iter().cloned().collect();
    let tags_json = tags::serialize_tags(tag_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let is_area = geometry::is_closed_area(&refs, &tags_map);

    WayMeta {
        id: e.id,
        refs,
        tags_json,
        is_area,
        version,
    }
}

fn parse_relation(e: &ElemIndex, elem: &[u8]) -> RelationRecord {
    let version = parse_attr_i32(opening_tag(elem), b"version");

    let mut tag_pairs: Vec<(String, String)> = Vec::new();
    let mut members: Vec<MemberEntry> = Vec::new();

    scan_children(elem, |name, child| {
        if name == b"tag" {
            if let (Some(k), Some(v)) = (
                xml_vtd::find_attr(child, b"k"),
                xml_vtd::find_attr(child, b"v"),
            ) {
                tag_pairs.push((unescape(k), unescape(v)));
            }
        } else if name == b"member" {
            let member_type = xml_vtd::find_attr(child, b"type")
                .map(|t| match t {
                    b"node" => "node",
                    b"way" => "way",
                    b"relation" => "relation",
                    _ => "node",
                })
                .unwrap_or("node");
            let member_ref = xml_vtd::find_attr(child, b"ref")
                .map(xml_vtd::parse_i64)
                .unwrap_or(0);
            let role = xml_vtd::find_attr(child, b"role")
                .map(unescape)
                .unwrap_or_default();
            members.push(MemberEntry {
                member_type,
                member_ref,
                role,
            });
        }
    });

    let tags_json = tags::serialize_tags(tag_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let members_json = serde_json::to_string(&members).unwrap_or_else(|_| String::from("[]"));

    RelationRecord {
        id: e.id,
        tags_json,
        members_json,
        version,
    }
}

// ── XML element helpers ───────────────────────────────────────────────────────

/// Return the bytes between `<` and the first `>` in `elem` (the opening tag
/// attributes, without the angle brackets). Empty slice on malformed input.
fn opening_tag(elem: &[u8]) -> &[u8] {
    let start = if elem.first() == Some(&b'<') { 1 } else { 0 };
    match memchr(b'>', elem) {
        Some(end) => elem.get(start..end).unwrap_or_default(),
        None => elem.get(start..).unwrap_or_default(),
    }
}

/// Call `f(name, child_tag)` for every direct child tag inside `elem`.
/// `name`      — bytes of the tag name (e.g. `b"nd"`, `b"tag"`, `b"member"`)
/// `child_tag` — all bytes between `<` and `>` (exclusive), i.e. attributes
///
/// Stops at the first closing tag (`</`).
fn scan_children(elem: &[u8], mut f: impl FnMut(&[u8], &[u8])) {
    // skip past the opening tag's `>`
    let Some(first_close) = memchr(b'>', elem) else {
        return;
    };
    let mut pos = first_close.saturating_add(1);

    while let Some(rel) = memchr(b'<', elem.get(pos..).unwrap_or_default()) {
        let child_open = pos.saturating_add(rel);
        let tag_start = child_open.saturating_add(1);

        let first = elem.get(tag_start).copied();
        if first == Some(b'/') {
            break; // closing tag — done
        }
        if first == Some(b'?') || first == Some(b'!') {
            pos = tag_start; // skip PI / comment
            continue;
        }

        let Some(rel2) = memchr(b'>', elem.get(tag_start..).unwrap_or_default()) else {
            break;
        };
        let child_close = tag_start.saturating_add(rel2);

        let child_tag = elem.get(tag_start..child_close).unwrap_or_default();
        let name_end = memchr(b' ', child_tag).unwrap_or(child_tag.len());
        let name = child_tag.get(..name_end).unwrap_or_default();

        // strip self-closing `/` from end of child_tag before passing to f
        let attr_end = if child_tag.last() == Some(&b'/') {
            child_tag.len().saturating_sub(1)
        } else {
            child_tag.len()
        };
        let child_attrs = child_tag.get(..attr_end).unwrap_or(child_tag);

        f(name, child_attrs);
        pos = child_close.saturating_add(1);
    }
}

/// Return the `name="..."` attribute value as an i32, or `None`.
fn parse_attr_i32(tag: &[u8], name: &[u8]) -> Option<i32> {
    let raw = xml_vtd::find_attr(tag, name)?;
    let s = std::str::from_utf8(raw).ok()?;
    s.parse::<i32>().ok()
}

/// Scan child `<tag k="..." v="..."/>` elements and return a JSON object string.
fn parse_tags_json(elem: &[u8]) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    scan_children(elem, |name, child| {
        if name == b"tag" {
            if let (Some(k), Some(v)) = (
                xml_vtd::find_attr(child, b"k"),
                xml_vtd::find_attr(child, b"v"),
            ) {
                pairs.push((unescape(k), unescape(v)));
            }
        }
    });
    tags::serialize_tags(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
}

// ── Streaming passes — for compressed inputs (.osm.bz2) ──────────────────────
//
// Both passes use the same pipelined reader loop (same as build_elem_index_pipelined)
// but with a generic Read source instead of a File.
//
// Key pattern: output variables are declared BEFORE thread::scope so the scope
// closure (which runs as the processor on the calling thread) can mutate them.
// Only the I/O reader is spawned as a thread; the processor stays on the caller.

// ── Raw bz2 → Parquet on the Gatling engine (fast path) ──────────────────────

// ── Raw single-pass → Parquet on the Gatling TYPED engine ────────────────────
//
// Each worker decodes its segment, VTD-parses the middle, and:
//   • nodes  → encodes Parquet row groups in-worker (NodeColumnEncoder, like
//              resolved pass-1) so zstd runs in parallel across workers;
//   • ways   → collected as raw (unresolved) WayRecords;
//   • rels   → collected as RelationRecords.
// The collector ([`RawParallelParquetSink`]) only stitches the pre-encoded node row
// groups (ParallelNodeWriter) and ships way/rel batches to a single ParquetSink
// writer thread — so the parse+encode is no longer serial on the collector.
//
// Boundary stubs (`prev_stub + left_stub`) are parsed on the collector; volume
// is a handful of elements per segment boundary, negligible vs the middle.

/// One worker's output for one raw segment: pre-encoded node/way/relation row
/// groups + the partial edge bytes that straddle the boundary.
///
/// Ways and relations are now Arrow-built + zstd-encoded **on the worker** (via
/// the shared [`WAY_ACC`]/[`REL_ACC`] accumulators and `pass2_accumulate`),
/// exactly like nodes and exactly like the resolved 2-pass path — so way/rel
/// compression runs across all Gatling workers instead of funnelling through one
/// `ParquetSink` writer thread. The collector only stitches the pre-encoded row
/// groups in order (plus the tiny boundary-stub groups it encodes itself).
#[derive(Default)]
struct RawSegment {
    node_row_groups: Vec<writer::EncodedRowGroup>,
    node_count: usize,
    way_row_groups: Vec<writer::EncodedRowGroup>,
    rel_row_groups: Vec<writer::EncodedRowGroup>,
    way_rows: usize,
    rel_rows: usize,
    left_stub: Vec<u8>,
    right_stub: Vec<u8>,
}

/// Parse a decoded XML run into a [`RawSegment`]. Nodes, ways and relations are
/// all Arrow-built + zstd-encoded in the worker: nodes via the per-worker
/// [`NODE_ACC`] (`node_encoder`), ways/rels via the shared [`WAY_ACC`]/[`REL_ACC`]
/// accumulators + `pass2_accumulate` (`way_encoder`/`rel_encoder`) — so the
/// collector never compresses. Shared by the bz2 and gz raw codecs.
fn raw_parse_decoded(
    decoded: &[u8],
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    node_encoder: Option<&writer::NodeColumnEncoder>,
    way_encoder: Option<&writer::ColumnEncoder>,
    rel_encoder: Option<&writer::ColumnEncoder>,
) -> RawSegment {
    if decoded.is_empty() {
        return RawSegment::default();
    }

    let first = xml_vtd::find_top_level_start(decoded, 0);
    let last = xml_vtd::find_safe_slot_end(decoded);
    let last = last.max(first);

    let left_stub = decoded[..first].to_vec();
    let right_stub = decoded[last..].to_vec();
    let middle = &decoded[first..last];

    let (node_row_groups, node_count, p2) = raw_encode_middle(
        middle,
        include_nodes,
        include_ways,
        include_rels,
        node_encoder,
        way_encoder,
        rel_encoder,
    );

    RawSegment {
        node_row_groups,
        node_count,
        way_row_groups: p2.way_row_groups,
        rel_row_groups: p2.rel_row_groups,
        way_rows: p2.way_rows,
        rel_rows: p2.rel_rows,
        left_stub,
        right_stub,
    }
}

/// Parse an ALREADY element-aligned XML run (no partial elements at either end,
/// so both boundary stubs are empty) into a [`RawSegment`], sharing the exact
/// worker-side encode body with [`raw_parse_decoded`] via [`raw_encode_middle`].
///
/// Used by the uncompressed `.osm` single-pass codec ([`RawXmlParallelCodec`]):
/// its gatling split (`xml_split_typed`) already cuts on top-level element
/// boundaries — so, unlike the bz2/gz decoded buffers, there are never partial
/// boundary elements to carry as stubs. This is what lets the uncompressed path
/// encode node/way/rel Parquet row groups ON THE WORKERS (parallel zstd) instead
/// of on a single collector thread (the former ~1.8-core serial gate).
fn raw_parse_aligned(
    sub: &[u8],
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    node_encoder: Option<&writer::NodeColumnEncoder>,
    way_encoder: Option<&writer::ColumnEncoder>,
    rel_encoder: Option<&writer::ColumnEncoder>,
) -> RawSegment {
    if sub.is_empty() {
        return RawSegment::default();
    }
    let (node_row_groups, node_count, p2) = raw_encode_middle(
        sub,
        include_nodes,
        include_ways,
        include_rels,
        node_encoder,
        way_encoder,
        rel_encoder,
    );
    RawSegment {
        node_row_groups,
        node_count,
        way_row_groups: p2.way_row_groups,
        rel_row_groups: p2.rel_row_groups,
        way_rows: p2.way_rows,
        rel_rows: p2.rel_rows,
        left_stub: Vec::new(),
        right_stub: Vec::new(),
    }
}

/// Shared worker-side encode of a run of complete top-level elements: nodes via
/// the per-worker [`NODE_ACC`] (`node_encoder`), ways/rels via the shared
/// [`WAY_ACC`]/[`REL_ACC`] accumulators + `pass2_accumulate`. Returns the sealed
/// full node row groups, the node count (counted at parse time), and the pass-2
/// segment (full way/rel groups + their row counts). Compresses NOTHING on the
/// caller's behalf beyond what these per-worker encoders do — the collector only
/// stitches. Shared verbatim by [`raw_parse_decoded`] (stub path, bz2/gz) and
/// [`raw_parse_aligned`] (no-stub path, uncompressed `.osm`).
fn raw_encode_middle(
    middle: &[u8],
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    node_encoder: Option<&writer::NodeColumnEncoder>,
    way_encoder: Option<&writer::ColumnEncoder>,
    rel_encoder: Option<&writer::ColumnEncoder>,
) -> (Vec<writer::EncodedRowGroup>, usize, P2Segment) {
    let mut node_count = 0usize;
    let mut ways: Vec<WayRecord> = Vec::new();
    let mut rels: Vec<RelationRecord> = Vec::new();
    let mut node_row_groups: Vec<writer::EncodedRowGroup> = Vec::new();

    NODE_ACC.with(|cell| {
        let mut slot = cell.borrow_mut();
        let mut acc = if include_nodes && node_encoder.is_some() {
            Some(slot.get_or_insert_with(writer::NodeAccumulator::new))
        } else {
            None
        };
        let enc = node_encoder;

        xml_vtd::build_elem_index_slice(middle, 0, &mut |e| {
            let lo = e.file_offset as usize;
            let hi = lo.saturating_add(e.file_length as usize).min(middle.len());
            let b = middle.get(lo..hi).unwrap_or_default();
            match e.kind {
                ElemKind::Node if include_nodes => {
                    node_count += 1;
                    if let (Some(acc), Some(enc)) = (acc.as_deref_mut(), enc) {
                        let lat = e.lat_e7 as f32 / 1e7_f32;
                        let lon = e.lon_e7 as f32 / 1e7_f32;
                        acc.push(&NodeRecord {
                            id: e.id,
                            lon_lat: (f64::from(lon), f64::from(lat)),
                            tags_json: parse_tags_json(b),
                            version: parse_attr_i32(opening_tag(b), b"version"),
                        });
                        if let Ok(Some(batch)) = acc.take_if_full() {
                            node_row_groups
                                .push(enc.encode(&batch).expect("node row group encode"));
                        }
                    }
                }
                ElemKind::Way if include_ways => ways.push(parse_way_raw(&e, b)),
                ElemKind::Relation if include_rels => rels.push(parse_relation(&e, b)),
                _ => {}
            }
        });
    });

    // Ways/rels: seal full ROW_GROUP_SIZE groups on THIS worker (parallel zstd)
    // via the shared per-worker accumulators — identical to the resolved path.
    let mut p2 = P2Segment::default();
    pass2_accumulate(&ways, &rels, way_encoder, rel_encoder, &mut p2);
    (node_row_groups, node_count, p2)
}

/// Drain the per-worker [`NODE_ACC`]/[`WAY_ACC`]/[`REL_ACC`] remainders into one
/// final row group each. Mirrors [`pass1_finish_worker`] + [`pass2_finish_worker`]
/// but returns a single [`RawSegment`] carrying all three tails.
fn raw_finish_worker(
    include_nodes: bool,
    node_encoder: Option<&writer::NodeColumnEncoder>,
    way_encoder: Option<&writer::ColumnEncoder>,
    rel_encoder: Option<&writer::ColumnEncoder>,
) -> Option<RawSegment> {
    let mut seg = RawSegment::default();
    let mut any = false;

    if include_nodes {
        if let Some(enc) = node_encoder {
            NODE_ACC.with(|cell| {
                if let Some(mut acc) = cell.borrow_mut().take() {
                    if let Ok(Some(batch)) = acc.take_remaining() {
                        // Nodes are counted at PARSE time (node_count += 1 per node
                        // in raw_parse_decoded), so the tail row group must NOT add
                        // to node_count again — only emit the pre-encoded group.
                        seg.node_row_groups
                            .push(enc.encode(&batch).expect("node tail row group encode"));
                        any = true;
                    }
                }
            });
        }
    }

    // Ways/rels: reuse the resolved path's worker-drain helper verbatim.
    if let Some(p2) = pass2_finish_worker(way_encoder, rel_encoder) {
        seg.way_row_groups = p2.way_row_groups;
        seg.rel_row_groups = p2.rel_row_groups;
        seg.way_rows = p2.way_rows;
        seg.rel_rows = p2.rel_rows;
        any = true;
    }

    if any { Some(seg) } else { None }
}

/// Raw bz2 → Parquet [`gatling::TypedCodec`]: decode a bz2 block range + parse +
/// (node) encode, all on the worker.
struct RawBz2ParquetTypedCodec {
    max_blocksize: u32,
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    node_encoder: Option<writer::NodeColumnEncoder>,
    way_encoder: Option<writer::ColumnEncoder>,
    rel_encoder: Option<writer::ColumnEncoder>,
}

impl gatling::TypedCodec for RawBz2ParquetTypedCodec {
    type Seg = (u64, u64);
    type Output = RawSegment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<(u64, u64)>> {
        let s = lbzip2::chunk::split_chunk(data, n_workers, self.max_blocksize, is_last)?;
        let total_bits = data.len() as u64 * 8;
        let n_seg = s.segment_starts.len();
        let segments = (0..s.decode_segments)
            .map(|i| {
                let start = s.segment_starts[i].bit_offset;
                let end = if i + 1 < n_seg {
                    s.segment_starts[i + 1].bit_offset
                } else {
                    total_bits
                };
                (start, end)
            })
            .collect();
        Some(gatling::Split {
            segments,
            consumed: s.consumed,
        })
    }

    fn transform(&self, data: &[u8], &(start_bit, end_bit): &(u64, u64)) -> RawSegment {
        let decoded = lbzip2::chunk::decode_segment(data, start_bit, end_bit, self.max_blocksize);
        let nenc = if self.include_nodes {
            self.node_encoder.as_ref()
        } else {
            None
        };
        let wenc = if self.include_ways {
            self.way_encoder.as_ref()
        } else {
            None
        };
        let renc = if self.include_rels {
            self.rel_encoder.as_ref()
        } else {
            None
        };
        raw_parse_decoded(
            &decoded,
            self.include_nodes,
            self.include_ways,
            self.include_rels,
            nenc,
            wenc,
            renc,
        )
    }

    fn finish_worker(&self) -> Option<RawSegment> {
        raw_finish_worker(
            self.include_nodes,
            self.node_encoder.as_ref(),
            self.way_encoder.as_ref(),
            self.rel_encoder.as_ref(),
        )
    }
}

/// Raw gz → Parquet [`gatling::TypedCodec`]: DEFLATE decode + parse + (node/way/
/// rel) encode on the worker. Mirrors [`RawBz2ParquetTypedCodec`] with lgz splits.
struct RawGzParquetTypedCodec {
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    node_encoder: Option<writer::NodeColumnEncoder>,
    way_encoder: Option<writer::ColumnEncoder>,
    rel_encoder: Option<writer::ColumnEncoder>,
}

impl gatling::TypedCodec for RawGzParquetTypedCodec {
    type Seg = (usize, usize);
    type Output = RawSegment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<(usize, usize)>> {
        crate::xml_to_pbf::gz_split(data, n_workers, is_last)
    }

    fn transform(&self, data: &[u8], seg: &(usize, usize)) -> RawSegment {
        let decoded = crate::xml_to_pbf::gz_decode_segment(data, seg);
        let nenc = if self.include_nodes {
            self.node_encoder.as_ref()
        } else {
            None
        };
        let wenc = if self.include_ways {
            self.way_encoder.as_ref()
        } else {
            None
        };
        let renc = if self.include_rels {
            self.rel_encoder.as_ref()
        } else {
            None
        };
        raw_parse_decoded(
            &decoded,
            self.include_nodes,
            self.include_ways,
            self.include_rels,
            nenc,
            wenc,
            renc,
        )
    }

    fn finish_worker(&self) -> Option<RawSegment> {
        raw_finish_worker(
            self.include_nodes,
            self.node_encoder.as_ref(),
            self.way_encoder.as_ref(),
            self.rel_encoder.as_ref(),
        )
    }
}

/// Raw single-pass `.osm` (UNCOMPRESSED XML) → Parquet [`gatling::TypedCodec`]:
/// each worker VTD-parses its element-aligned segment and Arrow-builds +
/// zstd-encodes its own node/way/rel row groups (parallel), exactly like the
/// bz2/gz raw codecs. Because `xml_split_typed` cuts on top-level element
/// boundaries there are no partial boundary elements — [`raw_parse_aligned`]
/// carries empty stubs — so the collector ([`RawParallelParquetSink`]) only
/// stitches pre-compressed groups. This replaced the former serial
/// `RawXmlTypedCodec` + `RawParquetTypedSink`, whose collector compressed every
/// row group on ONE thread and pegged the all-core raw convert at ~1.8 cores.
struct RawXmlParallelCodec {
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    node_encoder: Option<writer::NodeColumnEncoder>,
    way_encoder: Option<writer::ColumnEncoder>,
    rel_encoder: Option<writer::ColumnEncoder>,
}

impl gatling::TypedCodec for RawXmlParallelCodec {
    type Seg = (usize, usize);
    type Output = RawSegment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<Self::Seg>> {
        xml_split_typed(data, n_workers, is_last)
    }

    fn transform(&self, data: &[u8], seg: &Self::Seg) -> RawSegment {
        let nenc = if self.include_nodes {
            self.node_encoder.as_ref()
        } else {
            None
        };
        let wenc = if self.include_ways {
            self.way_encoder.as_ref()
        } else {
            None
        };
        let renc = if self.include_rels {
            self.rel_encoder.as_ref()
        } else {
            None
        };
        raw_parse_aligned(
            &data[seg.0..seg.1],
            self.include_nodes,
            self.include_ways,
            self.include_rels,
            nenc,
            wenc,
            renc,
        )
    }

    fn finish_worker(&self) -> Option<RawSegment> {
        raw_finish_worker(
            self.include_nodes,
            self.node_encoder.as_ref(),
            self.way_encoder.as_ref(),
            self.rel_encoder.as_ref(),
        )
    }
}

/// Raw single-pass [`gatling::TypedSink`]: stitches the workers' pre-encoded
/// node/way/relation row groups in order (NO compression on this thread) and
/// encodes only the tiny boundary-stub batches itself. Ways/rels are now encoded
/// on the workers (like nodes and like the resolved 2-pass path) instead of
/// funnelling through a single `ParquetSink` writer thread.
struct RawParallelParquetSink {
    node_acc: Option<writer::NodeAccumulator>,
    node_encoder: Option<writer::NodeColumnEncoder>,
    node_writer: Option<writer::ParallelNodeWriter>,
    node_count: usize,
    /// Tiny collector-side accumulators for boundary-stub ways/rels parsed HERE
    /// (a handful per segment boundary); full groups are encoded with
    /// `way_encoder`/`rel_encoder` — the SAME encoders the workers hold.
    way_acc: Option<writer::WayAccumulator>,
    rel_acc: Option<writer::RelAccumulator>,
    way_encoder: Option<writer::ColumnEncoder>,
    rel_encoder: Option<writer::ColumnEncoder>,
    /// In-order row-group stitchers (no compression): append both the workers'
    /// bulk row groups and the collector's boundary-stub groups.
    way_writer: Option<writer::ParallelRowGroupWriter>,
    rel_writer: Option<writer::ParallelRowGroupWriter>,
    way_count: usize,
    rel_count: usize,
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    prev_stub: Vec<u8>,
    pb: indicatif::ProgressBar,
}

impl RawParallelParquetSink {
    fn flush_stub(&mut self, stub: &[u8]) -> Result<()> {
        if stub.is_empty() {
            return Ok(());
        }
        let (inc_n, inc_w, inc_r) = (self.include_nodes, self.include_ways, self.include_rels);
        let mut nodes: Vec<NodeRecord> = Vec::new();
        let mut ways: Vec<WayRecord> = Vec::new();
        let mut rels: Vec<RelationRecord> = Vec::new();
        xml_vtd::build_elem_index_slice(stub, 0, &mut |e| {
            let lo = e.file_offset as usize;
            let hi = lo.saturating_add(e.file_length as usize).min(stub.len());
            let b = stub.get(lo..hi).unwrap_or_default();
            match e.kind {
                ElemKind::Node if inc_n => {
                    let lat = e.lat_e7 as f32 / 1e7_f32;
                    let lon = e.lon_e7 as f32 / 1e7_f32;
                    nodes.push(NodeRecord {
                        id: e.id,
                        lon_lat: (f64::from(lon), f64::from(lat)),
                        tags_json: parse_tags_json(b),
                        version: parse_attr_i32(opening_tag(b), b"version"),
                    });
                }
                ElemKind::Way if inc_w => ways.push(parse_way_raw(&e, b)),
                ElemKind::Relation if inc_r => rels.push(parse_relation(&e, b)),
                _ => {}
            }
        });

        self.node_count += nodes.len();
        if let (Some(acc), Some(enc), Some(w)) = (
            self.node_acc.as_mut(),
            self.node_encoder.as_ref(),
            self.node_writer.as_mut(),
        ) {
            for r in &nodes {
                acc.push(r);
            }
            while let Some(batch) = acc.take_if_full()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        self.way_count += ways.len();
        if let (Some(acc), Some(enc), Some(w)) = (
            self.way_acc.as_mut(),
            self.way_encoder.as_ref(),
            self.way_writer.as_mut(),
        ) {
            for r in &ways {
                acc.push(r);
            }
            while let Some(batch) = acc.take_if_full()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        self.rel_count += rels.len();
        if let (Some(acc), Some(enc), Some(w)) = (
            self.rel_acc.as_mut(),
            self.rel_encoder.as_ref(),
            self.rel_writer.as_mut(),
        ) {
            for r in &rels {
                acc.push(r);
            }
            while let Some(batch) = acc.take_if_full()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(usize, usize, usize)> {
        let stub = std::mem::take(&mut self.prev_stub);
        self.flush_stub(&stub)?;
        if let (Some(acc), Some(enc), Some(w)) = (
            self.node_acc.as_mut(),
            self.node_encoder.as_ref(),
            self.node_writer.as_mut(),
        ) {
            if let Some(batch) = acc.take_remaining()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        if let Some(w) = self.node_writer.take() {
            w.finish()?;
        }
        if let (Some(acc), Some(enc), Some(w)) = (
            self.way_acc.as_mut(),
            self.way_encoder.as_ref(),
            self.way_writer.as_mut(),
        ) {
            if let Some(batch) = acc.take_remaining()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        if let Some(w) = self.way_writer.take() {
            w.finish()?;
        }
        if let (Some(acc), Some(enc), Some(w)) = (
            self.rel_acc.as_mut(),
            self.rel_encoder.as_ref(),
            self.rel_writer.as_mut(),
        ) {
            if let Some(batch) = acc.take_remaining()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        if let Some(w) = self.rel_writer.take() {
            w.finish()?;
        }
        Ok((self.node_count, self.way_count, self.rel_count))
    }
}

impl gatling::TypedSink<RawSegment> for RawParallelParquetSink {
    fn process(&mut self, seg: RawSegment, _is_last: bool) -> Result<()> {
        let boundary = [self.prev_stub.as_slice(), seg.left_stub.as_slice()].concat();
        self.flush_stub(&boundary)?;

        // Nodes / ways / rels: stitch the pre-encoded row groups in order (no
        // zstd on this thread — the workers already compressed them).
        self.node_count += seg.node_count;
        if let Some(w) = self.node_writer.as_mut() {
            for rg in seg.node_row_groups {
                w.append(rg)?;
            }
        }
        self.way_count += seg.way_rows;
        if let Some(w) = self.way_writer.as_mut() {
            for rg in seg.way_row_groups {
                w.append(rg)?;
            }
        }
        self.rel_count += seg.rel_rows;
        if let Some(w) = self.rel_writer.as_mut() {
            for rg in seg.rel_row_groups {
                w.append(rg)?;
            }
        }
        self.pb.inc(
            (seg.left_stub.len() + seg.node_count * 64 + seg.way_rows * 512 + seg.right_stub.len())
                as u64,
        );

        self.prev_stub = seg.right_stub;
        Ok(())
    }
}

/// The three column encoders the raw codec hands to the Gatling workers so each
/// worker Arrow-builds + zstd-encodes its own node/way/rel row groups in parallel.
#[derive(Default, Clone)]
struct RawEncoders {
    node: Option<writer::NodeColumnEncoder>,
    way: Option<writer::ColumnEncoder>,
    rel: Option<writer::ColumnEncoder>,
}

/// Build the raw single-pass typed sink + its writers, shared by the bz2 and gz
/// raw entries. Nodes, ways AND relations use the parallel (worker-encode) writer
/// pattern (one row-group stitcher per table on the collector, all zstd on the
/// workers) — no single funnel writer thread.
fn raw_typed_sink(
    out_dir: &Path,
    compression: &str,
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    pb: indicatif::ProgressBar,
) -> Result<(RawParallelParquetSink, RawEncoders)> {
    let (node_encoder, node_writer) = if include_nodes {
        let (enc, w) = writer::parallel_node_writer(&out_dir.join("nodes.parquet"), compression)?;
        (Some(enc), Some(w))
    } else {
        (None, None)
    };
    let node_acc = if include_nodes {
        Some(writer::NodeAccumulator::new())
    } else {
        None
    };

    let (way_encoder, way_writer) = if include_ways {
        let (enc, w) = writer::parallel_way_writer(&out_dir.join("ways.parquet"), compression)?;
        (Some(enc), Some(w))
    } else {
        (None, None)
    };
    let (rel_encoder, rel_writer) = if include_rels {
        let (enc, w) =
            writer::parallel_rel_writer(&out_dir.join("relations.parquet"), compression)?;
        (Some(enc), Some(w))
    } else {
        (None, None)
    };
    let way_acc = if include_ways {
        Some(writer::WayAccumulator::new())
    } else {
        None
    };
    let rel_acc = if include_rels {
        Some(writer::RelAccumulator::new())
    } else {
        None
    };

    let encoders = RawEncoders {
        node: node_encoder.clone(),
        way: way_encoder.clone(),
        rel: rel_encoder.clone(),
    };
    let sink = RawParallelParquetSink {
        node_acc,
        node_encoder,
        node_writer,
        node_count: 0,
        way_acc,
        rel_acc,
        way_encoder,
        rel_encoder,
        way_writer,
        rel_writer,
        way_count: 0,
        rel_count: 0,
        include_nodes,
        include_ways,
        include_rels,
        prev_stub: Vec::new(),
        pb,
    };
    Ok((sink, encoders))
}

/// Raw single-pass `.osm.bz2` → GeoParquet on the Gatling engine.
///
/// The engine decodes bz2 in parallel (split + N decode workers, no barrier) and
/// hands contiguous XML to [`RawParquetSink`]. Single-pass, no node store.
/// Returns `(nodes, ways, rels)`.
#[allow(clippy::too_many_arguments)]
pub fn read_raw_bz2(
    input: &Path,
    out_dir: &Path,
    compression: &str,
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    n_workers: usize,
    skip_to_nodes: bool,
    pb: indicatif::ProgressBar,
) -> Result<(usize, usize, usize)> {
    let (mut sink, encoders) = raw_typed_sink(
        out_dir,
        compression,
        include_nodes,
        include_ways,
        include_rels,
        pb,
    )?;

    let skip = if skip_to_nodes {
        crate::xml_to_pbf::Bz2Skip::Changesets(crate::xml_to_pbf::DATA_NEEDLES)
    } else {
        crate::xml_to_pbf::Bz2Skip::None
    };
    let crate::xml_to_pbf::Bz2Prepared {
        reader,
        max_blocksize,
        initial_carry,
    } = crate::xml_to_pbf::bz2_prepare(input, skip)?;
    let codec = RawBz2ParquetTypedCodec {
        max_blocksize,
        include_nodes,
        include_ways,
        include_rels,
        node_encoder: encoders.node,
        way_encoder: encoders.way,
        rel_encoder: encoders.rel,
    };
    gatling::run_typed(
        reader,
        codec,
        &mut sink,
        n_workers,
        crate::xml_to_pbf::mk_bz2_cfg(initial_carry),
    )?;
    sink.finish()
}

// ── Resolved bz2 → Parquet on the Gatling engine (2-pass) ─────────────────────
// Live path: Bz2Pass1TypedCodec + Pass1TypedSink (and pass-2 equivalents) below.
// The byte-mode Pass1ParquetSink / Pass2ParquetSink + parse_nodes_slot +
// parse_ways_rels_slot were removed 2026-05-29 — unreachable after the
// TypedCodec migration; held ~200 lines of rayon par_iter in the dead path.

// ── TypedCodec path: bz2 decode + XML parse in one worker ────────────────────
//
// Each Gatling worker decodes its bz2 segment then immediately scans the decoded
// XML, producing typed records.  No rayon pool inside the collector.
//
// Boundary handling: bz2 block boundaries do not align with XML element boundaries.
// Each decoded segment is trimmed with find_top_level_start / find_safe_slot_end to
// isolate complete elements ("middle").  The leading/trailing partial bytes
// (left_stub / right_stub) are carried in the output and reassembled by the sink
// between consecutive segments so no element is ever dropped.

/// Output of one bz2 segment's pass-1 parse (node coords + optional node row groups).
///
/// `node_row_groups` are encoded **in the worker**: each worker turns its
/// segment's nodes into one (or more) fully-compressed Parquet row groups, so
/// the zstd/page encoding runs in parallel across all Gatling workers. The
/// collector only stitches the pre-compressed chunks into the file — it never
/// compresses. Boundary records (in `left_stub` / `right_stub`) are still
/// handled by the collector via `flush_stub`, but their volume is tiny
/// (~1–10 records per segment vs ~50K in the middle).
struct P1Segment {
    node_row_groups: Vec<writer::EncodedRowGroup>, // empty when include_nodes=false
    packed: Vec<u8>,     // tightly packed (i64 id, f32 lat, f32 lon) per node
    left_stub: Vec<u8>,  // decoded bytes before first complete element
    right_stub: Vec<u8>, // decoded bytes after last complete element
}

impl Default for P1Segment {
    fn default() -> Self {
        Self {
            node_row_groups: Vec::new(),
            packed: Vec::new(),
            left_stub: Vec::new(),
            right_stub: Vec::new(),
        }
    }
}

/// Output of one bz2 segment's pass-2 parse (resolved ways + relations).
struct P2Segment {
    /// Full ROW_GROUP_SIZE way row groups, Arrow-built + zstd-encoded ON THE
    /// WORKER (parallel). The collector only stitches these in order.
    way_row_groups: Vec<writer::EncodedRowGroup>,
    /// Full relation row groups, likewise pre-encoded on the worker.
    rel_row_groups: Vec<writer::EncodedRowGroup>,
    /// Count of way rows represented by `way_row_groups` (for progress/totals).
    way_rows: usize,
    /// Count of relation rows represented by `rel_row_groups`.
    rel_rows: usize,
    left_stub: Vec<u8>,
    right_stub: Vec<u8>,
}

impl Default for P2Segment {
    fn default() -> Self {
        Self {
            way_row_groups: Vec::new(),
            rel_row_groups: Vec::new(),
            way_rows: 0,
            rel_rows: 0,
            left_stub: Vec::new(),
            right_stub: Vec::new(),
        }
    }
}

thread_local! {
    /// Per-worker pass-2 way accumulator that persists across the segments a
    /// single worker thread processes — the exact mirror of pass-1's `NODE_ACC`.
    /// Full ROW_GROUP_SIZE batches are Arrow-built + zstd-encoded inside the
    /// worker (parallel); the sub-full remainder carries into this worker's next
    /// segment so we don't emit a tiny group per segment. `pass2_finish_worker`
    /// drains the final remainder once before the thread exits.
    static WAY_ACC: std::cell::RefCell<Option<writer::WayAccumulator>> =
        const { std::cell::RefCell::new(None) };
    /// Per-worker pass-2 relation accumulator (mirror of `WAY_ACC`).
    static REL_ACC: std::cell::RefCell<Option<writer::RelAccumulator>> =
        const { std::cell::RefCell::new(None) };
}

/// Push finished way/rel records into the per-worker accumulators, sealing +
/// encoding any full ROW_GROUP_SIZE row groups on this worker thread. Returns
/// the encoded full groups (the sub-full remainder stays in the thread-locals).
/// `way_enc`/`rel_enc` are the shared (cloneable, Sync) column encoders.
fn pass2_accumulate(
    ways: &[WayRecord],
    rels: &[RelationRecord],
    way_enc: Option<&writer::ColumnEncoder>,
    rel_enc: Option<&writer::ColumnEncoder>,
    out: &mut P2Segment,
) {
    // Count rows ONLY from the batches actually emitted (here as full groups,
    // and in `pass2_finish_worker` for the tail) so every row is counted exactly
    // once regardless of how it splits across segments / row groups.
    if let Some(enc) = way_enc {
        WAY_ACC.with(|cell| {
            let mut slot = cell.borrow_mut();
            let acc = slot.get_or_insert_with(writer::WayAccumulator::new);
            for r in ways {
                acc.push(r);
                if let Ok(Some(batch)) = acc.take_if_full() {
                    out.way_rows += batch.num_rows();
                    out.way_row_groups
                        .push(enc.encode(&batch).expect("way row group encode"));
                }
            }
        });
    }
    if let Some(enc) = rel_enc {
        REL_ACC.with(|cell| {
            let mut slot = cell.borrow_mut();
            let acc = slot.get_or_insert_with(writer::RelAccumulator::new);
            for r in rels {
                acc.push(r);
                if let Ok(Some(batch)) = acc.take_if_full() {
                    out.rel_rows += batch.num_rows();
                    out.rel_row_groups
                        .push(enc.encode(&batch).expect("rel row group encode"));
                }
            }
        });
    }
}

/// Drain the per-worker `WAY_ACC`/`REL_ACC` remainders into one final row group
/// each. Mirror of pass-1's `pass1_finish_worker`.
fn pass2_finish_worker(
    way_enc: Option<&writer::ColumnEncoder>,
    rel_enc: Option<&writer::ColumnEncoder>,
) -> Option<P2Segment> {
    let mut seg = P2Segment::default();
    let mut any = false;
    if let Some(enc) = way_enc {
        WAY_ACC.with(|cell| {
            if let Some(mut acc) = cell.borrow_mut().take() {
                if let Ok(Some(batch)) = acc.take_remaining() {
                    seg.way_rows += batch.num_rows();
                    seg.way_row_groups
                        .push(enc.encode(&batch).expect("way tail row group encode"));
                    any = true;
                }
            }
        });
    }
    if let Some(enc) = rel_enc {
        REL_ACC.with(|cell| {
            if let Some(mut acc) = cell.borrow_mut().take() {
                if let Ok(Some(batch)) = acc.take_remaining() {
                    seg.rel_rows += batch.num_rows();
                    seg.rel_row_groups
                        .push(enc.encode(&batch).expect("rel tail row group encode"));
                    any = true;
                }
            }
        });
    }
    if any { Some(seg) } else { None }
}

// ── Pass-1 TypedCodec ─────────────────────────────────────────────────────────

struct Bz2Pass1TypedCodec {
    max_blocksize: u32,
    include_nodes: bool,
    /// Per-worker Parquet encoder: each worker compresses its own segment's
    /// node row group in parallel (no rayon, no shared writer lock).
    node_encoder: Option<writer::NodeColumnEncoder>,
    /// Optional region clip applied per-node inside the worker (no extra pass).
    clip: Option<Arc<crate::Clip>>,
}

thread_local! {
    /// Per-worker node accumulator that persists across the segments a single
    /// worker thread processes. Full ROW_GROUP_SIZE batches are sealed mid-stream
    /// (parallel zstd, in the worker); the sub-full remainder carries into this
    /// worker's next segment instead of being flushed as its own tiny row group.
    /// `finish_worker` drains the final remainder once, before the thread exits.
    static NODE_ACC: std::cell::RefCell<Option<writer::NodeAccumulator>> =
        const { std::cell::RefCell::new(None) };
}

/// Parse decoded XML bytes into a pass-1 segment (node coords + node row
/// groups). Shared by the bz2 and gz typed codecs — only the decode step
/// upstream differs. Uses the per-worker [`NODE_ACC`] accumulator so full row
/// groups are sealed (parallel zstd) inside the worker.
fn pass1_parse_decoded(
    decoded: &[u8],
    include_nodes: bool,
    node_encoder: Option<&writer::NodeColumnEncoder>,
    clip: Option<&crate::Clip>,
) -> P1Segment {
    if decoded.is_empty() {
        return P1Segment::default();
    }

    let first = xml_vtd::find_top_level_start(decoded, 0);
    let last = xml_vtd::find_safe_slot_end(decoded);
    let last = last.max(first);

    let left_stub = decoded[..first].to_vec();
    let right_stub = decoded[last..].to_vec();
    let middle = &decoded[first..last];

    let mut packed = Vec::new();
    let mut node_row_groups: Vec<writer::EncodedRowGroup> = Vec::new();

    NODE_ACC.with(|cell| {
        let mut slot = cell.borrow_mut();
        let mut acc = if include_nodes && node_encoder.is_some() {
            Some(slot.get_or_insert_with(writer::NodeAccumulator::new))
        } else {
            None
        };
        let enc = node_encoder;

        xml_vtd::build_elem_index_slice(middle, 0, &mut |e| {
            if e.kind == ElemKind::Node {
                let lat = e.lat_e7 as f32 / 1e7_f32;
                let lon = e.lon_e7 as f32 / 1e7_f32;
                // Region clip at decode: drop out-of-region nodes before packing
                // coords or building the node record. Uses the full-precision e7
                // ints so the test matches the PBF path.
                if !crate::clip_keeps(clip, e.lon_e7 as f64 / 1e7, e.lat_e7 as f64 / 1e7) {
                    return;
                }
                packed.extend_from_slice(&e.id.to_le_bytes());
                packed.extend_from_slice(&lat.to_le_bytes());
                packed.extend_from_slice(&lon.to_le_bytes());
                if let (Some(acc), Some(enc)) = (acc.as_deref_mut(), enc) {
                    let lo = e.file_offset as usize;
                    let hi = lo.saturating_add(e.file_length as usize).min(middle.len());
                    let b = middle.get(lo..hi).unwrap_or_default();
                    acc.push(&NodeRecord {
                        id: e.id,
                        lon_lat: (f64::from(lon), f64::from(lat)),
                        tags_json: parse_tags_json(b),
                        version: parse_attr_i32(opening_tag(b), b"version"),
                    });
                    if let Ok(Some(batch)) = acc.take_if_full() {
                        node_row_groups.push(enc.encode(&batch).expect("node row group encode"));
                    }
                }
            }
        });
    });

    P1Segment {
        node_row_groups,
        packed,
        left_stub,
        right_stub,
    }
}

/// Drain the per-worker [`NODE_ACC`] remainder into one final row group. Shared
/// `finish_worker` body for the bz2 and gz pass-1 codecs.
fn pass1_finish_worker(
    include_nodes: bool,
    node_encoder: Option<&writer::NodeColumnEncoder>,
) -> Option<P1Segment> {
    if !include_nodes {
        return None;
    }
    let enc = node_encoder?;
    NODE_ACC.with(|cell| {
        let mut acc = cell.borrow_mut().take()?;
        let batch = acc.take_remaining().ok().flatten()?;
        let rg = enc.encode(&batch).expect("node tail row group encode");
        Some(P1Segment {
            node_row_groups: vec![rg],
            ..P1Segment::default()
        })
    })
}

/// Parse one PBF blob into a pass-1 segment (node coords + node row groups).
/// PBF analogue of [`pass1_parse_decoded`]: blobs are self-contained, so there
/// are no boundary stubs. `data` is the full slot slice; `seg` indexes the blob.
/// Parse one COARSE candidate range into a pass-1 segment. `seg` is
/// `(cand_start, cand_end)`; the worker first aligns to its own blob boundary via
/// `pbf_io::align_and_collect` (boundary-finding is DISTRIBUTED across all workers,
/// not serialized on main) and then decodes every OSMData blob it owns into ONE
/// segment. Blobs are self-contained so there are no boundary stubs. `data` is
/// the full slot slice (borrowed, zero-copy).
fn pass1_parse_blob(
    data: &[u8],
    seg: &(usize, usize),
    include_nodes: bool,
    node_encoder: Option<&writer::NodeColumnEncoder>,
    clip: Option<&crate::Clip>,
) -> P1Segment {
    let blobs = crate::pbf_io::align_and_collect(data, seg.0, seg.1);
    if blobs.is_empty() {
        return P1Segment::default();
    }

    // Reused across the blobs this worker owns — no per-blob Vec churn.
    let mut packed: Vec<u8> = Vec::new();
    let mut node_row_groups: Vec<writer::EncodedRowGroup> = Vec::new();

    NODE_ACC.with(|cell| {
        let mut slot = cell.borrow_mut();
        let mut acc = if include_nodes && node_encoder.is_some() {
            Some(slot.get_or_insert_with(writer::NodeAccumulator::new))
        } else {
            None
        };
        for (off, len) in &blobs {
            let pos = crate::pbf_io::BlobPos {
                offset: *off,
                length: *len,
            };
            let (records, coords) = crate::reader::blob_nodes_and_coords(data, &pos, clip);
            if coords.is_empty() {
                continue;
            }
            packed.reserve(coords.len() * 16);
            for (id, lat, lon) in &coords {
                packed.extend_from_slice(&id.to_le_bytes());
                packed.extend_from_slice(&lat.to_le_bytes());
                packed.extend_from_slice(&lon.to_le_bytes());
            }
            if let (Some(acc), Some(enc)) = (acc.as_deref_mut(), node_encoder) {
                for r in &records {
                    acc.push(r);
                    if let Ok(Some(batch)) = acc.take_if_full() {
                        node_row_groups.push(enc.encode(&batch).expect("node row group encode"));
                    }
                }
            }
        }
    });

    P1Segment {
        node_row_groups,
        packed,
        left_stub: Vec::new(),
        right_stub: Vec::new(),
    }
}

/// Parse one COARSE candidate range into a pass-2 segment (resolved ways +
/// relations). `seg` is `(cand_start, cand_end)`; see [`pass1_parse_blob`] for the
/// alignment contract. Arrow-build + zstd-encode of full row groups happens HERE
/// on the worker (via the per-worker `WAY_ACC`/`REL_ACC` accumulators); only the
/// sub-full remainder carries into this worker's next segment. No boundary stubs.
#[allow(clippy::too_many_arguments)]
fn pass2_parse_blob(
    data: &[u8],
    seg: &(usize, usize),
    store: &Arc<NodeStore>,
    include_ways: bool,
    include_rels: bool,
    way_enc: Option<&writer::ColumnEncoder>,
    rel_enc: Option<&writer::ColumnEncoder>,
    clip_active: bool,
) -> P2Segment {
    let blobs = crate::pbf_io::align_and_collect(data, seg.0, seg.1);
    let mut out = P2Segment::default();
    if blobs.is_empty() {
        return out;
    }
    for (off, len) in &blobs {
        let pos = crate::pbf_io::BlobPos {
            offset: *off,
            length: *len,
        };
        let (ways, rels) = crate::reader::blob_ways_rels(data, &pos, store, clip_active);
        let ways = if include_ways { ways } else { Vec::new() };
        let rels = if include_rels { rels } else { Vec::new() };
        pass2_accumulate(&ways, &rels, way_enc, rel_enc, &mut out);
    }
    out
}

/// Parse decoded XML bytes into a pass-2 segment (resolved ways + relations).
/// Shared by the bz2 and gz typed codecs. The segment's complete (middle)
/// ways/rels are Arrow-built + zstd-encoded ON THE WORKER (via the per-worker
/// accumulators); only the boundary stubs travel raw to the collector, which
/// stitches the straddling element(s) into its own (tiny) stub accumulator.
#[allow(clippy::too_many_arguments)]
fn pass2_parse_decoded(
    decoded: &[u8],
    store: &Arc<NodeStore>,
    backend: &dyn GpuBackend,
    include_ways: bool,
    include_rels: bool,
    way_enc: Option<&writer::ColumnEncoder>,
    rel_enc: Option<&writer::ColumnEncoder>,
    clip_active: bool,
) -> P2Segment {
    if decoded.is_empty() {
        return P2Segment::default();
    }

    let first = xml_vtd::find_top_level_start(decoded, 0);
    let last = xml_vtd::find_safe_slot_end(decoded);
    let last = last.max(first);

    let left_stub = decoded[..first].to_vec();
    let right_stub = decoded[last..].to_vec();
    let middle = &decoded[first..last];

    let mut elems: Vec<ElemIndex> = Vec::new();
    xml_vtd::build_elem_index_slice(middle, 0, &mut |e| {
        if matches!(e.kind, ElemKind::Way | ElemKind::Relation) {
            elems.push(e);
        }
    });

    if elems.is_empty() {
        return P2Segment {
            left_stub,
            right_stub,
            ..P2Segment::default()
        };
    }

    let refs: Vec<&ElemIndex> = elems.iter().collect();
    let chunks = plan_chunks(&refs, MAX_CHUNK_BYTES);

    let mut all_ways: Vec<CollectedWay> = Vec::new();
    let mut all_rels: Vec<RelationRecord> = Vec::new();
    for (lo, hi) in chunks {
        let (ways, rels) = parse_chunk(middle, &refs[lo..hi], store, 0, clip_active);
        all_ways.extend(ways);
        all_rels.extend(rels);
    }

    let ways = if include_ways {
        collected_to_way_records(all_ways, backend)
    } else {
        Vec::new()
    };
    let rels = if include_rels { all_rels } else { Vec::new() };

    let mut out = P2Segment::default();
    pass2_accumulate(&ways, &rels, way_enc, rel_enc, &mut out);
    out.left_stub = left_stub;
    out.right_stub = right_stub;
    out
}

impl gatling::TypedCodec for Bz2Pass1TypedCodec {
    type Seg = (u64, u64);
    type Output = P1Segment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<(u64, u64)>> {
        let s = lbzip2::chunk::split_chunk(data, n_workers, self.max_blocksize, is_last)?;
        let total_bits = data.len() as u64 * 8;
        let n_seg = s.segment_starts.len();
        let segments = (0..s.decode_segments)
            .map(|i| {
                let start = s.segment_starts[i].bit_offset;
                let end = if i + 1 < n_seg {
                    s.segment_starts[i + 1].bit_offset
                } else {
                    total_bits
                };
                (start, end)
            })
            .collect();
        Some(gatling::Split {
            segments,
            consumed: s.consumed,
        })
    }

    fn transform(&self, data: &[u8], &(start_bit, end_bit): &(u64, u64)) -> P1Segment {
        let decoded = lbzip2::chunk::decode_segment(data, start_bit, end_bit, self.max_blocksize);
        let enc = if self.include_nodes {
            self.node_encoder.as_ref()
        } else {
            None
        };
        pass1_parse_decoded(&decoded, self.include_nodes, enc, self.clip.as_deref())
    }

    fn finish_worker(&self) -> Option<P1Segment> {
        pass1_finish_worker(self.include_nodes, self.node_encoder.as_ref())
    }
}

/// gzip pass-1 [`gatling::TypedCodec`]: DEFLATE decode + node parse fused in the
/// worker. Mirrors [`Bz2Pass1TypedCodec`] but with lgz flush-boundary splits.
struct GzPass1TypedCodec {
    include_nodes: bool,
    node_encoder: Option<writer::NodeColumnEncoder>,
    clip: Option<Arc<crate::Clip>>,
}

impl gatling::TypedCodec for GzPass1TypedCodec {
    type Seg = (usize, usize);
    type Output = P1Segment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<(usize, usize)>> {
        crate::xml_to_pbf::gz_split(data, n_workers, is_last)
    }

    fn transform(&self, data: &[u8], seg: &(usize, usize)) -> P1Segment {
        let decoded = crate::xml_to_pbf::gz_decode_segment(data, seg);
        let enc = if self.include_nodes {
            self.node_encoder.as_ref()
        } else {
            None
        };
        pass1_parse_decoded(&decoded, self.include_nodes, enc, self.clip.as_deref())
    }

    fn finish_worker(&self) -> Option<P1Segment> {
        pass1_finish_worker(self.include_nodes, self.node_encoder.as_ref())
    }
}

/// Uncompressed `.osm` pass-1 (the `read_resolved_osm` entry). Identical to the
/// bz2/gz pass-1 codecs but with NO decode step — the slot bytes are already XML,
/// so `transform` slices its element-aligned segment and runs the shared
/// [`pass1_parse_decoded`]. This replaced the old serial `Pass1ResolvedCodec` +
/// per-record `NodeAccumulator` on the collector, which pegged raw `.osm` convert
/// at ~3 cores (workers starved while the single sink built + wrote every node
/// batch). Nodes are now Arrow-built + zstd-encoded on the workers; the sink only
/// stitches pre-compressed row groups + `write_raw`s the packed coords.
struct RawXmlPass1Codec {
    include_nodes: bool,
    node_encoder: Option<writer::NodeColumnEncoder>,
    clip: Option<Arc<crate::Clip>>,
}

impl gatling::TypedCodec for RawXmlPass1Codec {
    type Seg = (usize, usize);
    type Output = P1Segment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<(usize, usize)>> {
        xml_split_typed(data, n_workers, is_last)
    }

    fn transform(&self, data: &[u8], seg: &(usize, usize)) -> P1Segment {
        let enc = if self.include_nodes {
            self.node_encoder.as_ref()
        } else {
            None
        };
        pass1_parse_decoded(
            &data[seg.0..seg.1],
            self.include_nodes,
            enc,
            self.clip.as_deref(),
        )
    }

    fn finish_worker(&self) -> Option<P1Segment> {
        pass1_finish_worker(self.include_nodes, self.node_encoder.as_ref())
    }
}

// ── Pass-2 TypedCodec ─────────────────────────────────────────────────────────

struct Bz2Pass2TypedCodec<'a> {
    max_blocksize: u32,
    include_ways: bool,
    include_rels: bool,
    store: Arc<NodeStore>,
    backend: &'a dyn GpuBackend,
    way_enc: Option<writer::ColumnEncoder>,
    rel_enc: Option<writer::ColumnEncoder>,
    clip_active: bool,
}

impl gatling::TypedCodec for Bz2Pass2TypedCodec<'_> {
    type Seg = (u64, u64);
    type Output = P2Segment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<(u64, u64)>> {
        let s = lbzip2::chunk::split_chunk(data, n_workers, self.max_blocksize, is_last)?;
        let total_bits = data.len() as u64 * 8;
        let n_seg = s.segment_starts.len();
        let segments = (0..s.decode_segments)
            .map(|i| {
                let start = s.segment_starts[i].bit_offset;
                let end = if i + 1 < n_seg {
                    s.segment_starts[i + 1].bit_offset
                } else {
                    total_bits
                };
                (start, end)
            })
            .collect();
        Some(gatling::Split {
            segments,
            consumed: s.consumed,
        })
    }

    fn transform(&self, data: &[u8], &(start_bit, end_bit): &(u64, u64)) -> P2Segment {
        let decoded = lbzip2::chunk::decode_segment(data, start_bit, end_bit, self.max_blocksize);
        pass2_parse_decoded(
            &decoded,
            &self.store,
            self.backend,
            self.include_ways,
            self.include_rels,
            self.way_enc.as_ref(),
            self.rel_enc.as_ref(),
            self.clip_active,
        )
    }

    fn finish_worker(&self) -> Option<P2Segment> {
        pass2_finish_worker(self.way_enc.as_ref(), self.rel_enc.as_ref())
    }
}

/// gzip pass-2 [`gatling::TypedCodec`]: DEFLATE decode + way/relation resolve
/// fused in the worker. Mirrors [`Bz2Pass2TypedCodec`] with lgz splits.
struct GzPass2TypedCodec<'a> {
    include_ways: bool,
    include_rels: bool,
    store: Arc<NodeStore>,
    backend: &'a dyn GpuBackend,
    way_enc: Option<writer::ColumnEncoder>,
    rel_enc: Option<writer::ColumnEncoder>,
    clip_active: bool,
}

impl gatling::TypedCodec for GzPass2TypedCodec<'_> {
    type Seg = (usize, usize);
    type Output = P2Segment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<(usize, usize)>> {
        crate::xml_to_pbf::gz_split(data, n_workers, is_last)
    }

    fn transform(&self, data: &[u8], seg: &(usize, usize)) -> P2Segment {
        let decoded = crate::xml_to_pbf::gz_decode_segment(data, seg);
        pass2_parse_decoded(
            &decoded,
            &self.store,
            self.backend,
            self.include_ways,
            self.include_rels,
            self.way_enc.as_ref(),
            self.rel_enc.as_ref(),
            self.clip_active,
        )
    }

    fn finish_worker(&self) -> Option<P2Segment> {
        pass2_finish_worker(self.way_enc.as_ref(), self.rel_enc.as_ref())
    }
}

// ── PBF TypedCodecs ───────────────────────────────────────────────────────────
//
// PBF blobs are self-contained: `split` cuts the slot at blob frame boundaries
// (pbf_io), `transform` zlib+protobuf-decodes one blob into a P1/P2 segment.
// No boundary stubs (blobs never straddle a logical element), so the shared
// Pass1TypedSink / Pass2TypedSink consume them with empty stubs — unifying PBF
// onto the same coord-sort / node-store path as bz2 and gz.

struct PbfPass1TypedCodec {
    include_nodes: bool,
    node_encoder: Option<writer::NodeColumnEncoder>,
    clip: Option<Arc<crate::Clip>>,
}

impl gatling::TypedCodec for PbfPass1TypedCodec {
    type Seg = (usize, usize);
    type Output = P1Segment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<(usize, usize)>> {
        crate::xml_to_pbf::pbf_split(data, n_workers, is_last)
    }

    fn transform(&self, data: &[u8], seg: &(usize, usize)) -> P1Segment {
        let enc = if self.include_nodes {
            self.node_encoder.as_ref()
        } else {
            None
        };
        pass1_parse_blob(data, seg, self.include_nodes, enc, self.clip.as_deref())
    }

    fn finish_worker(&self) -> Option<P1Segment> {
        pass1_finish_worker(self.include_nodes, self.node_encoder.as_ref())
    }
}

struct PbfPass2TypedCodec {
    include_ways: bool,
    include_rels: bool,
    store: Arc<NodeStore>,
    /// Shared column encoders handed to every worker so the Arrow build + zstd
    /// encode of the way/rel row groups runs in PARALLEL on the workers, not on
    /// the single collector (the pass-2 saturation fix). `None` when the
    /// corresponding output is disabled.
    way_enc: Option<writer::ColumnEncoder>,
    rel_enc: Option<writer::ColumnEncoder>,
    /// True when a region clip is active: pass-2 then drops ways with zero
    /// resolvable (in-region) coords (node-membership clip semantics).
    clip_active: bool,
}

impl gatling::TypedCodec for PbfPass2TypedCodec {
    type Seg = (usize, usize);
    type Output = P2Segment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<(usize, usize)>> {
        crate::xml_to_pbf::pbf_split(data, n_workers, is_last)
    }

    fn transform(&self, data: &[u8], seg: &(usize, usize)) -> P2Segment {
        pass2_parse_blob(
            data,
            seg,
            &self.store,
            self.include_ways,
            self.include_rels,
            self.way_enc.as_ref(),
            self.rel_enc.as_ref(),
            self.clip_active,
        )
    }

    fn finish_worker(&self) -> Option<P2Segment> {
        pass2_finish_worker(self.way_enc.as_ref(), self.rel_enc.as_ref())
    }
}

struct Pass1TypedSink {
    coord_writer: CoordFileWriter,
    node_acc: Option<writer::NodeAccumulator>,
    /// Encodes the (tiny) boundary-stub node batches on the collector thread.
    node_encoder: Option<writer::NodeColumnEncoder>,
    /// Stitches pre-compressed row groups (from workers + boundary stubs) into
    /// the file. No compression on this thread.
    node_writer: Option<writer::ParallelNodeWriter>,
    node_count: usize,
    pb: indicatif::ProgressBar,
    prev_stub: Vec<u8>, // right_stub from last segment; combined with next left_stub
    include_nodes: bool,
    /// Optional shared `busy_ns` counter for the surrounding `Phase`.
    busy_ns: Option<Arc<std::sync::atomic::AtomicU64>>,
}

impl Pass1TypedSink {
    fn flush_stub(&mut self, stub: &[u8]) -> Result<()> {
        if stub.is_empty() {
            return Ok(());
        }
        let mut packed = Vec::new();
        xml_vtd::build_elem_index_slice(stub, 0, &mut |e| {
            if e.kind == ElemKind::Node {
                let lat = e.lat_e7 as f32 / 1e7_f32;
                let lon = e.lon_e7 as f32 / 1e7_f32;
                packed.extend_from_slice(&e.id.to_le_bytes());
                packed.extend_from_slice(&lat.to_le_bytes());
                packed.extend_from_slice(&lon.to_le_bytes());
                self.node_count += 1;
                if self.include_nodes {
                    if let Some(acc) = self.node_acc.as_mut() {
                        let lo = e.file_offset as usize;
                        let hi = lo.saturating_add(e.file_length as usize).min(stub.len());
                        let b = stub.get(lo..hi).unwrap_or_default();
                        acc.push(&NodeRecord {
                            id: e.id,
                            lon_lat: (f64::from(lon), f64::from(lat)),
                            tags_json: parse_tags_json(b),
                            version: parse_attr_i32(opening_tag(b), b"version"),
                        });
                    }
                }
            }
        });
        self.coord_writer.write_raw(&packed)?;
        if let (Some(acc), Some(enc), Some(w)) = (
            self.node_acc.as_mut(),
            self.node_encoder.as_ref(),
            self.node_writer.as_mut(),
        ) {
            while let Some(batch) = acc.take_if_full()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(CoordFileWriter, usize)> {
        let stub = std::mem::take(&mut self.prev_stub);
        self.flush_stub(&stub)?;
        if let (Some(acc), Some(enc), Some(w)) = (
            self.node_acc.as_mut(),
            self.node_encoder.as_ref(),
            self.node_writer.as_mut(),
        ) {
            if let Some(batch) = acc.take_remaining()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        if let Some(w) = self.node_writer.take() {
            w.finish()?;
        }
        Ok((self.coord_writer, self.node_count))
    }
}

impl gatling::TypedSink<P1Segment> for Pass1TypedSink {
    fn process(&mut self, seg: P1Segment, _is_last: bool) -> Result<()> {
        let t0 = std::time::Instant::now();
        // Combine right_stub from previous segment with this segment's left_stub,
        // then parse any complete element that straddles the segment boundary.
        let boundary = [self.prev_stub.as_slice(), seg.left_stub.as_slice()].concat();
        self.flush_stub(&boundary)?;

        // Main records: write the packed coords, then stitch the pre-compressed
        // node row groups the worker already encoded. No Arrow append, no zstd
        // on this thread.
        self.coord_writer.write_raw(&seg.packed)?;
        self.node_count += seg.packed.len() / 16;
        if let Some(w) = self.node_writer.as_mut() {
            for rg in seg.node_row_groups {
                w.append(rg)?;
            }
        }
        self.pb
            .inc((seg.left_stub.len() + seg.packed.len() / 16 * 220 + seg.right_stub.len()) as u64);

        self.prev_stub = seg.right_stub;
        if let Some(b) = &self.busy_ns {
            b.fetch_add(
                t0.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        Ok(())
    }
}

// ── Pass-2 TypedSink ──────────────────────────────────────────────────────────
//
// Workers build WayRecord + RelationRecord per segment (in parallel, including
// WKB encode via the GpuBackend). The collector pushes them through an
// Arrow-builder accumulator and ships full row-group RecordBatches over a
// channel to a dedicated `ParquetSink` writer thread — the actual parquet
// encode + zstd + disk write happens off the hot path.
//
// Without this routing the collector calls `WayWriter::push` per row, which
// hits `writer.write(&batch)` synchronously every ROW_GROUP_SIZE rows and
// pegged pass-2 at ~5 cores on planet (workers blocked on collector_tx.send
// while collector was inside parquet flush). See backlog.md / commit history.

struct Pass2TypedSink<'a> {
    store: Arc<NodeStore>,
    backend: &'a dyn GpuBackend,
    /// Tiny accumulator for boundary-stub ways parsed ON THE COLLECTOR (a few
    /// rows per segment boundary); full groups are encoded with `way_encoder`
    /// here, but this is negligible work next to the workers' bulk.
    way_acc: Option<writer::WayAccumulator>,
    rel_acc: Option<writer::RelAccumulator>,
    /// Column encoders: encode the (rare) stub batches on the collector and are
    /// the SAME encoders the workers hold for the bulk row groups.
    way_encoder: Option<writer::ColumnEncoder>,
    rel_encoder: Option<writer::ColumnEncoder>,
    /// In-order row-group stitchers (no compression here). They append both the
    /// workers' pre-encoded bulk row groups and the collector's stub groups.
    way_writer: Option<writer::ParallelRowGroupWriter>,
    rel_writer: Option<writer::ParallelRowGroupWriter>,
    way_count: usize,
    rel_count: usize,
    pb: indicatif::ProgressBar,
    prev_stub: Vec<u8>,
    include_ways: bool,
    busy_ns: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// Region clip active — boundary-stub ways with zero in-region coords are
    /// dropped here too, matching the worker path.
    clip_active: bool,
}

impl Pass2TypedSink<'_> {
    /// Append the pre-encoded bulk row groups the worker produced for one
    /// segment — pure stitch + I/O, no compression on the collector.
    fn append_segment_groups(&mut self, seg: &mut P2Segment) -> Result<()> {
        if let Some(w) = self.way_writer.as_mut() {
            for rg in std::mem::take(&mut seg.way_row_groups) {
                w.append(rg)?;
            }
        }
        if let Some(w) = self.rel_writer.as_mut() {
            for rg in std::mem::take(&mut seg.rel_row_groups) {
                w.append(rg)?;
            }
        }
        self.way_count += seg.way_rows;
        self.rel_count += seg.rel_rows;
        Ok(())
    }

    fn flush_stub(&mut self, stub: &[u8]) -> Result<()> {
        if stub.is_empty() {
            return Ok(());
        }
        let mut elems: Vec<ElemIndex> = Vec::new();
        xml_vtd::build_elem_index_slice(stub, 0, &mut |e| {
            if matches!(e.kind, ElemKind::Way | ElemKind::Relation) {
                elems.push(e);
            }
        });
        if elems.is_empty() {
            return Ok(());
        }
        let refs: Vec<&ElemIndex> = elems.iter().collect();
        let (ways, rels) = parse_chunk(stub, &refs, &self.store, 0, self.clip_active);
        let ways = if self.include_ways {
            collected_to_way_records(ways, self.backend)
        } else {
            Vec::new()
        };
        self.way_count += ways.len();
        self.rel_count += rels.len();
        if let (Some(acc), Some(enc), Some(w)) = (
            self.way_acc.as_mut(),
            self.way_encoder.as_ref(),
            self.way_writer.as_mut(),
        ) {
            for r in &ways {
                acc.push(r);
            }
            while let Some(batch) = acc.take_if_full()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        if let (Some(acc), Some(enc), Some(w)) = (
            self.rel_acc.as_mut(),
            self.rel_encoder.as_ref(),
            self.rel_writer.as_mut(),
        ) {
            for r in &rels {
                acc.push(r);
            }
            while let Some(batch) = acc.take_if_full()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(usize, usize)> {
        let stub = std::mem::take(&mut self.prev_stub);
        self.flush_stub(&stub)?;
        // Drain the collector's stub remainders.
        if let (Some(acc), Some(enc), Some(w)) = (
            self.way_acc.as_mut(),
            self.way_encoder.as_ref(),
            self.way_writer.as_mut(),
        ) {
            if let Some(batch) = acc.take_remaining()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        if let (Some(acc), Some(enc), Some(w)) = (
            self.rel_acc.as_mut(),
            self.rel_encoder.as_ref(),
            self.rel_writer.as_mut(),
        ) {
            if let Some(batch) = acc.take_remaining()? {
                w.append(enc.encode(&batch)?)?;
            }
        }
        if let Some(w) = self.way_writer.take() {
            w.finish()?;
        }
        if let Some(w) = self.rel_writer.take() {
            w.finish()?;
        }
        Ok((self.way_count, self.rel_count))
    }
}

/// Build a parallel pass-2 sink (workers encode, collector stitches) together
/// with the shared way/rel column encoders to hand to the codec's workers.
/// Shared by all four resolved readers (pbf / bz2 / gz / osm).
fn build_pass2_sink<'a>(
    out_dir: &Path,
    compression: &str,
    store: &Arc<NodeStore>,
    backend: &'a dyn GpuBackend,
    include_ways: bool,
    include_rels: bool,
    pb: indicatif::ProgressBar,
    busy_ns: Option<Arc<std::sync::atomic::AtomicU64>>,
    clip_active: bool,
) -> Result<(
    Pass2TypedSink<'a>,
    Option<writer::ColumnEncoder>,
    Option<writer::ColumnEncoder>,
)> {
    let (way_encoder, way_writer) = if include_ways {
        let (e, w) = writer::parallel_way_writer(&out_dir.join("ways.parquet"), compression)?;
        (Some(e), Some(w))
    } else {
        (None, None)
    };
    let (rel_encoder, rel_writer) = if include_rels {
        let (e, w) = writer::parallel_rel_writer(&out_dir.join("relations.parquet"), compression)?;
        (Some(e), Some(w))
    } else {
        (None, None)
    };
    let way_acc = if include_ways {
        Some(writer::WayAccumulator::new())
    } else {
        None
    };
    let rel_acc = if include_rels {
        Some(writer::RelAccumulator::new())
    } else {
        None
    };
    let sink = Pass2TypedSink {
        store: Arc::clone(store),
        backend,
        way_acc,
        rel_acc,
        way_encoder: way_encoder.clone(),
        rel_encoder: rel_encoder.clone(),
        way_writer,
        rel_writer,
        way_count: 0,
        rel_count: 0,
        pb,
        prev_stub: Vec::new(),
        include_ways,
        busy_ns,
        clip_active,
    };
    Ok((sink, way_encoder, rel_encoder))
}

impl gatling::TypedSink<P2Segment> for Pass2TypedSink<'_> {
    fn process(&mut self, mut seg: P2Segment, _is_last: bool) -> Result<()> {
        let t0 = std::time::Instant::now();
        let boundary = [self.prev_stub.as_slice(), seg.left_stub.as_slice()].concat();
        self.flush_stub(&boundary)?;

        let prog = seg.left_stub.len() + seg.way_rows * 512 + seg.right_stub.len();
        self.append_segment_groups(&mut seg)?;
        self.pb.inc(prog as u64);

        self.prev_stub = seg.right_stub;
        if let Some(b) = &self.busy_ns {
            b.fetch_add(
                t0.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        Ok(())
    }
}

/// Resolved 2-pass `.osm.bz2` → GeoParquet on the Gatling engine.
///
/// Pass 1 (engine pass): stream node coords to `node_coords.bin` + nodes.parquet, then
/// sort into a `NodeStore`. Pass 2 (engine pass): resolve way/relation geometry against
/// the store → ways/relations.parquet. Each pass is one parallel bz2 decode through the
/// engine. Returns `(node_count, way_count, rel_count)`.
#[allow(clippy::too_many_arguments)]
pub fn read_resolved_bz2(
    input: &Path,
    out_dir: &Path,
    compression: &str,
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    n_workers: usize,
    skip_to_nodes: bool,
    pb: indicatif::ProgressBar,
    backend: &dyn GpuBackend,
    sink: Option<&crate::phase_log::PhaseSink>,
    clip: Option<Arc<crate::Clip>>,
) -> Result<(usize, usize, usize)> {
    use crate::xml_to_pbf::{Bz2Prepared, Bz2Skip, bz2_prepare, mk_bz2_cfg};
    let n_workers_str = n_workers.to_string();

    // ── Pass 1: node coords + node records (TypedCodec — decode+parse per worker) ─
    pb.set_message("pass 1/2  (coords)");
    let p1_phase = sink.map(|s| s.phase("pass1", &[("workers", &n_workers_str)]));
    let (node_encoder, node_writer) = if include_nodes {
        let (enc, w) = writer::parallel_node_writer(&out_dir.join("nodes.parquet"), compression)?;
        (Some(enc), Some(w))
    } else {
        (None, None)
    };
    let node_acc = if include_nodes {
        Some(writer::NodeAccumulator::new())
    } else {
        None
    };
    let mut p1 = Pass1TypedSink {
        coord_writer: CoordFileWriter::new(&out_dir.join("node_coords.bin"))?,
        node_acc,
        node_encoder: node_encoder.clone(),
        node_writer,
        node_count: 0,
        pb: pb.clone(),
        prev_stub: Vec::new(),
        include_nodes,
        busy_ns: p1_phase.as_ref().map(|p| Arc::clone(&p.busy_ns)),
    };
    {
        let skip = if skip_to_nodes {
            Bz2Skip::Changesets(crate::xml_to_pbf::DATA_NEEDLES)
        } else {
            Bz2Skip::None
        };
        let Bz2Prepared {
            reader,
            max_blocksize,
            initial_carry,
        } = bz2_prepare(input, skip)?;
        let codec = Bz2Pass1TypedCodec {
            max_blocksize,
            include_nodes,
            node_encoder,
            clip: clip.clone(),
        };
        gatling::run_typed(reader, codec, &mut p1, n_workers, mk_bz2_cfg(initial_carry))?;
    }
    let (coord_writer, node_count) = p1.finish()?;
    if let Some(p) = p1_phase {
        let coord_bytes = std::fs::metadata(out_dir.join("node_coords.bin"))
            .map(|m| m.len())
            .unwrap_or(0);
        let parquet_bytes = std::fs::metadata(out_dir.join("nodes.parquet"))
            .map(|m| m.len())
            .unwrap_or(0);
        p.done(&[
            ("nodes", node_count.to_string()),
            ("coord_bytes", coord_bytes.to_string()),
            ("parquet_bytes", parquet_bytes.to_string()),
        ]);
    }

    pb.set_message("sorting node coords …");
    let sort_phase = sink.map(|s| s.phase("sort_and_stree", &[("nodes", &node_count.to_string())]));
    let store = Arc::new(coord_writer.finalize()?);
    if let Some(p) = sort_phase {
        p.done(&[("note", "psort-samplesort".into())]);
    }

    // ── Pass 2: ways + relations resolved (TypedCodec — decode+parse per worker) ──
    // Uses seek_past_nodes (finds last <node> block + 1) rather than seeking for <way>,
    // which fails on large ways that span entire bz2 blocks (no <way> opening tag in block).
    pb.set_message(format!("pass 2/2  ({} nodes)", store.len()));
    let p2_phase = sink.map(|s| {
        s.phase(
            "pass2",
            &[
                ("workers", &n_workers_str),
                ("store_nodes", &store.len().to_string()),
            ],
        )
    });
    let (mut p2, way_enc, rel_enc) = build_pass2_sink(
        out_dir,
        compression,
        &store,
        backend,
        include_ways,
        include_rels,
        pb.clone(),
        p2_phase.as_ref().map(|p| Arc::clone(&p.busy_ns)),
        clip.is_some(),
    )?;
    {
        let skip = if skip_to_nodes {
            Bz2Skip::Nodes
        } else {
            Bz2Skip::None
        };
        let Bz2Prepared {
            reader,
            max_blocksize,
            initial_carry,
        } = bz2_prepare(input, skip)?;
        let codec = Bz2Pass2TypedCodec {
            max_blocksize,
            include_ways,
            include_rels,
            store: Arc::clone(&store),
            backend,
            way_enc,
            rel_enc,
            clip_active: clip.is_some(),
        };
        gatling::run_typed(reader, codec, &mut p2, n_workers, mk_bz2_cfg(initial_carry))?;
    }
    let (way_count, rel_count) = p2.finish()?;
    if let Some(p) = p2_phase {
        let way_bytes = std::fs::metadata(out_dir.join("ways.parquet"))
            .map(|m| m.len())
            .unwrap_or(0);
        let rel_bytes = std::fs::metadata(out_dir.join("relations.parquet"))
            .map(|m| m.len())
            .unwrap_or(0);
        p.done(&[
            ("ways", way_count.to_string()),
            ("rels", rel_count.to_string()),
            ("way_bytes", way_bytes.to_string()),
            ("rel_bytes", rel_bytes.to_string()),
        ]);
    }

    Ok((node_count, way_count, rel_count))
}

/// Raw single-pass `.osm.gz` → GeoParquet on the Gatling engine.
///
/// The engine decodes DEFLATE in parallel where the gzip stream has full-flush
/// boundaries (pigz/bgzf); standard single-stream gzip decodes as one segment.
/// Hands contiguous XML to [`RawParquetSink`]. Mirrors [`read_raw_bz2`].
#[allow(clippy::too_many_arguments)]
pub fn read_raw_gz(
    input: &Path,
    out_dir: &Path,
    compression: &str,
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    n_workers: usize,
    pb: indicatif::ProgressBar,
) -> Result<(usize, usize, usize)> {
    let (mut sink, encoders) = raw_typed_sink(
        out_dir,
        compression,
        include_nodes,
        include_ways,
        include_rels,
        pb,
    )?;
    let codec = RawGzParquetTypedCodec {
        include_nodes,
        include_ways,
        include_rels,
        node_encoder: encoders.node,
        way_encoder: encoders.way,
        rel_encoder: encoders.rel,
    };
    crate::xml_to_pbf::gz_gatling_run_typed(input, codec, &mut sink, n_workers)?;
    sink.finish()
}

/// Resolved 2-pass `.osm.gz` → GeoParquet on the Gatling engine.
///
/// Mirrors [`read_resolved_bz2`]: pass 1 streams node coords + nodes.parquet and
/// sorts into a `NodeStore`; pass 2 resolves way/relation geometry. Each pass is
/// one parallel DEFLATE decode through the engine via the gz typed codecs.
#[allow(clippy::too_many_arguments)]
pub fn read_resolved_gz(
    input: &Path,
    out_dir: &Path,
    compression: &str,
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    n_workers: usize,
    pb: indicatif::ProgressBar,
    backend: &dyn GpuBackend,
    sink: Option<&crate::phase_log::PhaseSink>,
    clip: Option<Arc<crate::Clip>>,
) -> Result<(usize, usize, usize)> {
    let n_workers_str = n_workers.to_string();

    // ── Pass 1: node coords + node records ───────────────────────────────────
    pb.set_message("pass 1/2  (coords)");
    let p1_phase = sink.map(|s| s.phase("pass1", &[("workers", &n_workers_str)]));
    let (node_encoder, node_writer) = if include_nodes {
        let (enc, w) = writer::parallel_node_writer(&out_dir.join("nodes.parquet"), compression)?;
        (Some(enc), Some(w))
    } else {
        (None, None)
    };
    let node_acc = if include_nodes {
        Some(writer::NodeAccumulator::new())
    } else {
        None
    };
    let mut p1 = Pass1TypedSink {
        coord_writer: CoordFileWriter::new(&out_dir.join("node_coords.bin"))?,
        node_acc,
        node_encoder: node_encoder.clone(),
        node_writer,
        node_count: 0,
        pb: pb.clone(),
        prev_stub: Vec::new(),
        include_nodes,
        busy_ns: p1_phase.as_ref().map(|p| Arc::clone(&p.busy_ns)),
    };
    {
        let codec = GzPass1TypedCodec {
            include_nodes,
            node_encoder,
            clip: clip.clone(),
        };
        crate::xml_to_pbf::gz_gatling_run_typed(input, codec, &mut p1, n_workers)?;
    }
    let (coord_writer, node_count) = p1.finish()?;
    if let Some(p) = p1_phase {
        let coord_bytes = std::fs::metadata(out_dir.join("node_coords.bin"))
            .map(|m| m.len())
            .unwrap_or(0);
        let parquet_bytes = std::fs::metadata(out_dir.join("nodes.parquet"))
            .map(|m| m.len())
            .unwrap_or(0);
        p.done(&[
            ("nodes", node_count.to_string()),
            ("coord_bytes", coord_bytes.to_string()),
            ("parquet_bytes", parquet_bytes.to_string()),
        ]);
    }

    pb.set_message("sorting node coords …");
    let sort_phase = sink.map(|s| s.phase("sort_and_stree", &[("nodes", &node_count.to_string())]));
    let store = Arc::new(coord_writer.finalize()?);
    if let Some(p) = sort_phase {
        p.done(&[("note", "psort-samplesort".into())]);
    }

    // ── Pass 2: ways + relations resolved ────────────────────────────────────
    pb.set_message(format!("pass 2/2  ({} nodes)", store.len()));
    let p2_phase = sink.map(|s| {
        s.phase(
            "pass2",
            &[
                ("workers", &n_workers_str),
                ("store_nodes", &store.len().to_string()),
            ],
        )
    });
    let (mut p2, way_enc, rel_enc) = build_pass2_sink(
        out_dir,
        compression,
        &store,
        backend,
        include_ways,
        include_rels,
        pb.clone(),
        p2_phase.as_ref().map(|p| Arc::clone(&p.busy_ns)),
        clip.is_some(),
    )?;
    {
        let codec = GzPass2TypedCodec {
            include_ways,
            include_rels,
            store: Arc::clone(&store),
            backend,
            way_enc,
            rel_enc,
            clip_active: clip.is_some(),
        };
        crate::xml_to_pbf::gz_gatling_run_typed(input, codec, &mut p2, n_workers)?;
    }
    let (way_count, rel_count) = p2.finish()?;
    if let Some(p) = p2_phase {
        let way_bytes = std::fs::metadata(out_dir.join("ways.parquet"))
            .map(|m| m.len())
            .unwrap_or(0);
        let rel_bytes = std::fs::metadata(out_dir.join("relations.parquet"))
            .map(|m| m.len())
            .unwrap_or(0);
        p.done(&[
            ("ways", way_count.to_string()),
            ("rels", rel_count.to_string()),
            ("way_bytes", way_bytes.to_string()),
            ("rel_bytes", rel_bytes.to_string()),
        ]);
    }

    Ok((node_count, way_count, rel_count))
}

/// Resolved 2-pass `.pbf` → GeoParquet on the Gatling engine (NO rayon).
///
/// Each pass reads the file once; `split` cuts the byte stream at PBF blob frame
/// boundaries and workers zlib+protobuf-decode one blob each. Pass 1 fuses node
/// coord extraction (→ `node_coords.bin`, sorted into a `NodeStore`) and
/// nodes.parquet encoding (per-worker row groups); pass 2 resolves way/relation
/// geometry against the store. Reuses the shared [`Pass1TypedSink`] /
/// [`Pass2TypedSink`], so PBF now shares the exact coord-sort / node-store path
/// as the bz2 and gz converters. Returns `(node_count, way_count, rel_count)`.
#[allow(clippy::too_many_arguments)]
pub fn read_resolved_pbf(
    input: &Path,
    out_dir: &Path,
    compression: &str,
    include_nodes: bool,
    include_ways: bool,
    include_rels: bool,
    n_workers: usize,
    pb: indicatif::ProgressBar,
    backend: &dyn GpuBackend,
    sink: Option<&crate::phase_log::PhaseSink>,
    clip: Option<Arc<crate::Clip>>,
) -> Result<(usize, usize, usize)> {
    let n_workers_str = n_workers.to_string();

    // ── Pass 1: node coords + node records (decode+parse per worker) ─────────
    pb.set_message("pass 1/2  (coords)");
    let p1_phase = sink.map(|s| s.phase("pass1", &[("workers", &n_workers_str)]));
    let (node_encoder, node_writer) = if include_nodes {
        let (enc, w) = writer::parallel_node_writer(&out_dir.join("nodes.parquet"), compression)?;
        (Some(enc), Some(w))
    } else {
        (None, None)
    };
    let node_acc = if include_nodes {
        Some(writer::NodeAccumulator::new())
    } else {
        None
    };
    let mut p1 = Pass1TypedSink {
        coord_writer: CoordFileWriter::new(&out_dir.join("node_coords.bin"))?,
        node_acc,
        node_encoder: node_encoder.clone(),
        node_writer,
        node_count: 0,
        pb: pb.clone(),
        prev_stub: Vec::new(),
        include_nodes,
        busy_ns: p1_phase.as_ref().map(|p| Arc::clone(&p.busy_ns)),
    };
    {
        let codec = PbfPass1TypedCodec {
            include_nodes,
            node_encoder,
            clip: clip.clone(),
        };
        crate::xml_to_pbf::pbf_gatling_run_typed(input, codec, &mut p1, n_workers)?;
    }
    let (coord_writer, node_count) = p1.finish()?;
    if let Some(p) = p1_phase {
        let coord_bytes = std::fs::metadata(out_dir.join("node_coords.bin"))
            .map(|m| m.len())
            .unwrap_or(0);
        let parquet_bytes = std::fs::metadata(out_dir.join("nodes.parquet"))
            .map(|m| m.len())
            .unwrap_or(0);
        p.done(&[
            ("nodes", node_count.to_string()),
            ("coord_bytes", coord_bytes.to_string()),
            ("parquet_bytes", parquet_bytes.to_string()),
        ]);
    }

    pb.set_message("sorting node coords …");
    let sort_phase = sink.map(|s| s.phase("sort_and_stree", &[("nodes", &node_count.to_string())]));
    let store = Arc::new(coord_writer.finalize()?);
    if let Some(p) = sort_phase {
        p.done(&[("note", "psort-samplesort".into())]);
    }

    // ── Pass 2: ways + relations resolved (decode+parse per worker) ──────────
    pb.set_message(format!("pass 2/2  ({} nodes)", store.len()));
    let p2_phase = sink.map(|s| {
        s.phase(
            "pass2",
            &[
                ("workers", &n_workers_str),
                ("store_nodes", &store.len().to_string()),
            ],
        )
    });
    let (mut p2, way_enc, rel_enc) = build_pass2_sink(
        out_dir,
        compression,
        &store,
        backend,
        include_ways,
        include_rels,
        pb.clone(),
        p2_phase.as_ref().map(|p| Arc::clone(&p.busy_ns)),
        clip.is_some(),
    )?;
    {
        let codec = PbfPass2TypedCodec {
            include_ways,
            include_rels,
            store: Arc::clone(&store),
            way_enc,
            rel_enc,
            clip_active: clip.is_some(),
        };
        crate::xml_to_pbf::pbf_gatling_run_typed(input, codec, &mut p2, n_workers)?;
    }
    let (way_count, rel_count) = p2.finish()?;
    if let Some(p) = p2_phase {
        let way_bytes = std::fs::metadata(out_dir.join("ways.parquet"))
            .map(|m| m.len())
            .unwrap_or(0);
        let rel_bytes = std::fs::metadata(out_dir.join("relations.parquet"))
            .map(|m| m.len())
            .unwrap_or(0);
        p.done(&[
            ("ways", way_count.to_string()),
            ("rels", rel_count.to_string()),
            ("way_bytes", way_bytes.to_string()),
            ("rel_bytes", rel_bytes.to_string()),
        ]);
    }

    Ok((node_count, way_count, rel_count))
}

// ── WKB encode helper ─────────────────────────────────────────────────────────

fn collected_to_way_records(
    collected: Vec<CollectedWay>,
    backend: &dyn GpuBackend,
) -> Vec<WayRecord> {
    // Gather indices of ways that have enough coords to encode.
    let encodable: Vec<usize> = collected
        .iter()
        .enumerate()
        .filter(|(_, w)| w.coords.len() >= 2)
        .map(|(i, _)| i)
        .collect();
    let raw: Vec<crate::shared::gpu_backend::RawWay> = encodable
        .iter()
        .map(|&i| crate::shared::gpu_backend::RawWay {
            coords: collected[i].coords.clone(),
            is_area: collected[i].is_area,
        })
        .collect();
    let mut wkbs = backend.encode_wkb(&raw).into_iter();
    let mut geoms: Vec<Option<Vec<u8>>> = vec![None; collected.len()];
    for &i in &encodable {
        geoms[i] = wkbs.next().flatten();
    }
    collected
        .into_iter()
        .zip(geoms)
        .map(|(w, geom)| WayRecord {
            id: w.id,
            geometry: geom,
            tags_json: w.tags_json,
            node_refs: w.node_refs,
            version: w.version,
        })
        .collect()
}

/// Decode the five standard XML character references. Everything else passes through.
fn unescape(raw: &[u8]) -> String {
    if memchr(b'&', raw).is_none() {
        return String::from_utf8_lossy(raw).into_owned();
    }
    String::from_utf8_lossy(raw)
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod raw_parallel_tests {
    //! FAIL-ON-BUG for the raw single-pass way/rel parallelization: ways and
    //! relations are now Arrow-built + zstd-encoded on the Gatling WORKERS (via
    //! the shared `WAY_ACC`/`REL_ACC` accumulators + `pass2_accumulate`) and
    //! stitched in order by the collector — instead of every batch funnelling
    //! through one `ParquetSink` writer thread. The output row SET must be
    //! unchanged: every node / way / relation in the input appears exactly once
    //! in the matching parquet, with no drops and no duplicates.
    //!
    //! Two inputs cover the change: a hermetic single-segment gz (worker encode
    //! + collector stitch + counts) and — when `bzip2` is installed — a
    //! multi-BLOCK bz2 that lbzip2 splits into several decode segments, so way/rel
    //! row groups are produced on MULTIPLE workers AND the cross-segment
    //! boundary-stub path (`flush_stub`) runs. Both share the raw code under test
    //! (`raw_parse_decoded` / `RawParallelParquetSink`).

    use std::collections::BTreeSet;
    use std::io::Write;

    use arrow::array::Int64Array;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    /// Deterministic synthetic OSM XML: nodes `1..=n_nodes`, ways `1..=n_ways`
    /// (each referencing 3 node ids), relations `1..=n_rels` (each with 2
    /// members). Emitted in canonical nodes→ways→relations order.
    fn synth_osm_xml(n_nodes: i64, n_ways: i64, n_rels: i64) -> String {
        let mut s = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<osm version=\"0.6\" generator=\"raw-parallel-test\">\n",
        );
        for id in 1..=n_nodes {
            let lat = 50.0 + (id as f64) * 1e-5;
            let lon = 8.0 + (id as f64) * 1e-5;
            s.push_str(&format!(
                "  <node id=\"{id}\" lat=\"{lat:.6}\" lon=\"{lon:.6}\" version=\"1\"><tag k=\"amenity\" v=\"bench\"/></node>\n"
            ));
        }
        for id in 1..=n_ways {
            let a = (id % n_nodes) + 1;
            let b = ((id + 1) % n_nodes) + 1;
            let c = ((id + 2) % n_nodes) + 1;
            s.push_str(&format!(
                "  <way id=\"{id}\" version=\"1\"><nd ref=\"{a}\"/><nd ref=\"{b}\"/><nd ref=\"{c}\"/><tag k=\"highway\" v=\"residential\"/></way>\n"
            ));
        }
        for id in 1..=n_rels {
            let m0 = (id % n_ways.max(1)) + 1;
            s.push_str(&format!(
                "  <relation id=\"{id}\" version=\"1\"><member type=\"way\" ref=\"{m0}\" role=\"outer\"/><member type=\"node\" ref=\"1\" role=\"\"/><tag k=\"type\" v=\"multipolygon\"/></relation>\n"
            ));
        }
        s.push_str("</osm>\n");
        s
    }

    /// Single-member gzip via flate2 (hermetic — no external tool). lgz decodes it
    /// as one segment (one worker); enough to prove the worker-encode + stitch +
    /// counting are correct through the changed code.
    fn gz_single(data: &[u8]) -> Vec<u8> {
        use flate2::{Compression, write::GzEncoder};
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn have(tool: &str) -> bool {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Set of `id` values (parquet Int64 `id` column) across all row groups.
    fn id_set(path: &std::path::Path) -> BTreeSet<i64> {
        let mut set = BTreeSet::new();
        let rdr = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).unwrap())
            .unwrap()
            .build()
            .unwrap();
        for batch in rdr {
            let batch = batch.unwrap();
            let col = batch
                .column_by_name("id")
                .expect("id column")
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("id is Int64");
            for i in 0..col.len() {
                set.insert(col.value(i));
            }
        }
        set
    }

    /// Assert the three parquet tables carry EXACTLY the input id sets (1..=n).
    fn assert_row_sets(out: &std::path::Path, n_nodes: i64, n_ways: i64, n_rels: i64) {
        assert_eq!(
            id_set(&out.join("nodes.parquet")),
            (1..=n_nodes).collect::<BTreeSet<_>>(),
            "node id set"
        );
        assert_eq!(
            id_set(&out.join("ways.parquet")),
            (1..=n_ways).collect::<BTreeSet<_>>(),
            "way id set"
        );
        assert_eq!(
            id_set(&out.join("relations.parquet")),
            (1..=n_rels).collect::<BTreeSet<_>>(),
            "relation id set"
        );
    }

    #[test]
    fn raw_gz_worker_encoded_ways_rels_preserve_row_set() {
        let (n_nodes, n_ways, n_rels) = (300i64, 200i64, 50i64);
        let xml = synth_osm_xml(n_nodes, n_ways, n_rels);
        let gz = gz_single(xml.as_bytes());

        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.osm.gz");
        std::fs::write(&input, &gz).unwrap();
        let out = dir.path().join("out");

        let (nodes, ways, rels) = super::read_raw_gz(
            &input,
            &out,
            "zstd",
            true,
            true,
            true,
            6,
            indicatif::ProgressBar::hidden(),
        )
        .expect("read_raw_gz");

        assert_eq!(nodes, n_nodes as usize, "node count");
        assert_eq!(ways, n_ways as usize, "way count");
        assert_eq!(rels, n_rels as usize, "relation count");
        assert_row_sets(&out, n_nodes, n_ways, n_rels);
    }

    /// Multi-BLOCK bz2 → several lbzip2 decode segments → way/rel row groups
    /// encoded on MULTIPLE workers, plus the collector boundary-stub path. Gated
    /// on the `bzip2` CLI so the suite stays green where it is absent; the input
    /// is >2 bz2 blocks (each block is 900 KiB at -9) yet still small.
    #[test]
    fn raw_bz2_multiblock_multiworker_preserves_row_set() {
        if !have("bzip2") {
            eprintln!("skipping: bzip2 CLI not installed (multi-block bz2 unavailable)");
            return;
        }
        // ~8000 nodes + 6000 ways + 1000 rels → a few MB of XML → ≥3 bz2 blocks.
        let (n_nodes, n_ways, n_rels) = (8000i64, 6000i64, 1000i64);
        let xml = synth_osm_xml(n_nodes, n_ways, n_rels);

        let dir = tempfile::tempdir().unwrap();
        let osm = dir.path().join("in.osm");
        std::fs::write(&osm, xml.as_bytes()).unwrap();
        let input = dir.path().join("in.osm.bz2");

        // bzip2 -9 -c in.osm > in.osm.bz2 (single stream, multiple 900 KiB blocks).
        let st = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "bzip2 -9 -c {} > {}",
                osm.display(),
                input.display()
            ))
            .status()
            .expect("run bzip2");
        assert!(st.success(), "bzip2 compress failed");

        let out = dir.path().join("out");
        let (nodes, ways, rels) = super::read_raw_bz2(
            &input,
            &out,
            "zstd",
            true,
            true,
            true,
            6,
            false,
            indicatif::ProgressBar::hidden(),
        )
        .expect("read_raw_bz2");

        assert_eq!(nodes, n_nodes as usize, "node count");
        assert_eq!(ways, n_ways as usize, "way count");
        assert_eq!(rels, n_rels as usize, "relation count");
        assert_row_sets(&out, n_nodes, n_ways, n_rels);
    }
}
