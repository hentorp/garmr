//! XML → zstd-PBF converter.
//!
//! Two paths:
//!   1. **mmap** (`xml_to_pbf`): requires pre-built VTD index + uncompressed XML.
//!      Three passes over the ElemIndex (nodes → ways → relations).
//!   2. **streaming** (`xml_to_pbf_streaming`): single-pass through any `Read`
//!      source (e.g. lbzip2 pipe).  Per-slot parallel VTD parse + PBF encode.
//!
//! Both paths batch elements into PrimitiveBlocks, compress in parallel on the
//! Gatling workers (no rayon), and write in order. No metadata (version/timestamp)
//! emitted.

use std::{
    io::{BufReader, BufWriter, Write},
    path::Path,
};

use anyhow::{Context as _, Result};
use memchr::memchr;
use znippy_zoomies::gatling;

use crate::{
    pbf_enc::{
        DenseNodesBuilder, StringTable, compress_zstd, encode_primitive_block, encode_relation,
        encode_way, write_blob, write_osm_header,
    },
    xml_vtd::{self, ElemIndex, ElemKind, as_elem_index, find_attr, mmap_input, parse_i64},
};

const NODE_BLOCK: usize = 8_000;
const WAY_BLOCK: usize = 2_000;
const RELATION_BLOCK: usize = 200;

// ── Zero-copy element reference ───────────────────────────────────────────────

/// Lightweight element descriptor — offsets into an xml buffer, no owned data.
#[derive(Clone, Copy)]
struct ElemRef {
    kind: ElemKind,
    id: i64,
    lat_e7: i32,
    lon_e7: i32,
    xml_off: u32,
    xml_len: u32,
}

/// Encode one PBF block from element refs that point into `xml`.
fn encode_block_ref(xml: &[u8], block: &[ElemRef], kind: ElemKind) -> Result<(usize, Vec<u8>)> {
    match kind {
        ElemKind::Node => {
            let mut st = StringTable::new();
            let mut dn = DenseNodesBuilder::new();
            for e in block {
                let raw = &xml[e.xml_off as usize..][..e.xml_len as usize];
                let tags = parse_tags(raw, &mut st);
                dn.push(e.id, e.lat_e7, e.lon_e7, &tags);
            }
            let blk = encode_primitive_block(&st, Some(&dn), &[], &[]);
            let raw = blk.len();
            Ok((raw, compress_zstd(&blk)?))
        }
        ElemKind::Way => {
            let mut st = StringTable::new();
            let ways_enc: Vec<Vec<u8>> = block
                .iter()
                .map(|e| {
                    let raw = &xml[e.xml_off as usize..][..e.xml_len as usize];
                    let tags = parse_tags(raw, &mut st);
                    let refs = parse_nd_refs(raw);
                    encode_way(e.id, &tags, &refs)
                })
                .collect();
            let blk = encode_primitive_block(&st, None, &ways_enc, &[]);
            let raw = blk.len();
            Ok((raw, compress_zstd(&blk)?))
        }
        ElemKind::Relation => {
            let mut st = StringTable::new();
            let rels_enc: Vec<Vec<u8>> = block
                .iter()
                .map(|e| {
                    let raw = &xml[e.xml_off as usize..][..e.xml_len as usize];
                    let tags = parse_tags(raw, &mut st);
                    let members = parse_members(raw, &mut st);
                    encode_relation(e.id, &tags, &members)
                })
                .collect();
            let blk = encode_primitive_block(&st, None, &[], &rels_enc);
            let raw = blk.len();
            Ok((raw, compress_zstd(&blk)?))
        }
    }
}

/// Serially VTD-parse an xml slice into a flat `Vec<ElemRef>` with offsets
/// relative to `xml` (base 0). Serial on purpose: this runs inside one Gatling
/// worker (1-of-N), so the parallelism is across segments, not within one.
fn vtd_parse_serial(xml: &[u8]) -> Vec<ElemRef> {
    let mut elems = Vec::new();
    xml_vtd::build_elem_index_slice(xml, 0, &mut |e| {
        elems.push(ElemRef {
            kind: e.kind,
            id: e.id,
            lat_e7: e.lat_e7,
            lon_e7: e.lon_e7,
            xml_off: e.file_offset as u32,
            xml_len: e.file_length,
        });
    });
    elems
}

/// Group a flat list of element refs by kind, chunk into PrimitiveBlocks, and
/// encode + zstd-compress each block. Runs serially (the caller is one Gatling
/// worker among N). All XML reads are zero-copy slices into `xml`.
fn encode_elems_to_blobs(xml: &[u8], elems: &[ElemRef]) -> Result<Vec<(usize, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < elems.len() {
        let kind = elems[i].kind;
        let end = elems[i..]
            .iter()
            .position(|e| e.kind != kind)
            .map_or(elems.len(), |p| i + p);
        let group = &elems[i..end];

        let block_size = match kind {
            ElemKind::Node => NODE_BLOCK,
            ElemKind::Way => WAY_BLOCK,
            ElemKind::Relation => RELATION_BLOCK,
        };

        let n_blocks = group.len().div_ceil(block_size);
        for c in 0..n_blocks {
            let lo = c * block_size;
            let hi = (lo + block_size).min(group.len());
            out.push(encode_block_ref(xml, &group[lo..hi], kind)?);
        }
        i = end;
    }
    Ok(out)
}

/// Writer thread: receives compressed blobs and writes them to disk.
fn blob_writer_loop(
    rx: std::sync::mpsc::Receiver<(usize, Vec<u8>)>,
    mut out: BufWriter<std::fs::File>,
) -> Result<u64> {
    let mut written = 0u64;
    while let Ok((raw_size, compressed)) = rx.recv() {
        written += compressed.len() as u64;
        write_blob(&mut out, b"OSMData", raw_size, &compressed)?;
    }
    out.flush()?;
    Ok(written)
}

/// Output of one Gatling worker for one segment: the fully-encoded, zstd-
/// compressed PBF blobs for the segment's *middle* (complete elements), plus
/// the partial edge bytes (`left_stub`/`right_stub`) that straddle the segment
/// boundary. The collector stitches `prev_stub + left_stub` into the boundary
/// element(s). `count` is the number of node/way/relation elements in `blobs`.
#[derive(Default)]
struct PbfSegment {
    blobs: Vec<(usize, Vec<u8>)>,
    count: u64,
    left_stub: Vec<u8>,
    right_stub: Vec<u8>,
}

/// Encode one decoded XML run into a [`PbfSegment`]. Trims to the middle of
/// complete elements (carrying the partial edges as stubs), VTD-parses, groups
/// by kind, and encodes + compresses every PrimitiveBlock — all on the calling
/// Gatling worker so the heavy parse+encode+zstd runs in parallel across
/// workers (the fix for the serial collector dip). Mirrors the geoparquet
/// `pass1_parse_decoded` template.
fn encode_decoded_to_pbf(decoded: &[u8]) -> Result<PbfSegment> {
    if decoded.is_empty() {
        return Ok(PbfSegment::default());
    }

    let first = xml_vtd::find_top_level_start(decoded, 0);
    let last = xml_vtd::find_safe_slot_end(decoded);
    let last = last.max(first);

    let left_stub = decoded[..first].to_vec();
    let right_stub = decoded[last..].to_vec();
    let middle = &decoded[first..last];

    let elems = vtd_parse_serial(middle);
    let count = elems.len() as u64;
    let blobs = encode_elems_to_blobs(middle, &elems)?;

    Ok(PbfSegment {
        blobs,
        count,
        left_stub,
        right_stub,
    })
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Convert a VTD-indexed OSM XML file to a zstd-compressed PBF file.
///
/// `idx_path` must point to a pre-built `.elem.idx` file (see
/// `build_elem_index_pipelined` / `build_elem_index_to_mmap`).
pub fn xml_to_pbf(xml_path: &Path, idx_path: &Path, out_path: &Path) -> Result<u64> {
    let xml_mmap = mmap_input(xml_path).context("mmap XML")?;
    let idx_mmap = mmap_input(idx_path).context("mmap index")?;
    let xml = xml_mmap.as_ref();
    let index = as_elem_index(&idx_mmap);

    let out_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(out_path)
        .context("create PBF output")?;
    let mut out = BufWriter::with_capacity(4 * 1024 * 1024, out_file);

    write_osm_header(&mut out)?;

    let mut total = 0u64;
    total += write_nodes(xml, index, &mut out)?;
    total += write_ways(xml, index, &mut out)?;
    total += write_relations(xml, index, &mut out)?;

    Ok(total)
}

// ── Node pass ────────────────────────────────────────────────────────────────

fn write_nodes(xml: &[u8], index: &[ElemIndex], out: &mut impl std::io::Write) -> Result<u64> {
    let nodes: Vec<&ElemIndex> = index.iter().filter(|e| e.kind == ElemKind::Node).collect();
    let total = nodes.len() as u64;

    let n_blocks = nodes.len().div_ceil(NODE_BLOCK);
    let blobs: Result<Vec<(usize, Vec<u8>)>> = crate::par::par_map(n_blocks, |c| {
        let lo = c * NODE_BLOCK;
        let hi = (lo + NODE_BLOCK).min(nodes.len());
        let chunk = &nodes[lo..hi];
        let mut st = StringTable::new();
        let mut dn = DenseNodesBuilder::new();
        for e in chunk {
            let elem = elem_bytes(xml, e);
            let tags = parse_tags(elem, &mut st);
            dn.push(e.id, e.lat_e7, e.lon_e7, &tags);
        }
        let block = encode_primitive_block(&st, Some(&dn), &[], &[]);
        let raw = block.len();
        Ok((raw, compress_zstd(&block)?))
    })
    .into_iter()
    .collect();

    for (raw, comp) in blobs? {
        write_blob(out, b"OSMData", raw, &comp)?;
    }
    Ok(total)
}

// ── Way pass ─────────────────────────────────────────────────────────────────

fn write_ways(xml: &[u8], index: &[ElemIndex], out: &mut impl std::io::Write) -> Result<u64> {
    let ways: Vec<&ElemIndex> = index.iter().filter(|e| e.kind == ElemKind::Way).collect();
    let total = ways.len() as u64;

    let n_blocks = ways.len().div_ceil(WAY_BLOCK);
    let blobs: Result<Vec<(usize, Vec<u8>)>> = crate::par::par_map(n_blocks, |c| {
        let lo = c * WAY_BLOCK;
        let hi = (lo + WAY_BLOCK).min(ways.len());
        let chunk = &ways[lo..hi];
        let mut st = StringTable::new();
        let ways_enc: Vec<Vec<u8>> = chunk
            .iter()
            .map(|e| {
                let elem = elem_bytes(xml, e);
                let tags = parse_tags(elem, &mut st);
                let refs = parse_nd_refs(elem);
                encode_way(e.id, &tags, &refs)
            })
            .collect();
        let block = encode_primitive_block(&st, None, &ways_enc, &[]);
        let raw = block.len();
        Ok((raw, compress_zstd(&block)?))
    })
    .into_iter()
    .collect();

    for (raw, comp) in blobs? {
        write_blob(out, b"OSMData", raw, &comp)?;
    }
    Ok(total)
}

// ── Relation pass ─────────────────────────────────────────────────────────────

fn write_relations(xml: &[u8], index: &[ElemIndex], out: &mut impl std::io::Write) -> Result<u64> {
    let rels: Vec<&ElemIndex> = index
        .iter()
        .filter(|e| e.kind == ElemKind::Relation)
        .collect();
    let total = rels.len() as u64;

    let n_blocks = rels.len().div_ceil(RELATION_BLOCK);
    let blobs: Result<Vec<(usize, Vec<u8>)>> = crate::par::par_map(n_blocks, |c| {
        let lo = c * RELATION_BLOCK;
        let hi = (lo + RELATION_BLOCK).min(rels.len());
        let chunk = &rels[lo..hi];
        let mut st = StringTable::new();
        let rels_enc: Vec<Vec<u8>> = chunk
            .iter()
            .map(|e| {
                let elem = elem_bytes(xml, e);
                let tags = parse_tags(elem, &mut st);
                let members = parse_members(elem, &mut st);
                encode_relation(e.id, &tags, &members)
            })
            .collect();
        let block = encode_primitive_block(&st, None, &[], &rels_enc);
        let raw = block.len();
        Ok((raw, compress_zstd(&block)?))
    })
    .into_iter()
    .collect();

    for (raw, comp) in blobs? {
        write_blob(out, b"OSMData", raw, &comp)?;
    }
    Ok(total)
}

// ── XML mini-parsers ──────────────────────────────────────────────────────────

#[inline]
fn elem_bytes<'a>(xml: &'a [u8], e: &ElemIndex) -> &'a [u8] {
    let start = e.file_offset as usize;
    let end = (e.file_offset + e.file_length as u64) as usize;
    &xml[start..end.min(xml.len())]
}

/// Scan element bytes for `<tag k="..." v="..."/>` children.
/// Interns keys+values into `st`, returns (key_sid, val_sid) pairs.
fn parse_tags(elem: &[u8], st: &mut StringTable) -> Vec<(u32, u32)> {
    let mut result = Vec::new();
    let mut pos = 0;
    while let Some(rel) = memchr(b'<', &elem[pos..]) {
        let lt = pos + rel;
        pos = lt + 1;
        if elem.get(pos..pos + 4) == Some(b"tag ") {
            let gt = memchr(b'>', &elem[pos..]).map_or(elem.len(), |p| pos + p);
            let tag = &elem[pos..gt];
            if let (Some(k), Some(v)) = (find_attr(tag, b"k"), find_attr(tag, b"v")) {
                result.push((st.intern(k), st.intern(v)));
            }
            pos = gt + 1;
        } else if elem.get(pos..pos + 1) == Some(b"/") {
            break; // closing tag — no more children
        }
    }
    result
}

/// Scan for `<nd ref="..."/>` and return the list of node IDs.
fn parse_nd_refs(elem: &[u8]) -> Vec<i64> {
    let mut result = Vec::new();
    let mut pos = 0;
    while let Some(rel) = memchr(b'<', &elem[pos..]) {
        let lt = pos + rel;
        pos = lt + 1;
        if elem.get(pos..pos + 3) == Some(b"nd ") {
            let gt = memchr(b'>', &elem[pos..]).map_or(elem.len(), |p| pos + p);
            let tag = &elem[pos..gt];
            if let Some(r) = find_attr(tag, b"ref") {
                result.push(parse_i64(r));
            }
            pos = gt + 1;
        } else if elem.get(pos..pos + 1) == Some(b"/") {
            break;
        }
    }
    result
}

/// Scan for `<member type="..." ref="..." role="..."/>`.
/// Returns (member_type_byte, ref_id, role_sid).
fn parse_members(elem: &[u8], st: &mut StringTable) -> Vec<(u8, i64, u32)> {
    let mut result = Vec::new();
    let mut pos = 0;
    while let Some(rel) = memchr(b'<', &elem[pos..]) {
        let lt = pos + rel;
        pos = lt + 1;
        if elem.get(pos..pos + 7) == Some(b"member ") {
            let gt = memchr(b'>', &elem[pos..]).map_or(elem.len(), |p| pos + p);
            let tag = &elem[pos..gt];
            let mt = match find_attr(tag, b"type") {
                Some(b"node") => 0u8,
                Some(b"way") => 1,
                Some(b"relation") => 2,
                _ => {
                    pos = gt + 1;
                    continue;
                }
            };
            let ref_id = find_attr(tag, b"ref").map(parse_i64).unwrap_or(0);
            let role_sid = find_attr(tag, b"role")
                .map(|r| st.intern(r))
                .unwrap_or_else(|| st.intern(b""));
            result.push((mt, ref_id, role_sid));
            pos = gt + 1;
        } else if elem.get(pos..pos + 1) == Some(b"/") {
            break;
        }
    }
    result
}

// ── Raw XML typed codec (split at element boundaries → encode PBF on worker) ──

const RAW_CHUNK_SIZE: usize = 128 * 1024 * 1024; // 128 MB per read
// Keep 6-8 slots in flight so the single reader always runs ahead of the 32
// workers (they never starve waiting for the next slot → flat-100% cores).
const RAW_RING_SLOTS: usize = 8;

/// Raw (uncompressed) XML [`gatling::TypedCodec`]: `split` cuts the slot into N
/// element-aligned segments, each worker VTD-parses + PBF-encodes its segment
/// into a [`PbfSegment`]. Element-aligned splits mean stubs are normally empty,
/// but they are still carried so any cross-chunk-boundary residue is stitched.
struct RawPbfTypedCodec;

impl gatling::TypedCodec for RawPbfTypedCodec {
    type Seg = (usize, usize);
    type Output = PbfSegment;

    fn split(
        &self,
        data: &[u8],
        n_workers: usize,
        is_last: bool,
    ) -> Option<gatling::Split<(usize, usize)>> {
        crate::xml_reader::xml_split_typed(data, n_workers, is_last)
    }

    fn transform(&self, data: &[u8], &(s, e): &(usize, usize)) -> PbfSegment {
        encode_decoded_to_pbf(&data[s..e]).expect("raw PBF encode")
    }
}

/// Run the Gatling typed engine over uncompressed XML from `reader`.
pub(crate) fn raw_gatling_run_typed<R, C, S>(
    reader: R,
    codec: C,
    sink: &mut S,
    n_workers: usize,
) -> Result<()>
where
    R: std::io::Read + Send,
    C: gatling::TypedCodec,
    S: gatling::TypedSink<C::Output>,
{
    let cfg = gatling::Config {
        chunk_size: RAW_CHUNK_SIZE,
        carry_headroom: 16 * 1024 * 1024,
        ring_slots: RAW_RING_SLOTS,
        initial_carry: Vec::new(),
        // Big: raw XML/PBF is a long sequential read, every slot full but the
        // last → reuse the full slot, skip Incremental's per-chunk resize churn.
        slot_fill: gatling::SlotFill::Big,
    };
    gatling::run_typed(reader, codec, sink, n_workers, cfg)
}

/// Convert uncompressed `.osm` to zstd PBF via the Gatling typed engine: workers
/// split the chunk, parse + encode PBF blobs in parallel, a single writer thread
/// appends them in stream order. Single-pass, no VTD index needed.
pub fn xml_to_pbf_raw<R: std::io::Read + Send>(
    reader: R,
    out_path: &Path,
    n_workers: usize,
) -> Result<(u64, u64)> {
    let mut sink = PbfTypedSink::new(out_path)?;
    raw_gatling_run_typed(reader, RawPbfTypedCodec, &mut sink, n_workers)?;
    sink.finish()
}

/// Path-based raw XML → PBF. Opens the file and drives the Gatling engine.
pub fn xml_to_pbf_raw_path(path: &Path, out_path: &Path, n_workers: usize) -> Result<(u64, u64)> {
    let file = std::fs::File::open(path).context("open XML")?;
    let reader = std::io::BufReader::with_capacity(4 * 1024 * 1024, file);
    xml_to_pbf_raw(reader, out_path, n_workers)
}

// ── Bzip2 path (Gatling worker-pool engine: split → N decode → collect → VTD → PBF) ─────

/// Constants matching the lbunzip2 worker-pool design.
const BZ2_CHUNK_SIZE: usize = 200 * 1024 * 1024; // 200 MB compressed per slot
const BZ2_CARRY_HEADROOM: usize = 32 * 1024 * 1024; // 32 MB headroom for carry
const BZ2_RING_SLOTS: usize = 6;

/// bz2 [`gatling::TypedCodec`]: `split` finds independent block boundaries,
/// each worker decodes one block range AND parses + encodes it into PBF blobs.
struct Bz2PbfTypedCodec {
    max_blocksize: u32,
}

impl gatling::TypedCodec for Bz2PbfTypedCodec {
    type Seg = (u64, u64);
    type Output = PbfSegment;

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

    fn transform(&self, data: &[u8], &(start_bit, end_bit): &(u64, u64)) -> PbfSegment {
        let decoded = lbzip2::chunk::decode_segment(data, start_bit, end_bit, self.max_blocksize);
        encode_decoded_to_pbf(&decoded).expect("bz2 PBF encode")
    }
}

/// PBF [`gatling::TypedSink`]: receives the pre-encoded blobs each worker
/// produced (in strict stream order), stitches the cross-segment boundary
/// elements (`prev_stub + left_stub`) on the collector thread, and forwards
/// every blob to a single writer thread. No parse/encode on this thread.
struct PbfTypedSink {
    blob_tx: Option<std::sync::mpsc::SyncSender<(usize, Vec<u8>)>>,
    writer: Option<std::thread::JoinHandle<Result<u64>>>,
    total: u64,
    prev_stub: Vec<u8>,
}

impl PbfTypedSink {
    fn new(out_path: &Path) -> Result<Self> {
        let out_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(out_path)
            .context("create PBF output")?;
        let mut out = BufWriter::with_capacity(4 * 1024 * 1024, out_file);
        write_osm_header(&mut out)?;

        // ROOT LAW #0 — SANCTIONED, and deliberately not converted (audited
        // 2026-07-22). This is ONE named, long-lived worker doing blocking file
        // I/O (`write_blob` + `flush`) off the gatling collector thread, fed by a
        // bounded mpsc channel. It is IO-offload, not CPU fan-out: there is
        // exactly one of it, it never grows with core count, it claims no units
        // from a shared cursor, and it does no parse/encode (all of that already
        // happens on the gatling workers). The output is a single sequential byte
        // stream whose blob order IS the stream order, so there is nothing to
        // fan out — routing it through `gatling_for_each` would mean forcing a
        // serial sink onto a work pool. The law's own carve-out ("Sanctioned: ONE
        // named worker doing blocking I/O off a UI/async thread = IO-offload")
        // names exactly this shape; `PRIVATE_POOL_ALLOW` in
        // `tests/rayon_free_law.rs` licenses this file for that reason.
        let (blob_tx, blob_rx) = std::sync::mpsc::sync_channel::<(usize, Vec<u8>)>(64);
        let writer = std::thread::spawn(move || blob_writer_loop(blob_rx, out));

        Ok(Self {
            blob_tx: Some(blob_tx),
            writer: Some(writer),
            total: 0,
            prev_stub: Vec::new(),
        })
    }

    /// Parse + encode the tiny boundary stub on the collector thread and forward
    /// its blobs. Volume is ~1–10 elements per segment boundary vs ~tens of
    /// thousands in the middle, so the serial work here is negligible.
    fn flush_stub(&mut self, stub: &[u8]) -> Result<()> {
        if stub.is_empty() {
            return Ok(());
        }
        let elems = vtd_parse_serial(stub);
        if elems.is_empty() {
            return Ok(());
        }
        let blobs = encode_elems_to_blobs(stub, &elems)?;
        self.total += elems.len() as u64;
        let tx = self.blob_tx.as_ref().expect("blob_tx present");
        for b in blobs {
            tx.send(b).map_err(|_| anyhow::anyhow!("writer closed"))?;
        }
        Ok(())
    }

    /// Flush the trailing stub, drop the sender, join the writer, and return
    /// `(elements, bytes_written)`.
    fn finish(mut self) -> Result<(u64, u64)> {
        let stub = std::mem::take(&mut self.prev_stub);
        self.flush_stub(&stub)?;
        drop(self.blob_tx.take());
        let written = self
            .writer
            .take()
            .expect("writer present")
            .join()
            .expect("writer panicked")?;
        Ok((self.total, written))
    }
}

impl gatling::TypedSink<PbfSegment> for PbfTypedSink {
    fn process(&mut self, seg: PbfSegment, _is_last: bool) -> Result<()> {
        // Stitch the boundary: this segment's left_stub appended to the previous
        // segment's right_stub may form one or more complete elements. Their
        // blobs precede this segment's middle, so flush them first.
        let boundary = [self.prev_stub.as_slice(), seg.left_stub.as_slice()].concat();
        self.flush_stub(&boundary)?;

        let tx = self
            .blob_tx
            .as_ref()
            .expect("blob_tx present during process");
        for b in seg.blobs {
            tx.send(b).map_err(|_| anyhow::anyhow!("writer closed"))?;
        }
        self.total += seg.count;
        self.prev_stub = seg.right_stub;
        Ok(())
    }
}

/// Validate a bzip2 stream header (`BZhN`) and return `max_blocksize`.
pub fn bz2_max_blocksize(header: &[u8; 4]) -> Result<u32> {
    let level = header[3];
    if &header[..2] != b"BZ" || header[2] != b'h' || !(b'1'..=b'9').contains(&level) {
        anyhow::bail!("invalid bzip2 header");
    }
    Ok(100_000 * u32::from(level - b'0'))
}

/// gzip path: see `gz_split`/`gz_decode_segment` (used by the typed codecs).
//
// ── Gzip path (Gatling worker-pool engine; lgz split_chunk + decode_segment) ──
//
// Mirrors the bz2 path for DEFLATE. lgz finds full-flush boundaries
// (`00 00 FF FF`, emitted by pigz/bgzf/Z_FULL_FLUSH) so segments decode in
// parallel across Gatling workers. Standard single-stream gzip has no flush
// boundaries, so the whole DEFLATE stream decodes as one segment (single
// worker) — same fallback as lgz itself, still rayon-free.
//
// The variable-length gzip header is stripped and the 8-byte trailer excluded
// before the engine runs, so the codec only ever sees raw DEFLATE. The chunk is
// sized to cover the whole stream, so `split` is called once with `is_last`.

const GZ_CARRY_HEADROOM: usize = 1024 * 1024; // header stripped → carry stays empty

/// Build Gatling segment ranges from an lgz chunk split (byte offsets). Falls
/// back to a single whole-stream segment when no full-flush boundary exists and
/// this is the last chunk, so boundary-less gzip is never dropped.
pub(crate) fn gz_split(
    data: &[u8],
    n_workers: usize,
    is_last: bool,
) -> Option<gatling::Split<(usize, usize)>> {
    if data.is_empty() {
        return None;
    }
    match lgz::chunk::split_chunk(data, n_workers, is_last) {
        Some(s) => {
            let n_seg = s.segment_starts.len();
            let segments = (0..s.decode_segments)
                .map(|i| {
                    let start = s.segment_starts[i];
                    let end = if i + 1 < n_seg {
                        s.segment_starts[i + 1]
                    } else {
                        s.consumed
                    };
                    (start, end)
                })
                .collect();
            Some(gatling::Split {
                segments,
                consumed: s.consumed,
            })
        }
        None if is_last => Some(gatling::Split {
            segments: vec![(0, data.len())],
            consumed: data.len(),
        }),
        None => None,
    }
}

/// Decode one DEFLATE segment (empty on failure, mirroring the bz2 codec).
pub(crate) fn gz_decode_segment(data: &[u8], &(start, end): &(usize, usize)) -> Vec<u8> {
    lgz::chunk::decode_segment(&data[start..end]).unwrap_or_default()
}

/// Open a `.gz` file, strip the gzip header + trailer, and return a reader over
/// the raw DEFLATE stream plus a chunk size large enough to read it in one go
/// (so the engine sees a single `is_last` chunk — no carry accumulation).
pub(crate) fn gz_open(path: &Path) -> Result<(std::io::Take<std::fs::File>, usize)> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let file_size = file.metadata().context("gz metadata")?.len();
    if file_size < 18 {
        anyhow::bail!("gz file too small ({file_size} bytes)");
    }
    let probe_len = file_size.min(64 * 1024) as usize;
    let mut probe = vec![0u8; probe_len];
    file.read_exact(&mut probe).context("read gz header")?;
    let deflate_start =
        lgz::deflate_offset(&probe).map_err(|e| anyhow::anyhow!("lgz: {e}"))? as u64;
    let deflate_len = file_size
        .checked_sub(deflate_start + 8)
        .ok_or_else(|| anyhow::anyhow!("gz stream shorter than header + trailer"))?;
    file.seek(SeekFrom::Start(deflate_start))
        .context("seek gz deflate start")?;
    let chunk_size = usize::try_from(deflate_len)
        .unwrap_or(usize::MAX - GZ_CARRY_HEADROOM)
        .saturating_add(1)
        .max(64 * 1024);
    Ok((file.take(deflate_len), chunk_size))
}

fn gz_cfg(chunk_size: usize) -> gatling::Config {
    gatling::Config {
        chunk_size,
        carry_headroom: GZ_CARRY_HEADROOM,
        // 8 slots → reader stays 6-8 ahead so workers never starve.
        ring_slots: 8,
        initial_carry: Vec::new(),
        // Big: sequential .gz read, slots reused full → no per-chunk resize churn.
        slot_fill: gatling::SlotFill::Big,
    }
}

/// Run the Gatling engine (TypedCodec/TypedSink model) over a `.gz` file.
pub(crate) fn gz_gatling_run_typed<C, S>(
    path: &Path,
    codec: C,
    sink: &mut S,
    n_workers: usize,
) -> Result<()>
where
    C: gatling::TypedCodec,
    S: gatling::TypedSink<C::Output>,
{
    let (reader, chunk_size) = gz_open(path)?;
    gatling::run_typed(reader, codec, sink, n_workers, gz_cfg(chunk_size))
}

// ── PBF path (Gatling worker-pool engine; pbf_io blob-boundary split) ─────────
//
// PBF is a sequence of self-contained frames: [4-byte BE header len][BlobHeader]
// [Blob]. Each OSMData blob decodes (zlib + protobuf) independently, so the
// Gatling `split` cuts the slot at blob frame boundaries and each worker decodes
// + parses one blob. No carry-stub reassembly is needed (unlike XML) because
// blobs never straddle a logical element. The engine reads the file once per
// pass (no mmap, no rayon par_bridge).

/// Read per slot. Large enough to hold many blobs (OSM blobs are typically
/// <1 MB compressed) so split emits plenty of parallel work per chunk.
const PBF_CHUNK_SIZE: usize = 64 * 1024 * 1024;
/// Headroom for a partial trailing blob carried to the next slot. OSM blobs are
/// spec-capped at 32 MB; 64 MB is comfortably safe.
const PBF_CARRY_HEADROOM: usize = 64 * 1024 * 1024;
// 8 slots in flight: the single PBF reader always pre-reads 6-8 chunks ahead so
// the 32 workers never block on the next slot (the reader-1 never starves the
// worker-32 → continuous saturation, not a 16-core stall).
const PBF_RING_SLOTS: usize = 8;

/// Gatling segment split for a PBF slot: ~`2 * n_workers` COARSE candidate byte
/// ranges (cheap O(n_workers) division, NO blob walk on main); each worker aligns
/// to its own blob boundary and decodes its whole range. `consumed` is the last
/// complete blob end (bounded tail scan). Returns `None` only for a fully empty
/// slot, so a boundary-less tail is never dropped at `is_last`.
pub(crate) fn pbf_split(
    data: &[u8],
    n_workers: usize,
    _is_last: bool,
) -> Option<gatling::Split<(usize, usize)>> {
    if data.is_empty() {
        return None;
    }
    // ~2× workers for load-balance headroom (a worker that drew a dense range
    // returns to the channel and grabs another). NO per-blob walk on main.
    let n_segments = (n_workers.max(1) * 2).max(1);
    let (segments, consumed) = crate::pbf_io::coarse_split_slot(data, n_segments);
    Some(gatling::Split { segments, consumed })
}

fn pbf_cfg() -> gatling::Config {
    gatling::Config {
        chunk_size: PBF_CHUNK_SIZE,
        carry_headroom: PBF_CARRY_HEADROOM,
        ring_slots: PBF_RING_SLOTS,
        initial_carry: Vec::new(),
        // Big: a PBF is a long sequential read where nearly every 64 MB slot is
        // full, so the up-front fault amortizes to ~zero and the slot is reused
        // with no re-zero / no realloc per chunk. Incremental's per-block
        // resize/truncate churn on the reader thread throttled slot turnover and
        // starved the workers (the saturation regression). The resolved convert
        // (read_resolved_pbf, two passes) runs through here.
        slot_fill: gatling::SlotFill::Big,
    }
}

/// Run the Gatling typed engine over a `.pbf` file (read once) driving `sink`.
pub(crate) fn pbf_gatling_run_typed<C, S>(
    path: &Path,
    codec: C,
    sink: &mut S,
    n_workers: usize,
) -> Result<()>
where
    C: gatling::TypedCodec,
    S: gatling::TypedSink<C::Output>,
{
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::with_capacity(8 * 1024 * 1024, file);
    gatling::run_typed(reader, codec, sink, n_workers, pbf_cfg())
}

// ── Changeset-prologue skip (seek to first data block) ────────────────────────

/// Element tags marking "real" OSM data (anything past the changeset prologue).
pub const DATA_NEEDLES: &[&[u8]] = &[b"<node ", b"<way ", b"<relation "];

/// Ways + relations only — for resolved pass 2, which can also skip every node.
pub const WAYREL_NEEDLES: &[&[u8]] = &[b"<way ", b"<relation "];

fn contains_any(hay: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|n| memchr::memmem::find(hay, n).is_some())
}

/// Decode the first complete bz2 block in `window` (compressed) and report whether
/// its decoded XML contains any `needle`. Returns `(absolute_byte_of_that_block,
/// matched)`, or `None` if the window holds no complete block pair.
/// Minimum decoded size to consider a block "real" rather than a multi-stream boundary
/// artifact. lbzip2 produces bzip2 files where streams are concatenated; between streams
/// the block scanner can find 50-100 byte false-positive hits. Skip those.
const MIN_REAL_BLOCK_BYTES: usize = 4096;

fn probe_block(
    window: &[u8],
    window_off: u64,
    max_blocksize: u32,
    needles: &[&[u8]],
) -> Option<(u64, bool)> {
    let mut bit = 0u64;
    loop {
        let b0 = lbzip2::block_scan::find_next_block(window, bit)?;
        let b1 = lbzip2::block_scan::find_next_block(window, b0.bit_offset + 48)?;
        let decoded =
            lbzip2::chunk::decode_segment(window, b0.bit_offset, b1.bit_offset, max_blocksize);
        if decoded.len() >= MIN_REAL_BLOCK_BYTES {
            return Some((
                window_off + b0.byte_offset() as u64,
                contains_any(&decoded, needles),
            ));
        }
        // Skip micro-block (multi-stream boundary artifact) and try the next one.
        bit = b1.bit_offset;
    }
}

/// Find the byte offset of the first bz2 block whose decoded XML contains one of
/// `needles`, so the engine can start there and skip the changeset prologue (and,
/// for pass 2, every node block too). `None` if no such block exists.
///
/// The predicate "first block at/after X matches" is monotonic over the file
/// (OSM order: changesets → nodes → ways → relations), so we binary-search the
/// compressed file, then linear-scan the final window to pin the exact block.
/// Uses only public lbzip2 block-scan + decode primitives — no lbzip2 changes.
pub fn seek_first_data_block(
    file: &mut std::fs::File,
    file_size: u64,
    max_blocksize: u32,
    needles: &[&[u8]],
) -> Result<Option<u64>> {
    use std::io::{Read, Seek, SeekFrom};
    const WINDOW: usize = 8 * 1024 * 1024;

    let read_window = |file: &mut std::fs::File, off: u64| -> Result<Vec<u8>> {
        file.seek(SeekFrom::Start(off))?;
        let cap = WINDOW.min(file_size.saturating_sub(off) as usize);
        let mut buf = vec![0u8; cap];
        let mut got = 0;
        while got < buf.len() {
            match file.read(&mut buf[got..])? {
                0 => break,
                k => got += k,
            }
        }
        buf.truncate(got);
        Ok(buf)
    };

    // Binary search for the smallest offset whose first block matches a needle.
    // Stop with margin (WINDOW/2) so the matching block + its end fit one window.
    let mut lo = 4u64;
    let mut hi = file_size;
    while hi - lo > (WINDOW as u64) / 2 {
        let mid = lo + (hi - lo) / 2;
        let w = read_window(file, mid)?;
        match probe_block(&w, mid, max_blocksize, needles) {
            Some((_, true)) => hi = mid,
            _ => lo = mid + 1, // changeset/node block, or none in window → search right
        }
    }

    // Linear scan of [lo, lo+WINDOW]: enumerate blocks, decode each, first match wins.
    // Skip micro-blocks (multi-stream boundary artifacts).
    let w = read_window(file, lo)?;
    let mut bit = 0u64;
    while let Some(b0) = lbzip2::block_scan::find_next_block(&w, bit) {
        let Some(b1) = lbzip2::block_scan::find_next_block(&w, b0.bit_offset + 48) else {
            break;
        };
        let decoded =
            lbzip2::chunk::decode_segment(&w, b0.bit_offset, b1.bit_offset, max_blocksize);
        if decoded.len() >= MIN_REAL_BLOCK_BYTES && contains_any(&decoded, needles) {
            return Ok(Some(lo + b0.byte_offset() as u64));
        }
        bit = b1.bit_offset;
    }
    Ok(None)
}

/// Find the byte offset of the first bz2 block whose decoded XML does NOT contain
/// `<node ` — i.e., the first block past the node section. Used by pass 2 to skip
/// the changeset+node prologue.
///
/// Unlike [`seek_first_data_block`] with `WAYREL_NEEDLES`, this is immune to the
/// false-negative problem caused by large ways that span entire bz2 blocks (those
/// blocks contain no `<way >` opening tag). The predicate "block contains `<node `"
/// is monotonic: true throughout the node section, false once ways start — because
/// node elements are ~100 bytes each, so thousands fit in one bz2 block.
pub fn seek_past_nodes(
    file: &mut std::fs::File,
    file_size: u64,
    max_blocksize: u32,
) -> Result<Option<u64>> {
    use std::io::{Read, Seek, SeekFrom};
    const WINDOW: usize = 8 * 1024 * 1024;
    const NODE_NEEDLE: &[&[u8]] = &[b"<node "];

    let read_window = |file: &mut std::fs::File, off: u64| -> Result<Vec<u8>> {
        file.seek(SeekFrom::Start(off))?;
        let cap = WINDOW.min(file_size.saturating_sub(off) as usize);
        let mut buf = vec![0u8; cap];
        let mut got = 0;
        while got < buf.len() {
            match file.read(&mut buf[got..])? {
                0 => break,
                k => got += k,
            }
        }
        buf.truncate(got);
        Ok(buf)
    };

    // First: skip the changeset prologue to find the node section start.
    let node_start = match seek_first_data_block(file, file_size, max_blocksize, NODE_NEEDLE)? {
        Some(off) => off,
        None => return Ok(None),
    };

    // Binary search for the LAST block that contains <node >.
    // Predicate: "block at mid contains <node>" — monotonic (true in node section, false after).
    let mut lo = node_start;
    let mut hi = file_size;
    while hi - lo > (WINDOW as u64) / 2 {
        let mid = lo + (hi - lo) / 2;
        let w = read_window(file, mid)?;
        match probe_block(&w, mid, max_blocksize, NODE_NEEDLE) {
            Some((_, true)) => lo = mid + 1, // still in nodes → search right for end
            _ => hi = mid,                   // past nodes → search left
        }
    }

    // Scan [lo - WINDOW, lo + WINDOW] to find the LAST real block containing <node >.
    // We return that block's offset so the TypedCodec starts from the transition block
    // (which holds the last nodes + first ways), then uses find_top_level_start to skip to
    // the first <way>. This avoids missing ways whose <way> opening tag is in the
    // transition block rather than the first pure-way block.
    let scan_start = lo.saturating_sub(WINDOW as u64 / 2);
    let w = read_window(file, scan_start)?;
    let mut bit = 0u64;
    let mut last_node_off: Option<u64> = None;
    loop {
        let Some(b0) = lbzip2::block_scan::find_next_block(&w, bit) else {
            break;
        };
        let Some(b1) = lbzip2::block_scan::find_next_block(&w, b0.bit_offset + 48) else {
            break;
        };
        let decoded =
            lbzip2::chunk::decode_segment(&w, b0.bit_offset, b1.bit_offset, max_blocksize);
        let abs_off = scan_start + b0.byte_offset() as u64;
        // Stop once we're WINDOW/2 past the binary-search convergence point.
        if abs_off > lo + WINDOW as u64 / 2 {
            break;
        }
        bit = b1.bit_offset;
        if decoded.len() < MIN_REAL_BLOCK_BYTES {
            continue;
        }
        if contains_any(&decoded, NODE_NEEDLE) {
            last_node_off = Some(abs_off);
        }
    }
    Ok(last_node_off)
}

/// What to skip at the start of a bz2 stream before running the engine.
pub(crate) enum Bz2Skip<'a> {
    /// No seek — process the whole stream from byte 0.
    None,
    /// Seek past changesets to the first block containing any of these needles.
    /// Works for `DATA_NEEDLES` (seeking to first node) where elements are small.
    Changesets(&'a [&'a [u8]]),
    /// Seek past changesets AND the entire node section to the first non-node block.
    /// Uses the monotonic `<node >` predicate — immune to large-way false negatives.
    Nodes,
}

/// Open a bz2 file and prepare it for Gatling (either byte-mode or typed-mode).
/// Seeks to the appropriate start position based on `skip`.
pub(crate) struct Bz2Prepared {
    pub reader: std::io::BufReader<std::fs::File>,
    pub max_blocksize: u32,
    pub initial_carry: Vec<u8>,
}

pub(crate) fn bz2_prepare(path: &Path, skip: Bz2Skip<'_>) -> Result<Bz2Prepared> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).context("open bz2")?;
    let mut header = [0u8; 4];
    file.read_exact(&mut header).context("read bzip2 header")?;
    let max_blocksize = bz2_max_blocksize(&header)?;

    let seek_to: Option<u64> = match skip {
        Bz2Skip::None => None,
        Bz2Skip::Changesets(needles) => {
            let file_size = file.metadata()?.len();
            seek_first_data_block(&mut file, file_size, max_blocksize, needles)?
        }
        Bz2Skip::Nodes => {
            let file_size = file.metadata()?.len();
            seek_past_nodes(&mut file, file_size, max_blocksize)?
        }
    };

    if let Some(b) = seek_to {
        file.seek(SeekFrom::Start(b))?;
        let reader = std::io::BufReader::with_capacity(4 * 1024 * 1024, file);
        return Ok(Bz2Prepared {
            reader,
            max_blocksize,
            initial_carry: Vec::new(),
        });
    }

    file.seek(SeekFrom::Start(4))?;
    let reader = std::io::BufReader::with_capacity(4 * 1024 * 1024, file);
    Ok(Bz2Prepared {
        reader,
        max_blocksize,
        initial_carry: header.to_vec(),
    })
}

/// Build the Gatling [`Config`] for bz2 streaming.
pub(crate) fn mk_bz2_cfg(initial_carry: Vec<u8>) -> gatling::Config {
    gatling::Config {
        chunk_size: BZ2_CHUNK_SIZE,
        carry_headroom: BZ2_CARRY_HEADROOM,
        ring_slots: BZ2_RING_SLOTS,
        initial_carry,
        slot_fill: gatling::SlotFill::Incremental,
    }
}

/// Bz2-native streaming path on the Gatling typed engine.
///
/// Pipeline (no barriers, zero-copy decode): Reader → split → N workers each
/// decode + VTD-parse + PBF-encode their block range → in-order Collector
/// stitches boundary stubs and forwards blobs → single Writer thread. The engine
/// (`gatling::run_typed`) owns the slot pool and threading; [`Bz2PbfTypedCodec`]
/// supplies decode+encode, [`PbfTypedSink`] the output.
///
/// Returns `(total_elements, bytes_written)`.
pub fn xml_to_pbf_bz2<R: std::io::Read + Send>(
    mut reader: R,
    out_path: &Path,
    n_workers: usize,
) -> Result<(u64, u64)> {
    let mut header_buf = [0u8; 4];
    reader
        .read_exact(&mut header_buf)
        .context("read bzip2 header")?;
    let max_blocksize = bz2_max_blocksize(&header_buf)?;

    let mut sink = PbfTypedSink::new(out_path)?;
    let codec = Bz2PbfTypedCodec { max_blocksize };
    gatling::run_typed(
        reader,
        codec,
        &mut sink,
        n_workers,
        mk_bz2_cfg(header_buf.to_vec()),
    )?;
    sink.finish()
}

/// Path-based PBF conversion. When `skip_to_nodes` is set, skips the changeset
/// prologue (seeks to the first node/way/relation block). Output is identical to
/// the full run — PBF never contains changesets — just faster.
pub fn xml_to_pbf_bz2_path(
    path: &Path,
    out_path: &Path,
    n_workers: usize,
    skip_to_nodes: bool,
) -> Result<(u64, u64)> {
    let skip = if skip_to_nodes {
        Bz2Skip::Changesets(DATA_NEEDLES)
    } else {
        Bz2Skip::None
    };
    let Bz2Prepared {
        reader,
        max_blocksize,
        initial_carry,
    } = bz2_prepare(path, skip)?;

    let mut sink = PbfTypedSink::new(out_path)?;
    let codec = Bz2PbfTypedCodec { max_blocksize };
    gatling::run_typed(
        reader,
        codec,
        &mut sink,
        n_workers,
        mk_bz2_cfg(initial_carry),
    )?;
    sink.finish()
}
