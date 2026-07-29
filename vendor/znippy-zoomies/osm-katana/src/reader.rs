#![allow(clippy::float_arithmetic, clippy::arithmetic_side_effects)]

use crate::shared::gpu_backend::{GpuBackend, RawWay};
use serde::Serialize;

use crate::{Clip, clip_keeps};
use crate::{geometry, node_store::NodeStore, pbf_decomp, pbf_io, tags};

// ── Records ───────────────────────────────────────────────────────────────────

pub struct NodeRecord {
    pub id: i64,
    pub lon_lat: (f64, f64), // (longitude, latitude) — WKB encoded at write time
    pub tags_json: String,
    pub version: Option<i32>,
}

pub struct WayRecord {
    pub id: i64,
    pub geometry: Option<Vec<u8>>,
    pub tags_json: String,
    pub node_refs: Vec<i64>,
    pub version: Option<i32>,
}

pub struct RelationRecord {
    pub id: i64,
    pub tags_json: String,
    pub members_json: String,
    pub version: Option<i32>,
}

#[derive(Serialize)]
pub(crate) struct MemberEntry {
    #[serde(rename = "type")]
    pub(crate) member_type: &'static str,
    #[serde(rename = "ref")]
    pub(crate) member_ref: i64,
    pub(crate) role: String,
}

pub(crate) struct CollectedWay {
    pub(crate) id: i64,
    pub(crate) coords: Vec<(f64, f64)>,
    pub(crate) tags_json: String,
    pub(crate) node_refs: Vec<i64>,
    pub(crate) version: Option<i32>,
    pub(crate) is_area: bool,
}

// ── Per-blob helpers for streaming PBF pipeline ───────────────────────────────
//
// One function call = one compressed blob. The Gatling PBF codec fans these
// across all cores (one blob per self-dispatched worker) — no rayon, no nesting.

/// Decompress one blob and extract full NodeRecords + coords in one decode.
/// Way/relation blobs return empty vecs. Used by the Gatling PBF pass-1 codec to
/// fuse coord extraction and node-record encoding (single protobuf parse).
#[inline]
pub fn blob_nodes_and_coords(
    data: &[u8],
    pos: &pbf_io::BlobPos,
    clip: Option<&Clip>,
) -> (Vec<NodeRecord>, Vec<(i64, f32, f32)>) {
    data.get(pos.offset..pos.offset.saturating_add(pos.length))
        .and_then(|blob| pbf_decomp::decompress(blob).ok().flatten())
        .map(|bytes| parse_nodes(&bytes, clip))
        .unwrap_or_default()
}

/// Decompress one blob, parse ways+rels, encode WKB.
/// Node blobs return empty vecs.
#[inline]
pub fn blob_ways_rels(
    data: &[u8],
    pos: &pbf_io::BlobPos,
    store: &NodeStore,
    clip_active: bool,
) -> (Vec<WayRecord>, Vec<RelationRecord>) {
    let bytes = match data
        .get(pos.offset..pos.offset.saturating_add(pos.length))
        .and_then(|blob| pbf_decomp::decompress(blob).ok().flatten())
    {
        Some(b) => b,
        None => return (Vec::new(), Vec::new()),
    };
    let (collected, rels) = parse_ways_rels(&bytes, store, clip_active);
    let raw: Vec<RawWay> = collected
        .iter()
        .map(|w| RawWay {
            coords: w.coords.clone(),
            is_area: w.is_area,
        })
        .collect();
    let wkb_list = crate::shared::gpu_backend::CpuBackend.encode_wkb(&raw);
    let ways = collected
        .into_iter()
        .zip(wkb_list)
        .map(|(w, geom)| WayRecord {
            id: w.id,
            geometry: geom,
            tags_json: w.tags_json,
            node_refs: w.node_refs,
            version: w.version,
        })
        .collect();
    (ways, rels)
}

// ── mmap single-pass variants ────────────────────────────────────────────────

/// Pass 1 over a mmap'd PBF: extract only (id, lat, lon) from every blob.
/// Way/relation blobs find no node groups and return empty — fast skip.
pub fn read_pass1_mmap(
    data: &[u8],
    positions: &[crate::pbf_io::BlobPos],
) -> anyhow::Result<NodeStore> {
    read_pass1_mmap_planned(data, positions).map(|(store, _)| store)
}

/// Blob indices that carry ways or relations — the ONLY blobs pass 2 needs.
///
/// Pass 2 used to re-read and re-inflate **every** blob, including the node-only
/// blobs it was always going to find nothing in. On a Sweden clip that was measured
/// at **1693 s of a 2726 s run — 62 %** — and it cost 64 % LONGER than pass 1 to find
/// 8.6 M ways where pass 1 found 96.9 M nodes. The work was not unbalanced; it was
/// done twice.
///
/// The design doc recorded this as blocked: *"the streaming codec's `transform` is
/// handed a slot-relative slice and does not know the blob's absolute file offset, so
/// the map has no key yet."* That is true of the STREAMING path (`.bz2`/`.gz`/XML via
/// `run_typed`) and NOT of the mmap path, which is what a `.pbf` convert actually
/// takes: `BlobPos` carries the absolute `offset`, and the blob's index in
/// `positions` is already a perfectly good key.
///
/// The flag is free. Pass 1 decompresses and protobuf-parses each block anyway, and
/// walks its `primitivegroup`s looking for nodes — so it can see a `ways`/`relations`
/// group in the same walk, with no extra decode.
pub type Pass2Plan = Vec<u32>;

/// Pass 1 that also reports which blobs pass 2 must visit.
///
/// The predicate is *carries ways or relations*, NOT *carries no nodes*. A PBF
/// `PrimitiveBlock` may legally hold groups of different kinds, and although the
/// common writers emit homogeneous blocks, skipping on "this blob had nodes" would
/// silently drop ways out of any mixed block. Asking the question directly costs
/// nothing and cannot be wrong.
pub fn read_pass1_mmap_planned(
    data: &[u8],
    positions: &[crate::pbf_io::BlobPos],
) -> anyhow::Result<(NodeStore, Pass2Plan)> {
    let per_block: Vec<(Vec<(i64, f32, f32)>, bool)> = crate::par::par_map(positions.len(), |i| {
        let p = &positions[i];
        data.get(p.offset..p.offset.saturating_add(p.length))
            .and_then(|blob| pbf_decomp::decompress(blob).ok().flatten())
            .map(|bytes| parse_node_coords_probed(&bytes, None))
            // A blob we could not read at all stays a pass-2 CANDIDATE: the
            // conservative direction is to look again, never to skip unseen.
            .unwrap_or((Vec::new(), true))
    });

    let mut plan: Pass2Plan = Vec::new();
    let mut all_coords: Vec<(i64, f32, f32)> = Vec::new();
    for (i, (coords, has_way_or_rel)) in per_block.into_iter().enumerate() {
        if has_way_or_rel {
            plan.push(i as u32);
        }
        all_coords.extend(coords);
    }

    Ok((NodeStore::from_coords(all_coords), plan))
}

/// Pass 2 over a mmap'd PBF: resolve ways against the completed NodeStore.
/// Node blobs find no way groups and return empty — fast skip.
pub fn read_pass2_mmap(
    data: &[u8],
    positions: &[crate::pbf_io::BlobPos],
    node_store: &NodeStore,
    backend: &dyn GpuBackend,
) -> anyhow::Result<(Vec<WayRecord>, Vec<RelationRecord>)> {
    // No plan ⇒ visit every blob, exactly as before.
    let all: Pass2Plan = (0..positions.len() as u32).collect();
    read_pass2_mmap_planned(data, positions, &all, node_store, backend)
}

/// Pass 2 restricted to the blobs [`read_pass1_mmap_planned`] said carry ways or
/// relations.
///
/// Same work, same order, same output — just without re-inflating the node-only
/// blobs. Those were 62 % of a Sweden clip's wall time and by construction contain
/// nothing pass 2 can use.
pub fn read_pass2_mmap_planned(
    data: &[u8],
    positions: &[crate::pbf_io::BlobPos],
    plan: &[u32],
    node_store: &NodeStore,
    backend: &dyn GpuBackend,
) -> anyhow::Result<(Vec<WayRecord>, Vec<RelationRecord>)> {
    // Parse + WKB-encode each blob ON ITS WORKER. The old shape parsed in
    // parallel but then (a) encoded every way's WKB serially on one core and
    // (b) materialized the WayRecords serially — two 1-core tails after the
    // fan-out. Here each worker resolves its blob's ways AND encodes their WKB
    // (via the shared `backend`, `Send + Sync`), emitting finished WayRecords, so
    // the whole parse→encode→materialize path saturates every core. Balanced by
    // blob byte length (LPT) so a fat blob can't leave the tail on one core.
    let per_block: Vec<(Vec<WayRecord>, Vec<RelationRecord>)> =
        gatling::gatling_forkjoin::gatling_for_each_balanced(
            plan.len(),
            0,
            1,
            |i| positions[plan[i] as usize].length as u64,
            |i| {
                let p = &positions[plan[i] as usize];
                let (collected, rels): (Vec<CollectedWay>, Vec<RelationRecord>) = data
                    .get(p.offset..p.offset.saturating_add(p.length))
                    .and_then(|blob| pbf_decomp::decompress(blob).ok().flatten())
                    .map(|bytes| parse_ways_rels(&bytes, node_store, false))
                    .unwrap_or_default();

                let raw: Vec<RawWay> = collected
                    .iter()
                    .map(|w| RawWay {
                        coords: w.coords.clone(),
                        is_area: w.is_area,
                    })
                    .collect();
                let wkb_list = backend.encode_wkb(&raw);

                let ways: Vec<WayRecord> = collected
                    .into_iter()
                    .zip(wkb_list)
                    .map(|(w, geom)| WayRecord {
                        id: w.id,
                        geometry: geom,
                        tags_json: w.tags_json,
                        node_refs: w.node_refs,
                        version: w.version,
                    })
                    .collect();
                (ways, rels)
            },
        );

    // Materialize = concatenation of finished per-block records (moves only).
    let mut all_ways: Vec<WayRecord> = Vec::new();
    let mut all_rels: Vec<RelationRecord> = Vec::new();
    for (ways, rels) in per_block {
        all_ways.extend(ways);
        all_rels.extend(rels);
    }

    Ok((all_ways, all_rels))
}

// ── Stage 3: parse PrimitiveBlock ─────────────────────────────────────────────

/// Extract only (id, lat, lon) from a PrimitiveBlock — no geometry encoding, no tag
/// serialisation. Used by `read_pass1_store_only` to avoid ~2 GB of throw-away allocations.
fn parse_node_coords(bytes: &[u8], clip: Option<&Clip>) -> Vec<(i64, f32, f32)> {
    parse_node_coords_probed(bytes, clip).0
}

/// [`parse_node_coords`] plus the pass-2 probe: does this block carry any way or
/// relation group?
///
/// One extra `bool` off a walk pass 1 already performs, so pass 2 can skip the
/// node-only blobs instead of re-inflating them. An unparseable block reports `true`
/// — if we could not read it, we must not claim there is nothing in it.
fn parse_node_coords_probed(bytes: &[u8], clip: Option<&Clip>) -> (Vec<(i64, f32, f32)>, bool) {
    use crate::proto::osmformat::PrimitiveBlock;
    use protobuf::Message as _;

    let block = match PrimitiveBlock::parse_from_bytes(bytes) {
        Ok(b) => b,
        Err(_) => return (Vec::new(), true),
    };
    let has_way_or_rel = block
        .primitivegroup
        .iter()
        .any(|g| !g.ways.is_empty() || !g.relations.is_empty());
    (parse_node_coords_inner(&block, clip), has_way_or_rel)
}

fn parse_node_coords_inner(
    block: &crate::proto::osmformat::PrimitiveBlock,
    clip: Option<&Clip>,
) -> Vec<(i64, f32, f32)> {
    let gran = block.granularity.unwrap_or(100) as i64;
    let lat_off = block.lat_offset.unwrap_or(0);
    let lon_off = block.lon_offset.unwrap_or(0);
    let mut coords: Vec<(i64, f32, f32)> = Vec::new();

    for group in &block.primitivegroup {
        if let Some(dense) = group.dense.as_ref() {
            let mut id: i64 = 0;
            let mut lat: i64 = 0;
            let mut lon: i64 = 0;
            let mut kv_pos = 0usize;
            let has_tags = !dense.keys_vals.is_empty();
            for ((&di, &dlat), &dlon) in dense.id.iter().zip(dense.lat.iter()).zip(dense.lon.iter())
            {
                id += di;
                lat += dlat;
                lon += dlon;
                // skip tags — advance kv_pos past this node's key-value pairs
                // (still done for clipped-out nodes so the shared cursor stays
                // in sync, but it is a cheap pointer walk — no alloc, no JSON)
                if has_tags {
                    while let Some(&k) = dense.keys_vals.get(kv_pos) {
                        kv_pos = kv_pos.saturating_add(1);
                        if k == 0 {
                            break;
                        }
                        kv_pos = kv_pos.saturating_add(1); // skip value
                    }
                }
                let lat_deg = (lat_off + gran * lat) as f64 / 1_000_000_000.0;
                let lon_deg = (lon_off + gran * lon) as f64 / 1_000_000_000.0;
                if !clip_keeps(clip, lon_deg, lat_deg) {
                    continue;
                }
                coords.push((id, lat_deg as f32, lon_deg as f32));
            }
        }
        for node in &group.nodes {
            let lat_deg = (lat_off + gran * node.lat.unwrap_or(0)) as f64 / 1_000_000_000.0;
            let lon_deg = (lon_off + gran * node.lon.unwrap_or(0)) as f64 / 1_000_000_000.0;
            if !clip_keeps(clip, lon_deg, lat_deg) {
                continue;
            }
            coords.push((node.id.unwrap_or(0), lat_deg as f32, lon_deg as f32));
        }
    }
    coords
}

fn parse_nodes(bytes: &[u8], clip: Option<&Clip>) -> (Vec<NodeRecord>, Vec<(i64, f32, f32)>) {
    use crate::proto::osmformat::PrimitiveBlock;
    use protobuf::Message as _;

    let block = match PrimitiveBlock::parse_from_bytes(bytes) {
        Ok(b) => b,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let gran = block.granularity.unwrap_or(100) as i64;
    let lat_off = block.lat_offset.unwrap_or(0);
    let lon_off = block.lon_offset.unwrap_or(0);
    let strtab = string_table(&block);

    let mut records: Vec<NodeRecord> = Vec::new();
    let mut coords: Vec<(i64, f32, f32)> = Vec::new();

    for group in &block.primitivegroup {
        // Dense nodes (MessageField<DenseNodes> — use .as_deref() to get Option<&DenseNodes>)
        if let Some(dense) = group.dense.as_ref() {
            let mut id: i64 = 0;
            let mut lat: i64 = 0;
            let mut lon: i64 = 0;
            let mut kv_pos = 0usize;
            let has_tags = !dense.keys_vals.is_empty();

            for (i, ((&di, &dlat), &dlon)) in dense
                .id
                .iter()
                .zip(dense.lat.iter())
                .zip(dense.lon.iter())
                .enumerate()
            {
                id += di;
                lat += dlat;
                lon += dlon;

                let lat_deg = (lat_off + gran * lat) as f64 / 1_000_000_000.0;
                let lon_deg = (lon_off + gran * lon) as f64 / 1_000_000_000.0;

                // Region clip at decode: a clipped-out node still advances the
                // SHARED key/value cursor (a cheap pointer walk, no alloc/JSON),
                // then is skipped before any tag serialisation or record push.
                if !clip_keeps(clip, lon_deg, lat_deg) {
                    if has_tags {
                        kv_pos = skip_dense_tags(&dense.keys_vals, kv_pos);
                    }
                    continue;
                }

                let version = dense
                    .denseinfo
                    .as_ref()
                    .and_then(|di| di.version.get(i))
                    .copied();

                let tags_json = if has_tags {
                    let (json, new_pos) = collect_dense_tags(&dense.keys_vals, kv_pos, &strtab);
                    kv_pos = new_pos;
                    json
                } else {
                    String::from("{}")
                };

                coords.push((id, lat_deg as f32, lon_deg as f32));
                records.push(NodeRecord {
                    id,
                    lon_lat: (lon_deg, lat_deg),
                    tags_json,
                    version,
                });
            }
        }

        // Regular (non-dense) nodes
        for node in &group.nodes {
            let lat_deg = (lat_off + gran * node.lat.unwrap_or(0)) as f64 / 1_000_000_000.0;
            let lon_deg = (lon_off + gran * node.lon.unwrap_or(0)) as f64 / 1_000_000_000.0;
            // Region clip — regular nodes carry their own tags, no shared cursor.
            if !clip_keeps(clip, lon_deg, lat_deg) {
                continue;
            }
            let version = node.info.as_ref().and_then(|i| i.version);
            let tags_json =
                tags::serialize_tags(node.keys.iter().zip(node.vals.iter()).filter_map(
                    |(&k, &v)| Some((*strtab.get(k as usize)?, *strtab.get(v as usize)?)),
                ));

            let id = node.id.unwrap_or(0);
            coords.push((id, lat_deg as f32, lon_deg as f32));
            records.push(NodeRecord {
                id,
                lon_lat: (lon_deg, lat_deg),
                tags_json,
                version,
            });
        }
    }

    (records, coords)
}

fn parse_ways_rels(
    bytes: &[u8],
    store: &NodeStore,
    clip_active: bool,
) -> (Vec<CollectedWay>, Vec<RelationRecord>) {
    use crate::proto::osmformat::PrimitiveBlock;
    use protobuf::Message as _;

    let block = match PrimitiveBlock::parse_from_bytes(bytes) {
        Ok(b) => b,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let strtab = string_table(&block);
    let mut ways: Vec<CollectedWay> = Vec::new();
    let mut rels: Vec<RelationRecord> = Vec::new();

    // Collect all way metadata + refs, then batch-resolve all node IDs at once.
    struct WayPending {
        id: i64,
        version: Option<i32>,
        tags_json: String,
        refs: Vec<i64>,
        is_area: bool,
        ref_offset: usize, // index into all_refs
    }
    let mut pending: Vec<WayPending> = Vec::new();
    let mut all_refs: Vec<i64> = Vec::new();

    for group in &block.primitivegroup {
        for way in &group.ways {
            let id = way.id.unwrap_or(0);
            let version = way.info.as_ref().and_then(|i| i.version);

            let tags_map: std::collections::HashMap<String, String> = way
                .keys
                .iter()
                .zip(way.vals.iter())
                .filter_map(|(&k, &v)| {
                    let key = strtab.get(k as usize)?;
                    let val = strtab.get(v as usize)?;
                    Some(((*key).to_string(), (*val).to_string()))
                })
                .collect();

            let tags_json =
                tags::serialize_tags(tags_map.iter().map(|(k, v)| (k.as_str(), v.as_str())));

            let mut r: i64 = 0;
            let refs: Vec<i64> = way
                .refs
                .iter()
                .map(|&delta| {
                    r += delta;
                    r
                })
                .collect();

            let is_area = geometry::is_closed_area(&refs, &tags_map);
            let ref_offset = all_refs.len();
            all_refs.extend_from_slice(&refs);
            pending.push(WayPending {
                id,
                version,
                tags_json,
                refs,
                is_area,
                ref_offset,
            });
        }

        for rel in &group.relations {
            let id = rel.id.unwrap_or(0);
            let version = rel.info.as_ref().and_then(|i| i.version);
            let tags_json =
                tags::serialize_tags(rel.keys.iter().zip(rel.vals.iter()).filter_map(
                    |(&k, &v)| Some((*strtab.get(k as usize)?, *strtab.get(v as usize)?)),
                ));

            // Delta-decode member IDs
            let mut memid: i64 = 0;
            let members: Vec<MemberEntry> = rel
                .memids
                .iter()
                .zip(rel.roles_sid.iter())
                .zip(rel.types.iter())
                .filter_map(|((&dm, &role_sid), mtype)| {
                    memid += dm;
                    let role = strtab
                        .get(role_sid as usize)
                        .copied()
                        .unwrap_or("")
                        .to_string();
                    use crate::proto::osmformat::relation::MemberType;
                    let member_type = match mtype.enum_value_or_default() {
                        MemberType::NODE => "node",
                        MemberType::WAY => "way",
                        MemberType::RELATION => "relation",
                    };
                    Some(MemberEntry {
                        member_type,
                        member_ref: memid,
                        role,
                    })
                })
                .collect();

            let members_json =
                serde_json::to_string(&members).unwrap_or_else(|_| String::from("[]"));

            rels.push(RelationRecord {
                id,
                tags_json,
                members_json,
                version,
            });
        }
    }

    // Batch-resolve all node refs at once using Ragnar's pipelined prefetch
    let resolved = store.lookup_batch(&all_refs);
    for wp in pending {
        let n = wp.refs.len();
        let coords: Vec<(f64, f64)> = resolved[wp.ref_offset..wp.ref_offset + n]
            .iter()
            .filter_map(|opt| opt.map(|(lat, lon)| (lon as f64, lat as f64)))
            .collect();
        // Region-clip way semantics (node membership): with a clip active the
        // node store holds ONLY in-region nodes, so a way with zero resolvable
        // coords lies entirely outside the region → drop it. A way that crosses
        // the boundary keeps its in-region endpoints (truncated, not edge-clipped
        // — documented). Without a clip every way is kept (unchanged behaviour).
        if clip_active && coords.is_empty() {
            continue;
        }
        ways.push(CollectedWay {
            id: wp.id,
            coords,
            tags_json: wp.tags_json,
            node_refs: wp.refs,
            version: wp.version,
            is_area: wp.is_area,
        });
    }

    (ways, rels)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn string_table<'a>(block: &'a crate::proto::osmformat::PrimitiveBlock) -> Vec<&'a str> {
    block
        .stringtable
        .as_ref()
        .map(|st| {
            st.s.iter()
                .map(|b| std::str::from_utf8(b).unwrap_or(""))
                .collect()
        })
        .unwrap_or_default()
}

/// Consume dense node key-value pairs up to (and including) the 0 separator.
/// Returns (tags_json, new_kv_pos).
/// Advance the shared dense key/value cursor past one node's tags WITHOUT
/// building any string — used for clipped-out dense nodes so the next node's
/// cursor stays in sync at zero JSON/alloc cost.
#[inline]
fn skip_dense_tags(kv: &[i32], mut pos: usize) -> usize {
    while let Some(&k) = kv.get(pos) {
        pos = pos.saturating_add(1);
        if k == 0 {
            break;
        }
        pos = pos.saturating_add(1); // skip value
    }
    pos
}

fn collect_dense_tags(kv: &[i32], mut pos: usize, strtab: &[&str]) -> (String, usize) {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    loop {
        let k = kv.get(pos).copied().unwrap_or(0);
        pos = pos.saturating_add(1);
        if k == 0 {
            break;
        }
        let v = kv.get(pos).copied().unwrap_or(0);
        pos = pos.saturating_add(1);
        if let (Some(&key), Some(&val)) = (strtab.get(k as usize), strtab.get(v as usize)) {
            pairs.push((key, val));
        }
    }
    (tags::serialize_tags(pairs.into_iter()), pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pbf_enc;
    use crate::shared::gpu_backend::CpuBackend;

    /// Encode one OSMData blob: dense nodes `ids[i]` at `(lat_e7, lon_e7)` on a
    /// diagonal, plus one way per `way_refs` entry (no tags).
    fn blob(ids: &[i64], way_refs: &[Vec<i64>]) -> Vec<u8> {
        let st = pbf_enc::StringTable::new();
        let mut dn = pbf_enc::DenseNodesBuilder::new();
        for (k, &id) in ids.iter().enumerate() {
            let c = (k as i32 + 1) * 1_000; // arbitrary, distinct coords
            dn.push(id, c, c, &[]);
        }
        let ways: Vec<Vec<u8>> = way_refs
            .iter()
            .enumerate()
            .map(|(i, refs)| pbf_enc::encode_way(1_000 + i as i64, &[], refs))
            .collect();
        pbf_enc::encode_primitive_block(&st, Some(&dn), &ways, &[])
    }

    /// Frame a full PBF (`OSMHeader` + one `OSMData` blob per block) in memory.
    fn pbf_file(blocks: &[Vec<u8>]) -> Vec<u8> {
        use std::io::Cursor;
        let mut bytes: Vec<u8> = Vec::new();
        let mut cur = Cursor::new(&mut bytes);
        pbf_enc::write_osm_header(&mut cur).unwrap();
        for block in blocks {
            let zstd = pbf_enc::compress_zstd(block).unwrap();
            pbf_enc::write_blob(&mut cur, b"OSMData", block.len(), &zstd).unwrap();
        }
        drop(cur);
        bytes
    }

    /// Core-saturation correctness for `read_pass2_mmap`: the reworked path
    /// (parse + WKB-encode + build WayRecords ON THE WORKER via a balanced
    /// fan-out, then concatenate) must yield byte-identical WKB geometries, in
    /// the same order, as a SERIAL reference that parses every blob in order,
    /// encodes WKB once on one core, and zips. Pushing the encode into the worker
    /// only changes WHICH core does each blob — never the bytes or the order.
    #[test]
    fn read_pass2_parallel_wkb_matches_serial() {
        // SKEWED across three blobs: blob 0 carries one fat way (60 nodes),
        // blobs 1 and 2 carry several tiny ways — the exact shape that tail-chokes
        // a plain fan-out and that the LPT balance is meant to spread.
        let heavy_ids: Vec<i64> = (1..=60).collect();
        let b0 = blob(&heavy_ids, &[heavy_ids.clone()]);
        let b1 = blob(
            &[100, 101, 102, 103],
            &[vec![100, 101, 102], vec![101, 102, 103]],
        );
        let b2 = blob(&[200, 201, 202], &[vec![200, 201, 202], vec![200, 202]]);
        let data = pbf_file(&[b0, b1, b2]);

        let positions = crate::pbf_io::scan_blob_positions_par(&data);
        assert!(
            positions.len() >= 3,
            "expected ≥3 blobs, got {}",
            positions.len()
        );
        let store = read_pass1_mmap(&data, &positions).unwrap();

        // Parallel path under test.
        let backend = CpuBackend;
        let (par_ways, _rels) = read_pass2_mmap(&data, &positions, &store, &backend).unwrap();
        let par_pairs: Vec<(i64, Option<Vec<u8>>)> = par_ways
            .iter()
            .map(|w| (w.id, w.geometry.clone()))
            .collect();

        // Serial reference: parse each blob in order, encode WKB once, zip.
        let mut all_collected: Vec<CollectedWay> = Vec::new();
        for p in &positions {
            if let Some(bytes) = data
                .get(p.offset..p.offset.saturating_add(p.length))
                .and_then(|blob| pbf_decomp::decompress(blob).ok().flatten())
            {
                let (c, _r) = parse_ways_rels(&bytes, &store, false);
                all_collected.extend(c);
            }
        }
        let raw: Vec<RawWay> = all_collected
            .iter()
            .map(|w| RawWay {
                coords: w.coords.clone(),
                is_area: w.is_area,
            })
            .collect();
        let wkb = CpuBackend.encode_wkb(&raw);
        let serial_pairs: Vec<(i64, Option<Vec<u8>>)> = all_collected
            .iter()
            .zip(wkb)
            .map(|(w, g)| (w.id, g))
            .collect();

        assert!(!serial_pairs.is_empty(), "reference produced no ways");
        assert!(
            serial_pairs.iter().any(|(_, g)| g.is_some()),
            "reference produced no WKB geometry"
        );
        assert_eq!(
            par_pairs, serial_pairs,
            "parallel in-worker WKB must equal the serial-WKB reference (id + bytes + order)"
        );
    }
}
