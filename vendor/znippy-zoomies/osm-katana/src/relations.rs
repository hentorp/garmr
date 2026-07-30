#![allow(clippy::float_arithmetic, clippy::arithmetic_side_effects)]

//! Admin-boundary **relation** assembly: OSM `boundary=administrative` (and the
//! general `type=multipolygon` / `type=boundary`) relations are multipolygons,
//! not single ways. The PBF read path resolves member ways' node geometry; here
//! we stitch those unordered member ways end-to-end into closed rings, group the
//! holes (inner rings) under the outer rings that contain them, and emit one
//! **WKB MultiPolygon** per relation.
//!
//! Messy real-world relations (ways that don't close into a ring, members whose
//! nodes didn't resolve) are skipped with a logged reason rather than panicking —
//! a relation keeps whatever rings it could close.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::reader;
use crate::shared::geometry::decode_coords;

/// One assembled admin relation: its tags (same JSON map shape as `PbfWayRecord`)
/// plus a WKB **MultiPolygon** of its assembled rings (`None` if no outer ring
/// could be closed). The `(id, tags, geometry)` triple is exactly what a borders
/// collector consumes — mirrors [`crate::PbfWayRecord`].
pub struct PbfAdminRelation {
    pub id: i64,
    /// WKB-encoded MultiPolygon (type 6) in (lon, lat); `None` if no ring closed.
    pub geometry: Option<Vec<u8>>,
    /// JSON-serialised tag map, e.g. `{"boundary":"administrative","admin_level":"7"}`.
    pub tags: String,
    /// Number of outer rings (polygons) successfully closed.
    pub outer_rings: usize,
    /// Number of inner rings (holes) successfully closed and placed.
    pub inner_rings: usize,
}

/// A member way contributing to ring assembly: its node-id sequence (used for
/// exact endpoint matching when stitching) and its resolved `(lon, lat)`
/// coordinates (used to build geometry). The two are index-aligned.
#[derive(Clone)]
pub(crate) struct MemberWay {
    pub(crate) nodes: Vec<i64>,
    pub(crate) coords: Vec<(f64, f64)>,
}

#[derive(Deserialize)]
struct RawMember {
    #[serde(rename = "type")]
    member_type: String,
    #[serde(rename = "ref")]
    member_ref: i64,
    #[serde(default)]
    role: String,
}

/// True if a relation's tags mark it as an area we assemble: an administrative
/// boundary, or generally a `type=multipolygon` / `type=boundary` relation.
fn is_assembled_relation(tags: &serde_json::Value) -> bool {
    let rel_type = tags.get("type").and_then(|v| v.as_str());
    matches!(rel_type, Some("multipolygon") | Some("boundary"))
        || tags.get("boundary").and_then(|v| v.as_str()) == Some("administrative")
}

/// Two-pass PBF → assembled admin-boundary relations as WKB MultiPolygons.
///
/// Pass 1 builds a node-ID → (lat, lon) store; pass 2 resolves member ways. We
/// then keep only `boundary=administrative` / `type=multipolygon|boundary`
/// relations, stitch their member ways into rings, and assemble a MultiPolygon
/// per relation. Pure Rust, no JVM — same shape as [`crate::load_ways_pbf`].
pub fn load_admin_boundaries_pbf(pbf_path: &str) -> anyhow::Result<Vec<PbfAdminRelation>> {
    use anyhow::Context as _;
    use memmap2::MmapOptions;

    let file = std::fs::File::open(pbf_path).with_context(|| format!("open {pbf_path}"))?;
    // SAFETY: file is not modified while the mmap is alive.
    let mmap =
        unsafe { MmapOptions::new().map(&file) }.with_context(|| format!("mmap {pbf_path}"))?;

    let positions = crate::pbf_io::scan_blob_positions_par(&mmap);
    let store = reader::read_pass1_mmap(&mmap, &positions)?;
    let backend = crate::shared::gpu_backend::CpuBackend;
    let (ways, rels) = reader::read_pass2_mmap(&mmap, &positions, &store, &backend)?;

    assemble_relations(ways, rels)
}

/// The in-memory half of [`load_admin_boundaries_pbf`], split out so the read
/// path and the assembly logic can be exercised independently.
pub(crate) fn assemble_relations(
    ways: Vec<reader::WayRecord>,
    rels: Vec<reader::RelationRecord>,
) -> anyhow::Result<Vec<PbfAdminRelation>> {
    // 1. Keep only the relations we assemble, decode their tags + members once.
    struct Kept {
        id: i64,
        tags: String,
        outers: Vec<i64>,
        inners: Vec<i64>,
    }
    let mut kept: Vec<Kept> = Vec::new();
    let mut needed: HashSet<i64> = HashSet::new();

    for rel in &rels {
        let tags_val: serde_json::Value = match serde_json::from_str(&rel.tags_json) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !is_assembled_relation(&tags_val) {
            continue;
        }
        let members: Vec<RawMember> = serde_json::from_str(&rel.members_json).unwrap_or_default();
        let mut outers = Vec::new();
        let mut inners = Vec::new();
        for m in members {
            if m.member_type != "way" {
                continue; // node/relation members carry no ring geometry
            }
            if m.role == "inner" {
                inners.push(m.member_ref);
            } else {
                // outer | empty | (any other way role) → treat as outer ring part
                outers.push(m.member_ref);
            }
            needed.insert(m.member_ref);
        }
        if outers.is_empty() && inners.is_empty() {
            continue;
        }
        kept.push(Kept {
            id: rel.id,
            tags: rel.tags_json.clone(),
            outers,
            inners,
        });
    }

    // 2. Build a way map (id → node-ids + coords) only for the ways we need,
    //    decoding the already-WKB-encoded way geometry back to coordinates.
    let mut way_map: HashMap<i64, MemberWay> = HashMap::new();
    for w in &ways {
        if !needed.contains(&w.id) {
            continue;
        }
        let Some(wkb) = w.geometry.as_ref() else {
            continue;
        };
        let Some(coords) = decode_coords(wkb) else {
            continue;
        };
        if coords.len() != w.node_refs.len() || coords.len() < 2 {
            // Coords come from the same resolved pass as node_refs; a mismatch
            // means some node didn't resolve — skip, can't match endpoints safely.
            continue;
        }
        way_map.insert(
            w.id,
            MemberWay {
                nodes: w.node_refs.clone(),
                coords,
            },
        );
    }

    // 3. Assemble each kept relation into a MultiPolygon.
    let mut out = Vec::with_capacity(kept.len());
    for k in kept {
        let gather = |refs: &[i64]| -> Vec<MemberWay> {
            refs.iter()
                .filter_map(|r| way_map.get(r).cloned())
                .collect()
        };
        let outer_ways = gather(&k.outers);
        let inner_ways = gather(&k.inners);

        let (geometry, outer_rings, inner_rings) =
            match build_multipolygon(outer_ways, inner_ways, k.id) {
                Some((wkb, o, i)) => (Some(wkb), o, i),
                None => (None, 0, 0),
            };

        out.push(PbfAdminRelation {
            id: k.id,
            geometry,
            tags: k.tags,
            outer_rings,
            inner_rings,
        });
    }

    Ok(out)
}

/// Assemble outer + inner member ways into a WKB MultiPolygon. Returns the WKB
/// bytes and the (outer-ring, inner-ring) counts, or `None` if not a single
/// outer ring could be closed. Inner rings (holes) are placed under the first
/// outer ring that geometrically contains them.
pub(crate) fn build_multipolygon(
    outer_ways: Vec<MemberWay>,
    inner_ways: Vec<MemberWay>,
    rel_id: i64,
) -> Option<(Vec<u8>, usize, usize)> {
    let (mut outer_rings, outer_skipped) = assemble_rings(outer_ways);
    let (inner_rings, inner_skipped) = assemble_rings(inner_ways);

    for reason in outer_skipped.iter().chain(inner_skipped.iter()) {
        eprintln!("  osm-katana relation {rel_id}: {reason}");
    }

    if outer_rings.is_empty() {
        return None;
    }

    // Orient outer rings CCW (positive signed area) for a canonical winding.
    for ring in &mut outer_rings {
        if signed_area(ring) < 0.0 {
            ring.reverse();
        }
    }

    // Each polygon is (outer_ring, holes). Place every inner ring under the
    // first outer ring that contains its representative point.
    let mut polys: Vec<(Vec<(f64, f64)>, Vec<Vec<(f64, f64)>>)> =
        outer_rings.into_iter().map(|r| (r, Vec::new())).collect();

    let mut placed_inners = 0usize;
    for mut hole in inner_rings {
        let pt = representative_point(&hole);
        if let Some((outer, holes)) = polys.iter_mut().find(|(outer, _)| point_in_ring(pt, outer)) {
            // Orient hole CW (negative signed area), opposite the outer.
            if signed_area(&hole) > 0.0 {
                hole.reverse();
            }
            let _ = outer; // containment already checked
            holes.push(hole);
            placed_inners += 1;
        } else {
            eprintln!(
                "  osm-katana relation {rel_id}: inner ring not contained by any outer ring — dropped"
            );
        }
    }

    let outer_count = polys.len();
    let wkb = wkb_multipolygon(&polys);
    Some((wkb, outer_count, placed_inners))
}

/// Stitch unordered member ways end-to-end into closed rings.
///
/// Ways in a relation are unordered and may need reversing; we grow a ring from
/// an unused way, then repeatedly attach any unused way whose first or last
/// **node id** equals the ring's current tail (reversing it when joined by its
/// tail). A ring is complete when its first node id equals its last. Ways that
/// can't be closed into a ring are reported (and their nodes dropped from the
/// geometry) rather than panicking.
pub(crate) fn assemble_rings(ways: Vec<MemberWay>) -> (Vec<Vec<(f64, f64)>>, Vec<String>) {
    // Drop degenerate members up front.
    let ways: Vec<MemberWay> = ways
        .into_iter()
        .filter(|w| w.nodes.len() >= 2 && w.nodes.len() == w.coords.len())
        .collect();

    let mut rings: Vec<Vec<(f64, f64)>> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut used = vec![false; ways.len()];

    for start in 0..ways.len() {
        if used[start] {
            continue;
        }
        used[start] = true;
        let mut ring_nodes: Vec<i64> = ways[start].nodes.clone();
        let mut ring_coords: Vec<(f64, f64)> = ways[start].coords.clone();

        loop {
            if is_closed(&ring_nodes) {
                break;
            }
            let tail = *ring_nodes.last().expect("non-empty by construction");
            let mut found = false;
            for j in 0..ways.len() {
                if used[j] {
                    continue;
                }
                let w = &ways[j];
                let head_id = w.nodes[0];
                let last_id = *w.nodes.last().expect("len >= 2");
                if head_id == tail {
                    ring_nodes.extend_from_slice(&w.nodes[1..]);
                    ring_coords.extend_from_slice(&w.coords[1..]);
                    used[j] = true;
                    found = true;
                    break;
                } else if last_id == tail {
                    for k in (0..w.nodes.len() - 1).rev() {
                        ring_nodes.push(w.nodes[k]);
                        ring_coords.push(w.coords[k]);
                    }
                    used[j] = true;
                    found = true;
                    break;
                }
            }
            if !found {
                break;
            }
        }

        if is_closed(&ring_nodes) {
            // Ensure the geometry ring is explicitly closed (first == last point).
            if ring_coords.first() != ring_coords.last() {
                if let Some(&first) = ring_coords.first() {
                    ring_coords.push(first);
                }
            }
            rings.push(ring_coords);
        } else {
            skipped.push(format!(
                "open ring ({} nodes, ends {}..{}) could not be closed — skipped",
                ring_nodes.len(),
                ring_nodes.first().copied().unwrap_or(0),
                ring_nodes.last().copied().unwrap_or(0),
            ));
        }
    }

    (rings, skipped)
}

/// A node sequence is a closed ring if it has at least 4 nodes and its first id
/// equals its last (3 distinct corners + the repeated closing node).
fn is_closed(nodes: &[i64]) -> bool {
    nodes.len() >= 4 && nodes.first() == nodes.last()
}

/// Signed area of a closed ring via the shoelace formula. Positive ⇒ CCW.
fn signed_area(ring: &[(f64, f64)]) -> f64 {
    if ring.len() < 3 {
        return 0.0;
    }
    let mut a = 0.0;
    for i in 0..ring.len() - 1 {
        let (x1, y1) = ring[i];
        let (x2, y2) = ring[i + 1];
        a += x1 * y2 - x2 * y1;
    }
    a / 2.0
}

/// A point that lies strictly inside a simple ring: the centroid of its
/// (de-duplicated) vertices is a robust-enough representative for hole placement.
fn representative_point(ring: &[(f64, f64)]) -> (f64, f64) {
    let n = if ring.len() > 1 && ring.first() == ring.last() {
        ring.len() - 1 // drop the repeated closing vertex
    } else {
        ring.len()
    };
    if n == 0 {
        return (0.0, 0.0);
    }
    let mut sx = 0.0;
    let mut sy = 0.0;
    for &(x, y) in &ring[..n] {
        sx += x;
        sy += y;
    }
    (sx / n as f64, sy / n as f64)
}

/// Even-odd ray-cast point-in-polygon for a single closed ring.
fn point_in_ring((lon, lat): (f64, f64), ring: &[(f64, f64)]) -> bool {
    let n = ring.len();
    if n < 3 {
        return false;
    }
    let mut inside = false;
    let mut j = n - 1;
    for i in 0..n {
        let (xi, yi) = ring[i];
        let (xj, yj) = ring[j];
        if ((yi > lat) != (yj > lat)) && (lon < (xj - xi) * (lat - yi) / (yj - yi) + xi) {
            inside = !inside;
        }
        j = i;
    }
    inside
}

/// Encode polygons (each `(outer_ring, holes)`) as a WKB MultiPolygon (type 6),
/// little-endian, coordinates in (lon, lat). Every ring is emitted closed.
fn wkb_multipolygon(polys: &[(Vec<(f64, f64)>, Vec<Vec<(f64, f64)>>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(1u8); // little-endian
    buf.extend_from_slice(&6u32.to_le_bytes()); // WKB MultiPolygon
    buf.extend_from_slice(&(polys.len() as u32).to_le_bytes());
    for (outer, holes) in polys {
        buf.push(1u8);
        buf.extend_from_slice(&3u32.to_le_bytes()); // WKB Polygon
        let ring_count = 1 + holes.len();
        buf.extend_from_slice(&(ring_count as u32).to_le_bytes());
        push_ring(&mut buf, outer);
        for hole in holes {
            push_ring(&mut buf, hole);
        }
    }
    buf
}

/// Append one WKB linear ring (point count + closed point list).
fn push_ring(buf: &mut Vec<u8>, ring: &[(f64, f64)]) {
    let closed_extra = if ring.len() > 1 && ring.first() != ring.last() {
        1
    } else {
        0
    };
    let n = ring.len() + closed_extra;
    buf.extend_from_slice(&(n as u32).to_le_bytes());
    for &(x, y) in ring {
        buf.extend_from_slice(&x.to_le_bytes());
        buf.extend_from_slice(&y.to_le_bytes());
    }
    if closed_extra == 1 {
        if let Some(&(x, y)) = ring.first() {
            buf.extend_from_slice(&x.to_le_bytes());
            buf.extend_from_slice(&y.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a member way from explicit (id, lon, lat) vertices.
    fn way(verts: &[(i64, f64, f64)]) -> MemberWay {
        MemberWay {
            nodes: verts.iter().map(|&(id, _, _)| id).collect(),
            coords: verts.iter().map(|&(_, lon, lat)| (lon, lat)).collect(),
        }
    }

    /// Absolute polygon area from a closed ring (shoelace).
    fn ring_area(ring: &[(f64, f64)]) -> f64 {
        signed_area(ring).abs()
    }

    /// FAIL-ON-BUG: two open ways that share endpoints stitch into one closed
    /// square ring — the load-bearing relation logic. A relation's ways are
    /// unordered and one is given reversed; the stitcher must still close it.
    #[test]
    fn stitch_two_ways_into_closed_square() {
        // Square (0,0)-(4,0)-(4,4)-(0,4). Way A is the lower+right edge, way B is
        // the upper+left edge given in REVERSED node order to force a flip.
        let a = way(&[(1, 0.0, 0.0), (2, 4.0, 0.0), (3, 4.0, 4.0)]);
        let b = way(&[(1, 0.0, 0.0), (4, 0.0, 4.0), (3, 4.0, 4.0)]); // 3..1 reversed vs ring
        let (rings, skipped) = assemble_rings(vec![a, b]);
        assert!(
            skipped.is_empty(),
            "both ways should close, got skips: {skipped:?}"
        );
        assert_eq!(rings.len(), 1, "two ways → exactly one ring");
        let r = &rings[0];
        assert_eq!(r.first(), r.last(), "ring must be explicitly closed");
        assert!(
            (ring_area(r) - 16.0).abs() < 1e-9,
            "4x4 square area = 16, got {}",
            ring_area(r)
        );
    }

    /// A single already-closed way is a ring on its own.
    #[test]
    fn single_closed_way_is_a_ring() {
        let sq = way(&[
            (1, 0.0, 0.0),
            (2, 2.0, 0.0),
            (3, 2.0, 2.0),
            (4, 0.0, 2.0),
            (1, 0.0, 0.0),
        ]);
        let (rings, skipped) = assemble_rings(vec![sq]);
        assert!(skipped.is_empty());
        assert_eq!(rings.len(), 1);
        assert!((ring_area(&rings[0]) - 4.0).abs() < 1e-9);
    }

    /// An open chain that never closes is reported, not panicked on.
    #[test]
    fn open_chain_is_skipped() {
        let open = way(&[(1, 0.0, 0.0), (2, 1.0, 0.0), (3, 2.0, 0.0)]);
        let (rings, skipped) = assemble_rings(vec![open]);
        assert!(rings.is_empty(), "an open line is not a ring");
        assert_eq!(skipped.len(), 1, "the open chain is reported");
    }

    /// FAIL-ON-BUG: a square outer with a square hole assembles into a
    /// MultiPolygon whose Polygon has 2 rings, hole placed under the outer.
    #[test]
    fn outer_with_inner_hole_builds_multipolygon() {
        // Outer 0..10 square (two ways), inner 3..7 hole (one closed way).
        let outer_a = way(&[(1, 0.0, 0.0), (2, 10.0, 0.0), (3, 10.0, 10.0)]);
        let outer_b = way(&[(3, 10.0, 10.0), (4, 0.0, 10.0), (1, 0.0, 0.0)]);
        let inner = way(&[
            (11, 3.0, 3.0),
            (12, 7.0, 3.0),
            (13, 7.0, 7.0),
            (14, 3.0, 7.0),
            (11, 3.0, 3.0),
        ]);
        let (wkb, outers, inners) =
            build_multipolygon(vec![outer_a, outer_b], vec![inner], 42).expect("an outer ring");
        assert_eq!(outers, 1, "one outer ring");
        assert_eq!(inners, 1, "hole placed under the outer");

        // WKB header: byte order 1, type 6 (MultiPolygon), 1 polygon, 2 rings.
        assert_eq!(wkb[0], 1, "little-endian");
        assert_eq!(
            u32::from_le_bytes(wkb[1..5].try_into().unwrap()),
            6,
            "MultiPolygon"
        );
        assert_eq!(
            u32::from_le_bytes(wkb[5..9].try_into().unwrap()),
            1,
            "1 polygon"
        );
        // polygon header at offset 9: byte order, type 3, ring count
        assert_eq!(wkb[9], 1);
        assert_eq!(
            u32::from_le_bytes(wkb[10..14].try_into().unwrap()),
            3,
            "Polygon"
        );
        assert_eq!(
            u32::from_le_bytes(wkb[14..18].try_into().unwrap()),
            2,
            "outer + 1 hole = 2 rings"
        );
    }

    /// Read the absolute area of the first ring of the first polygon of a WKB
    /// MultiPolygon (test-only sanity decoder).
    fn first_ring_area(wkb: &[u8]) -> f64 {
        assert_eq!(wkb[0], 1);
        assert_eq!(
            u32::from_le_bytes(wkb[1..5].try_into().unwrap()),
            6,
            "MultiPolygon"
        );
        // skip 1 (order) + 4 (type) + 4 (npolys) = 9; polygon: 1 + 4 (type) + 4 (nrings) = 9 → 18
        let npoints = u32::from_le_bytes(wkb[18..22].try_into().unwrap()) as usize;
        let mut ring = Vec::with_capacity(npoints);
        for i in 0..npoints {
            let base = 22 + i * 16;
            let x = f64::from_le_bytes(wkb[base..base + 8].try_into().unwrap());
            let y = f64::from_le_bytes(wkb[base + 8..base + 16].try_into().unwrap());
            ring.push((x, y));
        }
        ring_area(&ring)
    }

    /// FAIL-ON-BUG / PASS-ON-FIX: a real synthetic PBF carrying a two-way
    /// `boundary=administrative` relation, read through the production two-pass
    /// PBF path (`load_admin_boundaries_pbf`), yields exactly one admin relation
    /// whose geometry is a closed WKB MultiPolygon with the right area and whose
    /// tags survive for the downstream collector. If `RelationRecord` were still
    /// discarded (the gap), this returns zero relations and fails.
    #[test]
    fn load_admin_boundaries_from_synthetic_pbf() {
        use crate::pbf_enc;
        use std::io::Cursor;

        let mut st = pbf_enc::StringTable::new();
        let k_boundary = st.intern(b"boundary");
        let v_admin = st.intern(b"administrative");
        let k_level = st.intern(b"admin_level");
        let v_seven = st.intern(b"7");
        let k_type = st.intern(b"type");
        let v_boundary = st.intern(b"boundary");
        let k_name = st.intern(b"name");
        let v_name = st.intern(b"Testville");
        let role_outer = st.intern(b"outer");

        // Square 0..10 corners: ids 1..4.
        let mut dn = pbf_enc::DenseNodesBuilder::new();
        dn.push(1, 0, 0, &[]);
        dn.push(2, 0, (10.0 * 1e7) as i32, &[]); // lon 10
        dn.push(3, (10.0 * 1e7) as i32, (10.0 * 1e7) as i32, &[]); // (10,10)
        dn.push(4, (10.0 * 1e7) as i32, 0, &[]); // lat 10
        // Two outer member ways: 1→2→3 and 3→4→1 (closes the square).
        let way_a = pbf_enc::encode_way(100, &[], &[1, 2, 3]);
        let way_b = pbf_enc::encode_way(101, &[], &[3, 4, 1]);
        // Relation 200: admin boundary made of both ways.
        let rel = pbf_enc::encode_relation(
            200,
            &[
                (k_boundary, v_admin),
                (k_level, v_seven),
                (k_type, v_boundary),
                (k_name, v_name),
            ],
            &[(1, 100, role_outer), (1, 101, role_outer)], // member type 1 = way
        );

        let block = pbf_enc::encode_primitive_block(&st, Some(&dn), &[way_a, way_b], &[rel]);
        let zstd = pbf_enc::compress_zstd(&block).unwrap();
        let mut bytes: Vec<u8> = Vec::new();
        {
            let mut cur = Cursor::new(&mut bytes);
            pbf_enc::write_osm_header(&mut cur).unwrap();
            pbf_enc::write_blob(&mut cur, b"OSMData", block.len(), &zstd).unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let pbf = dir.path().join("admin.osm.pbf");
        std::fs::write(&pbf, &bytes).unwrap();

        let rels = load_admin_boundaries_pbf(pbf.to_str().unwrap()).unwrap();
        assert_eq!(rels.len(), 1, "exactly one admin relation assembled");
        let r = &rels[0];
        assert_eq!(r.id, 200);
        assert_eq!(r.outer_rings, 1, "the two ways close into one outer ring");
        assert_eq!(r.inner_rings, 0);
        let wkb = r
            .geometry
            .as_ref()
            .expect("assembled MultiPolygon geometry");
        assert!(
            (first_ring_area(wkb) - 100.0).abs() < 1e-3,
            "10x10 square area ≈ 100, got {}",
            first_ring_area(wkb)
        );
        // Tags survive verbatim for the downstream admin collector.
        assert!(
            r.tags.contains("administrative"),
            "tags carry boundary=administrative: {}",
            r.tags
        );
        assert!(
            r.tags.contains("Testville"),
            "tags carry the name: {}",
            r.tags
        );
    }

    /// Hole placement is geometric: an inner ring outside the outer is dropped.
    #[test]
    fn inner_outside_outer_is_dropped() {
        let outer_a = way(&[(1, 0.0, 0.0), (2, 4.0, 0.0), (3, 4.0, 4.0)]);
        let outer_b = way(&[(3, 4.0, 4.0), (4, 0.0, 4.0), (1, 0.0, 0.0)]);
        // Inner ring far away (100,100): contained by no outer → dropped.
        let stray = way(&[
            (11, 100.0, 100.0),
            (12, 101.0, 100.0),
            (13, 101.0, 101.0),
            (11, 100.0, 100.0),
        ]);
        let (_wkb, outers, inners) =
            build_multipolygon(vec![outer_a, outer_b], vec![stray], 7).expect("outer ring");
        assert_eq!(outers, 1);
        assert_eq!(inners, 0, "stray inner ring is not placed under any outer");
    }
}
