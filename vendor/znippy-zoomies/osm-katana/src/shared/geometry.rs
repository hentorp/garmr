#![allow(clippy::arithmetic_side_effects)]

/// Decode a WKB byte slice into a flat list of (lon, lat) pairs.
/// Handles Point (1), LineString (2), and Polygon exterior ring (3).
/// Returns `None` for unsupported or malformed WKB.
pub fn decode_coords(wkb: &[u8]) -> Option<Vec<(f64, f64)>> {
    if wkb.len() < 5 {
        return None;
    }
    let wkb_type = u32::from_le_bytes(wkb.get(1..5)?.try_into().ok()?);
    match wkb_type {
        1 => {
            let x = f64::from_le_bytes(wkb.get(5..13)?.try_into().ok()?);
            let y = f64::from_le_bytes(wkb.get(13..21)?.try_into().ok()?);
            Some(vec![(x, y)])
        }
        2 => decode_linestring(wkb),
        3 => decode_polygon_exterior(wkb),
        _ => None,
    }
}

fn decode_linestring(wkb: &[u8]) -> Option<Vec<(f64, f64)>> {
    let n = u32::from_le_bytes(wkb.get(5..9)?.try_into().ok()?) as usize;
    let mut coords = Vec::with_capacity(n);
    for i in 0..n {
        let base = 9 + i * 16;
        let x = f64::from_le_bytes(wkb.get(base..base + 8)?.try_into().ok()?);
        let y = f64::from_le_bytes(wkb.get(base + 8..base + 16)?.try_into().ok()?);
        coords.push((x, y));
    }
    Some(coords)
}

fn decode_polygon_exterior(wkb: &[u8]) -> Option<Vec<(f64, f64)>> {
    // 1 byte order + 4 type + 4 ring_count = 9; ring point count at offset 9
    let n = u32::from_le_bytes(wkb.get(9..13)?.try_into().ok()?) as usize;
    let mut coords = Vec::with_capacity(n);
    for i in 0..n {
        let base = 13 + i * 16;
        let x = f64::from_le_bytes(wkb.get(base..base + 8)?.try_into().ok()?);
        let y = f64::from_le_bytes(wkb.get(base + 8..base + 16)?.try_into().ok()?);
        coords.push((x, y));
    }
    Some(coords)
}
