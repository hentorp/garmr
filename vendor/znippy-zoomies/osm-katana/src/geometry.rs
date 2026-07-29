#![allow(clippy::float_arithmetic, clippy::arithmetic_side_effects)]

const AREA_TAGS: &[&str] = &[
    "building", "landuse", "natural", "amenity", "leisure", "area",
];

/// Encode a WKB Point on the stack — exactly 21 bytes, no heap allocation.
/// This is called 9.5 billion times for planet; the stack array avoids
/// that many malloc/free cycles.
#[inline]
pub fn encode_point_inline(lon: f64, lat: f64) -> [u8; 21] {
    let mut buf = [0u8; 21];
    buf[0] = 1; // little-endian
    buf[1..5].copy_from_slice(&1u32.to_le_bytes()); // WKB Point type
    buf[5..13].copy_from_slice(&lon.to_le_bytes());
    buf[13..21].copy_from_slice(&lat.to_le_bytes());
    buf
}

/// HashMap-based version (backward compat).
pub fn is_closed_area(refs: &[i64], tags: &std::collections::HashMap<String, String>) -> bool {
    if refs.len() < 4 {
        return false;
    }
    if refs.first() != refs.last() {
        return false;
    }
    if tags.get("area").is_some_and(|v| v == "yes") {
        return true;
    }
    AREA_TAGS.iter().any(|key| tags.contains_key(*key))
}
