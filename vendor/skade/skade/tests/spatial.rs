// Apache-2.0 licensed. Tests for the geohash spatial index (`skade::spatial`).

use std::sync::Arc;

use skade::arrow_array::{Float64Array, Int64Array, RecordBatch};
use skade::arrow_schema::{DataType, Field, Schema};
use skade::spatial::{GeoIndex, geohash_encode, haversine_m};

// A few well-known cities: (name, lat, lon, id).
const CITIES: &[(&str, f64, f64, u64)] = &[
    ("Stockholm", 59.3293, 18.0686, 1),
    ("Oslo", 59.9139, 10.7522, 2),
    ("Copenhagen", 55.6761, 12.5683, 3),
    ("Helsinki", 60.1699, 24.9384, 4),
    ("Paris", 48.8566, 2.3522, 5),
    ("Reykjavik", 64.1466, -21.9426, 6),
    ("New York", 40.7128, -74.0060, 7),
];

fn nordics() -> GeoIndex {
    let mut idx = GeoIndex::new(9);
    for (_, lat, lon, id) in CITIES {
        idx.insert(*lat, *lon, *id);
    }
    idx.build();
    idx
}

#[test]
fn geohash_is_a_prefix_code() {
    // Two nearby points share a long prefix; a far point does not.
    let sthlm = geohash_encode(59.3293, 18.0686, 12);
    let sthlm2 = geohash_encode(59.3300, 18.0700, 12);
    let paris = geohash_encode(48.8566, 2.3522, 12);
    // Known geohash for Stockholm centre starts "u6sce".
    assert!(sthlm.starts_with("u6sce"), "got {sthlm}");
    let shared = sthlm
        .chars()
        .zip(sthlm2.chars())
        .take_while(|(a, b)| a == b)
        .count();
    assert!(
        shared >= 5,
        "nearby points should share a long prefix, got {shared}"
    );
    assert!(
        !paris.starts_with("u6"),
        "Paris must not share Stockholm's cell"
    );
}

#[test]
fn encode_is_deterministic() {
    // Byte-identical across runs — the property the index + bench rely on.
    for _ in 0..3 {
        assert_eq!(
            geohash_encode(59.3293, 18.0686, 9),
            geohash_encode(59.3293, 18.0686, 9)
        );
    }
}

#[test]
fn bbox_selects_only_inside_points() {
    let idx = nordics();
    // A box around the Nordic capitals (excludes Paris, Reykjavik, NY).
    let mut hits = idx.query_bbox(54.0, 9.0, 61.0, 26.0);
    hits.sort_unstable();
    assert_eq!(hits, vec![1, 2, 3, 4]);
}

#[test]
fn bbox_argument_order_is_normalised() {
    let idx = nordics();
    let a = idx.query_bbox(54.0, 9.0, 61.0, 26.0);
    let b = idx.query_bbox(61.0, 26.0, 54.0, 9.0); // swapped corners
    let mut a = a.clone();
    let mut b = b.clone();
    a.sort_unstable();
    b.sort_unstable();
    assert_eq!(a, b);
}

#[test]
fn tiny_bbox_matches_a_full_scan() {
    // Exactness: over a grid of random-ish points, the index agrees with brute force.
    let mut idx = GeoIndex::new(10);
    let pts: Vec<(f64, f64, u64)> = (0..2000)
        .map(|i| {
            let lat = -60.0 + (i as f64 * 7.3) % 120.0;
            let lon = -170.0 + (i as f64 * 11.7) % 340.0;
            (lat, lon, i as u64)
        })
        .collect();
    for (lat, lon, id) in &pts {
        idx.insert(*lat, *lon, *id);
    }
    idx.build();

    let (min_lat, max_lat, min_lon, max_lon) = (10.0, 40.0, 20.0, 80.0);
    let mut got = idx.query_bbox(min_lat, min_lon, max_lat, max_lon);
    got.sort_unstable();
    let mut expect: Vec<u64> = pts
        .iter()
        .filter(|(la, lo, _)| *la >= min_lat && *la <= max_lat && *lo >= min_lon && *lo <= max_lon)
        .map(|(_, _, id)| *id)
        .collect();
    expect.sort_unstable();
    assert_eq!(got, expect, "index bbox must equal brute-force filter");
}

#[test]
fn global_bbox_returns_everything() {
    let idx = nordics();
    let mut hits = idx.query_bbox(-90.0, -180.0, 90.0, 180.0);
    hits.sort_unstable();
    assert_eq!(hits, vec![1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn radius_query_uses_great_circle_distance() {
    let idx = nordics();
    // Within ~600 km of Stockholm: Oslo (~415 km) and Copenhagen (~520 km) in;
    // Helsinki (~395 km) in; Paris (~1540 km) out.
    let hits = idx.query_radius(59.3293, 18.0686, 600_000.0);
    let ids: std::collections::BTreeSet<u64> = hits.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&1), "self must be within radius");
    assert!(ids.contains(&2), "Oslo within 600km");
    assert!(ids.contains(&4), "Helsinki within 600km");
    assert!(!ids.contains(&5), "Paris is >1500km away");
    // Every returned distance must actually be within the radius.
    assert!(hits.iter().all(|(_, d)| *d <= 600_000.0));
}

#[test]
fn nearest_returns_closest_first() {
    let idx = nordics();
    let got = idx.nearest(59.3293, 18.0686, 3);
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].0, 1, "closest to Stockholm is itself");
    // Distances are non-decreasing.
    for w in got.windows(2) {
        assert!(w[0].1 <= w[1].1);
    }
    // Helsinki (395km) is nearer than Oslo (415km) — both beat Copenhagen.
    let ids: Vec<u64> = got.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids[0], 1);
    assert!(ids.contains(&4) || ids.contains(&2));
}

#[test]
fn haversine_matches_known_distance() {
    // Stockholm↔Oslo is ~416 km; allow a few percent for the sphere model.
    let d = haversine_m(59.3293, 18.0686, 59.9139, 10.7522);
    assert!((350_000.0..480_000.0).contains(&d), "got {d} m");
}

#[test]
fn from_batches_reads_the_read_seam() {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("lat", DataType::Float64, true),
        Field::new("lon", DataType::Float64, true),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![Some(1), Some(2), Some(3), Some(4)])),
            Arc::new(Float64Array::from(vec![
                Some(59.3293),
                Some(59.9139),
                None,
                Some(48.8566),
            ])),
            Arc::new(Float64Array::from(vec![
                Some(18.0686),
                Some(10.7522),
                Some(12.0),
                Some(2.3522),
            ])),
        ],
    )
    .unwrap();

    let idx = GeoIndex::from_batches(&[batch], "lat", "lon", "id", 9).unwrap();
    // Row 3 had a null lat → skipped.
    assert_eq!(idx.len(), 3);
    let mut hits = idx.query_bbox(54.0, 9.0, 61.0, 26.0);
    hits.sort_unstable();
    assert_eq!(hits, vec![1, 2]);
}

#[test]
fn from_batches_rejects_bad_columns() {
    let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
    let batch = RecordBatch::try_new(schema, vec![Arc::new(Int64Array::from(vec![1i64]))]).unwrap();
    assert!(GeoIndex::from_batches(&[batch], "lat", "lon", "id", 9).is_err());
}

/// `query_radius` must return exactly the brute-force great-circle result — the
/// same id set with the same distances — after the O(k·n)→O(k) rewrite that
/// takes each candidate's coords straight from the covering-cell walk instead
/// of re-finding the row by id. This is the byte-identical guard for that perf
/// change over a non-trivial (unique-id) point cloud.
#[test]
fn radius_matches_brute_force_after_zero_copy_rewrite() {
    let mut idx = GeoIndex::new(10);
    let pts: Vec<(f64, f64, u64)> = (0..5000)
        .map(|i| {
            let lat = -70.0 + (i as f64 * 3.7).rem_euclid(140.0);
            let lon = -175.0 + (i as f64 * 5.9).rem_euclid(350.0);
            (lat, lon, i as u64)
        })
        .collect();
    for (lat, lon, id) in &pts {
        idx.insert(*lat, *lon, *id);
    }
    idx.build();

    for &(qlat, qlon, r) in &[
        (0.0, 0.0, 500_000.0),
        (59.3293, 18.0686, 1_500_000.0),
        (-33.8, 151.2, 800_000.0),
        (48.85, 2.35, 50_000.0),
    ] {
        let mut got: Vec<(u64, u64)> = idx
            .query_radius(qlat, qlon, r)
            .into_iter()
            .map(|(id, d)| (id, d.to_bits())) // exact-bit distance compare
            .collect();
        got.sort_unstable();
        let mut expect: Vec<(u64, u64)> = pts
            .iter()
            .filter_map(|(la, lo, id)| {
                let d = haversine_m(qlat, qlon, *la, *lo);
                (d <= r).then_some((*id, d.to_bits()))
            })
            .collect();
        expect.sort_unstable();
        assert_eq!(
            got, expect,
            "radius query must equal brute-force at ({qlat},{qlon}) r={r}"
        );
    }
}

/// A LIGHT timing guard that `query_radius` is now sub-linear per candidate: a
/// tight radius over a 50k index must not re-scan all 50k rows per candidate (the
/// old `entries.iter().find(id)` made it O(k·n)). Catches a regression back to
/// the linear re-find.
#[test]
fn light_radius_timing_is_sublinear() {
    let n = 50_000u64;
    let mut idx = GeoIndex::new(9);
    for i in 0..n {
        let lat = -80.0 + (i as f64 * 0.017) % 160.0;
        let lon = -175.0 + (i as f64 * 0.031) % 350.0;
        idx.insert(lat, lon, i);
    }
    idx.build();

    let t = std::time::Instant::now();
    let mut total = 0usize;
    for _ in 0..200 {
        total += idx.query_radius(10.0, 20.0, 25_000.0).len();
    }
    let per = t.elapsed().as_nanos() as f64 / 200.0;
    assert!(
        per < 5_000_000.0,
        "radius query too slow: {per:.0} ns/query (hits so far {total})"
    );
}

/// A LIGHT in-process timing sanity check — NOT a heavy bench (those queue to
/// Loki/Odin). Builds a modest index and asserts a point query is fast, so a
/// future regression that turns the prefix scan into a full scan is caught.
#[test]
fn light_query_timing_is_sublinear() {
    let n = 50_000u64;
    let mut idx = GeoIndex::new(9);
    for i in 0..n {
        let lat = -80.0 + (i as f64 * 0.017) % 160.0;
        let lon = -175.0 + (i as f64 * 0.031) % 350.0;
        idx.insert(lat, lon, i);
    }
    idx.build();

    // A small box: with the prefix index this touches far fewer than `n` rows.
    let t = std::time::Instant::now();
    let mut total = 0usize;
    for _ in 0..200 {
        total += idx.query_bbox(10.0, 20.0, 10.5, 20.5).len();
    }
    let per = t.elapsed().as_nanos() as f64 / 200.0;
    // Generous ceiling (CI/shared box): a full 50k scan per query would blow
    // past this; the index should sit far under it.
    assert!(
        per < 5_000_000.0,
        "bbox query too slow: {per:.0} ns/query (hits so far {total})"
    );
}
