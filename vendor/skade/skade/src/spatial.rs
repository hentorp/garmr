// Apache-2.0 licensed. See ../LICENSE-APACHE.

//! Spatial index — a dependency-free **geohash** grid index over point rows, the
//! first *spatial* structure in the warehouse.
//!
//! skade already streams OSM / GeoParquet features
//! ([`ParquetWindows`](crate::ParquetWindows)) and korp renders a geo view, but
//! neither could answer a **bounding-box** or **radius** question without a full
//! table scan: the warehouse had columnar + ACID + time-travel but no spatial
//! acceleration structure. [`GeoIndex`] closes that gap.
//!
//! It is deliberately self-contained and pure-Rust (no `geo`, no R-tree crate,
//! no external service): a geohash is a *prefix code*, so a sorted `Vec` of
//! `(geohash, id)` **is** a spatial index — a bounding box maps to a small set
//! of covering cells, each a contiguous prefix range found by binary search. It
//! plugs into the existing read path: build it from the Arrow batches the
//! warehouse already hands back ([`GeoIndex::from_batches`]), then answer
//! [`GeoIndex::query_bbox`] / [`GeoIndex::query_radius`] in O(log n + hits).
//!
//! ```
//! use skade::spatial::GeoIndex;
//! let mut idx = GeoIndex::new(9); // ~5 m cells
//! idx.insert(59.3293, 18.0686, 1); // Stockholm
//! idx.insert(59.9139, 10.7522, 2); // Oslo
//! idx.insert(48.8566,  2.3522, 3); // Paris
//! idx.build();
//! // Everything roughly inside the Nordics:
//! let mut hits = idx.query_bbox(58.0, 9.0, 61.0, 19.0);
//! hits.sort_unstable();
//! assert_eq!(hits, vec![1, 2]);
//! ```
//!
//! See `.nornir/spatial-index-design.md`.

use arrow_array::cast::AsArray;
use arrow_array::types::{Float32Type, Float64Type, Int32Type, Int64Type, UInt32Type, UInt64Type};
use arrow_array::{Array, RecordBatch};
use arrow_schema::DataType;

use crate::error::{Result, SkadeError};

/// The geohash base-32 alphabet (RFC-none, the de-facto Niemeyer alphabet). Note
/// it omits `a`, `i`, `l`, `o`; the max byte is `z` (`0x7A`).
const BASE32: &[u8] = b"0123456789bcdefghjkmnpqrstuvwxyz";

/// Largest geohash length [`GeoIndex`] will store / query at (12 base32 chars ≈
/// 5·12 = 60 bits ≈ sub-centimetre — far past any real GNSS precision).
pub const MAX_PRECISION: usize = 12;

/// Cap on covering cells a bounding-box query will enumerate before falling back
/// to a full linear scan (keeps a pathological world-spanning bbox bounded).
const MAX_COVER_CELLS: usize = 4096;

const EARTH_RADIUS_M: f64 = 6_371_000.0;

/// Encode `(lat, lon)` to a `len`-char geohash. `lat` is clamped to `[-90, 90]`
/// and `lon` to `[-180, 180]`; `len` is clamped to `1..=`[`MAX_PRECISION`].
///
/// Deterministic and allocation-stable (one `String` of exactly `len` bytes) —
/// the same inputs always produce the same bytes, which is what makes the sorted
/// index reproducible and the bench byte-identical run to run.
pub fn geohash_encode(lat: f64, lon: f64, len: usize) -> String {
    let len = len.clamp(1, MAX_PRECISION);
    let lat = lat.clamp(-90.0, 90.0);
    let lon = lon.clamp(-180.0, 180.0);

    let mut lat_lo = -90.0f64;
    let mut lat_hi = 90.0f64;
    let mut lon_lo = -180.0f64;
    let mut lon_hi = 180.0f64;

    let mut hash = String::with_capacity(len);
    let mut even = true; // even bit index → longitude
    let mut bit = 0u8;
    let mut ch = 0usize;

    while hash.len() < len {
        if even {
            let mid = (lon_lo + lon_hi) / 2.0;
            if lon >= mid {
                ch |= 1 << (4 - bit);
                lon_lo = mid;
            } else {
                lon_hi = mid;
            }
        } else {
            let mid = (lat_lo + lat_hi) / 2.0;
            if lat >= mid {
                ch |= 1 << (4 - bit);
                lat_lo = mid;
            } else {
                lat_hi = mid;
            }
        }
        even = !even;
        if bit < 4 {
            bit += 1;
        } else {
            hash.push(BASE32[ch] as char);
            bit = 0;
            ch = 0;
        }
    }
    hash
}

/// The `(lat, lon)` degree extent of a single geohash cell at length `p`.
///
/// Over `5·p` bits longitude takes the ceiling half and latitude the floor half
/// (bit 0 is longitude), so the cell is `360/2^lonbits` wide and
/// `180/2^latbits` tall.
fn cell_extent(p: usize) -> (f64, f64) {
    let bits = 5 * p;
    let lon_bits = bits.div_ceil(2);
    let lat_bits = bits / 2;
    let lat = 180.0 / 2f64.powi(lat_bits as i32);
    let lon = 360.0 / 2f64.powi(lon_bits as i32);
    (lat, lon)
}

/// Largest precision (finest cells) whose single cell is still at least as big
/// as the query box in both dimensions, so the box is covered by a handful of
/// cells rather than millions. Clamped to `1..=max_p`.
fn pick_precision(dlat: f64, dlon: f64, max_p: usize) -> usize {
    for p in (1..=max_p).rev() {
        let (clat, clon) = cell_extent(p);
        if clat >= dlat && clon >= dlon {
            return p;
        }
    }
    1
}

/// Great-circle distance in metres (haversine). Used by [`GeoIndex::query_radius`].
pub fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dlon / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_M * a.sqrt().asin()
}

/// One indexed point: its geohash (at the index precision), row id, and the raw
/// coordinates kept for exact (false-positive-free) filtering.
#[derive(Clone, Debug, PartialEq)]
struct Entry {
    hash: String,
    id: u64,
    lat: f64,
    lon: f64,
}

/// A geohash grid index over point rows: insert `(lat, lon, id)`, [`build`] once
/// (sorts by geohash), then answer bounding-box / radius / nearest queries.
///
/// [`build`](Self::build) is idempotent and cheap to re-run after more inserts.
/// Queries require a built (sorted) index; they return **exact** results (every
/// candidate is verified against the real coordinates — no false positives).
#[derive(Clone, Debug, Default)]
pub struct GeoIndex {
    precision: usize,
    entries: Vec<Entry>,
    built: bool,
}

impl GeoIndex {
    /// A new, empty index storing geohashes of length `precision`
    /// (clamped `1..=`[`MAX_PRECISION`]). Higher precision = finer cells =
    /// tighter candidate sets (precision 9 ≈ 5 m cells, a good OSM default).
    pub fn new(precision: usize) -> Self {
        Self {
            precision: precision.clamp(1, MAX_PRECISION),
            entries: Vec::new(),
            built: false,
        }
    }

    /// Number of indexed points.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index holds no points.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The geohash precision (cell length) this index stores.
    pub fn precision(&self) -> usize {
        self.precision
    }

    /// Add one point. Coordinates outside `[-90,90]`/`[-180,180]` are clamped by
    /// [`geohash_encode`]. Marks the index unbuilt (call [`build`](Self::build)
    /// before querying).
    pub fn insert(&mut self, lat: f64, lon: f64, id: u64) {
        self.entries.push(Entry {
            hash: geohash_encode(lat, lon, self.precision),
            id,
            lat,
            lon,
        });
        self.built = false;
    }

    /// Sort the entries by geohash so prefix ranges are contiguous. Idempotent;
    /// a no-op if nothing changed since the last build.
    pub fn build(&mut self) {
        if self.built {
            return;
        }
        self.entries.sort_by(|a, b| a.hash.cmp(&b.hash));
        self.built = true;
    }

    /// Visit every entry whose geohash starts with `prefix`, in sorted order.
    /// The core primitive: one binary search to the range start, then a linear
    /// walk while the prefix matches. `O(log n + range)`.
    fn for_prefix(&self, prefix: &str, mut f: impl FnMut(&Entry)) {
        let start = self.entries.partition_point(|e| e.hash.as_str() < prefix);
        for e in &self.entries[start..] {
            if e.hash.starts_with(prefix) {
                f(e);
            } else {
                break;
            }
        }
    }

    /// Enumerate the covering geohash cells (as prefixes) for a bounding box, or
    /// `None` if it would exceed [`MAX_COVER_CELLS`] (caller falls back to a full
    /// scan). Samples the box on a half-cell grid so no covering cell is missed.
    fn cover_cells(
        &self,
        min_lat: f64,
        min_lon: f64,
        max_lat: f64,
        max_lon: f64,
    ) -> Option<Vec<String>> {
        let dlat = (max_lat - min_lat).abs().max(f64::MIN_POSITIVE);
        let dlon = (max_lon - min_lon).abs().max(f64::MIN_POSITIVE);
        let qp = pick_precision(dlat, dlon, self.precision);
        let (clat, clon) = cell_extent(qp);
        let (step_lat, step_lon) = (clat / 2.0, clon / 2.0);

        let mut cells: Vec<String> = Vec::new();
        let mut la = min_lat;
        loop {
            let mut lo = min_lon;
            loop {
                let h = geohash_encode(la, lo, qp);
                if !cells.contains(&h) {
                    if cells.len() >= MAX_COVER_CELLS {
                        return None;
                    }
                    cells.push(h);
                }
                if lo >= max_lon {
                    break;
                }
                lo = (lo + step_lon).min(max_lon + step_lon);
            }
            if la >= max_lat {
                break;
            }
            la = (la + step_lat).min(max_lat + step_lat);
        }
        Some(cells)
    }

    /// Visit every entry whose point falls inside the closed bounding box, in
    /// the order the covering cells enumerate them. The shared core of
    /// [`query_bbox`](Self::query_bbox) and [`query_radius`](Self::query_radius):
    /// the covering-cell walk already has the matching [`Entry`] in hand (with
    /// its `lat`/`lon`), so callers that need the coordinates take them straight
    /// from the walk instead of re-finding the row by id afterwards.
    fn for_bbox(
        &self,
        min_lat: f64,
        min_lon: f64,
        max_lat: f64,
        max_lon: f64,
        mut f: impl FnMut(&Entry),
    ) {
        let inside = |e: &Entry| {
            e.lat >= min_lat && e.lat <= max_lat && e.lon >= min_lon && e.lon <= max_lon
        };
        match self.cover_cells(min_lat, min_lon, max_lat, max_lon) {
            Some(cells) => {
                for cell in &cells {
                    self.for_prefix(cell, |e| {
                        if inside(e) {
                            f(e);
                        }
                    });
                }
            }
            None => {
                // Degenerate (near-global) box: a full scan is cheaper than
                // millions of cells, and still exact.
                for e in &self.entries {
                    if inside(e) {
                        f(e);
                    }
                }
            }
        }
    }

    /// All ids whose point falls inside the closed bounding box
    /// `[min_lat,max_lat] × [min_lon,max_lon]`. Exact — candidates from the
    /// covering cells are verified against their real coordinates. Order is
    /// unspecified (dedup + sort at the call site if needed).
    pub fn query_bbox(&self, min_lat: f64, min_lon: f64, max_lat: f64, max_lon: f64) -> Vec<u64> {
        debug_assert!(self.built, "call build() before querying");
        let (min_lat, max_lat) = (min_lat.min(max_lat), min_lat.max(max_lat));
        let (min_lon, max_lon) = (min_lon.min(max_lon), min_lon.max(max_lon));
        let mut out = Vec::new();
        self.for_bbox(min_lat, min_lon, max_lat, max_lon, |e| out.push(e.id));
        out
    }

    /// All `(id, distance_m)` within `radius_m` of `(lat, lon)`, by great-circle
    /// distance. Prefilters with the bounding box that encloses the circle, then
    /// verifies each candidate with [`haversine_m`].
    pub fn query_radius(&self, lat: f64, lon: f64, radius_m: f64) -> Vec<(u64, f64)> {
        debug_assert!(self.built, "call build() before querying");
        // Degrees subtended by `radius_m`: latitude is uniform; longitude scales
        // by 1/cos(lat) (guard the poles).
        let dlat = (radius_m / EARTH_RADIUS_M).to_degrees();
        let cos = lat.to_radians().cos().abs().max(1e-9);
        let dlon = dlat / cos;
        // Normalise the box exactly as query_bbox does, then verify each
        // candidate against the great-circle radius using the coords the walk
        // already carries — no per-candidate O(n) `entries.iter().find(id)`.
        let (min_lat, max_lat) = ((lat - dlat).min(lat + dlat), (lat - dlat).max(lat + dlat));
        let (min_lon, max_lon) = ((lon - dlon).min(lon + dlon), (lon - dlon).max(lon + dlon));
        let mut out = Vec::new();
        self.for_bbox(min_lat, min_lon, max_lat, max_lon, |e| {
            let d = haversine_m(lat, lon, e.lat, e.lon);
            if d <= radius_m {
                out.push((e.id, d));
            }
        });
        out
    }

    /// The `k` nearest ids to `(lat, lon)` as `(id, distance_m)`, closest first.
    /// Widens the search box until at least `k` candidates (or the whole index)
    /// are found, then sorts. Best for small `k`.
    pub fn nearest(&self, lat: f64, lon: f64, k: usize) -> Vec<(u64, f64)> {
        debug_assert!(self.built, "call build() before querying");
        if k == 0 || self.entries.is_empty() {
            return Vec::new();
        }
        // Start near the finest cell size and double until enough candidates.
        let (clat0, _) = cell_extent(self.precision);
        let mut radius_m = (clat0.to_radians() * EARTH_RADIUS_M).max(1.0);
        let mut hits;
        loop {
            hits = self.query_radius(lat, lon, radius_m);
            if hits.len() >= k || radius_m >= EARTH_RADIUS_M * std::f64::consts::PI {
                break;
            }
            radius_m *= 2.0;
        }
        hits.sort_by(|a, b| a.1.total_cmp(&b.1));
        hits.truncate(k);
        hits
    }

    /// Build an index from Arrow record batches — the warehouse read seam. Reads
    /// the `lat_col` / `lon_col` (any float or integer numeric column) and the
    /// `id_col` (any integer column) from each batch. Rows where any of the
    /// three is null are skipped. Errors if a named column is missing or of an
    /// unsupported type. The index is returned already [`build`](Self::build)-ed.
    pub fn from_batches(
        batches: &[RecordBatch],
        lat_col: &str,
        lon_col: &str,
        id_col: &str,
        precision: usize,
    ) -> Result<Self> {
        let mut idx = GeoIndex::new(precision);
        for batch in batches {
            let lat = numeric_f64(batch, lat_col)?;
            let lon = numeric_f64(batch, lon_col)?;
            let id = integer_u64(batch, id_col)?;
            for row in 0..batch.num_rows() {
                if let (Some(la), Some(lo), Some(i)) = (lat[row], lon[row], id[row]) {
                    idx.insert(la, lo, i);
                }
            }
        }
        idx.build();
        crate::functional_status(
            "skade/spatial",
            "geo_index_from_batches",
            true,
            &format!("{} points @ p{precision}", idx.len()),
        );
        Ok(idx)
    }
}

/// Read a numeric column as `Vec<Option<f64>>` (any float/int width).
fn numeric_f64(batch: &RecordBatch, col: &str) -> Result<Vec<Option<f64>>> {
    let arr = column(batch, col)?;
    let n = arr.len();
    let mut out = Vec::with_capacity(n);
    macro_rules! push_prim {
        ($ty:ty) => {{
            let a = arr.as_primitive::<$ty>();
            for i in 0..n {
                out.push(if a.is_null(i) {
                    None
                } else {
                    Some(a.value(i) as f64)
                });
            }
        }};
    }
    match arr.data_type() {
        DataType::Float64 => push_prim!(Float64Type),
        DataType::Float32 => push_prim!(Float32Type),
        DataType::Int64 => push_prim!(Int64Type),
        DataType::Int32 => push_prim!(Int32Type),
        DataType::UInt64 => push_prim!(UInt64Type),
        DataType::UInt32 => push_prim!(UInt32Type),
        other => {
            return Err(SkadeError::Other(format!(
                "spatial: column '{col}' has non-numeric type {other:?}"
            )));
        }
    }
    Ok(out)
}

/// Read an integer column as `Vec<Option<u64>>`.
fn integer_u64(batch: &RecordBatch, col: &str) -> Result<Vec<Option<u64>>> {
    let arr = column(batch, col)?;
    let n = arr.len();
    let mut out = Vec::with_capacity(n);
    macro_rules! push_prim {
        ($ty:ty) => {{
            let a = arr.as_primitive::<$ty>();
            for i in 0..n {
                out.push(if a.is_null(i) {
                    None
                } else {
                    Some(a.value(i) as u64)
                });
            }
        }};
    }
    match arr.data_type() {
        DataType::Int64 => push_prim!(Int64Type),
        DataType::Int32 => push_prim!(Int32Type),
        DataType::UInt64 => push_prim!(UInt64Type),
        DataType::UInt32 => push_prim!(UInt32Type),
        other => {
            return Err(SkadeError::Other(format!(
                "spatial: id column '{col}' has non-integer type {other:?}"
            )));
        }
    }
    Ok(out)
}

fn column<'a>(batch: &'a RecordBatch, col: &str) -> Result<&'a dyn Array> {
    batch
        .column_by_name(col)
        .map(|c| c.as_ref())
        .ok_or_else(|| SkadeError::Other(format!("spatial: column '{col}' not found")))
}
