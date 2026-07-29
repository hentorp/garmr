// Spatial layout for GeoParquet output — Hilbert row ordering + a `covering.bbox`
// column. See `.nornir/geoparquet-spatial-layout-design.md`.

//! **Make the file its own spatial index.**
//!
//! A Parquet file is read in pieces: a reader parses the footer, looks at each
//! row group's min/max statistics, and fetches only the column chunks of the row
//! groups that can possibly match. For that to prune anything, two things must
//! hold, and osm-katana's streaming convert output satisfied *neither*:
//!
//! 1. **Spatially-near rows must be physically adjacent.** Convert emits rows in
//!    PBF/parse order, so any given row group spans the whole extract and every
//!    row group's bounds are the file's bounds — nothing can ever be pruned.
//!    [`hilbert_index`] gives each feature a 1-D key that preserves 2-D locality,
//!    and sorting on it packs each row group into a compact region.
//!
//! 2. **There must be something prunable to compare.** Min/max statistics on the
//!    WKB `geometry` column are *useless* for space: WKB compares
//!    lexicographically, and a WKB point is
//!    `[0x01][01 00 00 00][8 LE bytes of x][8 LE bytes of y]`, so the ordering is
//!    dominated by the LOW-order mantissa byte of x. Hilbert sorting alone
//!    therefore buys nothing a reader can see. [`bbox_field`] adds the
//!    GeoParquet 1.1 `covering.bbox` struct column — four plain `f64`s whose
//!    min/max statistics Parquet records natively and every engine understands.
//!
//! Both are needed; either alone is inert. The pair is what turns
//! "read when close to the point" from a wish into four byte-range requests.
//!
//! The covering column is **derived** — a pure function of `geometry` — so
//! [`crate::digest`] excludes it from the content digest and a Hilbert-packed
//! table still compares equal (multiset) to the convert output it came from.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use arrow::array::{Array, ArrayRef, BinaryArray, Float32Builder, StructArray};
use arrow::datatypes::{DataType, Field, Fields, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::file::properties::WriterProperties;

use crate::metadata::{self, BBOX_COLUMN};

/// Bits per axis in the Hilbert curve. 31 keeps the index inside 62 bits, so it
/// is always a non-negative `i64` (sortable as a signed key) while resolving
/// 360° / 2^31 ≈ 1.7e-7° ≈ **1.9 cm** of longitude — far finer than OSM's own
/// 1e-7° coordinate grid, so the ordering never collapses distinct nodes.
pub const HILBERT_BITS: u32 = 31;

/// Map `(lon, lat)` in degrees onto the `HILBERT_BITS`-per-axis integer grid.
#[inline]
#[allow(clippy::float_arithmetic)]
fn quantize(lon: f64, lat: f64) -> (u32, u32) {
    let side = f64::from(1u32 << (HILBERT_BITS - 1)) * 2.0; // 2^31 as f64
    let max = (1u64 << HILBERT_BITS) - 1;
    let nx = (((lon + 180.0) / 360.0).clamp(0.0, 1.0) * side) as u64;
    let ny = (((lat + 90.0) / 180.0).clamp(0.0, 1.0) * side) as u64;
    (nx.min(max) as u32, ny.min(max) as u32)
}

/// The Hilbert d-index of grid cell `(x, y)` on a `2^HILBERT_BITS` square.
///
/// The classic iterative rotation algorithm (Wikipedia's `xy2d`): walk the
/// quadrant size from half the side down to 1, accumulate the quadrant's
/// contribution, and rotate the remaining coordinates into the sub-square's
/// frame. `O(HILBERT_BITS)`, no allocation, no floating point.
#[inline]
pub fn hilbert_d(mut x: u32, mut y: u32) -> u64 {
    let mut rx: u32;
    let mut ry: u32;
    let mut d: u64 = 0;
    let mut s: u32 = 1 << (HILBERT_BITS - 1);
    while s > 0 {
        rx = u32::from((x & s) > 0);
        ry = u32::from((y & s) > 0);
        d = d.wrapping_add(u64::from(s) * u64::from(s) * u64::from((3 * rx) ^ ry));
        // rotate
        if ry == 0 {
            if rx == 1 {
                x = s.wrapping_sub(1).wrapping_sub(x);
                y = s.wrapping_sub(1).wrapping_sub(y);
            }
            std::mem::swap(&mut x, &mut y);
        }
        s >>= 1;
    }
    d
}

/// The Hilbert index of a `(lon, lat)` point in degrees. Locality-preserving:
/// points close in index are close on the ground (the converse is not guaranteed
/// at curve seams, which is why the reader still checks the real bbox).
#[inline]
pub fn hilbert_index(lon: f64, lat: f64) -> u64 {
    let (x, y) = quantize(lon, lat);
    hilbert_d(x, y)
}

/// A feature's bounding box in `[xmin, ymin, xmax, ymax]` order — the covering.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bbox {
    pub xmin: f64,
    pub ymin: f64,
    pub xmax: f64,
    pub ymax: f64,
}

impl Bbox {
    /// Midpoint of the box — the point the Hilbert key is taken at.
    #[allow(clippy::float_arithmetic)]
    pub fn centre(&self) -> (f64, f64) {
        ((self.xmin + self.xmax) / 2.0, (self.ymin + self.ymax) / 2.0)
    }
}

/// Bounding box of a WKB geometry, or `None` for null / unparsable / empty WKB.
///
/// Handles the geometry types osm-katana writes (Point, LineString, Polygon) and
/// their Multi\* / GeometryCollection wrappers, in either byte order, by walking
/// the WKB structure rather than materialising coordinates — one pass, no
/// allocation.
pub fn wkb_bbox(wkb: &[u8]) -> Option<Bbox> {
    let mut b = Bbox {
        xmin: f64::MAX,
        ymin: f64::MAX,
        xmax: f64::MIN,
        ymax: f64::MIN,
    };
    let mut pos = 0usize;
    scan(wkb, &mut pos, &mut b, 0)?;
    if b.xmin > b.xmax { None } else { Some(b) }
}

/// Recursive WKB walker. `depth` bounds pathological nesting.
fn scan(w: &[u8], pos: &mut usize, b: &mut Bbox, depth: u32) -> Option<()> {
    if depth > 8 {
        return None;
    }
    let le = *w.get(*pos)? == 1;
    *pos += 1;
    let ty = rd_u32(w, pos, le)? % 1000; // strip Z/M/ZM (1000/2000/3000) qualifiers
    match ty {
        1 => pt(w, pos, b, le),
        2 => {
            let n = rd_u32(w, pos, le)? as usize;
            for _ in 0..n {
                pt(w, pos, b, le)?;
            }
            Some(())
        }
        3 => {
            let rings = rd_u32(w, pos, le)? as usize;
            for _ in 0..rings {
                let n = rd_u32(w, pos, le)? as usize;
                for _ in 0..n {
                    pt(w, pos, b, le)?;
                }
            }
            Some(())
        }
        4 | 5 | 6 | 7 => {
            let n = rd_u32(w, pos, le)? as usize;
            for _ in 0..n {
                scan(w, pos, b, depth + 1)?;
            }
            Some(())
        }
        _ => None,
    }
}

#[inline]
fn pt(w: &[u8], pos: &mut usize, b: &mut Bbox, le: bool) -> Option<()> {
    let x = rd_f64(w, pos, le)?;
    let y = rd_f64(w, pos, le)?;
    if x < b.xmin {
        b.xmin = x;
    }
    if y < b.ymin {
        b.ymin = y;
    }
    if x > b.xmax {
        b.xmax = x;
    }
    if y > b.ymax {
        b.ymax = y;
    }
    Some(())
}

#[inline]
fn rd_u32(w: &[u8], pos: &mut usize, le: bool) -> Option<u32> {
    let s: [u8; 4] = w.get(*pos..*pos + 4)?.try_into().ok()?;
    *pos += 4;
    Some(if le {
        u32::from_le_bytes(s)
    } else {
        u32::from_be_bytes(s)
    })
}

#[inline]
fn rd_f64(w: &[u8], pos: &mut usize, le: bool) -> Option<f64> {
    let s: [u8; 8] = w.get(*pos..*pos + 8)?.try_into().ok()?;
    *pos += 8;
    Some(if le {
        f64::from_le_bytes(s)
    } else {
        f64::from_be_bytes(s)
    })
}

/// The GeoParquet 1.1 covering column: `struct<xmin,ymin,xmax,ymax: float>`.
///
/// The spec requires the children be named `xmin, ymin, xmax, ymax` **in that
/// order** and be "of Parquet type FLOAT or DOUBLE", all the same type.
///
/// **FLOAT, not DOUBLE — measured.** On Stockholm's 4.7 M nodes the four covering
/// columns cost, compressed:
///
/// ```text
///   f64, plain            132611232
///   f64, byte-stream-split 97321255
///   f32, plain             46296340
///   f32, byte-stream-split 28774887      ← 4.6× smaller than f64 plain
/// ```
///
/// A covering is a *conservative approximation* by definition — the reader
/// re-checks the real geometry — so spending 8 bytes to carry a coordinate the
/// WKB column already holds exactly is pure waste. What f32 costs is ~2 m of slop
/// at Stockholm's latitude, which is invisible at row-group granularity (a group
/// spans hundreds of metres at minimum).
///
/// Correctness is preserved by rounding **outwards** ([`down`] / [`up`]): the
/// stored box always CONTAINS the true box, so a row group is never pruned away
/// when it might have matched. Rounding to nearest would shrink some boxes and
/// could drop a real hit — see the `covering_is_conservative` test.
pub fn bbox_field() -> Field {
    Field::new(
        BBOX_COLUMN,
        DataType::Struct(Fields::from(vec![
            Field::new("xmin", DataType::Float32, true),
            Field::new("ymin", DataType::Float32, true),
            Field::new("xmax", DataType::Float32, true),
            Field::new("ymax", DataType::Float32, true),
        ])),
        true,
    )
}

/// Largest `f32` that is `<= v` — the outward rounding for a bbox MINIMUM.
#[inline]
#[allow(clippy::float_cmp)]
pub fn down(v: f64) -> f32 {
    let r = v as f32;
    if f64::from(r) <= v {
        r
    } else {
        next_toward_neg_inf(r)
    }
}

/// Smallest `f32` that is `>= v` — the outward rounding for a bbox MAXIMUM.
#[inline]
#[allow(clippy::float_cmp)]
pub fn up(v: f64) -> f32 {
    let r = v as f32;
    if f64::from(r) >= v {
        r
    } else {
        next_toward_pos_inf(r)
    }
}

#[inline]
fn next_toward_neg_inf(x: f32) -> f32 {
    if x.is_nan() || x == f32::NEG_INFINITY {
        return x;
    }
    let b = x.to_bits();
    // IEEE-754 magnitude ordering: stepping the bit pattern moves one ULP.
    f32::from_bits(if x > 0.0 {
        b - 1
    } else if x == 0.0 {
        0x8000_0001
    } else {
        b + 1
    })
}

#[inline]
fn next_toward_pos_inf(x: f32) -> f32 {
    if x.is_nan() || x == f32::INFINITY {
        return x;
    }
    let b = x.to_bits();
    f32::from_bits(if x >= 0.0 { b + 1 } else { b - 1 })
}

/// Options for [`spatial_pack`].
#[derive(Clone, Debug)]
pub struct PackOptions {
    /// Parquet compression name (`zstd` | `snappy` | `none`).
    pub compression: String,
    /// Rows per row group. This is the pruning/compression dial and the default
    /// is **measured, not guessed**. Sweeping Stockholm (bytes read for one
    /// city-block bbox, and total file size):
    ///
    /// ```text
    ///   rows/group   nodes read    ways read    packed total
    ///        8192        0.69%        8.83%     178486633
    ///       16384        0.86%       15.59%     179619338
    ///       32768        2.73%       29.90%     177283892
    ///       65536        4.15%       48.24%     171899868
    ///      131072        8.40%      100.00%     167987505
    /// ```
    ///
    /// 8192 reads 6x fewer bytes than 65536 for 3.8% more file. At ~200 KB of
    /// compressed node data per group it is also a sensible HTTP range-request
    /// size, which is the delivery this layout exists to serve.
    pub row_group_rows: usize,
    /// Emit the `covering.bbox` column. Off ⇒ Hilbert ordering only, which keeps
    /// the schema **byte-identical** to convert's output (useful to isolate the
    /// ordering effect from the covering effect when measuring).
    pub covering: bool,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            compression: String::from("zstd"),
            row_group_rows: 8_192,
            covering: true,
        }
    }
}

/// Result of packing one table.
#[derive(Clone, Copy, Debug, Default)]
pub struct PackStats {
    pub rows: usize,
    /// Rows whose geometry was null / unparsable — they sort last, keeping the
    /// operation total (no row is ever dropped).
    pub rows_no_geometry: usize,
    pub row_groups: usize,
    pub bytes: u64,
}

/// Read `src`, sort its rows on the Hilbert index of each feature's bounding-box
/// centre, and write `dst` with a GeoParquet 1.1 `covering.bbox` column.
///
/// **Content-preserving by construction**: every input row is carried across
/// unchanged; only the row ORDER changes and (optionally) a derived column is
/// appended. `osm-katana verify --digest` reports the same `set` digest before
/// and after — that is the equivalence gate.
///
/// Rows with no usable geometry keep their relative order and are placed after
/// every geometric row, so they occupy their own trailing row groups and never
/// widen a real group's bounds.
pub fn spatial_pack(src: &Path, dst: &Path, opts: &PackOptions) -> anyhow::Result<PackStats> {
    let file = fs::File::open(src).with_context(|| format!("open {src:?}"))?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let in_schema = builder.schema().clone();
    let reader = builder.with_batch_size(8192).build()?;

    let mut batches: Vec<RecordBatch> = Vec::new();
    for b in reader {
        batches.push(b?);
    }
    let total: usize = batches.iter().map(RecordBatch::num_rows).sum();

    let geom_idx = in_schema.index_of("geometry").map_err(|_| {
        anyhow::anyhow!("{src:?} has no `geometry` column — not a GeoParquet table")
    })?;

    // ── key extraction ────────────────────────────────────────────────────────
    // One (hilbert, batch, row) tuple per row. Batches are independent, so the
    // per-batch WKB walk fans out on gatling (ROOT LAW #0 — no rayon, no
    // hand-rolled pool); results come back in batch order so the key vector is
    // reproducible.
    let per_batch: Vec<Vec<(u64, Option<Bbox>)>> = gatling::gatling_forkjoin::gatling_map_balanced(
        &batches,
        0,
        1,
        |b: &RecordBatch| b.num_rows() as u64,
        |_i, b: &RecordBatch| {
            let g = b.column(geom_idx).as_any().downcast_ref::<BinaryArray>();
            (0..b.num_rows())
                .map(|r| match g {
                    Some(a) if !a.is_null(r) => match wkb_bbox(a.value(r)) {
                        Some(bb) => {
                            let (cx, cy) = bb.centre();
                            (hilbert_index(cx, cy), Some(bb))
                        }
                        None => (u64::MAX, None),
                    },
                    _ => (u64::MAX, None),
                })
                .collect()
        },
    );

    let mut order: Vec<(u64, u32, u32)> = Vec::with_capacity(total);
    let mut boxes: Vec<Vec<Option<Bbox>>> = Vec::with_capacity(batches.len());
    let mut no_geom = 0usize;
    for (bi, keys) in per_batch.into_iter().enumerate() {
        let mut bb = Vec::with_capacity(keys.len());
        for (ri, (h, b)) in keys.into_iter().enumerate() {
            if b.is_none() {
                no_geom += 1;
            }
            order.push((h, bi as u32, ri as u32));
            bb.push(b);
        }
        boxes.push(bb);
    }

    // Stable by construction: the tuple carries (batch, row), so equal Hilbert
    // keys — and the u64::MAX bucket of geometry-less rows — retain input order.
    gatling::gatling_sort::gatling_sort_unstable_by(&mut order, |a, b| a.cmp(b));

    // ── write ─────────────────────────────────────────────────────────────────
    let out_schema = Arc::new(pack_schema(&in_schema, opts.covering));
    let geo_json = pack_geo_json(&in_schema, opts.covering);
    let mut pb = WriterProperties::builder()
        .set_compression(crate::writer::codec(&opts.compression))
        .set_max_row_group_row_count(Some(opts.row_group_rows.max(1)))
        .set_key_value_metadata(Some(vec![parquet::file::metadata::KeyValue::new(
            String::from(metadata::GEO_KEY),
            geo_json,
        )]));
    if opts.covering {
        // BYTE_STREAM_SPLIT transposes the four bytes of each f32 into four
        // planes. After Hilbert sorting, neighbouring rows share their sign +
        // exponent + high mantissa bytes almost exactly, so three of the four
        // planes become long runs that zstd flattens. Measured on Stockholm's
        // covering columns: 46296340 → 28774887 bytes (−38%). Dictionary encoding
        // is disabled on these leaves — the values are near-unique, so a
        // dictionary is pure overhead and would pre-empt the split encoding.
        for leaf in ["xmin", "ymin", "xmax", "ymax"] {
            let path = parquet::schema::types::ColumnPath::new(vec![
                String::from(BBOX_COLUMN),
                String::from(leaf),
            ]);
            pb = pb
                .set_column_encoding(path.clone(), parquet::basic::Encoding::BYTE_STREAM_SPLIT)
                .set_column_dictionary_enabled(path, false);
        }
    }
    let props = pb.build();

    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let out = fs::File::create(dst).with_context(|| format!("create {dst:?}"))?;
    let mut w = ArrowWriter::try_new(out, out_schema.clone(), Some(props))?;

    let mut groups = 0usize;
    for chunk in order.chunks(opts.row_group_rows.max(1)) {
        let idx = take_indices(chunk, &batches);
        let mut cols: Vec<ArrayRef> = Vec::with_capacity(out_schema.fields().len());
        for c in 0..in_schema.fields().len() {
            cols.push(gather(&batches, c, &idx)?);
        }
        if opts.covering {
            cols.push(covering_array(chunk, &boxes));
        }
        w.write(&RecordBatch::try_new(out_schema.clone(), cols)?)?;
        groups += 1;
    }
    w.close()?;

    Ok(PackStats {
        rows: total,
        rows_no_geometry: no_geom,
        row_groups: groups,
        bytes: fs::metadata(dst).map(|m| m.len()).unwrap_or(0),
    })
}

/// Output schema = input schema (+ the covering column), carrying the `geo` key
/// in the Arrow metadata too so an Arrow-only round trip still sees it.
fn pack_schema(input: &Schema, covering: bool) -> Schema {
    let mut fields: Vec<Arc<Field>> = input.fields().iter().cloned().collect();
    if covering {
        fields.push(Arc::new(bbox_field()));
    }
    let mut meta: HashMap<String, String> = input.metadata().clone();
    meta.insert(
        String::from(metadata::GEO_KEY),
        pack_geo_json(input, covering),
    );
    Schema::new_with_metadata(fields, meta)
}

/// The `geo` document for the packed table: the input's geometry types (parsed
/// back out of its own `geo` key, so a repack never invents types) plus the
/// `covering` declaration.
fn pack_geo_json(input: &Schema, covering: bool) -> String {
    let types = input
        .metadata()
        .get(metadata::GEO_KEY)
        .and_then(|j| geometry_types_of(j))
        .unwrap_or_else(|| vec![String::from("Point")]);
    let refs: Vec<&str> = types.iter().map(String::as_str).collect();
    let mut m = metadata::GeoMeta::new(&refs);
    if covering {
        m = m.with_covering(BBOX_COLUMN);
    }
    m.to_json()
}

/// Pull `geometry_types` out of a `geo` JSON document without a JSON dependency
/// in the hot path (the array is a flat list of quoted strings).
fn geometry_types_of(geo_json: &str) -> Option<Vec<String>> {
    let at = geo_json.find("\"geometry_types\"")?;
    let rest = &geo_json[at..];
    let open = rest.find('[')?;
    let close = rest.find(']')?;
    if close < open {
        return None;
    }
    let inner = &rest[open + 1..close];
    let out: Vec<String> = inner
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            s.strip_prefix('"')?.strip_suffix('"').map(String::from)
        })
        .collect();
    if out.is_empty() { None } else { Some(out) }
}

/// Group a row-group's worth of `(hilbert, batch, row)` into per-batch take lists.
fn take_indices(chunk: &[(u64, u32, u32)], batches: &[RecordBatch]) -> Vec<Vec<u32>> {
    let mut idx: Vec<Vec<u32>> = vec![Vec::new(); batches.len()];
    for &(_, b, r) in chunk {
        idx[b as usize].push(r);
    }
    idx
}

/// Gather column `col` across batches in the row-group's order.
///
/// Rows are taken per source batch with Arrow's `take` (vectorised) and the
/// per-batch pieces concatenated, then re-ordered — the concatenation order is
/// the same interleave `covering_array` uses, so the derived column stays aligned
/// with the data columns.
fn gather(batches: &[RecordBatch], col: usize, idx: &[Vec<u32>]) -> anyhow::Result<ArrayRef> {
    let mut parts: Vec<ArrayRef> = Vec::new();
    for (b, rows) in batches.iter().zip(idx) {
        if rows.is_empty() {
            continue;
        }
        let take = arrow::array::UInt32Array::from(rows.clone());
        parts.push(arrow::compute::take(b.column(col).as_ref(), &take, None)?);
    }
    let refs: Vec<&dyn Array> = parts.iter().map(|a| a.as_ref()).collect();
    Ok(arrow::compute::concat(&refs)?)
}

/// The covering column for one row group, in the SAME interleave order [`gather`]
/// produces (all of batch 0's picks, then batch 1's, …).
fn covering_array(chunk: &[(u64, u32, u32)], boxes: &[Vec<Option<Bbox>>]) -> ArrayRef {
    let mut by_batch: Vec<Vec<u32>> = vec![Vec::new(); boxes.len()];
    for &(_, b, r) in chunk {
        by_batch[b as usize].push(r);
    }
    let n = chunk.len();
    let (mut xmin, mut ymin) = (
        Float32Builder::with_capacity(n),
        Float32Builder::with_capacity(n),
    );
    let (mut xmax, mut ymax) = (
        Float32Builder::with_capacity(n),
        Float32Builder::with_capacity(n),
    );
    for (bi, rows) in by_batch.iter().enumerate() {
        for &r in rows {
            match boxes[bi][r as usize] {
                Some(b) => {
                    // Outward rounding — the stored box must CONTAIN the true box.
                    xmin.append_value(down(b.xmin));
                    ymin.append_value(down(b.ymin));
                    xmax.append_value(up(b.xmax));
                    ymax.append_value(up(b.ymax));
                }
                None => {
                    xmin.append_null();
                    ymin.append_null();
                    xmax.append_null();
                    ymax.append_null();
                }
            }
        }
    }
    let DataType::Struct(fields) = bbox_field().data_type().clone() else {
        unreachable!("bbox_field is a Struct")
    };
    Arc::new(StructArray::new(
        fields,
        vec![
            Arc::new(xmin.finish()) as ArrayRef,
            Arc::new(ymin.finish()),
            Arc::new(xmax.finish()),
            Arc::new(ymax.finish()),
        ],
        None,
    ))
}

/// Pack every GeoParquet table in a convert output directory.
pub fn spatial_pack_dir(
    src: &Path,
    dst: &Path,
    opts: &PackOptions,
) -> anyhow::Result<Vec<(String, PackStats)>> {
    fs::create_dir_all(dst)?;
    let mut out = Vec::new();
    for name in ["nodes.parquet", "ways.parquet", "relations.parquet"] {
        let p = src.join(name);
        if !p.exists() {
            continue;
        }
        let stats = spatial_pack(&p, &dst.join(name), opts)?;
        out.push((String::from(name), stats));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{BinaryBuilder, Int64Builder};

    /// Locality is the whole point: two points a few metres apart must land near
    /// each other in Hilbert index, and a point on another continent must not.
    /// RED if the curve is ever replaced by something non-locality-preserving
    /// (e.g. a raw interleave of the two coordinates' high bits, or plain
    /// longitude order).
    #[test]
    fn hilbert_preserves_locality() {
        let stockholm = hilbert_index(18.0686, 59.3293);
        let next_block = hilbert_index(18.0696, 59.3298); // ~ 70 m away
        let gothenburg = hilbert_index(11.9746, 57.7089); // ~ 400 km
        let sydney = hilbert_index(151.2093, -33.8688); // other hemisphere

        let d_near = stockholm.abs_diff(next_block);
        let d_far = stockholm.abs_diff(gothenburg);
        let d_world = stockholm.abs_diff(sydney);
        assert!(
            d_near < d_far,
            "a neighbouring block must be closer in index than another city"
        );
        assert!(
            d_far < d_world,
            "another city must be closer than another continent"
        );
        // And the ordering must be a bijection on the grid — distinct cells,
        // distinct indices.
        assert_ne!(stockholm, next_block);
        assert_eq!(hilbert_index(18.0686, 59.3293), stockholm, "deterministic");
    }

    /// The curve must cover the grid exactly once — a permutation, not a hash.
    #[test]
    fn hilbert_is_a_bijection_on_a_small_grid() {
        // Exercise the real 31-bit curve but only over the coarsest 4x4 quadrants
        // (shift the cell into the top bits), which is where the rotation logic
        // lives.
        let sh = HILBERT_BITS - 2;
        let mut seen: Vec<u64> = Vec::new();
        for y in 0..4u32 {
            for x in 0..4u32 {
                seen.push(hilbert_d(x << sh, y << sh));
            }
        }
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            16,
            "16 distinct quadrants must give 16 distinct indices"
        );
        // Consecutive Hilbert cells are grid-adjacent — the defining property.
        let mut cells: Vec<(u64, u32, u32)> = Vec::new();
        for y in 0..4u32 {
            for x in 0..4u32 {
                cells.push((hilbert_d(x << sh, y << sh), x, y));
            }
        }
        cells.sort_unstable();
        for w in cells.windows(2) {
            let (_, x0, y0) = w[0];
            let (_, x1, y1) = w[1];
            let manhattan = x0.abs_diff(x1) + y0.abs_diff(y1);
            assert_eq!(
                manhattan, 1,
                "consecutive Hilbert cells must be grid neighbours"
            );
        }
    }

    /// WKB bbox must handle every shape osm-katana writes, in both byte orders.
    #[test]
    fn wkb_bbox_covers_the_written_geometry_types() {
        let p = crate::geometry::encode_point_inline(18.0686, 59.3293);
        let bb = wkb_bbox(&p).expect("point must parse");
        assert_eq!(bb.xmin, 18.0686);
        assert_eq!(bb.xmax, 18.0686);
        assert_eq!(bb.ymin, 59.3293);
        assert_eq!(bb.ymax, 59.3293);

        // LineString with three points → the enclosing box.
        let mut ls: Vec<u8> = vec![1];
        ls.extend_from_slice(&2u32.to_le_bytes());
        ls.extend_from_slice(&3u32.to_le_bytes());
        for (x, y) in [(1.0f64, 5.0f64), (3.0, 2.0), (-1.0, 4.0)] {
            ls.extend_from_slice(&x.to_le_bytes());
            ls.extend_from_slice(&y.to_le_bytes());
        }
        let bb = wkb_bbox(&ls).unwrap();
        assert_eq!((bb.xmin, bb.ymin, bb.xmax, bb.ymax), (-1.0, 2.0, 3.0, 5.0));

        // Big-endian point — the byte-order flag must actually be honoured.
        let mut be: Vec<u8> = vec![0];
        be.extend_from_slice(&1u32.to_be_bytes());
        be.extend_from_slice(&7.5f64.to_be_bytes());
        be.extend_from_slice(&(-2.5f64).to_be_bytes());
        let bb = wkb_bbox(&be).unwrap();
        assert_eq!((bb.xmin, bb.ymin), (7.5, -2.5));

        // RED-when-broken: junk must be rejected, not silently boxed at 0,0
        // (a 0,0 bbox would poison every row group's statistics).
        assert!(wkb_bbox(&[]).is_none());
        assert!(
            wkb_bbox(&[1, 9, 9, 9, 9]).is_none(),
            "unknown WKB type must not parse"
        );
        assert!(
            wkb_bbox(&p[..10]).is_none(),
            "truncated point must not parse"
        );
    }

    /// A covering must CONTAIN the geometry it covers. `f32` cannot represent an
    /// OSM 1e-7° coordinate exactly, so the rounding direction is load-bearing:
    /// round-to-nearest would shrink roughly half of all boxes and a reader could
    /// then prune away a row group holding a real hit.
    ///
    /// RED-when-broken: replace `down`/`up` with `as f32` and this fails on the
    /// first coordinate whose nearest f32 lands on the wrong side.
    #[test]
    fn covering_is_conservative() {
        let mut shrunk = 0usize;
        // Real OSM-grid coordinates across Stockholm, at 1e-7° resolution.
        for k in 0..20_000i64 {
            let lon = 17.5 + (k as f64) * 1e-7;
            let lat = 59.1 + (k as f64) * 1e-7;
            assert!(
                f64::from(down(lon)) <= lon,
                "xmin must round DOWN past {lon}"
            );
            assert!(f64::from(up(lon)) >= lon, "xmax must round UP past {lon}");
            assert!(
                f64::from(down(lat)) <= lat,
                "ymin must round DOWN past {lat}"
            );
            assert!(f64::from(up(lat)) >= lat, "ymax must round UP past {lat}");
            if (lon as f32) as f64 > lon {
                shrunk += 1; // naive cast would have shrunk this box
            }
        }
        assert!(
            shrunk > 1000,
            "the fixture must actually exercise the case a naive cast gets wrong \
             (only {shrunk} of 20000 did)"
        );
        // Negative coordinates and zero must round outwards too.
        for v in [-18.0685_f64, -0.000_000_3, 0.0, 179.999_999_9] {
            assert!(f64::from(down(v)) <= v, "down({v})");
            assert!(f64::from(up(v)) >= v, "up({v})");
        }
    }

    fn tiny_table(path: &Path, pts: &[(i64, f64, f64)]) {
        let schema = Arc::new(crate::shared::schema::nodes_schema());
        let mut id = Int64Builder::new();
        let mut g = BinaryBuilder::new();
        for &(i, lon, lat) in pts {
            id.append_value(i);
            g.append_value(crate::geometry::encode_point_inline(lon, lat));
        }
        let n = pts.len();
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id.finish()),
                Arc::new(g.finish()),
                arrow::array::new_null_array(&DataType::Utf8, n),
                arrow::array::new_null_array(&DataType::Int32, n),
                arrow::array::new_null_array(&DataType::Int64, n),
                arrow::array::new_null_array(&DataType::Utf8, n),
            ],
        )
        .unwrap();
        let f = fs::File::create(path).unwrap();
        let mut w = ArrowWriter::try_new(f, schema, None).unwrap();
        w.write(&batch).unwrap();
        w.close().unwrap();
    }

    /// THE deliverable, in miniature: after packing, each row group's `bbox.xmin`
    /// / `bbox.xmax` statistics must describe a COMPACT region, not the whole
    /// file — that is what makes pruning possible. Also asserts the covering
    /// metadata is declared and no row is lost.
    #[test]
    fn pack_makes_row_groups_compact_and_declares_covering() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.parquet");
        let dst = dir.path().join("out.parquet");

        // Four well-separated clusters, INTERLEAVED on input — exactly the
        // pathology convert produces (parse order ≠ spatial order).
        let clusters = [
            (18.06, 59.33),
            (11.97, 57.71),
            (13.00, 55.60),
            (17.64, 59.85),
        ];
        let mut pts = Vec::new();
        for k in 0..64i64 {
            let (lon, lat) = clusters[(k % 4) as usize];
            let j = (k / 4) as f64 * 1e-4;
            pts.push((k, lon + j, lat + j));
        }
        tiny_table(&src, &pts);

        let opts = PackOptions {
            row_group_rows: 16,
            ..Default::default()
        };
        let st = spatial_pack(&src, &dst, &opts).unwrap();
        assert_eq!(st.rows, 64);
        assert_eq!(st.rows_no_geometry, 0);
        assert_eq!(st.row_groups, 4);

        let f = fs::File::open(&dst).unwrap();
        let b = ParquetRecordBatchReaderBuilder::try_new(f).unwrap();
        let md = b.metadata().clone();

        // The `covering` declaration must be in the FILE-level key-value metadata.
        let kv = md
            .file_metadata()
            .key_value_metadata()
            .expect("kv metadata");
        let geo = kv
            .iter()
            .find(|k| k.key == "geo")
            .and_then(|k| k.value.clone())
            .expect("geo key");
        assert!(
            geo.contains("\"covering\""),
            "packed file must declare covering.bbox"
        );

        // Locate the bbox.xmin / bbox.xmax leaves and read each group's stats.
        let sch = md.file_metadata().schema_descr();
        let (mut lo_i, mut hi_i) = (usize::MAX, usize::MAX);
        for i in 0..sch.num_columns() {
            match sch.column(i).path().string().as_str() {
                "bbox.xmin" => lo_i = i,
                "bbox.xmax" => hi_i = i,
                _ => {}
            }
        }
        assert_ne!(lo_i, usize::MAX, "bbox.xmin leaf must exist");

        let mut widths = Vec::new();
        for g in 0..md.num_row_groups() {
            let lo = md.row_group(g).column(lo_i).statistics().unwrap();
            let hi = md.row_group(g).column(hi_i).statistics().unwrap();
            // FLOAT per `bbox_field` (4.6x smaller than DOUBLE, and the spec
            // permits either). The reader side must therefore understand
            // `Statistics::Float` — skade's `row_group_survives` gained that arm
            // alongside this change; without it the covering prunes nothing.
            let (
                parquet::file::statistics::Statistics::Float(l),
                parquet::file::statistics::Statistics::Float(h),
            ) = (lo, hi)
            else {
                panic!("covering statistics must be FLOAT (see bbox_field)");
            };
            widths.push(f64::from(*h.max_opt().unwrap()) - f64::from(*l.min_opt().unwrap()));
        }
        let file_width = 18.06 - 11.97;
        for (g, w) in widths.iter().enumerate() {
            assert!(
                *w < file_width / 10.0,
                "row group {g} spans {w}° — Hilbert packing must make it far tighter \
                 than the file's {file_width}°; unsorted input gives every group the full span"
            );
        }

        // Content is preserved: same ids, same count.
        let rdr = ParquetRecordBatchReaderBuilder::try_new(fs::File::open(&dst).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let mut ids: Vec<i64> = Vec::new();
        for batch in rdr {
            let batch = batch.unwrap();
            let a = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::Int64Array>()
                .unwrap();
            ids.extend((0..a.len()).map(|i| a.value(i)));
        }
        assert_ne!(
            ids,
            (0..64).collect::<Vec<_>>(),
            "the order MUST have changed (that is the point)"
        );
        ids.sort_unstable();
        assert_eq!(
            ids,
            (0..64).collect::<Vec<_>>(),
            "…but not one row may be lost or duplicated"
        );
    }

    /// Rows with null/garbage geometry are kept, sorted last, and get a NULL
    /// covering — never a fake 0,0 box that would wreck the statistics.
    #[test]
    fn geometryless_rows_survive_and_sort_last() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.parquet");
        let dst = dir.path().join("out.parquet");

        let schema = Arc::new(crate::shared::schema::nodes_schema());
        let mut id = Int64Builder::new();
        let mut g = BinaryBuilder::new();
        for k in 0..10i64 {
            id.append_value(k);
            if k % 2 == 0 {
                g.append_value(crate::geometry::encode_point_inline(
                    18.0 + k as f64 * 1e-3,
                    59.0,
                ));
            } else {
                g.append_null();
            }
        }
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id.finish()),
                Arc::new(g.finish()),
                arrow::array::new_null_array(&DataType::Utf8, 10),
                arrow::array::new_null_array(&DataType::Int32, 10),
                arrow::array::new_null_array(&DataType::Int64, 10),
                arrow::array::new_null_array(&DataType::Utf8, 10),
            ],
        )
        .unwrap();
        let f = fs::File::create(&src).unwrap();
        let mut w = ArrowWriter::try_new(f, schema, None).unwrap();
        w.write(&batch).unwrap();
        w.close().unwrap();

        let st = spatial_pack(&src, &dst, &PackOptions::default()).unwrap();
        assert_eq!(st.rows, 10, "no row may be dropped");
        assert_eq!(st.rows_no_geometry, 5);

        let rdr = ParquetRecordBatchReaderBuilder::try_new(fs::File::open(&dst).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let mut ids: Vec<i64> = Vec::new();
        let mut bbox_null: Vec<bool> = Vec::new();
        for batch in rdr {
            let batch = batch.unwrap();
            let a = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::Int64Array>()
                .unwrap();
            ids.extend((0..a.len()).map(|i| a.value(i)));
            let bb = batch
                .column_by_name("bbox")
                .unwrap()
                .as_any()
                .downcast_ref::<StructArray>()
                .unwrap()
                .column(0)
                .clone();
            bbox_null.extend((0..bb.len()).map(|i| bb.is_null(i)));
        }
        assert_eq!(
            &ids[5..],
            &[1, 3, 5, 7, 9],
            "geometry-less rows sort last, in input order"
        );
        assert_eq!(
            &bbox_null[5..],
            &[true; 5],
            "…with a NULL covering, not a fabricated 0,0 box"
        );
        assert_eq!(&bbox_null[..5], &[false; 5]);
    }
}
