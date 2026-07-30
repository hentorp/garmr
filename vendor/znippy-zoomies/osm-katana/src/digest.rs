//! Layout-invariant **content digest** of a GeoParquet table — the equivalence
//! gate for "did this optimisation change the output?".
//!
//! ## Why not `sha256 nodes.parquet`
//!
//! osm-katana encodes row groups **on the gatling workers** and stitches them in
//! stream order, so the *number and boundaries* of row groups depend on how the
//! input happened to be segmented across workers on that run. Two runs of the
//! **same binary on the same input** therefore produce parquet files with
//! identical row CONTENT but different bytes (verified: three back-to-back
//! liechtenstein converts gave three distinct `sha256(nodes.parquet)` while
//! `node_coords.arrow` — written by the deterministic merge — matched exactly).
//! A raw file checksum can never be the equivalence gate for this converter.
//!
//! ## What this computes instead
//!
//! The digest of the **row sequence**: every row is encoded to a canonical byte
//! string (per column, in schema order: a presence tag then the value's raw
//! bytes), hashed to a 64-bit value, and the per-row hashes are folded with a
//! **positional polynomial** over the Mersenne prime `2^61 - 1`:
//!
//! ```text
//!   H(r0..rn) = ((h0 * B + h1) * B + h2) … * B + hn        (Horner)
//!   H(A ++ B) = H(A) * B^len(B) + H(B)                     (associative)
//! ```
//!
//! Because the combine rule needs only the *row count* of the right-hand run,
//! each row group can be hashed independently on its own core and the partials
//! folded back in row-group order — so the digest is **invariant to row-group
//! layout** while remaining **order-sensitive** (a swapped pair of rows changes
//! it). Two outputs with the same digest hold the same rows, in the same order,
//! with the same values; that is the strongest statement available here and it
//! is what "byte-identical output" means for this pipeline.
//!
//! Fan-out is [`gatling::gatling_forkjoin::gatling_for_each_balanced`] over the
//! row-group indices, weighted by each group's compressed byte size (LPT) —
//! ROOT LAW #0: no rayon, no hand-rolled thread pool.

use std::fs::File;
use std::path::Path;

use anyhow::Context as _;
use arrow::array::{Array, BinaryArray, Int32Array, Int64Array, ListArray, StringArray};
use arrow::datatypes::DataType;
use arrow::record_batch::RecordBatch;
use parquet::arrow::arrow_reader::{
    ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReaderBuilder,
};

/// Mersenne prime modulus `2^61 - 1` — big enough that an accidental collision is
/// not a practical concern, small enough that `u128` intermediates never overflow.
const P: u128 = (1u128 << 61) - 1;
/// Polynomial base (an odd 61-bit constant, the golden-ratio mix reduced mod P).
const B: u128 = 0x1E37_79B9_7F4A_7C15;

#[inline]
fn mulm(a: u128, b: u128) -> u128 {
    // a, b < 2^61 ⇒ a*b < 2^122, fits u128.
    (a * b) % P
}

#[inline]
fn addm(a: u128, b: u128) -> u128 {
    (a + b) % P
}

/// `B^n mod P` by square-and-multiply.
fn powm(mut base: u128, mut n: u64) -> u128 {
    let mut acc: u128 = 1;
    base %= P;
    while n > 0 {
        if n & 1 == 1 {
            acc = mulm(acc, base);
        }
        base = mulm(base, base);
        n >>= 1;
    }
    acc
}

/// A digest of a contiguous run of rows.
///
/// Two independent folds are carried, because the converter guarantees two
/// different things:
///
/// * `hash` — the **ordered** polynomial digest. Sensitive to row order.
/// * `set`  — the **multiset** digest (plain sum of the per-row hashes mod `P`).
///   Invariant to row order, so it still catches any changed / dropped / added /
///   duplicated row.
///
/// The converter's row ORDER is *not* deterministic run-to-run: at end of pass
/// each gatling worker flushes its partial row-group accumulator via
/// `finish_worker`, and those tail batches are appended in worker-completion
/// order. So `set` (+ `rows`) is the equivalence gate; `hash` is reported
/// alongside it as the stronger statement to use when a change is expected to
/// preserve order too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunDigest {
    pub hash: u128,
    pub set: u128,
    pub rows: u64,
}

impl RunDigest {
    pub const EMPTY: RunDigest = RunDigest {
        hash: 0,
        set: 0,
        rows: 0,
    };

    /// Fold the run `other`, which follows `self` in row order, onto `self`.
    /// Associative, so any bracketing of the row groups yields one value.
    pub fn concat(self, other: RunDigest) -> RunDigest {
        RunDigest {
            hash: addm(mulm(self.hash, powm(B, other.rows)), other.hash),
            set: addm(self.set, other.set),
            rows: self.rows + other.rows,
        }
    }

    /// Append one already-hashed row.
    #[inline]
    fn push_row(&mut self, h: u64) {
        let hp = (h as u128) % P;
        self.hash = addm(mulm(self.hash, B), hp);
        self.set = addm(self.set, hp);
        self.rows += 1;
    }

    /// Stable 16-hex-digit rendering of the ORDERED digest.
    pub fn hex(&self) -> String {
        fold_hex(self.hash)
    }

    /// Stable 16-hex-digit rendering of the ORDER-INDEPENDENT (multiset) digest —
    /// the one the equivalence gate compares.
    pub fn set_hex(&self) -> String {
        fold_hex(self.set)
    }
}

fn fold_hex(v: u128) -> String {
    format!("{:016x}", (v as u64) ^ ((v >> 61) as u64))
}

/// FNV-1a over the canonical row encoding. Cheap, stable across builds and
/// architectures (no `RandomState`, no pointer values).
struct RowHasher(u64);

impl RowHasher {
    #[inline]
    fn new() -> Self {
        RowHasher(0xcbf2_9ce4_8422_2325)
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x1000_0000_01b3);
        }
    }
    #[inline]
    fn tag(&mut self, t: u8) {
        self.write(&[t]);
    }
}

/// Hash every row of `batch` into `run`, in batch order.
///
/// Canonical encoding, per column in schema order: a presence tag (`0` null /
/// `1` present) followed by the value's raw bytes (little-endian for the numeric
/// widths, UTF-8/raw for the byte columns, and for a `List<Int64>` the element
/// count then each element). Column *count* and order come from the schema, so a
/// column added/removed/reordered changes the digest — which is what we want.
fn hash_batch(batch: &RecordBatch, run: &mut RunDigest) -> anyhow::Result<()> {
    let n = batch.num_rows();
    if n == 0 {
        return Ok(());
    }
    // Resolve each column to a typed view ONCE per batch, not per row.
    enum Col<'a> {
        I64(&'a Int64Array),
        I32(&'a Int32Array),
        Str(&'a StringArray),
        Bin(&'a BinaryArray),
        ListI64(&'a ListArray),
    }
    let mut cols: Vec<Col> = Vec::with_capacity(batch.num_columns());
    for (i, f) in batch.schema().fields().iter().enumerate() {
        let a = batch.column(i).as_ref();
        let c = match f.data_type() {
            DataType::Int64 => Col::I64(
                a.as_any()
                    .downcast_ref::<Int64Array>()
                    .context("column typed Int64 is not an Int64Array")?,
            ),
            DataType::Int32 => Col::I32(
                a.as_any()
                    .downcast_ref::<Int32Array>()
                    .context("column typed Int32 is not an Int32Array")?,
            ),
            DataType::Utf8 => Col::Str(
                a.as_any()
                    .downcast_ref::<StringArray>()
                    .context("column typed Utf8 is not a StringArray")?,
            ),
            DataType::Binary => Col::Bin(
                a.as_any()
                    .downcast_ref::<BinaryArray>()
                    .context("column typed Binary is not a BinaryArray")?,
            ),
            DataType::List(inner) if matches!(inner.data_type(), DataType::Int64) => Col::ListI64(
                a.as_any()
                    .downcast_ref::<ListArray>()
                    .context("column typed List<Int64> is not a ListArray")?,
            ),
            other => anyhow::bail!(
                "digest: unsupported column type {other:?} for field {:?} — extend digest.rs \
                 rather than silently hashing a partial row",
                f.name()
            ),
        };
        cols.push(c);
    }

    for r in 0..n {
        let mut h = RowHasher::new();
        for c in &cols {
            match c {
                Col::I64(a) => {
                    if a.is_null(r) {
                        h.tag(0);
                    } else {
                        h.tag(1);
                        h.write(&a.value(r).to_le_bytes());
                    }
                }
                Col::I32(a) => {
                    if a.is_null(r) {
                        h.tag(0);
                    } else {
                        h.tag(1);
                        h.write(&a.value(r).to_le_bytes());
                    }
                }
                Col::Str(a) => {
                    if a.is_null(r) {
                        h.tag(0);
                    } else {
                        h.tag(1);
                        h.write(a.value(r).as_bytes());
                    }
                }
                Col::Bin(a) => {
                    if a.is_null(r) {
                        h.tag(0);
                    } else {
                        h.tag(1);
                        h.write(a.value(r));
                    }
                }
                Col::ListI64(a) => {
                    if a.is_null(r) {
                        h.tag(0);
                    } else {
                        h.tag(1);
                        let vals = a.value(r);
                        let iv = vals
                            .as_any()
                            .downcast_ref::<Int64Array>()
                            .context("List<Int64> values are not an Int64Array")?;
                        h.write(&(iv.len() as u64).to_le_bytes());
                        for k in 0..iv.len() {
                            if iv.is_null(k) {
                                h.tag(0);
                            } else {
                                h.tag(1);
                                h.write(&iv.value(k).to_le_bytes());
                            }
                        }
                    }
                }
            }
        }
        run.push_row(h.0);
    }
    Ok(())
}

/// The `geo` document of a parquet file, from the file-level Parquet key-value
/// metadata (the spec's location) or, failing that, the Arrow schema metadata
/// (where this crate used to hide it).
fn geo_doc(
    meta: &parquet::file::metadata::ParquetMetaData,
    schema: &arrow::datatypes::Schema,
) -> Option<String> {
    if let Some(kv) = meta.file_metadata().key_value_metadata() {
        if let Some(v) = kv.iter().find(|k| k.key == crate::metadata::GEO_KEY) {
            if let Some(v) = &v.value {
                return Some(v.clone());
            }
        }
    }
    schema.metadata().get(crate::metadata::GEO_KEY).cloned()
}

/// Content digest of one parquet file. Row groups are hashed in parallel (one
/// gatling unit each, LPT-scheduled by compressed size) and folded in row-group
/// order, so the result is independent of how many row groups the writer chose.
///
/// **The GeoParquet `covering` column is excluded.** A covering bbox is a *pure
/// function of the geometry column* — it carries no independent content — so
/// hashing it would add nothing while making a spatially-packed table
/// incomparable with the convert output it was built from. Excluding it is what
/// lets `verify --digest` remain THE equivalence gate across
/// [`crate::spatial::spatial_pack`]: same rows, same values, only the order (and
/// a derived column) changed. Every non-derived column is still hashed, so a real
/// change is still caught.
pub fn digest_file(path: &Path) -> anyhow::Result<RunDigest> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(
        File::open(path).with_context(|| format!("open {path:?}"))?,
    )?;
    let meta = builder.metadata().clone();
    let arrow_schema = builder.schema().clone();
    let n_rg = meta.num_row_groups();
    if n_rg == 0 {
        return Ok(RunDigest::EMPTY);
    }
    let sizes: Vec<u64> = meta
        .row_groups()
        .iter()
        .map(|rg| rg.compressed_size().max(0) as u64)
        .collect();

    // Root-column projection that drops the declared covering column (if any).
    let covering = geo_doc(&meta, &arrow_schema).and_then(|g| crate::metadata::covering_column(&g));
    let keep: Option<Vec<usize>> = covering.as_ref().map(|c| {
        arrow_schema
            .fields()
            .iter()
            .enumerate()
            .filter(|(_, f)| f.name() != c)
            .map(|(i, _)| i)
            .collect()
    });

    let per_group: Vec<anyhow::Result<RunDigest>> =
        gatling::gatling_forkjoin::gatling_for_each_balanced(
            n_rg,
            0,
            1,
            |i| sizes[i],
            |i| -> anyhow::Result<RunDigest> {
                let arm = ArrowReaderMetadata::try_new(meta.clone(), ArrowReaderOptions::new())?;
                let mut b = ParquetRecordBatchReaderBuilder::new_with_metadata(
                    File::open(path).with_context(|| format!("open {path:?}"))?,
                    arm,
                )
                .with_row_groups(vec![i])
                .with_batch_size(8192);
                if let Some(k) = &keep {
                    b = b.with_projection(parquet::arrow::ProjectionMask::roots(
                        meta.file_metadata().schema_descr(),
                        k.iter().copied(),
                    ));
                }
                let rdr = b.build()?;
                let mut run = RunDigest::EMPTY;
                for batch in rdr {
                    hash_batch(&batch?, &mut run)?;
                }
                Ok(run)
            },
        );

    let mut total = RunDigest::EMPTY;
    for r in per_group {
        total = total.concat(r?);
    }
    Ok(total)
}

/// Digest every GeoParquet table in a convert output `dir`, in a fixed table
/// order. Missing tables are reported as `None` so a digest line is comparable
/// across runs that emitted different subsets.
pub fn digest_dir(dir: &Path) -> anyhow::Result<Vec<(&'static str, Option<RunDigest>)>> {
    let mut out = Vec::new();
    for name in ["nodes.parquet", "ways.parquet", "relations.parquet"] {
        let p = dir.join(name);
        if p.exists() {
            out.push((name, Some(digest_file(&p)?)));
        } else {
            out.push((name, None));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{BinaryBuilder, Int32Builder, Int64Builder, StringBuilder};
    use arrow::datatypes::{Field, Schema};
    use std::sync::Arc;

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("geometry", DataType::Binary, true),
            Field::new("tags", DataType::Utf8, true),
            Field::new("version", DataType::Int32, true),
        ]))
    }

    fn batch(ids: &[i64]) -> RecordBatch {
        let mut i = Int64Builder::new();
        let mut g = BinaryBuilder::new();
        let mut t = StringBuilder::new();
        let mut v = Int32Builder::new();
        for &id in ids {
            i.append_value(id);
            if id % 3 == 0 {
                g.append_null();
            } else {
                g.append_value(id.to_le_bytes());
            }
            t.append_value(format!("{{\"k\":\"{id}\"}}"));
            v.append_option(if id % 2 == 0 { Some(1) } else { None });
        }
        RecordBatch::try_new(
            schema(),
            vec![
                Arc::new(i.finish()),
                Arc::new(g.finish()),
                Arc::new(t.finish()),
                Arc::new(v.finish()),
            ],
        )
        .unwrap()
    }

    fn digest_of(chunks: &[&[i64]]) -> RunDigest {
        let mut total = RunDigest::EMPTY;
        for c in chunks {
            let mut run = RunDigest::EMPTY;
            hash_batch(&batch(c), &mut run).unwrap();
            total = total.concat(run);
        }
        total
    }

    /// THE property the equivalence gate rests on: the digest depends on the ROW
    /// SEQUENCE only — re-chunking the same rows into different row groups (which
    /// is exactly what the parallel writer does run-to-run) must not move it.
    /// RED if `concat` ever loses associativity or forgets the row count.
    #[test]
    fn digest_is_invariant_to_row_group_layout() {
        let all: Vec<i64> = (1..=50).collect();
        let one = digest_of(&[&all]);
        let split3 = digest_of(&[&all[..7], &all[7..31], &all[31..]]);
        let split_many = digest_of(&all.chunks(5).collect::<Vec<_>>());
        assert_eq!(
            one, split3,
            "row-group boundaries must not change the digest"
        );
        assert_eq!(one, split_many, "any chunking must give the same digest");
        assert_eq!(one.rows, 50);
    }

    /// The MULTISET digest — the actual equivalence gate, because the converter's
    /// tail batches land in worker-completion order. It must ignore row ORDER but
    /// still catch a changed / dropped row. RED if `set` ever picks up a
    /// position-dependent term.
    #[test]
    fn set_digest_ignores_order_but_not_content() {
        let all: Vec<i64> = (1..=30).collect();
        let base = digest_of(&[&all]);

        let mut shuffled = all.clone();
        shuffled.reverse();
        assert_ne!(
            base.hash,
            digest_of(&[&shuffled]).hash,
            "ordered digest sees the reorder"
        );
        assert_eq!(
            base.set,
            digest_of(&[&shuffled]).set,
            "multiset digest must NOT see a reorder"
        );
        assert_eq!(base.rows, digest_of(&[&shuffled]).rows);

        let mut changed = all.clone();
        changed[7] = 4242;
        assert_ne!(
            base.set,
            digest_of(&[&changed]).set,
            "a changed value must move the multiset digest"
        );

        let dropped: Vec<i64> = all.iter().copied().filter(|&x| x != 11).collect();
        assert_ne!(
            base.set,
            digest_of(&[&dropped]).set,
            "a dropped row must move the multiset digest"
        );

        let mut dup = all.clone();
        dup.push(11);
        assert_ne!(
            base.set,
            digest_of(&[&dup]).set,
            "a duplicated row must move the multiset digest"
        );
    }

    /// RED-when-broken: the digest must actually NOTICE a changed row, a dropped
    /// row, and a reordered pair — otherwise it would green-light a corrupting
    /// "optimisation".
    #[test]
    fn digest_detects_content_order_and_count_changes() {
        let all: Vec<i64> = (1..=20).collect();
        let base = digest_of(&[&all]);

        let mut changed = all.clone();
        changed[9] = 999;
        assert_ne!(
            base,
            digest_of(&[&changed]),
            "a changed value must change the digest"
        );

        let dropped: Vec<i64> = all.iter().copied().filter(|&x| x != 5).collect();
        assert_ne!(
            base,
            digest_of(&[&dropped]),
            "a dropped row must change the digest"
        );

        let mut swapped = all.clone();
        swapped.swap(3, 4);
        assert_ne!(
            base,
            digest_of(&[&swapped]),
            "reordered rows must change the digest"
        );

        // A pure re-chunk of the SAME rows must NOT change it (the other side of
        // the same coin, asserted here so both directions live in one test).
        assert_eq!(base, digest_of(&[&all[..4], &all[4..]]));
    }

    /// `concat` must be associative — the fold order of the parallel row-group
    /// partials is an implementation detail and may not affect the result.
    #[test]
    fn concat_is_associative() {
        let a: Vec<i64> = (1..=6).collect();
        let b: Vec<i64> = (7..=9).collect();
        let c: Vec<i64> = (10..=17).collect();
        let mk = |v: &[i64]| {
            let mut r = RunDigest::EMPTY;
            hash_batch(&batch(v), &mut r).unwrap();
            r
        };
        let (da, db, dc) = (mk(&a), mk(&b), mk(&c));
        assert_eq!(da.concat(db).concat(dc), da.concat(db.concat(dc)));
    }
}
