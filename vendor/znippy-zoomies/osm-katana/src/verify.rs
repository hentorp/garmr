//! GeoParquet output verification — the ONE canonical implementation.
//!
//! Both the `osm-katana verify` CLI subcommand and any programmatic caller go
//! through [`verify`] so they can never report divergent numbers. It reads the
//! parquet footer once (rows + geometry null/set straight from column
//! statistics — no data decode) and, for `node_refs`, does a no-barrier,
//! column-projected, row-group-parallel count. If the footer lacks geometry
//! statistics it falls back to a (still column-projected, parallel) geometry
//! decode rather than silently reporting wrong numbers.

use std::path::Path;
use std::sync::Arc;

use parquet::file::metadata::ParquetMetaData;

/// Verified counts for a single parquet file — obtained from the footer (rows +
/// geometry null) for free, and from a no-barrier, column-projected,
/// row-group-parallel decode for `node_refs`.
pub struct VerifyCounts {
    pub rows: usize,
    pub has_geom: bool,
    pub geom_set: usize,
    pub geom_null: usize,
    pub has_refs: bool,
    pub refs_nonempty: usize,
    pub refs_total: usize,
}

/// Verify a single GeoParquet file, returning its [`VerifyCounts`].
pub fn verify(path: &Path) -> anyhow::Result<VerifyCounts> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;

    // One footer read. No data decode yet.
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?;
    let arrow_schema = builder.schema().clone();
    let has_geom = arrow_schema.index_of("geometry").is_ok();
    let has_refs = arrow_schema.index_of("node_refs").is_ok();

    let meta = builder.metadata().clone();
    let rows = meta.file_metadata().num_rows() as usize;
    let n_rg = meta.num_row_groups();

    // --- geometry null/set: metadata fast-path (footer statistics, no decode) ---
    // Locate the geometry leaf column(s) in the parquet schema by root path part.
    let mut geom_null: usize = 0;
    let mut geom_stats_ok = true;
    if has_geom {
        for rg in meta.row_groups() {
            // geometry is a single Binary leaf; sum any column chunk rooted at "geometry".
            let mut found = false;
            for col in rg.columns() {
                let parts = col.column_path().parts();
                if parts.first().map(|s| s.as_str()) == Some("geometry") {
                    found = true;
                    match col.statistics().and_then(|s| s.null_count_opt()) {
                        Some(n) => geom_null += n as usize,
                        None => {
                            geom_stats_ok = false;
                        }
                    }
                }
            }
            if !found {
                geom_stats_ok = false;
            }
            if !geom_stats_ok {
                break;
            }
        }
    }

    // --- node_refs: needs real data. Parallelize over row groups, project ONLY
    //     node_refs, one reader per worker, no barrier — final sum is the only join.
    let (refs_nonempty, refs_total) = if has_refs && n_rg > 0 {
        count_node_refs(path, &meta, n_rg)?
    } else {
        (0, 0)
    };

    // If the footer lacked geometry statistics, never report wrong numbers:
    // fall back to a (still column-projected, parallel) decode of geometry only.
    let geom_set;
    if has_geom {
        if geom_stats_ok {
            geom_set = rows - geom_null;
        } else {
            let (g_null, g_set) = count_geometry(path, &meta, n_rg)?;
            geom_null = g_null;
            geom_set = g_set;
        }
    } else {
        geom_set = 0;
        geom_null = 0;
    }

    Ok(VerifyCounts {
        rows,
        has_geom,
        geom_set,
        geom_null,
        has_refs,
        refs_nonempty,
        refs_total,
    })
}

/// Count `node_refs` across every row group, ROOT LAW #0 style: gatling fan-out,
/// one unit per ROW GROUP, LPT-scheduled heaviest-first by the group's compressed
/// byte size. Each unit opens its OWN reader projected to ONLY `node_refs` over
/// its single group and counts locally; the sum is the only join.
///
/// The old shape was a hand-rolled `std::thread::scope` pool over a **round-robin
/// `rg % n_workers` partition** — a static carve-up that could not rebalance: row
/// groups in an osm-katana table differ several-fold in compressed size (a group
/// full of long `node_refs` lists against a group of bare nodes), and whichever
/// worker drew the fat ones held the whole tail alone. One unit per group means a
/// worker that draws a cheap group immediately claims the next, and heaviest-first
/// keeps the fattest group from being the last thing started.
fn count_node_refs(
    path: &Path,
    meta: &Arc<ParquetMetaData>,
    n_rg: usize,
) -> anyhow::Result<(usize, usize)> {
    let results = gatling::gatling_forkjoin::gatling_for_each_balanced(
        n_rg,
        0,
        1,
        |rg| meta.row_group(rg).compressed_size().max(0) as u64,
        |rg| count_refs_for_row_groups(path, meta, std::slice::from_ref(&rg)),
    );

    let mut nonempty = 0usize;
    let mut total = 0usize;
    for r in results {
        let (ne, t) = r?;
        nonempty += ne;
        total += t;
    }
    Ok((nonempty, total))
}

fn count_refs_for_row_groups(
    path: &Path,
    meta: &Arc<ParquetMetaData>,
    rgs: &[usize],
) -> anyhow::Result<(usize, usize)> {
    use arrow::array::{Array, ListArray};
    use parquet::arrow::ProjectionMask;
    use parquet::arrow::arrow_reader::{
        ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReaderBuilder,
    };
    use std::fs::File;

    // Reuse the already-parsed footer; project ONLY node_refs (never touch
    // the 57 GB geometry/tags columns just to count refs).
    let arm = ArrowReaderMetadata::try_new(meta.clone(), ArrowReaderOptions::new())?;
    let builder = ParquetRecordBatchReaderBuilder::new_with_metadata(File::open(path)?, arm);
    let mask = ProjectionMask::columns(builder.parquet_schema(), ["node_refs"]);
    let reader = builder
        .with_row_groups(rgs.to_vec())
        .with_projection(mask)
        .build()?;

    let mut nonempty = 0usize;
    let mut total = 0usize;
    for batch in reader {
        let b = batch?;
        // node_refs is the only projected column → index 0 in the output schema.
        if let Some(l) = b.column(0).as_any().downcast_ref::<ListArray>() {
            let offsets = l.value_offsets();
            for i in 0..l.len() {
                if l.is_valid(i) {
                    let len = (offsets[i + 1] - offsets[i]) as usize;
                    total += len;
                    if len > 0 {
                        nonempty += 1;
                    }
                }
            }
        }
    }
    Ok((nonempty, total))
}

/// Fallback (only when the footer lacks geometry statistics): row-group-parallel,
/// geometry-only projected decode. Never silently report wrong numbers.
///
/// Same gatling shape as [`count_node_refs`] — one unit per row group, LPT by the
/// group's compressed size, sum-reduced. (Was the same round-robin
/// `std::thread::scope` pool.)
fn count_geometry(
    path: &Path,
    meta: &Arc<ParquetMetaData>,
    n_rg: usize,
) -> anyhow::Result<(usize, usize)> {
    let results = gatling::gatling_forkjoin::gatling_for_each_balanced(
        n_rg,
        0,
        1,
        |rg| meta.row_group(rg).compressed_size().max(0) as u64,
        |rg| count_geom_for_row_groups(path, meta, std::slice::from_ref(&rg)),
    );

    let mut null = 0usize;
    let mut set = 0usize;
    for r in results {
        let (n, s) = r?;
        null += n;
        set += s;
    }
    Ok((null, set))
}

fn count_geom_for_row_groups(
    path: &Path,
    meta: &Arc<ParquetMetaData>,
    rgs: &[usize],
) -> anyhow::Result<(usize, usize)> {
    use arrow::array::Array;
    use parquet::arrow::ProjectionMask;
    use parquet::arrow::arrow_reader::{
        ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReaderBuilder,
    };
    use std::fs::File;

    let arm = ArrowReaderMetadata::try_new(meta.clone(), ArrowReaderOptions::new())?;
    let builder = ParquetRecordBatchReaderBuilder::new_with_metadata(File::open(path)?, arm);
    let mask = ProjectionMask::columns(builder.parquet_schema(), ["geometry"]);
    let reader = builder
        .with_row_groups(rgs.to_vec())
        .with_projection(mask)
        .build()?;

    let mut null = 0usize;
    let mut set = 0usize;
    for batch in reader {
        let b = batch?;
        let col = b.column(0);
        let n = col.null_count();
        null += n;
        set += col.len() - n;
    }
    Ok((null, set))
}

#[cfg(test)]
mod tests {
    use super::verify;
    use std::sync::Arc;

    use arrow::array::{Array, BinaryBuilder, Int64Builder, ListBuilder};
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;
    use parquet::arrow::ArrowWriter;
    use parquet::file::properties::WriterProperties;

    /// Build a small GeoParquet fixture with known geometry null/set counts and
    /// known `node_refs` list contents, written across TWO row groups so the
    /// row-group-parallel counter actually partitions work.
    ///
    /// Layout (4 rows):
    ///   row0  geometry=b"AAA"  node_refs=[1,2,3]
    ///   row1  geometry=NULL    node_refs=[]        (empty list, valid)
    ///   row2  geometry=b"BB"   node_refs=[4,5]
    ///   row3  geometry=b"C"    node_refs=NULL      (null list)
    ///
    /// ⇒ rows=4, geom_set=3, geom_null=1, refs_nonempty=2, refs_total=5.
    fn write_fixture(path: &std::path::Path) {
        let mut gb = BinaryBuilder::new();
        gb.append_value(b"AAA");
        gb.append_null();
        gb.append_value(b"BB");
        gb.append_value(b"C");
        let geom = gb.finish();

        let mut lb = ListBuilder::new(Int64Builder::new());
        lb.values().append_value(1);
        lb.values().append_value(2);
        lb.values().append_value(3);
        lb.append(true); // row0 [1,2,3]
        lb.append(true); // row1 [] empty, valid
        lb.values().append_value(4);
        lb.values().append_value(5);
        lb.append(true); // row2 [4,5]
        lb.append(false); // row3 null list
        let refs = lb.finish();

        let schema = Schema::new(vec![
            Field::new("geometry", DataType::Binary, true),
            Field::new("node_refs", refs.data_type().clone(), true),
        ]);
        let batch =
            RecordBatch::try_new(Arc::new(schema), vec![Arc::new(geom), Arc::new(refs)]).unwrap();

        // Force 2 row groups (2 rows each) so count_node_refs partitions.
        let props = WriterProperties::builder()
            .set_max_row_group_row_count(Some(2))
            .build();
        let file = std::fs::File::create(path).unwrap();
        let mut w = ArrowWriter::try_new(file, batch.schema(), Some(props)).unwrap();
        w.write(&batch).unwrap();
        w.close().unwrap();
    }

    #[test]
    fn counts_geometry_and_node_refs_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.parquet");
        write_fixture(&path);

        let v = verify(&path).unwrap();
        assert_eq!(v.rows, 4, "rows");
        assert!(v.has_geom, "has_geom");
        assert_eq!(v.geom_set, 3, "geom_set");
        assert_eq!(v.geom_null, 1, "geom_null");
        assert!(v.has_refs, "has_refs");
        assert_eq!(v.refs_nonempty, 2, "refs_nonempty (rows with >0 refs)");
        assert_eq!(v.refs_total, 5, "refs_total (sum of all list lengths)");
    }

    #[test]
    fn absent_columns_report_zero() {
        // A parquet with neither `geometry` nor `node_refs`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bare.parquet");

        let mut ib = Int64Builder::new();
        ib.append_value(10);
        ib.append_value(20);
        let ids = ib.finish();
        let schema = Schema::new(vec![Field::new("id", DataType::Int64, false)]);
        let batch = RecordBatch::try_new(Arc::new(schema), vec![Arc::new(ids)]).unwrap();
        let file = std::fs::File::create(&path).unwrap();
        let mut w = ArrowWriter::try_new(file, batch.schema(), None).unwrap();
        w.write(&batch).unwrap();
        w.close().unwrap();

        let v = verify(&path).unwrap();
        assert_eq!(v.rows, 2, "rows");
        assert!(!v.has_geom, "has_geom must be false");
        assert!(!v.has_refs, "has_refs must be false");
        assert_eq!(v.geom_set, 0);
        assert_eq!(v.geom_null, 0);
        assert_eq!(v.refs_nonempty, 0);
        assert_eq!(v.refs_total, 0);
    }
}
