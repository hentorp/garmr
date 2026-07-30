//! Integration test for `osm-katana optimize` — the embed-shrink stage.
//!
//! Builds a realistic multi-row-group `nodes.parquet` + `ways.parquet`, runs the
//! public [`osm_katana::optimize`] (the 1→N→1 gatling), and asserts the output is:
//!   1. much smaller than the input,
//!   2. a valid two-column (`geometry` WKB + `tags` JSON) GeoParquet that
//!      `facett-osm::read_points` / `read_ways` can consume,
//!   3. named-POI-first under `--max-features`,
//!   4. produced with the cores-busy phase telemetry the gatling LAW requires.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use arrow::array::{
    Array, BinaryArray, BinaryBuilder, Int32Builder, Int64Builder, StringArray, StringBuilder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use osm_katana::{OptimizeOptions, optimize};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;

fn wkb_point(lon: f64, lat: f64) -> Vec<u8> {
    let mut b = vec![1u8];
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&lon.to_le_bytes());
    b.extend_from_slice(&lat.to_le_bytes());
    b
}

fn wkb_linestring(pts: &[(f64, f64)]) -> Vec<u8> {
    let mut b = vec![1u8];
    b.extend_from_slice(&2u32.to_le_bytes()); // LineString
    b.extend_from_slice(&(pts.len() as u32).to_le_bytes());
    for (lon, lat) in pts {
        b.extend_from_slice(&lon.to_le_bytes());
        b.extend_from_slice(&lat.to_le_bytes());
    }
    b
}

/// Write a `nodes.parquet` with `n` rows (`n_named` carrying a `name` POI tag),
/// many small row groups so the gatling fans across workers.
fn write_nodes(dir: &Path, n: usize, n_named: usize) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("geometry", DataType::Binary, true),
        Field::new("tags", DataType::Utf8, true),
        Field::new("version", DataType::Int32, true),
    ]));
    let mut id = Int64Builder::new();
    let mut geo = BinaryBuilder::new();
    let mut tag = StringBuilder::new();
    let mut ver = Int32Builder::new();
    for i in 0..n {
        id.append_value(i as i64);
        geo.append_value(&wkb_point(17.0 + i as f64 * 1e-4, 59.0 + i as f64 * 1e-5));
        if i < n_named {
            tag.append_value(&format!(
                "{{\"name\":\"poi{i}\",\"amenity\":\"cafe\",\"source\":\"survey\"}}"
            ));
        } else {
            tag.append_value("{\"created_by\":\"JOSM\"}");
        }
        ver.append_value(1);
    }
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(id.finish()),
            Arc::new(geo.finish()),
            Arc::new(tag.finish()),
            Arc::new(ver.finish()),
        ],
    )
    .unwrap();
    let props = WriterProperties::builder()
        .set_max_row_group_row_count(Some(256))
        .set_compression(Compression::ZSTD(Default::default()))
        .build();
    let mut w = ArrowWriter::try_new(
        File::create(dir.join("nodes.parquet")).unwrap(),
        schema,
        Some(props),
    )
    .unwrap();
    w.write(&batch).unwrap();
    w.close().unwrap();
}

fn write_ways(dir: &Path, n: usize) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("geometry", DataType::Binary, true),
        Field::new("tags", DataType::Utf8, true),
        Field::new("version", DataType::Int32, true),
    ]));
    let mut id = Int64Builder::new();
    let mut geo = BinaryBuilder::new();
    let mut tag = StringBuilder::new();
    let mut ver = Int32Builder::new();
    for i in 0..n {
        id.append_value(i as i64);
        let b = i as f64;
        geo.append_value(&wkb_linestring(&[
            (17.0 + b * 1e-4, 59.0),
            (17.001 + b * 1e-4, 59.001),
        ]));
        tag.append_value("{\"highway\":\"residential\",\"surface\":\"asphalt\"}");
        ver.append_value(1);
    }
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(id.finish()),
            Arc::new(geo.finish()),
            Arc::new(tag.finish()),
            Arc::new(ver.finish()),
        ],
    )
    .unwrap();
    let props = WriterProperties::builder()
        .set_max_row_group_row_count(Some(256))
        .set_compression(Compression::ZSTD(Default::default()))
        .build();
    let mut w = ArrowWriter::try_new(
        File::create(dir.join("ways.parquet")).unwrap(),
        schema,
        Some(props),
    )
    .unwrap();
    w.write(&batch).unwrap();
    w.close().unwrap();
}

/// Read the embed output back the way facett-osm does: a Binary `geometry` (WKB)
/// column + a Utf8 `tags` column.
fn read_embed(path: &Path) -> Vec<(u8, Option<String>)> {
    let rdr = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let mut out = Vec::new();
    for batch in rdr {
        let b = batch.unwrap();
        let g = b
            .column_by_name("geometry")
            .unwrap()
            .as_any()
            .downcast_ref::<BinaryArray>()
            .expect("facett contract: Binary geometry (WKB)");
        let t = b
            .column_by_name("tags")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("facett contract: Utf8 tags");
        for i in 0..b.num_rows() {
            let tag = if t.is_null(i) {
                None
            } else {
                Some(t.value(i).to_string())
            };
            out.push((g.value(i)[0], tag));
        }
    }
    out
}

#[test]
fn optimize_shrinks_and_keeps_named_first_facett_readable() {
    let dir = tempfile::tempdir().unwrap();
    write_nodes(dir.path(), 4000, 300);
    write_ways(dir.path(), 1000);

    let in_nodes = std::fs::metadata(dir.path().join("nodes.parquet"))
        .unwrap()
        .len();
    let in_ways = std::fs::metadata(dir.path().join("ways.parquet"))
        .unwrap()
        .len();

    let out = dir.path().join("embed.parquet");
    let log = dir.path().join("phases.jsonl");
    let opts = OptimizeOptions {
        output: out.clone(),
        points_only: false,
        include_ways: true,
        named_first: true,
        named_only: false,
        buildings: false,
        max_features: 500,
        compression: "zstd".into(),
        log_path: Some(log.clone()),
    };
    optimize(dir.path(), &opts).unwrap();

    // (1) much smaller than the (nodes + ways) input.
    let out_bytes = std::fs::metadata(&out).unwrap().len();
    assert!(
        out_bytes < (in_nodes + in_ways),
        "output {out_bytes} not smaller than input {}",
        in_nodes + in_ways
    );

    // (2) valid two-column WKB GeoParquet, capped at 500.
    let rows = read_embed(&out);
    assert_eq!(rows.len(), 500, "cap not applied");
    for (b0, _) in &rows {
        assert_eq!(*b0, 1u8, "WKB not little-endian");
    }

    // (3) named-first: the first 300 are the named nodes (carry a `name` tag);
    //     `source`/`created_by`/`surface` were pruned away.
    let named_in_first_300 = rows[..300]
        .iter()
        .filter(|(_, t)| {
            t.as_deref()
                .map(|s| s.contains("\"name\""))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(named_in_first_300, 300, "named features not ranked first");
    for (_, t) in &rows {
        if let Some(s) = t {
            assert!(!s.contains("source"), "non-whitelisted tag `source` leaked");
            assert!(!s.contains("created_by"), "`created_by` not pruned");
            assert!(!s.contains("surface"), "`surface` not pruned");
        }
    }

    // (4) cores-busy perf check: the gatling emitted phase telemetry with a
    //     cpu_cores / busy_pct field for the parallel process phase.
    let log_text = std::fs::read_to_string(&log).unwrap();
    assert!(
        log_text.contains("\"phase\":\"optimize.process\"")
            && log_text.contains("\"cpu_cores\":")
            && log_text.contains("\"busy_pct\":"),
        "gatling phase telemetry (cpu_cores / busy_pct) missing from phase log"
    );
    assert!(
        log_text.contains("\"workers\":"),
        "worker count not reported (parallel fan-out not exercised)"
    );
}

#[test]
fn optimize_points_only_named_only() {
    let dir = tempfile::tempdir().unwrap();
    write_nodes(dir.path(), 2000, 120);
    write_ways(dir.path(), 500); // present but must be ignored under --points-only

    let out = dir.path().join("named.parquet");
    let opts = OptimizeOptions {
        output: out.clone(),
        points_only: true,
        named_only: true,
        ..Default::default()
    };
    optimize(dir.path(), &opts).unwrap();

    let rows = read_embed(&out);
    // Only the 120 named NODE points; ways skipped (points_only), unnamed dropped.
    assert_eq!(rows.len(), 120, "points-only + named-only count wrong");
    for (b0, t) in &rows {
        assert_eq!(*b0, 1u8, "expected Point WKB");
        assert!(
            t.as_deref()
                .map(|s| s.contains("\"name\""))
                .unwrap_or(false),
            "named_only kept an unnamed feature"
        );
    }
}
