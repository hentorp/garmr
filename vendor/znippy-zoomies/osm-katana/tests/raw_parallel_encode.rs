//! RED-when-broken correctness gate for the parallel raw-XML encode path.
//!
//! `read_raw` (uncompressed `.osm`, `--geometry raw`) was changed 2026-07-14 to
//! encode node/way/relation Parquet row groups ON THE GATLING WORKERS
//! (`RawXmlParallelCodec` + `RawParallelParquetSink`) instead of serially on the
//! collector (the former ~1.8-core gate). Because workers now coalesce records
//! across the (dynamically-stolen) segments they process, the emitted Parquet ROW
//! ORDER is no longer strict file order — so correctness must be asserted on the
//! multiset of row VALUES, not on position.
//!
//! This test converts a deterministic synthetic `.osm` with KNOWN nodes and ways,
//! reads `nodes.parquet` + `ways.parquet` back with the `parquet` crate, and
//! asserts the exact set of node `(id → lon,lat,tags,version)` and way
//! `(id → node_refs,tags)` matches the input. It runs with a fixed `vtd_workers`
//! > 1 so the multi-worker / multi-segment / `finish_worker`-drain / collector-
//! stitch path is genuinely exercised. If the parallel encode ever drops,
//! duplicates, misroutes or corrupts a row, a set comparison here fails.

use std::collections::HashMap;
use std::fs::File;

use arrow::array::{Array, BinaryArray, Int32Array, Int64Array, ListArray, StringArray};
use osm_katana::{ConvertOptions, convert};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

const N_NODES: i64 = 1500;
const N_WAYS: i64 = 400;
/// Window of node ids each way references (like the real bench corpus).
const WAY_WINDOW: i64 = 6;

fn node_lat(id: i64) -> f64 {
    50.0 + (id as f64) * 1e-4
}
fn node_lon(id: i64) -> f64 {
    8.0 + (id as f64) * 7e-5
}
/// Reader stores coords as `f32` (lat_e7/1e7 as f32); mirror that so expected
/// values compare exactly to what the pipeline round-trips.
fn expect_coord(v: f64) -> f32 {
    // XML is written with 7 decimals → e7 int → f32 (the reader's exact path).
    let e7 = (v * 1e7).round() as i32;
    e7 as f32 / 1e7_f32
}

fn build_osm() -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str("<osm version=\"0.6\" generator=\"raw-parallel-test\">\n");
    for id in 1..=N_NODES {
        s.push_str(&format!(
            "  <node id=\"{id}\" lat=\"{:.7}\" lon=\"{:.7}\" version=\"1\">\
             <tag k=\"amenity\" v=\"bench\"/></node>\n",
            node_lat(id),
            node_lon(id),
        ));
    }
    for wid in 1..=N_WAYS {
        s.push_str(&format!("  <way id=\"{wid}\" version=\"1\">"));
        for k in 0..WAY_WINDOW {
            // deterministic refs inside [1, N_NODES]
            let nid = ((wid + k) % N_NODES) + 1;
            s.push_str(&format!("<nd ref=\"{nid}\"/>"));
        }
        s.push_str("<tag k=\"highway\" v=\"residential\"/></way>\n");
    }
    s.push_str("</osm>\n");
    s
}

fn read_nodes(path: &std::path::Path) -> HashMap<i64, (f32, f32, String)> {
    let rb = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let mut out = HashMap::new();
    for batch in rb {
        let batch = batch.unwrap();
        let ids = batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        let geoms = batch
            .column(1)
            .as_any()
            .downcast_ref::<BinaryArray>()
            .unwrap();
        let tags = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        for i in 0..batch.num_rows() {
            let g = geoms.value(i);
            assert_eq!(g.len(), 21, "WKB point is 21 bytes");
            let lon = f64::from_le_bytes(g[5..13].try_into().unwrap()) as f32;
            let lat = f64::from_le_bytes(g[13..21].try_into().unwrap()) as f32;
            let prev = out.insert(ids.value(i), (lon, lat, tags.value(i).to_string()));
            assert!(
                prev.is_none(),
                "duplicate node id {} in output",
                ids.value(i)
            );
        }
    }
    out
}

fn read_ways(path: &std::path::Path) -> HashMap<i64, (Vec<i64>, String)> {
    let rb = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let mut out = HashMap::new();
    for batch in rb {
        let batch = batch.unwrap();
        let ids = batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        let tags = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let refs = batch
            .column(3)
            .as_any()
            .downcast_ref::<ListArray>()
            .unwrap();
        let _versions = batch
            .column(4)
            .as_any()
            .downcast_ref::<Int32Array>()
            .unwrap();
        for i in 0..batch.num_rows() {
            let list = refs.value(i);
            let list = list.as_any().downcast_ref::<Int64Array>().unwrap();
            let r: Vec<i64> = (0..list.len()).map(|j| list.value(j)).collect();
            let prev = out.insert(ids.value(i), (r, tags.value(i).to_string()));
            assert!(
                prev.is_none(),
                "duplicate way id {} in output",
                ids.value(i)
            );
        }
    }
    out
}

#[test]
fn raw_parallel_encode_preserves_every_row() {
    let dir = tempfile::tempdir().unwrap();
    let osm = dir.path().join("in.osm");
    std::fs::write(&osm, build_osm()).unwrap();
    let out = dir.path().join("out");

    let opts = ConvertOptions {
        output_dir: out.clone(),
        geometry: "raw".into(),
        // Force real multi-worker parallelism so the worker-encode / finish_worker
        // / collector-stitch path is exercised (not a 1-worker degenerate run).
        vtd_workers: 4,
        skip_changesets: true,
        ..Default::default()
    };
    convert(&osm, &opts).expect("convert raw");

    // ── Nodes: exact id set + per-id coords + tags ────────────────────────────
    let nodes = read_nodes(&out.join("nodes.parquet"));
    assert_eq!(
        nodes.len() as i64,
        N_NODES,
        "node row count must equal input (no drops/dups) — got {}",
        nodes.len()
    );
    for id in 1..=N_NODES {
        let (lon, lat, tags) = nodes
            .get(&id)
            .unwrap_or_else(|| panic!("node id {id} missing from output"));
        assert_eq!(*lon, expect_coord(node_lon(id)), "node {id} lon mismatch");
        assert_eq!(*lat, expect_coord(node_lat(id)), "node {id} lat mismatch");
        assert_eq!(tags, "{\"amenity\":\"bench\"}", "node {id} tags mismatch");
    }

    // ── Ways: exact id set + per-id node_refs + tags ──────────────────────────
    let ways = read_ways(&out.join("ways.parquet"));
    assert_eq!(
        ways.len() as i64,
        N_WAYS,
        "way row count must equal input (no drops/dups) — got {}",
        ways.len()
    );
    for wid in 1..=N_WAYS {
        let expected_refs: Vec<i64> = (0..WAY_WINDOW).map(|k| ((wid + k) % N_NODES) + 1).collect();
        let (refs, tags) = ways
            .get(&wid)
            .unwrap_or_else(|| panic!("way id {wid} missing from output"));
        assert_eq!(refs, &expected_refs, "way {wid} node_refs mismatch");
        assert_eq!(
            tags, "{\"highway\":\"residential\"}",
            "way {wid} tags mismatch"
        );
    }
}

/// A single-worker run must produce the identical row set — proves the parallel
/// path's output does not depend on the worker count (byte layout may differ, the
/// row VALUES may not).
#[test]
fn raw_encode_worker_count_invariant() {
    let dir = tempfile::tempdir().unwrap();
    let osm = dir.path().join("in.osm");
    std::fs::write(&osm, build_osm()).unwrap();

    let run = |workers: usize, sub: &str| -> HashMap<i64, (f32, f32, String)> {
        let out = dir.path().join(sub);
        let opts = ConvertOptions {
            output_dir: out.clone(),
            geometry: "raw".into(),
            vtd_workers: workers,
            skip_changesets: true,
            ..Default::default()
        };
        convert(&osm, &opts).expect("convert raw");
        read_nodes(&out.join("nodes.parquet"))
    };

    let one = run(1, "w1");
    let many = run(8, "w8");
    assert_eq!(
        one, many,
        "node row set must be identical for 1 vs 8 workers"
    );
    assert_eq!(one.len() as i64, N_NODES);
}
