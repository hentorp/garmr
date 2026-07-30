//! nornir bencher entry point (the contract in `nornir::bench::api`).
//!
//! `cargo run --release --example nornir-bench` — or, end-to-end,
//! `nornir bench run nornir-catalog` from `workspace_nornir-catalog/` — prints
//! one `BenchRun` JSON line on stdout. nornir parses it, persists the run into
//! the `bench_runs` Iceberg table, and `nornir docs render nornir-catalog` folds
//! the results into `.nornir/README.md`'s `benches` regions → root `README.md`.
//!
//! Each `Bencher` produces one named `BenchResult`; the README sections filter by
//! result-name substring (`table_exists`; `skade_katalog_embedded` minus `table_exists`;
//! `data_pipe`; `commit_burst`). The result ids match the `required_results` in
//! `workspace_nornir-catalog/release/nornir.toml`. S3/Nessie/Polaris benchers need
//! their containers (`cargo run --bin bench-containers up all`); if a container is
//! down that bench degrades to a recorded failure, not a run abort.
//!
//! Env knobs: `NORNIR_BENCH_FULL=1` (10k-table read scale), `NORNIR_BENCH_TABLES`
//! / `NORNIR_BENCH_ITERS` (read scale), `BENCH_DATA_ROWS` / `BENCH_DATA_BATCH`
//! (data-pipe), `NORNIR_BURST_TABLES` / `NORNIR_BURST_COMMITS` (commit-burst),
//! `BENCH_REST_URI` (Nessie endpoint), `OSM_GEOPARQUET` / `OSM_MAX_ROWS`
//! (OSM GeoParquet ingest; the `osm_ingest_*` benchers skip-as-failure if unset).

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use iceberg::{Catalog, NamespaceIdent, TableIdent};
use serde_json::{json, Map, Value};

use nornir::bench::api::{run_main_json, Bencher};
use nornir::bench::BenchResult;
use nornir::register_bench;

use skade_katalog_bench::scenarios::{CatalogResult, Scale};
use skade_katalog_bench::{data, factory, pipeline, scenarios};
#[cfg(feature = "rest")]
use skade_katalog_bench::rest_shim;

fn main() -> Result<()> {
    run_main_json()
}

// ---- shared helpers --------------------------------------------------------

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

/// Read-latency scale: small + fast by default (latency is scale-insensitive);
/// `NORNIR_BENCH_FULL=1` uses the 10k-table headline scale.
fn read_scale() -> Scale {
    if std::env::var("NORNIR_BENCH_FULL").is_ok() {
        Scale::full()
    } else {
        Scale {
            tables: env_usize("NORNIR_BENCH_TABLES", 100),
            iters: env_usize("NORNIR_BENCH_ITERS", 2_000),
            threads: vec![],
        }
    }
}

fn bench(name: &str, metrics: Map<String, Value>) -> BenchResult {
    BenchResult::measured(name, metrics)
}

fn latency_metrics(r: &CatalogResult) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("ops_sec".into(), json!(r.ops_sec));
    m.insert("min_us".into(), json!(r.min_us));
    m.insert("mean_us".into(), json!(r.mean_us));
    m.insert("p50_us".into(), json!(r.p50_us));
    m.insert("p90_us".into(), json!(r.p90_us));
    m.insert("p99_us".into(), json!(r.p99_us));
    m.insert("p999_us".into(), json!(r.p999_us));
    m.insert("max_us".into(), json!(r.max_us));
    m
}

fn pctl_metrics(extra: &[(&str, f64)], mut samples_ns: Vec<u128>, wall_ns: u128) -> Map<String, Value> {
    samples_ns.sort_unstable();
    let ops = samples_ns.len() as u64;
    let pct = |q: f64| -> f64 {
        let idx = (((samples_ns.len().max(1) - 1) as f64) * q).round() as usize;
        samples_ns.get(idx).copied().unwrap_or(0) as f64 / 1000.0
    };
    let mean_us = if ops == 0 {
        0.0
    } else {
        (samples_ns.iter().sum::<u128>() as f64 / ops as f64) / 1000.0
    };
    let mut m = Map::new();
    for (k, v) in extra {
        m.insert((*k).to_string(), json!(v));
    }
    m.insert("ops_sec".into(), json!(if wall_ns > 0 { ops as f64 * 1e9 / wall_ns as f64 } else { 0.0 }));
    m.insert("min_us".into(), json!(samples_ns.first().copied().unwrap_or(0) as f64 / 1000.0));
    m.insert("mean_us".into(), json!(mean_us));
    m.insert("p50_us".into(), json!(pct(0.50)));
    m.insert("p90_us".into(), json!(pct(0.90)));
    m.insert("p99_us".into(), json!(pct(0.99)));
    m.insert("p999_us".into(), json!(pct(0.999)));
    m.insert("max_us".into(), json!(samples_ns.last().copied().unwrap_or(0) as f64 / 1000.0));
    m
}

// ---- data-pipe / commit-burst cores (reused across targets) ----------------

/// `write_concurrency`: 1 → the single-writer-sequential path (optimal for local
/// NVMe/RAM where a write is a memcpy-class syscall). >1 → the GATLING-style
/// concurrent multi-PUT path (`run_concurrent_writer_ingest`, N PUTs in flight)
/// to hide S3/network per-request latency. The S3/Nessie benchers pass
/// `BENCH_PIPE_WRITE_CONCURRENCY` (default 16); local passes 1.
async fn data_pipe_metrics(cat: Arc<dyn Catalog>, write_concurrency: usize) -> Result<Map<String, Value>> {
    let rows = env_usize("BENCH_DATA_ROWS", 500_000);
    let per_batch = env_usize("BENCH_DATA_BATCH", 50_000);
    let ns = NamespaceIdent::new("bench".to_string());
    if !cat.namespace_exists(&ns).await.unwrap_or(false) {
        cat.create_namespace(&ns, Default::default()).await?;
    }
    let ident = TableIdent::new(ns.clone(), "osm_nodes_pipe".to_string());
    if cat.table_exists(&ident).await.unwrap_or(false) {
        let _ = cat.drop_table(&ident).await;
    }
    let table = data::create_node_table(cat.as_ref(), &ident).await?;
    let schema = data::node_arrow_schema_standalone()?;
    let groups: Vec<Vec<_>> = data::synthetic_batches(schema.clone(), rows, per_batch)
        .into_iter()
        .map(|b| vec![b])
        .collect();
    let (table, stats) = if write_concurrency > 1 {
        pipeline::run_concurrent_writer_ingest(Arc::clone(&cat), table, groups, schema, 8, 8, "pipe", write_concurrency).await?
    } else {
        pipeline::run_single_writer_ingest(Arc::clone(&cat), table, groups, schema, 8, 8, "pipe").await?
    };
    let (scanned, _) = data::scan_count(&table).await?;
    anyhow::ensure!(scanned == stats.rows, "scan mismatch: {} != {}", scanned, stats.rows);
    let mut m = Map::new();
    m.insert("rows_per_sec".into(), json!(stats.rows_per_sec()));
    m.insert("files".into(), json!(stats.files as f64));
    m.insert("commits".into(), json!(stats.commits as f64));
    m.insert("encode_workers".into(), json!(stats.encode_workers as f64));
    m.insert("write_concurrency".into(), json!(stats.write_concurrency as f64));
    m.insert("peak_inflight".into(), json!(stats.peak_inflight as f64));
    Ok(m)
}

/// Concurrent-write level for S3/network targets (GATLING multi-PUT). Local
/// targets pass 1 (sequential is optimal there).
fn s3_write_concurrency() -> usize {
    env_usize("BENCH_PIPE_WRITE_CONCURRENCY", 16).max(1)
}

async fn commit_burst_metrics(cat: Arc<dyn Catalog>) -> Result<Map<String, Value>> {
    use iceberg::transaction::{ApplyTransactionAction, Transaction};
    let tables = env_usize("NORNIR_BURST_TABLES", 32);
    let per_table = env_usize("NORNIR_BURST_COMMITS", 100);
    let ns = NamespaceIdent::new("burst".to_string());
    if !cat.namespace_exists(&ns).await.unwrap_or(false) {
        cat.create_namespace(&ns, Default::default()).await?;
    }
    let mut tabs = Vec::with_capacity(tables);
    for t in 0..tables {
        let ident = TableIdent::new(ns.clone(), format!("burst_{t:03}"));
        if cat.table_exists(&ident).await.unwrap_or(false) {
            let _ = cat.drop_table(&ident).await;
        }
        tabs.push(data::create_node_table(cat.as_ref(), &ident).await?);
    }
    let wall = Instant::now();
    let mut handles = Vec::with_capacity(tables);
    for table in tabs {
        let cat = Arc::clone(&cat);
        handles.push(tokio::spawn(async move {
            let mut table = table;
            let mut lat = Vec::with_capacity(per_table);
            for i in 0..per_table {
                let tx = Transaction::new(&table);
                let action = tx.update_table_properties().set("bench.seq".to_string(), i.to_string());
                let tx = action.apply(tx)?;
                let t0 = Instant::now();
                table = tx.commit(cat.as_ref()).await?;
                lat.push(t0.elapsed().as_nanos());
            }
            Ok::<Vec<u128>, anyhow::Error>(lat)
        }));
    }
    let mut all: Vec<u128> = Vec::new();
    for h in handles {
        all.extend(h.await??);
    }
    let secs = wall.elapsed().as_secs_f64().max(1e-9);
    let commits = all.len() as f64;
    Ok(pctl_metrics(&[("commits_per_sec", commits / secs)], all, wall.elapsed().as_nanos()))
}

// ---- embedded read scenarios ----------------------------------------------

struct EmbeddedTableExists;
impl Bencher for EmbeddedTableExists {
    fn id(&self) -> &'static str { "skade_katalog_embedded_table_exists" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let sc = read_scale();
            let (cat, _tmp) = factory::embedded().await?;
            let ns = scenarios::seed(&cat, &sc).await?;
            let r = scenarios::table_exists_latency(&cat, &ns, &sc).await;
            Ok(bench(self.id(), latency_metrics(&r)))
        })
    }
}
register_bench!(EmbeddedTableExists);

struct EmbeddedResolveMetadata;
impl Bencher for EmbeddedResolveMetadata {
    fn id(&self) -> &'static str { "skade_katalog_embedded_resolve_metadata" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let sc = read_scale();
            let (cat, _tmp) = factory::embedded().await?;
            let ns = scenarios::seed(&cat, &sc).await?;
            let n = sc.tables.max(1);
            for i in 0..100 {
                let _ = cat
                    .resolve_metadata(&TableIdent::new(ns.clone(), format!("bench_t_{:06}", i % n)))
                    .await;
            }
            let mut samples = Vec::with_capacity(sc.iters);
            let wall = Instant::now();
            for i in 0..sc.iters {
                let ident = TableIdent::new(ns.clone(), format!("bench_t_{:06}", i % n));
                let t = Instant::now();
                let _ = cat.resolve_metadata(&ident).await;
                samples.push(t.elapsed().as_nanos());
            }
            Ok(bench(self.id(), pctl_metrics(&[], samples, wall.elapsed().as_nanos())))
        })
    }
}
register_bench!(EmbeddedResolveMetadata);

struct EmbeddedLoadTable;
impl Bencher for EmbeddedLoadTable {
    fn id(&self) -> &'static str { "skade_katalog_embedded_load_table" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let sc = read_scale();
            let (cat, _tmp) = factory::embedded().await?;
            let ns = scenarios::seed(&cat, &sc).await?;
            let r = scenarios::load_table_latency(&cat, &ns, &sc).await;
            Ok(bench(self.id(), latency_metrics(&r)))
        })
    }
}
register_bench!(EmbeddedLoadTable);

// ---- static capabilities (issue #13 seam) ----------------------------------
// The front-page competitive matrix (skade vs Iceberg-Java / PyIceberg / Delta)
// emitted as a `BenchSource::Static` row — NOT a timed measurement. It carries
// the ✓/✗/◐/NA matrix as numeric coverage codes (see
// `skade_katalog_bench::capabilities`), tagged Static so the warehouse persists
// it and the no-regression gate skips it. The same matrix definition renders the
// README-full capability table, so the two can't drift.

struct SkadeCapabilities;
impl Bencher for SkadeCapabilities {
    fn id(&self) -> &'static str { skade_katalog_bench::capabilities::RESULT_NAME }
    fn run(&self) -> Result<BenchResult> {
        Ok(BenchResult::static_capabilities(
            self.id(),
            skade_katalog_bench::capabilities::numeric_metrics(),
        ))
    }
}
register_bench!(SkadeCapabilities);

// ---- catalog-key micro-bench (in-proc, no containers/S3) -------------------
// Times the redb key builders (`keys::{table_key,namespace_key,table_prefix}`) —
// the `pub(crate)` hot-path fns reached out-of-crate via skade-katalog's `bench`
// feature hook (`skade_katalog::bench_keys`). Every commit + every catalog op
// builds one of these keys; the zero-copy rewrite (one pre-sized alloc vs
// clone+join+`format!`) is byte-identical and ~8-10× on this box. A LIGHT,
// pure-in-proc run; the heavy N sweep goes to the quiet bench box via
// `BENCH_CATALOG_KEY_ITERS` (Loki/Odin). See `.nornir/catalog-key-zerocopy.md`.
struct CatalogKeyBuild;
impl Bencher for CatalogKeyBuild {
    fn id(&self) -> &'static str { "skade_catalog_key_build" }
    fn run(&self) -> Result<BenchResult> {
        use std::hint::black_box;
        use iceberg::{NamespaceIdent, TableIdent};
        use skade_katalog::bench_keys;

        let n = env_usize("BENCH_CATALOG_KEY_ITERS", 500_000);
        let ns = NamespaceIdent::from_strs(["analytics", "warehouse"])
            .expect("namespace ident");
        let tbl = TableIdent::new(ns.clone(), "orders".to_string());

        // Batched timing: a key build is a ~30ns op, so per-iteration
        // `Instant::now()` overhead would swamp it — time the whole loop and
        // divide. `black_box` keeps the builder (and its alloc) from being
        // elided; the running `sink` pins the result live.
        let mut sink = 0usize;
        let warm = (n / 10).max(1);
        let mut time_ns = |f: &dyn Fn() -> String| -> f64 {
            for _ in 0..warm {
                sink = sink.wrapping_add(black_box(f()).len());
            }
            let t = Instant::now();
            for _ in 0..n {
                sink = sink.wrapping_add(black_box(f()).len());
            }
            t.elapsed().as_nanos() as f64 / n as f64
        };

        let table_key_ns = time_ns(&|| bench_keys::table_key("my_catalog", &tbl));
        let namespace_key_ns = time_ns(&|| bench_keys::namespace_key("my_catalog", &ns));
        let table_prefix_ns = time_ns(&|| bench_keys::table_prefix("my_catalog", &ns));

        let mut m = Map::new();
        // `ops_sec` keyed off the headline builder (`table_key`, one per commit)
        // so the warehouse no-regression gate has a single throughput number.
        m.insert("ops_sec".into(), json!(if table_key_ns > 0.0 { 1e9 / table_key_ns } else { 0.0 }));
        m.insert("table_key_ns_per_op".into(), json!(table_key_ns));
        m.insert("namespace_key_ns_per_op".into(), json!(namespace_key_ns));
        m.insert("table_prefix_ns_per_op".into(), json!(table_prefix_ns));
        m.insert("iters".into(), json!(n as f64));
        // Keep the accumulator observable so the optimizer can't drop the loops.
        m.insert("_sink".into(), json!(sink as f64));
        Ok(bench(self.id(), m))
    }
}
register_bench!(CatalogKeyBuild);

// ---- spatial radius micro-bench (in-proc, no containers/S3) ----------------
// Times `GeoIndex::query_radius` over a synthetic point cloud — the OSM/GeoParquet
// nearest-features hot path. The candidate walk now carries each point's coords
// straight from the covering cells, so a k-hit radius is O(k) instead of the old
// O(k·n) `entries.iter().find(id)` re-scan (byte-identical result set — guarded
// by `skade/tests/spatial.rs::radius_matches_brute_force_after_zero_copy_rewrite`).
// LIGHT by default; the heavy N sweep goes to the quiet bench box via
// `BENCH_SPATIAL_POINTS` / `BENCH_SPATIAL_QUERIES` (Loki/Odin).
struct SpatialRadiusQuery;
impl Bencher for SpatialRadiusQuery {
    fn id(&self) -> &'static str { "skade_spatial_radius" }
    fn run(&self) -> Result<BenchResult> {
        use std::hint::black_box;
        use skade::spatial::GeoIndex;

        let points = env_usize("BENCH_SPATIAL_POINTS", 50_000);
        let queries = env_usize("BENCH_SPATIAL_QUERIES", 2_000);

        // Deterministic pseudo-random cloud (same integer recurrence as the
        // spatial tests) so the bench is byte-stable run to run.
        let mut idx = GeoIndex::new(9);
        for i in 0..points as u64 {
            let lat = -80.0 + (i as f64 * 0.017) % 160.0;
            let lon = -175.0 + (i as f64 * 0.031) % 350.0;
            idx.insert(lat, lon, i);
        }
        idx.build();

        // A tight radius: touches a small candidate set, so a per-candidate O(n)
        // re-find (the old code) would dominate — this bench pins that cost.
        let radius_m = 25_000.0;
        let query_at = |q: usize| -> (f64, f64) {
            let lat = -70.0 + (q as f64 * 3.7).rem_euclid(140.0);
            let lon = -170.0 + (q as f64 * 5.9).rem_euclid(340.0);
            (lat, lon)
        };

        let warm = (queries / 10).max(1);
        let mut sink = 0usize;
        for q in 0..warm {
            let (la, lo) = query_at(q);
            sink = sink.wrapping_add(black_box(idx.query_radius(la, lo, radius_m)).len());
        }
        let t = Instant::now();
        for q in 0..queries {
            let (la, lo) = query_at(q);
            sink = sink.wrapping_add(black_box(idx.query_radius(la, lo, radius_m)).len());
        }
        let ns_per_query = t.elapsed().as_nanos() as f64 / queries.max(1) as f64;

        let mut m = Map::new();
        m.insert("ops_sec".into(), json!(if ns_per_query > 0.0 { 1e9 / ns_per_query } else { 0.0 }));
        m.insert("ns_per_query".into(), json!(ns_per_query));
        m.insert("points".into(), json!(points as f64));
        m.insert("queries".into(), json!(queries as f64));
        m.insert("radius_m".into(), json!(radius_m));
        m.insert("_sink".into(), json!(sink as f64));
        Ok(bench(self.id(), m))
    }
}
register_bench!(SpatialRadiusQuery);

// ---- git-like refs micro-bench (in-proc embedded, no containers/S3) --------
// Times the git-like catalog surface (`src/git.rs`): the lock-free ref-read hot
// path (`ref_snapshot_id`, `list_refs`) over a table carrying a linear snapshot
// history and many branches/tags, plus the ref-move write path (`fast_forward`
// / `rollback_to` alternation — one redb commit + fsync each). Reads route
// through the same L1 pointer mirror + L0 metadata cache as `resolve_metadata`,
// so a warm ref lookup is a metadata-map read, not a redb hit. LIGHT by default;
// the heavy sweep goes to the quiet bench box via `BENCH_GIT_REFS` (refs seeded)
// / `BENCH_GIT_READ_ITERS` / `BENCH_GIT_WRITE_ITERS` (Loki/Odin).
// See `.nornir/git-refs-design.md`.
struct GitRefOps;
impl GitRefOps {
    // A synthetic append-snapshot on a ref, through the normal commit_table path.
    async fn append(
        cat: &skade_katalog::RedbCatalog,
        ident: &TableIdent,
        ref_name: &str,
        snapshot_id: i64,
        parent: Option<i64>,
        seq: i64,
    ) -> Result<()> {
        use iceberg::spec::{Operation, Snapshot, SnapshotReference, SnapshotRetention, Summary};
        use iceberg::TableUpdate;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let snap = Snapshot::builder()
            .with_snapshot_id(snapshot_id)
            .with_parent_snapshot_id(parent)
            .with_sequence_number(seq)
            .with_timestamp_ms(now_ms + seq)
            .with_manifest_list(format!("file:///dev/null/m-{snapshot_id}.avro"))
            .with_schema_id(0)
            .with_summary(Summary {
                operation: Operation::Append,
                additional_properties: std::collections::HashMap::new(),
            })
            .build();
        let updates = vec![
            TableUpdate::AddSnapshot { snapshot: snap },
            TableUpdate::SetSnapshotRef {
                ref_name: ref_name.to_string(),
                reference: SnapshotReference::new(
                    snapshot_id,
                    SnapshotRetention::Branch {
                        min_snapshots_to_keep: None,
                        max_snapshot_age_ms: None,
                        max_ref_age_ms: None,
                    },
                ),
            },
        ];
        cat.commit_table(ident.clone(), vec![], updates).await?;
        Ok(())
    }
}
impl Bencher for GitRefOps {
    fn id(&self) -> &'static str { "skade_git_refs" }
    fn run(&self) -> Result<BenchResult> {
        use std::hint::black_box;
        use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};

        let n_refs = env_usize("BENCH_GIT_REFS", 256);
        let read_iters = env_usize("BENCH_GIT_READ_ITERS", 500_000);
        let write_iters = env_usize("BENCH_GIT_WRITE_ITERS", 2_000);

        rt().block_on(async move {
            let (cat, _tmp) = factory::embedded().await?;
            let ns = NamespaceIdent::new("git".to_string());
            cat.create_namespace(&ns, Default::default()).await?;
            let schema = Schema::builder()
                .with_schema_id(0)
                .with_fields(vec![
                    NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
                ])
                .build()?;
            let creation = iceberg::TableCreation::builder()
                .name("t".to_string())
                .schema(schema)
                .build();
            cat.create_table(&ns, creation).await?;
            let ident = TableIdent::new(ns, "t".to_string());

            // Linear snapshot history 1000..1000+depth on main.
            let depth: i64 = 64;
            let mut parent = None;
            for i in 0..depth {
                let sid = 1000 + i;
                Self::append(&cat, &ident, "main", sid, parent, i + 1).await?;
                parent = Some(sid);
            }
            let head = 1000 + depth - 1;

            // Seed n_refs branches + tags pinned across the history.
            let ref_names: Vec<String> = (0..n_refs)
                .map(|i| if i % 2 == 0 { format!("branch_{i:05}") } else { format!("tag_{i:05}") })
                .collect();
            for (i, name) in ref_names.iter().enumerate() {
                let sid = 1000 + (i as i64 % depth);
                if i % 2 == 0 {
                    cat.create_branch(&ident, name, Some(sid), skade_katalog::BranchRetention::default()).await?;
                } else {
                    cat.create_tag(&ident, name, Some(sid), None).await?;
                }
            }

            // ---- READ hot path: ref_snapshot_id resolution (lock-free) --------
            let warm = (read_iters / 10).max(1);
            let mut sink: i64 = 0;
            for i in 0..warm {
                let name = &ref_names[i % ref_names.len()];
                sink = sink.wrapping_add(black_box(cat.ref_snapshot_id(&ident, name).await?).unwrap_or(0));
            }
            let t = Instant::now();
            for i in 0..read_iters {
                let name = &ref_names[i % ref_names.len()];
                sink = sink.wrapping_add(black_box(cat.ref_snapshot_id(&ident, name).await?).unwrap_or(0));
            }
            let ref_read_ns = t.elapsed().as_nanos() as f64 / read_iters.max(1) as f64;

            // ---- READ: list_refs (build + sort the whole refs map) ------------
            let list_warm = (read_iters / 100).max(1);
            for _ in 0..list_warm {
                sink = sink.wrapping_add(black_box(cat.list_refs(&ident).await?).len() as i64);
            }
            let list_n = (read_iters / 50).max(1);
            let t2 = Instant::now();
            for _ in 0..list_n {
                sink = sink.wrapping_add(black_box(cat.list_refs(&ident).await?).len() as i64);
            }
            let list_refs_ns = t2.elapsed().as_nanos() as f64 / list_n as f64;

            // ---- WRITE path: ref-move commits ---------------------------------
            // Each iteration is two redb commits (fsync each) through
            // commit_table: create a tag then drop it. Measures the git ref
            // mutation throughput (the WAP/branch-lifecycle write cost).
            let _ = head;
            let w = Instant::now();
            for i in 0..write_iters {
                let sid = 1000 + (i as i64 % depth);
                cat.create_tag(&ident, "churn", Some(sid), None).await?;
                cat.drop_ref(&ident, "churn").await?;
            }
            let write_wall = w.elapsed().as_secs_f64().max(1e-9);
            let ref_writes_per_sec = (write_iters as f64 * 2.0) / write_wall;

            let mut m = Map::new();
            // Headline throughput: the lock-free ref read (the git read surface).
            m.insert("ops_sec".into(), json!(if ref_read_ns > 0.0 { 1e9 / ref_read_ns } else { 0.0 }));
            m.insert("ref_read_ns_per_op".into(), json!(ref_read_ns));
            m.insert("list_refs_ns_per_op".into(), json!(list_refs_ns));
            m.insert("ref_writes_per_sec".into(), json!(ref_writes_per_sec));
            m.insert("refs_seeded".into(), json!(n_refs as f64));
            m.insert("history_depth".into(), json!(depth as f64));
            m.insert("read_iters".into(), json!(read_iters as f64));
            m.insert("write_iters".into(), json!(write_iters as f64));
            m.insert("_sink".into(), json!(sink as f64));
            Ok(bench(self.id(), m))
        })
    }
}
register_bench!(GitRefOps);

// ---- nornir-rest (in-proc axum shim, no container) -------------------------

#[cfg(feature = "rest")]
struct RestTableExists;
#[cfg(feature = "rest")]
impl Bencher for RestTableExists {
    fn id(&self) -> &'static str { "skade_katalog_rest_table_exists" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let sc = read_scale();
            let (cat, _tmp) = factory::embedded().await?;
            let bound = rest_shim::spawn(cat, "127.0.0.1:0".parse().unwrap()).await?;
            let rest = factory::rest(&format!("http://{bound}"), "warehouse").await?;
            let ns = scenarios::seed(&rest, &sc).await?;
            let r = scenarios::table_exists_latency(&rest, &ns, &sc).await;
            Ok(bench(self.id(), latency_metrics(&r)))
        })
    }
}
#[cfg(feature = "rest")]
register_bench!(RestTableExists);

// ---- Nessie (needs RustFS + Nessie containers) -----------------------------

#[cfg(feature = "rest")]
fn nessie_uri() -> String {
    std::env::var("BENCH_REST_URI").unwrap_or_else(|_| "http://localhost:19120/iceberg".to_string())
}

#[cfg(feature = "rest")]
struct NessieTableExists;
#[cfg(feature = "rest")]
impl Bencher for NessieTableExists {
    fn id(&self) -> &'static str { "nessie_table_exists" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let sc = read_scale();
            let rest = factory::rest_s3(&nessie_uri(), "warehouse").await?;
            let ns = scenarios::seed(&rest, &sc).await?;
            let r = scenarios::table_exists_latency(&rest, &ns, &sc).await;
            Ok(bench(self.id(), latency_metrics(&r)))
        })
    }
}
#[cfg(feature = "rest")]
register_bench!(NessieTableExists);

// ---- Polaris (control-plane only: table_exists; needs the Polaris container) -

#[cfg(feature = "rest")]
struct PolarisTableExists;
#[cfg(feature = "rest")]
impl Bencher for PolarisTableExists {
    fn id(&self) -> &'static str { "polaris_table_exists" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let sc = read_scale();
            let uri = std::env::var("BENCH_POLARIS_URI")
                .unwrap_or_else(|_| "http://localhost:8181/api/catalog".to_string());
            let rest = factory::rest_polaris(&uri).await?;
            // Storage-free RPC: just the namespace; tables aren't created (the
            // Polaris FILE warehouse 503s under a bind mount), so this times the
            // exists-RPC round-trip, the apples-to-apples comparable.
            let ns = scenarios::seed_namespace(&rest).await?;
            let r = scenarios::table_exists_latency(&rest, &ns, &sc).await;
            Ok(bench(self.id(), latency_metrics(&r)))
        })
    }
}
#[cfg(feature = "rest")]
register_bench!(PolarisTableExists);

// ---- data-pipe across targets ----------------------------------------------

// Two file destinations for the local-FS data plane: NVMe (/path/to/scratch)
// and RAM (/dev/shm). Both run the identical pipeline; the gap is pure storage.
struct DataPipeNornirNvme;
impl Bencher for DataPipeNornirNvme {
    fn id(&self) -> &'static str { "data_pipe_skade_nvme" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let (cat, _tmp) = factory::embedded().await?;
            Ok(bench(self.id(), data_pipe_metrics(Arc::new(cat), 1).await?))
        })
    }
}
register_bench!(DataPipeNornirNvme);

struct DataPipeNornirRam;
impl Bencher for DataPipeNornirRam {
    fn id(&self) -> &'static str { "data_pipe_skade_ram" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let tmp = factory::tempdir_in(&factory::ram_dir())?;
            let cat = factory::embedded_in(&tmp).await?;
            Ok(bench(self.id(), data_pipe_metrics(Arc::new(cat), 1).await?))
        })
    }
}
register_bench!(DataPipeNornirRam);

struct DataPipeNornirS3;
impl Bencher for DataPipeNornirS3 {
    fn id(&self) -> &'static str { "data_pipe_skade_s3" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let (cat, _tmp) = factory::embedded_s3().await?;
            Ok(bench(self.id(), data_pipe_metrics(Arc::new(cat), s3_write_concurrency()).await?))
        })
    }
}
register_bench!(DataPipeNornirS3);

#[cfg(feature = "rest")]
struct DataPipeNessie;
#[cfg(feature = "rest")]
impl Bencher for DataPipeNessie {
    fn id(&self) -> &'static str { "data_pipe_nessie" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let rest = factory::rest_s3(&nessie_uri(), "warehouse").await?;
            Ok(bench(self.id(), data_pipe_metrics(Arc::new(rest), s3_write_concurrency()).await?))
        })
    }
}
#[cfg(feature = "rest")]
register_bench!(DataPipeNessie);

#[cfg(feature = "rest")]
struct DataPipePolaris;
#[cfg(feature = "rest")]
impl Bencher for DataPipePolaris {
    fn id(&self) -> &'static str { "data_pipe_polaris" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            // Polaris serves a FILE warehouse end-to-end (its S3 vending 301s on
            // RustFS — see TpchPolarisFile), so the full create→ingest→scan pipe
            // runs through the REST control plane just like Nessie does.
            let uri = std::env::var("BENCH_POLARIS_URI")
                .unwrap_or_else(|_| "http://localhost:8181/api/catalog".to_string());
            let rest = factory::rest_polaris(&uri).await?;
            Ok(bench(self.id(), data_pipe_metrics(Arc::new(rest), s3_write_concurrency()).await?))
        })
    }
}
#[cfg(feature = "rest")]
register_bench!(DataPipePolaris);

// ---- OSM GeoParquet ingest --------------------------------------------------
// Ingest a real `nodes.parquet` (OSM nodes converted to GeoParquet by the
// `katana-osm` / `osm2geoparquet` project) into a fresh RedbCatalog Iceberg
// table via the single-writer pipeline, then scan it back to verify. Unlike the
// synthetic `data_pipe_*` benchers this measures end-to-end ingest of authentic
// OSM data (id/geometry-WKB/tags-JSON/version/changeset/timestamp). Point
// `OSM_GEOPARQUET` at the file; `OSM_MAX_ROWS` caps rows (default: all).

fn osm_geoparquet_path() -> Option<String> {
    std::env::var("OSM_GEOPARQUET").ok().filter(|s| !s.is_empty())
}

async fn geoparquet_ingest_metrics(cat: Arc<dyn Catalog>, path: &str) -> Result<Map<String, Value>> {
    let max_rows = env_usize("OSM_MAX_ROWS", usize::MAX);
    let per_batch = env_usize("BENCH_DATA_BATCH", 1_000_000);
    // Stream the file in row-group windows of ~this many rows so peak memory is
    // one window, not the whole file — lets us ingest all 3.75B Europe nodes
    // (~290GB) without OOM. Default 50M ≈ a few GB resident.
    let window_rows = env_usize("OSM_WINDOW_ROWS", 50_000_000);
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);

    // Layout only (no data read yet): derive the Iceberg schema + per-row-group
    // sizes so we can window the file.
    let (ice, _file_schema, rg_rows) = data::parquet_layout(path)?;
    let windows = data::rowgroup_windows(&rg_rows, window_rows, max_rows);
    anyhow::ensure!(!windows.is_empty(), "no row groups in {path}");

    let ns = NamespaceIdent::new("bench".to_string());
    if !cat.namespace_exists(&ns).await.unwrap_or(false) {
        cat.create_namespace(&ns, Default::default()).await?;
    }
    let ident = TableIdent::new(ns.clone(), "osm_geoparquet".to_string());
    if cat.table_exists(&ident).await.unwrap_or(false) {
        let _ = cat.drop_table(&ident).await;
    }
    let creation = iceberg::TableCreation::builder()
        .name("osm_geoparquet".to_string())
        .schema(ice)
        .build();
    let mut table = cat.create_table(&ns, creation).await?;
    let target = data::table_arrow_schema(&table)?;

    // Stream: read one window of row groups (parallel) → recast → ingest+commit →
    // free → next. Time the whole read+write end-to-end (decode is real work).
    let t0 = Instant::now();
    let mut total_rows = 0u64;
    let mut total_files = 0u64;
    let mut total_commits = 0u64;
    let mut total_bytes = 0u64;
    let mut read_ns: u128 = 0;
    let mut encode_workers = 0u64;
    let nwin = windows.len();
    for (wi, rgs) in windows.into_iter().enumerate() {
        let tr = Instant::now();
        let src = data::read_row_groups(path, &rgs, per_batch, threads)?;
        read_ns += tr.elapsed().as_nanos();
        if src.is_empty() {
            continue;
        }
        let groups: Vec<Vec<_>> = data::recast(&src, target.clone())?.into_iter().map(|b| vec![b]).collect();
        drop(src);
        // Per-window prefix so file names are unique across windows (each call
        // restarts the pipeline's seq at 0; without this they'd collide).
        let prefix = format!("w{wi:04}");
        let (t2, stats) =
            pipeline::run_single_writer_ingest(Arc::clone(&cat), table, groups, target.clone(), 8, 8, &prefix).await?;
        table = t2;
        total_rows += stats.rows;
        total_files += stats.files;
        total_commits += stats.commits;
        total_bytes += stats.bytes_written;
        encode_workers = stats.encode_workers as u64;
        eprintln!("  osm window {}/{}: +{} rows ({} total)", wi + 1, nwin, stats.rows, total_rows);
    }
    anyhow::ensure!(total_rows > 0, "no rows ingested from {path}");

    // scan_count streams (folds row counts over the arrow stream), so verifying
    // the whole table back stays memory-bounded too.
    let (scanned, _) = data::scan_count(&table).await?;
    anyhow::ensure!(scanned == total_rows, "scan mismatch: {} != {}", scanned, total_rows);

    let e2e_s = t0.elapsed().as_secs_f64().max(1e-9);
    let read_s = (read_ns as f64 / 1e9).max(1e-9);
    let write_s = (e2e_s - read_s).max(1e-9);
    let rows = total_rows as f64;
    let mut m = Map::new();
    // Headline = end-to-end (read source → committed in the lake). Read vs write
    // split out so the catalog speed isn't masked by decode.
    m.insert("rows_per_sec".into(), json!(rows / e2e_s));
    m.insert("write_rows_per_sec".into(), json!(rows / write_s));
    m.insert("read_rows_per_sec".into(), json!(rows / read_s));
    m.insert("rows".into(), json!(rows));
    m.insert("windows".into(), json!(nwin as f64));
    m.insert("mb_per_sec".into(), json!(total_bytes as f64 / 1e6 / write_s));
    m.insert("read_threads".into(), json!(threads as f64));
    m.insert("files".into(), json!(total_files as f64));
    m.insert("commits".into(), json!(total_commits as f64));
    m.insert("encode_workers".into(), json!(encode_workers as f64));
    Ok(m)
}

struct OsmIngestNornirNvme;
impl Bencher for OsmIngestNornirNvme {
    fn id(&self) -> &'static str { "osm_ingest_skade_nvme" }
    fn run(&self) -> Result<BenchResult> {
        let path = osm_geoparquet_path().ok_or_else(|| {
            anyhow::anyhow!("set OSM_GEOPARQUET=/path/to/nodes.parquet (katana-osm osm2geoparquet output)")
        })?;
        rt().block_on(async {
            let (cat, _tmp) = factory::embedded().await?;
            Ok(bench(self.id(), geoparquet_ingest_metrics(Arc::new(cat), &path).await?))
        })
    }
}
register_bench!(OsmIngestNornirNvme);

struct OsmIngestNornirRam;
impl Bencher for OsmIngestNornirRam {
    fn id(&self) -> &'static str { "osm_ingest_skade_ram" }
    fn run(&self) -> Result<BenchResult> {
        let path = osm_geoparquet_path().ok_or_else(|| {
            anyhow::anyhow!("set OSM_GEOPARQUET=/path/to/nodes.parquet (katana-osm osm2geoparquet output)")
        })?;
        rt().block_on(async {
            let tmp = factory::tempdir_in(&factory::ram_dir())?;
            let cat = factory::embedded_in(&tmp).await?;
            Ok(bench(self.id(), geoparquet_ingest_metrics(Arc::new(cat), &path).await?))
        })
    }
}
register_bench!(OsmIngestNornirRam);

// ---- zstd decode: zstd-sys-rs (zero-copy) vs the `zstd` crate ----------------
// Both call the SAME statically-linked libzstd 1.5.7, so this validates the
// user's bindings on real OSM data (WKB geometry bytes from europe nodes.parquet)
// and isolates the zero-copy path — a reused ZSTD_DCtx decoding into one reused
// output buffer (no per-frame Vec) — from the stock one-shot decode.

struct ZstdCorpus {
    frames: Vec<Vec<u8>>, // zstd-compressed chunks of real OSM geometry bytes
    max_raw: usize,       // largest decompressed chunk (= reused output buffer size)
    raw_total: u64,       // decompressed bytes in one pass over all frames
}

fn zstd_corpus() -> Result<&'static ZstdCorpus> {
    use std::sync::OnceLock;
    static C: OnceLock<Option<ZstdCorpus>> = OnceLock::new();
    C.get_or_init(|| {
        let path = osm_geoparquet_path()?;
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
        let chunk = env_usize("ZSTD_CHUNK_KB", 64) * 1024; // ~parquet-page sized frames
        let raw = data::osm_value_chunks(&path, env_usize("OSM_MAX_ROWS", 20_000_000), threads, chunk).ok()?;
        let mut frames = Vec::with_capacity(raw.len());
        let (mut max_raw, mut raw_total) = (0usize, 0u64);
        for chunk in &raw {
            max_raw = max_raw.max(chunk.len());
            raw_total += chunk.len() as u64;
            frames.push(zstd::bulk::compress(chunk, 3).ok()?);
        }
        Some(ZstdCorpus { frames, max_raw, raw_total })
    })
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("set OSM_GEOPARQUET=/path/to/nodes.parquet (katana-osm) for the zstd corpus"))
}

fn run_zstd_decode(name: &str, zero_copy_sys: bool) -> Result<BenchResult> {
    let c = zstd_corpus()?;
    let iters = env_usize("ZSTD_BENCH_ITERS", 10);
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let n = c.frames.len();
    let per = n.div_ceil(threads);

    // One pass = decode every frame, fanned out across all cores (an ingest
    // engine decompresses many pages at once, so aggregate bandwidth is what
    // matters). Each thread owns its context + output buffer.
    let decode_pass = || {
        std::thread::scope(|s| {
            for t in 0..threads {
                let (lo, hi) = (t * per, ((t + 1) * per).min(n));
                if lo >= hi {
                    continue;
                }
                let frames = &c.frames[lo..hi];
                let max_raw = c.max_raw.max(1);
                s.spawn(move || {
                    let mut buf = vec![0u8; max_raw];
                    if zero_copy_sys {
                        let mut d = zstd_sys_rs::Decompressor::new(); // reused ctx, no per-frame alloc
                        for f in frames {
                            let _ = d.decompress_into(f, &mut buf).expect("zstd-sys-rs decode");
                        }
                    } else {
                        for f in frames {
                            let _ = zstd::bulk::decompress(f, max_raw).expect("zstd crate decode"); // allocs/frame
                        }
                    }
                });
            }
        });
    };

    decode_pass(); // warmup
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        decode_pass();
        samples.push(t.elapsed().as_nanos());
    }
    let wall: u128 = samples.iter().sum();
    let mb_per_sec = c.raw_total as f64 / 1e6 * iters as f64 / (wall as f64 / 1e9).max(1e-9);
    let extra = [
        ("mb_per_sec", mb_per_sec),
        ("decompressed_mb", c.raw_total as f64 / 1e6),
        ("frames", c.frames.len() as f64),
        ("threads", threads as f64),
    ];
    Ok(bench(name, pctl_metrics(&extra, samples, wall)))
}

struct ZstdDecodeCrate;
impl Bencher for ZstdDecodeCrate {
    fn id(&self) -> &'static str { "zstd_decode_crate" }
    fn run(&self) -> Result<BenchResult> { run_zstd_decode(self.id(), false) }
}
register_bench!(ZstdDecodeCrate);

struct ZstdDecodeSysZeroCopy;
impl Bencher for ZstdDecodeSysZeroCopy {
    fn id(&self) -> &'static str { "zstd_decode_sys_zerocopy" }
    fn run(&self) -> Result<BenchResult> { run_zstd_decode(self.id(), true) }
}
register_bench!(ZstdDecodeSysZeroCopy);

// ---- commit-burst across targets -------------------------------------------

struct CommitBurstNornirNvme;
impl Bencher for CommitBurstNornirNvme {
    fn id(&self) -> &'static str { "commit_burst_skade_nvme" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let (cat, _tmp) = factory::embedded().await?;
            Ok(bench(self.id(), commit_burst_metrics(Arc::new(cat)).await?))
        })
    }
}
register_bench!(CommitBurstNornirNvme);

struct CommitBurstNornirRam;
impl Bencher for CommitBurstNornirRam {
    fn id(&self) -> &'static str { "commit_burst_skade_ram" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let tmp = factory::tempdir_in(&factory::ram_dir())?;
            let cat = factory::embedded_in(&tmp).await?;
            Ok(bench(self.id(), commit_burst_metrics(Arc::new(cat)).await?))
        })
    }
}
register_bench!(CommitBurstNornirRam);

struct CommitBurstNornirS3;
impl Bencher for CommitBurstNornirS3 {
    fn id(&self) -> &'static str { "commit_burst_skade_s3" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let (cat, _tmp) = factory::embedded_s3().await?;
            Ok(bench(self.id(), commit_burst_metrics(Arc::new(cat)).await?))
        })
    }
}
register_bench!(CommitBurstNornirS3);

#[cfg(feature = "rest")]
struct CommitBurstNessie;
#[cfg(feature = "rest")]
impl Bencher for CommitBurstNessie {
    fn id(&self) -> &'static str { "commit_burst_nessie" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let rest = factory::rest_s3(&nessie_uri(), "warehouse").await?;
            Ok(bench(self.id(), commit_burst_metrics(Arc::new(rest)).await?))
        })
    }
}
#[cfg(feature = "rest")]
register_bench!(CommitBurstNessie);

// ---- multi-table atomic commit (skade's flagship `atomic_release`) ----------
// `commit_burst_*` above measures per-table `iceberg::Transaction::commit`
// (single-table atomicity). This bencher measures skade's differentiator: the
// all-or-nothing `RedbCatalog::atomic_release_raw` that flips N table pointers
// in ONE redb write transaction. Each batch stages N property updates, writes
// N metadata blobs, then swaps all N pointers atomically — the exact hot path
// the `.nornir` docs call "publish bench_runs + dep_graph + components
// together". Reports batches/sec, table-flips/sec, and per-batch latency
// percentiles over a fresh embedded warehouse (tempdir on the NVMe work dir).
// Env: NORNIR_ATOMIC_TABLES (default 8), NORNIR_ATOMIC_BATCHES (default 50).
async fn atomic_release_metrics(cat: &skade_katalog::RedbCatalog) -> Result<Map<String, Value>> {
    use std::collections::HashMap;
    let tables = env_usize("NORNIR_ATOMIC_TABLES", 8).max(1);
    let batches = env_usize("NORNIR_ATOMIC_BATCHES", 50).max(1);
    let ns = NamespaceIdent::new("atomic".to_string());
    if !cat.namespace_exists(&ns).await.unwrap_or(false) {
        cat.create_namespace(&ns, Default::default()).await?;
    }
    let mut idents = Vec::with_capacity(tables);
    for t in 0..tables {
        let ident = TableIdent::new(ns.clone(), format!("rel_{t:03}"));
        if cat.table_exists(&ident).await.unwrap_or(false) {
            let _ = cat.drop_table(&ident).await;
        }
        data::create_node_table(cat, &ident).await?;
        idents.push(ident);
    }
    let wall = Instant::now();
    let mut lat = Vec::with_capacity(batches);
    for b in 0..batches {
        let commits: Vec<_> = idents
            .iter()
            .map(|ident| {
                let mut updates = HashMap::new();
                updates.insert("skade.release_seq".to_string(), b.to_string());
                (
                    ident.clone(),
                    Vec::<iceberg::TableRequirement>::new(),
                    vec![iceberg::TableUpdate::SetProperties { updates }],
                )
            })
            .collect();
        let t0 = Instant::now();
        cat.atomic_release_raw(commits).await?;
        lat.push(t0.elapsed().as_nanos());
    }
    let secs = wall.elapsed().as_secs_f64().max(1e-9);
    let batches_f = lat.len() as f64;
    let flips = batches_f * tables as f64;
    Ok(pctl_metrics(
        &[
            ("batches_per_sec", batches_f / secs),
            ("table_flips_per_sec", flips / secs),
            ("tables_per_batch", tables as f64),
        ],
        lat,
        wall.elapsed().as_nanos(),
    ))
}

struct SkadeAtomicRelease;
impl Bencher for SkadeAtomicRelease {
    fn id(&self) -> &'static str { "skade.atomic_release" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let tmp = factory::tempdir_in(&factory::nvme_dir())?;
            let cat = factory::embedded_in(&tmp).await?;
            Ok(bench(self.id(), atomic_release_metrics(&cat).await?))
        })
    }
}
register_bench!(SkadeAtomicRelease);

// ---- skade.* throughput (migrated from the old criterion suite) -------------
// These drive the high-level `skade::Table` API (append / ingest /
// ingest_parallel / ingest_pipelined / read / recast / compression codec) over
// a fresh embedded warehouse on a temp dir — a different code path from the
// catalog-level `data_pipe_*` / `commit_burst_*` benchers above (those go
// through the raw `pipeline` module over an `iceberg::Catalog`). Each emits
// throughput keys (`*_per_sec` / `*_mbs`), `elapsed_ms`, and raw counts.
// No external infra needed: a tempdir on the NVMe work dir (factory::nvme_dir).

use skade_katalog_bench::skade_throughput::{batch as sk_batch, schema as sk_schema};

/// Median wall-clock over `iters` timed runs of `f` (warm up once first).
fn timed_median(iters: usize, mut f: impl FnMut() -> std::time::Duration) -> std::time::Duration {
    f(); // warmup
    let mut samples: Vec<std::time::Duration> = (0..iters.max(1)).map(|_| f()).collect();
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Fresh embedded skade warehouse + an (optionally partitioned) table on a temp
/// dir under the NVMe work dir. Returns the warehouse handle (kept alive via the
/// returned TempDir) and the table.
async fn sk_open_table(
    tmp: &tempfile::TempDir,
    partition: Option<&[&str]>,
) -> Result<skade::Table> {
    let wh = skade::open(tmp.path()).await?;
    let t = match partition {
        Some(cols) => {
            wh.create_partitioned_table("t", sk_schema().as_ref(), cols)
                .await?
        }
        None => wh.create_table("t", sk_schema().as_ref()).await?,
    };
    Ok(t)
}

fn sk_tmp() -> Result<tempfile::TempDir> {
    factory::tempdir_in(&factory::nvme_dir())
}

/// Single-batch `Table::append` (one snapshot/commit per call) — commit-bound.
/// Sweeps 1k + 10k rows; reports rows/sec at each.
struct SkadeAppend;
impl Bencher for SkadeAppend {
    fn id(&self) -> &'static str { "skade.append" }
    fn run(&self) -> Result<BenchResult> {
        let rt = rt();
        let iters = env_usize("SKADE_BENCH_ITERS", 20);
        let mut m = Map::new();
        let mut headline = 0.0f64;
        for &rows in &[1_000usize, 10_000] {
            let b = sk_batch(rows);
            let tmp = sk_tmp()?;
            let mut table = rt.block_on(sk_open_table(&tmp, None))?;
            let dur = timed_median(iters, || {
                let t = Instant::now();
                rt.block_on(async { table.append(std::slice::from_ref(&b)).await.unwrap() });
                t.elapsed()
            });
            let rps = rows as f64 / dur.as_secs_f64().max(1e-9);
            m.insert(format!("rows_{rows}_per_sec"), json!(rps));
            m.insert(format!("rows_{rows}_elapsed_ms"), json!(dur.as_secs_f64() * 1e3));
            headline = headline.max(rps);
        }
        m.insert("rows_per_sec".into(), json!(headline));
        Ok(bench(self.id(), m))
    }
}
register_bench!(SkadeAppend);

/// Partitioned (`repo`) single-batch append — adds skade's per-commit identity
/// `partition_key_for` over the unpartitioned `skade.append` path.
struct SkadeAppendPartitioned;
impl Bencher for SkadeAppendPartitioned {
    fn id(&self) -> &'static str { "skade.append_partitioned" }
    fn run(&self) -> Result<BenchResult> {
        let rt = rt();
        let iters = env_usize("SKADE_BENCH_ITERS", 20);
        let rows = 10_000usize;
        let b = sk_batch(rows);
        let tmp = sk_tmp()?;
        let mut table = rt.block_on(sk_open_table(&tmp, Some(&["repo"])))?;
        let dur = timed_median(iters, || {
            let t = Instant::now();
            rt.block_on(async { table.append(std::slice::from_ref(&b)).await.unwrap() });
            t.elapsed()
        });
        let mut m = Map::new();
        m.insert("rows_per_sec".into(), json!(rows as f64 / dur.as_secs_f64().max(1e-9)));
        m.insert("rows".into(), json!(rows as f64));
        m.insert("elapsed_ms".into(), json!(dur.as_secs_f64() * 1e3));
        Ok(bench(self.id(), m))
    }
}
register_bench!(SkadeAppendPartitioned);

/// Bulk `Table::ingest` — many batches, commit every 8. Amortises the fsync, so
/// this is the real bulk-load throughput of the high-level ingest API.
struct SkadeIngest;
impl Bencher for SkadeIngest {
    fn id(&self) -> &'static str { "skade.ingest" }
    fn run(&self) -> Result<BenchResult> {
        let rt = rt();
        let iters = env_usize("SKADE_BENCH_ITERS", 10);
        let n_batches = env_usize("SKADE_INGEST_BATCHES", 64);
        let rows = env_usize("SKADE_INGEST_ROWS", 1_000);
        let total = (n_batches * rows) as f64;
        let dur = timed_median(iters, || {
            // Fresh warehouse + table per iteration (ingest mutates state).
            let tmp = sk_tmp().unwrap();
            let mut table = rt.block_on(sk_open_table(&tmp, None)).unwrap();
            let batches: Vec<_> = (0..n_batches).map(|_| sk_batch(rows)).collect();
            let t = Instant::now();
            rt.block_on(async { table.ingest(batches, 8).await.unwrap() });
            let e = t.elapsed();
            drop(tmp);
            e
        });
        let mut m = Map::new();
        m.insert("rows_per_sec".into(), json!(total / dur.as_secs_f64().max(1e-9)));
        m.insert("rows".into(), json!(total));
        m.insert("batches".into(), json!(n_batches as f64));
        m.insert("commit_every".into(), json!(8.0));
        m.insert("elapsed_ms".into(), json!(dur.as_secs_f64() * 1e3));
        Ok(bench(self.id(), m))
    }
}
register_bench!(SkadeIngest);

/// Full-snapshot `Table::read` (scan → Arrow) across table sizes — 10k / 100k
/// rows by default (`SKADE_READ_FULL=1` adds the 1M-row scale). Absorbs the old
/// criterion `read` group (100k scan) into a size sweep.
struct SkadeReadScan;
impl Bencher for SkadeReadScan {
    fn id(&self) -> &'static str { "skade.read_scan" }
    fn run(&self) -> Result<BenchResult> {
        let rt = rt();
        let iters = env_usize("SKADE_BENCH_ITERS", 10);
        let mut sizes = vec![10_000usize, 100_000];
        if std::env::var("SKADE_READ_FULL").is_ok() {
            sizes.push(1_000_000);
        }
        let mut m = Map::new();
        let mut headline = 0.0f64;
        for rows in sizes {
            let tmp = sk_tmp()?;
            let mut table = rt.block_on(sk_open_table(&tmp, None))?;
            let per = 10_000usize;
            let groups: Vec<Vec<_>> = (0..rows / per).map(|_| vec![sk_batch(per)]).collect();
            rt.block_on(async { table.ingest_parallel(groups, 16).await })?;
            let dur = timed_median(iters, || {
                let t = Instant::now();
                let got = rt.block_on(async { table.read().await.unwrap() });
                assert_eq!(got.iter().map(|b| b.num_rows()).sum::<usize>(), rows);
                t.elapsed()
            });
            let rps = rows as f64 / dur.as_secs_f64().max(1e-9);
            m.insert(format!("rows_{rows}_per_sec"), json!(rps));
            m.insert(format!("rows_{rows}_elapsed_ms"), json!(dur.as_secs_f64() * 1e3));
            headline = headline.max(rps);
            drop(tmp);
        }
        m.insert("rows_per_sec".into(), json!(headline));
        Ok(bench(self.id(), m))
    }
}
register_bench!(SkadeReadScan);

/// Parallel-encode saturation — `ingest_parallel` fans the Parquet encode across
/// all cores via the ONE fork-join engine (znippy-zoomies `gatling_forkjoin`),
/// with one sequential writer committing. Encode-heavy on purpose (32 files ×
/// 20k rows). Reports throughput plus the **core-saturation** number: the avg
/// cores the encode kept busy (measured only around the `ingest_parallel` call,
/// so table-open/batch-gen don't dilute it). The gatling payoff is a `cores_busy`
/// near `cores_total`. (Was a rayon-pool 1-core-vs-all comparison; rayon is gone
/// — the engine self-dispatches its own scoped threads, so we measure saturation
/// directly instead of throttling a global pool.)
struct SkadeIngestParallelScaling;
impl Bencher for SkadeIngestParallelScaling {
    fn id(&self) -> &'static str { "skade.ingest_parallel_scaling" }
    fn run(&self) -> Result<BenchResult> {
        let rt = rt();
        let iters = env_usize("SKADE_BENCH_ITERS", 10);
        let n_files = env_usize("SKADE_SCALE_FILES", 32);
        let rows = env_usize("SKADE_SCALE_ROWS", 20_000);
        let total = (n_files * rows) as f64;
        // Accumulate CPU + wall ONLY around the encode+commit (not setup) so
        // cores_busy reflects the gatling fan-out, not single-threaded batch gen.
        let mut cpu_acc = 0.0f64;
        let mut wall_acc = 0.0f64;
        let dur = timed_median(iters, || {
            let tmp = sk_tmp().unwrap();
            let mut table = rt.block_on(sk_open_table(&tmp, None)).unwrap();
            let groups: Vec<Vec<_>> = (0..n_files).map(|_| vec![sk_batch(rows)]).collect();
            let cpu0 = proc_cpu_secs();
            let t = Instant::now();
            rt.block_on(async { table.ingest_parallel(groups, 8).await.unwrap() });
            let e = t.elapsed();
            cpu_acc += proc_cpu_secs() - cpu0;
            wall_acc += e.as_secs_f64();
            drop(tmp);
            e
        });
        let cores_busy = if wall_acc > 0.0 { cpu_acc / wall_acc } else { 0.0 };
        let ct = cores_total();
        let rps = total / dur.as_secs_f64().max(1e-9);
        let mut m = Map::new();
        m.insert("rows_per_sec".into(), json!(rps));
        m.insert("elapsed_ms".into(), json!(dur.as_secs_f64() * 1e3));
        m.insert("files".into(), json!(n_files as f64));
        m.insert("cores_busy".into(), json!(cores_busy));
        m.insert("cores_used".into(), json!(cores_busy));
        m.insert("cores_total".into(), json!(ct as f64));
        m.insert("core_saturation".into(), json!(cores_busy / ct.max(1) as f64));
        Ok(bench(self.id(), m))
    }
}
register_bench!(SkadeIngestParallelScaling);

/// `skade::recast` — the zero-copy fast path. When a batch already matches the
/// table's field-id schema, recast re-stamps the schema over the same Arc'd
/// buffers (zero copy); only type-mismatched columns are cast+allocated. This
/// contrasts the two over 100k rows: `match_zerocopy` should be orders of
/// magnitude faster than `needs_cast` (which re-materialises one column).
struct SkadeRecast;
impl Bencher for SkadeRecast {
    fn id(&self) -> &'static str { "skade.recast" }
    fn run(&self) -> Result<BenchResult> {
        use skade::arrow_array::{Float64Array, Int32Array, Int64Array, RecordBatch, StringArray};
        use skade::arrow_schema::{DataType, Field, Schema};
        let rows = env_usize("SKADE_RECAST_ROWS", 100_000);
        let iters = env_usize("SKADE_BENCH_ITERS", 50);
        let target = Arc::new(Schema::new(vec![
            Field::new("a", DataType::Int64, false),
            Field::new("b", DataType::Float64, false),
            Field::new("c", DataType::Utf8, false),
        ]));
        let b = Arc::new(Float64Array::from((0..rows).map(|i| i as f64).collect::<Vec<_>>()));
        let s = Arc::new(StringArray::from((0..rows).map(|i| format!("r{i}")).collect::<Vec<_>>()));
        let match_batch = RecordBatch::try_new(
            target.clone(),
            vec![Arc::new(Int64Array::from((0..rows as i64).collect::<Vec<_>>())), b.clone(), s.clone()],
        )?;
        let cast_schema = Arc::new(Schema::new(vec![
            Field::new("a", DataType::Int32, false), // differs → forces a cast
            Field::new("b", DataType::Float64, false),
            Field::new("c", DataType::Utf8, false),
        ]));
        let cast_batch = RecordBatch::try_new(
            cast_schema,
            vec![Arc::new(Int32Array::from((0..rows as i32).collect::<Vec<_>>())), b, s],
        )?;

        let zc = timed_median(iters, || {
            let t = Instant::now();
            skade::recast(std::slice::from_ref(&match_batch), target.clone()).unwrap();
            t.elapsed()
        });
        let cast = timed_median(iters, || {
            let t = Instant::now();
            skade::recast(std::slice::from_ref(&cast_batch), target.clone()).unwrap();
            t.elapsed()
        });
        let mut m = Map::new();
        let zc_rps = rows as f64 / zc.as_secs_f64().max(1e-9);
        let cast_rps = rows as f64 / cast.as_secs_f64().max(1e-9);
        m.insert("match_zerocopy_rows_per_sec".into(), json!(zc_rps));
        m.insert("match_zerocopy_elapsed_ms".into(), json!(zc.as_secs_f64() * 1e3));
        m.insert("needs_cast_rows_per_sec".into(), json!(cast_rps));
        m.insert("needs_cast_elapsed_ms".into(), json!(cast.as_secs_f64() * 1e3));
        m.insert("zerocopy_speedup".into(), json!(if cast_rps > 0.0 { zc_rps / cast_rps } else { 0.0 }));
        m.insert("rows_per_sec".into(), json!(zc_rps));
        m.insert("rows".into(), json!(rows as f64));
        Ok(bench(self.id(), m))
    }
}
register_bench!(SkadeRecast);

/// Append throughput per Parquet codec — the CPU cost of compression on write
/// (none vs snappy vs zstd). Each is a single-batch append on a fresh table
/// configured with that codec.
struct SkadeCompressionAppend;
impl Bencher for SkadeCompressionAppend {
    fn id(&self) -> &'static str { "skade.compression_append" }
    fn run(&self) -> Result<BenchResult> {
        let rt = rt();
        let iters = env_usize("SKADE_BENCH_ITERS", 20);
        let rows = 10_000usize;
        let b = sk_batch(rows);
        let mut m = Map::new();
        let mut headline = 0.0f64;
        for (name, codec) in [
            ("none", skade::Compression::UNCOMPRESSED),
            ("snappy", skade::Compression::SNAPPY),
            ("zstd", skade::Compression::ZSTD(Default::default())),
        ] {
            let tmp = sk_tmp()?;
            let mut table = rt.block_on(async {
                let wh = skade::open(tmp.path()).await?;
                Ok::<_, anyhow::Error>(
                    wh.create_table("t", sk_schema().as_ref()).await?.compression(codec),
                )
            })?;
            let dur = timed_median(iters, || {
                let t = Instant::now();
                rt.block_on(async { table.append(std::slice::from_ref(&b)).await.unwrap() });
                t.elapsed()
            });
            let rps = rows as f64 / dur.as_secs_f64().max(1e-9);
            m.insert(format!("{name}_rows_per_sec"), json!(rps));
            m.insert(format!("{name}_elapsed_ms"), json!(dur.as_secs_f64() * 1e3));
            if name == "zstd" {
                headline = rps;
            }
            drop(tmp);
        }
        m.insert("rows_per_sec".into(), json!(headline));
        m.insert("rows".into(), json!(rows as f64));
        Ok(bench(self.id(), m))
    }
}
register_bench!(SkadeCompressionAppend);

/// `ingest_parallel` (encode-all-then-write) vs `ingest_pipelined` (no-barrier:
/// encoders run ahead of one writer through a bounded channel — overlaps encode
/// with the writer's commit + bounds memory). Same encode-heavy workload.
struct SkadeIngestStrategies;
impl Bencher for SkadeIngestStrategies {
    fn id(&self) -> &'static str { "skade.ingest_strategies" }
    fn run(&self) -> Result<BenchResult> {
        let rt = rt();
        let iters = env_usize("SKADE_BENCH_ITERS", 10);
        let n_files = env_usize("SKADE_SCALE_FILES", 32);
        let rows = env_usize("SKADE_SCALE_ROWS", 20_000);
        let total = (n_files * rows) as f64;
        let mut m = Map::new();
        // parallel
        let par = timed_median(iters, || {
            let tmp = sk_tmp().unwrap();
            let mut t = rt.block_on(sk_open_table(&tmp, None)).unwrap();
            let groups: Vec<Vec<_>> = (0..n_files).map(|_| vec![sk_batch(rows)]).collect();
            let i = Instant::now();
            rt.block_on(async { t.ingest_parallel(groups, 8).await.unwrap() });
            let e = i.elapsed();
            drop(tmp);
            e
        });
        // pipelined
        let pipe = timed_median(iters, || {
            let tmp = sk_tmp().unwrap();
            let mut t = rt.block_on(sk_open_table(&tmp, None)).unwrap();
            let groups: Vec<Vec<_>> = (0..n_files).map(|_| vec![sk_batch(rows)]).collect();
            let i = Instant::now();
            rt.block_on(async { t.ingest_pipelined(groups, 8, 8).await.unwrap() });
            let e = i.elapsed();
            drop(tmp);
            e
        });
        let par_rps = total / par.as_secs_f64().max(1e-9);
        let pipe_rps = total / pipe.as_secs_f64().max(1e-9);
        m.insert("parallel_rows_per_sec".into(), json!(par_rps));
        m.insert("parallel_elapsed_ms".into(), json!(par.as_secs_f64() * 1e3));
        m.insert("pipelined_rows_per_sec".into(), json!(pipe_rps));
        m.insert("pipelined_elapsed_ms".into(), json!(pipe.as_secs_f64() * 1e3));
        m.insert("rows_per_sec".into(), json!(par_rps.max(pipe_rps)));
        m.insert("files".into(), json!(n_files as f64));
        Ok(bench(self.id(), m))
    }
}
register_bench!(SkadeIngestStrategies);

// ---- TPC-H: all 22 queries, per-query latency over RedbCatalog -------------
// Shared 8-table fixture (generate + ingest + DataFusion wiring) is built once
// and reused by all 22 query benchers, so setup isn't paid 22×.

#[path = "../tpch_shared.rs"]
mod tpch;

struct TpchFixture {
    rt: tokio::runtime::Runtime,
    ctx: datafusion::prelude::SessionContext,
    _tmp: tempfile::TempDir,
}

fn tpch_fixture() -> &'static TpchFixture {
    use std::sync::OnceLock;
    static F: OnceLock<TpchFixture> = OnceLock::new();
    F.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tpch rt");
        let sf = std::env::var("TPCH_SF").ok().and_then(|v| v.parse().ok()).unwrap_or(0.01);
        let (ctx, tmp, _rows) = rt.block_on(tpch::build_ctx(sf)).expect("tpch fixture setup");
        TpchFixture { rt, ctx, _tmp: tmp }
    })
}

fn tpch_query_result(name: &str, n: i32) -> Result<BenchResult> {
    let fx = tpch_fixture();
    let sql = tpch::query_sql(n);
    let iters = env_usize("TPCH_BENCH_ITERS", 5);
    let exec = |q: &str| -> Result<usize> {
        let b = fx
            .rt
            .block_on(async { fx.ctx.sql(q).await?.collect().await })
            .map_err(anyhow::Error::from)?;
        Ok(b.iter().map(|x| x.num_rows()).sum())
    };
    let _ = exec(&sql)?; // warmup
    let mut samples = Vec::with_capacity(iters);
    let mut rows = 0usize;
    for _ in 0..iters {
        let t = Instant::now();
        rows = exec(&sql)?;
        samples.push(t.elapsed().as_nanos());
    }
    let wall: u128 = samples.iter().sum();
    Ok(bench(name, pctl_metrics(&[("rows", rows as f64)], samples, wall)))
}

macro_rules! tpch_q {
    ($s:ident, $id:literal, $n:expr) => {
        struct $s;
        impl Bencher for $s {
            fn id(&self) -> &'static str { $id }
            fn run(&self) -> Result<BenchResult> { tpch_query_result($id, $n) }
        }
        register_bench!($s);
    };
}
tpch_q!(TpchQ01, "tpch_q01", 1);
tpch_q!(TpchQ02, "tpch_q02", 2);
tpch_q!(TpchQ03, "tpch_q03", 3);
tpch_q!(TpchQ04, "tpch_q04", 4);
tpch_q!(TpchQ05, "tpch_q05", 5);
tpch_q!(TpchQ06, "tpch_q06", 6);
tpch_q!(TpchQ07, "tpch_q07", 7);
tpch_q!(TpchQ08, "tpch_q08", 8);
tpch_q!(TpchQ09, "tpch_q09", 9);
tpch_q!(TpchQ10, "tpch_q10", 10);
tpch_q!(TpchQ11, "tpch_q11", 11);
tpch_q!(TpchQ12, "tpch_q12", 12);
tpch_q!(TpchQ13, "tpch_q13", 13);
tpch_q!(TpchQ14, "tpch_q14", 14);
tpch_q!(TpchQ15, "tpch_q15", 15);
tpch_q!(TpchQ16, "tpch_q16", 16);
tpch_q!(TpchQ17, "tpch_q17", 17);
tpch_q!(TpchQ18, "tpch_q18", 18);
tpch_q!(TpchQ19, "tpch_q19", 19);
tpch_q!(TpchQ20, "tpch_q20", 20);
tpch_q!(TpchQ21, "tpch_q21", 21);
tpch_q!(TpchQ22, "tpch_q22", 22);

// ---- TPC-H large warehouse (runs by default; scalable) ----------------------
// A full warehouse run: ingest the 8-table warehouse at a scale factor across all
// cores (partitioned parallel ingest), then run all 22 queries over it, reporting
// build vs query time. Runs by default at a moderate scale; tune / disable with:
//   TPCH_WAREHOUSE_SF    scale factor (default 10 ≈ 60M lineitem rows, a few min;
//                        100-200 for the 10-60 min big-iron workout)
//   TPCH_WAREHOUSE       set to 0 to disable this bench entirely
//   TPCH_WAREHOUSE_PARTS ingest partitions (default = all cores)

struct TpchWarehouse;
impl Bencher for TpchWarehouse {
    fn id(&self) -> &'static str { "tpch_warehouse" }
    fn run(&self) -> Result<BenchResult> {
        let sf: f64 = std::env::var("TPCH_WAREHOUSE_SF").ok().and_then(|v| v.parse().ok()).unwrap_or(10.0);
        let disabled = std::env::var("TPCH_WAREHOUSE").map(|v| v == "0").unwrap_or(false) || sf <= 0.0;
        if disabled {
            anyhow::bail!("tpch_warehouse disabled (TPCH_WAREHOUSE=0 or TPCH_WAREHOUSE_SF=0)");
        }
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
        let parts = env_usize("TPCH_WAREHOUSE_PARTS", cores).max(1) as i32;
        rt().block_on(async move {
            let t0 = Instant::now();
            let (ctx, _tmp, rows) = tpch::build_ctx_scaled(sf, parts).await?;
            let build_s = t0.elapsed().as_secs_f64();

            let tq = Instant::now();
            let mut result_rows = 0u64;
            let (mut slowest_q, mut slowest_s) = (0i32, 0.0f64);
            for n in 1..=22 {
                let sql = tpch::query_sql(n);
                let qt = Instant::now();
                let b = ctx.sql(&sql).await?.collect().await?;
                let s = qt.elapsed().as_secs_f64();
                result_rows += b.iter().map(|x| x.num_rows()).sum::<usize>() as u64;
                if s > slowest_s { slowest_s = s; slowest_q = n; }
                eprintln!("  warehouse Q{n:<2} {s:8.2}s");
            }
            let query_s = tq.elapsed().as_secs_f64();

            let mut m = Map::new();
            m.insert("scale_factor".into(), json!(sf));
            m.insert("parts".into(), json!(parts as f64));
            m.insert("ingest_rows".into(), json!(rows as f64));
            m.insert("build_s".into(), json!(build_s));
            m.insert("ingest_rows_per_sec".into(), json!(rows as f64 / build_s.max(1e-9)));
            m.insert("query_s".into(), json!(query_s));
            m.insert("total_s".into(), json!(build_s + query_s));
            m.insert("slowest_query".into(), json!(slowest_q as f64));
            m.insert("slowest_query_s".into(), json!(slowest_s));
            m.insert("result_rows".into(), json!(result_rows as f64));
            Ok(bench("tpch_warehouse", m))
        })
    }
}
register_bench!(TpchWarehouse);

// ---- TPC-H across catalogs (nornir / Nessie / Polaris) ----------------------
// The same SF≥0.5 warehouse built + all-22 queried over each catalog, so the
// analytical SQL path is comparable apples-to-apples (not just the table_exists
// RPC). nornir embedded runs anywhere; the REST targets need their container +
// the shared RustFS S3 warehouse (BENCH_S3_*), else they skip-as-failure.
// TPCH_COMPARE_SF sets the scale (default 0.5).

fn compare_sf() -> f64 {
    // Default to the canonical TPC-H SF1 (~1GB / 8.66M rows); bump for a bigger run.
    std::env::var("TPCH_COMPARE_SF").ok().and_then(|v| v.parse().ok()).unwrap_or(1.0)
}
fn compare_parts() -> i32 {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8) as i32
}

async fn tpch_suite_metrics(cat: Arc<dyn Catalog>, sf: f64, parts: i32) -> Result<Map<String, Value>> {
    let t0 = Instant::now();
    let (ctx, rows) = tpch::build_ctx_in(cat, sf, parts).await?;
    let build_s = t0.elapsed().as_secs_f64();

    let tq = Instant::now();
    let (mut slowest_q, mut slowest_s) = (0i32, 0.0f64);
    let mut per_query: Vec<(String, f64)> = Vec::with_capacity(22);
    for n in 1..=22 {
        let sql = tpch::query_sql(n);
        let qt = Instant::now();
        let _ = ctx.sql(&sql).await?.collect().await?;
        let s = qt.elapsed().as_secs_f64();
        // per-query time on THIS backend, so the docs renderer can compute
        // nornir-vs-competitor speedup per query and surface the most dramatic.
        per_query.push((format!("q{n:02}_s"), s));
        if s > slowest_s { slowest_s = s; slowest_q = n; }
    }
    let query_s = tq.elapsed().as_secs_f64();

    let mut m = Map::new();
    for (k, s) in per_query {
        m.insert(k, json!(s));
    }
    m.insert("scale_factor".into(), json!(sf));
    m.insert("rows".into(), json!(rows as f64));
    m.insert("build_s".into(), json!(build_s));
    m.insert("query_s".into(), json!(query_s));
    m.insert("total_s".into(), json!(build_s + query_s));
    m.insert("slowest_query".into(), json!(slowest_q as f64));
    m.insert("slowest_query_s".into(), json!(slowest_s));
    Ok(m)
}

// Storage matrix — each (catalog × storage) combination that's actually
// possible. nornir runs on all three (file-NVMe, file-RAM, S3); Nessie rejects a
// local file warehouse so it's S3-only; Polaris serves FILE end-to-end (its S3
// vending 301s on RustFS — see containers.rs). The REST targets skip-as-failure
// without their container + RustFS S3.

struct TpchNornirFileNvme;
impl Bencher for TpchNornirFileNvme {
    fn id(&self) -> &'static str { "tpch_cmp_skade_file_nvme" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let (cat, _tmp) = factory::embedded().await?;
            Ok(bench(self.id(), tpch_suite_metrics(Arc::new(cat), compare_sf(), compare_parts()).await?))
        })
    }
}
register_bench!(TpchNornirFileNvme);

struct TpchNornirFileRam;
impl Bencher for TpchNornirFileRam {
    fn id(&self) -> &'static str { "tpch_cmp_skade_file_ram" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let tmp = factory::tempdir_in(&factory::ram_dir())?;
            let cat = factory::embedded_in(&tmp).await?;
            Ok(bench(self.id(), tpch_suite_metrics(Arc::new(cat), compare_sf(), compare_parts()).await?))
        })
    }
}
register_bench!(TpchNornirFileRam);

struct TpchNornirS3;
impl Bencher for TpchNornirS3 {
    fn id(&self) -> &'static str { "tpch_cmp_skade_s3" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let (cat, _tmp) = factory::embedded_s3().await?;
            Ok(bench(self.id(), tpch_suite_metrics(Arc::new(cat), compare_sf(), compare_parts()).await?))
        })
    }
}
register_bench!(TpchNornirS3);

#[cfg(feature = "rest")]
struct TpchNessieS3;
#[cfg(feature = "rest")]
impl Bencher for TpchNessieS3 {
    fn id(&self) -> &'static str { "tpch_cmp_nessie_s3" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let cat = factory::rest_s3(&nessie_uri(), "warehouse").await?;
            Ok(bench(self.id(), tpch_suite_metrics(Arc::new(cat), compare_sf(), compare_parts()).await?))
        })
    }
}
#[cfg(feature = "rest")]
register_bench!(TpchNessieS3);

#[cfg(feature = "rest")]
struct TpchPolarisFile;
#[cfg(feature = "rest")]
impl Bencher for TpchPolarisFile {
    fn id(&self) -> &'static str { "tpch_cmp_polaris_file" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let uri = std::env::var("BENCH_POLARIS_URI")
                .unwrap_or_else(|_| "http://localhost:8181/api/catalog".to_string());
            let cat = factory::rest_polaris(&uri).await?;
            Ok(bench(self.id(), tpch_suite_metrics(Arc::new(cat), compare_sf(), compare_parts()).await?))
        })
    }
}
#[cfg(feature = "rest")]
register_bench!(TpchPolarisFile);

// ==== SEARCH / DATA-SKIPPING — the warehouse-perf trade ======================
// Proves the warehouse-perf knobs (zstd + per-column bloom + small row-groups +
// per-file min/max bounds): writes are MODESTLY slower + files SMALLER, and
// point/predicate READS skip data files via the Iceberg manifest's min/max
// bounds — collapsing a full scan to a few-file read.
//
// Tables are built with `append` (iceberg's DataFileWriter, which records the
// per-column min/max bounds the scan planner prunes on). The fast
// `ingest_parallel`/`ingest_pipelined` paths build the DataFile by hand and DO
// NOT emit those bounds, so a table written that way CANNOT be file-pruned — the
// knobs only pay off through a bounds-emitting writer (flagged in skade/.nornir).

/// (repos, rows_per_repo) — small + fast by default; `NORNIR_BENCH_FULL=1` scales up.
fn search_params() -> (usize, usize) {
    if std::env::var("NORNIR_BENCH_FULL").is_ok() {
        (env_usize("SEARCH_REPOS", 32), env_usize("SEARCH_ROWS_PER_REPO", 250_000))
    } else {
        (env_usize("SEARCH_REPOS", 16), env_usize("SEARCH_ROWS_PER_REPO", 50_000))
    }
}

fn search_schema() -> skade::arrow_schema::Schema {
    use skade::arrow_schema::{DataType, Field, Schema};
    Schema::new(vec![
        Field::new("repo", DataType::Utf8, false),
        Field::new("symbol", DataType::Utf8, false),
        Field::new("value", DataType::Int64, false),
    ])
}

/// One file's rows, all for a single `repo` (file `repo` min==max) with a
/// disjoint, contiguous `symbol`/`value` range per repo (so min/max bounds are
/// tight and a point lookup prunes to one file).
fn search_repo_batch(repo_idx: usize, rows: usize) -> Result<skade::arrow_array::RecordBatch> {
    use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
    let base = (repo_idx * rows) as i64;
    let repo = format!("repo{repo_idx:02}");
    let repos: Vec<&str> = std::iter::repeat(repo.as_str()).take(rows).collect();
    let syms: Vec<String> = (0..rows).map(|i| format!("SYM{:08}", base + i as i64)).collect();
    let vals: Vec<i64> = (0..rows).map(|i| base + i as i64).collect();
    Ok(RecordBatch::try_new(
        std::sync::Arc::new(search_schema()),
        vec![
            std::sync::Arc::new(StringArray::from(repos)),
            std::sync::Arc::new(StringArray::from(syms)),
            std::sync::Arc::new(Int64Array::from(vals)),
        ],
    )?)
}

/// Sum the bytes of every `.parquet` data file under `dir` (on-disk table size).
fn search_lake_bytes(dir: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("parquet") {
                total += std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    total
}

/// Build a table with `props`, one `append` per repo (one bounds-carrying data
/// file per repo). Returns the handle + the wall time to write all rows.
async fn search_build(
    wh: &skade::Warehouse,
    name: &str,
    props: skade::WriteProps,
    repos: usize,
    rows: usize,
) -> Result<(skade::Table, std::time::Duration)> {
    let mut t = wh.create_table(name, &search_schema()).await?.write_props(props);
    let t0 = Instant::now();
    for r in 0..repos {
        t.append(&[search_repo_batch(r, rows)?]).await?;
    }
    let elapsed = t0.elapsed();
    anyhow::ensure!(t.count().await? == (repos * rows) as u64, "all rows persisted");
    Ok((t, elapsed))
}

// ---- WRITE side: tuned (zstd+bloom+small-rg) vs baseline (uncompressed) ------
struct SearchWriteCost;
impl Bencher for SearchWriteCost {
    fn id(&self) -> &'static str { "search_write_cost" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            let (repos, rows) = search_params();
            let total = (repos * rows) as f64;

            let base_tmp = factory::tempdir_in(&factory::nvme_dir())?;
            let base_wh = skade::open(base_tmp.path().join("lake")).await?;
            let (_bt, base_t) = search_build(
                &base_wh, "base",
                skade::WriteProps::new(skade::Compression::UNCOMPRESSED),
                repos, rows,
            ).await?;
            let base_bytes = search_lake_bytes(base_tmp.path());

            let tuned_tmp = factory::tempdir_in(&factory::nvme_dir())?;
            let tuned_wh = skade::open(tuned_tmp.path().join("lake")).await?;
            let (_tt, tuned_t) = search_build(
                &tuned_wh, "tuned",
                skade::WriteProps::new(skade::Compression::ZSTD(Default::default()))
                    .bloom_columns(["symbol"])
                    .row_group_size(8192),
                repos, rows,
            ).await?;
            let tuned_bytes = search_lake_bytes(tuned_tmp.path());

            anyhow::ensure!(base_bytes > 0 && tuned_bytes > 0, "both tables wrote parquet bytes");
            let mut m = Map::new();
            m.insert("baseline_rows_per_sec".into(), json!(total / base_t.as_secs_f64().max(1e-9)));
            m.insert("tuned_rows_per_sec".into(), json!(total / tuned_t.as_secs_f64().max(1e-9)));
            m.insert("write_slowdown_pct".into(),
                json!((tuned_t.as_secs_f64() / base_t.as_secs_f64().max(1e-9) - 1.0) * 100.0));
            m.insert("baseline_mb".into(), json!(base_bytes as f64 / 1e6));
            m.insert("tuned_mb".into(), json!(tuned_bytes as f64 / 1e6));
            m.insert("size_reduction_pct".into(),
                json!((1.0 - tuned_bytes as f64 / base_bytes as f64) * 100.0));
            m.insert("rows".into(), json!(total));
            Ok(bench(self.id(), m))
        })
    }
}
register_bench!(SearchWriteCost);

// ---- READ side: file-skipping via manifest min/max bounds (the win) ---------
struct SearchDataSkip;
impl Bencher for SearchDataSkip {
    fn id(&self) -> &'static str { "search_data_skip" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            use skade::ScanFilter;
            let (repos, rows) = search_params();
            let tmp = factory::tempdir_in(&factory::nvme_dir())?;
            let wh = skade::open(tmp.path().join("lake")).await?;
            let (t, _) = search_build(
                &wh, "syms",
                skade::WriteProps::new(skade::Compression::ZSTD(Default::default()))
                    .bloom_columns(["symbol"])
                    .row_group_size(8192),
                repos, rows,
            ).await?;

            let target = format!("repo{:02}", repos / 2);
            let full = t.plan_stats(None).await?;
            let pruned = t.plan_stats(Some(&ScanFilter::eq("repo", target.as_str()))).await?;
            anyhow::ensure!(full.data_files == repos as u64, "one file per repo: {}", full.data_files);
            anyhow::ensure!(
                pruned.data_files < full.data_files,
                "data-skipping must prune files (planned {}/{}); bounds missing?",
                pruned.data_files, full.data_files
            );

            // Symbol point-lookup: a single value in the target repo's range.
            let sym = format!("SYM{:08}", ((repos / 2) * rows) as i64 + (rows as i64 / 2));
            let sym_plan = t.plan_stats(Some(&ScanFilter::eq("symbol", sym.as_str()))).await?;

            // Wall: full scan vs pruned read (mean of K reads), and verify the
            // filtered read returns EXACTLY the target repo's rows (correctness).
            let iters = env_usize("SEARCH_READ_ITERS", 5).max(1);
            let mut full_ns = 0u128;
            let mut pruned_ns = 0u128;
            let mut got = 0usize;
            for _ in 0..iters {
                let a = Instant::now();
                let _ = t.read().await?;
                full_ns += a.elapsed().as_nanos();
                let b = Instant::now();
                let rb = t.read_filtered(&ScanFilter::eq("repo", target.as_str()), &[]).await?;
                pruned_ns += b.elapsed().as_nanos();
                got = rb.iter().map(|x| x.num_rows()).sum();
            }
            anyhow::ensure!(got == rows, "filtered read returns exactly {} rows, got {}", rows, got);
            let full_ms = (full_ns as f64 / iters as f64) / 1e6;
            let pruned_ms = (pruned_ns as f64 / iters as f64) / 1e6;

            let mut m = Map::new();
            m.insert("total_data_files".into(), json!(full.data_files as f64));
            m.insert("repo_pruned_files".into(), json!(pruned.data_files as f64));
            m.insert("repo_files_skipped".into(), json!((full.data_files - pruned.data_files) as f64));
            m.insert("repo_files_skip_pct".into(),
                json!((full.data_files - pruned.data_files) as f64 / full.data_files as f64 * 100.0));
            m.insert("symbol_pruned_files".into(), json!(sym_plan.data_files as f64));
            m.insert("symbol_files_skipped".into(), json!((full.data_files - sym_plan.data_files) as f64));
            m.insert("full_rows_planned".into(), json!(full.rows_planned as f64));
            m.insert("pruned_rows_planned".into(), json!(pruned.rows_planned as f64));
            m.insert("full_scan_ms".into(), json!(full_ms));
            m.insert("pruned_scan_ms".into(), json!(pruned_ms));
            m.insert("scan_speedup_x".into(), json!(full_ms / pruned_ms.max(1e-9)));
            Ok(bench(self.id(), m))
        })
    }
}
register_bench!(SearchDataSkip);

// ---- READ side: bloom-pruned POINT LOOKUP (the 5–50× point-lookup win) -------
// Isolates the written-bloom read path (`Table::lookup` → `read::lookup_gatling`,
// which probes each key column's Parquet bloom filter and decodes only the
// surviving row groups). Two tables with IDENTICAL compression + row-group
// layout are built; the ONLY difference is a per-column bloom on `symbol`. A
// point lookup on the bloom table skips every row group the key can't be in and
// decodes one; the no-bloom table must decode every row group of every file. The
// gap IS the bloom win. Both must resolve the SAME row (bloom never drops a
// present key) and both must return `None` for a definitely-absent key.
fn row_i64(b: &skade::arrow_array::RecordBatch, col: &str) -> i64 {
    use skade::arrow_array::{Array, Int64Array};
    b.column_by_name(col)
        .unwrap()
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap()
        .value(0)
}

struct SearchPointLookup;
impl Bencher for SearchPointLookup {
    fn id(&self) -> &'static str { "search_point_lookup" }
    fn run(&self) -> Result<BenchResult> {
        rt().block_on(async {
            use skade::Scalar;
            let (repos, rows) = search_params();
            let rg = 8192usize;

            let bloom_tmp = factory::tempdir_in(&factory::nvme_dir())?;
            let bloom_wh = skade::open(bloom_tmp.path().join("lake")).await?;
            let (bloom_t, _) = search_build(
                &bloom_wh, "bloom",
                skade::WriteProps::new(skade::Compression::ZSTD(Default::default()))
                    .bloom_columns(["symbol"])
                    .row_group_size(rg),
                repos, rows,
            ).await?;

            // Baseline: same layout + codec, NO bloom — so the only variable is
            // whether the point lookup can prune row groups.
            let plain_tmp = factory::tempdir_in(&factory::nvme_dir())?;
            let plain_wh = skade::open(plain_tmp.path().join("lake")).await?;
            let (plain_t, _) = search_build(
                &plain_wh, "plain",
                skade::WriteProps::new(skade::Compression::ZSTD(Default::default()))
                    .row_group_size(rg),
                repos, rows,
            ).await?;

            // A symbol living in exactly one repo's file (one row group).
            let sym = format!("SYM{:08}", ((repos / 2) * rows) as i64 + (rows as i64 / 2));
            let key = [("symbol", Scalar::Str(sym.clone()))];

            // Correctness: identical row from both paths; absent key ⇒ None on both.
            let bloom_row = bloom_t.lookup(&key, None).await?.expect("symbol present (bloom)");
            let plain_row = plain_t.lookup(&key, None).await?.expect("symbol present (plain)");
            anyhow::ensure!(
                row_i64(&bloom_row, "value") == row_i64(&plain_row, "value"),
                "bloom and plain lookups must resolve the same row"
            );
            let absent = [("symbol", Scalar::Str("SYM-DEFINITELY-ABSENT".to_string()))];
            anyhow::ensure!(
                bloom_t.lookup(&absent, None).await?.is_none(),
                "a definitely-absent key must resolve to None"
            );

            let iters = env_usize("SEARCH_LOOKUP_ITERS", 20).max(1);
            let (mut bloom_ns, mut plain_ns) = (0u128, 0u128);
            for _ in 0..iters {
                let a = Instant::now();
                let _ = bloom_t.lookup(&key, None).await?;
                bloom_ns += a.elapsed().as_nanos();
                let b = Instant::now();
                let _ = plain_t.lookup(&key, None).await?;
                plain_ns += b.elapsed().as_nanos();
            }
            let bloom_us = (bloom_ns as f64 / iters as f64) / 1e3;
            let plain_us = (plain_ns as f64 / iters as f64) / 1e3;

            let mut m = Map::new();
            m.insert("ops_sec".into(), json!(if bloom_us > 0.0 { 1e6 / bloom_us } else { 0.0 }));
            m.insert("bloom_lookup_us".into(), json!(bloom_us));
            m.insert("plain_lookup_us".into(), json!(plain_us));
            m.insert("lookup_speedup_x".into(), json!(plain_us / bloom_us.max(1e-9)));
            m.insert("repos".into(), json!(repos as f64));
            m.insert("rows_per_repo".into(), json!(rows as f64));
            m.insert("row_group_size".into(), json!(rg as f64));
            Ok(bench(self.id(), m))
        })
    }
}
register_bench!(SearchPointLookup);

// ---- WRITE side: partition-scan accelerator (uniform-collapse) --------------
// Times the `partition_key_for` single-partition proof on the identity-partition
// write hot path: the offsets+`memcmp` uniform-collapse (`uniform_str_value`) vs
// the naive per-row `value(i)` scan it replaces, over one uniform string column.
// A/B in-proc via the `skade::bench_partition` bench hook (feature `bench`), the
// same pattern as `skade_catalog_key_build`. LIGHT by default; the heavy N sweep
// goes to the quiet bench box via `BENCH_PARTITION_ROWS` (Loki/Odin).
struct PartitionKeyScan;
impl Bencher for PartitionKeyScan {
    fn id(&self) -> &'static str { "skade_partition_key_scan" }
    fn run(&self) -> Result<BenchResult> {
        use std::hint::black_box;
        use skade::arrow_array::StringArray;
        use skade::bench_partition::{naive_str_value, uniform_str_value};

        let rows = env_usize("BENCH_PARTITION_ROWS", 250_000);
        let iters = env_usize("BENCH_PARTITION_ITERS", 200);
        // The identity-partition write shape: one repo value across every row.
        let col = StringArray::from(vec!["repo42"; rows]);

        // Both must agree on the value for the uniform column (fast == naive).
        anyhow::ensure!(
            uniform_str_value(&col) == naive_str_value(&col) && uniform_str_value(&col) == Some("repo42"),
            "fast and naive partition scans must agree on the uniform value"
        );

        let time = |f: &dyn Fn() -> usize| -> f64 {
            let warm = (iters / 10).max(1);
            for _ in 0..warm { black_box(f()); }
            let t = Instant::now();
            let mut s = 0usize;
            for _ in 0..iters { s = s.wrapping_add(black_box(f())); }
            black_box(s);
            t.elapsed().as_nanos() as f64 / iters as f64
        };
        let fast_ns = time(&|| uniform_str_value(&col).map(|s| s.len()).unwrap_or(0));
        let naive_ns = time(&|| naive_str_value(&col).map(|s| s.len()).unwrap_or(0));

        let mut m = Map::new();
        m.insert("ops_sec".into(), json!(if fast_ns > 0.0 { 1e9 / fast_ns } else { 0.0 }));
        m.insert("fast_ns_per_scan".into(), json!(fast_ns));
        m.insert("naive_ns_per_scan".into(), json!(naive_ns));
        m.insert("speedup_x".into(), json!(naive_ns / fast_ns.max(1e-9)));
        m.insert("rows".into(), json!(rows as f64));
        Ok(bench(self.id(), m))
    }
}
register_bench!(PartitionKeyScan);

// ==== OURS vs RIVALS — skade vs reference Iceberg vs raw Parquet =============
// A FAIR, single-dataset head-to-head of three write+read data planes over ONE
// identical dataset, ONE storage root, and (for skade & Iceberg) the SAME
// embedded RedbCatalog — so the ONLY variable is the data-plane engine:
//
//   • skade    — ours: `skade::Table::{ingest,read}` (custom encode + zero-copy
//                 recast + commit path).
//   • iceberg  — rival: upstream iceberg-rust's stock writer stack
//                 (`DataFileWriterBuilder` + `ParquetWriterBuilder` + `fast_append`)
//                 and stock scan (`table.scan()…to_arrow()`), driven over the
//                 *same* RedbCatalog + LocalFsStorageFactory (`data::ingest` /
//                 `data::scan_count`). Holding the catalog + storage constant means
//                 the delta is purely skade's data-plane vs vanilla Iceberg's.
//   • parquet  — rival (the floor): raw `parquet::arrow::ArrowWriter` files with
//                 NO catalog / NO snapshots / NO ACID, read back with
//                 `ParquetRecordBatchReaderBuilder`. The bare columnar I/O cost.
//
// Fairness controls: identical deterministic dataset (`data::synthetic_batches`,
// byte-for-byte the same for every engine); identical file/commit cadence
// (`commit_every` batches → one data file, one commit); SERIAL single-writer for
// all three (skade's parallel `ingest_parallel` is deliberately NOT used here so
// parallelism is held constant); one warmup pass + median of `OXR_ITERS` timed
// passes; a FRESH table + tempdir per pass; and a correctness gate — every pass
// must scan back exactly the rows it wrote or the bench fails. Storage root is the
// NVMe scratch by default, RAM (`/dev/shm`) with `OXR_RAM=1`.
//
// Env: OXR_ROWS (default 1_000_000), OXR_BATCH (50_000), OXR_COMMIT_EVERY (8),
// OXR_ITERS (5), OXR_RAM=1 (tmpfs root).

use std::path::Path;
use std::time::Duration as OxrDuration;

struct OxrParams {
    rows: usize,
    batch: usize,
    commit_every: usize,
    iters: usize,
    ram: bool,
}

fn oxr_params() -> OxrParams {
    OxrParams {
        rows: env_usize("OXR_ROWS", 1_000_000),
        batch: env_usize("OXR_BATCH", 50_000),
        commit_every: env_usize("OXR_COMMIT_EVERY", 8).max(1),
        iters: env_usize("OXR_ITERS", 5).max(1),
        ram: std::env::var("OXR_RAM").is_ok(),
    }
}

fn oxr_root(ram: bool) -> std::path::PathBuf {
    if ram { factory::ram_dir() } else { factory::nvme_dir() }
}

/// The one dataset every engine writes — deterministic, so all three see
/// byte-identical rows.
fn oxr_dataset(p: &OxrParams) -> Result<Vec<arrow_array::RecordBatch>> {
    let schema = data::node_arrow_schema_standalone()?;
    Ok(data::synthetic_batches(schema, p.rows, p.batch))
}

fn oxr_median(mut v: Vec<OxrDuration>) -> f64 {
    v.sort_unstable();
    v[v.len() / 2].as_secs_f64()
}

/// Process CPU-seconds consumed so far (Linux `/proc/self/stat` `utime`+`stime`,
/// clock ticks ÷ 100). Sampled around a timed region, `Δcpu / Δwall` is the
/// **average number of cores this process kept busy** — the core-saturation
/// number the warehouse needs to see the gatling all-core encode is real (and
/// which `oxr_metrics` previously omitted, leaving the run core-invisible).
fn proc_cpu_secs() -> f64 {
    // Field 2 (comm) can contain spaces/parens, so split *after* the trailing
    // ')': field 3 (state) is then index 0, utime (14) → 11, stime (15) → 12.
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let Some(i) = s.rfind(')') else { return 0.0 };
    let f: Vec<&str> = s[i + 1..].split_whitespace().collect();
    let utime: f64 = f.get(11).and_then(|x| x.parse().ok()).unwrap_or(0.0);
    let stime: f64 = f.get(12).and_then(|x| x.parse().ok()).unwrap_or(0.0);
    (utime + stime) / 100.0
}

/// Total logical cores on the box (denominator for `core_saturation`).
fn cores_total() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Run `pass` once as warmup (row-count checked), then `iters` timed passes;
/// return (median_write_secs, median_read_secs, cores_busy) — where `cores_busy`
/// is the avg cores this process kept busy across the timed passes (Δcpu/Δwall),
/// the core-saturation number that proves the gatling all-core encode is real.
/// Each pass returns (write, read, rows_scanned_back) and MUST scan back exactly
/// `expect` rows.
fn oxr_measure(
    iters: usize,
    expect: u64,
    mut pass: impl FnMut() -> Result<(OxrDuration, OxrDuration, u64)>,
) -> Result<(f64, f64, f64)> {
    let (_, _, warm) = pass()?;
    anyhow::ensure!(warm == expect, "warmup scanned {warm} rows, expected {expect}");
    let mut ws = Vec::with_capacity(iters);
    let mut rs = Vec::with_capacity(iters);
    // Sample process CPU + wall across the timed passes → average cores busy.
    let cpu0 = proc_cpu_secs();
    let wall0 = std::time::Instant::now();
    for _ in 0..iters {
        let (w, r, got) = pass()?;
        anyhow::ensure!(got == expect, "pass scanned {got} rows, expected {expect}");
        ws.push(w);
        rs.push(r);
    }
    let wall = wall0.elapsed().as_secs_f64();
    let cores_busy = if wall > 0.0 { (proc_cpu_secs() - cpu0) / wall } else { 0.0 };
    Ok((oxr_median(ws), oxr_median(rs), cores_busy))
}

fn oxr_metrics(p: &OxrParams, write_s: f64, read_s: f64, cores_busy: f64) -> Map<String, Value> {
    let rows = p.rows as f64;
    let total = cores_total();
    let mut m = Map::new();
    m.insert("write_rows_per_sec".into(), json!(rows / write_s.max(1e-9)));
    m.insert("read_rows_per_sec".into(), json!(rows / read_s.max(1e-9)));
    m.insert("write_ms".into(), json!(write_s * 1e3));
    m.insert("read_ms".into(), json!(read_s * 1e3));
    m.insert("rows".into(), json!(rows));
    m.insert("batches".into(), json!(p.rows.div_ceil(p.batch.max(1)) as f64));
    m.insert("commit_every".into(), json!(p.commit_every as f64));
    m.insert("iters".into(), json!(p.iters as f64));
    m.insert("storage".into(), json!(if p.ram { "ram" } else { "nvme" }));
    // Core-saturation telemetry (avg cores this process kept busy over the timed
    // passes) — persisted so the warehouse sees whether the run saturated the box.
    m.insert("cores_busy".into(), json!(cores_busy));
    m.insert("cores_used".into(), json!(cores_busy));
    m.insert("cores_total".into(), json!(total as f64));
    m.insert("core_saturation".into(), json!(cores_busy / total.max(1) as f64));
    // Headline = write throughput (the primary ingest story); read is the second column.
    m.insert("rows_per_sec".into(), json!(rows / write_s.max(1e-9)));
    m
}

/// skade (ours): the flagship **no-barrier gatling pipeline**
/// (`skade::Table::ingest_pipelined`) — the ONE fork-join engine (znippy-zoomies
/// `gatling_forkjoin`) fans the Parquet encode across all cores while a single
/// sequential writer commits, overlapped through a bounded channel. Each input
/// batch becomes its own file so the encode has per-core fan-out (that is what
/// drives `cores_busy` toward `cores_total`). Read-back is the all-core
/// `skade::Table::read` scan. This is the core-saturation story the oxr mashup
/// exists to show — a serial `Table::ingest` here would pin one core and violate
/// the core-saturation law.
struct OxrSkade;
impl Bencher for OxrSkade {
    fn id(&self) -> &'static str { "oxr_skade" }
    fn run(&self) -> Result<BenchResult> {
        let p = oxr_params();
        let root = oxr_root(p.ram);
        let batches = oxr_dataset(&p)?;
        let rt = rt();
        let expect = p.rows as u64;
        let schema = data::node_arrow_schema_standalone()?;
        // Bounded-channel depth = cores, so up to `cores_total` files are encoded
        // in flight ahead of the lone writer (the full channel is the backpressure).
        let depth = cores_total();
        let (write_s, read_s, cores_busy) = oxr_measure(p.iters, expect, || {
            let tmp = factory::tempdir_in(&root)?;
            rt.block_on(async {
                let wh = skade::open(tmp.path().join("lake")).await?;
                let mut table = wh.create_table("t", schema.as_ref()).await?;
                // One file per batch → per-core encode fan-out across the gatling pool.
                let groups: Vec<Vec<_>> = batches.iter().map(|b| vec![b.clone()]).collect();
                let w = Instant::now();
                table.ingest_pipelined(groups, p.commit_every, depth).await?;
                let wd = w.elapsed();
                let r = Instant::now();
                let got = table.read().await?;
                let rd = r.elapsed();
                let rows: u64 = got.iter().map(|b| b.num_rows() as u64).sum();
                Ok((wd, rd, rows))
            })
        })?;
        Ok(bench(self.id(), oxr_metrics(&p, write_s, read_s, cores_busy)))
    }
}
register_bench!(OxrSkade);

/// Reference Iceberg (rival): upstream iceberg-rust stock writer + scan over the
/// SAME RedbCatalog + LocalFsStorageFactory (`data::ingest` / `data::scan_count`).
struct OxrIceberg;
impl Bencher for OxrIceberg {
    fn id(&self) -> &'static str { "oxr_iceberg" }
    fn run(&self) -> Result<BenchResult> {
        let p = oxr_params();
        let root = oxr_root(p.ram);
        let batches = oxr_dataset(&p)?;
        let rt = rt();
        let expect = p.rows as u64;
        let (write_s, read_s, cores_busy) = oxr_measure(p.iters, expect, || {
            let tmp = factory::tempdir_in(&root)?;
            rt.block_on(async {
                let cat = factory::embedded_in(&tmp).await?;
                let ns = NamespaceIdent::new("bench".to_string());
                if !cat.namespace_exists(&ns).await.unwrap_or(false) {
                    cat.create_namespace(&ns, Default::default()).await?;
                }
                let ident = TableIdent::new(ns, "t".to_string());
                let table = data::create_node_table(&cat, &ident).await?;
                let w = Instant::now();
                let (table, _stats) =
                    data::ingest(&cat, table, batches.iter().cloned(), p.commit_every).await?;
                let wd = w.elapsed();
                let (rows, rd) = data::scan_count(&table).await?;
                Ok((wd, rd, rows))
            })
        })?;
        Ok(bench(self.id(), oxr_metrics(&p, write_s, read_s, cores_busy)))
    }
}
register_bench!(OxrIceberg);

/// Raw Parquet (rival / floor): `parquet::arrow::ArrowWriter` files, no catalog /
/// no snapshots, read back with `ParquetRecordBatchReaderBuilder`.
struct OxrParquet;
impl Bencher for OxrParquet {
    fn id(&self) -> &'static str { "oxr_parquet" }
    fn run(&self) -> Result<BenchResult> {
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        use parquet::arrow::ArrowWriter;
        use parquet::file::properties::WriterProperties;
        let p = oxr_params();
        let root = oxr_root(p.ram);
        let batches = oxr_dataset(&p)?;
        let expect = p.rows as u64;
        let schema = batches.first().map(|b| b.schema()).ok_or_else(|| anyhow::anyhow!("empty dataset"))?;
        let pass = || -> Result<(OxrDuration, OxrDuration, u64)> {
            let tmp = factory::tempdir_in(&root)?;
            let dir: &Path = tmp.path();
            // WRITE — one file per `commit_every` batches (matches the catalog cadence).
            let w = Instant::now();
            let mut files = Vec::new();
            for (gi, chunk) in batches.chunks(p.commit_every).enumerate() {
                let path = dir.join(format!("part-{gi:05}.parquet"));
                let file = std::fs::File::create(&path)?;
                let mut wr = ArrowWriter::try_new(file, schema.clone(), Some(WriterProperties::builder().build()))?;
                for b in chunk {
                    wr.write(b)?;
                }
                wr.close()?;
                files.push(path);
            }
            let wd = w.elapsed();
            // READ — full scan every file back to Arrow, count rows.
            let r = Instant::now();
            let mut rows = 0u64;
            for path in &files {
                let file = std::fs::File::open(path)?;
                let rdr = ParquetRecordBatchReaderBuilder::try_new(file)?.build()?;
                for b in rdr {
                    rows += b?.num_rows() as u64;
                }
            }
            let rd = r.elapsed();
            Ok((wd, rd, rows))
        };
        let (write_s, read_s, cores_busy) = oxr_measure(p.iters, expect, pass)?;
        Ok(bench(self.id(), oxr_metrics(&p, write_s, read_s, cores_busy)))
    }
}
register_bench!(OxrParquet);
