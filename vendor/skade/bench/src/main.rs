//! Catalog benchmark runner.
//!
//! Usage:
//!   catalog-bench embedded
//!   catalog-bench nessie  [uri] [warehouse]
//!   catalog-bench polaris [uri] [warehouse]
//!
//! `BENCH_QUICK=1` selects the small workload. Results are emitted as JSONL
//! (one scenario per line) so they can be appended to `bench_history.jsonl`
//! and folded into the README table, exactly like holger.

use skade_katalog_bench::{data, factory, pipeline, scenarios};
#[cfg(feature = "rest")]
use skade_katalog_bench::rest_shim;

#[cfg(feature = "rest")]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use iceberg::{Catalog, NamespaceIdent, TableCreation, TableIdent};
use scenarios::{CatalogResult, Scale};
use tempfile::TempDir;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("embedded");
    let scale = if std::env::var("BENCH_QUICK").is_ok() {
        Scale::quick()
    } else {
        Scale::full()
    };

    match mode {
        "embedded" => run_embedded(&scale).await?,
        #[cfg(feature = "rest")]
        "skade-rest" => run_skade_rest(&scale).await?,
        #[cfg(feature = "rest")]
        "nessie" => {
            let uri = arg_or(&args, 2, "http://localhost:19120/iceberg");
            let wh = arg_or(&args, 3, "warehouse");
            run_rest("nessie", &uri, &wh, &scale).await?;
        }
        #[cfg(feature = "rest")]
        "polaris" => {
            let uri = arg_or(&args, 2, "http://localhost:8181/api/catalog");
            let wh = arg_or(&args, 3, "warehouse");
            run_rest("polaris", &uri, &wh, &scale).await?;
        }
        #[cfg(not(feature = "rest"))]
        "skade-rest" | "nessie" | "polaris" => anyhow::bail!(
            "mode {mode:?} needs the Iceberg-REST client — rebuild with `--features rest` \
             (note: it links the crates.io arrow-57 iceberg, not the arrow-58 fork)"
        ),
        // Data-plane: ingest rows + scan back. `data <target> [pbf]`.
        // target: skade-file | skade-s3 | nessie | polaris
        "data" => {
            let target = arg_or(&args, 2, "skade-s3");
            let pbf = args.get(3).cloned();
            run_data(&target, pbf.as_deref()).await?;
        }
        // Single-writer/many-processor ingest (znippy pattern). `data-pipe <target> [pbf]`.
        "data-pipe" => {
            let target = arg_or(&args, 2, "skade-file");
            let pbf = args.get(3).cloned();
            run_data_pipe(&target, pbf.as_deref()).await?;
        }
        // Commit-bursty write path — where group-commit (nornir's catalog lever)
        // shows. `commit-burst <target>`.
        "commit-burst" => {
            let target = arg_or(&args, 2, "skade-file");
            run_commit_burst(&target).await?;
        }
        other => anyhow::bail!(
            "unknown mode {other:?}; expected embedded|skade-rest|nessie|polaris|data|data-pipe|commit-burst"
        ),
    }
    Ok(())
}

fn arg_or(args: &[String], i: usize, default: &str) -> String {
    args.get(i).cloned().unwrap_or_else(|| default.to_string())
}

fn emit(target: &str, r: &CatalogResult) {
    let mut v = r.to_json();
    v["target"] = serde_json::json!(target);
    println!("{v}");
}

fn emit_data(target: &str, name: &str, body: serde_json::Value) {
    let mut v = body;
    v["name"] = serde_json::json!(name);
    v["target"] = serde_json::json!(target);
    println!("{v}");
}

fn data_params() -> (usize, usize, usize) {
    let env = |k: &str, d: usize| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let quick = std::env::var("BENCH_QUICK").is_ok();
    let rows = env("BENCH_DATA_ROWS", if quick { 20_000 } else { 500_000 });
    let per_batch = env("BENCH_DATA_BATCH", 50_000);
    let per_commit = env("BENCH_DATA_BATCHES_PER_COMMIT", 1);
    (rows, per_batch, per_commit)
}

async fn run_embedded(scale: &Scale) -> Result<()> {
    eprintln!("# skade-katalog embedded: seeding {} tables…", scale.tables);
    let (cat, _tmp) = factory::embedded().await?;
    let ns = scenarios::seed(&cat, scale).await?;

    emit("nornir-embedded", &scenarios::table_exists_latency(&cat, &ns, scale).await);
    emit("nornir-embedded", &scenarios::load_table_latency(&cat, &ns, scale).await);
    emit("nornir-embedded", &resolve_metadata_latency(&cat, &ns, scale).await);
    emit("nornir-embedded", &scenarios::create_table_latency(&cat, &ns, 1_000).await?);

    let arc: Arc<dyn Catalog> = Arc::new(cat);
    for r in scenarios::load_table_throughput(arc, &ns, scale).await {
        emit("nornir-embedded", &r);
    }
    Ok(())
}

/// nornir behind its own axum Iceberg-REST shim — apples-to-apples REST-vs-REST
/// against Nessie/Polaris, all in-process (no container needed).
#[cfg(feature = "rest")]
async fn run_skade_rest(scale: &Scale) -> Result<()> {
    let (cat, _tmp) = factory::embedded().await?;
    let bound = rest_shim::spawn(cat, "127.0.0.1:0".parse::<SocketAddr>().unwrap()).await?;
    let uri = format!("http://{bound}");
    eprintln!("# skade-rest shim @ {uri}: seeding {} tables…", scale.tables);

    let rest = factory::rest(&uri, "warehouse").await?;
    let ns = scenarios::seed(&rest, scale).await?;
    emit("skade-rest", &scenarios::table_exists_latency(&rest, &ns, scale).await);
    emit("skade-rest", &scenarios::load_table_latency(&rest, &ns, scale).await);
    emit("skade-rest", &scenarios::create_table_latency(&rest, &ns, 1_000).await?);
    let arc: Arc<dyn Catalog> = Arc::new(rest);
    for r in scenarios::load_table_throughput(arc, &ns, scale).await {
        emit("skade-rest", &r);
    }
    Ok(())
}

#[cfg(feature = "rest")]
async fn run_rest(target: &str, uri: &str, warehouse: &str, scale: &Scale) -> Result<()> {
    eprintln!("# {target} @ {uri}", );
    let cat = factory::rest(uri, warehouse).await?;
    let ns = scenarios::seed_namespace(&cat).await?;

    // Pure catalog RPC latency — always works (no storage involved).
    emit(target, &scenarios::table_exists_latency(&cat, &ns, scale).await);

    // Table scenarios need object storage the server accepts. Some REST servers
    // (e.g. Nessie) reject a local `file:` warehouse; tolerate that and report.
    match scenarios::seed(&cat, scale).await {
        Ok(ns) => {
            emit(target, &scenarios::load_table_latency(&cat, &ns, scale).await);
            if let Ok(r) = scenarios::create_table_latency(&cat, &ns, 1_000).await {
                emit(target, &r);
            }
            let arc: Arc<dyn Catalog> = Arc::new(cat);
            for r in scenarios::load_table_throughput(arc, &ns, scale).await {
                emit(target, &r);
            }
        }
        Err(e) => {
            eprintln!("# {target}: table scenarios skipped — server rejected table create: {e}");
        }
    }
    Ok(())
}

/// Data-plane run: create a node table, ingest rows (synthetic, or OSM PBF if a
/// path is given), commit via `fast_append`, then full-scan back. `target`
/// selects the catalog + storage: skade-file (local FS), skade-s3 / nessie /
/// polaris (shared RustFS S3 warehouse).
async fn run_data(target: &str, pbf: Option<&str>) -> Result<()> {
    let (rows, per_batch, per_commit) = data_params();
    let ns = NamespaceIdent::new("bench".to_string());
    let ident = TableIdent::new(ns.clone(), "osm_nodes".to_string());

    let (cat, _tmp) = setup_catalog(target).await?;

    eprintln!("# data[{target}]: rows={rows} batch={per_batch} batches/commit={per_commit} source={}",
        pbf.map(|_| "osm").unwrap_or("synthetic"));

    if !cat.namespace_exists(&ns).await.unwrap_or(false) {
        cat.create_namespace(&ns, Default::default()).await?;
    }
    let _ = &ident; // (single-table ident no longer used directly)

    // Concurrency: N parallel writers, each into its own table, to actually use
    // the box's cores. Default to all of them. The OSM source is read once
    // (bounded) and sharded across the writers.
    let threads = std::env::var("BENCH_DATA_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
        .max(1);

    // Each writer gets its own ~equal row-share so all cores stay busy. OSM is
    // parsed once into a shared column set and sliced; synthetic is generated
    // per writer.
    let arrow_schema = data::node_arrow_schema_standalone()?;
    let per_thread = rows.div_ceil(threads).max(1);
    let osm_cols = match pbf {
        Some(p) => Some(Arc::new(data::osm_columns(p, rows)?)),
        None => None,
    };

    eprintln!("# data[{target}]: {threads} parallel writers, ~{per_thread} rows each");

    let wall = Instant::now();
    let mut handles = Vec::with_capacity(threads);
    for tid in 0..threads {
        let cat = Arc::clone(&cat);
        let ns = ns.clone();
        let arrow_schema = arrow_schema.clone();
        let osm_cols = osm_cols.clone();
        handles.push(tokio::spawn(async move {
            let batches = match &osm_cols {
                Some(cols) => cols.slice_batches(tid * per_thread, per_thread, per_batch, arrow_schema)?,
                None => data::synthetic_batches(arrow_schema, per_thread, per_batch),
            };
            let ident = TableIdent::new(ns.clone(), format!("osm_nodes_{tid}"));
            if cat.table_exists(&ident).await.unwrap_or(false) {
                let _ = cat.drop_table(&ident).await;
            }
            let creation = TableCreation::builder()
                .name(format!("osm_nodes_{tid}"))
                .schema(data::node_schema())
                .build();
            let table = cat.create_table(&ns, creation).await?;
            let (table, stats) = data::ingest(cat.as_ref(), table, batches, per_commit).await?;
            let (scanned, _) = data::scan_count(&table).await?;
            Ok::<(u64, u64, u64), anyhow::Error>((stats.rows, stats.commits, scanned))
        }));
    }
    let (mut tot_rows, mut tot_commits, mut tot_scanned) = (0u64, 0u64, 0u64);
    for h in handles {
        let (r, c, s) = h.await??;
        tot_rows += r;
        tot_commits += c;
        tot_scanned += s;
    }
    let secs = wall.elapsed().as_secs_f64().max(1e-9);

    emit_data(target, "data_ingest", serde_json::json!({
        "threads": threads,
        "rows": tot_rows,
        "commits": tot_commits,
        "rows_per_sec": tot_rows as f64 / secs,
        "commits_per_sec": tot_commits as f64 / secs,
        "elapsed_ms": wall.elapsed().as_millis(),
    }));
    emit_data(target, "data_scan_total", serde_json::json!({
        "threads": threads,
        "rows": tot_scanned,
    }));
    eprintln!(
        "# {target}: {threads} writers ingested {tot_rows} rows / {tot_commits} commits, scanned {tot_scanned}"
    );
    Ok(())
}

/// Whether a target's data files live in object storage (S3/RustFS), where
/// per-PUT/GET latency is the bottleneck and the ingest/scan paths need
/// concurrency. Local file targets (`skade-file`/`-nvme`/`-ram`) return `false`:
/// their sequential single-writer / single-GET paths are already optimal.
fn is_s3_target(target: &str) -> bool {
    matches!(target, "skade-s3" | "nessie" | "polaris")
}

/// Build the catalog + storage for a data-plane target (shared by `data`,
/// `data-pipe`, and `commit-burst`).
async fn setup_catalog(target: &str) -> Result<(Arc<dyn Catalog>, Option<TempDir>)> {
    Ok(match target {
        "skade-file" | "skade-nvme" => {
            let (c, t) = factory::embedded().await?;
            (Arc::new(c) as Arc<dyn Catalog>, Some(t))
        }
        // Second file destination: RAM-backed tmpfs (/dev/shm).
        "skade-ram" => {
            let tmp = factory::tempdir_in(&factory::ram_dir())?;
            let c = factory::embedded_in(&tmp).await?;
            (Arc::new(c) as Arc<dyn Catalog>, Some(tmp))
        }
        #[cfg(feature = "s3")]
        "skade-s3" => {
            let (c, t) = factory::embedded_s3().await?;
            (Arc::new(c) as Arc<dyn Catalog>, Some(t))
        }
        #[cfg(all(feature = "s3", feature = "rest"))]
        "nessie" => {
            let uri = std::env::var("BENCH_REST_URI")
                .unwrap_or_else(|_| "http://localhost:19120/iceberg".to_string());
            (Arc::new(factory::rest_s3(&uri, "warehouse").await?) as Arc<dyn Catalog>, None)
        }
        #[cfg(all(feature = "s3", feature = "rest"))]
        "polaris" => {
            let uri = std::env::var("BENCH_REST_URI")
                .unwrap_or_else(|_| "http://localhost:8181/api/catalog".to_string());
            (Arc::new(factory::rest_s3(&uri, "warehouse").await?) as Arc<dyn Catalog>, None)
        }
        #[cfg(not(feature = "s3"))]
        "skade-s3" => anyhow::bail!(
            "target {target:?} needs the S3 backend — rebuild with `--features s3`"
        ),
        #[cfg(not(feature = "rest"))]
        "nessie" | "polaris" => anyhow::bail!(
            "target {target:?} needs the Iceberg-REST client — rebuild with `--features rest`"
        ),
        other => anyhow::bail!(
            "unknown target {other:?}; expected skade-file|skade-nvme|skade-ram|skade-s3|nessie|polaris"
        ),
    })
}

/// Single-writer / many-processor ingest: all cores encode Parquet in parallel,
/// one writer streams files sequentially + commits via `fast_append`. Backend-
/// agnostic (run it on every target for a fair comparison). Validates the
/// round-trip by scanning the rows back. See `bench/src/pipeline.rs`.
async fn run_data_pipe(target: &str, pbf: Option<&str>) -> Result<()> {
    let (rows, per_batch, _per_commit) = data_params();
    let env = |k: &str, d: usize| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let depth = env("BENCH_PIPE_DEPTH", 8);
    let files_per_commit = env("BENCH_PIPE_FILES_PER_COMMIT", 8);
    // Write concurrency: object stores (S3/Nessie/Polaris) are PUT-latency-bound,
    // so keep N PUTs in flight; local NVMe/RAM is sequential-optimal (1 writer).
    // Override the S3 fan-out with BENCH_PIPE_WRITE_CONCURRENCY.
    let write_concurrency = if is_s3_target(target) {
        env("BENCH_PIPE_WRITE_CONCURRENCY", 16)
    } else {
        1
    };

    let (cat, _tmp) = setup_catalog(target).await?;
    let ns = NamespaceIdent::new("bench".to_string());
    if !cat.namespace_exists(&ns).await.unwrap_or(false) {
        cat.create_namespace(&ns, Default::default()).await?;
    }
    let ident = TableIdent::new(ns.clone(), "osm_nodes_pipe".to_string());
    if cat.table_exists(&ident).await.unwrap_or(false) {
        let _ = cat.drop_table(&ident).await;
    }
    let table = data::create_node_table(cat.as_ref(), &ident).await?;

    let arrow_schema = data::node_arrow_schema_standalone()?;
    // One Parquet file per batch (each batch is its own encode group).
    let batches = match pbf {
        Some(p) => data::osm_columns(p, rows)?.slice_batches(0, rows, per_batch, arrow_schema.clone())?,
        None => data::synthetic_batches(arrow_schema.clone(), rows, per_batch),
    };
    let groups: Vec<Vec<arrow_array::RecordBatch>> = batches.into_iter().map(|b| vec![b]).collect();
    eprintln!(
        "# data-pipe[{target}]: {} files, depth={depth}, files/commit={files_per_commit}, source={}",
        groups.len(),
        pbf.map(|_| "osm").unwrap_or("synthetic")
    );

    let (table, stats) = if write_concurrency > 1 {
        pipeline::run_concurrent_writer_ingest(
            Arc::clone(&cat),
            table,
            groups,
            arrow_schema,
            depth,
            files_per_commit,
            "pipe",
            write_concurrency,
        )
        .await?
    } else {
        pipeline::run_single_writer_ingest(
            Arc::clone(&cat),
            table,
            groups,
            arrow_schema,
            depth,
            files_per_commit,
            "pipe",
        )
        .await?
    };
    let (scanned, _) = data::scan_count(&table).await?;

    emit_data(target, "data_pipe_ingest", serde_json::json!({
        "encode_workers": stats.encode_workers,
        "write_concurrency": stats.write_concurrency,
        "peak_inflight": stats.peak_inflight,
        "rows": stats.rows,
        "files": stats.files,
        "commits": stats.commits,
        "bytes_written": stats.bytes_written,
        "rows_per_sec": stats.rows_per_sec(),
        "elapsed_ms": stats.elapsed.as_millis(),
        "scanned": scanned,
    }));
    eprintln!(
        "# data-pipe[{target}]: {} rows / {} files / {} commits ({:.2}M rows/s; wconc={} peak_inflight={}); scanned {}",
        stats.rows, stats.files, stats.commits, stats.rows_per_sec() / 1e6,
        stats.write_concurrency, stats.peak_inflight, scanned
    );
    if scanned != stats.rows {
        anyhow::bail!("scan mismatch: ingested {} rows but scanned {}", stats.rows, scanned);
    }
    Ok(())
}

/// Commit-bursty write path: `tables` tables, each driven with `per_table`
/// metadata-only property commits, all concurrently. This is where nornir's
/// group-commit coalesces many commits into one redb txn/fsync — the catalog
/// write lever (storage-bound bulk ingest does not exercise it). Generic over
/// the catalog, so run it on every target for a fair comparison.
async fn run_commit_burst(target: &str) -> Result<()> {
    let env = |k: &str, d: usize| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let quick = std::env::var("BENCH_QUICK").is_ok();
    let tables = env("BENCH_BURST_TABLES", if quick { 8 } else { 32 });
    let per_table = env("BENCH_BURST_COMMITS", if quick { 25 } else { 100 });

    let (cat, _tmp) = setup_catalog(target).await?;
    let ns = NamespaceIdent::new("burst".to_string());
    if !cat.namespace_exists(&ns).await.unwrap_or(false) {
        cat.create_namespace(&ns, Default::default()).await?;
    }
    // Pre-create tables; their creation cost is excluded from the measurement.
    let mut tabs = Vec::with_capacity(tables);
    for t in 0..tables {
        let ident = TableIdent::new(ns.clone(), format!("burst_{t:03}"));
        if cat.table_exists(&ident).await.unwrap_or(false) {
            let _ = cat.drop_table(&ident).await;
        }
        tabs.push(data::create_node_table(cat.as_ref(), &ident).await?);
    }
    eprintln!("# commit-burst[{target}]: {tables} tables x {per_table} metadata commits each");

    let wall = Instant::now();
    let mut handles = Vec::with_capacity(tables);
    for table in tabs {
        let cat = Arc::clone(&cat);
        handles.push(tokio::spawn(async move {
            use iceberg::transaction::{ApplyTransactionAction, Transaction};
            let mut table = table;
            let mut lat = Vec::with_capacity(per_table);
            for i in 0..per_table {
                let tx = Transaction::new(&table);
                let action = tx
                    .update_table_properties()
                    .set("bench.seq".to_string(), i.to_string());
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
    all.sort_unstable();
    let pct = |q: f64| -> f64 {
        let idx = (((all.len().max(1) - 1) as f64) * q).round() as usize;
        all.get(idx).copied().unwrap_or(0) as f64 / 1000.0
    };
    let commits = all.len() as u64;
    emit_data(target, "commit_burst", serde_json::json!({
        "tables": tables,
        "commits": commits,
        "commits_per_sec": commits as f64 / secs,
        "p50_us": pct(0.50),
        "p99_us": pct(0.99),
        "p999_us": pct(0.999),
        "elapsed_ms": wall.elapsed().as_millis(),
    }));
    eprintln!(
        "# commit-burst[{target}]: {commits} commits, {:.0}/s, p50 {:.1}us p99 {:.1}us",
        commits as f64 / secs,
        pct(0.50),
        pct(0.99)
    );
    Ok(())
}

/// nornir-only fast path: `resolve_metadata` skips `Table::build()` (whose
/// per-call `ObjectCache` allocation dominates `load_table`). This is the true
/// catalog read speed and the basis for the future batch API.
async fn resolve_metadata_latency(
    cat: &skade_katalog::RedbCatalog,
    ns: &NamespaceIdent,
    scale: &Scale,
) -> CatalogResult {
    let n = scale.tables.max(1);
    for i in 0..100 {
        let _ = cat
            .resolve_metadata(&TableIdent::new(ns.clone(), format!("bench_t_{:06}", i % n)))
            .await;
    }
    let mut samples = Vec::with_capacity(scale.iters);
    let wall = Instant::now();
    for i in 0..scale.iters {
        let ident = TableIdent::new(ns.clone(), format!("bench_t_{:06}", i % n));
        let t = Instant::now();
        let _ = cat.resolve_metadata(&ident).await;
        samples.push(t.elapsed().as_nanos());
    }
    let mut samples_sorted = samples.clone();
    samples_sorted.sort_unstable();
    let ops = samples.len() as u64;
    let wall_ns = wall.elapsed().as_nanos();
    let pct = |q: f64| -> f64 {
        let idx = (((samples_sorted.len().max(1) - 1) as f64) * q).round() as usize;
        samples_sorted.get(idx).copied().unwrap_or(0) as f64 / 1000.0
    };
    let mean_us = if ops == 0 {
        0.0
    } else {
        (samples.iter().sum::<u128>() as f64 / ops as f64) / 1000.0
    };
    CatalogResult {
        name: "resolve_metadata.latency".to_string(),
        ops,
        ops_sec: if wall_ns > 0 { ops as f64 * 1e9 / wall_ns as f64 } else { 0.0 },
        min_us: samples_sorted.first().copied().unwrap_or(0) as f64 / 1000.0,
        mean_us,
        p50_us: pct(0.50),
        p90_us: pct(0.90),
        p99_us: pct(0.99),
        p999_us: pct(0.999),
        max_us: samples_sorted.last().copied().unwrap_or(0) as f64 / 1000.0,
    }
}
