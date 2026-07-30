//! Catalog benchmark scenarios — generic over `iceberg::Catalog`, so nornir
//! (embedded or REST-fronted), Nessie, and Polaris all run the identical code.
//!
//! Mirrors the `holger/bench-scenarios` shape (`Scale`, warmup + timed loop,
//! barrier-style concurrency) but adds **latency percentiles**, because a
//! catalog is a latency product, not just a throughput one.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::{Catalog, NamespaceIdent, TableCreation, TableIdent};

/// Tunable workload size. `quick` for smoke runs, `full` for real numbers.
#[derive(Debug, Clone)]
pub struct Scale {
    /// Number of tables seeded into the catalog.
    pub tables: usize,
    /// Read iterations per latency/throughput scenario.
    pub iters: usize,
    /// Concurrency levels measured for throughput.
    pub threads: Vec<usize>,
}

impl Scale {
    pub fn quick() -> Self {
        Self { tables: 200, iters: 5_000, threads: vec![1, 4, 16] }
    }
    pub fn full() -> Self {
        Self { tables: 10_000, iters: 50_000, threads: vec![1, 8, 32] }
    }
}

/// One scenario's measured result. `ops_sec` is the headline; percentiles are
/// in microseconds.
#[derive(Debug, Clone)]
pub struct CatalogResult {
    pub name: String,
    pub ops: u64,
    pub ops_sec: f64,
    pub min_us: f64,
    pub mean_us: f64,
    pub p50_us: f64,
    pub p90_us: f64,
    pub p99_us: f64,
    pub p999_us: f64,
    pub max_us: f64,
}

impl CatalogResult {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "ops": self.ops,
            "ops_sec": self.ops_sec,
            "min_us": self.min_us,
            "mean_us": self.mean_us,
            "p50_us": self.p50_us,
            "p90_us": self.p90_us,
            "p99_us": self.p99_us,
            "p999_us": self.p999_us,
            "max_us": self.max_us,
        })
    }
}

fn schema() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
        ])
        .build()
        .expect("schema")
}

fn table_name(i: usize) -> String {
    format!("bench_t_{i:06}")
}

/// Quantile from sorted nanosecond samples, returned in microseconds.
fn pct(sorted: &[u128], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (((sorted.len() - 1) as f64) * q).round() as usize;
    sorted[idx] as f64 / 1000.0
}

fn summarize(name: &str, mut samples_ns: Vec<u128>, wall_ns: u128) -> CatalogResult {
    samples_ns.sort_unstable();
    let ops = samples_ns.len() as u64;
    let ops_sec = if wall_ns == 0 {
        0.0
    } else {
        ops as f64 * 1_000_000_000.0 / wall_ns as f64
    };
    let mean_us = if ops == 0 {
        0.0
    } else {
        (samples_ns.iter().sum::<u128>() as f64 / ops as f64) / 1000.0
    };
    CatalogResult {
        name: name.to_string(),
        ops,
        ops_sec,
        min_us: samples_ns.first().copied().unwrap_or(0) as f64 / 1000.0,
        mean_us,
        p50_us: pct(&samples_ns, 0.50),
        p90_us: pct(&samples_ns, 0.90),
        p99_us: pct(&samples_ns, 0.99),
        p999_us: pct(&samples_ns, 0.999),
        max_us: samples_ns.last().copied().unwrap_or(0) as f64 / 1000.0,
    }
}

/// Create the namespace and `scale.tables` tables. Returns the namespace.
pub async fn seed(cat: &dyn Catalog, scale: &Scale) -> Result<NamespaceIdent> {
    let ns = NamespaceIdent::new("bench".to_string());
    if !cat.namespace_exists(&ns).await.unwrap_or(false) {
        cat.create_namespace(&ns, Default::default()).await?;
    }
    for i in 0..scale.tables {
        let ident = TableIdent::new(ns.clone(), table_name(i));
        if !cat.table_exists(&ident).await.unwrap_or(false) {
            let creation = TableCreation::builder()
                .name(table_name(i))
                .schema(schema())
                .build();
            cat.create_table(&ns, creation).await?;
        }
    }
    Ok(ns)
}

/// Create just the namespace (for catalogs whose table create needs object
/// storage we can't provide locally, e.g. Nessie with `file:` rejected).
pub async fn seed_namespace(cat: &dyn Catalog) -> Result<NamespaceIdent> {
    let ns = NamespaceIdent::new("bench".to_string());
    if !cat.namespace_exists(&ns).await.unwrap_or(false) {
        cat.create_namespace(&ns, Default::default()).await?;
    }
    Ok(ns)
}

/// Single-thread `table_exists` latency — a pure catalog read RPC with no
/// storage involvement, so it isolates the catalog server's round-trip cost and
/// works on every backend (including ones we can't create tables on locally).
pub async fn table_exists_latency(cat: &dyn Catalog, ns: &NamespaceIdent, scale: &Scale) -> CatalogResult {
    let n = scale.tables.max(1);
    for i in 0..100 {
        let _ = cat.table_exists(&TableIdent::new(ns.clone(), table_name(i % n))).await;
    }
    let mut samples = Vec::with_capacity(scale.iters);
    let wall = Instant::now();
    for i in 0..scale.iters {
        let ident = TableIdent::new(ns.clone(), table_name(i % n));
        let t = Instant::now();
        let _ = cat.table_exists(&ident).await;
        samples.push(t.elapsed().as_nanos());
    }
    summarize("table_exists.latency", samples, wall.elapsed().as_nanos())
}

/// Single-thread `load_table` latency over the seeded tables (warm).
pub async fn load_table_latency(cat: &dyn Catalog, ns: &NamespaceIdent, scale: &Scale) -> CatalogResult {
    let n = scale.tables.max(1);
    // Warmup.
    for i in 0..100 {
        let _ = cat.load_table(&TableIdent::new(ns.clone(), table_name(i % n))).await;
    }
    let mut samples = Vec::with_capacity(scale.iters);
    let wall = Instant::now();
    for i in 0..scale.iters {
        let ident = TableIdent::new(ns.clone(), table_name(i % n));
        let t = Instant::now();
        let _ = cat.load_table(&ident).await;
        samples.push(t.elapsed().as_nanos());
    }
    summarize("load_table.latency", samples, wall.elapsed().as_nanos())
}

/// Single-thread `create_table` latency (write path).
pub async fn create_table_latency(cat: &dyn Catalog, ns: &NamespaceIdent, count: usize) -> Result<CatalogResult> {
    let mut samples = Vec::with_capacity(count);
    let wall = Instant::now();
    for i in 0..count {
        let name = format!("write_t_{i:06}");
        let creation = TableCreation::builder().name(name).schema(schema()).build();
        let t = Instant::now();
        cat.create_table(ns, creation).await?;
        samples.push(t.elapsed().as_nanos());
    }
    Ok(summarize("create_table.latency", samples, wall.elapsed().as_nanos()))
}

/// Concurrent `load_table` throughput at each requested thread count.
pub async fn load_table_throughput(
    cat: Arc<dyn Catalog>,
    ns: &NamespaceIdent,
    scale: &Scale,
) -> Vec<CatalogResult> {
    let n = scale.tables.max(1);
    let per_thread = (scale.iters / scale.threads.iter().max().copied().unwrap_or(1).max(1)).max(1000);
    let mut out = Vec::new();
    for &threads in &scale.threads {
        let wall = Instant::now();
        let mut handles = Vec::new();
        for tid in 0..threads {
            let cat = Arc::clone(&cat);
            let ns = ns.clone();
            handles.push(tokio::spawn(async move {
                for i in 0..per_thread {
                    let idx = (i * 7 + tid * 1337) % n;
                    let _ = cat.load_table(&TableIdent::new(ns.clone(), table_name(idx))).await;
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        let total = (threads * per_thread) as u64;
        let secs = wall.elapsed().as_secs_f64();
        out.push(CatalogResult {
            name: format!("load_table.throughput.t{threads}"),
            ops: total,
            ops_sec: if secs > 0.0 { total as f64 / secs } else { 0.0 },
            min_us: 0.0,
            mean_us: 0.0,
            p50_us: 0.0,
            p90_us: 0.0,
            p99_us: 0.0,
            p999_us: 0.0,
            max_us: 0.0,
        });
    }
    out
}
