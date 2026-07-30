//! Throwaway A/B: how much of `load_table` is the per-`Table` ObjectCache alloc?
//!
//! Times the warm read three ways, all over a single pre-seeded table:
//!   1. load_table (full)         — Catalog::load_table (builds a default cache)
//!   2. Table::build default      — build only, metadata pre-resolved
//!   3. Table::build disable_cache — build only, capacity-0 moka
//!   4. resolve_metadata (floor)  — no Table at all
//!
//! Run: cargo run --release --example cache_ab

use std::time::Instant;

use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::table::Table;
use iceberg::{Catalog, NamespaceIdent, TableCreation, TableIdent};

// factory.rs references `crate::s3_storage::...` only under the `s3` feature;
// include it on the same gate (this example only exercises the embedded catalog,
// hence dead_code on both).
#[cfg(feature = "s3")]
#[path = "../src/s3_storage.rs"]
#[allow(dead_code)]
mod s3_storage;

#[path = "../src/factory.rs"]
#[allow(dead_code)] // shares factory.rs with the bench; only `embedded` is used here
mod factory;

fn schema() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
        ])
        .build()
        .unwrap()
}

fn report(label: &str, mut s: Vec<u128>, wall_ns: u128) {
    s.sort_unstable();
    let pct = |q: f64| s[((s.len() - 1) as f64 * q) as usize] as f64 / 1000.0;
    let ops_sec = s.len() as f64 * 1e9 / wall_ns as f64;
    println!(
        "{label:<28} p50 {:>8.3} us  p99 {:>8.3} us  {:>10.0} ops/s",
        pct(0.50),
        pct(0.99),
        ops_sec
    );
}

/// Time a synchronous closure `iters` times (1000-iter warmup).
fn bench_sync(label: &str, iters: usize, mut f: impl FnMut()) {
    for _ in 0..1000 {
        f();
    }
    let mut s = Vec::with_capacity(iters);
    let wall = Instant::now();
    for _ in 0..iters {
        let t = Instant::now();
        f();
        s.push(t.elapsed().as_nanos());
    }
    report(label, s, wall.elapsed().as_nanos());
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let iters: usize =
        std::env::var("ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(50_000);
    let (cat, _tmp) = factory::embedded().await?;

    let ns = NamespaceIdent::new("bench".to_string());
    cat.create_namespace(&ns, Default::default()).await?;
    let ident = TableIdent::new(ns.clone(), "t".to_string());
    cat.create_table(&ns, TableCreation::builder().name("t".to_string()).schema(schema()).build())
        .await?;

    // Resolve once; reuse the immutable metadata + location + FileIO for builds.
    let metadata = cat.resolve_metadata(&ident).await?;
    let seed = cat.load_table(&ident).await?;
    let location = seed.metadata_location().unwrap().to_string();
    let fileio = seed.file_io().clone();

    println!("# Table::build() A/B — {iters} iters, warm, single thread\n");

    // 1) load_table (full) — async.
    for _ in 0..1000 {
        let _ = cat.load_table(&ident).await;
    }
    {
        let mut s = Vec::with_capacity(iters);
        let wall = Instant::now();
        for _ in 0..iters {
            let t = Instant::now();
            let _ = cat.load_table(&ident).await?;
            s.push(t.elapsed().as_nanos());
        }
        report("load_table (full)", s, wall.elapsed().as_nanos());
    }

    // 2) Table::build with default cache (metadata pre-resolved) — sync.
    bench_sync("Table::build default", iters, || {
        let _: Table = Table::builder()
            .file_io(fileio.clone())
            .identifier(ident.clone())
            .metadata_location(location.clone())
            .metadata(metadata.clone())
            .build()
            .unwrap();
    });

    // 3) Table::build with cache DISABLED (capacity-0 moka) — sync.
    bench_sync("Table::build disable_cache", iters, || {
        let _: Table = Table::builder()
            .file_io(fileio.clone())
            .identifier(ident.clone())
            .metadata_location(location.clone())
            .metadata(metadata.clone())
            .disable_cache()
            .build()
            .unwrap();
    });

    // 3b) clone a pre-built Table (shares Arc<ObjectCache>) — sync.
    let template = Table::builder()
        .file_io(fileio.clone())
        .identifier(ident.clone())
        .metadata_location(location.clone())
        .metadata(metadata.clone())
        .build()
        .unwrap();
    bench_sync("Table::clone (cached)", iters, || {
        let _: Table = template.clone();
    });

    // 4) resolve_metadata — no Table at all (the floor) — async.
    {
        let mut s = Vec::with_capacity(iters);
        let wall = Instant::now();
        for _ in 0..iters {
            let t = Instant::now();
            let _ = cat.resolve_metadata(&ident).await?;
            s.push(t.elapsed().as_nanos());
        }
        report("resolve_metadata (floor)", s, wall.elapsed().as_nanos());
    }

    Ok(())
}
