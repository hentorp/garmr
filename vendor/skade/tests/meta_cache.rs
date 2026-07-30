// Apache-2.0 licensed.
//
// L0 parsed-metadata cache: correctness + a warm-vs-cold microbench.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation, TableIdent};
use skade_katalog::RedbCatalogBuilder;
use tempfile::TempDir;

fn schema_v1() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "run_id", Type::Primitive(PrimitiveType::String)).into(),
            NestedField::required(2, "ops_sec", Type::Primitive(PrimitiveType::Double)).into(),
        ])
        .build()
        .expect("schema v1")
}

async fn catalog_with_cache(tmp: &TempDir, cache_bytes: u64) -> Result<skade_katalog::RedbCatalog> {
    let db_path = tmp.path().join("catalog.redb");
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse)?;
    Ok(RedbCatalogBuilder::default()
        .db_path(db_path)
        .warehouse_location(format!("file://{}", warehouse.display()))
        .metadata_cache_bytes(cache_bytes)
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await?)
}

async fn seed_table(cat: &skade_katalog::RedbCatalog) -> Result<TableIdent> {
    let ns = NamespaceIdent::new("bench".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    let creation = TableCreation::builder()
        .name("bench_runs".to_string())
        .schema(schema_v1())
        .build();
    cat.create_table(&ns, creation).await?;
    Ok(TableIdent::new(ns, "bench_runs".to_string()))
}

/// The cache is keyed by the (immutable, content-addressed) metadata location,
/// so a commit that writes a *new* metadata file and flips the pointer must
/// never be masked by a stale cache entry for the *old* location.
#[tokio::test]
async fn commit_is_never_masked_by_stale_cache() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog_with_cache(&tmp, 64 * 1024 * 1024).await?;
    let ident = seed_table(&cat).await?;

    // Warm the cache with the v1 metadata location.
    let v1 = cat.load_table(&ident).await?;
    assert!(v1.metadata().properties().get("nornir.marker").is_none());
    let loc_v1 = v1.metadata_location().map(str::to_string);

    // Commit a property change → new metadata file at a new location.
    let tx = Transaction::new(&v1);
    let action = tx
        .update_table_properties()
        .set("nornir.marker".to_string(), "v2".to_string());
    action.apply(tx)?.commit(&cat).await?;

    // Reload: the pointer now references the new location, which is not yet
    // cached, so we must observe the new value — not the cached v1.
    let v2 = cat.load_table(&ident).await?;
    let marker = v2.metadata().properties().get("nornir.marker").cloned();
    let loc_v2 = v2.metadata_location().map(str::to_string);
    assert_eq!(
        marker,
        Some("v2".to_string()),
        "cache served a stale pre-commit metadata"
    );
    assert_ne!(
        loc_v2, loc_v1,
        "metadata location should advance after a commit"
    );
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "meta_cache",
        "commit_is_never_masked_by_stale_cache",
        marker == Some("v2".to_string()) && loc_v2 != loc_v1,
        &format!(
            "post-commit marker={marker:?} location_advanced={}",
            loc_v2 != loc_v1
        ),
    );
    Ok(())
}

/// Disabling the cache (`metadata_cache_bytes(0)`) still serves correct reads.
#[tokio::test]
async fn disabled_cache_still_correct() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog_with_cache(&tmp, 0).await?;
    let ident = seed_table(&cat).await?;
    let a = cat.load_table(&ident).await?;
    let b = cat.load_table(&ident).await?;
    let same = a.metadata_location() == b.metadata_location();
    assert!(same);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "meta_cache",
        "disabled_cache_still_correct",
        same,
        &format!("cache_bytes=0, two reads agree on location={same}"),
    );
    Ok(())
}

/// Many concurrent first-touch readers (a thundering herd on a cold key) must
/// all succeed; moka coalesces them into a single `read_from`.
#[tokio::test]
async fn concurrent_cold_readers_all_succeed() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog_with_cache(&tmp, 64 * 1024 * 1024).await?;
    let ident = seed_table(&cat).await?;

    let mut handles = Vec::new();
    for _ in 0..64 {
        let cat = cat.clone();
        let ident = ident.clone();
        handles.push(tokio::spawn(async move { cat.load_table(&ident).await }));
    }
    let mut succeeded = 0usize;
    for h in handles {
        h.await.expect("join")?;
        succeeded += 1;
    }
    assert_eq!(succeeded, 64);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "meta_cache",
        "concurrent_cold_readers_all_succeed",
        succeeded == 64,
        &format!("{succeeded}/64 thundering-herd cold readers succeeded"),
    );
    Ok(())
}

/// Run with: `cargo test --release --test meta_cache -- --ignored --nocapture`
#[tokio::test]
#[ignore = "microbench; run with --release --ignored --nocapture"]
async fn warm_vs_cold_microbench() -> Result<()> {
    const WARM_ITERS: u32 = 20_000;
    const COLD_ITERS: u32 = 500;

    let tmp_on = TempDir::new()?;
    let cat = catalog_with_cache(&tmp_on, 128 * 1024 * 1024).await?;
    let ident = seed_table(&cat).await?;

    // Cold: the very first load misses → FileIO read + parse.
    let t = Instant::now();
    let _ = cat.load_table(&ident).await?;
    let cold_ns = t.elapsed().as_nanos();

    // Warm: every subsequent load hits L0 (redb pointer + Arc clone + build).
    let t = Instant::now();
    for _ in 0..WARM_ITERS {
        let _ = cat.load_table(&ident).await?;
    }
    let warm_ns = t.elapsed().as_nanos() / WARM_ITERS as u128;

    // Baseline: cache disabled → every load pays FileIO + parse.
    let tmp_off = TempDir::new()?;
    let cat_off = catalog_with_cache(&tmp_off, 0).await?;
    let ident_off = seed_table(&cat_off).await?;
    let _ = cat_off.load_table(&ident_off).await?; // warm the OS page cache fairly
    let t = Instant::now();
    for _ in 0..COLD_ITERS {
        let _ = cat_off.load_table(&ident_off).await?;
    }
    let off_ns = t.elapsed().as_nanos() / COLD_ITERS as u128;

    eprintln!("L0 metadata cache microbench (local NVMe, single thread)");
    eprintln!("  cold first load (miss)   : {cold_ns:>10} ns");
    eprintln!("  warm load (L0 hit)       : {warm_ns:>10} ns/op");
    eprintln!("  cache disabled (baseline): {off_ns:>10} ns/op");
    let speedup = off_ns as f64 / warm_ns.max(1) as f64;
    eprintln!("  warm speedup vs disabled : {speedup:.1}x");
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "meta_cache",
        "warm_vs_cold_microbench",
        warm_ns < off_ns,
        &format!("warm={warm_ns}ns/op disabled={off_ns}ns/op speedup={speedup:.1}x"),
    );
    Ok(())
}
