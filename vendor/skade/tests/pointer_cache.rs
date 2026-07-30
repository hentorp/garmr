// Apache-2.0 licensed.
//
// L1 lock-free pointer mirror: write-through correctness across every mutation
// path, generation monotonicity, and rebuild-on-reopen.

use std::collections::HashMap;
use std::sync::Arc;

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
        ])
        .build()
        .expect("schema")
}

async fn open(tmp: &TempDir) -> Result<skade_katalog::RedbCatalog> {
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse)?;
    Ok(RedbCatalogBuilder::default()
        .db_path(tmp.path().join("catalog.redb"))
        .warehouse_location(format!("file://{}", warehouse.display()))
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await?)
}

fn creation(name: &str) -> TableCreation {
    TableCreation::builder()
        .name(name.to_string())
        .schema(schema_v1())
        .build()
}

/// Every mutation publishes a new mirror generation, and reads reflect it.
#[tokio::test]
async fn generation_advances_and_reads_reflect_mutations() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = open(&tmp).await?;
    let ns = NamespaceIdent::new("g".to_string());

    let g0 = cat.pointer_generation();
    cat.create_namespace(&ns, HashMap::new()).await?;
    cat.create_table(&ns, creation("t")).await?;
    let g_after_create = cat.pointer_generation();
    assert!(g_after_create > g0, "create_table should bump generation");

    // Read is served from the mirror and resolves the freshly created table.
    let ident = TableIdent::new(ns.clone(), "t".to_string());
    let loaded = cat.load_table(&ident).await?;
    let loc_v1 = loaded.metadata_location().map(str::to_string);

    // Commit advances the pointer → mirror reflects the new location.
    let tx = Transaction::new(&loaded);
    let action = tx
        .update_table_properties()
        .set("k".to_string(), "v".to_string());
    action.apply(tx)?.commit(&cat).await?;
    let g_after_commit = cat.pointer_generation();
    assert!(
        g_after_commit > g_after_create,
        "commit should bump generation"
    );
    let reloaded = cat.load_table(&ident).await?;
    assert_ne!(
        reloaded.metadata_location().map(str::to_string),
        loc_v1,
        "mirror must serve the post-commit location"
    );

    // Rename moves the pointer to the new key and drops the old.
    let dst = TableIdent::new(ns.clone(), "t2".to_string());
    cat.rename_table(&ident, &dst).await?;
    assert!(!cat.table_exists(&ident).await?, "old key gone from mirror");
    assert!(cat.table_exists(&dst).await?, "new key present in mirror");
    assert!(cat.load_table(&ident).await.is_err());
    cat.load_table(&dst).await?;

    // Drop removes the pointer.
    cat.drop_table(&dst).await?;
    let dropped = !cat.table_exists(&dst).await? && cat.load_table(&dst).await.is_err();
    assert!(dropped);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "pointer_cache",
        "generation_advances_and_reads_reflect_mutations",
        g_after_create > g0 && g_after_commit > g_after_create && dropped,
        &format!(
            "gen g0={g0}→create={g_after_create}→commit={g_after_commit} monotonic; drop_removed={dropped}"
        ),
    );
    Ok(())
}

/// A fresh catalog instance over the same file rebuilds the mirror from redb,
/// so reads resolve without ever having seen the writes in this process.
#[tokio::test]
async fn mirror_rebuilt_on_reopen() -> Result<()> {
    let tmp = TempDir::new()?;
    let ns = NamespaceIdent::new("re".to_string());
    let ident = TableIdent::new(ns.clone(), "t".to_string());
    let expected_loc;
    {
        let cat = open(&tmp).await?;
        cat.create_namespace(&ns, HashMap::new()).await?;
        let t = cat.create_table(&ns, creation("t")).await?;
        expected_loc = t.metadata_location().map(str::to_string);
        // First instance starts at generation 0 and bumps once per create.
        assert!(cat.pointer_generation() >= 1);
    }

    let cat2 = open(&tmp).await?;
    // Rebuilt mirror starts fresh at generation 0 but is fully populated.
    let gen0 = cat2.pointer_generation();
    assert_eq!(gen0, 0);
    let loaded = cat2.load_table(&ident).await?;
    let loc = loaded.metadata_location().map(str::to_string);
    assert_eq!(loc, expected_loc);
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "pointer_cache",
        "mirror_rebuilt_on_reopen",
        gen0 == 0 && loc == expected_loc,
        &format!(
            "reopen gen={gen0} (want 0); rebuilt mirror resolves location match={}",
            loc == expected_loc
        ),
    );
    Ok(())
}

/// Where does warm `load_table` time actually go, and does L1 (lock-free reads)
/// scale across threads? Run:
/// `cargo test --release --test pointer_cache -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "microbench; run with --release --ignored --nocapture"]
async fn l1_read_breakdown_and_scaling() -> Result<()> {
    use std::time::Instant;

    const ITERS: u32 = 50_000;

    let tmp = TempDir::new()?;
    let cat = open(&tmp).await?;
    let ns = NamespaceIdent::new("b".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    cat.create_table(&ns, creation("t")).await?;
    let ident = TableIdent::new(ns, "t".to_string());

    // Warm the L0 + L1 caches and capture pieces for the isolation measurements.
    let loaded = cat.load_table(&ident).await?;
    let md = loaded.metadata_ref();
    let loc = loaded.metadata_location().unwrap().to_string();
    let fileio = cat.file_io().clone();

    // (1) Full warm load_table: L1 pointer + L0 metadata + Table::build().
    let t = Instant::now();
    for _ in 0..ITERS {
        let _ = cat.load_table(&ident).await?;
    }
    let full_ns = t.elapsed().as_nanos() / ITERS as u128;

    // (2) Just iceberg's Table::build() from already-resolved pieces — no redb,
    //     no FileIO, no cache. This is the per-call ObjectCache allocation.
    let t = Instant::now();
    for _ in 0..ITERS {
        let _ = iceberg::table::Table::builder()
            .file_io(fileio.clone())
            .identifier(ident.clone())
            .metadata_location(loc.clone())
            .metadata(md.clone())
            .build()?;
    }
    let build_ns = t.elapsed().as_nanos() / ITERS as u128;

    // (2b) Direct resolution API: L1 pointer + L0 metadata, no Table::build().
    let t = Instant::now();
    for _ in 0..ITERS {
        let _ = cat.resolve_metadata(&ident).await?;
    }
    let resolve_ns = t.elapsed().as_nanos() / ITERS as u128;

    eprintln!("L1 read breakdown (single thread, warm)");
    eprintln!("  full load_table        : {full_ns:>8} ns/op");
    eprintln!(
        "  iceberg Table::build() : {build_ns:>8} ns/op  ({}% of full)",
        build_ns * 100 / full_ns.max(1)
    );
    eprintln!("  resolve_metadata (L1+L0): {resolve_ns:>7} ns/op  ← catalog fast path");

    // (3) Concurrent scaling: many tasks hammering reads. L1 reads are
    //     lock-free (ArcSwap), so this should scale near-linearly with cores —
    //     the old `db.lock().await` path would serialize every reader.
    for threads in [1usize, 4, 16] {
        let t = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..threads {
            let cat = cat.clone();
            let ident = ident.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..ITERS {
                    let _ = cat.load_table(&ident).await.unwrap();
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let total = (threads as u128) * (ITERS as u128);
        let ops_sec = total * 1_000_000_000 / t.elapsed().as_nanos().max(1);
        eprintln!("  concurrency {threads:>2}: {ops_sec:>10} load_table/sec aggregate");
        #[cfg(feature = "testmatrix")]
        nornir_testmatrix::functional_status(
            "pointer_cache",
            "l1_read_breakdown_and_scaling",
            ops_sec > 0,
            &format!(
                "threads={threads} aggregate={ops_sec} load_table/sec; resolve={resolve_ns}ns/op build={build_ns}ns/op full={full_ns}ns/op"
            ),
        );
    }
    Ok(())
}
