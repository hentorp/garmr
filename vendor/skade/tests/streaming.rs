// Apache-2.0 licensed.
//
// Phase 0 — the katalog streaming spine. Every durable commit publishes a
// `CommitEvent` on a `tokio::sync::broadcast` (the low-latency hint) and appends
// a `commit_seq`-keyed row to the durable `COMMIT_LOG` (the source of truth,
// replayed by `commits_since`). These tests drive the public
// `RedbCatalog::{subscribe_commits, commits_since, commit_table_key}` surface.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation, TableIdent, TableUpdate};
use skade_katalog::{COMMIT_EVENT_BUFFER, RedbCatalog, RedbCatalogBuilder, WriteDurability};
use tempfile::TempDir;
use tokio::sync::broadcast::error::TryRecvError;

fn schema() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
        ])
        .build()
        .unwrap()
}

async fn open_with(
    db_path: &std::path::Path,
    warehouse: &std::path::Path,
    durability: WriteDurability,
) -> Result<RedbCatalog> {
    Ok(RedbCatalogBuilder::default()
        .db_path(db_path)
        .warehouse_location(format!("file://{}", warehouse.display()))
        .durability(durability)
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await?)
}

async fn fresh(durability: WriteDurability) -> Result<(TempDir, RedbCatalog)> {
    let tmp = TempDir::new()?;
    let db_path = tmp.path().join("catalog.redb");
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse)?;
    let cat = open_with(&db_path, &warehouse, durability).await?;
    Ok((tmp, cat))
}

fn creation(name: &str) -> TableCreation {
    TableCreation::builder()
        .name(name.to_string())
        .schema(schema())
        .build()
}

/// A single durable commit fires exactly one broadcast event, carrying the
/// table's internal key and the gapless `commit_seq`.
#[tokio::test]
async fn commit_fires_broadcast_event() -> Result<()> {
    let (_tmp, cat) = fresh(WriteDurability::Immediate).await?;

    // Subscribe BEFORE any commit — the returned cursor is the pre-commit seq.
    let (cursor, mut rx) = cat.subscribe_commits().await?;
    assert_eq!(cursor, 0, "fresh catalog: cursor at 0");

    let ns = NamespaceIdent::new("d".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    // Namespace creation is NOT a table-pointer commit → no event, no seq bump.
    assert!(
        matches!(rx.try_recv(), Err(TryRecvError::Empty)),
        "create_namespace fires no commit event"
    );

    let ident = TableIdent::new(ns.clone(), "a".to_string());
    cat.create_table(&ns, creation("a")).await?;

    let ev = rx.recv().await.expect("one commit event delivered");
    assert_eq!(ev.commit_seq, 1, "first commit → seq 1");
    assert_eq!(
        ev.table_key.as_ref(),
        cat.commit_table_key(&ident),
        "event names the committed table's internal key"
    );
    assert!(
        ev.snapshot_id.is_none(),
        "a freshly created (empty) table carries no snapshot"
    );
    assert!(ev.ts_micros > 0, "event is timestamped");

    // No second phantom event.
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "store",
        "commit_fires_broadcast_event",
        ev.commit_seq == 1,
        "one create_table commit → one CommitEvent seq=1",
    );
    Ok(())
}

/// Two independent subscribers both see the same commit event (a broadcast, not
/// a single-consumer queue).
#[tokio::test]
async fn subscribe_commits_delivers_to_multiple_subscribers() -> Result<()> {
    let (_tmp, cat) = fresh(WriteDurability::Immediate).await?;

    let (_c1, mut rx1) = cat.subscribe_commits().await?;
    let (_c2, mut rx2) = cat.subscribe_commits().await?;

    let ns = NamespaceIdent::new("d".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    cat.create_table(&ns, creation("a")).await?;

    let e1 = rx1.recv().await.expect("subscriber 1 got the event");
    let e2 = rx2.recv().await.expect("subscriber 2 got the event");
    assert_eq!(e1, e2, "both subscribers observe the identical event");
    assert_eq!(e1.commit_seq, 1);

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "store",
        "subscribe_commits_delivers_to_multiple_subscribers",
        e1 == e2,
        "two subscribers, one event, identical delivery",
    );
    Ok(())
}

/// A slow subscriber that never drains the (bounded, lossy) broadcast observes a
/// `Lagged` gap once the ring overflows — but `commits_since(cursor)` replays the
/// full, gapless commit history from the durable `COMMIT_LOG`, so no commit is
/// lost. This is the "snapshot + tail" recovery contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commits_since_returns_gap_after_lagged_subscriber() -> Result<()> {
    // Eventual durability: no per-commit fsync, so overflowing the ring is fast.
    let (_tmp, cat) = fresh(WriteDurability::Eventual).await?;

    let (cursor, mut rx) = cat.subscribe_commits().await?;
    assert_eq!(cursor, 0);

    let ns = NamespaceIdent::new("d".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;

    // Overflow the broadcast ring while the subscriber sleeps (never drains).
    let total = COMMIT_EVENT_BUFFER + 64;
    for i in 0..total {
        cat.create_table(&ns, creation(&format!("t{i:05}"))).await?;
    }

    // The lossy channel dropped the oldest events → the first drain sees Lagged.
    let mut lagged = false;
    loop {
        match rx.try_recv() {
            Ok(_) => continue,
            Err(TryRecvError::Lagged(_)) => {
                lagged = true;
                break;
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
        }
    }
    assert!(
        lagged,
        "an undrained subscriber lags once the ring overflows"
    );

    // Durable replay recovers EVERY commit, gaplessly, from the cursor.
    let backfill = cat.commits_since(cursor).await?;
    assert_eq!(
        backfill.len(),
        total,
        "commits_since replays all {total} durable commits the broadcast dropped"
    );
    for (i, ev) in backfill.iter().enumerate() {
        assert_eq!(
            ev.commit_seq,
            cursor + 1 + i as u64,
            "durable replay is gapless + monotonic"
        );
    }
    // And commit_seq agrees with the durable tail.
    assert_eq!(cat.commit_seq().await?, total as u64);

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "store",
        "commits_since_returns_gap_after_lagged_subscriber",
        lagged && backfill.len() == total,
        &format!("{total} commits; broadcast lagged; commits_since recovered all"),
    );
    Ok(())
}

/// Under concurrent commits coalesced through the group-commit path, `commit_seq`
/// stays gapless + strictly monotonic — the durable `COMMIT_LOG` holds exactly
/// the sequence `1..=N` with no gap and no duplicate, so it is a valid resume
/// cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commit_seq_is_gapless_monotonic_under_concurrency() -> Result<()> {
    let (_tmp, cat) = fresh(WriteDurability::Immediate).await?;
    let cat = Arc::new(cat);

    let ns = NamespaceIdent::new("d".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;

    // Create N tables serially (seq → N), then fire N concurrent property
    // commits — one per distinct table so they all succeed (no optimistic
    // conflict) while coalescing through `group_commit`.
    let n = 50usize;
    for i in 0..n {
        cat.create_table(&ns, creation(&format!("t{i:03}"))).await?;
    }

    let mut handles = Vec::new();
    for i in 0..n {
        let c = cat.clone();
        let ident = TableIdent::new(ns.clone(), format!("t{i:03}"));
        handles.push(tokio::spawn(async move {
            let mut updates = HashMap::new();
            updates.insert("touched".to_string(), format!("v{i}"));
            c.commit_table(ident, vec![], vec![TableUpdate::SetProperties { updates }])
                .await
        }));
    }
    for h in handles {
        h.await??;
    }

    let total = 2 * n as u64;
    assert_eq!(cat.commit_seq().await?, total, "N creates + N updates");

    let all = cat.commits_since(0).await?;
    let seqs: Vec<u64> = all.iter().map(|e| e.commit_seq).collect();
    let expected: Vec<u64> = (1..=total).collect();
    assert_eq!(
        seqs, expected,
        "durable log is gapless, monotonic, no duplicates"
    );

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "store",
        "commit_seq_is_gapless_monotonic_under_concurrency",
        seqs == expected,
        &format!("{total} concurrent+serial commits → gapless 1..={total}"),
    );
    Ok(())
}
