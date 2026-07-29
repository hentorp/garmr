// Apache-2.0 licensed.
//
// Public time-travel surface: `load_table_at` / `resolve_metadata_at` route
// snapshot lookups through the static index → commit log, and
// `compact_static_index` rebuilds the index on demand. A snapshot that was
// never committed must surface a clear not-found error. (Happy-path resolution
// is covered by the `static_index` + `store` unit tests, which drive the commit
// log directly without needing a data-append snapshot.)

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::{Catalog, CatalogBuilder, ErrorKind, NamespaceIdent, TableCreation, TableIdent};
use skade_katalog::{RedbCatalog, RedbCatalogBuilder};
use tempfile::TempDir;

fn schema() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
        ])
        .build()
        .unwrap()
}

async fn catalog(tmp: &TempDir) -> Result<RedbCatalog> {
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse)?;
    Ok(RedbCatalogBuilder::default()
        .db_path(tmp.path().join("catalog.redb"))
        .warehouse_location(format!("file://{}", warehouse.display()))
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await?)
}

#[tokio::test]
async fn time_travel_surface_and_not_found() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog(&tmp).await?;

    let ns = NamespaceIdent::new("d".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    let creation = TableCreation::builder()
        .name("t".to_string())
        .schema(schema())
        .build();
    cat.create_table(&ns, creation).await?;
    let ident = TableIdent::new(ns, "t".to_string());

    // A freshly created table has no data snapshots, so the commit log holds no
    // snapshot rows yet: a deterministic compaction indexes zero of them.
    let indexed = cat.compact_static_index().await?;
    assert_eq!(indexed, 0);

    // Time-travel to a snapshot that was never committed → clear not-found.
    let e1 = cat.load_table_at(&ident, 1234567890).await.unwrap_err();
    assert_eq!(e1.kind(), ErrorKind::TableNotFound);
    let e2 = cat
        .resolve_metadata_at(&ident, 1234567890)
        .await
        .unwrap_err();
    assert_eq!(e2.kind(), ErrorKind::TableNotFound);

    // Batch resolve returns one slot per id, in order, all absent here.
    let many = cat.resolve_many(&ident, &[11, 22, 33]).await?;
    let all_absent = many.len() == 3 && many.iter().all(Option::is_none);
    assert!(all_absent);

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "time_travel",
        "time_travel_surface_and_not_found",
        indexed == 0
            && e1.kind() == ErrorKind::TableNotFound
            && e2.kind() == ErrorKind::TableNotFound
            && all_absent,
        &format!(
            "compacted={indexed} load_at/resolve_at=TableNotFound resolve_many=3 all-absent={all_absent}"
        ),
    );
    Ok(())
}

// Time-travel by **timestamp**: every table-pointer advance records a durable
// `ts_micros` in the commit log, so `load_table_as_of` / `resolve_metadata_as_of`
// resolve the newest commit at or before a wall-clock instant — and a timestamp
// before the table's first commit is a clean not-found. Unlike `load_table_at`
// (data-snapshot keyed), the as-of path resolves a create-only table, because a
// create commit carries a real metadata_location even with no data snapshot.
#[tokio::test]
async fn time_travel_as_of_timestamp() -> Result<()> {
    let tmp = TempDir::new()?;
    let cat = catalog(&tmp).await?;

    let ns = NamespaceIdent::new("d".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    let creation = TableCreation::builder()
        .name("t".to_string())
        .schema(schema())
        .build();
    cat.create_table(&ns, creation).await?;
    let ident = TableIdent::new(ns, "t".to_string());

    // Read the real commit timestamp the create recorded (durable, not the
    // in-memory broadcast) so the assertions key off actual stored data.
    let events = cat.commits_since(0).await?;
    assert_eq!(events.len(), 1, "one create commit in the log");
    let created_at = events[0].ts_micros;
    let created_loc = events[0].metadata_location.to_string();

    // As-of the create instant (and any later instant) resolves the table to
    // exactly the metadata_location the create recorded.
    let at_create = cat.load_table_as_of(&ident, created_at).await?;
    assert_eq!(at_create.metadata_location(), Some(created_loc.as_str()));
    let far_future = cat.load_table_as_of(&ident, created_at + 1_000_000).await?;
    assert_eq!(far_future.metadata_location(), Some(created_loc.as_str()));

    // The metadata-only path agrees with the live current metadata.
    let as_of_meta = cat.resolve_metadata_as_of(&ident, created_at).await?;
    let current_meta = cat.resolve_metadata(&ident).await?;
    let meta_agrees = as_of_meta.current_snapshot_id() == current_meta.current_snapshot_id();
    assert!(
        meta_agrees,
        "as-of metadata matches current for a fresh table"
    );

    // One microsecond before the first commit is pre-history → clean not-found.
    let pre = cat
        .load_table_as_of(&ident, created_at - 1)
        .await
        .unwrap_err();
    assert_eq!(pre.kind(), ErrorKind::TableNotFound);
    let pre_meta = cat
        .resolve_metadata_as_of(&ident, created_at - 1)
        .await
        .unwrap_err();
    assert_eq!(pre_meta.kind(), ErrorKind::TableNotFound);

    let ok = at_create.metadata_location() == Some(created_loc.as_str())
        && far_future.metadata_location() == Some(created_loc.as_str())
        && meta_agrees
        && pre.kind() == ErrorKind::TableNotFound
        && pre_meta.kind() == ErrorKind::TableNotFound;
    assert!(ok);

    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "time_travel",
        "time_travel_as_of_timestamp",
        ok,
        &format!(
            "as_of(created)=loc as_of(future)=loc meta-agrees={meta_agrees} pre-history=TableNotFound"
        ),
    );
    Ok(())
}
