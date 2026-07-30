//! End-to-end exercise of the REST shim's `commit_table` (update) endpoint.
//!
//! Spins the in-process axum shim over an embedded `RedbCatalog`, points an
//! iceberg-rust `RestCatalog` at it, creates a table, then commits a
//! property-update transaction *through the REST path*. Verifies the commit
//! round-trips: the metadata location advances and the new property is visible
//! both via the REST client's `load_table` and via the embedded catalog
//! underneath the shim (i.e. the commit was actually persisted in redb, not
//! just echoed back).

use std::collections::HashMap;
use std::sync::Arc;

use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation, TableIdent};
use iceberg_catalog_rest::{
    RestCatalogBuilder, REST_CATALOG_PROP_URI, REST_CATALOG_PROP_WAREHOUSE,
};
use skade_katalog::{RedbCatalog, RedbCatalogBuilder};
use skade_katalog_bench::rest_shim;
use tempfile::TempDir;

fn schema() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
        ])
        .build()
        .expect("schema")
}

async fn embedded(tmp: &TempDir) -> RedbCatalog {
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse).unwrap();
    RedbCatalogBuilder::default()
        .db_path(tmp.path().join("catalog.redb"))
        .warehouse_location(format!("file://{}", warehouse.display()))
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await
        .expect("embedded catalog")
}

#[tokio::test]
async fn commit_table_round_trips_over_rest() {
    let tmp = TempDir::new().unwrap();
    // The embedded catalog the shim writes through. Keep a clone so we can
    // inspect the persisted state after the REST commit.
    let cat = embedded(&tmp).await;
    let underlying = cat.clone();

    let bound = rest_shim::spawn(cat, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("shim bound");

    let rest = RestCatalogBuilder::default()
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load(
            "rest",
            HashMap::from([
                (REST_CATALOG_PROP_URI.to_string(), format!("http://{bound}")),
                (
                    REST_CATALOG_PROP_WAREHOUSE.to_string(),
                    "warehouse".to_string(),
                ),
            ]),
        )
        .await
        .expect("rest client");

    let ns = NamespaceIdent::new("db".to_string());
    rest.create_namespace(&ns, HashMap::new()).await.unwrap();

    let ident = TableIdent::new(ns.clone(), "t".to_string());
    let creation = TableCreation::builder()
        .name("t".to_string())
        .schema(schema())
        .build();
    let table = rest.create_table(&ns, creation).await.unwrap();
    let loc_before = table.metadata_location().unwrap().to_string();
    assert!(
        table.metadata().properties().get("answer").is_none(),
        "fresh table should not carry the property yet"
    );

    // Commit a property update through the REST commit_table endpoint.
    let tx = Transaction::new(&table);
    let tx = tx
        .update_table_properties()
        .set("answer".to_string(), "42".to_string())
        .apply(tx)
        .unwrap();
    let committed = tx.commit(&rest).await.expect("REST commit_table");

    // The commit advanced the metadata location and carries the new property.
    let loc_after = committed.metadata_location().unwrap().to_string();
    assert_ne!(loc_before, loc_after, "commit must write a new metadata file");
    assert_eq!(
        committed.metadata().properties().get("answer").map(String::as_str),
        Some("42"),
        "committed table reflects the update"
    );

    // A fresh REST load sees the committed state (not the create-time metadata).
    let reloaded = rest.load_table(&ident).await.unwrap();
    assert_eq!(reloaded.metadata_location().unwrap(), loc_after);
    assert_eq!(
        reloaded.metadata().properties().get("answer").map(String::as_str),
        Some("42"),
        "REST load_table sees the persisted commit"
    );

    // And it was persisted in the backing redb catalog, not just echoed: the
    // embedded catalog's pointer advanced to the same new location.
    let direct = underlying.load_table(&ident).await.unwrap();
    assert_eq!(
        direct.metadata_location().unwrap(),
        loc_after,
        "embedded catalog under the shim advanced its pointer"
    );
    assert_eq!(
        direct.metadata().properties().get("answer").map(String::as_str),
        Some("42"),
    );
}

/// `commit_table` on a missing table must surface `TableNotFound` — the kind the
/// REST shim maps to HTTP 404.
///
/// This drives the in-flight primitive directly rather than through the
/// high-level `Transaction::commit`. iceberg-rust's `Transaction::commit` does a
/// pre-commit *refresh* (`catalog.load_table`, core `transaction/mod.rs`); for a
/// missing table that refresh fails first, and the REST client maps a
/// `load_table` 404 to `ErrorKind::Unexpected` (only its `update_table` path maps
/// 404 → `TableNotFound`). So the high-level path can never observe
/// `TableNotFound` here — the meaningful assertion is on the catalog primitive
/// that backs the shim's `commit_table` handler.
#[tokio::test]
async fn commit_table_not_found_for_missing_table() {
    let tmp = TempDir::new().unwrap();
    let cat = embedded(&tmp).await;

    let ns = NamespaceIdent::new("db".to_string());
    cat.create_namespace(&ns, HashMap::new()).await.unwrap();
    let ghost = TableIdent::new(ns, "ghost".to_string());

    let err = cat
        .commit_table(ghost, vec![], vec![])
        .await
        .expect_err("commit on a table that was never created");
    assert_eq!(err.kind(), iceberg::ErrorKind::TableNotFound);
}
