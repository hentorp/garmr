// Apache-2.0 licensed.
//
// Every durability level must produce a correct, readable catalog. (We can't
// assert crash semantics in a unit test; we assert functional correctness and
// that the knob is accepted via builder and prop.)

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation, TableIdent};
use skade_katalog::{REDB_CATALOG_PROP_DURABILITY, RedbCatalogBuilder, WriteDurability};
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

async fn roundtrip(cat: &skade_katalog::RedbCatalog) -> Result<bool> {
    let ns = NamespaceIdent::new("d".to_string());
    cat.create_namespace(&ns, HashMap::new()).await?;
    let creation = TableCreation::builder()
        .name("t".to_string())
        .schema(schema())
        .build();
    cat.create_table(&ns, creation).await?;
    let ident = TableIdent::new(ns, "t".to_string());
    let exists = cat.table_exists(&ident).await?;
    assert!(exists);
    cat.load_table(&ident).await?;
    Ok(exists)
}

#[tokio::test]
async fn all_durability_levels_roundtrip() -> Result<()> {
    let mut ok_all = true;
    for level in [
        WriteDurability::Immediate,
        WriteDurability::Eventual,
        WriteDurability::None,
    ] {
        let tmp = TempDir::new()?;
        let warehouse = tmp.path().join("warehouse");
        std::fs::create_dir_all(&warehouse)?;
        let cat = RedbCatalogBuilder::default()
            .db_path(tmp.path().join("catalog.redb"))
            .warehouse_location(format!("file://{}", warehouse.display()))
            .durability(level)
            .with_storage_factory(Arc::new(LocalFsStorageFactory))
            .load("nornir", HashMap::new())
            .await?;
        ok_all &= roundtrip(&cat).await?;
    }
    assert!(ok_all, "every durability level must roundtrip");
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "durability",
        "all_durability_levels_roundtrip",
        ok_all,
        &format!("Immediate+Eventual+None all roundtrip table_exists={ok_all}"),
    );
    Ok(())
}

#[tokio::test]
async fn durability_via_prop() -> Result<()> {
    let tmp = TempDir::new()?;
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse)?;
    let cat = RedbCatalogBuilder::default()
        .db_path(tmp.path().join("catalog.redb"))
        .warehouse_location(format!("file://{}", warehouse.display()))
        .prop(REDB_CATALOG_PROP_DURABILITY, "eventual")
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await?;
    roundtrip(&cat).await?;

    // An invalid value is rejected.
    let bad = RedbCatalogBuilder::default()
        .db_path(tmp.path().join("catalog2.redb"))
        .warehouse_location(format!("file://{}", warehouse.display()))
        .prop(REDB_CATALOG_PROP_DURABILITY, "sometimes")
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await;
    let rejected = bad.is_err();
    assert!(rejected, "invalid durability should be rejected");
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "durability",
        "durability_via_prop",
        rejected,
        &format!("eventual prop accepted + invalid 'sometimes' rejected={rejected}"),
    );
    Ok(())
}
