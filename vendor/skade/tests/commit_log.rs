// Apache-2.0 licensed.
//
// The durable commit log (`commits`/`meta` redb tables) must advance once per
// table-pointer advance and survive a reopen. This exercises the public path
// (create_table → record_commit) and the persisted `commit_seq` counter.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation, TableIdent};
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

async fn open(db_path: &std::path::Path, warehouse: &std::path::Path) -> Result<RedbCatalog> {
    Ok(RedbCatalogBuilder::default()
        .db_path(db_path)
        .warehouse_location(format!("file://{}", warehouse.display()))
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await?)
}

#[tokio::test]
async fn commit_seq_advances_per_table_and_persists() -> Result<()> {
    let tmp = TempDir::new()?;
    let db_path = tmp.path().join("catalog.redb");
    let warehouse = tmp.path().join("warehouse");
    std::fs::create_dir_all(&warehouse)?;

    {
        let cat = open(&db_path, &warehouse).await?;
        assert_eq!(cat.commit_seq().await?, 0, "fresh catalog has no commits");

        let ns = NamespaceIdent::new("d".to_string());
        cat.create_namespace(&ns, HashMap::new()).await?;
        // Creating a namespace is not a table commit.
        assert_eq!(cat.commit_seq().await?, 0);

        for name in ["a", "b", "c"] {
            let creation = TableCreation::builder()
                .name(name.to_string())
                .schema(schema())
                .build();
            cat.create_table(&ns, creation).await?;
        }
        assert_eq!(cat.commit_seq().await?, 3, "one commit per created table");

        // Rename moves a pointer but mints no new metadata → no commit-log entry.
        cat.rename_table(
            &TableIdent::new(ns.clone(), "c".to_string()),
            &TableIdent::new(ns.clone(), "c2".to_string()),
        )
        .await?;
        assert_eq!(
            cat.commit_seq().await?,
            3,
            "rename does not advance commit_seq"
        );
    }

    // Reopen the same file: the durable counter must survive (unlike the
    // in-memory pointer generation, which resets to 0 on open).
    let cat = open(&db_path, &warehouse).await?;
    let seq = cat.commit_seq().await?;
    let generation = cat.pointer_generation();
    assert_eq!(seq, 3, "commit_seq persists across reopen");
    assert_eq!(generation, 0, "in-memory generation resets on reopen");
    #[cfg(feature = "testmatrix")]
    nornir_testmatrix::functional_status(
        "commit_log",
        "commit_seq_advances_per_table_and_persists",
        seq == 3 && generation == 0,
        &format!(
            "commit_seq_after_reopen={seq} (want 3), pointer_generation={generation} (want 0)"
        ),
    );
    Ok(())
}
