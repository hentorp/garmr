//! DataFusion reads `RedbCatalog` through `iceberg-datafusion` and runs SQL.
//!
//! This is the additive SQL surface (NOT a replacement for iceberg-rust):
//! `RedbCatalog` keeps implementing `iceberg::Catalog`; DataFusion becomes one
//! more *reader* of it via `IcebergCatalogProvider`. It's also the first
//! end-to-end exercise of the read path under real query planning (scan →
//! manifest-list → manifests/data-files), the intrinsic batch the Ragnar
//! `resolve_many` path targets. See `.nornir/TODO.md` "DataFusion / SQL surface".

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use arrow_array::{Int64Array, RecordBatch};
use iceberg::io::LocalFsStorageFactory;
use iceberg::spec::{DataFileFormat, NestedField, PrimitiveType, Schema, Type};
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::writer::base_writer::data_file_writer::DataFileWriterBuilder;
use iceberg::writer::file_writer::location_generator::{
    DefaultFileNameGenerator, DefaultLocationGenerator,
};
use iceberg::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
use iceberg::writer::file_writer::ParquetWriterBuilder;
use iceberg::writer::{IcebergWriter, IcebergWriterBuilder};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation, TableIdent};
use skade_katalog::RedbCatalogBuilder;
use parquet::file::properties::WriterProperties;

use datafusion::arrow::array::Array;
use datafusion::prelude::SessionContext;
use iceberg_datafusion::IcebergCatalogProvider;

/// Two-column table: `id: long, val: long`.
fn schema() -> Schema {
    Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Long)).into(),
            NestedField::required(2, "val", Type::Primitive(PrimitiveType::Long)).into(),
        ])
        .build()
        .expect("schema")
}

/// Append one Parquet data file (`ids`/`vals`) to `table` via `fast_append`.
async fn append_rows(
    catalog: &dyn Catalog,
    table: iceberg::table::Table,
    ids: Vec<i64>,
    vals: Vec<i64>,
) -> Result<iceberg::table::Table> {
    let arrow_schema = Arc::new(iceberg::arrow::schema_to_arrow_schema(
        table.metadata().current_schema(),
    )?);
    let batch = RecordBatch::try_new(arrow_schema, vec![
        Arc::new(Int64Array::from(ids)),
        Arc::new(Int64Array::from(vals)),
    ])?;

    let iceberg_schema = table.metadata().current_schema().clone();
    let data_location = format!("{}/data", table.metadata().location());
    let location_gen = DefaultLocationGenerator::with_data_location(data_location);
    let file_name_gen = DefaultFileNameGenerator::new("df".into(), None, DataFileFormat::Parquet);
    let pw = ParquetWriterBuilder::new(WriterProperties::builder().build(), iceberg_schema);
    let rolling = RollingFileWriterBuilder::new_with_default_file_size(
        pw,
        table.file_io().clone(),
        location_gen,
        file_name_gen,
    );
    let mut writer = DataFileWriterBuilder::new(rolling).build(None).await?;
    writer.write(batch).await?;
    let data_files = writer.close().await?;

    let tx = Transaction::new(&table);
    let action = tx.fast_append().add_data_files(data_files);
    let tx = action.apply(tx)?;
    Ok(tx.commit(catalog).await?)
}

#[tokio::test]
async fn datafusion_queries_redb_catalog_via_iceberg() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let warehouse = format!("file://{}", tmp.path().join("warehouse").display());

    // Build the embedded catalog over a local-FS warehouse.
    let catalog = RedbCatalogBuilder::default()
        .db_path(tmp.path().join("catalog.redb").to_string_lossy().to_string())
        .warehouse_location(warehouse)
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("nornir", HashMap::new())
        .await?;
    let catalog: Arc<dyn Catalog> = Arc::new(catalog);

    // Seed: namespace "bench", table "t", 10 rows (id=1..=10, val=id*10).
    let ns = NamespaceIdent::new("bench".to_string());
    catalog.create_namespace(&ns, HashMap::new()).await?;
    let ident = TableIdent::new(ns.clone(), "t".to_string());
    let table = catalog
        .create_table(
            &ns,
            TableCreation::builder().name("t".to_string()).schema(schema()).build(),
        )
        .await?;
    let ids: Vec<i64> = (1..=10).collect();
    let vals: Vec<i64> = ids.iter().map(|i| i * 10).collect();
    let _ = ident;
    append_rows(catalog.as_ref(), table, ids, vals).await?;

    // Register the catalog with DataFusion (provider snapshots tables here, so it
    // must run AFTER the seed) and run SQL through it.
    let provider = IcebergCatalogProvider::try_new(catalog.clone()).await?;
    let ctx = SessionContext::new();
    ctx.register_catalog("nornir", Arc::new(provider));

    let batches = ctx
        .sql("SELECT count(*) AS n, sum(id) AS s, sum(val) AS v FROM nornir.bench.t")
        .await?
        .collect()
        .await?;

    assert_eq!(batches.len(), 1, "one result batch");
    let b = &batches[0];
    let col = |name: &str| -> i64 {
        let i = b.schema().index_of(name).expect("column");
        b.column(i)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("Int64 result")
            .value(0)
    };
    assert_eq!(col("n"), 10, "row count");
    assert_eq!(col("s"), 55, "sum(id) = 1+..+10");
    assert_eq!(col("v"), 550, "sum(val) = 10*(1+..+10)");

    // And a filtered scan exercises predicate pushdown through the table provider.
    let filtered = ctx
        .sql("SELECT count(*) AS n FROM nornir.bench.t WHERE id > 7")
        .await?
        .collect()
        .await?;
    let n = filtered[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap()
        .value(0);
    assert_eq!(n, 3, "ids 8,9,10");

    Ok(())
}
