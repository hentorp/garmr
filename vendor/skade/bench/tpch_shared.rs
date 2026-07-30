//! Shared TPC-H harness, `#[path]`-included by both `tests/tpch_suite.rs` and
//! `examples/nornir-bench.rs`. It can't live in `src/` (the lib) because it uses
//! dev-deps (datafusion, tpchgen, iceberg-datafusion) — those are only available
//! to tests/examples, so this neutral file is shared by inclusion.
//!
//! `build_ctx(sf)` generates + ingests all 8 TPC-H tables into a fresh
//! `RedbCatalog` and returns a DataFusion `SessionContext` (default catalog/schema
//! `nornir.tpch`) wired via `iceberg-datafusion`. `query_sql(n)` returns the
//! canonical query `n` with standard validation params + DataFusion fixups.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Schema as ArrowSchema};
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
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation};
use skade_katalog::RedbCatalogBuilder;
use parquet::file::properties::WriterProperties;

use datafusion::arrow::compute::cast;
use datafusion::prelude::{SessionConfig, SessionContext};
use iceberg_datafusion::IcebergCatalogProvider;

use tpchgen::generators::{
    CustomerGenerator, LineItemGenerator, NationGenerator, OrderGenerator, PartGenerator,
    PartSuppGenerator, RegionGenerator, SupplierGenerator,
};
use tpchgen_arrow::{
    CustomerArrow, LineItemArrow, NationArrow, OrderArrow, PartArrow, PartSuppArrow,
    RecordBatchIterator, RegionArrow, SupplierArrow,
};

/// Bridge a tpchgen-arrow (arrow-57) `RecordBatch` to an arrow-58 `RecordBatch`.
///
/// tpchgen-arrow 2.0.2 hard-pins arrow-57, but the writer/reader path is arrow-58
/// (iceberg-arrow58 + datafusion-54). The two `arrow` majors are distinct crates
/// with no value-level interop, so we serialize the batch through the Arrow IPC
/// stream format with the 57 writer and deserialize it with the 58 reader. The
/// IPC stream format is stable across these majors; buffers are length-prefixed
/// and copied once. This keeps the bench's TPC-H ingest measuring the arrow-58
/// writer (the thing under test), not the generator's arrow version.
fn bridge_batch_57_to_58(b57: &arrow::record_batch::RecordBatch) -> Result<RecordBatch> {
    use arrow::ipc::writer::StreamWriter as StreamWriter57;
    use datafusion::arrow::ipc::reader::StreamReader as StreamReader58;

    let mut buf: Vec<u8> = Vec::new();
    {
        let mut w = StreamWriter57::try_new(&mut buf, b57.schema_ref())?;
        w.write(b57)?;
        w.finish()?;
    }
    let mut r = StreamReader58::try_new(std::io::Cursor::new(buf), None)?;
    let b58 = r
        .next()
        .context("IPC stream produced no batch when bridging arrow-57 → arrow-58")??;
    Ok(b58)
}

/// Map a tpchgen Arrow schema to an Iceberg schema (field ids 1..N, all required).
///
/// Takes the arrow-57 schema the tpchgen-arrow generator emits (`arrow::datatypes`),
/// so the `DataType` match is against arrow-57's enum. The data itself is bridged
/// to arrow-58 per batch by [`bridge_batch_57_to_58`]; the field-id Iceberg schema
/// is identical either way (primitive type mapping only).
fn arrow_to_iceberg(schema: &arrow::datatypes::Schema) -> Result<Schema> {
    use arrow::datatypes::DataType as Dt57;
    let mut fields = Vec::with_capacity(schema.fields().len());
    for (i, f) in schema.fields().iter().enumerate() {
        let pt = match f.data_type() {
            Dt57::Boolean => PrimitiveType::Boolean,
            Dt57::Int8 | Dt57::Int16 | Dt57::Int32 => PrimitiveType::Int,
            Dt57::Int64 => PrimitiveType::Long,
            Dt57::Float32 => PrimitiveType::Float,
            Dt57::Float64 => PrimitiveType::Double,
            Dt57::Decimal128(p, s) => {
                PrimitiveType::Decimal { precision: *p as u32, scale: (*s).max(0) as u32 }
            }
            Dt57::Date32 => PrimitiveType::Date,
            Dt57::Utf8 | Dt57::LargeUtf8 | Dt57::Utf8View => PrimitiveType::String,
            other => anyhow::bail!("unmapped arrow type {other:?} for column {}", f.name()),
        };
        fields.push(NestedField::required((i + 1) as i32, f.name().to_string(), Type::Primitive(pt)).into());
    }
    Ok(Schema::builder().with_schema_id(0).with_fields(fields).build()?)
}

/// Create the Iceberg table from the generator's Arrow schema and ingest every
/// batch (cast to the table's field-id Arrow schema). Returns rows ingested.
async fn ingest_table<I>(catalog: &Arc<dyn Catalog>, ns: &NamespaceIdent, name: &str, it: I) -> Result<u64>
where
    I: RecordBatchIterator,
{
    let arrow_schema = it.schema().clone();
    let ice = arrow_to_iceberg(arrow_schema.as_ref()).with_context(|| format!("schema for {name}"))?;
    let table = catalog
        .create_table(ns, TableCreation::builder().name(name.to_string()).schema(ice).build())
        .await?;
    let target = Arc::new(iceberg::arrow::schema_to_arrow_schema(table.metadata().current_schema())?);

    let data_location = format!("{}/data", table.metadata().location());
    let location_gen = DefaultLocationGenerator::with_data_location(data_location);
    let file_name_gen = DefaultFileNameGenerator::new(name.into(), None, DataFileFormat::Parquet);
    let pw = ParquetWriterBuilder::new(
        WriterProperties::builder().build(),
        table.metadata().current_schema().clone(),
    );
    let rolling = RollingFileWriterBuilder::new_with_default_file_size(
        pw,
        table.file_io().clone(),
        location_gen,
        file_name_gen,
    );
    let mut writer = DataFileWriterBuilder::new(rolling).build(None).await?;

    let ncols = target.fields().len();
    let mut rows = 0u64;
    for batch in it {
        let batch = bridge_batch_57_to_58(&batch)?;
        let cols: Vec<ArrayRef> = (0..ncols)
            .map(|i| cast(batch.column(i), target.field(i).data_type()).map_err(anyhow::Error::from))
            .collect::<Result<_>>()?;
        let rb = RecordBatch::try_new(target.clone(), cols)?;
        rows += rb.num_rows() as u64;
        writer.write(rb).await?;
    }
    let data_files = writer.close().await?;
    let tx = Transaction::new(&table);
    let action = tx.fast_append().add_data_files(data_files);
    let tx = action.apply(tx)?;
    tx.commit(catalog.as_ref()).await?;
    Ok(rows)
}

/// Ingest a table generated across `parts` tpchgen partitions concurrently — one
/// task per partition, each streaming its share through its own `DataFileWriter`
/// (bounded memory; rolls files to disk) — then one `fast_append` commit of all
/// data files. `make(part, part_count)` builds a partition's Arrow iterator. This
/// is what puts the warehouse build on all cores; `parts == 1` is the sequential
/// path (used for the tiny nation/region tables).
async fn ingest_table_parallel<F, I>(
    catalog: &Arc<dyn Catalog>,
    ns: &NamespaceIdent,
    name: &str,
    parts: i32,
    make: F,
) -> Result<u64>
where
    F: Fn(i32, i32) -> I + Send + Sync + 'static,
    I: RecordBatchIterator + Send + 'static,
{
    let parts = parts.max(1);
    let arrow_schema = make(1, parts).schema().clone();
    let ice = arrow_to_iceberg(arrow_schema.as_ref()).with_context(|| format!("schema for {name}"))?;
    let table = Arc::new(
        catalog
            .create_table(ns, TableCreation::builder().name(name.to_string()).schema(ice).build())
            .await?,
    );
    let target = Arc::new(iceberg::arrow::schema_to_arrow_schema(table.metadata().current_schema())?);
    let make = Arc::new(make);

    let mut handles = Vec::with_capacity(parts as usize);
    for p in 1..=parts {
        let (table, target, make, name) = (table.clone(), target.clone(), make.clone(), name.to_string());
        handles.push(tokio::spawn(async move {
            let data_location = format!("{}/data", table.metadata().location());
            let location_gen = DefaultLocationGenerator::with_data_location(data_location);
            let file_name_gen =
                DefaultFileNameGenerator::new(format!("{name}-p{p}"), None, DataFileFormat::Parquet);
            let pw = ParquetWriterBuilder::new(
                WriterProperties::builder().build(),
                table.metadata().current_schema().clone(),
            );
            let rolling = RollingFileWriterBuilder::new_with_default_file_size(
                pw,
                table.file_io().clone(),
                location_gen,
                file_name_gen,
            );
            let mut writer = DataFileWriterBuilder::new(rolling).build(None).await?;
            let ncols = target.fields().len();
            let mut rows = 0u64;
            for batch in make(p, parts) {
                let batch = bridge_batch_57_to_58(&batch)?;
                let cols: Vec<ArrayRef> = (0..ncols)
                    .map(|i| cast(batch.column(i), target.field(i).data_type()).map_err(anyhow::Error::from))
                    .collect::<Result<_>>()?;
                let rb = RecordBatch::try_new(target.clone(), cols)?;
                rows += rb.num_rows() as u64;
                writer.write(rb).await?;
            }
            Ok::<_, anyhow::Error>((rows, writer.close().await?))
        }));
    }

    let mut total = 0u64;
    let mut data_files = Vec::new();
    for h in handles {
        let (rows, files) = h.await??;
        total += rows;
        data_files.extend(files);
    }
    let tx = Transaction::new(table.as_ref());
    let action = tx.fast_append().add_data_files(data_files);
    let tx = action.apply(tx)?;
    tx.commit(catalog.as_ref()).await?;
    Ok(total)
}

/// Standard TPC-H validation substitution parameters (positional `:1..`).
fn params(n: i32) -> Vec<&'static str> {
    match n {
        1 => vec!["90"],
        2 => vec!["15", "BRASS", "EUROPE"],
        3 => vec!["BUILDING", "1995-03-15"],
        4 => vec!["1993-07-01"],
        5 => vec!["ASIA", "1994-01-01"],
        6 => vec!["1994-01-01", "0.06", "24"],
        7 => vec!["FRANCE", "GERMANY"],
        8 => vec!["BRAZIL", "AMERICA", "ECONOMY ANODIZED STEEL"],
        9 => vec!["green"],
        10 => vec!["1993-10-01"],
        11 => vec!["GERMANY", "0.0001"],
        12 => vec!["MAIL", "SHIP", "1994-01-01"],
        13 => vec!["special", "requests"],
        14 => vec!["1995-09-01"],
        15 => vec!["1996-01-01"],
        16 => vec!["Brand#45", "MEDIUM POLISHED", "49", "14", "23", "45", "19", "3", "36", "9"],
        17 => vec!["Brand#23", "MED BOX"],
        18 => vec!["300"],
        19 => vec!["Brand#12", "Brand#23", "Brand#34", "1", "10", "20"],
        20 => vec!["forest", "1994-01-01", "CANADA"],
        21 => vec!["SAUDI ARABIA"],
        22 => vec!["13", "31", "23", "29", "30", "18", "17"],
        _ => vec![],
    }
}

/// Substitute `:1..` (longest index first so `:1` doesn't match inside `:10`).
fn substitute(sql: &str, ps: &[&str]) -> String {
    let mut out = sql.to_string();
    for (i, val) in ps.iter().enumerate().rev() {
        out = out.replace(&format!(":{}", i + 1), val);
    }
    out
}

/// DataFusion dialect fixups + trailing-`;` strip.
fn adapt(sql: &str) -> String {
    let s = sql
        .replace(" day (3)", " day")
        .replace("substring(c_phone from 1 for 2)", "substr(c_phone, 1, 2)");
    s.trim().trim_end_matches(';').trim().to_string()
}

/// DataFusion-ready SQL for TPC-H query `n` (1..=22).
pub fn query_sql(n: i32) -> String {
    if n == 15 {
        // Spec Q15 uses CREATE VIEW / DROP VIEW; iceberg-datafusion's schema is
        // read-only, so use the canonical CTE form (same query, no view).
        let d = params(15)[0];
        return format!(
            "WITH revenue0 AS (\
               SELECT l_suppkey AS supplier_no, \
                      sum(l_extendedprice * (1 - l_discount)) AS total_revenue \
               FROM lineitem \
               WHERE l_shipdate >= date '{d}' AND l_shipdate < date '{d}' + interval '3' month \
               GROUP BY l_suppkey) \
             SELECT s_suppkey, s_name, s_address, s_phone, total_revenue \
             FROM supplier, revenue0 \
             WHERE s_suppkey = supplier_no \
               AND total_revenue = (SELECT max(total_revenue) FROM revenue0) \
             ORDER BY s_suppkey"
        );
    }
    adapt(&substitute(tpchgen::q_and_a::queries::query(n).expect("query text"), &params(n)))
}

/// Build a fresh RedbCatalog warehouse with all 8 TPC-H tables ingested, and a
/// DataFusion `SessionContext` wired to it (default catalog/schema `nornir.tpch`).
/// Returns the ctx, the warehouse TempDir (keep alive), and rows ingested.
pub async fn build_ctx(sf: f64) -> Result<(SessionContext, tempfile::TempDir, u64)> {
    build_ctx_scaled(sf, 1).await
}

/// Like [`build_ctx`], but the query `SessionContext` is built by **skade**
/// (`Warehouse::session`, the `sql` feature) instead of wiring DataFusion +
/// iceberg-datafusion by hand. The 8 tables are ingested into skade's own
/// warehouse catalog (reusing [`build_ctx_in`]); `session()` registers every
/// table by bare name so the canonical TPC-H queries resolve. Dogfoods skade's
/// SQL surface on the full 22-query workload.
pub async fn build_ctx_skade(sf: f64) -> Result<(SessionContext, tempfile::TempDir, u64)> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path()).await?;
    let catalog: Arc<dyn Catalog> = wh.catalog();
    let (_discard, total) = build_ctx_in(catalog, sf, 1).await?;
    let ctx = wh.session().await?;
    Ok((ctx, tmp, total))
}

/// Like [`build_ctx`] but ingests each large table across `parts` partitions in
/// parallel (one task per partition) — the path the large-warehouse bencher uses
/// to put the build on all cores. `parts == 1` ⇒ the plain sequential build.
/// nation/region (fixed tiny) always use a single partition.
pub async fn build_ctx_scaled(
    sf: f64,
    parts: i32,
) -> Result<(SessionContext, tempfile::TempDir, u64)> {
    let tmp = tempfile::tempdir()?;
    let warehouse = format!("file://{}", tmp.path().join("warehouse").display());
    let catalog = RedbCatalogBuilder::default()
        .db_path(tmp.path().join("catalog.redb").to_string_lossy().to_string())
        .warehouse_location(warehouse)
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load("skade", HashMap::new())
        .await?;
    let catalog: Arc<dyn Catalog> = Arc::new(catalog);
    let (ctx, total) = build_ctx_in(catalog, sf, parts).await?;
    Ok((ctx, tmp, total))
}

/// Ingest the 8 TPC-H tables into **any** `catalog` at scale `sf` (`parts`-way
/// parallel) and return a DataFusion `SessionContext` wired to it (default
/// catalog/schema `nornir.tpch`). Used to run the same suite over nornir / Nessie
/// / Polaris. The caller owns the catalog's storage lifetime. Best-effort drops
/// the tpch tables first so a re-run against a persistent server (Nessie/Polaris)
/// doesn't collide.
pub async fn build_ctx_in(
    catalog: Arc<dyn Catalog>,
    sf: f64,
    parts: i32,
) -> Result<(SessionContext, u64)> {
    let ns = NamespaceIdent::new("tpch".to_string());
    if !catalog.namespace_exists(&ns).await.unwrap_or(false) {
        catalog.create_namespace(&ns, HashMap::new()).await?;
    }
    for t in ["nation", "region", "supplier", "part", "partsupp", "customer", "orders", "lineitem"] {
        let id = iceberg::TableIdent::new(ns.clone(), t.to_string());
        if catalog.table_exists(&id).await.unwrap_or(false) {
            let _ = catalog.drop_table(&id).await;
        }
    }

    let mut total = 0u64;
    total += ingest_table_parallel(&catalog, &ns, "nation", 1, move |p, n| NationArrow::new(NationGenerator::new(sf, p, n))).await?;
    total += ingest_table_parallel(&catalog, &ns, "region", 1, move |p, n| RegionArrow::new(RegionGenerator::new(sf, p, n))).await?;
    total += ingest_table_parallel(&catalog, &ns, "supplier", parts, move |p, n| SupplierArrow::new(SupplierGenerator::new(sf, p, n))).await?;
    total += ingest_table_parallel(&catalog, &ns, "part", parts, move |p, n| PartArrow::new(PartGenerator::new(sf, p, n))).await?;
    total += ingest_table_parallel(&catalog, &ns, "partsupp", parts, move |p, n| PartSuppArrow::new(PartSuppGenerator::new(sf, p, n))).await?;
    total += ingest_table_parallel(&catalog, &ns, "customer", parts, move |p, n| CustomerArrow::new(CustomerGenerator::new(sf, p, n))).await?;
    total += ingest_table_parallel(&catalog, &ns, "orders", parts, move |p, n| OrderArrow::new(OrderGenerator::new(sf, p, n))).await?;
    total += ingest_table_parallel(&catalog, &ns, "lineitem", parts, move |p, n| LineItemArrow::new(LineItemGenerator::new(sf, p, n))).await?;

    let provider = IcebergCatalogProvider::try_new(catalog.clone()).await?;
    let config = SessionConfig::new().with_default_catalog_and_schema("skade", "tpch");
    let ctx = SessionContext::new_with_config(config);
    ctx.register_catalog("skade", Arc::new(provider));
    Ok((ctx, total))
}
