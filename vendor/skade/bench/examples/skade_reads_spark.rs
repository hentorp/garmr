//! skade reads a **Spark-written** Iceberg table — interop + scan-speed demo for
//! the `skade vs Spark` container benchmark. Spark (knut-spark-iceberg, Hadoop
//! `lake` catalog) writes `lake.db.t`; we point skade at the resulting
//! `metadata.json` via an `iceberg::StaticTable` (no catalog needed) and scan it
//! through `skade::read_all`.
//!
//!   cargo run --release --example skade_reads_spark -- <…/db/t/metadata/vN.metadata.json>
use std::sync::Arc;
use std::time::Instant;

use skade::iceberg::io::{FileIOBuilder, LocalFsStorageFactory};
use skade::iceberg::table::StaticTable;
use skade::iceberg::TableIdent;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: skade_reads_spark <metadata.json>");
    let uri = if path.starts_with("file://") { path } else { format!("file://{path}") };

    let file_io = FileIOBuilder::new(Arc::new(LocalFsStorageFactory)).build();
    let ident = TableIdent::from_strs(["db", "t"])?;
    let table = StaticTable::from_metadata_file(&uri, ident, file_io).await?.into_table();

    let t0 = Instant::now();
    let batches = skade::read_all(&table).await?;
    let dt = t0.elapsed();
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    println!(
        "skade read Spark-written Iceberg: {rows} rows in {:.3}s = {:.1} Mrows/s",
        dt.as_secs_f64(),
        rows as f64 / dt.as_secs_f64() / 1e6
    );
    Ok(())
}
