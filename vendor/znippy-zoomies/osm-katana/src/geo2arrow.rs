//! GeoParquet → Arrow IPC on `gatling::ordered::run_ordered_sink` (no rayon, no
//! hand-rolled pool — ROOT LAW #0).
//!
//! Replaces the old serial 5-line pipe (decode batch → write batch → repeat on
//! ONE core) which was insane at planet scale (decompressing a 157 GB GeoParquet
//! single-threaded). N decoder workers decompress+decode row groups in parallel
//! and the ordered sink serializes them to the Arrow IPC file in original order.

use std::fs::File;
use std::path::Path;

use anyhow::Context as _;
use arrow::ipc::writer::FileWriter as ArrowFileWriter;
use arrow::record_batch::RecordBatch;
use parquet::arrow::arrow_reader::{
    ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReaderBuilder,
};

/// GeoParquet → Arrow IPC on `gatling::ordered::run_ordered_sink`.
///
/// ROOT LAW #0. This used to be a hand-rolled `std::thread::scope` pool: N decoder
/// threads spawned by hand, a `sync_channel` carrying `(row_group, seq, batch)`
/// plus `End(rg, count)` markers, and a bespoke `HashMap` reorder buffer with its
/// own `want_rg`/`want_seq` cursor and a `try_flush` closure — about 60 lines
/// re-implementing, badly, the ordered streaming sink gatling already ships. The
/// whole reorder machine, the End markers and the private pool are gone; what is
/// left is a producer, a map and a sink.
///
/// - **Producer** yields the row-group indices `0..n_rg` lazily, pulled only when
///   a worker slot is free.
/// - **Map** (N workers, self-dispatched, no barrier) opens its OWN reader over
///   ONE row group, reusing the already-parsed footer (`ArrowReaderMetadata` /
///   `new_with_metadata`), and decodes it. That decode (zstd-decompress +
///   arrow-decode) is the parallel CPU cost. NOTHING is projected away — every
///   column / the full schema is kept, so the output is data-identical to the old
///   serial decode.
/// - **Sink** writes each row group's batches to the Arrow IPC `FileWriter` in
///   strict producer order. `run_ordered_sink` runs the collector on the CALLING
///   thread, so the writer needs no `Send` and no channel of its own.
///
/// Output order == input order: row groups in original order, batches within a row
/// group in read order → the same sequence the serial loop produced.
///
/// Memory is bounded by the `cap` permit pool: at most `cap` row groups are alive
/// (pulled-but-not-yet-written) at any instant, so a slow writer back-pressures
/// the decoders instead of letting 157 GB of batches pile up. `cap == n_workers`
/// is the smallest value that still keeps every worker fed; the unit is a whole
/// row group rather than a single batch, which is the one thing this shape costs —
/// it holds `n_workers` decoded row groups instead of `4 * n_workers` decoded
/// batches. Measured below on real data, that is a few hundred MB, and it buys the
/// deletion of a hand-rolled pool plus its hand-rolled reorder buffer.
pub fn geo2arrow(input: &Path, output: &Path) -> anyhow::Result<()> {
    // Escape hatch for benchmarking the old single-thread path against the new
    // parallel one with the SAME binary: OSM_KATANA_GEO2ARROW_SERIAL=1 forces the
    // original serial decode→write loop. Off by default (parallel is the shipped
    // behaviour).
    if std::env::var_os("OSM_KATANA_GEO2ARROW_SERIAL").is_some() {
        return geo2arrow_serial_impl(input, output);
    }
    // One footer read; reused by every worker (no re-parse per thread).
    let builder = ParquetRecordBatchReaderBuilder::try_new(
        File::open(input).with_context(|| format!("open {input:?}"))?,
    )?;
    let schema = builder.schema().clone();
    let meta = builder.metadata().clone();
    let n_rg = meta.num_row_groups();

    let mut w = ArrowFileWriter::try_new(
        File::create(output).with_context(|| format!("create {output:?}"))?,
        &schema,
    )?;

    // Empty parquet (no row groups): just finish an empty IPC file.
    if n_rg == 0 {
        w.finish()?;
        eprintln!(
            "wrote {output:?} (0 row groups, {} cols)",
            schema.fields().len()
        );
        return Ok(());
    }

    let n_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(n_rg)
        .max(1);

    // Lazy producer: the next row-group index, pulled only when a permit is free.
    let mut next_rg = 0usize;
    let producer = move || {
        if next_rg < n_rg {
            let rg = next_rg;
            next_rg += 1;
            Some((rg, ()))
        } else {
            None
        }
    };

    let mut rows: u64 = 0;
    let mut n_batches: u64 = 0;

    gatling::gatling::ordered::run_ordered_sink(
        producer,
        n_workers,
        // ≤ n_workers row groups alive at once — the memory bound.
        n_workers,
        // Decode ONE row group. A reader per row group is cheap (the footer is
        // already parsed) and keeps the per-rg batch boundaries the old code
        // needed End markers to reconstruct.
        |rg: usize, _: ()| -> anyhow::Result<Vec<RecordBatch>> {
            let arm = ArrowReaderMetadata::try_new(meta.clone(), ArrowReaderOptions::new())?;
            let reader = ParquetRecordBatchReaderBuilder::new_with_metadata(
                File::open(input).with_context(|| format!("open {input:?}"))?,
                arm,
            )
            .with_row_groups(vec![rg])
            .build()?;
            reader.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        },
        // Sink on the calling thread, strictly in producer (row-group) order.
        &mut |_seq: u64, decoded: anyhow::Result<Vec<RecordBatch>>| -> anyhow::Result<()> {
            for b in decoded? {
                rows += b.num_rows() as u64;
                n_batches += 1;
                w.write(&b)?;
            }
            Ok(())
        },
    )?;

    w.finish()?;
    eprintln!(
        "wrote {output:?}: {rows} rows, {n_batches} batches, {n_rg} row groups, {} cols, {n_workers} decoder workers",
        schema.fields().len(),
    );
    Ok(())
}

/// The original serial path (decode batch → write batch → repeat, ONE thread).
/// Kept only as a benchmarking baseline behind OSM_KATANA_GEO2ARROW_SERIAL; the
/// parallel `geo2arrow` is what ships.
fn geo2arrow_serial_impl(input: &Path, output: &Path) -> anyhow::Result<()> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(
        File::open(input).with_context(|| format!("open {input:?}"))?,
    )?;
    let schema = builder.schema().clone();
    let mut w = ArrowFileWriter::try_new(
        File::create(output).with_context(|| format!("create {output:?}"))?,
        &schema,
    )?;
    let mut rows: u64 = 0;
    for batch in builder.build()? {
        let b = batch?;
        rows += b.num_rows() as u64;
        w.write(&b)?;
    }
    w.finish()?;
    eprintln!("wrote {output:?}: {rows} rows (SERIAL, 1 thread)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::Array;
    use arrow::array::{Float64Array, Int64Array, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use parquet::basic::Compression;
    use parquet::file::properties::WriterProperties;
    use std::sync::Arc;

    /// The OLD serial logic, kept verbatim as the reference oracle: decode batch,
    /// write batch, repeat on one thread. The new parallel path must produce
    /// data-identical output to this.
    fn geo2arrow_serial(input: &Path, output: &Path) -> anyhow::Result<()> {
        let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(input)?)?;
        let schema = builder.schema().clone();
        let mut w = ArrowFileWriter::try_new(File::create(output)?, &schema)?;
        for batch in builder.build()? {
            w.write(&batch?)?;
        }
        w.finish()?;
        Ok(())
    }

    /// Build a multi-row-group GeoParquet-shaped file (id:i64, lon/lat:f64, tag:utf8,
    /// with nulls) using a small row-group size so we get many row groups — the case
    /// the parallel path must reorder correctly.
    fn write_test_parquet(path: &Path, n_rows: i64, rg_size: usize) -> anyhow::Result<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("lon", DataType::Float64, false),
            Field::new("lat", DataType::Float64, false),
            Field::new("tag", DataType::Utf8, true),
        ]));
        let props = WriterProperties::builder()
            .set_max_row_group_row_count(Some(rg_size))
            .set_compression(Compression::ZSTD(Default::default()))
            .build();
        let mut w = ArrowWriter::try_new(File::create(path)?, schema.clone(), Some(props))?;
        // Write in several arrow batches of varying size so a row group can span
        // multiple decoded batches and vice versa.
        let mut written = 0i64;
        let chunk_sizes = [1000i64, 333, 1500, 50, 2000];
        let mut ci = 0;
        while written < n_rows {
            let take = chunk_sizes[ci % chunk_sizes.len()].min(n_rows - written);
            ci += 1;
            let ids: Vec<i64> = (written..written + take).collect();
            let lons: Vec<f64> = ids.iter().map(|&i| i as f64 * 0.0001).collect();
            let lats: Vec<f64> = ids.iter().map(|&i| 50.0 + i as f64 * 0.00001).collect();
            let tags: Vec<Option<String>> = ids
                .iter()
                .map(|&i| {
                    if i % 7 == 0 {
                        None
                    } else {
                        Some(format!("t{i}"))
                    }
                })
                .collect();
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(Int64Array::from(ids)),
                    Arc::new(Float64Array::from(lons)),
                    Arc::new(Float64Array::from(lats)),
                    Arc::new(StringArray::from(tags)),
                ],
            )?;
            w.write(&batch)?;
            written += take;
        }
        w.close()?;
        Ok(())
    }

    /// Read an Arrow IPC file back into one concatenated set of rows as (id, lon,
    /// lat, tag) tuples — for asserting data + ORDER identity independent of how the
    /// rows were chunked into IPC blocks.
    fn read_ipc_rows(path: &Path) -> anyhow::Result<Vec<(i64, f64, f64, Option<String>)>> {
        use arrow::ipc::reader::FileReader;
        let reader = FileReader::try_new(File::open(path)?, None)?;
        let mut out = Vec::new();
        for batch in reader {
            let b = batch?;
            let ids = b.column(0).as_any().downcast_ref::<Int64Array>().unwrap();
            let lons = b.column(1).as_any().downcast_ref::<Float64Array>().unwrap();
            let lats = b.column(2).as_any().downcast_ref::<Float64Array>().unwrap();
            let tags = b.column(3).as_any().downcast_ref::<StringArray>().unwrap();
            for i in 0..b.num_rows() {
                let tag = if tags.is_null(i) {
                    None
                } else {
                    Some(tags.value(i).to_string())
                };
                out.push((ids.value(i), lons.value(i), lats.value(i), tag));
            }
        }
        Ok(out)
    }

    #[test]
    fn parallel_geo2arrow_is_data_identical_to_serial() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        // Many small row groups → exercises the writer's cross-row-group reordering.
        let parquet = dir.path().join("nodes.parquet");
        write_test_parquet(&parquet, 12_345, 500)?;

        // Sanity: the input really has multiple row groups (else the test is moot).
        let meta = ParquetRecordBatchReaderBuilder::try_new(File::open(&parquet)?)?
            .metadata()
            .clone();
        assert!(
            meta.num_row_groups() > 4,
            "test parquet should have many row groups, got {}",
            meta.num_row_groups()
        );

        let out_serial = dir.path().join("serial.arrow");
        let out_par = dir.path().join("par.arrow");
        geo2arrow_serial(&parquet, &out_serial)?;
        geo2arrow(&parquet, &out_par)?;

        let rows_serial = read_ipc_rows(&out_serial)?;
        let rows_par = read_ipc_rows(&out_par)?;

        // Row COUNT identical.
        assert_eq!(rows_serial.len(), 12_345, "serial row count");
        assert_eq!(
            rows_par.len(),
            rows_serial.len(),
            "parallel row count != serial"
        );
        // Row ORDER + DATA identical, element by element.
        assert_eq!(
            rows_par, rows_serial,
            "parallel rows differ from serial (order/data)"
        );
        Ok(())
    }

    #[test]
    fn parallel_geo2arrow_single_row_group() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let parquet = dir.path().join("nodes.parquet");
        write_test_parquet(&parquet, 200, 100_000)?; // one big row group
        let out_serial = dir.path().join("s.arrow");
        let out_par = dir.path().join("p.arrow");
        geo2arrow_serial(&parquet, &out_serial)?;
        geo2arrow(&parquet, &out_par)?;
        assert_eq!(read_ipc_rows(&out_par)?, read_ipc_rows(&out_serial)?);
        Ok(())
    }
}
