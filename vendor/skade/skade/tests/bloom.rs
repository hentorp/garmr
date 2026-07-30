//! WriteProps knobs that live in skade (not the catalog): per-column bloom
//! filters, row-group size, and dictionary control. These complement nornir's
//! sort/SortOrder file-level data-skipping with intra-file row-group skipping
//! on point lookups.
//!
//! LAW 6 — assert on data: every test here writes a real table, then reads the
//! resulting Parquet file's metadata back off disk and asserts on it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, anyhow};
use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};
use skade::parquet::file::metadata::{ParquetMetaData, ParquetMetaDataReader};
use skade::{Compression, WriteProps};

fn trade_schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("symbol", DataType::Utf8, false),
    ])
}

fn trade_batch(n: i64) -> Result<RecordBatch> {
    // High-cardinality-ish symbol so a bloom filter is meaningful.
    let ids: Vec<i64> = (0..n).collect();
    let syms: Vec<String> = (0..n).map(|i| format!("SYM{:04}", i % 500)).collect();
    Ok(RecordBatch::try_new(
        Arc::new(trade_schema()),
        vec![
            Arc::new(Int64Array::from(ids)),
            Arc::new(StringArray::from(syms)),
        ],
    )?)
}

/// Walk `dir` and return the single `.parquet` data file's bytes (the table was
/// written with exactly one append → one file).
fn only_parquet_bytes(dir: &Path) -> Result<Vec<u8>> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let p = entry?.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("parquet") {
                found.push(p);
            }
        }
    }
    match found.as_slice() {
        [one] => Ok(std::fs::read(one)?),
        other => Err(anyhow!(
            "expected exactly one parquet file, found {}",
            other.len()
        )),
    }
}

fn parse_meta(bytes: &[u8]) -> Result<ParquetMetaData> {
    Ok(ParquetMetaDataReader::new().parse_and_finish(&bytes::Bytes::copy_from_slice(bytes))?)
}

/// Does `col` have a bloom filter in *any* row group? (offset present ⇒ written.)
fn has_bloom(meta: &ParquetMetaData, col: &str) -> bool {
    meta.row_groups().iter().any(|rg| {
        rg.columns()
            .iter()
            .any(|c| c.column_path().string() == col && c.bloom_filter_offset().is_some())
    })
}

#[tokio::test]
async fn bloom_filter_and_row_group_size_take_effect() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    // Bloom on `symbol`, a small row-group size, dictionary explicitly ON.
    let props = WriteProps::new(Compression::SNAPPY)
        .bloom_columns(["symbol"])
        .row_group_size(100)
        .dictionary(true);
    let mut t = wh
        .create_table("trades", &trade_schema())
        .await?
        .write_props(props);

    // 1000 rows / 100-row groups → 10 row groups.
    t.append(&[trade_batch(1000)?]).await?;
    assert_eq!(t.count().await?, 1000);

    let meta = parse_meta(&only_parquet_bytes(tmp.path())?)?;

    // Row-group size took effect: 1000 rows / 100 → 10 groups, each ≤ 100 rows.
    assert_eq!(meta.num_row_groups(), 10, "1000 rows / row_group_size 100");
    for rg in meta.row_groups() {
        assert!(
            rg.num_rows() <= 100,
            "row group has {} rows, expected ≤ 100",
            rg.num_rows()
        );
    }

    // Bloom IS present on `symbol`, ABSENT on the non-bloom `id` column.
    assert!(has_bloom(&meta, "symbol"), "bloom filter on `symbol`");
    assert!(!has_bloom(&meta, "id"), "no bloom filter on `id`");

    // Dictionary state as configured (on): each column chunk carries a
    // dictionary page offset.
    for rg in meta.row_groups() {
        for c in rg.columns() {
            assert!(
                c.dictionary_page_offset().is_some(),
                "dictionary enabled ⇒ `{}` has a dictionary page",
                c.column_path().string()
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn no_bloom_columns_writes_no_bloom_filter() -> Result<()> {
    // Fail-on-bug: with no bloom_columns, no bloom filter is written anywhere.
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    let mut t = wh
        .create_table("plain", &trade_schema())
        .await?
        .write_props(WriteProps::new(Compression::UNCOMPRESSED)); // defaults: no bloom

    t.append(&[trade_batch(300)?]).await?;

    let meta = parse_meta(&only_parquet_bytes(tmp.path())?)?;
    assert!(
        !has_bloom(&meta, "symbol"),
        "no bloom requested ⇒ none on `symbol`"
    );
    assert!(!has_bloom(&meta, "id"), "no bloom requested ⇒ none on `id`");

    Ok(())
}

#[tokio::test]
async fn dictionary_disabled_writes_no_dictionary_pages() -> Result<()> {
    // Dictionary state as configured (off): no column chunk has a dictionary page.
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    let mut t = wh
        .create_table("nodict", &trade_schema())
        .await?
        .write_props(WriteProps::new(Compression::UNCOMPRESSED).dictionary(false));

    t.append(&[trade_batch(300)?]).await?;

    let meta = parse_meta(&only_parquet_bytes(tmp.path())?)?;
    for rg in meta.row_groups() {
        for c in rg.columns() {
            assert!(
                c.dictionary_page_offset().is_none(),
                "dictionary disabled ⇒ `{}` has no dictionary page",
                c.column_path().string()
            );
        }
    }

    Ok(())
}

/// The bloom path also works through the parallel (all-core encode) ingest.
#[tokio::test]
async fn bloom_through_ingest_parallel() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    let mut t = wh
        .create_table("paral", &trade_schema())
        .await?
        .write_props(
            WriteProps::new(Compression::ZSTD(Default::default())).bloom_columns(["symbol"]),
        );

    // One group → one file.
    let stats = t.ingest_parallel(vec![vec![trade_batch(400)?]], 1).await?;
    assert_eq!(stats.rows, 400);

    let meta = parse_meta(&only_parquet_bytes(tmp.path())?)?;
    assert!(
        has_bloom(&meta, "symbol"),
        "bloom on `symbol` via ingest_parallel"
    );
    assert!(!has_bloom(&meta, "id"), "no bloom on `id`");
    Ok(())
}
