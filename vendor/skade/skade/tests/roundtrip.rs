//! End-to-end: temp-dir warehouse → write rows → read back → SQL roundtrip,
//! plus warehouse persistence across reopen and multi-table SQL.

use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Float64Array, Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};

fn events_schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("score", DataType::Float64, false),
        Field::new("name", DataType::Utf8, false),
    ])
}

fn events_batch(ids: Vec<i64>) -> Result<RecordBatch> {
    let scores: Vec<f64> = ids.iter().map(|i| *i as f64 * 0.5).collect();
    let names: Vec<String> = ids.iter().map(|i| format!("row-{i}")).collect();
    Ok(RecordBatch::try_new(
        Arc::new(events_schema()),
        vec![
            Arc::new(Int64Array::from(ids)),
            Arc::new(Float64Array::from(scores)),
            Arc::new(StringArray::from(names)),
        ],
    )?)
}

#[cfg(feature = "sql")]
fn first_i64(batches: &[RecordBatch], col: &str) -> i64 {
    let b = batches
        .iter()
        .find(|b| b.num_rows() > 0)
        .expect("non-empty result");
    let i = b.schema().index_of(col).expect("column");
    b.column(i)
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("Int64 column")
        .value(0)
}

#[cfg(feature = "sql")]
#[tokio::test]
async fn write_read_sql_roundtrip() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    let mut events = wh.create_table("events", &events_schema()).await?;
    events.append(&[events_batch((1..=10).collect())?]).await?;

    // Read back: full scan to Arrow.
    let batches = events.read().await?;
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 10);
    assert_eq!(events.count().await?, 10);

    // SQL on the single table, bare name.
    let res = events
        .sql("SELECT count(*) AS n, sum(id) AS s FROM events WHERE id > 7")
        .await?;
    assert_eq!(first_i64(&res, "n"), 3, "ids 8,9,10");
    assert_eq!(first_i64(&res, "s"), 27, "8+9+10");

    // Second append → new snapshot; a fresh warehouse SQL session sees it.
    events.append(&[events_batch((11..=15).collect())?]).await?;
    let res = wh.sql("SELECT count(*) AS n FROM events").await?;
    assert_eq!(first_i64(&res, "n"), 15);

    // Qualified name through the catalog provider works too.
    let res = wh
        .sql("SELECT count(*) AS n FROM skade.main.events")
        .await?;
    assert_eq!(first_i64(&res, "n"), 15);

    Ok(())
}

#[cfg(feature = "sql")]
#[tokio::test]
async fn multi_table_sql_in_one_statement() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    let mut a = wh.create_table("a", &events_schema()).await?;
    let mut b = wh.create_table("b", &events_schema()).await?;
    a.append(&[events_batch((1..=6).collect())?]).await?;
    b.append(&[events_batch((4..=9).collect())?]).await?;

    // Join two Iceberg tables in one statement, bare names.
    let res = wh
        .sql("SELECT count(*) AS n FROM a JOIN b ON a.id = b.id")
        .await?;
    assert_eq!(first_i64(&res, "n"), 3, "ids 4,5,6 overlap");

    // A table outside the default namespace is reachable qualified.
    let mut c = wh.create_table("logs.c", &events_schema()).await?;
    c.append(&[events_batch((1..=4).collect())?]).await?;
    let res = wh.sql("SELECT count(*) AS n FROM skade.logs.c").await?;
    assert_eq!(first_i64(&res, "n"), 4);

    Ok(())
}

#[tokio::test]
async fn warehouse_persists_across_reopen() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("lake");

    {
        let wh = skade::open(&dir).await?;
        let mut t = wh.create_table("events", &events_schema()).await?;
        t.append(&[events_batch((1..=5).collect())?]).await?;
    } // drop → releases the redb file lock

    let wh = skade::open(&dir).await?;
    let events = wh.table("events").await?;
    assert_eq!(events.count().await?, 5);

    // table_or_create on an existing table must not wipe it.
    let events = wh.table_or_create("events", &events_schema()).await?;
    assert_eq!(events.count().await?, 5);

    Ok(())
}

#[tokio::test]
async fn ingest_commits_in_groups() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("bulk", &events_schema()).await?;

    let batches: Vec<RecordBatch> = (0..5)
        .map(|k| events_batch((k * 100 + 1..=k * 100 + 100).collect()))
        .collect::<Result<_>>()?;
    let stats = t.ingest(batches, 2).await?;
    assert_eq!(stats.rows, 500);
    assert_eq!(stats.commits, 3, "5 batches / 2 per commit → 3 commits");
    assert_eq!(t.count().await?, 500);
    Ok(())
}

/// Direct-call coverage of the re-exported free functions `read_all`,
/// `scan_count` and `arrow_schema_of` — usually reached only via `Table::read`
/// / `Table::count`. Exercises BOTH `read_all` selectors: the gatling fast path
/// (plain append-only, single schema) and the engine fallback (schema evolution
/// → more than one schema in the metadata, so the raw decode declines and the
/// engine's field-id remap runs), asserting each agrees with `Table::read`.
#[tokio::test]
async fn read_all_fastpath_and_fallback_agree() -> Result<()> {
    use skade::arrow_schema::{DataType, Field, Schema as ArrowSchema};

    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("events", &events_schema()).await?;
    t.append(&[events_batch((1..=10).collect())?]).await?;

    // FAST PATH: plain append-only, single schema, no delete files → read_all
    // decodes the parquet bytes directly through gatling. The free fn agrees
    // with the handle.
    let direct = skade::read_all(t.inner()).await?;
    let via_handle = t.read().await?;
    let d: usize = direct.iter().map(|b| b.num_rows()).sum();
    assert_eq!(d, 10, "fast-path read_all sees all 10 rows");
    assert_eq!(
        d,
        via_handle.iter().map(|b| b.num_rows()).sum::<usize>(),
        "read_all free-fn agrees with Table::read (fast path)"
    );
    // scan_count free-fn matches the same count without materializing batches.
    assert_eq!(
        skade::scan_count(t.inner()).await?,
        10,
        "scan_count matches read"
    );

    // FALLBACK: evolve the schema (add a nullable column). Now the metadata
    // carries >1 schema, so `read_all_gatling` DECLINES (a raw parquet decode
    // can't apply the field-id → current-schema remap) and `read_all` falls back
    // to the engine's correctness-complete `to_arrow()` scan.
    let evolved = ArrowSchema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("score", DataType::Float64, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("tag", DataType::Utf8, true), // new, nullable
    ]);
    t.ensure_schema(&evolved).await?;
    assert!(
        t.inner().metadata().schemas_iter().len() > 1,
        "schema evolution registered a second schema (forces the engine fallback)"
    );

    let after = skade::read_all(t.inner()).await?;
    let a: usize = after.iter().map(|b| b.num_rows()).sum();
    assert_eq!(a, 10, "engine fallback still sees all 10 rows");
    assert_eq!(
        a,
        t.read().await?.iter().map(|b| b.num_rows()).sum::<usize>(),
        "read_all free-fn agrees with Table::read (fallback path)"
    );
    assert_eq!(
        skade::scan_count(t.inner()).await?,
        10,
        "scan_count matches on evolved schema"
    );

    // arrow_schema_of carries the Iceberg field-id metadata on EVERY field
    // (the scan needs it to remap columns by id).
    let sch = skade::arrow_schema_of(t.inner())?;
    assert_eq!(sch.fields().len(), 4);
    for f in sch.fields() {
        assert!(
            f.metadata().keys().any(|k| k.contains("field_id")),
            "field `{}` is missing its iceberg field-id metadata: {:?}",
            f.name(),
            f.metadata()
        );
    }

    skade::functional_status(
        "skade/read",
        "read_all_fastpath_and_fallback_agree",
        true,
        "read_all fast+fallback == Table::read; scan_count matches; field-ids present",
    );
    Ok(())
}

/// Read the row-group-0 / column-0 compression codec out of a parquet file's
/// footer (no bytes dep — a `File` is a `ChunkReader`).
fn file_compression(path: &std::path::Path) -> skade::Compression {
    let f = std::fs::File::open(path).unwrap();
    let builder =
        skade::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(f).unwrap();
    builder.metadata().row_group(0).column(0).compression()
}

/// Every `.parquet` file under `root`, recursively.
fn parquet_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().map(|x| x == "parquet").unwrap_or(false) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// The compression convenience wrappers `append_with` / `ingest_parallel_with`
/// (the public `*_with(Compression)` surface) apply the chosen codec AND
/// round-trip the rows. Only the bare and `*_props` forms were exercised before.
/// Each codec gets its own warehouse dir so the footer assertion is unambiguous.
#[tokio::test]
async fn compression_wrappers_apply_and_roundtrip() -> Result<()> {
    // append_with(ZSTD): one snapshot, codec applied, rows read back.
    {
        let tmp = tempfile::tempdir()?;
        let wh = skade::open(tmp.path().join("lake")).await?;
        let cat = wh.catalog();
        let t = wh.create_table("z", &events_schema()).await?;
        let updated = skade::append_with(
            cat.as_ref(),
            t.inner(),
            &[events_batch((1..=100).collect())?],
            skade::Compression::ZSTD(Default::default()),
        )
        .await?;
        assert_eq!(
            skade::scan_count(&updated).await?,
            100,
            "ZSTD rows read back"
        );
        let files = parquet_files(tmp.path());
        assert!(
            !files.is_empty(),
            "append_with wrote at least one parquet file"
        );
        for f in &files {
            assert!(
                matches!(file_compression(f), skade::Compression::ZSTD(_)),
                "footer must report ZSTD for {f:?}"
            );
        }
    }

    // ingest_parallel_with(SNAPPY): 4 groups → 2-file commits, codec applied.
    {
        let tmp = tempfile::tempdir()?;
        let wh = skade::open(tmp.path().join("lake")).await?;
        let cat = wh.catalog();
        let t = wh.create_table("s", &events_schema()).await?;
        let groups: Vec<Vec<RecordBatch>> = (0..4)
            .map(|k| vec![events_batch((k * 10 + 1..=k * 10 + 10).collect()).unwrap()])
            .collect();
        let (updated, stats) = skade::ingest_parallel_with(
            cat.as_ref(),
            t.inner().clone(),
            groups,
            2,
            skade::Compression::SNAPPY,
        )
        .await?;
        assert_eq!(stats.rows, 40, "ingest_parallel_with counted 40 rows");
        assert_eq!(
            skade::scan_count(&updated).await?,
            40,
            "SNAPPY rows read back"
        );
        let files = parquet_files(tmp.path());
        assert_eq!(files.len(), 4, "4 groups → 4 parquet data files");
        for f in &files {
            assert!(
                matches!(file_compression(f), skade::Compression::SNAPPY),
                "footer must report SNAPPY for {f:?}"
            );
        }
    }

    skade::functional_status(
        "skade/write",
        "compression_wrappers_apply_and_roundtrip",
        true,
        "append_with(ZSTD) + ingest_parallel_with(SNAPPY): footer codec + row parity",
    );
    Ok(())
}

#[tokio::test]
async fn scalar_and_v3_nanosecond_types_round_trip() -> Result<()> {
    use skade::arrow_array::{
        Decimal128Array, Int64Array, Time64MicrosecondArray, TimestampMicrosecondArray,
        TimestampNanosecondArray,
    };
    use skade::arrow_schema::{DataType, Field, TimeUnit};

    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new(
            "ts_us",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        ),
        Field::new(
            "ts_ns",
            DataType::Timestamp(TimeUnit::Nanosecond, None),
            false,
        ), // v3
        Field::new("amount", DataType::Decimal128(12, 2), false),
        Field::new("t", DataType::Time64(TimeUnit::Microsecond), false),
    ]));

    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("typed", &schema).await?;

    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1i64, 2, 3])),
            Arc::new(TimestampMicrosecondArray::from(vec![
                1_000_000i64,
                2_000_000,
                3_000_000,
            ])),
            Arc::new(TimestampNanosecondArray::from(vec![10i64, 20, 30])),
            Arc::new(
                Decimal128Array::from(vec![100i128, 250, 399]).with_precision_and_scale(12, 2)?,
            ),
            Arc::new(Time64MicrosecondArray::from(vec![1i64, 2, 3])),
        ],
    )?;
    t.append(&[batch]).await?;
    assert_eq!(t.count().await?, 3);
    let back: usize = t.read().await?.iter().map(|b| b.num_rows()).sum();
    assert_eq!(back, 3, "timestamp(µs/ns), decimal, time round-trip");
    Ok(())
}
