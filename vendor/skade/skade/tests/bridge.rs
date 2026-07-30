//! Schema bridges: widen → Iceberg roundtrip → un-widen, bit-exact for
//! unsigned values above the signed max; windowed Parquet reads.

use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Int64Array, RecordBatch, UInt32Array, UInt64Array};
use skade::arrow_schema::{DataType, Field, Schema};

fn unsigned_schema() -> Schema {
    Schema::new(vec![
        Field::new("u32", DataType::UInt32, false),
        Field::new("u64", DataType::UInt64, false),
    ])
}

fn unsigned_batch() -> Result<RecordBatch> {
    // Values past the signed max — the cases plain casts would null/refuse.
    Ok(RecordBatch::try_new(
        Arc::new(unsigned_schema()),
        vec![
            Arc::new(UInt32Array::from(vec![0u32, 7, u32::MAX, u32::MAX - 1])),
            Arc::new(UInt64Array::from(vec![
                0u64,
                7,
                u64::MAX,
                (i64::MAX as u64) + 1,
            ])),
        ],
    )?)
}

#[test]
fn widen_unwiden_is_bit_exact() -> Result<()> {
    let original = unsigned_batch()?;

    let widened = skade::widen_for_iceberg(&original)?;
    assert_eq!(widened.column(0).data_type(), &DataType::Int32);
    assert_eq!(widened.column(1).data_type(), &DataType::Int64);
    // u64::MAX reinterprets to -1.
    let w64 = widened
        .column(1)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap();
    assert_eq!(w64.value(2), -1);

    let back = skade::unwiden(&[widened], original.schema())?;
    assert_eq!(back.len(), 1);
    assert_eq!(
        &back[0], &original,
        "widen→unwiden roundtrip must be bit-exact"
    );
    Ok(())
}

/// Unsigned columns survive a full Iceberg write/read cycle via widen → store
/// (signed) → scan → unwiden.
#[tokio::test]
async fn unsigned_roundtrip_through_iceberg() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    let original = unsigned_batch()?;
    let widened = skade::widen_for_iceberg(&original)?;

    let mut t = wh.create_table("idx", widened.schema().as_ref()).await?;
    t.append(&[widened]).await?;

    let stored = t.read().await?;
    let back = skade::unwiden(&stored, original.schema())?;
    let total: usize = back.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total, original.num_rows());

    // Sort-insensitive check: collect u64 column values from all batches.
    let mut got: Vec<u64> = back
        .iter()
        .flat_map(|b| {
            b.column(1)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap()
                .values()
                .to_vec()
        })
        .collect();
    got.sort_unstable();
    let mut want = vec![0u64, 7, u64::MAX, (i64::MAX as u64) + 1];
    want.sort_unstable();
    assert_eq!(got, want);
    Ok(())
}

#[test]
fn windowed_parquet_reads() -> Result<()> {
    use skade::parquet::arrow::ArrowWriter;
    use skade::parquet::file::properties::WriterProperties;

    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("rows.parquet");

    // 10 row groups × 100 rows.
    let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
    let props = WriterProperties::builder()
        .set_max_row_group_size(100)
        .build();
    let file = std::fs::File::create(&path)?;
    let mut w = ArrowWriter::try_new(file, schema.clone(), Some(props))?;
    let ids: Vec<i64> = (0..1000).collect();
    w.write(&RecordBatch::try_new(
        schema,
        vec![Arc::new(Int64Array::from(ids))],
    )?)?;
    w.close()?;

    let (ice, file_schema, rg_rows) = skade::parquet_layout(&path)?;
    assert_eq!(ice.as_struct().fields().len(), 1);
    assert_eq!(file_schema.fields().len(), 1);
    assert_eq!(rg_rows, vec![100usize; 10]);

    // ~300-row windows over the first 800 rows → 8 row groups in 3 windows.
    let windows = skade::rowgroup_windows(&rg_rows, 300, 800);
    assert_eq!(windows.len(), 3);
    assert_eq!(windows.iter().map(|w| w.len()).sum::<usize>(), 8);

    let mut total = 0usize;
    for w in &windows {
        let batches = skade::read_row_groups(&path, w, 64, 4)?;
        total += batches.iter().map(|b| b.num_rows()).sum::<usize>();
    }
    assert_eq!(total, 800);
    Ok(())
}

#[test]
fn streaming_parquet_windows_bounded_memory() -> Result<()> {
    use skade::parquet::arrow::ArrowWriter;
    use skade::parquet::file::properties::WriterProperties;

    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("rows.parquet");

    // 10 row groups × 100 rows = 1000 rows.
    let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
    let props = WriterProperties::builder()
        .set_max_row_group_size(100)
        .build();
    let file = std::fs::File::create(&path)?;
    let mut w = ArrowWriter::try_new(file, schema.clone(), Some(props))?;
    let ids: Vec<i64> = (0..1000).collect();
    w.write(&RecordBatch::try_new(
        schema,
        vec![Arc::new(Int64Array::from(ids))],
    )?)?;
    w.close()?;

    // Open as a streaming reader: ~250-row windows over ALL 1000 rows → 4 windows.
    let (ice, file_schema, windows) = skade::ParquetWindows::open(&path, 250, usize::MAX, 64, 4)?;
    assert_eq!(ice.as_struct().fields().len(), 1);
    assert_eq!(
        file_schema.fields().len(),
        1,
        "file's arrow schema returned up front"
    );

    // ExactSizeIterator: the window count is known before decoding any data.
    assert_eq!(windows.len(), 4, "1000 rows / 250 per window = 4 windows");

    // Drive the stream one window at a time — peak memory is one window's batches.
    let mut total = 0usize;
    let mut nwindows = 0usize;
    let mut seen: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
    for window in windows {
        let batches = window?;
        for b in &batches {
            total += b.num_rows();
            let col = b
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("id column is Int64");
            seen.extend(col.values().iter().copied());
        }
        nwindows += 1;
    }
    assert_eq!(nwindows, 4, "streamed exactly 4 windows");
    assert_eq!(total, 1000, "every row streamed exactly once");
    // Streaming must lose no rows and duplicate none: the full 0..1000 id set.
    assert_eq!(seen.len(), 1000);
    assert_eq!(*seen.iter().next().unwrap(), 0);
    assert_eq!(*seen.iter().next_back().unwrap(), 999);
    Ok(())
}

#[test]
fn streaming_parquet_windows_max_rows_cap() -> Result<()> {
    use skade::parquet::arrow::ArrowWriter;
    use skade::parquet::file::properties::WriterProperties;

    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("rows.parquet");

    let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
    let props = WriterProperties::builder()
        .set_max_row_group_size(100)
        .build();
    let file = std::fs::File::create(&path)?;
    let mut w = ArrowWriter::try_new(file, schema.clone(), Some(props))?;
    let ids: Vec<i64> = (0..1000).collect();
    w.write(&RecordBatch::try_new(
        schema,
        vec![Arc::new(Int64Array::from(ids))],
    )?)?;
    w.close()?;

    // max_rows caps the stream: 300-row windows, stop after ~500 rows → the
    // window builder covers whole row groups until it passes the cap.
    let (_ice, _fs, windows) = skade::ParquetWindows::open(&path, 300, 500, 64, 4)?;
    let capped: usize = windows
        .map(|wnd| wnd.map(|bs| bs.iter().map(|b| b.num_rows()).sum::<usize>()))
        .collect::<std::result::Result<Vec<_>, skade::SkadeError>>()?
        .into_iter()
        .sum();
    // Row groups are 100 rows; the cap stops after the window that reaches 500.
    assert!(
        capped >= 500 && capped <= 800,
        "capped stream read {capped} rows"
    );
    assert!(capped < 1000, "max_rows must cap below the full file");
    Ok(())
}
